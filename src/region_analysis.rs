//! Static region analysis for eBPF memory loads.
//!
//! Classifies the pointer operand of every load (`LDX`) instruction as pointing
//! into the per-invocation stack, the shared read-only data region, or neither
//! ("unknown"). The JIT consumes the result (via `ubpf_set_region_hints`) to
//! emit a single-region bounds check and address translation for confidently
//! classified loads, instead of probing both regions.
//!
//! ## Provenance
//!
//! Pointer provenance in this runtime is narrow:
//!  * Stack pointers derive from `R10` (the frame pointer) or the entry `ctx`
//!    argument in `R1`, which points at the calldata living on the guest stack.
//!  * Data pointers are produced exclusively by `lddw` instructions whose
//!    64-bit immediate was patched by an `R_BPF_64_64` relocation to an address
//!    inside the data region `[data_bottom, data_top)`.
//!  * Pointer arithmetic with a scalar preserves the region.
//!
//! ## Soundness
//!
//! This pass is a *precision optimization, not a security boundary*. The stack
//! and data guest ranges are disjoint and the JIT always retains a
//! single-region bounds check, so a misclassified load can only fault
//! spuriously — never read out of bounds or cross between regions. Loads that
//! cannot be classified confidently are left `UNKNOWN` and fall back to the
//! original dual-region probe.
//!
//! The analysis is a standard forward dataflow over the instruction-slot CFG
//! with a per-register lattice and a meet at control-flow joins. Local calls
//! add an edge to the callee entry (carrying `R10`/`R6-R9`), so callee stack
//! accesses are analyzed too; argument-derived pointers (`R1-R5`) reach the
//! callee as `Unknown`. Any slot still unreached keeps its registers `Uninit`
//! and yields `UNKNOWN` hints — safe, just unoptimized.

/// Routing hint values shared with the JIT (`JIT_REGION_*` in the backends).
pub const REGION_UNKNOWN: u8 = 0;
pub const REGION_STACK: u8 = 1;
pub const REGION_DATA: u8 = 2;

const NUM_REGS: usize = 11;

// eBPF opcode encoding helpers.
const EBPF_CLS_MASK: u8 = 0x07;
const EBPF_CLS_LD: u8 = 0x00;
const EBPF_CLS_LDX: u8 = 0x01;
const EBPF_CLS_ST: u8 = 0x02;
const EBPF_CLS_STX: u8 = 0x03;
const EBPF_CLS_ALU: u8 = 0x04;
const EBPF_CLS_JMP: u8 = 0x05;
const EBPF_CLS_JMP32: u8 = 0x06;
const EBPF_CLS_ALU64: u8 = 0x07;

const EBPF_SRC_REG: u8 = 0x08;
const EBPF_ALU_OP_MASK: u8 = 0xf0;
const EBPF_ALU_OP_ADD: u8 = 0x00;
const EBPF_ALU_OP_SUB: u8 = 0x10;
const EBPF_ALU_OP_MOV: u8 = 0xb0;

/// Operation selector inside an atomic instruction's `imm` field, and the
/// CMPXCHG value. These mirror `EBPF_ALU_OP_MASK` and
/// `EBPF_ATOMIC_OP_CMPXCHG & ~EBPF_ATOMIC_OP_FETCH` in the JIT backends; the
/// comparison is written the same way the backends switch on `imm` so the
/// analysis and the emitted code always agree on which ops are CMPXCHG.
const EBPF_ATOMIC_OP_MASK: i32 = 0xf0;
const EBPF_ATOMIC_OP_CMPXCHG: i32 = 0xf0;

const EBPF_OP_LDDW: u8 = EBPF_CLS_LD | 0x18; // LD | IMM | DW
const EBPF_OP_JA: u8 = EBPF_CLS_JMP; // JMP | JA (mode 0)
const EBPF_OP_JA32: u8 = EBPF_CLS_JMP32;
const EBPF_OP_CALL: u8 = EBPF_CLS_JMP | 0x80; // JMP | CALL
const EBPF_OP_EXIT: u8 = EBPF_CLS_JMP | 0x90; // JMP | EXIT

/// Abstract value tracked per register. The lattice top is [`RegKind::Uninit`]
/// (no information / unreachable); the meet of two distinct concrete kinds is
/// [`RegKind::Unknown`] (bottom for routing purposes).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub(crate) enum RegKind {
  Uninit,
  Stack(StackKind),
  Data,
  Scalar,
  Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub(crate) enum StackKind {
  Current(Option<i32>),
  Foreign,
}

impl RegKind {
  /// Greatest-lower-bound used at control-flow joins.
  fn meet(self, other: RegKind) -> RegKind {
    match (self, other) {
      (a, b) if a == b => a,
      (RegKind::Uninit, b) => b,
      (a, RegKind::Uninit) => a,
      (RegKind::Stack(a), RegKind::Stack(b)) => match (a, b) {
        (StackKind::Current(a), StackKind::Current(b)) => {
          if a == b {
            RegKind::Stack(StackKind::Current(a))
          } else {
            RegKind::Stack(StackKind::Current(None))
          }
        }
        (StackKind::Foreign, StackKind::Foreign) => RegKind::Stack(StackKind::Foreign),
        _ => RegKind::Stack(StackKind::Current(None)),
      },
      _ => RegKind::Unknown,
    }
  }

  fn region(self) -> u8 {
    match self {
      RegKind::Stack(_) => REGION_STACK,
      RegKind::Data => REGION_DATA,
      _ => REGION_UNKNOWN,
    }
  }

  fn is_pointer(self) -> bool {
    matches!(self, RegKind::Stack(_) | RegKind::Data)
  }

  fn is_stack(self) -> bool {
    matches!(self, RegKind::Stack(_))
  }

  fn foreign_for_call(self) -> Self {
    match self {
      RegKind::Stack(_) => RegKind::Stack(StackKind::Foreign),
      other => other,
    }
  }

  fn aliases_current_stack(self) -> bool {
    !matches!(self, RegKind::Stack(StackKind::Foreign))
  }
}

/// Index of the read-only frame pointer register `R10`.
const R10: usize = 10;

/// Abstract state at a program point: the kind of every register plus the kinds
/// of values spilled to `R10`-relative stack slots (keyed by byte offset).
/// Spill/fill tracking lets the analysis follow pointers that the compiler
/// round-trips through the stack (e.g. argument spills), which is the dominant
/// pattern in `-O2` BPF output. Absent register/slot entries are `Uninit` (top).
#[derive(Clone, PartialEq, Eq)]
struct State {
  regs: [RegKind; NUM_REGS],
  slots: std::collections::BTreeMap<i32, RegKind>,
}

impl State {
  fn top() -> State {
    State {
      regs: [RegKind::Uninit; NUM_REGS],
      slots: std::collections::BTreeMap::new(),
    }
  }

  /// Per-element meet with `other`; returns whether `self` changed.
  fn meet_from(&mut self, other: &State) -> bool {
    let mut changed = false;
    for r in 0..NUM_REGS {
      let merged = self.regs[r].meet(other.regs[r]);
      if merged != self.regs[r] {
        self.regs[r] = merged;
        changed = true;
      }
    }
    // Meet slots over the union of keys; an absent slot is Uninit (top).
    for (&off, &k) in &other.slots {
      let cur = self.slots.get(&off).copied().unwrap_or(RegKind::Uninit);
      let merged = cur.meet(k);
      if merged != cur {
        self.slots.insert(off, merged);
        changed = true;
      }
    }
    changed
  }

  /// Marks every tracked slot `Unknown` after a store/call that may alias the
  /// stack at an offset we cannot pin down. Entries are set rather than removed
  /// so the imprecision survives control-flow joins.
  fn invalidate_slots(&mut self) {
    for v in self.slots.values_mut() {
      *v = RegKind::Unknown;
    }
  }

  /// Invalidates tracked R10-relative spill slots overlapped by a stack write.
  /// If the write address is not a known frame-relative range, invalidate all
  /// tracked slots because any spill may have been overwritten.
  fn invalidate_stack_write(&mut self, start: Option<i32>, width: usize) {
    let Some(start) = start else {
      self.invalidate_slots();
      return;
    };
    let Some(end) = start.checked_add(width as i32) else {
      self.invalidate_slots();
      return;
    };

    for (&slot_off, value) in self.slots.iter_mut() {
      let slot_start = slot_off as i32;
      let Some(slot_end) = slot_start.checked_add(8) else {
        *value = RegKind::Unknown;
        continue;
      };
      if start < slot_end && slot_start < end {
        *value = RegKind::Unknown;
      }
    }
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub(crate) struct PointerSignature {
  regs: [RegKind; NUM_REGS],
}

impl PointerSignature {
  pub(crate) fn entry() -> Self {
    // The entry trampoline zeroes every eBPF register except `R1` (the ctx) and
    // `R10` (the frame pointer), so everything else provably holds the scalar 0.
    let mut regs = [RegKind::Scalar; NUM_REGS];
    regs[1] = RegKind::Stack(StackKind::Current(None));
    regs[R10] = RegKind::Stack(StackKind::Current(Some(0)));
    Self { regs }
  }

  fn apply_to_state(self, state: &mut State) {
    state.regs = self.regs;
    state.regs[R10] = RegKind::Stack(StackKind::Current(Some(0)));
  }

  fn from_state(state: &State) -> Self {
    let mut regs = state.regs;
    for (reg, kind) in regs.iter_mut().enumerate() {
      if reg != R10 {
        *kind = kind.foreign_for_call();
      }
    }
    regs[R10] = RegKind::Stack(StackKind::Current(Some(0)));
    Self { regs }
  }

  /// Drops every register the callee cannot observe, so two call sites that
  /// differ only in the caller's incidental live state share one specialization.
  ///
  /// A register outside `mask` is not live-in to the callee (see
  /// [`function_live_in`]), meaning it is overwritten before any read on every
  /// path. Replacing it with `Unknown` therefore changes no hint, no unresolved
  /// access and no signature the callee passes on - it only collapses
  /// signatures that would have produced identical analyses.
  fn masked(mut self, mask: RegMask) -> Self {
    for (reg, kind) in self.regs.iter_mut().enumerate() {
      if reg != R10 && mask & (1 << reg) == 0 {
        *kind = RegKind::Unknown;
      }
    }
    self
  }

  #[cfg(any(test, feature = "testing"))]
  pub(crate) fn from_regs_for_testing(regs: [RegKind; NUM_REGS]) -> Self {
    Self { regs }
  }
}

#[derive(Clone, Copy)]
struct Inst {
  opcode: u8,
  dst: usize,
  src: usize,
  offset: i16,
  imm: i32,
}

fn decode(slot: &[u8]) -> Inst {
  Inst {
    opcode: slot[0],
    dst: (slot[1] & 0x0f) as usize,
    src: (slot[1] >> 4) as usize,
    offset: i16::from_le_bytes([slot[2], slot[3]]),
    imm: i32::from_le_bytes([slot[4], slot[5], slot[6], slot[7]]),
  }
}

fn access_width(opcode: u8) -> usize {
  match opcode & 0x18 {
    0x00 => 4, // W
    0x08 => 2, // H
    0x10 => 1, // B
    0x18 => 8, // DW
    _ => 8,
  }
}

fn stack_access_start(base: RegKind, offset: i16) -> Option<i32> {
  let RegKind::Stack(StackKind::Current(Some(base_off))) = base else {
    return None;
  };
  base_off.checked_add(offset as i32)
}

/// Result of the region analysis for one code section.
#[cfg(any(test, feature = "testing"))]
pub struct RegionAnalysis {
  /// Per-instruction-slot load region hint for the JIT (`REGION_*`). Non-load
  /// slots are [`REGION_UNKNOWN`].
  #[allow(dead_code)]
  pub hints: Vec<u8>,
  /// Slots of memory-access instructions (load, store, atomic) whose pointer
  /// could not be resolved to a single region. Empty iff every access is
  /// statically routable.
  pub unresolved: Vec<usize>,
}

pub(crate) struct FunctionRegionAnalysis {
  pub(crate) hints: Vec<u8>,
  pub(crate) unresolved: Vec<usize>,
  pub(crate) call_signatures: std::collections::HashMap<usize, PointerSignature>,
}

/// Analyzes the pointer region of every memory access in one code section.
///
/// `code` is the relocated bytecode (8 bytes per slot, matching uBPF's
/// `vm->insts` indexing; `lddw` occupies two slots). `data_lo`/`data_hi` are the
/// guest data region bounds used to recognize relocated data pointers.
#[cfg(any(test, feature = "testing"))]
pub fn analyze(code: &[u8], data_lo: u64, data_hi: u64) -> RegionAnalysis {
  let num_slots = code.len() / 8;
  let mut hints = vec![REGION_UNKNOWN; num_slots];
  let mut unresolved = Vec::new();
  if num_slots == 0 {
    return RegionAnalysis { hints, unresolved };
  }

  // Forward dataflow to a fixpoint over the instruction-slot CFG.
  let mut states: Vec<State> = (0..num_slots).map(|_| State::top()).collect();
  let mut reached = vec![false; num_slots];
  // Entry: R1 holds ctx (points into the guest stack), R10 is the frame pointer,
  // and the entry trampoline zeroed everything else.
  states[0].regs = [RegKind::Scalar; NUM_REGS];
  states[0].regs[1] = RegKind::Stack(StackKind::Current(None));
  states[0].regs[R10] = RegKind::Stack(StackKind::Current(Some(0)));
  reached[0] = true;

  let mut worklist: Vec<usize> = vec![0];
  let mut on_list = vec![false; num_slots];
  on_list[0] = true;

  while let Some(pc) = worklist.pop() {
    on_list[pc] = false;
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    let lddw_addr = lddw_full_imm(code, pc, &inst);
    let out = transfer(&states[pc], &inst, lddw_addr, data_lo, data_hi);

    for succ in successors(pc, &inst, num_slots) {
      let was_reached = reached[succ];
      reached[succ] = true;
      let changed = states[succ].meet_from(&out);
      if (!was_reached || changed) && !on_list[succ] {
        on_list[succ] = true;
        worklist.push(succ);
      }
    }
  }

  // Classify every memory access from the converged entry state of its slot.
  // Loads additionally produce a JIT routing hint; stores/atomics are always
  // confined to the stack by the backend but are still checked for strict-mode
  // analyzability. The second slot of a `lddw` has opcode 0 and is skipped.
  for pc in 0..num_slots {
    if !reached[pc] {
      continue;
    }
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    let cls = inst.opcode & EBPF_CLS_MASK;
    let base = match cls {
      EBPF_CLS_LDX => inst.src,               // load: pointer is src
      EBPF_CLS_ST | EBPF_CLS_STX => inst.dst, // store/atomic: pointer is dst
      _ => continue,
    };
    let region = states[pc].regs[base].region();
    if cls == EBPF_CLS_LDX {
      hints[pc] = region;
    }
    if region == REGION_UNKNOWN {
      unresolved.push(pc);
    }
  }

  RegionAnalysis { hints, unresolved }
}

pub(crate) fn analyze_function(
  code: &[u8],
  start_pc: usize,
  end_pc: usize,
  incoming: PointerSignature,
  data_lo: u64,
  data_hi: u64,
  layout: &crate::function_analysis::FunctionLayout,
) -> FunctionRegionAnalysis {
  let num_slots = code.len() / 8;
  let mut hints = vec![REGION_UNKNOWN; num_slots];
  let mut unresolved = Vec::new();
  let mut call_signatures = std::collections::HashMap::new();
  if start_pc >= end_pc || end_pc > num_slots {
    return FunctionRegionAnalysis {
      hints,
      unresolved,
      call_signatures,
    };
  }

  let mut states: Vec<State> = (0..num_slots).map(|_| State::top()).collect();
  let mut reached = vec![false; num_slots];
  incoming.apply_to_state(&mut states[start_pc]);
  reached[start_pc] = true;

  let mut worklist = vec![start_pc];
  let mut on_list = vec![false; num_slots];
  on_list[start_pc] = true;

  while let Some(pc) = worklist.pop() {
    on_list[pc] = false;
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    if inst.opcode == EBPF_OP_CALL && inst.src == 1 {
      let target = (pc as i64 + 1 + inst.imm as i64) as usize;
      let mask = layout
        .pc_to_func
        .get(target)
        .and_then(|&callee| layout.arg_masks.get(callee).copied())
        .unwrap_or(ALL_SIGNATURE_REGS);
      call_signatures.insert(pc, PointerSignature::from_state(&states[pc]).masked(mask));
    }
    let lddw_addr = lddw_full_imm(code, pc, &inst);
    let out = transfer(&states[pc], &inst, lddw_addr, data_lo, data_hi);

    for succ in function_successors(pc, &inst, num_slots, start_pc, end_pc) {
      let was_reached = reached[succ];
      reached[succ] = true;
      let changed = states[succ].meet_from(&out);
      if (!was_reached || changed) && !on_list[succ] {
        on_list[succ] = true;
        worklist.push(succ);
      }
    }
  }

  for pc in start_pc..end_pc {
    if !reached[pc] {
      continue;
    }
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    let cls = inst.opcode & EBPF_CLS_MASK;
    let base = match cls {
      EBPF_CLS_LDX => inst.src,
      EBPF_CLS_ST | EBPF_CLS_STX => inst.dst,
      _ => continue,
    };
    let region = states[pc].regs[base].region();
    if cls == EBPF_CLS_LDX {
      hints[pc] = region;
    }
    if region == REGION_UNKNOWN {
      unresolved.push(pc);
    }
  }

  FunctionRegionAnalysis {
    hints,
    unresolved,
    call_signatures,
  }
}

/// Mask over the registers a [`PointerSignature`] can carry (`R0`-`R9`). `R10`
/// is never included: it is the frame pointer, fixed to
/// `Stack(Current(Some(0)))` at every function entry regardless of the caller.
pub(crate) type RegMask = u16;

/// Every register a signature can carry.
pub(crate) const ALL_SIGNATURE_REGS: RegMask = 0x03ff;

/// Registers a helper call reads (`R1`-`R5`) and the ones any call leaves
/// clobbered (`R0`-`R5`), matching how [`transfer`] models `EBPF_OP_CALL`.
const HELPER_ARG_REGS: RegMask = 0b011_1110;
const CALL_CLOBBERED_REGS: RegMask = 0b011_1111;

fn reg_bit(reg: usize) -> RegMask {
  if reg < R10 {
    1 << reg
  } else {
    0
  }
}

/// Registers `inst` reads and writes.
///
/// `uses` is taken from the instruction encoding — every register the opcode
/// reads, whether or not [`transfer`] happens to consult its kind. That is more
/// than strictly necessary (a 32-bit ALU op or a comparison cannot change a
/// register's region), but it keeps this sound under any future change to
/// `transfer` that starts reading a register the instruction names.
///
/// `defs` must be a *subset* of what the instruction actually overwrites: a def
/// kills liveness, so over-claiming one would drop a register from the mask
/// that the callee can still observe. Fetching atomics write `src` (and
/// CMPXCHG writes `R0`) conditionally on the operation selector, so they claim
/// no definition at all.
fn uses_and_defs(inst: &Inst, callee_live_in: RegMask) -> (RegMask, RegMask) {
  match inst.opcode & EBPF_CLS_MASK {
    // Only LDDW reaches here; it materializes a constant into dst.
    EBPF_CLS_LD => (0, reg_bit(inst.dst)),
    EBPF_CLS_LDX => (reg_bit(inst.src), reg_bit(inst.dst)),
    EBPF_CLS_ST => (reg_bit(inst.dst), 0),
    EBPF_CLS_STX => {
      let is_atomic = (inst.opcode & 0xe0) == 0xc0;
      let mut uses = reg_bit(inst.dst) | reg_bit(inst.src);
      if is_atomic {
        uses |= reg_bit(0);
      }
      (uses, 0)
    }
    EBPF_CLS_ALU | EBPF_CLS_ALU64 => {
      let src = if inst.opcode & EBPF_SRC_REG != 0 {
        reg_bit(inst.src)
      } else {
        0
      };
      if inst.opcode & EBPF_ALU_OP_MASK == EBPF_ALU_OP_MOV {
        (src, reg_bit(inst.dst))
      } else {
        (src | reg_bit(inst.dst), reg_bit(inst.dst))
      }
    }
    EBPF_CLS_JMP | EBPF_CLS_JMP32 => {
      if inst.opcode == EBPF_OP_EXIT {
        // `exit` hands the callee's R0 back to its caller, but the caller
        // models the result of any call as a fresh scalar (see `transfer`), so
        // an incoming R0 kind is never observable through a return. Counting R0
        // as a use here would make it live-in for every function with a path
        // that does not assign it - which is exactly the incidental caller
        // state this mask exists to drop.
        (0, 0)
      } else if inst.opcode == EBPF_OP_CALL {
        match inst.src {
          0 => (HELPER_ARG_REGS, CALL_CLOBBERED_REGS),
          // A local callee sees the caller's whole register file: R1-R5 are
          // passed, R6-R9 are preserved across the call by the caller's stub,
          // and R0 survives it. So the call reads whatever the callee reads.
          1 => (callee_live_in, CALL_CLOBBERED_REGS),
          _ => (0, 0),
        }
      } else if inst.opcode == EBPF_OP_JA || inst.opcode == EBPF_OP_JA32 {
        (0, 0)
      } else {
        let src = if inst.opcode & EBPF_SRC_REG != 0 {
          reg_bit(inst.src)
        } else {
          0
        };
        (src | reg_bit(inst.dst), 0)
      }
    }
    _ => (0, 0),
  }
}

/// Registers whose incoming kind the function `[start_pc, end_pc)` can observe,
/// i.e. those it may read before writing, transitively through its callees.
///
/// This is what makes per-signature specialization affordable. A signature is
/// the caller's whole abstract register file at the call site, so without a
/// mask a callee gets a fresh specialization every time the caller's incidental
/// live state differs - a stale `R2` from an earlier helper call, or a pointer
/// the caller happens to be holding in `R6` - even when the callee's own
/// analysis could not possibly differ. Masking a register that is not live-in
/// to `Unknown` is free: it is overwritten before any read on every path, so no
/// hint, no unresolved access and no callee signature can depend on it.
///
/// `callee_live_in` maps a local call's target PC to that callee's mask, so
/// callers must compute masks bottom-up over the call graph (which is a DAG -
/// recursion is rejected at load).
pub(crate) fn function_live_in(
  code: &[u8],
  start_pc: usize,
  end_pc: usize,
  callee_live_in: &dyn Fn(usize) -> RegMask,
) -> RegMask {
  let num_slots = code.len() / 8;
  if start_pc >= end_pc || end_pc > num_slots {
    return ALL_SIGNATURE_REGS;
  }

  // Only reachable instructions can read anything; walking dead code would add
  // uses that no execution can perform.
  let mut reachable = vec![false; num_slots];
  let mut pending = vec![start_pc];
  reachable[start_pc] = true;
  while let Some(pc) = pending.pop() {
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    for succ in function_successors(pc, &inst, num_slots, start_pc, end_pc) {
      if !reachable[succ] {
        reachable[succ] = true;
        pending.push(succ);
      }
    }
  }

  // Backward liveness to a fixpoint. Reverse instruction order converges in a
  // couple of passes for the reducible CFGs the loader accepts.
  let mut live = vec![0 as RegMask; num_slots];
  loop {
    let mut changed = false;
    for pc in (start_pc..end_pc).rev() {
      if !reachable[pc] {
        continue;
      }
      let inst = decode(&code[pc * 8..pc * 8 + 8]);
      let mut live_out = 0;
      for succ in function_successors(pc, &inst, num_slots, start_pc, end_pc) {
        live_out |= live[succ];
      }
      let callee = if inst.opcode == EBPF_OP_CALL && inst.src == 1 {
        callee_live_in((pc as i64 + 1 + inst.imm as i64) as usize)
      } else {
        0
      };
      let (uses, defs) = uses_and_defs(&inst, callee);
      let next = uses | (live_out & !defs);
      if next != live[pc] {
        live[pc] = next;
        changed = true;
      }
    }
    if !changed {
      break;
    }
  }

  live[start_pc]
}

/// Full 64-bit immediate of a `lddw` (low half in `inst`, high half in the next
/// slot's imm field). Returns 0 for non-`lddw` instructions.
fn lddw_full_imm(code: &[u8], pc: usize, inst: &Inst) -> u64 {
  if inst.opcode != EBPF_OP_LDDW || (pc + 2) * 8 > code.len() {
    return 0;
  }
  let hi = decode(&code[(pc + 1) * 8..(pc + 1) * 8 + 8]).imm;
  (inst.imm as u32 as u64) | ((hi as u32 as u64) << 32)
}

/// Successor slots in the CFG. Slot indices, not byte offsets.
fn successors(pc: usize, inst: &Inst, num_slots: usize) -> Vec<usize> {
  let fallthrough = if inst.opcode == EBPF_OP_LDDW {
    pc + 2
  } else {
    pc + 1
  };
  let cls = inst.opcode & EBPF_CLS_MASK;
  let mut out = Vec::new();
  let mut push = |s: usize| {
    if s < num_slots {
      out.push(s);
    }
  };

  if cls == EBPF_CLS_JMP || cls == EBPF_CLS_JMP32 {
    if inst.opcode == EBPF_OP_EXIT {
      return out;
    }
    if inst.opcode == EBPF_OP_CALL {
      match inst.src {
        // Helper call: returns to the next instruction.
        0 => push(fallthrough),
        // Local eBPF call: returns to the next instruction and also enters the
        // callee at pc+imm+1. The callee inherits the (clobbered) caller state,
        // which preserves R10=Stack and the callee-saved R6-R9, so callee
        // stack accesses remain analyzable; arg-derived accesses (R1-R5, now
        // Unknown) are conservatively unresolved.
        1 => {
          push(fallthrough);
          push((pc as i64 + 1 + inst.imm as i64) as usize);
        }
        // Other forms branch to exit; no fallthrough.
        _ => {}
      }
      return out;
    }
    // JA32 is the only jump whose target is the 32-bit imm; every other jump
    // (JA and all conditional JMP/JMP32 forms) uses the 16-bit offset. This
    // matches how the JIT/linker resolve branch targets.
    let target = if inst.opcode == EBPF_OP_JA32 {
      pc as i64 + 1 + inst.imm as i64
    } else {
      pc as i64 + 1 + inst.offset as i64
    } as usize;
    push(target);
    if inst.opcode != EBPF_OP_JA && inst.opcode != EBPF_OP_JA32 {
      push(fallthrough); // conditional branch also falls through
    }
    return out;
  }

  push(fallthrough);
  out
}

fn function_successors(
  pc: usize,
  inst: &Inst,
  num_slots: usize,
  start_pc: usize,
  end_pc: usize,
) -> Vec<usize> {
  let mut succs = successors(pc, inst, num_slots);
  if inst.opcode == EBPF_OP_CALL && inst.src == 1 {
    let fallthrough = pc + 1;
    succs.clear();
    if fallthrough < num_slots {
      succs.push(fallthrough);
    }
  }
  succs
    .into_iter()
    .filter(|&succ| succ >= start_pc && succ < end_pc)
    .collect()
}

/// Abstract transfer function: register/slot state after executing `inst`.
fn transfer(in_state: &State, inst: &Inst, lddw_addr: u64, data_lo: u64, data_hi: u64) -> State {
  let mut s = in_state.clone();
  let cls = inst.opcode & EBPF_CLS_MASK;

  match cls {
    EBPF_CLS_LD => {
      // Only LDDW reaches here (LD|IMM|DW). It materializes a 64-bit constant;
      // a relocated data pointer falls inside [data_lo, data_hi).
      if inst.opcode == EBPF_OP_LDDW {
        s.regs[inst.dst] = if lddw_addr >= data_lo && lddw_addr < data_hi {
          RegKind::Data
        } else {
          RegKind::Scalar
        };
      } else {
        s.regs[inst.dst] = RegKind::Unknown;
      }
    }
    EBPF_CLS_LDX => {
      // A value loaded from memory is a scalar for routing purposes. Treating
      // it as Scalar (rather than Unknown) lets it serve as an index into a
      // known pointer — `ptr + loaded_index` keeps the pointer's region — which
      // is both common (e.g. `literal[i]`) and safe: using a loaded value
      // directly as a pointer base still yields Scalar (unroutable), and the
      // retained single-region bounds check backstops any mis-sized index.
      //
      // A fill off R10 recovers a spilled *pointer* only when a concrete
      // Stack/Data kind is still tracked at that offset. An absent, scalar, or
      // call-invalidated slot reads back as a scalar — e.g. a byte loaded from a
      // stack buffer after a helper call, which must not poison later pointer
      // arithmetic that uses it as an index.
      s.regs[inst.dst] = if inst.src == R10 {
        match s.slots.get(&(inst.offset as i32)).copied() {
          Some(k) if k.is_pointer() => k,
          _ => RegKind::Scalar,
        }
      } else {
        RegKind::Scalar
      };
    }
    EBPF_CLS_ST | EBPF_CLS_STX => {
      let is_atomic = cls == EBPF_CLS_STX && (inst.opcode & 0xe0) == 0xc0;
      // Value being stored: ST writes an immediate (scalar); STX writes a reg.
      let value = if cls == EBPF_CLS_ST {
        RegKind::Scalar
      } else {
        s.regs[inst.src]
      };
      let width = access_width(inst.opcode);
      let stack_base = if inst.dst == R10 {
        RegKind::Stack(StackKind::Current(Some(0)))
      } else {
        s.regs[inst.dst]
      };
      if stack_base.is_stack() {
        if stack_base.aliases_current_stack() {
          let start = stack_access_start(stack_base, inst.offset);
          s.invalidate_stack_write(start, width);
        }
        let stored = if is_atomic {
          RegKind::Unknown
        } else if value == RegKind::Uninit {
          RegKind::Unknown
        } else {
          value
        };
        if !is_atomic && width == 8 {
          if let Some(start) = stack_access_start(stack_base, inst.offset) {
            s.slots.insert(start, stored);
          }
        }
      } else if s.regs[inst.dst] != RegKind::Data {
        // A store through an unknown/scalar base may alias an untracked stack
        // slot; conservatively invalidate all tracked slots.
        s.invalidate_slots();
      }
      if is_atomic {
        // An atomic fetch writes the previous value into src.
        s.regs[inst.src] = RegKind::Unknown;
        if inst.imm & EBPF_ATOMIC_OP_MASK == EBPF_ATOMIC_OP_CMPXCHG {
          // CMPXCHG is the exception: it leaves src alone and writes the
          // previous memory contents into R0 instead (x86-64 lowers it to
          // `lock cmpxchg`, whose comparand is RAX; the arm64 backend mirrors
          // that). The guest chooses those contents, so R0 must not keep the
          // provenance it had before the instruction.
          s.regs[0] = RegKind::Unknown;
        }
      }
    }
    EBPF_CLS_ALU => {
      // 32-bit ALU result cannot be a valid 64-bit pointer.
      s.regs[inst.dst] = RegKind::Scalar;
    }
    EBPF_CLS_ALU64 => {
      let op = inst.opcode & EBPF_ALU_OP_MASK;
      let is_reg = inst.opcode & EBPF_SRC_REG != 0;
      match op {
        EBPF_ALU_OP_MOV => {
          s.regs[inst.dst] = if is_reg {
            match s.regs[inst.src] {
              RegKind::Uninit => RegKind::Unknown,
              k => k,
            }
          } else {
            RegKind::Scalar
          };
        }
        EBPF_ALU_OP_ADD => {
          s.regs[inst.dst] = if is_reg {
            add_kinds(s.regs[inst.dst], s.regs[inst.src])
          } else {
            add_imm_kind(s.regs[inst.dst], inst.imm)
          };
        }
        EBPF_ALU_OP_SUB => {
          s.regs[inst.dst] = if is_reg {
            sub_kinds(s.regs[inst.dst], s.regs[inst.src])
          } else {
            add_imm_kind(s.regs[inst.dst], inst.imm.wrapping_neg())
          };
        }
        // All other 64-bit ALU ops (mul/div/and/or/xor/shifts/neg/mod/end)
        // are conservatively scalars for routing purposes.
        _ => s.regs[inst.dst] = RegKind::Scalar,
      }
    }
    EBPF_CLS_JMP | EBPF_CLS_JMP32 => {
      if inst.opcode == EBPF_OP_CALL {
        // Helper/local call: R0 is the return value, R1-R5 are caller-saved and
        // clobbered; R6-R10 are preserved. Keep tracked stack spill provenance
        // across calls: generated code commonly spills stack/data pointers,
        // calls a helper, then reloads those pointers for later buffer work.
        // If a helper/callee actually overwrites a pointer spill, the emitted
        // single-region bounds translation still protects the access; the worst
        // case is a spurious fault from a stale region hint.
        //
        // The return value is treated as a scalar: helpers return handles,
        // lengths, and status codes, so a returned value commonly indexes a
        // pointer (`buf + helper_len`) and must keep that pointer's region.
        // Using a returned value directly as a pointer base still yields Scalar
        // (unroutable), and the single-region bounds check backstops any
        // out-of-range index, so this stays safe.
        s.regs[0] = RegKind::Scalar;
        for r in 1..=5 {
          s.regs[r] = RegKind::Unknown;
        }
      }
    }
    _ => {}
  }

  s
}

/// `ptr + scalar` preserves the pointer's region; `scalar + scalar` is scalar.
fn add_kinds(a: RegKind, b: RegKind) -> RegKind {
  match (a, b) {
    (RegKind::Stack(_), RegKind::Scalar) | (RegKind::Scalar, RegKind::Stack(_)) => match (a, b) {
      (RegKind::Stack(StackKind::Foreign), _) | (_, RegKind::Stack(StackKind::Foreign)) => {
        RegKind::Stack(StackKind::Foreign)
      }
      _ => RegKind::Stack(StackKind::Current(None)),
    },
    (RegKind::Data, RegKind::Scalar) | (RegKind::Scalar, RegKind::Data) => RegKind::Data,
    (RegKind::Scalar, RegKind::Scalar) => RegKind::Scalar,
    _ => RegKind::Unknown,
  }
}

/// `ptr - scalar` preserves the region; `ptr - ptr` (same region) is a scalar.
fn sub_kinds(a: RegKind, b: RegKind) -> RegKind {
  match (a, b) {
    (RegKind::Stack(StackKind::Foreign), RegKind::Scalar) => RegKind::Stack(StackKind::Foreign),
    (RegKind::Stack(_), RegKind::Scalar) => RegKind::Stack(StackKind::Current(None)),
    (RegKind::Data, RegKind::Scalar) => RegKind::Data,
    (RegKind::Stack(_), RegKind::Stack(_)) | (RegKind::Data, RegKind::Data) => RegKind::Scalar,
    (RegKind::Scalar, RegKind::Scalar) => RegKind::Scalar,
    _ => RegKind::Unknown,
  }
}

/// Adding an immediate preserves region; for known stack aliases, also update
/// the frame-relative offset.
fn add_imm_kind(a: RegKind, imm: i32) -> RegKind {
  match a {
    RegKind::Stack(StackKind::Current(Some(off))) => {
      RegKind::Stack(StackKind::Current(off.checked_add(imm)))
    }
    RegKind::Stack(StackKind::Current(None)) => RegKind::Stack(StackKind::Current(None)),
    RegKind::Stack(StackKind::Foreign) => RegKind::Stack(StackKind::Foreign),
    RegKind::Data => RegKind::Data,
    RegKind::Scalar => RegKind::Scalar,
    _ => RegKind::Unknown,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // Builders for raw eBPF instruction slots.
  fn slot(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> [u8; 8] {
    let mut s = [0u8; 8];
    s[0] = opcode;
    s[1] = (dst & 0x0f) | (src << 4);
    s[2..4].copy_from_slice(&offset.to_le_bytes());
    s[4..8].copy_from_slice(&imm.to_le_bytes());
    s
  }

  fn flatten(slots: &[[u8; 8]]) -> Vec<u8> {
    slots.iter().flatten().copied().collect()
  }

  const DATA_LO: u64 = 0x10000;
  const DATA_HI: u64 = 0x20000;

  /// `function_live_in` over a whole fragment, with callees reporting `callee`.
  fn live_in(code: &[u8], callee: RegMask) -> RegMask {
    function_live_in(code, 0, code.len() / 8, &|_| callee)
  }

  #[test]
  fn a_register_read_before_it_is_written_is_live_in() {
    let code = flatten(&[
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0), // r0 = *(u64*)(r6)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(live_in(&code, 0), 1 << 6);
  }

  #[test]
  fn a_register_overwritten_before_every_read_is_not_live_in() {
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_MOV, 6, 0, 0, 0), // r6 = 0
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0),              // r0 = *(u64*)(r6)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(live_in(&code, 0), 0);
  }

  #[test]
  fn a_register_a_previous_call_clobbered_is_not_live_in() {
    // The load reads R1, but the local call ahead of it leaves R0-R5 clobbered,
    // so the caller's incoming R1 can never reach it. The callee here reads
    // nothing.
    let code = flatten(&[
      slot(EBPF_OP_CALL, 0, 1, 0, 2),        // call -> slot 3
      slot(EBPF_CLS_LDX | 0x18, 0, 1, 0, 0), // r0 = *(u64*)(r1)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0), // callee
    ]);
    assert_eq!(function_live_in(&code, 0, 3, &|_| 0), 0);
  }

  #[test]
  fn a_call_contributes_whatever_its_callee_reads() {
    let code = flatten(&[
      slot(EBPF_OP_CALL, 0, 1, 0, 1), // call -> slot 2
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0), // callee, reported as reading r7
    ]);
    assert_eq!(function_live_in(&code, 0, 2, &|_| 1 << 7), 1 << 7);
  }

  #[test]
  fn exit_does_not_make_r0_live_in() {
    // A function that returns without assigning R0 hands its caller's R0 back,
    // but the caller models any call's result as a fresh scalar - so the
    // incoming kind is not observable and must not force a specialization.
    // Counting R0 here would put it in the mask of nearly every function.
    let code = flatten(&[slot(EBPF_OP_EXIT, 0, 0, 0, 0)]);
    assert_eq!(live_in(&code, 0), 0);
  }

  #[test]
  fn a_dead_read_does_not_make_a_register_live_in() {
    // The load is unreachable, so no execution can observe r6.
    let code = flatten(&[
      slot(EBPF_OP_JA, 0, 0, 1, 0),          // goto slot 2
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0), // r0 = *(u64*)(r6)  (dead)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(live_in(&code, 0), 0);
  }

  #[test]
  fn a_read_on_either_branch_makes_a_register_live_in() {
    let code = flatten(&[
      slot(EBPF_CLS_JMP | 0x50, 0, 0, 1, 0), // jset r0, 0 -> slot 2
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(EBPF_CLS_LDX | 0x18, 0, 8, 0, 0), // r0 = *(u64*)(r8)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(live_in(&code, 0), 1 << 8 | 1);
  }

  #[test]
  fn stack_load_via_r10_is_routed_to_stack() {
    // r2 = r10; r2 += -8; r0 = *(u64*)(r2 + 0); exit
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 2, 10, 0, 0),
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 2, 0, 0, -8),
      slot(EBPF_CLS_LDX | 0x18, 0, 2, 0, 0), // LDXDW
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[2], REGION_STACK);
  }

  #[test]
  fn ctx_load_via_r1_is_routed_to_stack() {
    // r0 = *(u64*)(r1 + 0); exit  -- r1 is the ctx (calldata on the stack)
    let code = flatten(&[
      slot(EBPF_CLS_LDX | 0x18, 0, 1, 0, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[0], REGION_STACK);
  }

  #[test]
  fn data_pointer_load_is_routed_to_data() {
    // r1 = <data addr> (lddw, 2 slots); r0 = *(u8*)(r1 + 0); exit
    let addr = (DATA_LO + 0x40) as i32;
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 1, 0, 0, addr),
      slot(0, 0, 0, 0, 0),                   // lddw high half
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0), // LDXB
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[2], REGION_DATA);
  }

  #[test]
  fn loaded_pointer_is_unknown() {
    // r2 = *(u64*)(r10 - 8); r0 = *(u64*)(r2 + 0); exit
    // r2 comes from memory, so the second load cannot be classified.
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 2, 10, 0, 0),
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 2, 0, 0, -8),
      slot(EBPF_CLS_LDX | 0x18, 2, 2, 0, 0),
      slot(EBPF_CLS_LDX | 0x18, 0, 2, 0, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[3], REGION_UNKNOWN);
  }

  #[test]
  fn ambiguous_join_is_unknown() {
    // if (r1 == 0) goto +2
    //   r2 = r10           (stack)
    //   goto +1
    // r2 = <data addr lddw low only via mov imm? use lddw>  -> here mimic data
    // We construct: r2 = r10 on one path, r2 stays data on the other, then load.
    // Path A: slot0 cond jump to slot3; slot1 r2=r10; slot2 ja to slot5(load)...
    // Simpler: two predecessors of the load with different kinds.
    let code = flatten(&[
      // 0: if r1 == 0 goto +3 (to slot 4)
      slot(EBPF_CLS_JMP | 0x10, 1, 0, 3, 0), // JEQ_IMM
      // 1: r2 = r10  (stack)
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 2, 10, 0, 0),
      // 2: goto +2 (to slot 5)
      slot(EBPF_OP_JA, 0, 0, 2, 0),
      // 3: padding (unreachable)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      // 4: r2 = 12345 (scalar)
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_MOV, 2, 0, 0, 12345),
      // 5: r0 = *(u64*)(r2 + 0)  -- r2 is Stack on one path, Scalar on the other
      slot(EBPF_CLS_LDX | 0x18, 0, 2, 0, 0),
      // 6: exit
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[5], REGION_UNKNOWN);
  }

  #[test]
  fn spilled_arg_pointer_is_recovered_via_fill() {
    // The -O2 BPF backend spills the argument pointer (R1, ctx => stack) to a
    // stack slot and reloads it before dereferencing:
    //   *(u64*)(r10 - 8) = r1
    //   r1 = *(u64*)(r10 - 8)
    //   r0 = *(u64*)(r1 + 0)
    //   exit
    let code = flatten(&[
      slot(EBPF_CLS_STX | 0x18, 10, 1, -8, 0), // spill r1
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0), // fill r1
      slot(EBPF_CLS_LDX | 0x18, 0, 1, 0, 0),   // deref
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[2], REGION_STACK);
    assert!(result.unresolved.is_empty());
  }

  #[test]
  fn data_pointer_indexed_by_loaded_value_stays_data() {
    // Mirrors the unrolled `zs_strcmp` tail `literal[i]`, where `i` was derived
    // from a byte loaded out of a stack buffer. The loaded value is a scalar
    // index, so `data_ptr + i` must remain routable to the data region.
    let addr = DATA_LO as i32;
    let code = flatten(&[
      slot(EBPF_CLS_LDX | 0x10, 3, 10, -16, 0), // r3 = *(u8*)(r10-16)  [index from stack data]
      slot(EBPF_OP_LDDW, 1, 0, 0, addr),        // r1 = <data literal>
      slot(0, 0, 0, 0, 0),                      // lddw high half
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_ADD, 1, 3, 0, 0), // r1 += r3
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0),    // r0 = *(u8*)(r1)  [literal[i]]
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[4], REGION_DATA);
    assert!(result.unresolved.is_empty());
  }

  #[test]
  fn call_return_used_as_index_keeps_pointer_region() {
    // Mirrors `bp += len; *bp = ...` where `len` is a helper return value. The
    // return is a scalar index, so the store through `stack_ptr + len` stays
    // routable to the stack.
    let code = flatten(&[
      slot(EBPF_OP_CALL, 0, 0, 0, 1), // r0 = helper()  -> scalar
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_ADD, 6, 0, 0, 0), // r6 += r0
      slot(EBPF_CLS_STX | 0x10, 6, 1, 0, 0), // *(u8*)(r6) = r1
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn stack_byte_read_after_call_indexes_data_pointer() {
    // Mirrors the inlined `zs_strcmp(buf, literal)` tail where `buf` was filled
    // by a helper: a byte is loaded from a stack slot after the call and used as
    // the index into the literal. A scalar stack spill must still read back as a
    // scalar, keeping `literal[i]` routable to data.
    let code = flatten(&[
      slot(EBPF_CLS_STX | 0x10, 10, 6, -32, 0), // *(u8*)(r10-32) = r6  (spill a scalar)
      slot(EBPF_OP_CALL, 0, 0, 0, 1),           // call helper
      slot(EBPF_CLS_LDX | 0x10, 2, 10, -32, 0), // r2 = *(u8*)(r10-32)  [byte index]
      slot(EBPF_OP_LDDW, 1, 0, 0, DATA_LO as i32), // r1 = <data literal>
      slot(0, 0, 0, 0, 0),                      // lddw high half
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_ADD, 1, 2, 0, 0), // r1 += r2
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0),    // r0 = *(u8*)(r1)  [literal[i]]
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[6], REGION_DATA);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn spilled_stack_pointer_survives_helper_call() {
    // Mirrors generated Caddy middleware: a stack buffer pointer is spilled,
    // helper calls run, then the pointer is reloaded for later host matching.
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 6, 0, 0, -64),               // r6 = &stack_buf
      slot(EBPF_CLS_STX | 0x18, 10, 6, -8, 0),                            // spill stack pointer
      slot(EBPF_OP_CALL, 0, 0, 0, 1),                                     // helper call
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0),                            // reload stack pointer
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0), // dereference stack buffer
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[5], REGION_STACK);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn spilled_stack_pointer_survives_stack_alias_store() {
    // A write through `r7 = r10 - 64` is a stack-buffer write. It should not
    // erase an unrelated pointer spill that later reloads the same stack buffer
    // pointer.
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 6, 0, 0, -64),               // r6 = &stack_buf
      slot(EBPF_CLS_STX | 0x18, 10, 6, -8, 0),                            // spill stack pointer
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 7, 10, 0, 0), // r7 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 7, 0, 0, -64),               // r7 = &stack_buf
      slot(EBPF_CLS_ST | 0x10, 7, 0, 0, 1),                               // *(u8*)r7 = 1
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0),                            // reload stack pointer
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0), // dereference stack buffer
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[7], REGION_STACK);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn stack_alias_store_invalidates_overlapping_pointer_spill() {
    // The write through `r7 = r10 - 8` overlaps the tracked spill at `r10 - 8`,
    // so reloading that slot must not recover the stale stack pointer.
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 6, 0, 0, -64),               // r6 = &stack_buf
      slot(EBPF_CLS_STX | 0x18, 10, 6, -8, 0),                            // spill stack pointer
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 7, 10, 0, 0), // r7 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 7, 0, 0, -8),                // r7 = &spill
      slot(EBPF_CLS_ST | 0x18, 7, 0, 0, 0),                               // overwrite spill
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0),                            // reload overwritten slot
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0), // stale deref must be unresolved
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[7], REGION_UNKNOWN);
    assert_eq!(result.unresolved, vec![7]);
  }

  #[test]
  fn direct_partial_stack_store_invalidates_pointer_spill() {
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 6, 0, 0, -64),               // r6 = &stack_buf
      slot(EBPF_CLS_STX | 0x18, 10, 6, -8, 0),                            // spill stack pointer
      slot(EBPF_CLS_ST | 0x10, 10, 0, -7, 0), // partial overwrite of spill
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0), // reload overwritten slot
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0),  // stale deref must be unresolved
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[5], REGION_UNKNOWN);
    assert_eq!(result.unresolved, vec![5]);
  }

  #[test]
  fn known_stack_alias_store_updates_pointer_spill() {
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 6, 0, 0, -64),               // r6 = &stack_buf
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 7, 10, 0, 0), // r7 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 7, 0, 0, -8),                // r7 = &spill
      slot(EBPF_CLS_STX | 0x18, 7, 6, 0, 0),                              // spill through alias
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0),                            // reload stack pointer
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0), // dereference stack buffer
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[6], REGION_STACK);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn foreign_stack_store_does_not_invalidate_current_frame_spill() {
    let code = flatten(&[
      slot(EBPF_CLS_STX | 0x18, 10, 1, -8, 0), // spill foreign stack pointer
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 1, 0, 0, 1), // r1 += 1
      slot(EBPF_CLS_ST | 0x10, 1, 0, 0, 0),    // write through foreign stack
      slot(EBPF_CLS_LDX | 0x18, 2, 10, -8, 0), // reload foreign stack pointer
      slot(EBPF_CLS_LDX | 0x10, 0, 2, 0, 0),   // dereference it
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let mut regs = [RegKind::Uninit; NUM_REGS];
    regs[1] = RegKind::Stack(StackKind::Foreign);
    regs[R10] = RegKind::Stack(StackKind::Current(Some(0)));
    let result = analyze_function(
      &code,
      0,
      code.len() / 8,
      PointerSignature { regs },
      DATA_LO,
      DATA_HI,
      &crate::function_analysis::FunctionLayout::unmasked(code.len() / 8),
    );
    assert_eq!(result.hints[4], REGION_STACK);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn ja32_target_follows_imm_not_offset() {
    // JA32 jumps to pc+imm+1. Here imm routes control to the real load (r6 is a
    // stack pointer); the misleading offset=0 would fall onto a poison block
    // that reassigns r6 to a data pointer. The load must be classified from the
    // imm path (stack), not the offset path (data).
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10 (stack)
      slot(EBPF_OP_JA32, 0, 0, 0, 2), // goto slot 4 (pc+imm+1); offset=0 would target slot 2
      slot(EBPF_OP_LDDW, 6, 0, 0, DATA_LO as i32), // poison: r6 = <data> (only reached if offset is used)
      slot(0, 0, 0, 0, 0),                         // lddw high half
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0),       // r0 = *(u64*)(r6)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[4], REGION_STACK);
  }

  #[test]
  fn unresolved_lists_unclassifiable_accesses() {
    // A clean stack load (slot 1) is resolved; a load through a
    // loaded-from-memory pointer (slot 3) is not.
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 2, 10, 0, 0),
      slot(EBPF_CLS_LDX | 0x18, 3, 2, 0, 0), // r3 = *(u64*)(r2)  [resolved: stack]
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 4, 3, 0, 0),
      slot(EBPF_CLS_LDX | 0x18, 0, 4, 0, 0), // r0 = *(u64*)(r4)  [unresolved]
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.unresolved, vec![3]);
  }

  /// `BPF_ATOMIC | CMPXCHG` writes the previous memory contents into R0, so a
  /// data pointer materialized there before the instruction must not survive it.
  #[test]
  fn atomic_cmpxchg_clobbers_r0() {
    const ATOMIC_DW: u8 = EBPF_CLS_STX | 0xc0 | 0x18;
    const CMPXCHG_FETCH: i32 = 0xf1;
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 0, 0, 0, DATA_LO as i32), // r0 = <data>
      slot(0, 0, 0, 0, 0),                         // lddw high half
      slot(ATOMIC_DW, 10, 2, -16, CMPXCHG_FETCH),  // r0 = old(*(u64*)(r10-16))
      slot(EBPF_CLS_LDX | 0x10, 1, 0, 0, 0),       // r1 = *(u8*)(r0)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[3], REGION_UNKNOWN);
    assert_eq!(result.unresolved, vec![3]);
  }

  /// The CMPXCHG rule is narrow: every other atomic writes only `src`, so an
  /// unrelated pointer register stays routable across it.
  #[test]
  fn atomic_fetch_add_leaves_r0_alone() {
    const ATOMIC_DW: u8 = EBPF_CLS_STX | 0xc0 | 0x18;
    const ADD_FETCH: i32 = 0x01;
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 0, 0, 0, DATA_LO as i32),
      slot(0, 0, 0, 0, 0),
      slot(ATOMIC_DW, 10, 2, -16, ADD_FETCH), // r2 = old(...); r0 untouched
      slot(EBPF_CLS_LDX | 0x10, 1, 0, 0, 0),  // r1 = *(u8*)(r0)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[3], REGION_DATA);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn unreachable_memory_accesses_are_not_unresolved() {
    let code = flatten(&[
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(EBPF_CLS_LDX | 0x18, 0, 4, 0, 0), // dead: r0 = *(u64*)(r4)
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert!(result.unresolved.is_empty());
  }
}

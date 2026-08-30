//! Static region analysis for eBPF memory accesses.
//!
//! Classifies the pointer operand of every load, store, and atomic as pointing
//! into the per-invocation stack, the shared data region, or neither
//! ("unknown"). The JIT consumes the result as
//! [`crate::jit::TranslationInputs::hints`], and emits a single-region bounds
//! check and address translation for confidently classified accesses instead of
//! probing both regions.
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
//! single-region bounds check, so a misclassified access can only fault
//! spuriously — never access out of bounds or cross between regions. Accesses that
//! cannot be classified confidently are left `UNKNOWN` and fall back to the
//! original dual-region probe.
//!
//! The analysis is a standard forward dataflow over the instruction-slot CFG
//! with a per-register lattice and a meet at control-flow joins. Local calls
//! add an edge to the callee entry (carrying `R10`/`R6-R9`), so callee stack
//! accesses are analyzed too; argument-derived pointers (`R1-R5`) reach the
//! callee as `Unknown`. Any slot still unreached keeps its registers `Uninit`
//! and yields `UNKNOWN` hints — safe, just unoptimized.

use std::collections::HashMap;

/// Routing hint values shared with the JIT (`JIT_REGION_*` in the backends).
pub const REGION_UNKNOWN: u8 = 0;
pub const REGION_STACK: u8 = 1;
pub const REGION_DATA: u8 = 2;
/// A displacement off an unmodified frame pointer that provably stays inside
/// the guest stack. See [`frame_access`].
pub const REGION_FRAME: u8 = 3;

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
/// The spill map is a persistent red-black tree rather than a plain map so
/// that `State::clone` is O(1) (structural sharing) and every insert is
/// O(log k). A straight-line function with `n` distinct store offsets would
/// otherwise cost Θ(n²) time and retained memory: each instruction clones the
/// whole map and every slot's state keeps its own merged copy. With a
/// persistent map the retained states share their trees, so the analysis
/// stays O(n log n) no matter how many offsets a hostile program invents.
///
/// Invalidation (an unpinnable stack write) is the same shape of trap at one
/// remove: it maps *every* value to the same constant `Unknown`, so rewriting
/// the map per event costs O(k). Instead each entry carries the state's
/// invalidation epoch at write time, and an entry older than the state's
/// current epoch reads as `Unknown`. Whole-map invalidation is then a single
/// epoch bump, O(1), while a spill written after the bump keeps its kind —
/// exactly what eager rewriting would produce.
///
/// The number of distinct spill offsets one state may track is capped at
/// [`MAX_TRACKED_SLOTS`]. The map is pure precision, never soundness — a slot
/// the cap refuses reads back as a scalar and falls back to the JIT's
/// dual-region probe, the same path every untracked slot already takes — and
/// the cap is what bounds a hostile function that invents distinct store
/// offsets: time O(n · M · log M) and a retained node pool of O(n · log M)
/// instead of Θ(n²) time and memory (measured worst case ≈ 0.1 s / 140 MB at
/// M = 32 for a maximum-size program). Real code — including unoptimized
/// builds — stays far below it: three measured objects (redis.sock and two
/// zeroserve variants) peak at 13 distinct offsets per function.
/// How many distinct `R10`-relative spill offsets one state may track.
///
/// See the [`State`] docs for the cost bound and the precision fallback; the
/// value covers everything measured in real builds (max 13 per function,
/// including unoptimized ones) with headroom, while keeping a hostile
/// function's worst case at ~0.1 s / ~140 MB.
const MAX_TRACKED_SLOTS: usize = 32;

#[derive(Clone, PartialEq, Eq)]
struct State {
  regs: [RegKind; NUM_REGS],
  /// Spill slots, keyed by `R10`-relative byte offset. The value is the kind
  /// stored there together with the state's invalidation epoch at write time;
  /// an entry is effectively `Unknown` when its epoch predates
  /// [`State::invalid_epoch`].
  slots: rpds::RedBlackTreeMap<i32, (u64, RegKind)>,
  /// Bumped by [`State::invalidate_slots`]; every entry written before the
  /// current value reads as `Unknown`.
  invalid_epoch: u64,
}

impl State {
  fn top() -> State {
    State {
      regs: [RegKind::Uninit; NUM_REGS],
      slots: rpds::RedBlackTreeMap::new(),
      invalid_epoch: 0,
    }
  }

  /// The kind an entry written at `epoch` with value `kind` currently has.
  fn effective_kind(&self, epoch: u64, kind: RegKind) -> RegKind {
    if epoch >= self.invalid_epoch {
      kind
    } else {
      RegKind::Unknown
    }
  }

  /// Per-element meet with `other`; returns whether `self` changed.
  fn meet_from(&mut self, other: &State, cap_warning_emitted: &mut bool) -> bool {
    let mut changed = false;
    for r in 0..NUM_REGS {
      let merged = self.regs[r].meet(other.regs[r]);
      if merged != self.regs[r] {
        self.regs[r] = merged;
        changed = true;
      }
    }
    // Meet slots over the union of keys; an absent slot is Uninit (top).
    if self.slots.is_empty() {
      // Nothing tracked yet means every key of `other` meets Uninit (top)
      // into itself, so adopt the incoming map wholesale. The clone is O(1)
      // under structural sharing, which is what keeps straight-line analysis
      // linear in the number of distinct spill offsets. The epoch is adopted
      // with it: the entries' epochs are all consistent with `other`'s
      // counter, and `self` having no entries means its own (possibly higher)
      // epoch is irrelevant — it only ever matters for entries, and none
      // survive.
      if !other.slots.is_empty() {
        self.slots = other.slots.clone();
        self.invalid_epoch = other.invalid_epoch;
        changed = true;
      }
    } else {
      for (&off, &(other_epoch, other_kind)) in &other.slots {
        let cur = self
          .slots
          .get(&off)
          .map(|&(e, k)| self.effective_kind(e, k))
          .unwrap_or(RegKind::Uninit);
        let merged = cur.meet(other.effective_kind(other_epoch, other_kind));
        if merged != cur {
          // Cap the map: a key the cap refuses stays untracked (reads as
          // Scalar), the same safe fallback as an absent key. Skipping the
          // insert leaves `changed` false: the state's observable behavior
          // is unchanged, so the fixpoint terminates as before.
          if self.insert_slot(off, (self.invalid_epoch, merged), cap_warning_emitted) {
            changed = true;
          }
        }
      }
    }
    changed
  }

  /// Inserts one spill entry if it is already tracked or the cap has room.
  /// Warns at most once per analysis when a new offset has to be refused.
  fn insert_slot(
    &mut self,
    off: i32,
    entry: (u64, RegKind),
    cap_warning_emitted: &mut bool,
  ) -> bool {
    if self.slots.contains_key(&off) || self.slots.size() < MAX_TRACKED_SLOTS {
      self.slots = self.slots.insert(off, entry);
      return true;
    }

    if !*cap_warning_emitted {
      tracing::warn!(
        max_tracked_slots = MAX_TRACKED_SLOTS,
        spill_offset = off,
        "region analysis spill-slot tracking cap reached; additional offsets will use dynamic \
         region routing"
      );
      *cap_warning_emitted = true;
    }
    false
  }

  /// Marks every tracked slot `Unknown` after a store that may alias the
  /// stack at an offset we cannot pin down. Lazy: bumping the epoch makes
  /// every entry written before it read as `Unknown`, so the map itself is
  /// untouched — O(1) however large it is — and the imprecision still
  /// survives control-flow joins, because the entries remain present.
  fn invalidate_slots(&mut self) {
    self.invalid_epoch += 1;
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

    // Only slots overlapping [start, start + width) can be affected, and
    // overlapping slots are contiguous in offset order, so a range scan
    // replaces a full-map scan: O(log k + overlaps) instead of O(k) per
    // stack write. A hostile straight-line program of distinct-offset
    // stores would otherwise still be quadratic, one full scan per store.
    // The saturating bounds only widen the range at the extremes of i32;
    // every candidate is still re-checked below.
    let affected: Vec<i32> = self
      .slots
      .range((
        std::ops::Bound::Included(start.saturating_sub(7)),
        std::ops::Bound::Included(end.saturating_sub(1)),
      ))
      .filter_map(|(&slot_off, _)| {
        let slot_start = slot_off;
        let Some(slot_end) = slot_start.checked_add(8) else {
          return Some(slot_off);
        };
        if start < slot_end && slot_start < end {
          Some(slot_off)
        } else {
          None
        }
      })
      .collect();
    // Stamp the affected entries with the current epoch and `Unknown`, so
    // they read as invalidated while entries outside the range keep their
    // kinds.
    for off in affected {
      self.slots = self
        .slots
        .insert(off, (self.invalid_epoch, RegKind::Unknown));
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

  /// Drops every register outside `mask`, i.e. every register the callee cannot
  /// observe. See [`function_live_in`] for why that costs no precision.
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

/// Whether `inst`, whose pointer operand is register `base`, is a frame access
/// the JIT may emit with no bounds check at all.
///
/// This is the one hint that removes a runtime check rather than narrowing one,
/// so the conditions are worth stating in full:
///
///  * **The base is `R10` itself**, not a register derived from it. A derived
///    register holds a *guest* address at run time - the backend hands programs
///    the guest frame pointer wherever they read `R10` as a value - so its
///    displacement is not the one a native frame access would use.
///  * **`R10` still holds the frame pointer.** No instruction can assign it and
///    the loader refuses every program that tries, but an assignment would show
///    up here as `Unknown`, so check rather than assume. This is the only part
///    of the claim the backend cannot re-derive for itself.
///  * **The access lies in `[R10 - frame_size, R10)`.** That window is inside
///    the guest stack at every call depth the loader accepts.
///
/// Atomics are excluded: a fetching atomic writes its source register, so it is
/// not purely an access, and the loader refuses the frame-pointer cases anyway.
fn frame_access(state: &State, inst: &Inst, base: usize, frame_size: u16) -> bool {
  if base != R10 || state.regs[R10] != RegKind::Stack(StackKind::Current(Some(0))) {
    return false;
  }
  if inst.opcode & EBPF_CLS_MASK == EBPF_CLS_STX && inst.opcode & 0xe0 == 0xc0 {
    return false;
  }
  let width = access_width(inst.opcode) as i32;
  let offset = inst.offset as i32;
  offset >= -(frame_size as i32) && offset <= -width
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
  /// Per-slot access grouping, parallel to `hints`. See [`PlanEntry`].
  pub(crate) plan: Vec<PlanEntry>,
  pub(crate) unresolved: Vec<usize>,
  pub(crate) call_signatures: std::collections::HashMap<usize, PointerSignature>,
}

/// Analyzes the pointer region of every memory access in one code section.
///
/// `code` is the relocated bytecode, 8 bytes per slot, indexed the same way the
/// JIT indexes it — `lddw` occupies two slots, and the second is not an
/// instruction. `data_lo`/`data_hi` are the guest data region bounds used to
/// recognize relocated data pointers.
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
  let mut cap_warning_emitted = false;

  while let Some(pc) = worklist.pop() {
    on_list[pc] = false;
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    let lddw_addr = lddw_full_imm(code, pc, &inst);
    let out = transfer(
      &states[pc],
      &inst,
      lddw_addr,
      data_lo,
      data_hi,
      &mut cap_warning_emitted,
    );

    for succ in successors(pc, &inst, num_slots) {
      let was_reached = reached[succ];
      reached[succ] = true;
      let changed = states[succ].meet_from(&out, &mut cap_warning_emitted);
      if (!was_reached || changed) && !on_list[succ] {
        on_list[succ] = true;
        worklist.push(succ);
      }
    }
  }

  // Classify every memory access from the converged entry state of its slot.
  // Every access produces the same region-routing hint, independently of
  // whether it reads or writes. Page protection enforces data permissions.
  // The second slot of a `lddw` has opcode 0 and is skipped.
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
    let hint = if frame_access(
      &states[pc],
      &inst,
      base,
      crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
    ) {
      REGION_FRAME
    } else {
      region
    };
    hints[pc] = hint;
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
  frame_size: u16,
) -> FunctionRegionAnalysis {
  let num_slots = code.len() / 8;
  let mut hints = vec![REGION_UNKNOWN; num_slots];
  let mut unresolved = Vec::new();
  let mut call_signatures = std::collections::HashMap::new();
  if start_pc >= end_pc || end_pc > num_slots {
    return FunctionRegionAnalysis {
      hints,
      plan: vec![PlanEntry::default(); num_slots],
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
  let mut cap_warning_emitted = false;

  while let Some(pc) = worklist.pop() {
    on_list[pc] = false;
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    if inst.opcode == EBPF_OP_CALL && (inst.src == 1 || inst.src == 2) {
      let mask = if inst.src == 1 {
        let target = (pc as i64 + 1 + inst.imm as i64) as usize;
        layout
          .pc_to_func
          .get(target)
          .and_then(|&callee| layout.arg_masks.get(callee).copied())
          .unwrap_or(ALL_SIGNATURE_REGS)
      } else {
        // A cross-section callee lives in another section's layout, so its
        // mask is carried here per call site by the whole-program fixed point.
        // The fallback is only reached by a fragment analyzed outside the
        // loader, which has no cross-section call graph to consult.
        layout
          .cross_section_arg_masks
          .get(&pc)
          .copied()
          .unwrap_or(ALL_SIGNATURE_REGS)
      };
      call_signatures.insert(pc, PointerSignature::from_state(&states[pc]).masked(mask));
    }
    let lddw_addr = lddw_full_imm(code, pc, &inst);
    let out = transfer(
      &states[pc],
      &inst,
      lddw_addr,
      data_lo,
      data_hi,
      &mut cap_warning_emitted,
    );

    for succ in function_successors(pc, &inst, num_slots, start_pc, end_pc) {
      let was_reached = reached[succ];
      reached[succ] = true;
      let changed = states[succ].meet_from(&out, &mut cap_warning_emitted);
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
    let hint = if frame_access(&states[pc], &inst, base, frame_size) {
      REGION_FRAME
    } else {
      region
    };
    hints[pc] = hint;
    if region == REGION_UNKNOWN {
      unresolved.push(pc);
    }
  }

  // Grouping runs last: it keys off the hints the loop above just settled.
  let plan = build_access_plan(code, start_pc, end_pc, num_slots, &hints, &reached);

  FunctionRegionAnalysis {
    hints,
    plan,
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
/// `uses` comes from the instruction encoding - every register the opcode
/// reads, whether or not [`transfer`] consults its kind. That is more than
/// strictly necessary, but it stays sound if `transfer` later starts reading a
/// register the instruction names.
///
/// `defs` must be a *subset* of what the instruction overwrites: a def kills
/// liveness, so over-claiming one would drop a register the callee can still
/// observe. Fetching atomics write `src` (and CMPXCHG writes `R0`) conditionally
/// on the operation selector, so they claim no definition at all.
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
          1 | 2 => (callee_live_in, CALL_CLOBBERED_REGS),
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

/// Where a local call sends control, as seen from inside one code section.
///
/// A section-local call names its callee by a displacement this buffer can
/// resolve. A cross-section call cannot: its immediate was zeroed by the
/// linker and its callee lives in another section, so the call *site* is the
/// only handle on it from here, and the caller is the one holding the map from
/// site to callee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum CallSite {
  /// A `src == 1` call entering `target_pc` in this same buffer.
  Local { target_pc: usize },
  /// A linker-tagged `src == 2` call at `call_pc`, whose callee is elsewhere.
  CrossSection { call_pc: usize },
}

/// Registers whose incoming kind the function `[start_pc, end_pc)` can observe,
/// i.e. those it may read before writing, transitively through its callees.
///
/// This is the mask [`PointerSignature::masked`] applies, and it is what keeps
/// per-signature specialization affordable. A signature is the caller's whole
/// abstract register file, so without it a callee is split every time the
/// caller's incidental live state differs - a stale `R2` from an earlier helper
/// call, a pointer the caller happens to be holding in `R6` - and because those
/// registers survive calls, the splits compound down the graph. Masking a
/// register that is not live-in costs no precision: it is overwritten before
/// any read on every path, so no hint, no unresolved access and no onward
/// signature can depend on it.
///
/// `callee_live_in` reports a call site's callee summary. This solves one
/// function against summaries it is *given*; the runtime instead solves every
/// function and every summary together, in [`program_live_in`]. This is kept
/// as the readable statement of the per-function equations, and
/// `program_live_in_agrees_with_the_per_function_solver` pins the two to the
/// same answer.
#[cfg(test)]
pub(crate) fn function_live_in(
  code: &[u8],
  start_pc: usize,
  end_pc: usize,
  callee_live_in: &dyn Fn(CallSite) -> RegMask,
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

  // Backward liveness to a fixpoint, worklist-driven. The all-slots sweep
  // needed one pass per backward edge on a path: a hostile acyclic "ladder"
  // CFG (`ja +1; ja +1; ja -2` repeated) forces ~n/3 passes over all n slots,
  // Θ(n²) — measured ~17 s at the 65535-instruction maximum, inside the
  // non-preemptible load path. Re-processing only predecessors of a changed
  // slot makes every register bit traverse every edge at most once (a
  // `RegMask` has ten signature bits, so a slot can change at most ten
  // times): O(bits · edges), with the same least fixed point the sweep
  // computed. The unit test `worklist_live_in_is_bit_identical_to_the_sweep`
  // pins the two to agree.
  let span = end_pc - start_pc;
  let mut edges = vec![Vec::new(); span];
  let mut predecessors = vec![Vec::new(); span];
  for pc in start_pc..end_pc {
    if !reachable[pc] {
      continue;
    }
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    for succ in function_successors(pc, &inst, num_slots, start_pc, end_pc) {
      edges[pc - start_pc].push(succ);
      predecessors[succ - start_pc].push(pc);
    }
  }
  let mut live = vec![0 as RegMask; num_slots];
  // Seeded in program order so a LIFO worklist starts at the last slot and
  // forward edges converge on the first visit, like the old reverse sweep; a
  // change re-queues only the predecessors it can affect.
  let mut work: Vec<usize> = (start_pc..end_pc).filter(|&pc| reachable[pc]).collect();
  while let Some(pc) = work.pop() {
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    let mut live_out = 0;
    for &succ in &edges[pc - start_pc] {
      live_out |= live[succ];
    }
    let callee = if inst.opcode == EBPF_OP_CALL {
      match inst.src {
        1 => callee_live_in(CallSite::Local {
          target_pc: (pc as i64 + 1 + inst.imm as i64) as usize,
        }),
        2 => callee_live_in(CallSite::CrossSection { call_pc: pc }),
        _ => 0,
      }
    } else {
      0
    };
    let (uses, defs) = uses_and_defs(&inst, callee);
    let next = uses | (live_out & !defs);
    if next != live[pc] {
      live[pc] = next;
      work.extend_from_slice(&predecessors[pc - start_pc]);
    }
  }

  live[start_pc]
}

/// One code section, already partitioned into local functions, as
/// [`program_live_in`] sees it.
pub(crate) struct LiveInSection<'a> {
  pub(crate) code: &'a [u8],
  /// Function start slots, strictly ascending from 0. Function `i` spans
  /// `starts[i]` up to `starts[i + 1]`, or to the end of the section.
  pub(crate) starts: &'a [usize],
  /// The function owning each slot, as `FunctionLayout::pc_to_func`.
  pub(crate) pc_to_func: &'a [usize],
}

/// A call site whose callee the caller's own bytes cannot name: the linker
/// zeroed its immediate and identified the callee in metadata instead.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CrossSectionCallSite {
  pub(crate) caller_section: usize,
  pub(crate) call_pc: usize,
  pub(crate) callee_section: usize,
  pub(crate) callee_function: usize,
}

/// Least fixed point of the live-in equations over every function in the
/// program at once. One mask per function, per section, in input order.
///
/// # Why this is one flat solve and not a solve per function
///
/// The equations are two-level only in appearance. A function's mask *is* the
/// liveness of its own entry slot, and a call site's `uses` *is* the mask of
/// its callee's entry slot. Written out, that is a single monotone backward
/// dataflow problem over every slot in the program whose only unusual edge
/// runs from a call site to its callee's entry.
///
/// Solving it as a per-function inner fixed point wrapped in a per-function
/// outer one is what made it quadratic. The inner solve starts from nothing
/// every time any callee's mask grows, and each restart costs the whole
/// function, so a function with `m` callees whose masks settle one at a time is
/// re-analyzed `m` times at O(span) each. A caller of a chain of `m` functions
/// is then Θ(m · span), and no property of the call graph bounds that below the
/// size of the program — condensing the graph into strongly connected
/// components would fix the chain but not a cycle spanning the same functions.
///
/// Flattened, nothing restarts because nothing is discarded between visits.
/// Every slot's liveness only grows, and it is capped at ten signature bits, so
/// each bit crosses each edge at most once: O(bits · edges), linear in the
/// program.
///
/// The space is linear in the program too, which the per-function solve was
/// not: the predecessor index spans every slot at once, where that one held
/// one function's worth. Measured on the largest object `link_elf` admits (128
/// sections × 65,535 slots = 64 MiB of code), this function costs 6.4 s and
/// 416 MiB, and the whole of `analyze_program` around it 6.7 s and 968 MiB —
/// on the non-preemptible load path, for an object that already occupies 64
/// MiB twice over. Both are far below what the per-function solve cost on far
/// smaller objects, but the memory is a real change in kind and is why the
/// indices are `u32` rather than `usize`.
pub(crate) fn program_live_in(
  sections: &[LiveInSection<'_>],
  cross_section_calls: &[CrossSectionCallSite],
) -> Vec<Vec<RegMask>> {
  let conservative = || -> Vec<Vec<RegMask>> {
    sections
      .iter()
      .map(|section| vec![ALL_SIGNATURE_REGS; section.starts.len()])
      .collect()
  };

  // Slot and function ids run consecutively across sections, so one worklist
  // covers the program.
  let mut slot_base = Vec::with_capacity(sections.len() + 1);
  let mut func_base = Vec::with_capacity(sections.len() + 1);
  let mut total_slots = 0usize;
  let mut total_funcs = 0usize;
  for section in sections {
    slot_base.push(total_slots);
    func_base.push(total_funcs);
    total_slots += section.code.len() / 8;
    total_funcs += section.starts.len();
  }
  slot_base.push(total_slots);
  func_base.push(total_funcs);

  // Ids are `u32` to keep the predecessor index compact. The linker caps a
  // program at 64 MiB of code, i.e. 8M slots, so this cannot bind in practice;
  // a caller that ignores that cap gets the conservative summary, not a wrong
  // one. Same for a `starts` array that does not partition its section: every
  // walk below assumes `starts[i] < starts[i + 1] <= num_slots`.
  if total_slots > u32::MAX as usize {
    return conservative();
  }
  for section in sections {
    let num_slots = section.code.len() / 8;
    if section.pc_to_func.len() != num_slots {
      return conservative();
    }
    let partitions = section.starts.windows(2).all(|pair| pair[0] < pair[1])
      && section.starts.last().is_none_or(|&last| last < num_slots)
      && section.starts.first().is_none_or(|&first| first == 0);
    if !partitions {
      return conservative();
    }
    // `bounds` indexes `starts` by a `pc_to_func` entry, and the whole-program
    // ids below are derived from it, so an entry naming no function of this
    // section is refused here rather than panicking or silently naming a
    // function in the next one.
    if section
      .pc_to_func
      .iter()
      .any(|&function| function >= section.starts.len())
    {
      return conservative();
    }
  }
  if total_funcs == 0 {
    return conservative();
  }

  let bounds = |si: usize, fi: usize| -> (usize, usize) {
    let section = &sections[si];
    let end = section
      .starts
      .get(fi + 1)
      .copied()
      .unwrap_or(section.code.len() / 8);
    (section.starts[fi], end)
  };

  // Only reachable slots can read anything; walking dead code would invent
  // uses no execution can perform.
  let mut reachable = vec![false; total_slots];
  let mut stack: Vec<usize> = Vec::new();
  for (si, section) in sections.iter().enumerate() {
    let num_slots = section.code.len() / 8;
    let base = slot_base[si];
    for fi in 0..section.starts.len() {
      let (start, end) = bounds(si, fi);
      reachable[base + start] = true;
      stack.push(start);
      while let Some(pc) = stack.pop() {
        let inst = decode(&section.code[pc * 8..pc * 8 + 8]);
        let mut succs = [0usize; 2];
        let written = function_successors_into(pc, &inst, num_slots, start, end, &mut succs);
        for &succ in &succs[..written] {
          if !reachable[base + succ] {
            reachable[base + succ] = true;
            stack.push(succ);
          }
        }
      }
    }
  }

  // Each call site's callee, by global slot id. `None` is the conservative
  // summary, for a target this analysis cannot resolve; the loader's own
  // validation refuses those long before here, so it is a backstop.
  let mut callee_of: HashMap<u32, Option<u32>> = HashMap::new();
  let mut cross_callee: HashMap<u32, u32> = HashMap::new();
  for call in cross_section_calls {
    if call.caller_section >= sections.len() || call.callee_section >= sections.len() {
      continue;
    }
    if call.callee_function >= sections[call.callee_section].starts.len() {
      continue;
    }
    // A call site outside its own section would alias a slot in a later one:
    // global slot ids are only injective while every `call_pc` is inside the
    // section it is attributed to, and the aliased slot's callee would be
    // silently rebound - narrowing a mask rather than widening it.
    if call.call_pc >= sections[call.caller_section].code.len() / 8 {
      continue;
    }
    cross_callee.insert(
      (slot_base[call.caller_section] + call.call_pc) as u32,
      (func_base[call.callee_section] + call.callee_function) as u32,
    );
  }
  for (si, section) in sections.iter().enumerate() {
    let num_slots = section.code.len() / 8;
    let base = slot_base[si];
    for pc in 0..num_slots {
      if !reachable[base + pc] {
        continue;
      }
      let inst = decode(&section.code[pc * 8..pc * 8 + 8]);
      if inst.opcode != EBPF_OP_CALL {
        continue;
      }
      let callee = match inst.src {
        1 => {
          // A wild displacement wraps to something enormous, which `get`
          // rejects along with every other out-of-range target.
          let target = (pc as i64 + 1 + inst.imm as i64) as usize;
          section
            .pc_to_func
            .get(target)
            .map(|&callee| (func_base[si] + callee) as u32)
        }
        2 => cross_callee.get(&((base + pc) as u32)).copied(),
        _ => continue,
      };
      callee_of.insert((base + pc) as u32, callee);
    }
  }

  // The global slot each function starts at: a function's mask is exactly the
  // liveness of that slot, which is what makes this one dataflow problem.
  let mut func_start_slot = vec![0u32; total_funcs];
  for (si, section) in sections.iter().enumerate() {
    for (fi, &start) in section.starts.iter().enumerate() {
      func_start_slot[func_base[si] + fi] = (slot_base[si] + start) as u32;
    }
  }

  // Predecessors, and the call sites reading each function's entry, both as
  // flat CSR arrays. Built once for the whole program: rebuilding a
  // `Vec<Vec<_>>` per function per visit is the cost this solve exists to
  // avoid.
  let mut pred_offset = vec![0u32; total_slots + 1];
  let mut caller_offset = vec![0u32; total_funcs + 1];
  let for_each_edge = |mut on_pred: Box<dyn FnMut(usize, usize) + '_>,
                       mut on_caller: Box<dyn FnMut(usize, usize) + '_>| {
    for (si, section) in sections.iter().enumerate() {
      let num_slots = section.code.len() / 8;
      let base = slot_base[si];
      for pc in 0..num_slots {
        if !reachable[base + pc] {
          continue;
        }
        let inst = decode(&section.code[pc * 8..pc * 8 + 8]);
        let (start, end) = bounds(si, section.pc_to_func[pc]);
        let mut succs = [0usize; 2];
        let written = function_successors_into(pc, &inst, num_slots, start, end, &mut succs);
        for &succ in &succs[..written] {
          on_pred(base + succ, base + pc);
        }
        if let Some(&Some(callee)) = callee_of.get(&((base + pc) as u32)) {
          on_caller(callee as usize, base + pc);
        }
      }
    }
  };
  for_each_edge(
    Box::new(|succ, _| pred_offset[succ + 1] += 1),
    Box::new(|callee, _| caller_offset[callee + 1] += 1),
  );
  for i in 0..total_slots {
    pred_offset[i + 1] += pred_offset[i];
  }
  for i in 0..total_funcs {
    caller_offset[i + 1] += caller_offset[i];
  }
  let mut pred_entries = vec![0u32; pred_offset[total_slots] as usize];
  let mut caller_entries = vec![0u32; caller_offset[total_funcs] as usize];
  {
    let mut pred_cursor = pred_offset.clone();
    let mut caller_cursor = caller_offset.clone();
    for_each_edge(
      Box::new(|succ, pred| {
        pred_entries[pred_cursor[succ] as usize] = pred as u32;
        pred_cursor[succ] += 1;
      }),
      Box::new(|callee, call_slot| {
        caller_entries[caller_cursor[callee] as usize] = call_slot as u32;
        caller_cursor[callee] += 1;
      }),
    );
  }

  let mut live = vec![0 as RegMask; total_slots];
  let mut queued = vec![false; total_slots];
  // Seeded in ascending program order so a LIFO worklist starts at the last
  // slot and backward edges converge on the first visit.
  let mut work: Vec<u32> = (0..total_slots as u32)
    .filter(|&slot| reachable[slot as usize])
    .collect();
  for &slot in &work {
    queued[slot as usize] = true;
  }

  while let Some(slot) = work.pop() {
    let slot = slot as usize;
    queued[slot] = false;
    // `slot_base` is ascending, so the owning section is the last base at or
    // below this slot. A section with no slots contributes none, and so is
    // never selected.
    let si = slot_base.partition_point(|&base| base <= slot) - 1;
    let section = &sections[si];
    let num_slots = section.code.len() / 8;
    let pc = slot - slot_base[si];
    let fi = section.pc_to_func[pc];
    let (start, end) = bounds(si, fi);

    let inst = decode(&section.code[pc * 8..pc * 8 + 8]);
    let mut live_out = 0;
    let mut succs = [0usize; 2];
    let written = function_successors_into(pc, &inst, num_slots, start, end, &mut succs);
    for &succ in &succs[..written] {
      live_out |= live[slot_base[si] + succ];
    }
    let callee = match callee_of.get(&(slot as u32)) {
      Some(Some(callee)) => live[func_start_slot[*callee as usize] as usize],
      Some(None) => ALL_SIGNATURE_REGS,
      None => 0,
    };
    let (uses, defs) = uses_and_defs(&inst, callee);
    let next = uses | (live_out & !defs);
    if next == live[slot] {
      continue;
    }
    // Monotone: `uses` grows with the callee summary and `live_out` with the
    // successors, both of which only ever gain bits.
    debug_assert_eq!(live[slot] & !next, 0);
    live[slot] = next;

    let mut wake = |target: usize| {
      if !queued[target] {
        queued[target] = true;
        work.push(target as u32);
      }
    };
    for i in pred_offset[slot]..pred_offset[slot + 1] {
      wake(pred_entries[i as usize] as usize);
    }
    // A function's mask is its entry slot's liveness, so growing that slot is
    // what wakes its call sites - anywhere in the program.
    if start == pc {
      let func = func_base[si] + fi;
      for i in caller_offset[func]..caller_offset[func + 1] {
        wake(caller_entries[i as usize] as usize);
      }
    }
  }

  sections
    .iter()
    .enumerate()
    .map(|(si, section)| {
      (0..section.starts.len())
        .map(|fi| live[func_start_slot[func_base[si] + fi] as usize])
        .collect()
    })
    .collect()
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

/// Successor slots in the whole-program CFG, in which a local call also enters
/// its callee. Slot indices, not byte offsets.
///
/// Only [`analyze`] treats the program as one CFG; every other consumer works a
/// function at a time and wants [`function_successors_into`], which stops at
/// the function's own range.
#[cfg(any(test, feature = "testing"))]
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
        // A linker-tagged cross-section local call returns here but its callee
        // is represented outside this section's CFG.
        2 => push(fallthrough),
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

/// Writes `pc`'s in-function successor slots into `out` and returns how many
/// were written.
///
/// Two is the ceiling: a conditional jump reaches its target and its
/// fallthrough, and no encoding reaches more. A local call is not an edge here
/// — its callee is a separate function with its own range — so every call form
/// that returns contributes only the next slot.
///
/// Allocation-free because [`program_live_in`] walks this once per slot per
/// worklist pop; [`function_successors`] is the `Vec`-returning wrapper, so the
/// two cannot disagree.
fn function_successors_into(
  pc: usize,
  inst: &Inst,
  num_slots: usize,
  start_pc: usize,
  end_pc: usize,
  out: &mut [usize; 2],
) -> usize {
  let mut raw = [0usize; 2];
  let mut count = 0usize;
  let mut push = |slot: usize| {
    raw[count] = slot;
    count += 1;
  };

  let cls = inst.opcode & EBPF_CLS_MASK;
  if cls == EBPF_CLS_JMP || cls == EBPF_CLS_JMP32 {
    if inst.opcode == EBPF_OP_EXIT {
      // Nothing follows an exit.
    } else if inst.opcode == EBPF_OP_CALL {
      match inst.src {
        // Helper, section-local and cross-section calls all return to the
        // next slot. Any other source branches to exit.
        0 | 1 | 2 => push(pc + 1),
        _ => {}
      }
    } else {
      // JA32 is the only jump whose displacement is the 32-bit immediate.
      let target = if inst.opcode == EBPF_OP_JA32 {
        pc as i64 + 1 + inst.imm as i64
      } else {
        pc as i64 + 1 + inst.offset as i64
      } as usize;
      push(target);
      if inst.opcode != EBPF_OP_JA && inst.opcode != EBPF_OP_JA32 {
        push(pc + 1); // a conditional branch also falls through
      }
    }
  } else if inst.opcode == EBPF_OP_LDDW {
    // The second slot carries the immediate's high half, not an instruction.
    push(pc + 2);
  } else {
    push(pc + 1);
  }

  let mut written = 0;
  for &slot in &raw[..count] {
    // The `as usize` above wraps a wild displacement to something enormous,
    // which `< num_slots` rejects along with everything else out of range.
    if slot < num_slots && slot >= start_pc && slot < end_pc {
      out[written] = slot;
      written += 1;
    }
  }
  written
}

fn function_successors(
  pc: usize,
  inst: &Inst,
  num_slots: usize,
  start_pc: usize,
  end_pc: usize,
) -> Vec<usize> {
  let mut out = [0usize; 2];
  let written = function_successors_into(pc, inst, num_slots, start_pc, end_pc, &mut out);
  out[..written].to_vec()
}

/// Abstract transfer function: register/slot state after executing `inst`.
fn transfer(
  in_state: &State,
  inst: &Inst,
  lddw_addr: u64,
  data_lo: u64,
  data_hi: u64,
  cap_warning_emitted: &mut bool,
) -> State {
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
        match s.slots.get(&(inst.offset as i32)) {
          Some(&(e, k)) if e >= s.invalid_epoch && k.is_pointer() => k,
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
            // Cap the map at MAX_TRACKED_SLOTS distinct offsets: an already
            // tracked slot always updates in place, a new one only while room
            // remains. Refused slots stay untracked and read back as scalars —
            // the same fallback as slots the analysis never saw.
            s.insert_slot(start, (s.invalid_epoch, stored), cap_warning_emitted);
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

/// One entry per instruction slot, handed to the JIT alongside the region hints
/// as [`crate::jit::TranslationInputs::plan`].
///
/// A *group* is a run of memory accesses sharing one base register, so all of
/// their addresses lie within a bounded window around that register's value.
/// The first access is the group's **leader**: it bounds-checks the whole window
/// once and parks the translated base in the frame. Every later **member** reads
/// that base back and accesses it at a constant displacement - two instructions
/// instead of a full check.
///
/// The plan is advisory. The backend re-derives every condition it can see for
/// itself and emits an ordinary checked access when any of them fails, so a
/// wrong plan costs speed, not safety.
/// The plan entry type is [`crate::jit::PlanEntry`] itself: the analysis builds
/// the same struct the backend reads, so there is nothing to keep in step.
pub(crate) use crate::jit::PlanEntry;

pub(crate) const PLAN_ROLE_LEADER: u8 = 1;
pub(crate) const PLAN_ROLE_MEMBER: u8 = 2;

/// Widest window a group may span.
///
/// A failed check yields base 0, so a member then dereferences `[0 + delta]`.
/// That has to land inside the runtime's guard window - the range the SIGSEGV
/// handler claims as a guest fault rather than a host crash - which bounds
/// `delta`, and with it the span, at one page.
pub(crate) const MAX_GROUP_SPAN: i32 = 4096;

/// A group under construction.
struct OpenGroup {
  base: usize,
  leader_pc: usize,
  /// `(pc, displacement)` of each access so far.
  members: Vec<(usize, i32)>,
  /// The region all members so far agree on, if any.
  region: Option<u8>,
  lo: i32,
  hi: i32,
}

fn close_group(open: &mut Option<OpenGroup>, plan: &mut [PlanEntry]) {
  let Some(g) = open.take() else { return };
  if g.members.len() < 2 {
    return;
  }
  let region = g.region.unwrap_or(REGION_UNKNOWN);
  let span = (g.hi - g.lo) as u32;
  for (i, &(pc, disp)) in g.members.iter().enumerate() {
    plan[pc] = PlanEntry {
      role: if i == 0 {
        PLAN_ROLE_LEADER
      } else {
        PLAN_ROLE_MEMBER
      },
      region,
      delta: (disp - g.lo) as u16,
      span,
      lo: g.lo,
      leader_pc: g.leader_pc as u32,
    };
  }
}

/// Registers `inst` may overwrite. Over-approximating only ends groups early;
/// under-approximating would let a group keep using a base that has changed.
fn written_registers(inst: &Inst) -> Vec<usize> {
  match inst.opcode & EBPF_CLS_MASK {
    EBPF_CLS_LD | EBPF_CLS_LDX | EBPF_CLS_ALU | EBPF_CLS_ALU64 => vec![inst.dst],
    // A fetching atomic writes its source register, and CMPXCHG writes R0.
    EBPF_CLS_STX if inst.opcode & 0xe0 == 0xc0 => vec![inst.src, 0],
    EBPF_CLS_JMP | EBPF_CLS_JMP32 if inst.opcode == EBPF_OP_CALL => (0..6).collect(),
    _ => Vec::new(),
  }
}

/// Assigns the accesses in `[start_pc, end_pc)` to groups.
///
/// The rule is deliberately local: a group is a straight-line run inside one
/// basic block, off a base register that nothing redefines along the way. That
/// covers the shape compilers actually emit - a struct initialised field by
/// field, a loop body touching several members of one object - without having to
/// reason about what a branch or a call might have done to the base.
///
/// Frame accesses are left out: `R10` addressing is already unchecked, so a
/// window would save nothing.
fn build_access_plan(
  code: &[u8],
  start_pc: usize,
  end_pc: usize,
  num_slots: usize,
  hints: &[u8],
  reached: &[bool],
) -> Vec<PlanEntry> {
  let mut plan = vec![PlanEntry::default(); num_slots];

  // Anything a branch can land on ends the previous group: the base would not
  // have been established on the path that jumped in. Calls end it too - a
  // local callee runs in the same host frame and would overwrite the parked
  // base, and a helper call can suspend the guest entirely.
  let mut is_target = vec![false; num_slots];
  for pc in start_pc..end_pc {
    if !reached[pc] {
      continue;
    }
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    let cls = inst.opcode & EBPF_CLS_MASK;
    if (cls == EBPF_CLS_JMP || cls == EBPF_CLS_JMP32) && inst.opcode != EBPF_OP_EXIT {
      for succ in function_successors(pc, &inst, num_slots, start_pc, end_pc) {
        is_target[succ] = true;
      }
    }
  }

  let mut open: Option<OpenGroup> = None;
  let mut written: u16 = 0;

  for pc in start_pc..end_pc {
    if !reached[pc] {
      close_group(&mut open, &mut plan);
      written = 0;
      continue;
    }
    if is_target[pc] {
      close_group(&mut open, &mut plan);
      written = 0;
    }

    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    let cls = inst.opcode & EBPF_CLS_MASK;
    let is_atomic = cls == EBPF_CLS_STX && inst.opcode & 0xe0 == 0xc0;
    let base = match cls {
      EBPF_CLS_LDX => Some(inst.src),
      EBPF_CLS_ST | EBPF_CLS_STX => Some(inst.dst),
      _ => None,
    };

    // Atomics both read and write, and the backend routes them through the full
    // check, so they neither join nor start a group.
    if let Some(base) = base.filter(|_| !is_atomic) {
      if base != R10 {
        let width = access_width(inst.opcode) as i32;
        let disp = inst.offset as i32;
        let extends = open.as_ref().is_some_and(|g| {
          g.base == base
            && written & (1 << base) == 0
            && g.hi.max(disp + width) - g.lo.min(disp) <= MAX_GROUP_SPAN
        });
        if !extends {
          close_group(&mut open, &mut plan);
          written = 0;
          open = Some(OpenGroup {
            base,
            leader_pc: pc,
            members: Vec::new(),
            region: None,
            lo: disp,
            hi: disp + width,
          });
        }
        let g = open.as_mut().expect("a group is open");
        g.members.push((pc, disp));
        g.lo = g.lo.min(disp);
        g.hi = g.hi.max(disp + width);
        // Members that disagree on a region leave the group to the dual-region
        // probe, which covers both.
        g.region = Some(match g.region {
          None => hints[pc],
          Some(prev) if prev == hints[pc] => prev,
          Some(_) => REGION_UNKNOWN,
        });
      }
    }

    // Record what this instruction overwrites, after using it: an access whose
    // destination is its own base is still valid, but nothing after it is.
    for reg in written_registers(&inst) {
      written |= 1 << reg;
      if open.as_ref().is_some_and(|g| g.base == reg) {
        close_group(&mut open, &mut plan);
        written = 0;
      }
    }
  }
  close_group(&mut open, &mut plan);

  plan
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

  // ---------------------------------------------------------------------
  // Audit scaffolding (added while reviewing the access plan / frame hint).
  // ---------------------------------------------------------------------

  /// Whole-fragment `analyze_function` from the ordinary entry signature.
  fn analyze_fn(code: &[u8]) -> FunctionRegionAnalysis {
    analyze_function(
      code,
      0,
      code.len() / 8,
      PointerSignature::entry(),
      DATA_LO,
      DATA_HI,
      &crate::function_analysis::FunctionLayout::unmasked(code.len() / 8),
      crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
    )
  }

  fn plan_of(code: &[u8]) -> Vec<PlanEntry> {
    analyze_fn(code).plan
  }

  /// `(role, region, delta, span, lo, leader_pc)` for a slot, for terse asserts.
  fn entry(p: &PlanEntry) -> (u8, u8, u16, u32, i32, u32) {
    (p.role, p.region, p.delta, p.span, p.lo, p.leader_pc)
  }

  const LDXB: u8 = EBPF_CLS_LDX | 0x10;
  const LDXH: u8 = EBPF_CLS_LDX | 0x08;
  const LDXW: u8 = EBPF_CLS_LDX | 0x00;
  const LDXDW: u8 = EBPF_CLS_LDX | 0x18;
  const LDXWSX: u8 = EBPF_CLS_LDX | 0x80; // MEMSX | W
  const LDXHSX: u8 = EBPF_CLS_LDX | 0x88;
  const LDXBSX: u8 = EBPF_CLS_LDX | 0x90;
  const STDW: u8 = EBPF_CLS_ST | 0x18;
  const STXDW: u8 = EBPF_CLS_STX | 0x18;
  const ATOMIC_DW: u8 = EBPF_CLS_STX | 0xc0 | 0x18;
  const MOV64_REG: u8 = EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV;
  const ADD64_IMM: u8 = EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD;
  const JEQ_IMM: u8 = EBPF_CLS_JMP | 0x10;

  /// `r1 = r10; r1 += -1024` - a base that is stack-derived but is not `R10`
  /// itself, so accesses off it are grouped rather than taking the frame path.
  fn base_off_frame() -> [[u8; 8]; 2] {
    [
      slot(MOV64_REG, 1, 10, 0, 0),
      slot(ADD64_IMM, 1, 0, 0, -1024),
    ]
  }

  /// Every accepted `LDX`/`ST`/`STX` opcode form, with the width the backend
  /// uses for it. The frame window test and the group span both depend on
  /// `access_width` agreeing with the backend for every one of them.
  #[test]
  fn access_width_matches_every_accepted_opcode_form() {
    for (opcode, want) in [
      (LDXB, 1),
      (LDXH, 2),
      (LDXW, 4),
      (LDXDW, 8),
      (LDXBSX, 1),
      (LDXHSX, 2),
      (LDXWSX, 4),
      (EBPF_CLS_ST | 0x10, 1),
      (EBPF_CLS_ST | 0x08, 2),
      (EBPF_CLS_ST | 0x00, 4),
      (STDW, 8),
      (EBPF_CLS_STX | 0x10, 1),
      (EBPF_CLS_STX | 0x08, 2),
      (EBPF_CLS_STX | 0x00, 4),
      (STXDW, 8),
      (EBPF_CLS_STX | 0xc0 | 0x00, 4), // ATOMIC32
      (ATOMIC_DW, 8),
    ] {
      assert_eq!(access_width(opcode), want, "opcode {opcode:#04x}");
    }
  }

  /// The default frame window is closed at the bottom and open at the top, for
  /// every width.
  #[test]
  fn frame_hint_window_boundaries() {
    const W: i16 = crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE as i16;
    for (opcode, width) in [(LDXB, 1i16), (LDXH, 2), (LDXW, 4), (LDXDW, 8)] {
      for (offset, want_frame) in [
        (-W, true),          // lowest byte of the window
        (-W - 1, false),     // one byte below it
        (-width, true),      // ends exactly at R10
        (-width + 1, false), // would cross R10
        (0i16, false),
        (1, false),
      ] {
        let code = flatten(&[
          slot(opcode, 0, 10, offset, 0),
          slot(EBPF_OP_EXIT, 0, 0, 0, 0),
        ]);
        let hints = analyze_fn(&code).hints;
        let want = if want_frame {
          REGION_FRAME
        } else {
          REGION_STACK
        };
        assert_eq!(
          hints[0], want,
          "opcode {opcode:#04x} width {width} offset {offset}"
        );
      }
    }
  }

  #[test]
  fn configured_frame_size_changes_the_unchecked_window() {
    let code = flatten(&[slot(LDXDW, 0, 10, -8192, 0), slot(EBPF_OP_EXIT, 0, 0, 0, 0)]);
    let result = analyze_function(
      &code,
      0,
      code.len() / 8,
      PointerSignature::entry(),
      DATA_LO,
      DATA_HI,
      &crate::function_analysis::FunctionLayout::unmasked(code.len() / 8),
      8192,
    );
    assert_eq!(result.hints[0], REGION_FRAME);
  }

  /// The sign-extended loads carry their width in the same bits, so they get
  /// the same window - `ldxwsx [r10-4]` fits, `ldxwsx [r10-3]` does not.
  #[test]
  fn sign_extended_loads_use_their_real_width_in_the_frame_window() {
    for (opcode, width) in [(LDXBSX, 1i16), (LDXHSX, 2), (LDXWSX, 4)] {
      for (offset, want) in [(-width, REGION_FRAME), (-width + 1, REGION_STACK)] {
        let code = flatten(&[
          slot(opcode, 0, 10, offset, 0),
          slot(EBPF_OP_EXIT, 0, 0, 0, 0),
        ]);
        assert_eq!(
          analyze_fn(&code).hints[0],
          want,
          "opcode {opcode:#04x} offset {offset}"
        );
      }
    }
  }

  /// Stores and atomics get the same region hint as loads. Only the narrower
  /// frame fast path remains specific to non-atomic frame accesses.
  #[test]
  fn stores_receive_their_statically_classified_region() {
    let code = flatten(&[
      slot(STDW, 10, 0, -8, 0),      // st [r10-8], 0      -> FRAME
      slot(STXDW, 10, 1, -16, 0),    // stx [r10-16], r1   -> FRAME
      slot(STDW, 10, 0, -8192, 0),   // outside the window -> STACK
      slot(ATOMIC_DW, 10, 2, -8, 1), // atomic -> STACK, never FRAME
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze_fn(&code).hints;
    assert_eq!(hints[0], REGION_FRAME);
    assert_eq!(hints[1], REGION_FRAME);
    assert_eq!(hints[2], REGION_STACK);
    assert_eq!(hints[3], REGION_STACK);
  }

  /// A group's window is the convex hull of its members, and every member's
  /// delta is measured from the hull's low bound - including the leader, which
  /// need not be the lowest.
  #[test]
  fn group_deltas_are_measured_from_the_windows_low_bound() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXB, 2, 1, 5, 0),  // leader, disp 5, width 1
      slot(LDXDW, 3, 1, 8, 0), // disp 8, width 8 -> hi = 16
      slot(LDXH, 4, 1, 0, 0),  // disp 0, width 2 -> lo = 0
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let code = flatten(&slots);
    let plan = plan_of(&code);
    assert_eq!(
      entry(&plan[2]),
      (PLAN_ROLE_LEADER, REGION_STACK, 5, 16, 0, 2)
    );
    assert_eq!(
      entry(&plan[3]),
      (PLAN_ROLE_MEMBER, REGION_STACK, 8, 16, 0, 2)
    );
    assert_eq!(
      entry(&plan[4]),
      (PLAN_ROLE_MEMBER, REGION_STACK, 0, 16, 0, 2)
    );
    // What the backend re-derives: delta + width <= span, for every member.
    for (pc, width) in [(2usize, 1u32), (3, 8), (4, 2)] {
      assert!(plan[pc].delta as u32 + width <= plan[pc].span);
    }
  }

  /// The span cap is inclusive, and one byte past it starts a new group.
  #[test]
  fn the_span_cap_is_inclusive() {
    let build = |far: i16| {
      let mut slots = base_off_frame().to_vec();
      slots.extend([
        slot(LDXB, 2, 1, 0, 0),
        slot(LDXB, 3, 1, far, 0),
        slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      ]);
      plan_of(&flatten(&slots))
    };
    let plan = build(4095); // hull [0, 4096) - exactly the cap
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(
      entry(&plan[3]),
      (PLAN_ROLE_MEMBER, REGION_STACK, 4095, 4096, 0, 2)
    );

    let plan = build(4096); // hull [0, 4097) - over the cap
    assert_eq!(plan[2].role, 0);
    assert_eq!(plan[3].role, 0);
  }

  /// The extreme displacements an `i16` offset can hold must not overflow the
  /// span arithmetic; they just refuse to group.
  #[test]
  fn extreme_displacements_do_not_overflow_the_span() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, i16::MIN, 0),
      slot(LDXDW, 3, 1, i16::MAX, 0),
      slot(LDXDW, 4, 1, i16::MIN, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    for pc in 2..5 {
      assert_eq!(plan[pc].role, 0, "slot {pc}");
    }
  }

  /// Stores participate in the same region agreement as loads.
  #[test]
  fn a_store_keeps_the_groups_data_region() {
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 1, 0, 0, DATA_LO as i32),
      slot(0, 0, 0, 0, 0),
      slot(LDXDW, 2, 1, 0, 0), // hint DATA
      slot(LDXDW, 3, 1, 8, 0), // hint DATA
      slot(STDW, 1, 0, 16, 0), // same DATA base
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze_fn(&code);
    assert_eq!(result.hints[2], REGION_DATA);
    assert_eq!(result.hints[3], REGION_DATA);
    assert_eq!(result.hints[4], REGION_DATA);
    assert_eq!(result.plan[2].region, REGION_DATA);
    assert_eq!(result.plan[3].region, REGION_DATA);
    assert_eq!(result.plan[4].region, REGION_DATA);
  }

  /// The window a group covers never reaches from one guest region into the
  /// other. The cage's inter-region guard is what guarantees it.
  #[test]
  fn a_group_window_cannot_span_two_guest_regions() {
    // The narrowest guard the cage can randomize to, on the smallest page size
    // it will accept.
    const MIN_INTER_REGION_GUARD: i32 = 16 * 4096;
    assert!(
      MAX_GROUP_SPAN <= MIN_INTER_REGION_GUARD,
      "a single group window could straddle the stack and data regions"
    );
  }

  /// A group without a store takes the loads' region, and a group whose loads
  /// cannot be routed stays UNKNOWN so the backend probes both.
  #[test]
  fn a_load_only_group_takes_the_loads_region() {
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 1, 0, 0, DATA_LO as i32),
      slot(0, 0, 0, 0, 0),
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&code);
    assert_eq!(plan[2].region, REGION_DATA);
    assert_eq!(plan[3].region, REGION_DATA);

    // r6 is Scalar at entry, so nothing routes.
    let code = flatten(&[
      slot(LDXDW, 2, 6, 0, 0),
      slot(LDXDW, 3, 6, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&code);
    assert_eq!(plan[0].region, REGION_UNKNOWN);
    assert_eq!(plan[0].role, PLAN_ROLE_LEADER);
  }

  /// An `R10` access in the middle of a run neither joins the group nor closes
  /// it: it needs no base of its own and touches nothing the group parked.
  #[test]
  fn a_frame_access_between_members_keeps_the_group_open() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 3, 10, -8, 0), // frame access, ungrouped
      slot(LDXDW, 4, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[3].role, 0);
    assert_eq!(
      entry(&plan[4]),
      (PLAN_ROLE_MEMBER, REGION_STACK, 8, 16, 0, 2)
    );
  }

  /// An atomic is routed through the full check, so it neither joins a group
  /// nor ends one - but it does write its source register, which does.
  #[test]
  fn an_atomic_does_not_join_a_group_but_its_write_closes_one() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(ATOMIC_DW, 1, 3, 16, 1), // atomic fetch_add through r1, writes r3
      slot(LDXDW, 4, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[3].role, 0, "the atomic itself is never grouped");
    assert_eq!(plan[4].role, PLAN_ROLE_MEMBER);
    // The window covers only the two loads; the atomic's own displacement is
    // not in it.
    assert_eq!(plan[2].span, 16);

    // An atomic whose source is the base closes the group.
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(ATOMIC_DW, 6, 1, 0, 1), // fetch writes r1
      slot(LDXDW, 4, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, 0);
    assert_eq!(plan[4].role, 0);
  }

  /// A `lddw` in the middle of a run of accesses splits the group in two,
  /// because its second slot is never reached by the dataflow. Nothing unsafe -
  /// but both halves lose their window.
  #[test]
  fn a_lddw_between_accesses_dissolves_the_group() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(EBPF_OP_LDDW, 3, 0, 0, 0), // two slots
      slot(0, 0, 0, 0, 0),
      slot(LDXDW, 4, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    // Both accesses are left ungrouped: the group is closed at the unreached
    // second slot with a single member, and the one after it never gets a
    // partner.
    assert_eq!(plan[2].role, 0, "the group did not survive the lddw");
    assert_eq!(plan[5].role, 0);

    // Without the lddw the very same pair does group, which is the point.
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(MOV64_REG, 3, 0, 0, 0),
      slot(LDXDW, 4, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[4].role, PLAN_ROLE_MEMBER);
  }

  /// The second slot of a `lddw` is never decoded as an access, so it can
  /// neither lead nor join a group even when its bit pattern would say so.
  #[test]
  fn the_second_slot_of_a_lddw_is_never_an_access() {
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 1, 0, 0, DATA_LO as i32),
      slot(0, 0, 0, 0, 0),
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze_fn(&code);
    assert_eq!(result.plan[1], PlanEntry::default());
    assert_eq!(result.hints[1], REGION_UNKNOWN);
    assert!(!result.unresolved.contains(&1));
    assert_eq!(result.plan[2].role, PLAN_ROLE_LEADER);
  }

  /// Unreachable slots get no plan entry, so the backend - which walks the
  /// whole range regardless of reachability - falls back to a checked access.
  #[test]
  fn unreachable_accesses_get_no_plan_entry() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(LDXDW, 4, 1, 16, 0), // dead
      slot(LDXDW, 5, 1, 24, 0), // dead
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[3].role, PLAN_ROLE_MEMBER);
    assert_eq!(plan[5], PlanEntry::default());
    assert_eq!(plan[6], PlanEntry::default());
  }

  /// Every landing site of a conditional branch - target and fall-through -
  /// ends the group before it.
  #[test]
  fn both_edges_of_a_conditional_branch_are_barriers() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(JEQ_IMM, 3, 0, 1, 0), // -> slot 5 (skipping slot 4)
      slot(LDXDW, 4, 1, 8, 0),   // fall-through, and a barrier itself
      slot(LDXDW, 5, 1, 16, 0),  // branch target
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    for pc in [2usize, 4, 5] {
      assert_eq!(plan[pc].role, 0, "slot {pc} should not be grouped");
    }
  }

  /// A backward branch target ends the group that ran into it.
  #[test]
  fn a_backward_branch_target_is_a_barrier() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),    // slot 2: loop head, a branch target
      slot(LDXDW, 3, 1, 8, 0),    // slot 3
      slot(JEQ_IMM, 4, 0, -3, 0), // slot 4: back to slot 2
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER, "the loop body still groups");
    assert_eq!(plan[3].role, PLAN_ROLE_MEMBER);
  }

  /// A branch whose target lands outside the function is dropped rather than
  /// indexing out of the barrier array.
  #[test]
  fn an_out_of_range_branch_target_is_dropped() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(EBPF_OP_JA, 0, 0, i16::MIN, 0), // wildly out of range, backwards
      slot(LDXDW, 3, 1, 8, 0),             // unreachable after the JA
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots)); // must not panic
    assert_eq!(plan[2].role, 0);
  }

  /// The barrier pre-pass ignores unreachable branches, so a group can span a
  /// slot the backend treats as a landing site. Safe - the backend closes the
  /// group itself and the member falls back to a checked access - but it means
  /// the two barrier sets are not identical.
  #[test]
  fn an_unreachable_branch_leaves_no_barrier() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(EBPF_OP_JA, 0, 0, 2, 0),   // slot 2: -> slot 5
      slot(JEQ_IMM, 0, 0, 3, 0),      // slot 3: dead; its target would be slot 7
      slot(EBPF_OP_EXIT, 0, 0, 0, 0), // slot 4: dead
      slot(LDXDW, 2, 1, 0, 0),        // slot 5
      slot(LDXDW, 3, 1, 8, 0),        // slot 6
      slot(LDXDW, 4, 1, 16, 0),       // slot 7: the dead branch's target
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[5].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[6].role, PLAN_ROLE_MEMBER);
    // Slot 7 is in the group even though the backend's barrier table marks it.
    assert_eq!(plan[7].role, PLAN_ROLE_MEMBER);
  }

  /// Both a helper call and a local call end the group at their return slot.
  #[test]
  fn a_call_ends_the_group_at_its_return_slot() {
    for src in [0u8, 1] {
      let mut slots = base_off_frame().to_vec();
      slots.extend([
        slot(MOV64_REG, 6, 10, 0, 0),
        slot(ADD64_IMM, 6, 0, 0, -1024),
        slot(LDXDW, 2, 6, 0, 0),
        slot(LDXDW, 3, 6, 8, 0),
        slot(EBPF_OP_CALL, 0, src, 0, 2), // -> slot 9 when local
        slot(LDXDW, 4, 6, 16, 0),
        slot(LDXDW, 5, 6, 24, 0),
        slot(EBPF_OP_EXIT, 0, 0, 0, 0),
        slot(EBPF_OP_EXIT, 0, 0, 0, 0), // callee
      ]);
      let code = flatten(&slots);
      let plan = analyze_function(
        &code,
        0,
        9,
        PointerSignature::entry(),
        DATA_LO,
        DATA_HI,
        &crate::function_analysis::FunctionLayout::unmasked(code.len() / 8),
        crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
      )
      .plan;
      assert_eq!(plan[4].role, PLAN_ROLE_LEADER, "src {src}");
      assert_eq!(plan[5].role, PLAN_ROLE_MEMBER, "src {src}");
      assert_eq!(plan[5].span, 16, "src {src}: the window stops at the call");
      assert_eq!(plan[7].role, PLAN_ROLE_LEADER, "src {src}");
      assert_eq!(plan[7].leader_pc, 7, "src {src}");
      assert_eq!(plan[8].role, PLAN_ROLE_MEMBER, "src {src}");
    }
  }

  /// A group of one is no group at all.
  #[test]
  fn a_lone_access_is_not_a_group() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([slot(LDXDW, 2, 1, 0, 0), slot(EBPF_OP_EXIT, 0, 0, 0, 0)]);
    assert_eq!(plan_of(&flatten(&slots))[2], PlanEntry::default());
  }

  /// `hints` and `plan` are always as long as the whole program's slot count,
  /// including on the early-return path, because the backend indexes both by
  /// absolute PC.
  #[test]
  fn hints_and_plan_always_cover_every_slot() {
    let code = flatten(&[
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let slots = code.len() / 8;
    let layout = crate::function_analysis::FunctionLayout::unmasked(slots);
    for (start, end) in [(0, slots), (1, 2), (2, 2), (1, 0), (0, slots + 1)] {
      let r = analyze_function(
        &code,
        start,
        end,
        PointerSignature::entry(),
        DATA_LO,
        DATA_HI,
        &layout,
        crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
      );
      assert_eq!(r.hints.len(), slots, "[{start}, {end})");
      assert_eq!(r.plan.len(), slots, "[{start}, {end})");
    }
  }

  /// The plan is built over `[start_pc, end_pc)` only: no entry is written
  /// outside the function the backend is about to translate.
  #[test]
  fn the_plan_is_confined_to_the_function_being_analyzed() {
    let code = flatten(&[
      slot(LDXDW, 2, 1, 0, 0), // another function's body
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(LDXDW, 2, 1, 0, 0), // the function under analysis
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let slots = code.len() / 8;
    let plan = analyze_function(
      &code,
      3,
      slots,
      PointerSignature::entry(),
      DATA_LO,
      DATA_HI,
      &crate::function_analysis::FunctionLayout::unmasked(slots),
      crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
    )
    .plan;
    assert_eq!(plan[0], PlanEntry::default());
    assert_eq!(plan[1], PlanEntry::default());
    assert_eq!(plan[3].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[3].leader_pc, 3);
    assert_eq!(plan[4].role, PLAN_ROLE_MEMBER);
  }

  /// An access whose destination is its own base ends the group after it, but
  /// is itself still a valid member.
  #[test]
  fn a_load_into_its_own_base_ends_the_group_after_it() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 1, 1, 8, 0), // r1 = *(u64 *)(r1 + 8)
      slot(LDXDW, 3, 1, 16, 0),
      slot(LDXDW, 4, 1, 24, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(
      entry(&plan[3]),
      (PLAN_ROLE_MEMBER, REGION_STACK, 8, 16, 0, 2)
    );
    assert_eq!(
      plan[4].role, PLAN_ROLE_LEADER,
      "a fresh group off the new r1"
    );
    assert_eq!(plan[4].leader_pc, 4);
    assert_eq!(plan[5].role, PLAN_ROLE_MEMBER);
  }

  /// The frame hint's one unverifiable claim is that `R10` still holds the
  /// frame pointer. The loader refuses every assignment to it, but the analysis
  /// checks rather than assumes - so an assignment must suppress the hint.
  #[test]
  fn an_assignment_to_r10_suppresses_the_frame_hint() {
    // `r10 = r1` (the ctx: a stack pointer, but not this frame's base).
    let code = flatten(&[
      slot(MOV64_REG, 10, 1, 0, 0),
      slot(LDXDW, 0, 10, -8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(analyze_fn(&code).hints[1], REGION_STACK);

    // `r10 = <data>` - not even a stack pointer any more.
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 10, 0, 0, DATA_LO as i32),
      slot(0, 0, 0, 0, 0),
      slot(LDXDW, 0, 10, -8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(analyze_fn(&code).hints[2], REGION_DATA);

    // A fetching atomic writes its source, so `r10` as a source kills it too.
    let code = flatten(&[
      slot(ATOMIC_DW, 1, 10, 0, 1),
      slot(LDXDW, 0, 10, -8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(analyze_fn(&code).hints[1], REGION_UNKNOWN);
  }

  /// The hint is decided from the state *entering* the access, not the state
  /// leaving it. `ldx r10, [r10 - 8]` is the sharp case: R10 is the frame
  /// pointer when the address is formed and something else immediately after,
  /// so the two states disagree and only the entering one is right.
  ///
  /// (The loader refuses this instruction; it is here because it is the only
  /// shape that tells the two readings apart.)
  #[test]
  fn the_frame_hint_reads_the_state_entering_the_access() {
    let code = flatten(&[
      slot(LDXDW, 10, 10, -8, 0),
      slot(LDXDW, 0, 10, -8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze_fn(&code).hints;
    // Entering slot 0, R10 is still the frame pointer.
    assert_eq!(hints[0], REGION_FRAME);
    // Leaving it, R10 holds a value read out of guest memory, so the next
    // access through it is not a frame access at all.
    assert_eq!(hints[1], REGION_UNKNOWN);
  }

  /// `R10` displaced and restored is still the frame pointer, and the offset
  /// tracking is what says so - the hint follows the tracked displacement, not
  /// the mere fact that the register is `R10`.
  #[test]
  fn the_frame_hint_follows_r10s_tracked_displacement() {
    let code = flatten(&[
      slot(ADD64_IMM, 10, 0, 0, -8),
      slot(LDXDW, 0, 10, -8, 0), // r10 is displaced here: no frame hint
      slot(ADD64_IMM, 10, 0, 0, 8),
      slot(LDXDW, 1, 10, -8, 0), // restored: frame hint again
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze_fn(&code).hints;
    assert_eq!(hints[1], REGION_STACK);
    assert_eq!(hints[3], REGION_FRAME);
  }

  /// A join that cannot agree on `R10` suppresses the hint on the merged path.
  #[test]
  fn a_join_that_loses_r10_suppresses_the_frame_hint() {
    let code = flatten(&[
      slot(JEQ_IMM, 0, 0, 1, 0),      // -> slot 2
      slot(ADD64_IMM, 10, 0, 0, -16), // only on the fall-through
      slot(LDXDW, 0, 10, -8, 0),      // join: r10 is Current(None)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(analyze_fn(&code).hints[2], REGION_STACK);
  }

  /// The hint is for `R10` itself, never a register derived from it: a copy
  /// holds a guest address at run time, so its displacement is not a native one.
  #[test]
  fn a_copy_of_r10_does_not_get_the_frame_hint() {
    let code = flatten(&[
      slot(MOV64_REG, 1, 10, 0, 0),
      slot(LDXDW, 0, 1, -8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(analyze_fn(&code).hints[1], REGION_STACK);
  }

  /// A local callee's `R10` is its own frame pointer, not the caller's, so the
  /// frame hint has to be re-established from the callee's entry.
  #[test]
  fn a_callees_frame_hint_is_its_own() {
    let code = flatten(&[
      slot(EBPF_OP_CALL, 0, 1, 0, 1), // -> slot 2
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(LDXDW, 0, 10, -8, 0), // callee
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let slots = code.len() / 8;
    let layout = crate::function_analysis::FunctionLayout::unmasked(slots);
    // Whatever signature the caller hands over, `apply_to_state` pins R10.
    let mut regs = [RegKind::Unknown; NUM_REGS];
    regs[R10] = RegKind::Unknown;
    let r = analyze_function(
      &code,
      2,
      slots,
      PointerSignature { regs },
      DATA_LO,
      DATA_HI,
      &layout,
      crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
    );
    assert_eq!(r.hints[2], REGION_FRAME);
  }

  /// Every register an instruction can overwrite has to end a group based on
  /// it. This walks the forms the backend's own mask lists.
  #[test]
  fn written_registers_covers_every_writing_form() {
    let cases: [(&str, [u8; 8], &[usize]); 9] = [
      ("lddw", slot(EBPF_OP_LDDW, 4, 0, 0, 0), &[4]),
      ("ldxdw", slot(LDXDW, 4, 1, 0, 0), &[4]),
      ("alu64 add", slot(ADD64_IMM, 4, 0, 0, 1), &[4]),
      (
        "alu32 mov",
        slot(EBPF_CLS_ALU | EBPF_ALU_OP_MOV, 4, 0, 0, 1),
        &[4],
      ),
      ("byteswap le", slot(EBPF_CLS_ALU | 0xd0, 4, 0, 0, 64), &[4]),
      ("bswap64", slot(EBPF_CLS_ALU64 | 0xd0, 4, 0, 0, 64), &[4]),
      ("atomic fetch", slot(ATOMIC_DW, 1, 4, 0, 1), &[4, 0]),
      (
        "call helper",
        slot(EBPF_OP_CALL, 0, 0, 0, 1),
        &[0, 1, 2, 3, 4, 5],
      ),
      (
        "call local",
        slot(EBPF_OP_CALL, 0, 1, 0, 1),
        &[0, 1, 2, 3, 4, 5],
      ),
    ];
    for (name, s, want) in cases {
      let got = written_registers(&decode(&s));
      for reg in want {
        assert!(got.contains(reg), "{name}: expected r{reg} in {got:?}");
      }
    }
    // Plain stores write nothing.
    for s in [slot(STDW, 1, 0, 0, 0), slot(STXDW, 1, 2, 0, 0)] {
      assert!(written_registers(&decode(&s)).is_empty());
    }
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
  fn a_cross_section_call_conservatively_reads_signature_registers() {
    let code = flatten(&[
      slot(EBPF_OP_CALL, 0, 2, 0, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(
      function_live_in(&code, 0, 2, &|_| ALL_SIGNATURE_REGS),
      ALL_SIGNATURE_REGS
    );
  }

  /// The all-slots fixpoint sweep [`function_live_in`] used before the
  /// worklist, kept verbatim so the two can be proven to agree bit for bit.
  fn sweep_live_in(
    code: &[u8],
    start_pc: usize,
    end_pc: usize,
    callee_live_in: &dyn Fn(CallSite) -> RegMask,
  ) -> RegMask {
    let num_slots = code.len() / 8;
    if start_pc >= end_pc || end_pc > num_slots {
      return ALL_SIGNATURE_REGS;
    }
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
        let callee = if inst.opcode == EBPF_OP_CALL {
          match inst.src {
            1 => callee_live_in(CallSite::Local {
              target_pc: (pc as i64 + 1 + inst.imm as i64) as usize,
            }),
            2 => callee_live_in(CallSite::CrossSection { call_pc: pc }),
            _ => 0,
          }
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

  #[test]
  fn worklist_live_in_is_bit_identical_to_the_sweep() {
    // The masks are precision-only inputs to per-signature specialization, so
    // a single bit of difference would change which variants the loader
    // builds. Exercise the hostile ladder shape the sweep was quadratic on,
    // plus a deterministic spread of random fragments (any bytes are safe:
    // decode, successors and uses_and_defs are total).
    fn ladder(n: usize) -> Vec<u8> {
      let mut code = Vec::with_capacity((n + 2) * 8);
      let mut pc = 0;
      while pc + 3 <= n {
        code.extend_from_slice(&slot(EBPF_OP_JA, 0, 0, 1, 0)); // ja +1
        code.extend_from_slice(&slot(EBPF_OP_JA, 0, 0, 1, 0)); // ja +1
        code.extend_from_slice(&slot(EBPF_OP_JA, 0, 0, -2, 0)); // ja -2
        pc += 3;
      }
      while pc < n {
        code.extend_from_slice(&slot(EBPF_OP_JA, 0, 0, 1, 0));
        pc += 1;
      }
      // A register use after the ladder makes every live bit cross every
      // backward edge on the way to the entry. Register form (`| EBPF_SRC_REG`),
      // so the source nibble is the read register.
      code.extend_from_slice(&slot(
        EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_ADD,
        0,
        6,
        0,
        0,
      ));
      code.extend_from_slice(&slot(EBPF_OP_EXIT, 0, 0, 0, 0));
      code
    }

    for n in [2usize, 3, 7, 64, 1000, 4096] {
      let code = ladder(n);
      assert_eq!(
        function_live_in(&code, 0, code.len() / 8, &|_| 0),
        sweep_live_in(&code, 0, code.len() / 8, &|_| 0),
        "worklist diverged from the sweep on the {n}-slot ladder"
      );
    }

    // A small deterministic PRNG so the spread is identical on every host.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next_u8 = move || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      (state >> 32) as u8
    };
    for _ in 0..1000 {
      let n = (next_u8() as usize % 60) + 1;
      let mut code = Vec::with_capacity(n * 8);
      for _ in 0..n * 8 {
        code.push(next_u8());
      }
      assert_eq!(
        function_live_in(&code, 0, n, &|_| 0),
        sweep_live_in(&code, 0, n, &|_| 0),
        "worklist diverged from the sweep on a random {n}-slot fragment"
      );
    }
  }

  /// Naive whole-program Kleene iteration over the same equations
  /// [`program_live_in`] solves: recompute every function from the current
  /// summaries until nothing moves. No worklist, no predecessor index, no
  /// caller index, no global-id arithmetic - it shares none of the machinery
  /// the real solver's speed depends on, which is what makes it worth
  /// comparing against.
  fn sweep_program_live_in(
    sections: &[LiveInSection<'_>],
    cross_section_calls: &[CrossSectionCallSite],
  ) -> Vec<Vec<RegMask>> {
    let mut masks: Vec<Vec<RegMask>> = sections
      .iter()
      .map(|section| vec![0 as RegMask; section.starts.len()])
      .collect();
    loop {
      let snapshot = masks.clone();
      for (si, section) in sections.iter().enumerate() {
        let num_slots = section.code.len() / 8;
        for fi in 0..section.starts.len() {
          let start = section.starts[fi];
          let end = section.starts.get(fi + 1).copied().unwrap_or(num_slots);
          masks[si][fi] = function_live_in(section.code, start, end, &|site| match site {
            CallSite::Local { target_pc } => section
              .pc_to_func
              .get(target_pc)
              .and_then(|&callee| snapshot[si].get(callee).copied())
              .unwrap_or(ALL_SIGNATURE_REGS),
            CallSite::CrossSection { call_pc } => cross_section_calls
              .iter()
              .find(|call| call.caller_section == si && call.call_pc == call_pc)
              .map(|call| snapshot[call.callee_section][call.callee_function])
              .unwrap_or(ALL_SIGNATURE_REGS),
          });
        }
      }
      if masks == snapshot {
        return masks;
      }
    }
  }

  /// The flat whole-program solver must agree with the per-function one, bit
  /// for bit, on every program.
  ///
  /// [`program_live_in`] flattens two nested fixed points into one worklist to
  /// escape a quadratic; this pins that the flattening did not also change the
  /// answer. The bytes are random from a structured alphabet rather than valid
  /// eBPF: both solvers decode the same bytes the same way, so anything that
  /// decodes exercises the equations, and the odd shapes a fuzzer finds are
  /// exactly the ones hand-written cases miss.
  #[test]
  fn program_live_in_agrees_with_the_per_function_solver() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state
    };
    let mut below = |n: u64| next() % n;

    let mut with_cross_calls = 0usize;
    for _ in 0..3000 {
      let section_count = 1 + below(3) as usize;
      let mut codes: Vec<Vec<u8>> = Vec::new();
      let mut starts: Vec<Vec<usize>> = Vec::new();
      let mut pc_to_func: Vec<Vec<usize>> = Vec::new();
      for _ in 0..section_count {
        let num_slots = 1 + below(12) as usize;
        let mut code = Vec::new();
        for _ in 0..num_slots {
          let dst = below(11) as u8;
          let src = below(11) as u8;
          let offset = below(9) as i16 - 4;
          let imm = below(9) as i32 - 4;
          let opcode = match below(9) {
            0 => EBPF_OP_EXIT,
            1 => EBPF_OP_CALL,
            2 => EBPF_OP_CALL,
            3 => EBPF_OP_JA,
            4 => EBPF_OP_JA32,
            5 => EBPF_CLS_JMP | 0x50, // jset, a conditional
            6 => EBPF_OP_LDDW,
            7 => EBPF_CLS_LDX | 0x18,
            _ => EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_ADD,
          };
          code.extend_from_slice(&slot(opcode, dst, src, offset, imm));
        }
        // Any strictly ascending set containing 0 is a legal partition; the
        // loader derives one from call targets, but the solvers take it as
        // given, so exercise arbitrary ones.
        let mut section_starts = vec![0usize];
        for pc in 1..num_slots {
          if below(3) == 0 {
            section_starts.push(pc);
          }
        }
        let mut owner = vec![0usize; num_slots];
        for (fi, &start) in section_starts.iter().enumerate() {
          let end = section_starts.get(fi + 1).copied().unwrap_or(num_slots);
          owner[start..end].fill(fi);
        }
        codes.push(code);
        starts.push(section_starts);
        pc_to_func.push(owner);
      }

      // At most one edge per call site: the solvers disagree on which of two
      // edges at one site wins, and the loader refuses that object anyway
      // ("more than one cross-section relocation targets call PC").
      let mut cross_section_calls: Vec<CrossSectionCallSite> = Vec::new();
      for caller_section in 0..section_count {
        for call_pc in 0..codes[caller_section].len() / 8 {
          if below(4) != 0 {
            continue;
          }
          let callee_section = below(section_count as u64) as usize;
          let callee_function = below(starts[callee_section].len() as u64) as usize;
          cross_section_calls.push(CrossSectionCallSite {
            caller_section,
            call_pc,
            callee_section,
            callee_function,
          });
        }
      }
      if !cross_section_calls.is_empty() {
        with_cross_calls += 1;
      }

      let sections = (0..section_count)
        .map(|si| LiveInSection {
          code: &codes[si],
          starts: &starts[si],
          pc_to_func: &pc_to_func[si],
        })
        .collect::<Vec<_>>();

      assert_eq!(
        program_live_in(&sections, &cross_section_calls),
        sweep_program_live_in(&sections, &cross_section_calls),
        "flat solver diverged from the per-function sweep on {codes:?} \
         starts {starts:?} cross calls {cross_section_calls:?}"
      );
    }
    assert!(
      with_cross_calls > 1000,
      "only {with_cross_calls} generated programs had a cross-section call"
    );
  }

  /// A cross-section call site outside the section it is attributed to must be
  /// dropped, not folded into whichever section its global slot id lands in.
  ///
  /// Slot ids are assigned per section and concatenated, so they are injective
  /// only while every `call_pc` is inside its own section. An out-of-range one
  /// aliases a real slot in a later section and rebinds *that* slot's callee,
  /// which narrows a mask - the unsafe direction, since a callee would then be
  /// specialized on fewer registers than it can observe.
  #[test]
  fn a_cross_section_call_outside_its_own_section_is_dropped() {
    let first = flatten(&[slot(EBPF_OP_EXIT, 0, 0, 0, 0)]);
    let second = flatten(&[
      slot(EBPF_OP_CALL, 0, 2, 0, 0), // no edge names this one
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let sections = [
      LiveInSection {
        code: &first,
        starts: &[0],
        pc_to_func: &[0],
      },
      LiveInSection {
        code: &second,
        starts: &[0],
        pc_to_func: &[0, 0],
      },
    ];
    // `call_pc: 1` does not exist in section 0, which has one slot. Its global
    // id is section 1's slot 0 - the untagged call above.
    let stray = [CrossSectionCallSite {
      caller_section: 0,
      call_pc: 1,
      callee_section: 0,
      callee_function: 0,
    }];

    assert_eq!(
      program_live_in(&sections, &stray),
      vec![vec![0], vec![ALL_SIGNATURE_REGS]],
      "a stray call site rebound an unrelated section's call"
    );
  }

  /// A `pc_to_func` entry naming no function of its section takes the
  /// conservative bail the guard block promises, rather than panicking in
  /// `bounds` or silently naming a function in the next section.
  #[test]
  fn a_pc_to_func_entry_outside_its_section_takes_the_conservative_bail() {
    let code = flatten(&[
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0), // r0 = *(u64*)(r6)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let sections = [LiveInSection {
      code: &code,
      starts: &[0],
      pc_to_func: &[0, 7],
    }];

    assert_eq!(
      program_live_in(&sections, &[]),
      vec![vec![ALL_SIGNATURE_REGS]]
    );
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
      crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
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

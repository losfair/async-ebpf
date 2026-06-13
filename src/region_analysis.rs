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

const EBPF_OP_LDDW: u8 = EBPF_CLS_LD | 0x18; // LD | IMM | DW
const EBPF_OP_JA: u8 = EBPF_CLS_JMP; // JMP | JA (mode 0)
const EBPF_OP_JA32: u8 = EBPF_CLS_JMP32;
const EBPF_OP_CALL: u8 = EBPF_CLS_JMP | 0x80; // JMP | CALL
const EBPF_OP_EXIT: u8 = EBPF_CLS_JMP | 0x90; // JMP | EXIT

/// Abstract value tracked per register. The lattice top is [`RegKind::Uninit`]
/// (no information / unreachable); the meet of two distinct concrete kinds is
/// [`RegKind::Unknown`] (bottom for routing purposes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RegKind {
  Uninit,
  Stack,
  Data,
  Scalar,
  Unknown,
}

impl RegKind {
  /// Greatest-lower-bound used at control-flow joins.
  fn meet(self, other: RegKind) -> RegKind {
    match (self, other) {
      (a, b) if a == b => a,
      (RegKind::Uninit, b) => b,
      (a, RegKind::Uninit) => a,
      _ => RegKind::Unknown,
    }
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
  slots: std::collections::BTreeMap<i16, RegKind>,
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

/// Result of the region analysis for one code section.
pub struct RegionAnalysis {
  /// Per-instruction-slot load region hint for the JIT (`REGION_*`). Non-load
  /// slots are [`REGION_UNKNOWN`].
  pub hints: Vec<u8>,
  /// Slots of memory-access instructions (load, store, atomic) whose pointer
  /// could not be resolved to a single region. Empty iff every access is
  /// statically routable.
  pub unresolved: Vec<usize>,
}

/// Analyzes the pointer region of every memory access in one code section.
///
/// `code` is the relocated bytecode (8 bytes per slot, matching uBPF's
/// `vm->insts` indexing; `lddw` occupies two slots). `data_lo`/`data_hi` are the
/// guest data region bounds used to recognize relocated data pointers.
pub fn analyze(code: &[u8], data_lo: u64, data_hi: u64) -> RegionAnalysis {
  let num_slots = code.len() / 8;
  let mut hints = vec![REGION_UNKNOWN; num_slots];
  let mut unresolved = Vec::new();
  if num_slots == 0 {
    return RegionAnalysis { hints, unresolved };
  }

  // Forward dataflow to a fixpoint over the instruction-slot CFG.
  let mut states: Vec<State> = (0..num_slots).map(|_| State::top()).collect();
  // Entry: R1 holds ctx (points into the guest stack), R10 is the frame pointer.
  states[0].regs[1] = RegKind::Stack;
  states[0].regs[R10] = RegKind::Stack;

  let mut worklist: Vec<usize> = vec![0];
  let mut on_list = vec![false; num_slots];
  on_list[0] = true;

  while let Some(pc) = worklist.pop() {
    on_list[pc] = false;
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    let lddw_addr = lddw_full_imm(code, pc, &inst);
    let out = transfer(&states[pc], &inst, lddw_addr, data_lo, data_hi);

    for succ in successors(pc, &inst, num_slots) {
      if states[succ].meet_from(&out) && !on_list[succ] {
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
    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    let cls = inst.opcode & EBPF_CLS_MASK;
    let base = match cls {
      EBPF_CLS_LDX => inst.src,                 // load: pointer is src
      EBPF_CLS_ST | EBPF_CLS_STX => inst.dst,   // store/atomic: pointer is dst
      _ => continue,
    };
    let region = match states[pc].regs[base] {
      RegKind::Stack => REGION_STACK,
      RegKind::Data => REGION_DATA,
      _ => REGION_UNKNOWN,
    };
    if cls == EBPF_CLS_LDX {
      hints[pc] = region;
    }
    if region == REGION_UNKNOWN {
      unresolved.push(pc);
    }
  }

  RegionAnalysis { hints, unresolved }
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
        match s.slots.get(&inst.offset).copied() {
          Some(k @ (RegKind::Stack | RegKind::Data)) => k,
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
      if inst.dst == R10 {
        // Spill to a known R10-relative slot. Atomics modify the slot in ways
        // we do not model precisely, so mark it Unknown.
        let stored = if is_atomic {
          RegKind::Unknown
        } else if value == RegKind::Uninit {
          RegKind::Unknown
        } else {
          value
        };
        s.slots.insert(inst.offset, stored);
      } else if s.regs[inst.dst] != RegKind::Data {
        // A store through anything not provably in the data region may alias an
        // untracked stack slot; conservatively invalidate all tracked slots.
        s.invalidate_slots();
      }
      if is_atomic {
        // An atomic fetch writes the previous value into src.
        s.regs[inst.src] = RegKind::Unknown;
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
            preserve_with_imm(s.regs[inst.dst])
          };
        }
        EBPF_ALU_OP_SUB => {
          s.regs[inst.dst] = if is_reg {
            sub_kinds(s.regs[inst.dst], s.regs[inst.src])
          } else {
            preserve_with_imm(s.regs[inst.dst])
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
        // clobbered; R6-R10 are preserved. A callee may write through a stack
        // pointer it was handed, so spilled slots can no longer be trusted.
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
        s.invalidate_slots();
      }
    }
    _ => {}
  }

  s
}

/// `ptr + scalar` preserves the pointer's region; `scalar + scalar` is scalar.
fn add_kinds(a: RegKind, b: RegKind) -> RegKind {
  match (a, b) {
    (RegKind::Stack, RegKind::Scalar) | (RegKind::Scalar, RegKind::Stack) => RegKind::Stack,
    (RegKind::Data, RegKind::Scalar) | (RegKind::Scalar, RegKind::Data) => RegKind::Data,
    (RegKind::Scalar, RegKind::Scalar) => RegKind::Scalar,
    _ => RegKind::Unknown,
  }
}

/// `ptr - scalar` preserves the region; `ptr - ptr` (same region) is a scalar.
fn sub_kinds(a: RegKind, b: RegKind) -> RegKind {
  match (a, b) {
    (RegKind::Stack, RegKind::Scalar) => RegKind::Stack,
    (RegKind::Data, RegKind::Scalar) => RegKind::Data,
    (RegKind::Stack, RegKind::Stack) | (RegKind::Data, RegKind::Data) => RegKind::Scalar,
    (RegKind::Scalar, RegKind::Scalar) => RegKind::Scalar,
    _ => RegKind::Unknown,
  }
}

/// Adding an immediate preserves a known region/scalar; an undefined register
/// stays undefined-for-routing (`Unknown`).
fn preserve_with_imm(a: RegKind) -> RegKind {
  match a {
    RegKind::Stack => RegKind::Stack,
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
      slot(0, 0, 0, 0, 0), // lddw high half
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
    // by a helper: a byte is loaded from a stack slot the call invalidated, used
    // as the index into the literal. The fill must read back as a scalar (not a
    // stale/invalidated pointer kind), keeping `literal[i]` routable to data.
    let code = flatten(&[
      slot(EBPF_CLS_STX | 0x10, 10, 6, -32, 0), // *(u8*)(r10-32) = r6  (spill a scalar)
      slot(EBPF_OP_CALL, 0, 0, 0, 1),           // call helper -> invalidates slots
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
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0), // r0 = *(u64*)(r6)
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
}

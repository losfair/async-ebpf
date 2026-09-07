//! The region analysis' dataflow core: the abstract domain, its meet, the
//! transfer function, and the per-slot classification the JIT consumes.
//!
//! `crate::region_analysis` drives these to a fixed point over each
//! function's control-flow graph; what it feeds them and what it does with
//! the result stays there. Everything that decides what a register or spill
//! slot *is* lives here, so that `lean/AsyncEbpf/Region` can state what the
//! decision means.
//!
//! ## The domain
//!
//! A [`RegKind`] classifies one value: a pointer into the current frame
//! (optionally at a known displacement from the frame pointer), a pointer
//! into some caller's frame, a pointer into the data region, a scalar, or
//! unknown. `Uninit` is the top of the lattice (nothing has reached the
//! point yet); `Unknown` is the bottom for routing purposes.
//!
//! A [`State`] classifies every register and up to [`MAX_TRACKED_SLOTS`]
//! frame-pointer-relative spill slots. A slot entry carries the state's
//! invalidation epoch at write time: bumping the epoch invalidates every
//! entry written before it, so a store that may alias the whole frame costs
//! O(1). The slots are a bounded array rather than a map: the cap keeps a
//! hostile function's cost linear, and a slot the cap refuses reads back as
//! a scalar, the same safe fallback an untracked slot takes.
//!
//! ## What the classification means, and does not
//!
//! The analysis is a precision optimization behind a bounds check the JIT
//! always keeps for `STACK` and `DATA` hints, so those two hints may be
//! wrong without breaking memory safety: the check faults spuriously. Four
//! of the rules below are deliberately optimistic in that sense — a value
//! loaded from memory is a scalar, a helper's result is a scalar, spills
//! survive a call, and a slot the cap refuses reads back as a scalar — so
//! no natural provenance semantics makes the kinds an over-approximation,
//! and `lean/AsyncEbpf/Region` does not claim one. What it proves is what
//! the runtime relies on: the `FRAME` hint, the one that removes a check,
//! goes only to an access off `R10` itself inside the frame window
//! (`classify_frame`, carried to executions by `Semantics/Frames.lean`);
//! `R10`'s kind survives every transfer and meet of an accepted
//! instruction; and `transfer` reads only the registers `uses_and_defs`
//! names. The live-in masking of call signatures is exactly neutral
//! (`lean/AsyncEbpf/Region/Masking.lean`): the fixed point projects every
//! state onto its slot's live-in registers ([`project`]), so a signature
//! and its masked form give the same entry state and the same solution.

use super::isa::*;
use super::stack::in_frame_window;

/// Routing hint values shared with the JIT (`region::*` in `jit::abi`).
pub const REGION_UNKNOWN: u8 = 0;
pub const REGION_STACK: u8 = 1;
pub const REGION_DATA: u8 = 2;
/// A displacement off an unmodified frame pointer that provably stays inside
/// the guest stack. See [`frame_access`].
pub const REGION_FRAME: u8 = 3;

/// eBPF general-purpose registers, `R0`–`R10`.
pub const NUM_REGS: usize = 11;

/// Index of the read-only frame pointer register `R10`.
pub const R10: usize = 10;

/// How many distinct `R10`-relative spill offsets one state may track.
///
/// The value covers everything measured in real builds (max 13 per
/// function, including unoptimized ones) with headroom, while keeping a
/// hostile function's worst case small.
pub const MAX_TRACKED_SLOTS: usize = 32;

const ALU_OP_ADD: u8 = 0x00;
const ALU_OP_SUB: u8 = 0x10;
const ALU_OP_MOV: u8 = 0xb0;
const ATOMIC_OP_MASK: i32 = 0xf0;
const ATOMIC_OP_CMPXCHG: i32 = 0xf0;

/// Abstract value tracked per register. The lattice top is [`RegKind::Uninit`]
/// (no information / unreachable); the meet of two distinct concrete kinds is
/// [`RegKind::Unknown`] (bottom for routing purposes).
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub enum RegKind {
  Uninit,
  Stack(StackKind),
  Data,
  Scalar,
  Unknown,
}

#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub enum StackKind {
  Current(Option<i32>),
  Foreign,
}

/// Structural equality on kinds. Written out so that the translation does
/// not go through a derived `PartialEq` it cannot evaluate.
pub fn kind_eq(a: RegKind, b: RegKind) -> bool {
  match (a, b) {
    (RegKind::Uninit, RegKind::Uninit) => true,
    (RegKind::Data, RegKind::Data) => true,
    (RegKind::Scalar, RegKind::Scalar) => true,
    (RegKind::Unknown, RegKind::Unknown) => true,
    (RegKind::Stack(StackKind::Foreign), RegKind::Stack(StackKind::Foreign)) => true,
    (RegKind::Stack(StackKind::Current(None)), RegKind::Stack(StackKind::Current(None))) => true,
    (RegKind::Stack(StackKind::Current(Some(x))), RegKind::Stack(StackKind::Current(Some(y)))) => {
      x == y
    }
    _ => false,
  }
}

/// Greatest lower bound, used at control-flow joins.
pub fn meet(a: RegKind, b: RegKind) -> RegKind {
  if kind_eq(a, b) {
    return a;
  }
  match (a, b) {
    (RegKind::Uninit, other) => other,
    (other, RegKind::Uninit) => other,
    (RegKind::Stack(x), RegKind::Stack(y)) => match (x, y) {
      (StackKind::Current(Some(p)), StackKind::Current(Some(q))) => {
        if p == q {
          RegKind::Stack(StackKind::Current(Some(p)))
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

/// The routing hint a kind yields.
pub fn region_of(kind: RegKind) -> u8 {
  match kind {
    RegKind::Stack(_) => REGION_STACK,
    RegKind::Data => REGION_DATA,
    _ => REGION_UNKNOWN,
  }
}

pub fn is_pointer(kind: RegKind) -> bool {
  match kind {
    RegKind::Stack(_) => true,
    RegKind::Data => true,
    _ => false,
  }
}

pub fn is_stack(kind: RegKind) -> bool {
  match kind {
    RegKind::Stack(_) => true,
    _ => false,
  }
}

/// A local callee sees every caller stack pointer as foreign.
pub fn foreign_for_call(kind: RegKind) -> RegKind {
  match kind {
    RegKind::Stack(_) => RegKind::Stack(StackKind::Foreign),
    other => other,
  }
}

/// Whether a stack pointer of this kind may alias the current frame.
pub fn aliases_current_stack(kind: RegKind) -> bool {
  match kind {
    RegKind::Stack(StackKind::Foreign) => false,
    _ => true,
  }
}

/// The frame pointer's kind: the current frame at displacement 0.
pub fn frame_pointer_kind() -> RegKind {
  RegKind::Stack(StackKind::Current(Some(0)))
}

/// One tracked spill slot: its `R10`-relative byte offset, the state's
/// invalidation epoch when it was written, and the kind written.
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug))]
pub struct Slot {
  pub off: i32,
  pub epoch: u64,
  pub kind: RegKind,
}

/// The tracked spill slots of a state. Absent slots are `Uninit` (top). An
/// entry whose epoch predates `invalid_epoch` reads as `Unknown`.
///
/// Its own struct, and every function on it takes only it: what a spill
/// slot reads back as depends on the slots alone, never on a register, and
/// `lean/AsyncEbpf/Region` gets that for free.
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug))]
pub struct Spills {
  pub slots: [Slot; MAX_TRACKED_SLOTS],
  /// Entries `0..num_slots` of `slots` are meaningful.
  pub num_slots: usize,
  /// Bumped by [`invalidate_slots`]; every entry written before the current
  /// value reads as `Unknown`.
  pub invalid_epoch: u64,
}

/// Abstract state at a program point: the kind of every register plus the
/// kinds of values spilled to `R10`-relative stack slots.
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug))]
pub struct State {
  pub regs: [RegKind; NUM_REGS],
  pub spills: Spills,
}

const EMPTY_SLOT: Slot = Slot {
  off: 0,
  epoch: 0,
  kind: RegKind::Uninit,
};

/// The state nothing has reached.
pub fn top() -> State {
  State {
    regs: [RegKind::Uninit; NUM_REGS],
    spills: Spills {
      slots: [EMPTY_SLOT; MAX_TRACKED_SLOTS],
      num_slots: 0,
      invalid_epoch: 0,
    },
  }
}

/// The kind an entry written at `epoch` with value `kind` currently has.
fn effective_kind(spills: &Spills, epoch: u64, kind: RegKind) -> RegKind {
  if epoch >= spills.invalid_epoch {
    kind
  } else {
    RegKind::Unknown
  }
}

/// The index of the entry for `off`, if tracked.
fn find_slot(spills: &Spills, off: i32) -> Option<usize> {
  let mut i = 0;
  while i < spills.num_slots {
    if spills.slots[i].off == off {
      return Some(i);
    }
    i += 1;
  }
  None
}

/// The kind currently tracked at `off`: `Uninit` if untracked, `Unknown` if
/// invalidated.
pub fn slot_kind(spills: &Spills, off: i32) -> RegKind {
  match find_slot(spills, off) {
    None => RegKind::Uninit,
    Some(i) => effective_kind(spills, spills.slots[i].epoch, spills.slots[i].kind),
  }
}

/// Inserts one spill entry if it is already tracked or the cap has room.
/// Returns whether it was inserted.
pub fn insert_slot(spills: &mut Spills, off: i32, epoch: u64, kind: RegKind) -> bool {
  match find_slot(spills, off) {
    Some(i) => {
      spills.slots[i] = Slot { off, epoch, kind };
      true
    }
    None => {
      if spills.num_slots < MAX_TRACKED_SLOTS {
        spills.slots[spills.num_slots] = Slot { off, epoch, kind };
        spills.num_slots += 1;
        true
      } else {
        false
      }
    }
  }
}

/// Marks every tracked slot `Unknown` after a store that may alias the
/// stack at an offset that cannot be pinned down. Lazy: bumping the epoch
/// makes every entry written before it read as `Unknown`.
pub fn invalidate_slots(spills: &mut Spills) {
  spills.invalid_epoch += 1;
}

/// Whether the 8-byte slot at `slot_off` overlaps `[start, end)`.
fn slot_overlaps(slot_off: i32, start: i32, end: i32) -> bool {
  // `slot_off + 8` overflowing means the slot runs to the top of the
  // address space; treat it as overlapping, as the map-based version did.
  if slot_off > i32::MAX - 8 {
    return true;
  }
  let slot_end = slot_off + 8;
  start < slot_end && slot_off < end
}

/// Invalidates tracked spill slots overlapped by a stack write of `width`
/// bytes at frame offset `start`; every slot if the offset is unknown or
/// the range overflows.
pub fn invalidate_stack_write(spills: &mut Spills, start: Option<i32>, width: u8) {
  let start = match start {
    None => {
      invalidate_slots(spills);
      return;
    }
    Some(s) => s,
  };
  let width = width as i32;
  if start > i32::MAX - width {
    invalidate_slots(spills);
    return;
  }
  let end = start + width;
  let mut i = 0;
  while i < spills.num_slots {
    if slot_overlaps(spills.slots[i].off, start, end) {
      spills.slots[i] = Slot {
        off: spills.slots[i].off,
        epoch: spills.invalid_epoch,
        kind: RegKind::Unknown,
      };
    }
    i += 1;
  }
}

/// Per-register meet of `regs` with `other`. Returns whether `regs` changed.
fn meet_regs(regs: &mut [RegKind; NUM_REGS], other: &[RegKind; NUM_REGS]) -> bool {
  let mut changed = false;
  let mut r = 0;
  while r < NUM_REGS {
    let merged = meet(regs[r], other[r]);
    if !kind_eq(merged, regs[r]) {
      regs[r] = merged;
      changed = true;
    }
    r += 1;
  }
  changed
}

/// Meet of the spill slots over the union of tracked offsets; an absent
/// slot is `Uninit` (top). Returns `(changed, refused)`.
fn meet_spills(spills: &mut Spills, other: &Spills) -> (bool, bool) {
  let mut changed = false;
  let mut refused = false;
  if spills.num_slots == 0 {
    // Nothing tracked yet: every key of `other` meets Uninit into itself,
    // so adopt the incoming slots wholesale, epoch included.
    if other.num_slots != 0 {
      *spills = *other;
      changed = true;
    }
  } else {
    let mut i = 0;
    while i < other.num_slots {
      let off = other.slots[i].off;
      let cur = slot_kind(spills, off);
      let incoming = effective_kind(other, other.slots[i].epoch, other.slots[i].kind);
      let merged = meet(cur, incoming);
      if !kind_eq(merged, cur) {
        // A key the cap refuses stays untracked (reads as Scalar), the same
        // safe fallback as an absent key, and leaves `changed` alone: the
        // state's observable behavior is unchanged, so the fixpoint
        // terminates as before.
        if insert_slot(spills, off, spills.invalid_epoch, merged) {
          changed = true;
        } else {
          refused = true;
        }
      }
      i += 1;
    }
  }
  (changed, refused)
}

/// Per-element meet of `state` with `other`. Returns `(changed, refused)`:
/// whether `state` changed, and whether the slot cap refused an entry.
pub fn meet_from(state: &mut State, other: &State) -> (bool, bool) {
  let regs_changed = meet_regs(&mut state.regs, &other.regs);
  let (spills_changed, refused) = meet_spills(&mut state.spills, &other.spills);
  (regs_changed || spills_changed, refused)
}

/// The abstract register file a call site hands its callee.
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub struct PointerSignature {
  pub regs: [RegKind; NUM_REGS],
}

/// Mask over the registers a [`PointerSignature`] can carry (`R0`-`R9`).
/// `R10` is never included: it is the frame pointer, fixed to the current
/// frame at every function entry regardless of the caller.
pub type RegMask = u16;

/// Every register a signature can carry.
pub const ALL_SIGNATURE_REGS: RegMask = 0x03ff;

/// Registers a helper call reads (`R1`-`R5`) and the ones any call leaves
/// clobbered (`R0`-`R5`), matching how [`transfer`] models a call.
pub const HELPER_ARG_REGS: RegMask = 0b011_1110;
pub const CALL_CLOBBERED_REGS: RegMask = 0b011_1111;

/// The entry signature: the trampoline zeroes every register except `R1`
/// (the ctx, which points into the guest stack) and `R10`.
pub fn entry_signature() -> PointerSignature {
  let mut regs = [RegKind::Scalar; NUM_REGS];
  regs[1] = RegKind::Stack(StackKind::Current(None));
  regs[R10] = frame_pointer_kind();
  PointerSignature { regs }
}

/// The state a function starts in under `sig`.
pub fn apply_signature(sig: &PointerSignature, state: &mut State) {
  state.regs = sig.regs;
  state.regs[R10] = frame_pointer_kind();
}

/// The signature a call site passes: the caller's registers, its stack
/// pointers turned foreign, its frame pointer replaced by the callee's.
pub fn signature_from_state(state: &State) -> PointerSignature {
  let mut regs = state.regs;
  let mut reg = 0;
  while reg < NUM_REGS {
    if reg != R10 {
      regs[reg] = foreign_for_call(regs[reg]);
    }
    reg += 1;
  }
  regs[R10] = frame_pointer_kind();
  PointerSignature { regs }
}

/// Sets every register outside `mask` to `Unknown`, `R10` excepted.
///
/// This is the projection onto a slot's live-in registers. [`entry_state`]
/// applies it to a function's entry and `fixpoint::propagate` to every value
/// flowing into a slot, so a dead register never carries a kind at all:
/// what the analysis reports cannot depend on one, and neither can the
/// order in which its worklist visits slots. Masking a call signature
/// ([`mask_signature`]) is the same projection.
pub fn project_regs(regs: &mut [RegKind; NUM_REGS], mask: RegMask) {
  let mut reg = 0;
  while reg < NUM_REGS {
    if reg != R10 && mask & (1 << reg) == 0 {
      set_kind(regs, reg, RegKind::Unknown);
    }
    reg += 1;
  }
}

/// Projects `state`'s registers onto `live`; the spill slots are untouched.
pub fn project(state: &mut State, live: RegMask) {
  project_regs(&mut state.regs, live);
}

/// Drops every register outside `mask`, i.e. every register the callee
/// cannot observe.
pub fn mask_signature(sig: &PointerSignature, mask: RegMask) -> PointerSignature {
  let mut regs = sig.regs;
  project_regs(&mut regs, mask);
  PointerSignature { regs }
}

/// The state a function starts in under `sig`, projected onto the live-in
/// registers of its entry slot.
pub fn entry_state(sig: &PointerSignature, live: RegMask) -> State {
  let mut state = top();
  apply_signature(sig, &mut state);
  project(&mut state, live);
  state
}

/// `regs[reg] = kind`; see [`set_reg`] for why this is a function.
fn set_kind(regs: &mut [RegKind; NUM_REGS], reg: usize, kind: RegKind) {
  regs[reg] = kind;
}

/// Bytes a load, store or atomic touches, from the size bits.
pub fn access_width(opcode: u8) -> u8 {
  match opcode & 0x18 {
    0x00 => 4, // W
    0x08 => 2, // H
    0x10 => 1, // B
    _ => 8,    // DW
  }
}

/// Whether `opcode` is an atomic (`STX` with the atomic mode bits).
pub fn is_atomic(opcode: u8) -> bool {
  opcode & CLS_MASK == CLS_STX && opcode & 0xe0 == 0xc0
}

/// The frame offset a stack access starts at, when its base is at a known
/// displacement from the frame pointer.
pub fn stack_access_start(base: RegKind, offset: i16) -> Option<i32> {
  match base {
    RegKind::Stack(StackKind::Current(Some(base_off))) => checked_add_i32(base_off, offset as i32),
    _ => None,
  }
}

fn checked_add_i32(a: i32, b: i32) -> Option<i32> {
  if b >= 0 {
    if a > i32::MAX - b {
      return None;
    }
  } else if a < i32::MIN - b {
    return None;
  }
  Some(a + b)
}

/// `-imm` with wraparound, as `i32::wrapping_neg`.
fn wrapping_neg_i32(imm: i32) -> i32 {
  if imm == i32::MIN {
    i32::MIN
  } else {
    -imm
  }
}

/// Whether `inst`, whose pointer operand is register `base`, is a frame
/// access the JIT may emit with no bounds check at all.
///
/// This is the one hint that removes a runtime check rather than narrowing
/// one, so the conditions are worth stating in full:
///
///  * **The base is `R10` itself**, not a register derived from it. A derived
///    register holds a *guest* address at run time - the backend hands
///    programs the guest frame pointer wherever they read `R10` as a value -
///    so its displacement is not the one a native frame access would use.
///  * **`R10` still holds the frame pointer.** No instruction can assign it
///    and the loader refuses every program that tries, but an assignment
///    would show up here as `Unknown`, so check rather than assume.
///  * **The access lies in `[R10 - frame_size, R10)`.** That window is inside
///    the guest stack at every call depth the loader accepts
///    (`lean/AsyncEbpf/Semantics/Frames.lean`).
///
/// Atomics are excluded: a fetching atomic writes its source register, so it
/// is not purely an access, and the loader refuses the frame-pointer cases
/// anyway.
pub fn frame_access(state: &State, inst: &Insn, base: usize, frame_size: u16) -> bool {
  if base != R10 {
    return false;
  }
  if !kind_eq(state.regs[R10], frame_pointer_kind()) {
    return false;
  }
  if is_atomic(inst.opcode) {
    return false;
  }
  in_frame_window(frame_size, inst.offset, access_width(inst.opcode))
}

/// The routing hint for the instruction at a slot with abstract state
/// `state`: `(is_access, hint, region)`. `is_access` is false for anything
/// but a load, store or atomic; `region` is the plain classification of the
/// base, and `hint` is `REGION_FRAME` where [`frame_access`] admits it.
pub fn classify(state: &State, inst: &Insn, frame_size: u16) -> (bool, u8, u8) {
  let cls = inst.opcode & CLS_MASK;
  let base = if cls == CLS_LDX {
    inst.src as usize
  } else if cls == CLS_ST || cls == CLS_STX {
    inst.dst as usize
  } else {
    return (false, REGION_UNKNOWN, REGION_UNKNOWN);
  };
  // Named `plain` rather than `region`: a local of that name would shadow
  // this module's namespace in the translation.
  let plain = region_of(state.regs[base]);
  if frame_access(state, inst, base, frame_size) {
    (true, REGION_FRAME, plain)
  } else {
    (true, plain, plain)
  }
}

/// `ptr + scalar` preserves the pointer's region; `scalar + scalar` is scalar.
pub fn add_kinds(a: RegKind, b: RegKind) -> RegKind {
  match (a, b) {
    (RegKind::Stack(StackKind::Foreign), RegKind::Scalar) => RegKind::Stack(StackKind::Foreign),
    (RegKind::Scalar, RegKind::Stack(StackKind::Foreign)) => RegKind::Stack(StackKind::Foreign),
    (RegKind::Stack(_), RegKind::Scalar) => RegKind::Stack(StackKind::Current(None)),
    (RegKind::Scalar, RegKind::Stack(_)) => RegKind::Stack(StackKind::Current(None)),
    (RegKind::Data, RegKind::Scalar) => RegKind::Data,
    (RegKind::Scalar, RegKind::Data) => RegKind::Data,
    (RegKind::Scalar, RegKind::Scalar) => RegKind::Scalar,
    _ => RegKind::Unknown,
  }
}

/// `ptr - scalar` preserves the region; `ptr - ptr` (same region) is a scalar.
pub fn sub_kinds(a: RegKind, b: RegKind) -> RegKind {
  match (a, b) {
    (RegKind::Stack(StackKind::Foreign), RegKind::Scalar) => RegKind::Stack(StackKind::Foreign),
    (RegKind::Stack(_), RegKind::Scalar) => RegKind::Stack(StackKind::Current(None)),
    (RegKind::Data, RegKind::Scalar) => RegKind::Data,
    (RegKind::Stack(_), RegKind::Stack(_)) => RegKind::Scalar,
    (RegKind::Data, RegKind::Data) => RegKind::Scalar,
    (RegKind::Scalar, RegKind::Scalar) => RegKind::Scalar,
    _ => RegKind::Unknown,
  }
}

/// Adding an immediate preserves the region; for a known frame displacement,
/// it moves the displacement.
pub fn add_imm_kind(a: RegKind, imm: i32) -> RegKind {
  match a {
    RegKind::Stack(StackKind::Current(Some(off))) => {
      RegKind::Stack(StackKind::Current(checked_add_i32(off, imm)))
    }
    RegKind::Stack(StackKind::Current(None)) => RegKind::Stack(StackKind::Current(None)),
    RegKind::Stack(StackKind::Foreign) => RegKind::Stack(StackKind::Foreign),
    RegKind::Data => RegKind::Data,
    RegKind::Scalar => RegKind::Scalar,
    _ => RegKind::Unknown,
  }
}

/// The value a load yields: a spilled pointer when a fill off `R10` finds
/// one tracked, a scalar otherwise.
fn load_kind(spills: &Spills, inst: &Insn) -> RegKind {
  if inst.src as usize == R10 {
    let k = slot_kind(spills, inst.offset as i32);
    if is_pointer(k) {
      k
    } else {
      RegKind::Scalar
    }
  } else {
    RegKind::Scalar
  }
}

/// `state.regs[reg] = kind`. A function rather than an assignment so that
/// the translation sees the kind as a value (an assignment of a fieldless
/// variant through a literal index came out as a discriminant write).
fn set_reg(state: &mut State, reg: usize, kind: RegKind) {
  state.regs[reg] = kind;
}

/// The abstract state after a store or atomic. Returns whether the slot
/// cap refused a spill.
fn transfer_store(s: &mut State, inst: &Insn, cls: u8) -> bool {
  let atomic = is_atomic(inst.opcode);
  // Value being stored: ST writes an immediate (scalar); STX writes a reg.
  let value = if cls == CLS_ST {
    RegKind::Scalar
  } else {
    s.regs[inst.src as usize]
  };
  let width = access_width(inst.opcode);
  let stack_base = if inst.dst as usize == R10 {
    frame_pointer_kind()
  } else {
    s.regs[inst.dst as usize]
  };
  let mut refused = false;
  if is_stack(stack_base) {
    if aliases_current_stack(stack_base) {
      let start = stack_access_start(stack_base, inst.offset);
      invalidate_stack_write(&mut s.spills, start, width);
    }
    let stored = if atomic {
      RegKind::Unknown
    } else {
      match value {
        RegKind::Uninit => RegKind::Unknown,
        v => v,
      }
    };
    if !atomic && width == 8 {
      if let Some(start) = stack_access_start(stack_base, inst.offset) {
        let epoch = s.spills.invalid_epoch;
        if !insert_slot(&mut s.spills, start, epoch, stored) {
          refused = true;
        }
      }
    }
  } else {
    match s.regs[inst.dst as usize] {
      RegKind::Data => {}
      // A store through an unknown/scalar base may alias an untracked stack
      // slot; conservatively invalidate all tracked slots.
      _ => invalidate_slots(&mut s.spills),
    }
  }
  if atomic {
    // An atomic fetch writes the previous value into src.
    s.regs[inst.src as usize] = RegKind::Unknown;
    if inst.imm & ATOMIC_OP_MASK == ATOMIC_OP_CMPXCHG {
      // CMPXCHG leaves src alone and writes the previous memory contents
      // into R0 instead. The guest chooses those contents, so R0 must not
      // keep the provenance it had before the instruction.
      s.regs[0] = RegKind::Unknown;
    }
  }
  refused
}

/// The abstract state after a 64-bit ALU instruction.
fn transfer_alu64(s: &mut State, inst: &Insn) {
  let op = inst.opcode & ALU_MASK;
  let is_reg = inst.opcode & SRC_REG != 0;
  let dst = inst.dst as usize;
  let src = inst.src as usize;
  if op == ALU_OP_MOV {
    s.regs[dst] = if is_reg {
      match s.regs[src] {
        RegKind::Uninit => RegKind::Unknown,
        k => k,
      }
    } else {
      RegKind::Scalar
    };
  } else if op == ALU_OP_ADD {
    s.regs[dst] = if is_reg {
      add_kinds(s.regs[dst], s.regs[src])
    } else {
      add_imm_kind(s.regs[dst], inst.imm)
    };
  } else if op == ALU_OP_SUB {
    s.regs[dst] = if is_reg {
      sub_kinds(s.regs[dst], s.regs[src])
    } else {
      add_imm_kind(s.regs[dst], wrapping_neg_i32(inst.imm))
    };
  } else {
    // All other 64-bit ALU ops (mul/div/and/or/xor/shifts/neg/mod/end) are
    // conservatively scalars for routing purposes.
    s.regs[dst] = RegKind::Scalar;
  }
}

/// Abstract transfer function: the state after executing `inst` from
/// `in_state`. `lddw_addr` is the full 64-bit immediate of an `lddw`,
/// `[data_lo, data_hi)` the guest data region. Returns the state and
/// whether the slot cap refused a spill.
pub fn transfer(
  in_state: &State,
  inst: &Insn,
  lddw_addr: u64,
  data_lo: u64,
  data_hi: u64,
) -> (State, bool) {
  let mut s = *in_state;
  let cls = inst.opcode & CLS_MASK;
  let mut refused = false;

  if cls == CLS_LD {
    // Only LDDW reaches here (LD|IMM|DW). It materializes a 64-bit constant;
    // a relocated data pointer falls inside [data_lo, data_hi).
    s.regs[inst.dst as usize] = if inst.opcode == OP_LDDW {
      if lddw_addr >= data_lo && lddw_addr < data_hi {
        RegKind::Data
      } else {
        RegKind::Scalar
      }
    } else {
      RegKind::Unknown
    };
  } else if cls == CLS_LDX {
    // A value loaded from memory is a scalar for routing purposes, unless a
    // fill off R10 recovers a spilled pointer still tracked at that offset.
    s.regs[inst.dst as usize] = load_kind(&s.spills, inst);
  } else if cls == CLS_ST || cls == CLS_STX {
    refused = transfer_store(&mut s, inst, cls);
  } else if cls == CLS_ALU {
    // A 32-bit ALU result cannot be a valid 64-bit pointer.
    s.regs[inst.dst as usize] = RegKind::Scalar;
  } else if cls == CLS_ALU64 {
    transfer_alu64(&mut s, inst);
  } else if inst.opcode == OP_CALL {
    // Helper/local call: R0 is the return value, R1-R5 are caller-saved and
    // clobbered; R6-R10 are preserved. Tracked spills are kept across the
    // call (see the module docs for what that assumes).
    set_reg(&mut s, 0, RegKind::Scalar);
    let mut r = 1;
    while r <= 5 {
      set_reg(&mut s, r, RegKind::Unknown);
      r += 1;
    }
  }

  (s, refused)
}

/// The bit of `reg` in a [`RegMask`]; `R10` has none.
pub fn reg_bit(reg: usize) -> RegMask {
  if reg < R10 {
    1 << reg
  } else {
    0
  }
}

/// Registers `inst` reads and writes.
///
/// `uses` comes from the instruction encoding - every register the opcode
/// reads, whether or not [`transfer`] consults its kind. `defs` must be a
/// *subset* of what the instruction overwrites: a def kills liveness, so
/// over-claiming one would drop a register the callee can still observe.
/// Fetching atomics write `src` (and CMPXCHG writes `R0`) conditionally on
/// the operation selector, so they claim no definition at all.
pub fn uses_and_defs(inst: &Insn, callee_live_in: RegMask) -> (RegMask, RegMask) {
  let cls = inst.opcode & CLS_MASK;
  let dst = inst.dst as usize;
  let src = inst.src as usize;
  if cls == CLS_LD {
    // Only LDDW reaches here; it materializes a constant into dst.
    (0, reg_bit(dst))
  } else if cls == CLS_LDX {
    (reg_bit(src), reg_bit(dst))
  } else if cls == CLS_ST {
    (reg_bit(dst), 0)
  } else if cls == CLS_STX {
    let mut uses = reg_bit(dst) | reg_bit(src);
    if is_atomic(inst.opcode) {
      uses |= reg_bit(0);
    }
    (uses, 0)
  } else if cls == CLS_ALU || cls == CLS_ALU64 {
    let src_bits = if inst.opcode & SRC_REG != 0 {
      reg_bit(src)
    } else {
      0
    };
    if inst.opcode & ALU_MASK == ALU_OP_MOV {
      (src_bits, reg_bit(dst))
    } else {
      (src_bits | reg_bit(dst), reg_bit(dst))
    }
  } else if cls == CLS_JMP || cls == CLS_JMP32 {
    if inst.opcode == OP_EXIT {
      // `exit` hands the callee's R0 back to its caller, but the caller
      // models the result of any call as a fresh scalar, so an incoming R0
      // kind is never observable through a return.
      (0, 0)
    } else if inst.opcode == OP_CALL {
      if inst.src == 0 {
        (HELPER_ARG_REGS, CALL_CLOBBERED_REGS)
      } else if inst.src == 1 || inst.src == 2 {
        // A local callee sees the caller's whole register file, so the call
        // reads whatever the callee reads.
        (callee_live_in, CALL_CLOBBERED_REGS)
      } else {
        (0, 0)
      }
    } else if inst.opcode == OP_JA || inst.opcode == OP_JA32 {
      (0, 0)
    } else {
      let src_bits = if inst.opcode & SRC_REG != 0 {
        reg_bit(src)
      } else {
        0
      };
      (src_bits | reg_bit(dst), 0)
    }
  } else {
    (0, 0)
  }
}

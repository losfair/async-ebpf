//! The aarch64 backend.
//!
//! # Changing what this emits
//!
//! Every byte this backend produces for the canonical cases is recorded in
//! `src/jit/goldens/aarch64.txt`, so any change to code generation shows up as a
//! diff there. That is deliberate: the diff is the deliverable, and an
//! unexplained one means something moved that nobody meant to move.
//!
//! # Quirks worth knowing before reading
//!
//! Each of these is deliberate and labelled where it lives. None is reachable
//! through `Translator::load`, because the validator refuses the programs that
//! would reach them; they are retained as defence in depth, not as behaviour
//! anything depends on.
//!
//! * `le` with `imm == 64` emits nothing at all, and `be` with `imm == 32`
//!   emits no zero-extension where `bswap` does.
//! * A `st` whose raw `src` nibble is 10 would, under a native frame base, have
//!   the guest frame pointer materialised over the immediate it just parked in
//!   the same register. The check reads the raw nibble rather than the lowered
//!   operand; the operand filter bounds `st`'s source to zero, so no such
//!   program loads.
//! * `resolve_adr` writes only the `immhi` field and drops the two `immlo` bits.
//! * The atomic selector is the immediate's high nibble and the fetch flag its
//!   low bit, with bits 1..3 dead. `xchg` and `cmpxchg` fetch whether or not the
//!   flag is set, because this backend hardcodes it. That matches
//!   [`Insn::op_with_imm`], so decoder and backend agree on the non-canonical
//!   selectors the 32-bit operand filter admits.
//!
//! # What is not here
//!
//! Whole-program translation, the eager local call, and constant blinding.
//! `translate_range` always translates one function at a time and always
//! resolves local calls lazily, so none of them is reachable.

use crate::jit::abi;
use crate::jit::isa::{AluOp, AtomicOp, EndKind, Insn, JmpOp, Op, Source, Width};
use crate::jit::patch::{JitState, OpenGroup, PatchTarget, Progress, SpecialTarget};
use crate::jit::{Config, PlanEntry, TranslateError, TranslationInputs, Translator};

// ---------------------------------------------------------------------------
// Registers
// ---------------------------------------------------------------------------

const R0: u32 = 0;
const R2: u32 = 2;
const R3: u32 = 3;
const R5: u32 = 5;
const R6: u32 = 6;
const R8: u32 = 8;
const R9: u32 = 9;
const R16: u32 = 16;
const R17: u32 = 17;
const R19: u32 = 19;
const R20: u32 = 20;
const R21: u32 = 21;
const R22: u32 = 22;
const R23: u32 = 23;
const R24: u32 = 24;
const R25: u32 = 25;
const R26: u32 = 26;
const R29: u32 = 29;
const R30: u32 = 30;
/// The stack pointer and the zero register share encoding 31; which one an
/// instruction means is fixed by the instruction, not by the operand.
const SP: u32 = 31;
const RZ: u32 = 31;

/// Temp register for immediate generation.
const TEMP_REGISTER: u32 = R24;
/// Value register for a store-immediate lowered to a store-register.
const TEMP_STORE_VALUE_REGISTER: u32 = R9;
/// Temp register for division results.
const TEMP_DIV_REGISTER: u32 = R25;
/// Temp register for load/store offsets.
const OFFSET_REGISTER: u32 = R26;
/// Special register for external dispatcher context. Aliases [`OFFSET_REGISTER`]
/// here too.
const VOLATILE_CTXT: u32 = R26;

/// eBPF register to aarch64 register. `R0` is held in `R5` for the
/// duration of the function and moved into the ABI return register only at the
/// end.
const REGISTER_MAP: [u32; 11] = [R5, R0, 1, R2, R3, 4, R19, R20, R21, R22, R23];

/// The aarch64 register holding eBPF register `r`.
/// Wraps modularly rather than panicking on an out-of-range register, so a
/// register field the validator would have refused still maps to something.
fn map_register(r: u8) -> u32 {
  REGISTER_MAP[(r as usize) % REGISTER_MAP.len()]
}

/// The eBPF register mapped to `native`, or `None`. The map is injective, so
/// this is exact.
fn unmap_register(native: u32) -> Option<u8> {
  REGISTER_MAP
    .iter()
    .position(|&n| n == native)
    .map(|r| r as u8)
}

// ---------------------------------------------------------------------------
// Instruction encodings
// ---------------------------------------------------------------------------

/// `AddSubOpcode`, used as the two-bit `op` field at bit 29.
mod addsub {
  pub const ADD: u32 = 0;
  /// Present for completeness; nothing this entry point
  /// reaches emits a flag-setting add.
  #[allow(dead_code)]
  pub const ADDS: u32 = 1;
  pub const SUB: u32 = 2;
  pub const SUBS: u32 = 3;
}

/// `LoadStoreOpcode`.
mod ls {
  pub const STRB: u32 = 0x0000_0000;
  pub const LDRB: u32 = 0x0040_0000;
  pub const LDRL: u32 = 0x5000_0000;
  pub const LDRSBX: u32 = 0x0080_0000;
  pub const STRH: u32 = 0x4000_0000;
  pub const LDRH: u32 = 0x4040_0000;
  pub const LDRSHX: u32 = 0x4080_0000;
  pub const STRW: u32 = 0x8000_0000;
  pub const LDRW: u32 = 0x8040_0000;
  pub const LDRSW: u32 = 0x8080_0000;
  pub const STRX: u32 = 0xc000_0000;
  pub const LDRX: u32 = 0xc040_0000;
}

/// `LoadStoreExclusiveOpcode`.
mod lse {
  pub const STXRW: u32 = 0x8800_7c00;
  pub const LDXRW: u32 = 0x885f_7c00;
  pub const STXRX: u32 = 0xc800_7c00;
  pub const LDXRX: u32 = 0xc85f_7c00;
}

/// `LoadStorePairOpcode`.
mod lsp {
  pub const STPX: u32 = 0xa900_0000;
  pub const LDPX: u32 = 0xa940_0000;
}

/// `LogicalOpcode`.
mod log {
  pub const AND: u32 = 0x0000_0000;
  pub const ORR: u32 = 0x2000_0000;
  pub const EOR: u32 = 0x4000_0000;
  pub const ANDS: u32 = 0x6000_0000;
}

/// `UnconditionalBranchOpcode`.
mod br {
  pub const BLR: u32 = 0xd63f_0000;
  pub const RET: u32 = 0xd65f_0000;
}

/// `UnconditionalBranchImmediateOpcode`.
mod ubr {
  pub const B: u32 = 0x1400_0000;
  pub const BL: u32 = 0x9400_0000;
}

const BR_BCOND: u32 = 0x5400_0000;

/// `Condition`.
mod cond {
  pub const EQ: u32 = 0;
  pub const NE: u32 = 1;
  pub const CS: u32 = 2;
  pub const CC: u32 = 3;
  pub const HI: u32 = 8;
  pub const LS: u32 = 9;
  pub const GE: u32 = 10;
  pub const LT: u32 = 11;
  pub const GT: u32 = 12;
  pub const LE: u32 = 13;
  pub const HS: u32 = CS;
  pub const LO: u32 = CC;
}

/// `DP1Opcode`.
mod dp1 {
  pub const REV16: u32 = 0x5ac0_0400;
  pub const REV32: u32 = 0x5ac0_0800;
  pub const REV64: u32 = 0xdac0_0c00;
}

/// `DP2Opcode`.
mod dp2 {
  pub const UDIV: u32 = 0x1ac0_0800;
  pub const SDIV: u32 = 0x1ac0_0c00;
  pub const LSLV: u32 = 0x1ac0_2000;
  pub const LSRV: u32 = 0x1ac0_2400;
  pub const ASRV: u32 = 0x1ac0_2800;
}

/// `DP3Opcode`.
mod dp3 {
  pub const MADD: u32 = 0x1b00_0000;
  pub const MSUB: u32 = 0x1b00_8000;
}

/// `MoveWideOpcode`.
mod mw {
  pub const MOVN: u32 = 0x1280_0000;
  pub const MOVZ: u32 = 0x5280_0000;
  pub const MOVK: u32 = 0x7280_0000;
}

/// `bti c`, emitted as the first instruction of every lazily compiled function
/// because it is entered through an indirect call.
const BTI_C: u32 = 0xd503_245f;

fn align_to(amount: u32, boundary: u32) -> u32 {
  (amount + (boundary - 1)) & !(boundary - 1)
}

/// Bit 31, the size bit in most encodings.
fn sz(sixty_four: bool) -> u32 {
  if sixty_four {
    1 << 31
  } else {
    0
  }
}

fn emit_instruction(st: &mut JitState, instr: u32) {
  st.emit_bytes(instr as u64, 4);
}

/// C4.1.64 add/subtract (immediate).
fn emit_addsub_immediate(
  st: &mut JitState,
  sixty_four: bool,
  op: u32,
  rd: u32,
  rn: u32,
  imm12: u32,
) {
  let mut imm12 = imm12;
  let mut sh = 0;
  if imm12 >= 0x1000 {
    // The low twelve bits must be clear; with the shift on they have
    // no bearing on the result. Every reachable caller satisfies it.
    debug_assert_eq!(imm12 & 0xfff, 0);
    imm12 >>= 12;
    sh = 1 << 22;
  }
  debug_assert!(imm12 < 0x1000);
  emit_instruction(
    st,
    sz(sixty_four) | sh | (op << 29) | 0x1100_0000 | (imm12 << 10) | (rn << 5) | rd,
  );
}

/// C4.1.67 add/subtract (shifted register).
fn emit_addsub_register(st: &mut JitState, sixty_four: bool, op: u32, rd: u32, rn: u32, rm: u32) {
  emit_instruction(
    st,
    sz(sixty_four) | (op << 29) | 0x0b00_0000 | (rm << 16) | (rn << 5) | rd,
  );
}

/// C4.1.66 load/store register, unscaled immediate.
/// This is the *unscaled* form: `imm9` is a byte displacement in `[-256, 256)`
/// regardless of the access width. Using the scaled unsigned-offset form would
/// change every one of these bytes.
fn emit_loadstore_immediate(st: &mut JitState, op: u32, rt: u32, rn: u32, imm9: i16) {
  debug_assert!((-256..256).contains(&imm9));
  let imm9 = (imm9 as u32) & 0x1ff;
  emit_instruction(st, 0x3800_0000 | op | (imm9 << 12) | (rn << 5) | rt);
}

/// Load-exclusive / store-exclusive, for atomics.
fn emit_loadstore_exclusive(st: &mut JitState, op: u32, rt: u32, rn: u32, rs: u32) {
  emit_instruction(st, op | (rs << 16) | (rn << 5) | rt);
}

/// PC-relative literal load; the displacement is patched later.
fn emit_loadstore_literal(st: &mut JitState, op: u32, rt: u32, target: PatchTarget) {
  note_load(st, target);
  emit_instruction(st, op | 0x0800_0000 | rt);
}

/// PC-relative address; the displacement is patched later.
fn emit_adr(st: &mut JitState, target: PatchTarget, rd: u32) {
  note_lea(st, target);
  emit_instruction(st, 0x1000_0000 | rd);
}

/// C4.1.66 load/store register pair, offset form.
fn emit_loadstorepair_immediate(st: &mut JitState, op: u32, rt: u32, rt2: u32, rn: u32, imm7: i32) {
  let imm_div = if op == lsp::STPX || op == lsp::LDPX {
    8
  } else {
    4
  };
  debug_assert_eq!(imm7 % imm_div, 0);
  let imm7 = imm7 / imm_div;
  emit_instruction(
    st,
    op | ((imm7 as u32) << 15) | (rt2 << 10) | (rn << 5) | rt,
  );
}

/// C4.1.67 logical (shifted register).
fn emit_logical_register(st: &mut JitState, sixty_four: bool, op: u32, rd: u32, rn: u32, rm: u32) {
  emit_instruction(
    st,
    sz(sixty_four) | op | (1 << 27) | (1 << 25) | (rm << 16) | (rn << 5) | rd,
  );
}

/// `CSEL Rd, Rn, Rm, cond` (64-bit): `Rd = cond ? Rn : Rm`.
fn emit_conditionalselect(st: &mut JitState, rd: u32, rn: u32, rm: u32, c: u32) {
  emit_instruction(st, 0x9a80_0000 | (rm << 16) | (c << 12) | (rn << 5) | rd);
}

/// `CCMP Rn, Rm, #nzcv, cond` (64-bit).
fn emit_conditionalcompare(st: &mut JitState, rn: u32, rm: u32, nzcv: u32, c: u32) {
  emit_instruction(
    st,
    0xfa40_0000 | (rm << 16) | (c << 12) | (rn << 5) | (nzcv & 0xf),
  );
}

/// C4.1.67 data-processing, one source.
fn emit_dataprocessing_onesource(st: &mut JitState, sixty_four: bool, op: u32, rd: u32, rn: u32) {
  emit_instruction(st, sz(sixty_four) | op | (rn << 5) | rd);
}

/// C4.1.67 data-processing, two sources.
fn emit_dataprocessing_twosource(
  st: &mut JitState,
  sixty_four: bool,
  op: u32,
  rd: u32,
  rn: u32,
  rm: u32,
) {
  emit_instruction(st, sz(sixty_four) | op | (rm << 16) | (rn << 5) | rd);
}

/// C4.1.67 data-processing, three sources.
fn emit_dataprocessing_threesource(
  st: &mut JitState,
  sixty_four: bool,
  op: u32,
  rd: u32,
  rn: u32,
  rm: u32,
  ra: u32,
) {
  emit_instruction(
    st,
    sz(sixty_four) | op | (rm << 16) | (ra << 10) | (rn << 5) | rd,
  );
}

/// C4.1.64 move wide (immediate).
/// A `MOVZ`/`MOVN` followed by `MOVK`s, choosing whichever of the `0x0000` and
/// `0xffff` block patterns is more common so the sequence is as short as
/// possible. The *number* of instructions therefore depends on the value: one
/// for `0`, `-1` and any single non-zero halfword, up to four for a value with
/// four distinct halfwords.
fn emit_movewide_immediate(st: &mut JitState, sixty_four: bool, rd: u32, imm: u64) {
  // count0000 is seeded with 2 in the 32-bit case, standing in for the two
  // high halfwords it never examines.
  let mut count0000: u32 = if sixty_four { 0 } else { 2 };
  let mut countffff: u32 = 0;
  let bits = if sixty_four { 64 } else { 32 };
  let mut i = 0;
  while i < bits {
    let block = (imm >> i) & 0xffff;
    if block == 0xffff {
      countffff += 1;
    } else if block == 0 {
      count0000 += 1;
    }
    i += 16;
  }

  let mut invert = count0000 < countffff;
  let mut op = if invert { mw::MOVN } else { mw::MOVZ };
  let skip_pattern: u64 = if invert { 0xffff } else { 0 };
  let blocks = if sixty_four { 4 } else { 2 };
  for i in 0..blocks {
    let mut imm16 = (imm >> (i * 16)) & 0xffff;
    if imm16 != skip_pattern {
      if invert {
        imm16 = !imm16 & 0xffff;
      }
      emit_instruction(
        st,
        sz(sixty_four) | op | ((i as u32) << 21) | ((imm16 as u32) << 5) | rd,
      );
      op = mw::MOVK;
      invert = false;
    }
  }

  // Tidy up for imm == 0 and imm == -1, where the loop emitted nothing.
  if op != mw::MOVK {
    emit_instruction(st, sz(sixty_four) | op | rd);
  }
}

// ---------------------------------------------------------------------------
// Patch-table plumbing
// ---------------------------------------------------------------------------

fn note_load(st: &mut JitState, target: PatchTarget) {
  let at = st.offset;
  st.note_load(at, target);
}

fn note_lea(st: &mut JitState, target: PatchTarget) {
  let at = st.offset;
  st.note_lea(at, target);
}

/// C4.1.65 unconditional branch (immediate).
/// A `BL` to a non-special target is a local call and goes in its own table, so
/// that `resolve_local_calls` can subtract the per-function prologue from it.
/// Returns the offset the instruction was emitted at, which is the handle
/// [`emit_jump_target`] later retargets.
fn emit_unconditionalbranch_immediate(st: &mut JitState, op: u32, target: PatchTarget) -> u32 {
  let source_offset = st.offset;
  let is_local_call = op == ubr::BL && !matches!(target, PatchTarget::Special(_));
  if is_local_call {
    st.note_local_call(source_offset, target);
  } else {
    st.note_jump(source_offset, target);
  }
  emit_instruction(st, op);
  source_offset
}

/// C4.1.65 conditional branch (immediate).
fn emit_conditionalbranch_immediate(st: &mut JitState, c: u32, target: PatchTarget) -> u32 {
  let source_offset = st.offset;
  st.note_jump(source_offset, target);
  emit_instruction(st, BR_BCOND | c);
  source_offset
}

/// Retargets the branch emitted at `jump_src` to land here. Mirrors
/// Resolves one jump target.
fn emit_jump_target(st: &mut JitState, jump_src: u32) {
  let here = st.offset;
  st.retarget_jumps(
    jump_src,
    PatchTarget::JitOffset {
      offset: here,
      near: false,
    },
  );
}

// ---------------------------------------------------------------------------
// The pointer cage
// ---------------------------------------------------------------------------

/// Mask-and-offset the address in `src` into `dst`.
/// Unreachable from this entry point — every caller of
/// [`emit_masked_address_with_offset`] is already inside a `jit_pointer_mask`
/// guard, so the fall-through that reaches this is dead. Kept for shape.
fn emit_masked_address(cfg: &Config, st: &mut JitState, src: u32, dst: u32, scratch: u32) {
  debug_assert_ne!(dst, scratch);
  if src != dst {
    emit_logical_register(st, true, log::ORR, dst, RZ, src);
  }
  if cfg.pointer_mask != 0 {
    emit_movewide_immediate(st, true, scratch, cfg.pointer_mask as u32 as u64);
    emit_logical_register(st, true, log::AND, dst, dst, scratch);
    emit_movewide_immediate(st, true, scratch, cfg.pointer_offset as u64);
    emit_addsub_register(st, true, addsub::ADD, dst, dst, scratch);
  }
}

/// Bounds-check `[dst, dst+size)` against one guest region described by the
/// memory descriptor, then translate `dst` to the native address.
/// Branchless on purpose: the address is translated unconditionally and a final
/// `CSEL` replaces it with 0 — a guaranteed faulting access — when out of range,
/// so there is no predictable branch whose mis-speculation could perform a
/// transient out-of-bounds access.
fn emit_single_region_address(
  st: &mut JitState,
  dst: u32,
  scratch: u32,
  size: i32,
  bottom_off: i32,
  top_off: i32,
  base_off: i32,
) {
  let translated = TEMP_REGISTER;

  // translated = dst - bottom + base
  emit_loadstore_immediate(st, ls::LDRX, scratch, R29, abi::FRAME_OFFSET as i16);
  emit_loadstore_immediate(st, ls::LDRX, scratch, scratch, bottom_off as i16);
  emit_addsub_register(st, true, addsub::SUB, translated, dst, scratch);
  emit_loadstore_immediate(st, ls::LDRX, scratch, R29, abi::FRAME_OFFSET as i16);
  emit_loadstore_immediate(st, ls::LDRX, scratch, scratch, base_off as i16);
  emit_addsub_register(st, true, addsub::ADD, translated, translated, scratch);

  // valid <=> (dst >= bottom) && (dst <= top - size).
  emit_loadstore_immediate(st, ls::LDRX, scratch, R29, abi::FRAME_OFFSET as i16);
  emit_loadstore_immediate(st, ls::LDRX, scratch, scratch, bottom_off as i16);
  emit_addsub_register(st, true, addsub::SUBS, RZ, dst, scratch);
  emit_loadstore_immediate(st, ls::LDRX, scratch, R29, abi::FRAME_OFFSET as i16);
  emit_loadstore_immediate(st, ls::LDRX, scratch, scratch, top_off as i16);
  if size != 0 {
    emit_addsub_immediate(st, true, addsub::SUB, scratch, scratch, size as u32);
  }
  emit_conditionalcompare(st, scratch, dst, 0, cond::HS);

  emit_conditionalselect(st, dst, translated, RZ, cond::HS);
}

/// The same check, reading the region's bounds from the frame constants the
/// embedder derived once per invocation.
fn emit_single_region_address_from_frame(
  st: &mut JitState,
  dst: u32,
  scratch: u32,
  size: i32,
  bottom_slot: i32,
  delta_slot: i32,
  span_base: i32,
) {
  let off = TEMP_REGISTER;

  emit_loadstore_immediate(st, ls::LDRX, scratch, R29, bottom_slot as i16);
  emit_addsub_register(st, true, addsub::SUB, off, dst, scratch);

  // Translate unconditionally; the CSEL below undoes it when out of range.
  emit_loadstore_immediate(st, ls::LDRX, scratch, R29, delta_slot as i16);
  emit_addsub_register(st, true, addsub::ADD, dst, dst, scratch);

  if let Some(slot) = abi::span_slot_index(size as usize) {
    emit_loadstore_immediate(
      st,
      ls::LDRX,
      scratch,
      R29,
      (span_base + slot as i32 * 8) as i16,
    );
  } else {
    // An access group checks a whole window at once, which is any width up to
    // a page rather than one of the four the precomputed spans cover. Narrow
    // the width-1 span instead.
    emit_loadstore_immediate(st, ls::LDRX, scratch, R29, span_base as i16);
    emit_addsub_immediate(st, true, addsub::SUB, scratch, scratch, (size - 1) as u32);
  }

  emit_addsub_register(st, true, addsub::SUBS, RZ, scratch, off);
  emit_conditionalselect(st, dst, dst, RZ, cond::HS);
}

/// Where one guest region's bounds can be found.
struct GuestRegion {
  desc_bottom: i32,
  desc_top: i32,
  desc_native_base: i32,
  slot_bottom: i32,
  slot_delta: i32,
  slot_span: i32,
}

const GUEST_STACK_REGION: GuestRegion = GuestRegion {
  desc_bottom: abi::memory::STACK_GUEST_BOTTOM,
  desc_top: abi::memory::STACK_GUEST_TOP,
  desc_native_base: abi::memory::STACK_NATIVE_BASE,
  slot_bottom: abi::derived_slot(abi::DERIVED_STACK_BASE + abi::DERIVED_BOTTOM),
  slot_delta: abi::derived_slot(abi::DERIVED_STACK_BASE + abi::DERIVED_DELTA),
  slot_span: abi::derived_slot(abi::DERIVED_STACK_BASE + abi::DERIVED_SPAN),
};

const GUEST_DATA_REGION: GuestRegion = GuestRegion {
  desc_bottom: abi::memory::DATA_GUEST_BOTTOM,
  desc_top: abi::memory::DATA_GUEST_TOP,
  desc_native_base: abi::memory::DATA_NATIVE_BASE,
  slot_bottom: abi::derived_slot(abi::DERIVED_DATA_BASE + abi::DERIVED_BOTTOM),
  slot_delta: abi::derived_slot(abi::DERIVED_DATA_BASE + abi::DERIVED_DELTA),
  slot_span: abi::derived_slot(abi::DERIVED_DATA_BASE + abi::DERIVED_SPAN),
};

fn emit_region_address(
  cfg: &Config,
  st: &mut JitState,
  dst: u32,
  scratch: u32,
  size: i32,
  region: &GuestRegion,
) {
  if cfg.frame_constants {
    emit_single_region_address_from_frame(
      st,
      dst,
      scratch,
      size,
      region.slot_bottom,
      region.slot_delta,
      region.slot_span,
    );
  } else {
    emit_single_region_address(
      st,
      dst,
      scratch,
      size,
      region.desc_bottom,
      region.desc_top,
      region.desc_native_base,
    );
  }
}

/// Whether the native-frame-base fast path is live.
fn native_frame_base_active(cfg: &Config) -> bool {
  cfg.pointer_mask != 0 && cfg.native_frame_base
}

/// True when `[base + offset]`, `size` bytes wide, is a frame access that needs
/// no bounds check at all.
/// The hint is deliberately not taken on trust: the base really being R10, and
/// the access ending at or below it and starting no more than one local frame
/// below, are re-derived here from the instruction itself.
fn emit_frame_access_ok(cfg: &Config, region_hint: u8, base: u32, offset: i16, size: i32) -> bool {
  if !native_frame_base_active(cfg) || region_hint != abi::region::FRAME {
    return false;
  }
  if base != map_register(10) {
    return false;
  }
  if (offset as i32) > -size {
    return false;
  }
  if (offset as i32) < -(abi::LOCAL_FUNCTION_STACK_SIZE as i32) {
    return false;
  }
  // The unscaled load/store form this turns into reaches -256 only.
  offset >= -256
}

/// Materialise the *guest* value of eBPF R10 into `dst`.
fn emit_guest_frame_pointer(st: &mut JitState, dst: u32, scratch: u32) {
  emit_loadstore_immediate(st, ls::LDRX, scratch, R29, abi::FRAME_DELTA_OFFSET as i16);
  emit_addsub_register(st, true, addsub::SUB, dst, map_register(10), scratch);
}

/// True when `insn` reads its source register as a value rather than as a
/// memory base or an opcode mode selector.
fn reads_src_as_value(insn: &Insn) -> bool {
  use crate::jit::isa::{cls, opcode, src};
  match insn.opcode & cls::MASK {
    cls::ALU | cls::ALU64 => insn.opcode & src::REG == src::REG,
    cls::JMP | cls::JMP32 => {
      if insn.opcode == opcode::CALL
        || insn.opcode == opcode::EXIT
        || insn.opcode == opcode::JA
        || insn.opcode == opcode::JA32
      {
        return false;
      }
      insn.opcode & src::REG == src::REG
    }
    _ => false,
  }
}

/// eBPF registers `insn` may overwrite. Over-approximating only
/// ends access groups early.
fn written_registers_mask(insn: &Insn) -> u16 {
  use crate::jit::isa::{cls, mode, opcode};
  match insn.opcode & cls::MASK {
    cls::LD | cls::LDX | cls::ALU | cls::ALU64 => 1u16 << insn.dst,
    cls::STX => {
      if insn.opcode & mode::MASK == mode::ATOMIC {
        (1u16 << insn.src) | 1
      } else {
        0
      }
    }
    cls::JMP | cls::JMP32 => {
      if insn.opcode == opcode::CALL {
        0x3f
      } else {
        0
      }
    }
    _ => 0,
  }
}

/// Translate `[src + offset]` to a native address in `dst`, emitting whatever
/// bounds check the configuration and hint call for.
#[allow(clippy::too_many_arguments)]
fn emit_masked_address_with_offset(
  cfg: &Config,
  st: &mut JitState,
  src: u32,
  dst: u32,
  scratch: u32,
  offset: i16,
  size: i32,
  store: bool,
  region_hint: u8,
) {
  debug_assert_ne!(dst, scratch);

  if native_frame_base_active(cfg) && src == map_register(10) {
    // Everything below works in guest space, so recover the guest frame
    // pointer before starting.
    emit_guest_frame_pointer(st, dst, scratch);
  } else if src != dst {
    emit_logical_register(st, true, log::ORR, dst, RZ, src);
  }

  if offset != 0 {
    let mut abs_offset = offset as i32;
    let mut op = addsub::ADD;
    if offset < 0 {
      op = addsub::SUB;
      abs_offset = -(offset as i32);
    }
    if abs_offset < 0x1000 {
      emit_addsub_immediate(st, true, op, dst, dst, abs_offset as u32);
    } else {
      emit_movewide_immediate(st, true, scratch, abs_offset as u32 as u64);
      emit_addsub_register(st, true, op, dst, dst, scratch);
    }
  }

  if cfg.pointer_mask != 0 {
    // Stores are always confined to the active stack regardless of the hint,
    // preserving the read-only guarantee for the data region.
    if !cfg.writable_data
      && (store || region_hint == abi::region::STACK || region_hint == abi::region::FRAME)
    {
      emit_region_address(cfg, st, dst, scratch, size, &GUEST_STACK_REGION);
      return;
    }
    if !cfg.writable_data && region_hint == abi::region::DATA {
      emit_region_address(cfg, st, dst, scratch, size, &GUEST_DATA_REGION);
      return;
    }

    // Unknown region: probe both branchlessly. The two guest ranges are
    // disjoint, so at most one candidate is non-zero and OR-ing them recovers
    // the address (or 0, a guaranteed faulting access). R16/R17 are the
    // intra-procedure scratch registers and are mapped to no eBPF register.
    let saved_addr = R16;
    let stack_candidate = R17;

    emit_logical_register(st, true, log::ORR, saved_addr, RZ, dst);
    emit_region_address(cfg, st, dst, scratch, size, &GUEST_STACK_REGION);
    emit_logical_register(st, true, log::ORR, stack_candidate, RZ, dst);
    emit_logical_register(st, true, log::ORR, dst, RZ, saved_addr);
    emit_region_address(cfg, st, dst, scratch, size, &GUEST_DATA_REGION);
    emit_logical_register(st, true, log::ORR, dst, dst, stack_candidate);
    return;
  }

  emit_masked_address(cfg, st, dst, dst, scratch);
}

/// Folds a group displacement into the address, since the load/store immediate
/// form reaches only ±256 while a group window is a page wide.
fn apply_group_delta(st: &mut JitState, addr_reg: u32, delta: u16) -> i16 {
  if delta < 256 {
    return delta as i16;
  }
  emit_addsub_immediate(st, true, addsub::ADD, addr_reg, addr_reg, delta as u32);
  0
}

/// Resolve `[base + offset]`, `width` bytes wide, to a native address, and
/// return the register holding it together with the displacement to use
///.
/// The plan is not taken on trust: every condition the backend can re-derive
/// from the instruction stream it is already walking, it does, and any that
/// fails drops through to an ordinary checked access.
#[allow(clippy::too_many_arguments)]
fn emit_checked_address(
  cfg: &Config,
  st: &mut JitState,
  plan: Option<&PlanEntry>,
  pc: u32,
  base: u32,
  offset: i16,
  width: i32,
  store: bool,
  region_hint: u8,
  addr_reg: u32,
  scratch_reg: u32,
) -> (u32, i16) {
  if emit_frame_access_ok(cfg, region_hint, base, offset, width) {
    return (base, offset);
  }

  let base_ebpf = unmap_register(base);

  if let Some(plan) = plan {
    if plan.role == abi::plan_role::MEMBER {
      let usable = match (st.group, base_ebpf) {
        (Some(group), Some(base_ebpf)) => {
          group.leader_pc == plan.leader_pc
            && base_ebpf == group.base_reg
            && group.written & (1u16 << base_ebpf) == 0
            && plan.delta as u64 + width as u64 <= group.span as u64
            && group.lo as i64 + plan.delta as i64 == offset as i64
            && (!store || cfg.writable_data || group.region == abi::region::STACK)
        }
        _ => false,
      };
      if usable {
        emit_loadstore_immediate(st, ls::LDRX, addr_reg, R29, abi::GROUP_BASE_OFFSET as i16);
        let disp = apply_group_delta(st, addr_reg, plan.delta);
        return (addr_reg, disp);
      }
    }

    if plan.role == abi::plan_role::LEADER {
      let usable = base_ebpf.is_some()
        && plan.span > 0
        && plan.span <= abi::MAX_GROUP_SPAN
        && plan.delta as u64 + width as u64 <= plan.span as u64
        && plan.lo as i64 + plan.delta as i64 == offset as i64
        && plan.region != abi::region::FRAME
        && (!store || cfg.writable_data || plan.region == abi::region::STACK)
        && plan.lo >= i16::MIN as i32
        && plan.lo <= i16::MAX as i32;
      if usable {
        emit_masked_address_with_offset(
          cfg,
          st,
          base,
          addr_reg,
          scratch_reg,
          plan.lo as i16,
          plan.span as i32,
          store,
          plan.region,
        );
        emit_loadstore_immediate(st, ls::STRX, addr_reg, R29, abi::GROUP_BASE_OFFSET as i16);
        st.group = Some(OpenGroup {
          leader_pc: pc,
          span: plan.span,
          lo: plan.lo,
          base_reg: base_ebpf.expect("checked above"),
          region: plan.region,
          written: 0,
        });
        let disp = apply_group_delta(st, addr_reg, plan.delta);
        return (addr_reg, disp);
      }
    }
  }

  emit_masked_address_with_offset(
    cfg,
    st,
    base,
    addr_reg,
    scratch_reg,
    offset,
    width,
    store,
    region_hint,
  );
  (addr_reg, 0)
}

/// Access width of a load/store opcode.
fn loadstore_access_size(op: u32) -> i32 {
  match op {
    ls::STRB | ls::LDRB | ls::LDRSBX => 1,
    ls::STRH | ls::LDRH | ls::LDRSHX => 2,
    ls::STRW | ls::LDRW | ls::LDRSW => 4,
    _ => 8,
  }
}

fn loadstore_is_store(op: u32) -> bool {
  op == ls::STRB || op == ls::STRH || op == ls::STRW || op == ls::STRX
}

/// Emit one guest load or store, with the cage applied where it is on
///.
#[allow(clippy::too_many_arguments)]
fn emit_masked_loadstore(
  cfg: &Config,
  st: &mut JitState,
  plan: Option<&PlanEntry>,
  op: u32,
  rt: u32,
  rn: u32,
  offset: i16,
  region_hint: u8,
  pc: u32,
) {
  if cfg.pointer_mask != 0 {
    let (addr, disp) = emit_checked_address(
      cfg,
      st,
      plan,
      pc,
      rn,
      offset,
      loadstore_access_size(op),
      loadstore_is_store(op),
      region_hint,
      TEMP_DIV_REGISTER,
      OFFSET_REGISTER,
    );
    emit_loadstore_immediate(st, op, rt, addr, disp);
    return;
  }

  if (-256..256).contains(&offset) {
    emit_loadstore_immediate(st, op, rt, rn, offset);
  } else {
    let addr_temp = TEMP_DIV_REGISTER;
    let mut abs_offset = offset as i32;
    let mut addsub_op = addsub::ADD;
    if offset < 0 {
      addsub_op = addsub::SUB;
      abs_offset = -(offset as i32);
    }
    if abs_offset < 0x1000 {
      emit_addsub_immediate(st, true, addsub_op, addr_temp, rn, abs_offset as u32);
    } else {
      emit_movewide_immediate(st, true, OFFSET_REGISTER, abs_offset as u32 as u64);
      emit_addsub_register(st, true, addsub_op, addr_temp, rn, OFFSET_REGISTER);
    }
    emit_loadstore_immediate(st, op, rt, addr_temp, 0);
  }
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

/// Call an external helper, through the registered dispatcher if there is one
/// and through the per-index helper table otherwise.
fn emit_dispatched_external_helper_call(st: &mut JitState, idx: u32) {
  let stack_movement = align_to(8, 16);
  emit_addsub_immediate(st, true, addsub::SUB, SP, SP, stack_movement);
  emit_loadstore_immediate(st, ls::STRX, R30, SP, 0);

  emit_loadstore_literal(
    st,
    ls::LDRL,
    TEMP_REGISTER,
    PatchTarget::Special(SpecialTarget::ExternalDispatcher),
  );

  // Is the dispatcher slot empty?
  emit_addsub_immediate(st, true, addsub::SUBS, TEMP_REGISTER, TEMP_REGISTER, 0);

  let default_tgt = PatchTarget::EbpfPc { pc: 0, near: false };
  let external_dispatcher_jump_source = emit_conditionalbranch_immediate(st, cond::NE, default_tgt);

  // No dispatcher: load the helper address by index out of the table.
  emit_movewide_immediate(st, true, R5, idx as u64);
  emit_movewide_immediate(st, true, R6, 3);
  emit_dataprocessing_twosource(st, true, dp2::LSLV, R5, R5, R6);

  emit_movewide_immediate(st, true, TEMP_REGISTER, 0);
  emit_adr(
    st,
    PatchTarget::Special(SpecialTarget::LoadHelperTable),
    TEMP_REGISTER,
  );
  emit_addsub_register(st, true, addsub::ADD, TEMP_REGISTER, TEMP_REGISTER, R5);
  emit_loadstore_immediate(st, ls::LDRX, TEMP_REGISTER, TEMP_REGISTER, 0);

  // Add the implicit 6th parameter (the context).
  emit_logical_register(st, true, log::ORR, R5, RZ, VOLATILE_CTXT);

  let no_dispatcher_jump_source = emit_unconditionalbranch_immediate(st, ubr::B, default_tgt);

  emit_jump_target(st, external_dispatcher_jump_source);

  // Dispatcher path: the helper index is its sixth and final argument.
  emit_movewide_immediate(st, true, R5, idx as u64);

  emit_jump_target(st, no_dispatcher_jump_source);

  emit_unconditionalbranch_register(st, br::BLR, TEMP_REGISTER);

  let dest = map_register(0);
  if dest != R0 {
    emit_logical_register(st, true, log::ORR, dest, RZ, R0);
  }

  emit_loadstore_immediate(st, ls::LDRX, R30, SP, 0);
  emit_addsub_immediate(st, true, addsub::ADD, SP, SP, stack_movement);
}

fn emit_unconditionalbranch_register(st: &mut JitState, op: u32, rn: u32) {
  emit_instruction(st, op | (rn << 5));
}

/// A local call whose target has not been compiled yet: ask the embedder's
/// resolver for the entry address at run time, then call it.
fn emit_lazy_local_call(
  cfg: &Config,
  inputs: &TranslationInputs<'_>,
  st: &mut JitState,
  call_pc: usize,
) {
  let (resolver, id) = match (cfg.local_call_resolver, inputs.resolver_ids.get(call_pc)) {
    (Some(resolver), Some(&id)) => (resolver, id),
    _ => {
      st.fail(Progress::UnexpectedInstruction);
      return;
    }
  };

  // Stack usage is fixed for every local function. Materialise the constant
  // directly instead of reloading the prologue's bookkeeping slot: a coroutine
  // suspension may use host stack storage below the current frame, while R10
  // is guest state and must not depend on that storage surviving a yield.
  emit_movewide_immediate(
    st,
    true,
    TEMP_REGISTER,
    abi::LOCAL_FUNCTION_STACK_SIZE as u64,
  );
  emit_addsub_register(
    st,
    true,
    addsub::SUB,
    map_register(10),
    map_register(10),
    TEMP_REGISTER,
  );

  let stack_movement = align_to(48, 16);
  emit_addsub_immediate(st, true, addsub::SUB, SP, SP, stack_movement);

  emit_loadstore_immediate(st, ls::STRX, R30, SP, 0);
  emit_loadstorepair_immediate(st, lsp::STPX, map_register(6), map_register(7), SP, 16);
  emit_loadstorepair_immediate(st, lsp::STPX, map_register(8), map_register(9), SP, 32);

  // eBPF r0 is mapped to a caller-saved host register, so the resolver would
  // otherwise leave host residue in it for the callee to read.
  let arg_stack_movement = align_to(48, 16);
  emit_addsub_immediate(st, true, addsub::SUB, SP, SP, arg_stack_movement);
  emit_loadstorepair_immediate(st, lsp::STPX, map_register(1), map_register(2), SP, 0);
  emit_loadstorepair_immediate(st, lsp::STPX, map_register(3), map_register(4), SP, 16);
  emit_loadstorepair_immediate(st, lsp::STPX, map_register(5), map_register(0), SP, 32);

  emit_movewide_immediate(st, true, R0, id as u64);
  emit_movewide_immediate(st, true, TEMP_REGISTER, resolver as usize as u64);
  emit_unconditionalbranch_register(st, br::BLR, TEMP_REGISTER);
  emit_logical_register(st, true, log::ORR, R17, RZ, R0);

  emit_loadstorepair_immediate(st, lsp::LDPX, map_register(1), map_register(2), SP, 0);
  emit_loadstorepair_immediate(st, lsp::LDPX, map_register(3), map_register(4), SP, 16);
  emit_loadstorepair_immediate(st, lsp::LDPX, map_register(5), map_register(0), SP, 32);
  emit_addsub_immediate(st, true, addsub::ADD, SP, SP, arg_stack_movement);

  emit_unconditionalbranch_register(st, br::BLR, R17);
  emit_loadstore_immediate(st, ls::LDRX, R30, SP, 0);
  emit_loadstorepair_immediate(st, lsp::LDPX, map_register(6), map_register(7), SP, 16);
  emit_loadstorepair_immediate(st, lsp::LDPX, map_register(8), map_register(9), SP, 32);

  emit_addsub_immediate(st, true, addsub::ADD, SP, SP, stack_movement);

  emit_movewide_immediate(
    st,
    true,
    TEMP_REGISTER,
    abi::LOCAL_FUNCTION_STACK_SIZE as u64,
  );
  emit_addsub_register(
    st,
    true,
    addsub::ADD,
    map_register(10),
    map_register(10),
    TEMP_REGISTER,
  );
}

// ---------------------------------------------------------------------------
// Atomics
// ---------------------------------------------------------------------------

/// An `LDXR`/`STXR` retry loop implementing one eBPF atomic.
#[allow(clippy::too_many_arguments)]
fn emit_atomic_operation(
  cfg: &Config,
  st: &mut JitState,
  is_64bit: bool,
  value_reg: u32,
  addr_reg: u32,
  result_reg: u32,
  temp_reg: u32,
  status_reg: u32,
  offset: i16,
  alu_op: u8,
  is_cmpxchg: bool,
  is_xchg: bool,
  fetch: bool,
) {
  use crate::jit::isa::alu;

  // The base register used by LDXR/STXR must never alias the status register.
  let addr_temp = if status_reg == TEMP_DIV_REGISTER {
    OFFSET_REGISTER
  } else {
    TEMP_DIV_REGISTER
  };
  let scratch = if addr_temp == OFFSET_REGISTER {
    TEMP_DIV_REGISTER
  } else {
    OFFSET_REGISTER
  };

  if cfg.pointer_mask != 0 {
    emit_masked_address_with_offset(
      cfg,
      st,
      addr_reg,
      addr_temp,
      scratch,
      offset,
      if is_64bit { 8 } else { 4 },
      true,
      abi::region::UNKNOWN,
    );
  } else if offset != 0 {
    let mut abs_offset = offset as i32;
    let mut op = addsub::ADD;
    if offset < 0 {
      op = addsub::SUB;
      abs_offset = -(offset as i32);
    }
    if abs_offset < 0x1000 {
      emit_addsub_immediate(st, true, op, addr_temp, addr_reg, abs_offset as u32);
    } else {
      emit_movewide_immediate(st, true, scratch, abs_offset as u32 as u64);
      emit_addsub_register(st, true, op, addr_temp, addr_reg, scratch);
    }
  } else {
    emit_logical_register(st, true, log::ORR, addr_temp, RZ, addr_reg);
  }

  let retry_loc = st.offset;
  let retry_tgt = PatchTarget::JitOffset {
    offset: retry_loc,
    near: false,
  };

  let load_reg = temp_reg;
  if is_64bit {
    emit_loadstore_exclusive(st, lse::LDXRX, load_reg, addr_temp, RZ);
  } else {
    emit_loadstore_exclusive(st, lse::LDXRW, load_reg, addr_temp, RZ);
  }

  if is_cmpxchg {
    // BPF expects the expected value in r0.
    let expected_reg = map_register(0);
    emit_addsub_register(st, is_64bit, addsub::SUBS, RZ, load_reg, expected_reg);

    let skip_store_src =
      emit_conditionalbranch_immediate(st, cond::NE, PatchTarget::EbpfPc { pc: 0, near: false });

    if is_64bit {
      emit_loadstore_exclusive(st, lse::STXRX, value_reg, addr_temp, status_reg);
    } else {
      emit_loadstore_exclusive(st, lse::STXRW, value_reg, addr_temp, status_reg);
    }

    emit_addsub_immediate(st, false, addsub::SUBS, RZ, status_reg, 0);
    emit_conditionalbranch_immediate(st, cond::NE, retry_tgt);

    emit_jump_target(st, skip_store_src);

    if result_reg != load_reg {
      emit_logical_register(st, is_64bit, log::ORR, result_reg, RZ, load_reg);
    }
  } else if is_xchg {
    if is_64bit {
      emit_loadstore_exclusive(st, lse::STXRX, value_reg, addr_temp, status_reg);
    } else {
      emit_loadstore_exclusive(st, lse::STXRW, value_reg, addr_temp, status_reg);
    }

    emit_addsub_immediate(st, false, addsub::SUBS, RZ, status_reg, 0);
    emit_conditionalbranch_immediate(st, cond::NE, retry_tgt);

    // XCHG always has implicit fetch semantics.
    if result_reg != load_reg {
      emit_logical_register(st, is_64bit, log::ORR, result_reg, RZ, load_reg);
    }
  } else {
    // R8 is caller-saved and used nowhere else; the status, address and loaded
    // value registers are all live here.
    let op_result_reg = R8;

    match alu_op {
      alu::ADD => emit_addsub_register(
        st,
        is_64bit,
        addsub::ADD,
        op_result_reg,
        load_reg,
        value_reg,
      ),
      alu::OR => emit_logical_register(st, is_64bit, log::ORR, op_result_reg, load_reg, value_reg),
      alu::AND => emit_logical_register(st, is_64bit, log::AND, op_result_reg, load_reg, value_reg),
      alu::XOR => emit_logical_register(st, is_64bit, log::EOR, op_result_reg, load_reg, value_reg),
      // Should not happen.
      _ => {}
    }

    if is_64bit {
      emit_loadstore_exclusive(st, lse::STXRX, op_result_reg, addr_temp, status_reg);
    } else {
      emit_loadstore_exclusive(st, lse::STXRW, op_result_reg, addr_temp, status_reg);
    }

    emit_addsub_immediate(st, false, addsub::SUBS, RZ, status_reg, 0);
    emit_conditionalbranch_immediate(st, cond::NE, retry_tgt);

    if fetch && result_reg != load_reg {
      emit_logical_register(st, is_64bit, log::ORR, result_reg, RZ, load_reg);
    }
  }
}

// ---------------------------------------------------------------------------
// Trailers
// ---------------------------------------------------------------------------

/// Park the dispatcher's address, 4-byte aligned so the PC-relative load that
/// reads it has a multiple-of-four displacement.
fn emit_dispatched_external_helper_address(st: &mut JitState, dispatcher_addr: u64) -> u32 {
  let adjustment = (4 - (st.offset % 4)) % 4;
  for _ in 0..adjustment {
    st.emit_bytes(0, 1);
  }
  let helper_address = st.offset;
  st.emit_bytes(dispatcher_addr, 8);
  helper_address
}

/// The consecutive helper-address table. `async-ebpf` never
/// registers individual helpers, so every entry is null.
fn emit_helper_table(st: &mut JitState) -> u32 {
  let helper_table_address_target = st.offset;
  for _ in 0..abi::MAX_EXT_FUNCS {
    st.emit_bytes(0, 8);
  }
  helper_table_address_target
}

// ---------------------------------------------------------------------------
// Opcode classification
// ---------------------------------------------------------------------------

/// Whether this instruction carries an immediate operand the backend may have
/// to lower into a register first.
fn is_imm_op(insn: &Insn) -> bool {
  use crate::jit::isa::{alu, cls, opcode, src};
  let class = insn.opcode & cls::MASK;
  let is_imm = insn.opcode & src::REG == src::IMM;
  let is_endian = insn.opcode & alu::MASK == alu::END;
  let is_neg = insn.opcode & alu::MASK == alu::NEG;
  let is_call = insn.opcode == opcode::CALL;
  let is_exit = insn.opcode == opcode::EXIT;
  let is_ja = insn.opcode == opcode::JA || insn.opcode == opcode::JA32;
  let is_alu = (class == cls::ALU || class == cls::ALU64) && !is_endian && !is_neg;
  let is_jmp = class == cls::JMP && !is_ja && !is_call && !is_exit;
  let is_jmp32 = class == cls::JMP32 && insn.opcode != opcode::JA32;
  let is_store = class == cls::ST;
  (is_imm && (is_alu || is_jmp || is_jmp32)) || is_store
}

/// Whether the operation is 64-bit wide.
fn is_alu64_op(insn: &Insn) -> bool {
  use crate::jit::isa::cls;
  let class = insn.opcode & cls::MASK;
  class == cls::ALU64 || class == cls::JMP
}

/// Whether the immediate can go straight into the instruction encoding, or has
/// to be materialised in a register first.
/// The `add`/`sub` and conditional-jump forms take a 12-bit unsigned immediate.
/// Everything else — including the logical operations, whose aarch64 immediate
/// form uses the N/immr/imms bitmask encoding — is lowered to its register
/// form. The bitmask encoding is never attempted, so no constant is
/// ever "not encodable": the fallback is the only path.
fn is_simple_imm(insn: &Insn) -> bool {
  use crate::jit::isa::{alu, cls};
  let class = insn.opcode & cls::MASK;
  if class == cls::ST {
    return false;
  }
  match class {
    cls::ALU | cls::ALU64 => match insn.opcode & alu::MASK {
      alu::ADD | alu::SUB => insn.imm >= 0 && insn.imm < 0x1000,
      alu::MOV => true,
      _ => false,
    },
    cls::JMP | cls::JMP32 => {
      use crate::jit::isa::jmp;
      match insn.opcode & jmp::MASK {
        jmp::JSET => false,
        _ => insn.imm >= 0 && insn.imm < 0x1000,
      }
    }
    // Unreachable for any
    // opcode the validator admits.
    _ => false,
  }
}

/// Rewrite an immediate-form opcode into its register form.
fn to_reg_op(opcode: u8) -> u8 {
  use crate::jit::isa::{cls, src};
  let class = opcode & cls::MASK;
  if class == cls::ALU64 || class == cls::ALU || class == cls::JMP || class == cls::JMP32 {
    opcode | src::REG
  } else if class == cls::ST {
    (opcode & !cls::MASK) | cls::STX
  } else {
    // Unreachable: every caller passes a width this covers.
    0
  }
}

/// The condition code a conditional jump maps to.
fn to_condition(op: JmpOp) -> u32 {
  match op {
    JmpOp::Eq => cond::EQ,
    JmpOp::Gt => cond::HI,
    JmpOp::Ge => cond::HS,
    JmpOp::Lt => cond::LO,
    JmpOp::Le => cond::LS,
    JmpOp::Set => cond::NE,
    JmpOp::Ne => cond::NE,
    JmpOp::Sgt => cond::GT,
    JmpOp::Sge => cond::GE,
    JmpOp::Slt => cond::LT,
    JmpOp::Sle => cond::LE,
  }
}

/// The load/store opcode for a memory access.
fn to_loadstore_opcode(width: Width, signed: bool, load: bool) -> u32 {
  if load {
    match (width, signed) {
      (Width::W, false) => ls::LDRW,
      (Width::H, false) => ls::LDRH,
      (Width::B, false) => ls::LDRB,
      (Width::DW, false) => ls::LDRX,
      (Width::W, true) => ls::LDRSW,
      (Width::H, true) => ls::LDRSHX,
      (Width::B, true) => ls::LDRSBX,
      // No sign-extending doubleword load exists; `Op::Load` never decodes one.
      (Width::DW, true) => ls::LDRX,
    }
  } else {
    match width {
      Width::W => ls::STRW,
      Width::H => ls::STRH,
      Width::B => ls::STRB,
      Width::DW => ls::STRX,
    }
  }
}

/// The one-source byte-reversal opcode for an `end` immediate.
fn to_dp1_opcode(imm: i32) -> u32 {
  match imm {
    16 => dp1::REV16,
    32 => dp1::REV32,
    64 => dp1::REV64,
    // Unreachable: every caller passes a width this covers.
    _ => 0,
  }
}

/// `divmod`. `offset == 1` selects the signed form.
fn divmod(st: &mut JitState, opcode: u8, rd: u32, rn: u32, rm: u32, offset: i16) {
  use crate::jit::isa::{alu, cls};
  let is_mod = opcode & alu::MASK == alu::MOD;
  let sixty_four = opcode & cls::MASK == cls::ALU64;
  let is_signed = offset == 1;
  let div_dest = if is_mod { TEMP_DIV_REGISTER } else { rd };

  // Division by zero needs no special case: UDIV/SDIV already return 0.
  let div_op = if is_signed { dp2::SDIV } else { dp2::UDIV };
  emit_dataprocessing_twosource(st, sixty_four, div_op, div_dest, rn, rm);
  if is_mod {
    emit_dataprocessing_threesource(st, sixty_four, dp3::MSUB, rd, rm, div_dest, rn);
  }
}

// ---------------------------------------------------------------------------
// Relocation
// ---------------------------------------------------------------------------

/// Patch a branch immediate.
/// Conditional and compare-and-branch forms carry a signed 19-bit word
/// displacement (±1 MiB); the unconditional form carries a signed 26-bit one
/// (±128 MiB). Anything wider is [`Progress::RelocationOutOfRange`] rather than
/// a silently truncated branch.
fn resolve_branch_immediate(st: &mut JitState, offset: u32, imm: i32) -> bool {
  if imm & 3 != 0 {
    return false;
  }
  let imm = imm >> 2;
  let mut instr = st.read_bytes(offset, 4) as u32;
  if instr & 0xfe00_0000 == 0x5400_0000 || instr & 0x7e00_0000 == 0x3400_0000 {
    if (imm >> 18) != -1 && (imm >> 18) != 0 {
      st.fail(Progress::RelocationOutOfRange);
      return false;
    }
    instr |= ((imm & 0x7ffff) as u32) << 5;
  } else if instr & 0x7c00_0000 == 0x1400_0000 {
    if (imm >> 25) != -1 && (imm >> 25) != 0 {
      st.fail(Progress::RelocationOutOfRange);
      return false;
    }
    instr |= (imm & 0x03ff_ffff) as u32;
  } else {
    return false;
  }
  st.patch_bytes(offset, instr as u64, 4);
  true
}

/// Patch an `LDR` (literal), whose immediate is signed 19-bit.
fn resolve_load_literal(st: &mut JitState, instr_offset: u32, target_offset: i32) -> bool {
  if (target_offset >> 18) != -1 && (target_offset >> 18) != 0 {
    st.fail(Progress::RelocationOutOfRange);
    return false;
  }
  let field = ((0x7ffff & target_offset) as u32) << 5;
  let instr = st.read_bytes(instr_offset, 4) as u32 | field;
  st.patch_bytes(instr_offset, instr as u64, 4);
  true
}

/// Patch an `ADR`.
/// Only the `immhi` field is written; the two `immlo` bits at 30:29 are left
/// clear, because the caller already divided the displacement by four. That is
/// what callers depend on.
fn resolve_adr(st: &mut JitState, instr_offset: u32, immediate: i32) -> bool {
  if (immediate >> 18) != -1 && (immediate >> 18) != 0 {
    st.fail(Progress::RelocationOutOfRange);
    return false;
  }
  let immhi = ((immediate & 0x7ffff) as u32) << 5;
  let instr = st.read_bytes(instr_offset, 4) as u32 | immhi;
  st.patch_bytes(instr_offset, instr as u64, 4);
  true
}

/// Resolve one patch target to a native offset, dispatching
///.
/// Decides between the two regular flavours with
/// `jit_target_pc != 0` — a sentinel that would collide with a real offset of
/// zero. It cannot here: offset 0 always holds the `bti c`, so nothing is ever
/// patched to point at it. [`PatchTarget`] keeps the two apart by construction.
fn jump_target_loc(st: &JitState, target: PatchTarget) -> Option<i32> {
  match target {
    PatchTarget::Special(SpecialTarget::Exit) => Some(st.exit_loc as i32),
    PatchTarget::Special(SpecialTarget::Enter) => Some(st.entry_loc as i32),
    PatchTarget::Special(_) => None,
    PatchTarget::JitOffset { offset, .. } => Some(offset as i32),
    PatchTarget::EbpfPc { pc, .. } => {
      Some(st.pc_locs.get(pc as usize).copied().unwrap_or(0) as i32)
    }
  }
}

fn resolve_jumps(st: &mut JitState) -> bool {
  for jump in std::mem::take(&mut st.jumps) {
    let target_loc = match jump_target_loc(st, jump.target) {
      Some(loc) => loc,
      None => return false,
    };
    let rel = target_loc.wrapping_sub(jump.offset_loc as i32);
    if !resolve_branch_immediate(st, jump.offset_loc, rel) {
      return false;
    }
  }
  true
}

fn resolve_loads(st: &mut JitState) -> bool {
  for load in std::mem::take(&mut st.loads) {
    // Right now it is only possible to load from the external dispatcher.
    let target_loc = match load.target {
      PatchTarget::Special(SpecialTarget::ExternalDispatcher) => st.dispatcher_loc as i32,
      _ => return false,
    };
    let rel = target_loc.wrapping_sub(load.offset_loc as i32);
    if rel % 4 != 0 {
      return false;
    }
    if !resolve_load_literal(st, load.offset_loc, rel >> 2) {
      return false;
    }
  }
  true
}

fn resolve_leas(st: &mut JitState) -> bool {
  for lea in std::mem::take(&mut st.leas) {
    // Right now it is only possible to have leas to the helper table.
    let target_loc = match lea.target {
      PatchTarget::Special(SpecialTarget::LoadHelperTable) => st.helper_table_loc as i32,
      _ => return false,
    };
    let rel = target_loc.wrapping_sub(lea.offset_loc as i32);
    if rel % 4 != 0 {
      return false;
    }
    if !resolve_adr(st, lea.offset_loc, rel >> 2) {
      return false;
    }
  }
  true
}

/// Local-call fixups. Always empty here: this entry point uses
/// the lazy resolver, which calls through a register rather than a `BL`.
fn resolve_local_calls(st: &mut JitState) -> bool {
  for call in std::mem::take(&mut st.local_calls) {
    let target_loc = match call.target {
      PatchTarget::EbpfPc { pc, .. } => st.pc_locs.get(pc as usize).copied().unwrap_or(0) as i32,
      // A local call must be eBPF PC-relative and cannot be special.
      _ => return false,
    };
    let rel = target_loc
      .wrapping_sub(call.offset_loc as i32)
      .wrapping_sub(st.prolog_size as i32);
    if !resolve_branch_immediate(st, call.offset_loc, rel) {
      return false;
    }
  }
  true
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

fn failed(msg: impl Into<String>) -> TranslateError {
  TranslateError::Failed(msg.into())
}

/// Translates `inputs.start_pc .. inputs.end_pc` into `buffer`, returning the
/// number of bytes written.
/// Port of `translate_range` with `whole_program = false, lazy_local_calls =
/// true`, followed by the relocation passes
/// translation runs.
pub fn translate_range(
  t: &Translator,
  inputs: &TranslationInputs<'_>,
  buffer: &mut [u8],
) -> Result<usize, TranslateError> {
  let cfg = t.config();
  let insns = t.insns();
  let num_insts = insns.len();
  let start_pc = inputs.start_pc;
  let end_pc = inputs.end_pc;

  if end_pc > num_insts || start_pc >= end_pc {
    return Err(failed(format!(
      "Invalid function range [{start_pc}, {end_pc})"
    )));
  }

  // In function-granular mode the emitted prologue/epilogue assume the range is
  // exactly one local function: the per-function prologue is only emitted at a
  // function entry, but EXIT always pops a frame.
  if !(start_pc == 0 || t.is_local_func_entry(start_pc)) {
    return Err(failed(format!(
      "Function range start {start_pc} is not a local function entry"
    )));
  }
  if end_pc != num_insts && !t.is_local_func_entry(end_pc) {
    return Err(failed(format!(
      "Function range end {end_pc} is not a local function boundary"
    )));
  }

  let mut st = JitState::new(buffer, num_insts);
  let mut errmsg: Option<String> = None;

  // Lazy functions are entered through an indirect call.
  emit_instruction(&mut st, BTI_C);

  barrier_prepass(t, &mut st, start_pc, end_pc);

  st.group = None;

  let mut i = start_pc;
  while i < end_pc {
    if !st.ok() {
      break;
    }

    let insn = insns[i];

    // If the previous instruction could fall through to this one and this one
    // starts a local function, jump around the stack manipulation.
    let mut fallthrough_jump_source = 0u32;
    let mut fallthrough_jump_present = false;
    if i != start_pc && t.is_local_func_entry(i) && insns[i - 1].has_fallthrough() {
      fallthrough_jump_source = emit_unconditionalbranch_immediate(
        &mut st,
        ubr::B,
        PatchTarget::EbpfPc { pc: 0, near: false },
      );
      fallthrough_jump_present = true;
    }

    if i == 0 || t.is_local_func_entry(i) {
      let prolog_start = st.offset;
      emit_movewide_immediate(&mut st, true, TEMP_REGISTER, t.stack_usage_for(i) as u64);
      emit_addsub_immediate(&mut st, true, addsub::SUB, SP, SP, 16);
      emit_loadstorepair_immediate(&mut st, lsp::STPX, TEMP_REGISTER, TEMP_REGISTER, SP, 0);
      // Recorded so a local call can skip it. Every function's prologue is the
      // same length, which the assertion below pins.
      if st.prolog_size == 0 {
        st.prolog_size = (st.offset - prolog_start) as usize;
      } else {
        debug_assert_eq!(st.prolog_size, (st.offset - prolog_start) as usize);
      }
    }

    if fallthrough_jump_present {
      let here = st.offset;
      st.retarget_jumps(
        fallthrough_jump_source,
        PatchTarget::JitOffset {
          offset: here,
          near: false,
        },
      );
    }

    st.pc_locs[i] = st.offset;

    // A branch can land here, so no access group can span it: a member
    // addresses the base its leader parked, and any path arriving here without
    // having run the leader would read a stale one.
    if st.is_barrier(i) {
      st.group = None;
    }

    let mut dst = map_register(insn.dst);
    let mut src = map_register(insn.src);
    let mut opcode = insn.opcode;

    // Under a native frame base the register mapped to eBPF R10 holds a host
    // address, so an instruction that reads R10 as a value must see the guest
    // address instead. TEMP_STORE_VALUE_REGISTER is used rather than
    // TEMP_REGISTER, which the div/mod helper may take as its own scratch.
    if native_frame_base_active(cfg) && insn.src == 10 && reads_src_as_value(&insn) {
      emit_guest_frame_pointer(&mut st, TEMP_STORE_VALUE_REGISTER, OFFSET_REGISTER);
      src = TEMP_STORE_VALUE_REGISTER;
    }

    let target_pc_64 = if opcode == crate::jit::isa::opcode::JA32 {
      i as i64 + insn.imm as i64 + 1
    } else {
      i as i64 + insn.offset as i64 + 1
    };
    let target_pc = target_pc_64 as u32;

    // A relative branch resolves against pc_locs[target_pc]; in sub-range mode
    // only entries inside [start_pc, end_pc) are ever written, so a target
    // outside the range would silently retarget the branch to the top of the
    // buffer.
    {
      use crate::jit::isa::{cls, opcode as opc};
      let branch_cls = insn.opcode & cls::MASK;
      if (branch_cls == cls::JMP || branch_cls == cls::JMP32)
        && insn.opcode != opc::CALL
        && insn.opcode != opc::EXIT
        && ((target_pc as usize) < start_pc || (target_pc as usize) >= end_pc)
      {
        st.fail(Progress::UnexpectedInstruction);
        errmsg = Some(format!(
          "jump target {target_pc} at PC {i} is outside the translation range [{start_pc}, {end_pc})"
        ));
        break;
      }
    }

    let tgt = PatchTarget::EbpfPc {
      pc: target_pc,
      near: false,
    };

    let sixty_four = is_alu64_op(&insn);

    // An immediate operand that is not "simple" is moved into a temporary and
    // the operation rewritten to its register form. MOV_IMM/MOV64_IMM are
    // excluded and handled directly below, which saves an ORR.
    if is_imm_op(&insn) && !is_mov_imm(opcode) && !is_simple_imm(&insn) {
      // A store's value has to survive the address computation, which uses
      // TEMP_REGISTER for the translated address.
      let is_store = opcode & crate::jit::isa::cls::MASK == crate::jit::isa::cls::ST;
      let imm_register = if is_store {
        TEMP_STORE_VALUE_REGISTER
      } else {
        TEMP_REGISTER
      };
      // A store's immediate is sign-extended to 64 bits and only then truncated
      // to the access width, so a doubleword store has to materialise it wide.
      // `ST` is not an ALU64 class, so `sixty_four` is false here, and building
      // the value in a W register would zero-extend instead - storing
      // 0x00000000ffffffff for `stdw [r1+0], -1` where x86_64 and the reference
      // interpreter both store all ones. The narrower widths keep only the low
      // bits, which are the same either way, so they stay at 32 bits.
      let wide = sixty_four
        || (is_store
          && matches!(
            Width::from_size_bits(insn.opcode & crate::jit::isa::size::DW),
            Some(Width::DW)
          ));
      emit_movewide_immediate(&mut st, wide, imm_register, insn.imm as i64 as u64);
      src = imm_register;
      opcode = to_reg_op(opcode);
    }

    let decoded = Insn { opcode, ..insn }.op_with_imm();

    match decoded {
      None => {
        // An atomic whose selector immediate names no operation is reported
        // differently from an unrecognised opcode. Both arms are
        // unreachable through `Translator::load`, whose filter table enumerates the
        // ten legal atomic immediates.
        errmsg = Some(
          if matches!(Insn { opcode, ..insn }.op(), Some(Op::Atomic { .. })) {
            format!(
              "Unknown atomic operation at PC {i}: imm {:02x}",
              insn.imm as u32
            )
          } else {
            format!("Unknown instruction at PC {i}: opcode {opcode:02x}")
          },
        );
        st.fail(Progress::UnknownInstruction);
      }

      Some(Op::Alu { op, source, .. }) => {
        emit_alu(
          &mut st,
          &insn,
          opcode,
          op,
          source,
          sixty_four,
          dst,
          src,
          &mut errmsg,
          i,
        );
      }

      Some(Op::End(kind)) => {
        emit_end(&mut st, kind, insn.imm, sixty_four, dst);
      }

      Some(Op::Ja { .. }) => {
        emit_unconditionalbranch_immediate(&mut st, ubr::B, tgt);
      }

      Some(Op::Jmp { op, source, .. }) => match (op, source) {
        (JmpOp::Set, Source::Reg) => {
          emit_logical_register(&mut st, sixty_four, log::ANDS, RZ, dst, src);
          emit_conditionalbranch_immediate(&mut st, to_condition(op), tgt);
        }
        (_, Source::Reg) => {
          emit_addsub_register(&mut st, sixty_four, addsub::SUBS, RZ, dst, src);
          emit_conditionalbranch_immediate(&mut st, to_condition(op), tgt);
        }
        (JmpOp::Set, Source::Imm) => {
          // Unreachable: JSET_IMM is never "simple", so the lowering above
          // already rewrote it to JSET_REG. It is listed under `Unexpected
          // instruction`, but that arm has no `break` and falls into
          // `default:`, so the status it reports is `UnknownInstruction`.
          errmsg = Some(format!(
            "Unknown instruction at PC {i}: opcode {opcode:02x}"
          ));
          st.fail(Progress::UnknownInstruction);
        }
        (_, Source::Imm) => {
          emit_addsub_immediate(&mut st, sixty_four, addsub::SUBS, RZ, dst, insn.imm as u32);
          emit_conditionalbranch_immediate(&mut st, to_condition(op), tgt);
        }
      },

      Some(Op::Call) => {
        let exit_tgt = PatchTarget::Special(SpecialTarget::Exit);
        if insn.src == 0 {
          emit_dispatched_external_helper_call(&mut st, insn.imm as u32);
          let unwind = cfg.unwind_helper_index.map_or(-1i64, |x| x as i32 as i64);
          if insn.imm as i64 == unwind {
            emit_addsub_immediate(&mut st, true, addsub::SUBS, RZ, map_register(0), 0);
            emit_conditionalbranch_immediate(&mut st, cond::EQ, exit_tgt);
          }
        } else if insn.src == 1 {
          // Always lazy from this entry point.
          emit_lazy_local_call(cfg, inputs, &mut st, i);
        } else {
          emit_unconditionalbranch_immediate(&mut st, ubr::B, exit_tgt);
        }
      }

      Some(Op::Exit) => {
        emit_addsub_immediate(&mut st, true, addsub::ADD, SP, SP, 16);
        emit_unconditionalbranch_register(&mut st, br::RET, R30);
      }

      Some(Op::StoreReg { width }) | Some(Op::StoreImm { width }) => {
        // A lowered store-immediate arrives here as a store-register whose
        // source is TEMP_STORE_VALUE_REGISTER.
        if native_frame_base_active(cfg) && insn.src == 10 {
          // Storing R10 stores a pointer, and it has to be the guest one.
          //
          // This tests the *raw* `inst.src` nibble, so a `st`
          // instruction that happens to carry src == 10 has the frame pointer
          // materialised over the immediate it just parked in the same
          // register. Reproduced.
          emit_guest_frame_pointer(&mut st, TEMP_STORE_VALUE_REGISTER, OFFSET_REGISTER);
          src = TEMP_STORE_VALUE_REGISTER;
        }
        std::mem::swap(&mut dst, &mut src);
        let region_hint = inputs.hint(i);
        let plan = inputs.plan_entry(cfg, i).copied();
        emit_masked_loadstore(
          cfg,
          &mut st,
          plan.as_ref(),
          to_loadstore_opcode(width, false, false),
          dst,
          src,
          insn.offset,
          region_hint,
          i as u32,
        );
      }

      Some(Op::Load { width, signed }) => {
        let region_hint = inputs.hint(i);
        let plan = inputs.plan_entry(cfg, i).copied();
        emit_masked_loadstore(
          cfg,
          &mut st,
          plan.as_ref(),
          to_loadstore_opcode(width, signed, true),
          dst,
          src,
          insn.offset,
          region_hint,
          i as u32,
        );
      }

      Some(Op::Atomic { width, op, fetch }) => {
        let is_64bit = width == Width::DW;
        let temp_reg = TEMP_REGISTER;
        let status_reg = TEMP_DIV_REGISTER;
        let (result_reg, is_cmpxchg, is_xchg, alu_op, fetch) = match op {
          AtomicOp::Add => (src, false, false, crate::jit::isa::alu::ADD, fetch),
          AtomicOp::Or => (src, false, false, crate::jit::isa::alu::OR, fetch),
          AtomicOp::And => (src, false, false, crate::jit::isa::alu::AND, fetch),
          AtomicOp::Xor => (src, false, false, crate::jit::isa::alu::XOR, fetch),
          AtomicOp::Xchg => (src, false, true, 0, true),
          // For CMPXCHG the result goes to eBPF r0.
          AtomicOp::Cmpxchg => (map_register(0), true, false, 0, true),
        };
        emit_atomic_operation(
          cfg,
          &mut st,
          is_64bit,
          src,
          dst,
          result_reg,
          temp_reg,
          status_reg,
          insn.offset,
          alu_op,
          is_cmpxchg,
          is_xchg,
          fetch,
        );
      }

      Some(Op::LoadImm64) => {
        i += 1;
        let hi = insns.get(i).map_or(0, |n| n.imm);
        let imm = (insn.imm as u32 as u64) | ((hi as u32 as u64) << 32);
        emit_movewide_immediate(&mut st, true, dst, imm);
      }
    }

    // After the instruction has used its operands, note what it overwrote: an
    // access whose destination is its own base is still valid, but nothing
    // addressing that base afterwards is. Routed through the shared helper, as
    // x86_64 does, so both backends invalidate a group by the same rule rather
    // than by two mechanisms that happen to agree.
    let mask = written_registers_mask(&insn);
    for reg in 0..16u8 {
      if mask & (1u16 << reg) != 0 {
        st.note_register_written(reg);
      }
    }
    i += 1;
  }

  if !st.ok() {
    return Err(loop_error(st.status, errmsg));
  }

  st.exit_loc = st.offset;
  emit_addsub_immediate(&mut st, true, addsub::ADD, SP, SP, 16);
  emit_unconditionalbranch_register(&mut st, br::RET, R30);

  let dispatcher_addr = cfg.dispatcher.map_or(0u64, |d| d as usize as u64);
  st.dispatcher_loc = emit_dispatched_external_helper_address(&mut st, dispatcher_addr);
  st.helper_table_loc = emit_helper_table(&mut st);

  // Everything above is emitted after the per-instruction error check, so an
  // overflow here would otherwise be reported as success — and a patch site
  // recorded just before the overflow is still in the jump table.
  if !st.ok() {
    return Err(if st.status == Progress::NotEnoughSpace {
      TranslateError::OutOfSpace
    } else {
      failed("Failure to emit the function epilogue")
    });
  }

  if !resolve_jumps(&mut st)
    || !resolve_loads(&mut st)
    || !resolve_leas(&mut st)
    || !resolve_local_calls(&mut st)
  {
    return Err(if st.status == Progress::RelocationOutOfRange {
      failed(
        "Branch or load target out of range in the JIT'd code (the program is too large for \
         arm64 PC-relative addressing).",
      )
    } else {
      failed("Could not patch the relative addresses in the JIT'd code.")
    });
  }

  Ok(st.offset as usize)
}

/// Whether this opcode is `mov`/`mov64` with an immediate, which the lowering
/// above deliberately skips so the value lands directly in the destination.
fn is_mov_imm(opcode: u8) -> bool {
  use crate::jit::isa::{alu, cls, src};
  let class = opcode & cls::MASK;
  (class == cls::ALU || class == cls::ALU64)
    && opcode & alu::MASK == alu::MOV
    && opcode & src::REG == src::IMM
}

/// Map a non-`Ok` status to the error reported for it.
fn loop_error(status: Progress, errmsg: Option<String>) -> TranslateError {
  match status {
    Progress::TooManyJumps => failed("Too many jump instructions."),
    Progress::TooManyLoads => failed("Too many load instructions."),
    Progress::TooManyLeas => failed("Too many LEA calculations."),
    Progress::TooManyLocalCalls => failed("Too many local calls."),
    Progress::UnexpectedInstruction => failed(errmsg.unwrap_or_else(|| {
      // The lazy local-call guard sets the status without a message.
      "Unexpected instruction or missing local-call resolver during JIT compilation".to_string()
    })),
    Progress::UnknownInstruction => failed(errmsg.unwrap_or_default()),
    Progress::NotEnoughSpace => TranslateError::OutOfSpace,
    Progress::RelocationOutOfRange | Progress::Ok => failed(errmsg.unwrap_or_default()),
  }
}

/// The barrier pre-pass, which the x86_64 backend does not have.
/// Builds the set of instruction slots a branch can land on. An access group's
/// members address the base its leader parked, so any path reaching a member
/// without running the leader would read a stale one.
fn barrier_prepass(t: &Translator, st: &mut JitState, start_pc: usize, end_pc: usize) {
  use crate::jit::isa::{cls, opcode as opc};
  let insns = t.insns();
  let num_insts = insns.len();

  for i in start_pc..end_pc {
    let insn = insns[i];

    // A local function entry is reached by `call`, never by falling into it.
    if t.is_local_func_entry(i) {
      st.mark_barrier(i);
    }

    let barrier_cls = insn.opcode & cls::MASK;
    if barrier_cls != cls::JMP && barrier_cls != cls::JMP32 {
      continue;
    }
    // Nothing falls through an EXIT, an unconditional jump or a call, so
    // whatever follows is entered from somewhere else. A call ends the group
    // for its own reasons too: a local callee shares this host frame.
    if i + 1 <= num_insts {
      st.mark_barrier(i + 1);
    }
    if insn.opcode == opc::CALL || insn.opcode == opc::EXIT {
      continue;
    }
    let target = i as i64
      + 1
      + if insn.opcode == opc::JA32 {
        insn.imm as i64
      } else {
        insn.offset as i64
      };
    if target >= 0 && target <= num_insts as i64 {
      st.mark_barrier(target as usize);
    }
  }
}

/// The ALU arm of the main `switch`.
#[allow(clippy::too_many_arguments)]
fn emit_alu(
  st: &mut JitState,
  insn: &Insn,
  opcode: u8,
  op: AluOp,
  source: Source,
  sixty_four: bool,
  dst: u32,
  src: u32,
  errmsg: &mut Option<String>,
  pc: usize,
) {
  match (op, source) {
    (AluOp::Add, Source::Imm) => {
      emit_addsub_immediate(st, sixty_four, addsub::ADD, dst, dst, insn.imm as u32)
    }
    (AluOp::Sub, Source::Imm) => {
      emit_addsub_immediate(st, sixty_four, addsub::SUB, dst, dst, insn.imm as u32)
    }
    (AluOp::Add, Source::Reg) => emit_addsub_register(st, sixty_four, addsub::ADD, dst, dst, src),
    (AluOp::Sub, Source::Reg) => emit_addsub_register(st, sixty_four, addsub::SUB, dst, dst, src),
    (AluOp::Lsh, Source::Reg) => {
      emit_dataprocessing_twosource(st, sixty_four, dp2::LSLV, dst, dst, src)
    }
    (AluOp::Rsh, Source::Reg) => {
      emit_dataprocessing_twosource(st, sixty_four, dp2::LSRV, dst, dst, src)
    }
    (AluOp::Arsh, Source::Reg) => {
      emit_dataprocessing_twosource(st, sixty_four, dp2::ASRV, dst, dst, src)
    }
    (AluOp::Mul, Source::Reg) => {
      emit_dataprocessing_threesource(st, sixty_four, dp3::MADD, dst, dst, src, RZ)
    }
    (AluOp::Div, Source::Reg) | (AluOp::Mod, Source::Reg) => {
      divmod(st, opcode, dst, dst, src, insn.offset)
    }
    (AluOp::Or, Source::Reg) => emit_logical_register(st, sixty_four, log::ORR, dst, dst, src),
    (AluOp::And, Source::Reg) => emit_logical_register(st, sixty_four, log::AND, dst, dst, src),
    (AluOp::Xor, Source::Reg) => emit_logical_register(st, sixty_four, log::EOR, dst, dst, src),
    (AluOp::Neg, _) => emit_addsub_register(st, sixty_four, addsub::SUB, dst, RZ, dst),
    (AluOp::Mov, Source::Imm) => {
      emit_movewide_immediate(st, sixty_four, dst, insn.imm as i64 as u64)
    }
    (AluOp::Mov, Source::Reg) => {
      // MOVSX: sign-extend based on the offset field (RFC 9669).
      if insn.offset == 8 {
        let opc = if sixty_four { 0x9340_1c00 } else { 0x1300_1c00 };
        emit_instruction(st, opc | (src << 5) | dst);
      } else if insn.offset == 16 {
        let opc = if sixty_four { 0x9340_3c00 } else { 0x1300_3c00 };
        emit_instruction(st, opc | (src << 5) | dst);
      } else if insn.offset == 32 && sixty_four {
        emit_instruction(st, 0x9340_7c00 | (src << 5) | dst);
      } else {
        emit_logical_register(st, sixty_four, log::ORR, dst, RZ, src);
      }
    }
    // Every remaining immediate form is rewritten to its register form before
    // the switch, so these arms are unreachable. They are listed under
    // `Unexpected instruction` but that arm has no `break`, so it falls into
    // `default:` and the status the caller sees is `UnknownInstruction`.
    (_, Source::Imm) => {
      *errmsg = Some(format!(
        "Unknown instruction at PC {pc}: opcode {opcode:02x}"
      ));
      st.fail(Progress::UnknownInstruction);
    }
  }
}

/// `le` / `be` / `bswap`.
/// Two deliberate asymmetries are reproduced: on a little-endian host `le`
/// emits no byte reversal at all (and nothing whatsoever for `imm == 64`), and
/// `be` zero-extends only for `imm == 16` where `bswap` also does so for 32.
fn emit_end(st: &mut JitState, kind: EndKind, imm: i32, sixty_four: bool, dst: u32) {
  const UXTH: u32 = 0x5300_3c00;
  const UXTW: u32 = 0x5300_7c00;
  match kind {
    EndKind::Le => {
      // Little-endian host: the reversal is a no-op. Both supported targets are
      // little-endian, so the big-endian form never takes the other
      // branch here.
      if imm == 16 {
        emit_instruction(st, UXTH | (dst << 5) | dst);
      } else if imm == 32 {
        emit_instruction(st, UXTW | (dst << 5) | dst);
      }
    }
    EndKind::Be => {
      emit_dataprocessing_onesource(st, sixty_four, to_dp1_opcode(imm), dst, dst);
      if imm == 16 {
        emit_instruction(st, UXTH | (dst << 5) | dst);
      }
    }
    EndKind::Bswap => {
      emit_dataprocessing_onesource(st, sixty_four, to_dp1_opcode(imm), dst, dst);
      if imm == 16 {
        emit_instruction(st, UXTH | (dst << 5) | dst);
      } else if imm == 32 {
        emit_instruction(st, UXTW | (dst << 5) | dst);
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::jit::golden::{self, SweepDigest};
  use crate::jit::isa::{alu, atomic, cls, jmp, mode, opcode, size, src as srcbit};
  use crate::jit::{Dispatcher, LocalCallResolver, Target};

  fn insn(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Insn {
    Insn {
      opcode,
      dst,
      src,
      offset,
      imm,
    }
  }

  fn exit() -> Insn {
    insn(opcode::EXIT, 0, 0, 0, 0)
  }

  // ---------------------------------------------------------------------------
  // The harness
  // ---------------------------------------------------------------------------

  /// Stand-in addresses for the helper dispatcher and the local-call resolver.
  /// A helper call materialises the dispatcher's address as an immediate, and a
  /// lazy local call materialises the resolver's, so both end up *inside* the
  /// emitted bytes. A real function's address moves with every build and with
  /// address-space randomisation, so recording it would make the output differ
  /// from one run to the next for no reason anybody could review. These fixed
  /// sentinels keep the emitted code reproducible.
  /// Nothing ever calls them: translation only writes their value into the
  /// buffer, and this module never executes what it emits.
  const STAND_IN_DISPATCHER: usize = 0x0000_5eed_1111_0000;
  const STAND_IN_RESOLVER: usize = 0x0000_5eed_2222_0000;

  fn stand_in_dispatcher() -> Dispatcher {
    // SAFETY: the address is only ever materialised as an immediate. Producing
    // a function pointer from an integer is well defined; calling it would not
    // be, and nothing here does.
    unsafe { std::mem::transmute::<usize, Dispatcher>(STAND_IN_DISPATCHER) }
  }

  fn stand_in_resolver() -> LocalCallResolver {
    // SAFETY: as for the dispatcher above.
    unsafe { std::mem::transmute::<usize, LocalCallResolver>(STAND_IN_RESOLVER) }
  }

  /// Admits every helper index, so that helper-call emission is exercised
  /// rather than refused at load. This one is a real function, because the
  /// validator calls it.
  unsafe extern "C" fn accept_every_helper(_index: u32, _vm: *const std::ffi::c_void) -> bool {
    true
  }

  /// Builds [`TranslationInputs`] covering a whole program with no hints or
  /// plan.
  fn plain_inputs(num_insns: usize) -> TranslationInputs<'static> {
    TranslationInputs {
      hints: &[],
      plan: &[],
      resolver_ids: &[],
      start_pc: 0,
      end_pc: num_insns,
    }
  }

  /// The configuration sweep every emitter test runs over.
  /// The emitted code depends on the pointer cage, the native frame base, the
  /// frame constants and the region hints, and those features *interact* —
  /// which is exactly where code generation goes wrong. Sweeping them is not
  /// optional.
  fn config_sweep(target: Target) -> Vec<(&'static str, Config)> {
    let base = Config {
      target,
      dispatcher: Some(stand_in_dispatcher()),
      dispatcher_validate: Some(accept_every_helper),
      local_call_resolver: Some(stand_in_resolver()),
      ..Default::default()
    };
    vec![
      (
        "no cage",
        Config {
          pointer_mask: 0,
          pointer_offset: 0,
          ..base.clone()
        },
      ),
      (
        "cage only",
        Config {
          pointer_mask: 0x0fff_ffff,
          pointer_offset: 0x1_0000_0000,
          ..base.clone()
        },
      ),
      (
        "cage + native frame base",
        Config {
          pointer_mask: 0x0fff_ffff,
          pointer_offset: 0x1_0000_0000,
          native_frame_base: true,
          ..base.clone()
        },
      ),
      (
        "cage + frame constants",
        Config {
          pointer_mask: 0x0fff_ffff,
          pointer_offset: 0x1_0000_0000,
          frame_constants: true,
          ..base.clone()
        },
      ),
      (
        // What `async-ebpf` actually runs.
        "production",
        Config {
          pointer_mask: 0x0fff_ffff,
          pointer_offset: 0x1_0000_0000,
          native_frame_base: true,
          frame_constants: true,
          ..base.clone()
        },
      ),
      (
        "production + unwind helper",
        Config {
          pointer_mask: 0x0fff_ffff,
          pointer_offset: 0x1_0000_0000,
          native_frame_base: true,
          frame_constants: true,
          unwind_helper_index: Some(3),
          ..base
        },
      ),
    ]
  }

  /// One case against its golden. Returns whether it produced code.
  /// The label has to distinguish cases that share a program, a configuration
  /// and a set of inputs but differ in the buffer they are given, since the
  /// golden key is content-addressed over everything *but* the capacity.
  fn golden_case(
    label: &str,
    config: &Config,
    code: &[u8],
    inputs: &TranslationInputs<'_>,
    capacity: usize,
  ) -> bool {
    let translated = golden::check(label, config, code, inputs, capacity);
    // The test runner does not run process-exit hooks, so a recording run has
    // to write the file back as it goes.
    golden::flush();
    translated
  }

  /// Folds one case into a sweep's rolling digest.
  /// A program the loader refuses contributes its own outcome rather than
  /// nothing, so a generator that quietly stops producing loadable programs
  /// still moves the digest instead of silently shrinking the sweep.
  fn sweep_case(
    digest: &mut SweepDigest,
    config: &Config,
    code: &[u8],
    inputs: &TranslationInputs<'_>,
    capacity: usize,
  ) {
    let out = golden::translate_one(config, code, inputs, capacity)
      .unwrap_or_else(|| Err(TranslateError::Failed("refused at load".into())));
    digest.add(&out);
  }

  /// Closes a sweep and writes it back, as [`golden_case`] does for one case.
  fn finish_sweep(digest: SweepDigest, label: &str) {
    digest.finish(label, Target::Aarch64);
    golden::flush();
  }

  /// Runs one program through every aarch64 configuration, against the goldens.
  #[track_caller]
  fn check(what: &str, insns: &[Insn]) {
    check_with(what, insns, &plain_inputs(insns.len()));
  }

  /// Checks the goldens *and* that real code came out, so a test cannot pass by
  /// quietly degrading into a program that is refused for a reason it never
  /// meant to exercise.
  #[track_caller]
  fn check_with(what: &str, insns: &[Insn], inputs: &TranslationInputs<'_>) {
    let code = Insn::encode_all(insns);
    let capacity = 262144.max(insns.len() * 512);
    for (name, config) in config_sweep(Target::Aarch64) {
      assert!(
        golden_case(&format!("{what}/{name}"), &config, &code, inputs, capacity),
        "{what} under {name:?} produced no code"
      );
    }
  }

  /// Asserts that every configuration refuses the program.
  #[track_caller]
  fn check_rejected(what: &str, insns: &[Insn], inputs: &TranslationInputs<'_>) {
    let code = Insn::encode_all(insns);
    let capacity = 262144.max(insns.len() * 512);
    for (name, config) in config_sweep(Target::Aarch64) {
      assert!(
        !golden_case(&format!("{what}/{name}"), &config, &code, inputs, capacity),
        "{what} under {name:?} emitted code where a refusal was expected"
      );
    }
  }

  // -------------------------------------------------------------------------
  // Shape
  // -------------------------------------------------------------------------

  #[test]
  fn a_function_granular_callee_does_not_skip_its_own_prologue() {
    // The preceding, unreachable JA is deliberately treated as potentially
    // falling through by Insn::has_fallthrough. Whole-program translation
    // needs a jump around a later function's prologue in that case, but a
    // buffer translated for the callee starts at pc 4 and must enter its own
    // prologue directly.
    let insns = vec![
      insn(opcode::CALL, 0, 1, 0, 3), // pc 0 -> pc 4
      exit(),
      insn(opcode::JA, 0, 0, 0, 0),
      insn(opcode::CALL, 0, 0, 0, 0),
      insn(cls::ALU64 | alu::MOV, 0, 0, 0, 7),
      exit(),
    ];
    let code = Insn::encode_all(&insns);
    let config = Config {
      target: Target::Aarch64,
      dispatcher: Some(stand_in_dispatcher()),
      dispatcher_validate: Some(accept_every_helper),
      local_call_resolver: Some(stand_in_resolver()),
      ..Default::default()
    };
    let translator = Translator::load(std::sync::Arc::new(config), &code).unwrap();
    let resolver_ids = [1u32; 6];
    let inputs = TranslationInputs {
      resolver_ids: &resolver_ids,
      start_pc: 4,
      end_pc: 6,
      ..Default::default()
    };
    let mut out = vec![0u8; 4096];
    let len = translator.translate_range(&inputs, &mut out).unwrap();

    assert!(len >= 8);
    assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), BTI_C);
    assert_ne!(
      u32::from_le_bytes(out[4..8].try_into().unwrap()) & 0xfc00_0000,
      ubr::B,
      "the callee entry jumped past its own prologue"
    );
  }

  #[test]
  fn prologue_epilogue_and_exit() {
    check("mov/exit", &[insn(0xb7, 0, 0, 0, 42), exit()]);
  }

  #[test]
  fn every_register_is_a_legal_destination_and_source() {
    let mut program = Vec::new();
    for dst in 0..10u8 {
      for src in 0..=10u8 {
        program.push(insn(cls::ALU64 | srcbit::REG | alu::MOV, dst, src, 0, 0));
        program.push(insn(cls::ALU | srcbit::REG | alu::ADD, dst, src, 0, 0));
      }
    }
    program.push(exit());
    check("all register pairs", &program);
  }

  // -------------------------------------------------------------------------
  // ALU
  // -------------------------------------------------------------------------

  const ALU_OPS: [u8; 12] = [
    alu::ADD,
    alu::SUB,
    alu::MUL,
    alu::DIV,
    alu::OR,
    alu::AND,
    alu::LSH,
    alu::RSH,
    alu::MOD,
    alu::XOR,
    alu::MOV,
    alu::ARSH,
  ];

  #[test]
  fn every_alu_op_at_both_widths_in_both_forms() {
    let mut program = Vec::new();
    for class in [cls::ALU, cls::ALU64] {
      for op in ALU_OPS {
        for imm in [0i32, 1, 0xfff, 0x1000, -1, i32::MIN, 0x1234_5678] {
          program.push(insn(class | srcbit::IMM | op, 1, 0, 0, imm));
        }
        program.push(insn(class | srcbit::REG | op, 1, 2, 0, 0));
      }
      // `neg` takes no source.
      program.push(insn(class | alu::NEG, 3, 0, 0, 0));
    }
    program.push(exit());
    check("alu", &program);
  }

  #[test]
  fn signed_div_and_mod_are_selected_by_the_offset_field() {
    let mut program = Vec::new();
    for class in [cls::ALU, cls::ALU64] {
      for op in [alu::DIV, alu::MOD] {
        for offset in [0i16, 1] {
          program.push(insn(class | srcbit::REG | op, 1, 2, offset, 0));
          program.push(insn(class | srcbit::IMM | op, 1, 0, offset, 7));
        }
      }
    }
    program.push(exit());
    check("divmod", &program);
  }

  #[test]
  fn movsx_uses_the_offset_field_to_pick_a_width() {
    let mut program = Vec::new();
    // A 32-bit MOVSX has no 32-bit sign-extension form, and the loader refuses
    // `offset == 32` there.
    for (class, offsets) in [
      (cls::ALU, &[0i16, 8, 16][..]),
      (cls::ALU64, &[0, 8, 16, 32][..]),
    ] {
      for &offset in offsets {
        program.push(insn(class | srcbit::REG | alu::MOV, 1, 2, offset, 0));
      }
    }
    program.push(exit());
    check("movsx", &program);
  }

  #[test]
  fn byte_swaps_at_every_width() {
    let mut program = Vec::new();
    for op in [opcode::LE, opcode::BE, opcode::BSWAP] {
      for imm in [16i32, 32, 64] {
        program.push(insn(op, 1, 0, 0, imm));
      }
    }
    program.push(exit());
    check("end", &program);
  }

  // -------------------------------------------------------------------------
  // Immediate materialisation
  // -------------------------------------------------------------------------

  #[test]
  fn movewide_sequences_of_every_length() {
    // 1, 2, 3 and 4 instruction sequences, plus the MOVN-preferring shapes.
    let constants: [u64; 14] = [
      0,
      0xffff_ffff_ffff_ffff,
      0x1234,
      0x1234_0000,
      0x1234_0000_0000_0000,
      0x1234_5678,
      0x1234_0000_5678,
      0x1234_5678_9abc,
      0x1234_5678_9abc_def0,
      0xffff_ffff_ffff_1234,
      0xffff_1234_ffff_ffff,
      0x0000_ffff_0000_ffff,
      0xffff_0000_ffff_0000,
      0x8000_0000_0000_0000,
    ];
    let mut program = Vec::new();
    for c in constants {
      program.push(insn(opcode::LDDW, 1, 0, 0, c as u32 as i32));
      program.push(insn(0, 0, 0, 0, (c >> 32) as u32 as i32));
    }
    program.push(exit());
    check("lddw", &program);
  }

  #[test]
  fn thirty_two_bit_immediates_are_materialised_at_thirty_two_bits() {
    let mut program = Vec::new();
    for imm in [
      0i32,
      -1,
      1,
      0xffff,
      0x1_0000,
      0x7fff_ffff,
      i32::MIN,
      -0x1_0000,
    ] {
      program.push(insn(cls::ALU | srcbit::IMM | alu::MOV, 1, 0, 0, imm));
      program.push(insn(cls::ALU64 | srcbit::IMM | alu::MOV, 1, 0, 0, imm));
      program.push(insn(cls::ALU | srcbit::IMM | alu::OR, 1, 0, 0, imm));
      program.push(insn(cls::ALU64 | srcbit::IMM | alu::OR, 1, 0, 0, imm));
    }
    program.push(exit());
    check("mov imm", &program);
  }

  // -------------------------------------------------------------------------
  // Jumps
  // -------------------------------------------------------------------------

  const JMP_OPS: [u8; 11] = [
    jmp::JEQ,
    jmp::JGT,
    jmp::JGE,
    jmp::JSET,
    jmp::JNE,
    jmp::JSGT,
    jmp::JSGE,
    jmp::JLT,
    jmp::JLE,
    jmp::JSLT,
    jmp::JSLE,
  ];

  #[test]
  fn every_conditional_jump_at_both_widths_in_both_forms() {
    let mut program = Vec::new();
    for class in [cls::JMP, cls::JMP32] {
      for op in JMP_OPS {
        for imm in [0i32, 0xfff, 0x1000, -1] {
          program.push(insn(class | srcbit::IMM | op, 1, 0, 0, imm));
        }
        program.push(insn(class | srcbit::REG | op, 1, 2, 0, 0));
      }
    }
    // Every jump above has offset 0, i.e. targets the next instruction.
    program.push(exit());
    check("conditional jumps", &program);
  }

  #[test]
  fn unconditional_jumps_use_offset_for_ja_and_imm_for_ja32() {
    let program = vec![
      insn(opcode::JA, 0, 0, 1, 0),
      insn(0xb7, 0, 0, 0, 1),
      insn(opcode::JA32, 0, 0, 0, 1),
      insn(0xb7, 0, 0, 0, 2),
      insn(opcode::JA, 0, 0, -2, 0),
      exit(),
    ];
    check("ja", &program);
  }

  #[test]
  fn backward_and_forward_jumps_resolve_the_same_way() {
    let program = vec![
      insn(0xb7, 1, 0, 0, 0),
      insn(cls::JMP | srcbit::IMM | jmp::JEQ, 1, 0, 2, 0),
      insn(0xb7, 1, 0, 0, 1),
      insn(opcode::JA, 0, 0, -3, 0),
      exit(),
    ];
    check("branch both ways", &program);
  }

  // -------------------------------------------------------------------------
  // Memory
  // -------------------------------------------------------------------------

  #[test]
  fn loads_and_stores_at_all_four_widths() {
    let mut program = Vec::new();
    for sz in [size::B, size::H, size::W, size::DW] {
      for offset in [0i16, 1, 8, 255, 256, -1, -256, -257, 4095, 4096, -4096] {
        program.push(insn(cls::LDX | mode::MEM | sz, 1, 2, offset, 0));
        program.push(insn(cls::STX | mode::MEM | sz, 1, 2, offset, 0));
        program.push(insn(cls::ST | mode::MEM | sz, 1, 0, offset, 0x1234));
      }
    }
    program.push(exit());
    check("load/store", &program);
  }

  #[test]
  fn sign_extending_loads() {
    let mut program = Vec::new();
    for sz in [size::B, size::H, size::W] {
      for offset in [0i16, 100, -100, 1000] {
        program.push(insn(cls::LDX | mode::MEMSX | sz, 1, 2, offset, 0));
      }
    }
    program.push(exit());
    check("ldxsx", &program);
  }

  #[test]
  fn the_frame_pointer_is_read_as_a_guest_value_and_used_as_a_base() {
    let program = vec![
      // R10 as a value.
      insn(cls::ALU64 | srcbit::REG | alu::MOV, 1, 10, 0, 0),
      insn(cls::ALU64 | srcbit::REG | alu::ADD, 1, 10, 0, 0),
      insn(cls::JMP | srcbit::REG | jmp::JEQ, 1, 10, 0, 0),
      // R10 as a base.
      insn(cls::LDX | mode::MEM | size::DW, 1, 10, -8, 0),
      insn(cls::STX | mode::MEM | size::DW, 10, 1, -8, 0),
      // Storing R10 itself.
      insn(cls::STX | mode::MEM | size::DW, 1, 10, 0, 0),
      exit(),
    ];
    check("r10", &program);
  }

  #[test]
  fn region_hints_zero_through_three() {
    let insns = vec![
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
      insn(cls::LDX | mode::MEM | size::W, 1, 10, -8, 0),
      insn(cls::STX | mode::MEM | size::B, 2, 1, -4, 0),
      insn(cls::LDX | mode::MEM | size::H, 1, 10, -256, 0),
      insn(cls::LDX | mode::MEM | size::DW, 1, 10, -300, 0),
      exit(),
    ];
    // Sixteen hint pairings across six configurations: a cross-product, so one
    // digest rather than ninety-six entries.
    let code = Insn::encode_all(&insns);
    let mut digest = SweepDigest::new();
    for a in 0..4u8 {
      for b in 0..4u8 {
        let hints = vec![a, b, a, b, a, 0];
        let inputs = TranslationInputs {
          hints: &hints,
          ..plain_inputs(insns.len())
        };
        for (_, config) in config_sweep(Target::Aarch64) {
          sweep_case(&mut digest, &config, &code, &inputs, 65536);
        }
      }
    }
    assert_eq!(
      digest.translated(),
      digest.cases(),
      "every hint pairing must translate"
    );
    finish_sweep(digest, "region-hints");
  }

  // -------------------------------------------------------------------------
  // Atomics
  // -------------------------------------------------------------------------

  #[test]
  fn every_atomic_operation_at_both_widths() {
    let mut program = Vec::new();
    for op in [opcode::ATOMIC32_STORE, opcode::ATOMIC_STORE] {
      for imm in [
        alu::ADD as i32,
        alu::ADD as i32 | atomic::OP_FETCH,
        alu::OR as i32,
        alu::OR as i32 | atomic::OP_FETCH,
        alu::AND as i32,
        alu::AND as i32 | atomic::OP_FETCH,
        alu::XOR as i32,
        alu::XOR as i32 | atomic::OP_FETCH,
        atomic::OP_XCHG,
        atomic::OP_CMPXCHG,
      ] {
        for offset in [0i16, 8, -8, 4096] {
          program.push(insn(op, 1, 2, offset, imm));
        }
        // The fetch destination being r0 exercises `result_reg == load_reg`.
        program.push(insn(op, 1, 0, 0, imm));
      }
    }
    program.push(exit());
    check("atomics", &program);
  }

  #[test]
  fn non_canonical_atomic_selectors_at_thirty_two_bits() {
    // The 32-bit atomic filter bounds the immediate at 0..=255 rather than
    // enumerating legal values (the doubleword one does enumerate), so
    // selectors no compiler emits still load at this width. The backend
    // switches on `imm & 0xf0` and takes the fetch flag from bit 0, which
    // leaves bits 1..3 dead: `0x02` is a plain atomic add and `0x0f` a fetching
    // one. Both are recorded, so the dead bits staying dead is pinned.
    let mut program = Vec::new();
    for imm in [
      0x02i32, 0x0f, 0x0e, 0x41, 0x4f, 0x5e, 0xa2, 0xe1, 0xf1, 0xff,
    ] {
      for offset in [0i16, 8] {
        program.push(insn(opcode::ATOMIC32_STORE, 1, 2, offset, imm));
      }
      // The fetch destination being r0 exercises `result_reg == load_reg`.
      program.push(insn(opcode::ATOMIC32_STORE, 1, 0, 0, imm));
    }
    program.push(exit());
    check("non-canonical atomic selectors", &program);
  }

  #[test]
  fn an_atomic_selector_naming_no_operation_is_refused() {
    // `validate()` masks the selector the same way the backend does and refuses
    // any high nibble it does not name, plus `xchg`/`cmpxchg` without the fetch
    // bit. So the backend's own `Unknown atomic operation` arm is in fact
    // unreachable through the loader; what these inputs establish is that the
    // refusal happens at load, where it can still be reported cleanly, rather
    // than half-way through emitting code.
    for imm in [
      0x10i32, 0x20, 0x30, 0x60, 0x70, 0x80, 0x90, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0xe2, 0xf2,
    ] {
      let program = vec![insn(opcode::ATOMIC32_STORE, 1, 2, 0, imm), exit()];
      check_rejected(
        &format!("atomic selector {imm:#04x}"),
        &program,
        &plain_inputs(2),
      );
    }
  }

  // -------------------------------------------------------------------------
  // Calls
  // -------------------------------------------------------------------------

  #[test]
  fn helper_calls_including_the_unwind_index() {
    let mut program = Vec::new();
    for idx in [0i32, 1, 3, 63] {
      program.push(insn(opcode::CALL, 0, 0, 0, idx));
    }
    program.push(exit());
    check("helper calls", &program);
  }

  #[test]
  fn local_calls_with_resolver_ids() {
    let insns = vec![
      insn(opcode::CALL, 0, 1, 0, 1),
      exit(),
      insn(0xb7, 0, 0, 0, 7),
      exit(),
    ];
    let ids = [11u32, 0, 0, 0];
    check_with(
      "local call",
      &insns,
      &TranslationInputs {
        resolver_ids: &ids,
        end_pc: 2,
        ..plain_inputs(insns.len())
      },
    );
  }

  #[test]
  fn a_local_call_without_a_resolver_id_is_rejected() {
    let insns = vec![insn(opcode::CALL, 0, 1, 0, 1), exit(), exit()];
    check_rejected(
      "local call, no ids",
      &insns,
      &TranslationInputs {
        start_pc: 0,
        end_pc: 2,
        ..Default::default()
      },
    );
  }

  // -------------------------------------------------------------------------
  // Sub-ranges
  // -------------------------------------------------------------------------

  #[test]
  fn a_strict_sub_range_translates_only_its_own_function() {
    // pc 2 begins a local function (it is the target of the call at pc 0).
    let insns = vec![
      insn(opcode::CALL, 0, 1, 0, 1),
      exit(),
      insn(0xb7, 0, 0, 0, 9),
      insn(cls::JMP | srcbit::IMM | jmp::JEQ, 0, 0, 0, 9),
      exit(),
    ];
    let ids = [5u32; 5];
    for (start, end) in [(0usize, 2usize), (2, 5)] {
      check_with(
        &format!("range {start}..{end}"),
        &insns,
        &TranslationInputs {
          resolver_ids: &ids,
          start_pc: start,
          end_pc: end,
          ..Default::default()
        },
      );
    }
  }

  #[test]
  fn a_jump_out_of_the_translation_range_is_refused() {
    let insns = vec![
      insn(opcode::CALL, 0, 1, 0, 1),
      exit(),
      insn(opcode::JA, 0, 0, -3, 0),
      exit(),
    ];
    let ids = [5u32; 4];
    check_rejected(
      "escaping jump",
      &insns,
      &TranslationInputs {
        resolver_ids: &ids,
        start_pc: 2,
        end_pc: 4,
        ..Default::default()
      },
    );
  }

  #[test]
  fn an_invalid_range_is_refused() {
    let insns = vec![insn(0xb7, 0, 0, 0, 1), exit()];
    for (start, end) in [(0usize, 0usize), (1, 2), (0, 3)] {
      check_rejected(
        &format!("bad range {start}..{end}"),
        &insns,
        &TranslationInputs {
          start_pc: start,
          end_pc: end,
          ..Default::default()
        },
      );
    }
  }

  // -------------------------------------------------------------------------
  // Access plans
  // -------------------------------------------------------------------------

  fn none_entry() -> PlanEntry {
    PlanEntry::default()
  }

  fn leader(region: u8, lo: i32, delta: u16, span: u32, pc: u32) -> PlanEntry {
    PlanEntry {
      role: abi::plan_role::LEADER,
      region,
      delta,
      span,
      lo,
      leader_pc: pc,
    }
  }

  fn member(region: u8, lo: i32, delta: u16, pc: u32) -> PlanEntry {
    PlanEntry {
      role: abi::plan_role::MEMBER,
      region,
      delta,
      span: 0,
      lo,
      leader_pc: pc,
    }
  }

  /// `ldxdw r1, [r2+lo]; ldxdw r3, [r2+lo+delta]; exit`
  fn two_access_group(lo: i16, second: i16) -> Vec<Insn> {
    vec![
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, lo, 0),
      insn(cls::LDX | mode::MEM | size::DW, 3, 2, second, 0),
      exit(),
    ]
  }

  #[test]
  fn a_well_formed_group_is_honoured() {
    let insns = two_access_group(0, 8);
    let plan = [
      leader(abi::region::STACK, 0, 0, 16, 0),
      member(abi::region::STACK, 0, 8, 0),
      none_entry(),
    ];
    check_with(
      "group",
      &insns,
      &TranslationInputs {
        plan: &plan,
        ..plain_inputs(insns.len())
      },
    );
  }

  #[test]
  fn a_member_displacement_past_the_unscaled_reach_is_folded_into_the_address() {
    // delta >= 256 does not fit the unscaled load/store immediate, so the
    // backend adds it to the address first.
    let insns = two_access_group(0, 300);
    let plan = [
      leader(abi::region::STACK, 0, 0, 4096, 0),
      member(abi::region::STACK, 0, 300, 0),
      none_entry(),
    ];
    check_with(
      "wide member",
      &insns,
      &TranslationInputs {
        plan: &plan,
        ..plain_inputs(insns.len())
      },
    );
  }

  #[test]
  fn a_store_group_is_honoured_only_against_the_stack() {
    for region in [abi::region::STACK, abi::region::DATA, abi::region::UNKNOWN] {
      let insns = vec![
        insn(cls::STX | mode::MEM | size::DW, 2, 1, 0, 0),
        insn(cls::STX | mode::MEM | size::DW, 2, 3, 8, 0),
        exit(),
      ];
      let plan = [
        leader(region, 0, 0, 16, 0),
        member(region, 0, 8, 0),
        none_entry(),
      ];
      check_with(
        &format!("store group region {region}"),
        &insns,
        &TranslationInputs {
          plan: &plan,
          ..plain_inputs(insns.len())
        },
      );
    }
  }

  #[test]
  fn hostile_plans_fall_back_to_an_ordinary_checked_access() {
    // Each of these must be rejected by the backend's own re-derivation, which
    // means it emits exactly what no plan at all would: an ordinary checked
    // access. A plan that is wrong - or hostile - costs speed and nothing else,
    // and the recorded bytes are what holds that claim up.
    let cases: Vec<(&str, Vec<Insn>, Vec<PlanEntry>)> = vec![
      (
        "member names a leader that never ran",
        two_access_group(0, 8),
        vec![
          leader(abi::region::STACK, 0, 0, 16, 0),
          member(abi::region::STACK, 0, 8, 999),
          none_entry(),
        ],
      ),
      (
        "member with no leader at all",
        two_access_group(0, 8),
        vec![
          none_entry(),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        "member reaches past the checked window",
        two_access_group(0, 8),
        vec![
          leader(abi::region::STACK, 0, 0, 12, 0),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        "member displacement disagrees with its own offset",
        two_access_group(0, 8),
        vec![
          leader(abi::region::STACK, 0, 0, 64, 0),
          member(abi::region::STACK, 0, 16, 0),
          none_entry(),
        ],
      ),
      (
        "leader claims a zero-byte window",
        two_access_group(0, 8),
        vec![
          leader(abi::region::STACK, 0, 0, 0, 0),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        "leader claims a window wider than a page",
        two_access_group(0, 8),
        vec![
          leader(abi::region::STACK, 0, 0, abi::MAX_GROUP_SPAN + 1, 0),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        "leader claims the unchecked frame region",
        two_access_group(0, 8),
        vec![
          leader(abi::region::FRAME, 0, 0, 16, 0),
          member(abi::region::FRAME, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        "leader low bound disagrees with its own offset",
        two_access_group(0, 8),
        vec![
          leader(abi::region::STACK, 32, 0, 64, 0),
          member(abi::region::STACK, 32, 8, 0),
          none_entry(),
        ],
      ),
      (
        "leader low bound is out of the offset field's range",
        two_access_group(0, 8),
        vec![
          leader(abi::region::STACK, -40000, 40000, 64, 0),
          member(abi::region::STACK, -40000, 40008, 0),
          none_entry(),
        ],
      ),
      (
        // The base register is redefined by the leader itself.
        "member addresses a base the leader overwrote",
        vec![
          insn(cls::LDX | mode::MEM | size::DW, 2, 2, 0, 0),
          insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
          exit(),
        ],
        vec![
          leader(abi::region::STACK, 0, 0, 16, 0),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        // An unconditional jump lands between the two, so the member could be
        // reached without the leader having run.
        "a branch can land between leader and member",
        vec![
          insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
          insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
          insn(opcode::JA, 0, 0, -2, 0),
          exit(),
        ],
        vec![
          leader(abi::region::STACK, 0, 0, 16, 0),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
          none_entry(),
        ],
      ),
      (
        // A call clobbers r0-r5 and shares the host frame, so the parked base
        // does not survive it.
        "a call sits between leader and member",
        vec![
          insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
          insn(opcode::CALL, 0, 0, 0, 0),
          insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
          exit(),
        ],
        vec![
          leader(abi::region::STACK, 0, 0, 16, 0),
          none_entry(),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        "a store member against the data region",
        vec![
          insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
          insn(cls::STX | mode::MEM | size::DW, 2, 3, 8, 0),
          exit(),
        ],
        vec![
          leader(abi::region::DATA, 0, 0, 16, 0),
          member(abi::region::DATA, 0, 8, 0),
          none_entry(),
        ],
      ),
    ];

    for (what, insns, plan) in cases {
      check_with(
        what,
        &insns,
        &TranslationInputs {
          plan: &plan,
          ..plain_inputs(insns.len())
        },
      );
    }
  }

  #[test]
  fn a_plan_shorter_than_the_program_covers_only_what_it_names() {
    let insns = two_access_group(0, 8);
    let plan = [leader(abi::region::STACK, 0, 0, 16, 0)];
    check_with(
      "short plan",
      &insns,
      &TranslationInputs {
        plan: &plan,
        ..plain_inputs(insns.len())
      },
    );
  }

  #[test]
  fn a_group_survives_a_local_function_boundary_check() {
    // pc 1 begins a local function, so it is a barrier even though nothing
    // branches to it inside the range.
    let insns = vec![
      insn(opcode::CALL, 0, 1, 0, 1),
      exit(),
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
      insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
      exit(),
    ];
    let plan = vec![
      none_entry(),
      none_entry(),
      leader(abi::region::STACK, 0, 0, 16, 2),
      member(abi::region::STACK, 0, 8, 2),
      none_entry(),
    ];
    let ids = [1u32; 5];
    for (start, end) in [(0usize, 2usize), (2, 5)] {
      check_with(
        &format!("group across the function boundary {start}..{end}"),
        &insns,
        &TranslationInputs {
          plan: &plan,
          resolver_ids: &ids,
          start_pc: start,
          end_pc: end,
          ..Default::default()
        },
      );
    }
  }

  // -------------------------------------------------------------------------
  // Relocation range
  // -------------------------------------------------------------------------

  /// Filler whose emitted size is large and identical per instruction, so a
  /// branch over `n` of them grows linearly and the ±1 MiB conditional-branch
  /// boundary can be straddled within the 65536-instruction program limit.
  fn filler() -> Insn {
    insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0)
  }

  fn rust_len(config: &crate::jit::Config, insns: &[Insn]) -> usize {
    let code = Insn::encode_all(insns);
    let t = Translator::load(std::sync::Arc::new(config.clone()), &code).unwrap();
    let mut buf = vec![0u8; 8 << 20];
    t.translate_range(&plain_inputs(insns.len()), &mut buf)
      .expect("the probe must translate")
  }

  /// The raw outcome of one translation, for tests that classify a *failure*
  /// rather than only pinning it.
  fn outcome(
    config: &Config,
    code: &[u8],
    inputs: &TranslationInputs<'_>,
    capacity: usize,
  ) -> Result<Vec<u8>, TranslateError> {
    let t =
      Translator::load(std::sync::Arc::new(config.clone()), code).expect("the program must load");
    let mut buf = vec![0u8; capacity];
    t.translate_range(inputs, &mut buf).map(|len| {
      buf.truncate(len);
      buf
    })
  }

  /// Grows a branch span across a reach boundary, requiring the sweep to
  /// straddle it: some sizes must fit and some must be refused as out of range.
  /// The golden pins each outcome; this pins that the *boundary itself* is
  /// still where the test believes it is, which a golden alone cannot say.
  #[track_caller]
  fn straddle(
    what: &str,
    config: &Config,
    range: std::ops::RangeInclusive<usize>,
    build: impl Fn(usize) -> Vec<Insn>,
  ) {
    let capacity = (1 << 21) + (1 << 16);
    let mut saw_success = false;
    let mut saw_out_of_range = false;
    for n in range {
      let insns = build(n);
      let code = Insn::encode_all(&insns);
      let inputs = plain_inputs(insns.len());
      golden_case(&format!("{what} n={n}"), config, &code, &inputs, capacity);
      match outcome(config, &code, &inputs, capacity) {
        Ok(_) => saw_success = true,
        Err(TranslateError::Failed(msg)) if msg.starts_with("Branch or load") => {
          saw_out_of_range = true
        }
        other => panic!("{what}: n = {n} failed unexpectedly: {other:?}"),
      }
    }
    assert!(
      saw_success,
      "{what}: never fitted; the boundary was not straddled"
    );
    assert!(
      saw_out_of_range,
      "{what}: never overflowed; the boundary was not straddled"
    );
  }

  /// `jeq r1, 0, +n; <n fillers>; exit`
  fn long_forward_branch(n: usize) -> Vec<Insn> {
    let mut p = vec![insn(cls::JMP | srcbit::IMM | jmp::JEQ, 1, 0, n as i16, 0)];
    p.extend(std::iter::repeat(filler()).take(n));
    p.push(exit());
    p
  }

  #[test]
  fn a_conditional_branch_straddling_one_mebibyte_is_pinned_either_side() {
    // A conditional branch carries a signed 19-bit word displacement, so it
    // reaches +-1 MiB. Grow the span across that boundary and require both the
    // success and the refusal to be pinned.
    let (_, config) = config_sweep(Target::Aarch64)
      .into_iter()
      .find(|(name, _)| *name == "cage only")
      .unwrap();

    let per = (rust_len(&config, &long_forward_branch(200))
      - rust_len(&config, &long_forward_branch(100)))
      / 100;
    assert!(per > 0, "the filler must grow the output");
    let boundary = (1 << 20) / per;

    straddle(
      "conditional branch at 1 MiB",
      &config,
      boundary - 2..=boundary + 2,
      long_forward_branch,
    );
  }

  #[test]
  fn a_literal_load_straddling_one_mebibyte_is_pinned_either_side() {
    // The dispatcher address and the helper table are parked after all the
    // code, and a helper call reaches them with an LDR (literal) and an ADR -
    // both signed 19-bit, so both stop reaching at 1 MiB.
    let (_, config) = config_sweep(Target::Aarch64)
      .into_iter()
      .find(|(name, _)| *name == "cage only")
      .unwrap();

    let build = |n: usize| {
      // `call 0` is not the unwind index in any sweep configuration, so no
      // long branch to the epilogue competes with the literal load.
      let mut p = vec![insn(opcode::CALL, 0, 0, 0, 0)];
      p.extend(std::iter::repeat(filler()).take(n));
      p.push(exit());
      p
    };

    let per = (rust_len(&config, &build(200)) - rust_len(&config, &build(100))) / 100;
    let boundary = (1 << 20) / per;

    straddle(
      "literal load at 1 MiB",
      &config,
      boundary - 2..=boundary + 2,
      build,
    );
  }

  // -------------------------------------------------------------------------
  // Store immediates
  // -------------------------------------------------------------------------

  /// The immediate a store materialises has to be built at the access width, so
  /// a negative one reaches memory sign-extended. Asserted on the encoding
  /// rather than left to the goldens, which would only say that *something*
  /// moved.
  #[test]
  fn a_negative_store_immediate_is_built_at_the_access_width() {
    // Bit 31 of a move-wide is `sf`: set for an X-register destination, clear
    // for a W one. A W destination zero-extends, which is what silently turned
    // `stdw [r1+0], -1` into a store of 0x00000000ffffffff.
    const SF: u32 = 1 << 31;
    // A move-wide into TEMP_STORE_VALUE_REGISTER, which is where a lowered `st`
    // parks its immediate. Keying on the destination keeps the prologue's own
    // move-wides out of the assertion.
    let move_wide_into_store_value =
      |word: u32| word & 0x1f80_0000 == 0x1280_0000 && word & 0x1f == TEMP_STORE_VALUE_REGISTER;

    for (label, sz, want_wide) in [
      ("stdw", size::DW, true),
      ("stw", size::W, false),
      ("sth", size::H, false),
      ("stb", size::B, false),
    ] {
      let program = vec![insn(cls::ST | mode::MEM | sz, 1, 0, 0, -1), exit()];
      let code = Insn::encode_all(&program);
      let (_, config) = config_sweep(Target::Aarch64)
        .into_iter()
        .find(|(name, _)| *name == "no cage")
        .expect("the sweep always includes an uncaged configuration");
      let out =
        crate::jit::golden::translate_one(&config, &code, &plain_inputs(program.len()), 262144)
          .expect("the program loads")
          .expect("the program translates");

      let moves: Vec<u32> = out
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
        .filter(|&w| move_wide_into_store_value(w))
        .collect();
      assert!(
        !moves.is_empty(),
        "{label} materialised no immediate at all"
      );
      for word in moves {
        assert_eq!(
          word & SF != 0,
          want_wide,
          "{label} built its immediate at the wrong width ({word:08x})"
        );
      }
    }
  }

  #[test]
  fn store_immediates_are_sign_extended_at_the_access_width() {
    // A `st` is lowered to a `stx` through TEMP_STORE_VALUE_REGISTER. `stdw`
    // materialises its immediate in an X register so the sign extension
    // survives; the narrower widths stay in a W register, since they discard
    // everything above their access width anyway.
    //
    // This used to build every store immediate at 32 bits, inherited from the C
    // runtime this backend was ported from, which made `stdw [r1+0], -1` store
    // 0x00000000ffffffff here and 0xffffffffffffffff on x86_64.
    let mut program = Vec::new();
    for sz in [size::B, size::H, size::W, size::DW] {
      for imm in [0i32, 1, -1, 0xffff, 0x1_0000, i32::MIN, 0x1234_5678] {
        program.push(insn(cls::ST | mode::MEM | sz, 1, 0, 0, imm));
        program.push(insn(cls::ST | mode::MEM | sz, 10, 0, -8, imm));
      }
    }
    program.push(exit());
    check("store immediates", &program);
  }

  #[test]
  fn an_atomic_between_leader_and_member_closes_the_group() {
    // An atomic with FETCH writes its source register and r0, so a group based
    // on either does not survive it.
    let insns = vec![
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
      insn(
        opcode::ATOMIC_STORE,
        3,
        2,
        0,
        alu::ADD as i32 | atomic::OP_FETCH,
      ),
      insn(cls::LDX | mode::MEM | size::DW, 4, 2, 8, 0),
      exit(),
    ];
    let plan = vec![
      leader(abi::region::STACK, 0, 0, 16, 0),
      none_entry(),
      member(abi::region::STACK, 0, 8, 0),
      none_entry(),
    ];
    check_with(
      "atomic between leader and member",
      &insns,
      &TranslationInputs {
        plan: &plan,
        ..plain_inputs(insns.len())
      },
    );
  }

  // -------------------------------------------------------------------------
  // Randomised programs
  // -------------------------------------------------------------------------

  fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
      .ok()
      .and_then(|v| v.parse().ok())
      .unwrap_or(default)
  }

  /// A deterministic xorshift, so a failure reproduces from the seed alone.
  struct Rng(u64);

  impl Rng {
    fn next(&mut self) -> u64 {
      self.0 ^= self.0 << 13;
      self.0 ^= self.0 >> 7;
      self.0 ^= self.0 << 17;
      self.0
    }
    fn below(&mut self, n: usize) -> usize {
      (self.next() % n as u64) as usize
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
      xs[self.below(xs.len())]
    }
  }

  const RANDOM_IMMS: [i32; 10] = [
    0,
    1,
    -1,
    7,
    0xfff,
    0x1000,
    0xffff,
    0x1234_5678,
    i32::MIN,
    i32::MAX,
  ];
  const RANDOM_OFFSETS: [i16; 10] = [0, 1, -1, 8, 255, 256, -256, -257, 4095, -4096];

  /// One random instruction, kept inside what the loader accepts so that most
  /// generated programs actually translate. Jumps are emitted with a zero
  /// offset and retargeted once the program's instruction boundaries are known.
  fn random_insn(rng: &mut Rng) -> Insn {
    let dst = rng.below(10) as u8;
    let src = rng.below(11) as u8;
    let imm = rng.pick(&RANDOM_IMMS);
    let offset = rng.pick(&RANDOM_OFFSETS);
    match rng.below(9) {
      0 => {
        let class = rng.pick(&[cls::ALU, cls::ALU64]);
        let op = rng.pick(&ALU_OPS);
        let source = rng.pick(&[srcbit::IMM, srcbit::REG]);
        // A shift immediate has to be smaller than the operand width; an
        // immediate form carries no source register, and a register form
        // carries no immediate.
        let imm = if source == srcbit::REG {
          0
        } else if matches!(op, alu::LSH | alu::RSH | alu::ARSH) {
          rng.below(if class == cls::ALU64 { 64 } else { 32 }) as i32
        } else {
          imm
        };
        Insn {
          opcode: class | source | op,
          dst,
          src: if source == srcbit::IMM { 0 } else { src },
          offset: 0,
          imm,
        }
      }
      1 => insn(rng.pick(&[cls::ALU, cls::ALU64]) | alu::NEG, dst, 0, 0, 0),
      2 => insn(
        rng.pick(&[opcode::LE, opcode::BE, opcode::BSWAP]),
        dst,
        0,
        0,
        rng.pick(&[16i32, 32, 64]),
      ),
      3 => {
        let width = rng.pick(&[size::B, size::H, size::W, size::DW]);
        let mode = if width == size::DW {
          mode::MEM
        } else {
          rng.pick(&[mode::MEM, mode::MEMSX])
        };
        insn(cls::LDX | mode | width, dst, src, offset, 0)
      }
      4 => {
        let width = rng.pick(&[size::B, size::H, size::W, size::DW]);
        if rng.below(2) == 0 {
          insn(
            cls::ST | mode::MEM | width,
            rng.below(11) as u8,
            0,
            offset,
            imm,
          )
        } else {
          insn(
            cls::STX | mode::MEM | width,
            rng.below(11) as u8,
            src,
            offset,
            0,
          )
        }
      }
      5 => {
        let class = rng.pick(&[cls::JMP, cls::JMP32]);
        let op = rng.pick(&JMP_OPS);
        let source = rng.pick(&[srcbit::IMM, srcbit::REG]);
        insn(
          class | source | op,
          dst,
          if source == srcbit::IMM { 0 } else { src },
          0,
          if source == srcbit::IMM { imm } else { 0 },
        )
      }
      6 => {
        // Only the canonical ten load at doubleword width; the 32-bit filter
        // takes anything in 0..=255, so the non-canonical selectors below are
        // reachable there and must agree too.
        let canonical = [
          alu::ADD as i32,
          alu::ADD as i32 | atomic::OP_FETCH,
          alu::OR as i32,
          alu::OR as i32 | atomic::OP_FETCH,
          alu::AND as i32,
          alu::AND as i32 | atomic::OP_FETCH,
          alu::XOR as i32,
          alu::XOR as i32 | atomic::OP_FETCH,
          atomic::OP_XCHG,
          atomic::OP_CMPXCHG,
        ];
        let (width, imm) = if rng.below(2) == 0 {
          (opcode::ATOMIC_STORE, rng.pick(&canonical))
        } else {
          let imm = if rng.below(2) == 0 {
            rng.pick(&canonical)
          } else {
            rng.pick(&[0x02i32, 0x0f, 0x0e, 0x4f, 0x5e, 0xa2, 0xe1, 0xf1, 0xff])
          };
          (opcode::ATOMIC32_STORE, imm)
        };
        insn(width, rng.below(11) as u8, rng.below(10) as u8, offset, imm)
      }
      7 => insn(opcode::CALL, 0, 0, 0, rng.below(64) as i32),
      _ => insn(cls::ALU64 | srcbit::REG | alu::MOV, dst, src, 0, 0),
    }
  }

  fn is_conditional_jump(insn: &Insn) -> bool {
    let class = insn.opcode & cls::MASK;
    (class == cls::JMP || class == cls::JMP32)
      && insn.opcode != opcode::CALL
      && insn.opcode != opcode::EXIT
      && insn.opcode & jmp::MASK != jmp::JA
  }

  /// `FUZZ_SEED` and `FUZZ_N` crank this up without editing it; the defaults
  /// keep the suite fast. It has been run at 1500 programs across five seeds -
  /// 45,000 differential translations - with no disagreement.
  #[test]
  fn randomised_programs_with_random_hints_and_plans_are_pinned() {
    const SEED: u64 = 0x2545_f491_4f6c_dd1d;
    const COUNT: usize = 400;
    let seed = env_u64("FUZZ_SEED", SEED);
    let count = env_u64("FUZZ_N", COUNT as u64) as usize;
    let mut rng = Rng(seed);
    let mut digest = SweepDigest::new();
    for _ in 0..count {
      let len = 4 + rng.below(24);

      // `is_start` marks the slots a jump may target: an `lddw`'s second slot
      // is not an instruction.
      let mut program: Vec<Insn> = Vec::with_capacity(len);
      let mut is_start: Vec<bool> = Vec::with_capacity(len);
      let mut jump_sites: Vec<usize> = Vec::new();
      while program.len() < len - 1 {
        if len - 1 - program.len() >= 2 && rng.below(12) == 0 {
          program.push(insn(
            opcode::LDDW,
            rng.below(10) as u8,
            0,
            0,
            rng.pick(&RANDOM_IMMS),
          ));
          is_start.push(true);
          program.push(insn(0, 0, 0, 0, rng.pick(&RANDOM_IMMS)));
          is_start.push(false);
          continue;
        }
        let next = random_insn(&mut rng);
        if is_conditional_jump(&next) {
          jump_sites.push(program.len());
        }
        program.push(next);
        is_start.push(true);
      }
      program.push(exit());
      is_start.push(true);

      for site in jump_sites {
        let candidates: Vec<usize> = (site + 1..program.len()).filter(|&p| is_start[p]).collect();
        let target = rng.pick(&candidates);
        program[site].offset = (target - site - 1) as i16;
      }

      let hints: Vec<u8> = (0..program.len()).map(|_| rng.below(4) as u8).collect();
      let plan: Vec<PlanEntry> = (0..program.len())
        .map(|_| PlanEntry {
          role: rng.below(3) as u8,
          region: rng.below(4) as u8,
          delta: rng.pick(&[0u16, 4, 8, 255, 256, 300, 4095]),
          span: rng.pick(&[0u32, 8, 16, 4096, 4097, 100_000]),
          lo: rng.pick(&[0i32, 8, -8, 255, -40000]),
          leader_pc: rng.below(program.len() + 2) as u32,
        })
        .collect();

      let inputs = TranslationInputs {
        hints: &hints,
        plan: &plan,
        resolver_ids: &[],
        start_pc: 0,
        end_pc: program.len(),
      };
      let code = Insn::encode_all(&program);
      for (_, config) in config_sweep(Target::Aarch64) {
        sweep_case(&mut digest, &config, &code, &inputs, 262144);
      }
    }
    // A run in which nothing translated would prove nothing.
    let translated = digest.translated();
    assert!(
      translated * 10 > 2000,
      "only {translated} randomised translations produced code"
    );
    // A run cranked up through the environment explores a different corner of
    // the space and has no golden of its own; only the default sweep is pinned.
    if (seed, count) == (SEED, COUNT) {
      finish_sweep(digest, "randomised-programs");
    }
  }

  #[test]
  fn randomised_multi_function_programs_translate_a_function_at_a_time() {
    // The runtime never translates a whole program: it compiles one local
    // function at a time and resolves the calls between them lazily. This is
    // that shape - several functions, calls into each of them, and each range
    // translated on its own.
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut digest = SweepDigest::new();

    for _ in 0..150 {
      let functions = 2 + rng.below(3);
      let mut bounds = vec![0usize];
      let mut program: Vec<Insn> = Vec::new();

      // Function 0 calls every other function, so each one really is an entry.
      // The call sites are filled in once the boundaries are known.
      let call_sites: Vec<usize> = (0..functions - 1).map(|k| k).collect();
      for _ in &call_sites {
        program.push(insn(opcode::CALL, 0, 1, 0, 0));
      }
      for _ in 0..rng.below(4) {
        program.push(random_insn(&mut rng));
      }
      program.push(exit());

      for _ in 1..functions {
        bounds.push(program.len());
        let body = rng.below(5);
        for _ in 0..body {
          let next = random_insn(&mut rng);
          // Keep conditional jumps inside their own function.
          program.push(if is_conditional_jump(&next) {
            Insn { offset: 0, ..next }
          } else {
            next
          });
        }
        program.push(exit());
      }
      bounds.push(program.len());

      for (k, &site) in call_sites.iter().enumerate() {
        program[site].imm = (bounds[k + 1] as i64 - site as i64 - 1) as i32;
      }

      let ids: Vec<u32> = (0..program.len()).map(|_| rng.next() as u32).collect();
      let code = Insn::encode_all(&program);

      for w in 0..bounds.len() - 1 {
        let inputs = TranslationInputs {
          hints: &[],
          plan: &[],
          resolver_ids: &ids,
          start_pc: bounds[w],
          end_pc: bounds[w + 1],
        };
        for (_, config) in config_sweep(Target::Aarch64) {
          sweep_case(&mut digest, &config, &code, &inputs, 262144);
        }
      }
    }
    let translated = digest.translated();
    assert!(translated > 1000, "only {translated} ranges produced code");
    finish_sweep(digest, "randomised-multi-function-programs");
  }

  // -------------------------------------------------------------------------
  // Capacity
  // -------------------------------------------------------------------------

  #[test]
  fn running_out_of_space_is_reported_as_recorded() {
    let code = Insn::encode_all(&[insn(0xb7, 0, 0, 0, 42), exit()]);
    for (name, config) in config_sweep(Target::Aarch64) {
      for capacity in [0usize, 4, 8, 64, 128, 512] {
        golden_case(
          &format!("out of space/{name}/cap {capacity}"),
          &config,
          &code,
          &plain_inputs(2),
          capacity,
        );
      }
    }
  }

  // -------------------------------------------------------------------------
  // AUDIT: probes added by the adversarial audit.
  // -------------------------------------------------------------------------

  /// AUDIT: a small buffer combined with a *rejected* program. This shape
  /// passes; the one that does not is
  /// `audit_a_full_buffer_masks_a_later_error` below.
  #[test]
  fn audit_capacity_sweep_with_an_escaping_jump() {
    // NOTE: this program is refused by `validate` (a jump may not leave its own
    // sub-program), so the backend's own translation-range guard is never
    // reached through the loader - it is defence in depth only.
    let insns = vec![
      insn(opcode::CALL, 0, 1, 0, 1),
      exit(),
      insn(cls::JMP | srcbit::REG | jmp::JEQ, 1, 10, -3, 0),
      exit(),
    ];
    let ids = [5u32; 4];
    let code = Insn::encode_all(&insns);
    let inputs = TranslationInputs {
      resolver_ids: &ids,
      start_pc: 2,
      end_pc: 4,
      ..Default::default()
    };
    let mut digest = SweepDigest::new();
    for (_, config) in config_sweep(Target::Aarch64) {
      for capacity in 0usize..64 {
        sweep_case(&mut digest, &config, &code, &inputs, capacity);
      }
    }
    assert_eq!(digest.cases(), 64 * 6);
    finish_sweep(digest, "audit-escaping-jump-capacity");
  }

  /// AUDIT FINDING 1: which failure survives when two happen at once.
  /// `JitState::fail` keeps the *first* failure. So when the per-function
  /// prologue overruns the buffer (`NotEnoughSpace`) and the very same
  /// instruction then hits an error arm, what comes out is `OutOfSpace` and not
  /// the instruction error. The two are not interchangeable: the caller's code
  /// arena treats `OutOfSpace` as terminal for the whole program and a `Failed`
  /// as terminal for one function, so which one wins decides whether the rest
  /// of the program is still compiled.
  /// Reachable through the loader: pc2 is a local function entry (the target of
  /// the call at pc0) *and* a local call with no resolver id, so the guard in
  /// `emit_lazy_local_call` fires after the prologue has already been emitted.
  /// Every buffer size either side of that point is recorded.
  #[test]
  fn audit_a_full_buffer_masks_a_later_error() {
    let insns = vec![
      insn(opcode::CALL, 0, 1, 0, 1),
      exit(),
      insn(opcode::CALL, 0, 1, 0, -3),
      exit(),
    ];
    let code = Insn::encode_all(&insns);
    let inputs = TranslationInputs {
      start_pc: 2,
      end_pc: 4,
      ..Default::default()
    };
    let mut digest = SweepDigest::new();
    for (_, config) in config_sweep(Target::Aarch64) {
      for capacity in 0usize..=64 {
        sweep_case(&mut digest, &config, &code, &inputs, capacity);
      }
    }
    assert_eq!(digest.cases(), 65 * 6);
    finish_sweep(digest, "audit-full-buffer-masks-a-later-error");
  }

  /// AUDIT: fold one probe into the batch's rolling digest.
  /// These batches enumerate hundreds of shapes apiece, so they are recorded as
  /// one digest per batch rather than one entry per case: the whole batch stays
  /// a single reviewable line, at the cost of saying only *that* something
  /// changed rather than which shape.
  fn audit_case(
    digest: &mut SweepDigest,
    what: &str,
    insns: &[Insn],
    inputs: &TranslationInputs<'_>,
  ) {
    let code = Insn::encode_all(insns);
    let capacity = 262144.max(insns.len() * 512);
    let _ = what;
    for (_, config) in config_sweep(Target::Aarch64) {
      sweep_case(digest, &config, &code, inputs, capacity);
    }
  }

  #[test]
  fn audit_probe_batch() {
    let mut digest = SweepDigest::new();

    // --- B: extreme load/store offsets -------------------------------------
    for &off in &[
      i16::MIN,
      -32767,
      -4097,
      -4096,
      -4095,
      -257,
      -256,
      -255,
      -1,
      0,
      1,
      255,
      256,
      257,
      4095,
      4096,
      4097,
      32766,
      i16::MAX,
    ] {
      let mut p = Vec::new();
      for sz in [size::B, size::H, size::W, size::DW] {
        p.push(insn(cls::LDX | mode::MEM | sz, 1, 2, off, 0));
        p.push(insn(cls::STX | mode::MEM | sz, 1, 2, off, 0));
        p.push(insn(cls::ST | mode::MEM | sz, 1, 0, off, 0x1234));
        p.push(insn(cls::LDX | mode::MEM | sz, 1, 10, off, 0));
        p.push(insn(cls::STX | mode::MEM | sz, 10, 1, off, 0));
      }
      for sz in [size::B, size::H, size::W] {
        p.push(insn(cls::LDX | mode::MEMSX | sz, 1, 2, off, 0));
      }
      p.push(exit());
      let n = p.len();
      for hint in [0u8, 1, 2, 3] {
        let hints = vec![hint; n];
        audit_case(
          &mut digest,
          &format!("offset {off} hint {hint}"),
          &p,
          &TranslationInputs {
            hints: &hints,
            ..plain_inputs(n)
          },
        );
      }
    }

    // --- I: extreme atomic offsets -----------------------------------------
    for &off in &[i16::MIN, -4096, -256, -1, 0, 4095, 4096, i16::MAX] {
      let mut p = Vec::new();
      for op in [opcode::ATOMIC32_STORE, opcode::ATOMIC_STORE] {
        for imm in [
          alu::ADD as i32,
          alu::ADD as i32 | atomic::OP_FETCH,
          atomic::OP_XCHG,
          atomic::OP_CMPXCHG,
        ] {
          p.push(insn(op, 1, 2, off, imm));
        }
      }
      p.push(exit());
      let n = p.len();
      audit_case(
        &mut digest,
        &format!("atomic offset {off}"),
        &p,
        &plain_inputs(n),
      );
    }

    // --- D: call immediates outside 0..64 ----------------------------------
    for &idx in &[-1i32, i32::MIN, i32::MAX, 64, 65, 1000, 0x7fff_ffff] {
      let p = vec![insn(opcode::CALL, 0, 0, 0, idx), exit()];
      audit_case(
        &mut digest,
        &format!("call imm {idx}"),
        &p,
        &plain_inputs(2),
      );
    }

    // --- F: region hints outside 0..=3 -------------------------------------
    for &hint in &[4u8, 5, 100, 255] {
      let p = vec![
        insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
        insn(cls::LDX | mode::MEM | size::DW, 1, 10, -8, 0),
        insn(cls::STX | mode::MEM | size::DW, 10, 1, -8, 0),
        exit(),
      ];
      let hints = vec![hint; 4];
      audit_case(
        &mut digest,
        &format!("hint {hint}"),
        &p,
        &TranslationInputs {
          hints: &hints,
          ..plain_inputs(4)
        },
      );
    }

    finish_sweep(digest, "audit-probe-batch");
  }

  /// AUDIT: the existing fuzzer draws offsets, plan deltas, spans, lo bounds
  /// and leader_pcs from small hand-picked sets. This one draws from the whole
  /// domain of each field, including the values a hostile embedder could pass.
  #[test]
  fn audit_wide_randomised_plans_and_offsets() {
    const SEED: u64 = 0xdead_beef_1234_5678;
    const COUNT: usize = 500;
    let seed = env_u64("AUDIT_SEED", SEED);
    let count = env_u64("AUDIT_N", COUNT as u64) as usize;
    let mut rng = Rng(seed);
    let mut digest = SweepDigest::new();

    const WIDE_OFFSETS: [i16; 16] = [
      i16::MIN,
      -32767,
      -4097,
      -4096,
      -4095,
      -257,
      -256,
      -255,
      -1,
      0,
      1,
      255,
      256,
      4095,
      4096,
      i16::MAX,
    ];

    for _ in 0..count {
      let len = 3 + rng.below(10);
      let mut program: Vec<Insn> = Vec::new();
      while program.len() < len - 1 {
        let mut next = random_insn(&mut rng);
        if is_conditional_jump(&next) {
          next.offset = 0;
        }
        // Widen the offsets the memory instructions carry.
        let class = next.opcode & cls::MASK;
        if class == cls::LDX || class == cls::STX || class == cls::ST {
          next.offset = rng.pick(&WIDE_OFFSETS);
        }
        program.push(next);
      }
      program.push(exit());
      let n = program.len();

      let hints: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
      let plan: Vec<PlanEntry> = (0..n)
        .map(|_| PlanEntry {
          role: if rng.below(4) == 0 {
            rng.next() as u8
          } else {
            rng.below(3) as u8
          },
          region: if rng.below(4) == 0 {
            rng.next() as u8
          } else {
            rng.below(4) as u8
          },
          delta: if rng.below(3) == 0 {
            rng.next() as u16
          } else {
            rng.pick(&[0u16, 1, 4, 8, 255, 256, 4088, 4095, 4096])
          },
          span: if rng.below(3) == 0 {
            rng.next() as u32
          } else {
            rng.pick(&[0u32, 1, 2, 3, 4, 8, 9, 16, 4095, 4096, 4097, u32::MAX])
          },
          lo: if rng.below(3) == 0 {
            rng.next() as i32
          } else {
            rng.pick(&[
              0i32,
              8,
              -8,
              255,
              -32768,
              32767,
              -32769,
              32768,
              i32::MIN,
              i32::MAX,
            ])
          },
          leader_pc: if rng.below(3) == 0 {
            rng.next() as u32
          } else {
            rng.below(n + 2) as u32
          },
        })
        .collect();

      let inputs = TranslationInputs {
        hints: &hints,
        plan: &plan,
        resolver_ids: &[],
        start_pc: 0,
        end_pc: n,
      };
      let code = Insn::encode_all(&program);
      for (_, config) in config_sweep(Target::Aarch64) {
        sweep_case(&mut digest, &config, &code, &inputs, 262144);
      }
    }
    let translated = digest.translated();
    assert!(
      translated > 100,
      "only {translated} translations produced code"
    );
    if (seed, count) == (SEED, COUNT) {
      finish_sweep(digest, "audit-wide-randomised-plans");
    }
  }

  /// AUDIT: well-formed groups at every boundary of span/delta/lo/width.
  #[test]
  fn audit_group_boundaries() {
    let mut digest = SweepDigest::new();

    let widths = [(size::B, 1i32), (size::H, 2), (size::W, 4), (size::DW, 8)];

    // span exactly equal to the width (the precomputed-span slots), and spans
    // that are not one of 1/2/4/8 (the narrowed width-1 span).
    for (szbits, w) in widths {
      for span in [w as u32, w as u32 + 1, 3, 5, 8, 9, 16, 255, 256, 4095, 4096] {
        if span < w as u32 {
          continue;
        }
        for lo in [0i32, 8, -8, -32768, 32767 - 4096] {
          let deltas: Vec<u32> = vec![0, 255, 256, span.saturating_sub(w as u32)];
          for d in deltas {
            if d + w as u32 > span {
              continue;
            }
            let second = lo as i64 + d as i64;
            if !(i16::MIN as i64..=i16::MAX as i64).contains(&second) {
              continue;
            }
            let insns = vec![
              insn(cls::LDX | mode::MEM | size::DW, 1, 2, lo as i16, 0),
              insn(cls::LDX | mode::MEM | szbits, 3, 2, second as i16, 0),
              exit(),
            ];
            let plan = vec![
              leader(abi::region::STACK, lo, 0, span, 0),
              member(abi::region::STACK, lo, d as u16, 0),
              none_entry(),
            ];
            // The leader's own access must fit its window too, or it is refused
            // - which is itself worth checking, so do not skip it.
            audit_case(
              &mut digest,
              &format!("group span {span} delta {d} lo {lo} width {w}"),
              &insns,
              &TranslationInputs {
                plan: &plan,
                ..plain_inputs(3)
              },
            );
          }
        }
      }
    }
    finish_sweep(digest, "audit-group-boundaries");
  }

  /// AUDIT: plan shapes the existing hostile-plan table does not name.
  #[test]
  fn audit_more_hostile_plans() {
    let mut digest = SweepDigest::new();
    let g = two_access_group(0, 8);

    let cases: Vec<(&str, Vec<PlanEntry>)> = vec![
      (
        "member names itself as leader",
        vec![
          leader(abi::region::STACK, 0, 0, 16, 0),
          member(abi::region::STACK, 0, 8, 1),
          none_entry(),
        ],
      ),
      (
        "member names a leader ahead of it",
        vec![
          leader(abi::region::STACK, 0, 0, 16, 0),
          member(abi::region::STACK, 0, 8, 2),
          none_entry(),
        ],
      ),
      (
        "member names leader_pc u32::MAX",
        vec![
          leader(abi::region::STACK, 0, 0, 16, 0),
          member(abi::region::STACK, 0, 8, u32::MAX),
          none_entry(),
        ],
      ),
      (
        "no leader at all, member names u32::MAX",
        vec![
          none_entry(),
          member(abi::region::STACK, 0, 8, u32::MAX),
          none_entry(),
        ],
      ),
      (
        "leader with role 3",
        vec![
          PlanEntry {
            role: 3,
            ..leader(abi::region::STACK, 0, 0, 16, 0)
          },
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        "member with role 255",
        vec![
          leader(abi::region::STACK, 0, 0, 16, 0),
          PlanEntry {
            role: 255,
            ..member(abi::region::STACK, 0, 8, 0)
          },
          none_entry(),
        ],
      ),
      (
        "leader region 255",
        vec![leader(255, 0, 0, 16, 0), member(255, 0, 8, 0), none_entry()],
      ),
      (
        "leader span u32::MAX",
        vec![
          leader(abi::region::STACK, 0, 0, u32::MAX, 0),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        "leader delta 65535",
        vec![
          PlanEntry {
            delta: 65535,
            ..leader(abi::region::STACK, 0, 0, 4096, 0)
          },
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        "member delta 65535",
        vec![
          leader(abi::region::STACK, 0, 0, 4096, 0),
          PlanEntry {
            delta: 65535,
            ..member(abi::region::STACK, 0, 8, 0)
          },
          none_entry(),
        ],
      ),
      (
        "leader lo i32::MIN",
        vec![
          leader(abi::region::STACK, i32::MIN, 0, 16, 0),
          member(abi::region::STACK, i32::MIN, 8, 0),
          none_entry(),
        ],
      ),
      (
        "leader lo i32::MAX",
        vec![
          leader(abi::region::STACK, i32::MAX, 0, 16, 0),
          member(abi::region::STACK, i32::MAX, 8, 0),
          none_entry(),
        ],
      ),
      (
        "leader lo 32768, one past the offset field",
        vec![
          leader(abi::region::STACK, 32768, 0, 16, 0),
          member(abi::region::STACK, 32768, 8, 0),
          none_entry(),
        ],
      ),
      (
        "leader lo -32769, one past the offset field",
        vec![
          leader(abi::region::STACK, -32769, 0, 16, 0),
          member(abi::region::STACK, -32769, 8, 0),
          none_entry(),
        ],
      ),
      (
        "leader span exactly MAX_GROUP_SPAN",
        vec![
          leader(abi::region::STACK, 0, 0, abi::MAX_GROUP_SPAN, 0),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        "member reaches exactly to the end of the window",
        vec![
          leader(abi::region::STACK, 0, 0, 16, 0),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
      (
        "member one byte past the window",
        vec![
          leader(abi::region::STACK, 0, 0, 15, 0),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ],
      ),
    ];

    for (what, plan) in cases {
      for hint in [0u8, 1, 2, 3] {
        let hints = vec![hint; g.len()];
        audit_case(
          &mut digest,
          &format!("{what} hint {hint}"),
          &g,
          &TranslationInputs {
            plan: &plan,
            hints: &hints,
            ..plain_inputs(g.len())
          },
        );
      }
    }
    finish_sweep(digest, "audit-more-hostile-plans");
  }

  /// AUDIT: a leader whose access is also a frame access, and a group crossing
  /// a `lddw` (whose second slot the loop skips).
  #[test]
  fn audit_group_interactions() {
    let mut digest = SweepDigest::new();

    // The frame fast path preempts the plan entirely.
    {
      let insns = vec![
        insn(cls::LDX | mode::MEM | size::DW, 1, 10, -8, 0),
        insn(cls::LDX | mode::MEM | size::DW, 3, 10, 0, 0),
        exit(),
      ];
      let plan = vec![
        leader(abi::region::STACK, -8, 0, 16, 0),
        member(abi::region::STACK, -8, 8, 0),
        none_entry(),
      ];
      for hint in [0u8, 1, 2, 3] {
        let hints = vec![hint; 3];
        audit_case(
          &mut digest,
          &format!("frame-eligible leader hint {hint}"),
          &insns,
          &TranslationInputs {
            plan: &plan,
            hints: &hints,
            ..plain_inputs(3)
          },
        );
      }
    }

    // A group spanning a `lddw`, whose high half the loop skips.
    {
      let insns = vec![
        insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
        insn(opcode::LDDW, 4, 0, 0, 0x1234_5678),
        insn(0, 0, 0, 0, -1),
        insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
        exit(),
      ];
      for lddw_dst in [4u8, 2u8] {
        let mut insns = insns.clone();
        insns[1].dst = lddw_dst;
        let plan = vec![
          leader(abi::region::STACK, 0, 0, 16, 0),
          none_entry(),
          none_entry(),
          member(abi::region::STACK, 0, 8, 0),
          none_entry(),
        ];
        audit_case(
          &mut digest,
          &format!("group across a lddw writing r{lddw_dst}"),
          &insns,
          &TranslationInputs {
            plan: &plan,
            ..plain_inputs(5)
          },
        );
      }
    }

    // A forward `ja` whose target is the member, so the member is a barrier.
    {
      let insns = vec![
        insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
        insn(opcode::JA, 0, 0, 0, 0),
        insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
        exit(),
      ];
      let plan = vec![
        leader(abi::region::STACK, 0, 0, 16, 0),
        none_entry(),
        member(abi::region::STACK, 0, 8, 0),
        none_entry(),
      ];
      audit_case(
        &mut digest,
        "ja lands on the member",
        &insns,
        &TranslationInputs {
          plan: &plan,
          ..plain_inputs(4)
        },
      );
    }

    // A group whose leader is the last instruction before `exit`.
    {
      let insns = vec![insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0), exit()];
      let plan = vec![leader(abi::region::STACK, 0, 0, 16, 0), none_entry()];
      audit_case(
        &mut digest,
        "leader at the end of the range",
        &insns,
        &TranslationInputs {
          plan: &plan,
          ..plain_inputs(2)
        },
      );
    }

    finish_sweep(digest, "audit-group-interactions");
  }

  /// AUDIT: a local function entry reached by *fall-through*.
  /// The validator requires every sub-program to end with `exit` or to carry an
  /// unconditional jump as its second-to-last instruction - so the instruction
  /// physically before a function entry can still fall through, and the
  /// backend's "jump around the prologue" path is reachable after all. No
  /// existing test reaches it.
  #[test]
  fn audit_fallthrough_into_a_local_function_entry() {
    let mut digest = SweepDigest::new();
    // pc0 calls pc3; pc1 is the unconditional jump that satisfies the
    // validator; pc2 falls through into the function entry at pc3.
    let insns = vec![
      insn(opcode::CALL, 0, 1, 0, 2),
      insn(opcode::JA, 0, 0, -2, 0),
      insn(0xb7, 1, 0, 0, 7),
      insn(0xb7, 2, 0, 0, 9),
      exit(),
    ];
    let ids = [4u32; 5];
    audit_case(
      &mut digest,
      "fallthrough entry, whole program",
      &insns,
      &TranslationInputs {
        resolver_ids: &ids,
        ..plain_inputs(5)
      },
    );
    for (start, end) in [(0usize, 3usize), (3, 5)] {
      audit_case(
        &mut digest,
        &format!("fallthrough entry, range {start}..{end}"),
        &insns,
        &TranslationInputs {
          resolver_ids: &ids,
          start_pc: start,
          end_pc: end,
          ..Default::default()
        },
      );
    }

    // The same shape with a group open across the boundary.
    let plan = vec![
      none_entry(),
      none_entry(),
      leader(abi::region::STACK, 0, 0, 16, 2),
      member(abi::region::STACK, 0, 8, 2),
      none_entry(),
    ];
    let insns2 = vec![
      insn(opcode::CALL, 0, 1, 0, 2),
      insn(opcode::JA, 0, 0, -2, 0),
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
      insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
      exit(),
    ];
    audit_case(
      &mut digest,
      "fallthrough entry with a group across it",
      &insns2,
      &TranslationInputs {
        plan: &plan,
        resolver_ids: &ids,
        ..plain_inputs(5)
      },
    );

    finish_sweep(digest, "audit-fallthrough-entry");
  }

  /// AUDIT: a region-hint array shorter than the program.
  #[test]
  fn audit_short_hint_array() {
    let mut digest = SweepDigest::new();
    let insns = vec![
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
      insn(cls::LDX | mode::MEM | size::W, 1, 10, -8, 0),
      insn(cls::STX | mode::MEM | size::B, 2, 1, -4, 0),
      exit(),
    ];
    for n in 0..=4usize {
      for fill in [0u8, 1, 2, 3] {
        let hints = vec![fill; n];
        audit_case(
          &mut digest,
          &format!("hints len {n} fill {fill}"),
          &insns,
          &TranslationInputs {
            hints: &hints,
            ..plain_inputs(4)
          },
        );
      }
    }
    finish_sweep(digest, "audit-short-hint-array");
  }

  /// AUDIT: the *backward* conditional-branch boundary. The existing test only
  /// straddles it forwards.
  #[test]
  fn audit_a_backward_conditional_branch_straddling_one_mebibyte() {
    let (_, config) = config_sweep(Target::Aarch64)
      .into_iter()
      .find(|(name, _)| *name == "cage only")
      .unwrap();

    // `mov r1, 0; <n fillers>; jeq r1, 0, -(n+1); exit`
    let build = |n: usize| {
      let mut p = vec![insn(0xb7, 1, 0, 0, 0)];
      p.extend(std::iter::repeat(filler()).take(n));
      p.push(insn(
        cls::JMP | srcbit::IMM | jmp::JEQ,
        1,
        0,
        -((n + 1) as i32) as i16,
        0,
      ));
      p.push(exit());
      p
    };

    let per = (rust_len(&config, &build(200)) - rust_len(&config, &build(100))) / 100;
    assert!(per > 0);
    let boundary = (1 << 20) / per;
    assert!(
      boundary + 2 < 32000,
      "the offset field must reach the target"
    );

    straddle(
      "backward conditional branch at 1 MiB",
      &config,
      boundary - 2..=boundary + 2,
      build,
    );
  }

  /// AUDIT: the unwind helper emits a conditional branch to the epilogue, which
  /// sits after all the code - a +-1 MiB reach the existing tests deliberately
  /// avoid exercising ("call 0 is not the unwind index in any configuration").
  #[test]
  fn audit_the_unwind_branch_to_the_epilogue_straddles_one_mebibyte() {
    let (_, config) = config_sweep(Target::Aarch64)
      .into_iter()
      .find(|(name, _)| *name == "production + unwind helper")
      .unwrap();
    assert_eq!(config.unwind_helper_index, Some(3));

    let build = |n: usize| {
      let mut p = vec![insn(opcode::CALL, 0, 0, 0, 3)];
      p.extend(std::iter::repeat(filler()).take(n));
      p.push(exit());
      p
    };

    let per = (rust_len(&config, &build(200)) - rust_len(&config, &build(100))) / 100;
    assert!(per > 0);
    let boundary = (1 << 20) / per;

    straddle(
      "unwind branch to the epilogue at 1 MiB",
      &config,
      boundary - 3..=boundary + 3,
      build,
    );
  }

  /// AUDIT: `is_simple_imm` decides whether an immediate can be folded into the
  /// instruction instead of materialised into a register, and it is written as
  /// a match on class plus operation nibble. The set it is *meant* to name is a
  /// flat list of whole opcode bytes, written out below; a nibble match is a
  /// compression of that list and can easily admit one byte too many.
  /// So enumerate all 256 opcodes against the list and report every byte where
  /// the two differ, together with whether that byte can reach the function at
  /// all — most cannot, because the loader refuses the opcode outright.
  #[test]
  fn audit_is_simple_imm_matches_the_opcode_list_byte_for_byte() {
    /// The opcodes that may carry a folded immediate, one byte at a time.
    /// ADD/SUB take a 12-bit unsigned immediate, and so does the compare a
    /// conditional jump lowers to; everything else has to go through a
    /// register. `mov` is the exception at the end: an immediate move *is* the
    /// materialisation, so it is always "simple".
    fn expected_is_simple_imm(op: u8, imm: i32) -> bool {
      const RANGED: [u8; 24] = [
        0x04, 0x07, 0x14, 0x17, // ADD/SUB IMM, both widths
        0x15, 0x25, 0x35, 0x55, 0x65, 0x75, 0xa5, 0xb5, 0xc5, 0xd5, // JMP  *_IMM
        0x16, 0x26, 0x36, 0x56, 0x66, 0x76, 0xa6, 0xb6, 0xc6, 0xd6, // JMP32 *_IMM
      ];
      if RANGED.contains(&op) {
        return imm >= 0 && imm < 0x1000;
      }
      matches!(op, 0xb4 | 0xb7) // MOV_IMM / MOV64_IMM
    }

    let mut disagree_reachable = Vec::new();
    let mut disagree_gated = Vec::new();
    for op in 0u8..=255 {
      for imm in [-1i32, 0, 0x7ff, 0xfff, 0x1000, i32::MIN, i32::MAX] {
        let i = insn(op, 1, 2, 0, imm);
        let rust = is_simple_imm(&i);
        let expected = expected_is_simple_imm(op, imm);
        if rust == expected {
          continue;
        }
        // The function is only consulted for an instruction `is_imm_op` admits
        // and that is not a bare MOV immediate.
        let consulted = is_imm_op(&i) && !is_mov_imm(op);
        // ...and only for an opcode the ISA actually defines, since anything
        // else is refused at load.
        let defined = Op::from_opcode(op).is_some();
        if consulted && defined {
          disagree_reachable.push((op, imm));
        } else if consulted {
          disagree_gated.push(op);
        }
      }
    }
    disagree_gated.sort_unstable();
    disagree_gated.dedup();
    println!(
      "is_simple_imm: {} consulted-but-undefined opcodes disagree: {:02x?}",
      disagree_gated.len(),
      disagree_gated
    );
    assert!(
      disagree_reachable.is_empty(),
      "is_simple_imm folds an immediate for a defined, consulted opcode that is \
       not on the list — or refuses one that is: {disagree_reachable:02x?}"
    );
  }

  /// AUDIT: the module doc says a `st` whose raw `src` nibble is 10 has the
  /// guest frame pointer materialised over its immediate. Establish whether the
  /// loader can produce such an instruction at all.
  #[test]
  fn audit_a_store_immediate_with_src_ten_is_refused_at_load() {
    for sz in [size::B, size::H, size::W, size::DW] {
      let insns = vec![insn(cls::ST | mode::MEM | sz, 1, 10, 0, 0x1234), exit()];
      let code = Insn::encode_all(&insns);
      for (name, config) in config_sweep(Target::Aarch64) {
        assert!(
          !golden_case(
            &format!("st src=10 width {sz}/{name}"),
            &config,
            &code,
            &plain_inputs(2),
            65536
          ),
          "st src=10 under {name} translated; the loader is expected to refuse it"
        );
      }
    }
  }

  /// AUDIT: `le` with `imm == 64` must emit nothing at all.
  #[test]
  fn audit_le_sixty_four_emits_nothing() {
    let (_, config) = config_sweep(Target::Aarch64)
      .into_iter()
      .find(|(name, _)| *name == "production")
      .unwrap();
    let base = rust_len(&config, &[insn(0xb7, 1, 0, 0, 0), exit()]);
    let with_le = rust_len(
      &config,
      &[
        insn(0xb7, 1, 0, 0, 0),
        insn(opcode::LE, 1, 0, 0, 64),
        exit(),
      ],
    );
    assert_eq!(base, with_le, "le imm=64 emitted {} bytes", with_le - base);

    // ...while `le 16`/`le 32` emit exactly one instruction, and `bswap 64`
    // emits one too.
    for (imm, want) in [(16i32, 4usize), (32, 4)] {
      let n = rust_len(
        &config,
        &[
          insn(0xb7, 1, 0, 0, 0),
          insn(opcode::LE, 1, 0, 0, imm),
          exit(),
        ],
      );
      assert_eq!(n - base, want, "le imm={imm}");
    }
    let n = rust_len(
      &config,
      &[
        insn(0xb7, 1, 0, 0, 0),
        insn(opcode::BSWAP, 1, 0, 0, 64),
        exit(),
      ],
    );
    assert_eq!(n - base, 4, "bswap 64");
  }

  /// AUDIT: multi-function programs translated over ranges that *span several
  /// functions*, with random hints and plans. The existing multi-function
  /// fuzzer always passes empty hints and an empty plan, and always translates
  /// exactly one function per range.
  #[test]
  fn audit_wide_multi_function_ranges_with_plans_and_hints() {
    const SEED: u64 = 0x1357_9bdf_2468_ace0;
    const COUNT: usize = 400;
    let seed = env_u64("AUDIT_SEED", SEED);
    let count = env_u64("AUDIT_N", COUNT as u64) as usize;
    let mut rng = Rng(seed);
    let mut digest = SweepDigest::new();

    for _ in 0..count {
      let functions = 2 + rng.below(4);
      let mut bounds = vec![0usize];
      let mut program: Vec<Insn> = Vec::new();

      let call_sites: Vec<usize> = (0..functions - 1).collect();
      for _ in &call_sites {
        program.push(insn(opcode::CALL, 0, 1, 0, 0));
      }
      for _ in 0..rng.below(5) {
        let next = random_insn(&mut rng);
        program.push(if is_conditional_jump(&next) {
          Insn { offset: 0, ..next }
        } else {
          next
        });
      }
      // Half the time the first function ends with a `ja` two slots from the
      // end, so the next function entry is reached by fall-through too.
      if rng.below(2) == 0 {
        program.push(insn(opcode::JA, 0, 0, -1 - (program.len() as i16), 0));
        program.push(insn(0xb7, 1, 0, 0, 3));
      } else {
        program.push(exit());
      }

      for _ in 1..functions {
        bounds.push(program.len());
        for _ in 0..rng.below(5) {
          let next = random_insn(&mut rng);
          program.push(if is_conditional_jump(&next) {
            Insn { offset: 0, ..next }
          } else {
            next
          });
        }
        program.push(exit());
      }
      bounds.push(program.len());

      for (k, &site) in call_sites.iter().enumerate() {
        program[site].imm = (bounds[k + 1] as i64 - site as i64 - 1) as i32;
      }

      let n = program.len();
      let ids: Vec<u32> = (0..n).map(|_| rng.next() as u32).collect();
      let hints: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
      let plan: Vec<PlanEntry> = (0..n)
        .map(|_| PlanEntry {
          role: rng.below(3) as u8,
          region: rng.below(4) as u8,
          delta: rng.pick(&[0u16, 4, 8, 255, 256, 4088, 4095]),
          span: rng.pick(&[0u32, 1, 2, 4, 8, 16, 4095, 4096, 4097, u32::MAX]),
          lo: rng.pick(&[0i32, 8, -8, 255, -32768, 32767, i32::MIN]),
          leader_pc: rng.below(n + 2) as u32,
        })
        .collect();
      let code = Insn::encode_all(&program);

      // Every legal range: start at a boundary, end at any later boundary.
      for a in 0..bounds.len() - 1 {
        for b in a + 1..bounds.len() {
          let inputs = TranslationInputs {
            hints: &hints,
            plan: &plan,
            resolver_ids: &ids,
            start_pc: bounds[a],
            end_pc: bounds[b],
          };
          for (_, config) in config_sweep(Target::Aarch64) {
            sweep_case(&mut digest, &config, &code, &inputs, 262144);
          }
        }
      }
    }
    let translated = digest.translated();
    assert!(
      translated > 200,
      "only {translated} translations produced code"
    );
    if (seed, count) == (SEED, COUNT) {
      finish_sweep(digest, "audit-wide-multi-function-ranges");
    }
  }

  /// AUDIT FINDING 2 (was: the patch tables grew sixteen times too far).
  /// The jump-fixup table stops growing at [`abi::MAX_INSTS`] entries, the same
  /// ceiling a loaded program's instruction count has, and reports "Too many
  /// jump instructions." past it. The tables in `patch.rs` were once set to
  /// `1 << 20`, which let a program that should have been refused emit a
  /// megabyte of code instead.
  /// A `cmpxchg` emits two jump fixups, so 32769 of them cross the ceiling
  /// while staying well inside the instruction limit — the smallest program
  /// that tells the two ceilings apart. `patch.rs` is shared, so the x86_64
  /// backend is bounded by the same numbers.
  #[test]
  fn audit_the_patch_table_ceilings_hold_at_the_instruction_limit() {
    let (_, config) = config_sweep(Target::Aarch64)
      .into_iter()
      .find(|(name, _)| *name == "no cage")
      .unwrap();

    let build = |n: usize| {
      let mut p: Vec<Insn> =
        std::iter::repeat(insn(opcode::ATOMIC_STORE, 1, 2, 0, atomic::OP_CMPXCHG))
          .take(n)
          .collect();
      p.push(exit());
      p
    };

    // 32768 cmpxchg is exactly 65536 fixups - the last one the ceiling admits.
    // 32769 is one jump past it, and must be refused.
    for (n, fits) in [(32768usize, true), (32769, false)] {
      let insns = build(n);
      let code = Insn::encode_all(&insns);
      let inputs = plain_inputs(insns.len());
      let capacity = 32 << 20;
      assert_eq!(
        golden_case(
          &format!("cmpxchg storm n={n}"),
          &config,
          &code,
          &inputs,
          capacity
        ),
        fits,
        "{n} cmpxchg is {} jump fixups against a ceiling of {}",
        n * 2,
        abi::MAX_INSTS
      );
      if !fits {
        assert_eq!(
          outcome(&config, &code, &inputs, capacity),
          Err(TranslateError::Failed("Too many jump instructions.".into())),
          "the {}th jump fixup must be refused by name",
          n * 2
        );
      }
    }
  }

  /// AUDIT: every capacity from zero to just past the full output, for a
  /// program that fills all four patch tables. The existing capacity test uses
  /// six sizes and a two-instruction program, so it never lands inside the
  /// epilogue, the dispatcher slot or the helper table - the places where a
  /// truncated buffer is most likely to be handled badly.
  #[test]
  fn audit_every_capacity_for_a_program_that_fills_the_patch_tables() {
    let insns = vec![
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
      insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
      insn(opcode::CALL, 0, 0, 0, 3),
      insn(opcode::ATOMIC_STORE, 1, 2, 0, atomic::OP_CMPXCHG),
      insn(cls::JMP | srcbit::IMM | jmp::JEQ, 1, 0, 1, 0),
      insn(0xb7, 1, 0, 0, 1),
      insn(opcode::JA, 0, 0, -3, 0),
      exit(),
    ];
    let plan = vec![
      leader(abi::region::STACK, 0, 0, 16, 0),
      member(abi::region::STACK, 0, 8, 0),
      none_entry(),
      none_entry(),
      none_entry(),
      none_entry(),
      none_entry(),
      none_entry(),
    ];
    let hints = vec![1u8, 1, 0, 0, 0, 0, 0, 0];
    let code = Insn::encode_all(&insns);
    let inputs = TranslationInputs {
      hints: &hints,
      plan: &plan,
      ..plain_inputs(insns.len())
    };
    // Every capacity in the sweep is one entry, so this one rolls up into a
    // digest rather than several thousand lines of mostly "out of space".
    let mut digest = SweepDigest::new();
    for (_, config) in config_sweep(Target::Aarch64) {
      let full = rust_len(&config, &insns);
      for capacity in 0..full + 16 {
        sweep_case(&mut digest, &config, &code, &inputs, capacity);
      }
      // The last sixteen capacities are past the full output, so the sweep has
      // to contain successes as well as refusals.
      assert!(
        digest.translated() > 0,
        "no capacity in the sweep was large enough to translate {full} bytes"
      );
    }
    finish_sweep(digest, "audit-every-capacity");
  }

  /// AUDIT: every way the barrier pre-pass can close a group - the slot after a
  /// jump/call/exit, a forward branch target, a backward branch target, and a
  /// local function entry - with a leader/member pair straddling each.
  #[test]
  fn audit_every_barrier_source_closes_a_group() {
    let mut digest = SweepDigest::new();
    let ld = |dst: u8, off: i16| insn(cls::LDX | mode::MEM | size::DW, dst, 2, off, 0);

    // leader; <separator>; member
    let separators: Vec<(&str, Vec<Insn>)> = vec![
      (
        "conditional jump forward over the member",
        vec![insn(cls::JMP | srcbit::IMM | jmp::JEQ, 1, 0, 1, 0)],
      ),
      (
        "conditional jump onto the member",
        vec![insn(cls::JMP | srcbit::IMM | jmp::JEQ, 1, 0, 0, 0)],
      ),
      ("ja onto the member", vec![insn(opcode::JA, 0, 0, 0, 0)]),
      ("helper call", vec![insn(opcode::CALL, 0, 0, 0, 0)]),
      (
        "jmp32 conditional",
        vec![insn(cls::JMP32 | srcbit::IMM | jmp::JNE, 1, 0, 0, 0)],
      ),
      ("plain alu, no barrier at all", vec![insn(0xb7, 4, 0, 0, 1)]),
    ];

    for (what, sep) in separators {
      let mut insns = vec![ld(1, 0)];
      insns.extend(sep.iter().copied());
      insns.push(ld(3, 8));
      insns.push(exit());
      let n = insns.len();
      let mut plan = vec![leader(abi::region::STACK, 0, 0, 16, 0)];
      for _ in &sep {
        plan.push(none_entry());
      }
      plan.push(member(abi::region::STACK, 0, 8, 0));
      plan.push(none_entry());
      assert_eq!(plan.len(), n);
      audit_case(
        &mut digest,
        what,
        &insns,
        &TranslationInputs {
          plan: &plan,
          ..plain_inputs(n)
        },
      );
    }

    // A backward jump whose target is the member.
    {
      let insns = vec![
        ld(1, 0),
        ld(3, 8),
        insn(cls::JMP | srcbit::IMM | jmp::JEQ, 1, 0, -2, 0),
        exit(),
      ];
      let plan = vec![
        leader(abi::region::STACK, 0, 0, 16, 0),
        member(abi::region::STACK, 0, 8, 0),
        none_entry(),
        none_entry(),
      ];
      audit_case(
        &mut digest,
        "backward branch target is the member",
        &insns,
        &TranslationInputs {
          plan: &plan,
          ..plain_inputs(4)
        },
      );
    }

    // A local function entry between the two, inside one translation range.
    {
      let insns = vec![
        insn(opcode::CALL, 0, 1, 0, 2),
        insn(opcode::JA, 0, 0, -2, 0),
        ld(1, 0),
        ld(3, 8),
        exit(),
      ];
      let plan = vec![
        none_entry(),
        none_entry(),
        leader(abi::region::STACK, 0, 0, 16, 2),
        member(abi::region::STACK, 0, 8, 2),
        none_entry(),
      ];
      let ids = [7u32; 5];
      audit_case(
        &mut digest,
        "function entry lands on the member",
        &insns,
        &TranslationInputs {
          plan: &plan,
          resolver_ids: &ids,
          ..plain_inputs(5)
        },
      );
    }

    finish_sweep(digest, "audit-barrier-sources");
  }

  /// AUDIT (informational): how far one eBPF instruction can expand, which
  /// bounds whether the +-128 MiB unconditional-branch reach can be exceeded
  /// inside the 65536-instruction program limit.
  #[test]
  fn audit_report_worst_case_expansion() {
    let candidates: Vec<(&str, Insn)> = vec![
      (
        "ldxdw unknown region",
        insn(cls::LDX | mode::MEM | size::DW, 1, 2, 4096, 0),
      ),
      (
        "stxdw",
        insn(cls::STX | mode::MEM | size::DW, 1, 2, 4096, 0),
      ),
      (
        "stdw imm",
        insn(cls::ST | mode::MEM | size::DW, 1, 0, 4096, i32::MIN),
      ),
      (
        "atomic cmpxchg",
        insn(opcode::ATOMIC_STORE, 1, 2, 4096, atomic::OP_CMPXCHG),
      ),
      ("helper call", insn(opcode::CALL, 0, 0, 0, 3)),
      ("lddw", insn(opcode::LDDW, 1, 0, 0, 0x1234_5678)),
    ];
    let mut worst = 0usize;
    for (name, config) in config_sweep(Target::Aarch64) {
      for (what, i0) in &candidates {
        let mut a = vec![insn(0xb7, 1, 0, 0, 0)];
        let mut b = vec![insn(0xb7, 1, 0, 0, 0)];
        for _ in 0..10 {
          a.push(*i0);
          b.push(*i0);
          if i0.opcode == opcode::LDDW {
            a.push(insn(0, 0, 0, 0, -1));
            b.push(insn(0, 0, 0, 0, -1));
          }
        }
        for _ in 0..10 {
          b.push(*i0);
          if i0.opcode == opcode::LDDW {
            b.push(insn(0, 0, 0, 0, -1));
          }
        }
        a.push(exit());
        b.push(exit());
        let per = (rust_len(&config, &b) - rust_len(&config, &a)) / 10;
        if per > worst {
          worst = per;
          println!("worst so far: {per} bytes/insn for {what} under {name}");
        }
      }
    }
    let reach = worst * abi::MAX_INSTS as usize;
    println!(
      "worst-case expansion {worst} bytes/insn; {} instructions reach {} MiB",
      abi::MAX_INSTS,
      reach >> 20
    );
    // Which is why the 26-bit arm of `resolve_branch_immediate` can never fire
    // for a loadable program, while the 19-bit arms (conditional branch, LDR
    // literal, ADR) can and do - see the +-1 MiB tests above.
    assert!(
      reach < (128 << 20),
      "a program can now exceed the +-128 MiB unconditional-branch reach; the \
       26-bit relocation arm has become reachable and needs its own test"
    );
    assert!(reach > (1 << 20));
  }
}

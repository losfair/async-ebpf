//! The x86_64 primitive encoder, and the two-pass assembler around it.
//!
//! [`encode_one`] maps one [`PInsn`] to the bytes the backend has always
//! written for it, with every deferred displacement left as zero;
//! [`size_of`] gives that sequence's length without producing it; and
//! [`assemble`] runs the two passes that turn a primitive list into a
//! function: measure every primitive and record where each label landed, then
//! encode each primitive and patch its displacement.
//!
//! ```text
//!   Vec<PInsn>
//!     │  offsets          where every primitive starts   (pass one)
//!     │  collect_labels   where every label landed       (pass one)
//!     │  encode_one       the bytes, displacements zero  (pass two)
//!     │  patch            the displacements              (pass two)
//!     ▼
//!   bytes
//! ```
//!
//! This used to be `jit::emit::x86_64`'s `Enc`, with a `Vec<Fixup>` walked
//! after the fact. The table is the same table and the bytes are the same
//! bytes — the goldens pin them — but the fixups are gone: a displacement is
//! written by the pass that emits the instruction carrying it, from the
//! offsets pass one already computed, so `decode (encode p) = p` is a
//! statement about one function rather than about a mutable side table.
//!
//! One deliberate difference. The old fixup pass resolved a branch to an
//! unlabelled slot to offset zero, the top of the function; this one refuses
//! the list with [`AsmError::MissingLabel`]. `x64_check` already refuses a
//! macro list that branches to an unlabelled slot, so nothing the backend
//! builds reaches either behaviour.
//!
//! [`x64_decode`](super::x64_decode) inverts [`encode_one`].
//!
//! # A shape the extraction needs
//!
//! No arm of [`encode_one`]'s or [`size_of`]'s match branches: every arm is a
//! constant, a single call, or a call to one of the small helpers beside the
//! byte emitters — `emit_muldiv_rcx`, `emit_movsx`, `emit_cmp_rcx_minus_one`,
//! `emit_call_reg`, `emit_guest_load` and their `*_len` counterparts — which
//! do the branching. An `if` written directly in an arm of a match this wide
//! makes Aeneas fail to join the branch while the function's borrowed argument
//! is live (`Unreachable`, from `interp/InterpAbs.ml`), and the whole body is
//! extracted as `sorry`. Keep new variants' arms one call wide.

// `Range::contains` is a method call on a range, which the extraction has no
// model for; every bound here is written out as a comparison instead.
#![allow(clippy::manual_range_contains)]

use super::x64_ir::{
  AluRI, AluRM, AluRR, MulDivKind, PInsn, PTarget, ShiftOp, Size, MAX_EXT_FUNCS, R12, R13, RBP,
  RCX, RSP,
};

/// Why a primitive list could not be assembled.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub enum AsmError {
  /// A branch, a RIP-relative load or a RIP-relative `lea` named a label the
  /// list does not carry.
  MissingLabel,
  /// A one-byte displacement does not reach its target.
  RelocationOutOfRange,
}

/// The patch pass' outcomes, as a number rather than an enum so that the
/// assemble loop can carry one in a local and test it in its condition.
const ERR_NONE: u32 = 0;
const ERR_MISSING: u32 = 1;
const ERR_RANGE: u32 = 2;

/// The smallest and largest immediate the sign-extended 32-bit forms carry.
const IMM32_MIN: i64 = -2147483648;
const IMM32_MAX: i64 = 2147483647;

// ---------------------------------------------------------------------------
// Bytes
// ---------------------------------------------------------------------------

/// A flag as the bit the encodings spell it with.
fn bit(b: bool) -> u8 {
  if b {
    1
  } else {
    0
  }
}

/// A register's high bit, which a REX prefix carries.
fn high(r: u8) -> u8 {
  if (r & 8) != 0 {
    1
  } else {
    0
  }
}

fn emit1(out: &mut Vec<u8>, x: u8) {
  out.push(x);
}

fn emit2(out: &mut Vec<u8>, x: u16) {
  out.push((x & 0xff) as u8);
  out.push(((x >> 8) & 0xff) as u8);
}

fn emit4(out: &mut Vec<u8>, x: u32) {
  out.push((x & 0xff) as u8);
  out.push(((x >> 8) & 0xff) as u8);
  out.push(((x >> 16) & 0xff) as u8);
  out.push(((x >> 24) & 0xff) as u8);
}

fn emit8(out: &mut Vec<u8>, x: u64) {
  out.push((x & 0xff) as u8);
  out.push(((x >> 8) & 0xff) as u8);
  out.push(((x >> 16) & 0xff) as u8);
  out.push(((x >> 24) & 0xff) as u8);
  out.push(((x >> 32) & 0xff) as u8);
  out.push(((x >> 40) & 0xff) as u8);
  out.push(((x >> 48) & 0xff) as u8);
  out.push(((x >> 56) & 0xff) as u8);
}

fn emit_modrm(out: &mut Vec<u8>, md: u8, r: u8, m: u8) {
  out.push((md & 0xc0) | ((r & 7) << 3) | (m & 7));
}

fn emit_modrm_reg2reg(out: &mut Vec<u8>, r: u8, m: u8) {
  emit_modrm(out, 0xc0, r, m);
}

/// Whether `d` fits the one-byte displacement form.
fn near_disp(d: i32) -> bool {
  d >= -128 && d <= 127
}

/// Whether a base register needs a displacement even when it is zero.
///
/// `RBP`/`R13` cannot encode a bare `[base]`, so they always get an explicit
/// displacement; `RSP`/`R12` need a SIB byte, and the zero-displacement form
/// with a SIB byte means something else, so they get one too.
fn needs_disp(rm: u8) -> bool {
  rm == RSP || rm == RBP || rm == R12 || rm == R13
}

/// Whether a base register needs the SIB byte, emitted as `0x24`.
///
/// `RSP` and `R12` share the low three bits that ModRM encodes, so both need
/// it. No caller passes `RSP` as a base — the sequences that address the host
/// stack emit their ModRM and SIB bytes literally — so emitting it for `R12`
/// alone produces correct code.
fn needs_sib(rm: u8) -> bool {
  rm == RSP || rm == R12
}

/// ModRM plus displacement, with the zero-displacement shortcut.
fn emit_modrm_and_displacement(out: &mut Vec<u8>, reg: u8, rm: u8, d: i32) {
  let rm = rm & 0xf;
  let reg = reg & 0xf;
  let needs = needs_disp(rm);

  if d == 0 && !needs {
    emit_modrm(out, 0x00, reg, rm);
  } else {
    let near = near_disp(d);
    let md = if near { 0x40 } else { 0x80 };
    emit_modrm(out, md, reg, rm);
    if needs_sib(rm) {
      emit1(out, 0x24);
    }
    if near {
      emit1(out, d as u8);
    } else {
      emit4(out, d as u32);
    }
  }
}

/// The bytes [`emit_modrm_and_displacement`] writes.
fn modrm_and_displacement_len(rm: u8, d: i32) -> usize {
  let rm = rm & 0xf;
  let needs = needs_disp(rm);
  if d == 0 && !needs {
    1
  } else {
    let sib: usize = if needs_sib(rm) { 1 } else { 0 };
    let disp: usize = if near_disp(d) { 1 } else { 4 };
    1 + sib + disp
  }
}

fn emit_rex(out: &mut Vec<u8>, w: u8, r: u8, x: u8, b: u8) {
  out.push(0x40 | (w << 3) | (r << 2) | (x << 1) | b);
}

/// Whether [`emit_basic_rex`] writes a prefix at all.
fn basic_rex(w: u8, src: u8, dst: u8) -> bool {
  w != 0 || (src & 8) != 0 || (dst & 8) != 0
}

/// REX carrying only the high bits of `src`/`dst`, skipped when no bit would
/// be set.
fn emit_basic_rex(out: &mut Vec<u8>, w: u8, src: u8, dst: u8) {
  if basic_rex(w, src, dst) {
    emit_rex(out, w, high(src), 0, high(dst));
  }
}

fn basic_rex_len(w: u8, src: u8, dst: u8) -> usize {
  if basic_rex(w, src, dst) {
    1
  } else {
    0
  }
}

fn emit_alu(out: &mut Vec<u8>, w64: bool, op: u8, src: u8, dst: u8) {
  emit_basic_rex(out, bit(w64), src, dst);
  emit1(out, op);
  emit_modrm_reg2reg(out, src, dst);
}

fn alu_len(w64: bool, src: u8, dst: u8) -> usize {
  basic_rex_len(bit(w64), src, dst) + 2
}

/// `load [src + offset] -> dst`, zero-extending for the narrow widths.
fn emit_load(out: &mut Vec<u8>, size: Size, src: u8, dst: u8, offset: i32) {
  emit_basic_rex(out, bit(size == 8), dst, src);
  if size == 1 {
    emit1(out, 0x0f);
    emit1(out, 0xb6);
  } else if size == 2 {
    emit1(out, 0x0f);
    emit1(out, 0xb7);
  } else {
    emit1(out, 0x8b);
  }
  emit_modrm_and_displacement(out, dst, src, offset);
}

fn load_len(size: Size, src: u8, dst: u8, offset: i32) -> usize {
  let op: usize = if size == 1 || size == 2 { 2 } else { 1 };
  basic_rex_len(bit(size == 8), dst, src) + op + modrm_and_displacement_len(src, offset)
}

/// `load [src + offset] -> dst`, sign-extending to 64 bits. The doubleword
/// form emits nothing at all: there is no `ldxdwsx` encoding, so no caller
/// reaches it.
fn emit_load_sx(out: &mut Vec<u8>, size: Size, src: u8, dst: u8, offset: i32) {
  if size != 8 {
    emit_basic_rex(out, 1, dst, src);
    if size == 4 {
      emit1(out, 0x63);
    } else {
      emit1(out, 0x0f);
      if size == 1 {
        emit1(out, 0xbe);
      } else {
        emit1(out, 0xbf);
      }
    }
    emit_modrm_and_displacement(out, dst, src, offset);
  }
}

fn load_sx_len(size: Size, src: u8, offset: i32) -> usize {
  if size == 8 {
    0
  } else {
    let op: usize = if size == 4 { 1 } else { 2 };
    1 + op + modrm_and_displacement_len(src, offset)
  }
}

/// Whether a store's REX prefix is written.
///
/// The byte-width term is what makes a byte store through `SIL`/`DIL`/`SPL`/
/// `BPL` name the right register: without a REX prefix those encodings mean
/// `AH`/`CH`/`DH`/`BH`.
fn store_rex(size: Size, src: u8, dst: u8) -> bool {
  size == 8 || (src & 8) != 0 || (dst & 8) != 0 || size == 1
}

/// `store src -> [dst + offset]`.
fn emit_store(out: &mut Vec<u8>, size: Size, src: u8, dst: u8, offset: i32) {
  if size == 2 {
    emit1(out, 0x66);
  }
  if store_rex(size, src, dst) {
    emit_rex(out, bit(size == 8), high(src), 0, high(dst));
  }
  if size == 1 {
    emit1(out, 0x88);
  } else {
    emit1(out, 0x89);
  }
  emit_modrm_and_displacement(out, src, dst, offset);
}

fn store_len(size: Size, src: u8, dst: u8, offset: i32) -> usize {
  let pfx: usize = if size == 2 { 1 } else { 0 };
  let rex: usize = if store_rex(size, src, dst) { 1 } else { 0 };
  pfx + rex + 1 + modrm_and_displacement_len(dst, offset)
}

/// `store imm -> [dst + offset]`.
fn emit_store_imm(out: &mut Vec<u8>, size: Size, dst: u8, offset: i32, imm: i32) {
  if size == 2 {
    emit1(out, 0x66);
  }
  emit_basic_rex(out, bit(size == 8), 0, dst);
  if size == 1 {
    emit1(out, 0xc6);
  } else {
    emit1(out, 0xc7);
  }
  emit_modrm_and_displacement(out, 0, dst, offset);
  if size == 1 {
    emit1(out, imm as u8);
  } else if size == 2 {
    emit2(out, imm as u16);
  } else {
    emit4(out, imm as u32);
  }
}

fn store_imm_len(size: Size, dst: u8, offset: i32) -> usize {
  let pfx: usize = if size == 2 { 1 } else { 0 };
  let imm: usize = if size == 1 {
    1
  } else if size == 2 {
    2
  } else {
    4
  };
  pfx + basic_rex_len(bit(size == 8), 0, dst) + 1 + modrm_and_displacement_len(dst, offset) + imm
}

/// Whether a 64-bit immediate goes through the sign-extended 32-bit form.
fn imm_fits32(imm: i64) -> bool {
  imm >= IMM32_MIN && imm <= IMM32_MAX
}

/// Materialises a 64-bit immediate, preferring the sign-extended 32-bit form.
fn emit_load_imm(out: &mut Vec<u8>, dst: u8, imm: i64) {
  if imm_fits32(imm) {
    emit_alu(out, true, 0xc7, 0, dst);
    emit4(out, imm as u32);
  } else {
    emit_basic_rex(out, 1, 0, dst);
    emit1(out, 0xb8 | (dst & 7));
    emit8(out, imm as u64);
  }
}

fn load_imm_len(dst: u8, imm: i64) -> usize {
  if imm_fits32(imm) {
    alu_len(true, 0, dst) + 4
  } else {
    basic_rex_len(1, 0, dst) + 1 + 8
  }
}

/// The register-form opcode byte for each ALU operation.
fn alu_rr_opcode(op: AluRR) -> u8 {
  match op {
    AluRR::Add => 0x01,
    AluRR::Sub => 0x29,
    AluRR::Or => 0x09,
    AluRR::And => 0x21,
    AluRR::Xor => 0x31,
    AluRR::Mov => 0x89,
    AluRR::Cmp => 0x39,
    AluRR::Test => 0x85,
  }
}

/// The opcode byte for each immediate-form operation.
fn alu_ri_opcode(op: AluRI) -> u8 {
  match op {
    AluRI::Add => 0x81,
    AluRI::Or => 0x81,
    AluRI::And => 0x81,
    AluRI::Sub => 0x81,
    AluRI::Xor => 0x81,
    AluRI::Cmp => 0x81,
    AluRI::Mov => 0xc7,
    AluRI::Test => 0xf7,
  }
}

/// The ModRM extension for each immediate-form operation.
fn alu_ri_ext(op: AluRI) -> u8 {
  match op {
    AluRI::Add => 0,
    AluRI::Or => 1,
    AluRI::And => 4,
    AluRI::Sub => 5,
    AluRI::Xor => 6,
    AluRI::Cmp => 7,
    AluRI::Mov => 0,
    AluRI::Test => 0,
  }
}

fn shift_ext(op: ShiftOp) -> u8 {
  match op {
    ShiftOp::Shl => 4,
    ShiftOp::Shr => 5,
    ShiftOp::Sar => 7,
  }
}

/// The opcode byte for each `op reg, [mem]` form the bounds checks use.
fn alu_rm_opcode(op: AluRM) -> u8 {
  match op {
    AluRM::Sub => 0x2b,
    AluRM::Add => 0x03,
    AluRM::CmpMR => 0x39,
    AluRM::CmpRM => 0x3b,
    AluRM::Or => 0x0b,
  }
}

/// `/4` is MUL, `/6` DIV and `/7` IDIV. Modulo is the same instruction as
/// division; the macro layer keeps the difference.
fn muldiv_ext(kind: MulDivKind, signed: bool) -> u8 {
  match kind {
    MulDivKind::Mul => 4,
    _ => {
      if signed {
        7
      } else {
        6
      }
    }
  }
}

/// Sixty-four null helper addresses.
///
/// `async-ebpf` never registers individual helpers — it uses the dispatcher —
/// so every entry is null. The table is emitted anyway because the default
/// dispatch path indexes into it and the trailer's layout is part of the ABI
/// the runtime patches through.
fn emit_helper_table(out: &mut Vec<u8>) {
  let mut k: u32 = 0;
  while k < MAX_EXT_FUNCS {
    emit8(out, 0);
    k += 1;
  }
}

/// The bytes [`emit_helper_table`] writes.
pub const HELPER_TABLE_LEN: usize = 8 * MAX_EXT_FUNCS as usize;

/// `mul rcx` / `div rcx` / `idiv rcx`, at 32 or 64 bits.
fn emit_muldiv_rcx(out: &mut Vec<u8>, w64: bool, kind: MulDivKind, signed: bool) {
  if w64 {
    emit_rex(out, 1, 0, 0, 0);
  }
  emit_alu(out, false, 0xf7, muldiv_ext(kind, signed), RCX);
}

fn muldiv_rcx_len(w64: bool, kind: MulDivKind, signed: bool) -> usize {
  let rex: usize = if w64 { 1 } else { 0 };
  rex + alu_len(false, muldiv_ext(kind, signed), RCX)
}

/// `movsx dst, src`, from 8, 16 or 32 source bits.
///
/// The explicit REX is what makes a byte source name `SIL`/`DIL`/`SPL`/`BPL`
/// rather than `AH`/`CH`/`DH`/`BH`, so it is emitted even when no
/// high-register bit is set.
fn emit_movsx(out: &mut Vec<u8>, from: u8, w64: bool, src: u8, dst: u8) {
  if w64 || from == 8 {
    emit_rex(out, bit(w64), high(dst), 0, high(src));
  } else {
    emit_basic_rex(out, 0, dst, src);
  }
  if from == 32 {
    emit1(out, 0x63);
  } else {
    emit1(out, 0x0f);
    if from == 8 {
      emit1(out, 0xbe);
    } else {
      emit1(out, 0xbf);
    }
  }
  emit_modrm_reg2reg(out, dst, src);
}

fn movsx_len(from: u8, w64: bool, src: u8, dst: u8) -> usize {
  let rex: usize = if w64 || from == 8 {
    1
  } else {
    basic_rex_len(0, dst, src)
  };
  let op: usize = if from == 32 { 1 } else { 2 };
  rex + op + 1
}

/// `cmp rcx, -1` / `cmp ecx, -1`.
fn emit_cmp_rcx_minus_one(out: &mut Vec<u8>, w64: bool) {
  if w64 {
    emit1(out, 0x48);
  }
  emit1(out, 0x83);
  emit1(out, 0xf9);
  emit1(out, 0xff);
}

fn cmp_rcx_minus_one_len(w64: bool) -> usize {
  let rex: usize = if w64 { 1 } else { 0 };
  rex + 3
}

/// `call reg`.
fn emit_call_reg(out: &mut Vec<u8>, reg: u8) {
  if (reg & 8) != 0 {
    emit1(out, 0x41);
  }
  emit1(out, 0xff);
  emit1(out, 0xd0 | (reg & 7));
}

fn call_reg_len(reg: u8) -> usize {
  let rex: usize = if (reg & 8) != 0 { 1 } else { 0 };
  rex + 2
}

/// A guest load, zero- or sign-extending.
fn emit_guest_load(out: &mut Vec<u8>, size: Size, sx: bool, base: u8, dst: u8, disp: i32) {
  if sx {
    emit_load_sx(out, size, base, dst, disp);
  } else {
    emit_load(out, size, base, dst, disp);
  }
}

fn guest_load_len(size: Size, sx: bool, base: u8, dst: u8, disp: i32) -> usize {
  if sx {
    load_sx_len(size, base, disp)
  } else {
    load_len(size, base, dst, disp)
  }
}

// ---------------------------------------------------------------------------
// One primitive
// ---------------------------------------------------------------------------

/// Appends the bytes for `p`.
///
/// Every deferred displacement is written as a zero placeholder of the right
/// width: the rel32 of `Jcc`, `Jmp`, `Call`, `RipLoadDispatcher` and
/// `RipLeaHelperTable`, and the rel8 of `JmpNear`, `Jcc8` and `Jmp8`.
/// `JmpNear` keeps its three bytes of padding, which are never executed — the
/// jump is unconditional and lands past them. [`assemble`] is what fills the
/// placeholders in.
///
/// The four label primitives and the sign-extending eight-byte `Load` emit
/// nothing.
pub fn encode_one(p: &PInsn, out: &mut Vec<u8>) {
  let insn = *p;
  match insn {
    PInsn::PcLabel(_) => {}
    PInsn::Local(_) => {}
    PInsn::ExitLabel => {}
    PInsn::RetpolineLabel => {}

    PInsn::Push(r) => {
      emit_basic_rex(out, 0, 0, r);
      emit1(out, 0x50 | (r & 7));
    }
    PInsn::Pop(r) => {
      emit_basic_rex(out, 0, 0, r);
      emit1(out, 0x58 | (r & 7));
    }
    PInsn::Alu { w64, op, src, dst } => emit_alu(out, w64, alu_rr_opcode(op), src, dst),
    PInsn::AluImm { w64, op, dst, imm } => {
      emit_alu(out, w64, alu_ri_opcode(op), alu_ri_ext(op), dst);
      emit4(out, imm as u32);
    }
    PInsn::ShiftImm { w64, op, dst, imm } => {
      emit_alu(out, w64, 0xc1, shift_ext(op), dst);
      // The shift count is a byte, so the immediate is truncated here.
      emit1(out, imm as u8);
    }
    PInsn::ShiftCl { w64, op, dst } => emit_alu(out, w64, 0xd3, shift_ext(op), dst),
    PInsn::Neg { w64, dst } => emit_alu(out, w64, 0xf7, 3, dst),
    PInsn::MulDivRcx { w64, kind, signed } => emit_muldiv_rcx(out, w64, kind, signed),
    PInsn::MovSx {
      from,
      w64,
      src,
      dst,
    } => emit_movsx(out, from, w64, src, dst),
    PInsn::Bswap { w64, dst } => {
      emit_basic_rex(out, bit(w64), 0, dst);
      emit1(out, 0x0f);
      emit1(out, 0xc8 | (dst & 7));
    }
    PInsn::Rol16 { dst } => {
      emit1(out, 0x66);
      emit_alu(out, false, 0xc1, 0, dst);
      emit1(out, 8);
    }
    PInsn::Cmov { cc, dst, src } => {
      emit_basic_rex(out, 1, dst, src);
      emit1(out, 0x0f);
      // `cmovcc` is the `0x4x` row of the same condition table the near `jcc`
      // forms name in the `0x8x` row.
      emit1(out, 0x40 | (cc & 0x0f));
      emit_modrm_reg2reg(out, dst, src);
    }
    PInsn::LoadImm { dst, imm } => emit_load_imm(out, dst, imm),
    PInsn::Pushfq => emit1(out, 0x9c),
    PInsn::Popfq => emit1(out, 0x9d),
    PInsn::Cqo => {
      emit1(out, 0x48);
      emit1(out, 0x99);
    }
    PInsn::Cdq => emit1(out, 0x99),
    PInsn::CmpRcxMinusOne { w64 } => emit_cmp_rcx_minus_one(out, w64),
    PInsn::CmpEaxImm { imm } => {
      emit1(out, 0x3d);
      emit4(out, imm);
    }

    PInsn::Load {
      size,
      sx,
      base,
      dst,
      disp,
    } => emit_guest_load(out, size, sx, base, dst, disp),
    PInsn::Store {
      size,
      src,
      base,
      disp,
    } => emit_store(out, size, src, base, disp),
    PInsn::StoreImm {
      size,
      base,
      disp,
      imm,
    } => emit_store_imm(out, size, base, disp, imm),
    PInsn::AluRM {
      op,
      reg,
      base,
      disp,
    } => {
      emit_basic_rex(out, 1, reg, base);
      emit1(out, alu_rm_opcode(op));
      emit_modrm_and_displacement(out, reg, base, disp);
    }
    PInsn::StoreRspImm { imm } => {
      // The ModRM/SIB pair for an `[rsp]` base is emitted literally.
      emit1(out, 0x48);
      emit1(out, 0xc7);
      emit1(out, 0x04);
      emit1(out, 0x24);
      emit4(out, imm);
    }
    PInsn::StoreRspRax => {
      emit1(out, 0x48);
      emit1(out, 0x89);
      emit1(out, 0x04);
      emit1(out, 0x24);
    }

    PInsn::LockAlu {
      op,
      w64,
      src,
      base,
      disp,
    } => {
      emit1(out, 0xf0);
      emit_basic_rex(out, bit(w64), src, base);
      emit1(out, op);
      emit_modrm_and_displacement(out, src, base, disp);
    }
    PInsn::LockCmpxchg {
      w64,
      src,
      base,
      disp,
    } => {
      emit1(out, 0xf0);
      emit_basic_rex(out, bit(w64), src, base);
      emit1(out, 0x0f);
      emit1(out, 0xb1);
      emit_modrm_and_displacement(out, src, base, disp);
    }
    PInsn::Xchg {
      w64,
      src,
      base,
      disp,
    } => {
      // `xchg` with a memory operand is implicitly locked; the prefix is
      // emitted anyway.
      emit1(out, 0xf0);
      emit_basic_rex(out, bit(w64), src, base);
      emit1(out, 0x87);
      emit_modrm_and_displacement(out, src, base, disp);
    }

    PInsn::Jcc { cc, target: _ } => {
      emit1(out, 0x0f);
      emit1(out, cc);
      emit4(out, 0);
    }
    PInsn::Jmp { target: _ } => {
      emit1(out, 0xe9);
      emit4(out, 0);
    }
    PInsn::JmpNear { target: _ } => {
      emit1(out, 0xeb);
      // A near jump still reserves four bytes, so three are wasted after
      // every one. They are never executed, so this costs code size and
      // nothing else.
      emit4(out, 0);
    }
    PInsn::Call { target: _ } => {
      emit1(out, 0xe8);
      emit4(out, 0);
    }
    PInsn::Jcc8 { cc, target: _ } => {
      emit1(out, 0x70 | (cc & 0x0f));
      emit1(out, 0);
    }
    PInsn::Jmp8 { target: _ } => {
      emit1(out, 0xeb);
      emit1(out, 0);
    }
    PInsn::Ret => emit1(out, 0xc3),
    PInsn::Pause => {
      emit1(out, 0xf3);
      emit1(out, 0x90);
    }
    PInsn::Ud2 => {
      emit1(out, 0x0f);
      emit1(out, 0x0b);
    }
    PInsn::CallReg(reg) => emit_call_reg(out, reg),
    PInsn::RipLoadDispatcher { dst } => {
      // The REX `R` bit is zero: the only destination is RAX.
      emit_rex(out, 1, 0, 0, 0);
      emit1(out, 0x8b);
      emit_modrm(out, 0, dst, 0x05);
      emit4(out, 0);
    }
    PInsn::RipLeaHelperTable { dst } => {
      emit_rex(out, 1, high(dst), 0, 0);
      emit1(out, 0x8d);
      emit_modrm(out, 0, dst, 0x05);
      emit4(out, 0);
    }

    PInsn::DispatcherSlot { addr } => emit8(out, addr),
    PInsn::HelperTable => emit_helper_table(out),
  }
}

/// The number of bytes [`encode_one`] appends for `p`.
///
/// Computed from the same rules rather than by encoding into a scratch
/// buffer, so that `size_of p = length (encode_one p)` is a theorem about two
/// pieces of code rather than a definition.
pub fn size_of(p: &PInsn) -> usize {
  let insn = *p;
  match insn {
    PInsn::PcLabel(_) => 0,
    PInsn::Local(_) => 0,
    PInsn::ExitLabel => 0,
    PInsn::RetpolineLabel => 0,

    PInsn::Push(r) => basic_rex_len(0, 0, r) + 1,
    PInsn::Pop(r) => basic_rex_len(0, 0, r) + 1,
    PInsn::Alu {
      w64,
      op: _,
      src,
      dst,
    } => alu_len(w64, src, dst),
    PInsn::AluImm {
      w64,
      op,
      dst,
      imm: _,
    } => alu_len(w64, alu_ri_ext(op), dst) + 4,
    PInsn::ShiftImm {
      w64,
      op,
      dst,
      imm: _,
    } => alu_len(w64, shift_ext(op), dst) + 1,
    PInsn::ShiftCl { w64, op, dst } => alu_len(w64, shift_ext(op), dst),
    PInsn::Neg { w64, dst } => alu_len(w64, 3, dst),
    PInsn::MulDivRcx { w64, kind, signed } => muldiv_rcx_len(w64, kind, signed),
    PInsn::MovSx {
      from,
      w64,
      src,
      dst,
    } => movsx_len(from, w64, src, dst),
    PInsn::Bswap { w64, dst } => basic_rex_len(bit(w64), 0, dst) + 2,
    PInsn::Rol16 { dst } => 1 + alu_len(false, 0, dst) + 1,
    PInsn::Cmov { cc: _, dst, src } => basic_rex_len(1, dst, src) + 3,
    PInsn::LoadImm { dst, imm } => load_imm_len(dst, imm),
    PInsn::Pushfq => 1,
    PInsn::Popfq => 1,
    PInsn::Cqo => 2,
    PInsn::Cdq => 1,
    PInsn::CmpRcxMinusOne { w64 } => cmp_rcx_minus_one_len(w64),
    PInsn::CmpEaxImm { imm: _ } => 5,

    PInsn::Load {
      size,
      sx,
      base,
      dst,
      disp,
    } => guest_load_len(size, sx, base, dst, disp),
    PInsn::Store {
      size,
      src,
      base,
      disp,
    } => store_len(size, src, base, disp),
    PInsn::StoreImm {
      size,
      base,
      disp,
      imm: _,
    } => store_imm_len(size, base, disp),
    PInsn::AluRM {
      op: _,
      reg: _,
      base,
      disp,
    } => 2 + modrm_and_displacement_len(base, disp),
    PInsn::StoreRspImm { imm: _ } => 8,
    PInsn::StoreRspRax => 4,

    PInsn::LockAlu {
      op: _,
      w64,
      src,
      base,
      disp,
    } => 1 + basic_rex_len(bit(w64), src, base) + 1 + modrm_and_displacement_len(base, disp),
    PInsn::LockCmpxchg {
      w64,
      src,
      base,
      disp,
    } => 1 + basic_rex_len(bit(w64), src, base) + 2 + modrm_and_displacement_len(base, disp),
    PInsn::Xchg {
      w64,
      src,
      base,
      disp,
    } => 1 + basic_rex_len(bit(w64), src, base) + 1 + modrm_and_displacement_len(base, disp),

    PInsn::Jcc { cc: _, target: _ } => 6,
    PInsn::Jmp { target: _ } => 5,
    PInsn::JmpNear { target: _ } => 5,
    PInsn::Call { target: _ } => 5,
    PInsn::Jcc8 { cc: _, target: _ } => 2,
    PInsn::Jmp8 { target: _ } => 2,
    PInsn::Ret => 1,
    PInsn::Pause => 2,
    PInsn::Ud2 => 2,
    PInsn::CallReg(reg) => call_reg_len(reg),
    PInsn::RipLoadDispatcher { dst: _ } => 7,
    PInsn::RipLeaHelperTable { dst: _ } => 7,

    PInsn::DispatcherSlot { addr: _ } => 8,
    PInsn::HelperTable => HELPER_TABLE_LEN,
  }
}

// ---------------------------------------------------------------------------
// Pass one: offsets and labels
// ---------------------------------------------------------------------------

/// Where every primitive starts, and where the last one ends.
///
/// Appends `code.len() + 1` offsets: the start of each primitive, and the
/// total length. Offsets are measured from the start of the assembled
/// function, which is what every relative displacement is measured against.
pub fn offsets(code: &[PInsn], starts: &mut Vec<u32>) {
  let mut off: usize = 0;
  let mut i: usize = 0;
  while i < code.len() {
    starts.push(off as u32);
    off += size_of(&code[i]);
    i += 1;
  }
  starts.push(off as u32);
}

/// Where each label landed.
///
/// The slot and local tables are `Vec<u32>` indexed by the label's number and
/// sized by the largest one the list carries, with a `Vec<bool>` beside each
/// saying whether that entry was ever written: a branch to a number the list
/// never labels is a [`AsmError::MissingLabel`], not offset zero. The four
/// singleton positions — the exit epilogue, the retpoline, the dispatcher
/// slot and the helper table — are a field and a flag apiece.
struct Labels {
  pc: Vec<u32>,
  pc_set: Vec<bool>,
  local: Vec<u32>,
  local_set: Vec<bool>,
  exit: u32,
  exit_set: bool,
  retpoline: u32,
  retpoline_set: bool,
  dispatcher: u32,
  dispatcher_set: bool,
  helper_table: u32,
  helper_table_set: bool,
}

/// What a primitive labels: a tag and, for the two numbered kinds, the
/// number. `0` is "labels nothing". A function of the matched value, so that
/// the walk branches on a number once rather than matching twice.
fn label_kind(p: &PInsn) -> (u8, u32) {
  match p {
    PInsn::PcLabel(pc) => (1, *pc),
    PInsn::Local(n) => (2, *n),
    PInsn::ExitLabel => (3, 0),
    PInsn::RetpolineLabel => (4, 0),
    PInsn::DispatcherSlot { addr: _ } => (5, 0),
    PInsn::HelperTable => (6, 0),
    _ => (0, 0),
  }
}

/// One past the largest slot number any [`PInsn::PcLabel`] carries.
fn pc_label_count(code: &[PInsn]) -> usize {
  let mut n: usize = 0;
  let mut i: usize = 0;
  while i < code.len() {
    let (kind, number) = label_kind(&code[i]);
    if kind == 1 {
      let k = number as usize + 1;
      if k > n {
        n = k;
      }
    }
    i += 1;
  }
  n
}

/// One past the largest number any [`PInsn::Local`] carries.
fn local_label_count(code: &[PInsn]) -> usize {
  let mut n: usize = 0;
  let mut i: usize = 0;
  while i < code.len() {
    let (kind, number) = label_kind(&code[i]);
    if kind == 2 {
      let k = number as usize + 1;
      if k > n {
        n = k;
      }
    }
    i += 1;
  }
  n
}

/// Records every label's offset, reading the starts pass one computed.
fn collect_labels(code: &[PInsn], starts: &[u32]) -> Labels {
  let np = pc_label_count(code);
  let nl = local_label_count(code);
  let mut labels = Labels {
    pc: vec![0; np],
    pc_set: vec![false; np],
    local: vec![0; nl],
    local_set: vec![false; nl],
    exit: 0,
    exit_set: false,
    retpoline: 0,
    retpoline_set: false,
    dispatcher: 0,
    dispatcher_set: false,
    helper_table: 0,
    helper_table_set: false,
  };
  let n = code.len();
  if starts.len() > n {
    let mut i: usize = 0;
    while i < n {
      let here = starts[i];
      let (kind, number) = label_kind(&code[i]);
      let k = number as usize;
      if kind == 1 {
        if k < np {
          labels.pc[k] = here;
          labels.pc_set[k] = true;
        }
      } else if kind == 2 {
        if k < nl {
          labels.local[k] = here;
          labels.local_set[k] = true;
        }
      } else if kind == 3 {
        labels.exit = here;
        labels.exit_set = true;
      } else if kind == 4 {
        labels.retpoline = here;
        labels.retpoline_set = true;
      } else if kind == 5 {
        // The first dispatcher slot is the one the RIP-relative load names.
        if !labels.dispatcher_set {
          labels.dispatcher = here;
          labels.dispatcher_set = true;
        }
      } else if kind == 6 && !labels.helper_table_set {
        labels.helper_table = here;
        labels.helper_table_set = true;
      }
      i += 1;
    }
  }
  labels
}

// ---------------------------------------------------------------------------
// Pass two: the displacements
// ---------------------------------------------------------------------------

/// Where a branch target landed, or `-1` when the list never labelled it.
/// An `i64` rather than an `Option<u32>`: offsets are never negative, and the
/// sign is what the callers test.
fn target_loc(labels: &Labels, target: PTarget) -> i64 {
  match target {
    PTarget::Pc(pc) => {
      let k = pc as usize;
      if k < labels.pc.len() {
        if labels.pc_set[k] {
          labels.pc[k] as i64
        } else {
          -1
        }
      } else {
        -1
      }
    }
    PTarget::Exit => {
      if labels.exit_set {
        labels.exit as i64
      } else {
        -1
      }
    }
    PTarget::Retpoline => {
      if labels.retpoline_set {
        labels.retpoline as i64
      } else {
        -1
      }
    }
    PTarget::Local(n) => {
      let k = n as usize;
      if k < labels.local.len() {
        if labels.local_set[k] {
          labels.local[k] as i64
        } else {
          -1
        }
      } else {
        -1
      }
    }
  }
}

/// Overwrites four bytes at `at`, little-endian.
fn put32(out: &mut Vec<u8>, at: usize, v: u32) {
  if at + 4 <= out.len() {
    out[at] = (v & 0xff) as u8;
    out[at + 1] = ((v >> 8) & 0xff) as u8;
    out[at + 2] = ((v >> 16) & 0xff) as u8;
    out[at + 3] = ((v >> 24) & 0xff) as u8;
  }
}

/// Overwrites one byte at `at`.
fn put8(out: &mut Vec<u8>, at: usize, v: u8) {
  if at < out.len() {
    out[at] = v;
  }
}

/// Writes the four-byte displacement at `site` (an offset into the assembled
/// function, `base` bytes into `out`) reaching `loc`.
///
/// The value is `loc - (site + 4)` in two's complement, computed in `i64` and
/// truncated by the cast: an `i64` difference of two offsets under `2^32` is
/// exact, and the low thirty-two bits of it are what the instruction carries.
fn write_rel32(out: &mut Vec<u8>, base: usize, site: usize, loc: i64) -> u32 {
  let mut err = ERR_NONE;
  if loc < 0 {
    err = ERR_MISSING;
  } else {
    let rel = loc - (site as i64 + 4);
    put32(out, base + site, rel as u32);
  }
  err
}

/// Writes the one-byte displacement at `site` reaching `loc`, or refuses.
///
/// Unlike the fixup pass this replaces, the range check covers every rel8
/// site rather than only the padded one: a `Jcc8` or `Jmp8` that does not
/// reach is a refusal rather than a truncated byte. Every such branch is
/// inside one macro's expansion, so none of them is near the limit.
fn write_rel8(out: &mut Vec<u8>, base: usize, site: usize, loc: i64) -> u32 {
  let mut err = ERR_NONE;
  if loc < 0 {
    err = ERR_MISSING;
  } else {
    let rel = loc - (site as i64 + 1);
    if rel < -128 || rel > 127 {
      err = ERR_RANGE;
    } else {
      put8(out, base + site, rel as u8);
    }
  }
  err
}

/// Patches the displacement of the primitive that starts at `here`, which
/// [`encode_one`] has just appended to `out`.
fn patch(labels: &Labels, out: &mut Vec<u8>, base: usize, here: usize, p: &PInsn) -> u32 {
  let insn = *p;
  match insn {
    PInsn::Jcc { cc: _, target } => {
      let loc = target_loc(labels, target);
      write_rel32(out, base, here + 2, loc)
    }
    PInsn::Jmp { target } => {
      let loc = target_loc(labels, target);
      write_rel32(out, base, here + 1, loc)
    }
    PInsn::Call { target } => {
      let loc = target_loc(labels, target);
      write_rel32(out, base, here + 1, loc)
    }
    PInsn::JmpNear { target } => {
      let loc = target_loc(labels, target);
      write_rel8(out, base, here + 1, loc)
    }
    PInsn::Jcc8 { cc: _, target } => {
      let loc = target_loc(labels, PTarget::Local(target));
      write_rel8(out, base, here + 1, loc)
    }
    PInsn::Jmp8 { target } => {
      let loc = target_loc(labels, PTarget::Local(target));
      write_rel8(out, base, here + 1, loc)
    }
    PInsn::RipLoadDispatcher { dst: _ } => {
      let loc = if labels.dispatcher_set {
        labels.dispatcher as i64
      } else {
        -1
      };
      write_rel32(out, base, here + 3, loc)
    }
    PInsn::RipLeaHelperTable { dst: _ } => {
      let loc = if labels.helper_table_set {
        labels.helper_table as i64
      } else {
        -1
      };
      write_rel32(out, base, here + 3, loc)
    }
    _ => ERR_NONE,
  }
}

/// Assembles a primitive list, appending its bytes to `out`.
///
/// Pass one measures every primitive with [`size_of`] and records where each
/// label landed; pass two encodes each primitive with [`encode_one`] and
/// patches the displacement it carries. Offsets are relative to the start of
/// the appended region, so `out` is normally empty on the way in.
pub fn assemble(code: &[PInsn], out: &mut Vec<u8>) -> Result<(), AsmError> {
  let mut starts: Vec<u32> = Vec::new();
  offsets(code, &mut starts);
  let labels = collect_labels(code, &starts);

  let base = out.len();
  let n = code.len();
  let mut err: u32 = ERR_NONE;
  // `offsets` pushes one entry per primitive and one past the end, so the
  // guard always holds; it is what makes the indexing below total.
  if starts.len() > n {
    let mut i: usize = 0;
    while i < n && err == ERR_NONE {
      let p = code[i];
      let here = starts[i] as usize;
      encode_one(&p, out);
      err = patch(&labels, out, base, here, &p);
      i += 1;
    }
  }

  if err == ERR_MISSING {
    Err(AsmError::MissingLabel)
  } else if err == ERR_RANGE {
    Err(AsmError::RelocationOutOfRange)
  } else {
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use super::super::x64_ir::{cc, RAX};

  /// The bytes one list assembles to.
  fn bytes_of(code: &[PInsn]) -> Vec<u8> {
    let mut out = Vec::new();
    assemble(code, &mut out).expect("the list assembles");
    out
  }

  #[test]
  fn offsets_are_the_running_sum_of_the_sizes() {
    let code = vec![
      PInsn::PcLabel(0),
      PInsn::Push(RAX),
      PInsn::Ret,
      PInsn::Jmp {
        target: PTarget::Pc(0),
      },
      PInsn::DispatcherSlot { addr: 7 },
    ];
    let mut starts = Vec::new();
    offsets(&code, &mut starts);
    assert_eq!(starts, vec![0, 0, 1, 2, 7, 15]);
    assert_eq!(bytes_of(&code).len(), 15);
  }

  #[test]
  fn a_rel32_is_measured_from_just_past_itself() {
    // `jmp` back to the top of the function: the displacement is negative and
    // two's complement, and the target is the label's offset.
    let code = vec![
      PInsn::PcLabel(0),
      PInsn::Ret,
      PInsn::Jmp {
        target: PTarget::Pc(0),
      },
    ];
    let bytes = bytes_of(&code);
    assert_eq!(bytes, vec![0xc3, 0xe9, 0xfa, 0xff, 0xff, 0xff]);

    // Forward, to the exit epilogue.
    let code = vec![
      PInsn::Jcc {
        cc: cc::E,
        target: PTarget::Exit,
      },
      PInsn::Ret,
      PInsn::ExitLabel,
      PInsn::Ret,
    ];
    let bytes = bytes_of(&code);
    assert_eq!(bytes, vec![0x0f, 0x84, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3]);
  }

  #[test]
  fn a_rel8_is_measured_from_just_past_itself_and_keeps_its_padding() {
    let code = vec![
      PInsn::JmpNear {
        target: PTarget::Local(0),
      },
      PInsn::Ret,
      PInsn::Local(0),
      PInsn::Ret,
    ];
    // Five bytes for the near jump, three of them dead.
    assert_eq!(bytes_of(&code), vec![0xeb, 0x04, 0, 0, 0, 0xc3, 0xc3]);

    // Backwards, through the short forms.
    let code = vec![
      PInsn::Local(0),
      PInsn::Ret,
      PInsn::Jmp8 { target: 0 },
      PInsn::Jcc8 {
        cc: cc::NE,
        target: 0,
      },
    ];
    assert_eq!(bytes_of(&code), vec![0xc3, 0xeb, 0xfd, 0x75, 0xfb]);
  }

  #[test]
  fn the_rip_relative_forms_reach_the_trailer() {
    let code = vec![
      PInsn::RipLeaHelperTable { dst: RAX },
      PInsn::RipLoadDispatcher { dst: RAX },
      PInsn::DispatcherSlot { addr: 0 },
      PInsn::HelperTable,
    ];
    let bytes = bytes_of(&code);
    // The `lea` ends at 7 and the table starts at 22: eight bytes of
    // dispatcher slot after the two seven-byte instructions.
    assert_eq!(&bytes[3..7], &[15, 0, 0, 0]);
    // The load ends at 14 and the slot starts at 14.
    assert_eq!(&bytes[10..14], &[0, 0, 0, 0]);
    assert_eq!(bytes.len(), 14 + 8 + HELPER_TABLE_LEN);
  }

  #[test]
  fn a_branch_to_an_unlabelled_slot_is_refused() {
    // The old fixup pass resolved this to offset zero.
    let code = vec![
      PInsn::PcLabel(0),
      PInsn::Jmp {
        target: PTarget::Pc(3),
      },
    ];
    let mut out = Vec::new();
    assert_eq!(assemble(&code, &mut out), Err(AsmError::MissingLabel));

    // Likewise a slot inside the table that was never written.
    let code = vec![
      PInsn::PcLabel(3),
      PInsn::Jmp {
        target: PTarget::Pc(1),
      },
    ];
    let mut out = Vec::new();
    assert_eq!(assemble(&code, &mut out), Err(AsmError::MissingLabel));

    // And the four singletons.
    for target in [PTarget::Exit, PTarget::Retpoline, PTarget::Local(0)] {
      let code = vec![PInsn::Jmp { target }];
      let mut out = Vec::new();
      assert_eq!(assemble(&code, &mut out), Err(AsmError::MissingLabel));
    }
    let mut out = Vec::new();
    assert_eq!(
      assemble(&[PInsn::RipLoadDispatcher { dst: RAX }], &mut out),
      Err(AsmError::MissingLabel)
    );
    let mut out = Vec::new();
    assert_eq!(
      assemble(&[PInsn::RipLeaHelperTable { dst: RAX }], &mut out),
      Err(AsmError::MissingLabel)
    );
  }

  #[test]
  fn a_one_byte_displacement_that_does_not_reach_is_refused() {
    let far = |n: usize, head: PInsn| {
      let mut code = vec![head];
      let mut i = 0;
      while i < n {
        code.push(PInsn::Ret);
        i += 1;
      }
      code.push(PInsn::Local(0));
      code
    };

    // The jump is five bytes and its displacement is measured from the byte
    // after it, so 124 `ret`s still reach and 125 do not.
    let mut out = Vec::new();
    assert_eq!(
      assemble(
        &far(
          124,
          PInsn::JmpNear {
            target: PTarget::Local(0)
          }
        ),
        &mut out
      ),
      Ok(())
    );
    let mut out = Vec::new();
    assert_eq!(
      assemble(
        &far(
          125,
          PInsn::JmpNear {
            target: PTarget::Local(0)
          }
        ),
        &mut out
      ),
      Err(AsmError::RelocationOutOfRange)
    );

    // The short forms are range-checked too, which the fixup pass they
    // replace did not do.
    let mut out = Vec::new();
    assert_eq!(
      assemble(&far(200, PInsn::Jmp8 { target: 0 }), &mut out),
      Err(AsmError::RelocationOutOfRange)
    );
    let mut out = Vec::new();
    assert_eq!(
      assemble(
        &far(
          200,
          PInsn::Jcc8 {
            cc: cc::E,
            target: 0
          }
        ),
        &mut out
      ),
      Err(AsmError::RelocationOutOfRange)
    );
  }
}

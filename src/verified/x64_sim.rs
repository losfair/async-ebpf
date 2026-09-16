//! An executable model of the x86_64 primitive instruction set.
//!
//! [`step`] runs one [`PInsn`] of a list against a [`Sim`]; [`run`] runs up to
//! a step budget. The semantics are those of
//! `lean/AsyncEbpf/X64/Machine.lean`, which is the specification: every
//! deterministic primitive does exactly what `Step` says, with the same
//! 32-bit zero-extension, the same masked shift counts, the same
//! sign-extended displacements and immediates, the same "compares write no
//! register", and the same little-endian memory.
//!
//! Where the Lean model is deliberately loose — the flags a shift, a rotate,
//! a `neg`, a locked read-modify-write or a multiply/divide leaves, all but
//! the zero flag after a `cmpxchg`, and `rax`/`rdx` after `MulDivRcx` — this
//! model is not: it does what the hardware does, so that
//! `src/test/x64_sim_native.rs` can run the same list on a real CPU and
//! compare. Every such choice is one of the choices the Lean model allows, so
//! a refinement proof of this model against `Step` may read them as "some
//! value" and never has to know which.
//!
//! ## The machine
//!
//! Sixteen registers indexed as the ModRM/REX encoding numbers them, the four
//! flags the backend branches on, one mapped byte range
//! `[mem_base, mem_base + mem.len())` — every access outside it is a fault,
//! which is how this model says "the hardware would have trapped" — and a
//! program counter over the *list*, exactly as in Lean: position `i` has
//! native address `code_base + i`, which is what a `Call` pushes and a `Ret`
//! reads back.
//!
//! ## Where this model differs from the hardware, on purpose
//!
//! * `Pop` writes `rsp` last, so `pop rsp` lands at `rsp + 8` rather than at
//!   the popped word. That is what `Step.pop` says, and the backend never
//!   emits `pop rsp`.
//! * `Pushfq` writes the four modelled flags and nothing else, so the word it
//!   leaves in memory is not the hardware's `RFLAGS`. That is `flagsWord`.
//! * `RipLoadDispatcher`, `RipLeaHelperTable` and `CallReg` are
//!   [`Outcome::Unsupported`]: the first two need the list's trailer address
//!   and the helper table's, which are parameters this model does not carry,
//!   and the third leaves the list entirely. `Ud2`, `DispatcherSlot` and
//!   `HelperTable` are [`Outcome::Halt`], as in Lean.
//! * A `Ret` whose word is not `code_base + i` for an `i` inside the list is
//!   [`Outcome::Unsupported`] rather than a return to a caller this model has
//!   no representation for.
//!
//! ## The undefined-flag choices
//!
//! These are the bits the Intel manual calls undefined, measured on the
//! hardware rather than guessed. The Lean model quantifies over all of them.
//!
//! * A shift by a masked count of zero leaves all four flags alone. Otherwise
//!   `cf` is the last bit shifted out, `zf`/`sf` come from the result, and
//!   `of` is the one-bit-shift formula applied to the *source*: `shl` gives
//!   the top two source bits' difference, `shr` the source's sign, `sar`
//!   zero.
//! * `rol r16, 8` sets `cf` from the rotated result's low bit and leaves
//!   `zf`, `sf` and `of` alone.
//! * `mul` sets `cf` and `of` from the high half, `sf` from the low half's
//!   sign, and clears `zf`.
//! * `div` and `idiv` leave all four flags alone.
//! * `neg` leaves the flags of `sub 0, src`, and a locked `add`/`or`/`and`/
//!   `xor` the flags of the same unlocked operation; `xchg` leaves them
//!   alone. `cmpxchg` leaves the flags of `cmp rax, [mem]`.

// Nothing in the runtime executes this model. It is the executable
// counterpart of `lean/AsyncEbpf/X64/Machine.lean`, and its one caller is the
// differential test in `src/test/x64_sim_native.rs`, which only exists on
// x86_64 Linux; any other build sees every item here as unused.
#![allow(dead_code)]

use super::x64_ir::{AluRI, AluRM, AluRR, MulDivKind, PInsn, PTarget, ShiftOp, Size};

/// The machine state: sixteen registers, four flags, one mapped byte range,
/// and a position in the instruction list.
#[cfg_attr(not(feature = "extract"), derive(Debug, Clone))]
pub struct Sim {
  pub regs: [u64; 16],
  pub cf: bool,
  pub zf: bool,
  pub sf: bool,
  pub of: bool,
  /// The address the first byte of `mem` has.
  pub mem_base: u64,
  /// The only mapped memory: `[mem_base, mem_base + mem.len())`.
  pub mem: Vec<u8>,
  /// The position in the list, not a byte offset.
  pub pc: usize,
  /// Position `i` of the list has native address `code_base + i`.
  pub code_base: u64,
}

/// How a step ended.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub enum Outcome {
  /// The state moved on; another instruction of this list is next.
  Next,
  /// `ud2`, the trailer's data, or the end of the list.
  Halt,
  /// An access outside the mapped range, or a divide the hardware would have
  /// trapped on. The state is left as the faulting instruction found it.
  Fault,
  /// A primitive this model does not execute, or a branch to a label the list
  /// does not carry.
  Unsupported,
}

/// The four flags, as one value, so that an instruction computes them once.
#[derive(Copy, Clone)]
pub struct Flags {
  pub cf: bool,
  pub zf: bool,
  pub sf: bool,
  pub of: bool,
}

const MASK64: u128 = 0xffff_ffff_ffff_ffff;
const MASK32: u64 = 0xffff_ffff;

// ---------------------------------------------------------------------------
// Arithmetic, by hand
//
// Aeneas reads `+` and `-` as failing on overflow, so every wrapping operation
// here goes through `u128`/`i128` and a mask instead of through the wrapping
// methods, which have no model either.
// ---------------------------------------------------------------------------

/// `a + b` modulo 2^64.
pub fn add64(a: u64, b: u64) -> u64 {
  (((a as u128) + (b as u128)) & MASK64) as u64
}

/// `a - b` modulo 2^64, as `a + !b + 1`.
pub fn sub64(a: u64, b: u64) -> u64 {
  (((a as u128) + ((!b) as u128) + 1) & MASK64) as u64
}

/// All ones at the operation's width.
fn width_mask(w64: bool) -> u64 {
  if w64 {
    0xffff_ffff_ffff_ffff
  } else {
    MASK32
  }
}

/// The operation's width in bits.
fn width_bits(w64: bool) -> u32 {
  if w64 {
    64
  } else {
    32
  }
}

/// The bytes an operation of the given width touches.
fn op_width(w64: bool) -> usize {
  if w64 {
    8
  } else {
    4
  }
}

/// The sign bit of `v` at the operation's width.
fn msb(w64: bool, v: u64) -> bool {
  if w64 {
    (v >> 63) & 1 == 1
  } else {
    (v >> 31) & 1 == 1
  }
}

/// The low 32 bits.
fn lo32(v: u64) -> u64 {
  v & MASK32
}

/// What an operation of the given width leaves in a 64-bit register: the whole
/// result at 64 bits, its low half zero-extended at 32.
fn wr(w64: bool, v: u64) -> u64 {
  if w64 {
    v
  } else {
    lo32(v)
  }
}

/// `v`, read as a `bits`-bit two's-complement number, widened to 64 bits.
fn sign_extend(v: u64, bits: u32) -> u64 {
  if bits == 0 {
    0
  } else if bits >= 64 {
    v
  } else {
    let m: u64 = (1u64 << bits) - 1;
    let val = v & m;
    if (val >> (bits - 1)) & 1 == 1 {
      val | !m
    } else {
      val
    }
  }
}

/// A sign-extended `i32` displacement or immediate.
fn sx32(imm: i32) -> u64 {
  sign_extend(imm as u32 as u64, 32)
}

/// `v << n` at the operation's width, zero-extended.
fn shl_at(w64: bool, v: u64, n: u32) -> u64 {
  let bits = width_bits(w64);
  if n >= bits {
    0
  } else {
    (v << n) & width_mask(w64)
  }
}

/// `v >> n`, logical, at the operation's width.
fn shr_at(w64: bool, v: u64, n: u32) -> u64 {
  let bits = width_bits(w64);
  let x = v & width_mask(w64);
  if n >= bits {
    0
  } else {
    x >> n
  }
}

/// `v >> n`, arithmetic, at the operation's width, zero-extended.
fn sar_at(w64: bool, v: u64, n: u32) -> u64 {
  let bits = width_bits(w64);
  let x = sign_extend(v, bits) as i64;
  let amt = if n >= 63 { 63 } else { n };
  ((x >> amt) as u64) & width_mask(w64)
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// The flags an `add` (`sub = false`) or a `sub`, `cmp` or `neg`-style
/// subtraction leaves at the named width.
pub fn flags_of_add_sub(w64: bool, sub: bool, a: u64, b: u64) -> Flags {
  let m = width_mask(w64);
  let x = a & m;
  let y = b & m;
  let sx = msb(w64, x);
  let sy = msb(w64, y);
  if sub {
    let r = sub64(x, y) & m;
    let sr = msb(w64, r);
    let differ = sx != sy;
    Flags {
      cf: x < y,
      zf: r == 0,
      sf: sr,
      of: differ && (sr != sx),
    }
  } else {
    let wide = (x as u128) + (y as u128);
    let r = (wide & (m as u128)) as u64;
    let sr = msb(w64, r);
    let same = sx == sy;
    Flags {
      cf: wide > (m as u128),
      zf: r == 0,
      sf: sr,
      of: same && (sr != sx),
    }
  }
}

/// The flags `and`, `or`, `xor` and `test` leave.
pub fn flags_of_logic(w64: bool, r: u64) -> Flags {
  let v = r & width_mask(w64);
  Flags {
    cf: false,
    zf: v == 0,
    sf: msb(w64, v),
    of: false,
  }
}

/// The word `pushfq` pushes, as far as this model tracks it.
fn flags_word(f: Flags) -> u64 {
  let a: u64 = if f.cf { 1 } else { 0 };
  let b: u64 = if f.zf { 0x40 } else { 0 };
  let c: u64 = if f.sf { 0x80 } else { 0 };
  let d: u64 = if f.of { 0x800 } else { 0 };
  a | b | c | d
}

/// The flags `popfq` takes from a word.
fn flags_of_word(v: u64) -> Flags {
  Flags {
    cf: (v >> 0) & 1 == 1,
    zf: (v >> 6) & 1 == 1,
    sf: (v >> 7) & 1 == 1,
    of: (v >> 11) & 1 == 1,
  }
}

/// A condition code, as the low byte of the two-byte `jcc`/`cmovcc` opcode. A
/// byte the backend never emits is never taken.
pub fn cond(cc: u8, f: Flags) -> bool {
  if cc == 0x82 {
    f.cf
  } else if cc == 0x83 {
    !f.cf
  } else if cc == 0x84 {
    f.zf
  } else if cc == 0x85 {
    !f.zf
  } else if cc == 0x86 {
    f.cf || f.zf
  } else if cc == 0x87 {
    !f.cf && !f.zf
  } else if cc == 0x8c {
    f.sf != f.of
  } else if cc == 0x8d {
    f.sf == f.of
  } else if cc == 0x8e {
    let ord = f.sf != f.of;
    f.zf || ord
  } else if cc == 0x8f {
    let ord = f.sf == f.of;
    !f.zf && ord
  } else {
    false
  }
}

// ---------------------------------------------------------------------------
// The state
// ---------------------------------------------------------------------------

const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RSP: u8 = 4;

/// A register, numbered as the encoding numbers it. The encoder keeps only the
/// low four bits of a register number, so this does too.
pub fn reg(s: &Sim, r: u8) -> u64 {
  s.regs[(r & 15) as usize]
}

fn set_reg(s: &mut Sim, r: u8, v: u64) {
  s.regs[(r & 15) as usize] = v;
}

fn get_flags(s: &Sim) -> Flags {
  Flags {
    cf: s.cf,
    zf: s.zf,
    sf: s.sf,
    of: s.of,
  }
}

fn set_flags(s: &mut Sim, f: Flags) {
  s.cf = f.cf;
  s.zf = f.zf;
  s.sf = f.sf;
  s.of = f.of;
}

/// `[base + disp]`, with the displacement sign-extended.
fn addr(s: &Sim, base: u8, disp: i32) -> u64 {
  add64(reg(s, base), sx32(disp))
}

/// Whether `n` bytes at `a` are inside the one mapped range.
fn in_bounds(s: &Sim, a: u64, n: usize) -> bool {
  let lo = s.mem_base as u128;
  let hi = lo + (s.mem.len() as u128);
  let start = a as u128;
  let end = start + (n as u128);
  start >= lo && end <= hi
}

/// Reads `n` little-endian bytes, zero-extended. The flag is false, and the
/// value zero, when the access leaves the mapped range.
fn load_mem(s: &Sim, a: u64, n: usize) -> (bool, u64) {
  let ok = in_bounds(s, a, n);
  let off = if ok { (a - s.mem_base) as usize } else { 0 };
  let mut v: u64 = 0;
  let mut i: usize = 0;
  while ok && i < n {
    let idx = off + i;
    if idx < s.mem.len() {
      v |= (s.mem[idx] as u64) << (8 * i);
    }
    i += 1;
  }
  (ok, v)
}

/// Writes the `n` low bytes of `v`, little-endian. Writes nothing and returns
/// false when the access leaves the mapped range.
fn store_mem(s: &mut Sim, a: u64, n: usize, v: u64) -> bool {
  let ok = in_bounds(s, a, n);
  let off = if ok { (a - s.mem_base) as usize } else { 0 };
  let len = s.mem.len();
  let mut i: usize = 0;
  while ok && i < n {
    let idx = off + i;
    if idx < len {
      s.mem[idx] = ((v >> (8 * i)) & 0xff) as u8;
    }
    i += 1;
  }
  ok
}

/// The bytes a `Size` names, or zero for a width the backend never emits.
fn size_bytes(size: Size) -> usize {
  if size == 1 {
    1
  } else if size == 2 {
    2
  } else if size == 4 {
    4
  } else if size == 8 {
    8
  } else {
    0
  }
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

/// Whether an instruction is the label a target names.
fn is_target(t: PTarget, i: &PInsn) -> bool {
  match t {
    PTarget::Pc(p) => match i {
      PInsn::PcLabel(q) => p == *q,
      _ => false,
    },
    PTarget::Exit => match i {
      PInsn::ExitLabel => true,
      _ => false,
    },
    PTarget::Retpoline => match i {
      PInsn::RetpolineLabel => true,
      _ => false,
    },
    PTarget::Local(n) => match i {
      PInsn::Local(m) => n == *m,
      _ => false,
    },
  }
}

/// Where a branch target sits in the list: the position of the first label
/// that matches it, or `code.len()` when the list carries no such label —
/// the encoder's unresolved fixup, made into a stuck state.
///
/// The shape is [`x64_ir::unmap_register`](super::x64_ir::unmap_register)'s,
/// which is the shape the translation copes with: one index, one accumulator
/// that starts at the "nothing found" sentinel, no early return, and the
/// accumulator never read inside the loop — so the loop's state is one
/// unchanging shape and the fixed point is immediate. Keeping the *first*
/// match, which is what `Machine.lean`'s `pos` names, is what the reversed
/// index is for: the scan walks the list backwards, so the surviving write is
/// the earliest position that matches.
fn find_label(code: &[PInsn], t: PTarget) -> usize {
  let n = code.len();
  let mut i: usize = 0;
  let mut at: usize = n;
  while i < n {
    let j = n - 1 - i;
    if is_target(t, &code[j]) {
      at = j;
    }
    i += 1;
  }
  at
}

/// Jumps to `t`, or reports a target the list does not carry.
fn branch(code: &[PInsn], s: &mut Sim, t: PTarget) -> Outcome {
  let n = code.len();
  let at = find_label(code, t);
  if at < n {
    s.pc = at;
    Outcome::Next
  } else {
    Outcome::Unsupported
  }
}

// ---------------------------------------------------------------------------
// One primitive per family
// ---------------------------------------------------------------------------

/// `Alu`: register-to-register arithmetic. `Cmp` and `Test` write no register,
/// `Mov` writes no flag.
fn alu_rr(s: &mut Sim, w64: bool, op: AluRR, src: u8, dst: u8) -> Outcome {
  let a = reg(s, dst);
  let b = reg(s, src);
  match op {
    AluRR::Add => {
      let f = flags_of_add_sub(w64, false, a, b);
      set_reg(s, dst, wr(w64, add64(a, b)));
      set_flags(s, f);
    }
    AluRR::Sub => {
      let f = flags_of_add_sub(w64, true, a, b);
      set_reg(s, dst, wr(w64, sub64(a, b)));
      set_flags(s, f);
    }
    AluRR::Or => {
      let r = a | b;
      set_reg(s, dst, wr(w64, r));
      let f = flags_of_logic(w64, r);
      set_flags(s, f);
    }
    AluRR::And => {
      let r = a & b;
      set_reg(s, dst, wr(w64, r));
      let f = flags_of_logic(w64, r);
      set_flags(s, f);
    }
    AluRR::Xor => {
      let r = a ^ b;
      set_reg(s, dst, wr(w64, r));
      let f = flags_of_logic(w64, r);
      set_flags(s, f);
    }
    AluRR::Mov => set_reg(s, dst, wr(w64, b)),
    AluRR::Cmp => {
      let f = flags_of_add_sub(w64, true, a, b);
      set_flags(s, f);
    }
    AluRR::Test => {
      let f = flags_of_logic(w64, a & b);
      set_flags(s, f);
    }
  }
  s.pc += 1;
  Outcome::Next
}

/// `AluImm`: the immediate is sign-extended at 64 bits and taken as it stands
/// at 32, where only its low half is read anyway.
fn alu_imm(s: &mut Sim, w64: bool, op: AluRI, dst: u8, imm: i32) -> Outcome {
  let a = reg(s, dst);
  let b = if w64 { sx32(imm) } else { imm as u32 as u64 };
  match op {
    AluRI::Add => {
      let f = flags_of_add_sub(w64, false, a, b);
      set_reg(s, dst, wr(w64, add64(a, b)));
      set_flags(s, f);
    }
    AluRI::Sub => {
      let f = flags_of_add_sub(w64, true, a, b);
      set_reg(s, dst, wr(w64, sub64(a, b)));
      set_flags(s, f);
    }
    AluRI::Or => {
      let r = a | b;
      set_reg(s, dst, wr(w64, r));
      let f = flags_of_logic(w64, r);
      set_flags(s, f);
    }
    AluRI::And => {
      let r = a & b;
      set_reg(s, dst, wr(w64, r));
      let f = flags_of_logic(w64, r);
      set_flags(s, f);
    }
    AluRI::Xor => {
      let r = a ^ b;
      set_reg(s, dst, wr(w64, r));
      let f = flags_of_logic(w64, r);
      set_flags(s, f);
    }
    AluRI::Mov => set_reg(s, dst, wr(w64, b)),
    AluRI::Cmp => {
      let f = flags_of_add_sub(w64, true, a, b);
      set_flags(s, f);
    }
    AluRI::Test => {
      let f = flags_of_logic(w64, a & b);
      set_flags(s, f);
    }
  }
  s.pc += 1;
  Outcome::Next
}

/// The shift count x86 uses: the low byte, masked to the width.
fn shift_amount(w64: bool, n: u8) -> u32 {
  let bits = width_bits(w64);
  (n as u32) & (bits - 1)
}

/// `shl`, `shr` (logical) and `sar` (arithmetic at the width), with the 32-bit
/// forms computing on the low half and zero-extending.
fn shift_result(w64: bool, op: ShiftOp, v: u64, amt: u32) -> u64 {
  match op {
    ShiftOp::Shl => shl_at(w64, v, amt),
    ShiftOp::Shr => shr_at(w64, v, amt),
    ShiftOp::Sar => sar_at(w64, v, amt),
  }
}

/// The flags a shift by a *non-zero* masked count leaves. `cf` is the last bit
/// shifted out; `of` is the one-bit formula read off the source, which is what
/// the hardware computes whatever the count is.
/// Bit zero of `v`, as a boolean. A comparison written as a value extracts
/// as a proposition; a branch extracts as a boolean.
fn low_bit(v: u64) -> bool {
  if v & 1 == 1 {
    true
  } else {
    false
  }
}

fn shift_flags(w64: bool, op: ShiftOp, src: u64, res: u64, amt: u32) -> Flags {
  let bits = width_bits(w64);
  let x = src & width_mask(w64);
  let cf = match op {
    ShiftOp::Shl => low_bit(x >> (bits - amt)),
    ShiftOp::Shr => low_bit(x >> (amt - 1)),
    ShiftOp::Sar => low_bit(x >> (amt - 1)),
  };
  let of = match op {
    ShiftOp::Shl => msb(w64, x) != low_bit(x >> (bits - 2)),
    ShiftOp::Shr => msb(w64, x),
    ShiftOp::Sar => false,
  };
  Flags {
    cf,
    zf: (res & width_mask(w64)) == 0,
    sf: msb(w64, res),
    of,
  }
}

/// `ShiftImm` and `ShiftCl`, which differ only in where the count comes from.
/// A masked count of zero still writes the destination — so the 32-bit form
/// still zero-extends — and leaves every flag alone.
fn shift(s: &mut Sim, w64: bool, op: ShiftOp, dst: u8, count: u8) -> Outcome {
  let amt = shift_amount(w64, count);
  let src = reg(s, dst);
  let res = shift_result(w64, op, src, amt);
  set_reg(s, dst, wr(w64, res));
  if amt != 0 {
    let f = shift_flags(w64, op, src, res, amt);
    set_flags(s, f);
  }
  s.pc += 1;
  Outcome::Next
}

/// `neg`: the result and the flags of `sub 0, dst`.
fn neg(s: &mut Sim, w64: bool, dst: u8) -> Outcome {
  let v = reg(s, dst);
  let f = flags_of_add_sub(w64, true, 0, v);
  set_reg(s, dst, wr(w64, sub64(0, v)));
  set_flags(s, f);
  s.pc += 1;
  Outcome::Next
}

/// `mul rcx`: `rdx:rax = rax * rcx`, unsigned, at the width. `cf` and `of` say
/// the high half is non-zero; `sf` is the low half's sign and `zf` is clear,
/// which is what the hardware leaves where the manual says nothing.
fn mul_rcx(s: &mut Sim, w64: bool) -> Outcome {
  let a = reg(s, RAX);
  let c = reg(s, RCX);
  let lo: u64;
  let hi: u64;
  if w64 {
    let p = (a as u128) * (c as u128);
    lo = (p & MASK64) as u64;
    hi = ((p >> 64) & MASK64) as u64;
  } else {
    let p = lo32(a) * lo32(c);
    lo = p & MASK32;
    hi = (p >> 32) & MASK32;
  }
  set_reg(s, RAX, lo);
  set_reg(s, RDX, hi);
  let f = Flags {
    cf: hi != 0,
    zf: false,
    sf: msb(w64, lo),
    of: hi != 0,
  };
  set_flags(s, f);
  s.pc += 1;
  Outcome::Next
}

/// `div rcx` / `idiv rcx`: the quotient in `rax`, the remainder in `rdx`, both
/// at the width. A zero divisor and a quotient that does not fit are the two
/// `#DE` cases, and both are [`Outcome::Fault`]. The flags are left alone,
/// which is what the hardware does with the ones the manual calls undefined.
fn div_rcx(s: &mut Sim, w64: bool, signed: bool) -> Outcome {
  let a = reg(s, RAX);
  let d = reg(s, RDX);
  let c = reg(s, RCX);
  let mut quo: u64 = 0;
  let mut rem: u64 = 0;
  let mut ok = false;
  if signed {
    let dividend: i128 = if w64 {
      (((d as u128) << 64) | (a as u128)) as i128
    } else {
      ((lo32(d) << 32) | lo32(a)) as i64 as i128
    };
    let divisor: i128 = if w64 {
      (c as i64) as i128
    } else {
      (lo32(c) as u32 as i32) as i128
    };
    let lo_lim: i128 = if w64 {
      i64::MIN as i128
    } else {
      i32::MIN as i128
    };
    let hi_lim: i128 = if w64 {
      i64::MAX as i128
    } else {
      i32::MAX as i128
    };
    // `i128::MIN / -1` is the one division that would itself overflow; it is
    // also one of the quotients the hardware refuses, so it never divides.
    let overflows = divisor == -1 && dividend == i128::MIN;
    if divisor != 0 && !overflows {
      let q = dividend / divisor;
      if q >= lo_lim && q <= hi_lim {
        let r = dividend - q * divisor;
        quo = wr(w64, (q as i64) as u64);
        rem = wr(w64, (r as i64) as u64);
        ok = true;
      }
    }
  } else {
    let dividend: u128 = if w64 {
      ((d as u128) << 64) | (a as u128)
    } else {
      ((lo32(d) << 32) | lo32(a)) as u128
    };
    let divisor: u128 = if w64 { c as u128 } else { lo32(c) as u128 };
    let hi_lim: u128 = if w64 { MASK64 } else { MASK32 as u128 };
    if divisor != 0 {
      let q = dividend / divisor;
      if q <= hi_lim {
        let r = dividend - q * divisor;
        quo = (q & MASK64) as u64;
        rem = (r & MASK64) as u64;
        ok = true;
      }
    }
  }
  if ok {
    set_reg(s, RAX, quo);
    set_reg(s, RDX, rem);
    s.pc += 1;
    Outcome::Next
  } else {
    Outcome::Fault
  }
}

/// `movsx`, from 8, 16 or 32 source bits. A `from` the backend never emits
/// moves the source unchanged.
fn movsx(s: &mut Sim, bits: u8, w64: bool, src: u8, dst: u8) -> Outcome {
  let v = reg(s, src);
  let x = if bits == 8 {
    sign_extend(v, 8)
  } else if bits == 16 {
    sign_extend(v, 16)
  } else if bits == 32 {
    sign_extend(v, 32)
  } else {
    v
  };
  set_reg(s, dst, wr(w64, x));
  s.pc += 1;
  Outcome::Next
}

/// Reverses the low `bytes` bytes and zero-extends.
fn bswap_bytes(bytes: u32, w: u64) -> u64 {
  let mut acc: u64 = 0;
  let mut i: u32 = 0;
  while i < bytes && i < 8 {
    let byte = (w >> (8 * i)) & 0xff;
    acc |= byte << (8 * (bytes - 1 - i));
    i += 1;
  }
  acc
}

fn bswap(s: &mut Sim, w64: bool, dst: u8) -> Outcome {
  let v = reg(s, dst);
  let r = if w64 {
    bswap_bytes(8, v)
  } else {
    bswap_bytes(4, v)
  };
  set_reg(s, dst, r);
  s.pc += 1;
  Outcome::Next
}

/// `rol r16, 8`: the low sixteen bits rotate, the upper forty-eight stay. The
/// carry takes the rotated result's low bit; the other three flags stay as
/// they were, which is what the hardware does for a count the manual leaves
/// undefined.
fn rol16(s: &mut Sim, dst: u8) -> Outcome {
  let v = reg(s, dst);
  let lo = v & 0xffff;
  let rot = ((lo << 8) | (lo >> 8)) & 0xffff;
  set_reg(s, dst, (v & 0xffff_ffff_ffff_0000) | rot);
  s.cf = rot & 1 == 1;
  s.pc += 1;
  Outcome::Next
}

/// The register-form opcode byte a `lock` prefix carries, as an operation. A
/// byte the backend never emits writes the value back unchanged and leaves
/// the flags alone.
fn lock_op(op: u8, a: u64, b: u64) -> u64 {
  if op == 0x01 {
    add64(a, b)
  } else if op == 0x09 {
    a | b
  } else if op == 0x21 {
    a & b
  } else if op == 0x31 {
    a ^ b
  } else {
    a
  }
}

/// `lock op [base + disp], src`, at the operation's width, with the flags the
/// same operation would leave without the prefix.
fn lock_alu(s: &mut Sim, op: u8, w64: bool, src: u8, base: u8, disp: i32) -> Outcome {
  let a = addr(s, base, disp);
  let n = op_width(w64);
  let (ok, cur) = load_mem(s, a, n);
  if ok {
    let b = reg(s, src);
    let v = lock_op(op, cur, b);
    store_mem(s, a, n, v);
    if op == 0x01 {
      let f = flags_of_add_sub(w64, false, cur, b);
      set_flags(s, f);
    } else if op == 0x09 || op == 0x21 || op == 0x31 {
      let f = flags_of_logic(w64, v);
      set_flags(s, f);
    }
    s.pc += 1;
    Outcome::Next
  } else {
    Outcome::Fault
  }
}

/// `lock cmpxchg [base + disp], src`: the accumulator decides, and the flags
/// are those of `cmp rax, [base + disp]`.
fn cmpxchg(s: &mut Sim, w64: bool, src: u8, base: u8, disp: i32) -> Outcome {
  let a = addr(s, base, disp);
  let n = op_width(w64);
  let (ok, cur) = load_mem(s, a, n);
  if ok {
    let acc = wr(w64, reg(s, RAX));
    let f = flags_of_add_sub(w64, true, acc, cur);
    if cur == acc {
      let v = reg(s, src);
      store_mem(s, a, n, v);
    } else {
      set_reg(s, RAX, cur);
    }
    set_flags(s, f);
    s.pc += 1;
    Outcome::Next
  } else {
    Outcome::Fault
  }
}

/// `xchg [base + disp], src`; no flag moves.
fn xchg(s: &mut Sim, w64: bool, src: u8, base: u8, disp: i32) -> Outcome {
  let a = addr(s, base, disp);
  let n = op_width(w64);
  let (ok, cur) = load_mem(s, a, n);
  if ok {
    let v = reg(s, src);
    store_mem(s, a, n, v);
    set_reg(s, src, cur);
    s.pc += 1;
    Outcome::Next
  } else {
    Outcome::Fault
  }
}

/// `AluRM`: the bounds-check forms, all at 64 bits.
fn alu_rm(s: &mut Sim, op: AluRM, r: u8, base: u8, disp: i32) -> Outcome {
  let a = addr(s, base, disp);
  let (ok, v) = load_mem(s, a, 8);
  if ok {
    let x = reg(s, r);
    match op {
      AluRM::Sub => {
        let f = flags_of_add_sub(true, true, x, v);
        set_reg(s, r, sub64(x, v));
        set_flags(s, f);
      }
      AluRM::Add => {
        let f = flags_of_add_sub(true, false, x, v);
        set_reg(s, r, add64(x, v));
        set_flags(s, f);
      }
      AluRM::Or => {
        let y = x | v;
        set_reg(s, r, y);
        let f = flags_of_logic(true, y);
        set_flags(s, f);
      }
      AluRM::CmpMR => {
        let f = flags_of_add_sub(true, true, v, x);
        set_flags(s, f);
      }
      AluRM::CmpRM => {
        let f = flags_of_add_sub(true, true, x, v);
        set_flags(s, f);
      }
    }
    s.pc += 1;
    Outcome::Next
  } else {
    Outcome::Fault
  }
}

/// A guest load of `size` bytes, zero- or sign-extended into the destination.
/// The sign-extending eight-byte form encodes nothing, so it does nothing.
fn load(s: &mut Sim, size: Size, sx: bool, base: u8, dst: u8, disp: i32) -> Outcome {
  let n = size_bytes(size);
  if sx && n == 8 {
    s.pc += 1;
    Outcome::Next
  } else if n == 0 {
    Outcome::Unsupported
  } else {
    let a = addr(s, base, disp);
    let (ok, v) = load_mem(s, a, n);
    if ok {
      let x = if sx {
        sign_extend(v, 8 * (n as u32))
      } else {
        v
      };
      set_reg(s, dst, x);
      s.pc += 1;
      Outcome::Next
    } else {
      Outcome::Fault
    }
  }
}

/// A guest store of a register's low `size` bytes.
fn store(s: &mut Sim, size: Size, src: u8, base: u8, disp: i32) -> Outcome {
  let n = size_bytes(size);
  if n == 0 {
    Outcome::Unsupported
  } else {
    let a = addr(s, base, disp);
    let v = reg(s, src);
    let ok = store_mem(s, a, n, v);
    if ok {
      s.pc += 1;
      Outcome::Next
    } else {
      Outcome::Fault
    }
  }
}

/// A guest store of an immediate: sign-extended to a word first, then
/// truncated, so the eight-byte form stores `imm32` sign-extended.
fn store_imm(s: &mut Sim, size: Size, base: u8, disp: i32, imm: i32) -> Outcome {
  let n = size_bytes(size);
  if n == 0 {
    Outcome::Unsupported
  } else {
    let a = addr(s, base, disp);
    let ok = store_mem(s, a, n, sx32(imm));
    if ok {
      s.pc += 1;
      Outcome::Next
    } else {
      Outcome::Fault
    }
  }
}

/// `push`: `rsp` moves before the store.
fn push(s: &mut Sim, v: u64) -> Outcome {
  let top = sub64(reg(s, RSP), 8);
  let ok = store_mem(s, top, 8, v);
  if ok {
    set_reg(s, RSP, top);
    Outcome::Next
  } else {
    Outcome::Fault
  }
}

/// `pop`: the word is read, then `rsp` moves, then the destination is
/// written — so `pop rsp` ends holding the popped word, as the hardware and
/// `Step.pop` in the Lean model both say.
fn pop(s: &mut Sim, r: u8) -> Outcome {
  let top = reg(s, RSP);
  let (ok, v) = load_mem(s, top, 8);
  if ok {
    set_reg(s, RSP, add64(top, 8));
    set_reg(s, r, v);
    s.pc += 1;
    Outcome::Next
  } else {
    Outcome::Fault
  }
}

/// `ret`: the popped word must be a position of this list.
fn ret(code: &[PInsn], s: &mut Sim) -> Outcome {
  let top = reg(s, RSP);
  let (ok, v) = load_mem(s, top, 8);
  if !ok {
    Outcome::Fault
  } else {
    let n = code.len() as u64;
    let at = if v >= s.code_base { v - s.code_base } else { n };
    if at < n {
      set_reg(s, RSP, add64(top, 8));
      s.pc = at as usize;
      Outcome::Next
    } else {
      Outcome::Unsupported
    }
  }
}

/// `call` to a label: push `code_base + (pc + 1)` and go.
fn call(code: &[PInsn], s: &mut Sim, t: PTarget) -> Outcome {
  let n = code.len();
  let at = find_label(code, t);
  if at < n {
    let ret_addr = add64(s.code_base, (s.pc + 1) as u64);
    let pushed = push(s, ret_addr);
    match pushed {
      Outcome::Next => {
        s.pc = at;
        Outcome::Next
      }
      _ => pushed,
    }
  } else {
    Outcome::Unsupported
  }
}

// ---------------------------------------------------------------------------
// The step relation
// ---------------------------------------------------------------------------

/// Executes `insn`, which is the instruction at `s.pc`.
fn step_at(code: &[PInsn], insn: PInsn, s: &mut Sim) -> Outcome {
  match insn {
    // The four label forms and `pause` emit nothing.
    PInsn::PcLabel(_) => {
      s.pc += 1;
      Outcome::Next
    }
    PInsn::Local(_) => {
      s.pc += 1;
      Outcome::Next
    }
    PInsn::ExitLabel => {
      s.pc += 1;
      Outcome::Next
    }
    PInsn::RetpolineLabel => {
      s.pc += 1;
      Outcome::Next
    }
    PInsn::Pause => {
      s.pc += 1;
      Outcome::Next
    }

    PInsn::Push(r) => {
      let v = reg(s, r);
      let done = push(s, v);
      match done {
        Outcome::Next => {
          s.pc += 1;
          Outcome::Next
        }
        _ => done,
      }
    }
    PInsn::Pop(r) => pop(s, r),
    PInsn::Pushfq => {
      let v = flags_word(get_flags(s));
      let done = push(s, v);
      match done {
        Outcome::Next => {
          s.pc += 1;
          Outcome::Next
        }
        _ => done,
      }
    }
    PInsn::Popfq => {
      let top = reg(s, RSP);
      let (ok, v) = load_mem(s, top, 8);
      if ok {
        set_reg(s, RSP, add64(top, 8));
        let f = flags_of_word(v);
        set_flags(s, f);
        s.pc += 1;
        Outcome::Next
      } else {
        Outcome::Fault
      }
    }

    PInsn::Alu { w64, op, src, dst } => alu_rr(s, w64, op, src, dst),
    PInsn::AluImm { w64, op, dst, imm } => alu_imm(s, w64, op, dst, imm),
    PInsn::ShiftImm { w64, op, dst, imm } => shift(s, w64, op, dst, imm as u8),
    PInsn::ShiftCl { w64, op, dst } => {
      let count = (reg(s, RCX) & 0xff) as u8;
      shift(s, w64, op, dst, count)
    }
    PInsn::Neg { w64, dst } => neg(s, w64, dst),
    PInsn::MulDivRcx { w64, kind, signed } => match kind {
      MulDivKind::Mul => mul_rcx(s, w64),
      _ => div_rcx(s, w64, signed),
    },
    PInsn::MovSx {
      from,
      w64,
      src,
      dst,
    } => movsx(s, from, w64, src, dst),
    PInsn::Bswap { w64, dst } => bswap(s, w64, dst),
    PInsn::Rol16 { dst } => rol16(s, dst),
    PInsn::Cmov { cc, dst, src } => {
      let taken = cond(cc, get_flags(s));
      if taken {
        let v = reg(s, src);
        set_reg(s, dst, v);
      }
      s.pc += 1;
      Outcome::Next
    }
    PInsn::LoadImm { dst, imm } => {
      set_reg(s, dst, imm as u64);
      s.pc += 1;
      Outcome::Next
    }
    PInsn::Cqo => {
      let v = if msb(true, reg(s, RAX)) {
        0xffff_ffff_ffff_ffff
      } else {
        0
      };
      set_reg(s, RDX, v);
      s.pc += 1;
      Outcome::Next
    }
    PInsn::Cdq => {
      let v: u64 = if msb(false, reg(s, RAX)) { MASK32 } else { 0 };
      set_reg(s, RDX, v);
      s.pc += 1;
      Outcome::Next
    }
    PInsn::CmpRcxMinusOne { w64 } => {
      let f = flags_of_add_sub(w64, true, reg(s, RCX), 0xffff_ffff_ffff_ffff);
      set_flags(s, f);
      s.pc += 1;
      Outcome::Next
    }
    PInsn::CmpEaxImm { imm } => {
      let f = flags_of_add_sub(false, true, reg(s, RAX), imm as u64);
      set_flags(s, f);
      s.pc += 1;
      Outcome::Next
    }

    PInsn::Load {
      size,
      sx,
      base,
      dst,
      disp,
    } => load(s, size, sx, base, dst, disp),
    PInsn::Store {
      size,
      src,
      base,
      disp,
    } => store(s, size, src, base, disp),
    PInsn::StoreImm {
      size,
      base,
      disp,
      imm,
    } => store_imm(s, size, base, disp, imm),
    PInsn::AluRM {
      op,
      reg: r,
      base,
      disp,
    } => alu_rm(s, op, r, base, disp),
    PInsn::StoreRspImm { imm } => {
      let top = reg(s, RSP);
      let ok = store_mem(s, top, 8, sign_extend(imm as u64, 32));
      if ok {
        s.pc += 1;
        Outcome::Next
      } else {
        Outcome::Fault
      }
    }
    PInsn::StoreRspRax => {
      let top = reg(s, RSP);
      let v = reg(s, RAX);
      let ok = store_mem(s, top, 8, v);
      if ok {
        s.pc += 1;
        Outcome::Next
      } else {
        Outcome::Fault
      }
    }

    PInsn::LockAlu {
      op,
      w64,
      src,
      base,
      disp,
    } => lock_alu(s, op, w64, src, base, disp),
    PInsn::LockCmpxchg {
      w64,
      src,
      base,
      disp,
    } => cmpxchg(s, w64, src, base, disp),
    PInsn::Xchg {
      w64,
      src,
      base,
      disp,
    } => xchg(s, w64, src, base, disp),

    PInsn::Jcc { cc, target } => {
      let taken = cond(cc, get_flags(s));
      if taken {
        branch(code, s, target)
      } else {
        s.pc += 1;
        Outcome::Next
      }
    }
    PInsn::Jmp { target } => branch(code, s, target),
    PInsn::JmpNear { target } => branch(code, s, target),
    PInsn::Jcc8 { cc, target } => {
      let taken = cond(cc, get_flags(s));
      if taken {
        branch(code, s, PTarget::Local(target))
      } else {
        s.pc += 1;
        Outcome::Next
      }
    }
    PInsn::Jmp8 { target } => branch(code, s, PTarget::Local(target)),
    PInsn::Call { target } => call(code, s, target),
    PInsn::Ret => ret(code, s),

    // `ud2` and the trailer's data halt, as in Lean. The three that leave the
    // list, or read an address this model does not carry, are not executed.
    PInsn::Ud2 => Outcome::Halt,
    PInsn::DispatcherSlot { addr: _ } => Outcome::Halt,
    PInsn::HelperTable => Outcome::Halt,
    PInsn::CallReg(_) => Outcome::Unsupported,
    PInsn::RipLoadDispatcher { dst: _ } => Outcome::Unsupported,
    PInsn::RipLeaHelperTable { dst: _ } => Outcome::Unsupported,
  }
}

/// Executes `code[s.pc]`. A program counter off the end of the list halts.
pub fn step(code: &[PInsn], s: &mut Sim) -> Outcome {
  if s.pc < code.len() {
    let insn = code[s.pc];
    step_at(code, insn, s)
  } else {
    Outcome::Halt
  }
}

/// Runs up to `max_steps` instructions. Returns the first outcome that is not
/// [`Outcome::Next`], or [`Outcome::Next`] when the budget ran out with the
/// machine still runnable.
pub fn run(code: &[PInsn], s: &mut Sim, max_steps: usize) -> Outcome {
  let mut i: usize = 0;
  let mut out = Outcome::Next;
  let mut done = false;
  while i < max_steps && !done {
    let o = step(code, s);
    match o {
      Outcome::Next => {}
      _ => {
        out = o;
        done = true;
      }
    }
    i += 1;
  }
  out
}

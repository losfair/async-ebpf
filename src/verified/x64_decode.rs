//! The inverse of the x86_64 primitive encoder.
//!
//! [`decode_one`] reads the bytes at one instruction boundary and returns the
//! [`PInsn`] that produced them, the number of bytes it consumed, and the
//! displacement the instruction carried. It is the other half of the
//! statement a later Lean proof is about:
//!
//! ```text
//!   decode_one (encode_one p) 0 = Some { insn = p, len = size_of p, disp = 0 }
//! ```
//!
//! and, at the offsets [`x64_encode::offsets`](super::x64_encode::offsets)
//! computes, the same over a whole assembled function, with `disp` the
//! displacement [`assemble`](super::x64_encode::assemble) patched in.
//!
//! # What it reads
//!
//! Only the encodings [`encode_one`](super::x64_encode::encode_one)
//! produces. Anything else is [`None`]. In particular the decoder accepts the
//! prefixes in the order the encoder writes them (`f0`, then `66` or `f3`,
//! then REX), the ModRM forms
//! [`emit_modrm_and_displacement`](super::x64_encode) produces — which never
//! use an index register, never a bare `[rsp]` or `[rip]`, and never a
//! displacement wider than the value needs — and the two literal `[rsp]`
//! forms the host-stack sequences spell out.
//!
//! # Where a label was
//!
//! A branch's target is not in its bytes: the bytes hold a displacement, and
//! which label it reached is a fact about the whole function. So a decoded
//! branch carries a placeholder target — [`PTarget::Local`]`(0)` for `Jcc`,
//! `Jmp`, `JmpNear` and `Call`, the number `0` for `Jcc8` and `Jmp8` — and
//! the displacement in [`Decoded::disp`], sign-extended from whichever width
//! the encoding used. The same holds for `RipLoadDispatcher` and
//! `RipLeaHelperTable`, whose rel32 reaches the trailer.
//!
//! # What cannot be inverted
//!
//! Four places where the encoding is not injective, all of them collisions
//! between primitives that mean the same instruction:
//!
//! * a `LoadImm` whose immediate fits in 32 bits is the same three bytes and
//!   four immediate bytes as `AluImm { w64: true, op: Mov }`; the decoder
//!   returns the `AluImm`, which is the only reading available when the
//!   operand size is 32 bits;
//! * `MulDivKind::Div` and `MulDivKind::Mod` are one x86 instruction — the
//!   macro layer keeps the difference — so `MulDivRcx` decodes as `Div`, and
//!   `Mul` ignores `signed`, so it decodes as unsigned;
//! * `ShiftImm` truncates its immediate to a byte and `StoreImm` to its
//!   width, so the decoder returns the truncated value;
//! * `JmpNear` is `eb rel8` followed by three bytes of padding and `Jmp8` is
//!   `eb rel8` alone. The padding the encoder writes is three zero bytes and
//!   it is dead — the jump is unconditional and lands past it — so `eb` with
//!   three zero bytes after its displacement decodes as `JmpNear`, consuming
//!   all five, and anything else as `Jmp8`. No sequence the backend emits
//!   puts three zero bytes after a `Jmp8`: the byte `0x00` starts no
//!   encoding the encoder produces.
//!
//! The four label primitives and the sign-extending eight-byte `Load` encode
//! to no bytes at all, so nothing decodes to them.
//!
//! # Data
//!
//! The trailer's two data primitives are not self-describing: eight bytes of
//! dispatcher address can spell any instruction. The decoder reads them as a
//! last resort — after no instruction encoding matched, 512 zero bytes are a
//! [`PInsn::HelperTable`] and eight remaining bytes a
//! [`PInsn::DispatcherSlot`] — which is only meaningful at an instruction
//! boundary the assembler produced, and is why the theorem quantifies over
//! those boundaries rather than over arbitrary offsets. A dispatcher slot
//! holding zero, immediately before the helper table, reads as the table.

// The runtime never decodes: this module exists for the roundtrip tests and
// for the Lean statement about the encoder, so its helpers are dead code in a
// build that compiles no tests.
#![allow(dead_code)]
// `Range::contains` is a method call on a range, which the extraction has no
// model for; every bound here is written out as a comparison instead.
#![allow(clippy::manual_range_contains)]

use super::x64_encode::HELPER_TABLE_LEN;
use super::x64_ir::{AluRI, AluRM, AluRR, MulDivKind, PInsn, PTarget, ShiftOp, Size};

/// One decoded instruction.
///
/// A struct rather than a tuple inside the [`Option`]: the extraction is
/// happier with one shape than with nested products.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub struct Decoded {
  /// The primitive, with any label target replaced by a placeholder.
  pub insn: PInsn,
  /// Bytes consumed, including `JmpNear`'s three dead padding bytes.
  pub len: usize,
  /// The relative displacement the instruction carried, sign-extended.
  pub disp: i64,
}

// ---------------------------------------------------------------------------
// Bytes
// ---------------------------------------------------------------------------

/// The byte at `i`, or `-1` past the end.
fn byte_at(bytes: &[u8], i: usize) -> i32 {
  if i < bytes.len() {
    bytes[i] as i32
  } else {
    -1
  }
}

/// Whether `n` bytes remain from `at`.
fn have(bytes: &[u8], at: usize, n: usize) -> bool {
  let end = at + n;
  end <= bytes.len()
}

/// Four bytes at `at`, little-endian; zero if they are not all there.
fn read32(bytes: &[u8], at: usize) -> u32 {
  let mut v: u32 = 0;
  if have(bytes, at, 4) {
    v = (bytes[at] as u32)
      | ((bytes[at + 1] as u32) << 8)
      | ((bytes[at + 2] as u32) << 16)
      | ((bytes[at + 3] as u32) << 24);
  }
  v
}

/// Eight bytes at `at`, little-endian; zero if they are not all there.
fn read64(bytes: &[u8], at: usize) -> u64 {
  let mut v: u64 = 0;
  if have(bytes, at, 8) {
    v = (bytes[at] as u64)
      | ((bytes[at + 1] as u64) << 8)
      | ((bytes[at + 2] as u64) << 16)
      | ((bytes[at + 3] as u64) << 24)
      | ((bytes[at + 4] as u64) << 32)
      | ((bytes[at + 5] as u64) << 40)
      | ((bytes[at + 6] as u64) << 48)
      | ((bytes[at + 7] as u64) << 56);
  }
  v
}

/// A signed byte as a displacement.
fn sx8(b: i32) -> i64 {
  (b as u8) as i8 as i64
}

/// A little-endian four-byte value as a displacement.
fn sx32(v: u32) -> i64 {
  v as i32 as i64
}

// ---------------------------------------------------------------------------
// Prefixes
// ---------------------------------------------------------------------------

/// The prefixes an instruction carries, and where its opcode starts.
struct Pfx {
  lock: bool,
  op16: bool,
  rep: bool,
  /// REX.W, as the bit.
  w: u8,
  /// REX.R and REX.B, as bits.
  r: u8,
  b: u8,
  /// Index of the opcode byte.
  at: usize,
}

/// Reads the prefixes at `at`. REX is last, as the encoder writes it.
fn prefixes(bytes: &[u8], at: usize) -> Pfx {
  let mut p = Pfx {
    lock: false,
    op16: false,
    rep: false,
    w: 0,
    r: 0,
    b: 0,
    at,
  };
  let n = bytes.len();
  let mut i = at;
  let mut more = true;
  while more && i < n {
    let c = bytes[i];
    if c == 0xf0 {
      p.lock = true;
      i += 1;
    } else if c == 0x66 {
      p.op16 = true;
      i += 1;
    } else if c == 0xf3 {
      p.rep = true;
      i += 1;
    } else if c >= 0x40 && c <= 0x4f {
      p.w = (c >> 3) & 1;
      p.r = (c >> 2) & 1;
      p.b = c & 1;
      i += 1;
      more = false;
    } else {
      more = false;
    }
  }
  p.at = i;
  p
}

// ---------------------------------------------------------------------------
// ModRM
// ---------------------------------------------------------------------------

/// A decoded memory operand.
struct Mem {
  /// False when the bytes are not a memory form the encoder produces.
  ok: bool,
  /// The ModRM `reg` field, with REX.R.
  reg: u8,
  /// The base register, with REX.B.
  base: u8,
  disp: i32,
  /// Bytes the operand occupies: ModRM, the SIB byte if any, the
  /// displacement if any.
  len: usize,
}

/// Decodes the memory operand whose ModRM byte is at `at`.
///
/// Refuses everything `emit_modrm_and_displacement` never writes: the
/// register form, the RIP-relative form, a SIB byte other than `0x24`, and
/// the zero-displacement `[rsp]`/`[r12]` form, which the two literal host
/// stack sequences own.
fn decode_mem(bytes: &[u8], at: usize, rex_r: u8, rex_b: u8) -> Mem {
  let mut m = Mem {
    ok: false,
    reg: 0,
    base: 0,
    disp: 0,
    len: 0,
  };
  let head = byte_at(bytes, at);
  if head >= 0 {
    let modrm = head as u8;
    let md = modrm & 0xc0;
    m.reg = ((modrm >> 3) & 7) | (rex_r << 3);
    m.base = (modrm & 7) | (rex_b << 3);
    let rm = modrm & 7;
    let sib: usize = if rm == 4 { 1 } else { 0 };
    let sib_ok = if rm == 4 {
      byte_at(bytes, at + 1) == 0x24
    } else {
      true
    };
    if md == 0xc0 || !sib_ok {
      // The register form, or an addressing mode the encoder never writes.
    } else if md == 0x00 {
      // `[rbp]` and `[rsp]` have no zero-displacement encoding, so the
      // encoder never takes this form for them.
      if rm != 4 && rm != 5 {
        m.disp = 0;
        m.len = 1;
        m.ok = true;
      }
    } else if md == 0x40 {
      let d = byte_at(bytes, at + 1 + sib);
      if d >= 0 {
        m.disp = sx8(d) as i32;
        m.len = 2 + sib;
        m.ok = true;
      }
    } else if have(bytes, at + 1 + sib, 4) {
      m.disp = read32(bytes, at + 1 + sib) as i32;
      m.len = 5 + sib;
      m.ok = true;
    }
  }
  m
}

/// A decoded register-to-register ModRM byte.
struct Reg2 {
  ok: bool,
  /// The ModRM `reg` field, with REX.R.
  reg: u8,
  /// The ModRM `rm` field, with REX.B.
  rm: u8,
  /// The ModRM `reg` field alone, which the opcode extensions use.
  ext: u8,
}

/// Decodes the register form (`mod == 11`) whose ModRM byte is at `at`.
fn decode_reg2(bytes: &[u8], at: usize, rex_r: u8, rex_b: u8) -> Reg2 {
  let mut g = Reg2 {
    ok: false,
    reg: 0,
    rm: 0,
    ext: 0,
  };
  let head = byte_at(bytes, at);
  if head >= 0 {
    let modrm = head as u8;
    if (modrm & 0xc0) == 0xc0 {
      g.ext = (modrm >> 3) & 7;
      g.reg = g.ext | (rex_r << 3);
      g.rm = (modrm & 7) | (rex_b << 3);
      g.ok = true;
    }
  }
  g
}

/// Whether the ModRM byte at `at` is the RIP-relative form.
fn is_rip(bytes: &[u8], at: usize) -> bool {
  let head = byte_at(bytes, at);
  let mut yes = false;
  if head >= 0 {
    yes = ((head as u8) & 0xc7) == 0x05;
  }
  yes
}

/// The `reg` field of the ModRM byte at `at`, with REX.R.
fn modrm_reg(bytes: &[u8], at: usize, rex_r: u8) -> u8 {
  let head = byte_at(bytes, at);
  let mut r: u8 = 0;
  if head >= 0 {
    r = (((head as u8) >> 3) & 7) | (rex_r << 3);
  }
  r
}

/// The operand width a REX.W bit and a `0x66` prefix name.
fn mem_size(w: u8, op16: bool) -> Size {
  if w == 1 {
    8
  } else if op16 {
    2
  } else {
    4
  }
}

/// One decoded instruction, given where it started and where it ended.
fn done(insn: PInsn, at: usize, end: usize, disp: i64) -> Option<Decoded> {
  Some(Decoded {
    insn,
    len: end - at,
    disp,
  })
}

// ---------------------------------------------------------------------------
// Opcode tables, inverted
// ---------------------------------------------------------------------------

/// Whether `op` is a register-form ALU opcode.
fn is_alu_rr(op: u8) -> bool {
  op == 0x01
    || op == 0x29
    || op == 0x09
    || op == 0x21
    || op == 0x31
    || op == 0x89
    || op == 0x39
    || op == 0x85
}

/// The operation a register-form ALU opcode names. Only called when
/// [`is_alu_rr`] holds.
fn alu_rr_of(op: u8) -> AluRR {
  if op == 0x01 {
    AluRR::Add
  } else if op == 0x29 {
    AluRR::Sub
  } else if op == 0x09 {
    AluRR::Or
  } else if op == 0x21 {
    AluRR::And
  } else if op == 0x31 {
    AluRR::Xor
  } else if op == 0x89 {
    AluRR::Mov
  } else if op == 0x39 {
    AluRR::Cmp
  } else {
    AluRR::Test
  }
}

/// Whether `ext` is one of the `0x81` group's extensions.
fn is_alu_ri_ext(ext: u8) -> bool {
  ext == 0 || ext == 1 || ext == 4 || ext == 5 || ext == 6 || ext == 7
}

/// The operation a `0x81` extension names. Only called when
/// [`is_alu_ri_ext`] holds.
fn alu_ri_of(ext: u8) -> AluRI {
  if ext == 0 {
    AluRI::Add
  } else if ext == 1 {
    AluRI::Or
  } else if ext == 4 {
    AluRI::And
  } else if ext == 5 {
    AluRI::Sub
  } else if ext == 6 {
    AluRI::Xor
  } else {
    AluRI::Cmp
  }
}

/// Whether `ext` is one of the shift group's extensions.
fn is_shift_ext(ext: u8) -> bool {
  ext == 4 || ext == 5 || ext == 7
}

/// The shift an extension names. Only called when [`is_shift_ext`] holds.
fn shift_of(ext: u8) -> ShiftOp {
  if ext == 4 {
    ShiftOp::Shl
  } else if ext == 5 {
    ShiftOp::Shr
  } else {
    ShiftOp::Sar
  }
}

/// Whether `op` is one of the opcodes [`decode_alu`] reads.
fn alu_op(op: u8) -> bool {
  let rr = is_alu_rr(op);
  let rm = is_alu_rm(op);
  rr || rm || op == 0x88
}

/// Whether `op` is an `op reg, [mem]` opcode the bounds checks use.
fn is_alu_rm(op: u8) -> bool {
  op == 0x2b || op == 0x03 || op == 0x39 || op == 0x3b || op == 0x0b
}

/// The form an `op reg, [mem]` opcode names. Only called when [`is_alu_rm`]
/// holds.
fn alu_rm_of(op: u8) -> AluRM {
  if op == 0x2b {
    AluRM::Sub
  } else if op == 0x03 {
    AluRM::Add
  } else if op == 0x39 {
    AluRM::CmpMR
  } else if op == 0x3b {
    AluRM::CmpRM
  } else {
    AluRM::Or
  }
}

// ---------------------------------------------------------------------------
// The decoder
// ---------------------------------------------------------------------------

/// Decodes the instruction at `at`.
pub fn decode_one(bytes: &[u8], at: usize) -> Option<Decoded> {
  let p = prefixes(bytes, at);
  let insn = decode_insn(bytes, at, &p);
  match insn {
    Some(d) => Some(d),
    None => decode_data(bytes, at),
  }
}

/// The instruction encodings, by prefix and opcode.
fn decode_insn(bytes: &[u8], at: usize, p: &Pfx) -> Option<Decoded> {
  let head = byte_at(bytes, p.at);
  if head < 0 {
    None
  } else if p.lock {
    decode_locked(bytes, at, p, head as u8)
  } else if head == 0x0f {
    decode_two_byte(bytes, at, p)
  } else {
    decode_one_byte(bytes, at, p, head as u8)
  }
}

/// The three `lock`-prefixed forms: `cmpxchg`, `xchg`, and the read-modify-
/// write ALU operations, whose opcode byte the primitive carries verbatim.
fn decode_locked(bytes: &[u8], at: usize, p: &Pfx, op: u8) -> Option<Decoded> {
  let w64 = p.w == 1;
  if op == 0x0f {
    let second = byte_at(bytes, p.at + 1);
    if second == 0xb1 {
      let m = decode_mem(bytes, p.at + 2, p.r, p.b);
      if m.ok {
        done(
          PInsn::LockCmpxchg {
            w64,
            src: m.reg,
            base: m.base,
            disp: m.disp,
          },
          at,
          p.at + 2 + m.len,
          0,
        )
      } else {
        None
      }
    } else {
      None
    }
  } else if op == 0x87 {
    let m = decode_mem(bytes, p.at + 1, p.r, p.b);
    if m.ok {
      done(
        PInsn::Xchg {
          w64,
          src: m.reg,
          base: m.base,
          disp: m.disp,
        },
        at,
        p.at + 1 + m.len,
        0,
      )
    } else {
      None
    }
  } else {
    // `add`, `or`, `and` and `xor` are what the atomics use; the primitive
    // carries the opcode byte, so any other register-form ALU opcode reads
    // back as itself.
    let m = decode_mem(bytes, p.at + 1, p.r, p.b);
    if m.ok {
      done(
        PInsn::LockAlu {
          op,
          w64,
          src: m.reg,
          base: m.base,
          disp: m.disp,
        },
        at,
        p.at + 1 + m.len,
        0,
      )
    } else {
      None
    }
  }
}

/// The `0f`-escaped opcodes.
fn decode_two_byte(bytes: &[u8], at: usize, p: &Pfx) -> Option<Decoded> {
  let second = byte_at(bytes, p.at + 1);
  let w64 = p.w == 1;
  if second < 0 {
    None
  } else if second == 0x0b {
    done(PInsn::Ud2, at, p.at + 2, 0)
  } else if second >= 0x40 && second <= 0x4f {
    let g = decode_reg2(bytes, p.at + 2, p.r, p.b);
    if g.ok {
      done(
        PInsn::Cmov {
          cc: 0x80 | ((second as u8) & 0x0f),
          dst: g.reg,
          src: g.rm,
        },
        at,
        p.at + 3,
        0,
      )
    } else {
      None
    }
  } else if second >= 0x80 && second <= 0x8f {
    if have(bytes, p.at + 2, 4) {
      done(
        PInsn::Jcc {
          cc: second as u8,
          target: PTarget::Local(0),
        },
        at,
        p.at + 6,
        sx32(read32(bytes, p.at + 2)),
      )
    } else {
      None
    }
  } else if second >= 0xc8 && second <= 0xcf {
    done(
      PInsn::Bswap {
        w64,
        dst: ((second as u8) & 7) | (p.b << 3),
      },
      at,
      p.at + 2,
      0,
    )
  } else if second == 0xb6 || second == 0xb7 {
    let size: Size = if second == 0xb6 { 1 } else { 2 };
    let m = decode_mem(bytes, p.at + 2, p.r, p.b);
    if m.ok {
      done(
        PInsn::Load {
          size,
          sx: false,
          base: m.base,
          dst: m.reg,
          disp: m.disp,
        },
        at,
        p.at + 2 + m.len,
        0,
      )
    } else {
      None
    }
  } else if second == 0xbe || second == 0xbf {
    let from: u8 = if second == 0xbe { 8 } else { 16 };
    let size: Size = if second == 0xbe { 1 } else { 2 };
    let g = decode_reg2(bytes, p.at + 2, p.r, p.b);
    if g.ok {
      done(
        PInsn::MovSx {
          from,
          w64,
          src: g.rm,
          dst: g.reg,
        },
        at,
        p.at + 3,
        0,
      )
    } else {
      let m = decode_mem(bytes, p.at + 2, p.r, p.b);
      if m.ok {
        done(
          PInsn::Load {
            size,
            sx: true,
            base: m.base,
            dst: m.reg,
            disp: m.disp,
          },
          at,
          p.at + 2 + m.len,
          0,
        )
      } else {
        None
      }
    }
  } else {
    None
  }
}

/// The one-byte opcodes, in four groups so that no function is a wall.
fn decode_one_byte(bytes: &[u8], at: usize, p: &Pfx, op: u8) -> Option<Decoded> {
  if op >= 0x50 && op <= 0x5f {
    let r = (op & 7) | (p.b << 3);
    if op <= 0x57 {
      done(PInsn::Push(r), at, p.at + 1, 0)
    } else {
      done(PInsn::Pop(r), at, p.at + 1, 0)
    }
  } else if op >= 0x70 && op <= 0x7f {
    let d = byte_at(bytes, p.at + 1);
    if d < 0 {
      None
    } else {
      done(
        PInsn::Jcc8 {
          cc: 0x80 | (op & 0x0f),
          target: 0,
        },
        at,
        p.at + 2,
        sx8(d),
      )
    }
  } else if op >= 0xb8 && op <= 0xbf {
    // The only `b8+r` form the encoder writes is the 64-bit one.
    let room = have(bytes, p.at + 1, 8);
    if p.w == 1 && room {
      done(
        PInsn::LoadImm {
          dst: (op & 7) | (p.b << 3),
          imm: read64(bytes, p.at + 1) as i64,
        },
        at,
        p.at + 9,
        0,
      )
    } else {
      None
    }
  } else if alu_op(op) {
    decode_alu(bytes, at, p, op)
  } else if op == 0x8b || op == 0x8d || op == 0xc6 || op == 0xc7 {
    decode_move(bytes, at, p, op)
  } else {
    decode_rest(bytes, at, p, op)
  }
}

/// The register and memory forms that share the ALU opcode bytes.
fn decode_alu(bytes: &[u8], at: usize, p: &Pfx, op: u8) -> Option<Decoded> {
  let w64 = p.w == 1;
  let g = decode_reg2(bytes, p.at + 1, p.r, p.b);
  let rr = is_alu_rr(op);
  let rm = is_alu_rm(op);
  let modrm = byte_at(bytes, p.at + 1);
  let sib = byte_at(bytes, p.at + 2);
  if g.ok && rr {
    done(
      PInsn::Alu {
        w64,
        op: alu_rr_of(op),
        src: g.reg,
        dst: g.rm,
      },
      at,
      p.at + 2,
      0,
    )
  } else if op == 0x89 && modrm == 0x04 && sib == 0x24 {
    // `mov [rsp], rax`, whose ModRM and SIB bytes the encoder spells out.
    if p.w == 1 {
      done(PInsn::StoreRspRax, at, p.at + 3, 0)
    } else {
      None
    }
  } else {
    let m = decode_mem(bytes, p.at + 1, p.r, p.b);
    if !m.ok {
      None
    } else if op == 0x88 || op == 0x89 {
      let size: Size = if op == 0x88 { 1 } else { mem_size(p.w, p.op16) };
      done(
        PInsn::Store {
          size,
          src: m.reg,
          base: m.base,
          disp: m.disp,
        },
        at,
        p.at + 1 + m.len,
        0,
      )
    } else if rm {
      done(
        PInsn::AluRM {
          op: alu_rm_of(op),
          reg: m.reg,
          base: m.base,
          disp: m.disp,
        },
        at,
        p.at + 1 + m.len,
        0,
      )
    } else {
      None
    }
  }
}

/// The loads, the two RIP-relative forms and the immediate stores.
fn decode_move(bytes: &[u8], at: usize, p: &Pfx, op: u8) -> Option<Decoded> {
  let rip = is_rip(bytes, p.at + 1);
  let room = have(bytes, p.at + 2, 4);
  if op == 0x8b && rip {
    if room {
      done(
        PInsn::RipLoadDispatcher {
          dst: modrm_reg(bytes, p.at + 1, 0),
        },
        at,
        p.at + 6,
        sx32(read32(bytes, p.at + 2)),
      )
    } else {
      None
    }
  } else if op == 0x8d {
    if rip && room {
      done(
        PInsn::RipLeaHelperTable {
          dst: modrm_reg(bytes, p.at + 1, p.r),
        },
        at,
        p.at + 6,
        sx32(read32(bytes, p.at + 2)),
      )
    } else {
      None
    }
  } else if op == 0x8b {
    let m = decode_mem(bytes, p.at + 1, p.r, p.b);
    if m.ok {
      done(
        PInsn::Load {
          size: mem_size(p.w, false),
          sx: false,
          base: m.base,
          dst: m.reg,
          disp: m.disp,
        },
        at,
        p.at + 1 + m.len,
        0,
      )
    } else {
      None
    }
  } else {
    decode_store_imm(bytes, at, p, op)
  }
}

/// `c6`/`c7`: the immediate stores, the `mov reg, imm32` they share `c7`
/// with, and the literal `mov qword [rsp], imm32`.
fn decode_store_imm(bytes: &[u8], at: usize, p: &Pfx, op: u8) -> Option<Decoded> {
  let g = decode_reg2(bytes, p.at + 1, p.r, p.b);
  let modrm = byte_at(bytes, p.at + 1);
  let sib = byte_at(bytes, p.at + 2);
  let room = have(bytes, p.at + 2, 4);
  if op == 0xc7 && g.ok {
    // A `LoadImm` whose immediate fits in 32 bits is these same bytes.
    if g.ext == 0 && room {
      done(
        PInsn::AluImm {
          w64: p.w == 1,
          op: AluRI::Mov,
          dst: g.rm,
          imm: read32(bytes, p.at + 2) as i32,
        },
        at,
        p.at + 6,
        0,
      )
    } else {
      None
    }
  } else if op == 0xc7 && modrm == 0x04 && sib == 0x24 {
    let wide = have(bytes, p.at + 3, 4);
    if p.w == 1 && wide {
      done(
        PInsn::StoreRspImm {
          imm: read32(bytes, p.at + 3),
        },
        at,
        p.at + 7,
        0,
      )
    } else {
      None
    }
  } else {
    let m = decode_mem(bytes, p.at + 1, p.r, p.b);
    let size: Size = if op == 0xc6 { 1 } else { mem_size(p.w, p.op16) };
    let imm_len: usize = if size == 1 {
      1
    } else if size == 2 {
      2
    } else {
      4
    };
    let start = p.at + 1 + m.len;
    let fits = have(bytes, start, imm_len);
    if !m.ok || m.reg != 0 || !fits {
      None
    } else {
      let imm: i32 = if size == 1 {
        bytes[start] as i32
      } else if size == 2 {
        (bytes[start] as i32) | ((bytes[start + 1] as i32) << 8)
      } else {
        read32(bytes, start) as i32
      };
      done(
        PInsn::StoreImm {
          size,
          base: m.base,
          disp: m.disp,
          imm,
        },
        at,
        start + imm_len,
        0,
      )
    }
  }
}

/// Everything else: the shifts, the unary group, the branches and the
/// one-byte instructions.
fn decode_rest(bytes: &[u8], at: usize, p: &Pfx, op: u8) -> Option<Decoded> {
  let w64 = p.w == 1;
  if op == 0x3d {
    if have(bytes, p.at + 1, 4) {
      done(
        PInsn::CmpEaxImm {
          imm: read32(bytes, p.at + 1),
        },
        at,
        p.at + 5,
        0,
      )
    } else {
      None
    }
  } else if op == 0x63 {
    let g = decode_reg2(bytes, p.at + 1, p.r, p.b);
    if g.ok {
      done(
        PInsn::MovSx {
          from: 32,
          w64,
          src: g.rm,
          dst: g.reg,
        },
        at,
        p.at + 2,
        0,
      )
    } else {
      let m = decode_mem(bytes, p.at + 1, p.r, p.b);
      if m.ok {
        done(
          PInsn::Load {
            size: 4,
            sx: true,
            base: m.base,
            dst: m.reg,
            disp: m.disp,
          },
          at,
          p.at + 1 + m.len,
          0,
        )
      } else {
        None
      }
    }
  } else if op == 0x81 {
    let g = decode_reg2(bytes, p.at + 1, p.r, p.b);
    let known = is_alu_ri_ext(g.ext);
    let room = have(bytes, p.at + 2, 4);
    if g.ok && known && room {
      done(
        PInsn::AluImm {
          w64,
          op: alu_ri_of(g.ext),
          dst: g.rm,
          imm: read32(bytes, p.at + 2) as i32,
        },
        at,
        p.at + 6,
        0,
      )
    } else {
      None
    }
  } else if op == 0x83 {
    // The only `83` form the encoder writes is `cmp rcx, -1`.
    let modrm = byte_at(bytes, p.at + 1);
    let imm = byte_at(bytes, p.at + 2);
    if modrm == 0xf9 && imm == 0xff {
      done(PInsn::CmpRcxMinusOne { w64 }, at, p.at + 3, 0)
    } else {
      None
    }
  } else if op == 0x90 {
    if p.rep {
      done(PInsn::Pause, at, p.at + 1, 0)
    } else {
      None
    }
  } else if op == 0x99 {
    if w64 {
      done(PInsn::Cqo, at, p.at + 1, 0)
    } else {
      done(PInsn::Cdq, at, p.at + 1, 0)
    }
  } else if op == 0x9c {
    done(PInsn::Pushfq, at, p.at + 1, 0)
  } else if op == 0x9d {
    done(PInsn::Popfq, at, p.at + 1, 0)
  } else if op == 0xc1 {
    decode_shift(bytes, at, p)
  } else if op == 0xc3 {
    done(PInsn::Ret, at, p.at + 1, 0)
  } else if op == 0xd3 {
    let g = decode_reg2(bytes, p.at + 1, p.r, p.b);
    let known = is_shift_ext(g.ext);
    if g.ok && known {
      done(
        PInsn::ShiftCl {
          w64,
          op: shift_of(g.ext),
          dst: g.rm,
        },
        at,
        p.at + 2,
        0,
      )
    } else {
      None
    }
  } else if op == 0xe8 || op == 0xe9 {
    if have(bytes, p.at + 1, 4) {
      let target = PTarget::Local(0);
      let insn = if op == 0xe8 {
        PInsn::Call { target }
      } else {
        PInsn::Jmp { target }
      };
      done(insn, at, p.at + 5, sx32(read32(bytes, p.at + 1)))
    } else {
      None
    }
  } else if op == 0xeb {
    decode_short_jmp(bytes, at, p)
  } else if op == 0xf7 {
    decode_unary(bytes, at, p)
  } else if op == 0xff {
    let head = byte_at(bytes, p.at + 1);
    if head >= 0 && ((head as u8) & 0xf8) == 0xd0 {
      done(
        PInsn::CallReg(((head as u8) & 7) | (p.b << 3)),
        at,
        p.at + 2,
        0,
      )
    } else {
      None
    }
  } else {
    None
  }
}

/// `c1`: a shift by an immediate, or the sixteen-bit byte swap.
fn decode_shift(bytes: &[u8], at: usize, p: &Pfx) -> Option<Decoded> {
  let g = decode_reg2(bytes, p.at + 1, p.r, p.b);
  let imm = byte_at(bytes, p.at + 2);
  if !g.ok || imm < 0 {
    None
  } else if p.op16 {
    // `rol r16, 8`, the only `66`-prefixed shift the encoder writes.
    if g.ext == 0 && imm == 8 {
      done(PInsn::Rol16 { dst: g.rm }, at, p.at + 3, 0)
    } else {
      None
    }
  } else if is_shift_ext(g.ext) {
    done(
      PInsn::ShiftImm {
        w64: p.w == 1,
        op: shift_of(g.ext),
        dst: g.rm,
        imm,
      },
      at,
      p.at + 3,
      0,
    )
  } else {
    None
  }
}

/// `eb`: a near jump with its three dead padding bytes, or a short one.
fn decode_short_jmp(bytes: &[u8], at: usize, p: &Pfx) -> Option<Decoded> {
  let d = byte_at(bytes, p.at + 1);
  if d < 0 {
    None
  } else {
    let pad0 = byte_at(bytes, p.at + 2);
    let pad1 = byte_at(bytes, p.at + 3);
    let pad2 = byte_at(bytes, p.at + 4);
    let padded = pad0 == 0 && pad1 == 0 && pad2 == 0;
    if padded {
      done(
        PInsn::JmpNear {
          target: PTarget::Local(0),
        },
        at,
        p.at + 5,
        sx8(d),
      )
    } else {
      done(PInsn::Jmp8 { target: 0 }, at, p.at + 2, sx8(d))
    }
  }
}

/// `f7`: the test immediate, the negation, and the multiply and divide.
fn decode_unary(bytes: &[u8], at: usize, p: &Pfx) -> Option<Decoded> {
  let w64 = p.w == 1;
  let g = decode_reg2(bytes, p.at + 1, p.r, p.b);
  if !g.ok {
    None
  } else if g.ext == 0 {
    if have(bytes, p.at + 2, 4) {
      done(
        PInsn::AluImm {
          w64,
          op: AluRI::Test,
          dst: g.rm,
          imm: read32(bytes, p.at + 2) as i32,
        },
        at,
        p.at + 6,
        0,
      )
    } else {
      None
    }
  } else if g.ext == 3 {
    done(PInsn::Neg { w64, dst: g.rm }, at, p.at + 2, 0)
  } else if g.rm != 1 {
    // The multiply and divide forms name RCX and nothing else.
    None
  } else if g.ext == 4 {
    done(
      PInsn::MulDivRcx {
        w64,
        kind: MulDivKind::Mul,
        signed: false,
      },
      at,
      p.at + 2,
      0,
    )
  } else if g.ext == 6 || g.ext == 7 {
    done(
      PInsn::MulDivRcx {
        w64,
        kind: MulDivKind::Div,
        signed: g.ext == 7,
      },
      at,
      p.at + 2,
      0,
    )
  } else {
    None
  }
}

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

/// Whether `n` zero bytes start at `at`.
fn zeros(bytes: &[u8], at: usize, n: usize) -> bool {
  let mut ok = have(bytes, at, n);
  let mut i: usize = 0;
  while ok && i < n {
    if bytes[at + i] != 0 {
      ok = false;
    }
    i += 1;
  }
  ok
}

/// The trailer's two data primitives, read as a last resort.
fn decode_data(bytes: &[u8], at: usize) -> Option<Decoded> {
  if zeros(bytes, at, HELPER_TABLE_LEN) {
    Some(Decoded {
      insn: PInsn::HelperTable,
      len: HELPER_TABLE_LEN,
      disp: 0,
    })
  } else if have(bytes, at, 8) {
    Some(Decoded {
      insn: PInsn::DispatcherSlot {
        addr: read64(bytes, at),
      },
      len: 8,
      disp: 0,
    })
  } else {
    None
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use super::super::x64_encode::{assemble, encode_one, offsets, size_of};
  use super::super::x64_expand::expand;
  use super::super::x64_ir::{cc, region, Cfg, MInsn, Target};

  // -----------------------------------------------------------------------
  // The shape a decoded primitive has
  // -----------------------------------------------------------------------

  /// What [`decode_one`] owes for `p`: `p` itself, except where the encoding
  /// is not injective.
  ///
  /// * a branch carries a placeholder target, because its label is not in its
  ///   bytes;
  /// * `ShiftImm` and the narrow `StoreImm` truncate their immediate;
  /// * a `LoadImm` that fits in 32 bits is `mov r64, imm32`, which is also
  ///   `AluImm { w64: true, op: Mov }`;
  /// * `Mod` is `Div` and `Mul` is unsigned: one x86 instruction apiece;
  /// * `RipLoadDispatcher` has no REX.R bit to carry a high destination.
  fn shape(p: PInsn) -> PInsn {
    match p {
      PInsn::ShiftImm { w64, op, dst, imm } => PInsn::ShiftImm {
        w64,
        op,
        dst,
        imm: imm & 0xff,
      },
      PInsn::StoreImm {
        size,
        base,
        disp,
        imm,
      } => {
        let imm = if size == 1 {
          imm & 0xff
        } else if size == 2 {
          imm & 0xffff
        } else {
          imm
        };
        PInsn::StoreImm {
          size,
          base,
          disp,
          imm,
        }
      }
      PInsn::LoadImm { dst, imm } => {
        if imm >= i32::MIN as i64 && imm <= i32::MAX as i64 {
          PInsn::AluImm {
            w64: true,
            op: AluRI::Mov,
            dst,
            imm: imm as i32,
          }
        } else {
          p
        }
      }
      PInsn::MulDivRcx { w64, kind, signed } => match kind {
        MulDivKind::Mul => PInsn::MulDivRcx {
          w64,
          kind: MulDivKind::Mul,
          signed: false,
        },
        _ => PInsn::MulDivRcx {
          w64,
          kind: MulDivKind::Div,
          signed,
        },
      },
      PInsn::Jcc { cc, target: _ } => PInsn::Jcc {
        cc,
        target: PTarget::Local(0),
      },
      PInsn::Jmp { target: _ } => PInsn::Jmp {
        target: PTarget::Local(0),
      },
      PInsn::JmpNear { target: _ } => PInsn::JmpNear {
        target: PTarget::Local(0),
      },
      PInsn::Call { target: _ } => PInsn::Call {
        target: PTarget::Local(0),
      },
      PInsn::Jcc8 { cc, target: _ } => PInsn::Jcc8 { cc, target: 0 },
      PInsn::Jmp8 { target: _ } => PInsn::Jmp8 { target: 0 },
      PInsn::RipLoadDispatcher { dst } => PInsn::RipLoadDispatcher { dst: dst & 7 },
      _ => p,
    }
  }

  /// Encodes `p` on its own, checks [`size_of`] against the bytes, and
  /// decodes them back.
  #[track_caller]
  fn roundtrip(p: PInsn) {
    let mut bytes: Vec<u8> = Vec::new();
    encode_one(&p, &mut bytes);
    assert!(!bytes.is_empty(), "{p:?} encodes to nothing");
    assert_eq!(size_of(&p), bytes.len(), "size_of disagrees for {p:?}");
    let want = Decoded {
      insn: shape(p),
      len: bytes.len(),
      disp: 0,
    };
    assert_eq!(
      decode_one(&bytes, 0),
      Some(want),
      "roundtrip failed for {p:?}: {bytes:02x?}"
    );
  }

  // -----------------------------------------------------------------------
  // The operand sweeps
  // -----------------------------------------------------------------------

  /// Every native register, in every operand position.
  fn regs() -> Vec<u8> {
    (0..16u8).collect()
  }

  /// Displacements at every boundary the ModRM encoding has, and at the ends
  /// of the range.
  const DISPS: [i32; 11] = [
    0,
    1,
    -1,
    127,
    -127,
    128,
    -128,
    4096,
    -4096,
    i32::MIN,
    i32::MAX,
  ];

  /// Immediates, likewise.
  const IMMS: [i32; 11] = DISPS;

  const CCS: [u8; 10] = [
    cc::B,
    cc::AE,
    cc::E,
    cc::NE,
    cc::BE,
    cc::A,
    cc::L,
    cc::GE,
    cc::LE,
    cc::G,
  ];

  const ALU_RR: [AluRR; 8] = [
    AluRR::Add,
    AluRR::Sub,
    AluRR::Or,
    AluRR::And,
    AluRR::Xor,
    AluRR::Mov,
    AluRR::Cmp,
    AluRR::Test,
  ];

  const ALU_RI: [AluRI; 8] = [
    AluRI::Add,
    AluRI::Or,
    AluRI::And,
    AluRI::Sub,
    AluRI::Xor,
    AluRI::Cmp,
    AluRI::Mov,
    AluRI::Test,
  ];

  const ALU_RM: [AluRM; 5] = [
    AluRM::Sub,
    AluRM::Add,
    AluRM::CmpMR,
    AluRM::CmpRM,
    AluRM::Or,
  ];

  const SHIFTS: [ShiftOp; 3] = [ShiftOp::Shl, ShiftOp::Shr, ShiftOp::Sar];

  const KINDS: [MulDivKind; 3] = [MulDivKind::Mul, MulDivKind::Div, MulDivKind::Mod];

  const SIZES: [Size; 4] = [1, 2, 4, 8];

  const WIDTHS: [bool; 2] = [false, true];

  // -----------------------------------------------------------------------
  // Roundtrips
  // -----------------------------------------------------------------------

  #[test]
  fn every_register_only_form_round_trips() {
    let mut cases = 0;
    for r in regs() {
      roundtrip(PInsn::Push(r));
      roundtrip(PInsn::Pop(r));
      roundtrip(PInsn::CallReg(r));
      cases += 3;
      for w64 in WIDTHS {
        roundtrip(PInsn::Neg { w64, dst: r });
        roundtrip(PInsn::Bswap { w64, dst: r });
        cases += 2;
        for op in SHIFTS {
          roundtrip(PInsn::ShiftCl { w64, op, dst: r });
          cases += 1;
          for imm in IMMS {
            roundtrip(PInsn::ShiftImm {
              w64,
              op,
              dst: r,
              imm,
            });
            cases += 1;
          }
        }
        for op in ALU_RI {
          for imm in IMMS {
            roundtrip(PInsn::AluImm {
              w64,
              op,
              dst: r,
              imm,
            });
            cases += 1;
          }
        }
        for src in regs() {
          for op in ALU_RR {
            roundtrip(PInsn::Alu {
              w64,
              op,
              src,
              dst: r,
            });
            cases += 1;
          }
          for from in [8u8, 16, 32] {
            roundtrip(PInsn::MovSx {
              from,
              w64,
              src,
              dst: r,
            });
            cases += 1;
          }
        }
      }
      roundtrip(PInsn::Rol16 { dst: r });
      cases += 1;
      for src in regs() {
        for c in CCS {
          roundtrip(PInsn::Cmov { cc: c, dst: r, src });
          cases += 1;
        }
      }
      for imm in [
        0i64,
        1,
        -1,
        i32::MIN as i64,
        i32::MAX as i64,
        i32::MAX as i64 + 1,
        i32::MIN as i64 - 1,
        i64::MIN,
        i64::MAX,
        0x0000_7f00_d15b_a000,
      ] {
        roundtrip(PInsn::LoadImm { dst: r, imm });
        cases += 1;
      }
      roundtrip(PInsn::RipLeaHelperTable { dst: r });
      cases += 1;
      if r < 8 {
        // The RIP-relative load's REX prefix has no `R` bit to spare, so it
        // can only name the low eight registers; the expansion only ever
        // names RAX.
        roundtrip(PInsn::RipLoadDispatcher { dst: r });
        cases += 1;
      }
    }
    for w64 in WIDTHS {
      roundtrip(PInsn::CmpRcxMinusOne { w64 });
      for kind in KINDS {
        for signed in WIDTHS {
          roundtrip(PInsn::MulDivRcx { w64, kind, signed });
          cases += 1;
        }
      }
    }
    for imm in [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
      roundtrip(PInsn::CmpEaxImm { imm });
      cases += 1;
    }
    for p in [
      PInsn::Pushfq,
      PInsn::Popfq,
      PInsn::Cqo,
      PInsn::Cdq,
      PInsn::Ret,
      PInsn::Pause,
      PInsn::Ud2,
      PInsn::StoreRspRax,
    ] {
      roundtrip(p);
      cases += 1;
    }
    for imm in [0u32, 1, 0xffff_ffff] {
      roundtrip(PInsn::StoreRspImm { imm });
      cases += 1;
    }
    assert!(cases > 10_000, "the sweep shrank to {cases} cases");
  }

  #[test]
  fn every_memory_form_round_trips() {
    let mut cases = 0;
    for base in regs() {
      for disp in DISPS {
        for size in SIZES {
          for reg in regs() {
            roundtrip(PInsn::Load {
              size,
              sx: false,
              base,
              dst: reg,
              disp,
            });
            roundtrip(PInsn::Store {
              size,
              src: reg,
              base,
              disp,
            });
            cases += 2;
            if size != 8 {
              // The sign-extending eight-byte load encodes nothing.
              roundtrip(PInsn::Load {
                size,
                sx: true,
                base,
                dst: reg,
                disp,
              });
              cases += 1;
            }
            for w64 in WIDTHS {
              roundtrip(PInsn::LockCmpxchg {
                w64,
                src: reg,
                base,
                disp,
              });
              roundtrip(PInsn::Xchg {
                w64,
                src: reg,
                base,
                disp,
              });
              cases += 2;
              for op in [0x01u8, 0x09, 0x21, 0x31] {
                roundtrip(PInsn::LockAlu {
                  op,
                  w64,
                  src: reg,
                  base,
                  disp,
                });
                cases += 1;
              }
            }
          }
          for imm in IMMS {
            roundtrip(PInsn::StoreImm {
              size,
              base,
              disp,
              imm,
            });
            cases += 1;
          }
        }
        for op in ALU_RM {
          for reg in regs() {
            roundtrip(PInsn::AluRM {
              op,
              reg,
              base,
              disp,
            });
            cases += 1;
          }
        }
      }
    }
    assert!(cases > 10_000, "the sweep shrank to {cases} cases");
  }

  #[test]
  fn every_branch_form_round_trips() {
    let mut cases = 0;
    for target in [
      PTarget::Pc(0),
      PTarget::Pc(7),
      PTarget::Exit,
      PTarget::Retpoline,
      PTarget::Local(3),
    ] {
      roundtrip(PInsn::Jmp { target });
      roundtrip(PInsn::JmpNear { target });
      roundtrip(PInsn::Call { target });
      cases += 3;
      for c in CCS {
        roundtrip(PInsn::Jcc { cc: c, target });
        cases += 1;
      }
    }
    for n in [0u32, 1, 9, 65535] {
      roundtrip(PInsn::Jmp8 { target: n });
      cases += 1;
      for c in CCS {
        roundtrip(PInsn::Jcc8 { cc: c, target: n });
        cases += 1;
      }
    }
    assert!(cases > 50, "the sweep shrank to {cases} cases");
  }

  #[test]
  fn the_data_primitives_round_trip() {
    // A dispatcher address is not self-describing; these decode as data
    // because no instruction encoding starts with a zero byte.
    for addr in [
      0u64,
      0x0000_7f00_d15b_a000,
      0x0000_7f00_0e50_1000,
      0xffff_ffff_ffff_ff00,
    ] {
      roundtrip(PInsn::DispatcherSlot { addr });
    }
    roundtrip(PInsn::HelperTable);
  }

  #[test]
  fn the_primitives_that_encode_nothing_encode_nothing() {
    for p in [
      PInsn::PcLabel(3),
      PInsn::Local(4),
      PInsn::ExitLabel,
      PInsn::RetpolineLabel,
      PInsn::Load {
        size: 8,
        sx: true,
        base: 1,
        dst: 2,
        disp: 16,
      },
    ] {
      let mut bytes = Vec::new();
      encode_one(&p, &mut bytes);
      assert!(bytes.is_empty(), "{p:?} encoded {bytes:02x?}");
      assert_eq!(size_of(&p), 0, "{p:?}");
    }
  }

  // -----------------------------------------------------------------------
  // Whole functions
  // -----------------------------------------------------------------------

  fn cfg() -> Cfg {
    Cfg {
      pointer_mask: -1,
      native_frame_base: true,
      frame_constants: true,
      stack_frame_size: 4096,
      stack_frame_stride: 4096,
      // A low byte of zero, so the trailer's eight data bytes start with a
      // byte no instruction encoding uses.
      dispatcher: 0x0000_7f00_d15b_a000,
      unwind_helper_index: -1,
      has_local_call_callbacks: true,
      local_call_resolver: 0x0000_7f00_0e50_1000,
      local_call_stack_exhausted: 0x0000_7f00_57ac_0000,
    }
  }

  /// Where a label landed, recomputed from the primitive list the way the
  /// assembler does.
  fn label_offset(code: &[PInsn], starts: &[u32], target: PTarget) -> i64 {
    let mut found: i64 = -1;
    for (i, p) in code.iter().enumerate() {
      let hit = match (*p, target) {
        (PInsn::PcLabel(a), PTarget::Pc(b)) => a == b,
        (PInsn::Local(a), PTarget::Local(b)) => a == b,
        (PInsn::ExitLabel, PTarget::Exit) => true,
        (PInsn::RetpolineLabel, PTarget::Retpoline) => true,
        _ => false,
      };
      if hit && found < 0 {
        found = starts[i] as i64;
      }
    }
    found
  }

  /// Where the trailer's dispatcher slot and helper table landed.
  fn data_offset(code: &[PInsn], starts: &[u32], table: bool) -> i64 {
    let mut found: i64 = -1;
    for (i, p) in code.iter().enumerate() {
      let hit = match *p {
        PInsn::DispatcherSlot { addr: _ } => !table,
        PInsn::HelperTable => table,
        _ => false,
      };
      if hit && found < 0 {
        found = starts[i] as i64;
      }
    }
    found
  }

  /// The displacement the assembler must have written into the primitive at
  /// `i`, and where in it the displacement sits.
  fn expected_disp(code: &[PInsn], starts: &[u32], i: usize) -> i64 {
    let here = starts[i] as i64;
    match code[i] {
      PInsn::Jcc { cc: _, target } => label_offset(code, starts, target) - (here + 6),
      PInsn::Jmp { target } => label_offset(code, starts, target) - (here + 5),
      PInsn::Call { target } => label_offset(code, starts, target) - (here + 5),
      PInsn::JmpNear { target } => label_offset(code, starts, target) - (here + 2),
      PInsn::Jcc8 { cc: _, target } => {
        label_offset(code, starts, PTarget::Local(target)) - (here + 2)
      }
      PInsn::Jmp8 { target } => label_offset(code, starts, PTarget::Local(target)) - (here + 2),
      PInsn::RipLoadDispatcher { dst: _ } => data_offset(code, starts, false) - (here + 7),
      PInsn::RipLeaHelperTable { dst: _ } => data_offset(code, starts, true) - (here + 7),
      _ => 0,
    }
  }

  /// Expands a macro list, assembles it, and decodes every primitive at the
  /// offset the assembler put it at.
  #[track_caller]
  fn walk(macros: &[MInsn]) -> usize {
    let mut code: Vec<PInsn> = Vec::new();
    expand(&cfg(), macros, &mut code);

    let mut starts: Vec<u32> = Vec::new();
    offsets(&code, &mut starts);

    let mut bytes: Vec<u8> = Vec::new();
    assemble(&code, &mut bytes).expect("the list assembles");
    assert_eq!(bytes.len(), starts[code.len()] as usize);

    let mut decoded = 0;
    for i in 0..code.len() {
      if size_of(&code[i]) == 0 {
        continue;
      }
      let at = starts[i] as usize;
      let got = decode_one(&bytes, at).unwrap_or_else(|| {
        panic!(
          "no decoding at {at} for {:?}: {:02x?}",
          code[i],
          &bytes[at..bytes.len().min(at + 16)]
        )
      });
      assert_eq!(
        got.insn,
        shape(code[i]),
        "decoded the wrong primitive at {at} (for {:?})",
        code[i]
      );
      assert_eq!(got.len, size_of(&code[i]), "wrong length at {at}");
      assert_eq!(
        got.disp,
        expected_disp(&code, &starts, i),
        "wrong displacement at {at} (for {:?})",
        code[i]
      );
      decoded += 1;
    }
    decoded
  }

  /// A function: the prologue, a body, then the epilogue and the trailer.
  fn function(body: &[MInsn]) -> Vec<MInsn> {
    let mut code = vec![MInsn::Prologue {
      usage: 64,
      skip: true,
    }];
    code.extend_from_slice(body);
    code.push(MInsn::Epilogue);
    code.push(MInsn::Retpoline);
    code.push(MInsn::DispatcherSlot);
    code.push(MInsn::HelperTable);
    code
  }

  #[test]
  fn real_expansions_decode_at_the_offsets_the_assembler_recorded() {
    let bodies: Vec<Vec<MInsn>> = vec![
      vec![
        MInsn::PcLabel(0),
        MInsn::Alu {
          w64: true,
          op: AluRR::Mov,
          src: 0,
          dst: 3,
        },
        MInsn::AluImm {
          w64: false,
          op: AluRI::Add,
          dst: 3,
          imm: -4096,
        },
        MInsn::Jcc {
          cc: cc::E,
          target: Target::Pc(0),
        },
        MInsn::PcLabel(1),
        MInsn::Jmp {
          target: Target::Exit,
        },
      ],
      vec![
        MInsn::PcLabel(0),
        MInsn::CheckedAddr {
          src: 3,
          dst: 1,
          scratch: 11,
          offset: 16,
          size: 8,
          region: region::UNKNOWN,
        },
        MInsn::Load {
          size: 8,
          sx: false,
          base: 1,
          dst: 3,
          disp: 0,
        },
        MInsn::GroupBaseStore { src: 1 },
        MInsn::GroupBaseLoad { dst: 2 },
        MInsn::Store {
          size: 2,
          src: 3,
          base: 2,
          disp: 4,
        },
        MInsn::StoreImm {
          size: 4,
          base: 2,
          disp: -8,
          imm: -1,
        },
      ],
      vec![
        MInsn::PcLabel(0),
        MInsn::MulDivMod {
          kind: MulDivKind::Div,
          w64: true,
          reg: true,
          signed: true,
          src: 3,
          dst: 6,
          imm: 0,
        },
        MInsn::MulDivMod {
          kind: MulDivKind::Mod,
          w64: false,
          reg: false,
          signed: true,
          src: 0,
          dst: 6,
          imm: 7,
        },
        MInsn::MulDivMod {
          kind: MulDivKind::Mul,
          w64: true,
          reg: false,
          signed: false,
          src: 0,
          dst: 6,
          imm: 3,
        },
      ],
      vec![
        MInsn::PcLabel(0),
        MInsn::AtomicAlu {
          op: 0x01,
          w64: true,
          src: 3,
          base: 12,
          disp: 8,
        },
        MInsn::AtomicFetchAlu {
          op: 0x21,
          w64: false,
          src: 3,
          base: 12,
          disp: -128,
        },
        MInsn::AtomicXchg {
          w64: true,
          src: 3,
          base: 13,
          disp: 0,
        },
        MInsn::AtomicCmpxchg {
          w64: true,
          src: 3,
          base: 5,
          disp: 0,
        },
      ],
      vec![
        MInsn::PcLabel(0),
        MInsn::HelperCall { idx: 3 },
        MInsn::GuestFp { dst: 3 },
        MInsn::MovSx {
          from: 16,
          w64: true,
          src: 3,
          dst: 3,
        },
        MInsn::Bswap { w64: false, dst: 3 },
        MInsn::Rol16 { dst: 3 },
        MInsn::LoadImm {
          dst: 3,
          imm: 0x1234_5678_9abc,
        },
      ],
      vec![MInsn::PcLabel(0), MInsn::LazyLocalCall { id: 2 }],
    ];

    let mut decoded = 0;
    for body in &bodies {
      decoded += walk(&function(body));
    }
    assert!(
      decoded > 200,
      "only {decoded} primitives were decoded; the expansions shrank"
    );
  }
}

//! The eBPF instruction set: the wire layout of one instruction and the
//! decoder from opcode byte to [`Op`].
//!
//! There is a single [`Op`] enum and a single [`decode`] that produces it, and
//! every consumer `match`es it without a catch-all, so an opcode added to the
//! enum is a compile error everywhere it must be handled.
//!
//! The numeric constants are the eBPF wire format; the census in
//! `jit::isa`'s tests pins the exact set of opcode bytes the decoder accepts.

/// A single eBPF instruction, unpacked exactly as `jit::isa::Insn` unpacks it.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Hash))]
pub struct Insn {
  pub opcode: u8,
  pub dst: u8,
  pub src: u8,
  pub offset: i16,
  pub imm: i32,
}

// ---------------------------------------------------------------------------
// The instruction set, as `jit::isa` decodes it
// ---------------------------------------------------------------------------

pub const CLS_MASK: u8 = 0x07;
pub const CLS_LD: u8 = 0x00;
pub const CLS_LDX: u8 = 0x01;
pub const CLS_ST: u8 = 0x02;
pub const CLS_STX: u8 = 0x03;
pub const CLS_ALU: u8 = 0x04;
pub const CLS_JMP: u8 = 0x05;
pub const CLS_JMP32: u8 = 0x06;
pub const CLS_ALU64: u8 = 0x07;

pub const SRC_REG: u8 = 0x08;

pub const SIZE_MASK: u8 = 0x18;
pub const SIZE_W: u8 = 0x00;
pub const SIZE_H: u8 = 0x08;
pub const SIZE_B: u8 = 0x10;
pub const SIZE_DW: u8 = 0x18;

pub const MODE_MASK: u8 = 0xe0;
pub const MODE_IMM: u8 = 0x00;
pub const MODE_MEM: u8 = 0x60;
pub const MODE_MEMSX: u8 = 0x80;
pub const MODE_ATOMIC: u8 = 0xc0;

pub const ALU_MASK: u8 = 0xf0;
pub const ALU_ADD: u8 = 0x00;
pub const ALU_SUB: u8 = 0x10;
pub const ALU_MUL: u8 = 0x20;
pub const ALU_DIV: u8 = 0x30;
pub const ALU_OR: u8 = 0x40;
pub const ALU_AND: u8 = 0x50;
pub const ALU_LSH: u8 = 0x60;
pub const ALU_RSH: u8 = 0x70;
pub const ALU_NEG: u8 = 0x80;
pub const ALU_MOD: u8 = 0x90;
pub const ALU_XOR: u8 = 0xa0;
pub const ALU_MOV: u8 = 0xb0;
pub const ALU_ARSH: u8 = 0xc0;
pub const ALU_END: u8 = 0xd0;

pub const JMP_MASK: u8 = 0xf0;
pub const JMP_JA: u8 = 0x00;
pub const JMP_JEQ: u8 = 0x10;
pub const JMP_JGT: u8 = 0x20;
pub const JMP_JGE: u8 = 0x30;
pub const JMP_JSET: u8 = 0x40;
pub const JMP_JNE: u8 = 0x50;
pub const JMP_JSGT: u8 = 0x60;
pub const JMP_JSGE: u8 = 0x70;
pub const JMP_CALL: u8 = 0x80;
pub const JMP_EXIT: u8 = 0x90;
pub const JMP_JLT: u8 = 0xa0;
pub const JMP_JLE: u8 = 0xb0;
pub const JMP_JSLT: u8 = 0xc0;
pub const JMP_JSLE: u8 = 0xd0;

pub const ATOMIC_OP_FETCH: i32 = 0x01;
pub const ATOMIC_OP_XCHG: i32 = 0xe0 | ATOMIC_OP_FETCH;
pub const ATOMIC_OP_CMPXCHG: i32 = 0xf0 | ATOMIC_OP_FETCH;

pub const OP_LDDW: u8 = 0x18;
pub const OP_CALL: u8 = 0x85;
pub const OP_EXIT: u8 = 0x95;
pub const OP_JA: u8 = 0x05;
pub const OP_JA32: u8 = 0x06;

#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub enum Width {
  B,
  H,
  W,
  DW,
}

#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub enum AluWidth {
  W32,
  W64,
}

#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub enum Source {
  Imm,
  Reg,
}

#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub enum AluOp {
  Add,
  Sub,
  Mul,
  Div,
  Or,
  And,
  Lsh,
  Rsh,
  Neg,
  Mod,
  Xor,
  Mov,
  Arsh,
}

#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub enum JmpOp {
  Eq,
  Gt,
  Ge,
  Set,
  Ne,
  Sgt,
  Sge,
  Lt,
  Le,
  Slt,
  Sle,
}

#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub enum EndKind {
  Le,
  Be,
  Bswap,
}

/// The atomic read-modify-write operation an atomic store performs.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub enum AtomicOp {
  Add,
  Or,
  And,
  Xor,
  Xchg,
  Cmpxchg,
}

/// Every defined eBPF instruction, decoded.
///
/// Consumers `match` this exhaustively. There is deliberately no catch-all
/// variant: an unrecognised opcode byte is `None` from [`decode`], which the
/// validator turns into a rejection, and everything downstream of the validator
/// can assume a defined opcode.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub enum Op {
  /// ALU or ALU64 arithmetic. `Neg` ignores the source.
  Alu {
    width: AluWidth,
    op: AluOp,
    source: Source,
  },
  /// `le` / `be` / `bswap`. The immediate carries the bit width.
  End(EndKind),
  /// `ldx` — load from `[src + offset]` into `dst`.
  Load { width: Width, signed: bool },
  /// `st` — store the immediate to `[dst + offset]`.
  StoreImm { width: Width },
  /// `stx` — store `src` to `[dst + offset]`.
  StoreReg { width: Width },
  /// `lddw` — 64-bit immediate load, occupying two instruction slots.
  LoadImm64,
  /// Atomic read-modify-write against `[dst + offset]`. Which operation is
  /// meant lives in the immediate, not the opcode, so [`decode`] fills in
  /// `Add` / `false` and `Insn::op_with_imm` decodes the selector.
  Atomic {
    width: Width,
    op: AtomicOp,
    fetch: bool,
  },
  /// Unconditional jump. `JMP` uses `offset`, `JMP32` uses `imm`.
  Ja { width: AluWidth },
  /// Conditional jump.
  Jmp {
    width: AluWidth,
    op: JmpOp,
    source: Source,
  },
  /// `call` — to a host helper (`src == 0`) or a local function (`src == 1`).
  Call,
  /// `exit` — return from the current function.
  Exit,
}

pub fn width_from_size_bits(bits: u8) -> Option<Width> {
  if bits == SIZE_B {
    Some(Width::B)
  } else if bits == SIZE_H {
    Some(Width::H)
  } else if bits == SIZE_W {
    Some(Width::W)
  } else if bits == SIZE_DW {
    Some(Width::DW)
  } else {
    None
  }
}

fn alu_op_from_nibble(nibble: u8) -> Option<AluOp> {
  if nibble == ALU_ADD {
    Some(AluOp::Add)
  } else if nibble == ALU_SUB {
    Some(AluOp::Sub)
  } else if nibble == ALU_MUL {
    Some(AluOp::Mul)
  } else if nibble == ALU_DIV {
    Some(AluOp::Div)
  } else if nibble == ALU_OR {
    Some(AluOp::Or)
  } else if nibble == ALU_AND {
    Some(AluOp::And)
  } else if nibble == ALU_LSH {
    Some(AluOp::Lsh)
  } else if nibble == ALU_RSH {
    Some(AluOp::Rsh)
  } else if nibble == ALU_NEG {
    Some(AluOp::Neg)
  } else if nibble == ALU_MOD {
    Some(AluOp::Mod)
  } else if nibble == ALU_XOR {
    Some(AluOp::Xor)
  } else if nibble == ALU_MOV {
    Some(AluOp::Mov)
  } else if nibble == ALU_ARSH {
    Some(AluOp::Arsh)
  } else {
    None
  }
}

fn jmp_op_from_nibble(nibble: u8) -> Option<JmpOp> {
  if nibble == JMP_JEQ {
    Some(JmpOp::Eq)
  } else if nibble == JMP_JGT {
    Some(JmpOp::Gt)
  } else if nibble == JMP_JGE {
    Some(JmpOp::Ge)
  } else if nibble == JMP_JSET {
    Some(JmpOp::Set)
  } else if nibble == JMP_JNE {
    Some(JmpOp::Ne)
  } else if nibble == JMP_JSGT {
    Some(JmpOp::Sgt)
  } else if nibble == JMP_JSGE {
    Some(JmpOp::Sge)
  } else if nibble == JMP_JLT {
    Some(JmpOp::Lt)
  } else if nibble == JMP_JLE {
    Some(JmpOp::Le)
  } else if nibble == JMP_JSLT {
    Some(JmpOp::Slt)
  } else if nibble == JMP_JSLE {
    Some(JmpOp::Sle)
  } else {
    None
  }
}

fn is_neg(op: AluOp) -> bool {
  match op {
    AluOp::Neg => true,
    _ => false,
  }
}

fn is_reg(source: Source) -> bool {
  match source {
    Source::Reg => true,
    Source::Imm => false,
  }
}

fn is_w64(width: AluWidth) -> bool {
  match width {
    AluWidth::W64 => true,
    AluWidth::W32 => false,
  }
}

fn is_w(width: Width) -> bool {
  match width {
    Width::W => true,
    _ => false,
  }
}

fn is_dw(width: Width) -> bool {
  match width {
    Width::DW => true,
    _ => false,
  }
}

/// Decodes an opcode byte. Returns `None` for undefined encodings.
///
/// This deliberately says nothing about whether the *operands* are legal —
/// that is [`super::validate`]'s job. A defined opcode with a register number
/// out of range still decodes here.
pub fn decode(opcode: u8) -> Option<Op> {
  let source = if opcode & SRC_REG != 0 {
    Source::Reg
  } else {
    Source::Imm
  };
  let cls = opcode & CLS_MASK;

  if cls == CLS_ALU || cls == CLS_ALU64 {
    let width = if cls == CLS_ALU64 {
      AluWidth::W64
    } else {
      AluWidth::W32
    };
    if opcode & ALU_MASK == ALU_END {
      return match (width, source) {
        (AluWidth::W32, Source::Imm) => Some(Op::End(EndKind::Le)),
        (AluWidth::W32, Source::Reg) => Some(Op::End(EndKind::Be)),
        (AluWidth::W64, Source::Imm) => Some(Op::End(EndKind::Bswap)),
        (AluWidth::W64, Source::Reg) => None,
      };
    }
    let Some(op) = alu_op_from_nibble(opcode & ALU_MASK) else {
      return None;
    };
    // `neg` has no source operand and is only defined with the source bit
    // clear. Enum comparisons are spelled as matches: a derived `PartialEq`
    // extracts through `read_discriminant`, which Lean cannot evaluate.
    if is_neg(op) && is_reg(source) {
      return None;
    }
    return Some(Op::Alu { width, op, source });
  }

  if cls == CLS_LD {
    if opcode == OP_LDDW {
      return Some(Op::LoadImm64);
    }
    return None;
  }

  if cls == CLS_LDX {
    let Some(width) = width_from_size_bits(opcode & SIZE_MASK) else {
      return None;
    };
    let mode = opcode & MODE_MASK;
    if mode == MODE_MEM {
      return Some(Op::Load {
        width,
        signed: false,
      });
    }
    if mode == MODE_MEMSX && !is_dw(width) {
      return Some(Op::Load {
        width,
        signed: true,
      });
    }
    return None;
  }

  if cls == CLS_ST {
    let Some(width) = width_from_size_bits(opcode & SIZE_MASK) else {
      return None;
    };
    if opcode & MODE_MASK == MODE_MEM {
      return Some(Op::StoreImm { width });
    }
    return None;
  }

  if cls == CLS_STX {
    let Some(width) = width_from_size_bits(opcode & SIZE_MASK) else {
      return None;
    };
    let mode = opcode & MODE_MASK;
    if mode == MODE_MEM {
      return Some(Op::StoreReg { width });
    }
    if mode == MODE_ATOMIC && (is_w(width) || is_dw(width)) {
      return Some(Op::Atomic {
        width,
        op: AtomicOp::Add,
        fetch: false,
      });
    }
    return None;
  }

  // cls is JMP or JMP32: the class is three bits and every other value is
  // handled above.
  let width = if cls == CLS_JMP32 {
    AluWidth::W32
  } else {
    AluWidth::W64
  };
  let nibble = opcode & JMP_MASK;
  if nibble == JMP_JA {
    if is_reg(source) {
      return None;
    }
    return Some(Op::Ja { width });
  }
  if nibble == JMP_CALL {
    if is_w64(width) && !is_reg(source) {
      return Some(Op::Call);
    }
    return None;
  }
  if nibble == JMP_EXIT {
    if is_w64(width) && !is_reg(source) {
      return Some(Op::Exit);
    }
    return None;
  }
  let Some(op) = jmp_op_from_nibble(nibble) else {
    return None;
  };
  Some(Op::Jmp { width, op, source })
}

// ---------------------------------------------------------------------------
// Runtime conveniences, invisible to the extraction
// ---------------------------------------------------------------------------

#[cfg(not(feature = "extract"))]
impl std::fmt::Debug for Insn {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "Insn {{ op: {:#04x}, dst: r{}, src: r{}, off: {}, imm: {} }}",
      self.opcode, self.dst, self.src, self.offset, self.imm
    )
  }
}

// The codec and the decoder wrappers are the ISA's API; the runtime does not
// call every one of them outside its tests.
#[cfg(not(feature = "extract"))]
#[allow(dead_code)]
impl Insn {
  /// Decodes one instruction from its little-endian 8-byte wire form.
  ///
  /// `dst` and `src` occupy one byte on the wire as two nibbles; this and
  /// [`Insn::to_u64`] are the only places that know about the packing.
  pub const fn from_u64(raw: u64) -> Self {
    Self {
      opcode: (raw & 0xff) as u8,
      dst: ((raw >> 8) & 0x0f) as u8,
      src: ((raw >> 12) & 0x0f) as u8,
      offset: ((raw >> 16) & 0xffff) as u16 as i16,
      imm: ((raw >> 32) & 0xffff_ffff) as u32 as i32,
    }
  }

  /// Re-encodes the instruction to its little-endian 8-byte wire form.
  pub const fn to_u64(self) -> u64 {
    (self.opcode as u64)
      | ((self.dst as u64 & 0x0f) << 8)
      | ((self.src as u64 & 0x0f) << 12)
      | ((self.offset as u16 as u64) << 16)
      | ((self.imm as u32 as u64) << 32)
  }

  /// Decodes a whole instruction stream. `code.len()` must be a multiple of 8.
  pub fn decode_all(code: &[u8]) -> Option<Vec<Insn>> {
    if code.len() % 8 != 0 {
      return None;
    }
    Some(
      code
        .chunks_exact(8)
        .map(|c| Insn::from_u64(u64::from_le_bytes(c.try_into().unwrap())))
        .collect(),
    )
  }

  /// Encodes a whole instruction stream back to bytes.
  pub fn encode_all(insns: &[Insn]) -> Vec<u8> {
    let mut out = Vec::with_capacity(insns.len() * 8);
    for insn in insns {
      out.extend_from_slice(&insn.to_u64().to_le_bytes());
    }
    out
  }

  /// The instruction class, i.e. the low three opcode bits.
  pub const fn class(self) -> u8 {
    self.opcode & CLS_MASK
  }

  /// Whether this instruction is a 128-bit `lddw`, whose second slot is not an
  /// instruction but the high half of the immediate.
  pub const fn is_lddw(self) -> bool {
    self.opcode == OP_LDDW
  }

  /// Whether this instruction is a call to another eBPF function in the same
  /// program, rather than to a host helper.
  pub const fn is_local_call(self) -> bool {
    self.opcode == OP_CALL && self.src == 1
  }

  /// Whether control can fall through to the next instruction.
  ///
  /// Only `exit` cannot. An unconditional jump counts as falling through, which
  /// is deliberately conservative rather than exact: the one caller asks this to
  /// decide whether a local function entry needs a branch emitted around its
  /// prologue, so a spurious yes costs one unreachable jump and a spurious no
  /// would let control run into the prologue of the function that follows.
  pub const fn has_fallthrough(self) -> bool {
    self.opcode != OP_EXIT
  }

  /// Decodes the opcode into the exhaustive [`Op`] enum, or `None` if the byte
  /// is not a defined encoding.
  ///
  /// This deliberately says nothing about whether the *operands* are legal —
  /// that is [`super::validate`]'s job. A defined opcode with a register
  /// number out of range still decodes here.
  pub fn op(self) -> Option<Op> {
    decode(self.opcode)
  }

  /// Decodes the opcode *and* the immediate, which for atomic stores is where
  /// the operation selector lives.
  ///
  /// Returns `None` for an undefined opcode or an undefined atomic selector.
  pub fn op_with_imm(self) -> Option<Op> {
    match self.op()? {
      Op::Atomic { width, .. } => {
        // The selector is the immediate's *high nibble*, and the fetch flag is
        // its low bit. Everything in between is ignored.
        //
        // That matters more than it looks. Clearing only the fetch bit — the
        // obvious reading — decodes every canonical selector correctly and then
        // rejects the non-canonical ones. Those reach here: `validate`'s filter
        // for 32-bit atomics bounds the immediate at `0..=255` rather than
        // enumerating legal values, so any immediate whose dead middle bits are
        // set still loads. `imm = 0x02` and `0x0f` mask to `ALU_ADD`, `0x4e`
        // to `OR`, `0xff` to `CMPXCHG`. Reading only the high nibble is what
        // keeps the decoder and the validator agreeing about which programs
        // exist; a stricter decode here turns loadable programs into
        // `UnknownInstruction` at translation time, on inputs a fuzzer reaches
        // quickly.
        //
        // `imm = 0xe0` and `0xf0` are decoded the same way for consistency but
        // do not in fact reach a backend: `validate` refuses exchange and
        // compare-exchange with the fetch bit clear, at both widths.
        let fetch = self.imm & ATOMIC_OP_FETCH != 0;
        let op = match (self.imm & ALU_MASK as i32) as u8 {
          ALU_ADD => AtomicOp::Add,
          ALU_OR => AtomicOp::Or,
          ALU_AND => AtomicOp::And,
          ALU_XOR => AtomicOp::Xor,
          sel if sel == (ATOMIC_OP_XCHG & !ATOMIC_OP_FETCH) as u8 => AtomicOp::Xchg,
          sel if sel == (ATOMIC_OP_CMPXCHG & !ATOMIC_OP_FETCH) as u8 => AtomicOp::Cmpxchg,
          _ => return None,
        };
        Some(Op::Atomic { width, op, fetch })
      }
      other => Some(other),
    }
  }
}

#[cfg(not(feature = "extract"))]
#[allow(dead_code)]
impl Op {
  /// Decodes an opcode byte. Returns `None` for undefined encodings.
  pub fn from_opcode(opcode: u8) -> Option<Op> {
    decode(opcode)
  }
}

#[cfg(not(feature = "extract"))]
#[allow(dead_code)]
impl Width {
  /// Decodes the size field of a load/store opcode.
  pub const fn from_size_bits(bits: u8) -> Option<Width> {
    match bits {
      SIZE_B => Some(Width::B),
      SIZE_H => Some(Width::H),
      SIZE_W => Some(Width::W),
      SIZE_DW => Some(Width::DW),
      _ => None,
    }
  }

  /// The number of bytes this access touches.
  pub const fn bytes(self) -> usize {
    match self {
      Width::B => 1,
      Width::H => 2,
      Width::W => 4,
      Width::DW => 8,
    }
  }

  /// The size bits this width encodes to.
  pub const fn size_bits(self) -> u8 {
    match self {
      Width::W => SIZE_W,
      Width::H => SIZE_H,
      Width::B => SIZE_B,
      Width::DW => SIZE_DW,
    }
  }
}

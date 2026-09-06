//! The load-time validator, restated in the subset of Rust that Aeneas can
//! translate to Lean.
//!
//! This crate is the *proof kernel* of `crate::jit::validate` in the runtime.
//! It reproduces the same decisions in the same order — the opcode match, the
//! `src > 10` bound, the `dst > 9` bound with its store-form exception, the
//! per-opcode operand filter, and the sub-program self-containment check — but
//! with everything Aeneas cannot model removed:
//!
//! * rejection *messages* become variants of [`Reject`] carrying the slot;
//! * the embedder's helper-index callback becomes [`Config::accept_every_helper`]
//!   plus an explicit list of known indices;
//! * the `const` filter table becomes the function [`filter_for`], and the
//!   enumerated offset/immediate sets become [`offset_ok`] and [`imm_ok`];
//! * the local-call target is computed in exact `i64` arithmetic rather than
//!   wrapping `i32`. Both refuse exactly the same programs: the wrapped and the
//!   exact target are equal whenever no wrap occurs, and a wrap can only produce
//!   a target that is out of range either way. Only the number quoted in the
//!   message differs, and this crate quotes no numbers.
//! * `sort_unstable` + `dedup` over the sub-program start list becomes a
//!   boolean array indexed by slot, which is the same set.
//!
//! What ties it to the runtime is `src/jit/validate.rs`'s
//! `the_kernel_agrees_with_the_validator` test, which runs both over the
//! recorded decision sweeps and asserts they accept and refuse the same
//! programs. What ties it to Lean is `lean/AsyncEbpf/Validate.lean`, which
//! Aeneas generates from this file, and the theorems proved about that output.
//!
//! Style constraints, all of them for the translator's sake: no closures, no
//! iterator chains, no `String`, no wrapping arithmetic, one loop per function,
//! and every early return in the function that owns the loop.

/// A single eBPF instruction, unpacked exactly as `jit::isa::Insn` unpacks it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Insn {
  pub opcode: u8,
  pub dst: u8,
  pub src: u8,
  pub offset: i16,
  pub imm: i32,
}

/// The two facts about a `jit::Config` that the validator consults.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Config {
  /// Exclusive upper bound on instruction slots; a program of exactly this
  /// many is refused.
  pub instruction_limit: usize,
  /// Whether a helper dispatcher *and* its validation callback are registered.
  /// Without both, every helper call is unknown.
  pub has_dispatcher: bool,
  /// Stand-in for a validation callback that accepts every index. When false,
  /// an index is known only if it appears in the list handed to [`validate`].
  pub accept_every_helper: bool,
}

/// Why a program was refused, and at which slot. One variant per distinct
/// rejection message of the runtime validator.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Reject {
  TooManyInstructions,
  UnknownOpcode(usize),
  NegSrc(usize),
  EndianImm(usize),
  LddwSrc(usize),
  IncompleteLddw(usize),
  LddwSecondHalf(usize),
  AtomicUnknown(usize),
  AtomicNeedsFetch(usize),
  InfiniteLoop(usize),
  JumpOutOfBounds(usize),
  JumpIntoLddw(usize),
  CrossSectionMetadata(usize),
  HelperImm(usize),
  UnknownHelper(usize),
  LocalCallOutOfBounds(usize),
  CallIntoLddw(usize),
  BtfCall(usize),
  CallType(usize),
  InvalidSrc(usize),
  InvalidDst(usize),
  FilterOpcode(usize),
  FilterDst(usize),
  FilterSrc(usize),
  FilterImm(usize),
  FilterOffset(usize),
  SubProgramJump(usize),
  SubProgramEnd(usize),
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

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Width {
  B,
  H,
  W,
  DW,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AluWidth {
  W32,
  W64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Source {
  Imm,
  Reg,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EndKind {
  Le,
  Be,
  Bswap,
}

/// Every defined instruction, decoded from its opcode byte alone. Mirrors
/// `jit::isa::Op` variant for variant, minus the atomic operation selector,
/// which lives in the immediate and is checked by [`check_atomic_selector`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Op {
  Alu(AluWidth, AluOp, Source),
  End(EndKind),
  Load(Width, bool),
  StoreImm(Width),
  StoreReg(Width),
  LoadImm64,
  Atomic(Width),
  Ja(AluWidth),
  Jmp(AluWidth, JmpOp, Source),
  Call,
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

/// Decodes an opcode byte. `None` for an undefined encoding. Same decisions as
/// `jit::isa::Op::from_opcode`, arm for arm.
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
    if op == AluOp::Neg && source == Source::Reg {
      return None;
    }
    return Some(Op::Alu(width, op, source));
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
      return Some(Op::Load(width, false));
    }
    if mode == MODE_MEMSX && width != Width::DW {
      return Some(Op::Load(width, true));
    }
    return None;
  }

  if cls == CLS_ST {
    let Some(width) = width_from_size_bits(opcode & SIZE_MASK) else {
      return None;
    };
    if opcode & MODE_MASK == MODE_MEM {
      return Some(Op::StoreImm(width));
    }
    return None;
  }

  if cls == CLS_STX {
    let Some(width) = width_from_size_bits(opcode & SIZE_MASK) else {
      return None;
    };
    let mode = opcode & MODE_MASK;
    if mode == MODE_MEM {
      return Some(Op::StoreReg(width));
    }
    if mode == MODE_ATOMIC && (width == Width::W || width == Width::DW) {
      return Some(Op::Atomic(width));
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
    if source == Source::Reg {
      return None;
    }
    return Some(Op::Ja(width));
  }
  if nibble == JMP_CALL {
    if width == AluWidth::W64 && source == Source::Imm {
      return Some(Op::Call);
    }
    return None;
  }
  if nibble == JMP_EXIT {
    if width == AluWidth::W64 && source == Source::Imm {
      return Some(Op::Exit);
    }
    return None;
  }
  let Some(op) = jmp_op_from_nibble(nibble) else {
    return None;
  };
  Some(Op::Jmp(width, op, source))
}

// ---------------------------------------------------------------------------
// Layer 1: the per-opcode operand filter
// ---------------------------------------------------------------------------

/// Inclusive register, offset and immediate bounds for one opcode. The
/// enumerated sets some opcodes carry are in [`offset_ok`] and [`imm_ok`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Filter {
  pub src_lo: u8,
  pub src_hi: u8,
  pub dst_lo: u8,
  pub dst_hi: u8,
  pub off_lo: i16,
  pub off_hi: i16,
  pub imm_lo: i32,
  pub imm_hi: i32,
}

const fn filter(src: (u8, u8), dst: (u8, u8), off: (i16, i16), imm: (i32, i32)) -> Filter {
  Filter {
    src_lo: src.0,
    src_hi: src.1,
    dst_lo: dst.0,
    dst_hi: dst.1,
    off_lo: off.0,
    off_hi: off.1,
    imm_lo: imm.0,
    imm_hi: imm.1,
  }
}

const ANY_OFF: (i16, i16) = (i16::MIN, i16::MAX);
const NO_OFF: (i16, i16) = (0, 0);
const ANY_IMM: (i32, i32) = (i32::MIN, i32::MAX);
const NO_IMM: (i32, i32) = (0, 0);

pub const ALU_IMM: Filter = filter((0, 0), (0, 9), NO_OFF, ANY_IMM);
pub const ALU_REG: Filter = filter((0, 10), (0, 9), NO_OFF, NO_IMM);
pub const DIV_IMM: Filter = filter((0, 0), (0, 9), (0, 1), ANY_IMM);
pub const DIV_REG: Filter = filter((0, 10), (0, 9), (0, 1), NO_IMM);
pub const NEG: Filter = filter((0, 0), (0, 9), NO_OFF, NO_IMM);
pub const ENDIAN: Filter = filter((0, 0), (0, 9), NO_OFF, (0, 64));
/// `movsx32` / `movsx64`: register bounds as `ALU_REG`; the offset is
/// enumerated in [`offset_ok`], so the range here is never consulted.
pub const MOVSX: Filter = ALU_REG;
pub const LDX: Filter = filter((0, 10), (0, 9), ANY_OFF, NO_IMM);
pub const ST: Filter = filter((0, 0), (0, 10), ANY_OFF, ANY_IMM);
pub const STX: Filter = filter((0, 10), (0, 10), ANY_OFF, NO_IMM);
pub const LDDW: Filter = filter((0, 6), (0, 9), NO_OFF, ANY_IMM);
pub const LDDW_HIGH: Filter = filter((0, 0), (0, 0), NO_OFF, ANY_IMM);
pub const JA: Filter = filter((0, 0), (0, 0), ANY_OFF, NO_IMM);
pub const JA32: Filter = filter((0, 0), (0, 0), NO_OFF, ANY_IMM);
pub const JMP_IMM: Filter = filter((0, 0), (0, 9), ANY_OFF, ANY_IMM);
pub const JMP_REG: Filter = filter((0, 10), (0, 9), ANY_OFF, NO_IMM);
pub const CALL: Filter = filter((0, 2), (0, 0), NO_OFF, ANY_IMM);
pub const EXIT: Filter = filter((0, 0), (0, 0), NO_OFF, NO_IMM);
pub const ATOMIC32: Filter = filter((0, 9), (0, 10), ANY_OFF, (0, 255));
/// The 64-bit atomic's immediate is enumerated in [`imm_ok`]; the range here
/// is never consulted.
pub const ATOMIC64: Filter = filter((0, 9), (0, 10), ANY_OFF, NO_IMM);

/// The filter table, one row per opcode. Same 120 entries as the runtime's
/// `FILTERS`, grouped the same way.
pub fn filter_for(opcode: u8) -> Option<Filter> {
  match opcode {
    0x04 | 0x14 | 0x24 | 0x44 | 0x54 | 0x64 | 0x74 | 0xa4 | 0xb4 | 0xc4 | 0x07 | 0x17 | 0x27
    | 0x47 | 0x57 | 0x67 | 0x77 | 0xa7 | 0xb7 | 0xc7 => Some(ALU_IMM),
    0x0c | 0x1c | 0x2c | 0x4c | 0x5c | 0x6c | 0x7c | 0xac | 0xcc | 0x0f | 0x1f | 0x2f | 0x4f
    | 0x5f | 0x6f | 0x7f | 0xaf | 0xcf => Some(ALU_REG),
    0x34 | 0x94 | 0x37 | 0x97 => Some(DIV_IMM),
    0x3c | 0x9c | 0x3f | 0x9f => Some(DIV_REG),
    0x84 | 0x87 => Some(NEG),
    0xd4 | 0xd7 | 0xdc => Some(ENDIAN),
    0xbc | 0xbf => Some(MOVSX),
    0x61 | 0x69 | 0x71 | 0x79 | 0x81 | 0x89 | 0x91 => Some(LDX),
    0x62 | 0x6a | 0x72 | 0x7a => Some(ST),
    0x63 | 0x6b | 0x73 | 0x7b => Some(STX),
    0x18 => Some(LDDW),
    0x00 => Some(LDDW_HIGH),
    0x05 => Some(JA),
    0x06 => Some(JA32),
    0x15 | 0x25 | 0x35 | 0x45 | 0x55 | 0x65 | 0x75 | 0xa5 | 0xb5 | 0xc5 | 0xd5 | 0x16 | 0x26
    | 0x36 | 0x46 | 0x56 | 0x66 | 0x76 | 0xa6 | 0xb6 | 0xc6 | 0xd6 => Some(JMP_IMM),
    0x1d | 0x2d | 0x3d | 0x4d | 0x5d | 0x6d | 0x7d | 0xad | 0xbd | 0xcd | 0xdd | 0x1e | 0x2e
    | 0x3e | 0x4e | 0x5e | 0x6e | 0x7e | 0xae | 0xbe | 0xce | 0xde => Some(JMP_REG),
    0x85 => Some(CALL),
    0x95 => Some(EXIT),
    0xc3 => Some(ATOMIC32),
    0xdb => Some(ATOMIC64),
    _ => None,
  }
}

/// The offset check: an enumerated set for the two `movsx` forms, the row's
/// range for everything else.
pub fn offset_ok(opcode: u8, f: &Filter, offset: i16) -> bool {
  if opcode == 0xbc {
    offset == 0 || offset == 8 || offset == 16
  } else if opcode == 0xbf {
    offset == 0 || offset == 8 || offset == 16 || offset == 32
  } else {
    offset >= f.off_lo && offset <= f.off_hi
  }
}

/// The immediate check: an enumerated set for the 64-bit atomic, the row's
/// range for everything else.
pub fn imm_ok(opcode: u8, f: &Filter, imm: i32) -> bool {
  if opcode == 0xdb {
    imm == 0x00
      || imm == 0x01
      || imm == 0x40
      || imm == 0x41
      || imm == 0x50
      || imm == 0x51
      || imm == 0xa0
      || imm == 0xa1
      || imm == 0xe1
      || imm == 0xf1
  } else {
    imm >= f.imm_lo && imm <= f.imm_hi
  }
}

/// Applies the operand filter to one instruction, in the runtime's order:
/// destination, source, immediate, offset.
pub fn check_operand_filter(insn: &Insn, pc: usize) -> Result<(), Reject> {
  let Some(f) = filter_for(insn.opcode) else {
    return Err(Reject::FilterOpcode(pc));
  };
  if insn.dst < f.dst_lo || insn.dst > f.dst_hi {
    return Err(Reject::FilterDst(pc));
  }
  if insn.src < f.src_lo || insn.src > f.src_hi {
    return Err(Reject::FilterSrc(pc));
  }
  if !imm_ok(insn.opcode, &f, insn.imm) {
    return Err(Reject::FilterImm(pc));
  }
  if !offset_ok(insn.opcode, &f, insn.offset) {
    return Err(Reject::FilterOffset(pc));
  }
  Ok(())
}

// ---------------------------------------------------------------------------
// Layer 2: whole-program validation
// ---------------------------------------------------------------------------

/// Checks the operation selector an atomic store carries in its immediate.
pub fn check_atomic_selector(insn: &Insn, pc: usize) -> Result<(), Reject> {
  let fetch = insn.imm & ATOMIC_OP_FETCH != 0;
  let op = insn.imm & (ALU_MASK as i32);
  if op == ALU_ADD as i32 || op == ALU_OR as i32 || op == ALU_AND as i32 || op == ALU_XOR as i32 {
    return Ok(());
  }
  if op == (ATOMIC_OP_XCHG & !ATOMIC_OP_FETCH) || op == (ATOMIC_OP_CMPXCHG & !ATOMIC_OP_FETCH) {
    if fetch {
      return Ok(());
    }
    return Err(Reject::AtomicNeedsFetch(pc));
  }
  Err(Reject::AtomicUnknown(pc))
}

/// Whether `index` names a helper the embedder recognises.
fn helper_known(config: &Config, known_helpers: &[u32], index: u32) -> bool {
  if !config.has_dispatcher {
    return false;
  }
  if config.accept_every_helper {
    return true;
  }
  let mut k = 0;
  while k < known_helpers.len() {
    if known_helpers[k] == index {
      return true;
    }
    k += 1;
  }
  false
}

/// Checks one `call` instruction. The source field is the call kind.
pub fn check_call(
  config: &Config,
  known_helpers: &[u32],
  insn: &Insn,
  insns: &[Insn],
  pc: usize,
  cross_section: bool,
) -> Result<(), Reject> {
  let num_insns = insns.len();
  if cross_section && insn.src != 2 {
    return Err(Reject::CrossSectionMetadata(pc));
  }
  if insn.src == 0 {
    if insn.imm < 0 {
      return Err(Reject::HelperImm(pc));
    }
    if !helper_known(config, known_helpers, insn.imm as u32) {
      return Err(Reject::UnknownHelper(pc));
    }
    return Ok(());
  }
  if insn.src == 1 {
    let target = pc as i64 + 1 + insn.imm as i64;
    if target < 0 || target >= num_insns as i64 {
      return Err(Reject::LocalCallOutOfBounds(pc));
    }
    if insns[target as usize].opcode == 0 {
      return Err(Reject::CallIntoLddw(pc));
    }
    return Ok(());
  }
  if insn.src == 2 {
    if cross_section {
      return Ok(());
    }
    return Err(Reject::BtfCall(pc));
  }
  Err(Reject::CallType(pc))
}

/// The per-slot body of [`validate`]'s loop. Returns whether the slot after
/// `pc` is the high half of a `lddw` and must be skipped.
pub fn check_slot(
  config: &Config,
  known_helpers: &[u32],
  insns: &[Insn],
  external_calls: &[bool],
  pc: usize,
) -> Result<bool, Reject> {
  let num_insns = insns.len();
  let insn = insns[pc];
  let mut store = false;
  let mut skip_next = false;

  let Some(op) = decode(insn.opcode) else {
    return Err(Reject::UnknownOpcode(pc));
  };

  match op {
    Op::Alu(_, AluOp::Neg, _) => {
      if insn.src != 0 {
        return Err(Reject::NegSrc(pc));
      }
    }
    Op::End(_) => {
      if insn.imm != 16 && insn.imm != 32 && insn.imm != 64 {
        return Err(Reject::EndianImm(pc));
      }
    }
    Op::LoadImm64 => {
      if insn.src != 0 {
        return Err(Reject::LddwSrc(pc));
      }
      if pc + 1 >= num_insns || insns[pc + 1].opcode != 0 {
        return Err(Reject::IncompleteLddw(pc));
      }
      let high = insns[pc + 1];
      if high.dst != 0 || high.src != 0 || high.offset != 0 {
        return Err(Reject::LddwSecondHalf(pc + 1));
      }
      skip_next = true;
    }
    Op::StoreImm(_) | Op::StoreReg(_) => store = true,
    Op::Atomic(_) => {
      store = true;
      check_atomic_selector(&insn, pc)?;
    }
    Op::Ja(_) | Op::Jmp(_, _, _) => {
      let displacement = if insn.opcode == OP_JA32 {
        insn.imm
      } else {
        insn.offset as i32
      };
      if displacement == -1 {
        return Err(Reject::InfiniteLoop(pc));
      }
      let target = pc as i64 + 1 + displacement as i64;
      if target < 0 || target >= num_insns as i64 {
        return Err(Reject::JumpOutOfBounds(pc));
      }
      if insns[target as usize].opcode == 0 {
        return Err(Reject::JumpIntoLddw(pc));
      }
    }
    Op::Call => {
      let cross_section = if pc < external_calls.len() {
        external_calls[pc]
      } else {
        false
      };
      check_call(config, known_helpers, &insn, insns, pc, cross_section)?;
    }
    Op::Exit | Op::Alu(_, _, _) | Op::Load(_, _) => {}
  }

  if insn.src > 10 {
    return Err(Reject::InvalidSrc(pc));
  }
  // R10 is the frame pointer and read-only. The store forms name it as a
  // memory base rather than writing it, so they are the exception.
  if insn.dst > 9 && !(store && insn.dst == 10) {
    return Err(Reject::InvalidDst(pc));
  }

  check_operand_filter(&insn, pc)?;
  Ok(skip_next)
}

/// Validates a decoded program.
pub fn validate(
  config: &Config,
  known_helpers: &[u32],
  insns: &[Insn],
  external_calls: &[bool],
) -> Result<(), Reject> {
  if insns.len() >= config.instruction_limit {
    return Err(Reject::TooManyInstructions);
  }
  let num_insns = insns.len();
  let mut i = 0;
  while i < num_insns {
    let skip_next = check_slot(config, known_helpers, insns, external_calls, i)?;
    if skip_next {
      i += 2;
    } else {
      i += 1;
    }
  }
  check_self_contained_sub_programs(insns)
}

fn is_local_call(insn: &Insn) -> bool {
  insn.opcode == OP_CALL && insn.src == 1
}

fn is_unconditional_jump(insn: &Insn) -> bool {
  insn.opcode == OP_JA || insn.opcode == OP_JA32
}

/// Marks every local-call target as a sub-program start. Returns whether the
/// program contains any local call at all.
fn mark_sub_program_starts(insns: &[Insn], is_start: &mut Vec<bool>) -> bool {
  let mut any = false;
  let mut i = 0;
  while i < insns.len() {
    if is_local_call(&insns[i]) {
      // `validate` established this lands inside the program.
      let target = (i as i64 + 1 + insns[i].imm as i64) as usize;
      is_start[target] = true;
      any = true;
    }
    i += 1;
  }
  any
}

/// The end of the sub-program starting at `start`: the next start, or the end
/// of the program.
fn sub_program_end(is_start: &[bool], start: usize) -> usize {
  let mut end = start + 1;
  while end < is_start.len() {
    if is_start[end] {
      return end;
    }
    end += 1;
  }
  is_start.len()
}

/// One sub-program `[start, end)`: every jump lands inside it, and it ends
/// in `exit` or has an unconditional jump in one of its last two slots.
fn check_sub_program(insns: &[Insn], start: usize, end: usize) -> Result<(), Reject> {
  let mut j = start;
  while j < end {
    let insn = insns[j];
    let cls = insn.opcode & CLS_MASK;
    if (cls == CLS_JMP || cls == CLS_JMP32) && insn.opcode != OP_CALL && insn.opcode != OP_EXIT {
      let displacement = if insn.opcode == OP_JA32 {
        insn.imm as i64
      } else {
        insn.offset as i64
      };
      let target = j as i64 + 1 + displacement;
      if target < start as i64 || target > end as i64 - 1 {
        return Err(Reject::SubProgramJump(j));
      }
    }
    j += 1;
  }

  let ends_with_exit = insns[end - 1].opcode == OP_EXIT;
  let ends_with_jump = is_unconditional_jump(&insns[end - 1])
    || (end >= start + 2 && is_unconditional_jump(&insns[end - 2]));
  if !ends_with_exit && !ends_with_jump {
    return Err(Reject::SubProgramEnd(end - 1));
  }
  Ok(())
}

/// Rejects programs whose sub-programs are not self-contained. Skipped
/// entirely when the program contains no local call.
pub fn check_self_contained_sub_programs(insns: &[Insn]) -> Result<(), Reject> {
  let num_insns = insns.len();
  let mut is_start: Vec<bool> = vec![false; num_insns];
  if !mark_sub_program_starts(insns, &mut is_start) {
    return Ok(());
  }
  is_start[0] = true;

  let mut start = 0;
  while start < num_insns {
    let end = sub_program_end(&is_start, start);
    check_sub_program(insns, start, end)?;
    start = end;
  }
  Ok(())
}

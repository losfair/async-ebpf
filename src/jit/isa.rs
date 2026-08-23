//! eBPF instruction encoding, decoded exactly once.
//!
//! The C runtime decodes the opcode byte independently in `validate()`, in the
//! interpreter, and in each JIT backend's `switch`, and every one of those ends
//! in a `default:` label. Adding an opcode there means remembering three places.
//! Here there is one [`Op`] enum and one [`Insn::op`], and every consumer
//! `match`es it without a catch-all arm, so an opcode added to the ISA is a
//! compile error everywhere it must be handled.
//!
//! The numeric constants are the wire format and are reproduced from
//! `vendor/ubpf/vm/ebpf.h`.

/// Number of eBPF general-purpose registers, `R0` through `R10`.
pub const NUM_REGS: usize = 11;

/// The frame pointer register.
pub const REG_FP: u8 = 10;

/// Instruction classes (low three bits of the opcode).
pub mod cls {
  pub const MASK: u8 = 0x07;
  pub const LD: u8 = 0x00;
  pub const LDX: u8 = 0x01;
  pub const ST: u8 = 0x02;
  pub const STX: u8 = 0x03;
  pub const ALU: u8 = 0x04;
  pub const JMP: u8 = 0x05;
  pub const JMP32: u8 = 0x06;
  pub const ALU64: u8 = 0x07;
}

/// Source modifier: immediate or register operand.
pub mod src {
  pub const IMM: u8 = 0x00;
  pub const REG: u8 = 0x08;
}

/// Access size for load/store classes.
pub mod size {
  pub const W: u8 = 0x00;
  pub const H: u8 = 0x08;
  pub const B: u8 = 0x10;
  pub const DW: u8 = 0x18;
}

/// Addressing modes.
///
/// The mode occupies the top *three* bits of the opcode, so [`MASK`] is `0xe0`.
/// Masking with `0xc0` — which the two highest mode values happen to fit in —
/// silently rejects every plain `ldx`/`stx` encoding and accepts five byte
/// values that name nothing.
pub mod mode {
  pub const MASK: u8 = 0xe0;
  pub const IMM: u8 = 0x00;
  pub const MEM: u8 = 0x60;
  pub const MEMSX: u8 = 0x80;
  pub const ATOMIC: u8 = 0xc0;
}

/// ALU operation selector (high nibble of an ALU/ALU64 opcode).
pub mod alu {
  pub const MASK: u8 = 0xf0;
  pub const ADD: u8 = 0x00;
  pub const SUB: u8 = 0x10;
  pub const MUL: u8 = 0x20;
  pub const DIV: u8 = 0x30;
  pub const OR: u8 = 0x40;
  pub const AND: u8 = 0x50;
  pub const LSH: u8 = 0x60;
  pub const RSH: u8 = 0x70;
  pub const NEG: u8 = 0x80;
  pub const MOD: u8 = 0x90;
  pub const XOR: u8 = 0xa0;
  pub const MOV: u8 = 0xb0;
  pub const ARSH: u8 = 0xc0;
  pub const END: u8 = 0xd0;
}

/// Jump operation selector (high nibble of a JMP/JMP32 opcode).
pub mod jmp {
  pub const MASK: u8 = 0xf0;
  pub const JA: u8 = 0x00;
  pub const JEQ: u8 = 0x10;
  pub const JGT: u8 = 0x20;
  pub const JGE: u8 = 0x30;
  pub const JSET: u8 = 0x40;
  pub const JNE: u8 = 0x50;
  pub const JSGT: u8 = 0x60;
  pub const JSGE: u8 = 0x70;
  pub const CALL: u8 = 0x80;
  pub const EXIT: u8 = 0x90;
  pub const JLT: u8 = 0xa0;
  pub const JLE: u8 = 0xb0;
  pub const JSLT: u8 = 0xc0;
  pub const JSLE: u8 = 0xd0;
}

/// Atomic operation selectors, carried in the immediate of an atomic store.
pub mod atomic {
  pub const OP_FETCH: i32 = 0x01;
  pub const OP_XCHG: i32 = 0xe0 | OP_FETCH;
  pub const OP_CMPXCHG: i32 = 0xf0 | OP_FETCH;
}

/// Named opcode bytes, for call sites that want to test one specific encoding
/// rather than match on a decoded [`Op`].
pub mod opcode {
  use super::{alu, cls, jmp, mode, size, src};

  pub const LDDW: u8 = cls::LD | mode::IMM | size::DW;
  pub const CALL: u8 = cls::JMP | jmp::CALL;
  pub const EXIT: u8 = cls::JMP | jmp::EXIT;
  pub const JA: u8 = cls::JMP | jmp::JA;
  pub const JA32: u8 = cls::JMP32 | jmp::JA;
  pub const LE: u8 = cls::ALU | src::IMM | alu::END;
  pub const BE: u8 = cls::ALU | src::REG | alu::END;
  pub const BSWAP: u8 = cls::ALU64 | src::IMM | alu::END;
  pub const ATOMIC32_STORE: u8 = cls::STX | mode::ATOMIC | size::W;
  pub const ATOMIC_STORE: u8 = cls::STX | mode::ATOMIC | size::DW;
}

/// A single eBPF instruction, in the wire layout.
///
/// `dst` and `src` occupy one byte on the wire as two nibbles; they are stored
/// unpacked here. [`Insn::decode`] and [`Insn::encode`] are the only places that
/// know about the packing.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Insn {
  pub opcode: u8,
  pub dst: u8,
  pub src: u8,
  pub offset: i16,
  pub imm: i32,
}

impl std::fmt::Debug for Insn {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "Insn {{ op: {:#04x}, dst: r{}, src: r{}, off: {}, imm: {} }}",
      self.opcode, self.dst, self.src, self.offset, self.imm
    )
  }
}

impl Insn {
  /// Decodes one instruction from its little-endian 8-byte wire form.
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
    self.opcode & cls::MASK
  }

  /// Whether this instruction is a 128-bit `lddw`, whose second slot is not an
  /// instruction but the high half of the immediate.
  pub const fn is_lddw(self) -> bool {
    self.opcode == opcode::LDDW
  }

  /// Whether this instruction is a call to another eBPF function in the same
  /// program, rather than to a host helper.
  pub const fn is_local_call(self) -> bool {
    self.opcode == opcode::CALL && self.src == 1
  }

  /// Whether control can fall through to the next instruction. Only `exit`
  /// cannot; an unconditional jump still "falls through" for the purposes uBPF
  /// uses this for, matching `ubpf_instruction_has_fallthrough()`.
  pub const fn has_fallthrough(self) -> bool {
    self.opcode != opcode::EXIT
  }

  /// Decodes the opcode into the exhaustive [`Op`] enum, or `None` if the byte
  /// is not a defined encoding.
  ///
  /// This deliberately says nothing about whether the *operands* are legal —
  /// that is [`crate::jit::validate`]'s job. A defined opcode with a register
  /// number out of range still decodes here.
  pub fn op(self) -> Option<Op> {
    Op::from_opcode(self.opcode)
  }
}

/// Width of a memory access, in bytes.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum Width {
  B = 1,
  H = 2,
  W = 4,
  DW = 8,
}

impl Width {
  /// Decodes the size field of a load/store opcode.
  pub const fn from_size_bits(bits: u8) -> Option<Width> {
    match bits {
      size::B => Some(Width::B),
      size::H => Some(Width::H),
      size::W => Some(Width::W),
      size::DW => Some(Width::DW),
      _ => None,
    }
  }

  /// The number of bytes this access touches.
  pub const fn bytes(self) -> usize {
    self as usize
  }

  /// The size bits this width encodes to.
  pub const fn size_bits(self) -> u8 {
    match self {
      Width::W => size::W,
      Width::H => size::H,
      Width::B => size::B,
      Width::DW => size::DW,
    }
  }
}

/// Whether an ALU instruction operates on the full 64-bit register or on the
/// low 32 bits with zero-extension of the result.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum AluWidth {
  W32,
  W64,
}

/// Whether the second operand comes from a register or the immediate field.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum Source {
  Imm,
  Reg,
}

/// The arithmetic and logical operations.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
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

/// The comparison a conditional jump performs.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
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

/// Byte-order conversion flavour.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum EndKind {
  /// `le`: convert to little-endian (a no-op on a little-endian host).
  Le,
  /// `be`: convert to big-endian.
  Be,
  /// `bswap`: unconditional byte reversal, ALU64 class.
  Bswap,
}

/// The atomic read-modify-write operation an atomic store performs.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
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
/// variant: an unrecognised opcode byte is `None` from [`Insn::op`], which the
/// validator turns into a rejection, and everything downstream of the validator
/// can assume a defined opcode.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
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
  /// Atomic read-modify-write against `[dst + offset]`.
  Atomic { width: Width, op: AtomicOp, fetch: bool },
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

impl Op {
  /// Decodes an opcode byte. Returns `None` for undefined encodings.
  pub fn from_opcode(opcode: u8) -> Option<Op> {
    let source = if opcode & src::REG != 0 {
      Source::Reg
    } else {
      Source::Imm
    };

    match opcode & cls::MASK {
      cls::ALU | cls::ALU64 => {
        let width = if opcode & cls::MASK == cls::ALU64 {
          AluWidth::W64
        } else {
          AluWidth::W32
        };
        // `end` is selected by the ALU op nibble, but which flavour depends on
        // both the class and the source bit: ALU/IMM is `le`, ALU/REG is `be`,
        // and ALU64/IMM is `bswap`. ALU64/REG is not a defined encoding.
        if opcode & alu::MASK == alu::END {
          return match (width, source) {
            (AluWidth::W32, Source::Imm) => Some(Op::End(EndKind::Le)),
            (AluWidth::W32, Source::Reg) => Some(Op::End(EndKind::Be)),
            (AluWidth::W64, Source::Imm) => Some(Op::End(EndKind::Bswap)),
            (AluWidth::W64, Source::Reg) => None,
          };
        }
        let op = match opcode & alu::MASK {
          alu::ADD => AluOp::Add,
          alu::SUB => AluOp::Sub,
          alu::MUL => AluOp::Mul,
          alu::DIV => AluOp::Div,
          alu::OR => AluOp::Or,
          alu::AND => AluOp::And,
          alu::LSH => AluOp::Lsh,
          alu::RSH => AluOp::Rsh,
          alu::NEG => AluOp::Neg,
          alu::MOD => AluOp::Mod,
          alu::XOR => AluOp::Xor,
          alu::MOV => AluOp::Mov,
          alu::ARSH => AluOp::Arsh,
          _ => return None,
        };
        // `neg` has no source operand and is only defined with the source bit
        // clear.
        if op == AluOp::Neg && source == Source::Reg {
          return None;
        }
        Some(Op::Alu { width, op, source })
      }

      cls::LD => {
        // The only defined `ld` encoding is the 64-bit immediate load.
        if opcode == opcode::LDDW {
          Some(Op::LoadImm64)
        } else {
          None
        }
      }

      cls::LDX => {
        let width = Width::from_size_bits(opcode & size::DW)?;
        match opcode & mode::MASK {
          mode::MEM => Some(Op::Load {
            width,
            signed: false,
          }),
          // Sign-extending loads are defined for byte, half and word only:
          // a sign-extended doubleword would be the same as a plain one.
          mode::MEMSX if width != Width::DW => Some(Op::Load {
            width,
            signed: true,
          }),
          _ => None,
        }
      }

      cls::ST => {
        let width = Width::from_size_bits(opcode & size::DW)?;
        match opcode & mode::MASK {
          mode::MEM => Some(Op::StoreImm { width }),
          _ => None,
        }
      }

      cls::STX => {
        let width = Width::from_size_bits(opcode & size::DW)?;
        match opcode & mode::MASK {
          mode::MEM => Some(Op::StoreReg { width }),
          // Atomics are defined at word and doubleword width only. Which
          // operation is meant lives in the immediate, not the opcode, so the
          // opcode alone cannot say - `Op::Atomic`'s `op` and `fetch` are
          // filled in by `Insn::op_with_imm`.
          mode::ATOMIC if width == Width::W || width == Width::DW => Some(Op::Atomic {
            width,
            op: AtomicOp::Add,
            fetch: false,
          }),
          _ => None,
        }
      }

      cls::JMP | cls::JMP32 => {
        let width = if opcode & cls::MASK == cls::JMP32 {
          AluWidth::W32
        } else {
          AluWidth::W64
        };
        match opcode & jmp::MASK {
          jmp::JA => {
            // `ja` takes no source operand.
            if source == Source::Reg {
              return None;
            }
            Some(Op::Ja { width })
          }
          // `call` and `exit` are JMP-class only; there is no 32-bit form.
          jmp::CALL if width == AluWidth::W64 && source == Source::Imm => Some(Op::Call),
          jmp::EXIT if width == AluWidth::W64 && source == Source::Imm => Some(Op::Exit),
          other => {
            let op = match other {
              jmp::JEQ => JmpOp::Eq,
              jmp::JGT => JmpOp::Gt,
              jmp::JGE => JmpOp::Ge,
              jmp::JSET => JmpOp::Set,
              jmp::JNE => JmpOp::Ne,
              jmp::JSGT => JmpOp::Sgt,
              jmp::JSGE => JmpOp::Sge,
              jmp::JLT => JmpOp::Lt,
              jmp::JLE => JmpOp::Le,
              jmp::JSLT => JmpOp::Slt,
              jmp::JSLE => JmpOp::Sle,
              _ => return None,
            };
            Some(Op::Jmp { width, op, source })
          }
        }
      }

      _ => unreachable!("class is masked to three bits and all eight are handled"),
    }
  }
}

impl Insn {
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
        // diverges on the non-canonical ones the C happily accepts: `imm = 0x02`
        // masks to `ALU_OP_ADD` and emits a plain atomic add, and `imm = 0xe0`
        // is an `xchg` without the fetch flag. The validator's filter for
        // 32-bit atomics bounds the immediate at `0..=255` rather than
        // enumerating legal values, so both of those reach the backend on a
        // program that loads. A stricter decode here turns them into
        // `UnknownInstruction` where the C emits code — a byte-level
        // divergence, on an input a fuzzer reaches quickly.
        let fetch = self.imm & atomic::OP_FETCH != 0;
        let op = match (self.imm & alu::MASK as i32) as u8 {
          alu::ADD => AtomicOp::Add,
          alu::OR => AtomicOp::Or,
          alu::AND => AtomicOp::And,
          alu::XOR => AtomicOp::Xor,
          sel if sel == (atomic::OP_XCHG & !atomic::OP_FETCH) as u8 => AtomicOp::Xchg,
          sel if sel == (atomic::OP_CMPXCHG & !atomic::OP_FETCH) as u8 => AtomicOp::Cmpxchg,
          _ => return None,
        };
        Some(Op::Atomic { width, op, fetch })
      }
      other => Some(other),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn wire_round_trip_preserves_every_field() {
    let insn = Insn {
      opcode: 0xb7,
      dst: 9,
      src: 3,
      offset: -1234,
      imm: -987_654,
    };
    assert_eq!(Insn::from_u64(insn.to_u64()), insn);
  }

  #[test]
  fn nibbles_land_in_the_documented_order() {
    // dst is the low nibble of byte 1, src the high nibble.
    let raw = Insn::from_u64(0x0000_0000_0000_3a07);
    assert_eq!(raw.opcode, 0x07);
    assert_eq!(raw.dst, 0xa);
    assert_eq!(raw.src, 0x3);
  }

  #[test]
  fn the_end_family_is_selected_by_class_and_source_together() {
    assert_eq!(Op::from_opcode(opcode::LE), Some(Op::End(EndKind::Le)));
    assert_eq!(Op::from_opcode(opcode::BE), Some(Op::End(EndKind::Be)));
    assert_eq!(Op::from_opcode(opcode::BSWAP), Some(Op::End(EndKind::Bswap)));
    // ALU64 | SRC_REG | END is not a defined encoding.
    assert_eq!(Op::from_opcode(cls::ALU64 | src::REG | alu::END), None);
  }

  #[test]
  fn a_sign_extending_doubleword_load_is_not_an_encoding() {
    assert_eq!(Op::from_opcode(cls::LDX | mode::MEMSX | size::DW), None);
    for (bits, width) in [(size::B, Width::B), (size::H, Width::H), (size::W, Width::W)] {
      assert_eq!(
        Op::from_opcode(cls::LDX | mode::MEMSX | bits),
        Some(Op::Load {
          width,
          signed: true
        })
      );
    }
  }

  #[test]
  fn atomics_exist_only_at_word_and_doubleword_width() {
    assert!(Op::from_opcode(opcode::ATOMIC32_STORE).is_some());
    assert!(Op::from_opcode(opcode::ATOMIC_STORE).is_some());
    assert_eq!(Op::from_opcode(cls::STX | mode::ATOMIC | size::B), None);
    assert_eq!(Op::from_opcode(cls::STX | mode::ATOMIC | size::H), None);
  }

  #[test]
  fn the_atomic_selector_comes_from_the_immediate() {
    let mk = |imm| Insn {
      opcode: opcode::ATOMIC_STORE,
      dst: 1,
      src: 2,
      offset: 0,
      imm,
    };
    assert_eq!(
      mk(alu::ADD as i32).op_with_imm(),
      Some(Op::Atomic {
        width: Width::DW,
        op: AtomicOp::Add,
        fetch: false
      })
    );
    assert_eq!(
      mk(alu::ADD as i32 | atomic::OP_FETCH).op_with_imm(),
      Some(Op::Atomic {
        width: Width::DW,
        op: AtomicOp::Add,
        fetch: true
      })
    );
    assert_eq!(
      mk(atomic::OP_CMPXCHG).op_with_imm(),
      Some(Op::Atomic {
        width: Width::DW,
        op: AtomicOp::Cmpxchg,
        fetch: true
      })
    );
    assert_eq!(
      mk(atomic::OP_XCHG).op_with_imm(),
      Some(Op::Atomic {
        width: Width::DW,
        op: AtomicOp::Xchg,
        fetch: true
      })
    );
    // `mul` has no atomic form.
    assert_eq!(mk(alu::MUL as i32).op_with_imm(), None);
  }

  #[test]
  fn the_atomic_selector_is_the_high_nibble_and_ignores_the_middle_bits() {
    // Regression. The C computes `fetch = imm & 1` and switches on
    // `imm & 0xf0`, so bits 1-3 are dead. Decoding by clearing only the fetch
    // bit gets every canonical selector right and then diverges on exactly the
    // non-canonical ones the validator lets through for 32-bit atomics, where
    // its filter bounds the immediate at 0..=255 instead of enumerating.
    let mk = |imm| Insn {
      opcode: opcode::ATOMIC32_STORE,
      dst: 1,
      src: 2,
      offset: 0,
      imm,
    };
    // Middle bits set: still a plain add, not an unknown instruction.
    assert_eq!(
      mk(0x02).op_with_imm(),
      Some(Op::Atomic {
        width: Width::W,
        op: AtomicOp::Add,
        fetch: false
      })
    );
    assert_eq!(
      mk(0x0f).op_with_imm(),
      Some(Op::Atomic {
        width: Width::W,
        op: AtomicOp::Add,
        fetch: true
      })
    );
    // xchg and cmpxchg without the fetch bit are still xchg and cmpxchg.
    assert_eq!(
      mk(0xe0).op_with_imm(),
      Some(Op::Atomic {
        width: Width::W,
        op: AtomicOp::Xchg,
        fetch: false
      })
    );
    assert_eq!(
      mk(0xf0).op_with_imm(),
      Some(Op::Atomic {
        width: Width::W,
        op: AtomicOp::Cmpxchg,
        fetch: false
      })
    );
    // A high nibble that names nothing is still rejected.
    assert_eq!(mk(0x30).op_with_imm(), None);
    assert_eq!(mk(0xb0).op_with_imm(), None);
  }

  #[test]
  fn call_and_exit_have_no_thirty_two_bit_form() {
    assert_eq!(Op::from_opcode(opcode::CALL), Some(Op::Call));
    assert_eq!(Op::from_opcode(opcode::EXIT), Some(Op::Exit));
    assert_eq!(Op::from_opcode(cls::JMP32 | jmp::CALL), None);
    assert_eq!(Op::from_opcode(cls::JMP32 | jmp::EXIT), None);
  }

  #[test]
  fn neg_is_only_defined_without_a_source_register() {
    assert_eq!(
      Op::from_opcode(cls::ALU64 | alu::NEG),
      Some(Op::Alu {
        width: AluWidth::W64,
        op: AluOp::Neg,
        source: Source::Imm
      })
    );
    assert_eq!(Op::from_opcode(cls::ALU64 | src::REG | alu::NEG), None);
  }

  #[test]
  fn local_calls_are_distinguished_by_the_source_field() {
    let helper = Insn {
      opcode: opcode::CALL,
      dst: 0,
      src: 0,
      offset: 0,
      imm: 7,
    };
    let local = Insn { src: 1, ..helper };
    assert!(!helper.is_local_call());
    assert!(local.is_local_call());
  }

  /// The exact set of opcode bytes `vendor/ubpf/vm/ebpf.h` names, evaluated
  /// from its `EBPF_OP_*` defines. All 119 are distinct — the header has no
  /// aliases.
  ///
  /// Comparing against the set rather than against its cardinality is what
  /// makes a decode bug legible: a count-only check reports "112, expected 119"
  /// and leaves you guessing, where this names the twelve `ldx`/`stx`
  /// encodings that went missing and the five byte values that were accepted
  /// but name nothing.
  const C_NAMED_OPCODES: [u8; 119] = [
    0x04, 0x05, 0x06, 0x07, 0x0c, 0x0f, 0x14, 0x15, 0x16, 0x17, 0x18, 0x1c, 0x1d, 0x1e, 0x1f,
    0x24, 0x25, 0x26, 0x27, 0x2c, 0x2d, 0x2e, 0x2f, 0x34, 0x35, 0x36, 0x37, 0x3c, 0x3d, 0x3e,
    0x3f, 0x44, 0x45, 0x46, 0x47, 0x4c, 0x4d, 0x4e, 0x4f, 0x54, 0x55, 0x56, 0x57, 0x5c, 0x5d,
    0x5e, 0x5f, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
    0x6f, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x81, 0x84, 0x85, 0x87, 0x89, 0x91, 0x94, 0x95, 0x97, 0x9c, 0x9f, 0xa4, 0xa5, 0xa6, 0xa7,
    0xac, 0xad, 0xae, 0xaf, 0xb4, 0xb5, 0xb6, 0xb7, 0xbc, 0xbd, 0xbe, 0xbf, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xcc, 0xcd, 0xce, 0xcf, 0xd4, 0xd5, 0xd6, 0xd7, 0xdb, 0xdc, 0xdd, 0xde,
  ];

  #[test]
  fn the_decoder_accepts_exactly_the_opcodes_the_c_header_names() {
    use std::collections::BTreeSet;
    let named: BTreeSet<u8> = C_NAMED_OPCODES.into_iter().collect();
    assert_eq!(named.len(), 119, "the reference set has a duplicate");
    let decoded: BTreeSet<u8> = (0u8..=255).filter(|&b| Op::from_opcode(b).is_some()).collect();

    let missing: Vec<String> = named.difference(&decoded).map(|b| format!("{b:#04x}")).collect();
    let extra: Vec<String> = decoded.difference(&named).map(|b| format!("{b:#04x}")).collect();
    assert!(
      missing.is_empty() && extra.is_empty(),
      "decoder disagrees with ebpf.h\n  named but rejected: {missing:?}\n  accepted but unnamed: {extra:?}"
    );
  }

  #[test]
  fn the_mode_field_is_three_bits_wide() {
    // Regression: masking the mode with 0xc0 instead of 0xe0 still recognises
    // MEMSX and ATOMIC, because their values happen to fit, but silently
    // rejects every plain ldx/stx and accepts five byte values that name
    // nothing. The census above catches it; this pins the cause.
    assert_eq!(mode::MEM & mode::MASK, mode::MEM);
    assert_eq!(0x61 & mode::MASK, mode::MEM, "ldxw must decode as MEM");
    assert_eq!(0xa1 & mode::MASK, 0xa0, "0xa1 names no mode");
    assert_eq!(Op::from_opcode(0xa1), None);
    assert_eq!(Op::from_opcode(0xe3), None);
  }
}

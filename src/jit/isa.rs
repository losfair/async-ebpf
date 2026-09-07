//! eBPF instruction encoding, decoded exactly once.
//!
//! The types and the decoder live in [`crate::verified::isa`], the verified
//! core that the Lean proofs describe; this module re-exports them and names
//! the wire-format constants in the groups the backends use. The census in the
//! tests below pins the exact set of opcode bytes the decoder accepts.
//!
//! The obvious shape for this is a raw opcode byte that [`validate`], the
//! interpreter and each backend switch on independently, each ending in a
//! catch-all arm. Then adding an opcode means remembering every one of those
//! places, and forgetting one is silent. Here there is a single [`Op`] enum and
//! a single [`Insn::op`] that produces it, and every consumer `match`es it
//! without a catch-all, so an opcode added to the enum is a compile error
//! everywhere it must be handled.
//!
//! [`validate`]: crate::jit::validate

pub use crate::verified::isa::{
  AluOp, AluWidth, AtomicOp, EndKind, Insn, JmpOp, Op, Source, Width,
};

use crate::verified::isa as v;

/// Number of eBPF general-purpose registers, `R0` through `R10`.
pub const NUM_REGS: usize = 11;

/// The frame pointer register.
pub const REG_FP: u8 = 10;

/// Instruction classes (low three bits of the opcode).
pub mod cls {
  use super::v;
  pub const MASK: u8 = v::CLS_MASK;
  pub const LD: u8 = v::CLS_LD;
  pub const LDX: u8 = v::CLS_LDX;
  pub const ST: u8 = v::CLS_ST;
  pub const STX: u8 = v::CLS_STX;
  pub const ALU: u8 = v::CLS_ALU;
  pub const JMP: u8 = v::CLS_JMP;
  pub const JMP32: u8 = v::CLS_JMP32;
  pub const ALU64: u8 = v::CLS_ALU64;
}

/// Source modifier: immediate or register operand.
pub mod src {
  use super::v;
  pub const IMM: u8 = 0x00;
  pub const REG: u8 = v::SRC_REG;
}

/// Access size for load/store classes.
pub mod size {
  use super::v;
  pub const W: u8 = v::SIZE_W;
  pub const H: u8 = v::SIZE_H;
  pub const B: u8 = v::SIZE_B;
  pub const DW: u8 = v::SIZE_DW;
}

/// Addressing modes.
///
/// The mode occupies the top *three* bits of the opcode, so [`MASK`] is `0xe0`.
/// Masking with `0xc0` — which the two highest mode values happen to fit in —
/// silently rejects every plain `ldx`/`stx` encoding and accepts five byte
/// values that name nothing.
pub mod mode {
  use super::v;
  pub const MASK: u8 = v::MODE_MASK;
  pub const IMM: u8 = v::MODE_IMM;
  pub const MEM: u8 = v::MODE_MEM;
  pub const MEMSX: u8 = v::MODE_MEMSX;
  pub const ATOMIC: u8 = v::MODE_ATOMIC;
}

/// ALU operation selector (high nibble of an ALU/ALU64 opcode).
pub mod alu {
  use super::v;
  pub const MASK: u8 = v::ALU_MASK;
  pub const ADD: u8 = v::ALU_ADD;
  pub const SUB: u8 = v::ALU_SUB;
  pub const MUL: u8 = v::ALU_MUL;
  pub const DIV: u8 = v::ALU_DIV;
  pub const OR: u8 = v::ALU_OR;
  pub const AND: u8 = v::ALU_AND;
  pub const LSH: u8 = v::ALU_LSH;
  pub const RSH: u8 = v::ALU_RSH;
  pub const NEG: u8 = v::ALU_NEG;
  pub const MOD: u8 = v::ALU_MOD;
  pub const XOR: u8 = v::ALU_XOR;
  pub const MOV: u8 = v::ALU_MOV;
  pub const ARSH: u8 = v::ALU_ARSH;
  pub const END: u8 = v::ALU_END;
}

/// Jump operation selector (high nibble of a JMP/JMP32 opcode).
pub mod jmp {
  use super::v;
  pub const MASK: u8 = v::JMP_MASK;
  pub const JA: u8 = v::JMP_JA;
  pub const JEQ: u8 = v::JMP_JEQ;
  pub const JGT: u8 = v::JMP_JGT;
  pub const JGE: u8 = v::JMP_JGE;
  pub const JSET: u8 = v::JMP_JSET;
  pub const JNE: u8 = v::JMP_JNE;
  pub const JSGT: u8 = v::JMP_JSGT;
  pub const JSGE: u8 = v::JMP_JSGE;
  pub const CALL: u8 = v::JMP_CALL;
  pub const EXIT: u8 = v::JMP_EXIT;
  pub const JLT: u8 = v::JMP_JLT;
  pub const JLE: u8 = v::JMP_JLE;
  pub const JSLT: u8 = v::JMP_JSLT;
  pub const JSLE: u8 = v::JMP_JSLE;
}

/// Atomic operation selectors, carried in the immediate of an atomic store.
pub mod atomic {
  use super::v;
  pub const OP_FETCH: i32 = v::ATOMIC_OP_FETCH;
  pub const OP_XCHG: i32 = v::ATOMIC_OP_XCHG;
  pub const OP_CMPXCHG: i32 = v::ATOMIC_OP_CMPXCHG;
}

/// Named opcode bytes, for call sites that want to test one specific encoding
/// rather than match on a decoded [`Op`].
pub mod opcode {
  use super::{alu, cls, jmp, mode, size, src, v};

  pub const LDDW: u8 = v::OP_LDDW;
  pub const CALL: u8 = v::OP_CALL;
  pub const EXIT: u8 = v::OP_EXIT;
  pub const JA: u8 = v::OP_JA;
  pub const JA32: u8 = v::OP_JA32;
  pub const LE: u8 = cls::ALU | src::IMM | alu::END;
  pub const BE: u8 = cls::ALU | src::REG | alu::END;
  pub const BSWAP: u8 = cls::ALU64 | src::IMM | alu::END;
  pub const ATOMIC32_STORE: u8 = cls::STX | mode::ATOMIC | size::W;
  pub const ATOMIC_STORE: u8 = cls::STX | mode::ATOMIC | size::DW;
  #[allow(dead_code)]
  const _ASSERT: () = assert!(
    LDDW == cls::LD | mode::IMM | size::DW
      && CALL == cls::JMP | jmp::CALL
      && EXIT == cls::JMP | jmp::EXIT
      && JA == cls::JMP | jmp::JA
      && JA32 == cls::JMP32 | jmp::JA
  );
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
    assert_eq!(
      Op::from_opcode(opcode::BSWAP),
      Some(Op::End(EndKind::Bswap))
    );
    // ALU64 | SRC_REG | END is not a defined encoding.
    assert_eq!(Op::from_opcode(cls::ALU64 | src::REG | alu::END), None);
  }

  #[test]
  fn a_sign_extending_doubleword_load_is_not_an_encoding() {
    assert_eq!(Op::from_opcode(cls::LDX | mode::MEMSX | size::DW), None);
    for (bits, width) in [
      (size::B, Width::B),
      (size::H, Width::H),
      (size::W, Width::W),
    ] {
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
    // Regression. The selector is `imm & 0xf0` and the fetch flag is `imm & 1`,
    // so bits 1-3 are dead. Decoding by clearing only the fetch bit gets every
    // canonical selector right and then rejects exactly the non-canonical ones
    // the validator lets through for 32-bit atomics, where its filter bounds
    // the immediate at 0..=255 instead of enumerating.
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

  /// Every opcode byte the eBPF ISA defines, as 119 distinct values. Written
  /// out rather than derived, so a change to the decoder has to be argued
  /// against an independent list instead of against itself.
  ///
  /// Comparing against the set rather than against its cardinality is what
  /// makes a decode bug legible: a count-only check reports "112, expected 119"
  /// and leaves you guessing, where this names the twelve `ldx`/`stx`
  /// encodings that went missing and the five byte values that were accepted
  /// but define nothing.
  const DEFINED_OPCODES: [u8; 119] = [
    0x04, 0x05, 0x06, 0x07, 0x0c, 0x0f, 0x14, 0x15, 0x16, 0x17, 0x18, 0x1c, 0x1d, 0x1e, 0x1f, 0x24,
    0x25, 0x26, 0x27, 0x2c, 0x2d, 0x2e, 0x2f, 0x34, 0x35, 0x36, 0x37, 0x3c, 0x3d, 0x3e, 0x3f, 0x44,
    0x45, 0x46, 0x47, 0x4c, 0x4d, 0x4e, 0x4f, 0x54, 0x55, 0x56, 0x57, 0x5c, 0x5d, 0x5e, 0x5f, 0x61,
    0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x71, 0x72, 0x73,
    0x74, 0x75, 0x76, 0x77, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x81, 0x84, 0x85, 0x87, 0x89,
    0x91, 0x94, 0x95, 0x97, 0x9c, 0x9f, 0xa4, 0xa5, 0xa6, 0xa7, 0xac, 0xad, 0xae, 0xaf, 0xb4, 0xb5,
    0xb6, 0xb7, 0xbc, 0xbd, 0xbe, 0xbf, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xcc, 0xcd, 0xce, 0xcf, 0xd4,
    0xd5, 0xd6, 0xd7, 0xdb, 0xdc, 0xdd, 0xde,
  ];

  #[test]
  fn the_decoder_accepts_exactly_the_defined_opcodes() {
    use std::collections::BTreeSet;
    let named: BTreeSet<u8> = DEFINED_OPCODES.into_iter().collect();
    assert_eq!(named.len(), 119, "the reference set has a duplicate");
    let decoded: BTreeSet<u8> = (0u8..=255)
      .filter(|&b| Op::from_opcode(b).is_some())
      .collect();

    let missing: Vec<String> = named
      .difference(&decoded)
      .map(|b| format!("{b:#04x}"))
      .collect();
    let extra: Vec<String> = decoded
      .difference(&named)
      .map(|b| format!("{b:#04x}"))
      .collect();
    assert!(
      missing.is_empty() && extra.is_empty(),
      "decoder disagrees with the ISA\n  defined but rejected: {missing:?}\n  accepted but undefined: {extra:?}"
    );
  }

  #[test]
  fn the_mode_field_is_three_bits_wide() {
    // Regression: masking the mode with 0xc0 instead of 0xe0 still recognises
    // MEMSX and ATOMIC, because their values happen to fit, but silently
    // rejects every plain ldx/stx and accepts five byte values that define
    // nothing. The census above catches it; this pins the cause.
    assert_eq!(mode::MEM & mode::MASK, mode::MEM);
    assert_eq!(0x61 & mode::MASK, mode::MEM, "ldxw must decode as MEM");
    assert_eq!(0xa1 & mode::MASK, 0xa0, "0xa1 is not a defined mode");
    assert_eq!(Op::from_opcode(0xa1), None);
    assert_eq!(Op::from_opcode(0xe3), None);
  }
}

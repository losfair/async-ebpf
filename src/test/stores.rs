//! Storing an immediate through a bounds-checked pointer.
//!
//! An `ST` instruction has no source register, so a backend that has no
//! store-immediate form has to materialize the value somewhere first. Doing that
//! before the address is computed puts the value and the translated address in
//! the same place at the same time, and what reaches memory is then the address:
//! a native pointer, written into guest memory, where the guest can read it
//! straight back. These pin the value down on both backends.

use crate::test::raw_elf::{run_raw, Insn};

const RODATA: [u8; 8] = 0x1122334455667788u64.to_le_bytes();

/// `*(u64 *)(dst + offset) = imm`
fn st_dw(dst: u8, offset: i16, imm: i32) -> Insn {
  Insn::raw(0x7a, dst, 0, offset, imm)
}

/// Through a derived pointer, so the store takes the full checked path - which
/// is where the value and the address computation can collide.
#[tokio::test]
async fn a_store_immediate_through_a_checked_pointer_stores_the_immediate() {
  let code = vec![
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, -64),
    st_dw(1, 0, 0x5a5a),
    Insn::ldx_dw(0, 1, 0),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x5a5a);
}

/// The same value must come back whether it is written as an immediate or
/// through a register. Comparing the two catches a backend that stores
/// something plausible - an address is a perfectly ordinary-looking u64 - rather
/// than something obviously wrong.
#[tokio::test]
async fn a_store_immediate_agrees_with_a_store_register() {
  let via_imm = vec![
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, -64),
    st_dw(1, 0, 0x1234),
    Insn::ldx_dw(0, 1, 0),
    Insn::exit(),
  ];
  let via_reg = vec![
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, -64),
    Insn::mov64_imm(2, 0x1234),
    Insn::stx_dw(1, 2, 0),
    Insn::ldx_dw(0, 1, 0),
    Insn::exit(),
  ];
  let a = run_raw(&via_imm, &RODATA, &[], true).await.unwrap();
  let b = run_raw(&via_reg, &RODATA, &[], true).await.unwrap();
  assert_eq!(a, 0x1234);
  assert_eq!(a, b);
}

/// Every width, since the value register is shared across all of them.
#[tokio::test]
async fn store_immediate_round_trips_at_every_width() {
  for (op, load, expected) in [
    (0x7au8, Insn::ldx_dw(0, 1, 0), 0x0123_4567i64),
    (0x62, Insn::raw(0x61, 0, 1, 0, 0), 0x0123_4567),
    (0x6a, Insn::raw(0x69, 0, 1, 0, 0), 0x4567),
    (0x72, Insn::raw(0x71, 0, 1, 0, 0), 0x67),
  ] {
    let code = vec![
      Insn::mov64_reg(1, 10),
      Insn::add64_imm(1, -64),
      st_dw(10, -64, 0), // clear the slot first
      Insn::raw(op, 1, 0, 0, 0x0123_4567),
      load,
      Insn::exit(),
    ];
    assert_eq!(
      run_raw(&code, &RODATA, &[], true).await.unwrap(),
      expected,
      "width of opcode {op:#04x}"
    );
  }
}

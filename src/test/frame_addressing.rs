//! Frame-relative addressing, where the JIT drops the per-access bounds check.
//!
//! The x86-64 backend carries a *native* frame pointer in the register mapped to
//! eBPF `R10`, so a displacement off it that provably stays inside the guest
//! stack is emitted as one native instruction with no check at all. Two things
//! have to keep working alongside that: an access the window argument does not
//! cover must still take the checked path, and a program that reads `R10` as a
//! value must still see a guest address.

use crate::test::raw_elf::{run_raw, Insn};

const RODATA: [u8; 8] = 0x1122334455667788u64.to_le_bytes();

const EBPF_OP_JA: u8 = 0x05;
const EBPF_OP_STDW: u8 = 0x7a;
const EBPF_OP_LDXW: u8 = 0x61;

/// `goto +offset`, in instruction slots.
fn ja(offset: i16) -> Insn {
  Insn::raw(EBPF_OP_JA, 0, 0, offset, 0)
}

/// `*(u64 *)(dst + offset) = imm`
fn st_dw(dst: u8, offset: i16, imm: i32) -> Insn {
  Insn::raw(EBPF_OP_STDW, dst, 0, offset, imm)
}

/// A displacement the window argument covers is emitted unchecked; the rest of
/// the frame still has to work.
#[tokio::test]
async fn frame_slots_round_trip() {
  let code = vec![
    st_dw(10, -8, 0x11),
    st_dw(10, -16, 0x22),
    Insn::ldx_dw(1, 10, -8),
    Insn::ldx_dw(2, 10, -16),
    Insn::mov64_reg(0, 1),
    Insn::or64_reg(0, 2),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x33);
}

/// An access that reaches above `R10` is outside the window the backend can
/// prove, so it falls back to the checked path - which works in *guest* space
/// and therefore has to undo the native frame base first.
///
/// `[r10 - 4]` read as a doubleword spans `[r10 - 4, r10 + 4)`, so it fails the
/// `offset + width <= 0` test even though the bytes themselves are mapped. They
/// are only mapped because calldata is passed: with none, `R10` starts at the
/// very top of the guest stack and the checked path is right to reject this.
#[tokio::test]
async fn an_access_the_window_does_not_cover_still_works() {
  let calldata = [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0];
  let code = vec![
    st_dw(10, -8, 0x7788),
    // The upper half of the slot written above, plus the first four bytes of
    // the calldata sitting immediately above R10.
    Insn::ldx_dw(0, 10, -4),
    Insn::exit(),
  ];
  let got = run_raw(&code, &RODATA, &calldata, true).await.unwrap() as u64;
  assert_eq!(got, 0xefbe_adde_0000_0000);
}

/// A narrower access at the same displacement *is* inside the window, and reads
/// back what the wide store put there.
#[tokio::test]
async fn a_narrow_access_at_the_same_displacement_is_covered() {
  let code = vec![
    st_dw(10, -8, 0x7788),
    Insn::raw(EBPF_OP_LDXW, 0, 10, -8, 0),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x7788);
}

/// Reading `R10` as a value must yield a guest address, or dereferencing what
/// the program computed from it would fail the bounds check - or worse, succeed
/// against a host address.
#[tokio::test]
async fn the_frame_pointer_read_as_a_value_is_a_guest_address() {
  let code = vec![
    Insn::mov64_reg(2, 10), // r2 = r10   (a value use, not a memory base)
    Insn::add64_imm(2, -24),
    st_dw(2, 0, 0x5a), // *(u64 *)(r10 - 24) = 0x5a, via the derived pointer
    Insn::ldx_dw(0, 10, -24),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x5a);
}

/// The same, but reached by a branch.
///
/// The materialization that recovers the guest frame pointer is emitted inline,
/// so it has to sit *after* the instruction's recorded location - otherwise a
/// branch to this instruction would jump straight past it and use whatever the
/// scratch register happened to hold. That is not a hypothetical: it is what
/// broke every branch-heavy program until the emission moved.
#[tokio::test]
async fn the_frame_pointer_read_as_a_value_at_a_branch_target_is_a_guest_address() {
  let code = vec![
    Insn::mov64_imm(3, 1),
    ja(1),                  // skip the poison below
    Insn::mov64_imm(2, -1), // never executed; would make r2 obviously wrong
    // branch target: the value use of r10 lands here
    Insn::mov64_reg(2, 10),
    Insn::add64_imm(2, -32),
    st_dw(2, 0, 0x6b),
    Insn::ldx_dw(0, 10, -32),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x6b);
}

/// Storing `R10` itself stores a pointer, and it must be the guest one - through
/// both the unchecked frame path and the checked one.
#[tokio::test]
async fn storing_the_frame_pointer_stores_a_guest_address() {
  // Base is R10, so the store takes the unchecked frame path.
  let via_frame = vec![
    Insn::stx_dw(10, 10, -16), // *(u64 *)(r10 - 16) = r10
    Insn::ldx_dw(2, 10, -16),
    Insn::add64_imm(2, -40),
    st_dw(2, 0, 0x9c),
    Insn::ldx_dw(0, 10, -40),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&via_frame, &RODATA, &[], true).await.unwrap(), 0x9c);

  // Base is a derived register, so the store takes the checked path - whose
  // address computation clobbers the scratch the frame pointer would sit in.
  let via_derived = vec![
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, -16),
    Insn::stx_dw(1, 10, 0), // *(u64 *)(r10 - 16) = r10, through r1
    Insn::ldx_dw(2, 10, -16),
    Insn::add64_imm(2, -40),
    st_dw(2, 0, 0x9c),
    Insn::ldx_dw(0, 10, -40),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&via_derived, &RODATA, &[], true).await.unwrap(), 0x9c);
}

/// Frame addressing has to survive a local call, which moves `R10` down by one
/// charged frame and back up on return. Translation is an affine shift, so it
/// commutes with that arithmetic - this is what says so out loud.
#[tokio::test]
async fn a_callee_frame_is_addressed_independently_of_its_caller() {
  let code = vec![
    st_dw(10, -8, 0xaa),
    Insn::call_local(2), // -> the callee below
    Insn::ldx_dw(0, 10, -8),
    Insn::exit(),
    // callee: writes its own frame at the same displacement, which must be a
    // different address from the caller's.
    st_dw(10, -8, 0xbb),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0xaa);
}

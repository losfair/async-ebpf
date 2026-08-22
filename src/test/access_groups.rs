//! Access grouping: one bounds check covering a run of accesses off one base.
//!
//! The leader checks the whole window and parks the translated base in the
//! frame; members address it at a constant displacement. Getting the window or
//! the displacements wrong would read or write the wrong place, so these tests
//! pin down the arithmetic, the conditions that have to close a group, and what
//! happens when the check fails.

use crate::{
  error::{Error, RuntimeError},
  test::raw_elf::{run_raw, Insn},
};

const RODATA: [u8; 8] = 0x1122334455667788u64.to_le_bytes();

const EBPF_OP_STDW: u8 = 0x7a;
const EBPF_OP_JEQ_IMM: u8 = 0x15;
const EBPF_OP_ADD64_REG: u8 = 0x0f;

/// `*(u64 *)(dst + offset) = imm`
fn st_dw(dst: u8, offset: i16, imm: i32) -> Insn {
  Insn::raw(EBPF_OP_STDW, dst, 0, offset, imm)
}

/// `if dst == imm goto +offset`
fn jeq_imm(dst: u8, imm: i32, offset: i16) -> Insn {
  Insn::raw(EBPF_OP_JEQ_IMM, dst, 0, offset, imm)
}

/// `dst += src`
fn add64_reg(dst: u8, src: u8) -> Insn {
  Insn::raw(EBPF_OP_ADD64_REG, dst, src, 0, 0)
}

/// `r1` pointing 256 bytes into the current frame - a valid non-frame base, so
/// accesses off it are grouped rather than taking the unchecked frame path.
fn base_in_frame() -> Vec<Insn> {
  vec![Insn::mov64_reg(1, 10), Insn::add64_imm(1, -256)]
}

/// The displacements have to survive the round trip: what a member writes at
/// `[base + d]` is what a member reads back from `[base + d]`.
///
/// Stores and loads share one base here, so they land in a single group - which
/// is the case worth pinning down, because a store is confined to the stack
/// whatever its hint says and the loads inherit that window.
#[tokio::test]
async fn a_mixed_group_round_trips_every_displacement() {
  let mut code = base_in_frame();
  code.extend([
    st_dw(1, 0, 0x1),
    st_dw(1, 8, 0x2),
    st_dw(1, 16, 0x4),
    st_dw(1, 24, 0x8),
    Insn::ldx_dw(0, 1, 0),
    Insn::ldx_dw(2, 1, 8),
    Insn::or64_reg(0, 2),
    Insn::ldx_dw(2, 1, 16),
    Insn::or64_reg(0, 2),
    Insn::ldx_dw(2, 1, 24),
    Insn::or64_reg(0, 2),
    Insn::exit(),
  ]);
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0xf);
}

/// Negative displacements, and a window that does not start at the leader.
///
/// The leader is the first access, but the window's low bound is the *smallest*
/// displacement in the group - so the leader itself sits at a non-zero offset
/// from the base it parks.
#[tokio::test]
async fn a_window_can_start_below_its_leader() {
  let mut code = base_in_frame();
  code.extend([
    st_dw(1, 0, 0x1),   // leader, but not the low bound
    st_dw(1, -16, 0x2), // the low bound
    st_dw(1, -8, 0x4),
    Insn::ldx_dw(0, 1, -16),
    Insn::ldx_dw(2, 1, -8),
    Insn::or64_reg(0, 2),
    Insn::ldx_dw(2, 1, 0),
    Insn::or64_reg(0, 2),
    Insn::exit(),
  ]);
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x7);
}

/// Redefining the base has to close the group: the displacements a member uses
/// are relative to the base the *leader* parked, so an access after the base
/// moves is addressing a different object.
#[tokio::test]
async fn redefining_the_base_closes_the_group() {
  let mut code = base_in_frame();
  code.extend([
    st_dw(1, 0, 0x1), // -> frame - 256
    Insn::add64_imm(1, -64),
    st_dw(1, 0, 0x2), // -> frame - 320, not frame - 256
    // Read both back through the frame, which does not depend on r1 at all.
    Insn::ldx_dw(0, 10, -256),
    Insn::ldx_dw(2, 10, -320),
    Insn::or64_reg(0, 2),
    Insn::exit(),
  ]);
  // 0x3 only if the second store moved with the base. A group that wrongly
  // spanned the redefinition would put both values at frame - 256 and yield 2.
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x3);
}

/// An access whose destination is its own base is still valid - the read
/// happens first - but nothing addressing that base after it is.
///
/// Run without strict region analysis, because a pointer read out of guest
/// memory deliberately carries no provenance and so cannot be routed to a
/// single region. That is the whole reason this shape is worth a test: the
/// group is the only thing holding the two accesses together.
#[tokio::test]
async fn a_load_into_its_own_base_closes_the_group() {
  let mut code = base_in_frame();
  code.extend([
    // Park a second frame pointer in the slot r1 is about to load from.
    Insn::mov64_reg(2, 10),
    Insn::add64_imm(2, -512),
    Insn::stx_dw(1, 2, 0), // *(u64 *)(r1) = frame - 512
    st_dw(2, 8, 0x9),      // *(u64 *)(frame - 504) = 9
    Insn::ldx_dw(1, 1, 0), // r1 = frame - 512, from its own base
    Insn::ldx_dw(0, 1, 8), // must read frame - 504, not frame - 248
    Insn::exit(),
  ]);
  assert_eq!(run_raw(&code, &RODATA, &[], false).await.unwrap(), 0x9);
}

/// A branch target closes a group, because the path that jumps in never ran the
/// leader and the parked base would be whatever the last group left behind.
#[tokio::test]
async fn a_branch_target_closes_the_group() {
  let mut code = base_in_frame();
  code.extend([
    st_dw(1, 0, 0x1),
    st_dw(1, 8, 0x2),
    Insn::mov64_imm(3, 0),
    jeq_imm(3, 0, 1), // always taken, over the store below
    st_dw(1, 16, 0xff),
    // branch target
    Insn::ldx_dw(0, 1, 0),
    Insn::ldx_dw(2, 1, 8),
    Insn::or64_reg(0, 2),
    Insn::exit(),
  ]);
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x3);
}

/// A local call closes a group: the callee runs in the same host frame and
/// would overwrite the parked base.
#[tokio::test]
async fn a_local_call_closes_the_group() {
  // The base lives in r6: a call clobbers r0-r5, so a base there would not
  // survive to be regrouped afterwards whatever the grouping did.
  let code = vec![
    Insn::mov64_reg(6, 10),
    Insn::add64_imm(6, -256),
    st_dw(6, 0, 0x1),
    st_dw(6, 8, 0x2),
    Insn::call_local(4), // the callee below, which runs a group of its own
    Insn::ldx_dw(0, 6, 0),
    Insn::ldx_dw(2, 6, 8),
    Insn::or64_reg(0, 2),
    Insn::exit(),
    // callee: its own base, its own group, in its own frame
    Insn::mov64_reg(6, 10),
    Insn::add64_imm(6, -256),
    st_dw(6, 0, 0x40),
    st_dw(6, 8, 0x80),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x3);
}

/// A group off a base that is not a valid guest address must fault, not read
/// whatever the failed check left behind.
///
/// The leader's check fails and parks address 0, so every member dereferences
/// its displacement from 0 - inside the guard window, where the fault handler
/// recognises it as a guest fault rather than a host crash.
#[tokio::test]
async fn a_group_off_a_bad_base_faults() {
  let code = vec![
    Insn::mov64_imm(1, 0x1000), // not inside either guest region
    st_dw(1, 0, 0x1),
    st_dw(1, 8, 0x2),
    st_dw(1, 16, 0x4),
    Insn::exit(),
  ];
  match run_raw(&code, &RODATA, &[], false).await {
    Err(Error(RuntimeError::MemoryFault(_))) => {}
    other => panic!("expected a memory fault, got {other:?}"),
  }
}

/// The same, with the window as wide as one is allowed to be. The furthest
/// member still has to land inside the guard window - that bound is the whole
/// reason the span is capped at a page.
#[tokio::test]
async fn the_widest_group_off_a_bad_base_still_faults() {
  let code = vec![
    Insn::mov64_imm(1, 0x1000),
    st_dw(1, 0, 0x1),
    st_dw(1, 2048, 0x2),
    st_dw(1, 4088, 0x4), // ends exactly at the 4096-byte cap
    Insn::exit(),
  ];
  match run_raw(&code, &RODATA, &[], false).await {
    Err(Error(RuntimeError::MemoryFault(_))) => {}
    other => panic!("expected a memory fault, got {other:?}"),
  }
}

/// A run too wide to cover with one window is not one group, and still works.
#[tokio::test]
async fn a_run_wider_than_the_cap_still_works() {
  let mut code = base_in_frame();
  // 8192 bytes apart, so no single window can hold both. r1 is 256 bytes into
  // the frame, so reach downward - the frame is the only region a store may
  // touch.
  code.extend([
    Insn::add64_imm(1, -4096),
    st_dw(1, 0, 0x1),
    st_dw(1, 4088, 0x2),
    Insn::ldx_dw(0, 1, 0),
    Insn::ldx_dw(2, 1, 4088),
    Insn::or64_reg(0, 2),
    Insn::exit(),
  ]);
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x3);
}

/// Grouping must not change what a program computes when the base is only known
/// at run time. Both branches write through the same register, so the group in
/// each arm has to use the base that arm established.
#[tokio::test]
async fn each_arm_of_a_branch_groups_on_its_own_base() {
  for (selector, expected) in [(0i32, 0x11u64), (1, 0x22)] {
    let code = vec![
      Insn::mov64_reg(1, 10),
      Insn::add64_imm(1, -256),
      Insn::mov64_reg(2, 10),
      Insn::add64_imm(2, -512),
      Insn::mov64_imm(3, selector),
      jeq_imm(3, 0, 3),
      // r3 != 0: write through r2
      st_dw(2, 0, 0x22),
      Insn::mov64_reg(4, 2),
      jeq_imm(3, selector, 2),
      // r3 == 0: write through r1
      st_dw(1, 0, 0x11),
      Insn::mov64_reg(4, 1),
      // join
      Insn::ldx_dw(0, 4, 0),
      Insn::exit(),
    ];
    assert_eq!(
      run_raw(&code, &RODATA, &[], true).await.unwrap() as u64,
      expected,
      "selector {selector}"
    );
  }
}

/// Grouping is per base register, and two live bases must not be confused.
#[tokio::test]
async fn interleaved_bases_do_not_share_a_window() {
  let code = vec![
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, -256),
    Insn::mov64_reg(2, 10),
    Insn::add64_imm(2, -512),
    st_dw(1, 0, 0x1),
    st_dw(2, 0, 0x2),
    st_dw(1, 8, 0x4),
    st_dw(2, 8, 0x8),
    Insn::ldx_dw(0, 10, -256),  // 0x1
    Insn::ldx_dw(3, 10, -248),  // 0x4
    add64_reg(0, 3),
    Insn::ldx_dw(3, 10, -512),  // 0x2
    add64_reg(0, 3),
    Insn::ldx_dw(3, 10, -504),  // 0x8
    add64_reg(0, 3),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0xf);
}

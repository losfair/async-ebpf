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
    Insn::ldx_dw(0, 10, -256), // 0x1
    Insn::ldx_dw(3, 10, -248), // 0x4
    add64_reg(0, 3),
    Insn::ldx_dw(3, 10, -512), // 0x2
    add64_reg(0, 3),
    Insn::ldx_dw(3, 10, -504), // 0x8
    add64_reg(0, 3),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0xf);
}

// ---------------------------------------------------------------------------
// Added during the static-analysis audit of the access plan. These pin down the
// cases where the Rust plan and the backend's own group bookkeeping have to
// agree about what does and does not disturb the parked base.
// ---------------------------------------------------------------------------

/// `*(u8 *)(dst + offset) = imm`
fn st_b(dst: u8, offset: i16, imm: i32) -> Insn {
  Insn::raw(0x72, dst, 0, offset, imm)
}

/// `*(u16 *)(dst + offset) = imm`
fn st_h(dst: u8, offset: i16, imm: i32) -> Insn {
  Insn::raw(0x6a, dst, 0, offset, imm)
}

/// `*(u32 *)(dst + offset) = imm`
fn st_w(dst: u8, offset: i16, imm: i32) -> Insn {
  Insn::raw(0x62, dst, 0, offset, imm)
}

/// `dst = *(u16 *)(src + offset)`
fn ldx_h(dst: u8, src: u8, offset: i16) -> Insn {
  Insn::raw(0x69, dst, src, offset, 0)
}

/// `dst = *(u32 *)(src + offset)`
fn ldx_w(dst: u8, src: u8, offset: i16) -> Insn {
  Insn::raw(0x61, dst, src, offset, 0)
}

/// A window built from accesses of different widths. The high bound comes from
/// whichever member reaches furthest, which is not the one with the largest
/// displacement, so the widths have to be part of the arithmetic.
#[tokio::test]
async fn a_group_of_mixed_widths_round_trips() {
  let mut code = base_in_frame();
  code.extend([
    st_b(1, 7, 0x11),  // leader: one byte at +7
    st_dw(1, 8, 0x22), // reaches +16, the high bound
    st_h(1, 0, 0x33),  // the low bound
    st_w(1, 20, 0x44), // reaches +24
    ldx_h(0, 1, 0),    // 0x33
    Insn::ldx_b(2, 1, 7),
    Insn::or64_reg(0, 2), // | 0x11
    Insn::ldx_dw(2, 1, 8),
    Insn::or64_reg(0, 2), // | 0x22
    ldx_w(2, 1, 20),
    Insn::or64_reg(0, 2), // | 0x44
    Insn::exit(),
  ]);
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x77);
}

/// A frame access between two members must not disturb the base the leader
/// parked: it needs no bounds check and no scratch register of its own.
#[tokio::test]
async fn a_frame_access_between_members_does_not_disturb_the_group() {
  let mut code = base_in_frame();
  code.extend([
    st_dw(1, 0, 0x1),
    st_dw(1, 8, 0x2),
    // A frame store and a frame load right in the middle of the run.
    st_dw(10, -8, 0x40),
    Insn::ldx_dw(3, 10, -8),
    st_dw(1, 16, 0x4),
    Insn::ldx_dw(0, 1, 0),
    Insn::ldx_dw(2, 1, 8),
    Insn::or64_reg(0, 2),
    Insn::ldx_dw(2, 1, 16),
    Insn::or64_reg(0, 2),
    Insn::or64_reg(0, 3),
    Insn::exit(),
  ]);
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x47);
}

/// An atomic in the middle of a run is routed through the full check and does
/// not join the group - but it must not invalidate it either. Its own scratch
/// use has to leave the parked base alone.
#[tokio::test]
async fn an_atomic_between_members_does_not_disturb_the_group() {
  const ATOMIC_DW: u8 = 0xdb;
  const ADD_FETCH: i32 = 0x01;
  let mut code = base_in_frame();
  code.extend([
    st_dw(1, 0, 0x1),
    st_dw(1, 8, 0x2),
    // atomic_fetch_add through a *different* frame slot; r3 takes the old value.
    Insn::mov64_reg(4, 10),
    Insn::add64_imm(4, -2048),
    st_dw(4, 0, 0x40),
    Insn::mov64_imm(3, 0),
    Insn::raw(ATOMIC_DW, 4, 3, 0, ADD_FETCH), // r3 = old(*(u64*)(r4)) = 0x40
    st_dw(1, 16, 0x4),
    Insn::ldx_dw(0, 1, 0),
    Insn::ldx_dw(2, 1, 8),
    Insn::or64_reg(0, 2),
    Insn::ldx_dw(2, 1, 16),
    Insn::or64_reg(0, 2),
    Insn::or64_reg(0, 3),
    Insn::exit(),
  ]);
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x47);
}

/// An `lddw` between two accesses currently dissolves the group, because its
/// second slot is never reached by the dataflow. Whether or not that stays
/// true, the values must not move.
#[tokio::test]
async fn accesses_split_by_a_lddw_still_round_trip() {
  let mut code = base_in_frame();
  code.extend([st_dw(1, 0, 0x1), st_dw(1, 8, 0x2)]);
  code.extend(Insn::lddw_data(5, 0));
  code.extend([
    st_dw(1, 16, 0x4),
    Insn::ldx_dw(0, 1, 0),
    Insn::ldx_dw(2, 1, 8),
    Insn::or64_reg(0, 2),
    Insn::ldx_dw(2, 1, 16),
    Insn::or64_reg(0, 2),
    Insn::ldx_b(2, 5, 0), // the loaded data pointer is real
    Insn::or64_reg(0, 2),
    Insn::exit(),
  ]);
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x8f);
}

/// A group whose loads are data accesses but which also contains a store is
/// checked against the *stack*, because a store is confined there whatever its
/// hint says. That is only sound if the program was already doomed - the store
/// through a data pointer faults today too. Either way it must be a clean guest
/// memory fault, not a host crash.
#[tokio::test]
async fn a_store_through_a_data_pointer_in_a_group_still_faults_cleanly() {
  let mut code = Vec::new();
  code.extend(Insn::lddw_data(1, 0));
  code.extend([
    Insn::ldx_b(0, 1, 0), // fine on its own
    Insn::ldx_b(2, 1, 1),
    st_b(1, 2, 0xff), // pins the whole window to the stack
    Insn::exit(),
  ]);
  match run_raw(&code, &RODATA, &[], false).await {
    Err(Error(RuntimeError::MemoryFault(_))) => {}
    other => panic!("expected a memory fault, got {other:?}"),
  }
}

/// Read-only data loads that share a base and have no store among them keep
/// their data window, and every displacement still lands where it should.
#[tokio::test]
async fn a_data_only_group_round_trips() {
  let mut code = Vec::new();
  code.extend(Insn::lddw_data(1, 0));
  code.extend([
    Insn::ldx_b(0, 1, 7), // 0x11
    Insn::ldx_b(2, 1, 0), // 0x88
    Insn::or64_reg(0, 2),
    Insn::ldx_b(2, 1, 3), // 0x55
    Insn::or64_reg(0, 2),
    Insn::exit(),
  ]);
  // RODATA is 0x1122334455667788 little-endian: byte 0 = 0x88, 3 = 0x55, 7 = 0x11.
  assert_eq!(
    run_raw(&code, &RODATA, &[], true).await.unwrap() as u64,
    0x11 | 0x88 | 0x55
  );
}

/// A group that starts with a store and continues with loads: the leader is the
/// store, so the window's region is decided before any load has contributed one.
#[tokio::test]
async fn a_group_led_by_a_store_still_serves_its_loads() {
  let mut code = base_in_frame();
  code.extend([
    st_dw(1, 24, 0x8), // leader, and the window's high bound
    st_dw(1, 0, 0x1),  // the low bound
    Insn::ldx_dw(0, 1, 24),
    Insn::ldx_dw(2, 1, 0),
    Insn::or64_reg(0, 2),
    Insn::exit(),
  ]);
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x9);
}

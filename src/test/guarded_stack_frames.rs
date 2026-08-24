//! Runtime coverage for sparse, page-guarded eBPF stack frames.

use std::{any::Any, sync::Arc};

use crate::{
  error::{Error, RuntimeError},
  program::{
    DummyProgramEventListener, HelperScope, PreemptionEnabled, Program, ProgramLoader,
    MAX_CALLDATA_SIZE,
  },
  test::raw_elf::{build_elf, Insn},
  test_util::{gt_env, timeslice_config, TokioTimeslicer},
};

const FRAME_SIZE: i16 = 4096;

fn default_frame_is_page_aligned() -> bool {
  unsafe { libc::sysconf(libc::_SC_PAGESIZE) == FRAME_SIZE as libc::c_long }
}

fn st_dw(dst: u8, offset: i16, imm: i32) -> Insn {
  Insn::raw(0x7a, dst, 0, offset, imm)
}

fn load_guarded(code: &[Insn]) -> Result<Program, Error> {
  let (_, thread) = gt_env();
  ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_guarded_stack_frames(true)
  .load(&mut rand::thread_rng(), &build_elf(code, &[]))
  .map(|program| program.pin_to_current_thread(thread))
}

fn reject_gap(scope: &HelperScope, ptr: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
  Ok(u64::from(scope.user_memory(ptr, 1).is_err()))
}

static GAP_HELPERS: &[(&str, crate::helpers::Helper)] = &[("h", reject_gap)];

async fn run(program: &Program, calldata: &[u8]) -> Result<i64, Error> {
  let (_, thread) = gt_env();
  let mut resources: [&mut dyn Any; 0] = [];
  program
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut resources,
      calldata,
      &PreemptionEnabled::new(thread),
    )
    .await
}

#[tokio::test]
async fn frame_low_boundary_is_mapped_and_the_byte_below_faults() {
  if !default_frame_is_page_aligned() {
    return;
  }
  let valid = load_guarded(&[Insn::raw(0x71, 0, 10, -FRAME_SIZE, 0), Insn::exit()]).unwrap();
  assert!(run(&valid, &[]).await.is_ok());

  let invalid = load_guarded(&[Insn::raw(0x71, 0, 10, -FRAME_SIZE - 1, 0), Insn::exit()]).unwrap();
  assert!(matches!(
    run(&invalid, &[]).await,
    Err(Error(RuntimeError::MemoryFault(_)))
  ));
}

#[tokio::test]
async fn callee_positive_r10_displacements_fault_in_the_gap() {
  if !default_frame_is_page_aligned() {
    return;
  }
  for offset in [1, i16::MAX] {
    let program = load_guarded(&[
      Insn::call_local(1),
      Insn::exit(),
      Insn::raw(0x71, 0, 10, offset, 0),
      Insn::exit(),
    ])
    .unwrap();
    assert!(matches!(
      run(&program, &[]).await,
      Err(Error(RuntimeError::MemoryFault(_)))
    ));
  }
}

#[tokio::test]
async fn a_wide_access_crossing_a_frame_edge_faults() {
  if !default_frame_is_page_aligned() {
    return;
  }
  let program = load_guarded(&[
    // The low four bytes are in the gap and the high four are in the root
    // frame. The native load must fault instead of partially succeeding.
    Insn::ldx_dw(0, 10, -FRAME_SIZE - 4),
    Insn::exit(),
  ])
  .unwrap();
  assert!(matches!(
    run(&program, &[]).await,
    Err(Error(RuntimeError::MemoryFault(_)))
  ));
}

#[tokio::test]
async fn an_atomic_access_in_the_caller_gap_faults() {
  if !default_frame_is_page_aligned() {
    return;
  }
  let program = load_guarded(&[
    Insn::call_local(1),
    Insn::exit(),
    Insn::mov64_imm(1, 1),
    // atomic64 add *(r10 + 1), r1
    Insn::raw(0xdb, 10, 1, 1, 0),
    Insn::exit(),
  ])
  .unwrap();
  assert!(matches!(
    run(&program, &[]).await,
    Err(Error(RuntimeError::MemoryFault(_)))
  ));
}

#[tokio::test]
async fn explicitly_passed_caller_frame_pointer_remains_valid() {
  if !default_frame_is_page_aligned() {
    return;
  }
  let program = load_guarded(&[
    st_dw(10, -8, 0x11),
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, -8),
    Insn::call_local(2),
    Insn::ldx_dw(0, 10, -8),
    Insn::exit(),
    st_dw(1, 0, 0x5a),
    Insn::exit(),
  ])
  .unwrap();
  assert_eq!(run(&program, &[]).await.unwrap(), 0x5a);
}

#[tokio::test]
async fn helpers_reject_gap_addresses_without_dereferencing_them() {
  if !default_frame_is_page_aligned() {
    return;
  }
  let (_, thread) = gt_env();
  let code = [
    Insn::call_local(1),
    Insn::exit(),
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, 1),
    Insn::call_helper(),
    Insn::exit(),
  ];
  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[GAP_HELPERS],
  )
  .with_guarded_stack_frames(true)
  .load(&mut rand::thread_rng(), &build_elf(&code, &[]))
  .unwrap()
  .pin_to_current_thread(thread);
  assert_eq!(run(&program, &[]).await.unwrap(), 1);
}

#[tokio::test]
async fn guarded_default_preserves_eight_frame_capacity_with_calldata() {
  if !default_frame_is_page_aligned() {
    return;
  }
  let mut code = Vec::new();
  for _ in 0..7 {
    code.push(Insn::call_local(1));
    code.push(Insn::exit());
  }
  code.push(Insn::raw(0x71, 0, 10, -FRAME_SIZE, 0));
  code.push(Insn::exit());

  let program = load_guarded(&code).unwrap();
  assert!(run(&program, &[0xa5; MAX_CALLDATA_SIZE]).await.is_ok());
}

#[test]
fn guarded_frames_reject_a_subpage_frame_size_at_load_time() {
  let code = build_elf(&[Insn::exit()], &[]);
  let err = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_stack_frame_size(512)
  .with_guarded_stack_frames(true)
  .load(&mut rand::thread_rng(), &code)
  .err()
  .expect("a subpage guarded frame unexpectedly loaded");
  assert!(matches!(
    err,
    Error(RuntimeError::InvalidArgumentOwned(message))
      if message.contains("multiple of the host page size")
  ));
}

#[tokio::test]
async fn subpage_frames_still_work_when_guarded_mode_is_disabled() {
  let (_, thread) = gt_env();
  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_stack_frame_size(512)
  .with_guarded_stack_frames(false)
  .load(
    &mut rand::thread_rng(),
    &build_elf(&[Insn::call_local(1), Insn::exit(), Insn::exit()], &[]),
  )
  .unwrap()
  .pin_to_current_thread(thread);
  assert!(run(&program, &[]).await.is_ok());
}

#[tokio::test]
async fn default_mode_falls_back_for_a_subpage_frame() {
  let (_, thread) = gt_env();
  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_stack_frame_size(512)
  .load(
    &mut rand::thread_rng(),
    &build_elf(&[Insn::call_local(1), Insn::exit(), Insn::exit()], &[]),
  )
  .unwrap()
  .pin_to_current_thread(thread);
  assert!(run(&program, &[]).await.is_ok());
}

//! Runtime lifecycle of the per-invocation state the JIT keeps in the host
//! frame.
//!
//! The entry trampoline establishes `RBP` once per invocation and fills in the
//! descriptor pointer, the guest→native frame delta and the twelve derived
//! bounds-check constants; the backend additionally uses one slot as the parked
//! base of an open access group. Every local function inherits that frame, and
//! the guest can be suspended between any two instructions - by an
//! asynchronously delivered SIGUSR1, by a helper, or by a lazy local call that
//! runs the Rust compiler. These tests drive those suspensions through code that
//! reads every one of those slots and check that what comes back is still right.
//!
//! The compile-time side of access grouping is covered in `access_groups.rs`;
//! what is exercised here is the *dynamic* side.

use std::{
  any::Any,
  sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
  },
  time::Duration,
};

use crate::{
  program::{
    DummyProgramEventListener, GlobalEnv, HelperScope, PreemptionEnabled, ProgramEventListener,
    ProgramLoader, TimesliceConfig,
  },
  test::raw_elf::{build_elf, Insn},
  test_util::{gt_env, timeslice_config, TokioTimeslicer},
};

const OP_STXDW: u8 = 0x7b;
const OP_ADD64_REG: u8 = 0x0f;
const OP_JNE_IMM: u8 = 0x55;
const OP_JEQ_REG: u8 = 0x1d;
const OP_STDW: u8 = 0x7a;

fn stx_dw(dst: u8, src: u8, offset: i16) -> Insn {
  Insn::raw(OP_STXDW, dst, src, offset, 0)
}

fn st_dw(dst: u8, offset: i16, imm: i32) -> Insn {
  Insn::raw(OP_STDW, dst, 0, offset, imm)
}

fn add64_reg(dst: u8, src: u8) -> Insn {
  Insn::raw(OP_ADD64_REG, dst, src, 0, 0)
}

fn jne_imm(dst: u8, imm: i32, offset: i16) -> Insn {
  Insn::raw(OP_JNE_IMM, dst, 0, offset, imm)
}

fn jeq_reg(dst: u8, src: u8, offset: i16) -> Insn {
  Insn::raw(OP_JEQ_REG, dst, src, offset, 0)
}

/// Two 64-bit words the data-region group below reads back.
const RODATA: [u8; 16] = {
  let mut out = [0u8; 16];
  out[0] = 1;
  out[8] = 2;
  out
};

/// Iterations of the mixed-access loop.
///
/// Chosen so the guest stays in JIT code for well over 100 ms on a fast
/// machine: the point of these tests is that a preemption lands *inside* the
/// loop body, and the loop body is where every frame slot is read. Raise this
/// rather than weakening the assertion if it ever goes flaky.
const ITERS: i32 = 4_000_000;

/// What the loop below accumulates: per iteration, three copies of the counter
/// through the stack group, the two data words, and one more copy of the counter
/// through the unchecked frame access.
fn expected_checksum(iters: i64) -> i64 {
  4 * (iters * (iters - 1) / 2) + iters * 3
}

/// A loop body that touches, every iteration, each of the four kinds of state
/// this change put in the host frame:
///
///  * a **stack access group** - a leader that checks a window and parks the
///    translated base at `[rbp-144]`, and five members that address it;
///  * a **data access group** - the same, checked against the other region, so
///    the data half of the derived constants is read too;
///  * an **unchecked frame access** off `R15`, which is the register the entry
///    trampoline seeded with a native address;
///  * `r10` **read as a value**, which the backend rebuilds from the delta at
///    `[rbp-40]` - compared against the value captured before the loop, so a
///    delta that changed mid-run shows up as a non-zero error flag rather than
///    as a plausible-looking address.
///
/// The counter is stored and read back rather than left in a register, so a
/// member addressing a stale parked base would show up in the checksum.
fn mixed_access_loop(iters: i32) -> Vec<Insn> {
  let mut code = Vec::new();
  code.extend(Insn::lddw_data(8, 0)); // 0, 1
  code.push(Insn::mov64_reg(9, 10)); // 2: guest frame pointer, captured once
  code.push(Insn::mov64_reg(1, 10)); // 3
  code.push(Insn::add64_imm(1, -2048)); // 4: the group base
  code.push(Insn::mov64_imm(6, 0)); // 5: counter
  code.push(Insn::mov64_imm(7, 0)); // 6: checksum
  code.push(Insn::mov64_imm(5, 0)); // 7: error flag
  let loop_pc = code.len() as i16; // 8
  code.extend([
    stx_dw(1, 6, 0),  // 8: stack group leader
    stx_dw(1, 6, 8),  // 9
    stx_dw(1, 6, 16), // 10
    Insn::ldx_dw(2, 1, 0),
    add64_reg(7, 2),
    Insn::ldx_dw(2, 1, 8),
    add64_reg(7, 2),
    Insn::ldx_dw(2, 1, 16),
    add64_reg(7, 2),
    Insn::ldx_dw(2, 8, 0), // data group leader
    add64_reg(7, 2),
    Insn::ldx_dw(2, 8, 8),
    add64_reg(7, 2),
    stx_dw(10, 6, -8), // unchecked frame store
    Insn::ldx_dw(2, 10, -8),
    add64_reg(7, 2),
    Insn::mov64_reg(3, 10), // r10 as a value, again
  ]);
  let jeq_pc = code.len() as i16;
  code.push(jeq_reg(3, 9, 1)); // skip the error bump when unchanged
  code.push(Insn::add64_imm(5, 1));
  code.push(Insn::add64_imm(6, 1));
  let jne_pc = code.len() as i16;
  code.push(jne_imm(6, iters, loop_pc - (jne_pc + 1)));
  let _ = jeq_pc;
  let tail_pc = code.len() as i16;
  code.extend([
    jne_imm(5, 0, 2), // an error flag set anywhere in the loop
    Insn::mov64_reg(0, 7),
    Insn::exit(),
    Insn::mov64_imm(0, -1),
    Insn::exit(),
  ]);
  let _ = tail_pc;
  code
}

#[derive(Default)]
struct PreemptCounter {
  preempts: AtomicUsize,
}

impl ProgramEventListener for PreemptCounter {
  fn did_async_preempt(&self, _: &HelperScope) {
    self.preempts.fetch_add(1, Ordering::SeqCst);
  }
}

/// Runs `code` on a thread of its own with a 1 ms preemption watcher, and
/// reports how many asynchronous preemptions the run observed.
fn run_preempted(code: &[Insn], rodata: &[u8], strict: bool) -> (Result<i64, String>, usize) {
  let elf = build_elf(code, rodata);
  std::thread::spawn(move || {
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    runtime.block_on(async move {
      let global = unsafe { GlobalEnv::new() };
      let thread = global.init_thread(Duration::from_millis(1));
      let events = Arc::new(PreemptCounter::default());
      let program = ProgramLoader::new(&mut rand::thread_rng(), events.clone(), &[])
        .require_static_region_analysis(strict)
        .load(&mut rand::thread_rng(), &elf)
        .unwrap()
        .pin_to_current_thread(thread);
      // Never throttle or yield: the only suspension under test here is the
      // asynchronous one.
      let timeslice = TimesliceConfig {
        max_run_time_before_throttle: Duration::from_secs(60),
        max_run_time_before_yield: Duration::from_secs(60),
        throttle_duration: Duration::from_millis(1),
      };
      let mut resources: [&mut dyn Any; 0] = [];
      let ret = program
        .run(
          &timeslice,
          &TokioTimeslicer,
          "test",
          &mut resources,
          &[],
          &PreemptionEnabled::new(thread),
        )
        .await
        .map_err(|e| format!("{e:?}"));
      (ret, events.preempts.load(Ordering::SeqCst))
    })
  })
  .join()
  .unwrap()
}

/// Every frame slot the backend reads has to survive an asynchronous
/// preemption arriving between any two guest instructions.
///
/// The signal handler runs on the guest's own native stack - there is no
/// `SA_ONSTACK` - and then switches stacks through the coroutine to run host
/// code before switching back. The slots live *above* `RSP` in the entry frame,
/// so nothing in that sequence should reach them; this drives millions of
/// preemptions through a loop that reads all of them to say so.
#[test]
fn the_frame_slots_survive_asynchronous_preemption() {
  let code = mixed_access_loop(ITERS);
  let (ret, preempts) = run_preempted(&code, &RODATA, true);
  assert_eq!(ret, Ok(expected_checksum(ITERS as i64)));
  eprintln!("preemptions observed: {preempts}");
  assert!(
    preempts > 0,
    "the run was never preempted, so it proves nothing"
  );
}

/// The same, with the whole loop inside a lazily compiled local function.
///
/// This puts the loop one frame deeper - so `R15` has been moved down by a
/// frame and moved back up again - and makes the guest suspend mid-call-sequence
/// to run the Rust compiler before the loop even starts.
#[test]
fn the_frame_slots_survive_preemption_inside_a_lazy_callee() {
  let mut code = vec![
    Insn::mov64_imm(0, 0),
    Insn::call_local(1), // the callee starts at pc 3
    Insn::exit(),
  ];
  code.extend(mixed_access_loop(ITERS));
  let (ret, preempts) = run_preempted(&code, &RODATA, true);
  assert_eq!(ret, Ok(expected_checksum(ITERS as i64)));
  eprintln!("preemptions observed: {preempts}");
  assert!(
    preempts > 0,
    "the run was never preempted, so it proves nothing"
  );
}

/// The pooled guest stack is reused across invocations, so what one program
/// leaves in its frame must not be readable by the next.
///
/// The backing store changed in this branch from a heap allocation to a guarded
/// mapping, and only `SHADOW_STACK_SIZE` bytes of it are scrubbed - the mapping
/// itself is page-rounded and so slightly larger. This checks the scrub still
/// covers everything a guest can address, at the top of the window, in the
/// middle, and at the very bottom.
#[tokio::test]
async fn the_pooled_guest_stack_is_scrubbed_between_invocations() {
  const MARKER: i32 = 0x5a5a5a5a;
  // Offsets a guest can reach: the first two through the unchecked frame path,
  // the last through an ordinary checked stack access.
  let writer = vec![
    st_dw(10, -8, MARKER),
    st_dw(10, -4096, MARKER),
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, -32768),
    st_dw(1, 0, MARKER),
    Insn::mov64_imm(0, 0),
    Insn::exit(),
  ];
  let reader = vec![
    Insn::ldx_dw(0, 10, -8),
    Insn::ldx_dw(2, 10, -4096),
    Insn::or64_reg(0, 2),
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, -32768),
    Insn::ldx_dw(2, 1, 0),
    Insn::or64_reg(0, 2),
    Insn::exit(),
  ];

  let (_, t_env) = gt_env();
  let mut resources: [&mut dyn Any; 0] = [];
  for (code, expected) in [
    (writer, 0u64),
    // `BorrowedExecContext::new` fills the window with 0x8e, so a scrubbed slot
    // reads back as that pattern and a leaked one as the marker.
    (reader, 0x8e8e_8e8e_8e8e_8e8eu64),
  ] {
    let program = ProgramLoader::new(
      &mut rand::thread_rng(),
      Arc::new(DummyProgramEventListener),
      &[],
    )
    .load(&mut rand::thread_rng(), &build_elf(&code, &RODATA))
    .unwrap()
    .pin_to_current_thread(t_env);
    let got = program
      .run(
        &timeslice_config(),
        &TokioTimeslicer,
        "test",
        &mut resources,
        &[],
        &PreemptionEnabled::new(t_env),
      )
      .await
      .unwrap() as u64;
    assert_eq!(got, expected);
  }
}

/// The derived bounds-check constants are per *invocation*, not per
/// compilation: two programs on one thread have independently randomized cages,
/// and the second run of the first program has to see its own again.
///
/// Compiled code is cached on the program, so if any of those constants had
/// been baked into the emitted code - or read once and cached anywhere outside
/// the frame - interleaving two programs would surface it as a fault or as a
/// read of the wrong region.
#[tokio::test]
async fn interleaved_programs_each_see_their_own_region_constants() {
  // A data-region group plus a stack-region group, so both halves of the
  // derived block are exercised.
  let code = {
    let mut code = Vec::new();
    code.extend(Insn::lddw_data(8, 0));
    code.extend([
      Insn::ldx_dw(0, 8, 0),
      Insn::ldx_dw(2, 8, 8),
      add64_reg(0, 2),
      Insn::mov64_reg(1, 10),
      Insn::add64_imm(1, -256),
      Insn::mov64_imm(3, 0),
      stx_dw(1, 3, 0),
      stx_dw(1, 3, 8),
      Insn::ldx_dw(2, 1, 0),
      add64_reg(0, 2),
      Insn::ldx_dw(2, 1, 8),
      add64_reg(0, 2),
      Insn::exit(),
    ]);
    code
  };

  let rodata_a: [u8; 16] = {
    let mut out = [0u8; 16];
    out[0] = 3;
    out[8] = 4;
    out
  };
  let rodata_b: [u8; 16] = {
    let mut out = [0u8; 16];
    out[0] = 30;
    out[8] = 40;
    out
  };

  let (_, t_env) = gt_env();
  let load = |rodata: &[u8]| {
    ProgramLoader::new(
      &mut rand::thread_rng(),
      Arc::new(DummyProgramEventListener),
      &[],
    )
    .load(&mut rand::thread_rng(), &build_elf(&code, rodata))
    .unwrap()
    .pin_to_current_thread(t_env)
  };
  let a = load(&rodata_a);
  let b = load(&rodata_b);

  let mut resources: [&mut dyn Any; 0] = [];
  for (program, expected) in [(&a, 7i64), (&b, 70), (&a, 7), (&b, 70)] {
    let got = program
      .run(
        &timeslice_config(),
        &TokioTimeslicer,
        "test",
        &mut resources,
        &[],
        &PreemptionEnabled::new(t_env),
      )
      .await
      .unwrap();
    // The stores write 0 twice, so only the two data words contribute.
    assert_eq!(got, expected);
  }
}

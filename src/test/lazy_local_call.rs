//! Behaviour of the lazy, per-signature local-function JIT.
//!
//! Local calls are not linked at load time. Each call site is compiled into a
//! stub that asks a host resolver for the callee's native address the first
//! time it executes; the resolver suspends the guest, JIT-compiles the callee
//! for the pointer signature the caller was analysed with, and resumes. These
//! tests pin the parts of that design that are observable through the public
//! API: what the callee sees in its registers, when a compilation failure is
//! reported, how many native copies of a function a program can force, and what
//! the run loop does with the time spent compiling.

use std::{
  any::Any,
  sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
  },
  time::Duration,
};

use crate::{
  error::{Error, RuntimeError},
  helpers::Helper,
  program::{
    DummyProgramEventListener, HelperScope, PreemptionEnabled, Program, ProgramEventListener,
    ProgramLoader, TimesliceConfig, DEFAULT_CODE_SIZE_LIMIT,
  },
  test::raw_elf::{build_elf, run_raw, Insn},
  test_util::{compile_ebpf, gt_env, timeslice_config, TokioTimeslicer},
};

fn load_raw(code: &[Insn], rodata: &[u8]) -> Program {
  let (_, t_env) = gt_env();
  ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .load(&mut rand::thread_rng(), &build_elf(code, rodata))
  .unwrap()
  .pin_to_current_thread(t_env)
}

async fn run(program: &Program, calldata: &[u8]) -> Result<i64, Error> {
  let (_, t_env) = gt_env();
  let mut resources: [&mut dyn Any; 0] = [];
  program
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut resources,
      calldata,
      &PreemptionEnabled::new(t_env),
    )
    .await
}

/// A chain of `levels` callers ending in a leaf that touches the very bottom of
/// its own frame. `levels == 7` is the deepest chain the loader accepts.
fn depth_chain(levels: usize) -> Vec<Insn> {
  let mut code = Vec::new();
  for _ in 0..levels {
    // Target is `pc + imm + 1`, i.e. the next function.
    code.push(Insn::call_local(1));
    code.push(Insn::exit());
  }
  code.push(Insn::ldx_dw(0, 10, -4096));
  code.push(Insn::exit());
  code
}

#[test]
fn a_deeper_call_chain_is_rejected_at_load() {
  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .load(&mut rand::thread_rng(), &build_elf(&depth_chain(8), &[]));
  match program {
    Err(Error(RuntimeError::InvalidArgumentOwned(msg)))
      if msg.contains("call graph depth (9) exceeds max (8)") => {}
    other => panic!("expected a depth rejection, got {:?}", other.err()),
  }
}

/// The loader caps the local call graph at 8 frames because 8 * 4096 is exactly
/// the guest stack window. Calldata is copied into the top of that same window
/// and `R10` starts below it, so the deepest frame of an accepted program runs
/// off the bottom of the stack by as much calldata as the caller passed.
#[tokio::test]
async fn the_call_depth_limit_does_not_account_for_calldata() {
  let code = depth_chain(7);

  let without = run_raw(&code, &[], &[], true).await;
  assert!(
    matches!(without, Ok(_)),
    "the deepest accepted chain should fit an empty-calldata stack, got {without:?}"
  );

  for calldata_len in [1usize, 8, 64] {
    let with = run_raw(&code, &[], &vec![0u8; calldata_len], true).await;
    assert!(
      matches!(with, Err(Error(RuntimeError::MemoryFault(_)))),
      "{calldata_len} bytes of calldata should push the deepest frame off the \
       stack, got {with:?}"
    );
  }
}

static BUMPS: AtomicU64 = AtomicU64::new(0);

fn h_bump(_: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
  BUMPS.fetch_add(1, Ordering::SeqCst);
  Ok(0)
}

static BUMP_HELPERS: &[(&str, Helper)] = &[("bump", h_bump)];

/// `require_static_region_analysis` is enforced per function, when that function
/// is first called. A callee that fails it is only rejected after the entry
/// function has already run — including its helper side effects — and the same
/// prefix runs again on every subsequent invocation.
#[tokio::test]
async fn a_callee_is_region_checked_only_after_the_entry_has_taken_effect() {
  let (_, t_env) = gt_env();
  let binary = compile_ebpf(
    br#"
  extern int bump(void);
  static unsigned long long __attribute__((noinline, section("test")))
  deref(unsigned long long **pp) {
    return **pp;
  }
  unsigned long long __attribute__((section("test"))) entry(unsigned long long **pp) {
    bump();
    bump();
    bump();
    return deref(pp);
  }
  "#
    .to_vec(),
  )
  .await
  .unwrap();

  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[BUMP_HELPERS],
  )
  .require_static_region_analysis(true)
  .load(&mut rand::thread_rng(), &binary)
  .unwrap()
  .pin_to_current_thread(t_env);

  assert_eq!(BUMPS.load(Ordering::SeqCst), 0, "loading must not execute");

  for attempt in 1..=3u64 {
    let ret = run(&program, &[]).await;
    match ret {
      Err(Error(RuntimeError::InvalidArgumentOwned(ref msg)))
        if msg.contains("static region analysis") => {}
      other => panic!("expected a static region rejection, got {other:?}"),
    }
    assert_eq!(
      BUMPS.load(Ordering::SeqCst),
      attempt * 3,
      "the entry function's side effects ran again before the rejection"
    );
  }
}

/// Builds `levels` nested functions, each of which calls the next once per
/// distinct pointer signature it can hand it. Level `i` is therefore compiled
/// `arity^i` times.
///
/// The carrier register is callee-saved (`R6`-`R9`) so the choice a level makes
/// survives into the grandchild's signature; `R1`-`R5` are clobbered by the
/// call and would collapse the branching.
fn signature_fanout(levels: usize, arity: usize, tail_pad: usize) -> Vec<Insn> {
  fn setup(kind: usize, carrier: u8) -> Vec<Insn> {
    match kind {
      // A relocated data pointer, a frame pointer, a plain scalar, and a value
      // the analysis cannot route - four distinct `RegKind`s.
      0 => Insn::lddw_data(carrier, 0).to_vec(),
      1 => vec![Insn::mov64_reg(carrier, 10)],
      2 => vec![Insn::mov64_imm(carrier, 0)],
      _ => vec![Insn::mov64_reg(carrier, 1)],
    }
  }

  let carrier_of = |level: usize| 6u8 + (level % 4) as u8;
  let level_len = |level: usize| {
    (0..arity)
      .map(|kind| setup(kind, carrier_of(level)).len() + 1)
      .sum::<usize>()
      + 1
      + tail_pad
  };

  let mut starts = vec![0usize];
  for level in 0..levels {
    starts.push(starts[level] + level_len(level));
  }

  let mut code: Vec<Insn> = Vec::new();
  for level in 0..levels {
    for kind in 0..arity {
      code.extend_from_slice(&setup(kind, carrier_of(level)));
      let pc = code.len();
      code.push(Insn::call_local(starts[level + 1] as i32 - pc as i32 - 1));
    }
    code.extend(std::iter::repeat_n(Insn::mov64_imm(0, 0), tail_pad));
    code.push(Insn::exit());
  }
  code.extend(std::iter::repeat_n(Insn::mov64_imm(0, 0), tail_pad));
  code.push(Insn::mov64_imm(0, 0));
  code.push(Insn::exit());
  code
}

/// A callee is compiled once per incoming pointer signature, and a signature is
/// carried down the call graph, so the number of native copies is exponential
/// in the call depth rather than linear in the program size.
#[tokio::test]
async fn callee_specialisation_is_exponential_in_call_depth() {
  let code = signature_fanout(4, 4, 0);
  assert_eq!(code.len(), 42, "the program is 42 instructions");

  let program = load_raw(&code, &[0u8; 8]);
  assert_eq!(run(&program, &[]).await.unwrap(), 0);

  assert_eq!(
    program.function_variant_counts_for_tests(),
    vec![1, 4, 16, 64, 256],
    "each level is compiled once per signature its caller can produce"
  );
  assert_eq!(program.compiled_function_count_for_tests(), 341);
}

/// The same fan-out at the maximum call depth exhausts the default 1 MiB code
/// budget part way through a run, from an eBPF program of about two kilobytes.
#[tokio::test]
async fn specialisation_can_exhaust_the_code_arena_mid_run() {
  let code = signature_fanout(7, 4, 24);
  assert!(
    code.len() * 8 < 4096,
    "the source program is small: {} bytes",
    code.len() * 8
  );

  let program = load_raw(&code, &[0u8; 8]);
  let ret = run(&program, &[]).await;
  match ret {
    Err(Error(RuntimeError::InvalidArgumentOwned(ref msg)))
      if msg.contains("code translation failed") || msg.contains("no space left") => {}
    other => panic!("expected the code arena to run out, got {other:?}"),
  }
  assert!(
    program.code_arena_used_for_tests() > DEFAULT_CODE_SIZE_LIMIT - 4096,
    "the arena should be full: {}",
    program.code_arena_used_for_tests()
  );
}

#[derive(Default)]
struct CountingEventListener {
  yields: AtomicUsize,
  throttles: AtomicUsize,
}

impl ProgramEventListener for CountingEventListener {
  fn did_yield(&self) {
    self.yields.fetch_add(1, Ordering::SeqCst);
  }

  fn did_throttle(
    &self,
    _: &HelperScope,
  ) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>> {
    self.throttles.fetch_add(1, Ordering::SeqCst);
    None
  }
}

async fn count_events(
  binary: &[u8],
  helpers: &[&'static [(&'static str, Helper)]],
) -> (usize, usize) {
  let (_, t_env) = gt_env();
  let events = Arc::new(CountingEventListener::default());
  let program = ProgramLoader::new(&mut rand::thread_rng(), events.clone(), helpers)
    .load(&mut rand::thread_rng(), binary)
    .unwrap()
    .pin_to_current_thread(t_env);
  // Zero budgets: the run loop should yield and throttle at every opportunity.
  let timeslice = TimesliceConfig {
    max_run_time_before_yield: Duration::ZERO,
    max_run_time_before_throttle: Duration::ZERO,
    throttle_duration: Duration::from_millis(1),
  };
  let mut resources: [&mut dyn Any; 0] = [];
  program
    .run(
      &timeslice,
      &TokioTimeslicer,
      "test",
      &mut resources,
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await
    .unwrap();
  (
    events.yields.load(Ordering::SeqCst),
    events.throttles.load(Ordering::SeqCst),
  )
}

/// Time spent JIT-compiling a callee is never charged to the timeslice: the
/// run loop resumes the guest directly after a lazy compilation instead of
/// falling through to the yield and throttle checks. An async helper call on
/// the same zero budgets does reach them, which is the contrast.
#[tokio::test]
async fn lazy_compilation_is_not_charged_to_the_timeslice() {
  let lazy = build_elf(&signature_fanout(2, 2, 0), &[0u8; 8]);
  let (yields, throttles) = count_events(&lazy, &[]).await;
  assert_eq!(
    (yields, throttles),
    (0, 0),
    "lazy compilations bypass the timeslice accounting entirely"
  );

  let helper = compile_ebpf(
    br#"
  extern int return_7_async(void);
  int __attribute__((section("test"))) entry(void) {
    // The first dispatch only seeds the budget clocks; later ones can expire.
    return return_7_async() + return_7_async() + return_7_async();
  }
  "#
    .to_vec(),
  )
  .await
  .unwrap();
  let (yields, throttles) = count_events(&helper, &[ASYNC_HELPERS]).await;
  assert!(
    yields > 0 || throttles > 0,
    "a helper dispatch on a zero budget should yield or throttle"
  );
}

fn h_return_7_async(
  scope: &HelperScope,
  _: u64,
  _: u64,
  _: u64,
  _: u64,
  _: u64,
) -> Result<u64, ()> {
  scope.post_task(async move {
    tokio::time::sleep(Duration::from_millis(1)).await;
    |_: &HelperScope| Ok(7)
  });
  Ok(0)
}

static ASYNC_HELPERS: &[(&str, Helper)] = &[("return_7_async", h_return_7_async)];

/// The resolver is a full host call - it suspends the guest, runs the region
/// analysis and re-`mprotect`s the code arena - and the callee is entered from
/// the middle of that sequence. Nothing it touches may reach a guest register,
/// on the first (compiling) call or on the cached one.
#[tokio::test]
async fn a_lazy_call_leaks_nothing_into_the_callees_registers() {
  // The entry trampoline zeroes every register except R1 and R10, so a callee
  // that ORs the register file together must see zero - twice, because the two
  // call sites share a pointer signature and so share one compiled callee.
  let mut code = vec![
    Insn::mov64_imm(9, 0), // accumulator
    Insn::mov64_imm(1, 0),
    Insn::call_local(11), // cold: resolver compiles the callee
    Insn::or64_reg(9, 0),
    Insn::mov64_imm(0, 0),
    Insn::mov64_imm(1, 0),
    Insn::mov64_imm(2, 0),
    Insn::mov64_imm(3, 0),
    Insn::mov64_imm(4, 0),
    Insn::mov64_imm(5, 0),
    Insn::call_local(3), // warm: resolver answers from the cache
    Insn::or64_reg(9, 0),
    Insn::mov64_reg(0, 9),
    Insn::exit(),
  ];
  for reg in 1..=8u8 {
    code.push(Insn::or64_reg(0, reg));
  }
  code.push(Insn::exit());

  let program = load_raw(&code, &[]);
  assert_eq!(
    run(&program, &[]).await.unwrap(),
    0,
    "a callee register held something other than the caller's zero"
  );
  assert_eq!(
    program.function_variant_counts_for_tests(),
    vec![1, 1],
    "both call sites must share one specialisation, so one call is cached"
  );
}

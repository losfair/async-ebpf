//! Local calls through the lazy, per-signature JIT.
//!
//! A local call is not linked at load time: each call site is compiled into a
//! stub that asks a host resolver for the callee's native address the first
//! time it runs. The resolver suspends the guest, JIT-compiles the callee for
//! the pointer signature the caller was analyzed with, and resumes. These tests
//! cover what that path guarantees — what the callee sees in its registers, how
//! many native copies of a function a program can force, and that the time
//! spent compiling is charged to the run budget.

use std::{
  any::Any,
  sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
  },
  time::Duration,
};

use crate::{
  error::{Error, RuntimeError},
  helpers::Helper,
  program::{
    DummyProgramEventListener, HelperScope, PreemptionEnabled, Program, ProgramEventListener,
    ProgramLoader, TimesliceConfig, Timeslicer, MAX_CALLDATA_SIZE,
  },
  test::raw_elf::{build_elf, Insn},
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

fn load_raw_with_large_stack(code: &[Insn], rodata: &[u8]) -> Program {
  let (_, t_env) = gt_env();
  ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_guest_stack_size(8 * 1024 * 1024)
  .load(&mut rand::thread_rng(), &build_elf(code, rodata))
  .unwrap()
  .pin_to_current_thread(t_env)
}

fn load_raw_with_frame_size(code: &[Insn], rodata: &[u8], frame_size: usize) -> Program {
  let (_, t_env) = gt_env();
  ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_stack_frame_size(frame_size)
  .with_guarded_stack_frames(false)
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

/// The historical default carries eight complete local-function frames, while
/// calldata is copied into the top of the same guest stack window with `R10`
/// starting below it. The runtime guard has to account for both.
#[tokio::test]
async fn the_default_call_capacity_fits_alongside_calldata() {
  // Seven callers plus a leaf that touches the very bottom of its own frame -
  // the complete eight-frame capacity retained by the default.
  let mut code = Vec::new();
  for _ in 0..7 {
    code.push(Insn::call_local(1)); // target is pc + imm + 1, the next function
    code.push(Insn::exit());
  }
  code.push(Insn::ldx_dw(0, 10, -4096));
  code.push(Insn::exit());

  let program = load_raw(&code, &[]);
  for calldata_len in [0usize, 1, 8, 64, MAX_CALLDATA_SIZE] {
    let ret = run(&program, &vec![0u8; calldata_len]).await;
    assert!(
      ret.is_ok(),
      "{calldata_len} bytes of calldata pushed the deepest frame off the stack: {ret:?}"
    );
  }
}

fn local_call_chain(function_count: usize) -> Vec<Insn> {
  let mut code = Vec::new();
  for index in 0..function_count {
    if index + 1 == function_count {
      code.push(Insn::exit());
    } else {
      code.push(Insn::call_local(1));
      code.push(Insn::exit());
    }
  }
  code
}

#[tokio::test]
async fn a_call_beyond_the_default_guest_stack_returns_stack_exhausted() {
  let program = load_raw(&local_call_chain(9), &[]);
  assert!(matches!(
    run(&program, &[]).await,
    Err(Error(RuntimeError::StackExhausted))
  ));
}

#[tokio::test]
async fn configurable_frame_size_controls_local_call_stack_movement() {
  const FRAME_SIZE: i16 = 512;
  let code = [
    Insn::call_local(2),
    Insn::ldx_dw(0, 10, -FRAME_SIZE - 8),
    Insn::exit(),
    Insn::mov64_imm(0, 0x5a),
    Insn::stx_dw(10, 0, -8),
    Insn::exit(),
  ];
  let program = load_raw_with_frame_size(&code, &[], FRAME_SIZE as usize);
  assert_eq!(run(&program, &[]).await.unwrap(), 0x5a);
}

#[tokio::test]
async fn smaller_frames_increase_the_default_call_capacity() {
  let program = load_raw_with_frame_size(&local_call_chain(9), &[], 2048);
  assert!(run(&program, &[]).await.is_ok());
}

/// Entry keeps the calldata pointer in callee-saved R6. The recursive function
/// decrements the word it points at until zero, so the same cyclic call graph
/// can be exercised both below and beyond a configured dynamic stack bound.
fn counted_recursion() -> Vec<Insn> {
  vec![
    Insn::mov64_reg(6, 1),
    Insn::call_local(2), // pc 1 -> recursive function at pc 4
    Insn::ldx_dw(0, 6, 0),
    Insn::exit(),
    Insn::ldx_dw(0, 6, 0),
    Insn::raw(0x15, 0, 0, 3, 0), // if r0 == 0, exit
    Insn::add64_imm(0, -1),
    Insn::stx_dw(6, 0, 0),
    Insn::call_local(-5), // pc 8 -> itself at pc 4
    Insn::exit(),
  ]
}

#[tokio::test]
async fn terminating_recursion_runs_without_an_escape_hatch() {
  let program = load_raw(&counted_recursion(), &[]);
  assert_eq!(run(&program, &6u64.to_le_bytes()).await.unwrap(), 0);
}

#[tokio::test]
async fn recursion_past_the_guest_stack_returns_stack_exhausted() {
  let program = load_raw(&counted_recursion(), &[]);
  assert!(matches!(
    run(&program, &7u64.to_le_bytes()).await,
    Err(Error(RuntimeError::StackExhausted))
  ));
  assert_eq!(
    run(&program, &6u64.to_le_bytes()).await.unwrap(),
    0,
    "abandoning the exhausted coroutine must leave later invocations usable"
  );
}

#[tokio::test]
async fn ninth_local_call_preserves_r6_with_an_enlarged_guest_stack() {
  let mut code = Vec::new();
  for _ in 0..7 {
    code.push(Insn::call_local(1));
    code.push(Insn::exit());
  }
  code.extend_from_slice(&Insn::lddw_data(6, 0));
  code.push(Insn::call_local(2));
  code.push(Insn::ldx_b(0, 6, 0));
  code.push(Insn::exit());
  code.push(Insn::mov64_imm(6, 0));
  code.push(Insn::exit());

  let program = load_raw_with_large_stack(&code, &[0x5a]);
  assert_eq!(run(&program, &[]).await.unwrap(), 0x5a);
}

#[tokio::test]
async fn cold_local_callee_observes_callers_r6() {
  let mut code = Vec::new();
  code.extend_from_slice(&Insn::lddw_data(6, 0));
  code.push(Insn::call_local(1)); // pc 2 -> pc 4
  code.push(Insn::exit());
  code.push(Insn::ldx_b(0, 6, 0));
  code.push(Insn::exit());

  let program = load_raw(&code, &[0x5a]);
  assert_eq!(run(&program, &[]).await.unwrap(), 0x5a);
}

#[tokio::test]
async fn deep_local_calls_preserve_r6_with_an_enlarged_guest_stack() {
  const DEPTH: usize = 64;
  let mut code = Vec::new();
  for _ in 0..DEPTH - 2 {
    code.push(Insn::call_local(1));
    code.push(Insn::exit());
  }
  code.extend_from_slice(&Insn::lddw_data(6, 0));
  code.push(Insn::call_local(2));
  code.push(Insn::ldx_b(0, 6, 0));
  code.push(Insn::exit());
  code.push(Insn::mov64_imm(6, 0));
  code.push(Insn::exit());

  let program = load_raw_with_large_stack(&code, &[0x5a]);
  assert_eq!(run(&program, &[]).await.unwrap(), 0x5a);
}

/// The resolver is a full host call — it suspends the guest, runs the region
/// analysis and re-`mprotect`s the code arena — and the callee is entered from
/// the middle of the call sequence, so nothing it touches may reach a guest
/// register. This has to hold on the first (compiling) call and on the cached
/// one, which take different paths through the resolver.
#[tokio::test]
async fn a_lazy_call_leaks_nothing_into_the_callees_registers() {
  // The entry trampoline zeroes every register except R1 and R10, so a callee
  // that ORs the register file together must see zero — twice, because the two
  // call sites share a pointer signature and so share one compiled callee.
  let mut code = vec![
    Insn::mov64_imm(9, 0), // accumulator
    Insn::mov64_imm(1, 0),
    Insn::call_local(11), // cold: the resolver compiles the callee
    Insn::or64_reg(9, 0),
    Insn::mov64_imm(0, 0),
    Insn::mov64_imm(1, 0),
    Insn::mov64_imm(2, 0),
    Insn::mov64_imm(3, 0),
    Insn::mov64_imm(4, 0),
    Insn::mov64_imm(5, 0),
    Insn::call_local(3), // warm: the resolver answers from the cache
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
    "both call sites must share one specialization, so one call is cached"
  );
}

/// The JIT's jump/load/lea patch tables are sized for the range being
/// translated and grow as it is emitted, so a function with far more branches
/// than the initial capacity has to keep landing every branch correctly.
#[tokio::test]
async fn a_branch_heavy_function_grows_the_jit_patch_tables() {
  const BRANCHES: usize = 300;

  // Each `jeq r0, 0` is taken (R0 is zero at entry) and skips the `exit` behind
  // it, so control reaches the tail only if all 300 branch targets were patched
  // correctly. A table that moved without its entries following lands on an
  // `exit` and returns 0.
  let mut code: Vec<Insn> = Vec::new();
  for _ in 0..BRANCHES {
    code.push(Insn::raw(0x15, 0, 0, 1, 0));
    code.push(Insn::exit());
  }
  code.push(Insn::mov64_imm(0, 42));
  code.push(Insn::exit());

  let program = load_raw(&code, &[]);
  assert_eq!(run(&program, &[]).await.unwrap(), 42);
}

/// Whether the fan-out's leaf actually reads the carrier registers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Carriers {
  /// Set but never read, so no callee can observe them.
  Ignored,
  /// Dereferenced on a statically reachable but never-taken path, so they are
  /// live-in all the way up the chain.
  Observed,
}

/// Builds `levels` nested functions, each calling the next once per distinct
/// pointer signature it can hand it, so level `i` sees up to `arity^i` distinct
/// incoming signatures.
///
/// The carrier register is callee-saved (`R6`-`R9`) so the choice a level makes
/// survives into its grandchild's signature; `R1`-`R5` are clobbered by the call
/// and would collapse the branching. Whether those signatures turn into separate
/// specializations depends on [`Carriers`].
fn signature_fanout(levels: usize, arity: usize, carriers: Carriers) -> Vec<Insn> {
  const CARRIERS: [u8; 4] = [6, 7, 8, 9];

  fn setup(kind: usize, carrier: u8) -> Vec<Insn> {
    match kind {
      // A relocated data pointer, a frame pointer, a plain scalar, and a value
      // the analysis cannot route — four distinct `RegKind`s.
      0 => Insn::lddw_data(carrier, 0).to_vec(),
      1 => vec![Insn::mov64_reg(carrier, 10)],
      2 => vec![Insn::mov64_imm(carrier, 0)],
      _ => vec![Insn::mov64_reg(carrier, 1)],
    }
  }

  let carrier_of = |level: usize| CARRIERS[level % CARRIERS.len()];
  let level_len = |level: usize| {
    (0..arity)
      .map(|kind| setup(kind, carrier_of(level)).len() + 1)
      .sum::<usize>()
      + 1
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
    code.push(Insn::exit());
  }

  if carriers == Carriers::Observed {
    // `r0 = 0; if (r0 == 0) goto tail;` then a dereference of each carrier. The
    // branch is always taken, so the loads never execute — but they are on a
    // statically reachable path, which is what the analysis looks at. Executing
    // them would fault for the carriers holding scalars.
    code.push(Insn::mov64_imm(0, 0));
    code.push(Insn::raw(0x15, 0, 0, CARRIERS.len() as i16, 0));
    for carrier in CARRIERS {
      code.push(Insn::ldx_dw(0, carrier, 0));
    }
  }
  code.push(Insn::mov64_imm(0, 0));
  code.push(Insn::exit());
  code
}

/// A pointer signature is the caller's whole abstract register file, but a
/// callee is specialized only on the registers it can actually observe. Here
/// every level hands its callee four distinct signatures and no callee ever
/// reads a carrier, so all four collapse to one specialization.
#[tokio::test]
async fn unobserved_signature_registers_do_not_multiply_specialisations() {
  let program = load_raw(&signature_fanout(4, 4, Carriers::Ignored), &[0u8; 8]);
  assert_eq!(run(&program, &[]).await.unwrap(), 0);

  assert_eq!(
    program.function_variant_counts_for_tests(),
    vec![1, 1, 1, 1, 1],
    "no callee reads a carrier, so every incoming signature masks to the same thing"
  );
}

/// The other half of that property: masking must not collapse a distinction a
/// callee can see. The identical fan-out, with the leaf dereferencing each
/// carrier, specializes fully — one native copy per distinct incoming signature.
#[tokio::test]
async fn observed_signature_registers_still_specialise() {
  let program = load_raw(&signature_fanout(4, 4, Carriers::Observed), &[0u8; 8]);
  assert_eq!(run(&program, &[]).await.unwrap(), 0);

  assert_eq!(
    program.function_variant_counts_for_tests(),
    vec![1, 4, 16, 64, 256],
    "each level is compiled once per signature its caller can produce"
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

/// Yield at every opportunity; never throttle.
const ZERO_YIELD_BUDGET: TimesliceConfig = TimesliceConfig {
  max_run_time_before_yield: Duration::ZERO,
  max_run_time_before_throttle: Duration::from_secs(3600),
  throttle_duration: Duration::from_millis(1),
};

/// Throttle at every opportunity. The throttle branch is checked first, so this
/// wins over the yield branch.
const ZERO_THROTTLE_BUDGET: TimesliceConfig = TimesliceConfig {
  max_run_time_before_yield: Duration::ZERO,
  max_run_time_before_throttle: Duration::ZERO,
  throttle_duration: Duration::ZERO,
};

/// Runs `code` under `timeslice`, reporting how many times the run loop yielded
/// and throttled alongside the program itself.
async fn count_events(code: &[Insn], timeslice: TimesliceConfig) -> (Program, usize, usize) {
  let (_, t_env) = gt_env();
  let events = Arc::new(CountingEventListener::default());
  let program = ProgramLoader::new(&mut rand::thread_rng(), events.clone(), &[])
    .load(&mut rand::thread_rng(), &build_elf(code, &[0u8; 8]))
    .unwrap()
    .pin_to_current_thread(t_env);
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
  let yields = events.yields.load(Ordering::SeqCst);
  let throttles = events.throttles.load(Ordering::SeqCst);
  (program, yields, throttles)
}

/// JIT-compiling a callee is guest-triggered work of unbounded size, so it is
/// charged to the run budget like any other dispatch — including bypassing the
/// timestamp-free fast path, which exists so that a helper call does not pay for
/// a clock read.
#[tokio::test]
async fn lazy_compilation_is_charged_to_the_timeslice() {
  // Three functions, seven specializations: one is compiled eagerly as the
  // entry point and the other six are lazy-call dispatches.
  let (program, yields, throttles) = count_events(
    &signature_fanout(2, 2, Carriers::Observed),
    ZERO_YIELD_BUDGET,
  )
  .await;
  assert_eq!(program.compiled_function_count_for_tests(), 7);
  assert!(
    yields >= 4,
    "expected roughly one yield per lazy compilation, got {yields} yields and \
     {throttles} throttles"
  );

  let (_, yields, throttles) = count_events(
    &signature_fanout(2, 2, Carriers::Observed),
    ZERO_THROTTLE_BUDGET,
  )
  .await;
  assert!(
    throttles >= 4,
    "expected the throttle budget to bite, got {yields} yields and {throttles} throttles"
  );
}

/// Running out of code budget names the budget and the limit that set it,
/// rather than surfacing the JIT's internal out-of-space failure with nothing
/// pointing at the cause.
#[tokio::test]
async fn code_budget_exhaustion_names_the_budget() {
  let (_, t_env) = gt_env();
  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_code_size_limit(64 * 1024)
  .load(
    &mut rand::thread_rng(),
    &build_elf(&signature_fanout(7, 4, Carriers::Observed), &[0u8; 8]),
  )
  .unwrap()
  .pin_to_current_thread(t_env);

  match run(&program, &[]).await {
    Err(Error(RuntimeError::InvalidArgumentOwned(ref msg)))
      if msg.contains("code budget exhausted")
        && msg.contains("65536 byte code budget")
        && msg.contains("with_code_size_limit") => {}
    other => panic!("expected a code budget error, got {other:?}"),
  }
  assert!(program.compiled_function_count_for_tests() > 0);
}

static BUDGET_HELPER_CALLS: AtomicUsize = AtomicUsize::new(0);

fn h_bump(_: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
  BUDGET_HELPER_CALLS.fetch_add(1, Ordering::SeqCst);
  Ok(0)
}

static BUDGET_HELPERS: &[(&str, Helper)] = &[("bump", h_bump)];

/// A cold local call suspends to compile its target, and every helper call also
/// suspends to the host. Nest the two paths to ensure the native lazy-call save
/// areas survive repeated coroutine switches at every supported call depth.
#[tokio::test]
async fn nested_cold_calls_and_helpers_preserve_native_call_frames() {
  let source = br#"
    extern int bump(void);
    #define F __attribute__((noinline, section("test")))
    static int F f6(void) { bump(); return 1; }
    static int F f5(void) { bump(); return f6() + 1; }
    static int F f4(void) { bump(); return f5() + 1; }
    static int F f3(void) { bump(); return f4() + 1; }
    static int F f2(void) { bump(); return f3() + 1; }
    static int F f1(void) { bump(); return f2() + 1; }
    static int F f0(void) { bump(); return f1() + 1; }
    int F entry(void) { bump(); return f0() + 1; }
  "#;
  let binary = compile_ebpf(source.to_vec()).await.unwrap();
  let (_, t_env) = gt_env();
  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[BUDGET_HELPERS],
  )
  .load(&mut rand::thread_rng(), &binary)
  .unwrap()
  .pin_to_current_thread(t_env);

  assert_eq!(run(&program, &[]).await.unwrap(), 8);
  assert_eq!(program.compiled_function_count_for_tests(), 8);
}

/// Exhausting the budget is terminal for the whole program - the arena never
/// shrinks, so nothing can be compiled from there on. Later runs must fail
/// without replaying the program up to the call that cannot be resolved.
#[tokio::test]
async fn code_budget_exhaustion_is_terminal() {
  // A small entry that calls a helper, then a callee too big for the budget.
  // The loop count is sized to overshoot `with_code_size_limit` below with room
  // to spare, because how much native code an eBPF instruction costs is exactly
  // what the frame-addressing work changes: at 1200 the callee used to be a
  // little over the 64 KiB budget and is now a little under it.
  let mut body = String::new();
  for i in 0..3000u64 {
    body.push_str(&format!("  acc ^= acc << {}; acc += {i};\n", (i % 13) + 1));
  }
  let source = format!(
    r#"
  extern int bump(void);
  static unsigned long long __attribute__((noinline, section("test")))
  big(unsigned long long acc) {{
    volatile unsigned long long sink = 0;
  {body}
    sink = acc;
    return sink;
  }}
  unsigned long long __attribute__((section("test"))) entry(void) {{
    bump();
    return big(1);
  }}
  "#
  );

  let (_, t_env) = gt_env();
  let binary = compile_ebpf(source.into_bytes()).await.unwrap();
  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[BUDGET_HELPERS],
  )
  .with_code_size_limit(64 * 1024)
  .load(&mut rand::thread_rng(), &binary)
  .unwrap()
  .pin_to_current_thread(t_env);

  let before = BUDGET_HELPER_CALLS.load(Ordering::SeqCst);
  match run(&program, &[]).await {
    Err(Error(RuntimeError::InvalidArgumentOwned(ref msg)))
      if msg.contains("code budget exhausted") => {}
    other => panic!("expected a code budget error, got {other:?}"),
  }
  assert_eq!(
    BUDGET_HELPER_CALLS.load(Ordering::SeqCst),
    before + 1,
    "the first run should get as far as the helper call"
  );

  assert!(run(&program, &[]).await.is_err());
  assert_eq!(
    BUDGET_HELPER_CALLS.load(Ordering::SeqCst),
    before + 1,
    "a terminal budget failure must not re-execute the program"
  );
}

/// End to end: a program that forces a long chain of compilations must not hold
/// the thread for the whole chain.
#[tokio::test(flavor = "current_thread")]
async fn a_compilation_storm_does_not_starve_the_async_runtime() {
  let ticks = Arc::new(AtomicUsize::new(0));
  let counter = ticks.clone();
  let heartbeat = tokio::spawn(async move {
    loop {
      tokio::time::sleep(Duration::from_millis(1)).await;
      counter.fetch_add(1, Ordering::SeqCst);
    }
  });
  tokio::time::sleep(Duration::from_millis(5)).await;
  let before = ticks.load(Ordering::SeqCst);

  let (program, yields, _) = count_events(
    &signature_fanout(7, 4, Carriers::Observed),
    ZERO_YIELD_BUDGET,
  )
  .await;
  let during = ticks.load(Ordering::SeqCst) - before;
  heartbeat.abort();

  let compiled = program.compiled_function_count_for_tests();
  assert!(compiled > 300, "expected a long chain, got {compiled}");
  assert!(
    yields > 100,
    "expected the run to yield repeatedly, got {yields}"
  );
  assert!(
    during > 0,
    "the heartbeat task was starved for the whole run"
  );
}

/// The compilations themselves run wherever `Timeslicer::run_blocking` puts
/// them - here, on Tokio's blocking pool - never on the thread driving the run
/// loop.
#[tokio::test]
async fn lazy_compilation_runs_on_the_blocking_executor() {
  struct RecordingTimeslicer {
    compile_threads: Arc<std::sync::Mutex<Vec<std::thread::ThreadId>>>,
  }
  impl Timeslicer for RecordingTimeslicer {
    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> {
      tokio::time::sleep(duration)
    }
    fn yield_now(&self) -> impl std::future::Future<Output = ()> {
      tokio::task::yield_now()
    }
    fn run_blocking<T: Send + 'static>(
      &self,
      f: impl FnOnce() -> T + Send + 'static,
    ) -> impl std::future::Future<Output = T> {
      let threads = self.compile_threads.clone();
      let handle = tokio::task::spawn_blocking(move || {
        threads.lock().unwrap().push(std::thread::current().id());
        f()
      });
      async move { handle.await.unwrap() }
    }
  }

  let timeslicer = RecordingTimeslicer {
    compile_threads: Arc::new(std::sync::Mutex::new(Vec::new())),
  };
  let program = load_raw(&signature_fanout(2, 2, Carriers::Observed), &[0u8; 8]);
  let (_, t_env) = gt_env();
  let mut resources: [&mut dyn Any; 0] = [];
  let ret = program
    .run(
      &timeslice_config(),
      &timeslicer,
      "test",
      &mut resources,
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await
    .unwrap();
  assert_eq!(ret, 0);
  assert_eq!(program.compiled_function_count_for_tests(), 7);

  let threads = timeslicer.compile_threads.lock().unwrap();
  assert_eq!(
    threads.len(),
    7,
    "expected one run_blocking invocation per compiled variant"
  );
  let loop_thread = std::thread::current().id();
  assert!(
    threads.iter().all(|id| *id != loop_thread),
    "a compilation ran on the run-loop thread"
  );
}

/// The trait's default `run_blocking` runs the job inline on the current
/// thread - the behavior every embedder had before the hook existed - and the
/// lazy pipeline works identically through it.
#[tokio::test]
async fn the_default_run_blocking_compiles_inline() {
  struct InlineTimeslicer;
  impl Timeslicer for InlineTimeslicer {
    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> {
      tokio::time::sleep(duration)
    }
    fn yield_now(&self) -> impl std::future::Future<Output = ()> {
      tokio::task::yield_now()
    }
  }

  let program = load_raw(&signature_fanout(2, 2, Carriers::Observed), &[0u8; 8]);
  let (_, t_env) = gt_env();
  let mut resources: [&mut dyn Any; 0] = [];
  let ret = program
    .run(
      &timeslice_config(),
      &InlineTimeslicer,
      "test",
      &mut resources,
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await
    .unwrap();
  assert_eq!(ret, 0);
  assert_eq!(program.compiled_function_count_for_tests(), 7);
}

/// Two interleaved runs hitting the same cold function share one compilation:
/// the second finds the first's claim in flight and awaits it instead of
/// compiling the variant again.
#[tokio::test]
async fn interleaved_runs_share_one_in_flight_compilation() {
  struct SlowCompileTimeslicer;
  impl Timeslicer for SlowCompileTimeslicer {
    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> {
      tokio::time::sleep(duration)
    }
    fn yield_now(&self) -> impl std::future::Future<Output = ()> {
      tokio::task::yield_now()
    }
    fn run_blocking<T: Send + 'static>(
      &self,
      f: impl FnOnce() -> T + Send + 'static,
    ) -> impl std::future::Future<Output = T> {
      let handle = tokio::task::spawn_blocking(move || {
        // Hold the claim open long enough for the other run to reach the same
        // call site and find it in flight.
        std::thread::sleep(Duration::from_millis(20));
        f()
      });
      async move { handle.await.unwrap() }
    }
  }

  let code = [
    Insn::call_local(1),
    Insn::exit(),
    Insn::mov64_imm(0, 7),
    Insn::exit(),
  ];
  let program = load_raw(&code, &[]);
  let (_, t_env) = gt_env();
  let preemption = PreemptionEnabled::new(t_env);
  let timeslice = timeslice_config();
  let mut resources_a: [&mut dyn Any; 0] = [];
  let mut resources_b: [&mut dyn Any; 0] = [];
  let run_a = program.run(
    &timeslice,
    &SlowCompileTimeslicer,
    "test",
    &mut resources_a,
    &[],
    &preemption,
  );
  let run_b = program.run(
    &timeslice,
    &SlowCompileTimeslicer,
    "test",
    &mut resources_b,
    &[],
    &preemption,
  );
  let (ret_a, ret_b) = tokio::join!(run_a, run_b);
  assert_eq!(ret_a.unwrap(), 7);
  assert_eq!(ret_b.unwrap(), 7);

  // The entry point and the callee, compiled once each even though both runs
  // needed both while the claims were still open.
  assert_eq!(program.function_compile_attempt_count_for_tests(), 2);
  assert_eq!(program.compiled_function_count_for_tests(), 2);
}

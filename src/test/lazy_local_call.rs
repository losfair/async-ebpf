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
    ProgramLoader, TimesliceConfig, MAX_CALLDATA_SIZE,
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

/// The loader caps the local call graph at `MAX_LOCAL_CALL_DEPTH` frames, and
/// calldata is copied into the top of the same guest stack window with `R10`
/// starting below it. The window has to cover both, or the deepest chain the
/// loader accepts runs off the bottom of the stack as soon as any calldata is
/// passed.
#[tokio::test]
async fn the_deepest_accepted_call_chain_fits_alongside_calldata() {
  // Seven callers plus a leaf that touches the very bottom of its own frame -
  // the deepest chain `validate_local_call_graph` accepts.
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

/// Running out of code budget names the budget, rather than surfacing uBPF's
/// internal "target buffer too small" with nothing pointing at the cause.
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
        && msg.contains("65536 byte budget")
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

/// Exhausting the budget is terminal for the whole program - the arena never
/// shrinks, so nothing can be compiled from there on. Later runs must fail
/// without replaying the program up to the call that cannot be resolved.
#[tokio::test]
async fn code_budget_exhaustion_is_terminal() {
  // A small entry that calls a helper, then a callee too big for the budget.
  let mut body = String::new();
  for i in 0..1200u64 {
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

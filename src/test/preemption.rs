use std::{
  sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
  },
  time::Duration,
};

use crate::{
  program::{GlobalEnv, PreemptionEnabled, ProgramEventListener, ProgramLoader, TimesliceConfig},
  test_util::{compile_ebpf, TokioTimeslicer},
};

/// Iterations of the preempted guest loop.
///
/// These tests assert that async preemption *was observed*, so the guest has to
/// stay in JIT code long enough for the watcher thread to get scheduled at least
/// once. The watcher fires on a fixed interval (1-2 ms below), so what matters
/// is wall-clock time in the guest, not iterations - which makes this constant a
/// hostage to how fast the JIT is. It has already been raised once, when frame
/// addressing made this loop (all of it volatile frame traffic) about eight
/// times faster and CI stopped seeing any preemption at all.
///
/// **If a JIT change makes these tests flaky, raise this rather than weakening
/// the assertion.** The margin to aim for is a guest run of well over 100 ms on
/// a fast machine; CI runs this under emulation, where the watcher is scheduled
/// far more coarsely than the nominal interval.
const LOOP_ITERS: u64 = 200_000_000;
const LOCAL_CALL_LOOP_ITERS: u64 = 10_000_000;
const EXPECTED_SUM: i64 = (LOOP_ITERS / 8 * 28) as i64;
const EXPECTED_LOCAL_CALL_SUM: i64 =
  (LOCAL_CALL_LOOP_ITERS / 8 * 28 + LOCAL_CALL_LOOP_ITERS * 11) as i64;

/// The guest source for the plain loop, with [`LOOP_ITERS`] substituted in.
///
/// The iteration count is interpolated rather than written twice: the expected
/// results below are computed from the constant, so a literal in the C source
/// that drifted from it would make the tests fail in a way that looks like a
/// runtime bug.
fn stateful_loop_source() -> Vec<u8> {
  STATEFUL_LOOP_TEMPLATE
    .replace("{ITERS}", &LOOP_ITERS.to_string())
    .into_bytes()
}

/// The guest source for the local-call loop, with [`LOCAL_CALL_LOOP_ITERS`]
/// substituted in.
fn local_call_loop_source() -> Vec<u8> {
  LOCAL_CALL_LOOP_TEMPLATE
    .replace("{ITERS}", &LOCAL_CALL_LOOP_ITERS.to_string())
    .into_bytes()
}

// These tests intentionally depend on watcher scheduling within a short JIT
// workload. Running several of them concurrently can starve a watcher on small
// CI machines and turn the "was preempted" assertion into a scheduler test.
static PREEMPTION_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Takes [`PREEMPTION_TEST_LOCK`], ignoring poisoning.
///
/// The lock guards nothing but scheduling, so a test that panicked while holding
/// it has left no state for the next one to be confused by. Unwrapping instead
/// would turn one real failure into a run of `PoisonError`s that bury it - which
/// is exactly what happened the first time these assertions tripped in CI.
fn preemption_test_lock() -> std::sync::MutexGuard<'static, ()> {
  PREEMPTION_TEST_LOCK
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
}

const STATEFUL_LOOP_TEMPLATE: &str = r#"
#define LOOP_ITERS {ITERS}ULL

unsigned long long __attribute__((section("test"))) entry(void) {
  volatile unsigned long long guard = 0x1122334455667788ULL;
  volatile unsigned long long sum = 0;

  for (unsigned long long i = 0; i < LOOP_ITERS; i++) {
    sum += i & 7;
    guard ^= i | 1;
    guard ^= i | 1;
  }

  if (guard != 0x1122334455667788ULL) {
    return 0xffffffffffffffffULL;
  }

  return sum;
}
"#;

const LOCAL_CALL_LOOP_TEMPLATE: &str = r#"
#define LOOP_ITERS {ITERS}ULL

static unsigned long long __attribute__((noinline, section("test")))
bump(unsigned long long i, volatile unsigned long long *guard) {
  *guard ^= i | 1;
  *guard ^= i | 1;
  return (i & 7) + 11;
}

unsigned long long __attribute__((section("test"))) entry(void) {
  volatile unsigned long long guard = 0x1122334455667788ULL;
  unsigned long long sum = 0;

  for (unsigned long long i = 0; i < LOOP_ITERS; i++) {
    sum += bump(i, &guard);
  }

  if (guard != 0x1122334455667788ULL) {
    return 0xffffffffffffffffULL;
  }

  return sum;
}
"#;

#[derive(Default)]
struct CountingEventListener {
  async_preempts: AtomicUsize,
  yields: AtomicUsize,
}

impl ProgramEventListener for CountingEventListener {
  fn did_async_preempt(&self, _: &crate::program::HelperScope) {
    self.async_preempts.fetch_add(1, Ordering::SeqCst);
  }

  fn did_yield(&self) {
    self.yields.fetch_add(1, Ordering::SeqCst);
  }
}

#[test]
fn test_async_preemption_preserves_guest_state() {
  let _guard = preemption_test_lock();
  let timeslice = TimesliceConfig {
    max_run_time_before_throttle: Duration::from_secs(60),
    max_run_time_before_yield: Duration::from_secs(60),
    throttle_duration: Duration::from_millis(1),
  };

  let (ret, events, heartbeat_ticks) = run_preempted_program(timeslice, false);

  assert_eq!(ret, EXPECTED_SUM);
  assert!(
    events.async_preempts.load(Ordering::SeqCst) > 0,
    "the guest was never preempted; it ran {LOOP_ITERS} iterations without the \
     watcher getting scheduled once. If a JIT change made the guest faster, raise \
     LOOP_ITERS rather than weakening this."
  );
  assert_eq!(events.yields.load(Ordering::SeqCst), 0);
  assert_eq!(heartbeat_ticks, 0);
}

#[test]
fn test_async_preemption_yields_to_async_runtime() {
  let _guard = preemption_test_lock();
  let timeslice = TimesliceConfig {
    max_run_time_before_throttle: Duration::from_secs(60),
    max_run_time_before_yield: Duration::ZERO,
    throttle_duration: Duration::from_millis(1),
  };

  let (ret, events, heartbeat_ticks) = run_preempted_program(timeslice, true);

  assert_eq!(ret, EXPECTED_SUM);
  assert!(
    events.async_preempts.load(Ordering::SeqCst) > 0,
    "the guest was never preempted; it ran {LOOP_ITERS} iterations without the \
     watcher getting scheduled once. If a JIT change made the guest faster, raise \
     LOOP_ITERS rather than weakening this."
  );
  assert!(events.yields.load(Ordering::SeqCst) > 0);
  assert!(heartbeat_ticks > 0);
}

#[test]
fn test_async_preemption_preserves_lazy_local_call_state() {
  let _guard = preemption_test_lock();
  let timeslice = TimesliceConfig {
    max_run_time_before_throttle: Duration::from_secs(60),
    max_run_time_before_yield: Duration::from_secs(60),
    throttle_duration: Duration::from_millis(1),
  };

  let (ret, events, compiled_functions) = run_preempted_local_call_program(timeslice);

  assert_eq!(ret, EXPECTED_LOCAL_CALL_SUM);
  assert!(
    events.async_preempts.load(Ordering::SeqCst) > 0,
    "the guest was never preempted; it ran {LOOP_ITERS} iterations without the \
     watcher getting scheduled once. If a JIT change made the guest faster, raise \
     LOOP_ITERS rather than weakening this."
  );
  assert_eq!(events.yields.load(Ordering::SeqCst), 0);
  assert_eq!(compiled_functions, 2);
}

#[cfg(target_os = "openbsd")]
#[test]
fn test_openbsd_preemption_thread_lifecycle_stress() {
  let _guard = preemption_test_lock();
  const ITERATIONS: usize = 128;

  let compiler_runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
  let binary = Arc::new(
    compiler_runtime
      .block_on(compile_ebpf(stateful_loop_source()))
      .unwrap(),
  );
  let global = unsafe { GlobalEnv::new() };

  for iteration in 0..ITERATIONS {
    let binary = binary.clone();
    std::thread::spawn(move || {
      let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
      runtime.block_on(async move {
        let thread = global.init_thread(Duration::from_millis(1));
        let events = Arc::new(CountingEventListener::default());
        let program = ProgramLoader::new(&mut rand::thread_rng(), events.clone(), &[])
          .load(&mut rand::thread_rng(), &binary)
          .unwrap()
          .pin_to_current_thread(thread);
        let preemption = PreemptionEnabled::new(thread);
        let timeslice = TimesliceConfig {
          max_run_time_before_throttle: Duration::from_secs(60),
          max_run_time_before_yield: Duration::from_secs(60),
          throttle_duration: Duration::from_millis(1),
        };

        let ret = program
          .run(
            &timeslice,
            &TokioTimeslicer,
            "test",
            &mut [],
            &[],
            &preemption,
          )
          .await
          .unwrap();
        assert_eq!(ret, EXPECTED_SUM, "stress iteration {iteration}");
        assert!(
          events.async_preempts.load(Ordering::SeqCst) > 0,
          "stress iteration {iteration} was not preempted"
        );
      });
    })
    .join()
    .unwrap();
  }
}

fn run_preempted_program(
  timeslice: TimesliceConfig,
  run_heartbeat: bool,
) -> (i64, Arc<CountingEventListener>, usize) {
  std::thread::spawn(move || {
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_io()
      .enable_time()
      .build()
      .unwrap();

    runtime.block_on(async move {
      let binary = compile_ebpf(stateful_loop_source()).await.unwrap();
      let global = unsafe { GlobalEnv::new() };
      let thread = global.init_thread(Duration::from_millis(2));
      let events = Arc::new(CountingEventListener::default());
      let loader = ProgramLoader::new(&mut rand::thread_rng(), events.clone(), &[]);
      let program = loader
        .load(&mut rand::thread_rng(), &binary)
        .unwrap()
        .pin_to_current_thread(thread);
      let preemption = PreemptionEnabled::new(thread);

      let stop_heartbeat = Arc::new(AtomicBool::new(false));
      let heartbeat_ticks = Arc::new(AtomicUsize::new(0));
      let heartbeat = if run_heartbeat {
        let stop_heartbeat = stop_heartbeat.clone();
        let heartbeat_ticks = heartbeat_ticks.clone();
        Some(tokio::spawn(async move {
          while !stop_heartbeat.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
            heartbeat_ticks.fetch_add(1, Ordering::SeqCst);
          }
        }))
      } else {
        None
      };

      let mut resources: [&mut dyn std::any::Any; 0] = [];
      let ret = program
        .run(
          &timeslice,
          &TokioTimeslicer,
          "test",
          &mut resources,
          &[],
          &preemption,
        )
        .await
        .unwrap();

      stop_heartbeat.store(true, Ordering::SeqCst);
      if let Some(heartbeat) = heartbeat {
        heartbeat.await.unwrap();
      }

      (ret, events, heartbeat_ticks.load(Ordering::SeqCst))
    })
  })
  .join()
  .unwrap()
}

fn run_preempted_local_call_program(
  timeslice: TimesliceConfig,
) -> (i64, Arc<CountingEventListener>, usize) {
  std::thread::spawn(move || {
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_io()
      .enable_time()
      .build()
      .unwrap();

    runtime.block_on(async move {
      let binary = compile_ebpf(local_call_loop_source()).await.unwrap();
      let global = unsafe { GlobalEnv::new() };
      let thread = global.init_thread(Duration::from_millis(1));
      let events = Arc::new(CountingEventListener::default());
      let loader = ProgramLoader::new(&mut rand::thread_rng(), events.clone(), &[]);
      let program = loader
        .load(&mut rand::thread_rng(), &binary)
        .unwrap()
        .pin_to_current_thread(thread);
      let preemption = PreemptionEnabled::new(thread);

      let mut resources: [&mut dyn std::any::Any; 0] = [];
      let ret = program
        .run(
          &timeslice,
          &TokioTimeslicer,
          "test",
          &mut resources,
          &[],
          &preemption,
        )
        .await
        .unwrap();

      (ret, events, program.compiled_function_count_for_tests())
    })
  })
  .join()
  .unwrap()
}

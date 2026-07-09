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

const LOOP_ITERS: u64 = 10_000_000;
const LOCAL_CALL_LOOP_ITERS: u64 = 10_000_000;
const EXPECTED_SUM: i64 = (LOOP_ITERS / 8 * 28) as i64;
const EXPECTED_LOCAL_CALL_SUM: i64 =
  (LOCAL_CALL_LOOP_ITERS / 8 * 28 + LOCAL_CALL_LOOP_ITERS * 11) as i64;

// These tests intentionally depend on watcher scheduling within a short JIT
// workload. Running several of them concurrently can starve a watcher on small
// CI machines and turn the "was preempted" assertion into a scheduler test.
static PREEMPTION_TEST_LOCK: Mutex<()> = Mutex::new(());

const STATEFUL_LOOP: &str = r#"
#define LOOP_ITERS 10000000ULL

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

const LOCAL_CALL_LOOP: &str = r#"
#define LOOP_ITERS 10000000ULL

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
  let _guard = PREEMPTION_TEST_LOCK.lock().unwrap();
  let timeslice = TimesliceConfig {
    max_run_time_before_throttle: Duration::from_secs(60),
    max_run_time_before_yield: Duration::from_secs(60),
    throttle_duration: Duration::from_millis(1),
  };

  let (ret, events, heartbeat_ticks) = run_preempted_program(timeslice, false);

  assert_eq!(ret, EXPECTED_SUM);
  assert!(events.async_preempts.load(Ordering::SeqCst) > 0);
  assert_eq!(events.yields.load(Ordering::SeqCst), 0);
  assert_eq!(heartbeat_ticks, 0);
}

#[test]
fn test_async_preemption_yields_to_async_runtime() {
  let _guard = PREEMPTION_TEST_LOCK.lock().unwrap();
  let timeslice = TimesliceConfig {
    max_run_time_before_throttle: Duration::from_secs(60),
    max_run_time_before_yield: Duration::ZERO,
    throttle_duration: Duration::from_millis(1),
  };

  let (ret, events, heartbeat_ticks) = run_preempted_program(timeslice, true);

  assert_eq!(ret, EXPECTED_SUM);
  assert!(events.async_preempts.load(Ordering::SeqCst) > 0);
  assert!(events.yields.load(Ordering::SeqCst) > 0);
  assert!(heartbeat_ticks > 0);
}

#[test]
fn test_async_preemption_preserves_lazy_local_call_state() {
  let _guard = PREEMPTION_TEST_LOCK.lock().unwrap();
  let timeslice = TimesliceConfig {
    max_run_time_before_throttle: Duration::from_secs(60),
    max_run_time_before_yield: Duration::from_secs(60),
    throttle_duration: Duration::from_millis(1),
  };

  let (ret, events, compiled_functions) = run_preempted_local_call_program(timeslice);

  assert_eq!(ret, EXPECTED_LOCAL_CALL_SUM);
  assert!(events.async_preempts.load(Ordering::SeqCst) > 0);
  assert_eq!(events.yields.load(Ordering::SeqCst), 0);
  assert_eq!(compiled_functions, 2);
}

#[cfg(target_os = "openbsd")]
#[test]
fn test_openbsd_preemption_thread_lifecycle_stress() {
  let _guard = PREEMPTION_TEST_LOCK.lock().unwrap();
  const ITERATIONS: usize = 128;

  let compiler_runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
  let binary = Arc::new(
    compiler_runtime
      .block_on(compile_ebpf(STATEFUL_LOOP.as_bytes().to_vec()))
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
      let binary = compile_ebpf(STATEFUL_LOOP.as_bytes().to_vec())
        .await
        .unwrap();
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
      let binary = compile_ebpf(LOCAL_CALL_LOOP.as_bytes().to_vec())
        .await
        .unwrap();
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

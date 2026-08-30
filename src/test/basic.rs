use std::{any::Any, sync::Arc, time::Duration};

use tokio::sync::Notify;

use crate::{
  error::{Error, RuntimeError},
  helpers::Helper,
  program::{DummyProgramEventListener, HelperScope, PreemptionEnabled, ProgramLoader},
  test_util::{compile_ebpf, gt_env, run_one_program, timeslice_config, RunOpts, TokioTimeslicer},
};

#[tokio::test]
async fn configurable_guest_stack_exposes_a_larger_writable_window() {
  const STACK_SIZE: usize = 2 * 1024 * 1024;
  let binary = compile_ebpf(
    br#"
      unsigned long long __attribute__((section("test"))) entry(unsigned long long *input) {
        volatile unsigned char *arena = (unsigned char *)input - 1024 * 1024;
        arena[0] = 0x5a;
        arena[1024] = 0xa5;
        return arena[0] | ((unsigned long long)arena[1024] << 8);
      }
    "#
    .to_vec(),
  )
  .await
  .unwrap();
  let (_, t_env) = crate::test_util::gt_env();
  let loader = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_guarded_stack_frames(false)
  .with_guest_stack_size(STACK_SIZE);
  let prog = loader
    .load(&mut rand::thread_rng(), &binary)
    .unwrap()
    .pin_to_current_thread(t_env);
  let preemption = PreemptionEnabled::new(prog.thread_env());
  let ret = prog
    .run(
      &crate::test_util::timeslice_config(),
      &crate::test_util::TokioTimeslicer,
      "test",
      &mut [],
      &0u64.to_ne_bytes(),
      &preemption,
    )
    .await
    .unwrap();
  assert_eq!(ret, 0xa55a);
}

static HELPERS: &'static [(&'static str, Helper)] = &[
  ("return_5", h_return_5),
  ("return_7_async", h_return_7_async),
];
static FAILING_ASYNC_HELPERS: &[(&str, Helper)] = &[("fail_async", h_fail_async)];

struct InterleavingGate {
  entered: Arc<Notify>,
  release: Arc<Notify>,
}

fn h_wait_for_peer(scope: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
  let (entered, release) = scope.with_resource_mut::<InterleavingGate, _>(|gate| {
    gate.map(|gate| (Arc::clone(&gate.entered), Arc::clone(&gate.release)))
  })?;
  scope.post_task(async move {
    entered.notify_one();
    release.notified().await;
    |_: &HelperScope| Ok(0)
  });
  Ok(0)
}

static INTERLEAVING_HELPERS: &[(&str, Helper)] = &[("wait_for_peer", h_wait_for_peer)];

fn h_fill_user_memory(
  scope: &HelperScope,
  ptr: u64,
  len: u64,
  value: u64,
  _: u64,
  _: u64,
) -> Result<u64, ()> {
  scope.user_memory_mut(ptr, len)?.fill(value as u8);
  Ok(0)
}

static WRITABLE_DATA_HELPERS: &[(&str, Helper)] = &[("fill_user_memory", h_fill_user_memory)];

#[tokio::test]
async fn writable_globals_are_exclusive_and_persist() {
  let binary = compile_ebpf(
    br#"
      extern void wait_for_peer(void);
      volatile unsigned long long shared_name_but_private_state = 7;
      volatile unsigned long long *state_pointer = &shared_name_but_private_state;

      unsigned long long __attribute__((section("test")))
      entry(unsigned long long *input) {
        *state_pointer = *input;
        wait_for_peer();
        return *state_pointer;
      }

      unsigned long long __attribute__((section("initial")))
      read_initial(void) {
        return *state_pointer;
      }
    "#
    .to_vec(),
  )
  .await
  .unwrap();
  let (_, t_env) = gt_env();
  let loader = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[INTERLEAVING_HELPERS],
  );
  let prog = loader
    .load(&mut rand::thread_rng(), &binary)
    .unwrap()
    .pin_to_current_thread(t_env);

  let entered = Arc::new(Notify::new());
  let release = Arc::new(Notify::new());
  let mut gate_a = InterleavingGate {
    entered: Arc::clone(&entered),
    release: Arc::clone(&release),
  };
  let mut resources_a: [&mut dyn Any; 1] = [&mut gate_a];
  let input_a = 0xaaaa_u64.to_ne_bytes();
  let input_b = 0xbbbb_u64.to_ne_bytes();
  let preemption_a = PreemptionEnabled::new(prog.thread_env());
  let preemption_b = PreemptionEnabled::new(prog.thread_env());
  let timeslice = timeslice_config();
  let timeslicer = TokioTimeslicer;

  let (result_a, ()) = tokio::join!(
    prog.run_mut(
      &timeslice,
      &timeslicer,
      "test",
      &mut resources_a,
      &input_a,
      &preemption_a,
    ),
    async {
      entered.notified().await;
      assert!(matches!(
        prog
          .run_mut(
            &timeslice,
            &timeslicer,
            "test",
            &mut [],
            &input_b,
            &preemption_b,
          )
          .await,
        Err(Error(RuntimeError::ProgramBusy))
      ));
      assert!(matches!(
        prog
          .run(
            &timeslice,
            &timeslicer,
            "initial",
            &mut [],
            &[],
            &preemption_b,
          )
          .await,
        Err(Error(RuntimeError::ProgramBusy))
      ));
      release.notify_one();
    },
  );

  assert_eq!(result_a.unwrap(), 0xaaaa);

  let initial = prog
    .run(
      &timeslice,
      &timeslicer,
      "initial",
      &mut [],
      &[],
      &PreemptionEnabled::new(prog.thread_env()),
    )
    .await
    .unwrap();
  assert_eq!(initial, 0xaaaa);
}

#[tokio::test]
async fn cancelling_a_writable_run_restores_protection_before_unlocking() {
  let binary = compile_ebpf(
    br#"
      extern void wait_for_peer(void);
      volatile unsigned long long state = 7;

      unsigned long long __attribute__((section("hold"))) entry_hold(void) {
        wait_for_peer();
        state = 9;
        return state;
      }
      unsigned long long __attribute__((section("write"))) write_state(void) {
        state = 10;
        return state;
      }
    "#
    .to_vec(),
  )
  .await
  .unwrap();
  let (_, t_env) = gt_env();
  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[INTERLEAVING_HELPERS],
  )
  .load(&mut rand::thread_rng(), &binary)
  .unwrap()
  .pin_to_current_thread(t_env);
  let entered = Arc::new(Notify::new());
  let release = Arc::new(Notify::new());
  let mut gate = InterleavingGate {
    entered: Arc::clone(&entered),
    release,
  };
  let mut resources: [&mut dyn Any; 1] = [&mut gate];
  let timeslice = timeslice_config();
  let preemption = PreemptionEnabled::new(t_env);
  let mut run = Box::pin(program.run_mut(
    &timeslice,
    &TokioTimeslicer,
    "hold",
    &mut resources,
    &[],
    &preemption,
  ));
  tokio::select! {
    _ = entered.notified() => {}
    result = &mut run => panic!("writable run returned before suspension: {result:?}"),
  }
  drop(run);

  assert!(matches!(
    program
      .run(
        &timeslice,
        &TokioTimeslicer,
        "write",
        &mut [],
        &[],
        &preemption,
      )
      .await,
    Err(Error(RuntimeError::MemoryFault(_)))
  ));
  assert_eq!(
    program
      .run_mut(
        &timeslice,
        &TokioTimeslicer,
        "write",
        &mut [],
        &[],
        &preemption,
      )
      .await
      .unwrap(),
    10
  );
}

#[tokio::test]
async fn helpers_mutate_data_only_through_the_writable_entry() {
  let binary = compile_ebpf(
    br#"
      extern unsigned long long fill_user_memory(
        unsigned char *, unsigned long long, unsigned long long
      );
      volatile unsigned char global_buffer[2] = { 1, 2 };

      unsigned long long __attribute__((section("test"))) entry(void) {
        if (fill_user_memory((unsigned char *)global_buffer, 2, 0x5a) != 0) {
          return 0;
        }
        return global_buffer[0] | ((unsigned long long)global_buffer[1] << 8);
      }
    "#
    .to_vec(),
  )
  .await
  .unwrap();
  let (_, t_env) = gt_env();

  let writable = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[WRITABLE_DATA_HELPERS],
  )
  .load(&mut rand::thread_rng(), &binary)
  .unwrap()
  .pin_to_current_thread(t_env);
  let result = writable
    .run_mut(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut [],
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await
    .unwrap();
  assert_eq!(result, 0x5a5a);

  assert!(matches!(
    writable
      .run(
        &timeslice_config(),
        &TokioTimeslicer,
        "test",
        &mut [],
        &[],
        &PreemptionEnabled::new(t_env),
      )
      .await,
    Err(Error(RuntimeError::HelperError("fill_user_memory")))
  ));
}

#[tokio::test]
async fn mutable_data_and_rodata_keep_distinct_page_permissions() {
  let binary = compile_ebpf(
    br#"
      volatile unsigned long long state = 7;
      static const volatile unsigned long long frozen = 9;

      unsigned long long __attribute__((section("write_state"))) entry_write_state(void) {
        return ++state;
      }
      unsigned long long __attribute__((section("read"))) read_both(void) {
        return state + frozen;
      }
      unsigned long long __attribute__((section("write_frozen"))) entry_write_frozen(void) {
        *(volatile unsigned long long *)&frozen = 10;
        return frozen;
      }
    "#
    .to_vec(),
  )
  .await
  .unwrap();
  let (_, t_env) = gt_env();
  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .load(&mut rand::thread_rng(), &binary)
  .unwrap()
  .pin_to_current_thread(t_env);
  let timeslice = timeslice_config();
  let preemption = PreemptionEnabled::new(t_env);

  assert!(matches!(
    program
      .run(
        &timeslice,
        &TokioTimeslicer,
        "write_state",
        &mut [],
        &[],
        &preemption,
      )
      .await,
    Err(Error(RuntimeError::MemoryFault(_)))
  ));
  assert_eq!(
    program
      .run_mut(
        &timeslice,
        &TokioTimeslicer,
        "write_state",
        &mut [],
        &[],
        &preemption,
      )
      .await
      .unwrap(),
    8
  );
  assert_eq!(
    program
      .run(
        &timeslice,
        &TokioTimeslicer,
        "read",
        &mut [],
        &[],
        &preemption,
      )
      .await
      .unwrap(),
    17
  );
  assert!(matches!(
    program
      .run_mut(
        &timeslice,
        &TokioTimeslicer,
        "write_frozen",
        &mut [],
        &[],
        &preemption,
      )
      .await,
    Err(Error(RuntimeError::MemoryFault(_)))
  ));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_sync_and_async_call() {
  let ret = run_one_program(
    RunOpts::simple(vec![HELPERS], "test"),
    r#"
  extern int return_5(void);
  extern int return_7_async(void);
  int __attribute__((section("test"))) entry(void) {
    int a = return_5();
    int b = return_5();
    int c = return_5();
    int d = return_7_async();
    int e = return_7_async();
    return a + b + c + d + e;
  }
  "#,
  )
  .await
  .unwrap();
  assert_eq!(ret, 5 * 3 + 7 * 2);
}

#[tokio::test]
async fn an_async_completion_error_clears_the_active_jit_state() {
  let result = run_one_program(
    RunOpts::simple(vec![FAILING_ASYNC_HELPERS], "test"),
    r#"
    extern int fail_async(void);
    int __attribute__((section("test"))) entry(void) {
      return fail_async();
    }
    "#,
  )
  .await;

  assert!(result.is_err());
  assert!(crate::program::active_jit_state_is_clear_for_tests());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_calldata() {
  let v_100 = 100u64.to_le_bytes();

  let ret = run_one_program(
    RunOpts {
      helpers: vec![HELPERS],
      entrypoint: "test",
      calldata: &v_100,
      resources: &mut [],
      allow_dynamic_regions: false,
    },
    r#"
  unsigned long long __attribute__((section("test"))) entry(unsigned long long *input) {
    return *input + 1;
  }
  "#,
  )
  .await
  .unwrap();
  assert_eq!(ret, 101);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_noinline_local_function_calls() {
  let ret = run_one_program(
    RunOpts::simple(vec![], "test"),
    r#"
  static int __attribute__((noinline, section("test"))) add_seven(int x) {
    return x + 7;
  }

  static int __attribute__((noinline, section("test"))) twice_after_add(int x) {
    return add_seven(x) * 2;
  }

  int __attribute__((section("test"))) entry(void) {
    return twice_after_add(4);
  }
  "#,
  )
  .await
  .unwrap();
  assert_eq!(ret, 22);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_local_function_calls_across_elf_sections() {
  let (_, t_env) = gt_env();
  let binary = compile_ebpf(
    r#"
  static int add_eight(int x) __attribute__((noinline, section("late_leaf")));

  static int __attribute__((noinline, section("leaf"))) add_six(int x) {
    return x + 6;
  }

  static int __attribute__((noinline, section("leaf"))) add_seven(int x) {
    return add_six(x) + 1;
  }

  static int __attribute__((noinline, section("middle"))) twice_after_add(int x) {
    return add_seven(x) + add_eight(x);
  }

  int __attribute__((section("test"))) entry(void) {
    return twice_after_add(4);
  }

  static int add_eight(int x) {
    return x + 8;
  }
  "#
    .as_bytes()
    .to_vec(),
  )
  .await
  .unwrap();
  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .require_static_region_analysis(true)
  .load(&mut rand::thread_rng(), &binary)
  .unwrap()
  .pin_to_current_thread(t_env);
  let section_counts = program.section_instruction_counts_for_tests();
  assert_eq!(section_counts.len(), 4);
  assert!(section_counts.iter().sum::<usize>() > *section_counts.iter().max().unwrap());
  let ret = program
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut [],
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await
    .unwrap();
  assert_eq!(ret, 23);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_lazy_jit_compiles_entry_on_first_run() {
  let (_, t_env) = gt_env();
  let binary = compile_ebpf(
    r#"
  int __attribute__((section("test"))) entry(void) {
    return 42;
  }
  "#
    .as_bytes()
    .to_vec(),
  )
  .await
  .unwrap();
  let loader = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[&[]],
  )
  .require_static_region_analysis(true);
  let prog = loader
    .load(&mut rand::thread_rng(), &binary)
    .unwrap()
    .pin_to_current_thread(t_env);

  assert_eq!(prog.compiled_function_count_for_tests(), 0);
  assert_eq!(prog.code_arena_used_for_tests(), 0);

  let ret = prog
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut [],
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await
    .unwrap();
  assert_eq!(ret, 42);
  assert_eq!(prog.compiled_function_count_for_tests(), 1);
  let arena_used = prog.code_arena_used_for_tests();
  assert!(arena_used > 0);

  let ret = prog
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut [],
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await
    .unwrap();
  assert_eq!(ret, 42);
  assert_eq!(prog.compiled_function_count_for_tests(), 1);
  assert_eq!(prog.code_arena_used_for_tests(), arena_used);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_lazy_jit_compiles_local_functions_on_first_call() {
  let (_, t_env) = gt_env();
  let binary = compile_ebpf(
    r#"
  static int __attribute__((noinline, section("test"))) add_seven(int x) {
    return x + 7;
  }

  static int __attribute__((noinline, section("test"))) twice_after_add(int x) {
    return add_seven(x) * 2;
  }

  int __attribute__((section("test"))) entry(void) {
    return twice_after_add(4);
  }
  "#
    .as_bytes()
    .to_vec(),
  )
  .await
  .unwrap();
  let loader = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[&[]],
  )
  .require_static_region_analysis(true);
  let prog = loader
    .load(&mut rand::thread_rng(), &binary)
    .unwrap()
    .pin_to_current_thread(t_env);

  assert_eq!(prog.compiled_function_count_for_tests(), 0);

  let ret = prog
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut [],
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await
    .unwrap();
  assert_eq!(ret, 22);
  assert_eq!(prog.compiled_function_count_for_tests(), 3);
  let arena_used = prog.code_arena_used_for_tests();

  let ret = prog
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut [],
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await
    .unwrap();
  assert_eq!(ret, 22);
  assert_eq!(prog.compiled_function_count_for_tests(), 3);
  assert_eq!(prog.code_arena_used_for_tests(), arena_used);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_lazy_jit_specializes_callee_per_pointer_signature() {
  let (_, t_env) = gt_env();
  // `first_byte` is called once with a stack pointer and once with a read-only
  // data pointer. The two call sites produce different incoming pointer
  // signatures (R1 = foreign-stack vs R1 = data), so the callee is JIT-compiled
  // into two distinct specializations.
  let binary = compile_ebpf(
    r#"
  static int __attribute__((noinline, section("test"))) first_byte(const char *p) {
    return *p;
  }

  int __attribute__((section("test"))) entry(void) {
    char buf[8];
    buf[0] = 3;
    const char *ro = "Z";
    return first_byte(buf) + first_byte(ro);
  }
  "#
    .as_bytes()
    .to_vec(),
  )
  .await
  .unwrap();
  let loader = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[&[]],
  )
  .require_static_region_analysis(true);
  let prog = loader
    .load(&mut rand::thread_rng(), &binary)
    .unwrap()
    .pin_to_current_thread(t_env);

  let ret = prog
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut [],
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await
    .unwrap();
  assert_eq!(ret, 3 + 'Z' as i64);

  // Two source functions (`entry`, `first_byte`); `first_byte` is specialized
  // into two pointer-signature variants, so three native functions total.
  let variant_counts = prog.function_variant_counts_for_tests();
  assert_eq!(
    variant_counts.len(),
    2,
    "expected exactly two source functions, got {variant_counts:?}"
  );
  assert!(
    variant_counts.contains(&2),
    "expected one callee specialized into two variants, got {variant_counts:?}"
  );
  assert_eq!(prog.compiled_function_count_for_tests(), 3);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_fault_write_rodata() {
  let ret = run_one_program(
    RunOpts::simple(vec![HELPERS], "test"),
    r#"
  extern int return_5(const char *x);
  unsigned long long __attribute__((section("test"))) entry() {
    const char *rostr = "test";
    *(char *) rostr = 'a';
    return_5(rostr); // force side effect
    return 0;
  }
  "#,
  )
  .await;
  assert!(matches!(ret, Err(Error(RuntimeError::MemoryFault(_)))));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_read_rodata_via_data_region() {
  // A volatile read of a constant compiles to a load whose pointer is a
  // relocated data-section address. The region analysis routes it to the data
  // region, exercising the branchless single-region (data) JIT path.
  let ret = run_one_program(
    RunOpts::simple(vec![], "test"),
    r#"
  unsigned long long __attribute__((section("test"))) entry(void) {
    static const volatile char msg[] = "ABCD";
    return (unsigned char) msg[0] + (unsigned char) msg[3];
  }
  "#,
  )
  .await
  .unwrap();
  assert_eq!(ret, ('A' as i64) + ('D' as i64));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_fault_read_past_stack() {
  let ret = run_one_program(
    RunOpts::simple(vec![HELPERS], "test"),
    r#"
  unsigned long long __attribute__((section("test"))) entry(unsigned long long *bad) {
    return *bad;
  }
  "#,
  )
  .await;
  assert!(matches!(ret, Err(Error(RuntimeError::MemoryFault(_)))));
}

#[cfg(target_os = "openbsd")]
#[tokio::test]
async fn test_openbsd_repeated_memory_fault_stress() {
  const ITERATIONS: usize = 512;

  let (_, thread) = gt_env();
  let binary = compile_ebpf(
    r#"
  unsigned long long __attribute__((section("test"))) entry(unsigned long long *bad) {
    return *bad;
  }
  "#
    .as_bytes()
    .to_vec(),
  )
  .await
  .unwrap();
  let program = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .load(&mut rand::thread_rng(), &binary)
  .unwrap()
  .pin_to_current_thread(thread);
  let preemption = PreemptionEnabled::new(thread);

  for iteration in 0..ITERATIONS {
    let ret = program
      .run(
        &timeslice_config(),
        &TokioTimeslicer,
        "test",
        &mut [],
        &[],
        &preemption,
      )
      .await;
    assert!(
      matches!(ret, Err(Error(RuntimeError::MemoryFault(_)))),
      "stress iteration {iteration} returned {ret:?}"
    );
  }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_fault_write_past_stack() {
  let ret = run_one_program(
    RunOpts::simple(vec![HELPERS], "test"),
    r#"
  unsigned long long __attribute__((section("test"))) entry(unsigned long long *bad) {
    *bad = 1;
    return 0;
  }
  "#,
  )
  .await;
  assert!(matches!(ret, Err(Error(RuntimeError::MemoryFault(_)))));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_fault_read_null_ptr() {
  // This program dereferences a helper-returned pointer, whose region cannot be
  // determined statically, so it opts out of strict region analysis.
  let mut opts = RunOpts::simple(vec![HELPERS], "test");
  opts.allow_dynamic_regions = true;
  let ret = run_one_program(
    opts,
    r#"
  extern char * return_5(void);
  unsigned long long __attribute__((section("test"))) entry(unsigned long long *bad) {
    char *p = return_5() - 5;
    return *p;
  }
  "#,
  )
  .await;
  assert!(matches!(ret, Err(Error(RuntimeError::MemoryFault(_)))));
}

/// Asserts that executing `code` under the default (strict) region analysis is
/// rejected because some access cannot be routed to a single region for the
/// concrete function specialization being compiled.
fn assert_static_region_rejected(ret: Result<i64, Error>) {
  match ret {
    Err(Error(RuntimeError::InvalidArgumentOwned(msg)))
      if msg.contains("static region analysis") => {}
    other => panic!("expected static region rejection, got {other:?}"),
  }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_strict_region_validation_is_deferred_until_execution() {
  let (_, t_env) = gt_env();
  let binary = compile_ebpf(
    r#"
  extern char *return_5(void);
  unsigned long long __attribute__((section("test"))) entry(void) {
    char *p = return_5();
    return *p;
  }
  "#
    .as_bytes()
    .to_vec(),
  )
  .await
  .unwrap();
  let loader = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[HELPERS],
  )
  .require_static_region_analysis(true);
  let prog = loader
    .load(&mut rand::thread_rng(), &binary)
    .unwrap()
    .pin_to_current_thread(t_env);

  assert_eq!(prog.compiled_function_count_for_tests(), 0);
  assert_eq!(prog.failed_function_count_for_tests(), 0);
  assert_eq!(prog.function_compile_attempt_count_for_tests(), 0);
  let ret = prog
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut [],
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await;
  assert_static_region_rejected(ret);
  assert_eq!(prog.compiled_function_count_for_tests(), 0);
  assert_eq!(prog.failed_function_count_for_tests(), 1);
  assert_eq!(prog.function_compile_attempt_count_for_tests(), 1);
  assert_eq!(prog.code_arena_used_for_tests(), 0);

  let ret = prog
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut [],
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await;
  assert_static_region_rejected(ret);
  assert_eq!(prog.compiled_function_count_for_tests(), 0);
  assert_eq!(prog.failed_function_count_for_tests(), 1);
  assert_eq!(prog.function_compile_attempt_count_for_tests(), 1);
  assert_eq!(prog.code_arena_used_for_tests(), 0);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_reject_helper_returned_pointer() {
  // The pointer comes from a helper return value, whose region is unknown.
  let code = r#"
  extern char *return_5(void);
  unsigned long long __attribute__((section("test"))) entry(void) {
    char *p = return_5();
    return *p;
  }
  "#;
  assert_static_region_rejected(
    run_one_program(RunOpts::simple(vec![HELPERS], "test"), code).await,
  );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_reject_pointer_loaded_from_memory() {
  // `**pp` first loads a pointer out of memory (region not tracked through
  // memory), then dereferences it — the inner deref is unroutable. The same
  // program loads and faults at runtime once strict analysis is disabled,
  // confirming the lazy strict-region rejection is the gate, not a bad program.
  let code = r#"
  unsigned long long __attribute__((section("test"))) entry(unsigned long long **pp) {
    return **pp;
  }
  "#;
  assert_static_region_rejected(run_one_program(RunOpts::simple(vec![], "test"), code).await);

  let mut opts = RunOpts::simple(vec![], "test");
  opts.allow_dynamic_regions = true;
  let dynamic = run_one_program(opts, code).await;
  assert!(
    matches!(dynamic, Err(Error(RuntimeError::MemoryFault(_)))),
    "expected runtime fault when opted out, got {dynamic:?}"
  );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_reject_pointer_selected_across_regions() {
  // A pointer that is a stack address on one path and a data address on the
  // other joins to an ambiguous region, so the dereference is unroutable.
  let idx = 1u64.to_le_bytes();
  let code = r#"
  unsigned long long __attribute__((section("test"))) entry(unsigned long long *sel) {
    static const volatile char msg[] = "ABCD";
    char stackbuf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const char *p = (*sel) ? (const char *) msg : (const char *) stackbuf;
    return p[0];
  }
  "#;
  let ret = run_one_program(
    RunOpts {
      helpers: vec![],
      entrypoint: "test",
      calldata: &idx,
      resources: &mut [],
      allow_dynamic_regions: false,
    },
    code,
  )
  .await;
  assert_static_region_rejected(ret);
}

fn h_return_5(_: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
  Ok(5)
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
    tokio::time::sleep(Duration::from_millis(5)).await;
    |_: &HelperScope| Ok(7)
  });
  Ok(0)
}

fn h_fail_async(scope: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
  fn fail(_: &HelperScope) -> Result<u64, ()> {
    Err(())
  }
  scope.post_task(async { fail });
  Ok(0)
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_custom_code_size_limit() {
  use crate::program::{DummyProgramEventListener, PreemptionEnabled, ProgramLoader};
  use crate::test_util::compile_ebpf;
  use std::sync::Arc;

  let (_, t_env) = gt_env();
  let binary = compile_ebpf(
    br#"
  int __attribute__((section("test"))) entry(void) {
    return 42;
  }
  "#
    .to_vec(),
  )
  .await
  .unwrap();

  let loader = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_code_size_limit(64 * 1024);
  let prog = loader
    .load(&mut rand::thread_rng(), &binary)
    .unwrap()
    .pin_to_current_thread(t_env);
  let ret = prog
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut [],
      &[],
      &PreemptionEnabled::new(t_env),
    )
    .await
    .unwrap();
  assert_eq!(ret, 42);
}

#[test]
#[should_panic(expected = "multiple of 64 KiB")]
fn test_invalid_code_size_limit() {
  use crate::program::{DummyProgramEventListener, ProgramLoader};
  use std::sync::Arc;

  let _ = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_code_size_limit(4096);
}

#[test]
#[should_panic(expected = "stack frame size must be a non-zero multiple of 16")]
fn test_invalid_stack_frame_size() {
  let _ = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_stack_frame_size(24);
}

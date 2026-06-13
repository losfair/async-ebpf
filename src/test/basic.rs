use std::time::Duration;

use crate::{
  error::{Error, RuntimeError},
  helpers::Helper,
  program::HelperScope,
  test_util::{run_one_program, RunOpts},
};

static HELPERS: &'static [(&'static str, Helper)] = &[
  ("return_5", h_return_5),
  ("return_7_async", h_return_7_async),
];

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

/// Asserts that loading `code` under the default (strict) region analysis is
/// rejected because some access cannot be routed to a single region.
fn assert_static_region_rejected(ret: Result<i64, Error>) {
  match ret {
    Err(Error(RuntimeError::InvalidArgumentOwned(msg))) if msg.contains("static region analysis") => {}
    other => panic!("expected static region rejection, got {other:?}"),
  }
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
  assert_static_region_rejected(run_one_program(RunOpts::simple(vec![HELPERS], "test"), code).await);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_reject_pointer_loaded_from_memory() {
  // `**pp` first loads a pointer out of memory (region not tracked through
  // memory), then dereferences it — the inner deref is unroutable. The same
  // program loads and faults at runtime once strict analysis is disabled,
  // confirming the load-time rejection is the strict gate, not a bad program.
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

#[tokio::test]
#[tracing_test::traced_test]
async fn test_custom_code_size_limit() {
  use crate::program::{DummyProgramEventListener, ProgramLoader};
  use crate::test_util::compile_ebpf;
  use std::sync::Arc;

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
  loader.load(&mut rand::thread_rng(), &binary).unwrap();
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

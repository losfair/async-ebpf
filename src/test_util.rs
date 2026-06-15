use std::{any::Any, process::Stdio, sync::Arc, time::Duration};

use futures::Future;
use tokio::{io::AsyncWriteExt, process::Command};

use crate::{
  error::Error,
  helpers::Helper,
  program::{
    DummyProgramEventListener, GlobalEnv, PreemptionEnabled, ProgramLoader, ThreadEnv,
    TimesliceConfig, Timeslicer,
  },
};

/// `Timeslicer` implementation backed by Tokio.
pub struct TokioTimeslicer;

impl Timeslicer for TokioTimeslicer {
  fn sleep(&self, duration: Duration) -> impl Future<Output = ()> {
    tokio::time::sleep(duration)
  }

  fn yield_now(&self) -> impl Future<Output = ()> {
    tokio::task::yield_now()
  }
}

/// Compiles C source to an eBPF ELF object using LLVM tools.
pub async fn compile_ebpf(src: Vec<u8>) -> anyhow::Result<Vec<u8>> {
  let mut clang = Command::new("clang")
    .arg("-target")
    .arg("bpf")
    .arg("-emit-llvm")
    .arg("-c")
    .arg("-x")
    .arg("c")
    .arg("-")
    .arg("-o")
    .arg("-")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()?;
  let mut clang_stdin = clang.stdin.take().unwrap();
  tokio::spawn(async move {
    let _ = clang_stdin.write_all(&src).await;
  });

  let mut llvm_link = Command::new("llvm-link")
    .arg("-o")
    .arg("-")
    .arg("-")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()?;
  let mut clang_stdout = clang.stdout.take().unwrap();
  let mut llvm_link_stdin = llvm_link.stdin.take().unwrap();
  tokio::spawn(async move {
    let _ = tokio::io::copy(&mut clang_stdout, &mut llvm_link_stdin).await;
  });

  let mut opt = Command::new("opt")
    .arg("-O2")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()?;
  let mut llvm_link_stdout = llvm_link.stdout.take().unwrap();
  let mut opt_stdin = opt.stdin.take().unwrap();
  tokio::spawn(async move {
    let _ = tokio::io::copy(&mut llvm_link_stdout, &mut opt_stdin).await;
  });

  let mut llc = Command::new("llc")
    .arg("-march=bpf")
    .arg("-bpf-stack-size=4096")
    .arg("-mcpu=v3")
    .arg("-filetype=obj")
    .arg("-o")
    .arg("-")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()?;
  let mut opt_stdout = opt.stdout.take().unwrap();
  let mut llc_stdin = llc.stdin.take().unwrap();
  tokio::spawn(async move {
    let _ = tokio::io::copy(&mut opt_stdout, &mut llc_stdin).await;
  });

  let mut llvm_objcopy = Command::new("llvm-objcopy")
    .arg("--remove-section")
    .arg(".text")
    .arg("-")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()?;
  let mut llc_stdout = llc.stdout.take().unwrap();
  let mut llvm_objcopy_stdin = llvm_objcopy.stdin.take().unwrap();
  tokio::spawn(async move {
    let _ = tokio::io::copy(&mut llc_stdout, &mut llvm_objcopy_stdin).await;
  });

  let (clang_out, llvm_link_out, opt_out, llc_out, output) = tokio::join!(
    clang.wait(),
    llvm_link.wait(),
    opt.wait(),
    llc.wait(),
    llvm_objcopy.wait_with_output()
  );
  let output = output?;
  let exit_status_list = [
    clang_out?,
    llvm_link_out?,
    opt_out?,
    llc_out?,
    output.status,
  ];
  if exit_status_list.iter().any(|x| !x.success()) {
    anyhow::bail!("one or more commands failed");
  }

  Ok(output.stdout)
}

/// Creates a default global and thread environment for tests.
pub fn gt_env() -> (GlobalEnv, ThreadEnv) {
  let g = unsafe { GlobalEnv::new() };
  let t = g.init_thread(Duration::from_millis(10));
  (g, t)
}

/// Returns a timeslice configuration suitable for tests.
pub fn timeslice_config() -> TimesliceConfig {
  TimesliceConfig {
    max_run_time_before_throttle: Duration::from_secs(10),
    max_run_time_before_yield: Duration::from_millis(5),
    throttle_duration: Duration::from_millis(1),
  }
}

/// Options for running a single program in tests.
pub struct RunOpts<'a, 'b> {
  /// Helper tables to register with the loader.
  pub helpers: Vec<&'static [(&'static str, Helper)]>,
  /// Entrypoint name to invoke.
  pub entrypoint: &'a str,
  /// Calldata passed to the program.
  pub calldata: &'a [u8],
  /// Host resources exposed to helpers.
  pub resources: &'a mut [&'b mut dyn Any],
  /// Opt out of strict region analysis, which the test harness requires by
  /// default. Used by tests that intentionally exercise an access pattern that
  /// cannot be statically routed to a single region.
  pub allow_dynamic_regions: bool,
}

impl<'a, 'b> RunOpts<'a, 'b> {
  /// Creates options with no calldata or resources.
  pub fn simple(helpers: Vec<&'static [(&'static str, Helper)]>, entrypoint: &'a str) -> Self {
    Self {
      helpers,
      entrypoint,
      calldata: &[],
      resources: &mut [],
      allow_dynamic_regions: false,
    }
  }
}

/// Compiles and runs a single program, returning its result.
pub async fn run_one_program(opts: RunOpts<'_, '_>, code: &str) -> Result<i64, Error> {
  let (_, t_env) = gt_env();

  let binary = compile_ebpf(code.as_bytes().to_vec()).await.unwrap();
  let helpers = opts.helpers;
  // Strict region analysis is required by default; tests may opt out for
  // intentionally unanalyzable access patterns.
  let require_static_regions = !opts.allow_dynamic_regions;

  // ensure the Send trait bound works
  let prog = tokio::task::spawn_blocking(move || {
    let loader = ProgramLoader::new(
      &mut rand::thread_rng(),
      Arc::new(DummyProgramEventListener),
      &helpers,
    )
    .require_static_region_analysis(require_static_regions);
    loader.load(&mut rand::thread_rng(), &binary)
  })
  .await
  .unwrap()?;

  let prog = prog.pin_to_current_thread(t_env);
  prog
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      opts.entrypoint,
      opts.resources,
      opts.calldata,
      &PreemptionEnabled::new(t_env),
    )
    .await
}

/// Testing-only accessors for fuzzing the static region analyzer.
///
/// This module is intentionally gated behind the `testing` feature through
/// `test_util`; it is not part of the runtime's stable public API.
pub mod region_analysis {
  use crate::region_analysis::{
    self as analyzer, PointerSignature, RegKind, StackKind, REGION_DATA, REGION_STACK,
    REGION_UNKNOWN,
  };

  /// Number of eBPF general-purpose registers modeled by the analyzer.
  pub const NUM_REGS: usize = 11;
  /// Unknown/unroutable memory region.
  pub const UNKNOWN: u8 = REGION_UNKNOWN;
  /// Guest stack memory region.
  pub const STACK: u8 = REGION_STACK;
  /// Read-only data memory region.
  pub const DATA: u8 = REGION_DATA;

  /// Register provenance tag used to build fuzz-time function signatures.
  #[derive(Clone, Copy, Debug)]
  pub enum PointerTag {
    /// No information is known for this register.
    Uninit,
    /// Pointer into the current eBPF stack frame, with a known frame offset.
    CurrentStack(i32),
    /// Pointer into the current eBPF stack frame, with an unknown frame offset.
    CurrentStackUnknown,
    /// Pointer into a caller/ancestor eBPF stack frame.
    ForeignStack,
    /// Pointer into the relocated read-only data region.
    Data,
    /// Non-pointer scalar value.
    Scalar,
    /// Conflicting or otherwise unroutable value.
    Unknown,
  }

  /// Opaque region-analysis function signature.
  #[derive(Clone, Copy)]
  pub struct FunctionSignature(PointerSignature);

  /// Result returned by the whole-section analyzer.
  pub struct SectionAnalysis {
    /// Per-instruction-slot load region hint.
    pub hints: Vec<u8>,
    /// Memory-access slots that could not be statically routed.
    pub unresolved: Vec<usize>,
  }

  /// Result returned by the per-function analyzer.
  pub struct FunctionAnalysis {
    /// Per-instruction-slot load region hint.
    pub hints: Vec<u8>,
    /// Memory-access slots that could not be statically routed.
    pub unresolved: Vec<usize>,
    /// Local-call sites and the pointer signature inferred for the callee.
    pub call_signatures: Vec<(usize, FunctionSignature)>,
  }

  /// Entry function signature used by normal program invocations.
  pub fn entry_signature() -> FunctionSignature {
    FunctionSignature(PointerSignature::entry())
  }

  /// Builds a signature from explicit per-register provenance tags.
  pub fn signature_from_tags(tags: [PointerTag; NUM_REGS]) -> FunctionSignature {
    let mut regs = [RegKind::Uninit; NUM_REGS];
    for (index, tag) in tags.into_iter().enumerate() {
      regs[index] = match tag {
        PointerTag::Uninit => RegKind::Uninit,
        PointerTag::CurrentStack(offset) => RegKind::Stack(StackKind::Current(Some(offset))),
        PointerTag::CurrentStackUnknown => RegKind::Stack(StackKind::Current(None)),
        PointerTag::ForeignStack => RegKind::Stack(StackKind::Foreign),
        PointerTag::Data => RegKind::Data,
        PointerTag::Scalar => RegKind::Scalar,
        PointerTag::Unknown => RegKind::Unknown,
      };
    }
    FunctionSignature(PointerSignature::from_regs_for_testing(regs))
  }

  /// Runs whole-section static region analysis.
  pub fn analyze_section(code: &[u8], data_lo: u64, data_hi: u64) -> SectionAnalysis {
    let result = analyzer::analyze(code, data_lo, data_hi);
    SectionAnalysis {
      hints: result.hints,
      unresolved: result.unresolved,
    }
  }

  /// Runs per-function static region analysis.
  pub fn analyze_function(
    code: &[u8],
    start_pc: usize,
    end_pc: usize,
    signature: FunctionSignature,
    data_lo: u64,
    data_hi: u64,
  ) -> FunctionAnalysis {
    let result = analyzer::analyze_function(code, start_pc, end_pc, signature.0, data_lo, data_hi);
    let mut call_signatures: Vec<_> = result
      .call_signatures
      .into_iter()
      .map(|(pc, sig)| (pc, FunctionSignature(sig)))
      .collect();
    call_signatures.sort_by_key(|(pc, _)| *pc);
    FunctionAnalysis {
      hints: result.hints,
      unresolved: result.unresolved,
      call_signatures,
    }
  }
}

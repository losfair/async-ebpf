//! Regression tests for the signal-machinery findings from the audit.
//!
//! 1. Fault containment was single-shot: `chain_to_previous_fault_handler`
//!    permanently replaced this crate's SIGSEGV/SIGBUS disposition with the
//!    previous one via `sigaction`, so the first foreign fault uninstalled
//!    containment and a later guest fault that should have surfaced as a
//!    `MemoryFault` reached the displaced disposition and aborted the
//!    process. The previous handler is now invoked directly, keeping this
//!    crate's handler installed.
//! 2. Preemption is signal-only, so a run thread with SIGUSR1 blocked (from
//!    the embedder or a library) silently made every guest spin a permanent
//!    wedge — the watcher's signals pend and the run budget's fast path
//!    never trips. And the dispatch loop's unconditional SIG_UNBLOCK
//!    permanently cleared whatever blocking an embedder had deliberately
//!    placed on SIGUSR1/SIGSEGV/SIGBUS after the first guest fault (the
//!    fault path drops the coroutine without resuming it, so the kernel's
//!    `rt_sigreturn` never restores the mask). The run path now refuses to
//!    start — and to resume — while SIGUSR1 is blocked, and restores the
//!    exact pre-signal mask instead of unblocking.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::Duration;

use crate::{
  error::{Error, RuntimeError},
  test::raw_elf::{run_raw, run_raw_with_helpers, Insn},
};

/// A statically stack-routed store whose derived address is outside every
/// supported default stack layout.
///
/// A direct `R10 - 4097` access faults in the guarded 4 KiB-frame layout, but
/// it is still inside the contiguous fallback used when the host page is larger
/// than a frame (notably macOS/aarch64's 16 KiB pages). Deriving the address in
/// a register gives us the wider immediate needed to get past the entire stack
/// on every platform while retaining a valid stack-region hint.
fn guest_fault_program() -> Vec<Insn> {
  vec![
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, -1_000_000),
    Insn::stx_dw(1, 0, 0),
    Insn::exit(),
  ]
}

/// Blocks `signum` on the current thread while alive; unblocks it on drop.
struct SignalBlockGuard(libc::c_int);

impl SignalBlockGuard {
  fn new(signum: libc::c_int) -> Self {
    unsafe {
      let mut set: libc::sigset_t = std::mem::zeroed();
      libc::sigemptyset(&mut set);
      libc::sigaddset(&mut set, signum);
      assert_eq!(
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
        0
      );
    }
    Self(signum)
  }

  /// Unblocks on drop without having blocked at construction — for signals an
  /// embedder helper blocked mid-test.
  fn unblock_on_drop(signum: libc::c_int) -> Self {
    Self(signum)
  }

  fn is_blocked(&self) -> bool {
    unsafe {
      let mut current: libc::sigset_t = std::mem::zeroed();
      assert_eq!(
        libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut current),
        0
      );
      libc::sigismember(&current, self.0) == 1
    }
  }
}

impl Drop for SignalBlockGuard {
  fn drop(&mut self) {
    unsafe {
      let mut set: libc::sigset_t = std::mem::zeroed();
      libc::sigemptyset(&mut set);
      libc::sigaddset(&mut set, self.0);
      libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
    }
  }
}

/// The run path must refuse a thread whose SIGUSR1 is blocked, the same way
/// it refuses a stopped watcher — a blocked preemption signal makes every
/// guest spin a permanent wedge, and nothing in the run loop can observe the
/// failure once the guest is inside `resume`.
#[tokio::test]
async fn a_run_with_sigusr1_blocked_is_refused() {
  let guard = SignalBlockGuard::new(libc::SIGUSR1);
  let code = vec![Insn::mov64_imm(0, 1), Insn::exit()];
  let result = run_raw(&code, &[], &[], false).await;
  drop(guard);

  assert!(
    matches!(result, Err(Error(RuntimeError::PlatformError(msg))) if msg.contains("SIGUSR1")),
    "a run on a thread with SIGUSR1 blocked must be refused, got {result:?}"
  );
}

/// A guest memory fault must leave an embedder's deliberate signal blocking
/// intact: the dispatch loop restores the exact pre-signal mask instead of
/// unconditionally unblocking SIGUSR1/SIGSEGV/SIGBUS.
#[tokio::test]
async fn embedder_signal_blocks_survive_a_guest_fault() {
  let guard = SignalBlockGuard::new(libc::SIGBUS);
  let code = guest_fault_program();
  let result = run_raw(&code, &[], &[], false).await;
  let still_blocked = guard.is_blocked();
  drop(guard);

  assert!(
    matches!(result, Err(Error(RuntimeError::MemoryFault(_)))),
    "the out-of-frame store must surface as a contained guest fault, got {result:?}"
  );
  assert!(
    still_blocked,
    "an embedder's SIGBUS block must survive a guest fault; the dispatch loop \
     must restore the pre-signal mask, not unconditionally unblock"
  );
}

/// An embedder helper that blocks SIGUSR1 while the guest is suspended must
/// stop the run at the next dispatch, so a subsequent guest spin cannot wedge
/// the thread.
#[tokio::test]
async fn a_helper_that_blocks_sigusr1_stops_the_run() {
  let _unblock = SignalBlockGuard::unblock_on_drop(libc::SIGUSR1);
  let helper: crate::helpers::Helper = |_scope, _a1, _a2, _a3, _a4, _a5| {
    unsafe {
      let mut set: libc::sigset_t = std::mem::zeroed();
      libc::sigemptyset(&mut set);
      libc::sigaddset(&mut set, libc::SIGUSR1);
      libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    Ok(0)
  };
  // The check has to sit at the resume boundary: after this helper returns,
  // even a plain `exit` must not receive control with preemption blocked. A
  // second helper would hide a misplaced post-resume check by yielding again.
  let code = vec![Insn::call_helper(), Insn::exit()];
  let result = run_raw_with_helpers(&code, &[], &[], false, &[&[("h", helper)]]).await;

  assert!(
    matches!(result, Err(Error(RuntimeError::PlatformError(msg))) if msg.contains("SIGUSR1")),
    "a helper that blocks SIGUSR1 must stop the run at the next dispatch, got {result:?}"
  );
}

/// The fault-containment regression, run in a child process: the recovering
/// previous handler has to be installed *before* `GlobalEnv::new` captures
/// it, which a process where other tests have already initialized can no
/// longer do (the `Once`). The child installs a probe handler that skips the
/// faulting instruction, then checks that a later guest fault is still
/// contained.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const CHILD_ENV: &str = "ASYNC_EBPF_FAULT_CONTAINMENT_CHILD";

#[cfg(any(target_os = "linux", target_os = "macos"))]
static PREVIOUS_MASK_WAS_HONOURED: AtomicBool = AtomicBool::new(false);
#[cfg(any(target_os = "linux", target_os = "macos"))]
static PREVIOUS_USED_ALTSTACK: AtomicBool = AtomicBool::new(false);
#[cfg(any(target_os = "linux", target_os = "macos"))]
static ALTSTACK_BOTTOM: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(target_os = "linux", target_os = "macos"))]
static ALTSTACK_TOP: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn fault_containment_survives_a_foreign_fault() {
  if std::env::var(CHILD_ENV).is_ok() {
    fault_containment_child().await;
    return;
  }

  let child = tokio::process::Command::new(std::env::current_exe().unwrap())
    .args([
      "--exact",
      "test::signal_safety::fault_containment_survives_a_foreign_fault",
      // The marker is printed from the test body; without this the harness
      // swallows captured output on success.
      "--nocapture",
    ])
    .env(CHILD_ENV, "1")
    .kill_on_drop(true)
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()
    .unwrap();

  let output = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
    .await
    .expect("the fault-containment child hung (a foreign fault wedged or looped the child?)")
    .expect("failed to read the fault-containment child's output");
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(
    output.status.success() && stdout.contains("FOREIGN_FAULT_CONTAINED"),
    "the fault-containment child did not contain a post-foreign-fault guest fault:\n\
     status: {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
    output.status
  );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn fault_containment_child() {
  // The saved disposition asks the kernel for a custom mask, SA_NODEFER, and
  // an alternate stack. Direct chaining must preserve those parts of
  // sigaction's contract even though this runtime's dispatcher stays installed.
  let mut altstack = vec![0u8; libc::SIGSTKSZ as usize * 2];
  ALTSTACK_BOTTOM.store(altstack.as_mut_ptr() as usize, Ordering::SeqCst);
  ALTSTACK_TOP.store(
    altstack.as_mut_ptr() as usize + altstack.len(),
    Ordering::SeqCst,
  );
  let stack = libc::stack_t {
    ss_sp: altstack.as_mut_ptr().cast(),
    ss_flags: 0,
    ss_size: altstack.len(),
  };
  let mut old_stack: libc::stack_t = unsafe { std::mem::zeroed() };
  unsafe {
    assert_eq!(
      libc::sigaltstack(&stack, &mut old_stack),
      0,
      "failed to install the probe alternate stack"
    );
  }

  // A recovering previous handler that returns from a user-generated foreign
  // SIGSEGV. It must be installed before `GlobalEnv::new` captures the previous
  // disposition. Using `raise` exercises the same chaining path without
  // hard-coding the length of a faulting instruction in each host ISA.
  let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
  act.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
  act.sa_sigaction = fixup_handler as *const () as usize;
  unsafe {
    libc::sigemptyset(&mut act.sa_mask);
    libc::sigaddset(&mut act.sa_mask, libc::SIGUSR2);
    assert_eq!(
      libc::sigaction(libc::SIGSEGV, &act, std::ptr::null_mut()),
      0,
      "failed to install the probe handler"
    );
  }

  // `GlobalEnv::new` captures the probe as the previous SIGSEGV disposition;
  // `init_thread` initializes every TLS slot the signal handlers touch (a
  // signal must never trigger lazy TLS initialization).
  let _env = crate::test_util::gt_env();

  // A foreign signal delivered outside any JIT code range, so the runtime
  // hands it to the probe and keeps its own handler installed.
  unsafe {
    assert_eq!(libc::raise(libc::SIGSEGV), 0, "failed to raise SIGSEGV");
  }

  // A guest fault must still be contained: the runtime's own handler is still
  // the SIGSEGV disposition, so the out-of-stack store surfaces as a
  // `MemoryFault` instead of reaching the returning probe and re-executing the
  // same fault forever.
  let code = guest_fault_program();
  let result = run_raw(&code, &[], &[], false).await;
  unsafe {
    assert_eq!(
      libc::sigaltstack(&old_stack, std::ptr::null_mut()),
      0,
      "failed to restore the previous alternate stack"
    );
  }
  match result {
    Err(Error(RuntimeError::MemoryFault(_)))
      if PREVIOUS_MASK_WAS_HONOURED.load(Ordering::SeqCst)
        && PREVIOUS_USED_ALTSTACK.load(Ordering::SeqCst) =>
    {
      println!("FOREIGN_FAULT_CONTAINED")
    }
    other => {
      eprintln!(
        "unexpected child result: {other:?}; mask honoured: {}; used altstack: {}",
        PREVIOUS_MASK_WAS_HONOURED.load(Ordering::SeqCst),
        PREVIOUS_USED_ALTSTACK.load(Ordering::SeqCst)
      );
      std::process::exit(1);
    }
  }
}

/// Records the execution contract seen by the previous handler and returns.
#[cfg(any(target_os = "linux", target_os = "macos"))]
extern "C" fn fixup_handler(
  _sig: libc::c_int,
  _siginfo: *mut libc::siginfo_t,
  _uctx: *mut libc::ucontext_t,
) {
  unsafe {
    let mut current: libc::sigset_t = std::mem::zeroed();
    if libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut current) == 0
      && libc::sigismember(&current, libc::SIGUSR2) == 1
      && libc::sigismember(&current, libc::SIGSEGV) == 0
    {
      PREVIOUS_MASK_WAS_HONOURED.store(true, Ordering::SeqCst);
    }
    let stack_probe = 0u8;
    let stack_addr = &stack_probe as *const u8 as usize;
    if stack_addr >= ALTSTACK_BOTTOM.load(Ordering::SeqCst)
      && stack_addr < ALTSTACK_TOP.load(Ordering::SeqCst)
    {
      PREVIOUS_USED_ALTSTACK.store(true, Ordering::SeqCst);
    }
  }
}

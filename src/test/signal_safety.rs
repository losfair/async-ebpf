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

use std::time::Duration;

use crate::{
  error::{Error, RuntimeError},
  test::raw_elf::{run_raw, run_raw_with_helpers, Insn},
};

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
  let code = vec![Insn::stx_dw(10, 0, -4097), Insn::exit()];
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
  // The first call blocks SIGUSR1; the second call's dispatch must refuse the
  // resume (a plain `exit` breaks out of the loop before the re-check).
  let code = vec![Insn::call_helper(), Insn::call_helper(), Insn::exit()];
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
const CHILD_ENV: &str = "ASYNC_EBPF_FAULT_CONTAINMENT_CHILD";

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn fault_containment_survives_a_foreign_fault() {
  if std::env::var(CHILD_ENV).is_ok() {
    fault_containment_child().await;
    return;
  }

  let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
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
  // A "recovering" previous handler, libsigsegv style: skip the faulting
  // instruction in the interrupted context and return. Must be installed
  // before `GlobalEnv::new` captures the previous disposition.
  let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
  act.sa_flags = libc::SA_SIGINFO;
  act.sa_sigaction = fixup_handler as *const () as usize;
  unsafe {
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

  // A foreign fault: the faulting PC is outside any JIT code range, so the
  // runtime hands it to the probe, which skips the faulting instruction.
  // The runtime's own handler must stay installed.
  unsafe {
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!("mov rax, qword ptr [1]", out("rax") _, options(nostack));
    #[cfg(target_arch = "aarch64")]
    core::arch::asm!(
      "mov x1, 1; ldr x0, [x1]",
      lateout("x0") _,
      lateout("x1") _,
      options(nostack)
    );
  }

  // A guest fault must still be contained: the runtime's own handler is still
  // the SIGSEGV disposition, so the out-of-frame store surfaces as a
  // `MemoryFault` instead of reaching the probe (which would not recognize
  // the address and could only mis-skip the JIT instruction).
  let code = vec![Insn::stx_dw(10, 0, -4097), Insn::exit()];
  let result = run_raw(&code, &[], &[], false).await;
  match result {
    Err(Error(RuntimeError::MemoryFault(_))) => println!("FOREIGN_FAULT_CONTAINED"),
    other => {
      eprintln!("unexpected child result: {other:?}");
      std::process::exit(1);
    }
  }
}

/// Skips the faulting instruction in the interrupted context and returns.
/// The faulting sequence is `mov rax, qword ptr [1]` (8 bytes) on x86_64 and
/// `ldr x0, [x1]` (4 bytes, fixed width) on aarch64 — the stride matches the
/// instruction the child faults on, so the thread continues exactly after it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
extern "C" fn fixup_handler(
  _sig: libc::c_int,
  _siginfo: *mut libc::siginfo_t,
  uctx: *mut libc::ucontext_t,
) {
  unsafe {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
      let rip = &mut (*uctx).uc_mcontext.gregs[libc::REG_RIP as usize];
      *rip += 8;
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
      (*(*uctx).uc_mcontext).__ss.__rip += 8;
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
      (*uctx).uc_mcontext.pc += 4;
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
      (*(*uctx).uc_mcontext).__ss.__pc += 4;
    }
  }
}

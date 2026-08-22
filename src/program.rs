//! This module contains the core logic for eBPF program execution. A lot of
//! `unsafe` code is used - be careful when making changes here.

use std::{
  any::{Any, TypeId},
  cell::{Cell, RefCell},
  collections::HashMap,
  ffi::CStr,
  marker::PhantomData,
  mem::ManuallyDrop,
  ops::{Deref, DerefMut},
  pin::Pin,
  ptr::NonNull,
  rc::Rc,
  sync::{
    atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering},
    Arc, Once,
  },
  task::{Context, Poll},
  thread::ThreadId,
  time::{Duration, Instant},
};

use futures::{task::noop_waker_ref, Future, FutureExt};
use memmap2::{MmapOptions, MmapRaw};
use parking_lot::{Condvar, Mutex};
use rand::prelude::SliceRandom;

use crate::{
  coroutine::{
    stack::{DefaultStack, Stack},
    Coroutine, CoroutineResult, ScopedCoroutine, Yielder,
  },
  error::{Error, RuntimeError},
  function_analysis::{analyze_functions, FunctionLayout},
  helpers::Helper,
  linker::{link_elf, validate_local_call_graph},
  pointer_cage::PointerCage,
  region_analysis::PointerSignature,
  util::nonnull_bytes_overlap,
};

const NATIVE_STACK_SIZE: usize = 16384;
const SHADOW_STACK_SIZE: usize = 32768;
const MAX_CALLDATA_SIZE: usize = 512;
const MAX_MUTABLE_DEREF_REGIONS: usize = 4;
const MAX_IMMUTABLE_DEREF_REGIONS: usize = 16;

#[cfg(all(
  target_arch = "x86_64",
  any(target_os = "linux", target_os = "openbsd")
))]
std::arch::global_asm!(
  r#"
.global async_ebpf_entry_trampoline
.type async_ebpf_entry_trampoline,@function
async_ebpf_entry_trampoline:
    // rdi = target, rsi = ctx, rcx = guest stack bottom, r8 = guest stack len,
    // [rsp + 8] = JitMemory descriptor. The entry target is staged through r9
    // and then rcx, neither of which uBPF maps to an eBPF register, so it can
    // be called after the register scrub below. r11 is uBPF's VOLATILE_CTXT.
    mov r9, rdi
    mov rax, [rsp + 8]
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r15, rcx
    add r15, r8
    mov rdi, rsi
    sub rsp, 8
    mov rbp, rsp
    sub rsp, 32
    mov [rbp - 8], rax
    mov rcx, r9
    mov r11, rdi
    // Scrub every register the guest can name (uBPF maps eBPF r0-r10 to
    // rax/rdi/rsi/rdx/r10/r8/rbx/r12/r13/r14/r15) except r1 (ctx) and r10
    // (frame pointer). Without this the guest reads host addresses left behind
    // by this trampoline and by our caller's callee-saved registers.
    xor eax, eax
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    xor ebx, ebx
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    call rcx
    mov rsp, rbp
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.size async_ebpf_entry_trampoline, . - async_ebpf_entry_trampoline
"#
);

#[cfg(all(
  target_arch = "aarch64",
  any(target_os = "linux", target_os = "openbsd")
))]
std::arch::global_asm!(
  r#"
.global async_ebpf_entry_trampoline
.type async_ebpf_entry_trampoline,%function
async_ebpf_entry_trampoline:
    // x0 = target, x1 = ctx, x3 = guest stack bottom, x4 = guest stack len,
    // x6 = JitMemory descriptor. x17 is not mapped to any eBPF register, so the
    // entry target is staged through it.
    bti c
    mov x17, x0
    sub sp, sp, #16
    stp x29, x30, [sp]
    sub sp, sp, #64
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    mov x29, sp
    add x23, x3, x4
    mov x0, x1
    sub sp, sp, #16
    str x6, [x29, #-8]
    mov x26, x0
    // Scrub every register the guest can name (uBPF maps eBPF r0-r10 to
    // x5/x0-x4/x19-x23) except r1 (ctx) and r10 (frame pointer), plus the
    // descriptor still held in x6. Without this the guest reads host addresses
    // left behind by our caller's callee-saved registers.
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x6, xzr
    mov x19, xzr
    mov x20, xzr
    mov x21, xzr
    mov x22, xzr
    blr x17
    mov x0, x5
    mov sp, x29
    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    add sp, sp, #64
    ldp x29, x30, [sp]
    add sp, sp, #16
    ret
.size async_ebpf_entry_trampoline, . - async_ebpf_entry_trampoline
"#
);

extern "C" {
  fn async_ebpf_entry_trampoline(
    target: usize,
    ctx: usize,
    mem_len: usize,
    stack: usize,
    stack_len: usize,
    reserved: usize,
    memory: usize,
  ) -> u64;
}

/// Per-invocation storage for helper state during a program run.
pub struct InvokeScope {
  data: HashMap<TypeId, Box<dyn Any + Send>>,
}

impl InvokeScope {
  /// Gets or creates typed data scoped to this invocation.
  pub fn data_mut<T: Default + Send + 'static>(&mut self) -> &mut T {
    let ty = TypeId::of::<T>();
    self
      .data
      .entry(ty)
      .or_insert_with(|| Box::new(T::default()))
      .downcast_mut()
      .expect("InvokeScope::data_mut: downcast failed")
  }
}

/// Context passed to helpers while a program is executing.
pub struct HelperScope<'a, 'b> {
  /// The program being executed.
  pub program: &'a Program,
  /// Mutable per-invocation data for helpers.
  pub invoke: RefCell<&'a mut InvokeScope>,
  resources: RefCell<&'a mut [&'b mut dyn Any]>,
  memory: &'a JitMemory,
  mutable_dereferenced_regions: [Cell<Option<NonNull<[u8]>>>; MAX_MUTABLE_DEREF_REGIONS],
  immutable_dereferenced_regions: [Cell<Option<NonNull<[u8]>>>; MAX_IMMUTABLE_DEREF_REGIONS],
  can_post_task: bool,
}

/// A validated mutable view into user memory.
pub struct MutableUserMemory<'a, 'b, 'c> {
  _scope: &'c HelperScope<'a, 'b>,
  region: NonNull<[u8]>,
}

impl<'a, 'b, 'c> Deref for MutableUserMemory<'a, 'b, 'c> {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    unsafe { self.region.as_ref() }
  }
}

impl<'a, 'b, 'c> DerefMut for MutableUserMemory<'a, 'b, 'c> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    unsafe { self.region.as_mut() }
  }
}

impl<'a, 'b> HelperScope<'a, 'b> {
  /// Posts an async task to be run between timeslices.
  pub fn post_task(
    &self,
    task: impl Future<Output = impl FnOnce(&HelperScope) -> Result<u64, ()> + 'static> + 'static,
  ) {
    if !self.can_post_task {
      panic!("HelperScope::post_task() called in a context where posting task is not allowed");
    }

    PENDING_ASYNC_TASK.with(|x| {
      let mut x = x.borrow_mut();
      if x.is_some() {
        panic!("post_task called while another task is pending");
      }
      *x = Some(async move { Box::new(task.await) as AsyncTaskOutput }.boxed_local());
    });
  }

  /// Calls `callback` with a mutable resource of type `T`, if present.
  pub fn with_resource_mut<'c, T: 'static, R>(
    &'c self,
    callback: impl FnOnce(Result<&mut T, ()>) -> R,
  ) -> R {
    let mut resources = self.resources.borrow_mut();
    let Some(res) = resources
      .iter_mut()
      .filter_map(|x| x.downcast_mut::<T>())
      .next()
    else {
      tracing::warn!(resource_type = ?TypeId::of::<T>(), "resource not found");
      return callback(Err(()));
    };

    callback(Ok(res))
  }

  /// Validates and returns an immutable view into user memory.
  pub fn user_memory(&self, ptr: u64, size: u64) -> Result<&[u8], ()> {
    let Some(region) = self.memory.safe_deref_for_read(ptr as usize, size as usize) else {
      tracing::warn!(ptr, size, "invalid read");
      return Err(());
    };

    if size != 0 {
      // The region must not overlap with any previously dereferenced mutable regions
      if self
        .mutable_dereferenced_regions
        .iter()
        .filter_map(|x| x.get())
        .any(|x| nonnull_bytes_overlap(x, region))
      {
        tracing::warn!(ptr, size, "read overlapped with previous write");
        return Err(());
      }

      // Find a slot to record this dereference
      let Some(slot) = self
        .immutable_dereferenced_regions
        .iter()
        .find(|x| x.get().is_none())
      else {
        tracing::warn!(ptr, size, "too many reads");
        return Err(());
      };
      slot.set(Some(region));
    }

    Ok(unsafe { region.as_ref() })
  }

  /// Validates and returns a mutable view into user memory.
  pub fn user_memory_mut<'c>(
    &'c self,
    ptr: u64,
    size: u64,
  ) -> Result<MutableUserMemory<'a, 'b, 'c>, ()> {
    let Some(region) = self
      .memory
      .safe_deref_for_write(ptr as usize, size as usize)
    else {
      tracing::warn!(ptr, size, "invalid write");
      return Err(());
    };

    if size != 0 {
      // The region must not overlap with any other previously dereferenced mutable or immutable regions
      if self
        .mutable_dereferenced_regions
        .iter()
        .chain(self.immutable_dereferenced_regions.iter())
        .filter_map(|x| x.get())
        .any(|x| nonnull_bytes_overlap(x, region))
      {
        tracing::warn!(ptr, size, "write overlapped with previous read/write");
        return Err(());
      }

      // Find a slot to record this dereference
      let Some(slot) = self
        .mutable_dereferenced_regions
        .iter()
        .find(|x| x.get().is_none())
      else {
        tracing::warn!(ptr, size, "too many writes");
        return Err(());
      };
      slot.set(Some(region));
    }

    Ok(MutableUserMemory {
      _scope: self,
      region,
    })
  }
}

#[derive(Copy, Clone)]
struct AssumeSend<T>(T);
unsafe impl<T> Send for AssumeSend<T> {}

struct ExecContext {
  native_stack: DefaultStack,
  guest_stack: Box<[u8; SHADOW_STACK_SIZE]>,
}

impl ExecContext {
  fn new() -> Self {
    Self {
      native_stack: DefaultStack::new(NATIVE_STACK_SIZE)
        .expect("failed to initialize native stack"),
      guest_stack: Box::new([0u8; SHADOW_STACK_SIZE]),
    }
  }
}

#[repr(C)]
struct JitMemory {
  stack_guest_bottom: usize,
  stack_guest_top: usize,
  stack_native_base: usize,
  data_guest_bottom: usize,
  data_guest_top: usize,
  data_native_base: usize,
}

impl JitMemory {
  fn checked_region(
    guest: usize,
    size: usize,
    guest_bottom: usize,
    guest_top: usize,
    native_base: usize,
  ) -> Option<NonNull<[u8]>> {
    if size == 0 {
      return Some(NonNull::slice_from_raw_parts(NonNull::dangling(), 0));
    }

    let end = guest.checked_add(size)?;
    if guest < guest_bottom || end > guest_top {
      return None;
    }
    let native = native_base.checked_add(guest - guest_bottom)? as *mut u8;
    unsafe {
      Some(NonNull::new_unchecked(std::ptr::slice_from_raw_parts_mut(
        native, size,
      )))
    }
  }

  fn safe_deref_for_write(&self, guest: usize, size: usize) -> Option<NonNull<[u8]>> {
    Self::checked_region(
      guest,
      size,
      self.stack_guest_bottom,
      self.stack_guest_top,
      self.stack_native_base,
    )
  }

  fn safe_deref_for_read(&self, guest: usize, size: usize) -> Option<NonNull<[u8]>> {
    Self::checked_region(
      guest,
      size,
      self.stack_guest_bottom,
      self.stack_guest_top,
      self.stack_native_base,
    )
    .or_else(|| {
      Self::checked_region(
        guest,
        size,
        self.data_guest_bottom,
        self.data_guest_top,
        self.data_native_base,
      )
    })
  }
}

/// A pending async task spawned by a helper.
pub type PendingAsyncTask = Pin<Box<dyn Future<Output = AsyncTaskOutput>>>;
/// The callback produced by a helper async task when it resumes.
pub type AsyncTaskOutput = Box<dyn FnOnce(&HelperScope) -> Result<u64, ()>>;

static NEXT_PROGRAM_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Copy, Clone, Debug)]
enum PreemptionState {
  Inactive,
  Armed(usize),
  Shutdown,
}

type PreemptionStateSignal = (Mutex<PreemptionState>, Condvar);

thread_local! {
  static RUST_TID: ThreadId = std::thread::current().id();
  static SIGUSR1_COUNTER: Cell< u64> = Cell::new(0);
  static ACTIVE_JIT_CODE_ZONE: ActiveJitCodeZone = ActiveJitCodeZone::default();
  static EXEC_CONTEXT_POOL: RefCell<Vec<ExecContext>> = Default::default();
  static PENDING_ASYNC_TASK: RefCell<Option<PendingAsyncTask>> = RefCell::new(None);
  static PREEMPTION_STATE: Arc<PreemptionStateSignal> = Arc::new((Mutex::new(PreemptionState::Inactive), Condvar::new()));
  static LOADING_PROGRAM_LOADER: Cell<*const ProgramLoader> = const { Cell::new(std::ptr::null()) };
  static ACTIVE_PROGRAM: Cell<*const Program> = const { Cell::new(std::ptr::null()) };
}

struct BorrowedExecContext {
  ctx: ManuallyDrop<ExecContext>,
}

impl BorrowedExecContext {
  fn new() -> Self {
    let mut me = Self {
      ctx: ManuallyDrop::new(
        EXEC_CONTEXT_POOL.with(|x| x.borrow_mut().pop().unwrap_or_else(ExecContext::new)),
      ),
    };
    me.ctx.guest_stack.fill(0x8e);
    me
  }
}

impl Drop for BorrowedExecContext {
  fn drop(&mut self) {
    let ctx = unsafe { ManuallyDrop::take(&mut self.ctx) };
    EXEC_CONTEXT_POOL.with(|x| x.borrow_mut().push(ctx));
  }
}

#[derive(Default)]
struct ActiveJitCodeZone {
  valid: AtomicBool,
  code_range: Cell<(usize, usize)>,
  pointer_cage_protected_range: Cell<(usize, usize)>,
  yielder: Cell<Option<NonNull<Yielder<u64, Dispatch>>>>,
}

/// Hooks for observing program execution events.
pub trait ProgramEventListener: Send + Sync + 'static {
  /// Called after an async preemption is triggered.
  fn did_async_preempt(&self, _scope: &HelperScope) {}
  /// Called after yielding back to the async runtime.
  fn did_yield(&self) {}
  /// Called after throttling a program's execution.
  fn did_throttle(&self, _scope: &HelperScope) -> Option<Pin<Box<dyn Future<Output = ()>>>> {
    None
  }
}

/// No-op event listener implementation.
pub struct DummyProgramEventListener;
impl ProgramEventListener for DummyProgramEventListener {}

/// Default limit for the total JIT-compiled native code size of one program.
pub const DEFAULT_CODE_SIZE_LIMIT: usize = 1 << 20;

/// Prepares helper tables and loads eBPF programs.
pub struct ProgramLoader {
  helpers_inverse: HashMap<&'static str, i32>,
  event_listener: Arc<dyn ProgramEventListener>,
  helper_id_xor: u16,
  helpers: Arc<Vec<(u16, &'static str, Helper)>>,
  code_size_limit: usize,
  require_static_regions: bool,
}

/// A loaded program that is not yet pinned to a thread.
pub struct UnboundProgram {
  id: u64,
  _code_mem: MmapRaw,
  code_base: usize,
  code_size: usize,
  page_size: usize,
  code_arena: RefCell<CodeArena>,
  cage: PointerCage,
  helper_id_xor: u16,
  helpers: Arc<Vec<(u16, &'static str, Helper)>>,
  event_listener: Arc<dyn ProgramEventListener>,
  require_static_regions: bool,
  entrypoints: HashMap<String, usize>,
  sections: RefCell<Vec<Section>>,
  resolvers: RefCell<HashMap<u32, ResolverInfo>>,
  next_resolver_id: Cell<u32>,
}

/// A program pinned to a specific thread and ready to execute.
pub struct Program {
  unbound: UnboundProgram,
  data: RefCell<HashMap<TypeId, Rc<dyn Any>>>,
  t: ThreadEnv,
}

#[derive(Copy, Clone)]
struct Entrypoint {
  code_ptr: usize,
}

struct CodeArena {
  used: usize,
}

struct Section {
  vm: Vm,
  code_vaddr: usize,
  code_len: usize,
  layout: FunctionLayout,
  functions: Vec<FunctionState>,
}

#[derive(Default)]
struct FunctionState {
  compiled: HashMap<PointerSignature, FunctionCompilation>,
  #[cfg(test)]
  compile_attempts: usize,
}

#[derive(Clone)]
enum FunctionCompilation {
  Succeeded(Entrypoint),
  Failed(RuntimeError),
}

impl FunctionCompilation {
  fn result(&self) -> Result<Entrypoint, RuntimeError> {
    match self {
      Self::Succeeded(entrypoint) => Ok(*entrypoint),
      Self::Failed(err) => Err(err.clone()),
    }
  }

  fn entrypoint(&self) -> Option<Entrypoint> {
    match self {
      Self::Succeeded(entrypoint) => Some(*entrypoint),
      Self::Failed(_) => None,
    }
  }
}

#[derive(Clone, Copy)]
struct ResolverInfo {
  section_index: usize,
  function_index: usize,
  signature: PointerSignature,
}

/// Time limits used to yield or throttle execution.
#[derive(Clone, Debug)]
pub struct TimesliceConfig {
  /// Maximum runtime before yielding to the async scheduler.
  pub max_run_time_before_yield: Duration,
  /// Maximum runtime before a throttle sleep is forced.
  pub max_run_time_before_throttle: Duration,
  /// Duration of the throttle sleep once triggered.
  pub throttle_duration: Duration,
}

/// Async runtime integration for yielding and sleeping.
pub trait Timeslicer {
  /// Sleep for the provided duration.
  fn sleep(&self, duration: Duration) -> impl Future<Output = ()>;
  /// Yield to the async scheduler.
  fn yield_now(&self) -> impl Future<Output = ()>;
}

/// Global runtime environment for signal handlers.
#[derive(Copy, Clone)]
pub struct GlobalEnv(());

/// Per-thread runtime environment for preemption handling.
#[derive(Copy, Clone)]
pub struct ThreadEnv {
  _not_send_sync: std::marker::PhantomData<*const ()>,
}

#[cfg(target_os = "linux")]
type NativeThread = (libc::pid_t, libc::pid_t);
#[cfg(target_os = "openbsd")]
type NativeThread = libc::pthread_t;

#[cfg(target_os = "linux")]
unsafe fn current_native_thread() -> NativeThread {
  (libc::getpid(), libc::gettid())
}

#[cfg(target_os = "openbsd")]
unsafe fn current_native_thread() -> NativeThread {
  libc::pthread_self()
}

#[cfg(target_os = "linux")]
unsafe fn signal_native_thread(thread: NativeThread, signal: i32) -> i32 {
  libc::syscall(libc::SYS_tgkill, thread.0, thread.1, signal) as i32
}

#[cfg(target_os = "openbsd")]
unsafe fn signal_native_thread(thread: NativeThread, signal: i32) -> i32 {
  libc::pthread_kill(thread, signal)
}

impl GlobalEnv {
  /// Initializes global state and installs signal handlers.
  ///
  /// # Safety
  /// Must be called in a process that can install SIGUSR1/SIGSEGV handlers.
  pub unsafe fn new() -> Self {
    static INIT: Once = Once::new();

    // SIGUSR1 must be blocked during exception handling
    // Otherwise it seems that Linux gives up and throws an uncatchable SI_KERNEL SIGSEGV:
    //
    // [pid 517110] tgkill(517109, 517112, SIGUSR1 <unfinished ...>
    // [pid 517112] --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_ACCERR, si_addr=0x793789be227e} ---
    // [pid 517109] write(15, "\1\0\0\0\0\0\0\0", 8 <unfinished ...>
    // [pid 517110] <... tgkill resumed>)      = 0
    // [pid 517109] <... write resumed>)       = 8
    // [pid 517112] --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_TKILL, si_pid=517109, si_uid=1000} ---
    // [pid 517109] recvfrom(57,  <unfinished ...>
    // [pid 517110] futex(0x79378abff5a8, FUTEX_WAIT_PRIVATE, 1, {tv_sec=0, tv_nsec=5999909} <unfinished ...>
    // [pid 517109] <... recvfrom resumed>"GET /write_rodata HTTP/1.1\r\nHost"..., 8192, 0, NULL, NULL) = 61
    // [pid 517112] --- SIGSEGV {si_signo=SIGSEGV, si_code=SI_KERNEL, si_addr=NULL} ---

    INIT.call_once(|| {
      let sa_mask = get_blocked_sigset();

      for (sig, handler) in [
        (libc::SIGUSR1, sigusr1_handler as *const () as usize),
        (libc::SIGSEGV, sigsegv_handler as *const () as usize),
      ] {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handler;
        act.sa_flags = libc::SA_SIGINFO;
        act.sa_mask = sa_mask;
        if libc::sigaction(sig, &act, std::ptr::null_mut()) != 0 {
          panic!("failed to setup handler for signal {}", sig);
        }
      }
    });

    Self(())
  }

  /// Initializes per-thread state and starts the async preemption watcher.
  pub fn init_thread(self, async_preemption_interval: Duration) -> ThreadEnv {
    // Signal handlers must never trigger lazy TLS initialization. In
    // particular, OpenBSD aborts if a signal recursively enters the runtime's
    // TLS initialization path. Initialize every slot touched by SIGUSR1 before
    // the watcher can send its first signal.
    RUST_TID.with(|_| {});
    SIGUSR1_COUNTER.with(|_| {});
    ACTIVE_JIT_CODE_ZONE.with(|_| {});

    struct DeferDrop(Arc<PreemptionStateSignal>);
    impl Drop for DeferDrop {
      fn drop(&mut self) {
        let x = &self.0;
        *x.0.lock() = PreemptionState::Shutdown;
        x.1.notify_one();
      }
    }

    thread_local! {
      static WATCHER: RefCell<Option<DeferDrop>> = RefCell::new(None);
    }

    if WATCHER.with(|x| x.borrow().is_some()) {
      return ThreadEnv {
        _not_send_sync: PhantomData,
      };
    }

    let preemption_state = PREEMPTION_STATE.with(|x| x.clone());

    unsafe {
      let target_thread = current_native_thread();
      let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);

      std::thread::Builder::new()
        .name("preempt-watcher".to_string())
        .spawn(move || {
          let mut state = preemption_state.0.lock();
          let _ = ready_tx.send(());
          loop {
            match *state {
              PreemptionState::Shutdown => break,
              PreemptionState::Inactive => {
                preemption_state.1.wait(&mut state);
              }
              PreemptionState::Armed(_) => {
                let timeout = preemption_state.1.wait_while_for(
                  &mut state,
                  |x| matches!(x, PreemptionState::Armed(_)),
                  async_preemption_interval,
                );
                if timeout.timed_out() {
                  match *state {
                    PreemptionState::Armed(0) => {
                      *state = PreemptionState::Inactive;
                    }
                    PreemptionState::Armed(_) => {
                      if signal_native_thread(target_thread, libc::SIGUSR1) != 0 {
                        break;
                      }
                    }
                    PreemptionState::Inactive => {}
                    PreemptionState::Shutdown => break,
                  }
                }
              }
            }
          }
        })
        .expect("failed to spawn preemption watcher");
      ready_rx
        .recv()
        .expect("preemption watcher stopped during startup");

      WATCHER.with(|x| {
        x.borrow_mut()
          .replace(DeferDrop(PREEMPTION_STATE.with(|x| x.clone())));
      });

      ThreadEnv {
        _not_send_sync: PhantomData,
      }
    }
  }
}

impl UnboundProgram {
  /// Pins the program to the current thread using a prepared `ThreadEnv`.
  pub fn pin_to_current_thread(self, t: ThreadEnv) -> Program {
    Program {
      unbound: self,
      data: RefCell::new(HashMap::new()),
      t,
    }
  }
}

pub struct PreemptionEnabled(());

impl PreemptionEnabled {
  pub fn new(_: ThreadEnv) -> Self {
    PREEMPTION_STATE.with(|x| {
      let mut notify = false;
      {
        let mut st = x.0.lock();
        let next = match *st {
          PreemptionState::Inactive => {
            notify = true;
            PreemptionState::Armed(1)
          }
          PreemptionState::Armed(n) => PreemptionState::Armed(n + 1),
          PreemptionState::Shutdown => unreachable!(),
        };
        *st = next;
      }

      if notify {
        x.1.notify_one();
      }
    });
    Self(())
  }
}

impl Drop for PreemptionEnabled {
  fn drop(&mut self) {
    PREEMPTION_STATE.with(|x| {
      let mut st = x.0.lock();
      let next = match *st {
        PreemptionState::Armed(1) => PreemptionState::Armed(0),
        PreemptionState::Armed(n) => {
          assert!(n > 1);
          PreemptionState::Armed(n - 1)
        }
        PreemptionState::Inactive | PreemptionState::Shutdown => unreachable!(),
      };
      *st = next;
    });
  }
}

impl Program {
  /// Returns the unique program identifier.
  pub fn id(&self) -> u64 {
    self.unbound.id
  }

  pub fn thread_env(&self) -> ThreadEnv {
    self.t
  }

  /// Gets or creates shared typed data for this program instance.
  pub fn data<T: Default + 'static>(&self) -> Rc<T> {
    let mut data = self.data.borrow_mut();
    let entry = data.entry(TypeId::of::<T>());
    let entry = entry.or_insert_with(|| Rc::new(T::default()));
    entry.clone().downcast().unwrap()
  }

  pub fn has_section(&self, name: &str) -> bool {
    self.unbound.entrypoints.contains_key(name)
  }

  #[cfg(test)]
  pub(crate) fn compiled_function_count_for_tests(&self) -> usize {
    self
      .unbound
      .sections
      .borrow()
      .iter()
      .map(|section| {
        section
          .functions
          .iter()
          .map(|function| {
            function
              .compiled
              .values()
              .filter(|compilation| compilation.entrypoint().is_some())
              .count()
          })
          .sum::<usize>()
      })
      .sum()
  }

  #[cfg(test)]
  pub(crate) fn failed_function_count_for_tests(&self) -> usize {
    self
      .unbound
      .sections
      .borrow()
      .iter()
      .map(|section| {
        section
          .functions
          .iter()
          .map(|function| {
            function
              .compiled
              .values()
              .filter(|compilation| compilation.entrypoint().is_none())
              .count()
          })
          .sum::<usize>()
      })
      .sum()
  }

  #[cfg(test)]
  pub(crate) fn function_compile_attempt_count_for_tests(&self) -> usize {
    self
      .unbound
      .sections
      .borrow()
      .iter()
      .map(|section| {
        section
          .functions
          .iter()
          .map(|function| function.compile_attempts)
          .sum::<usize>()
      })
      .sum()
  }

  #[cfg(test)]
  pub(crate) fn code_arena_used_for_tests(&self) -> usize {
    self.unbound.code_arena.borrow().used
  }

  /// Number of successfully compiled variants per source function, flattened
  /// across sections. One entry per function in the layout; a value > 1 means
  /// that callee was specialized for multiple incoming pointer signatures.
  #[cfg(test)]
  pub(crate) fn function_variant_counts_for_tests(&self) -> Vec<usize> {
    self
      .unbound
      .sections
      .borrow()
      .iter()
      .flat_map(|section| {
        section.functions.iter().map(|function| {
          function
            .compiled
            .values()
            .filter(|compilation| compilation.entrypoint().is_some())
            .count()
        })
      })
      .collect()
  }

  fn compile_entrypoint(&self, section_index: usize) -> Result<Entrypoint, RuntimeError> {
    self.compile_function(section_index, 0, PointerSignature::entry())
  }

  fn compile_resolver(&self, resolver_id: u32) -> Result<Entrypoint, RuntimeError> {
    let Some(info) = self.unbound.resolvers.borrow().get(&resolver_id).copied() else {
      return Err(RuntimeError::InvalidArgument(
        "local call resolver not found",
      ));
    };
    self.compile_function(info.section_index, info.function_index, info.signature)
  }

  fn cached_resolver_target(&self, resolver_id: u32) -> Option<usize> {
    let info = self.unbound.resolvers.borrow().get(&resolver_id).copied()?;
    let sections = self.unbound.sections.borrow();
    let section = sections.get(info.section_index)?;
    section
      .functions
      .get(info.function_index)?
      .compiled
      .get(&info.signature)
      .and_then(|compilation| compilation.entrypoint())
      .map(|entrypoint| entrypoint.code_ptr)
  }

  fn protect_code_pages(&self, executable_len: usize) -> Result<(), RuntimeError> {
    let executable_len =
      (executable_len + self.unbound.page_size - 1) & !(self.unbound.page_size - 1);
    unsafe {
      if executable_len > 0
        && libc::mprotect(
          self.unbound.code_base as *mut _,
          executable_len,
          libc::PROT_READ | libc::PROT_EXEC,
        ) != 0
      {
        return Err(RuntimeError::PlatformError(
          "failed to protect executable code",
        ));
      }
      if executable_len < self.unbound.code_size
        && libc::mprotect(
          (self.unbound.code_base + executable_len) as *mut _,
          self.unbound.code_size - executable_len,
          libc::PROT_NONE,
        ) != 0
      {
        return Err(RuntimeError::PlatformError("failed to protect unused code"));
      }
    }
    Ok(())
  }

  fn compile_function(
    &self,
    section_index: usize,
    function_index: usize,
    signature: PointerSignature,
  ) -> Result<Entrypoint, RuntimeError> {
    {
      let sections = self.unbound.sections.borrow();
      let Some(section) = sections.get(section_index) else {
        return Err(RuntimeError::InvalidArgument("section not found"));
      };
      let Some(function) = section.functions.get(function_index) else {
        return Err(RuntimeError::InvalidArgument("function not found"));
      };
      if let Some(compilation) = function.compiled.get(&signature) {
        return compilation.result();
      }
    }

    let mut sections = self.unbound.sections.borrow_mut();
    let section = sections
      .get_mut(section_index)
      .ok_or(RuntimeError::InvalidArgument("section not found"))?;
    if function_index >= section.functions.len() {
      return Err(RuntimeError::InvalidArgument("function not found"));
    }
    if let Some(compilation) = section.functions[function_index].compiled.get(&signature) {
      return compilation.result();
    }
    #[cfg(test)]
    {
      section.functions[function_index].compile_attempts += 1;
    }
    let function = section.layout.functions[function_index].clone();
    let code = self
      .unbound
      .cage
      .data_slice(section.code_vaddr, section.code_len)
      .unwrap();
    let code_bytes = unsafe { std::slice::from_raw_parts(code.as_ptr() as *const u8, code.len()) };
    let region_analysis = crate::region_analysis::analyze_function(
      code_bytes,
      function.start_pc,
      function.end_pc,
      signature,
      self.unbound.cage.data_bottom() as u64,
      self.unbound.cage.data_top() as u64,
      &section.layout,
    );
    if self.unbound.require_static_regions && !region_analysis.unresolved.is_empty() {
      let err = RuntimeError::InvalidArgumentOwned(format!(
        "static region analysis failed in function [{}, {}): {} memory access(es) could not be \
         routed to a single region (instruction slots {:?})",
        function.start_pc,
        function.end_pc,
        region_analysis.unresolved.len(),
        region_analysis.unresolved,
      ));
      section.functions[function_index]
        .compiled
        .insert(signature, FunctionCompilation::Failed(err.clone()));
      return Err(err);
    }

    // Allocate resolver ids and build their metadata locally. Nothing is
    // committed to `next_resolver_id` or the shared `resolvers` map until the
    // function has been fully compiled and protected, so a failed compilation
    // does not leak resolver ids or orphan map entries.
    let mut resolver_ids = vec![0u32; code_bytes.len() / 8];
    let mut pending_resolvers: Vec<(u32, ResolverInfo)> = Vec::new();
    let mut next_resolver_id = self.unbound.next_resolver_id.get();
    for (&call_pc, &callee_signature) in &region_analysis.call_signatures {
      let target_pc = local_call_target(code_bytes, call_pc);
      let callee_index = section.layout.pc_to_func[target_pc];
      let resolver_id = next_resolver_id;
      let Some(advanced) = resolver_id.checked_add(1) else {
        let err = RuntimeError::InvalidArgument("too many local call resolvers");
        section.functions[function_index]
          .compiled
          .insert(signature, FunctionCompilation::Failed(err.clone()));
        return Err(err);
      };
      next_resolver_id = advanced;
      resolver_ids[call_pc] = resolver_id;
      pending_resolvers.push((
        resolver_id,
        ResolverInfo {
          section_index,
          function_index: callee_index,
          signature: callee_signature,
        },
      ));
    }

    let mut arena = self.unbound.code_arena.borrow_mut();
    if arena.used >= self.unbound.code_size {
      let err = RuntimeError::InvalidArgument("no space left for jit compilation");
      section.functions[function_index]
        .compiled
        .insert(signature, FunctionCompilation::Failed(err.clone()));
      return Err(err);
    }

    unsafe {
      if libc::mprotect(
        self.unbound.code_base as *mut _,
        self.unbound.code_size,
        libc::PROT_READ | libc::PROT_WRITE,
      ) != 0
      {
        let err = RuntimeError::PlatformError("failed to make code writable");
        section.functions[function_index]
          .compiled
          .insert(signature, FunctionCompilation::Failed(err.clone()));
        return Err(err);
      }
    }

    let code_ptr = self.unbound.code_base + arena.used;
    let mut written_len = self.unbound.code_size - arena.used;
    let mut errmsg_ptr = std::ptr::null_mut();

    let ret = unsafe {
      crate::ubpf::ubpf_set_region_hints(
        section.vm.0.as_ptr(),
        region_analysis.hints.as_ptr(),
        region_analysis.hints.len(),
      );
      crate::ubpf::ubpf_set_lazy_local_call_resolver(
        section.vm.0.as_ptr(),
        Some(tls_local_call_resolver),
        resolver_ids.as_ptr(),
        resolver_ids.len(),
      );
      let ret = crate::ubpf::ubpf_translate_function_ex(
        section.vm.0.as_ptr(),
        code_ptr as *mut u8,
        &mut written_len,
        &mut errmsg_ptr,
        crate::ubpf::JitMode_ExtendedJitMode,
        function.start_pc as u32,
        function.end_pc as u32,
      );
      crate::ubpf::ubpf_set_region_hints(section.vm.0.as_ptr(), std::ptr::null(), 0);
      crate::ubpf::ubpf_set_lazy_local_call_resolver(
        section.vm.0.as_ptr(),
        None,
        std::ptr::null(),
        0,
      );
      ret
    };

    if ret != 0 {
      let errmsg = unsafe {
        if errmsg_ptr.is_null() {
          "".to_string()
        } else {
          CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned()
        }
      };
      if !errmsg_ptr.is_null() {
        unsafe { libc::free(errmsg_ptr as _) };
      }
      let _ = self.protect_code_pages(arena.used);
      let err =
        RuntimeError::InvalidArgumentOwned(format!("ubpf: code translation failed: {errmsg}"));
      section.functions[function_index]
        .compiled
        .insert(signature, FunctionCompilation::Failed(err.clone()));
      return Err(err);
    }
    if !errmsg_ptr.is_null() {
      unsafe { libc::free(errmsg_ptr as _) };
    }

    unsafe {
      crate::ubpf::ubpf_clear_instruction_cache(code_ptr as *mut u8, written_len);
    }

    // Restore W^X protection covering the newly emitted function before
    // advancing the arena. If protection cannot be restored the function is not
    // executable, so leave `arena.used` unchanged (reclaiming the space, which
    // the next compilation overwrites after making the region writable again)
    // and do not register its resolvers.
    let new_used = arena.used + written_len;
    if let Err(err) = self.protect_code_pages(new_used) {
      section.functions[function_index]
        .compiled
        .insert(signature, FunctionCompilation::Failed(err.clone()));
      return Err(err);
    }
    arena.used = new_used;

    // Compilation succeeded: commit the resolver ids and metadata.
    self.unbound.next_resolver_id.set(next_resolver_id);
    {
      let mut resolvers = self.unbound.resolvers.borrow_mut();
      for (resolver_id, info) in pending_resolvers {
        resolvers.insert(resolver_id, info);
      }
    }

    let entrypoint = Entrypoint { code_ptr };
    section.functions[function_index]
      .compiled
      .insert(signature, FunctionCompilation::Succeeded(entrypoint));
    tracing::debug!(
      section_index,
      function_index,
      start_pc = function.start_pc,
      end_pc = function.end_pc,
      native_code_addr = ?(code_ptr as *const u8),
      native_code_size = written_len,
      "jit compiled function"
    );
    Ok(entrypoint)
  }

  /// Runs the program entrypoint with the provided resources and calldata.
  pub async fn run(
    &self,
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
    entrypoint: &str,
    resources: &mut [&mut dyn Any],
    calldata: &[u8],
    preemption: &PreemptionEnabled,
  ) -> Result<i64, Error> {
    self
      ._run(
        timeslice, timeslicer, entrypoint, resources, calldata, preemption,
      )
      .await
      .map_err(Error)
  }

  async fn _run(
    &self,
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
    entrypoint: &str,
    resources: &mut [&mut dyn Any],
    calldata: &[u8],
    _: &PreemptionEnabled,
  ) -> Result<i64, RuntimeError> {
    let Some(section_index) = self.unbound.entrypoints.get(entrypoint).copied() else {
      return Err(RuntimeError::InvalidArgument("entrypoint not found"));
    };
    let entrypoint = self.compile_entrypoint(section_index)?;
    struct CoDropper<'a, Input, Yield, Return, DefaultStack: Stack>(
      ScopedCoroutine<'a, Input, Yield, Return, DefaultStack>,
    );
    impl<'a, Input, Yield, Return, DefaultStack: Stack> Drop
      for CoDropper<'a, Input, Yield, Return, DefaultStack>
    {
      fn drop(&mut self) {
        // Prevent the coroutine library from attempting to unwind the stack of the coroutine
        // and run destructors, because this stack might be running a signal handler and
        // it's not allowed to unwind from there.
        //
        // SAFETY: The coroutine stack only contains stack frames for JIT-compiled code and
        // carefully chosen Rust code that do not hold Droppable values, so it's safe to
        // skip destructors.
        unsafe {
          self.0.force_reset();
        }
      }
    }

    let mut ectx = BorrowedExecContext::new();

    if calldata.len() > MAX_CALLDATA_SIZE {
      return Err(RuntimeError::InvalidArgument("calldata too large"));
    }
    ectx.ctx.guest_stack[SHADOW_STACK_SIZE - calldata.len()..].copy_from_slice(calldata);
    let calldata_len = calldata.len();

    let program_ret: u64 = {
      let guest_stack_top = self.unbound.cage.stack_top();
      let guest_stack_bottom = self.unbound.cage.stack_bottom();
      let ctx = &mut *ectx.ctx;
      let memory = JitMemory {
        stack_guest_bottom: guest_stack_bottom,
        stack_guest_top: guest_stack_top,
        stack_native_base: ctx.guest_stack.as_mut_ptr() as usize,
        data_guest_bottom: self.unbound.cage.data_bottom(),
        data_guest_top: self.unbound.cage.data_top(),
        data_native_base: self.unbound.cage.data_native_base(),
      };
      let memory_ptr = &memory as *const JitMemory as usize;

      let mut co = AssumeSend(CoDropper(Coroutine::with_stack(
        &mut ctx.native_stack,
        move |yielder, _input| unsafe {
          ACTIVE_JIT_CODE_ZONE.with(|x| {
            x.yielder.set(NonNull::new(yielder as *const _ as *mut _));
          });
          let calldata_start = guest_stack_top - calldata_len;
          let stack_top = calldata_start & !0x7;
          let stack_len = stack_top - guest_stack_bottom;
          async_ebpf_entry_trampoline(
            entrypoint.code_ptr,
            calldata_start,
            calldata_start,
            guest_stack_bottom,
            stack_len,
            0,
            memory_ptr,
          )
        },
      )));

      let mut last_yield_time: Option<Instant> = None;
      let mut last_throttle_time: Option<Instant> = None;
      let mut yielder: Option<AssumeSend<NonNull<Yielder<u64, Dispatch>>>> = None;
      let mut resume_input: u64 = 0;
      let mut did_throttle = false;
      let mut rust_tid_sigusr1_counter = (RUST_TID.with(|x| *x), SIGUSR1_COUNTER.with(|x| x.get()));
      let mut prev_async_task_output: Option<(&'static str, AsyncTaskOutput)> = None;
      let mut invoke_scope = InvokeScope {
        data: HashMap::new(),
      };

      loop {
        ACTIVE_JIT_CODE_ZONE.with(|x| {
          x.code_range.set((
            self.unbound.code_base,
            self.unbound.code_base + self.unbound.code_size,
          ));
          x.yielder.set(yielder.map(|x| x.0));
          x.pointer_cage_protected_range.set((0, 4096));
          compiler_fence(Ordering::Release);
          x.valid.store(true, Ordering::Relaxed);
        });
        ACTIVE_PROGRAM.with(|x| x.set(self as *const _));

        // If the previous iteration wants to write back to machine state
        if let Some((helper_name, prev_async_task_output)) = prev_async_task_output.take() {
          resume_input = prev_async_task_output(&HelperScope {
            program: self,
            invoke: RefCell::new(&mut invoke_scope),
            resources: RefCell::new(resources),
            memory: &memory,
            mutable_dereferenced_regions: unsafe { std::mem::zeroed() },
            immutable_dereferenced_regions: unsafe { std::mem::zeroed() },
            can_post_task: false,
          })
          .map_err(|_| RuntimeError::AsyncHelperError(helper_name))?;
        }

        let ret = co.0 .0.resume(resume_input);
        ACTIVE_PROGRAM.with(|x| x.set(std::ptr::null()));
        ACTIVE_JIT_CODE_ZONE.with(|x| {
          x.valid.store(false, Ordering::Relaxed);
          compiler_fence(Ordering::Release);
          yielder = x.yielder.get().map(AssumeSend);
        });

        let dispatch: Dispatch = match ret {
          CoroutineResult::Return(x) => break x,
          CoroutineResult::Yield(x) => x,
        };

        // restore signal mask of current thread
        if dispatch.memory_access_error.is_some() || dispatch.async_preemption {
          unsafe {
            let unblock = get_blocked_sigset();
            libc::sigprocmask(libc::SIG_UNBLOCK, &unblock, std::ptr::null_mut());
          }
        }

        if let Some(si_addr) = dispatch.memory_access_error {
          let vaddr = if si_addr >= memory.stack_native_base
            && si_addr < memory.stack_native_base + SHADOW_STACK_SIZE
          {
            memory.stack_guest_bottom + (si_addr - memory.stack_native_base)
          } else if si_addr >= memory.data_native_base
            && si_addr
              < memory.data_native_base + (memory.data_guest_top - memory.data_guest_bottom)
          {
            memory.data_guest_bottom + (si_addr - memory.data_native_base)
          } else {
            0
          };
          return Err(RuntimeError::MemoryFault(vaddr));
        }

        // Clear pending task if something else has set it
        PENDING_ASYNC_TASK.with(|x| x.borrow_mut().take());
        let mut helper_name: &'static str = "";

        let mut helper_scope = HelperScope {
          program: self,
          invoke: RefCell::new(&mut invoke_scope),
          resources: RefCell::new(resources),
          memory: &memory,
          mutable_dereferenced_regions: unsafe { std::mem::zeroed() },
          immutable_dereferenced_regions: unsafe { std::mem::zeroed() },
          can_post_task: false,
        };

        // A lazy local call JIT-compiles a function on this thread before the
        // guest can continue. That is guest-triggered work of unbounded size -
        // a program chooses how many (function, pointer signature) pairs exist,
        // and every one of them is a separate compilation - so it has to reach
        // the run-budget check below like any other dispatch. Async preemption
        // cannot substitute for that: the SIGUSR1 handler only acts on a PC
        // inside the JIT code range, and during compilation the PC is in the
        // compiler.
        let compiled_lazily = if let Some(resolver_id) = dispatch.lazy_local_call {
          resume_input = self.compile_resolver(resolver_id)?.code_ptr as u64;
          true
        } else if dispatch.async_preemption {
          self
            .unbound
            .event_listener
            .did_async_preempt(&mut helper_scope);
          false
        } else {
          // validator should ensure all helper indexes are present in the table
          let Some((_, got_helper_name, helper)) = self
            .unbound
            .helpers
            .get(
              ((dispatch.index & 0xffff) as u16 ^ self.unbound.helper_id_xor).wrapping_sub(1)
                as usize,
            )
            .copied()
          else {
            panic!("unknown helper index: {}", dispatch.index);
          };
          helper_name = got_helper_name;

          helper_scope.can_post_task = true;
          resume_input = helper(
            &mut helper_scope,
            dispatch.arg1,
            dispatch.arg2,
            dispatch.arg3,
            dispatch.arg4,
            dispatch.arg5,
          )
          .map_err(|()| RuntimeError::HelperError(helper_name))?;
          helper_scope.can_post_task = false;
          false
        };

        let pending_async_task = PENDING_ASYNC_TASK.with(|x| x.borrow_mut().take());

        // Fast path: do not read timestamp if no thread migration or async preemption happened.
        // A lazy compilation always takes the slow path - the fast path exists so that a helper
        // call does not pay for a clock read, which is not a trade worth making against a JIT
        // compilation.
        let new_rust_tid_sigusr1_counter =
          (RUST_TID.with(|x| *x), SIGUSR1_COUNTER.with(|x| x.get()));
        if !compiled_lazily
          && new_rust_tid_sigusr1_counter == rust_tid_sigusr1_counter
          && pending_async_task.is_none()
        {
          continue;
        }

        rust_tid_sigusr1_counter = new_rust_tid_sigusr1_counter;

        let now = Instant::now();
        let last_throttle = last_throttle_time.get_or_insert(now);
        let last_yield = last_yield_time.get_or_insert(now);
        let should_throttle = now > *last_throttle
          && now.duration_since(*last_throttle) >= timeslice.max_run_time_before_throttle;
        let should_yield = now > *last_yield
          && now.duration_since(*last_yield) >= timeslice.max_run_time_before_yield;
        if should_throttle || should_yield || pending_async_task.is_some() {
          // we are now free to give up control of current thread to other async tasks

          if should_throttle {
            if !did_throttle {
              did_throttle = true;
              tracing::warn!("throttling program");
            }
            timeslicer.sleep(timeslice.throttle_duration).await;
            let now = Instant::now();
            last_throttle_time = Some(now);
            last_yield_time = Some(now);
            let task = self.unbound.event_listener.did_throttle(&mut helper_scope);
            if let Some(task) = task {
              task.await;
            }
          } else if should_yield {
            timeslicer.yield_now().await;
            let now = Instant::now();
            last_yield_time = Some(now);
            self.unbound.event_listener.did_yield();
          }

          // Now we have released all exclusive resources and can safely execute the async task.
          if let Some(mut pending_async_task) = pending_async_task {
            // Fast path: helpers that merely compute a value (the common case)
            // complete on the first poll without ever suspending. Poll once and,
            // if it's ready, skip the `Instant::now()` reads used for run-budget
            // compensation below. This matters because `clock_gettime` can cost
            // ~200ns on virtualized hosts, and this path runs on every async
            // helper invocation.
            let output =
              match pending_async_task.poll_unpin(&mut Context::from_waker(noop_waker_ref())) {
                Poll::Ready(output) => output,
                Poll::Pending => {
                  // The task genuinely suspended; account for the wall-clock time
                  // it took so it isn't charged against the program's run budget.
                  let async_start = Instant::now();
                  let output = pending_async_task.await;
                  let async_dur = async_start.elapsed();
                  if let Some(last_throttle_time) = &mut last_throttle_time {
                    *last_throttle_time += async_dur;
                  }
                  if let Some(last_yield_time) = &mut last_yield_time {
                    *last_yield_time += async_dur;
                  }
                  output
                }
              };
            prev_async_task_output = Some((helper_name, output));
          }
        }
      }
    };

    Ok(program_ret as i64)
  }
}

struct Vm(NonNull<crate::ubpf::ubpf_vm>);
unsafe impl Send for Vm {}

impl Vm {
  fn new(cage: &PointerCage) -> Self {
    let vm = NonNull::new(unsafe { crate::ubpf::ubpf_create() }).expect("failed to create ubpf_vm");
    unsafe {
      crate::ubpf::ubpf_toggle_bounds_check(vm.as_ptr(), false);
      crate::ubpf::ubpf_set_jit_pointer_mask_and_offset(vm.as_ptr(), cage.mask(), cage.offset());
    }
    Self(vm)
  }
}

impl Drop for Vm {
  fn drop(&mut self) {
    unsafe {
      crate::ubpf::ubpf_destroy(self.0.as_ptr());
    }
  }
}

struct LoaderValidationScope {
  previous: *const ProgramLoader,
}

impl LoaderValidationScope {
  fn new(loader: &ProgramLoader) -> Self {
    let previous = LOADING_PROGRAM_LOADER.with(|x| {
      let previous = x.get();
      x.set(loader as *const _);
      previous
    });
    Self { previous }
  }
}

impl Drop for LoaderValidationScope {
  fn drop(&mut self) {
    LOADING_PROGRAM_LOADER.with(|x| x.set(self.previous));
  }
}

fn local_call_target(code: &[u8], pc: usize) -> usize {
  let offset = pc * 8;
  let imm = i32::from_le_bytes([
    code[offset + 4],
    code[offset + 5],
    code[offset + 6],
    code[offset + 7],
  ]);
  (pc as i64 + imm as i64 + 1) as usize
}

impl ProgramLoader {
  /// Creates a new `ProgramLoader` to load eBPF code.
  pub fn new(
    rng: &mut impl rand::Rng,
    event_listener: Arc<dyn ProgramEventListener>,
    raw_helpers: &[&[(&'static str, Helper)]],
  ) -> Self {
    let helper_id_xor = rng.gen::<u16>();
    let mut helpers_inverse: HashMap<&'static str, i32> = HashMap::new();
    // Collect first to a HashMap then to a Vec to deduplicate
    let mut shuffled_helpers = raw_helpers
      .iter()
      .flat_map(|x| x.iter().copied())
      .collect::<HashMap<_, _>>()
      .into_iter()
      .collect::<Vec<_>>();
    shuffled_helpers.shuffle(rng);
    let mut helpers: Vec<(u16, &'static str, Helper)> = Vec::with_capacity(shuffled_helpers.len());

    assert!(shuffled_helpers.len() <= 65535);

    for (i, (name, helper)) in shuffled_helpers.into_iter().enumerate() {
      let entropy = rng.gen::<u16>() & 0x7fff;
      helpers.push((entropy, name, helper));
      helpers_inverse.insert(
        name,
        (((entropy as usize) << 16) | ((i + 1) ^ (helper_id_xor as usize))) as i32,
      );
    }

    tracing::info!(?helpers_inverse, "generated helper table");
    Self {
      helper_id_xor,
      helpers: Arc::new(helpers),
      helpers_inverse,
      event_listener,
      code_size_limit: DEFAULT_CODE_SIZE_LIMIT,
      require_static_regions: false,
    }
  }

  /// Requires every guest memory access to be statically routable to a single
  /// region (stack or read-only data). When enabled, compilation fails if the
  /// region analysis cannot classify any load, store, or atomic — i.e. no
  /// access falls back to the dual-region runtime probe. Memory accesses
  /// reached only through unmodeled control flow (e.g. an argument pointer in a
  /// local function) count as unresolved and are rejected.
  ///
  /// Because functions are JIT-compiled lazily and per pointer-signature
  /// specialization, this check runs when each function variant is first
  /// compiled — at the start of [`Program::run`], not at load time. The error
  /// is therefore surfaced through `Program::run`. A function variant that is
  /// never reached is never compiled and never checked; the guarantee is "every
  /// executed access is statically routable", scoped to the variants actually
  /// invoked, rather than a whole-section load-time guarantee. (Soundness does
  /// not depend on this flag: unclassified accesses still get the dual-region
  /// runtime probe, so the flag only tightens strictness.)
  pub fn require_static_region_analysis(mut self, require: bool) -> Self {
    self.require_static_regions = require;
    self
  }

  /// Sets the maximum total size of JIT-compiled native code per program.
  ///
  /// Must be a non-zero multiple of 64 KiB so the code region stays
  /// page-aligned on all supported page sizes.
  ///
  /// Note for arm64: conditional branches and literal loads emitted by the
  /// JIT have a ±1 MiB range, and a section's helper calls reference a
  /// literal pool at the end of that section's code. Any single ELF section
  /// whose jitted code exceeds ~1 MiB is therefore rejected at load time
  /// ("ubpf: code translation failed") regardless of this limit; raising it
  /// past 1 MiB only adds room for more or larger sections within that
  /// per-section ceiling. x86-64 has no such per-section constraint.
  pub fn with_code_size_limit(mut self, limit: usize) -> Self {
    assert!(
      limit > 0 && limit % (64 * 1024) == 0,
      "code size limit must be a non-zero multiple of 64 KiB"
    );
    assert!(
      limit <= u32::MAX as usize,
      "code size limit must fit in u32"
    );
    self.code_size_limit = limit;
    self
  }

  /// Loads an ELF image into a new `UnboundProgram`.
  pub fn load(&self, rng: &mut impl rand::Rng, elf: &[u8]) -> Result<UnboundProgram, Error> {
    self._load(rng, elf).map_err(Error)
  }

  fn _load(&self, rng: &mut impl rand::Rng, elf: &[u8]) -> Result<UnboundProgram, RuntimeError> {
    let start_time = Instant::now();
    let cage = PointerCage::new(rng, SHADOW_STACK_SIZE, elf.len())?;

    let code_sections = {
      let mut data = cage.data_slice(cage.data_bottom(), elf.len()).unwrap();
      let data = unsafe { data.as_mut() };
      data.copy_from_slice(elf);

      link_elf(data, cage.data_bottom(), &self.helpers_inverse).map_err(RuntimeError::Linker)?
    };
    cage.freeze_data();

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size < 0 {
      return Err(RuntimeError::PlatformError("failed to get page size"));
    }
    let page_size = page_size as usize;

    let guard_size_before = rng.gen_range(16..128) * page_size;
    let guard_size_after = rng.gen_range(16..128) * page_size;

    let code_len_allocated = self.code_size_limit;
    let code_mem = MmapRaw::from(
      MmapOptions::new()
        .len(code_len_allocated + guard_size_before + guard_size_after)
        .map_anon()
        .map_err(|_| RuntimeError::PlatformError("failed to allocate code memory"))?,
    );
    let code_base = code_mem.as_ptr() as usize + guard_size_before;

    unsafe {
      if libc::mprotect(
        code_mem.as_mut_ptr() as *mut _,
        guard_size_before,
        libc::PROT_NONE,
      ) != 0
        || libc::mprotect(
          code_mem
            .as_mut_ptr()
            .offset((guard_size_before + code_len_allocated) as isize) as *mut _,
          guard_size_after,
          libc::PROT_NONE,
        ) != 0
        || libc::mprotect(
          code_mem.as_mut_ptr().offset(guard_size_before as isize) as *mut _,
          code_len_allocated,
          libc::PROT_NONE,
        ) != 0
      {
        return Err(RuntimeError::PlatformError("failed to protect code memory"));
      }
    }

    let mut entrypoints = HashMap::new();
    let mut sections = Vec::new();
    let resolvers = HashMap::new();
    let next_resolver_id = 1u32;

    for (section_name, code_vaddr_size) in code_sections {
      let vm = Vm::new(&cage);
      unsafe {
        if crate::ubpf::ubpf_register_external_dispatcher(
          vm.0.as_ptr(),
          Some(tls_dispatcher),
          Some(std_validator),
        ) != 0
        {
          return Err(RuntimeError::PlatformError(
            "ubpf: failed to register external dispatcher",
          ));
        }
      }

      let mut errmsg_ptr = std::ptr::null_mut();
      let code = cage
        .data_slice(code_vaddr_size.0, code_vaddr_size.1)
        .unwrap();
      let code_bytes =
        unsafe { std::slice::from_raw_parts(code.as_ptr() as *const u8, code.len()) };
      validate_local_call_graph(code_bytes).map_err(|err| {
        RuntimeError::InvalidArgumentOwned(format!(
          "local call graph validation failed in {section_name}: {err}"
        ))
      })?;
      let layout = analyze_functions(code_bytes).map_err(|err| {
        RuntimeError::InvalidArgumentOwned(format!(
          "local function analysis failed in {section_name}: {err}"
        ))
      })?;
      let ret = unsafe {
        let validation_scope = LoaderValidationScope::new(self);
        let ret = crate::ubpf::ubpf_load(
          vm.0.as_ptr(),
          code.as_ptr() as *const _,
          code.len() as u32,
          &mut errmsg_ptr,
        );
        drop(validation_scope);
        ret
      };
      if ret != 0 {
        let errmsg = unsafe {
          if errmsg_ptr.is_null() {
            "".to_string()
          } else {
            CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned()
          }
        };
        if !errmsg_ptr.is_null() {
          unsafe { libc::free(errmsg_ptr as _) };
        }
        tracing::error!(section_name, error = errmsg, "failed to load code");
        return Err(RuntimeError::InvalidArgumentOwned(format!(
          "ubpf: code load failed: {errmsg}"
        )));
      }

      let section_index = sections.len();

      entrypoints.insert(section_name, section_index);
      let functions = (0..layout.functions.len())
        .map(|_| FunctionState::default())
        .collect();
      sections.push(Section {
        vm,
        code_vaddr: code_vaddr_size.0,
        code_len: code_vaddr_size.1,
        layout,
        functions,
      });
    }

    tracing::info!(
      elf_size = elf.len(),
      native_code_addr = ?code_mem.as_ptr(),
      native_code_size_limit = code_len_allocated,
      guard_size_before,
      guard_size_after,
      duration = ?start_time.elapsed(),
      cage_ptr = ?cage.region().as_ptr(),
      cage_mapped_size = cage.region().len(),
      "loaded program for lazy jit"
    );

    Ok(UnboundProgram {
      id: NEXT_PROGRAM_ID.fetch_add(1, Ordering::Relaxed),
      _code_mem: code_mem,
      code_base,
      code_size: code_len_allocated,
      page_size,
      code_arena: RefCell::new(CodeArena { used: 0 }),
      cage,
      helper_id_xor: self.helper_id_xor,
      helpers: self.helpers.clone(),
      event_listener: self.event_listener.clone(),
      require_static_regions: self.require_static_regions,
      entrypoints,
      sections: RefCell::new(sections),
      resolvers: RefCell::new(resolvers),
      next_resolver_id: Cell::new(next_resolver_id),
    })
  }
}

#[derive(Default)]
struct Dispatch {
  async_preemption: bool,
  memory_access_error: Option<usize>,
  lazy_local_call: Option<u32>,

  index: u32,
  arg1: u64,
  arg2: u64,
  arg3: u64,
  arg4: u64,
  arg5: u64,
}

unsafe extern "C" fn tls_dispatcher(
  arg1: u64,
  arg2: u64,
  arg3: u64,
  arg4: u64,
  arg5: u64,
  index: std::os::raw::c_uint,
  _cookie: *mut std::os::raw::c_void,
) -> u64 {
  let yielder = ACTIVE_JIT_CODE_ZONE
    .with(|x| x.yielder.get())
    .expect("no yielder");
  let yielder = yielder.as_ref();
  let ret = yielder.suspend(Dispatch {
    async_preemption: false,
    memory_access_error: None,
    lazy_local_call: None,
    index,
    arg1,
    arg2,
    arg3,
    arg4,
    arg5,
  });
  ret
}

unsafe extern "C" fn tls_local_call_resolver(resolver_id: std::os::raw::c_uint) -> u64 {
  let program = ACTIVE_PROGRAM.with(|x| x.get());
  if !program.is_null() {
    if let Some(ptr) = (*program).cached_resolver_target(resolver_id) {
      return ptr as u64;
    }
  }

  let yielder = ACTIVE_JIT_CODE_ZONE
    .with(|x| x.yielder.get())
    .expect("no yielder");
  let yielder = yielder.as_ref();
  yielder.suspend(Dispatch {
    lazy_local_call: Some(resolver_id),
    ..Default::default()
  })
}

unsafe extern "C" fn std_validator(
  index: std::os::raw::c_uint,
  _vm: *const crate::ubpf::ubpf_vm,
) -> bool {
  let loader = LOADING_PROGRAM_LOADER.with(|x| x.get());
  if loader.is_null() {
    return false;
  }
  let loader = &*loader;
  let entropy = (index >> 16) & 0xffff;
  let index = (((index & 0xffff) as u16) ^ loader.helper_id_xor).wrapping_sub(1);
  loader.helpers.get(index as usize).map(|x| x.0) == Some(entropy as u16)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
unsafe fn program_counter(uctx: *mut libc::ucontext_t) -> usize {
  (*uctx).uc_mcontext.gregs[libc::REG_RIP as usize] as usize
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe fn program_counter(uctx: *mut libc::ucontext_t) -> usize {
  (*uctx).uc_mcontext.pc as usize
}

#[cfg(all(target_arch = "x86_64", target_os = "openbsd"))]
unsafe fn program_counter(uctx: *mut libc::ucontext_t) -> usize {
  (*uctx).sc_rip as usize
}

#[cfg(all(target_arch = "aarch64", target_os = "openbsd"))]
unsafe fn program_counter(uctx: *mut libc::ucontext_t) -> usize {
  (*uctx).sc_elr as usize
}

unsafe extern "C" fn sigsegv_handler(
  _sig: i32,
  siginfo: *mut libc::siginfo_t,
  uctx: *mut libc::ucontext_t,
) {
  let fail = || restore_default_signal_handler(libc::SIGSEGV);

  let Some((jit_code_zone, pointer_cage, yielder)) = ACTIVE_JIT_CODE_ZONE.with(|x| {
    if x.valid.load(Ordering::Relaxed) {
      compiler_fence(Ordering::Acquire);
      Some((
        x.code_range.get(),
        x.pointer_cage_protected_range.get(),
        x.yielder.get(),
      ))
    } else {
      None
    }
  }) else {
    return fail();
  };

  let pc = program_counter(uctx);

  if pc < jit_code_zone.0 || pc >= jit_code_zone.1 {
    return fail();
  }

  // SEGV_MAPERR or SEGV_ACCERR.
  if (*siginfo).si_code != 1 && (*siginfo).si_code != 2 {
    return fail();
  }

  let si_addr = (*siginfo).si_addr() as usize;
  if si_addr < pointer_cage.0 || si_addr >= pointer_cage.1 {
    return fail();
  }

  let yielder = yielder.expect("no yielder").as_ref();
  yielder.suspend(Dispatch {
    memory_access_error: Some(si_addr),
    ..Default::default()
  });
}

unsafe extern "C" fn sigusr1_handler(
  _sig: i32,
  _siginfo: *mut libc::siginfo_t,
  uctx: *mut libc::ucontext_t,
) {
  SIGUSR1_COUNTER.with(|x| x.set(x.get() + 1));

  let Some((jit_code_zone, yielder)) = ACTIVE_JIT_CODE_ZONE.with(|x| {
    if x.valid.load(Ordering::Relaxed) {
      compiler_fence(Ordering::Acquire);
      Some((x.code_range.get(), x.yielder.get()))
    } else {
      None
    }
  }) else {
    return;
  };
  let pc = program_counter(uctx);
  if pc < jit_code_zone.0 || pc >= jit_code_zone.1 {
    return;
  }

  // A signal can arrive after the active zone is published but before the
  // coroutine has installed its yielder on its first resume.
  let Some(yielder) = yielder else {
    return;
  };
  yielder.as_ref().suspend(Dispatch {
    async_preemption: true,
    ..Default::default()
  });
}

unsafe fn restore_default_signal_handler(signum: i32) {
  let mut act: libc::sigaction = std::mem::zeroed();
  act.sa_sigaction = libc::SIG_DFL;
  act.sa_flags = libc::SA_SIGINFO;
  if libc::sigaction(signum, &act, std::ptr::null_mut()) != 0 {
    libc::abort();
  }
}

fn get_blocked_sigset() -> libc::sigset_t {
  unsafe {
    let mut s: libc::sigset_t = std::mem::zeroed();
    libc::sigaddset(&mut s, libc::SIGUSR1);
    libc::sigaddset(&mut s, libc::SIGSEGV);
    s
  }
}

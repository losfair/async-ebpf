//! This module contains the core logic for eBPF program execution. A lot of
//! `unsafe` code is used - be careful when making changes here.

use std::{
  any::{Any, TypeId},
  cell::{Cell, RefCell},
  collections::HashMap,
  marker::PhantomData,
  mem::ManuallyDrop,
  ops::{Deref, DerefMut},
  pin::Pin,
  ptr::NonNull,
  rc::Rc,
  sync::{
    atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering},
    Arc, Once, OnceLock,
  },
  task::{Context, Poll},
  thread::ThreadId,
  time::{Duration, Instant},
};

use futures::{task::noop_waker_ref, Future, FutureExt};
use memmap2::{MmapOptions, MmapRaw};
use parking_lot::{Condvar, Mutex, RwLock};
use rand::prelude::SliceRandom;

use crate::{
  coroutine::{
    stack::{DefaultStack, Stack},
    Coroutine, CoroutineResult, ScopedCoroutine, Yielder,
  },
  error::{Error, RuntimeError},
  function_analysis::{analyze_functions, FunctionLayout},
  helpers::Helper,
  linker::{link_elf, plan_writable_data},
  pointer_cage::PointerCage,
  region_analysis::PointerSignature,
  util::nonnull_bytes_overlap,
};

/// Native stack left below the deepest admitted JIT frame for the entry
/// trampoline, resolver/dispatcher callbacks, and the stack-exhaustion path.
const NATIVE_STACK_RESERVE: usize = 16 * 1024;
pub(crate) const MAX_CALLDATA_SIZE: usize = 512;

/// Guest stack carried by the historical eight-frame default. Call graphs are
/// no longer capped statically: a run may recurse until its configured stack
/// window cannot hold the next complete frame.
const DEFAULT_LOCAL_CALL_FRAME_BUDGET: usize = crate::jit::abi::EBPF_STACK_SIZE as usize;

/// The guest stack window.
///
/// Calldata is copied into the top of this window and `R10` starts at the first
/// 8-aligned address below it, so the window has to cover the frame budget *and*
/// the largest calldata a caller can pass. Sizing it to the frame budget alone
/// leaves no slack: the eighth default frame would then run off the bottom of
/// the stack by as much calldata as was passed, and a program that works with
/// none would fault with any.
pub const DEFAULT_GUEST_STACK_SIZE: usize =
  DEFAULT_LOCAL_CALL_FRAME_BUDGET + MAX_CALLDATA_SIZE.next_multiple_of(8);
const MAX_MUTABLE_DEREF_REGIONS: usize = 4;
const MAX_IMMUTABLE_DEREF_REGIONS: usize = 16;

/// Displacement below `R10` that a frame access may use without a runtime bounds
/// check.
///
/// This is the one place the runtime trades a per-access check for a static
/// argument, so the argument is worth spelling out. `R10` starts at
/// `stack_top - calldata`, rounded down to 8, and drops one
/// [`crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE`] frame per local call. Before
/// every local call the backend checks that the callee's R10 will leave this
/// complete window above the invocation's stack bottom. The entry trampoline
/// establishes the same invariant for the root. `[r10 + k]` with
/// `-FRAME_WINDOW <= k` and `k + width <= 0` is therefore inside the guarded
/// guest-stack backing at every admitted dynamic depth, which is what lets the
/// backend emit it as a plain native access.
///
/// `src/test/lazy_local_call.rs::the_default_call_capacity_fits_alongside_calldata`
/// exercises exactly this corner at run time.
pub(crate) const FRAME_WINDOW: usize = crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE as usize;

/// Guest addresses the SIGSEGV/SIGBUS handlers claim as a guest fault rather
/// than a host crash: `(0, POINTER_CAGE_PROTECTED_WINDOW)`.
///
/// A bounds check that fails substitutes address 0, so this is the window every
/// failed access has to land in. An access group makes that load-bearing at a
/// distance: a failed leader parks base 0 and its members then dereference
/// `[0 + delta]`, so the group span has to fit here too. Three constants in
/// three files have to agree about that page - this one, `MAX_GROUP_SPAN` in
/// the analysis, and `JIT_MAX_GROUP_SPAN` in the backend - and if they ever
/// drift apart the symptom is a legitimate guest aborting the process rather
/// than taking a fault. The assertion below ties the first two together.
pub(crate) const POINTER_CAGE_PROTECTED_WINDOW: usize = 4096;

const _: () = {
  assert!(
    crate::region_analysis::MAX_GROUP_SPAN as usize <= POINTER_CAGE_PROTECTED_WINDOW,
    "an access group can span further than the guard window the fault handler \
     claims, so a group off a bad base would abort the process instead of faulting"
  );
  assert!(
    crate::region_analysis::MAX_GROUP_SPAN == crate::jit::abi::MAX_GROUP_SPAN as i32,
    "the analysis and the backend disagree about how wide an access group may be"
  );
};

// What Tier F needs from the guest stack window, stated as the facts that
// can each drift on their own.
//
// The obvious phrasing - "DEFAULT_GUEST_STACK_SIZE, less the calldata, less the frames
// below the entry one, still leaves FRAME_WINDOW" - cannot fail. Substituting
// the definition of DEFAULT_GUEST_STACK_SIZE cancels the calldata term against itself
// and the budget against the frames, leaving `FRAME_WINDOW >= FRAME_WINDOW`:
// true for every value of every constant it names, including all the ones it is
// supposed to be watching. Each assertion below is instead written against
// constants that are *not* derived from the one being checked, so raising
// MAX_CALLDATA_SIZE, charging a local function more than one frame, or
// redefining the window all fail the build rather than quietly eating the
// margin Tier F addresses within.
const _: () = {
  // 1. The unchecked window fits in the frame every local call is charged.
  assert!(
    FRAME_WINDOW <= crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE as usize,
    "the Tier F frame window is wider than the frame a local call is charged, \
     so an admitted dynamic frame can address below the guest stack"
  );
  // 2. The historical default really does retain eight complete frames.
  assert!(
    DEFAULT_LOCAL_CALL_FRAME_BUDGET >= crate::jit::abi::EBPF_STACK_SIZE as usize,
    "the default local-call frame budget no longer covers the ABI default"
  );
  // 3. The window covers that budget *and* the largest calldata a caller can
  //    pass, rounded the way R10's 8-alignment rounds it.
  assert!(
    DEFAULT_GUEST_STACK_SIZE
      >= DEFAULT_LOCAL_CALL_FRAME_BUDGET + MAX_CALLDATA_SIZE.next_multiple_of(8),
    "the guest stack window no longer covers FRAME_WINDOW below the deepest \
     accepted frame pointer; Tier F frame addressing would be unsound"
  );
  // 4. R10 starts at the first 8-aligned address below the calldata, which the
  //    runtime computes with `& !0x7`. Assertion 3 models that rounding as
  //    `next_multiple_of(8)` of the calldata size, and the two agree only while
  //    the top of the window is itself 8-aligned. That follows today from the
  //    guard being page-aligned and the window being a multiple of 8, but
  //    nothing else says so, so say it here - `_run` re-checks the address the
  //    cage actually hands back.
  assert!(
    DEFAULT_GUEST_STACK_SIZE.is_multiple_of(8),
    "the guest stack window is not a multiple of 8, so R10's alignment rounding \
     eats into the headroom Tier F frame addressing depends on"
  );
};

// `extern "C"` applies the leading underscore to this symbol on Darwin, but
// global assembly names are passed through verbatim. Keep the object-format
// spelling here alongside the ELF type/size directives that Mach-O rejects.
#[cfg(target_os = "macos")]
macro_rules! entry_trampoline_begin {
  () => {
    ".global _async_ebpf_entry_trampoline\n.private_extern \
     _async_ebpf_entry_trampoline\n_async_ebpf_entry_trampoline:\n"
  };
}

#[cfg(all(not(target_os = "macos"), target_arch = "x86_64"))]
macro_rules! entry_trampoline_begin {
  () => {
    ".global async_ebpf_entry_trampoline\n.type \
     async_ebpf_entry_trampoline,@function\nasync_ebpf_entry_trampoline:\n"
  };
}

#[cfg(all(not(target_os = "macos"), target_arch = "aarch64"))]
macro_rules! entry_trampoline_begin {
  () => {
    ".global async_ebpf_entry_trampoline\n.type \
     async_ebpf_entry_trampoline,%function\nasync_ebpf_entry_trampoline:\n"
  };
}

#[cfg(target_os = "macos")]
macro_rules! entry_trampoline_end {
  () => {
    ""
  };
}

#[cfg(not(target_os = "macos"))]
macro_rules! entry_trampoline_end {
  () => {
    ".size async_ebpf_entry_trampoline, . - async_ebpf_entry_trampoline\n"
  };
}

#[cfg(all(
  target_arch = "x86_64",
  any(target_os = "linux", target_os = "macos", target_os = "openbsd")
))]
std::arch::global_asm!(
  entry_trampoline_begin!(),
  r#"
    // rdi = target, rsi = ctx, rcx = guest stack bottom, r8 = guest stack len,
    // [rsp + 8] = JitMemory descriptor. The entry target is staged through r9
    // and then rcx, neither of which the backend maps to an eBPF register, so
    // it can be called after the register scrub below. r11 is the backend's
    // volatile context register.
    mov r9, rdi
    mov rax, [rsp + 8]
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    // r15 carries eBPF r10, and it carries the *native* frame pointer rather
    // than the guest one - this is what `jit::Config::native_frame_base`
    // promises the backend. Guest-to-native translation for the stack region is
    // the affine shift `native_base - guest_bottom`, so applying it once here to
    // the entry frame is enough: the backend only ever adds and subtracts frame
    // sizes from r10, and that commutes with the shift. What it buys is a frame
    // access emitted as one native instruction instead of a bounds check and a
    // translation.
    //
    // rdx is free by here (the guest sees it scrubbed below), so use it to
    // carry the delta into the frame slot the backend reads when a program
    // needs the guest value of r10 back. [rax + 16] is
    // JitMemory::stack_native_base and [rbp - 40] is the backend's
    // JIT_MEMORY_FRAME_DELTA_OFFSET; both are asserted below.
    mov rdx, [rax + 16]
    sub rdx, rcx
    mov r15, rcx
    add r15, r8
    add r15, rdx
    mov rdi, rsi
    sub rsp, 8
    mov rbp, rsp
    sub rsp, 160
    mov [rbp - 8], rax
    mov [rbp - 40], rdx
    // Copy JitMemory::derived - the twelve bounds-check constants - into the
    // frame, where the backend reads them off rbp without a descriptor load -
    // this is what `jit::Config::frame_constants` promises. The layout is
    // `jit::abi::derived_slot`. xmm0 keeps this to twelve instructions
    // without disturbing any of the registers still carrying guest state; the
    // guest has no way to name an xmm register, and these are guest-space
    // bounds rather than host addresses, but it is cleared afterwards anyway.
    movdqu xmm0, [rax + 48]
    movdqu [rbp - 136], xmm0
    movdqu xmm0, [rax + 64]
    movdqu [rbp - 120], xmm0
    movdqu xmm0, [rax + 80]
    movdqu [rbp - 104], xmm0
    movdqu xmm0, [rax + 96]
    movdqu [rbp - 88], xmm0
    movdqu xmm0, [rax + 112]
    movdqu [rbp - 72], xmm0
    movdqu xmm0, [rax + 128]
    movdqu [rbp - 56], xmm0
    pxor xmm0, xmm0
    // The access-group base slot. The backend only reads it after emitting the
    // leader that writes it, so this is belt and braces - but it costs one
    // instruction per invocation and turns any future hole in that reasoning
    // into a fault at page 0 rather than a dereference of whatever the host
    // stack happened to hold.
    mov qword ptr [rbp - 144], 0
    mov rcx, r9
    mov r11, rdi
    // Scrub every register the guest can name (the backend maps eBPF r0-r10 to
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
"#,
  entry_trampoline_end!(),
);

#[cfg(all(
  target_arch = "aarch64",
  any(target_os = "linux", target_os = "macos", target_os = "openbsd")
))]
std::arch::global_asm!(
  entry_trampoline_begin!(),
  r#"
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
    // x23 carries eBPF r10, and it carries the *native* frame pointer rather
    // than the guest one - this is what `jit::Config::native_frame_base`
    // promises the backend. Guest-to-native
    // translation for the stack region is the affine shift
    // `native_base - guest_bottom`, so applying it once here to the entry frame
    // is enough: the backend only ever adds and subtracts frame sizes from r10,
    // and that commutes with the shift.
    ldr x7, [x6, #16]
    sub x7, x7, x3
    add x23, x3, x4
    add x23, x23, x7
    mov x0, x1
    sub sp, sp, #160
    str x6, [x29, #-8]
    // The delta that recovers the guest value of r10 where a program reads it
    // as a value rather than as a memory base.
    str x7, [x29, #-40]
    // The twelve derived bounds-check constants, copied from JitMemory::derived
    // into [x29-136, x29-40) where the backend reads them off the frame pointer
    // without a descriptor load, as `jit::Config::frame_constants` promises.
    // The layout is `jit::abi::derived_slot`.
    ldp x7, x16, [x6, #48]
    stp x7, x16, [x29, #-136]
    ldp x7, x16, [x6, #64]
    stp x7, x16, [x29, #-120]
    ldp x7, x16, [x6, #80]
    stp x7, x16, [x29, #-104]
    ldp x7, x16, [x6, #96]
    stp x7, x16, [x29, #-88]
    ldp x7, x16, [x6, #112]
    stp x7, x16, [x29, #-72]
    ldp x7, x16, [x6, #128]
    stp x7, x16, [x29, #-56]
    // The access-group base slot. The backend only reads it after emitting the
    // leader that writes it; zeroing turns any hole in that reasoning into a
    // fault at page 0 rather than a dereference of stale host stack.
    str xzr, [x29, #-144]
    mov x7, xzr
    mov x16, xzr
    mov x26, x0
    // Scrub every register the guest can name (the backend maps eBPF r0-r10 to
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
"#,
  entry_trampoline_end!(),
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
  writable_data: bool,
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
  ///
  /// # Panics
  ///
  /// Panics if called from a context that cannot post a task - an async task's
  /// own completion callback, most notably - or if this invocation has already
  /// posted one. Both are helper bugs rather than anything a guest can provoke:
  /// a guest chooses *which* helper runs, not how that helper uses its scope.
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
    let Some(region) = self.memory.safe_deref_for_write(
      ptr as usize,
      size as usize,
      self
        .writable_data
        .then_some(self.program.unbound.cage.writable_data_bottom()),
    ) else {
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

/// Native backing for one invocation-local guest region, in its own mapping
/// with a `PROT_NONE` page on each side.
///
/// The guest stack used to be a plain heap allocation, which was fine while
/// every guest access carried a runtime bounds check: an out-of-range address
/// was rejected before it was ever dereferenced. Tier F frame accesses are
/// emitted without that check, on the static argument recorded at
/// [`FRAME_WINDOW`]. Guard pages are what turns a mistake in that argument - or
/// in the backend test that enforces it - into a fault instead of a silent read
/// or write of whatever the allocator happened to place next to the stack.
///
/// This backs the guest stack. The usable
/// window is laid out flush against the low guard, which is load-bearing for
/// the stack because `R10` descends with call depth and every frame displacement
/// is negative. For data, both guards are defense in depth around the JIT's
/// explicit region checks.
struct GuardedRegion {
  region: MmapRaw,
  offset: usize,
  len: usize,
}

impl GuardedRegion {
  fn new(size: usize) -> Result<Self, RuntimeError> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
      return Err(RuntimeError::PlatformError("failed to query page size"));
    }
    let page_size = page_size as usize;
    let len = size.next_multiple_of(page_size);
    let total = len + 2 * page_size;

    let region = MmapRaw::from(
      MmapOptions::new()
        .len(total)
        .map_anon()
        .map_err(|_| RuntimeError::PlatformError("failed to allocate guarded guest memory"))?,
    );
    unsafe {
      if libc::mprotect(region.as_ptr() as *mut _, total, libc::PROT_NONE) != 0
        || libc::mprotect(
          region.as_ptr().add(page_size) as *mut _,
          len,
          libc::PROT_READ | libc::PROT_WRITE,
        ) != 0
      {
        return Err(RuntimeError::PlatformError(
          "failed to protect guarded guest memory",
        ));
      }
    }

    Ok(Self {
      region,
      offset: page_size,
      len: size,
    })
  }

  fn as_mut_slice(&mut self) -> &mut [u8] {
    unsafe {
      std::slice::from_raw_parts_mut(self.region.as_ptr().add(self.offset) as *mut u8, self.len)
    }
  }

  fn as_mut_ptr(&mut self) -> *mut u8 {
    unsafe { self.region.as_ptr().add(self.offset) as *mut u8 }
  }

  fn len(&self) -> usize {
    self.len
  }
}

struct ExecContext {
  native_stack: DefaultStack,
  guest_stack: GuardedRegion,
}

fn native_stack_size(guest_stack_size: usize) -> usize {
  let guest_frame = crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE as usize;
  let frame_capacity = guest_stack_size.div_ceil(guest_frame);
  NATIVE_STACK_RESERVE
    .checked_add(
      frame_capacity
        .checked_mul(crate::jit::abi::NATIVE_LOCAL_CALL_BUDGET)
        .expect("native local-call stack budget overflow"),
    )
    .expect("native coroutine stack size overflow")
}

#[cfg(test)]
#[test]
fn native_coroutine_stack_is_derived_but_smaller_than_the_guest_stack() {
  let guest_stack_size = 8 * 1024 * 1024;
  assert_eq!(
    native_stack_size(guest_stack_size),
    NATIVE_STACK_RESERVE
      + guest_stack_size / crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE as usize
        * crate::jit::abi::NATIVE_LOCAL_CALL_BUDGET
  );
  assert!(native_stack_size(guest_stack_size) < guest_stack_size);
  assert!(native_stack_size(DEFAULT_GUEST_STACK_SIZE) < DEFAULT_GUEST_STACK_SIZE);
}

impl ExecContext {
  fn new(guest_stack_size: usize) -> Self {
    Self {
      // A guest frame is 4 KiB but its persistent native call frame is under
      // 128 bytes on both backends. Charge a deliberately conservative 256
      // bytes per possible guest frame, plus a fixed reserve for transient Rust
      // resolver/dispatcher frames and the stack-exhaustion callback.
      native_stack: DefaultStack::new(native_stack_size(guest_stack_size))
        .expect("failed to initialize native stack"),
      guest_stack: GuardedRegion::new(guest_stack_size).expect("failed to initialize guest stack"),
    }
  }
}

/// Access widths a single guest memory instruction can have, in the order the
/// backend's span slots expect. Mirrors [`crate::jit::abi::ACCESS_WIDTHS`],
/// which is what `jit::abi::span_slot_index` indexes with.
const ACCESS_WIDTHS: [usize; 4] = [1, 2, 4, 8];

#[repr(C)]
struct JitMemory {
  stack_guest_bottom: usize,
  stack_guest_top: usize,
  stack_native_base: usize,
  data_guest_bottom: usize,
  data_guest_top: usize,
  data_native_base: usize,
  /// Everything a single-region bounds check needs, derived once here instead
  /// of being rebuilt from the fields above at every guest memory access. The
  /// entry trampoline copies the block into the frame, where the backend reads
  /// it off `RBP` directly. See [`crate::jit::abi::derived_slot`] for the
  /// layout.
  derived: [usize; 12],
  /// Lowest native R10 from which a local call can leave a complete frame for
  /// its callee below the resulting frame pointer.
  local_call_guest_floor: usize,
  /// Lowest native SP from which a local call can consume its conservative
  /// native frame budget without entering the emergency reserve.
  local_call_native_floor: usize,
}

/// The entry trampoline reaches into this layout with literal displacements,
/// and so does the JIT backend (see [`crate::jit::abi::memory`]). Nothing else
/// ties the three together, so tie them here.
const _: () = {
  assert!(std::mem::offset_of!(JitMemory, stack_guest_bottom) == 0);
  assert!(std::mem::offset_of!(JitMemory, stack_guest_top) == 8);
  assert!(std::mem::offset_of!(JitMemory, stack_native_base) == 16);
  assert!(std::mem::offset_of!(JitMemory, data_guest_bottom) == 24);
  assert!(std::mem::offset_of!(JitMemory, data_guest_top) == 32);
  assert!(std::mem::offset_of!(JitMemory, data_native_base) == 40);
  assert!(std::mem::offset_of!(JitMemory, derived) == 48);
  assert!(std::mem::offset_of!(JitMemory, local_call_guest_floor) == 144);
  assert!(std::mem::offset_of!(JitMemory, local_call_native_floor) == 152);
  assert!(std::mem::size_of::<JitMemory>() == 160);
};

impl JitMemory {
  /// Derives the twelve bounds-check constants from the six region fields.
  ///
  /// The check the backend emits is a single unsigned comparison: with
  /// `off = guest - bottom`, an access of width `w` is in range exactly when
  /// `off <= (top - w) - bottom`. Both operands are invariant for the whole
  /// invocation, so precomputing them here is the difference between a bounds
  /// check that reloads and re-derives them every time and one that reads two
  /// frame slots.
  fn fill_derived(&mut self) {
    // A region narrower than the width being checked makes `(top - w) - bottom`
    // wrap, and the single unsigned comparison would then accept *every* address
    // for that region - a complete bypass of the cage, not a near miss.
    //
    // The width that matters is not the widest single access. A group leader
    // checks its whole window at once, so `w` reaches `MAX_GROUP_SPAN`. Both
    // regions are comfortably larger than that and `PointerCage::new` refuses to
    // build one that is not, so this is a restatement of a load-time invariant
    // rather than a live check - which is why it is a debug assertion here and
    // an error there.
    debug_assert!(
      self.stack_guest_top - self.stack_guest_bottom
        >= crate::region_analysis::MAX_GROUP_SPAN as usize
        && self.data_guest_top - self.data_guest_bottom
          >= crate::region_analysis::MAX_GROUP_SPAN as usize,
      "a guest region is narrower than the widest window a bounds check can be asked for"
    );

    let mut slot = 0;
    for (bottom, top, native_base) in [
      (
        self.stack_guest_bottom,
        self.stack_guest_top,
        self.stack_native_base,
      ),
      (
        self.data_guest_bottom,
        self.data_guest_top,
        self.data_native_base,
      ),
    ] {
      self.derived[slot] = bottom;
      self.derived[slot + 1] = native_base.wrapping_sub(bottom);
      for (i, width) in ACCESS_WIDTHS.iter().enumerate() {
        self.derived[slot + 2 + i] = (top - width) - bottom;
      }
      slot += 2 + ACCESS_WIDTHS.len();
    }
    debug_assert_eq!(slot, self.derived.len());
  }

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

  fn safe_deref_for_write(
    &self,
    guest: usize,
    size: usize,
    writable_data_bottom: Option<usize>,
  ) -> Option<NonNull<[u8]>> {
    let stack = Self::checked_region(
      guest,
      size,
      self.stack_guest_bottom,
      self.stack_guest_top,
      self.stack_native_base,
    );
    if let Some(writable_data_bottom) = writable_data_bottom {
      stack.or_else(|| {
        Self::checked_region(
          guest,
          size,
          writable_data_bottom,
          self.data_guest_top,
          self.data_native_base + (writable_data_bottom - self.data_guest_bottom),
        )
      })
    } else {
      stack
    }
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

/// The per-thread handle onto that thread's preemption watcher.
struct PreemptionStateSignal {
  state: Mutex<PreemptionState>,
  changed: Condvar,
  /// Set when the watcher stops for any reason other than an orderly shutdown -
  /// a failed `tgkill`/`pthread_kill`, or a panic in the watcher itself.
  ///
  /// Preemption is asynchronous and has no cooperative fallback, so a watcher
  /// that has stopped means a guest resumed on this thread can hold the OS
  /// thread for as long as it likes: the reactor and timer wheel stop with it,
  /// and there is no await point at which the run could be cancelled. The
  /// thread never gets a watcher back either, because `init_thread` sees the
  /// `WATCHER` slot already filled and returns early. `Program::run` reads this
  /// and refuses to start rather than wedging the runtime.
  watcher_failed: AtomicBool,
}

thread_local! {
  static RUST_TID: ThreadId = std::thread::current().id();
  static SIGUSR1_COUNTER: Cell< u64> = Cell::new(0);
  static ACTIVE_JIT_CODE_ZONE: ActiveJitCodeZone = ActiveJitCodeZone::default();
  static EXEC_CONTEXT_POOL: RefCell<Vec<ExecContext>> = Default::default();
  static PENDING_ASYNC_TASK: RefCell<Option<PendingAsyncTask>> = RefCell::new(None);
  static PREEMPTION_STATE: Arc<PreemptionStateSignal> = Arc::new(PreemptionStateSignal {
    state: Mutex::new(PreemptionState::Inactive),
    changed: Condvar::new(),
    watcher_failed: AtomicBool::new(false),
  });
  static LOADING_PROGRAM_LOADER: Cell<*const ProgramLoader> = const { Cell::new(std::ptr::null()) };
  static ACTIVE_PROGRAM: Cell<*const Program> = const { Cell::new(std::ptr::null()) };
}

struct BorrowedExecContext {
  ctx: ManuallyDrop<ExecContext>,
}

impl BorrowedExecContext {
  fn new(guest_stack_size: usize) -> Self {
    let mut me = Self {
      ctx: ManuallyDrop::new(EXEC_CONTEXT_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        let ctx = pool
          .iter()
          .position(|ctx| ctx.guest_stack.len() == guest_stack_size)
          .map(|index| pool.swap_remove(index));
        ctx.unwrap_or_else(|| ExecContext::new(guest_stack_size))
      })),
    };
    me.ctx.guest_stack.as_mut_slice().fill(0x8e);
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
  data_range: Cell<(usize, usize)>,
  yielder: Cell<Option<NonNull<Yielder<u64, Dispatch>>>>,
}

#[cfg(test)]
pub(crate) fn active_jit_state_is_clear_for_tests() -> bool {
  let zone_is_clear =
    ACTIVE_JIT_CODE_ZONE.with(|x| !x.valid.load(Ordering::Relaxed) && x.yielder.get().is_none());
  let program_is_clear = ACTIVE_PROGRAM.with(|x| x.get().is_null());
  zone_is_clear && program_is_clear
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
  instruction_limit: usize,
  guest_stack_size: usize,
  require_static_regions: bool,
}

/// A loaded program that is not yet pinned to a thread.
pub struct UnboundProgram {
  id: u64,
  _code_mem: MmapRaw,
  code_base: usize,
  code_size: usize,
  page_size: usize,
  guest_stack_size: usize,
  run_lock: RwLock<()>,
  data_protection_failed: Cell<bool>,
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
  /// Set when the code arena becomes unusable. Unlike a per-variant compilation
  /// failure, this is terminal for the whole program: a full arena cannot grow,
  /// and a page-protection failure leaves code permissions indeterminate.
  /// Recorded here so later runs fail before entering previously generated code.
  code_exhausted: RefCell<Option<RuntimeError>>,
}

/// A program pinned to a specific thread and ready to execute.
///
/// Pinned in earnest: this must stay neither `Send` nor `Sync`, because the
/// future [`Program::run`] returns borrows it, and that future must not be
/// spawnable onto a work-stealing executor. A guest suspends inside the SIGUSR1
/// handler, so resuming it on a second worker would run the `sigreturn` and the
/// unblocking `sigprocmask` on a thread that never took the signal - leaving
/// SIGUSR1, SIGSEGV, and SIGBUS blocked forever on the thread that did, with
/// neither preemption nor guest fault handling. The watcher would also still
/// be signalling the original thread, and the pooled `ExecContext` would
/// migrate with it.
///
/// `ThreadEnv`'s `PhantomData<*const ()>` and the `Rc` in `data` are what
/// establish this today; the doctests pin it so a future change to either has
/// to come with a decision about the above rather than silently making the
/// future spawnable. A wrapper asserting `Send` over the live coroutine used to
/// stand here instead, which hid exactly this reasoning.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<async_ebpf::Program>();
/// ```
///
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<async_ebpf::Program>();
/// ```
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
  translator: crate::jit::Translator,
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
#[cfg(any(target_os = "macos", target_os = "openbsd"))]
type NativeThread = libc::pthread_t;

#[cfg(target_os = "linux")]
unsafe fn current_native_thread() -> NativeThread {
  (libc::getpid(), libc::gettid())
}

#[cfg(any(target_os = "macos", target_os = "openbsd"))]
unsafe fn current_native_thread() -> NativeThread {
  libc::pthread_self()
}

#[cfg(target_os = "linux")]
unsafe fn signal_native_thread(thread: NativeThread, signal: i32) -> i32 {
  libc::syscall(libc::SYS_tgkill, thread.0, thread.1, signal) as i32
}

#[cfg(any(target_os = "macos", target_os = "openbsd"))]
unsafe fn signal_native_thread(thread: NativeThread, signal: i32) -> i32 {
  libc::pthread_kill(thread, signal)
}

impl GlobalEnv {
  /// Initializes global state and installs signal handlers.
  ///
  /// # Safety
  ///
  /// Must be called in a process that can install SIGUSR1/SIGSEGV/SIGBUS
  /// handlers.
  ///
  /// The effect is **process-wide**, not scoped to this crate's threads: it
  /// replaces whatever dispositions SIGUSR1, SIGSEGV, and SIGBUS had. Notably
  /// that includes the SIGSEGV handler Rust's standard library installs to
  /// report thread stack overflow, so a host stack overflow reports as a plain
  /// segmentation fault while this is installed. The previous fault
  /// dispositions are kept and restored for any fault this crate determines
  /// is not its own, so another component's handler still sees those - but it
  /// does not see them *first*, and a component that needs to run before this
  /// one cannot be accommodated.
  ///
  /// An embedder sharing the process with another SIGSEGV/SIGBUS user - a
  /// garbage collector, another JIT, a crash reporter, a
  /// `userfaultfd`-style mapper - should know this before calling.
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
        (libc::SIGSEGV, fault_handler as *const () as usize),
        (libc::SIGBUS, fault_handler as *const () as usize),
      ] {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handler;
        // SA_RESTART: the watcher signals its thread every interval for as long
        // as any `PreemptionEnabled` is alive, whether or not a guest is
        // actually running, so a thread parked in a syscall takes those signals
        // too. Without this each one surfaces as EINTR to whatever the host was
        // doing - an embedder's blocking FFI in a helper, a third-party crate's
        // libc call - and not every caller retries.
        act.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        act.sa_mask = sa_mask;
        let mut prev: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(sig, &act, &mut prev) != 0 {
          panic!("failed to setup handler for signal {}", sig);
        }
        if sig == libc::SIGSEGV || sig == libc::SIGBUS {
          // Kept so a fault this crate does not own can go back to whoever was
          // handling the signal before - Rust's own stack-overflow reporter, a
          // crash reporter, another runtime's guard pages - instead of being
          // converted into an abort. See `chain_to_previous_fault_handler`.
          if sig == libc::SIGSEGV {
            let _ = PREV_SIGSEGV.set(prev);
          } else {
            let _ = PREV_SIGBUS.set(prev);
          }
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
        *x.state.lock() = PreemptionState::Shutdown;
        x.changed.notify_one();
      }
    }

    /// Marks the watcher as failed unless it left through the shutdown arm.
    /// Covers a panic in the watcher as well as the signal failure below, since
    /// either leaves the thread just as unpreemptible.
    struct WatcherExitGuard {
      shared: Arc<PreemptionStateSignal>,
      orderly: bool,
    }
    impl Drop for WatcherExitGuard {
      fn drop(&mut self) {
        if !self.orderly {
          self.shared.watcher_failed.store(true, Ordering::SeqCst);
        }
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
          let mut exit = WatcherExitGuard {
            shared: preemption_state.clone(),
            orderly: false,
          };
          let mut state = preemption_state.state.lock();
          let _ = ready_tx.send(());
          loop {
            match *state {
              PreemptionState::Shutdown => {
                exit.orderly = true;
                break;
              }
              PreemptionState::Inactive => {
                preemption_state.changed.wait(&mut state);
              }
              PreemptionState::Armed(_) => {
                let timeout = preemption_state.changed.wait_while_for(
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
                      // The thread is now unpreemptible for the rest of its
                      // life, and `init_thread` will not replace this watcher.
                      // Leave the guard set to failed so `run` refuses work
                      // here rather than letting a guest wedge the runtime.
                      if signal_native_thread(target_thread, libc::SIGUSR1) != 0 {
                        break;
                      }
                    }
                    PreemptionState::Inactive => {}
                    PreemptionState::Shutdown => {
                      exit.orderly = true;
                      break;
                    }
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

/// Arms asynchronous preemption for **the current thread**, until dropped.
///
/// This is a thread-local arming token, not a transferable capability: the
/// state it flips lives in a thread-local, and the watcher it wakes signals the
/// thread that called [`GlobalEnv::init_thread`]. Sending it elsewhere and
/// running a program there would leave that thread unarmed and unpreemptible -
/// the guest would hold the OS thread, stopping the reactor and the timer wheel
/// with it - so the token is deliberately neither `Send` nor `Sync` and cannot
/// leave the thread that created it. [`ThreadEnv`] is `!Send` for the same
/// reason; before this marker existed the token derived from it silently was
/// not.
pub struct PreemptionEnabled {
  /// The thread this token armed, checked on drop.
  armed_on: ThreadId,
  /// `*const ()` is neither `Send` nor `Sync`, which is inherited here.
  ///
  /// ```compile_fail
  /// fn send<T: Send>() {}
  /// send::<async_ebpf::PreemptionEnabled>();
  /// ```
  ///
  /// ```compile_fail
  /// fn sync<T: Sync>() {}
  /// sync::<async_ebpf::PreemptionEnabled>();
  /// ```
  _not_send_sync: PhantomData<*const ()>,
}

impl PreemptionEnabled {
  pub fn new(_: ThreadEnv) -> Self {
    PREEMPTION_STATE.with(|x| {
      let mut notify = false;
      {
        let mut st = x.state.lock();
        let next = match *st {
          PreemptionState::Inactive => {
            notify = true;
            PreemptionState::Armed(1)
          }
          PreemptionState::Armed(n) => PreemptionState::Armed(n.saturating_add(1)),
          // The watcher for this thread has already stopped. Arming is then a
          // no-op rather than a process-killing panic on what is only ever an
          // embedder sequencing mistake; `Program::run` is where an unarmed
          // thread is reported, and it reports it as an error.
          PreemptionState::Shutdown => PreemptionState::Shutdown,
        };
        *st = next;
      }

      if notify {
        x.changed.notify_one();
      }
    });
    Self {
      armed_on: RUST_TID.with(|x| *x),
      _not_send_sync: PhantomData,
    }
  }
}

impl Drop for PreemptionEnabled {
  fn drop(&mut self) {
    debug_assert_eq!(
      self.armed_on,
      RUST_TID.with(|x| *x),
      "a PreemptionEnabled was dropped on a thread other than the one it armed"
    );
    PREEMPTION_STATE.with(|x| {
      let mut st = x.state.lock();
      let next = match *st {
        PreemptionState::Armed(1) => PreemptionState::Armed(0),
        PreemptionState::Armed(n) => PreemptionState::Armed(n.saturating_sub(1)),
        // Either the watcher shut down under us, or arming was a no-op above.
        // Neither is worth killing the process over on the way out.
        other @ (PreemptionState::Inactive | PreemptionState::Shutdown) => other,
      };
      *st = next;
    });
  }
}

/// Exclusive lease for an invocation that may mutate packed ELF data.
///
/// The permission transition is tied to the lease so cancellation restores
/// read-only protection before the write lock can be released.
struct WritableRunGuard<'a> {
  program: &'a Program,
  _lease: parking_lot::RwLockWriteGuard<'a, ()>,
  writable: bool,
}

impl<'a> WritableRunGuard<'a> {
  fn try_new(program: &'a Program) -> Result<Self, RuntimeError> {
    let Some(lease) = program.unbound.run_lock.try_write() else {
      return Err(RuntimeError::ProgramBusy);
    };
    if program.unbound.data_protection_failed.get() {
      return Err(RuntimeError::PlatformError(
        "writable data protection is unavailable",
      ));
    }
    program.unbound.cage.protect_writable_data(true)?;
    Ok(Self {
      program,
      _lease: lease,
      writable: true,
    })
  }

  fn restore(&mut self) -> Result<(), RuntimeError> {
    if !self.writable {
      return Ok(());
    }
    self.writable = false;
    if let Err(err) = self.program.unbound.cage.protect_writable_data(false) {
      self.program.unbound.data_protection_failed.set(true);
      if !self.program.unbound.cage.quarantine_writable_data() {
        std::process::abort();
      }
      return Err(err);
    }
    Ok(())
  }

  fn finish(mut self) -> Result<(), RuntimeError> {
    self.restore()
  }
}

impl Drop for WritableRunGuard<'_> {
  fn drop(&mut self) {
    let _ = self.restore();
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

  /// Debug-only check that this frame holds nothing a cancellation would
  /// strand, immediately before it suspends the guest.
  ///
  /// The crate declares no `unwind` feature, so `force_unwind_slow` on a
  /// started, suspended coroutine panics from inside a `Drop` inside a
  /// scopeguard - an abort. `CoDropper::drop` is what keeps every cancelled
  /// `run` away from that, by force-resetting the coroutine instead of
  /// unwinding it. The consequence is that cancelling a run abandons the
  /// coroutine stack *without running a single destructor* on it, which is
  /// sound only while none of the frames that can be live at a suspension owns
  /// anything that needs dropping.
  ///
  /// That holds today, but narrowly: `cached_resolver_target` takes borrows of
  /// both `resolvers` and `sections`, and stays sound only because both `Ref`s
  /// die when it returns, one line before the suspension. Hoisting the suspend
  /// into it - or holding either borrow across it - would leak the borrow on
  /// the first cancelled run and panic every later `borrow_mut` on that cell,
  /// from JIT-adjacent code, for the life of the program. This turns that from
  /// an argument in a comment into something a debug build fails on.
  fn debug_assert_nothing_to_drop_across_suspend(&self) {
    debug_assert!(
      self.unbound.resolvers.try_borrow_mut().is_ok(),
      "a `resolvers` borrow is live across a suspension; a cancelled run would \
       abandon it without dropping it"
    );
    debug_assert!(
      self.unbound.sections.try_borrow_mut().is_ok(),
      "a `sections` borrow is live across a suspension; a cancelled run would \
       abandon it without dropping it"
    );
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

  /// Removes every permission from the code arena after a failed protection
  /// transition. The caller marks the program terminal regardless of whether
  /// this best-effort quarantine succeeds, so generated code is never entered
  /// again through this `Program`.
  fn quarantine_code_pages(&self) {
    unsafe {
      let _ = libc::mprotect(
        self.unbound.code_base as *mut _,
        self.unbound.code_size,
        libc::PROT_NONE,
      );
    }
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
    let remaining = self.unbound.code_size - arena.used;
    let outcome = unsafe {
      translate_function_into(
        &section.translator,
        &TranslationInputs {
          hints: &region_analysis.hints,
          plan: &region_analysis.plan,
          resolver_ids: &resolver_ids,
          start_pc: function.start_pc,
          end_pc: function.end_pc,
        },
        code_ptr as *mut u8,
        remaining,
      )
    };

    let written_len = match outcome {
      Ok(written_len) => written_len,
      Err(reason) => {
        if let Err(err) = self.protect_code_pages(arena.used) {
          self.quarantine_code_pages();
          *self.unbound.code_exhausted.borrow_mut() = Some(err.clone());
          section.functions[function_index]
            .compiled
            .insert(signature, FunctionCompilation::Failed(err.clone()));
          return Err(err);
        }

        let err = match reason {
          // The function translates; there was just no room left for it. That is
          // terminal for the whole program, not for this variant: the arena never
          // shrinks, so nothing can be compiled from here on.
          TranslateError::OutOfSpace => {
            let err = RuntimeError::InvalidArgumentOwned(format!(
              "jit code budget exhausted: function [{}, {}) did not fit in the {remaining} bytes \
               left of the {} byte code budget ({} already in use). Raise \
               ProgramLoader::with_code_size_limit if the program needs more.",
              function.start_pc, function.end_pc, self.unbound.code_size, arena.used,
            ));
            *self.unbound.code_exhausted.borrow_mut() = Some(err.clone());
            err
          }
          TranslateError::Failed(errmsg) => RuntimeError::InvalidArgumentOwned(format!(
            "jit: code translation failed for function [{}, {}): {errmsg}",
            function.start_pc, function.end_pc,
          )),
        };
        section.functions[function_index]
          .compiled
          .insert(signature, FunctionCompilation::Failed(err.clone()));
        return Err(err);
      }
    };

    unsafe {
      crate::jit::clear_instruction_cache(code_ptr as *mut u8, written_len);
    }

    // Restore W^X protection covering the newly emitted function before
    // advancing the arena. If protection cannot be restored the function is not
    // executable, so leave `arena.used` unchanged (reclaiming the space, which
    // the next compilation overwrites after making the region writable again)
    // and do not register its resolvers.
    let new_used = arena.used + written_len;
    if let Err(err) = self.protect_code_pages(new_used) {
      self.quarantine_code_pages();
      *self.unbound.code_exhausted.borrow_mut() = Some(err.clone());
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

  /// Runs the program entrypoint with immutable access to shared ELF data.
  ///
  /// Multiple immutable runs may interleave. A live [`Program::run_mut`]
  /// conflicts and produces an error immediately rather than waiting.
  #[allow(clippy::await_holding_lock)] // the read lease intentionally spans the full async run
  pub async fn run(
    &self,
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
    entrypoint: &str,
    resources: &mut [&mut dyn Any],
    calldata: &[u8],
    _preemption: &PreemptionEnabled,
  ) -> Result<i64, Error> {
    let Some(_lease) = self.unbound.run_lock.try_read() else {
      return Err(Error(RuntimeError::ProgramBusy));
    };
    if self.unbound.data_protection_failed.get() {
      return Err(Error(RuntimeError::PlatformError(
        "writable data protection is unavailable",
      )));
    }
    self
      ._run(
        timeslice, timeslicer, entrypoint, resources, calldata, false,
      )
      .await
      .map_err(Error)
  }

  /// Runs an entrypoint with exclusive, persistent access to mutable ELF data.
  ///
  /// The lease is non-blocking: a conflicting invocation returns an error
  /// immediately. Only the packed writable-data suffix is made read-write, and
  /// it is restored to read-only before the exclusive lease is released.
  pub async fn run_mut(
    &self,
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
    entrypoint: &str,
    resources: &mut [&mut dyn Any],
    calldata: &[u8],
    _preemption: &PreemptionEnabled,
  ) -> Result<i64, Error> {
    let guard = WritableRunGuard::try_new(self).map_err(Error)?;
    let result = self
      ._run(timeslice, timeslicer, entrypoint, resources, calldata, true)
      .await;
    guard.finish().map_err(Error)?;
    result.map_err(Error)
  }

  async fn _run(
    &self,
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
    entrypoint: &str,
    resources: &mut [&mut dyn Any],
    calldata: &[u8],
    writable_data: bool,
  ) -> Result<i64, RuntimeError> {
    // Once the code budget is gone nothing can ever be compiled again, so fail
    // before running anything rather than replaying the program up to the call
    // that cannot be resolved - side effects included - on every invocation.
    if let Some(err) = self.unbound.code_exhausted.borrow().clone() {
      return Err(err);
    }

    // Preemption is asynchronous with no cooperative fallback, so a stopped
    // watcher means nothing can interrupt a guest on this thread. Refuse the
    // run: a program that never returns would otherwise hold the OS thread, and
    // with the reactor and timer wheel stopped there is no await point left at
    // which the caller could time it out or cancel it.
    if PREEMPTION_STATE.with(|x| x.watcher_failed.load(Ordering::SeqCst)) {
      return Err(RuntimeError::PlatformError(
        "the preemption watcher for this thread has stopped, so a program run \
         here could not be preempted",
      ));
    }

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

    if calldata.len() > MAX_CALLDATA_SIZE {
      return Err(RuntimeError::InvalidArgument("calldata too large"));
    }

    let guest_stack_size = self.unbound.guest_stack_size;
    let mut ectx = BorrowedExecContext::new(guest_stack_size);

    ectx.ctx.guest_stack.as_mut_slice()[guest_stack_size - calldata.len()..]
      .copy_from_slice(calldata);
    let calldata_len = calldata.len();

    let program_ret: u64 = {
      let guest_stack_top = self.unbound.cage.stack_top();
      let guest_stack_bottom = self.unbound.cage.stack_bottom();
      // Tier F addresses `[R10 - FRAME_WINDOW, R10)` with no bounds check. The
      // root must leave that window above the stack bottom; every later local
      // call establishes the same invariant dynamically before entering its
      // callee.
      debug_assert!(
        ((guest_stack_top - calldata_len) & !0x7)
          .checked_sub(FRAME_WINDOW)
          .is_some_and(|floor| floor >= guest_stack_bottom),
        "the entry frame pointer does not leave FRAME_WINDOW above the guest stack bottom"
      );
      let ctx = &mut *ectx.ctx;
      let stack_native_base = ctx.guest_stack.as_mut_ptr() as usize;
      let guest_frame = crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE as usize;
      let local_call_guest_floor = stack_native_base
        .checked_add(FRAME_WINDOW)
        .and_then(|floor| floor.checked_add(guest_frame))
        .expect("local-call guest stack floor overflow");
      let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
      if page_size <= 0 {
        return Err(RuntimeError::PlatformError("failed to query page size"));
      }
      let native_usable_bottom = ctx
        .native_stack
        .limit()
        .get()
        .checked_add(page_size as usize)
        .expect("native stack usable bottom overflow");
      let local_call_native_floor = native_usable_bottom
        .checked_add(NATIVE_STACK_RESERVE)
        .and_then(|floor| floor.checked_add(crate::jit::abi::NATIVE_LOCAL_CALL_BUDGET))
        .expect("local-call native stack floor overflow");
      let mut memory = JitMemory {
        stack_guest_bottom: guest_stack_bottom,
        stack_guest_top: guest_stack_top,
        stack_native_base,
        data_guest_bottom: self.unbound.cage.data_bottom(),
        data_guest_top: self.unbound.cage.data_top(),
        data_native_base: self.unbound.cage.data_native_base(),
        derived: [0; 12],
        local_call_guest_floor,
        local_call_native_floor,
      };
      memory.fill_derived();
      let memory = memory;
      let memory_ptr = &memory as *const JitMemory as usize;

      let mut co = CoDropper(Coroutine::with_stack(
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
      ));

      let mut last_yield_time: Option<Instant> = None;
      let mut last_throttle_time: Option<Instant> = None;
      let mut yielder: Option<NonNull<Yielder<u64, Dispatch>>> = None;
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
          x.yielder.set(yielder);
          x.pointer_cage_protected_range
            .set((0, POINTER_CAGE_PROTECTED_WINDOW));
          x.data_range.set((
            memory.data_native_base,
            memory.data_native_base + (memory.data_guest_top - memory.data_guest_bottom),
          ));
          compiler_fence(Ordering::Release);
          x.valid.store(true, Ordering::Relaxed);
        });
        ACTIVE_PROGRAM.with(|x| x.set(self as *const _));
        let active_jit_zone = scopeguard::guard((), |()| {
          ACTIVE_PROGRAM.with(|x| x.set(std::ptr::null()));
          ACTIVE_JIT_CODE_ZONE.with(|x| {
            x.valid.store(false, Ordering::Relaxed);
            compiler_fence(Ordering::Release);
            x.yielder.set(None);
            x.code_range.set((0, 0));
            x.pointer_cage_protected_range.set((0, 0));
            x.data_range.set((0, 0));
          });
        });

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
            writable_data,
          })
          .map_err(|_| RuntimeError::AsyncHelperError(helper_name))?;
        }

        let ret = co.0.resume(resume_input);
        // The coroutine is suspended here, which is exactly the state a
        // cancellation abandons without running destructors. Checked on the
        // host stack rather than at the suspension sites themselves: those run
        // within the coroutine stack's fixed emergency reserve, where a failing
        // assertion can overrun into the guard page and report as a bare
        // SIGSEGV instead of saying what went wrong. This also covers every
        // suspension point at once -
        // helper dispatch, the lazy local-call resolver, and preemption.
        self.debug_assert_nothing_to_drop_across_suspend();
        ACTIVE_PROGRAM.with(|x| x.set(std::ptr::null()));
        let next_yielder = ACTIVE_JIT_CODE_ZONE.with(|x| {
          x.valid.store(false, Ordering::Relaxed);
          compiler_fence(Ordering::Release);
          let yielder = x.yielder.get();
          x.yielder.set(None);
          x.code_range.set((0, 0));
          x.pointer_cage_protected_range.set((0, 0));
          x.data_range.set((0, 0));
          yielder
        });
        yielder = next_yielder;
        std::mem::forget(active_jit_zone);

        let dispatch: Dispatch = match ret {
          CoroutineResult::Return(x) => break x,
          CoroutineResult::Yield(x) => x,
        };

        if dispatch.local_call_stack_exhausted {
          return Err(RuntimeError::StackExhausted);
        }

        // restore signal mask of current thread
        if dispatch.memory_access_error.is_some() || dispatch.async_preemption {
          unsafe {
            let unblock = get_blocked_sigset();
            libc::sigprocmask(libc::SIG_UNBLOCK, &unblock, std::ptr::null_mut());
          }
        }

        if let Some(si_addr) = dispatch.memory_access_error {
          let vaddr = if si_addr >= memory.stack_native_base
            && si_addr < memory.stack_native_base + guest_stack_size
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
          writable_data,
        };

        // A lazy local call JIT-compiles a function on this thread before the
        // guest can continue - guest-triggered work whose size the program
        // chooses, since every (function, pointer signature) pair is a separate
        // compilation. So it has to reach the run-budget check below like any
        // other dispatch. Async preemption cannot substitute: the SIGUSR1
        // handler only acts on a PC inside the JIT code range, and during
        // compilation the PC is in the compiler.
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
        // A lazy compilation always takes the slow path: the fast path exists to spare a helper
        // call a clock read, which is not worth trading against a JIT compilation.
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

/// The JIT configuration this runtime always uses.
///
/// Built once, so the settings that only make sense together cannot drift
/// apart: `native_frame_base` and `frame_constants` are on because both entry
/// trampolines above establish exactly the frame the backend expects, and
/// neither means anything without the pointer cage.
fn jit_config(cage: &PointerCage, instruction_limit: usize) -> crate::jit::Config {
  crate::jit::Config {
    target: crate::jit::Target::host(),
    pointer_mask: cage.mask(),
    pointer_offset: cage.offset(),
    // Both entry trampolines establish the frame these describe.
    native_frame_base: true,
    frame_constants: true,
    instruction_limit,
    dispatcher: Some(tls_dispatcher),
    dispatcher_validate: Some(std_validator),
    unwind_helper_index: None,
    local_call_resolver: Some(tls_local_call_resolver),
    local_call_stack_exhausted: Some(tls_local_call_stack_exhausted),
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

use crate::jit::TranslateError;

/// What the analysis tells the JIT about one function, beyond the bytecode
/// itself. All of it is borrowed for the duration of a single translation and
/// cleared again afterwards.
struct TranslationInputs<'a> {
  hints: &'a [u8],
  plan: &'a [crate::jit::PlanEntry],
  resolver_ids: &'a [u32],
  start_pc: usize,
  end_pc: usize,
}

/// Translates `[start_pc, end_pc)` into `buffer`, returning the number of bytes
/// emitted.
///
/// # Safety
/// `buffer` must be writable for `capacity` bytes.
unsafe fn translate_function_into(
  translator: &crate::jit::Translator,
  inputs: &TranslationInputs<'_>,
  buffer: *mut u8,
  capacity: usize,
) -> Result<usize, TranslateError> {
  // The analysis inputs describe this one range under this one specialization,
  // and are borrowed for exactly this call.
  let jit_inputs = crate::jit::TranslationInputs {
    hints: inputs.hints,
    plan: inputs.plan,
    resolver_ids: inputs.resolver_ids,
    start_pc: inputs.start_pc,
    end_pc: inputs.end_pc,
  };
  let out = std::slice::from_raw_parts_mut(buffer, capacity);
  translator.translate_range(&jit_inputs, out)
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
      instruction_limit: crate::jit::abi::MAX_INSTS as usize,
      guest_stack_size: DEFAULT_GUEST_STACK_SIZE,
      require_static_regions: false,
    }
  }

  /// Requires every guest memory access to be statically routable to a single
  /// region (stack or data). When enabled, compilation fails if the
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
  /// ("jit: code translation failed") regardless of this limit; raising it
  /// past 1 MiB only adds room for more or larger sections within that
  /// per-section ceiling. x86-64 has no such per-section constraint.
  ///
  /// # Panics
  ///
  /// Panics if `limit` is zero, is not a multiple of 64 KiB, or does not fit in
  /// a `u32`.
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

  /// Sets the exclusive upper bound on decoded eBPF instruction slots.
  pub fn with_instruction_limit(mut self, limit: usize) -> Self {
    assert!(limit > 0, "instruction limit must be non-zero");
    assert!(
      limit <= i32::MAX as usize,
      "instruction limit must fit in a signed 32-bit PC"
    );
    self.instruction_limit = limit;
    self
  }

  /// Sets the writable guest stack window size used by each invocation.
  ///
  /// Each dynamic local call consumes one fixed 4 KiB guest frame. Recursive
  /// and statically deep call graphs are admitted, then stopped with a runtime
  /// error before the next complete frame would cross this window's bottom.
  /// Space not consumed by call frames can be used as a caller-managed arena.
  /// The default remains [`DEFAULT_GUEST_STACK_SIZE`].
  pub fn with_guest_stack_size(mut self, size: usize) -> Self {
    assert!(
      size >= DEFAULT_GUEST_STACK_SIZE,
      "guest stack size must be at least {DEFAULT_GUEST_STACK_SIZE} bytes"
    );
    self.guest_stack_size = size;
    self
  }

  /// Loads an ELF image into a new `UnboundProgram`.
  pub fn load(&self, rng: &mut impl rand::Rng, elf: &[u8]) -> Result<UnboundProgram, Error> {
    self._load(rng, elf).map_err(Error)
  }

  fn _load(&self, rng: &mut impl rand::Rng, elf: &[u8]) -> Result<UnboundProgram, RuntimeError> {
    let start_time = Instant::now();
    let writable_plan = plan_writable_data(elf).map_err(RuntimeError::Linker)?;
    let cage = PointerCage::new(rng, self.guest_stack_size, elf.len(), writable_plan.size)?;

    let code_sections = {
      let mut data = cage.data_slice(cage.data_bottom(), elf.len()).unwrap();
      let data = unsafe { data.as_mut() };
      data.copy_from_slice(elf);

      link_elf(
        data,
        cage.data_bottom(),
        cage.writable_data_bottom(),
        &writable_plan,
        &self.helpers_inverse,
      )
      .map_err(RuntimeError::Linker)?
    };

    // Relocations above were applied to the immutable ELF image. Copy only the
    // allocated writable sections into their packed, page-aligned suffix;
    // code, rodata, and ELF metadata remain single-copy in the frozen prefix.
    for section in &writable_plan.sections {
      unsafe {
        std::ptr::copy_nonoverlapping(
          (cage.data_native_base() + section.file_offset) as *const u8,
          (cage.data_native_base()
            + (cage.writable_data_bottom() - cage.data_bottom())
            + section.backing_offset) as *mut u8,
          section.size,
        );
      }
    }
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

    let config = std::sync::Arc::new(jit_config(&cage, self.instruction_limit));

    for (section_name, code_vaddr_size) in code_sections {
      let code = cage
        .data_slice(code_vaddr_size.0, code_vaddr_size.1)
        .unwrap();
      let code_bytes =
        unsafe { std::slice::from_raw_parts(code.as_ptr() as *const u8, code.len()) };
      // `Translator::load` enforces this, but it runs last: without the check
      // here an oversized section is walked twice and given per-instruction
      // tables by the two analyses below, only to be refused afterwards for a
      // reason that was knowable from its length.
      if code_bytes.len() / 8 > self.instruction_limit as usize {
        return Err(RuntimeError::InvalidArgumentOwned(format!(
          "too many instructions in {section_name} (max {})",
          self.instruction_limit
        )));
      }
      let layout = analyze_functions(code_bytes).map_err(|err| {
        RuntimeError::InvalidArgumentOwned(format!(
          "local function analysis failed in {section_name}: {err}"
        ))
      })?;
      // The validator calls back into the loader to check helper indices, so
      // the scope has to be live across the call.
      let translator = {
        let _validation_scope = LoaderValidationScope::new(self);
        crate::jit::Translator::load(config.clone(), code_bytes)
      };
      let translator = match translator {
        Ok(translator) => translator,
        Err(err) => {
          tracing::error!(section_name, error = %err, "failed to load code");
          return Err(RuntimeError::InvalidArgumentOwned(format!(
            "jit: code load failed: {err}"
          )));
        }
      };

      let section_index = sections.len();

      entrypoints.insert(section_name, section_index);
      let functions = (0..layout.functions.len())
        .map(|_| FunctionState::default())
        .collect();
      sections.push(Section {
        translator,
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
      guest_stack_size: self.guest_stack_size,
      run_lock: RwLock::new(()),
      data_protection_failed: Cell::new(false),
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
      code_exhausted: RefCell::new(None),
    })
  }
}

#[derive(Default)]
struct Dispatch {
  async_preemption: bool,
  memory_access_error: Option<usize>,
  lazy_local_call: Option<u32>,
  local_call_stack_exhausted: bool,

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
) -> u64 {
  let yielder = ACTIVE_JIT_CODE_ZONE
    .with(|x| x.yielder.get())
    .expect("no yielder");
  let yielder = yielder.as_ref();
  let ret = yielder.suspend(Dispatch {
    async_preemption: false,
    memory_access_error: None,
    lazy_local_call: None,
    local_call_stack_exhausted: false,
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

unsafe extern "C" fn tls_local_call_stack_exhausted() -> ! {
  let yielder = ACTIVE_JIT_CODE_ZONE
    .with(|x| x.yielder.get())
    .expect("no yielder");
  yielder.as_ref().suspend(Dispatch {
    local_call_stack_exhausted: true,
    ..Default::default()
  });

  // The parent terminates and drops the coroutine instead of resuming this
  // dispatch. If that contract is ever broken, abort rather than returning to
  // JIT code that deliberately did not establish a callee frame.
  libc::abort()
}

unsafe extern "C" fn std_validator(
  index: std::os::raw::c_uint,
  _vm: *const std::ffi::c_void,
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

#[cfg(all(target_arch = "x86_64", target_os = "macos"))]
unsafe fn program_counter(uctx: *mut libc::ucontext_t) -> usize {
  (*(*uctx).uc_mcontext).__ss.__rip as usize
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
unsafe fn program_counter(uctx: *mut libc::ucontext_t) -> usize {
  (*(*uctx).uc_mcontext).__ss.__pc as usize
}

unsafe extern "C" fn fault_handler(
  sig: i32,
  siginfo: *mut libc::siginfo_t,
  uctx: *mut libc::ucontext_t,
) {
  let fail = || chain_to_previous_fault_handler(sig);

  let Some((jit_code_zone, pointer_cage, data_range, yielder)) = ACTIVE_JIT_CODE_ZONE.with(|x| {
    if x.valid.load(Ordering::Relaxed) {
      compiler_fence(Ordering::Acquire);
      Some((
        x.code_range.get(),
        x.pointer_cage_protected_range.get(),
        x.data_range.get(),
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

  // SEGV_MAPERR/SEGV_ACCERR and BUS_ADRALN/BUS_ADRERR are 1/2 on the
  // supported platforms. Other causes belong to the previous handler.
  if (*siginfo).si_code != 1 && (*siginfo).si_code != 2 {
    return fail();
  }

  let si_addr = (*siginfo).si_addr() as usize;
  let in_fault_window = si_addr >= pointer_cage.0 && si_addr < pointer_cage.1;
  let in_data = si_addr >= data_range.0 && si_addr < data_range.1;
  if !in_fault_window && !in_data {
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

/// The fault dispositions that were in place before [`GlobalEnv::new`]
/// replaced them, captured once under `INIT` and only ever read afterwards.
static PREV_SIGSEGV: OnceLock<libc::sigaction> = OnceLock::new();
static PREV_SIGBUS: OnceLock<libc::sigaction> = OnceLock::new();

/// Hands a fault back to whoever had it before this crate took it, then returns
/// so the faulting instruction re-executes under that disposition.
///
/// Installing `SIG_DFL` here instead - which is what this used to do - turns a
/// fault another component would have *recovered* from into a process death,
/// and silently discards Rust's own stack-overflow handler, so a host stack
/// overflow reports as a bare `Segmentation fault` rather than naming itself.
/// `sigaction` is async-signal-safe, so this is legal from a handler.
unsafe fn chain_to_previous_fault_handler(signum: i32) {
  let prev = if signum == libc::SIGSEGV {
    PREV_SIGSEGV.get()
  } else if signum == libc::SIGBUS {
    PREV_SIGBUS.get()
  } else {
    None
  };
  if let Some(prev) = prev {
    if libc::sigaction(signum, prev, std::ptr::null_mut()) == 0 {
      return;
    }
  }
  restore_default_signal_handler(signum);
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
    libc::sigaddset(&mut s, libc::SIGBUS);
    s
  }
}

//! The host side of the guest boundary.
//!
//! A helper is the one place where guest-controlled values are handed to host
//! code that is not itself sandboxed, so it is where an embedder can undo
//! everything the pointer cage and the verifier do. This module is small; the
//! rules are not obvious from its size.

use crate::program::{HelperScope, MutableUserMemory};

/// Function signature for eBPF helpers invoked by the runtime.
///
/// # The arguments are untrusted
///
/// `arg1`..`arg5` are the guest's registers, verbatim. There is no arity check,
/// no type check and no tagging: a guest that calls a two-argument helper with
/// five arguments is calling it with five, and every one of them is a 64-bit
/// value it chose. In particular **an argument is not a host pointer**, however
/// much it may look like one. A helper that does `*(arg1 as *const u8)` hands
/// the guest an arbitrary-read primitive over the host address space, and
/// nothing in this crate can stop it.
///
/// The only sound way to turn an argument into memory is
/// [`HelperScope::user_memory`] or [`HelperScope::user_memory_mut`], which
/// validate the address against the guest's own regions. Treat every other use
/// of an argument as arithmetic on an attacker-chosen integer.
///
/// # What the scope will and will not do
///
/// * [`user_memory`](HelperScope::user_memory) accepts a guest stack *or* data
///   address. [`user_memory_mut`](HelperScope::user_memory_mut) always accepts
///   stack addresses and accepts allocated writable-data addresses only during
///   [`Program::run_mut`](crate::program::Program::run_mut). Those writes target
///   the program's persistent packed data copy. Immutable invocations and ELF
///   image/rodata addresses return `Err(())` rather than faulting in host code.
/// * A read refuses a region overlapping one already handed out for writing,
///   and a write refuses one overlapping any region already handed out at all,
///   so a mutable view can never alias another live view. Two reads may
///   overlap, which is harmless.
/// * There is a per-invocation cap of 4 mutable and 16 immutable regions.
///   Exceeding it returns `Err(())`. Slots are not released when a view is
///   dropped, so the cap counts regions *requested*, not regions live: a helper
///   that writes five separate buffers fails on the fifth. A zero-sized request
///   takes no slot.
///
/// # Helpers are scoped to the loader, not to the program
///
/// Every program loaded by one [`ProgramLoader`](crate::program::ProgramLoader)
/// can call every helper registered on it. The per-helper entropy checked at
/// load makes an index unforgeable; it is not a capability check. An embedder
/// that wants different helper sets for different programs needs a separate
/// loader per set.
pub type Helper =
  fn(scope: &HelperScope, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<u64, ()>;

/// Writes a NUL-terminated C string assembled from slices into user memory.
///
/// Return value has the same semantics as `snprintf`.
pub fn write_cstr(mut input: &[&[u8]], output: &mut MutableUserMemory) -> u64 {
  let input_len = input.iter().map(|x| x.len()).sum::<usize>();

  if output.len() == 0 {
    return input_len as u64;
  }

  let copy_len = input_len.min(output.len() - 1);
  let mut written_len = 0;

  while written_len < copy_len {
    let part = input[0];
    input = &input[1..];
    let part_copy_len = part.len().min(copy_len - written_len);
    output[written_len..written_len + part_copy_len].copy_from_slice(&part[..part_copy_len]);
    written_len += part_copy_len;
  }

  output[copy_len] = 0;
  input_len as u64
}

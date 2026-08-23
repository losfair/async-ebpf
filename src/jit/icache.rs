//! Instruction-cache maintenance after writing generated code.
//!
//! This is the one part of the JIT that cannot be written in safe Rust: there is
//! no stable Rust equivalent of `__builtin___clear_cache`, so the aarch64
//! sequence is spelled out in inline assembly here.
//!
//! Getting it wrong is not a crash you will see in testing: stale instruction
//! cache lines produce a program that runs correctly on the machine you wrote it
//! on and faults on a machine with a different cache geometry, or after a
//! context switch. The line sizes therefore come from `CTR_EL0` rather than an
//! assumed 64 bytes.

/// Synchronises `size` bytes at `buffer` with the instruction cache.
///
/// # Safety
/// `buffer` must point at `size` bytes of mapped memory.
#[inline]
pub unsafe fn clear(buffer: *mut u8, size: usize) {
  imp::clear(buffer, size)
}

#[cfg(target_arch = "x86_64")]
mod imp {
  /// x86_64 has a coherent instruction cache: a store to a location and a
  /// subsequent fetch from it are ordered by the hardware, so no explicit
  /// maintenance is required and this is genuinely empty rather than
  /// unimplemented.
  #[inline]
  pub unsafe fn clear(_buffer: *mut u8, _size: usize) {}
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
mod imp {
  use std::ffi::c_void;

  extern "C" {
    fn sys_icache_invalidate(start: *mut c_void, len: usize);
  }

  /// Uses Darwin's cache-maintenance API, which handles the cache geometry and
  /// required barriers for the current Apple processor.
  #[inline]
  pub unsafe fn clear(buffer: *mut u8, size: usize) {
    if size != 0 {
      sys_icache_invalidate(buffer.cast(), size);
    }
  }
}

#[cfg(all(target_arch = "aarch64", not(target_os = "macos")))]
mod imp {
  use std::arch::asm;

  /// Reads the cache-line geometry out of `CTR_EL0`.
  ///
  /// `DminLine` (bits 19:16) and `IminLine` (bits 3:0) are each `log2` of the
  /// line size in *words*, so the byte size is `4 << field`. Using a larger
  /// value than the hardware's would skip lines; using a smaller one only costs
  /// redundant operations, but there is no reason to guess when the register
  /// says.
  #[inline]
  fn cache_line_sizes() -> (usize, usize) {
    let ctr: u64;
    // SAFETY: `CTR_EL0` is readable from EL0 on every aarch64 implementation
    // Linux and OpenBSD run on; where the hardware traps it, the kernel
    // emulates the read.
    unsafe {
      asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags));
    }
    let dmin = 4usize << ((ctr >> 16) & 0xf);
    let imin = 4usize << (ctr & 0xf);
    (dmin, imin)
  }

  /// Clean the data cache to the point of unification, then invalidate the
  /// instruction cache over the same range, with the barriers that make the
  /// sequence observable to instruction fetch.
  ///
  /// The ordering is load-bearing and is the sequence the architecture reference
  /// manual prescribes for self-modifying code: every `dc cvau` must retire
  /// before any `ic ivau` runs, and the `isb` must follow the second `dsb` so
  /// that this core discards anything it prefetched from the range.
  #[inline]
  pub unsafe fn clear(buffer: *mut u8, size: usize) {
    if size == 0 {
      return;
    }
    let (dline, iline) = cache_line_sizes();
    let start = buffer as usize;
    let end = start.saturating_add(size);

    let mut addr = start & !(dline - 1);
    while addr < end {
      asm!("dc cvau, {}", in(reg) addr, options(nostack, preserves_flags));
      addr += dline;
    }
    asm!("dsb ish", options(nostack, preserves_flags));

    let mut addr = start & !(iline - 1);
    while addr < end {
      asm!("ic ivau, {}", in(reg) addr, options(nostack, preserves_flags));
      addr += iline;
    }
    asm!("dsb ish", options(nostack, preserves_flags));
    asm!("isb", options(nostack, preserves_flags));
  }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod imp {
  #[inline]
  pub unsafe fn clear(_buffer: *mut u8, _size: usize) {
    unreachable!("unsupported architecture; lib.rs refuses to compile here")
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn clearing_an_empty_range_is_a_no_op() {
    let mut buf = [0u8; 8];
    // SAFETY: the buffer is live and the length is zero.
    unsafe { super::clear(buf.as_mut_ptr(), 0) };
  }

  #[test]
  fn clearing_a_range_that_is_not_line_aligned_covers_it() {
    // Exercises the rounding in both loops: a range starting mid-line and
    // ending mid-line must still touch the first and last line.
    let mut buf = vec![0u8; 4096];
    // SAFETY: the range is inside a live allocation.
    unsafe { super::clear(buf.as_mut_ptr().add(3), 4090) };
  }
}

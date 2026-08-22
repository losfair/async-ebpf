use std::ptr::NonNull;

use memmap2::{MmapOptions, MmapRaw};

use crate::error::RuntimeError;

/// Memory-mapped pointer cage backing the guest's read-only data region.
///
/// The cage additionally *reserves* — but never maps — a guest address window
/// for the per-invocation stack. The stack's backing memory lives outside the
/// cage (`ExecContext::guest_stack`), and every guest access is translated
/// against `JitMemory`, so the cage never needs pages for it. Reserving the
/// window here keeps the guest stack and data address ranges disjoint by
/// construction, with a randomized distance between them — which is what the
/// JIT's single-region bounds checks and the region analysis rely on.
pub struct PointerCage {
  region: MmapRaw,
  stack_bottom: usize,
  stack_top: usize,
  data_bottom: usize,
  data_top: usize,
  margin: usize,
}

impl PointerCage {
  /// Creates a new pointer cage with randomized guard regions.
  ///
  /// `stack_size` sizes the reserved guest stack window; `data_size` sizes the
  /// mapped read-only data region. Neither has to be page-aligned.
  pub fn new(
    rng: &mut impl rand::Rng,
    stack_size: usize,
    data_size: usize,
  ) -> Result<Self, RuntimeError> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size < 0 {
      return Err(RuntimeError::PlatformError("failed to get page size"));
    }
    let page_size = page_size as usize;

    assert!(page_size <= 65536 && page_size.is_power_of_two());

    let round_up = |x: usize| (x + page_size - 1) & !(page_size - 1);

    // The stack window is reserved address space, not a mapping, so its size is
    // unconstrained; only its layout slot is rounded so that the data region
    // that follows stays page-aligned for `mprotect`.
    let stack_slot = round_up(stack_size);
    let data_size = round_up(data_size);

    let guard_size_1 = rng.gen_range(16..128) * page_size;
    let guard_size_2 = rng.gen_range(16..128) * page_size;
    let guard_size_3 = rng.gen_range(16..128) * page_size;

    // max range of offset in ld/st instructions
    // | margin | usable pointer cage range | margin |
    //          ^                           ^
    //      self.offset()           self.offset() + self.mask() + 1
    let margin: usize = page_size;

    let data_bottom = guard_size_1 + stack_slot + guard_size_2;
    let map_size = (data_bottom + data_size + guard_size_3).next_power_of_two() + margin * 2;
    let region = MmapRaw::from(
      MmapOptions::new()
        .len(map_size)
        .map_anon()
        .map_err(|_| RuntimeError::PlatformError("failed to allocate memory for pointer cage"))?,
    );
    unsafe {
      // Everything is `PROT_NONE` except the data region: the guard regions and
      // the reserved guest stack window are address space only.
      if libc::mprotect(region.as_ptr() as *mut _, map_size, libc::PROT_NONE) != 0
        || libc::mprotect(
          region.as_ptr().add(margin + data_bottom) as *mut _,
          data_size,
          libc::PROT_READ | libc::PROT_WRITE,
        ) != 0
      {
        return Err(RuntimeError::PlatformError(
          "failed to protect memory for pointer cage",
        ));
      }
    }

    Ok(Self {
      region,
      stack_bottom: guard_size_1,
      stack_top: guard_size_1 + stack_size,
      data_bottom,
      data_top: data_bottom + data_size,
      margin,
    })
  }

  /// Returns the top of the guest address window reserved for the stack.
  ///
  /// The window is not backed by the cage mapping; see [`PointerCage`].
  pub fn stack_top(&self) -> usize {
    self.stack_top
  }

  /// Returns the bottom of the guest address window reserved for the stack.
  ///
  /// The window is not backed by the cage mapping; see [`PointerCage`].
  pub fn stack_bottom(&self) -> usize {
    self.stack_bottom
  }

  /// Returns the bottom offset of the data region within the cage.
  pub fn data_bottom(&self) -> usize {
    self.data_bottom
  }

  /// Returns the top offset of the data region within the cage.
  pub fn data_top(&self) -> usize {
    self.data_top
  }

  /// Returns the native address backing the data region.
  pub fn data_native_base(&self) -> usize {
    unsafe { self.region.as_ptr().add(self.margin + self.data_bottom) as usize }
  }

  /// Returns the pointer mask used for JIT pointer masking.
  pub fn mask(&self) -> i32 {
    let addressable_len = self.region.len() - 2 * self.margin;
    assert_eq!(addressable_len.count_ones(), 1);
    assert!(addressable_len <= 0x8000_0000usize);
    (addressable_len - 1) as i32
  }

  /// Returns the pointer offset used alongside the mask for JIT pointers.
  pub fn offset(&self) -> usize {
    self.region.as_ptr() as usize + self.margin
  }

  /// Makes the data region read-only after initialization.
  pub fn freeze_data(&self) {
    unsafe {
      if libc::mprotect(
        self.region.as_ptr().add(self.margin + self.data_bottom) as *mut _,
        self.data_top - self.data_bottom,
        libc::PROT_READ,
      ) != 0
      {
        panic!("failed to freeze data region");
      }
    }
    tracing::info!(len = self.data_top - self.data_bottom, "frozen data region");
  }

  /// Validates a read against the mapped data region and returns a slice on
  /// success.
  ///
  /// Only the data region is mapped, so this is the only part of the cage that
  /// can be dereferenced; guest stack accesses go through `JitMemory`.
  pub fn data_slice(&self, offset: usize, size: usize) -> Option<NonNull<[u8]>> {
    if size == 0 {
      return Some(NonNull::slice_from_raw_parts(NonNull::dangling(), 0));
    }

    let end = offset.checked_add(size)?;
    if offset < self.data_bottom || end > self.data_top {
      return None;
    }
    let ptr = unsafe { self.region.as_ptr().add(self.margin).add(offset) as *mut u8 };
    unsafe {
      Some(NonNull::new_unchecked(std::ptr::slice_from_raw_parts_mut(
        ptr, size,
      )))
    }
  }

  /// Returns the backing memory-mapped region.
  pub fn region(&self) -> &MmapRaw {
    &self.region
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
  }

  #[test]
  fn stack_window_is_reserved_but_never_dereferenceable() {
    let cage = PointerCage::new(&mut rand::thread_rng(), 32768, 4096).unwrap();

    // The guest stack window sits below the data region with a guard between
    // them, so the two guest address ranges can never overlap.
    assert!(cage.stack_bottom() < cage.stack_top());
    assert!(cage.stack_top() < cage.data_bottom());

    // Only the data region is mapped, so only it can be dereferenced.
    assert!(cage.data_slice(cage.stack_bottom(), 1).is_none());
    assert!(cage.data_slice(cage.stack_top() - 1, 1).is_none());
    assert!(cage
      .data_slice(cage.data_bottom(), cage.data_top() - cage.data_bottom())
      .is_some());
    assert!(cage.data_slice(cage.data_bottom() - 1, 1).is_none());
    assert!(cage.data_slice(cage.data_top() - 1, 2).is_none());
    assert!(cage.data_slice(usize::MAX, 1).is_none());
    assert!(cage.data_slice(cage.data_bottom(), 0).is_some());
  }

  #[test]
  fn stack_size_need_not_be_page_aligned() {
    // The stack window is address space, not a mapping. This is what lets a
    // 32 KiB guest stack work on a 64 KiB-page kernel.
    let cage = PointerCage::new(&mut rand::thread_rng(), 1000, 4096).unwrap();
    assert_eq!(cage.stack_top() - cage.stack_bottom(), 1000);
    assert_eq!(cage.data_bottom() % page_size(), 0);

    // The data region is still mapped read-write until it is frozen.
    let slice = cage.data_slice(cage.data_bottom(), 4096).unwrap();
    unsafe { (slice.as_ptr() as *mut u8).write(0x41) };
    assert_eq!(unsafe { (slice.as_ptr() as *const u8).read() }, 0x41);
  }
}

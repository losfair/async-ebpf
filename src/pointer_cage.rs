use std::ptr::NonNull;

use memmap2::{MmapOptions, MmapRaw};

use crate::error::RuntimeError;

/// Memory-mapped pointer cage backing one contiguous guest data region. The
/// immutable ELF image occupies its page-aligned prefix and a packed copy of
/// allocated writable sections occupies its suffix.
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
  writable_data_bottom: usize,
  margin: usize,
}

/// Smallest guard, in pages, that separates the guest regions from each other
/// and from everything around them.
///
/// The randomization is what makes guest addresses unpredictable, but the
/// *minimum* carries a load-bearing property of its own: an access group is
/// checked as one window around a base, so no window may straddle from the
/// stack into data. A guard wider than the widest group guarantees that.
const MIN_GUARD_PAGES: usize = 16;

/// Widest span the cage can address, set by [`PointerCage::mask`] handing the
/// JIT an `i32` mask: 2 GiB, the largest power of two whose mask still fits.
const MAX_ADDRESSABLE_LEN: usize = 0x8000_0000;

/// The smallest page size the cage asserts against. Real pages are at least
/// this, so a bound proved here holds on any supported platform.
const MIN_PAGE_SIZE: usize = 4096;

const _: () = assert!(
  MIN_GUARD_PAGES * MIN_PAGE_SIZE > crate::region_analysis::MAX_GROUP_SPAN as usize,
  "an access group could span from one guest region into another"
);

impl PointerCage {
  /// Creates a new pointer cage with randomized guard regions.
  ///
  /// `stack_size` sizes the reserved guest stack window; `data_size` sizes the
  /// immutable ELF image and `writable_data_size` sizes the packed writable
  /// suffix. Neither has to be page-aligned.
  pub fn new(
    rng: &mut impl rand::Rng,
    stack_size: usize,
    data_size: usize,
    writable_data_size: usize,
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
    let writable_data_size = round_up(writable_data_size);
    let total_data_size = data_size
      .checked_add(writable_data_size)
      .ok_or(RuntimeError::PlatformError("guest data size overflow"))?;

    // A bounds check folds both bounds into one unsigned comparison against
    // `(top - width) - bottom`, and a group leader asks for a `width` as wide as
    // the whole window it covers. A region narrower than that makes the
    // subtraction wrap, and the comparison then accepts every address for that
    // region. Both regions are far larger in practice - the data region is
    // page-rounded and the guest stack is tens of kilobytes - so this refuses a
    // configuration that cannot arise today rather than one that does.
    let widest_window = crate::region_analysis::MAX_GROUP_SPAN as usize;
    if stack_size < widest_window || total_data_size < widest_window {
      return Err(RuntimeError::PlatformError(
        "a guest region is narrower than the widest window a bounds check can cover",
      ));
    }

    let guard_size_1 = rng.gen_range(MIN_GUARD_PAGES..128) * page_size;
    let guard_size_2 = rng.gen_range(MIN_GUARD_PAGES..128) * page_size;
    let guard_size_3 = rng.gen_range(MIN_GUARD_PAGES..128) * page_size;

    // max range of offset in ld/st instructions
    // | margin | usable pointer cage range | margin |
    //          ^                           ^
    //      self.offset()           self.offset() + self.mask() + 1
    let margin: usize = page_size;

    let data_bottom = guard_size_1 + stack_slot + guard_size_2;
    // Keeping the two page-aligned pieces adjacent is load-bearing: the JIT
    // deliberately sees them as one affine DATA region. Page protection, not
    // region analysis, distinguishes the immutable prefix from the suffix.
    let writable_data_bottom = data_bottom + data_size;
    // The addressable span has to stay inside what `mask()` can express: it is
    // handed to the JIT as an `i32` mask, so anything above 2 GiB has no valid
    // encoding. Refused here rather than asserted in `mask()`, which the loader
    // reaches three frames later - by which point a 4 GiB mapping and a copy of
    // the whole input have already been committed for an input that was never
    // going to load.
    let addressable_len = writable_data_bottom
      .checked_add(writable_data_size)
      .and_then(|x| x.checked_add(guard_size_3))
      .filter(|&x| x <= MAX_ADDRESSABLE_LEN)
      .map(|x| x.next_power_of_two())
      .filter(|&x| x <= MAX_ADDRESSABLE_LEN)
      .ok_or(RuntimeError::PlatformError(
        "the guest data region is too large for the pointer cage to address",
      ))?;
    let map_size = addressable_len + margin * 2;
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
          total_data_size,
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
      data_top: writable_data_bottom + writable_data_size,
      writable_data_bottom,
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

  /// Returns the start of the page-aligned writable-data suffix.
  pub fn writable_data_bottom(&self) -> usize {
    self.writable_data_bottom
  }

  /// Returns the pointer mask used for JIT pointer masking.
  pub fn mask(&self) -> i32 {
    let addressable_len = self.region.len() - 2 * self.margin;
    // Both established by `new`, which refuses an oversized region before it
    // maps anything.
    debug_assert_eq!(addressable_len.count_ones(), 1);
    debug_assert!(addressable_len <= MAX_ADDRESSABLE_LEN);
    (addressable_len - 1) as i32
  }

  /// Returns the pointer offset used alongside the mask for JIT pointers.
  pub fn offset(&self) -> usize {
    self.region.as_ptr() as usize + self.margin
  }

  /// Makes both parts of the data region read-only after initialization.
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

  /// Changes only the packed writable-data suffix's page protection.
  pub fn protect_writable_data(&self, writable: bool) -> Result<(), RuntimeError> {
    let len = self.data_top - self.writable_data_bottom;
    if len == 0 {
      return Ok(());
    }
    let protection = if writable {
      libc::PROT_READ | libc::PROT_WRITE
    } else {
      libc::PROT_READ
    };
    if unsafe {
      libc::mprotect(
        self
          .region
          .as_ptr()
          .add(self.margin + self.writable_data_bottom) as *mut _,
        len,
        protection,
      )
    } != 0
    {
      return Err(RuntimeError::PlatformError(
        "failed to protect writable data region",
      ));
    }
    Ok(())
  }

  /// Removes access to the mutable suffix after a failed permission restore.
  /// Returning false means the process can no longer safely continue.
  pub fn quarantine_writable_data(&self) -> bool {
    let len = self.data_top - self.writable_data_bottom;
    len == 0
      || unsafe {
        libc::mprotect(
          self
            .region
            .as_ptr()
            .add(self.margin + self.writable_data_bottom) as *mut _,
          len,
          libc::PROT_NONE,
        ) == 0
      }
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
    let cage = PointerCage::new(&mut rand::thread_rng(), 32768, 4096, 4096).unwrap();

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
  fn immutable_and_writable_backing_are_one_affine_data_region() {
    let page = page_size();
    let cage = PointerCage::new(&mut rand::thread_rng(), 32768, page + 1, page + 1).unwrap();

    // There is no guard or second translation base at the protection boundary:
    // the JIT translates either side with `native = data_native_base +
    // (guest - data_bottom)`.
    assert_eq!(cage.writable_data_bottom(), cage.data_bottom() + 2 * page);
    let before = cage.data_slice(cage.writable_data_bottom() - 1, 1).unwrap();
    let after = cage.data_slice(cage.writable_data_bottom(), 1).unwrap();
    assert_eq!(
      after.as_ptr() as *mut u8 as usize,
      before.as_ptr() as *mut u8 as usize + 1
    );
  }

  #[test]
  fn a_region_narrower_than_the_widest_window_is_refused() {
    // `(top - width) - bottom` would wrap, and the single unsigned comparison
    // the bounds check folds down to would then accept every address for that
    // region. Refusing the cage is the only place this can be caught.
    let widest = crate::region_analysis::MAX_GROUP_SPAN as usize;

    // The stack window is used unrounded, so it is the one that can be too
    // small.
    assert!(PointerCage::new(&mut rand::thread_rng(), widest - 1, 4096, 0).is_err());
    assert!(PointerCage::new(&mut rand::thread_rng(), widest, 4096, 0).is_ok());

    // The data region is rounded up to a page first, so on any page size at
    // least as large as the window it can only be too small when it is empty.
    assert!(PointerCage::new(&mut rand::thread_rng(), 32768, 0, 0).is_err());
    assert!(PointerCage::new(&mut rand::thread_rng(), 32768, 1, 0).is_ok());
  }

  #[test]
  fn stack_size_need_not_be_page_aligned() {
    // The stack window is address space, not a mapping. This is what lets a
    // 32 KiB guest stack work on a 64 KiB-page kernel. The size is deliberately
    // not a multiple of any page size, but it does have to clear the widest
    // window a bounds check can be asked to cover.
    let cage = PointerCage::new(&mut rand::thread_rng(), 5000, 4096, 4096).unwrap();
    assert_eq!(cage.stack_top() - cage.stack_bottom(), 5000);
    assert_eq!(cage.data_bottom() % page_size(), 0);

    // The data region is still mapped read-write until it is frozen.
    let slice = cage.data_slice(cage.data_bottom(), 4096).unwrap();
    unsafe { (slice.as_ptr() as *mut u8).write(0x41) };
    assert_eq!(unsafe { (slice.as_ptr() as *const u8).read() }, 0x41);
  }
}

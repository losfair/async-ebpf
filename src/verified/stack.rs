//! The guest stack's frame geometry: where the frames are, where the entry
//! frame pointer starts, how far down a local call may go, and which
//! accesses the JIT emits with no bounds check.
//!
//! In the guarded layout the guest stack is `frame_count` mapped islands of
//! `frame_size` bytes, `frame_stride` apart, with unmapped gaps between them;
//! the entry frame pointer is the top of the highest island and every local
//! call moves it down one stride. Four pieces of arithmetic tie that
//! together, and all four are here so that `lean/AsyncEbpf/Stack` can prove
//! they agree:
//!
//! * [`root_frame_offset`] is where the entry frame pointer starts;
//! * [`local_call_floor`] is the lowest frame pointer a local call may be
//!   made from: the JIT refuses the call below it (`LOCAL_CALL_GUEST_FLOOR`);
//! * [`island_access`] is how the runtime's helpers decide whether a guest
//!   address range lies in a mapped island (`checked_stack_region`);
//! * [`in_frame_window`] is the displacement test the region analysis uses
//!   to emit an `R10`-relative access with no bounds check at all
//!   (`frame_access`).
//!
//! The theorem (`frame_window_mapped`): from the entry, as long as every
//! local call passes the floor test, every access `in_frame_window` admits
//! satisfies `island_access`. The JIT's unchecked frame accesses are the
//! accesses the checked path would have accepted.
//!
//! Offsets here are relative to the guest stack's bottom, so that nothing
//! depends on where the mapping landed.

/// The frame islands of a guest stack, as offsets from its bottom.
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub struct FrameLayout {
  /// Bytes each local function may address below its frame pointer.
  pub frame_size: usize,
  /// Bytes between the frame pointers of a caller and its callee.
  pub frame_stride: usize,
  /// Islands mapped, the entry's included.
  pub frame_count: usize,
}

/// `a + b`, or `None` on overflow.
fn add_checked(a: usize, b: usize) -> Option<usize> {
  if a > usize::MAX - b {
    return None;
  }
  Some(a + b)
}

/// `a * b`, or `None` on overflow.
fn mul_checked(a: usize, b: usize) -> Option<usize> {
  if b != 0 && a > usize::MAX / b {
    return None;
  }
  Some(a * b)
}

/// The entry frame pointer: the top of the highest island,
/// `(frame_count - 1) * frame_stride + frame_size`. `None` if the layout
/// has no island or the span overflows.
pub fn root_frame_offset(layout: &FrameLayout) -> Option<usize> {
  if layout.frame_count == 0 {
    return None;
  }
  // `?` on `Option` has no Aeneas model; spell the match out.
  match mul_checked(layout.frame_count - 1, layout.frame_stride) {
    None => None,
    Some(span) => add_checked(span, layout.frame_size),
  }
}

/// The lowest frame pointer a local call may be made from: one stride
/// down, the callee must still have a complete frame above the bottom.
pub fn local_call_floor(layout: &FrameLayout) -> Option<usize> {
  add_checked(layout.frame_size, layout.frame_stride)
}

/// Whether `[offset, offset + size)` lies inside one mapped island.
pub fn island_access(layout: &FrameLayout, offset: usize, size: usize) -> bool {
  let slot = offset / layout.frame_stride;
  let within = offset % layout.frame_stride;
  slot < layout.frame_count && within < layout.frame_size && size <= layout.frame_size - within
}

/// Whether an access of `width` bytes at `R10 + offset` lies in
/// `[R10 - frame_size, R10)`.
pub fn in_frame_window(frame_size: u16, offset: i16, width: u8) -> bool {
  let offset = offset as i32;
  let width = width as i32;
  offset >= -(frame_size as i32) && offset <= -width
}

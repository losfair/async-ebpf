//! The layout hypotheses of the x86_64 memory-safety theorem, as a decidable
//! check the runtime can run before it enters generated code.
//!
//! `lean/AsyncEbpf/X64/Contract.lean` states `Layout P`: what the mappings
//! promise about the parameters an activation is entered with. It is a
//! hypothesis of `check_safe`, so nothing in the proof establishes it —
//! `lean/README.md` lists "the entry trampolines and the descriptor" among
//! what is trusted. This module is how much of it stops being trusted: every
//! clause of `Layout` that mentions only the numbers the descriptor and the
//! mappings hold is checked here, on the concrete values `program.rs` is about
//! to hand the trampoline, and a run whose layout fails is refused instead of
//! entered.
//!
//! What is *not* checked here is the rest of `Layout`: the clauses about
//! `rsp0`, `rbp0` and `fp0`, which are per-activation values the entry
//! trampoline establishes rather than numbers the runtime computes
//! (`frameRoom`, `stackRoom`, `stackBelowFrame`, `frameAbove`, `frameBelow`,
//! `nativeStackLo`, `nativeStackHi`, `frameNoWrap`, `stackWindowNoWrap`, and
//! the disjointness clauses that mention `frameSlots P` or `stackWindow P`).
//! Those follow from the native-stack clauses that *are* checked —
//! `nativeStackNoWrap`, `nativeStackOffPage`, `stackNativeOffNativeStack`,
//! `dataNativeOffNativeStack`, `descOffNativeStack` — once `rsp0` and `rbp0`
//! are known to lie inside `[stackLo, stackHi)`, which is what the trampoline
//! arranges and the later Lean lemma proves.
//!
//! [`derived_block`] is the other half: the six bounds-check constants
//! `JitMemory::fill_derived` writes into the descriptor for one region, which
//! `RoMem`'s `DerivedBlock` reads back. The two agree by construction because
//! `program.rs` computes them through this function.
//!
//! Everything is `u64` with the overflow checks written out as comparisons;
//! see `lean/README.md`, "Writing verified code".

/// Bytes at address zero that a failed bounds check folds onto, and that the
/// fault handler claims: `InRange 0#64 4096` in `Allowed`.
pub const FIRST_PAGE_LEN: u64 = 4096;

/// Bytes of the `JitMemory` descriptor: `InRange P.desc 200` in `Allowed`.
pub const DESCRIPTOR_LEN: u64 = 200;

/// Narrowest guest region a bounds check may be asked about, `x64_ir`'s
/// `MAX_GROUP_SPAN`: the `stackWide` and `dataWide` clauses.
pub const MIN_REGION_SPAN: u64 = 4096;

/// Bytes a local call pushes below the caller's window before the callee's own
/// window begins: the constant in the `floorNative` clause.
pub const NATIVE_CALL_RESERVE: u64 = 240;

/// The concrete numbers one invocation's layout consists of, as the descriptor
/// and the mappings hold them.
///
/// Field for field these are `Params` of `AsyncEbpf/X64/Machine.lean`, minus
/// the per-activation registers and the code addresses: `sgb sgt snb`,
/// `dgb dgt dnb`, `desc`, `stackLo stackHi`, `guestFloor nativeFloor`,
/// `frameSize stride`.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub struct NativeLayout {
  /// `P.sgb`: the guest stack's bottom guest address.
  pub stack_guest_bottom: u64,
  /// `P.sgt`: one past its top guest address.
  pub stack_guest_top: u64,
  /// `P.snb`: the native address the guest stack's bottom is backed by.
  pub stack_native_base: u64,
  /// `P.dgb`: the data region's bottom guest address.
  pub data_guest_bottom: u64,
  /// `P.dgt`: one past its top guest address.
  pub data_guest_top: u64,
  /// `P.dnb`: the native address the data region's bottom is backed by.
  pub data_native_base: u64,
  /// `P.desc`: the address of the `JitMemory` descriptor, 200 bytes wide.
  pub descriptor: u64,
  /// `P.stackLo`: the bottom of the coroutine stack's mapping.
  pub native_stack_lo: u64,
  /// `P.stackHi`: one past its top.
  pub native_stack_hi: u64,
  /// `P.guestFloor`: the lowest frame base a local call may descend from.
  pub guest_floor: u64,
  /// `P.nativeFloor`: the lowest native stack pointer a local call may
  /// descend from.
  pub native_floor: u64,
  /// `P.frameSize`: guest stack bytes charged to one local function.
  pub frame_size: u64,
  /// `P.stride`: guest-address distance between successive frame bases.
  pub frame_stride: u64,
}

/// Whether `a + b` is representable, i.e. `a + b <= u64::MAX`.
///
/// The no-wrap clauses of `Layout` read `x.toNat + n <= 2 ^ 64`; this is the
/// one-byte-stricter `x + n <= u64::MAX`, which implies them and leaves every
/// sum below computable in `u64`.
fn fits(a: u64, b: u64) -> bool {
  a <= u64::MAX - b
}

/// `a - b` modulo `2 ^ 64`, without `wrapping_sub`, which has no Aeneas model.
///
/// In the wrapping branch `b > a`, so `b - a >= 1` and `u64::MAX - (b - a)`
/// is at most `u64::MAX - 1`: the `+ 1` cannot overflow.
fn sub_mod(a: u64, b: u64) -> u64 {
  if a >= b {
    a - b
  } else {
    u64::MAX - (b - a) + 1
  }
}

/// Lean `RangesDisjoint b₁ n₁ b₂ n₂`: `[a_lo, a_lo + a_len)` and
/// `[b_lo, b_lo + b_len)` do not meet.
///
/// A range whose end is not representable is reported as meeting everything;
/// the no-wrap clauses refuse such a layout on their own, so the answer only
/// has to be conservative.
fn disjoint(a_lo: u64, a_len: u64, b_lo: u64, b_len: u64) -> bool {
  let a_fits = fits(a_lo, a_len);
  let b_fits = fits(b_lo, b_len);
  if !a_fits {
    return false;
  }
  if !b_fits {
    return false;
  }
  let a_hi = a_lo + a_len;
  let b_hi = b_lo + b_len;
  let a_below = a_hi <= b_lo;
  let b_below = b_hi <= a_lo;
  a_below || b_below
}

/// Lean `stackSpan P`: the bytes the guest stack spans, and so the bytes its
/// native backing spans. Zero unless the region is a range, which
/// [`stack_ordered`] is what refuses.
fn stack_span(l: &NativeLayout) -> u64 {
  if l.stack_guest_bottom > l.stack_guest_top {
    return 0;
  }
  l.stack_guest_top - l.stack_guest_bottom
}

/// Lean `dataSpan P`: the bytes the guest data region spans. Zero unless the
/// region is a range, which [`data_ordered`] is what refuses.
fn data_span(l: &NativeLayout) -> u64 {
  if l.data_guest_bottom > l.data_guest_top {
    return 0;
  }
  l.data_guest_top - l.data_guest_bottom
}

/// The bytes the coroutine stack's mapping spans, spelled
/// `P.stackHi.toNat - P.stackLo.toNat` in every Lean clause that names it.
/// Zero unless the mapping is a range, which [`native_stack_no_wrap`]
/// refuses.
fn native_stack_span(l: &NativeLayout) -> u64 {
  if l.native_stack_lo > l.native_stack_hi {
    return 0;
  }
  l.native_stack_hi - l.native_stack_lo
}

/// Lean `Layout.stackOrdered`: the guest stack is a range.
fn stack_ordered(l: &NativeLayout) -> bool {
  l.stack_guest_bottom <= l.stack_guest_top
}

/// Lean `Layout.dataOrdered`: the guest data region is a range.
fn data_ordered(l: &NativeLayout) -> bool {
  l.data_guest_bottom <= l.data_guest_top
}

/// Lean `Layout.guestDisjoint`: the two guest regions do not meet, so a guest
/// address names at most one of them.
fn guest_disjoint(l: &NativeLayout) -> bool {
  let span_s = stack_span(l);
  let span_d = data_span(l);
  disjoint(l.stack_guest_bottom, span_s, l.data_guest_bottom, span_d)
}

/// Lean `Layout.stackNativeNoWrap`: the stack's native backing does not wrap
/// past the end of the address space.
fn stack_native_no_wrap(l: &NativeLayout) -> bool {
  let span_s = stack_span(l);
  fits(l.stack_native_base, span_s)
}

/// Lean `Layout.dataNativeNoWrap`: the data region's native backing does not
/// wrap past the end of the address space.
fn data_native_no_wrap(l: &NativeLayout) -> bool {
  let span_d = data_span(l);
  fits(l.data_native_base, span_d)
}

/// Lean `Layout.descNoWrap`: the descriptor's 200 bytes do not wrap past the
/// end of the address space.
fn desc_no_wrap(l: &NativeLayout) -> bool {
  fits(l.descriptor, DESCRIPTOR_LEN)
}

/// Lean `Layout.nativeStackNoWrap`: the coroutine stack's mapping is a range.
/// Its second conjunct, `P.stackHi.toNat <= 2 ^ 64`, holds of every `u64`.
fn native_stack_no_wrap(l: &NativeLayout) -> bool {
  l.native_stack_lo <= l.native_stack_hi
}

/// Lean `Layout.nativeDisjoint`: the two native backings do not meet each
/// other.
fn native_disjoint(l: &NativeLayout) -> bool {
  let span_s = stack_span(l);
  let span_d = data_span(l);
  disjoint(l.stack_native_base, span_s, l.data_native_base, span_d)
}

/// Lean `Layout.stackNativeOffPage`: the stack's native backing does not
/// contain the first page, which is where a failed check lands.
fn stack_native_off_page(l: &NativeLayout) -> bool {
  let span_s = stack_span(l);
  disjoint(0, FIRST_PAGE_LEN, l.stack_native_base, span_s)
}

/// Lean `Layout.dataNativeOffPage`: nor does the data region's backing.
fn data_native_off_page(l: &NativeLayout) -> bool {
  let span_d = data_span(l);
  disjoint(0, FIRST_PAGE_LEN, l.data_native_base, span_d)
}

/// Lean `Layout.stackNativeOffDesc`: the stack's native backing does not meet
/// the descriptor, so a checked guest store cannot rewrite the constants the
/// next check reads.
fn stack_native_off_desc(l: &NativeLayout) -> bool {
  let span_s = stack_span(l);
  disjoint(l.descriptor, DESCRIPTOR_LEN, l.stack_native_base, span_s)
}

/// Lean `Layout.dataNativeOffDesc`: nor does the data region's backing.
fn data_native_off_desc(l: &NativeLayout) -> bool {
  let span_d = data_span(l);
  disjoint(l.descriptor, DESCRIPTOR_LEN, l.data_native_base, span_d)
}

/// Lean `Layout.descOffPage`: the descriptor does not meet the first page.
fn desc_off_page(l: &NativeLayout) -> bool {
  disjoint(0, FIRST_PAGE_LEN, l.descriptor, DESCRIPTOR_LEN)
}

/// Lean `Layout.nativeStackOffPage`: the coroutine stack sits clear of the
/// first page.
fn native_stack_off_page(l: &NativeLayout) -> bool {
  let span_n = native_stack_span(l);
  disjoint(0, FIRST_PAGE_LEN, l.native_stack_lo, span_n)
}

/// Lean `Layout.stackNativeOffNativeStack`: the coroutine stack does not meet
/// the guest stack's native backing.
fn stack_native_off_native_stack(l: &NativeLayout) -> bool {
  let span_n = native_stack_span(l);
  let span_s = stack_span(l);
  disjoint(l.native_stack_lo, span_n, l.stack_native_base, span_s)
}

/// Lean `Layout.dataNativeOffNativeStack`: nor the data region's backing.
fn data_native_off_native_stack(l: &NativeLayout) -> bool {
  let span_n = native_stack_span(l);
  let span_d = data_span(l);
  disjoint(l.native_stack_lo, span_n, l.data_native_base, span_d)
}

/// Lean `Layout.descOffNativeStack`: nor the descriptor.
fn desc_off_native_stack(l: &NativeLayout) -> bool {
  let span_n = native_stack_span(l);
  disjoint(l.native_stack_lo, span_n, l.descriptor, DESCRIPTOR_LEN)
}

/// Lean `Layout.floorRoom`: the local-call floor leaves room for at least the
/// current frame and one more stride below it,
/// `snb + frameSize + stride <= guestFloor`.
fn floor_room(l: &NativeLayout) -> bool {
  if !fits(l.stack_native_base, l.frame_size) {
    return false;
  }
  let one_frame = l.stack_native_base + l.frame_size;
  if !fits(one_frame, l.frame_stride) {
    return false;
  }
  one_frame + l.frame_stride <= l.guest_floor
}

/// Lean `Layout.floorNative`: the native floor keeps two hundred and forty
/// bytes above the bottom of the coroutine stack's mapping, which is what a
/// local call pushes before the callee's own window begins.
fn floor_native(l: &NativeLayout) -> bool {
  if !fits(l.native_stack_lo, NATIVE_CALL_RESERVE) {
    return false;
  }
  l.native_stack_lo + NATIVE_CALL_RESERVE <= l.native_floor
}

/// Lean `Layout.stackWide`: the guest stack is at least as wide as the widest
/// window a bounds check may cover.
fn stack_wide(l: &NativeLayout) -> bool {
  let span_s = stack_span(l);
  span_s >= MIN_REGION_SPAN
}

/// Lean `Layout.dataWide`: and so is the guest data region.
fn data_wide(l: &NativeLayout) -> bool {
  let span_d = data_span(l);
  span_d >= MIN_REGION_SPAN
}

/// Whether `l` satisfies every clause of Lean's `Layout P` that mentions only
/// the numbers the descriptor and the mappings hold — that is, all of them
/// except the ones about `rsp0`, `rbp0` and `fp0`, which the entry trampoline
/// establishes per activation (see the module comment).
///
/// A few dozen comparisons, run once per invocation setup. `program.rs`
/// refuses the run when this is false, which is what turns the theorem's
/// hypothesis into something the runtime enforces.
pub fn layout_ok(l: &NativeLayout) -> bool {
  let ordered_s = stack_ordered(l);
  let ordered_d = data_ordered(l);
  let wide_s = stack_wide(l);
  let wide_d = data_wide(l);
  let nowrap_s = stack_native_no_wrap(l);
  let nowrap_d = data_native_no_wrap(l);
  let nowrap_desc = desc_no_wrap(l);
  let nowrap_native = native_stack_no_wrap(l);
  let guest_pair = guest_disjoint(l);
  let native_pair = native_disjoint(l);
  let page_s = stack_native_off_page(l);
  let page_d = data_native_off_page(l);
  let page_desc = desc_off_page(l);
  let page_native = native_stack_off_page(l);
  let desc_s = stack_native_off_desc(l);
  let desc_d = data_native_off_desc(l);
  let native_s = stack_native_off_native_stack(l);
  let native_d = data_native_off_native_stack(l);
  let native_desc = desc_off_native_stack(l);
  let room_guest = floor_room(l);
  let room_native = floor_native(l);
  ordered_s
    && ordered_d
    && wide_s
    && wide_d
    && nowrap_s
    && nowrap_d
    && nowrap_desc
    && nowrap_native
    && guest_pair
    && native_pair
    && page_s
    && page_d
    && page_desc
    && page_native
    && desc_s
    && desc_d
    && native_s
    && native_d
    && native_desc
    && room_guest
    && room_native
}

/// One region's six derived bounds-check constants, in the order
/// `jit::abi::derived_slot` lays them out and Lean's `DerivedBlock` reads
/// them: the guest bottom, the guest-to-native delta, and the highest in-range
/// guest address for each of the four access widths, relative to the bottom.
///
/// `bottom`, `delta = nb - gb`, `span1 = (gt - 1) - gb`, `span2`, `span4`,
/// `span8`. Every subtraction is modulo `2 ^ 64`, as it is in the `BitVec 64`
/// arithmetic of the Lean structure, and is written through [`sub_mod`]
/// because `wrapping_sub` has no Aeneas model.
pub fn derived_block(bottom: u64, top: u64, native_base: u64) -> [u64; 6] {
  let delta = sub_mod(native_base, bottom);
  let top1 = sub_mod(top, 1);
  let top2 = sub_mod(top, 2);
  let top4 = sub_mod(top, 4);
  let top8 = sub_mod(top, 8);
  let span1 = sub_mod(top1, bottom);
  let span2 = sub_mod(top2, bottom);
  let span4 = sub_mod(top4, bottom);
  let span8 = sub_mod(top8, bottom);
  [bottom, delta, span1, span2, span4, span8]
}

#[cfg(test)]
mod tests {
  use super::*;

  /// A layout in the shape of a real one: two guest regions in one cage's
  /// address space, two native backings in their own mappings, a coroutine
  /// stack elsewhere, and the descriptor on the host stack above it all.
  fn good() -> NativeLayout {
    NativeLayout {
      stack_guest_bottom: 0x1_0000,
      stack_guest_top: 0x1_0000 + 0x8_0000,
      stack_native_base: 0x7000_0000_0000,
      data_guest_bottom: 0x10_0000,
      data_guest_top: 0x10_0000 + 0x10_0000,
      data_native_base: 0x7000_1000_0000,
      descriptor: 0x7fff_0000_0000,
      native_stack_lo: 0x7000_2000_0000,
      native_stack_hi: 0x7000_2000_0000 + 0x10_0000,
      guest_floor: 0x7000_0000_0000 + 0x1000 + 0x1_0000,
      native_floor: 0x7000_2000_0000 + 0x4000,
      frame_size: 0x1000,
      frame_stride: 0x1_0000,
    }
  }

  #[test]
  fn a_real_shaped_layout_passes() {
    assert!(layout_ok(&good()));
  }

  #[test]
  fn each_clause_can_fail_on_its_own() {
    // stackOrdered / dataOrdered.
    let mut l = good();
    l.stack_guest_top = l.stack_guest_bottom - 1;
    assert!(!layout_ok(&l));
    let mut l = good();
    l.data_guest_top = l.data_guest_bottom - 1;
    assert!(!layout_ok(&l));

    // stackWide / dataWide: a region narrower than MAX_GROUP_SPAN.
    let mut l = good();
    l.stack_guest_top = l.stack_guest_bottom + 4095;
    assert!(!layout_ok(&l));
    let mut l = good();
    l.data_guest_top = l.data_guest_bottom + 4095;
    assert!(!layout_ok(&l));

    // stackNativeNoWrap / dataNativeNoWrap / descNoWrap.
    let mut l = good();
    l.stack_native_base = u64::MAX - 8;
    assert!(!layout_ok(&l));
    let mut l = good();
    l.data_native_base = u64::MAX - 8;
    assert!(!layout_ok(&l));
    let mut l = good();
    l.descriptor = u64::MAX - 8;
    assert!(!layout_ok(&l));

    // nativeStackNoWrap.
    let mut l = good();
    l.native_stack_hi = l.native_stack_lo - 1;
    assert!(!layout_ok(&l));

    // guestDisjoint: the data region overlapping the guest stack window.
    let mut l = good();
    l.data_guest_bottom = l.stack_guest_top - 8;
    assert!(!layout_ok(&l));

    // nativeDisjoint: the two backings overlapping.
    let mut l = good();
    l.data_native_base = l.stack_native_base + 8;
    assert!(!layout_ok(&l));

    // stackNativeOffPage / dataNativeOffPage.
    let mut l = good();
    l.stack_native_base = 0x800;
    assert!(!layout_ok(&l));
    let mut l = good();
    l.data_native_base = 0x800;
    assert!(!layout_ok(&l));

    // descOffPage.
    let mut l = good();
    l.descriptor = 0x100;
    assert!(!layout_ok(&l));

    // nativeStackOffPage.
    let mut l = good();
    l.native_stack_lo = 0;
    l.native_stack_hi = 0x10_0000;
    l.native_floor = 0x4000;
    assert!(!layout_ok(&l));

    // stackNativeOffDesc / dataNativeOffDesc.
    let mut l = good();
    l.descriptor = l.stack_native_base + 16;
    assert!(!layout_ok(&l));
    let mut l = good();
    l.descriptor = l.data_native_base + 16;
    assert!(!layout_ok(&l));

    // stackNativeOffNativeStack / dataNativeOffNativeStack.
    let mut l = good();
    l.native_stack_lo = l.stack_native_base + 0x1000;
    l.native_stack_hi = l.native_stack_lo + 0x1000;
    l.native_floor = l.native_stack_lo + 0x400;
    assert!(!layout_ok(&l));
    let mut l = good();
    l.native_stack_lo = l.data_native_base + 0x1000;
    l.native_stack_hi = l.native_stack_lo + 0x1000;
    l.native_floor = l.native_stack_lo + 0x400;
    assert!(!layout_ok(&l));

    // descOffNativeStack.
    let mut l = good();
    l.descriptor = l.native_stack_lo + 0x100;
    assert!(!layout_ok(&l));

    // floorRoom: the floor one byte below frame_size + stride above the base.
    let mut l = good();
    l.guest_floor = l.stack_native_base + l.frame_size + l.frame_stride - 1;
    assert!(!layout_ok(&l));

    // floorNative: the floor one byte below the 240-byte call reserve.
    let mut l = good();
    l.native_floor = l.native_stack_lo + NATIVE_CALL_RESERVE - 1;
    assert!(!layout_ok(&l));
  }

  #[test]
  fn the_boundary_cases_of_each_room_clause_are_accepted() {
    let mut l = good();
    l.guest_floor = l.stack_native_base + l.frame_size + l.frame_stride;
    assert!(layout_ok(&l));
    let mut l = good();
    l.native_floor = l.native_stack_lo + NATIVE_CALL_RESERVE;
    assert!(layout_ok(&l));
    // Regions exactly one page wide, and windows that abut without meeting.
    let mut l = good();
    l.stack_guest_top = l.stack_guest_bottom + MIN_REGION_SPAN;
    l.data_guest_bottom = l.stack_guest_top;
    l.data_guest_top = l.data_guest_bottom + MIN_REGION_SPAN;
    l.data_native_base = l.stack_native_base + MIN_REGION_SPAN;
    assert!(layout_ok(&l));
  }

  #[test]
  fn disjointness_is_symmetric_and_abutting_ranges_do_not_meet() {
    assert!(disjoint(0x1000, 0x1000, 0x2000, 0x1000));
    assert!(disjoint(0x2000, 0x1000, 0x1000, 0x1000));
    assert!(!disjoint(0x1000, 0x1001, 0x2000, 0x1000));
    assert!(!disjoint(0x2000, 0x1000, 0x1000, 0x1001));
    // An empty range never meets anything, whatever it abuts.
    assert!(disjoint(0x1000, 0, 0x1000, 0x1000));
    // An end that is not representable is reported as meeting.
    assert!(!disjoint(u64::MAX, 2, 0, 1));
  }

  #[test]
  fn sub_mod_agrees_with_wrapping_sub() {
    let xs = [
      0u64,
      1,
      2,
      8,
      4096,
      0x7fff_ffff_ffff_ffff,
      0x8000_0000_0000_0000,
      u64::MAX - 1,
      u64::MAX,
    ];
    for a in xs {
      for b in xs {
        assert_eq!(sub_mod(a, b), a.wrapping_sub(b), "{a:#x} - {b:#x}");
      }
    }
  }

  #[test]
  fn derived_block_agrees_with_the_wrapping_formulation() {
    let cases = [
      (0x1_0000u64, 0x9_0000u64, 0x7000_0000_0000u64),
      (0, 8, 0),
      (0, 0, u64::MAX),
      (u64::MAX, u64::MAX, 1),
      (0x10_0000, 0x20_0000, 0x40),
    ];
    for (bottom, top, native_base) in cases {
      let mut want = [0u64; 6];
      want[0] = bottom;
      want[1] = native_base.wrapping_sub(bottom);
      want[2] = top.wrapping_sub(1).wrapping_sub(bottom);
      want[3] = top.wrapping_sub(2).wrapping_sub(bottom);
      want[4] = top.wrapping_sub(4).wrapping_sub(bottom);
      want[5] = top.wrapping_sub(8).wrapping_sub(bottom);
      assert_eq!(derived_block(bottom, top, native_base), want);
    }
  }
}

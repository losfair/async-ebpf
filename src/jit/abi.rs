//! The contract between the entry trampoline, the JIT backends, and the
//! runtime's memory descriptor.
//!
//! These displacements are stated in three places: the `global_asm!` entry
//! trampolines in `program.rs`, the `JitMemory` struct they fill in, and here.
//! If they ever drift, the symptom is a legitimate guest program corrupting
//! host memory or aborting the process rather than taking a fault.
//!
//! Both emitters read this module. The trampolines do not: their `global_asm!`
//! blocks are raw string literals with hard-coded displacements, and
//! `JitMemory`'s `offset_of` assertions use literals too. So this is the
//! authority by convention, not by construction — editing a constant here
//! produces no compile error in the trampoline that has to agree with it.
//!
//! `jit::audit::trampoline_contract` closes that gap from the other side: it
//! reads `program.rs` with `include_str!` and asserts every displacement in both
//! trampolines equals the value named here. That is a test rather than a type,
//! so it is worth knowing it exists — a change here that the trampoline does not
//! follow fails there and nowhere else.
//!
//! Making the trampolines take `const` operands would be the real fix and is
//! left as a follow-up; it changes generated code, which this port deliberately
//! does not.
//!
//! Both backends use the same values, so they are stated once here rather than
//! per-architecture.

/// Byte offsets into the `JitMemory` descriptor the runtime builds once per
/// invocation and whose address lives at [`FRAME_OFFSET`] below the frame
/// pointer.
pub mod memory {
  pub const STACK_GUEST_BOTTOM: i32 = 0;
  pub const STACK_GUEST_TOP: i32 = 8;
  pub const STACK_NATIVE_BASE: i32 = 16;
  pub const DATA_GUEST_BOTTOM: i32 = 24;
  pub const DATA_GUEST_TOP: i32 = 32;
  pub const DATA_NATIVE_BASE: i32 = 40;
}

/// Where the descriptor pointer itself is parked, relative to the established
/// frame pointer.
pub const FRAME_OFFSET: i32 = -8;

/// Scratch slots the bounds-check sequence spills through when the frame
/// constants are not available.
pub const SPILL_OFFSET: i32 = -16;
/// Scratch slot holding the untranslated guest address during a dual-region probe.
pub const ADDR_SPILL_OFFSET: i32 = -24;
/// Scratch slot accumulating the stack-region candidate during a dual-region probe.
pub const ACC_SPILL_OFFSET: i32 = -32;

/// Where the entry code parks `native_base - guest_bottom` for the stack region,
/// so a program that reads `R10` as a value rather than as a memory base can
/// have the guest address recovered. Only meaningful under
/// [`super::Config::native_frame_base`].
pub const FRAME_DELTA_OFFSET: i32 = -40;

/// How many derived bounds-check constants the entry code fills in.
pub const DERIVED_SLOTS: usize = 12;

/// The frame displacement of derived slot `i`.
///
/// The twelve slots are, in order: for the stack region and then the data
/// region, the guest bottom, the guest-to-native delta, and the four spans
/// `(guest_top - w) - guest_bottom` for access widths 1, 2, 4 and 8.
pub const fn derived_slot(i: usize) -> i32 {
  debug_assert!(i < DERIVED_SLOTS);
  -136 + (i as i32) * 8
}

/// Base slot index of the stack region's derived constants.
pub const DERIVED_STACK_BASE: usize = 0;
/// Base slot index of the data region's derived constants.
pub const DERIVED_DATA_BASE: usize = 6;
/// Offset within a region's block of the guest bottom.
pub const DERIVED_BOTTOM: usize = 0;
/// Offset within a region's block of the guest-to-native delta.
pub const DERIVED_DELTA: usize = 1;
/// Offset within a region's block of the first (width-1) span.
pub const DERIVED_SPAN: usize = 2;

/// Access widths the derived span slots cover, in slot order.
pub const ACCESS_WIDTHS: [usize; 4] = [1, 2, 4, 8];

/// Maps an access width to its span slot index within a region's block.
///
/// A width the table does not cover has no span slot; the caller must not ask.
pub const fn span_slot_index(width: usize) -> Option<usize> {
  match width {
    1 => Some(0),
    2 => Some(1),
    4 => Some(2),
    8 => Some(3),
    _ => None,
  }
}

/// Where an access group's leader parks the translated base for its members.
pub const GROUP_BASE_OFFSET: i32 = -144;

/// Bytes of frame the generated prologue reserves below the frame pointer for
/// all of the above.
pub const FRAME_RESERVED: i32 = 160;

/// Per-instruction region routing hints. The values are shared with
/// `crate::region_analysis`, which produces them.
pub mod region {
  /// Probe both regions.
  pub const UNKNOWN: u8 = 0;
  /// Check against the guest stack only.
  pub const STACK: u8 = 1;
  /// Check against the guest data region only.
  pub const DATA: u8 = 2;
  /// A displacement off an unmodified frame pointer that provably stays inside
  /// the guest stack, emitted with no bounds check at all. Only honoured under
  /// [`super::Config::native_frame_base`], and the backend re-derives the
  /// conditions it can see for itself before trusting it.
  pub const FRAME: u8 = 3;
}

/// Access plan roles.
pub mod plan_role {
  pub const NONE: u8 = 0;
  pub const LEADER: u8 = 1;
  pub const MEMBER: u8 = 2;
}

/// Widest window one access group may cover.
///
/// A failed check leaves the parked base at 0, so a member then dereferences
/// `[0 + delta]`. That has to land inside the runtime's guard window - the range
/// its fault handler claims as a guest fault rather than a host crash - which
/// bounds delta, and with it the span, at one page.
pub const MAX_GROUP_SPAN: u32 = 4096;

/// Guest stack charged to each local function.
pub const LOCAL_FUNCTION_STACK_SIZE: u16 = 4096;

/// Maximum eBPF call depth permitted.
pub const MAX_CALL_DEPTH: u32 = 8;

/// Total guest stack `UBPF_EBPF_STACK_SIZE` describes.
pub const EBPF_STACK_SIZE: u32 = MAX_CALL_DEPTH * LOCAL_FUNCTION_STACK_SIZE as u32;

/// Maximum instructions in a single loaded program.
pub const MAX_INSTS: u32 = 65536;

/// Maximum registered external helper functions.
pub const MAX_EXT_FUNCS: u32 = 64;

/// Callee-saved eBPF registers `R6`-`R9`, in bytes.
pub const NONVOLATILE_SIZE: u32 = 8 * 5;

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn the_derived_slots_are_contiguous_and_land_above_the_group_base() {
    for i in 0..DERIVED_SLOTS {
      assert_eq!(derived_slot(i), -136 + (i as i32) * 8);
    }
    // The group base sits immediately below the last derived slot, and the
    // whole block has to fit in the reserved frame.
    assert_eq!(derived_slot(DERIVED_SLOTS - 1), -48);
    assert!(GROUP_BASE_OFFSET < derived_slot(0));
    assert!(-FRAME_RESERVED <= GROUP_BASE_OFFSET);
  }

  #[test]
  fn every_access_width_has_a_span_slot_in_the_documented_order() {
    for (expected, width) in ACCESS_WIDTHS.iter().enumerate() {
      assert_eq!(span_slot_index(*width), Some(expected));
    }
    assert_eq!(span_slot_index(3), None);
    assert_eq!(span_slot_index(16), None);
  }

  #[test]
  fn a_region_block_covers_bottom_delta_and_four_spans() {
    assert_eq!(DERIVED_DATA_BASE - DERIVED_STACK_BASE, 6);
    assert_eq!(DERIVED_SPAN + ACCESS_WIDTHS.len(), 6);
    assert_eq!(DERIVED_DATA_BASE + 6, DERIVED_SLOTS);
  }

  /// The numbers themselves, written out.
  ///
  /// Every constant below is part of the contract with loaded programs and with
  /// the entry trampolines: change one and previously valid programs are
  /// refused, or the stack the guest is given stops matching the stack the
  /// prologue reserves. None of them can be derived from anything else in the
  /// tree, so restating them here is what makes an edit to one of them a
  /// deliberate act rather than a typo nobody notices.
  #[test]
  fn the_constants_are_the_ones_the_contract_names() {
    // One local eBPF function's stack frame, and the eight-deep call chain
    // built out of it: together they are the whole guest stack.
    assert_eq!(LOCAL_FUNCTION_STACK_SIZE, 4096);
    assert_eq!(MAX_CALL_DEPTH, 8);
    assert_eq!(EBPF_STACK_SIZE, 32768);

    // The widest window one bounds check may cover, so that a checked group
    // can never straddle more than a page.
    assert_eq!(MAX_GROUP_SPAN, 4096);

    // The instruction ceiling a loaded program may not reach: 65536 is refused,
    // 65535 is accepted.
    //
    // The same number is reused as the per-patch-table ceiling, but not for the
    // reason it looks like: a fixup is not one per instruction. A single helper
    // call emits three jump fixups, so roughly 21,800 helper calls cross the
    // ceiling in a program comfortably inside the instruction limit. See
    // `patch::MAX_JUMPS`.
    assert_eq!(MAX_INSTS, 65536);

    // Helper indices run 0..64, which is what makes the helper address table a
    // fixed-size block the emitted code can index without a bounds check.
    assert_eq!(MAX_EXT_FUNCS, 64);
  }
}

//! The code buffer, the patch tables, and the open-access-group bookkeeping.
//!
//! Port of `ubpf_jit_support.{c,h}`, minus the parts nothing reaches:
//! constant-blinding seed generation (`ubpf_toggle_constant_blinding` is not in
//! the reachable seam) and the malloc/realloc growth dance, which is what a
//! `Vec` already does.
//!
//! # Why the two backends share this and not the driver
//!
//! `translate_range` in the two C backends shares only its preamble checks;
//! after that arm64 runs a barrier pre-pass x86_64 does not have, and the two
//! loops have drifted before — the arm64 jump-sentinel bug lived in exactly that
//! gap. Unifying them would be a refactor performed during a port that is
//! required to be byte-identical, so each backend keeps its own loop and shares
//! only the state below.

use super::TranslateError;

/// How far a translation got, and why it stopped.
///
/// Mirrors `enum JitProgress`. Everything except [`Progress::Ok`] aborts the
/// translation; [`Progress::NotEnoughSpace`] is the one that must stay
/// distinguishable, because the caller's code arena treats it as terminal for
/// the whole program rather than for one function.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Progress {
  Ok,
  TooManyJumps,
  TooManyLoads,
  TooManyLeas,
  TooManyLocalCalls,
  NotEnoughSpace,
  UnexpectedInstruction,
  UnknownInstruction,
  RelocationOutOfRange,
}

impl Progress {
  /// The error a non-`Ok` progress turns into.
  ///
  /// The strings are reproduced from the C because `program.rs` surfaces them
  /// verbatim to callers and tests match on them. They become typed variants
  /// only once the oracle is retired.
  pub fn into_error(self) -> Option<TranslateError> {
    let msg = match self {
      Progress::Ok => return None,
      Progress::NotEnoughSpace => return Some(TranslateError::OutOfSpace),
      Progress::TooManyJumps => "Too many jump instructions",
      Progress::TooManyLoads => "Too many load instructions",
      Progress::TooManyLeas => "Too many lea instructions",
      Progress::TooManyLocalCalls => "Too many local calls",
      Progress::UnexpectedInstruction => "Unexpected instruction",
      Progress::UnknownInstruction => "Unknown instruction",
      Progress::RelocationOutOfRange => "Relocation out of range",
    };
    Some(TranslateError::Failed(msg.to_string()))
  }
}

/// A control-flow target whose location is not yet known.
///
/// The C models this as a tagged union with a `bool is_special`; an enum says
/// the same thing without the discipline of keeping the tag and the payload in
/// step.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PatchTarget {
  /// One of the generated stubs, whose offset the state records.
  Special(SpecialTarget),
  /// An eBPF instruction, located through `pc_locs`.
  EbpfPc { pc: u32, near: bool },
  /// A native offset already known at emission time, bypassing `pc_locs`.
  JitOffset { offset: u32, near: bool },
}

/// The generated stubs a patchable target can name. Mirrors `enum SpecialTarget`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SpecialTarget {
  Exit,
  Enter,
  Retpoline,
  ExternalDispatcher,
  LoadHelperTable,
}

/// One deferred fixup: a location in the emitted stream, and how to compute what
/// belongs there.
#[derive(Copy, Clone, Debug)]
pub struct PatchableRelative {
  /// Where in the emitted stream the resolved target is written.
  pub offset_loc: u32,
  pub target: PatchTarget,
}

/// The scratch state for one translation.
///
/// Port of `struct jit_state`. The four patch tables are `Vec`s rather than
/// hand-grown arrays, so `reserve_patchable_relatives` and its capacity fields
/// have no analogue here — but the *limits* those capacities implied are gone
/// too, which would be a behaviour change, so the `TooMany*` progress values are
/// retained and checked against the same bounds the C grew to.
pub struct JitState<'a> {
  /// The output buffer. Writes past its end set [`Progress::NotEnoughSpace`]
  /// rather than panicking, matching the C's `emit_bytes` guard.
  pub buf: &'a mut [u8],
  /// Bytes emitted so far.
  pub offset: u32,

  /// Native offset of each eBPF instruction, indexed by absolute pc.
  pub pc_locs: Vec<u32>,

  pub exit_loc: u32,
  pub entry_loc: u32,
  pub unwind_loc: u32,
  pub retpoline_loc: u32,
  /// Offset of the slot holding the external dispatcher's address.
  pub dispatcher_loc: u32,
  /// Offset of the consecutive helper address table.
  pub helper_table_loc: u32,

  pub status: Progress,

  pub jumps: Vec<PatchableRelative>,
  pub loads: Vec<PatchableRelative>,
  pub leas: Vec<PatchableRelative>,
  pub local_calls: Vec<PatchableRelative>,

  pub stack_size: u32,
  /// Bytes emitted at the start of the function, before the first instruction.
  pub prolog_size: usize,

  /// State of the open access group, if any.
  ///
  /// A group's members address the base its leader checked and parked, so the
  /// backend has to know the leader really did run: that it is the most recent
  /// one emitted, that no branch can land between the two, and that nothing
  /// redefined the base register in between. The plan asserts all of this, but
  /// the plan is not trusted — these fields are what the backend derives for
  /// itself while walking the instruction stream.
  pub group: Option<OpenGroup>,
  /// Non-zero where a branch can land, which closes any open group. Indexed by
  /// absolute eBPF pc.
  pub group_barrier: Vec<bool>,
}

/// The access group currently open, as the backend has verified it.
#[derive(Copy, Clone, Debug)]
pub struct OpenGroup {
  pub leader_pc: u32,
  /// Bytes the leader's check covered.
  pub span: u32,
  /// The low bound, relative to the base register.
  pub lo: i32,
  /// eBPF register the group is based on.
  pub base_reg: u8,
  /// Region the leader checked against.
  pub region: u8,
  /// eBPF registers written since the leader ran. A write to the base register
  /// invalidates the group.
  pub written: u16,
}

/// Growth bounds the C's tables reached before erroring. Retained so that a
/// pathological program is rejected identically rather than allocating without
/// limit.
pub const MAX_JUMPS: usize = 1 << 20;
pub const MAX_LOADS: usize = 1 << 20;
pub const MAX_LEAS: usize = 1 << 20;
pub const MAX_LOCAL_CALLS: usize = 1 << 20;

impl<'a> JitState<'a> {
  /// Prepares the scratch state for one translation.
  ///
  /// `pc_locs` is indexed by absolute eBPF pc, so it is sized from the whole
  /// program even when only a range is being translated. Mirrors
  /// `initialize_jit_state_result`.
  pub fn new(buf: &'a mut [u8], num_insts: usize) -> Self {
    Self {
      buf,
      offset: 0,
      // The C over-allocates by one so a jump to the instruction one past the
      // end - which `exit` fixups use - has a slot.
      pc_locs: vec![0; num_insts + 1],
      exit_loc: 0,
      entry_loc: 0,
      unwind_loc: 0,
      retpoline_loc: 0,
      dispatcher_loc: 0,
      helper_table_loc: 0,
      status: Progress::Ok,
      jumps: Vec::new(),
      loads: Vec::new(),
      leas: Vec::new(),
      local_calls: Vec::new(),
      stack_size: 0,
      prolog_size: 0,
      group: None,
      group_barrier: vec![false; num_insts + 1],
    }
  }

  /// Whether the translation is still viable.
  pub fn ok(&self) -> bool {
    self.status == Progress::Ok
  }

  /// Records the first failure. Later failures do not overwrite the first, so
  /// the reported cause is the one that actually stopped progress.
  pub fn fail(&mut self, progress: Progress) {
    if self.status == Progress::Ok {
      self.status = progress;
    }
  }

  /// Appends one byte, failing with [`Progress::NotEnoughSpace`] if the buffer
  /// is full.
  #[inline]
  pub fn emit1(&mut self, byte: u8) {
    let at = self.offset as usize;
    if at >= self.buf.len() {
      self.fail(Progress::NotEnoughSpace);
      return;
    }
    self.buf[at] = byte;
    self.offset += 1;
  }

  /// Appends `n` little-endian bytes of `value`.
  ///
  /// Mirrors `emit_bytes`: the C writes a fixed-width integer through a memcpy,
  /// so only the low `n` bytes are used and the rest are discarded.
  #[inline]
  pub fn emit_bytes(&mut self, value: u64, n: usize) {
    debug_assert!(n <= 8);
    let at = self.offset as usize;
    if at + n > self.buf.len() {
      self.fail(Progress::NotEnoughSpace);
      // The C advances `offset` past the end so that the *final* size report
      // still says how much room would have been needed. Matching that keeps
      // the out-of-space path byte-compatible.
      self.offset = self.offset.saturating_add(n as u32);
      return;
    }
    self.buf[at..at + n].copy_from_slice(&value.to_le_bytes()[..n]);
    self.offset += n as u32;
  }

  /// Overwrites `n` little-endian bytes at an already-emitted location.
  ///
  /// Used by the fixup passes, which write into space the emitter reserved, so
  /// running off the end here is a bug rather than a capacity problem.
  #[inline]
  pub fn patch_bytes(&mut self, at: u32, value: u64, n: usize) {
    let at = at as usize;
    if at + n > self.buf.len() {
      self.fail(Progress::NotEnoughSpace);
      return;
    }
    self.buf[at..at + n].copy_from_slice(&value.to_le_bytes()[..n]);
  }

  /// Reads `n` little-endian bytes back out of the emitted stream.
  #[inline]
  pub fn read_bytes(&self, at: u32, n: usize) -> u64 {
    let at = at as usize;
    let mut raw = [0u8; 8];
    let end = (at + n).min(self.buf.len());
    if at < end {
      raw[..end - at].copy_from_slice(&self.buf[at..end]);
    }
    u64::from_le_bytes(raw)
  }

  /// Records a deferred jump fixup. Mirrors `emit_patchable_relative` against
  /// the jumps table.
  pub fn note_jump(&mut self, offset_loc: u32, target: PatchTarget) {
    if self.jumps.len() >= MAX_JUMPS {
      self.fail(Progress::TooManyJumps);
      return;
    }
    self.jumps.push(PatchableRelative { offset_loc, target });
  }

  /// Records a deferred load fixup. Mirrors `note_load`.
  pub fn note_load(&mut self, offset_loc: u32, target: PatchTarget) {
    if self.loads.len() >= MAX_LOADS {
      self.fail(Progress::TooManyLoads);
      return;
    }
    self.loads.push(PatchableRelative { offset_loc, target });
  }

  /// Records a deferred lea fixup. Mirrors `note_lea`.
  pub fn note_lea(&mut self, offset_loc: u32, target: PatchTarget) {
    if self.leas.len() >= MAX_LEAS {
      self.fail(Progress::TooManyLeas);
      return;
    }
    self.leas.push(PatchableRelative { offset_loc, target });
  }

  /// Records a deferred local-call fixup.
  pub fn note_local_call(&mut self, offset_loc: u32, target: PatchTarget) {
    if self.local_calls.len() >= MAX_LOCAL_CALLS {
      self.fail(Progress::TooManyLocalCalls);
      return;
    }
    self.local_calls.push(PatchableRelative { offset_loc, target });
  }

  /// Retargets every jump fixup that was emitted at `src` to `target`.
  ///
  /// Mirrors `modify_patchable_relatives_target`. Used where a jump is emitted
  /// before its real destination is known — the `exit` path retargets to the
  /// unwind stub once it has been placed.
  pub fn retarget_jumps(&mut self, src: u32, target: PatchTarget) {
    for entry in &mut self.jumps {
      if entry.offset_loc == src {
        entry.target = target;
      }
    }
  }

  /// Marks `pc` as a place a branch can land, which closes any group open
  /// across it.
  pub fn mark_barrier(&mut self, pc: usize) {
    if let Some(slot) = self.group_barrier.get_mut(pc) {
      *slot = true;
    }
  }

  /// Whether a branch can land on `pc`.
  pub fn is_barrier(&self, pc: usize) -> bool {
    self.group_barrier.get(pc).copied().unwrap_or(true)
  }

  /// Closes the open access group, if any.
  pub fn close_group(&mut self) {
    self.group = None;
  }

  /// Notes that `reg` has been written, invalidating any group based on it.
  pub fn note_register_written(&mut self, reg: u8) {
    if let Some(group) = &mut self.group {
      group.written |= 1u16 << (reg & 0xf);
      if group.base_reg == reg {
        self.group = None;
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn emitting_past_the_end_reports_out_of_space_rather_than_panicking() {
    let mut buf = [0u8; 4];
    let mut state = JitState::new(&mut buf, 1);
    state.emit_bytes(0x1122_3344, 4);
    assert!(state.ok());
    state.emit_bytes(0x55, 1);
    assert_eq!(state.status, Progress::NotEnoughSpace);
    assert_eq!(
      Progress::NotEnoughSpace.into_error(),
      Some(TranslateError::OutOfSpace)
    );
  }

  #[test]
  fn the_first_failure_is_the_one_reported() {
    let mut buf = [0u8; 1];
    let mut state = JitState::new(&mut buf, 1);
    state.fail(Progress::UnknownInstruction);
    state.fail(Progress::NotEnoughSpace);
    assert_eq!(state.status, Progress::UnknownInstruction);
  }

  #[test]
  fn only_the_low_n_bytes_of_a_value_are_emitted() {
    let mut buf = [0u8; 8];
    let mut state = JitState::new(&mut buf, 1);
    state.emit_bytes(0xdead_beef_1122_3344, 2);
    assert_eq!(&buf[..2], &[0x44, 0x33]);
  }

  #[test]
  fn writing_a_groups_base_register_closes_it() {
    let mut buf = [0u8; 8];
    let mut state = JitState::new(&mut buf, 4);
    state.group = Some(OpenGroup {
      leader_pc: 0,
      span: 16,
      lo: 0,
      base_reg: 3,
      region: 1,
      written: 0,
    });
    state.note_register_written(5);
    assert!(state.group.is_some(), "an unrelated write keeps the group");
    state.note_register_written(3);
    assert!(state.group.is_none(), "writing the base must close the group");
  }

  #[test]
  fn a_pc_outside_the_program_counts_as_a_barrier() {
    let mut buf = [0u8; 8];
    let state = JitState::new(&mut buf, 2);
    assert!(!state.is_barrier(0));
    assert!(state.is_barrier(99), "out of range must be conservative");
  }

  #[test]
  fn retargeting_only_touches_the_named_source() {
    let mut buf = [0u8; 8];
    let mut state = JitState::new(&mut buf, 2);
    state.note_jump(4, PatchTarget::EbpfPc { pc: 1, near: false });
    state.note_jump(8, PatchTarget::EbpfPc { pc: 2, near: false });
    state.retarget_jumps(8, PatchTarget::Special(SpecialTarget::Exit));
    assert_eq!(state.jumps[0].target, PatchTarget::EbpfPc { pc: 1, near: false });
    assert_eq!(state.jumps[1].target, PatchTarget::Special(SpecialTarget::Exit));
  }
}

//! The code buffer, the patch tables, and the open-access-group bookkeeping
//! that the two backends share.
//!
//! # Why the two backends share this and not the driver
//!
//! The two `translate_range` implementations have almost nothing in common past
//! their preamble checks: aarch64 runs a barrier pre-pass x86_64 does not have,
//! and the per-opcode work is entirely architecture-specific. What they do share
//! is bookkeeping — where the next byte goes, which sites still need a fixup,
//! whether an access group is open — and that is what lives here.
//!
//! The two loops have drifted apart before; the aarch64 jump-sentinel bug lived
//! in exactly the gap between them. Unifying them is a real option, but it is a
//! restructuring of both backends rather than a comment-level tidy, so for now
//! each keeps its own loop and shares only the state below.

use super::TranslateError;

/// How far a translation got, and why it stopped.
///
/// Everything except [`Progress::Ok`] aborts the translation;
/// [`Progress::NotEnoughSpace`] is the one that must stay distinguishable,
/// because the caller's code arena treats it as terminal for the whole program
/// rather than for one function.
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
  /// The error a non-`Ok` progress turns into, worded as `target`'s backend
  /// words it.
  ///
  /// `program.rs` surfaces these strings verbatim to callers and tests match on
  /// them, so the wording is part of the interface. They would be better as
  /// typed variants.
  ///
  /// Two things here are easy to get wrong and were:
  ///
  /// * The two backends disagree about punctuation — aarch64 ends each
  ///   `TooMany*` message with a full stop and x86_64 does not. Taking the
  ///   target is the difference between a helper correct for both and one
  ///   quietly correct for whichever backend called it first.
  /// * The three statuses below carry no message of their own, and must not be
  ///   given one here. Their text needs the pc and the opcode, neither of which
  ///   this function has, so the backend records an `errmsg` where the error is
  ///   *detected* and substitutes it before this helper is ever consulted.
  ///   Returning an empty string is how that arrangement stays visible: a
  ///   plausible-looking string invented here would silently become the message
  ///   for any path that forgot to record one.
  pub fn into_error(self, target: super::Target) -> Option<TranslateError> {
    let msg = match self {
      Progress::Ok => return None,
      Progress::NotEnoughSpace => return Some(TranslateError::OutOfSpace),
      Progress::TooManyJumps => "Too many jump instructions",
      Progress::TooManyLoads => "Too many load instructions",
      // "calculations", not "instructions", in both backends' wording.
      Progress::TooManyLeas => "Too many LEA calculations",
      Progress::TooManyLocalCalls => "Too many local calls",
      // Set at detection; see above.
      Progress::UnexpectedInstruction
      | Progress::UnknownInstruction
      | Progress::RelocationOutOfRange => return Some(TranslateError::Failed(String::new())),
    };
    let full_stop = match target {
      super::Target::Aarch64 => ".",
      super::Target::X86_64 => "",
    };
    Some(TranslateError::Failed(format!("{msg}{full_stop}")))
  }
}

/// A control-flow target whose location is not yet known.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PatchTarget {
  /// One of the generated stubs, whose offset the state records.
  Special(SpecialTarget),
  /// An eBPF instruction, located through `pc_locs`.
  EbpfPc { pc: u32, near: bool },
  /// A native offset already known at emission time, bypassing `pc_locs`.
  JitOffset { offset: u32, near: bool },
}

/// The generated stubs a patchable target can name.
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
/// The four patch tables are `Vec`s and grow on demand, so nothing here forces
/// a `TooMany*` failure by running out of room. The limits are still enforced
/// explicitly — see [`MAX_JUMPS`] and friends — because which programs the JIT
/// accepts is a property callers depend on, and dropping the ceilings just
/// because the storage no longer needs them would quietly widen it.
pub struct JitState<'a> {
  /// The output buffer. Writes past its end set [`Progress::NotEnoughSpace`]
  /// rather than panicking: running out of code space is an ordinary outcome
  /// the caller handles, not a bug.
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

/// Ceiling on each patch table, above which translation stops with the matching
/// `TooMany*` error.
///
/// [`MAX_INSTS`](super::abi::MAX_INSTS) — 65,536 — rather than a round number of
/// the tables' own. It is a real limit and not a formality: a fixup is not one
/// per instruction, because each helper call emits three jump fixups on its own,
/// so around 21,800 helper calls cross the ceiling, and a program that size is
/// comfortably inside the instruction limit.
///
/// That is also why the exact value matters. An earlier version used `1 << 20`,
/// sixteen times higher, which changed nothing about the bytes emitted for any
/// program that compiled and everything about which programs compiled at all —
/// the kind of difference a test that compares generated code cannot see, and
/// only a test that loads an oversized program will.
pub const MAX_JUMPS: usize = super::abi::MAX_INSTS as usize;
pub const MAX_LOADS: usize = super::abi::MAX_INSTS as usize;
pub const MAX_LEAS: usize = super::abi::MAX_INSTS as usize;
pub const MAX_LOCAL_CALLS: usize = super::abi::MAX_INSTS as usize;

impl<'a> JitState<'a> {
  /// Prepares the scratch state for one translation.
  ///
  /// `pc_locs` is indexed by absolute eBPF pc, so it is sized from the whole
  /// program even when only a range is being translated.
  pub fn new(buf: &'a mut [u8], num_insts: usize) -> Self {
    Self {
      buf,
      offset: 0,
      // One slot longer than the program: a jump to the instruction one past
      // the end - which `exit` fixups use - has to have somewhere to record
      // its native offset.
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

  /// Records a failure, overwriting any earlier one.
  ///
  /// Last assignment wins, deliberately. An earlier version kept the *first*
  /// failure, on the reasoning that it is the one that actually stopped
  /// progress; that is wrong, and the counterexample has teeth. Translating a
  /// range whose first instruction is both a local function entry and a local
  /// call, into a buffer too small for the prologue, overruns first
  /// (`NotEnoughSpace`) and then hits the lazy local-call guard
  /// (`UnexpectedInstruction`). Keeping the first reports `OutOfSpace` for a
  /// function that would not have translated into any buffer — and the two are
  /// not interchangeable to the caller, which treats `OutOfSpace` as terminal
  /// for the whole program and a plain failure as terminal for one function.
  ///
  /// This composes with `emit1`/`emit_bytes` refusing to emit once the status
  /// is set, so a failed *emit* still cannot overwrite an earlier status: only
  /// a check that actually ran can.
  pub fn fail(&mut self, progress: Progress) {
    self.status = progress;
  }

  /// Appends one byte, failing with [`Progress::NotEnoughSpace`] if the buffer
  /// is full.
  #[inline]
  pub fn emit1(&mut self, byte: u8) {
    // Never emit any bytes once there is an error. Without this guard the
    // emitters keep writing into the code arena, and keep advancing `offset`,
    // past the point where the output stopped being meaningful - and the
    // caller is handed a byte count for a buffer full of half a function.
    if !self.ok() {
      return;
    }
    let at = self.offset as usize;
    if at >= self.buf.len() {
      self.fail(Progress::NotEnoughSpace);
      return;
    }
    self.buf[at] = byte;
    self.offset += 1;
  }

  /// Appends the low `n` little-endian bytes of `value`.
  ///
  /// Any higher bytes are discarded rather than being an error, so callers can
  /// pass a widened value and name the field width separately.
  #[inline]
  pub fn emit_bytes(&mut self, value: u64, n: usize) {
    debug_assert!(n <= 8);
    // See `emit1`: nothing is emitted once the status is not Ok.
    if !self.ok() {
      return;
    }
    let at = self.offset as usize;
    if at + n > self.buf.len() {
      // `offset` is deliberately NOT advanced here.
      //
      // An earlier version of this advanced `offset` past the end, on the
      // theory that the final size report should say how much room would have
      // been needed. That is wrong:
      // `offset` is what the emitters measure spans with, so a failed emit that
      // moves it corrupts every later measurement taken from it. Concretely, a
      // buffer that runs out inside a *second* function's prologue then
      // produced a partial `prolog_size`, tripping a debug assertion instead of
      // reporting `OutOfSpace`.
      self.fail(Progress::NotEnoughSpace);
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

  /// Records a deferred jump fixup.
  pub fn note_jump(&mut self, offset_loc: u32, target: PatchTarget) {
    if self.jumps.len() >= MAX_JUMPS {
      self.fail(Progress::TooManyJumps);
      return;
    }
    self.jumps.push(PatchableRelative { offset_loc, target });
  }

  /// Records a deferred load fixup.
  pub fn note_load(&mut self, offset_loc: u32, target: PatchTarget) {
    if self.loads.len() >= MAX_LOADS {
      self.fail(Progress::TooManyLoads);
      return;
    }
    self.loads.push(PatchableRelative { offset_loc, target });
  }

  /// Records a deferred lea fixup.
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
    self
      .local_calls
      .push(PatchableRelative { offset_loc, target });
  }

  /// Retargets every jump fixup that was emitted at `src` to `target`.
  ///
  /// Used where a jump is emitted before its real destination is known — the
  /// `exit` path retargets to the unwind stub once it has been placed.
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
      Progress::NotEnoughSpace.into_error(crate::jit::Target::X86_64),
      Some(TranslateError::OutOfSpace)
    );
  }

  /// The last failure recorded is the one reported. Keeping the first instead
  /// changes which error the caller sees, and `OutOfSpace` is not
  /// interchangeable with a plain failure.
  #[test]
  fn the_last_failure_is_the_one_reported() {
    let mut buf = [0u8; 1];
    let mut state = JitState::new(&mut buf, 1);
    state.fail(Progress::NotEnoughSpace);
    state.fail(Progress::UnexpectedInstruction);
    assert_eq!(state.status, Progress::UnexpectedInstruction);
  }

  /// But a failed *emit* cannot overwrite a status, because it returns before
  /// reaching the length check.
  #[test]
  fn a_failed_emit_does_not_overwrite_an_existing_status() {
    let mut buf = [0u8; 1];
    let mut state = JitState::new(&mut buf, 1);
    state.fail(Progress::UnknownInstruction);
    state.emit_bytes(0xdead_beef, 4);
    assert_eq!(state.status, Progress::UnknownInstruction);
    assert_eq!(state.offset, 0);
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
    assert!(
      state.group.is_none(),
      "writing the base must close the group"
    );
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
    assert_eq!(
      state.jumps[0].target,
      PatchTarget::EbpfPc { pc: 1, near: false }
    );
    assert_eq!(
      state.jumps[1].target,
      PatchTarget::Special(SpecialTarget::Exit)
    );
  }
}

#[cfg(test)]
mod out_of_space_tests {
  use super::*;

  /// Regression: a failed emit must not move `offset`.
  ///
  /// The emitters measure spans - notably each function's prologue size - by
  /// differencing `offset`. If a failed emit advances it, every later
  /// measurement taken from it is wrong, and the symptom is a debug assertion
  /// firing somewhere unrelated rather than a clean `OutOfSpace`.
  ///
  #[test]
  fn a_failed_emit_leaves_the_offset_where_it_was() {
    let mut buf = [0u8; 4];
    let mut state = JitState::new(&mut buf, 1);
    state.emit_bytes(0x1122_3344, 4);
    assert_eq!(state.offset, 4);

    state.emit_bytes(0xaa, 1);
    assert_eq!(state.status, Progress::NotEnoughSpace);
    assert_eq!(
      state.offset, 4,
      "a failed emit moved the offset, which corrupts every span measured from it"
    );

    // And it stays put across further failed emits, so a span differenced
    // across a run of them is zero rather than arbitrary.
    state.emit_bytes(0xbbbb, 2);
    assert_eq!(state.offset, 4);
  }

  #[test]
  fn a_failed_single_byte_emit_also_leaves_the_offset_alone() {
    let mut buf = [0u8; 1];
    let mut state = JitState::new(&mut buf, 1);
    state.emit1(0x90);
    assert_eq!(state.offset, 1);
    state.emit1(0x90);
    assert_eq!(state.status, Progress::NotEnoughSpace);
    assert_eq!(state.offset, 1);
  }
}

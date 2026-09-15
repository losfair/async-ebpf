//! The memory-safety gate on the x86_64 backend's macro list.
//!
//! [`check`] is what `x64_lower` runs on the [`MInsn`] list it built, and a
//! function it refuses is a translation failure rather than code in the
//! arena. That is the hook the safety theorem hangs on: what the backend
//! returns is checked code, by construction.
//!
//! The walk carries an abstract state — a [`Tag`] per native register, the
//! native stack depth, the tag of the group base parked at `[rbp - 144]`,
//! and whether the walk is live — and applies the contract stated on each
//! [`MInsn`] variant. It never looks inside a macro. Each macro's expansion
//! is proved against its contract once, in `lean/AsyncEbpf/X64/Check.lean`,
//! with the operands symbolic, so the part of the backend that actually
//! changes — which sequence the lowering picks, for which slot, against
//! which region — is checked by a pass that only reads contracts.
//!
//! The tags carry the whole argument about guest memory. `Checked(w)` says
//! the register holds zero or a native address whose `w`-byte window lies
//! inside one guest region, which is what the branchless check sequence
//! establishes; `Fp` says the register still holds the native frame base the
//! entry code put there, which is what makes `[r15 + d]` an address in this
//! activation's island. So a guest access is admitted three ways and only
//! three: through a `Checked(w)` base with the access inside `[0, w)`,
//! through the frame register into the frame window under a native frame
//! base, or with the cage off, where the checker vouches for nothing about
//! guest memory because nothing was promised.
//!
//! The rest of the state is there to keep those three honest. The depth
//! bounds the native stack: every macro that pushes declares how deep, and
//! the running depth plus that stays under [`MAX_DEPTH`]. Liveness is what
//! lets the walk ignore code after a `jmp` or an epilogue, which is code no
//! execution reaches. And every slot a branch can land on is entered in the
//! entry state — depth one, the frame register intact, every other register
//! and the parked group base `Top` — which is what forbids a branch target
//! between a group's leader and its members: a different leader, with a
//! smaller window, could have parked since.
//!
//! Rejections name the macro and the eBPF slot it came from, and nothing
//! else; rendering them is the caller's business.

use super::x64_ir::*;

/// Native stack slots, eight bytes each, one activation may hold below its
/// entry `rsp`. The prologue's own slot counts, so the depth of a function
/// body is one and every macro that pushes must fit in the rest.
pub const MAX_DEPTH: u32 = 16;

/// The frame register: eBPF `R10` maps here, the entry code puts the native
/// frame base in it, and the generated code never writes it.
pub const FRAME: u8 = R15;

/// The registers the abstract state tracks, which is all of them.
const NUM_REGS: usize = 16;

/// A refused macro: its index in the list, and the eBPF slot being
/// translated, which is the most recent [`MInsn::PcLabel`] at or before it,
/// or zero when the walk has not reached one.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug))]
pub struct Unsafe {
  pub index: usize,
  pub pc: u32,
}

/// What is known about a native register's value.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug))]
pub enum Tag {
  /// Anything at all. Nothing may be dereferenced through it.
  Top,
  /// The entry value of the frame register: the native address of the top of
  /// this activation's guest stack island.
  Fp,
  /// Zero, or a native address whose window of this many bytes lies inside
  /// one guest region.
  Checked(u32),
}

/// The abstract state between two macros.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug))]
pub struct State {
  /// One tag per native register, indexed as in the ModRM encoding.
  pub regs: [Tag; NUM_REGS],
  /// Eight-byte native stack slots pushed since entry, the prologue's
  /// included.
  pub depth: u32,
  /// The tag of the group base parked at `[rbp - 144]`.
  pub group: Tag,
  /// Whether any execution reaches here. A dead walk still checks the
  /// structure — labels, branch targets, the trailer — but nothing about
  /// values.
  pub alive: bool,
}

/// The state before the first macro: the frame register holds the frame
/// base, nothing else is known, and nothing has been pushed.
pub fn entry_state() -> State {
  let mut st = State {
    regs: [Tag::Top; NUM_REGS],
    depth: 0,
    group: Tag::Top,
    alive: true,
  };
  set_tag(&mut st, FRAME, Tag::Fp);
  st
}

/// Writes a register's tag. Out-of-range register numbers, which no macro
/// the lowering builds carries, are dropped rather than trapping.
fn set_tag(st: &mut State, r: u8, tag: Tag) {
  if (r as usize) < NUM_REGS {
    st.regs[r as usize] = tag;
  }
}

/// Reads a register's tag. An out-of-range register number reads as `Top`,
/// which admits nothing.
fn tag_of(st: &State, r: u8) -> Tag {
  if (r as usize) < NUM_REGS {
    st.regs[r as usize]
  } else {
    Tag::Top
  }
}

/// Whether the frame register still holds its entry value.
fn frame_intact(st: &State) -> bool {
  match tag_of(st, FRAME) {
    Tag::Fp => true,
    Tag::Top => false,
    Tag::Checked(_) => false,
  }
}

fn reject(index: usize, pc: u32) -> Unsafe {
  Unsafe { index, pc }
}

/// The effect of a register-writing macro on its destination: `rsp`, `rbp`
/// and the frame register are not writable at all, and a destination outside
/// the sixteen registers is not a destination; anything else becomes `Top`.
fn write(st: &mut State, r: u8, index: usize, pc: u32) -> Result<(), Unsafe> {
  if r == RSP || r == RBP || r == FRAME || (r as usize) >= NUM_REGS {
    return Err(reject(index, pc));
  }
  set_tag(st, r, Tag::Top);
  Ok(())
}

/// Whether `pushes` more native stack slots fit.
fn depth_ok(st: &State, pushes: u32) -> bool {
  st.depth + pushes <= MAX_DEPTH
}

/// The state at a function entry, and at every slot a branch can land on:
/// one slot pushed, the frame register intact, nothing else known, no group
/// base parked.
fn enter(st: &mut State) {
  let mut r: usize = 0;
  while r < NUM_REGS {
    set_tag(st, r as u8, Tag::Top);
    r += 1;
  }
  set_tag(st, FRAME, Tag::Fp);
  st.depth = 1;
  st.group = Tag::Top;
  st.alive = true;
}

// ---------------------------------------------------------------------------
// The pre-pass: which slots are labelled, which are branched to, and whether
// the function has a trailer
// ---------------------------------------------------------------------------

/// What one walk over the list has to know about the whole of it.
struct Labels {
  /// Slots some `jcc` or `jmp` names.
  is_target: Vec<bool>,
  /// Slots a [`MInsn::PcLabel`] marks.
  has_label: Vec<bool>,
  /// Whether the list ends in `Epilogue, Retpoline, DispatcherSlot,
  /// HelperTable`, which is what a branch to [`Target::Exit`] and the
  /// retpoline's own placement need.
  trailer: bool,
}

/// The slot a macro labels: `(true, pc)` for a [`MInsn::PcLabel`].
fn label_of(insn: &MInsn) -> (bool, u32) {
  match insn {
    MInsn::PcLabel(pc) => (true, *pc),
    _ => (false, 0),
  }
}

/// Where a branch target points: `(1, pc)` for a slot, `(2, 0)` for the exit
/// epilogue. A tag rather than an `Option<Target>` so that callers branch on
/// a number once instead of matching twice.
fn target_of(target: &Target) -> (u8, u32) {
  match target {
    Target::Pc(pc) => (1, *pc),
    Target::Exit => (2, 0),
  }
}

/// The target a macro branches to, in [`target_of`]'s encoding, or `(0, 0)`
/// for a macro that does not branch.
fn branch_target(insn: &MInsn) -> (u8, u32) {
  match insn {
    MInsn::Jcc { target, .. } => target_of(target),
    MInsn::Jmp { target } => target_of(target),
    _ => (0, 0),
  }
}

/// The largest slot number any label or branch target names.
fn max_named_slot(code: &[MInsn]) -> u32 {
  let mut max: u32 = 0;
  let mut i: usize = 0;
  while i < code.len() {
    let insn = code[i];
    let (labelled, slot) = label_of(&insn);
    if labelled && slot > max {
      max = slot;
    }
    let (kind, target) = branch_target(&insn);
    if kind == 1 && target > max {
      max = target;
    }
    i += 1;
  }
  max
}

/// Collects the label and target tables, both indexed by slot up to the
/// largest one named.
fn scan(code: &[MInsn]) -> Labels {
  let size = max_named_slot(code) as usize + 1;
  let mut is_target: Vec<bool> = vec![false; size];
  let mut has_label: Vec<bool> = vec![false; size];
  let mut i: usize = 0;
  while i < code.len() {
    let insn = code[i];
    let (labelled, slot) = label_of(&insn);
    if labelled && (slot as usize) < size {
      has_label[slot as usize] = true;
    }
    let (kind, target) = branch_target(&insn);
    if kind == 1 && (target as usize) < size {
      is_target[target as usize] = true;
    }
    i += 1;
  }
  Labels {
    is_target,
    has_label,
    trailer: has_trailer(code),
  }
}

/// Whether a branch can land on `slot`.
fn is_target(labels: &Labels, slot: u32) -> bool {
  (slot as usize) < labels.is_target.len() && labels.is_target[slot as usize]
}

/// Whether `slot` has a label to land on.
fn is_labelled(labels: &Labels, slot: u32) -> bool {
  (slot as usize) < labels.has_label.len() && labels.has_label[slot as usize]
}

fn is_epilogue(insn: MInsn) -> bool {
  match insn {
    MInsn::Epilogue => true,
    _ => false,
  }
}

fn is_retpoline(insn: MInsn) -> bool {
  match insn {
    MInsn::Retpoline => true,
    _ => false,
  }
}

fn is_dispatcher_slot(insn: MInsn) -> bool {
  match insn {
    MInsn::DispatcherSlot => true,
    _ => false,
  }
}

fn is_helper_table(insn: MInsn) -> bool {
  match insn {
    MInsn::HelperTable => true,
    _ => false,
  }
}

/// Whether the retpoline at `i` has the rest of the trailer around it: the
/// epilogue before it, the dispatcher slot and the helper table after it,
/// and nothing at all after those.
fn trailer_at(code: &[MInsn], i: usize) -> bool {
  i >= 1
    && i + 3 == code.len()
    && is_epilogue(code[i - 1])
    && is_retpoline(code[i])
    && is_dispatcher_slot(code[i + 1])
    && is_helper_table(code[i + 2])
}

/// Whether the list ends in a trailer.
fn has_trailer(code: &[MInsn]) -> bool {
  code.len() >= 4 && trailer_at(code, code.len() - 3)
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// The checked-base rule: the base holds a window of `size` bytes and the
/// access lies inside it. Computed in `i64`, where neither sum can wrap.
fn checked_ok(st: &State, base: u8, disp: i64, size: i64) -> bool {
  match tag_of(st, base) {
    Tag::Checked(width) => disp >= 0 && disp + size <= width as i64,
    Tag::Fp => false,
    Tag::Top => false,
  }
}

/// The frame fast path: the frame register, still holding the frame base,
/// with the access inside the frame window `[-stack_frame_size, 0)`.
fn frame_ok(cfg: &Cfg, st: &State, base: u8, disp: i64, size: i64) -> bool {
  base == FRAME
    && frame_intact(st)
    && cfg.pointer_mask != 0
    && cfg.native_frame_base
    && disp >= -(cfg.stack_frame_size as i64)
    && disp + size <= 0
}

/// Whether a guest access of `size` bytes at `[base + disp]` is admitted.
/// With the cage off every access is: the emitted code is raw, and the
/// checker vouches for nothing about guest memory.
fn addr_ok(cfg: &Cfg, st: &State, base: u8, disp: i32, size: u32) -> bool {
  cfg.pointer_mask == 0
    || checked_ok(st, base, disp as i64, size as i64)
    || frame_ok(cfg, st, base, disp as i64, size as i64)
}

/// The width an atomic operates at.
fn atomic_size(w64: bool) -> u32 {
  if w64 {
    8
  } else {
    4
  }
}

// ---------------------------------------------------------------------------
// The per-macro rules
// ---------------------------------------------------------------------------

/// Whether a register-to-register ALU operation writes its destination.
fn alu_rr_writes(op: AluRR) -> bool {
  match op {
    AluRR::Cmp => false,
    AluRR::Test => false,
    AluRR::Add => true,
    AluRR::Sub => true,
    AluRR::Or => true,
    AluRR::And => true,
    AluRR::Xor => true,
    AluRR::Mov => true,
  }
}

/// Whether a register-with-immediate ALU operation writes its destination.
fn alu_ri_writes(op: AluRI) -> bool {
  match op {
    AluRI::Cmp => false,
    AluRI::Test => false,
    AluRI::Add => true,
    AluRI::Sub => true,
    AluRI::Or => true,
    AluRI::And => true,
    AluRI::Xor => true,
    AluRI::Mov => true,
  }
}

/// A label. One a branch can land on is an entry: the state there is the
/// meet of every path to it, and the entry state is what every path has to
/// establish, so a live path into it must arrive at depth one with the frame
/// register intact, and everything else is forgotten. A label nothing
/// branches to is a position and nothing more.
fn label_step(
  labels: &Labels,
  slot: u32,
  index: usize,
  pc: u32,
  st: &mut State,
) -> Result<(), Unsafe> {
  if !is_target(labels, slot) {
    return Ok(());
  }
  if st.alive && (st.depth != 1 || !frame_intact(st)) {
    return Err(reject(index, pc));
  }
  enter(st);
  Ok(())
}

/// Whether a prologue may stand here: any dead state; a skippable one at
/// depth one with the frame register intact; a plain one at depth zero.
fn prologue_ok(skip: bool, st: &State) -> bool {
  if !st.alive {
    return true;
  }
  if skip {
    if st.depth != 1 {
      return false;
    }
    return frame_intact(st);
  }
  if st.depth == 0 {
    true
  } else {
    false
  }
}

/// The prologue. Reached from a dead state — the start of the range, or the
/// slot after a `jmp` or an epilogue — it pushes the one slot the body runs
/// at. A skippable one is also fallen into from the instruction before it,
/// which has already pushed that slot and jumps over the push.
fn prologue_step(skip: bool, index: usize, pc: u32, st: &mut State) -> Result<(), Unsafe> {
  let ok = prologue_ok(skip, st);
  if !ok {
    return Err(reject(index, pc));
  }
  enter(st);
  Ok(())
}

/// A branch. It needs the stack as the epilogue will need it and the frame
/// register intact, because the target is entered in the entry state, and it
/// needs somewhere to land: a labelled slot, or the trailer's epilogue.
fn branch_step(
  labels: &Labels,
  target: Target,
  unconditional: bool,
  index: usize,
  pc: u32,
  st: &mut State,
) -> Result<(), Unsafe> {
  if st.alive && (st.depth != 1 || !frame_intact(st)) {
    return Err(reject(index, pc));
  }
  let (kind, slot) = target_of(&target);
  let landable = if kind == 1 {
    is_labelled(labels, slot)
  } else {
    labels.trailer
  };
  if !landable {
    return Err(reject(index, pc));
  }
  if unconditional {
    st.alive = false;
  }
  Ok(())
}

/// The retpoline, which is admitted only as part of a trailer. Nothing
/// follows it, so the walk is dead after it.
fn retpoline_step(code: &[MInsn], index: usize, pc: u32, st: &mut State) -> Result<(), Unsafe> {
  if !trailer_at(code, index) {
    return Err(reject(index, pc));
  }
  st.alive = false;
  Ok(())
}

/// The trailer's two data macros, admitted only at their fixed distance
/// behind the retpoline that owns them and nowhere else: they are read
/// through `rip`, never executed.
fn data_step(code: &[MInsn], index: usize, pc: u32, behind: usize) -> Result<(), Unsafe> {
  if index >= behind && trailer_at(code, index - behind) {
    return Ok(());
  }
  Err(reject(index, pc))
}

/// Every macro whose rule is about values rather than structure. A dead walk
/// skips all of them: no execution reaches here, so there is nothing to say
/// about what they touch.
fn live_step(cfg: &Cfg, insn: MInsn, index: usize, pc: u32, st: &mut State) -> Result<(), Unsafe> {
  if !st.alive {
    return Ok(());
  }
  match insn {
    MInsn::Epilogue => {
      if st.depth != 1 || !frame_intact(st) {
        return Err(reject(index, pc));
      }
      st.alive = false;
      Ok(())
    }

    MInsn::Alu { op, dst, .. } => {
      if alu_rr_writes(op) {
        write(st, dst, index, pc)
      } else {
        Ok(())
      }
    }
    MInsn::AluImm { op, dst, .. } => {
      if alu_ri_writes(op) {
        write(st, dst, index, pc)
      } else {
        Ok(())
      }
    }
    MInsn::ShiftImm { dst, .. } => write(st, dst, index, pc),
    MInsn::ShiftCl { dst, .. } => write(st, dst, index, pc),
    MInsn::Neg { dst, .. } => write(st, dst, index, pc),
    MInsn::MovSx { dst, .. } => write(st, dst, index, pc),
    MInsn::Bswap { dst, .. } => write(st, dst, index, pc),
    MInsn::Rol16 { dst } => write(st, dst, index, pc),
    MInsn::LoadImm { dst, .. } => write(st, dst, index, pc),
    MInsn::GuestFp { dst } => write(st, dst, index, pc),

    MInsn::MulDivMod { dst, .. } => {
      if !depth_ok(st, 4) {
        return Err(reject(index, pc));
      }
      write(st, dst, index, pc)?;
      write(st, RAX, index, pc)?;
      write(st, RCX, index, pc)?;
      write(st, RDX, index, pc)?;
      write(st, R11, index, pc)
    }

    MInsn::CheckedAddr {
      dst, scratch, size, ..
    } => {
      if dst == scratch || dst == R9 || scratch == R9 {
        return Err(reject(index, pc));
      }
      write(st, dst, index, pc)?;
      write(st, scratch, index, pc)?;
      set_tag(st, R9, Tag::Top);
      let checked = if cfg.pointer_mask != 0 {
        Tag::Checked(size)
      } else {
        Tag::Top
      };
      set_tag(st, dst, checked);
      Ok(())
    }

    MInsn::GroupBaseStore { src } => {
      st.group = tag_of(st, src);
      Ok(())
    }
    MInsn::GroupBaseLoad { dst } => {
      write(st, dst, index, pc)?;
      let parked = st.group;
      set_tag(st, dst, parked);
      Ok(())
    }

    MInsn::Load {
      size,
      base,
      dst,
      disp,
      ..
    } => {
      if !addr_ok(cfg, st, base, disp, size as u32) {
        return Err(reject(index, pc));
      }
      write(st, dst, index, pc)
    }
    MInsn::Store {
      size, base, disp, ..
    } => {
      if !addr_ok(cfg, st, base, disp, size as u32) {
        return Err(reject(index, pc));
      }
      Ok(())
    }
    MInsn::StoreImm {
      size, base, disp, ..
    } => {
      if !addr_ok(cfg, st, base, disp, size as u32) {
        return Err(reject(index, pc));
      }
      Ok(())
    }

    MInsn::AtomicAlu {
      w64, base, disp, ..
    } => {
      if !addr_ok(cfg, st, base, disp, atomic_size(w64)) {
        return Err(reject(index, pc));
      }
      Ok(())
    }
    MInsn::AtomicFetchAlu {
      w64,
      src,
      base,
      disp,
      ..
    } => {
      if !addr_ok(cfg, st, base, disp, atomic_size(w64)) || !depth_ok(st, 1) {
        return Err(reject(index, pc));
      }
      write(st, src, index, pc)?;
      write(st, RAX, index, pc)?;
      write(st, RCX, index, pc)?;
      write(st, R10, index, pc)?;
      write(st, R11, index, pc)
    }
    MInsn::AtomicXchg {
      w64,
      src,
      base,
      disp,
    } => {
      if !addr_ok(cfg, st, base, disp, atomic_size(w64)) {
        return Err(reject(index, pc));
      }
      write(st, src, index, pc)
    }
    MInsn::AtomicCmpxchg {
      w64, base, disp, ..
    } => {
      if !addr_ok(cfg, st, base, disp, atomic_size(w64)) {
        return Err(reject(index, pc));
      }
      write(st, RAX, index, pc)
    }

    MInsn::HelperCall { .. } => {
      if cfg.dispatcher == 0 || !depth_ok(st, 2) {
        return Err(reject(index, pc));
      }
      clobber_call(st);
      Ok(())
    }
    MInsn::LazyLocalCall { .. } => {
      if !cfg.has_local_call_callbacks || !frame_intact(st) || !depth_ok(st, 13) {
        return Err(reject(index, pc));
      }
      clobber_call(st);
      Ok(())
    }

    // Structure, not values; [`step`] has already handled these.
    MInsn::PcLabel(_)
    | MInsn::Prologue { .. }
    | MInsn::Jcc { .. }
    | MInsn::Jmp { .. }
    | MInsn::Retpoline
    | MInsn::DispatcherSlot
    | MInsn::HelperTable => Ok(()),
  }
}

/// What a call leaves: the caller-saved registers and the writable frame
/// slots, the parked group base among them. The callee-saved registers, the
/// frame register included, come back as they went in.
fn clobber_call(st: &mut State) {
  set_tag(st, RAX, Tag::Top);
  set_tag(st, RCX, Tag::Top);
  set_tag(st, RDX, Tag::Top);
  set_tag(st, RSI, Tag::Top);
  set_tag(st, RDI, Tag::Top);
  set_tag(st, R8, Tag::Top);
  set_tag(st, R9, Tag::Top);
  set_tag(st, R10, Tag::Top);
  set_tag(st, R11, Tag::Top);
  st.group = Tag::Top;
}

/// One macro. The structural rules — labels, prologues, branches, the
/// trailer — hold whether or not the walk is live; everything else is a rule
/// about values, and [`live_step`] skips it when no execution arrives.
fn step(
  cfg: &Cfg,
  labels: &Labels,
  code: &[MInsn],
  index: usize,
  pc: u32,
  st: &mut State,
) -> Result<(), Unsafe> {
  let insn = code[index];
  match insn {
    MInsn::PcLabel(slot) => label_step(labels, slot, index, pc, st),
    MInsn::Prologue { skip, .. } => prologue_step(skip, index, pc, st),
    MInsn::Jcc { target, .. } => branch_step(labels, target, false, index, pc, st),
    MInsn::Jmp { target } => branch_step(labels, target, true, index, pc, st),
    MInsn::Retpoline => retpoline_step(code, index, pc, st),
    MInsn::DispatcherSlot => data_step(code, index, pc, 1),
    MInsn::HelperTable => data_step(code, index, pc, 2),
    _ => live_step(cfg, insn, index, pc, st),
  }
}

/// Checks a macro list. `Ok` means: entered under the entry contract, every
/// execution of the list's expansion touches only the frame scratch, the
/// bounded native stack, checked guest addresses and the function's own
/// trailer — whatever the lowering was handed.
///
/// A list that runs off its end still live is refused: execution would fall
/// out of the function, so there is nothing to say about where it goes.
pub fn check(cfg: &Cfg, code: &[MInsn]) -> Result<(), Unsafe> {
  let num_macros = code.len();
  let labels = scan(code);
  let mut st = entry_state();
  let mut pc: u32 = 0;
  let mut i: usize = 0;
  while i < num_macros {
    let insn = code[i];
    let (labelled, slot) = label_of(&insn);
    if labelled {
      pc = slot;
    }
    step(cfg, &labels, code, i, pc, &mut st)?;
    i += 1;
  }
  if st.alive {
    let last = if num_macros == 0 { 0 } else { num_macros - 1 };
    return Err(reject(last, pc));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn cfg() -> Cfg {
    Cfg {
      pointer_mask: -1,
      native_frame_base: true,
      frame_constants: true,
      stack_frame_size: 4096,
      stack_frame_stride: 4096,
      dispatcher: 1,
      unwind_helper_index: -1,
      has_local_call_callbacks: true,
      local_call_resolver: 1,
      local_call_stack_exhausted: 1,
    }
  }

  fn prologue() -> MInsn {
    MInsn::Prologue {
      usage: 0,
      skip: false,
    }
  }

  fn checked_addr(src: u8, dst: u8, scratch: u8, size: u32) -> MInsn {
    MInsn::CheckedAddr {
      src,
      dst,
      scratch,
      offset: 0,
      size,
      region: region::UNKNOWN,
    }
  }

  fn load(base: u8, dst: u8, disp: i32, size: Size) -> MInsn {
    MInsn::Load {
      size,
      sx: false,
      base,
      dst,
      disp,
    }
  }

  fn mov(src: u8, dst: u8) -> MInsn {
    MInsn::Alu {
      w64: true,
      op: AluRR::Mov,
      src,
      dst,
    }
  }

  /// A function whose translated body is `body`: the prologue, the body,
  /// then the epilogue and the trailer.
  fn function(body: &[MInsn]) -> Vec<MInsn> {
    let mut code = vec![prologue()];
    code.extend_from_slice(body);
    code.push(MInsn::Epilogue);
    code.push(MInsn::Retpoline);
    code.push(MInsn::DispatcherSlot);
    code.push(MInsn::HelperTable);
    code
  }

  fn accepts(cfg: &Cfg, code: &[MInsn]) {
    assert_eq!(check(cfg, code), Ok(()));
  }

  /// The index of the refused macro; fails the test if the list is accepted.
  fn refused_at(cfg: &Cfg, code: &[MInsn]) -> usize {
    match check(cfg, code) {
      Ok(()) => panic!("expected a rejection"),
      Err(u) => u.index,
    }
  }

  #[test]
  fn the_canonical_function_is_accepted() {
    let code = vec![
      prologue(),
      MInsn::PcLabel(0),
      checked_addr(RDI, R11, RCX, 8),
      load(R11, RAX, 0, 8),
      MInsn::PcLabel(1),
      MInsn::Epilogue,
      MInsn::Retpoline,
      MInsn::DispatcherSlot,
      MInsn::HelperTable,
    ];
    accepts(&cfg(), &code);
  }

  #[test]
  fn a_load_through_an_unchecked_register_is_refused() {
    let code = function(&[MInsn::PcLabel(0), load(RDI, RAX, 0, 8)]);
    assert_eq!(refused_at(&cfg(), &code), 2);
  }

  #[test]
  fn a_load_wider_than_the_checked_window_is_refused() {
    let code = function(&[
      MInsn::PcLabel(3),
      checked_addr(RDI, R11, RCX, 4),
      load(R11, RAX, 0, 8),
    ]);
    match check(&cfg(), &code) {
      Ok(()) => panic!("expected a rejection"),
      Err(u) => {
        assert_eq!(u.index, 3);
        assert_eq!(u.pc, 3);
      }
    }
  }

  #[test]
  fn a_load_past_the_end_of_the_checked_window_is_refused() {
    let code = function(&[
      MInsn::PcLabel(0),
      checked_addr(RDI, R11, RCX, 8),
      load(R11, RAX, 4, 8),
    ]);
    assert_eq!(refused_at(&cfg(), &code), 3);
  }

  #[test]
  fn a_negative_displacement_from_a_checked_base_is_refused() {
    let code = function(&[
      MInsn::PcLabel(0),
      checked_addr(RDI, R11, RCX, 16),
      load(R11, RAX, -1, 8),
    ]);
    assert_eq!(refused_at(&cfg(), &code), 3);
  }

  #[test]
  fn the_frame_fast_path_is_accepted_inside_the_frame_window() {
    let code = function(&[MInsn::PcLabel(0), load(FRAME, RAX, -8, 8)]);
    accepts(&cfg(), &code);
  }

  #[test]
  fn the_frame_fast_path_is_refused_below_the_frame_window() {
    let code = function(&[MInsn::PcLabel(0), load(FRAME, RAX, -4096 - 8, 8)]);
    assert_eq!(refused_at(&cfg(), &code), 2);
  }

  #[test]
  fn the_frame_fast_path_is_refused_at_and_above_the_frame_pointer() {
    let code = function(&[MInsn::PcLabel(0), load(FRAME, RAX, 0, 8)]);
    assert_eq!(refused_at(&cfg(), &code), 2);
  }

  #[test]
  fn the_frame_fast_path_is_refused_without_a_native_frame_base() {
    let mut c = cfg();
    c.native_frame_base = false;
    let code = function(&[MInsn::PcLabel(0), load(FRAME, RAX, -8, 8)]);
    assert_eq!(refused_at(&c, &code), 2);
  }

  #[test]
  fn writing_the_stack_pointer_the_base_pointer_or_the_frame_register_is_refused() {
    let rsp = function(&[MInsn::PcLabel(0), mov(RAX, RSP)]);
    let rbp = function(&[MInsn::PcLabel(0), mov(RAX, RBP)]);
    let frame = function(&[MInsn::PcLabel(0), mov(RAX, FRAME)]);
    assert_eq!(refused_at(&cfg(), &rsp), 2);
    assert_eq!(refused_at(&cfg(), &rbp), 2);
    assert_eq!(refused_at(&cfg(), &frame), 2);
  }

  #[test]
  fn a_comparison_writes_nothing_and_may_name_the_frame_register() {
    let code = function(&[
      MInsn::PcLabel(0),
      MInsn::Alu {
        w64: true,
        op: AluRR::Cmp,
        src: RAX,
        dst: FRAME,
      },
    ]);
    accepts(&cfg(), &code);
  }

  /// A leader parks its checked base; the member reads it back and accesses
  /// it at a constant displacement.
  fn group(between: &[MInsn]) -> Vec<MInsn> {
    let mut body = vec![
      MInsn::PcLabel(0),
      checked_addr(RDI, R11, RCX, 16),
      MInsn::GroupBaseStore { src: R11 },
      load(R11, RAX, 0, 8),
    ];
    body.extend_from_slice(between);
    body.push(MInsn::GroupBaseLoad { dst: R11 });
    body.push(load(R11, RAX, 8, 8));
    function(&body)
  }

  #[test]
  fn a_leader_and_its_member_are_accepted() {
    accepts(&cfg(), &group(&[]));
  }

  #[test]
  fn a_label_nothing_branches_to_does_not_split_a_group() {
    accepts(&cfg(), &group(&[MInsn::PcLabel(1)]));
  }

  #[test]
  fn a_branch_target_between_a_leader_and_its_member_is_refused() {
    let mut code = group(&[MInsn::PcLabel(1)]);
    // Name slot 1 from somewhere, which makes its label an entry.
    code.insert(
      1,
      MInsn::Jcc {
        cc: cc::E,
        target: Target::Pc(1),
      },
    );
    // The member's load, now through a base the label reset to `Top`.
    assert_eq!(refused_at(&cfg(), &code), 8);
  }

  #[test]
  fn code_after_an_unconditional_branch_is_not_checked() {
    let code = vec![
      prologue(),
      MInsn::PcLabel(0),
      MInsn::Jmp {
        target: Target::Pc(3),
      },
      MInsn::PcLabel(1),
      load(RDI, RAX, 0, 8),
      MInsn::PcLabel(3),
      MInsn::Epilogue,
      MInsn::Retpoline,
      MInsn::DispatcherSlot,
      MInsn::HelperTable,
    ];
    accepts(&cfg(), &code);
  }

  #[test]
  fn a_branch_target_revives_the_walk() {
    let code = vec![
      prologue(),
      MInsn::PcLabel(0),
      MInsn::Jmp {
        target: Target::Pc(1),
      },
      MInsn::PcLabel(1),
      load(RDI, RAX, 0, 8),
      MInsn::Epilogue,
      MInsn::Retpoline,
      MInsn::DispatcherSlot,
      MInsn::HelperTable,
    ];
    assert_eq!(refused_at(&cfg(), &code), 4);
  }

  #[test]
  fn a_branch_to_an_unlabelled_slot_is_refused() {
    let code = function(&[
      MInsn::PcLabel(0),
      MInsn::Jmp {
        target: Target::Pc(9),
      },
    ]);
    assert_eq!(refused_at(&cfg(), &code), 2);
  }

  #[test]
  fn a_walk_that_ends_live_is_refused() {
    let code = vec![prologue(), MInsn::PcLabel(0), mov(RAX, RCX)];
    assert_eq!(refused_at(&cfg(), &code), 2);
  }

  #[test]
  fn a_truncated_trailer_is_refused() {
    let code = vec![
      prologue(),
      MInsn::PcLabel(0),
      MInsn::Epilogue,
      MInsn::Retpoline,
      MInsn::DispatcherSlot,
    ];
    assert_eq!(refused_at(&cfg(), &code), 3);
  }

  #[test]
  fn a_helper_table_outside_the_trailer_is_refused() {
    let code = vec![prologue(), MInsn::HelperTable, MInsn::Epilogue];
    assert_eq!(refused_at(&cfg(), &code), 1);
  }

  #[test]
  fn a_branch_to_the_exit_needs_the_trailer() {
    let exit = MInsn::Jcc {
      cc: cc::E,
      target: Target::Exit,
    };
    accepts(&cfg(), &function(&[MInsn::PcLabel(0), exit]));

    let without_trailer = vec![prologue(), MInsn::PcLabel(0), exit, MInsn::Epilogue];
    assert_eq!(refused_at(&cfg(), &without_trailer), 2);
  }

  #[test]
  fn a_helper_call_needs_a_dispatcher() {
    let code = function(&[MInsn::PcLabel(0), MInsn::HelperCall { idx: 0 }]);
    accepts(&cfg(), &code);

    let mut c = cfg();
    c.dispatcher = 0;
    assert_eq!(refused_at(&c, &code), 2);
  }

  #[test]
  fn a_call_forgets_the_parked_group_base() {
    let code = function(&[
      MInsn::PcLabel(0),
      checked_addr(RDI, R11, RCX, 16),
      MInsn::GroupBaseStore { src: R11 },
      MInsn::HelperCall { idx: 0 },
      MInsn::GroupBaseLoad { dst: R11 },
      load(R11, RAX, 0, 8),
    ]);
    assert_eq!(refused_at(&cfg(), &code), 6);
  }

  #[test]
  fn a_lazy_local_call_needs_its_callbacks() {
    let code = function(&[MInsn::PcLabel(0), MInsn::LazyLocalCall { id: 0 }]);
    accepts(&cfg(), &code);

    let mut c = cfg();
    c.has_local_call_callbacks = false;
    assert_eq!(refused_at(&c, &code), 2);
  }

  #[test]
  fn an_epilogue_at_depth_zero_is_refused() {
    let code = vec![MInsn::Epilogue];
    assert_eq!(refused_at(&cfg(), &code), 0);
  }

  #[test]
  fn a_second_prologue_at_depth_one_is_refused_unless_it_is_skippable() {
    let code = function(&[MInsn::PcLabel(0), prologue()]);
    assert_eq!(refused_at(&cfg(), &code), 2);

    let skippable = function(&[
      MInsn::PcLabel(0),
      MInsn::Prologue {
        usage: 0,
        skip: true,
      },
    ]);
    accepts(&cfg(), &skippable);
  }

  #[test]
  fn a_checked_address_may_not_collide_with_its_scratches() {
    let same = function(&[MInsn::PcLabel(0), checked_addr(RDI, R11, R11, 8)]);
    let over_r9 = function(&[MInsn::PcLabel(0), checked_addr(RDI, R9, RCX, 8)]);
    assert_eq!(refused_at(&cfg(), &same), 2);
    assert_eq!(refused_at(&cfg(), &over_r9), 2);
  }

  #[test]
  fn with_the_cage_off_any_address_is_admitted_but_no_register_is_writable() {
    let mut c = cfg();
    c.pointer_mask = 0;
    accepts(&c, &function(&[MInsn::PcLabel(0), load(RDI, RAX, 0, 8)]));
    assert_eq!(
      refused_at(&c, &function(&[MInsn::PcLabel(0), mov(RAX, RSP)])),
      2
    );
  }

  #[test]
  fn with_the_cage_off_a_checked_address_stays_unchecked() {
    let mut c = cfg();
    c.pointer_mask = 0;
    let code = function(&[
      MInsn::PcLabel(0),
      checked_addr(RDI, R11, RCX, 8),
      load(R11, RAX, 0, 8),
    ]);
    accepts(&c, &code);
  }
}

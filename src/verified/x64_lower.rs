//! The x86_64 backend's decisions, as macro instructions.
//!
//! Everything the backend chooses lives here: which sequence an eBPF
//! instruction becomes, which bounds check an access gets, whether an access
//! plan is honoured, where a branch may land, and when a function is refused.
//! What it produces is a list of [`MInsn`], the macro instruction set; nothing
//! in this file knows a byte or an offset.
//!
//! [`lower`] takes the program as plain slices rather than a description
//! struct, because the extraction has no model of a struct holding borrows.
//! Three groups of them travel together. The program and what the loader
//! established about it: the instruction stream, which slots begin local
//! functions, which calls cross a section, and each function's guest stack
//! charge. What the analysis contributes for one translation: the region
//! hints, the access plan, the lazy-call resolver ids, and the half-open slot
//! range. And [`Cfg`], the configuration the whole program was built under.
//!
//! # The access plan is advisory
//!
//! A plan entry is never taken on trust. Before a member rides the base its
//! leader parked, this re-derives that the named leader is the one most
//! recently emitted, that no branch can land between the two, that nothing has
//! redefined the base register since, and that the access lies inside the
//! checked window. Any failure emits an ordinary checked access instead, so a
//! plan that is wrong — or hostile — costs speed and nothing else.
//!
//! # Refusals
//!
//! [`Reject`] carries the slot, the opcode or the target the runtime needs to
//! word its message; `jit::emit::x86_64` renders it. The fixup ceilings are
//! counted here too, because the number of relative branches a function needs
//! is a property of the sequences chosen, not of the bytes they encode to.

use super::isa::{
  decode, AluOp, AluWidth, AtomicOp, EndKind, Insn, JmpOp, Op, Source, Width, ALU_ADD, ALU_AND,
  ALU_MASK, ALU_OR, ALU_XOR, CLS_ALU, CLS_ALU64, CLS_JMP, CLS_JMP32, CLS_LD, CLS_LDX, CLS_MASK,
  CLS_STX, OP_CALL, OP_EXIT, OP_JA32,
};
use super::x64_ir::{
  cc, map_register, plan_role, region, unmap_register, AluRI, AluRR, Cfg, MInsn, MulDivKind,
  PlanEntry, ShiftOp, Target, MAX_GROUP_SPAN, MAX_JUMPS, MAX_LEAS, MAX_LOADS, R11, R15, RAX, RCX,
  RCX_ALT,
};

/// Why a function was refused, and the data its message names.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug, Hash))]
pub enum Reject {
  /// The range is empty, inverted, or runs past the program.
  InvalidRange,
  /// The range begins somewhere other than a local function entry.
  RangeStartNotEntry,
  /// The range ends somewhere other than a local function boundary.
  RangeEndNotBoundary,
  /// A branch at `pc` leaves the translated range.
  JumpOutOfRange {
    pc: usize,
    target: u32,
  },
  /// The opcode byte at `pc` is not a defined encoding.
  UnknownInstruction {
    pc: usize,
    opcode: u8,
  },
  /// The atomic selector in the immediate at `pc` names no operation.
  UnknownAtomic {
    pc: usize,
    imm: i32,
  },
  /// A local call with no resolver id, or with the callbacks unregistered.
  UnexpectedInstruction,
  TooManyJumps,
  TooManyLoads,
  TooManyLeas,
  /// A ceiling was reached while emitting the trailer.
  TrailerFailed,
  /// The macro list failed the memory-safety check (`x64_check`) at the
  /// macro translating slot `pc`. No program the lowering handles is known
  /// to reach this; it is the gate the safety theorem hangs on.
  Unsafe {
    pc: u32,
  },
}

/// Relative-branch fixups one macro's expansion records.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug))]
pub struct Fixups {
  pub jumps: u32,
  /// RIP-relative loads, which only the dispatcher slot is read through.
  pub loads: u32,
  /// RIP-relative LEAs, which only the helper table is addressed through.
  pub leas: u32,
}

/// Where a resolved access ended up: the register holding the native address,
/// and the displacement to use with it.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug))]
pub struct Addr {
  pub reg: u8,
  pub disp: i32,
}

/// Bookkeeping carried across one function.
///
/// The three counters are the relative-branch fixup tables the encoder will
/// fill in. They are counted here because how many a function needs follows
/// from the sequences chosen, and a program that would overrun them has to be
/// refused before any of it is emitted.
///
/// The group fields are what the backend has derived for itself about the open
/// access group: which leader established it, the window that leader checked,
/// which eBPF register it is based on, and which registers have been written
/// since.
pub struct Lowering {
  jumps: u32,
  loads: u32,
  leas: u32,
  group_open: bool,
  group_leader_pc: u32,
  group_span: u32,
  group_lo: i32,
  group_base_reg: u8,
  group_written: u16,
}

/// Lowers one function to macro instructions.
pub fn lower(
  cfg: &Cfg,
  insns: &[Insn],
  entries: &[bool],
  external_calls: &[bool],
  stack_usage: &[u16],
  hints: &[u8],
  plan: &[PlanEntry],
  resolver_ids: &[u32],
  start_pc: usize,
  end_pc: usize,
  out: &mut Vec<MInsn>,
) -> Result<(), Reject> {
  check_range(insns, entries, start_pc, end_pc)?;

  let mut barrier: Vec<bool> = vec![false; insns.len() + 1];
  mark_barriers(insns, entries, start_pc, end_pc, &mut barrier);

  let mut st = Lowering {
    jumps: 0,
    loads: 0,
    leas: 0,
    group_open: false,
    group_leader_pc: 0,
    group_span: 0,
    group_lo: 0,
    group_base_reg: 0,
    group_written: 0,
  };
  lower_body(
    cfg,
    insns,
    entries,
    external_calls,
    stack_usage,
    hints,
    plan,
    resolver_ids,
    start_pc,
    end_pc,
    &barrier,
    &mut st,
    out,
  )?;
  lower_trailer(&mut st, out)?;
  gate(cfg, out)
}

/// The memory-safety gate: what `lower` returns is code `x64_check::check`
/// accepted, by construction.
fn gate(cfg: &Cfg, out: &Vec<MInsn>) -> Result<(), Reject> {
  match super::x64_check::check(cfg, out) {
    Ok(()) => Ok(()),
    Err(u) => Err(Reject::Unsafe { pc: u.pc }),
  }
}

/// The range has to be exactly one local function: the prologue is only
/// emitted at a function entry, but every `exit` pops a frame, so a start that
/// is not an entry, or an end that splits a function, would unbalance the
/// native stack.
fn check_range(
  insns: &[Insn],
  entries: &[bool],
  start_pc: usize,
  end_pc: usize,
) -> Result<(), Reject> {
  let num_insns = insns.len();
  if end_pc > num_insns || start_pc >= end_pc {
    return Err(Reject::InvalidRange);
  }
  let start_is_entry = is_func_entry(entries, start_pc);
  if !(start_pc == 0 || start_is_entry) {
    return Err(Reject::RangeStartNotEntry);
  }
  let end_is_entry = is_func_entry(entries, end_pc);
  if end_pc != num_insns && !end_is_entry {
    return Err(Reject::RangeEndNotBoundary);
  }
  Ok(())
}

/// Whether the slot at `pc` begins a local function. Out of range is not.
fn is_func_entry(entries: &[bool], pc: usize) -> bool {
  if pc >= entries.len() {
    return false;
  }
  entries[pc]
}

/// Whether `pc` is an intra- or cross-section local call.
fn is_local_call(insns: &[Insn], external_calls: &[bool], pc: usize) -> bool {
  if pc < insns.len() {
    let insn = insns[pc];
    if insn.opcode == OP_CALL && insn.src == 1 {
      return true;
    }
  }
  if pc >= external_calls.len() {
    return false;
  }
  external_calls[pc]
}

/// The guest stack charge recorded for the function beginning at `pc`.
fn stack_usage_at(stack_usage: &[u16], pc: usize) -> u16 {
  if pc >= stack_usage.len() {
    return 0;
  }
  stack_usage[pc]
}

/// The region hint for `pc`, or [`region::UNKNOWN`] where there is none.
fn hint_at(hints: &[u8], pc: usize) -> u8 {
  if pc >= hints.len() {
    return region::UNKNOWN;
  }
  hints[pc]
}

/// Whether a branch can land on `pc`, which closes any group open across it.
fn is_barrier(barrier: &[bool], pc: usize) -> bool {
  if pc >= barrier.len() {
    return true;
  }
  barrier[pc]
}

/// Marks every slot a branch can land on. A local function entry is reached by
/// `call` rather than by falling into it, so a group must not span one either.
fn mark_barriers(
  insns: &[Insn],
  entries: &[bool],
  start_pc: usize,
  end_pc: usize,
  barrier: &mut Vec<bool>,
) {
  let num_insns = insns.len();
  let mut i = start_pc;
  while i < end_pc {
    let insn = insns[i];
    let entry = is_func_entry(entries, i);
    if entry {
      barrier[i] = true;
    }
    let class = insn.opcode & CLS_MASK;
    if class == CLS_JMP || class == CLS_JMP32 {
      // Nothing falls through an `exit`, an unconditional jump or a call, so
      // whatever follows one is entered from somewhere else.
      if i + 1 <= num_insns {
        barrier[i + 1] = true;
      }
      if insn.opcode != OP_CALL && insn.opcode != OP_EXIT {
        let delta = branch_delta(insn);
        let target = i as i64 + 1 + delta;
        if target >= 0 && target <= num_insns as i64 {
          barrier[target as usize] = true;
        }
      }
    }
    i += 1;
  }
}

/// A branch's displacement. `ja32` carries it in the immediate; everything
/// else uses the offset.
fn branch_delta(insn: Insn) -> i64 {
  if insn.opcode == OP_JA32 {
    return insn.imm as i64;
  }
  insn.offset as i64
}

// ---------------------------------------------------------------------------
// Fixup accounting
// ---------------------------------------------------------------------------

fn no_fixups() -> Fixups {
  Fixups {
    jumps: 0,
    loads: 0,
    leas: 0,
  }
}

/// The fixups one macro's expansion records.
fn fixups_of(m: MInsn) -> Fixups {
  match m {
    MInsn::Jcc { .. } => Fixups {
      jumps: 1,
      loads: 0,
      leas: 0,
    },
    MInsn::Jmp { .. } => Fixups {
      jumps: 1,
      loads: 0,
      leas: 0,
    },
    MInsn::Prologue { skip, .. } => {
      if skip {
        Fixups {
          jumps: 1,
          loads: 0,
          leas: 0,
        }
      } else {
        no_fixups()
      }
    }
    // The two forward branches around the dispatcher choice, the call through
    // the retpoline, the dispatcher load and the helper-table LEA.
    MInsn::HelperCall { .. } => Fixups {
      jumps: 3,
      loads: 1,
      leas: 1,
    },
    // Two exhaustion guards and the branch around the exhaustion callback.
    MInsn::LazyLocalCall { .. } => Fixups {
      jumps: 3,
      loads: 0,
      leas: 0,
    },
    // The call that parks the return address, and the speculation trap's loop.
    MInsn::Retpoline => Fixups {
      jumps: 2,
      loads: 0,
      leas: 0,
    },
    _ => no_fixups(),
  }
}

/// Appends one macro, charging its fixups against the ceilings first.
///
/// A ceiling is reached when a table would grow past it, so a macro needing
/// three jumps is refused three short of the limit rather than at it. The
/// order of the three tests is the order in which the tables overflow, which
/// decides which refusal a macro that overruns two of them reports.
fn push(st: &mut Lowering, out: &mut Vec<MInsn>, m: MInsn) -> Result<(), Reject> {
  let f = fixups_of(m);
  if f.jumps > 0 && st.jumps + f.jumps > MAX_JUMPS {
    return Err(Reject::TooManyJumps);
  }
  if f.leas > 0 && st.leas + f.leas > MAX_LEAS {
    return Err(Reject::TooManyLeas);
  }
  if f.loads > 0 && st.loads + f.loads > MAX_LOADS {
    return Err(Reject::TooManyLoads);
  }
  st.jumps += f.jumps;
  st.leas += f.leas;
  st.loads += f.loads;
  out.push(m);
  Ok(())
}

/// The trailer: the function's epilogue, the retpoline the helper call goes
/// through, the dispatcher address and the helper table. A ceiling reached
/// here is reported as the trailer's own failure.
fn lower_trailer(st: &mut Lowering, out: &mut Vec<MInsn>) -> Result<(), Reject> {
  let outcome = push_trailer(st, out);
  match outcome {
    Ok(()) => Ok(()),
    Err(_) => Err(Reject::TrailerFailed),
  }
}

fn push_trailer(st: &mut Lowering, out: &mut Vec<MInsn>) -> Result<(), Reject> {
  push(st, out, MInsn::Epilogue)?;
  push(st, out, MInsn::Retpoline)?;
  push(st, out, MInsn::DispatcherSlot)?;
  push(st, out, MInsn::HelperTable)
}

// ---------------------------------------------------------------------------
// Access groups
// ---------------------------------------------------------------------------

/// Closes the open access group, if any.
fn close_group(st: &mut Lowering) {
  st.group_open = false;
  st.group_written = 0;
}

/// Notes that eBPF register `reg` has been written. A write to the base
/// register invalidates the group outright; any other write is recorded, so
/// that a member naming a register written since the leader ran is declined.
fn note_register_written(st: &mut Lowering, reg: u8) {
  if !st.group_open {
    return;
  }
  st.group_written |= 1u16 << (reg & 0xf);
  if st.group_base_reg == reg {
    close_group(st);
  }
}

/// Notes every register a mask names.
fn note_written_mask(st: &mut Lowering, mask: u16) {
  let mut reg: u8 = 0;
  while reg < 16 {
    if mask & (1u16 << reg) != 0 {
      note_register_written(st, reg);
    }
    reg += 1;
  }
}

/// eBPF registers an instruction may overwrite.
///
/// Naming too many registers only ends access groups early; naming too few
/// would let a group keep addressing a base that has changed, so every class
/// that writes anything is listed.
fn written_registers_mask(insn: Insn) -> u16 {
  let class = insn.opcode & CLS_MASK;
  if class == CLS_LD || class == CLS_LDX || class == CLS_ALU || class == CLS_ALU64 {
    return 1u16 << (insn.dst & 0xf);
  }
  if class == CLS_STX {
    // A fetching atomic writes its source register, and compare-exchange
    // writes R0. Plain stores write nothing.
    if insn.opcode & 0xe0 == 0xc0 {
      return (1u16 << (insn.src & 0xf)) | 1;
    }
    return 0;
  }
  if class == CLS_JMP || class == CLS_JMP32 {
    // A call clobbers R0-R5 either way; the group ends at the call anyway.
    if insn.opcode == OP_CALL {
      return 0x3f;
    }
    return 0;
  }
  0
}

/// Whether an instruction reads its source register as a *value* rather than
/// as a memory base or a mode selector.
///
/// The store forms are deliberately absent even though they do read a value
/// source: the address computation they perform first would clobber the
/// scratch register the value would sit in, so they recover the guest frame
/// pointer themselves, afterwards.
fn reads_src_as_value(insn: Insn) -> bool {
  let class = insn.opcode & CLS_MASK;
  if class == CLS_ALU || class == CLS_ALU64 {
    return insn.opcode & 0x08 == 0x08;
  }
  if class == CLS_JMP || class == CLS_JMP32 {
    // `call` and `exit` put a mode selector in the source field rather than a
    // register number, and `ja` has no source operand at all.
    if insn.opcode == OP_CALL || insn.opcode == OP_EXIT {
      return false;
    }
    if insn.opcode & 0xf0 == 0x00 {
      return false;
    }
    return insn.opcode & 0x08 == 0x08;
  }
  false
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

fn lower_body(
  cfg: &Cfg,
  insns: &[Insn],
  entries: &[bool],
  external_calls: &[bool],
  stack_usage: &[u16],
  hints: &[u8],
  plan: &[PlanEntry],
  resolver_ids: &[u32],
  start_pc: usize,
  end_pc: usize,
  barrier: &[bool],
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
) -> Result<(), Reject> {
  let mut i = start_pc;
  while i < end_pc {
    i = lower_slot(
      cfg,
      insns,
      entries,
      external_calls,
      stack_usage,
      hints,
      plan,
      resolver_ids,
      start_pc,
      end_pc,
      barrier,
      st,
      out,
      i,
    )?;
  }
  Ok(())
}

/// Whether a function entry at `pc` needs a jump around its prologue, because
/// the instruction before it can fall into it.
fn prologue_needs_skip(insns: &[Insn], entries: &[bool], start_pc: usize, pc: usize) -> bool {
  if pc == start_pc {
    return false;
  }
  let entry = is_func_entry(entries, pc);
  if !entry {
    return false;
  }
  // Only `exit` cannot fall through; an unconditional jump counts as falling
  // through, which is deliberately conservative.
  insns[pc - 1].opcode != OP_EXIT
}

/// Whether the instruction at `pc` reads eBPF `R10` as a value, so that the
/// guest frame pointer has to be materialised before it runs.
fn needs_guest_fp(cfg: &Cfg, insn: Insn) -> bool {
  let active = cfg.native_frame_base_active();
  if !active {
    return false;
  }
  if insn.src != 10 {
    return false;
  }
  reads_src_as_value(insn)
}

/// Whether the branch at `pc` names a slot outside the translated range.
fn branch_leaves_range(insn: Insn, target_pc: u32, start_pc: usize, end_pc: usize) -> bool {
  let class = insn.opcode & CLS_MASK;
  if !(class == CLS_JMP || class == CLS_JMP32) {
    return false;
  }
  if insn.opcode == OP_CALL || insn.opcode == OP_EXIT {
    return false;
  }
  (target_pc as usize) < start_pc || target_pc as usize >= end_pc
}

/// One slot: the group barrier, the branch-range check, the function prologue,
/// the slot's label, the guest frame pointer materialisation, the instruction
/// itself, the 32-bit truncation and the written-register bookkeeping.
///
/// Returns the slot to continue from, which `lddw` advances by two.
fn lower_slot(
  cfg: &Cfg,
  insns: &[Insn],
  entries: &[bool],
  external_calls: &[bool],
  stack_usage: &[u16],
  hints: &[u8],
  plan: &[PlanEntry],
  resolver_ids: &[u32],
  start_pc: usize,
  end_pc: usize,
  barrier: &[bool],
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  pc: usize,
) -> Result<usize, Reject> {
  let insn = insns[pc];

  // A branch can land here, so no group can span it.
  let barred = is_barrier(barrier, pc);
  if barred {
    close_group(st);
  }

  let dst = map_register(insn.dst);
  let mut src = map_register(insn.src);
  let hint = hint_at(hints, pc);

  // Computed in i64 throughout, so a large immediate does not overflow.
  let target_pc_64 = pc as i64 + 1 + branch_delta(insn);
  let target_pc = target_pc_64 as u32;

  // A relative branch is resolved against the label of its target slot, and
  // only slots inside the range are labelled, so a target outside it would
  // silently retarget the branch to the top of the emitted function.
  let leaves = branch_leaves_range(insn, target_pc, start_pc, end_pc);
  if leaves {
    return Err(Reject::JumpOutOfRange {
      pc,
      target: target_pc,
    });
  }

  // The top of the native stack always holds the guest stack charge of the
  // function executing, so a function entry pushes its own. A previous
  // instruction that can fall into the entry needs a way around it.
  let entry = is_func_entry(entries, pc);
  if pc == 0 || entry {
    let skip = prologue_needs_skip(insns, entries, start_pc, pc);
    let usage = stack_usage_at(stack_usage, pc);
    push(st, out, MInsn::Prologue { usage, skip })?;
  }

  push(st, out, MInsn::PcLabel(pc as u32))?;

  // Under a native frame base the register mapped to eBPF R10 holds a host
  // address, so an instruction reading R10 as a value must see the guest one.
  // This comes after the label: a branch landing here has to run it too.
  let guest_fp = needs_guest_fp(cfg, insn);
  if guest_fp {
    push(st, out, MInsn::GuestFp { dst: RCX })?;
    src = RCX;
  }

  let next = lower_one(
    cfg,
    insns,
    external_calls,
    plan,
    resolver_ids,
    st,
    out,
    pc,
    insn,
    dst,
    src,
    hint,
    target_pc,
  )?;

  // A 32-bit ALU instruction zero-extends its result. The `end` family is
  // excluded, which is why `le`/`be` truncate for themselves.
  let class = insn.opcode & CLS_MASK;
  if class == CLS_ALU && insn.opcode & 0xf0 != 0xd0 {
    push(st, out, and_imm(false, dst, -1))?;
  }

  // After the instruction has used its operands, note what it overwrote: an
  // access whose destination is its own base is still valid, but nothing
  // addressing that base afterwards is.
  let mask = written_registers_mask(insn);
  note_written_mask(st, mask);
  Ok(next)
}

/// Dispatches one instruction, returning the slot to continue from.
fn lower_one(
  cfg: &Cfg,
  insns: &[Insn],
  external_calls: &[bool],
  plan: &[PlanEntry],
  resolver_ids: &[u32],
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  pc: usize,
  insn: Insn,
  dst: u8,
  src: u8,
  hint: u8,
  target_pc: u32,
) -> Result<usize, Reject> {
  let decoded = decode(insn.opcode);
  let Some(op) = decoded else {
    return Err(Reject::UnknownInstruction {
      pc,
      opcode: insn.opcode,
    });
  };

  match op {
    Op::Alu {
      width,
      op: alu,
      source,
    } => {
      lower_alu(st, out, insn, width, alu, source, dst, src)?;
      Ok(pc + 1)
    }
    Op::End(kind) => {
      lower_end(st, out, insn, kind, dst)?;
      Ok(pc + 1)
    }
    Op::Ja { .. } => {
      push(
        st,
        out,
        MInsn::Jmp {
          target: Target::Pc(target_pc),
        },
      )?;
      Ok(pc + 1)
    }
    Op::Jmp {
      width,
      op: cond,
      source,
    } => {
      lower_jump(st, out, insn, width, cond, source, dst, src, target_pc)?;
      Ok(pc + 1)
    }
    Op::Call => {
      lower_call(cfg, insns, external_calls, resolver_ids, st, out, pc, insn)?;
      Ok(pc + 1)
    }
    Op::Exit => {
      push(st, out, MInsn::Epilogue)?;
      Ok(pc + 1)
    }
    Op::Load { width, signed } => {
      lower_load(cfg, plan, st, out, pc, insn, width, signed, dst, src, hint)?;
      Ok(pc + 1)
    }
    Op::StoreImm { width } => {
      lower_store_imm(cfg, plan, st, out, pc, insn, width, dst, hint)?;
      Ok(pc + 1)
    }
    Op::StoreReg { width } => {
      lower_store_reg(cfg, plan, st, out, pc, insn, width, dst, src, hint)?;
      Ok(pc + 1)
    }
    Op::LoadImm64 => {
      let high_pc = pc + 1;
      let imm = load_imm64_value(insns, insn, high_pc);
      push(st, out, MInsn::LoadImm { dst, imm })?;
      // The second slot is not an instruction but the high half of the
      // immediate, so the driver skips it.
      Ok(high_pc + 1)
    }
    Op::Atomic { width, .. } => {
      lower_atomic(cfg, st, out, pc, insn, width, dst, src)?;
      Ok(pc + 1)
    }
  }
}

/// The 64-bit immediate a `lddw` pair carries.
///
/// The validator refuses a `lddw` in the last slot, which is what makes the
/// zero fallback unreachable rather than a behaviour change.
fn load_imm64_value(insns: &[Insn], insn: Insn, high_pc: usize) -> i64 {
  let mut high_imm: i32 = 0;
  if high_pc < insns.len() {
    high_imm = insns[high_pc].imm;
  }
  let imm = (insn.imm as u32 as u64) | ((high_imm as u32 as u64) << 32);
  imm as i64
}

// ---------------------------------------------------------------------------
// ALU
// ---------------------------------------------------------------------------

fn is_w64(width: AluWidth) -> bool {
  match width {
    AluWidth::W64 => true,
    AluWidth::W32 => false,
  }
}

fn is_reg(source: Source) -> bool {
  match source {
    Source::Reg => true,
    Source::Imm => false,
  }
}

fn width_bytes(width: Width) -> u8 {
  match width {
    Width::B => 1,
    Width::H => 2,
    Width::W => 4,
    Width::DW => 8,
  }
}

/// The multiply/divide/modulo kind an ALU operation names, or `None`.
fn muldiv_kind(alu: AluOp) -> Option<MulDivKind> {
  match alu {
    AluOp::Mul => Some(MulDivKind::Mul),
    AluOp::Div => Some(MulDivKind::Div),
    AluOp::Mod => Some(MulDivKind::Mod),
    _ => None,
  }
}

/// The shift direction an ALU operation names, or `None`.
fn shift_op(alu: AluOp) -> Option<ShiftOp> {
  match alu {
    AluOp::Lsh => Some(ShiftOp::Shl),
    AluOp::Rsh => Some(ShiftOp::Shr),
    AluOp::Arsh => Some(ShiftOp::Sar),
    _ => None,
  }
}

/// The register-form spelling of the five plain binary operations.
fn binary_rr(alu: AluOp) -> Option<AluRR> {
  match alu {
    AluOp::Add => Some(AluRR::Add),
    AluOp::Sub => Some(AluRR::Sub),
    AluOp::Or => Some(AluRR::Or),
    AluOp::And => Some(AluRR::And),
    AluOp::Xor => Some(AluRR::Xor),
    _ => None,
  }
}

/// The immediate-form spelling of the same five.
fn binary_ri(alu: AluOp) -> AluRI {
  match alu {
    AluOp::Sub => AluRI::Sub,
    AluOp::Or => AluRI::Or,
    AluOp::And => AluRI::And,
    AluOp::Xor => AluRI::Xor,
    _ => AluRI::Add,
  }
}

fn lower_alu(
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  insn: Insn,
  width: AluWidth,
  alu: AluOp,
  source: Source,
  dst: u8,
  src: u8,
) -> Result<(), Reject> {
  let w64 = is_w64(width);
  let reg = is_reg(source);

  let muldiv = muldiv_kind(alu);
  if let Some(kind) = muldiv {
    return push(
      st,
      out,
      MInsn::MulDivMod {
        kind,
        w64,
        reg,
        signed: insn.offset == 1,
        src,
        dst,
        imm: insn.imm,
      },
    );
  }

  match alu {
    AluOp::Neg => push(st, out, MInsn::Neg { w64, dst }),
    AluOp::Mov => lower_mov(st, out, insn, w64, reg, dst, src),
    _ => lower_alu_rest(st, out, insn, alu, w64, reg, dst, src),
  }
}

/// `mov`, whose register form selects a sign-extending width with the offset
/// field (RFC 9669).
fn lower_mov(
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  insn: Insn,
  w64: bool,
  reg: bool,
  dst: u8,
  src: u8,
) -> Result<(), Reject> {
  if !reg {
    if w64 {
      return push(
        st,
        out,
        MInsn::LoadImm {
          dst,
          imm: insn.imm as i64,
        },
      );
    }
    return push(
      st,
      out,
      MInsn::AluImm {
        w64: false,
        op: AluRI::Mov,
        dst,
        imm: insn.imm,
      },
    );
  }

  let from = movsx_width(w64, insn.offset);
  if from == 0 {
    return push(
      st,
      out,
      MInsn::Alu {
        w64: true,
        op: AluRR::Mov,
        src,
        dst,
      },
    );
  }
  push(
    st,
    out,
    MInsn::MovSx {
      from,
      w64,
      src,
      dst,
    },
  )
}

/// The source width a register `mov`'s offset field selects, or 0 for a plain
/// move. Only 32 at 64-bit width, and 8 and 16 at both.
fn movsx_width(w64: bool, offset: i16) -> u8 {
  if offset == 8 {
    return 8;
  }
  if offset == 16 {
    return 16;
  }
  if w64 && offset == 32 {
    return 32;
  }
  0
}

fn lower_alu_rest(
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  insn: Insn,
  alu: AluOp,
  w64: bool,
  reg: bool,
  dst: u8,
  src: u8,
) -> Result<(), Reject> {
  let shift = shift_op(alu);
  if let Some(op) = shift {
    return lower_shift(st, out, insn, op, w64, reg, dst, src);
  }

  let rr = binary_rr(alu);
  let Some(op) = rr else {
    // `mul`, `div`, `mod`, `neg` and `mov` are handled above; nothing else
    // reaches here.
    return Ok(());
  };
  if reg {
    return push(st, out, MInsn::Alu { w64, op, src, dst });
  }
  push(
    st,
    out,
    MInsn::AluImm {
      w64,
      op: binary_ri(alu),
      dst,
      imm: insn.imm,
    },
  )
}

/// A shift, whose register form has to go through RCX.
fn lower_shift(
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  insn: Insn,
  op: ShiftOp,
  w64: bool,
  reg: bool,
  dst: u8,
  src: u8,
) -> Result<(), Reject> {
  if !reg {
    return push(
      st,
      out,
      MInsn::ShiftImm {
        w64,
        op,
        dst,
        imm: insn.imm,
      },
    );
  }
  push(
    st,
    out,
    MInsn::Alu {
      w64: true,
      op: AluRR::Mov,
      src,
      dst: RCX,
    },
  )?;
  push(st, out, MInsn::ShiftCl { w64, op, dst })
}

/// `le` / `be` / `bswap`. x86 is already little-endian, so `le` is a
/// truncation and nothing else; an immediate the family does not define emits
/// nothing at all.
fn lower_end(
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  insn: Insn,
  kind: EndKind,
  dst: u8,
) -> Result<(), Reject> {
  let imm = insn.imm;
  match kind {
    EndKind::Le => lower_end_le(st, out, imm, dst),
    EndKind::Be => lower_end_be(st, out, imm, dst),
    EndKind::Bswap => lower_end_bswap(st, out, imm, dst),
  }
}

fn lower_end_le(st: &mut Lowering, out: &mut Vec<MInsn>, imm: i32, dst: u8) -> Result<(), Reject> {
  if imm == 16 {
    return push(st, out, and_imm(false, dst, 0xffff));
  }
  if imm == 32 {
    return push(st, out, and_imm(false, dst, -1));
  }
  Ok(())
}

fn lower_end_be(st: &mut Lowering, out: &mut Vec<MInsn>, imm: i32, dst: u8) -> Result<(), Reject> {
  if imm == 16 {
    push(st, out, MInsn::Rol16 { dst })?;
    return push(st, out, and_imm(false, dst, 0xffff));
  }
  if imm == 32 || imm == 64 {
    return push(
      st,
      out,
      MInsn::Bswap {
        w64: imm == 64,
        dst,
      },
    );
  }
  Ok(())
}

fn lower_end_bswap(
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  imm: i32,
  dst: u8,
) -> Result<(), Reject> {
  if imm == 16 {
    push(st, out, MInsn::Rol16 { dst })?;
    return push(st, out, and_imm(true, dst, 0xffff));
  }
  if imm == 32 {
    push(st, out, MInsn::Bswap { w64: false, dst })?;
    // Zero-extend to 64 bits.
    return push(
      st,
      out,
      MInsn::Alu {
        w64: false,
        op: AluRR::Mov,
        src: dst,
        dst,
      },
    );
  }
  if imm == 64 {
    return push(st, out, MInsn::Bswap { w64: true, dst });
  }
  Ok(())
}

fn and_imm(w64: bool, dst: u8, imm: i32) -> MInsn {
  MInsn::AluImm {
    w64,
    op: AluRI::And,
    dst,
    imm,
  }
}

// ---------------------------------------------------------------------------
// Jumps
// ---------------------------------------------------------------------------

/// The condition code a conditional jump tests.
fn jump_cc(cond: JmpOp) -> u8 {
  match cond {
    JmpOp::Eq => cc::E,
    JmpOp::Gt => cc::A,
    JmpOp::Ge => cc::AE,
    JmpOp::Lt => cc::B,
    JmpOp::Le => cc::BE,
    JmpOp::Set => cc::NE,
    JmpOp::Ne => cc::NE,
    JmpOp::Sgt => cc::G,
    JmpOp::Sge => cc::GE,
    JmpOp::Slt => cc::L,
    JmpOp::Sle => cc::LE,
  }
}

/// `jset` tests rather than compares.
fn is_set(cond: JmpOp) -> bool {
  match cond {
    JmpOp::Set => true,
    _ => false,
  }
}

fn lower_jump(
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  insn: Insn,
  width: AluWidth,
  cond: JmpOp,
  source: Source,
  dst: u8,
  src: u8,
  target_pc: u32,
) -> Result<(), Reject> {
  let w64 = is_w64(width);
  let reg = is_reg(source);
  let set = is_set(cond);
  if reg {
    let op = if set { AluRR::Test } else { AluRR::Cmp };
    push(st, out, MInsn::Alu { w64, op, src, dst })?;
  } else {
    let op = if set { AluRI::Test } else { AluRI::Cmp };
    push(
      st,
      out,
      MInsn::AluImm {
        w64,
        op,
        dst,
        imm: insn.imm,
      },
    )?;
  }
  push(
    st,
    out,
    MInsn::Jcc {
      cc: jump_cc(cond),
      target: Target::Pc(target_pc),
    },
  )
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

fn lower_call(
  cfg: &Cfg,
  insns: &[Insn],
  external_calls: &[bool],
  resolver_ids: &[u32],
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  pc: usize,
  insn: Insn,
) -> Result<(), Reject> {
  if insn.src == 0 {
    return lower_helper_call(cfg, st, out, insn);
  }

  let local = is_local_call(insns, external_calls, pc);
  if local {
    return lower_lazy_local_call(cfg, resolver_ids, st, out, pc);
  }

  // A call that is neither a helper nor a local call emits nothing. The
  // operand filter bounds `call`'s source to 0..=2, source 1 is a local call
  // by definition, and a source-2 call is only accepted when the loader
  // tagged it as a cross-section local call — which is what makes it one.
  Ok(())
}

fn lower_helper_call(
  cfg: &Cfg,
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  insn: Insn,
) -> Result<(), Reject> {
  // RCX is reserved for shifts, so the register mapped to eBPF R4 has to move
  // out of the way before the host call.
  push(
    st,
    out,
    MInsn::Alu {
      w64: true,
      op: AluRR::Mov,
      src: RCX_ALT,
      dst: RCX,
    },
  )?;
  push(
    st,
    out,
    MInsn::HelperCall {
      idx: insn.imm as u32,
    },
  )?;
  // The unwind index defaults to -1, so a `call -1` really does take the
  // unwind path when no index is configured.
  if insn.imm != cfg.unwind_helper_index {
    return Ok(());
  }
  push(
    st,
    out,
    MInsn::AluImm {
      w64: true,
      op: AluRI::Cmp,
      dst: RAX,
      imm: 0,
    },
  )?;
  push(
    st,
    out,
    MInsn::Jcc {
      cc: cc::E,
      target: Target::Exit,
    },
  )
}

fn lower_lazy_local_call(
  cfg: &Cfg,
  resolver_ids: &[u32],
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  pc: usize,
) -> Result<(), Reject> {
  let known = cfg.has_local_call_callbacks;
  let ids = resolver_ids.len();
  if !known || pc >= ids {
    return Err(Reject::UnexpectedInstruction);
  }
  push(
    st,
    out,
    MInsn::LazyLocalCall {
      id: resolver_ids[pc],
    },
  )
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

fn lower_load(
  cfg: &Cfg,
  plan: &[PlanEntry],
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  pc: usize,
  insn: Insn,
  width: Width,
  signed: bool,
  dst: u8,
  src: u8,
  hint: u8,
) -> Result<(), Reject> {
  let size = width_bytes(width);
  let at = checked_address(
    cfg,
    plan,
    st,
    out,
    pc,
    src,
    insn.offset as i32,
    size as i32,
    hint,
    R11,
    RCX,
  )?;
  push(
    st,
    out,
    MInsn::Load {
      size,
      sx: signed,
      base: at.reg,
      dst,
      disp: at.disp,
    },
  )
}

fn lower_store_reg(
  cfg: &Cfg,
  plan: &[PlanEntry],
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  pc: usize,
  insn: Insn,
  width: Width,
  dst: u8,
  src: u8,
  hint: u8,
) -> Result<(), Reject> {
  let size = width_bytes(width);
  // A program storing R10 stores a pointer, and under a native frame base the
  // register holds the host one. Recover the guest value — but only after the
  // address is resolved, which uses RCX as its scratch.
  let active = cfg.native_frame_base_active();
  let recover_fp = active && src == R15;
  let at = checked_address(
    cfg,
    plan,
    st,
    out,
    pc,
    dst,
    insn.offset as i32,
    size as i32,
    hint,
    R11,
    RCX,
  )?;
  let mut value = src;
  if recover_fp {
    push(st, out, MInsn::GuestFp { dst: RCX })?;
    value = RCX;
  }
  push(
    st,
    out,
    MInsn::Store {
      size,
      src: value,
      base: at.reg,
      disp: at.disp,
    },
  )
}

fn lower_store_imm(
  cfg: &Cfg,
  plan: &[PlanEntry],
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  pc: usize,
  insn: Insn,
  width: Width,
  dst: u8,
  hint: u8,
) -> Result<(), Reject> {
  let size = width_bytes(width);
  // RCX carries the address here and R11 is the scratch, the other way round
  // from the register forms, because the immediate still needs a register of
  // its own once the address is resolved.
  let at = checked_address(
    cfg,
    plan,
    st,
    out,
    pc,
    dst,
    insn.offset as i32,
    size as i32,
    hint,
    RCX,
    R11,
  )?;
  if at.reg == dst {
    // No translation was needed, so the guest displacement stands.
    return push(
      st,
      out,
      MInsn::StoreImm {
        size,
        base: at.reg,
        disp: at.disp,
        imm: insn.imm,
      },
    );
  }
  push(
    st,
    out,
    MInsn::LoadImm {
      dst: R11,
      imm: insn.imm as i64,
    },
  )?;
  push(
    st,
    out,
    MInsn::Store {
      size,
      src: R11,
      base: at.reg,
      disp: at.disp,
    },
  )
}

/// True when `[base + offset]`, `size` bytes wide, is a frame access needing
/// no bounds check at all.
///
/// This is the one place a runtime check is traded for a static argument, so
/// three of the four conditions are re-derived here rather than taken from the
/// hint.
fn frame_access_ok(cfg: &Cfg, hint: u8, base: u8, offset: i32, size: i32) -> bool {
  let active = cfg.native_frame_base_active();
  if !active {
    return false;
  }
  if hint != region::FRAME {
    return false;
  }
  if base != R15 {
    return false;
  }
  // offset + size <= 0
  if offset > -size {
    return false;
  }
  if offset < -(cfg.stack_frame_size as i32) {
    return false;
  }
  true
}

/// The plan entry for `pc`, when plans are active and one exists.
fn plan_entry_at(cfg: &Cfg, plan: &[PlanEntry], pc: usize) -> Option<PlanEntry> {
  let active = cfg.access_plans_active();
  if !active {
    return None;
  }
  if pc >= plan.len() {
    return None;
  }
  Some(plan[pc])
}

/// Whether a member entry may ride the open group's parked base.
fn member_usable(st: &Lowering, entry: PlanEntry, base_ebpf: u8, offset: i32, width: i32) -> bool {
  if !st.group_open || base_ebpf >= 11 {
    return false;
  }
  if st.group_leader_pc != entry.leader_pc || st.group_base_reg != base_ebpf {
    return false;
  }
  if st.group_written & (1u16 << base_ebpf) != 0 {
    return false;
  }
  if entry.delta as i64 + width as i64 > st.group_span as i64 {
    return false;
  }
  st.group_lo as i64 + entry.delta as i64 == offset as i64
}

/// Whether a leader entry describes a window worth checking once.
fn leader_usable(entry: PlanEntry, base_ebpf: u8, offset: i32, width: i32) -> bool {
  if base_ebpf >= 11 {
    return false;
  }
  if entry.span == 0 || entry.span > MAX_GROUP_SPAN {
    return false;
  }
  if entry.delta as i64 + width as i64 > entry.span as i64 {
    return false;
  }
  if entry.lo as i64 + entry.delta as i64 != offset as i64 {
    return false;
  }
  entry.region != region::FRAME
}

/// Whether the plan entry at this slot takes the member fast path.
fn takes_member_path(
  st: &Lowering,
  entry: PlanEntry,
  base_ebpf: u8,
  offset: i32,
  width: i32,
) -> bool {
  if entry.role != plan_role::MEMBER {
    return false;
  }
  member_usable(st, entry, base_ebpf, offset, width)
}

/// Whether the plan entry at this slot opens a group.
fn takes_leader_path(entry: PlanEntry, base_ebpf: u8, offset: i32, width: i32) -> bool {
  if entry.role != plan_role::LEADER {
    return false;
  }
  leader_usable(entry, base_ebpf, offset, width)
}

/// Records the window a leader just checked and parked.
fn open_group(st: &mut Lowering, pc: usize, entry: PlanEntry, base_ebpf: u8) {
  st.group_open = true;
  st.group_leader_pc = pc as u32;
  st.group_span = entry.span;
  st.group_lo = entry.lo;
  st.group_base_reg = base_ebpf;
  st.group_written = 0;
}

/// Resolves `[base + offset]` to a native address, returning the register it
/// was left in and the displacement to use with it.
fn checked_address(
  cfg: &Cfg,
  plan: &[PlanEntry],
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  pc: usize,
  base: u8,
  offset: i32,
  width: i32,
  hint: u8,
  addr_reg: u8,
  scratch_reg: u8,
) -> Result<Addr, Reject> {
  let framed = frame_access_ok(cfg, hint, base, offset, width);
  if framed {
    return Ok(Addr {
      reg: base,
      disp: offset,
    });
  }
  if cfg.pointer_mask == 0 {
    return Ok(Addr {
      reg: base,
      disp: offset,
    });
  }

  let base_ebpf = unmap_register(base);
  let entry = plan_entry_at(cfg, plan, pc);

  if let Some(p) = entry {
    let member = takes_member_path(st, p, base_ebpf, offset, width);
    if member {
      push(st, out, MInsn::GroupBaseLoad { dst: addr_reg })?;
      return Ok(Addr {
        reg: addr_reg,
        disp: p.delta as i32,
      });
    }
    // A member the backend declined falls through to a checked access. The
    // group stays open: declining one member does not invalidate the parked
    // base for the ones after it.
    let leader = takes_leader_path(p, base_ebpf, offset, width);
    if leader {
      push(
        st,
        out,
        MInsn::CheckedAddr {
          src: base,
          dst: addr_reg,
          scratch: scratch_reg,
          offset: p.lo,
          size: p.span,
          region: p.region,
        },
      )?;
      push(st, out, MInsn::GroupBaseStore { src: addr_reg })?;
      open_group(st, pc, p, base_ebpf);
      return Ok(Addr {
        reg: addr_reg,
        disp: p.delta as i32,
      });
    }
  }

  push(
    st,
    out,
    MInsn::CheckedAddr {
      src: base,
      dst: addr_reg,
      scratch: scratch_reg,
      offset,
      size: width as u32,
      region: hint,
    },
  )?;
  Ok(Addr {
    reg: addr_reg,
    disp: 0,
  })
}

// ---------------------------------------------------------------------------
// Atomics
// ---------------------------------------------------------------------------

/// x86 ALU opcodes the atomic forms use.
const X64_ALU_ADD: u8 = 0x01;
const X64_ALU_OR: u8 = 0x09;
const X64_ALU_AND: u8 = 0x21;
const X64_ALU_XOR: u8 = 0x31;

/// The operation an atomic store's immediate selects.
///
/// The selector is the immediate's *high nibble* and the fetch flag its low
/// bit; everything in between is ignored, which is what keeps this and the
/// validator's operand filter agreeing about which programs exist.
fn atomic_selector(imm: i32) -> Option<AtomicOp> {
  let sel = (imm & (ALU_MASK as i32)) as u8;
  if sel == ALU_ADD {
    return Some(AtomicOp::Add);
  }
  if sel == ALU_OR {
    return Some(AtomicOp::Or);
  }
  if sel == ALU_AND {
    return Some(AtomicOp::And);
  }
  if sel == ALU_XOR {
    return Some(AtomicOp::Xor);
  }
  if sel == 0xe0 {
    return Some(AtomicOp::Xchg);
  }
  if sel == 0xf0 {
    return Some(AtomicOp::Cmpxchg);
  }
  None
}

/// The x86 register-form opcode for an atomic's arithmetic, or 0 for the
/// exchange forms, which have their own encodings.
fn atomic_alu_opcode(op: AtomicOp) -> u8 {
  match op {
    AtomicOp::Add => X64_ALU_ADD,
    AtomicOp::Or => X64_ALU_OR,
    AtomicOp::And => X64_ALU_AND,
    AtomicOp::Xor => X64_ALU_XOR,
    _ => 0,
  }
}

fn lower_atomic(
  cfg: &Cfg,
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  pc: usize,
  insn: Insn,
  width: Width,
  dst: u8,
  src: u8,
) -> Result<(), Reject> {
  let is64 = width_bytes(width) == 8;
  let mut base = dst;
  let mut disp = insn.offset as i32;
  if cfg.pointer_mask != 0 {
    // Atomics take the ordinary all-region probe. Page protection decides
    // whether the selected data backing is writable for this invocation.
    let size: u32 = if is64 { 8 } else { 4 };
    push(
      st,
      out,
      MInsn::CheckedAddr {
        src: dst,
        dst: R11,
        scratch: RCX,
        offset: insn.offset as i32,
        size,
        region: region::UNKNOWN,
      },
    )?;
    base = R11;
    disp = 0;
  }

  let selected = atomic_selector(insn.imm);
  let Some(selector) = selected else {
    return Err(Reject::UnknownAtomic { pc, imm: insn.imm });
  };

  match selector {
    AtomicOp::Xchg => lower_atomic_xchg(st, out, is64, src, base, disp),
    AtomicOp::Cmpxchg => lower_atomic_cmpxchg(st, out, is64, src, base, disp),
    _ => lower_atomic_alu(st, out, selector, insn.imm, is64, src, base, disp),
  }
}

/// `xchg`, which always yields the previous value in the source register.
fn lower_atomic_xchg(
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  is64: bool,
  src: u8,
  base: u8,
  disp: i32,
) -> Result<(), Reject> {
  push(
    st,
    out,
    MInsn::AtomicXchg {
      w64: is64,
      src,
      base,
      disp,
    },
  )?;
  if !is64 {
    return push(st, out, and_imm(false, src, -1));
  }
  Ok(())
}

/// `cmpxchg`, which always yields the previous value in eBPF `R0`.
fn lower_atomic_cmpxchg(
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  is64: bool,
  src: u8,
  base: u8,
  disp: i32,
) -> Result<(), Reject> {
  push(
    st,
    out,
    MInsn::AtomicCmpxchg {
      w64: is64,
      src,
      base,
      disp,
    },
  )?;
  if !is64 {
    return push(st, out, and_imm(false, RAX, -1));
  }
  Ok(())
}

fn lower_atomic_alu(
  st: &mut Lowering,
  out: &mut Vec<MInsn>,
  selector: AtomicOp,
  imm: i32,
  is64: bool,
  src: u8,
  base: u8,
  disp: i32,
) -> Result<(), Reject> {
  let op = atomic_alu_opcode(selector);
  let fetch = imm & 0x01 != 0;
  if fetch {
    return push(
      st,
      out,
      MInsn::AtomicFetchAlu {
        op,
        w64: is64,
        src,
        base,
        disp,
      },
    );
  }
  push(
    st,
    out,
    MInsn::AtomicAlu {
      op,
      w64: is64,
      src,
      base,
      disp,
    },
  )
}

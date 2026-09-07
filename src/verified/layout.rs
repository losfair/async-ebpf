//! Function layout: where the local functions of a section begin and end,
//! and the check that control flow never leaves one except through a call.
//!
//! A local function starts at slot 0, at every entry the container supplies
//! (the targets of calls from other sections), and at the target of every
//! local call; it runs to the next start or to the end of the section. The
//! JIT translates one function at a time, so a branch that leaves its function
//! would have nowhere to go. [`partition`] therefore walks every function from
//! its start, following fallthrough and jumps but not calls, and refuses the
//! section if the walk ever leaves the function's range or a local call names
//! a slot that is not a function start.
//!
//! What the walk visits is reported in [`Layout::reachable`]: exactly the
//! slots some execution of the section can reach without crossing a function
//! boundary. `lean/AsyncEbpf/Layout` proves that set is closed under the
//! semantics' successors and inside its function's range, which is what makes
//! "control stays in its function" a theorem about execution.
//!
//! Rejections carry the numbers the runtime's messages quote; the wording is
//! `crate::function_analysis`'s.

use super::isa::*;

/// Why a section's layout was refused.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(PartialEq, Eq, Debug))]
pub enum LayoutReject {
  /// A container-supplied entry is not inside the section.
  EntryOutOfRange { entry: usize },
  /// A local call's target is not inside the section.
  LocalCallTargetOutOfRange { pc: usize, target: i64 },
  /// A jump's target is not inside the section.
  JumpTargetOutOfRange { pc: usize, target: i64 },
  /// The walk popped a slot outside the function. Unreachable in practice:
  /// every pushed slot was checked first. Kept so the walk says so itself.
  ControlFlowOutside { pc: usize, start: usize, end: usize },
  /// A jump lands outside the function.
  JumpOutside {
    pc: usize,
    target: usize,
    start: usize,
    end: usize,
  },
  /// Fallthrough leaves the function.
  FallthroughOutside {
    pc: usize,
    target: usize,
    start: usize,
    end: usize,
  },
  /// A local call names a slot that is not a function start.
  LocalCallNonFunction { pc: usize, target: usize },
}

/// The layout of one section.
#[derive(Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug))]
pub struct Layout {
  /// Function start slots, strictly ascending, beginning with 0.
  pub starts: Vec<usize>,
  /// The function owning each slot: the index into `starts` of the last start
  /// at or before it.
  pub pc_to_func: Vec<usize>,
  /// The slots the walk visited: those reachable from a function start without
  /// crossing a function boundary.
  pub reachable: Vec<bool>,
}

fn is_local_call(insn: &Insn) -> bool {
  insn.opcode == OP_CALL && insn.src == 1
}

/// `pc + imm + 1`, checked against the section.
fn local_call_target(pc: usize, insn: &Insn, num_insns: usize) -> Result<usize, LayoutReject> {
  let target = pc as i64 + insn.imm as i64 + 1;
  if target < 0 || target >= num_insns as i64 {
    return Err(LayoutReject::LocalCallTargetOutOfRange { pc, target });
  }
  Ok(target as usize)
}

/// `pc + displacement + 1`, checked against the section.
fn jump_target(pc: usize, displacement: i64, num_insns: usize) -> Result<usize, LayoutReject> {
  let target = pc as i64 + displacement + 1;
  if target < 0 || target >= num_insns as i64 {
    return Err(LayoutReject::JumpTargetOutOfRange { pc, target });
  }
  Ok(target as usize)
}

fn mark_entries(
  entries: &[usize],
  num_insns: usize,
  is_start: &mut Vec<bool>,
) -> Result<(), LayoutReject> {
  let mut k = 0;
  while k < entries.len() {
    let entry = entries[k];
    if entry >= num_insns {
      return Err(LayoutReject::EntryOutOfRange { entry });
    }
    is_start[entry] = true;
    k += 1;
  }
  Ok(())
}

fn mark_call_targets(insns: &[Insn], is_start: &mut Vec<bool>) -> Result<(), LayoutReject> {
  let num_insns = insns.len();
  let mut pc = 0;
  while pc < num_insns {
    if is_local_call(&insns[pc]) {
      let target = local_call_target(pc, &insns[pc], num_insns)?;
      is_start[target] = true;
    }
    pc += 1;
  }
  Ok(())
}

fn collect_starts(is_start: &[bool]) -> Vec<usize> {
  let mut starts: Vec<usize> = Vec::new();
  let mut pc = 0;
  while pc < is_start.len() {
    if is_start[pc] {
      starts.push(pc);
    }
    pc += 1;
  }
  starts
}

/// `pc_to_func[pc] = func` for every `pc` in `[start, end)`.
fn fill_range(pc_to_func: &mut Vec<usize>, start: usize, end: usize, func: usize) {
  let mut pc = start;
  while pc < end {
    pc_to_func[pc] = func;
    pc += 1;
  }
}

/// The function owning each slot: function `i` owns `[starts[i], starts[i + 1])`,
/// the last one running to the end.
fn assign_functions(starts: &[usize], num_insns: usize) -> Vec<usize> {
  let mut pc_to_func: Vec<usize> = vec![0; num_insns];
  let mut i = 0;
  while i < starts.len() {
    let end = if i + 1 < starts.len() {
      starts[i + 1]
    } else {
      num_insns
    };
    fill_range(&mut pc_to_func, starts[i], end, i);
    i += 1;
  }
  pc_to_func
}

fn check_in_range(
  pc: usize,
  target: usize,
  start: usize,
  end: usize,
  jump: bool,
) -> Result<(), LayoutReject> {
  if target < start || target >= end {
    if jump {
      return Err(LayoutReject::JumpOutside {
        pc,
        target,
        start,
        end,
      });
    }
    return Err(LayoutReject::FallthroughOutside {
      pc,
      target,
      start,
      end,
    });
  }
  Ok(())
}

/// The slots control can reach from `pc` without a call: at most two.
/// `count` says how many of `first`, `second` are meaningful; `first_is_jump`
/// says whether `first` is a jump target (as opposed to fallthrough), which
/// only the rejection's wording cares about. `second` is always fallthrough.
///
/// A local call is checked here to name a function start; its successor is
/// the slot after it, since the callee returns there.
fn successors(
  insns: &[Insn],
  pc: usize,
  is_start: &[bool],
) -> Result<(usize, usize, bool, usize), LayoutReject> {
  let num_insns = insns.len();
  let insn = insns[pc];

  if insn.opcode == OP_EXIT {
    return Ok((0, 0, false, 0));
  }
  if insn.opcode == OP_CALL {
    if insn.src == 1 {
      let target = local_call_target(pc, &insn, num_insns)?;
      if !is_start[target] {
        return Err(LayoutReject::LocalCallNonFunction { pc, target });
      }
    }
    return Ok((1, pc + 1, false, 0));
  }
  if insn.opcode == OP_LDDW {
    return Ok((1, pc + 2, false, 0));
  }
  let cls = insn.opcode & CLS_MASK;
  if cls == CLS_JMP || cls == CLS_JMP32 {
    if insn.opcode == OP_JA {
      let target = jump_target(pc, insn.offset as i64, num_insns)?;
      return Ok((1, target, true, 0));
    }
    if insn.opcode == OP_JA32 {
      let target = jump_target(pc, insn.imm as i64, num_insns)?;
      return Ok((1, target, true, 0));
    }
    let target = jump_target(pc, insn.offset as i64, num_insns)?;
    return Ok((2, target, true, pc + 1));
  }
  Ok((1, pc + 1, false, 0))
}

/// Walks the function `[start, end)` from `start`, following fallthrough and
/// jumps but not calls, marking what it visits in `reachable`.
///
/// `pending` is scratch space for the worklist, at least `2 * (end - start) + 2`
/// long: every slot is expanded at most once and pushes at most two successors.
fn scan_function(
  insns: &[Insn],
  start: usize,
  end: usize,
  is_start: &[bool],
  reachable: &mut Vec<bool>,
  pending: &mut Vec<usize>,
) -> Result<(), LayoutReject> {
  pending[0] = start;
  let mut top = 1;

  while top > 0 {
    top -= 1;
    let pc = pending[top];
    if pc < start || pc >= end {
      return Err(LayoutReject::ControlFlowOutside { pc, start, end });
    }
    if reachable[pc] {
      continue;
    }
    reachable[pc] = true;

    let (count, first, first_is_jump, second) = successors(insns, pc, is_start)?;
    if count >= 1 {
      check_in_range(pc, first, start, end, first_is_jump)?;
      pending[top] = first;
      top += 1;
    }
    if count >= 2 {
      check_in_range(pc, second, start, end, false)?;
      pending[top] = second;
      top += 1;
    }
  }

  Ok(())
}

/// Walks every function.
fn scan_all(
  insns: &[Insn],
  starts: &[usize],
  is_start: &[bool],
  reachable: &mut Vec<bool>,
) -> Result<(), LayoutReject> {
  let num_insns = insns.len();
  let mut pending: Vec<usize> = vec![0; 2 * num_insns + 2];
  let mut i = 0;
  while i < starts.len() {
    let start = starts[i];
    let end = if i + 1 < starts.len() {
      starts[i + 1]
    } else {
      num_insns
    };
    scan_function(insns, start, end, is_start, reachable, &mut pending)?;
    i += 1;
  }
  Ok(())
}

/// Partitions a non-empty section into local functions and checks that each
/// is closed under its own control flow. `entries` are the container-supplied
/// starts.
pub fn partition(insns: &[Insn], entries: &[usize]) -> Result<Layout, LayoutReject> {
  let num_insns = insns.len();
  let mut is_start: Vec<bool> = vec![false; num_insns];
  is_start[0] = true;
  mark_entries(entries, num_insns, &mut is_start)?;
  mark_call_targets(insns, &mut is_start)?;
  let starts = collect_starts(&is_start);
  let pc_to_func = assign_functions(&starts, num_insns);
  let mut reachable: Vec<bool> = vec![false; num_insns];
  scan_all(insns, &starts, &is_start, &mut reachable)?;
  Ok(Layout {
    starts,
    pc_to_func,
    reachable,
  })
}

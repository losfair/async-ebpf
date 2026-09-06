//! The region analysis' fixed point over one function.
//!
//! [`solve`] is the worklist `crate::region_analysis::analyze_function`
//! drives: from the entry state a signature gives, apply [`transfer`] to a
//! slot and [`meet_from`] the result into each successor inside the
//! function, re-queueing a successor whose state changed, until nothing is
//! queued. What it adds to the textbook loop is the projection: the value
//! flowing into a slot is first restricted to that slot's live-in registers
//! ([`project`]), and so is the entry state. A register that is dead at a
//! slot therefore never holds a kind there. That is what makes the live-in
//! masking of call signatures exactly neutral — `lean/AsyncEbpf/Region/
//! Masking.lean` shows the masked and the unmasked signature give the same
//! entry state, after which the two runs are one — and it is also why the
//! worklist's order, which depends on which registers change, cannot depend
//! on a dead one either.
//!
//! The live-in table is an input; `region_analysis::program_live_in`
//! computes it. It must over-approximate the registers a slot can read
//! before writing, else the projection would drop a kind the slot still
//! consults; the same table already keys the specialization of callees.

use super::isa::*;
use super::region::{meet_from, project, top, transfer, PointerSignature, RegMask, State};

/// The result of [`solve`]: the state at every slot of the function (`top`
/// where the walk never arrived), which slots it reached, both indexed from
/// the function's start, and whether the spill-slot cap refused an entry
/// anywhere.
pub struct Solution {
  pub states: Vec<State>,
  pub reached: Vec<bool>,
  pub refused: bool,
}

/// The slots control can reach from `pc` before filtering by the function:
/// `(count, first, second)`. A call of any kind continues at the next slot
/// (a local callee is a separate function), `lddw` skips its second half,
/// and a conditional jump has its target first and the fallthrough second.
fn raw_successors(insn: &Insn, pc: usize) -> (usize, i64, i64) {
  let next = pc as i64 + 1;
  let cls = insn.opcode & CLS_MASK;
  if cls == CLS_JMP || cls == CLS_JMP32 {
    if insn.opcode == OP_EXIT {
      return (0, 0, 0);
    }
    if insn.opcode == OP_CALL {
      if insn.src == 0 || insn.src == 1 || insn.src == 2 {
        return (1, next, 0);
      }
      return (0, 0, 0);
    }
    // `ja32` is the only jump whose displacement is the 32-bit immediate.
    let target = if insn.opcode == OP_JA32 {
      next + insn.imm as i64
    } else {
      next + insn.offset as i64
    };
    if insn.opcode == OP_JA || insn.opcode == OP_JA32 {
      return (1, target, 0);
    }
    return (2, target, next);
  }
  if insn.opcode == OP_LDDW {
    return (1, next + 1, 0);
  }
  (1, next, 0)
}

fn in_function(target: i64, start: usize, end: usize) -> bool {
  target >= start as i64 && target < end as i64
}

/// The successors of `pc` inside the function `[start, end)`: `(count,
/// first, second)`, with `count` saying how many are meaningful. A target
/// outside the function is dropped; `partition` has refused any that a
/// non-call could reach, so on an accepted section only a wild displacement
/// is ever dropped here.
pub fn function_successors(
  insns: &[Insn],
  pc: usize,
  start: usize,
  end: usize,
) -> (usize, usize, usize) {
  let insn = insns[pc];
  let (count, first, second) = raw_successors(&insn, pc);
  let keep_first = count >= 1 && in_function(first, start, end);
  let keep_second = count >= 2 && in_function(second, start, end);
  if keep_first {
    if keep_second {
      (2, first as usize, second as usize)
    } else {
      (1, first as usize, 0)
    }
  } else if keep_second {
    (1, second as usize, 0)
  } else {
    (0, 0, 0)
  }
}

/// The 64-bit immediate of an `lddw` at `pc`: its own `imm` is the low half,
/// the next slot's the high half. Zero for anything else, and for an `lddw`
/// whose second half is missing.
pub fn lddw_full_imm(insns: &[Insn], pc: usize) -> u64 {
  let insn = insns[pc];
  if insn.opcode == OP_LDDW && pc + 1 < insns.len() {
    let lo = insn.imm as u32 as u64;
    let hi = insns[pc + 1].imm as u32 as u64;
    lo | (hi << 32u32)
  } else {
    0
  }
}

/// Meets `out`, projected onto `live`, into `succ`, and queues `succ` if it
/// is new or changed and not already queued. `sp` is the stack's height;
/// returns the new height and whether the spill-slot cap refused an entry.
fn propagate(
  states: &mut Vec<State>,
  reached: &mut Vec<bool>,
  on_list: &mut Vec<bool>,
  stack: &mut Vec<usize>,
  sp: usize,
  succ: usize,
  out: &State,
  live: RegMask,
) -> (usize, bool) {
  let mut incoming = *out;
  project(&mut incoming, live);
  let was_reached = reached[succ];
  reached[succ] = true;
  let (changed, refused) = meet_from(&mut states[succ], &incoming);
  let mut top = sp;
  if (!was_reached || changed) && !on_list[succ] {
    on_list[succ] = true;
    stack[sp] = succ;
    top = sp + 1;
  }
  (top, refused)
}

/// The fixed point of one function from `entry` at its first slot. `insns`
/// are the function's own slots, so every pc here is relative to its start;
/// `live[pc]` is the live-in mask of slot `pc`; `[data_lo, data_hi)` is the
/// guest data region. Requires `0 < insns.len() <= live.len()`.
///
/// Everything allocated here is the function's size, not the section's:
/// the loader runs this once per function and signature it compiles, and a
/// section can hold thousands of functions.
///
/// The worklist is a stack: a slot is on it at most once (`on_list`), so it
/// never holds more than `insns.len()` entries.
pub fn solve_from(
  insns: &[Insn],
  entry: State,
  live: &[RegMask],
  data_lo: u64,
  data_hi: u64,
) -> Solution {
  let num = insns.len();
  let mut states: Vec<State> = vec![top(); num];
  let mut reached: Vec<bool> = vec![false; num];
  let mut on_list: Vec<bool> = vec![false; num];
  let mut stack: Vec<usize> = vec![0; num];
  states[0] = entry;
  reached[0] = true;
  on_list[0] = true;
  stack[0] = 0;
  let mut sp = 1;
  let mut refused = false;

  while sp > 0 {
    sp -= 1;
    let pc = stack[sp];
    on_list[pc] = false;
    let insn = insns[pc];
    let lddw_addr = lddw_full_imm(insns, pc);
    let (out, r) = transfer(&states[pc], &insn, lddw_addr, data_lo, data_hi);
    if r {
      refused = true;
    }
    let (count, first, second) = function_successors(insns, pc, 0, num);
    if count >= 1 {
      let (top, r1) = propagate(
        &mut states,
        &mut reached,
        &mut on_list,
        &mut stack,
        sp,
        first,
        &out,
        live[first],
      );
      sp = top;
      if r1 {
        refused = true;
      }
    }
    if count >= 2 {
      let (top, r2) = propagate(
        &mut states,
        &mut reached,
        &mut on_list,
        &mut stack,
        sp,
        second,
        &out,
        live[second],
      );
      sp = top;
      if r2 {
        refused = true;
      }
    }
  }

  Solution {
    states,
    reached,
    refused,
  }
}

/// [`solve_from`] the entry state `sig` gives, projected onto the first
/// slot's live-in registers.
pub fn solve(
  insns: &[Insn],
  sig: &PointerSignature,
  live: &[RegMask],
  data_lo: u64,
  data_hi: u64,
) -> Solution {
  let entry = super::region::entry_state(sig, live[0]);
  solve_from(insns, entry, live, data_lo, data_hi)
}

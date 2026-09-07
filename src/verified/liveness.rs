//! The live-in solver: which registers each slot of a program can read
//! before writing, transitively through the functions it calls.
//!
//! [`solve`] is the whole-program backward dataflow behind
//! `crate::region_analysis::program_live_in`. Its input is every section's
//! instructions laid end to end, with each slot's function, each function's
//! bounds and entry, and each call site's callee already resolved by the
//! caller; its output is one mask per slot. A function's mask is the
//! liveness of its entry slot, and a local call site reads its callee's
//! mask, which is what makes every function and every summary one dataflow
//! problem rather than a fixed point of fixed points.
//!
//! The equations, per slot `p`:
//!
//! ```text
//! live[p] ⊇ uses(p) ∪ (⋃ { live[q] | q a successor of p } ∖ defs(p))
//! ```
//!
//! where `uses(p)` for a local call is the callee's entry liveness
//! (`callee_summary`). `lean/AsyncEbpf/Liveness/Proofs.lean` proves the
//! table `solve` returns satisfies them at every slot, which is exactly the
//! `LiveSolution` hypothesis the region analysis' masking proofs rest on.
//!
//! The solver is a worklist over one predecessor list per slot and one
//! call-site list per function, both as intrusive linked lists built in one
//! pass ([`build_preds`], [`build_callers`]): a slot whose liveness grows
//! re-queues its predecessors, and a function entry that grows re-queues
//! the function's call sites. Every slot's liveness only gains bits, ten at
//! most, so each edge is traversed at most ten times — linear in the
//! program, which the load path needs (`src/test/region_analysis_complexity.rs`).
//!
//! Unreachable slots are solved along with the rest. They cannot reach a
//! reachable slot's equation (liveness flows to predecessors, and a
//! predecessor of an unreachable slot is unreachable), so every reachable
//! slot and every function mask comes out as if they had been skipped.

use super::fixpoint::function_successors;
use super::isa::Insn;
use super::region::{uses_and_defs, RegMask, ALL_SIGNATURE_REGS};

/// A slot that is not a call, in the callee table.
pub const NOT_A_CALL: u32 = u32::MAX;
/// A call whose callee the caller could not name: reads everything.
pub const UNRESOLVED: u32 = u32::MAX - 1;
/// The end of a linked list.
const NO_EDGE: u32 = u32::MAX;

/// Pushes `edge` onto the list of `target`.
fn link(head: &mut Vec<u32>, next: &mut Vec<u32>, target: usize, edge: usize) {
  next[edge] = head[target];
  head[target] = edge as u32;
}

/// The predecessor lists. Edge `2 * p + k` is slot `p`'s `k`-th successor
/// edge; `head[q]` starts the list of edges into `q`.
fn build_preds(
  insns: &[Insn],
  slot_func: &[u32],
  func_start: &[u32],
  func_end: &[u32],
  head: &mut Vec<u32>,
  next: &mut Vec<u32>,
) {
  let mut p = 0;
  while p < insns.len() {
    let f = slot_func[p] as usize;
    let (count, first, second) =
      function_successors(insns, p, func_start[f] as usize, func_end[f] as usize);
    if count >= 1 {
      link(head, next, first, 2 * p);
    }
    if count >= 2 {
      link(head, next, second, 2 * p + 1);
    }
    p += 1;
  }
}

/// The call-site lists. Edge `p` is the call at slot `p`; `head[f]` starts
/// the list of calls into function `f`.
fn build_callers(callee: &[u32], head: &mut Vec<u32>, next: &mut Vec<u32>) {
  let mut p = 0;
  while p < callee.len() {
    let c = callee[p];
    if c != NOT_A_CALL && c != UNRESOLVED {
      link(head, next, c as usize, p);
    }
    p += 1;
  }
}

/// Queues every slot on the list starting at `edge`, where an edge names
/// slot `edge / per_slot`. Returns the stack's new height.
fn wake(
  next: &[u32],
  queued: &mut Vec<bool>,
  stack: &mut Vec<u32>,
  sp: usize,
  edge: u32,
  per_slot: u32,
) -> usize {
  let mut e = edge;
  let mut top = sp;
  while e != NO_EDGE {
    let p = (e / per_slot) as usize;
    if !queued[p] {
      queued[p] = true;
      stack[top] = p as u32;
      top += 1;
    }
    e = next[e as usize];
  }
  top
}

/// What a call at a slot reads of its caller's registers: nothing for a
/// non-call, everything for a call the caller could not resolve, and the
/// callee's entry liveness otherwise.
fn callee_summary(callee: u32, func_start: &[u32], live: &[RegMask]) -> RegMask {
  if callee == NOT_A_CALL {
    0
  } else if callee == UNRESOLVED {
    ALL_SIGNATURE_REGS
  } else {
    live[func_start[callee as usize] as usize]
  }
}

/// `stack[i] = i`: every slot queued, in ascending order, so the first pop
/// is the last slot and forward edges converge on the first visit.
fn seed(stack: &mut Vec<u32>) {
  let mut i = 0;
  while i < stack.len() {
    stack[i] = i as u32;
    i += 1;
  }
}

/// The live-in mask of every slot. `insns` are all sections' slots end to
/// end; `slot_func[p]` is the function slot `p` belongs to, whose bounds are
/// `func_start[f]..func_end[f]`; `callee[p]` is the function a local call at
/// `p` enters, [`NOT_A_CALL`] or [`UNRESOLVED`]. Requires every function to
/// lie inside one section, every index to be in range, and fewer than
/// `2^31` slots, so that edge ids fit.
pub fn solve(
  insns: &[Insn],
  slot_func: &[u32],
  func_start: &[u32],
  func_end: &[u32],
  callee: &[u32],
) -> Vec<RegMask> {
  let n = insns.len();
  let nf = func_start.len();
  let mut pred_head: Vec<u32> = vec![NO_EDGE; n];
  let mut pred_next: Vec<u32> = vec![NO_EDGE; 2 * n];
  build_preds(
    insns,
    slot_func,
    func_start,
    func_end,
    &mut pred_head,
    &mut pred_next,
  );
  let mut caller_head: Vec<u32> = vec![NO_EDGE; nf];
  let mut caller_next: Vec<u32> = vec![NO_EDGE; n];
  build_callers(callee, &mut caller_head, &mut caller_next);

  let mut live: Vec<RegMask> = vec![0; n];
  let mut queued: Vec<bool> = vec![true; n];
  let mut stack: Vec<u32> = vec![0; n];
  seed(&mut stack);
  let mut sp = n;

  while sp > 0 {
    sp -= 1;
    let p = stack[sp] as usize;
    queued[p] = false;
    let f = slot_func[p] as usize;
    let start = func_start[f] as usize;
    let (count, first, second) = function_successors(insns, p, start, func_end[f] as usize);
    let mut live_out: RegMask = 0;
    if count >= 1 {
      live_out |= live[first];
    }
    if count >= 2 {
      live_out |= live[second];
    }
    let summary = callee_summary(callee[p], func_start, &live);
    let (uses, defs) = uses_and_defs(&insns[p], summary);
    // Monotone by construction: the union with the previous value keeps
    // termination independent of `uses` and `live_out` only ever growing.
    let next = live[p] | uses | (live_out & !defs);
    if next != live[p] {
      live[p] = next;
      sp = wake(&pred_next, &mut queued, &mut stack, sp, pred_head[p], 2);
      if p == start {
        // A function's mask is its entry slot's liveness, so growing that
        // slot is what wakes its call sites, anywhere in the program.
        sp = wake(&caller_next, &mut queued, &mut stack, sp, caller_head[f], 1);
      }
    }
  }

  live
}

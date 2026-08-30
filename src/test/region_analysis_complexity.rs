//! Regression test for the region-analysis time-complexity fix.
//!
//! A straight-line function of stores at distinct `R10`-relative offsets used
//! to make [`analyze_function`](crate::region_analysis) quadratic: `transfer`
//! cloned the whole `State` — including the spill-offset map, one entry per
//! distinct offset — at every instruction, and every slot's state kept its own
//! merged copy, so `n` distinct store offsets cost Θ(n²) time and retained
//! memory. A hostile program of ~16,000 such stores pinned the host thread for
//! ~124 s (debug build) with GiB-scale allocations on the first
//! `Program::run`, and the compile is not preemption-interruptible (the
//! SIGUSR1 handler only acts inside the JIT code zone).
//!
//! The spill map is now persistent ([`rpds::RedBlackTreeMap`]): `State` clones
//! are O(1) under structural sharing, inserts are O(log n), `meet_from` adopts
//! the incoming map wholesale while a state is still top, and
//! `invalidate_stack_write` range-scans the tree instead of scanning the whole
//! map. This test runs the canonical hostile shape end to end and bounds the
//! wall time. The budget is ~75× the measured time of the fixed code, so a
//! loaded CI machine does not flake it, while any reintroduction of the
//! per-instruction full-state clone (the Θ(n²) mechanism) misses it by ~8×.
//!
//! A second hostile shape targets whole-map invalidation: a store through a
//! base the analysis cannot pin makes every tracked spill slot `Unknown`, and
//! that used to cost O(k) per store no matter how the map was represented.
//! Invalidation is now lazy — each entry carries the state's invalidation
//! epoch, so an unpinnable store is a single O(1) epoch bump.

use std::time::{Duration, Instant};

use crate::{
  error::{Error, RuntimeError},
  test::raw_elf::{run_raw, Insn},
};

/// Distinct `R10`-relative store offsets in one straight-line function.
/// 16,000 was the canonical repro size from the audit: ~124 s (debug) before
/// the fix, ~0.2 s after.
const DISTINCT_STORES: usize = 16_000;

/// Generates `n` `stx dw r0, [r10 + off]` instructions with distinct offsets,
/// then `exit`. The offsets are deliberately unaligned and far beyond the
/// frame window, so the program faults at the first store at run time — what
/// matters here is that it *loads* and that its first-run compile is the thing
/// being timed.
fn hostile_store_function(n: usize) -> Vec<Insn> {
  let mut code = Vec::with_capacity(n + 1);
  for i in 0..n {
    code.push(Insn::stx_dw(10, 0, -((i as i16) + 1)));
  }
  code.push(Insn::exit());
  code
}

#[tokio::test]
async fn distinct_off_stack_stores_analyze_in_nlogn_time() {
  // Generous on purpose: the fixed code takes ~200 ms (debug) / ~30 ms
  // (release) at this size, so the budget is ~75× headroom even on a loaded
  // CI runner. The pre-fix code took ~124 s (debug) / ~11 s (release) — any
  // return to per-instruction full-state clones fails by ~8×.
  let budget = if cfg!(debug_assertions) {
    Duration::from_secs(15)
  } else {
    Duration::from_secs(5)
  };

  let code = hostile_store_function(DISTINCT_STORES);

  let start = Instant::now();
  // Loads the hostile object, then JIT-compiles the entrypoint on first run.
  let result = run_raw(&code, &[], &[], false).await;
  let elapsed = start.elapsed();

  // The object must load and compile, then fault at the first out-of-frame
  // store. A fast `Err` for any other reason (e.g. a load-time rejection)
  // would let the test pass without ever timing the analysis.
  assert!(
    matches!(result, Err(Error(RuntimeError::MemoryFault(_)))),
    "hostile program must load, compile, and fault at an out-of-frame store; got {result:?}"
  );
  assert!(
    elapsed < budget,
    "region analysis of {DISTINCT_STORES} distinct-offset stack stores took {elapsed:?} \
     (budget {budget:?}); the analysis must be O(n log n), not O(n²) — see the \
     persistent-map fix in region_analysis.rs"
  );
}

/// Grows the spill map by `spills_per_round` distinct pointer spills, then
/// issues `invalidations_per_round` stores through `r0` — a base the analysis
/// cannot pin, so every tracked slot is invalidated. The function alternates
/// the two `rounds` times, ending with `exit`. Before the epoch-based
/// invalidation this was Θ(n·k): each unpinnable store walked the whole map.
fn hostile_invalidate_function(
  spills_per_round: usize,
  invalidations_per_round: usize,
  rounds: usize,
) -> Vec<Insn> {
  let mut code = Vec::new();
  let mut n = 0usize;
  for _ in 0..rounds {
    // Spill a distinct stack pointer value at a distinct offset: the analysis
    // tracks slot `-(n as i16)` as a pointer, growing the map by one.
    for _ in 0..spills_per_round {
      n += 1;
      code.push(Insn::mov64_reg(1, 10));
      code.push(Insn::add64_imm(1, -(n as i32)));
      code.push(Insn::stx_dw(10, 1, -(n as i16)));
    }
    // Store through the still-scalar `r0`: whole-map invalidation.
    for _ in 0..invalidations_per_round {
      code.push(Insn::stx_dw(0, 0, 0));
    }
  }
  code.push(Insn::exit());
  code
}

#[tokio::test]
async fn unpinnable_stores_invalidate_in_constant_time() {
  // The fixed code takes ~150 ms (debug) at this size; the budget is ~100×
  // headroom. The eager whole-map invalidation took ~30-60 s (debug) — any
  // return to per-event map rewriting misses the budget by ~4×.
  let budget = if cfg!(debug_assertions) {
    Duration::from_secs(15)
  } else {
    Duration::from_secs(5)
  };

  let code = hostile_invalidate_function(2000, 2000, 5); // 40,000 instructions

  let start = Instant::now();
  let result = run_raw(&code, &[], &[], false).await;
  let elapsed = start.elapsed();

  assert!(
    matches!(result, Err(Error(RuntimeError::MemoryFault(_)))),
    "hostile program must load, compile, and fault at the first unpinnable store; got {result:?}"
  );
  assert!(
    elapsed < budget,
    "region analysis of alternating pointer spills and unpinnable stores took {elapsed:?} \
     (budget {budget:?}); invalidation must be O(1) per unpinnable store — see the \
     invalidation-epoch fix in region_analysis.rs"
  );
}

/// The "ladder" CFG from the liveness-fixpoint audit finding: `ja +1; ja +1;
/// ja -2` repeated — an acyclic chain whose every path crosses ~n/3 backward
/// edges, ending in a register use (`add64 r0, r6`) and `exit`, so every live
/// bit has to cross every backward edge to reach the entry.
///
/// [`function_live_in`](crate::region_analysis) used to compute backward
/// liveness with an all-slots fixpoint sweep: one pass per backward edge on a
/// path, ~n/3 passes over all n slots, Θ(n²) — measured ~17 s (release) at
/// the maximum program size, inside the non-preemptible load path. The
/// fixpoint is now worklist-driven (only predecessors of changed slots are
/// re-evaluated), so the same shape costs O(bits · edges). This test runs the
/// hostile shape end to end and bounds the wall time; the budget is ~50× the
/// measured time of the fixed code, while the sweep misses it by ~3×.
#[tokio::test]
async fn ladder_cfg_live_in_analysis_is_linear() {
  let budget = if cfg!(debug_assertions) {
    Duration::from_secs(15)
  } else {
    Duration::from_secs(5)
  };

  // 65,534 = 3 × 21,844 triples + `add64 r0, r6` + `exit`; 65,536 is refused,
  // so this is the legal maximum and the shape that maximizes the Θ(n²) cost.
  let n = 65_534;
  let triples = (n - 2) / 3;
  let mut code = Vec::with_capacity(n);
  for _ in 0..triples {
    code.push(Insn::raw(0x05, 0, 0, 1, 0)); // ja +1
    code.push(Insn::raw(0x05, 0, 0, 1, 0)); // ja +1
    code.push(Insn::raw(0x05, 0, 0, -2, 0)); // ja -2, target pc + 1
  }
  // Chain from the last triple into the register use.
  for _ in code.len()..n - 2 {
    code.push(Insn::raw(0x05, 0, 0, 1, 0));
  }
  code.push(Insn::raw(0x0f, 0, 6, 0, 0)); // add64 r0, r6 — makes R6 live-in
  code.push(Insn::exit());

  let start = Instant::now();
  // The load (where the pre-fix code burned ~17 s) and the run of the whole
  // chain must both succeed — a fast rejection would pass without timing the
  // analysis.
  let result = run_raw(&code, &[], &[], false).await;
  let elapsed = start.elapsed();

  assert!(
    result.is_ok(),
    "ladder program must load and run; got {result:?}"
  );
  assert!(
    elapsed < budget,
    "liveness analysis of the {n}-slot ladder took {elapsed:?} (budget {budget:?}); \
     the fixpoint must be O(bits · edges), not O(n²) — see function_live_in"
  );
}

/// Links in the chain the two tests below build. `3 · CHAIN + 1` slots stays
/// inside the 65,535-instruction ceiling, and it is large enough that the two
/// solvers are not close: the fixed one takes ~13 ms release, the per-function
/// one 48.5 s.
const CHAIN: usize = 16_000;

/// One caller that calls all `links` links of a chain, laid out so the live bit
/// has to walk the chain from its tail one worklist step at a time.
///
/// This is the shape that made the previous two-level solve quadratic: every
/// link that settled woke the caller, and re-analyzing the caller cost its
/// whole span each time. Nothing about the call graph bounded that. Condensing
/// into strongly connected components would not have helped either — the graph
/// is a DAG, and the cost is in one function's fan-out, not in a cycle.
fn call_chain_section(links: usize) -> Vec<u8> {
  let mut code: Vec<Insn> = Vec::with_capacity(3 * links + 1);
  // The caller: one call per link, then `exit`. Function `[0, links + 1)`.
  for pc in 0..links {
    let target = links + 1 + 2 * pc;
    code.push(Insn::call_local((target - pc - 1) as i32));
  }
  code.push(Insn::exit());
  // The chain: two slots each, every link calling the next. Only the last
  // reads R6, so the bit has to travel the whole way back to the caller.
  for i in 0..links {
    let pc = links + 1 + 2 * i;
    if i + 1 < links {
      let target = links + 1 + 2 * (i + 1);
      code.push(Insn::call_local((target - pc - 1) as i32));
    } else {
      // `mov`, not `add`: it reads R6 without also reading R0, so the expected
      // mask is exactly one bit.
      code.push(Insn::raw(0xbf, 0, 6, 0, 0)); // mov64 r0, r6
    }
    code.push(Insn::exit());
  }
  code
    .iter()
    .flat_map(|insn| insn.value.to_le_bytes())
    .collect()
}

/// ~370× headroom on the fixed solver, and the per-function solve this replaced
/// misses it by ~10× (48.5 s, measured at `CHAIN`).
fn live_in_budget() -> Duration {
  if cfg!(debug_assertions) {
    Duration::from_secs(15)
  } else {
    Duration::from_secs(5)
  }
}

#[test]
fn a_call_chain_in_one_section_analyzes_in_linear_time() {
  let code = call_chain_section(CHAIN);

  let start = Instant::now();
  let layout = crate::function_analysis::analyze_functions(&code).unwrap();
  let elapsed = start.elapsed();

  // Every function must end up reading R6, or the bit never travelled the
  // chain and the timing measured nothing.
  assert_eq!(
    layout.arg_masks,
    vec![1 << 6; CHAIN + 1],
    "the live bit must reach every link, or this timed the wrong thing"
  );
  assert!(
    elapsed < live_in_budget(),
    "live-in analysis of a {CHAIN}-link call chain took {elapsed:?} (budget {:?}); \
     the solve must be O(bits · edges) over the whole program, not a per-function \
     fixed point that restarts a caller once per callee — see program_live_in",
    live_in_budget()
  );
}

#[test]
fn a_call_chain_across_sections_analyzes_in_linear_time() {
  use crate::function_analysis::{analyze_program, CrossSectionEdge, SectionInput};

  // The same shape with the caller and the chain in different sections.
  // Solving the sections separately used to cut every one of these edges,
  // which hid the cost behind a summary; solving them together, which is what
  // buys the specialization precision, must not reintroduce it.
  let mut caller: Vec<Insn> = (0..CHAIN).map(|_| Insn::raw(0x85, 0, 2, 0, 0)).collect();
  caller.push(Insn::exit());
  let caller = caller
    .iter()
    .flat_map(|insn| insn.value.to_le_bytes())
    .collect::<Vec<u8>>();

  let mut callee: Vec<Insn> = Vec::with_capacity(2 * CHAIN);
  for i in 0..CHAIN {
    if i + 1 < CHAIN {
      callee.push(Insn::call_local(1)); // the next link, two slots along
    } else {
      callee.push(Insn::raw(0xbf, 0, 6, 0, 0)); // mov64 r0, r6
    }
    callee.push(Insn::exit());
  }
  let callee = callee
    .iter()
    .flat_map(|insn| insn.value.to_le_bytes())
    .collect::<Vec<u8>>();

  let entries = (0..CHAIN).map(|i| i * 2).collect::<Vec<_>>();
  let edges = (0..CHAIN)
    .map(|i| CrossSectionEdge {
      caller_section: 0,
      call_pc: i,
      callee_section: 1,
      callee_pc: i * 2,
    })
    .collect::<Vec<_>>();

  let start = Instant::now();
  let layouts = analyze_program(
    &[
      SectionInput {
        code: &caller,
        entries: &[],
      },
      SectionInput {
        code: &callee,
        entries: &entries,
      },
    ],
    &edges,
  )
  .unwrap();
  let elapsed = start.elapsed();

  assert_eq!(
    layouts[0].arg_masks,
    vec![1 << 6],
    "the caller's mask must come from the chain's tail, through every link"
  );
  assert!(
    elapsed < live_in_budget(),
    "live-in analysis of a {CHAIN}-link cross-section call chain took {elapsed:?} \
     (budget {:?}); coupling the sections must not cost more than solving them \
     apart — see program_live_in",
    live_in_budget()
  );
}

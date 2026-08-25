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

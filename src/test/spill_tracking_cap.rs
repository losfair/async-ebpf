//! The tracked-spill-slot cap: one state tracks at most
//! `MAX_TRACKED_SLOTS` distinct `R10`-relative store offsets.
//!
//! The cap exists to bound a hostile function that invents distinct spill
//! offsets; the cost of refusing a slot is pure precision — the slot reads
//! back as a scalar and its uses fall back to the JIT's dual-region probe,
//! exactly like a slot the analysis never saw. These tests pin that contract:
//! slots within the cap get a confident region hint, slots beyond it get
//! `UNKNOWN`, and a program that actually spills past the cap still runs
//! correctly end to end.

use crate::{
  test::raw_elf::{run_raw, Insn},
  test_util::region_analysis::analyze_section,
};

const DATA_LO: u64 = 0x1_0000;
const DATA_HI: u64 = 0x2_0000;
/// A constant inside `[DATA_LO, DATA_HI)`: the analysis routes it as `Data`.
const DATA_ADDR: u64 = DATA_LO + 8;

/// The cap as exercised by this test: 40 distinct spill offsets, 32 tracked.
const SPILLS: usize = 40;

/// `lddw r1, DATA_ADDR` — two slots, no relocation (the test-only analysis
/// takes the data bounds explicitly).
fn lddw_data_reg() -> [Insn; 2] {
  [
    Insn::raw(0x18, 1, 0, 0, DATA_ADDR as i32),
    Insn::raw(0, 0, 0, 0, (DATA_ADDR >> 32) as i32),
  ]
}

#[test]
fn slots_beyond_the_cap_are_not_tracked() {
  // 40 distinct data-pointer spills at -8, -16, ..., -320, then a fill and
  // deref from the first slot (within the cap) and from the last (beyond it).
  let mut code = Vec::new();
  code.extend(lddw_data_reg());
  for i in 0..SPILLS {
    code.push(Insn::stx_dw(10, 1, -((i as i16) + 1) * 8));
  }
  code.push(Insn::ldx_dw(0, 10, -8)); // fill from slot 1 — tracked
  code.push(Insn::ldx_dw(2, 0, 0)); // deref
  code.push(Insn::ldx_dw(0, 10, -((SPILLS as i16) * 8))); // fill from slot 40 — refused
  code.push(Insn::ldx_dw(2, 0, 0)); // deref
  code.push(Insn::exit());

  let code_bytes: Vec<u8> = code.iter().flat_map(|i| i.value.to_le_bytes()).collect();
  let hints = analyze_section(&code_bytes, DATA_LO, DATA_HI).hints;
  // The deref of the tracked fill is confidently a data-region access...
  assert_eq!(
    hints[2 + SPILLS + 1],
    crate::region_analysis::REGION_DATA,
    "a spill within the cap must recover a confident region hint"
  );
  // ...the deref of the refused fill falls back to the dual-region probe.
  assert_eq!(
    hints[2 + SPILLS + 3],
    crate::region_analysis::REGION_UNKNOWN,
    "a spill beyond the cap must degrade to the UNKNOWN fallback"
  );
}

#[test]
#[tracing_test::traced_test]
fn reaching_the_cap_logs_one_warning() {
  let mut code = Vec::new();
  code.extend(lddw_data_reg());
  for i in 0..SPILLS {
    code.push(Insn::stx_dw(10, 1, -((i as i16) + 1) * 8));
  }
  code.push(Insn::exit());

  let code_bytes: Vec<u8> = code.iter().flat_map(|i| i.value.to_le_bytes()).collect();
  let _ = analyze_section(&code_bytes, DATA_LO, DATA_HI);

  logs_assert(|lines| {
    let warnings = lines
      .iter()
      .filter(|line| line.contains("region analysis spill-slot tracking cap reached"))
      .count();
    if warnings == 1 {
      Ok(())
    } else {
      Err(format!(
        "expected exactly one spill-cap warning, got {warnings}"
      ))
    }
  });
}

#[tokio::test]
async fn spills_beyond_the_cap_still_run_correctly() {
  // The same shape through the real loader: spill a data pointer 40 times,
  // reload the refused slot, and deref it. The runtime dual-region probe
  // backstops the missing hint, so the program returns the rodata value.
  const RODATA: [u8; 8] = 0x1122_3344_5566_7788u64.to_le_bytes();

  let mut code = Vec::new();
  code.extend(Insn::lddw_data(1, 0)); // relocated data-region pointer
  for i in 0..SPILLS {
    code.push(Insn::stx_dw(10, 1, -((i as i16) + 1) * 8));
  }
  code.push(Insn::ldx_dw(0, 10, -((SPILLS as i16) * 8))); // fill from the refused slot
  code.push(Insn::ldx_dw(0, 0, 0)); // deref through the probe
  code.push(Insn::exit());

  let result = run_raw(&code, &RODATA, &[], false).await;
  assert!(
    matches!(result, Ok(v) if v == 0x1122_3344_5566_7788u64 as i64),
    "a program spilling past the cap must still round-trip its pointer; got {result:?}"
  );
}

#[test]
fn invalidation_wins_at_joins() {
  // A spill, then a join where one path invalidates all slots (an unpinnable
  // store) and the other does not. The invalidated path's Unknown must win
  // the meet: pointer-equal maps are NOT semantically equal when the
  // invalidation epochs differ. (Regression: a ptr_eq fast path in the meet
  // skipped this and let the stale provenance survive, emitting a confident
  // DATA hint for a spill the program had invalidated.)
  let mut code = Vec::new();
  code.extend(lddw_data_reg());
  code.push(Insn::stx_dw(10, 1, -8)); // spill the data pointer
  code.push(Insn::raw(0x15, 0, 0, 1, 0)); // jeq r0, 0, +1: path B, else path A
  code.push(Insn::stx_dw(0, 0, 0)); // path A: unpinnable store -> epoch bump
  code.push(Insn::ldx_dw(0, 10, -8)); // join: fill the spill
  code.push(Insn::ldx_dw(2, 0, 0)); // deref
  code.push(Insn::exit());

  let code_bytes: Vec<u8> = code.iter().flat_map(|i| i.value.to_le_bytes()).collect();
  let hints = analyze_section(&code_bytes, DATA_LO, DATA_HI).hints;
  assert_eq!(
    hints[6],
    crate::region_analysis::REGION_UNKNOWN,
    "an invalidated spill must not recover a confident region hint"
  );
}

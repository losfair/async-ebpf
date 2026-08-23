//! Ceilings on how much work one ELF may ask the loader to do.
//!
//! The instruction limit is enforced per code section, and the code-size limit
//! bounds JIT output, which lazy compilation means is never reached at load. So
//! neither of them bounds the *object*: section headers are 64 bytes, nothing
//! in ELF requires two of them to describe disjoint bytes, and every code
//! section is independently walked by two analyses and a translator whose
//! results are all retained. A few hundred extra headers pointed at one code
//! blob therefore bought hundreds of full analysis passes for ~67 bytes apiece,
//! and a 667 KB object cost gigabytes of resident memory and tens of seconds on
//! the thread that called `load`.
//!
//! These are the limits, tested at the loader's front door.

use crate::test::raw_elf::{build_elf, duplicate_code_section_header, load_raw_elf, Insn};

fn minimal_program() -> Vec<Insn> {
  vec![Insn::mov64_imm(0, 0), Insn::exit()]
}

#[test]
fn the_baseline_object_still_loads() {
  // The limits below are only meaningful if the shape they bound is otherwise
  // accepted, so pin that first.
  let elf = build_elf(&minimal_program(), &[0u8; 16]);
  load_raw_elf(&elf).expect("a single-section object loads");
}

#[test]
fn two_code_sections_describing_the_same_bytes_are_refused() {
  let elf = build_elf(&minimal_program(), &[0u8; 16]);
  let elf = duplicate_code_section_header(&elf, 1);

  let err = load_raw_elf(&elf).expect_err("overlapping code sections must not load");
  let err = format!("{err:?}");
  assert!(
    err.contains("overlaps another code section"),
    "unexpected load error: {err}"
  );
}

#[test]
fn a_storm_of_duplicate_code_section_headers_is_refused_cheaply() {
  // The shape of the original denial of service: one code blob, many headers.
  // Each copy used to buy a `validate_local_call_graph`, an `analyze_functions`
  // and a retained `Translator`; the load now fails on the first duplicate,
  // before any of that runs even once more.
  let elf = build_elf(&minimal_program(), &[0u8; 16]);
  let elf = duplicate_code_section_header(&elf, 4096);

  let started = std::time::Instant::now();
  let err = load_raw_elf(&elf).expect_err("a header storm must not load");
  let elapsed = started.elapsed();

  let err = format!("{err:?}");
  assert!(
    err.contains("overlaps another code section") || err.contains("too many code sections"),
    "unexpected load error: {err}"
  );
  // Generous by three orders of magnitude against the ~40s the unbounded
  // version took for half this many headers: this is here to catch a
  // regression to per-header work, not to measure anything.
  assert!(
    elapsed < std::time::Duration::from_secs(5),
    "rejecting a header storm took {elapsed:?}, which suggests per-header work"
  );
}

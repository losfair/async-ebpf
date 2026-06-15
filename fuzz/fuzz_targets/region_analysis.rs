#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../src/harness.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
  harness::run_region_analysis_case(data);
});

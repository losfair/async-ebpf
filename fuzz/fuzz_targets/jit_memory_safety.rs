#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../src/harness.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
  harness::run_memory_safety_case(data);
});

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../src/harness.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
  harness::run_host_pointer_escape_case(data);
});

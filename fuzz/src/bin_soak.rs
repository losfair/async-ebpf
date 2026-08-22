//! Runs the fuzz harness over pseudorandom inputs on a stable toolchain.
//!
//! The cargo-fuzz targets need nightly and a sanitizer runtime, which is not
//! always to hand; this drives the same cases with a deterministic generator so
//! a change to the JIT can be soaked anywhere. It is a complement to fuzzing,
//! not a replacement: there is no coverage feedback and no AddressSanitizer, so
//! it catches what crashes, faults, or lets a host pointer escape.
//!
//! Usage: `cargo run --release --bin soak -- [cases] [seed]`
#[path = "harness.rs"]
mod harness;

fn main() {
  let iters: u64 = std::env::args().nth(1).and_then(|x| x.parse().ok()).unwrap_or(20000);
  let mut state: u64 = std::env::args().nth(2).and_then(|x| x.parse().ok()).unwrap_or(0x243f6a8885a308d3);
  let mut buf = Vec::with_capacity(256);
  for i in 0..iters {
    // xorshift64*
    state ^= state >> 12; state ^= state << 25; state ^= state >> 27;
    let r = state.wrapping_mul(0x2545F4914F6CDD1D);
    let len = 8 + (r % 200) as usize;
    buf.clear();
    let mut s = r;
    for _ in 0..len {
      s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
      buf.push((s.wrapping_mul(0x2545F4914F6CDD1D) >> 33) as u8);
    }
    harness::run_memory_safety_case(&buf);
    harness::run_host_pointer_escape_case(&buf);
    harness::run_region_analysis_case(&buf);
    if i % 2000 == 0 {
      eprintln!("soak: {i}/{iters}");
    }
  }
  println!("soak: {iters} cases, no crash and no host-pointer escape");
}

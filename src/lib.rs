#[cfg(not(all(
  any(target_os = "linux", target_os = "openbsd"),
  any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!("only x86_64/aarch64 Linux and OpenBSD are supported");

mod coroutine;
/// Error types returned by the runtime.
pub mod error;
mod function_analysis;
/// Helper definitions and utilities for eBPF programs.
pub mod helpers;
mod linker;
mod pointer_cage;
/// Program loading and execution APIs.
pub mod program;
mod region_analysis;
mod ubpf;
mod util;

#[cfg(test)]
mod test;

#[cfg(any(test, feature = "testing"))]
/// Test helpers and fixtures for exercising the runtime.
pub mod test_util;

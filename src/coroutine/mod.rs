//! Stackful coroutine implementation used to isolate JIT execution.
//!
//! This is intentionally private and only supports the Unix architectures
//! supported by async-ebpf. The low-level switching design is adapted from
//! corosensei 0.1.4 (Apache-2.0/MIT), with a reduced platform surface and
//! OpenBSD stack/BTI support maintained here. The inherited Darwin support is
//! also used by the macOS runtime target.

#![allow(dead_code, unexpected_cfgs)]

// Must come first because it defines macros used by the architecture modules.
mod arch;
mod runtime;
pub mod stack;
mod trap;
mod unwind;
mod util;

pub use runtime::{Coroutine, CoroutineResult, ScopedCoroutine, Yielder};

//! Re-export of the vendored uBPF C bindings.
//!
//! Kept as a shim so the FFI call sites in `program.rs` are untouched while the
//! Rust JIT backend is brought up next to the C one. Once `crate::jit` is the
//! default backend this module becomes `#[cfg(feature = "oracle")]` and then
//! goes away entirely.
pub use ubpf_sys::*;

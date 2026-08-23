//! Raw bindings to the vendored uBPF C runtime.
//!
//! This crate exists to be an *oracle*, not a dependency. The Rust JIT backend
//! in `async-ebpf` is a port of the C in `vendor/ubpf`, and through the
//! migration the two are required to emit byte-identical machine code. Keeping
//! the C reachable from tests is what makes that requirement checkable.
//!
//! Nothing in the default build of `async-ebpf` links against this crate; it is
//! a dev-dependency behind the `oracle` feature.
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unnecessary_transmutes)]

include!(concat!(env!("OUT_DIR"), "/ubpf_bindings.rs"));

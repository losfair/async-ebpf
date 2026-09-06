//! The verified core: code the runtime runs *and* the Lean proofs describe.
//!
//! This directory is compiled twice. The runtime includes it as
//! `crate::verified` and executes it: `jit::isa` re-exports [`isa`]'s types,
//! `jit::validate` calls [`validate::validate`] and only renders the
//! rejection, `function_analysis` calls [`layout::partition`] likewise, and
//! `program` and `region_analysis` compute the guest stack's frame geometry
//! with [`stack`]. `lean/verified` is a Cargo manifest whose library *is* this
//! directory, built by Charon and translated by Aeneas into
//! `lean/AsyncEbpf/AsyncEbpfVerified.lean`, which the theorems under `lean/`
//! are about. So the code the proofs describe is the code that runs, not a
//! restatement of it, and every analysis pass that gains a proof moves in here.
//!
//! The `extract` feature is on only for the Charon build. Everything behind
//! `cfg(not(feature = "extract"))` is runtime convenience — the wire codec, the
//! derives the runtime prints and hashes with — that Aeneas need not see.
//!
//! Style constraints, all of them for the translator's sake, and each one a
//! lesson (see `lean/README.md`): no closures, no iterator chains, no `String`,
//! no wrapping arithmetic, no `==` on enums, one loop per function, and every
//! early return in the function that owns the loop.
#![allow(
  clippy::question_mark,
  clippy::ptr_arg,
  clippy::match_like_matches_macro
)]

pub mod isa;
pub mod layout;
pub mod stack;
pub mod validate;

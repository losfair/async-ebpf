//! The two JIT backends.
//!
//! Each owns its own `translate_range` port. They share [`super::patch`] but not
//! a driver loop: the C's two loops share only their preamble checks, and arm64
//! runs a barrier pre-pass x86_64 does not have. Unifying them would be a
//! refactor performed during a port required to be byte-identical, and the
//! arm64 jump-sentinel bug already lived in exactly that gap.

use super::{Target, TranslateError, TranslationInputs, Translator};

pub mod aarch64;
pub mod x86_64;

/// Translates `inputs.start_pc .. inputs.end_pc` into `buffer`.
pub fn translate(
  t: &Translator,
  inputs: &TranslationInputs<'_>,
  buffer: &mut [u8],
) -> Result<usize, TranslateError> {
  match t.config().target {
    Target::X86_64 => x86_64::translate_range(t, inputs, buffer),
    Target::Aarch64 => aarch64::translate_range(t, inputs, buffer),
  }
}

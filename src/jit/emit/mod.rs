//! The two JIT backends.
//!
//! Each owns its own `translate_range`. They share [`super::patch`] — the code
//! buffer, the fixup tables, the access-group state — but not a driver loop:
//! past the preamble checks the two have little in common, and aarch64 runs a
//! barrier pre-pass x86_64 does not have. See [`super::patch`] for why they are
//! still separate.

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

//! The two JIT backends.
//!
//! Each owns its own `translate_range`, and the two are built differently.
//! x86_64 is three layers — the decisions in `verified::x64_lower`, each
//! macro's native sequence in `verified::x64_expand`, and the bytes in
//! [`x86_64`] — so that `lean/AsyncEbpf/X64/` can be about the code generation
//! that runs; see `docs/jit-memory-safety.md`. aarch64 still writes bytes from
//! the instruction it is translating, through the shared buffer and fixup
//! tables in [`super::patch`]. Giving it the same split is the natural next
//! step.

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

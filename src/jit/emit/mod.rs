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

/// Checks that `[start_pc, end_pc)` is exactly one local function.
///
/// A buffer holds one function and nothing else. The prologue is emitted once,
/// before the first instruction, and every `EXIT` pops the frame it reserved —
/// so a range starting mid-function would return through a frame it never
/// pushed, and a range holding *two* functions would enter the second without
/// its prologue and leave the host stack unbalanced when it returned.
///
/// uBPF translated whole programs and carried the machinery for the second
/// case: a prologue emitted at every function entry the range crossed, and a
/// branch around it for the entry a preceding instruction could fall into.
/// Nothing here compiles more than one function at a time, so both are gone and
/// this is what keeps them gone.
///
/// Shared so that the two backends refuse the same ranges in the same words;
/// callers surface these strings verbatim and tests match on them.
pub fn check_function_range(
  t: &Translator,
  start_pc: usize,
  end_pc: usize,
) -> Result<(), TranslateError> {
  let num_insts = t.insns().len();

  if end_pc > num_insts || start_pc >= end_pc {
    return Err(TranslateError::Failed(format!(
      "Invalid function range [{start_pc}, {end_pc})"
    )));
  }
  if !(start_pc == 0 || t.is_local_func_entry(start_pc)) {
    return Err(TranslateError::Failed(format!(
      "Function range start {start_pc} is not a local function entry"
    )));
  }
  if end_pc != num_insts && !t.is_local_func_entry(end_pc) {
    return Err(TranslateError::Failed(format!(
      "Function range end {end_pc} is not a local function boundary"
    )));
  }
  // The range may not *contain* another function's entry: that is the
  // whole-program shape, and nothing emits the second prologue any more.
  for pc in start_pc + 1..end_pc {
    if t.is_local_func_entry(pc) {
      return Err(TranslateError::Failed(format!(
        "Function range [{start_pc}, {end_pc}) spans more than one local \
         function; {pc} begins another"
      )));
    }
  }
  Ok(())
}

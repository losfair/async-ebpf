//! STUB - replaced by the x86_64 emitter port.
use crate::jit::{TranslateError, TranslationInputs, Translator};
pub fn translate_range(
  _t: &Translator,
  _inputs: &TranslationInputs<'_>,
  _buffer: &mut [u8],
) -> Result<usize, TranslateError> {
  todo!("x86_64 emitter")
}

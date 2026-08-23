//! STUB - replaced by the aarch64 emitter port.
use crate::jit::{TranslateError, TranslationInputs, Translator};
pub fn translate_range(
  _t: &Translator,
  _inputs: &TranslationInputs<'_>,
  _buffer: &mut [u8],
) -> Result<usize, TranslateError> {
  todo!("aarch64 emitter")
}

use std::sync::Arc;

use elf::{relocation::Rel, ParseError};
use thiserror::Error as ThisError;

#[derive(ThisError, Debug, Clone)]
#[error("ebpf runtime error: {0}")]
/// Public error wrapper for runtime failures.
pub struct Error(pub(crate) RuntimeError);

impl Error {
  /// Returns whether an invocation failed because it conflicted with a live
  /// data-access lease.
  pub fn is_program_busy(&self) -> bool {
    matches!(self.0, RuntimeError::ProgramBusy)
  }
}

#[derive(ThisError, Debug, Clone)]
pub(crate) enum RuntimeError {
  #[error("invalid argument: {0}")]
  InvalidArgument(&'static str),

  #[error("invalid argument: {0}")]
  InvalidArgumentOwned(String),

  #[error("platform error: {0}")]
  PlatformError(&'static str),

  #[error("helper returned error: {0}")]
  HelperError(&'static str),

  #[error("helper returned error during async invocation: {0}")]
  AsyncHelperError(&'static str),

  #[error("linker returned error: {0}")]
  Linker(LinkerError),

  #[error("memory fault at virtual address {0:#x}")]
  MemoryFault(usize),

  #[error("local call stack exhausted")]
  StackExhausted,

  #[error("program data is already in use by a conflicting invocation")]
  ProgramBusy,
}

#[derive(ThisError, Debug, Clone)]
pub(crate) enum LinkerError {
  #[error("invalid elf image: {0}")]
  InvalidElf(&'static str),

  #[error("bad relocation: {0} ({1:?})")]
  Reloc(String, Rel),

  #[error("elf parse failed: {0}")]
  Parse(Arc<ParseError>),
}

impl From<ParseError> for LinkerError {
  fn from(e: ParseError) -> Self {
    Self::Parse(Arc::new(e))
  }
}

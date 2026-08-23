//! TEMPORARY PERMISSIVE STUB - being replaced by the port of `validate()` and
//! `ubpf_instruction_valid.c`.
//!
//! It accepts everything so that the emitter work can use the differential
//! harness, which goes through `Translator::load`. Callers must not rely on it.
use super::{isa::Insn, Config};

pub fn validate(_config: &Config, _insns: &[Insn]) -> Result<(), String> {
  Ok(())
}

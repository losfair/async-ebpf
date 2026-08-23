//! Per-local-function guest stack usage.
//!
//! Every local function is charged the same fixed frame,
//! [`crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE`], regardless of what it
//! actually uses. Nothing inspects the instruction stream, so this file is
//! almost entirely a constant behind a lookup.
//!
//! That the answer is uniform is what makes the runtime's stack budget a matter
//! of arithmetic rather than analysis: the deepest accepted call chain consumes
//! exactly `MAX_LOCAL_CALL_DEPTH` frames, which is how `program.rs` sizes the
//! guest stack window and how it justifies the unchecked frame-access window
//! below `R10`. A per-function calculation would make the
//! frame budget depend on which functions are on the stack, and both of those
//! arguments would have to be redone.
//!
//! The 16-byte alignment check below is load-bearing: the generated prologue
//! subtracts this size from the native stack pointer, so an unaligned value
//! would show up as a misaligned native stack in generated code rather than as
//! a diagnostic here.

use super::abi;
use super::isa::Insn;

/// Stack usage lookup for a program's local functions.
///
/// Kept as a type rather than a bare constant so that reinstating a per-function
/// calculation later is a change to one file. It holds no state today.
#[derive(Debug, Default)]
pub struct StackUsage {
  num_insns: usize,
}

impl StackUsage {
  pub fn new(num_insns: usize) -> Self {
    Self { num_insns }
  }

  /// Guest stack bytes charged to the local function beginning at `pc`.
  ///
  /// The same for every function; `pc` and `insns` are taken so that a
  /// per-function calculation would not change the signature.
  pub fn for_function(&self, _insns: &[Insn], pc: usize) -> u16 {
    debug_assert!(
      pc < self.num_insns,
      "stack usage asked for pc {pc} outside a program of {} instructions",
      self.num_insns
    );
    abi::LOCAL_FUNCTION_STACK_SIZE
  }
}

/// The generated prologue subtracts this from the native stack pointer, which
/// must stay 16-byte aligned on both supported architectures.
const _: () = {
  assert!(
    abi::LOCAL_FUNCTION_STACK_SIZE % 16 == 0,
    "local function stack size is not 16-byte aligned; the generated prologue \
     would misalign the native stack"
  );
};

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn every_local_function_is_charged_one_fixed_frame() {
    let usage = StackUsage::new(4);
    for pc in 0..4 {
      assert_eq!(usage.for_function(&[], pc), 4096);
    }
  }
}

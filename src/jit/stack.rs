//! Per-local-function guest stack usage.
//!
//! Every local function is charged the configured fixed frame, regardless of
//! what it actually uses. Nothing inspects the instruction stream, so this
//! file is almost entirely a configured value behind a lookup.
//!
//! That the answer is uniform is what makes the runtime's stack budget a matter
//! of arithmetic rather than call-graph analysis. Before every local call the
//! backend can prove that subtracting this charge still leaves one complete
//! unchecked frame-access window below the callee's `R10`; cycles need no
//! special case. A per-function calculation would make that runtime check
//! depend on which functions are on the dynamic stack.
//!
use super::isa::Insn;

/// Stack usage lookup for a program's local functions.
///
/// Kept as a type rather than a bare constant so that reinstating a per-function
/// calculation later is a change to one file.
#[derive(Debug)]
pub struct StackUsage {
  num_insns: usize,
  frame_size: u16,
}

impl StackUsage {
  pub fn new(num_insns: usize, frame_size: u16) -> Self {
    Self {
      num_insns,
      frame_size,
    }
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
    self.frame_size
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn every_local_function_is_charged_one_fixed_frame() {
    let usage = StackUsage::new(4, 768);
    for pc in 0..4 {
      assert_eq!(usage.for_function(&[], pc), 768);
    }
  }
}

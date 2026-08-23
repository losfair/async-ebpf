//! Per-local-function guest stack usage.
//!
//! # Why this is so much smaller than the C
//!
//! uBPF supports a custom stack-usage calculator registered through
//! `ubpf_register_stack_usage_calculator`, and carries a three-state memo table
//! (`UNKNOWN` / `CUSTOM` / `DEFAULT`) per instruction slot to cache its answers.
//!
//! `async-ebpf` never registers one. That symbol is not among the twenty-one it
//! reaches, so `vm->stack_usage_calculator` is always NULL, every entry resolves
//! to `UBPF_STACK_USAGE_DEFAULT`, and `ubpf_stack_usage_for_local_func` returns
//! `UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE` unconditionally. The memo table, the
//! three-state enum and the calculator indirection are all dead weight behind a
//! constant.
//!
//! The one piece of live behaviour is the 16-byte alignment check, which is
//! retained: it is a load-bearing invariant for the generated prologue, and if
//! [`crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE`] were ever changed to something
//! unaligned the failure would otherwise be a misaligned native stack rather
//! than a diagnostic.

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
  /// Mirrors `ubpf_stack_usage_for_local_func` under the configuration
  /// `async-ebpf` actually uses.
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

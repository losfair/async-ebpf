//! What guest code can observe in its own registers.
//!
//! The runtime hands control to JIT-compiled guest code with host state still
//! in machine registers unless the entry trampoline clears it. Nothing rejects
//! a read of a register that was never assigned, so a program that simply reads
//! one sees whatever was left there.

use crate::test::raw_elf::{run_raw, Insn};

/// Every eBPF register except `r1` (the context) and `r10` (the frame pointer)
/// must read zero at entry.
///
/// The backend maps several of them onto native registers the entry path uses:
/// the entrypoint's own native code address, the guest memory descriptor, the
/// randomized guest stack bounds, and the Rust caller's callee-saved registers.
/// Leaking any of those hands the guest host addresses and the pointer cage's
/// layout.
#[tokio::test]
#[tracing_test::traced_test]
async fn entry_registers_are_scrubbed() {
  const PROBED: [u8; 9] = [0, 2, 3, 4, 5, 6, 7, 8, 9];

  // Spill before computing anything: any instruction with a destination would
  // destroy the value under test.
  let mut code = Vec::new();
  for (index, reg) in PROBED.iter().enumerate() {
    code.push(Insn::stx_dw(10, *reg, -8 - 8 * (index as i16)));
  }
  code.push(Insn::mov64_imm(0, 0));
  for index in 0..PROBED.len() {
    code.push(Insn::ldx_dw(1, 10, -8 - 8 * (index as i16)));
    code.push(Insn::or64_reg(0, 1));
  }
  code.push(Insn::exit());

  let observed = run_raw(&code, &[], &[], true).await.unwrap();
  assert_eq!(
    observed, 0,
    "registers {PROBED:?} must all be zero at entry"
  );
}

/// The scrub must leave the two registers the entry ABI does define.
#[tokio::test]
#[tracing_test::traced_test]
async fn entry_context_and_frame_pointer_survive_the_scrub() {
  let code = vec![
    Insn::ldx_dw(0, 1, 0),   // r0 = *(u64 *) ctx
    Insn::stx_dw(10, 0, -8), // round it through the guest stack
    Insn::ldx_dw(0, 10, -8),
    Insn::exit(),
  ];
  let calldata = 0x5eedu64.to_le_bytes();
  assert_eq!(run_raw(&code, &[], &calldata, true).await.unwrap(), 0x5eed);
}

/// A local call must not leave a host address in `r0`.
///
/// Local calls are resolved lazily through a host callback, and its return
/// value — the callee's native code address — arrives in the host ABI return
/// register, which the backend maps to eBPF `r0`. The call sequence preserves
/// `r0` across the resolver instead, matching a direct local call.
#[tokio::test]
#[tracing_test::traced_test]
async fn local_call_preserves_r0() {
  let code = vec![
    Insn::mov64_imm(0, 0x5eed),
    Insn::call_local(1), // callee at pc 3
    Insn::exit(),        // returns whatever the callee left in r0
    Insn::exit(),        // callee: does not touch r0
  ];
  assert_eq!(run_raw(&code, &[], &[], true).await.unwrap(), 0x5eed);
}

/// The same, observed from inside the callee rather than after it returns.
#[tokio::test]
#[tracing_test::traced_test]
async fn local_callee_observes_the_callers_r0() {
  let code = vec![
    Insn::mov64_imm(0, 0x5eed),
    Insn::call_local(1), // callee at pc 3
    Insn::exit(),
    Insn::mov64_reg(6, 0), // callee: capture r0 as it arrives
    Insn::mov64_reg(0, 6),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&code, &[], &[], true).await.unwrap(), 0x5eed);
}

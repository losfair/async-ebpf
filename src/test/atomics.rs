//! Region routing across atomic instructions.

use crate::{
  error::{Error, RuntimeError},
  test::raw_elf::{run_raw, Insn},
};

const EBPF_OP_ATOMIC_STORE: u8 = 0xdb;
const EBPF_ATOMIC_CMPXCHG_FETCH: i32 = 0xf1;

const RODATA: [u8; 8] = 0x1122334455667788u64.to_le_bytes();

/// Builds `code` around a `cmpxchg` whose target slot holds a stack address, so
/// the instruction leaves that stack address in `r0`.
fn cmpxchg_program(deref: Insn) -> Vec<Insn> {
  let mut code = Vec::new();
  code.extend(Insn::lddw_data(0, 0)); // r0 = &rodata
  code.extend(Insn::lddw_data(6, 0)); // r6 = &rodata
  code.push(Insn::mov64_reg(3, 10));
  code.push(Insn::add64_imm(3, -256)); // r3 = a stack address
  code.push(Insn::stx_dw(10, 3, -16)); // *(u64 *)(r10 - 16) = r3
  code.push(Insn::mov64_imm(2, 0));
  // r0 != *(u64 *)(r10 - 16), so the compare fails and r0 takes the old value.
  code.push(Insn::raw(
    EBPF_OP_ATOMIC_STORE,
    10,
    2,
    -16,
    EBPF_ATOMIC_CMPXCHG_FETCH,
  ));
  code.push(deref);
  code.push(Insn::exit());
  code
}

/// `BPF_ATOMIC | CMPXCHG` writes the previous memory contents into `r0`, so a
/// data pointer materialized there beforehand does not survive it.
///
/// x86-64 lowers the instruction to `lock cmpxchg`, whose comparand is `RAX`;
/// the arm64 backend routes the result to `map_register(0)` explicitly. The
/// guest chooses the memory contents, so the analysis must not keep routing
/// `r0` to the region its old value pointed at.
#[tokio::test]
#[tracing_test::traced_test]
async fn cmpxchg_result_is_not_routed_to_the_stale_region() {
  // r0 now carries no provenance, so the dereference takes the dual-region
  // probe and resolves against the stack address the cmpxchg actually left.
  let code = cmpxchg_program(Insn::ldx_b(0, 0, 0));
  assert_eq!(run_raw(&code, &RODATA, &[], false).await.unwrap(), 0x8e);

  // And strict mode reports the access as unroutable rather than accepting it
  // and faulting at run time.
  match run_raw(&code, &RODATA, &[], true).await {
    Err(Error(RuntimeError::InvalidArgumentOwned(msg)))
      if msg.contains("static region analysis") => {}
    other => panic!("expected static region rejection, got {other:?}"),
  }
}

/// The rule is narrow: `cmpxchg` writes only `r0`, so a data pointer in another
/// register stays statically routed across it.
#[tokio::test]
#[tracing_test::traced_test]
async fn cmpxchg_preserves_other_registers() {
  let code = cmpxchg_program(Insn::ldx_b(0, 6, 0));
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 0x88);
}

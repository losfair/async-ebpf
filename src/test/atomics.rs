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

const EBPF_OP_ATOMIC32_STORE: u8 = 0xc3;
const EBPF_ATOMIC_ADD_FETCH: i32 = 0x01;
const EBPF_ATOMIC_XCHG_FETCH: i32 = 0xe1;

/// Every way of writing `R10` must be refused at load.
///
/// The frame pointer is read-only, and Tier F frame addressing depends on that:
/// it drops the per-access bounds check for `[r10 + k]` and leans on a
/// window argument instead, so a guest-chosen `R10` would be an arbitrary host
/// access rather than a spurious fault. Direct writes were always refused, but a
/// fetching atomic writes its *source* register and both validation layers used
/// to bound that at `BPF_REG_10` - the x86-64 backend really did emit
/// `mov <src>, rax` into R15.
#[tokio::test]
async fn the_frame_pointer_cannot_be_written() {
  // (description, program) - each writes R10, and none may load.
  let cases: Vec<(&str, Vec<Insn>)> = vec![
    (
      "atomic64 fetch_add",
      vec![
        Insn::raw(EBPF_OP_ATOMIC_STORE, 10, 10, -16, EBPF_ATOMIC_ADD_FETCH),
        Insn::exit(),
      ],
    ),
    (
      "atomic64 xchg",
      vec![
        Insn::raw(EBPF_OP_ATOMIC_STORE, 10, 10, -16, EBPF_ATOMIC_XCHG_FETCH),
        Insn::exit(),
      ],
    ),
    (
      "atomic32 fetch_add",
      vec![
        Insn::raw(EBPF_OP_ATOMIC32_STORE, 10, 10, -16, EBPF_ATOMIC_ADD_FETCH),
        Insn::exit(),
      ],
    ),
    (
      "atomic64 cmpxchg",
      vec![
        Insn::raw(EBPF_OP_ATOMIC_STORE, 10, 10, -16, EBPF_ATOMIC_CMPXCHG_FETCH),
        Insn::exit(),
      ],
    ),
    ("mov64 reg", vec![Insn::mov64_reg(10, 1), Insn::exit()]),
    ("mov64 imm", vec![Insn::mov64_imm(10, 42), Insn::exit()]),
    ("add64 imm", vec![Insn::add64_imm(10, 8), Insn::exit()]),
    ("ldxdw", vec![Insn::ldx_dw(10, 10, -16), Insn::exit()]),
  ];

  for (what, code) in cases {
    let result = run_raw(&code, &RODATA, &[], false).await;
    assert!(
      result.is_err(),
      "{what} wrote the frame pointer and was accepted: {result:?}"
    );
  }
}

/// The rejection is narrow: an atomic on an ordinary register still loads and
/// runs, and the frame pointer is still usable as a memory base.
#[tokio::test]
async fn atomics_on_ordinary_registers_still_load() {
  let code = vec![
    Insn::mov64_imm(2, 7),
    Insn::stx_dw(10, 2, -16),
    Insn::mov64_imm(3, 5),
    // r3 = old(*(u64 *)(r10 - 16)); *(u64 *)(r10 - 16) += 5
    Insn::raw(EBPF_OP_ATOMIC_STORE, 10, 3, -16, EBPF_ATOMIC_ADD_FETCH),
    Insn::ldx_dw(0, 10, -16),
    Insn::exit(),
  ];
  assert_eq!(run_raw(&code, &RODATA, &[], true).await.unwrap(), 12);
}

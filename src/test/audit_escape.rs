//! Adversarial probes written during the sandbox-escape audit of the
//! frame-addressing / access-grouping change. Not part of the feature's own
//! test suite; each one is an attempt to reach outside the two guest regions or
//! to observe a host address.

use crate::{
  error::{Error, RuntimeError},
  program::MAX_CALLDATA_SIZE,
  test::raw_elf::{run_raw, Insn},
};

const RODATA: [u8; 16] = [
  0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
];

const EBPF_OP_STDW: u8 = 0x7a;
const EBPF_OP_SUB64_REG: u8 = 0x1f;
const EBPF_OP_ATOMIC_STORE: u8 = 0xdb;
const EBPF_OP_ATOMIC32_STORE: u8 = 0xc3;
const EBPF_OP_LDDW: u8 = 0x18;

fn st_dw(dst: u8, offset: i16, imm: i32) -> Insn {
  Insn::raw(EBPF_OP_STDW, dst, 0, offset, imm)
}

fn sub64_reg(dst: u8, src: u8) -> Insn {
  Insn::raw(EBPF_OP_SUB64_REG, dst, src, 0, 0)
}

/// The opcode filter table names `R10` as a legal destination for `lddw`, so
/// the only thing refusing `lddw r10, imm64` is `validate`'s `store` rule. If
/// it ever stopped doing so the guest would overwrite the native frame pointer
/// outright and every frame access would become an arbitrary host access.
#[tokio::test]
async fn lddw_into_the_frame_pointer_is_refused() {
  let code = vec![
    Insn::raw(EBPF_OP_LDDW, 10, 0, 0, 0x4141_4141u32 as i32),
    Insn::raw(0x00, 0, 0, 0, 0x4141_4141u32 as i32),
    Insn::ldx_dw(0, 10, -8),
    Insn::exit(),
  ];
  let result = run_raw(&code, &RODATA, &[], false).await;
  assert!(result.is_err(), "lddw r10 was accepted: {result:?}");
}

/// A conditional jump reads its *destination* as a value, and the opcode filter
/// names `R10` as a legal destination for every one of them. Only `validate`'s
/// `store` rule refuses it - the pre-switch rewrite in `translate_range`
/// materializes the guest frame pointer for a `src` operand and never for a
/// `dst` one, so `if r10 == imm goto ...` would compare the *native* frame
/// pointer and leak a host address to the guest one bit at a time.
#[tokio::test]
async fn a_conditional_jump_cannot_name_the_frame_pointer_as_its_destination() {
  // (name, opcode) over the JMP and JMP32 encodings, immediate and register.
  let forms: &[(&str, u8)] = &[
    ("jeq imm", 0x15),
    ("jgt imm", 0x25),
    ("jge imm", 0x35),
    ("jset imm", 0x45),
    ("jne imm", 0x55),
    ("jeq reg", 0x1d),
    ("jgt reg", 0x2d),
    ("jeq32 imm", 0x16),
    ("jgt32 imm", 0x26),
    ("jeq32 reg", 0x1e),
  ];
  for &(what, opcode) in forms {
    let code = vec![
      Insn::mov64_imm(0, 0),
      Insn::raw(opcode, 10, 1, 1, 0), // if r10 <op> r1/imm goto +1
      Insn::mov64_imm(0, 1),
      Insn::exit(),
    ];
    let result = run_raw(&code, &RODATA, &[], false).await;
    assert!(
      result.is_err(),
      "{what} compared the frame pointer and was accepted: {result:?}"
    );
  }
}

/// A *non-fetching* atomic does not write its source register, but it does copy
/// it into guest memory. Under a native frame base that source is a host
/// pointer, and nothing in `emit_masked_store`'s frame-pointer recovery covers
/// the atomic path - so the only thing between the guest and a leaked host
/// address is the opcode filter's `source_upper_bound`.
#[tokio::test]
async fn non_fetching_atomics_cannot_name_the_frame_pointer_as_a_source() {
  // (name, opcode, imm) for every non-fetch atomic form the filter enumerates.
  let forms: &[(&str, u8, i32)] = &[
    ("atomic64 add", EBPF_OP_ATOMIC_STORE, 0x00),
    ("atomic64 or", EBPF_OP_ATOMIC_STORE, 0x40),
    ("atomic64 and", EBPF_OP_ATOMIC_STORE, 0x50),
    ("atomic64 xor", EBPF_OP_ATOMIC_STORE, 0xa0),
    ("atomic32 add", EBPF_OP_ATOMIC32_STORE, 0x00),
    ("atomic32 or", EBPF_OP_ATOMIC32_STORE, 0x40),
    ("atomic32 and", EBPF_OP_ATOMIC32_STORE, 0x50),
    ("atomic32 xor", EBPF_OP_ATOMIC32_STORE, 0xa0),
  ];
  for &(what, opcode, imm) in forms {
    let code = vec![
      Insn::mov64_imm(1, 0),
      Insn::stx_dw(10, 1, -16),
      // *(u64 *)(r10 - 16) op= r10
      Insn::raw(opcode, 10, 10, -16, imm),
      Insn::ldx_dw(0, 10, -16),
      Insn::exit(),
    ];
    let result = run_raw(&code, &RODATA, &[], false).await;
    assert!(
      result.is_err(),
      "{what} with R10 as its source was accepted: {result:?}"
    );
  }
}

/// Every syntactic position that reads `R10` as a value has to hand the guest
/// the *guest* frame pointer. `R1` at entry is the calldata pointer, which is
/// `R10` rounded up to the calldata length, so the guest can subtract the two
/// and check the answer is small without knowing either address.
#[tokio::test]
async fn no_reading_of_the_frame_pointer_yields_a_host_address() {
  // r0 = r10 - r1, by four different routes. With no calldata, R1 == R10, so
  // every one of them must be exactly 0.
  let cases: Vec<(&str, Vec<Insn>)> = vec![
    (
      "mov64_reg",
      vec![Insn::mov64_reg(0, 10), sub64_reg(0, 1), Insn::exit()],
    ),
    (
      "sub64_reg directly off r10",
      vec![
        Insn::mov64_reg(0, 1),
        Insn::raw(0x1f, 0, 10, 0, 0), // r0 -= r10
        Insn::raw(0x87, 0, 0, 0, 0),  // neg64 r0  => r10 - r1
        Insn::exit(),
      ],
    ),
    (
      "stored then reloaded",
      vec![
        Insn::stx_dw(10, 10, -16),
        Insn::ldx_dw(0, 10, -16),
        sub64_reg(0, 1),
        Insn::exit(),
      ],
    ),
    (
      "stored through a derived base then reloaded",
      vec![
        Insn::mov64_reg(2, 10),
        Insn::add64_imm(2, -24),
        Insn::stx_dw(2, 10, 0),
        Insn::ldx_dw(0, 10, -24),
        sub64_reg(0, 1),
        Insn::exit(),
      ],
    ),
    (
      "read back through a fetching atomic",
      vec![
        Insn::stx_dw(10, 10, -32),
        Insn::mov64_imm(0, 0),
        // r0 = old(*(u64 *)(r10 - 32)) = the guest frame pointer
        Insn::raw(EBPF_OP_ATOMIC_STORE, 10, 0, -32, 0x01),
        sub64_reg(0, 1),
        Insn::exit(),
      ],
    ),
  ];

  for (what, code) in cases {
    let got = run_raw(&code, &RODATA, &[], false).await;
    assert_eq!(got.as_ref().map(|x| *x).ok(), Some(0), "{what}: {got:?}");
  }
}

/// The frame window's bottom edge, exercised as a *write* at the deepest call
/// depth the loader accepts with the largest calldata a caller may pass. This
/// is the exact corner the frame-window invariant is about: one byte
/// further down is the `PROT_NONE` guard page, and an unchecked store there
/// would take the process out rather than raise a guest fault.
#[tokio::test]
async fn the_deepest_frame_write_lands_inside_the_guest_stack() {
  let mut code = Vec::new();
  for _ in 0..7 {
    code.push(Insn::call_local(1));
    code.push(Insn::exit());
  }
  // Leaf: write and read back the lowest slot the window covers.
  code.push(st_dw(10, -4096, 0x5a));
  code.push(Insn::ldx_dw(0, 10, -4096));
  code.push(Insn::exit());

  for len in [0usize, 1, 7, 8, 511, MAX_CALLDATA_SIZE] {
    let got = run_raw(&code, &RODATA, &vec![0u8; len], true).await;
    assert_eq!(
      got.as_ref().map(|x| *x).ok(),
      Some(0x5a),
      "{len} bytes of calldata: {got:?}"
    );
  }
}

/// A run of accesses off a data-region pointer that also contains a store must
/// not end up writing the read-only region through the group's parked base.
#[tokio::test]
async fn a_group_cannot_launder_a_store_into_the_data_region() {
  let mut code = Vec::new();
  code.extend(Insn::lddw_data(1, 0));
  code.extend([
    Insn::ldx_dw(2, 1, 0),
    Insn::ldx_dw(3, 1, 8),
    st_dw(1, 0, 0xff),
    Insn::mov64_imm(0, 1),
    Insn::exit(),
  ]);
  match run_raw(&code, &RODATA, &[], false).await {
    Err(Error(RuntimeError::MemoryFault(_))) => {}
    other => panic!("a store rode a data-region window: {other:?}"),
  }

  // And the region really is untouched: a fresh program reads it back.
  let mut probe = Vec::new();
  probe.extend(Insn::lddw_data(1, 0));
  probe.extend([Insn::ldx_dw(0, 1, 0), Insn::exit()]);
  assert_eq!(
    run_raw(&probe, &RODATA, &[], true).await.unwrap() as u64,
    u64::from_le_bytes(RODATA[..8].try_into().unwrap())
  );
}

/// Jumping into the middle of a run of accesses must not let the later ones
/// keep using a base that a *narrower* check parked. Both the plan builder and
/// the backend are supposed to close a group at every branch target; this walks
/// the three branch encodings whose target arithmetic differs (backward `JA`,
/// forward conditional, and `JA32`, which carries its target in `imm`).
#[tokio::test]
async fn jumping_into_a_run_of_accesses_does_not_reuse_a_narrow_window() {
  // r6 sits 16 bytes below the top of the guest stack, so a window of 16 bytes
  // fits and one of 4096 does not. If a member ever rode the narrow window at
  // the wide displacement it would store 4 KiB above the top of the stack -
  // into the guard page, which the fault handler does not claim.
  const JA: u8 = 0x05;
  const JA32: u8 = 0x06;
  const JEQ_IMM: u8 = 0x15;

  // Forward conditional jump straight onto the wide run's second access.
  //  0 r6 = r10
  //  1 r6 += -16
  //  2 narrow leader (window 16)
  //  3 narrow member
  //  4 r3 = 0
  //  5 if r3 == 0 goto 7
  //  6 wide leader (window 4096) - skipped
  //  7 wide member - jumped into
  //  8 r0 = 1
  //  9 exit
  let forward = vec![
    Insn::mov64_reg(6, 10),
    Insn::add64_imm(6, -16),
    st_dw(6, 0, 0x1),
    st_dw(6, 8, 0x2),
    Insn::mov64_imm(3, 0),
    Insn::raw(JEQ_IMM, 3, 0, 1, 0),
    st_dw(6, 0, 0x3),
    st_dw(6, 4088, 0x4),
    Insn::mov64_imm(0, 1),
    Insn::exit(),
  ];

  // The same, reached by a backward JA.
  //  0 r6 = r10
  //  1 r6 += -16
  //  2 r3 = 0
  //  3 if r3 == 0 goto 8   (first pass: run the narrow group first)
  //  4 wide leader
  //  5 wide member
  //  6 r0 = 1
  //  7 exit
  //  8 narrow leader
  //  9 narrow member
  // 10 goto 5              (back onto the wide member)
  let backward = vec![
    Insn::mov64_reg(6, 10),
    Insn::add64_imm(6, -16),
    Insn::mov64_imm(3, 0),
    Insn::raw(JEQ_IMM, 3, 0, 4, 0),
    st_dw(6, 0, 0x3),
    st_dw(6, 4088, 0x4),
    Insn::mov64_imm(0, 1),
    Insn::exit(),
    st_dw(6, 0, 0x1),
    st_dw(6, 8, 0x2),
    Insn::raw(JA, 0, 0, -6, 0),
  ];

  // And by JA32, whose target is the 32-bit immediate rather than the offset.
  //  0..3 as above, 4 goto 6, 5 wide leader, 6 wide member
  let gotol = vec![
    Insn::mov64_reg(6, 10),
    Insn::add64_imm(6, -16),
    st_dw(6, 0, 0x1),
    st_dw(6, 8, 0x2),
    Insn::raw(JA32, 0, 0, 0, 1),
    st_dw(6, 0, 0x3),
    st_dw(6, 4088, 0x4),
    Insn::mov64_imm(0, 1),
    Insn::exit(),
  ];

  for (what, code) in [
    ("forward conditional", forward),
    ("backward JA", backward),
    ("JA32", gotol),
  ] {
    // The store 4 KiB above r6 is out of the guest stack, so the only correct
    // outcome is a guest memory fault. Reaching the guard page instead would
    // abort the process, which is itself the failure signal.
    match run_raw(&code, &RODATA, &[], false).await {
      Err(Error(RuntimeError::MemoryFault(_))) => {}
      other => panic!("{what}: expected a guest fault, got {other:?}"),
    }
  }
}

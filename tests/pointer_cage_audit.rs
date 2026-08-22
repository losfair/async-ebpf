//! Reproducers for a security/soundness audit of the pointer cage
//! (`src/pointer_cage.rs`, the JIT address translation in `vendor/ubpf`) and
//! the static pointer-region analysis (`src/region_analysis.rs`).
//!
//! Every test here goes through the *safe* public API only:
//! `ProgramLoader::new(..).load(..)` + `Program::run(..)`. No `unsafe`, no
//! private module access, no direct calls into the analyzer.
//!
//! The assertions record the behaviour observed at the time of the audit. Each
//! test's doc comment states what a sound implementation would do instead; when
//! a finding is fixed, flip the assertion marked `FIXME(audit)`.

mod common;

use common::*;

static NO_HELPERS: &[(&str, async_ebpf::helpers::Helper)] = &[];

// ---------------------------------------------------------------------------
// Baselines: the runtime works as intended for ordinary programs.
// ---------------------------------------------------------------------------

#[test]
fn baseline_stack_roundtrip() {
  let code = vec![
    Insn::st_dw(10, -8, 0x1234),
    Insn::ldx_dw(0, 10, -8),
    Insn::exit(),
  ];
  assert_eq!(
    run_program_with(&code, NO_HELPERS, &[], true, 1).unwrap(),
    0x1234
  );
}

#[test]
fn baseline_rodata_load() {
  let mut code = Vec::new();
  code.extend(Insn::lddw_reloc(1, "DATA_SYM", 0));
  code.push(Insn::ldx_dw(0, 1, 0));
  code.push(Insn::exit());
  let elf = build_elf_with_data(&code, &[], &0xdeadbeefu64.to_le_bytes());
  assert_eq!(run_elf(&elf, NO_HELPERS, &[], true, 1).unwrap(), 0xdeadbeef);
}

// ---------------------------------------------------------------------------
// Finding 1 — host pointers are readable from the guest at program entry.
// ---------------------------------------------------------------------------

/// Classifies a host address using /proc/self/maps while the program (and thus
/// its JIT code mapping) is still alive. Returns 0 = unmapped, 1 = executable
/// mapping, 2 = some other mapping.
fn h_classify(
  _: &async_ebpf::program::HelperScope,
  addr: u64,
  tag: u64,
  _: u64,
  _: u64,
  _: u64,
) -> Result<u64, ()> {
  let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
  for line in maps.lines() {
    let (range, rest) = line.split_once(' ').unwrap();
    let (lo, hi) = range.split_once('-').unwrap();
    let lo = u64::from_str_radix(lo, 16).unwrap();
    let hi = u64::from_str_radix(hi, 16).unwrap();
    if addr >= lo && addr < hi {
      println!("  r{tag} = {addr:#018x}  in {line}");
      return Ok(if rest.starts_with("r-xp") { 1 } else { 2 });
    }
  }
  println!("  r{tag} = {addr:#018x}  [not a mapped host address]");
  Ok(0)
}

static CLASSIFY: &[(&str, async_ebpf::helpers::Helper)] = &[("classify", h_classify)];

/// FINDING 1: at the first guest instruction, several eBPF registers still hold
/// raw host values left there by `async_ebpf_entry_trampoline` and by the Rust
/// caller. uBPF's uninitialized-register check (`undefined_behavior_check`) is
/// left disabled, so the guest may simply read them.
///
/// On x86-64 the trampoline maps BPF r0 -> RAX, r4 -> x86 r10, r6..r9 ->
/// RBX/R12/R13/R14, and does `mov r10, rdi` (entrypoint code pointer) and
/// `mov rax, [rsp + 8]` (the `JitMemory` descriptor pointer) before `call r10`,
/// without clearing them. RBX/R12/R13/R14 are merely saved, not zeroed.
///
/// A sound sandbox would zero every eBPF register that is not part of the guest
/// ABI (r1 = ctx, r10 = frame pointer) before entering guest code.
#[test]
fn finding1_host_pointers_readable_at_entry() {
  // r4 is the entrypoint's own native code address.
  let code = vec![
    Insn::mov64_reg(2, 4), // 0: save r4 before the helper call clobbers r1-r5
    Insn::stx_dw(10, 2, -8),
    Insn::ldx_dw(1, 10, -8),
    Insn::mov64_imm(2, 4),
    Insn::call("classify"),
    Insn::exit(),
  ];
  let class = run_program_with(&code, CLASSIFY, &[], false, 33).unwrap();
  // FIXME(audit): should be 0 (r4 zeroed at entry).
  assert_eq!(
    class, 1,
    "r4 at entry is a host address in an executable mapping"
  );

  // r0 is the JitMemory descriptor pointer (host stack).
  let code = vec![
    Insn::mov64_reg(2, 0),
    Insn::stx_dw(10, 2, -8),
    Insn::ldx_dw(1, 10, -8),
    Insn::mov64_imm(2, 0),
    Insn::call("classify"),
    Insn::exit(),
  ];
  let class = run_program_with(&code, CLASSIFY, &[], false, 33).unwrap();
  // FIXME(audit): should be 0 (r0 zeroed at entry).
  assert_eq!(
    class, 2,
    "r0 at entry is a live host (non-executable) address"
  );
}

/// FINDING 1 (cont.): the guest can also read the randomized pointer-cage
/// layout out of r2/r3, which the trampoline leaves holding
/// `calldata_start` and `guest_stack_bottom`. `guest_stack_bottom` *is* the
/// randomized `guard_size_1` chosen in `PointerCage::new`, so the guard-size
/// randomization is fully disclosed to the guest.
#[test]
fn finding1_cage_layout_disclosed_at_entry() {
  // Return r3 (== guest_stack_bottom == PointerCage guard_size_1).
  let code = vec![Insn::mov64_reg(0, 3), Insn::exit()];
  let bottom = run_program_with(&code, NO_HELPERS, &[], false, 33).unwrap() as u64;
  println!("  leaked guest_stack_bottom / guard_size_1 = {bottom:#x}");
  // guard_size_1 = rng.gen_range(16..128) * page_size
  let page = 4096u64;
  // FIXME(audit): should be 0 (r3 zeroed at entry).
  assert!(
    bottom % page == 0 && (16..128).contains(&(bottom / page)),
    "r3 exposes the randomized guard size: {bottom:#x}"
  );

  // A guest-visible confirmation that this really is the live stack base: the
  // very first byte of the guest stack region is readable at that address.
  let code = vec![Insn::mov64_reg(1, 3), Insn::ldx_b(0, 1, 0), Insn::exit()];
  assert_eq!(
    run_program_with(&code, NO_HELPERS, &[], false, 33).unwrap(),
    0x8e,
    "r3 points at the live guest stack bottom"
  );
}

// ---------------------------------------------------------------------------
// Finding 2 — lazy local calls leak the callee's native code address in r0.
// ---------------------------------------------------------------------------

/// FINDING 2: every local eBPF call is compiled as a *lazy* call
/// (`emit_lazy_local_call`): the resolver is invoked, and its return value —
/// the callee's native code address — is left in RAX, which is BPF r0, when the
/// callee is entered. r0 is not saved/restored around the call, so the callee
/// (and, on return, the caller) observes a host code pointer.
///
/// This also contradicts the region analysis, which models r0 as preserved
/// across a local call (`PointerSignature::from_state` copies the caller's r0
/// kind into the callee signature).
///
/// A sound implementation would spill/restore r0 around the resolver call, or
/// return the callee address in a register that is not mapped to an eBPF
/// register.
#[test]
fn finding2_local_call_leaks_callee_code_address() {
  let code = vec![
    Insn::mov64_imm(0, 0), // 0: r0 = 0
    Insn::call_local(4),   // 1: call func1 @6
    Insn::mov64_reg(1, 0), // 2: r1 = whatever the callee left in r0
    Insn::mov64_imm(2, 0),
    Insn::call("classify"), // 3
    Insn::exit(),           // 5
    Insn::exit(),           // 6: func1 — does not touch r0
  ];
  let class = run_program_with(&code, CLASSIFY, &[], false, 21).unwrap();
  // FIXME(audit): should be 0 (r0 preserved across the local call).
  assert_eq!(
    class, 1,
    "r0 after a local call is a host executable address"
  );

  // The same value is handed straight back to the host embedder as the
  // program's return value.
  let code = vec![
    Insn::mov64_imm(0, 0),
    Insn::call_local(1),
    Insn::exit(),
    Insn::exit(),
  ];
  let leaked = run_program_with(&code, NO_HELPERS, &[], false, 21).unwrap() as u64;
  println!("  leaked JIT code address returned to the host: {leaked:#x}");
  assert!(leaked > 0x1000, "guest returned a host code address");
}

// ---------------------------------------------------------------------------
// Finding 3 — `StackKind::Foreign` may alias the current frame.
// ---------------------------------------------------------------------------

/// FINDING 3: the analysis treats a stack pointer inherited from a caller as
/// `StackKind::Foreign` and assumes it "does not alias the current frame", so a
/// store through it does not invalidate tracked R10-relative spill slots
/// (`RegKind::aliases_current_stack`).
///
/// That premise is false: local frames are carved out of one flat guest stack,
/// with the callee's R10 sitting `stack_usage` (4096) *below* the caller's, so
/// any caller-derived pointer with a large enough negative displacement lands
/// inside the callee's own frame. Here the caller passes `r10 - 4104`, which is
/// exactly the callee's `r10 - 8` spill slot.
///
/// Result: the callee's spilled *data* pointer is overwritten with a *stack*
/// pointer, but the analysis still emits a confident `REGION_DATA` hint for the
/// reload, so the JIT bounds-checks a stack address against the data region and
/// the access is folded to address 0 — a spurious `MemoryFault` in a program
/// that performs only in-bounds accesses.
///
/// (This is a precision/robustness failure, not a memory-safety failure: the
/// JIT always retains an exact single-region bounds check, so a wrong hint can
/// only fault.)
#[test]
fn finding3_foreign_stack_pointer_aliases_callee_frame() {
  let mut code = Vec::new();
  // --- func0 (entry) ---
  code.push(Insn::mov64_reg(1, 10)); // 0: r1 = r10
  code.push(Insn::add64_imm(1, -4104)); // 1: r1 = callee_r10 - 8
  code.push(Insn::call_local(1)); // 2: call func1 @4
  code.push(Insn::exit()); // 3
                           // --- func1 @4: r1 is `Stack(Foreign)` to the analysis ---
  code.extend(Insn::lddw_reloc(2, "DATA_SYM", 0)); // 4,5: r2 = &rodata
  code.push(Insn::stx_dw(10, 2, -8)); // 6: spill the DATA pointer
  code.push(Insn::mov64_reg(3, 10)); // 7
  code.push(Insn::add64_imm(3, -256)); // 8: r3 = an in-bounds stack address
  code.push(Insn::stx_dw(1, 3, 0)); // 9: *(u64*)r1 = r3  -> overwrites r10-8
  code.push(Insn::ldx_dw(4, 10, -8)); // 10: reload: analysis still says DATA
  code.push(Insn::ldx_b(0, 4, 0)); // 11: deref -> hint DATA, value is stack
  code.push(Insn::exit()); // 12
  let elf = build_elf_with_data(&code, &[], &0x1122334455667788u64.to_le_bytes());

  let lax = run_elf(&elf, NO_HELPERS, &[], false, 7);
  println!("  foreign-alias, lax:    {lax:?}");
  // FIXME(audit): should be Ok(0x8e) — every access above is in bounds.
  assert!(
    matches!(lax, Err(ref e) if format!("{e:?}").contains("MemoryFault")),
    "expected the stale DATA hint to fault, got {lax:?}"
  );

  // Strict region analysis reports the program as fully statically routable and
  // still lets it fault at run time.
  let strict = run_elf(&elf, NO_HELPERS, &[], true, 7);
  println!("  foreign-alias, strict: {strict:?}");
  assert!(
    !format!("{strict:?}").contains("static region analysis failed"),
    "strict mode accepted the misclassified program"
  );

  // Control: identical run-time memory effects, but the overwriting store goes
  // through a pointer the analysis calls a scalar, which invalidates the spill
  // slot and leaves the reload UNKNOWN (dual-region probe). This one succeeds,
  // proving the fault above is caused by the wrong hint and not by the access.
  let mut ctl = Vec::new();
  ctl.push(Insn::mov64_reg(1, 10));
  ctl.push(Insn::add64_imm(1, -4104));
  ctl.push(Insn::stx_dw(10, 1, -4112)); // hand the pointer over via memory
  ctl.push(Insn::call_local(1));
  ctl.push(Insn::exit());
  ctl.extend(Insn::lddw_reloc(2, "DATA_SYM", 0));
  ctl.push(Insn::stx_dw(10, 2, -8));
  ctl.push(Insn::mov64_reg(3, 10));
  ctl.push(Insn::add64_imm(3, -256));
  ctl.push(Insn::ldx_dw(5, 10, -16)); // scalar provenance
  ctl.push(Insn::stx_dw(5, 3, 0));
  ctl.push(Insn::ldx_dw(4, 10, -8));
  ctl.push(Insn::ldx_b(0, 4, 0));
  ctl.push(Insn::exit());
  let elf_ctl = build_elf_with_data(&ctl, &[], &0x1122334455667788u64.to_le_bytes());
  let ctl_res = run_elf(&elf_ctl, NO_HELPERS, &[], false, 7);
  println!("  control (UNKNOWN hint): {ctl_res:?}");
  assert_eq!(
    ctl_res.unwrap(),
    0x8e,
    "the same accesses succeed without a hint"
  );
}

// ---------------------------------------------------------------------------
// Finding 4 — spill slots are assumed to survive helper calls.
// ---------------------------------------------------------------------------

fn h_write_ptr(
  scope: &async_ebpf::program::HelperScope,
  ptr: u64,
  value: u64,
  _: u64,
  _: u64,
  _: u64,
) -> Result<u64, ()> {
  let mut mem = scope.user_memory_mut(ptr, 8)?;
  mem.copy_from_slice(&value.to_le_bytes());
  Ok(0)
}

static WRITE_HELPERS: &[(&str, async_ebpf::helpers::Helper)] = &[("write_ptr", h_write_ptr)];

/// FINDING 4: `transfer()` deliberately keeps tracked R10-relative spill slots
/// across `EBPF_OP_CALL`. But a host helper handed a guest pointer via
/// `HelperScope::user_memory_mut` — the supported way for host data to reach
/// guest memory — can write anywhere in the guest stack region, including a
/// tracked spill slot. Same failure mode as finding 3: a confident but stale
/// region hint, and a spurious `MemoryFault`.
///
/// The same holds for a local callee, which can reach the caller's frame with a
/// positive displacement off its own R10.
#[test]
fn finding4_helper_write_invalidates_tracked_spill() {
  let mut code = Vec::new();
  code.extend(Insn::lddw_reloc(2, "DATA_SYM", 0)); // 0,1: r2 = &rodata
  code.push(Insn::stx_dw(10, 2, -8)); // 2: spill the DATA pointer
  code.push(Insn::mov64_reg(1, 10)); // 3
  code.push(Insn::add64_imm(1, -8)); // 4: r1 = &spill slot
  code.push(Insn::mov64_reg(2, 10)); // 5
  code.push(Insn::add64_imm(2, -256)); // 6: r2 = in-bounds stack address
  code.push(Insn::call("write_ptr")); // 7: helper writes *r1 = r2
  code.push(Insn::ldx_dw(4, 10, -8)); // 8: reload: analysis says DATA
  code.push(Insn::ldx_b(0, 4, 0)); // 9: deref
  code.push(Insn::exit()); // 10
  let elf = build_elf_with_data(&code, &["write_ptr"], &0x1122334455667788u64.to_le_bytes());

  let lax = run_elf(&elf, WRITE_HELPERS, &[], false, 11);
  println!("  helper-overwrite, lax:    {lax:?}");
  // FIXME(audit): should be Ok(0x8e).
  assert!(
    matches!(lax, Err(ref e) if format!("{e:?}").contains("MemoryFault")),
    "expected the stale DATA hint to fault, got {lax:?}"
  );

  let strict = run_elf(&elf, WRITE_HELPERS, &[], true, 11);
  println!("  helper-overwrite, strict: {strict:?}");
  assert!(
    !format!("{strict:?}").contains("static region analysis failed"),
    "strict mode accepted the misclassified program"
  );
}

// ---------------------------------------------------------------------------
// Finding 5 — `atomic cmpxchg` clobbers r0; the analysis does not model it.
// ---------------------------------------------------------------------------

const ATOMIC_DW: u8 = 0xdb;
const CMPXCHG_FETCH: i32 = 0xf1;

/// FINDING 5: `BPF_ATOMIC | CMPXCHG` writes the previous memory contents into
/// **r0** (x86-64 `lock cmpxchg` uses RAX, which is BPF r0; the JIT even
/// truncates `map_register(0)` for the 32-bit form). `region_analysis::transfer`
/// only marks `inst.src` as clobbered for atomics, so r0 keeps whatever
/// provenance it had — here a `Data` pointer materialized by `lddw`.
///
/// The guest fully controls the value that lands in r0, so the confident
/// `REGION_DATA` hint is attached to an arbitrary pointer. As with findings 3
/// and 4 the retained bounds check means this only faults, but strict region
/// analysis reports the access as statically routable.
#[test]
fn finding5_atomic_cmpxchg_clobbers_r0() {
  let mut code = Vec::new();
  code.extend(Insn::lddw_reloc(0, "DATA_SYM", 0)); // 0,1: r0 = &rodata (Data)
  code.push(Insn::mov64_reg(3, 10)); // 2
  code.push(Insn::add64_imm(3, -256)); // 3: r3 = stack address
  code.push(Insn::stx_dw(10, 3, -16)); // 4: [r10-16] = r3
  code.push(Insn::mov64_imm(2, 0)); // 5
  code.push(Insn::raw(ATOMIC_DW, 10, 2, -16, CMPXCHG_FETCH)); // 6: r0 = old([r10-16])
  code.push(Insn::ldx_b(1, 0, 0)); // 7: deref r0 (hint DATA)
  code.push(Insn::mov64_imm(0, 0)); // 8
  code.push(Insn::exit()); // 9
  let elf = build_elf_with_data(&code, &[], &0x1122334455667788u64.to_le_bytes());

  let strict = run_elf(&elf, NO_HELPERS, &[], true, 5);
  println!("  cmpxchg, strict: {strict:?}");
  assert!(
    !format!("{strict:?}").contains("static region analysis failed"),
    "strict mode accepted the misclassified program"
  );
  // FIXME(audit): should be Ok(0).
  assert!(
    matches!(strict, Err(ref e) if format!("{e:?}").contains("MemoryFault")),
    "expected the stale DATA hint to fault, got {strict:?}"
  );

  // Control: same run-time behaviour with unknown provenance for r0.
  let mut ctl = Vec::new();
  ctl.push(Insn::ldx_dw(0, 10, -32));
  ctl.push(Insn::mov64_reg(3, 10));
  ctl.push(Insn::add64_imm(3, -256));
  ctl.push(Insn::stx_dw(10, 3, -16));
  ctl.push(Insn::mov64_imm(2, 0));
  ctl.push(Insn::raw(ATOMIC_DW, 10, 2, -16, CMPXCHG_FETCH));
  ctl.push(Insn::ldx_b(1, 0, 0));
  ctl.push(Insn::mov64_imm(0, 0));
  ctl.push(Insn::exit());
  let elf_ctl = build_elf_with_data(&ctl, &[], &0x1122334455667788u64.to_le_bytes());
  let ctl_res = run_elf(&elf_ctl, NO_HELPERS, &[], false, 5);
  println!("  control (UNKNOWN hint): {ctl_res:?}");
  assert_eq!(
    ctl_res.unwrap(),
    0,
    "the same accesses succeed without a hint"
  );
}

// ---------------------------------------------------------------------------
// Positive result: the cage bounds check itself holds.
// ---------------------------------------------------------------------------

/// The region hints are only a routing optimization: the JIT keeps an exact
/// bounds check for the selected region, guest stack and guest data ranges are
/// disjoint, and stores are unconditionally confined to the stack region. These
/// probes confirm that out-of-region guest addresses fault rather than reading
/// or writing across regions.
#[test]
fn positive_out_of_region_accesses_fault() {
  // Read one byte past the top of the guest data region via a relocated lddw
  // addend. `data_top - data_bottom` is the ELF size rounded up to a page.
  let mut code = Vec::new();
  code.extend(Insn::lddw_reloc(1, "DATA_SYM", 1 << 30));
  code.push(Insn::ldx_b(0, 1, 0));
  code.push(Insn::exit());
  let elf = build_elf_with_data(&code, &[], &0xdeadbeefu64.to_le_bytes());
  let r = run_elf(&elf, NO_HELPERS, &[], false, 3);
  println!("  far out-of-range data load: {r:?}");
  assert!(matches!(r, Err(ref e) if format!("{e:?}").contains("MemoryFault")));

  // A store through a data pointer is confined to the stack region, so it
  // cannot reach (and cannot write) the read-only data region.
  let mut code = Vec::new();
  code.extend(Insn::lddw_reloc(1, "DATA_SYM", 0));
  code.push(Insn::st_dw(1, 0, 0x41));
  code.push(Insn::mov64_imm(0, 0));
  code.push(Insn::exit());
  let elf = build_elf_with_data(&code, &[], &0xdeadbeefu64.to_le_bytes());
  let r = run_elf(&elf, NO_HELPERS, &[], false, 3);
  println!("  store through a data pointer: {r:?}");
  assert!(matches!(r, Err(ref e) if format!("{e:?}").contains("MemoryFault")));

  // Walking off the bottom of the guest stack faults.
  let code = vec![
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, -32769),
    Insn::ldx_b(0, 1, 0),
    Insn::exit(),
  ];
  let r = run_program_with(&code, NO_HELPERS, &[], false, 3);
  println!("  under-run of the guest stack: {r:?}");
  assert!(matches!(r, Err(ref e) if format!("{e:?}").contains("MemoryFault")));
}

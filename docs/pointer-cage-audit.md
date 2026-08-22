# Audit: pointer cage and pointer region analysis

Scope: `src/pointer_cage.rs`, the JIT address translation it drives
(`vendor/ubpf/vm/ubpf_jit_x86_64.c`, `ubpf_jit_arm64.c`), the guest-memory
descriptor in `src/program.rs` (`JitMemory`, `async_ebpf_entry_trampoline`), and
the static pointer-region analysis in `src/region_analysis.rs`.

Every finding below is reproduced in `tests/pointer_cage_audit.rs` using only
the safe public API (`ProgramLoader::load` + `Program::run`); the test helper in
`tests/common/mod.rs` assembles a BPF relocatable ELF, which the loader accepts
like any other program. Run with:

```
cargo test --features testing --test pointer_cage_audit -- --nocapture
```

Host used for the reproductions: Linux x86-64, 4 KiB pages.

## Summary

| # | Finding | Class | Severity |
|---|---------|-------|----------|
| 1 | Host pointers and the randomized cage layout are readable from eBPF registers at program entry | Information disclosure | High |
| 2 | Lazy local calls hand the callee's native code address to the guest in `r0` | Information disclosure | High |
| 3 | `StackKind::Foreign` is wrongly assumed not to alias the current frame | Analysis unsoundness | Medium |
| 4 | Spill slots are assumed to survive calls, but helpers/callees can overwrite them | Analysis unsoundness | Medium |
| 5 | `BPF_ATOMIC \| CMPXCHG` clobbers `r0`; the analysis does not model it | Analysis unsoundness | Medium |

What held up under the audit is described in
[What the cage does get right](#what-the-cage-does-get-right) — in particular,
none of findings 3–5 is a memory-safety hole. The confinement guarantee itself
survives; what breaks is the analysis's own stated invariant, plus address
disclosure that undoes the crate's deliberate randomization.

---

## Finding 1 — host pointers readable from eBPF registers at program entry

**Severity: High** (sandbox information disclosure; defeats the crate's own
JIT-code and pointer-cage randomization)

`async_ebpf_entry_trampoline` (`src/program.rs`) sets up only the registers the
guest ABI defines — `r1` (ctx) and `r10` (frame pointer) — and leaves everything
else holding whatever the host had there. On x86-64, with uBPF's register map
(`r0→RAX`, `r4→x86 r10`, `r6..r9→RBX/R12/R13/R14`):

```asm
mov r10, rdi        ; x86 r10 == BPF r4  <- entrypoint's native code address
mov rax, [rsp + 8]  ; RAX   == BPF r0    <- &JitMemory (host stack address)
push rbp/rbx/r12..r15   ; saved, never cleared -> BPF r6..r9 keep host values
...
call r10
```

uBPF's uninitialized-register check (`ubpf_validate_shadow_register`) is gated on
`vm->undefined_behavior_check_enabled`, which `ubpf_create` initialises to
`false` and `Vm::new` never enables, so the guest can simply read these
registers. Observed at the first guest instruction:

```
r0 = 0x00007fe423ffc450  [rw-p]   &JitMemory, on the host stack
r2 = 0x000000000002a000           calldata_start (guest)
r3 = 0x0000000000022000           guest_stack_bottom == PointerCage guard_size_1
r4 = 0x00007fe423cdb000  [r-xp]   the entrypoint's JIT code address
r6 = 0x000000000008e000
r7 = 0x000056412ecd1888  [rw-p]   leftover host pointer
r8 = 0x7fffffffffffffff
r9 = 0x00007fe41c0064c0  [rw-p]   leftover host pointer
```

Consequences:

* The guest learns the base of the executable JIT mapping (`r4`), a host stack
  address (`r0`), and whatever the Rust caller left in the callee-saved
  registers (`r7`, `r9`). That is a complete ASLR break for the JIT code region,
  whose placement `_load` randomizes on purpose
  (`guard_size_before = rng.gen_range(16..128) * page_size`).
* `r3` is `guest_stack_bottom`, i.e. exactly the randomized `guard_size_1` that
  `PointerCage::new` picked. The guard-size randomization is therefore fully
  disclosed to the guest, and with it the offsets of the stack and data regions
  inside the cage.

Reproducers: `finding1_host_pointers_readable_at_entry`,
`finding1_cage_layout_disclosed_at_entry`. The first classifies the leaked
values against `/proc/self/maps` from inside a helper (while the mappings are
still alive) and asserts `r4` lands in an `r-xp` mapping and `r0` in a live
`rw-p` mapping. The second returns `r3` to the host, checks it matches the
`gen_range(16..128) * page_size` shape, and then dereferences it to show it
really is the live guest stack bottom.

**Suggested fix.** Zero every eBPF register except `r1` and `r10` in the entry
trampoline (both architectures) before transferring control, rather than relying
on the guest not to read them. Enabling
`ubpf_toggle_undefined_behavior_check` would also reject such reads at load
time, but that is a load-time policy, not a confinement guarantee — clearing the
registers is the robust fix.

## Finding 2 — lazy local calls leak the callee's native code address in `r0`

**Severity: High** (information disclosure; also an analysis/runtime mismatch)

`compile_function` always installs a lazy local-call resolver, so every eBPF
`call`-local is compiled by `emit_lazy_local_call`, which ends with:

```asm
mov  rdi, <resolver id>
mov  rax, <tls_local_call_resolver>
call rax          ; RAX := the callee's native code address
pop  r5..r1, ctx  ; r0/RAX is NOT restored
call rax          ; callee entered with BPF r0 == host code pointer
```

`emit_local_call` (the non-lazy path) has no such effect, and the region
analysis models `r0` as preserved across a local call
(`PointerSignature::from_state` copies the caller's `r0` kind into the callee
signature). Neither matches what the generated code does.

The callee sees the code pointer in `r0`; if it returns without touching `r0`,
the caller sees it too, and a plain `exit` hands it to the host embedder as the
program's return value:

```
leaked JIT code address returned to the host: 0x7f92c428b27c
```

Reproducer: `finding2_local_call_leaks_callee_code_address` — classifies the
value as living in an `r-xp` mapping, and separately shows it flowing out
through `Program::run`'s return value.

**Suggested fix.** Save and restore BPF `r0` around the resolver call (push/pop
`RAX` alongside `r1..r5`), or have the resolver return the target in a register
that is not mapped to an eBPF register. Whichever is chosen, `region_analysis`
must model `r0` the same way.

## Finding 3 — `StackKind::Foreign` may alias the current frame

**Severity: Medium** (analysis unsoundness → spurious `MemoryFault` on
in-bounds programs; strict mode accepts the program anyway)

`region_analysis` splits stack provenance into `Current` (this frame) and
`Foreign` (inherited from a caller), and `RegKind::aliases_current_stack`
returns `false` for `Foreign`, so a store through a foreign pointer does **not**
invalidate tracked `r10`-relative spill slots. `foreign_stack_store_does_not_invalidate_current_frame_spill`
in `src/region_analysis.rs` asserts exactly this behaviour.

The premise is false. Local frames are carved out of one flat guest stack: the
JIT lowers `r10` by `stack_usage` (4096, uBPF's
`UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE`) at each local call, so a caller-derived
pointer with a large enough negative displacement lands inside the *callee's*
frame. `r10_caller - 4104` is precisely the callee's `r10 - 8`.

The reproducer has the callee spill a data pointer at `r10 - 8`, overwrite it
through the inherited (`Foreign`) pointer, reload it, and dereference:

```
foreign-alias, lax:     Err(Error(MemoryFault(0)))
foreign-alias, strict:  Err(Error(MemoryFault(0)))   <- analysis reported "fully routable"
control (UNKNOWN hint): Ok(142)
```

The control performs the *same* stores and loads at the *same* addresses, but
routes the overwriting store through a pointer the analysis calls a scalar,
which invalidates the slot and leaves the reload `UNKNOWN`. It succeeds. So the
fault is caused solely by the stale `REGION_DATA` hint: the JIT bounds-checks a
stack address against the data region and folds it to address 0.

Reproducer: `finding3_foreign_stack_pointer_aliases_callee_frame`.

**Suggested fix.** Drop the `Foreign` special case for aliasing:
`aliases_current_stack()` should be true for every `Stack` kind, so a store
through any stack pointer with an unknown frame-relative offset invalidates all
tracked slots. `Foreign` remains useful for routing (it is still `REGION_STACK`)
but must not be used to prove non-aliasing.

## Finding 4 — spill slots are assumed to survive calls

**Severity: Medium** (same failure mode as finding 3)

`transfer()` deliberately preserves tracked `r10`-relative spill slots across
`EBPF_OP_CALL`, with the comment that a helper overwriting a spill can at worst
cause "a spurious fault from a stale region hint". That spurious fault is
reachable through the supported host API: a helper that takes a guest pointer
and writes through `HelperScope::user_memory_mut` may write anywhere in the
guest stack region, including a tracked slot. The same applies to a local callee,
which reaches the caller's frame with a positive displacement off its own `r10`.

```
helper-overwrite, lax:    Err(Error(MemoryFault(0)))
helper-overwrite, strict: Err(Error(MemoryFault(0)))   <- analysis reported "fully routable"
```

Reproducer: `finding4_helper_write_invalidates_tracked_spill`.

**Suggested fix.** Either invalidate tracked slots on every call (costly for the
generated code this optimization targets), or keep the slot but downgrade the
recorded kind to `Unknown` at call boundaries unless the analysis can prove no
guest pointer to that slot escaped. Downgrading is enough: the routing hint
becomes `UNKNOWN` (dual-region probe) instead of confidently wrong.

## Finding 5 — `BPF_ATOMIC | CMPXCHG` clobbers `r0`

**Severity: Medium** (same failure mode as findings 3 and 4)

x86-64 `lock cmpxchg` uses `RAX` — BPF `r0` — as the comparand and writes the
previous memory contents back into it; the JIT's 32-bit path makes this explicit
with `emit_truncate_u32(state, map_register(0))`. `region_analysis::transfer`
models only `inst.src` as clobbered by atomics:

```rust
if is_atomic {
  // An atomic fetch writes the previous value into src.
  s.regs[inst.src] = RegKind::Unknown;
}
```

so `r0` keeps whatever provenance it had. Because the guest chooses the memory
contents, it also chooses the value that lands in `r0` while the analysis still
believes it is, say, a relocated data pointer:

```
cmpxchg, strict:        Err(Error(MemoryFault(0)))   <- analysis reported "fully routable"
control (UNKNOWN hint): Ok(0)
```

Reproducer: `finding5_atomic_cmpxchg_clobbers_r0`, with a control that performs
the identical accesses under an `UNKNOWN` hint and succeeds.

**Suggested fix.** In `transfer()`, set `s.regs[0] = RegKind::Unknown` (or
`Scalar`) for `EBPF_ATOMIC_OP_CMPXCHG`, in addition to the existing `src`
handling.

## Cross-cutting: `require_static_region_analysis` is weaker than documented

`ProgramLoader::require_static_region_analysis` is documented as guaranteeing
that "every executed access is statically routable". Findings 3, 4 and 5 each
produce an access that the analysis classifies *confidently and wrongly*: it is
counted as resolved, strict mode accepts the program, and the access then faults
at run time. A wrong classification is worse than `UNKNOWN` — `UNKNOWN` falls
back to the dual-region probe and works, whereas a wrong hint faults. The flag's
guarantee should be restated as "every executed access was classified", or the
classifier tightened so that classification implies correctness.

---

## What the cage does get right

These were examined and found sound; they are why findings 3–5 are correctness
bugs rather than sandbox escapes.

* **The bounds check is exact and is never skipped for a hint.**
  `emit_single_region_address` folds both bounds into one unsigned comparison
  (`(addr - bottom) <= (top - size - bottom)`) and substitutes address 0 via
  `CMOV`/`CSEL` when out of range, so a misrouted access faults instead of
  reading out of bounds. It is branchless, so there is no mis-speculatable path
  either.
* **Guest stack and guest data ranges are disjoint**, separated by a randomized
  guard region of at least 16 pages, so at most one candidate of the
  `UNKNOWN` dual probe is ever non-zero and the `OR` that merges them cannot
  produce a hybrid address.
* **Stores are unconditionally confined to the stack region** regardless of the
  hint (`if (store || region_hint == JIT_REGION_STACK)`), so the read-only data
  region cannot be written from JIT code even with a maximally wrong analysis;
  `freeze_data()`'s `PROT_READ` backs this up. `JitMemory::safe_deref_for_write`
  applies the same restriction to helpers.
* **`r10` cannot be assigned by the guest** (uBPF's validator rejects any
  instruction with `dst > 9` except stores), so the analysis's hardcoding of
  `r10` as `Stack(Current(Some(0)))` is safe.
* **Local recursion and deep call chains are rejected** before JIT
  (`function_analysis::visit_local_call_graph`, `MAX_LOCAL_CALL_DEPTH = 8`), and
  8 × 4096 exactly matches `SHADOW_STACK_SIZE`, so `r10` cannot walk out of the
  stack region through call nesting alone.
* **Guest stacks are refilled with `0x8e` on every borrow** from
  `EXEC_CONTEXT_POOL`, so no guest data leaks between invocations.
* `positive_out_of_region_accesses_fault` exercises three of these directly: a
  far out-of-range data load, a store through a data pointer, and an under-run
  of the guest stack all produce `MemoryFault`.

## Additional observations (not reproduced here)

These are not exploitable as far as this audit found, but are worth recording.

* **The cage's stack region is allocated, `mprotect`ed and randomized, but never
  used.** `PointerCage::new` reserves `stack_size` bytes of RW mapping between
  two guard regions, yet the live guest stack is
  `ExecContext::guest_stack: Box<[u8; SHADOW_STACK_SIZE]>` — ordinary heap
  memory with no guard pages, which `JitMemory::stack_native_base` points at.
  The cage's guard pages therefore protect only the data region; for the stack
  the exact bounds check is the *only* line of defense, with no defense in depth
  behind it. `PointerCage::safe_deref_for_read` still accepts stack offsets and
  would hand back a pointer into the unused mapping — a live footgun for future
  callers, even though today it is only called with data offsets.
* **`PointerCage::new` panics on 64 KiB-page kernels.** It asserts
  `stack_size % page_size == 0`, and `stack_size` is `SHADOW_STACK_SIZE`
  (32768). On aarch64 Linux built with `CONFIG_ARM64_64K_PAGES`, `page_size` is
  65536 and the assertion fails, panicking inside the safe `ProgramLoader::load`.
  Not reproducible on the x86-64 host used here.
* **`PointerCage::mask()` panics on very large images.** It asserts
  `addressable_len <= 0x8000_0000`; an ELF of roughly 2 GiB or more makes the
  rounded-up cage exceed that and panics inside `load` rather than returning
  `RuntimeError`. `freeze_data()` likewise panics instead of returning an error
  if `mprotect` fails.
* **`MemoryFault(vaddr)` always reports 0.** Out-of-range accesses are folded to
  address 0 *before* the faulting instruction, so the guest address that caused
  the fault is never recoverable from `siginfo`; the reverse-translation code in
  `_run` is effectively dead. Reporting the offending guest address would need
  the faulting address to be preserved (for example by folding to a distinct
  poison page per region and encoding the offset).
* **`jit_pointer_mask`/`jit_pointer_offset` are now only a feature flag.** The
  x86-64 backend uses `vm->jit_pointer_mask` solely as a boolean gate; the
  arm64 `emit_masked_address` that actually applies the mask is dead code (its
  only caller is guarded by the same flag it checks). The values still come from
  `PointerCage::mask()`/`offset()`, which is where the two `assert!`s above
  live. Retiring them would remove those panic paths.

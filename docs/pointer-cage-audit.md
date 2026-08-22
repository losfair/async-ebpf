# Audit: pointer cage and pointer region analysis

Scope: `src/pointer_cage.rs`, the JIT address translation it drives
(`vendor/ubpf/vm/ubpf_jit_x86_64.c`, `ubpf_jit_arm64.c`), the guest-memory
descriptor in `src/program.rs` (`JitMemory`, `async_ebpf_entry_trampoline`), and
the static pointer-region analysis in `src/region_analysis.rs`.

Every finding below was reproduced through the safe public API
(`ProgramLoader::load` + `Program::run`). Several need instruction-level control
the C pipeline cannot express, so they hand-assemble a BPF relocatable ELF via
`src/test/raw_elf.rs`, which the loader accepts like any other program. The
reproducers now live as ordinary tests:

| | |
|---|---|
| Findings 1, 2 | `src/test/entry_isolation.rs` |
| Finding 5 | `src/test/atomics.rs`, plus unit tests in `src/region_analysis.rs` |

```
cargo test --features testing
```

Host used for the reproductions: Linux x86-64, 4 KiB pages.

## Summary

| # | Finding | Class | Severity | Status |
|---|---------|-------|----------|--------|
| 1 | Host pointers and the randomized cage layout are readable from eBPF registers at program entry | Information disclosure | High | Fixed |
| 2 | Lazy local calls hand the callee's native code address to the guest in `r0` | Information disclosure | High | Fixed |
| 3 | `StackKind::Foreign` is wrongly assumed not to alias the current frame | Analysis precision | Low | By design |
| 4 | Spill slots are assumed to survive calls, but helpers/callees can overwrite them | Analysis precision | Low | By design |
| 5 | `BPF_ATOMIC \| CMPXCHG` clobbers `r0`; the analysis does not model it | Analysis unsoundness | Medium | Fixed |

Findings 1, 2 and 5 are fixed in this branch and their reproducers are now
regression tests. Findings 3 and 4 were reviewed and **accepted as intended
behaviour**: both require the program to break its own invariants, and the
cost of detecting them is a cost this runtime deliberately does not pay. See
each section for the reasoning.

Finding 5 is the one that needed fixing, and the line between it and the other
two is worth stating: in findings 3 and 4 the *guest* does something the eBPF
model does not define, and only harms itself. In finding 5 a plain, well-formed
`cmpxchg` was enough — the analysis simply did not model an instruction's
register effects.

What held up under the audit is described in
[What the cage does get right](#what-the-cage-does-get-right) — in particular,
none of findings 3–5 is a memory-safety hole. The confinement guarantee itself
survives; what breaks is analysis precision, plus the address disclosure of
findings 1 and 2 that undid the crate's deliberate randomization.

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

Reproduced during the audit by classifying the leaked values against
`/proc/self/maps` from inside a helper, while the mappings were still alive:
`r4` landed in an `r-xp` mapping, `r0` in a live `rw-p` one, and `r3` matched
the `gen_range(16..128) * page_size` shape and dereferenced to the live guest
stack bottom. The regression tests are
`entry_isolation::entry_registers_are_scrubbed` (every probed register must read
zero) and `entry_isolation::entry_context_and_frame_pointer_survive_the_scrub`.

**Fix.** `async_ebpf_entry_trampoline` now zeroes every eBPF-visible register
except `r1` (ctx) and `r10` (frame pointer) immediately before entering guest
code, on both x86-64 and aarch64. The entry target is staged through a register
that is not part of uBPF's register map (`rcx` / `x17`) so it can be called
after the scrub, and the `JitMemory` descriptor is written to its frame slot
before `rax` / `x6` is cleared. This is a confinement guarantee rather than a
load-time policy, so it holds regardless of whether uBPF's uninitialized-register
check is enabled.

Because those registers now provably hold zero, `PointerSignature::entry()` and
the whole-section analyzer model them as `Scalar` instead of `Uninit`, which is
both truthful and slightly more precise.

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

Reproduced by classifying the value as living in an `r-xp` mapping, and
separately by watching it flow out through `Program::run`'s return value.
Regression tests: `entry_isolation::local_call_preserves_r0` and
`entry_isolation::local_callee_observes_the_callers_r0`.

**Fix.** `emit_lazy_local_call` now preserves BPF `r0` across the resolver call
alongside `r1`-`r5` and enters the callee through a register that is not mapped
to any eBPF register (`rcx` on x86-64; aarch64 already staged the target in
`x17` but did not preserve `r0`, which is caller-saved there too). Lazy and
non-lazy local calls therefore have identical register semantics, which is what
`PointerSignature::from_state` already assumed — so the analysis needed no
change.

This one could not be fixed from the Rust side: the leak lives in the two
instructions between the resolver's `ret` and the callee's first guest
instruction, so only the emitted call sequence can close it. The change is
confined to `emit_lazy_local_call`, which is this project's own addition to the
vendored uBPF rather than upstream code. On x86-64 `r0` is pushed twice to keep
the host stack 16-byte aligned at the resolver call, matching the idiom the
helper-call sequence already uses.

## Finding 3 — `StackKind::Foreign` may alias the current frame

**Severity: Low &mdash; reviewed and accepted as intended behaviour**

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

**Resolution: by design.** Deriving a pointer that crosses a frame boundary is
undefined in the eBPF model, and nothing a compiler emits does it. A program
that does it breaks only itself: the JIT keeps its exact single-region bounds
check, so the access faults rather than escaping, and no other program or the
host is affected.

The alternative — making `aliases_current_stack()` true for every `Stack` kind
— would invalidate every tracked spill slot on any store through a stack pointer
with an unknown frame-relative offset. That is the dominant pattern in `-O2` BPF
output, so it would cost the optimization most of its value in order to serve
programs that are already outside the model.

## Finding 4 — spill slots are assumed to survive calls

**Severity: Low &mdash; reviewed and accepted as intended behaviour**

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

**Resolution: by design.** Knowing which bytes a helper may write would mean
every helper declaring its argument types and buffer layout, which this runtime
deliberately does not require — `Helper` is a plain function of five `u64`s, and
`user_memory_mut` validates only that the range is inside the guest stack. A
program that hands a helper a pointer overlapping its own spilled pointers is
breaking its own invariants, and again breaks only itself.

## Finding 5 — `BPF_ATOMIC | CMPXCHG` clobbers `r0`

**Severity: Medium &mdash; fixed**

Unlike findings 3 and 4, nothing here is the program's fault. A single
well-formed `cmpxchg` is enough, the guest stays entirely inside the eBPF model,
and the analysis still hands the JIT a confident, wrong region.

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

**Fix.** `transfer()` now marks `r0` unknown when the atomic's operation
selector is `CMPXCHG`, matching the way the backends themselves switch on `imm`
so the analysis and the emitted code cannot disagree about which encodings are
compare-and-exchange:

```rust
if is_atomic {
  // An atomic fetch writes the previous value into src.
  s.regs[inst.src] = RegKind::Unknown;
  if inst.imm & EBPF_ATOMIC_OP_MASK == EBPF_ATOMIC_OP_CMPXCHG {
    // ... but CMPXCHG leaves src alone and writes the previous memory
    // contents into R0 instead.
    s.regs[0] = RegKind::Unknown;
  }
}
```

The rule is deliberately narrow: every other atomic writes only `src`, so an
unrelated pointer register stays statically routed across it. With the fix the
program above runs to completion under the dual-region probe, and strict mode
rejects it up front instead of accepting it and faulting later:

```
cmpxchg, lax:     Ok(0x8e)
cmpxchg, strict:  Err(InvalidArgumentOwned("static region analysis failed in
                  function [0, 12): 1 memory access(es) could not be routed ..."))
```

Tests: `atomics::cmpxchg_result_is_not_routed_to_the_stale_region`,
`atomics::cmpxchg_preserves_other_registers`, and the analysis-level
`region_analysis::tests::atomic_cmpxchg_clobbers_r0` /
`atomic_fetch_add_leaves_r0_alone`.

## Cross-cutting: what `require_static_region_analysis` guarantees

`ProgramLoader::require_static_region_analysis` is documented as guaranteeing
that "every executed access is statically routable". All three findings produced
an access the analysis classified *confidently and wrongly* — counted as
resolved, accepted by strict mode, then faulting at run time. A wrong
classification is worse than `UNKNOWN`, because `UNKNOWN` falls back to the
dual-region probe and works.

With finding 5 fixed, the guarantee holds for any program that stays inside the
eBPF model. It does **not** extend to a program that leaves it: findings 3 and 4
are still accepted by strict mode and still fault, by design. The documented
scope is worth stating that way — the flag proves routability for well-formed
programs, not for programs that alias across their own frames or invite a helper
to overwrite their spilled pointers.

---

## What the cage does get right

These were examined and found sound; they are why findings 3–5 stay inside the
offending program rather than becoming sandbox escapes.

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
* The existing suite already exercises these directly:
  `basic::test_fault_read_past_stack`, `test_fault_write_past_stack`,
  `test_fault_write_rodata` and `test_fault_read_null_ptr` all produce
  `MemoryFault`, and `pointer_cage::tests` covers the reserved stack window and
  the data-region bounds of `data_slice`.

## Additional observations (not reproduced here)

These are not exploitable as far as this audit found, but are worth recording.

* **The cage's stack region was allocated, `mprotect`ed and randomized, but
  never used** — the live guest stack is
  `ExecContext::guest_stack: Box<[u8; SHADOW_STACK_SIZE]>`, ordinary heap
  memory, which `JitMemory::stack_native_base` points at. *Addressed in this
  branch*: the cage now only *reserves* the guest stack address window (it stays
  `PROT_NONE`, so it costs address space and nothing else) and maps only the
  data region. Reserving the window keeps the guest stack and data ranges
  disjoint with a randomized distance between them, which is what the JIT's
  single-region checks rely on. `PointerCage::safe_deref_for_read` — which used
  to hand back pointers into the unused mapping — is now `data_slice` and
  rejects everything outside the data region.

  This does not change the fact that for the guest stack the exact bounds check
  is the only line of defense, with no guard pages behind it. Backing the guest
  stack with its own guarded mapping would be a separate change.
* **`PointerCage::new` used to panic on 64 KiB-page kernels.** It asserted
  `stack_size % page_size == 0`, and `stack_size` is `SHADOW_STACK_SIZE`
  (32768), so on aarch64 Linux built with `CONFIG_ARM64_64K_PAGES` the
  assertion failed inside the safe `ProgramLoader::load`. *Fixed by the same
  change*: the stack window is address space, not a mapping, so it no longer has
  to be page-sized; only its layout slot is rounded up to keep the data region
  page-aligned for `mprotect`.
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

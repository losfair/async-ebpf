# Audit: the lazy local-function JIT

Scope: the lazy per-function, per-signature JIT that backs eBPF local calls —
`Program::compile_function` / `compile_resolver` / `cached_resolver_target` and
the `_run` dispatch loop in `src/program.rs`, the `tls_local_call_resolver`
callback, `emit_lazy_local_call` in `vendor/ubpf/vm/ubpf_jit_x86_64.c` and
`ubpf_jit_arm64.c`, the call-graph validation in `src/function_analysis.rs`, and
the `PointerSignature` specialisation key produced by `src/region_analysis.rs`.

Every finding below was reproduced through the safe public API
(`ProgramLoader::load` + `Program::run`) with no `unsafe` and no access to
private items. Several need instruction-level control the C pipeline cannot
express, so they hand-assemble a BPF relocatable ELF via `src/test/raw_elf.rs`,
which the loader accepts like any other program. The reproducers live as
ordinary tests in `src/test/lazy_local_call.rs`:

```
cargo test --features testing lazy_local_call
```

Findings 1 and 3 are fixed in this branch and finding 2 is mitigated; their
reproducers now assert the fixed behaviour, and the numbers quoted for them
below are from before and after the fix.

Host used for the reproductions and timings: Linux x86-64, 4 KiB pages,
`cargo test --release` unless stated otherwise.

## How the mechanism works

A local call is not linked at load time. `translate_range` is invoked once per
`(function, PointerSignature)` pair with `whole_program = false` and
`lazy_local_calls = true`, and every `call src=1` inside the range becomes a
stub that:

1. lowers `R10` by the current function's frame size,
2. spills `R0`–`R9` and uBPF's context register to the host stack,
3. calls `tls_local_call_resolver` with an id baked in as an immediate,
4. moves the returned native address into a register uBPF does not map to any
   eBPF register (`RCX` on x86-64, `x17` on arm64),
5. restores the spilled registers and `call`s through it.

The resolver answers from `cached_resolver_target` when the callee has already
been compiled for that signature. Otherwise it suspends the guest coroutine, and
the `_run` loop calls `compile_resolver`, which runs the region analysis over
the callee, `mprotect`s the whole code arena writable, translates, restores
`PROT_READ | PROT_EXEC`, and resumes the guest with the new address.

The specialisation key is the caller's abstract register state at the call site,
mapped through `RegKind::foreign_for_call()` and then masked to the registers
the callee can actually observe (`function_live_in`, see finding 2). Two call
sites that reach the same callee with signatures that differ in a register it
reads produce two independent native copies.

## Summary

| # | Finding | Class | Severity | Status |
|---|---------|-------|----------|--------|
| 1 | Time spent JIT-compiling is never charged to the timeslice, and cannot be preempted | Availability | Medium | Fixed |
| 2 | Callee specialisation is exponential in call depth | Availability | Low | Mitigated |
| 3 | Each compiled function pays a fixed ~5.5 MiB / ~2 ms cost independent of its size | Availability | Medium | Fixed |
| 4 | Arena exhaustion surfaces as an opaque uBPF error and permanently poisons the program | Robustness | Low | Open |
| 5 | `require_static_region_analysis` does not gate a callee until the entry function has already run | Robustness | Low | Open |
| 6 | The call-depth limit does not account for calldata, so the deepest accepted frame under-runs the stack | Robustness | Low | Open |

**No memory-safety or confidentiality defect was found in the lazy call
mechanism itself.** The register discipline, frame accounting, stack alignment,
resolver-id lifecycle and specialisation key all hold up; see
[What the mechanism gets right](#what-the-mechanism-gets-right) for what was
checked and how. Findings 1–3 compose: 2 and 3 are the multipliers that turn 1
from a design remark into several seconds of unyielding CPU from a program of a
few hundred bytes.

Findings 1 and 3 are fixed in this branch and finding 2 is mitigated; their
reproducers are now regression tests asserting the fixed behaviour. Together
they take the worst case measured here — 1112 compilations forced by a 576-byte
program — from 2.33 s of unyielding CPU to 8 compilations and under a
millisecond. Findings 4, 5 and 6 remain open.

## Finding 1 — compilation time is invisible to the timeslice (fixed)

`_run` handled a lazy-call dispatch and immediately restarted the loop:

```rust
if let Some(resolver_id) = dispatch.lazy_local_call {
  resume_input = self.compile_resolver(resolver_id)?.code_ptr as u64;
  continue;
}
```

The `continue` jumps over the entire budget block at the bottom of the loop, so
`max_run_time_before_yield` and `max_run_time_before_throttle` are neither
consulted nor updated. `last_yield_time` and `last_throttle_time` are only
sampled inside that block, which means the wall clock consumed by an arbitrary
number of compilations does not exist as far as the budget is concerned.

Async preemption does not cover the gap either. The watcher keeps delivering
`SIGUSR1` on schedule, but `sigusr1_handler` returns early unless the
interrupted PC is inside the JIT code range:

```rust
let pc = program_counter(uctx);
if pc < jit_code_zone.0 || pc >= jit_code_zone.1 {
  return;
}
```

During compilation the PC is in Rust and uBPF's C, so every signal is counted
and discarded. `strace -c` over a compilation storm shows 325 `tgkill`s
delivered and no resulting suspension.

**Original behaviour.** A program whose only dispatches were lazy compilations
reported zero `did_yield` and zero `did_throttle` calls with *both* budgets set
to `Duration::ZERO`. Driving the fan-out of Finding 2 with a 1 ms tokio
heartbeat task running alongside:

```
run -> Ok(0) in 720.406943ms; heartbeat ticks during run = 0
```

720 ms of a `current_thread` runtime, from a 336-byte eBPF program, with the
heartbeat starved for the whole duration. At the maximum call depth the same
shape held the thread for ~2.4 s.

**Fix.** The lazy-call branch no longer short-circuits the loop. It now sits
alongside the async-preemption and helper branches and falls through to the same
budget block, and it opts out of the timestamp-free fast path — that fast path
exists so a helper call does not pay for a `clock_gettime`, which is not a trade
worth making against a JIT compilation.

Note that the budget check alone would not have been sufficient.
`compile_function` is a single synchronous call with no suspension point, so one
compilation is still atomic with respect to the runtime; the budget can only
interpose *between* compilations. Finding 3 is what sets the size of that atom,
which is why the two were fixed together.

**Reproduction, now a regression test** —
`lazy_compilation_is_charged_to_the_timeslice` asserts that the same
compilation-only program yields roughly once per lazy compilation on a zero
yield budget, and throttles instead on a zero throttle budget (the throttle
branch is checked first). `a_compilation_storm_does_not_starve_the_async_runtime`
asserts the end-to-end property the finding was really about: the 1112-compilation
program yields over a hundred times and a 1 ms heartbeat task alongside it
actually runs.

## Finding 2 — specialisation is exponential in call depth (mitigated)

`PointerSignature::from_state` snapshotted all eleven registers at the call site,
and the callee inherited them. Registers `R6`–`R9` are callee-saved, so a
distinction a caller introduced survived into its grandchildren's signatures.
A function with `k` call sites that each gave a callee-saved register a
different `RegKind` therefore produced `k` specialisations of its callee, `k²`
of the callee's callee, and so on.

Only four `RegKind`s are reachable from a loaded program (`Data`,
`Stack(Foreign)`, `Scalar`, `Unknown`), so `k = 4` per level, and the loader
allows a depth of 8.

**Original behaviour.** Five functions, 42 instructions, `[1, 4, 16, 64, 256]`
variants:

```
levels=4 arity=4 insns=42 -> Ok(0) in 723ms; compiled=341 arena=220300
levels=5 insns=52  -> compiled=598  arena=441035
levels=6 insns=62  -> compiled=855  arena=662055
levels=7 insns=72  -> compiled=1112 arena=883075
```

1112 native copies and 863 KiB of the 1 MiB default budget, from 576 bytes of
eBPF.

**What was actually wrong.** The signature is the caller's *whole* abstract
register file, but the eBPF calling convention only makes `R1`–`R5` arguments.
`R0` and `R6`–`R9` at a call site are the caller's incidental live state — a
stale value from an earlier helper call, a pointer the caller happens to be
holding across the call — and a callee that has not written them yet is looking
at data that is not its own. Keying specialisation on them splits a callee for
reasons it cannot observe, and because they survive calls, those splits compound
down the graph. That is the part ordinary compiler output hits by accident: `f`
calling `g(buf)` twice with identical arguments still gets two copies of `g` if
its own `R6` differs between the two sites.

**Fix.** `analyze_functions` now computes, per function, the set of registers
whose incoming kind it can observe — a **live-in** mask: registers it may read
before writing, transitively through its callees. It is a backward liveness pass
per function, ordered bottom-up over the call graph (already a DAG, since
recursion is rejected at load), and `from_state` masks every register outside
that set to `Unknown` in the signature it hands the callee.

Masking a register that is not live-in is free rather than a coarsening: it is
overwritten before any read on every path, so no hint, no unresolved access and
no signature passed further down can depend on it. Concretely that means
`require_static_region_analysis` behaviour is bit-identical — nothing that loads
today is rejected, nothing rejected today starts loading — and only the variant
count changes. Every pre-existing test passes unaltered.

Two rules in the mask are worth stating because they are where it could go
wrong:

- Uses are taken from the instruction *encoding* — every register the opcode
  reads, even where `transfer` happens to ignore its kind (32-bit ALU ops,
  comparisons). Defs are the opposite: a subset of what is actually written,
  since a def kills liveness and over-claiming one would drop a register the
  callee can still see. Fetching atomics therefore claim no definition at all.
- `exit` does **not** count `R0` as a use. A callee that returns without
  assigning `R0` hands its caller's value back, but the caller models any call's
  result as a fresh scalar, so the incoming kind is unobservable through a
  return. Counting it would put `R0` — the most incidental register of all — in
  nearly every mask. `region_analysis::tests::exit_does_not_make_r0_live_in`
  pins this.

**After the fix.** The reproducer collapses completely, because none of its
carriers is ever read:

```
levels=4 -> compiled=5   variants=[1, 1, 1, 1, 1]
levels=7 -> compiled=8   variants=[1, 1, 1, 1, 1, 1, 1, 1]
```

341 → 5 and 1112 → 8. The same programs with the leaf dereferencing each carrier
on a statically reachable path specialise exactly as before —
`[1, 4, 16, 64, 256]`, 341 copies — which is the other half of the property:
masking must not collapse a distinction a callee can see. Both directions are
pinned by `unobserved_signature_registers_do_not_multiply_specialisations` and
`observed_signature_registers_still_specialise`.

**Why this is a mitigation and not a bound.** A program that genuinely
dereferences each carrier still gets the full exponent, so the count is still
formally unbounded in the depth. That is accepted rather than capped. With
finding 3 fixed a compilation costs ~21 µs and at minimum ~646 bytes of arena,
so a 1 MiB code budget caps a program at roughly 1620 compilations and ~35 ms of
CPU that finding 1's fix now charges to the timeslice — both resources the
embedder already bounds, and the blast radius is the one program instance.
Capping it explicitly would need a budget calibrated against real workloads, and
the workloads say the exponent is not what bites: CoreMark at `-O3` inlines to a
single function with no local calls at all, and the deliberate two-kind test
produces two variants. What bites is the accidental compounding above, and the
mask removes that at the root.

## Finding 3 — per-compilation cost is O(`UBPF_MAX_INSTS`), not O(function size) (fixed)

`initialize_jit_state_result` allocated uBPF's scratch tables sized for the
maximum program length on *every* translation:

```c
state->pc_locs     = calloc(UBPF_MAX_INSTS + 1, sizeof(state->pc_locs[0]));
state->jumps       = calloc(UBPF_MAX_INSTS, sizeof(state->jumps[0]));
state->loads       = calloc(UBPF_MAX_INSTS, sizeof(state->loads[0]));
state->leas        = calloc(UBPF_MAX_INSTS, sizeof(state->leas[0]));
state->local_calls = calloc(UBPF_MAX_INSTS, sizeof(state->local_calls[0]));
```

`UBPF_MAX_INSTS` is 65536 and `struct patchable_relative` is 20 bytes, so that
is roughly 5.5 MiB allocated, zeroed and freed to compile a six-instruction
function. That design is unremarkable for a whole-program JIT that runs once per
load. Under the lazy JIT it runs once per `(function, signature)` pair — 1112
times for the program above.

The cost is measurable and dominant. Rebuilding with a smaller
`UBPF_MAX_INSTS`, same program, same 341 compilations:

| `UBPF_MAX_INSTS` | wall clock |
|---|---|
| 65536 (default) | 730 ms |
| 4096 | 30 ms |

A 24× difference — about 96% of lazy-compilation time. The remainder is not the
Rust dataflow analysis (release and debug builds were within 5% of each other,
2.33 s vs 2.45 s for the depth-7 program) and it was not the `mprotect` pair
either: holding the program fixed and varying `with_code_size_limit` from
256 KiB to 16 MiB moved the total by less than 5%, and `strace -c` attributed
64 ms to 4164 `mprotect` calls across four runs.

**Fix.** `pc_locs` is indexed by absolute eBPF PC and has to be zeroed, so it is
now sized from `vm->num_insts` rather than `UBPF_MAX_INSTS` — the validator
already guarantees every branch and call target is below that, so the indexing
is unchanged. The four patch tables are append-only and only ever hold entries
for the range being translated, so they now start empty and grow by doubling as
they are appended to, with `UBPF_MAX_INSTS` kept as the hard ceiling so the
`TooManyJumps` / `TooManyLoads` / `TooManyLeas` / `TooManyLocalCalls` errors fire
for exactly the programs they used to.

The growth check also closes a latent hole in the arm64 backend, which appended
to `state->jumps` and `state->local_calls` with no capacity check at all and
relied entirely on `UBPF_MAX_INSTS` entries being more than any program could
need. It is not reachable from this crate — under the function-granular JIT the
table only ever holds entries for one function — but the bound was load-bearing
and unenforced, and an over-capacity append is now a clean compile error on both
backends instead of a heap write.

Measured after the fix, same programs:

| compilations | before | after |
|---|---|---|
| 341 (42-instruction program) | 730 ms | 4.8 ms |
| 1112 (72-instruction program) | 2.33 s | 23.3 ms |

Per compilation that is ~21 µs, down from ~2.1 ms.

None of this touches an emit path, so the generated code is unchanged. CoreMark
is the end-to-end check: it is large, branch-heavy and full of local calls, so
it exercises the growth path well past the initial capacity, and its CRCs verify
every patched branch target. Before and after the fix it reports the same
`crclist 0xe714 / crcmatrix 0x1fd7 / crcstate 0x8e3a` and the same steady-state
throughput (5272 vs 5288 iterations/s over three runs each, i.e. noise).

Two smaller allocations still scale with something other than the function being
compiled, and are left alone for now: `compile_function` allocates
`vec![0u32; code_bytes.len() / 8]` of resolver ids per compilation, and
`analyze_function` allocates `Vec<State>`, `reached` and `on_list` over the whole
*section* rather than the function's range. Both are O(section) rather than
O(`UBPF_MAX_INSTS`), so they no longer dominate.

## Finding 4 — arena exhaustion is opaque and permanent

`compile_function` guards the arena with

```rust
if arena.used >= self.unbound.code_size {
  let err = RuntimeError::InvalidArgument("no space left for jit compilation");
```

but that is only true on exact equality, which essentially never happens: the
arena advances by whatever `written_len` uBPF reports. What actually happens is
that the next compilation is handed a short output buffer and uBPF fails inside
`emit_bytes`. The embedder sees

```
InvalidArgumentOwned("ubpf: code translation failed: Target buffer too small")
```

mid-run, with nothing pointing at the code budget as the cause.

The failure is then cached as `FunctionCompilation::Failed`, so the program is
permanently unable to complete — and because the entry function is still
compiled and still runs, every later invocation re-executes the whole prefix
(helper side effects included) before failing identically.

**Reproduction** — `arena_exhaustion_is_reported_mid_run_and_is_permanent`.
Three consecutive runs all reach the same point and fail the same way, with the
arena pinned at the limit and not growing on the repeats.

Before finding 2 was mitigated this was reachable from a 2112-byte program
against the default 1 MiB budget:

```
pad=24 insns=264 -> Err("ubpf: code translation failed: Target buffer too small")
                    compiled=1091 failed=1 arena=1048303
```

The live-in mask raises that bar a long way — the same fan-out now produces 344
compilations and about 300 KiB — so the reproducer sets
`with_code_size_limit(64 * 1024)` instead. That keeps the finding pointed at
what is actually wrong with it: not that the budget can be reached, but that
reaching it is reported as an internal uBPF message with nothing naming the code
budget, and that the cached failure makes the program permanently unable to
complete while still re-running its whole prefix on every invocation.

## Finding 5 — strict region analysis does not gate a callee until the entry has run

`require_static_region_analysis(true)` is checked inside `compile_function`, so
it applies to each function at the moment that function is first compiled.
Under the lazy JIT that is the moment it is first *called*. A program whose
entry function is clean but whose callee is not therefore loads, runs its entry
function to the point of the call, and only then is rejected.

The existing `test_strict_region_validation_is_deferred_until_execution` covers
the entry function itself (nothing has run, `arena` is still 0). What the lazy
mechanism adds is that arbitrary guest execution — including helper calls with
side effects outside the sandbox — happens first, and repeats on every
invocation because the rejection is cached rather than terminal.

**Reproduction** —
`a_callee_is_region_checked_only_after_the_entry_has_taken_effect`:

```
load ok; bumps after load = 0
run 0 -> Err("static region analysis failed in function [7, 12): ..."); bumps = 3
run 1 -> Err(...); bumps = 6
run 2 -> Err(...); bumps = 9
```

The counter is incremented by a host helper, so these are real effects outside
the guest, three per rejected run.

Compiling every reachable `(function, signature)` pair eagerly at load time
would restore the load-time guarantee — but Finding 2 is exactly why that is
not cheap, and the two need to be solved together.

## Finding 6 — the call-depth limit does not account for calldata

`MAX_LOCAL_CALL_DEPTH` is 8 and every local function is charged
`UBPF_EBPF_LOCAL_FUNCTION_STACK_SIZE` = 4096, which is exactly the 32 KiB
`SHADOW_STACK_SIZE` the cage reserves for the guest stack. The budget has no
slack, and calldata is copied into the top of that same window:

```rust
ectx.ctx.guest_stack[SHADOW_STACK_SIZE - calldata.len()..].copy_from_slice(calldata);
...
let calldata_start = guest_stack_top - calldata_len;
let stack_top = calldata_start & !0x7;
let stack_len = stack_top - guest_stack_bottom;
```

`R10` starts at `stack_top`, i.e. `align8(calldata_len)` bytes *below* the top
of the region, while the depth check still assumes 8 full frames fit beneath it.
The deepest accepted call chain therefore runs off the bottom of the stack by
`align8(calldata_len)` bytes.

**Reproduction** — `the_call_depth_limit_does_not_account_for_calldata`. The
same 7-level chain, leaf reading `[r10 - 4096]`:

```
levels=7 calldata=0  -> Ok(...)
levels=7 calldata=1  -> Err(MemoryFault(0))
levels=7 calldata=8  -> Err(MemoryFault(0))
levels=7 calldata=64 -> Err(MemoryFault(0))
```

This is not a memory-safety problem — the single-region bounds check is exact
and unconditional, so the out-of-range access folds to address 0 and surfaces as
`MemoryFault` — but it means a program's maximum usable call depth silently
depends on how much calldata its caller passes, and strict region analysis does
not catch it either (the access is statically `REGION_STACK`; only the runtime
address is out of range).

## What the mechanism gets right

These were probed and held. They are the properties a fix to any of the above
must not disturb.

**No host state reaches the callee, on either path.** The resolver is a full
host call that suspends the coroutine, runs the region analysis and re-`mprotect`s
the code arena, and the callee is entered from the middle of that sequence.
`a_lazy_call_leaks_nothing_into_the_callees_registers` ORs together every
register the callee can name, across one cold call (which compiles) and one warm
call (which is answered from the cache), and gets zero both times. The resolved
address travels in `RCX` / `x17`, which appear in neither the SysV nor the Win64
`register_map`, and every uBPF path that touches `RCX` writes it before reading
it.

**Frame and host-stack accounting is balanced.** The x86-64 stub does
`sub r15, [rsp]` before twelve pushes and `add r15, [rsp]` after the matching
twelve pops, so `R10` is restored exactly. The twelve pushes also preserve the
16-byte host stack alignment the resolver's C ABI requires — that is what the
otherwise odd-looking doubled `push r0` is for. The arm64 stub is the same shape
with two 48-byte frames.

**Resolver ids cannot dangle or be confused.** Ids are allocated into a local
`pending_resolvers` vector and only committed to `next_resolver_id` and the
shared map after the function has been compiled *and* re-protected, so a failed
compilation leaves neither orphaned entries nor a gap. Allocation is
`checked_add`, and id 0 is never issued — a call site the region analysis did
not reach keeps the zero default and produces a clean
`"local call resolver not found"` error rather than a wild call. The
`resolver_ids` and `hints` pointers handed to uBPF are cleared immediately after
`ubpf_translate_function_ex` returns, on both the success and failure paths.

**A wrong specialisation cannot become a wrong translation.** A region hint only
selects *which* range an access is checked against; `emit_single_region_address`
still performs the exact unsigned range check and substitutes address 0 on
failure, and stores are checked against the stack region regardless of hint. So
the worst a mismatched signature can do is fault. This is the same property the
pointer-cage audit relied on, and it is what keeps Findings 1–6 out of
memory-safety territory.

**Reachability agrees between the two analyses.** `scan_local_function_ranges`
and `region_analysis::function_successors` walk the same CFG with the same
special cases (`lddw` advances two slots, a local call's only intra-function
successor is its fallthrough, `JA32` takes its target from `imm`). A call the
JIT can execute is therefore a call the region analysis assigned a signature to.
uBPF's own validator independently rejects the remaining edge cases — a jump
into the second slot of a `lddw` is caught by its `insts[new_pc].opcode == 0`
check, which matters here because `pc_locs` is `calloc`ed and such a target
would otherwise resolve to offset 0 of the function, re-running its prologue and
walking the host stack pointer down.

**Concurrency and preemption.** Two `Program::run` futures joined on a
`current_thread` runtime both complete correctly and share the compilation
cache; `compile_function` holds its `RefCell` borrows across no suspension
point, and `ACTIVE_JIT_CODE_ZONE` / `ACTIVE_PROGRAM` are republished at the top
of every loop iteration, so interleaving is safe. Repeated runs under the 10 ms
preemption watcher return the correct result, and the coroutine stack has a
guard page, so the ~112 bytes of host stack each guest frame costs cannot
silently overflow into anything.

## Additional observations (not reproduced here)

- On Windows, `emit_local_call` brackets its `call` with the 32-byte home
  register space but `emit_lazy_local_call` only brackets the *resolver* call,
  not the `call *rcx` that follows. Windows is not a supported target, so this
  is noted rather than filed.
- Every lazily compiled function emits its own retpoline, external-dispatcher
  address and helper table (`translate_range` does this per range, not per
  program). With 1112 specialisations that is 1112 copies of the helper table.
  It is part of why per-function arena cost is ~640 bytes for a six-instruction
  function, and it scales with the number of registered helpers.
- `compile_function` makes the *entire* code arena writable while it translates,
  including every function compiled so far. Nothing guest-controlled runs in that
  window — the guest coroutine is suspended and both signal handlers bail out
  when `ACTIVE_JIT_CODE_ZONE.valid` is false — so this is a W^X weakening in
  wall-clock terms only, not a reachable one. It could be narrowed to the pages
  the new function will occupy.
- `protect_code_pages` failures are ignored on the translation-error path
  (`let _ = self.protect_code_pages(arena.used);`). If `mprotect` ever failed
  there the arena would stay writable and non-executable, and the next run would
  fault outside the cage — a crash rather than a corruption, but the error is
  worth propagating.

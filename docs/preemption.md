# Signal-less async preemption

## Status

Proposal. Nothing described here is implemented yet; this document is the design
to argue about before any code moves. The mechanism it replaces —
watcher-injected `SIGUSR1` — is in `src/program.rs` today and is described first
so the trade is explicit.

## What we do today

A per-thread watcher thread is armed for the lifetime of a `PreemptionEnabled`
guard. Every `async_preemption_interval` it wakes and sends `SIGUSR1` to the
thread running the guest, via `tgkill` on Linux and `pthread_kill` on OpenBSD.
`sigusr1_handler` runs on that thread, checks that the interrupted PC is inside
the program's native code arena, and — from inside the signal handler —
suspends the coroutine with `Dispatch { async_preemption: true }`. The run loop
in `Program::_run` then reads the clock and decides whether to yield to the
async runtime, throttle, or resume immediately.

It works, and the cost of it is spread across the runtime in places that do not
look like preemption:

- **The handler suspends a coroutine from a signal context.** The coroutine
  switches away with a signal frame on its stack and resumes back into it. This
  is why `CoDropper` calls `force_reset` rather than unwinding, and why nothing
  on the guest stack may own a destructor.
- **`SIGUSR1` must be blocked while `SIGSEGV` is being handled.** The comment on
  `GlobalEnv::new` records the strace of what happens otherwise: Linux gives up
  and delivers an uncatchable `SI_KERNEL` `SIGSEGV`. So both handlers carry an
  `sa_mask`, and the run loop has to `sigprocmask` the mask back off on every
  fault and every preemption dispatch.
- **Nothing in the handler may touch lazily-initialised TLS.** `init_thread`
  pre-touches `RUST_TID`, `SIGUSR1_COUNTER` and `ACTIVE_JIT_CODE_ZONE` before
  the watcher can fire, because OpenBSD aborts if a signal re-enters TLS setup.
- **Neither handler is installed with `SA_RESTART`.** A `SIGUSR1` that lands
  while the thread is inside a host helper does not preempt anything — the PC is
  outside the code arena, so the handler returns — but it can still interrupt
  that helper's syscall with `EINTR`. Every helper the embedder writes inherits
  that hazard.
- **Preemption is imprecise, so the run loop needs a proxy for it.**
  `SIGUSR1_COUNTER` exists only so `_run` can tell whether a signal happened at
  all, since a signal delivered outside the arena produces no dispatch.
- **Tests have to be timing tests.** `src/test/preemption.rs` runs 200,000,000
  guest iterations and says, in a comment, that the number is a hostage to how
  fast the JIT is and has already been raised once when the JIT got faster.
- **It takes over a process-wide signal.** An embedder that uses `SIGUSR1`, or
  links something that does, loses.

## What we do instead

The JIT emits an explicit poll of a per-thread preemption word at points it
chooses, and calls out to the runtime when it finds the word set. The watcher
thread stops sending signals and starts doing a relaxed store.

```text
  ; x86_64, at a backedge
  mov  rcx, [rbp - 152]          ; the thread's preempt word
  cmp  dword ptr [rcx], 0
  jz   .skip
  call preempt_stub              ; shared, in the function's trailer
.skip:
```

```text
  ; aarch64, at a backedge
  ldr  x16, [x29, #-152]
  ldr  w16, [x16]
  cbz  w16, .skip
  adr  x17, .skip                ; the stub returns through x17, so x30 survives
  b    preempt_stub
.skip:
```

Three instructions on the fast path, all of them hitting L1: the frame slot is
the hottest line the guest has, and the flag line stays Shared until the watcher
writes it. The slow path is one shared out-of-line stub per compiled function,
next to the retpoline.

Preemption stops being an interrupt and becomes an ordinary call into the
runtime, at a point the code generator picked, with a register state the code
generator knows.

## Where the polls go, and why that is enough

Two placements, and a bound that falls out of them:

1. **Every backward branch**, emitted immediately before the branch's own
   compare and jump. Whether the branch is taken or not, the poll ran.
2. **Every function entry**, in the per-function prologue.

The claim is that these bound the number of guest instructions between two
polls, and the bound is small:

- Every cycle in a function's CFG contains a backward branch. Forward edges
  alone cannot close a cycle, and eBPF has no indirect intra-function branch, so
  a poll at every backward branch bounds every loop at one iteration.
- The call graph is acyclic and shallow. `function_analysis` rejects recursion
  and caps depth at `MAX_LOCAL_CALL_DEPTH`, so call nesting cannot substitute
  for a loop, and a poll at each entry bounds the tree anyway.
- Everything else that runs for a while already leaves guest code. Helper calls,
  lazy local-call resolution and memory faults all dispatch back to the host,
  and the run loop's budget check is on that path today.

So the worst case between two polls is the longest acyclic straight-line path
through a single function, which `MAX_INSTS` caps at 65,535 instructions — tens
of microseconds, against a preemption interval measured in milliseconds. There
is no program shape that escapes it, because the guest does not choose what the
JIT emits.

That last point is worth stating as the security property, because it is the one
that replaces "the kernel will deliver the signal regardless": **preemptability
is now a property of code generation.** An emitter bug that drops a poll at a
backedge is a guest that cannot be preempted — a denial of service, not a
correctness bug that shows up in a test run. The mitigations are in
[Testing](#testing) and they are not optional.

## Placement details the emitters have to respect

- **Flags are dead at instruction boundaries.** Each eBPF instruction emits its
  own compare next to its own branch, so the poll's `cmp` clobbers nothing
  live. Emitting the poll *before* the branch's compare, rather than between the
  compare and the jump, is what makes this true rather than merely likely.
- **The poll must not split an access group.** A group's translated base lives
  in the frame at `GROUP_BASE_OFFSET`, not in a register, so a poll cannot
  corrupt one — but a group must still be closed before a poll is emitted, for
  the same reason branch targets are barriers. Backedges and function entries
  are already barriers, so in practice this is an assertion rather than new
  logic.
- **The scratch register is one nothing else owns.** On x86_64 the eBPF map
  covers `rax, rdi, rsi, rdx, r10, r8, rbx, r12, r13, r14, r15`; `rcx` and `r9`
  are free, and `rcx` is only ever used transiently (shifts). On aarch64 `x16`
  and `x17` are the transient temporaries and neither survives an instruction.
- **The poll runs after `pc_locs[i]` is recorded**, so a branch landing on the
  polled instruction runs the poll too — the same ordering constraint the `R10`
  materialisation already documents.
- **A poll is guest-observationally transparent.** It reads one host word and
  either falls through or calls out; no guest register, no guest memory, and no
  guest-visible flag changes. This is what lets `interp.rs` stay poll-free and
  remain a valid semantic oracle.

## The stub

One per compiled function, emitted in the trailer beside the retpoline, reached
by `call` on x86_64 and by a `b` with the return address staged in `x17` on
aarch64.

The stub calls a host function — `Config::preempt_handler`, plumbed exactly like
`Config::dispatcher` — that does nothing but

```rust
yielder.suspend(Dispatch { async_preemption: true, ..Default::default() })
```

so the host side of preemption is bit-for-bit what it is today. What the stub
has to get right is the guest register state:

- **x86_64.** Guest `r6`–`r10` map to `rbx, r12, r13, r14, r15`, all host
  callee-saved, so the host function preserves them for free. Guest `r0`–`r5`
  map to `rax, rdi, rsi, rdx, r10, r8` and must be saved, along with
  `VOLATILE_CTXT` (`r11`). That is seven pushes, which lands `rsp` back on a
  16-byte boundary for the call — guest instruction boundaries sit at
  `rsp ≡ 0 (mod 16)`, the same invariant the helper-call sequence maintains by
  pushing `VOLATILE_CTXT` twice.
- **aarch64.** Guest `r6`–`r10` are `x19`–`x23` and `VOLATILE_CTXT` is `x26`,
  all callee-saved. Guest `r0`–`r5` (`x5, x0`–`x4`) and `x30` must be saved.
- **Neither stub touches `[rsp]`/`[sp]` as data.** On x86_64 the top of the host
  stack holds the current guest function's stack usage; the stub's return
  address sits above it and is gone before anything reads it.
- **No SIMD state to preserve.** The guest cannot name an xmm or a vector
  register, and the trampoline clears the one it uses.

`R0` deserves a note: the existing external-dispatcher sequence returns a value
in `rax`, which is guest `r0`. A preemption returns nothing and must not perturb
`r0`, which is why this is a separate stub rather than a reserved helper index.

## Where the flag lives

A per-thread cell, cache-line padded, held in an `Arc` so the watcher can write
it without borrowing the thread:

```rust
#[repr(align(128))]
struct PreemptCell {
  /// Bit 0: yield requested. Bits 1..: reserved (see below).
  flags: AtomicU32,
}
```

Its address reaches the emitted code through the frame, at a new slot the entry
trampoline fills from a new `JitMemory` field:

- `abi::PREEMPT_FLAG_OFFSET = -152`. The reserved frame is 160 bytes and the
  lowest slot in use today is `GROUP_BASE_OFFSET` at `-144`, so this fits
  without moving anything or growing `FRAME_RESERVED`.
- Both `global_asm!` trampolines gain one load and one store, and
  `jit::audit::trampoline_contract` — which reads `program.rs` with
  `include_str!` and checks every displacement against `abi` — gains one more
  displacement to check.

The frame pointer is established once by the entry trampoline and is never
changed by a guest function: the per-function prologue moves only `rsp`/`sp`,
and the lazy local call moves only `sp` and `r10`. So one slot, filled once per
invocation, is readable from every compiled function at every call depth.

**The alternative considered and rejected for now** is baking the flag's address
into the emitted code as a RIP-relative operand, which on x86_64 collapses the
poll to a single fused `cmp dword ptr [rip+disp], 0`. It is tempting and it is
correct — programs are pinned to a thread before anything is compiled — but the
±2GB reach between a heap allocation and the code arena is not guaranteed, and
buying the instruction back properly means moving the flag word into a dedicated
read-write page inside the arena reservation. That is a self-contained follow-up
to make once the benchmark says the load matters, not part of this change.

Ordering is relaxed on all three sides: the watcher's store, the guest's load,
and the run loop's clear. Nothing is published through the word — it carries no
payload — so nothing needs to be ordered against it. That changes the moment a
bit carries a reason with it, which is the next section.

## What the word buys beyond a timeslice

The poll compares against zero, so the host decides what a set bit means, and
new bits cost nothing at the poll site:

- **Bit 0, yield.** What the watcher sets; the run loop clears it and applies
  the existing `TimesliceConfig` logic unchanged.
- **Bit 1, terminate.** Cross-thread cancellation of a running program, which is
  impossible today. `Program::run` returns a `RuntimeError` at the next
  safepoint instead of running to completion. This one needs release/acquire if
  a reason travels with it.
- **A deterministic fuel mode**, for fuzzing and for tests that want a bounded
  run without a clock: the same sites decrement a frame-slot counter and call
  the stub when it reaches zero. Reproducible, and free when unused.

None of these is in scope for the first change. They are the reason to spend the
frame slot and the instruction now rather than wiring a bespoke boolean.

## What the runtime sheds

Once the emitters are polling, `SIGUSR1` has no remaining user and the following
all go:

- `sigusr1_handler`, and with it the only place a coroutine is suspended from a
  signal context outside the fault path.
- `signal_native_thread`, `current_native_thread`, and the `NativeThread`
  type — the whole Linux/OpenBSD split for delivering a signal to a thread.
- `SIGUSR1` in `get_blocked_sigset`, which reduces to `SIGSEGV` alone, and with
  it the `sa_mask` interaction that produced the `SI_KERNEL` `SIGSEGV` quirk.
- The `sigprocmask` restore on the preemption path in `_run` (the fault path
  keeps its own).
- `SIGUSR1_COUNTER` and the `(RUST_TID, SIGUSR1_COUNTER)` fast-path tuple in the
  run loop, which becomes `RUST_TID` alone — a preemption now arrives as an
  explicit dispatch, so nothing has to infer that one happened.
- The TLS pre-touching in `init_thread` that exists for signal-handler safety.
- The `EINTR` exposure that host helpers inherit today.

**`SIGSEGV` stays.** Memory faults are still delivered as signals and still
suspend the coroutine from the handler, so `force_reset` and the "no destructors
on the guest stack" rule are unchanged. This proposal removes one of the two
signals, not the signal handler.

The watcher thread stays, doing less: a condvar wait and a relaxed store. It no
longer needs the target thread's identity at all, which opens an obvious
follow-up — one process-wide timer thread walking a registry of per-thread
cells, instead of one watcher thread per runtime thread. Worth doing, worth
doing separately.

## Costs

- **Three instructions and ~21 bytes (x86_64) / ~20 bytes (aarch64) per
  backedge**, plus the same per function entry, plus one stub per compiled
  function. On a tight loop this is the honest cost of the change and it should
  be measured, not estimated: CoreMark and a synthetic tight loop, before and
  after, on both architectures.
- **Code size**, which is charged against `DEFAULT_CODE_SIZE_LIMIT` (1 MiB) and
  surfaces as `OutOfSpace` for a large loop-heavy program. If the measured
  growth is material the default should move in the same change, so nobody
  discovers it as a mysterious regression.
- **Two fixups per poll** against the patch tables, which are capped at
  `MAX_INSTS`. A poll per backedge cannot exceed one per instruction, so the
  ceiling holds, but the accounting should be stated in `patch.rs` rather than
  left to be re-derived.
- **Goldens change on both backends**, which per `AGENTS.md` is the deliverable
  rather than a side effect.
- **Preemption granularity coarsens** from "anywhere in JIT code" to "at a
  safepoint". The README says "fully preemptive"; the accurate claim is
  "preemptible at safepoints no more than one function body apart", and the
  wording should follow the code.

## Testing

The coverage property is the one that has to be tested by construction, because
the failure mode is a guest that runs forever and a test suite that says nothing.

- **Emitter coverage, asserted structurally.** Under `cfg(test)` the emitter
  counts polls; a test over a corpus of generated programs asserts
  `polls == backward_branches + function_entries` for every translated range,
  on both targets. This is the test that fails when someone adds an instruction
  form that branches backward without going through the shared path.
- **Deterministic preemption tests replace timing ones.** With the flag exposed
  to tests, a program can be preempted on demand and the yield asserted to
  happen within a bounded number of guest instructions. `src/test/preemption.rs`
  keeps one wall-clock test as an integration check, but `LOOP_ITERS` stops
  being load-bearing and the comment warning that JIT speed makes it flaky stops
  being true.
- **Goldens** for a loop, a nested loop, a local-call loop and a leaf function,
  on both backends, with the poll on and off.
- **A/B benchmarking** falls out of making poll emission a `TranslationInputs`
  field rather than a `Config` one: the same program compiles with and without
  polls in the same process.
- **Fuzzing** already translates arbitrary programs; the new failure surface is
  `OutOfSpace` accounting around the stub and the per-site sequence.

## Plan

Each phase lands and is testable on its own; both mechanisms are live from
phase 0 until phase 4 removes the old one.

0. `PreemptCell`, its `Arc`, and the watcher writing the flag instead of — for
   now, in addition to — signalling. Nothing is emitted yet, nothing observes
   the flag.
1. The ABI: `abi::PREEMPT_FLAG_OFFSET`, the `JitMemory` field, both trampolines,
   and the `trampoline_contract` audit that keeps them honest.
2. The emitters: `Config::preempt_handler`, the per-function stub, the poll at
   backedges and entries, the coverage test, the goldens.
3. The host side: the preempt handler function, the run loop clearing the flag,
   the deterministic tests.
4. Delete `SIGUSR1` and everything in [What the runtime sheds](#what-the-runtime-sheds).
5. Optional, separately: one process-wide timer thread; the arena-resident flag
   and the fused RIP-relative compare; the terminate bit; fuel mode.

## Alternatives considered

- **A guard page poll** (HotSpot's polling page): emit a load from a page the
  runtime `mprotect`s to `PROT_NONE` when it wants to preempt, and catch the
  fault. One instruction per safepoint instead of three, and the fault is
  synchronous and precise — but it is still a signal, which is the thing we are
  trying to stop relying on, and cross-thread `mprotect` costs a syscall and a
  TLB shootdown per preemption against a relaxed store. The machinery exists
  here (the arena already flips protections), so it stays on the table if the
  poll ever shows up in a profile in a way the arena-resident flag does not fix.
- **Patching the running code** at safepoints, the way some JITs implement
  handshakes. Rejected: it means writing to executable pages while another
  thread executes them, plus an icache maintenance sequence on aarch64, in
  exchange for instructions we are not short of.
- **Poisoning a check the code already emits**, the way Go folds preemption into
  the stack bound. There is no per-iteration check to poison here — the frame
  fast path exists precisely to emit *no* check — so this would mean adding a
  check to overload, which is the proposal above with extra steps.
- **Fuel only, with no timer.** Deterministic and thread-free, but an
  instruction budget is not a time budget, and `TimesliceConfig` is written in
  `Duration`. Kept as a mode, not as the mechanism.

# Memory safety of the generated code

## The question

The proofs under `lean/` say what the *analysis passes* guarantee about an
accepted program: the validator, the layout, the frame geometry, the region
analysis. None of them says anything about the native code the backends emit.
The frame fast path, the branchless bounds check, the access groups, the local
call sequence: each is a place where the emitter trades a runtime check for an
argument, and until now the argument lived in comments and tests.

This document is about proving the missing half: that the code the x86_64
backend emits is *memory-safe*. Not that it implements eBPF, only that
whatever it does, it never touches host memory it was not given.

## What memory safety means here

Read `emit_checked_address` and the frame contract in `src/jit/abi.rs` and the
property falls out. One emitted function variant is memory-safe if, entered
under the entry contract (below), for *any* bytecode the validator accepts and
*any* hints and plan, including hostile ones, every execution only touches
addresses in a fixed allowed set:

- **The frame scratch.** The frame-pointer-relative slots inside the 160
  bytes the entry trampoline reserves. The generated code never writes `rbp`.
- **The native stack.** Balanced pushes and pops plus the 8-byte prologue
  slot, bounded per activation, above the native floor the local-call
  sequence checks before it descends.
- **The guest frame fast path.** `[r15 + d]` only when `-F <= d` and
  `d + width <= 0`, where `F` is the configured frame size. The register
  mapped to eBPF `R10` moves by exactly one stride per local call and is
  restored on return, so its value is always the top of a mapped island.
- **Checked accesses.** The branchless check sequence produces either a
  native address whose window lies inside one guest region or the value 0. A
  failed group leader parks 0 and its members touch `[0 + delta]` with
  `delta` under a page. Both land in the windows the fault handler claims as
  a guest fault (`POINTER_CAGE_PROTECTED_WINDOW` and the stack and data
  ranges in `program.rs`).
- **The literal pool.** RIP-relative loads only from the function's own
  trailer.
- **Control flow.** Branches only to translated slots of the same function or
  its epilogue; calls only through the retpoline to the dispatcher, to the
  resolver and stack-exhausted callbacks the configuration names, or to the
  address the resolver returned; `ret` only with the stack balanced.

Deliberately outside the statement: functional correctness, and information
leaks such as the native value of `R10` reaching the guest as a value. The
`audit_escape` tests probe the latter; memory safety does not cover it.

One useful simplification falls out of stating it precisely. The emitter's
`written` mask on open groups is a correctness invariant, not a safety one: a
parked group base is already translated and checked, so a member stays inside
the checked window whatever happened to the base *register* since. What
safety needs is that no branch lands between leader and member, because a
different leader with a smaller span could have parked since.

## Why the emitter could not be proved as it was

The two backends write bytes straight from the eBPF instruction they are
translating, through `&mut self` methods over a borrowed buffer, `Vec` patch
tables, closures, `String` errors and inline byte literals. None of that is
in the subset Aeneas translates, and a proof about bytes would first need a
verified x86 decoder. The proof also cannot be about eBPF: the only thing the
emitted code has in common with the bytecode is the emitter's word.

So the x86_64 backend was restructured into layers, with the decisions moved
into the verified core and the bytes left outside:

```text
  eBPF program + hints + plan
    │  src/verified/x64_lower.rs   lower: which sequence, which check, which group
    ▼
  Vec<MInsn>   macro instructions (src/verified/x64_ir.rs)
    │  src/verified/x64_check.rs   check: the memory-safety gate
    │  src/verified/x64_expand.rs  expand: each macro's fixed native sequence
    ▼
  Vec<PInsn>   primitive instructions, one per x86 instruction
    │  src/verified/x64_encode.rs  assemble: bytes and relative-branch fixups
    ▼
  bytes        (src/jit/emit/x86_64.rs only reports the two errors)
```

The bytes are unchanged: every golden in `src/jit/goldens/x86_64.txt` is the
same before and after, which is what makes the restructuring reviewable.

### Macros and primitives

A *macro* (`MInsn`) is one emitted idea: a bounds check, a helper call, a
lazy local call, a division with eBPF's fix-ups, a guest load. A *primitive*
(`PInsn`) is one x86 instruction. `expand` turns each macro into its fixed
primitive sequence; the assembler is a table from primitives to bytes with no
decisions left in it, and a verified decoder inverts it.

The split is what keeps the proof small. The checker reads macros and knows
each one's *contract* only: what it requires of the abstract state, which
registers it writes, whether it touches guest memory. Each contract is proved
once in Lean against the macro's expansion, with the operands symbolic. The
emitter's decisions, which are the part that changes, are checked by a pass
that never looks inside a sequence.

### The checker

`x64_check::check` walks the macro list once with an abstract state: a tag per
native register, the native stack depth, the tag of the parked group base,
and whether the walk is live. The tags are `Top` (anything), `Fp` (the
register still holds its entry value; only the register mapped to `R10`
carries it), and `Checked(w)` (zero, or a native address whose `w`-byte
window lies inside one guest region).

The rules are the contracts on `MInsn`. In short:

- A register-only instruction may not write `rsp`, `rbp` or the frame
  register; it sets its destination to `Top`.
- `CheckedAddr` sets its destination to `Checked(size)` and its scratches to
  `Top`.
- A guest load, store or atomic needs its base `Checked(w)` with the access
  inside `[0, w)`, or the frame register with the access inside the frame
  window under a native frame base, or the cage off.
- `GroupBaseStore` copies the register's tag into the parked-base tag;
  `GroupBaseLoad` copies it back. A call, and any slot a branch can land on,
  resets the parked base to `Top`.
- A branch needs depth one and the frame register intact, and its target
  labelled. The state after `Jmp`, `Epilogue` and the trailer is dead.
- A prologue is entered at depth zero (from a dead state or the start of the
  range) and leaves depth one; a skippable one may also be fallen into at
  depth one.
- Every macro with pushes declares its depth, and the running depth plus
  that stays under `MAX_DEPTH`.
- The trailer is exactly `Epilogue, Retpoline, DispatcherSlot, HelperTable`,
  last, and a helper call needs a registered dispatcher.

`lower` runs `check` on what it built and refuses the function if the check
fails. That gate is the theorem's hook: what the backend returns is checked
code, by construction. Whether the gate ever fires on real emitter output is
a separate question, a precision one, and is what the goldens, the
configuration sweeps, the randomised emitter sweeps and the runtime tests
answer: none of them trips it. The fuzz targets under `fuzz/` exercise the
same path and would report a refusal as a compile failure.

## What is proved

In `lean/AsyncEbpf/X64/`:

- `Machine.lean` is an operational semantics of the primitive instruction
  set extracted from `x64_ir.rs`: sixteen registers, the four flags the
  checks read, byte-addressed memory, and a program counter over the
  primitive list. Branch targets are labels, so no encoding is modelled. A
  call to an address outside the function is an *external call*: it
  returns to the pushed return address with `rsp`, `rbp`, `r15` and the
  read-only frame slots and descriptor preserved, and everything else —
  `rbx` and `r12`-`r14` among it, and guest memory wherever the runtime
  mapped it — arbitrary. That is what the runtime promises of the
  dispatcher and the callbacks, and it is exactly this theorem's own
  conclusion for a lazily compiled callee, which is why it promises no more
  than that conclusion does. `stores` names the subset of an instruction's
  accesses that write.
- `Contract.lean` states the entry contract, the allowed set and the
  writable set: the descriptor at `[rbp - 8]` and the derived constants
  below it describe two disjoint guest regions with disjoint native
  backings, neither containing the first page; the frame register holds the
  native address of the current frame's top, inside the stack's backing;
  the native stack has a bounded window below `rsp`. `WritableAllowed` is
  the part of the allowed set a function may *change* — the native stack
  below the entry `rsp`, the four writable frame slots, the two guest
  backings and the first page — and `SafeStores`, the second half of
  `Contract`, says every store lands in it. That is what a caller needs of
  its callee and what `Safe` on its own does not say; `romem_kept` is the
  corollary, that the read-only slots and the descriptor come back
  untouched.
- `CheckSpec.lean` turns `check = ok` into a chain of abstract states with
  one rule application per macro; `Expand.lean` turns `expand` into a
  concatenation of per-macro chunks with every label resolved; `Abs.lean`
  and `Run.lean` say when an abstract state describes a machine state and
  what every macro's expansion owes (`MacroOk`); `Simple.lean`,
  `CheckedAddr.lean`, `Arith.lean` and `Calls.lean` prove it macro by macro.
- `Soundness.lean` composes: `check_safe` says that if `check` accepts a
  macro list then, under the cage and with a registered dispatcher whose
  address is off the function's code, every execution of the list's
  expansion from the entry contract touches only allowed addresses and
  returns, if it returns, with the contract kept; `lower_safe` says the
  same of what `lower` returns.

The per-macro lemmas are where the emitter's old comments became theorems:
the branchless check yields zero or an in-region address for both the
frame-constants and the descriptor paths and for the two-region probe; the
lazy call moves the frame register by one stride and restores it around
the callee; the helper call's default path is dead when a dispatcher is
registered and its retpoline returns through the address the call pushed;
the division sequence's pushes balance; the fetching atomic's loop
re-dereferences a base nothing has rewritten.

The theorem is about one activation entered at the head of the list, which
is how the runtime enters every function it translates. Four more results
connect it to the rest of the runtime:

- **Across activations** (`Compose.lean`). The model answers every call out
  of the list with `ExternalReturn`, an assumption about the callee.
  `callee_externalReturn` discharges it for the callee that is another
  instance of this theorem: a lazily compiled function that satisfies
  `Contract`, entered one stride down with the two floor checks passed,
  returns to its caller exactly as `ExternalReturn` says, and its own
  `Layout` follows from the caller's. The dispatcher and the two callbacks
  are host code and stay assumed.
- **The layout the runtime checks** (`x64_layout.rs`, `LayoutCheck.lean`).
  `layout_ok` is twenty-one comparisons over the thirteen numbers the
  descriptor and the mappings carry; `program.rs` runs it on every
  invocation and refuses the run if it fails. `layout_of_check` turns a
  passing check, plus the six per-activation facts only the trampoline can
  establish, into the theorem's `Layout` hypothesis, clause by clause.
- **The bytes** (`x64_encode.rs`, `x64_decode.rs`, `Encode.lean`).
  The encoder is no longer trusted: `assemble` is the two-pass assembler,
  `decode_one` an independently written inverse, and `decodesTo_all` says
  every primitive the backend can emit decodes back to its shape and its
  `size_of` length, every operand symbolic; `assemble_spec` says the
  assembled bytes are that concatenation with each branch site carrying
  the displacement to its label, and that an unlabelled target is refused.
  What remains trusted of the bytes is the decoder's table.
- **The model and the machine** (`x64_sim.rs`, `SimRefines.lean`,
  `src/test/x64_sim_native.rs`). `x64_sim` is an executable simulator of the
  primitives; `step_refines` and `run_refines` prove it is a run of
  `Machine.lean`'s relation. A differential test runs twenty thousand
  random primitive lists through the simulator and the processor and
  compares registers, flags and memory. The test is what ties the model
  to the hardware; the refinement is what makes it a test of the model.

## What is trusted

- **The x86 instruction set** as the model and the decoder read it: that
  the bytes the assembler emits mean to the processor what `Machine.lean`
  says the primitive means. The simulator's differential test against the
  hardware is the evidence; it is not a proof.
- **The entry trampolines** (`global_asm!` in `program.rs`): that they
  enter generated code with `rsp`, `rbp` and the frame register where the
  six per-activation facts say, inside the mappings `layout_ok` checked,
  and with the descriptor and derived slots filled as `RoMem` reads them.
- **The fault handler** and the windows it claims; **the mappings** (islands,
  gaps, the cage, the arena's write-xor-execute discipline).
- **The host side of every call**: the dispatcher, the resolver (that it
  returns the address of checked code), the stack-exhausted callback (that it
  does not return), and the SysV convention.
- **Charon and Aeneas**, and the Aeneas model of `Vec`, arrays and scalars.

## What changed for embedders

Nothing in the bytes. Two things at the edge:

- A function whose lowering fails is reported as a translation failure
  before the buffer is consulted, so a program that would never translate is
  no longer reported as `OutOfSpace` when the buffer is also too small.
  (`OutOfSpace` is terminal for the whole program; a translation failure is
  terminal for one function. The old ordering could turn the second into the
  first.)
- A function the checker refuses is a translation failure naming the slot.
  No known program reaches it.
- An invocation whose memory layout fails `layout_ok` — the guest regions,
  their native backings, the coroutine stack and the descriptor not
  ordered, page-wide and pairwise disjoint — is refused with a
  `PlatformError` before generated code is entered. No mapping the runtime
  builds fails it; it is the theorem's hypothesis, checked.
- A branch to an unlabelled slot is an assembler error rather than a
  silent branch to the top of the function, and a short branch that does
  not reach is an error rather than a truncated byte. The checker refuses
  both before the assembler sees them.

## Cost, for the record

The first estimate for this work said a machine model of two to four thousand
lines and a proof several times the size of the layout proofs. The macro
split cut both: the model covers the forty-odd primitive shapes the backend
uses, and the checker's soundness is one lemma per macro rather than one per
eBPF instruction per configuration.

The aarch64 backend is untouched. It emits through typed encoders already,
so the same split applies with less restructuring; the Lean model is the new
work there.

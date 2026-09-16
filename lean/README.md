# Lean proofs

Machine-checked statements about the runtime's analysis passes — the
load-time validator, the function layout, the region analysis — and about
the x86_64 backend: the native code it emits is memory-safe. The code the
proofs describe is the code the runtime runs:

```
src/verified/                   the verified core: isa.rs, validate.rs, layout.rs,
  │                             stack.rs, region.rs, fixpoint.rs, liveness.rs,
  │                             x64_ir.rs, x64_lower.rs, x64_check.rs, x64_expand.rs
  │  compiled into the runtime as crate::verified (jit::isa re-exports it,
  │  jit::validate and function_analysis call it and render the rejection,
  │  program computes the frame geometry with it, region_analysis drives
  │  its transfer function to a fixed point, jit::emit::x86_64 lowers,
  │  checks and expands with it and only encodes the result)
  │
  │  also the library of lean/verified/Cargo.toml, a stand-alone crate
  │  charon cargo --preset=aeneas ; aeneas -backend lean
  ▼
lean/AsyncEbpf/AsyncEbpfVerified.lean   generated, do not edit
  │
  ├─ AsyncEbpf/Loop.lean                 induction rule for extracted loops
  ├─ AsyncEbpf/Validate/Spec.lean        what an accepted program looks like
  ├─ AsyncEbpf/Validate/Structure.lean   jump, call and lddw rules, read off the code
  ├─ AsyncEbpf/Validate/Proofs.lean      validate = ok → WellFormed
  ├─ AsyncEbpf/Validate/Decoder.lean     the opcode table, pinned to bytes
  ├─ AsyncEbpf/Layout/Spec.lean          what a good function layout looks like
  ├─ AsyncEbpf/Layout/Proofs.lean        partition = ok → LayoutOk
  ├─ AsyncEbpf/Layout/Decoder.lean       byte classes agree with the decoder
  ├─ AsyncEbpf/Stack/Proofs.lean         frame islands, floor and window arithmetic
  ├─ AsyncEbpf/Region/Proofs.lean        the region analysis' transfer function
  ├─ AsyncEbpf/Region/Masking.lean       live-in masking and projection
  ├─ AsyncEbpf/Liveness/Proofs.lean      the live-in solver solves its equations
  ├─ AsyncEbpf/Semantics/Machine.lean    an operational semantics of eBPF
  ├─ AsyncEbpf/Semantics/Soundness.lean  accepted programs never go wrong
  ├─ AsyncEbpf/Semantics/Functions.lean  control never leaves a function
  ├─ AsyncEbpf/Semantics/Frames.lean     unchecked frame accesses stay mapped
  ├─ AsyncEbpf/X64/Bytes.lean            byte-addressed memory
  ├─ AsyncEbpf/X64/Machine.lean          an operational semantics of the x86_64 primitives
  ├─ AsyncEbpf/X64/Contract.lean         the entry contract, the allowed set, Safe
  ├─ AsyncEbpf/X64/Tag.lean              reading the checker's abstract state
  ├─ AsyncEbpf/X64/CheckSpec.lean        the checker's walk as a chain; its rules inverted
  ├─ AsyncEbpf/X64/Abs.lean              agreement between abstract and machine states
  ├─ AsyncEbpf/X64/Run.lean              runs inside a region; the per-macro contract
  ├─ AsyncEbpf/X64/Simple.lean           the one- and two-primitive macros
  ├─ AsyncEbpf/X64/CheckedAddr.lean      the branchless bounds check
  ├─ AsyncEbpf/X64/Arith.lean            division fix-ups, the fetching atomic loop
  ├─ AsyncEbpf/X64/Calls.lean            the helper call and the lazy local call
  ├─ AsyncEbpf/X64/Expand.lean           the expansion as chunks, every label resolved
  └─ AsyncEbpf/X64/Soundness.lean        check = ok → Contract (memory safety)
```

Every analysis pass that gains a proof moves into `src/verified/`; the crate
under `lean/verified` is that directory and nothing else.

## The semantics

`Semantics/Machine.lean` is a small-step operational semantics of the
instruction set, written against the decoder extracted from
`src/verified/isa.rs` so that it and the runtime agree on what each byte
means. It models the eleven 64-bit registers, the program counter, and a call
stack whose frames save `R6`–`R9` and the frame pointer, with `R10` moving
down one stride per local call. Every ALU and jump instruction is given with
the ISA's fine print: 32-bit operations compute on the low half and
zero-extend, shift amounts are masked, division by zero is defined, `arsh` is
arithmetic at its width, 32-bit jumps compare the low halves, immediates are
sign-extended, `lddw` reads its high half from the next slot. A run ends by
`exit` at depth zero, by running off the end, or by a fault.

Memory is abstracted: a load yields any value of its width, a store changes
nothing the state records, and any memory instruction or helper may fault.
Helpers return any `R0` and may clobber `R1`–`R5`. Every real execution is one
of these, so a property proved of all of them holds of the real ones.

## What is proved

`validate_sound` (in `Semantics/Soundness.lean`): along every execution of a
program `validate` accepts, from the entry state,

- the program counter is on an instruction slot the validator walked, or
  exactly at the end of the instruction stream;
- the machine is never stuck: it can always step, halt at `exit`, or run off
  the end. It never reaches an undefined instruction, never jumps or calls
  into the high half of an `lddw`, never jumps or calls out of the program;
- every return address on the call stack is such a slot;
- `R10` is the frame base for the current call depth
  (`validate_sound_frame_pointer`), so the only instructions that ever move
  it are local calls and returns.

The last clause is what the JIT's unchecked frame-relative accesses rest on:
`frame_access` in `src/region_analysis.rs` calls "R10 still holds the frame
pointer" the one condition the backend cannot re-derive for itself, and this
shows it holds in every execution, not just at the instruction that reads it.

The proof is progress and preservation over an invariant, fed by
`validate_ok_wellFormed` (in `Validate/Proofs.lean`): every slot the
validator walks decodes, keeps its source register at or below R10 and its
destination at or below R9 unless it is a store form, and satisfies the
structural rule for its kind: a jump or local call lands on a real slot
inside the program and never on itself, an `lddw` has its zero high half. The
structural half is read off the generated `check_jump`, `check_call_kind` and
`check_structure` in `Validate/Structure.lean`.

`Decoder.lean` pins the classes the spec states through the decoder to
concrete bytes: the store forms are exactly `0x62 0x6a 0x72 0x7a 0x63 0x6b
0x73 0x7b 0xc3 0xdb`, `0x18` is the one two-slot instruction, and every
atomic's filter row bounds its source at R9.

The theorems assume the program is shorter than `2^63` slots, so that the
validator's `i64` target arithmetic is exact.

### Functions

`partition` in `src/verified/layout.rs` splits a section into local
functions (one starts at slot 0, at each container-supplied entry, and at
each local call target) and walks every function from its start, following
fallthrough and jumps but not calls. It refuses the section if the walk ever
leaves the function's range or a local call names a slot that is not a
function start. `function_analysis.rs` renders its rejection and builds the
call graph from what the walk visited.

`layout_sound` and `step_classification` (in `Semantics/Functions.lean`):
along every execution of a program `validate` and `partition` both accept,

- the program counter is always on a slot the walk visited, so inside the
  function `pc_to_func` assigns it to, and so is every return address on the
  call stack;
- every step either keeps `pc_to_func`, is a local call to a function start
  whose return address is in the caller's function, or is a return to the
  address the matching call pushed.

This is what lets the JIT translate a function at a time: no branch it
emits inside one function ever needs a target in another.

`partition_ok` (in `Layout/Proofs.lean`) is the code half: the `Layout`
`partition` returns has sorted starts beginning at 0, `pc_to_func` names the
range holding each slot, every start is marked reachable, the reachable set
is closed under slot successors within each function, and every local call
on a reachable slot targets a start. The depth-first walk is proved by a
loop invariant over its explicit worklist (`ScanInv`), through the
fixed-point induction rule in `Loop.lean`, so there is no termination
argument to make: the theorem is about what the loop returns when it does.

The layout code classifies slots by opcode byte without decoding them
(`byteEdges`); `Layout/Decoder.lean` runs the decoder on all 256 bytes to
check that every successor the semantics can take is one the byte
classification lists. The layout's over-approximation is harmless: it may
walk a slot the machine never reaches, never the reverse.

### Stack frames

`src/verified/stack.rs` holds the arithmetic the guarded guest stack rests
on. The stack is `frame_count` mapped islands of `frame_size` bytes,
`frame_stride` apart, with unmapped gaps between them. `root_frame_offset`
is where the entry frame pointer starts (the top of the highest island;
`program.rs` places the calldata slab there), `local_call_floor` is the
lowest frame pointer the JIT allows a local call from (`LOCAL_CALL_GUEST_FLOOR`
in the memory descriptor), `island_access` is the runtime's test for a
guest range lying in one island (`checked_stack_region`), and
`in_frame_window` is the region analysis' test for an `R10`-relative access
the JIT may emit with no bounds check (`frame_access`).

`frame_access_mapped` and `floor_iff_depth` (in `Semantics/Frames.lean`):
with the machine's parameters taken from the layout (`StackParams`: `R10`
starts at the top of the highest island, moves one stride per call, and the
stack admits `frame_count - 1` calls), in every execution of an accepted
program

- the frame pointer is the top of a mapped island at every reachable state
  (`frame_pointer_on_island`);
- every access `in_frame_window` admits — in particular every access the
  region analysis marks `FRAME` (`frame_hint_mapped`) — satisfies
  `island_access`: the unchecked accesses are exactly ones the checked path
  would have accepted;
- the floor test the JIT emits before a local call passes exactly when the
  semantics admits another frame.

The pure-arithmetic half (`frame_window_mapped` in `Stack/Proofs.lean`) is
the statement the `debug_assert!` in `_run` and the comment on
`frame_access` used to carry by hand.

### The region analysis

`src/verified/region.rs` is the dataflow core of `region_analysis.rs`: the
abstract domain, its meet, the bounded spill-slot table, the transfer
function, the uses/defs table, the per-slot classification and the call
signatures. `src/verified/fixpoint.rs` is the worklist that drives them to
a fixed point over one function (`solve`), and `src/verified/liveness.rs`
is the whole-program live-in solver whose table the masking reads. The
access-plan builder stays outside and calls into them.

A word on what is *not* proved. The `STACK` and `DATA` hints narrow a
bounds check the JIT keeps, so a wrong one costs a spurious fault, not
memory safety, and the analysis uses that freedom: a value loaded from
memory is a scalar, a helper's result is a scalar, spills survive calls,
and a slot the 32-entry cap refuses reads back as a scalar. Under any
natural provenance semantics each of these makes the kinds fail to
over-approximate the values, so there is no theorem of the form "the
analysis is sound" to prove, and `Region/Proofs.lean` does not pretend
otherwise. It proves the three things the runtime relies on:

- `classify_frame`: the `FRAME` hint, the one that removes a check, goes
  only to a load, store or atomic whose base register is `R10` itself and
  whose window `in_frame_window` admits, never to an atomic. With
  `frame_hint_mapped` this closes the chain from the analysis' decision to
  the mapped island;
- `transfer_R10`, `meet_from_R10`: on an instruction the validator accepts
  (destination `R10` only in a store form, atomic source not `R10`), the
  transfer function and the meet keep `R10`'s kind, so `frame_access`'s
  "R10 still holds the frame pointer" test never fails on an accepted
  program;
- `transfer_agree`: two states that agree on the spill slots, on `R10`,
  and on the registers `uses_and_defs` names as uses produce, after
  `transfer`, states that agree on the spill slots, on the registers named
  as defs, and — elsewhere — either agree or are each left untouched.

`Region/Masking.lean` is about the live-in masking of call signatures.
A caller hands its callee the caller's abstract registers, masked to the
registers the callee can read before writing (`mask_signature`), so that
callees are specialized on what they observe and not on the caller's
incidental state. The fixed point projects every state onto its slot's
live-in registers the same way (`project`, in `entry_state` and
`fixpoint::propagate`): a register that is dead at a slot never holds a
kind there. That makes the masking claim a one-line consequence:

- `entry_state_eq`, `solve_masked_eq`: a signature and its masked form
  give the same entry state whenever the mask covers the entry slot's
  live-in — which is how the loader builds the mask — and `solve` is a
  function of its entry state, so the two solutions are equal. Not merely
  the same hints: the same states at every slot.

The rest of the file says what the projection costs, which is nothing
the analysis can see. `AgreeAt` is agreement on the live registers, `R10`
and the spills; `LiveSolution` is a live-in table that solves the
equations the Rust solver computes (at every reachable slot: the slot's
uses, and every successor's live-in minus the slot's defs). Then:

- `project_agree`: a state agrees with its projection;
- `step_agree`, `trace_agree`: one transfer from states that agree at a
  slot gives states that agree at each of its successors, so along every
  path of the control-flow graph agreement is kept;
- `meet_from_agree`, `run_agree`: the meet keeps the agreement, so a
  worklist processing any sequence of slots keeps two agreeing state
  tables agreeing, whether either of them projects or not;
- `hint_agree`, `call_signature_agree`, `projection_neutral`: at every
  reachable slot, agreeing states give the same hint and the same routing
  region, and the same masked signature to every local call.

`projection_neutral` compares the projecting walk with the textbook one
that meets values in as they are, over a common schedule. It is a
statement about the algorithm, not a comparison with code that runs:
nothing in the runtime walks without projecting any more, and the hints
of real programs are pinned by the golden and plan tests, which the
projection left unchanged.

`Liveness/Proofs.lean` discharges the one hypothesis `Masking.lean` makes
about the table. `src/verified/liveness.rs` solves the whole program at
once: every section's slots end to end, each slot's function and each
function's bounds beside them, and each local call's callee resolved by
the loader, so that a call site reads its callee's entry row and every
function and every summary is one dataflow problem. It is a worklist over
intrusive predecessor and call-site lists. Then:

- `build_preds_ok`, `build_callers_ok`: every successor edge
  `fixpoint::function_successors` names is on its target's list, and every
  resolved call is on its callee's;
- `wake_ok`: waking a list queues each of its members and dequeues none,
  keeping the stack a set of distinct in-range slots (`StackInv`);
- `solve_step`, `solve_ok`: the loop keeps every slot that is not queued
  at a value satisfying its equation, so when the worklist empties the
  table satisfies every slot's equation, at every slot (`Holds`);
- `solve_live_solution`: that table is a `LiveSolution` — for the whole
  program, with each call's summary read from the table itself — over the
  successor lists `function_successors` computes, which
  `function_successors_bounds` keeps inside the slot's function.

The hypotheses (`Shape`) are what `program_live_in` builds: every index in
range, every function's entry inside it, fewer than `2^31` slots.

### The x86_64 backend

`docs/jit-memory-safety.md` says what memory safety of the emitted code
means and why the backend was restructured for it. In short: the emitter's
decisions live in `src/verified/x64_lower.rs`, which builds a list of
*macro* instructions (`x64_ir::MInsn`); `src/verified/x64_check.rs`
refuses the list unless an abstract walk over it — a tag per native
register, the native stack depth, the parked group base, liveness — admits
every guest access; `src/verified/x64_expand.rs` turns each macro into its
fixed sequence of *primitive* instructions (`x64_ir::PInsn`, one per x86
instruction); and `src/jit/emit/x86_64.rs` keeps only the encoder from
primitives to bytes and the branch fixups. `lower` runs `check` on what it
built, so what the backend returns is checked code by construction.

`X64/Machine.lean` is an operational semantics of the primitive
instruction set: sixteen registers, the four flags the checks read, a
byte-addressed memory, a program counter over the primitive list, branches
to labels rather than offsets. A call to an address outside the function is
an *external call*: it returns to the pushed return address with `rsp`,
`rbp`, `r15`, the read-only frame slots and the descriptor preserved and
everything else arbitrary — `rbx` and `r12`–`r14` among it, and guest memory
wherever the runtime mapped it. That is what the runtime promises of the
dispatcher and the callbacks, and it is no stronger than this theorem's own
conclusion for a lazily compiled callee, which is what lets the two compose. Shifts, multiplies, divides and `rol` leave the flags
arbitrary and the divide leaves `rax`/`rdx` arbitrary: over-approximations,
so every real execution is a modelled one.

`X64/Contract.lean` states the entry contract (`Entry`: the descriptor at
`[rbp - 8]`, the delta at `[rbp - 40]`, the twelve derived slots, the
descriptor's fields, the frame register at the native frame base) and the
layout facts (`Layout`: the two guest regions and their native backings are
ranges, disjoint from each other, from the first page, from the frame
scratch, from the native stack window and from the descriptor; the frame
window lies inside the stack's backing; each region is at least a page
wide), and the property: `Safe P code` says every access any reachable step
makes is inside `Allowed P` — the frame scratch, the native stack window,
the two native backings, the first page (where a failed check lands, and
which the fault handler claims), and the descriptor; `SafeStores P code`
says every range a step *writes* (`stores`, the writing part of `accesses`)
is inside the smaller `WritableAllowed P` — the native stack below the
entry `rsp`, the four writable frame slots, the two native backings and the
first page; and `Returns P code` says a `ret` at the entry `rsp` leaves
`rsp`, `rbp` and the frame register as the caller expects. `Contract` is
all three. The stores half is what a caller needs of its callee and `Safe`
does not give: `romem_kept` reads off it that the read-only frame slots and
the descriptor come back untouched, which is half of what the caller
assumed through `ExternalReturn`.

`check_safe` (in `X64/Soundness.lean`): if `x64_check::check` accepts a
macro list, then under the cage (`pointer_mask ≠ 0`), with the machine's
frame size the configured one, the machine's dispatcher the configured one
and off the function's own code, and the list ending in the trailer, every
execution of the list's expansion from an entry state satisfies both. The
trailer is a hypothesis because the checker does not insist on it by itself,
while a helper call needs the dispatcher slot that lives in it: with no slot
the macro's fallback path, which loads through the embedded helper table,
becomes reachable. `lower_safe` composes `check_safe` with `lower`'s gate and
the expansion — and discharges the trailer, which `lower` always emits: what
`translate_range` returns is safe.

The proof is macro by macro. `Abs.lean` says when an abstract state and a
machine state agree (`Agree`: `Fp` means the frame register holds its entry
value; `Checked w` means zero or a native address whose `w`-byte window is
inside one backing; `rsp` is `depth` words below its entry; `rbp` and the
read-only slots are intact; the parked group base carries its tag).
`Run.lean` states the contract every macro's expansion satisfies
(`MacroOk`: from an agreeing state every step is safe, every range it
writes is writable, `rsp` stays in the native stack window at every
position, and control leaves the macro's primitives only to the next macro,
agreeing with the checker's post-state, to a labelled slot in the entry
state, or by returning under the contract). The `rsp` clause is what the
whole-function `StackKept` is assembled from, and `romem_kept` needs it:
without it nothing says a callee's own frame lies below this activation's
frame scratch, because a register-only primitive can move `rsp` without
touching memory. `Simple.lean`, `CheckedAddr.lean`, `Arith.lean` and
`Calls.lean` prove it for each macro with the operands symbolic — the
branchless check yields zero or an in-region address on both the
frame-constants and the descriptor paths and for the two-region probe; the
division's pushes balance; the fetching atomic's loop re-dereferences a
base nothing has rewritten; the helper call's default-dispatcher path is
dead when a dispatcher is registered and its retpoline returns through the
address the call pushed; the lazy call restores the frame register it moved
by one stride. `CheckSpec.lean` turns `check = ok` into a chain of abstract
states with one rule application per macro; `Expand.lean` turns `expand`
into a concatenation of per-macro chunks and resolves every label to a
chunk start. `Soundness.lean` runs the machine invariant — the current
state is inside some macro's chunk, reached from a boundary state agreeing
with that macro's abstract pre-state — through every step.

Two things are outside the statement, deliberately. Functional
correctness, and information leaks: the native value of `R10` reaching the
guest as a value is not a memory-safety property, and `audit_escape` in the
Rust tests is what probes it. And the theorem is about one activation
entered at the head of the list, which is how the runtime enters every
function it translates (one function per range); a multi-function range,
which only the tests build, is covered for its first function.

## What is trusted

- **The x86_64 encoder and fixups.** `src/jit/emit/x86_64.rs` maps each
  primitive to bytes and resolves the relative branches; it is a table, and
  the goldens pin it byte for byte.
- **The entry trampolines and the descriptor.** `Entry` is what the
  `global_asm!` trampolines and `JitMemory` in `program.rs` establish;
  `Layout` is what the mappings establish. Also the fault handler and the
  windows it claims, the write-xor-execute discipline of the arena, the
  SysV convention, the resolver (that it returns the address of checked
  code), and the stack-exhausted callback (that it does not return).
- **The adapters.** `jit::validate` folds the embedder's helper callback into
  the list of known indices the core consults, and renders each `Reject` as
  the message embedders match on; `function_analysis` decodes the section
  bytes, renders each `LayoutReject`, and reads the call graph off the
  `Layout`; `program.rs` builds the `FrameLayout` from the configured sizes
  and adds the mapping's base to the offsets the core computes. None of these
  changes a decision. The recorded decision sweeps in `src/jit/validate.rs`
  pin every message, so a change shows up as a golden diff.
- **The JIT's floor test and native frame base.** `StackParams` states what
  the emitted code does with `R10`: starts it at the top of the highest
  island and subtracts one stride per call. On x86_64, `macroOk_lazyLocalCall`
  shows the frame register moves by exactly one stride around the callee and
  comes back; that the stride and the floor are the layout's is an adapter
  fact. On aarch64 it is checked by the backend's tests, not here.
- **The live-in adapter.** `program_live_in` lays the sections end to end
  and builds the per-slot function, per-function bounds and per-call callee
  tables `liveness::solve` reads; `Liveness/Proofs.lean` takes their shape
  (`Shape`: indices in range, entries inside their functions) as given.
  That the callee it names for a call is the function the call enters, and
  that the bounds it hands the solver are the ones the per-function
  analysis runs over, so that both walk the edges
  `fixpoint::function_successors` gives, are adapter facts like the others
  in this list. `Masking.lean` assumes of the table only what
  `LiveSolution` states, which `solve_live_solution` now proves of the
  table the solver computes, or, for `solve_masked_eq`, nothing at all
  beyond the loader masking with the entry's own row.
- **Aeneas and Charon.** The translation from Rust to Lean is trusted, as is
  the Aeneas standard library's model of `Vec`, slices and scalar arithmetic.
- **The `extract` feature.** The Charon build hides the runtime-only
  conveniences in `src/verified/` (the wire codec, `Debug`, `Hash`) behind
  `cfg(not(feature = "extract"))`. Nothing the theorems mention is behind it.

Nothing else: the proofs use no `sorry` and no `native_decide`, the generated
file declares no axioms, and `#print axioms` on the theorems lists only Lean's
`propext`, `Classical.choice` and `Quot.sound`. The byte-table facts are
checked by running the decoder on all 256 bytes inside the kernel
(`decide +kernel`).

## Building

```sh
cd lean
lake exe cache get   # Mathlib oleans, once
lake build           # checks every proof
```

The Aeneas Lean library is pinned by commit in `lakefile.toml`. `lean-toolchain`
must match the one in Aeneas' `backends/lean`.

## Regenerating

The generated file is checked in so that the proofs build without an OCaml
toolchain. To regenerate after editing `src/verified/`:

```sh
cd lean
make setup-tools   # clones and builds Charon and Aeneas under tools/, once
make extract       # -> AsyncEbpf/AsyncEbpfVerified.lean
make build
```

`setup-tools` needs a Rust nightly (Charon pins one in its `rust-toolchain`),
OCaml 5 with opam, and the packages listed in Aeneas' README. The Aeneas commit
in `lakefile.toml` and the Charon commit in that Aeneas checkout's `charon-pin`
are the pair that produced the checked-in file.

## Writing verified code

`src/verified/` is deliberately plain Rust: no closures, no iterator chains,
no `String`, no wrapping arithmetic, one loop per function. Three shapes
matter for whether the extraction is usable:

- a `match` whose arms assign local flags that the code after the match reads
  is duplicated into every arm by the control-flow reconstruction. Compute
  such flags with a function of the matched value instead;
- a `?` inside a nested loop is not supported. Put the inner loop in its own
  function;
- `==` on an enum extracts through a derived `PartialEq` that Lean cannot
  evaluate, which blocks `decide`. Compare enums with `match`;
- an early `return` inside an `if` followed by common code duplicates the
  common code into every arm. Give the arms a function that returns a value
  and branch on it once (`successors` in `layout.rs` returns a count and up
  to two targets for this reason);
- recomputing `pc + 1` after a `?` made Charon stop with an unimplemented
  binary operation; compute such values once, before the `?`;
- `?` on an `Option` extracts to an axiom (Aeneas has no model of its `Try`
  instance); spell the `match` out. `checked_add` and friends have no model
  either, so `stack.rs` writes the overflow checks by hand;
- assigning a fieldless enum variant through a literal index
  (`regs[0] = Kind::Scalar`) came out as a unit write; go through a helper
  that takes the value as an argument (`set_reg` in `region.rs`). A local
  named after its module (`let region = …` inside `mod region`) shadows the
  module's namespace in the translation;
- `Vec::pop` has no model. A worklist is a preallocated `Vec` and a height
  (`solve_from` in `fixpoint.rs`), which also makes its bound explicit.

On the Lean side, `loop_ok_induction` in `Loop.lean` is the tool for every
extracted loop: give it an invariant of the loop state and what the exit
establishes, and it needs no measure. Proofs of loop bodies should clear the
previous hypothesis at each bind (`obtain_bind` in `Layout/Proofs.lean`) and
keep indexed slots as variables rather than substituting `v[i]` for them;
otherwise the arithmetic tactics choke on the accumulated context.

Anything the runtime needs that the proofs do not — codecs, derives, helper
methods — goes behind `cfg(not(feature = "extract"))`.

## Next

`solve` is extracted but, beyond determinism, nothing is yet proved about
its loop: that it reaches a post-fixed point (every reached slot's transfer
is absorbed by its successors), and that it visits exactly the slots
`partition` marks reachable, are the natural next invariants, and the
`Run` model in `Region/Masking.lean` is the shape they would take.

The x86_64 theorem is about what `check` accepts; that `lower` never builds
a list `check` refuses is a precision property, answered today by the
goldens, the configuration and randomised sweeps and the runtime tests
rather than by a proof. Proving it — `lower = ok` without the gate implies `check = ok` — is
the natural next step, and would make the gate dead code. The aarch64
backend is untouched: it emits through typed encoders already, so the same
split applies with less restructuring, and the machine model is the new
work there.

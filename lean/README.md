# Lean proofs

Machine-checked statements about the runtime's analysis passes: the load-time
validator and the function layout. The code the proofs describe is the code
the runtime runs:

```
src/verified/                   the verified core: isa.rs, validate.rs, layout.rs,
  │                             stack.rs, region.rs
  │  compiled into the runtime as crate::verified (jit::isa re-exports it,
  │  jit::validate and function_analysis call it and render the rejection,
  │  program computes the frame geometry with it, region_analysis drives
  │  its transfer function to a fixed point)
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
  ├─ AsyncEbpf/Region/Masking.lean       live-in masking, schedule by schedule
  ├─ AsyncEbpf/Semantics/Machine.lean    an operational semantics of eBPF
  ├─ AsyncEbpf/Semantics/Soundness.lean  accepted programs never go wrong
  ├─ AsyncEbpf/Semantics/Functions.lean  control never leaves a function
  └─ AsyncEbpf/Semantics/Frames.lean     unchecked frame accesses stay mapped
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
function, the uses/defs table and the per-slot classification. The
worklists, the live-in solver and the access-plan builder stay outside and
call into it.

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
  as defs, and — elsewhere — either agree or are each left untouched. This
  is the per-instruction fact behind the live-in masking of call signatures
  (`mask_signature`): a register that is not live-in is overwritten before
  any read, so dropping it costs no precision.

`Region/Masking.lean` lifts that to the function. `LiveSolution` is a
live-in table that solves the equations the Rust solver computes (at every
reachable slot: the slot's uses, and every successor's live-in minus the
slot's defs); `AgreeAt` is agreement on the live registers, `R10` and the
spills. Then:

- `step_agree`, `trace_agree`: one transfer from states that agree at a
  slot gives states that agree at each of its successors, so along every
  path of the control-flow graph the masked and the unmasked run agree;
- `meet_from_agree`, `run_agree`: the meet keeps the agreement, so a
  worklist processing any sequence of slots keeps two agreeing state
  tables agreeing at every slot;
- `hint_agree`, `call_signature_agree`, `masked_entry_agree`,
  `masking_neutral`: at every reachable slot, `classify` gives the same
  hint and the same routing region on both sides, every local call gets
  the same masked signature (`signature_from_state` then
  `mask_signature`), and the masked and the unmasked entry states agree
  at the entry whenever the mask covers its live-in — which is how the
  loader builds the mask.

What `masking_neutral` quantifies over is a *common* schedule: the same
sequence of slots processed on both sides. The driver's two runs do not
share one. Its worklist re-queues a slot when any register changes, dead
ones included, so the masked and the unmasked run can process slots in
different orders; and `transfer` is not monotone in the kind lattice (a
fill from an untracked slot reads as a scalar, from a tracked one as the
spilled pointer), so different orders can in principle reach different
fixed points. Whether they do is the one step that is tested rather than
proved: `region_analysis::masking_fuzz::masking_is_precision_neutral`
compares the two runs on random programs and random incoming signatures,
and counts that their schedules really do diverge on a good share of them.

## What is trusted

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
  island and subtracts one stride per call. That the backends do so is
  checked by their tests, not here.
- **The dataflow drivers.** `analyze_function`'s worklist and the live-in
  solver are not extracted. `Region/Masking.lean` takes the live-in table
  as a hypothesis (`LiveSolution`, the equations the solver's fixed point
  satisfies) and the worklist's schedule as a parameter; that the solver
  returns a solution, and that the two runs' schedules — which differ —
  lead to the same result, are covered by the unit tests, not by Lean.
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
  module's namespace in the translation.

On the Lean side, `loop_ok_induction` in `Loop.lean` is the tool for every
extracted loop: give it an invariant of the loop state and what the exit
establishes, and it needs no measure. Proofs of loop bodies should clear the
previous hypothesis at each bind (`obtain_bind` in `Layout/Proofs.lean`) and
keep indexed slots as variables rather than substituting `v[i]` for them;
otherwise the arithmetic tactics choke on the accumulated context.

Anything the runtime needs that the proofs do not — codecs, derives, helper
methods — goes behind `cfg(not(feature = "extract"))`.

## Next

Closing the last gap in the masking argument — that the masked and the
unmasked run's different schedules reach the same fixed point — needs
either a confluence argument for this non-monotone transfer function or a
driver whose schedule does not depend on dead registers. Extracting the
worklist itself is the smaller part. The access-plan grouping in
`region_analysis.rs` is advisory (the backends re-derive every condition
before trusting it), so its safety is a property of the emitters, out of
reach of this approach.

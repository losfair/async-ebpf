# Lean proofs

Machine-checked statements about the runtime's analysis passes, starting with
the load-time validator. The code the proofs describe is the code the runtime
runs:

```
src/verified/                   the verified core: isa.rs, validate.rs
  │  compiled into the runtime as crate::verified (jit::isa re-exports it,
  │  jit::validate calls it and renders the rejection)
  │
  │  also the library of lean/verified/Cargo.toml, a stand-alone crate
  │  charon cargo --preset=aeneas ; aeneas -backend lean
  ▼
lean/AsyncEbpf/AsyncEbpfVerified.lean   generated, do not edit
  │
  ├─ AsyncEbpf/Validate/Spec.lean        what an accepted program looks like
  ├─ AsyncEbpf/Validate/Structure.lean   jump, call and lddw rules, read off the code
  ├─ AsyncEbpf/Validate/Proofs.lean      validate = ok → WellFormed
  ├─ AsyncEbpf/Validate/Decoder.lean     the opcode table, pinned to bytes
  ├─ AsyncEbpf/Semantics/Machine.lean    an operational semantics of eBPF
  └─ AsyncEbpf/Semantics/Soundness.lean  accepted programs never go wrong
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

## What is trusted

- **The adapter.** `jit::validate` folds the embedder's helper callback into
  the list of known indices the core consults, and renders each `Reject` as
  the message embedders match on. Neither changes a decision. The recorded
  decision sweeps in `src/jit/validate.rs` pin every message, so a change in
  either shows up as a golden diff.
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
  evaluate, which blocks `decide`. Compare enums with `match`.

Anything the runtime needs that the proofs do not — codecs, derives, helper
methods — goes behind `cfg(not(feature = "extract"))`.

## Next

The semantics is the base the analysis passes can now be proved against. In
order of value: the region analysis' transfer function against this
semantics extended with pointer provenance, the live-in non-interference
claim behind signature masking, and the function-layout partition in
`src/function_analysis.rs`.

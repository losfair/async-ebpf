# Lean proofs

Machine-checked statements about the runtime's analysis passes, starting with
the load-time validator. The chain is:

```
src/jit/validate.rs            the validator the runtime runs
  │  decision sweeps assert both accept/refuse the same programs at the same slot
  ▼
lean/ebpf_validate/src/lib.rs  the same validator in the Rust subset Aeneas translates
  │  charon cargo --preset=aeneas ; aeneas -backend lean
  ▼
lean/AsyncEbpf/EbpfValidate.lean   generated, do not edit
  │
  ├─ AsyncEbpf/Validate/Spec.lean     what an accepted program looks like
  ├─ AsyncEbpf/Validate/Proofs.lean   validate = ok → WellFormed
  └─ AsyncEbpf/Validate/Decoder.lean  the opcode table, pinned to bytes
```

## What is proved

`validate_ok_wellFormed` (in `Proofs.lean`): if the kernel validator accepts a
program, then every instruction slot the validator walks

- decodes to a defined instruction,
- has a source register at most R10, and
- names a destination at most R9, or names R10 and is a store form (`st`,
  `stx`, or an atomic), whose destination is a memory base rather than a
  written register.

The last clause is `validate_ok_no_frame_pointer_write`, the premise the JIT's
unchecked frame-relative access path rests on: `frame_access` in
`src/region_analysis.rs` calls "R10 still holds the frame pointer" the one
condition the backend cannot re-derive for itself.

`Decoder.lean` pins the classes the spec states through the decoder to
concrete bytes: the store forms are exactly `0x62 0x6a 0x72 0x7a 0x63 0x6b
0x73 0x7b 0xc3 0xdb`, and `0x18` is the one two-slot instruction.

## What is trusted

- **The kernel matches the runtime.** `ebpf_validate` is a restatement, not
  the code the runtime runs. Every decision sweep in `src/jit/validate.rs`
  (about a hundred thousand generated and enumerated programs per run) also
  puts the program to the kernel and fails if the two disagree on acceptance
  or on the rejecting slot. `cargo test --features testing --lib jit::validate`
  runs them.
- **Aeneas and Charon.** The translation from Rust to Lean is trusted, as is
  the Aeneas standard library's model of `Vec`, slices and scalar arithmetic.
- **The type transcription.** `Insn`, `Config` and `Op` in the generated file
  are the Rust types field for field.

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
toolchain. To regenerate after editing `ebpf_validate`:

```sh
cd lean
make setup-tools   # clones and builds Charon and Aeneas under tools/, once
make extract       # -> AsyncEbpf/EbpfValidate.lean
make build
```

`setup-tools` needs a Rust nightly (Charon pins one in its `rust-toolchain`),
OCaml 5 with opam, and the packages listed in Aeneas' README. The Aeneas commit
in `lakefile.toml` and the Charon commit in that Aeneas checkout's `charon-pin`
are the pair that produced the checked-in file.

## Writing the kernel

`ebpf_validate` is deliberately plain Rust: no closures, no iterator chains,
no `String`, no wrapping arithmetic, one loop per function. Three shapes matter
for the size of the generated Lean:

- a `match` whose arms assign local flags that the code after the match reads
  is duplicated into every arm by the control-flow reconstruction. Compute
  such flags with a function of the matched value instead;
- a `?` inside a nested loop is not supported. Put the inner loop in its own
  function;
- `==` on an enum extracts through a derived `PartialEq` that Lean cannot
  evaluate, which blocks `decide`. Compare enums with `match`.

The derives the runtime's tests need (`Debug`, `PartialEq` on `Insn`) are behind
the `test-support` feature so that extraction sees no `fmt` code.

## Next

The same pattern applies to the other passes. In order of value: the
function-layout partition in `src/function_analysis.rs`, the live-in
non-interference claim behind signature masking, and the region analysis'
transfer function against a concrete semantics with pointer provenance.

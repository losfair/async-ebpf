# Repository Guidelines

## Project Structure & Module Organization
- `src/` holds the Rust library. Core runtime logic lives in `src/program.rs`, with helper APIs in `src/helpers.rs`, pointer-cage memory safety in `src/pointer_cage.rs`, and ELF relocation in `src/linker.rs`.
- `src/test/` contains crate tests (Tokio-based) for execution and memory fault behavior.
- `benches/bench.rs` hosts Criterion benchmarks (requires the `testing` feature).
- `src/jit/` is the JIT: `isa.rs` (one instruction decode), `abi.rs` (the frame contract shared with the entry trampolines), `validate.rs`, `patch.rs` (aarch64's code buffer and fixups), and `emit/{x86_64,aarch64}.rs`. The x86_64 backend is an adapter: its decisions live in `src/verified/x64_lower.rs`, each macro's native sequence in `src/verified/x64_expand.rs`, `src/verified/x64_check.rs` refuses any macro list that is not memory-safe, and `src/verified/x64_encode.rs` assembles the bytes, with `x64_decode.rs` as its verified inverse (see `docs/jit-memory-safety.md`).
- `src/jit/goldens/` holds the machine code each backend is expected to emit. A diff there means code generation changed; regenerate with `ASYNC_EBPF_UPDATE_GOLDENS=1` and make the diff part of the change under review.
- `src/jit/interp.rs` is a reference interpreter written from the instruction set rather than from the JIT, so it can be used to check the JIT's semantics independently.
- `src/verified/` is the verified core: the instruction set, the load-time validator, the function layout, the guest stack's frame geometry, the region analysis' domain, transfer function, fixed point and whole-program live-in solver, the x86_64 backend's lowering, expansion, memory-safety checker, assembler and decoder, the layout check the runtime runs before entering generated code (`x64_layout.rs`) and an executable simulator of the primitives (`x64_sim.rs`) that the differential test in `src/test/x64_sim_native.rs` runs against the hardware, which `jit::isa`, `jit::validate`, `function_analysis`, `program` and `region_analysis` call. The same directory is the library of the `lean/verified` crate that Charon and Aeneas translate to Lean, so the proofs under `lean/` (see `lean/README.md`) are about the code that runs. Keep it in the Aeneas-friendly subset described there, and after changing it run `make extract` in `lean/` and rebuild the proofs.

## Build, Test, and Development Commands
- `cargo build` — build the library.
- `cargo test --features testing` — run tests; enables optional deps used by `test_util`.
- `cargo bench --features testing` — run benchmarks (Criterion).
- `cargo fmt` — format with rustfmt (configured in `rustfmt.toml`).

## Coding Style & Naming Conventions
- Rust 2021 edition; follow rustfmt with 2-space indentation (`tab_spaces = 2`).
- Use standard Rust naming: `CamelCase` for types, `snake_case` for functions/vars, and `SCREAMING_SNAKE_CASE` for consts.
- Keep public APIs documented with `///` comments.

## Testing Guidelines
- Tests are in `src/test/` and use `#[tokio::test]` plus `tracing-test`.
- The eBPF compile pipeline shells out to LLVM tools. Ensure `clang`, `llvm-link`, `opt`, and `llc` are available in PATH.
- Entrypoints are the object's exported (non-`static`) functions, named by symbol. Test fixtures need no section attributes; where they use them it is to control which functions share a section.
- Prefer adding tests alongside existing patterns in `src/test/basic.rs`.

## Commit & Pull Request Guidelines
- Git history uses short, imperative summaries (e.g., `rename`, `aarch64`). Keep commit messages concise and action-oriented.
- PRs should include: a brief change summary, testing commands run (or “not run”), and any platform constraints (Linux x86_64/aarch64 only).

## Platform & Environment Notes
- The crate supports Linux and OpenBSD on `x86_64` and `aarch64` (enforced at compile time).
- A change to code generation must come with its `src/jit/goldens/` diff. An unexplained golden change means something moved that nobody meant to move.

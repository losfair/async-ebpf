# Repository Guidelines

## Project Structure & Module Organization
- `src/` holds the Rust library. Core runtime logic lives in `src/program.rs`, with helper APIs in `src/helpers.rs`, pointer-cage memory safety in `src/pointer_cage.rs`, and ELF relocation in `src/linker.rs`.
- `src/test/` contains crate tests (Tokio-based) for execution and memory fault behavior.
- `benches/bench.rs` hosts Criterion benchmarks (requires the `testing` feature).
- `src/jit/` is the Rust JIT: `isa.rs` (one instruction decode), `abi.rs` (the frame contract shared with the entry trampolines), `validate.rs`, `patch.rs`, and `emit/{x86_64,aarch64}.rs`.
- `oracle/ubpf-sys/` holds the vendored uBPF C runtime the JIT was ported from, kept as a differential-testing oracle behind the `oracle` feature. It is the only thing that needs CMake and bindgen, and nothing in a default build links it.

## Build, Test, and Development Commands
- `cargo build` — build the library.
- `cargo test --features testing` — run tests; enables optional deps used by `test_util`.
- `cargo test --features testing,oracle` — additionally byte-diff the JIT against the vendored C. Requires CMake and libclang.
- `cargo bench --features testing` — run benchmarks (Criterion).
- `cargo fmt` — format with rustfmt (configured in `rustfmt.toml`).

## Coding Style & Naming Conventions
- Rust 2021 edition; follow rustfmt with 2-space indentation (`tab_spaces = 2`).
- Use standard Rust naming: `CamelCase` for types, `snake_case` for functions/vars, and `SCREAMING_SNAKE_CASE` for consts.
- Keep public APIs documented with `///` comments.

## Testing Guidelines
- Tests are in `src/test/` and use `#[tokio::test]` plus `tracing-test`.
- The eBPF compile pipeline shells out to LLVM tools. Ensure `clang`, `llvm-link`, `opt`, `llc`, and `llvm-objcopy` are available in PATH.
- Prefer adding tests alongside existing patterns in `src/test/basic.rs`.

## Commit & Pull Request Guidelines
- Git history uses short, imperative summaries (e.g., `rename`, `aarch64`). Keep commit messages concise and action-oriented.
- PRs should include: a brief change summary, testing commands run (or “not run”), and any platform constraints (Linux x86_64/aarch64 only).

## Platform & Environment Notes
- The crate supports Linux and OpenBSD on `x86_64` and `aarch64` (enforced at compile time).
- Changes touching `oracle/ubpf-sys/` should note external toolchain requirements (CMake, bindgen/clang).
- The Rust JIT must stay byte-identical to the vendored C while the oracle exists. If a change makes the two differ, that is a finding to raise, not a diff to accept.

# async-ebpf

Async-friendly, fully preemptive userspace eBPF runtime.

## Supported platforms

- Linux: x86-64 and arm64
- OpenBSD: amd64 and arm64

Building requires only a Rust toolchain. Tests require the LLVM BPF tools
(`clang`, `llvm-link`, `opt`, `llc`, and `llvm-objcopy`), which compile the C
fixtures the test suite runs.

The JIT is written in Rust. A vendored copy of the uBPF C runtime it was ported
from is kept as a differential-testing oracle behind the `oracle` feature, which
is the only configuration that needs CMake and libclang:

```sh
cargo test --features testing,oracle
```

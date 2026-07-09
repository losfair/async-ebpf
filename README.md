# async-ebpf

Async-friendly, fully preemptive userspace eBPF runtime.

## Supported platforms

- Linux: x86-64 and arm64
- OpenBSD: amd64 and arm64

Building requires CMake and libclang. Tests additionally require the LLVM BPF
tools (`clang`, `llvm-link`, `opt`, `llc`, and `llvm-objcopy`).

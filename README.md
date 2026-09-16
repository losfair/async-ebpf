# async-ebpf

Async-friendly, fully preemptive userspace eBPF runtime.

## Supported platforms

- Linux: x86-64 and arm64
- macOS: Intel and Apple silicon
- OpenBSD: amd64 and arm64

Building requires only a Rust toolchain. Tests additionally require the LLVM BPF
tools (`clang`, `llvm-link`, `opt`, and `llc`), which compile the fixtures the
test suite runs.

## Entrypoints

A program's entrypoints are its exported functions: every non-`static` C
function, under its own name. No section attributes are needed, and the object
is loaded as the compiler emits it, `.text` included.

```c
static int helper(int x) { return x + 7; }
int entry(void) { return helper(35); }
```

```rust,ignore
program.run(&timeslice, &timeslicer, "entry", &mut [], &calldata, &preemption).await?;
```

`static` functions are internal to the program and cannot be run from the host.

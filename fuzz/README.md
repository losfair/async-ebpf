# Fuzzing

This crate contains cargo-fuzz targets for the JIT/runtime security boundary.

Run with:

```sh
ASAN_OPTIONS=detect_leaks=0 cargo +nightly fuzz run jit_memory_safety
ASAN_OPTIONS=detect_leaks=0 cargo +nightly fuzz run host_pointer_escape
```

The targets generate minimal BPF ELF objects directly, so fuzzing does not shell
out to LLVM tools in the hot path. `jit_memory_safety` mutates valid programs
that exercise stack/data loads, stores, arithmetic, branches, and memory faults.
`host_pointer_escape` exposes a real host pointer through a helper and verifies
that JIT pointer masking prevents guest stores from modifying that host memory.

Leak detection is disabled for the bounded fuzz jobs because LeakSanitizer can
fail at process shutdown on the supported sanitizer runner configurations. The
targets still run with cargo-fuzz coverage instrumentation and AddressSanitizer.

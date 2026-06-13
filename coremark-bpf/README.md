# CoreMark BPF Adaptation

The CI job clones upstream CoreMark at `1f483d5`; this directory only contains
the async-ebpf port layer and the patch rules live in `examples/coremark.rs`.
The patches are deliberately small and are guarded by exact string matches so a
future CoreMark update fails loudly instead of silently changing the benchmark.

The goal is to run the standard CoreMark list, matrix, and state workloads under
async-ebpf while preserving CoreMark's CRCs. If a change produces a bad CRC, the
run is invalid.

## Port Layer

Upstream CoreMark is a hosted C program: it parses command-line arguments, uses
a port layer for timing and printing, and reports through stdout. The BPF
benchmark cannot call libc or own the timing loop, so `coremark_entry.c`
provides a single `coremark` section entrypoint.

The Rust example passes the iteration count through calldata, times execution on
the host side, and receives the CRCs packed into the return value. The entrypoint
uses CoreMark's normal seeds and 2 KiB data size, allocates the benchmark memory
on the BPF stack, runs `iterate`, and validates the expected per-workload CRCs:

- list: `0xe714`
- matrix: `0x1fd7`
- state: `0x8e3a`

`coremark.h` is a minimal header for the BPF build. It defines CoreMark's data
types and structures without including the hosted port layer. `core_util_min.c`
contains the CRC helpers needed by the three workloads.

## Source Patches

### `core_list_join.c`

The upstream merge sort takes a C function pointer comparator. eBPF local calls
are direct calls; async-ebpf's linker and call-graph validator do not support an
indirect function-pointer call target. The patch replaces the function pointer
with a small selector (`CMP_IDX` or `CMP_COMPLEX`) and dispatches to the same two
comparators at the call site.

CoreMark also has local functions with six parameters:

- `core_list_insert_new`
- `core_bench_state`

The BPF C calling convention only has five argument registers (`R1` through
`R5`) for local calls. The patch packs the extra stable arguments into small
stack structs (`list_alloc_state` and `state_bench_args`) and passes a pointer
to the struct instead. The callee still reads the same values, so this changes
the call shape, not the benchmark algorithm.

### `core_state.c`

The state workload initializes input from fixed string pattern tables. Upstream
CoreMark represents these as arrays of pointers to string literals, which
requires a rodata pointer table and relocations to other rodata objects.

The BPF adaptation replaces those pointer tables with `state_pattern_char`,
which returns the same bytes from packed integer constants. That avoids rodata
pointer indirection while preserving the generated state input and CRCs.

The `core_bench_state` signature is also rewritten to take `state_bench_args`
for the five-argument BPF call limit described above.

### `core_matrix.c`

The matrix seed step is rewritten from signed modulo to explicit unsigned
modulo:

```c
seed = (ee_s32)(((ee_u32)(order * seed)) % 65536U);
```

CoreMark's intended behavior here is a seed reduced to 16 bits. Making the
modulo unsigned avoids depending on signed `%` lowering in the BPF backend and
keeps the generated matrix data stable across optimization. The CRC check
verifies that the patched matrix workload still matches CoreMark.

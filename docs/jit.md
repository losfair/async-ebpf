# Lazy per-function JIT design

## Goal

`async-ebpf` currently JIT-compiles every executable ELF section during
`ProgramLoader::load`. The target design is to make loading validate and prepare
metadata only, then JIT-compile individual eBPF functions on first execution.

The code cache should be a single large native-code arena:

- allocate one code region up front with guard pages;
- keep unused code pages `PROT_NONE`;
- append generated function variants into the region;
- temporarily make pages writable while emitting or patching code;
- flip emitted pages to `PROT_READ | PROT_EXEC`;
- never leave pages writable and executable at the same time.

Function code should be specialized by the pointer-region tags known at a
particular call site. The important tags are stack, data, scalar, unknown, and
uninitialized, matching the region-analysis model.

## Load-time work

Loading should still perform the work that is independent of the eventual
specialization:

1. Allocate the pointer cage.
2. Copy the ELF into the data region.
3. Relocate the ELF.
4. Freeze the data region.
5. Run uBPF validation for each executable section.
6. Run shared local-function layout validation.
7. Allocate the native code arena as `PROT_NONE`.
8. Store per-section metadata, but do not translate eBPF to native code.

Loading must not perform strict region validation. Local functions are
polymorphic over their incoming pointer tags, so an access that is unroutable
from a section-wide or default entry state may be routable for a concrete local
call specialization. Strict region validation happens only when compiling a
specific function variant.

The existing `validate_local_call_graph` logic in `src/linker.rs` should be
extracted into a reusable function-layout pass. `region_analysis` currently
walks local-call CFG edges, but the reusable boundary/range logic lives in the
linker validation path. The new pass should produce a single source of truth for
validation, region analysis, and function-granular JIT.

Suggested shape:

```rust
struct FunctionLayout {
  functions: Vec<FunctionInfo>,
  pc_to_func: Vec<usize>,
}

struct FunctionInfo {
  start_pc: usize,
  end_pc: usize,
  callees: Vec<usize>,
  callers: Vec<usize>,
}
```

The pass should also retain the current guarantees:

- local-call targets must be function starts;
- intra-function jumps and fallthrough must stay inside the function range;
- recursion is rejected;
- local-call depth remains bounded.

## Runtime structures

`Entrypoint` should become a lazy handle rather than a raw native pointer:

```rust
struct Section {
  name: String,
  code_vaddr: usize,
  code_len: usize,
  layout: FunctionLayout,
  variants: Vec<FunctionVariants>,
}

struct FunctionVariants {
  by_signature: HashMap<PointerSignature, CompiledFunction>,
}

struct CompiledFunction {
  ptr: usize,
  len: usize,
  signature: PointerSignature,
}
```

`PointerSignature` should describe the callee's incoming register kinds. At a
minimum this needs `R1` through `R5`, and it may include callee-saved registers
if the analysis needs them for precision or soundness. `R10` is always stack.

Because `Program::run` takes `&self`, compilation needs interior mutability.
Programs are already pinned to one thread, so `RefCell` is a reasonable starting
point unless the execution model later changes.

## Region analysis

Region analysis should become function-aware. Instead of one section-wide entry
state, it should support:

```rust
analyze_function(
  code: &[u8],
  layout: &FunctionLayout,
  function_index: usize,
  incoming: PointerSignature,
  data_lo: u64,
  data_hi: u64,
) -> FunctionRegionAnalysis
```

The analysis result should include:

- per-instruction region hints for the function's instruction range;
- unresolved memory accesses for strict static-region mode;
- outgoing register state at each local-call site.

The outgoing state at a local-call site determines the callee's specialization
key. For example, the same callee may be compiled once for `R1=stack` and once
for `R1=data`.

The key is masked to the registers the callee can observe — those it may read
before writing, transitively through its own callees (`function_live_in`). A
register outside that set is overwritten before any read on every path, so no
hint, unresolved access, or onward signature can depend on it; masking it costs
no precision and keeps a callee from being split over the caller's incidental
live state, which would otherwise compound down the call graph.

For a section entrypoint, the initial signature is:

- `R1 = Stack`, because calldata lives on the guest stack;
- `R10 = Stack`;
- every other register `Scalar`, because the entry trampoline zeroes them.

## Local-call resolver stubs

Local eBPF calls should use small native resolver stubs, not eager recursive
compilation during parent compilation.

The generated local-call sequence should call through a resolver slot:

1. The slot initially points at a resolver stub.
2. The first execution enters the stub.
3. The stub preserves the JIT's BPF register state and native call-frame
   invariants.
4. The stub yields out to Rust using the same coroutine/yielder mechanism used
   by external helpers.
5. Rust compiles the callee variant selected by the call-site pointer signature.
6. Rust stores the compiled callee in the per-program function-variant cache.
7. The stub resumes, transfers control to the compiled callee, and returns
   normally to the original caller.
8. Later calls enter the same resolver host function, which returns the cached
   native callee pointer without suspending back to the runtime.

This is similar to helper dispatch because it yields to the host, but it is not
the same ABI as a helper call. A helper receives only `R1` through `R5` and
returns a value in `R0`. A local function call must preserve the JIT's complete
eBPF machine state and stack-frame bookkeeping, including callee-saved registers
and frame-pointer behavior.

Suggested dispatch extension:

```rust
enum DispatchKind {
  Helper {
    index: u32,
    args: [u64; 5],
  },
  LazyLocalCall {
    resolver_id: u32,
  },
  AsyncPreemption,
  MemoryFault {
    addr: usize,
  },
}
```

The current flat `Dispatch` struct can also be extended with an optional
`lazy_local_call` field if that is less disruptive.

## Why uBPF needs changes

Passing a per-function eBPF slice to the current `ubpf_load` and
`ubpf_translate_ex` APIs is not enough for correct local functions.

Slicing works only for a standalone leaf function:

- internal PC-relative jumps remain valid after slicing;
- relocated data pointers remain valid;
- there are no local calls to resolve.

It does not work for general local functions:

- local-call immediates target PCs in the original section, so they become
  invalid or out of bounds after slicing;
- uBPF currently emits local calls as native calls inside one generated code
  body and resolves them through `pc_locs`;
- a separately translated slice has the public program ABI
  `fn(ctx, mem_len, stack, stack_len)`, not the internal native ABI expected by
  a local eBPF callee;
- the external-helper ABI cannot marshal the full eBPF register file or local
  stack-frame state.

The smallest useful uBPF change is a function-granular translation mode:

- translate only `[start_pc, end_pc)`;
- use caller-provided region hints for that range;
- reject or externalize any branch that leaves the function range;
- emit local calls through caller-provided resolver slots;
- keep uBPF's existing internal register mapping, prologue/epilogue, helper
  dispatch, masked memory access, and stack-frame conventions.

## Code arena and protection

The native code arena should track:

- allocation base and guard sizes;
- append offset;
- executable high-water mark;
- page size;
- resolver ids and their owning call-site metadata.

When emitting a function variant:

1. Reserve aligned space from the append pointer.
2. `mprotect` the affected pages to `PROT_READ | PROT_WRITE`.
3. Ask the function-granular uBPF JIT to write into the reserved range.
4. Flush the instruction cache where required, especially on aarch64.
5. `mprotect` the emitted pages to `PROT_READ | PROT_EXEC`.
6. Advance the executable high-water mark.

The current implementation does not patch generated call slots after the first
call. It avoids repeated compilation by consulting the per-program function
cache in the resolver host function. Direct slot patching can still be added
later if the remaining host-call overhead matters.

## Signal and preemption handling

`ACTIVE_JIT_CODE_ZONE` currently records the active entrypoint's native pointer
range. With lazy per-function code, execution may move through multiple compiled
function ranges and resolver stubs.

The signal handlers should accept PCs anywhere in the generated-code arena's
active executable span, not just the original entry function. Otherwise memory
fault and async preemption handling may incorrectly fall through to the default
signal handler while executing a lazily compiled callee.

## Error behavior

Errors that previously happened at load time may move to first execution:

- native code arena exhaustion;
- function-specific translation failure;
- strict static-region failure for a particular specialization;
- architecture-specific branch/literal range failures.

The public error should still be surfaced through `Program::run`, because that
is the point where lazy compilation occurs.

## Test plan

Add focused tests for:

- loading does not JIT-translate every function;
- first entrypoint execution compiles the entry function;
- first local-call execution yields to the host and compiles the callee;
- a second local call reuses the patched resolver slot;
- one callee can have multiple variants for different pointer signatures;
- strict static-region mode fails when a specialization still has unresolved
  accesses;
- code-size exhaustion is reported at first execution;
- memory faults and async preemption work from lazily compiled callees;
- behavior remains correct on x86_64 and aarch64.

Existing runtime tests should continue to pass unchanged after the lazy JIT is
complete.

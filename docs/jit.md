# Lazy per-function JIT design

## What this describes

`async-ebpf` does not JIT-compile a program at load time. `ProgramLoader::load`
validates the image and prepares metadata; individual eBPF functions are
translated to native code the first time they are executed, and are specialized
by the pointer-region tags known at the call site that reached them.

This document describes that design and the reasoning behind it. The JIT itself
lives in `src/jit`; see `src/jit/mod.rs` for its interface.

The code cache is a single large native-code arena:

- one code region is allocated up front, with `PROT_NONE` guard pages on each
  side and a randomized guard size;
- unused code pages stay `PROT_NONE`;
- generated function variants are appended into the region;
- pages are made writable only while emitting or patching code;
- emitted pages are flipped to `PROT_READ | PROT_EXEC`;
- pages are never writable and executable at the same time.

Function code is specialized by the pointer-region tags known at a particular
call site. The tags are stack, data, scalar, unknown, and uninitialized, matching
the region-analysis model in `src/region_analysis.rs`.

## Load-time work

Loading performs only the work that is independent of the eventual
specialization:

1. Allocate the pointer cage.
2. Copy the ELF into the data region.
3. Relocate the ELF.
4. Freeze the data region.
5. Validate each executable section (`jit::Translator::load`).
6. Run shared local-function layout validation.
7. Allocate the native code arena as `PROT_NONE`.
8. Store per-section metadata, but do not translate eBPF to native code.

Loading deliberately does *not* perform strict region validation. Local functions
are polymorphic over their incoming pointer tags, so an access that is unroutable
from a section-wide or default entry state may be routable for a concrete local
call specialization. Strict region validation therefore happens only when
compiling a specific function variant, which is also why
`ProgramLoader::require_static_region_analysis` is a per-variant guarantee rather
than a load-time one.

The function-layout pass lives in `src/function_analysis.rs` and is the single
source of truth shared by validation, region analysis, and the function-granular
JIT. `src/linker.rs` calls into it rather than carrying its own copy of the
boundary and range logic.

```rust
struct FunctionLayout {
  functions: Vec<FunctionInfo>,
  pc_to_func: Vec<usize>,
  arg_masks: Vec<RegMask>,
}

struct FunctionInfo {
  start_pc: usize,
  end_pc: usize,
  callees: Vec<usize>,
  callers: Vec<usize>,
}
```

The pass enforces:

- local-call targets must be function starts;
- intra-function jumps and fallthrough must stay inside the function range;
- recursion is rejected;
- local-call depth is bounded by `MAX_LOCAL_CALL_DEPTH`.

The depth bound is load-bearing beyond the call graph itself: every local
function is charged one fixed frame, so a bounded depth is what makes the guest
stack window a fixed size and what justifies the unchecked frame-access window
below `R10`.

## Runtime structures

An entrypoint is a lazy handle rather than a raw native pointer. Per section:

```rust
struct Section {
  translator: jit::Translator,
  code_vaddr: usize,
  code_len: usize,
  layout: FunctionLayout,
  functions: Vec<FunctionState>,
}

struct FunctionState {
  compiled: HashMap<PointerSignature, FunctionCompilation>,
}

enum FunctionCompilation {
  Succeeded(Entrypoint),
  Failed(RuntimeError),
}
```

Failures are cached alongside successes, so a variant that does not compile is
not retried on every call.

`PointerSignature` describes the callee's incoming register kinds, one per eBPF
register. `R10` is always stack.

Because `Program::run` takes `&self`, compilation needs interior mutability.
Programs are pinned to one thread, so `RefCell` is enough.

## Region analysis

Region analysis is function-aware:

```rust
fn analyze_function(
  code: &[u8],
  start_pc: usize,
  end_pc: usize,
  incoming: PointerSignature,
  data_lo: u64,
  data_hi: u64,
  layout: &FunctionLayout,
) -> FunctionRegionAnalysis
```

The result carries:

- per-instruction region hints for the function's instruction range;
- an access plan, grouping runs of accesses that share a base register;
- unresolved memory accesses, for strict static-region mode;
- outgoing register state at each local-call site.

The hints and the plan are handed to the JIT as `jit::TranslationInputs`, and
both are advisory: the backend re-derives every condition it can see for itself
and falls back to a fully checked access whenever a hint or plan entry does not
hold. A wrong analysis costs speed, not safety.

The outgoing state at a local-call site determines the callee's specialization
key. The same callee may be compiled once for `R1=stack` and once for `R1=data`.

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

Local eBPF calls go through resolver slots rather than being compiled eagerly
along with their caller.

The generated local-call sequence calls through a resolver slot:

1. The slot initially points at a resolver stub.
2. The first execution enters the stub.
3. The stub preserves the JIT's eBPF register state and native call-frame
   invariants.
4. The stub yields out to Rust using the same coroutine/yielder mechanism used
   by external helpers.
5. Rust compiles the callee variant selected by the call-site pointer signature.
6. Rust stores the compiled callee in the per-program function-variant cache.
7. The stub resumes, transfers control to the compiled callee, and returns
   normally to the original caller.
8. Later calls enter the same resolver host function, which returns the cached
   native callee pointer without suspending back to the runtime.

This resembles helper dispatch in that it yields to the host, but it is not the
same ABI. A helper receives only `R1` through `R5` and returns a value in `R0`. A
local function call must preserve the JIT's complete eBPF machine state and
stack-frame bookkeeping, including callee-saved registers and frame-pointer
behavior. The resolver's return value — the callee's native code address —
arrives in the host ABI return register, which the backend maps to eBPF `R0`, so
the call sequence saves and restores `R0` around it.

Dispatch back to the host distinguishes the cases:

```rust
struct Dispatch {
  async_preemption: bool,
  memory_access_error: Option<usize>,
  lazy_local_call: Option<u32>,

  index: u32,
  arg1: u64,
  // ... arg2 ..= arg5
}
```

## Why translation is function-granular

Handing the JIT a per-function slice of the section's bytecode is not enough on
its own, which is why `jit::Translator::translate_range` takes a range into the
whole program rather than a standalone buffer.

Slicing alone would work for a standalone leaf function:

- internal PC-relative jumps remain valid after slicing;
- relocated data pointers remain valid;
- there are no local calls to resolve.

It does not work for general local functions:

- local-call immediates target PCs in the original section, so they become
  invalid or out of bounds after slicing;
- a local call compiled as a direct native call would have to point at code
  that has not been generated yet, and may never be;
- a slice translated as if it were a whole program is entered through the
  program entry ABI, which is not the internal native ABI a local eBPF callee is
  entered with;
- the external-helper ABI cannot marshal the full eBPF register file or local
  stack-frame state.

What the JIT provides instead:

- translate only `[start_pc, end_pc)`, where the range must be *exactly one*
  local function: it begins at pc 0 or at a local function entry, ends at the
  next entry or at the end of the program, and contains no entry in between.
  There is no whole-program mode — a range holding two functions is refused,
  not compiled, so the prologue can be emitted once and every `EXIT` can pop
  what it pushed;
- consume caller-provided region hints and access plan for that range;
- reject any branch that leaves the function range, rather than emitting a jump
  to code that is not in this buffer;
- emit local calls through caller-provided resolver ids;
- keep one internal register mapping, prologue/epilogue, helper dispatch, masked
  memory access, and stack-frame convention across all of the above, so that
  separately compiled functions can call each other.

## Code arena and protection

The native code arena tracks:

- allocation base and guard sizes;
- append offset;
- executable high-water mark;
- page size;
- resolver ids and their owning call-site metadata.

Emitting a function variant:

1. Reserve aligned space from the append pointer.
2. `mprotect` the affected pages to `PROT_READ | PROT_WRITE`.
3. Translate the function's range into the reserved space.
4. Flush the instruction cache where required — `jit::clear_instruction_cache`,
   which is a real sequence on aarch64 and a no-op on x86_64.
5. `mprotect` the emitted pages to `PROT_READ | PROT_EXEC`, and the rest of the
   arena back to `PROT_NONE`.
6. Advance the executable high-water mark.

Generated call slots are not patched after the first call. Repeated compilation
is avoided by consulting the per-program function cache in the resolver host
function instead. Direct slot patching could still be added if the remaining
host-call overhead matters.

## Signal and preemption handling

`ACTIVE_JIT_CODE_ZONE` records the whole code arena's range, not the active
entrypoint's. With lazy per-function code, execution moves through multiple
compiled function ranges and resolver stubs, so the signal handlers accept PCs
anywhere in the arena's active executable span. Recording only the entry
function's range would make memory-fault and async-preemption handling fall
through to the default signal handler while executing a lazily compiled callee.

## Error behavior

Errors that would otherwise happen at load time happen at first execution:

- native code arena exhaustion;
- function-specific translation failure;
- strict static-region failure for a particular specialization;
- architecture-specific branch/literal range failures.

These are surfaced through `Program::run`, because that is the point where lazy
compilation occurs.

Arena exhaustion is distinguished from an ordinary translation failure and is
terminal for the whole program rather than for one function: the arena never
shrinks, so nothing can be compiled after it runs out. It is reported against the
configured code-size limit, so the message names the budget rather than the
JIT's internal out-of-space condition.

## Tests

The behaviour specific to lazy, per-function, specialized compilation is
exercised in `src/test/lazy_local_call.rs`:

- the deepest accepted call chain fits alongside the largest calldata;
- a lazy call leaks nothing into the callee's registers;
- a branch-heavy function grows the patch tables without tripping their limits;
- signature registers the callee cannot observe do not multiply
  specializations, and observed ones do;
- lazy compilation is charged to the caller's timeslice, and a compilation storm
  does not starve the async runtime;
- code-budget exhaustion names the budget, and is terminal for the program.

`src/test/jit_limits.rs` covers the arena and per-section code-size ceilings;
`src/test/entry_isolation.rs` covers what a lazily compiled callee can observe in
its registers, including `R0` across the resolver; `src/test/preemption.rs`
covers async preemption from inside a local-call loop. All of these run on both
x86_64 and aarch64.

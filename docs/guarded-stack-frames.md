# Sparse guarded eBPF stack frames

## Status and goal

This document describes the optional guest-stack layout that detects an eBPF
function walking directly out of its own stack frame and into an adjacent
caller's frame. It is the default layout when the logical frame is aligned to
the host page size. The loader automatically uses the contiguous layout when
the default frame cannot be page-isolated. Use
`ProgramLoader::with_guarded_stack_frames(false)` to select the contiguous
compatibility layout, including for logical frame sizes that are not aligned to
the host page size.

The design has three constraints:

- valid frame-relative loads and stores must remain a single native memory
  instruction;
- local calls must not gain additional hot-path instructions;
- correctness must not depend on region analysis proving that an access stays
  inside its frame.

The mechanism uses inaccessible virtual-address gaps between the mappings that
back successive eBPF frames. The eBPF guest address space is made sparse in the
same way as its native backing, preserving the JIT's existing affine address
translation.

This changes only the eBPF guest stack. The native coroutine stack remains a
normal contiguous `DefaultStack`, with its existing guard, sizing, and
exhaustion check.

## Current behavior

The compatibility guest stack is one contiguous `GuardedRegion`. Its two outer
guard pages protect the allocation as a whole. They cannot distinguish two
adjacent eBPF call frames within that allocation.

The JIT carries eBPF `R10` as a native pointer into the guest-stack backing. A
load or store whose base is an unmodified `R10` and whose complete byte range is
inside `[R10 - stack_frame_size, R10)` takes the `FRAME` fast path and is emitted
without a bounds check. An access outside that window falls back to a check
against the complete guest-stack allocation. It therefore succeeds if its
address happens to be in a caller's frame.

A local call currently moves `R10` down by `stack_frame_size` and restores it on
return. Independently, it checks that the guest-stack allocation has room for
another complete eBPF frame and that the native coroutine stack retains its
emergency reserve.

## Sparse layout

Let:

```text
F = configured bytes in one eBPF frame
S = virtual-address stride between successive R10 values
G = S - F, the inaccessible gap between frames
```

Choose the stride as:

```text
S = next_power_of_two(F + 32,768)
G = S - F
```

Both `F` and `S` must be multiples of the host page size. The power-of-two
stride is not required for protection, but simplifies layout calculations and
usually remains cheap to materialize in generated code.

The `32,768` minimum gap follows from the eBPF instruction encoding. A memory
instruction has a signed 16-bit displacement, whose greatest positive value is
32,767. An access based directly on a callee's `R10` therefore cannot skip the
whole gap and begin in the caller's mapped frame. A wide access that starts near
the end of the gap still touches a `PROT_NONE` page and faults.

The address space is arranged from high to low as follows:

```text
                    higher addresses

  mapped calldata slab
  ------------------------- R10 for the root function
  mapped root frame                         F bytes
  -------------------------------------------------
  PROT_NONE gap                             G bytes
  ------------------------- R10 for its callee
  mapped callee frame                       F bytes
  -------------------------------------------------
  PROT_NONE gap                             G bytes
  ------------------------- R10 for the next callee
  mapped callee frame                       F bytes

                    lower addresses
```

For `N` frames, the sparse stack address span is approximately:

```text
(N - 1) * S + F + calldata_slab_size
```

Only the frame islands and calldata slab are readable and writable. Gaps and
outer guards remain `PROT_NONE` and consume no physical pages.

## Mirrored guest and native addresses

The guest stack window reserved by `PointerCage` must use the same sparse
offsets as the native mapping. If a frame begins at offset `k` in guest space,
its native backing also begins at offset `k` from `stack_native_base`.

The existing translation consequently remains affine:

```text
native = stack_native_base + (guest - stack_guest_bottom)
```

This property is load-bearing. It means:

- the entry trampoline can continue to translate `R10` once;
- `FRAME_DELTA_OFFSET` remains one invocation-wide constant;
- reading `R10` as an eBPF value still subtracts that constant;
- checked stack accesses retain their existing instruction sequence;
- an address in a guest gap translates to the matching native `PROT_NONE` gap;
- a caller-frame pointer passed explicitly to a callee continues to refer to
  the caller's mapped frame.

Using contiguous guest addresses with sparse native backing would require a
frame-index lookup on checked accesses and would not meet the hot-path goal.

Sparse guest addresses do make the distance between successive observable
`R10` values equal to `S` instead of `F`. Compilers normally treat stack
pointers as opaque, but this is an observable ABI change for programs that
compare stack pointers belonging to different call frames. The contiguous
compatibility mode remains available for programs that depend on the old
distance.

## JIT configuration and code generation

The JIT needs separate frame-window and frame-stride values:

```rust
pub stack_frame_size: u32;
pub stack_frame_stride: u32;
```

`stack_frame_size` continues to control:

- the `FRAME` region hint;
- the backend's independent fast-path checks;
- the valid interval `[R10 - F, R10)`;
- the eBPF compiler's local-frame ABI.

Only local-call movement uses `stack_frame_stride`. On x86-64, for example:

```asm
sub r15, stack_frame_stride
call callee
add r15, stack_frame_stride
```

replaces the existing additions and subtractions of `stack_frame_size`. The
same replacement applies to `x23` on aarch64. This changes an immediate, not
the instruction count. The frame fast path and all ordinary memory-access
sequences remain unchanged.

`emit_frame_access_ok` must continue comparing the instruction displacement
against `stack_frame_size`, never the stride. The gap is not usable frame
space.

The lowest native `R10` from which a local call is allowed becomes:

```text
stack_native_base + F + S
```

Subtracting `S` from that value places the callee's `R10` at the top of the
lowest mapped frame. The native coroutine-stack floor and
`NATIVE_LOCAL_CALL_BUDGET` are unchanged.

## Runtime representation

Replace `ExecContext::guest_stack: GuardedRegion` in guarded mode with a
structure along these lines:

```rust
struct SparseGuestStack {
  region: MmapRaw,
  native_base_offset: usize,
  address_span: usize,
  frame_size: usize,
  frame_stride: usize,
  frame_count: usize,
  calldata_offset: usize,
  calldata_capacity: usize,
}
```

Construction performs the following work:

1. Reserve the complete native address span with `PROT_NONE` protection.
2. Retain an outer guard page at both ends.
3. Change only each frame island to `PROT_READ | PROT_WRITE`.
4. Map a scrubbed calldata slab immediately above the root `R10`.
5. Leave each inter-frame gap as `PROT_NONE`.

The context pool key must include the layout parameters, at least frame size,
stride, frame count, and page size. Reusing a context does not require
rebuilding its mappings.

The current whole-slice scrub cannot cross inaccessible gaps. Replace it with
iteration over the mapped islands and calldata slab. The number of bytes
scrubbed remains proportional to writable guest-stack capacity, not the sparse
address span.

Calldata should occupy a fixed slab directly above the root `R10`, rather than
being placed at a variable distance from it based on the calldata length. The
slab must be scrubbed before each invocation, and only the requested prefix is
exposed as calldata. Padding in its last page remains mapped because page
protection cannot express a partial-page boundary.

## Stack capacity and pointer-cage sizing

The public `guest_stack_size` should continue to describe writable stack
capacity, not virtual-address consumption. The loader derives the frame count
and sparse span separately. For example:

```text
frame_count = floor((guest_stack_size - calldata_headroom) / F)
sparse_span = (frame_count - 1) * S + F + calldata_slab_size
```

Any unused remainder should not silently enlarge a frame; doing so would make
the protected frame boundary disagree with `F`. The loader may either leave the
remainder unavailable in guarded mode or require the writable capacity to be
an exact multiple after calldata headroom. Leaving it unavailable is more
compatible with the existing API, provided the effective frame count is
reported clearly.

`PointerCage::new` must reserve `sparse_span` for the stack rather than
`guest_stack_size`. The cage's current 2 GiB addressability ceiling applies to
the expanded span. Guarded mode therefore admits a smaller maximum writable
stack and must fail cleanly if expansion cannot fit.

The native coroutine stack must be sized from `frame_count`, not from the sparse
span:

```text
native_stack_size = NATIVE_STACK_RESERVE
                  + frame_count * NATIVE_LOCAL_CALL_BUDGET
```

Charging native stack for the inaccessible gaps would waste memory and confuse
two independent resources.

## Page-size requirement

Exact frame boundaries require:

```text
F % host_page_size == 0
```

The default 4 KiB frame can therefore use this mode on a 4 KiB-page host. It
cannot be protected exactly on a host with 16 KiB or 64 KiB pages. Mapping a
4 KiB logical frame inside a larger writable page would leave undetectable
out-of-frame bytes and must not be presented as frame isolation.

Explicitly requiring guarded mode rejects a configured frame size that is not
page-aligned. The loader's automatic default falls back to the contiguous
layout on such a host. Supporting a 64 KiB frame later requires widening the
current `u16` frame-size representation before layout or code-generation work,
because 65,536 does not fit in it.

## Checked accesses and access groups

The generated bounds check may continue treating the complete sparse span as
one stack region. A gap address passes the inexpensive outer-range comparison,
is translated affinely, and then faults on `PROT_NONE`. Adding a per-frame
membership test would defeat the purpose of the design.

Access groups also need no new generated checks. Their individual instruction
offsets use the same signed 16-bit field, and their maximum grouped span is
smaller than the minimum gap. A group that resolves into a gap faults rather
than reaching an adjacent frame.

Host helper validation is different. `JitMemory::checked_region` must not
construct a Rust reference into a `PROT_NONE` gap. Its stack half needs an
island-aware check:

```text
offset = guest - stack_guest_bottom
slot = offset / S
within = offset % S

accept only if:
  slot < frame_count
  within < F
  within + length <= F
```

The calldata slab is checked as a separate valid island. This computation is
performed only when a host helper requests a validated view; it is not emitted
for eBPF loads and stores.

## Fault handling

`ACTIVE_JIT_CODE_ZONE` records the page-zero fault window, native data range,
and native sparse-stack reservation:

```rust
stack_range: Cell<(usize, usize)>
```

When the program counter is inside active JIT code and `SIGSEGV` or `SIGBUS`
names an address inside that reservation, the handler owns the fault and yields
it as a guest memory error. The native address converts back to a guest address
with the same affine formula:

```text
guest = stack_guest_bottom + (fault - stack_native_base)
```

Initially this can remain `RuntimeError::MemoryFault(guest)`. A later diagnostic
variant could report a specific stack-frame fault. Recovering the active `R10`
from `ucontext` would make it possible to report the current frame and whether
the access crossed its upper or lower boundary, without adding hot-path work.

Faults in host helper code must not be claimed: helper validation rejects gaps
before forming a reference, and the existing program-counter check keeps the
signal handler limited to generated code.

## Detection guarantee and limitation

This layout deterministically detects every direct `R10`-relative memory
instruction that leaves the current frame toward its adjacent caller. The
greatest encodable positive displacement is smaller than the guard, so such an
instruction cannot start in the caller's mapped island. It likewise catches
small derived-pointer errors whenever their final address lies in a gap.

It is not a capability system and must not be described as a security boundary
against malicious bytecode. eBPF permits unrestricted 64-bit arithmetic. A
program can deliberately derive `R10 + S`, or otherwise synthesize the exact
address of another mapped frame, and skip a finite guard without touching it.
Pointers explicitly passed from a caller must also remain valid, so merely
rejecting every access to an ancestor frame would break the caller-managed arena
model.

Eliminating this escape requires pointer provenance enforced by static
validation, dynamic metadata, or suitable hardware capabilities. Sparse guards
instead provide zero-extra-instruction detection for the direct frame-relative
overruns most likely to result from a compiler, JIT, or handwritten-bytecode
bug.

## Performance properties

The intended steady-state properties are:

- no additional instructions for a valid `FRAME` load or store;
- no additional instructions for an ordinary checked memory access;
- no additional instructions for local-call `R10` movement;
- the same number of mapped and touched guest-stack data pages;
- native coroutine-stack sizing unchanged for a given frame count.

The mechanism is not literally free. It increases reserved virtual address
space, creates additional VM areas or protection ranges, and adds allocation
and `mprotect` work when an execution context is first created. Context pooling
amortizes that setup. Unmapped gaps should not consume physical memory or TLB
entries during successful execution, but the larger mapping and VM metadata
remain platform costs that benchmarks must measure.

## API and rollout

The mode is controlled by a loader setting and is enabled by default on
compatible page sizes:

```rust
ProgramLoader::with_guarded_stack_frames(false) // opt out
ProgramLoader::with_guarded_stack_frames(true)  // require guards or fail loading
```

Loading in this mode rejects:

- a frame size that is not a multiple of the host page size;
- a derived sparse span that exceeds the pointer cage's addressability limit;
- arithmetic overflow in frame-count, stride, span, or mapping calculations;
- a configuration that cannot hold at least one complete frame and the
  calldata slab.

## Implementation areas

The implementation spans:

- `src/program.rs`: sparse allocation, context pooling and scrubbing, calldata
  placement, `JitMemory`, helper validation, stack exhaustion, and fault-range
  publication;
- `src/pointer_cage.rs`: reserve the expanded sparse guest span;
- `src/jit/mod.rs` and `src/jit/abi.rs`: carry frame size and stride as separate
  values;
- `src/jit/emit/x86_64.rs` and `src/jit/emit/aarch64.rs`: use the stride only at
  local-call entry and return;
- `src/jit/interp.rs`: model the sparse guest layout or reject gap addresses so
  it remains an independent semantic reference;
- `src/jit/goldens/`: record the changed local-call constants.

Region analysis continues to reason about `F`, the usable frame size. It must
not classify guard bytes as frame storage, but no new proof is required for the
runtime protection to work.

## Validation checklist

The implementation's regression coverage and cross-platform rollout should
retain the following checks:

- `[R10 - F]` succeeds and `[R10 - F - 1]` faults;
- callee loads and stores at `[R10 + 1]` and `[R10 + 32767]` fault without
  changing the caller's frame;
- wide accesses beginning at either edge of a gap fault;
- atomics and access groups cannot cross an adjacent-frame gap;
- a valid caller-frame pointer explicitly passed in an argument still works;
- recursion reaches the configured frame count and then reports
  `StackExhausted`;
- the maximum calldata length neither overlaps the root frame nor changes frame
  capacity;
- pooled contexts scrub every mapped island and the calldata slab;
- helper dereference APIs reject gaps without forming invalid references;
- a gap fault is converted to the correct sparse guest address;
- unsupported host page sizes and cage-span overflow fail at load time;
- the interpreter and both JIT backends agree on accesses to mapped islands and
  gaps;
- JIT golden diffs contain only the expected local-call stride changes.

Criterion benchmarks should compare valid frame accesses, checked accesses,
local-call recursion, first context creation, and pooled-context reuse between
contiguous and guarded modes.

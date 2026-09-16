import AsyncEbpf.X64.Machine

/-!
# The entry contract and the allowed set

What memory safety of an emitted function means, stated over the machine of
`AsyncEbpf/X64/Machine.lean`.

Two halves. `Allowed` is the set of addresses the generated code is given:
the frame scratch the entry trampoline reserved, a bounded native stack
window below the entry `rsp`, the two guest regions' native backings, the
first page — which the pointer cage's failed checks fold onto, and which the
fault handler claims — and the memory descriptor. `Entry` is what the entry
trampoline promises: where the registers point, what the descriptor and the
twelve derived slots below the frame pointer hold, and that the windows those
values describe are laid out as `program.rs` lays them out, each inside the
address space and none overlapping another.

`Safe` then says: from any state satisfying `Entry`, along every execution,
every range any step is about to touch is inside `Allowed`. `Returns` is the
other half of the contract an emitted function owes its caller, and the one a
lazily compiled callee owes this theorem through `ExternalReturn`: if it
returns, it returns with the stack balanced and the callee-saved registers
this model names still holding their entry values.

## What is deliberately not stated

Functional correctness, and information leaks — the native value of the frame
register reaching the guest as a value is not a memory-safety property and
`audit_escape` in the Rust tests is what probes it. Nor is progress: a stuck
state (a branch to a label the list does not carry) trivially satisfies
`Safe`, because the encoder would have refused to emit it and the checker is
what rules it out.
-/
open Aeneas

namespace async_ebpf_verified

namespace X64

/-! ## The windows

`InRange` and `RangesDisjoint` are in `AsyncEbpf/X64/Bytes.lean`, beside the
load and store lemmas whose hypotheses they are. -/

/-- Bytes the guest stack spans, and so bytes its native backing spans. -/
def stackSpan (P : Params) : Nat := P.sgt.toNat - P.sgb.toNat

/-- Bytes the guest data region spans. -/
def dataSpan (P : Params) : Nat := P.dgt.toNat - P.dgb.toNat

/-- The frame scratch: the 160 bytes below the entry frame pointer that the
entry trampoline reserved (`x64_ir::frame::FRAME_RESERVED`). -/
def frameSlots (P : Params) : Word := P.rbp0 - 160#64

/-- The native stack window: sixteen words below the entry `rsp`, plus the
word at it, which is as deep as any macro's pushes go. -/
def stackWindow (P : Params) : Word := P.rsp0 - 128#64

/-- Its length. -/
def stackWindowLen : Nat := 8 * 16 + 8

/-- The addresses the generated code is given. -/
def Allowed (P : Params) (a : Word) : Prop :=
  InRange (frameSlots P) 160 a ∨
  InRange (stackWindow P) stackWindowLen a ∨
  InRange P.snb (stackSpan P) a ∨
  InRange P.dnb (dataSpan P) a ∨
  InRange 0#64 4096 a ∨
  InRange P.desc 200 a

/-- An access of `n` bytes at `b` is allowed: the range is a range, and every
byte of it is allowed. -/
def AccessOk (P : Params) (b : Word) (n : Nat) : Prop :=
  b.toNat + n ≤ 2 ^ 64 ∧ ∀ a : Word, InRange b n a → Allowed P a

theorem allowed_frame {P a} (h : InRange (frameSlots P) 160 a) : Allowed P a := .inl h
theorem allowed_stack {P a} (h : InRange (stackWindow P) stackWindowLen a) : Allowed P a :=
  .inr (.inl h)
theorem allowed_stackNative {P a} (h : InRange P.snb (stackSpan P) a) : Allowed P a :=
  .inr (.inr (.inl h))
theorem allowed_dataNative {P a} (h : InRange P.dnb (dataSpan P) a) : Allowed P a :=
  .inr (.inr (.inr (.inl h)))
theorem allowed_firstPage {P a} (h : InRange 0#64 4096 a) : Allowed P a :=
  .inr (.inr (.inr (.inr (.inl h))))
theorem allowed_desc {P a} (h : InRange P.desc 200 a) : Allowed P a :=
  .inr (.inr (.inr (.inr (.inr h))))

/-- An access inside a window every byte of which is allowed. -/
theorem accessOk_of_within {P : Params} {b : Word} {n : Nat} {c : Word} {k : Nat}
    (hn : b.toNat + n ≤ 2 ^ 64) (hlo : c.toNat ≤ b.toNat) (hhi : b.toNat + n ≤ c.toNat + k)
    (hall : ∀ a : Word, InRange c k a → Allowed P a) : AccessOk P b n :=
  ⟨hn, fun a ha => hall a ⟨le_trans hlo ha.1, by have := ha.2; omega⟩⟩

/-! ## The entry contract -/

/-- The frame displacement of derived slot `i`, as `x64_ir::frame::derived_slot`
names it: twelve slots at `-136 .. -48`. -/
def derivedSlot (P : Params) (i : Nat) : Word := P.rbp0 - 136#64 + BitVec.ofNat 64 (8 * i)

/-- One region's six derived constants: the guest bottom, the guest-to-native
delta, and the highest in-range guest address for each of the four access
widths, all relative to the bottom. The bounds check reads these instead of
the descriptor when `frame_constants` is on. -/
structure DerivedBlock (P : Params) (m : Mem) (k : Nat) (gb gt nb : Word) : Prop where
  bottom : load64 m (derivedSlot P k) = gb
  delta : load64 m (derivedSlot P (k + 1)) = nb - gb
  span1 : load64 m (derivedSlot P (k + 2)) = (gt - 1#64) - gb
  span2 : load64 m (derivedSlot P (k + 3)) = (gt - 2#64) - gb
  span4 : load64 m (derivedSlot P (k + 4)) = (gt - 4#64) - gb
  span8 : load64 m (derivedSlot P (k + 5)) = (gt - 8#64) - gb


/-! ## The layout, the read-only memory, and the entry state

`Entry` used to be one flat structure. It is now three: the clauses that
mention only the parameters (`Layout`), the clauses about the bytes the
generated code never writes (`RoMem`), and the four register clauses. Every
clause it had is still here; the split is what lets the agreement relation of
`AsyncEbpf/X64/Abs.lean` carry the two halves that survive a step —
`Layout P` never changes, and `RoMem P s.mem` is what every macro must be
shown to keep. -/

/-- What the mappings promise about the parameters alone: each region is a
range, no window wraps, and no two of the six windows meet. -/
structure Layout (P : Params) : Prop where
  /-- Each guest region is a range. -/
  stackOrdered : P.sgb.toNat ≤ P.sgt.toNat
  dataOrdered : P.dgb.toNat ≤ P.dgt.toNat
  /-- The two guest regions do not meet, so a guest address names at most
  one of them. -/
  guestDisjoint : RangesDisjoint P.sgb (stackSpan P) P.dgb (dataSpan P)
  /-- None of the six windows wraps past the end of the address space. -/
  frameNoWrap : (frameSlots P).toNat + 160 ≤ 2 ^ 64
  stackWindowNoWrap : (stackWindow P).toNat + stackWindowLen ≤ 2 ^ 64
  stackNativeNoWrap : P.snb.toNat + stackSpan P ≤ 2 ^ 64
  dataNativeNoWrap : P.dnb.toNat + dataSpan P ≤ 2 ^ 64
  descNoWrap : P.desc.toNat + 200 ≤ 2 ^ 64
  /-- The two native backings do not meet each other. -/
  nativeDisjoint : RangesDisjoint P.snb (stackSpan P) P.dnb (dataSpan P)
  /-- Neither contains the first page, which is where a failed check lands. -/
  stackNativeOffPage : RangesDisjoint 0#64 4096 P.snb (stackSpan P)
  dataNativeOffPage : RangesDisjoint 0#64 4096 P.dnb (dataSpan P)
  /-- Nor the frame scratch, the native stack window or the descriptor. -/
  stackNativeOffFrame : RangesDisjoint (frameSlots P) 160 P.snb (stackSpan P)
  dataNativeOffFrame : RangesDisjoint (frameSlots P) 160 P.dnb (dataSpan P)
  stackNativeOffStack : RangesDisjoint (stackWindow P) stackWindowLen P.snb (stackSpan P)
  dataNativeOffStack : RangesDisjoint (stackWindow P) stackWindowLen P.dnb (dataSpan P)
  stackNativeOffDesc : RangesDisjoint P.desc 200 P.snb (stackSpan P)
  dataNativeOffDesc : RangesDisjoint P.desc 200 P.dnb (dataSpan P)
  /-- The frame scratch, the native stack window and the descriptor do not
  meet each other either. -/
  frameOffStack : RangesDisjoint (frameSlots P) 160 (stackWindow P) stackWindowLen
  frameOffDesc : RangesDisjoint (frameSlots P) 160 P.desc 200
  stackOffDesc : RangesDisjoint (stackWindow P) stackWindowLen P.desc 200
  /-- The native stack sits below the frame scratch, with the entry word in
  between: `rsp0 + 8 ≤ rbp0 - 160`. -/
  stackBelowFrame : P.rsp0.toNat + 8 ≤ (frameSlots P).toNat
  /-- The guest frame window `[fp0 - frameSize, fp0)` lies inside the stack's
  native backing, which is what the frame fast path rests on. -/
  frameAbove : P.snb.toNat + P.frameSize ≤ P.fp0.toNat
  frameBelow : P.fp0.toNat ≤ P.snb.toNat + stackSpan P
  /-- The local-call floor leaves room for at least the current frame and one
  more stride below it. -/
  floorRoom : P.snb.toNat + P.frameSize + P.stride ≤ P.guestFloor.toNat
  /-- Neither guest region is narrower than the widest window a check may
  cover (`x64_ir::MAX_GROUP_SPAN`); the runtime refuses to map one that is.
  A failed check parks zero, and the members of its group then touch the
  first page, so the page and the region have to be the same size for the
  two cases of a `Checked` base to be one statement. -/
  stackWide : 4096 ≤ stackSpan P
  dataWide : 4096 ≤ dataSpan P
  /-- The frame scratch and the native stack window are ranges below `rbp0`
  and `rsp0` in the arithmetic sense, not merely modulo `2 ^ 64`: the host
  stack the trampoline was entered on is nowhere near address zero. -/
  frameRoom : 160 ≤ P.rbp0.toNat
  stackRoom : 128 ≤ P.rsp0.toNat
  /-- The first page, which is where a failed check folds, meets neither the
  frame scratch nor the descriptor. Without this a checked store through a
  zero base could rewrite the descriptor the next check reads. -/
  frameOffPage : RangesDisjoint 0#64 4096 (frameSlots P) 160
  descOffPage : RangesDisjoint 0#64 4096 P.desc 200
  /-- The native stack is one mapping, `[stackLo, stackHi)`, that holds the
  entry `rsp` with the whole window below it and the frame scratch above it,
  sits clear of the first page, the two guest backings and the descriptor,
  and keeps two hundred and forty bytes below the native floor: what a
  local call pushes before the callee's own window begins. These are what
  make an activation's contract pass to the activation it calls. -/
  nativeStackNoWrap : P.stackLo.toNat ≤ P.stackHi.toNat ∧ P.stackHi.toNat ≤ 2 ^ 64
  nativeStackLo : P.stackLo.toNat + 128 ≤ P.rsp0.toNat
  nativeStackHi : P.rbp0.toNat ≤ P.stackHi.toNat
  nativeStackOffPage : RangesDisjoint 0#64 4096 P.stackLo (P.stackHi.toNat - P.stackLo.toNat)
  stackNativeOffNativeStack :
    RangesDisjoint P.stackLo (P.stackHi.toNat - P.stackLo.toNat) P.snb (stackSpan P)
  dataNativeOffNativeStack :
    RangesDisjoint P.stackLo (P.stackHi.toNat - P.stackLo.toNat) P.dnb (dataSpan P)
  descOffNativeStack : RangesDisjoint P.stackLo (P.stackHi.toNat - P.stackLo.toNat) P.desc 200
  floorNative : P.stackLo.toNat + 240 ≤ P.nativeFloor.toNat

/-- The bytes below the frame pointer, and the descriptor, that the entry
trampoline filled in and the generated code never writes: the descriptor's
address at `[rbp - 8]`, the stack delta at `[rbp - 40]`, the twelve derived
slots, and the eight descriptor fields a bounds check reads.

This is the half of the entry contract that a macro has to be shown to keep,
which is why it is a structure over a `Mem` rather than over a `State`: the
four writable frame slots, the native stack and the guest regions are
elsewhere, and a store to any of them leaves this alone. -/
structure RoMem (P : Params) (m : Mem) : Prop where
  /-- `[rbp - 8]` is the descriptor's address. -/
  descSlot : load64 m (P.rbp0 - 8#64) = P.desc
  /-- `[rbp - 40]` is the guest-to-native delta of the stack. -/
  deltaSlot : load64 m (P.rbp0 - 40#64) = P.snb - P.sgb
  /-- Derived slots 0–5 describe the stack. -/
  stackDerived : DerivedBlock P m 0 P.sgb P.sgt P.snb
  /-- Derived slots 6–11 describe the data region. -/
  dataDerived : DerivedBlock P m 6 P.dgb P.dgt P.dnb
  descStackBottom : load64 m (P.desc + 0#64) = P.sgb
  descStackTop : load64 m (P.desc + 8#64) = P.sgt
  descStackNative : load64 m (P.desc + 16#64) = P.snb
  descDataBottom : load64 m (P.desc + 24#64) = P.dgb
  descDataTop : load64 m (P.desc + 32#64) = P.dgt
  descDataNative : load64 m (P.desc + 40#64) = P.dnb
  descGuestFloor : load64 m (P.desc + 144#64) = P.guestFloor
  descNativeFloor : load64 m (P.desc + 152#64) = P.nativeFloor

/-- The state an emitted function is entered in.

The register clauses and the memory clauses are what the entry trampolines in
`program.rs` and the runtime's descriptor filling promise; the layout clauses
are what the mappings promise. Both are trusted — they are the hypotheses of
the theorem, not its conclusion. -/
structure Entry (P : Params) (s : State) : Prop where
  /-- Execution starts at the head of the list. -/
  atStart : s.pc = 0
  rsp : s.regs RSP = P.rsp0
  rbp : s.regs RBP = P.rbp0
  /-- `r15` is the native frame base. -/
  fp : s.regs R15 = P.fp0
  /-- What the trampoline wrote below the frame pointer and into the
  descriptor. -/
  ro : RoMem P s.mem
  /-- What the mappings promise. -/
  layout : Layout P


/-! ## What is to be proved of an emitted function -/

/-- Memory safety: along every execution from an entry state, every range the
instruction about to be taken touches is allowed. -/
def Safe (P : Params) (code : List x64_ir.PInsn) : Prop :=
  ∀ s, Entry P s → ∀ s', Reachable P code s s' → ∀ c, Step P code s' c →
    ∀ i, code[s'.pc]? = some i → ∀ bn ∈ accesses i s', AccessOk P bn.1 bn.2

/-- The other half of the contract: if the function returns, it returns with
the stack balanced and the registers its caller expects kept. -/
def Returns (P : Params) (code : List x64_ir.PInsn) : Prop :=
  ∀ s, Entry P s → ∀ s', Reachable P code s s' → ∀ s'', Step P code s' (.returned s'') →
    s''.regs RSP = P.rsp0 + 8#64 ∧ s''.regs RBP = P.rbp0 ∧ s''.regs R15 = P.fp0

/-- Both halves, which is what a proof about an emitted list establishes. -/
def Contract (P : Params) (code : List x64_ir.PInsn) : Prop := Safe P code ∧ Returns P code

/-! ## Sanity lemmas -/

/-- A return happens only at `ret` with `rsp` at its entry value, and moves
nothing but `rsp`. The two register clauses of `Returns` are therefore about
what the execution did before the `ret`, not about the `ret` itself. -/
theorem step_returned {P code} {s s'' : State} (h : Step P code s (.returned s'')) :
    s.regs RSP = P.rsp0 ∧ s''.regs RSP = s.regs RSP + 8#64 ∧
      (∀ r : Nat, r ≠ RSP → s''.regs r = s.regs r) := by
  cases h with
  | retTop _ h2 =>
    refine ⟨h2, by simp [popRsp], fun r hr => ?_⟩
    simp [popRsp, hr]

/-- An instruction with no accesses is safe whatever the state. -/
theorem accesses_nil_safe {P : Params} {i : x64_ir.PInsn} {s : State}
    (h : accesses i s = []) : ∀ bn ∈ accesses i s, AccessOk P bn.1 bn.2 := by
  simp [h]

end X64

end async_ebpf_verified

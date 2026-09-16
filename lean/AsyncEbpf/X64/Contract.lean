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
every range any step is about to touch is inside `Allowed`. `SafeStores` says
the same of the ranges a step *writes*, against the smaller set
`WritableAllowed`: memory safety as `Safe` states it says where the code may
reach, not what may come back changed, and what may come back changed is what
a caller needs of its callee. `Returns` is the third part of the contract an
emitted function owes its caller, and all three are what a lazily compiled
callee owes this theorem through `ExternalReturn`: it returns with the stack
balanced, the two registers this model names kept, and — `romem_kept` — the
read-only bytes of the entry contract intact.

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
load and store lemmas whose hypotheses they are; `stackSpan` and `dataSpan`
are in `AsyncEbpf/X64/Machine.lean`, beside `ExternalReturn`, which names
them. -/

/-! ### Arithmetic

The two facts about 64-bit addresses every window argument reduces to, stated
on `toNat` because that is the form `omega` reasons in. -/

theorem toNat_sub_ofNat {x : Word} {k : Nat} (h : k ≤ x.toNat) (hk : k < 2 ^ 64) :
    (x - BitVec.ofNat 64 k).toNat = x.toNat - k := by
  have := x.isLt
  rw [BitVec.toNat_sub, BitVec.toNat_ofNat, Nat.mod_eq_of_lt hk]
  omega

theorem toNat_add_ofNat {x : Word} {k : Nat} (h : x.toNat + k < 2 ^ 64) :
    (x + BitVec.ofNat 64 k).toNat = x.toNat + k := by
  have := x.isLt
  rw [BitVec.toNat_add, BitVec.toNat_ofNat]
  omega

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

/-! ### What may be written

`Allowed` says where the generated code may *reach*; it says nothing about
what it may *change*, and a caller needs that of its callee. `WritableAllowed`
is the smaller set: the native stack window, but only up to `rsp0` — the word
at the entry `rsp` is the return address, which is read and never written —
the four writable frame slots, the two guest backings and the first page. The
rest of the frame scratch and the whole descriptor are read-only, which is
what `RoMem` pins and `romem_kept` below concludes. -/

/-- The addresses the generated code may write. -/
def WritableAllowed (P : Params) (a : Word) : Prop :=
  InRange (P.rsp0 - 128#64) 128 a ∨
  WritableSlot P a ∨
  InRange P.snb (stackSpan P) a ∨
  InRange P.dnb (dataSpan P) a ∨
  InRange 0#64 4096 a

/-- A store of `n` bytes at `b` is allowed: the range is a range, and every
byte of it may be written. -/
def StoreOk (P : Params) (b : Word) (n : Nat) : Prop :=
  b.toNat + n ≤ 2 ^ 64 ∧ ∀ a : Word, InRange b n a → WritableAllowed P a

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


/-! ## The layout, read off

The `toNat` of each window, which every range argument below and in
`AsyncEbpf/X64/Abs.lean` reduces to. They live here rather than in `Abs.lean`
because `writableAllowed_allowed` and `romem_kept` are stated here. -/

namespace Layout

variable {P : Params}

/-- The frame scratch really is the 160 bytes below `rbp0`. -/
theorem frameSlots_toNat (h : Layout P) : (frameSlots P).toNat = P.rbp0.toNat - 160 := by
  have := h.frameRoom
  rw [frameSlots, show (160#64 : Word) = BitVec.ofNat 64 160 from rfl]
  exact toNat_sub_ofNat (by omega) (by norm_num)

/-- And the native stack window the 136 bytes from `rsp0 - 128`. -/
theorem stackWindow_toNat (h : Layout P) : (stackWindow P).toNat = P.rsp0.toNat - 128 := by
  have := h.stackRoom
  rw [stackWindow, show (128#64 : Word) = BitVec.ofNat 64 128 from rfl]
  exact toNat_sub_ofNat (by omega) (by norm_num)

end Layout

/-- A slot of the frame scratch, by its displacement below `rbp0`. -/
theorem rbp_sub_toNat {P : Params} (hL : Layout P) {j : Nat} (hj : j ≤ 160) :
    (P.rbp0 - BitVec.ofNat 64 j).toNat = P.rbp0.toNat - j := by
  have := hL.frameRoom
  exact toNat_sub_ofNat (by omega) (by omega)

/-- A field of the descriptor, by its offset. -/
theorem desc_add_toNat {P : Params} (hL : Layout P) {j : Nat} (hj : j < 200) :
    (P.desc + BitVec.ofNat 64 j).toNat = P.desc.toNat + j := by
  have := hL.descNoWrap
  exact toNat_add_ofNat (by omega)

/-- And a derived slot, by its index. -/
theorem derivedSlot_toNat {P : Params} (hL : Layout P) {i : Nat} (hi : i ≤ 11) :
    (derivedSlot P i).toNat = P.rbp0.toNat - 136 + 8 * i := by
  have hr := hL.frameRoom
  have h1 : (P.rbp0 - 136#64).toNat = P.rbp0.toNat - 136 :=
    rbp_sub_toNat hL (j := 136) (by norm_num)
  rw [derivedSlot]
  rw [toNat_add_ofNat (by omega), h1]

/-- The four writable slots, by their displacements. -/
private theorem writableSlot_toNat {P : Params} (hL : Layout P) {a : Word}
    (h : WritableSlot P a) :
    (P.rbp0.toNat - 144 ≤ a.toNat ∧ a.toNat < P.rbp0.toNat - 136) ∨
    (P.rbp0.toNat - 32 ≤ a.toNat ∧ a.toNat < P.rbp0.toNat - 8) := by
  have e16 : (P.rbp0 - 16#64).toNat = P.rbp0.toNat - 16 := by
    rw [show (16#64 : Word) = BitVec.ofNat 64 16 from rfl]; exact rbp_sub_toNat hL (by norm_num)
  have e24 : (P.rbp0 - 24#64).toNat = P.rbp0.toNat - 24 := by
    rw [show (24#64 : Word) = BitVec.ofNat 64 24 from rfl]; exact rbp_sub_toNat hL (by norm_num)
  have e32 : (P.rbp0 - 32#64).toNat = P.rbp0.toNat - 32 := by
    rw [show (32#64 : Word) = BitVec.ofNat 64 32 from rfl]; exact rbp_sub_toNat hL (by norm_num)
  have e144 : (P.rbp0 - 144#64).toNat = P.rbp0.toNat - 144 := by
    rw [show (144#64 : Word) = BitVec.ofNat 64 144 from rfl]; exact rbp_sub_toNat hL (by norm_num)
  have hr := hL.frameRoom
  rcases h with h | h | h | h <;> simp only [InRange, e16, e24, e32, e144] at h <;> omega

/-- Everything that may be written may be touched: the stack part is the
native stack window without its top word, the four slots are slots of the
frame scratch, and the other three are clauses of `Allowed` as they stand. -/
theorem writableAllowed_allowed {P : Params} (hL : Layout P) {a : Word}
    (h : WritableAllowed P a) : Allowed P a := by
  have hsw := hL.stackWindow_toNat
  have hfs := hL.frameSlots_toNat
  have hr := hL.frameRoom
  have hsr := hL.stackRoom
  rcases h with h | h | h | h | h
  · refine allowed_stack ?_
    have e : (P.rsp0 - 128#64).toNat = P.rsp0.toNat - 128 := by
      rw [show (128#64 : Word) = BitVec.ofNat 64 128 from rfl]
      exact toNat_sub_ofNat (by omega) (by norm_num)
    simp only [InRange, e] at h
    exact ⟨by omega, by simp only [stackWindowLen]; omega⟩
  · refine allowed_frame ?_
    rcases writableSlot_toNat hL h with h | h <;> exact ⟨by omega, by omega⟩
  · exact allowed_stackNative h
  · exact allowed_dataNative h
  · exact allowed_firstPage h

/-! ## The bytes that are never written

`RoMem` pins three ranges: the stack delta and the twelve derived slots, which
sit together in `[rbp0 - 136, rbp0 - 32)`; the descriptor's address at
`[rbp0 - 8, rbp0)`; and the descriptor itself. Nothing a function may write
meets any of them, which is `writableAllowed_off_ro`, and that is what makes
`RoMem` an invariant of a function whose stores are all allowed. -/

/-- A byte `RoMem` pins. -/
def RoByte (P : Params) (a : Word) : Prop :=
  (P.rbp0.toNat - 136 ≤ a.toNat ∧ a.toNat < P.rbp0.toNat - 32) ∨
  (P.rbp0.toNat - 8 ≤ a.toNat ∧ a.toNat < P.rbp0.toNat) ∨
  (P.desc.toNat ≤ a.toNat ∧ a.toNat < P.desc.toNat + 200)

/-- Where a writable byte can be, as plain arithmetic. -/
private theorem writableAllowed_toNat {P : Params} (hL : Layout P) {a : Word}
    (hw : WritableAllowed P a) :
    (P.rsp0.toNat - 128 ≤ a.toNat ∧ a.toNat < P.rsp0.toNat) ∨
    (P.rbp0.toNat - 144 ≤ a.toNat ∧ a.toNat < P.rbp0.toNat - 136) ∨
    (P.rbp0.toNat - 32 ≤ a.toNat ∧ a.toNat < P.rbp0.toNat - 8) ∨
    (P.snb.toNat ≤ a.toNat ∧ a.toNat < P.snb.toNat + stackSpan P) ∨
    (P.dnb.toNat ≤ a.toNat ∧ a.toNat < P.dnb.toNat + dataSpan P) ∨
    a.toNat < 4096 := by
  have hsr := hL.stackRoom
  rcases hw with h | h | h | h | h
  · have e : (P.rsp0 - 128#64).toNat = P.rsp0.toNat - 128 := by
      rw [show (128#64 : Word) = BitVec.ofNat 64 128 from rfl]
      exact toNat_sub_ofNat (by omega) (by norm_num)
    simp only [InRange, e] at h
    exact Or.inl ⟨by omega, by omega⟩
  · rcases writableSlot_toNat hL h with h | h
    · exact Or.inr (Or.inl h)
    · exact Or.inr (Or.inr (Or.inl h))
  · exact Or.inr (Or.inr (Or.inr (Or.inl h)))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl h))))
  · refine Or.inr (Or.inr (Or.inr (Or.inr (Or.inr ?_))))
    have := h.2
    simp only [BitVec.toNat_ofNat] at this
    omega

/-- No byte a function may write is a byte `RoMem` pins: the writable frame
slots fall in the two gaps of the read-only block, the native stack window is
below the whole frame scratch, and the two guest backings and the first page
are off the frame scratch and off the descriptor by the layout. -/
theorem writableAllowed_off_ro {P : Params} (hL : Layout P) {a : Word}
    (hw : WritableAllowed P a) : ¬ RoByte P a := by
  have hfs := hL.frameSlots_toNat
  have hr := hL.frameRoom
  have hsr := hL.stackRoom
  have hbf := hL.stackBelowFrame
  have hsw := hL.stackWindow_toNat
  have hfd : RangesDisjoint (frameSlots P) 160 P.desc 200 := hL.frameOffDesc
  have hsd : RangesDisjoint (stackWindow P) stackWindowLen P.desc 200 := hL.stackOffDesc
  have hsn : RangesDisjoint (frameSlots P) 160 P.snb (stackSpan P) := hL.stackNativeOffFrame
  have hdn : RangesDisjoint (frameSlots P) 160 P.dnb (dataSpan P) := hL.dataNativeOffFrame
  have hsnd : RangesDisjoint P.desc 200 P.snb (stackSpan P) := hL.stackNativeOffDesc
  have hdnd : RangesDisjoint P.desc 200 P.dnb (dataSpan P) := hL.dataNativeOffDesc
  have hfp : RangesDisjoint 0#64 4096 (frameSlots P) 160 := hL.frameOffPage
  have hdp : RangesDisjoint 0#64 4096 P.desc 200 := hL.descOffPage
  simp only [RangesDisjoint, stackWindowLen] at hfd hsd hsn hdn
  simp only [RangesDisjoint, BitVec.toNat_ofNat] at hsnd hdnd hfp hdp
  norm_num at hfp hdp
  have key := writableAllowed_toNat hL hw
  rintro (hro | hro | hro) <;> rcases key with h | h | h | h | h | h <;> omega

/-- A load of eight bytes reads only its own range. -/
private theorem load64_congr_range {m m' : Mem} {x : Word} (hx : x.toNat + 8 ≤ 2 ^ 64)
    (h : ∀ a : Word, x.toNat ≤ a.toNat → a.toNat < x.toNat + 8 → m' a = m a) :
    load64 m' x = load64 m x := by
  simp only [load64, load]
  congr 1
  refine loadNat_congr 8 m' m x (fun i hi => ?_)
  have e : (x + BitVec.ofNat 64 i).toNat = x.toNat + i := toNat_add_ofNat (by omega)
  exact h _ (by omega) (by omega)

/-- Two memories that agree on every byte `RoMem` pins satisfy it together. -/
theorem romem_congr {P : Params} {m m' : Mem} (hL : Layout P) (h : RoMem P m)
    (hb : ∀ a : Word, RoByte P a → m' a = m a) : RoMem P m' := by
  have hr := hL.frameRoom
  have hdw := hL.descNoWrap
  have hlt := P.rbp0.isLt
  have e8 : (P.rbp0 - 8#64).toNat = P.rbp0.toNat - 8 := by
    rw [show (8#64 : Word) = BitVec.ofNat 64 8 from rfl]; exact rbp_sub_toNat hL (by norm_num)
  have e40 : (P.rbp0 - 40#64).toNat = P.rbp0.toNat - 40 := by
    rw [show (40#64 : Word) = BitVec.ofNat 64 40 from rfl]; exact rbp_sub_toNat hL (by norm_num)
  have frame : ∀ x : Word, P.rbp0.toNat - 136 ≤ x.toNat → x.toNat + 8 ≤ P.rbp0.toNat - 32 →
      load64 m' x = load64 m x := by
    intro x h1 h2
    exact load64_congr_range (by omega) (fun a ha1 ha2 => hb a (Or.inl ⟨by omega, by omega⟩))
  have ptr : load64 m' (P.rbp0 - 8#64) = load64 m (P.rbp0 - 8#64) :=
    load64_congr_range (by omega) (fun a ha1 ha2 => hb a (Or.inr (Or.inl ⟨by omega, by omega⟩)))
  have dfield : ∀ j : Nat, j ≤ 152 →
      load64 m' (P.desc + BitVec.ofNat 64 j) = load64 m (P.desc + BitVec.ofNat 64 j) := by
    intro j hj
    have e := desc_add_toNat hL (j := j) (by omega)
    exact load64_congr_range (by omega)
      (fun a ha1 ha2 => hb a (Or.inr (Or.inr ⟨by omega, by omega⟩)))
  have slot : ∀ i, i ≤ 11 → load64 m' (derivedSlot P i) = load64 m (derivedSlot P i) := by
    intro i hi
    exact frame _ (by rw [derivedSlot_toNat hL hi]; omega)
      (by rw [derivedSlot_toNat hL hi]; omega)
  have block : ∀ (kk : Nat), kk + 5 ≤ 11 → ∀ gb gt nb, DerivedBlock P m kk gb gt nb →
      DerivedBlock P m' kk gb gt nb := by
    intro kk hkk gb gt nb hbk
    exact ⟨by rw [slot kk (by omega)]; exact hbk.bottom,
      by rw [slot (kk + 1) (by omega)]; exact hbk.delta,
      by rw [slot (kk + 2) (by omega)]; exact hbk.span1,
      by rw [slot (kk + 3) (by omega)]; exact hbk.span2,
      by rw [slot (kk + 4) (by omega)]; exact hbk.span4,
      by rw [slot (kk + 5) (by omega)]; exact hbk.span8⟩
  refine ⟨by rw [ptr]; exact h.descSlot, ?_, block 0 (by norm_num) _ _ _ h.stackDerived,
    block 6 (by norm_num) _ _ _ h.dataDerived,
    by rw [show (0#64 : Word) = BitVec.ofNat 64 0 from rfl, dfield 0 (by norm_num)]
       exact h.descStackBottom,
    by rw [show (8#64 : Word) = BitVec.ofNat 64 8 from rfl, dfield 8 (by norm_num)]
       exact h.descStackTop,
    by rw [show (16#64 : Word) = BitVec.ofNat 64 16 from rfl, dfield 16 (by norm_num)]
       exact h.descStackNative,
    by rw [show (24#64 : Word) = BitVec.ofNat 64 24 from rfl, dfield 24 (by norm_num)]
       exact h.descDataBottom,
    by rw [show (32#64 : Word) = BitVec.ofNat 64 32 from rfl, dfield 32 (by norm_num)]
       exact h.descDataTop,
    by rw [show (40#64 : Word) = BitVec.ofNat 64 40 from rfl, dfield 40 (by norm_num)]
       exact h.descDataNative,
    by rw [show (144#64 : Word) = BitVec.ofNat 64 144 from rfl, dfield 144 (by norm_num)]
       exact h.descGuestFloor,
    by rw [show (152#64 : Word) = BitVec.ofNat 64 152 from rfl, dfield 152 (by norm_num)]
       exact h.descNativeFloor⟩
  · rw [frame _ (by omega) (by omega)]
    exact h.deltaSlot

/-- A store every byte of which may be written keeps the read-only bytes. -/
theorem romem_store_ok {P : Params} {m : Mem} {b : Word} {k : Nat} (hL : Layout P)
    (h : RoMem P m) (hok : StoreOk P b k) (v : BitVec (8 * k)) : RoMem P (store k m b v) := by
  refine romem_congr hL h (fun a ha => ?_)
  simp only [store]
  refine if_neg (fun hd => ?_)
  have hsum : a.toNat = (b.toNat + (a - b).toNat) % 2 ^ 64 := by
    conv_lhs => rw [show a = b + (a - b) by ring]
    rw [BitVec.toNat_add]
  have hin : InRange b k a := by
    refine ⟨?_, ?_⟩ <;>
      · rw [hsum, Nat.mod_eq_of_lt (by have := hok.1; omega)]
        omega
  exact writableAllowed_off_ro hL (hok.2 a hin) ha


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

/-- What an emitted function may *write*: along every execution from an entry
state, every range the instruction about to be taken stores into is writable.

This is the clause a caller needs of its callee and `Safe` does not give.
`Safe` says the callee only touches memory the runtime gave this activation;
`SafeStores` says which of it can come back changed, and `romem_kept` below is
the half of `ExternalReturn` that follows from it. -/
def SafeStores (P : Params) (code : List x64_ir.PInsn) : Prop :=
  ∀ s, Entry P s → ∀ s', Reachable P code s s' → ∀ c, Step P code s' c →
    ∀ i, code[s'.pc]? = some i → ∀ bn ∈ stores i s', StoreOk P bn.1 bn.2

/-- The three halves, which is what a proof about an emitted list
establishes. -/
def Contract (P : Params) (code : List x64_ir.PInsn) : Prop :=
  Safe P code ∧ SafeStores P code ∧ Returns P code

/-! ## The read-only bytes survive an activation

`romem_kept` is the composition corollary: a function whose stores are all
writable hands its caller back the bytes `RoMem` pins, which is what the
caller assumed of it through `ExternalReturn.descKept` and the frame half of
`ExternalReturn.frameKept`.

It needs one fact about the execution that `SafeStores` cannot give, and
`StackKept` is that fact: `rsp` stays between the first word and its entry
value. A callee's own frame is below the caller's `rsp`, so this is what puts
the caller's frame scratch above it; and a register-only primitive can move
`rsp` without touching memory, so no statement about accesses pins it. The
checker's depth bookkeeping — `Agree.rsp` with `Agree.depth` — is what
establishes it for a checked list. -/

/-- The stack pointer never rises above its entry value, nor wraps below the
first word. -/
def StackKept (P : Params) (code : List x64_ir.PInsn) : Prop :=
  ∀ s, Entry P s → ∀ s', Reachable P code s s' →
    8 ≤ (s'.regs RSP).toNat ∧ (s'.regs RSP).toNat ≤ P.rsp0.toNat

/-- What a callee leaves of the read-only bytes: the descriptor by
`descKept`, and the frame words because they are above the caller's `rsp`,
are not writable slots, and are off the guest backings and the first page. -/
theorem romem_external {P : Params} {code : List x64_ir.PInsn} {t u : State} (hL : Layout P)
    (hro : RoMem P t.mem) (hb : (t.regs RSP).toNat + 8 ≤ P.rbp0.toNat - 136)
    (h : ExternalReturn P code t u) : RoMem P u.mem := by
  have hfs := hL.frameSlots_toNat
  have hr := hL.frameRoom
  have hsn : RangesDisjoint (frameSlots P) 160 P.snb (stackSpan P) := hL.stackNativeOffFrame
  have hdn : RangesDisjoint (frameSlots P) 160 P.dnb (dataSpan P) := hL.dataNativeOffFrame
  have hfp : RangesDisjoint 0#64 4096 (frameSlots P) 160 := hL.frameOffPage
  simp only [RangesDisjoint, BitVec.toNat_ofNat] at hsn hdn hfp
  norm_num at hfp
  have hframe : ∀ a : Word, (t.regs RSP).toNat + 8 ≤ a.toNat →
      P.rbp0.toNat - 160 ≤ a.toNat → a.toNat < P.rbp0.toNat →
      ¬ (P.rbp0.toNat - 144 ≤ a.toNat ∧ a.toNat < P.rbp0.toNat - 136) →
      ¬ (P.rbp0.toNat - 32 ≤ a.toNat ∧ a.toNat < P.rbp0.toNat - 8) →
      u.mem a = t.mem a := by
    intro a h1 h2 h3 h4 h5
    refine h.frameKept a h1 (fun hw => ?_) (fun hw => ?_) (fun hw => ?_) (fun hw => ?_)
    · rcases writableSlot_toNat hL hw with hw | hw
      · exact h4 hw
      · exact h5 hw
    · have := hw.1; have := hw.2; omega
    · have := hw.1; have := hw.2; omega
    · have := hw.2; simp only [BitVec.toNat_ofNat] at this; omega
  refine romem_congr hL hro (fun a ha => ?_)
  rcases ha with ha | ha | ha
  · exact hframe a (by omega) (by omega) (by omega) (by omega) (by omega)
  · exact hframe a (by omega) (by omega) (by omega) (by omega) (by omega)
  · exact h.descKept a ha.1 ha.2

/-- One step keeps the read-only bytes: it either leaves memory alone, writes
a range `stores` names — and `SafeStores` made that range writable — or hands
control to a callee, which keeps them by `romem_external`. -/
theorem romem_step {P : Params} {code : List x64_ir.PInsn} {t u : State} (hL : Layout P)
    (hro : RoMem P t.mem)
    (hst : ∀ i, code[t.pc]? = some i → ∀ bn ∈ stores i t, StoreOk P bn.1 bn.2)
    (hlo : 8 ≤ (t.regs RSP).toNat) (hhi : (t.regs RSP).toNat ≤ P.rsp0.toNat)
    (h : Step P code t (.next u)) : RoMem P u.mem := by
  have hfs := hL.frameSlots_toNat
  have hr := hL.frameRoom
  have hbf := hL.stackBelowFrame
  have hrlt := (t.regs RSP).isLt
  have hpush : ((t.regs RSP) - 8#64).toNat = (t.regs RSP).toNat - 8 := by
    rw [show (8#64 : Word) = BitVec.ofNat 64 8 from rfl]
    exact toNat_sub_ofNat (by omega) (by norm_num)
  have hpop : ((t.regs RSP) + 8#64).toNat = (t.regs RSP).toNat + 8 := by
    rw [show (8#64 : Word) = BitVec.ofNat 64 8 from rfl]
    exact toNat_add_ofNat (by omega)
  cases h with
  | pcLabel _ hc => exact hro
  | localLabel _ hc => exact hro
  | exitLabel hc => exact hro
  | retpolineLabel hc => exact hro
  | pause hc => exact hro
  | push r hc =>
    have hok : StoreOk P (t.regs RSP - 8#64) 8 := (hst _ hc) (t.regs RSP - 8#64, 8) (by simp)
    exact romem_store_ok hL hro hok _
  | pop _ hc => exact hro
  | alu w64 op src dst hc => simp only [aluRRStep_mem]; exact hro
  | aluImm w64 op dst imm hc => simp only [aluImmStep_mem]; exact hro
  | shiftImm => exact hro
  | shiftCl => exact hro
  | neg => exact hro
  | mulDivRcx => exact hro
  | movsx => exact hro
  | bswap => exact hro
  | rol16 => exact hro
  | cmovTaken => exact hro
  | cmovNotTaken => exact hro
  | loadImm => exact hro
  | pushfq hc =>
    have hok : StoreOk P (t.regs RSP - 8#64) 8 := (hst _ hc) (t.regs RSP - 8#64, 8) (by simp)
    exact romem_store_ok hL hro hok _
  | popfq => exact hro
  | cqo => exact hro
  | cdq => exact hro
  | cmpRcxMinusOne => exact hro
  | cmpEaxImm => exact hro
  | load => exact hro
  | loadNop => exact hro
  | store size src base disp hc =>
    have hok : StoreOk P (addr t base disp) size.val := (hst _ hc) (addr t base disp, size.val) (by simp)
    exact romem_store_ok hL hro hok _
  | storeImm size base disp imm hc =>
    have hok : StoreOk P (addr t base disp) size.val := (hst _ hc) (addr t base disp, size.val) (by simp)
    exact romem_store_ok hL hro hok _
  | aluRM op reg base disp hc =>
    have e : (aluRMStep op reg base disp t).mem = t.mem := by
      cases op <;> simp [aluRMStep, wRegFlags, wFlags]
    rw [e]; exact hro
  | storeRspImm imm hc =>
    have hok : StoreOk P (t.regs RSP) 8 := (hst _ hc) (t.regs RSP, 8) (by simp)
    exact romem_store_ok hL hro hok _
  | storeRspRax hc =>
    have hok : StoreOk P (t.regs RSP) 8 := (hst _ hc) (t.regs RSP, 8) (by simp)
    exact romem_store_ok hL hro hok _
  | lockAlu op w64 src base disp f hc =>
    have hok : StoreOk P (addr t base disp) (opWidth w64) := (hst _ hc) (addr t base disp, opWidth w64) (by simp)
    simp only [lockAluStep]
    exact romem_store_ok hL hro hok _
  | lockCmpxchg w64 src base disp f hc =>
    have hok : StoreOk P (addr t base disp) (opWidth w64) := (hst _ hc) (addr t base disp, opWidth w64) (by simp)
    simp only [cmpxchgStep]
    split
    · exact romem_store_ok hL hro hok _
    · exact hro
  | xchg w64 src base disp hc =>
    have hok : StoreOk P (addr t base disp) (opWidth w64) := (hst _ hc) (addr t base disp, opWidth w64) (by simp)
    simp only [xchgStep]
    exact romem_store_ok hL hro hok _
  | jccTaken => exact hro
  | jccNotTaken => exact hro
  | jmp => exact hro
  | jmpNear => exact hro
  | jcc8Taken => exact hro
  | jcc8NotTaken => exact hro
  | jmp8 => exact hro
  | call tgt i hc hp =>
    have hok : StoreOk P (t.regs RSP - 8#64) 8 := (hst _ hc) (t.regs RSP - 8#64, 8) (by simp)
    exact romem_store_ok hL hro hok _
  | retLocal => exact hro
  | retExternal u hc hne hno hext =>
    refine romem_external (t := popRsp t) hL hro ?_ hext
    rw [popRsp_rsp, hpop]
    omega
  | callReg u r hc hext =>
    have hok : StoreOk P (t.regs RSP - 8#64) 8 := (hst _ hc) (t.regs RSP - 8#64, 8) (by simp)
    refine romem_external (t := push t (retAddr P t)) hL ?_ ?_ hext
    · exact romem_store_ok hL hro hok _
    · rw [push_rsp, hpush]
      omega
  | ripLoadDispatcher => exact hro
  | ripLeaHelperTable => exact hro

/-- The read-only bytes of the entry contract survive the whole activation. -/
theorem romem_kept {P : Params} {code : List x64_ir.PInsn} (hL : Layout P)
    (hs : SafeStores P code) (hk : StackKept P code) {s s' : State} (he : Entry P s)
    (hr : Reachable P code s s') : RoMem P s'.mem := by
  induction hr with
  | refl => exact he.ro
  | step hre hstep ih =>
    rename_i t u
    obtain ⟨hlo, hhi⟩ := hk s he t hre
    exact romem_step hL ih (fun i hi => hs s he t hre _ hstep i hi) hlo hhi hstep

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

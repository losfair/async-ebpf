import AsyncEbpf.Validate.Spec

/-!
# What a good function layout looks like

`src/verified/layout.rs` splits a section into local functions and walks each
one, refusing the section if control can leave a function other than through
a call. `LayoutOk` says what the `Layout` it returns means:

* the function starts are sorted, begin at slot 0, and lie inside the section;
* `pc_to_func` names, for every slot, the function whose range holds it;
* every function start is reachable, and the reachable set is closed under
  the slot-level successor relation `succB` *within each function*: from a
  reachable slot of function `i`, every successor is a reachable slot of
  function `i`;
* a local call on a reachable slot targets a function start.

`succB` reads successors off the opcode byte the way the layout code does,
without decoding the instruction: `exit` has none, `call` continues at the
next slot (the callee returns there), `lddw` skips its high half, `ja` and
`ja32` go to their target, every other jump-class instruction may go to its
target or fall through, and everything else falls through. The semantics
proof (`Semantics/Functions.lean`) shows that every successor the machine
takes is in this list.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

/-! ## Slot successors -/

/-- A way control leaves a slot without a call or return. -/
inductive Edge where
  /-- The next slot. -/
  | fall
  /-- The slot after the next: `lddw` skips its high half. -/
  | skip
  /-- The jump target. -/
  | jump
  deriving DecidableEq

/-- The edges out of a slot with opcode byte `x`, as the layout code
classifies bytes. -/
def byteEdges (x : U8) : List Edge :=
  if x = isa.OP_EXIT then []
  else if x = isa.OP_CALL then [.fall]
  else if x = isa.OP_LDDW then [.skip]
  else if (x &&& isa.CLS_MASK) = isa.CLS_JMP ∨ (x &&& isa.CLS_MASK) = isa.CLS_JMP32 then
    if x = isa.OP_JA ∨ x = isa.OP_JA32 then [.jump] else [.jump, .fall]
  else [.fall]

def edgeTarget (insn : isa.Insn) (pc : Nat) : Edge → Nat
  | .fall => pc + 1
  | .skip => pc + 2
  | .jump => (jumpTargetInt insn pc).toNat

/-- The slots control can move to from `pc` without a call or return. -/
def succB (insns : List isa.Insn) (pc : Nat) : List Nat :=
  match insns[pc]? with
  | some insn => (byteEdges insn.opcode).map (edgeTarget insn pc)
  | none => []

/-- A `call` with `src = 1`. -/
def IsLocalCall (insn : isa.Insn) : Prop := insn.opcode = isa.OP_CALL ∧ insn.src.val = 1

/-! ## Reading a `Layout` -/

/-- The function starts, as slot numbers. -/
def starts (L : layout.Layout) : List Nat := L.starts.val.map (fun s => s.val)

/-- Function `i` ends where function `i + 1` begins; the last one at `len`. -/
def funcEnd (starts : List Nat) (len : Nat) (i : Nat) : Nat :=
  match starts[i + 1]? with
  | some s => s
  | none => len

/-- Slot `pc` is in the range of function `i`. -/
def InFunc (starts : List Nat) (len : Nat) (i pc : Nat) : Prop :=
  ∃ s, starts[i]? = some s ∧ s ≤ pc ∧ pc < funcEnd starts len i

/-- The walk marked slot `pc`. -/
def Reach (L : layout.Layout) (pc : Nat) : Prop := L.reachable.val[pc]? = some true

/-- The function `pc_to_func` names for slot `pc`. -/
def funcOf (L : layout.Layout) (pc : Nat) : Option Nat :=
  (L.pc_to_func.val[pc]?).map (fun f => f.val)

/-- A local call at `pc` lands on slot `t`. -/
def CallsTo (insns : List isa.Insn) (pc t : Nat) : Prop :=
  ∃ h : pc < insns.length, IsLocalCall insns[pc] ∧ callTargetInt insns[pc] pc = (t : Int)

structure LayoutOk (insns : List isa.Insn) (L : layout.Layout) : Prop where
  starts_zero : (starts L)[0]? = some 0
  starts_sorted : (starts L).Pairwise (· < ·)
  starts_lt : ∀ s ∈ starts L, s < insns.length
  func_len : L.pc_to_func.length = insns.length
  reach_len : L.reachable.length = insns.length
  /-- `pc_to_func` names the function whose range holds the slot. -/
  func_of : ∀ i pc, InFunc (starts L) insns.length i pc → funcOf L pc = some i
  /-- Every function start was walked. -/
  start_reach : ∀ (i s : Nat), (starts L)[i]? = some s → Reach L s
  /-- From a walked slot of function `i`, every successor is a walked slot
  of function `i`. -/
  closed : ∀ i pc, InFunc (starts L) insns.length i pc → Reach L pc →
    ∀ q ∈ succB insns pc, InFunc (starts L) insns.length i q ∧ Reach L q
  /-- A local call on a walked slot targets a function start. -/
  call_start : ∀ pc t, Reach L pc → CallsTo insns pc t → t ∈ starts L

/-! ## Consequences -/

/-- Every slot of the section is in some function's range: the ranges tile
`[0, len)`. -/
theorem InFunc_exists {starts : List Nat} {len : Nat}
    (h0 : starts[0]? = some 0)
    (pc : Nat) (hpc : pc < len) : ∃ i, InFunc starts len i pc := by
  -- Walk up the starts while they stay at or below `pc`.
  have key : ∀ k, ∀ i (s : Nat), i + k = starts.length → starts[i]? = some s → s ≤ pc →
      ∃ j, InFunc starts len j pc := by
    intro k
    induction k with
    | zero =>
      intro i s hk hs _
      have : i < starts.length := List.getElem?_eq_some_iff.mp hs |>.1
      omega
    | succ k ih =>
      intro i s hk hs hle
      match hnext : starts[i + 1]? with
      | none =>
        refine ⟨i, s, hs, hle, ?_⟩
        simp [funcEnd, hnext, hpc]
      | some s' =>
        by_cases hlt : pc < s'
        · refine ⟨i, s, hs, hle, ?_⟩
          simp [funcEnd, hnext, hlt]
        · exact ih (i + 1) s' (by omega) hnext (by omega)
  exact key (starts.length - 0) 0 0 (by
    have : 0 < starts.length := List.getElem?_eq_some_iff.mp h0 |>.1
    omega) h0 (Nat.zero_le _)

theorem LayoutOk.reach_lt {insns : List isa.Insn} {L : layout.Layout} (hL : LayoutOk insns L)
    {pc : Nat} (h : Reach L pc) : pc < insns.length := by
  have := List.getElem?_eq_some_iff.mp h |>.1
  rw [← hL.reach_len]
  exact this

/-- The successors of a walked slot are walked slots of the same function. -/
theorem LayoutOk.succ_same_func {insns : List isa.Insn} {L : layout.Layout}
    (hL : LayoutOk insns L) {pc : Nat} (h : Reach L pc) {q : Nat} (hq : q ∈ succB insns pc) :
    Reach L q ∧ funcOf L q = funcOf L pc := by
  obtain ⟨i, hi⟩ := InFunc_exists hL.starts_zero pc (hL.reach_lt h)
  obtain ⟨hq_in, hq_reach⟩ := hL.closed i pc hi h q hq
  refine ⟨hq_reach, ?_⟩
  rw [hL.func_of i q hq_in, hL.func_of i pc hi]

end async_ebpf_verified

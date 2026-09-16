import AsyncEbpf.X64.Simple
import AsyncEbpf.X64.CheckSpec

/-!
# The pointer cage, proved

`MInsn.CheckedAddr src dst scratch offset size hint` is the macro every guest
access goes through: it resolves `[src + offset]` to a native address in `dst`,
and the checker hands out a `Checked size` tag for `dst` afterwards. This file
is the discharge of that tag — the `MacroOk` theorem for the macro, against the
primitives `x64_expand::expand_checked_addr` emits.

It is the theorem the old `emit_single_region_address` comments stated, and
which nothing checked: *after the sequence `dst` holds either zero — a
guaranteed faulting address, which the first page catches — or a native
address whose `size`-byte window lies inside one guest region's native
backing.* Everything else here is in service of that sentence.

## The sequence

`checkedAddrList` mirrors `expand_checked_addr` branch for branch: the guest
frame pointer materialisation when the frame register is the base, the `mov`
otherwise, the displacement, and then — with the cage on — one region check,
or, for an access whose region the analysis did not pin down, two of them
through the `ADDR_SPILL`/`ACC_SPILL` slots with a final `or`. A region check
is `regionFromFrameList` when the embedder filled in the derived constants and
`regionViaDescriptorList` when it did not. `AsyncEbpf/X64/Expand.lean` writes
the same list as `chunkCheckedAddr`; the two are proved equal where the macro
lemmas are glued to the expansion.

## The argument

With `g` the guest address in `dst` when the region check starts, and `bottom`,
`top` and `nb` the region's guest bottom, guest top and native base:

* `scratch := g - bottom` and `dst := g + (nb - bottom)` are computed
  unconditionally, and the flags are then set by comparing the region's
  precomputed span `(top - size) - bottom` against `scratch`, *as unsigned
  numbers* — the memory operand on the left, so the carry flag is raised
  exactly when the span is below the offset;
* `cmovb dst, 0` parks zero when it is. When it is not,
  `(g - bottom).toNat ≤ (top - size - bottom).toNat`, and `Layout` — the
  region ordered, no narrower than a page, its native backing not wrapping —
  turns that into `bottom ≤ g` and `g + size ≤ top`, because a `g` below
  `bottom` would make `g - bottom` wrap far above any span. That is
  `WindowIn nb (top - bottom) (g + (nb - bottom)) size`.

The two-region probe rests on `Layout.guestDisjoint`: a guest address lies in
at most one region, so at most one of the two candidates is non-zero — and a
non-zero candidate is genuinely non-zero, since a native backing never
contains the first page — and the `or` is that candidate, or zero.

## The shape of the proof

`Seg` is a straight-line run of primitives with a state predicate at each
position, `Seg.trans` concatenates two of them, and `macroOk_of_seg` turns one
into the `MacroOk` of `AsyncEbpf/X64/Run.lean` (the expansion is straight-line,
so `leave` is the fallthrough and `returns` is vacuous). A position of a run
carries three obligations: the primitive's accesses are inside the allowed
set, its *writes* are inside the writable set — the three spill slots are the
only memory the expansion writes, and every other primitive of it writes
nothing — and the stack pointer is in the native stack window, which is
`MacroOk`'s fifth clause and which `Mid` gives for free, since the expansion
never touches `rsp`. The per-primitive lemmas below are
`AsyncEbpf/X64/Run.lean`'s step shapes in that form. `Mid` is the part of
`Agree` that holds all the way through: every register but `dst`, `scratch`
and `r9`, the two fixed registers, the read-only bytes and the parked group
base.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-! ## The sequence, mirrored from the emitter

The names are prefixed where the mirror would otherwise collide with the
machine-side `derivedSlot` of `AsyncEbpf/X64/Contract.lean`, which is the same
slot as an address rather than as a displacement. -/

/-- A 32-bit displacement from an integer, truncating. -/
def caI32 (n : Int) : Std.I32 := ⟨BitVec.ofInt 32 n⟩

/-- `x64_ir::frame::derived_slot`: the displacement of derived constant `i`. -/
def caDerivedSlot (i : Nat) : Std.I32 := caI32 (-136 + 8 * (i : Int))

/-- `x64_expand::derived_base`. -/
def caDerivedBase (stack : Bool) : Nat := if stack then 0 else 6

/-- `x64_expand::width_span_slot`. -/
def caWidthSpan (size : Std.U32) : Option Nat :=
  if size = 1#u32 then some 0
  else if size = 2#u32 then some 1
  else if size = 4#u32 then some 2
  else if size = 8#u32 then some 3
  else none

/-- `x64_expand::desc_bottom`. -/
def caDescBottom (stack : Bool) : Std.I32 :=
  if stack then x64_ir.memory.STACK_GUEST_BOTTOM else x64_ir.memory.DATA_GUEST_BOTTOM

/-- `x64_expand::desc_top`. -/
def caDescTop (stack : Bool) : Std.I32 :=
  if stack then x64_ir.memory.STACK_GUEST_TOP else x64_ir.memory.DATA_GUEST_TOP

/-- `x64_expand::desc_native_base`. -/
def caDescNative (stack : Bool) : Std.I32 :=
  if stack then x64_ir.memory.STACK_NATIVE_BASE else x64_ir.memory.DATA_NATIVE_BASE

/-- `x64_ir::Cfg::native_frame_base_active`. -/
def caFramed (cfg : x64_ir.Cfg) : Bool :=
  if cfg.pointer_mask = 0#i32 then false else cfg.native_frame_base

/-- `x64_expand::expand_guest_fp`. -/
def guestFpList (dst : Std.U8) : List x64_ir.PInsn :=
  [ .Alu true .Mov x64_ir.R15 dst,
    .AluRM .Sub dst x64_ir.RBP x64_ir.frame.FRAME_DELTA_OFFSET ]

/-- `x64_expand::expand_region_from_frame`. -/
def regionFromFrameList (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    List x64_ir.PInsn :=
  [ .Alu true .Mov dst scratch,
    .AluRM .Sub scratch x64_ir.RBP (caDerivedSlot (caDerivedBase stack)),
    .AluRM .Add dst x64_ir.RBP (caDerivedSlot (caDerivedBase stack + 1)) ] ++
  (match caWidthSpan size with
   | some slot =>
     [ .Alu true .Xor x64_ir.R9 x64_ir.R9,
       .AluRM .CmpMR scratch x64_ir.RBP (caDerivedSlot (caDerivedBase stack + 2 + slot)),
       .Cmov x64_ir.cc.B dst x64_ir.R9 ]
   | none =>
     [ .Load 8#u8 false x64_ir.RBP x64_ir.R9 (caDerivedSlot (caDerivedBase stack + 2)),
       .AluImm true .Sub x64_ir.R9 (caI32 ((Std.UScalar.hcast .I32 size).val - 1)),
       .Alu true .Cmp scratch x64_ir.R9,
       .AluImm true .Mov scratch 0#i32,
       .Cmov x64_ir.cc.B dst scratch ])

/-- `x64_expand::expand_region_via_descriptor`. -/
def regionViaDescriptorList (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    List x64_ir.PInsn :=
  [ .Load 8#u8 false x64_ir.RBP scratch x64_ir.frame.FRAME_OFFSET,
    .AluRM .Sub dst scratch (caDescBottom stack),
    .Store 8#u8 dst x64_ir.RBP x64_ir.frame.SPILL_OFFSET,
    .AluRM .Add dst scratch (caDescNative stack),
    .Load 8#u8 false scratch x64_ir.R9 (caDescTop stack) ] ++
  (if size != 0#u32 then [ .AluImm true .Sub x64_ir.R9 (Std.UScalar.hcast .I32 size) ] else []) ++
  [ .AluRM .Sub x64_ir.R9 scratch (caDescBottom stack),
    .Alu true .Xor scratch scratch,
    .AluRM .CmpRM x64_ir.R9 x64_ir.RBP x64_ir.frame.SPILL_OFFSET,
    .Cmov x64_ir.cc.B dst scratch ]

/-- `x64_expand::expand_region`. -/
def regionList (cfg : x64_ir.Cfg) (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    List x64_ir.PInsn :=
  if cfg.frame_constants then regionFromFrameList dst scratch size stack
  else regionViaDescriptorList dst scratch size stack

/-- `x64_expand::expand_checked_addr`. -/
def checkedAddrList (cfg : x64_ir.Cfg) (src dst scratch : Std.U8) (offset : Std.I32)
    (size : Std.U32) (hint : Std.U8) : List x64_ir.PInsn :=
  (if caFramed cfg then
     (if src = x64_ir.R15 then guestFpList dst
      else if src != dst then [ .Alu true .Mov src dst ] else [])
   else (if src != dst then [ .Alu true .Mov src dst ] else [])) ++
  (if offset != 0#i32 then [ .AluImm true .Add dst offset ] else []) ++
  (if cfg.pointer_mask = 0#i32 then []
   else if hint = x64_ir.region.STACK then regionList cfg dst scratch size true
   else if hint = x64_ir.region.DATA then regionList cfg dst scratch size false
   else
     [ .Store 8#u8 dst x64_ir.RBP x64_ir.frame.ADDR_SPILL_OFFSET ] ++
     regionList cfg dst scratch size true ++
     [ .Store 8#u8 dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET,
       .Load 8#u8 false x64_ir.RBP dst x64_ir.frame.ADDR_SPILL_OFFSET ] ++
     regionList cfg dst scratch size false ++
     [ .AluRM .Or dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET ])

namespace CA

/-! ## Straight-line runs

`Seg P code p n A B` is the statement a straight-line run of `n` primitives
laid out at `p` supports: from a state at `p` satisfying `A`, every step is
safe, writes only where this activation may write, leaves `rsp` in the native
stack window and lands one position on, and the state at `p + n` satisfies
`B`. `Seg.trans` concatenates two runs and `macroOk_of_seg` turns one into a
`MacroOk`, whose five clauses are these three plus the fallthrough and the
vacuous `returns`. -/

/-- The stack pointer inside the native stack window, which is the `rsp`
clause of `MacroOk` read as a predicate on one state. -/
def RspWin (P : Params) (t : State) : Prop :=
  (t.regs RSP).toNat ≤ P.rsp0.toNat ∧ P.rsp0.toNat ≤ (t.regs RSP).toNat + 128

/-- The primitives of `L` sit at `p`. -/
def Laid (code : List x64_ir.PInsn) (p : Nat) (L : List x64_ir.PInsn) : Prop :=
  ∀ k, k < L.length → code[p + k]? = L[k]?

theorem Laid.head {code p} {i : x64_ir.PInsn} {L} (h : Laid code p (i :: L)) :
    code[p]? = some i := by
  have h0 := h 0 (by simp)
  simpa using h0

theorem Laid.tail {code p} {i : x64_ir.PInsn} {L} (h : Laid code p (i :: L)) :
    Laid code (p + 1) L := by
  intro k hk
  have h1 := h (k + 1) (by simp; omega)
  rw [show p + (k + 1) = p + 1 + k by omega] at h1
  simpa using h1

theorem Laid.left {code p} {L1 L2 : List x64_ir.PInsn} (h : Laid code p (L1 ++ L2)) :
    Laid code p L1 := by
  intro k hk
  have h1 := h k (by simp; omega)
  rwa [List.getElem?_append_left hk] at h1

theorem Laid.right {code p} {L1 L2 : List x64_ir.PInsn} (h : Laid code p (L1 ++ L2)) :
    Laid code (p + L1.length) L2 := by
  intro k hk
  have h1 := h (L1.length + k) (by simp; omega)
  rw [show p + (L1.length + k) = p + L1.length + k by omega] at h1
  rwa [List.getElem?_append_right (by omega), Nat.add_sub_cancel_left] at h1

/-- A straight-line run of `n` primitives at `p`, carrying a state predicate
from its first position to the one past its last. -/
inductive Seg (P : Params) (code : List x64_ir.PInsn) :
    Nat → Nat → (State → Prop) → (State → Prop) → Prop
  | nil {p : Nat} {A B : State → Prop} : (∀ t, A t → B t) → Seg P code p 0 A B
  | cons {p n : Nat} {A B C : State → Prop} :
      (∀ t : State, t.pc = p → A t →
        (∀ i, code[p]? = some i → ∀ bn ∈ accesses i t, AccessOk P bn.1 bn.2) ∧
        (∀ i, code[p]? = some i → ∀ bn ∈ stores i t, StoreOk P bn.1 bn.2) ∧
        RspWin P t ∧
        (∀ c, Step P code t c → ∃ t', c = .next t' ∧ t'.pc = p + 1 ∧ B t')) →
      Seg P code (p + 1) n B C → Seg P code p (n + 1) A C

theorem Seg.weaken {P code p n} {A B A' B' : State → Prop} (h : Seg P code p n A B)
    (hA : ∀ t, A' t → A t) (hB : ∀ t, B t → B' t) : Seg P code p n A' B' := by
  induction h generalizing A' with
  | nil hAB => exact .nil (fun t ht => hB t (hAB t (hA t ht)))
  | cons hstep _ ih => exact .cons (fun t ht hA' => hstep t ht (hA t hA')) (ih (fun _ h => h) hB)

theorem Seg.trans {P code p n1} {A B : State → Prop} (h1 : Seg P code p n1 A B) :
    ∀ {n2 : Nat} {C : State → Prop}, Seg P code (p + n1) n2 B C → Seg P code p (n1 + n2) A C := by
  induction h1 with
  | nil hAB =>
    intro n2 C h2
    rw [Nat.zero_add]
    rw [Nat.add_zero] at h2
    exact h2.weaken hAB (fun _ h => h)
  | cons hstep _ ih =>
    rename_i p' n' _ _ _ _
    intro n2 C h2
    rw [show n' + 1 + n2 = n' + n2 + 1 by omega]
    refine .cons hstep (ih ?_)
    rw [show p' + 1 + n' = p' + (n' + 1) by omega]
    exact h2

/-- The one-primitive run. -/
theorem seg_one {P : Params} {code : List x64_ir.PInsn} {p : Nat} {j : x64_ir.PInsn}
    {A B : State → Prop} (hc : code[p]? = some j)
    (hrsp : ∀ t : State, t.pc = p → A t → RspWin P t)
    (hacc : ∀ t : State, t.pc = p → A t → ∀ bn ∈ accesses j t, AccessOk P bn.1 bn.2)
    (hstr : ∀ t : State, t.pc = p → A t → ∀ bn ∈ stores j t, StoreOk P bn.1 bn.2)
    (hstp : ∀ t : State, t.pc = p → A t → ∀ c, Step P code t c →
      ∃ t', c = .next t' ∧ t'.pc = p + 1 ∧ B t') :
    Seg P code p 1 A B := by
  refine .cons (fun t ht hA => ⟨?_, ?_, hrsp t ht hA, hstp t ht hA⟩) (.nil (fun _ h => h))
  · intro i hi
    rw [hc] at hi
    simp only [Option.some.injEq] at hi
    subst hi
    exact hacc t ht hA
  · intro i hi
    rw [hc] at hi
    simp only [Option.some.injEq] at hi
    subst hi
    exact hstr t ht hA

/-! ## The run, as a chain of per-position predicates -/

/-- `Seg` unrolled: one predicate per position, each step safe and advancing. -/
def Chain (P : Params) (code : List x64_ir.PInsn) (p n : Nat) (R : Nat → State → Prop) : Prop :=
  ∀ k, k < n → ∀ t : State, t.pc = p + k → R k t →
    (∀ i, code[p + k]? = some i → ∀ bn ∈ accesses i t, AccessOk P bn.1 bn.2) ∧
    (∀ i, code[p + k]? = some i → ∀ bn ∈ stores i t, StoreOk P bn.1 bn.2) ∧
    RspWin P t ∧
    (∀ c, Step P code t c → ∃ t', c = .next t' ∧ t'.pc = p + (k + 1) ∧ R (k + 1) t')

theorem Seg.toChain {P code p n} {A B : State → Prop} (h : Seg P code p n A B) :
    ∃ R : Nat → State → Prop, (∀ t, A t → R 0 t) ∧ (∀ t, R n t → B t) ∧ Chain P code p n R := by
  induction h with
  | nil hAB =>
    rename_i p' A' B'
    exact ⟨fun _ t => A' t, fun _ h => h, hAB, fun k hk => absurd hk (by omega)⟩
  | cons hstep _ ih =>
    rename_i p' n' A' B' C' _
    obtain ⟨R', hR0, hRn, hCh⟩ := ih
    refine ⟨fun k => match k with | 0 => A' | j + 1 => R' j, fun _ h => h, hRn, ?_⟩
    intro k hk t ht hR
    match k with
    | 0 =>
      rw [Nat.add_zero] at ht ⊢
      obtain ⟨hacc, hstr, hrsp, hstp⟩ := hstep t ht hR
      refine ⟨hacc, hstr, hrsp, fun c hc => ?_⟩
      obtain ⟨t', he, hp, hB⟩ := hstp c hc
      exact ⟨t', he, by rw [hp], hR0 t' hB⟩
    | j + 1 =>
      have hj : j < n' := by omega
      have ht' : t.pc = p' + 1 + j := by rw [ht]; omega
      obtain ⟨hacc, hstr, hrsp, hstp⟩ := hCh j hj t ht' hR
      refine ⟨?_, ?_, hrsp, fun c hc => ?_⟩
      · rw [show p' + (j + 1) = p' + 1 + j by omega]; exact hacc
      · rw [show p' + (j + 1) = p' + 1 + j by omega]; exact hstr
      · obtain ⟨t', he, hp, hB⟩ := hstp c hc
        exact ⟨t', he, by rw [hp]; omega, hB⟩

theorem macroOk_of_chain {P : Params} {code : List x64_ir.PInsn} {p n : Nat}
    {pre post : x64_check.State} {R : Nat → State → Prop}
    (hR0 : ∀ t : State, t.pc = p → Agree P pre t → R 0 t)
    (hRn : ∀ t : State, R n t → Agree P post t)
    (h : Chain P code p n R) : MacroOk P code p (p + n) pre post [] := by
  set I : State → Prop := fun u => ∃ k, k ≤ n ∧ u.pc = p + k ∧ R k u with hI
  have hinv : ∀ s s' : State, s.pc = p → Agree P pre s →
      Stays P code (Range p (p + n)) s s' → I s' := by
    intro s s' hs hag hsty
    refine stays_invariant (I := I) ⟨0, by omega, by rw [hs]; omega, hR0 s hs hag⟩ ?_ hsty
    rintro t t' ⟨k, hk, hpc, hRk⟩ hin hstep hin'
    have hkn : k < n := by simp only [Range, hpc] at hin; omega
    obtain ⟨-, -, -, hstp⟩ := h k hkn t hpc hRk
    obtain ⟨u, he, hp, hRu⟩ := hstp _ hstep
    simp only [Config.next.injEq] at he
    subst he
    exact ⟨k + 1, by omega, hp, hRu⟩
  have hpos : ∀ s s' : State, s.pc = p → Agree P pre s →
      Stays P code (Range p (p + n)) s s' → ∃ k, k < n ∧ s'.pc = p + k ∧ R k s' := by
    intro s s' hs hag hsty
    obtain ⟨k, hk, hpc, hRk⟩ := hinv s s' hs hag hsty
    refine ⟨k, ?_, hpc, hRk⟩
    have := hsty.inside_last; simp only [Range, hpc] at this; omega
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro s hs hag s' hsty c hstep i hi bn hbn
    obtain ⟨k, hkn, hpc, hRk⟩ := hpos s s' hs hag hsty
    obtain ⟨hacc, -, -, -⟩ := h k hkn s' hpc hRk
    rw [hpc] at hi
    exact hacc i hi bn hbn
  · intro s hs hag s' hsty s'' hstep hout
    obtain ⟨k, hkn, hpc, hRk⟩ := hpos s s' hs hag hsty
    obtain ⟨-, -, -, hstp⟩ := h k hkn s' hpc hRk
    obtain ⟨u, he, hp, hRu⟩ := hstp _ hstep
    simp only [Config.next.injEq] at he
    subst he
    have hkn' : k + 1 = n := by
      by_contra hc
      exact hout (by simp only [Range, hp]; omega)
    rw [hkn'] at hp hRu
    exact Or.inl ⟨hp, hRn _ hRu⟩
  · intro s hs hag s' hsty s'' hstep
    exfalso
    obtain ⟨k, hkn, hpc, hRk⟩ := hpos s s' hs hag hsty
    obtain ⟨-, -, -, hstp⟩ := h k hkn s' hpc hRk
    obtain ⟨u, he, -, -⟩ := hstp _ hstep
    simp at he
  · intro s hs hag s' hsty c hstep i hi bn hbn
    obtain ⟨k, hkn, hpc, hRk⟩ := hpos s s' hs hag hsty
    obtain ⟨-, hstr, -, -⟩ := h k hkn s' hpc hRk
    rw [hpc] at hi
    exact hstr i hi bn hbn
  · intro s hs hag s' hsty
    obtain ⟨k, hkn, hpc, hRk⟩ := hpos s s' hs hag hsty
    exact (h k hkn s' hpc hRk).2.2.1

theorem macroOk_of_seg {P : Params} {code : List x64_ir.PInsn} {p n : Nat}
    {pre post : x64_check.State} {A B : State → Prop}
    (hA : ∀ t : State, t.pc = p → Agree P pre t → A t)
    (hB : ∀ t : State, B t → Agree P post t)
    (h : Seg P code p n A B) : MacroOk P code p (p + n) pre post [] := by
  obtain ⟨R, hR0, hRn, hCh⟩ := h.toChain
  exact macroOk_of_chain (fun t ht hag => hR0 t (hA t ht hag)) (fun t hRt => hB t (hRn t hRt)) hCh

/-! ## One primitive at a time

`AsyncEbpf/X64/Run.lean`'s step shapes, in the form `Seg.cons` wants: what the
instruction touches, and what it leaves. -/

/-- `cmovcc` goes one of two ways, and touches no memory either way. -/
theorem step_cmov {P code} {s : State} {c : Config} {cc dst src : Std.U8}
    (hc : code[s.pc]? = some (.Cmov cc dst src)) (h : Step P code s c) :
    (cond cc s.flags = true ∧ c = .next (wReg s dst (s.regs src.val))) ∨
    (cond cc s.flags = false ∧ c = .next (wNext s)) := by
  cases h <;> simp_all

theorem seg_alu {P : Params} {code : List x64_ir.PInsn} {p : Nat} {w64 : Bool}
    {op : x64_ir.AluRR} {src dst : Std.U8} {A B : State → Prop}
    (hc : code[p]? = some (.Alu w64 op src dst))
    (hrsp : ∀ t : State, t.pc = p → A t → RspWin P t)
    (hB : ∀ t : State, t.pc = p → A t → B (aluRRStep w64 op src dst t)) :
    Seg P code p 1 A B := by
  refine seg_one hc hrsp (fun t ht hA bn hbn => by simp at hbn)
    (fun t ht hA bn hbn => by simp at hbn) (fun t ht hA c hstep => ?_)
  exact ⟨_, step_alu (by rw [ht]; exact hc) hstep, by simp [ht], hB t ht hA⟩

theorem seg_aluImm {P : Params} {code : List x64_ir.PInsn} {p : Nat} {w64 : Bool}
    {op : x64_ir.AluRI} {dst : Std.U8} {imm : Std.I32} {A B : State → Prop}
    (hc : code[p]? = some (.AluImm w64 op dst imm))
    (hrsp : ∀ t : State, t.pc = p → A t → RspWin P t)
    (hB : ∀ t : State, t.pc = p → A t → B (aluImmStep w64 op dst imm t)) :
    Seg P code p 1 A B := by
  refine seg_one hc hrsp (fun t ht hA bn hbn => by simp at hbn)
    (fun t ht hA bn hbn => by simp at hbn) (fun t ht hA c hstep => ?_)
  exact ⟨_, step_aluImm (by rw [ht]; exact hc) hstep, by simp [ht], hB t ht hA⟩

theorem seg_aluRM {P : Params} {code : List x64_ir.PInsn} {p : Nat} {op : x64_ir.AluRM}
    {reg base : Std.U8} {disp : Std.I32} {A B : State → Prop}
    (hc : code[p]? = some (.AluRM op reg base disp))
    (hrsp : ∀ t : State, t.pc = p → A t → RspWin P t)
    (hacc : ∀ t : State, t.pc = p → A t → AccessOk P (addr t base disp) 8)
    (hB : ∀ t : State, t.pc = p → A t → B (aluRMStep op reg base disp t)) :
    Seg P code p 1 A B := by
  refine seg_one hc hrsp (fun t ht hA bn hbn => ?_) (fun t ht hA bn hbn => by simp at hbn)
    (fun t ht hA c hstep => ?_)
  · simp only [accesses_aluRM, List.mem_singleton] at hbn
    subst hbn
    exact hacc t ht hA
  · exact ⟨_, step_aluRM (by rw [ht]; exact hc) hstep, by simp [ht], hB t ht hA⟩

theorem seg_cmov {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cc dst src : Std.U8}
    {A B : State → Prop} (hc : code[p]? = some (.Cmov cc dst src))
    (hrsp : ∀ t : State, t.pc = p → A t → RspWin P t)
    (hB1 : ∀ t : State, t.pc = p → A t → cond cc t.flags = true →
      B (wReg t dst (t.regs src.val)))
    (hB2 : ∀ t : State, t.pc = p → A t → cond cc t.flags = false → B (wNext t)) :
    Seg P code p 1 A B := by
  refine seg_one hc hrsp (fun t ht hA bn hbn => by simp [accesses] at hbn)
    (fun t ht hA bn hbn => by simp [stores] at hbn) (fun t ht hA c hstep => ?_)
  rcases step_cmov (by rw [ht]; exact hc) hstep with ⟨hcc, hu⟩ | ⟨hcc, hu⟩
  · exact ⟨_, hu, by simp [wReg, ht], hB1 t ht hA hcc⟩
  · exact ⟨_, hu, by simp [wNext, ht], hB2 t ht hA hcc⟩

theorem seg_load8 {P : Params} {code : List x64_ir.PInsn} {p : Nat} {base dst : Std.U8}
    {disp : Std.I32} {A B : State → Prop}
    (hc : code[p]? = some (.Load 8#u8 false base dst disp))
    (hrsp : ∀ t : State, t.pc = p → A t → RspWin P t)
    (hacc : ∀ t : State, t.pc = p → A t → AccessOk P (addr t base disp) 8)
    (hB : ∀ t : State, t.pc = p → A t → B (wReg t dst (load64 t.mem (addr t base disp)))) :
    Seg P code p 1 A B := by
  refine seg_one hc hrsp (fun t ht hA bn hbn => ?_) (fun t ht hA bn hbn => by simp at hbn)
    (fun t ht hA c hstep => ?_)
  · simp only [accesses_load] at hbn
    rw [if_neg (by simp)] at hbn
    simp only [List.mem_singleton] at hbn
    subst hbn
    exact hacc t ht hA
  · rcases step_load (by rw [ht]; exact hc) hstep with ⟨-, hu⟩ | ⟨hbad, -, -⟩
    · refine ⟨_, hu, by simp [wReg, ht], ?_⟩
      have := hB t ht hA
      rwa [show (8#u8 : Std.U8).val = 8 from rfl, loadExt_eight]
    · simp at hbad

theorem seg_store8 {P : Params} {code : List x64_ir.PInsn} {p : Nat} {src base : Std.U8}
    {disp : Std.I32} {A B : State → Prop}
    (hc : code[p]? = some (.Store 8#u8 src base disp))
    (hrsp : ∀ t : State, t.pc = p → A t → RspWin P t)
    (hacc : ∀ t : State, t.pc = p → A t → AccessOk P (addr t base disp) 8)
    (hstr : ∀ t : State, t.pc = p → A t → StoreOk P (addr t base disp) 8)
    (hB : ∀ t : State, t.pc = p → A t →
      B { t with mem := store64 t.mem (addr t base disp) (t.regs src.val), pc := t.pc + 1 }) :
    Seg P code p 1 A B := by
  refine seg_one hc hrsp (fun t ht hA bn hbn => ?_) (fun t ht hA bn hbn => ?_)
    (fun t ht hA c hstep => ?_)
  · simp only [accesses_store, List.mem_singleton] at hbn
    subst hbn
    exact hacc t ht hA
  · simp only [stores_store, List.mem_singleton] at hbn
    subst hbn
    exact hstr t ht hA
  · refine ⟨_, step_store (by rw [ht]; exact hc) hstep, by simp [ht], ?_⟩
    have := hB t ht hA
    rwa [show (8#u8 : Std.U8).val = 8 from rfl, storeVal_eight]

/-! ## What holds all the way through

`dst`, `scratch` and `r9` are the only registers the expansion writes, and the
only memory it writes is the three writable frame slots. `Mid` is `Agree`
minus the three registers: it is what every primitive of the expansion keeps,
and reinstating the three at the end is what `Agree P post` asks for. -/

/-- The clauses of `Agree` that survive the whole expansion. -/
structure Mid (P : Params) (a : x64_check.State) (D S : Nat) (t : State) : Prop where
  regs : ∀ r, r < 16 → r ≠ D → r ≠ S → r ≠ 9 → TagOk P (tagAt a r) (t.regs r)
  rsp : t.regs RSP = P.rsp0 - BitVec.ofNat 64 (8 * a.depth.val)
  depth : a.depth.val ≤ 16
  rbp : t.regs RBP = P.rbp0
  ro : RoMem P t.mem
  group : TagOk P a.group (load64 t.mem (P.rbp0 - 144#64))

theorem Mid.keep {P : Params} {a : x64_check.State} {D S : Nat} {t t' : State}
    (hD4 : D ≠ 4) (hD5 : D ≠ 5) (hS4 : S ≠ 4) (hS5 : S ≠ 5) (h : Mid P a D S t)
    (hregs : ∀ r, r ≠ D → r ≠ S → r ≠ 9 → t'.regs r = t.regs r)
    (hro : RoMem P t'.mem)
    (hgrp : load64 t'.mem (P.rbp0 - 144#64) = load64 t.mem (P.rbp0 - 144#64)) :
    Mid P a D S t' := by
  refine ⟨fun r hr h1 h2 h3 => ?_, ?_, h.depth, ?_, hro, ?_⟩
  · rw [hregs r h1 h2 h3]; exact h.regs r hr h1 h2 h3
  · rw [hregs RSP (Ne.symm hD4) (Ne.symm hS4) (by decide)]; exact h.rsp
  · rw [hregs RBP (Ne.symm hD5) (Ne.symm hS5) (by decide)]; exact h.rbp
  · rw [hgrp]; exact h.group

/-- Every position of the expansion keeps the stack pointer where the entry
state had it, and `Mid` carries that: the depth is the checker's, and the
checker's depths are inside the native stack window. -/
theorem Mid.rspWin {P : Params} {a : x64_check.State} {D S : Nat} {t : State}
    (hL : Layout P) (h : Mid P a D S t) : RspWin P t :=
  rsp_window_of_depth hL h.rsp h.depth

/-! ## Arithmetic

Unsigned subtraction with and without a borrow, and the two displacement
forms the sequence names: the derived slots below `rbp`, and the descriptor
fields above `desc`. -/

theorem toNat_sub_le {x y : Word} (h : y.toNat ≤ x.toNat) :
    (x - y).toNat = x.toNat - y.toNat := by
  have h1 := x.isLt
  have h2 := y.isLt
  rw [BitVec.toNat_sub]
  omega

theorem toNat_sub_gt {x y : Word} (h : x.toNat < y.toNat) :
    (x - y).toNat = 2 ^ 64 + x.toNat - y.toNat := by
  have h1 := x.isLt
  have h2 := y.isLt
  rw [BitVec.toNat_sub]
  omega

theorem toNat_add_lt {x y : Word} (h : x.toNat + y.toNat < 2 ^ 64) :
    (x + y).toNat = x.toNat + y.toNat := by
  have h1 := x.isLt
  have h2 := y.isLt
  rw [BitVec.toNat_add]
  omega

theorem caI32_val {n : Int} (h1 : -(2 ^ 31) ≤ n) (h2 : n < 2 ^ 31) : (caI32 n).val = n := by
  show (BitVec.ofInt 32 n).toInt = n
  rw [BitVec.toInt_ofInt, Int.bmod]
  norm_num
  omega

theorem caDerivedSlot_val {i : Nat} (h : i ≤ 11) :
    (caDerivedSlot i).val = -136 + 8 * (i : Int) := by
  rw [caDerivedSlot]
  exact caI32_val (by omega) (by omega)

/-- A non-negative displacement denotes the offset it names. -/
theorem signExtend_nonneg {d : Std.I32} {k : Nat} (hkb : k < 2 ^ 31) (h : d.val = (k : Int)) :
    (BitVec.signExtend 64 d.bv : Word) = BitVec.ofNat 64 k := by
  have hyi : (BitVec.signExtend 64 d.bv : Word).toInt = (k : Int) := by
    rw [toInt_signExtend]; exact h
  have hcond := BitVec.toInt_eq_toNat_cond (BitVec.signExtend 64 d.bv : Word)
  have hylt := (BitVec.signExtend 64 d.bv : Word).isLt
  rw [hyi] at hcond
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]
  split at hcond <;> omega

/-- `[rbp + derived_slot i]` is the machine-side `derivedSlot P i`. -/
theorem rbp_derived {P : Params} {i : Nat} (h : i ≤ 11) :
    P.rbp0 + BitVec.signExtend 64 (caDerivedSlot i).bv = derivedSlot P i := by
  have hv : (caDerivedSlot i).val = -((136 - 8 * i : Nat) : Int) := by
    rw [caDerivedSlot_val h]; omega
  rw [rbp_slot (k := 136 - 8 * i) (by omega) (by omega) hv, derivedSlot]
  have hk : (BitVec.ofNat 64 (136 - 8 * i) : Word) = 136#64 - BitVec.ofNat 64 (8 * i) := by
    apply BitVec.eq_of_toNat_eq
    rw [BitVec.toNat_ofNat, BitVec.toNat_sub, BitVec.toNat_ofNat, BitVec.toNat_ofNat]
    omega
  rw [hk]
  ring

/-- And it is a slot of the frame scratch. -/
theorem derived_access {P : Params} (hL : Layout P) {i : Nat} (h : i ≤ 11) :
    AccessOk P (P.rbp0 + BitVec.signExtend 64 (caDerivedSlot i).bv) 8 := by
  have hv := caDerivedSlot_val h
  exact frame_slot_ok hL (by rw [hv]; omega) (by rw [hv]; omega)

/-- A `u32` width, cast to a displacement, denotes itself. -/
theorem hcast_size_val {size : Std.U32} (h : size.val ≤ 4096) :
    (Std.UScalar.hcast (src_ty := .U32) .I32 size).val = (size.val : Int) := by
  have hb : (Std.UScalar.hcast (src_ty := .U32) .I32 size).bv = size.bv := by
    rw [Std.UScalar.hcast_bv_eq]
    exact BitVec.setWidth_eq _
  show (Std.UScalar.hcast (src_ty := .U32) .I32 size).bv.toInt = _
  rw [hb]
  have hc := BitVec.toInt_eq_toNat_cond size.bv
  have hv : size.bv.toNat = size.val := rfl
  split at hc <;> omega

/-! ## One region, read off the parameters -/

/-- The region a check is against, chosen by the flag `expand_region` carries. -/
def regGb (P : Params) (stack : Bool) : Word := if stack then P.sgb else P.dgb
def regGt (P : Params) (stack : Bool) : Word := if stack then P.sgt else P.dgt
def regNb (P : Params) (stack : Bool) : Word := if stack then P.snb else P.dnb
def regSpan (P : Params) (stack : Bool) : Nat := if stack then stackSpan P else dataSpan P

/-- What `Layout` says of that region. -/
structure RegFacts (P : Params) (stack : Bool) : Prop where
  ordered : (regGb P stack).toNat ≤ (regGt P stack).toNat
  span : regSpan P stack = (regGt P stack).toNat - (regGb P stack).toNat
  wide : 4096 ≤ regSpan P stack
  noWrap : (regNb P stack).toNat + regSpan P stack ≤ 2 ^ 64
  offPage : 4096 ≤ (regNb P stack).toNat

theorem reg_facts {P : Params} (hL : Layout P) (stack : Bool) : RegFacts P stack := by
  have hz : (0#64 : Word).toNat = 0 := rfl
  cases stack
  · have h1 := hL.dataNativeOffPage
    have h2 := hL.dataWide
    simp only [RangesDisjoint, hz] at h1
    refine ⟨hL.dataOrdered, rfl, h2, hL.dataNativeNoWrap, ?_⟩
    show 4096 ≤ P.dnb.toNat
    omega
  · have h1 := hL.stackNativeOffPage
    have h2 := hL.stackWide
    simp only [RangesDisjoint, hz] at h1
    refine ⟨hL.stackOrdered, rfl, h2, hL.stackNativeNoWrap, ?_⟩
    show 4096 ≤ P.snb.toNat
    omega

theorem romem_block {P : Params} {m : Mem} (h : RoMem P m) (stack : Bool) :
    DerivedBlock P m (caDerivedBase stack) (regGb P stack) (regGt P stack) (regNb P stack) := by
  cases stack
  · exact h.dataDerived
  · exact h.stackDerived

/-! ## The descriptor fields -/

theorem desc_bottom_value {P : Params} {m : Mem} (h : RoMem P m) (stack : Bool) :
    load64 m (P.desc + BitVec.signExtend 64 (caDescBottom stack).bv) = regGb P stack := by
  cases stack
  · have hd : (caDescBottom false).val = (24 : Int) := by
      rw [show caDescBottom false = x64_ir.memory.DATA_GUEST_BOTTOM from rfl,
        x64_ir.memory.DATA_GUEST_BOTTOM]
      decide
    rw [signExtend_nonneg (k := 24) (by norm_num) hd]
    exact h.descDataBottom
  · have hd : (caDescBottom true).val = (0 : Int) := by
      rw [show caDescBottom true = x64_ir.memory.STACK_GUEST_BOTTOM from rfl,
        x64_ir.memory.STACK_GUEST_BOTTOM]
      decide
    rw [signExtend_nonneg (k := 0) (by norm_num) hd]
    exact h.descStackBottom

theorem desc_top_value {P : Params} {m : Mem} (h : RoMem P m) (stack : Bool) :
    load64 m (P.desc + BitVec.signExtend 64 (caDescTop stack).bv) = regGt P stack := by
  cases stack
  · have hd : (caDescTop false).val = (32 : Int) := by
      rw [show caDescTop false = x64_ir.memory.DATA_GUEST_TOP from rfl,
        x64_ir.memory.DATA_GUEST_TOP]
      decide
    rw [signExtend_nonneg (k := 32) (by norm_num) hd]
    exact h.descDataTop
  · have hd : (caDescTop true).val = (8 : Int) := by
      rw [show caDescTop true = x64_ir.memory.STACK_GUEST_TOP from rfl,
        x64_ir.memory.STACK_GUEST_TOP]
      decide
    rw [signExtend_nonneg (k := 8) (by norm_num) hd]
    exact h.descStackTop

theorem desc_native_value {P : Params} {m : Mem} (h : RoMem P m) (stack : Bool) :
    load64 m (P.desc + BitVec.signExtend 64 (caDescNative stack).bv) = regNb P stack := by
  cases stack
  · have hd : (caDescNative false).val = (40 : Int) := by
      rw [show caDescNative false = x64_ir.memory.DATA_NATIVE_BASE from rfl,
        x64_ir.memory.DATA_NATIVE_BASE]
      decide
    rw [signExtend_nonneg (k := 40) (by norm_num) hd]
    exact h.descDataNative
  · have hd : (caDescNative true).val = (16 : Int) := by
      rw [show caDescNative true = x64_ir.memory.STACK_NATIVE_BASE from rfl,
        x64_ir.memory.STACK_NATIVE_BASE]
      decide
    rw [signExtend_nonneg (k := 16) (by norm_num) hd]
    exact h.descStackNative

theorem desc_bottom_access {P : Params} (hL : Layout P) (stack : Bool) :
    AccessOk P (P.desc + BitVec.signExtend 64 (caDescBottom stack).bv) 8 := by
  cases stack
  · have hd : (caDescBottom false).val = (24 : Int) := by
      rw [show caDescBottom false = x64_ir.memory.DATA_GUEST_BOTTOM from rfl,
        x64_ir.memory.DATA_GUEST_BOTTOM]
      decide
    exact desc_field_ok hL (by rw [hd]; try norm_num) (by rw [hd]; try norm_num)
  · have hd : (caDescBottom true).val = (0 : Int) := by
      rw [show caDescBottom true = x64_ir.memory.STACK_GUEST_BOTTOM from rfl,
        x64_ir.memory.STACK_GUEST_BOTTOM]
      decide
    exact desc_field_ok hL (by rw [hd]; try norm_num) (by rw [hd]; try norm_num)

theorem desc_top_access {P : Params} (hL : Layout P) (stack : Bool) :
    AccessOk P (P.desc + BitVec.signExtend 64 (caDescTop stack).bv) 8 := by
  cases stack
  · have hd : (caDescTop false).val = (32 : Int) := by
      rw [show caDescTop false = x64_ir.memory.DATA_GUEST_TOP from rfl,
        x64_ir.memory.DATA_GUEST_TOP]
      decide
    exact desc_field_ok hL (by rw [hd]; try norm_num) (by rw [hd]; try norm_num)
  · have hd : (caDescTop true).val = (8 : Int) := by
      rw [show caDescTop true = x64_ir.memory.STACK_GUEST_TOP from rfl,
        x64_ir.memory.STACK_GUEST_TOP]
      decide
    exact desc_field_ok hL (by rw [hd]; try norm_num) (by rw [hd]; try norm_num)

theorem desc_native_access {P : Params} (hL : Layout P) (stack : Bool) :
    AccessOk P (P.desc + BitVec.signExtend 64 (caDescNative stack).bv) 8 := by
  cases stack
  · have hd : (caDescNative false).val = (40 : Int) := by
      rw [show caDescNative false = x64_ir.memory.DATA_NATIVE_BASE from rfl,
        x64_ir.memory.DATA_NATIVE_BASE]
      decide
    exact desc_field_ok hL (by rw [hd]; try norm_num) (by rw [hd]; try norm_num)
  · have hd : (caDescNative true).val = (16 : Int) := by
      rw [show caDescNative true = x64_ir.memory.STACK_NATIVE_BASE from rfl,
        x64_ir.memory.STACK_NATIVE_BASE]
      decide
    exact desc_field_ok hL (by rw [hd]; try norm_num) (by rw [hd]; try norm_num)

/-! ## The check itself -/

/-- The span the check compares against: the region's width less the access. -/
theorem span_sub_toNat {P : Params} (hL : Layout P) (stack : Bool) {c : Nat}
    (hc2 : c ≤ 4096) :
    ((regGt P stack - BitVec.ofNat 64 c) - regGb P stack).toNat
      = (regGt P stack).toNat - c - (regGb P stack).toNat := by
  obtain ⟨ho, hs, hwide, hnw, hpg⟩ := reg_facts hL stack
  have h1 : (regGt P stack - BitVec.ofNat 64 c).toNat = (regGt P stack).toNat - c :=
    toNat_sub_ofNat (by omega) (by omega)
  rw [toNat_sub_le (by omega), h1]

/-- The check not firing means the access is inside the region. -/
theorem region_pass {P : Params} (hL : Layout P) (stack : Bool) {w : Nat}
    (hw1 : 1 ≤ w) (hw2 : w ≤ 4096) {g : Word} {sp : Nat}
    (hsp : sp = (regGt P stack).toNat - w - (regGb P stack).toNat)
    (hcf : ¬ (sp < (g - regGb P stack).toNat)) :
    (regGb P stack).toNat ≤ g.toNat ∧ g.toNat + w ≤ (regGt P stack).toNat := by
  obtain ⟨ho, hs, hwide, hnw, hpg⟩ := reg_facts hL stack
  have hgt := (regGt P stack).isLt
  by_cases hge : (regGb P stack).toNat ≤ g.toNat
  · rw [toNat_sub_le hge] at hcf
    omega
  · rw [toNat_sub_gt (by omega)] at hcf
    have hg := g.isLt
    omega

/-- And then the translated address's window is inside the native backing. -/
theorem region_window {P : Params} (hL : Layout P) (stack : Bool) {w : Nat}
    (hw1 : 1 ≤ w) {g : Word}
    (h1 : (regGb P stack).toNat ≤ g.toNat) (h2 : g.toNat + w ≤ (regGt P stack).toNat) :
    (regNb P stack + (g - regGb P stack)).toNat
        = (regNb P stack).toNat + (g.toNat - (regGb P stack).toNat) ∧
      WindowIn (regNb P stack) (regSpan P stack) (regNb P stack + (g - regGb P stack)) w := by
  obtain ⟨ho, hs, hwide, hnw, hpg⟩ := reg_facts hL stack
  have hsub : (g - regGb P stack).toNat = g.toNat - (regGb P stack).toNat := toNat_sub_le h1
  have hlt : (regNb P stack).toNat + (g - regGb P stack).toNat < 2 ^ 64 := by
    rw [hsub]; omega
  have hv := toNat_add_lt hlt
  rw [hsub] at hv
  exact ⟨hv, by simp only [WindowIn, hv]; omega⟩

/-- What one region check leaves in `dst`. -/
def RegionOut (P : Params) (stack : Bool) (w : Nat) (g v : Word) : Prop :=
  v = 0#64 ∨ ((regGb P stack).toNat ≤ g.toNat ∧ g.toNat + w ≤ (regGt P stack).toNat ∧
    v = regNb P stack + (g - regGb P stack))

theorem tagOk_of_regionOut {P : Params} (hL : Layout P) {stack : Bool} {w : Std.U32} {g v : Word}
    (hw1 : 1 ≤ w.val) (h : RegionOut P stack w.val g v) :
    TagOk P (x64_check.Tag.Checked w) v := by
  rcases h with rfl | ⟨h1, h2, rfl⟩
  · exact Or.inl rfl
  · have hwin := (region_window hL stack hw1 h1 h2).2
    cases stack
    · exact Or.inr (Or.inr hwin)
    · exact Or.inr (Or.inl hwin)

/-- A candidate that passed is genuinely non-zero: no native backing contains
the first page. -/
theorem regionOut_ne_zero {P : Params} (hL : Layout P) {stack : Bool} {w : Nat} {g v : Word}
    (hw1 : 1 ≤ w) (h1 : (regGb P stack).toNat ≤ g.toNat)
    (h2 : g.toNat + w ≤ (regGt P stack).toNat) (hv : v = regNb P stack + (g - regGb P stack)) :
    v ≠ 0#64 := by
  obtain ⟨-, -, -, -, hpg⟩ := reg_facts hL stack
  have hval := (region_window hL stack hw1 h1 h2).1
  intro hz
  rw [hv] at hz
  rw [hz] at hval
  have hzero : (0#64 : Word).toNat = 0 := rfl
  omega

/-- A guest address lies in at most one region. -/
theorem region_unique {P : Params} (hL : Layout P) {w : Nat} (hw : 1 ≤ w) {g : Word}
    (h1 : (regGb P true).toNat ≤ g.toNat ∧ g.toNat + w ≤ (regGt P true).toNat)
    (h2 : (regGb P false).toNat ≤ g.toNat ∧ g.toNat + w ≤ (regGt P false).toNat) : False := by
  have hd := hL.guestDisjoint
  have hs := hL.stackOrdered
  have hda := hL.dataOrdered
  simp only [RangesDisjoint, stackSpan, dataSpan] at hd
  replace h1 : P.sgb.toNat ≤ g.toNat ∧ g.toNat + w ≤ P.sgt.toNat := h1
  replace h2 : P.dgb.toNat ≤ g.toNat ∧ g.toNat + w ≤ P.dgt.toNat := h2
  omega

/-! ## Reading a step's result

The state transformers of `AsyncEbpf/X64/Machine.lean`, projected. Every one
of these is `rfl` or a one-line `simp`; they are here so that the per-position
bookkeeping below is a matter of rewriting. -/

theorem wReg_mem (s : State) (r : Std.U8) (v : Word) : (wReg s r v).mem = s.mem := rfl
theorem wReg_flags (s : State) (r : Std.U8) (v : Word) : (wReg s r v).flags = s.flags := rfl
theorem wReg_regs_self (s : State) (r : Std.U8) (v : Word) : (wReg s r v).regs r.val = v := by
  simp [wReg]
theorem wReg_regs_ne (s : State) (r : Std.U8) (v : Word) {q : Nat} (h : q ≠ r.val) :
    (wReg s r v).regs q = s.regs q := by simp [wReg, Function.update_of_ne h]
theorem wRegFlags_mem (s : State) (r : Std.U8) (v : Word) (f : Flags) :
    (wRegFlags s r v f).mem = s.mem := rfl
theorem wRegFlags_flags (s : State) (r : Std.U8) (v : Word) (f : Flags) :
    (wRegFlags s r v f).flags = f := rfl
theorem wRegFlags_regs_self (s : State) (r : Std.U8) (v : Word) (f : Flags) :
    (wRegFlags s r v f).regs r.val = v := by simp [wRegFlags]
theorem wRegFlags_regs_ne (s : State) (r : Std.U8) (v : Word) (f : Flags) {q : Nat}
    (h : q ≠ r.val) : (wRegFlags s r v f).regs q = s.regs q := by
  simp [wRegFlags, Function.update_of_ne h]
theorem wFlags_mem (s : State) (f : Flags) : (wFlags s f).mem = s.mem := rfl
theorem wFlags_flags (s : State) (f : Flags) : (wFlags s f).flags = f := rfl
theorem wFlags_regs (s : State) (f : Flags) (q : Nat) : (wFlags s f).regs q = s.regs q := rfl
theorem wNext_mem (s : State) : (wNext s).mem = s.mem := rfl
theorem wNext_flags (s : State) : (wNext s).flags = s.flags := rfl
theorem wNext_regs (s : State) (q : Nat) : (wNext s).regs q = s.regs q := rfl

theorem alu_mov (w64 : Bool) (src dst : Std.U8) (s : State) :
    aluRRStep w64 .Mov src dst s = wReg s dst (wr w64 (s.regs src.val)) := rfl
theorem alu_xor (w64 : Bool) (src dst : Std.U8) (s : State) :
    aluRRStep w64 .Xor src dst s
      = wRegFlags s dst (wr w64 (s.regs dst.val ^^^ s.regs src.val))
          (flagsOfLogic w64 (s.regs dst.val ^^^ s.regs src.val)) := rfl
theorem alu_cmp (w64 : Bool) (src dst : Std.U8) (s : State) :
    aluRRStep w64 .Cmp src dst s
      = wFlags s (flagsOfAddSub w64 true (s.regs dst.val) (s.regs src.val)) := rfl
theorem aluImm_sub (w64 : Bool) (dst : Std.U8) (imm : Std.I32) (s : State) :
    aluImmStep w64 .Sub dst imm s
      = wRegFlags s dst
          (wr w64 (s.regs dst.val -
            (if w64 then BitVec.signExtend 64 imm.bv else BitVec.zeroExtend 64 imm.bv)))
          (flagsOfAddSub w64 true (s.regs dst.val)
            (if w64 then BitVec.signExtend 64 imm.bv else BitVec.zeroExtend 64 imm.bv)) := rfl
theorem aluImm_mov (w64 : Bool) (dst : Std.U8) (imm : Std.I32) (s : State) :
    aluImmStep w64 .Mov dst imm s
      = wReg s dst (wr w64
          (if w64 then BitVec.signExtend 64 imm.bv else BitVec.zeroExtend 64 imm.bv)) := rfl
theorem aluImm_add (w64 : Bool) (dst : Std.U8) (imm : Std.I32) (s : State) :
    aluImmStep w64 .Add dst imm s
      = wRegFlags s dst
          (wr w64 (s.regs dst.val +
            (if w64 then BitVec.signExtend 64 imm.bv else BitVec.zeroExtend 64 imm.bv)))
          (flagsOfAddSub w64 false (s.regs dst.val)
            (if w64 then BitVec.signExtend 64 imm.bv else BitVec.zeroExtend 64 imm.bv)) := rfl
theorem aluRM_sub (reg base : Std.U8) (disp : Std.I32) (s : State) :
    aluRMStep .Sub reg base disp s
      = wRegFlags s reg (s.regs reg.val - load64 s.mem (addr s base disp))
          (subFlags (s.regs reg.val) (load64 s.mem (addr s base disp))) := rfl
theorem aluRM_add (reg base : Std.U8) (disp : Std.I32) (s : State) :
    aluRMStep .Add reg base disp s
      = wRegFlags s reg (s.regs reg.val + load64 s.mem (addr s base disp))
          (addFlags (s.regs reg.val) (load64 s.mem (addr s base disp))) := rfl
theorem aluRM_or (reg base : Std.U8) (disp : Std.I32) (s : State) :
    aluRMStep .Or reg base disp s
      = wRegFlags s reg (s.regs reg.val ||| load64 s.mem (addr s base disp))
          (logicFlags (s.regs reg.val ||| load64 s.mem (addr s base disp))) := rfl
theorem aluRM_cmpMR (reg base : Std.U8) (disp : Std.I32) (s : State) :
    aluRMStep .CmpMR reg base disp s
      = wFlags s (subFlags (load64 s.mem (addr s base disp)) (s.regs reg.val)) := rfl
theorem aluRM_cmpRM (reg base : Std.U8) (disp : Std.I32) (s : State) :
    aluRMStep .CmpRM reg base disp s
      = wFlags s (subFlags (s.regs reg.val) (load64 s.mem (addr s base disp))) := rfl

theorem wr_true (v : Word) : wr true v = v := rfl

/-- `cmovb` reads the carry flag. -/
theorem cond_ccB (f : Flags) : cond x64_ir.cc.B f = f.cf := by
  rw [cond, x64_ir.cc.B]
  norm_num

theorem r9_val : (x64_ir.R9).val = 9 := by rw [x64_ir.R9]; rfl

/-! ## The frame slots the sequence touches -/

theorem spill_val : (x64_ir.frame.SPILL_OFFSET).val = -16 := by
  rw [x64_ir.frame.SPILL_OFFSET]; decide
theorem addrSpill_val : (x64_ir.frame.ADDR_SPILL_OFFSET).val = -24 := by
  rw [x64_ir.frame.ADDR_SPILL_OFFSET]; decide
theorem accSpill_val : (x64_ir.frame.ACC_SPILL_OFFSET).val = -32 := by
  rw [x64_ir.frame.ACC_SPILL_OFFSET]; decide
theorem frameOff_val : (x64_ir.frame.FRAME_OFFSET).val = -8 := by
  rw [x64_ir.frame.FRAME_OFFSET]; decide

/-- The address a negative `rbp`-relative operand names, when `rbp` is intact. -/
theorem mid_rbp_addr {P : Params} {a : x64_check.State} {D S : Nat} {t : State}
    (hm : Mid P a D S t) {disp : Std.I32} {k : Nat} (hk : 0 < k) (hkb : k < 2 ^ 31)
    (h : disp.val = -(k : Int)) :
    addr t x64_ir.RBP disp = P.rbp0 - BitVec.ofNat 64 k := by
  simp only [addr, rbp_val, hm.rbp]
  exact rbp_slot hk hkb h

/-- A store to one frame slot leaves another alone. -/
theorem load_slot_store_slot {P : Params} (hL : Layout P) (m : Mem) {i j : Nat}
    (hi1 : 8 ≤ i) (hi2 : i ≤ 160) (hj1 : 8 ≤ j) (hj2 : j ≤ 160)
    (hne : i + 8 ≤ j ∨ j + 8 ≤ i) (v : Word) :
    load64 (store64 m (P.rbp0 - BitVec.ofNat 64 j) v) (P.rbp0 - BitVec.ofNat 64 i)
      = load64 m (P.rbp0 - BitVec.ofNat 64 i) := by
  have hr := hL.frameRoom
  have hi' : (P.rbp0 - BitVec.ofNat 64 i).toNat = P.rbp0.toNat - i := rbp_sub_toNat hL hi2
  have hj' : (P.rbp0 - BitVec.ofNat 64 j).toNat = P.rbp0.toNat - j := rbp_sub_toNat hL hj2
  have hlt := P.rbp0.isLt
  rcases hne with hne | hne <;>
    exact load64_store64_disjoint m _ _ v (by omega) (by omega)
      (by simp only [RangesDisjoint, hi', hj']; omega)

/-- The parked group base sits at `[rbp - 144]`, and the three spills miss it. -/
theorem group_slot_kept {P : Params} (hL : Layout P) (m : Mem) {j : Nat}
    (hj : j = 16 ∨ j = 24 ∨ j = 32) (v : Word) :
    load64 (store64 m (P.rbp0 - BitVec.ofNat 64 j) v) (P.rbp0 - 144#64)
      = load64 m (P.rbp0 - 144#64) := by
  have h := load_slot_store_slot hL m (i := 144) (j := j) (by norm_num) (by norm_num)
    (by omega) (by omega) (by omega) v
  rwa [show (BitVec.ofNat 64 144 : Word) = 144#64 from rfl] at h

/-! ## The width spans -/

theorem widthSpan_spec {size : Std.U32} {slot : Nat} (h : caWidthSpan size = some slot) :
    (slot = 0 ∧ size.val = 1) ∨ (slot = 1 ∧ size.val = 2) ∨ (slot = 2 ∧ size.val = 4) ∨
      (slot = 3 ∧ size.val = 8) := by
  unfold caWidthSpan at h
  split at h
  · rename_i he
    simp only [Option.some.injEq] at h
    exact Or.inl ⟨h.symm, by rw [he]; rfl⟩
  · split at h
    · rename_i he
      simp only [Option.some.injEq] at h
      exact Or.inr (Or.inl ⟨h.symm, by rw [he]; rfl⟩)
    · split at h
      · rename_i he
        simp only [Option.some.injEq] at h
        exact Or.inr (Or.inr (Or.inl ⟨h.symm, by rw [he]; rfl⟩))
      · split at h
        · rename_i he
          simp only [Option.some.injEq] at h
          exact Or.inr (Or.inr (Or.inr ⟨h.symm, by rw [he]; rfl⟩))
        · simp at h

/-- The precomputed span of the width the slot names. -/
theorem derived_span_value {P : Params} {m : Mem} (h : RoMem P m) (stack : Bool)
    {size : Std.U32} {slot : Nat} (hws : caWidthSpan size = some slot) :
    load64 m (derivedSlot P (caDerivedBase stack + 2 + slot))
      = regGt P stack - BitVec.ofNat 64 size.val - regGb P stack := by
  have hb := romem_block h stack
  rcases widthSpan_spec hws with ⟨rfl, hs⟩ | ⟨rfl, hs⟩ | ⟨rfl, hs⟩ | ⟨rfl, hs⟩
  · rw [hs]; exact hb.span1
  · rw [hs]; exact hb.span2
  · rw [hs]; exact hb.span4
  · rw [hs]; exact hb.span8

theorem widthSpan_le {size : Std.U32} {slot : Nat} (hws : caWidthSpan size = some slot) :
    slot ≤ 3 := by
  rcases widthSpan_spec hws with ⟨rfl, -⟩ | ⟨rfl, -⟩ | ⟨rfl, -⟩ | ⟨rfl, -⟩ <;> omega

theorem derivedBase_le (stack : Bool) : caDerivedBase stack ≤ 6 := by
  cases stack <;> simp [caDerivedBase]

/-- Reading the list at a position. -/
theorem Laid.get {code : List x64_ir.PInsn} {p : Nat} {L : List x64_ir.PInsn} (h : Laid code p L)
    {k : Nat} {i : x64_ir.PInsn} (hk : L[k]? = some i) : code[p + k]? = some i := by
  have hlt : k < L.length := by
    by_contra hc
    rw [List.getElem?_eq_none (by omega)] at hk
    simp at hk
  rw [h k hlt]
  exact hk

theorem wReg_regs_eq (s : State) (r : Std.U8) (v : Word) {q : Nat} (h : q = r.val) :
    (wReg s r v).regs q = v := by subst h; exact wReg_regs_self _ _ _
theorem wRegFlags_regs_eq (s : State) (r : Std.U8) (v : Word) (f : Flags) {q : Nat}
    (h : q = r.val) : (wRegFlags s r v f).regs q = v := by
  subst h; exact wRegFlags_regs_self _ _ _ _

/-- `[rbp + derived_slot i]` names the machine-side slot. -/
theorem mid_derived_addr {P : Params} {a : x64_check.State} {D S : Nat} {t : State}
    (hm : Mid P a D S t) {i : Nat} (hi : i ≤ 11) :
    addr t x64_ir.RBP (caDerivedSlot i) = derivedSlot P i := by
  simp only [addr, rbp_val, hm.rbp]
  exact rbp_derived hi

theorem derived_access' {P : Params} (hL : Layout P) {i : Nat} (hi : i ≤ 11) :
    AccessOk P (derivedSlot P i) 8 := by
  rw [← rbp_derived hi]
  exact derived_access hL hi

/-! ## The check against the derived constants

`mov scratch, dst ; sub scratch, [bottom] ; add dst, [delta]`, and then the
compare and the `cmov` in whichever of the two shapes the width calls for. -/

/-- The three primitives both shapes begin with. -/
theorem regionFrame_head {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {a : x64_check.State} {dst scratch : Std.U8} {stack : Bool} {g : Word} {K : Mem → Prop}
    (hL : Layout P) (hD4 : dst.val ≠ 4) (hD5 : dst.val ≠ 5)
    (hS4 : scratch.val ≠ 4) (hS5 : scratch.val ≠ 5) (hds : dst.val ≠ scratch.val)
    (hc0 : code[p]? = some (.Alu true .Mov dst scratch))
    (hc1 : code[p + 1]? = some
      (.AluRM .Sub scratch x64_ir.RBP (caDerivedSlot (caDerivedBase stack))))
    (hc2 : code[p + 2]? = some
      (.AluRM .Add dst x64_ir.RBP (caDerivedSlot (caDerivedBase stack + 1)))) :
    Seg P code p 3
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧ K t.mem)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack) := by
  have hkb := derivedBase_le stack
  have step0 : Seg P code p 1
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧ K t.mem)
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧
        t.regs scratch.val = g ∧ K t.mem) := by
    refine seg_alu hc0 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_)
    obtain ⟨hm, hdv, hk⟩ := hA
    rw [alu_mov, wr_true]
    exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun q _ h2 _ => wReg_regs_ne t scratch _ h2) hm.ro rfl,
      by rw [wReg_regs_ne t scratch _ hds]; exact hdv,
      by rw [wReg_regs_self]; exact hdv, hk⟩
  have step1 : Seg P code (p + 1) 1
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧
        t.regs scratch.val = g ∧ K t.mem)
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧
        t.regs scratch.val = g - regGb P stack ∧ K t.mem) := by
    refine seg_aluRM hc1 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_) (fun t ht hA => ?_)
    · obtain ⟨hm, -, -, -⟩ := hA
      rw [mid_derived_addr hm (by omega)]
      exact derived_access' hL (by omega)
    · obtain ⟨hm, hdv, hsv, hk⟩ := hA
      have haddr := mid_derived_addr hm (i := caDerivedBase stack) (by omega)
      have hval : load64 t.mem (addr t x64_ir.RBP (caDerivedSlot (caDerivedBase stack)))
          = regGb P stack := by rw [haddr]; exact (romem_block hm.ro stack).bottom
      rw [aluRM_sub, hval]
      exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm
          (fun q _ h2 _ => wRegFlags_regs_ne t scratch _ _ h2) hm.ro rfl,
        by rw [wRegFlags_regs_ne t scratch _ _ hds]; exact hdv,
        by rw [wRegFlags_regs_self]; rw [hsv], hk⟩
  have step2 : Seg P code (p + 2) 1
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧
        t.regs scratch.val = g - regGb P stack ∧ K t.mem)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack) := by
    refine seg_aluRM hc2 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_) (fun t ht hA => ?_)
    · obtain ⟨hm, -, -, -⟩ := hA
      rw [mid_derived_addr hm (by omega)]
      exact derived_access' hL (by omega)
    · obtain ⟨hm, hdv, hsv, hk⟩ := hA
      have haddr := mid_derived_addr hm (i := caDerivedBase stack + 1) (by omega)
      have hval : load64 t.mem (addr t x64_ir.RBP (caDerivedSlot (caDerivedBase stack + 1)))
          = regNb P stack - regGb P stack := by
        rw [haddr]; exact (romem_block hm.ro stack).delta
      rw [aluRM_add, hval]
      refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm
          (fun q h1 _ _ => wRegFlags_regs_ne t dst _ _ h1) hm.ro rfl, hk, ?_, ?_⟩
      · rw [wRegFlags_regs_self, hdv]; ring
      · rw [wRegFlags_regs_ne t dst _ _ (Ne.symm hds)]; exact hsv
  have h01 : Seg P code p 2 _ _ := step0.trans step1
  exact h01.trans step2

/-- The compare against the precomputed span of one of the four widths. -/
theorem regionFrame_tailSome {P : Params} {code : List x64_ir.PInsn} {q : Nat}
    {a : x64_check.State} {dst scratch : Std.U8} {size : Std.U32} {stack : Bool} {slot : Nat}
    {g : Word} {K : Mem → Prop}
    (hL : Layout P) (hD4 : dst.val ≠ 4) (hD5 : dst.val ≠ 5)
    (hS4 : scratch.val ≠ 4) (hS5 : scratch.val ≠ 5) (_hds : dst.val ≠ scratch.val)
    (hd9 : dst.val ≠ 9) (hs9 : scratch.val ≠ 9)
    (hw1 : 1 ≤ size.val) (hw2 : size.val ≤ 4096) (hws : caWidthSpan size = some slot)
    (hc3 : code[q]? = some (.Alu true .Xor x64_ir.R9 x64_ir.R9))
    (hc4 : code[q + 1]? = some (.AluRM .CmpMR scratch x64_ir.RBP
      (caDerivedSlot (caDerivedBase stack + 2 + slot))))
    (hc5 : code[q + 2]? = some (.Cmov x64_ir.cc.B dst x64_ir.R9)) :
    Seg P code q 3
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        RegionOut P stack size.val g (t.regs dst.val)) := by
  have hslot := widthSpan_le hws
  have hkb := derivedBase_le stack
  have step3 : Seg P code q 1
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack ∧ t.regs 9 = 0#64) := by
    refine seg_alu hc3 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_)
    obtain ⟨hm, hk, hdv, hsv⟩ := hA
    rw [alu_xor, wr_true]
    refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm
        (fun j _ _ h3 => wRegFlags_regs_ne t x64_ir.R9 _ _ (by rw [r9_val]; exact h3))
        hm.ro rfl, hk, ?_, ?_, ?_⟩
    · rw [wRegFlags_regs_ne t x64_ir.R9 _ _ (by rw [r9_val]; exact hd9)]; exact hdv
    · rw [wRegFlags_regs_ne t x64_ir.R9 _ _ (by rw [r9_val]; exact hs9)]; exact hsv
    · rw [wRegFlags_regs_eq t x64_ir.R9 _ _ r9_val.symm]; simp
  have step4 : Seg P code (q + 1) 1
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack ∧ t.regs 9 = 0#64)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧ t.regs 9 = 0#64 ∧
        (t.flags.cf = false → (regGb P stack).toNat ≤ g.toNat ∧
          g.toNat + size.val ≤ (regGt P stack).toNat)) := by
    refine seg_aluRM hc4 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_) (fun t ht hA => ?_)
    · obtain ⟨hm, -, -, -, -⟩ := hA
      rw [mid_derived_addr hm (by omega)]
      exact derived_access' hL (by omega)
    · obtain ⟨hm, hk, hdv, hsv, h9⟩ := hA
      have haddr := mid_derived_addr hm (i := caDerivedBase stack + 2 + slot) (by omega)
      have hval : load64 t.mem
          (addr t x64_ir.RBP (caDerivedSlot (caDerivedBase stack + 2 + slot)))
          = regGt P stack - BitVec.ofNat 64 size.val - regGb P stack := by
        rw [haddr]; exact derived_span_value hm.ro stack hws
      rw [aluRM_cmpMR, hval]
      refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ _ _ => wFlags_regs t _ j) hm.ro rfl, hk,
        by rw [wFlags_regs]; exact hdv, by rw [wFlags_regs]; exact h9, fun hcf => ?_⟩
      rw [wFlags_flags] at hcf
      have hcf' : ¬ ((regGt P stack - BitVec.ofNat 64 size.val - regGb P stack).toNat
          < (t.regs scratch.val).toNat) := by
        have : (subFlags (regGt P stack - BitVec.ofNat 64 size.val - regGb P stack)
            (t.regs scratch.val)).cf
            = decide ((regGt P stack - BitVec.ofNat 64 size.val - regGb P stack).toNat
              < (t.regs scratch.val).toNat) := rfl
        rw [this] at hcf
        simpa using hcf
      rw [hsv] at hcf'
      exact region_pass hL stack hw1 hw2 (span_sub_toNat hL stack hw2) hcf'
  have step5 : Seg P code (q + 2) 1
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧ t.regs 9 = 0#64 ∧
        (t.flags.cf = false → (regGb P stack).toNat ≤ g.toNat ∧
          g.toNat + size.val ≤ (regGt P stack).toNat))
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        RegionOut P stack size.val g (t.regs dst.val)) := by
    refine seg_cmov hc5 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA hcc => ?_)
      (fun t ht hA hcc => ?_)
    · obtain ⟨hm, hk, hdv, h9, -⟩ := hA
      refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j h1 _ _ => wReg_regs_ne t dst _ h1) hm.ro rfl,
        hk, ?_⟩
      left
      rw [wReg_regs_self, r9_val]
      exact h9
    · obtain ⟨hm, hk, hdv, h9, himp⟩ := hA
      rw [cond_ccB] at hcc
      obtain ⟨h1, h2⟩ := himp hcc
      exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ _ _ => wNext_regs t j) hm.ro rfl, hk,
        Or.inr ⟨h1, h2, by rw [wNext_regs]; exact hdv⟩⟩
  have h34 : Seg P code q 2 _ _ := step3.trans step4
  exact h34.trans step5

theorem alu_mov_true (src dst : Std.U8) (s : State) :
    aluRRStep true .Mov src dst s = wReg s dst (s.regs src.val) := rfl
theorem alu_xor_true (src dst : Std.U8) (s : State) :
    aluRRStep true .Xor src dst s
      = wRegFlags s dst (s.regs dst.val ^^^ s.regs src.val)
          (logicFlags (s.regs dst.val ^^^ s.regs src.val)) := rfl
theorem alu_cmp_true (src dst : Std.U8) (s : State) :
    aluRRStep true .Cmp src dst s = wFlags s (subFlags (s.regs dst.val) (s.regs src.val)) := rfl
theorem aluImm_sub_true (dst : Std.U8) (imm : Std.I32) (s : State) :
    aluImmStep true .Sub dst imm s
      = wRegFlags s dst (s.regs dst.val - BitVec.signExtend 64 imm.bv)
          (subFlags (s.regs dst.val) (BitVec.signExtend 64 imm.bv)) := rfl
theorem aluImm_add_true (dst : Std.U8) (imm : Std.I32) (s : State) :
    aluImmStep true .Add dst imm s
      = wRegFlags s dst (s.regs dst.val + BitVec.signExtend 64 imm.bv)
          (addFlags (s.regs dst.val) (BitVec.signExtend 64 imm.bv)) := rfl
theorem aluImm_mov_true (dst : Std.U8) (imm : Std.I32) (s : State) :
    aluImmStep true .Mov dst imm s = wReg s dst (BitVec.signExtend 64 imm.bv) := rfl

theorem signExtend_zero : (BitVec.signExtend 64 (0#i32 : Std.I32).bv : Word) = 0#64 := by
  have h : (0#i32 : Std.I32).val = ((0 : Nat) : Int) := by decide
  rw [signExtend_nonneg (k := 0) (by norm_num) h]

/-- The width the group-span shape subtracts. -/
theorem groupSpan_imm {size : Std.U32} (hw1 : 1 ≤ size.val) (hw2 : size.val ≤ 4096) :
    (BitVec.signExtend 64 (caI32 ((Std.UScalar.hcast (src_ty := .U32) .I32 size).val - 1)).bv
      : Word) = BitVec.ofNat 64 (size.val - 1) := by
  have hv : (caI32 ((Std.UScalar.hcast (src_ty := .U32) .I32 size).val - 1)).val
      = ((size.val - 1 : Nat) : Int) := by
    rw [caI32_val (by rw [hcast_size_val hw2]; omega) (by rw [hcast_size_val hw2]; omega),
      hcast_size_val hw2]
    omega
  exact signExtend_nonneg (by omega) hv

/-- The compare against the width-1 span, narrowed: the shape an access group
whose width is none of the four takes. -/
theorem regionFrame_tailNone {P : Params} {code : List x64_ir.PInsn} {q : Nat}
    {a : x64_check.State} {dst scratch : Std.U8} {size : Std.U32} {stack : Bool}
    {g : Word} {K : Mem → Prop}
    (hL : Layout P) (hD4 : dst.val ≠ 4) (hD5 : dst.val ≠ 5)
    (hS4 : scratch.val ≠ 4) (hS5 : scratch.val ≠ 5) (hds : dst.val ≠ scratch.val)
    (hd9 : dst.val ≠ 9) (hs9 : scratch.val ≠ 9)
    (hw1 : 1 ≤ size.val) (hw2 : size.val ≤ 4096)
    (hc3 : code[q]? = some
      (.Load 8#u8 false x64_ir.RBP x64_ir.R9 (caDerivedSlot (caDerivedBase stack + 2))))
    (hc4 : code[q + 1]? = some (.AluImm true .Sub x64_ir.R9
      (caI32 ((Std.UScalar.hcast (src_ty := .U32) .I32 size).val - 1))))
    (hc5 : code[q + 2]? = some (.Alu true .Cmp scratch x64_ir.R9))
    (hc6 : code[q + 3]? = some (.AluImm true .Mov scratch 0#i32))
    (hc7 : code[q + 4]? = some (.Cmov x64_ir.cc.B dst scratch)) :
    Seg P code q 5
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        RegionOut P stack size.val g (t.regs dst.val)) := by
  have hkb := derivedBase_le stack
  obtain ⟨hord, hsp, hwide, hnw, hpg⟩ := reg_facts hL stack
  have hone : (regGt P stack - 1#64 - regGb P stack).toNat
      = (regGt P stack).toNat - 1 - (regGb P stack).toNat := by
    have h := span_sub_toNat hL stack (c := 1) (by norm_num)
    rwa [show (BitVec.ofNat 64 1 : Word) = 1#64 from rfl] at h
  have step3 : Seg P code q 1
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack ∧
        (t.regs 9).toNat = (regGt P stack).toNat - 1 - (regGb P stack).toNat) := by
    refine seg_load8 hc3 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_) (fun t ht hA => ?_)
    · obtain ⟨hm, -, -, -⟩ := hA
      rw [mid_derived_addr hm (by omega)]
      exact derived_access' hL (by omega)
    · obtain ⟨hm, hk, hdv, hsv⟩ := hA
      have haddr := mid_derived_addr hm (i := caDerivedBase stack + 2) (by omega)
      refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm
          (fun j _ _ h3 => wReg_regs_ne t x64_ir.R9 _ (by rw [r9_val]; exact h3)) hm.ro rfl,
        hk, ?_, ?_, ?_⟩
      · rw [wReg_regs_ne t x64_ir.R9 _ (by rw [r9_val]; exact hd9)]; exact hdv
      · rw [wReg_regs_ne t x64_ir.R9 _ (by rw [r9_val]; exact hs9)]; exact hsv
      · rw [wReg_regs_eq t x64_ir.R9 _ r9_val.symm, haddr, (romem_block hm.ro stack).span1]
        exact hone
  have step4 : Seg P code (q + 1) 1
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack ∧
        (t.regs 9).toNat = (regGt P stack).toNat - 1 - (regGb P stack).toNat)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack ∧
        (t.regs 9).toNat
          = (regGt P stack).toNat - size.val - (regGb P stack).toNat) := by
    refine seg_aluImm hc4 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_)
    obtain ⟨hm, hk, hdv, hsv, h9⟩ := hA
    rw [aluImm_sub_true, groupSpan_imm hw1 hw2]
    refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm
        (fun j _ _ h3 => wRegFlags_regs_ne t x64_ir.R9 _ _ (by rw [r9_val]; exact h3))
        hm.ro rfl, hk, ?_, ?_, ?_⟩
    · rw [wRegFlags_regs_ne t x64_ir.R9 _ _ (by rw [r9_val]; exact hd9)]; exact hdv
    · rw [wRegFlags_regs_ne t x64_ir.R9 _ _ (by rw [r9_val]; exact hs9)]; exact hsv
    · rw [wRegFlags_regs_eq t x64_ir.R9 _ _ r9_val.symm]
      rw [show t.regs (x64_ir.R9).val = t.regs 9 from by rw [r9_val]]
      rw [toNat_sub_ofNat (by omega) (by omega), h9]
      omega
  have step5 : Seg P code (q + 2) 1
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = g - regGb P stack ∧
        (t.regs 9).toNat
          = (regGt P stack).toNat - size.val - (regGb P stack).toNat)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        (t.flags.cf = false → (regGb P stack).toNat ≤ g.toNat ∧
          g.toNat + size.val ≤ (regGt P stack).toNat)) := by
    refine seg_alu hc5 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_)
    obtain ⟨hm, hk, hdv, hsv, h9⟩ := hA
    rw [alu_cmp_true]
    refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ _ _ => wFlags_regs t _ j) hm.ro rfl, hk,
      by rw [wFlags_regs]; exact hdv, fun hcf => ?_⟩
    rw [wFlags_flags] at hcf
    have he : (subFlags (t.regs (x64_ir.R9).val) (t.regs scratch.val)).cf
        = decide ((t.regs (x64_ir.R9).val).toNat < (t.regs scratch.val).toNat) := rfl
    rw [he] at hcf
    rw [show t.regs (x64_ir.R9).val = t.regs 9 from by rw [r9_val]] at hcf
    rw [hsv] at hcf
    refine region_pass hL stack hw1 hw2 h9 ?_
    simpa using hcf
  have step6 : Seg P code (q + 3) 1
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        (t.flags.cf = false → (regGb P stack).toNat ≤ g.toNat ∧
          g.toNat + size.val ≤ (regGt P stack).toNat))
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = 0#64 ∧
        (t.flags.cf = false → (regGb P stack).toNat ≤ g.toNat ∧
          g.toNat + size.val ≤ (regGt P stack).toNat)) := by
    refine seg_aluImm hc6 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_)
    obtain ⟨hm, hk, hdv, himp⟩ := hA
    rw [aluImm_mov_true, signExtend_zero]
    exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ h2 _ => wReg_regs_ne t scratch _ h2) hm.ro rfl,
      hk, by rw [wReg_regs_ne t scratch _ hds]; exact hdv, by rw [wReg_regs_self],
      by rw [wReg_flags]; exact himp⟩
  have step7 : Seg P code (q + 4) 1
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = 0#64 ∧
        (t.flags.cf = false → (regGb P stack).toNat ≤ g.toNat ∧
          g.toNat + size.val ≤ (regGt P stack).toNat))
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        RegionOut P stack size.val g (t.regs dst.val)) := by
    refine seg_cmov hc7 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA hcc => ?_)
      (fun t ht hA hcc => ?_)
    · obtain ⟨hm, hk, hdv, hsv, -⟩ := hA
      exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j h1 _ _ => wReg_regs_ne t dst _ h1) hm.ro rfl,
        hk, Or.inl (by rw [wReg_regs_self]; exact hsv)⟩
    · obtain ⟨hm, hk, hdv, hsv, himp⟩ := hA
      rw [cond_ccB] at hcc
      obtain ⟨h1, h2⟩ := himp hcc
      exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ _ _ => wNext_regs t j) hm.ro rfl, hk,
        Or.inr ⟨h1, h2, by rw [wNext_regs]; exact hdv⟩⟩
  have h34 : Seg P code q 2 _ _ := step3.trans step4
  have h35 : Seg P code q 3 _ _ := h34.trans step5
  have h36 : Seg P code q 4 _ _ := h35.trans step6
  exact h36.trans step7

/-- The whole check against the derived constants. -/
theorem regionFromFrame_seg {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {a : x64_check.State} {dst scratch : Std.U8} {size : Std.U32} {stack : Bool}
    {g : Word} {K : Mem → Prop}
    (hL : Layout P) (hD4 : dst.val ≠ 4) (hD5 : dst.val ≠ 5)
    (hS4 : scratch.val ≠ 4) (hS5 : scratch.val ≠ 5) (hds : dst.val ≠ scratch.val)
    (hd9 : dst.val ≠ 9) (hs9 : scratch.val ≠ 9)
    (hw1 : 1 ≤ size.val) (hw2 : size.val ≤ 4096)
    (hlaid : Laid code p (regionFromFrameList dst scratch size stack)) :
    Seg P code p (regionFromFrameList dst scratch size stack).length
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧ K t.mem)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        RegionOut P stack size.val g (t.regs dst.val)) := by
  cases hws : caWidthSpan size with
  | some slot =>
    have hlist : regionFromFrameList dst scratch size stack =
        [ (.Alu true .Mov dst scratch : x64_ir.PInsn),
          .AluRM .Sub scratch x64_ir.RBP (caDerivedSlot (caDerivedBase stack)),
          .AluRM .Add dst x64_ir.RBP (caDerivedSlot (caDerivedBase stack + 1)),
          .Alu true .Xor x64_ir.R9 x64_ir.R9,
          .AluRM .CmpMR scratch x64_ir.RBP (caDerivedSlot (caDerivedBase stack + 2 + slot)),
          .Cmov x64_ir.cc.B dst x64_ir.R9 ] := by
      simp only [regionFromFrameList, hws]
      rfl
    rw [hlist] at hlaid ⊢
    have hc0 : code[p]? = some (.Alu true .Mov dst scratch) := hlaid.get (k := 0) rfl
    have hc1 : code[p + 1]? = some
        (.AluRM .Sub scratch x64_ir.RBP (caDerivedSlot (caDerivedBase stack))) :=
      hlaid.get (k := 1) rfl
    have hc2 : code[p + 2]? = some
        (.AluRM .Add dst x64_ir.RBP (caDerivedSlot (caDerivedBase stack + 1))) :=
      hlaid.get (k := 2) rfl
    have hc3 : code[p + 3]? = some (.Alu true .Xor x64_ir.R9 x64_ir.R9) :=
      hlaid.get (k := 3) rfl
    have hc4 : code[p + 3 + 1]? = some (.AluRM .CmpMR scratch x64_ir.RBP
        (caDerivedSlot (caDerivedBase stack + 2 + slot))) := by
      rw [show p + 3 + 1 = p + 4 from by omega]; exact hlaid.get (k := 4) rfl
    have hc5 : code[p + 3 + 2]? = some (.Cmov x64_ir.cc.B dst x64_ir.R9) := by
      rw [show p + 3 + 2 = p + 5 from by omega]; exact hlaid.get (k := 5) rfl
    exact (regionFrame_head (a := a) (g := g) (K := K) hL hD4 hD5 hS4 hS5 hds hc0 hc1 hc2).trans
      (regionFrame_tailSome hL hD4 hD5 hS4 hS5 hds hd9 hs9 hw1 hw2 hws hc3 hc4 hc5)
  | none =>
    have hlist : regionFromFrameList dst scratch size stack =
        [ (.Alu true .Mov dst scratch : x64_ir.PInsn),
          .AluRM .Sub scratch x64_ir.RBP (caDerivedSlot (caDerivedBase stack)),
          .AluRM .Add dst x64_ir.RBP (caDerivedSlot (caDerivedBase stack + 1)),
          .Load 8#u8 false x64_ir.RBP x64_ir.R9 (caDerivedSlot (caDerivedBase stack + 2)),
          .AluImm true .Sub x64_ir.R9
            (caI32 ((Std.UScalar.hcast (src_ty := .U32) .I32 size).val - 1)),
          .Alu true .Cmp scratch x64_ir.R9,
          .AluImm true .Mov scratch 0#i32,
          .Cmov x64_ir.cc.B dst scratch ] := by
      simp only [regionFromFrameList, hws]
      rfl
    rw [hlist] at hlaid ⊢
    have hc0 : code[p]? = some (.Alu true .Mov dst scratch) := hlaid.get (k := 0) rfl
    have hc1 : code[p + 1]? = some
        (.AluRM .Sub scratch x64_ir.RBP (caDerivedSlot (caDerivedBase stack))) :=
      hlaid.get (k := 1) rfl
    have hc2 : code[p + 2]? = some
        (.AluRM .Add dst x64_ir.RBP (caDerivedSlot (caDerivedBase stack + 1))) :=
      hlaid.get (k := 2) rfl
    have hc3 : code[p + 3]? = some
        (.Load 8#u8 false x64_ir.RBP x64_ir.R9 (caDerivedSlot (caDerivedBase stack + 2))) :=
      hlaid.get (k := 3) rfl
    have hc4 : code[p + 3 + 1]? = some (.AluImm true .Sub x64_ir.R9
        (caI32 ((Std.UScalar.hcast (src_ty := .U32) .I32 size).val - 1))) := by
      rw [show p + 3 + 1 = p + 4 from by omega]; exact hlaid.get (k := 4) rfl
    have hc5 : code[p + 3 + 2]? = some (.Alu true .Cmp scratch x64_ir.R9) := by
      rw [show p + 3 + 2 = p + 5 from by omega]; exact hlaid.get (k := 5) rfl
    have hc6 : code[p + 3 + 3]? = some (.AluImm true .Mov scratch 0#i32) := by
      rw [show p + 3 + 3 = p + 6 from by omega]; exact hlaid.get (k := 6) rfl
    have hc7 : code[p + 3 + 4]? = some (.Cmov x64_ir.cc.B dst scratch) := by
      rw [show p + 3 + 4 = p + 7 from by omega]; exact hlaid.get (k := 7) rfl
    exact (regionFrame_head (a := a) (g := g) (K := K) hL hD4 hD5 hS4 hS5 hds hc0 hc1 hc2).trans
      (regionFrame_tailNone hL hD4 hD5 hS4 hS5 hds hd9 hs9 hw1 hw2 hc3 hc4 hc5 hc6 hc7)

theorem mid_frame_access {P : Params} {a : x64_check.State} {D S : Nat} {t : State}
    (hL : Layout P) (hm : Mid P a D S t) {disp : Std.I32}
    (hlo : -160 ≤ disp.val) (hhi : disp.val + 8 ≤ 0) :
    AccessOk P (addr t x64_ir.RBP disp) 8 := by
  simp only [addr, rbp_val, hm.rbp]
  exact frame_slot_ok hL hlo hhi

/-- And the three slots the expansion *writes* — `[rbp - 16]`, `[rbp - 24]`
and `[rbp - 32]` — are three of the four the contract lets it write. -/
theorem mid_frame_store {P : Params} {a : x64_check.State} {D S : Nat} {t : State}
    (hL : Layout P) (hm : Mid P a D S t) {disp : Std.I32} {j : Nat}
    (hj : j = 16 ∨ j = 24 ∨ j = 32 ∨ j = 144) (hd : disp.val = -(j : Int)) :
    StoreOk P (addr t x64_ir.RBP disp) 8 := by
  simp only [addr, rbp_val, hm.rbp]
  exact storeOk_slot hL hj hd (le_refl 8)

/-! ## The check through the descriptor

The same check with the region's bounds read out of the memory descriptor,
whose address the entry trampoline parked at `[rbp - 8]`. The offset is
spilled to `[rbp - 16]` because both other registers are live across the
compare; that slot is one of the four the contract lets the generated code
write, so `RoMem` survives it. -/

theorem regionViaDescriptor_seg {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {a : x64_check.State} {dst scratch : Std.U8} {size : Std.U32} {stack : Bool}
    {g : Word} {K : Mem → Prop}
    (hL : Layout P) (hD4 : dst.val ≠ 4) (hD5 : dst.val ≠ 5)
    (hS4 : scratch.val ≠ 4) (hS5 : scratch.val ≠ 5) (hds : dst.val ≠ scratch.val)
    (hd9 : dst.val ≠ 9) (hs9 : scratch.val ≠ 9)
    (hw1 : 1 ≤ size.val) (hw2 : size.val ≤ 4096)
    (hK : ∀ (m : Mem) (v : Word), K m → K (store64 m (P.rbp0 - BitVec.ofNat 64 16) v))
    (hlaid : Laid code p (regionViaDescriptorList dst scratch size stack)) :
    Seg P code p (regionViaDescriptorList dst scratch size stack).length
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧ K t.mem)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        RegionOut P stack size.val g (t.regs dst.val)) := by
  obtain ⟨hord, hsp, hwide, hnw, hpg⟩ := reg_facts hL stack
  have hne : (size != 0#u32) = true := by
    have hv : size.val ≠ 0 := by omega
    simp only [bne_iff_ne, ne_eq]
    intro hc
    exact hv (by rw [hc]; rfl)
  have hlist : regionViaDescriptorList dst scratch size stack =
      [ (.Load 8#u8 false x64_ir.RBP scratch x64_ir.frame.FRAME_OFFSET : x64_ir.PInsn),
        .AluRM .Sub dst scratch (caDescBottom stack),
        .Store 8#u8 dst x64_ir.RBP x64_ir.frame.SPILL_OFFSET,
        .AluRM .Add dst scratch (caDescNative stack),
        .Load 8#u8 false scratch x64_ir.R9 (caDescTop stack),
        .AluImm true .Sub x64_ir.R9 (Std.UScalar.hcast .I32 size),
        .AluRM .Sub x64_ir.R9 scratch (caDescBottom stack),
        .Alu true .Xor scratch scratch,
        .AluRM .CmpRM x64_ir.R9 x64_ir.RBP x64_ir.frame.SPILL_OFFSET,
        .Cmov x64_ir.cc.B dst scratch ] := by
    simp only [regionViaDescriptorList, hne, if_true]
    rfl
  rw [hlist] at hlaid ⊢
  have hc0 := hlaid.get (k := 0) rfl
  have hc1 := hlaid.get (k := 1) rfl
  have hc2 := hlaid.get (k := 2) rfl
  have hc3 := hlaid.get (k := 3) rfl
  have hc4 := hlaid.get (k := 4) rfl
  have hc5 := hlaid.get (k := 5) rfl
  have hc6 := hlaid.get (k := 6) rfl
  have hc7 := hlaid.get (k := 7) rfl
  have hc8 := hlaid.get (k := 8) rfl
  have hc9 := hlaid.get (k := 9) rfl
  -- `[rbp - 16]`, the slot the offset is spilled to.
  have hspill : ∀ t : State, Mid P a dst.val scratch.val t →
      addr t x64_ir.RBP x64_ir.frame.SPILL_OFFSET = P.rbp0 - BitVec.ofNat 64 16 :=
    fun t hm => mid_rbp_addr hm (by norm_num) (by norm_num) spill_val
  have step0 : Seg P code p 1
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧ K t.mem)
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧
        t.regs scratch.val = P.desc ∧ K t.mem) := by
    refine seg_load8 hc0 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_) (fun t ht hA => ?_)
    · obtain ⟨hm, -, -⟩ := hA
      exact mid_frame_access hL hm (by rw [frameOff_val]; norm_num)
        (by rw [frameOff_val]; norm_num)
    · obtain ⟨hm, hdv, hk⟩ := hA
      have haddr : addr t x64_ir.RBP x64_ir.frame.FRAME_OFFSET = P.rbp0 - 8#64 := by
        rw [mid_rbp_addr hm (k := 8) (by norm_num) (by norm_num) frameOff_val]
      exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ h2 _ => wReg_regs_ne t scratch _ h2)
          hm.ro rfl,
        by rw [wReg_regs_ne t scratch _ hds]; exact hdv,
        by rw [wReg_regs_self, haddr]; exact hm.ro.descSlot, hk⟩
  have step1 : Seg P code (p + 1) 1
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧
        t.regs scratch.val = P.desc ∧ K t.mem)
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g - regGb P stack ∧
        t.regs scratch.val = P.desc ∧ K t.mem) := by
    refine seg_aluRM hc1 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_) (fun t ht hA => ?_)
    · obtain ⟨-, -, hsv, -⟩ := hA
      simp only [addr, hsv]
      exact desc_bottom_access hL stack
    · obtain ⟨hm, hdv, hsv, hk⟩ := hA
      have hval : load64 t.mem (addr t scratch (caDescBottom stack)) = regGb P stack := by
        simp only [addr, hsv]
        exact desc_bottom_value hm.ro stack
      rw [aluRM_sub, hval]
      exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j h1 _ _ => wRegFlags_regs_ne t dst _ _ h1)
          hm.ro rfl,
        by rw [wRegFlags_regs_self, hdv],
        by rw [wRegFlags_regs_ne t dst _ _ (Ne.symm hds)]; exact hsv, hk⟩
  have step2 : Seg P code (p + 2) 1
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g - regGb P stack ∧
        t.regs scratch.val = P.desc ∧ K t.mem)
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g - regGb P stack ∧
        t.regs scratch.val = P.desc ∧ K t.mem ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack) := by
    refine seg_store8 hc2 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_)
      (fun t _ hA => mid_frame_store (j := 16) hL hA.1 (by norm_num)
        (by rw [spill_val]; norm_num))
      (fun t ht hA => ?_)
    · obtain ⟨hm, -, -, -⟩ := hA
      exact mid_frame_access hL hm (by rw [spill_val]; norm_num) (by rw [spill_val]; norm_num)
    · obtain ⟨hm, hdv, hsv, hk⟩ := hA
      rw [hspill t hm]
      refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ _ _ => rfl)
          (romem_store64_slot hL hm.ro (Or.inl rfl) _)
          (group_slot_kept hL t.mem (Or.inl rfl) _), hdv, hsv, hK t.mem _ hk, ?_⟩
      rw [load64_store64_same]
      exact hdv
  have step3 : Seg P code (p + 3) 1
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g - regGb P stack ∧
        t.regs scratch.val = P.desc ∧ K t.mem ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack)
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = P.desc ∧ K t.mem ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack) := by
    refine seg_aluRM hc3 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_) (fun t ht hA => ?_)
    · obtain ⟨-, -, hsv, -, -⟩ := hA
      simp only [addr, hsv]
      exact desc_native_access hL stack
    · obtain ⟨hm, hdv, hsv, hk, hsp16⟩ := hA
      have hval : load64 t.mem (addr t scratch (caDescNative stack)) = regNb P stack := by
        simp only [addr, hsv]
        exact desc_native_value hm.ro stack
      rw [aluRM_add, hval]
      refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j h1 _ _ => wRegFlags_regs_ne t dst _ _ h1)
          hm.ro rfl, ?_,
        by rw [wRegFlags_regs_ne t dst _ _ (Ne.symm hds)]; exact hsv, hk, hsp16⟩
      rw [wRegFlags_regs_self, hdv]
      ring
  have step4 : Seg P code (p + 4) 1
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = P.desc ∧ K t.mem ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack)
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = P.desc ∧ K t.mem ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack ∧
        t.regs 9 = regGt P stack) := by
    refine seg_load8 hc4 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_) (fun t ht hA => ?_)
    · obtain ⟨-, -, hsv, -, -⟩ := hA
      simp only [addr, hsv]
      exact desc_top_access hL stack
    · obtain ⟨hm, hdv, hsv, hk, hsp16⟩ := hA
      have hval : load64 t.mem (addr t scratch (caDescTop stack)) = regGt P stack := by
        simp only [addr, hsv]
        exact desc_top_value hm.ro stack
      refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm
          (fun j _ _ h3 => wReg_regs_ne t x64_ir.R9 _ (by rw [r9_val]; exact h3)) hm.ro rfl,
        by rw [wReg_regs_ne t x64_ir.R9 _ (by rw [r9_val]; exact hd9)]; exact hdv,
        by rw [wReg_regs_ne t x64_ir.R9 _ (by rw [r9_val]; exact hs9)]; exact hsv,
        hk, hsp16, ?_⟩
      rw [wReg_regs_eq t x64_ir.R9 _ r9_val.symm]
      exact hval
  have step5 : Seg P code (p + 5) 1
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = P.desc ∧ K t.mem ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack ∧
        t.regs 9 = regGt P stack)
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = P.desc ∧ K t.mem ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack ∧
        t.regs 9 = regGt P stack - BitVec.ofNat 64 size.val) := by
    refine seg_aluImm hc5 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_)
    obtain ⟨hm, hdv, hsv, hk, hsp16, h9⟩ := hA
    rw [aluImm_sub_true,
      signExtend_nonneg (d := Std.UScalar.hcast (src_ty := .U32) .I32 size) (k := size.val)
        (by omega) (hcast_size_val hw2)]
    refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm
        (fun j _ _ h3 => wRegFlags_regs_ne t x64_ir.R9 _ _ (by rw [r9_val]; exact h3))
        hm.ro rfl,
      by rw [wRegFlags_regs_ne t x64_ir.R9 _ _ (by rw [r9_val]; exact hd9)]; exact hdv,
      by rw [wRegFlags_regs_ne t x64_ir.R9 _ _ (by rw [r9_val]; exact hs9)]; exact hsv,
      hk, hsp16, ?_⟩
    rw [wRegFlags_regs_eq t x64_ir.R9 _ _ r9_val.symm,
      show t.regs (x64_ir.R9).val = t.regs 9 from by rw [r9_val], h9]
  have step6 : Seg P code (p + 6) 1
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧
        t.regs scratch.val = P.desc ∧ K t.mem ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack ∧
        t.regs 9 = regGt P stack - BitVec.ofNat 64 size.val)
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧ K t.mem ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack ∧
        (t.regs 9).toNat
          = (regGt P stack).toNat - size.val - (regGb P stack).toNat) := by
    refine seg_aluRM hc6 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_) (fun t ht hA => ?_)
    · obtain ⟨-, -, hsv, -, -, -⟩ := hA
      simp only [addr, hsv]
      exact desc_bottom_access hL stack
    · obtain ⟨hm, hdv, hsv, hk, hsp16, h9⟩ := hA
      have hval : load64 t.mem (addr t scratch (caDescBottom stack)) = regGb P stack := by
        simp only [addr, hsv]
        exact desc_bottom_value hm.ro stack
      rw [aluRM_sub, hval]
      refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm
          (fun j _ _ h3 => wRegFlags_regs_ne t x64_ir.R9 _ _ (by rw [r9_val]; exact h3))
          hm.ro rfl,
        by rw [wRegFlags_regs_ne t x64_ir.R9 _ _ (by rw [r9_val]; exact hd9)]; exact hdv,
        hk, hsp16, ?_⟩
      rw [wRegFlags_regs_eq t x64_ir.R9 _ _ r9_val.symm,
        show t.regs (x64_ir.R9).val = t.regs 9 from by rw [r9_val], h9]
      exact span_sub_toNat hL stack hw2
  have step7 : Seg P code (p + 7) 1
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧ K t.mem ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack ∧
        (t.regs 9).toNat
          = (regGt P stack).toNat - size.val - (regGb P stack).toNat)
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧ K t.mem ∧
        t.regs scratch.val = 0#64 ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack ∧
        (t.regs 9).toNat
          = (regGt P stack).toNat - size.val - (regGb P stack).toNat) := by
    refine seg_alu hc7 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_)
    obtain ⟨hm, hdv, hk, hsp16, h9⟩ := hA
    rw [alu_xor_true]
    refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ h2 _ => wRegFlags_regs_ne t scratch _ _ h2)
        hm.ro rfl,
      by rw [wRegFlags_regs_ne t scratch _ _ hds]; exact hdv, hk,
      by rw [wRegFlags_regs_self]; simp, hsp16, ?_⟩
    rw [wRegFlags_regs_ne t scratch _ _ (Ne.symm hs9)]
    exact h9
  have step8 : Seg P code (p + 8) 1
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧ K t.mem ∧
        t.regs scratch.val = 0#64 ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 16) = g - regGb P stack ∧
        (t.regs 9).toNat
          = (regGt P stack).toNat - size.val - (regGb P stack).toNat)
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧ K t.mem ∧
        t.regs scratch.val = 0#64 ∧
        (t.flags.cf = false → (regGb P stack).toNat ≤ g.toNat ∧
          g.toNat + size.val ≤ (regGt P stack).toNat)) := by
    refine seg_aluRM hc8 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA => ?_) (fun t ht hA => ?_)
    · obtain ⟨hm, -, -, -, -, -⟩ := hA
      exact mid_frame_access hL hm (by rw [spill_val]; norm_num) (by rw [spill_val]; norm_num)
    · obtain ⟨hm, hdv, hk, hsv, hsp16, h9⟩ := hA
      have hval : load64 t.mem (addr t x64_ir.RBP x64_ir.frame.SPILL_OFFSET)
          = g - regGb P stack := by rw [hspill t hm]; exact hsp16
      rw [aluRM_cmpRM, hval]
      refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ _ _ => wFlags_regs t _ j) hm.ro rfl,
        by rw [wFlags_regs]; exact hdv, hk, by rw [wFlags_regs]; exact hsv, fun hcf => ?_⟩
      rw [wFlags_flags] at hcf
      have he : (subFlags (t.regs (x64_ir.R9).val) (g - regGb P stack)).cf
          = decide ((t.regs (x64_ir.R9).val).toNat < (g - regGb P stack).toNat) := rfl
      rw [he, show t.regs (x64_ir.R9).val = t.regs 9 from by rw [r9_val]] at hcf
      refine region_pass hL stack hw1 hw2 h9 ?_
      simpa using hcf
  have step9 : Seg P code (p + 9) 1
      (fun t => Mid P a dst.val scratch.val t ∧
        t.regs dst.val = regNb P stack + (g - regGb P stack) ∧ K t.mem ∧
        t.regs scratch.val = 0#64 ∧
        (t.flags.cf = false → (regGb P stack).toNat ≤ g.toNat ∧
          g.toNat + size.val ≤ (regGt P stack).toNat))
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        RegionOut P stack size.val g (t.regs dst.val)) := by
    refine seg_cmov hc9 (fun t _ hA => hA.1.rspWin hL) (fun t ht hA hcc => ?_)
      (fun t ht hA hcc => ?_)
    · obtain ⟨hm, hdv, hk, hsv, -⟩ := hA
      exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j h1 _ _ => wReg_regs_ne t dst _ h1) hm.ro rfl,
        hk, Or.inl (by rw [wReg_regs_self]; exact hsv)⟩
    · obtain ⟨hm, hdv, hk, hsv, himp⟩ := hA
      rw [cond_ccB] at hcc
      obtain ⟨h1, h2⟩ := himp hcc
      exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ _ _ => wNext_regs t j) hm.ro rfl, hk,
        Or.inr ⟨h1, h2, by rw [wNext_regs]; exact hdv⟩⟩
  have h1 : Seg P code p 2 _ _ := step0.trans step1
  have h2 : Seg P code p 3 _ _ := h1.trans step2
  have h3 : Seg P code p 4 _ _ := h2.trans step3
  have h4 : Seg P code p 5 _ _ := h3.trans step4
  have h5 : Seg P code p 6 _ _ := h4.trans step5
  have h6 : Seg P code p 7 _ _ := h5.trans step6
  have h7 : Seg P code p 8 _ _ := h6.trans step7
  have h8 : Seg P code p 9 _ _ := h7.trans step8
  exact h8.trans step9

/-! ## Quantifying the guest address

The value the check starts from is whatever the head of the expansion left in
`dst`; the region lemmas take it as a parameter, so the two are joined by
pushing an existential through a run. `Chain.toSeg` is the converse of
`Seg.toChain`, and is what lets a family of runs be taken apart and put back
together. -/

theorem Chain.toSeg {P : Params} {code : List x64_ir.PInsn} {p n : Nat}
    {R : Nat → State → Prop} (h : Chain P code p n R) : Seg P code p n (R 0) (R n) := by
  induction n generalizing p R with
  | zero => exact .nil (fun _ ht => ht)
  | succ n ih =>
    refine .cons (fun t ht hR => ?_) (ih (R := fun k => R (k + 1)) ?_)
    · exact h 0 (by omega) t (by omega) hR
    · intro k hk t ht hR
      have ht' : t.pc = p + (k + 1) := by omega
      obtain ⟨hacc, hstr, hrsp, hstp⟩ := h (k + 1) (by omega) t ht' hR
      refine ⟨by rw [show p + 1 + k = p + (k + 1) from by omega]; exact hacc,
        by rw [show p + 1 + k = p + (k + 1) from by omega]; exact hstr, hrsp, fun c hc => ?_⟩
      obtain ⟨t', he, hp, hR'⟩ := hstp c hc
      exact ⟨t', he, by rw [hp]; omega, hR'⟩

theorem Seg.exists_index {P : Params} {code : List x64_ir.PInsn} {p n : Nat} {ι : Type}
    {A B : ι → State → Prop} (h : ∀ i, Seg P code p n (A i) (B i)) :
    Seg P code p n (fun t => ∃ i, A i t) (fun t => ∃ i, B i t) := by
  choose R hA hB hCh using fun i => (h i).toChain
  refine Seg.weaken (Chain.toSeg (R := fun k t => ∃ i, R i k t) ?_) ?_ ?_
  · intro k hk t ht hR
    obtain ⟨i, hRi⟩ := hR
    obtain ⟨hacc, hstr, hrsp, hstp⟩ := hCh i k hk t ht hRi
    refine ⟨hacc, hstr, hrsp, fun c hc => ?_⟩
    obtain ⟨t', he, hp, hR'⟩ := hstp c hc
    exact ⟨t', he, hp, ⟨i, hR'⟩⟩
  · rintro t ⟨i, hAi⟩; exact ⟨i, hA i t hAi⟩
  · rintro t ⟨i, hRi⟩; exact ⟨i, hB i t hRi⟩

/-! ## The whole check, one region or two -/

/-- Either shape of region check. -/
theorem region_seg {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {a : x64_check.State} {dst scratch : Std.U8} {size : Std.U32} {stack : Bool}
    {g : Word} {K : Mem → Prop}
    (hL : Layout P) (hD4 : dst.val ≠ 4) (hD5 : dst.val ≠ 5)
    (hS4 : scratch.val ≠ 4) (hS5 : scratch.val ≠ 5) (hds : dst.val ≠ scratch.val)
    (hd9 : dst.val ≠ 9) (hs9 : scratch.val ≠ 9)
    (hw1 : 1 ≤ size.val) (hw2 : size.val ≤ 4096)
    (hK : ∀ (m : Mem) (v : Word), K m → K (store64 m (P.rbp0 - BitVec.ofNat 64 16) v))
    (hlaid : Laid code p (regionList cfg dst scratch size stack)) :
    Seg P code p (regionList cfg dst scratch size stack).length
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧ K t.mem)
      (fun t => Mid P a dst.val scratch.val t ∧ K t.mem ∧
        RegionOut P stack size.val g (t.regs dst.val)) := by
  unfold regionList at hlaid ⊢
  by_cases hfc : cfg.frame_constants = true
  · rw [if_pos hfc] at hlaid ⊢
    exact regionFromFrame_seg hL hD4 hD5 hS4 hS5 hds hd9 hs9 hw1 hw2 hlaid
  · rw [if_neg hfc] at hlaid ⊢
    exact regionViaDescriptor_seg hL hD4 hD5 hS4 hS5 hds hd9 hs9 hw1 hw2 hK hlaid

/-- The `or` of the two candidates: at most one is non-zero. -/
theorem or_regions {P : Params} (hL : Layout P) {size : Std.U32} (hw1 : 1 ≤ size.val)
    {g cs cd : Word} (hs : RegionOut P true size.val g cs)
    (hd : RegionOut P false size.val g cd) :
    TagOk P (x64_check.Tag.Checked size) (cd ||| cs) := by
  have h0r : ∀ x : Word, x ||| 0#64 = x := by intro x; simp
  have h0l : ∀ x : Word, 0#64 ||| x = x := by intro x; simp
  rcases hs with rfl | ⟨h1, h2, rfl⟩
  · rw [h0r]
    exact tagOk_of_regionOut hL hw1 hd
  · rcases hd with rfl | ⟨h3, h4, rfl⟩
    · rw [h0l]
      exact tagOk_of_regionOut hL hw1 (Or.inr ⟨h1, h2, rfl⟩)
    · exact (region_unique hL hw1 ⟨h1, h2⟩ ⟨h3, h4⟩).elim

/-- `x64_expand::expand_checked_addr`, split at the three `++`. -/
def caHead (cfg : x64_ir.Cfg) (src dst : Std.U8) : List x64_ir.PInsn :=
  if caFramed cfg then
    (if src = x64_ir.R15 then guestFpList dst
     else if src != dst then [ .Alu true .Mov src dst ] else [])
  else (if src != dst then [ .Alu true .Mov src dst ] else [])

def caOff (dst : Std.U8) (offset : Std.I32) : List x64_ir.PInsn :=
  if offset != 0#i32 then [ .AluImm true .Add dst offset ] else []

def caProbe (cfg : x64_ir.Cfg) (dst scratch : Std.U8) (size : Std.U32) : List x64_ir.PInsn :=
  [ .Store 8#u8 dst x64_ir.RBP x64_ir.frame.ADDR_SPILL_OFFSET ] ++
  regionList cfg dst scratch size true ++
  [ .Store 8#u8 dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET,
    .Load 8#u8 false x64_ir.RBP dst x64_ir.frame.ADDR_SPILL_OFFSET ] ++
  regionList cfg dst scratch size false ++
  [ .AluRM .Or dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET ]

def caBody (cfg : x64_ir.Cfg) (dst scratch : Std.U8) (size : Std.U32) (hint : Std.U8) :
    List x64_ir.PInsn :=
  if cfg.pointer_mask = 0#i32 then []
  else if hint = x64_ir.region.STACK then regionList cfg dst scratch size true
  else if hint = x64_ir.region.DATA then regionList cfg dst scratch size false
  else caProbe cfg dst scratch size

theorem checkedAddrList_eq (cfg : x64_ir.Cfg) (src dst scratch : Std.U8) (offset : Std.I32)
    (size : Std.U32) (hint : Std.U8) :
    checkedAddrList cfg src dst scratch offset size hint
      = caHead cfg src dst ++ caOff dst offset ++ caBody cfg dst scratch size hint := rfl

/-! ## The two-region probe -/

theorem Laid.shift {code : List x64_ir.PInsn} {p p' : Nat} {L : List x64_ir.PInsn}
    (h : Laid code p L) (hp : p' = p) : Laid code p' L := hp ▸ h

theorem probe_seg {P : Params} {code : List x64_ir.PInsn} {q : Nat} {cfg : x64_ir.Cfg}
    {a : x64_check.State} {dst scratch : Std.U8} {size : Std.U32} {g : Word}
    (hL : Layout P) (hD4 : dst.val ≠ 4) (hD5 : dst.val ≠ 5)
    (hS4 : scratch.val ≠ 4) (hS5 : scratch.val ≠ 5) (hds : dst.val ≠ scratch.val)
    (hd9 : dst.val ≠ 9) (hs9 : scratch.val ≠ 9)
    (hw1 : 1 ≤ size.val) (hw2 : size.val ≤ 4096)
    (hlaid : Laid code q (caProbe cfg dst scratch size)) :
    Seg P code q (caProbe cfg dst scratch size).length
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g)
      (fun t => Mid P a dst.val scratch.val t ∧
        TagOk P (x64_check.Tag.Checked size) (t.regs dst.val)) := by
  obtain ⟨r1, hr1⟩ : ∃ n, (regionList cfg dst scratch size true).length = n := ⟨_, rfl⟩
  obtain ⟨r2, hr2⟩ : ∃ n, (regionList cfg dst scratch size false).length = n := ⟨_, rfl⟩
  have hlen : (caProbe cfg dst scratch size).length = 1 + r1 + 2 + r2 + 1 := by
    simp only [caProbe, List.length_append, List.length_cons, List.length_nil, hr1, hr2]
  -- the list, taken apart at its four appends
  have hA := Laid.left hlaid
  have hB := Laid.left hA
  have hC := Laid.left hB
  have hc0 : code[q]? = some (.Store 8#u8 dst x64_ir.RBP x64_ir.frame.ADDR_SPILL_OFFSET) :=
    (Laid.left hC).head
  have hl1 : Laid code (q + 1) (regionList cfg dst scratch size true) :=
    (Laid.right hC).shift (by simp)
  have hl2 : Laid code (q + (1 + r1))
      [(.Store 8#u8 dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET : x64_ir.PInsn),
       .Load 8#u8 false x64_ir.RBP dst x64_ir.frame.ADDR_SPILL_OFFSET] :=
    (Laid.right hB).shift
      (by
        simp only [List.length_append, List.length_cons, List.length_nil, hr1])
  have hl3 : Laid code (q + (1 + r1 + 2)) (regionList cfg dst scratch size false) :=
    (Laid.right hA).shift
      (by
        simp only [List.length_append, List.length_cons, List.length_nil, hr1])
  have hl4 : Laid code (q + (1 + r1 + 2 + r2))
      [(.AluRM .Or dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET : x64_ir.PInsn)] :=
    (Laid.right hlaid).shift
      (by
        simp only [List.length_append, List.length_cons, List.length_nil, hr1, hr2])
  have hc2 : code[q + (1 + r1)]? = some
      (.Store 8#u8 dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET) := hl2.head
  have hc3 : code[q + (1 + r1) + 1]? = some
      (.Load 8#u8 false x64_ir.RBP dst x64_ir.frame.ADDR_SPILL_OFFSET) := hl2.tail.head
  have hc5 : code[q + (1 + r1 + 2 + r2)]? = some
      (.AluRM .Or dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET) := hl4.head
  -- the two slots the probe parks values in
  have haddr24 : ∀ t : State, Mid P a dst.val scratch.val t →
      addr t x64_ir.RBP x64_ir.frame.ADDR_SPILL_OFFSET = P.rbp0 - BitVec.ofNat 64 24 :=
    fun t hm => mid_rbp_addr hm (by norm_num) (by norm_num) addrSpill_val
  have haddr32 : ∀ t : State, Mid P a dst.val scratch.val t →
      addr t x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET = P.rbp0 - BitVec.ofNat 64 32 :=
    fun t hm => mid_rbp_addr hm (by norm_num) (by norm_num) accSpill_val
  have step0 : Seg P code q 1
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g)
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 24) = g) := by
    refine seg_store8 hc0 (fun t _ hA' => hA'.1.rspWin hL) (fun t ht hA' => ?_)
      (fun t _ hA' => mid_frame_store (j := 24) hL hA'.1 (by norm_num)
        (by rw [addrSpill_val]; norm_num))
      (fun t ht hA' => ?_)
    · obtain ⟨hm, -⟩ := hA'
      exact mid_frame_access hL hm (by rw [addrSpill_val]; norm_num)
        (by rw [addrSpill_val]; norm_num)
    · obtain ⟨hm, hdv⟩ := hA'
      rw [haddr24 t hm]
      exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ _ _ => rfl)
          (romem_store64_slot hL hm.ro (Or.inr (Or.inl rfl)) _)
          (group_slot_kept hL t.mem (Or.inr (Or.inl rfl)) _), hdv,
        by rw [load64_store64_same]; exact hdv⟩
  have step1 : Seg P code (q + 1) r1
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 24) = g)
      (fun t => Mid P a dst.val scratch.val t ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 24) = g ∧
        RegionOut P true size.val g (t.regs dst.val)) := by
    rw [← hr1]
    exact region_seg (K := fun m => load64 m (P.rbp0 - BitVec.ofNat 64 24) = g)
      hL hD4 hD5 hS4 hS5 hds hd9 hs9 hw1 hw2
      (fun m v hm => by rw [load_slot_store_slot hL m (by norm_num) (by norm_num)
        (by norm_num) (by norm_num) (by norm_num) v]; exact hm) hl1
  have step2 : Seg P code (q + (1 + r1)) 2
      (fun t => Mid P a dst.val scratch.val t ∧
        load64 t.mem (P.rbp0 - BitVec.ofNat 64 24) = g ∧
        RegionOut P true size.val g (t.regs dst.val))
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧
        RegionOut P true size.val g (load64 t.mem (P.rbp0 - BitVec.ofNat 64 32))) := by
    have s2a : Seg P code (q + (1 + r1)) 1
        (fun t => Mid P a dst.val scratch.val t ∧
          load64 t.mem (P.rbp0 - BitVec.ofNat 64 24) = g ∧
          RegionOut P true size.val g (t.regs dst.val))
        (fun t => Mid P a dst.val scratch.val t ∧
          load64 t.mem (P.rbp0 - BitVec.ofNat 64 24) = g ∧
          RegionOut P true size.val g (load64 t.mem (P.rbp0 - BitVec.ofNat 64 32))) := by
      refine seg_store8 hc2 (fun t _ hA' => hA'.1.rspWin hL) (fun t ht hA' => ?_)
        (fun t _ hA' => mid_frame_store (j := 32) hL hA'.1 (by norm_num)
          (by rw [accSpill_val]; norm_num))
        (fun t ht hA' => ?_)
      · obtain ⟨hm, -, -⟩ := hA'
        exact mid_frame_access hL hm (by rw [accSpill_val]; norm_num)
          (by rw [accSpill_val]; norm_num)
      · obtain ⟨hm, h24, hro⟩ := hA'
        rw [haddr32 t hm]
        refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j _ _ _ => rfl)
            (romem_store64_slot hL hm.ro (Or.inr (Or.inr (Or.inl rfl))) _)
            (group_slot_kept hL t.mem (Or.inr (Or.inr rfl)) _), ?_, ?_⟩
        · rw [load_slot_store_slot hL t.mem (by norm_num) (by norm_num) (by norm_num)
            (by norm_num) (by norm_num)]
          exact h24
        · rw [load64_store64_same]
          exact hro
    have s2b : Seg P code (q + (1 + r1) + 1) 1
        (fun t => Mid P a dst.val scratch.val t ∧
          load64 t.mem (P.rbp0 - BitVec.ofNat 64 24) = g ∧
          RegionOut P true size.val g (load64 t.mem (P.rbp0 - BitVec.ofNat 64 32)))
        (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧
          RegionOut P true size.val g (load64 t.mem (P.rbp0 - BitVec.ofNat 64 32))) := by
      refine seg_load8 hc3 (fun t _ hA' => hA'.1.rspWin hL) (fun t ht hA' => ?_)
        (fun t ht hA' => ?_)
      · obtain ⟨hm, -, -⟩ := hA'
        exact mid_frame_access hL hm (by rw [addrSpill_val]; norm_num)
          (by rw [addrSpill_val]; norm_num)
      · obtain ⟨hm, h24, hro⟩ := hA'
        exact ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j h1 _ _ => wReg_regs_ne t dst _ h1) hm.ro rfl,
          by rw [wReg_regs_self, haddr24 t hm]; exact h24, hro⟩
    exact s2a.trans s2b
  have step3 : Seg P code (q + (1 + r1 + 2)) r2
      (fun t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧
        RegionOut P true size.val g (load64 t.mem (P.rbp0 - BitVec.ofNat 64 32)))
      (fun t => Mid P a dst.val scratch.val t ∧
        RegionOut P true size.val g (load64 t.mem (P.rbp0 - BitVec.ofNat 64 32)) ∧
        RegionOut P false size.val g (t.regs dst.val)) := by
    rw [← hr2]
    exact region_seg
      (K := fun m => RegionOut P true size.val g (load64 m (P.rbp0 - BitVec.ofNat 64 32)))
      hL hD4 hD5 hS4 hS5 hds hd9 hs9 hw1 hw2
      (fun m v hm => by rw [load_slot_store_slot hL m (by norm_num) (by norm_num)
        (by norm_num) (by norm_num) (by norm_num) v]; exact hm) hl3
  have step4 : Seg P code (q + (1 + r1 + 2 + r2)) 1
      (fun t => Mid P a dst.val scratch.val t ∧
        RegionOut P true size.val g (load64 t.mem (P.rbp0 - BitVec.ofNat 64 32)) ∧
        RegionOut P false size.val g (t.regs dst.val))
      (fun t => Mid P a dst.val scratch.val t ∧
        TagOk P (x64_check.Tag.Checked size) (t.regs dst.val)) := by
    refine seg_aluRM hc5 (fun t _ hA' => hA'.1.rspWin hL) (fun t ht hA' => ?_)
      (fun t ht hA' => ?_)
    · obtain ⟨hm, -, -⟩ := hA'
      exact mid_frame_access hL hm (by rw [accSpill_val]; norm_num)
        (by rw [accSpill_val]; norm_num)
    · obtain ⟨hm, hs, hd⟩ := hA'
      rw [aluRM_or, haddr32 t hm]
      refine ⟨Mid.keep hD4 hD5 hS4 hS5 hm (fun j h1 _ _ => wRegFlags_regs_ne t dst _ _ h1)
          hm.ro rfl, ?_⟩
      rw [wRegFlags_regs_self]
      exact or_regions hL hw1 hs hd
  rw [hlen]
  exact (((step0.trans step1).trans step2).trans step3).trans step4

/-! ## The head of the expansion

Recovering the guest frame pointer, or moving the base, and adding the
displacement: three primitives that write `dst` and nothing else. -/

theorem head_seg {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {a : x64_check.State} {src dst : Std.U8} {S : Nat}
    (hL : Layout P) (hD4 : dst.val ≠ 4) (hD5 : dst.val ≠ 5) (hS4 : S ≠ 4) (hS5 : S ≠ 5)
    (hlaid : Laid code p (caHead cfg src dst)) :
    Seg P code p (caHead cfg src dst).length
      (fun t => Mid P a dst.val S t) (fun t => Mid P a dst.val S t) := by
  have hmov : ∀ s : Std.U8, code[p]? = some (.Alu true .Mov s dst) →
      Seg P code p 1 (fun t => Mid P a dst.val S t) (fun t => Mid P a dst.val S t) := by
    intro s hc
    refine seg_alu hc (fun t _ hm => hm.rspWin hL) (fun t ht hm => ?_)
    rw [alu_mov_true]
    exact Mid.keep hD4 hD5 hS4 hS5 hm (fun j h1 _ _ => wReg_regs_ne t dst _ h1) hm.ro rfl
  have hplain : Laid code p (if src != dst then [(.Alu true .Mov src dst : x64_ir.PInsn)] else [])
      → Seg P code p (if src != dst then [(.Alu true .Mov src dst : x64_ir.PInsn)] else []).length
        (fun t => Mid P a dst.val S t) (fun t => Mid P a dst.val S t) := by
    intro hl
    by_cases hsd : (src != dst) = true
    · rw [if_pos hsd] at hl ⊢
      exact hmov _ (hl.get (k := 0) rfl)
    · rw [if_neg hsd] at hl ⊢
      exact .nil (fun _ h => h)
  unfold caHead at hlaid ⊢
  by_cases hf : caFramed cfg = true
  · rw [if_pos hf] at hlaid ⊢
    by_cases h15 : src = x64_ir.R15
    · rw [if_pos h15] at hlaid ⊢
      have hc0 : code[p]? = some (.Alu true .Mov x64_ir.R15 dst) := hlaid.get (k := 0) rfl
      have hc1 : code[p + 1]? = some
          (.AluRM .Sub dst x64_ir.RBP x64_ir.frame.FRAME_DELTA_OFFSET) := hlaid.get (k := 1) rfl
      have s1 : Seg P code (p + 1) 1
          (fun t => Mid P a dst.val S t) (fun t => Mid P a dst.val S t) := by
        refine seg_aluRM hc1 (fun t _ hm => hm.rspWin hL) (fun t ht hm => ?_) (fun t ht hm => ?_)
        · exact mid_frame_access hL hm (by rw [frameDelta_val]; norm_num)
            (by rw [frameDelta_val]; norm_num)
        · rw [aluRM_sub]
          exact Mid.keep hD4 hD5 hS4 hS5 hm
            (fun j h1 _ _ => wRegFlags_regs_ne t dst _ _ h1) hm.ro rfl
      exact (hmov _ hc0).trans s1
    · rw [if_neg h15] at hlaid ⊢
      exact hplain hlaid
  · rw [if_neg hf] at hlaid ⊢
    exact hplain hlaid

theorem off_seg {P : Params} {code : List x64_ir.PInsn} {q : Nat} {a : x64_check.State}
    {dst : Std.U8} {S : Nat} {offset : Std.I32} (hL : Layout P)
    (hD4 : dst.val ≠ 4) (hD5 : dst.val ≠ 5) (hS4 : S ≠ 4) (hS5 : S ≠ 5)
    (hlaid : Laid code q (caOff dst offset)) :
    Seg P code q (caOff dst offset).length
      (fun t => Mid P a dst.val S t) (fun t => Mid P a dst.val S t) := by
  unfold caOff at hlaid ⊢
  by_cases ho : (offset != 0#i32) = true
  · rw [if_pos ho] at hlaid ⊢
    refine seg_aluImm (hlaid.get (k := 0) rfl) (fun t _ hm => hm.rspWin hL) (fun t ht hm => ?_)
    rw [aluImm_add_true]
    exact Mid.keep hD4 hD5 hS4 hS5 hm (fun j h1 _ _ => wRegFlags_regs_ne t dst _ _ h1) hm.ro rfl
  · rw [if_neg ho] at hlaid ⊢
    exact .nil (fun _ h => h)

/-! ## The body: one region, or the probe through both -/

theorem body_seg {P : Params} {code : List x64_ir.PInsn} {q : Nat} {cfg : x64_ir.Cfg}
    {a : x64_check.State} {dst scratch : Std.U8} {size : Std.U32} {hint : Std.U8}
    (hL : Layout P) (hD4 : dst.val ≠ 4) (hD5 : dst.val ≠ 5)
    (hS4 : scratch.val ≠ 4) (hS5 : scratch.val ≠ 5) (hds : dst.val ≠ scratch.val)
    (hd9 : dst.val ≠ 9) (hs9 : scratch.val ≠ 9)
    (hw1 : 1 ≤ size.val) (hw2 : size.val ≤ 4096)
    (hcage : ¬ (cfg.pointer_mask = 0#i32))
    (hlaid : Laid code q (caBody cfg dst scratch size hint)) :
    Seg P code q (caBody cfg dst scratch size hint).length
      (fun t => Mid P a dst.val scratch.val t)
      (fun t => Mid P a dst.val scratch.val t ∧
        TagOk P (x64_check.Tag.Checked size) (t.regs dst.val)) := by
  have single : ∀ stack : Bool, Laid code q (regionList cfg dst scratch size stack) →
      Seg P code q (regionList cfg dst scratch size stack).length
        (fun t => Mid P a dst.val scratch.val t)
        (fun t => Mid P a dst.val scratch.val t ∧
          TagOk P (x64_check.Tag.Checked size) (t.regs dst.val)) := by
    intro stack hl
    refine Seg.weaken (Seg.exists_index (ι := Word)
      (A := fun g t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g ∧ True)
      (B := fun g t => Mid P a dst.val scratch.val t ∧ True ∧
        RegionOut P stack size.val g (t.regs dst.val))
      (fun g => region_seg (K := fun _ => True) hL hD4 hD5 hS4 hS5 hds hd9 hs9 hw1 hw2
        (fun _ _ _ => trivial) hl)) ?_ ?_
    · intro t hm
      exact ⟨t.regs dst.val, hm, rfl, trivial⟩
    · rintro t ⟨g, hm, -, hro⟩
      exact ⟨hm, tagOk_of_regionOut hL hw1 hro⟩
  unfold caBody at hlaid ⊢
  rw [if_neg hcage] at hlaid ⊢
  by_cases h1 : hint = x64_ir.region.STACK
  · rw [if_pos h1] at hlaid ⊢
    exact single true hlaid
  · rw [if_neg h1] at hlaid ⊢
    by_cases h2 : hint = x64_ir.region.DATA
    · rw [if_pos h2] at hlaid ⊢
      exact single false hlaid
    · rw [if_neg h2] at hlaid ⊢
      refine Seg.weaken (Seg.exists_index (ι := Word)
        (A := fun g t => Mid P a dst.val scratch.val t ∧ t.regs dst.val = g)
        (B := fun _ t => Mid P a dst.val scratch.val t ∧
          TagOk P (x64_check.Tag.Checked size) (t.regs dst.val))
        (fun g => probe_seg hL hD4 hD5 hS4 hS5 hds hd9 hs9 hw1 hw2 hlaid)) ?_ ?_
      · intro t hm
        exact ⟨t.regs dst.val, hm, rfl⟩
      · rintro t ⟨g, h⟩
        exact h

theorem u8_eq_iff' {x y : Std.U8} : x = y ↔ x.val = y.val := by scalar_tac
theorem i32_eq_iff' {x y : Std.I32} : x = y ↔ x.val = y.val := by scalar_tac

end CA

open CA

/-- **The pointer cage, discharged.** After `CheckedAddr`'s expansion every
access it makes is inside the allowed set, control falls through to the next
macro, and `dst` holds a value the checker's `Checked size` tag admits: zero,
or a native address whose `size`-byte window lies inside one guest region's
native backing.

This is the statement the old `emit_single_region_address` comments made about
the branchless bounds check, and the one every guest load, store and atomic
rests on: they are admitted by `tagOk_checked_window`, which is exactly this
tag read back. -/
theorem macroOk_checkedAddr {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {cfg : x64_ir.Cfg} {pre post : x64_check.State} {src dst scratch : Std.U8}
    {offset : Std.I32} {size : Std.U32} {hint : Std.U8} {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (hcage : cfg.pointer_mask ≠ 0#i32) (hlive : pre.alive = true)
    (hstep : x64_check.live_step cfg (.CheckedAddr src dst scratch offset size hint) index pcv pre
      = ok (.Ok (), post))
    (hE : ∀ k, k < (checkedAddrList cfg src dst scratch offset size hint).length →
      code[p + k]? = (checkedAddrList cfg src dst scratch offset size hint)[k]?) :
    MacroOk P code p (p + (checkedAddrList cfg src dst scratch offset size hint).length)
      pre post [] := by
  obtain ⟨hds, hd9, hs9, hw1, hw2, hwd, hwsr, htd, hts, ht9, hkeep, hdep, hgrp, -⟩ :=
    live_step_CheckedAddr_spec hlive hstep
  have hdsv : dst.val ≠ scratch.val := fun h => hds (u8_eq_iff'.mpr h)
  have hpm : cfg.pointer_mask.val ≠ 0 := fun h => hcage (i32_eq_iff'.mpr (by simp [h]))
  rw [if_pos hpm] at htd
  have hlaid : Laid code p (checkedAddrList cfg src dst scratch offset size hint) := hE
  rw [checkedAddrList_eq] at hlaid
  have hlen : (checkedAddrList cfg src dst scratch offset size hint).length
      = (caHead cfg src dst).length + (caOff dst offset).length
        + (caBody cfg dst scratch size hint).length := by
    rw [checkedAddrList_eq, List.length_append, List.length_append]
  have hbody : Laid code (p + ((caHead cfg src dst).length + (caOff dst offset).length))
      (caBody cfg dst scratch size hint) :=
    (Laid.right hlaid).shift (by rw [List.length_append])
  have seg := ((head_seg (a := pre) (S := scratch.val) hL hwd.1 hwd.2.1 hwsr.1 hwsr.2.1
      (Laid.left (Laid.left hlaid))).trans
    (off_seg (a := pre) (S := scratch.val) hL hwd.1 hwd.2.1 hwsr.1 hwsr.2.1
      (Laid.right (Laid.left hlaid)))).trans
    (body_seg (a := pre) hL hwd.1 hwd.2.1 hwsr.1 hwsr.2.1 hdsv hd9 hs9 hw1 hw2 hcage hbody)
  rw [hlen]
  refine macroOk_of_seg ?_ ?_ seg
  · intro t ht hag
    exact ⟨fun r hr _ _ _ => hag.regs r hr, hag.rsp, hag.depth, hag.rbp, hag.ro, hag.group⟩
  · rintro t ⟨hm, htag⟩
    refine ⟨fun r hr => ?_, ?_, ?_, hm.rbp, hm.ro, ?_⟩
    · by_cases h1 : r = dst.val
      · subst h1; rw [htd]; exact htag
      · by_cases h2 : r = scratch.val
        · subst h2; rw [hts]; trivial
        · by_cases h3 : r = 9
          · subst h3; rw [ht9]; trivial
          · rw [hkeep r h1 h2 h3]; exact hm.regs r hr h1 h2 h3
    · rw [hdep]; exact hm.rsp
    · rw [hdep]; exact hm.depth
    · rw [hgrp]; exact hm.group

end X64

end async_ebpf_verified

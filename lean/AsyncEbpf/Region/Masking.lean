import AsyncEbpf.Region.Proofs

/-!
# Live-in masking does not change what the region analysis sees

`region_analysis::analyze_function` runs `transfer` and `meet_from` to a
fixed point over a function's control-flow graph from the signature its
caller passes, and the caller first masks that signature to the callee's
live-in registers (`mask_signature`), so that callees are not specialized
on registers they never read. This file states what makes the masking
harmless, at the level of the extracted core:

* `AgreeAt L S₁ S₂`: two states agree on the registers `L` names, on `R10`,
  and on the spill slots;
* `LiveSolution`: a live-in table `L` solves the dataflow equations the
  Rust live-in solver computes — at every reachable slot it covers the
  slot's uses and, minus the slot's defs, the live-in of every successor;
* `step_agree`: one `transfer` from states that agree at `p` yields states
  that agree at every successor `q` of `p`, and the same cap flag;
* `meet_from_agree`: `meet_from` keeps the agreement;
* `run_agree`: hence any schedule of the worklist — any sequence of slots,
  each processed by a transfer and a meet into its successors — keeps two
  state tables agreeing at every slot;
* `classify_agree`, `call_signature_agree`: agreeing states classify
  every access alike and hand every callee the same masked signature;
* `masked_entry_agree`: the masked and the unmasked entry states agree at
  the entry slot.

What this does not say is that the two actual runs of the driver process
the same schedule: the driver's worklist re-queues a slot when *any*
register changes, dead ones included, so the masked and the unmasked run
can process slots in different orders. `transfer` is not monotone in the
kind lattice (a fill from an untracked slot reads as a scalar, from a
tracked one as the spilled pointer), so a different order can in principle
reach a different fixed point. The unit test
`region_analysis::masking_fuzz::masking_is_precision_neutral` checks that
it does not, on random programs whose two runs do take different
schedules; that step is tested, not proved.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

/-! ## Structural equality and the meet -/

/-- `kind_eq` is structural equality. -/
theorem kind_eq_true {a b : region.RegKind} {c : Bool} (h : region.kind_eq a b = ok c) :
    c = true ↔ a = b := by
  unfold region.kind_eq at h
  cases a <;> cases b <;> (try (simp only [ok.injEq] at h; subst h; simp))
  rename_i x y
  cases x <;> cases y <;> (try (simp only [ok.injEq] at h; subst h; simp))
  rename_i o o'
  cases o <;> cases o' <;> simp only [ok.injEq] at h <;> subst h <;> simp

/-- `meet_regs` is the pointwise meet. -/
theorem meet_regs_spec {regs other : Std.Array region.RegKind 11#usize} {c : Bool}
    {a : Std.Array region.RegKind 11#usize} (h : region.meet_regs regs other = ok (c, a)) :
    ∀ (k : Nat) x y, regs.val[k]? = some x → other.val[k]? = some y →
      ∃ m, region.meet x y = ok m ∧ a.val[k]? = some m := by
  unfold region.meet_regs region.meet_regs_loop at h
  exact loop_ok_induction _
    (fun st => st.2.2.val ≤ 11 ∧
      (∀ (k : Nat) x y, k < st.2.2.val → regs.val[k]? = some x → other.val[k]? = some y →
        ∃ m, region.meet x y = ok m ∧ st.1.val[k]? = some m) ∧
      (∀ (k : Nat), st.2.2.val ≤ k → st.1.val[k]? = regs.val[k]?))
    (fun y => ∀ (k : Nat) x z, regs.val[k]? = some x → other.val[k]? = some z →
      ∃ m, region.meet x z = ok m ∧ y.2.val[k]? = some m)
    (by
      rintro ⟨rs, ch, r⟩ ⟨hr, hlt, hge⟩ res hb
      dsimp only at hr hlt hge
      change region.meet_regs_loop.body other rs ch r = ok res at hb
      unfold region.meet_regs_loop.body at hb
      split at hb
      · rename_i hlt11
        have hlt11' : r.val < 11 := by
          rw [UScalar.lt_equiv] at hlt11; simpa [region.NUM_REGS] using hlt11
        obtain_bind ⟨rk, hrk, hb⟩ := hb
        obtain_bind ⟨rk1, hrk1, hb⟩ := hb
        obtain_bind ⟨merged, hm, hb⟩ := hb
        obtain_bind ⟨beq, hbeq, hb⟩ := hb
        obtain ⟨_, rfl⟩ := array_index_usize_eq_ok hrk
        obtain ⟨hlo, rfl⟩ := array_index_usize_eq_ok hrk1
        have hrs : regs.val[r.val]? = some rs.val[r.val] := by
          rw [← hge r.val (le_refl _), List.getElem?_eq_getElem]
        have hot : other.val[r.val]? = some other.val[r.val] := List.getElem?_eq_getElem hlo
        split at hb
        · obtain_bind ⟨r1, hr1, hb⟩ := hb
          have hr1v := usize_add_eq_ok hr1
          simp at hr1v
          simp only [ok.injEq] at hb
          subst hb
          rename_i hbt
          have heq := (kind_eq_true hbeq).mp hbt
          refine ⟨by dsimp only; omega, fun k x y hk hx hy => ?_, fun k hk => ?_⟩
          · dsimp only at hk ⊢
            by_cases hkr : k = r.val
            · subst hkr
              rw [hrs] at hx
              rw [hot] at hy
              simp only [Option.some.injEq] at hx hy
              subst hx hy
              exact ⟨merged, hm, by rw [heq, List.getElem?_eq_getElem]⟩
            · exact hlt k x y (by omega) hx hy
          · dsimp only at hk ⊢
            exact hge k (by omega)
        · obtain_bind ⟨a', ha', hb⟩ := hb
          obtain_bind ⟨r1, hr1, hb⟩ := hb
          have hr1v := usize_add_eq_ok hr1
          simp at hr1v
          simp only [ok.injEq] at hb
          subst hb
          obtain ⟨hltl, ha'⟩ := array_update_eq_ok ha'
          refine ⟨by dsimp only; omega, fun k x y hk hx hy => ?_, fun k hk => ?_⟩
          · dsimp only at hk ⊢
            rw [ha']
            by_cases hkr : k = r.val
            · subst hkr
              rw [hrs] at hx
              rw [hot] at hy
              simp only [Option.some.injEq] at hx hy
              subst hx hy
              exact ⟨merged, hm, List.getElem?_set_self hltl⟩
            · rw [List.getElem?_set_ne (Ne.symm hkr)]
              exact hlt k x y (by omega) hx hy
          · dsimp only at hk ⊢
            rw [ha', List.getElem?_set_ne (by omega)]
            exact hge k (by omega)
      · rename_i hge11
        simp only [ok.injEq] at hb
        subst hb
        have h11 : 11 ≤ r.val := by
          have := usize_not_lt hge11; simpa [region.NUM_REGS] using this
        intro k x z hx hz
        have hk : k < 11 := by
          have := List.getElem?_eq_some_iff.mp hx
          simpa using this.1
        exact hlt k x z (by omega) hx hz)
    _ _ ⟨by simp, fun k _ _ hk _ _ => by simp at hk, fun k _ => rfl⟩ h

/-- The registers `live` names agree, `R10` agrees, and the spills are equal. -/
structure AgreeAt (live : U16) (S₁ S₂ : region.State) : Prop where
  live : ∀ r, live.val.testBit r → S₁.regs.val[r]? = S₂.regs.val[r]?
  fp : S₁.regs.val[10]? = S₂.regs.val[10]?
  spills : S₁.spills = S₂.spills

theorem AgreeAt.of_eq {live : U16} {S : region.State} : AgreeAt live S S :=
  ⟨fun _ _ => rfl, rfl, rfl⟩

/-- `meet_from` keeps agreement: where both inputs agree, so does the meet. -/
theorem meet_from_agree {live : U16} {S₁ S₂ O₁ O₂ T₁ T₂ : region.State} {c₁ c₂ r₁ r₂ : Bool}
    (hS : AgreeAt live S₁ S₂) (hO : AgreeAt live O₁ O₂)
    (h₁ : region.meet_from S₁ O₁ = ok ((c₁, r₁), T₁))
    (h₂ : region.meet_from S₂ O₂ = ok ((c₂, r₂), T₂)) :
    AgreeAt live T₁ T₂ ∧ r₁ = r₂ := by
  unfold region.meet_from at h₁ h₂
  obtain_bind ⟨⟨rc₁, a₁⟩, hmr₁, h₁⟩ := h₁
  obtain_bind ⟨⟨rc₂, a₂⟩, hmr₂, h₂⟩ := h₂
  obtain_bind ⟨⟨⟨sc₁, rf₁⟩, sp₁⟩, hms₁, h₁⟩ := h₁
  obtain_bind ⟨⟨⟨sc₂, rf₂⟩, sp₂⟩, hms₂, h₂⟩ := h₂
  rw [hS.spills, hO.spills, hms₂] at hms₁
  simp only [ok.injEq, Prod.mk.injEq] at hms₁
  obtain ⟨⟨rfl, rfl⟩, rfl⟩ := hms₁
  have hm₁ := meet_regs_spec hmr₁
  have hm₂ := meet_regs_spec hmr₂
  have hreg : ∀ k, k < 11 → S₁.regs.val[k]? = S₂.regs.val[k]? → O₁.regs.val[k]? = O₂.regs.val[k]? →
      a₁.val[k]? = a₂.val[k]? := by
    intro k hk hs ho
    have l₁ : S₂.regs.val.length = 11 := by simp
    have l₂ : O₂.regs.val.length = 11 := by simp
    obtain ⟨m₁, hm₁, ha₁⟩ := hm₁ k _ _ (hs.trans (List.getElem?_eq_getElem (by omega)))
      (ho.trans (List.getElem?_eq_getElem (by omega)))
    obtain ⟨m₂, hm₂, ha₂⟩ := hm₂ k _ _ (List.getElem?_eq_getElem (by omega))
      (List.getElem?_eq_getElem (by omega))
    rw [hm₂] at hm₁
    simp only [ok.injEq] at hm₁
    subst hm₁
    rw [ha₁, ha₂]
  have h₁' : (if rc₁ = true then ok ((true, rf₂), ({ regs := a₁, spills := sp₂ } : region.State))
      else ok ((sc₂, rf₂), ({ regs := a₁, spills := sp₂ } : region.State))) = ok ((c₁, r₁), T₁) := h₁
  have h₂' : (if rc₂ = true then ok ((true, rf₂), ({ regs := a₂, spills := sp₂ } : region.State))
      else ok ((sc₂, rf₂), ({ regs := a₂, spills := sp₂ } : region.State))) = ok ((c₂, r₂), T₂) := h₂
  have e₁ : T₁ = { regs := a₁, spills := sp₂ } ∧ r₁ = rf₂ := by
    split at h₁' <;> simp only [ok.injEq, Prod.mk.injEq] at h₁' <;> exact ⟨h₁'.2.symm, h₁'.1.2.symm⟩
  have e₂ : T₂ = { regs := a₂, spills := sp₂ } ∧ r₂ = rf₂ := by
    split at h₂' <;> simp only [ok.injEq, Prod.mk.injEq] at h₂' <;> exact ⟨h₂'.2.symm, h₂'.1.2.symm⟩
  obtain ⟨rfl, rfl⟩ := e₁
  obtain ⟨rfl, rfl⟩ := e₂
  refine ⟨⟨fun r hr => ?_, ?_, rfl⟩, rfl⟩
  · by_cases hk : r < 11
    · exact hreg r hk (hS.live r hr) (hO.live r hr)
    · have l₁ : a₁.val.length = 11 := by simp
      have l₂ : a₂.val.length = 11 := by simp
      show a₁.val[r]? = a₂.val[r]?
      rw [List.getElem?_eq_none (by omega), List.getElem?_eq_none (by omega)]
  · exact hreg 10 (by omega) hS.fp hO.fp

/-! ## One step along an edge -/

/-- A live-in table `L` over a function whose slots `p` hold `insn p`, whose
successor lists are `succs`, and whose reachable slots are `R`: the table
solves the equations the Rust live-in solver computes, as inequalities —
at every reachable slot, `L p` covers the slot's uses and every successor's
live-in minus the slot's defs. `callee p` is the live-in mask of the callee
a local call at `p` enters. -/
structure LiveSolution (insn : Nat → isa.Insn) (callee : Nat → U16) (succs : Nat → List Nat)
    (R : Nat → Prop) (L : Nat → U16) : Prop where
  closed : ∀ p q, R p → q ∈ succs p → R q
  live : ∀ p, R p → ∃ uses defs, region.uses_and_defs (insn p) (callee p) = ok (uses, defs) ∧
    (∀ r, uses.val.testBit r → (L p).val.testBit r) ∧
    (∀ q, q ∈ succs p → ∀ r, (L q).val.testBit r → ¬ defs.val.testBit r → (L p).val.testBit r)

/-- Every instruction the validator accepts names registers `R0`–`R10`. -/
def RegsOk (insn : Nat → isa.Insn) (R : Nat → Prop) : Prop :=
  ∀ p, R p → (insn p).dst.val ≤ 10 ∧ (insn p).src.val ≤ 10

/-- One `transfer` from states that agree at `p` yields states that agree at
every successor `q`, and the same cap flag. -/
theorem step_agree {insn : Nat → isa.Insn} {callee : Nat → U16} {succs : Nat → List Nat}
    {R : Nat → Prop} {L : Nat → U16} (hL : LiveSolution insn callee succs R L)
    (hregs : RegsOk insn R) {p q : Nat} (hp : R p) (hq : q ∈ succs p)
    {S₁ S₂ T₁ T₂ : region.State} {b₁ b₂ : Bool} {lddw lo hi : U64}
    (hA : AgreeAt (L p) S₁ S₂)
    (h₁ : region.transfer S₁ (insn p) lddw lo hi = ok (T₁, b₁))
    (h₂ : region.transfer S₂ (insn p) lddw lo hi = ok (T₂, b₂)) :
    AgreeAt (L q) T₁ T₂ ∧ b₁ = b₂ := by
  obtain ⟨uses, defs, hud, huses, hflow⟩ := hL.live p hp
  obtain ⟨hst, hb⟩ := transfer_agree hud hA.spills (fun r hr => hA.live r (huses r hr)) hA.fp
    (hregs p hp).1 (hregs p hp).2 h₁ h₂
  refine ⟨⟨fun r hr => ?_, ?_, hst.spills⟩, hb⟩
  · by_cases hd : defs.val.testBit r
    · exact hst.defs r hd
    · rcases hst.rest r with h | ⟨e₁, e₂⟩
      · exact h
      · rw [e₁, e₂]
        exact hA.live r (hflow q hq r hr hd)
  · rcases hst.rest 10 with h | ⟨e₁, e₂⟩
    · exact h
    · rw [e₁, e₂]
      exact hA.fp

/-! ## Along a path -/

/-- Two runs of the analysis along one path of the control-flow graph: both
start at `start` in `E₁`, `E₂` and take the same edges. -/
inductive Trace2 (insn : Nat → isa.Insn) (succs : Nat → List Nat) (lddw : Nat → U64) (lo hi : U64)
    (start : Nat) (E₁ E₂ : region.State) : Nat → region.State → region.State → Prop
  | start : Trace2 insn succs lddw lo hi start E₁ E₂ start E₁ E₂
  | step {p q : Nat} {S₁ S₂ T₁ T₂ : region.State} {b₁ b₂ : Bool} :
      Trace2 insn succs lddw lo hi start E₁ E₂ p S₁ S₂ → q ∈ succs p →
      region.transfer S₁ (insn p) (lddw p) lo hi = ok (T₁, b₁) →
      region.transfer S₂ (insn p) (lddw p) lo hi = ok (T₂, b₂) →
      Trace2 insn succs lddw lo hi start E₁ E₂ q T₁ T₂

/-- Along every path, the two runs agree at every slot they reach. -/
theorem trace_agree {insn : Nat → isa.Insn} {callee : Nat → U16} {succs : Nat → List Nat}
    {R : Nat → Prop} {L : Nat → U16} (hL : LiveSolution insn callee succs R L)
    (hregs : RegsOk insn R) {lddw : Nat → U64} {lo hi : U64} {start : Nat} {E₁ E₂ : region.State}
    (hstart : R start) (hE : AgreeAt (L start) E₁ E₂) {p : Nat} {S₁ S₂ : region.State}
    (ht : Trace2 insn succs lddw lo hi start E₁ E₂ p S₁ S₂) : R p ∧ AgreeAt (L p) S₁ S₂ := by
  induction ht with
  | start => exact ⟨hstart, hE⟩
  | step _ hq h₁ h₂ ih =>
    exact ⟨hL.closed _ _ ih.1 hq, (step_agree hL hregs ih.1 hq ih.2 h₁ h₂).1⟩

/-! ## Along a schedule of the worklist -/

/-- `MeetInto out qs T T'`: meet `out` into each slot of `qs` in turn. -/
inductive MeetInto (out : region.State) : List Nat → (Nat → region.State) → (Nat → region.State) → Prop
  | nil {T : Nat → region.State} : MeetInto out [] T T
  | cons {q : Nat} {qs : List Nat} {T T' : Nat → region.State} {U : region.State} {c r : Bool} :
      region.meet_from (T q) out = ok ((c, r), U) → MeetInto out qs (Function.update T q U) T' →
      MeetInto out (q :: qs) T T'

/-- `Run sched T T'`: the worklist processes the slots of `sched` in order,
each by one transfer and a meet into its successors. -/
inductive Run (insn : Nat → isa.Insn) (succs : Nat → List Nat) (lddw : Nat → U64) (lo hi : U64) :
    List Nat → (Nat → region.State) → (Nat → region.State) → Prop
  | nil {T : Nat → region.State} : Run insn succs lddw lo hi [] T T
  | cons {p : Nat} {ps : List Nat} {T T' T'' : Nat → region.State} {out : region.State} {b : Bool} :
      region.transfer (T p) (insn p) (lddw p) lo hi = ok (out, b) → MeetInto out (succs p) T T' →
      Run insn succs lddw lo hi ps T' T'' → Run insn succs lddw lo hi (p :: ps) T T''

/-- Two state tables agree at every slot. -/
def TablesAgree (L : Nat → U16) (T₁ T₂ : Nat → region.State) : Prop :=
  ∀ p, AgreeAt (L p) (T₁ p) (T₂ p)

theorem meet_into_agree {L : Nat → U16} {out₁ out₂ : region.State} {qs : List Nat}
    {T₁ T₂ T₁' T₂' : Nat → region.State}
    (hout : ∀ q, q ∈ qs → AgreeAt (L q) out₁ out₂) (hT : TablesAgree L T₁ T₂)
    (h₁ : MeetInto out₁ qs T₁ T₁') (h₂ : MeetInto out₂ qs T₂ T₂') : TablesAgree L T₁' T₂' := by
  induction h₁ generalizing T₂ with
  | nil => cases h₂; exact hT
  | @cons q qs T T' U c r hm hrest ih =>
    cases h₂ with
    | cons hm' hrest' =>
      apply ih (fun q' hq' => hout q' (List.mem_cons_of_mem _ hq')) _ hrest'
      intro p
      by_cases hpq : p = q
      · subst hpq
        simp only [Function.update_self]
        exact (meet_from_agree (hT p) (hout p (List.mem_cons_self ..)) hm hm').1
      · simp only [Function.update_of_ne hpq]
        exact hT p

/-- Any common schedule keeps two agreeing tables agreeing. -/
theorem run_agree {insn : Nat → isa.Insn} {callee : Nat → U16} {succs : Nat → List Nat}
    {R : Nat → Prop} {L : Nat → U16} (hL : LiveSolution insn callee succs R L)
    (hregs : RegsOk insn R) {lddw : Nat → U64} {lo hi : U64} {sched : List Nat}
    (hsched : ∀ p, p ∈ sched → R p) {T₁ T₂ T₁' T₂' : Nat → region.State}
    (hT : TablesAgree L T₁ T₂) (h₁ : Run insn succs lddw lo hi sched T₁ T₁')
    (h₂ : Run insn succs lddw lo hi sched T₂ T₂') : TablesAgree L T₁' T₂' := by
  induction h₁ generalizing T₂ with
  | nil => cases h₂; exact hT
  | @cons p ps T T' T'' out b htr hmi hrest ih =>
    cases h₂ with
    | cons htr' hmi' hrest' =>
      have hp : R p := hsched p (List.mem_cons_self ..)
      refine ih (fun q hq => hsched q (List.mem_cons_of_mem _ hq)) ?_ hrest'
      exact meet_into_agree (fun q hq => (step_agree hL hregs hp hq (hT p) htr htr').1) hT hmi hmi'

/-! ## What the analysis reports -/

theorem index_usize_congr {α : Type} {n : Usize} {a b : Std.Array α n} {i : Usize}
    (h : a.val[i.val]? = b.val[i.val]?) : Array.index_usize a i = Array.index_usize b i := by
  unfold Array.index_usize
  rw [show a[i]? = a.val[i.val]? from rfl, show b[i]? = b.val[i.val]? from rfl, h]

/-- `frame_access` reads only `R10`. -/
theorem frame_access_congr {S₁ S₂ : region.State} (h10 : S₁.regs.val[10]? = S₂.regs.val[10]?)
    (inst : isa.Insn) (base : Usize) (F : U16) :
    region.frame_access S₁ inst base F = region.frame_access S₂ inst base F := by
  unfold region.frame_access
  have h10' : S₁.regs.val[region.R10.val]? = S₂.regs.val[region.R10.val]? := by
    simpa [region.R10] using h10
  rw [index_usize_congr h10']

/-- States that agree on an access's base register and on `R10` classify
it alike. -/
theorem classify_agree {S₁ S₂ : region.State} {inst : isa.Insn} {F : U16}
    (hsrc : inst.opcode.val &&& 7 = 1 → S₁.regs.val[inst.src.val]? = S₂.regs.val[inst.src.val]?)
    (hdst : inst.opcode.val &&& 7 = 2 ∨ inst.opcode.val &&& 7 = 3 →
      S₁.regs.val[inst.dst.val]? = S₂.regs.val[inst.dst.val]?)
    (h10 : S₁.regs.val[10]? = S₂.regs.val[10]?) :
    region.classify S₁ inst F = region.classify S₂ inst F := by
  have hdv : (UScalar.cast .Usize inst.dst).val = inst.dst.val := u8_cast_usize_val _
  have hsv : (UScalar.cast .Usize inst.src).val = inst.src.val := u8_cast_usize_val _
  unfold region.classify
  simp only [lift, bind_tc_ok, frame_access_congr h10]
  split
  · rename_i hc
    have := cls_eq (n := 1) hc (by simp [isa.CLS_LDX])
    have e := index_usize_congr (a := S₁.regs) (b := S₂.regs) (i := UScalar.cast .Usize inst.src)
      (by rw [hsv]; exact hsrc this)
    rw [e]
  split
  · rename_i hc
    have := cls_eq (n := 2) hc (by simp [isa.CLS_ST])
    have e := index_usize_congr (a := S₁.regs) (b := S₂.regs) (i := UScalar.cast .Usize inst.dst)
      (by rw [hdv]; exact hdst (Or.inl this))
    rw [e]
  split
  · rename_i hc
    have := cls_eq (n := 3) hc (by simp [isa.CLS_STX])
    have e := index_usize_congr (a := S₁.regs) (b := S₂.regs) (i := UScalar.cast .Usize inst.dst)
      (by rw [hdv]; exact hdst (Or.inr this))
    rw [e]
  rfl

/-- The base register of an access is among its uses. -/
theorem base_in_uses {inst : isa.Insn} {callee uses defs : U16}
    (hud : region.uses_and_defs inst callee = ok (uses, defs)) :
    (inst.opcode.val &&& 7 = 1 → inst.src.val < 10 → uses.val.testBit inst.src.val) ∧
    ((inst.opcode.val &&& 7 = 2 ∨ inst.opcode.val &&& 7 = 3) → inst.dst.val < 10 →
      uses.val.testBit inst.dst.val) := by
  have hdv : (UScalar.cast .Usize inst.dst).val = inst.dst.val := u8_cast_usize_val _
  have hsv : (UScalar.cast .Usize inst.src).val = inst.src.val := u8_cast_usize_val _
  unfold region.uses_and_defs at hud
  obtain_bind ⟨cls, hcls, hud⟩ := hud
  have hclsv : cls = inst.opcode &&& isa.CLS_MASK := lift_eq_ok hcls
  clear hcls
  obtain_bind ⟨dstU, hdstU, hud⟩ := hud
  obtain_bind ⟨srcU, hsrcU, hud⟩ := hud
  rw [lift_eq_ok hdstU, lift_eq_ok hsrcU] at hud
  clear hdstU hsrcU
  by_cases h0 : cls = isa.CLS_LD
  · have := cls_eq (n := 0) (hclsv.symm.trans h0) (by simp [isa.CLS_LD])
    exact ⟨fun h => by omega, fun h => by omega⟩
  rw [if_neg h0] at hud
  by_cases h1 : cls = isa.CLS_LDX
  · have := cls_eq (n := 1) (hclsv.symm.trans h1) (by simp [isa.CLS_LDX])
    rw [if_pos h1] at hud
    obtain_bind ⟨u, hu, hud⟩ := hud
    obtain_bind ⟨d, hd, hud⟩ := hud
    simp only [ok.injEq, Prod.mk.injEq] at hud
    obtain ⟨rfl, rfl⟩ := hud
    refine ⟨fun _ hlt => ?_, fun h => by omega⟩
    rw [reg_bit_testBit hu, hsv]
    exact ⟨hlt, rfl⟩
  rw [if_neg h1] at hud
  by_cases h2 : cls = isa.CLS_ST
  · have := cls_eq (n := 2) (hclsv.symm.trans h2) (by simp [isa.CLS_ST])
    rw [if_pos h2] at hud
    obtain_bind ⟨u, hu, hud⟩ := hud
    simp only [ok.injEq, Prod.mk.injEq] at hud
    obtain ⟨rfl, rfl⟩ := hud
    refine ⟨fun h => by omega, fun _ hlt => ?_⟩
    rw [reg_bit_testBit hu, hdv]
    exact ⟨hlt, rfl⟩
  rw [if_neg h2] at hud
  by_cases h3 : cls = isa.CLS_STX
  · have := cls_eq (n := 3) (hclsv.symm.trans h3) (by simp [isa.CLS_STX])
    rw [if_pos h3] at hud
    obtain_bind ⟨u, hu, hud⟩ := hud
    obtain_bind ⟨u', hu', hud⟩ := hud
    obtain_bind ⟨uses', huses', hud⟩ := hud
    rw [lift_eq_ok huses'] at hud
    clear huses'
    obtain_bind ⟨at_, hat, hud⟩ := hud
    refine ⟨fun h => by omega, fun _ hlt => ?_⟩
    have hbit : (u ||| u').val.testBit inst.dst.val := by
      rw [or_testBit]
      have : u.val.testBit inst.dst.val := by
        rw [reg_bit_testBit hu, hdv]
        exact ⟨hlt, rfl⟩
      simp [this]
    by_cases hb : at_ = true
    · rw [if_pos hb] at hud
      obtain_bind ⟨u0, hu0, hud⟩ := hud
      obtain_bind ⟨u1, hu1, hud⟩ := hud
      rw [lift_eq_ok hu1] at hud
      simp only [ok.injEq, Prod.mk.injEq] at hud
      obtain ⟨rfl, rfl⟩ := hud
      rw [or_testBit, hbit]
      simp
    · rw [if_neg hb] at hud
      simp only [ok.injEq, Prod.mk.injEq] at hud
      obtain ⟨rfl, rfl⟩ := hud
      exact hbit
  · have hn2 : inst.opcode.val &&& 7 ≠ 2 := fun h => h2 (by
      rw [hclsv]
      apply UScalar.eq_equiv _ _ |>.mpr
      rw [cls_val, h]
      simp [isa.CLS_ST])
    have hn3 : inst.opcode.val &&& 7 ≠ 3 := fun h => h3 (by
      rw [hclsv]
      apply UScalar.eq_equiv _ _ |>.mpr
      rw [cls_val, h]
      simp [isa.CLS_STX])
    have hn1 : inst.opcode.val &&& 7 ≠ 1 := fun h => h1 (by
      rw [hclsv]
      apply UScalar.eq_equiv _ _ |>.mpr
      rw [cls_val, h]
      simp [isa.CLS_LDX])
    exact ⟨fun h => absurd h hn1, fun h => by rcases h with h | h <;> contradiction⟩

/-- At a slot the two runs agree at, every access gets the same hint and the
same routing region. -/
theorem hint_agree {insn : Nat → isa.Insn} {callee : Nat → U16} {succs : Nat → List Nat}
    {R : Nat → Prop} {L : Nat → U16} (hL : LiveSolution insn callee succs R L)
    (hregs : RegsOk insn R) {p : Nat} (hp : R p) {S₁ S₂ : region.State}
    (hA : AgreeAt (L p) S₁ S₂) (F : U16) :
    region.classify S₁ (insn p) F = region.classify S₂ (insn p) F := by
  obtain ⟨uses, defs, hud, huses, _⟩ := hL.live p hp
  obtain ⟨hs, hd⟩ := base_in_uses hud
  obtain ⟨hdst, hsrc⟩ := hregs p hp
  apply classify_agree _ _ hA.fp
  · intro hc
    by_cases h : (insn p).src.val = 10
    · rw [h]; exact hA.fp
    · exact hA.live _ (huses _ (hs hc (by omega)))
  · intro hc
    by_cases h : (insn p).dst.val = 10
    · rw [h]; exact hA.fp
    · exact hA.live _ (huses _ (hd hc (by omega)))

/-! ## Call signatures -/

theorem and_two_pow_eq_zero (m k : Nat) : m &&& 2 ^ k = 0 ↔ ¬ m.testBit k := by
  constructor
  · intro h hb
    have := congrArg (fun x => x.testBit k) h
    simp [Nat.testBit_and, hb] at this
  · intro hb
    apply Nat.eq_of_testBit_eq
    intro i
    simp only [Nat.testBit_and, Nat.testBit_two_pow, Nat.zero_testBit]
    by_cases hik : k = i
    · subst hik; simp [hb]
    · simp [hik]

theorem usize_ne_ten {reg : Usize} (h : (reg != region.R10) = true) : reg.val ≠ 10 := by
  intro h10
  rw [bne_iff_ne] at h
  apply h
  rw [UScalar.eq_equiv, h10]
  simp [region.R10]

theorem usize_eq_ten {reg : Usize} (h : ¬ (reg != region.R10) = true) : reg.val = 10 := by
  simp only [bne_iff_ne, ne_eq, not_not] at h
  subst h
  simp [region.R10]

/-- `signature_from_state` turns every stack pointer foreign and puts the
frame pointer in `R10`. -/
theorem signature_from_state_spec {S : region.State} {sig : region.PointerSignature}
    (h : region.signature_from_state S = ok sig) :
    sig.regs.val[10]? = some fpKind ∧
    ∀ (k : Nat) x, k ≠ 10 → S.regs.val[k]? = some x →
      ∃ f, region.foreign_for_call x = ok f ∧ sig.regs.val[k]? = some f := by
  unfold region.signature_from_state at h
  obtain_bind ⟨regs, hregs, h⟩ := h
  obtain_bind ⟨rk, hrk, h⟩ := h
  rw [frame_pointer_kind_eq] at hrk
  simp only [ok.injEq] at hrk
  subst hrk
  obtain_bind ⟨regs1, hregs1, h⟩ := h
  simp only [ok.injEq] at h
  subst h
  obtain ⟨hlt, hregs1⟩ := array_update_eq_ok hregs1
  have h10v : region.R10.val = 10 := by simp [region.R10]
  rw [h10v] at hlt hregs1
  unfold region.signature_from_state_loop at hregs
  have hloop := loop_ok_induction _
    (fun st => st.2.val ≤ 11 ∧
      (∀ (k : Nat) x, k < st.2.val → k ≠ 10 → S.regs.val[k]? = some x →
        ∃ f, region.foreign_for_call x = ok f ∧ st.1.val[k]? = some f) ∧
      (∀ (k : Nat), st.2.val ≤ k ∨ k = 10 → st.1.val[k]? = S.regs.val[k]?))
    (fun y => ∀ (k : Nat) x, k ≠ 10 → S.regs.val[k]? = some x →
      ∃ f, region.foreign_for_call x = ok f ∧ y.val[k]? = some f)
    (by
      rintro ⟨rs, r⟩ ⟨hr, hlt, hge⟩ res hb
      dsimp only at hr hlt hge
      change region.signature_from_state_loop.body rs r = ok res at hb
      unfold region.signature_from_state_loop.body at hb
      split at hb
      · rename_i hlt11
        have hlt11' : r.val < 11 := by
          rw [UScalar.lt_equiv] at hlt11; simpa [region.NUM_REGS] using hlt11
        obtain_bind ⟨rs1, hrs1, hb⟩ := hb
        obtain_bind ⟨r1, hr1, hb⟩ := hb
        have hr1v := usize_add_eq_ok hr1
        simp at hr1v
        simp only [ok.injEq] at hb
        subst hb
        refine ⟨by dsimp only; omega, fun k x hk hk10 hx => ?_, fun k hk => ?_⟩
        · dsimp only at hk ⊢
          split at hrs1
          · rename_i hne
            have hne' := usize_ne_ten hne
            obtain_bind ⟨rk, hrk, hrs1⟩ := hrs1
            obtain_bind ⟨rk1, hrk1, hrs1⟩ := hrs1
            obtain ⟨hlo, rfl⟩ := array_index_usize_eq_ok hrk
            obtain ⟨_, hrs1⟩ := array_update_eq_ok hrs1
            rw [hrs1]
            by_cases hkr : k = r.val
            · subst hkr
              have := hge r.val (Or.inl (le_refl _))
              rw [List.getElem?_eq_getElem hlo] at this
              rw [← this] at hx
              simp only [Option.some.injEq] at hx
              subst hx
              exact ⟨rk1, hrk1, List.getElem?_set_self hlo⟩
            · rw [List.getElem?_set_ne (Ne.symm hkr)]
              exact hlt k x (by omega) hk10 hx
          · rename_i heq
            have heq' := usize_eq_ten heq
            simp only [ok.injEq] at hrs1
            subst hrs1
            exact hlt k x (by omega) hk10 hx
        · dsimp only at hk ⊢
          split at hrs1
          · rename_i hne
            obtain_bind ⟨rk, hrk, hrs1⟩ := hrs1
            obtain_bind ⟨rk1, hrk1, hrs1⟩ := hrs1
            obtain ⟨_, hrs1⟩ := array_update_eq_ok hrs1
            rw [hrs1, List.getElem?_set_ne (by
              intro h
              rcases hk with hk | hk
              · omega
              · exact usize_ne_ten hne (h.trans hk))]
            exact hge k (by omega)
          · simp only [ok.injEq] at hrs1
            subst hrs1
            exact hge k (by omega)
      · rename_i hge11
        simp only [ok.injEq] at hb
        subst hb
        have h11 : 11 ≤ r.val := by
          have := usize_not_lt hge11; simpa [region.NUM_REGS] using this
        intro k x hk10 hx
        have hk : k < 11 := by
          have := List.getElem?_eq_some_iff.mp hx
          simpa using this.1
        exact hlt k x (by omega) hk10 hx)
    _ _ ⟨by simp, fun k _ hk _ _ => by simp at hk, fun k _ => rfl⟩ hregs
  refine ⟨?_, fun k x hk10 hx => ?_⟩
  · rw [hregs1, List.getElem?_set_self hlt]
  · obtain ⟨f, hf, hk⟩ := hloop k x hk10 hx
    refine ⟨f, hf, ?_⟩
    rw [hregs1, List.getElem?_set_ne (Ne.symm hk10), hk]

/-- `mask_signature` drops every register outside the mask except `R10`. -/
theorem mask_signature_spec {sig sig' : region.PointerSignature} {m : U16}
    (h : region.mask_signature sig m = ok sig') :
    ∀ (k : Nat), k < 11 → sig'.regs.val[k]? =
      (if k ≠ 10 ∧ ¬ m.val.testBit k then some region.RegKind.Unknown else sig.regs.val[k]?) := by
  unfold region.mask_signature at h
  obtain_bind ⟨regs, hregs, h⟩ := h
  simp only [ok.injEq] at h
  subst h
  unfold region.mask_signature_loop at hregs
  exact loop_ok_induction _
    (fun st => st.2.val ≤ 11 ∧
      (∀ (k : Nat), k < st.2.val → st.1.val[k]? =
        (if k ≠ 10 ∧ ¬ m.val.testBit k then some region.RegKind.Unknown else sig.regs.val[k]?)) ∧
      (∀ (k : Nat), st.2.val ≤ k → st.1.val[k]? = sig.regs.val[k]?))
    (fun y => ∀ (k : Nat), k < 11 → y.val[k]? =
      (if k ≠ 10 ∧ ¬ m.val.testBit k then some region.RegKind.Unknown else sig.regs.val[k]?))
    (by
      rintro ⟨rs, r⟩ ⟨hr, hlt, hge⟩ res hb
      dsimp only at hr hlt hge
      change region.mask_signature_loop.body m rs r = ok res at hb
      unfold region.mask_signature_loop.body at hb
      split at hb
      · rename_i hlt11
        have hlt11' : r.val < 11 := by
          rw [UScalar.lt_equiv] at hlt11; simpa [region.NUM_REGS] using hlt11
        obtain_bind ⟨rs1, hrs1, hb⟩ := hb
        obtain_bind ⟨r1, hr1, hb⟩ := hb
        have hr1v := usize_add_eq_ok hr1
        simp at hr1v
        simp only [ok.injEq] at hb
        subst hb
        -- What the body did to `rs`: wrote `Unknown` at `r` iff `r` is masked out.
        have hbody : ∀ (k : Nat), rs1.val[k]? =
            (if k = r.val ∧ r.val ≠ 10 ∧ ¬ m.val.testBit r.val then some region.RegKind.Unknown
             else rs.val[k]?) := by
          intro k
          split at hrs1
          · rename_i hne
            have hne' := usize_ne_ten hne
            obtain_bind ⟨i, hi, hrs1⟩ := hrs1
            obtain_bind ⟨i1, hi1, hrs1⟩ := hrs1
            rw [lift_eq_ok hi1] at hrs1
            clear hi1
            obtain ⟨z, hz, hzv, _⟩ := WP.spec_imp_exists (UScalar.ShiftLeft_spec 1#u16 r
              (UScalar.size .U16) (by change r.val < 16; omega) rfl)
            rw [hz] at hi
            simp only [ok.injEq] at hi
            subst hi
            have hsz : UScalar.size .U16 = 65536 := by
              norm_num [UScalar.size, U16.size, U16.numBits, UScalarTy.numBits]
            have h1 : (1#u16).val = 1 := by simp
            have hzv' : z.val = 2 ^ r.val := by
              rw [hzv, hsz, h1, Nat.shiftLeft_eq, Nat.one_mul, Nat.mod_eq_of_lt (by
                have : 2 ^ r.val < 2 ^ 16 := Nat.pow_lt_pow_right (by norm_num) (by omega)
                omega)]
            have hand : (m &&& z) = 0#u16 ↔ ¬ m.val.testBit r.val := by
              have h0 : (0#u16).val = 0 := by simp
              rw [UScalar.eq_equiv, UScalar.val_and, hzv', h0, and_two_pow_eq_zero]
            split at hrs1
            · rename_i hzero
              have hbit := hand.mp hzero
              unfold region.set_kind at hrs1
              obtain ⟨hlo, hrs1⟩ := array_update_eq_ok hrs1
              rw [hrs1]
              by_cases hkr : k = r.val
              · subst hkr
                rw [List.getElem?_set_self hlo, if_pos ⟨rfl, hne', hbit⟩]
              · rw [List.getElem?_set_ne (Ne.symm hkr), if_neg (fun h => hkr h.1)]
            · rename_i hnz
              have hbit := fun hb => hnz (hand.mpr hb)
              simp only [ok.injEq] at hrs1
              subst hrs1
              rw [if_neg (fun h => hbit h.2.2)]
          · rename_i heq
            have heq' := usize_eq_ten heq
            simp only [ok.injEq] at hrs1
            subst hrs1
            rw [if_neg (fun h => h.2.1 heq')]
        refine ⟨by dsimp only; omega, fun k hk => ?_, fun k hk => ?_⟩
        · dsimp only at hk ⊢
          rw [hbody k]
          by_cases hkr : k = r.val
          · rw [hkr, hge r.val (le_refl _)]
            by_cases hc : r.val ≠ 10 ∧ ¬ m.val.testBit r.val
            · rw [if_pos ⟨rfl, hc⟩, if_pos hc]
            · rw [if_neg (fun h => hc h.2), if_neg hc]
          · rw [if_neg (fun h => hkr h.1)]
            exact hlt k (by omega)
        · dsimp only at hk ⊢
          rw [hbody k, if_neg (by omega)]
          exact hge k (by omega)
      · rename_i hge11
        simp only [ok.injEq] at hb
        subst hb
        have h11 : 11 ≤ r.val := by
          have := usize_not_lt hge11; simpa [region.NUM_REGS] using this
        intro k hk
        exact hlt k (by omega))
    _ _ ⟨by simp, fun k hk => by simp at hk, fun k _ => rfl⟩ hregs

/-- Two states that agree on the registers a mask names hand a callee the
same masked signature. -/
theorem call_signature_agree {S₁ S₂ : region.State} {m : U16}
    (hA : ∀ (r : Nat), m.val.testBit r → S₁.regs.val[r]? = S₂.regs.val[r]?)
    {sig₁ sig₂ sig₁' sig₂' : region.PointerSignature}
    (h₁ : region.signature_from_state S₁ = ok sig₁) (h₂ : region.signature_from_state S₂ = ok sig₂)
    (hm₁ : region.mask_signature sig₁ m = ok sig₁') (hm₂ : region.mask_signature sig₂ m = ok sig₂') :
    sig₁' = sig₂' := by
  obtain ⟨h10₁, hf₁⟩ := signature_from_state_spec h₁
  obtain ⟨h10₂, hf₂⟩ := signature_from_state_spec h₂
  have hs₁ := mask_signature_spec hm₁
  have hs₂ := mask_signature_spec hm₂
  have hext : ∀ (k : Nat), sig₁'.regs.val[k]? = sig₂'.regs.val[k]? := by
    intro k
    by_cases hk : k < 11
    · rw [hs₁ k hk, hs₂ k hk]
      by_cases hc : k ≠ 10 ∧ ¬ m.val.testBit k
      · rw [if_pos hc, if_pos hc]
      · rw [if_neg hc, if_neg hc]
        by_cases h10 : k = 10
        · subst h10; rw [h10₁, h10₂]
        · have hbit : m.val.testBit k := by
            by_contra hn; exact hc ⟨h10, hn⟩
          have hagree := hA k hbit
          have l₁ : S₁.regs.val.length = 11 := by simp
          obtain ⟨f₁, hf, hk₁⟩ := hf₁ k _ h10 (List.getElem?_eq_getElem (by omega))
          obtain ⟨f₂, hf', hk₂⟩ := hf₂ k _ h10 (hagree.symm.trans (List.getElem?_eq_getElem (by omega)))
          rw [hf'] at hf
          simp only [ok.injEq] at hf
          subst hf
          rw [hk₁, hk₂]
    · have l₁ : sig₁'.regs.val.length = 11 := by simp
      have l₂ : sig₂'.regs.val.length = 11 := by simp
      rw [List.getElem?_eq_none (by omega), List.getElem?_eq_none (by omega)]
  cases sig₁' with
  | mk r₁ =>
    cases sig₂' with
    | mk r₂ =>
      congr 1
      apply (Aeneas.Std.Array.eq_iff _ _).mpr
      exact List.ext_getElem? hext

/-- The `uses` of a local call are the callee's live-in mask. -/
theorem local_call_uses {inst : isa.Insn} {callee uses defs : U16}
    (hop : inst.opcode = isa.OP_CALL) (hsrc : inst.src.val = 1 ∨ inst.src.val = 2)
    (hud : region.uses_and_defs inst callee = ok (uses, defs)) : uses = callee := by
  unfold region.uses_and_defs at hud
  obtain_bind ⟨cls, hcls, hud⟩ := hud
  have hclsv : cls = inst.opcode &&& isa.CLS_MASK := lift_eq_ok hcls
  clear hcls
  obtain_bind ⟨dstU, hdstU, hud⟩ := hud
  obtain_bind ⟨srcU, hsrcU, hud⟩ := hud
  rw [lift_eq_ok hdstU, lift_eq_ok hsrcU] at hud
  clear hdstU hsrcU
  have hc5 : cls = isa.CLS_JMP := by
    rw [hclsv, hop, UScalar.eq_equiv, UScalar.val_and]
    simp [isa.OP_CALL, isa.CLS_MASK, isa.CLS_JMP]
  have hne : ∀ c : U8, c.val ≠ 5 → cls ≠ c := by
    intro c hc h
    rw [hc5] at h
    apply hc
    rw [← h]
    simp [isa.CLS_JMP]
  rw [if_neg (hne _ (by simp [isa.CLS_LD])), if_neg (hne _ (by simp [isa.CLS_LDX])),
    if_neg (hne _ (by simp [isa.CLS_ST])), if_neg (hne _ (by simp [isa.CLS_STX])),
    if_neg (hne _ (by simp [isa.CLS_ALU])), if_neg (hne _ (by simp [isa.CLS_ALU64])),
    if_pos hc5] at hud
  have hnexit : ¬ inst.opcode = isa.OP_EXIT := by
    rw [hop, UScalar.eq_equiv]
    simp [isa.OP_CALL, isa.OP_EXIT]
  rw [if_neg hnexit, if_pos hop] at hud
  have hn0 : ¬ inst.src = 0#u8 := by
    intro h; rw [UScalar.eq_equiv] at h; simp at h; omega
  rw [if_neg hn0] at hud
  rcases hsrc with h | h
  · have h1 : inst.src = 1#u8 := by rw [UScalar.eq_equiv, h]; simp
    rw [if_pos h1] at hud
    simp only [ok.injEq, Prod.mk.injEq] at hud
    exact hud.1.symm
  · have h1 : ¬ inst.src = 1#u8 := by
      intro h1; rw [UScalar.eq_equiv] at h1; simp at h1; omega
    have h2 : inst.src = 2#u8 := by rw [UScalar.eq_equiv, h]; simp
    rw [if_neg h1, if_pos h2] at hud
    simp only [ok.injEq, Prod.mk.injEq] at hud
    exact hud.1.symm

/-! ## The entry -/

/-- The masked and the unmasked signature give entry states that agree at
the entry slot, whenever the mask covers the entry's live-in. -/
theorem masked_entry_agree {σ σ' : region.PointerSignature} {m live : U16}
    (hcover : ∀ (r : Nat), live.val.testBit r → m.val.testBit r)
    (hmask : region.mask_signature σ m = ok σ') {st E₁ E₂ : region.State}
    (h₁ : region.apply_signature σ st = ok E₁) (h₂ : region.apply_signature σ' st = ok E₂) :
    AgreeAt live E₁ E₂ := by
  unfold region.apply_signature at h₁ h₂
  obtain_bind ⟨rk, hrk, h₁⟩ := h₁
  obtain_bind ⟨rk', hrk', h₂⟩ := h₂
  rw [frame_pointer_kind_eq] at hrk hrk'
  simp only [ok.injEq] at hrk hrk'
  subst hrk hrk'
  obtain_bind ⟨a₁, ha₁, h₁⟩ := h₁
  obtain_bind ⟨a₂, ha₂, h₂⟩ := h₂
  simp only [ok.injEq] at h₁ h₂
  subst h₁ h₂
  obtain ⟨hl₁, ha₁⟩ := array_update_eq_ok ha₁
  obtain ⟨hl₂, ha₂⟩ := array_update_eq_ok ha₂
  have h10v : region.R10.val = 10 := by simp [region.R10]
  rw [h10v] at hl₁ hl₂ ha₁ ha₂
  have hs := mask_signature_spec hmask
  refine ⟨fun r hr => ?_, ?_, rfl⟩
  · show a₁.val[r]? = a₂.val[r]?
    rw [ha₁, ha₂]
    by_cases h10 : r = 10
    · subst h10
      rw [List.getElem?_set_self hl₁, List.getElem?_set_self hl₂]
    · rw [List.getElem?_set_ne (Ne.symm h10), List.getElem?_set_ne (Ne.symm h10)]
      by_cases hk : r < 11
      · rw [hs r hk, if_neg (fun h => h.2 (hcover r hr))]
      · have l₁ : σ.regs.val.length = 11 := by simp
        have l₂ : σ'.regs.val.length = 11 := by simp
        rw [List.getElem?_eq_none (by omega), List.getElem?_eq_none (by omega)]
  · show a₁.val[10]? = a₂.val[10]?
    rw [ha₁, ha₂, List.getElem?_set_self hl₁, List.getElem?_set_self hl₂]

/-! ## The statement -/

/-- Live-in masking is invisible to the analysis, schedule by schedule: run
the worklist over any common schedule from the masked and the unmasked
entry state, and at every reachable slot every access classifies alike and
every local call receives the same masked signature. -/
theorem masking_neutral {insn : Nat → isa.Insn} {callee : Nat → U16} {succs : Nat → List Nat}
    {R : Nat → Prop} {L : Nat → U16} (hL : LiveSolution insn callee succs R L)
    (hregs : RegsOk insn R) {lddw : Nat → U64} {lo hi : U64} {sched : List Nat}
    (hsched : ∀ p, p ∈ sched → R p) {T₁ T₂ T₁' T₂' : Nat → region.State}
    (hT : TablesAgree L T₁ T₂) (h₁ : Run insn succs lddw lo hi sched T₁ T₁')
    (h₂ : Run insn succs lddw lo hi sched T₂ T₂') {p : Nat} (hp : R p) :
    (∀ F, region.classify (T₁' p) (insn p) F = region.classify (T₂' p) (insn p) F) ∧
    ((insn p).opcode = isa.OP_CALL → (insn p).src.val = 1 ∨ (insn p).src.val = 2 →
      ∀ {sig₁ sig₂ sig₁' sig₂' : region.PointerSignature},
        region.signature_from_state (T₁' p) = ok sig₁ →
        region.signature_from_state (T₂' p) = ok sig₂ →
        region.mask_signature sig₁ (callee p) = ok sig₁' →
        region.mask_signature sig₂ (callee p) = ok sig₂' → sig₁' = sig₂') := by
  have hA := run_agree hL hregs hsched hT h₁ h₂ p
  refine ⟨fun F => hint_agree hL hregs hp hA F, fun hop hsrc sig₁ sig₂ sig₁' sig₂' hs₁ hs₂ hm₁ hm₂ => ?_⟩
  obtain ⟨uses, defs, hud, huses, _⟩ := hL.live p hp
  have hu := local_call_uses hop hsrc hud
  subst hu
  exact call_signature_agree (fun r hr => hA.live r (huses r hr)) hs₁ hs₂ hm₁ hm₂

end async_ebpf_verified

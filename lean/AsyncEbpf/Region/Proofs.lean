import AsyncEbpf.Stack.Proofs

/-!
# The region analysis' dataflow core

`src/verified/region.rs` is the abstract domain, meet and transfer function
behind the JIT's region hints. The hints `STACK` and `DATA` narrow a bounds
check the JIT keeps, so a wrong one costs a spurious fault, not memory
safety; the analysis is deliberately optimistic in four places (loaded
values and helper results are scalars, spills survive calls, a slot the cap
refuses reads back as a scalar), and no natural provenance semantics makes
those sound. What is proved here is therefore not "the kinds
over-approximate the values" but the three things the runtime relies on:

* `classify_frame`: the one hint that removes a check, `FRAME`, is given
  only to an access whose base register is `R10` itself and whose window
  `in_frame_window` admits; `Semantics/Frames.lean` shows such an access
  lands in a mapped island in every execution;
* `transfer_R10`, `meet_from_R10`: the frame pointer's kind survives every
  transfer and meet of an accepted instruction, so `frame_access`'s "R10
  still holds the frame pointer" test never fails on an accepted program;
* `transfer_agree`: `transfer` reads only the registers `uses_and_defs`
  names as uses (plus `R10` and the spill slots) and, outside the ones it
  names as defs, either leaves a register alone or sets it to a constant.
  This is the per-instruction fact the live-in masking of call signatures
  rests on: two states that agree on the live-in registers and the slots
  produce states that agree on the live-out registers and the slots.
  `Region/Masking.lean` carries it through the meet, the classification
  and the call signatures to any common worklist schedule.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

/-! ## Plumbing -/

theorem array_index_usize_eq_ok {α : Type} {n : Usize} {a : Std.Array α n} {i : Usize} {x : α}
    (h : Array.index_usize a i = ok x) : ∃ hi : i.val < a.val.length, x = a.val[i.val] := by
  unfold Array.index_usize at h
  rw [show a[i]? = a.val[i.val]? from rfl] at h
  split at h
  · simp at h
  · rename_i hget
    simp only [ok.injEq] at h
    subst h
    rw [List.getElem?_eq_some_iff] at hget
    obtain ⟨hi, hx⟩ := hget
    exact ⟨hi, hx.symm⟩

theorem array_update_eq_ok {α : Type} {n : Usize} {a a' : Std.Array α n} {i : Usize} {x : α}
    (h : Array.update a i x = ok a') : i.val < a.val.length ∧ a'.val = a.val.set i.val x := by
  unfold Array.update at h
  rw [show a[i]? = a.val[i.val]? from rfl] at h
  split at h
  · simp at h
  · rename_i hget
    simp only [ok.injEq] at h
    subst h
    rw [List.getElem?_eq_some_iff] at hget
    exact ⟨hget.1, Array.from_val _ _⟩

theorem array_index_mut_usize_eq_ok {α : Type} {n : Usize} {a : Std.Array α n} {i : Usize} {x : α}
    {back : α → Std.Array α n} (h : Array.index_mut_usize a i = ok (x, back)) :
    ∃ hi : i.val < a.val.length, x = a.val[i.val] ∧ back = Std.Array.set a i := by
  unfold Array.index_mut_usize at h
  obtain_bind ⟨y, hy, h⟩ := h
  simp only [ok.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  obtain ⟨hi, rfl⟩ := array_index_usize_eq_ok hy
  exact ⟨hi, rfl, rfl⟩

theorem lift_eq_ok {α : Type} {x y : α} (h : lift x = ok y) : y = x := by
  simp only [lift, ok.injEq] at h
  exact h.symm

theorem u8_cast_usize_val (x : U8) : (UScalar.cast .Usize x).val = x.val := by simp

/-- The class bits of an opcode, as a number. -/
theorem cls_val (opcode : U8) : (opcode &&& isa.CLS_MASK).val = opcode.val &&& 7 := by
  simp [isa.CLS_MASK]

/-! ## The frame hint -/

/-- The access's base register is `R10` itself: `src` for a load, `dst` for a
store or atomic. -/
def FrameBase (inst : isa.Insn) : Prop :=
  (inst.opcode.val &&& 7 = 1 ∧ inst.src.val = 10) ∨
  ((inst.opcode.val &&& 7 = 2 ∨ inst.opcode.val &&& 7 = 3) ∧ inst.dst.val = 10)

theorem frame_access_true {S : region.State} {inst : isa.Insn} {base : Usize} {F : U16}
    (h : region.frame_access S inst base F = ok true) :
    base.val = 10 ∧ region.is_atomic inst.opcode = ok false ∧
    ∃ w, region.access_width inst.opcode = ok w ∧ stack.in_frame_window F inst.offset w = ok true := by
  unfold region.frame_access at h
  split at h
  · simp at h
  · rename_i hb
    have hb' : base.val = 10 := by
      simp only [bne_iff_ne, ne_eq, not_not] at hb
      subst hb
      simp [region.R10]
    obtain_bind ⟨rk, _, h⟩ := h
    obtain_bind ⟨rk1, _, h⟩ := h
    obtain_bind ⟨b, _, h⟩ := h
    split at h
    · obtain_bind ⟨b1, hat, h⟩ := h
      split at h
      · simp at h
      · rename_i hnat
        obtain_bind ⟨w, hw, h⟩ := h
        refine ⟨hb', ?_, w, hw, h⟩
        cases b1
        · exact hat
        · exact absurd rfl hnat
    · simp at h

/-- The `FRAME` hint goes only to an access off `R10` itself that
`in_frame_window` admits, and never to an atomic. -/
theorem classify_frame {S : region.State} {inst : isa.Insn} {F : U16} {r : U8}
    (h : region.classify S inst F = ok (true, region.REGION_FRAME, r)) :
    FrameBase inst ∧ region.is_atomic inst.opcode = ok false ∧
    ∃ w, region.access_width inst.opcode = ok w ∧ stack.in_frame_window F inst.offset w = ok true := by
  unfold region.classify at h
  obtain_bind ⟨cls, hcls, h⟩ := h
  have hcls' := lift_eq_ok hcls
  subst hcls'
  have hne : ∀ x : U8, x ≠ region.REGION_FRAME → (true, x, r) ≠ (true, region.REGION_FRAME, r) := by
    intro x hx heq
    simp only [Prod.mk.injEq] at heq
    exact hx heq.2.1
  -- The same shape three times over: a base, a plain region, the frame test.
  have arm : ∀ (base : Usize) (hbase : base.val = inst.src.val ∨ base.val = inst.dst.val),
      (do
        let rk ← Array.index_usize S.regs base
        let plain ← region.region_of rk
        let b ← region.frame_access S inst base F
        if b then ok (true, region.REGION_FRAME, plain) else ok (true, plain, plain)) =
        ok (true, region.REGION_FRAME, r) →
      base.val = 10 ∧ region.is_atomic inst.opcode = ok false ∧
        ∃ w, region.access_width inst.opcode = ok w ∧
          stack.in_frame_window F inst.offset w = ok true := by
    intro base _ h
    obtain_bind ⟨rk, _, h⟩ := h
    obtain_bind ⟨plain, hplain, h⟩ := h
    obtain_bind ⟨b, hfa, h⟩ := h
    split at h
    · subst b
      exact frame_access_true hfa
    · -- A plain hint is never `REGION_FRAME`: `region_of` yields 0, 1 or 2.
      exfalso
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨_, hp, _⟩ := h
      unfold region.region_of at hplain
      split at hplain <;> simp only [ok.injEq] at hplain <;> subst hplain <;>
        simp [region.REGION_STACK, region.REGION_DATA, region.REGION_UNKNOWN,
          region.REGION_FRAME] at hp
  split at h
  · rename_i h1
    obtain_bind ⟨base, hbase, h⟩ := h
    have hb := lift_eq_ok hbase
    subst hb
    have := arm _ (Or.inl (u8_cast_usize_val _)) h
    rw [u8_cast_usize_val] at this
    refine ⟨Or.inl ⟨?_, this.1⟩, this.2⟩
    have := congrArg UScalar.val h1
    rw [cls_val] at this
    simpa [isa.CLS_LDX] using this
  · rename_i hn1
    split at h
    · rename_i h2
      obtain_bind ⟨base, hbase, h⟩ := h
      have hb := lift_eq_ok hbase
      subst hb
      have := arm _ (Or.inr (u8_cast_usize_val _)) h
      rw [u8_cast_usize_val] at this
      refine ⟨Or.inr ⟨Or.inl ?_, this.1⟩, this.2⟩
      have := congrArg UScalar.val h2
      rw [cls_val] at this
      simpa [isa.CLS_ST] using this
    · rename_i hn2
      split at h
      · rename_i h3
        obtain_bind ⟨base, hbase, h⟩ := h
        have hb := lift_eq_ok hbase
        subst hb
        have := arm _ (Or.inr (u8_cast_usize_val _)) h
        rw [u8_cast_usize_val] at this
        refine ⟨Or.inr ⟨Or.inr ?_, this.1⟩, this.2⟩
        have := congrArg UScalar.val h3
        rw [cls_val] at this
        simpa [isa.CLS_STX] using this
      · simp at h

end async_ebpf_verified

namespace async_ebpf_verified

/-! ## Registers, as lists -/

/-- The kind of the frame pointer. -/
def fpKind : region.RegKind := .Stack (.Current (some 0#i32))

theorem frame_pointer_kind_eq : region.frame_pointer_kind = ok fpKind := rfl

theorem regs_length (S : region.State) : S.regs.val.length = 11 := by
  simp

/-- After writing `k` at `d` in two register files, every register either
agrees or is untouched on both sides. -/
theorem set_agree {l₁ l₂ : List region.RegKind} {d : Nat} {k : region.RegKind}
    (hd₁ : d < l₁.length) (hd₂ : d < l₂.length) (r : Nat) :
    (l₁.set d k)[r]? = (l₂.set d k)[r]? ∨
    ((l₁.set d k)[r]? = l₁[r]? ∧ (l₂.set d k)[r]? = l₂[r]?) := by
  by_cases hr : r = d
  · subst hr
    left
    rw [List.getElem?_set_self hd₁, List.getElem?_set_self hd₂]
  · right
    rw [List.getElem?_set_ne (Ne.symm hr), List.getElem?_set_ne (Ne.symm hr)]
    exact ⟨rfl, rfl⟩

theorem set_agree_self {l₁ l₂ : List region.RegKind} {d : Nat} {k : region.RegKind}
    (hd₁ : d < l₁.length) (hd₂ : d < l₂.length) :
    (l₁.set d k)[d]? = (l₂.set d k)[d]? := by
  rw [List.getElem?_set_self hd₁, List.getElem?_set_self hd₂]

/-- Two runs of one step: the registers `defs` names agree; every other
register agrees or is left alone on both sides; the spills agree. -/
structure StepAgree (defs : U16) (S₁ S₂ T₁ T₂ : region.State) : Prop where
  defs : ∀ (r : Nat), defs.val.testBit r → T₁.regs.val[r]? = T₂.regs.val[r]?
  rest : ∀ (r : Nat), T₁.regs.val[r]? = T₂.regs.val[r]? ∨
    (T₁.regs.val[r]? = S₁.regs.val[r]? ∧ T₂.regs.val[r]? = S₂.regs.val[r]?)
  spills : T₁.spills = T₂.spills

/-! ## Masks -/

theorem reg_bit_testBit {d : Usize} {b : U16} (h : region.reg_bit d = ok b) (r : Nat) :
    b.val.testBit r ↔ (d.val < 10 ∧ r = d.val) := by
  unfold region.reg_bit at h
  split at h
  · rename_i hlt
    have hlt' : d.val < 10 := by
      rw [UScalar.lt_equiv] at hlt
      simpa [region.R10] using hlt
    obtain ⟨z, hz, hzv, _⟩ := WP.spec_imp_exists (UScalar.ShiftLeft_spec 1#u16 d (UScalar.size .U16)
      (by simp; omega) rfl)
    rw [hz] at h
    simp only [ok.injEq] at h
    subst h
    have hsz : UScalar.size .U16 = 65536 := by
      norm_num [UScalar.size, U16.size, U16.numBits, UScalarTy.numBits]
    have h1 : (1#u16).val = 1 := by simp
    rw [hzv, hsz, h1, Nat.shiftLeft_eq, Nat.one_mul, Nat.mod_eq_of_lt (by
      have : 2 ^ d.val < 2 ^ 16 := Nat.pow_lt_pow_right (by norm_num) (by omega)
      omega)]
    rw [Nat.testBit_two_pow]
    constructor
    · intro h; exact ⟨hlt', (decide_eq_true_iff.mp h).symm⟩
    · rintro ⟨_, rfl⟩; exact decide_eq_true rfl
  · rename_i hge
    simp only [ok.injEq] at h
    subst h
    have h0 : (0#u16).val = 0 := by simp
    rw [h0]
    simp only [Nat.zero_testBit, Bool.false_eq_true, false_iff, not_and]
    intro hlt
    exfalso
    apply hge
    rw [UScalar.lt_equiv]
    simpa [region.R10] using hlt

theorem or_testBit (a b : U16) (r : Nat) :
    (a ||| b).val.testBit r = (a.val.testBit r || b.val.testBit r) := by
  simp [Nat.testBit_or]

/-! ## The classes of `transfer` -/

theorem index_agree {S₁ S₂ : region.State} {i : Usize} {x₁ x₂ : region.RegKind}
    (h : S₁.regs.val[i.val]? = S₂.regs.val[i.val]?)
    (h₁ : Array.index_usize S₁.regs i = ok x₁) (h₂ : Array.index_usize S₂.regs i = ok x₂) :
    x₁ = x₂ := by
  obtain ⟨hi₁, rfl⟩ := array_index_usize_eq_ok h₁
  obtain ⟨hi₂, rfl⟩ := array_index_usize_eq_ok h₂
  rw [List.getElem?_eq_getElem hi₁, List.getElem?_eq_getElem hi₂] at h
  simpa using h

/-- `transfer_alu64` writes `dst` with a kind determined by `dst` and `src`. -/
theorem transfer_alu64_agree {inst : isa.Insn} {S₁ S₂ T₁ T₂ : region.State}
    (hdst : inst.opcode.val &&& 0xf0 ≠ 0xb0 → S₁.regs.val[inst.dst.val]? = S₂.regs.val[inst.dst.val]?)
    (hsrc' : inst.opcode.val &&& 8 ≠ 0 → S₁.regs.val[inst.src.val]? = S₂.regs.val[inst.src.val]?)
    (h₁ : region.transfer_alu64 S₁ inst = ok T₁) (h₂ : region.transfer_alu64 S₂ inst = ok T₂) :
    ∃ k, T₁.regs.val = S₁.regs.val.set inst.dst.val k ∧ T₂.regs.val = S₂.regs.val.set inst.dst.val k ∧
      T₁.spills = S₁.spills ∧ T₂.spills = S₂.spills := by
  unfold region.transfer_alu64 at h₁ h₂
  obtain_bind ⟨op, hop, h₁⟩ := h₁
  obtain_bind ⟨op', hop', h₂⟩ := h₂
  rw [lift_eq_ok hop'] at h₂
  rw [lift_eq_ok hop] at h₁
  clear hop hop'
  obtain_bind ⟨sb, hsb, h₁⟩ := h₁
  obtain_bind ⟨sb', hsb', h₂⟩ := h₂
  rw [lift_eq_ok hsb'] at h₂
  rw [lift_eq_ok hsb] at h₁
  clear hsb hsb'
  obtain_bind ⟨dst, hd, h₁⟩ := h₁
  obtain_bind ⟨dst', hd', h₂⟩ := h₂
  rw [lift_eq_ok hd'] at h₂
  rw [lift_eq_ok hd] at h₁
  clear hd hd'
  obtain_bind ⟨src, hs, h₁⟩ := h₁
  obtain_bind ⟨src', hs', h₂⟩ := h₂
  rw [lift_eq_ok hs'] at h₂
  rw [lift_eq_ok hs] at h₁
  clear hs hs'
  have hdv : (UScalar.cast .Usize inst.dst).val = inst.dst.val := u8_cast_usize_val _
  have hsv : (UScalar.cast .Usize inst.src).val = inst.src.val := u8_cast_usize_val _
  have hsrcbit : inst.opcode &&& isa.SRC_REG != 0#u8 ↔ inst.opcode.val &&& 8 ≠ 0 := by
    simp only [bne_iff_ne, ne_eq]
    rw [not_iff_not, UScalar.eq_equiv]
    simp [isa.SRC_REG]
  have hmov : inst.opcode &&& isa.ALU_MASK = region.ALU_OP_MOV ↔ inst.opcode.val &&& 0xf0 = 0xb0 := by
    rw [UScalar.eq_equiv]
    simp [isa.ALU_MASK, region.ALU_OP_MOV]
  split at h₁
  · -- mov
    rename_i hm
    rw [if_pos hm] at h₂
    have hm' := hmov.mp hm
    obtain_bind ⟨⟨s1, k⟩, hk, h₁⟩ := h₁
    obtain_bind ⟨⟨s1', k'⟩, hk', h₂⟩ := h₂
    try simp only at h₁ h₂
    have hkk : k = k' ∧ s1 = S₁ ∧ s1' = S₂ := by
      split at hk
      · rename_i hreg
        rw [if_pos hreg] at hk'
        obtain_bind ⟨rk, hrk, hk⟩ := hk
        obtain_bind ⟨rk', hrk', hk'⟩ := hk'
        have := index_agree (by rw [hsv]; exact hsrc' (hsrcbit.mp hreg)) hrk hrk'
        subst this
        obtain_bind ⟨rk1, hrk1, hk⟩ := hk
        obtain_bind ⟨rk1', hrk1', hk'⟩ := hk'
        rw [hrk1] at hrk1'
        simp only [ok.injEq] at hrk1'
        subst hrk1'
        simp only [ok.injEq, Prod.mk.injEq] at hk hk'
        exact ⟨hk.2.symm.trans hk'.2, hk.1.symm, hk'.1.symm⟩
      · rename_i hreg
        rw [if_neg hreg] at hk'
        simp only [ok.injEq, Prod.mk.injEq] at hk hk'
        exact ⟨hk.2.symm.trans hk'.2, hk.1.symm, hk'.1.symm⟩
    obtain ⟨rfl, rfl, rfl⟩ := hkk
    obtain_bind ⟨a, ha, h₁⟩ := h₁
    obtain_bind ⟨a', ha', h₂⟩ := h₂
    simp only [ok.injEq] at h₁ h₂
    subst h₁ h₂
    obtain ⟨_, ha⟩ := array_update_eq_ok ha
    obtain ⟨_, ha'⟩ := array_update_eq_ok ha'
    rw [hdv] at ha ha'
    exact ⟨k, ha, ha', rfl, rfl⟩
  · rename_i hnm
    rw [if_neg hnm] at h₂
    have hnm' := fun h => hnm (hmov.mpr h)
    -- add, sub and the rest all read `dst`, and `src` when the source is a register.
    have read : ∀ {rk₁ rk₂ : Result region.RegKind}
        (f : region.RegKind → region.RegKind → Result region.RegKind)
        (g : region.RegKind → Result region.RegKind),
        (rk₁ = (if inst.opcode &&& isa.SRC_REG != 0#u8 then
          (do let a ← Array.index_usize S₁.regs (UScalar.cast .Usize inst.dst)
              let b ← Array.index_usize S₁.regs (UScalar.cast .Usize inst.src)
              f a b) else
          (do let a ← Array.index_usize S₁.regs (UScalar.cast .Usize inst.dst); g a))) →
        (rk₂ = (if inst.opcode &&& isa.SRC_REG != 0#u8 then
          (do let a ← Array.index_usize S₂.regs (UScalar.cast .Usize inst.dst)
              let b ← Array.index_usize S₂.regs (UScalar.cast .Usize inst.src)
              f a b) else
          (do let a ← Array.index_usize S₂.regs (UScalar.cast .Usize inst.dst); g a))) →
        ∀ k₁ k₂, rk₁ = ok k₁ → rk₂ = ok k₂ → k₁ = k₂ := by
      intro rk₁ rk₂ f g e₁ e₂ k₁ k₂ hk₁ hk₂
      subst e₁ e₂
      split at hk₁
      · rename_i hreg
        rw [if_pos hreg] at hk₂
        obtain_bind ⟨a, ha, hk₁⟩ := hk₁
        obtain_bind ⟨a', ha', hk₂⟩ := hk₂
        have := index_agree (by rw [hdv]; exact hdst hnm') ha ha'
        subst this
        obtain_bind ⟨b, hb, hk₁⟩ := hk₁
        obtain_bind ⟨b', hb', hk₂⟩ := hk₂
        have := index_agree (by rw [hsv]; exact hsrc' (hsrcbit.mp hreg)) hb hb'
        subst this
        rw [hk₁] at hk₂
        simpa using hk₂
      · rename_i hreg
        rw [if_neg hreg] at hk₂
        obtain_bind ⟨a, ha, hk₁⟩ := hk₁
        obtain_bind ⟨a', ha', hk₂⟩ := hk₂
        have := index_agree (by rw [hdv]; exact hdst hnm') ha ha'
        subst this
        rw [hk₁] at hk₂
        simpa using hk₂
    split at h₁
    · rename_i hadd
      rw [if_pos hadd] at h₂
      obtain_bind ⟨k, hk, h₁⟩ := h₁
      obtain_bind ⟨k', hk', h₂⟩ := h₂
      have := read region.add_kinds (fun a => region.add_imm_kind a inst.imm) rfl rfl k k' hk hk'
      subst this
      obtain_bind ⟨a, ha, h₁⟩ := h₁
      obtain_bind ⟨a', ha', h₂⟩ := h₂
      simp only [ok.injEq] at h₁ h₂
      subst h₁ h₂
      obtain ⟨_, ha⟩ := array_update_eq_ok ha
      obtain ⟨_, ha'⟩ := array_update_eq_ok ha'
      rw [hdv] at ha ha'
      exact ⟨k, ha, ha', rfl, rfl⟩
    · rename_i hnadd
      rw [if_neg hnadd] at h₂
      split at h₁
      · rename_i hsub
        rw [if_pos hsub] at h₂
        obtain_bind ⟨k, hk, h₁⟩ := h₁
        obtain_bind ⟨k', hk', h₂⟩ := h₂
        have := read region.sub_kinds
          (fun a => do let i ← region.wrapping_neg_i32 inst.imm; region.add_imm_kind a i) rfl rfl k k' hk hk'
        subst this
        obtain_bind ⟨a, ha, h₁⟩ := h₁
        obtain_bind ⟨a', ha', h₂⟩ := h₂
        simp only [ok.injEq] at h₁ h₂
        subst h₁ h₂
        obtain ⟨_, ha⟩ := array_update_eq_ok ha
        obtain ⟨_, ha'⟩ := array_update_eq_ok ha'
        rw [hdv] at ha ha'
        exact ⟨k, ha, ha', rfl, rfl⟩
      · rename_i hnsub
        rw [if_neg hnsub] at h₂
        obtain_bind ⟨a, ha, h₁⟩ := h₁
        obtain_bind ⟨a', ha', h₂⟩ := h₂
        simp only [ok.injEq] at h₁ h₂
        subst h₁ h₂
        obtain ⟨_, ha⟩ := array_update_eq_ok ha
        obtain ⟨_, ha'⟩ := array_update_eq_ok ha'
        rw [hdv] at ha ha'
        exact ⟨_, ha, ha', rfl, rfl⟩

/-- Two runs binding the same computation: name the value once. -/
macro "bind_same" x:ident hx:ident h₁:ident h₂:ident : tactic =>
  `(tactic| (obtain_bind ⟨$x:ident, $hx:ident, $h₁:ident⟩ := $h₁:ident
             obtain_bind ⟨x_dup, hx_dup, $h₂:ident⟩ := $h₂:ident
             rw [$hx:ident] at hx_dup
             simp only [ok.injEq] at hx_dup
             subst hx_dup))

/-- Two runs reading one register the states agree on. -/
macro "bind_reg" x:ident hx:ident h₁:ident h₂:ident hagree:term : tactic =>
  `(tactic| (obtain_bind ⟨$x:ident, $hx:ident, $h₁:ident⟩ := $h₁:ident
             obtain_bind ⟨x_dup, hx_dup, $h₂:ident⟩ := $h₂:ident
             have hx_eq := index_agree $hagree $hx:ident hx_dup
             subst hx_eq))

theorem set2_agree {l₁ l₂ : List region.RegKind} {d e : Nat} {k : region.RegKind}
    (hd₁ : d < l₁.length) (hd₂ : d < l₂.length) (he₁ : e < l₁.length) (he₂ : e < l₂.length)
    (r : Nat) :
    ((l₁.set d k).set e k)[r]? = ((l₂.set d k).set e k)[r]? ∨
    (((l₁.set d k).set e k)[r]? = l₁[r]? ∧ ((l₂.set d k).set e k)[r]? = l₂[r]?) := by
  by_cases hr : r = e
  · subst hr
    left
    rw [List.getElem?_set_self (by simpa using he₁), List.getElem?_set_self (by simpa using he₂)]
  · rw [List.getElem?_set_ne (Ne.symm hr), List.getElem?_set_ne (Ne.symm hr)]
    exact set_agree hd₁ hd₂ r

/-- `transfer_store`: the spills after depend on the spills before and on
`dst` (and `src`, for a register store); the registers are untouched, except
that an atomic writes `src` (and `R0`, for `cmpxchg`) to `Unknown`. -/
theorem transfer_store_agree {inst : isa.Insn} {cls : U8} {S₁ S₂ T₁ T₂ : region.State}
    {b₁ b₂ : Bool} (hsp : S₁.spills = S₂.spills)
    (hdst : S₁.regs.val[inst.dst.val]? = S₂.regs.val[inst.dst.val]?)
    (hsrc : cls ≠ isa.CLS_ST → S₁.regs.val[inst.src.val]? = S₂.regs.val[inst.src.val]?)
    (h₁ : region.transfer_store S₁ inst cls = ok (b₁, T₁))
    (h₂ : region.transfer_store S₂ inst cls = ok (b₂, T₂)) :
    b₁ = b₂ ∧ T₁.spills = T₂.spills ∧
    (∀ (r : Nat), T₁.regs.val[r]? = T₂.regs.val[r]? ∨
      (T₁.regs.val[r]? = S₁.regs.val[r]? ∧ T₂.regs.val[r]? = S₂.regs.val[r]?)) ∧
    (∀ (r : Nat), (region.is_atomic inst.opcode = ok true → r ≠ inst.src.val ∧ r ≠ 0) →
      T₁.regs.val[r]? = S₁.regs.val[r]?) := by
  have hdv : (UScalar.cast .Usize inst.dst).val = inst.dst.val := u8_cast_usize_val _
  have hsv : (UScalar.cast .Usize inst.src).val = inst.src.val := u8_cast_usize_val _
  unfold region.transfer_store at h₁ h₂
  bind_same atomic hat h₁ h₂
  -- The value stored.
  obtain_bind ⟨⟨s1, value⟩, hval, h₁⟩ := h₁
  obtain_bind ⟨⟨s1', value'⟩, hval', h₂⟩ := h₂
  try simp only at h₁ h₂
  have hv : s1 = S₁ ∧ s1' = S₂ ∧ value = value' := by
    split at hval
    · rename_i hst
      rw [if_pos hst] at hval'
      simp only [ok.injEq, Prod.mk.injEq] at hval hval'
      exact ⟨hval.1.symm, hval'.1.symm, hval.2.symm.trans hval'.2⟩
    · rename_i hst
      rw [if_neg hst] at hval'
      bind_same i hi hval hval'
      bind_reg v hvr hval hval' (by rw [lift_eq_ok hi, hsv]; exact hsrc hst)
      simp only [ok.injEq, Prod.mk.injEq] at hval hval'
      exact ⟨hval.1.symm, hval'.1.symm, hval.2.symm.trans hval'.2⟩
  obtain ⟨hv1, hv2, hv3⟩ := hv
  subst s1 s1' value'
  bind_same width hw h₁ h₂
  bind_same i hi h₁ h₂
  rw [lift_eq_ok hi] at h₁ h₂
  clear hi
  -- The base.
  obtain_bind ⟨⟨s2, base⟩, hb, h₁⟩ := h₁
  obtain_bind ⟨⟨s2', base'⟩, hb', h₂⟩ := h₂
  try simp only at h₁ h₂
  have hbv : s2 = S₁ ∧ s2' = S₂ ∧ base = base' := by
    split at hb
    · rename_i h10
      rw [if_pos h10] at hb'
      bind_same fp hfp hb hb'
      simp only [ok.injEq, Prod.mk.injEq] at hb hb'
      exact ⟨hb.1.symm, hb'.1.symm, hb.2.symm.trans hb'.2⟩
    · rename_i h10
      rw [if_neg h10] at hb'
      bind_same i1 hi1 hb hb'
      bind_reg v hvr hb hb' (by rw [lift_eq_ok hi1, hdv]; exact hdst)
      simp only [ok.injEq, Prod.mk.injEq] at hb hb'
      exact ⟨hb.1.symm, hb'.1.symm, hb.2.symm.trans hb'.2⟩
  obtain ⟨hb1, hb2, hb3⟩ := hbv
  subst s2 s2' base'
  bind_same isst hisst h₁ h₂
  -- The spills, and whether the write is an atomic.
  obtain_bind ⟨⟨s3, atomic1, refused⟩, hs3, h₁⟩ := h₁
  obtain_bind ⟨⟨s3', atomic1', refused'⟩, hs3', h₂⟩ := h₂
  try simp only at h₁ h₂
  have hs3v : atomic1 = atomic ∧ atomic1' = atomic ∧ refused = refused' ∧
      s3.spills = s3'.spills ∧ s3.regs = S₁.regs ∧ s3'.regs = S₂.regs := by
    split at hs3
    · rename_i hstack
      rw [if_pos hstack] at hs3'
      bind_same b1 hb1 hs3 hs3'
      obtain_bind ⟨s4, hs4, hs3⟩ := hs3
      obtain_bind ⟨s4', hs4', hs3'⟩ := hs3'
      have hs4v : s4.spills = s4'.spills ∧ s4.regs = S₁.regs ∧ s4'.regs = S₂.regs := by
        split at hs4
        · rename_i hal
          rw [if_pos hal] at hs4'
          bind_same start hstart hs4 hs4'
          rw [hsp] at hs4
          bind_same s5 hs5 hs4 hs4'
          simp only [ok.injEq] at hs4 hs4'
          subst hs4 hs4'
          exact ⟨rfl, rfl, rfl⟩
        · rename_i hal
          rw [if_neg hal] at hs4'
          simp only [ok.injEq] at hs4 hs4'
          subst hs4 hs4'
          exact ⟨hsp, rfl, rfl⟩
      obtain ⟨hs4sp, hs4r, hs4r'⟩ := hs4v
      bind_same stored hstored hs3 hs3'
      obtain_bind ⟨⟨s5, b2⟩, hs5, hs3⟩ := hs3
      obtain_bind ⟨⟨s5', b2'⟩, hs5', hs3'⟩ := hs3'
      try simp only at hs3 hs3'
      have hs5v : b2 = b2' ∧ s5.spills = s5'.spills ∧ s5.regs = s4.regs ∧ s5'.regs = s4'.regs := by
        split at hs5
        · rename_i hatm
          rw [if_pos hatm] at hs5'
          simp only [ok.injEq, Prod.mk.injEq] at hs5 hs5'
          obtain ⟨rfl, rfl⟩ := hs5
          obtain ⟨rfl, rfl⟩ := hs5'
          exact ⟨rfl, hs4sp, rfl, rfl⟩
        · rename_i hatm
          rw [if_neg hatm] at hs5'
          split at hs5
          · rename_i h8
            rw [if_pos h8] at hs5'
            bind_same o ho hs5 hs5'
            cases o with
            | none =>
              simp only [ok.injEq, Prod.mk.injEq] at hs5 hs5'
              obtain ⟨rfl, rfl⟩ := hs5
              obtain ⟨rfl, rfl⟩ := hs5'
              exact ⟨rfl, hs4sp, rfl, rfl⟩
            | some start =>
              rw [hs4sp] at hs5
              obtain_bind ⟨⟨b3, s6⟩, hins, hs5⟩ := hs5
              obtain_bind ⟨⟨b3', s6'⟩, hins', hs5'⟩ := hs5'
              rw [hins] at hins'
              simp only [ok.injEq, Prod.mk.injEq] at hins'
              obtain ⟨rfl, rfl⟩ := hins'
              try simp only at hs5 hs5'
              bind_same b4 hb4 hs5 hs5'
              simp only [ok.injEq, Prod.mk.injEq] at hs5 hs5'
              obtain ⟨rfl, rfl⟩ := hs5
              obtain ⟨rfl, rfl⟩ := hs5'
              exact ⟨rfl, rfl, rfl, rfl⟩
          · rename_i h8
            rw [if_neg h8] at hs5'
            simp only [ok.injEq, Prod.mk.injEq] at hs5 hs5'
            obtain ⟨rfl, rfl⟩ := hs5
            obtain ⟨rfl, rfl⟩ := hs5'
            exact ⟨rfl, hs4sp, rfl, rfl⟩
      obtain ⟨rfl, hs5sp, hs5r, hs5r'⟩ := hs5v
      have hs3e : ok (s5, atomic, b2) = ok (s3, atomic1, refused) := hs3
      have hs3e' : ok (s5', atomic, b2) = ok (s3', atomic1', refused') := hs3'
      simp only [ok.injEq, Prod.mk.injEq] at hs3e hs3e'
      obtain ⟨rfl, rfl, rfl⟩ := hs3e
      obtain ⟨rfl, rfl, rfl⟩ := hs3e'
      exact ⟨rfl, rfl, rfl, hs5sp, hs5r.trans hs4r, hs5r'.trans hs4r'⟩
    · rename_i hstack
      rw [if_neg hstack] at hs3'
      bind_same i1 hi1 hs3 hs3'
      bind_reg rk hrk hs3 hs3' (by rw [lift_eq_ok hi1, hdv]; exact hdst)
      obtain_bind ⟨s4, hs4, hs3⟩ := hs3
      obtain_bind ⟨s4', hs4', hs3'⟩ := hs3'
      rw [hsp] at hs4
      rw [hs4] at hs4'
      simp only [ok.injEq] at hs4'
      subst hs4'
      have hs3e : ok ({ S₁ with spills := s4 }, atomic, false) = ok (s3, atomic1, refused) := hs3
      have hs3e' : ok ({ S₂ with spills := s4 }, atomic, false) = ok (s3', atomic1', refused') := hs3'
      simp only [ok.injEq, Prod.mk.injEq] at hs3e hs3e'
      obtain ⟨rfl, rfl, rfl⟩ := hs3e
      obtain ⟨rfl, rfl, rfl⟩ := hs3e'
      exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩
  obtain ⟨ha1, ha2, ha3, hsp3, hr3, hr3'⟩ := hs3v
  subst atomic1 atomic1' refused'
  -- The atomic's register writes.
  change (if atomic = true then _ else _) = ok (b₁, T₁) at h₁
  change (if atomic = true then _ else _) = ok (b₂, T₂) at h₂
  split at h₁
  · rename_i hatm
    rw [if_pos hatm] at h₂
    bind_same i1 hi1 h₁ h₂
    obtain_bind ⟨⟨_, back⟩, hmut, h₁⟩ := h₁
    obtain_bind ⟨⟨_, back'⟩, hmut', h₂⟩ := h₂
    try simp only at h₁ h₂
    obtain ⟨hi₁, _, rfl⟩ := array_index_mut_usize_eq_ok hmut
    obtain ⟨hi₂, _, rfl⟩ := array_index_mut_usize_eq_ok hmut'
    bind_same i2 hi2 h₁ h₂
    split at h₁
    · rename_i hcmp
      rw [if_pos hcmp] at h₂
      obtain_bind ⟨a1, ha1, h₁⟩ := h₁
      obtain_bind ⟨a1', ha1', h₂⟩ := h₂
      simp only [ok.injEq, Prod.mk.injEq] at h₁ h₂
      obtain ⟨rfl, rfl⟩ := h₁
      obtain ⟨rfl, rfl⟩ := h₂
      obtain ⟨h0₁, ha1⟩ := array_update_eq_ok ha1
      obtain ⟨h0₂, ha1'⟩ := array_update_eq_ok ha1'
      have h0v : (0#usize).val = 0 := by simp
      have hi1v : i1.val = inst.src.val := by rw [lift_eq_ok hi1, hsv]
      refine ⟨rfl, hsp3, fun r => ?_, fun r hr => ?_⟩
      · simp only [ha1, ha1', Array.set_val_eq, hr3, hr3', h0v]
        simp only [Array.set_val_eq, hr3, hr3', List.length_set, h0v] at h0₁ h0₂ hi₁ hi₂
        exact set2_agree hi₁ hi₂ h0₁ h0₂ r
      · obtain ⟨hrs, hr0⟩ := hr (by rw [hat, hatm])
        simp only [ha1, Array.set_val_eq, hr3, h0v, hi1v]
        rw [List.getElem?_set_ne (Ne.symm hr0), List.getElem?_set_ne (Ne.symm hrs)]
    · rename_i hcmp
      rw [if_neg hcmp] at h₂
      simp only [ok.injEq, Prod.mk.injEq] at h₁ h₂
      obtain ⟨rfl, rfl⟩ := h₁
      obtain ⟨rfl, rfl⟩ := h₂
      have hi1v : i1.val = inst.src.val := by rw [lift_eq_ok hi1, hsv]
      refine ⟨rfl, hsp3, fun r => ?_, fun r hr => ?_⟩
      · simp only [Array.set_val_eq, hr3, hr3']
        rw [hr3] at hi₁
        rw [hr3'] at hi₂
        exact set_agree hi₁ hi₂ r
      · obtain ⟨hrs, _⟩ := hr (by rw [hat, hatm])
        simp only [Array.set_val_eq, hr3, hi1v]
        rw [List.getElem?_set_ne (Ne.symm hrs)]
  · rename_i hatm
    rw [if_neg hatm] at h₂
    simp only [ok.injEq, Prod.mk.injEq] at h₁ h₂
    obtain ⟨rfl, rfl⟩ := h₁
    obtain ⟨rfl, rfl⟩ := h₂
    refine ⟨rfl, hsp3, fun r => Or.inr ⟨?_, ?_⟩, fun r _ => ?_⟩
    · rw [hr3]
    · rw [hr3']
    · rw [hr3]

/-! ## Calls -/

theorem usize_not_le {x y : Usize} (h : ¬ x ≤ y) : y.val < x.val := by
  rw [UScalar.le_equiv] at h; omega

/-- `transfer_loop` from `r₀` writes `Unknown` to registers `r₀ … 5` and
nothing else. -/
theorem transfer_loop_ok {S T : region.State} {r₀ : Usize} (h6 : r₀.val ≤ 6)
    (h : region.transfer_loop S r₀ = ok T) :
    T.spills = S.spills ∧ ∀ (k : Nat), T.regs.val[k]? =
      (if r₀.val ≤ k ∧ k ≤ 5 then some region.RegKind.Unknown else S.regs.val[k]?) := by
  unfold region.transfer_loop at h
  exact loop_ok_induction _
    (fun x => x.1.spills = S.spills ∧ r₀.val ≤ x.2.val ∧ x.2.val ≤ 6 ∧ ∀ (k : Nat), x.1.regs.val[k]? =
      (if r₀.val ≤ k ∧ k < x.2.val then some region.RegKind.Unknown else S.regs.val[k]?))
    (fun y => y.spills = S.spills ∧ ∀ (k : Nat), y.regs.val[k]? =
      (if r₀.val ≤ k ∧ k ≤ 5 then some region.RegKind.Unknown else S.regs.val[k]?))
    (by
      rintro ⟨s, r⟩ ⟨hsp, hr1, hr6, hk⟩ res hb
      dsimp only at hsp hr1 hr6 hk
      change region.transfer_loop.body s r = ok res at hb
      unfold region.transfer_loop.body at hb
      split at hb
      · rename_i hle
        have hle' : r.val ≤ 5 := by rw [UScalar.le_equiv] at hle; simpa using hle
        obtain_bind ⟨s1, hs1, hb⟩ := hb
        obtain_bind ⟨r1, hr1', hb⟩ := hb
        have hr1v := usize_add_eq_ok hr1'
        simp at hr1v
        simp only [ok.injEq] at hb
        subst hb
        unfold region.set_reg at hs1
        obtain_bind ⟨a, ha, hs1⟩ := hs1
        simp only [ok.injEq] at hs1
        subst hs1
        obtain ⟨hlt, ha⟩ := array_update_eq_ok ha
        refine ⟨hsp, by dsimp only; omega, by dsimp only; omega, fun k => ?_⟩
        dsimp only
        simp only [ha, hr1v]
        by_cases hkr : k = r.val
        · subst hkr
          rw [List.getElem?_set_self hlt, if_pos ⟨hr1, by omega⟩]
        · rw [List.getElem?_set_ne (Ne.symm hkr), hk k]
          by_cases hc : r₀.val ≤ k ∧ k < r.val
          · rw [if_pos hc, if_pos ⟨hc.1, by omega⟩]
          · rw [if_neg hc, if_neg (by omega)]
      · rename_i hgt
        simp only [ok.injEq] at hb
        subst hb
        have h5 : 5 < r.val := by
          have := usize_not_le hgt; simp at this; omega
        refine ⟨hsp, fun k => ?_⟩
        rw [hk k]
        by_cases hc : r₀.val ≤ k ∧ k ≤ 5
        · rw [if_pos hc, if_pos ⟨hc.1, by omega⟩]
        · rw [if_neg hc, if_neg (by omega)])
    _ _ ⟨rfl, le_refl _, h6, fun k => by dsimp only; rw [if_neg (by omega)]⟩ h

/-- A call: `R0` becomes a scalar, `R1`–`R5` unknown, nothing else moves. -/
theorem transfer_call_regs {S T : region.State}
    (h : (do
      let s1 ← region.set_reg S 0#usize region.RegKind.Scalar
      region.transfer_loop s1 1#usize) = ok T) :
    T.spills = S.spills ∧ ∀ (k : Nat), T.regs.val[k]? =
      (if k = 0 then some region.RegKind.Scalar
       else if k ≤ 5 then some region.RegKind.Unknown else S.regs.val[k]?) := by
  obtain_bind ⟨s1, hs1, h⟩ := h
  unfold region.set_reg at hs1
  obtain_bind ⟨a, ha, hs1⟩ := hs1
  simp only [ok.injEq] at hs1
  subst hs1
  obtain ⟨h0, ha⟩ := array_update_eq_ok ha
  obtain ⟨hsp, hk⟩ := transfer_loop_ok (by simp) h
  refine ⟨hsp, fun k => ?_⟩
  rw [hk k, ha]
  have h0v : (0#usize).val = 0 := by simp
  have h1v : (1#usize).val = 1 := by simp
  rw [h0v, h1v]
  rw [h0v] at h0
  by_cases hk0 : k = 0
  · subst hk0
    simp
  · by_cases hk5 : k ≤ 5
    · simp [hk0, hk5, show 1 ≤ k by omega]
    · simp [hk0, hk5, List.getElem?_set_ne (show 0 ≠ k by omega)]

/-! ## The theorem -/

/-- Agreement at a register a mask names, or at `R10`. -/
theorem agree_at {S₁ S₂ : region.State} {uses : U16}
    (hin : ∀ (r : Nat), uses.val.testBit r → S₁.regs.val[r]? = S₂.regs.val[r]?)
    (h10 : S₁.regs.val[10]? = S₂.regs.val[10]?)
    {d : U8} {b : U16} (hb : region.reg_bit (UScalar.cast .Usize d) = ok b)
    (hsub : ∀ (r : Nat), b.val.testBit r → uses.val.testBit r) (hd : d.val ≤ 10) :
    S₁.regs.val[d.val]? = S₂.regs.val[d.val]? := by
  by_cases h : d.val = 10
  · rw [h]; exact h10
  · apply hin
    apply hsub
    rw [reg_bit_testBit hb, u8_cast_usize_val]
    exact ⟨by omega, rfl⟩

theorem transfer_agree {inst : isa.Insn} {callee uses defs : U16}
    (hud : region.uses_and_defs inst callee = ok (uses, defs))
    {S₁ S₂ T₁ T₂ : region.State} {b₁ b₂ : Bool} {lddw lo hi : U64}
    (hsp : S₁.spills = S₂.spills)
    (hin : ∀ (r : Nat), uses.val.testBit r → S₁.regs.val[r]? = S₂.regs.val[r]?)
    (h10 : S₁.regs.val[10]? = S₂.regs.val[10]?)
    (hdst : inst.dst.val ≤ 10) (hsrc : inst.src.val ≤ 10)
    (h₁ : region.transfer S₁ inst lddw lo hi = ok (T₁, b₁))
    (h₂ : region.transfer S₂ inst lddw lo hi = ok (T₂, b₂)) :
    StepAgree defs S₁ S₂ T₁ T₂ ∧ b₁ = b₂ := by
  have hdv : (UScalar.cast .Usize inst.dst).val = inst.dst.val := u8_cast_usize_val _
  have hsv : (UScalar.cast .Usize inst.src).val = inst.src.val := u8_cast_usize_val _
  have hl₁ := regs_length S₁
  have hl₂ := regs_length S₂
  unfold region.transfer at h₁ h₂
  unfold region.uses_and_defs at hud
  bind_same cls hcls h₁ h₂
  obtain_bind ⟨cls', hcls', hud⟩ := hud
  rw [hcls] at hcls'
  simp only [ok.injEq] at hcls'
  subst hcls'
  obtain_bind ⟨dstU, hdstU, hud⟩ := hud
  obtain_bind ⟨srcU, hsrcU, hud⟩ := hud
  rw [lift_eq_ok hdstU, lift_eq_ok hsrcU] at hud
  clear hdstU hsrcU
  -- A write of `dst` on both sides, with defs = reg_bit dst.
  have set_dst : ∀ {k : region.RegKind} {a₁ a₂ : Std.Array region.RegKind 11#usize} {bd : U16},
      Array.update S₁.regs (UScalar.cast .Usize inst.dst) k = ok a₁ →
      Array.update S₂.regs (UScalar.cast .Usize inst.dst) k = ok a₂ →
      region.reg_bit (UScalar.cast .Usize inst.dst) = ok bd →
      StepAgree bd S₁ S₂ { S₁ with regs := a₁ } { S₂ with regs := a₂ } := by
    intro k a₁ a₂ bd ha₁ ha₂ hbd
    obtain ⟨hi₁, ha₁⟩ := array_update_eq_ok ha₁
    obtain ⟨hi₂, ha₂⟩ := array_update_eq_ok ha₂
    refine ⟨fun r hr => ?_, fun r => ?_, hsp⟩
    · rw [reg_bit_testBit hbd] at hr
      obtain ⟨_, rfl⟩ := hr
      simp only [ha₁, ha₂]
      exact set_agree_self hi₁ hi₂
    · simp only [ha₁, ha₂]
      exact set_agree hi₁ hi₂ r
  split at h₁
  · -- lddw
    rename_i hc
    rw [if_pos hc] at h₂ hud
    bind_same rk hrk h₁ h₂
    bind_same i hi h₁ h₂
    obtain_bind ⟨a₁, ha₁, h₁⟩ := h₁
    obtain_bind ⟨a₂, ha₂, h₂⟩ := h₂
    simp only [ok.injEq, Prod.mk.injEq] at h₁ h₂
    obtain ⟨rfl, rfl⟩ := h₁
    obtain ⟨rfl, rfl⟩ := h₂
    obtain_bind ⟨bd, hbd, hud⟩ := hud
    simp only [ok.injEq, Prod.mk.injEq] at hud
    obtain ⟨rfl, rfl⟩ := hud
    rw [lift_eq_ok hi] at ha₁ ha₂
    exact ⟨set_dst ha₁ ha₂ hbd, rfl⟩
  rename_i hnc0
  rw [if_neg hnc0] at h₂ hud
  split at h₁
  · -- load
    rename_i hc
    rw [if_pos hc] at h₂ hud
    obtain_bind ⟨rk, hrk, h₁⟩ := h₁
    obtain_bind ⟨rk', hrk', h₂⟩ := h₂
    rw [hsp] at hrk
    rw [hrk] at hrk'
    simp only [ok.injEq] at hrk'
    subst hrk'
    bind_same i hi h₁ h₂
    obtain_bind ⟨a₁, ha₁, h₁⟩ := h₁
    obtain_bind ⟨a₂, ha₂, h₂⟩ := h₂
    simp only [ok.injEq, Prod.mk.injEq] at h₁ h₂
    obtain ⟨rfl, rfl⟩ := h₁
    obtain ⟨rfl, rfl⟩ := h₂
    obtain_bind ⟨bs, hbs, hud⟩ := hud
    obtain_bind ⟨bd, hbd, hud⟩ := hud
    simp only [ok.injEq, Prod.mk.injEq] at hud
    obtain ⟨rfl, rfl⟩ := hud
    rw [lift_eq_ok hi] at ha₁ ha₂
    exact ⟨set_dst ha₁ ha₂ hbd, rfl⟩
  rename_i hnc1
  rw [if_neg hnc1] at h₂ hud
  -- The two store classes share their argument.
  have store : ∀ (hst : cls ≠ isa.CLS_ST → ∀ (r : Nat), uses.val.testBit r → S₁.regs.val[r]? = S₂.regs.val[r]?)
      {bd : U16} (hbd : region.reg_bit (UScalar.cast .Usize inst.dst) = ok bd)
      (hsub : ∀ (r : Nat), bd.val.testBit r → uses.val.testBit r)
      (hbs : cls ≠ isa.CLS_ST → ∃ bs, region.reg_bit (UScalar.cast .Usize inst.src) = ok bs ∧
        ∀ (r : Nat), bs.val.testBit r → uses.val.testBit r),
      (do let (refused, s) ← region.transfer_store S₁ inst cls; ok (s, refused)) = ok (T₁, b₁) →
      (do let (refused, s) ← region.transfer_store S₂ inst cls; ok (s, refused)) = ok (T₂, b₂) →
      defs = 0#u16 →
      StepAgree defs S₁ S₂ T₁ T₂ ∧ b₁ = b₂ := by
    intro _ bd hbd hsub hbs h₁ h₂ hdefs
    obtain_bind ⟨⟨r₁, s₁⟩, hts₁, h₁⟩ := h₁
    obtain_bind ⟨⟨r₂, s₂⟩, hts₂, h₂⟩ := h₂
    have h₁e : ok (s₁, r₁) = ok (T₁, b₁) := h₁
    have h₂e : ok (s₂, r₂) = ok (T₂, b₂) := h₂
    simp only [ok.injEq, Prod.mk.injEq] at h₁e h₂e
    obtain ⟨rfl, rfl⟩ := h₁e
    obtain ⟨rfl, rfl⟩ := h₂e
    obtain ⟨hb, hspT, hregs, _⟩ := transfer_store_agree hsp (agree_at hin h10 hbd hsub hdst)
      (fun hne => by
        obtain ⟨bs, hbs, hsubs⟩ := hbs hne
        exact agree_at hin h10 hbs hsubs hsrc) hts₁ hts₂
    subst hdefs
    refine ⟨⟨fun r hr => ?_, hregs, hspT⟩, hb⟩
    have h0 : (0#u16).val = 0 := by simp
    rw [h0] at hr
    simp at hr
  split at h₁
  · -- st
    rename_i hc
    rw [if_pos hc] at h₂ hud
    obtain_bind ⟨bd, hbd, hud⟩ := hud
    simp only [ok.injEq, Prod.mk.injEq] at hud
    obtain ⟨rfl, rfl⟩ := hud
    exact store (fun hne => absurd hc hne) hbd (fun r hr => hr) (fun hne => absurd hc hne) h₁ h₂ rfl
  rename_i hnc2
  rw [if_neg hnc2] at h₂ hud
  split at h₁
  · -- stx, atomics included
    rename_i hc
    rw [if_pos hc] at h₂ hud
    obtain_bind ⟨bd, hbd, hud⟩ := hud
    obtain_bind ⟨bs, hbs, hud⟩ := hud
    obtain_bind ⟨u, hu, hud⟩ := hud
    rw [lift_eq_ok hu] at hud
    obtain_bind ⟨at', hat, hud⟩ := hud
    have hsub : ∀ (r : Nat), (bd ||| bs).val.testBit r → uses.val.testBit r := by
      split at hud
      · obtain_bind ⟨b0, hb0, hud⟩ := hud
        obtain_bind ⟨u1, hu1, hud⟩ := hud
        rw [lift_eq_ok hu1] at hud
        simp only [ok.injEq, Prod.mk.injEq] at hud
        obtain ⟨rfl, _⟩ := hud
        intro r hr
        rw [or_testBit (bd ||| bs) b0, hr]
        simp
      · simp only [ok.injEq, Prod.mk.injEq] at hud
        obtain ⟨rfl, _⟩ := hud
        exact fun r hr => hr
    have hdefs : defs = 0#u16 := by
      split at hud
      · obtain_bind ⟨b0, hb0, hud⟩ := hud
        obtain_bind ⟨u1, hu1, hud⟩ := hud
        simp only [ok.injEq, Prod.mk.injEq] at hud
        exact hud.2.symm
      · simp only [ok.injEq, Prod.mk.injEq] at hud
        exact hud.2.symm
    refine store (fun _ => hin) hbd (fun r hr => hsub r ?_) (fun _ => ⟨bs, hbs, fun r hr => hsub r ?_⟩) h₁ h₂ hdefs
    · rw [or_testBit, hr]; simp
    · rw [or_testBit, hr]; simp
  rename_i hnc3
  rw [if_neg hnc3] at h₂ hud
  split at h₁
  · -- alu32
    rename_i hc
    rw [if_pos hc] at h₂ hud
    bind_same i hi h₁ h₂
    obtain_bind ⟨a₁, ha₁, h₁⟩ := h₁
    obtain_bind ⟨a₂, ha₂, h₂⟩ := h₂
    simp only [ok.injEq, Prod.mk.injEq] at h₁ h₂
    obtain ⟨rfl, rfl⟩ := h₁
    obtain ⟨rfl, rfl⟩ := h₂
    obtain_bind ⟨sb, hsb, hud⟩ := hud
    obtain_bind ⟨src_bits, hsrcb, hud⟩ := hud
    obtain_bind ⟨am, ham, hud⟩ := hud
    have hdefs : ∃ bd, region.reg_bit (UScalar.cast .Usize inst.dst) = ok bd ∧ defs = bd := by
      split at hud
      · obtain_bind ⟨bd, hbd, hud⟩ := hud
        simp only [ok.injEq, Prod.mk.injEq] at hud
        exact ⟨bd, hbd, hud.2.symm⟩
      · obtain_bind ⟨bd, hbd, hud⟩ := hud
        obtain_bind ⟨u1, hu1, hud⟩ := hud
        simp only [ok.injEq, Prod.mk.injEq] at hud
        exact ⟨bd, hbd, hud.2.symm⟩
    obtain ⟨bd, hbd, rfl⟩ := hdefs
    rw [lift_eq_ok hi] at ha₁ ha₂
    exact ⟨set_dst ha₁ ha₂ hbd, rfl⟩
  rename_i hnc4
  rw [if_neg hnc4] at h₂ hud
  split at h₁
  · -- alu64
    rename_i hc
    rw [if_pos hc] at h₂ hud
    obtain_bind ⟨t₁, ht₁, h₁⟩ := h₁
    obtain_bind ⟨t₂, ht₂, h₂⟩ := h₂
    simp only [ok.injEq, Prod.mk.injEq] at h₁ h₂
    obtain ⟨rfl, rfl⟩ := h₁
    obtain ⟨rfl, rfl⟩ := h₂
    obtain_bind ⟨sb, hsb, hud⟩ := hud
    rw [lift_eq_ok hsb] at hud
    obtain_bind ⟨src_bits, hsrcb, hud⟩ := hud
    obtain_bind ⟨am, ham, hud⟩ := hud
    rw [lift_eq_ok ham] at hud
    -- What `uses` and `defs` are, and the agreement they buy.
    have hreg : (inst.opcode &&& isa.SRC_REG != 0#u8) ↔ inst.opcode.val &&& 8 ≠ 0 := by
      simp only [bne_iff_ne, ne_eq]
      rw [not_iff_not, UScalar.eq_equiv]
      simp [isa.SRC_REG]
    have hsrc_agree : inst.opcode.val &&& 8 ≠ 0 → ∀ (r : Nat), src_bits.val.testBit r → uses.val.testBit r → True := fun _ _ _ _ => trivial
    have hsrcb' : inst.opcode.val &&& 8 ≠ 0 → region.reg_bit (UScalar.cast .Usize inst.src) = ok src_bits := by
      intro hb
      split at hsrcb
      · exact hsrcb
      · rename_i hz; exact absurd (hreg.mpr hb) hz
    have hmov : (inst.opcode &&& isa.ALU_MASK = region.ALU_OP_MOV) ↔ inst.opcode.val &&& 0xf0 = 0xb0 := by
      rw [UScalar.eq_equiv]
      simp [isa.ALU_MASK, region.ALU_OP_MOV]
    have main : ∀ (bd : U16), region.reg_bit (UScalar.cast .Usize inst.dst) = ok bd →
        (inst.opcode.val &&& 0xf0 ≠ 0xb0 → ∀ (r : Nat), bd.val.testBit r → uses.val.testBit r) →
        (inst.opcode.val &&& 8 ≠ 0 → ∀ (r : Nat), src_bits.val.testBit r → uses.val.testBit r) →
        defs = bd → StepAgree defs S₁ S₂ t₁ t₂ ∧ false = false := by
      intro bd hbd hsubd hsubs hdefs
      subst hdefs
      obtain ⟨k, hk₁, hk₂, hsp₁, hsp₂⟩ := transfer_alu64_agree
        (fun hnm => agree_at hin h10 hbd (hsubd hnm) hdst)
        (fun hr => agree_at hin h10 (hsrcb' hr) (hsubs hr) hsrc) ht₁ ht₂
      refine ⟨⟨fun r hr => ?_, fun r => ?_, hsp₁.trans (hsp.trans hsp₂.symm)⟩, rfl⟩
      · rw [reg_bit_testBit hbd, u8_cast_usize_val] at hr
        obtain ⟨_, rfl⟩ := hr
        rw [hk₁, hk₂]
        exact set_agree_self (by omega) (by omega)
      · rw [hk₁, hk₂]
        exact set_agree (by omega) (by omega) r
    split at hud
    · -- mov: uses = src bits, defs = dst
      rename_i hm
      obtain_bind ⟨bd, hbd, hud⟩ := hud
      simp only [ok.injEq, Prod.mk.injEq] at hud
      obtain ⟨rfl, rfl⟩ := hud
      exact main bd hbd (fun hnm => absurd (hmov.mp hm) hnm) (fun _ r hr => hr) rfl
    · rename_i hnm
      obtain_bind ⟨bd, hbd, hud⟩ := hud
      obtain_bind ⟨u1, hu1, hud⟩ := hud
      rw [lift_eq_ok hu1] at hud
      simp only [ok.injEq, Prod.mk.injEq] at hud
      obtain ⟨rfl, rfl⟩ := hud
      refine main bd hbd (fun _ r hr => ?_) (fun _ r hr => ?_) rfl
      · rw [or_testBit]; simp [hr]
      · rw [or_testBit]; simp [hr]
  rename_i hnc7
  rw [if_neg hnc7] at h₂ hud
  -- What remains is a jump: a call clobbers `R0`–`R5`, nothing else moves.
  have hcall_defs : inst.opcode = isa.OP_CALL →
      defs = region.CALL_CLOBBERED_REGS ∨ defs = 0#u16 := by
    intro hc
    repeat' split at hud
    all_goals first
      | exact absurd hc ‹_›
      | (simp only [ok.injEq, Prod.mk.injEq] at hud
         rcases hud with ⟨_, rfl⟩
         first | exact Or.inl rfl | exact Or.inr rfl)
  have hnocall_defs : inst.opcode ≠ isa.OP_CALL → defs = 0#u16 := by
    intro hnc
    repeat' split at hud
    all_goals first
      | exact absurd ‹inst.opcode = isa.OP_CALL› hnc
      | (simp only [ok.injEq, Prod.mk.injEq] at hud
         rcases hud with ⟨_, rfl⟩
         rfl)
      | (obtain_bind ⟨_, _, hud⟩ := hud
         obtain_bind ⟨_, _, hud⟩ := hud
         obtain_bind ⟨_, _, hud⟩ := hud
         obtain_bind ⟨_, _, hud⟩ := hud
         simp only [ok.injEq, Prod.mk.injEq] at hud
         rcases hud with ⟨_, rfl⟩
         rfl)
  split at h₁
  · -- call
    rename_i hc
    rw [if_pos hc] at h₂
    obtain_bind ⟨s₁, hs₁, h₁⟩ := h₁
    obtain_bind ⟨s₂, hs₂, h₂⟩ := h₂
    obtain_bind ⟨t₁, ht₁, h₁⟩ := h₁
    obtain_bind ⟨t₂, ht₂, h₂⟩ := h₂
    simp only [ok.injEq, Prod.mk.injEq] at h₁ h₂
    obtain ⟨rfl, rfl⟩ := h₁
    obtain ⟨rfl, rfl⟩ := h₂
    obtain ⟨hspT₁, hk₁⟩ := transfer_call_regs (bind_ok_of hs₁ ht₁)
    obtain ⟨hspT₂, hk₂⟩ := transfer_call_regs (bind_ok_of hs₂ ht₂)
    have rest : ∀ (r : Nat), t₁.regs.val[r]? = t₂.regs.val[r]? ∨
        (t₁.regs.val[r]? = S₁.regs.val[r]? ∧ t₂.regs.val[r]? = S₂.regs.val[r]?) := by
      intro r
      rw [hk₁, hk₂]
      by_cases h0 : r = 0
      · left; simp [h0]
      · by_cases h5 : r ≤ 5
        · left; simp [h0, h5]
        · right; simp [h0, h5]
    refine ⟨⟨fun r hr => ?_, rest, hspT₁.trans (hsp.trans hspT₂.symm)⟩, rfl⟩
    rcases hcall_defs hc with hd | hd
    · subst hd
      have hr' : r ≤ 5 := by
        have hv : (region.CALL_CLOBBERED_REGS).val = 63 := by simp [region.CALL_CLOBBERED_REGS]
        rw [hv] at hr
        by_contra hgt
        have : (63 : Nat).testBit r = false := by
          rw [Nat.testBit_lt_two_pow]  -- 63 < 2^6 ≤ 2^r
          calc (63 : Nat) < 2 ^ 6 := by norm_num
            _ ≤ 2 ^ r := Nat.pow_le_pow_right (by norm_num) (by omega)
        simp [this] at hr
      rw [hk₁, hk₂]
      by_cases h0 : r = 0
      · simp [h0]
      · simp [h0, hr']
    · subst hd
      have h0 : (0#u16).val = 0 := by simp
      rw [h0] at hr
      simp at hr
  · -- any other jump: nothing moves
    rename_i hnc
    rw [if_neg hnc] at h₂
    simp only [ok.injEq, Prod.mk.injEq] at h₁ h₂
    obtain ⟨rfl, rfl⟩ := h₁
    obtain ⟨rfl, rfl⟩ := h₂
    have hd := hnocall_defs hnc
    subst hd
    refine ⟨⟨fun r hr => ?_, fun r => Or.inr ⟨rfl, rfl⟩, hsp⟩, rfl⟩
    have h0 : (0#u16).val = 0 := by simp
    rw [h0] at hr
    simp at hr

/-! ## The frame pointer's kind -/

theorem meet_fp_fp : region.meet fpKind fpKind = ok fpKind := by
  simp [region.meet, region.kind_eq, fpKind]

/-- The class bits, from a comparison of the masked opcode. -/
theorem cls_eq {inst : isa.Insn} {c : U8} {n : Nat} (hc : inst.opcode &&& isa.CLS_MASK = c)
    (hcv : c.val = n) : inst.opcode.val &&& 7 = n := by
  rw [← hcv, ← hc, cls_val]

/-- `transfer` never touches `R10` on an instruction the validator accepts:
one whose destination is `R10` only in a store form, and whose atomic source
is not `R10`. -/
theorem transfer_R10 {inst : isa.Insn} {S T : region.State} {b : Bool} {lddw lo hi : U64}
    (hdst : inst.dst.val = 10 → inst.opcode.val &&& 7 = 2 ∨ inst.opcode.val &&& 7 = 3)
    (hatomic : region.is_atomic inst.opcode = ok true → inst.src.val ≠ 10)
    (h : region.transfer S inst lddw lo hi = ok (T, b)) :
    T.regs.val[10]? = S.regs.val[10]? := by
  have hdv : (UScalar.cast .Usize inst.dst).val = inst.dst.val := u8_cast_usize_val _
  unfold region.transfer at h
  obtain_bind ⟨cls, hcls, h⟩ := h
  rw [lift_eq_ok hcls] at h
  clear hcls
  -- A write of `dst` in a class that is not a store leaves `R10` alone.
  have set_dst : ∀ {k : region.RegKind} {a : Std.Array region.RegKind 11#usize},
      Array.update S.regs (UScalar.cast .Usize inst.dst) k = ok a →
      inst.opcode.val &&& 7 ≠ 2 → inst.opcode.val &&& 7 ≠ 3 → a.val[10]? = S.regs.val[10]? := by
    intro k a ha hn2 hn3
    obtain ⟨_, ha⟩ := array_update_eq_ok ha
    rw [ha, hdv, List.getElem?_set_ne]
    intro h10
    rcases hdst h10 with h | h
    · exact hn2 h
    · exact hn3 h
  split at h
  · rename_i hc
    have := cls_eq (n := 0) hc (by simp [isa.CLS_LD])
    obtain_bind ⟨rk, _, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    obtain_bind ⟨a, ha, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    rw [lift_eq_ok hi] at ha
    exact set_dst ha (by omega) (by omega)
  split at h
  · rename_i hc
    have := cls_eq (n := 1) hc (by simp [isa.CLS_LDX])
    obtain_bind ⟨rk, _, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    obtain_bind ⟨a, ha, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    rw [lift_eq_ok hi] at ha
    exact set_dst ha (by omega) (by omega)
  -- Both store classes: only an atomic writes a register, and never `R10`.
  have store : ∀ {c : U8},
      (do let (refused, s) ← region.transfer_store S inst c; ok (s, refused)) = ok (T, b) →
      T.regs.val[10]? = S.regs.val[10]? := by
    intro c h
    obtain_bind ⟨⟨r, s⟩, hts, h⟩ := h
    have he : ok (s, r) = ok (T, b) := h
    simp only [ok.injEq, Prod.mk.injEq] at he
    obtain ⟨rfl, rfl⟩ := he
    obtain ⟨_, _, _, hkeep⟩ := transfer_store_agree rfl rfl (fun _ => rfl) hts hts
    exact hkeep 10 (fun hat => ⟨Ne.symm (hatomic hat), by omega⟩)
  split at h
  · exact store h
  split at h
  · exact store h
  split at h
  · rename_i hc
    have := cls_eq (n := 4) hc (by simp [isa.CLS_ALU])
    obtain_bind ⟨i, hi, h⟩ := h
    obtain_bind ⟨a, ha, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    rw [lift_eq_ok hi] at ha
    exact set_dst ha (by omega) (by omega)
  split at h
  · rename_i hc
    have := cls_eq (n := 7) hc (by simp [isa.CLS_ALU64])
    obtain_bind ⟨t, ht, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    obtain ⟨k, hk, _, _, _⟩ := transfer_alu64_agree (fun _ => rfl) (fun _ => rfl) ht ht
    rw [hk, List.getElem?_set_ne]
    intro h10
    rcases hdst h10 with h | h <;> omega
  split at h
  · obtain_bind ⟨s₁, hs₁, h⟩ := h
    obtain_bind ⟨t, ht, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    obtain ⟨_, hk⟩ := transfer_call_regs (bind_ok_of hs₁ ht)
    rw [hk 10]
    simp
  · simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    rfl

/-- `meet_regs` keeps `R10`'s kind when both sides have the frame pointer there. -/
theorem meet_regs_R10 {regs other : Std.Array region.RegKind 11#usize} {c : Bool}
    {a : Std.Array region.RegKind 11#usize}
    (hr : regs.val[10]? = some fpKind) (ho : other.val[10]? = some fpKind)
    (h : region.meet_regs regs other = ok (c, a)) : a.val[10]? = some fpKind := by
  unfold region.meet_regs region.meet_regs_loop at h
  exact loop_ok_induction _
    (fun x => x.1.val[10]? = some fpKind)
    (fun y => y.2.val[10]? = some fpKind)
    (by
      rintro ⟨rs, ch, r⟩ hinv res hb
      dsimp only at hinv
      change region.meet_regs_loop.body other rs ch r = ok res at hb
      unfold region.meet_regs_loop.body at hb
      split at hb
      · obtain_bind ⟨rk, hrk, hb⟩ := hb
        obtain_bind ⟨rk1, hrk1, hb⟩ := hb
        obtain_bind ⟨merged, hm, hb⟩ := hb
        obtain_bind ⟨beq, hbeq, hb⟩ := hb
        split at hb
        · obtain_bind ⟨r1, _, hb⟩ := hb
          simp only [ok.injEq] at hb
          subst hb
          exact hinv
        · obtain_bind ⟨a', ha', hb⟩ := hb
          obtain_bind ⟨r1, _, hb⟩ := hb
          simp only [ok.injEq] at hb
          subst hb
          obtain ⟨hlt, ha'⟩ := array_update_eq_ok ha'
          dsimp only
          rw [ha']
          by_cases h10 : r.val = 10
          · -- `R10` meets itself: nothing changes, so this branch is impossible.
            exfalso
            obtain ⟨_, rfl⟩ := array_index_usize_eq_ok hrk
            obtain ⟨_, rfl⟩ := array_index_usize_eq_ok hrk1
            rw [← h10] at hinv ho
            have e1 : rs.val[r.val] = fpKind := by
              rw [List.getElem?_eq_getElem] at hinv; simpa using hinv
            have e2 : other.val[r.val] = fpKind := by
              rw [List.getElem?_eq_getElem] at ho; simpa using ho
            simp only [e1, e2, meet_fp_fp, ok.injEq] at hm
            subst hm
            rw [e1] at hbeq
            simp [region.kind_eq, fpKind] at hbeq
            subst hbeq
            rename_i hne
            exact hne rfl
          · rw [List.getElem?_set_ne h10]
            exact hinv
      · simp only [ok.injEq] at hb
        subst hb
        exact hinv)
    _ _ hr h

/-- `meet_from` keeps `R10`'s kind when both states have the frame pointer there. -/
theorem meet_from_R10 {S O T : region.State} {c r : Bool}
    (hS : S.regs.val[10]? = some fpKind) (hO : O.regs.val[10]? = some fpKind)
    (h : region.meet_from S O = ok ((c, r), T)) : T.regs.val[10]? = some fpKind := by
  unfold region.meet_from at h
  obtain_bind ⟨⟨rc, a⟩, hmr, h⟩ := h
  obtain_bind ⟨⟨⟨sc, rf⟩, sp⟩, hms, h⟩ := h
  have hme : (if rc = true then ok ((true, rf), ({ regs := a, spills := sp } : region.State))
      else ok ((sc, rf), ({ regs := a, spills := sp } : region.State))) = ok ((c, r), T) := h
  have ha := meet_regs_R10 hS hO hmr
  split at hme <;> simp only [ok.injEq, Prod.mk.injEq] at hme <;> obtain ⟨_, rfl⟩ := hme <;> exact ha

end async_ebpf_verified

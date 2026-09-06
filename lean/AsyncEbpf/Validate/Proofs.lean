import AsyncEbpf.Validate.Structure
import AsyncEbpf.Validate.Decoder

/-!
# The validator characterization

`validate_ok_wellFormed`: a program the kernel validator accepts is
`WellFormed`. The proof follows the code: one lemma per generated function
that matters, and a strong induction on the remaining slots for the loop.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

/-! ## One slot -/

theorem check_slot_ok {config : validate.Config} {kh : Slice U32} {insns : Slice isa.Insn}
    {ext : Slice Bool} {pc : Usize} {skip : Bool}
    (h : validate.check_slot config kh insns ext pc = ok (.Ok skip)) :
    ∃ (hpc : pc.val < insns.length) (op : isa.Op),
      isa.decode insns.val[pc.val].opcode = ok (some op) ∧
      validate.check_structure config kh insns ext pc insns.val[pc.val] op = ok (.Ok ()) ∧
      insns.val[pc.val].src.val ≤ 10 ∧
      (insns.val[pc.val].dst.val ≤ 9 ∨
        (insns.val[pc.val].dst.val = 10 ∧ validate.is_store_form op = ok true)) ∧
      validate.check_operand_filter insns.val[pc.val] pc = ok (.Ok ()) ∧
      validate.is_load_imm64 op = ok skip := by
  unfold validate.check_slot at h
  obtain ⟨insn, hidx, h⟩ := bind_eq_ok h
  obtain ⟨hpc, rfl⟩ := index_usize_eq_ok hidx
  refine ⟨hpc, ?_⟩
  obtain ⟨o, hdec, h⟩ := bind_eq_ok h
  cases o with
  | none => simp at h
  | some op =>
    refine ⟨op, hdec, ?_⟩
    simp only at h
    obtain ⟨r, hcs, h⟩ := bind_eq_ok h
    obtain ⟨cf, hbr, h⟩ := bind_eq_ok h
    cases r with
    | Err e =>
      rw [branch_Err] at hbr
      simp only [ok.injEq] at hbr
      subst hbr
      simp only at h
      exact absurd h (from_residual_ne_ok _ _)
    | Ok u =>
      rw [branch_Ok] at hbr
      simp only [ok.injEq] at hbr
      subst hbr
      simp only at h
      split at h
      · simp at h
      · rename_i hsrc
        refine ⟨hcs, by scalar_tac, ?_⟩
        split at h
        · rename_i hdst
          obtain ⟨b, hsf, h⟩ := bind_eq_ok h
          split at h
          · rename_i hb
            split at h
            · rename_i hd10
              obtain ⟨r1, hf, h⟩ := bind_eq_ok h
              obtain ⟨cf1, hbr1, h⟩ := bind_eq_ok h
              cases r1 with
              | Err e =>
                rw [branch_Err] at hbr1
                simp only [ok.injEq] at hbr1
                subst hbr1
                simp only at h
                exact absurd h (from_residual_ne_ok _ _)
              | Ok u1 =>
                rw [branch_Ok] at hbr1
                simp only [ok.injEq] at hbr1
                subst hbr1
                simp only at h
                obtain ⟨b1, hli, h⟩ := bind_eq_ok h
                simp only [ok.injEq, core.result.Result.Ok.injEq] at h
                subst h
                subst hb
                exact ⟨Or.inr ⟨by scalar_tac, hsf⟩, hf, hli⟩
            · simp at h
          · simp at h
        · rename_i hdst
          obtain ⟨r1, hf, h⟩ := bind_eq_ok h
          obtain ⟨cf1, hbr1, h⟩ := bind_eq_ok h
          cases r1 with
          | Err e =>
            rw [branch_Err] at hbr1
            simp only [ok.injEq] at hbr1
            subst hbr1
            simp only at h
            exact absurd h (from_residual_ne_ok _ _)
          | Ok u1 =>
            rw [branch_Ok] at hbr1
            simp only [ok.injEq] at hbr1
            subst hbr1
            simp only at h
            obtain ⟨b1, hli, h⟩ := bind_eq_ok h
            simp only [ok.injEq, core.result.Result.Ok.injEq] at h
            subst h
            exact ⟨Or.inl (by scalar_tac), hf, hli⟩

/-- The `SlotOk` facts, packaged, plus how the slot after this one is chosen. -/
theorem check_slot_slotOk {config : validate.Config} {kh : Slice U32} {insns : Slice isa.Insn}
    {ext : Slice Bool} {pc : Usize} {skip : Bool} (hlen : insns.length < 2 ^ 63)
    (h : validate.check_slot config kh insns ext pc = ok (.Ok skip)) :
    ∃ hpc : pc.val < insns.length,
      SlotOk insns.val pc.val hpc ∧
      ∃ op, isa.decode insns.val[pc.val].opcode = ok (some op) ∧
        validate.is_load_imm64 op = ok skip := by
  obtain ⟨hpc, op, hdec, hcs, hsrc, hdst, hf, hli⟩ := check_slot_ok h
  have hpc' : pc.val < 2 ^ 63 := by omega
  refine ⟨hpc, ⟨op, hdec, ?_⟩, op, hdec, hli⟩
  obtain ⟨fl, hfl, _, hsrc_hi⟩ := check_operand_filter_ok hf
  exact {
    src_bound := hsrc
    dst_bound := hdst
    atomic_src := by
      intro hat
      cases op with
      | Atomic w o b => exact le_trans hsrc_hi (atomic_src_hi _ w o b hdec fl hfl)
      | _ => exact absurd hat (by simp [IsAtomic])
    structure_ok := check_structure_ok hlen hpc' hcs }

/-- Two classifications of one opcode agree on `is_load_imm64`. -/
theorem is_load_imm64_det {opcode : U8} {op op' : isa.Op} {b b' : Bool}
    (h : isa.decode opcode = ok (some op)) (h' : isa.decode opcode = ok (some op'))
    (hb : validate.is_load_imm64 op = ok b) (hb' : validate.is_load_imm64 op' = ok b') : b = b' := by
  rw [h] at h'
  simp only [ok.injEq, Option.some.injEq] at h'
  subst h'
  rw [hb] at hb'
  simp only [ok.injEq] at hb'
  exact hb'

/-! ## The loop -/

theorem Walk.le {insns : List isa.Insn} {i j : Nat} (h : Walk insns i j) : i ≤ j := by
  induction h with
  | refl => exact Nat.le_refl _
  | next _ _ _ ih => omega
  | lddw _ _ _ ih => omega

theorem validate_loop_ok (il : Usize) (b b1 : Bool) (kh : Slice U32) (insns : Slice isa.Insn)
    (ext : Slice Bool) (n : Usize) (hlen : insns.length < 2 ^ 63) :
    ∀ (k : Nat) (i1 : Usize), n.val - i1.val = k →
      validate.validate_loop il b b1 kh insns ext n i1 = ok (.Ok ()) →
      ∀ j (hj : j < insns.length), Walk insns.val i1.val j → j < n.val →
        SlotOk insns.val j hj := by
  intro k
  induction k using Nat.strong_induction_on with
  | _ k ih =>
  intro i1 hk h j hj hw hjn
  unfold validate.validate_loop at h
  unfold loop at h
  try dsimp only at h
  rcases hb : validate.validate_loop.body il b b1 kh insns ext n i1 with r | e | _
    <;> simp [hb] at h
  unfold validate.validate_loop.body at hb
  split at hb
  · rename_i hlt
    obtain ⟨r0, hcs, hb⟩ := bind_eq_ok hb
    obtain ⟨cf, hbr, hb⟩ := bind_eq_ok hb
    cases r0 with
    | Err e =>
      rw [branch_Err] at hbr
      simp only [ok.injEq] at hbr
      subst hbr
      simp only at hb
      obtain ⟨r1, hres, hb⟩ := bind_eq_ok hb
      rw [from_residual_Err] at hres
      simp only [ok.injEq] at hres
      subst hres
      simp only [ok.injEq] at hb
      subst hb
      simp at h
    | Ok skip =>
      rw [branch_Ok] at hbr
      simp only [ok.injEq] at hbr
      subst hbr
      simp only at hb
      obtain ⟨hpc, hok, op, hdec, hli⟩ := check_slot_slotOk hlen hcs
      -- The next slot the loop visits.
      have step : ∃ i2 : Usize, r = ControlFlow.cont i2 ∧
          ((skip = true ∧ i2.val = i1.val + 2) ∨ (skip = false ∧ i2.val = i1.val + 1)) := by
        split at hb
        · rename_i hs
          obtain ⟨i2, hadd, hb⟩ := bind_eq_ok hb
          simp only [ok.injEq] at hb
          subst hb
          have := usize_add_eq_ok hadd
          exact ⟨i2, rfl, Or.inl ⟨hs, by scalar_tac⟩⟩
        · rename_i hs
          obtain ⟨i2, hadd, hb⟩ := bind_eq_ok hb
          simp only [ok.injEq] at hb
          subst hb
          have := usize_add_eq_ok hadd
          exact ⟨i2, rfl, Or.inr ⟨by simpa using hs, by scalar_tac⟩⟩
      obtain ⟨i2, rfl, hi2⟩ := step
      simp only at h
      change validate.validate_loop il b b1 kh insns ext n i2 = ok (.Ok ()) at h
      cases hw with
      | refl => exact hok
      | next _ hsingle hw' =>
        obtain ⟨op', hdec', hli'⟩ := hsingle
        have hs := is_load_imm64_det hdec hdec' hli hli'
        subst hs
        rcases hi2 with ⟨hbad, _⟩ | ⟨_, hi2⟩
        · exact absurd hbad (by decide)
        · exact ih (n.val - i2.val) (by scalar_tac) i2 rfl h j hj (by rw [hi2]; exact hw') hjn
      | lddw _ hlddw hw' =>
        obtain ⟨op', hdec', hli'⟩ := hlddw
        have hs := is_load_imm64_det hdec hdec' hli hli'
        subst hs
        rcases hi2 with ⟨_, hi2⟩ | ⟨hbad, _⟩
        · exact ih (n.val - i2.val) (by scalar_tac) i2 rfl h j hj (by rw [hi2]; exact hw') hjn
        · exact absurd hbad (by decide)
  · rename_i hge
    have := Walk.le hw
    scalar_tac

/-! ## The theorem -/

/-- Every program `validate` accepts is `WellFormed`. In particular no
instruction slot of it writes R10 except through a store form. -/
theorem validate_ok_wellFormed (config : validate.Config) (kh : Slice U32) (insns : Slice isa.Insn)
    (ext : Slice Bool) (hlen : insns.length < 2 ^ 63)
    (h : validate.validate config kh insns ext = ok (.Ok ())) :
    WellFormed insns.val := by
  unfold validate.validate at h
  dsimp only at h
  split at h
  · simp at h
  · intro j hj hs
    exact validate_loop_ok _ _ _ _ _ _ _ hlen _ 0#usize rfl h j hj hs (by simpa using hj)

/-- The headline, spelled out: an accepted program never assigns the frame
pointer outside the store forms. -/
theorem validate_ok_no_frame_pointer_write (config : validate.Config) (kh : Slice U32)
    (insns : Slice isa.Insn) (ext : Slice Bool) (hlen : insns.length < 2 ^ 63)
    (h : validate.validate config kh insns ext = ok (.Ok ()))
    (j : Nat) (hj : j < insns.length) (hs : InsnSlot insns.val j) :
    NoFramePointerWrite insns.val j hj := by
  have hw := validate_ok_wellFormed config kh insns ext hlen h
  unfold WellFormed at hw
  obtain ⟨op, hdec, facts⟩ := hw j hj hs
  rcases facts.dst_bound with hle | ⟨h10, hsf⟩
  · exact Or.inl hle
  · exact Or.inr ⟨h10, op, hdec, hsf⟩

end async_ebpf_verified

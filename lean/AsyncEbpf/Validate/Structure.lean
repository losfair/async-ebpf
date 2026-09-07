import AsyncEbpf.Validate.Spec

/-!
# The structural checks, read off the generated code

`check_structure_ok`: when `check_structure` returns `Ok`, the decoded
instruction satisfies `StructureOk`. `check_operand_filter_ok`: when the
operand filter returns `Ok`, the register fields are within the row's bounds.

Both are case analyses on the generated definitions. The arithmetic in the
jump and call arms is done in `i64` there; the lemmas translate it back into
`Int` on the slot numbers, which needs the program to be shorter than `2^63`
slots so that the unsigned-to-signed casts are the identity.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

/-! ## Monad plumbing -/

theorem bind_eq_ok {α β : Type} {x : Result α} {f : α → Result β} {y : β}
    (h : (x >>= f) = ok y) : ∃ a, x = ok a ∧ f a = ok y := by
  cases x <;> simp_all

theorem index_usize_eq_ok {α : Type} {v : Slice α} {i : Usize} {x : α}
    (h : Slice.index_usize v i = ok x) : ∃ hi : i.val < v.length, x = v.val[i.val] := by
  unfold Slice.index_usize at h
  rw [Slice.getElem?_Usize_eq] at h
  split at h
  · simp at h
  · rename_i hget
    simp only [ok.injEq] at h
    subst h
    rw [List.getElem?_eq_some_iff] at hget
    obtain ⟨hi, hx⟩ := hget
    exact ⟨hi, hx.symm⟩

theorem branch_Ok {T E : Type} (v : T) :
    core.result.Result.Insts.CoreOpsTry.branch (E := E) (.Ok v) = ok (.Continue v) := rfl

theorem branch_Err {T E : Type} (e : E) :
    core.result.Result.Insts.CoreOpsTry.branch (T := T) (.Err e) = ok (.Break (.Err e)) := rfl

theorem from_residual_ne_ok {T E : Type} (r : core.result.Result core.convert.Infallible E) (x : T) :
    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
      T (core.convert.FromSame E) r ≠ ok (.Ok x) := by
  cases r with
  | Ok i => nomatch i
  | Err e =>
    simp [core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual]

theorem from_residual_Err {T E : Type} (e : E) :
    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
      T (core.convert.FromSame E) (.Err e) = ok (.Err e) := rfl

theorem usize_add_eq_ok {x y z : Usize} (h : x + y = ok z) : z.val = x.val + y.val := by
  have := UScalar.add_equiv x y
  rw [h] at this
  exact this.2.1

theorem i64_add_eq_ok {x y z : I64} (h : x + y = ok z) : z.val = x.val + y.val := by
  have := IScalar.add_equiv x y
  rw [h] at this
  exact this.2.1

/-- `pc as i64` is `pc` below `2^63`. -/
theorem usize_hcast_i64_val (x : Usize) (hx : x.val < 2 ^ 63) :
    (UScalar.hcast .I64 x).val = (x.val : Int) := by
  rw [UScalar.hcast_val_eq]
  simp only [IScalarTy.I64_numBits_eq]
  unfold Int.bmod
  push_cast
  have hx' : (x.val : Int) < 9223372036854775808 := by
    have : (2:Nat) ^ 63 = 9223372036854775808 := by norm_num
    rw [this] at hx
    exact_mod_cast hx
  split <;> omega

/-- `target as usize` is `target` when it is a valid slot number. -/
theorem i64_hcast_usize_val (x : I64) (hx : 0 ≤ x.val) (hx2 : x.val ≤ (Usize.max : Int)) :
    ((IScalar.hcast .Usize x).val : Int) = x.val := by
  rw [IScalar.hcast_val_eq]
  rw [Usize.max_def, Usize.numBits_def] at hx2
  simp only [UScalarTy.Usize_numBits_eq] at *
  have hpos := Nat.two_pow_pos System.Platform.numBits
  have hlt : x.val < ((2 ^ System.Platform.numBits : Nat) : Int) := by omega
  rw [Int.emod_eq_of_lt hx (by simpa using hlt)]
  omega

theorem RealSlot_of (l : List isa.Insn) (t : Int) (k : Nat) (hk : (k : Int) = t)
    (hkl : k < l.length) (hnz : l[k].opcode.val ≠ 0) : RealSlot l t := by
  have h0 : 0 ≤ t := by omega
  have hkt : t.toNat = k := by omega
  refine ⟨h0, ?_⟩
  rw [hkt]
  exact ⟨hkl, hnz⟩

/-! ## Jumps and calls -/

theorem check_jump_ok {insns : Slice isa.Insn} {pc : Usize} {insn : isa.Insn}
    (hlen : insns.length < 2 ^ 63) (hpc : pc.val < 2 ^ 63)
    (h : validate.check_jump insns pc insn = ok (.Ok ())) :
    JumpOk insns.val pc.val insn := by
  unfold validate.check_jump at h
  dsimp only at h
  obtain ⟨disp, hd, h⟩ := bind_eq_ok h
  have hdisp : disp.val = jumpDisp insn := by
    unfold jumpDisp
    split at hd <;> rename_i hja <;> simp only [ok.injEq] at hd <;> subst hd
    · have h6 : insn.opcode.val = 6 := by
        simp only [isa.OP_JA32] at hja
        scalar_tac
      simp [h6]
    · have h6 : insn.opcode.val ≠ 6 := by
        intro h6
        apply hja
        simp only [isa.OP_JA32]
        scalar_tac
      simp [h6]
  split at h
  · simp at h
  · rename_i hne
    obtain ⟨i, hi, h⟩ := bind_eq_ok h
    simp only [lift, ok.injEq] at hi
    subst hi
    obtain ⟨i1, hi1, h⟩ := bind_eq_ok h
    obtain ⟨i2, hi2, h⟩ := bind_eq_ok h
    simp only [lift, ok.injEq] at hi2
    subst hi2
    obtain ⟨target, ht, h⟩ := bind_eq_ok h
    split at h
    · simp at h
    · rename_i hnn
      obtain ⟨i3, hi3, h⟩ := bind_eq_ok h
      simp only [lift, ok.injEq] at hi3
      subst hi3
      split at h
      · simp at h
      · rename_i hlt
        obtain ⟨i4, hi4, h⟩ := bind_eq_ok h
        simp only [lift, ok.injEq] at hi4
        subst hi4
        obtain ⟨i5, hidx, h⟩ := bind_eq_ok h
        obtain ⟨hb, rfl⟩ := index_usize_eq_ok hidx
        split at h
        · simp at h
        · rename_i hnz
          have h1 := i64_add_eq_ok hi1
          have h2 := i64_add_eq_ok ht
          rw [usize_hcast_i64_val pc hpc] at h1
          have hc2 : (IScalar.cast .I64 disp).val = disp.val := by simp
          rw [hc2] at h2
          have hlen' : (UScalar.hcast .I64 (Slice.len insns)).val = (insns.length : Int) := by
            rw [usize_hcast_i64_val]
            · simp
            · scalar_tac
          have hnn' : 0 ≤ target.val := by scalar_tac
          have hlt' : target.val < insns.length := by
            simp only [ge_iff_le] at hlt
            scalar_tac
          have hmax : target.val ≤ (Usize.max : Int) := by
            have := insns.property
            scalar_tac
          have hi4v := i64_hcast_usize_val target hnn' hmax
          refine ⟨?_, ?_⟩
          · rw [← hdisp]
            intro heq
            apply hne
            scalar_tac
          · unfold jumpTargetInt
            rw [← hdisp]
            refine RealSlot_of _ _ (IScalar.hcast .Usize target).val ?_ hb ?_
            · have h1v : (1#i64).val = 1 := by simp
              simp only [Int.ofNat_eq_natCast] at *
              omega
            scalar_tac

theorem check_call_kind_ok {config : validate.Config} {kh : Slice U32} {insn : isa.Insn}
    {insns : Slice isa.Insn} {pc : Usize} {cross : Bool}
    (hlen : insns.length < 2 ^ 63) (hpc : pc.val < 2 ^ 63)
    (h : validate.check_call_kind config kh insn insns pc cross = ok (.Ok ())) :
    CallOk insns.val pc.val insn := by
  unfold validate.check_call_kind at h
  dsimp only at h
  split at h
  · -- helper call
    rename_i h0
    have h0' : insn.src.val = 0 := by scalar_tac
    refine ⟨Or.inl h0', fun h1 => by omega⟩
  · rename_i hn0
    split at h
    · -- local call
      rename_i h1
      have h1' : insn.src.val = 1 := by scalar_tac
      obtain ⟨i, hi, h⟩ := bind_eq_ok h
      simp only [lift, ok.injEq] at hi
      subst hi
      obtain ⟨i1, hi1, h⟩ := bind_eq_ok h
      obtain ⟨i2, hi2, h⟩ := bind_eq_ok h
      simp only [lift, ok.injEq] at hi2
      subst hi2
      obtain ⟨target, ht, h⟩ := bind_eq_ok h
      split at h
      · simp at h
      · rename_i hnn
        obtain ⟨i3, hi3, h⟩ := bind_eq_ok h
        simp only [lift, ok.injEq] at hi3
        subst hi3
        split at h
        · simp at h
        · rename_i hlt
          obtain ⟨i4, hi4, h⟩ := bind_eq_ok h
          simp only [lift, ok.injEq] at hi4
          subst hi4
          obtain ⟨i5, hidx, h⟩ := bind_eq_ok h
          obtain ⟨hb, rfl⟩ := index_usize_eq_ok hidx
          split at h
          · simp at h
          · rename_i hnz
            have hA := i64_add_eq_ok hi1
            have hB := i64_add_eq_ok ht
            rw [usize_hcast_i64_val pc hpc] at hA
            have hc2 : (IScalar.cast .I64 insn.imm).val = insn.imm.val := by simp
            rw [hc2] at hB
            have hlen' : (UScalar.hcast .I64 (Slice.len insns)).val = (insns.length : Int) := by
              rw [usize_hcast_i64_val]
              · simp
              · scalar_tac
            have hnn' : 0 ≤ target.val := by scalar_tac
            have hlt' : target.val < insns.length := by
              simp only [ge_iff_le] at hlt
              scalar_tac
            have hmax : target.val ≤ (Usize.max : Int) := by
              have := insns.property
              scalar_tac
            have hi4v := i64_hcast_usize_val target hnn' hmax
            refine ⟨Or.inr (Or.inl h1'), fun _ => ?_⟩
            unfold callTargetInt
            refine RealSlot_of _ _ (IScalar.hcast .Usize target).val ?_ hb ?_
            · have h1v : (1#i64).val = 1 := by simp
              simp only [Int.ofNat_eq_natCast] at *
              omega
            scalar_tac
    · rename_i hn1
      split at h
      · rename_i h2
        have h2' : insn.src.val = 2 := by scalar_tac
        refine ⟨Or.inr (Or.inr h2'), fun h1 => by omega⟩
      · simp at h

theorem check_call_ok {config : validate.Config} {kh : Slice U32} {insn : isa.Insn}
    {insns : Slice isa.Insn} {pc : Usize} {cross : Bool}
    (hlen : insns.length < 2 ^ 63) (hpc : pc.val < 2 ^ 63)
    (h : validate.check_call config kh insn insns pc cross = ok (.Ok ())) :
    CallOk insns.val pc.val insn := by
  unfold validate.check_call at h
  repeat' split at h
  all_goals first
    | simp at h
    | exact check_call_kind_ok hlen hpc h

/-! ## The structural rule -/

theorem check_structure_ok {config : validate.Config} {kh : Slice U32} {insns : Slice isa.Insn}
    {ext : Slice Bool} {pc : Usize} {insn : isa.Insn} {op : isa.Op}
    (hlen : insns.length < 2 ^ 63) (hpc : pc.val < 2 ^ 63)
    (h : validate.check_structure config kh insns ext pc insn op = ok (.Ok ())) :
    StructureOk insns.val pc.val insn op := by
  unfold validate.check_structure at h
  dsimp only at h
  cases op with
  | LoadImm64 =>
    simp only at h
    split at h
    · simp at h
    · obtain ⟨i, hi, h⟩ := bind_eq_ok h
      have hiv := usize_add_eq_ok hi
      split at h
      · simp at h
      · rename_i hge
        obtain ⟨i1, hidx, h⟩ := bind_eq_ok h
        obtain ⟨hb, rfl⟩ := index_usize_eq_ok hidx
        split at h
        · simp at h
        · rename_i hz
          simp only [ge_iff_le] at hge
          have hb' : pc.val + 1 < insns.length := by scalar_tac
          have hiv' : i.val = pc.val + 1 := by scalar_tac
          refine ⟨hb', ?_⟩
          have hz' : insns.val[i.val].opcode.val = 0 := by scalar_tac
          simp only [hiv'] at hz'
          exact hz'
  | Ja w => exact check_jump_ok hlen hpc h
  | Jmp w o s => exact check_jump_ok hlen hpc h
  | Call =>
    simp only at h
    obtain ⟨cross, hc, h⟩ := bind_eq_ok h
    exact check_call_ok hlen hpc h
  | Alu w ao s => simp [StructureOk]
  | End k => simp [StructureOk]
  | Load w s => simp [StructureOk]
  | StoreImm w => simp [StructureOk]
  | StoreReg w => simp [StructureOk]
  | Atomic w o f => simp [StructureOk]
  | Exit => simp [StructureOk]

/-! ## The operand filter -/

theorem check_operand_filter_ok {insn : isa.Insn} {pc : Usize}
    (h : validate.check_operand_filter insn pc = ok (.Ok ())) :
    ∃ f, validate.filter_for insn.opcode = ok (some f) ∧
      insn.dst.val ≤ f.dst_hi.val ∧ insn.src.val ≤ f.src_hi.val := by
  unfold validate.check_operand_filter at h
  obtain ⟨o, hf, h⟩ := bind_eq_ok h
  cases o with
  | none => simp at h
  | some f =>
    simp only at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · rename_i hdst
        split at h
        · simp at h
        · split at h
          · simp at h
          · rename_i hsrc
            exact ⟨f, hf, by scalar_tac, by scalar_tac⟩

end async_ebpf_verified

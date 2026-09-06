import AsyncEbpf.Loop
import AsyncEbpf.Layout.Spec
import AsyncEbpf.Validate.Structure

/-!
# The layout code, read off the generated definitions

`partition_ok`: a `Layout` that `partition` returns is `LayoutOk`. One lemma
per generated function; the loops go through `loop_ok_induction` with an
invariant each.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

/-! ## Plumbing -/

/-- `obtain_bind ⟨a, ha, h⟩ := h` is `obtain_bind ⟨a, ha, h⟩ := h` with the
old `h` cleared, so that a long chain of binds does not pile up shadowed
copies of the whole loop body (which slow every `simp` and `scalar_tac`). -/
macro "obtain_bind" pat:Lean.Parser.Tactic.rcasesPatMed " := " h:ident : tactic =>
  `(tactic| (have h_bind_tmp := bind_eq_ok $h:ident
             clear $h:ident
             obtain $pat := h_bind_tmp))

theorem vec_index_usize_eq_ok {α : Type} {v : alloc.vec.Vec α} {i : Usize} {x : α}
    (h : alloc.vec.Vec.index_usize v i = ok x) : ∃ hi : i.val < v.length, x = v.val[i.val] := by
  unfold alloc.vec.Vec.index_usize at h
  rw [show v[i.val]? = v.val[i.val]? from rfl] at h
  split at h
  · simp at h
  · rename_i hget
    simp only [ok.injEq] at h
    subst h
    rw [List.getElem?_eq_some_iff] at hget
    obtain ⟨hi, hx⟩ := hget
    exact ⟨hi, hx.symm⟩

theorem vec_index_eq_ok {α : Type} {v : alloc.vec.Vec α} {i : Usize} {x : α}
    (h : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i = ok x) :
    ∃ hi : i.val < v.length, x = v.val[i.val] := by
  rw [alloc.vec.Vec.index_slice_index] at h
  exact vec_index_usize_eq_ok h

theorem vec_index_mut_eq_ok {α : Type} {v : alloc.vec.Vec α} {i : Usize} {x : α}
    {back : α → alloc.vec.Vec α}
    (h : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice α) v i = ok (x, back)) :
    ∃ hi : i.val < v.length, x = v.val[i.val] ∧ back = alloc.vec.Vec.set v i := by
  rw [alloc.vec.Vec.index_mut_slice_index] at h
  unfold alloc.vec.Vec.index_mut_usize at h
  split at h
  · rename_i y hy
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    obtain ⟨hi, rfl⟩ := vec_index_usize_eq_ok hy
    exact ⟨hi, rfl, rfl⟩
  · simp at h
  · simp at h

theorem vec_push_eq_ok {α : Type} {v v' : alloc.vec.Vec α} {x : α}
    (h : alloc.vec.Vec.push v x = ok v') : v'.val = v.val ++ [x] := by
  unfold alloc.vec.Vec.push at h
  dsimp only at h
  split at h
  · simp only [ok.injEq] at h
    subst h
    simp
  · simp at h

theorem from_elem_eq_ok {α : Type} {inst : core.clone.Clone α} {x : α} {n : Usize}
    {v : alloc.vec.Vec α} (hc : inst.clone x = ok x)
    (h : alloc.vec.from_elem inst x n = ok v) : v.val = List.replicate n.val x := by
  have := alloc.vec.from_elem_spec inst x n hc
  rw [h] at this
  exact this.1

theorem usize_sub_eq_ok {x y z : Usize} (h : x - y = ok z) : z.val = x.val - y.val ∧ y.val ≤ x.val := by
  have := UScalar.sub_equiv x y
  rw [h] at this
  obtain ⟨h1, h2, _⟩ := this
  constructor <;> omega

theorem usize_mul_eq_ok {x y z : Usize} (h : x * y = ok z) : z.val = x.val * y.val := by
  have := UScalar.mul_equiv x y
  have h' : UScalar.mul x y = ok z := h
  rw [h'] at this
  exact this.2.1

theorem usize_not_lt {x y : Usize} (h : ¬ x < y) : y.val ≤ x.val := by
  rw [UScalar.lt_equiv] at h; omega

theorem usize_not_ge {x y : Usize} (h : ¬ x ≥ y) : x.val < y.val := by
  simp only [ge_iff_le, UScalar.le_equiv] at h; omega

theorem usize_not_gt {x y : Usize} (h : ¬ x > y) : x.val ≤ y.val := by
  simp only [gt_iff_lt, UScalar.lt_equiv] at h; omega

theorem usize_ge {x y : Usize} (h : x ≥ y) : y.val ≤ x.val := by
  simp only [ge_iff_le, UScalar.le_equiv] at h; exact h

theorem usize_gt {x y : Usize} (h : x > y) : y.val < x.val := by
  simp only [gt_iff_lt, UScalar.lt_equiv] at h; exact h

/-! ## Targets -/

/-- `local_call_target` returns the call target when it is a slot number. -/
theorem local_call_target_ok {pc : Usize} {insn : isa.Insn} {n : Usize} {t : Usize}
    (hpc : pc.val < 2 ^ 63) (hn : n.val < 2 ^ 63)
    (h : layout.local_call_target pc insn n = ok (.Ok t)) :
    (t.val : Int) = callTargetInt insn pc.val ∧ t.val < n.val := by
  unfold layout.local_call_target at h
  obtain_bind ⟨i, hi, h⟩ := h
  simp only [lift, ok.injEq] at hi
  subst hi
  obtain_bind ⟨i1, hi1, h⟩ := h
  simp only [lift, ok.injEq] at hi1
  subst hi1
  obtain_bind ⟨i2, hi2, h⟩ := h
  obtain_bind ⟨target, ht, h⟩ := h
  split at h
  · simp at h
  · rename_i hnn
    obtain_bind ⟨i3, hi3, h⟩ := h
    simp only [lift, ok.injEq] at hi3
    subst hi3
    split at h
    · simp at h
    · rename_i hlt
      obtain_bind ⟨i4, hi4, h⟩ := h
      simp only [lift, ok.injEq] at hi4
      subst hi4
      simp only [ok.injEq, core.result.Result.Ok.injEq] at h
      subst h
      have hA := i64_add_eq_ok hi2
      have hB := i64_add_eq_ok ht
      rw [usize_hcast_i64_val pc hpc] at hA
      have hc : (IScalar.cast .I64 insn.imm).val = insn.imm.val := by simp
      rw [hc] at hA
      have hn' : (UScalar.hcast .I64 n).val = (n.val : Int) := usize_hcast_i64_val n hn
      have hnn' : 0 ≤ target.val := by scalar_tac
      have hlt' : target.val < n.val := by
        simp only [ge_iff_le] at hlt
        scalar_tac
      have hmax : target.val ≤ (Usize.max : Int) := by scalar_tac
      have hv := i64_hcast_usize_val target hnn' hmax
      have h1v : (1#i64).val = 1 := by simp
      unfold callTargetInt
      simp only [Int.ofNat_eq_natCast] at *
      constructor <;> omega

/-- `jump_target` returns `pc + displacement + 1` when it is a slot number. -/
theorem jump_target_ok {pc : Usize} {disp : I64} {n : Usize} {t : Usize}
    (hpc : pc.val < 2 ^ 63) (hn : n.val < 2 ^ 63)
    (h : layout.jump_target pc disp n = ok (.Ok t)) :
    (t.val : Int) = Int.ofNat (pc.val + 1) + disp.val ∧ t.val < n.val := by
  unfold layout.jump_target at h
  obtain_bind ⟨i, hi, h⟩ := h
  simp only [lift, ok.injEq] at hi
  subst hi
  obtain_bind ⟨i1, hi1, h⟩ := h
  obtain_bind ⟨target, ht, h⟩ := h
  split at h
  · simp at h
  · rename_i hnn
    obtain_bind ⟨i2, hi2, h⟩ := h
    simp only [lift, ok.injEq] at hi2
    subst hi2
    split at h
    · simp at h
    · rename_i hlt
      obtain_bind ⟨i3, hi3, h⟩ := h
      simp only [lift, ok.injEq] at hi3
      subst hi3
      simp only [ok.injEq, core.result.Result.Ok.injEq] at h
      subst h
      have hA := i64_add_eq_ok hi1
      have hB := i64_add_eq_ok ht
      rw [usize_hcast_i64_val pc hpc] at hA
      have hn' : (UScalar.hcast .I64 n).val = (n.val : Int) := usize_hcast_i64_val n hn
      have hnn' : 0 ≤ target.val := by scalar_tac
      have hlt' : target.val < n.val := by
        simp only [ge_iff_le] at hlt
        scalar_tac
      have hmax : target.val ≤ (Usize.max : Int) := by scalar_tac
      have hv := i64_hcast_usize_val target hnn' hmax
      have h1v : (1#i64).val = 1 := by simp
      simp only [Int.ofNat_eq_natCast] at *
      constructor <;> omega

theorem check_in_range_ok {pc t start «end» : Usize} {jump : Bool}
    (h : layout.check_in_range pc t start «end» jump = ok (.Ok ())) :
    start.val ≤ t.val ∧ t.val < «end».val := by
  unfold layout.check_in_range at h
  split at h
  · split at h <;> simp at h
  · split at h
    · split at h <;> simp at h
    · rename_i h1 h2
      simp only [ge_iff_le] at h2
      constructor <;> scalar_tac


/-- After `obtain_bind ⟨cf, hbr, h⟩ := h` on a `?`: the `Err` arm never
yields `Ok`, so only the `Ok` arm, binding its value to `v`, is left. In a
loop body the `Err` arm ends in `done (Err e, …)`; then `h` is substituted and
the goal is expected to close by `simp`. -/
macro "try_ok" r:ident hbr:ident h:ident "with" v:ident : tactic => `(tactic|
  (rcases $r:ident with $v:ident | e
   rotate_left
   · rw [branch_Err] at $hbr:ident
     simp only [ok.injEq] at $hbr:ident
     subst $hbr:ident
     simp only at $h:ident
     first
       | exact absurd $h:ident (from_residual_ne_ok _ _)
       | (obtain ⟨r_err, hres, $h:ident⟩ := bind_eq_ok $h:ident
          rw [from_residual_Err] at hres
          simp only [ok.injEq] at hres
          subst hres
          simp only [ok.injEq] at $h:ident
          subst $h:ident
          intro hres; cases hres)
   rw [branch_Ok] at $hbr:ident
   simp only [ok.injEq] at $hbr:ident
   subst $hbr:ident
   simp only at $h:ident))

/-! ## Successors -/

/-- The successor list `successors` reports: `count` of `first`, `second`. -/
def succList (count first second : Usize) : List Nat :=
  if count.val = 0 then [] else if count.val = 1 then [first.val] else [first.val, second.val]

theorem successors_ok {insns : Slice isa.Insn} {pc : Usize} {is_start : Slice Bool}
    {count first : Usize} {jump : Bool} {second : Usize}
    (hlen : insns.length < 2 ^ 63)
    (h : layout.successors insns pc is_start = ok (.Ok (count, first, jump, second))) :
    ∃ hpc : pc.val < insns.length,
      succList count first second = succB insns.val pc.val ∧
      (IsLocalCall insns.val[pc.val] →
        ∃ t : Nat, callTargetInt insns.val[pc.val] pc.val = (t : Int) ∧
          is_start.val[t]? = some true) := by
  unfold layout.successors at h
  obtain_bind ⟨insn, hidx, h⟩ := h
  obtain ⟨hpc, rfl⟩ := index_usize_eq_ok hidx
  refine ⟨hpc, ?_⟩
  have hpc' : pc.val < 2 ^ 63 := by omega
  have hlen' : (Slice.len insns).val < 2 ^ 63 := by simp only [Slice.len_val]; exact hlen
  have hsucc : succB insns.val pc.val =
      (byteEdges insns.val[pc.val].opcode).map (edgeTarget insns.val[pc.val] pc.val) := by
    simp [succB, List.getElem?_eq_getElem hpc]
  rw [hsucc]
  generalize insns.val[pc.val] = insn at h ⊢
  split at h
  · -- exit
    rename_i hexit
    simp only [ok.injEq, core.result.Result.Ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl, rfl, rfl⟩ := h
    refine ⟨by rw [byteEdges, if_pos hexit]; simp [succList], fun hc => ?_⟩
    have := hc.1
    rw [hexit] at this
    simp only [isa.OP_EXIT, isa.OP_CALL] at this
    scalar_tac
  · rename_i hnexit
    split at h
    · rename_i hcall
      split at h
      · -- local call
        rename_i hsrc
        obtain_bind ⟨r, hr, h⟩ := h
        obtain_bind ⟨cf, hbr, h⟩ := h
        try_ok r hbr h with t
        obtain_bind ⟨b, hb, h⟩ := h
        obtain ⟨hbt, rfl⟩ := index_usize_eq_ok hb
        split at h
        · rename_i htrue
          obtain_bind ⟨i, hi, h⟩ := h
          have hiv := usize_add_eq_ok hi
          simp only [ok.injEq, core.result.Result.Ok.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl, rfl, rfl⟩ := h
          obtain ⟨ht, _⟩ := local_call_target_ok hpc' hlen' hr
          refine ⟨by rw [byteEdges, if_neg hnexit, if_pos hcall]; simp [succList, hiv, edgeTarget],
            fun _ => ⟨t.val, ht.symm, ?_⟩⟩
          rw [List.getElem?_eq_getElem hbt]
          simp [htrue]
        · simp at h
      · -- helper or cross-section call
        rename_i hsrc
        obtain_bind ⟨i, hi, h⟩ := h
        have hiv := usize_add_eq_ok hi
        simp only [ok.injEq, core.result.Result.Ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl, rfl, rfl⟩ := h
        refine ⟨by rw [byteEdges, if_neg hnexit, if_pos hcall]; simp [succList, hiv, edgeTarget],
          fun hc => ?_⟩
        have := hc.2
        exact absurd (UScalar.eq_of_val_eq (by simp [this])) hsrc
    · rename_i hncall
      split at h
      · -- lddw
        rename_i hlddw
        obtain_bind ⟨i, hi, h⟩ := h
        have hiv := usize_add_eq_ok hi
        simp only [ok.injEq, core.result.Result.Ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl, rfl, rfl⟩ := h
        exact ⟨by rw [byteEdges, if_neg hnexit, if_neg hncall, if_pos hlddw]; simp [succList, hiv, edgeTarget],
          fun hc => absurd hc.1 hncall⟩
      · rename_i hnlddw
        obtain_bind ⟨cls, hcls, h⟩ := h
        simp only [lift, ok.injEq] at hcls
        subst hcls
        -- The rest never is a local call.
        suffices hs : succList count first second =
            (byteEdges insn.opcode).map (edgeTarget insn pc.val) from
          ⟨hs, fun hc => absurd hc.1 hncall⟩
        -- One unconditional jump arm, for `ja` (displacement in `offset`).
        have ja_arm : ∀ {count first : Usize} {jump : Bool} {second : Usize},
            insn.opcode.val ≠ 6 →
            (do
              let i ← lift (IScalar.cast .I64 insn.offset)
              let r ← layout.jump_target pc i (Slice.len insns)
              let cf ← core.result.Result.Insts.CoreOpsTry.branch r
              match cf with
              | core.ops.control_flow.ControlFlow.Continue val =>
                ok (core.result.Result.Ok (1#usize, val, true, 0#usize))
              | core.ops.control_flow.ControlFlow.Break residual =>
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
                  (Std.Usize × Std.Usize × Bool × Std.Usize)
                  (core.convert.FromSame layout.LayoutReject) residual) =
              ok (.Ok (count, first, jump, second)) →
            succList count first second = [(jumpTargetInt insn pc.val).toNat] := by
          intro count first jump second h6 h
          obtain_bind ⟨d, hd, h⟩ := h
          simp only [lift, ok.injEq] at hd
          subst hd
          obtain_bind ⟨r, hr, h⟩ := h
          obtain_bind ⟨cf, hbr, h⟩ := h
          try_ok r hbr h with t
          simp only [ok.injEq, core.result.Result.Ok.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl, rfl, rfl⟩ := h
          obtain ⟨ht, _⟩ := jump_target_ok hpc' hlen' hr
          simp only [succList, jumpTargetInt, jumpDisp, h6, if_false]
          simp at ht
          simp only [Int.ofNat_eq_natCast] at *
          simp
          omega
        -- `ja32` (displacement in `imm`).
        have ja32_arm : ∀ {count first : Usize} {jump : Bool} {second : Usize},
            insn.opcode.val = 6 →
            (do
              let i ← lift (IScalar.cast .I64 insn.imm)
              let r ← layout.jump_target pc i (Slice.len insns)
              let cf ← core.result.Result.Insts.CoreOpsTry.branch r
              match cf with
              | core.ops.control_flow.ControlFlow.Continue val =>
                ok (core.result.Result.Ok (1#usize, val, true, 0#usize))
              | core.ops.control_flow.ControlFlow.Break residual =>
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
                  (Std.Usize × Std.Usize × Bool × Std.Usize)
                  (core.convert.FromSame layout.LayoutReject) residual) =
              ok (.Ok (count, first, jump, second)) →
            succList count first second = [(jumpTargetInt insn pc.val).toNat] := by
          intro count first jump second h6 h
          obtain_bind ⟨d, hd, h⟩ := h
          simp only [lift, ok.injEq] at hd
          subst hd
          obtain_bind ⟨r, hr, h⟩ := h
          obtain_bind ⟨cf, hbr, h⟩ := h
          try_ok r hbr h with t
          simp only [ok.injEq, core.result.Result.Ok.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl, rfl, rfl⟩ := h
          obtain ⟨ht, _⟩ := jump_target_ok hpc' hlen' hr
          simp only [succList, jumpTargetInt, jumpDisp, h6, if_true]
          simp at ht
          simp only [Int.ofNat_eq_natCast] at *
          simp
          omega
        -- A conditional jump (displacement in `offset`, may fall through).
        have cond_arm : ∀ {count first : Usize} {jump : Bool} {second : Usize},
            insn.opcode.val ≠ 6 →
            (do
              let i ← lift (IScalar.cast .I64 insn.offset)
              let r ← layout.jump_target pc i (Slice.len insns)
              let cf ← core.result.Result.Insts.CoreOpsTry.branch r
              match cf with
              | core.ops.control_flow.ControlFlow.Continue val =>
                let i1 ← pc + 1#usize
                ok (core.result.Result.Ok (2#usize, val, true, i1))
              | core.ops.control_flow.ControlFlow.Break residual =>
                core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
                  (Std.Usize × Std.Usize × Bool × Std.Usize)
                  (core.convert.FromSame layout.LayoutReject) residual) =
              ok (.Ok (count, first, jump, second)) →
            succList count first second = [(jumpTargetInt insn pc.val).toNat, pc.val + 1] := by
          intro count first jump second h6 h
          obtain_bind ⟨d, hd, h⟩ := h
          simp only [lift, ok.injEq] at hd
          subst hd
          obtain_bind ⟨r, hr, h⟩ := h
          obtain_bind ⟨cf, hbr, h⟩ := h
          try_ok r hbr h with t
          obtain_bind ⟨i1, hi1, h⟩ := h
          have hi1v := usize_add_eq_ok hi1
          simp only [ok.injEq, core.result.Result.Ok.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl, rfl, rfl⟩ := h
          obtain ⟨ht, _⟩ := jump_target_ok hpc' hlen' hr
          simp only [succList, jumpTargetInt, jumpDisp, h6, if_false]
          simp at ht
          simp only [Int.ofNat_eq_natCast] at *
          simp at hi1v
          simp
          constructor <;> omega
        have hja32_6 : insn.opcode = isa.OP_JA32 → insn.opcode.val = 6 := by
          intro h6; simp only [isa.OP_JA32] at h6; scalar_tac
        have hnja32_6 : ¬ insn.opcode = isa.OP_JA32 → insn.opcode.val ≠ 6 := by
          intro hn h6; apply hn; simp only [isa.OP_JA32]; scalar_tac
        have hja_ne6 : insn.opcode = isa.OP_JA → insn.opcode.val ≠ 6 := by
          intro h5; simp only [isa.OP_JA] at h5; scalar_tac
        split at h
        · rename_i hjmp
          split at h
          · rename_i hja
            rw [ja_arm (hja_ne6 hja) h, byteEdges, if_neg hnexit, if_neg hncall, if_neg hnlddw,
              if_pos (Or.inl hjmp), if_pos (Or.inl hja)]
            simp [edgeTarget]
          · rename_i hnja
            split at h
            · rename_i hja32
              rw [ja32_arm (hja32_6 hja32) h, byteEdges, if_neg hnexit, if_neg hncall, if_neg hnlddw,
                if_pos (Or.inl hjmp), if_pos (Or.inr hja32)]
              simp [edgeTarget]
            · rename_i hnja32
              rw [cond_arm (hnja32_6 hnja32) h, byteEdges, if_neg hnexit, if_neg hncall, if_neg hnlddw,
                if_pos (Or.inl hjmp), if_neg (not_or.mpr ⟨hnja, hnja32⟩)]
              simp [edgeTarget]
        · rename_i hnjmp
          split at h
          · rename_i hjmp32
            split at h
            · rename_i hja
              rw [ja_arm (hja_ne6 hja) h, byteEdges, if_neg hnexit, if_neg hncall, if_neg hnlddw,
                if_pos (Or.inr hjmp32), if_pos (Or.inl hja)]
              simp [edgeTarget]
            · rename_i hnja
              split at h
              · rename_i hja32
                rw [ja32_arm (hja32_6 hja32) h, byteEdges, if_neg hnexit, if_neg hncall, if_neg hnlddw,
                  if_pos (Or.inr hjmp32), if_pos (Or.inr hja32)]
                simp [edgeTarget]
              · rename_i hnja32
                rw [cond_arm (hnja32_6 hnja32) h, byteEdges, if_neg hnexit, if_neg hncall, if_neg hnlddw,
                  if_pos (Or.inr hjmp32), if_neg (not_or.mpr ⟨hnja, hnja32⟩)]
                simp [edgeTarget]
          · rename_i hnjmp32
            obtain_bind ⟨i, hi, h⟩ := h
            have hiv := usize_add_eq_ok hi
            simp only [ok.injEq, core.result.Result.Ok.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, rfl, rfl, rfl⟩ := h
            rw [byteEdges, if_neg hnexit, if_neg hncall, if_neg hnlddw, if_neg (not_or.mpr ⟨hnjmp, hnjmp32⟩)]
            simp [succList, hiv, edgeTarget]

end async_ebpf_verified

namespace async_ebpf_verified

/-! ## The walk of one function -/

/-- Slot `q` is on the worklist: at some index below `top`. -/
def Pending (p : List Usize) (top q : Nat) : Prop :=
  ∃ k, k < top ∧ ∃ h : k < p.length, p[k].val = q

theorem Pending.push {p : List Usize} {top : Nat} {x : Usize} {q : Nat}
    (h : Pending p top q) : Pending (p.set top x) (top + 1) q := by
  obtain ⟨k, hk, hkp, hq⟩ := h
  refine ⟨k, by omega, by simp; exact hkp, ?_⟩
  rw [List.getElem_set_ne (by omega)]
  exact hq

theorem Pending.top {p : List Usize} {top : Nat} {x : Usize} (htop : top < p.length) :
    Pending (p.set top x) (top + 1) x.val :=
  ⟨top, by omega, by simp; exact htop, by rw [List.getElem_set_self]⟩

theorem Pending.pop {p : List Usize} {top q : Nat} (h : Pending p (top + 1) q) :
    Pending p top q ∨ ∃ h : top < p.length, p[top].val = q := by
  obtain ⟨k, hk, hkp, hq⟩ := h
  by_cases hlt : k < top
  · exact Or.inl ⟨k, hlt, hkp, hq⟩
  · have : k = top := by omega
    subst this
    exact Or.inr ⟨hkp, hq⟩

/-- `r[pc] = true`, for a `Vec Bool`. -/
def Marked (r : List Bool) (pc : Nat) : Prop := r[pc]? = some true

theorem Marked.set_self {r : List Bool} {pc : Nat} (h : pc < r.length) :
    Marked (r.set pc true) pc := by
  simp [Marked, List.getElem?_set_self h]

theorem Marked.set_of {r : List Bool} {pc q : Nat} (h : Marked r q) :
    Marked (r.set pc true) q := by
  by_cases hq : pc = q
  · subst hq
    have := List.getElem?_eq_some_iff.mp h |>.1
    exact Marked.set_self this
  · simpa [Marked, List.getElem?_set_ne hq] using h

theorem Marked.of_set {r : List Bool} {pc q : Nat} (h : Marked (r.set pc true) q) :
    Marked r q ∨ q = pc := by
  by_cases hq : pc = q
  · exact Or.inr hq.symm
  · left
    simpa [Marked, List.getElem?_set_ne hq] using h

/-- The invariant of `scan_function`'s loop, relative to the section, the
function `[start, end)`, and the `reachable` it started from. -/
structure ScanInv (insns : List isa.Insn) (is_start : List Bool) (start «end» : Nat)
    (r0 : List Bool) (r : List Bool) (p : List Usize) (top : Nat) : Prop where
  len : r.length = r0.length
  /-- Slots outside the function are untouched. -/
  frame : ∀ pc, ¬ (start ≤ pc ∧ pc < «end») → r[pc]? = r0[pc]?
  /-- The start is marked, or still on the worklist. -/
  start_ok : Marked r start ∨ Pending p top start
  /-- Every successor of a marked slot is in the function and marked or on
  the worklist. -/
  closed : ∀ pc, start ≤ pc → pc < «end» → Marked r pc →
    ∀ q ∈ succB insns pc, start ≤ q ∧ q < «end» ∧ (Marked r q ∨ Pending p top q)
  /-- A local call on a marked slot targets a function start. -/
  calls : ∀ pc, start ≤ pc → pc < «end» → Marked r pc →
    ∀ h : pc < insns.length, IsLocalCall insns[pc] →
      ∃ t : Nat, callTargetInt insns[pc] pc = (t : Int) ∧ is_start[t]? = some true

/-- What `scan_function` establishes once the worklist is empty. -/
structure ScanPost (insns : List isa.Insn) (is_start : List Bool) (start «end» : Nat)
    (r0 : List Bool) (r : List Bool) : Prop where
  len : r.length = r0.length
  frame : ∀ pc, ¬ (start ≤ pc ∧ pc < «end») → r[pc]? = r0[pc]?
  start_ok : Marked r start
  closed : ∀ pc, start ≤ pc → pc < «end» → Marked r pc →
    ∀ q ∈ succB insns pc, start ≤ q ∧ q < «end» ∧ Marked r q
  calls : ∀ pc, start ≤ pc → pc < «end» → Marked r pc →
    ∀ h : pc < insns.length, IsLocalCall insns[pc] →
      ∃ t : Nat, callTargetInt insns[pc] pc = (t : Int) ∧ is_start[t]? = some true

theorem ScanInv.done {insns : List isa.Insn} {is_start : List Bool} {start «end» : Nat}
    {r0 r : List Bool} {p : List Usize}
    (h : ScanInv insns is_start start «end» r0 r p 0) :
    ScanPost insns is_start start «end» r0 r := by
  have nopend : ∀ q, ¬ Pending p 0 q := by
    rintro q ⟨k, hk, _⟩
    omega
  refine ⟨h.len, h.frame, ?_, ?_, h.calls⟩
  · rcases h.start_ok with hm | hp
    · exact hm
    · exact absurd hp (nopend _)
  · intro pc h1 h2 hm q hq
    obtain ⟨hq1, hq2, hq3⟩ := h.closed pc h1 h2 hm q hq
    refine ⟨hq1, hq2, ?_⟩
    rcases hq3 with hm' | hp
    · exact hm'
    · exact absurd hp (nopend _)

/-- Popping a slot that is already marked. -/
theorem ScanInv.pop_marked {insns : List isa.Insn} {is_start : List Bool} {start «end» : Nat}
    {r0 r : List Bool} {p : List Usize} {top : Nat}
    (h : ScanInv insns is_start start «end» r0 r p (top + 1))
    {htop : top < p.length} (hm : Marked r p[top].val) :
    ScanInv insns is_start start «end» r0 r p top := by
  refine ⟨h.len, h.frame, ?_, ?_, h.calls⟩
  · rcases h.start_ok with hs | hp
    · exact Or.inl hs
    · rcases hp.pop with hp' | ⟨_, heq⟩
      · exact Or.inr hp'
      · rw [heq] at hm; exact Or.inl hm
  · intro pc h1 h2 hmpc q hq
    obtain ⟨hq1, hq2, hq3⟩ := h.closed pc h1 h2 hmpc q hq
    refine ⟨hq1, hq2, ?_⟩
    rcases hq3 with hm' | hp
    · exact Or.inl hm'
    · rcases hp.pop with hp' | ⟨_, heq⟩
      · exact Or.inr hp'
      · rw [heq] at hm; exact Or.inl hm

/-- Popping an unmarked slot `pc` of the function, marking it, and pushing
its successors `succs` (which have been checked to be in the function) in
place of it. `p'`/`top'` is the worklist after the pushes. -/
theorem ScanInv.expand {insns : List isa.Insn} {is_start : List Bool} {start «end» : Nat}
    {r0 r : List Bool} {p p' : List Usize} {top top' : Nat}
    (h : ScanInv insns is_start start «end» r0 r p (top + 1))
    (htop : top < p.length) (pc : Nat) (hpc : p[top].val = pc)
    (h1 : start ≤ pc) (h2 : pc < «end») (hpcr : pc < r.length)
    (hsucc : ∀ q ∈ succB insns pc, start ≤ q ∧ q < «end» ∧ Pending p' top' q)
    (hkeep : ∀ q, Pending p top q → Pending p' top' q)
    (hcall : ∀ h : pc < insns.length, IsLocalCall insns[pc] →
      ∃ t : Nat, callTargetInt insns[pc] pc = (t : Int) ∧ is_start[t]? = some true) :
    ScanInv insns is_start start «end» r0 (r.set pc true) p' top' := by
  refine ⟨by simp [h.len], ?_, ?_, ?_, ?_⟩
  · intro q hq
    rw [List.getElem?_set_ne (by omega)]
    exact h.frame q hq
  · rcases h.start_ok with hs | hp
    · exact Or.inl (hs.set_of)
    · rcases hp.pop with hp' | ⟨_, heq⟩
      · exact Or.inr (hkeep _ hp')
      · rw [heq.symm.trans hpc]; exact Or.inl (Marked.set_self hpcr)
  · intro pc' h1' h2' hm q hq
    rcases hm.of_set with hm' | rfl
    · obtain ⟨hq1, hq2, hq3⟩ := h.closed pc' h1' h2' hm' q hq
      refine ⟨hq1, hq2, ?_⟩
      rcases hq3 with hmq | hp
      · exact Or.inl hmq.set_of
      · rcases hp.pop with hp' | ⟨_, heq⟩
        · exact Or.inr (hkeep _ hp')
        · rw [heq.symm.trans hpc]; exact Or.inl (Marked.set_self hpcr)
    · obtain ⟨hq1, hq2, hq3⟩ := hsucc q hq
      exact ⟨hq1, hq2, Or.inr hq3⟩
  · intro pc' h1' h2' hm hlt hc
    rcases hm.of_set with hm' | rfl
    · exact h.calls pc' h1' h2' hm' hlt hc
    · exact hcall hlt hc

/-- What one iteration of the walk must establish, by how it ends. -/
def ScanStepPost (insns : List isa.Insn) (is_start : List Bool) (start «end» : Nat)
    (r0 : List Bool)
    (res : ControlFlow (alloc.vec.Vec Bool × alloc.vec.Vec Usize × Usize)
      (core.result.Result Unit layout.LayoutReject × alloc.vec.Vec Bool × alloc.vec.Vec Usize)) :
    Prop :=
  match res with
  | .cont x => ScanInv insns is_start start «end» r0 x.1.val x.2.1.val x.2.2.val
  | .done y => y.1 = .Ok () → ScanPost insns is_start start «end» r0 y.2.1.val

/-- One iteration of the walk preserves `ScanInv`, and ends only with the
worklist empty. -/
theorem scan_function_step {insns : Slice isa.Insn} {start «end» : Usize} {is_start : Slice Bool}
    (hlen : insns.length < 2 ^ 63) (r0 : List Bool)
    (r : alloc.vec.Vec Bool) (p : alloc.vec.Vec Usize) (top : Usize)
    (hinv : ScanInv insns.val is_start.val start.val «end».val r0 r.val p.val top.val)
    (res : ControlFlow (alloc.vec.Vec Bool × alloc.vec.Vec Usize × Usize)
      (core.result.Result Unit layout.LayoutReject × alloc.vec.Vec Bool × alloc.vec.Vec Usize))
    (hb : layout.scan_function_loop.body insns start «end» is_start r p top = ok res) :
    ScanStepPost insns.val is_start.val start.val «end».val r0 res := by
  unfold layout.scan_function_loop.body at hb
  split at hb
  · rename_i htop
    obtain_bind ⟨top1, hsub, hb⟩ := hb
    obtain ⟨htop1, _⟩ := usize_sub_eq_ok hsub
    have htv : top.val = top1.val + 1 := by
      have := usize_gt htop
      simp at this
      have h1v : (1#usize).val = 1 := by simp
      omega
    rw [htv] at hinv
    obtain_bind ⟨pc, hidx, hb⟩ := hb
    obtain ⟨hpcp, hpc⟩ := vec_index_eq_ok hidx
    clear hidx
    split at hb
    · simp only [ok.injEq] at hb; subst hb; intro hres; cases hres
    rename_i hge
    split at hb
    · simp only [ok.injEq] at hb; subst hb; intro hres; cases hres
    rename_i hlt
    have h1 : start.val ≤ pc.val := usize_not_lt hge
    have h2 : pc.val < «end».val := usize_not_ge hlt
    obtain_bind ⟨b, hbidx, hb⟩ := hb
    obtain ⟨hpcr, rfl⟩ := vec_index_eq_ok hbidx
    split at hb
    · -- already marked: pop
      rename_i hm
      simp only [ok.injEq] at hb
      subst hb
      unfold ScanStepPost
      apply hinv.pop_marked (htop := hpcp)
      rw [← hpc]
      simp [Marked, List.getElem?_eq_getElem hpcr, hm]
    · rename_i hnm
      obtain ⟨⟨_, back⟩, hmut, hb⟩ := bind_eq_ok hb
      try simp only at hb
      obtain ⟨_, _, rfl⟩ := vec_index_mut_eq_ok hmut
      obtain_bind ⟨sr, hsucc, hb⟩ := hb
      obtain_bind ⟨cf, hbr, hb⟩ := hb
      try_ok sr hbr hb with val
      obtain ⟨count, first, fij, second⟩ := val
      change (if count ≥ 1#usize then _ else _) = ok res at hb
      obtain ⟨hpc_lt, hsl, hcalls⟩ := successors_ok hlen hsucc
      have hcall : ∀ h : pc.val < insns.length, IsLocalCall insns.val[pc.val] →
          ∃ t : Nat, callTargetInt insns.val[pc.val] pc.val = (t : Int) ∧
            is_start.val[t]? = some true := fun _ hc => hcalls hc
      split at hb
      · rename_i hc1
        obtain_bind ⟨r1, hcir, hb⟩ := hb
        obtain_bind ⟨cf1, hbr1, hb⟩ := hb
        try_ok r1 hbr1 hb with u
        obtain ⟨hf1, hf2⟩ := check_in_range_ok hcir
        obtain ⟨⟨_, back1⟩, hmut1, hb⟩ := bind_eq_ok hb
        try simp only at hb
        obtain ⟨htop1p, _, rfl⟩ := vec_index_mut_eq_ok hmut1
        obtain_bind ⟨top2, hadd2, hb⟩ := hb
        have htop2 := usize_add_eq_ok hadd2
        simp at htop2
        split at hb
        · rename_i hc2
          obtain_bind ⟨r2, hcir2, hb⟩ := hb
          obtain_bind ⟨cf2, hbr2, hb⟩ := hb
          try_ok r2 hbr2 hb with u2
          obtain ⟨hs1, hs2⟩ := check_in_range_ok hcir2
          obtain ⟨⟨_, back2⟩, hmut2, hb⟩ := bind_eq_ok hb
          try simp only at hb
          obtain ⟨htop2p, _, rfl⟩ := vec_index_mut_eq_ok hmut2
          obtain_bind ⟨top3, hadd3, hb⟩ := hb
          have htop3 := usize_add_eq_ok hadd3
          simp at htop3
          simp only [ok.injEq] at hb
          subst hb
          unfold ScanStepPost
          simp only [alloc.vec.Vec.set_val_eq]
          simp only [alloc.vec.Vec.set_val_eq, alloc.vec.Vec.length, List.length_set] at htop2p
          rw [htop3, htop2]
          have hc2' : 2 ≤ count.val := by have := usize_ge hc2; simpa using this
          refine hinv.expand hpcp pc.val (by rw [hpc]) h1 h2 hpcr ?_ ?_ hcall
          · intro q hq
            rw [← hsl] at hq
            simp only [succList, if_neg (by omega : ¬ count.val = 0),
              if_neg (by omega : ¬ count.val = 1), List.mem_cons,
              List.not_mem_nil, or_false] at hq
            rcases hq with rfl | rfl
            · exact ⟨hf1, hf2, (Pending.top htop1p).push⟩
            · exact ⟨hs1, hs2, Pending.top (by simp; omega)⟩
          · intro q hq
            exact hq.push.push
        · rename_i hc2
          simp only [ok.injEq] at hb
          subst hb
          unfold ScanStepPost
          simp only [alloc.vec.Vec.set_val_eq]
          rw [htop2]
          have hc1' : 1 ≤ count.val := by have := usize_ge hc1; simpa using this
          have hc2' : count.val < 2 := by have := usize_not_ge hc2; simpa using this
          refine hinv.expand hpcp pc.val (by rw [hpc]) h1 h2 hpcr ?_ ?_ hcall
          · intro q hq
            rw [← hsl] at hq
            simp only [succList, if_neg (by omega : ¬ count.val = 0),
              if_pos (by omega : count.val = 1), List.mem_singleton] at hq
            subst hq
            exact ⟨hf1, hf2, Pending.top htop1p⟩
          · intro q hq
            exact hq.push
      · rename_i hc1
        split at hb
        · rename_i hc2
          exfalso
          have : count.val < 1 := by have := usize_not_ge hc1; simpa using this
          have : 2 ≤ count.val := by have := usize_ge hc2; simpa using this
          omega
        · simp only [ok.injEq] at hb
          subst hb
          unfold ScanStepPost
          simp only [alloc.vec.Vec.set_val_eq]
          have hc0 : count.val = 0 := by
            have : count.val < 1 := by have := usize_not_ge hc1; simpa using this
            omega
          refine hinv.expand hpcp pc.val (by rw [hpc]) h1 h2 hpcr ?_ (fun _ hq => hq) hcall
          intro q hq
          rw [← hsl] at hq
          simp [succList, hc0] at hq
  · rename_i htop
    simp only [ok.injEq] at hb
    subst hb
    unfold ScanStepPost
    intro _
    have h0 : top.val = 0 := by have := usize_not_gt htop; simp at this; omega
    rw [h0] at hinv
    exact hinv.done

/-- The walk of one function: from a `reachable` with nothing of the
function marked, it marks the start and a set closed under successors
inside the function, touching nothing outside it. -/
theorem scan_function_ok {insns : Slice isa.Insn} {start «end» : Usize} {is_start : Slice Bool}
    {r : alloc.vec.Vec Bool} {p : alloc.vec.Vec Usize} {r' : alloc.vec.Vec Bool}
    {p' : alloc.vec.Vec Usize} (hlen : insns.length < 2 ^ 63)
    (hfresh : ∀ pc, start.val ≤ pc → pc < «end».val → ¬ Marked r.val pc)
    (h : layout.scan_function insns start «end» is_start r p = ok (.Ok (), r', p')) :
    ScanPost insns.val is_start.val start.val «end».val r.val r'.val := by
  unfold layout.scan_function at h
  obtain ⟨⟨_, back⟩, hmut, h⟩ := bind_eq_ok h
  simp only at h
  obtain ⟨h0p, _, rfl⟩ := vec_index_mut_eq_ok hmut
  unfold layout.scan_function_loop at h
  have hinit : ScanInv insns.val is_start.val start.val «end».val r.val r.val
      (alloc.vec.Vec.set p 0#usize start).val (1#usize).val := by
    simp only [alloc.vec.Vec.set_val_eq]
    refine ⟨rfl, fun _ _ => rfl, Or.inr ?_, ?_, ?_⟩
    · have := Pending.top (x := start) h0p
      simpa using this
    · intro pc h1 h2 hm
      exact absurd hm (hfresh pc h1 h2)
    · intro pc h1 h2 hm
      exact absurd hm (hfresh pc h1 h2)
  exact loop_ok_induction _
    (fun x => ScanInv insns.val is_start.val start.val «end».val r.val x.1.val x.2.1.val x.2.2.val)
    (fun y => y.1 = .Ok () → ScanPost insns.val is_start.val start.val «end».val r.val y.2.1.val)
    (by
      rintro ⟨r1, p1, top1⟩ hinv res hb
      have := scan_function_step hlen r.val r1 p1 top1 hinv res hb
      cases res <;> exact this)
    _ _ hinit h rfl

end async_ebpf_verified

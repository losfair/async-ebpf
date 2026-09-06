import AsyncEbpf.Layout.Proofs

/-!
# The guest stack's frame geometry

`src/verified/stack.rs` holds the four pieces of arithmetic the guarded
guest stack rests on: where the entry frame pointer starts
(`root_frame_offset`), the lowest frame pointer a local call may be made
from (`local_call_floor`), the runtime's test for an address range lying in
a mapped island (`island_access`), and the region analysis' test for an
`R10`-relative access the JIT may emit unchecked (`in_frame_window`).

`frame_window_mapped` ties them together: with the frame pointer at the top
of a mapped island, every access `in_frame_window` admits satisfies
`island_access`. `root_on_island`, `floor_iff` and `call_step` say how the
frame pointer gets there and stays there: the entry frame pointer is at the
top of the highest island, and the floor test passes exactly when there is
an island below, in which case one stride down is its top.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

/-! ## Scalars -/

theorem i32_neg_eq_ok {x y : I32} (h : -. x = ok y) : y.val = - x.val := by
  have := IScalar.tryMk_eq .I32 (- x.val)
  have h' : IScalar.tryMk .I32 (- x.val) = ok y := h
  rw [h'] at this
  exact this.1

theorem i32_le_eq {x y : I32} (h : decide (x ≤ y) = true) : x.val ≤ y.val := by
  have := of_decide_eq_true h
  rw [IScalar.le_equiv] at this
  exact this

/-- A narrow unsigned scalar is unchanged by `as i32`. -/
theorem uscalar_hcast_i32_val {ty : UScalarTy} (x : UScalar ty) (hx : x.val < 2 ^ 31) :
    (UScalar.hcast .I32 x).val = (x.val : Int) := by
  rw [UScalar.hcast_val_eq]
  simp only [IScalarTy.I32_numBits_eq]
  unfold Int.bmod
  push_cast
  have hx' : (x.val : Int) < 2147483648 := by
    have : (2:Nat) ^ 31 = 2147483648 := by norm_num
    rw [this] at hx
    exact_mod_cast hx
  split <;> omega

/-- `i16 as i32` is the identity on values. -/
theorem i16_cast_i32_val (x : I16) : (IScalar.cast .I32 x).val = x.val := by
  rw [IScalar.cast_val_eq]
  have hb : -32768 ≤ x.val ∧ x.val < 32768 := by scalar_tac
  simp only [IScalarTy.I16_numBits_eq, IScalarTy.I32_numBits_eq]
  norm_num

/-- Building a `bind` that succeeds, step by step. -/
theorem bind_ok_of {α β : Type} {x : Result α} {f : α → Result β} {a : α} {y : β}
    (hx : x = ok a) (hf : f a = ok y) : (x >>= f) = ok y := by
  subst hx
  exact hf

theorem usize_sub_ok {x y : Usize} (h : y.val ≤ x.val) : ∃ z, x - y = ok z ∧ z.val = x.val - y.val := by
  have := UScalar.sub_equiv x y
  rcases hxy : x - y with z | e | _ <;> rw [hxy] at this
  · exact ⟨z, rfl, by omega⟩
  · omega
  · exact absurd this id

/-! ## The four functions -/

theorem add_checked_ok {a b r : Usize} (h : stack.add_checked a b = ok (some r)) :
    r.val = a.val + b.val := by
  unfold stack.add_checked at h
  obtain_bind ⟨i, hi, h⟩ := h
  split at h
  · simp at h
  · obtain_bind ⟨i1, hi1, h⟩ := h
    simp only [ok.injEq, Option.some.injEq] at h
    subst h
    exact usize_add_eq_ok hi1

theorem mul_checked_ok {a b r : Usize} (h : stack.mul_checked a b = ok (some r)) :
    r.val = a.val * b.val := by
  unfold stack.mul_checked at h
  split at h
  · obtain_bind ⟨i, hi, h⟩ := h
    split at h
    · simp at h
    · obtain_bind ⟨i1, hi1, h⟩ := h
      simp only [ok.injEq, Option.some.injEq] at h
      subst h
      exact usize_mul_eq_ok hi1
  · obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Option.some.injEq] at h
    subst h
    exact usize_mul_eq_ok hi

/-- The frame pointer is at the top of island `j`. -/
def OnIsland (L : stack.FrameLayout) (j fp : Nat) : Prop :=
  j < L.frame_count.val ∧ fp = j * L.frame_stride.val + L.frame_size.val

/-- The entry frame pointer is the top of the highest island. -/
theorem root_on_island {L : stack.FrameLayout} {r : Usize}
    (h : stack.root_frame_offset L = ok (some r)) : OnIsland L (L.frame_count.val - 1) r.val := by
  unfold stack.root_frame_offset at h
  split at h
  · simp at h
  · rename_i hne
    have hpos : 0 < L.frame_count.val := by
      have : L.frame_count.val ≠ 0 := by
        intro h0; apply hne; exact UScalar.eq_of_val_eq (by simp [h0])
      omega
    obtain_bind ⟨i, hi, h⟩ := h
    obtain ⟨hiv, _⟩ := usize_sub_eq_ok hi
    simp at hiv
    obtain_bind ⟨o, ho, h⟩ := h
    cases o with
    | none => simp at h
    | some span =>
      have hspan := mul_checked_ok ho
      have hr := add_checked_ok h
      exact ⟨by omega, by rw [hr, hspan, hiv]⟩

theorem local_call_floor_ok {L : stack.FrameLayout} {r : Usize}
    (h : stack.local_call_floor L = ok (some r)) : r.val = L.frame_size.val + L.frame_stride.val :=
  add_checked_ok h

/-- The floor test on a frame pointer at the top of island `j` passes exactly
when there is an island below it. -/
theorem floor_iff {L : stack.FrameLayout} (hstride : 0 < L.frame_stride.val) {j fp : Nat}
    (hfp : OnIsland L j fp) :
    L.frame_size.val + L.frame_stride.val ≤ fp ↔ 1 ≤ j := by
  obtain ⟨_, rfl⟩ := hfp
  constructor
  · intro h
    by_contra hj
    have : j = 0 := by omega
    subst this
    simp at h
    omega
  · intro h
    obtain ⟨i, rfl⟩ : ∃ i, j = i + 1 := ⟨j - 1, by omega⟩
    rw [Nat.add_mul]
    omega

/-- One stride down from the top of island `j + 1` is the top of island `j`. -/
theorem call_step {L : stack.FrameLayout} {j fp : Nat} (hfp : OnIsland L j fp) (hj : 1 ≤ j) :
    OnIsland L (j - 1) (fp - L.frame_stride.val) := by
  obtain ⟨hlt, rfl⟩ := hfp
  obtain ⟨i, rfl⟩ : ∃ i, j = i + 1 := ⟨j - 1, by omega⟩
  refine ⟨by omega, ?_⟩
  simp only [Nat.add_sub_cancel, Nat.add_mul, Nat.one_mul]
  omega

theorem in_frame_window_ok {F : U16} {off : I16} {w : U8}
    (h : stack.in_frame_window F off w = ok true) :
    -(F.val : Int) ≤ off.val ∧ off.val + w.val ≤ 0 := by
  unfold stack.in_frame_window at h
  obtain_bind ⟨o, ho, h⟩ := h
  simp only [lift, ok.injEq] at ho
  subst ho
  obtain_bind ⟨w1, hw1, h⟩ := h
  simp only [lift, ok.injEq] at hw1
  subst hw1
  obtain_bind ⟨f, hf, h⟩ := h
  simp only [lift, ok.injEq] at hf
  subst hf
  obtain_bind ⟨nf, hnf, h⟩ := h
  have hnf' := i32_neg_eq_ok hnf
  split at h
  · rename_i hge
    obtain_bind ⟨nw, hnw, h⟩ := h
    have hnw' := i32_neg_eq_ok hnw
    simp only [ok.injEq] at h
    have hle := i32_le_eq h
    simp only [ge_iff_le, IScalar.le_equiv] at hge
    rw [i16_cast_i32_val] at hle hge
    rw [uscalar_hcast_i32_val _ (by scalar_tac)] at hnf'
    rw [uscalar_hcast_i32_val _ (by scalar_tac)] at hnw'
    omega
  · simp at h

theorem island_access_true {L : stack.FrameLayout} {off size : Usize}
    (hstride : 0 < L.frame_stride.val)
    (hslot : off.val / L.frame_stride.val < L.frame_count.val)
    (hwithin : off.val % L.frame_stride.val < L.frame_size.val)
    (hsize : size.val ≤ L.frame_size.val - off.val % L.frame_stride.val) :
    stack.island_access L off size = ok true := by
  unfold stack.island_access
  obtain ⟨slot, hslot_eq, hsv⟩ := UScalar.div_spec off (by omega : L.frame_stride.val ≠ 0)
  obtain ⟨within, hw_eq, hwv⟩ :=
    WP.spec_imp_exists (UScalar.rem_spec off (by omega : L.frame_stride.val ≠ 0))
  refine bind_ok_of hslot_eq ?_
  refine bind_ok_of hw_eq ?_
  try simp only
  rw [if_pos ((UScalar.lt_equiv _ _).mpr (by rw [hsv]; exact hslot))]
  rw [if_pos ((UScalar.lt_equiv _ _).mpr (by rw [hwv]; exact hwithin))]
  obtain ⟨i, hi, hiv⟩ := usize_sub_ok (x := L.frame_size) (y := within) (by rw [hwv]; omega)
  refine bind_ok_of hi ?_
  try simp only
  congr 1
  apply decide_eq_true
  rw [UScalar.le_equiv, hiv, hwv]
  exact hsize

/-! ## The theorem -/

/-- With the frame pointer at the top of a mapped island, every access
`in_frame_window` admits lies in that island. `a` is the accessed offset
`fp + off` and `size` the width, as the runtime's `checked_stack_region`
sees them. -/
theorem frame_window_mapped {L : stack.FrameLayout} (hstride : 0 < L.frame_stride.val)
    (hsize : L.frame_size.val ≤ L.frame_stride.val) {j fp : Nat} (hfp : OnIsland L j fp)
    {F : U16} (hF : F.val = L.frame_size.val) {off : I16} {w : U8} (hw0 : 0 < w.val)
    (hw : stack.in_frame_window F off w = ok true)
    {a size : Usize} (ha : (a.val : Int) = fp + off.val) (hsz : size.val = w.val) :
    stack.island_access L a size = ok true := by
  obtain ⟨h1, h2⟩ := in_frame_window_ok hw
  obtain ⟨hj, rfl⟩ := hfp
  -- The offset inside the island.
  obtain ⟨k, hk, hkw⟩ : ∃ k : Nat, a.val = j * L.frame_stride.val + k ∧ k + w.val ≤ L.frame_size.val := by
    refine ⟨a.val - j * L.frame_stride.val, ?_, ?_⟩ <;> omega
  have hklt : k < L.frame_stride.val := by omega
  have hdiv : a.val / L.frame_stride.val = j := by
    rw [hk, Nat.mul_comm, Nat.mul_add_div hstride, Nat.div_eq_of_lt hklt]
    simp
  have hmod : a.val % L.frame_stride.val = k := by
    rw [hk, Nat.mul_comm, Nat.mul_add_mod, Nat.mod_eq_of_lt hklt]
  apply island_access_true hstride
  · rw [hdiv]; exact hj
  · rw [hmod]; omega
  · rw [hmod, hsz]; omega

end async_ebpf_verified

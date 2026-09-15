import AsyncEbpf.Loop
import AsyncEbpf.X64.Tag

/-!
# The macro checker, read off the generated definitions

`x64_check::check` is the memory-safety gate the x86_64 backend runs on the
macro list it built, and `check_chain` is what a `check … = Ok(())` is worth
to a proof: the walk it performed, laid out as a chain of abstract states.
There is one state per position in the list plus the entry state, one running
eBPF slot number beside it, every consecutive pair related by the checker's
own `step`, and the last state dead — which is the checker's way of saying
that control does not fall out of the function.

The rest of the file is the other half of that bargain: one inversion lemma
per rule, so that a consumer reading the chain never unfolds an extracted
definition again. Each says, of a step that returned `Ok`, what had to hold
of the state before it and what holds of the state after it, in `tagAt`,
`Int` and `Nat` terms rather than in `Result`s and `Array`s. The shapes
recur, so they are named once: `Writable` is the set of registers a macro may
write, `SetsTop` is "these registers became `Top` and nothing else moved",
`EnterShaped` is the state at a function entry and at every branch target,
`ClobberCall` is what a call leaves, and `AddrOk` is the three-way
disjunction that admits a guest access.

The structural rules read the pre-pass' tables, so those are characterised
too: `scan_is_target` and `scan_is_labelled` say the tables `scan` builds
name exactly the slots some branch targets and exactly the slots some
`PcLabel` marks, and `scan_trailer` says its `trailer` flag holds exactly
when the list ends in `Epilogue, Retpoline, DispatcherSlot, HelperTable`.
The order of the file is bottom-up: states, addresses, the trailer, the
pre-pass, the rules, then the walk.

Nothing here is about what the macros *mean*; that is `X64/Machine.lean`'s
business, and the bridge between the two is the abstract-state invariant.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-! ## Plumbing

Scalar and monad glue, kept private: everything a consumer needs is stated in
`Nat`, `Int` and `tagAt` terms further down. -/

private theorem bind_eq_ok {α β : Type} {x : Result α} {f : α → Result β} {y : β}
    (h : (x >>= f) = ok y) : ∃ a, x = ok a ∧ f a = ok y := by
  cases x <;> simp_all

private theorem u8_eq_iff {x y : Std.U8} : x = y ↔ x.val = y.val := by scalar_tac

private theorem u8_ne {x y : Std.U8} (h : ¬ (x = y)) : x.val ≠ y.val := fun he => h (u8_eq_iff.mpr he)

private theorem u32_eq_iff {x y : Std.U32} : x = y ↔ x.val = y.val := by scalar_tac

private theorem usize_lt {x y : Std.Usize} (h : x < y) : x.val < y.val := by
  simpa using (UScalar.lt_equiv x y).mp h

private theorem usize_not_lt {x y : Std.Usize} (h : ¬ x < y) : y.val ≤ x.val := by
  rw [UScalar.lt_equiv] at h; omega

private theorem usize_ge {x y : Std.Usize} (h : x ≥ y) : y.val ≤ x.val := by
  simp only [ge_iff_le, UScalar.le_equiv] at h; exact h

private theorem usize_not_ge {x y : Std.Usize} (h : ¬ x ≥ y) : x.val < y.val := by
  simp only [ge_iff_le, UScalar.le_equiv] at h; omega

private theorem usize_add_eq_ok {x y z : Std.Usize} (h : x + y = ok z) : z.val = x.val + y.val := by
  have := UScalar.add_equiv x y
  rw [h] at this
  exact this.2.1

private theorem usize_sub_eq_ok {x y z : Std.Usize} (h : x - y = ok z) :
    z.val = x.val - y.val ∧ y.val ≤ x.val := by
  have := UScalar.sub_equiv x y
  rw [h] at this
  obtain ⟨h1, h2, _⟩ := this
  constructor <;> omega

private theorem usize_gt_u32 {x y : Std.U32} (h : x > y) : y.val < x.val := by
  simp only [gt_iff_lt, UScalar.lt_equiv] at h; exact h

private theorem u32_not_gt {x y : Std.U32} (h : ¬ x > y) : x.val ≤ y.val := by
  simp only [gt_iff_lt, UScalar.lt_equiv] at h; omega

private theorem u32_add_eq_ok {x y z : Std.U32} (h : x + y = ok z) : z.val = x.val + y.val := by
  have := UScalar.add_equiv x y
  rw [h] at this
  exact this.2.1

private theorem i64_add_eq_ok {x y z : Std.I64} (h : x + y = ok z) : z.val = x.val + y.val := by
  have := IScalar.add_equiv x y
  rw [h] at this
  exact this.2.1

private theorem slice_index_usize_eq_ok {α : Type} {v : Slice α} {i : Std.Usize} {x : α}
    (h : Slice.index_usize v i = ok x) : i.val < v.length ∧ v.val[i.val]? = some x := by
  unfold Slice.index_usize at h
  rw [show v[i]? = v.val[i.val]? from rfl] at h
  split at h
  · simp at h
  · rename_i y hget
    simp only [ok.injEq] at h
    subst h
    exact ⟨List.getElem?_eq_some_iff.mp hget |>.1, hget⟩

private theorem vec_index_eq_ok {α : Type} {v : alloc.vec.Vec α} {i : Std.Usize} {x : α}
    (h : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i = ok x) :
    i.val < v.length ∧ v.val[i.val]? = some x := by
  rw [alloc.vec.Vec.index_slice_index] at h
  unfold alloc.vec.Vec.index_usize at h
  rw [show v[i.val]? = v.val[i.val]? from rfl] at h
  split at h
  · simp at h
  · rename_i y hget
    simp only [ok.injEq] at h
    subst h
    exact ⟨List.getElem?_eq_some_iff.mp hget |>.1, hget⟩

private theorem vec_index_mut_eq_ok {α : Type} {v : alloc.vec.Vec α} {i : Std.Usize} {x : α}
    {back : α → alloc.vec.Vec α}
    (h : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice α) v i = ok (x, back)) :
    i.val < v.length ∧ back = alloc.vec.Vec.set v i := by
  rw [alloc.vec.Vec.index_mut_slice_index] at h
  unfold alloc.vec.Vec.index_mut_usize at h
  split at h
  · rename_i y hy
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    unfold alloc.vec.Vec.index_usize at hy
    rw [show v[i.val]? = v.val[i.val]? from rfl] at hy
    split at hy
    · simp at hy
    · rename_i z hget
      exact ⟨List.getElem?_eq_some_iff.mp hget |>.1, rfl⟩
  · simp at h
  · simp at h

private theorem getElem!_append_left {α : Type} [Inhabited α] (l : List α) (x : α) (k : Nat)
    (h : k < l.length) : (l ++ [x])[k]! = l[k]! := by
  have h1 : k < (l ++ [x]).length := by simp; omega
  rw [getElem!_pos (l ++ [x]) k h1, getElem!_pos l k h, List.getElem_append_left h]

private theorem getElem!_append_self {α : Type} [Inhabited α] (l : List α) (x : α) :
    (l ++ [x])[l.length]! = x := by
  have h1 : l.length < (l ++ [x]).length := by simp
  rw [getElem!_pos (l ++ [x]) l.length h1]
  simp

/-! ## The abstract state -/

/-- The registers a register-writing macro may name: not `rsp`, not `rbp`,
not the frame register, and one of the sixteen. -/
def Writable (r : Nat) : Prop := r ≠ 4 ∧ r ≠ 5 ∧ r ≠ 15 ∧ r < 16

/-- `post` is `pre` with exactly the registers `S` names reset to `Top`. The
depth, the parked group base and liveness are untouched. -/
def SetsTop (pre post : x64_check.State) (S : Nat → Prop) : Prop :=
  (∀ k, S k → tagAt post k = x64_check.Tag.Top) ∧
  (∀ k, ¬ S k → tagAt post k = tagAt pre k) ∧
  post.depth = pre.depth ∧ post.group = pre.group ∧ post.alive = pre.alive

theorem SetsTop.refl (pre : x64_check.State) : SetsTop pre pre (fun _ => False) :=
  ⟨fun _ h => absurd h id, fun _ _ => rfl, rfl, rfl, rfl⟩

/-- The state at a function entry and at every slot a branch can land on. -/
def EnterShaped (post : x64_check.State) : Prop :=
  (∀ k, tagAt post k = if k = 15 then x64_check.Tag.Fp else x64_check.Tag.Top) ∧
  post.depth = 1#u32 ∧ post.group = x64_check.Tag.Top ∧ post.alive = true

/-- The registers a call may have written: the caller-saved ones. -/
def CallerSaved (k : Nat) : Prop :=
  k = 0 ∨ k = 1 ∨ k = 2 ∨ k = 6 ∨ k = 7 ∨ k = 8 ∨ k = 9 ∨ k = 10 ∨ k = 11

/-- What a call leaves: the caller-saved registers and the parked group base
are `Top`, everything else — the frame register included — is as it was. -/
def ClobberCall (pre post : x64_check.State) : Prop :=
  (∀ k, CallerSaved k → tagAt post k = x64_check.Tag.Top) ∧
  (∀ k, ¬ CallerSaved k → tagAt post k = tagAt pre k) ∧
  post.depth = pre.depth ∧ post.group = x64_check.Tag.Top ∧ post.alive = pre.alive

private theorem set_tag_fields {pre post : x64_check.State} {r : Std.U8} {t : x64_check.Tag}
    (h : x64_check.set_tag pre r t = ok post) :
    post.depth = pre.depth ∧ post.group = pre.group ∧ post.alive = pre.alive := by
  unfold x64_check.set_tag at h
  simp only [lift, bind_tc_ok] at h
  split at h
  · unfold Std.Array.update at h
    split at h
    · simp at h
    · simp only [bind_tc_ok, ok.injEq] at h
      subst h
      exact ⟨rfl, rfl, rfl⟩
  · simp only [ok.injEq] at h
    subst h
    exact ⟨rfl, rfl, rfl⟩

/-- `set_tag` writes the register it names and moves nothing else. -/
theorem set_tag_spec {pre post : x64_check.State} {r : Std.U8} {t : x64_check.Tag}
    (h : x64_check.set_tag pre r t = ok post) :
    (∀ k, tagAt post k = if k = r.val ∧ k < 16 then t else tagAt pre k) ∧
    post.depth = pre.depth ∧ post.group = pre.group ∧ post.alive = pre.alive :=
  ⟨tagAt_set_tag h, set_tag_fields h⟩

/-- `tag_of` is `tagAt`, out-of-range reads included. -/
theorem tag_of_spec {st : x64_check.State} {r : Std.U8} {t : x64_check.Tag}
    (h : x64_check.tag_of st r = ok t) : t = tagAt st r.val := by
  have hlen : st.regs.val.length = 16 := by simp
  unfold x64_check.tag_of at h
  simp only [lift, x64_check.NUM_REGS, bind_tc_ok] at h
  split at h
  · rename_i hlt
    have hr : r.val < 16 := by
      have := (UScalar.lt_equiv (x := UScalar.cast .Usize r) (y := 16#usize)).mp hlt
      simpa using this
    unfold Std.Array.index_usize at h
    split at h
    · simp at h
    · rename_i x hx
      simp only [ok.injEq] at h
      subst h
      simp only [tagAt, List.getD_eq_getElem?_getD]
      have : st.regs.val[r.val]? = some x := by simpa using hx
      simp [this]
  · rename_i hge
    simp only [ok.injEq] at h
    subst h
    have hr : ¬ (r.val < 16) := by
      intro hr
      refine hge ?_
      have : (UScalar.cast (src_ty := .U8) .Usize r).val < (16#usize).val := by simpa using hr
      exact (UScalar.lt_equiv _ _).mpr this
    simp only [tagAt, List.getD_eq_getElem?_getD]
    rw [List.getElem?_eq_none (by omega)]
    rfl

/-- The frame register is intact exactly when it still holds `Fp`. -/
theorem frame_intact_spec {st : x64_check.State} {b : Bool}
    (h : x64_check.frame_intact st = ok b) : b = true ↔ tagAt st 15 = x64_check.Tag.Fp := by
  unfold x64_check.frame_intact at h
  obtain ⟨t, ht, h⟩ := bind_eq_ok h
  have hfr : (x64_check.FRAME).val = 15 := by simp [x64_check.FRAME, x64_ir.R15]
  have htag := tag_of_spec ht
  rw [hfr] at htag
  subst htag
  split at h <;> rename_i heq <;> simp only [ok.injEq] at h <;> subst h <;> simp [heq]

/-- `write` refuses `rsp`, `rbp`, the frame register and anything past the
sixteen, and otherwise makes its destination `Top`. -/
theorem write_spec {pre post : x64_check.State} {r : Std.U8} {index : Std.Usize} {pc : Std.U32}
    (h : x64_check.write pre r index pc = ok (.Ok (), post)) :
    Writable r.val ∧ SetsTop pre post (· = r.val) := by
  unfold x64_check.write x64_check.reject at h
  simp only [bind_tc_ok] at h
  split at h
  · simp at h
  · rename_i h4
    split at h
    · simp at h
    · rename_i h5
      split at h
      · simp at h
      · rename_i h15
        simp only [lift, bind_tc_ok] at h
        split at h
        · simp at h
        · rename_i hlt
          obtain ⟨st1, hst1, h⟩ := bind_eq_ok h
          simp only [ok.injEq, Prod.mk.injEq, true_and] at h
          subst h
          have hw : Writable r.val := by
            refine ⟨?_, ?_, ?_, ?_⟩
            · have := u8_ne h4; simpa [x64_ir.RSP] using this
            · have := u8_ne h5; simpa [x64_ir.RBP] using this
            · have := u8_ne h15; simpa [x64_check.FRAME, x64_ir.R15] using this
            · have := usize_not_ge hlt
              simpa [x64_check.NUM_REGS] using this
          refine ⟨hw, ?_, ?_, (set_tag_fields hst1).1, (set_tag_fields hst1).2.1,
            (set_tag_fields hst1).2.2⟩
          · rintro k rfl
            rw [tagAt_set_tag hst1]
            simp [hw.2.2.2]
          · intro k hk
            rw [tagAt_set_tag hst1]
            simp [hk]

/-- `depth_ok` is the bound on the native stack, in `Nat`. -/
theorem depth_ok_spec {st : x64_check.State} {pushes : Std.U32} {b : Bool}
    (h : x64_check.depth_ok st pushes = ok b) :
    b = true ↔ st.depth.val + pushes.val ≤ 16 := by
  unfold x64_check.depth_ok at h
  obtain ⟨i, hi, h⟩ := bind_eq_ok h
  simp only [ok.injEq] at h
  subst h
  have := u32_add_eq_ok hi
  simp only [x64_check.MAX_DEPTH, decide_eq_true_eq, UScalar.le_equiv]
  have h16 : (16#u32 : Std.U32).val = 16 := by simp
  omega

private theorem frame_val : (x64_check.FRAME).val = 15 := by
  simp [x64_check.FRAME, x64_ir.R15]

private theorem tagAt_out (st : x64_check.State) {k : Nat} (h : 16 ≤ k) :
    tagAt st k = x64_check.Tag.Top := by
  have hlen : st.regs.val.length = 16 := by simp
  simp only [tagAt, List.getD_eq_getElem?_getD]
  rw [List.getElem?_eq_none (by omega)]
  rfl

theorem SetsTop.mono {pre post : x64_check.State} {S T : Nat → Prop} (h : SetsTop pre post S)
    (hST : ∀ k, S k ↔ T k) : SetsTop pre post T :=
  ⟨fun k hk => h.1 k ((hST k).mpr hk), fun k hk => h.2.1 k (fun hs => hk ((hST k).mp hs)),
   h.2.2.1, h.2.2.2.1, h.2.2.2.2⟩

private theorem SetsTop.setTag {a b c : x64_check.State} {S : Nat → Prop} {r : Std.U8}
    (hr : r.val < 16) (h1 : SetsTop a b S) (h2 : x64_check.set_tag b r .Top = ok c) :
    SetsTop a c (fun k => S k ∨ k = r.val) := by
  obtain ⟨hd, hg, hal⟩ := set_tag_fields h2
  refine ⟨fun k hk => ?_, fun k hk => ?_, by rw [hd]; exact h1.2.2.1,
    by rw [hg]; exact h1.2.2.2.1, by rw [hal]; exact h1.2.2.2.2⟩
  · rw [tagAt_set_tag h2]
    by_cases hkr : k = r.val
    · simp [hkr, hr]
    · rw [if_neg (by simp [hkr])]
      exact h1.1 k (hk.resolve_right hkr)
  · rw [tagAt_set_tag h2, if_neg (by simp; intro he; exact absurd (Or.inr he) hk)]
    exact h1.2.1 k (fun hs => hk (Or.inl hs))

/-- One more `write` on top of a chain of them. -/
theorem SetsTop.write {a b c : x64_check.State} {S : Nat → Prop} {r : Std.U8}
    {index : Std.Usize} {pc : Std.U32} (h1 : SetsTop a b S)
    (h2 : x64_check.write b r index pc = ok (.Ok (), c)) :
    Writable r.val ∧ SetsTop a c (fun k => S k ∨ k = r.val) := by
  obtain ⟨hw, hs⟩ := write_spec h2
  refine ⟨hw, ?_, ?_, by rw [hs.2.2.1]; exact h1.2.2.1, by rw [hs.2.2.2.1]; exact h1.2.2.2.1,
    by rw [hs.2.2.2.2]; exact h1.2.2.2.2⟩
  · intro k hk
    by_cases hkr : k = r.val
    · exact hs.1 k hkr
    · rw [hs.2.1 k hkr]
      exact h1.1 k (hk.resolve_right hkr)
  · intro k hk
    rw [hs.2.1 k (fun he => hk (Or.inr he))]
    exact h1.2.1 k (fun hsk => hk (Or.inl hsk))

private def EnterInv (pre : x64_check.State) (x : x64_check.State × Std.Usize) : Prop :=
  x.2.val ≤ 16 ∧ (∀ k, k < x.2.val → tagAt x.1 k = x64_check.Tag.Top) ∧
  x.1.depth = pre.depth ∧ x.1.group = pre.group ∧ x.1.alive = pre.alive

private theorem enter_loop_ok {pre st : x64_check.State}
    (h : x64_check.enter_loop pre 0#usize = ok st) :
    (∀ k, tagAt st k = x64_check.Tag.Top) ∧
    st.depth = pre.depth ∧ st.group = pre.group ∧ st.alive = pre.alive := by
  unfold x64_check.enter_loop at h
  refine loop_ok_induction _ (EnterInv pre)
    (fun y => (∀ k, tagAt y k = x64_check.Tag.Top) ∧
      y.depth = pre.depth ∧ y.group = pre.group ∧ y.alive = pre.alive) ?_ _ _
    ⟨by simp, by simp, rfl, rfl, rfl⟩ h
  rintro ⟨st1, r1⟩ hinv res hb
  obtain ⟨hr1, htag, hd, hg, hal⟩ := hinv
  dsimp only at hr1 htag hd hg hal
  simp only at hb
  unfold x64_check.enter_loop.body at hb
  simp only [x64_check.NUM_REGS] at hb
  split at hb
  · rename_i hlt
    have hr : r1.val < 16 := by simpa using usize_lt hlt
    obtain ⟨i, hi, hb⟩ := bind_eq_ok hb
    have hival : i.val = r1.val := by
      have := UScalar.cast_inBounds_spec (src_ty := .Usize) .U8 r1 (by
        simp only [UScalar.max, UScalarTy.numBits]; omega)
      rw [hi] at this
      simpa using this
    obtain ⟨st2, h2, hb⟩ := bind_eq_ok hb
    obtain ⟨r2, hr2, hb⟩ := bind_eq_ok hb
    simp only [ok.injEq] at hb
    subst hb
    obtain ⟨hd2, hg2, hal2⟩ := set_tag_fields h2
    have hone : (1#usize : Std.Usize).val = 1 := by simp
    have hadd := usize_add_eq_ok hr2
    refine ⟨?_, ?_, by rw [hd2, hd], by rw [hg2, hg], by rw [hal2, hal]⟩
    · dsimp only
      omega
    · intro k hk
      dsimp only at hk ⊢
      rw [tagAt_set_tag h2, hival]
      by_cases hkr : k = r1.val
      · simp [hkr, hr]
      · rw [if_neg (by simp [hkr])]
        exact htag k (by omega)
  · rename_i hge
    simp only [ok.injEq] at hb
    subst hb
    have : (16 : Nat) ≤ r1.val := by simpa using usize_not_lt hge
    refine ⟨fun k => ?_, hd, hg, hal⟩
    by_cases hk : k < 16
    · exact htag k (by omega)
    · exact tagAt_out _ (by omega)

/-- `enter` is the state at a function entry: the frame register intact,
nothing else known, one slot pushed, no group base parked, alive. -/
theorem enter_spec {pre post : x64_check.State} (h : x64_check.enter pre = ok post) :
    EnterShaped post := by
  unfold x64_check.enter at h
  obtain ⟨st1, h1, h⟩ := bind_eq_ok h
  obtain ⟨st2, h2, h⟩ := bind_eq_ok h
  simp only [ok.injEq] at h
  subst h
  obtain ⟨hall, _, _, _⟩ := enter_loop_ok h1
  refine ⟨fun k => ?_, rfl, rfl, rfl⟩
  have he : tagAt { st2 with depth := 1#u32, group := x64_check.Tag.Top, alive := true } k
      = tagAt st2 k := rfl
  rw [he, tagAt_set_tag h2, frame_val]
  by_cases hk : k = 15
  · simp [hk]
  · rw [if_neg (by simp [hk]), if_neg hk]
    exact hall k

/-- The state before the first macro: the frame register holds the frame
base, nothing else is known, nothing has been pushed. -/
theorem entry_state_spec {st : x64_check.State} (h : x64_check.entry_state = ok st) :
    (∀ k, tagAt st k = if k = 15 then x64_check.Tag.Fp else x64_check.Tag.Top) ∧
    st.depth = 0#u32 ∧ st.group = x64_check.Tag.Top ∧ st.alive = true := by
  unfold x64_check.entry_state at h
  obtain ⟨hd, hg, hal⟩ := set_tag_fields h
  refine ⟨fun k => ?_, hd, hg, hal⟩
  rw [tagAt_set_tag h, frame_val]
  by_cases hk : k = 15
  · simp [hk]
  · rw [if_neg (by simp [hk]), if_neg hk]
    by_cases hk16 : k < 16
    · simp only [tagAt, Std.Array.repeat_val, List.getD_eq_getElem?_getD,
        List.getElem?_replicate]
      simp [hk16]
    · exact tagAt_out _ (by omega)

/-- A call leaves the caller-saved registers and the parked group base `Top`,
and everything else — the frame register included — as it was. -/
theorem clobber_call_spec {pre post : x64_check.State}
    (h : x64_check.clobber_call pre = ok post) : ClobberCall pre post := by
  unfold x64_check.clobber_call at h
  obtain ⟨s1, e1, h⟩ := bind_eq_ok h
  obtain ⟨s2, e2, h⟩ := bind_eq_ok h
  obtain ⟨s3, e3, h⟩ := bind_eq_ok h
  obtain ⟨s4, e4, h⟩ := bind_eq_ok h
  obtain ⟨s5, e5, h⟩ := bind_eq_ok h
  obtain ⟨s6, e6, h⟩ := bind_eq_ok h
  obtain ⟨s7, e7, h⟩ := bind_eq_ok h
  obtain ⟨s8, e8, h⟩ := bind_eq_ok h
  obtain ⟨s9, e9, h⟩ := bind_eq_ok h
  simp only [ok.injEq] at h
  subst h
  have b1 := SetsTop.setTag (by simp [x64_ir.RAX]) (SetsTop.refl pre) e1
  have b2 := SetsTop.setTag (by simp [x64_ir.RCX]) b1 e2
  have b3 := SetsTop.setTag (by simp [x64_ir.RDX]) b2 e3
  have b4 := SetsTop.setTag (by simp [x64_ir.RSI]) b3 e4
  have b5 := SetsTop.setTag (by simp [x64_ir.RDI]) b4 e5
  have b6 := SetsTop.setTag (by simp [x64_ir.R8]) b5 e6
  have b7 := SetsTop.setTag (by simp [x64_ir.R9]) b6 e7
  have b8 := SetsTop.setTag (by simp [x64_ir.R10]) b7 e8
  have b9 := SetsTop.setTag (by simp [x64_ir.R11]) b8 e9
  have hmono : SetsTop pre s9 CallerSaved := by
    refine b9.mono (fun k => ?_)
    simp only [CallerSaved, x64_ir.RAX, x64_ir.RCX, x64_ir.RDX, x64_ir.RSI, x64_ir.RDI,
      x64_ir.R8, x64_ir.R9, x64_ir.R10, x64_ir.R11]
    norm_num
    tauto
  exact ⟨fun k hk => hmono.1 k hk, fun k hk => hmono.2.1 k hk, hmono.2.2.1, rfl, hmono.2.2.2.2⟩


/-! ## Addresses -/

private theorem i32_eq_iff {x y : Std.I32} : x = y ↔ x.val = y.val := by scalar_tac

private theorem u32_hcast_i64 (x : Std.U32) :
    (UScalar.hcast (src_ty := .U32) .I64 x).val = (x.val : Int) := by
  have := UScalar.hcast_inBounds_spec (src_ty := .U32) .I64 x (by scalar_tac)
  simpa [lift] using this

private theorem u16_hcast_i64 (x : Std.U16) :
    (UScalar.hcast (src_ty := .U16) .I64 x).val = (x.val : Int) := by
  have := UScalar.hcast_inBounds_spec (src_ty := .U16) .I64 x (by scalar_tac)
  simpa [lift] using this

private theorem i32_cast_i64 (x : Std.I32) :
    (IScalar.cast (src_ty := .I32) .I64 x).val = x.val := by
  simp

private theorem i64_neg_eq_ok {x y : Std.I64} (h : (-. x : Result Std.I64) = ok y) :
    y.val = -x.val := by
  have h' : IScalar.neg x = ok y := h
  unfold IScalar.neg at h'
  have := IScalar.tryMk_eq .I64 (-x.val)
  rw [h'] at this
  exact this.1

/-- The three ways a guest access of `size` bytes at `[base + disp]` is
admitted, and the only three: with the cage off nothing about guest memory
was promised, so nothing is checked; through a `Checked` base with the access
inside the window it vouches for; or through the frame register, still
holding the frame base, into the frame window `[-stack_frame_size, 0)`. -/
def AddrOk (cfg : x64_ir.Cfg) (st : x64_check.State) (base : Std.U8) (disp : Int)
    (size : Nat) : Prop :=
  cfg.pointer_mask.val = 0 ∨
  (∃ w : Std.U32, tagAt st base.val = x64_check.Tag.Checked w ∧
    0 ≤ disp ∧ disp + size ≤ (w.val : Int)) ∨
  (base.val = 15 ∧ tagAt st 15 = x64_check.Tag.Fp ∧ cfg.pointer_mask.val ≠ 0 ∧
    cfg.native_frame_base = true ∧ -(cfg.stack_frame_size.val : Int) ≤ disp ∧
    disp + size ≤ 0)

/-- The checked-base rule, in `Int`. -/
theorem checked_ok_spec {st : x64_check.State} {base : Std.U8} {disp size : Std.I64} {b : Bool}
    (h : x64_check.checked_ok st base disp size = ok b) :
    b = true ↔ ∃ w : Std.U32, tagAt st base.val = x64_check.Tag.Checked w ∧
      0 ≤ disp.val ∧ disp.val + size.val ≤ (w.val : Int) := by
  unfold x64_check.checked_ok at h
  obtain ⟨t, ht, h⟩ := bind_eq_ok h
  have htag := tag_of_spec ht
  subst htag
  split at h
  · rename_i heq
    simp only [ok.injEq] at h
    subst h
    simp [heq]
  · rename_i heq
    simp only [ok.injEq] at h
    subst h
    simp [heq]
  · rename_i width heq
    split at h
    · rename_i hge
      have hdisp : (0 : Int) ≤ disp.val := by
        have := (IScalar.le_equiv (0#i64) disp).mp hge
        simpa using this
      obtain ⟨i, hi, h⟩ := bind_eq_ok h
      obtain ⟨i1, hi1, h⟩ := bind_eq_ok h
      simp only [ok.injEq] at h
      subst h
      have hiv := i64_add_eq_ok hi
      have hi1v : i1.val = (width.val : Int) := by
        simp only [lift, ok.injEq] at hi1
        subst hi1
        exact u32_hcast_i64 width
      simp only [decide_eq_true_eq, IScalar.le_equiv, hiv, hi1v]
      constructor
      · intro hb
        exact ⟨width, heq, hdisp, hb⟩
      · rintro ⟨w, hw, -, hle⟩
        rw [heq] at hw
        cases hw
        exact hle
    · rename_i hge
      simp only [ok.injEq] at h
      subst h
      have hdisp : ¬ ((0 : Int) ≤ disp.val) := by
        intro hc
        exact hge ((IScalar.le_equiv (0#i64) disp).mpr (by simpa using hc))
      simp only [Bool.false_eq_true, false_iff, not_exists]
      rintro w ⟨-, hd, -⟩
      exact hdisp hd

/-- The frame fast path, in `Int`. -/
theorem frame_ok_spec {cfg : x64_ir.Cfg} {st : x64_check.State} {base : Std.U8}
    {disp size : Std.I64} {b : Bool} (h : x64_check.frame_ok cfg st base disp size = ok b) :
    b = true ↔ (base.val = 15 ∧ tagAt st 15 = x64_check.Tag.Fp ∧ cfg.pointer_mask.val ≠ 0 ∧
      cfg.native_frame_base = true ∧ -(cfg.stack_frame_size.val : Int) ≤ disp.val ∧
      disp.val + size.val ≤ 0) := by
  unfold x64_check.frame_ok at h
  split at h
  · rename_i hbase
    have hb15 : base.val = 15 := by rw [hbase]; exact frame_val
    obtain ⟨fi, hfi, h⟩ := bind_eq_ok h
    have hfis := frame_intact_spec hfi
    split at h
    · rename_i hfit
      have hfp : tagAt st 15 = x64_check.Tag.Fp := hfis.mp hfit
      split at h
      · rename_i hmask
        have hm : cfg.pointer_mask.val ≠ 0 := by
          simp only [bne_iff_ne, ne_eq] at hmask
          intro hc
          exact hmask (i32_eq_iff.mpr (by simpa using hc))
        split at h
        · rename_i hnfb
          obtain ⟨i, hi, h⟩ := bind_eq_ok h
          obtain ⟨i1, hi1, h⟩ := bind_eq_ok h
          have hiv : i.val = (cfg.stack_frame_size.val : Int) := by
            simp only [lift, ok.injEq] at hi
            subst hi
            exact u16_hcast_i64 _
          have hi1v : i1.val = -(cfg.stack_frame_size.val : Int) := by
            rw [i64_neg_eq_ok hi1, hiv]
          split at h
          · rename_i hlow
            obtain ⟨i2, hi2, h⟩ := bind_eq_ok h
            simp only [ok.injEq] at h
            subst h
            have hi2v := i64_add_eq_ok hi2
            have hl : -(cfg.stack_frame_size.val : Int) ≤ disp.val := by
              have := (IScalar.le_equiv i1 disp).mp hlow
              omega
            simp only [decide_eq_true_eq, IScalar.le_equiv, hi2v]
            simp only [hb15, hfp, hm, hnfb, hl, true_and, ne_eq, not_false_eq_true]
            constructor
            · intro hc; simpa using hc
            · intro hc; simpa using hc
          · rename_i hlow
            simp only [ok.injEq] at h
            subst h
            simp only [Bool.false_eq_true, false_iff]
            rintro ⟨-, -, -, -, hc, -⟩
            exact absurd ((IScalar.le_equiv i1 disp).mpr (by omega)) hlow
        · rename_i hnfb
          simp only [ok.injEq] at h
          subst h
          simp only [Bool.false_eq_true, false_iff]
          rintro ⟨-, -, -, hc, -, -⟩
          exact absurd hc (by simpa using hnfb)
      · rename_i hmask
        simp only [ok.injEq] at h
        subst h
        simp only [bne_iff_ne, ne_eq, Decidable.not_not] at hmask
        simp only [Bool.false_eq_true, false_iff]
        rintro ⟨-, -, hc, -, -, -⟩
        exact hc (by rw [hmask]; simp)
    · rename_i hfit
      simp only [ok.injEq] at h
      subst h
      simp only [Bool.false_eq_true, false_iff]
      rintro ⟨-, hc, -, -, -, -⟩
      exact absurd (hfis.mpr hc) hfit
  · rename_i hbase
    simp only [ok.injEq] at h
    subst h
    simp only [Bool.false_eq_true, false_iff]
    rintro ⟨hc, -, -, -, -, -⟩
    exact absurd (u8_eq_iff.mpr (by rw [hc, frame_val])) hbase

/-- `addr_ok` is exactly `AddrOk`. -/
theorem addr_ok_spec {cfg : x64_ir.Cfg} {st : x64_check.State} {base : Std.U8}
    {disp : Std.I32} {size : Std.U32} {b : Bool}
    (h : x64_check.addr_ok cfg st base disp size = ok b) :
    b = true ↔ AddrOk cfg st base disp.val size.val := by
  unfold x64_check.addr_ok at h
  simp only [AddrOk]
  split at h
  · rename_i hmask
    simp only [ok.injEq] at h
    subst h
    simp [i32_eq_iff.mp hmask]
  · rename_i hmask
    have hm : cfg.pointer_mask.val ≠ 0 := fun hc => hmask (i32_eq_iff.mpr (by simpa using hc))
    obtain ⟨i, hi, h⟩ := bind_eq_ok h
    obtain ⟨i1, hi1, h⟩ := bind_eq_ok h
    obtain ⟨bc, hbc, h⟩ := bind_eq_ok h
    have hiv : i.val = disp.val := by
      simp only [lift, ok.injEq] at hi; subst hi; exact i32_cast_i64 _
    have hi1v : i1.val = (size.val : Int) := by
      simp only [lift, ok.injEq] at hi1; subst hi1; exact u32_hcast_i64 _
    have hcs := checked_ok_spec hbc
    rw [hiv, hi1v] at hcs
    split at h
    · rename_i hbct
      simp only [ok.injEq] at h
      subst h
      simp only [true_iff]
      exact Or.inr (Or.inl (hcs.mp hbct))
    · rename_i hbct
      obtain ⟨i2, hi2, h⟩ := bind_eq_ok h
      obtain ⟨i3, hi3, h⟩ := bind_eq_ok h
      have hi2v : i2.val = disp.val := by
        simp only [lift, ok.injEq] at hi2; subst hi2; exact i32_cast_i64 _
      have hi3v : i3.val = (size.val : Int) := by
        simp only [lift, ok.injEq] at hi3; subst hi3; exact u32_hcast_i64 _
      have hfs := frame_ok_spec h
      rw [hi2v, hi3v] at hfs
      rw [hfs]
      constructor
      · intro hf
        exact Or.inr (Or.inr hf)
      · rintro (hc | hc | hc)
        · exact absurd hc hm
        · exact absurd (hcs.mpr hc) (by simpa using hbct)
        · exact hc


/-! ## The trailer -/

private theorem usize_eq_iff {x y : Std.Usize} : x = y ↔ x.val = y.val := by scalar_tac

private theorem is_epilogue_spec {insn : x64_ir.MInsn} {b : Bool}
    (h : x64_check.is_epilogue insn = ok b) : b = true ↔ insn = .Epilogue := by
  unfold x64_check.is_epilogue at h
  cases insn <;> simp_all

private theorem is_retpoline_spec {insn : x64_ir.MInsn} {b : Bool}
    (h : x64_check.is_retpoline insn = ok b) : b = true ↔ insn = .Retpoline := by
  unfold x64_check.is_retpoline at h
  cases insn <;> simp_all

private theorem is_dispatcher_slot_spec {insn : x64_ir.MInsn} {b : Bool}
    (h : x64_check.is_dispatcher_slot insn = ok b) : b = true ↔ insn = .DispatcherSlot := by
  unfold x64_check.is_dispatcher_slot at h
  cases insn <;> simp_all

private theorem is_helper_table_spec {insn : x64_ir.MInsn} {b : Bool}
    (h : x64_check.is_helper_table insn = ok b) : b = true ↔ insn = .HelperTable := by
  unfold x64_check.is_helper_table at h
  cases insn <;> simp_all

/-- A macro list ends in a trailer: the epilogue, the retpoline that owns the
two data macros, and the two data macros, with nothing after them. -/
def HasTrailer (code : List x64_ir.MInsn) : Prop :=
  ∃ pre, code = pre ++ [.Epilogue, .Retpoline, .DispatcherSlot, .HelperTable]

/-- `HasTrailer`, read off the last four positions. -/
theorem hasTrailer_iff {l : List x64_ir.MInsn} :
    HasTrailer l ↔ (4 ≤ l.length ∧ l[l.length - 4]? = some .Epilogue ∧
      l[l.length - 3]? = some .Retpoline ∧ l[l.length - 2]? = some .DispatcherSlot ∧
      l[l.length - 1]? = some .HelperTable) := by
  constructor
  · rintro ⟨pre, rfl⟩
    have hp : (pre ++ [x64_ir.MInsn.Epilogue, .Retpoline, .DispatcherSlot, .HelperTable]).length
        = pre.length + 4 := by simp
    refine ⟨by omega, ?_, ?_, ?_, ?_⟩ <;>
      · rw [hp, List.getElem?_append_right (by omega)]
        simp
  · rintro ⟨hlen, h0, h1, h2, h3⟩
    refine ⟨l.take (l.length - 4), ?_⟩
    conv_lhs => rw [← List.take_append_drop (l.length - 4) l]
    congr 1
    apply List.ext_getElem?
    intro n
    rw [List.getElem?_drop]
    match n with
    | 0 => simpa using h0
    | 1 => simpa [show l.length - 4 + 1 = l.length - 3 by omega] using h1
    | 2 => simpa [show l.length - 4 + 2 = l.length - 2 by omega] using h2
    | 3 => simpa [show l.length - 4 + 3 = l.length - 1 by omega] using h3
    | (m + 4) =>
      rw [List.getElem?_eq_none (by omega)]
      simp

/-- The retpoline at `i` has the rest of the trailer around it, and nothing
at all after it. -/
def TrailerAt (code : List x64_ir.MInsn) (i : Nat) : Prop :=
  1 ≤ i ∧ i + 3 = code.length ∧ code[i - 1]? = some .Epilogue ∧
  code[i]? = some .Retpoline ∧ code[i + 1]? = some .DispatcherSlot ∧
  code[i + 2]? = some .HelperTable

/-- `trailer_at` reads the four positions the trailer occupies, and insists
that nothing follows them. -/
theorem trailer_at_spec {code : Slice x64_ir.MInsn} {i : Std.Usize} {b : Bool}
    (h : x64_check.trailer_at code i = ok b) : b = true ↔ TrailerAt code.val i.val := by
  simp only [TrailerAt]
  unfold x64_check.trailer_at at h
  split at h
  · rename_i hge
    have h1i : 1 ≤ i.val := by simpa using usize_ge hge
    obtain ⟨i1, hi1, h⟩ := bind_eq_ok h
    have hi1v : i1.val = i.val + 3 := by simpa using usize_add_eq_ok hi1
    simp only [Slice.len] at h
    split at h
    · rename_i heq
      have hlen : i.val + 3 = code.val.length := by
        rw [← hi1v, usize_eq_iff.mp heq]
        simp
      obtain ⟨i3, hi3, h⟩ := bind_eq_ok h
      have hi3v : i3.val = i.val - 1 := (usize_sub_eq_ok hi3).1.trans (by simp)
      obtain ⟨m, hm, h⟩ := bind_eq_ok h
      obtain ⟨be, hbe, h⟩ := bind_eq_ok h
      have hmv := (slice_index_usize_eq_ok hm).2
      rw [hi3v] at hmv
      have hbes := is_epilogue_spec hbe
      split at h
      · rename_i hbet
        have hE : code.val[i.val - 1]? = some .Epilogue := by rw [hmv, hbes.mp hbet]
        obtain ⟨m1, hm1, h⟩ := bind_eq_ok h
        obtain ⟨b1, hb1, h⟩ := bind_eq_ok h
        have hm1v := (slice_index_usize_eq_ok hm1).2
        have hb1s := is_retpoline_spec hb1
        split at h
        · rename_i hb1t
          have hR : code.val[i.val]? = some .Retpoline := by rw [hm1v, hb1s.mp hb1t]
          obtain ⟨i4, hi4, h⟩ := bind_eq_ok h
          have hi4v : i4.val = i.val + 1 := by simpa using usize_add_eq_ok hi4
          obtain ⟨m2, hm2, h⟩ := bind_eq_ok h
          obtain ⟨b2, hb2, h⟩ := bind_eq_ok h
          have hm2v := (slice_index_usize_eq_ok hm2).2
          rw [hi4v] at hm2v
          have hb2s := is_dispatcher_slot_spec hb2
          split at h
          · rename_i hb2t
            have hD : code.val[i.val + 1]? = some .DispatcherSlot := by
              rw [hm2v, hb2s.mp hb2t]
            obtain ⟨i5, hi5, h⟩ := bind_eq_ok h
            have hi5v : i5.val = i.val + 2 := by simpa using usize_add_eq_ok hi5
            obtain ⟨m3, hm3, h⟩ := bind_eq_ok h
            have hm3v := (slice_index_usize_eq_ok hm3).2
            rw [hi5v] at hm3v
            have hb3s := is_helper_table_spec h
            rw [hb3s, hm3v]
            simp [h1i, hlen, hE, hR, hD]
          · rename_i hb2f
            simp only [ok.injEq] at h
            subst h
            simp only [Bool.false_eq_true, false_iff]
            rintro ⟨-, -, -, -, hc, -⟩
            rw [hm2v] at hc
            exact hb2f (hb2s.mpr (by simpa using hc))
        · rename_i hb1f
          simp only [ok.injEq] at h
          subst h
          simp only [Bool.false_eq_true, false_iff]
          rintro ⟨-, -, -, hc, -, -⟩
          rw [hm1v] at hc
          exact hb1f (hb1s.mpr (by simpa using hc))
      · rename_i hbef
        simp only [ok.injEq] at h
        subst h
        simp only [Bool.false_eq_true, false_iff]
        rintro ⟨-, -, hc, -, -, -⟩
        rw [hmv] at hc
        exact hbef (hbes.mpr (by simpa using hc))
    · rename_i hne
      simp only [ok.injEq] at h
      subst h
      simp only [Bool.false_eq_true, false_iff]
      rintro ⟨-, hc, -, -, -, -⟩
      exact hne (usize_eq_iff.mpr (by rw [hi1v, hc]; simp))
  · rename_i hge
    simp only [ok.injEq] at h
    subst h
    simp only [Bool.false_eq_true, false_iff]
    rintro ⟨hc, -, -, -, -, -⟩
    have hlt := usize_not_ge hge
    have hone : (1#usize : Std.Usize).val = 1 := by simp
    omega

/-- `has_trailer` is `HasTrailer`. -/
theorem has_trailer_spec {code : Slice x64_ir.MInsn} {b : Bool}
    (h : x64_check.has_trailer code = ok b) : b = true ↔ HasTrailer code.val := by
  unfold x64_check.has_trailer at h
  simp only [Slice.len] at h
  split at h
  · rename_i hge
    have hlen4 : 4 ≤ code.val.length := by simpa [Slice.length] using usize_ge hge
    obtain ⟨i2, hi2, h⟩ := bind_eq_ok h
    have hi2v : i2.val = code.val.length - 3 := by
      have := (usize_sub_eq_ok hi2).1
      simpa [Slice.length] using this
    rw [trailer_at_spec h, hasTrailer_iff]
    simp only [TrailerAt]
    rw [show i2.val - 1 = code.val.length - 4 by omega,
      show i2.val + 1 = code.val.length - 2 by omega,
      show i2.val + 2 = code.val.length - 1 by omega,
      show i2.val = code.val.length - 3 from hi2v]
    constructor
    · rintro ⟨-, -, a, b, c, d⟩
      exact ⟨hlen4, a, b, c, d⟩
    · rintro ⟨-, a, b, c, d⟩
      exact ⟨by omega, by omega, a, b, c, d⟩
  · rename_i hge
    simp only [ok.injEq] at h
    subst h
    have hlt : code.val.length < 4 := by
      have := usize_not_ge hge
      simpa [Slice.length] using this
    simp only [Bool.false_eq_true, false_iff]
    intro hc
    have := hasTrailer_iff.mp hc
    omega


/-! ## The pre-pass

`scan` walks the list once and records, for every slot number a label or a
branch names, whether some `PcLabel` marks it and whether some `jcc` or `jmp`
targets it. The two lemmas below say the tables are exactly those two sets;
`scan_trailer` says the third field is `HasTrailer`. -/

/-- The slot a `PcLabel` marks. -/
def labelSlot : x64_ir.MInsn → Option Std.U32
  | .PcLabel n => some n
  | _ => none

/-- The slot a branch names, when it names one rather than the exit. -/
def targetSlot : x64_ir.MInsn → Option Std.U32
  | .Jcc _ (.Pc n) => some n
  | .Jmp (.Pc n) => some n
  | _ => none

/-- The running eBPF slot number after a macro: a `PcLabel` sets it. -/
def pcNext (insn : x64_ir.MInsn) (pc : Std.U32) : Std.U32 :=
  match insn with
  | .PcLabel n => n
  | _ => pc

/-- `labelSlot` names a `PcLabel` and nothing else. -/
theorem labelSlot_eq_some {insn : x64_ir.MInsn} {n : Std.U32} (h : labelSlot insn = some n) :
    insn = .PcLabel n := by
  cases insn <;> simp_all [labelSlot]

/-- `targetSlot` names a conditional or unconditional branch to a slot. -/
theorem targetSlot_eq_some {insn : x64_ir.MInsn} {n : Std.U32} (h : targetSlot insn = some n) :
    (∃ cc, insn = .Jcc cc (.Pc n)) ∨ insn = .Jmp (.Pc n) := by
  cases insn
  case Jcc cc tgt => cases tgt <;> simp_all [targetSlot]
  case Jmp tgt => cases tgt <;> simp_all [targetSlot]
  all_goals simp_all [targetSlot]

theorem label_of_spec {insn : x64_ir.MInsn} {b : Bool} {s : Std.U32}
    (h : x64_check.label_of insn = ok (b, s)) :
    (b = true ∧ labelSlot insn = some s) ∨ (b = false ∧ labelSlot insn = none) := by
  unfold x64_check.label_of at h
  cases insn <;> simp_all [labelSlot]

theorem label_of_pcNext {insn : x64_ir.MInsn} {b : Bool} {s : Std.U32}
    (h : x64_check.label_of insn = ok (b, s)) (pc : Std.U32) :
    (if b then s else pc) = pcNext insn pc := by
  unfold x64_check.label_of at h
  cases insn <;> simp_all [pcNext]

theorem branch_target_spec {insn : x64_ir.MInsn} {k : Std.U8} {t : Std.U32}
    (h : x64_check.branch_target insn = ok (k, t)) :
    (k = 1#u8 ∧ targetSlot insn = some t) ∨ (k ≠ 1#u8 ∧ targetSlot insn = none) := by
  unfold x64_check.branch_target x64_check.target_of at h
  cases insn
  case Jcc cc tgt =>
    cases tgt <;>
      (simp only [ok.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, rfl⟩ := h; simp [targetSlot])
  case Jmp tgt =>
    cases tgt <;>
      (simp only [ok.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, rfl⟩ := h; simp [targetSlot])
  all_goals
    (simp only [ok.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, rfl⟩ := h; simp [targetSlot])

private def MaxInv (code : Slice x64_ir.MInsn) (x : Std.U32 × Std.Usize) : Prop :=
  x.2.val ≤ code.val.length ∧
  (∀ (j : Nat) insn n, j < x.2.val → code.val[j]? = some insn → labelSlot insn = some n →
    n.val ≤ x.1.val) ∧
  (∀ (j : Nat) insn n, j < x.2.val → code.val[j]? = some insn → targetSlot insn = some n →
    n.val ≤ x.1.val)

private theorem max_named_slot_ok {code : Slice x64_ir.MInsn} {m : Std.U32}
    (h : x64_check.max_named_slot code = ok m) :
    (∀ (j : Nat) insn n, code.val[j]? = some insn → labelSlot insn = some n → n.val ≤ m.val) ∧
    (∀ (j : Nat) insn n, code.val[j]? = some insn → targetSlot insn = some n → n.val ≤ m.val) := by
  unfold x64_check.max_named_slot x64_check.max_named_slot_loop at h
  refine loop_ok_induction _ (MaxInv code)
    (fun y => (∀ (j : Nat) insn n, code.val[j]? = some insn → labelSlot insn = some n → n.val ≤ y.val) ∧
      (∀ (j : Nat) insn n, code.val[j]? = some insn → targetSlot insn = some n → n.val ≤ y.val))
    ?_ _ _ ⟨by simp, by simp, by simp⟩ h
  rintro ⟨mx, i⟩ hinv res hb
  obtain ⟨hi, hlab, htgt⟩ := hinv
  dsimp only at hi hlab htgt
  simp only at hb
  unfold x64_check.max_named_slot_loop.body at hb
  simp only [Slice.len] at hb
  split at hb
  · rename_i hlt
    have hival : i.val < code.val.length := by simpa [Slice.length] using usize_lt hlt
    obtain ⟨insn, hinsn, hb⟩ := bind_eq_ok hb
    have hinsnv := (slice_index_usize_eq_ok hinsn).2
    obtain ⟨p, hp, hb⟩ := bind_eq_ok hb
    obtain ⟨labelled, slot⟩ := p
    try simp only at hb
    obtain ⟨mx1, hmx1, hb⟩ := bind_eq_ok hb
    obtain ⟨q, hq, hb⟩ := bind_eq_ok hb
    obtain ⟨kind, target⟩ := q
    try simp only at hb
    obtain ⟨mx2, hmx2, hb⟩ := bind_eq_ok hb
    obtain ⟨i2, hi2, hb⟩ := bind_eq_ok hb
    simp only [ok.injEq] at hb
    subst hb
    have hone : (1#usize : Std.Usize).val = 1 := by simp
    have hi2v : i2.val = i.val + 1 := by rw [usize_add_eq_ok hi2, hone]
    have hmono1 : mx.val ≤ mx1.val ∧ (labelled = true → slot.val ≤ mx1.val) := by
      split at hmx1
      · rename_i hl
        split at hmx1
        · rename_i hgt
          simp only [ok.injEq] at hmx1
          exact ⟨le_of_lt (hmx1 ▸ usize_gt_u32 hgt), fun _ => le_of_eq (congrArg _ hmx1)⟩
        · rename_i hgt
          simp only [ok.injEq] at hmx1
          exact ⟨le_of_eq (congrArg _ hmx1), fun _ => hmx1 ▸ u32_not_gt hgt⟩
      · rename_i hnl
        simp only [ok.injEq] at hmx1
        exact ⟨le_of_eq (congrArg _ hmx1), fun hc => absurd hc (by simpa using hnl)⟩
    have hmono2 : mx1.val ≤ mx2.val ∧ (kind = 1#u8 → target.val ≤ mx2.val) := by
      split at hmx2
      · rename_i hk
        split at hmx2
        · rename_i hgt
          simp only [ok.injEq] at hmx2
          exact ⟨le_of_lt (hmx2 ▸ usize_gt_u32 hgt), fun _ => le_of_eq (congrArg _ hmx2)⟩
        · rename_i hgt
          simp only [ok.injEq] at hmx2
          exact ⟨le_of_eq (congrArg _ hmx2), fun _ => hmx2 ▸ u32_not_gt hgt⟩
      · rename_i hnk
        simp only [ok.injEq] at hmx2
        exact ⟨le_of_eq (congrArg _ hmx2), fun hc => absurd hc hnk⟩
    refine ⟨by dsimp only; omega, ?_, ?_⟩
    · intro j insn' n hj hj2 hn
      dsimp only at hj ⊢
      by_cases hje : j = i.val
      · subst hje
        rw [hinsnv] at hj2
        cases hj2
        rcases label_of_spec hp with ⟨hb1, hs⟩ | ⟨hb1, hs⟩
        · rw [hs] at hn
          cases hn
          exact le_trans (hmono1.2 hb1) hmono2.1
        · rw [hs] at hn; exact absurd hn (by simp)
      · exact le_trans (le_trans (hlab j insn' n (by omega) hj2 hn) hmono1.1) hmono2.1
    · intro j insn' n hj hj2 hn
      dsimp only at hj ⊢
      by_cases hje : j = i.val
      · subst hje
        rw [hinsnv] at hj2
        cases hj2
        rcases branch_target_spec hq with ⟨hk1, hs⟩ | ⟨hk1, hs⟩
        · rw [hs] at hn
          cases hn
          exact hmono2.2 hk1
        · rw [hs] at hn; exact absurd hn (by simp)
      · exact le_trans (le_trans (htgt j insn' n (by omega) hj2 hn) hmono1.1) hmono2.1
  · rename_i hge
    simp only [ok.injEq] at hb
    subst hb
    have hiv : code.val.length ≤ i.val := by simpa [Slice.length] using usize_not_lt hge
    exact ⟨fun (j : Nat) insn n hj hn => hlab j insn n
        (by have := List.getElem?_eq_some_iff.mp hj |>.1; omega) hj hn,
      fun (j : Nat) insn n hj hn => htgt j insn n
        (by have := List.getElem?_eq_some_iff.mp hj |>.1; omega) hj hn⟩


private theorem list_set_true {l : List Bool} {m size : Nat} {P : Nat → Prop}
    (hlen : l.length = size) (hm : m < size)
    (hinv : ∀ (k : Nat), l[k]? = some true ↔ (P k ∧ k < size)) (k : Nat) :
    (l.set m true)[k]? = some true ↔ ((P k ∨ k = m) ∧ k < size) := by
  rw [List.getElem?_set]
  split
  · rename_i he
    subst he
    simp only [hlen, hm, if_true, true_iff]
    exact ⟨Or.inr trivial, trivial⟩
  · rename_i hne
    rw [hinv k]
    constructor
    · rintro ⟨hp, hk⟩
      exact ⟨Or.inl hp, hk⟩
    · rintro ⟨hp | hp, hk⟩
      · exact ⟨hp, hk⟩
      · exact absurd hp.symm hne

private def ScanInv (code : Slice x64_ir.MInsn) (size : Std.Usize)
    (x : alloc.vec.Vec Bool × alloc.vec.Vec Bool × Std.Usize) : Prop :=
  x.2.2.val ≤ code.val.length ∧
  x.1.val.length = size.val ∧ x.2.1.val.length = size.val ∧
  (∀ (k : Nat), x.1.val[k]? = some true ↔
    ((∃ (j : Nat) (insn : x64_ir.MInsn) (n : Std.U32), j < x.2.2.val ∧ code.val[j]? = some insn ∧
      targetSlot insn = some n ∧ n.val = k) ∧ k < size.val)) ∧
  (∀ (k : Nat), x.2.1.val[k]? = some true ↔
    ((∃ (j : Nat) (insn : x64_ir.MInsn) (n : Std.U32), j < x.2.2.val ∧ code.val[j]? = some insn ∧
      labelSlot insn = some n ∧ n.val = k) ∧ k < size.val))

private theorem scan_loop_ok {code : Slice x64_ir.MInsn} {size : Std.Usize}
    {v : alloc.vec.Vec Bool} {t l : alloc.vec.Vec Bool}
    (hv : v.val = List.replicate size.val false)
    (h : x64_check.scan_loop code size v v 0#usize = ok (t, l)) :
    (∀ (k : Nat), t.val[k]? = some true ↔
      ((∃ (j : Nat) (insn : x64_ir.MInsn) (n : Std.U32), code.val[j]? = some insn ∧ targetSlot insn = some n ∧
        n.val = k) ∧ k < size.val)) ∧
    (∀ (k : Nat), l.val[k]? = some true ↔
      ((∃ (j : Nat) (insn : x64_ir.MInsn) (n : Std.U32), code.val[j]? = some insn ∧ labelSlot insn = some n ∧
        n.val = k) ∧ k < size.val)) := by
  unfold x64_check.scan_loop at h
  have hinit : ScanInv code size (v, v, 0#usize) := by
    refine ⟨by simp, by simp [hv], by simp [hv], fun k => ?_, fun k => ?_⟩ <;>
      · simp only [hv, List.getElem?_replicate]
        constructor
        · intro hc; split at hc <;> simp at hc
        · rintro ⟨⟨j, insn, n, hj, -⟩, -⟩
          simp at hj
  refine loop_ok_induction _ (ScanInv code size)
    (fun y => (∀ (k : Nat), y.1.val[k]? = some true ↔
        ((∃ (j : Nat) (insn : x64_ir.MInsn) (n : Std.U32), code.val[j]? = some insn ∧ targetSlot insn = some n ∧
          n.val = k) ∧ k < size.val)) ∧
      (∀ (k : Nat), y.2.val[k]? = some true ↔
        ((∃ (j : Nat) (insn : x64_ir.MInsn) (n : Std.U32), code.val[j]? = some insn ∧ labelSlot insn = some n ∧
          n.val = k) ∧ k < size.val)))
    ?_ _ _ hinit h
  rintro ⟨tv, lv, i⟩ hinv res hb
  obtain ⟨hi, htl, hll, hti, hli⟩ := hinv
  dsimp only at hi htl hll hti hli
  simp only at hb
  unfold x64_check.scan_loop.body at hb
  simp only [Slice.len] at hb
  split at hb
  · rename_i hlt
    have hival : i.val < code.val.length := by simpa [Slice.length] using usize_lt hlt
    obtain ⟨insn, hinsn, hb0⟩ := bind_eq_ok hb
    have hinsnv := (slice_index_usize_eq_ok hinsn).2
    obtain ⟨p, hp, hb1⟩ := bind_eq_ok hb0
    obtain ⟨labelled, slot⟩ := p
    obtain ⟨lv1, hlv1, hb2⟩ := bind_eq_ok hb1
    obtain ⟨q, hq, hb3⟩ := bind_eq_ok hb2
    obtain ⟨kind, target⟩ := q
    obtain ⟨tv1, htv1, hb4⟩ := bind_eq_ok hb3
    obtain ⟨i2, hi2, hb5⟩ := bind_eq_ok hb4
    simp only [ok.injEq] at hb5
    subst hb5
    have hone : (1#usize : Std.Usize).val = 1 := by simp
    have hi2v : i2.val = i.val + 1 := by rw [usize_add_eq_ok hi2, hone]
    -- what the step at `i` adds, for either table
    have hstep : ∀ (f : x64_ir.MInsn → Option Std.U32) (k : Nat),
        (∃ (j : Nat) (insn' : x64_ir.MInsn) (n : Std.U32), j < i.val + 1 ∧ code.val[j]? = some insn' ∧ f insn' = some n ∧
          n.val = k) ↔
        ((∃ (j : Nat) (insn' : x64_ir.MInsn) (n : Std.U32), j < i.val ∧ code.val[j]? = some insn' ∧ f insn' = some n ∧
          n.val = k) ∨ (∃ n, f insn = some n ∧ n.val = k)) := by
      intro f k
      constructor
      · rintro ⟨j, insn', n, hj, hj2, hf, hn⟩
        by_cases hje : j = i.val
        · subst hje
          rw [hinsnv] at hj2
          cases hj2
          exact Or.inr ⟨n, hf, hn⟩
        · exact Or.inl ⟨j, insn', n, by omega, hj2, hf, hn⟩
      · rintro (⟨j, insn', n, hj, hj2, hf, hn⟩ | ⟨n, hf, hn⟩)
        · exact ⟨j, insn', n, by omega, hj2, hf, hn⟩
        · exact ⟨i.val, insn, n, by omega, hinsnv, hf, hn⟩
    -- the label table
    have hL : lv1.val.length = size.val ∧ (∀ (k : Nat), lv1.val[k]? = some true ↔
        ((∃ (j : Nat) (insn' : x64_ir.MInsn) (n : Std.U32), j < i.val + 1 ∧ code.val[j]? = some insn' ∧
          labelSlot insn' = some n ∧ n.val = k) ∧ k < size.val)) := by
      split at hlv1
      · rename_i hlab
        obtain ⟨c2, hc2, hlv1a⟩ := bind_eq_ok hlv1
        have hc2v : c2.val = slot.val := by
          simp only [lift, ok.injEq] at hc2; subst hc2; simp
        have hslot : labelSlot insn = some slot :=
          ((label_of_spec hp).resolve_right (by simp [hlab])).2
        split at hlv1a
        · rename_i hsz
          have hsv : slot.val < size.val := by rw [← hc2v]; exact usize_lt hsz
          obtain ⟨c3, hc3, hlv1b⟩ := bind_eq_ok hlv1a
          have hc3v : c3.val = slot.val := by
            simp only [lift, ok.injEq] at hc3; subst hc3; simp
          obtain ⟨pr, hpr, hlv1c⟩ := bind_eq_ok hlv1b
          obtain ⟨y, back⟩ := pr
          obtain ⟨-, hback⟩ := vec_index_mut_eq_ok hpr
          have hlv1d : ok (back true) = ok lv1 := hlv1c
          simp only [ok.injEq] at hlv1d
          subst hback
          subst hlv1d
          refine ⟨by simp [hll], fun k => ?_⟩
          simp only [alloc.vec.Vec.set_val_eq, hc3v]
          rw [list_set_true hll hsv hli k, hstep labelSlot k]
          constructor
          · rintro ⟨hc | hc, hk⟩
            · exact ⟨Or.inl hc, hk⟩
            · exact ⟨Or.inr ⟨slot, hslot, hc.symm⟩, hk⟩
          · rintro ⟨hc | ⟨n, hn1, hn2⟩, hk⟩
            · exact ⟨Or.inl hc, hk⟩
            · rw [hslot] at hn1
              cases hn1
              exact ⟨Or.inr hn2.symm, hk⟩
        · rename_i hsz
          have hsv : size.val ≤ slot.val := by rw [← hc2v]; exact usize_not_lt hsz
          simp only [ok.injEq] at hlv1a
          subst hlv1a
          refine ⟨hll, fun k => ?_⟩
          rw [hli k, hstep labelSlot k]
          constructor
          · rintro ⟨hc, hk⟩
            exact ⟨Or.inl hc, hk⟩
          · rintro ⟨hc | ⟨n, hn1, hn2⟩, hk⟩
            · exact ⟨hc, hk⟩
            · rw [hslot] at hn1
              cases hn1
              omega
      · rename_i hlab
        have hnone : labelSlot insn = none :=
          ((label_of_spec hp).resolve_left (by simp [hlab])).2
        simp only [ok.injEq] at hlv1
        subst hlv1
        refine ⟨hll, fun k => ?_⟩
        rw [hli k, hstep labelSlot k]
        constructor
        · rintro ⟨hc, hk⟩
          exact ⟨Or.inl hc, hk⟩
        · rintro ⟨hc | ⟨n, hn1, -⟩, hk⟩
          · exact ⟨hc, hk⟩
          · rw [hnone] at hn1; exact absurd hn1 (by simp)
    -- the target table
    have hT : tv1.val.length = size.val ∧ (∀ (k : Nat), tv1.val[k]? = some true ↔
        ((∃ (j : Nat) (insn' : x64_ir.MInsn) (n : Std.U32), j < i.val + 1 ∧ code.val[j]? = some insn' ∧
          targetSlot insn' = some n ∧ n.val = k) ∧ k < size.val)) := by
      split at htv1
      · rename_i hkind
        obtain ⟨c2, hc2, htv1a⟩ := bind_eq_ok htv1
        have hc2v : c2.val = target.val := by
          simp only [lift, ok.injEq] at hc2; subst hc2; simp
        have hslot : targetSlot insn = some target :=
          ((branch_target_spec hq).resolve_right (by simp [hkind])).2
        split at htv1a
        · rename_i hsz
          have hsv : target.val < size.val := by rw [← hc2v]; exact usize_lt hsz
          obtain ⟨c3, hc3, htv1b⟩ := bind_eq_ok htv1a
          have hc3v : c3.val = target.val := by
            simp only [lift, ok.injEq] at hc3; subst hc3; simp
          obtain ⟨pr, hpr, htv1c⟩ := bind_eq_ok htv1b
          obtain ⟨y, back⟩ := pr
          obtain ⟨-, hback⟩ := vec_index_mut_eq_ok hpr
          have htv1d : ok (back true) = ok tv1 := htv1c
          simp only [ok.injEq] at htv1d
          subst hback
          subst htv1d
          refine ⟨by simp [htl], fun k => ?_⟩
          simp only [alloc.vec.Vec.set_val_eq, hc3v]
          rw [list_set_true htl hsv hti k, hstep targetSlot k]
          constructor
          · rintro ⟨hc | hc, hk⟩
            · exact ⟨Or.inl hc, hk⟩
            · exact ⟨Or.inr ⟨target, hslot, hc.symm⟩, hk⟩
          · rintro ⟨hc | ⟨n, hn1, hn2⟩, hk⟩
            · exact ⟨Or.inl hc, hk⟩
            · rw [hslot] at hn1
              cases hn1
              exact ⟨Or.inr hn2.symm, hk⟩
        · rename_i hsz
          have hsv : size.val ≤ target.val := by rw [← hc2v]; exact usize_not_lt hsz
          simp only [ok.injEq] at htv1a
          subst htv1a
          refine ⟨htl, fun k => ?_⟩
          rw [hti k, hstep targetSlot k]
          constructor
          · rintro ⟨hc, hk⟩
            exact ⟨Or.inl hc, hk⟩
          · rintro ⟨hc | ⟨n, hn1, hn2⟩, hk⟩
            · exact ⟨hc, hk⟩
            · rw [hslot] at hn1
              cases hn1
              omega
      · rename_i hkind
        have hnone : targetSlot insn = none :=
          ((branch_target_spec hq).resolve_left (by simp [hkind])).2
        simp only [ok.injEq] at htv1
        subst htv1
        refine ⟨htl, fun k => ?_⟩
        rw [hti k, hstep targetSlot k]
        constructor
        · rintro ⟨hc, hk⟩
          exact ⟨Or.inl hc, hk⟩
        · rintro ⟨hc | ⟨n, hn1, -⟩, hk⟩
          · exact ⟨hc, hk⟩
          · rw [hnone] at hn1; exact absurd hn1 (by simp)
    refine ⟨by dsimp only; omega, hT.1, hL.1, ?_, ?_⟩
    · intro k; dsimp only; rw [hT.2 k, hi2v]
    · intro k; dsimp only; rw [hL.2 k, hi2v]
  · rename_i hge
    simp only [ok.injEq] at hb
    subst hb
    have hiv : code.val.length ≤ i.val := by simpa [Slice.length] using usize_not_lt hge
    refine ⟨fun k => ?_, fun k => ?_⟩
    · rw [hti k]
      constructor
      · rintro ⟨⟨j, insn, n, -, h2, h3, h4⟩, hk⟩
        exact ⟨⟨j, insn, n, h2, h3, h4⟩, hk⟩
      · rintro ⟨⟨j, insn, n, h2, h3, h4⟩, hk⟩
        have := List.getElem?_eq_some_iff.mp h2 |>.1
        exact ⟨⟨j, insn, n, by omega, h2, h3, h4⟩, hk⟩
    · rw [hli k]
      constructor
      · rintro ⟨⟨j, insn, n, -, h2, h3, h4⟩, hk⟩
        exact ⟨⟨j, insn, n, h2, h3, h4⟩, hk⟩
      · rintro ⟨⟨j, insn, n, h2, h3, h4⟩, hk⟩
        have := List.getElem?_eq_some_iff.mp h2 |>.1
        exact ⟨⟨j, insn, n, by omega, h2, h3, h4⟩, hk⟩


private theorem vec_index_total {α : Type} (v : alloc.vec.Vec α) (i : Std.Usize)
    (h : i.val < v.val.length) :
    ∃ x, alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i = ok x := by
  rw [alloc.vec.Vec.index_slice_index]
  unfold alloc.vec.Vec.index_usize
  rw [show v[i.val]? = v.val[i.val]? from rfl]
  cases hg : v.val[i.val]? with
  | none =>
    rw [List.getElem?_eq_none_iff] at hg
    omega
  | some x => exact ⟨x, by simp⟩

private theorem is_target_total (labels : x64_check.Labels) (n : Std.U32) :
    ∃ b, x64_check.is_target labels n = ok b := by
  unfold x64_check.is_target
  simp only [lift, bind_tc_ok]
  split
  · rename_i hlt
    exact vec_index_total _ _ (by simpa [alloc.vec.Vec.len] using usize_lt hlt)
  · exact ⟨false, rfl⟩

private theorem is_labelled_total (labels : x64_check.Labels) (n : Std.U32) :
    ∃ b, x64_check.is_labelled labels n = ok b := by
  unfold x64_check.is_labelled
  simp only [lift, bind_tc_ok]
  split
  · rename_i hlt
    exact vec_index_total _ _ (by simpa [alloc.vec.Vec.len] using usize_lt hlt)
  · exact ⟨false, rfl⟩

private theorem from_elem_eq_ok {α : Type} {inst : core.clone.Clone α} {x : α} {n : Std.Usize}
    {v : alloc.vec.Vec α} (hc : inst.clone x = ok x)
    (h : alloc.vec.from_elem inst x n = ok v) : v.val = List.replicate n.val x := by
  have := alloc.vec.from_elem_spec inst x n hc
  rw [h] at this
  exact this.1

/-- The two tables and the trailer flag `scan` returns. -/
private theorem scan_spec {code : Slice x64_ir.MInsn} {labels : x64_check.Labels}
    (h : x64_check.scan code = ok labels) :
    (∀ (k : Nat), labels.is_target.val[k]? = some true ↔
      ∃ (j : Nat) (insn : x64_ir.MInsn) (n : Std.U32), code.val[j]? = some insn ∧
        targetSlot insn = some n ∧ n.val = k) ∧
    (∀ (k : Nat), labels.has_label.val[k]? = some true ↔
      ∃ (j : Nat) (insn : x64_ir.MInsn) (n : Std.U32), code.val[j]? = some insn ∧
        labelSlot insn = some n ∧ n.val = k) ∧
    (labels.trailer = true ↔ HasTrailer code.val) := by
  unfold x64_check.scan at h
  obtain ⟨m, hm, h1⟩ := bind_eq_ok h
  obtain ⟨i1, hi1, h2⟩ := bind_eq_ok h1
  have hi1v : i1.val = m.val := by
    simp only [lift, ok.injEq] at hi1; subst hi1; simp
  obtain ⟨size, hsize, h3⟩ := bind_eq_ok h2
  have hone : (1#usize : Std.Usize).val = 1 := by simp
  have hsizev : size.val = m.val + 1 := by rw [usize_add_eq_ok hsize, hi1v, hone]
  obtain ⟨v, hvv, h4⟩ := bind_eq_ok h3
  have hv := from_elem_eq_ok (inst := core.clone.CloneBool) rfl hvv
  obtain ⟨pr, hpr, h5⟩ := bind_eq_ok h4
  obtain ⟨tv, lv⟩ := pr
  obtain ⟨tr, htr, h6⟩ := bind_eq_ok h5
  simp only [ok.injEq] at h6
  subst h6
  obtain ⟨hmaxL, hmaxT⟩ := max_named_slot_ok hm
  obtain ⟨hT, hL⟩ := scan_loop_ok hv hpr
  refine ⟨fun k => ?_, fun k => ?_, has_trailer_spec htr⟩
  · rw [hT k]
    constructor
    · rintro ⟨hc, -⟩; exact hc
    · rintro ⟨j, insn, n, h1, h2, h3⟩
      exact ⟨⟨j, insn, n, h1, h2, h3⟩, by have := hmaxT j insn n h1 h2; omega⟩
  · rw [hL k]
    constructor
    · rintro ⟨hc, -⟩; exact hc
    · rintro ⟨j, insn, n, h1, h2, h3⟩
      exact ⟨⟨j, insn, n, h1, h2, h3⟩, by have := hmaxL j insn n h1 h2; omega⟩

/-- A slot is a branch target exactly when some `jcc` or `jmp` names it. -/
theorem scan_is_target {code : Slice x64_ir.MInsn} {labels : x64_check.Labels}
    (hs : x64_check.scan code = ok labels) (n : Std.U32) :
    x64_check.is_target labels n = ok true ↔
      ∃ (i : Nat) (insn : x64_ir.MInsn), i < code.val.length ∧
        code.val[i]? = some insn ∧ targetSlot insn = some n := by
  have hspec := (scan_spec hs).1
  have key : ∀ b : Bool, x64_check.is_target labels n = ok b → (b = true ↔
      ∃ (i : Nat) (insn : x64_ir.MInsn), i < code.val.length ∧
        code.val[i]? = some insn ∧ targetSlot insn = some n) := by
    intro b h
    unfold x64_check.is_target at h
    simp only [lift, bind_tc_ok] at h
    split at h
    · rename_i hlt
      obtain ⟨-, hval⟩ := vec_index_eq_ok h
      simp only [Std.U32.cast_Usize_val_eq] at hval
      constructor
      · rintro rfl
        obtain ⟨j, insn, n', h1, h2, h3⟩ := hspec n.val |>.mp hval
        have : n' = n := u32_eq_iff.mpr h3
        subst this
        exact ⟨j, insn, List.getElem?_eq_some_iff.mp h1 |>.1, h1, h2⟩
      · rintro ⟨i, insn, -, h1, h2⟩
        have := hspec n.val |>.mpr ⟨i, insn, n, h1, h2, rfl⟩
        rw [hval] at this
        simpa using this.symm
    · rename_i hge
      simp only [ok.injEq] at h
      subst h
      have hlen : labels.is_target.val.length ≤ n.val := by
        simpa [alloc.vec.Vec.len] using usize_not_lt hge
      simp only [Bool.false_eq_true, false_iff]
      rintro ⟨i, insn, -, h1, h2⟩
      have := hspec n.val |>.mpr ⟨i, insn, n, h1, h2, rfl⟩
      have := List.getElem?_eq_some_iff.mp this |>.1
      omega
  constructor
  · intro h; exact (key true h).mp rfl
  · intro hp
    obtain ⟨b, hb⟩ := is_target_total labels n
    rw [(key b hb).mpr hp] at hb
    exact hb

/-- A slot is labelled exactly when some `PcLabel` marks it. -/
theorem scan_is_labelled {code : Slice x64_ir.MInsn} {labels : x64_check.Labels}
    (hs : x64_check.scan code = ok labels) (n : Std.U32) :
    x64_check.is_labelled labels n = ok true ↔
      ∃ (i : Nat), i < code.val.length ∧ code.val[i]? = some (.PcLabel n) := by
  have hspec := (scan_spec hs).2.1
  have key : ∀ b : Bool, x64_check.is_labelled labels n = ok b → (b = true ↔
      ∃ (i : Nat), i < code.val.length ∧ code.val[i]? = some (.PcLabel n)) := by
    intro b h
    unfold x64_check.is_labelled at h
    simp only [lift, bind_tc_ok] at h
    split at h
    · rename_i hlt
      obtain ⟨-, hval⟩ := vec_index_eq_ok h
      simp only [Std.U32.cast_Usize_val_eq] at hval
      constructor
      · rintro rfl
        obtain ⟨j, insn, n', h1, h2, h3⟩ := hspec n.val |>.mp hval
        have hn : n' = n := u32_eq_iff.mpr h3
        subst hn
        rw [labelSlot_eq_some h2] at h1
        exact ⟨j, List.getElem?_eq_some_iff.mp h1 |>.1, h1⟩
      · rintro ⟨i, -, h1⟩
        have := hspec n.val |>.mpr ⟨i, .PcLabel n, n, h1, rfl, rfl⟩
        rw [hval] at this
        simpa using this.symm
    · rename_i hge
      simp only [ok.injEq] at h
      subst h
      have hlen : labels.has_label.val.length ≤ n.val := by
        simpa [alloc.vec.Vec.len] using usize_not_lt hge
      simp only [Bool.false_eq_true, false_iff]
      rintro ⟨i, -, h1⟩
      have := hspec n.val |>.mpr ⟨i, .PcLabel n, n, h1, rfl, rfl⟩
      have := List.getElem?_eq_some_iff.mp this |>.1
      omega
  constructor
  · intro h; exact (key true h).mp rfl
  · intro hp
    obtain ⟨b, hb⟩ := is_labelled_total labels n
    rw [(key b hb).mpr hp] at hb
    exact hb

/-- The `trailer` flag is `HasTrailer`. -/
theorem scan_trailer {code : Slice x64_ir.MInsn} {labels : x64_check.Labels}
    (hs : x64_check.scan code = ok labels) : labels.trailer = true ↔ HasTrailer code.val :=
  (scan_spec hs).2.2


/-! ## The structural rules -/

private theorem u32_bne_eq {x y : Std.U32} (h : ¬ (x != y) = true) : x = y :=
  u32_eq_iff.mpr (by simpa using h)

private theorem branch_continue {r : core.result.Result Unit x64_check.Unsafe}
    {cf : core.ops.control_flow.ControlFlow
      (core.result.Result core.convert.Infallible x64_check.Unsafe) Unit}
    (h : core.result.Result.Insts.CoreOpsTry.branch r = ok cf) :
    (∃ u, r = .Ok u ∧ cf = .Continue u) ∨ (∃ e, r = .Err e ∧ cf = .Break (.Err e)) := by
  cases r <;> simp_all [core.result.Result.Insts.CoreOpsTry.branch]

private theorem no_break {e : x64_check.Unsafe} {st1 post : x64_check.State}
    (h : (do
      let r1 ←
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
          Unit (core.convert.FromSame x64_check.Unsafe) (core.result.Result.Err e)
      ok (r1, st1)) = ok (core.result.Result.Ok (), post)) : False := by
  simp [core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual] at h

/-- A label a branch can land on is an entry: a live path into it arrives at
depth one with the frame register intact, and everything else is forgotten.
A label nothing branches to is a position and nothing more. -/
theorem label_step_spec {labels : x64_check.Labels} {slot : Std.U32} {index : Std.Usize}
    {pc : Std.U32} {pre post : x64_check.State}
    (h : x64_check.label_step labels slot index pc pre = ok (.Ok (), post)) :
    (x64_check.is_target labels slot = ok false ∧ post = pre) ∨
    (x64_check.is_target labels slot = ok true ∧
      (pre.alive = true → pre.depth = 1#u32 ∧ tagAt pre 15 = x64_check.Tag.Fp) ∧
      EnterShaped post) := by
  unfold x64_check.label_step at h
  obtain ⟨b, hb, h1⟩ := bind_eq_ok h
  split at h1
  · rename_i hbt
    subst hbt
    refine Or.inr ⟨hb, ?_, ?_⟩ <;> split at h1
    · rename_i hal
      split at h1
      · simp [x64_check.reject] at h1
      · rename_i hd
        obtain ⟨fi, hfi, h2⟩ := bind_eq_ok h1
        split at h2
        · rename_i hfit
          exact fun _ => ⟨u32_bne_eq hd, (frame_intact_spec hfi).mp hfit⟩
        · simp [x64_check.reject] at h2
    · rename_i hal
      exact fun hc => absurd hc (by simpa using hal)
    · rename_i hal
      split at h1
      · simp [x64_check.reject] at h1
      · obtain ⟨fi, hfi, h2⟩ := bind_eq_ok h1
        split at h2
        · obtain ⟨st1, hst1, h3⟩ := bind_eq_ok h2
          simp only [ok.injEq, Prod.mk.injEq, true_and] at h3
          subst h3
          exact enter_spec hst1
        · simp [x64_check.reject] at h2
    · obtain ⟨st1, hst1, h3⟩ := bind_eq_ok h1
      simp only [ok.injEq, Prod.mk.injEq, true_and] at h3
      subst h3
      exact enter_spec hst1
  · rename_i hbf
    simp only [Bool.not_eq_true] at hbf
    subst hbf
    simp only [ok.injEq, Prod.mk.injEq, true_and] at h1
    exact Or.inl ⟨hb, h1.symm⟩

/-- A prologue stands at a dead state, at a skippable one at depth one with
the frame register intact, or at a plain one at depth zero; it enters. -/
theorem prologue_step_spec {skip : Bool} {index : Std.Usize} {pc : Std.U32}
    {pre post : x64_check.State}
    (h : x64_check.prologue_step skip index pc pre = ok (.Ok (), post)) :
    (pre.alive = true → (skip = true → pre.depth = 1#u32 ∧ tagAt pre 15 = x64_check.Tag.Fp) ∧
      (skip = false → pre.depth = 0#u32)) ∧ EnterShaped post := by
  unfold x64_check.prologue_step at h
  obtain ⟨okb, hok, h1⟩ := bind_eq_ok h
  split at h1
  · rename_i hokt
    subst hokt
    obtain ⟨st1, hst1, h2⟩ := bind_eq_ok h1
    simp only [ok.injEq, Prod.mk.injEq, true_and] at h2
    subst h2
    refine ⟨fun hal => ?_, enter_spec hst1⟩
    unfold x64_check.prologue_ok at hok
    simp only [hal, if_true] at hok
    split at hok
    · rename_i hsk
      split at hok
      · simp at hok
      · rename_i hd
        exact ⟨fun _ => ⟨u32_bne_eq hd, (frame_intact_spec hok).mp rfl⟩,
          fun hc => absurd hsk (by simp [hc])⟩
    · rename_i hsk
      simp only [Bool.not_eq_true] at hsk
      split at hok
      · rename_i hd
        exact ⟨fun hc => absurd hsk (by simp [hc]), fun _ => hd⟩
      · simp at hok
  · simp [x64_check.reject] at h1

/-- A branch needs the stack as the epilogue will need it, the frame register
intact, and somewhere to land: a labelled slot, or the trailer's epilogue.
An unconditional one kills the walk. -/
theorem branch_step_spec {labels : x64_check.Labels} {target : x64_ir.Target}
    {unconditional : Bool} {index : Std.Usize} {pc : Std.U32} {pre post : x64_check.State}
    (h : x64_check.branch_step labels target unconditional index pc pre = ok (.Ok (), post)) :
    (pre.alive = true → pre.depth = 1#u32 ∧ tagAt pre 15 = x64_check.Tag.Fp) ∧
    (∀ n, target = .Pc n → x64_check.is_labelled labels n = ok true) ∧
    (target = .Exit → labels.trailer = true) ∧
    (∀ k, tagAt post k = tagAt pre k) ∧ post.depth = pre.depth ∧ post.group = pre.group ∧
    (unconditional = true → post.alive = false) ∧
    (unconditional = false → post.alive = pre.alive) := by
  have hland : ∀ (kind : Std.U8) (slot : Std.U32) (landable : Bool),
      x64_check.target_of target = ok (kind, slot) →
      (if kind = 1#u8 then x64_check.is_labelled labels slot else ok labels.trailer)
        = ok landable → landable = true →
      (∀ n, target = .Pc n → x64_check.is_labelled labels n = ok true) ∧
      (target = .Exit → labels.trailer = true) := by
    intro kind slot landable ht hl hlt
    subst hlt
    cases target <;>
      simp only [x64_check.target_of, ok.injEq, Prod.mk.injEq] at ht <;>
      obtain ⟨rfl, rfl⟩ := ht <;> split at hl
    · exact ⟨fun n hn => by cases hn; exact hl, fun hc => by simp at hc⟩
    · rename_i hk
      exact absurd rfl hk
    · rename_i hk
      exact absurd hk (by decide)
    · simp only [ok.injEq] at hl
      exact ⟨fun n hn => by simp at hn, fun _ => hl⟩
  unfold x64_check.branch_step at h
  split at h
  · rename_i hal
    split at h
    · simp [x64_check.reject] at h
    · rename_i hd
      obtain ⟨fi, hfi, h1⟩ := bind_eq_ok h
      split at h1
      · rename_i hfit
        obtain ⟨p, hp, h2⟩ := bind_eq_ok h1
        obtain ⟨kind, slot⟩ := p
        obtain ⟨landable, hlb, h3⟩ := bind_eq_ok h2
        split at h3
        · rename_i hlt
          obtain ⟨hl1, hl2⟩ := hland kind slot landable hp hlb hlt
          split at h3
          · rename_i huc
            simp only [ok.injEq, Prod.mk.injEq, true_and] at h3
            subst h3
            exact ⟨fun _ => ⟨u32_bne_eq hd, (frame_intact_spec hfi).mp hfit⟩, hl1, hl2,
              fun _ => rfl, rfl, rfl, fun _ => rfl, fun hc => absurd huc (by simp [hc])⟩
          · rename_i huc
            simp only [Bool.not_eq_true] at huc
            simp only [ok.injEq, Prod.mk.injEq, true_and] at h3
            subst h3
            exact ⟨fun _ => ⟨u32_bne_eq hd, (frame_intact_spec hfi).mp hfit⟩, hl1, hl2,
              fun _ => rfl, rfl, rfl, fun hc => absurd hc (by simp [huc]), fun _ => rfl⟩
        · simp [x64_check.reject] at h3
      · simp [x64_check.reject] at h1
  · rename_i hal
    simp only [Bool.not_eq_true] at hal
    obtain ⟨p, hp, h1⟩ := bind_eq_ok h
    obtain ⟨kind, slot⟩ := p
    obtain ⟨landable, hlb, h2⟩ := bind_eq_ok h1
    split at h2
    · rename_i hlt
      obtain ⟨hl1, hl2⟩ := hland kind slot landable hp hlb hlt
      have hpost : post = pre := by
        split at h2 <;> (simp only [ok.injEq, Prod.mk.injEq, true_and] at h2; exact h2.symm)
      subst hpost
      exact ⟨fun hc => absurd hc (by simp [hal]), hl1, hl2, fun _ => rfl, rfl, rfl,
        fun _ => hal, fun _ => rfl⟩
    · simp [x64_check.reject] at h2

/-- The retpoline is admitted only as part of a trailer; nothing follows it. -/
theorem retpoline_step_spec {code : Slice x64_ir.MInsn} {index : Std.Usize} {pc : Std.U32}
    {pre post : x64_check.State}
    (h : x64_check.retpoline_step code index pc pre = ok (.Ok (), post)) :
    TrailerAt code.val index.val ∧ post = { pre with alive := false } := by
  unfold x64_check.retpoline_step at h
  obtain ⟨b, hb, h1⟩ := bind_eq_ok h
  split at h1
  · rename_i hbt
    simp only [ok.injEq, Prod.mk.injEq, true_and] at h1
    exact ⟨(trailer_at_spec hb).mp hbt, h1.symm⟩
  · simp [x64_check.reject] at h1

/-- The trailer's two data macros stand at their fixed distance behind the
retpoline that owns them, and nowhere else. -/
theorem data_step_spec {code : Slice x64_ir.MInsn} {index : Std.Usize} {pc : Std.U32}
    {behind : Std.Usize} (h : x64_check.data_step code index pc behind = ok (.Ok ())) :
    behind.val ≤ index.val ∧ TrailerAt code.val (index.val - behind.val) := by
  unfold x64_check.data_step at h
  split at h
  · rename_i hge
    obtain ⟨i, hi, h1⟩ := bind_eq_ok h
    obtain ⟨b, hb, h2⟩ := bind_eq_ok h1
    obtain ⟨hiv, hle⟩ := usize_sub_eq_ok hi
    split at h2
    · rename_i hbt
      exact ⟨hle, hiv ▸ (trailer_at_spec hb).mp hbt⟩
    · simp [x64_check.reject] at h2
  · simp [x64_check.reject] at h


/-! ## The value rules

Every one of these is about a live walk; a dead one checks nothing, which is
`live_step_dead`. -/

/-- Whether a register-to-register ALU operation writes its destination. -/
def AluRRWrites : x64_ir.AluRR → Bool
  | .Cmp => false
  | .Test => false
  | _ => true

/-- Whether a register-with-immediate ALU operation writes its destination. -/
def AluRIWrites : x64_ir.AluRI → Bool
  | .Cmp => false
  | .Test => false
  | _ => true

/-- The width an atomic operates at. -/
def atomicSize (w64 : Bool) : Nat := if w64 then 8 else 4

theorem alu_rr_writes_spec (op : x64_ir.AluRR) :
    x64_check.alu_rr_writes op = ok (AluRRWrites op) := by
  cases op <;> rfl

theorem alu_ri_writes_spec (op : x64_ir.AluRI) :
    x64_check.alu_ri_writes op = ok (AluRIWrites op) := by
  cases op <;> rfl

private theorem atomic_size_spec (w64 : Bool) {n : Std.U32}
    (h : x64_check.atomic_size w64 = ok n) : n.val = atomicSize w64 := by
  cases w64 <;> simp only [x64_check.atomic_size, Bool.false_eq_true, if_false, if_true,
      ok.injEq] at h <;> rw [← h] <;> simp [atomicSize]

/-- A dead walk checks nothing about values. -/
theorem live_step_dead {cfg : x64_ir.Cfg} {insn : x64_ir.MInsn} {index : Std.Usize}
    {pc : Std.U32} {pre : x64_check.State} (h : pre.alive = false) :
    x64_check.live_step cfg insn index pc pre = ok (.Ok (), pre) := by
  unfold x64_check.live_step
  simp [h]

theorem live_step_Epilogue_spec {cfg : x64_ir.Cfg} {index : Std.Usize} {pc : Std.U32}
    {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg .Epilogue index pc pre = ok (.Ok (), post)) :
    pre.depth = 1#u32 ∧ tagAt pre 15 = x64_check.Tag.Fp ∧ post = { pre with alive := false } := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  split at h
  · simp [x64_check.reject] at h
  · rename_i hd
    obtain ⟨fi, hfi, h1⟩ := bind_eq_ok h
    split at h1
    · rename_i hfit
      simp only [ok.injEq, Prod.mk.injEq, true_and] at h1
      exact ⟨u32_bne_eq hd, (frame_intact_spec hfi).mp hfit, h1.symm⟩
    · simp [x64_check.reject] at h1

theorem live_step_Alu_spec {cfg : x64_ir.Cfg} {w64 : Bool} {op : x64_ir.AluRR} {src dst : Std.U8}
    {index : Std.Usize} {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.Alu w64 op src dst) index pc pre = ok (.Ok (), post)) :
    (AluRRWrites op = true → Writable dst.val ∧ SetsTop pre post (· = dst.val)) ∧
    (AluRRWrites op = false → post = pre) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true, alu_rr_writes_spec, bind_tc_ok] at h
  split at h
  · rename_i hw
    exact ⟨fun _ => write_spec h, fun hc => by rw [hw] at hc; simp at hc⟩
  · rename_i hw
    simp only [Bool.not_eq_true] at hw
    simp only [ok.injEq, Prod.mk.injEq, true_and] at h
    exact ⟨fun hc => by rw [hw] at hc; simp at hc, fun _ => h.symm⟩

theorem live_step_AluImm_spec {cfg : x64_ir.Cfg} {w64 : Bool} {op : x64_ir.AluRI} {dst : Std.U8}
    {imm : Std.I32} {index : Std.Usize} {pc : Std.U32} {pre post : x64_check.State}
    (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.AluImm w64 op dst imm) index pc pre = ok (.Ok (), post)) :
    (AluRIWrites op = true → Writable dst.val ∧ SetsTop pre post (· = dst.val)) ∧
    (AluRIWrites op = false → post = pre) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true, alu_ri_writes_spec, bind_tc_ok] at h
  split at h
  · rename_i hw
    exact ⟨fun _ => write_spec h, fun hc => by rw [hw] at hc; simp at hc⟩
  · rename_i hw
    simp only [Bool.not_eq_true] at hw
    simp only [ok.injEq, Prod.mk.injEq, true_and] at h
    exact ⟨fun hc => by rw [hw] at hc; simp at hc, fun _ => h.symm⟩

theorem live_step_ShiftImm_spec {cfg : x64_ir.Cfg} {w64 : Bool} {op : x64_ir.ShiftOp}
    {dst : Std.U8} {imm : Std.I32} {index : Std.Usize} {pc : Std.U32}
    {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.ShiftImm w64 op dst imm) index pc pre = ok (.Ok (), post)) :
    Writable dst.val ∧ SetsTop pre post (· = dst.val) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  exact write_spec h

theorem live_step_ShiftCl_spec {cfg : x64_ir.Cfg} {w64 : Bool} {op : x64_ir.ShiftOp}
    {dst : Std.U8} {index : Std.Usize} {pc : Std.U32} {pre post : x64_check.State}
    (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.ShiftCl w64 op dst) index pc pre = ok (.Ok (), post)) :
    Writable dst.val ∧ SetsTop pre post (· = dst.val) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  exact write_spec h

theorem live_step_Neg_spec {cfg : x64_ir.Cfg} {w64 : Bool} {dst : Std.U8} {index : Std.Usize}
    {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.Neg w64 dst) index pc pre = ok (.Ok (), post)) :
    Writable dst.val ∧ SetsTop pre post (· = dst.val) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  exact write_spec h

theorem live_step_MovSx_spec {cfg : x64_ir.Cfg} {from_ : Std.U8} {w64 : Bool}
    {src dst : Std.U8} {index : Std.Usize} {pc : Std.U32} {pre post : x64_check.State}
    (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.MovSx from_ w64 src dst) index pc pre = ok (.Ok (), post)) :
    Writable dst.val ∧ SetsTop pre post (· = dst.val) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  exact write_spec h

theorem live_step_Bswap_spec {cfg : x64_ir.Cfg} {w64 : Bool} {dst : Std.U8} {index : Std.Usize}
    {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.Bswap w64 dst) index pc pre = ok (.Ok (), post)) :
    Writable dst.val ∧ SetsTop pre post (· = dst.val) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  exact write_spec h

theorem live_step_Rol16_spec {cfg : x64_ir.Cfg} {dst : Std.U8} {index : Std.Usize}
    {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.Rol16 dst) index pc pre = ok (.Ok (), post)) :
    Writable dst.val ∧ SetsTop pre post (· = dst.val) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  exact write_spec h

theorem live_step_LoadImm_spec {cfg : x64_ir.Cfg} {dst : Std.U8} {imm : Std.I64}
    {index : Std.Usize} {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.LoadImm dst imm) index pc pre = ok (.Ok (), post)) :
    Writable dst.val ∧ SetsTop pre post (· = dst.val) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  exact write_spec h

theorem live_step_GuestFp_spec {cfg : x64_ir.Cfg} {dst : Std.U8} {index : Std.Usize}
    {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.GuestFp dst) index pc pre = ok (.Ok (), post)) :
    Writable dst.val ∧ SetsTop pre post (· = dst.val) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  exact write_spec h

theorem live_step_MulDivMod_spec {cfg : x64_ir.Cfg} {kind : x64_ir.MulDivKind}
    {w64 signed imm : Bool} {src dst : Std.U8} {d : Std.I32} {index : Std.Usize} {pc : Std.U32}
    {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.MulDivMod kind w64 signed imm src dst d) index pc pre
      = ok (.Ok (), post)) :
    pre.depth.val + 4 ≤ 16 ∧ Writable dst.val ∧
    SetsTop pre post (fun k => k = dst.val ∨ k = 0 ∨ k = 1 ∨ k = 2 ∨ k = 11) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  obtain ⟨db, hdb, h1⟩ := bind_eq_ok h
  split at h1
  · rename_i hdt
    have hdepth : pre.depth.val + 4 ≤ 16 := by
      have := (depth_ok_spec hdb).mp hdt
      simpa using this
    obtain ⟨⟨r1, s1⟩, hw1, h2⟩ := bind_eq_ok h1
    obtain ⟨cf1, hcf1, h3⟩ := bind_eq_ok h2
    rcases branch_continue hcf1 with ⟨u1, rfl, rfl⟩ | ⟨e1, rfl, rfl⟩
    case inr => exact (no_break h3).elim
    simp only at h3
    obtain ⟨⟨r2, s2⟩, hw2, h4⟩ := bind_eq_ok h3
    obtain ⟨cf2, hcf2, h5⟩ := bind_eq_ok h4
    rcases branch_continue hcf2 with ⟨u2, rfl, rfl⟩ | ⟨e2, rfl, rfl⟩
    case inr => exact (no_break h5).elim
    simp only at h5
    obtain ⟨⟨r3, s3⟩, hw3, h6⟩ := bind_eq_ok h5
    obtain ⟨cf3, hcf3, h7⟩ := bind_eq_ok h6
    rcases branch_continue hcf3 with ⟨u3, rfl, rfl⟩ | ⟨e3, rfl, rfl⟩
    case inr => exact (no_break h7).elim
    simp only at h7
    obtain ⟨⟨r4, s4⟩, hw4, h8⟩ := bind_eq_ok h7
    obtain ⟨cf4, hcf4, h9⟩ := bind_eq_ok h8
    rcases branch_continue hcf4 with ⟨u4, rfl, rfl⟩ | ⟨e4, rfl, rfl⟩
    case inr => exact (no_break h9).elim
    simp only at h9
    obtain ⟨hwd, b1⟩ := (SetsTop.refl pre).write hw1
    obtain ⟨-, b2⟩ := b1.write hw2
    obtain ⟨-, b3⟩ := b2.write hw3
    obtain ⟨-, b4⟩ := b3.write hw4
    obtain ⟨-, b5⟩ := b4.write h9
    refine ⟨hdepth, hwd, b5.mono (fun k => ?_)⟩
    simp only [x64_ir.RAX, x64_ir.RCX, x64_ir.RDX, x64_ir.R11]
    norm_num
    tauto
  · simp [x64_check.reject] at h1

theorem live_step_CheckedAddr_spec {cfg : x64_ir.Cfg} {src dst scratch : Std.U8}
    {offset : Std.I32} {size : Std.U32} {region : Std.U8} {index : Std.Usize} {pc : Std.U32}
    {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.CheckedAddr src dst scratch offset size region) index pc pre
      = ok (.Ok (), post)) :
    dst ≠ scratch ∧ dst.val ≠ 9 ∧ scratch.val ≠ 9 ∧ 1 ≤ size.val ∧ size.val ≤ 4096 ∧
    Writable dst.val ∧ Writable scratch.val ∧
    tagAt post dst.val =
      (if cfg.pointer_mask.val ≠ 0 then x64_check.Tag.Checked size else x64_check.Tag.Top) ∧
    tagAt post scratch.val = x64_check.Tag.Top ∧ tagAt post 9 = x64_check.Tag.Top ∧
    (∀ k, k ≠ dst.val → k ≠ scratch.val → k ≠ 9 → tagAt post k = tagAt pre k) ∧
    post.depth = pre.depth ∧ post.group = pre.group ∧ post.alive = pre.alive := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  split at h
  · simp [x64_check.reject] at h
  · rename_i hds
    split at h
    · simp [x64_check.reject] at h
    · rename_i hd9
      split at h
      · simp [x64_check.reject] at h
      · rename_i hs9
        split at h
        · simp [x64_check.reject] at h
        · rename_i hz
          split at h
          · simp [x64_check.reject] at h
          · rename_i hmax
            obtain ⟨⟨r1, s1⟩, hw1, h2⟩ := bind_eq_ok h
            obtain ⟨cf1, hcf1, h3⟩ := bind_eq_ok h2
            rcases branch_continue hcf1 with ⟨u1, rfl, rfl⟩ | ⟨e1, rfl, rfl⟩
            case inr => exact (no_break h3).elim
            simp only at h3
            obtain ⟨⟨r2, s2⟩, hw2, h4⟩ := bind_eq_ok h3
            obtain ⟨cf2, hcf2, h5⟩ := bind_eq_ok h4
            rcases branch_continue hcf2 with ⟨u2, rfl, rfl⟩ | ⟨e2, rfl, rfl⟩
            case inr => exact (no_break h5).elim
            simp only at h5
            obtain ⟨s3, hs3, h6⟩ := bind_eq_ok h5
            obtain ⟨chk, hchk, h7⟩ := bind_eq_ok h6
            obtain ⟨s4, hs4, h8⟩ := bind_eq_ok h7
            simp only [ok.injEq, Prod.mk.injEq, true_and] at h8
            subst h8
            obtain ⟨hwd, hsd⟩ := write_spec hw1
            obtain ⟨hws, hss⟩ := write_spec hw2
            have hdsv : dst.val ≠ scratch.val := u8_ne hds
            have hd9v : dst.val ≠ 9 := by
              have := u8_ne hd9; simpa [x64_ir.R9] using this
            have hs9v : scratch.val ≠ 9 := by
              have := u8_ne hs9; simpa [x64_ir.R9] using this
            have hchkv : chk =
                (if cfg.pointer_mask.val ≠ 0 then x64_check.Tag.Checked size
                 else x64_check.Tag.Top) := by
              split at hchk
              · rename_i hm
                have hm' : cfg.pointer_mask ≠ 0#i32 := by simpa using hm
                have hp : cfg.pointer_mask.val ≠ 0 := fun hc =>
                  hm' (i32_eq_iff.mpr (by simpa using hc))
                simp only [ok.injEq] at hchk
                rw [← hchk, if_pos hp]
              · rename_i hm
                simp only [bne_iff_ne, ne_eq, Decidable.not_not] at hm
                have : ¬ (cfg.pointer_mask.val ≠ 0) := by
                  simp only [ne_eq, Decidable.not_not, hm]
                  simp
                simp only [ok.injEq] at hchk
                rw [← hchk, if_neg this]
            have e3 := tagAt_set_tag hs3
            have e4 := tagAt_set_tag hs4
            have hr9 : (x64_ir.R9).val = 9 := by simp [x64_ir.R9]
            have hE4d : tagAt s4 dst.val = chk := by
              have hp : (dst.val = dst.val ∧ dst.val < 16) := ⟨rfl, hwd.2.2.2⟩
              rw [e4 dst.val, if_pos hp]
            have hE4 : ∀ k, k ≠ dst.val → tagAt s4 k = tagAt s3 k := by
              intro k hk
              have hn : ¬ (k = dst.val ∧ k < 16) := fun hc => hk hc.1
              rw [e4 k, if_neg hn]
            have hE3 : ∀ k, k ≠ 9 → tagAt s3 k = tagAt s2 k := by
              intro k hk
              have hn : ¬ (k = (x64_ir.R9).val ∧ k < 16) := fun hc => hk (by rw [hc.1, hr9])
              rw [e3 k, if_neg hn]
            have hE3n : tagAt s3 9 = x64_check.Tag.Top := by
              have hp : (9 = (x64_ir.R9).val ∧ 9 < 16) := ⟨hr9.symm, by omega⟩
              rw [e3 9, if_pos hp]
            refine ⟨hds, hd9v, hs9v, ?_, ?_, hwd, hws, ?_, ?_, ?_, ?_,
              ?_, ?_, ?_⟩
            · have : ¬ (size.val = 0) := fun hc => hz (u32_eq_iff.mpr (by simpa using hc))
              omega
            · have := u32_not_gt hmax
              simpa [x64_ir.MAX_GROUP_SPAN] using this
            · rw [hE4d, hchkv]
            · rw [hE4 scratch.val (fun hc => hdsv hc.symm), hE3 scratch.val hs9v,
                hss.1 scratch.val rfl]
            · rw [hE4 9 (fun hc => hd9v hc.symm), hE3n]
            · intro k hk1 hk2 hk3
              rw [hE4 k hk1, hE3 k hk3, hss.2.1 k hk2, hsd.2.1 k hk1]
            · rw [(set_tag_fields hs4).1, (set_tag_fields hs3).1, hss.2.2.1, hsd.2.2.1]
            · rw [(set_tag_fields hs4).2.1, (set_tag_fields hs3).2.1, hss.2.2.2.1, hsd.2.2.2.1]
            · rw [(set_tag_fields hs4).2.2, (set_tag_fields hs3).2.2, hss.2.2.2.2, hsd.2.2.2.2]

theorem live_step_GroupBaseStore_spec {cfg : x64_ir.Cfg} {src : Std.U8} {index : Std.Usize}
    {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.GroupBaseStore src) index pc pre = ok (.Ok (), post)) :
    post = { pre with group := tagAt pre src.val } := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  obtain ⟨t, ht, h1⟩ := bind_eq_ok h
  simp only [ok.injEq, Prod.mk.injEq, true_and] at h1
  rw [← h1, tag_of_spec ht, hl]

theorem live_step_GroupBaseLoad_spec {cfg : x64_ir.Cfg} {dst : Std.U8} {index : Std.Usize}
    {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.GroupBaseLoad dst) index pc pre = ok (.Ok (), post)) :
    Writable dst.val ∧ tagAt post dst.val = pre.group ∧
    (∀ k, k ≠ dst.val → tagAt post k = tagAt pre k) ∧
    post.depth = pre.depth ∧ post.group = pre.group ∧ post.alive = pre.alive := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  obtain ⟨⟨r1, s1⟩, hw1, h2⟩ := bind_eq_ok h
  obtain ⟨cf1, hcf1, h3⟩ := bind_eq_ok h2
  rcases branch_continue hcf1 with ⟨u1, rfl, rfl⟩ | ⟨e1, rfl, rfl⟩
  case inr => exact (no_break h3).elim
  simp only at h3
  obtain ⟨s2, hs2, h4⟩ := bind_eq_ok h3
  simp only [ok.injEq, Prod.mk.injEq, true_and] at h4
  subst h4
  obtain ⟨hwd, hsd⟩ := write_spec hw1
  have e2 := tagAt_set_tag hs2
  refine ⟨hwd, ?_, ?_, ?_, ?_, ?_⟩
  · rw [e2 dst.val, if_pos ⟨rfl, hwd.2.2.2⟩, hsd.2.2.2.1]
  · intro k hk
    rw [e2 k, if_neg (by simp [hk]), hsd.2.1 k hk]
  · rw [(set_tag_fields hs2).1, hsd.2.2.1]
  · rw [(set_tag_fields hs2).2.1, hsd.2.2.2.1]
  · rw [(set_tag_fields hs2).2.2, hsd.2.2.2.2]


private theorem u64_eq_iff {x y : Std.U64} : x = y ↔ x.val = y.val := by scalar_tac

theorem live_step_Load_spec {cfg : x64_ir.Cfg} {size : Std.U8} {sx : Bool} {base dst : Std.U8}
    {disp : Std.I32} {index : Std.Usize} {pc : Std.U32} {pre post : x64_check.State}
    (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.Load size sx base dst disp) index pc pre = ok (.Ok (), post)) :
    AddrOk cfg pre base disp.val size.val ∧ Writable dst.val ∧
    SetsTop pre post (· = dst.val) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  obtain ⟨i, hi, h1⟩ := bind_eq_ok h
  have hiv : i.val = size.val := by simp only [lift, ok.injEq] at hi; subst hi; simp
  obtain ⟨b, hb, h2⟩ := bind_eq_ok h1
  have ha := addr_ok_spec hb
  rw [hiv] at ha
  split at h2
  · rename_i hbt
    exact ⟨ha.mp hbt, (write_spec h2).1, (write_spec h2).2⟩
  · simp [x64_check.reject] at h2

theorem live_step_Store_spec {cfg : x64_ir.Cfg} {size src base : Std.U8} {disp : Std.I32}
    {index : Std.Usize} {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.Store size src base disp) index pc pre = ok (.Ok (), post)) :
    AddrOk cfg pre base disp.val size.val ∧ post = pre := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  obtain ⟨i, hi, h1⟩ := bind_eq_ok h
  have hiv : i.val = size.val := by simp only [lift, ok.injEq] at hi; subst hi; simp
  obtain ⟨b, hb, h2⟩ := bind_eq_ok h1
  have ha := addr_ok_spec hb
  rw [hiv] at ha
  split at h2
  · rename_i hbt
    simp only [ok.injEq, Prod.mk.injEq, true_and] at h2
    exact ⟨ha.mp hbt, h2.symm⟩
  · simp [x64_check.reject] at h2

theorem live_step_StoreImm_spec {cfg : x64_ir.Cfg} {size base : Std.U8} {disp imm : Std.I32}
    {index : Std.Usize} {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.StoreImm size base disp imm) index pc pre
      = ok (.Ok (), post)) :
    AddrOk cfg pre base disp.val size.val ∧ post = pre := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  obtain ⟨i, hi, h1⟩ := bind_eq_ok h
  have hiv : i.val = size.val := by simp only [lift, ok.injEq] at hi; subst hi; simp
  obtain ⟨b, hb, h2⟩ := bind_eq_ok h1
  have ha := addr_ok_spec hb
  rw [hiv] at ha
  split at h2
  · rename_i hbt
    simp only [ok.injEq, Prod.mk.injEq, true_and] at h2
    exact ⟨ha.mp hbt, h2.symm⟩
  · simp [x64_check.reject] at h2

theorem live_step_AtomicAlu_spec {cfg : x64_ir.Cfg} {op : Std.U8} {w64 : Bool}
    {src base : Std.U8} {disp : Std.I32} {index : Std.Usize} {pc : Std.U32}
    {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.AtomicAlu op w64 src base disp) index pc pre
      = ok (.Ok (), post)) :
    AddrOk cfg pre base disp.val (atomicSize w64) ∧ post = pre := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  obtain ⟨i, hi, h1⟩ := bind_eq_ok h
  have hiv := atomic_size_spec w64 hi
  obtain ⟨b, hb, h2⟩ := bind_eq_ok h1
  have ha := addr_ok_spec hb
  rw [hiv] at ha
  split at h2
  · rename_i hbt
    simp only [ok.injEq, Prod.mk.injEq, true_and] at h2
    exact ⟨ha.mp hbt, h2.symm⟩
  · simp [x64_check.reject] at h2

theorem live_step_AtomicFetchAlu_spec {cfg : x64_ir.Cfg} {op : Std.U8} {w64 : Bool}
    {src base : Std.U8} {disp : Std.I32} {index : Std.Usize} {pc : Std.U32}
    {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.AtomicFetchAlu op w64 src base disp) index pc pre
      = ok (.Ok (), post)) :
    AddrOk cfg pre base disp.val (atomicSize w64) ∧ pre.depth.val + 1 ≤ 16 ∧
    Writable src.val ∧
    SetsTop pre post (fun k => k = src.val ∨ k = 0 ∨ k = 1 ∨ k = 10 ∨ k = 11) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  obtain ⟨i, hi, h1⟩ := bind_eq_ok h
  have hiv := atomic_size_spec w64 hi
  obtain ⟨b, hb, h2⟩ := bind_eq_ok h1
  have ha := addr_ok_spec hb
  rw [hiv] at ha
  split at h2
  · rename_i hbt
    obtain ⟨db, hdb, h3⟩ := bind_eq_ok h2
    split at h3
    · rename_i hdt
      have hdepth : pre.depth.val + 1 ≤ 16 := by
        have := (depth_ok_spec hdb).mp hdt
        simpa using this
      obtain ⟨⟨r1, s1⟩, hw1, h4⟩ := bind_eq_ok h3
      obtain ⟨cf1, hcf1, h5⟩ := bind_eq_ok h4
      rcases branch_continue hcf1 with ⟨u1, rfl, rfl⟩ | ⟨e1, rfl, rfl⟩
      case inr => exact (no_break h5).elim
      simp only at h5
      obtain ⟨⟨r2, s2⟩, hw2, h6⟩ := bind_eq_ok h5
      obtain ⟨cf2, hcf2, h7⟩ := bind_eq_ok h6
      rcases branch_continue hcf2 with ⟨u2, rfl, rfl⟩ | ⟨e2, rfl, rfl⟩
      case inr => exact (no_break h7).elim
      simp only at h7
      obtain ⟨⟨r3, s3⟩, hw3, h8⟩ := bind_eq_ok h7
      obtain ⟨cf3, hcf3, h9⟩ := bind_eq_ok h8
      rcases branch_continue hcf3 with ⟨u3, rfl, rfl⟩ | ⟨e3, rfl, rfl⟩
      case inr => exact (no_break h9).elim
      simp only at h9
      obtain ⟨⟨r4, s4⟩, hw4, h10⟩ := bind_eq_ok h9
      obtain ⟨cf4, hcf4, h11⟩ := bind_eq_ok h10
      rcases branch_continue hcf4 with ⟨u4, rfl, rfl⟩ | ⟨e4, rfl, rfl⟩
      case inr => exact (no_break h11).elim
      simp only at h11
      obtain ⟨hws, b1⟩ := (SetsTop.refl pre).write hw1
      obtain ⟨-, b2⟩ := b1.write hw2
      obtain ⟨-, b3⟩ := b2.write hw3
      obtain ⟨-, b4⟩ := b3.write hw4
      obtain ⟨-, b5⟩ := b4.write h11
      refine ⟨ha.mp hbt, hdepth, hws, b5.mono (fun k => ?_)⟩
      simp only [x64_ir.RAX, x64_ir.RCX, x64_ir.R10, x64_ir.R11]
      norm_num
      tauto
    · simp [x64_check.reject] at h3
  · simp [x64_check.reject] at h2

theorem live_step_AtomicXchg_spec {cfg : x64_ir.Cfg} {w64 : Bool} {src base : Std.U8}
    {disp : Std.I32} {index : Std.Usize} {pc : Std.U32} {pre post : x64_check.State}
    (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.AtomicXchg w64 src base disp) index pc pre
      = ok (.Ok (), post)) :
    AddrOk cfg pre base disp.val (atomicSize w64) ∧ Writable src.val ∧
    SetsTop pre post (· = src.val) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  obtain ⟨i, hi, h1⟩ := bind_eq_ok h
  have hiv := atomic_size_spec w64 hi
  obtain ⟨b, hb, h2⟩ := bind_eq_ok h1
  have ha := addr_ok_spec hb
  rw [hiv] at ha
  split at h2
  · rename_i hbt
    exact ⟨ha.mp hbt, (write_spec h2).1, (write_spec h2).2⟩
  · simp [x64_check.reject] at h2

theorem live_step_AtomicCmpxchg_spec {cfg : x64_ir.Cfg} {w64 : Bool} {src base : Std.U8}
    {disp : Std.I32} {index : Std.Usize} {pc : Std.U32} {pre post : x64_check.State}
    (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.AtomicCmpxchg w64 src base disp) index pc pre
      = ok (.Ok (), post)) :
    AddrOk cfg pre base disp.val (atomicSize w64) ∧ SetsTop pre post (· = 0) := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  obtain ⟨i, hi, h1⟩ := bind_eq_ok h
  have hiv := atomic_size_spec w64 hi
  obtain ⟨b, hb, h2⟩ := bind_eq_ok h1
  have ha := addr_ok_spec hb
  rw [hiv] at ha
  split at h2
  · rename_i hbt
    refine ⟨ha.mp hbt, ((write_spec h2).2).mono (fun k => ?_)⟩
    simp [x64_ir.RAX]
  · simp [x64_check.reject] at h2

theorem live_step_HelperCall_spec {cfg : x64_ir.Cfg} {idx : Std.U32} {index : Std.Usize}
    {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.HelperCall idx) index pc pre = ok (.Ok (), post)) :
    cfg.dispatcher.val ≠ 0 ∧ pre.depth.val + 2 ≤ 16 ∧ ClobberCall pre post := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  split at h
  · simp [x64_check.reject] at h
  · rename_i hdisp
    have hd : cfg.dispatcher.val ≠ 0 := fun hc => hdisp (u64_eq_iff.mpr (by simpa using hc))
    obtain ⟨db, hdb, h1⟩ := bind_eq_ok h
    split at h1
    · rename_i hdt
      obtain ⟨st1, hst1, h2⟩ := bind_eq_ok h1
      simp only [ok.injEq, Prod.mk.injEq, true_and] at h2
      subst h2
      exact ⟨hd, by simpa using (depth_ok_spec hdb).mp hdt, clobber_call_spec hst1⟩
    · simp [x64_check.reject] at h1

theorem live_step_LazyLocalCall_spec {cfg : x64_ir.Cfg} {id : Std.U32} {index : Std.Usize}
    {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (h : x64_check.live_step cfg (.LazyLocalCall id) index pc pre = ok (.Ok (), post)) :
    cfg.has_local_call_callbacks = true ∧ tagAt pre 15 = x64_check.Tag.Fp ∧
    pre.depth.val + 13 ≤ 16 ∧ ClobberCall pre post := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  split at h
  · rename_i hcb
    obtain ⟨fi, hfi, h1⟩ := bind_eq_ok h
    split at h1
    · rename_i hfit
      obtain ⟨db, hdb, h2⟩ := bind_eq_ok h1
      split at h2
      · rename_i hdt
        obtain ⟨st1, hst1, h3⟩ := bind_eq_ok h2
        simp only [ok.injEq, Prod.mk.injEq, true_and] at h3
        subst h3
        exact ⟨hcb, (frame_intact_spec hfi).mp hfit,
          by simpa using (depth_ok_spec hdb).mp hdt, clobber_call_spec hst1⟩
      · simp [x64_check.reject] at h2
    · simp [x64_check.reject] at h1
  · simp [x64_check.reject] at h

/-- The structural macros are handled by `step`, not here: `live_step` leaves
the state as it found it. -/
theorem live_step_structural {cfg : x64_ir.Cfg} {insn : x64_ir.MInsn} {index : Std.Usize}
    {pc : Std.U32} {pre post : x64_check.State} (hl : pre.alive = true)
    (hs : (∃ n, insn = .PcLabel n) ∨ (∃ u sk, insn = .Prologue u sk) ∨
      (∃ cc t, insn = .Jcc cc t) ∨ (∃ t, insn = .Jmp t) ∨ insn = .Retpoline ∨
      insn = .DispatcherSlot ∨ insn = .HelperTable)
    (h : x64_check.live_step cfg insn index pc pre = ok (.Ok (), post)) : post = pre := by
  unfold x64_check.live_step at h
  simp only [hl, if_true] at h
  rcases hs with ⟨n, rfl⟩ | ⟨u, sk, rfl⟩ | ⟨cc, t, rfl⟩ | ⟨t, rfl⟩ | rfl | rfl | rfl <;>
    (simp only [ok.injEq, Prod.mk.injEq, true_and] at h; exact h.symm)


/-! ## One macro, and the whole walk -/

/-- `step` sends each macro to its rule. -/
theorem step_dispatch {cfg : x64_ir.Cfg} {labels : x64_check.Labels} {code : Slice x64_ir.MInsn}
    {index : Std.Usize} {pc : Std.U32} {pre : x64_check.State}
    {r : core.result.Result Unit x64_check.Unsafe × x64_check.State}
    (h : x64_check.step cfg labels code index pc pre = ok r) :
    ∃ insn, code.val[index.val]? = some insn ∧
      (match insn with
       | .PcLabel slot => x64_check.label_step labels slot index pc pre = ok r
       | .Prologue _ skip => x64_check.prologue_step skip index pc pre = ok r
       | .Jcc _ target => x64_check.branch_step labels target false index pc pre = ok r
       | .Jmp target => x64_check.branch_step labels target true index pc pre = ok r
       | .Retpoline => x64_check.retpoline_step code index pc pre = ok r
       | .DispatcherSlot => ∃ u, x64_check.data_step code index pc 1#usize = ok u ∧ r = (u, pre)
       | .HelperTable => ∃ u, x64_check.data_step code index pc 2#usize = ok u ∧ r = (u, pre)
       | _ => x64_check.live_step cfg insn index pc pre = ok r) := by
  unfold x64_check.step at h
  obtain ⟨insn, hinsn, h1⟩ := bind_eq_ok h
  refine ⟨insn, (slice_index_usize_eq_ok hinsn).2, ?_⟩
  cases insn
  case DispatcherSlot =>
    obtain ⟨u, hu, h2⟩ := bind_eq_ok h1
    simp only [ok.injEq] at h2
    exact ⟨u, hu, h2.symm⟩
  case HelperTable =>
    obtain ⟨u, hu, h2⟩ := bind_eq_ok h1
    simp only [ok.injEq] at h2
    exact ⟨u, hu, h2.symm⟩
  all_goals exact h1

/-- The pre-pass is the first thing `check` does, so a list it walks at all
has a label table. -/
theorem scan_ok {cfg : x64_ir.Cfg} {code : Slice x64_ir.MInsn}
    {r : core.result.Result Unit x64_check.Unsafe} (h : x64_check.check cfg code = ok r) :
    ∃ labels, x64_check.scan code = ok labels := by
  unfold x64_check.check at h
  simp only [Slice.len] at h
  obtain ⟨labels, hlabels, -⟩ := bind_eq_ok h
  exact ⟨labels, hlabels⟩

private def ChainInv (cfg : x64_ir.Cfg) (labels : x64_check.Labels) (code : Slice x64_ir.MInsn)
    (x : x64_check.State × Std.U32 × Std.Usize) : Prop :=
  x.2.2.val ≤ code.val.length ∧
  ∃ (a : List x64_check.State) (p : List Std.U32),
    a.length = x.2.2.val + 1 ∧ p.length = x.2.2.val + 1 ∧
    x64_check.entry_state = ok a[0]! ∧ p[0]! = 0#u32 ∧
    a[x.2.2.val]! = x.1 ∧ p[x.2.2.val]! = x.2.1 ∧
    (∀ (j : Nat), j < x.2.2.val → ∀ insn, code.val[j]? = some insn →
      p[j + 1]! = pcNext insn p[j]!) ∧
    (∀ (j : Nat) (idx : Std.Usize), idx.val = j → j < x.2.2.val →
      x64_check.step cfg labels code idx p[j + 1]! a[j]! = ok (.Ok (), a[j + 1]!))

/-- A macro list the checker accepts comes with a walk: one abstract state
per position plus the entry state, the running eBPF slot number beside it,
every consecutive pair related by the checker's own `step` — with the slot
number updated *before* the step, as `check` does — and the last state dead,
which is what forbids control falling out of the function. -/
theorem check_chain {cfg : x64_ir.Cfg} {code : Slice x64_ir.MInsn}
    (h : x64_check.check cfg code = ok (.Ok ())) :
    ∃ labels, x64_check.scan code = ok labels ∧
    ∃ (a : List x64_check.State) (p : List Std.U32),
      a.length = code.val.length + 1 ∧ p.length = code.val.length + 1 ∧
      x64_check.entry_state = ok a[0]! ∧ p[0]! = 0#u32 ∧
      (∀ (j : Nat), j < code.val.length → ∀ insn, code.val[j]? = some insn →
        p[j + 1]! = pcNext insn p[j]!) ∧
      (∀ (j : Nat) (idx : Std.Usize), idx.val = j → j < code.val.length →
        x64_check.step cfg labels code idx p[j + 1]! a[j]! = ok (.Ok (), a[j + 1]!)) ∧
      (a[code.val.length]!).alive = false := by
  unfold x64_check.check at h
  simp only [Slice.len] at h
  obtain ⟨labels, hlabels, h1⟩ := bind_eq_ok h
  obtain ⟨st0, hst0, h2⟩ := bind_eq_ok h1
  refine ⟨labels, hlabels, ?_⟩
  unfold x64_check.check_loop at h2
  have hinit : ChainInv cfg labels code (st0, 0#u32, 0#usize) := by
    refine ⟨by simp, [st0], [0#u32], by simp, by simp, ?_, rfl, ?_, ?_, ?_, ?_⟩
    · simpa using hst0
    · simp
    · simp
    · intro j hj; simp at hj
    · intro j idx _ hj; simp at hj
  refine loop_ok_induction _ (ChainInv cfg labels code)
    (fun y => y = .Ok () →
      ∃ (a : List x64_check.State) (p : List Std.U32),
        a.length = code.val.length + 1 ∧ p.length = code.val.length + 1 ∧
        x64_check.entry_state = ok a[0]! ∧ p[0]! = 0#u32 ∧
        (∀ (j : Nat), j < code.val.length → ∀ insn, code.val[j]? = some insn →
          p[j + 1]! = pcNext insn p[j]!) ∧
        (∀ (j : Nat) (idx : Std.Usize), idx.val = j → j < code.val.length →
          x64_check.step cfg labels code idx p[j + 1]! a[j]! = ok (.Ok (), a[j + 1]!)) ∧
        (a[code.val.length]!).alive = false)
    ?_ _ _ hinit h2 rfl
  rintro ⟨st, pc, i⟩ hinv res hb
  obtain ⟨hi, a, p, hal, hpl, ha0, hp0, hai, hpi, hpcs, hsteps⟩ := hinv
  dsimp only at hi hal hpl ha0 hp0 hai hpi hpcs hsteps
  simp only at hb
  unfold x64_check.check_loop.body at hb
  split at hb
  · rename_i hlt
    have hival : i.val < code.val.length := by simpa [Slice.length] using usize_lt hlt
    obtain ⟨insn, hinsn, hb0⟩ := bind_eq_ok hb
    have hinsnv := (slice_index_usize_eq_ok hinsn).2
    obtain ⟨q, hq, hb1⟩ := bind_eq_ok hb0
    obtain ⟨labelled, slot⟩ := q
    obtain ⟨pc1, hpc1, hb2⟩ := bind_eq_ok hb1
    have hpc1v : (if labelled = true then slot else pc) = pc1 := by
      split at hpc1
      · rename_i hlab
        simp only [ok.injEq] at hpc1
        rw [if_pos hlab]; exact hpc1
      · rename_i hlab
        simp only [ok.injEq] at hpc1
        rw [if_neg hlab]; exact hpc1
    obtain ⟨⟨r1, st1⟩, hstep, hb3⟩ := bind_eq_ok hb2
    obtain ⟨cf1, hcf1, hb4⟩ := bind_eq_ok hb3
    rcases branch_continue hcf1 with ⟨u1, rfl, rfl⟩ | ⟨e1, rfl, rfl⟩
    case inr =>
      simp only at hb4
      obtain ⟨r2, hr2, hb5⟩ := bind_eq_ok hb4
      simp only [ok.injEq] at hb5
      subst hb5
      intro hc
      subst hc
      simp [core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual]
        at hr2
    simp only at hb4
    obtain ⟨i1, hi1, hb5⟩ := bind_eq_ok hb4
    simp only [ok.injEq] at hb5
    subst hb5
    have hone : (1#usize : Std.Usize).val = 1 := by simp
    have hi1v : i1.val = i.val + 1 := by rw [usize_add_eq_ok hi1, hone]
    refine ⟨by dsimp only; omega, a ++ [st1], p ++ [pc1], ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · dsimp only; simp [hal]; omega
    · dsimp only; simp [hpl]; omega
    · rw [getElem!_append_left a st1 0 (by omega)]; exact ha0
    · rw [getElem!_append_left p pc1 0 (by omega)]; exact hp0
    · dsimp only
      rw [hi1v, show i.val + 1 = a.length by omega, getElem!_append_self]
    · dsimp only
      rw [hi1v, show i.val + 1 = p.length by omega, getElem!_append_self]
    · intro j hj insn' hinsn'
      dsimp only at hj
      rw [hi1v] at hj
      by_cases hje : j = i.val
      · subst hje
        rw [hinsnv] at hinsn'
        cases hinsn'
        rw [show i.val + 1 = p.length by omega, getElem!_append_self,
          getElem!_append_left p pc1 i.val (by omega), hpi, ← hpc1v, label_of_pcNext hq pc]
      · rw [getElem!_append_left p pc1 (j + 1) (by omega),
          getElem!_append_left p pc1 j (by omega)]
        exact hpcs j (by omega) insn' hinsn'
    · intro j idx hidx hj
      dsimp only at hj
      rw [hi1v] at hj
      by_cases hje : j = i.val
      · subst hje
        have hA : (a ++ [st1])[i.val]! = st := by
          rw [getElem!_append_left a st1 i.val (by omega)]; exact hai
        have hA1 : (a ++ [st1])[i.val + 1]! = st1 := by
          rw [show i.val + 1 = a.length by omega]; exact getElem!_append_self a st1
        have hP1 : (p ++ [pc1])[i.val + 1]! = pc1 := by
          rw [show i.val + 1 = p.length by omega]; exact getElem!_append_self p pc1
        rw [show idx = i from usize_eq_iff.mpr hidx, hP1, hA, hA1]
        exact hstep
      · rw [getElem!_append_left p pc1 (j + 1) (by omega),
          getElem!_append_left a st1 j (by omega),
          getElem!_append_left a st1 (j + 1) (by omega)]
        exact hsteps j idx hidx (by omega)
  · rename_i hge
    have hiv : code.val.length ≤ i.val := by simpa [Slice.length] using usize_not_lt hge
    have hieq : i.val = code.val.length := by omega
    split at hb
    · rename_i hal2
      obtain ⟨last, hlast, hb1⟩ := bind_eq_ok hb
      obtain ⟨u, hu, hb2⟩ := bind_eq_ok hb1
      simp only [ok.injEq] at hb2
      subst hb2
      intro hc
      simp at hc
    · rename_i hal2
      simp only [Bool.not_eq_true] at hal2
      simp only [ok.injEq] at hb
      subst hb
      intro _
      refine ⟨a, p, by omega, by omega, ha0, hp0, ?_, ?_, ?_⟩
      · intro j hj insn' hinsn'
        exact hpcs j (by omega) insn' hinsn'
      · intro j idx hidx hj
        exact hsteps j idx hidx (by omega)
      · rw [← hieq, hai]
        exact hal2


end X64

end async_ebpf_verified

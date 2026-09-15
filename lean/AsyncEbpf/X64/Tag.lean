import AsyncEbpf.AsyncEbpfVerified

/-!
# The checker's register file, as a function

`x64_check.State` carries its sixteen register tags in an Aeneas `Array`, and
the checker reads it through `tag_of`, which answers `Top` for a register
number the sixteen do not name. `tagAt` is that read as a plain function of a
`Nat`, so that every statement about an abstract state is phrased over one
total map and no consumer has to index the extracted array — or re-derive the
out-of-range case — for itself.

It sits in its own file because both halves of the x86_64 argument are
written in terms of it: the inversion lemmas that turn a successful
`x64_check.check` into facts about states (`X64/CheckSpec.lean`), and the
invariant that ties those states to the machine (`X64/Abs.lean`).
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-- The chain of abstract states the checker's walk builds is indexed by
`Nat` and read with `[i]!`, which wants a default at each of the three types
involved. None of them is ever the value of anything: every index the
statements below use is in range. -/
instance tagInhabited : Inhabited x64_check.Tag := ⟨.Top⟩

instance minsnInhabited : Inhabited x64_ir.MInsn := ⟨.Retpoline⟩

instance stateInhabited : Inhabited x64_check.State :=
  ⟨{ regs := Std.Array.repeat 16#usize .Top, depth := 0#u32, group := .Top, alive := false }⟩

/-- The tag the abstract state gives register `r`, `Top` outside the sixteen
the state tracks — which is what `x64_check.tag_of` answers there. -/
def tagAt (a : x64_check.State) (r : Nat) : x64_check.Tag := a.regs.val.getD r .Top

/-- `set_tag` writes the register it names and nothing else, and writes
nothing at all when the register number is not one of the sixteen. -/
theorem tagAt_set_tag {pre post : x64_check.State} {r : Std.U8} {t : x64_check.Tag}
    (h : x64_check.set_tag pre r t = ok post) (k : Nat) :
    tagAt post k = if k = r.val ∧ k < 16 then t else tagAt pre k := by
  have hlen : pre.regs.val.length = 16 := by simp
  unfold x64_check.set_tag at h
  simp only [lift, x64_check.NUM_REGS, bind_tc_ok] at h
  split at h
  · rename_i hlt
    have hr : r.val < 16 := by
      have := (UScalar.lt_equiv (x := UScalar.cast .Usize r) (y := 16#usize)).mp hlt
      simpa using this
    unfold Std.Array.update at h
    split at h
    · simp at h
    · simp only [bind_tc_ok, ok.injEq] at h
      subst h
      simp only [tagAt, Std.Array.from_val, List.getD_eq_getElem?_getD, List.getElem?_set,
        Std.U8.cast_Usize_val_eq]
      by_cases hk : k = r.val
      · subst hk
        simp [hr, hlen]
      · rw [if_neg (by simpa using fun hh => hk hh.symm), if_neg (by simp [hk])]
  · rename_i hge
    simp only [ok.injEq] at h
    subst h
    have hr : ¬ (r.val < 16) := by
      intro hr
      refine hge ?_
      have : (UScalar.cast (src_ty := .U8) .Usize r).val < (16#usize).val := by simpa using hr
      exact (UScalar.lt_equiv _ _).mpr this
    rw [if_neg]
    rintro ⟨rfl, hk⟩
    exact hr hk

end X64

end async_ebpf_verified

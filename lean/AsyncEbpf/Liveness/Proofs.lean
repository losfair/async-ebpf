import AsyncEbpf.Region.Masking

/-!
# The live-in solver computes a solution

`src/verified/liveness.rs` is the whole-program backward dataflow behind
`region_analysis::program_live_in`. `solve_ok` says the table it returns
satisfies the live-in equations at every slot — the slot's uses, and every
successor's live-in minus the slot's defs, with a local call reading its
callee's entry liveness — and `solve_live_solution` restates that as the
`LiveSolution` the region analysis' masking proofs assume, so the one
hypothesis those proofs made about the table is discharged for the table
the loader computes.

The solver is a worklist. The invariant is the usual one: every slot that
is not queued satisfies its equation. A slot whose liveness grows queues
every slot whose equation reads it — its predecessors, and its function's
call sites if it is the entry — and the lists the solver walks to find
them are complete (`build_preds_ok`, `build_callers_ok`). When the
worklist is empty, nothing is queued, so every equation holds.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

/-! ## Plumbing -/

theorem u32_cast_usize_val (x : U32) : (UScalar.cast .Usize x).val = x.val := by simp

theorem usize_cast_u32_val (p : Usize) (h : p.val < 2 ^ 32) : (UScalar.cast .U32 p).val = p.val := by
  simp [UScalar.cast_val_eq]
  omega

theorem u32_div_ok (x y : U32) (hy : y.val ≠ 0) : ∃ z, x / y = ok z ∧ z.val = x.val / y.val :=
  UScalar.div_spec x hy

theorem slice_index_usize_eq_ok {α : Type} {s : Slice α} {i : Usize} {x : α}
    (h : Slice.index_usize s i = ok x) : ∃ hi : i.val < s.length, x = s.val[i.val] :=
  index_usize_eq_ok h

/-- `testBit` through the U16 operations. -/
theorem u16_or_testBit (a b : U16) (r : Nat) :
    (a ||| b).val.testBit r = (a.val.testBit r || b.val.testBit r) := by
  simp [Nat.testBit_or]

theorem u16_and_testBit (a b : U16) (r : Nat) :
    (a &&& b).val.testBit r = (a.val.testBit r && b.val.testBit r) := by
  simp [Nat.testBit_and]

theorem u16_not_testBit (d : U16) (r : Nat) (hr : r < 16) :
    (~~~ d).val.testBit r = !d.val.testBit r := by
  show (UScalar.not d).val.testBit r = !d.val.testBit r
  simp only [UScalar.not, UScalar.val]
  have hg : ∀ (v : BitVec 16) (i : Nat), v.toNat.testBit i = v.getLsbD i := fun _ _ => rfl
  rw [hg, hg, BitVec.getLsbD_not]
  simp [hr]

theorem u16_testBit_ge (d : U16) (r : Nat) (hr : 16 ≤ r) : d.val.testBit r = false := by
  apply Nat.testBit_lt_two_pow
  have := d.hBounds
  simp only [UScalarTy.numBits] at this
  calc d.val < 2 ^ 16 := by omega
    _ ≤ 2 ^ r := Nat.pow_le_pow_right (by norm_num) hr

theorem NOT_A_CALL_val : liveness.NOT_A_CALL.val = 4294967295 := by
  simp [liveness.NOT_A_CALL, U32.rMax]

theorem NO_EDGE_val : liveness.NO_EDGE.val = 4294967295 := by
  simp [liveness.NO_EDGE, U32.rMax]

theorem UNRESOLVED_ok : ∃ u, liveness.UNRESOLVED = ok u ∧ u.val = 4294967294 := by
  simp only [liveness.UNRESOLVED]
  obtain ⟨z, hz, hzv, _⟩ := WP.spec_imp_exists
    (UScalar.sub_spec (x := core.num.U32.MAX) (y := 1#u32) (by simp [U32.rMax]))
  exact ⟨z, hz, by simp [U32.rMax] at hzv; omega⟩

theorem getBang_set_ne {α : Type} [Inhabited α] {l : List α} {k i : Nat} {v : α} (h : i ≠ k) :
    (l.set k v)[i]! = l[i]! := by
  simp only [List.getElem!_eq_getElem?_getD, List.getElem?_set_ne (Ne.symm h)]

theorem getBang_set_self {α : Type} [Inhabited α] {l : List α} {k : Nat} {v : α} (h : k < l.length) :
    (l.set k v)[k]! = v := by
  simp only [List.getElem!_eq_getElem?_getD, List.getElem?_set_self h, Option.getD_some]

theorem getBang_eq {α : Type} [Inhabited α] {l : List α} {i : Nat} (h : i < l.length) : l[i]! = l[i] := by
  simp only [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem h, Option.getD_some]

/-! ## Intrusive lists -/

/-- `x` is on the list that starts at edge `e`: one of `e`, `next[e]`, … up
to `NO_EDGE`. Nothing here needs the list to be finite. -/
inductive ListMem (next : List U32) : U32 → U32 → Prop
  | head {e : U32} : e.val ≠ liveness.NO_EDGE.val → ListMem next e e
  | tail {e x : U32} : e.val ≠ liveness.NO_EDGE.val → ListMem next next[e.val]! x → ListMem next e x

theorem ListMem.ne {next : List U32} {e x : U32} (h : ListMem next e x) : e.val ≠ liveness.NO_EDGE.val := by
  cases h <;> assumption

/-- Setting an edge no member names changes no membership. -/
theorem ListMem.set_fresh {next : List U32} {e x : U32} (h : ListMem next e x) {k : Nat} {v : U32}
    (hk : ∀ y, ListMem next e y → y.val ≠ k) : ListMem (next.set k v) e x := by
  induction h with
  | head hne => exact .head hne
  | @tail e x hne _ ih =>
    apply ListMem.tail hne
    rw [getBang_set_ne (hk e (.head hne))]
    exact ih (fun y hy => hk y (.tail hne hy))

/-- The converse: membership in a list that never runs through the set edge
was membership before the set. -/
theorem ListMem.unset_fresh {next : List U32} {e x : U32} {k : Nat} {v : U32}
    (h : ListMem (next.set k v) e x) (hk : ∀ y, ListMem next e y → y.val ≠ k) :
    ListMem next e x := by
  induction h with
  | head hne => exact .head hne
  | @tail e x hne _ ih =>
    apply ListMem.tail hne
    have hek : e.val ≠ k := hk e (.head hne)
    rw [getBang_set_ne hek] at ih
    exact ih (fun y hy => hk y (.tail hne hy))

/-- After `link`: the target's list gained the edge in front, every other
list is as it was, and every old member is still a member. -/
theorem ListMem.after_link {next head : List U32} {a k : Nat} {kU : U32} (hkv : kU.val = k)
    (hne : k ≠ liveness.NO_EDGE.val) (ha : a < head.length) (hkl : k < next.length)
    (hfresh : ∀ q, q < head.length → ∀ y, ListMem next head[q]! y → y.val ≠ k) :
    (∀ q, q < head.length → ∀ y, ListMem next head[q]! y →
      ListMem (next.set k head[a]!) (head.set a kU)[q]! y) ∧
    ListMem (next.set k head[a]!) (head.set a kU)[a]! kU := by
  have hk' : kU.val ≠ liveness.NO_EDGE.val := by rw [hkv]; exact hne
  refine ⟨fun q hq y hy => ?_, ?_⟩
  · by_cases hqa : q = a
    · subst hqa
      rw [getBang_set_self ha]
      apply ListMem.tail hk'
      rw [hkv, getBang_set_self hkl]
      exact hy.set_fresh (hfresh q hq)
    · rw [getBang_set_ne hqa]
      exact hy.set_fresh (hfresh q hq)
  · rw [getBang_set_self ha]
    exact .head hk'

/-- `link` writes exactly two cells. -/
theorem link_ok {head next head' next' : alloc.vec.Vec U32} {target edge : Usize}
    (h : liveness.link head next target edge = ok (head', next')) :
    target.val < head.length ∧ edge.val < next.length ∧
    head'.val = head.val.set target.val (UScalar.cast .U32 edge) ∧
    next'.val = next.val.set edge.val head.val[target.val]! := by
  unfold liveness.link at h
  obtain_bind ⟨i, hi, h⟩ := h
  obtain_bind ⟨⟨_, backn⟩, hbn, h⟩ := h
  obtain_bind ⟨⟨_, backh⟩, hbh, h⟩ := h
  obtain_bind ⟨i1, hi1, h⟩ := h
  simp only [ok.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  obtain ⟨ht, rfl⟩ := vec_index_eq_ok hi
  obtain ⟨he, _, rfl⟩ := vec_index_mut_eq_ok hbn
  obtain ⟨_, _, rfl⟩ := vec_index_mut_eq_ok hbh
  rw [lift_eq_ok hi1]
  refine ⟨ht, he, ?_, ?_⟩
  · simp [alloc.vec.Vec.set_val_eq]
  · simp [alloc.vec.Vec.set_val_eq, getBang_eq ht]

/-! ## The predecessor lists -/

/-- The function of slot `p`, and its bounds, as the solver reads them. -/
def sfun (slot_func : Slice U32) (p : Nat) : Nat := (slot_func.val.getD p 0#u32).val
def fsN (slot_func func_start : Slice U32) (p : Nat) : Nat :=
  (func_start.val.getD (sfun slot_func p) 0#u32).val
def feN (slot_func func_end : Slice U32) (p : Nat) : Nat :=
  (func_end.val.getD (sfun slot_func p) 0#u32).val

/-- Slot `p`'s successor edges are on their targets' lists. Stated for every
`Usize` naming `p` and its bounds, since that is how the solver calls
`function_successors`. -/
def PredFact (insns : Slice isa.Insn) (slot_func func_start func_end : Slice U32)
    (head next : List U32) (p : Nat) : Prop :=
  ∀ (pU s e : Usize) (c a b : Usize), pU.val = p → s.val = fsN slot_func func_start p →
    e.val = feN slot_func func_end p → fixpoint.function_successors insns pU s e = ok (c, a, b) →
    (1 ≤ c.val → a.val < head.length ∧ ∃ y, ListMem next head[a.val]! y ∧ y.val = 2 * p) ∧
    (2 ≤ c.val → b.val < head.length ∧ ∃ y, ListMem next head[b.val]! y ∧ y.val = 2 * p + 1)

/-- Every list member is an edge below `bound`. -/
def ListsBelow (head next : List U32) (bound : Nat) : Prop :=
  ∀ q, q < head.length → ∀ y, ListMem next head[q]! y → y.val < bound

theorem PredFact.after_link {insns : Slice isa.Insn} {slot_func func_start func_end : Slice U32}
    {head next : List U32} {a k : Nat} {kU : U32} (hkv : kU.val = k) (hne : k ≠ liveness.NO_EDGE.val)
    (ha : a < head.length) (hkl : k < next.length) (hbelow : ListsBelow head next k) {x : Nat}
    (hx : PredFact insns slot_func func_start func_end head next x) :
    PredFact insns slot_func func_start func_end (head.set a kU) (next.set k head[a]!) x := by
  intro pU s e c a' b hp hs he hsucc
  obtain ⟨h1, h2⟩ := hx pU s e c a' b hp hs he hsucc
  have keep := (ListMem.after_link hkv hne ha hkl
    (fun q hq y hy => by have := hbelow q hq y hy; omega)).1
  refine ⟨fun hc => ?_, fun hc => ?_⟩
  · obtain ⟨hlt, y, hy, hyv⟩ := h1 hc
    exact ⟨by simpa using hlt, y, keep _ hlt y hy, hyv⟩
  · obtain ⟨hlt, y, hy, hyv⟩ := h2 hc
    exact ⟨by simpa using hlt, y, keep _ hlt y hy, hyv⟩

theorem ListsBelow.after_link {head next : List U32} {a k : Nat} {kU : U32} (hkv : kU.val = k)
    (ha : a < head.length) (hkl : k < next.length) (hbelow : ListsBelow head next k) :
    ListsBelow (head.set a kU) (next.set k head[a]!) (k + 1) := by
  intro q hq y hy
  simp only [List.length_set] at hq
  -- Walk the new list: its members are the fresh edge and the old members.
  by_cases hqa : q = a
  · subst hqa
    rw [getBang_set_self ha] at hy
    cases hy with
    | head _ => omega
    | tail _ hm =>
      rw [hkv, getBang_set_self hkl] at hm
      have : ListMem next head[q]! y := by
        -- Undo the fresh set: no old member is `k`.
        exact ListMem.unset_fresh hm (fun z hz => by
          have := hbelow q hq z hz; omega)
      have := hbelow q hq y this
      omega
  · rw [getBang_set_ne hqa] at hy
    have : ListMem next head[q]! y :=
      ListMem.unset_fresh hy (fun z hz => by have := hbelow q hq z hz; omega)
    have := hbelow q hq y this
    omega

theorem ListsBelow.mono {head next : List U32} {b b' : Nat} (h : ListsBelow head next b) (hb : b ≤ b') :
    ListsBelow head next b' := fun q hq y hy => lt_of_lt_of_le (h q hq y hy) hb

/-- What the adapter guarantees about the solver's inputs: every index in
range, every function's entry inside the function, fewer than `2^31` slots. -/
structure Shape (insns : Slice isa.Insn) (slot_func func_start func_end callee : Slice U32) : Prop where
  n_lt : insns.length < 2 ^ 31
  slot_func_len : slot_func.length = insns.length
  callee_len : callee.length = insns.length
  func_end_len : func_end.length = func_start.length
  slot_func_lt : ∀ p, p < insns.length → (slot_func.val[p]!).val < func_start.length
  func_start_lt : ∀ f, f < func_start.length → (func_start.val[f]!).val < insns.length
  func_end_le : ∀ f, f < func_start.length → (func_end.val[f]!).val ≤ insns.length
  entry_func : ∀ f, f < func_start.length → (slot_func.val[(func_start.val[f]!).val]!).val = f

theorem slice_len_val {α : Type} (s : Slice α) : (Slice.len s).val = s.length := by
  simp [Slice.len]

/-- `build_preds` leaves every successor edge on its target's list. -/
theorem build_preds_ok {insns : Slice isa.Insn} {slot_func func_start func_end callee : Slice U32}
    (hS : Shape insns slot_func func_start func_end callee) {head next head' next' : alloc.vec.Vec U32}
    (hh : head.length = insns.length) (hn : next.length = 2 * insns.length)
    (hh0 : ∀ q, q < insns.length → head.val[q]! = liveness.NO_EDGE)
    (h : liveness.build_preds insns slot_func func_start func_end head next = ok (head', next')) :
    head'.length = insns.length ∧ next'.length = 2 * insns.length ∧
    (∀ p, p < insns.length → PredFact insns slot_func func_start func_end head'.val next'.val p) ∧
    ListsBelow head'.val next'.val (2 * insns.length) := by
  have hnlt := hS.n_lt
  unfold liveness.build_preds liveness.build_preds_loop at h
  have hres := loop_ok_induction _
    (fun st : alloc.vec.Vec U32 × alloc.vec.Vec U32 × Usize => st.2.2.val ≤ insns.length ∧
      st.1.length = insns.length ∧ st.2.1.length = 2 * insns.length ∧
      (∀ x, x < st.2.2.val → PredFact insns slot_func func_start func_end st.1.val st.2.1.val x) ∧
      ListsBelow st.1.val st.2.1.val (2 * st.2.2.val))
    (fun y : alloc.vec.Vec U32 × alloc.vec.Vec U32 => y.1.length = insns.length ∧
      y.2.length = 2 * insns.length ∧
      (∀ p, p < insns.length → PredFact insns slot_func func_start func_end y.1.val y.2.val p) ∧
      ListsBelow y.1.val y.2.val (2 * insns.length))
    (by
      rintro ⟨hd, nx, p⟩ ⟨hp, hhd, hnx, hfact, hbelow⟩ res hb
      dsimp only at hp hhd hnx hfact hbelow
      change liveness.build_preds_loop.body insns slot_func func_start func_end hd nx p = ok res at hb
      unfold liveness.build_preds_loop.body at hb
      dsimp only at hb
      split at hb
      · rename_i hlt
        have hlt' : p.val < insns.length := by
          rw [UScalar.lt_equiv] at hlt; simpa [slice_len_val] using hlt
        obtain_bind ⟨i1, hi1, hb⟩ := hb
        obtain_bind ⟨f, hf, hb⟩ := hb
        obtain_bind ⟨i2, hi2, hb⟩ := hb
        obtain_bind ⟨i3, hi3, hb⟩ := hb
        obtain_bind ⟨i4, hi4, hb⟩ := hb
        obtain_bind ⟨i5, hi5, hb⟩ := hb
        obtain_bind ⟨⟨count, first, second⟩, hsucc, hb⟩ := hb
        obtain_bind ⟨⟨hd1, nx1⟩, hl1, hb⟩ := hb
        obtain_bind ⟨⟨hd2, nx2⟩, hl2, hb⟩ := hb
        obtain_bind ⟨p1, hp1, hb⟩ := hb
        have hp1v := usize_add_eq_ok hp1
        simp only [ok.injEq] at hb
        subst hb
        simp at hp1v
        -- The bounds the body computed are the ones `PredFact` names.
        obtain ⟨_, rfl⟩ := slice_index_usize_eq_ok hi1
        rw [lift_eq_ok hf] at hi2 hi4
        obtain ⟨hflt, rfl⟩ := slice_index_usize_eq_ok hi2
        obtain ⟨_, rfl⟩ := slice_index_usize_eq_ok hi4
        rw [lift_eq_ok hi3, lift_eq_ok hi5] at hsucc
        have hsl : slot_func.val.length = insns.length := by
          have := hS.slot_func_len; simpa [Slice.length] using this
        have hfelen : func_end.val.length = func_start.val.length := by
          have := hS.func_end_len; simpa [Slice.length] using this
        have hhdl : hd.val.length = insns.length := by simpa [alloc.vec.Vec.length] using hhd
        have hnxl : nx.val.length = 2 * insns.length := by simpa [alloc.vec.Vec.length] using hnx
        have hflt' : (slot_func.val[p.val]).val < func_start.val.length := by
          simpa [Slice.length, u32_cast_usize_val] using hflt
        have e1 : slot_func.val.getD p.val 0#u32 = slot_func.val[p.val] :=
          List.getD_eq_getElem _ _ (by rw [hsl]; exact hlt')
        have e2 : func_start.val.getD (slot_func.val[p.val]).val 0#u32 =
            func_start.val[(slot_func.val[p.val]).val] := List.getD_eq_getElem _ _ hflt'
        have e3 : func_end.val.getD (slot_func.val[p.val]).val 0#u32 =
            func_end.val[(slot_func.val[p.val]).val] := List.getD_eq_getElem _ _ (by rw [hfelen]; exact hflt')
        have hsv : (UScalar.cast .Usize func_start.val[(UScalar.cast .Usize slot_func.val[p.val]).val]).val =
            fsN slot_func func_start p.val := by
          simp only [fsN, sfun, u32_cast_usize_val, e1, e2]
        have hev : (UScalar.cast .Usize func_end.val[(UScalar.cast .Usize slot_func.val[p.val]).val]).val =
            feN slot_func func_end p.val := by
          simp only [feN, sfun, u32_cast_usize_val, e1, e3]
        -- The first link.
        have step1 : hd1.length = insns.length ∧ nx1.length = 2 * insns.length ∧
            (∀ x, x < p.val → PredFact insns slot_func func_start func_end hd1.val nx1.val x) ∧
            ListsBelow hd1.val nx1.val (2 * p.val + 1) ∧
            (1 ≤ count.val → first.val < insns.length ∧
              ∃ y, ListMem nx1.val hd1.val[first.val]! y ∧ y.val = 2 * p.val) := by
          by_cases hc : count ≥ 1#usize
          · rw [if_pos hc] at hl1
            have hc' : 1 ≤ count.val := by
              simp only [ge_iff_le, UScalar.le_equiv] at hc; simpa using hc
            obtain_bind ⟨i6, hi6, hl1⟩ := hl1
            have hi6v := usize_mul_eq_ok hi6
            simp at hi6v
            obtain ⟨hfl, hel, hhd1, hnx1⟩ := link_ok hl1
            have hfl' : first.val < hd.val.length := by simpa [alloc.vec.Vec.length] using hfl
            have hfln : first.val < insns.length := by rw [← hhdl]; exact hfl'
            have hkl : 2 * p.val < nx.val.length := by rw [hnxl]; omega
            have hkv : (UScalar.cast .U32 i6).val = 2 * p.val := by
              rw [usize_cast_u32_val _ (by omega), hi6v]
            have hne : 2 * p.val ≠ liveness.NO_EDGE.val := by rw [NO_EDGE_val]; omega
            have hbelow' : ListsBelow hd.val nx.val (2 * p.val) := hbelow
            refine ⟨by simp [alloc.vec.Vec.length, hhd1, hhdl], by simp [alloc.vec.Vec.length, hnx1, hnxl],
              fun x hx => ?_, ?_, fun _ => ?_⟩
            · rw [hhd1, hnx1, hi6v]
              exact (hfact x hx).after_link hkv hne hfl' hkl hbelow'
            · rw [hhd1, hnx1, hi6v]
              exact ListsBelow.after_link hkv hfl' hkl hbelow'
            · refine ⟨hfln, UScalar.cast .U32 i6, ?_, hkv⟩
              rw [hhd1, hnx1, hi6v]
              exact (ListMem.after_link hkv hne hfl' hkl
                (fun q hq y hy => by have := hbelow' q hq y hy; omega)).2
          · rw [if_neg hc] at hl1
            simp only [ok.injEq, Prod.mk.injEq] at hl1
            obtain ⟨rfl, rfl⟩ := hl1
            have hc' : ¬ 1 ≤ count.val := by
              intro h1; apply hc
              simp only [ge_iff_le, UScalar.le_equiv]; simpa using h1
            exact ⟨hhd, hnx, hfact, hbelow.mono (by omega), fun h1 => absurd h1 hc'⟩
        obtain ⟨hhd1, hnx1, hfact1, hbelow1, hfirst⟩ := step1
        -- The second link.
        have step2 : hd2.length = insns.length ∧ nx2.length = 2 * insns.length ∧
            (∀ x, x < p.val → PredFact insns slot_func func_start func_end hd2.val nx2.val x) ∧
            ListsBelow hd2.val nx2.val (2 * p.val + 2) ∧
            (1 ≤ count.val → first.val < insns.length ∧
              ∃ y, ListMem nx2.val hd2.val[first.val]! y ∧ y.val = 2 * p.val) ∧
            (2 ≤ count.val → second.val < insns.length ∧
              ∃ y, ListMem nx2.val hd2.val[second.val]! y ∧ y.val = 2 * p.val + 1) := by
          by_cases hc : count ≥ 2#usize
          · rw [if_pos hc] at hl2
            have hc' : 2 ≤ count.val := by
              simp only [ge_iff_le, UScalar.le_equiv] at hc; simpa using hc
            obtain_bind ⟨i6, hi6, hl2⟩ := hl2
            obtain_bind ⟨i7, hi7, hl2⟩ := hl2
            have hi6v := usize_mul_eq_ok hi6
            have hi7v := usize_add_eq_ok hi7
            simp at hi6v hi7v
            obtain ⟨hsl, hel, hhd2, hnx2⟩ := link_ok hl2
            have hhd1l : hd1.val.length = insns.length := by simpa [alloc.vec.Vec.length] using hhd1
            have hnx1l : nx1.val.length = 2 * insns.length := by simpa [alloc.vec.Vec.length] using hnx1
            have hsl' : second.val < hd1.val.length := by simpa [alloc.vec.Vec.length] using hsl
            have hsln : second.val < insns.length := by rw [← hhd1l]; exact hsl'
            have hkl : 2 * p.val + 1 < nx1.val.length := by rw [hnx1l]; omega
            have hkv : (UScalar.cast .U32 i7).val = 2 * p.val + 1 := by
              rw [usize_cast_u32_val _ (by omega), hi7v, hi6v]
            have hne : 2 * p.val + 1 ≠ liveness.NO_EDGE.val := by rw [NO_EDGE_val]; omega
            have hfresh : ∀ q, q < hd1.val.length → ∀ y, ListMem nx1.val hd1.val[q]! y →
                y.val ≠ 2 * p.val + 1 := fun q hq y hy => by have := hbelow1 q hq y hy; omega
            have keep := (ListMem.after_link hkv hne hsl' hkl hfresh).1
            refine ⟨by simp [alloc.vec.Vec.length, hhd2, hhd1l], by simp [alloc.vec.Vec.length, hnx2, hnx1l],
              fun x hx => ?_, ?_, fun h1 => ?_, fun _ => ?_⟩
            · rw [hhd2, hnx2, hi7v, hi6v]
              exact (hfact1 x hx).after_link hkv hne hsl' hkl hbelow1
            · rw [hhd2, hnx2, hi7v, hi6v]
              exact ListsBelow.after_link hkv hsl' hkl hbelow1
            · obtain ⟨hlt1, y, hy, hyv⟩ := hfirst h1
              refine ⟨hlt1, y, ?_, hyv⟩
              rw [hhd2, hnx2, hi7v, hi6v]
              exact keep _ (by rw [hhd1l]; exact hlt1) y hy
            · refine ⟨hsln, UScalar.cast .U32 i7, ?_, hkv⟩
              rw [hhd2, hnx2, hi7v, hi6v]
              exact (ListMem.after_link hkv hne hsl' hkl hfresh).2
          · rw [if_neg hc] at hl2
            simp only [ok.injEq, Prod.mk.injEq] at hl2
            obtain ⟨rfl, rfl⟩ := hl2
            have hc' : ¬ 2 ≤ count.val := by
              intro h1; apply hc
              simp only [ge_iff_le, UScalar.le_equiv]; simpa using h1
            exact ⟨hhd1, hnx1, hfact1, hbelow1.mono (by omega), hfirst, fun h2 => absurd h2 hc'⟩
        obtain ⟨hhd2, hnx2, hfact2, hbelow2, hfirst2, hsecond2⟩ := step2
        refine ⟨by dsimp only; omega, hhd2, hnx2, fun x hx => ?_, ?_⟩
        · dsimp only at hx
          by_cases hxp : x = p.val
          · subst hxp
            intro pU s e c a b hpU hs he hsucc'
            have hpU' : pU = p := by rw [UScalar.eq_equiv]; exact hpU
            have hs' : s = UScalar.cast .Usize func_start.val[(UScalar.cast .Usize slot_func.val[p.val]).val] := by
              rw [UScalar.eq_equiv, hs, hsv]
            have he' : e = UScalar.cast .Usize func_end.val[(UScalar.cast .Usize slot_func.val[p.val]).val] := by
              rw [UScalar.eq_equiv, he, hev]
            rw [hpU', hs', he', hsucc] at hsucc'
            simp only [ok.injEq, Prod.mk.injEq] at hsucc'
            obtain ⟨rfl, rfl, rfl⟩ := hsucc'
            have hhd2l : hd2.val.length = insns.length := by simpa [alloc.vec.Vec.length] using hhd2
            refine ⟨fun h1 => ?_, fun h2 => ?_⟩
            · obtain ⟨hlt1, y, hy, hyv⟩ := hfirst2 h1
              exact ⟨by rw [hhd2l]; exact hlt1, y, hy, hyv⟩
            · obtain ⟨hlt2, y, hy, hyv⟩ := hsecond2 h2
              exact ⟨by rw [hhd2l]; exact hlt2, y, hy, hyv⟩
          · exact hfact2 x (by omega)
        · dsimp only
          rw [hp1v]
          exact hbelow2.mono (by omega)
      · rename_i hge
        simp only [ok.injEq] at hb
        subst hb
        have : insns.length ≤ p.val := by
          have := usize_not_lt hge; simpa [slice_len_val] using this
        have hpn : p.val = insns.length := by omega
        refine ⟨hhd, hnx, fun x hx => hfact x (by omega), ?_⟩
        rw [← hpn]; exact hbelow)
    _ _ ⟨by simp, hh, hn, fun x hx => by simp at hx, fun q hq y hy => ?_⟩ h
  · exact hres
  · exfalso
    rw [hh0 q (by rwa [← hh])] at hy
    exact hy.ne rfl

/-! ## The call-site lists -/

/-- A resolved call at `p` is on its callee's list. -/
def CallFact (callee : Slice U32) (head next : List U32) (p : Nat) : Prop :=
  ∀ f, (callee.val[p]!).val = f → f ≠ liveness.NOT_A_CALL.val → f ≠ 4294967294 →
    f < head.length ∧ ∃ y, ListMem next head[f]! y ∧ y.val = p

theorem CallFact.after_link {callee : Slice U32} {head next : List U32} {a k : Nat} {kU : U32}
    (hkv : kU.val = k) (hne : k ≠ liveness.NO_EDGE.val) (ha : a < head.length) (hkl : k < next.length)
    (hbelow : ListsBelow head next k) {x : Nat} (hx : CallFact callee head next x) :
    CallFact callee (head.set a kU) (next.set k head[a]!) x := by
  intro f hf h1 h2
  obtain ⟨hlt, y, hy, hyv⟩ := hx f hf h1 h2
  have keep := (ListMem.after_link hkv hne ha hkl
    (fun q hq y hy => by have := hbelow q hq y hy; omega)).1
  exact ⟨by simpa using hlt, y, keep _ hlt y hy, hyv⟩

/-- `build_callers` leaves every resolved call on its callee's list. -/
theorem build_callers_ok {insns : Slice isa.Insn} {slot_func func_start func_end callee : Slice U32}
    (hS : Shape insns slot_func func_start func_end callee) {head next head' next' : alloc.vec.Vec U32}
    (hh : head.length = func_start.length) (hn : next.length = insns.length)
    (hh0 : ∀ q, q < func_start.length → head.val[q]! = liveness.NO_EDGE)
    (h : liveness.build_callers callee head next = ok (head', next')) :
    head'.length = func_start.length ∧ next'.length = insns.length ∧
    (∀ p, p < insns.length → CallFact callee head'.val next'.val p) ∧
    ListsBelow head'.val next'.val insns.length := by
  have hnlt := hS.n_lt
  have hcl : callee.val.length = insns.length := by
    have := hS.callee_len; simpa [Slice.length] using this
  unfold liveness.build_callers liveness.build_callers_loop at h
  have hres := loop_ok_induction _
    (fun st : alloc.vec.Vec U32 × alloc.vec.Vec U32 × Usize => st.2.2.val ≤ insns.length ∧
      st.1.length = func_start.length ∧ st.2.1.length = insns.length ∧
      (∀ x, x < st.2.2.val → CallFact callee st.1.val st.2.1.val x) ∧
      ListsBelow st.1.val st.2.1.val st.2.2.val)
    (fun y : alloc.vec.Vec U32 × alloc.vec.Vec U32 => y.1.length = func_start.length ∧
      y.2.length = insns.length ∧ (∀ p, p < insns.length → CallFact callee y.1.val y.2.val p) ∧
      ListsBelow y.1.val y.2.val insns.length)
    (by
      rintro ⟨hd, nx, p⟩ ⟨hp, hhd, hnx, hfact, hbelow⟩ res hb
      dsimp only at hp hhd hnx hfact hbelow
      change liveness.build_callers_loop.body callee hd nx p = ok res at hb
      unfold liveness.build_callers_loop.body at hb
      dsimp only at hb
      have hhdl : hd.val.length = func_start.length := by simpa [alloc.vec.Vec.length] using hhd
      have hnxl : nx.val.length = insns.length := by simpa [alloc.vec.Vec.length] using hnx
      split at hb
      · rename_i hlt
        have hlt' : p.val < insns.length := by
          rw [UScalar.lt_equiv] at hlt; simpa [slice_len_val, Slice.length, hcl] using hlt
        obtain_bind ⟨c, hc, hb⟩ := hb
        obtain_bind ⟨⟨hd1, nx1⟩, hl, hb⟩ := hb
        obtain_bind ⟨p1, hp1, hb⟩ := hb
        have hp1v := usize_add_eq_ok hp1
        simp at hp1v
        simp only [ok.injEq] at hb
        subst hb
        obtain ⟨_, rfl⟩ := slice_index_usize_eq_ok hc
        have hcp : callee.val[p.val]! = callee.val[p.val] := getBang_eq (by rw [hcl]; exact hlt')
        -- Whether the slot is linked, and what that did.
        have step : hd1.length = func_start.length ∧ nx1.length = insns.length ∧
            (∀ x, x < p.val → CallFact callee hd1.val nx1.val x) ∧
            ListsBelow hd1.val nx1.val (p.val + 1) ∧ CallFact callee hd1.val nx1.val p.val := by
          by_cases h1 : (callee.val[p.val] != liveness.NOT_A_CALL) = true
          · rw [if_pos h1] at hl
            obtain_bind ⟨u, hu, hl⟩ := hl
            have huv : u.val = 4294967294 := by
              obtain ⟨u', hu', huv⟩ := UNRESOLVED_ok
              rw [hu'] at hu
              simp only [ok.injEq] at hu
              rw [← hu]; exact huv
            by_cases h2 : (callee.val[p.val] != u) = true
            · rw [if_pos h2] at hl
              obtain_bind ⟨i2, hi2, hl⟩ := hl
              rw [lift_eq_ok hi2] at hl
              obtain ⟨hal, hel, hhd1, hnx1⟩ := link_ok hl
              have hal' : (UScalar.cast .Usize callee.val[p.val]).val < hd.val.length := by
                simpa [alloc.vec.Vec.length] using hal
              have hkl : p.val < nx.val.length := by rw [hnxl]; exact hlt'
              have hkv : (UScalar.cast .U32 p).val = p.val := usize_cast_u32_val _ (by omega)
              have hne : p.val ≠ liveness.NO_EDGE.val := by rw [NO_EDGE_val]; omega
              refine ⟨by simp [alloc.vec.Vec.length, hhd1, hhdl], by simp [alloc.vec.Vec.length, hnx1, hnxl],
                fun x hx => ?_, ?_, ?_⟩
              · rw [hhd1, hnx1]
                exact (hfact x hx).after_link hkv hne hal' hkl hbelow
              · rw [hhd1, hnx1]
                exact ListsBelow.after_link hkv hal' hkl hbelow
              · intro f hf _ _
                rw [hcp, u32_cast_usize_val] at *
                subst hf
                refine ⟨by simpa [alloc.vec.Vec.length, hhd1] using hal', UScalar.cast .U32 p, ?_, hkv⟩
                rw [hhd1, hnx1]
                exact (ListMem.after_link hkv hne (by simpa [u32_cast_usize_val] using hal') hkl
                  (fun q hq y hy => by have := hbelow q hq y hy; omega)).2
            · rw [if_neg h2] at hl
              simp only [ok.injEq, Prod.mk.injEq] at hl
              obtain ⟨rfl, rfl⟩ := hl
              have heq : (callee.val[p.val]).val = 4294967294 := by
                simp only [bne_iff_ne, ne_eq, not_not] at h2
                rw [h2, huv]
              refine ⟨hhd, hnx, hfact, hbelow.mono (by omega), fun f hf _ hne => ?_⟩
              exfalso
              rw [hcp] at hf
              exact hne (hf ▸ heq)
          · rw [if_neg h1] at hl
            simp only [ok.injEq, Prod.mk.injEq] at hl
            obtain ⟨rfl, rfl⟩ := hl
            have heq : (callee.val[p.val]).val = liveness.NOT_A_CALL.val := by
              simp only [bne_iff_ne, ne_eq, not_not] at h1
              rw [h1]
            refine ⟨hhd, hnx, hfact, hbelow.mono (by omega), fun f hf hne _ => ?_⟩
            exfalso
            rw [hcp] at hf
            exact hne (hf ▸ heq)
        obtain ⟨hhd1, hnx1, hfact1, hbelow1, hfactp⟩ := step
        refine ⟨by dsimp only; omega, hhd1, hnx1, fun x hx => ?_, ?_⟩
        · dsimp only at hx
          by_cases hxp : x = p.val
          · subst hxp; exact hfactp
          · exact hfact1 x (by omega)
        · dsimp only
          rw [hp1v]
          exact hbelow1
      · rename_i hge
        simp only [ok.injEq] at hb
        subst hb
        have : insns.length ≤ p.val := by
          have := usize_not_lt hge; simpa [slice_len_val, Slice.length, hcl] using this
        have hpn : p.val = insns.length := by omega
        exact ⟨hhd, hnx, fun x hx => hfact x (by omega), hpn ▸ hbelow⟩)
    _ _ ⟨by simp, hh, hn, fun x hx => by simp at hx, fun q hq y hy => ?_⟩ h
  · exact hres
  · exfalso
    rw [hh0 q (by rwa [← hh])] at hy
    exact hy.ne rfl

/-! ## The worklist -/

/-- The worklist as a stack: `queued` marks exactly the slots on
`stack[0..sp)`, which are distinct and in range. -/
structure StackInv (n : Nat) (queued : List Bool) (stack : List U32) (sp : Nat) : Prop where
  qlen : queued.length = n
  slen : stack.length = n
  sp_le : sp ≤ n
  mem : ∀ x, x < n → (queued[x]! = true ↔ ∃ i, i < sp ∧ (stack[i]!).val = x)
  nodup : ∀ i j, i < sp → j < sp → (stack[i]!).val = (stack[j]!).val → i = j
  bounded : ∀ i, i < sp → (stack[i]!).val < n

/-- Distinct values below `n`, `sp` of them, with one below `n` missing: `sp < n`. -/
theorem StackInv.room {n : Nat} {queued : List Bool} {stack : List U32} {sp : Nat}
    (h : StackInv n queued stack sp) {x : Nat} (hx : x < n) (hq : queued[x]! = false) : sp < n := by
  -- The values on the stack together with `x` are `sp + 1` distinct numbers below `n`.
  let vals : List Nat := ((List.range sp).map fun i => (stack[i]!).val) ++ [x]
  have hnd : vals.Nodup := by
    rw [List.nodup_append]
    refine ⟨?_, List.nodup_singleton _, ?_⟩
    · rw [List.nodup_map_iff_inj_on (List.nodup_range)]
      intro i hi j hj hij
      exact h.nodup i j (List.mem_range.mp hi) (List.mem_range.mp hj) hij
    · intro a ha b hb
      simp only [List.mem_singleton] at hb
      rw [hb]
      obtain ⟨i, hi, rfl⟩ := List.mem_map.mp ha
      intro heq
      have := (h.mem x hx).mpr ⟨i, List.mem_range.mp hi, heq⟩
      rw [hq] at this
      exact Bool.false_ne_true this
  have hsub : vals ⊆ List.range n := by
    intro v hv
    rw [List.mem_range]
    rcases List.mem_append.mp hv with hv | hv
    · obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hv
      exact h.bounded i (List.mem_range.mp hi)
    · simp only [List.mem_singleton] at hv
      omega
  have := (hnd.subperm hsub).length_le
  simp [vals] at this
  omega

/-- `wake` queues every member of the list and dequeues nothing. -/
theorem wake_ok {n : Nat} {next : Slice U32} {queued queued' : alloc.vec.Vec Bool}
    {stack stack' : alloc.vec.Vec U32} {sp top : Usize} {e per : U32}
    (hn : n < 2 ^ 31) (hper : per.val ≠ 0) (hI : StackInv n queued.val stack.val sp.val)
    (hmem : ∀ y, ListMem next.val e y → y.val / per.val < n)
    (h : liveness.wake next queued stack sp e per = ok (top, queued', stack')) :
    StackInv n queued'.val stack'.val top.val ∧
    (∀ y, ListMem next.val e y → queued'.val[y.val / per.val]! = true) ∧
    (∀ x, x < n → queued.val[x]! = true → queued'.val[x]! = true) := by
  unfold liveness.wake liveness.wake_loop at h
  exact loop_ok_induction _
    (fun st : alloc.vec.Vec Bool × alloc.vec.Vec U32 × U32 × Usize =>
      StackInv n st.1.val st.2.1.val st.2.2.2.val ∧
      (∀ y, ListMem next.val st.2.2.1 y → ListMem next.val e y) ∧
      (∀ y, ListMem next.val e y → st.1.val[y.val / per.val]! = true ∨ ListMem next.val st.2.2.1 y) ∧
      (∀ x, x < n → queued.val[x]! = true → st.1.val[x]! = true))
    (fun y : Usize × alloc.vec.Vec Bool × alloc.vec.Vec U32 =>
      StackInv n y.2.1.val y.2.2.val y.1.val ∧
      (∀ z, ListMem next.val e z → y.2.1.val[z.val / per.val]! = true) ∧
      (∀ x, x < n → queued.val[x]! = true → y.2.1.val[x]! = true))
    (by
      rintro ⟨qd, st, ec, tp⟩ ⟨hI, hsub, hcover, hmono⟩ res hb
      dsimp only at hI hsub hcover hmono
      change liveness.wake_loop.body next per qd st ec tp = ok res at hb
      unfold liveness.wake_loop.body at hb
      split at hb
      · rename_i hne
        have hne' : ec.val ≠ liveness.NO_EDGE.val := by
          rw [bne_iff_ne] at hne
          intro h; apply hne; rw [UScalar.eq_equiv]; exact h
        obtain_bind ⟨i, hi, hb⟩ := hb
        obtain_bind ⟨p, hp, hb⟩ := hb
        obtain_bind ⟨b, hbq, hb⟩ := hb
        obtain_bind ⟨⟨qd1, st1, tp1⟩, hpush, hb⟩ := hb
        obtain_bind ⟨i1, hi1, hb⟩ := hb
        obtain_bind ⟨e1, he1, hb⟩ := hb
        simp only [ok.injEq] at hb
        subst hb
        rw [lift_eq_ok hp] at hbq hpush
        rw [lift_eq_ok hi1] at he1
        obtain ⟨z, hz, hzv⟩ := u32_div_ok ec per hper
        rw [hz] at hi
        simp only [ok.injEq] at hi
        subst hi
        have hpv : (UScalar.cast .Usize z).val = ec.val / per.val := by
          rw [u32_cast_usize_val, hzv]
        obtain ⟨hpl, rfl⟩ := vec_index_eq_ok hbq
        obtain ⟨hel, rfl⟩ := slice_index_usize_eq_ok he1
        have hecmem : ListMem next.val ec ec := .head hne'
        have hpn : ec.val / per.val < n := hmem ec (hsub ec hecmem)
        have he1v : next.val[(UScalar.cast .Usize ec).val] = next.val[ec.val]! := by
          rw [getBang_eq (l := next.val) (i := ec.val) (by simpa [u32_cast_usize_val] using hel)]
          simp
        -- Members of the tail are members of the list.
        have hsub' : ∀ y, ListMem next.val next.val[ec.val]! y → ListMem next.val e y :=
          fun y hy => hsub y (.tail hne' hy)
        -- The push, if any.
        have step : StackInv n qd1.val st1.val tp1.val ∧ qd1.val[ec.val / per.val]! = true ∧
            (∀ x, x < n → qd.val[x]! = true → qd1.val[x]! = true) := by
          by_cases hb' : qd.val[(UScalar.cast .Usize z).val] = true
          · rw [if_pos hb'] at hpush
            simp only [ok.injEq, Prod.mk.injEq] at hpush
            obtain ⟨rfl, rfl, rfl⟩ := hpush
            refine ⟨hI, ?_, fun x _ hx => hx⟩
            rw [← hpv, getBang_eq (by simpa [alloc.vec.Vec.length] using hpl)]
            exact hb'
          · rw [if_neg hb'] at hpush
            obtain_bind ⟨⟨_, backq⟩, hbq', hpush⟩ := hpush
            obtain_bind ⟨⟨_, backs⟩, hbs, hpush⟩ := hpush
            obtain_bind ⟨i2, hi2, hpush⟩ := hpush
            obtain_bind ⟨tp2, htp2, hpush⟩ := hpush
            simp only [ok.injEq, Prod.mk.injEq] at hpush
            obtain ⟨rfl, rfl, rfl⟩ := hpush
            obtain ⟨_, _, rfl⟩ := vec_index_mut_eq_ok hbq'
            obtain ⟨htpl, _, rfl⟩ := vec_index_mut_eq_ok hbs
            rw [lift_eq_ok hi2]
            have htp2v := usize_add_eq_ok htp2
            simp at htp2v
            have hqf : qd.val[ec.val / per.val]! = false := by
              rw [← hpv, getBang_eq (by simpa [alloc.vec.Vec.length] using hpl)]
              simpa using hb'
            have hroom := hI.room hpn hqf
            have hcast : (UScalar.cast .U32 (UScalar.cast .Usize z)).val = ec.val / per.val := by
              rw [usize_cast_u32_val _ (by rw [hpv]; omega), hpv]
            have hql : qd.val.length = n := hI.qlen
            have hsl : st.val.length = n := hI.slen
            refine ⟨⟨?_, ?_, ?_, ?_, ?_, ?_⟩, ?_, ?_⟩
            · simp [alloc.vec.Vec.set_val_eq, hql]
            · simp [alloc.vec.Vec.set_val_eq, hsl]
            · rw [htp2v]; omega
            · intro x hx
              simp only [alloc.vec.Vec.set_val_eq, htp2v]
              by_cases hxp : x = ec.val / per.val
              · subst hxp
                rw [← hpv, getBang_set_self (by rw [hpv, hql]; exact hpn)]
                simp only [true_iff]
                refine ⟨tp.val, by omega, ?_⟩
                rw [getBang_set_self (by rw [hsl]; exact hroom)]
                exact hcast.trans hpv.symm
              · rw [List.getElem!_eq_getElem?_getD, List.getElem?_set_ne (by rw [hpv]; exact Ne.symm hxp),
                  ← List.getElem!_eq_getElem?_getD, hI.mem x hx]
                constructor
                · rintro ⟨i, hi, hiv⟩
                  refine ⟨i, by omega, ?_⟩
                  rw [getBang_set_ne (by omega)]
                  exact hiv
                · rintro ⟨i, hi, hiv⟩
                  by_cases hit : i = tp.val
                  · subst hit
                    rw [getBang_set_self (by rw [hsl]; omega), hcast] at hiv
                    exact absurd hiv.symm hxp
                  · refine ⟨i, by omega, ?_⟩
                    rw [getBang_set_ne hit] at hiv
                    exact hiv
            · intro i j hi hj hij
              simp only [alloc.vec.Vec.set_val_eq, htp2v] at hi hj hij
              by_cases hit : i = tp.val <;> by_cases hjt : j = tp.val
              · rw [hit, hjt]
              · subst hit
                rw [getBang_set_self (by rw [hsl]; omega), getBang_set_ne hjt, hcast] at hij
                exfalso
                have := (hI.mem _ hpn).mpr ⟨j, by omega, hij.symm⟩
                rw [hqf] at this
                exact Bool.false_ne_true this
              · subst hjt
                rw [getBang_set_ne hit, getBang_set_self (by rw [hsl]; omega), hcast] at hij
                exfalso
                have := (hI.mem _ hpn).mpr ⟨i, by omega, hij⟩
                rw [hqf] at this
                exact Bool.false_ne_true this
              · rw [getBang_set_ne hit, getBang_set_ne hjt] at hij
                exact hI.nodup i j (by omega) (by omega) hij
            · intro i hi
              simp only [alloc.vec.Vec.set_val_eq, htp2v] at hi ⊢
              by_cases hit : i = tp.val
              · subst hit
                rw [getBang_set_self (by rw [hsl]; omega), hcast]
                exact hpn
              · rw [getBang_set_ne hit]
                exact hI.bounded i (by omega)
            · simp only [alloc.vec.Vec.set_val_eq]
              rw [← hpv, getBang_set_self (by rw [hpv, hql]; exact hpn)]
            · intro x hx hqx
              simp only [alloc.vec.Vec.set_val_eq]
              by_cases hxp : x = (UScalar.cast .Usize z).val
              · subst hxp
                rw [getBang_set_self (by simpa [alloc.vec.Vec.length, hql] using hpl)]
              · rw [List.getElem!_eq_getElem?_getD, List.getElem?_set_ne (Ne.symm hxp),
                  ← List.getElem!_eq_getElem?_getD]
                exact hqx
        obtain ⟨hI1, hqp, hmono1⟩ := step
        refine ⟨hI1, ?_, ?_, fun x hx hqx => hmono1 x hx (hmono x hx hqx)⟩
        · dsimp only
          rw [he1v]
          exact hsub'
        · intro y hy
          dsimp only
          rw [he1v]
          rcases hcover y hy with hq | hm
          · left
            exact hmono1 _ (hmem y hy) hq
          · cases hm with
            | head _ => left; exact hqp
            | tail _ hm' => right; exact hm'
      · rename_i hend
        simp only [ok.injEq] at hb
        subst hb
        have hend' : ec.val = liveness.NO_EDGE.val := by
          simp only [bne_iff_ne, ne_eq, not_not] at hend
          rw [hend]
        refine ⟨hI, fun z hz => ?_, hmono⟩
        rcases hcover z hz with hq | hm
        · exact hq
        · exact absurd hend' hm.ne)
    _ _ ⟨hI, fun y hy => hy, fun y hy => Or.inr hy, fun x _ hx => hx⟩ h

/-! ## `uses_and_defs` and the callee summary -/

theorem reg_bit_total (reg : Usize) : ∃ b, region.reg_bit reg = ok b := by
  unfold region.reg_bit
  split
  · rename_i hlt
    have hlt' : reg.val < 10 := by
      rw [UScalar.lt_equiv] at hlt; simpa [region.R10] using hlt
    obtain ⟨z, hz, _⟩ := WP.spec_imp_exists (UScalar.ShiftLeft_spec 1#u16 reg (UScalar.size .U16)
      (by change reg.val < 16; omega) rfl)
    exact ⟨z, hz⟩
  · exact ⟨_, rfl⟩

theorem is_atomic_total (opcode : U8) : ∃ b, region.is_atomic opcode = ok b := by
  unfold region.is_atomic
  simp only [lift, bind_tc_ok]
  split <;> exact ⟨_, rfl⟩

/-- Split one `if` in `h` and `h'` alike. -/
macro "both_if" hc:ident ":" c:term "at" h:ident h':ident : tactic =>
  `(tactic| (by_cases $hc:ident : $c <;>
      [rw [if_pos $hc] at $h:ident $h':ident; rw [if_neg $hc] at $h:ident $h':ident]))

/-- Split one `if` in the goal. -/
macro "goal_if" hc:ident ":" c:term : tactic =>
  `(tactic| (by_cases $hc:ident : $c <;> [rw [if_pos $hc]; rw [if_neg $hc]]))

/-- A leaf of `uses_and_defs`, reached in two runs: the same defs, and either
the same uses or the masks. -/
macro "leaf_same" h:ident h':ident : tactic =>
  `(tactic| (simp only [ok.injEq, Prod.mk.injEq] at $h:ident $h':ident
             obtain ⟨hu_leaf, hd_leaf⟩ := $h:ident
             obtain ⟨hu_leaf', hd_leaf'⟩ := $h':ident
             first
               | exact ⟨hd_leaf'.symm.trans hd_leaf, Or.inl (hu_leaf'.symm.trans hu_leaf)⟩
               | exact ⟨hd_leaf'.symm.trans hd_leaf, Or.inr ⟨hu_leaf.symm, hu_leaf'.symm⟩⟩))

set_option maxHeartbeats 1000000 in
/-- Two masks: the same defs, and either the same uses or the masks themselves.
The mask reaches the result only through the local-call leaf. -/
theorem uses_and_defs_summary {inst : isa.Insn} {m m' u d u' d' : U16}
    (h : region.uses_and_defs inst m = ok (u, d)) (h' : region.uses_and_defs inst m' = ok (u', d')) :
    d' = d ∧ (u' = u ∨ (u = m ∧ u' = m')) := by
  unfold region.uses_and_defs at h h'
  simp only [lift] at h h'
  simp only [bind_tc_ok] at h h'
  obtain ⟨bd, hbd⟩ := reg_bit_total (UScalar.cast .Usize inst.dst)
  obtain ⟨bs, hbs⟩ := reg_bit_total (UScalar.cast .Usize inst.src)
  obtain ⟨b0, hb0⟩ := reg_bit_total 0#usize
  obtain ⟨at_, hat⟩ := is_atomic_total inst.opcode
  simp only [hbd] at h h'
  simp only [hbs] at h h'
  simp only [hb0] at h h'
  simp only [hat] at h h'
  simp only [bind_tc_ok] at h h'
  both_if c0 : inst.opcode &&& isa.CLS_MASK = isa.CLS_LD at h h'
  · leaf_same h h'
  both_if c1 : inst.opcode &&& isa.CLS_MASK = isa.CLS_LDX at h h'
  · leaf_same h h'
  both_if c2 : inst.opcode &&& isa.CLS_MASK = isa.CLS_ST at h h'
  · leaf_same h h'
  both_if c3 : inst.opcode &&& isa.CLS_MASK = isa.CLS_STX at h h'
  · both_if ca : at_ = true at h h'
    · leaf_same h h'
    · leaf_same h h'
  both_if c4 : inst.opcode &&& isa.CLS_MASK = isa.CLS_ALU at h h'
  · both_if cs : (inst.opcode &&& isa.SRC_REG != 0#u8) = true at h h' <;>
      (try simp only [bind_tc_ok] at h h') <;>
      both_if cm : inst.opcode &&& isa.ALU_MASK = region.ALU_OP_MOV at h h' <;> leaf_same h h'
  both_if c5 : inst.opcode &&& isa.CLS_MASK = isa.CLS_ALU64 at h h'
  · both_if cs : (inst.opcode &&& isa.SRC_REG != 0#u8) = true at h h' <;>
      (try simp only [bind_tc_ok] at h h') <;>
      both_if cm : inst.opcode &&& isa.ALU_MASK = region.ALU_OP_MOV at h h' <;> leaf_same h h'
  both_if c6 : inst.opcode &&& isa.CLS_MASK = isa.CLS_JMP at h h'
  · both_if ce : inst.opcode = isa.OP_EXIT at h h'
    · leaf_same h h'
    both_if cc : inst.opcode = isa.OP_CALL at h h'
    · both_if s0 : inst.src = 0#u8 at h h'
      · leaf_same h h'
      both_if s1 : inst.src = 1#u8 at h h'
      · leaf_same h h'
      both_if s2 : inst.src = 2#u8 at h h'
      · leaf_same h h'
      · leaf_same h h'
    both_if cja : inst.opcode = isa.OP_JA at h h'
    · leaf_same h h'
    both_if cja32 : inst.opcode = isa.OP_JA32 at h h'
    · leaf_same h h'
    both_if cs : (inst.opcode &&& isa.SRC_REG != 0#u8) = true at h h' <;>
      (try simp only [bind_tc_ok] at h h') <;> leaf_same h h'
  both_if c7 : inst.opcode &&& isa.CLS_MASK = isa.CLS_JMP32 at h h'
  · both_if ce : inst.opcode = isa.OP_EXIT at h h'
    · leaf_same h h'
    both_if cc : inst.opcode = isa.OP_CALL at h h'
    · both_if s0 : inst.src = 0#u8 at h h'
      · leaf_same h h'
      both_if s1 : inst.src = 1#u8 at h h'
      · leaf_same h h'
      both_if s2 : inst.src = 2#u8 at h h'
      · leaf_same h h'
      · leaf_same h h'
    both_if cja : inst.opcode = isa.OP_JA at h h'
    · leaf_same h h'
    both_if cja32 : inst.opcode = isa.OP_JA32 at h h'
    · leaf_same h h'
    both_if cs : (inst.opcode &&& isa.SRC_REG != 0#u8) = true at h h' <;>
      (try simp only [bind_tc_ok] at h h') <;> leaf_same h h'
  leaf_same h h'

set_option maxHeartbeats 1000000 in
/-- `uses_and_defs` succeeds on every instruction and mask. -/
theorem uses_and_defs_total (inst : isa.Insn) (m : U16) :
    ∃ u d, region.uses_and_defs inst m = ok (u, d) := by
  unfold region.uses_and_defs
  simp only [lift]
  simp only [bind_tc_ok]
  obtain ⟨bd, hbd⟩ := reg_bit_total (UScalar.cast .Usize inst.dst)
  obtain ⟨bs, hbs⟩ := reg_bit_total (UScalar.cast .Usize inst.src)
  obtain ⟨b0, hb0⟩ := reg_bit_total 0#usize
  obtain ⟨at_, hat⟩ := is_atomic_total inst.opcode
  simp only [hbd]
  simp only [hbs]
  simp only [hb0]
  simp only [hat]
  simp only [bind_tc_ok]
  goal_if c0 : inst.opcode &&& isa.CLS_MASK = isa.CLS_LD
  · exact ⟨_, _, rfl⟩
  goal_if c1 : inst.opcode &&& isa.CLS_MASK = isa.CLS_LDX
  · exact ⟨_, _, rfl⟩
  goal_if c2 : inst.opcode &&& isa.CLS_MASK = isa.CLS_ST
  · exact ⟨_, _, rfl⟩
  goal_if c3 : inst.opcode &&& isa.CLS_MASK = isa.CLS_STX
  · goal_if ca : at_ = true <;> exact ⟨_, _, rfl⟩
  goal_if c4 : inst.opcode &&& isa.CLS_MASK = isa.CLS_ALU
  · goal_if cs : (inst.opcode &&& isa.SRC_REG != 0#u8) = true <;> (try simp only [bind_tc_ok]) <;>
      goal_if cm : inst.opcode &&& isa.ALU_MASK = region.ALU_OP_MOV <;> exact ⟨_, _, rfl⟩
  goal_if c5 : inst.opcode &&& isa.CLS_MASK = isa.CLS_ALU64
  · goal_if cs : (inst.opcode &&& isa.SRC_REG != 0#u8) = true <;> (try simp only [bind_tc_ok]) <;>
      goal_if cm : inst.opcode &&& isa.ALU_MASK = region.ALU_OP_MOV <;> exact ⟨_, _, rfl⟩
  goal_if c6 : inst.opcode &&& isa.CLS_MASK = isa.CLS_JMP
  · goal_if ce : inst.opcode = isa.OP_EXIT
    · exact ⟨_, _, rfl⟩
    goal_if cc : inst.opcode = isa.OP_CALL
    · goal_if s0 : inst.src = 0#u8
      · exact ⟨_, _, rfl⟩
      goal_if s1 : inst.src = 1#u8
      · exact ⟨_, _, rfl⟩
      goal_if s2 : inst.src = 2#u8 <;> exact ⟨_, _, rfl⟩
    goal_if cja : inst.opcode = isa.OP_JA
    · exact ⟨_, _, rfl⟩
    goal_if cja32 : inst.opcode = isa.OP_JA32
    · exact ⟨_, _, rfl⟩
    goal_if cs : (inst.opcode &&& isa.SRC_REG != 0#u8) = true <;> (try simp only [bind_tc_ok]) <;>
      exact ⟨_, _, rfl⟩
  goal_if c7 : inst.opcode &&& isa.CLS_MASK = isa.CLS_JMP32
  · goal_if ce : inst.opcode = isa.OP_EXIT
    · exact ⟨_, _, rfl⟩
    goal_if cc : inst.opcode = isa.OP_CALL
    · goal_if s0 : inst.src = 0#u8
      · exact ⟨_, _, rfl⟩
      goal_if s1 : inst.src = 1#u8
      · exact ⟨_, _, rfl⟩
      goal_if s2 : inst.src = 2#u8 <;> exact ⟨_, _, rfl⟩
    goal_if cja : inst.opcode = isa.OP_JA
    · exact ⟨_, _, rfl⟩
    goal_if cja32 : inst.opcode = isa.OP_JA32
    · exact ⟨_, _, rfl⟩
    goal_if cs : (inst.opcode &&& isa.SRC_REG != 0#u8) = true <;> (try simp only [bind_tc_ok]) <;>
      exact ⟨_, _, rfl⟩
  exact ⟨_, _, rfl⟩

/-- The callee summary a call at `p` reads from the table `live`. -/
def summary (callee func_start : Slice U32) (live : List U16) (p : Nat) : U16 :=
  if (callee.val[p]!).val = liveness.NOT_A_CALL.val then 0#u16
  else if (callee.val[p]!).val = 4294967294 then region.ALL_SIGNATURE_REGS
  else live[(func_start.val[(callee.val[p]!).val]!).val]!

theorem callee_summary_spec {callee func_start : Slice U32} {live : List U16} {p : Nat} {c : U32}
    (hc : c = callee.val[p]!) {s : Slice U16} (hs : s.val = live) {m : U16}
    (h : liveness.callee_summary c func_start s = ok m) : m = summary callee func_start live p := by
  unfold liveness.callee_summary at h
  unfold summary
  subst hc hs
  split at h
  · rename_i heq
    simp only [ok.injEq] at h
    rw [if_pos (by rw [heq])]
    exact h.symm
  · rename_i hne
    obtain_bind ⟨u, hu, h⟩ := h
    have huv : u.val = 4294967294 := by
      obtain ⟨u', hu', huv⟩ := UNRESOLVED_ok
      rw [hu'] at hu
      simp only [ok.injEq] at hu
      rw [← hu]; exact huv
    have hne' : (callee.val[p]!).val ≠ liveness.NOT_A_CALL.val := by
      intro h'; apply hne; rw [UScalar.eq_equiv]; exact h'
    rw [if_neg hne']
    split at h
    · rename_i heq
      simp only [ok.injEq] at h
      rw [if_pos (by rw [heq, huv])]
      exact h.symm
    · rename_i hne2
      have hne2' : (callee.val[p]!).val ≠ 4294967294 := by
        intro h'; apply hne2; rw [UScalar.eq_equiv, huv]; exact h'
      rw [if_neg hne2']
      obtain_bind ⟨i1, hi1, h⟩ := h
      obtain_bind ⟨i2, hi2, h⟩ := h
      obtain_bind ⟨i3, hi3, h⟩ := h
      rw [lift_eq_ok hi1] at hi2
      rw [lift_eq_ok hi3] at h
      obtain ⟨hl2, rfl⟩ := slice_index_usize_eq_ok hi2
      obtain ⟨hl3, rfl⟩ := slice_index_usize_eq_ok h
      have hcb : (callee.val[p]!).val < func_start.val.length := by
        simpa [u32_cast_usize_val, Slice.length] using hl2
      have hfb : (func_start.val[(callee.val[p]!).val]).val < s.val.length := by
        simpa [u32_cast_usize_val, Slice.length] using hl3
      simp only [List.getElem!_eq_getElem?_getD, u32_cast_usize_val] at hcb hfb ⊢
      rw [List.getElem?_eq_getElem hcb, Option.getD_some, List.getElem?_eq_getElem hfb, Option.getD_some]

/-- `seed` fills the stack with `0, 1, …`. -/
theorem seed_ok {stack stack' : alloc.vec.Vec U32} (hn : stack.length < 2 ^ 32)
    (h : liveness.seed stack = ok stack') :
    stack'.length = stack.length ∧ ∀ i, i < stack.length → (stack'.val[i]!).val = i := by
  unfold liveness.seed liveness.seed_loop at h
  exact loop_ok_induction _
    (fun st : alloc.vec.Vec U32 × Usize => st.2.val ≤ stack.length ∧ st.1.length = stack.length ∧
      ∀ i, i < st.2.val → (st.1.val[i]!).val = i)
    (fun y : alloc.vec.Vec U32 => y.length = stack.length ∧ ∀ i, i < stack.length → (y.val[i]!).val = i)
    (by
      rintro ⟨st, i⟩ ⟨hi, hl, hfill⟩ res hb
      dsimp only at hi hl hfill
      change liveness.seed_loop.body st i = ok res at hb
      unfold liveness.seed_loop.body at hb
      dsimp only at hb
      split at hb
      · rename_i hlt
        have hlt' : i.val < stack.length := by
          rw [UScalar.lt_equiv] at hlt; simpa [alloc.vec.Vec.len_val, hl] using hlt
        obtain_bind ⟨⟨_, back⟩, hbk, hb⟩ := hb
        obtain_bind ⟨i2, hi2, hb⟩ := hb
        obtain_bind ⟨i3, hi3, hb⟩ := hb
        simp only [ok.injEq] at hb
        subst hb
        obtain ⟨hil, _, rfl⟩ := vec_index_mut_eq_ok hbk
        rw [lift_eq_ok hi2]
        have hi3v := usize_add_eq_ok hi3
        simp at hi3v
        have hsl : st.val.length = stack.length := by simpa [alloc.vec.Vec.length] using hl
        refine ⟨by dsimp only; omega, by simp [alloc.vec.Vec.length, alloc.vec.Vec.set_val_eq, hsl], fun k hk => ?_⟩
        dsimp only at hk ⊢
        simp only [alloc.vec.Vec.set_val_eq]
        by_cases hki : k = i.val
        · subst hki
          rw [getBang_set_self (by rw [hsl]; exact hlt')]
          exact usize_cast_u32_val _ (by omega)
        · rw [getBang_set_ne hki]
          exact hfill k (by omega)
      · rename_i hge
        simp only [ok.injEq] at hb
        subst hb
        have : stack.length ≤ i.val := by
          have := usize_not_lt hge; simpa [alloc.vec.Vec.len_val, hl] using this
        exact ⟨hl, fun k hk => hfill k (by omega)⟩)
    _ _ ⟨by simp, rfl, fun k hk => by simp at hk⟩ h

/-! ## The equations -/

instance : Inhabited isa.Insn :=
  ⟨{ opcode := 0#u8, dst := 0#u8, src := 0#u8, offset := 0#i16, imm := 0#i32 }⟩

/-- The successors one `function_successors` result names. -/
def succsOf (c a b : Usize) : List Nat :=
  if 2 ≤ c.val then [a.val, b.val] else if 1 ≤ c.val then [a.val] else []

/-- Slot `p`'s successors were computed (for every `Usize` naming it). -/
def Ran (insns : Slice isa.Insn) (slot_func func_start func_end : Slice U32) (p : Nat) : Prop :=
  ∀ (pU s e : Usize), pU.val = p → s.val = fsN slot_func func_start p → e.val = feN slot_func func_end p →
    ∃ c a b, fixpoint.function_successors insns pU s e = ok (c, a, b)

/-- Slot `p`'s live-in equation holds in `live`. -/
def Holds (insns : Slice isa.Insn) (slot_func func_start func_end callee : Slice U32) (live : List U16)
    (p : Nat) : Prop :=
  ∀ (pU s e c a b : Usize), pU.val = p → s.val = fsN slot_func func_start p →
    e.val = feN slot_func func_end p → fixpoint.function_successors insns pU s e = ok (c, a, b) →
    ∀ u d, region.uses_and_defs insns.val[p]! (summary callee func_start live p) = ok (u, d) →
      (∀ r, u.val.testBit r → (live[p]!).val.testBit r) ∧
      (∀ q, q ∈ succsOf c a b → ∀ r, (live[q]!).val.testBit r → ¬ d.val.testBit r →
        (live[p]!).val.testBit r)

/-- The main loop's invariant: the stack is well formed and every slot that
is not queued satisfies its equation. -/
structure SolveInv (insns : Slice isa.Insn) (slot_func func_start func_end callee : Slice U32)
    (live : List U16) (queued : List Bool) (stack : List U32) (sp : Nat) : Prop where
  stack : StackInv insns.length queued stack sp
  llen : live.length = insns.length
  quiet : ∀ p, p < insns.length → queued[p]! = false →
    Ran insns slot_func func_start func_end p ∧ Holds insns slot_func func_start func_end callee live p

/-- Popping the top of the stack. -/
theorem StackInv.pop {n : Nat} {queued : List Bool} {stack : List U32} {sp : Nat}
    (h : StackInv n queued stack sp) (hsp : 0 < sp) :
    StackInv n (queued.set (stack[sp - 1]!).val false) stack (sp - 1) := by
  have htop := h.bounded (sp - 1) (by omega)
  have hle := h.sp_le
  refine ⟨by simp [h.qlen], h.slen, by omega, fun x hx => ?_, fun i j hi hj => h.nodup i j (by omega) (by omega),
    fun i hi => h.bounded i (by omega)⟩
  by_cases hxp : x = (stack[sp - 1]!).val
  · subst hxp
    rw [getBang_set_self (by rw [h.qlen]; exact htop)]
    simp only [Bool.false_eq_true, false_iff, not_exists, not_and]
    intro i hi heq
    have := h.nodup i (sp - 1) (by omega) (by omega) heq
    omega
  · rw [getBang_set_ne hxp, h.mem x hx]
    constructor
    · rintro ⟨i, hi, hiv⟩
      refine ⟨i, ?_, hiv⟩
      by_cases hi' : i = sp - 1
      · subst hi'; exact absurd hiv.symm hxp
      · omega
    · rintro ⟨i, hi, hiv⟩
      exact ⟨i, by omega, hiv⟩

/-! ## One step of the worklist -/

/-- Bits of a U16 above 15 are clear, so a claim about bit `r` of one only
matters for `r < 16`. -/
theorem u16_bit_cases (d : U16) (r : Nat) : r < 16 ∨ d.val.testBit r = false := by
  by_cases h : r < 16
  · exact Or.inl h
  · exact Or.inr (u16_testBit_ge d r (by omega))

theorem solve_step {insns : Slice isa.Insn} {slot_func func_start func_end callee : Slice U32}
    (hS : Shape insns slot_func func_start func_end callee)
    {pred_head pred_next caller_head caller_next : alloc.vec.Vec U32}
    (hph : pred_head.length = insns.length)
    (hpred : ∀ p, p < insns.length → PredFact insns slot_func func_start func_end pred_head.val pred_next.val p)
    (hpb : ListsBelow pred_head.val pred_next.val (2 * insns.length))
    (hcall : ∀ p, p < insns.length → CallFact callee caller_head.val caller_next.val p)
    (hcb : ListsBelow caller_head.val caller_next.val insns.length)
    (hchl : caller_head.length = func_start.length)
    {live : alloc.vec.Vec U16} {queued : alloc.vec.Vec Bool} {stack : alloc.vec.Vec U32} {sp : Usize}
    (hI : SolveInv insns slot_func func_start func_end callee live.val queued.val stack.val sp.val)
    {res : ControlFlow (alloc.vec.Vec U16 × alloc.vec.Vec Bool × alloc.vec.Vec U32 × Usize) (alloc.vec.Vec U16)}
    (hb : liveness.solve_loop.body insns slot_func func_start func_end callee pred_head pred_next
      caller_head caller_next live queued stack sp = ok res) :
    match res with
    | .cont st => SolveInv insns slot_func func_start func_end callee st.1.val st.2.1.val st.2.2.1.val st.2.2.2.val
    | .done live' => live'.length = insns.length ∧ ∀ p, p < insns.length →
        Ran insns slot_func func_start func_end p ∧ Holds insns slot_func func_start func_end callee live'.val p := by
  have hnlt := hS.n_lt
  have hsl : slot_func.val.length = insns.length := by
    have := hS.slot_func_len; simpa [Slice.length] using this
  have hcl : callee.val.length = insns.length := by
    have := hS.callee_len; simpa [Slice.length] using this
  have hfelen : func_end.val.length = func_start.val.length := by
    have := hS.func_end_len; simpa [Slice.length] using this
  have hll : live.val.length = insns.length := hI.llen
  have hphl : pred_head.val.length = insns.length := by simpa [alloc.vec.Vec.length] using hph
  unfold liveness.solve_loop.body at hb
  split at hb
  · rename_i hpos
    have hpos' : 0 < sp.val := by
      have := usize_gt hpos; simpa using this
    obtain_bind ⟨sp1, hsp1, hb⟩ := hb
    have hsp1v := usize_sub_eq_ok hsp1
    simp at hsp1v
    obtain_bind ⟨i, hi, hb⟩ := hb
    obtain_bind ⟨p, hp, hb⟩ := hb
    obtain_bind ⟨⟨_, backq⟩, hbq, hb⟩ := hb
    obtain_bind ⟨i1, hi1, hb⟩ := hb
    obtain_bind ⟨f, hf, hb⟩ := hb
    obtain_bind ⟨i2, hi2, hb⟩ := hb
    obtain_bind ⟨start, hstart, hb⟩ := hb
    obtain_bind ⟨i3, hi3, hb⟩ := hb
    obtain_bind ⟨i4, hi4, hb⟩ := hb
    obtain_bind ⟨⟨count, first, second⟩, hsucc, hb⟩ := hb
    obtain_bind ⟨⟨queued1, live_out⟩, hlo, hb⟩ := hb
    obtain_bind ⟨live_out1, hlo1, hb⟩ := hb
    obtain_bind ⟨i5, hi5, hb⟩ := hb
    obtain_bind ⟨summ, hsumm, hb⟩ := hb
    obtain_bind ⟨i6, hi6, hb⟩ := hb
    obtain_bind ⟨⟨uses, defs⟩, hud, hb⟩ := hb
    obtain_bind ⟨i7, hi7, hb⟩ := hb
    obtain_bind ⟨i8, hi8, hb⟩ := hb
    obtain_bind ⟨i9, hi9, hb⟩ := hb
    obtain_bind ⟨i10, hi10, hb⟩ := hb
    obtain_bind ⟨next, hnext, hb⟩ := hb
    obtain rfl : i8 = i7 ||| uses := lift_eq_ok hi8
    obtain rfl : i9 = ~~~ defs := lift_eq_ok hi9
    obtain rfl : i10 = live_out1 &&& ~~~ defs := lift_eq_ok hi10
    obtain rfl : next = (i7 ||| uses) ||| (live_out1 &&& ~~~ defs) := lift_eq_ok hnext
    -- The popped slot, its function and its bounds, as opaque scalars.
    obtain ⟨hil, rfl⟩ := vec_index_eq_ok hi
    rw [lift_eq_ok hp] at hbq hi1 hsucc hi5 hi6 hi7 hb
    have hil' : sp1.val < stack.val.length := by simpa [alloc.vec.Vec.length] using hil
    have hpv0 : (UScalar.cast .Usize stack.val[sp1.val]).val = (stack.val[sp1.val]!).val := by
      rw [u32_cast_usize_val, getBang_eq hil']
    generalize hpU : UScalar.cast .Usize stack.val[sp1.val] = pU at hbq hi1 hsucc hi5 hi6 hi7 hb hpv0
    generalize hpN : (stack.val[sp1.val]!).val = pN at hpv0
    have hpn : pN < insns.length := by
      rw [← hpN]; exact hI.stack.bounded sp1.val (by omega)
    obtain ⟨_, _, rfl⟩ := vec_index_mut_eq_ok hbq
    obtain ⟨_, rfl⟩ := slice_index_usize_eq_ok hi1
    rw [lift_eq_ok hf] at hi2 hi3 hb
    have hfv0 : (UScalar.cast .Usize slot_func.val[pU.val]).val = (slot_func.val[pU.val]).val :=
      u32_cast_usize_val _
    generalize hfU : UScalar.cast .Usize slot_func.val[pU.val] = fU at hi2 hi3 hb hfv0
    obtain ⟨hflt, rfl⟩ := slice_index_usize_eq_ok hi2
    obtain ⟨_, rfl⟩ := slice_index_usize_eq_ok hi3
    rw [lift_eq_ok hstart] at hsucc hb
    rw [lift_eq_ok hi4] at hsucc
    have hsv0 : (UScalar.cast .Usize func_start.val[fU.val]).val = (func_start.val[fU.val]).val :=
      u32_cast_usize_val _
    have hev0 : (UScalar.cast .Usize func_end.val[fU.val]).val = (func_end.val[fU.val]).val :=
      u32_cast_usize_val _
    generalize hsU : UScalar.cast .Usize func_start.val[fU.val] = startU at hsucc hb hsv0
    generalize heU : UScalar.cast .Usize func_end.val[fU.val] = endU at hsucc hev0
    have hflt' : fU.val < func_start.val.length := by simpa [Slice.length] using hflt
    have hfn : fU.val < func_start.length := hflt
    have e1 : slot_func.val.getD pN 0#u32 = slot_func.val[pU.val] := by
      rw [← hpv0, List.getD_eq_getElem _ _ (by rw [hsl, hpv0]; exact hpn)]
    have hsv : startU.val = fsN slot_func func_start pN := by
      rw [fsN, sfun, e1, ← hfv0, List.getD_eq_getElem _ _ hflt', hsv0]
    have hev : endU.val = feN slot_func func_end pN := by
      rw [feN, sfun, e1, ← hfv0, List.getD_eq_getElem _ _ (by rw [hfelen]; exact hflt'), hev0]
    have hstartv : startU.val = (func_start.val[fU.val]!).val := by
      rw [hsv0, getBang_eq hflt']
    -- Any representative of the slot and its bounds gives the same successors.
    have hran : Ran insns slot_func func_start func_end pN := by
      intro pU' s' e' hpU' hs' he'
      have h1 : pU' = pU := by rw [UScalar.eq_equiv, hpU', hpv0]
      have h2 : s' = startU := by rw [UScalar.eq_equiv, hs', hsv]
      have h3 : e' = endU := by rw [UScalar.eq_equiv, he', hev]
      rw [h1, h2, h3]
      exact ⟨_, _, _, hsucc⟩
    have hsame : ∀ (pU' s' e' c a b : Usize), pU'.val = pN → s'.val = fsN slot_func func_start pN →
        e'.val = feN slot_func func_end pN → fixpoint.function_successors insns pU' s' e' = ok (c, a, b) →
        c = count ∧ a = first ∧ b = second := by
      intro pU' s' e' c a b hpU' hs' he' hsucc'
      have h1 : pU' = pU := by rw [UScalar.eq_equiv, hpU', hpv0]
      have h2 : s' = startU := by rw [UScalar.eq_equiv, hs', hsv]
      have h3 : e' = endU := by rw [UScalar.eq_equiv, he', hev]
      rw [h1, h2, h3, hsucc] at hsucc'
      simp only [ok.injEq, Prod.mk.injEq] at hsucc'
      exact ⟨hsucc'.1.symm, hsucc'.2.1.symm, hsucc'.2.2.symm⟩
    -- The dequeue and the live-out.
    have hq1 : queued1.val = queued.val.set pN false ∧
        ∀ q, q ∈ succsOf count first second → ∀ r, (live.val[q]!).val.testBit r → live_out1.val.testBit r := by
      have hset : (alloc.vec.Vec.set queued pU false).val =
          queued.val.set pN false := by
        simp [alloc.vec.Vec.set_val_eq, hpv0]
      by_cases hc1 : count ≥ 1#usize
      · rw [if_pos hc1] at hlo
        have hc1' : 1 ≤ count.val := by simpa using usize_ge hc1
        obtain_bind ⟨j5, hj5, hlo⟩ := hlo
        obtain_bind ⟨lo1, hlo1', hlo⟩ := hlo
        simp only [ok.injEq, Prod.mk.injEq] at hlo
        obtain ⟨rfl, rfl⟩ := hlo
        obtain rfl : lo1 = 0#u16 ||| j5 := lift_eq_ok hlo1'
        obtain ⟨hfl, rfl⟩ := vec_index_eq_ok hj5
        have hfl' : first.val < live.val.length := by simpa [alloc.vec.Vec.length] using hfl
        refine ⟨hset, fun q hq r hr => ?_⟩
        by_cases hc2 : count ≥ 2#usize
        · rw [if_pos hc2] at hlo1
          have hc2' : 2 ≤ count.val := by simpa using usize_ge hc2
          obtain_bind ⟨j6, hj6, hlo1⟩ := hlo1
          simp only [ok.injEq] at hlo1
          subst hlo1
          obtain ⟨hsl2, rfl⟩ := vec_index_eq_ok hj6
          have hsl2' : second.val < live.val.length := by simpa [alloc.vec.Vec.length] using hsl2
          simp only [succsOf, if_pos hc2', List.mem_cons, List.not_mem_nil, or_false] at hq
          rw [u16_or_testBit, u16_or_testBit]
          rcases hq with rfl | rfl
          · rw [getBang_eq hfl'] at hr; simp [hr]
          · rw [getBang_eq hsl2'] at hr; simp [hr]
        · rw [if_neg hc2] at hlo1
          simp only [ok.injEq] at hlo1
          subst hlo1
          have hc2' : ¬ 2 ≤ count.val := fun h2 => hc2 (by
            simp only [ge_iff_le, UScalar.le_equiv]; simpa using h2)
          simp only [succsOf, if_neg hc2', if_pos hc1', List.mem_singleton] at hq
          subst hq
          rw [u16_or_testBit, getBang_eq hfl'] at *
          simp [hr]
      · rw [if_neg hc1] at hlo
        simp only [ok.injEq, Prod.mk.injEq] at hlo
        obtain ⟨rfl, rfl⟩ := hlo
        have hc1' : ¬ 1 ≤ count.val := fun h1 => hc1 (by
          simp only [ge_iff_le, UScalar.le_equiv]; simpa using h1)
        have hc2' : ¬ 2 ≤ count.val := by omega
        rw [if_neg (by
          intro h2; apply hc1; simp only [ge_iff_le, UScalar.le_equiv]
          have := usize_ge h2; simp at this; simp; omega)] at hlo1
        simp only [ok.injEq] at hlo1
        subst hlo1
        refine ⟨hset, fun q hq => ?_⟩
        simp [succsOf, hc1', hc2'] at hq
    obtain ⟨hq1v, hlo_bits⟩ := hq1
    -- The summary, the instruction, the old value.
    obtain ⟨hi5l, rfl⟩ := slice_index_usize_eq_ok hi5
    have hi5c : callee.val[pU.val] = callee.val[pN]! := by
      rw [getBang_eq (by rw [hcl]; exact hpn)]
      simp only [hpv0]
    have hsummv : summ = summary callee func_start live.val pN :=
      callee_summary_spec hi5c (vec_deref_val live) hsumm
    obtain ⟨hi6l, rfl⟩ := slice_index_usize_eq_ok hi6
    have hi6c : insns.val[pU.val] = insns.val[pN]! := by
      rw [getBang_eq (by simpa [Slice.length] using hpn)]
      simp only [hpv0]
    obtain ⟨hi7l, rfl⟩ := vec_index_eq_ok hi7
    have hi7c : live.val[pU.val] = live.val[pN]! := by
      rw [getBang_eq (by rw [hll]; exact hpn)]
      simp only [hpv0]
    rw [hi6c, hsummv] at hud
    -- Bits of `next`.
    have hnext_bit : ∀ r, ((live.val[pU.val] ||| uses) |||
        (live_out1 &&& ~~~ defs)).val.testBit r =
        ((live.val[pN]!).val.testBit r || uses.val.testBit r ||
          (live_out1.val.testBit r && !defs.val.testBit r)) := by
      intro r
      by_cases hr : r < 16
      · rw [u16_or_testBit, u16_or_testBit, u16_and_testBit, u16_not_testBit _ _ hr, hi7c]
      · have h16 : 16 ≤ r := by omega
        simp only [u16_testBit_ge _ _ h16]
        simp
    -- The stack after the pop.
    have hpop : StackInv insns.length queued1.val stack.val sp1.val := by
      rw [hq1v, ← hpN]
      have := hI.stack.pop hpos'
      rwa [show sp.val - 1 = sp1.val by omega] at this
    have hlive_set : ∀ (v : U16), (alloc.vec.Vec.set live pU v).val = live.val.set pN v := by
      intro v; simp [alloc.vec.Vec.set_val_eq, hpv0]
    have hnextV_len : ∀ v : U16, (live.val.set pN v).length = insns.length := by
      intro v; simp [hll]
    -- The successor list of the popped slot is what the body computed with.
    have hphc : pred_head.val[pU.val]? = some pred_head.val[pN]! := by
      rw [hpv0, List.getElem?_eq_getElem (by rw [hphl]; exact hpn), getBang_eq (by rw [hphl]; exact hpn)]
    -- What one whole step establishes, given where the wakes left the queue.
    have final : ∀ (v : U16) (queuedF : alloc.vec.Vec Bool) (stackF : alloc.vec.Vec U32) (spF : Usize),
        (∀ r, uses.val.testBit r → v.val.testBit r) →
        (∀ q, q ∈ succsOf count first second → ∀ r, (live.val[q]!).val.testBit r → ¬ defs.val.testBit r →
          v.val.testBit r) →
        StackInv insns.length queuedF.val stackF.val spF.val →
        (∀ x, x < insns.length → queued1.val[x]! = true → queuedF.val[x]! = true) →
        (v = live.val[pN]! ∨
          ((∀ y, ListMem pred_next.val pred_head.val[pN]! y → queuedF.val[y.val / 2]! = true) ∧
           (pU = startU → ∀ y, ListMem caller_next.val caller_head.val[fU.val]! y →
             queuedF.val[y.val]! = true))) →
        SolveInv insns slot_func func_start func_end callee (live.val.set pN v) queuedF.val stackF.val spF.val := by
      intro v queuedF stackF spF hvu hvs hIF hmonoF hcov
      refine ⟨hIF, hnextV_len v, fun x hx hqx => ?_⟩
      have hqx1 : queued1.val[x]! = false := by
        cases h : queued1.val[x]!
        · rfl
        · exact absurd (hmonoF x hx h) (by rw [hqx]; simp)
      by_cases hxp : x = pN
      · subst hxp
        refine ⟨hran, ?_⟩
        intro pU' s' e' c a b hp' hs' he' hsucc' u d hud'
        obtain ⟨rfl, rfl, rfl⟩ := hsame pU' s' e' c a b hp' hs' he' hsucc'
        have hl1p : (live.val.set x v)[x]! = v := getBang_set_self (by rw [hll]; exact hpn)
        obtain ⟨rfl, hu⟩ := uses_and_defs_summary hud hud'
        have hsum_sub : ∀ r, (summary callee func_start (live.val.set x v) x).val.testBit r →
            (summary callee func_start live.val x).val.testBit r ∨ v.val.testBit r := by
          intro r hr
          unfold summary at hr ⊢
          split_ifs at hr ⊢ with h1 h2
          · exact Or.inl hr
          · exact Or.inl hr
          · by_cases hidx : (func_start.val[(callee.val[x]!).val]!).val = x
            · rw [hidx, hl1p] at hr; exact Or.inr hr
            · rw [getBang_set_ne hidx] at hr; exact Or.inl hr
        refine ⟨fun r hr => ?_, fun q hq r hr hd => ?_⟩
        · rw [hl1p]
          rcases hu with rfl | ⟨huse, rfl⟩
          · exact hvu r hr
          · rcases hsum_sub r hr with h | h
            · rw [← huse] at h; exact hvu r h
            · exact h
        · rw [hl1p]
          by_cases hqp : q = x
          · subst hqp; rw [hl1p] at hr; exact hr
          · rw [getBang_set_ne hqp] at hr
            exact hvs q hq r hr hd
      · have hqx0 : queued.val[x]! = false := by rw [hq1v, getBang_set_ne hxp] at hqx1; exact hqx1
        obtain ⟨hranx, hholdx⟩ := hI.quiet x hx hqx0
        refine ⟨hranx, ?_⟩
        rcases hcov with hv | ⟨hcovP, hcovC⟩
        · -- Nothing changed: the table is the old one.
          have hset_id : live.val.set pN v = live.val := by
            rw [hv, getBang_eq (by rw [hll]; exact hpn)]
            exact List.set_getElem_self (by rw [hll]; exact hpn)
          rw [hset_id]
          exact hholdx
        intro pU' s' e' c a b hp' hs' he' hsucc' u d hud'
        obtain ⟨hpf1, hpf2⟩ := hpred x hx pU' s' e' c a b hp' hs' he' hsucc'
        have hqF : queuedF.val[x]! ≠ true := by rw [hqx]; simp
        have hnot_succ : ∀ q, q ∈ succsOf c a b → q ≠ pN := by
          intro q hq hqp
          subst hqp
          simp only [succsOf] at hq
          split_ifs at hq with h2 h1
          · simp only [List.mem_cons, List.not_mem_nil, or_false] at hq
            rcases hq with hq | hq
            · obtain ⟨_, y, hy, hyv⟩ := hpf1 (by omega)
              rw [← hq] at hy
              have := hcovP y hy
              rw [hyv, show 2 * x / 2 = x by omega] at this
              exact hqF this
            · obtain ⟨_, y, hy, hyv⟩ := hpf2 h2
              rw [← hq] at hy
              have := hcovP y hy
              rw [hyv, show (2 * x + 1) / 2 = x by omega] at this
              exact hqF this
          · simp only [List.mem_singleton] at hq
            obtain ⟨_, y, hy, hyv⟩ := hpf1 h1
            rw [← hq] at hy
            have := hcovP y hy
            rw [hyv, show 2 * x / 2 = x by omega] at this
            exact hqF this
          · simp at hq
        have hsum : summary callee func_start (live.val.set pN v) x = summary callee func_start live.val x := by
          unfold summary
          split_ifs with h1 h2
          · rfl
          · rfl
          · have hidx : (func_start.val[(callee.val[x]!).val]!).val ≠ pN := by
              intro hidx
              obtain ⟨hflt2, y, hy, hyv⟩ := hcall x hx _ rfl h1 h2
              have hfnf : (callee.val[x]!).val < func_start.length := by
                have := hchl; simp only [alloc.vec.Vec.length, Slice.length] at this ⊢; omega
              have hf' := hS.entry_func _ hfnf
              rw [hidx] at hf'
              have hfeq : fU.val = (callee.val[x]!).val := by
                rw [hfv0, ← hf', getBang_eq (by rw [hsl]; exact hpn)]
                simp only [hpv0]
              have hps : pU = startU := by
                rw [UScalar.eq_equiv, hstartv, hfeq, hidx, hpv0]
              have hhead : caller_head.val[fU.val]! = caller_head.val[(callee.val[x]!).val]! := by rw [hfeq]
              have := hcovC hps y (by rw [hhead]; exact hy)
              rw [hyv] at this
              exact hqF this
            rw [getBang_set_ne hidx]
        rw [hsum] at hud'
        obtain ⟨hb1, hb2⟩ := hholdx pU' s' e' c a b hp' hs' he' hsucc' u d hud'
        have hlx : (live.val.set pN v)[x]! = live.val[x]! := getBang_set_ne hxp
        refine ⟨fun r hr => by rw [hlx]; exact hb1 r hr, fun q hq r hr hd => ?_⟩
        rw [getBang_set_ne (hnot_succ q hq)] at hr
        rw [hlx]
        exact hb2 q hq r hr hd
    -- The two outcomes of the comparison.
    by_cases hne : (((live.val[pU.val] ||| uses) ||| (live_out1 &&& ~~~ defs)) != live.val[pU.val]) = true
    · rw [if_pos hne] at hb
      obtain_bind ⟨⟨_, backl⟩, hbl, hb⟩ := hb
      dsimp only at hb
      obtain_bind ⟨i11, hi11, hb⟩ := hb
      obtain_bind ⟨⟨sp2, queued2, stack1⟩, hw1, hb⟩ := hb
      obtain ⟨_, _, rfl⟩ := vec_index_mut_eq_ok hbl
      obtain ⟨hphl2, rfl⟩ := vec_index_eq_ok hi11
      have hphc' : pred_head.val[pU.val] = pred_head.val[pN]! := by
        rw [getBang_eq (by rw [hphl]; exact hpn)]
        simp only [hpv0]
      rw [hphc'] at hw1
      have hmem1 : ∀ y, ListMem (alloc.vec.Vec.deref pred_next).val pred_head.val[pN]! y → y.val / (2#u32).val < insns.length := by
        intro y hy
        rw [vec_deref_val] at hy
        have := hpb pN (by rw [hphl]; exact hpn) y hy
        have h2 : (2#u32).val = 2 := by simp
        rw [h2]; omega
      obtain ⟨hI2, hcov1, hmono1⟩ := wake_ok hnlt (by simp) hpop hmem1 hw1
      rw [vec_deref_val] at hcov1
      have h2v : (2#u32).val = 2 := by simp
      rw [h2v] at hcov1
      -- Bits the new value carries.
      have hvu : ∀ r, uses.val.testBit r →
          ((live.val[pU.val] ||| uses) ||| (live_out1 &&& ~~~ defs)).val.testBit r := by
        intro r hr; rw [hnext_bit r, hr]; simp
      have hvs : ∀ q, q ∈ succsOf count first second → ∀ r, (live.val[q]!).val.testBit r →
          ¬ defs.val.testBit r → ((live.val[pU.val] ||| uses) ||| (live_out1 &&& ~~~ defs)).val.testBit r := by
        intro q hq r hr hd
        have hd' : defs.val.testBit r = false := by simpa using hd
        rw [hnext_bit r, hlo_bits q hq r hr, hd']; simp
      split at hb
      · rename_i hps
        try dsimp only at hb
        obtain_bind ⟨i12, hi12, hb⟩ := hb
        obtain_bind ⟨⟨sp3, queued3, stack2⟩, hw2, hb⟩ := hb
        replace hb := ok.inj hb
        subst hb
        obtain ⟨hchl', rfl⟩ := vec_index_eq_ok hi12
        have hchc : caller_head.val[fU.val] = caller_head.val[fU.val]! := by
          rw [getBang_eq (by simpa [alloc.vec.Vec.length] using hchl')]
        rw [hchc] at hw2
        have hmem2 : ∀ y, ListMem (alloc.vec.Vec.deref caller_next).val caller_head.val[fU.val]! y →
            y.val / (1#u32).val < insns.length := by
          intro y hy
          rw [vec_deref_val] at hy
          have := hcb fU.val (by simpa [alloc.vec.Vec.length] using hchl') y hy
          have h1 : (1#u32).val = 1 := by simp
          rw [h1, Nat.div_one]; exact this
        obtain ⟨hI3, hcov2, hmono2⟩ := wake_ok hnlt (by simp) hI2 hmem2 hw2
        rw [vec_deref_val] at hcov2
        have h1v : (1#u32).val = 1 := by simp
        rw [h1v] at hcov2
        simp only [Nat.div_one] at hcov2
        show SolveInv insns slot_func func_start func_end callee (alloc.vec.Vec.set live pU _).val queued3.val stack2.val sp3.val
        rw [hlive_set]
        exact final _ queued3 stack2 sp3 hvu hvs hI3
          (fun x hx hq => hmono2 x hx (hmono1 x hx hq))
          (Or.inr ⟨fun y hy => hmono2 _ (by have := hpb pN (by rw [hphl]; exact hpn) y hy; omega) (hcov1 y hy),
            fun _ y hy => hcov2 y hy⟩)
      · rename_i hps
        replace hb := ok.inj hb
        subst hb
        show SolveInv insns slot_func func_start func_end callee (alloc.vec.Vec.set live pU _).val queued2.val stack1.val sp2.val
        rw [hlive_set]
        exact final _ queued2 stack1 sp2 hvu hvs hI2 hmono1 (Or.inr ⟨hcov1, fun hps' => absurd hps' hps⟩)
    · rw [if_neg hne] at hb
      simp only [ok.injEq] at hb
      subst hb
      have heq : ((live.val[pU.val] ||| uses) ||| (live_out1 &&& ~~~ defs)) = live.val[pU.val] := by
        simpa [bne_iff_ne, UScalar.eq_equiv] using hne
      show SolveInv insns slot_func func_start func_end callee live.val queued1.val stack.val sp1.val
      have hset_id : live.val.set pN live.val[pN]! = live.val := by
        rw [getBang_eq (by rw [hll]; exact hpn)]
        exact List.set_getElem_self (by rw [hll]; exact hpn)
      rw [← hset_id]
      refine final _ queued1 stack sp1 ?_ ?_ hpop (fun x _ hq => hq) (Or.inl rfl)
      · intro r hr
        have := hnext_bit r
        rw [heq, hi7c, hr] at this
        simpa using this
      · intro q hq r hr hd
        have hd' : defs.val.testBit r = false := by simpa using hd
        have := hnext_bit r
        rw [heq, hi7c, hlo_bits q hq r hr, hd'] at this
        simpa using this
  · rename_i hpos
    simp only [ok.injEq] at hb
    subst hb
    have hsp0 : sp.val = 0 := by
      have := usize_not_gt hpos; simpa using this
    refine ⟨hI.llen, fun p hp => hI.quiet p hp ?_⟩
    have := hI.stack.mem p hp
    rw [hsp0] at this
    cases hq : queued.val[p]!
    · rfl
    · exfalso
      obtain ⟨i, hi, _⟩ := this.mp hq
      omega

/-! ## The whole solver -/

theorem solve_loop_ok {insns : Slice isa.Insn} {slot_func func_start func_end callee : Slice U32}
    (hS : Shape insns slot_func func_start func_end callee)
    {pred_head pred_next caller_head caller_next : alloc.vec.Vec U32}
    (hph : pred_head.length = insns.length)
    (hpred : ∀ p, p < insns.length → PredFact insns slot_func func_start func_end pred_head.val pred_next.val p)
    (hpb : ListsBelow pred_head.val pred_next.val (2 * insns.length))
    (hcall : ∀ p, p < insns.length → CallFact callee caller_head.val caller_next.val p)
    (hcb : ListsBelow caller_head.val caller_next.val insns.length)
    (hchl : caller_head.length = func_start.length)
    {live : alloc.vec.Vec U16} {queued : alloc.vec.Vec Bool} {stack : alloc.vec.Vec U32} {sp : Usize}
    (hI : SolveInv insns slot_func func_start func_end callee live.val queued.val stack.val sp.val)
    {live' : alloc.vec.Vec U16}
    (h : liveness.solve_loop insns slot_func func_start func_end callee pred_head pred_next
      caller_head caller_next live queued stack sp = ok live') :
    live'.length = insns.length ∧ ∀ p, p < insns.length →
      Ran insns slot_func func_start func_end p ∧ Holds insns slot_func func_start func_end callee live'.val p := by
  unfold liveness.solve_loop at h
  exact loop_ok_induction _
    (fun st : alloc.vec.Vec U16 × alloc.vec.Vec Bool × alloc.vec.Vec U32 × Usize =>
      SolveInv insns slot_func func_start func_end callee st.1.val st.2.1.val st.2.2.1.val st.2.2.2.val)
    (fun y : alloc.vec.Vec U16 => y.length = insns.length ∧ ∀ p, p < insns.length →
      Ran insns slot_func func_start func_end p ∧ Holds insns slot_func func_start func_end callee y.val p)
    (by
      rintro ⟨lv, qd, st, s⟩ hI' res hb
      change liveness.solve_loop.body insns slot_func func_start func_end callee pred_head pred_next
        caller_head caller_next lv qd st s = ok res at hb
      cases res <;> exact solve_step hS hph hpred hpb hcall hcb hchl hI' hb)
    _ _ hI h

theorem replicate_getBang {α : Type} [Inhabited α] {n i : Nat} {x : α} (h : i < n) :
    (List.replicate n x)[i]! = x := by
  rw [getBang_eq (by simpa using h), List.getElem_replicate]

/-- The table `solve` returns satisfies every slot's equation. -/
theorem solve_ok {insns : Slice isa.Insn} {slot_func func_start func_end callee : Slice U32}
    (hS : Shape insns slot_func func_start func_end callee) {live : alloc.vec.Vec U16}
    (h : liveness.solve insns slot_func func_start func_end callee = ok live) :
    live.length = insns.length ∧ ∀ p, p < insns.length →
      Ran insns slot_func func_start func_end p ∧ Holds insns slot_func func_start func_end callee live.val p := by
  have hnlt := hS.n_lt
  unfold liveness.solve at h
  dsimp only at h
  obtain_bind ⟨ph, hph0, h⟩ := h
  obtain_bind ⟨i, hi, h⟩ := h
  obtain_bind ⟨pn, hpn0, h⟩ := h
  obtain_bind ⟨⟨ph1, pn1⟩, hbp, h⟩ := h
  obtain_bind ⟨ch, hch0, h⟩ := h
  obtain_bind ⟨⟨ch1, cn⟩, hbc, h⟩ := h
  obtain_bind ⟨lv, hlv, h⟩ := h
  obtain_bind ⟨qd, hqd, h⟩ := h
  obtain_bind ⟨st, hst, h⟩ := h
  obtain_bind ⟨st1, hseed, h⟩ := h
  have hn : (Slice.len insns).val = insns.length := slice_len_val insns
  have hnf : (Slice.len func_start).val = func_start.length := slice_len_val func_start
  have hphv := from_elem_eq_ok rfl hph0
  have hiv := usize_mul_eq_ok hi
  have hpnv := from_elem_eq_ok rfl hpn0
  have hchv := from_elem_eq_ok rfl hch0
  have hlvv := from_elem_eq_ok rfl hlv
  have hqdv := from_elem_eq_ok rfl hqd
  have hstv := from_elem_eq_ok rfl hst
  have hphl : ph.length = insns.length := by simp [alloc.vec.Vec.length, hphv, hn]
  have hpnl : pn.length = 2 * insns.length := by simp [alloc.vec.Vec.length, hpnv, hiv, hn]
  have hchl : ch.length = func_start.length := by simp [alloc.vec.Vec.length, hchv, hnf]
  have hph0' : ∀ q, q < insns.length → ph.val[q]! = liveness.NO_EDGE := by
    intro q hq; rw [hphv, replicate_getBang (by rw [hn]; exact hq)]
  have hch0' : ∀ q, q < func_start.length → ch.val[q]! = liveness.NO_EDGE := by
    intro q hq; rw [hchv, replicate_getBang (by rw [hnf]; exact hq)]
  obtain ⟨hph1, _, hpred, hpb⟩ := build_preds_ok hS hphl hpnl hph0' hbp
  -- The extraction reuses the untouched all-`NO_EDGE` vector of length `n`
  -- as the call-site `next` table.
  obtain ⟨hch1, _, hcall, hcb⟩ := build_callers_ok hS hchl hphl hch0' hbc
  have hstl : st.length = insns.length := by simp [alloc.vec.Vec.length, hstv, hn]
  obtain ⟨hst1l, hfill⟩ := seed_ok (by rw [hstl]; omega) hseed
  rw [hstl] at hst1l hfill
  have hlvl : lv.val.length = insns.length := by simp [hlvv, hn]
  have hqdl : qd.val.length = insns.length := by simp [hqdv, hn]
  have hst1l' : st1.val.length = insns.length := by simpa [alloc.vec.Vec.length] using hst1l
  have hqd_true : ∀ x, x < insns.length → qd.val[x]! = true := by
    intro x hx; rw [hqdv, replicate_getBang (by rw [hn]; exact hx)]
  refine solve_loop_ok hS hph1 hpred hpb hcall hcb hch1 ?_ h
  -- Initially every slot is queued, in ascending order, and nothing is quiet.
  refine ⟨⟨hqdl, hst1l', by rw [hn], fun x hx => ?_, fun i j hi hj hij => ?_, fun i hi => ?_⟩, hlvl,
    fun p hp hq => ?_⟩
  · rw [hn]; exact ⟨fun _ => ⟨x, hx, hfill x hx⟩, fun _ => hqd_true x hx⟩
  · rw [hn] at hi hj; rw [hfill i hi, hfill j hj] at hij; exact hij
  · rw [hn] at hi; rw [hfill i hi]; exact hi
  · rw [hqd_true p hp] at hq; exact absurd hq (by simp)

/-! ## The equations, as a `LiveSolution` -/

/-- `in_function` accepts exactly the targets in `[start, end)`. -/
theorem in_function_true {t : I64} {s e : Usize} (hs : s.val < 2 ^ 31) (he : e.val < 2 ^ 31)
    (h : fixpoint.in_function t s e = ok true) : (s.val : Int) ≤ t.val ∧ t.val < (e.val : Int) := by
  unfold fixpoint.in_function at h
  obtain_bind ⟨i, hi, h⟩ := h
  rw [lift_eq_ok hi] at h
  have hsv : (UScalar.hcast .I64 s).val = (s.val : Int) := by
    rw [UScalar.hcast_val_eq]
    refine Int.bmod_eq_of_le (by simp) ?_
    (try simp only [IScalarTy.numBits]); omega
  split at h
  · rename_i hge
    obtain_bind ⟨i1, hi1, h⟩ := h
    rw [lift_eq_ok hi1] at h
    have hev : (UScalar.hcast .I64 e).val = (e.val : Int) := by
      rw [UScalar.hcast_val_eq]
      refine Int.bmod_eq_of_le (by simp) ?_
      (try simp only [IScalarTy.numBits]); omega
    simp only [ok.injEq] at h
    have hlt : t < UScalar.hcast .I64 e := of_decide_eq_true h
    rw [IScalar.lt_equiv, hev] at hlt
    rw [ge_iff_le, IScalar.le_equiv, hsv] at hge
    exact ⟨hge, hlt⟩
  · simp at h

/-- The successors `function_successors` keeps lie inside `[start, end)`. -/
theorem function_successors_bounds {insns : Slice isa.Insn} {pc s e c a b : Usize}
    (hs : s.val < 2 ^ 31) (he : e.val < 2 ^ 31)
    (h : fixpoint.function_successors insns pc s e = ok (c, a, b)) :
    (1 ≤ c.val → s.val ≤ a.val ∧ a.val < e.val) ∧ (2 ≤ c.val → s.val ≤ b.val ∧ b.val < e.val) := by
  unfold fixpoint.function_successors at h
  obtain_bind ⟨insn, _, h⟩ := h
  obtain_bind ⟨⟨cnt, f1, f2⟩, _, h⟩ := h
  obtain_bind ⟨k1, hk1, h⟩ := h
  obtain_bind ⟨k2, hk2, h⟩ := h
  have hcast : ∀ (t : I64), (s.val : Int) ≤ t.val → t.val < (e.val : Int) →
      s.val ≤ (IScalar.hcast .Usize t).val ∧ (IScalar.hcast .Usize t).val < e.val := by
    intro t h1 h2
    rw [IScalar.hcast_val_eq]
    have hm : t.val % (2 : Int) ^ UScalarTy.Usize.numBits = t.val := by
      apply Int.emod_eq_of_lt (by omega)
      simp only [UScalarTy.numBits]
      rcases System.Platform.numBits_eq with hb | hb <;> rw [hb] <;> omega
    rw [hm]; omega
  have hk1' : k1 = true → (s.val : Int) ≤ f1.val ∧ f1.val < (e.val : Int) := by
    intro hk; subst hk
    split at hk1
    · exact in_function_true hs he hk1
    · simp at hk1
  have hk2' : k2 = true → (s.val : Int) ≤ f2.val ∧ f2.val < (e.val : Int) := by
    intro hk; subst hk
    split at hk2
    · exact in_function_true hs he hk2
    · simp at hk2
  split at h
  · rename_i h1
    split at h
    · rename_i h2
      obtain_bind ⟨i, hi, h⟩ := h
      obtain_bind ⟨i1, hi1, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      obtain rfl := lift_eq_ok hi
      obtain rfl := lift_eq_ok hi1
      exact ⟨fun _ => hcast f1 (hk1' h1).1 (hk1' h1).2, fun _ => hcast f2 (hk2' h2).1 (hk2' h2).2⟩
    · obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      obtain rfl := lift_eq_ok hi
      exact ⟨fun _ => hcast f1 (hk1' h1).1 (hk1' h1).2, fun h2' => by simp at h2'⟩
  · split at h
    · rename_i h2
      obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      obtain rfl := lift_eq_ok hi
      exact ⟨fun _ => hcast f2 (hk2' h2).1 (hk2' h2).2, fun h2' => by simp at h2'⟩
    · simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      exact ⟨fun h1' => by simp at h1', fun h2' => by simp at h2'⟩

theorem getD_eq_getBang {α : Type} [Inhabited α] {l : List α} {i : Nat} (d : α) (h : i < l.length) :
    l.getD i d = l[i]! := by
  rw [List.getD_eq_getElem _ _ h, getBang_eq h]

/-- The bounds of slot `p`'s function, as the solver reads them, are in range. -/
theorem bounds_lt {insns : Slice isa.Insn} {slot_func func_start func_end callee : Slice U32}
    (hS : Shape insns slot_func func_start func_end callee) {p : Nat} (hp : p < insns.length) :
    fsN slot_func func_start p < insns.length ∧ feN slot_func func_end p ≤ insns.length := by
  have hsl : slot_func.val.length = insns.length := by
    have := hS.slot_func_len; simpa [Slice.length] using this
  have hfelen : func_end.val.length = func_start.val.length := by
    have := hS.func_end_len; simpa [Slice.length] using this
  have hf : sfun slot_func p < func_start.length := by
    rw [sfun, getD_eq_getBang _ (by rw [hsl]; exact hp)]
    exact hS.slot_func_lt p hp
  have hf' : sfun slot_func p < func_start.val.length := by simpa [Slice.length] using hf
  constructor
  · rw [fsN, getD_eq_getBang _ hf']; exact hS.func_start_lt _ hf
  · rw [feN, getD_eq_getBang _ (by rw [hfelen]; exact hf')]; exact hS.func_end_le _ hf

/-- `succs p` is the successor list the solver computed for slot `p`. -/
def SuccsOf (insns : Slice isa.Insn) (slot_func func_start func_end : Slice U32)
    (succs : Nat → List Nat) (p : Nat) : Prop :=
  ∃ (pU s e c a b : Usize), pU.val = p ∧ s.val = fsN slot_func func_start p ∧
    e.val = feN slot_func func_end p ∧ fixpoint.function_successors insns pU s e = ok (c, a, b) ∧
    succs p = succsOf c a b

/-- The table `solve` returns is a `LiveSolution` over the whole program:
the hypothesis the region analysis' masking proofs take, discharged by the
code that computes the table. -/
theorem solve_live_solution {insns : Slice isa.Insn} {slot_func func_start func_end callee : Slice U32}
    (hS : Shape insns slot_func func_start func_end callee) {live : alloc.vec.Vec U16}
    (h : liveness.solve insns slot_func func_start func_end callee = ok live)
    {succs : Nat → List Nat}
    (hsucc : ∀ p, p < insns.length → SuccsOf insns slot_func func_start func_end succs p) :
    LiveSolution (fun p => insns.val[p]!) (fun p => summary callee func_start live.val p) succs
      (fun p => p < insns.length) (fun p => live.val[p]!) := by
  obtain ⟨_, hall⟩ := solve_ok hS h
  have hnlt := hS.n_lt
  refine ⟨fun p q hp hq => ?_, fun p hp => ?_⟩
  · have hp' : p < insns.length := hp
    show q < insns.length
    obtain ⟨pU, s, e, c, a, b, hpU, hs, he, hfs, hsp⟩ := hsucc p hp'
    obtain ⟨hslt, hele⟩ := bounds_lt hS hp'
    obtain ⟨h1, h2⟩ := function_successors_bounds (by omega) (by omega) hfs
    rw [hsp] at hq
    simp only [succsOf] at hq
    split_ifs at hq with hc2 hc1
    · simp only [List.mem_cons, List.not_mem_nil, or_false] at hq
      rcases hq with rfl | rfl
      · have := h1 (by omega); omega
      · have := h2 hc2; omega
    · simp only [List.mem_singleton] at hq
      subst hq; have := h1 hc1; omega
    · simp at hq
  · have hp' : p < insns.length := hp
    obtain ⟨_, hholds⟩ := hall p hp'
    obtain ⟨pU, s, e, c, a, b, hpU, hs, he, hfs, hsp⟩ := hsucc p hp'
    obtain ⟨u, d, hud⟩ := uses_and_defs_total insns.val[p]! (summary callee func_start live.val p)
    obtain ⟨h1, h2⟩ := hholds pU s e c a b hpU hs he hfs u d hud
    exact ⟨u, d, hud, h1, fun q hq => h2 q (by rwa [hsp] at hq)⟩

end async_ebpf_verified

import AsyncEbpf.X64.Contract

/-!
# The layout the runtime checks is the layout the theorem assumes

`check_safe` takes `Layout P` as a hypothesis: it says nothing about where
the mappings are, only what follows once they are where `program.rs` puts
them. `lean/README.md` lists "the entry trampolines and the descriptor"
among what is trusted, and `Layout` was the largest part of that trust.

`src/verified/x64_layout.rs` is how much of it stops being trusted. It holds
one `NativeLayout` — the thirteen numbers the descriptor and the mappings
carry — and `layout_ok`, twenty-one comparisons over them that `program.rs`
runs before it enters generated code, refusing the run when any fails. This
file is the bridge: `layout_of_check` turns `layout_ok l = ok true`, plus the
six per-activation facts about `rsp0`, `rbp0` and `fp0` that only the entry
trampoline can establish, into `Layout (paramsOf l …)` — every clause, with
nothing left over.

The per-activation facts are the ones the Rust module's comment says it does
not check: that the entry `rsp` and `rbp` sit inside the coroutine stack's
mapping with the frame scratch between them (`hrsp`, `hrbp`, `hbelow`,
`hframe160`), and that the frame register points into the guest stack's
backing (`hfpLo`, `hfpHi`). Everything else follows. In particular the ten
clauses about `frameSlots P` and `stackWindow P` mention `rbp0` and `rsp0`
and so cannot be checked from the numbers alone, but they are not assumed
either. The three that only order the two windows — `frameNoWrap`,
`stackWindowNoWrap`, `frameOffStack` — are `hbelow` and `hframe160` written
out. The other seven are `subrange_disjoint`: both windows lie inside
`[stackLo, stackHi)`, and that mapping is already checked clear of the first
page, of both guest backings and of the descriptor, so anything inside it is
clear of them too.

`derived_block` is the other half. `JitMemory::fill_derived` computes the six
bounds-check constants of one region through it and copies them into the
twelve derived slots below the frame pointer; `RoMem` reads them back as two
`DerivedBlock`s. `derived_block_spec` says the six words are the modular
differences `DerivedBlock` names — `sub_mod` is `wrapping_sub`, which is
`BitVec` subtraction — and `derivedBlock_of_slots` assembles the two
structures from the twelve loads.

Nothing here is about code. It is arithmetic on thirteen numbers, and its
only purpose is that the hypothesis of the memory-safety theorem and the test
the runtime performs are the same statement.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-! ## Plumbing

The extracted checks are `Result Bool` computations built from `>>=`, `ite`
and the two `u64` operations that can fail. These are the pieces every
inversion below is made of. -/

/-- A `bind` that succeeded ran its first half successfully. -/
theorem bind_ok {α β : Type} {x : Result α} {f : α → Result β} {y : β}
    (h : (x >>= f) = ok y) : ∃ a, x = ok a ∧ f a = ok y := by
  cases x <;> simp_all

/-- A `u64` subtraction that succeeded did not underflow. -/
theorem u64_sub_ok {x y z : U64} (h : x - y = ok z) :
    y.val ≤ x.val ∧ z.val = x.val - y.val ∧ z.bv = x.bv - y.bv := by
  have hx := UScalar.sub_equiv x y
  rw [h] at hx
  exact ⟨hx.1, by omega, hx.2.2⟩

/-- A `u64` addition that succeeded did not overflow. -/
theorem u64_add_ok {x y z : U64} (h : x + y = ok z) :
    x.val + y.val < 2 ^ 64 ∧ z.val = x.val + y.val ∧ z.bv = x.bv + y.bv := by
  have hx := UScalar.add_equiv x y
  rw [h] at hx
  exact ⟨hx.1, hx.2.1, hx.2.2⟩

/-- `<=` on `u64` is `≤` on the values; the extracted code returns it through
`decide`. -/
theorem u64_le_val {x y : U64} (h : x ≤ y) : x.val ≤ y.val := h

/-- The guard `if b then … else ok false`, which every clause of `layout_ok`
is wrapped in. -/
theorem ite_ok_true {b : Bool} {x : Result Bool}
    (h : (if b = true then x else ok false) = ok true) : b = true ∧ x = ok true := by
  split at h
  · exact ⟨by assumption, h⟩
  · simp at h

/-- A clause that returned a flag that turned out to be `true`. -/
theorem ok_of_eq {b : Bool} {r : Result Bool} (h : r = ok b) (hb : b = true) : r = ok true := by
  subst hb; exact h

/-- The four constants, as numbers. They are extracted `irreducible`, so
every statement about them goes through here. -/
theorem firstPageLen_val : x64_layout.FIRST_PAGE_LEN.val = 4096 := by
  simp [global_simps]

theorem descriptorLen_val : x64_layout.DESCRIPTOR_LEN.val = 200 := by
  simp [global_simps]

theorem minRegionSpan_val : x64_layout.MIN_REGION_SPAN.val = 4096 := by
  simp [global_simps]

theorem nativeCallReserve_val : x64_layout.NATIVE_CALL_RESERVE.val = 240 := by
  simp [global_simps]

/-! ## The parameters a checked layout describes -/

/-- The `Params` of one activation entered with the layout `l`: the thirteen
numbers `l` carries, field for field, and the six words that are the entry
trampoline's business rather than the descriptor's. -/
def paramsOf (l : x64_layout.NativeLayout)
    (codeBase rsp0 rbp0 fp0 tableBase dispatcher : Word) : Params where
  codeBase := codeBase
  rsp0 := rsp0
  rbp0 := rbp0
  fp0 := fp0
  desc := l.descriptor.bv
  tableBase := tableBase
  dispatcher := dispatcher
  sgb := l.stack_guest_bottom.bv
  sgt := l.stack_guest_top.bv
  snb := l.stack_native_base.bv
  dgb := l.data_guest_bottom.bv
  dgt := l.data_guest_top.bv
  dnb := l.data_native_base.bv
  guestFloor := l.guest_floor.bv
  nativeFloor := l.native_floor.bv
  frameSize := l.frame_size.val
  stride := l.frame_stride.val
  stackLo := l.native_stack_lo.bv
  stackHi := l.native_stack_hi.bv

/-! ## `fits`, `disjoint` and the three spans

`RangesDisjoint` and `InRange` read the value of a `u64` through
`BitVec.toNat`, which is what `UScalar.val` is, so the two forms are the same
proposition and `rangesDisjoint_of_val` is the identity. -/

/-- `RangesDisjoint` on `u64` fields, stated on values. -/
theorem rangesDisjoint_of_val {a_lo a_len b_lo b_len : U64}
    (h : a_lo.val + a_len.val ≤ b_lo.val ∨ b_lo.val + b_len.val ≤ a_lo.val) :
    RangesDisjoint a_lo.bv a_len.val b_lo.bv b_len.val := h

/-- `fits a b` is `a + b ≤ u64::MAX`, one byte stricter than the no-wrap
clauses of `Layout`, which is what leaves every sum below computable. -/
theorem fits_spec {a b : U64} {r : Bool} (h : x64_layout.fits a b = ok r) :
    r = true ↔ a.val + b.val ≤ 2 ^ 64 - 1 := by
  unfold x64_layout.fits at h
  obtain ⟨i, hi, h⟩ := bind_ok h
  obtain ⟨-, hiv, -⟩ := u64_sub_ok hi
  simp only [ok.injEq] at h
  subst h
  have hmax : (core.num.U64.MAX : U64).val = 2 ^ 64 - 1 := by
    simp [global_simps, U64.rMax]
  have hb : b.val < 2 ^ 64 := by scalar_tac
  simp only [decide_eq_true_eq, UScalar.le_equiv]
  omega

/-- `disjoint` is conservative: it reports a range whose end is not
representable as meeting everything, so only the `true` direction is a fact
about the ranges. That is the direction `layout_ok` supplies. -/
theorem disjoint_spec {a_lo a_len b_lo b_len : U64} {r : Bool}
    (h : x64_layout.disjoint a_lo a_len b_lo b_len = ok r) (hr : r = true) :
    RangesDisjoint a_lo.bv a_len.val b_lo.bv b_len.val := by
  subst hr
  unfold x64_layout.disjoint at h
  obtain ⟨af, -, h⟩ := bind_ok h
  obtain ⟨bf, -, h⟩ := bind_ok h
  split at h
  · split at h
    · obtain ⟨a_hi, hahi, h⟩ := bind_ok h
      obtain ⟨b_hi, hbhi, h⟩ := bind_ok h
      obtain ⟨-, hav, -⟩ := u64_add_ok hahi
      obtain ⟨-, hbv, -⟩ := u64_add_ok hbhi
      split at h
      · rename_i hle
        exact rangesDisjoint_of_val (Or.inl (by have := u64_le_val hle; omega))
      · simp only [ok.injEq, decide_eq_true_eq] at h
        exact rangesDisjoint_of_val (Or.inr (by have := u64_le_val h; omega))
    · simp at h
  · simp at h

/-- `stack_span` is `sgt - sgb`, truncated at zero when the region is not a
range — which is exactly `Nat` subtraction, and so exactly `stackSpan`. -/
theorem stack_span_spec {l : x64_layout.NativeLayout} {s : U64}
    (h : x64_layout.stack_span l = ok s) :
    s.val = l.stack_guest_top.val - l.stack_guest_bottom.val := by
  unfold x64_layout.stack_span at h
  split at h
  · rename_i hgt
    simp only [ok.injEq] at h
    subst h
    have : l.stack_guest_top.val < l.stack_guest_bottom.val := hgt
    have hz : (0#u64 : U64).val = 0 := by scalar_tac
    omega
  · exact (u64_sub_ok h).2.1

theorem data_span_spec {l : x64_layout.NativeLayout} {s : U64}
    (h : x64_layout.data_span l = ok s) :
    s.val = l.data_guest_top.val - l.data_guest_bottom.val := by
  unfold x64_layout.data_span at h
  split at h
  · rename_i hgt
    simp only [ok.injEq] at h
    subst h
    have : l.data_guest_top.val < l.data_guest_bottom.val := hgt
    have hz : (0#u64 : U64).val = 0 := by scalar_tac
    omega
  · exact (u64_sub_ok h).2.1

theorem native_stack_span_spec {l : x64_layout.NativeLayout} {s : U64}
    (h : x64_layout.native_stack_span l = ok s) :
    s.val = l.native_stack_hi.val - l.native_stack_lo.val := by
  unfold x64_layout.native_stack_span at h
  split at h
  · rename_i hgt
    simp only [ok.injEq] at h
    subst h
    have : l.native_stack_hi.val < l.native_stack_lo.val := hgt
    have hz : (0#u64 : U64).val = 0 := by scalar_tac
    omega
  · exact (u64_sub_ok h).2.1

/-! ## The twenty-one clauses, inverted

One lemma per clause function of `x64_layout.rs`, each naming the clause of
`Layout` it is. The ordering and no-wrap clauses are equivalences; the ones
built on `disjoint` are implications, for the reason `disjoint_spec` gives. -/

theorem stack_ordered_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.stack_ordered l = ok b) :
    b = true ↔ l.stack_guest_bottom.val ≤ l.stack_guest_top.val := by
  unfold x64_layout.stack_ordered at h
  simp only [ok.injEq] at h
  subst h
  simp

theorem data_ordered_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.data_ordered l = ok b) :
    b = true ↔ l.data_guest_bottom.val ≤ l.data_guest_top.val := by
  unfold x64_layout.data_ordered at h
  simp only [ok.injEq] at h
  subst h
  simp

theorem native_stack_no_wrap_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.native_stack_no_wrap l = ok b) :
    b = true ↔ l.native_stack_lo.val ≤ l.native_stack_hi.val := by
  unfold x64_layout.native_stack_no_wrap at h
  simp only [ok.injEq] at h
  subst h
  simp

theorem stack_wide_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.stack_wide l = ok b) :
    b = true ↔ 4096 ≤ l.stack_guest_top.val - l.stack_guest_bottom.val := by
  unfold x64_layout.stack_wide at h
  obtain ⟨s, hs, h⟩ := bind_ok h
  have hsv := stack_span_spec hs
  simp only [ok.injEq] at h
  subst h
  simp only [decide_eq_true_eq, ge_iff_le, UScalar.le_equiv, minRegionSpan_val, hsv]

theorem data_wide_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.data_wide l = ok b) :
    b = true ↔ 4096 ≤ l.data_guest_top.val - l.data_guest_bottom.val := by
  unfold x64_layout.data_wide at h
  obtain ⟨s, hs, h⟩ := bind_ok h
  have hsv := data_span_spec hs
  simp only [ok.injEq] at h
  subst h
  simp only [decide_eq_true_eq, ge_iff_le, UScalar.le_equiv, minRegionSpan_val, hsv]

theorem stack_native_no_wrap_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.stack_native_no_wrap l = ok b) :
    b = true ↔
      l.stack_native_base.val + (l.stack_guest_top.val - l.stack_guest_bottom.val)
        ≤ 2 ^ 64 - 1 := by
  unfold x64_layout.stack_native_no_wrap at h
  obtain ⟨s, hs, h⟩ := bind_ok h
  rw [← stack_span_spec hs]
  exact fits_spec h

theorem data_native_no_wrap_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.data_native_no_wrap l = ok b) :
    b = true ↔
      l.data_native_base.val + (l.data_guest_top.val - l.data_guest_bottom.val)
        ≤ 2 ^ 64 - 1 := by
  unfold x64_layout.data_native_no_wrap at h
  obtain ⟨s, hs, h⟩ := bind_ok h
  rw [← data_span_spec hs]
  exact fits_spec h

theorem desc_no_wrap_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.desc_no_wrap l = ok b) :
    b = true ↔ l.descriptor.val + 200 ≤ 2 ^ 64 - 1 := by
  unfold x64_layout.desc_no_wrap at h
  rw [← descriptorLen_val]
  exact fits_spec h

theorem guest_disjoint_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.guest_disjoint l = ok b) (hb : b = true) :
    RangesDisjoint l.stack_guest_bottom.bv
      (l.stack_guest_top.val - l.stack_guest_bottom.val)
      l.data_guest_bottom.bv (l.data_guest_top.val - l.data_guest_bottom.val) := by
  unfold x64_layout.guest_disjoint at h
  obtain ⟨s, hs, h⟩ := bind_ok h
  obtain ⟨d, hd, h⟩ := bind_ok h
  have := disjoint_spec h hb
  rwa [stack_span_spec hs, data_span_spec hd] at this

theorem native_disjoint_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.native_disjoint l = ok b) (hb : b = true) :
    RangesDisjoint l.stack_native_base.bv
      (l.stack_guest_top.val - l.stack_guest_bottom.val)
      l.data_native_base.bv (l.data_guest_top.val - l.data_guest_bottom.val) := by
  unfold x64_layout.native_disjoint at h
  obtain ⟨s, hs, h⟩ := bind_ok h
  obtain ⟨d, hd, h⟩ := bind_ok h
  have := disjoint_spec h hb
  rwa [stack_span_spec hs, data_span_spec hd] at this

theorem stack_native_off_page_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.stack_native_off_page l = ok b) (hb : b = true) :
    RangesDisjoint 0#64 4096 l.stack_native_base.bv
      (l.stack_guest_top.val - l.stack_guest_bottom.val) := by
  unfold x64_layout.stack_native_off_page at h
  obtain ⟨s, hs, h⟩ := bind_ok h
  have := disjoint_spec h hb
  rwa [stack_span_spec hs, firstPageLen_val] at this

theorem data_native_off_page_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.data_native_off_page l = ok b) (hb : b = true) :
    RangesDisjoint 0#64 4096 l.data_native_base.bv
      (l.data_guest_top.val - l.data_guest_bottom.val) := by
  unfold x64_layout.data_native_off_page at h
  obtain ⟨s, hs, h⟩ := bind_ok h
  have := disjoint_spec h hb
  rwa [data_span_spec hs, firstPageLen_val] at this

theorem desc_off_page_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.desc_off_page l = ok b) (hb : b = true) :
    RangesDisjoint 0#64 4096 l.descriptor.bv 200 := by
  unfold x64_layout.desc_off_page at h
  have := disjoint_spec h hb
  rwa [firstPageLen_val, descriptorLen_val] at this

theorem native_stack_off_page_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.native_stack_off_page l = ok b) (hb : b = true) :
    RangesDisjoint 0#64 4096 l.native_stack_lo.bv
      (l.native_stack_hi.val - l.native_stack_lo.val) := by
  unfold x64_layout.native_stack_off_page at h
  obtain ⟨n, hn, h⟩ := bind_ok h
  have := disjoint_spec h hb
  rwa [native_stack_span_spec hn, firstPageLen_val] at this

theorem stack_native_off_desc_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.stack_native_off_desc l = ok b) (hb : b = true) :
    RangesDisjoint l.descriptor.bv 200 l.stack_native_base.bv
      (l.stack_guest_top.val - l.stack_guest_bottom.val) := by
  unfold x64_layout.stack_native_off_desc at h
  obtain ⟨s, hs, h⟩ := bind_ok h
  have := disjoint_spec h hb
  rwa [stack_span_spec hs, descriptorLen_val] at this

theorem data_native_off_desc_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.data_native_off_desc l = ok b) (hb : b = true) :
    RangesDisjoint l.descriptor.bv 200 l.data_native_base.bv
      (l.data_guest_top.val - l.data_guest_bottom.val) := by
  unfold x64_layout.data_native_off_desc at h
  obtain ⟨s, hs, h⟩ := bind_ok h
  have := disjoint_spec h hb
  rwa [data_span_spec hs, descriptorLen_val] at this

theorem stack_native_off_native_stack_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.stack_native_off_native_stack l = ok b) (hb : b = true) :
    RangesDisjoint l.native_stack_lo.bv (l.native_stack_hi.val - l.native_stack_lo.val)
      l.stack_native_base.bv (l.stack_guest_top.val - l.stack_guest_bottom.val) := by
  unfold x64_layout.stack_native_off_native_stack at h
  obtain ⟨n, hn, h⟩ := bind_ok h
  obtain ⟨s, hs, h⟩ := bind_ok h
  have := disjoint_spec h hb
  rwa [native_stack_span_spec hn, stack_span_spec hs] at this

theorem data_native_off_native_stack_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.data_native_off_native_stack l = ok b) (hb : b = true) :
    RangesDisjoint l.native_stack_lo.bv (l.native_stack_hi.val - l.native_stack_lo.val)
      l.data_native_base.bv (l.data_guest_top.val - l.data_guest_bottom.val) := by
  unfold x64_layout.data_native_off_native_stack at h
  obtain ⟨n, hn, h⟩ := bind_ok h
  obtain ⟨s, hs, h⟩ := bind_ok h
  have := disjoint_spec h hb
  rwa [native_stack_span_spec hn, data_span_spec hs] at this

theorem desc_off_native_stack_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.desc_off_native_stack l = ok b) (hb : b = true) :
    RangesDisjoint l.native_stack_lo.bv (l.native_stack_hi.val - l.native_stack_lo.val)
      l.descriptor.bv 200 := by
  unfold x64_layout.desc_off_native_stack at h
  obtain ⟨n, hn, h⟩ := bind_ok h
  have := disjoint_spec h hb
  rwa [native_stack_span_spec hn, descriptorLen_val] at this

theorem floor_room_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.floor_room l = ok b) (hb : b = true) :
    l.stack_native_base.val + l.frame_size.val + l.frame_stride.val ≤ l.guest_floor.val := by
  subst hb
  unfold x64_layout.floor_room at h
  obtain ⟨f, -, h⟩ := bind_ok h
  split at h
  · obtain ⟨one_frame, hof, h⟩ := bind_ok h
    obtain ⟨f1, -, h⟩ := bind_ok h
    split at h
    · obtain ⟨i, hi, h⟩ := bind_ok h
      obtain ⟨-, hofv, -⟩ := u64_add_ok hof
      obtain ⟨-, hiv, -⟩ := u64_add_ok hi
      simp only [ok.injEq, decide_eq_true_eq] at h
      have := u64_le_val h
      omega
    · simp at h
  · simp at h

theorem floor_native_spec {l : x64_layout.NativeLayout} {b : Bool}
    (h : x64_layout.floor_native l = ok b) (hb : b = true) :
    l.native_stack_lo.val + 240 ≤ l.native_floor.val := by
  subst hb
  unfold x64_layout.floor_native at h
  obtain ⟨f, -, h⟩ := bind_ok h
  split at h
  · obtain ⟨i, hi, h⟩ := bind_ok h
    obtain ⟨-, hiv, -⟩ := u64_add_ok hi
    simp only [ok.injEq, decide_eq_true_eq] at h
    have := u64_le_val h
    rw [nativeCallReserve_val] at hiv
    omega
  · simp at h

/-! ## `layout_ok` as its twenty-one clauses -/

/-- `layout_ok` is the conjunction it looks like: it returns `true` only when
every one of the twenty-one clause functions does. -/
theorem layout_ok_clauses {l : x64_layout.NativeLayout}
    (h : x64_layout.layout_ok l = ok true) :
    x64_layout.stack_ordered l = ok true ∧
    x64_layout.data_ordered l = ok true ∧
    x64_layout.stack_wide l = ok true ∧
    x64_layout.data_wide l = ok true ∧
    x64_layout.stack_native_no_wrap l = ok true ∧
    x64_layout.data_native_no_wrap l = ok true ∧
    x64_layout.desc_no_wrap l = ok true ∧
    x64_layout.native_stack_no_wrap l = ok true ∧
    x64_layout.guest_disjoint l = ok true ∧
    x64_layout.native_disjoint l = ok true ∧
    x64_layout.stack_native_off_page l = ok true ∧
    x64_layout.data_native_off_page l = ok true ∧
    x64_layout.desc_off_page l = ok true ∧
    x64_layout.native_stack_off_page l = ok true ∧
    x64_layout.stack_native_off_desc l = ok true ∧
    x64_layout.data_native_off_desc l = ok true ∧
    x64_layout.stack_native_off_native_stack l = ok true ∧
    x64_layout.data_native_off_native_stack l = ok true ∧
    x64_layout.desc_off_native_stack l = ok true ∧
    x64_layout.floor_room l = ok true ∧
    x64_layout.floor_native l = ok true := by
  unfold x64_layout.layout_ok at h
  obtain ⟨v1, e1, h⟩ := bind_ok h
  obtain ⟨v2, e2, h⟩ := bind_ok h
  obtain ⟨v3, e3, h⟩ := bind_ok h
  obtain ⟨v4, e4, h⟩ := bind_ok h
  obtain ⟨v5, e5, h⟩ := bind_ok h
  obtain ⟨v6, e6, h⟩ := bind_ok h
  obtain ⟨v7, e7, h⟩ := bind_ok h
  obtain ⟨v8, e8, h⟩ := bind_ok h
  obtain ⟨v9, e9, h⟩ := bind_ok h
  obtain ⟨v10, e10, h⟩ := bind_ok h
  obtain ⟨v11, e11, h⟩ := bind_ok h
  obtain ⟨v12, e12, h⟩ := bind_ok h
  obtain ⟨v13, e13, h⟩ := bind_ok h
  obtain ⟨v14, e14, h⟩ := bind_ok h
  obtain ⟨v15, e15, h⟩ := bind_ok h
  obtain ⟨v16, e16, h⟩ := bind_ok h
  obtain ⟨v17, e17, h⟩ := bind_ok h
  obtain ⟨v18, e18, h⟩ := bind_ok h
  obtain ⟨v19, e19, h⟩ := bind_ok h
  obtain ⟨v20, e20, h⟩ := bind_ok h
  obtain ⟨v21, e21, h⟩ := bind_ok h
  obtain ⟨c1, h⟩ := ite_ok_true h
  obtain ⟨c2, h⟩ := ite_ok_true h
  obtain ⟨c3, h⟩ := ite_ok_true h
  obtain ⟨c4, h⟩ := ite_ok_true h
  obtain ⟨c5, h⟩ := ite_ok_true h
  obtain ⟨c6, h⟩ := ite_ok_true h
  obtain ⟨c7, h⟩ := ite_ok_true h
  obtain ⟨c8, h⟩ := ite_ok_true h
  obtain ⟨c9, h⟩ := ite_ok_true h
  obtain ⟨c10, h⟩ := ite_ok_true h
  obtain ⟨c11, h⟩ := ite_ok_true h
  obtain ⟨c12, h⟩ := ite_ok_true h
  obtain ⟨c13, h⟩ := ite_ok_true h
  obtain ⟨c14, h⟩ := ite_ok_true h
  obtain ⟨c15, h⟩ := ite_ok_true h
  obtain ⟨c16, h⟩ := ite_ok_true h
  obtain ⟨c17, h⟩ := ite_ok_true h
  obtain ⟨c18, h⟩ := ite_ok_true h
  obtain ⟨c19, h⟩ := ite_ok_true h
  obtain ⟨c20, h⟩ := ite_ok_true h
  simp only [ok.injEq] at h
  exact ⟨ok_of_eq e1 c1, ok_of_eq e2 c2, ok_of_eq e3 c3, ok_of_eq e4 c4,
    ok_of_eq e5 c5, ok_of_eq e6 c6, ok_of_eq e7 c7, ok_of_eq e8 c8,
    ok_of_eq e9 c9, ok_of_eq e10 c10, ok_of_eq e11 c11, ok_of_eq e12 c12,
    ok_of_eq e13 c13, ok_of_eq e14 c14, ok_of_eq e15 c15, ok_of_eq e16 c16,
    ok_of_eq e17 c17, ok_of_eq e18 c18, ok_of_eq e19 c19, ok_of_eq e20 c20,
    ok_of_eq e21 h⟩

/-! ## From the check to `Layout`

The ten clauses that mention `frameSlots P` or `stackWindow P` are not
checked and cannot be: they name `rbp0` and `rsp0`. They are not assumed
either. Both windows lie inside `[stackLo, stackHi)` — the frame scratch
because `rbp0` is below `stackHi` and the window because `rsp0 - 128` is
above `stackLo` — and a range inside a range that misses something misses it
too. -/

/-- A range inside a range that is disjoint from `[b, b + n)` is disjoint
from `[b, b + n)`. -/
theorem subrange_disjoint {lo c b : Word} {m k n : Nat}
    (hd : RangesDisjoint lo m b n) (h1 : lo.toNat ≤ c.toNat)
    (h2 : c.toNat + k ≤ lo.toNat + m) : RangesDisjoint c k b n := by
  unfold RangesDisjoint at hd ⊢
  omega

/-- What the runtime checks is what the theorem assumes.

`layout_ok l = ok true` is the twenty-one comparisons `program.rs` runs
before it enters generated code. The six side conditions are what the entry
trampoline establishes and no check over `l` alone could: the entry `rsp`
sits at least 128 bytes above the bottom of the coroutine stack's mapping,
the entry `rbp` at or below its top, with the frame scratch and the native
stack window between them and clear of address zero; and the frame register
points at a frame inside the guest stack's native backing. Together they are
`Layout` — every clause, `frameSlots` and `stackWindow` included. -/
theorem layout_of_check {l : x64_layout.NativeLayout}
    {codeBase rsp0 rbp0 fp0 tableBase dispatcher : Word}
    (h : x64_layout.layout_ok l = ok true)
    (hrsp : l.native_stack_lo.val + 128 ≤ rsp0.toNat)
    (hrbp : rbp0.toNat ≤ l.native_stack_hi.val)
    (hbelow : rsp0.toNat + 8 ≤ rbp0.toNat - 160)
    (hframe160 : 160 ≤ rbp0.toNat)
    (hfpLo : l.stack_native_base.val + l.frame_size.val ≤ fp0.toNat)
    (hfpHi : fp0.toNat ≤ l.stack_native_base.val
      + (l.stack_guest_top.val - l.stack_guest_bottom.val)) :
    Layout (paramsOf l codeBase rsp0 rbp0 fp0 tableBase dispatcher) := by
  obtain ⟨e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, e13, e14, e15, e16,
    e17, e18, e19, e20, e21⟩ := layout_ok_clauses h
  -- The clauses, as arithmetic.
  have cOrdS := (stack_ordered_spec e1).1 rfl
  have cOrdD := (data_ordered_spec e2).1 rfl
  have cWideS := (stack_wide_spec e3).1 rfl
  have cWideD := (data_wide_spec e4).1 rfl
  have cNoWrapS := (stack_native_no_wrap_spec e5).1 rfl
  have cNoWrapD := (data_native_no_wrap_spec e6).1 rfl
  have cNoWrapDesc := (desc_no_wrap_spec e7).1 rfl
  have cNoWrapNat := (native_stack_no_wrap_spec e8).1 rfl
  have cGuest := guest_disjoint_spec e9 rfl
  have cNative := native_disjoint_spec e10 rfl
  have cPageS := stack_native_off_page_spec e11 rfl
  have cPageD := data_native_off_page_spec e12 rfl
  have cPageDesc := desc_off_page_spec e13 rfl
  have cPageNat := native_stack_off_page_spec e14 rfl
  have cDescS := stack_native_off_desc_spec e15 rfl
  have cDescD := data_native_off_desc_spec e16 rfl
  have cNatS := stack_native_off_native_stack_spec e17 rfl
  have cNatD := data_native_off_native_stack_spec e18 rfl
  have cNatDesc := desc_off_native_stack_spec e19 rfl
  have cFloorRoom := floor_room_spec e20 rfl
  have cFloorNative := floor_native_spec e21 rfl
  -- The two windows, in `Nat`.
  have hfsN : (frameSlots (paramsOf l codeBase rsp0 rbp0 fp0 tableBase dispatcher)).toNat
      = rbp0.toNat - 160 := by
    show (rbp0 - 160#64).toNat = rbp0.toNat - 160
    rw [show (160#64 : Word) = BitVec.ofNat 64 160 from rfl]
    exact toNat_sub_ofNat (by omega) (by norm_num)
  have hswN : (stackWindow (paramsOf l codeBase rsp0 rbp0 fp0 tableBase dispatcher)).toNat
      = rsp0.toNat - 128 := by
    show (rsp0 - 128#64).toNat = rsp0.toNat - 128
    rw [show (128#64 : Word) = BitVec.ofNat 64 128 from rfl]
    exact toNat_sub_ofNat (by omega) (by norm_num)
  have hrbpLt : rbp0.toNat < 2 ^ 64 := rbp0.isLt
  -- Both windows lie inside the coroutine stack's mapping.
  have hframeSub : ∀ (b : Word) (n : Nat),
      RangesDisjoint l.native_stack_lo.bv
        (l.native_stack_hi.val - l.native_stack_lo.val) b n →
      RangesDisjoint
        (frameSlots (paramsOf l codeBase rsp0 rbp0 fp0 tableBase dispatcher)) 160 b n := by
    intro b n hd
    refine subrange_disjoint hd ?_ ?_
    · rw [hfsN]
      show l.native_stack_lo.val ≤ rbp0.toNat - 160
      omega
    · rw [hfsN]
      show rbp0.toNat - 160 + 160
        ≤ l.native_stack_lo.val + (l.native_stack_hi.val - l.native_stack_lo.val)
      omega
  have hwindowSub : ∀ (b : Word) (n : Nat),
      RangesDisjoint l.native_stack_lo.bv
        (l.native_stack_hi.val - l.native_stack_lo.val) b n →
      RangesDisjoint
        (stackWindow (paramsOf l codeBase rsp0 rbp0 fp0 tableBase dispatcher))
        stackWindowLen b n := by
    intro b n hd
    refine subrange_disjoint hd ?_ ?_
    · rw [hswN]
      show l.native_stack_lo.val ≤ rsp0.toNat - 128
      omega
    · rw [hswN]
      show rsp0.toNat - 128 + 136
        ≤ l.native_stack_lo.val + (l.native_stack_hi.val - l.native_stack_lo.val)
      omega
  exact
    { stackOrdered := cOrdS
      dataOrdered := cOrdD
      guestDisjoint := cGuest
      frameNoWrap := by rw [hfsN]; omega
      stackWindowNoWrap := by
        rw [hswN]; show rsp0.toNat - 128 + 136 ≤ 2 ^ 64; omega
      stackNativeNoWrap := by
        show l.stack_native_base.val
          + (l.stack_guest_top.val - l.stack_guest_bottom.val) ≤ 2 ^ 64
        omega
      dataNativeNoWrap := by
        show l.data_native_base.val
          + (l.data_guest_top.val - l.data_guest_bottom.val) ≤ 2 ^ 64
        omega
      descNoWrap := by show l.descriptor.val + 200 ≤ 2 ^ 64; omega
      nativeDisjoint := cNative
      stackNativeOffPage := cPageS
      dataNativeOffPage := cPageD
      stackNativeOffFrame := hframeSub _ _ cNatS
      dataNativeOffFrame := hframeSub _ _ cNatD
      stackNativeOffStack := hwindowSub _ _ cNatS
      dataNativeOffStack := hwindowSub _ _ cNatD
      stackNativeOffDesc := cDescS
      dataNativeOffDesc := cDescD
      frameOffStack := by
        refine Or.inr ?_
        show (stackWindow (paramsOf l codeBase rsp0 rbp0 fp0 tableBase dispatcher)).toNat + 136
          ≤ (frameSlots (paramsOf l codeBase rsp0 rbp0 fp0 tableBase dispatcher)).toNat
        rw [hfsN, hswN]
        omega
      frameOffDesc := hframeSub _ _ cNatDesc
      stackOffDesc := hwindowSub _ _ cNatDesc
      stackBelowFrame := by rw [hfsN]; exact hbelow
      frameAbove := hfpLo
      frameBelow := hfpHi
      floorRoom := cFloorRoom
      stackWide := cWideS
      dataWide := cWideD
      frameRoom := hframe160
      stackRoom := by show (128 : Nat) ≤ rsp0.toNat; omega
      frameOffPage := (hframeSub _ _ cPageNat.symm).symm
      descOffPage := cPageDesc
      nativeStackNoWrap := ⟨cNoWrapNat, le_of_lt l.native_stack_hi.bv.isLt⟩
      nativeStackLo := hrsp
      nativeStackHi := hrbp
      nativeStackOffPage := cPageNat
      stackNativeOffNativeStack := cNatS
      dataNativeOffNativeStack := cNatD
      descOffNativeStack := cNatDesc
      floorNative := cFloorNative }

/-! ## The derived constants

`sub_mod` is `wrapping_sub` written out — `wrapping_sub` has no Aeneas model —
and `wrapping_sub` is subtraction in `BitVec 64`, which is the arithmetic
`DerivedBlock` is stated in. -/

/-- `sub_mod a b` is `a - b` in `BitVec 64`. -/
theorem sub_mod_spec {a b r : U64} (h : x64_layout.sub_mod a b = ok r) :
    r.bv = a.bv - b.bv := by
  unfold x64_layout.sub_mod at h
  split at h
  · exact (u64_sub_ok h).2.2
  · rename_i hlt
    have hlt' : a.val < b.val := by
      have : ¬ (b.val ≤ a.val) := hlt
      omega
    obtain ⟨i, hi, h⟩ := bind_ok h
    obtain ⟨i1, hi1, h⟩ := bind_ok h
    obtain ⟨-, hiv, -⟩ := u64_sub_ok hi
    obtain ⟨-, hi1v, -⟩ := u64_sub_ok hi1
    obtain ⟨-, hrv, -⟩ := u64_add_ok h
    have hmax : (core.num.U64.MAX : U64).val = 2 ^ 64 - 1 := by
      simp [global_simps, U64.rMax]
    have hone : (1#u64 : U64).val = 1 := by scalar_tac
    have hb : b.val < 2 ^ 64 := by scalar_tac
    apply BitVec.eq_of_toNat_eq
    have hgoal : r.val = 2 ^ 64 - b.val + a.val := by omega
    rw [BitVec.toNat_sub]
    show r.val = (2 ^ 64 - b.bv.toNat + a.bv.toNat) % 2 ^ 64
    show r.val = (2 ^ 64 - b.val + a.val) % 2 ^ 64
    rw [Nat.mod_eq_of_lt (by omega)]
    exact hgoal

/-- The six words `derived_block` computes, one region's bounds-check
constants: the guest bottom, the guest-to-native delta, and the highest
in-range guest address at each of the four access widths, relative to the
bottom. They are the six fields of `DerivedBlock`, in order. -/
theorem derived_block_spec {bottom top nb : U64} {arr : Std.Array U64 6#usize}
    (h : x64_layout.derived_block bottom top nb = ok arr) :
    (arr.val[0]!).bv = bottom.bv ∧
    (arr.val[1]!).bv = nb.bv - bottom.bv ∧
    (arr.val[2]!).bv = (top.bv - 1#64) - bottom.bv ∧
    (arr.val[3]!).bv = (top.bv - 2#64) - bottom.bv ∧
    (arr.val[4]!).bv = (top.bv - 4#64) - bottom.bv ∧
    (arr.val[5]!).bv = (top.bv - 8#64) - bottom.bv := by
  unfold x64_layout.derived_block at h
  obtain ⟨delta, hdelta, h⟩ := bind_ok h
  obtain ⟨top1, htop1, h⟩ := bind_ok h
  obtain ⟨top2, htop2, h⟩ := bind_ok h
  obtain ⟨top4, htop4, h⟩ := bind_ok h
  obtain ⟨top8, htop8, h⟩ := bind_ok h
  obtain ⟨span1, hspan1, h⟩ := bind_ok h
  obtain ⟨span2, hspan2, h⟩ := bind_ok h
  obtain ⟨span4, hspan4, h⟩ := bind_ok h
  obtain ⟨span8, hspan8, h⟩ := bind_ok h
  simp only [ok.injEq] at h
  subst h
  have hd := sub_mod_spec hdelta
  have h1 := sub_mod_spec htop1
  have h2 := sub_mod_spec htop2
  have h4 := sub_mod_spec htop4
  have h8 := sub_mod_spec htop8
  have s1 := sub_mod_spec hspan1
  have s2 := sub_mod_spec hspan2
  have s4 := sub_mod_spec hspan4
  have s8 := sub_mod_spec hspan8
  refine ⟨rfl, hd, ?_, ?_, ?_, ?_⟩
  · show span1.bv = (top.bv - 1#64) - bottom.bv
    rw [s1, h1]
    rfl
  · show span2.bv = (top.bv - 2#64) - bottom.bv
    rw [s2, h2]
    rfl
  · show span4.bv = (top.bv - 4#64) - bottom.bv
    rw [s4, h4]
    rfl
  · show span8.bv = (top.bv - 8#64) - bottom.bv
    rw [s8, h8]
    rfl

/-- The twelve derived slots, read back as the two structures `RoMem` wants.

`JitMemory::fill_derived` computes each region's block with `derived_block`
and copies it into the six slots at `derivedSlot P k` and up; this is that
copy, inverted. -/
theorem derivedBlock_of_slots {P : Params} {m : Mem}
    {sgb sgt snb dgb dgt dnb : U64} {sa da : Std.Array U64 6#usize}
    (hs : x64_layout.derived_block sgb sgt snb = ok sa)
    (hd : x64_layout.derived_block dgb dgt dnb = ok da)
    (h0 : ∀ i, i < 6 → load64 m (derivedSlot P i) = (sa.val[i]!).bv)
    (h6 : ∀ i, i < 6 → load64 m (derivedSlot P (6 + i)) = (da.val[i]!).bv) :
    DerivedBlock P m 0 sgb.bv sgt.bv snb.bv ∧ DerivedBlock P m 6 dgb.bv dgt.bv dnb.bv := by
  obtain ⟨s0, s1, s2, s3, s4, s5⟩ := derived_block_spec hs
  obtain ⟨d0, d1, d2, d3, d4, d5⟩ := derived_block_spec hd
  exact
    ⟨{ bottom := (h0 0 (by norm_num)).trans s0
       delta := (h0 1 (by norm_num)).trans s1
       span1 := (h0 2 (by norm_num)).trans s2
       span2 := (h0 3 (by norm_num)).trans s3
       span4 := (h0 4 (by norm_num)).trans s4
       span8 := (h0 5 (by norm_num)).trans s5 },
     { bottom := (h6 0 (by norm_num)).trans d0
       delta := (h6 1 (by norm_num)).trans d1
       span1 := (h6 2 (by norm_num)).trans d2
       span2 := (h6 3 (by norm_num)).trans d3
       span4 := (h6 4 (by norm_num)).trans d4
       span8 := (h6 5 (by norm_num)).trans d5 }⟩

end X64

end async_ebpf_verified

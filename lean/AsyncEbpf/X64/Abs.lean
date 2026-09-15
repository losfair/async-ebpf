import AsyncEbpf.Loop
import AsyncEbpf.X64.Contract
import AsyncEbpf.X64.Tag

/-!
# Agreement between the checker's abstract state and the machine

`x64_check::check` walks the macro list carrying an abstract state: a `Tag`
per native register, the native stack depth, the tag of the group base parked
at `[rbp - 144]`, and whether the walk is live. This file says what that state
*means* about a machine state, and proves the handful of facts every macro
proof needs of it.

`Agree P a s` is the relation. It has six clauses and each of them is load
bearing:

* `regs` reads every register through its tag: `Fp` is the entry value of the
  frame register, `Checked w` is zero or a native address whose `w`-byte
  window lies inside one guest region, `Top` says nothing;
* `rsp` is the depth bookkeeping — `rsp` is exactly `depth` words below its
  entry value, which is what bounds the native stack;
* `depth` is the checker's own bound, carried over so that the bound on `rsp`
  is a bound on the stack window;
* `rbp` never moves: the generated code never writes it, and the frame scratch
  is addressed through it;
* `ro` is the half of the entry contract a macro has to keep: the derived
  slots, the delta slot, the descriptor pointer and the descriptor itself;
* `group` reads the parked group base the same way a register is read.

The rest of the file is the toolkit. `GuestOk` is what the three address rules
establish about an access: it is allowed, and it is clear of everything `RoMem`
pins, so a store through it keeps the agreement. `tagOk_checked_window` and
`frame_access_ok` are the two rules that produce it; `frame_slot_ok`,
`stack_slot_ok` and `desc_field_ok` are the accesses the generated code makes
to its own frame, its own stack and the descriptor.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-! ## Arithmetic

The three facts about 64-bit addresses every window argument below reduces to.
All three are stated on `toNat`, or on `Int` where a displacement is signed,
because that is the form `omega` reasons in. -/

theorem toNat_sub_ofNat {x : Word} {k : Nat} (h : k ≤ x.toNat) (hk : k < 2 ^ 64) :
    (x - BitVec.ofNat 64 k).toNat = x.toNat - k := by
  have := x.isLt
  rw [BitVec.toNat_sub, BitVec.toNat_ofNat, Nat.mod_eq_of_lt hk]
  omega

theorem toNat_add_ofNat {x : Word} {k : Nat} (h : x.toNat + k < 2 ^ 64) :
    (x + BitVec.ofNat 64 k).toNat = x.toNat + k := by
  have := x.isLt
  rw [BitVec.toNat_add, BitVec.toNat_ofNat]
  omega

/-- A sign-extended 32-bit displacement denotes the integer it names. -/
theorem toInt_signExtend (d : BitVec 32) : (BitVec.signExtend 64 d).toInt = d.toInt := by
  have h1 : d.toInt < 2 ^ 31 := by have := BitVec.toInt_lt (x := d); simpa using this
  have h2 : -(2 ^ 31 : Int) ≤ d.toInt := by have := BitVec.le_toInt (x := d); simpa using this
  rw [BitVec.toInt_signExtend, show min 64 32 = 32 from rfl, Int.bmod]
  norm_num
  omega

/-- `[base + disp]` sits where the integers say it does, as long as it stays
inside the address space. -/
theorem toNat_addr {x : Word} {d : Std.I32}
    (hlo : 0 ≤ (x.toNat : Int) + d.val) (hhi : (x.toNat : Int) + d.val < 2 ^ 64) :
    (((x + BitVec.signExtend 64 d.bv).toNat : Int)) = (x.toNat : Int) + d.val := by
  have hyi : (BitVec.signExtend 64 d.bv : Word).toInt = d.val := toInt_signExtend d.bv
  have hcond := BitVec.toInt_eq_toNat_cond (BitVec.signExtend 64 d.bv : Word)
  have hylt := (BitVec.signExtend 64 d.bv : Word).isLt
  have hxlt := x.isLt
  have hsum : (x + BitVec.signExtend 64 d.bv).toNat
      = (x.toNat + (BitVec.signExtend 64 d.bv : Word).toNat) % 2 ^ 64 := by
    rw [BitVec.toNat_add]
  rw [hsum, hyi] at *
  split at hcond <;> omega

/-! ## The layout, read off -/

namespace Layout

variable {P : Params}

/-- The frame scratch really is the 160 bytes below `rbp0`. -/
theorem frameSlots_toNat (h : Layout P) : (frameSlots P).toNat = P.rbp0.toNat - 160 := by
  have := h.frameRoom
  rw [frameSlots, show (160#64 : Word) = BitVec.ofNat 64 160 from rfl]
  exact toNat_sub_ofNat (by omega) (by norm_num)

/-- And the native stack window the 136 bytes from `rsp0 - 128`. -/
theorem stackWindow_toNat (h : Layout P) : (stackWindow P).toNat = P.rsp0.toNat - 128 := by
  have := h.stackRoom
  rw [stackWindow, show (128#64 : Word) = BitVec.ofNat 64 128 from rfl]
  exact toNat_sub_ofNat (by omega) (by norm_num)

end Layout

/-- Two disjoint ranges have no address in common. -/
theorem notInRange_of_disjoint {c : Word} {j : Nat} {d : Word} {i : Nat}
    (h : RangesDisjoint c j d i) : ∀ a : Word, InRange c j a → ¬ InRange d i a := by
  intro a ha hb
  obtain ⟨h1, h2⟩ := ha
  obtain ⟨h3, h4⟩ := hb
  rcases h with h | h <;> omega

/-- …and conversely, a range that meets no address of another is disjoint from
it. The two witnesses are the greater of the two bases, which is why both
ranges have to be non-empty. -/
theorem rangesDisjoint_of_forall {b : Word} {k : Nat} {c : Word} {j : Nat}
    (hk : 0 < k) (hj : 0 < j)
    (h : ∀ a : Word, InRange b k a → ¬ InRange c j a) : RangesDisjoint c j b k := by
  by_contra hcon
  simp only [RangesDisjoint, not_or, not_le] at hcon
  obtain ⟨h1, h2⟩ := hcon
  have hblt := b.isLt
  have hclt := c.isLt
  refine h (BitVec.ofNat 64 (max b.toNat c.toNat)) ?_ ?_ <;>
    · refine ⟨?_, ?_⟩ <;>
      · rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]
        omega

/-! ## Tags -/

/-- `[v, v + w)` lies inside `[c, c + k)`. -/
def WindowIn (c : Word) (k : Nat) (v : Word) (w : Nat) : Prop :=
  c.toNat ≤ v.toNat ∧ v.toNat + w ≤ c.toNat + k

/-- What a tag says about a value. `Checked w` is the branchless check's own
postcondition: the register holds zero — which a failed check parks, and which
the first page catches — or a native address whose `w`-byte window is inside
one of the two guest regions. -/
def TagOk (P : Params) : x64_check.Tag → Word → Prop
  | .Top, _ => True
  | .Fp, v => v = P.fp0
  | .Checked w, v =>
      v = 0#64 ∨ WindowIn P.snb (stackSpan P) v w.val ∨ WindowIn P.dnb (dataSpan P) v w.val

@[simp] theorem tagOk_top (P : Params) (v : Word) : TagOk P .Top v := trivial

@[simp] theorem tagOk_fp (P : Params) (v : Word) : TagOk P .Fp v ↔ v = P.fp0 := Iff.rfl

theorem regs_length (a : x64_check.State) : a.regs.val.length = 16 := a.regs.property

/-! ## The agreement relation -/

/-- The checker's abstract state `a` describes the machine state `s`. -/
structure Agree (P : Params) (a : x64_check.State) (s : State) : Prop where
  /-- Every register holds a value its tag admits. -/
  regs : ∀ r, r < 16 → TagOk P (tagAt a r) (s.regs r)
  /-- `rsp` is `depth` words below its entry value. -/
  rsp : s.regs RSP = P.rsp0 - BitVec.ofNat 64 (8 * a.depth.val)
  /-- And the depth is bounded, so that is inside the native stack window. -/
  depth : a.depth.val ≤ 16
  /-- `rbp` never moves. -/
  rbp : s.regs RBP = P.rbp0
  /-- The bytes the entry trampoline filled in are still there. -/
  ro : RoMem P s.mem
  /-- The parked group base holds a value its tag admits. -/
  group : TagOk P a.group (load64 s.mem (P.rbp0 - 144#64))

/-! ## Accesses

`GuestOk` is what the address rules establish: the access is allowed, *and* it
misses the frame scratch and the descriptor, which is what a store through it
needs in order to keep `RoMem`. -/

/-- An access the generated code makes to guest memory. -/
structure GuestOk (P : Params) (b : Word) (n : Nat) : Prop where
  access : AccessOk P b n
  /-- Clear of the frame scratch. -/
  offFrame : ∀ a : Word, InRange b n a → ¬ InRange (frameSlots P) 160 a
  /-- Clear of the descriptor. -/
  offDesc : ∀ a : Word, InRange b n a → ¬ InRange P.desc 200 a

/-- An empty access is safe wherever it points. -/
theorem accessOk_zero (P : Params) (b : Word) : AccessOk P b 0 := by
  refine ⟨by have := b.isLt; omega, fun a ha => ?_⟩
  exact absurd ha (by simp only [InRange, not_and, not_lt]; omega)

/-- The workhorse: `[base + disp, base + disp + n)` inside a window every byte
of which is allowed. `hfr` and `hde` are what makes the conclusion a `GuestOk`
rather than merely an `AccessOk`. -/
theorem guestOk_of_window {P : Params} {c : Word} {k : Nat} {v : Word} {n : Nat}
    {disp : Std.I32}
    (hnw : c.toNat + k ≤ 2 ^ 64)
    (hall : ∀ a : Word, InRange c k a → Allowed P a)
    (hfr : ∀ a : Word, InRange c k a → ¬ InRange (frameSlots P) 160 a)
    (hde : ∀ a : Word, InRange c k a → ¬ InRange P.desc 200 a)
    (hlo : (c.toNat : Int) ≤ (v.toNat : Int) + disp.val)
    (hhi : (v.toNat : Int) + disp.val + n ≤ (c.toNat : Int) + k) :
    GuestOk P (v + BitVec.signExtend 64 disp.bv) n := by
  rcases Nat.eq_zero_or_pos n with rfl | hn
  · -- An empty access touches nothing, so it is inside every window.
    exact ⟨accessOk_zero _ _, fun a ha => absurd ha.2 (by have := ha.1; omega),
      fun a ha => absurd ha.2 (by have := ha.1; omega)⟩
  · have hb : (((v + BitVec.signExtend 64 disp.bv).toNat : Int)) = (v.toNat : Int) + disp.val := by
      refine toNat_addr ?_ ?_ <;> omega
    have hsub : ∀ a : Word, InRange (v + BitVec.signExtend 64 disp.bv) n a → InRange c k a := by
      intro a ha
      obtain ⟨h1, h2⟩ := ha
      exact ⟨by omega, by omega⟩
    exact ⟨⟨by omega, fun a ha => hall a (hsub a ha)⟩, fun a ha => hfr a (hsub a ha),
      fun a ha => hde a (hsub a ha)⟩

/-- The checked rule: a `Checked w` base with the access inside `[0, w)`. The
first page catches the parked zero, and the region catches everything else;
the two are the same statement because a region is never narrower than a page
(`Layout.stackWide`, `Layout.dataWide`). -/
theorem tagOk_checked_window {P : Params} {w : Std.U32} {v : Word} {n : Nat} {disp : Std.I32}
    (hL : Layout P) (h : TagOk P (.Checked w) v)
    (hd0 : 0 ≤ disp.val) (hdn : disp.val + n ≤ (w.val : Int)) (hw : w.val ≤ 4096) :
    GuestOk P (v + BitVec.signExtend 64 disp.bv) n := by
  rcases h with hz | hs | hd
  · -- Zero: the whole window is the first page.
    subst hz
    refine guestOk_of_window (c := 0#64) (k := 4096) (by norm_num)
      (fun a ha => allowed_firstPage ha)
      (notInRange_of_disjoint hL.frameOffPage) (notInRange_of_disjoint hL.descOffPage)
      (by simp only [BitVec.toNat_ofNat]; omega) ?_
    simp only [BitVec.toNat_ofNat]
    omega
  · -- Inside the stack's native backing.
    obtain ⟨hlo, hhi⟩ := hs
    exact guestOk_of_window hL.stackNativeNoWrap (fun a ha => allowed_stackNative ha)
      (notInRange_of_disjoint hL.stackNativeOffFrame.symm)
      (notInRange_of_disjoint hL.stackNativeOffDesc.symm) (by omega) (by omega)
  · -- Inside the data region's native backing.
    obtain ⟨hlo, hhi⟩ := hd
    exact guestOk_of_window hL.dataNativeNoWrap (fun a ha => allowed_dataNative ha)
      (notInRange_of_disjoint hL.dataNativeOffFrame.symm)
      (notInRange_of_disjoint hL.dataNativeOffDesc.symm) (by omega) (by omega)

/-- The frame fast path: `[r15 + d]` with `-F ≤ d` and `d + n ≤ 0`, where the
frame register still holds the native frame base. The window
`[fp0 - F, fp0)` is inside the stack's native backing by the entry contract. -/
theorem frame_access_ok {P : Params} {v : Word} {n : Nat} {disp : Std.I32}
    (hL : Layout P) (hv : v = P.fp0)
    (hlo : -(P.frameSize : Int) ≤ disp.val) (hhi : disp.val + n ≤ 0) :
    GuestOk P (v + BitVec.signExtend 64 disp.bv) n := by
  subst hv
  have ha := hL.frameAbove
  have hb := hL.frameBelow
  exact guestOk_of_window hL.stackNativeNoWrap (fun a ha => allowed_stackNative ha)
    (notInRange_of_disjoint hL.stackNativeOffFrame.symm)
    (notInRange_of_disjoint hL.stackNativeOffDesc.symm) (by omega) (by omega)

/-- A slot of the frame scratch, read or written through `rbp`. -/
theorem frame_slot_ok {P : Params} {n : Nat} {disp : Std.I32}
    (hL : Layout P) (hlo : -160 ≤ disp.val) (hhi : disp.val + n ≤ 0) :
    AccessOk P (P.rbp0 + BitVec.signExtend 64 disp.bv) n := by
  have hfs := hL.frameSlots_toNat
  have hnw := hL.frameNoWrap
  have hroom := hL.frameRoom
  rcases Nat.eq_zero_or_pos n with rfl | hn
  · exact accessOk_zero _ _
  · have hb : (((P.rbp0 + BitVec.signExtend 64 disp.bv).toNat : Int))
        = (P.rbp0.toNat : Int) + disp.val := by
      refine toNat_addr ?_ ?_ <;> omega
    refine ⟨by omega, fun a ha => allowed_frame ?_⟩
    obtain ⟨h1, h2⟩ := ha
    exact ⟨by omega, by omega⟩

/-- A word of the native stack window: the word at `rsp`, or the one a push is
about to write below it. `d` is the depth after the push. -/
theorem stack_slot_ok {P : Params} {d : Nat} (hL : Layout P) (hd : d ≤ 16) :
    AccessOk P (P.rsp0 - BitVec.ofNat 64 (8 * d)) 8 := by
  have hsw := hL.stackWindow_toNat
  have hnw := hL.stackWindowNoWrap
  have hroom := hL.stackRoom
  simp only [stackWindowLen] at hnw
  have hb : (P.rsp0 - BitVec.ofNat 64 (8 * d)).toNat = P.rsp0.toNat - 8 * d :=
    toNat_sub_ofNat (by omega) (by omega)
  exact ⟨by omega, fun a ha => allowed_stack ⟨by simp only [InRange] at ha; omega,
    by simp only [InRange] at ha; simp only [stackWindowLen]; omega⟩⟩

/-- `rsp - 8` is the word one deeper. -/
theorem rsp_push {P : Params} {d : Nat} :
    P.rsp0 - BitVec.ofNat 64 (8 * d) - 8#64 = P.rsp0 - BitVec.ofNat 64 (8 * (d + 1)) := by
  have : (BitVec.ofNat 64 (8 * (d + 1)) : Word) = BitVec.ofNat 64 (8 * d) + 8#64 := by
    apply BitVec.eq_of_toNat_eq
    simp only [BitVec.toNat_add, BitVec.toNat_ofNat]
    omega
  rw [this]
  ring

/-- A field of the memory descriptor. -/
theorem desc_field_ok {P : Params} {n : Nat} {disp : Std.I32}
    (hL : Layout P) (hlo : 0 ≤ disp.val) (hhi : disp.val + n ≤ 200) :
    AccessOk P (P.desc + BitVec.signExtend 64 disp.bv) n := by
  have hnw := hL.descNoWrap
  rcases Nat.eq_zero_or_pos n with rfl | hn
  · exact accessOk_zero _ _
  · have hb : (((P.desc + BitVec.signExtend 64 disp.bv).toNat : Int))
        = (P.desc.toNat : Int) + disp.val := by
      refine toNat_addr ?_ ?_ <;> omega
    refine ⟨by omega, fun a ha => allowed_desc ?_⟩
    obtain ⟨h1, h2⟩ := ha
    exact ⟨by omega, by omega⟩

/-! ## Keeping the read-only bytes

`RoMem` is the half of the entry contract that a store can break. Everything
it pins lies in three ranges: `[rbp0 - 136, rbp0 - 32)` (the twelve derived
slots and the stack delta below them), `[rbp0 - 8, rbp0)` (the descriptor's
address), and the descriptor itself. The four writable frame slots — the two
spills, the accumulator spill and the parked group base — and the whole of
`[rbp0 - 160, rbp0 - 144 + 8)` fall in the gaps, which is why a store to one
of them keeps `RoMem`. -/

/-- A store of no bytes is not a store. -/
theorem store_zero (m : Mem) (b : Word) (v : BitVec (8 * 0)) : store 0 m b v = m := by
  funext x
  simp [store]

theorem rbp_sub_toNat {P : Params} (hL : Layout P) {j : Nat} (hj : j ≤ 160) :
    (P.rbp0 - BitVec.ofNat 64 j).toNat = P.rbp0.toNat - j := by
  have := hL.frameRoom
  exact toNat_sub_ofNat (by omega) (by omega)

theorem desc_add_toNat {P : Params} (hL : Layout P) {j : Nat} (hj : j < 200) :
    (P.desc + BitVec.ofNat 64 j).toNat = P.desc.toNat + j := by
  have := hL.descNoWrap
  exact toNat_add_ofNat (by omega)

theorem derivedSlot_toNat {P : Params} (hL : Layout P) {i : Nat} (hi : i ≤ 11) :
    (derivedSlot P i).toNat = P.rbp0.toNat - 136 + 8 * i := by
  have hr := hL.frameRoom
  have h1 : (P.rbp0 - 136#64).toNat = P.rbp0.toNat - 136 :=
    rbp_sub_toNat hL (j := 136) (by norm_num)
  rw [derivedSlot]
  rw [toNat_add_ofNat (by omega), h1]

/-- The core of it: a store that misses the three read-only ranges leaves
every byte `RoMem` names where it was. -/
theorem romem_store {P : Params} {m : Mem} {b : Word} {k : Nat} {v : BitVec (8 * k)}
    (hL : Layout P) (h : RoMem P m) (hk : b.toNat + k ≤ 2 ^ 64)
    (hd1 : RangesDisjoint (P.rbp0 - 136#64) 104 b k)
    (hd2 : RangesDisjoint (P.rbp0 - 8#64) 8 b k)
    (hd3 : RangesDisjoint P.desc 200 b k) :
    RoMem P (store k m b v) := by
  have hr := hL.frameRoom
  have hnw := hL.frameNoWrap
  have hdnw := hL.descNoWrap
  have hfs := hL.frameSlots_toNat
  have h136 : (P.rbp0 - 136#64).toNat = P.rbp0.toNat - 136 :=
    rbp_sub_toNat hL (j := 136) (by norm_num)
  have h8 : (P.rbp0 - 8#64).toNat = P.rbp0.toNat - 8 := rbp_sub_toNat hL (j := 8) (by norm_num)
  simp only [RangesDisjoint, h136, h8] at hd1 hd2 hd3
  -- Every read-only address, once its `toNat` is known, is a one-line `omega`.
  have keep : ∀ x : Word, x.toNat + 8 ≤ 2 ^ 64 →
      (RangesDisjoint x 8 b k) → load64 (store k m b v) x = load64 m x := by
    intro x hx hdx
    exact load64_store_disjoint k m x b v hx hk hdx
  have frame : ∀ x : Word, P.rbp0.toNat - 136 ≤ x.toNat → x.toNat + 8 ≤ P.rbp0.toNat - 32 →
      load64 (store k m b v) x = load64 m x := by
    intro x h1 h2
    exact keep x (by omega) (by simp only [RangesDisjoint]; omega)
  have ptr : load64 (store k m b v) (P.rbp0 - 8#64) = load64 m (P.rbp0 - 8#64) :=
    keep _ (by omega) (by simp only [RangesDisjoint]; omega)
  have dsc : ∀ x : Word, P.desc.toNat ≤ x.toNat → x.toNat + 8 ≤ P.desc.toNat + 200 →
      load64 (store k m b v) x = load64 m x := by
    intro x h1 h2
    exact keep x (by omega) (by simp only [RangesDisjoint]; omega)
  have block : ∀ (kk : Nat), kk + 5 ≤ 11 → ∀ gb gt nb, DerivedBlock P m kk gb gt nb →
      DerivedBlock P (store k m b v) kk gb gt nb := by
    intro kk hkk gb gt nb hb
    have slot : ∀ i, i ≤ 11 → load64 (store k m b v) (derivedSlot P i)
        = load64 m (derivedSlot P i) := by
      intro i hi
      exact frame _ (by rw [derivedSlot_toNat hL hi]; omega)
        (by rw [derivedSlot_toNat hL hi]; omega)
    exact ⟨by rw [slot kk (by omega)]; exact hb.bottom,
      by rw [slot (kk + 1) (by omega)]; exact hb.delta,
      by rw [slot (kk + 2) (by omega)]; exact hb.span1,
      by rw [slot (kk + 3) (by omega)]; exact hb.span2,
      by rw [slot (kk + 4) (by omega)]; exact hb.span4,
      by rw [slot (kk + 5) (by omega)]; exact hb.span8⟩
  have descField : ∀ j : Nat, j ≤ 152 → load64 (store k m b v) (P.desc + BitVec.ofNat 64 j)
      = load64 m (P.desc + BitVec.ofNat 64 j) := by
    intro j hj
    exact dsc _ (by rw [desc_add_toNat hL (by omega)]; omega)
      (by rw [desc_add_toNat hL (by omega)]; omega)
  refine ⟨by rw [ptr]; exact h.descSlot, ?_, block 0 (by norm_num) _ _ _ h.stackDerived,
    block 6 (by norm_num) _ _ _ h.dataDerived,
    by rw [show (0#64 : Word) = BitVec.ofNat 64 0 from rfl, descField 0 (by norm_num)]
       exact h.descStackBottom,
    by rw [show (8#64 : Word) = BitVec.ofNat 64 8 from rfl, descField 8 (by norm_num)]
       exact h.descStackTop,
    by rw [show (16#64 : Word) = BitVec.ofNat 64 16 from rfl, descField 16 (by norm_num)]
       exact h.descStackNative,
    by rw [show (24#64 : Word) = BitVec.ofNat 64 24 from rfl, descField 24 (by norm_num)]
       exact h.descDataBottom,
    by rw [show (32#64 : Word) = BitVec.ofNat 64 32 from rfl, descField 32 (by norm_num)]
       exact h.descDataTop,
    by rw [show (40#64 : Word) = BitVec.ofNat 64 40 from rfl, descField 40 (by norm_num)]
       exact h.descDataNative,
    by rw [show (144#64 : Word) = BitVec.ofNat 64 144 from rfl, descField 144 (by norm_num)]
       exact h.descGuestFloor,
    by rw [show (152#64 : Word) = BitVec.ofNat 64 152 from rfl, descField 152 (by norm_num)]
       exact h.descNativeFloor⟩
  · have h40 : (P.rbp0 - 40#64).toNat = P.rbp0.toNat - 40 :=
      rbp_sub_toNat hL (j := 40) (by norm_num)
    rw [show (40#64 : Word) = BitVec.ofNat 64 40 from rfl] at h40 ⊢
    rw [frame _ (by omega) (by omega)]
    exact h.deltaSlot

/-- A guest access, wherever the address rules put it, keeps the read-only
bytes: it is clear of the frame scratch, which contains all of them but the
descriptor, and clear of the descriptor. -/
theorem romem_store_guest {P : Params} {m : Mem} {b : Word} {k : Nat} {v : BitVec (8 * k)}
    (hL : Layout P) (h : RoMem P m) (g : GuestOk P b k) : RoMem P (store k m b v) := by
  rcases Nat.eq_zero_or_pos k with rfl | hk0
  · rw [store_zero]; exact h
  have hr := hL.frameRoom
  have hfs := hL.frameSlots_toNat
  have hdf : RangesDisjoint (frameSlots P) 160 b k :=
    rangesDisjoint_of_forall hk0 (by norm_num) g.offFrame
  have hdd : RangesDisjoint P.desc 200 b k :=
    rangesDisjoint_of_forall hk0 (by norm_num) g.offDesc
  have h136 : (P.rbp0 - 136#64).toNat = P.rbp0.toNat - 136 :=
    rbp_sub_toNat hL (j := 136) (by norm_num)
  have h8 : (P.rbp0 - 8#64).toNat = P.rbp0.toNat - 8 := rbp_sub_toNat hL (j := 8) (by norm_num)
  simp only [RangesDisjoint] at hdf hdd ⊢
  exact romem_store hL h g.access.1 (by simp only [RangesDisjoint, h136]; omega)
    (by simp only [RangesDisjoint, h8]; omega) (by simp only [RangesDisjoint]; omega)

/-- A store to one of the four writable frame slots. -/
theorem romem_store64_slot {P : Params} {m : Mem} (hL : Layout P) (h : RoMem P m) {j : Nat}
    (hj : j = 16 ∨ j = 24 ∨ j = 32 ∨ j = 144) (v : Word) :
    RoMem P (store64 m (P.rbp0 - BitVec.ofNat 64 j) v) := by
  have hr := hL.frameRoom
  have hfd := hL.frameOffDesc
  have hfs := hL.frameSlots_toNat
  have hb : (P.rbp0 - BitVec.ofNat 64 j).toNat = P.rbp0.toNat - j :=
    rbp_sub_toNat hL (by omega)
  have h136 : (P.rbp0 - 136#64).toNat = P.rbp0.toNat - 136 :=
    rbp_sub_toNat hL (j := 136) (by norm_num)
  have h8 : (P.rbp0 - 8#64).toNat = P.rbp0.toNat - 8 := rbp_sub_toNat hL (j := 8) (by norm_num)
  simp only [RangesDisjoint] at hfd
  refine romem_store hL h (by omega) ?_ ?_ ?_ <;>
    simp only [RangesDisjoint, h136, h8, hb] <;> omega

/-- A store to the native stack: the word at `rsp`, or the one a push writes
below it, at any depth the checker admits. -/
theorem romem_store64_stack {P : Params} {m : Mem} (hL : Layout P) (h : RoMem P m) {d : Nat}
    (hd : d ≤ 16) (v : Word) :
    RoMem P (store64 m (P.rsp0 - BitVec.ofNat 64 (8 * d)) v) := by
  have hsw := hL.stackWindow_toNat
  have hroom := hL.stackRoom
  have hnw := hL.stackWindowNoWrap
  have hfo := hL.frameOffStack
  have hso := hL.stackOffDesc
  have hfs := hL.frameSlots_toNat
  have hr := hL.frameRoom
  simp only [stackWindowLen] at hnw
  simp only [RangesDisjoint, stackWindowLen] at hfo hso
  have hb : (P.rsp0 - BitVec.ofNat 64 (8 * d)).toNat = P.rsp0.toNat - 8 * d :=
    toNat_sub_ofNat (by omega) (by omega)
  have h136 : (P.rbp0 - 136#64).toNat = P.rbp0.toNat - 136 :=
    rbp_sub_toNat hL (j := 136) (by norm_num)
  have h8 : (P.rbp0 - 8#64).toNat = P.rbp0.toNat - 8 := rbp_sub_toNat hL (j := 8) (by norm_num)
  refine romem_store hL h (by omega) ?_ ?_ ?_ <;>
    simp only [RangesDisjoint, h136, h8, hb] <;> omega

/-! ## Reading the extracted checker

`set_tag`, `tag_of`, `write`, `depth_ok`, `frame_intact` and `enter` are what
every per-macro rule is built from. Each of the lemmas below says what one of
them returns, in terms of `tagAt` rather than of the Aeneas `Array`, so that
no macro proof has to look at the array again. -/

theorem array_update_eq {α : Type} {n : Usize} {v : Array α n} {i : Usize} {x : α}
    {v' : Array α n} (h : Array.update v i x = ok v') :
    i.val < v.val.length ∧ v'.val = v.val.set i.val x := by
  unfold Array.update at h
  split at h
  · simp at h
  · rename_i y hy
    simp only [ok.injEq] at h
    subst h
    simp only [Array.getElem?_Usize_eq] at hy
    exact ⟨(List.getElem?_eq_some_iff.mp hy).1, Array.from_val _ _⟩

/-- `set_tag` writes one tag and nothing else. -/
theorem set_tag_eq {a a' : x64_check.State} {r : Std.U8} {t : x64_check.Tag}
    (hr : r.val < 16) (h : x64_check.set_tag a r t = ok a') :
    a'.depth = a.depth ∧ a'.group = a.group ∧ a'.alive = a.alive ∧
      ∀ r', tagAt a' r' = if r' = r.val then t else tagAt a r' := by
  unfold x64_check.set_tag at h
  simp only [lift, bind_tc_ok] at h
  rw [if_pos (by rw [x64_check.NUM_REGS]; scalar_tac)] at h
  cases hu : Array.update a.regs (UScalar.cast UScalarTy.Usize r) t with
  | ok w =>
    rw [hu] at h
    simp only [bind_tc_ok, ok.injEq] at h
    obtain ⟨hlt, hset⟩ := array_update_eq hu
    subst h
    refine ⟨rfl, rfl, rfl, fun r' => ?_⟩
    simp only [tagAt, hset]
    have hi : (UScalar.cast UScalarTy.Usize r).val = r.val := by simp
    rw [hi]
    by_cases hc : r' = r.val
    · subst hc
      rw [if_pos rfl, List.getD_eq_getElem?_getD, List.getElem?_set_self]
      · simp
      · rw [regs_length]; omega
    · rw [if_neg hc, List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD,
        List.getElem?_set_ne (by omega)]
  | fail e => rw [hu] at h; simp at h
  | div => rw [hu] at h; simp at h

/-- `tag_of` reads the tag `tagAt` names, out of range included. -/
theorem tag_of_eq {a : x64_check.State} {r : Std.U8} {t : x64_check.Tag}
    (h : x64_check.tag_of a r = ok t) : t = tagAt a r.val := by
  unfold x64_check.tag_of at h
  simp only [lift, bind_tc_ok] at h
  split at h
  · rename_i hlt
    rw [x64_check.NUM_REGS] at hlt
    have hr : r.val < 16 := by scalar_tac
    unfold Array.index_usize at h
    split at h
    · simp at h
    · rename_i y hy
      simp only [ok.injEq] at h
      subst h
      simp only [Array.getElem?_Usize_eq] at hy
      have hi : (UScalar.cast UScalarTy.Usize r).val = r.val := by simp
      rw [hi] at hy
      simp only [tagAt, List.getD_eq_getElem?_getD, hy, Option.getD_some]
  · rename_i hlt
    rw [x64_check.NUM_REGS] at hlt
    have hr : 16 ≤ r.val := by scalar_tac
    simp only [ok.injEq] at h
    subst h
    have hn : a.regs.val[r.val]? = none := List.getElem?_eq_none (by rw [regs_length]; omega)
    simp only [tagAt, List.getD_eq_getElem?_getD, hn, Option.getD_none]

theorem frame_val : (x64_check.FRAME).val = 15 := by rw [x64_check.FRAME, x64_ir.R15]; rfl

/-- `frame_intact` is `r15` carrying `Fp`. -/
theorem frame_intact_eq {a : x64_check.State} (h : x64_check.frame_intact a = ok true) :
    tagAt a 15 = .Fp := by
  unfold x64_check.frame_intact at h
  cases ht : x64_check.tag_of a x64_check.FRAME with
  | ok t =>
    rw [ht] at h
    have he : t = tagAt a 15 := by have := tag_of_eq ht; rwa [frame_val] at this
    rw [← he]
    cases t with
    | Top => simp at h
    | Fp => rfl
    | Checked w => simp at h
  | fail e => rw [ht] at h; simp at h
  | div => rw [ht] at h; simp at h

/-- `depth_ok` is the bound it says it is, and its addition does not wrap. -/
theorem depth_ok_eq {a : x64_check.State} {n : Std.U32} (h : x64_check.depth_ok a n = ok true) :
    a.depth.val + n.val ≤ 16 := by
  unfold x64_check.depth_ok at h
  cases hi : a.depth + n with
  | ok i =>
    rw [hi] at h
    simp only [bind_tc_ok, ok.injEq, decide_eq_true_eq] at h
    have hv := UScalar.add_equiv a.depth n
    rw [hi] at hv
    rw [x64_check.MAX_DEPTH] at h
    have : i.val ≤ 16 := by scalar_tac
    omega
  | fail e => rw [hi] at h; simp at h
  | div => rw [hi] at h; simp at h

/-- `write` refuses `rsp`, `rbp`, the frame register and anything out of
range, and turns its destination into `Top`. This is what makes the frame
register's `Fp` tag, and so the frame fast path, survive every macro. -/
theorem write_ok {a a' : x64_check.State} {r : Std.U8} {index : Usize} {pc : Std.U32}
    (h : x64_check.write a r index pc = ok (.Ok (), a')) :
    r.val ≠ 4 ∧ r.val ≠ 5 ∧ r.val ≠ 15 ∧ r.val < 16 ∧
      a'.depth = a.depth ∧ a'.group = a.group ∧ a'.alive = a.alive ∧
      ∀ r', tagAt a' r' = if r' = r.val then .Top else tagAt a r' := by
  unfold x64_check.write at h
  rw [x64_ir.RSP, x64_ir.RBP, x64_check.FRAME, x64_ir.R15, x64_check.NUM_REGS] at h
  split at h
  · simp only [x64_check.reject, bind_tc_ok] at h; simp at h
  · rename_i h4
    split at h
    · simp only [x64_check.reject, bind_tc_ok] at h; simp at h
    · rename_i h5
      split at h
      · simp only [x64_check.reject, bind_tc_ok] at h; simp at h
      · rename_i h15
        simp only [lift, bind_tc_ok] at h
        split at h
        · simp only [x64_check.reject, bind_tc_ok] at h; simp at h
        · rename_i hge
          have hr : r.val < 16 := by scalar_tac
          have hn4 : r.val ≠ 4 := by intro hc; exact h4 (by scalar_tac)
          have hn5 : r.val ≠ 5 := by intro hc; exact h5 (by scalar_tac)
          have hn15 : r.val ≠ 15 := by intro hc; exact h15 (by scalar_tac)
          cases hs : x64_check.set_tag a r x64_check.Tag.Top with
          | ok b =>
            rw [hs] at h
            simp only [bind_tc_ok, ok.injEq, Prod.mk.injEq] at h
            obtain ⟨-, rfl⟩ := h
            obtain ⟨h1, h2, h3, h4'⟩ := set_tag_eq hr hs
            exact ⟨hn4, hn5, hn15, hr, h1, h2, h3, h4'⟩
          | fail e => rw [hs] at h; simp at h
          | div => rw [hs] at h; simp at h

/-! ## The entry state and the state at a branch target -/

/-- The abstract state `x64_check::enter` produces, which is the state at a
function entry and at every slot a branch can land on: one native stack slot
pushed, the frame register intact, nothing else known. It does not depend on
the state it is reached from, which is exactly why a branch target may be
entered from anywhere. -/
def enterState : x64_check.State :=
  { regs := (Array.repeat 16#usize x64_check.Tag.Top).set 15#usize x64_check.Tag.Fp,
    depth := 1#u32, group := x64_check.Tag.Top, alive := true }

@[simp] theorem tagAt_enterState (i : Nat) :
    tagAt enterState i = if i = 15 then x64_check.Tag.Fp else x64_check.Tag.Top := by
  simp only [tagAt, enterState, Array.set_val_eq, Array.repeat_val, List.getD_eq_getElem?_getD]
  by_cases h : i = 15
  · subst h; simp
  · rw [List.getElem?_set_ne (by simpa using h)]
    by_cases h2 : i < 16
    · rw [List.getElem?_replicate]
      simp [h, h2]
    · rw [List.getElem?_eq_none (by simp; omega)]
      simp [h]

theorem enter_loop_eq {a : x64_check.State} :
    ∀ (x : x64_check.State × Usize) (b : x64_check.State),
      (x.2.val ≤ 16 ∧ x.1.depth = a.depth ∧ x.1.group = a.group ∧ x.1.alive = a.alive ∧
        ∀ i, i < x.2.val → tagAt x.1 i = x64_check.Tag.Top ∧ True) →
      x64_check.enter_loop x.1 x.2 = ok b →
      b.depth = a.depth ∧ b.group = a.group ∧ b.alive = a.alive ∧
        ∀ i, i < 16 → tagAt b i = x64_check.Tag.Top := by
  have key := loop_ok_induction (fun (st : x64_check.State × Usize) =>
      x64_check.enter_loop.body st.1 st.2)
    (fun (st : x64_check.State × Usize) =>
      st.2.val ≤ 16 ∧ st.1.depth = a.depth ∧ st.1.group = a.group ∧ st.1.alive = a.alive ∧
        ∀ i, i < st.2.val → tagAt st.1 i = x64_check.Tag.Top)
    (fun b : x64_check.State =>
      b.depth = a.depth ∧ b.group = a.group ∧ b.alive = a.alive ∧
        ∀ i, i < 16 → tagAt b i = x64_check.Tag.Top) ?_
  · intro x b hx h
    refine key x b ⟨hx.1, hx.2.1, hx.2.2.1, hx.2.2.2.1, fun i hi => (hx.2.2.2.2 i hi).1⟩ ?_
    unfold x64_check.enter_loop at h
    exact h
  · rintro ⟨st, r⟩ hx res hbody
    obtain ⟨hr16, hd, hg, hal, htop⟩ := hx
    replace hr16 : r.val ≤ 16 := hr16
    replace hd : st.depth = a.depth := hd
    replace hg : st.group = a.group := hg
    replace hal : st.alive = a.alive := hal
    replace htop : ∀ i, i < r.val → tagAt st i = x64_check.Tag.Top := htop
    unfold x64_check.enter_loop.body at hbody
    simp only at hbody
    split at hbody
    · rename_i hlt
      rw [x64_check.NUM_REGS] at hlt
      have hrlt : r.val < 16 := by scalar_tac
      simp only [lift, bind_tc_ok] at hbody
      cases hs : x64_check.set_tag st (UScalar.cast UScalarTy.U8 r) x64_check.Tag.Top with
      | ok st1 =>
        rw [hs] at hbody
        simp only [bind_tc_ok] at hbody
        cases hadd : r + 1#usize with
        | ok r1 =>
          rw [hadd] at hbody
          simp only [bind_tc_ok, ok.injEq] at hbody
          subst hbody
          show r1.val ≤ 16 ∧ st1.depth = a.depth ∧ st1.group = a.group ∧ st1.alive = a.alive ∧
            ∀ i, i < r1.val → tagAt st1 i = x64_check.Tag.Top
          have hcast : (UScalar.cast UScalarTy.U8 r).val = r.val := by
            simp only [UScalar.cast_val_eq]
            simp [UScalarTy.numBits]
            omega
          obtain ⟨h1, h2, h3, h4⟩ := set_tag_eq (by rw [hcast]; omega) hs
          have hv := UScalar.add_equiv r 1#usize
          rw [hadd] at hv
          have hr1 : r1.val = r.val + 1 := by scalar_tac
          refine ⟨by omega, by rw [h1, hd], by rw [h2, hg], by rw [h3, hal], fun i hi => ?_⟩
          rw [h4 i, hcast]
          by_cases hc : i = r.val
          · rw [if_pos hc]
          · rw [if_neg hc]; exact htop i (by omega)
        | fail e => rw [hadd] at hbody; simp at hbody
        | div => rw [hadd] at hbody; simp at hbody
      | fail e => rw [hs] at hbody; simp at hbody
      | div => rw [hs] at hbody; simp at hbody
    · rename_i hlt
      rw [x64_check.NUM_REGS] at hlt
      have : 16 ≤ r.val := by scalar_tac
      simp only [ok.injEq] at hbody
      subst hbody
      show st.depth = a.depth ∧ st.group = a.group ∧ st.alive = a.alive ∧
        ∀ i, i < 16 → tagAt st i = x64_check.Tag.Top
      exact ⟨hd, hg, hal, fun i hi => htop i (by omega)⟩

/-- Whatever it is reached from, `enter` returns `enterState`. -/
theorem enter_eq {a a' : x64_check.State} (h : x64_check.enter a = ok a') : a' = enterState := by
  have getEq : ∀ (st : x64_check.State) (j : Nat) (hj : j < st.regs.val.length),
      st.regs.val[j] = tagAt st j := by
    intro st j hj
    simp only [tagAt, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hj, Option.getD_some]
  unfold x64_check.enter at h
  cases hl : x64_check.enter_loop a 0#usize with
  | ok b =>
    rw [hl] at h
    simp only [bind_tc_ok] at h
    obtain ⟨-, -, -, htop⟩ := enter_loop_eq (a := a) (a, 0#usize) b
      ⟨by simp, rfl, rfl, rfl, by intro i hi; simp at hi⟩ hl
    cases hs : x64_check.set_tag b x64_check.FRAME x64_check.Tag.Fp with
    | ok c =>
      rw [hs] at h
      simp only [bind_tc_ok, ok.injEq] at h
      subst h
      obtain ⟨-, -, -, h4⟩ := set_tag_eq (r := x64_check.FRAME)
        (by rw [frame_val]; omega) hs
      have hc : ∀ i, i < 16 →
          tagAt c i = if i = 15 then x64_check.Tag.Fp else x64_check.Tag.Top := by
        intro i hi
        rw [h4 i, frame_val]
        by_cases h15 : i = 15
        · rw [if_pos h15, if_pos h15]
        · rw [if_neg h15, if_neg h15]; exact htop i hi
      have hregs : c.regs
          = (Array.repeat 16#usize x64_check.Tag.Top).set 15#usize x64_check.Tag.Fp := by
        refine (Array.eq_iff _ _).mpr (List.ext_getElem ?_ ?_)
        · rw [regs_length]; simp
        · intro i h1 h2
          have hi : i < 16 := by rw [regs_length] at h1; exact h1
          have e2 : tagAt enterState i = enterState.regs.val[i] := (getEq enterState i h2).symm
          rw [getEq c i h1, hc i hi, ← tagAt_enterState i, e2]
          rfl
      simp only [enterState]
      rw [hregs]
    | fail e => rw [hs] at h; simp at h
    | div => rw [hs] at h; simp at h
  | fail e => rw [hl] at h; simp at h
  | div => rw [hl] at h; simp at h

/-- And `entry_state` is the state before the prologue: depth zero, the frame
register intact, nothing else known. -/
theorem entry_state_eq {st : x64_check.State} (h : x64_check.entry_state = ok st) :
    st.depth.val = 0 ∧ st.group = x64_check.Tag.Top ∧ st.alive = true ∧
      ∀ i, tagAt st i = if i = 15 then x64_check.Tag.Fp else x64_check.Tag.Top := by
  unfold x64_check.entry_state at h
  obtain ⟨h1, h2, h3, h4⟩ := set_tag_eq (r := x64_check.FRAME)
    (by rw [x64_check.FRAME, x64_ir.R15]; scalar_tac) h
  have hval : (x64_check.FRAME).val = 15 := by rw [x64_check.FRAME, x64_ir.R15]; rfl
  refine ⟨by rw [h1]; rfl, by rw [h2], by rw [h3], fun i => ?_⟩
  rw [h4 i, hval]
  by_cases hc : i = 15
  · rw [if_pos hc, if_pos hc]
  · rw [if_neg hc, if_neg hc]
    simp only [tagAt, Array.repeat_val, List.getD_eq_getElem?_getD]
    by_cases h2 : i < 16
    · rw [List.getElem?_replicate]; simp [h2]
    · rw [List.getElem?_eq_none (by simp; omega)]; simp

/-! ## Moving the agreement along -/

/-- Flags and the program counter are not in the relation. -/
theorem agree_flags {P : Params} {a : x64_check.State} {s : State} (h : Agree P a s)
    (f : Flags) (p : Nat) : Agree P a { s with flags := f, pc := p } :=
  ⟨h.regs, h.rsp, h.depth, h.rbp, h.ro, h.group⟩

/-- A register write the checker admitted. The destination becomes `Top`,
which admits the new value whatever it is; every other register, `rsp`, `rbp`
and the frame register among them, is untouched. -/
theorem agree_wReg {P : Params} {a a' : x64_check.State} {s : State} {r : Std.U8}
    {index : Usize} {pc : Std.U32} (h : Agree P a s)
    (hw : x64_check.write a r index pc = ok (.Ok (), a')) (v : Word) (f : Flags) (p : Nat) :
    Agree P a' { s with regs := Function.update s.regs r.val v, flags := f, pc := p } := by
  obtain ⟨hn4, hn5, hn15, hlt, hd, hg, -, ht⟩ := write_ok hw
  refine ⟨fun r' hr' => ?_, ?_, ?_, ?_, h.ro, ?_⟩
  · rw [ht r']
    by_cases hc : r' = r.val
    · rw [if_pos hc]; trivial
    · rw [if_neg hc]
      simpa [Function.update_of_ne hc] using h.regs r' hr'
  · show Function.update s.regs r.val v RSP = _
    rw [Function.update_of_ne (by simpa [RSP] using Ne.symm hn4), hd]
    exact h.rsp
  · rw [hd]; exact h.depth
  · show Function.update s.regs r.val v RBP = _
    rw [Function.update_of_ne (by simpa [RBP] using Ne.symm hn5)]
    exact h.rbp
  · rw [hg]; exact h.group

/-- A memory write that kept the read-only bytes and left the parked group
base holding something its tag admits. -/
theorem agree_mem {P : Params} {a : x64_check.State} {s : State} (h : Agree P a s)
    {m : Mem} (f : Flags) (p : Nat) (hro : RoMem P m)
    (hgrp : TagOk P a.group (load64 m (P.rbp0 - 144#64))) :
    Agree P a { s with mem := m, flags := f, pc := p } :=
  ⟨h.regs, h.rsp, h.depth, h.rbp, hro, hgrp⟩

/-- Parking a new group base. -/
theorem agree_group {P : Params} {a : x64_check.State} {s : State} {t : x64_check.Tag}
    (h : Agree P a s) (ht : TagOk P t (load64 s.mem (P.rbp0 - 144#64))) :
    Agree P { a with group := t } s :=
  ⟨h.regs, h.rsp, h.depth, h.rbp, h.ro, ht⟩

/-- Arriving at a branch target, or at a prologue: depth one and the frame
register intact are exactly what `enterState` claims. -/
theorem agree_enter {P : Params} {a a' : x64_check.State} {s : State} (h : Agree P a s)
    (hrsp : s.regs RSP = P.rsp0 - 8#64) (hfp : s.regs R15 = P.fp0)
    (he : x64_check.enter a = ok a') : Agree P a' s := by
  rw [enter_eq he]
  refine ⟨fun r hr => ?_, ?_, by simp [enterState], h.rbp, h.ro, by simp [enterState]⟩
  · rw [tagAt_enterState]
    by_cases hc : r = 15
    · subst hc; simpa using hfp
    · rw [if_neg hc]; trivial
  · rw [hrsp]
    norm_num [enterState]

/-- The entry contract gives the agreement `check` starts from. -/
theorem agree_of_entry {P : Params} {s : State} {st : x64_check.State} (h : Entry P s)
    (he : x64_check.entry_state = ok st) : Agree P st s := by
  obtain ⟨hd, hg, -, ht⟩ := entry_state_eq he
  refine ⟨fun r hr => ?_, ?_, by omega, h.rbp, h.ro, ?_⟩
  · rw [ht r]
    by_cases hc : r = 15
    · subst hc; simpa using h.fp
    · rw [if_neg hc]; trivial
  · rw [hd, h.rsp]; norm_num
  · rw [hg]; trivial

/-! ## Moving the agreement along, in the form the macro proofs use

`agree_flags`, `agree_wReg` and `agree_mem` above name the state they land in;
the three below take the same steps but describe the new state by what it kept,
which is what the step-shape lemmas of `AsyncEbpf/X64/Run.lean` hand out. -/

/-- Nothing in the relation moved. -/
theorem agree_same {P : Params} {a : x64_check.State} {s s' : State} (h : Agree P a s)
    (hregs : ∀ r, s'.regs r = s.regs r) (hmem : s'.mem = s.mem) : Agree P a s' := by
  refine ⟨fun r hr => ?_, ?_, h.depth, ?_, ?_, ?_⟩
  · rw [hregs r]; exact h.regs r hr
  · rw [hregs]; exact h.rsp
  · rw [hregs]; exact h.rbp
  · rw [hmem]; exact h.ro
  · rw [hmem]; exact h.group

/-- A register write the checker admitted, described by what it left alone. -/
theorem agree_write {P : Params} {a a' : x64_check.State} {s s' : State} {r : Std.U8}
    {index : Usize} {pc : Std.U32} (h : Agree P a s)
    (hw : x64_check.write a r index pc = ok (.Ok (), a'))
    (hregs : ∀ r', r' ≠ r.val → s'.regs r' = s.regs r') (hmem : s'.mem = s.mem) :
    Agree P a' s' := by
  obtain ⟨hn4, hn5, hn15, hlt, hd, hg, -, ht⟩ := write_ok hw
  refine ⟨fun r' hr' => ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [ht r']
    by_cases hc : r' = r.val
    · rw [if_pos hc]; trivial
    · rw [if_neg hc, hregs r' hc]; exact h.regs r' hr'
  · rw [hregs RSP (by simpa [RSP] using Ne.symm hn4), hd]; exact h.rsp
  · rw [hd]; exact h.depth
  · rw [hregs RBP (by simpa [RBP] using Ne.symm hn5)]; exact h.rbp
  · rw [hmem]; exact h.ro
  · rw [hg, hmem]; exact h.group

/-- Writing a register that is already `Top`, which is what the second and
later primitives of one macro's expansion do to its destination. -/
theorem agree_write_top {P : Params} {a : x64_check.State} {s s' : State} {r : Nat}
    (h : Agree P a s) (htop : tagAt a r = x64_check.Tag.Top) (hn4 : r ≠ RSP) (hn5 : r ≠ RBP)
    (hregs : ∀ r', r' ≠ r → s'.regs r' = s.regs r') (hmem : s'.mem = s.mem) : Agree P a s' := by
  refine ⟨fun r' hr' => ?_, ?_, h.depth, ?_, ?_, ?_⟩
  · by_cases hc : r' = r
    · subst hc; rw [htop]; trivial
    · rw [hregs r' hc]; exact h.regs r' hr'
  · rw [hregs RSP (Ne.symm hn4)]; exact h.rsp
  · rw [hregs RBP (Ne.symm hn5)]; exact h.rbp
  · rw [hmem]; exact h.ro
  · rw [hmem]; exact h.group

/-- A memory write, described by what it left alone. -/
theorem agree_store {P : Params} {a : x64_check.State} {s s' : State} (h : Agree P a s)
    (hregs : ∀ r, s'.regs r = s.regs r) (hro : RoMem P s'.mem)
    (hgrp : TagOk P a.group (load64 s'.mem (P.rbp0 - 144#64))) : Agree P a s' := by
  refine ⟨fun r hr => ?_, ?_, h.depth, ?_, hro, hgrp⟩
  · rw [hregs r]; exact h.regs r hr
  · rw [hregs]; exact h.rsp
  · rw [hregs]; exact h.rbp

/-! ## The one fact about widths that is not local

`Checked w` is produced only by `CheckedAddr`, which refuses a `size` above
`x64_ir::MAX_GROUP_SPAN`. The address rules need that bound — it is what makes
the first page wide enough to catch a parked zero — but it is a property of
the walk rather than of one macro, so a macro lemma takes it as a hypothesis
and the glue carries it. -/

/-- Every checked width the abstract state carries fits in a page. -/
def WidthsOk (a : x64_check.State) : Prop :=
  (∀ r w, tagAt a r = x64_check.Tag.Checked w → w.val ≤ 4096) ∧
    (∀ w, a.group = x64_check.Tag.Checked w → w.val ≤ 4096)

/-- A tag other than `Top` names a register the state really has. -/
theorem tagAt_range {a : x64_check.State} {r : Nat} (h : tagAt a r ≠ x64_check.Tag.Top) :
    r < 16 := by
  by_contra hc
  refine h ?_
  have hn : a.regs.val[r]? = none := List.getElem?_eq_none (by rw [regs_length]; omega)
  simp only [tagAt, List.getD_eq_getElem?_getD, hn, Option.getD_none]

/-- The one thing the machine's parameters and the checker's configuration
have to agree on: the frame window the fast path admits is the frame window
the entry contract mapped. -/
def CfgOk (P : Params) (cfg : x64_ir.Cfg) : Prop := cfg.stack_frame_size.val = P.frameSize

/-- A guest access misses the parked group base, which lives in the frame
scratch. -/
theorem groupBase_kept {P : Params} {m : Mem} {b : Word} {k : Nat} {v : BitVec (8 * k)}
    (hL : Layout P) (g : GuestOk P b k) :
    load64 (store k m b v) (P.rbp0 - 144#64) = load64 m (P.rbp0 - 144#64) := by
  rcases Nat.eq_zero_or_pos k with rfl | hk0
  · rw [store_zero]
  have hr := hL.frameRoom
  have hfs := hL.frameSlots_toNat
  have hnw := hL.frameNoWrap
  have hdf : RangesDisjoint (frameSlots P) 160 b k :=
    rangesDisjoint_of_forall hk0 (by norm_num) g.offFrame
  have h144 : (P.rbp0 - 144#64).toNat = P.rbp0.toNat - 144 :=
    rbp_sub_toNat hL (j := 144) (by norm_num)
  simp only [RangesDisjoint] at hdf
  exact load64_store_disjoint k m _ b v (by omega) g.access.1
    (by simp only [RangesDisjoint, h144]; omega)

/-- A register write together with a memory write: the shape an `xchg` or a
`cmpxchg` takes. -/
theorem agree_write_store {P : Params} {a a' : x64_check.State} {s s' : State} {r : Std.U8}
    {index : Usize} {pc : Std.U32} (h : Agree P a s)
    (hw : x64_check.write a r index pc = ok (.Ok (), a'))
    (hregs : ∀ r', r' ≠ r.val → s'.regs r' = s.regs r') (hro : RoMem P s'.mem)
    (hgrp : TagOk P a'.group (load64 s'.mem (P.rbp0 - 144#64))) : Agree P a' s' := by
  obtain ⟨hn4, hn5, hn15, hlt, hd, hg, -, ht⟩ := write_ok hw
  refine ⟨fun r' hr' => ?_, ?_, ?_, ?_, hro, hgrp⟩
  · rw [ht r']
    by_cases hc : r' = r.val
    · rw [if_pos hc]; trivial
    · rw [if_neg hc, hregs r' hc]; exact h.regs r' hr'
  · rw [hregs RSP (by simpa [RSP] using Ne.symm hn4), hd]; exact h.rsp
  · rw [hd]; exact h.depth
  · rw [hregs RBP (by simpa [RBP] using Ne.symm hn5)]; exact h.rbp

/-- A tag out of range reads as `Top`, so every register number agrees. -/
theorem agree_regs_any {P : Params} {a : x64_check.State} {s : State} (h : Agree P a s)
    (r : Nat) : TagOk P (tagAt a r) (s.regs r) := by
  by_cases hr : r < 16
  · exact h.regs r hr
  · have hn : a.regs.val[r]? = none := List.getElem?_eq_none (by rw [regs_length]; omega)
    have : tagAt a r = x64_check.Tag.Top := by
      simp only [tagAt, List.getD_eq_getElem?_getD, hn, Option.getD_none]
    rw [this]; trivial

/-- Arriving in the state every branch target is entered in, without going
through `enter`: this is what a jump exit hands the macro at its target. -/
theorem agree_enterState {P : Params} {s : State} (hrsp : s.regs RSP = P.rsp0 - 8#64)
    (hfp : s.regs R15 = P.fp0) (hrbp : s.regs RBP = P.rbp0) (hro : RoMem P s.mem) :
    Agree P enterState s := by
  refine ⟨fun r hr => ?_, ?_, by simp [enterState], hrbp, hro, by simp [enterState]⟩
  · rw [tagAt_enterState]
    by_cases hc : r = 15
    · subst hc; simpa using hfp
    · rw [if_neg hc]; trivial
  · rw [hrsp]; norm_num [enterState]

/-- A negative 32-bit displacement from `rbp` names the frame slot the
`x64_ir::frame` offsets name. -/
theorem signExtend_neg {d : Std.I32} {k : Nat} (hk : 0 < k) (hkb : k < 2 ^ 31)
    (h : d.val = -(k : Int)) : (BitVec.signExtend 64 d.bv : Word) = - BitVec.ofNat 64 k := by
  have hyi : (BitVec.signExtend 64 d.bv : Word).toInt = -(k : Int) := by
    rw [toInt_signExtend]; exact h
  have hcond := BitVec.toInt_eq_toNat_cond (BitVec.signExtend 64 d.bv : Word)
  have hylt := (BitVec.signExtend 64 d.bv : Word).isLt
  rw [hyi] at hcond
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_neg, BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]
  rw [Nat.mod_eq_of_lt (by omega)]
  split at hcond <;> omega

/-- So the two spellings of a frame slot agree. -/
theorem rbp_slot {P : Params} {disp : Std.I32} {k : Nat} (hk : 0 < k) (hkb : k < 2 ^ 31)
    (h : disp.val = -(k : Int)) :
    P.rbp0 + BitVec.signExtend 64 disp.bv = P.rbp0 - BitVec.ofNat 64 k := by
  rw [signExtend_neg hk hkb h]; ring

/-- At depth one, `rsp` is one word below its entry value. -/
theorem agree_depth_one {P : Params} {a : x64_check.State} {s : State} (h : Agree P a s)
    (hd : a.depth.val = 1) : s.regs RSP = P.rsp0 - 8#64 := by
  rw [h.rsp, hd]

/-- And with the frame register intact it still holds the native frame base. -/
theorem agree_fp {P : Params} {a : x64_check.State} {s : State} (h : Agree P a s)
    (hf : tagAt a 15 = x64_check.Tag.Fp) : s.regs R15 = P.fp0 := by
  have := h.regs 15 (by norm_num)
  rw [hf] at this
  exact this

end X64

end async_ebpf_verified

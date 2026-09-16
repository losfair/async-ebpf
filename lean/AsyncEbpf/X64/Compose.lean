import AsyncEbpf.X64.Soundness

/-!
# One activation calls the next

`AsyncEbpf/X64/Soundness.lean` is about a single activation: from a state
satisfying `Entry`, the expansion of a checked macro list is safe, writes only
what it may, returns under the contract, and keeps its stack pointer in the
native stack window. Where it calls *out* of the list — the retpoline to the
dispatcher, and the three `CallReg`s of `MInsn::LazyLocalCall` — the model
answers with `ExternalReturn`, which is an *assumption* about the callee.

This file discharges that assumption for the one callee that is another
instance of the theorem: a lazily compiled local function. `callee_externalReturn`
says that a callee which satisfies this development's own conclusion —
`Contract` and the stack window — delivers exactly `ExternalReturn` to its
caller, and `checked_callee_externalReturn` reads that off `check_safe` for a
callee whose macro list the checker accepted.

## What has to be shown

`CalleeOf P P'` is how the two activations' parameters relate. The lazy call
descends one frame stride and hands the callee the same machine: the same
descriptor, the same two guest regions and their backings, the same floors,
frame size and stride, the same native stack mapping and the same frame
pointer, with the frame register one stride lower and the callee's entry `rsp`
wherever the twelve spills and the pushed return address left it. The two
comparisons the lazy-call sequence performs before it descends — `r15 - stride`
against the guest floor at `[desc + 144]`, `rsp` against the native floor at
`[desc + 152]` — are the two arithmetic clauses `guestRoom` and `nativeRoom`.

From that, `layout_callee` derives `Layout P'`: the guest floor check is what
puts the callee's frame window inside the stack's backing, and the native
floor check together with `Layout.floorNative` is what puts the callee's whole
native stack window inside `[stackLo, stackHi)` — and so clear of the
descriptor, the two backings and the first page, which the caller's layout
already keeps that mapping clear of.

The memory clauses of `ExternalReturn` come from `mem_kept`, which is
`romem_kept`'s argument run over an arbitrary address rather than over the
read-only bytes: an address the callee may not write, at or above the callee's
current stack pointer, is the same at the end as at the start. The threshold
moving with `rsp` is what makes it go through — a nested callee is allowed
everything below *its* return address, which is exactly the threshold of the
state the nested call returns in — and the window's lower half is what
disposes of a primitive that lowers `rsp` without writing anything.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-! ## What a step may leave changed -/

/-- A store all of whose bytes may be written leaves an address that may not
be written alone. This is `romem_store_ok`'s inner step, stated about one
address rather than about the read-only block. -/
theorem store_off_writable {P : Params} {m : Mem} {b : Word} {k : Nat}
    (hok : StoreOk P b k) (v : BitVec (8 * k)) {a : Word} (hw : ¬ WritableAllowed P a) :
    store k m b v a = m a := by
  simp only [store]
  refine if_neg (fun hd => ?_)
  have hsum : a.toNat = (b.toNat + (a - b).toNat) % 2 ^ 64 := by
    conv_lhs => rw [show a = b + (a - b) by ring]
    rw [BitVec.toNat_add]
  have hin : InRange b k a := by
    refine ⟨?_, ?_⟩ <;>
      · rw [hsum, Nat.mod_eq_of_lt (by have := hok.1; omega)]
        omega
  exact hw (hok.2 a hin)

/-- And a callee outside the list leaves alone an address that may not be
written, provided it is above the callee's own return address or in the
descriptor: the four other clauses of `WritableAllowed` are exactly the four
exceptions `ExternalReturn.frameKept` makes. -/
theorem externalReturn_off_writable {P : Params} {code : List x64_ir.PInsn} {t u : State}
    (h : ExternalReturn P code t u) {a : Word} (hw : ¬ WritableAllowed P a)
    (hge : (t.regs RSP).toNat + 8 ≤ a.toNat ∨ InRange P.desc 200 a) : u.mem a = t.mem a := by
  rcases hge with hge | hd
  · exact h.frameKept a hge (fun hc => hw (Or.inr (Or.inl hc)))
      (fun hc => hw (Or.inr (Or.inr (Or.inl hc))))
      (fun hc => hw (Or.inr (Or.inr (Or.inr (Or.inl hc)))))
      (fun hc => hw (Or.inr (Or.inr (Or.inr (Or.inr hc)))))
  · exact h.descKept a hd.1 hd.2

/-- One step leaves alone an address it may not write, at or above the stack
pointer the step *ends* with.

The threshold is the one of the state after the step, not before it, and that
is what makes the two calls work: a `call reg` ends one word above where the
callee's `ExternalReturn` starts promising, and a `ret` to an external address
ends two words above the `ret`'s own `rsp`, which is again exactly where that
callee's promise starts. -/
theorem mem_step {P : Params} {code : List x64_ir.PInsn} {t u : State} (hL : Layout P)
    (hst : ∀ i, code[t.pc]? = some i → ∀ bn ∈ stores i t, StoreOk P bn.1 bn.2)
    (hlo : 8 ≤ (t.regs RSP).toNat) (hhi : (t.regs RSP).toNat ≤ P.rsp0.toNat)
    (h : Step P code t (.next u)) {a : Word} (hw : ¬ WritableAllowed P a)
    (hge : (u.regs RSP).toNat ≤ a.toNat ∨ InRange P.desc 200 a) :
    u.mem a = t.mem a := by
  have hrb := hL.frameRoom
  have hbf := hL.stackBelowFrame
  have hfsN := hL.frameSlots_toNat
  have hlt := P.rbp0.isLt
  have hpush : ((t.regs RSP) - 8#64).toNat = (t.regs RSP).toNat - 8 := by
    rw [show (8#64 : Word) = BitVec.ofNat 64 8 from rfl]
    exact toNat_sub_ofNat (by omega) (by norm_num)
  have hpop : ((t.regs RSP) + 8#64).toNat = (t.regs RSP).toNat + 8 := by
    rw [show (8#64 : Word) = BitVec.ofNat 64 8 from rfl]
    exact toNat_add_ofNat (by omega)
  have hpop2 : ((t.regs RSP) + 8#64 + 8#64).toNat = (t.regs RSP).toNat + 16 := by
    rw [show (8#64 : Word) = BitVec.ofNat 64 8 from rfl] at hpop ⊢
    have h2 := toNat_add_ofNat (x := (t.regs RSP) + BitVec.ofNat 64 8) (k := 8) (by omega)
    omega
  cases h with
  | pcLabel _ hc => rfl
  | localLabel _ hc => rfl
  | exitLabel hc => rfl
  | retpolineLabel hc => rfl
  | pause hc => rfl
  | push r hc =>
    have hok : StoreOk P (t.regs RSP - 8#64) 8 := (hst _ hc) (t.regs RSP - 8#64, 8) (by simp)
    exact store_off_writable hok _ hw
  | pop _ hc => rfl
  | alu w64 op src dst hc => simp only [aluRRStep_mem]
  | aluImm w64 op dst imm hc => simp only [aluImmStep_mem]
  | shiftImm => rfl
  | shiftCl => rfl
  | neg => rfl
  | mulDivRcx => rfl
  | movsx => rfl
  | bswap => rfl
  | rol16 => rfl
  | cmovTaken => rfl
  | cmovNotTaken => rfl
  | loadImm => rfl
  | pushfq hc =>
    have hok : StoreOk P (t.regs RSP - 8#64) 8 := (hst _ hc) (t.regs RSP - 8#64, 8) (by simp)
    exact store_off_writable hok _ hw
  | popfq => rfl
  | cqo => rfl
  | cdq => rfl
  | cmpRcxMinusOne => rfl
  | cmpEaxImm => rfl
  | load => rfl
  | loadNop => rfl
  | store size src base disp hc =>
    have hok : StoreOk P (addr t base disp) size.val :=
      (hst _ hc) (addr t base disp, size.val) (by simp)
    exact store_off_writable hok _ hw
  | storeImm size base disp imm hc =>
    have hok : StoreOk P (addr t base disp) size.val :=
      (hst _ hc) (addr t base disp, size.val) (by simp)
    exact store_off_writable hok _ hw
  | aluRM op reg base disp hc =>
    have he : (aluRMStep op reg base disp t).mem = t.mem := by
      cases op <;> simp [aluRMStep, wRegFlags, wFlags]
    rw [he]
  | storeRspImm imm hc =>
    have hok : StoreOk P (t.regs RSP) 8 := (hst _ hc) (t.regs RSP, 8) (by simp)
    exact store_off_writable hok _ hw
  | storeRspRax hc =>
    have hok : StoreOk P (t.regs RSP) 8 := (hst _ hc) (t.regs RSP, 8) (by simp)
    exact store_off_writable hok _ hw
  | lockAlu op w64 src base disp f hc =>
    have hok : StoreOk P (addr t base disp) (opWidth w64) :=
      (hst _ hc) (addr t base disp, opWidth w64) (by simp)
    simp only [lockAluStep]
    exact store_off_writable hok _ hw
  | lockCmpxchg w64 src base disp f hc =>
    have hok : StoreOk P (addr t base disp) (opWidth w64) :=
      (hst _ hc) (addr t base disp, opWidth w64) (by simp)
    simp only [cmpxchgStep]
    split
    · exact store_off_writable hok _ hw
    · rfl
  | xchg w64 src base disp hc =>
    have hok : StoreOk P (addr t base disp) (opWidth w64) :=
      (hst _ hc) (addr t base disp, opWidth w64) (by simp)
    simp only [xchgStep]
    exact store_off_writable hok _ hw
  | jccTaken => rfl
  | jccNotTaken => rfl
  | jmp => rfl
  | jmpNear => rfl
  | jcc8Taken => rfl
  | jcc8NotTaken => rfl
  | jmp8 => rfl
  | call tgt j hc hp =>
    have hok : StoreOk P (t.regs RSP - 8#64) 8 := (hst _ hc) (t.regs RSP - 8#64, 8) (by simp)
    exact store_off_writable hok _ hw
  | retLocal => rfl
  | retExternal _ hc hne hno hext =>
    -- the external callee promises everything above its own return address,
    -- which sits one word above the `ret`'s `rsp`; the state it comes back in
    -- is another word above that, and that is the threshold in `hge`
    refine externalReturn_off_writable hext hw ?_
    rcases hge with hge | hd
    · refine Or.inl ?_
      rw [popRsp_rsp, hpop]
      have hv : (u.regs RSP).toNat = (t.regs RSP).toNat + 16 := by
        rw [hext.stackPopped, popRsp_rsp, hpop2]
      omega
    · exact Or.inr hd
  | callReg _ r hc hext =>
    have hok : StoreOk P (t.regs RSP - 8#64) 8 := (hst _ hc) (t.regs RSP - 8#64, 8) (by simp)
    have hmid : u.mem a = (push t (retAddr P t)).mem a := by
      refine externalReturn_off_writable hext hw ?_
      rcases hge with hge | hd
      · refine Or.inl ?_
        rw [push_rsp, hpush]
        have hv : (u.regs RSP).toNat = (t.regs RSP).toNat := by
          rw [hext.stackPopped, push_rsp]
          have he : (t.regs RSP - 8#64 + 8#64) = t.regs RSP := by ring
          rw [he]
        omega
      · exact Or.inr hd
    rw [hmid, push_mem]
    exact store_off_writable hok _ hw
  | ripLoadDispatcher => rfl
  | ripLeaHelperTable => rfl

/-- An address the activation may not write, at or above the stack pointer the
execution has reached — or inside the descriptor — still holds what it held at
entry.

The induction carries the threshold with `rsp`. A step that lowers `rsp`
widens the claim, and everything it widens it by lies in the native stack
window below the entry `rsp`, which the activation *may* write — so that case
cannot arise for an address it may not. -/
theorem mem_kept {P : Params} {code : List x64_ir.PInsn} (hL : Layout P)
    (hs : SafeStores P code) (hwin : StackWindow P code) {s s' : State} (he : Entry P s)
    (hr : Reachable P code s s') :
    ∀ a : Word, ¬ WritableAllowed P a →
      ((s'.regs RSP).toNat ≤ a.toNat ∨ InRange P.desc 200 a) → s'.mem a = s.mem a := by
  have hkept := stackKept_of_stackWindow hL hwin
  have hsr := hL.stackRoom
  have hwin128 : (P.rsp0 - 128#64).toNat = P.rsp0.toNat - 128 := by
    rw [show (128#64 : Word) = BitVec.ofNat 64 128 from rfl]
    exact toNat_sub_ofNat (by omega) (by norm_num)
  induction hr with
  | refl => intro a _ _; rfl
  | step hrch hstep ih =>
    rename_i t u
    intro a hw hge
    have hkt := hkept s he t hrch
    have hwt := hwin s he t hrch
    have hwu := hwin s he u (.step hrch hstep)
    have hu : u.mem a = t.mem a :=
      mem_step hL (fun i hi => hs s he t hrch _ hstep i hi) hkt.1 hwt.1 hstep hw hge
    rw [hu]
    refine ih a hw ?_
    rcases hge with hge | hd
    · by_cases hc : (t.regs RSP).toNat ≤ a.toNat
      · exact Or.inl hc
      · exact absurd (Or.inl ⟨by rw [hwin128]; omega, by rw [hwin128]; omega⟩) hw
    · exact Or.inr hd


/-! ## The two activations' parameters -/

/-- How a lazily compiled callee's parameters relate to its caller's.

Everything about the machine is shared: the descriptor, the two guest regions
and their native backings, the two local-call floors, the frame geometry and
the native stack mapping. The frame pointer is the caller's, the frame
register is one stride lower, and the callee's entry `rsp` is wherever the
lazy-call sequence's spills and the `call`'s own push left it — below the
caller's entry `rsp`, and no lower than the native floor allows.

The last three clauses are what the checked path of `MInsn::LazyLocalCall`
establishes before it descends. `guestRoom` is the first `jb`, which compares
the frame register against `[desc + 144]` and refuses the call when it is
below: the fall-through has the frame register, which is `fp0` for as long as
the checker keeps it tagged `Fp`, at or above the guest floor. `nativeRoom` is
the second, which compares `rsp` against `[desc + 152]`: the fall-through has
the caller's `rsp` at or above the native floor, and the callee's entry `rsp`
is that `rsp` less the four words the sequence still has on the stack at the
`call reg` and the return address it pushes — forty bytes. `below` is that the
callee's entry `rsp` is below the caller's, which the same pushes give. -/
structure CalleeOf (P P' : Params) : Prop where
  rbp0 : P'.rbp0 = P.rbp0
  /-- The lazy call moved the frame register down by one stride. -/
  fp0 : P'.fp0 = P.fp0 - BitVec.ofNat 64 P.stride
  desc : P'.desc = P.desc
  sgb : P'.sgb = P.sgb
  sgt : P'.sgt = P.sgt
  snb : P'.snb = P.snb
  dgb : P'.dgb = P.dgb
  dgt : P'.dgt = P.dgt
  dnb : P'.dnb = P.dnb
  guestFloor : P'.guestFloor = P.guestFloor
  nativeFloor : P'.nativeFloor = P.nativeFloor
  frameSize : P'.frameSize = P.frameSize
  stride : P'.stride = P.stride
  stackLo : P'.stackLo = P.stackLo
  stackHi : P'.stackHi = P.stackHi
  /-- The guest floor check: the frame register is at or above `[desc + 144]`. -/
  guestRoom : P.guestFloor.toNat ≤ P.fp0.toNat
  /-- The native floor check: the caller's `rsp` at the `call reg`, which is
  the callee's entry `rsp` plus the return address and the four words the
  sequence still holds, is at or above `[desc + 152]`. -/
  nativeRoom : P.nativeFloor.toNat ≤ P'.rsp0.toNat + 40
  /-- And the callee's entry `rsp` is below the caller's. -/
  below : P'.rsp0.toNat + 8 ≤ P.rsp0.toNat

namespace CalleeOf

variable {P P' : Params}

theorem frameSlots_eq (hr : CalleeOf P P') : frameSlots P' = frameSlots P := by
  simp only [frameSlots, hr.rbp0]

theorem stackSpan_eq (hr : CalleeOf P P') : stackSpan P' = stackSpan P := by
  simp only [stackSpan, hr.sgt, hr.sgb]

theorem dataSpan_eq (hr : CalleeOf P P') : dataSpan P' = dataSpan P := by
  simp only [dataSpan, hr.dgt, hr.dgb]

end CalleeOf

/-- The callee's layout, from the caller's and the two floor checks.

Everything but the frame register and the stack window is literally the
caller's. The frame window moves down one stride and stays inside the stack's
backing because `Layout.floorRoom` keeps a stride's worth of room below the
guest floor and `guestRoom` says the frame register has not crossed it. The
native stack window moves to the callee's `rsp` and stays inside
`[stackLo, stackHi)` because `Layout.floorNative` keeps two hundred and forty
bytes below the native floor and `nativeRoom` says the caller's `rsp` has not
crossed it; the caller's layout already keeps that mapping clear of the
descriptor, the two backings and the first page. -/
theorem layout_callee {P P' : Params} (hL : Layout P) (hr : CalleeOf P P') : Layout P' := by
  have hfs := hr.frameSlots_eq
  have hss := hr.stackSpan_eq
  have hds := hr.dataSpan_eq
  have hfn := hL.floorNative
  have hnl := hL.nativeStackLo
  have hnh := hL.nativeStackHi
  have hnw := hL.nativeStackNoWrap
  have hbf := hL.stackBelowFrame
  have hfr := hL.frameRoom
  have hfsN := hL.frameSlots_toNat
  have hrblt := P.rbp0.isLt
  have hlo : P.stackLo.toNat + 200 ≤ P'.rsp0.toNat := by
    have h1 := hr.nativeRoom
    omega
  have hbelow := hr.below
  have hhi : P'.rsp0.toNat + 8 ≤ P.stackHi.toNat := by omega
  have hwin : (stackWindow P').toNat = P'.rsp0.toNat - 128 := by
    rw [stackWindow, show (128#64 : Word) = BitVec.ofNat 64 128 from rfl]
    exact toNat_sub_ofNat (by omega) (by norm_num)
  -- anything the native stack mapping is clear of, the callee's window is
  have hband : ∀ (b : Word) (n : Nat),
      RangesDisjoint P.stackLo (P.stackHi.toNat - P.stackLo.toNat) b n →
      RangesDisjoint (stackWindow P') stackWindowLen b n := by
    intro b n hd
    simp only [RangesDisjoint] at hd ⊢
    simp only [hwin, stackWindowLen]
    omega
  -- the frame window, one stride down
  have hfloorRoom := hL.floorRoom
  have hguest := hr.guestRoom
  have hgflt := P.guestFloor.isLt
  have hfp : P'.fp0.toNat = P.fp0.toNat - P.stride := by
    rw [hr.fp0]
    exact toNat_sub_ofNat (by omega) (by omega)
  refine
    { stackOrdered := ?_, dataOrdered := ?_, guestDisjoint := ?_, frameNoWrap := ?_
      stackWindowNoWrap := ?_, stackNativeNoWrap := ?_, dataNativeNoWrap := ?_
      descNoWrap := ?_, nativeDisjoint := ?_, stackNativeOffPage := ?_
      dataNativeOffPage := ?_, stackNativeOffFrame := ?_, dataNativeOffFrame := ?_
      stackNativeOffStack := ?_, dataNativeOffStack := ?_, stackNativeOffDesc := ?_
      dataNativeOffDesc := ?_, frameOffStack := ?_, frameOffDesc := ?_, stackOffDesc := ?_
      stackBelowFrame := ?_, frameAbove := ?_, frameBelow := ?_, floorRoom := ?_
      stackWide := ?_, dataWide := ?_, frameRoom := ?_, stackRoom := ?_, frameOffPage := ?_
      descOffPage := ?_, nativeStackNoWrap := ?_, nativeStackLo := ?_, nativeStackHi := ?_
      nativeStackOffPage := ?_, stackNativeOffNativeStack := ?_
      dataNativeOffNativeStack := ?_, descOffNativeStack := ?_, floorNative := ?_ }
  · rw [hr.sgb, hr.sgt]; exact hL.stackOrdered
  · rw [hr.dgb, hr.dgt]; exact hL.dataOrdered
  · rw [hss, hds, hr.sgb, hr.dgb]; exact hL.guestDisjoint
  · rw [hfs]; exact hL.frameNoWrap
  · rw [hwin, stackWindowLen]; omega
  · rw [hss, hr.snb]; exact hL.stackNativeNoWrap
  · rw [hds, hr.dnb]; exact hL.dataNativeNoWrap
  · rw [hr.desc]; exact hL.descNoWrap
  · rw [hss, hds, hr.snb, hr.dnb]; exact hL.nativeDisjoint
  · rw [hss, hr.snb]; exact hL.stackNativeOffPage
  · rw [hds, hr.dnb]; exact hL.dataNativeOffPage
  · rw [hfs, hss, hr.snb]; exact hL.stackNativeOffFrame
  · rw [hfs, hds, hr.dnb]; exact hL.dataNativeOffFrame
  · rw [hss, hr.snb]; exact hband _ _ hL.stackNativeOffNativeStack
  · rw [hds, hr.dnb]; exact hband _ _ hL.dataNativeOffNativeStack
  · rw [hss, hr.snb, hr.desc]; exact hL.stackNativeOffDesc
  · rw [hds, hr.dnb, hr.desc]; exact hL.dataNativeOffDesc
  · rw [hfs]
    simp only [RangesDisjoint, hwin, stackWindowLen, hfsN]
    omega
  · rw [hfs, hr.desc]; exact hL.frameOffDesc
  · rw [hr.desc]; exact hband _ _ hL.descOffNativeStack
  · rw [hfs, hfsN]; omega
  · rw [hr.snb, hr.frameSize, hfp]; omega
  · rw [hr.snb, hss, hfp]; have := hL.frameBelow; omega
  · rw [hr.snb, hr.frameSize, hr.stride, hr.guestFloor]; exact hL.floorRoom
  · rw [hss]; exact hL.stackWide
  · rw [hds]; exact hL.dataWide
  · rw [hr.rbp0]; exact hL.frameRoom
  · omega
  · rw [hfs]; exact hL.frameOffPage
  · rw [hr.desc]; exact hL.descOffPage
  · rw [hr.stackLo, hr.stackHi]; exact hL.nativeStackNoWrap
  · rw [hr.stackLo]; omega
  · rw [hr.rbp0, hr.stackHi]; exact hL.nativeStackHi
  · rw [hr.stackLo, hr.stackHi]; exact hL.nativeStackOffPage
  · rw [hr.stackLo, hr.stackHi, hss, hr.snb]; exact hL.stackNativeOffNativeStack
  · rw [hr.stackLo, hr.stackHi, hds, hr.dnb]; exact hL.dataNativeOffNativeStack
  · rw [hr.stackLo, hr.stackHi, hr.desc]; exact hL.descOffNativeStack
  · rw [hr.stackLo, hr.nativeFloor]; exact hL.floorNative

/-- The read-only half of the entry contract is the same statement for the two
activations: every address it names is the frame pointer's or the descriptor's,
and every value it names is a region constant, and both are shared. -/
theorem romem_callee {P P' : Params} (hr : CalleeOf P P') {m : Mem} (h : RoMem P m) :
    RoMem P' m := by
  have hd : ∀ i, derivedSlot P' i = derivedSlot P i := by
    intro i; simp only [derivedSlot, hr.rbp0]
  have hblock : ∀ (k : Nat) (gb gt nb : Word), DerivedBlock P m k gb gt nb →
      DerivedBlock P' m k gb gt nb := by
    intro k gb gt nb hb
    exact ⟨by rw [hd]; exact hb.bottom, by rw [hd]; exact hb.delta,
      by rw [hd]; exact hb.span1, by rw [hd]; exact hb.span2,
      by rw [hd]; exact hb.span4, by rw [hd]; exact hb.span8⟩
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [hr.rbp0, hr.desc]; exact h.descSlot
  · rw [hr.rbp0, hr.snb, hr.sgb]; exact h.deltaSlot
  · rw [hr.sgb, hr.sgt, hr.snb]; exact hblock _ _ _ _ h.stackDerived
  · rw [hr.dgb, hr.dgt, hr.dnb]; exact hblock _ _ _ _ h.dataDerived
  · rw [hr.desc, hr.sgb]; exact h.descStackBottom
  · rw [hr.desc, hr.sgt]; exact h.descStackTop
  · rw [hr.desc, hr.snb]; exact h.descStackNative
  · rw [hr.desc, hr.dgb]; exact h.descDataBottom
  · rw [hr.desc, hr.dgt]; exact h.descDataTop
  · rw [hr.desc, hr.dnb]; exact h.descDataNative
  · rw [hr.desc, hr.guestFloor]; exact h.descGuestFloor
  · rw [hr.desc, hr.nativeFloor]; exact h.descNativeFloor


/-! ## The composition theorem -/

/-- **A callee that keeps this development's contract delivers
`ExternalReturn`.**

`code'` is the callee's primitive list and `P'` its parameters, related to the
caller's by `CalleeOf`; `hC'` and `hK'` are exactly what `check_safe` concludes
of it. `s` is the machine state on entering the callee — the caller's state
after the lazy-call sequence's `call reg` pushed the return address, with the
program counter reset to the head of the callee's list — and the callee runs
from it to a `ret` at its entry depth, leaving `s'`. The state the caller
resumes in is `s'` at the position the pushed return address names, and that
state is everything `Step.callReg` assumes of a callee. -/
theorem callee_externalReturn {P : Params} {code : List x64_ir.PInsn}
    {P' : Params} {code' : List x64_ir.PInsn}
    (hL : Layout P) (hrel : CalleeOf P P')
    (hC' : Contract P' code') (hK' : StackWindow P' code')
    {s s'' s' : State} {i : Nat}
    (hpc : s.pc = 0) (hrsp : s.regs RSP = P'.rsp0) (hrbp : s.regs RBP = P'.rbp0)
    (hfp : s.regs R15 = P'.fp0) (hro : RoMem P s.mem)
    (hi : i < code.length) (haddr : load64 s.mem (s.regs RSP) = codeAddr P i)
    (hrun : Reachable P' code' s s'') (hret : Step P' code' s'' (.returned s')) :
    ExternalReturn P code s { s' with pc := i } := by
  have hL' : Layout P' := layout_callee hL hrel
  have hE : Entry P' s := ⟨hpc, hrsp, hrbp, hfp, romem_callee hrel hro, hL'⟩
  obtain ⟨-, hstores, hreturns⟩ := hC'
  obtain ⟨hR1, hR2, hR3⟩ := hreturns s hE s'' hrun s' hret
  -- the `ret` itself moves only `rsp`, and it happens at the entry depth
  have hretTop : s'.mem = s''.mem ∧ s''.regs RSP = P'.rsp0 := by
    cases hret with
    | retTop _ h2 => exact ⟨rfl, h2⟩
  obtain ⟨hmem, hrspTop⟩ := hretTop
  -- what the callee left of an address it was not allowed to write
  have hkept : ∀ a : Word, ¬ WritableAllowed P' a →
      ((s''.regs RSP).toNat ≤ a.toNat ∨ InRange P'.desc 200 a) → s'.mem a = s.mem a := by
    intro a hw hge
    rw [hmem]
    exact mem_kept hL' hstores hK' hE hrun a hw hge
  have hsr := hL'.stackRoom
  have hwin128 : (P'.rsp0 - 128#64).toNat = P'.rsp0.toNat - 128 := by
    rw [show (128#64 : Word) = BitVec.ofNat 64 128 from rfl]
    exact toNat_sub_ofNat (by omega) (by norm_num)
  refine ⟨⟨i, hi, haddr, rfl⟩, ?_, ?_, ?_, ?_⟩
  · show s'.regs RSP = s.regs RSP + 8#64
    rw [hR1, hrsp]
  · intro r hr
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hr
    rcases hr with rfl | rfl
    · show s'.regs RBP = s.regs RBP
      rw [hR2, hrbp]
    · show s'.regs R15 = s.regs R15
      rw [hR3, hfp]
  · -- the caller's frame, above the return address
    intro a hge hslot hsn hdn hpg
    show s'.mem a = s.mem a
    refine hkept a (fun hcon => ?_) (Or.inl ?_)
    · rcases hcon with hc | hc | hc | hc | hc
      · rw [InRange, hwin128] at hc
        rw [hrsp] at hge
        omega
      · exact hslot (by rwa [WritableSlot, hrel.rbp0] at hc)
      · exact hsn (by rwa [hrel.snb, hrel.stackSpan_eq] at hc)
      · exact hdn (by rwa [hrel.dnb, hrel.dataSpan_eq] at hc)
      · exact hpg hc
    · rw [hrspTop, ← hrsp]
      omega
  · -- and the descriptor
    intro a h1 h2
    show s'.mem a = s.mem a
    have hin : InRange P'.desc 200 a := by rw [hrel.desc]; exact ⟨h1, h2⟩
    exact hkept a (fun hcon => writableAllowed_off_ro hL' hcon (Or.inr (Or.inr ⟨hin.1, hin.2⟩)))
      (Or.inr hin)

/-- The same for a callee whose macro list the checker accepted: `check_safe`
gives the contract and the stack window, and `layout_callee` gives the layout
it asks for, so the only hypotheses left are the checker's verdict and the
side conditions the checker does not look at — as in `check_safe` — together
with the relation between the two activations. -/
theorem checked_callee_externalReturn {P : Params} {code : List x64_ir.PInsn}
    {P' : Params} {cfg' : x64_ir.Cfg} {mcode : Slice x64_ir.MInsn}
    (hL : Layout P) (hrel : CalleeOf P P')
    (hcheck : x64_check.check cfg' mcode = ok (.Ok ()))
    (hcage : cfg'.pointer_mask ≠ 0#i32) (hcfg : CfgOk P' cfg')
    (hdisp : P'.dispatcher = BitVec.ofNat 64 cfg'.dispatcher.val)
    (hdispCode : ∀ j, j < (flat cfg' mcode.val).length → P'.dispatcher ≠ codeAddr P' j)
    (hlen : (flat cfg' mcode.val).length < 2 ^ 64)
    (hlabels : labelBase cfg' mcode.val mcode.val.length < 2 ^ 32)
    (htrailer : HasTrailer mcode.val)
    {s s'' s' : State} {i : Nat}
    (hpc : s.pc = 0) (hrsp : s.regs RSP = P'.rsp0) (hrbp : s.regs RBP = P'.rbp0)
    (hfp : s.regs R15 = P'.fp0) (hro : RoMem P s.mem)
    (hi : i < code.length) (haddr : load64 s.mem (s.regs RSP) = codeAddr P i)
    (hrun : Reachable P' (flat cfg' mcode.val) s s'')
    (hret : Step P' (flat cfg' mcode.val) s'' (.returned s')) :
    ExternalReturn P code s { s' with pc := i } := by
  obtain ⟨hC, -, hW⟩ := check_safe hcheck (layout_callee hL hrel) hcage hcfg hdisp hdispCode
    hlen hlabels htrailer
  exact callee_externalReturn hL hrel hC hW hpc hrsp hrbp hfp hro hi haddr hrun hret

end X64

end async_ebpf_verified

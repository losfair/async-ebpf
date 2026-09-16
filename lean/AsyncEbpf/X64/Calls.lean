import AsyncEbpf.X64.CheckSpec
import AsyncEbpf.X64.Simple

/-!
# The two call macros

`MInsn::HelperCall` and `MInsn::LazyLocalCall` are the two macros whose
expansion leaves this instruction list and comes back. Everything else the
backend emits is a handful of primitives over registers, the frame scratch
and one guest access; these two push a frame, hand control to the runtime,
and have to be shown to get back what they left.

## What is proved

`macroOk_lazyLocalCall` is an ordinary `MacroOk`: the expansion is one
contiguous run, the two `jcc`s that refuse the call land inside it, and the
`jmp done` at the end lands on the run's last primitive.

`macroOkIn_helperCall` is not, and that is the whole reason this file exists.
`expand_helper_call` ends in `call Retpoline`, and the retpoline lives in the
trailer: control leaves the macro's range, runs the eight primitives of
`expand_retpoline`, and comes back through the retpoline's `ret` — which is
not a return at all but the indirect branch into the dispatcher, with the
return into this list arriving later as an `ExternalReturn`. So the region
the proof is stated over is the macro's range *together with* the retpoline's,
and `MacroOkIn` is `MacroOk` with that region in place of `Range p q`. The two
differ in nothing else, and the glue reads them the same way.

## How

Both proofs are one `stays_invariant` over a per-position description of the
machine state. `Kept` is that description: the stack depth, `rbp`, the frame
register and the read-only bytes, at every position of both macros. It says
nothing about the four registers the lazy call spills, because nothing needs
it to: a lazily compiled callee does not keep them, and the state the
checker's `clobber_call` leaves says `Top` of all four. The description is
*absent* at the positions no execution reaches — the default-dispatcher path
the `jne` skips and the retpoline's speculation trap — which is how "inside
the region but unreachable" is spelled for an invariant that has to say
something everywhere.

The depth `Kept` carries is also what the two new clauses are read off: the
`stores` clause turns each push, each call's push and the retpoline's
`mov [rsp], rax` into `storeOk_stack` at that depth, and the `rsp` clause is
`rsp_window_of_depth` at it.

The three facts about leaving the list are `kept_callReg` (a `call reg` and
the `ExternalReturn` that answers it), `romem_kept` (an external callee that
left the frame scratch and the descriptor alone left the entry contract's
bytes where they were) and `codeAddr_inj` (a return address names one
position). The last one is why both theorems ask for `code.length < 2 ^ 64`:
`codeAddr` is injective only inside the address space, and a list that long
has no encoding anyway.
-/

-- The two theorems take one hypothesis per label of their expansion, and
-- each proof spends only the ones its reachable path needs; the rest are
-- there for the glue, which reads all of them off the same `expand` run.
set_option linter.unusedVariables false

open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-! Everything this file adds lives in `X64.CallSupport`, and the seven names
the glue needs are exported back into `X64` at the end. The two call proofs
need a fair amount of local scaffolding — a dozen ways of saying that a step
kept what the description carries — and none of it is anyone else's business.
-/
namespace CallSupport

/-! ## The expansions, mirrored

One list per `expand_*` function of `src/verified/x64_expand.rs`, primitive by
primitive. The labels are `Std.U32`s built from a `Nat`, because a position in
the list is a `Nat` everywhere else in this development; only `.val` is ever
read of them, through `isTarget`. -/

/-- A local label, as the primitive layer spells one. -/
def lbl (n : Nat) : Std.U32 := ⟨BitVec.ofNat 32 n⟩

/-- `expand_helper_call`: load the dispatcher slot, branch on it, and call the
retpoline either with the helper looked up in the embedded table or with the
index in `r9`; then scrub the five caller-saved registers eBPF `r1`–`r5` are
mapped to. `external` is `label`, `converge` is `label + 1`. -/
def helperCallList (idx : Std.U32) (label : Nat) : List x64_ir.PInsn :=
  [ .RipLoadDispatcher x64_ir.RAX,
    .AluImm true x64_ir.AluRI.Cmp x64_ir.RAX 0#i32,
    .Jcc x64_ir.cc.NE (.Local (lbl label)),
    -- the default dispatcher, which the branch above skips whenever the slot
    -- is non-zero
    .AluImm false x64_ir.AluRI.Mov x64_ir.RAX (UScalar.hcast .I32 idx),
    .ShiftImm true x64_ir.ShiftOp.Shl x64_ir.RAX 3#i32,
    .RipLeaHelperTable x64_ir.R10,
    .Alu true x64_ir.AluRR.Add x64_ir.R10 x64_ir.RAX,
    .Load 8#u8 false x64_ir.RAX x64_ir.RAX 0#i32,
    .Alu true x64_ir.AluRR.Mov x64_ir.VOLATILE_CTXT x64_ir.R9,
    .Jmp (.Local (lbl (label + 1))),
    -- the external dispatcher
    .Local (lbl label),
    .LoadImm x64_ir.R9 (UScalar.hcast .I64 (UScalar.cast .U64 idx)),
    .Local (lbl (label + 1)),
    .Call .Retpoline,
    -- `map_register 1 .. 5`
    .Alu true x64_ir.AluRR.Xor x64_ir.RDI x64_ir.RDI,
    .Alu true x64_ir.AluRR.Xor x64_ir.RSI x64_ir.RSI,
    .Alu true x64_ir.AluRR.Xor x64_ir.RDX x64_ir.RDX,
    .Alu true x64_ir.AluRR.Xor x64_ir.R10 x64_ir.R10,
    .Alu true x64_ir.AluRR.Xor x64_ir.R8 x64_ir.R8 ]

/-- `expand_retpoline`: `landing` is `label`, `capture` is `label + 1`. The
call at position 1 goes to the landing pad at position 5, which overwrites the
pushed return address with `rax` and returns to it; positions 2–4 are the
speculation trap, which architecturally executes never. -/
def retpolineList (label : Nat) : List x64_ir.PInsn :=
  [ .RetpolineLabel,
    .Call (.Local (lbl label)),
    .Local (lbl (label + 1)),
    .Pause,
    .Jmp (.Local (lbl (label + 1))),
    .Local (lbl label),
    .StoreRspRax,
    .Ret ]

/-- `expand_lazy_local_call` with `expand_lazy_call_body` inlined at its call
site. `exhausted` is `label`, `done` is `label + 1`; the registers are
`map_register`'s, written out. -/
def lazyLocalCallList (cfg : x64_ir.Cfg) (id : Std.U32) (label : Nat) :
    List x64_ir.PInsn :=
  [ .Load 8#u8 false x64_ir.RBP x64_ir.RCX x64_ir.frame.FRAME_OFFSET,
    .Load 8#u8 false x64_ir.RCX x64_ir.RCX x64_ir.memory.LOCAL_CALL_GUEST_FLOOR,
    .Alu true x64_ir.AluRR.Cmp x64_ir.RCX x64_ir.R15,
    .Jcc x64_ir.cc.B (.Local (lbl label)),
    .Load 8#u8 false x64_ir.RBP x64_ir.RCX x64_ir.frame.FRAME_OFFSET,
    .Load 8#u8 false x64_ir.RCX x64_ir.RCX x64_ir.memory.LOCAL_CALL_NATIVE_FLOOR,
    .Alu true x64_ir.AluRR.Cmp x64_ir.RCX x64_ir.RSP,
    .Jcc x64_ir.cc.B (.Local (lbl label)),
    .AluImm true x64_ir.AluRI.Sub x64_ir.R15 (UScalar.hcast .I32 cfg.stack_frame_stride),
    -- `expand_lazy_call_body`
    .Push x64_ir.RBX,   -- map_register 6
    .Push x64_ir.R12,   -- map_register 7
    .Push x64_ir.R13,   -- map_register 8
    .Push x64_ir.R14,   -- map_register 9
    .Push x64_ir.RDI,   -- map_register 1
    .Push x64_ir.RSI,   -- map_register 2
    .Push x64_ir.RDX,   -- map_register 3
    .Push x64_ir.R10,   -- map_register 4
    .Push x64_ir.R8,    -- map_register 5
    .Push x64_ir.VOLATILE_CTXT,
    .Push x64_ir.RAX,   -- map_register 0
    .Push x64_ir.RAX,
    .LoadImm x64_ir.RDI (UScalar.hcast .I64 (UScalar.cast .U64 id)),
    .LoadImm x64_ir.RAX (UScalar.hcast .I64 cfg.local_call_resolver),
    .CallReg x64_ir.RAX,
    .Alu true x64_ir.AluRR.Mov x64_ir.RAX x64_ir.RCX,
    .Pop x64_ir.RAX,
    .Pop x64_ir.RAX,
    .Pop x64_ir.VOLATILE_CTXT,
    .Pop x64_ir.R8,
    .Pop x64_ir.R10,
    .Pop x64_ir.RDX,
    .Pop x64_ir.RSI,
    .Pop x64_ir.RDI,
    .CallReg x64_ir.RCX,
    .Pop x64_ir.R14,
    .Pop x64_ir.R13,
    .Pop x64_ir.R12,
    .Pop x64_ir.RBX,
    -- back in the caller's frame
    .AluImm true x64_ir.AluRI.Add x64_ir.R15 (UScalar.hcast .I32 cfg.stack_frame_stride),
    .Jmp (.Local (lbl (label + 1))),
    .Local (lbl label),
    .LoadImm x64_ir.RAX (UScalar.hcast .I64 cfg.local_call_stack_exhausted),
    .CallReg x64_ir.RAX,
    .Ud2,
    .Local (lbl (label + 1)) ]

/-! ## Bytes, addresses and the read-only contract

Four facts the framework does not have, because nothing before this file left
the instruction list: a load reads only its own bytes, a store writes only its
own, a return address names one position, and a callee that kept the frame
kept the entry contract. -/

/-- A load reads the eight bytes of its range and nothing else. -/
theorem load64_congr {m₁ m₂ : Mem} {a : Word}
    (h : ∀ i, i < 8 → m₁ (a + BitVec.ofNat 64 i) = m₂ (a + BitVec.ofNat 64 i)) :
    load64 m₁ a = load64 m₂ a := by
  simp only [load64, load]
  rw [loadNat_congr 8 m₁ m₂ a (fun i hi => h i hi)]

/-- A store writes the eight bytes of its range and nothing else. -/
theorem store64_other {m : Mem} {b a : Word} (v : Word) (hb : b.toNat + 8 ≤ 2 ^ 64)
    (h : a.toNat < b.toNat ∨ b.toNat + 8 ≤ a.toNat) : store64 m b v a = m a := by
  have hsub : (a - b).toNat = (2 ^ 64 - b.toNat + a.toNat) % 2 ^ 64 := BitVec.toNat_sub _ _
  have := a.isLt
  have := b.isLt
  simp only [store64, store]
  rw [if_neg (by omega)]

/-- A return address names one position of the list. `codeAddr` is injective
only inside the address space, which is why both theorems below bound the
length of the list. -/
theorem codeAddr_inj {P : Params} {i j : Nat} (hi : i < 2 ^ 64) (hj : j < 2 ^ 64)
    (h : codeAddr P i = codeAddr P j) : i = j := by
  have h2 : (BitVec.ofNat 64 i : Word) = BitVec.ofNat 64 j := by
    simp only [codeAddr] at h
    exact add_left_cancel h
  have h3 := congrArg BitVec.toNat h2
  rw [BitVec.toNat_ofNat, BitVec.toNat_ofNat, Nat.mod_eq_of_lt hi, Nat.mod_eq_of_lt hj] at h3
  exact h3

/-- `rsp` one word shallower. -/
theorem rsp_pop {P : Params} {d : Nat} :
    P.rsp0 - BitVec.ofNat 64 (8 * (d + 1)) + 8#64 = P.rsp0 - BitVec.ofNat 64 (8 * d) := by
  rw [← rsp_push (P := P) (d := d)]; ring

/-- The native stack window stops short of the end of the address space. -/
theorem rsp0_top {P : Params} (hL : Layout P) : P.rsp0.toNat + 8 ≤ 2 ^ 64 := by
  have h1 := hL.stackWindowNoWrap
  have h2 := hL.stackWindow_toNat
  have h3 := hL.stackRoom
  simp only [stackWindowLen] at h1
  omega

/-- Where the word at depth `d` sits. -/
theorem rsp_toNat {P : Params} (hL : Layout P) {d : Nat} (hd : d ≤ 16) :
    (P.rsp0 - BitVec.ofNat 64 (8 * d)).toNat = P.rsp0.toNat - 8 * d := by
  have := hL.stackRoom
  exact toNat_sub_ofNat (by omega) (by omega)

/-- A store to one word of the native stack is invisible to a load of
another. -/
theorem load64_stack_other {P : Params} (hL : Layout P) {m : Mem} {i j : Nat}
    (hi : i ≤ 16) (hj : j ≤ 16) (hne : i ≠ j) (v : Word) :
    load64 (store64 m (P.rsp0 - BitVec.ofNat 64 (8 * j)) v)
        (P.rsp0 - BitVec.ofNat 64 (8 * i))
      = load64 m (P.rsp0 - BitVec.ofNat 64 (8 * i)) := by
  have ht := rsp0_top hL
  have hs := hL.stackRoom
  have ei := rsp_toNat hL hi
  have ej := rsp_toNat hL hj
  exact load64_store64_disjoint m _ _ v (by omega) (by omega)
    (by simp only [RangesDisjoint, ei, ej]; omega)

/-- A byte of the frame scratch lies in neither guest backing and outside the
first page, which is what `ExternalReturn.frameKept` asks of it on top of its
not being one of the four writable slots. -/
theorem frame_offRegions {P : Params} (hL : Layout P) {a : Word}
    (h1 : P.rbp0.toNat - 160 ≤ a.toNat) (h2 : a.toNat < P.rbp0.toNat) :
    ¬ InRange P.snb (stackSpan P) a ∧ ¬ InRange P.dnb (dataSpan P) a ∧
      ¬ InRange 0#64 4096 a := by
  have hfs := hL.frameSlots_toNat
  have hr := hL.frameRoom
  have hin : InRange (frameSlots P) 160 a := ⟨by omega, by omega⟩
  exact ⟨notInRange_of_disjoint hL.stackNativeOffFrame a hin,
    notInRange_of_disjoint hL.dataNativeOffFrame a hin,
    notInRange_of_disjoint hL.frameOffPage.symm a hin⟩

/-- An external callee that left the frame scratch and the descriptor alone
left the entry contract's bytes where they were. -/
theorem romem_kept {P : Params} {m m' : Mem} (hL : Layout P) (h : RoMem P m)
    (hfr : ∀ a : Word, P.rbp0.toNat - 160 ≤ a.toNat → a.toNat < P.rbp0.toNat →
      ¬ WritableSlot P a → m' a = m a)
    (hde : ∀ a : Word, P.desc.toNat ≤ a.toNat → a.toNat < P.desc.toNat + 200 → m' a = m a) :
    RoMem P m' := by
  have hr := hL.frameRoom
  have hdnw := hL.descNoWrap
  have hrlt := P.rbp0.isLt
  have e8 : (P.rbp0 - 8#64).toNat = P.rbp0.toNat - 8 := by
    rw [show (8#64 : Word) = BitVec.ofNat 64 8 from rfl]; exact rbp_sub_toNat hL (by norm_num)
  have e16 : (P.rbp0 - 16#64).toNat = P.rbp0.toNat - 16 := by
    rw [show (16#64 : Word) = BitVec.ofNat 64 16 from rfl]; exact rbp_sub_toNat hL (by norm_num)
  have e24 : (P.rbp0 - 24#64).toNat = P.rbp0.toNat - 24 := by
    rw [show (24#64 : Word) = BitVec.ofNat 64 24 from rfl]; exact rbp_sub_toNat hL (by norm_num)
  have e32 : (P.rbp0 - 32#64).toNat = P.rbp0.toNat - 32 := by
    rw [show (32#64 : Word) = BitVec.ofNat 64 32 from rfl]; exact rbp_sub_toNat hL (by norm_num)
  have e144 : (P.rbp0 - 144#64).toNat = P.rbp0.toNat - 144 := by
    rw [show (144#64 : Word) = BitVec.ofNat 64 144 from rfl]; exact rbp_sub_toNat hL (by norm_num)
  have frame : ∀ x : Word, P.rbp0.toNat - 136 ≤ x.toNat → x.toNat + 8 ≤ P.rbp0.toNat - 32 →
      load64 m' x = load64 m x := by
    intro x h1 h2
    refine load64_congr (fun i hi => ?_)
    have hx : (x + BitVec.ofNat 64 i).toNat = x.toNat + i := toNat_add_ofNat (by omega)
    refine hfr _ (by omega) (by omega) ?_
    simp only [WritableSlot, InRange, e16, e24, e32, e144, hx]
    omega
  have ptr : load64 m' (P.rbp0 - 8#64) = load64 m (P.rbp0 - 8#64) := by
    refine load64_congr (fun i hi => ?_)
    have hx : ((P.rbp0 - 8#64) + BitVec.ofNat 64 i).toNat = (P.rbp0 - 8#64).toNat + i :=
      toNat_add_ofNat (by omega)
    refine hfr _ (by omega) (by omega) ?_
    simp only [WritableSlot, InRange, e16, e24, e32, e144, hx, e8]
    omega
  have dsc : ∀ x : Word, P.desc.toNat ≤ x.toNat → x.toNat + 8 ≤ P.desc.toNat + 200 →
      load64 m' x = load64 m x := by
    intro x h1 h2
    refine load64_congr (fun i hi => ?_)
    have hx : (x + BitVec.ofNat 64 i).toNat = x.toNat + i := toNat_add_ofNat (by omega)
    exact hde _ (by omega) (by omega)
  have block : ∀ (kk : Nat), kk + 5 ≤ 11 → ∀ gb gt nb, DerivedBlock P m kk gb gt nb →
      DerivedBlock P m' kk gb gt nb := by
    intro kk hkk gb gt nb hb
    have slot : ∀ i, i ≤ 11 → load64 m' (derivedSlot P i) = load64 m (derivedSlot P i) := by
      intro i hi
      exact frame _ (by rw [derivedSlot_toNat hL hi]; omega)
        (by rw [derivedSlot_toNat hL hi]; omega)
    exact ⟨by rw [slot kk (by omega)]; exact hb.bottom,
      by rw [slot (kk + 1) (by omega)]; exact hb.delta,
      by rw [slot (kk + 2) (by omega)]; exact hb.span1,
      by rw [slot (kk + 3) (by omega)]; exact hb.span2,
      by rw [slot (kk + 4) (by omega)]; exact hb.span4,
      by rw [slot (kk + 5) (by omega)]; exact hb.span8⟩
  have descField : ∀ j : Nat, j ≤ 152 → load64 m' (P.desc + BitVec.ofNat 64 j)
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
  · rw [show (40#64 : Word) = BitVec.ofNat 64 40 from rfl] at *
    rw [frame _ (by rw [rbp_sub_toNat hL (j := 40) (by norm_num)]; omega)
      (by rw [rbp_sub_toNat hL (j := 40) (by norm_num)]; omega)]
    exact h.deltaSlot

/-- What `ExternalReturn` is worth once the return address is known: the
position it lands on, the stack it restores, the two registers it keeps, and
the two families of bytes it leaves alone.

Both halves are weaker than they were. Only `rbp` and the frame register come
back: a lazily compiled callee is another instance of this theorem, and this
theorem promises nothing of `rbx` and `r12`–`r14`. And a byte above the
return address comes back unchanged only once it is known to be none of the
four writable slots, to lie in neither guest backing, and to be outside the
first page. Every byte this file has to carry across a call is a byte of the
frame scratch, and `frame_offRegions` is what knows all three of it. -/
theorem externalReturn_facts {P : Params} {code : List x64_ir.PInsn} {u u' : State}
    (hlen : code.length < 2 ^ 64) (h : ExternalReturn P code u u') {j : Nat}
    (hj : j < 2 ^ 64) (hval : load64 u.mem (u.regs RSP) = codeAddr P j) :
    u'.pc = j ∧ u'.regs RSP = u.regs RSP + 8#64 ∧
      (∀ r ∈ [RBP, R15], u'.regs r = u.regs r) ∧
      (∀ a : Word, (u.regs RSP).toNat + 8 ≤ a.toNat → ¬ WritableSlot P a →
        ¬ InRange P.snb (stackSpan P) a → ¬ InRange P.dnb (dataSpan P) a →
        ¬ InRange 0#64 4096 a → u'.mem a = u.mem a) ∧
      (∀ a : Word, P.desc.toNat ≤ a.toNat → a.toNat < P.desc.toNat + 200 →
        u'.mem a = u.mem a) := by
  obtain ⟨i, hi, heq, hpc⟩ := h.returnsHere
  have : i = j := codeAddr_inj (by omega) hj (by rw [← heq, hval])
  subst this
  exact ⟨hpc, h.stackPopped, h.calleeSaved, h.frameKept, h.descKept⟩

/-! ## What both proofs carry

`Kept` is the description every position of both expansions satisfies, and it
is exactly what `Agree P (ClobberCall pre)` needs at the end: the thirteen
clobbered registers are `Top` and say nothing, and the other three — `rsp`,
`rbp` and the frame register — are where they were. -/

/-- The stack depth, the two fixed registers, the frame register and the
entry contract's bytes: what every position of both expansions carries.

The four registers the lazy call spills used to be here too, kept across a
call by `ExternalReturn.calleeSaved`. They are not kept any more — a lazily
compiled callee promises nothing of `rbx` and `r12`–`r14` — and they are not
needed either: `Clobbered` now covers all four, so the state the checker's
`clobber_call` leaves says `Top` of them and `agree_kept` has nothing to
prove. The four `pop`s at the end of the lazy call do restore them from its
own pushes; that is the machine's business, not this description's. -/
structure Kept (P : Params) (s t : State) (dd : Nat) (fp : Word) : Prop where
  rsp : t.regs RSP = P.rsp0 - BitVec.ofNat 64 (8 * dd)
  rbp : t.regs RBP = P.rbp0
  fpv : t.regs R15 = fp
  ro : RoMem P t.mem

@[simp] theorem push_regs_ne (s : State) (v : Word) {x : Nat} (hx : x ≠ RSP) :
    (push s v).regs x = s.regs x := by
  simp only [push, Function.update_of_ne hx]

/-- A macro's state agrees with what the checker's `clobber_call` left. -/
theorem agree_kept {P : Params} {pre post : x64_check.State} {s t : State}
    (hag : Agree P pre s) (hcl : ClobberCall pre post)
    (h : Kept P s t pre.depth.val (s.regs R15)) : Agree P post t := by
  have hdep : post.depth = pre.depth := hcl.2.2.1
  refine ⟨?_, ?_, ?_, h.rbp, h.ro, ?_⟩
  · intro r hr
    by_cases hcs : Clobbered r
    · rw [hcl.1 r hcs]; trivial
    · rw [hcl.2.1 r hcs]
      have hcases : r = 4 ∨ r = 5 ∨ r = 15 := by
        simp only [Clobbered, not_or] at hcs
        omega
      have hkp : t.regs r = s.regs r := by
        rcases hcases with rfl | rfl | rfl
        · rw [h.rsp, hag.rsp]
        · rw [h.rbp, hag.rbp]
        · exact h.fpv
      rw [hkp]
      exact hag.regs r hr
  · rw [hdep]; exact h.rsp
  · rw [hdep]; exact hag.depth
  · rw [hcl.2.2.2.1]; trivial

/-- `call reg` and the external return that answers it: the position after the
call, the stack restored, and everything the description carries kept. -/
theorem kept_callReg {P : Params} {code : List x64_ir.PInsn} {s t t' : State}
    {dd : Nat} {fp : Word} {r : Std.U8}
    (hL : Layout P) (hlen : code.length < 2 ^ 64)
    (hk : Kept P s t dd fp) (hd16 : dd + 1 ≤ 16)
    (hc : code[t.pc]? = some (.CallReg r)) (hstep : Step P code t (.next t')) :
    t'.pc = t.pc + 1 ∧ Kept P s t' dd fp := by
  obtain ⟨u, hext, hu⟩ := step_callReg hc hstep
  simp only [Config.next.injEq] at hu
  subst hu
  have hpclt : t.pc < code.length := by
    have := List.getElem?_eq_some_iff.mp hc
    exact this.1
  have hb : t.regs RSP - 8#64 = P.rsp0 - BitVec.ofNat 64 (8 * (dd + 1)) := by
    rw [hk.rsp, rsp_push]
  have hwrsp : (push t (retAddr P t)).regs RSP = P.rsp0 - BitVec.ofNat 64 (8 * (dd + 1)) := by
    rw [push_rsp, hb]
  have hwval : load64 (push t (retAddr P t)).mem ((push t (retAddr P t)).regs RSP)
      = codeAddr P (t.pc + 1) := by
    rw [push_rsp, load64_push]
    rfl
  obtain ⟨hpc, hrsp', hkeep', hfr', hde'⟩ :=
    externalReturn_facts hlen hext (j := t.pc + 1) (by omega) hwval
  have hs := hL.stackRoom
  have ht := rsp0_top hL
  have hbelow := hL.stackBelowFrame
  have hfs := hL.frameSlots_toNat
  have hwtn : (P.rsp0 - BitVec.ofNat 64 (8 * (dd + 1))).toNat = P.rsp0.toNat - 8 * (dd + 1) :=
    rsp_toNat hL (by omega)
  -- The bytes the push wrote, and the bytes the callee may have written, are
  -- both far below everything the entry contract pins.
  have hwmem : ∀ a : Word, P.rsp0.toNat ≤ a.toNat →
      (push t (retAddr P t)).mem a = t.mem a := by
    intro a ha
    show store64 t.mem (t.regs RSP - 8#64) (retAddr P t) a = t.mem a
    rw [hb]
    exact store64_other _ (by omega) (by omega)
  refine ⟨hpc, ?_, ?_, ?_, ?_⟩
  · rw [hrsp', hwrsp, rsp_pop]
  · rw [hkeep' RBP (by simp), push_regs_ne _ _ (by decide)]; exact hk.rbp
  · rw [hkeep' R15 (by simp), push_regs_ne _ _ (by decide)]; exact hk.fpv
  · refine romem_kept hL hk.ro ?_ ?_
    · intro a h1 h2 h3
      obtain ⟨hsn, hdn, hpg⟩ := frame_offRegions hL h1 h2
      rw [hfr' a (by rw [hwrsp] at *; omega) h3 hsn hdn hpg, hwmem a (by omega)]
    · intro a h1 h2
      have hdisj := hL.stackOffDesc
      have hsw := hL.stackWindow_toNat
      simp only [RangesDisjoint, stackWindowLen, hsw] at hdisj
      rw [hde' a h1 h2]
      show store64 t.mem (t.regs RSP - 8#64) (retAddr P t) a = t.mem a
      rw [hb]
      exact store64_other _ (by omega) (by omega)

/-! ## A macro whose region is not one range

`MacroOk` states its three clauses over `Range p q`, which is every macro's
region but one. `MacroOkIn` is the same three clauses over an arbitrary region
`inside`, which is what the helper call needs: its expansion branches into the
trailer's retpoline and comes back, so the positions it runs through are its
own range together with the retpoline's. Everything else is unchanged —
`MacroOk P code p q` is `MacroOkIn P code (Range p q) p q`. -/

/-- `MacroOk` with the region given as a predicate rather than as a range. -/
structure MacroOkIn (P : Params) (code : List x64_ir.PInsn) (inside : Nat → Prop) (p q : Nat)
    (pre post : x64_check.State) (exits : List (Nat × x64_check.State)) : Prop where
  safe : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code inside s s' →
    ∀ c, Step P code s' c → ∀ i, code[s'.pc]? = some i →
      ∀ bn ∈ accesses i s', AccessOk P bn.1 bn.2
  leave : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code inside s s' →
    ∀ s'', Step P code s' (.next s'') → ¬ inside s''.pc →
      (s''.pc = q ∧ Agree P post s'') ∨ (∃ e ∈ exits, s''.pc = e.1 ∧ Agree P e.2 s'')
  returns : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code inside s s' →
    ∀ s'', Step P code s' (.returned s'') →
      s''.regs RSP = P.rsp0 + 8#64 ∧ s''.regs RBP = P.rbp0 ∧ s''.regs R15 = P.fp0
  /-- Every range the region *writes* is one this activation may write. -/
  stores : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code inside s s' →
    ∀ c, Step P code s' c → ∀ i, code[s'.pc]? = some i →
      ∀ bn ∈ X64.stores i s', StoreOk P bn.1 bn.2
  /-- And the stack pointer stays in the native stack window at every position
  of the region, the retpoline's two words included. -/
  rsp : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code inside s s' →
    (s'.regs RSP).toNat ≤ P.rsp0.toNat ∧ P.rsp0.toNat ≤ (s'.regs RSP).toNat + 128

/-! ## Reading the two primitives the framework left out -/

/-- The RIP-relative load of the trailer's dispatcher slot. -/
theorem step_ripLoadDispatcher {P code} {s : State} {c : Config} {dst : Std.U8}
    (hc : code[s.pc]? = some (.RipLoadDispatcher dst)) (h : Step P code s c) :
    c = .next (wReg s dst (dispatcherAddr code)) := by
  cases h <;> simp_all

/-- `jne`, the condition the helper call branches on. -/
theorem cond_NE (f : Flags) : cond x64_ir.cc.NE f = !f.zf := by
  have h : (x64_ir.cc.NE).val = 133 := by rw [x64_ir.cc.NE]; rfl
  simp only [cond, h]
  norm_num

/-- `jb`, the condition the lazy local call refuses on. -/
theorem cond_B (f : Flags) : cond x64_ir.cc.B f = f.cf := by
  have h : (x64_ir.cc.B).val = 130 := by rw [x64_ir.cc.B]; rfl
  simp only [cond, h]
  norm_num

theorem signExtend_zero : (BitVec.signExtend 64 (0#i32 : Std.I32).bv : Word) = 0#64 := by decide

/-- A register-only primitive, in the form the invariant proofs consume. -/
theorem regOnly_next {P code} {t t' : State} {i : x64_ir.PInsn} (hi : RegOnly i)
    (hc : code[t.pc]? = some i) (h : Step P code t (.next t')) :
    t'.pc = t.pc + 1 ∧ t'.mem = t.mem ∧ ∀ r, r ∉ writes i → t'.regs r = t.regs r := by
  obtain ⟨u, hu, h1, h2, h3⟩ := step_regOnly hi hc h
  simp only [Config.next.injEq] at hu
  subst hu
  exact ⟨h1, h2, h3⟩

/-- A write to a register the description says nothing about. -/
theorem kept_wReg {P : Params} {s t t' : State} {dd : Nat} {fp : Word} {r : Nat}
    (hk : Kept P s t dd fp) (hr4 : r ≠ RSP) (hr5 : r ≠ RBP) (hr15 : r ≠ R15)
    (hregs : ∀ x, x ≠ r → t'.regs x = t.regs x) (hmem : t'.mem = t.mem) :
    Kept P s t' dd fp := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [hregs RSP (Ne.symm hr4)]; exact hk.rsp
  · rw [hregs RBP (Ne.symm hr5)]; exact hk.rbp
  · rw [hregs R15 (Ne.symm hr15)]; exact hk.fpv
  · rw [hmem]; exact hk.ro

/-- A push: one word deeper, and everything the description names kept. -/
theorem kept_pushW {P : Params} {s t t' : State} {dd : Nat} {fp v : Word}
    (hL : Layout P) (hk : Kept P s t dd fp) (hd16 : dd + 1 ≤ 16)
    (hregs : ∀ x, x ≠ RSP → t'.regs x = t.regs x)
    (hrsp : t'.regs RSP = t.regs RSP - 8#64)
    (hmem : t'.mem = store64 t.mem (t.regs RSP - 8#64) v) :
    Kept P s t' (dd + 1) fp := by
  have hb : t.regs RSP - 8#64 = P.rsp0 - BitVec.ofNat 64 (8 * (dd + 1)) := by
    rw [hk.rsp, rsp_push]
  refine ⟨by rw [hrsp, hb], ?_, ?_, ?_⟩
  · rw [hregs RBP (by decide)]; exact hk.rbp
  · rw [hregs R15 (by decide)]; exact hk.fpv
  · rw [hmem, hb]; exact romem_store64_stack hL hk.ro hd16 _

/-! ## Register numbers

The extracted constants, read as the numbers `Machine.lean` indexes with. -/

theorem rcx_val : (x64_ir.RCX).val = RCX := by rw [x64_ir.RCX]; rfl
theorem rdx_val : (x64_ir.RDX).val = RDX := by rw [x64_ir.RDX]; rfl
theorem rbx_val : (x64_ir.RBX).val = RBX := by rw [x64_ir.RBX]; rfl
theorem rsi_val : (x64_ir.RSI).val = RSI := by rw [x64_ir.RSI]; rfl
theorem rdi_val : (x64_ir.RDI).val = RDI := by rw [x64_ir.RDI]; rfl
theorem r8_val : (x64_ir.R8).val = R8 := by rw [x64_ir.R8]; rfl
theorem r9_val : (x64_ir.R9).val = R9 := by rw [x64_ir.R9]; rfl
theorem r10_val : (x64_ir.R10).val = R10 := by rw [x64_ir.R10]; rfl
theorem r11_val : (x64_ir.R11).val = R11 := by rw [x64_ir.R11]; rfl
theorem r12_val : (x64_ir.R12).val = R12 := by rw [x64_ir.R12]; rfl
theorem r13_val : (x64_ir.R13).val = R13 := by rw [x64_ir.R13]; rfl
theorem r14_val : (x64_ir.R14).val = R14 := by rw [x64_ir.R14]; rfl
theorem ctxt_val : (x64_ir.VOLATILE_CTXT).val = R11 := by
  rw [x64_ir.VOLATILE_CTXT, x64_ir.R11]; rfl

@[simp] theorem popRsp_regs_ne (s : State) {x : Nat} (hx : x ≠ RSP) :
    (popRsp s).regs x = s.regs x := by
  simp only [popRsp, Function.update_of_ne hx]

/-- A write to a register a call is allowed to clobber moves nothing the
description names: `Clobbered` is the thirteen registers that are neither
`rsp`, `rbp` nor the frame register. -/
theorem kept_wRegCaller {P : Params} {s t t' : State} {dd : Nat} {fp : Word} {r : Nat}
    (hk : Kept P s t dd fp) (hr : Clobbered r)
    (hregs : ∀ x, x ≠ r → t'.regs x = t.regs x) (hmem : t'.mem = t.mem) :
    Kept P s t' dd fp := by
  simp only [Clobbered] at hr
  refine kept_wReg hk ?_ ?_ ?_ hregs hmem <;> simp only [RSP, RBP, R15] <;> omega

theorem kept_same {P : Params} {s t t' : State} {dd : Nat} {fp : Word} (hk : Kept P s t dd fp)
    (hregs : ∀ x, t'.regs x = t.regs x) (hmem : t'.mem = t.mem) : Kept P s t' dd fp :=
  ⟨by rw [hregs]; exact hk.rsp, by rw [hregs]; exact hk.rbp, by rw [hregs]; exact hk.fpv,
    by rw [hmem]; exact hk.ro⟩

/-- `cmp rax, 0` reads the register it names. -/
theorem cmp_zero_zf (t : State) :
    (aluImmStep true x64_ir.AluRI.Cmp x64_ir.RAX 0#i32 t).flags.zf
      = decide (t.regs RAX = 0#64) := by
  simp only [aluImmStep, wFlags, flagsOfAddSub, subFlags, signExtend_zero, rax_val,
    if_true]
  rw [show (t.regs RAX) - 0#64 = t.regs RAX from by
    rw [show (0#64 : Word) = 0 from rfl]; ring]

/-! ## The helper call

The region is the macro's nineteen primitives together with the retpoline's
eight. `HcInv` is what the machine state satisfies at each of the seventeen
positions an execution reaches; the seven positions of the default-dispatcher
path and the three of the speculation trap are not among them, which is how
"inside the region but unreachable" is spelled. -/

/-- The description of the helper call's state, position by position. -/
def HcInv (P : Params) (d p rp : Nat) (s t : State) : Prop :=
  (t.pc = p ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 1 ∧ Kept P s t d (s.regs R15) ∧ t.regs RAX = P.dispatcher) ∨
  (t.pc = p + 2 ∧ Kept P s t d (s.regs R15) ∧ t.regs RAX = P.dispatcher ∧
    t.flags.zf = false) ∨
  (t.pc = p + 10 ∧ Kept P s t d (s.regs R15) ∧ t.regs RAX = P.dispatcher) ∨
  (t.pc = p + 11 ∧ Kept P s t d (s.regs R15) ∧ t.regs RAX = P.dispatcher) ∨
  (t.pc = p + 12 ∧ Kept P s t d (s.regs R15) ∧ t.regs RAX = P.dispatcher) ∨
  (t.pc = p + 13 ∧ Kept P s t d (s.regs R15) ∧ t.regs RAX = P.dispatcher) ∨
  (t.pc = rp ∧ Kept P s t (d + 1) (s.regs R15) ∧ t.regs RAX = P.dispatcher ∧
    load64 t.mem (P.rsp0 - BitVec.ofNat 64 (8 * (d + 1))) = codeAddr P (p + 14)) ∨
  (t.pc = rp + 1 ∧ Kept P s t (d + 1) (s.regs R15) ∧ t.regs RAX = P.dispatcher ∧
    load64 t.mem (P.rsp0 - BitVec.ofNat 64 (8 * (d + 1))) = codeAddr P (p + 14)) ∨
  (t.pc = rp + 5 ∧ Kept P s t (d + 2) (s.regs R15) ∧ t.regs RAX = P.dispatcher ∧
    load64 t.mem (P.rsp0 - BitVec.ofNat 64 (8 * (d + 1))) = codeAddr P (p + 14)) ∨
  (t.pc = rp + 6 ∧ Kept P s t (d + 2) (s.regs R15) ∧ t.regs RAX = P.dispatcher ∧
    load64 t.mem (P.rsp0 - BitVec.ofNat 64 (8 * (d + 1))) = codeAddr P (p + 14)) ∨
  (t.pc = rp + 7 ∧ Kept P s t (d + 2) (s.regs R15) ∧
    load64 t.mem (P.rsp0 - BitVec.ofNat 64 (8 * (d + 1))) = codeAddr P (p + 14) ∧
    load64 t.mem (t.regs RSP) = P.dispatcher) ∨
  ((t.pc = p + 14 ∨ t.pc = p + 15 ∨ t.pc = p + 16 ∨ t.pc = p + 17 ∨ t.pc = p + 18) ∧
    Kept P s t d (s.regs R15))

/-- Every position the description names is in the region. -/
theorem hcInv_inside {P : Params} {d p rp : Nat} {s t : State}
    (h : HcInv P d p rp s t) : Range p (p + 19) t.pc ∨ Range rp (rp + 8) t.pc := by
  simp only [HcInv] at h
  simp only [Range]
  rcases h with ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
    ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩
  · omega
  · omega
  · omega
  · omega
  · omega
  · omega
  · omega
  · omega
  · omega
  · omega
  · omega
  · omega
  · rcases ht with ht | ht | ht | ht | ht <;> omega

theorem helperCallList_length (idx : Std.U32) (label : Nat) :
    (helperCallList idx label).length = 19 := rfl

theorem retpolineList_length (label : Nat) : (retpolineList label).length = 8 := rfl

theorem lazyLocalCallList_length (cfg : x64_ir.Cfg) (id : Std.U32) (label : Nat) :
    (lazyLocalCallList cfg id label).length = 45 := rfl


/-- `MInsn::HelperCall`.

The region is the macro's own nineteen positions together with the
retpoline's eight: `call Retpoline` leaves the first and control returns
through the second's `ret`, which — the word on top of the stack having been
replaced by the dispatcher's address — is the indirect branch out of this
list, answered later by an `ExternalReturn` back to the primitive after the
call.

`hdisjoint` is the two ranges not overlapping, in the form the proof needs:
either the retpoline sits wholly below the macro, or it starts after the
macro's fallthrough, so that falling out of the macro really leaves the
region. Nothing is proved of the seven primitives of the default-dispatcher
path or of the retpoline's three-primitive speculation trap: the `jne` is
always taken, because the dispatcher slot is non-zero, and the `call` past the
trap always lands on the landing pad. -/
theorem macroOkIn_helperCall {P : Params} {code : List x64_ir.PInsn} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {idx : Std.U32} {index : Std.Usize} {pcv : Std.U32}
    {p rp label rlabel : Nat}
    (hL : Layout P) (hlen : code.length < 2 ^ 64) (hlive : pre.alive = true)
    (hstep : x64_check.live_step cfg (.HelperCall idx) index pcv pre = ok (.Ok (), post))
    (hE : ∀ k, k < (helperCallList idx label).length →
      code[p + k]? = (helperCallList idx label)[k]?)
    (hR : ∀ k, k < (retpolineList rlabel).length →
      code[rp + k]? = (retpolineList rlabel)[k]?)
    (hposR : pos code .Retpoline = some rp)
    (hposExt : pos code (.Local (lbl label)) = some (p + 10))
    (hposConv : pos code (.Local (lbl (label + 1))) = some (p + 12))
    (hposA : pos code (.Local (lbl rlabel)) = some (rp + 5))
    (hposB : pos code (.Local (lbl (rlabel + 1))) = some (rp + 2))
    (hdisp : dispatcherAddr code = P.dispatcher) (hdisp0 : P.dispatcher ≠ 0#64)
    (hdispCode : ∀ j, j < code.length → P.dispatcher ≠ codeAddr P j)
    (hdisjoint : rp + (retpolineList rlabel).length ≤ p ∨
      p + (helperCallList idx label).length < rp) :
    MacroOkIn P code
      (fun x => Range p (p + (helperCallList idx label).length) x ∨
        Range rp (rp + (retpolineList rlabel).length) x)
      p (p + (helperCallList idx label).length) pre post [] := by
  simp only [helperCallList_length, retpolineList_length] at hdisjoint ⊢
  obtain ⟨-, hdep, hcl⟩ := live_step_HelperCall_spec hlive hstep
  have e0 : code[p]? = some (x64_ir.PInsn.RipLoadDispatcher x64_ir.RAX) :=
    hE 0 (by rw [helperCallList_length]; norm_num)
  have e1 : code[p + 1]? =
      some (x64_ir.PInsn.AluImm true x64_ir.AluRI.Cmp x64_ir.RAX 0#i32) :=
    hE 1 (by rw [helperCallList_length]; norm_num)
  have e2 : code[p + 2]? =
      some (x64_ir.PInsn.Jcc x64_ir.cc.NE (x64_ir.PTarget.Local (lbl label))) :=
    hE 2 (by rw [helperCallList_length]; norm_num)
  have e10 : code[p + 10]? = some (x64_ir.PInsn.Local (lbl label)) :=
    hE 10 (by rw [helperCallList_length]; norm_num)
  have e11 : code[p + 11]? = some (x64_ir.PInsn.LoadImm x64_ir.R9
      (UScalar.hcast .I64 (UScalar.cast .U64 idx))) :=
    hE 11 (by rw [helperCallList_length]; norm_num)
  have e12 : code[p + 12]? = some (x64_ir.PInsn.Local (lbl (label + 1))) :=
    hE 12 (by rw [helperCallList_length]; norm_num)
  have e13 : code[p + 13]? = some (x64_ir.PInsn.Call x64_ir.PTarget.Retpoline) :=
    hE 13 (by rw [helperCallList_length]; norm_num)
  have e14 : code[p + 14]? =
      some (x64_ir.PInsn.Alu true x64_ir.AluRR.Xor x64_ir.RDI x64_ir.RDI) :=
    hE 14 (by rw [helperCallList_length]; norm_num)
  have e15 : code[p + 15]? =
      some (x64_ir.PInsn.Alu true x64_ir.AluRR.Xor x64_ir.RSI x64_ir.RSI) :=
    hE 15 (by rw [helperCallList_length]; norm_num)
  have e16 : code[p + 16]? =
      some (x64_ir.PInsn.Alu true x64_ir.AluRR.Xor x64_ir.RDX x64_ir.RDX) :=
    hE 16 (by rw [helperCallList_length]; norm_num)
  have e17 : code[p + 17]? =
      some (x64_ir.PInsn.Alu true x64_ir.AluRR.Xor x64_ir.R10 x64_ir.R10) :=
    hE 17 (by rw [helperCallList_length]; norm_num)
  have e18 : code[p + 18]? =
      some (x64_ir.PInsn.Alu true x64_ir.AluRR.Xor x64_ir.R8 x64_ir.R8) :=
    hE 18 (by rw [helperCallList_length]; norm_num)
  have r0 : code[rp]? = some x64_ir.PInsn.RetpolineLabel :=
    hR 0 (by rw [retpolineList_length]; norm_num)
  have r1 : code[rp + 1]? =
      some (x64_ir.PInsn.Call (x64_ir.PTarget.Local (lbl rlabel))) :=
    hR 1 (by rw [retpolineList_length]; norm_num)
  have r5 : code[rp + 5]? = some (x64_ir.PInsn.Local (lbl rlabel)) :=
    hR 5 (by rw [retpolineList_length]; norm_num)
  have r6 : code[rp + 6]? = some x64_ir.PInsn.StoreRspRax :=
    hR 6 (by rw [retpolineList_length]; norm_num)
  have r7 : code[rp + 7]? = some x64_ir.PInsn.Ret :=
    hR 7 (by rw [retpolineList_length]; norm_num)
  have hplt : p + 18 < code.length := (List.getElem?_eq_some_iff.mp e18).1
  have hqout : ¬ (Range p (p + 19) (p + 19) ∨ Range rp (rp + 8) (p + 19)) := by
    simp only [Range]
    rcases hdisjoint with hd | hd <;> rintro (⟨h1, h2⟩ | ⟨h1, h2⟩) <;> omega
  -- One step of the expansion: either the description still holds, or the
  -- last scrub has fallen out of the region.
  have hadv : ∀ s t t' : State, HcInv P pre.depth.val p rp s t →
      Step P code t (.next t') →
      HcInv P pre.depth.val p rp s t' ∨
        (t'.pc = p + 19 ∧ Kept P s t' pre.depth.val (s.regs R15)) := by
    intro s t t' hI hstep'
    simp only [HcInv] at hI ⊢
    rcases hI with ⟨ht, hk⟩ | ⟨ht, hk, hx⟩ | ⟨ht, hk, hx, hz⟩ | ⟨ht, hk, hx⟩ |
      ⟨ht, hk, hx⟩ | ⟨ht, hk, hx⟩ | ⟨ht, hk, hx⟩ | ⟨ht, hk, hx, hw⟩ | ⟨ht, hk, hx, hw⟩ |
      ⟨ht, hk, hx, hw⟩ | ⟨ht, hk, hx, hw⟩ | ⟨ht, hk, hw, hz⟩ | ⟨ht, hk⟩
    · -- `mov rax, [rip + dispatcher]`
      have hc : code[t.pc]? = some (x64_ir.PInsn.RipLoadDispatcher x64_ir.RAX) := by
        rw [ht]; exact e0
      have hu := step_ripLoadDispatcher hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ?_
      iterate 1 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_, ?_⟩
      · simp only [wReg, ht]
      · refine kept_wRegCaller (r := (x64_ir.RAX).val) hk (by rw [rax_val]; simp [Clobbered])
          (fun x hxx => ?_) rfl
        simp only [wReg, Function.update_of_ne hxx]
      · simp only [wReg, rax_val, Function.update_self]
        exact hdisp
    · -- `cmp rax, 0`
      have hc : code[t.pc]? =
          some (x64_ir.PInsn.AluImm true x64_ir.AluRI.Cmp x64_ir.RAX 0#i32) := by
        rw [ht]; exact e1
      have hu := step_aluImm hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ?_
      iterate 2 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_, ?_, ?_⟩
      · simp only [aluImmStep_pc, ht]
      · exact kept_same hk (fun x => by simp only [aluImmStep, wFlags]) rfl
      · show (aluImmStep true x64_ir.AluRI.Cmp x64_ir.RAX 0#i32 t).regs RAX = P.dispatcher
        simp only [aluImmStep, wFlags]
        exact hx
      · rw [cmp_zero_zf, hx]
        exact decide_eq_false hdisp0
    · -- `jne external`, always taken
      have hc : code[t.pc]? =
          some (x64_ir.PInsn.Jcc x64_ir.cc.NE (x64_ir.PTarget.Local (lbl label))) := by
        rw [ht]; exact e2
      rcases step_jcc hc hstep' with ⟨-, i, hi, hu⟩ | ⟨hcond, -⟩
      · rw [hposExt] at hi
        simp only [Option.some.injEq] at hi
        subst hi
        simp only [Config.next.injEq] at hu
        subst hu
        refine Or.inl ?_
        iterate 3 refine Or.inr ?_
        exact Or.inl ⟨rfl, kept_same hk (fun x => rfl) rfl, hx⟩
      · rw [cond_NE, hz] at hcond
        simp at hcond
    · -- the `external` label
      have hc : code[t.pc]? = some (x64_ir.PInsn.Local (lbl label)) := by rw [ht]; exact e10
      obtain ⟨hpc, hmem, hregs⟩ :=
        regOnly_next (i := .Local (lbl label)) trivial hc hstep'
      refine Or.inl ?_
      iterate 4 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_, ?_⟩
      · omega
      · exact kept_same hk (fun x => hregs x (by simp [writes])) hmem
      · rw [hregs RAX (by simp [writes])]; exact hx
    · -- `mov r9, idx`
      have hc : code[t.pc]? = some (x64_ir.PInsn.LoadImm x64_ir.R9
          (UScalar.hcast .I64 (UScalar.cast .U64 idx))) := by rw [ht]; exact e11
      obtain ⟨hpc, hmem, hregs⟩ := regOnly_next
        (i := .LoadImm x64_ir.R9 (UScalar.hcast .I64 (UScalar.cast .U64 idx)))
        trivial hc hstep'
      refine Or.inl ?_
      iterate 5 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_, ?_⟩
      · omega
      · refine kept_wRegCaller (r := (x64_ir.R9).val) hk (by rw [r9_val]; simp [Clobbered])
          (fun x hxx => hregs x ?_) hmem
        simp only [writes, List.mem_singleton]; exact hxx
      · rw [hregs RAX (by simp [writes, r9_val])]; exact hx
    · -- the `converge` label
      have hc : code[t.pc]? = some (x64_ir.PInsn.Local (lbl (label + 1))) := by
        rw [ht]; exact e12
      obtain ⟨hpc, hmem, hregs⟩ :=
        regOnly_next (i := .Local (lbl (label + 1))) trivial hc hstep'
      refine Or.inl ?_
      iterate 6 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_, ?_⟩
      · omega
      · exact kept_same hk (fun x => hregs x (by simp [writes])) hmem
      · rw [hregs RAX (by simp [writes])]; exact hx
    · -- `call Retpoline`
      have hc : code[t.pc]? = some (x64_ir.PInsn.Call x64_ir.PTarget.Retpoline) := by
        rw [ht]; exact e13
      obtain ⟨i, hi, hu⟩ := step_call hc hstep'
      rw [hposR] at hi
      simp only [Option.some.injEq] at hi
      subst hi
      simp only [Config.next.injEq] at hu
      subst hu
      have hra : retAddr P t = codeAddr P (p + 14) := by
        rw [retAddr, codeAddr, ht, show p + 13 + 1 = p + 14 from by omega]
      have hb : t.regs RSP - 8#64 = P.rsp0 - BitVec.ofNat 64 (8 * (pre.depth.val + 1)) := by
        rw [hk.rsp, rsp_push]
      refine Or.inl ?_
      iterate 7 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_, ?_, ?_⟩
      · rfl
      · exact kept_pushW (v := retAddr P t) hL hk (by omega)
          (fun x hxx => push_regs_ne t (retAddr P t) hxx) (by simp only [push_rsp]) rfl
      · rw [push_regs_ne t (retAddr P t) (show (RAX : Nat) ≠ RSP by decide)]
        exact hx
      · show load64 (store64 t.mem (t.regs RSP - 8#64) (retAddr P t)) _ = _
        rw [hb, hra, load64_store64_same]
    · -- the retpoline's label
      have hc : code[t.pc]? = some x64_ir.PInsn.RetpolineLabel := by rw [ht]; exact r0
      obtain ⟨hpc, hmem, hregs⟩ :=
        regOnly_next (i := .RetpolineLabel) trivial hc hstep'
      refine Or.inl ?_
      iterate 8 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_, ?_, ?_⟩
      · omega
      · exact kept_same hk (fun x => hregs x (by simp [writes])) hmem
      · rw [hregs RAX (by simp [writes])]; exact hx
      · rw [hmem]; exact hw
    · -- `call landing`
      have hc : code[t.pc]? =
          some (x64_ir.PInsn.Call (x64_ir.PTarget.Local (lbl rlabel))) := by
        rw [ht]; exact r1
      obtain ⟨i, hi, hu⟩ := step_call hc hstep'
      rw [hposA] at hi
      simp only [Option.some.injEq] at hi
      subst hi
      simp only [Config.next.injEq] at hu
      subst hu
      have hb : t.regs RSP - 8#64 = P.rsp0 - BitVec.ofNat 64 (8 * (pre.depth.val + 2)) := by
        rw [hk.rsp, show pre.depth.val + 2 = (pre.depth.val + 1) + 1 from by omega, rsp_push]
      refine Or.inl ?_
      iterate 9 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_, ?_, ?_⟩
      · rfl
      · exact kept_pushW (v := retAddr P t) hL hk (by omega)
          (fun x hxx => push_regs_ne t (retAddr P t) hxx) (by simp only [push_rsp]) rfl
      · rw [push_regs_ne t (retAddr P t) (show (RAX : Nat) ≠ RSP by decide)]
        exact hx
      · show load64 (store64 t.mem (t.regs RSP - 8#64) (retAddr P t)) _ = _
        rw [hb, load64_stack_other hL (by omega) (by omega) (by omega)]
        exact hw
    · -- the landing pad
      have hc : code[t.pc]? = some (x64_ir.PInsn.Local (lbl rlabel)) := by rw [ht]; exact r5
      obtain ⟨hpc, hmem, hregs⟩ :=
        regOnly_next (i := .Local (lbl rlabel)) trivial hc hstep'
      refine Or.inl ?_
      iterate 10 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_, ?_, ?_⟩
      · omega
      · exact kept_same hk (fun x => hregs x (by simp [writes])) hmem
      · rw [hregs RAX (by simp [writes])]; exact hx
      · rw [hmem]; exact hw
    · -- `mov [rsp], rax`: the dispatcher's address replaces the return address
      have hc : code[t.pc]? = some x64_ir.PInsn.StoreRspRax := by rw [ht]; exact r6
      have hu := step_storeRspRax hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ?_
      iterate 11 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_, ?_, ?_⟩
      · simp only [ht]
      · refine ⟨hk.rsp, hk.rbp, hk.fpv, ?_⟩
        show RoMem P (store64 t.mem (t.regs RSP) (t.regs RAX))
        rw [hk.rsp]
        exact romem_store64_stack hL hk.ro (by omega) _
      · show load64 (store64 t.mem (t.regs RSP) (t.regs RAX))
            (P.rsp0 - BitVec.ofNat 64 (8 * (pre.depth.val + 1))) = codeAddr P (p + 14)
        rw [hk.rsp, load64_stack_other hL (by omega) (by omega) (by omega)]
        exact hw
      · show load64 (store64 t.mem (t.regs RSP) (t.regs RAX)) (t.regs RSP) = P.dispatcher
        rw [load64_store64_same]
        exact hx
    · -- the retpoline's `ret`: the indirect branch into the dispatcher
      have hc : code[t.pc]? = some x64_ir.PInsn.Ret := by rw [ht]; exact r7
      rcases step_ret hc hstep' with ⟨-, hbad⟩ | ⟨-, i, hi, hval, hu⟩ | ⟨-, u, hext, hu⟩
      · simp at hbad
      · exact absurd (hz.symm.trans hval) (hdispCode i hi)
      · simp only [Config.next.injEq] at hu
        subst hu
        have hrspp : (popRsp t).regs RSP
            = P.rsp0 - BitVec.ofNat 64 (8 * (pre.depth.val + 1)) := by
          rw [popRsp_rsp, hk.rsp,
            show pre.depth.val + 2 = (pre.depth.val + 1) + 1 from by omega]
          exact rsp_pop
        have hwv : load64 (popRsp t).mem ((popRsp t).regs RSP) = codeAddr P (p + 14) := by
          rw [popRsp_mem, hrspp]; exact hw
        obtain ⟨hpc, hrsp', hkeep', hfr', hde'⟩ :=
          externalReturn_facts hlen hext (j := p + 14) (by omega) hwv
        have hs := hL.stackRoom
        have htp := rsp0_top hL
        have hbelow := hL.stackBelowFrame
        have hfs := hL.frameSlots_toNat
        have hwtn : (P.rsp0 - BitVec.ofNat 64 (8 * (pre.depth.val + 1))).toNat
            = P.rsp0.toNat - 8 * (pre.depth.val + 1) := rsp_toNat hL (by omega)
        refine Or.inl ?_
        iterate 12 refine Or.inr ?_
        refine ⟨?_, ?_⟩
        · exact Or.inl hpc
        · refine ⟨?_, ?_, ?_, ?_⟩
          · rw [hrsp', hrspp, rsp_pop]
          · rw [hkeep' RBP (by simp), popRsp_regs_ne _ (by decide)]; exact hk.rbp
          · rw [hkeep' R15 (by simp), popRsp_regs_ne _ (by decide)]; exact hk.fpv
          · refine romem_kept hL hk.ro ?_ ?_
            · intro a h1 h2 h3
              obtain ⟨hsn, hdn, hpg⟩ := frame_offRegions hL h1 h2
              rw [hfr' a (by rw [hrspp] at *; omega) h3 hsn hdn hpg, popRsp_mem]
            · intro a h1 h2
              rw [hde' a h1 h2, popRsp_mem]
    · -- the five scrubs of eBPF `r1`-`r5`
      rcases ht with ht | ht | ht | ht | ht
      · -- `xor RDI, RDI`
        have hc : code[t.pc]? =
            some (x64_ir.PInsn.Alu true x64_ir.AluRR.Xor x64_ir.RDI x64_ir.RDI) := by
          rw [ht]; exact e14
        obtain ⟨hpc, hmem, hregs⟩ := regOnly_next
          (i := .Alu true x64_ir.AluRR.Xor x64_ir.RDI x64_ir.RDI) trivial hc hstep'
        refine Or.inl ?_
        iterate 12 refine Or.inr ?_
        refine ⟨?_, ?_⟩
        · exact Or.inr (Or.inl (by omega : t'.pc = p + 15))
        · refine kept_wRegCaller (r := (x64_ir.RDI).val) hk (by rw [rdi_val]; simp [Clobbered])
            (fun x hxx => hregs x ?_) hmem
          simp only [writes, List.mem_singleton]; exact hxx
      · -- `xor RSI, RSI`
        have hc : code[t.pc]? =
            some (x64_ir.PInsn.Alu true x64_ir.AluRR.Xor x64_ir.RSI x64_ir.RSI) := by
          rw [ht]; exact e15
        obtain ⟨hpc, hmem, hregs⟩ := regOnly_next
          (i := .Alu true x64_ir.AluRR.Xor x64_ir.RSI x64_ir.RSI) trivial hc hstep'
        refine Or.inl ?_
        iterate 12 refine Or.inr ?_
        refine ⟨?_, ?_⟩
        · exact Or.inr (Or.inr (Or.inl (by omega : t'.pc = p + 16)))
        · refine kept_wRegCaller (r := (x64_ir.RSI).val) hk (by rw [rsi_val]; simp [Clobbered])
            (fun x hxx => hregs x ?_) hmem
          simp only [writes, List.mem_singleton]; exact hxx
      · -- `xor RDX, RDX`
        have hc : code[t.pc]? =
            some (x64_ir.PInsn.Alu true x64_ir.AluRR.Xor x64_ir.RDX x64_ir.RDX) := by
          rw [ht]; exact e16
        obtain ⟨hpc, hmem, hregs⟩ := regOnly_next
          (i := .Alu true x64_ir.AluRR.Xor x64_ir.RDX x64_ir.RDX) trivial hc hstep'
        refine Or.inl ?_
        iterate 12 refine Or.inr ?_
        refine ⟨?_, ?_⟩
        · exact Or.inr (Or.inr (Or.inr (Or.inl (by omega : t'.pc = p + 17))))
        · refine kept_wRegCaller (r := (x64_ir.RDX).val) hk (by rw [rdx_val]; simp [Clobbered])
            (fun x hxx => hregs x ?_) hmem
          simp only [writes, List.mem_singleton]; exact hxx
      · -- `xor R10, R10`
        have hc : code[t.pc]? =
            some (x64_ir.PInsn.Alu true x64_ir.AluRR.Xor x64_ir.R10 x64_ir.R10) := by
          rw [ht]; exact e17
        obtain ⟨hpc, hmem, hregs⟩ := regOnly_next
          (i := .Alu true x64_ir.AluRR.Xor x64_ir.R10 x64_ir.R10) trivial hc hstep'
        refine Or.inl ?_
        iterate 12 refine Or.inr ?_
        refine ⟨?_, ?_⟩
        · exact Or.inr (Or.inr (Or.inr (Or.inr ((by omega : t'.pc = p + 18)))))
        · refine kept_wRegCaller (r := (x64_ir.R10).val) hk (by rw [r10_val]; simp [Clobbered])
            (fun x hxx => hregs x ?_) hmem
          simp only [writes, List.mem_singleton]; exact hxx
      · -- `xor R8, R8`
        have hc : code[t.pc]? =
            some (x64_ir.PInsn.Alu true x64_ir.AluRR.Xor x64_ir.R8 x64_ir.R8) := by
          rw [ht]; exact e18
        obtain ⟨hpc, hmem, hregs⟩ := regOnly_next
          (i := .Alu true x64_ir.AluRR.Xor x64_ir.R8 x64_ir.R8) trivial hc hstep'
        refine Or.inr ⟨?_, ?_⟩
        · omega
        · refine kept_wRegCaller (r := (x64_ir.R8).val) hk (by rw [r8_val]; simp [Clobbered])
            (fun x hxx => hregs x ?_) hmem
          simp only [writes, List.mem_singleton]; exact hxx
  -- The walk never leaves the description.
  have hinv : ∀ s t : State, s.pc = p → Agree P pre s →
      Stays P code (fun x => Range p (p + 19) x ∨ Range rp (rp + 8) x) s t →
      HcInv P pre.depth.val p rp s t := by
    intro s t hs hag hsty
    have h0 : HcInv P pre.depth.val p rp s s := by
      simp only [HcInv]
      exact Or.inl ⟨hs, ⟨hag.rsp, hag.rbp, rfl, hag.ro⟩⟩
    refine stays_invariant (I := HcInv P pre.depth.val p rp s) h0 ?_ hsty
    intro u u' hIu hin hstepu hin'
    rcases hadv s u u' hIu hstepu with h | ⟨hq, -⟩
    · exact h
    · exact absurd (hq ▸ hin') hqout
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · -- every access the region makes is to the native stack
    intro s hs hag s' hsty c hstep' i hi bn hbn
    have hI := hinv s s' hs hag hsty
    simp only [HcInv] at hI
    rcases hI with ⟨ht, hk⟩ | ⟨ht, hk, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk, -⟩ | ⟨ht, hk, -⟩ |
      ⟨ht, hk, -⟩ | ⟨ht, hk, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk, -, -⟩ |
      ⟨ht, hk, -, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk⟩
    · rw [ht, e0] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · rw [ht, e1] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · rw [ht, e2] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · rw [ht, e10] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · rw [ht, e11] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · rw [ht, e12] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · rw [ht, e13] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_call, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · rw [ht, r0] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · rw [ht, r1] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_call, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · rw [ht, r5] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · rw [ht, r6] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_storeRspRax, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · rw [ht, r7] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_ret, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · rcases ht with ht | ht | ht | ht | ht
      · rw [ht, e14] at hi
        obtain rfl : i = _ := by simpa using hi.symm
        simp [accesses] at hbn
      · rw [ht, e15] at hi
        obtain rfl : i = _ := by simpa using hi.symm
        simp [accesses] at hbn
      · rw [ht, e16] at hi
        obtain rfl : i = _ := by simpa using hi.symm
        simp [accesses] at hbn
      · rw [ht, e17] at hi
        obtain rfl : i = _ := by simpa using hi.symm
        simp [accesses] at hbn
      · rw [ht, e18] at hi
        obtain rfl : i = _ := by simpa using hi.symm
        simp [accesses] at hbn
  · -- control leaves the region only by falling out of the last scrub
    intro s hs hag s' hsty s'' hstep' hout
    have hI := hinv s s' hs hag hsty
    rcases hadv s s' s'' hI hstep' with h | ⟨hq, hk⟩
    · exact absurd (hcInv_inside h) hout
    · exact Or.inl ⟨hq, agree_kept hag hcl hk⟩
  · -- and it never returns: the retpoline's `ret` is two words deep
    intro s hs hag s' hsty s'' hstep'
    exfalso
    have hr1 := (step_returned_ret hstep').1
    have hr2 := (step_returned_ret hstep').2.1
    have hI := hinv s s' hs hag hsty
    simp only [HcInv] at hI
    rcases hI with ⟨ht, hk⟩ | ⟨ht, hk, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk, -⟩ | ⟨ht, hk, -⟩ |
      ⟨ht, hk, -⟩ | ⟨ht, hk, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk, -, -⟩ |
      ⟨ht, hk, -, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk⟩
    · rw [ht, e0] at hr1
      simp at hr1
    · rw [ht, e1] at hr1
      simp at hr1
    · rw [ht, e2] at hr1
      simp at hr1
    · rw [ht, e10] at hr1
      simp at hr1
    · rw [ht, e11] at hr1
      simp at hr1
    · rw [ht, e12] at hr1
      simp at hr1
    · rw [ht, e13] at hr1
      simp at hr1
    · rw [ht, r0] at hr1
      simp at hr1
    · rw [ht, r1] at hr1
      simp at hr1
    · rw [ht, r5] at hr1
      simp at hr1
    · rw [ht, r6] at hr1
      simp at hr1
    · rw [hk.rsp] at hr2
      have h1 := rsp_toNat hL (P := P) (d := pre.depth.val + 2) (by omega)
      have h2 := hL.stackRoom
      have h3 := congrArg BitVec.toNat hr2
      rw [h1] at h3
      omega
    · rcases ht with ht | ht | ht | ht | ht
      · rw [ht, e14] at hr1
        simp at hr1
      · rw [ht, e15] at hr1
        simp at hr1
      · rw [ht, e16] at hr1
        simp at hr1
      · rw [ht, e17] at hr1
        simp at hr1
      · rw [ht, e18] at hr1
        simp at hr1
  · -- and every range it writes is a word of the native stack below `rsp0`
    intro s hs hag s' hsty c hstep' i hi bn hbn
    have hI := hinv s s' hs hag hsty
    simp only [HcInv] at hI
    rcases hI with ⟨ht, hk⟩ | ⟨ht, hk, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk, -⟩ | ⟨ht, hk, -⟩ |
      ⟨ht, hk, -⟩ | ⟨ht, hk, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk, -, -⟩ |
      ⟨ht, hk, -, -⟩ | ⟨ht, hk, -, -⟩ | ⟨ht, hk⟩
    · rw [ht, e0] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · rw [ht, e1] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · rw [ht, e2] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · rw [ht, e10] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · rw [ht, e11] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · rw [ht, e12] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · rw [ht, e13] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_call, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · rw [ht, r0] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · rw [ht, r1] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_call, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · rw [ht, r5] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · rw [ht, r6] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_storeRspRax, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact storeOk_stack hL (by omega) (by omega)
    · rw [ht, r7] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · rcases ht with ht | ht | ht | ht | ht
      · rw [ht, e14] at hi
        obtain rfl : i = _ := by simpa using hi.symm
        simp [stores] at hbn
      · rw [ht, e15] at hi
        obtain rfl : i = _ := by simpa using hi.symm
        simp [stores] at hbn
      · rw [ht, e16] at hi
        obtain rfl : i = _ := by simpa using hi.symm
        simp [stores] at hbn
      · rw [ht, e17] at hi
        obtain rfl : i = _ := by simpa using hi.symm
        simp [stores] at hbn
      · rw [ht, e18] at hi
        obtain rfl : i = _ := by simpa using hi.symm
        simp [stores] at hbn
  · -- and `rsp` never leaves the native stack window: the depth the
    -- description carries is two words at the deepest
    intro s hs hag s' hsty
    have hI := hinv s s' hs hag hsty
    simp only [HcInv] at hI
    rcases hI with ⟨-, hk⟩ | ⟨-, hk, -⟩ | ⟨-, hk, -, -⟩ | ⟨-, hk, -⟩ | ⟨-, hk, -⟩ |
      ⟨-, hk, -⟩ | ⟨-, hk, -⟩ | ⟨-, hk, -, -⟩ | ⟨-, hk, -, -⟩ | ⟨-, hk, -, -⟩ |
      ⟨-, hk, -, -⟩ | ⟨-, hk, -, -⟩ | ⟨-, hk⟩ <;>
      exact rsp_window_of_depth hL hk.rsp (by omega)

/-! ## The lazy local call

One contiguous run of forty-five primitives. The first eight refuse the call
when either floor is crossed; the rest spill twelve registers, ask the
resolver, enter what it returned, and unspill. -/

theorem frameOffset_val : (x64_ir.frame.FRAME_OFFSET).val = -8 := by
  rw [x64_ir.frame.FRAME_OFFSET]; decide
theorem guestFloor_val : (x64_ir.memory.LOCAL_CALL_GUEST_FLOOR).val = 144 := by
  rw [x64_ir.memory.LOCAL_CALL_GUEST_FLOOR]; decide
theorem nativeFloor_val : (x64_ir.memory.LOCAL_CALL_NATIVE_FLOOR).val = 152 := by
  rw [x64_ir.memory.LOCAL_CALL_NATIVE_FLOOR]; decide

/-- `[rbp - 8]` holds the descriptor's address. -/
theorem addr_frameOffset {P : Params} {t : State} (h : t.regs RBP = P.rbp0) :
    addr t x64_ir.RBP x64_ir.frame.FRAME_OFFSET = P.rbp0 - 8#64 := by
  simp only [addr, rbp_val, h]
  exact rbp_slot (by norm_num) (by norm_num) frameOffset_val

/-- And a field of the descriptor is read through `rcx`. -/
theorem addr_descField {P : Params} {t : State} {disp : Std.I32} (h : t.regs RCX = P.desc) :
    addr t x64_ir.RCX disp = P.desc + BitVec.signExtend 64 disp.bv := by
  simp only [addr, rcx_val, h]

theorem aluImm_subR15 (imm : Std.I32) (t : State) :
    (aluImmStep true x64_ir.AluRI.Sub x64_ir.R15 imm t).regs R15
      = t.regs R15 - BitVec.signExtend 64 imm.bv := by
  simp [aluImmStep, wRegFlags, r15_val, wr]

theorem aluImm_addR15 (imm : Std.I32) (t : State) :
    (aluImmStep true x64_ir.AluRI.Add x64_ir.R15 imm t).regs R15
      = t.regs R15 + BitVec.signExtend 64 imm.bv := by
  simp [aluImmStep, wRegFlags, r15_val, wr]

/-- A write to `r15`, the only register outside the clobbered set the
generated code ever moves. -/
theorem kept_fp {P : Params} {s t t' : State} {dd : Nat} {fp fp' : Word}
    (hk : Kept P s t dd fp) (hfp : t'.regs R15 = fp')
    (hregs : ∀ x, x ≠ R15 → t'.regs x = t.regs x) (hmem : t'.mem = t.mem) :
    Kept P s t' dd fp' := by
  refine ⟨?_, ?_, hfp, ?_⟩
  · rw [hregs RSP (by decide)]; exact hk.rsp
  · rw [hregs RBP (by decide)]; exact hk.rbp
  · rw [hmem]; exact hk.ro

/-- A pop into a register a call may clobber, which is every register the two
expansions pop: one word shallower, and nothing the description names moves. -/
theorem kept_popCaller {P : Params} {s t t' : State} {dd : Nat} {fp : Word} {r : Nat}
    (hk : Kept P s t (dd + 1) fp) (hr : Clobbered r)
    (hregs : ∀ x, x ≠ r → x ≠ RSP → t'.regs x = t.regs x)
    (hrsp : t'.regs RSP = t.regs RSP + 8#64) (hmem : t'.mem = t.mem) :
    Kept P s t' dd fp := by
  simp only [Clobbered] at hr
  have h5 : (RBP : Nat) ≠ r := by simp only [RBP]; omega
  have h15 : (R15 : Nat) ≠ r := by simp only [R15]; omega
  exact ⟨by rw [hrsp, hk.rsp, rsp_pop], by rw [hregs RBP h5 (by decide)]; exact hk.rbp,
    by rw [hregs R15 h15 (by decide)]; exact hk.fpv, by rw [hmem]; exact hk.ro⟩

/-- The two register facts a `pop` leaves behind. `pop` writes `rsp` before it
writes its destination, so the destination's update is the outer one and a
`pop rsp` would end holding the popped word. -/
theorem pop_facts (t : State) (r : Std.U8) (hr : r.val ≠ RSP) :
    (∀ x, x ≠ r.val → x ≠ RSP →
      (Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
        r.val (load64 t.mem (t.regs RSP))) x = t.regs x) ∧
    (Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
        r.val (load64 t.mem (t.regs RSP))) RSP = t.regs RSP + 8#64 := by
  refine ⟨fun x h1 h2 => ?_, ?_⟩
  · rw [Function.update_of_ne h1, Function.update_of_ne h2]
  · rw [Function.update_of_ne (Ne.symm hr), Function.update_self]

theorem regOnly_step {P code} {t t' : State} {i : x64_ir.PInsn}
    (hc : code[t.pc]? = some i) (hi : RegOnly i) (h : Step P code t (.next t')) :
    t'.pc = t.pc + 1 ∧ t'.mem = t.mem ∧ ∀ r, r ∉ writes i → t'.regs r = t.regs r :=
  regOnly_next hi hc h

@[simp] theorem accesses_callReg (r : Std.U8) (s : State) :
    accesses (.CallReg r) s = [(s.regs RSP - 8#64, 8)] := rfl

/-- The description of the lazy local call's state, position by position.
`imm` is the frame stride as the primitive layer carries it: between the
`sub r15` at position 8 and the `add r15` at position 38 the frame register is
one stride lower, and the depth walks down twelve words and back up. -/
def LzInv (P : Params) (d p : Nat) (imm : Std.I32) (s t : State) : Prop :=
  (t.pc = p ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 1 ∧ Kept P s t d (s.regs R15) ∧ t.regs RCX = P.desc) ∨
  (t.pc = p + 2 ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 3 ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 4 ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 5 ∧ Kept P s t d (s.regs R15) ∧ t.regs RCX = P.desc) ∨
  (t.pc = p + 6 ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 7 ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 8 ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 9 ∧ Kept P s t d (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 10 ∧ Kept P s t (d + 1) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 11 ∧ Kept P s t (d + 2) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 12 ∧ Kept P s t (d + 3) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 13 ∧ Kept P s t (d + 4) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 14 ∧ Kept P s t (d + 5) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 15 ∧ Kept P s t (d + 6) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 16 ∧ Kept P s t (d + 7) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 17 ∧ Kept P s t (d + 8) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 18 ∧ Kept P s t (d + 9) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 19 ∧ Kept P s t (d + 10) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 20 ∧ Kept P s t (d + 11) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 21 ∧ Kept P s t (d + 12) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 22 ∧ Kept P s t (d + 12) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 23 ∧ Kept P s t (d + 12) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 24 ∧ Kept P s t (d + 12) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 25 ∧ Kept P s t (d + 12) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 26 ∧ Kept P s t (d + 11) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 27 ∧ Kept P s t (d + 10) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 28 ∧ Kept P s t (d + 9) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 29 ∧ Kept P s t (d + 8) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 30 ∧ Kept P s t (d + 7) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 31 ∧ Kept P s t (d + 6) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 32 ∧ Kept P s t (d + 5) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 33 ∧ Kept P s t (d + 4) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 34 ∧ Kept P s t (d + 4) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 35 ∧ Kept P s t (d + 3) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 36 ∧ Kept P s t (d + 2) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 37 ∧ Kept P s t (d + 1) (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 38 ∧ Kept P s t d (s.regs R15 - BitVec.signExtend 64 imm.bv)) ∨
  (t.pc = p + 39 ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 40 ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 41 ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 42 ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 43 ∧ Kept P s t d (s.regs R15)) ∨
  (t.pc = p + 44 ∧ Kept P s t d (s.regs R15))

/-- Every position the description names is inside the macro's range. -/
theorem lzInv_inside {P : Params} {d p : Nat} {imm : Std.I32} {s t : State}
    (h : LzInv P d p imm s t) : Range p (p + 45) t.pc := by
  simp only [LzInv] at h
  simp only [Range]
  rcases h with
    ⟨ht, -⟩ | ⟨ht, -, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -, -⟩ |
    ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
    ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
    ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
    ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
    ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
    ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
    ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩
  all_goals omega

/-- `MInsn::LazyLocalCall`.

One contiguous run. The two `jb`s at positions 3 and 7 refuse the call when
the guest or the native floor is crossed and jump to the exhausted path, which
calls the embedder's non-returning callback and traps; the rest spills twelve
registers, calls the resolver, calls what it returned, unspills, and rejoins
at the `done` label, which is the run's last primitive. Both external returns
are answered by `ExternalReturn`, which is what keeps the stack pointer, `rbp`,
the frame register and the entry contract's bytes across them; what the four
unspilling `pop`s read back is nothing this proof has to say anything about,
because the state the checker's `clobber_call` leaves says `Top` of all four
registers they write. -/
theorem macroOk_lazyLocalCall {P : Params} {code : List x64_ir.PInsn} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {id : Std.U32} {index : Std.Usize} {pcv : Std.U32}
    {p label : Nat}
    (hL : Layout P) (hlen : code.length < 2 ^ 64) (hlive : pre.alive = true)
    (hstep : x64_check.live_step cfg (.LazyLocalCall id) index pcv pre = ok (.Ok (), post))
    (hE : ∀ k, k < (lazyLocalCallList cfg id label).length →
      code[p + k]? = (lazyLocalCallList cfg id label)[k]?)
    (hposExh : pos code (.Local (lbl label)) = some (p + 40))
    (hposDone : pos code (.Local (lbl (label + 1))) = some (p + 44)) :
    MacroOk P code p (p + (lazyLocalCallList cfg id label).length) pre post [] := by
  simp only [lazyLocalCallList_length]
  obtain ⟨-, -, hdep, hcl⟩ := live_step_LazyLocalCall_spec hlive hstep
  have e0 : code[p]? = some
      (x64_ir.PInsn.Load 8#u8 false x64_ir.RBP x64_ir.RCX
      x64_ir.frame.FRAME_OFFSET) :=
    hE 0 (by rw [lazyLocalCallList_length]; norm_num)
  have e1 : code[p + 1]? = some
      (x64_ir.PInsn.Load 8#u8 false x64_ir.RCX x64_ir.RCX
      x64_ir.memory.LOCAL_CALL_GUEST_FLOOR) :=
    hE 1 (by rw [lazyLocalCallList_length]; norm_num)
  have e2 : code[p + 2]? = some
      (x64_ir.PInsn.Alu true x64_ir.AluRR.Cmp x64_ir.RCX x64_ir.R15) :=
    hE 2 (by rw [lazyLocalCallList_length]; norm_num)
  have e3 : code[p + 3]? = some
      (x64_ir.PInsn.Jcc x64_ir.cc.B (x64_ir.PTarget.Local (lbl label))) :=
    hE 3 (by rw [lazyLocalCallList_length]; norm_num)
  have e4 : code[p + 4]? = some
      (x64_ir.PInsn.Load 8#u8 false x64_ir.RBP x64_ir.RCX
      x64_ir.frame.FRAME_OFFSET) :=
    hE 4 (by rw [lazyLocalCallList_length]; norm_num)
  have e5 : code[p + 5]? = some
      (x64_ir.PInsn.Load 8#u8 false x64_ir.RCX x64_ir.RCX
      x64_ir.memory.LOCAL_CALL_NATIVE_FLOOR) :=
    hE 5 (by rw [lazyLocalCallList_length]; norm_num)
  have e6 : code[p + 6]? = some
      (x64_ir.PInsn.Alu true x64_ir.AluRR.Cmp x64_ir.RCX x64_ir.RSP) :=
    hE 6 (by rw [lazyLocalCallList_length]; norm_num)
  have e7 : code[p + 7]? = some
      (x64_ir.PInsn.Jcc x64_ir.cc.B (x64_ir.PTarget.Local (lbl label))) :=
    hE 7 (by rw [lazyLocalCallList_length]; norm_num)
  have e8 : code[p + 8]? = some
      (x64_ir.PInsn.AluImm true x64_ir.AluRI.Sub x64_ir.R15
      (UScalar.hcast .I32 cfg.stack_frame_stride)) :=
    hE 8 (by rw [lazyLocalCallList_length]; norm_num)
  have e9 : code[p + 9]? = some
      (x64_ir.PInsn.Push x64_ir.RBX) :=
    hE 9 (by rw [lazyLocalCallList_length]; norm_num)
  have e10 : code[p + 10]? = some
      (x64_ir.PInsn.Push x64_ir.R12) :=
    hE 10 (by rw [lazyLocalCallList_length]; norm_num)
  have e11 : code[p + 11]? = some
      (x64_ir.PInsn.Push x64_ir.R13) :=
    hE 11 (by rw [lazyLocalCallList_length]; norm_num)
  have e12 : code[p + 12]? = some
      (x64_ir.PInsn.Push x64_ir.R14) :=
    hE 12 (by rw [lazyLocalCallList_length]; norm_num)
  have e13 : code[p + 13]? = some
      (x64_ir.PInsn.Push x64_ir.RDI) :=
    hE 13 (by rw [lazyLocalCallList_length]; norm_num)
  have e14 : code[p + 14]? = some
      (x64_ir.PInsn.Push x64_ir.RSI) :=
    hE 14 (by rw [lazyLocalCallList_length]; norm_num)
  have e15 : code[p + 15]? = some
      (x64_ir.PInsn.Push x64_ir.RDX) :=
    hE 15 (by rw [lazyLocalCallList_length]; norm_num)
  have e16 : code[p + 16]? = some
      (x64_ir.PInsn.Push x64_ir.R10) :=
    hE 16 (by rw [lazyLocalCallList_length]; norm_num)
  have e17 : code[p + 17]? = some
      (x64_ir.PInsn.Push x64_ir.R8) :=
    hE 17 (by rw [lazyLocalCallList_length]; norm_num)
  have e18 : code[p + 18]? = some
      (x64_ir.PInsn.Push x64_ir.VOLATILE_CTXT) :=
    hE 18 (by rw [lazyLocalCallList_length]; norm_num)
  have e19 : code[p + 19]? = some
      (x64_ir.PInsn.Push x64_ir.RAX) :=
    hE 19 (by rw [lazyLocalCallList_length]; norm_num)
  have e20 : code[p + 20]? = some
      (x64_ir.PInsn.Push x64_ir.RAX) :=
    hE 20 (by rw [lazyLocalCallList_length]; norm_num)
  have e21 : code[p + 21]? = some
      (x64_ir.PInsn.LoadImm x64_ir.RDI (UScalar.hcast .I64 (UScalar.cast .U64 id))) :=
    hE 21 (by rw [lazyLocalCallList_length]; norm_num)
  have e22 : code[p + 22]? = some
      (x64_ir.PInsn.LoadImm x64_ir.RAX (UScalar.hcast .I64 cfg.local_call_resolver)) :=
    hE 22 (by rw [lazyLocalCallList_length]; norm_num)
  have e23 : code[p + 23]? = some
      (x64_ir.PInsn.CallReg x64_ir.RAX) :=
    hE 23 (by rw [lazyLocalCallList_length]; norm_num)
  have e24 : code[p + 24]? = some
      (x64_ir.PInsn.Alu true x64_ir.AluRR.Mov x64_ir.RAX x64_ir.RCX) :=
    hE 24 (by rw [lazyLocalCallList_length]; norm_num)
  have e25 : code[p + 25]? = some
      (x64_ir.PInsn.Pop x64_ir.RAX) :=
    hE 25 (by rw [lazyLocalCallList_length]; norm_num)
  have e26 : code[p + 26]? = some
      (x64_ir.PInsn.Pop x64_ir.RAX) :=
    hE 26 (by rw [lazyLocalCallList_length]; norm_num)
  have e27 : code[p + 27]? = some
      (x64_ir.PInsn.Pop x64_ir.VOLATILE_CTXT) :=
    hE 27 (by rw [lazyLocalCallList_length]; norm_num)
  have e28 : code[p + 28]? = some
      (x64_ir.PInsn.Pop x64_ir.R8) :=
    hE 28 (by rw [lazyLocalCallList_length]; norm_num)
  have e29 : code[p + 29]? = some
      (x64_ir.PInsn.Pop x64_ir.R10) :=
    hE 29 (by rw [lazyLocalCallList_length]; norm_num)
  have e30 : code[p + 30]? = some
      (x64_ir.PInsn.Pop x64_ir.RDX) :=
    hE 30 (by rw [lazyLocalCallList_length]; norm_num)
  have e31 : code[p + 31]? = some
      (x64_ir.PInsn.Pop x64_ir.RSI) :=
    hE 31 (by rw [lazyLocalCallList_length]; norm_num)
  have e32 : code[p + 32]? = some
      (x64_ir.PInsn.Pop x64_ir.RDI) :=
    hE 32 (by rw [lazyLocalCallList_length]; norm_num)
  have e33 : code[p + 33]? = some
      (x64_ir.PInsn.CallReg x64_ir.RCX) :=
    hE 33 (by rw [lazyLocalCallList_length]; norm_num)
  have e34 : code[p + 34]? = some
      (x64_ir.PInsn.Pop x64_ir.R14) :=
    hE 34 (by rw [lazyLocalCallList_length]; norm_num)
  have e35 : code[p + 35]? = some
      (x64_ir.PInsn.Pop x64_ir.R13) :=
    hE 35 (by rw [lazyLocalCallList_length]; norm_num)
  have e36 : code[p + 36]? = some
      (x64_ir.PInsn.Pop x64_ir.R12) :=
    hE 36 (by rw [lazyLocalCallList_length]; norm_num)
  have e37 : code[p + 37]? = some
      (x64_ir.PInsn.Pop x64_ir.RBX) :=
    hE 37 (by rw [lazyLocalCallList_length]; norm_num)
  have e38 : code[p + 38]? = some
      (x64_ir.PInsn.AluImm true x64_ir.AluRI.Add x64_ir.R15
      (UScalar.hcast .I32 cfg.stack_frame_stride)) :=
    hE 38 (by rw [lazyLocalCallList_length]; norm_num)
  have e39 : code[p + 39]? = some
      (x64_ir.PInsn.Jmp (x64_ir.PTarget.Local (lbl (label + 1)))) :=
    hE 39 (by rw [lazyLocalCallList_length]; norm_num)
  have e40 : code[p + 40]? = some
      (x64_ir.PInsn.Local (lbl label)) :=
    hE 40 (by rw [lazyLocalCallList_length]; norm_num)
  have e41 : code[p + 41]? = some
      (x64_ir.PInsn.LoadImm x64_ir.RAX
      (UScalar.hcast .I64 cfg.local_call_stack_exhausted)) :=
    hE 41 (by rw [lazyLocalCallList_length]; norm_num)
  have e42 : code[p + 42]? = some
      (x64_ir.PInsn.CallReg x64_ir.RAX) :=
    hE 42 (by rw [lazyLocalCallList_length]; norm_num)
  have e43 : code[p + 43]? = some
      (x64_ir.PInsn.Ud2) :=
    hE 43 (by rw [lazyLocalCallList_length]; norm_num)
  have e44 : code[p + 44]? = some
      (x64_ir.PInsn.Local (lbl (label + 1))) :=
    hE 44 (by rw [lazyLocalCallList_length]; norm_num)
  have hqout : ¬ Range p (p + 45) (p + 45) := by simp only [Range]; omega
  -- One step of the expansion.
  have hadv : ∀ s t t' : State,
      LzInv P pre.depth.val p (UScalar.hcast .I32 cfg.stack_frame_stride) s t →
      Step P code t (.next t') →
      LzInv P pre.depth.val p (UScalar.hcast .I32 cfg.stack_frame_stride) s t' ∨
        (t'.pc = p + 45 ∧ Kept P s t' pre.depth.val (s.regs R15)) := by
    intro s t t' hI hstep'
    simp only [LzInv] at hI ⊢
    rcases hI with
      ⟨ht, hk⟩ | ⟨ht, hk, hrcx⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk, hrcx⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩
    · -- position 0
      have hc := e0
      rw [← ht] at hc
      rcases step_load hc hstep' with ⟨-, hu⟩ | ⟨hbad, -, -⟩
      · simp only [Config.next.injEq] at hu
        subst hu
        refine Or.inl ?_
        iterate 1 refine Or.inr ?_
        refine Or.inl ⟨?_, ?_, ?_⟩
        · simp only [wReg]; omega
        · exact kept_wRegCaller (r := (x64_ir.RCX).val) hk
            (by rw [rcx_val]; simp [Clobbered])
            (fun x hxx => by simp only [wReg, Function.update_of_ne hxx]) rfl
        · show (wReg t x64_ir.RCX (loadExt (8#u8 : Std.U8).val false t.mem
            (addr t x64_ir.RBP x64_ir.frame.FRAME_OFFSET))).regs RCX = P.desc
          simp only [wReg, rcx_val, Function.update_self]
          rw [show ((8#u8 : Std.U8).val) = 8 from rfl, loadExt_eight,
            addr_frameOffset hk.rbp]
          exact hk.ro.descSlot
      · simp at hbad
    · -- position 1
      have hc := e1
      rw [← ht] at hc
      rcases step_load hc hstep' with ⟨-, hu⟩ | ⟨hbad, -, -⟩
      · simp only [Config.next.injEq] at hu
        subst hu
        refine Or.inl ?_
        iterate 2 refine Or.inr ?_
        refine Or.inl ⟨?_, ?_⟩
        · simp only [wReg]; omega
        · exact kept_wRegCaller (r := (x64_ir.RCX).val) hk
            (by rw [rcx_val]; simp [Clobbered])
            (fun x hxx => by simp only [wReg, Function.update_of_ne hxx]) rfl
      · simp at hbad
    · -- position 2
      have hc := e2
      rw [← ht] at hc
      have hu := step_alu hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ?_
      iterate 3 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_⟩
      · simp only [aluRRStep_pc]; omega
      · exact kept_same hk (fun x => by simp only [aluRRStep, wFlags]) rfl
    · -- position 3
      have hc := e3
      rw [← ht] at hc
      rcases step_jcc hc hstep' with ⟨-, i, hi, hu⟩ | ⟨-, hu⟩
      · rw [hposExh] at hi
        simp only [Option.some.injEq] at hi
        subst hi
        simp only [Config.next.injEq] at hu
        subst hu
        refine Or.inl ?_
        iterate 40 refine Or.inr ?_
        exact Or.inl ⟨rfl, kept_same hk (fun x => rfl) rfl⟩
      · simp only [Config.next.injEq] at hu
        subst hu
        refine Or.inl ?_
        iterate 4 refine Or.inr ?_
        exact Or.inl ⟨by simp only [wNext]; omega, kept_same hk (fun x => rfl) rfl⟩
    · -- position 4
      have hc := e4
      rw [← ht] at hc
      rcases step_load hc hstep' with ⟨-, hu⟩ | ⟨hbad, -, -⟩
      · simp only [Config.next.injEq] at hu
        subst hu
        refine Or.inl ?_
        iterate 5 refine Or.inr ?_
        refine Or.inl ⟨?_, ?_, ?_⟩
        · simp only [wReg]; omega
        · exact kept_wRegCaller (r := (x64_ir.RCX).val) hk
            (by rw [rcx_val]; simp [Clobbered])
            (fun x hxx => by simp only [wReg, Function.update_of_ne hxx]) rfl
        · show (wReg t x64_ir.RCX (loadExt (8#u8 : Std.U8).val false t.mem
            (addr t x64_ir.RBP x64_ir.frame.FRAME_OFFSET))).regs RCX = P.desc
          simp only [wReg, rcx_val, Function.update_self]
          rw [show ((8#u8 : Std.U8).val) = 8 from rfl, loadExt_eight,
            addr_frameOffset hk.rbp]
          exact hk.ro.descSlot
      · simp at hbad
    · -- position 5
      have hc := e5
      rw [← ht] at hc
      rcases step_load hc hstep' with ⟨-, hu⟩ | ⟨hbad, -, -⟩
      · simp only [Config.next.injEq] at hu
        subst hu
        refine Or.inl ?_
        iterate 6 refine Or.inr ?_
        refine Or.inl ⟨?_, ?_⟩
        · simp only [wReg]; omega
        · exact kept_wRegCaller (r := (x64_ir.RCX).val) hk
            (by rw [rcx_val]; simp [Clobbered])
            (fun x hxx => by simp only [wReg, Function.update_of_ne hxx]) rfl
      · simp at hbad
    · -- position 6
      have hc := e6
      rw [← ht] at hc
      have hu := step_alu hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ?_
      iterate 7 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_⟩
      · simp only [aluRRStep_pc]; omega
      · exact kept_same hk (fun x => by simp only [aluRRStep, wFlags]) rfl
    · -- position 7
      have hc := e7
      rw [← ht] at hc
      rcases step_jcc hc hstep' with ⟨-, i, hi, hu⟩ | ⟨-, hu⟩
      · rw [hposExh] at hi
        simp only [Option.some.injEq] at hi
        subst hi
        simp only [Config.next.injEq] at hu
        subst hu
        refine Or.inl ?_
        iterate 40 refine Or.inr ?_
        exact Or.inl ⟨rfl, kept_same hk (fun x => rfl) rfl⟩
      · simp only [Config.next.injEq] at hu
        subst hu
        refine Or.inl ?_
        iterate 8 refine Or.inr ?_
        exact Or.inl ⟨by simp only [wNext]; omega, kept_same hk (fun x => rfl) rfl⟩
    · -- position 8
      have hc := e8
      rw [← ht] at hc
      have hu := step_aluImm hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ?_
      iterate 9 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_⟩
      · simp only [aluImmStep_pc]; omega
      · refine kept_fp hk ?_ (fun x hxx =>
          aluImmStep_regs_ne _ _ _ _ _ (by rw [r15_val]; exact hxx)) rfl
        rw [aluImm_subR15, hk.fpv]
    · -- position 9
      have hc := e9
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.RBX).val))
        (v := t.regs (x64_ir.RBX).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.RBX).val) hxx)
        (push_rsp t (t.regs (x64_ir.RBX).val)) (push_mem t (t.regs (x64_ir.RBX).val))
      refine Or.inl ?_
      iterate 10 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 10
      have hc := e10
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.R12).val))
        (v := t.regs (x64_ir.R12).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.R12).val) hxx)
        (push_rsp t (t.regs (x64_ir.R12).val)) (push_mem t (t.regs (x64_ir.R12).val))
      refine Or.inl ?_
      iterate 11 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 11
      have hc := e11
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.R13).val))
        (v := t.regs (x64_ir.R13).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.R13).val) hxx)
        (push_rsp t (t.regs (x64_ir.R13).val)) (push_mem t (t.regs (x64_ir.R13).val))
      refine Or.inl ?_
      iterate 12 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 12
      have hc := e12
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.R14).val))
        (v := t.regs (x64_ir.R14).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.R14).val) hxx)
        (push_rsp t (t.regs (x64_ir.R14).val)) (push_mem t (t.regs (x64_ir.R14).val))
      refine Or.inl ?_
      iterate 13 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 13
      have hc := e13
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.RDI).val))
        (v := t.regs (x64_ir.RDI).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.RDI).val) hxx)
        (push_rsp t (t.regs (x64_ir.RDI).val)) (push_mem t (t.regs (x64_ir.RDI).val))
      refine Or.inl ?_
      iterate 14 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 14
      have hc := e14
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.RSI).val))
        (v := t.regs (x64_ir.RSI).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.RSI).val) hxx)
        (push_rsp t (t.regs (x64_ir.RSI).val)) (push_mem t (t.regs (x64_ir.RSI).val))
      refine Or.inl ?_
      iterate 15 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 15
      have hc := e15
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.RDX).val))
        (v := t.regs (x64_ir.RDX).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.RDX).val) hxx)
        (push_rsp t (t.regs (x64_ir.RDX).val)) (push_mem t (t.regs (x64_ir.RDX).val))
      refine Or.inl ?_
      iterate 16 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 16
      have hc := e16
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.R10).val))
        (v := t.regs (x64_ir.R10).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.R10).val) hxx)
        (push_rsp t (t.regs (x64_ir.R10).val)) (push_mem t (t.regs (x64_ir.R10).val))
      refine Or.inl ?_
      iterate 17 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 17
      have hc := e17
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.R8).val))
        (v := t.regs (x64_ir.R8).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.R8).val) hxx)
        (push_rsp t (t.regs (x64_ir.R8).val)) (push_mem t (t.regs (x64_ir.R8).val))
      refine Or.inl ?_
      iterate 18 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 18
      have hc := e18
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.VOLATILE_CTXT).val))
        (v := t.regs (x64_ir.VOLATILE_CTXT).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.VOLATILE_CTXT).val) hxx)
        (push_rsp t (t.regs (x64_ir.VOLATILE_CTXT).val))
        (push_mem t (t.regs (x64_ir.VOLATILE_CTXT).val))
      refine Or.inl ?_
      iterate 19 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 19
      have hc := e19
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.RAX).val))
        (v := t.regs (x64_ir.RAX).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.RAX).val) hxx)
        (push_rsp t (t.regs (x64_ir.RAX).val)) (push_mem t (t.regs (x64_ir.RAX).val))
      refine Or.inl ?_
      iterate 20 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 20
      have hc := e20
      rw [← ht] at hc
      have hu := step_push hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      have h2 := kept_pushW (t' := push t (t.regs (x64_ir.RAX).val))
        (v := t.regs (x64_ir.RAX).val) hL hk (by omega)
        (fun x hxx => push_regs_ne t (t.regs (x64_ir.RAX).val) hxx)
        (push_rsp t (t.regs (x64_ir.RAX).val)) (push_mem t (t.regs (x64_ir.RAX).val))
      refine Or.inl ?_
      iterate 21 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega,
        kept_same h2 (fun x => rfl) rfl⟩
    · -- position 21
      have hc := e21
      rw [← ht] at hc
      obtain ⟨hpc, hmem, hregs⟩ := regOnly_step hc trivial hstep'
      refine Or.inl ?_
      iterate 22 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_⟩
      · omega
      · refine kept_wRegCaller (r := (x64_ir.RDI).val) hk
          (by rw [rdi_val]; simp [Clobbered]) (fun x hxx => hregs x ?_) hmem
        simp only [writes, List.mem_singleton]; exact hxx
    · -- position 22
      have hc := e22
      rw [← ht] at hc
      obtain ⟨hpc, hmem, hregs⟩ := regOnly_step hc trivial hstep'
      refine Or.inl ?_
      iterate 23 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_⟩
      · omega
      · refine kept_wRegCaller (r := (x64_ir.RAX).val) hk
          (by rw [rax_val]; simp [Clobbered]) (fun x hxx => hregs x ?_) hmem
        simp only [writes, List.mem_singleton]; exact hxx
    · -- position 23
      have hc := e23
      rw [← ht] at hc
      obtain ⟨hpc, hka⟩ :=
        kept_callReg hL hlen hk (by omega) hc hstep'
      refine Or.inl ?_
      iterate 24 refine Or.inr ?_
      exact Or.inl ⟨by omega, hka⟩
    · -- position 24
      have hc := e24
      rw [← ht] at hc
      have hu := step_alu hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ?_
      iterate 25 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_⟩
      · simp only [aluRRStep_pc]; omega
      · exact kept_wRegCaller (r := (x64_ir.RCX).val) hk
          (by rw [rcx_val]; simp [Clobbered])
          (fun x hxx => aluRRStep_regs_ne _ _ _ _ _ hxx) rfl
    · -- position 25
      have hc := e25
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.RAX (by rw [rax_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.RAX).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val + 11) (r := (x64_ir.RAX).val) hk
        (by rw [rax_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 26 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 26
      have hc := e26
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.RAX (by rw [rax_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.RAX).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val + 10) (r := (x64_ir.RAX).val) hk
        (by rw [rax_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 27 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 27
      have hc := e27
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.VOLATILE_CTXT (by rw [ctxt_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.VOLATILE_CTXT).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val + 9) (r := (x64_ir.VOLATILE_CTXT).val) hk
        (by rw [ctxt_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 28 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 28
      have hc := e28
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.R8 (by rw [r8_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.R8).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val + 8) (r := (x64_ir.R8).val) hk
        (by rw [r8_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 29 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 29
      have hc := e29
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.R10 (by rw [r10_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.R10).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val + 7) (r := (x64_ir.R10).val) hk
        (by rw [r10_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 30 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 30
      have hc := e30
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.RDX (by rw [rdx_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.RDX).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val + 6) (r := (x64_ir.RDX).val) hk
        (by rw [rdx_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 31 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 31
      have hc := e31
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.RSI (by rw [rsi_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.RSI).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val + 5) (r := (x64_ir.RSI).val) hk
        (by rw [rsi_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 32 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 32
      have hc := e32
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.RDI (by rw [rdi_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.RDI).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val + 4) (r := (x64_ir.RDI).val) hk
        (by rw [rdi_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 33 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 33
      have hc := e33
      rw [← ht] at hc
      obtain ⟨hpc, hka⟩ :=
        kept_callReg hL hlen hk (by omega) hc hstep'
      refine Or.inl ?_
      iterate 34 refine Or.inr ?_
      exact Or.inl ⟨by omega, hka⟩
    · -- position 34
      have hc := e34
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.R14 (by rw [r14_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.R14).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val + 3) (r := (x64_ir.R14).val) hk
        (by rw [r14_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 35 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 35
      have hc := e35
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.R13 (by rw [r13_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.R13).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val + 2) (r := (x64_ir.R13).val) hk
        (by rw [r13_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 36 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 36
      have hc := e36
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.R12 (by rw [r12_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.R12).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val + 1) (r := (x64_ir.R12).val) hk
        (by rw [r12_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 37 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 37
      have hc := e37
      rw [← ht] at hc
      have hu := step_pop hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨g1, g3⟩ := pop_facts t x64_ir.RBX (by rw [rbx_val]; decide)
      have hka := kept_popCaller
        (t' := { t with
          regs := Function.update (Function.update t.regs RSP (t.regs RSP + 8#64))
            (x64_ir.RBX).val (load64 t.mem (t.regs RSP)),
          pc := t.pc + 1 })
        (dd := pre.depth.val) (r := (x64_ir.RBX).val) hk
        (by rw [rbx_val]; simp [Clobbered]) g1 g3 rfl
      refine Or.inl ?_
      iterate 38 refine Or.inr ?_
      exact Or.inl ⟨by simp only []; omega, hka⟩
    · -- position 38
      have hc := e38
      rw [← ht] at hc
      have hu := step_aluImm hc hstep'
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ?_
      iterate 39 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_⟩
      · simp only [aluImmStep_pc]; omega
      · refine kept_fp hk ?_ (fun x hxx =>
          aluImmStep_regs_ne _ _ _ _ _ (by rw [r15_val]; exact hxx)) rfl
        rw [aluImm_addR15, hk.fpv]
        ring
    · -- position 39
      have hc := e39
      rw [← ht] at hc
      obtain ⟨i, hi, hu⟩ := step_jmp hc hstep'
      rw [hposDone] at hi
      simp only [Option.some.injEq] at hi
      subst hi
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ?_
      iterate 44 refine Or.inr ?_
      exact ⟨rfl, kept_same hk (fun x => rfl) rfl⟩
    · -- position 40
      have hc := e40
      rw [← ht] at hc
      obtain ⟨hpc, hmem, hregs⟩ := regOnly_step hc trivial hstep'
      refine Or.inl ?_
      iterate 41 refine Or.inr ?_
      exact Or.inl ⟨by omega,
        kept_same hk (fun x => hregs x (by simp [writes])) hmem⟩
    · -- position 41
      have hc := e41
      rw [← ht] at hc
      obtain ⟨hpc, hmem, hregs⟩ := regOnly_step hc trivial hstep'
      refine Or.inl ?_
      iterate 42 refine Or.inr ?_
      refine Or.inl ⟨?_, ?_⟩
      · omega
      · refine kept_wRegCaller (r := (x64_ir.RAX).val) hk
          (by rw [rax_val]; simp [Clobbered]) (fun x hxx => hregs x ?_) hmem
        simp only [writes, List.mem_singleton]; exact hxx
    · -- position 42
      have hc := e42
      rw [← ht] at hc
      obtain ⟨hpc, hka⟩ :=
        kept_callReg hL hlen hk (by omega) hc hstep'
      refine Or.inl ?_
      iterate 43 refine Or.inr ?_
      exact Or.inl ⟨by omega, hka⟩
    · -- position 43
      have hc := e43
      rw [← ht] at hc
      have hu := step_ud2 hc hstep'
      simp at hu
    · -- position 44
      have hc := e44
      rw [← ht] at hc
      obtain ⟨hpc, hmem, hregs⟩ := regOnly_step hc trivial hstep'
      exact Or.inr ⟨by omega,
        kept_same hk (fun x => hregs x (by simp [writes])) hmem⟩
  -- The walk never leaves the description.
  have hinv : ∀ s t : State, s.pc = p → Agree P pre s →
      Stays P code (Range p (p + 45)) s t →
      LzInv P pre.depth.val p (UScalar.hcast .I32 cfg.stack_frame_stride) s t := by
    intro s t hs hag hsty
    have h0 : LzInv P pre.depth.val p
        (UScalar.hcast .I32 cfg.stack_frame_stride) s s := by
      simp only [LzInv]
      exact Or.inl ⟨hs, ⟨hag.rsp, hag.rbp, rfl, hag.ro⟩⟩
    refine stays_invariant
      (I := LzInv P pre.depth.val p (UScalar.hcast .I32 cfg.stack_frame_stride) s) h0 ?_ hsty
    intro u u' hIu hin hstepu hin'
    rcases hadv s u u' hIu hstepu with h | ⟨hq, -⟩
    · exact h
    · exact absurd (hq ▸ hin') hqout
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · -- every access is to the frame scratch, the descriptor or the native stack
    intro s hs hag s' hsty c hstep' i hi bn hbn
    have hI := hinv s s' hs hag hsty
    simp only [LzInv] at hI
    rcases hI with
      ⟨ht, hk⟩ | ⟨ht, hk, hrcx⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk, hrcx⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩
    · have hc := e0
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_load] at hbn
      rw [if_neg (by simp)] at hbn
      simp only [List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (addr s' x64_ir.RBP x64_ir.frame.FRAME_OFFSET) (8#u8 : Std.U8).val
      rw [show ((8#u8 : Std.U8).val) = 8 from rfl, addr, rbp_val, hk.rbp]
      exact frame_slot_ok hL (by rw [frameOffset_val]; norm_num)
        (by rw [frameOffset_val]; norm_num)
    · have hc := e1
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_load] at hbn
      rw [if_neg (by simp)] at hbn
      simp only [List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (addr s' x64_ir.RCX x64_ir.memory.LOCAL_CALL_GUEST_FLOOR) (8#u8 : Std.U8).val
      rw [show ((8#u8 : Std.U8).val) = 8 from rfl, addr_descField hrcx]
      exact desc_field_ok hL (by rw [guestFloor_val]; norm_num) (by rw [guestFloor_val]; norm_num)
    · have hc := e2
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e3
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e4
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_load] at hbn
      rw [if_neg (by simp)] at hbn
      simp only [List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (addr s' x64_ir.RBP x64_ir.frame.FRAME_OFFSET) (8#u8 : Std.U8).val
      rw [show ((8#u8 : Std.U8).val) = 8 from rfl, addr, rbp_val, hk.rbp]
      exact frame_slot_ok hL (by rw [frameOffset_val]; norm_num)
        (by rw [frameOffset_val]; norm_num)
    · have hc := e5
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_load] at hbn
      rw [if_neg (by simp)] at hbn
      simp only [List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (addr s' x64_ir.RCX x64_ir.memory.LOCAL_CALL_NATIVE_FLOOR) (8#u8 : Std.U8).val
      rw [show ((8#u8 : Std.U8).val) = 8 from rfl, addr_descField hrcx]
      exact desc_field_ok hL (by rw [nativeFloor_val]; norm_num) (by rw [nativeFloor_val]; norm_num)
    · have hc := e6
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e7
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e8
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e9
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e10
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e11
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e12
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e13
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e14
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e15
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e16
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e17
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e18
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e19
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e20
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_push, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e21
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e22
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e23
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_callReg, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e24
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e25
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e26
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e27
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e28
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e29
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e30
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e31
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e32
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e33
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_callReg, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e34
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e35
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e36
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e37
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_pop, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP) 8
      rw [hk.rsp]
      exact stack_slot_ok hL (by omega)
    · have hc := e38
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e39
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e40
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e41
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e42
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [accesses_callReg, List.mem_singleton] at hbn
      subst hbn
      show AccessOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact stack_slot_ok hL (by omega)
    · have hc := e43
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
    · have hc := e44
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [accesses] at hbn
  · -- control leaves the region only by falling out of the `done` label
    intro s hs hag s' hsty s'' hstep' hout
    have hI := hinv s s' hs hag hsty
    rcases hadv s s' s'' hI hstep' with h | ⟨hq, hk⟩
    · exact absurd (lzInv_inside h) hout
    · exact Or.inl ⟨hq, agree_kept hag hcl hk⟩
  · -- and it never returns: the expansion carries no `ret`
    intro s hs hag s' hsty s'' hstep'
    exfalso
    have hr1 := (step_returned_ret hstep').1
    have hI := hinv s s' hs hag hsty
    simp only [LzInv] at hI
    rcases hI with
      ⟨ht, -⟩ | ⟨ht, -, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -, -⟩ |
      ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
      ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
      ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
      ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
      ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
      ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩ |
      ⟨ht, -⟩ | ⟨ht, -⟩ | ⟨ht, -⟩
    · have hc := e0
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e1
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e2
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e3
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e4
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e5
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e6
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e7
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e8
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e9
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e10
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e11
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e12
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e13
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e14
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e15
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e16
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e17
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e18
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e19
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e20
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e21
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e22
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e23
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e24
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e25
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e26
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e27
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e28
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e29
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e30
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e31
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e32
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e33
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e34
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e35
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e36
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e37
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e38
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e39
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e40
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e41
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e42
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e43
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
    · have hc := e44
      rw [← ht] at hc
      rw [hc] at hr1
      simp at hr1
  · -- and every range it writes is one of the thirteen words its own
    -- pushes and calls put below `rsp0`
    intro s hs hag s' hsty c hstep' i hi bn hbn
    have hI := hinv s s' hs hag hsty
    simp only [LzInv] at hI
    rcases hI with
      ⟨ht, hk⟩ | ⟨ht, hk, -⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk, -⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ |
      ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩ | ⟨ht, hk⟩
    · have hc := e0
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e1
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e2
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e3
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e4
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e5
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e6
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e7
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e8
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e9
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e10
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e11
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e12
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e13
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e14
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e15
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e16
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e17
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e18
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e19
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e20
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_push, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e21
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e22
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e23
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_callReg, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e24
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e25
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e26
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e27
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e28
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e29
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e30
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e31
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e32
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e33
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_callReg, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e34
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e35
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e36
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e37
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e38
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e39
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e40
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e41
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e42
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp only [stores_callReg, List.mem_singleton] at hbn
      subst hbn
      show StoreOk P (s'.regs RSP - 8#64) 8
      rw [hk.rsp, rsp_push]
      exact storeOk_stack hL (by omega) (by omega)
    · have hc := e43
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
    · have hc := e44
      rw [← ht] at hc
      rw [hc] at hi
      obtain rfl : i = _ := by simpa using hi.symm
      simp [stores] at hbn
  · -- and `rsp` never leaves the native stack window: the depth the
    -- description carries walks down twelve words and back up
    intro s hs hag s' hsty
    have hI := hinv s s' hs hag hsty
    simp only [LzInv] at hI
    rcases hI with
      ⟨-, hk⟩ | ⟨-, hk, -⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ |
      ⟨-, hk, -⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ |
      ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ |
      ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ |
      ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ |
      ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ |
      ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ |
      ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ | ⟨-, hk⟩ <;>
      exact rsp_window_of_depth hL hk.rsp (by omega)

end CallSupport

/-! ## What the glue reads

The two macro lemmas, the statement the helper call's is phrased in, and the
three lists, back under `X64`. -/

export CallSupport (MacroOkIn macroOkIn_helperCall macroOk_lazyLocalCall
  lbl helperCallList retpolineList lazyLocalCallList
  helperCallList_length retpolineList_length lazyLocalCallList_length)

end X64

end async_ebpf_verified

import AsyncEbpf.X64.Abs

/-!
# Running one macro's expansion

Two things live here: the shape of a single primitive step, and the statement
every per-macro lemma proves.

## The macro lemma template

`expand` turns each macro into a contiguous run of primitives, so a macro
occupies a range `[p, q)` of the primitive list. `MacroOk P code p q pre post
exits` is what a proof about that range establishes, and it is the *same*
statement for every macro, with the macro's operands symbolic:

```
structure MacroOk (P : Params) (code : List x64_ir.PInsn) (p q : Nat)
    (pre post : x64_check.State) (exits : List (Nat × x64_check.State)) : Prop where
  safe : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code (Range p q) s s' →
    ∀ c, Step P code s' c → ∀ i, code[s'.pc]? = some i → ∀ bn ∈ accesses i s', AccessOk P bn.1 bn.2
  leave : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code (Range p q) s s' →
    ∀ s'', Step P code s' (.next s'') → ¬ Range p q s''.pc →
      (s''.pc = q ∧ Agree P post s'') ∨ (∃ e ∈ exits, s''.pc = e.1 ∧ Agree P e.2 s'')
  returns : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code (Range p q) s s' →
    ∀ s'', Step P code s' (.returned s'') →
      s''.regs RSP = P.rsp0 + 8#64 ∧ s''.regs RBP = P.rbp0 ∧ s''.regs R15 = P.fp0
```

Read it as: started at the macro's first primitive from a state the checker's
*pre*-state describes, every step the expansion takes is safe; control leaves
the range only by falling through to `q`, where the checker's *post*-state
describes it, or to one of the listed exits, where the state listed with it
does; and if the expansion returns, it returns under the contract.

`Stays P code inside s s'` is the reflexive-transitive closure of `Step … (.next
_)` through states whose program counter satisfies `inside`, the last one
included. Quantifying over it rather than over `Reachable` is what makes the
statement local: a macro's proof never mentions the code outside its own range,
and the glue that chains macros together never looks inside one.

The general form of `leave` — the one a macro whose expansion is *not* one
contiguous range needs — reads

```
  (∃ q, s''.pc = q ∧ NextOf inside q ∧ Agree P post s'') ∨ (∃ e ∈ exits, …)
```

with `inside` an arbitrary predicate on positions. Only the helper call needs
it: its expansion branches into the trailer's retpoline and comes back. That
proof states its own variant with the retpoline's range added to `inside`;
everything else instantiates the contiguous form above, where `inside` is
`Range p q` and the fallthrough position is `q`.

Two conventions the glue relies on. A macro that jumps lists the jump's target
in `exits`, and no jump exit is ever at `q`, so the two disjuncts of `leave`
name different positions. And a macro the checker walked *dead* has no lemma
at all: no execution reaches it, so there is nothing to prove and the glue
never enters one.

## Step shapes

The rest of the file reads the step relation off one primitive at a time. Every
lemma has the same form — given that the instruction at `s.pc` is a particular
constructor, a step from `s` can only be the one that constructor takes — so a
macro proof spends no work on case analysis over `Step`. `RegOnly` collects the
primitives that touch no memory and advance by one, with `writes` naming the
registers each of them may change; the rest get a lemma each.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-! ## Staying inside a region -/

/-- The positions of a contiguous macro: `[p, q)`. -/
def Range (p q : Nat) : Nat → Prop := fun pc => p ≤ pc ∧ pc < q

/-- States reached from `s` without leaving the region: every state of the
chain, `s'` included, has its program counter inside. -/
inductive Stays (P : Params) (code : List x64_ir.PInsn) (inside : Nat → Prop) (s : State) :
    State → Prop
  | refl : inside s.pc → Stays P code inside s s
  | step {s' s'' : State} : Stays P code inside s s' → Step P code s' (.next s'') →
      inside s''.pc → Stays P code inside s s''

theorem stays_refl {P code inside} {s : State} (h : inside s.pc) : Stays P code inside s s :=
  .refl h

theorem stays_step {P code inside} {s s' s'' : State} (h : Stays P code inside s s')
    (hs : Step P code s' (.next s'')) (hi : inside s''.pc) : Stays P code inside s s'' :=
  .step h hs hi

/-- The last state of a chain is inside. -/
theorem Stays.inside_last {P code inside} {s s' : State} (h : Stays P code inside s s') :
    inside s'.pc := by
  cases h with
  | refl h => exact h
  | step _ _ h => exact h

/-- And so is the first. -/
theorem Stays.inside_first {P code inside} {s s' : State} (h : Stays P code inside s s') :
    inside s.pc := by
  induction h with
  | refl h => exact h
  | step _ _ _ ih => exact ih

theorem stays_trans {P code inside} {s s' s'' : State} (h₁ : Stays P code inside s s')
    (h₂ : Stays P code inside s' s'') : Stays P code inside s s'' := by
  induction h₂ with
  | refl _ => exact h₁
  | step _ hs hi ih => exact .step ih hs hi

/-- Staying inside is a special case of being reachable, which is how a macro
lemma feeds the whole-function statement. -/
theorem stays_reachable {P code inside} {s s' : State} (h : Stays P code inside s s') :
    Reachable P code s s' := by
  induction h with
  | refl _ => exact .refl
  | step _ hs _ ih => exact .step ih hs

/-- A region of one primitive that always leaves it: the walk never gets
anywhere. -/
theorem stays_leaves {P code} {p : Nat} {s s' : State}
    (hadv : ∀ t t' : State, t.pc = p → Step P code t (.next t') → ¬ Range p (p + 1) t'.pc)
    (h : Stays P code (Range p (p + 1)) s s') : s' = s := by
  induction h with
  | refl _ => rfl
  | step h₁ hst hi ih =>
    rename_i t t'
    have ht : t.pc = p := by
      have := h₁.inside_last
      simp only [Range] at this
      omega
    exact absurd hi (hadv t t' ht hst)

/-- The common case: the primitive advances by one. -/
theorem stays_single {P code} {p : Nat} {s s' : State}
    (hadv : ∀ t t' : State, t.pc = p → Step P code t (.next t') → t'.pc = p + 1)
    (h : Stays P code (Range p (p + 1)) s s') : s' = s := by
  refine stays_leaves ?_ h
  intro t t' ht hst
  rw [hadv t t' ht hst]
  simp only [Range]
  omega


/-- The induction the multi-primitive macro proofs run: an invariant that
holds at the macro's first position and survives every step that stays inside
the region. -/
theorem stays_invariant {P code inside} {I : State → Prop} {s s' : State} (h0 : I s)
    (hstep : ∀ t t' : State, I t → inside t.pc → Step P code t (.next t') → inside t'.pc → I t')
    (h : Stays P code inside s s') : I s' := by
  induction h with
  | refl _ => exact h0
  | step h1 hst hi ih => exact hstep _ _ ih h1.inside_last hst hi

/-! ## The macro lemma -/

/-- Running the primitives of one macro from a state agreeing with the
checker's pre-state: every step is safe, and control leaves the region only to
the next macro (agreeing with the post-state), to one of the listed exits
(agreeing with the state listed for it), or by returning under the contract. -/
structure MacroOk (P : Params) (code : List x64_ir.PInsn) (p q : Nat)
    (pre post : x64_check.State) (exits : List (Nat × x64_check.State)) : Prop where
  safe : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code (Range p q) s s' →
    ∀ c, Step P code s' c → ∀ i, code[s'.pc]? = some i →
      ∀ bn ∈ accesses i s', AccessOk P bn.1 bn.2
  leave : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code (Range p q) s s' →
    ∀ s'', Step P code s' (.next s'') → ¬ Range p q s''.pc →
      (s''.pc = q ∧ Agree P post s'') ∨ (∃ e ∈ exits, s''.pc = e.1 ∧ Agree P e.2 s'')
  returns : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code (Range p q) s s' →
    ∀ s'', Step P code s' (.returned s'') →
      s''.regs RSP = P.rsp0 + 8#64 ∧ s''.regs RBP = P.rbp0 ∧ s''.regs R15 = P.fp0

/-! ## Register-only primitives -/

/-- The primitives that read and write registers and flags only: no memory, no
branch, always one position forward. -/
def RegOnly : x64_ir.PInsn → Prop
  | .PcLabel _ => True
  | .Local _ => True
  | .ExitLabel => True
  | .RetpolineLabel => True
  | .Pause => True
  | .Alu _ _ _ _ => True
  | .AluImm _ _ _ _ => True
  | .ShiftImm _ _ _ _ => True
  | .ShiftCl _ _ _ => True
  | .Neg _ _ => True
  | .MovSx _ _ _ _ => True
  | .Bswap _ _ => True
  | .Rol16 _ => True
  | .Cmov _ _ _ => True
  | .LoadImm _ _ => True
  | .Cqo => True
  | .Cdq => True
  | .CmpRcxMinusOne _ => True
  | .CmpEaxImm _ => True
  | .MulDivRcx _ _ _ => True
  | .RipLoadDispatcher _ => True
  | .RipLeaHelperTable _ => True
  | _ => False

/-- The registers a primitive may write. Over-approximate, and only read for
the `RegOnly` ones. -/
def writes : x64_ir.PInsn → List Nat
  | .Alu _ _ _ dst => [dst.val]
  | .AluImm _ _ dst _ => [dst.val]
  | .ShiftImm _ _ dst _ => [dst.val]
  | .ShiftCl _ _ dst => [dst.val]
  | .Neg _ dst => [dst.val]
  | .MovSx _ _ _ dst => [dst.val]
  | .Bswap _ dst => [dst.val]
  | .Rol16 dst => [dst.val]
  | .Cmov _ dst _ => [dst.val]
  | .LoadImm dst _ => [dst.val]
  | .Cqo => [RDX]
  | .Cdq => [RDX]
  | .MulDivRcx _ _ _ => [RAX, RDX]
  | .RipLoadDispatcher dst => [dst.val]
  | .RipLeaHelperTable dst => [dst.val]
  | .Load _ _ _ dst _ => [dst.val]
  | .Pop dst => [dst.val, RSP]
  | .Push _ => [RSP]
  | .Pushfq => [RSP]
  | .Popfq => [RSP]
  | .Xchg _ src _ _ => [src.val]
  | .LockCmpxchg _ _ _ _ => [RAX]
  | .AluRM _ reg _ _ => [reg.val]
  | _ => []

@[simp] theorem aluRRStep_regs_ne (w64 op src dst s) {r : Nat} (hr : r ≠ dst.val) :
    (aluRRStep w64 op src dst s).regs r = s.regs r := by
  cases op <;>
    simp [aluRRStep, wRegFlags, wReg, wFlags, Function.update_of_ne hr]

@[simp] theorem aluImmStep_regs_ne (w64 op dst imm s) {r : Nat} (hr : r ≠ dst.val) :
    (aluImmStep w64 op dst imm s).regs r = s.regs r := by
  cases op <;>
    simp [aluImmStep, wRegFlags, wReg, wFlags, Function.update_of_ne hr]

/-- A register-only primitive touches no memory. -/
theorem accesses_regOnly {i : x64_ir.PInsn} (hi : RegOnly i) (s : State) : accesses i s = [] := by
  cases i <;> first | rfl | (exfalso; exact hi)

/-- A register-only primitive steps to the next position, keeps memory, and
changes only the registers `writes` names. -/
theorem step_regOnly {P code} {s : State} {c : Config} {i : x64_ir.PInsn} (hi : RegOnly i)
    (hc : code[s.pc]? = some i) (h : Step P code s c) :
    ∃ s', c = .next s' ∧ s'.pc = s.pc + 1 ∧ s'.mem = s.mem ∧
      ∀ r, r ∉ writes i → s'.regs r = s.regs r := by
  cases h <;> rw [hc] at * <;> simp_all only [Option.some.injEq] <;> subst_vars <;>
    simp_all only [RegOnly, writes] <;>
    refine ⟨_, rfl, by simp [wReg, wRegN, wRegFlags, wFlags, wNext], by
      simp [wReg, wRegN, wRegFlags, wFlags, wNext], ?_⟩ <;>
    intro r hr <;>
    simp_all [wReg, wRegN, wRegFlags, wFlags, wNext, Function.update_of_ne]

/-! ## The stack primitives -/

theorem step_pushfq {P code} {s : State} {c : Config} (hc : code[s.pc]? = some .Pushfq)
    (h : Step P code s c) : c = .next { push s (flagsWord s.flags) with pc := s.pc + 1 } := by
  cases h <;> simp_all

theorem step_popfq {P code} {s : State} {c : Config} (hc : code[s.pc]? = some .Popfq)
    (h : Step P code s c) :
    c = .next { popRsp s with
      flags := flagsOfWord (load64 s.mem (s.regs RSP)), pc := s.pc + 1 } := by
  cases h <;> simp_all

theorem step_storeRspImm {P code} {s : State} {c : Config} {imm : Std.U32}
    (hc : code[s.pc]? = some (.StoreRspImm imm)) (h : Step P code s c) :
    c = .next { s with
      mem := store64 s.mem (s.regs RSP) (BitVec.signExtend 64 imm.bv), pc := s.pc + 1 } := by
  cases h <;> simp_all

theorem step_storeRspRax {P code} {s : State} {c : Config} (hc : code[s.pc]? = some .StoreRspRax)
    (h : Step P code s c) :
    c = .next { s with mem := store64 s.mem (s.regs RSP) (s.regs RAX), pc := s.pc + 1 } := by
  cases h <;> simp_all

@[simp] theorem accesses_jmpNear (t s) : accesses (.JmpNear t) s = [] := rfl

@[simp] theorem accesses_storeRspImm (imm s) :
    accesses (.StoreRspImm imm) s = [(s.regs RSP, 8)] := rfl

/-! ## The memory primitives -/

@[simp] theorem accesses_storeImm (size base disp imm s) :
    accesses (.StoreImm size base disp imm) s = [(addr s base disp, size.val)] := rfl

@[simp] theorem accesses_lockAlu (op w64 src base disp s) :
    accesses (.LockAlu op w64 src base disp) s = [(addr s base disp, opWidth w64)] := rfl

@[simp] theorem accesses_lockCmpxchg (w64 src base disp s) :
    accesses (.LockCmpxchg w64 src base disp) s = [(addr s base disp, opWidth w64)] := rfl

@[simp] theorem accesses_xchg (w64 src base disp s) :
    accesses (.Xchg w64 src base disp) s = [(addr s base disp, opWidth w64)] := rfl

@[simp] theorem accesses_load (size sx base dst disp s) :
    accesses (.Load size sx base dst disp) s =
      if sx ∧ size.val = 8 then [] else [(addr s base disp, size.val)] := rfl

/-- A load either reads its range into `dst`, or, in the sign-extending
eight-byte form the encoder emits nothing for, does nothing at all. -/
theorem step_load {P code} {s : State} {c : Config} {size : Std.U8} {sx : Bool}
    {base dst : Std.U8} {disp : Std.I32}
    (hc : code[s.pc]? = some (.Load size sx base dst disp)) (h : Step P code s c) :
    (¬ (sx ∧ size.val = 8) ∧
      c = .next (wReg s dst (loadExt size.val sx s.mem (addr s base disp)))) ∨
    (sx = true ∧ size.val = 8 ∧ c = .next (wNext s)) := by
  cases h <;> simp_all

theorem step_store {P code} {s : State} {c : Config} {size src base : Std.U8} {disp : Std.I32}
    (hc : code[s.pc]? = some (.Store size src base disp)) (h : Step P code s c) :
    c = .next { s with
      mem := store size.val s.mem (addr s base disp) (storeVal size.val (s.regs src.val)),
      pc := s.pc + 1 } := by
  cases h <;> simp_all
  obtain ⟨rfl, rfl, rfl, rfl⟩ := hc
  rfl

theorem step_storeImm {P code} {s : State} {c : Config} {size base : Std.U8}
    {disp imm : Std.I32} (hc : code[s.pc]? = some (.StoreImm size base disp imm))
    (h : Step P code s c) :
    c = .next { s with
      mem := store size.val s.mem (addr s base disp)
        (storeVal size.val (BitVec.signExtend 64 imm.bv)),
      pc := s.pc + 1 } := by
  cases h <;> simp_all
  obtain ⟨rfl, rfl, rfl, rfl⟩ := hc
  rfl

theorem step_aluRM {P code} {s : State} {c : Config} {op : x64_ir.AluRM} {reg base : Std.U8}
    {disp : Std.I32} (hc : code[s.pc]? = some (.AluRM op reg base disp)) (h : Step P code s c) :
    c = .next (aluRMStep op reg base disp s) := by
  cases h <;> rw [hc] at * <;> simp_all only [Option.some.injEq, reduceCtorEq,
    x64_ir.PInsn.AluRM.injEq]

@[simp] theorem aluRMStep_mem (op reg base disp s) :
    (aluRMStep op reg base disp s).mem = s.mem := by
  cases op <;> simp [aluRMStep, wRegFlags, wFlags]

@[simp] theorem aluRMStep_pc (op reg base disp s) :
    (aluRMStep op reg base disp s).pc = s.pc + 1 := by
  cases op <;> simp [aluRMStep, wRegFlags, wFlags]

@[simp] theorem aluRMStep_regs_ne (op reg base disp s) {r : Nat} (hr : r ≠ reg.val) :
    (aluRMStep op reg base disp s).regs r = s.regs r := by
  cases op <;> simp [aluRMStep, wRegFlags, wFlags, Function.update_of_ne hr]

theorem step_lockAlu {P code} {s : State} {c : Config} {op : Std.U8} {w64 : Bool}
    {src base : Std.U8} {disp : Std.I32}
    (hc : code[s.pc]? = some (.LockAlu op w64 src base disp)) (h : Step P code s c) :
    ∃ f : Flags, c = .next (lockAluStep op w64 src base disp s f) := by
  cases h <;> rw [hc] at * <;> simp_all only [Option.some.injEq, reduceCtorEq,
    x64_ir.PInsn.LockAlu.injEq]
  exact ⟨_, rfl⟩

theorem step_lockCmpxchg {P code} {s : State} {c : Config} {w64 : Bool} {src base : Std.U8}
    {disp : Std.I32} (hc : code[s.pc]? = some (.LockCmpxchg w64 src base disp))
    (h : Step P code s c) : ∃ f : Flags, c = .next (cmpxchgStep w64 src base disp s f) := by
  cases h <;> rw [hc] at * <;> simp_all only [Option.some.injEq, reduceCtorEq,
    x64_ir.PInsn.LockCmpxchg.injEq]
  exact ⟨_, rfl⟩

theorem step_xchg {P code} {s : State} {c : Config} {w64 : Bool} {src base : Std.U8}
    {disp : Std.I32} (hc : code[s.pc]? = some (.Xchg w64 src base disp)) (h : Step P code s c) :
    c = .next (xchgStep w64 src base disp s) := by
  cases h <;> rw [hc] at * <;> simp_all only [Option.some.injEq, reduceCtorEq,
    x64_ir.PInsn.Xchg.injEq]

/-! ## Branches, calls and the end of a function -/

theorem step_jcc {P code} {s : State} {c : Config} {cc : Std.U8} {t : x64_ir.PTarget}
    (hc : code[s.pc]? = some (.Jcc cc t)) (h : Step P code s c) :
    (cond cc s.flags = true ∧ ∃ i, pos code t = some i ∧ c = .next { s with pc := i }) ∨
    (cond cc s.flags = false ∧ c = .next (wNext s)) := by
  cases h <;> simp_all

theorem step_jmp {P code} {s : State} {c : Config} {t : x64_ir.PTarget}
    (hc : code[s.pc]? = some (.Jmp t)) (h : Step P code s c) :
    ∃ i, pos code t = some i ∧ c = .next { s with pc := i } := by
  cases h <;> simp_all

theorem step_jmpNear {P code} {s : State} {c : Config} {t : x64_ir.PTarget}
    (hc : code[s.pc]? = some (.JmpNear t)) (h : Step P code s c) :
    ∃ i, pos code t = some i ∧ c = .next { s with pc := i } := by
  cases h <;> simp_all

theorem step_jcc8 {P code} {s : State} {c : Config} {cc : Std.U8} {n : Std.U32}
    (hc : code[s.pc]? = some (.Jcc8 cc n)) (h : Step P code s c) :
    (cond cc s.flags = true ∧
      ∃ i, pos code (.Local n) = some i ∧ c = .next { s with pc := i }) ∨
    (cond cc s.flags = false ∧ c = .next (wNext s)) := by
  cases h <;> simp_all

theorem step_jmp8 {P code} {s : State} {c : Config} {n : Std.U32}
    (hc : code[s.pc]? = some (.Jmp8 n)) (h : Step P code s c) :
    ∃ i, pos code (.Local n) = some i ∧ c = .next { s with pc := i } := by
  cases h <;> simp_all

theorem step_call {P code} {s : State} {c : Config} {t : x64_ir.PTarget}
    (hc : code[s.pc]? = some (.Call t)) (h : Step P code s c) :
    ∃ i, pos code t = some i ∧ c = .next { push s (retAddr P s) with pc := i } := by
  cases h <;> simp_all

theorem step_callReg {P code} {s : State} {c : Config} {r : Std.U8}
    (hc : code[s.pc]? = some (.CallReg r)) (h : Step P code s c) :
    ∃ s', ExternalReturn P code (push s (retAddr P s)) s' ∧ c = .next s' := by
  cases h <;> simp_all

/-- `ret` is the only way out of a function, and it goes one of three ways:
back to the caller with the stack balanced, back to a `call` inside this list,
or — the retpoline's own `ret` — into the dispatcher. -/
theorem step_ret {P code} {s : State} {c : Config} (hc : code[s.pc]? = some .Ret)
    (h : Step P code s c) :
    (s.regs RSP = P.rsp0 ∧ c = .returned (popRsp s)) ∨
    (s.regs RSP ≠ P.rsp0 ∧ ∃ i, i < code.length ∧ load64 s.mem (s.regs RSP) = codeAddr P i ∧
      c = .next { popRsp s with pc := i }) ∨
    (s.regs RSP ≠ P.rsp0 ∧ ∃ s', ExternalReturn P code (popRsp s) s' ∧ c = .next s') := by
  cases h <;> simp_all

/-- Only `ret` at the entry depth returns. -/
theorem step_returned_ret {P code} {s s'' : State} (h : Step P code s (.returned s'')) :
    code[s.pc]? = some .Ret ∧ s.regs RSP = P.rsp0 ∧ s'' = popRsp s := by
  cases h with
  | retTop h1 h2 => exact ⟨h1, h2, rfl⟩

/-- Only `ud2` and the trailer's data halt. -/
theorem step_halt {P code} {s : State} (h : Step P code s .halt) :
    code[s.pc]? = some .Ud2 ∨ (∃ a : Std.U64, code[s.pc]? = some (.DispatcherSlot a)) ∨
      code[s.pc]? = some .HelperTable := by
  cases h with
  | ud2 h1 => exact Or.inl h1
  | dispatcherSlot a h1 => exact Or.inr (Or.inl ⟨a, h1⟩)
  | helperTable h1 => exact Or.inr (Or.inr h1)

theorem step_ud2 {P code} {s : State} {c : Config} (hc : code[s.pc]? = some .Ud2)
    (h : Step P code s c) : c = .halt := by
  cases h <;> simp_all

/-! ## Addresses through the two fixed registers

`step_frameLoad`, `step_frameStore` and `step_aluRM_rbp` are `step_load`,
`step_store` and `step_aluRM` with `frame_access` for the access: a base of
`rbp` and a displacement inside `[-160, 0)` is a slot of the frame scratch. -/

/-- The address a `rbp`-relative operand names. -/
theorem addr_rbp {P : Params} {a : x64_check.State} {s : State} {base : Std.U8} {disp : Std.I32}
    (h : Agree P a s) (hb : base.val = RBP) :
    addr s base disp = P.rbp0 + BitVec.signExtend 64 disp.bv := by
  simp only [addr, hb, h.rbp]

/-- The address an `r15`-relative operand names, when the frame register still
carries `Fp`. -/
theorem addr_frame {P : Params} {a : x64_check.State} {s : State} {base : Std.U8}
    {disp : Std.I32} (h : Agree P a s) (hb : base.val = R15) (ht : tagAt a 15 = .Fp) :
    addr s base disp = P.fp0 + BitVec.signExtend 64 disp.bv := by
  have := h.regs 15 (by norm_num)
  rw [ht] at this
  simp only [addr, hb, R15]
  rw [this]

/-- Any access through `rbp` that stays inside the 160 reserved bytes. -/
theorem frame_access {P : Params} {a : x64_check.State} {s : State} {base : Std.U8}
    {disp : Std.I32} {n : Nat} (hL : Layout P) (h : Agree P a s) (hb : base.val = RBP)
    (hlo : -160 ≤ disp.val) (hhi : disp.val + n ≤ 0) : AccessOk P (addr s base disp) n := by
  rw [addr_rbp h hb]
  exact frame_slot_ok hL hlo hhi

/-- The word at `rsp`, at the depth the abstract state records. -/
theorem stack_top_access {P : Params} {a : x64_check.State} {s : State}
    (hL : Layout P) (h : Agree P a s) : AccessOk P (s.regs RSP) 8 := by
  rw [h.rsp]
  exact stack_slot_ok hL h.depth

/-- And the word a push is about to write below it. -/
theorem stack_push_access {P : Params} {a : x64_check.State} {s : State}
    (hL : Layout P) (h : Agree P a s) (hd : a.depth.val + 1 ≤ 16) :
    AccessOk P (s.regs RSP - 8#64) 8 := by
  rw [h.rsp, rsp_push]
  exact stack_slot_ok hL hd

end X64

end async_ebpf_verified

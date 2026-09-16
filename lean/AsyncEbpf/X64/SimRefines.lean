import AsyncEbpf.X64.Machine
import AsyncEbpf.Layout.Proofs

/-!
# The executable model refines the relational one

`src/verified/x64_sim.rs` is an executable model of the primitive instruction
set: `step` runs one `PInsn` against a `Sim` — sixteen registers, four flags,
one mapped byte range and a position in the list — and returns an `Outcome`.
`src/test/x64_sim_native.rs` runs the same list on a real x86_64 machine, from
the same state, and compares what the two leave behind: the sixteen registers,
the four flags the backend branches on, and every byte of the mapped range.
That differential test is the only thing in the tree that says the *semantics*
the memory-safety proof is stated over is the semantics the hardware has.

It compares the hardware with `x64_sim`, though, not with `Step`. This file
closes that gap. `step_refines`: every `Outcome::Next` step of the executable
model is a `Step` of `AsyncEbpf/X64/Machine.lean` over the denoted state.
`run_refines`: a `run` that comes back still stepping has walked a chain of
them, so its final state is `Reachable`. Together they let the test be read as
a statement about `Step`: what it establishes on the hardware, it establishes
for the model `check_safe` quantifies over.

Refinement is the useful direction and the only provable one. `Step` is
deliberately loose where the safety argument does not care — the flags a
shift, a rotate, a `neg`, a locked read-modify-write or a multiply leaves, all
but the zero flag after a `cmpxchg`, `rax`/`rdx` after a divide — and the
simulator picks one behaviour there, the hardware's. Every such choice is one
of the choices `Step` allows, and each case below hands the constructor the
simulator's value as the witness.

## What the theorems assume

* `CodeOk code`: every register operand of every instruction of the list is
  one of the sixteen the encoder emits. The simulator masks a register number
  to four bits and the machine model writes the number it is given, so the two
  agree exactly there; `x64_lower` never builds anything else. That is the
  only condition on the list: `pop rsp` included, the two models agree
  instruction for instruction — both move `rsp` before they write the
  destination, so the popped word wins, which is what the hardware does.
* `mem_base + mem.len() ≤ 2 ^ 64`: the mapped range does not wrap, which is
  what makes "the bytes at `a`" a range at all — the same hypothesis
  `Bytes.lean` takes for its own range lemmas.

Outcomes other than `Next` are outside the statement, which is where they
belong: a `Fault` is an access outside the mapped range or a division the
hardware would have trapped on, a `Halt` is `ud2` or the trailer's data, and
`Unsupported` is a primitive this model does not execute or a branch to a
label the list does not carry. `Step` says nothing about any of them, and the
differential test does not run them either.

`simParams` fills in the machine's parameters: the code base is the
simulator's, `rsp0` is the all-ones address — one at which no eight-byte
access fits inside a range that does not wrap, so the simulator's `rsp` never
equals it and a `ret` is always the `retLocal` rule — and the rest is zero,
since no rule a `Next` step uses reads them.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-! ## The abstraction

A `Sim` denotes a `State`: its register array read as a function (registers
above fifteen, which the simulator's `& 0xf` masking cannot produce, read as
zero), its four flags, its mapped range read as a total memory (every address
outside it reads as zero, which is sound because a step that touches one is a
`Fault` and so outside the theorem), and its position in the list. -/

/-- The four flags, as the machine model records them. -/
def absFlags (f : x64_sim.Flags) : Flags := ⟨f.cf, f.zf, f.sf, f.of⟩

/-- The registers the simulator's array denotes. -/
def absRegs (s : x64_sim.Sim) : Nat → Word :=
  fun r => if r < 16 then U64.bv (s.regs.val[r]!) else 0#64

instance instDecidableInRange (b : Word) (n : Nat) (a : Word) : Decidable (InRange b n a) := by
  unfold InRange; infer_instance

/-- The memory the simulator's mapped range denotes. -/
def absMem (s : x64_sim.Sim) : Mem :=
  fun a => if InRange (U64.bv s.mem_base) s.mem.val.length a
    then U8.bv (s.mem.val[(a - U64.bv s.mem_base).toNat]!) else 0#8

/-- The state a `Sim` denotes. -/
def absState (s : x64_sim.Sim) : State :=
  { regs := absRegs s
    flags := ⟨s.cf, s.zf, s.sf, s.of⟩
    mem := absMem s
    pc := s.pc.val }

@[simp] theorem absState_regs (s : x64_sim.Sim) : (absState s).regs = absRegs s := rfl
@[simp] theorem absState_flags (s : x64_sim.Sim) :
    (absState s).flags = ⟨s.cf, s.zf, s.sf, s.of⟩ := rfl
@[simp] theorem absState_mem (s : x64_sim.Sim) : (absState s).mem = absMem s := rfl
@[simp] theorem absState_pc (s : x64_sim.Sim) : (absState s).pc = s.pc.val := rfl

/-- The parameters the simulator carries: where the code sits, and nothing
else. The deterministic constructors read only `codeBase`, except `retTop`,
which reads `rsp0`; `rsp0` is the one address at which no eight-byte access
fits inside a mapped range that does not wrap, so the simulator's `rsp` never
equals it and `retLocal` is always the rule a `ret` takes here. -/
def simParams (s : x64_sim.Sim) : Params where
  codeBase := U64.bv s.code_base
  rsp0 := BitVec.allOnes 64
  rbp0 := 0#64
  fp0 := 0#64
  desc := 0#64
  tableBase := 0#64
  dispatcher := 0#64
  sgb := 0#64
  sgt := 0#64
  snb := 0#64
  dgb := 0#64
  dgt := 0#64
  dnb := 0#64
  guestFloor := 0#64
  nativeFloor := 0#64
  frameSize := 0
  stride := 0
  stackLo := 0#64
  stackHi := 0#64

@[simp] theorem simParams_codeBase (s : x64_sim.Sim) :
    (simParams s).codeBase = U64.bv s.code_base := rfl

@[simp] theorem simParams_rsp0 (s : x64_sim.Sim) :
    (simParams s).rsp0 = BitVec.allOnes 64 := rfl

/-! ## Which lists this is about

The simulator masks every register operand to four bits; the machine model
writes the number it is given. They agree exactly on the sixteen registers the
encoder can emit, so the theorem is about lists whose register operands are
below sixteen — which is every list `x64_lower` builds.

It is the only condition. `pop rsp` in particular needs none: both models
move `rsp` first and write the destination second, so the popped word wins in
each, as it does on the hardware. -/

/-- A register operand the simulator's masking leaves alone. -/
def RegOk (r : Std.U8) : Prop := r.val < 16

/-- The register operands of one instruction are all encodable. -/
def InsnOk : x64_ir.PInsn → Prop
  | .Push r => RegOk r
  | .Pop r => RegOk r
  | .Alu _ _ src dst => RegOk src ∧ RegOk dst
  | .AluImm _ _ dst _ => RegOk dst
  | .ShiftImm _ _ dst _ => RegOk dst
  | .ShiftCl _ _ dst => RegOk dst
  | .Neg _ dst => RegOk dst
  | .MovSx _ _ src dst => RegOk src ∧ RegOk dst
  | .Bswap _ dst => RegOk dst
  | .Rol16 dst => RegOk dst
  | .Cmov _ dst src => RegOk dst ∧ RegOk src
  | .LoadImm dst _ => RegOk dst
  | .Load _ _ base dst _ => RegOk base ∧ RegOk dst
  | .Store _ src base _ => RegOk src ∧ RegOk base
  | .StoreImm _ base _ _ => RegOk base
  | .AluRM _ reg base _ => RegOk reg ∧ RegOk base
  | .LockAlu _ _ src base _ => RegOk src ∧ RegOk base
  | .LockCmpxchg _ src base _ => RegOk src ∧ RegOk base
  | .Xchg _ src base _ => RegOk src ∧ RegOk base
  | .CallReg r => RegOk r
  | .RipLoadDispatcher dst => RegOk dst
  | .RipLeaHelperTable dst => RegOk dst
  | _ => True

/-- Every instruction of the list is one the encoder could have emitted. -/
def CodeOk (code : List x64_ir.PInsn) : Prop := ∀ i ∈ code, InsnOk i

/-! ## Plumbing

The generated code is a chain of `Result` binds over Aeneas' scalars; these
are the shapes the cases below read off it. -/

theorem array_update_eq_ok {α : Type} {n : Usize} {v : Array α n} {i : Usize} {x : α}
    {a : Array α n} (h : Array.update v i x = ok a) :
    i.val < v.val.length ∧ a.val = v.val.set i.val x := by
  unfold Array.update at h
  split at h
  · simp at h
  · rename_i y hy
    simp only [ok.injEq] at h
    subst h
    rw [Array.getElem?_Usize_eq, List.getElem?_eq_some_iff] at hy
    exact ⟨hy.1, by simp⟩

theorem array_index_usize_eq_ok {α : Type} [Inhabited α] {n : Usize} {v : Array α n}
    {i : Usize} {x : α} (h : Array.index_usize v i = ok x) : i.val < v.val.length ∧ x = v.val[i.val]! := by
  unfold Array.index_usize at h
  split at h
  · simp at h
  · rename_i y hy
    simp only [ok.injEq] at h
    subst h
    rw [Array.getElem?_Usize_eq, List.getElem?_eq_some_iff] at hy
    obtain ⟨hi, hx⟩ := hy
    exact ⟨hi, by rw [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem hi, hx]; rfl⟩

/-- The simulator's four-bit masking is the identity on the sixteen registers
the encoder emits. -/
theorem and_fifteen {r : Std.U8} (hr : r.val < 16) : (r &&& 15#u8).val = r.val := by
  have h : (r &&& 15#u8).val = r.val &&& (2 ^ 4 - 1) := by
    simp only [UScalar.val_and]
    rfl
  rw [h, Nat.and_two_pow_sub_one_eq_mod]
  exact Nat.mod_eq_of_lt (by norm_num; omega)

/-- A cast that does not truncate keeps the value. -/
theorem cast_val_of_lt {src tgt : UScalarTy} (x : UScalar src) (h : x.val < 2 ^ tgt.numBits) :
    (UScalar.cast tgt x).val = x.val := by
  rw [UScalar.cast_val_eq]; exact Nat.mod_eq_of_lt h

theorem two_pow_le_usize (n : Nat) (h : n ≤ 32) : (2 : Nat) ^ n ≤ 2 ^ (UScalarTy.Usize).numBits := by
  apply Nat.pow_le_pow_right (by norm_num)
  simp only [UScalarTy.Usize_numBits_eq]
  cases System.Platform.numBits_eq with
  | inl h32 => omega
  | inr h64 => omega

@[simp] theorem u8_cast_usize_val (x : Std.U8) : (UScalar.cast .Usize x).val = x.val := by
  refine cast_val_of_lt x (Nat.lt_of_lt_of_le ?_ (two_pow_le_usize 8 (by norm_num)))
  have := x.hBounds; simpa using this

/-! ## The state transformers

`reg`, `set_reg`, `set_flags` and the `pc` bump, read as operations on the
`State` the simulator denotes. -/

@[simp] theorem sim_regs_length (s : x64_sim.Sim) : s.regs.val.length = 16 := by
  simp

theorem reg_eq {s : x64_sim.Sim} {r : Std.U8} {v : Std.U64} (hr : RegOk r)
    (h : x64_sim.reg s r = ok v) : U64.bv v = (absState s).regs r.val := by
  unfold x64_sim.reg at h
  obtain_bind ⟨i, hi, h⟩ := h
  simp only [lift, ok.injEq] at hi
  subst hi
  obtain_bind ⟨i1, hi1, h⟩ := h
  simp only [lift, ok.injEq] at hi1
  subst hi1
  obtain ⟨_, hx⟩ := array_index_usize_eq_ok h
  have hr' : RegOk r := hr
  unfold RegOk at hr'
  simp only [u8_cast_usize_val, and_fifteen hr'] at hx
  simp only [absState_regs, absRegs, if_pos hr', hx]

theorem absState_pc_set (s : x64_sim.Sim) (i : Usize) :
    absState { s with pc := i } = { absState s with pc := i.val } := rfl

theorem set_flags_abs {s s' : x64_sim.Sim} {f : x64_sim.Flags}
    (h : x64_sim.set_flags s f = ok s') :
    absState s' = { absState s with flags := absFlags f } := by
  unfold x64_sim.set_flags at h
  simp only [ok.injEq] at h
  subst h
  rfl

theorem set_reg_frame {s s' : x64_sim.Sim} {r : Std.U8} {v : Std.U64}
    (h : x64_sim.set_reg s r v = ok s') :
    s'.pc = s.pc ∧ s'.mem_base = s.mem_base ∧ s'.code_base = s.code_base ∧ s'.mem = s.mem := by
  unfold x64_sim.set_reg at h
  obtain_bind ⟨i, hi, h⟩ := h
  obtain_bind ⟨i1, hi1, h⟩ := h
  obtain_bind ⟨a, ha, h⟩ := h
  simp only [ok.injEq] at h
  subst h
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem set_flags_frame {s s' : x64_sim.Sim} {f : x64_sim.Flags}
    (h : x64_sim.set_flags s f = ok s') :
    s'.pc = s.pc ∧ s'.mem_base = s.mem_base ∧ s'.code_base = s.code_base ∧ s'.mem = s.mem := by
  unfold x64_sim.set_flags at h
  simp only [ok.injEq] at h
  subst h
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem set_reg_abs {s s' : x64_sim.Sim} {r : Std.U8} {v : Std.U64} (hr : RegOk r)
    (h : x64_sim.set_reg s r v = ok s') :
    absState s' =
      { absState s with regs := Function.update (absState s).regs r.val (U64.bv v) } := by
  have hr' : r.val < 16 := hr
  unfold x64_sim.set_reg at h
  obtain_bind ⟨i, hi, h⟩ := h
  simp only [lift, ok.injEq] at hi
  subst hi
  obtain_bind ⟨i1, hi1, h⟩ := h
  simp only [lift, ok.injEq] at hi1
  subst hi1
  obtain_bind ⟨a, ha, h⟩ := h
  simp only [ok.injEq] at h
  subst h
  obtain ⟨_, hav⟩ := array_update_eq_ok ha
  simp only [u8_cast_usize_val, and_fifteen hr'] at hav
  have hregs : absRegs { s with regs := a } = Function.update (absRegs s) r.val (U64.bv v) := by
    funext x
    simp only [absRegs, Function.update]
    by_cases hx : x < 16
    · simp only [if_pos hx, hav]
      by_cases hxr : x = r.val
      · subst hxr
        rw [List.getElem!_eq_getElem?_getD, List.getElem?_set_self (by simp [hx]), dif_pos rfl]
        rfl
      · rw [dif_neg hxr, List.getElem!_eq_getElem?_getD, List.getElem?_set_ne (by omega),
          ← List.getElem!_eq_getElem?_getD]
    · have hxr : x ≠ r.val := by omega
      simp only [if_neg hx, dif_neg hxr]
  exact congrArg (fun g => ({ regs := g, flags := _, mem := _, pc := _ } : State)) hregs


/-! ## Arithmetic

The simulator does its wrapping arithmetic by hand, through `u128` and a
mask, because Aeneas reads `+` and `-` as failing on overflow. These lemmas
say the result is the `BitVec` operation the machine model uses. -/

/-- A bit of a word, as the simulator tests it. -/
theorem bit_test (v : BitVec 64) (k : Nat) :
    ((v >>> k) &&& 1#64 = 1#64) ↔ v.getLsbD k := by
  rw [← BitVec.testBit_toNat, Nat.testBit_eq_decide_div_mod_eq]
  have hone : (1#64 : BitVec 64).toNat = 1 := by norm_num
  constructor
  · intro h
    have h2 := congrArg BitVec.toNat h
    rw [BitVec.toNat_and, BitVec.toNat_ushiftRight, hone, Nat.and_one_is_mod,
      Nat.shiftRight_eq_div_pow] at h2
    simpa using h2
  · intro h
    simp only [decide_eq_true_eq] at h
    apply BitVec.eq_of_toNat_eq
    rw [BitVec.toNat_and, BitVec.toNat_ushiftRight, hone, Nat.and_one_is_mod,
      Nat.shiftRight_eq_div_pow, h]

theorem not_bv (b : Std.U64) : U64.bv (~~~b) = ~~~(U64.bv b) := rfl

theorem not_val (b : Std.U64) : (~~~b).val = 2 ^ 64 - 1 - b.val := by
  show (U64.bv (~~~b)).toNat = _
  rw [not_bv, BitVec.toNat_not]
  rfl

/-- Masking with `2 ^ k - 1` is reduction modulo `2 ^ k`. -/
theorem and_mask_val {ty : UScalarTy} {k : Nat} {m v : UScalar ty} (hm : m.val = 2 ^ k - 1) :
    (v &&& m).val = v.val % 2 ^ k := by
  have h : (v &&& m).val = v.val &&& (2 ^ k - 1) := by
    simp only [UScalar.val_and, hm]
  rw [h, Nat.and_two_pow_sub_one_eq_mod]

theorem add64_eq {a b c : Std.U64} (h : x64_sim.add64 a b = ok c) :
    U64.bv c = U64.bv a + U64.bv b := by
  unfold x64_sim.add64 at h
  obtain_bind ⟨i, hi, h⟩ := h
  simp only [lift, ok.injEq] at hi
  subst hi
  obtain_bind ⟨i1, hi1, h⟩ := h
  simp only [lift, ok.injEq] at hi1
  subst hi1
  obtain_bind ⟨i2, hi2, h⟩ := h
  obtain_bind ⟨i3, hi3, h⟩ := h
  simp only [lift, ok.injEq] at hi3
  subst hi3
  simp only [ok.injEq] at h
  subst h
  have hadd := UScalar.add_equiv (UScalar.cast .U128 a) (UScalar.cast .U128 b)
  rw [hi2] at hadd
  obtain ⟨-, hval, -⟩ := hadd
  apply BitVec.eq_of_toNat_eq
  have hm : (x64_sim.MASK64).val = 2 ^ 64 - 1 := by simp [x64_sim.MASK64]
  show (UScalar.cast .U64 (i2 &&& x64_sim.MASK64)).val = _
  rw [UScalar.cast_val_eq, and_mask_val hm, Nat.mod_mod_of_dvd _ (by simp), hval]
  simp

theorem sub64_eq {a b c : Std.U64} (h : x64_sim.sub64 a b = ok c) :
    U64.bv c = U64.bv a - U64.bv b := by
  unfold x64_sim.sub64 at h
  obtain_bind ⟨i, hi, h⟩ := h
  simp only [lift, ok.injEq] at hi
  subst hi
  obtain_bind ⟨i1, hi1, h⟩ := h
  simp only [lift, ok.injEq] at hi1
  subst hi1
  obtain_bind ⟨i2, hi2, h⟩ := h
  simp only [lift, ok.injEq] at hi2
  subst hi2
  obtain_bind ⟨i3, hi3, h⟩ := h
  obtain_bind ⟨i4, hi4, h⟩ := h
  obtain_bind ⟨i5, hi5, h⟩ := h
  simp only [lift, ok.injEq] at hi5
  subst hi5
  simp only [ok.injEq] at h
  subst h
  have h3 := UScalar.add_equiv (UScalar.cast .U128 a) (UScalar.cast .U128 (~~~b))
  rw [hi3] at h3
  obtain ⟨-, h3val, -⟩ := h3
  have h4 := UScalar.add_equiv i3 1#u128
  rw [hi4] at h4
  obtain ⟨-, h4val, -⟩ := h4
  have hb : b.val < 2 ^ 64 := b.hBounds
  have hcast : (UScalar.cast .U128 (~~~b)).val = 2 ^ 64 - 1 - b.val := by
    rw [cast_val_of_lt _ (by
      have := (~~~b).hBounds
      simp only [UScalarTy.U64_numBits_eq, UScalarTy.U128_numBits_eq] at *
      omega), not_val]
  have hca : (UScalar.cast .U128 a).val = a.val := by
    rw [cast_val_of_lt _ (by
      have := a.hBounds
      simp only [UScalarTy.U64_numBits_eq, UScalarTy.U128_numBits_eq] at *
      omega)]
  have hm : (x64_sim.MASK64).val = 2 ^ 64 - 1 := by simp [x64_sim.MASK64]
  apply BitVec.eq_of_toNat_eq
  show (UScalar.cast .U64 (i4 &&& x64_sim.MASK64)).val = _
  rw [UScalar.cast_val_eq, and_mask_val hm, Nat.mod_mod_of_dvd _ (by simp), h4val, h3val,
    hcast, hca]
  rw [BitVec.toNat_sub]
  simp only [UScalarTy.U64_numBits_eq, show ((1#u128 : Std.U128)).val = 1 from rfl]
  congr 1
  show a.val + (2 ^ 64 - 1 - b.val) + 1 = 2 ^ 64 - b.val + a.val
  omega


theorem uscalar_eq_iff {ty : UScalarTy} (x y : UScalar ty) : x = y ↔ (UScalar.bv x) = (UScalar.bv y) := by
  cases x; cases y; simp

/-- The four shift forms the generated code uses, as `BitVec` shifts. -/
theorem ushr_iscalar_eq {ty tys : _} {x z : UScalar ty} {s : IScalar tys}
    (h : x >>> s = ok z) : z.bv = (UScalar.bv x) >>> s.toNat := by
  simp only [HShiftRight.hShiftRight, UScalar.shiftRight_IScalar] at h
  split at h
  · unfold UScalar.shiftRight at h
    split at h
    · simp only [ok.injEq] at h
      subst h
      rfl
    · simp at h
  · simp at h

theorem ushr_uscalar_eq {ty tys : _} {x z : UScalar ty} {s : UScalar tys}
    (h : x >>> s = ok z) : z.bv = (UScalar.bv x) >>> s.val := by
  simp only [HShiftRight.hShiftRight, UScalar.shiftRight_UScalar] at h
  unfold UScalar.shiftRight at h
  split at h
  · simp only [ok.injEq] at h
    subst h
    rfl
  · simp at h

theorem ushl_uscalar_eq {ty tys : _} {x z : UScalar ty} {s : UScalar tys}
    (h : x <<< s = ok z) : z.bv = (UScalar.bv x) <<< s.val := by
  simp only [HShiftLeft.hShiftLeft, UScalar.shiftLeft_UScalar] at h
  unfold UScalar.shiftLeft at h
  split at h
  · simp only [ok.injEq] at h
    subst h
    rfl
  · simp at h

theorem ushl_iscalar_eq {ty tys : _} {x z : UScalar ty} {s : IScalar tys}
    (h : x <<< s = ok z) : z.bv = (UScalar.bv x) <<< s.toNat := by
  simp only [HShiftLeft.hShiftLeft, UScalar.shiftLeft_IScalar] at h
  split at h
  · unfold UScalar.shiftLeft at h
    split at h
    · simp only [ok.injEq] at h
      subst h
      rfl
    · simp at h
  · simp at h

theorem u64_eq_iff (x y : Std.U64) : x = y ↔ U64.bv x = U64.bv y := uscalar_eq_iff x y

theorem u64_bv_and (x y : Std.U64) : U64.bv (x &&& y) = U64.bv x &&& U64.bv y := rfl

theorem u64_bv_or (x y : Std.U64) : U64.bv (x ||| y) = U64.bv x ||| U64.bv y := rfl

theorem u64_bv_xor (x y : Std.U64) : U64.bv (x ^^^ y) = U64.bv x ^^^ U64.bv y := rfl

theorem u64_shr_i32 {x z : Std.U64} {t : Std.I32} (h : x >>> t = ok z) :
    U64.bv z = (U64.bv x) >>> t.toNat := ushr_iscalar_eq h

theorem u64_shl_i32 {x z : Std.U64} {t : Std.I32} (h : x <<< t = ok z) :
    U64.bv z = (U64.bv x) <<< t.toNat := ushl_iscalar_eq h

theorem u64_shr_u32 {x z : Std.U64} {t : Std.U32} (h : x >>> t = ok z) :
    U64.bv z = (U64.bv x) >>> t.val := ushr_uscalar_eq h

theorem u64_shl_u32 {x z : Std.U64} {t : Std.U32} (h : x <<< t = ok z) :
    U64.bv z = (U64.bv x) <<< t.val := ushl_uscalar_eq h

theorem u64_shl_usize {x z : Std.U64} {t : Usize} (h : x <<< t = ok z) :
    U64.bv z = (U64.bv x) <<< t.val := ushl_uscalar_eq h

theorem u64_shr_usize {x z : Std.U64} {t : Usize} (h : x >>> t = ok z) :
    U64.bv z = (U64.bv x) >>> t.val := ushr_uscalar_eq h

theorem width_mask_true {m : Std.U64} (h : x64_sim.width_mask true = ok m) :
    m.val = 2 ^ 64 - 1 := by
  unfold x64_sim.width_mask at h
  rw [if_pos rfl] at h
  simp only [ok.injEq] at h
  subst h
  simp

theorem width_mask_false {m : Std.U64} (h : x64_sim.width_mask false = ok m) :
    m.val = 2 ^ 32 - 1 := by
  unfold x64_sim.width_mask at h
  rw [if_neg (by simp)] at h
  simp only [ok.injEq] at h
  subst h
  simp [x64_sim.MASK32]

/-- Masking to the operation's width is what the machine model calls `wr`. -/
theorem and_width_mask {w64 : Bool} {m v : Std.U64} (h : x64_sim.width_mask w64 = ok m) :
    U64.bv (v &&& m) = wr w64 (U64.bv v) := by
  have hv := v.hBounds
  simp only [UScalarTy.U64_numBits_eq] at hv
  apply BitVec.eq_of_toNat_eq
  cases w64 with
  | true =>
    show (v &&& m).val = _
    rw [and_mask_val (k := 64) (width_mask_true h)]
    simp only [wr, if_pos]
    exact Nat.mod_eq_of_lt hv
  | false =>
    show (v &&& m).val = _
    rw [and_mask_val (k := 32) (width_mask_false h)]
    have hr : (wr false (U64.bv v)).toNat = v.val % 2 ^ 32 := by
      simp only [wr, Bool.false_eq_true, if_false, zx32, lo32,
        BitVec.zeroExtend_eq_setWidth]
      rw [BitVec.toNat_setWidth, BitVec.toNat_setWidth]
      have hlt : (U64.bv v).toNat % 2 ^ 32 < 2 ^ 64 := by omega
      exact Nat.mod_eq_of_lt hlt
    rw [hr]

theorem msb_eq {w64 : Bool} {v : Std.U64} {b : Bool} (h : x64_sim.msb w64 v = ok b) :
    b = if w64 then (U64.bv v).msb else (lo32 (U64.bv v)).msb := by
  unfold x64_sim.msb at h
  split at h
  · rename_i hw
    subst hw
    obtain_bind ⟨i, hi, h⟩ := h
    obtain_bind ⟨i1, hi1, h⟩ := h
    simp only [lift, ok.injEq] at hi1
    subst hi1
    simp only [ok.injEq] at h
    subst h
    have hbv := u64_shr_i32 hi
    rw [show I32.toNat (63#i32) = 63 from rfl] at hbv
    rw [if_pos rfl, BitVec.msb_eq_getLsbD_last]
    have hiff : ((i &&& 1#u64) = 1#u64) ↔ (U64.bv v).getLsbD 63 := by
      rw [u64_eq_iff]
      have he : U64.bv (i &&& 1#u64) = ((U64.bv v) >>> 63) &&& 1#64 := by
        simp only [UScalar.bv_and, hbv]
        rfl
      rw [he]
      exact bit_test (U64.bv v) 63
    simp only [hiff]
    simp
  · rename_i hw
    simp only [Bool.not_eq_true] at hw
    subst hw
    obtain_bind ⟨i, hi, h⟩ := h
    obtain_bind ⟨i1, hi1, h⟩ := h
    simp only [lift, ok.injEq] at hi1
    subst hi1
    simp only [ok.injEq] at h
    subst h
    have hbv := u64_shr_i32 hi
    rw [show I32.toNat (31#i32) = 31 from rfl] at hbv
    rw [if_neg (by simp), BitVec.msb_eq_getLsbD_last]
    have hl : (lo32 (U64.bv v)).getLsbD (32 - 1) = (U64.bv v).getLsbD 31 := by simp [lo32]
    rw [hl]
    have hiff : ((i &&& 1#u64) = 1#u64) ↔ (U64.bv v).getLsbD 31 := by
      rw [u64_eq_iff]
      have he : U64.bv (i &&& 1#u64) = ((U64.bv v) >>> 31) &&& 1#64 := by
        simp only [UScalar.bv_and, hbv]
        rfl
      rw [he]
      exact bit_test (U64.bv v) 31
    simp only [hiff]
    simp


theorem width_mask_false_eq : x64_sim.width_mask false = ok x64_sim.MASK32 := by
  unfold x64_sim.width_mask
  rw [if_neg (by simp)]

theorem wr_eq {w64 : Bool} {v r : Std.U64} (h : x64_sim.wr w64 v = ok r) :
    U64.bv r = wr w64 (U64.bv v) := by
  unfold x64_sim.wr at h
  split at h
  · rename_i hw
    subst hw
    simp only [ok.injEq] at h
    subst h
    simp [wr]
  · rename_i hw
    simp only [Bool.not_eq_true] at hw
    subst hw
    unfold x64_sim.lo32 at h
    simp only [ok.injEq] at h
    subst h
    exact and_width_mask width_mask_false_eq

theorem lo32_eq {v r : Std.U64} (h : x64_sim.lo32 v = ok r) :
    U64.bv r = wr false (U64.bv v) := by
  unfold x64_sim.lo32 at h
  simp only [ok.injEq] at h
  subst h
  exact and_width_mask width_mask_false_eq

/-- `sign_extend v bits` is the machine model's sign extension of the low
`bits` bits, at every width the backend uses. -/
theorem sign_extend_eq {v r : Std.U64} {bits : Std.U32} (hb : 0 < bits.val)
    (hlt : bits.val < 64) (h : x64_sim.sign_extend v bits = ok r) :
    U64.bv r = BitVec.signExtend 64 ((U64.bv v).setWidth bits.val) := by
  unfold x64_sim.sign_extend at h
  rw [if_neg (by rw [uscalar_eq_iff]; intro hc; exact absurd (congrArg BitVec.toNat hc) (by
        show bits.val ≠ (0#u32 : Std.U32).val
        simp only [show ((0#u32 : Std.U32)).val = 0 from rfl]
        omega)),
    if_neg (by
      simp only [ge_iff_le, UScalar.le_equiv, not_le]
      show bits.val < ((64#u32 : Std.U32)).val
      simpa using hlt)] at h
  obtain_bind ⟨i, hi, h⟩ := h
  obtain_bind ⟨m, hm, h⟩ := h
  obtain_bind ⟨val, hval, h⟩ := h
  simp only [lift, ok.injEq] at hval
  subst hval
  obtain_bind ⟨i1, hi1, h⟩ := h
  obtain_bind ⟨i2, hi2, h⟩ := h
  obtain_bind ⟨i3, hi3, h⟩ := h
  simp only [lift, ok.injEq] at hi3
  subst hi3
  -- the mask is `2 ^ bits - 1`
  have hival : i.val = 2 ^ bits.val := by
    have hs := u64_shl_u32 hi
    show (U64.bv i).toNat = _
    rw [hs, BitVec.toNat_shiftLeft]
    rw [show (U64.bv (1#u64 : Std.U64)).toNat = 1 from rfl, Nat.shiftLeft_eq, one_mul]
    exact Nat.mod_eq_of_lt (Nat.pow_lt_pow_right (by norm_num) hlt)
  have hmval : m.val = 2 ^ bits.val - 1 := by
    have hsub := UScalar.sub_equiv i 1#u64
    rw [hm] at hsub
    obtain ⟨-, hsv, -⟩ := hsub
    show m.val = _
    rw [show ((1#u64 : Std.U64)).val = 1 from rfl] at hsv
    omega
  have hvalval : (v &&& m).val = v.val % 2 ^ bits.val := and_mask_val hmval
  -- the sign bit
  have hbit : ((i2 &&& 1#u64) = 1#u64) ↔ (U64.bv v).getLsbD (bits.val - 1) := by
    have h2 := u64_shr_u32 hi2
    have h1 := UScalar.sub_equiv bits 1#u32
    rw [hi1] at h1
    obtain ⟨-, h1v, -⟩ := h1
    rw [show ((1#u32 : Std.U32)).val = 1 from rfl] at h1v
    rw [u64_eq_iff]
    have he : U64.bv (i2 &&& 1#u64) = (U64.bv (v &&& m) >>> (bits.val - 1)) &&& 1#64 := by
      simp only [UScalar.bv_and, h2]
      congr 2
      omega
    rw [he, show U64.bv (1#u64 : Std.U64) = (1#64 : BitVec 64) from rfl, bit_test]
    have hvm : (U64.bv (v &&& m)).getLsbD (bits.val - 1) = (U64.bv v).getLsbD (bits.val - 1) := by
      rw [← BitVec.testBit_toNat, ← BitVec.testBit_toNat]
      show ((v &&& m).val).testBit (bits.val - 1) = (v.val).testBit (bits.val - 1)
      rw [hvalval, Nat.testBit_mod_two_pow]
      simp only [Bool.and_eq_right_iff_imp, decide_eq_true_eq]
      omega
    rw [hvm]
  apply BitVec.eq_of_getLsbD_eq
  intro j hj
  try simp only [UScalarTy.U64_numBits_eq] at hj
  have hmbit : ∀ k, (U64.bv m).getLsbD k = decide (k < bits.val) := by
    intro k
    rw [← BitVec.testBit_toNat]
    show (m.val).testBit k = _
    rw [hmval, Nat.testBit_two_pow_sub_one]
  have hvalbit : ∀ k, (U64.bv (v &&& m)).getLsbD k = (decide (k < bits.val) && (U64.bv v).getLsbD k) := by
    intro k
    rw [← BitVec.testBit_toNat, ← BitVec.testBit_toNat]
    show ((v &&& m).val).testBit k = _
    rw [hvalval, Nat.testBit_mod_two_pow]
    rfl
  have hrhs : (BitVec.signExtend 64 ((U64.bv v).setWidth bits.val)).getLsbD j =
      (if j < bits.val then (U64.bv v).getLsbD j else (U64.bv v).getLsbD (bits.val - 1)) := by
    have hbb : bits.val - 1 < bits.val := by omega
    rw [BitVec.getLsbD_signExtend]
    by_cases hjb : j < bits.val
    · simp [hj, hjb]
    · simp [hj, hjb, hbb, BitVec.msb_eq_getLsbD_last]
  rw [hrhs]
  split at h
  · rename_i hone
    obtain_bind ⟨i4, hi4, h⟩ := h
    simp only [lift, ok.injEq] at hi4
    subst hi4
    simp only [ok.injEq] at h
    subst h
    have hsign : (U64.bv v).getLsbD (bits.val - 1) = true := hbit.mp hone
    simp only [UScalar.bv_or, BitVec.getLsbD_or, not_bv, BitVec.getLsbD_not, hvalbit, hmbit]
    by_cases hjb : j < bits.val
    · simp [hjb, hj]
    · simp [hjb, hj, hsign]
  · rename_i hone
    simp only [ok.injEq] at h
    subst h
    have hsign : (U64.bv v).getLsbD (bits.val - 1) = false := by
      by_contra hc
      exact hone (hbit.mpr (by simpa using hc))
    simp only [hvalbit]
    by_cases hjb : j < bits.val
    · simp [hjb]
    · simp [hjb, hsign]


/-! ## Widths

`wr` is the value an operation of the given width leaves in a register, and
the simulator's `& width_mask` is exactly it. These are the facts that let the
two models be compared at both widths at once. -/

theorem setWidth_sub_3264 (x y : Word) :
    (x - y).setWidth 32 = x.setWidth 32 - y.setWidth 32 := by
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_setWidth, BitVec.toNat_sub, BitVec.toNat_sub, BitVec.toNat_setWidth,
    BitVec.toNat_setWidth]
  have hx := x.isLt
  have hy := y.isLt
  omega

theorem setWidth_add_3264 (x y : Word) :
    (x + y).setWidth 32 = x.setWidth 32 + y.setWidth 32 :=
  BitVec.setWidth_add x y (by norm_num)

@[simp] theorem zx32_lo32 (x : BitVec 32) : lo32 (zx32 x) = x := by simp [lo32, zx32]

@[simp] theorem zx32_toNat (x : BitVec 32) : (zx32 x).toNat = x.toNat := by
  simp only [zx32, BitVec.zeroExtend_eq_setWidth, BitVec.toNat_setWidth]
  have := x.isLt
  omega

theorem zx32_eq_zero (x : BitVec 32) : (zx32 x = 0#64) ↔ (x = 0#32) := by
  constructor
  · intro h
    have h2 := congrArg lo32 h
    rw [zx32_lo32] at h2
    simpa [lo32] using h2
  · intro h
    subst h
    rfl

@[simp] theorem wr_true_eq (v : Word) : wr true v = v := rfl
@[simp] theorem wr_false_eq (v : Word) : wr false v = zx32 (lo32 v) := rfl

/-- The sign bit at the operation's width. -/
def msbW (w64 : Bool) (v : Word) : Bool := if w64 then v.msb else (lo32 v).msb

@[simp] theorem msbW_true (v : Word) : msbW true v = v.msb := rfl
@[simp] theorem msbW_false (v : Word) : msbW false v = (lo32 v).msb := rfl

theorem msb_eq' {w64 : Bool} {v : Std.U64} {b : Bool} (h : x64_sim.msb w64 v = ok b) :
    b = msbW w64 (U64.bv v) := msb_eq h

@[simp] theorem msbW_wr (w64 : Bool) (v : Word) : msbW w64 (wr w64 v) = msbW w64 v := by
  cases w64 <;> simp

@[simp] theorem wr_wr (w64 : Bool) (v : Word) : wr w64 (wr w64 v) = wr w64 v := by
  cases w64 <;> simp

/-- The operation's width in bits. -/
def widthBits (w64 : Bool) : Nat := if w64 then 64 else 32

@[simp] theorem widthBits_true : widthBits true = 64 := rfl
@[simp] theorem widthBits_false : widthBits false = 32 := rfl

theorem wr_toNat (w64 : Bool) (v : Word) :
    (wr w64 v).toNat = v.toNat % 2 ^ widthBits w64 := by
  cases w64 with
  | true =>
    have := v.isLt
    simp only [wr_true_eq, widthBits_true]
    omega
  | false =>
    simp only [wr_false_eq, zx32_toNat, widthBits_false, lo32,
      BitVec.truncate_eq_setWidth, BitVec.toNat_setWidth]

theorem lo32_sub_wr (a b : Word) : lo32 (wr false a - wr false b) = lo32 a - lo32 b := by
  rw [show lo32 (wr false a - wr false b) = lo32 (wr false a) - lo32 (wr false b) from
    setWidth_sub_3264 _ _, wr_false_eq, wr_false_eq, zx32_lo32, zx32_lo32]

theorem lo32_add_wr (a b : Word) : lo32 (wr false a + wr false b) = lo32 a + lo32 b := by
  rw [show lo32 (wr false a + wr false b) = lo32 (wr false a) + lo32 (wr false b) from
    setWidth_add_3264 _ _, wr_false_eq, wr_false_eq, zx32_lo32, zx32_lo32]

theorem uscalar_zero_iff {v : Std.U64} : (v = 0#u64) ↔ (U64.bv v = 0#64) :=
  u64_eq_iff v 0#u64

/-! ## Flags -/

theorem flagsOfLogic_eq (w64 : Bool) (v : Word) :
    flagsOfLogic w64 v =
      { cf := false, zf := decide (wr w64 v = 0#64), sf := msbW w64 v, of := false } := by
  cases w64 with
  | true => simp [flagsOfLogic, logicFlags]
  | false =>
    simp only [flagsOfLogic, Bool.false_eq_true, if_false, logicFlags, wr_false_eq,
      zx32_eq_zero, msbW_false]

theorem flagsOfAddSub_sub_eq (w64 : Bool) (a b : Word) :
    flagsOfAddSub w64 true a b =
      { cf := decide ((wr w64 a).toNat < (wr w64 b).toNat)
        zf := decide (wr w64 (wr w64 a - wr w64 b) = 0#64)
        sf := msbW w64 (wr w64 a - wr w64 b)
        of := if (msbW w64 a != msbW w64 b) = true then
                (msbW w64 (wr w64 a - wr w64 b) != msbW w64 a) else false } := by
  cases w64 with
  | true =>
    simp only [flagsOfAddSub, if_pos, subFlags, wr_true_eq, msbW_true]
    congr 1
    cases a.msb <;> cases b.msb <;> cases (a - b).msb <;> rfl
  | false =>
    have e1 : (wr false a).toNat = (lo32 a).toNat := by rw [wr_false_eq, zx32_toNat]
    have e2 : (wr false b).toNat = (lo32 b).toNat := by rw [wr_false_eq, zx32_toNat]
    have e3 : wr false (wr false a - wr false b) = zx32 (lo32 a - lo32 b) := by
      rw [wr_false_eq, lo32_sub_wr]
    have e4 : msbW false (wr false a - wr false b) = (lo32 a - lo32 b).msb := by
      rw [msbW_false, lo32_sub_wr]
    simp only [flagsOfAddSub, Bool.false_eq_true, if_false, if_true, subFlags, e1, e2, e3, e4,
      zx32_eq_zero, msbW_false]
    congr 1
    cases (lo32 a).msb <;> cases (lo32 b).msb <;> cases (lo32 a - lo32 b).msb <;> rfl

theorem flagsOfAddSub_add_eq (w64 : Bool) (a b : Word) :
    flagsOfAddSub w64 false a b =
      { cf := decide (2 ^ (if w64 then 64 else 32) ≤ (wr w64 a).toNat + (wr w64 b).toNat)
        zf := decide (wr w64 (wr w64 a + wr w64 b) = 0#64)
        sf := msbW w64 (wr w64 a + wr w64 b)
        of := if msbW w64 a = msbW w64 b then
                (msbW w64 (wr w64 a + wr w64 b) != msbW w64 a) else false } := by
  cases w64 with
  | true =>
    simp only [flagsOfAddSub, if_pos, addFlags, wr_true_eq, msbW_true]
    cases a.msb <;> cases b.msb <;> cases (a + b).msb <;> rfl
  | false =>
    have e1 : (wr false a).toNat = (lo32 a).toNat := by rw [wr_false_eq, zx32_toNat]
    have e2 : (wr false b).toNat = (lo32 b).toNat := by rw [wr_false_eq, zx32_toNat]
    have e3 : wr false (wr false a + wr false b) = zx32 (lo32 a + lo32 b) := by
      rw [wr_false_eq, lo32_add_wr]
    have e4 : msbW false (wr false a + wr false b) = (lo32 a + lo32 b).msb := by
      rw [msbW_false, lo32_add_wr]
    simp only [flagsOfAddSub, Bool.false_eq_true, if_false, addFlags, e1, e2, e3, e4,
      zx32_eq_zero, msbW_false]
    congr 1
    cases (lo32 a).msb <;> cases (lo32 b).msb <;> cases (lo32 a + lo32 b).msb <;> rfl


theorem flags_of_logic_eq {w64 : Bool} {r : Std.U64} {f : x64_sim.Flags}
    (h : x64_sim.flags_of_logic w64 r = ok f) :
    absFlags f = flagsOfLogic w64 (U64.bv r) := by
  unfold x64_sim.flags_of_logic at h
  obtain_bind ⟨m, hm, h⟩ := h
  obtain_bind ⟨v, hv, h⟩ := h
  simp only [lift, ok.injEq] at hv
  subst hv
  obtain_bind ⟨b, hb, h⟩ := h
  simp only [ok.injEq] at h
  subst h
  have hbv : U64.bv (r &&& m) = wr w64 (U64.bv r) := and_width_mask hm
  have hz : ((r &&& m) = 0#u64) ↔ (wr w64 (U64.bv r) = 0#64) := by
    rw [uscalar_zero_iff, hbv]
  have hs : b = msbW w64 (U64.bv r) := by rw [msb_eq' hb, hbv, msbW_wr]
  rw [flagsOfLogic_eq]
  simp only [absFlags, Flags.mk.injEq, hs, true_and, and_true]
  exact decide_eq_decide.mpr hz

theorem flags_of_add_sub_eq {w64 sub : Bool} {a b : Std.U64} {f : x64_sim.Flags}
    (h : x64_sim.flags_of_add_sub w64 sub a b = ok f) :
    absFlags f = flagsOfAddSub w64 sub (U64.bv a) (U64.bv b) := by
  unfold x64_sim.flags_of_add_sub at h
  obtain_bind ⟨m, hm, h⟩ := h
  obtain_bind ⟨x, hx, h⟩ := h
  simp only [lift, ok.injEq] at hx
  subst hx
  obtain_bind ⟨y, hy, h⟩ := h
  simp only [lift, ok.injEq] at hy
  subst hy
  obtain_bind ⟨sx, hsx, h⟩ := h
  obtain_bind ⟨sy, hsy, h⟩ := h
  have hxbv : U64.bv (a &&& m) = wr w64 (U64.bv a) := and_width_mask hm
  have hybv : U64.bv (b &&& m) = wr w64 (U64.bv b) := and_width_mask hm
  have hsxv : sx = msbW w64 (U64.bv a) := by rw [msb_eq' hsx, hxbv, msbW_wr]
  have hsyv : sy = msbW w64 (U64.bv b) := by rw [msb_eq' hsy, hybv, msbW_wr]
  have hcf : ((a &&& m) < (b &&& m)) ↔
      ((wr w64 (U64.bv a)).toNat < (wr w64 (U64.bv b)).toNat) := by
    rw [UScalar.lt_equiv]
    show (U64.bv (a &&& m)).toNat < (U64.bv (b &&& m)).toNat ↔ _
    rw [hxbv, hybv]
  split at h
  · -- subtraction
    rename_i hsub
    subst hsub
    obtain_bind ⟨i, hi, h⟩ := h
    obtain_bind ⟨r, hr, h⟩ := h
    simp only [lift, ok.injEq] at hr
    subst hr
    obtain_bind ⟨sr, hsr, h⟩ := h
    have hibv : (U64.bv i) = wr w64 (U64.bv a) - wr w64 (U64.bv b) := by
      rw [sub64_eq hi, hxbv, hybv]
    have hrbv : U64.bv (i &&& m) = wr w64 (wr w64 (U64.bv a) - wr w64 (U64.bv b)) := by
      rw [and_width_mask hm, hibv]
    have hsrv : sr = msbW w64 (wr w64 (U64.bv a) - wr w64 (U64.bv b)) := by
      rw [msb_eq' hsr, hrbv, msbW_wr]
    have hzf : ((i &&& m) = 0#u64) ↔ (wr w64 (wr w64 (U64.bv a) - wr w64 (U64.bv b)) = 0#64) := by
      rw [uscalar_zero_iff, hrbv]
    rw [flagsOfAddSub_sub_eq]
    split at h
    · rename_i hne
      simp only [ok.injEq] at h
      subst h
      rw [hsxv, hsyv] at hne
      simp only [absFlags, Flags.mk.injEq]
      exact ⟨decide_eq_decide.mpr hcf, decide_eq_decide.mpr hzf, hsrv,
        by rw [if_pos hne, hsrv, hsxv]⟩
    · rename_i hne
      simp only [ok.injEq] at h
      subst h
      rw [hsxv, hsyv] at hne
      simp only [absFlags, Flags.mk.injEq]
      exact ⟨decide_eq_decide.mpr hcf, decide_eq_decide.mpr hzf, hsrv, by rw [if_neg hne]⟩
  · -- addition
    rename_i hsub
    simp only [Bool.not_eq_true] at hsub
    subst hsub
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [lift, ok.injEq] at hi
    subst hi
    obtain_bind ⟨i1, hi1, h⟩ := h
    simp only [lift, ok.injEq] at hi1
    subst hi1
    obtain_bind ⟨wide, hwide, h⟩ := h
    obtain_bind ⟨i2, hi2, h⟩ := h
    simp only [lift, ok.injEq] at hi2
    subst hi2
    obtain_bind ⟨i3, hi3, h⟩ := h
    simp only [lift, ok.injEq] at hi3
    subst hi3
    obtain_bind ⟨r, hr, h⟩ := h
    simp only [lift, ok.injEq] at hr
    subst hr
    obtain_bind ⟨sr, hsr, h⟩ := h
    obtain_bind ⟨i4, hi4, h⟩ := h
    simp only [lift, ok.injEq] at hi4
    subst hi4
    -- the width, as a number
    have hmval : m.val = 2 ^ widthBits w64 - 1 := by
      cases w64 with
      | true => simpa using width_mask_true hm
      | false => simpa using width_mask_false hm
    have hkle : widthBits w64 ≤ 64 := by cases w64 <;> simp
    have hmcast : (UScalar.cast .U128 m).val = 2 ^ widthBits w64 - 1 := by
      rw [cast_val_of_lt _ (by
        have := m.hBounds
        simp only [UScalarTy.U64_numBits_eq, UScalarTy.U128_numBits_eq] at *
        omega), hmval]
    have hwideval : wide.val = (wr w64 (U64.bv a)).toNat + (wr w64 (U64.bv b)).toNat := by
      have hadd := UScalar.add_equiv (UScalar.cast .U128 (a &&& m)) (UScalar.cast .U128 (b &&& m))
      rw [hwide] at hadd
      obtain ⟨-, hv, -⟩ := hadd
      rw [hv, cast_val_of_lt _ (by
          have := (a &&& m).hBounds
          simp only [UScalarTy.U64_numBits_eq, UScalarTy.U128_numBits_eq] at *
          omega),
        cast_val_of_lt _ (by
          have := (b &&& m).hBounds
          simp only [UScalarTy.U64_numBits_eq, UScalarTy.U128_numBits_eq] at *
          omega)]
      show (U64.bv (a &&& m)).toNat + (U64.bv (b &&& m)).toNat = _
      rw [hxbv, hybv]
    have hrbv : U64.bv (UScalar.cast .U64 (wide &&& UScalar.cast .U128 m))
        = wr w64 (wr w64 (U64.bv a) + wr w64 (U64.bv b)) := by
      apply BitVec.eq_of_toNat_eq
      show (UScalar.cast .U64 (wide &&& UScalar.cast .U128 m)).val = _
      rw [UScalar.cast_val_eq, and_mask_val hmcast, hwideval,
        wr_toNat w64 (wr w64 (U64.bv a) + wr w64 (U64.bv b)), BitVec.toNat_add]
      have hax := (wr w64 (U64.bv a)).isLt
      have hbx := (wr w64 (U64.bv b)).isLt
      cases w64 with
      | true =>
        simp only [widthBits_true, UScalarTy.U64_numBits_eq]
      | false =>
        simp only [widthBits_false, UScalarTy.U64_numBits_eq]
        have h32 : (wr false (U64.bv a)).toNat < 2 ^ 32 := by
          rw [wr_toNat]; simp only [widthBits_false]; omega
        have h32' : (wr false (U64.bv b)).toNat < 2 ^ 32 := by
          rw [wr_toNat]; simp only [widthBits_false]; omega
        omega
    have hsrv : sr = msbW w64 (wr w64 (U64.bv a) + wr w64 (U64.bv b)) := by
      rw [msb_eq' hsr, hrbv, msbW_wr]
    have hzf : ((UScalar.cast .U64 (wide &&& UScalar.cast .U128 m)) = 0#u64)
        ↔ (wr w64 (wr w64 (U64.bv a) + wr w64 (U64.bv b)) = 0#64) := by
      rw [uscalar_zero_iff, hrbv]
    have hcfa : (wide > UScalar.cast .U128 m) ↔
        (2 ^ widthBits w64 ≤ (wr w64 (U64.bv a)).toNat + (wr w64 (U64.bv b)).toNat) := by
      simp only [gt_iff_lt, UScalar.lt_equiv, hmcast, hwideval]
      have : 0 < 2 ^ widthBits w64 := Nat.two_pow_pos _
      omega
    rw [flagsOfAddSub_add_eq]
    split at h
    · rename_i heq
      simp only [ok.injEq] at h
      subst h
      rw [hsxv, hsyv] at heq
      simp only [absFlags, Flags.mk.injEq]
      exact ⟨decide_eq_decide.mpr hcfa, decide_eq_decide.mpr hzf, hsrv,
        by rw [if_pos heq, hsrv, hsxv]⟩
    · rename_i hne
      simp only [ok.injEq] at h
      subst h
      rw [hsxv, hsyv] at hne
      simp only [absFlags, Flags.mk.injEq]
      exact ⟨decide_eq_decide.mpr hcfa, decide_eq_decide.mpr hzf, hsrv, by rw [if_neg hne]⟩


/-! ## Conditions, flag words, widths -/

theorem uscalar_ne_val {ty : UScalarTy} {x y : UScalar ty} (h : ¬ (x = y)) : x.val ≠ y.val :=
  fun hv => h (UScalar.eq_of_val_eq hv)

theorem cond_eq {cc : Std.U8} {f : x64_sim.Flags} {b : Bool} (h : x64_sim.cond cc f = ok b) :
    b = cond cc (absFlags f) := by
  unfold x64_sim.cond at h
  unfold cond
  repeat' split at h
  all_goals (try (rename_i hc; subst hc))
  all_goals simp_all [absFlags]
  all_goals (try (subst_vars; cases f.sf <;> cases f.of <;> rfl))

theorem flags_word_eq {f : x64_sim.Flags} {v : Std.U64} (h : x64_sim.flags_word f = ok v) :
    U64.bv v = flagsWord (absFlags f) := by
  unfold x64_sim.flags_word at h
  cases hcf : f.cf <;> cases hzf : f.zf <;> cases hsf : f.sf <;> cases hof : f.of <;>
    simp_all [absFlags, flagsWord, lift] <;> (subst_vars; rfl)

theorem flags_of_word_eq {v : Std.U64} {f : x64_sim.Flags} (h : x64_sim.flags_of_word v = ok f) :
    absFlags f = flagsOfWord (U64.bv v) := by
  unfold x64_sim.flags_of_word at h
  obtain_bind ⟨i, hi, h⟩ := h
  obtain_bind ⟨i1, hi1, h⟩ := h
  simp only [lift, ok.injEq] at hi1
  subst hi1
  obtain_bind ⟨i2, hi2, h⟩ := h
  obtain_bind ⟨i3, hi3, h⟩ := h
  simp only [lift, ok.injEq] at hi3
  subst hi3
  obtain_bind ⟨i4, hi4, h⟩ := h
  obtain_bind ⟨i5, hi5, h⟩ := h
  simp only [lift, ok.injEq] at hi5
  subst hi5
  obtain_bind ⟨i6, hi6, h⟩ := h
  obtain_bind ⟨i7, hi7, h⟩ := h
  simp only [lift, ok.injEq] at hi7
  subst hi7
  simp only [ok.injEq] at h
  subst h
  have e : ∀ (j : Std.U64) (k : Nat), U64.bv j = (U64.bv v) >>> k →
      ((((j &&& 1#u64) = 1#u64)) ↔ ((U64.bv v).getLsbD k = true)) := by
    intro j k hj
    rw [u64_eq_iff]
    have he : U64.bv (j &&& 1#u64) = ((U64.bv v) >>> k) &&& 1#64 := by
      simp only [UScalar.bv_and, hj]
      rfl
    rw [he, show U64.bv (1#u64 : Std.U64) = (1#64 : BitVec 64) from rfl, bit_test]
  have b0 := e i 0 (by rw [u64_shr_i32 hi]; rfl)
  have b6 := e i2 6 (by rw [u64_shr_i32 hi2]; rfl)
  have b7 := e i4 7 (by rw [u64_shr_i32 hi4]; rfl)
  have b11 := e i6 11 (by rw [u64_shr_i32 hi6]; rfl)
  simp only [absFlags, flagsOfWord, Flags.mk.injEq]
  refine ⟨?_, ?_, ?_, ?_⟩ <;> simp [b0, b6, b7, b11]

theorem width_bits_eq {w64 : Bool} {n : Std.U32} (h : x64_sim.width_bits w64 = ok n) :
    n.val = widthBits w64 := by
  unfold x64_sim.width_bits at h
  cases w64 with
  | true =>
    rw [if_pos rfl] at h
    simp only [ok.injEq] at h
    subst h
    rfl
  | false =>
    rw [if_neg (by simp)] at h
    simp only [ok.injEq] at h
    subst h
    rfl

theorem op_width_eq {w64 : Bool} {n : Usize} (h : x64_sim.op_width w64 = ok n) :
    n.val = opWidth w64 := by
  unfold x64_sim.op_width at h
  cases w64 with
  | true =>
    rw [if_pos rfl] at h
    simp only [ok.injEq] at h
    subst h
    rfl
  | false =>
    rw [if_neg (by simp)] at h
    simp only [ok.injEq] at h
    subst h
    rfl

theorem size_bytes_eq {size : Std.U8} {n : Usize} (h : x64_sim.size_bytes size = ok n)
    (hn : n.val ≠ 0) : n.val = size.val := by
  unfold x64_sim.size_bytes at h
  repeat' split at h
  all_goals (try (rename_i hc; subst hc))
  all_goals simp_all
  all_goals (subst_vars; rfl)

theorem sx32_eq {imm : Std.I32} {r : Std.U64} (h : x64_sim.sx32 imm = ok r) :
    U64.bv r = BitVec.signExtend 64 imm.bv := by
  unfold x64_sim.sx32 at h
  obtain_bind ⟨i, hi, h⟩ := h
  simp only [lift, ok.injEq] at hi
  subst hi
  obtain_bind ⟨i1, hi1, h⟩ := h
  simp only [lift, ok.injEq] at hi1
  subst hi1
  have hbits : ((32#u32 : Std.U32)).val = 32 := rfl
  rw [sign_extend_eq (by rw [hbits]; norm_num) (by rw [hbits]; norm_num) h, hbits]
  congr 1
  have hc : (U64.bv (UScalar.cast .U64 (IScalar.hcast .U32 imm)))
      = ((imm.bv).signExtend 32).setWidth 64 := rfl
  rw [hc]
  simp


/-! ## Memory

The simulator keeps one mapped range, `[mem_base, mem_base + mem.len())`, as a
`Vec<u8>`, and reads and writes it a byte at a time; `Bytes.lean` reads the
same bytes out of a total memory. The two loops are related to `loadNat` and
`store` below, with the no-wrap hypothesis (`mem_base + len ≤ 2 ^ 64`) doing
the work of turning "the range" into a range. -/

theorem bv_add_ofNat_succ (a : Word) (i : Nat) :
    a + 1#64 + BitVec.ofNat 64 i = a + BitVec.ofNat 64 (i + 1) := by
  apply BitVec.eq_of_toNat_eq
  simp only [BitVec.toNat_add, BitVec.toNat_ofNat, Nat.mod_add_mod, Nat.add_mod_mod]
  congr 1
  omega

theorem loadNat_lt : ∀ (n : Nat) (m : Mem) (a : Word), loadNat n m a < 256 ^ n
  | 0, _, _ => by simp [loadNat]
  | n + 1, m, a => by
    have hIH := loadNat_lt n m (a + 1#64)
    have hb : (m a).toNat < 256 := (m a).isLt
    simp only [loadNat]
    have : (256 : Nat) ^ (n + 1) = 256 * 256 ^ n := by ring
    omega

theorem loadNat_succ : ∀ (n : Nat) (m : Mem) (a : Word),
    loadNat (n + 1) m a = loadNat n m a + (m (a + BitVec.ofNat 64 n)).toNat * 256 ^ n
  | 0, m, a => by
    simp [loadNat]
  | n + 1, m, a => by
    have hIH := loadNat_succ n m (a + 1#64)
    rw [show loadNat (n + 1 + 1) m a = (m a).toNat + 256 * loadNat (n + 1) m (a + 1#64) from rfl,
      show loadNat (n + 1) m a = (m a).toNat + 256 * loadNat n m (a + 1#64) from rfl,
      hIH, bv_add_ofNat_succ]
    ring

/-- The byte the abstract memory holds at an address inside the mapped range. -/
theorem absMem_in (s : x64_sim.Sim) (x : Word)
    (h1 : s.mem_base.val ≤ x.toNat) (h2 : x.toNat < s.mem_base.val + s.mem.val.length) :
    absMem s x = U8.bv (s.mem.val[x.toNat - s.mem_base.val]!) := by
  have hb : (x - U64.bv s.mem_base).toNat = x.toNat - s.mem_base.val := by
    rw [BitVec.toNat_sub]
    have hxlt := x.isLt
    have hblt : (U64.bv s.mem_base).toNat < 2 ^ 64 := (U64.bv s.mem_base).isLt
    show (2 ^ 64 - s.mem_base.val + x.toNat) % 2 ^ 64 = _
    have : s.mem_base.val ≤ x.toNat := h1
    omega
  simp only [absMem, InRange, hb]
  rw [if_pos ⟨h1, h2⟩]

theorem in_bounds_true {s : x64_sim.Sim} {a : Std.U64} {n : Usize}
    (h : x64_sim.in_bounds s a n = ok true) :
    s.mem_base.val ≤ a.val ∧ a.val + n.val ≤ s.mem_base.val + s.mem.val.length := by
  unfold x64_sim.in_bounds at h
  obtain_bind ⟨lo, hlo, h⟩ := h
  simp only [lift, ok.injEq] at hlo
  subst hlo
  obtain_bind ⟨i1, hi1, h⟩ := h
  simp only [lift, ok.injEq] at hi1
  subst hi1
  obtain_bind ⟨hi, hhi, h⟩ := h
  obtain_bind ⟨start, hstart, h⟩ := h
  simp only [lift, ok.injEq] at hstart
  subst hstart
  obtain_bind ⟨i2, hi2, h⟩ := h
  simp only [lift, ok.injEq] at hi2
  subst hi2
  obtain_bind ⟨e, he, h⟩ := h
  have hcast : ∀ (x : Std.U64), (UScalar.cast .U128 x).val = x.val := by
    intro x
    exact cast_val_of_lt _ (by
      have := x.hBounds
      simp only [UScalarTy.U64_numBits_eq, UScalarTy.U128_numBits_eq] at *
      omega)
  have hcastu : ∀ (x : Usize), (UScalar.cast .U128 x).val = x.val := by
    intro x
    refine cast_val_of_lt _ ?_
    have := x.hBounds
    have h2 : (2 : Nat) ^ (UScalarTy.Usize).numBits ≤ 2 ^ (UScalarTy.U128).numBits := by
      apply Nat.pow_le_pow_right (by norm_num)
      simp only [UScalarTy.Usize_numBits_eq, UScalarTy.U128_numBits_eq]
      cases System.Platform.numBits_eq with
      | inl h32 => omega
      | inr h64 => omega
    omega
  have hhiv : hi.val = s.mem_base.val + s.mem.val.length := by
    have hadd := UScalar.add_equiv (UScalar.cast .U128 s.mem_base)
      (UScalar.cast .U128 (alloc.vec.Vec.len s.mem))
    rw [hhi] at hadd
    obtain ⟨-, hv, -⟩ := hadd
    rw [hv, hcast, hcastu]
    simp
  have hev : e.val = a.val + n.val := by
    have hadd := UScalar.add_equiv (UScalar.cast .U128 a) (UScalar.cast .U128 n)
    rw [he] at hadd
    obtain ⟨-, hv, -⟩ := hadd
    rw [hv, hcast, hcastu]
  split at h
  · rename_i hge
    simp only [ok.injEq] at h
    have hle : e.val ≤ hi.val := by
      have := of_decide_eq_true h
      rw [UScalar.le_equiv] at this
      exact this
    have hge' : (UScalar.cast .U128 s.mem_base).val ≤ (UScalar.cast .U128 a).val := by
      simp only [ge_iff_le, UScalar.le_equiv] at hge
      exact hge
    rw [hcast, hcast] at hge'
    omega
  · simp at h


/-- Or-ing a byte into the free bits above a partial word is addition. -/
theorem or_shift_add {v b : Word} {k : Nat} (hv : v.toNat < 2 ^ k) (hb : b.toNat < 256)
    (hk : k + 8 ≤ 64) : (v ||| (b <<< k)).toNat = v.toNat + b.toNat * 2 ^ k := by
  have hle : b.toNat * 2 ^ k ≤ 255 * 2 ^ k := Nat.mul_le_mul_right _ (by omega)
  have h256 : (256 : Nat) * 2 ^ k = 2 ^ (k + 8) := by ring
  have hpow : (2 : Nat) ^ (k + 8) ≤ 2 ^ 64 := Nat.pow_le_pow_right (by norm_num) hk
  have hsum : v.toNat + b.toNat * 2 ^ k < 2 ^ 64 := by omega
  have hshift : (b <<< k).toNat = b.toNat * 2 ^ k := by
    rw [BitVec.toNat_shiftLeft, Nat.shiftLeft_eq]
    exact Nat.mod_eq_of_lt (by omega)
  have hand : v &&& (b <<< k) = 0#64 := by
    apply BitVec.eq_of_getLsbD_eq
    intro j hj
    simp only [BitVec.getLsbD_and, BitVec.getLsbD_zero, BitVec.getLsbD_shiftLeft]
    by_cases hjk : j < k
    · simp [hjk]
    · have hvz : v.getLsbD j = false := by
        rw [← BitVec.testBit_toNat]
        exact Nat.testBit_lt_two_pow (lt_of_lt_of_le hv (Nat.pow_le_pow_right (by norm_num)
          (by omega)))
      simp [hvz]
  rw [← BitVec.add_eq_or_of_and_eq_zero v (b <<< k) hand, BitVec.toNat_add, hshift]
  exact Nat.mod_eq_of_lt (by omega)

/-- The loop `load_mem` runs: after `i` steps the accumulator holds the `i`
low bytes of the range, which is `loadNat i`. -/
theorem load_mem_loop_eq {s : x64_sim.Sim} {a : Std.U64} {n off : Usize} {b : Bool}
    {v : Std.U64} {i : Usize} {res : Bool × Std.U64}
    (hn : n.val ≤ 8)
    (hoff : off.val = a.val - s.mem_base.val)
    (hlo : s.mem_base.val ≤ a.val)
    (hhi : a.val + n.val ≤ s.mem_base.val + s.mem.val.length)
    (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (hb : b = true) (hi : i.val ≤ n.val)
    (hv : v.val = loadNat i.val (absMem s) (U64.bv a))
    (h : x64_sim.load_mem_loop s n b off v i = ok res) :
    res.1 = true ∧ res.2.val = loadNat n.val (absMem s) (U64.bv a) := by
  unfold x64_sim.load_mem_loop at h
  refine loop_ok_induction _
    (fun st => st.1 = true ∧ st.2.2.val ≤ n.val ∧
      st.2.1.val = loadNat st.2.2.val (absMem s) (U64.bv a))
    (fun r => r.1 = true ∧ r.2.val = loadNat n.val (absMem s) (U64.bv a))
    ?_ (b, v, i) res ⟨hb, hi, hv⟩ h
  rintro ⟨b', v', i'⟩ ⟨hb', hi', hv'⟩ r hbody
  dsimp only at hb' hi' hv'
  subst hb'
  simp only [x64_sim.load_mem_loop.body] at hbody
  rw [if_pos trivial] at hbody
  split at hbody
  · -- another byte
    rename_i hlt
    have hltv : i'.val < n.val := by rw [UScalar.lt_equiv] at hlt; exact hlt
    obtain_bind ⟨idx, hidx, hbody⟩ := hbody
    have hidxv : idx.val = off.val + i'.val := usize_add_eq_ok hidx
    obtain_bind ⟨v1, hv1, hbody⟩ := hbody
    obtain_bind ⟨i2, hi2, hbody⟩ := hbody
    have hi2v : i2.val = i'.val + 1 := usize_add_eq_ok hi2
    simp only [ok.injEq] at hbody
    subst hbody
    refine ⟨rfl, (by show i2.val ≤ n.val; omega), ?_⟩
    -- the byte that was read
    have hidxlt : idx.val < s.mem.val.length := by omega
    split at hv1
    · obtain_bind ⟨i3, hi3, hv1⟩ := hv1
      obtain ⟨hi3lt, hi3v⟩ := vec_index_eq_ok hi3
      obtain_bind ⟨i4, hi4, hv1⟩ := hv1
      simp only [lift, ok.injEq] at hi4
      subst hi4
      obtain_bind ⟨i5, hi5, hv1⟩ := hv1
      obtain_bind ⟨i6, hi6, hv1⟩ := hv1
      simp only [ok.injEq] at hv1
      subst hv1
      have hi5v : i5.val = 8 * i'.val := usize_mul_eq_ok hi5
      have hi6bv : U64.bv i6 = (U64.bv (UScalar.cast .U64 i3)) <<< i5.val :=
        u64_shl_usize hi6
      have hbyteval : (UScalar.cast .U64 i3).val = i3.val :=
        cast_val_of_lt _ (by
          have := i3.hBounds
          simp only [UScalarTy.U8_numBits_eq, UScalarTy.U64_numBits_eq] at *
          omega)
      have hbyte : (UScalar.cast .U64 i3).val < 256 := by
        rw [hbyteval]
        have := i3.hBounds
        simpa using this
      have he256 : (256 : Nat) ^ i'.val = 2 ^ (8 * i'.val) := by
        rw [show (256 : Nat) = 2 ^ 8 from rfl, ← pow_mul]
      have hvlt : v'.val < 2 ^ (8 * i'.val) := by
        rw [hv']
        have hlt256 := loadNat_lt i'.val (absMem s) (U64.bv a)
        omega
      have hor : (v' ||| i6).val = v'.val + (UScalar.cast .U64 i3).val * 2 ^ (8 * i'.val) := by
        show ((U64.bv v') ||| (U64.bv i6)).toNat = _
        rw [hi6bv, hi5v]
        exact or_shift_add hvlt hbyte (by omega)
      have haddr : ((U64.bv a) + BitVec.ofNat 64 i'.val).toNat = a.val + i'.val := by
        have ha : (U64.bv a).toNat = a.val := rfl
        have hof : (BitVec.ofNat 64 i'.val).toNat = i'.val := by
          rw [BitVec.toNat_ofNat]
          exact Nat.mod_eq_of_lt (by omega)
        rw [BitVec.toNat_add, ha, hof]
        exact Nat.mod_eq_of_lt (by omega)
      have hidxeq : a.val + i'.val - s.mem_base.val = idx.val := by omega
      have hget : s.mem.val[idx.val]! = s.mem.val[idx.val]'hi3lt := by
        rw [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem hi3lt]
        rfl
      have hbyteabs : ((absMem s) ((U64.bv a) + BitVec.ofNat 64 i'.val)).toNat
          = (UScalar.cast .U64 i3).val := by
        rw [absMem_in s _ (by rw [haddr]; omega) (by rw [haddr]; omega), haddr, hidxeq, hget,
          ← hi3v, hbyteval]
        rfl
      rw [hi2v, loadNat_succ, ← hv', hor, hbyteabs, he256]
    · rename_i hge
      exact absurd (by rw [UScalar.lt_equiv]; simpa using hidxlt) hge
  · -- the range is done
    rename_i hge
    simp only [ok.injEq] at hbody
    subst hbody
    have : i'.val = n.val := by
      rw [UScalar.lt_equiv] at hge
      omega
    exact ⟨rfl, by rw [hv', this]⟩


theorem load_mem_loop_false {s : x64_sim.Sim} {n off : Usize} {v : Std.U64} {i : Usize}
    {res : Bool × Std.U64} (h : x64_sim.load_mem_loop s n false off v i = ok res) :
    res.1 = false := by
  unfold x64_sim.load_mem_loop at h
  refine loop_ok_induction _ (fun st => st.1 = false) (fun r => r.1 = false) ?_
    (false, v, i) res rfl h
  rintro ⟨b', v', i'⟩ hb' r hbody
  dsimp only at hb'
  subst hb'
  simp only [x64_sim.load_mem_loop.body] at hbody
  rw [if_neg (by simp)] at hbody
  simp only [ok.injEq] at hbody
  subst hbody
  rfl

theorem usize_max_lt : (Usize.max : Nat) < 2 ^ (UScalarTy.Usize).numBits := by
  simp only [UScalarTy.Usize_numBits_eq, Usize.max, Usize.numBits]
  cases System.Platform.numBits_eq with
  | inl h32 => simp [h32]
  | inr h64 => simp [h64]

/-- A successful load reads the bytes the abstract memory holds. -/
theorem load_mem_eq {s : x64_sim.Sim} {a : Std.U64} {n : Usize} {v : Std.U64}
    (hn : n.val ≤ 8) (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.load_mem s a n = ok (true, v)) :
    v.val = loadNat n.val (absMem s) (U64.bv a) ∧
      s.mem_base.val ≤ a.val ∧ a.val + n.val ≤ s.mem_base.val + s.mem.val.length := by
  unfold x64_sim.load_mem at h
  obtain_bind ⟨ok1, hok1, h⟩ := h
  cases ok1 with
  | false =>
    obtain_bind ⟨p, hp, h⟩ := h
    simp only [Bool.false_eq_true, if_false, ok.injEq] at hp
    obtain ⟨rfl, rfl⟩ := hp
    have := load_mem_loop_false h
    simp at this
  | true =>
    obtain ⟨hlo, hhi⟩ := in_bounds_true hok1
    obtain_bind ⟨p, hp, h⟩ := h
    rw [if_pos rfl] at hp
    obtain_bind ⟨d, hd, hp⟩ := hp
    obtain_bind ⟨off, hoff, hp⟩ := hp
    simp only [lift, ok.injEq] at hoff
    subst hoff
    simp only [ok.injEq] at hp
    subst hp
    have hdv : d.val = a.val - s.mem_base.val := by
      have hsub := UScalar.sub_equiv a s.mem_base
      rw [hd] at hsub
      obtain ⟨-, hv, -⟩ := hsub
      omega
    have hoffv : (UScalar.cast .Usize d).val = a.val - s.mem_base.val := by
      rw [cast_val_of_lt _ (by
        have hlen : s.mem.val.length ≤ Usize.max := s.mem.property
        have := usize_max_lt
        omega), hdv]
    exact ⟨(load_mem_loop_eq hn hoffv hlo hhi hmem rfl (by simp) (by simp [loadNat]) h).2,
      hlo, hhi⟩


/-- The loop `store_mem` runs: after `i` steps the vector holds the `i` low
bytes of the value at the offset, and nothing else has moved. -/
theorem store_mem_loop_eq {s : x64_sim.Sim} {n off len : Usize} {v : Std.U64}
    {vec : alloc.vec.Vec Std.U8} {b : Bool} {i : Usize} {res : (alloc.vec.Vec Std.U8) × Bool}
    (hlen : len.val = s.mem.val.length)
    (hoff : off.val + n.val ≤ s.mem.val.length)
    (hb : b = true) (hi : i.val ≤ n.val)
    (hveclen : vec.val.length = s.mem.val.length)
    (hwritten : ∀ k, k < i.val → (vec.val[off.val + k]!).val = (v.val / 2 ^ (8 * k)) % 256)
    (hkept : ∀ j, (j < off.val ∨ off.val + i.val ≤ j) → vec.val[j]! = s.mem.val[j]!)
    (h : x64_sim.store_mem_loop vec n v b off len i = ok res) :
    res.2 = true ∧ res.1.val.length = s.mem.val.length ∧
      (∀ k, k < n.val → (res.1.val[off.val + k]!).val = (v.val / 2 ^ (8 * k)) % 256) ∧
      (∀ j, (j < off.val ∨ off.val + n.val ≤ j) → res.1.val[j]! = s.mem.val[j]!) := by
  unfold x64_sim.store_mem_loop at h
  refine loop_ok_induction _
    (fun st => st.2.1 = true ∧ st.2.2.val ≤ n.val ∧ st.1.val.length = s.mem.val.length ∧
      (∀ k, k < st.2.2.val → (st.1.val[off.val + k]!).val = (v.val / 2 ^ (8 * k)) % 256) ∧
      (∀ j, (j < off.val ∨ off.val + st.2.2.val ≤ j) → st.1.val[j]! = s.mem.val[j]!))
    (fun r => r.2 = true ∧ r.1.val.length = s.mem.val.length ∧
      (∀ k, k < n.val → (r.1.val[off.val + k]!).val = (v.val / 2 ^ (8 * k)) % 256) ∧
      (∀ j, (j < off.val ∨ off.val + n.val ≤ j) → r.1.val[j]! = s.mem.val[j]!))
    ?_ (vec, b, i) res ⟨hb, hi, hveclen, hwritten, hkept⟩ h
  rintro ⟨vec', b', i'⟩ ⟨hb', hi', hveclen', hwritten', hkept'⟩ r hbody
  dsimp only at hb' hi' hveclen' hwritten' hkept'
  subst hb'
  simp only [x64_sim.store_mem_loop.body] at hbody
  rw [if_pos trivial] at hbody
  split at hbody
  · rename_i hlt
    have hltv : i'.val < n.val := by rw [UScalar.lt_equiv] at hlt; exact hlt
    obtain_bind ⟨idx, hidx, hbody⟩ := hbody
    have hidxv : idx.val = off.val + i'.val := usize_add_eq_ok hidx
    obtain_bind ⟨vec2, hvec2, hbody⟩ := hbody
    obtain_bind ⟨i1, hi1, hbody⟩ := hbody
    have hi1v : i1.val = i'.val + 1 := usize_add_eq_ok hi1
    simp only [ok.injEq] at hbody
    subst hbody
    split at hvec2
    · -- the byte is written
      obtain_bind ⟨j1, hj1, hvec2⟩ := hvec2
      have hj1v : j1.val = 8 * i'.val := usize_mul_eq_ok hj1
      obtain_bind ⟨j2, hj2, hvec2⟩ := hvec2
      have hj2v : j2.val = v.val / 2 ^ (8 * i'.val) := by
        show (U64.bv j2).toNat = _
        rw [u64_shr_usize hj2, BitVec.toNat_ushiftRight, hj1v, Nat.shiftRight_eq_div_pow]
        rfl
      obtain_bind ⟨j3, hj3, hvec2⟩ := hvec2
      simp only [lift, ok.injEq] at hj3
      subst hj3
      obtain_bind ⟨pair, hpair, hvec2⟩ := hvec2
      obtain ⟨x0, back⟩ := pair
      obtain ⟨hidxlt, -, rfl⟩ := vec_index_mut_eq_ok hpair
      have hidxlt' : idx.val < vec'.val.length := hidxlt
      obtain_bind ⟨j4, hj4, hvec2⟩ := hvec2
      simp only [lift, ok.injEq] at hj4
      subst hj4
      simp only [ok.injEq] at hvec2
      subst hvec2
      have hbyte : (UScalar.cast .U8 (j2 &&& 255#u64)).val = (v.val / 2 ^ (8 * i'.val)) % 256 := by
        have h255 : ((255#u64 : Std.U64)).val = 2 ^ 8 - 1 := rfl
        rw [cast_val_of_lt _ (by
          rw [and_mask_val h255]
          have : v.val / 2 ^ (8 * i'.val) % 2 ^ 8 < 2 ^ 8 := Nat.mod_lt _ (by norm_num)
          simp only [UScalarTy.U8_numBits_eq]
          omega), and_mask_val h255, hj2v]
        norm_num
      dsimp only
      refine ⟨rfl, (by omega), ?_, ?_, ?_⟩
      · show (alloc.vec.Vec.set vec' idx _).val.length = _
        rw [alloc.vec.Vec.set_val_eq, List.length_set]
        exact hveclen'
      · intro k hk
        show ((alloc.vec.Vec.set vec' idx _).val[off.val + k]!).val = _
        rw [alloc.vec.Vec.set_val_eq]
        by_cases hkk : k = i'.val
        · subst hkk
          rw [List.getElem!_eq_getElem?_getD, ← hidxv,
            List.getElem?_set_self (by omega)]
          exact hbyte
        · rw [List.getElem!_eq_getElem?_getD, List.getElem?_set_ne (by omega),
            ← List.getElem!_eq_getElem?_getD]
          exact hwritten' k (by omega)
      · intro j hj
        show (alloc.vec.Vec.set vec' idx _).val[j]! = _
        rw [alloc.vec.Vec.set_val_eq, List.getElem!_eq_getElem?_getD,
          List.getElem?_set_ne (by omega), ← List.getElem!_eq_getElem?_getD]
        exact hkept' j (by omega)
    · -- out of the vector: impossible, the range is inside it
      rename_i hge
      exact absurd (by rw [UScalar.lt_equiv]; omega) hge
  · rename_i hge
    simp only [ok.injEq] at hbody
    subst hbody
    have heq : i'.val = n.val := by
      rw [UScalar.lt_equiv] at hge
      omega
    exact ⟨rfl, hveclen', by rw [← heq]; exact hwritten', by rw [← heq]; exact hkept'⟩


theorem bv_sub_toNat {x a : Word} (h : a.toNat ≤ x.toNat) : (x - a).toNat = x.toNat - a.toNat := by
  rw [BitVec.toNat_sub]
  have := x.isLt
  have := a.isLt
  omega

/-- An address whose distance from `a` is less than `n` sits `n` bytes above
`a`, when the window does not wrap. -/
theorem in_window {x a : Word} {n : Nat} (hlt : (x - a).toNat < n) (hnw : a.toNat + n ≤ 2 ^ 64) :
    a.toNat ≤ x.toNat ∧ x.toNat = a.toNat + (x - a).toNat := by
  rw [BitVec.toNat_sub] at hlt ⊢
  have := x.isLt
  have := a.isLt
  omega

/-- The byte a store of `v` writes at offset `k`. -/
theorem byteAt_storeVal {n k : Nat} (v : Word) (hk : k < n) :
    (byteAt (storeVal n v).toNat k).toNat = (v.toNat / 2 ^ (8 * k)) % 256 := by
  have hsv : (storeVal n v).toNat = v.toNat % 2 ^ (8 * n) := by
    simp only [storeVal, BitVec.truncate_eq_setWidth, BitVec.toNat_setWidth]
  have hsplit : (2 : Nat) ^ (8 * k) * 2 ^ (8 * (n - k)) = 2 ^ (8 * n) := by
    rw [← pow_add]
    congr 1
    omega
  have hdvd : (256 : Nat) ∣ 2 ^ (8 * (n - k)) := by
    have h8 : (8 : Nat) ≤ 8 * (n - k) := by omega
    have hp : (2 : Nat) ^ 8 ∣ 2 ^ (8 * (n - k)) := pow_dvd_pow 2 h8
    simpa using hp
  simp only [byteAt, BitVec.toNat_ofNat, hsv]
  rw [← hsplit, Nat.mod_mul_right_div_self, Nat.mod_mod_of_dvd _ hdvd]

/-- A successful store writes the bytes `Bytes.store` writes, and nothing
else moves. -/
theorem store_mem_eq {s s' : x64_sim.Sim} {a : Std.U64} {n : Usize} {v : Std.U64}
    (hn : n.val ≤ 8) (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.store_mem s a n v = ok (true, s')) :
    s' = { s with mem := s'.mem } ∧ s'.mem.val.length = s.mem.val.length ∧
      absState s' = { absState s with
        mem := store n.val (absState s).mem (U64.bv a) (storeVal n.val (U64.bv v)) } := by
  unfold x64_sim.store_mem at h
  obtain_bind ⟨ok1, hok1, h⟩ := h
  cases ok1 with
  | false =>
    obtain_bind ⟨p, hp, h⟩ := h
    simp only [Bool.false_eq_true, if_false, ok.injEq] at hp
    obtain ⟨rfl, rfl⟩ := hp
    obtain_bind ⟨q, hq, h⟩ := h
    obtain ⟨vfin, okfin⟩ := q
    have hfalse : okfin = false := by
      unfold x64_sim.store_mem_loop at hq
      refine loop_ok_induction _ (fun st => st.2.1 = false) (fun r => r.2 = false) ?_
        (s.mem, false, 0#usize) (vfin, okfin) rfl hq
      rintro ⟨vec', b', i'⟩ hb' r hbody
      dsimp only at hb'
      subst hb'
      simp only [x64_sim.store_mem_loop.body] at hbody
      rw [if_neg (by simp)] at hbody
      simp only [ok.injEq] at hbody
      subst hbody
      rfl
    replace h : ok (okfin, ({ s with mem := vfin } : x64_sim.Sim)) = ok (true, s') := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    rw [h.1] at hfalse
    simp at hfalse
  | true =>
    obtain ⟨hlo, hhi⟩ := in_bounds_true hok1
    obtain_bind ⟨p, hp, h⟩ := h
    rw [if_pos rfl] at hp
    obtain_bind ⟨d, hd, hp⟩ := hp
    obtain_bind ⟨off, hoff, hp⟩ := hp
    simp only [lift, ok.injEq] at hoff
    subst hoff
    simp only [ok.injEq] at hp
    subst hp
    have hdv : d.val = a.val - s.mem_base.val := by
      have hsub := UScalar.sub_equiv a s.mem_base
      rw [hd] at hsub
      obtain ⟨-, hv, -⟩ := hsub
      omega
    have hoffv : (UScalar.cast .Usize d).val = a.val - s.mem_base.val := by
      rw [cast_val_of_lt _ (by
        have hlen : s.mem.val.length ≤ Usize.max := s.mem.property
        have := usize_max_lt
        omega), hdv]
    obtain_bind ⟨q, hq, h⟩ := h
    obtain ⟨vfin, okfin⟩ := q
    replace h : ok (okfin, ({ s with mem := vfin } : x64_sim.Sim)) = ok (true, s') := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hq2, rfl⟩ := h
    obtain ⟨-, hlen', hwritten, hkept⟩ :=
      store_mem_loop_eq (s := s) (n := n) (off := UScalar.cast .Usize d)
        (len := alloc.vec.Vec.len s.mem) (v := v) (vec := s.mem) (b := true) (i := 0#usize)
        (res := (vfin, okfin)) (by simp) (by omega) rfl (by simp) rfl
        (by intro k hk; simp at hk) (by intro j _; rfl) hq
    dsimp only at hlen' hwritten hkept
    refine ⟨rfl, hlen', ?_⟩
    have hmemeq : absMem { s with mem := vfin }
        = store n.val (absMem s) (U64.bv a) (storeVal n.val (U64.bv v)) := by
      funext x
      have hbase : ({ s with mem := vfin } : x64_sim.Sim).mem_base = s.mem_base := rfl
      have hav : (U64.bv a).toNat = a.val := rfl
      by_cases hin : (x - (U64.bv a)).toNat < n.val
      · obtain ⟨hax, hxv⟩ := in_window hin (by
          show a.val + n.val ≤ 2 ^ 64
          omega)
        have hxr1 : s.mem_base.val ≤ x.toNat := by omega
        have hxr2 : x.toNat < s.mem_base.val + s.mem.val.length := by omega
        rw [store, if_pos hin]
        rw [show absMem { s with mem := vfin } x
            = U8.bv (vfin.val[x.toNat - s.mem_base.val]!) from
          absMem_in { s with mem := vfin } x (by rw [hbase]; omega) (by rw [hbase, hlen']; omega)]
        apply BitVec.eq_of_toNat_eq
        rw [byteAt_storeVal _ hin]
        rw [show x.toNat - s.mem_base.val
            = (UScalar.cast .Usize d).val + (x - (U64.bv a)).toNat by omega]
        exact hwritten _ hin
      · rw [store, if_neg hin]
        by_cases hr : s.mem_base.val ≤ x.toNat ∧ x.toNat < s.mem_base.val + s.mem.val.length
        · rw [show absMem { s with mem := vfin } x
              = U8.bv (vfin.val[x.toNat - s.mem_base.val]!) from
            absMem_in { s with mem := vfin } x (by rw [hbase]; omega)
              (by rw [hbase, hlen']; omega),
            show absMem s x = U8.bv (s.mem.val[x.toNat - s.mem_base.val]!) from
            absMem_in s x hr.1 hr.2]
          rw [hkept _ ?_]
          rcases Nat.lt_or_ge (x.toNat) a.val with hx | hx
          · left; omega
          · right
            have : (x - (U64.bv a)).toNat = x.toNat - a.val := bv_sub_toNat (by omega)
            omega
        · have hout : ¬ InRange (U64.bv s.mem_base) s.mem.val.length x := by
            simp only [InRange]
            intro hc
            exact hr ⟨hc.1, hc.2⟩
          have hout' : ¬ InRange (U64.bv ({ s with mem := vfin } : x64_sim.Sim).mem_base)
              vfin.val.length x := by
            rw [hbase, hlen']
            exact hout
          simp only [absMem, if_neg hout, if_neg hout']
    calc absState { s with mem := vfin }
        = { absState s with mem := absMem { s with mem := vfin } } := rfl
      _ = _ := by rw [hmemeq]; rfl


/-! ## Labels

`find_label` scans the list backwards keeping the last match it saw, which is
the *first* position that matches — the position `Machine.pos` names. -/

theorem uscalar_eq_val_iff {ty : UScalarTy} {x y : UScalar ty} : (x = y) ↔ (x.val = y.val) :=
  UScalar.val_eq_imp_iff

theorem is_target_eq {t : x64_ir.PTarget} {i : x64_ir.PInsn} {b : Bool}
    (h : x64_sim.is_target t i = ok b) : b = isTarget t i := by
  unfold x64_sim.is_target at h
  cases t <;> cases i <;> simp_all [isTarget, uscalar_eq_val_iff]

/-- Whether position `k` of the list is the label `t` names. -/
def tgtAt (code : List x64_ir.PInsn) (t : x64_ir.PTarget) (k : Nat) : Bool :=
  match code[k]? with
  | some i => isTarget t i
  | none => false

theorem tgtAt_eq {code : List x64_ir.PInsn} {t : x64_ir.PTarget} {k : Nat} (hk : k < code.length) :
    tgtAt code t k = isTarget t (code[k]'hk) := by
  simp only [tgtAt, List.getElem?_eq_getElem hk]

theorem find_label_loop_ok {code : Slice x64_ir.PInsn} {t : x64_ir.PTarget} {i at1 res : Usize}
    (hi : i.val ≤ code.val.length)
    (hlow : ∀ k, code.val.length ≤ k + i.val → k < at1.val → tgtAt code.val t k = false)
    (hhigh : at1.val < code.val.length → tgtAt code.val t at1.val = true)
    (h : x64_sim.find_label_loop code t (Slice.len code) i at1 = ok res) :
    (∀ k, k < res.val → tgtAt code.val t k = false) ∧
      (res.val < code.val.length → tgtAt code.val t res.val = true) := by
  unfold x64_sim.find_label_loop at h
  refine loop_ok_induction _
    (fun st => st.1.val ≤ code.val.length ∧
      (∀ k, code.val.length ≤ k + st.1.val → k < st.2.val → tgtAt code.val t k = false) ∧
      (st.2.val < code.val.length → tgtAt code.val t st.2.val = true))
    (fun r => (∀ k, k < r.val → tgtAt code.val t k = false) ∧
      (r.val < code.val.length → tgtAt code.val t r.val = true))
    ?_ (i, at1) res ⟨hi, hlow, hhigh⟩ h
  rintro ⟨i', at'⟩ ⟨hi', hlow', hhigh'⟩ r hbody
  dsimp only at hi' hlow' hhigh'
  simp only [x64_sim.find_label_loop.body] at hbody
  split at hbody
  · rename_i hlti
    have hltv : i'.val < code.val.length := by
      rw [UScalar.lt_equiv] at hlti
      simp only [Slice.len_val, Slice.length] at hlti
      exact hlti
    obtain_bind ⟨i1, hi1, hbody⟩ := hbody
    obtain ⟨hi1v, -⟩ := usize_sub_eq_ok hi1
    simp only [Slice.len_val, Slice.length, show ((1#usize : Usize)).val = 1 from rfl] at hi1v
    obtain_bind ⟨j, hj, hbody⟩ := hbody
    obtain ⟨hjv, -⟩ := usize_sub_eq_ok hj
    obtain_bind ⟨p, hp, hbody⟩ := hbody
    obtain ⟨hplt, rfl⟩ := index_usize_eq_ok hp
    obtain_bind ⟨bt, hbt, hbody⟩ := hbody
    have hbtv : bt = tgtAt code.val t j.val := by
      rw [is_target_eq hbt, tgtAt_eq hplt]
    obtain_bind ⟨at2, hat2, hbody⟩ := hbody
    obtain_bind ⟨i2, hi2, hbody⟩ := hbody
    have hi2v : i2.val = i'.val + 1 := usize_add_eq_ok hi2
    simp only [ok.injEq] at hbody
    subst hbody
    have hjval : j.val + 1 + i'.val = code.val.length := by omega
    dsimp only
    split at hat2 <;> simp only [ok.injEq] at hat2 <;> subst hat2
    · rename_i hbtt
      refine ⟨by omega, ?_, ?_⟩
      · intro k hk1 hk2
        omega
      · intro _
        rw [← hbtv]
        simpa using hbtt
    · rename_i hbtf
      refine ⟨by omega, ?_, hhigh'⟩
      intro k hk1 hk2
      rcases Nat.lt_or_ge k j.val with hkj | hkj
      · omega
      · rcases Nat.eq_or_lt_of_le hkj with hkeq | hkj'
        · rw [← hkeq, ← hbtv]
          simpa using hbtf
        · exact hlow' k (by omega) hk2
  · rename_i hge
    have hgev : code.val.length ≤ i'.val := by
      simp only [not_lt] at hge
      rw [UScalar.le_equiv] at hge
      simp only [Slice.len_val, Slice.length] at hge
      exact hge
    simp only [ok.injEq] at hbody
    subst hbody
    exact ⟨fun k hk => hlow' k (by omega) hk, hhigh'⟩

theorem find_label_eq {code : Slice x64_ir.PInsn} {t : x64_ir.PTarget} {at1 : Usize}
    (h : x64_sim.find_label code t = ok at1) (hlt : at1.val < code.val.length) :
    pos code.val t = some at1.val := by
  unfold x64_sim.find_label at h
  obtain ⟨hlow, hhigh⟩ := find_label_loop_ok (i := 0#usize) (at1 := Slice.len code)
    (by simp)
    (by
      intro k hk1 hk2
      simp only [Slice.len_val, Slice.length, show ((0#usize : Usize)).val = 0 from rfl]
        at hk1 hk2
      omega)
    (by
      intro hc
      simp only [Slice.len_val, Slice.length] at hc
      omega) h
  rw [pos, List.findIdx?_eq_some_iff_getElem]
  refine ⟨hlt, ?_, ?_⟩
  · rw [← tgtAt_eq hlt]
    exact hhigh hlt
  · intro j hj
    have hj' := hlow j hj
    rw [tgtAt_eq (by omega)] at hj'
    simp [hj']

/-! ## Shifts -/

theorem isar_uscalar_eq {ty tys : _} {x z : IScalar ty} {t : UScalar tys}
    (h : x >>> t = ok z) : z.bv = x.bv.sshiftRight t.val := by
  simp only [HShiftRight.hShiftRight, IScalar.shiftRight_UScalar] at h
  unfold IScalar.shiftRight at h
  split at h
  · simp only [ok.injEq] at h
    subst h
    rfl
  · simp at h

theorem lo32_shiftLeft (v : Word) (k : Nat) : lo32 (v <<< k) = (lo32 v) <<< k := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  simp only [lo32, BitVec.truncate_eq_setWidth, BitVec.getLsbD_setWidth, BitVec.getLsbD_shiftLeft,
    hi, decide_true, Bool.true_and]
  by_cases hik : i < k
  · simp [hik]
  · simp only [hik, decide_false, Bool.not_false, Bool.true_and]
    have hik' : i - k < 32 := by omega
    simp [hik']
    all_goals omega

theorem zx32_shiftRight (x : BitVec 32) (k : Nat) : (zx32 x) >>> k = zx32 (x >>> k) := by
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_ushiftRight, zx32_toNat, zx32_toNat, BitVec.toNat_ushiftRight]

theorem lo32_sshiftRight (x : BitVec 32) (k : Nat) (hk : k < 32) :
    lo32 (BitVec.sshiftRight (BitVec.signExtend 64 x) k) = x.sshiftRight k := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  simp only [lo32, BitVec.truncate_eq_setWidth, BitVec.getLsbD_setWidth, hi, decide_true,
    Bool.true_and, BitVec.getLsbD_sshiftRight]
  by_cases hki : k + i < 32
  · simp only [show ¬ (64 ≤ i) by omega, decide_false, Bool.not_false, Bool.true_and,
      show k + i < 64 by omega, BitVec.getLsbD_signExtend, hki]
    simp [hki]
    all_goals omega
  · simp only [show ¬ (64 ≤ i) by omega, decide_false, Bool.not_false, Bool.true_and,
      show k + i < 64 by omega, if_neg hki, BitVec.getLsbD_signExtend]
    simp [BitVec.msb_eq_getLsbD_last]
    all_goals omega

theorem shift_amount_eq {w64 : Bool} {n : Std.U8} {amt : Std.U32}
    (h : x64_sim.shift_amount w64 n = ok amt) : amt.val = shiftAmount w64 (U8.bv n) := by
  unfold x64_sim.shift_amount at h
  obtain_bind ⟨bits, hbits, h⟩ := h
  obtain_bind ⟨i, hi, h⟩ := h
  simp only [lift, ok.injEq] at hi
  subst hi
  obtain_bind ⟨i1, hi1, h⟩ := h
  simp only [ok.injEq] at h
  subst h
  have hbv := width_bits_eq hbits
  have hi1v : i1.val = widthBits w64 - 1 := by
    have hsub := UScalar.sub_equiv bits 1#u32
    rw [hi1] at hsub
    obtain ⟨-, hv, -⟩ := hsub
    rw [show ((1#u32 : Std.U32)).val = 1 from rfl] at hv
    omega
  have hcast : (UScalar.cast .U32 n).val = n.val :=
    cast_val_of_lt _ (by
      have := n.hBounds
      simp only [UScalarTy.U8_numBits_eq, UScalarTy.U32_numBits_eq] at *
      omega)
  cases w64 with
  | true =>
    rw [and_mask_val (k := 6) (by rw [hi1v]; rfl), hcast]
    rfl
  | false =>
    rw [and_mask_val (k := 5) (by rw [hi1v]; rfl), hcast]
    rfl

theorem shift_result_eq {w64 : Bool} {op : x64_ir.ShiftOp} {v r : Std.U64} {amt : Std.U32}
    (hamt : amt.val < widthBits w64) (h : x64_sim.shift_result w64 op v amt = ok r) :
    U64.bv r = shiftResult w64 op (U64.bv v) amt.val := by
  unfold x64_sim.shift_result at h
  cases op with
  | Shl =>
    unfold x64_sim.shl_at at h
    obtain_bind ⟨bits, hbits, h⟩ := h
    have hbv := width_bits_eq hbits
    rw [if_neg (by
      simp only [ge_iff_le, UScalar.le_equiv, not_le]
      omega)] at h
    obtain_bind ⟨i, hi, h⟩ := h
    obtain_bind ⟨m, hm, h⟩ := h
    simp only [ok.injEq] at h
    subst h
    rw [and_width_mask hm, u64_shl_u32 hi]
    cases w64 with
    | true => rfl
    | false =>
      simp only [shiftResult, Bool.false_eq_true, if_false, wr_false_eq]
      rw [lo32_shiftLeft]
  | Shr =>
    unfold x64_sim.shr_at at h
    obtain_bind ⟨bits, hbits, h⟩ := h
    have hbv := width_bits_eq hbits
    obtain_bind ⟨m, hm, h⟩ := h
    obtain_bind ⟨x, hx, h⟩ := h
    simp only [lift, ok.injEq] at hx
    subst hx
    rw [if_neg (by
      simp only [ge_iff_le, UScalar.le_equiv, not_le]
      omega)] at h
    rw [u64_shr_u32 h, and_width_mask hm]
    cases w64 with
    | true => rfl
    | false =>
      simp only [shiftResult, Bool.false_eq_true, if_false, wr_false_eq]
      rw [zx32_shiftRight]
  | Sar =>
    unfold x64_sim.sar_at at h
    obtain_bind ⟨bits, hbits, h⟩ := h
    have hbv := width_bits_eq hbits
    obtain_bind ⟨sxv, hsxv, h⟩ := h
    obtain_bind ⟨x, hx, h⟩ := h
    simp only [lift, ok.injEq] at hx
    subst hx
    obtain_bind ⟨amt2, hamt2, h⟩ := h
    have hamt2v : amt2.val = amt.val := by
      split at hamt2 <;> simp only [ok.injEq] at hamt2 <;> subst hamt2
      · rename_i hge
        have h63 : ((63#u32 : Std.U32)).val = 63 := rfl
        simp only [ge_iff_le, UScalar.le_equiv] at hge
        cases w64 with
        | true => simp only [widthBits_true] at hamt; omega
        | false => simp only [widthBits_false] at hamt; omega
      · rfl
    obtain_bind ⟨i1, hi1, h⟩ := h
    obtain_bind ⟨i2, hi2, h⟩ := h
    simp only [lift, ok.injEq] at hi2
    subst hi2
    obtain_bind ⟨m, hm, h⟩ := h
    simp only [ok.injEq] at h
    subst h
    have hi1bv : i1.bv = (UScalar.hcast .I64 sxv).bv.sshiftRight amt2.val := isar_uscalar_eq hi1
    have hcast : U64.bv (IScalar.hcast .U64 i1) = i1.bv := by
      show i1.bv.signExtend 64 = i1.bv
      simp
    have hsx : (UScalar.hcast .I64 sxv).bv = U64.bv sxv := rfl
    rw [and_width_mask hm, hcast, hi1bv, hsx, hamt2v]
    cases w64 with
    | true =>
      have hsxe : U64.bv sxv = U64.bv v := by
        unfold x64_sim.sign_extend at hsxv
        rw [if_neg (by rw [uscalar_eq_val_iff]; rw [hbv]; simp), if_pos (by
          simp only [ge_iff_le, UScalar.le_equiv]
          rw [hbv]
          rfl)] at hsxv
        simp only [ok.injEq] at hsxv
        rw [hsxv]
      rw [hsxe]
      rfl
    | false =>
      have hsxe : U64.bv sxv = BitVec.signExtend 64 (lo32 (U64.bv v)) := by
        rw [sign_extend_eq (by rw [hbv]; simp) (by rw [hbv]; simp) hsxv, hbv]
        rfl
      rw [hsxe]
      simp only [shiftResult, Bool.false_eq_true, if_false, wr_false_eq]
      rw [lo32_sshiftRight _ _ (by simpa using hamt)]


/-! ## `bswap` -/

theorem uscalar_add_eq_ok {ty : UScalarTy} {x y z : UScalar ty} (h : x + y = ok z) :
    z.val = x.val + y.val := by
  have := UScalar.add_equiv x y
  rw [h] at this
  exact this.2.1

theorem uscalar_sub_eq_ok {ty : UScalarTy} {x y z : UScalar ty} (h : x - y = ok z) :
    z.val = x.val - y.val ∧ y.val ≤ x.val := by
  have := UScalar.sub_equiv x y
  rw [h] at this
  obtain ⟨h1, h2, -⟩ := this
  omega

theorem uscalar_mul_eq_ok {ty : UScalarTy} {x y z : UScalar ty} (h : x * y = ok z) :
    z.val = x.val * y.val := by
  have := UScalar.mul_equiv x y
  have h' : UScalar.mul x y = ok z := h
  rw [h'] at this
  exact this.2.1

theorem bswap_bytes_loop_eq {bytes : Std.U32} {w acc : Std.U64} {i : Std.U32} {res : Std.U64}
    (hb : bytes.val ≤ 8) (hi : i.val ≤ bytes.val)
    (hacc : U64.bv acc = (List.range i.val).foldl
      (fun a k => a ||| ((((U64.bv w) >>> (8 * k)) &&& 0xff#64) <<< (8 * (bytes.val - 1 - k))))
      0#64)
    (h : x64_sim.bswap_bytes_loop bytes w acc i = ok res) :
    U64.bv res = bswapBytes bytes.val (U64.bv w) := by
  unfold x64_sim.bswap_bytes_loop at h
  refine loop_ok_induction _
    (fun st => st.2.val ≤ bytes.val ∧ U64.bv st.1 = (List.range st.2.val).foldl
      (fun a k => a ||| ((((U64.bv w) >>> (8 * k)) &&& 0xff#64) <<< (8 * (bytes.val - 1 - k))))
      0#64)
    (fun r => U64.bv r = bswapBytes bytes.val (U64.bv w))
    ?_ (acc, i) res ⟨hi, hacc⟩ h
  rintro ⟨acc', i'⟩ ⟨hi', hacc'⟩ r hbody
  dsimp only at hi' hacc'
  simp only [x64_sim.bswap_bytes_loop.body] at hbody
  split at hbody
  · rename_i hlt
    have hltv : i'.val < bytes.val := by rw [UScalar.lt_equiv] at hlt; exact hlt
    split at hbody
    · obtain_bind ⟨i1, hi1, hbody⟩ := hbody
      have hi1v : i1.val = 8 * i'.val := by
        rw [uscalar_mul_eq_ok hi1]
        rfl
      obtain_bind ⟨i2, hi2, hbody⟩ := hbody
      obtain_bind ⟨byte, hbyte, hbody⟩ := hbody
      simp only [lift, ok.injEq] at hbyte
      subst hbyte
      obtain_bind ⟨i3, hi3, hbody⟩ := hbody
      obtain ⟨hi3v, -⟩ := uscalar_sub_eq_ok hi3
      rw [show ((1#u32 : Std.U32)).val = 1 from rfl] at hi3v
      obtain_bind ⟨i4, hi4, hbody⟩ := hbody
      obtain ⟨hi4v, -⟩ := uscalar_sub_eq_ok hi4
      obtain_bind ⟨i5, hi5, hbody⟩ := hbody
      have hi5v : i5.val = 8 * i4.val := by
        rw [uscalar_mul_eq_ok hi5]
        rfl
      obtain_bind ⟨i6, hi6, hbody⟩ := hbody
      obtain_bind ⟨acc1, hacc1, hbody⟩ := hbody
      simp only [lift, ok.injEq] at hacc1
      subst hacc1
      obtain_bind ⟨i7, hi7, hbody⟩ := hbody
      have hi7v : i7.val = i'.val + 1 := by
        rw [uscalar_add_eq_ok hi7]
        rfl
      simp only [ok.injEq] at hbody
      subst hbody
      dsimp only
      refine ⟨by omega, ?_⟩
      rw [hi7v, List.range_succ, List.foldl_append]
      simp only [List.foldl_cons, List.foldl_nil, ← hacc']
      show (U64.bv acc') ||| (U64.bv i6) = _
      rw [u64_shl_u32 hi6, hi5v, hi4v, hi3v, u64_bv_and, u64_shr_u32 hi2, hi1v]
      rfl
    · rename_i hge
      simp only [ok.injEq] at hbody
      subst hbody
      dsimp only
      have : bytes.val ≤ 8 := hb
      have h8 : ¬ (i'.val < 8) := by
        intro hc
        exact hge (by rw [UScalar.lt_equiv]; exact hc)
      have : i'.val = bytes.val := by omega
      rw [hacc', this]
      rfl
  · rename_i hge
    simp only [ok.injEq] at hbody
    subst hbody
    dsimp only
    have hgev : bytes.val ≤ i'.val := by
      simp only [not_lt] at hge
      rw [UScalar.le_equiv] at hge
      exact hge
    have : i'.val = bytes.val := by omega
    rw [hacc', this]
    rfl

theorem bswap_bytes_eq {bytes : Std.U32} {w res : Std.U64} (hb : bytes.val ≤ 8)
    (h : x64_sim.bswap_bytes bytes w = ok res) :
    U64.bv res = bswapBytes bytes.val (U64.bv w) := by
  unfold x64_sim.bswap_bytes at h
  exact bswap_bytes_loop_eq hb (by simp) (by simp) h


theorem wr_shiftResult (w64 : Bool) (op : x64_ir.ShiftOp) (v : Word) (amt : Nat) :
    wr w64 (shiftResult w64 op v amt) = shiftResult w64 op v amt := by
  cases w64 with
  | true => rfl
  | false =>
    simp only [shiftResult, Bool.false_eq_true, if_false, wr_false_eq, zx32_lo32]

theorem signExtend_to_eight (x : BitVec 32) : BitVec.signExtend 8 x = x.setWidth 8 := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  rw [BitVec.getLsbD_signExtend, BitVec.getLsbD_setWidth]
  simp [hi, show i < 32 by omega]

theorem and_setWidth_eight (x : Word) : ((x &&& 255#64).setWidth 8) = x.setWidth 8 := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  rw [BitVec.getLsbD_setWidth, BitVec.getLsbD_setWidth, BitVec.getLsbD_and]
  have h255 : (255#64 : BitVec 64).getLsbD i = true := by
    rw [← BitVec.testBit_toNat]
    have : (255#64 : BitVec 64).toNat = 2 ^ 8 - 1 := by norm_num
    rw [this, Nat.testBit_two_pow_sub_one]
    simp
    omega
  simp [h255, hi]


/-! ## State shapes -/

theorem absState_bump {s1 : x64_sim.Sim} {i : Usize} (hi : i.val = s1.pc.val + 1) :
    absState { s1 with pc := i } = { absState s1 with pc := (absState s1).pc + 1 } := by
  have h1 : (absState s1).pc + 1 = i.val := by
    show s1.pc.val + 1 = i.val
    omega
  rw [h1]
  rfl

theorem absState_cf_pc (s1 : x64_sim.Sim) (b : Bool) (i : Usize) (hi : i.val = s1.pc.val + 1) :
    absState { s1 with cf := b, pc := i }
      = { absState s1 with flags := ⟨b, s1.zf, s1.sf, s1.of⟩, pc := (absState s1).pc + 1 } := by
  rw [show (absState s1).pc + 1 = i.val from hi.symm]
  rfl

theorem absState_flags_set {s1 : x64_sim.Sim} {f : x64_sim.Flags} :
    absState { s1 with cf := f.cf, zf := f.zf, sf := f.sf, of := f.of }
      = { absState s1 with flags := absFlags f } := rfl

theorem load_mem_bv {s : x64_sim.Sim} {a : Std.U64} {n : Usize} {v : Std.U64}
    (hn : n.val ≤ 8) (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.load_mem s a n = ok (true, v)) :
    load n.val (absMem s) (U64.bv a) = (U64.bv v).setWidth (8 * n.val)
      ∧ v.val < 2 ^ (8 * n.val) := by
  obtain ⟨hv, -, -⟩ := load_mem_eq hn hmem h
  have hlt : v.val < 2 ^ (8 * n.val) := by
    have h1 := loadNat_lt n.val (absMem s) (U64.bv a)
    have h2 : (256 : Nat) ^ n.val = 2 ^ (8 * n.val) := by
      rw [show (256 : Nat) = 2 ^ 8 from rfl, ← pow_mul]
    omega
  refine ⟨?_, hlt⟩
  apply BitVec.eq_of_toNat_eq
  rw [load, BitVec.toNat_ofNat, BitVec.toNat_setWidth, ← hv]
  rfl

theorem addr_eq {s : x64_sim.Sim} {base : Std.U8} {disp : Std.I32} {a : Std.U64}
    (hb : RegOk base) (h : x64_sim.addr s base disp = ok a) :
    U64.bv a = addr (absState s) base disp := by
  unfold x64_sim.addr at h
  obtain_bind ⟨i, hi, h⟩ := h
  obtain_bind ⟨i1, hi1, h⟩ := h
  rw [add64_eq h, reg_eq hb hi, sx32_eq hi1]
  rfl


/-! ## Register names -/

theorem regOk_RAX : RegOk x64_sim.RAX := by simp [RegOk, x64_sim.RAX]
theorem regOk_RCX : RegOk x64_sim.RCX := by simp [RegOk, x64_sim.RCX]
theorem regOk_RDX : RegOk x64_sim.RDX := by simp [RegOk, x64_sim.RDX]
theorem regOk_RSP : RegOk x64_sim.RSP := by simp [RegOk, x64_sim.RSP]

theorem sim_rax_val : (x64_sim.RAX).val = RAX := by simp [x64_sim.RAX]
theorem sim_rcx_val : (x64_sim.RCX).val = RCX := by simp [x64_sim.RCX]
theorem sim_rdx_val : (x64_sim.RDX).val = RDX := by simp [x64_sim.RDX]
theorem sim_rsp_val : (x64_sim.RSP).val = RSP := by simp [x64_sim.RSP]

theorem push_eq {s s2 : x64_sim.Sim} {v : Std.U64}
    (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.push s v = ok (.Next, s2)) :
    absState s2 = push (absState s) (U64.bv v) ∧ s2.pc = s.pc ∧
      s2.mem_base = s.mem_base ∧ s2.code_base = s.code_base ∧
      s2.mem.val.length = s.mem.val.length := by
  unfold x64_sim.push at h
  obtain_bind ⟨i, hi, h⟩ := h
  obtain_bind ⟨top, htop, h⟩ := h
  obtain_bind ⟨p, hp, h⟩ := h
  obtain ⟨ok1, s1⟩ := p
  cases ok1 with
  | false => simp at h
  | true =>
    obtain ⟨hs1, hlen, habs⟩ := store_mem_eq (n := 8#usize) (by simp) hmem hp
    obtain_bind ⟨s3, hs3, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have htopbv : U64.bv top = (absState s).regs RSP - 8#64 := by
      rw [sub64_eq htop, reg_eq regOk_RSP hi, sim_rsp_val]
      rfl
    have hs1pc : s1.pc = s.pc := by rw [hs1]
    have hs1base : s1.mem_base = s.mem_base := by rw [hs1]
    have hs1cb : s1.code_base = s.code_base := by rw [hs1]
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · rw [set_reg_abs regOk_RSP hs3, habs, sim_rsp_val, htopbv]
      simp only [push, storeVal, store64]
      have h8 : (8#usize : Usize).val = 8 := rfl
      rw [h8]
      simp
    · obtain ⟨h1, -, -, -⟩ := set_reg_frame hs3
      rw [h1, hs1pc]
    · obtain ⟨-, h2, -, -⟩ := set_reg_frame hs3
      rw [h2, hs1base]
    · obtain ⟨-, -, h3, -⟩ := set_reg_frame hs3
      rw [h3, hs1cb]
    · obtain ⟨-, -, -, h4⟩ := set_reg_frame hs3
      rw [h4, hlen]



/-! ## The refinement

`step_refines_frame` proves the refinement and the frame condition at once:
the same case analysis gives both, and `run_refines` needs the frame to know
that `simParams` and the no-wrap hypothesis survive a step. -/

/-- What a step leaves alone: where the code sits, where the mapped range
starts, and how long it is. -/
structure Frame (s s' : x64_sim.Sim) : Prop where
  base : s'.mem_base = s.mem_base
  code : s'.code_base = s.code_base
  len : s'.mem.val.length = s.mem.val.length

theorem Frame.refl' (s : x64_sim.Sim) : Frame s s := ⟨rfl, rfl, rfl⟩

theorem Frame.trans' {s1 s2 s3 : x64_sim.Sim} (h1 : Frame s1 s2) (h2 : Frame s2 s3) :
    Frame s1 s3 :=
  ⟨by rw [h2.base, h1.base], by rw [h2.code, h1.code], by rw [h2.len, h1.len]⟩

theorem frame_pc {s s' : x64_sim.Sim} {i : Usize} (h : Frame s s') :
    Frame s { s' with pc := i } := ⟨h.base, h.code, h.len⟩

theorem frame_cf_pc {s s' : x64_sim.Sim} {b : Bool} {i : Usize} (h : Frame s s') :
    Frame s { s' with cf := b, pc := i } := ⟨h.base, h.code, h.len⟩

theorem frame_set_reg {s s' : x64_sim.Sim} {r : Std.U8} {v : Std.U64}
    (h : x64_sim.set_reg s r v = ok s') : Frame s s' := by
  obtain ⟨-, h1, h2, h3⟩ := set_reg_frame h
  exact ⟨h1, h2, by rw [h3]⟩

theorem frame_set_flags {s s' : x64_sim.Sim} {f : x64_sim.Flags}
    (h : x64_sim.set_flags s f = ok s') : Frame s s' := by
  obtain ⟨-, h1, h2, h3⟩ := set_flags_frame h
  exact ⟨h1, h2, by rw [h3]⟩

theorem frame_store_mem {s s' : x64_sim.Sim} {a : Std.U64} {n : Usize} {v : Std.U64}
    (hn : n.val ≤ 8) (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.store_mem s a n v = ok (true, s')) : Frame s s' := by
  obtain ⟨hs, hlen, -⟩ := store_mem_eq hn hmem h
  exact ⟨by rw [hs], by rw [hs], hlen⟩

theorem frame_push {s s' : x64_sim.Sim} {v : Std.U64}
    (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.push s v = ok (.Next, s')) : Frame s s' := by
  obtain ⟨-, -, h1, h2, h3⟩ := push_eq hmem h
  exact ⟨h1, h2, h3⟩


/-- A store to a range a load has just read succeeds: both ask `in_bounds`. -/
theorem in_bounds_of_load {s : x64_sim.Sim} {a : Std.U64} {n : Usize} {v : Std.U64}
    (h : x64_sim.load_mem s a n = ok (true, v)) : x64_sim.in_bounds s a n = ok true := by
  unfold x64_sim.load_mem at h
  obtain_bind ⟨ok1, hok1, h⟩ := h
  cases ok1 with
  | true => exact hok1
  | false =>
    obtain_bind ⟨p, hp, h⟩ := h
    simp only [Bool.false_eq_true, if_false, ok.injEq] at hp
    subst hp
    have := load_mem_loop_false h
    simp at this

theorem store_mem_loop_true {vec : alloc.vec.Vec Std.U8} {n : Usize} {v : Std.U64}
    {off len i : Usize} {res : (alloc.vec.Vec Std.U8) × Bool}
    (h : x64_sim.store_mem_loop vec n v true off len i = ok res) : res.2 = true := by
  unfold x64_sim.store_mem_loop at h
  refine loop_ok_induction _ (fun st => st.2.1 = true) (fun r => r.2 = true) ?_
    (vec, true, i) res rfl h
  rintro ⟨vec', b', i'⟩ hb' r hbody
  dsimp only at hb'
  subst hb'
  simp only [x64_sim.store_mem_loop.body] at hbody
  rw [if_pos trivial] at hbody
  split at hbody
  · obtain_bind ⟨idx, hidx, hbody⟩ := hbody
    obtain_bind ⟨v2, hv2, hbody⟩ := hbody
    obtain_bind ⟨i1, hi1, hbody⟩ := hbody
    simp only [ok.injEq] at hbody
    subst hbody
    rfl
  · simp only [ok.injEq] at hbody
    subst hbody
    rfl

theorem store_mem_true {s s1 : x64_sim.Sim} {a : Std.U64} {n : Usize} {v : Std.U64} {b : Bool}
    (hb : x64_sim.in_bounds s a n = ok true)
    (h : x64_sim.store_mem s a n v = ok (b, s1)) : b = true := by
  unfold x64_sim.store_mem at h
  obtain_bind ⟨ok1, hok1, h⟩ := h
  rw [hb] at hok1
  simp only [ok.injEq] at hok1
  subst hok1
  obtain_bind ⟨p, hp, h⟩ := h
  obtain ⟨s2, off⟩ := p
  obtain_bind ⟨q, hq, h⟩ := h
  obtain ⟨vfin, okfin⟩ := q
  replace h : ok (okfin, ({ s2 with mem := vfin } : x64_sim.Sim)) = ok (b, s1) := h
  simp only [ok.injEq, Prod.mk.injEq] at h
  rw [← h.1]
  exact store_mem_loop_true hq


theorem size_bytes_le {size : Std.U8} {n : Usize} (h : x64_sim.size_bytes size = ok n) :
    n.val ≤ 8 := by
  unfold x64_sim.size_bytes at h
  repeat' split at h
  all_goals (simp only [ok.injEq] at h; subst h; simp)

theorem store_mem_eq' {s s' : x64_sim.Sim} {a : Std.U64} {n : Usize} {v : Std.U64} {k : Nat}
    (hk : n.val = k) (hn : k ≤ 8)
    (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.store_mem s a n v = ok (true, s')) :
    absState s' = { absState s with
      mem := store k (absState s).mem (U64.bv a) (storeVal k (U64.bv v)) } := by
  subst hk
  exact (store_mem_eq hn hmem h).2.2

theorem load_mem_bv' {s : x64_sim.Sim} {a : Std.U64} {n : Usize} {v : Std.U64} {k : Nat}
    (hk : n.val = k) (hn : k ≤ 8)
    (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.load_mem s a n = ok (true, v)) :
    load k (absMem s) (U64.bv a) = (U64.bv v).setWidth (8 * k) ∧ v.val < 2 ^ (8 * k) := by
  subst hk
  exact load_mem_bv hn hmem h

theorem bv_sub_eq_zero_iff {w : Nat} (x y : BitVec w) : (x - y = 0#w) ↔ (x = y) := by
  constructor
  · intro h
    have h2 := congrArg (fun z => z + y) h
    simpa using h2
  · intro h
    subst h
    simp

theorem flags_zf_eta (f : Flags) (b : Bool) (h : f.zf = b) :
    ({ f with zf := b } : Flags) = f := by
  subst h
  rfl

theorem wr_of_lt {w64 : Bool} {v : Word} (h : v.toNat < 2 ^ widthBits w64) : wr w64 v = v := by
  apply BitVec.eq_of_toNat_eq
  rw [wr_toNat]
  exact Nat.mod_eq_of_lt h

theorem wr_sub_eq_zero_iff {w64 : Bool} {x y : Word} (hx : wr w64 x = x) (hy : wr w64 y = y) :
    (wr w64 (x - y) = 0#64) ↔ (x = y) := by
  cases w64 with
  | true =>
    simp only [wr_true_eq]
    exact bv_sub_eq_zero_iff x y
  | false =>
    rw [wr_false_eq, show lo32 (x - y) = lo32 x - lo32 y from setWidth_sub_3264 x y, zx32_eq_zero,
      bv_sub_eq_zero_iff]
    constructor
    · intro hc
      rw [← hx, ← hy, wr_false_eq, wr_false_eq, hc]
    · intro hc
      rw [hc]

theorem zeroExtend_load_eq {s : x64_sim.Sim} {a : Std.U64} {n : Usize} {v : Std.U64} {k : Nat}
    (hk : n.val = k) (hkle : k ≤ 8)
    (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.load_mem s a n = ok (true, v)) :
    BitVec.zeroExtend 64 (load k (absMem s) (U64.bv a)) = U64.bv v := by
  obtain ⟨hload, hlt⟩ := load_mem_bv' hk hkle hmem h
  rw [hload]
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_setWidth, BitVec.toNat_setWidth]
  have h1 : (U64.bv v).toNat % 2 ^ (8 * k) = (U64.bv v).toNat := Nat.mod_eq_of_lt hlt
  rw [h1]
  exact Nat.mod_eq_of_lt (by have := v.hBounds; simpa using this)


theorem memVal_eq {s : x64_sim.Sim} {a : Std.U64} {n : Usize} {v : Std.U64} {w64 : Bool}
    (hn : n.val = opWidth w64)
    (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.load_mem s a n = ok (true, v)) :
    memVal w64 (absMem s) (U64.bv a) = U64.bv v := by
  obtain ⟨hload, hlt⟩ := load_mem_bv' hn (by cases w64 <;> simp [opWidth]) hmem h
  simp only [memVal, hload]
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_setWidth, BitVec.toNat_setWidth]
  have : v.val % 2 ^ (8 * opWidth w64) = v.val := Nat.mod_eq_of_lt hlt
  show (U64.bv v).toNat % 2 ^ (8 * opWidth w64) % 2 ^ 64 = (U64.bv v).toNat
  rw [show (U64.bv v).toNat = v.val from rfl, this]
  exact Nat.mod_eq_of_lt (by have := v.hBounds; simpa using this)

theorem load64_eq {s : x64_sim.Sim} {a : Std.U64} {n : Usize} {v : Std.U64}
    (hn : n.val = 8) (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.load_mem s a n = ok (true, v)) :
    load64 (absMem s) (U64.bv a) = U64.bv v := by
  obtain ⟨hload, -⟩ := load_mem_bv' hn (by norm_num) hmem h
  have h2 : load64 (absMem s) (U64.bv a) = (U64.bv v).setWidth 64 := hload
  rw [h2]
  simp

theorem lock_op_eq {op : Std.U8} {a b r : Std.U64} (h : x64_sim.lock_op op a b = ok r) :
    U64.bv r = lockOp op (U64.bv a) (U64.bv b) := by
  unfold x64_sim.lock_op at h
  unfold lockOp
  split at h
  · rename_i h1
    rw [if_pos (show op.val = 0x01 by rw [h1]; rfl)]
    exact add64_eq h
  · rename_i h1
    rw [if_neg (show ¬ (op.val = 0x01) from fun hc => h1 (UScalar.eq_of_val_eq hc))]
    split at h
    · rename_i h2
      rw [if_pos (show op.val = 0x09 by rw [h2]; rfl)]
      simp only [ok.injEq] at h
      rw [← h, u64_bv_or]
    · rename_i h2
      rw [if_neg (show ¬ (op.val = 0x09) from fun hc => h2 (UScalar.eq_of_val_eq hc))]
      split at h
      · rename_i h3
        rw [if_pos (show op.val = 0x21 by rw [h3]; rfl)]
        simp only [ok.injEq] at h
        rw [← h, u64_bv_and]
      · rename_i h3
        rw [if_neg (show ¬ (op.val = 0x21) from fun hc => h3 (UScalar.eq_of_val_eq hc))]
        split at h
        · rename_i h4
          rw [if_pos (show op.val = 0x31 by rw [h4]; rfl)]
          simp only [ok.injEq] at h
          rw [← h, u64_bv_xor]
        · rename_i h4
          rw [if_neg (show ¬ (op.val = 0x31) from fun hc => h4 (UScalar.eq_of_val_eq hc))]
          simp only [ok.injEq] at h
          rw [← h]


theorem usize_lt_two_pow_64 (x : Usize) : x.val < 2 ^ 64 := by
  have h1 := x.hBounds
  have h2 : (2 : Nat) ^ (UScalarTy.Usize).numBits ≤ 2 ^ 64 := by
    apply Nat.pow_le_pow_right (by norm_num)
    simp only [UScalarTy.Usize_numBits_eq]
    cases System.Platform.numBits_eq with
    | inl h32 => omega
    | inr h64 => omega
  omega

theorem branch_eq {code : Slice x64_ir.PInsn} {s s' : x64_sim.Sim} {t : x64_ir.PTarget}
    (h : x64_sim.branch code s t = ok (.Next, s')) :
    ∃ i : Nat, pos code.val t = some i ∧ absState s' = { absState s with pc := i } ∧ Frame s s' := by
  unfold x64_sim.branch at h
  dsimp only at h
  obtain_bind ⟨at1, hat, h⟩ := h
  split at h
  · rename_i hlt
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have hltv : at1.val < code.val.length := by
      rw [UScalar.lt_equiv] at hlt
      simp only [Slice.len_val, Slice.length] at hlt
      exact hlt
    exact ⟨at1.val, find_label_eq hat hltv, rfl, ⟨rfl, rfl, rfl⟩⟩
  · simp at h


set_option maxHeartbeats 2000000 in
theorem step_refines_frame {code : Slice x64_ir.PInsn} {s s' : x64_sim.Sim}
    (hcode : CodeOk code.val)
    (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.step code s = ok (.Next, s')) :
    Step (simParams s) code.val (absState s) (.next (absState s')) ∧ Frame s s' := by
  unfold x64_sim.step at h
  dsimp only at h
  split at h
  swap
  · simp at h
  obtain_bind ⟨insn, hinsn, h⟩ := h
  obtain ⟨hpclt, hinsnv⟩ := index_usize_eq_ok hinsn
  have hfetch : code.val[s.pc.val]? = some insn := by
    rw [hinsnv, List.getElem?_eq_getElem hpclt]
  have hok : InsnOk insn := hcode insn (by rw [hinsnv]; exact List.getElem_mem _)
  clear hinsn hinsnv
  unfold x64_sim.step_at at h
  cases insn with
  | PcLabel p =>
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    rw [absState_bump (s1 := s) (i := i) (usize_add_eq_ok hi)]
    exact ⟨Step.pcLabel _ p hfetch, ⟨rfl, rfl, rfl⟩⟩
  | Local n =>
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    rw [absState_bump (s1 := s) (i := i) (usize_add_eq_ok hi)]
    exact ⟨Step.localLabel _ n hfetch, ⟨rfl, rfl, rfl⟩⟩
  | ExitLabel =>
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    rw [absState_bump (s1 := s) (i := i) (usize_add_eq_ok hi)]
    exact ⟨Step.exitLabel _ hfetch, ⟨rfl, rfl, rfl⟩⟩
  | RetpolineLabel =>
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    rw [absState_bump (s1 := s) (i := i) (usize_add_eq_ok hi)]
    exact ⟨Step.retpolineLabel _ hfetch, ⟨rfl, rfl, rfl⟩⟩
  | Pause =>
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    rw [absState_bump (s1 := s) (i := i) (usize_add_eq_ok hi)]
    exact ⟨Step.pause _ hfetch, ⟨rfl, rfl, rfl⟩⟩
  | Push r =>
    have hr : RegOk r := hok
    obtain_bind ⟨v, hv, h⟩ := h
    obtain_bind ⟨p, hp, h⟩ := h
    obtain ⟨o, s1⟩ := p
    cases o with
    | Next =>
      obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      obtain ⟨habs, hpc, hbase, hcb, hlen⟩ := push_eq hmem hp
      refine ⟨?_, ⟨hbase, hcb, hlen⟩⟩
      rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), habs, reg_eq hr hv]
      exact Step.push _ r hfetch
    | Halt => simp at h
    | Fault => simp at h
    | Unsupported => simp at h
  | Pop r =>
    have hr : RegOk r := hok
    unfold x64_sim.pop at h
    obtain_bind ⟨top, htop, h⟩ := h
    obtain_bind ⟨pr, hpr, h⟩ := h
    obtain ⟨ok1, v⟩ := pr
    cases ok1 with
    | false => simp at h
    | true =>
      obtain_bind ⟨i, hi, h⟩ := h
      obtain_bind ⟨s1, hs1, h⟩ := h
      obtain_bind ⟨s2, hs2, h⟩ := h
      obtain_bind ⟨i1, hi1, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      obtain ⟨hload, -⟩ := load_mem_bv (by simp) hmem hpr
      have hv : load64 (absMem s) (U64.bv top) = U64.bv v := by
        have h2 : load64 (absMem s) (U64.bv top) = (U64.bv v).setWidth 64 := hload
        rw [h2]
        simp
      refine ⟨?_, frame_pc ((frame_set_reg hs1).trans' (frame_set_reg hs2))⟩
      rw [absState_bump (s1 := s2) (i := i1) (usize_add_eq_ok hi1), set_reg_abs hr hs2,
        set_reg_abs regOk_RSP hs1, add64_eq hi, ← hv, reg_eq regOk_RSP htop, sim_rsp_val,
        show U64.bv (8#u64 : Std.U64) = (8#64 : BitVec 64) from rfl]
      exact Step.pop _ r hfetch
  | Alu w64 op src dst =>
    obtain ⟨hsrc, hdst⟩ : RegOk src ∧ RegOk dst := hok
    unfold x64_sim.alu_rr at h
    obtain_bind ⟨a, ha, h⟩ := h
    obtain_bind ⟨b, hb, h⟩ := h
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have hbump := absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi)
    cases op with
    | Add =>
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      obtain_bind ⟨j1, hj1, hs1⟩ := hs1
      obtain_bind ⟨s2, hs2, hs1⟩ := hs1
      refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
      rw [hbump, set_flags_abs hs1, set_reg_abs hdst hs2, wr_eq hj1, add64_eq hj,
        flags_of_add_sub_eq hf, reg_eq hdst ha, reg_eq hsrc hb]
      exact Step.alu _ w64 .Add src dst hfetch
    | Sub =>
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      obtain_bind ⟨j1, hj1, hs1⟩ := hs1
      obtain_bind ⟨s2, hs2, hs1⟩ := hs1
      refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
      rw [hbump, set_flags_abs hs1, set_reg_abs hdst hs2, wr_eq hj1, sub64_eq hj,
        flags_of_add_sub_eq hf, reg_eq hdst ha, reg_eq hsrc hb]
      exact Step.alu _ w64 .Sub src dst hfetch
    | Or =>
      obtain_bind ⟨rr, hrr, hs1⟩ := hs1
      simp only [lift, ok.injEq] at hrr
      subst hrr
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      obtain_bind ⟨s2, hs2, hs1⟩ := hs1
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
      rw [hbump, set_flags_abs hs1, set_reg_abs hdst hs2, wr_eq hj, flags_of_logic_eq hf,
        u64_bv_or, reg_eq hdst ha, reg_eq hsrc hb]
      exact Step.alu _ w64 .Or src dst hfetch
    | And =>
      obtain_bind ⟨rr, hrr, hs1⟩ := hs1
      simp only [lift, ok.injEq] at hrr
      subst hrr
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      obtain_bind ⟨s2, hs2, hs1⟩ := hs1
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
      rw [hbump, set_flags_abs hs1, set_reg_abs hdst hs2, wr_eq hj, flags_of_logic_eq hf,
        u64_bv_and, reg_eq hdst ha, reg_eq hsrc hb]
      exact Step.alu _ w64 .And src dst hfetch
    | Xor =>
      obtain_bind ⟨rr, hrr, hs1⟩ := hs1
      simp only [lift, ok.injEq] at hrr
      subst hrr
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      obtain_bind ⟨s2, hs2, hs1⟩ := hs1
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
      rw [hbump, set_flags_abs hs1, set_reg_abs hdst hs2, wr_eq hj, flags_of_logic_eq hf,
        u64_bv_xor, reg_eq hdst ha, reg_eq hsrc hb]
      exact Step.alu _ w64 .Xor src dst hfetch
    | Mov =>
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
      rw [hbump, set_reg_abs hdst hs1, wr_eq hj, reg_eq hsrc hb]
      exact Step.alu _ w64 .Mov src dst hfetch
    | Cmp =>
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      refine ⟨?_, frame_pc (frame_set_flags hs1)⟩
      rw [hbump, set_flags_abs hs1, flags_of_add_sub_eq hf, reg_eq hdst ha, reg_eq hsrc hb]
      exact Step.alu _ w64 .Cmp src dst hfetch
    | Test =>
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      simp only [lift, ok.injEq] at hj
      subst hj
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      refine ⟨?_, frame_pc (frame_set_flags hs1)⟩
      rw [hbump, set_flags_abs hs1, flags_of_logic_eq hf, u64_bv_and, reg_eq hdst ha,
        reg_eq hsrc hb]
      exact Step.alu _ w64 .Test src dst hfetch
  | AluImm w64 op dst imm =>
    have hdst : RegOk dst := hok
    unfold x64_sim.alu_imm at h
    obtain_bind ⟨a, ha, h⟩ := h
    obtain_bind ⟨b, hb, h⟩ := h
    have hbv : U64.bv b
        = (if w64 then BitVec.signExtend 64 imm.bv else BitVec.zeroExtend 64 imm.bv) := by
      split at hb
      · rename_i hw
        subst hw
        rw [if_pos rfl]
        exact sx32_eq hb
      · rename_i hw
        simp only [Bool.not_eq_true] at hw
        subst hw
        rw [if_neg (by simp)]
        obtain_bind ⟨i0, hi0, hb⟩ := hb
        simp only [lift, ok.injEq] at hi0
        subst hi0
        simp only [ok.injEq] at hb
        subst hb
        show BitVec.setWidth 64 (BitVec.signExtend 32 imm.bv) = BitVec.zeroExtend 64 imm.bv
        simp
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have hbump := absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi)
    cases op with
    | Add =>
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      obtain_bind ⟨j1, hj1, hs1⟩ := hs1
      obtain_bind ⟨s2, hs2, hs1⟩ := hs1
      refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
      rw [hbump, set_flags_abs hs1, set_reg_abs hdst hs2, wr_eq hj1, add64_eq hj,
        flags_of_add_sub_eq hf, reg_eq hdst ha, hbv]
      exact Step.aluImm _ w64 .Add dst imm hfetch
    | Or =>
      obtain_bind ⟨rr, hrr, hs1⟩ := hs1
      simp only [lift, ok.injEq] at hrr
      subst hrr
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      obtain_bind ⟨s2, hs2, hs1⟩ := hs1
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
      rw [hbump, set_flags_abs hs1, set_reg_abs hdst hs2, wr_eq hj, flags_of_logic_eq hf,
        u64_bv_or, reg_eq hdst ha, hbv]
      exact Step.aluImm _ w64 .Or dst imm hfetch
    | And =>
      obtain_bind ⟨rr, hrr, hs1⟩ := hs1
      simp only [lift, ok.injEq] at hrr
      subst hrr
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      obtain_bind ⟨s2, hs2, hs1⟩ := hs1
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
      rw [hbump, set_flags_abs hs1, set_reg_abs hdst hs2, wr_eq hj, flags_of_logic_eq hf,
        u64_bv_and, reg_eq hdst ha, hbv]
      exact Step.aluImm _ w64 .And dst imm hfetch
    | Sub =>
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      obtain_bind ⟨j1, hj1, hs1⟩ := hs1
      obtain_bind ⟨s2, hs2, hs1⟩ := hs1
      refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
      rw [hbump, set_flags_abs hs1, set_reg_abs hdst hs2, wr_eq hj1, sub64_eq hj,
        flags_of_add_sub_eq hf, reg_eq hdst ha, hbv]
      exact Step.aluImm _ w64 .Sub dst imm hfetch
    | Xor =>
      obtain_bind ⟨rr, hrr, hs1⟩ := hs1
      simp only [lift, ok.injEq] at hrr
      subst hrr
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      obtain_bind ⟨s2, hs2, hs1⟩ := hs1
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
      rw [hbump, set_flags_abs hs1, set_reg_abs hdst hs2, wr_eq hj, flags_of_logic_eq hf,
        u64_bv_xor, reg_eq hdst ha, hbv]
      exact Step.aluImm _ w64 .Xor dst imm hfetch
    | Cmp =>
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      refine ⟨?_, frame_pc (frame_set_flags hs1)⟩
      rw [hbump, set_flags_abs hs1, flags_of_add_sub_eq hf, reg_eq hdst ha, hbv]
      exact Step.aluImm _ w64 .Cmp dst imm hfetch
    | Mov =>
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
      rw [hbump, set_reg_abs hdst hs1, wr_eq hj, hbv]
      exact Step.aluImm _ w64 .Mov dst imm hfetch
    | Test =>
      obtain_bind ⟨j, hj, hs1⟩ := hs1
      simp only [lift, ok.injEq] at hj
      subst hj
      obtain_bind ⟨f, hf, hs1⟩ := hs1
      refine ⟨?_, frame_pc (frame_set_flags hs1)⟩
      rw [hbump, set_flags_abs hs1, flags_of_logic_eq hf, u64_bv_and, reg_eq hdst ha, hbv]
      exact Step.aluImm _ w64 .Test dst imm hfetch
  | ShiftImm w64 op dst imm =>
    have hdst : RegOk dst := hok
    obtain_bind ⟨cnt, hcnt, h⟩ := h
    simp only [lift, ok.injEq] at hcnt
    subst hcnt
    unfold x64_sim.shift at h
    obtain_bind ⟨amt, hamt, h⟩ := h
    obtain_bind ⟨src, hsrc, h⟩ := h
    obtain_bind ⟨res, hres, h⟩ := h
    obtain_bind ⟨j, hj, h⟩ := h
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨s2, hs2, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have hc8 : U8.bv (IScalar.hcast .U8 imm) = imm.bv.truncate 8 := by
      show BitVec.signExtend 8 imm.bv = imm.bv.truncate 8
      exact signExtend_to_eight imm.bv
    have hamtv : amt.val = shiftAmount w64 (imm.bv.truncate 8) := by
      rw [shift_amount_eq hamt, hc8]
    have hamtlt : amt.val < widthBits w64 := by
      rw [hamtv]
      cases w64 with
      | true => exact Nat.mod_lt _ (by norm_num)
      | false => exact Nat.mod_lt _ (by norm_num)
    have hvalue : U64.bv j
        = shiftResult w64 op ((absState s).regs dst.val) (shiftAmount w64 (imm.bv.truncate 8)) := by
      rw [wr_eq hj, shift_result_eq hamtlt hres, wr_shiftResult, reg_eq hdst hsrc, hamtv]
    split at hs2
    · obtain_bind ⟨f, hf, hs2⟩ := hs2
      refine ⟨?_, frame_pc ((frame_set_reg hs1).trans' (frame_set_flags hs2))⟩
      rw [absState_bump (s1 := s2) (i := i) (usize_add_eq_ok hi), set_flags_abs hs2,
        set_reg_abs hdst hs1, hvalue]
      exact Step.shiftImm _ w64 op dst imm (absFlags f) hfetch
    · simp only [ok.injEq] at hs2
      subst hs2
      refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
      rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_reg_abs hdst hs1, hvalue]
      exact Step.shiftImm _ w64 op dst imm (absState s).flags hfetch
  | ShiftCl w64 op dst =>
    have hdst : RegOk dst := hok
    obtain_bind ⟨rcx, hrcx, h⟩ := h
    obtain_bind ⟨masked, hmasked, h⟩ := h
    simp only [lift, ok.injEq] at hmasked
    subst hmasked
    obtain_bind ⟨cnt, hcnt, h⟩ := h
    simp only [lift, ok.injEq] at hcnt
    subst hcnt
    unfold x64_sim.shift at h
    obtain_bind ⟨amt, hamt, h⟩ := h
    obtain_bind ⟨src, hsrc, h⟩ := h
    obtain_bind ⟨res, hres, h⟩ := h
    obtain_bind ⟨j, hj, h⟩ := h
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨s2, hs2, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have hamtv := shift_amount_eq hamt
    have hamtlt : amt.val < widthBits w64 := by
      rw [hamtv]
      cases w64 with
      | true => exact Nat.mod_lt _ (by norm_num)
      | false => exact Nat.mod_lt _ (by norm_num)
    have hcount : U8.bv (UScalar.cast .U8 (rcx &&& 255#u64)) = ((absState s).regs RCX).truncate 8 := by
      show ((U64.bv (rcx &&& 255#u64)).setWidth 8) = _
      rw [u64_bv_and, show U64.bv (255#u64 : Std.U64) = (255#64 : BitVec 64) from rfl,
        and_setWidth_eight, reg_eq regOk_RCX hrcx, sim_rcx_val]
    have hvalue : U64.bv j
        = shiftResult w64 op ((absState s).regs dst.val)
            (shiftAmount w64 (((absState s).regs RCX).truncate 8)) := by
      rw [wr_eq hj, shift_result_eq hamtlt hres, wr_shiftResult, reg_eq hdst hsrc, hamtv, hcount]
    split at hs2
    · obtain_bind ⟨f, hf, hs2⟩ := hs2
      refine ⟨?_, frame_pc ((frame_set_reg hs1).trans' (frame_set_flags hs2))⟩
      rw [absState_bump (s1 := s2) (i := i) (usize_add_eq_ok hi), set_flags_abs hs2,
        set_reg_abs hdst hs1, hvalue]
      exact Step.shiftCl _ w64 op dst (absFlags f) hfetch
    · simp only [ok.injEq] at hs2
      subst hs2
      refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
      rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_reg_abs hdst hs1, hvalue]
      exact Step.shiftCl _ w64 op dst (absState s).flags hfetch
  | Neg w64 dst =>
    have hdst : RegOk dst := hok
    unfold x64_sim.neg at h
    obtain_bind ⟨v, hv, h⟩ := h
    obtain_bind ⟨f, hf, h⟩ := h
    obtain_bind ⟨j, hj, h⟩ := h
    obtain_bind ⟨j1, hj1, h⟩ := h
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨s2, hs2, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    refine ⟨?_, frame_pc ((frame_set_reg hs1).trans' (frame_set_flags hs2))⟩
    rw [absState_bump (s1 := s2) (i := i) (usize_add_eq_ok hi), set_flags_abs hs2,
      set_reg_abs hdst hs1, wr_eq hj1, sub64_eq hj,
      show U64.bv (0#u64 : Std.U64) = (0#64 : BitVec 64) from rfl, BitVec.zero_sub,
      reg_eq hdst hv]
    exact Step.neg _ w64 dst (absFlags f) hfetch
  | MulDivRcx w64 kind signed =>
    have hmul : ∀ (kd : x64_ir.MulDivKind), x64_sim.mul_rcx s w64 = ok (.Next, s') →
        Step (simParams s) code.val (absState s) (.next (absState s')) ∧ Frame s s' := by
      intro kd hm
      unfold x64_sim.mul_rcx at hm
      obtain_bind ⟨a, ha, hm⟩ := hm
      obtain_bind ⟨c, hc, hm⟩ := hm
      obtain_bind ⟨t, ht, hm⟩ := hm
      obtain ⟨lo, hi⟩ := t
      obtain_bind ⟨s1, hs1, hm⟩ := hm
      obtain_bind ⟨s2, hs2, hm⟩ := hm
      obtain_bind ⟨b, hb, hm⟩ := hm
      obtain_bind ⟨s3, hs3, hm⟩ := hm
      obtain_bind ⟨i, hi2, hm⟩ := hm
      simp only [ok.injEq, Prod.mk.injEq] at hm
      obtain ⟨-, rfl⟩ := hm
      refine ⟨?_, frame_pc (((frame_set_reg hs1).trans' (frame_set_reg hs2)).trans'
        (frame_set_flags hs3))⟩
      rw [absState_bump (s1 := s3) (i := i) (usize_add_eq_ok hi2), set_flags_abs hs3,
        set_reg_abs regOk_RDX hs2, set_reg_abs regOk_RAX hs1, sim_rax_val, sim_rdx_val]
      exact Step.mulDivRcx _ w64 kind signed (U64.bv lo) (U64.bv hi) _ hfetch
    have hdiv : x64_sim.div_rcx s w64 signed = ok (.Next, s') →
        Step (simParams s) code.val (absState s) (.next (absState s')) ∧ Frame s s' := by
      intro hd
      unfold x64_sim.div_rcx at hd
      obtain_bind ⟨a, ha, hd⟩ := hd
      obtain_bind ⟨d, hdd, hd⟩ := hd
      obtain_bind ⟨c, hc, hd⟩ := hd
      obtain_bind ⟨t, ht, hd⟩ := hd
      obtain ⟨quo, rem, ok1⟩ := t
      cases ok1 with
      | false => simp at hd
      | true =>
        obtain_bind ⟨s1, hs1, hd⟩ := hd
        obtain_bind ⟨s2, hs2, hd⟩ := hd
        obtain_bind ⟨i, hi2, hd⟩ := hd
        simp only [ok.injEq, Prod.mk.injEq] at hd
        obtain ⟨-, rfl⟩ := hd
        refine ⟨?_, frame_pc ((frame_set_reg hs1).trans' (frame_set_reg hs2))⟩
        rw [absState_bump (s1 := s2) (i := i) (usize_add_eq_ok hi2),
          set_reg_abs regOk_RDX hs2, set_reg_abs regOk_RAX hs1, sim_rax_val, sim_rdx_val]
        exact Step.mulDivRcx _ w64 kind signed (U64.bv quo) (U64.bv rem)
          (absState s).flags hfetch
    cases kind with
    | Mul => exact hmul .Mul h
    | Div => exact hdiv h
    | Mod => exact hdiv h
  | MovSx bits w64 src dst =>
    obtain ⟨hsrc, hdst⟩ : RegOk src ∧ RegOk dst := hok
    unfold x64_sim.movsx at h
    obtain_bind ⟨v, hv, h⟩ := h
    obtain_bind ⟨x, hx, h⟩ := h
    obtain_bind ⟨j, hj, h⟩ := h
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have hxv : U64.bv x = (if bits.val = 8 then BitVec.signExtend 64 ((U64.bv v).truncate 8)
        else if bits.val = 16 then BitVec.signExtend 64 ((U64.bv v).truncate 16)
        else if bits.val = 32 then BitVec.signExtend 64 ((U64.bv v).truncate 32)
        else U64.bv v) := by
      split at hx
      · rename_i h8
        rw [if_pos (show bits.val = 8 by rw [h8]; rfl)]
        exact sign_extend_eq (by simp) (by simp) hx
      · rename_i h8
        rw [if_neg (show ¬ (bits.val = 8) from fun hc => h8 (UScalar.eq_of_val_eq hc))]
        split at hx
        · rename_i h16
          rw [if_pos (show bits.val = 16 by rw [h16]; rfl)]
          exact sign_extend_eq (by simp) (by simp) hx
        · rename_i h16
          rw [if_neg (show ¬ (bits.val = 16) from fun hc => h16 (UScalar.eq_of_val_eq hc))]
          split at hx
          · rename_i h32
            rw [if_pos (show bits.val = 32 by rw [h32]; rfl)]
            exact sign_extend_eq (by simp) (by simp) hx
          · rename_i h32
            rw [if_neg (show ¬ (bits.val = 32) from fun hc => h32 (UScalar.eq_of_val_eq hc))]
            simp only [ok.injEq] at hx
            rw [hx]
    refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
    rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_reg_abs hdst hs1,
      wr_eq hj, hxv, reg_eq hsrc hv]
    exact Step.movsx _ bits w64 src dst hfetch
  | Bswap w64 dst =>
    have hdst : RegOk dst := hok
    unfold x64_sim.bswap at h
    obtain_bind ⟨v, hv, h⟩ := h
    obtain_bind ⟨r, hr, h⟩ := h
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have hrv : U64.bv r = bswap w64 (U64.bv v) := by
      split at hr
      · rename_i hw
        subst hw
        rw [bswap_bytes_eq (by simp) hr]
        rfl
      · rename_i hw
        simp only [Bool.not_eq_true] at hw
        subst hw
        rw [bswap_bytes_eq (by simp) hr]
        rfl
    refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
    rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_reg_abs hdst hs1, hrv,
      reg_eq hdst hv]
    exact Step.bswap _ w64 dst hfetch
  | Rol16 dst =>
    have hdst : RegOk dst := hok
    unfold x64_sim.rol16 at h
    obtain_bind ⟨v, hv, h⟩ := h
    obtain_bind ⟨lo, hlo, h⟩ := h
    simp only [lift, ok.injEq] at hlo
    subst hlo
    obtain_bind ⟨j, hj, h⟩ := h
    obtain_bind ⟨j1, hj1, h⟩ := h
    obtain_bind ⟨j2, hj2, h⟩ := h
    simp only [lift, ok.injEq] at hj2
    subst hj2
    obtain_bind ⟨rot, hrot, h⟩ := h
    simp only [lift, ok.injEq] at hrot
    subst hrot
    obtain_bind ⟨j3, hj3, h⟩ := h
    simp only [lift, ok.injEq] at hj3
    subst hj3
    obtain_bind ⟨j4, hj4, h⟩ := h
    simp only [lift, ok.injEq] at hj4
    subst hj4
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨j5, hj5, h⟩ := h
    simp only [lift, ok.injEq] at hj5
    subst hj5
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have hrolv : U64.bv (v &&& 18446744073709486080#u64 ||| (j ||| j1) &&& 65535#u64)
        = rol16 ((absState s).regs dst.val) := by
      simp only [u64_bv_or, u64_bv_and, u64_shl_i32 hj, u64_shr_i32 hj1, reg_eq hdst hv,
        show I32.toNat (8#i32) = 8 from rfl,
        show U64.bv (65535#u64 : Std.U64) = (0xffff#64 : BitVec 64) from rfl,
        show U64.bv (18446744073709486080#u64 : Std.U64) = (0xffffffffffff0000#64 : BitVec 64)
          from rfl]
      rfl
    refine ⟨?_, frame_cf_pc (frame_set_reg hs1)⟩
    rw [absState_cf_pc s1 _ i (usize_add_eq_ok hi), set_reg_abs hdst hs1, hrolv]
    exact Step.rol16 _ dst ⟨decide (((j ||| j1) &&& 65535#u64) &&& 1#u64 = 1#u64),
      s1.zf, s1.sf, s1.of⟩ hfetch
  | Cmov cc dst src =>
    obtain ⟨hdst, hsrc⟩ : RegOk dst ∧ RegOk src := hok
    obtain_bind ⟨f, hf, h⟩ := h
    simp only [x64_sim.get_flags, ok.injEq] at hf
    subst hf
    obtain_bind ⟨taken, htaken, h⟩ := h
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have htv : taken = cond cc (absState s).flags := cond_eq htaken
    split at hs1
    · rename_i ht
      obtain_bind ⟨v, hv, hs1⟩ := hs1
      refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
      rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_reg_abs hdst hs1,
        reg_eq hsrc hv]
      exact Step.cmovTaken _ cc dst src hfetch (by rw [← htv]; exact ht)
    · rename_i ht
      simp only [ok.injEq] at hs1
      subst hs1
      refine ⟨?_, frame_pc (Frame.refl' s)⟩
      rw [absState_bump (s1 := s) (i := i) (usize_add_eq_ok hi)]
      exact Step.cmovNotTaken _ cc dst src hfetch
        (by rw [← htv]; simpa using ht)
  | LoadImm dst imm =>
    have hdst : RegOk dst := hok
    obtain_bind ⟨j, hj, h⟩ := h
    simp only [lift, ok.injEq] at hj
    subst hj
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
    rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_reg_abs hdst hs1,
      show U64.bv (IScalar.hcast .U64 imm) = imm.bv from by
        show imm.bv.signExtend 64 = imm.bv
        simp]
    exact Step.loadImm _ dst imm hfetch
  | Pushfq =>
    obtain_bind ⟨f, hf, h⟩ := h
    simp only [x64_sim.get_flags, ok.injEq] at hf
    subst hf
    obtain_bind ⟨v, hv, h⟩ := h
    obtain_bind ⟨p, hp, h⟩ := h
    obtain ⟨o, s1⟩ := p
    cases o with
    | Next =>
      obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      obtain ⟨habs, hpc, hbase, hcb, hlen⟩ := push_eq hmem hp
      refine ⟨?_, ⟨hbase, hcb, hlen⟩⟩
      rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), habs, flags_word_eq hv]
      exact Step.pushfq _ hfetch
    | Halt => simp at h
    | Fault => simp at h
    | Unsupported => simp at h
  | Popfq =>
    obtain_bind ⟨top, htop, h⟩ := h
    obtain_bind ⟨pr, hpr, h⟩ := h
    obtain ⟨ok1, v⟩ := pr
    cases ok1 with
    | false => simp at h
    | true =>
      obtain_bind ⟨i, hi, h⟩ := h
      obtain_bind ⟨s1, hs1, h⟩ := h
      obtain_bind ⟨f, hf, h⟩ := h
      obtain_bind ⟨s2, hs2, h⟩ := h
      obtain_bind ⟨i1, hi1, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      obtain ⟨hload, -⟩ := load_mem_bv (by simp) hmem hpr
      have hv : load64 (absMem s) (U64.bv top) = U64.bv v := by
        have h2 : load64 (absMem s) (U64.bv top) = (U64.bv v).setWidth 64 := hload
        rw [h2]
        simp
      refine ⟨?_, frame_pc ((frame_set_reg hs1).trans' (frame_set_flags hs2))⟩
      rw [absState_bump (s1 := s2) (i := i1) (usize_add_eq_ok hi1), set_flags_abs hs2,
        set_reg_abs regOk_RSP hs1, flags_of_word_eq hf, add64_eq hi, ← hv,
        reg_eq regOk_RSP htop, sim_rsp_val,
        show U64.bv (8#u64 : Std.U64) = (8#64 : BitVec 64) from rfl]
      exact Step.popfq _ hfetch
  | Cqo =>
    obtain_bind ⟨a, ha, h⟩ := h
    obtain_bind ⟨b, hb, h⟩ := h
    obtain_bind ⟨v, hvv, h⟩ := h
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have hbv : b = ((absState s).regs RAX).msb := by
      rw [msb_eq hb, if_pos rfl, reg_eq regOk_RAX ha, sim_rax_val]
    have hvbv : U64.bv v = if ((absState s).regs RAX).msb then BitVec.allOnes 64 else 0#64 := by
      rw [← hbv]
      split at hvv
      · rename_i hbt
        rw [if_pos hbt]
        simp only [ok.injEq] at hvv
        rw [← hvv]
        rfl
      · rename_i hbf
        rw [if_neg (by simpa using hbf)]
        simp only [ok.injEq] at hvv
        rw [← hvv]
        rfl
    refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
    rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_reg_abs regOk_RDX hs1,
      sim_rdx_val, hvbv]
    exact Step.cqo _ hfetch
  | Cdq =>
    obtain_bind ⟨a, ha, h⟩ := h
    obtain_bind ⟨b, hb, h⟩ := h
    obtain_bind ⟨v, hvv, h⟩ := h
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    have hbv : b = (lo32 ((absState s).regs RAX)).msb := by
      rw [msb_eq hb, if_neg (by simp), reg_eq regOk_RAX ha, sim_rax_val]
    have hvbv : U64.bv v
        = if (lo32 ((absState s).regs RAX)).msb then 0xffffffff#64 else 0#64 := by
      rw [← hbv]
      split at hvv
      · rename_i hbt
        rw [if_pos hbt]
        simp only [ok.injEq] at hvv
        rw [← hvv]
        simp [x64_sim.MASK32]
      · rename_i hbf
        rw [if_neg (by simpa using hbf)]
        simp only [ok.injEq] at hvv
        rw [← hvv]
        rfl
    refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
    rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_reg_abs regOk_RDX hs1,
      sim_rdx_val, hvbv]
    exact Step.cdq _ hfetch
  | CmpRcxMinusOne w64 =>
    obtain_bind ⟨c, hc, h⟩ := h
    obtain_bind ⟨f, hf, h⟩ := h
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    refine ⟨?_, frame_pc (frame_set_flags hs1)⟩
    rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_flags_abs hs1,
      flags_of_add_sub_eq hf, reg_eq regOk_RCX hc, sim_rcx_val,
      show U64.bv (18446744073709551615#u64 : Std.U64) = BitVec.allOnes 64 from rfl]
    exact Step.cmpRcxMinusOne _ w64 hfetch
  | CmpEaxImm imm =>
    obtain_bind ⟨a, ha, h⟩ := h
    obtain_bind ⟨j, hj, h⟩ := h
    simp only [lift, ok.injEq] at hj
    subst hj
    obtain_bind ⟨f, hf, h⟩ := h
    obtain_bind ⟨s1, hs1, h⟩ := h
    obtain_bind ⟨i, hi, h⟩ := h
    simp only [ok.injEq, Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    refine ⟨?_, frame_pc (frame_set_flags hs1)⟩
    rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_flags_abs hs1,
      flags_of_add_sub_eq hf, reg_eq regOk_RAX ha, sim_rax_val,
      show U64.bv (UScalar.cast .U64 imm) = zx32 imm.bv from rfl]
    exact Step.cmpEaxImm _ imm hfetch
  | Load size sx base dst disp =>
    obtain ⟨hbase, hdst⟩ : RegOk base ∧ RegOk dst := hok
    unfold x64_sim.load at h
    obtain_bind ⟨n, hn, h⟩ := h
    have hnle : n.val ≤ 8 := size_bytes_le hn
    split at h
    · -- sign-extending
      rename_i hsx
      subst hsx
      split at h
      · -- the eight-byte form does nothing
        rename_i h8
        obtain_bind ⟨i, hi, h⟩ := h
        simp only [ok.injEq, Prod.mk.injEq] at h
        obtain ⟨-, rfl⟩ := h
        have hsize : size.val = 8 := by
          rw [← size_bytes_eq hn (by rw [h8]; simp), h8]
          rfl
        refine ⟨?_, frame_pc (Frame.refl' s)⟩
        rw [absState_bump (s1 := s) (i := i) (usize_add_eq_ok hi)]
        exact Step.loadNop _ size true base dst disp hfetch rfl hsize
      · rename_i h8
        split at h
        · simp at h
        · rename_i hn0
          have hnv : n.val = size.val := size_bytes_eq hn (fun hc => hn0 (UScalar.eq_of_val_eq hc))
          have hn8 : n.val ≠ 8 := fun hc => h8 (UScalar.eq_of_val_eq hc)
          have hn0' : n.val ≠ 0 := fun hc => hn0 (UScalar.eq_of_val_eq hc)
          obtain_bind ⟨a, ha, h⟩ := h
          obtain_bind ⟨pr, hpr, h⟩ := h
          obtain ⟨ok1, v⟩ := pr
          cases ok1 with
          | false => simp at h
          | true =>
            obtain_bind ⟨j, hj, h⟩ := h
            simp only [lift, ok.injEq] at hj
            subst hj
            obtain_bind ⟨j1, hj1, h⟩ := h
            obtain_bind ⟨x, hx, h⟩ := h
            obtain_bind ⟨s1, hs1, h⟩ := h
            obtain_bind ⟨i, hi, h⟩ := h
            simp only [ok.injEq, Prod.mk.injEq] at h
            obtain ⟨-, rfl⟩ := h
            have hcast : (UScalar.cast .U32 n).val = n.val :=
              cast_val_of_lt _ (by simp only [UScalarTy.U32_numBits_eq]; omega)
            have hj1v : j1.val = 8 * size.val := by
              rw [uscalar_mul_eq_ok hj1, hcast, hnv]
              rfl
            obtain ⟨hload, -⟩ := load_mem_bv' hnv (by omega) hmem hpr
            have hxv : U64.bv x
                = BitVec.signExtend 64 (load size.val (absMem s) (U64.bv a)) := by
              rw [hload, sign_extend_eq (by rw [hj1v]; omega) (by rw [hj1v]; omega) hx, hj1v]
            refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
            rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_reg_abs hdst hs1,
              hxv, addr_eq hbase ha]
            exact Step.load _ size true base dst disp hfetch (by
              intro hc
              exact hn8 (by rw [hnv, hc.2]))
    · -- zero-extending
      rename_i hsx
      simp only [Bool.not_eq_true] at hsx
      subst hsx
      split at h
      · simp at h
      · rename_i hn0
        have hnv : n.val = size.val := size_bytes_eq hn (fun hc => hn0 (UScalar.eq_of_val_eq hc))
        obtain_bind ⟨a, ha, h⟩ := h
        obtain_bind ⟨pr, hpr, h⟩ := h
        obtain ⟨ok1, v⟩ := pr
        cases ok1 with
        | false => simp at h
        | true =>
          obtain_bind ⟨s1, hs1, h⟩ := h
          obtain_bind ⟨i, hi, h⟩ := h
          simp only [ok.injEq, Prod.mk.injEq] at h
          obtain ⟨-, rfl⟩ := h
          have hzx : BitVec.zeroExtend 64 (load size.val (absMem s) (U64.bv a)) = U64.bv v :=
            zeroExtend_load_eq hnv (by omega) hmem hpr
          refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
          rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi), set_reg_abs hdst hs1,
            ← hzx, addr_eq hbase ha]
          exact Step.load _ size false base dst disp hfetch (by simp)
  | Store size src base disp =>
    obtain ⟨hsrc, hbase⟩ : RegOk src ∧ RegOk base := hok
    unfold x64_sim.store at h
    obtain_bind ⟨n, hn, h⟩ := h
    split at h
    · simp at h
    · rename_i hn0
      obtain_bind ⟨a, ha, h⟩ := h
      obtain_bind ⟨v, hv, h⟩ := h
      obtain_bind ⟨p, hp, h⟩ := h
      obtain ⟨ok1, s1⟩ := p
      cases ok1 with
      | false => simp at h
      | true =>
        obtain_bind ⟨i, hi, h⟩ := h
        simp only [ok.injEq, Prod.mk.injEq] at h
        obtain ⟨-, rfl⟩ := h
        have hnv : n.val = size.val := size_bytes_eq hn (fun hc => hn0 (UScalar.eq_of_val_eq hc))
        refine ⟨?_, frame_pc (frame_store_mem (size_bytes_le hn) hmem hp)⟩
        rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi),
          store_mem_eq' hnv (by rw [← hnv]; exact size_bytes_le hn) hmem hp,
          addr_eq hbase ha, reg_eq hsrc hv]
        exact Step.store _ size src base disp hfetch
  | StoreImm size base disp imm =>
    have hbase : RegOk base := hok
    unfold x64_sim.store_imm at h
    obtain_bind ⟨n, hn, h⟩ := h
    split at h
    · simp at h
    · rename_i hn0
      obtain_bind ⟨a, ha, h⟩ := h
      obtain_bind ⟨v, hv, h⟩ := h
      obtain_bind ⟨p, hp, h⟩ := h
      obtain ⟨ok1, s1⟩ := p
      cases ok1 with
      | false => simp at h
      | true =>
        obtain_bind ⟨i, hi, h⟩ := h
        simp only [ok.injEq, Prod.mk.injEq] at h
        obtain ⟨-, rfl⟩ := h
        have hnv : n.val = size.val := size_bytes_eq hn (fun hc => hn0 (UScalar.eq_of_val_eq hc))
        refine ⟨?_, frame_pc (frame_store_mem (size_bytes_le hn) hmem hp)⟩
        rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi),
          store_mem_eq' hnv (by rw [← hnv]; exact size_bytes_le hn) hmem hp,
          addr_eq hbase ha, sx32_eq hv]
        exact Step.storeImm _ size base disp imm hfetch
  | AluRM op r base disp =>
    obtain ⟨hr, hbase⟩ : RegOk r ∧ RegOk base := hok
    unfold x64_sim.alu_rm at h
    obtain_bind ⟨a, ha, h⟩ := h
    obtain_bind ⟨pr, hpr, h⟩ := h
    obtain ⟨ok1, v⟩ := pr
    cases ok1 with
    | false => simp at h
    | true =>
      obtain_bind ⟨x, hx, h⟩ := h
      obtain_bind ⟨s1, hs1, h⟩ := h
      obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      have hload : load64 (absMem s) (U64.bv a) = U64.bv v := load64_eq rfl hmem hpr
      have hbump := absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi)
      cases op with
      | Sub =>
        obtain_bind ⟨f, hf, hs1⟩ := hs1
        obtain_bind ⟨j, hj, hs1⟩ := hs1
        obtain_bind ⟨s2, hs2, hs1⟩ := hs1
        refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
        rw [hbump, set_flags_abs hs1, set_reg_abs hr hs2, sub64_eq hj, flags_of_add_sub_eq hf,
          ← hload, reg_eq hr hx, addr_eq hbase ha]
        exact Step.aluRM _ .Sub r base disp hfetch
      | Add =>
        obtain_bind ⟨f, hf, hs1⟩ := hs1
        obtain_bind ⟨j, hj, hs1⟩ := hs1
        obtain_bind ⟨s2, hs2, hs1⟩ := hs1
        refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
        rw [hbump, set_flags_abs hs1, set_reg_abs hr hs2, add64_eq hj, flags_of_add_sub_eq hf,
          ← hload, reg_eq hr hx, addr_eq hbase ha]
        exact Step.aluRM _ .Add r base disp hfetch
      | CmpMR =>
        obtain_bind ⟨f, hf, hs1⟩ := hs1
        refine ⟨?_, frame_pc (frame_set_flags hs1)⟩
        rw [hbump, set_flags_abs hs1, flags_of_add_sub_eq hf, ← hload, reg_eq hr hx,
          addr_eq hbase ha]
        exact Step.aluRM _ .CmpMR r base disp hfetch
      | CmpRM =>
        obtain_bind ⟨f, hf, hs1⟩ := hs1
        refine ⟨?_, frame_pc (frame_set_flags hs1)⟩
        rw [hbump, set_flags_abs hs1, flags_of_add_sub_eq hf, ← hload, reg_eq hr hx,
          addr_eq hbase ha]
        exact Step.aluRM _ .CmpRM r base disp hfetch
      | Or =>
        obtain_bind ⟨y, hy, hs1⟩ := hs1
        simp only [lift, ok.injEq] at hy
        subst hy
        obtain_bind ⟨s2, hs2, hs1⟩ := hs1
        obtain_bind ⟨f, hf, hs1⟩ := hs1
        refine ⟨?_, frame_pc ((frame_set_reg hs2).trans' (frame_set_flags hs1))⟩
        rw [hbump, set_flags_abs hs1, set_reg_abs hr hs2, flags_of_logic_eq hf, u64_bv_or,
          ← hload, reg_eq hr hx, addr_eq hbase ha]
        exact Step.aluRM _ .Or r base disp hfetch
  | StoreRspImm imm =>
    obtain_bind ⟨top, htop, h⟩ := h
    obtain_bind ⟨j, hj, h⟩ := h
    simp only [lift, ok.injEq] at hj
    subst hj
    obtain_bind ⟨v, hv, h⟩ := h
    obtain_bind ⟨p, hp, h⟩ := h
    obtain ⟨ok1, s1⟩ := p
    cases ok1 with
    | false => simp at h
    | true =>
      obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      have hvv : U64.bv v = BitVec.signExtend 64 imm.bv := by
        rw [sign_extend_eq (by simp) (by simp) hv]
        congr 1
        show (BitVec.setWidth 64 imm.bv).setWidth 32 = imm.bv
        simp
      refine ⟨?_, frame_pc (frame_store_mem (by simp) hmem hp)⟩
      rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi),
        store_mem_eq' (k := 8) rfl (by norm_num) hmem hp,
        reg_eq regOk_RSP htop, sim_rsp_val, hvv]
      exact Step.storeRspImm _ imm hfetch
  | StoreRspRax =>
    obtain_bind ⟨top, htop, h⟩ := h
    obtain_bind ⟨v, hv, h⟩ := h
    obtain_bind ⟨p, hp, h⟩ := h
    obtain ⟨ok1, s1⟩ := p
    cases ok1 with
    | false => simp at h
    | true =>
      obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      refine ⟨?_, frame_pc (frame_store_mem (by simp) hmem hp)⟩
      rw [absState_bump (s1 := s1) (i := i) (usize_add_eq_ok hi),
        store_mem_eq' (k := 8) rfl (by norm_num) hmem hp,
        reg_eq regOk_RSP htop, sim_rsp_val, reg_eq regOk_RAX hv, sim_rax_val]
      exact Step.storeRspRax _ hfetch
  | LockAlu op w64 src base disp =>
    obtain ⟨hsrc, hbase⟩ : RegOk src ∧ RegOk base := hok
    unfold x64_sim.lock_alu at h
    obtain_bind ⟨a, ha, h⟩ := h
    obtain_bind ⟨n, hn, h⟩ := h
    obtain_bind ⟨pr, hpr, h⟩ := h
    obtain ⟨ok1, cur⟩ := pr
    cases ok1 with
    | false => simp at h
    | true =>
      obtain_bind ⟨b, hb, h⟩ := h
      obtain_bind ⟨v, hv, h⟩ := h
      obtain_bind ⟨p, hp, h⟩ := h
      obtain ⟨okst, s1⟩ := p
      have hokst : okst = true := store_mem_true (in_bounds_of_load hpr) hp
      subst hokst
      obtain_bind ⟨s2, hs2, h⟩ := h
      obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      have hnv : n.val = opWidth w64 := op_width_eq hn
      have hnle : n.val ≤ 8 := by rw [hnv]; cases w64 <;> simp [opWidth]
      have hvv : U64.bv v = lockOp op (memVal w64 (absMem s) (U64.bv a))
          ((absState s).regs src.val) := by
        rw [lock_op_eq hv, memVal_eq hnv hmem hpr, reg_eq hsrc hb]
      have hstore := store_mem_eq' hnv (by rw [← hnv]; exact hnle) hmem hp
      have hbump := absState_bump (s1 := s2) (i := i) (usize_add_eq_ok hi)
      have hgoal : ∀ f : x64_sim.Flags, x64_sim.set_flags s1 f = ok s2 →
          absState { s2 with pc := i }
            = lockAluStep op w64 src base disp (absState s) (absFlags f) := by
        intro f hf
        rw [hbump, set_flags_abs hf, hstore, hvv, addr_eq hbase ha]
        rfl
      split at hs2
      · obtain_bind ⟨f, hf, hs2⟩ := hs2
        refine ⟨?_, frame_pc ((frame_store_mem hnle hmem hp).trans' (frame_set_flags hs2))⟩
        rw [hgoal f hs2]
        exact Step.lockAlu _ op w64 src base disp (absFlags f) hfetch
      · split at hs2
        · obtain_bind ⟨f, hf, hs2⟩ := hs2
          refine ⟨?_, frame_pc ((frame_store_mem hnle hmem hp).trans' (frame_set_flags hs2))⟩
          rw [hgoal f hs2]
          exact Step.lockAlu _ op w64 src base disp (absFlags f) hfetch
        · split at hs2
          · obtain_bind ⟨f, hf, hs2⟩ := hs2
            refine ⟨?_, frame_pc ((frame_store_mem hnle hmem hp).trans' (frame_set_flags hs2))⟩
            rw [hgoal f hs2]
            exact Step.lockAlu _ op w64 src base disp (absFlags f) hfetch
          · split at hs2
            · obtain_bind ⟨f, hf, hs2⟩ := hs2
              refine ⟨?_, frame_pc ((frame_store_mem hnle hmem hp).trans' (frame_set_flags hs2))⟩
              rw [hgoal f hs2]
              exact Step.lockAlu _ op w64 src base disp (absFlags f) hfetch
            · simp only [ok.injEq] at hs2
              subst hs2
              refine ⟨?_, frame_pc (frame_store_mem hnle hmem hp)⟩
              rw [hbump, hstore, hvv, addr_eq hbase ha]
              exact Step.lockAlu _ op w64 src base disp (absState s).flags hfetch
  | LockCmpxchg w64 src base disp =>
    obtain ⟨hsrc, hbase⟩ : RegOk src ∧ RegOk base := hok
    unfold x64_sim.cmpxchg at h
    obtain_bind ⟨a, ha, h⟩ := h
    obtain_bind ⟨n, hn, h⟩ := h
    obtain_bind ⟨pr, hpr, h⟩ := h
    obtain ⟨ok1, cur⟩ := pr
    cases ok1 with
    | false => simp at h
    | true =>
      obtain_bind ⟨rax, hrax, h⟩ := h
      obtain_bind ⟨acc, hacc, h⟩ := h
      obtain_bind ⟨f, hf, h⟩ := h
      obtain_bind ⟨s1, hs1, h⟩ := h
      obtain_bind ⟨s2, hs2, h⟩ := h
      obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      have hnv : n.val = opWidth w64 := op_width_eq hn
      have hnle : n.val ≤ 8 := by rw [hnv]; cases w64 <;> simp [opWidth]
      have hcurv : memVal w64 (absMem s) (U64.bv a) = U64.bv cur := memVal_eq hnv hmem hpr
      have haccv : U64.bv acc = wr w64 ((absState s).regs RAX) := by
        rw [wr_eq hacc, reg_eq regOk_RAX hrax, sim_rax_val]
      have hflags : absFlags f
          = flagsOfAddSub w64 true (U64.bv acc) (U64.bv cur) := flags_of_add_sub_eq hf
      have hwracc : wr w64 (U64.bv acc) = U64.bv acc := by rw [haccv, wr_wr]
      have hwrcur : wr w64 (U64.bv cur) = U64.bv cur := by
        refine wr_of_lt ?_
        obtain ⟨-, hlt⟩ := load_mem_bv' hnv (by rw [← hnv]; exact hnle) hmem hpr
        have : 8 * opWidth w64 = widthBits w64 := by cases w64 <;> rfl
        rw [← this]
        exact hlt
      have habump := absState_bump (s1 := s2) (i := i) (usize_add_eq_ok hi)
      split at hs1
      · -- the accumulator matches: the store happens
        rename_i heq
        obtain_bind ⟨v, hv, hs1⟩ := hs1
        obtain_bind ⟨p, hp, hs1⟩ := hs1
        obtain ⟨okst, s3⟩ := p
        have hokst : okst = true := store_mem_true (in_bounds_of_load hpr) hp
        subst hokst
        replace hs1 : ok s3 = ok s1 := hs1
        simp only [ok.injEq] at hs1
        subst hs1
        have hcond : memVal w64 (absMem s) (U64.bv a) = wr w64 ((absState s).regs RAX) := by
          rw [hcurv, ← haccv, ← u64_eq_iff]
          exact heq
        have hzf : (absFlags f).zf = true := by
          rw [hflags, flagsOfAddSub_sub_eq]
          show decide (wr w64 (wr w64 (U64.bv acc) - wr w64 (U64.bv cur)) = 0#64) = true
          rw [hwracc, hwrcur, decide_eq_true_eq, wr_sub_eq_zero_iff hwracc hwrcur, ← u64_eq_iff]
          exact heq.symm
        refine ⟨?_, frame_pc ((frame_store_mem hnle hmem hp).trans' (frame_set_flags hs2))⟩
        have hgoal : absState { s2 with pc := i }
            = cmpxchgStep w64 src base disp (absState s) (absFlags f) := by
          simp only [cmpxchgStep]
          rw [if_pos (by rw [absState_mem, ← addr_eq hbase ha]; exact hcond)]
          rw [habump, set_flags_abs hs2,
            store_mem_eq' hnv (by rw [← hnv]; exact hnle) hmem hp,
            addr_eq hbase ha, reg_eq hsrc hv,
            flags_zf_eta (absFlags f) true hzf]
        rw [hgoal]
        exact Step.lockCmpxchg _ w64 src base disp (absFlags f) hfetch
      · -- the accumulator does not match: `rax` takes the memory
        rename_i hne
        have hcond : ¬ (memVal w64 (absMem s) (U64.bv a) = wr w64 ((absState s).regs RAX)) := by
          rw [hcurv, ← haccv, ← u64_eq_iff]
          exact hne
        have hzf : (absFlags f).zf = false := by
          rw [hflags, flagsOfAddSub_sub_eq]
          show decide (wr w64 (wr w64 (U64.bv acc) - wr w64 (U64.bv cur)) = 0#64) = false
          rw [hwracc, hwrcur, decide_eq_false_iff_not, wr_sub_eq_zero_iff hwracc hwrcur,
            ← u64_eq_iff]
          exact fun hc => hne hc.symm
        refine ⟨?_, frame_pc ((frame_set_reg hs1).trans' (frame_set_flags hs2))⟩
        have hgoal : absState { s2 with pc := i }
            = cmpxchgStep w64 src base disp (absState s) (absFlags f) := by
          simp only [cmpxchgStep]
          rw [if_neg (by rw [absState_mem, ← addr_eq hbase ha]; exact hcond)]
          rw [habump, set_flags_abs hs2, set_reg_abs regOk_RAX hs1, sim_rax_val,
            ← hcurv, addr_eq hbase ha,
            flags_zf_eta (absFlags f) false hzf]
          rfl
        rw [hgoal]
        exact Step.lockCmpxchg _ w64 src base disp (absFlags f) hfetch
  | Xchg w64 src base disp =>
    obtain ⟨hsrc, hbase⟩ : RegOk src ∧ RegOk base := hok
    unfold x64_sim.xchg at h
    obtain_bind ⟨a, ha, h⟩ := h
    obtain_bind ⟨n, hn, h⟩ := h
    obtain_bind ⟨pr, hpr, h⟩ := h
    obtain ⟨ok1, cur⟩ := pr
    cases ok1 with
    | false => simp at h
    | true =>
      obtain_bind ⟨v, hv, h⟩ := h
      obtain_bind ⟨p, hp, h⟩ := h
      obtain ⟨okst, s1⟩ := p
      have hokst : okst = true := store_mem_true (in_bounds_of_load hpr) hp
      subst hokst
      obtain_bind ⟨s2, hs2, h⟩ := h
      obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      have hnv : n.val = opWidth w64 := op_width_eq hn
      have hnle : n.val ≤ 8 := by rw [hnv]; cases w64 <;> simp [opWidth]
      refine ⟨?_, frame_pc ((frame_store_mem hnle hmem hp).trans' (frame_set_reg hs2))⟩
      rw [absState_bump (s1 := s2) (i := i) (usize_add_eq_ok hi), set_reg_abs hsrc hs2,
        store_mem_eq' hnv (by rw [← hnv]; exact hnle) hmem hp,
        ← memVal_eq hnv hmem hpr, addr_eq hbase ha, reg_eq hsrc hv]
      exact Step.xchg _ w64 src base disp hfetch
  | Jcc cc target =>
    obtain_bind ⟨f, hf, h⟩ := h
    simp only [x64_sim.get_flags, ok.injEq] at hf
    subst hf
    obtain_bind ⟨taken, htaken, h⟩ := h
    have htv : taken = cond cc (absState s).flags := cond_eq htaken
    split at h
    · rename_i ht
      obtain ⟨i, hpos, habs, hfr⟩ := branch_eq h
      rw [habs]
      exact ⟨Step.jccTaken _ cc target i hfetch (by rw [← htv]; exact ht) hpos, hfr⟩
    · rename_i ht
      obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      rw [absState_bump (s1 := s) (i := i) (usize_add_eq_ok hi)]
      exact ⟨Step.jccNotTaken _ cc target hfetch (by rw [← htv]; simpa using ht),
        frame_pc (Frame.refl' s)⟩
  | Jmp target =>
    obtain ⟨i, hpos, habs, hfr⟩ := branch_eq h
    rw [habs]
    exact ⟨Step.jmp _ target i hfetch hpos, hfr⟩
  | JmpNear target =>
    obtain ⟨i, hpos, habs, hfr⟩ := branch_eq h
    rw [habs]
    exact ⟨Step.jmpNear _ target i hfetch hpos, hfr⟩
  | Call target =>
    unfold x64_sim.call at h
    dsimp only at h
    obtain_bind ⟨at1, hat, h⟩ := h
    split at h
    · rename_i hlt
      have hltv : at1.val < code.val.length := by
        rw [UScalar.lt_equiv] at hlt
        simp only [Slice.len_val, Slice.length] at hlt
        exact hlt
      obtain_bind ⟨i, hi, h⟩ := h
      have hiv : i.val = s.pc.val + 1 := usize_add_eq_ok hi
      obtain_bind ⟨i1, hi1, h⟩ := h
      simp only [lift, ok.injEq] at hi1
      subst hi1
      obtain_bind ⟨ra, hra, h⟩ := h
      obtain_bind ⟨p, hp, h⟩ := h
      obtain ⟨o, s1⟩ := p
      cases o with
      | Next =>
        replace h : ok (x64_sim.Outcome.Next,
            ({ s1 with pc := at1 } : x64_sim.Sim)) = ok (x64_sim.Outcome.Next, s') := h
        simp only [ok.injEq, Prod.mk.injEq] at h
        obtain ⟨-, rfl⟩ := h
        obtain ⟨habs, hpc, hbase, hcb, hlen⟩ := push_eq hmem hp
        have hrav : U64.bv ra = retAddr (simParams s) (absState s) := by
          rw [add64_eq hra]
          simp only [retAddr, simParams_codeBase]
          congr 1
          apply BitVec.eq_of_toNat_eq
          show (UScalar.cast .U64 i).val = _
          rw [cast_val_of_lt _ (by
            have := usize_lt_two_pow_64 i
            simp only [UScalarTy.U64_numBits_eq]
            omega), BitVec.toNat_ofNat, hiv]
          exact (Nat.mod_eq_of_lt (by
            have := usize_lt_two_pow_64 i
            omega)).symm
        have habs2 : absState { s1 with pc := at1 }
            = { absState s1 with pc := at1.val } := rfl
        rw [habs2, habs, hrav]
        exact ⟨Step.call _ target at1.val hfetch (find_label_eq hat hltv),
          frame_pc ⟨hbase, hcb, hlen⟩⟩
      | Halt => simp at h
      | Fault => simp at h
      | Unsupported => simp at h
    · simp at h
  | Jcc8 cc target =>
    obtain_bind ⟨f, hf, h⟩ := h
    simp only [x64_sim.get_flags, ok.injEq] at hf
    subst hf
    obtain_bind ⟨taken, htaken, h⟩ := h
    have htv : taken = cond cc (absState s).flags := cond_eq htaken
    split at h
    · rename_i ht
      obtain ⟨i, hpos, habs, hfr⟩ := branch_eq h
      rw [habs]
      exact ⟨Step.jcc8Taken _ cc target i hfetch (by rw [← htv]; exact ht) hpos, hfr⟩
    · rename_i ht
      obtain_bind ⟨i, hi, h⟩ := h
      simp only [ok.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      rw [absState_bump (s1 := s) (i := i) (usize_add_eq_ok hi)]
      exact ⟨Step.jcc8NotTaken _ cc target hfetch (by rw [← htv]; simpa using ht),
        frame_pc (Frame.refl' s)⟩
  | Jmp8 target =>
    obtain ⟨i, hpos, habs, hfr⟩ := branch_eq h
    rw [habs]
    exact ⟨Step.jmp8 _ target i hfetch hpos, hfr⟩
  | Ret =>
    unfold x64_sim.ret at h
    obtain_bind ⟨top, htop, h⟩ := h
    obtain_bind ⟨pr, hpr, h⟩ := h
    obtain ⟨ok1, v⟩ := pr
    cases ok1 with
    | false => simp at h
    | true =>
      dsimp only at h
      obtain_bind ⟨n, hn, h⟩ := h
      simp only [lift, ok.injEq] at hn
      subst hn
      obtain_bind ⟨at1, hat1, h⟩ := h
      have hncast : (UScalar.cast .U64 (Slice.len code)).val = code.val.length := by
        rw [cast_val_of_lt _ (by
          have := usize_lt_two_pow_64 (Slice.len code)
          simp only [UScalarTy.U64_numBits_eq]
          omega)]
        simp
      split at h
      · rename_i hlt
        have hltv : at1.val < code.val.length := by
          rw [UScalar.lt_equiv, hncast] at hlt
          exact hlt
        obtain_bind ⟨i1, hi1, h⟩ := h
        obtain_bind ⟨s1, hs1, h⟩ := h
        obtain_bind ⟨i2, hi2, h⟩ := h
        simp only [lift, ok.injEq] at hi2
        subst hi2
        simp only [ok.injEq, Prod.mk.injEq] at h
        obtain ⟨-, rfl⟩ := h
        obtain ⟨-, hlo, hhi⟩ := load_mem_eq (by simp) hmem hpr
        have hvload : load64 (absMem s) (U64.bv top) = U64.bv v := load64_eq rfl hmem hpr
        have hatv : at1.val = v.val - s.code_base.val ∧ s.code_base.val ≤ v.val := by
          split at hat1
          · rename_i hge
            obtain ⟨h1, h2⟩ := uscalar_sub_eq_ok hat1
            exact ⟨h1, h2⟩
          · simp only [ok.injEq] at hat1
            subst hat1
            rw [hncast] at hltv
            omega
        have hi2v : (UScalar.cast .Usize at1).val = at1.val := by
          refine cast_val_of_lt _ ?_
          have hle : code.val.length ≤ Usize.max := code.property
          have := usize_max_lt
          omega
        have hcode : load64 (absMem s) ((absState s).regs RSP)
            = codeAddr (simParams s) (UScalar.cast .Usize at1).val := by
          rw [reg_eq regOk_RSP htop, sim_rsp_val] at hvload
          rw [hvload, hi2v]
          apply BitVec.eq_of_toNat_eq
          simp only [codeAddr, simParams_codeBase, BitVec.toNat_add, BitVec.toNat_ofNat]
          have hvlt : v.val < 2 ^ 64 := by have := v.hBounds; simpa using this
          have hclt : s.code_base.val < 2 ^ 64 := by
            have := s.code_base.hBounds; simpa using this
          show v.val = (s.code_base.val + at1.val % 2 ^ 64) % 2 ^ 64
          rw [Nat.mod_eq_of_lt (by omega)]
          omega
        have hrsp : (absState s).regs RSP ≠ (simParams s).rsp0 := by
          rw [← sim_rsp_val, ← reg_eq regOk_RSP htop]
          simp only [simParams_rsp0]
          intro hc
          have h1 : (U64.bv top).toNat = (BitVec.allOnes 64).toNat := by rw [hc]
          rw [BitVec.toNat_allOnes] at h1
          have h2 : top.val = 2 ^ 64 - 1 := h1
          have h8 : (8#usize : Usize).val = 8 := rfl
          omega
        refine ⟨?_, frame_pc (frame_set_reg hs1)⟩
        rw [absState_pc_set s1 (UScalar.cast .Usize at1), set_reg_abs regOk_RSP hs1, add64_eq hi1,
          reg_eq regOk_RSP htop, sim_rsp_val,
          show U64.bv (8#u64 : Std.U64) = (8#64 : BitVec 64) from rfl]
        exact Step.retLocal _ (UScalar.cast .Usize at1).val hfetch hrsp (by rw [hi2v]; exact hltv)
          hcode
      · simp at h
  | Ud2 => simp at h
  | CallReg r => simp at h
  | RipLoadDispatcher dst => simp at h
  | RipLeaHelperTable dst => simp at h
  | DispatcherSlot a => simp at h
  | HelperTable => simp at h


/-- The simulator's parameters depend on the code base alone, and no step
moves it. -/
theorem simParams_congr {s1 s2 : x64_sim.Sim} (h : s1.code_base = s2.code_base) :
    simParams s1 = simParams s2 := by
  unfold simParams
  rw [h]

/-- **Every `Next` step of the executable model is a step of `Machine.lean`.**
The list's register operands must be ones the encoder emits (`CodeOk`), and
the mapped range must not wrap. -/
theorem step_refines {code : Slice x64_ir.PInsn} {s s' : x64_sim.Sim}
    (hcode : CodeOk code.val)
    (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.step code s = ok (.Next, s')) :
    Step (simParams s) code.val (absState s) (.next (absState s')) :=
  (step_refines_frame hcode hmem h).1

/-- A step keeps the code base, the mapped range's base and its length, so
`simParams` and the no-wrap hypothesis survive it. -/
theorem step_keeps_bases {code : Slice x64_ir.PInsn} {s s' : x64_sim.Sim}
    (hcode : CodeOk code.val)
    (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.step code s = ok (.Next, s')) :
    s'.code_base = s.code_base ∧ s'.mem_base = s.mem_base ∧
      s'.mem.val.length = s.mem.val.length := by
  obtain ⟨-, hfr⟩ := step_refines_frame hcode hmem h
  exact ⟨hfr.code, hfr.base, hfr.len⟩

/-- **A run that never leaves `Next` reaches its final state.** `run` returns
`Next` exactly when the budget ran out with the machine still stepping, and
then every state it passed through is one the relational model can reach. -/
theorem run_refines {code : Slice x64_ir.PInsn} {s s' : x64_sim.Sim} {n : Usize}
    (hcode : CodeOk code.val)
    (hmem : s.mem_base.val + s.mem.val.length ≤ 2 ^ 64)
    (h : x64_sim.run code s n = ok (.Next, s')) :
    Reachable (simParams s) code.val (absState s) (absState s') := by
  simp only [x64_sim.run, x64_sim.run_loop] at h
  refine (loop_ok_induction _
    (fun st => st.2.2.1 = x64_sim.Outcome.Next →
      (st.2.2.2 = false ∧ Reachable (simParams s) code.val (absState s) (absState st.1) ∧
        Frame s st.1))
    (fun r => r.1 = x64_sim.Outcome.Next →
      Reachable (simParams s) code.val (absState s) (absState r.2))
    ?_ (s, 0#usize, x64_sim.Outcome.Next, false) (x64_sim.Outcome.Next, s')
    (by intro _; exact ⟨rfl, Reachable.refl, Frame.refl' s⟩) h) rfl
  rintro ⟨s1, i1, out1, done1⟩ hP r hbody
  dsimp only at hP
  simp only [x64_sim.run_loop.body] at hbody
  split at hbody
  · split at hbody
    · rename_i hd
      simp only [ok.injEq] at hbody
      subst hbody
      dsimp only
      intro hout
      obtain ⟨hdf, -, -⟩ := hP hout
      rw [hdf] at hd
      simp at hd
    · rename_i hd
      simp only [Bool.not_eq_true] at hd
      subst hd
      obtain_bind ⟨p, hstep, hbody⟩ := hbody
      obtain ⟨o, s2⟩ := p
      obtain_bind ⟨q, hq, hbody⟩ := hbody
      obtain ⟨out2, done2⟩ := q
      obtain_bind ⟨i2, hi2, hbody⟩ := hbody
      simp only [ok.injEq] at hbody
      subst hbody
      dsimp only
      intro hout2
      cases o with
      | Next =>
        replace hq : ok (out1, false) = ok (out2, done2) := hq
        simp only [ok.injEq, Prod.mk.injEq] at hq
        obtain ⟨rfl, rfl⟩ := hq
        obtain ⟨-, hreach, hfr⟩ := hP hout2
        have hmem1 : s1.mem_base.val + s1.mem.val.length ≤ 2 ^ 64 := by
          rw [hfr.base, hfr.len]
          exact hmem
        obtain ⟨hstep', hfr'⟩ := step_refines_frame hcode hmem1 hstep
        rw [simParams_congr hfr.code] at hstep'
        exact ⟨rfl, hreach.step hstep', hfr.trans' hfr'⟩
      | Halt =>
        replace hq : ok (x64_sim.Outcome.Halt, true) = ok (out2, done2) := hq
        simp only [ok.injEq, Prod.mk.injEq] at hq
        rw [← hq.1] at hout2
        simp at hout2
      | Fault =>
        replace hq : ok (x64_sim.Outcome.Fault, true) = ok (out2, done2) := hq
        simp only [ok.injEq, Prod.mk.injEq] at hq
        rw [← hq.1] at hout2
        simp at hout2
      | Unsupported =>
        replace hq : ok (x64_sim.Outcome.Unsupported, true) = ok (out2, done2) := hq
        simp only [ok.injEq, Prod.mk.injEq] at hq
        rw [← hq.1] at hout2
        simp at hout2
  · simp only [ok.injEq] at hbody
    subst hbody
    dsimp only
    intro hout
    exact (hP hout).2.1


end X64

end async_ebpf_verified

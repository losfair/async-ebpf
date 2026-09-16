import AsyncEbpf.AsyncEbpfVerified
import AsyncEbpf.Loop

/-!
# The encoder, as a function from primitives to bytes

`src/verified/x64_encode.rs` was the last piece of the x86_64 backend that was
trusted rather than checked: a table from primitives to bytes, pinned only by
the goldens. This file gives that table a Lean counterpart — `enc`, a pure
function from a `PInsn` to the list of bytes the encoder appends for it — and
proves that the extracted encoder appends exactly those bytes
(`encode_one_spec`) and that the structural `size_of` counts exactly that many
(`size_of_spec`). `offsets_spec` carries the same over pass one of the
assembler: the table of starts is the running sum of the sizes, measured from
the start of the assembled function.

`AsyncEbpf/X64/Assemble.lean` is the other half: it runs the independently
written decoder over `enc p` and shows the bytes read back as `p`.

Everything here is stated against the extracted code, so `enc` is a
transcription that the theorems check rather than a second source of truth: if
`enc` disagreed with `encode_one`, `encode_one_spec` would not be provable.

The Vec capacity bound (`out.val.length + 512 ≤ Usize.max`) is a side
condition on every statement that emits: `alloc.vec.Vec.push` in the Aeneas
model refuses to grow a vector past `Usize.max`, and the real buffers are many
orders of magnitude smaller.
-/
open Aeneas Aeneas.Std Result

set_option maxHeartbeats 4000000
set_option maxRecDepth 100000
set_option Aeneas.Deprecated.progressWarning false

namespace async_ebpf_verified

namespace X64Enc

/-! ## Bytes -/

/-- The low eight bits of a bitvector, as a byte. -/
def lo8 {n : Nat} (x : BitVec n) : Std.U8 := ⟨x.setWidth 8⟩

/-- A sixteen-bit value, little-endian. -/
def u16L (x : Std.U16) : List Std.U8 := [lo8 x.bv, lo8 (x.bv >>> 8)]

/-- A thirty-two-bit value, little-endian. -/
def u32L (x : Std.U32) : List Std.U8 :=
  [lo8 x.bv, lo8 (x.bv >>> 8), lo8 (x.bv >>> 16), lo8 (x.bv >>> 24)]

/-- A sixty-four-bit value, little-endian. -/
def u64L (x : Std.U64) : List Std.U8 :=
  [lo8 x.bv, lo8 (x.bv >>> 8), lo8 (x.bv >>> 16), lo8 (x.bv >>> 24),
   lo8 (x.bv >>> 32), lo8 (x.bv >>> 40), lo8 (x.bv >>> 48), lo8 (x.bv >>> 56)]

@[local simp] theorem u16L_length (x : Std.U16) : (u16L x).length = 2 := rfl
@[local simp] theorem u32L_length (x : Std.U32) : (u32L x).length = 4 := rfl
@[local simp] theorem u64L_length (x : Std.U64) : (u64L x).length = 8 := rfl


/-! ## Bitvector plumbing

`bv_decide` proves these in one line, but it checks its SAT certificate by
native reflection, which would put an extra axiom in `#print axioms`. Every
bitvector fact below is therefore either a bit-by-bit case split (`bits8`,
`bits32`) or a `decide` over the two hundred and fifty-six bytes (`u8_cases`).
-/

/-- Prove an eight-bit bitvector identity one bit at a time. -/
macro "bits8" : tactic => `(tactic|
  (ext i
   have h8 : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨ i = 6 ∨ i = 7 := by omega
   rcases h8 with h|h|h|h|h|h|h|h <;> subst h <;> simp))

/-- Prove a thirty-two-bit bitvector identity one bit at a time. -/
macro "bits32" : tactic => `(tactic|
  (ext i
   have h32 : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨ i = 6 ∨ i = 7 ∨ i = 8 ∨ i = 9 ∨ i = 10 ∨ i = 11 ∨ i = 12 ∨ i = 13 ∨ i = 14 ∨ i = 15 ∨ i = 16 ∨ i = 17 ∨ i = 18 ∨ i = 19 ∨ i = 20 ∨ i = 21 ∨ i = 22 ∨ i = 23 ∨ i = 24 ∨ i = 25 ∨ i = 26 ∨ i = 27 ∨ i = 28 ∨ i = 29 ∨ i = 30 ∨ i = 31 := by omega
   rcases h32 with h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h <;> subst h <;> simp))

/-- A property of every byte is a property of the two hundred and fifty-six
numbers below `256`, which `decide` can check. -/
theorem u8_cases {P : Std.U8 → Prop} (h : ∀ n : Nat, n < 256 → P ⟨BitVec.ofNat 8 n⟩)
    (r : Std.U8) : P r := by
  have hr : r = ⟨BitVec.ofNat 8 r.bv.toNat⟩ := by apply U8.bv_eq_imp_eq; simp
  rw [hr]
  exact h r.bv.toNat (by have := r.bv.isLt; omega)

@[local simp] theorem bv8_and255 (y : BitVec 8) : y &&& 255#8 = y := by bits8

theorem emit1_spec (out : alloc.vec.Vec Std.U8) (x : Std.U8)
    (h : out.val.length + 1 ≤ Usize.max) :
    x64_encode.emit1 out x ⦃ o => o.val = out.val ++ [x] ⦄ := by
  unfold x64_encode.emit1
  step <;> scalar_tac

theorem emit2_spec (out : alloc.vec.Vec Std.U8) (x : Std.U16)
    (h : out.val.length + 2 ≤ Usize.max) :
    x64_encode.emit2 out x ⦃ o => o.val = out.val ++ u16L x ⦄ := by
  unfold x64_encode.emit2
  step* <;> simp_all [u16L, lo8, UScalar.cast] <;> try scalar_tac

theorem emit4_spec (out : alloc.vec.Vec Std.U8) (x : Std.U32)
    (h : out.val.length + 4 ≤ Usize.max) :
    x64_encode.emit4 out x ⦃ o => o.val = out.val ++ u32L x ⦄ := by
  unfold x64_encode.emit4
  step* <;> simp_all [u32L, lo8, UScalar.cast] <;> try scalar_tac

theorem emit8_spec (out : alloc.vec.Vec Std.U8) (x : Std.U64)
    (h : out.val.length + 8 ≤ Usize.max) :
    x64_encode.emit8 out x ⦃ o => o.val = out.val ++ u64L x ⦄ := by
  unfold x64_encode.emit8
  step* <;> simp_all [u64L, lo8, UScalar.cast] <;> try scalar_tac


/-! ## The encoder's small helpers, as pure functions -/

/-- A byte shifted left, which never overflows at the widths the encoder uses. -/
def shlU (x : Std.U8) (k : Nat) : Std.U8 := ⟨x.bv <<< k⟩

@[local simp] theorem shlU1 (x : Std.U8) : x <<< 1#i32 = ok (shlU x 1) := rfl
@[local simp] theorem shlU2 (x : Std.U8) : x <<< 2#i32 = ok (shlU x 2) := rfl
@[local simp] theorem shlU3 (x : Std.U8) : x <<< 3#i32 = ok (shlU x 3) := rfl

/-- `x64_encode::bit`. -/
def bitU (b : Bool) : Std.U8 := if b then 1#u8 else 0#u8

/-- `x64_encode::high`: a register's REX bit. -/
def highU (r : Std.U8) : Std.U8 := if r &&& 8#u8 != 0#u8 then 1#u8 else 0#u8

/-- A REX prefix byte. -/
def rexByte (w r x b : Std.U8) : Std.U8 :=
  ((((64#u8 ||| shlU w 3) ||| shlU r 2) ||| shlU x 1) ||| b)

/-- A ModRM byte. -/
def modrmB (md r m : Std.U8) : Std.U8 :=
  (((md &&& 192#u8) ||| shlU (r &&& 7#u8) 3) ||| (m &&& 7#u8))

/-- `x64_encode::basic_rex`: whether the short REX prefix is written at all. -/
def basicRexB (w src dst : Std.U8) : Bool :=
  (w != 0#u8) || (src &&& 8#u8 != 0#u8) || (dst &&& 8#u8 != 0#u8)

/-- The bytes `emit_basic_rex` writes. -/
def basicRexL (w src dst : Std.U8) : List Std.U8 :=
  if basicRexB w src dst then [rexByte w (highU src) 0#u8 (highU dst)] else []

/-- `x64_encode::near_disp`. -/
def nearDispB (d : Std.I32) : Bool := if d ≥ (-128)#i32 then decide (d ≤ 127#i32) else false

/-- `x64_encode::needs_disp`. -/
def needsDispB (rm : Std.U8) : Bool :=
  decide (rm = 4#u8 ∨ rm = 5#u8 ∨ rm = 12#u8 ∨ rm = 13#u8)

/-- `x64_encode::needs_sib`. -/
def needsSibB (rm : Std.U8) : Bool := decide (rm = 4#u8 ∨ rm = 12#u8)

@[local simp] theorem bitU_true : bitU true = 1#u8 := rfl
@[local simp] theorem bitU_false : bitU false = 0#u8 := rfl

@[local simp] theorem bit_eq (b : Bool) : x64_encode.bit b = ok (bitU b) := by
  unfold x64_encode.bit bitU; split <;> rfl

@[local simp] theorem high_eq (r : Std.U8) : x64_encode.high r = ok (highU r) := by
  unfold x64_encode.high highU
  simp only [lift, bind_tc_ok]
  split <;> rfl

@[local simp] theorem basic_rex_eq (w src dst : Std.U8) :
    x64_encode.basic_rex w src dst = ok (basicRexB w src dst) := by
  unfold x64_encode.basic_rex basicRexB
  simp only [lift, bind_tc_ok]
  split <;> simp_all
  split <;> simp_all

@[local simp] theorem near_disp_eq (d : Std.I32) :
    x64_encode.near_disp d = ok (nearDispB d) := by
  unfold x64_encode.near_disp nearDispB; split <;> rfl

@[local simp] theorem needs_disp_eq (rm : Std.U8) :
    x64_encode.needs_disp rm = ok (needsDispB rm) := by
  unfold x64_encode.needs_disp needsDispB
  simp only [x64_ir.RSP, x64_ir.RBP, x64_ir.R12, x64_ir.R13]
  split <;> simp_all
  split <;> simp_all
  split <;> simp_all

@[local simp] theorem needs_sib_eq (rm : Std.U8) :
    x64_encode.needs_sib rm = ok (needsSibB rm) := by
  unfold x64_encode.needs_sib needsSibB
  simp only [x64_ir.RSP, x64_ir.R12]
  split <;> simp_all

theorem emit_rex_spec (out : alloc.vec.Vec Std.U8) (w r x b : Std.U8)
    (h : out.val.length + 1 ≤ Usize.max) :
    x64_encode.emit_rex out w r x b ⦃ o => o.val = out.val ++ [rexByte w r x b] ⦄ := by
  unfold x64_encode.emit_rex
  simp only [shlU1, shlU2, shlU3, lift, bind_tc_ok, rexByte]
  step <;> scalar_tac

theorem emit_modrm_spec (out : alloc.vec.Vec Std.U8) (md r m : Std.U8)
    (h : out.val.length + 1 ≤ Usize.max) :
    x64_encode.emit_modrm out md r m ⦃ o => o.val = out.val ++ [modrmB md r m] ⦄ := by
  unfold x64_encode.emit_modrm
  simp only [shlU3, lift, bind_tc_ok, modrmB]
  step <;> scalar_tac


attribute [local step] emit1_spec emit2_spec emit4_spec emit8_spec emit_rex_spec emit_modrm_spec

/-! ## The byte sequences the encoder writes -/

/-- `emit_alu`: an optional REX, an opcode and a register-to-register ModRM. -/
def aluL (w64 : Bool) (op src dst : Std.U8) : List Std.U8 :=
  basicRexL (bitU w64) src dst ++ [op, modrmB 192#u8 src dst]

/-- `emit_modrm_and_displacement`. -/
def modrmDispL (reg rm : Std.U8) (d : Std.I32) : List Std.U8 :=
  if d = 0#i32 ∧ needsDispB (rm &&& 15#u8) = false then
    [modrmB 0#u8 (reg &&& 15#u8) (rm &&& 15#u8)]
  else
    modrmB (if nearDispB d then 64#u8 else 128#u8) (reg &&& 15#u8) (rm &&& 15#u8)
      :: ((if needsSibB (rm &&& 15#u8) then [36#u8] else [])
          ++ (if nearDispB d then [IScalar.hcast .U8 d] else u32L (IScalar.hcast .U32 d)))

/-- The length of `modrm_and_displacement`, which does not depend on the `reg` field. -/
def modrmDispLen (rm : Std.U8) (d : Std.I32) : Nat :=
  if d = 0#i32 ∧ needsDispB (rm &&& 15#u8) = false then 1
  else 1 + ((if needsSibB (rm &&& 15#u8) then 1 else 0) + (if nearDispB d then 1 else 4))

@[local simp] theorem modrmDispL_length (reg rm : Std.U8) (d : Std.I32) :
    (modrmDispL reg rm d).length = modrmDispLen rm d := by
  unfold modrmDispL modrmDispLen
  split <;> simp [u32L] <;> split <;> split <;> simp

@[local scalar_tac modrmDispLen rm d]
theorem modrmDispLen_le (rm : Std.U8) (d : Std.I32) :
    1 ≤ modrmDispLen rm d ∧ modrmDispLen rm d ≤ 6 := by
  unfold modrmDispLen
  split
  · omega
  · split <;> split <;> omega

@[local step] theorem emit_basic_rex_spec (out : alloc.vec.Vec Std.U8) (w src dst : Std.U8)
    (h : out.val.length + 1 ≤ Usize.max) :
    x64_encode.emit_basic_rex out w src dst ⦃ o => o.val = out.val ++ basicRexL w src dst ⦄ := by
  unfold x64_encode.emit_basic_rex
  simp only [basic_rex_eq, high_eq, bind_tc_ok, basicRexL]
  split
  · step <;> scalar_tac
  · simp

@[local step] theorem basic_rex_len_spec (w src dst : Std.U8) :
    x64_encode.basic_rex_len w src dst ⦃ n => n.val = (basicRexL w src dst).length ⦄ := by
  unfold x64_encode.basic_rex_len
  simp only [basic_rex_eq, bind_tc_ok, basicRexL]
  split <;> simp

@[local step] theorem emit_modrm_reg2reg_spec (out : alloc.vec.Vec Std.U8) (r m : Std.U8)
    (h : out.val.length + 1 ≤ Usize.max) :
    x64_encode.emit_modrm_reg2reg out r m ⦃ o => o.val = out.val ++ [modrmB 192#u8 r m] ⦄ := by
  unfold x64_encode.emit_modrm_reg2reg
  step <;> scalar_tac

@[local step] theorem emit_alu_spec (out : alloc.vec.Vec Std.U8) (w64 : Bool) (op src dst : Std.U8)
    (h : out.val.length + 3 ≤ Usize.max) :
    x64_encode.emit_alu out w64 op src dst ⦃ o => o.val = out.val ++ aluL w64 op src dst ⦄ := by
  unfold x64_encode.emit_alu
  simp only [bit_eq, bind_tc_ok]
  by_cases hb : basicRexB (bitU w64) src dst = true <;>
    step* <;> simp_all [aluL, basicRexL] <;> scalar_tac

/-- The length of `emit_alu`, which does not depend on the opcode. -/
def aluLen (w64 : Bool) (src dst : Std.U8) : Nat := (basicRexL (bitU w64) src dst).length + 2

@[local simp] theorem aluL_length (w64 : Bool) (op src dst : Std.U8) :
    (aluL w64 op src dst).length = aluLen w64 src dst := by
  unfold aluL aluLen; simp

@[local scalar_tac aluLen w64 src dst]
theorem aluLen_le (w64 : Bool) (src dst : Std.U8) : 2 ≤ aluLen w64 src dst ∧ aluLen w64 src dst ≤ 3 := by
  unfold aluLen basicRexL; split <;> simp

@[local step] theorem alu_len_spec (w64 : Bool) (src dst : Std.U8) :
    x64_encode.alu_len w64 src dst ⦃ n => n.val = aluLen w64 src dst ⦄ := by
  unfold x64_encode.alu_len aluLen
  simp only [bit_eq, bind_tc_ok]
  by_cases hb : basicRexB (bitU w64) src dst = true <;>
    step* <;> (try simp_all [basicRexL]) <;> (try scalar_tac)

@[local step] theorem emit_modrm_and_displacement_spec (out : alloc.vec.Vec Std.U8)
    (reg rm : Std.U8) (d : Std.I32) (h : out.val.length + 6 ≤ Usize.max) :
    x64_encode.emit_modrm_and_displacement out reg rm d ⦃ o =>
      o.val = out.val ++ modrmDispL reg rm d ⦄ := by
  unfold x64_encode.emit_modrm_and_displacement
  simp only [needs_disp_eq, needs_sib_eq, near_disp_eq, lift, bind_tc_ok, modrmDispL]
  by_cases hd : d = 0#i32 <;> by_cases hn : needsDispB (rm &&& 15#u8) = true <;>
    by_cases hs : needsSibB (rm &&& 15#u8) = true <;> by_cases hnr : nearDispB d = true <;>
    simp_all <;> step* <;> simp_all [u32L] <;> scalar_tac

@[local step] theorem modrm_and_displacement_len_spec (rm : Std.U8) (d : Std.I32) :
    x64_encode.modrm_and_displacement_len rm d ⦃ n => n.val = modrmDispLen rm d ⦄ := by
  unfold x64_encode.modrm_and_displacement_len
  simp only [needs_disp_eq, needs_sib_eq, near_disp_eq, lift, bind_tc_ok, modrmDispLen]
  by_cases hd : d = 0#i32 <;> by_cases hn : needsDispB (rm &&& 15#u8) = true <;>
    by_cases hs : needsSibB (rm &&& 15#u8) = true <;> by_cases hnr : nearDispB d = true <;>
    simp_all <;> step* <;> simp_all [u32L] <;> scalar_tac

/-- `emit_load`. -/
def loadL (size src dst : Std.U8) (offset : Std.I32) : List Std.U8 :=
  basicRexL (bitU (size = 8#u8)) dst src
    ++ (if size = 1#u8 then [15#u8, 182#u8] else if size = 2#u8 then [15#u8, 183#u8] else [139#u8])
    ++ modrmDispL dst src offset

/-- `emit_load_sx`. -/
def loadSxL (size src dst : Std.U8) (offset : Std.I32) : List Std.U8 :=
  if size = 8#u8 then []
  else basicRexL 1#u8 dst src
    ++ (if size = 4#u8 then [99#u8] else if size = 1#u8 then [15#u8, 190#u8] else [15#u8, 191#u8])
    ++ modrmDispL dst src offset

/-- `x64_encode::store_rex`. -/
def storeRexB (size src dst : Std.U8) : Bool :=
  decide (size = 8#u8) || (src &&& 8#u8 != 0#u8) || (dst &&& 8#u8 != 0#u8) || decide (size = 1#u8)

/-- `emit_store`. -/
def storeL (size src dst : Std.U8) (offset : Std.I32) : List Std.U8 :=
  (if size = 2#u8 then [102#u8] else [])
    ++ (if storeRexB size src dst then
          [rexByte (bitU (size = 8#u8)) (highU src) 0#u8 (highU dst)] else [])
    ++ [if size = 1#u8 then 136#u8 else 137#u8]
    ++ modrmDispL src dst offset

/-- `emit_store_imm`. -/
def storeImmL (size dst : Std.U8) (offset imm : Std.I32) : List Std.U8 :=
  (if size = 2#u8 then [102#u8] else [])
    ++ basicRexL (bitU (size = 8#u8)) 0#u8 dst
    ++ [if size = 1#u8 then 198#u8 else 199#u8]
    ++ modrmDispL 0#u8 dst offset
    ++ (if size = 1#u8 then [IScalar.hcast .U8 imm]
        else if size = 2#u8 then u16L (IScalar.hcast .U16 imm)
        else u32L (IScalar.hcast .U32 imm))

/-- `x64_encode::imm_fits32`. -/
def immFits32B (imm : Std.I64) : Bool :=
  if imm ≥ x64_encode.IMM32_MIN then decide (imm ≤ x64_encode.IMM32_MAX) else false

/-- `emit_load_imm`. -/
def loadImmL (dst : Std.U8) (imm : Std.I64) : List Std.U8 :=
  if immFits32B imm then aluL true 199#u8 0#u8 dst ++ u32L (IScalar.hcast .U32 imm)
  else basicRexL 1#u8 0#u8 dst ++ [184#u8 ||| (dst &&& 7#u8)] ++ u64L (IScalar.hcast .U64 imm)

@[local scalar_tac (basicRexL w src dst).length]
theorem basicRexL_length_le (w src dst : Std.U8) : (basicRexL w src dst).length ≤ 1 := by
  unfold basicRexL; split <;> simp

@[local step] theorem emit_load_spec (out : alloc.vec.Vec Std.U8) (size src dst : Std.U8)
    (offset : Std.I32) (h : out.val.length + 9 ≤ Usize.max) :
    x64_encode.emit_load out size src dst offset ⦃ o =>
      o.val = out.val ++ loadL size src dst offset ⦄ := by
  unfold x64_encode.emit_load
  simp only [bit_eq, bind_tc_ok]
  by_cases h1 : size = 1#u8 <;> by_cases h2 : size = 2#u8 <;>
    by_cases hb : basicRexB (bitU (size = 8#u8)) dst src = true <;>
    (try simp_all [loadL, basicRexL]) <;> step* <;> (try simp_all [basicRexL]) <;> (try scalar_tac)

@[local step] theorem load_len_spec (size src dst : Std.U8) (offset : Std.I32) :
    x64_encode.load_len size src dst offset ⦃ n => n.val = (loadL size src dst offset).length ⦄ := by
  unfold x64_encode.load_len
  simp only [bit_eq, bind_tc_ok]
  by_cases h1 : size = 1#u8 <;> by_cases h2 : size = 2#u8 <;>
    by_cases hb : basicRexB (bitU (size = 8#u8)) dst src = true <;>
    (try simp_all [loadL, basicRexL]) <;> step* <;> (try simp_all [basicRexL]) <;> (try scalar_tac)

@[local step] theorem emit_load_sx_spec (out : alloc.vec.Vec Std.U8) (size src dst : Std.U8)
    (offset : Std.I32) (h : out.val.length + 9 ≤ Usize.max) :
    x64_encode.emit_load_sx out size src dst offset ⦃ o =>
      o.val = out.val ++ loadSxL size src dst offset ⦄ := by
  unfold x64_encode.emit_load_sx
  by_cases h8 : size = 8#u8 <;> by_cases h4 : size = 4#u8 <;> by_cases h1 : size = 1#u8 <;>
    by_cases hb : basicRexB 1#u8 dst src = true <;>
    (try simp_all [loadSxL, basicRexL]) <;> step* <;> (try simp_all [basicRexL]) <;> (try scalar_tac)

@[local simp] theorem basicRexB_w1 (src dst : Std.U8) : basicRexB 1#u8 src dst = true := by
  simp [basicRexB]

@[local simp] theorem basicRexL_w1_length (src dst : Std.U8) :
    (basicRexL 1#u8 src dst).length = 1 := by simp [basicRexL]

/-- The length of `emit_load_sx`, which does not depend on the destination. -/
def loadSxLen (size src : Std.U8) (offset : Std.I32) : Nat :=
  if size = 8#u8 then 0 else 1 + ((if size = 4#u8 then 1 else 2) + modrmDispLen src offset)

@[local simp] theorem loadSxL_length (size src dst : Std.U8) (offset : Std.I32) :
    (loadSxL size src dst offset).length = loadSxLen size src offset := by
  unfold loadSxL loadSxLen basicRexL
  by_cases h8 : size = 8#u8 <;> by_cases h4 : size = 4#u8 <;> by_cases h1 : size = 1#u8 <;>
    simp_all <;> omega

@[local scalar_tac loadSxLen size src offset]
theorem loadSxLen_le (size src : Std.U8) (offset : Std.I32) : loadSxLen size src offset ≤ 9 := by
  unfold loadSxLen
  have := modrmDispLen_le src offset
  split
  · omega
  · split <;> omega

@[local step] theorem load_sx_len_spec (size src : Std.U8) (offset : Std.I32) :
    x64_encode.load_sx_len size src offset ⦃ n => n.val = loadSxLen size src offset ⦄ := by
  unfold x64_encode.load_sx_len
  by_cases h8 : size = 8#u8 <;> by_cases h4 : size = 4#u8 <;> by_cases h1 : size = 1#u8 <;>
    (try simp_all [loadSxLen]) <;> step* <;> (try simp_all) <;> (try scalar_tac)

@[local simp] theorem store_rex_eq (size src dst : Std.U8) :
    x64_encode.store_rex size src dst = ok (storeRexB size src dst) := by
  unfold x64_encode.store_rex storeRexB
  simp only [lift, bind_tc_ok]
  by_cases a : size = 8#u8 <;> by_cases b : (src &&& 8#u8 != 0#u8) = true <;>
    by_cases c : (dst &&& 8#u8 != 0#u8) = true <;> simp_all

@[local step] theorem emit_store_spec (out : alloc.vec.Vec Std.U8) (size src dst : Std.U8)
    (offset : Std.I32) (h : out.val.length + 9 ≤ Usize.max) :
    x64_encode.emit_store out size src dst offset ⦃ o =>
      o.val = out.val ++ storeL size src dst offset ⦄ := by
  unfold x64_encode.emit_store
  simp only [store_rex_eq, bit_eq, high_eq, bind_tc_ok]
  by_cases h1 : size = 1#u8 <;> by_cases h2 : size = 2#u8 <;>
    by_cases hb : storeRexB size src dst = true <;>
    (try simp_all [storeL]) <;> step* <;> (try simp_all) <;> (try scalar_tac)

@[local step] theorem store_len_spec (size src dst : Std.U8) (offset : Std.I32) :
    x64_encode.store_len size src dst offset ⦃ n => n.val = (storeL size src dst offset).length ⦄ := by
  unfold x64_encode.store_len
  simp only [store_rex_eq, bind_tc_ok]
  by_cases h1 : size = 1#u8 <;> by_cases h2 : size = 2#u8 <;>
    by_cases hb : storeRexB size src dst = true <;>
    (try simp_all [storeL]) <;> step* <;> (try simp_all) <;> (try scalar_tac)

@[local step] theorem emit_store_imm_spec (out : alloc.vec.Vec Std.U8) (size dst : Std.U8)
    (offset imm : Std.I32) (h : out.val.length + 13 ≤ Usize.max) :
    x64_encode.emit_store_imm out size dst offset imm ⦃ o =>
      o.val = out.val ++ storeImmL size dst offset imm ⦄ := by
  unfold x64_encode.emit_store_imm
  simp only [bit_eq, bind_tc_ok, lift]
  by_cases h1 : size = 1#u8 <;> by_cases h2 : size = 2#u8 <;>
    by_cases hb : basicRexB (bitU (size = 8#u8)) 0#u8 dst = true <;>
    (try simp_all [storeImmL, basicRexL]) <;> step* <;> (try simp_all [basicRexL]) <;> (try scalar_tac)

/-- The length of `emit_store_imm`, which does not depend on the immediate. -/
def storeImmLen (size dst : Std.U8) (offset : Std.I32) : Nat :=
  (if size = 2#u8 then 1 else 0) + (basicRexL (bitU (size = 8#u8)) 0#u8 dst).length + 1
    + modrmDispLen dst offset + (if size = 1#u8 then 1 else if size = 2#u8 then 2 else 4)

@[local simp] theorem storeImmL_length (size dst : Std.U8) (offset imm : Std.I32) :
    (storeImmL size dst offset imm).length = storeImmLen size dst offset := by
  unfold storeImmL storeImmLen
  by_cases h1 : size = 1#u8 <;> by_cases h2 : size = 2#u8 <;>
    simp_all [u16L, u32L] <;> omega

@[local scalar_tac storeImmLen size dst offset]
theorem storeImmLen_le (size dst : Std.U8) (offset : Std.I32) : storeImmLen size dst offset ≤ 13 := by
  unfold storeImmLen
  have := modrmDispLen_le dst offset
  have := basicRexL_length_le (bitU (size = 8#u8)) 0#u8 dst
  by_cases h1 : size = 1#u8 <;> by_cases h2 : size = 2#u8 <;> simp_all <;> omega

@[local step] theorem store_imm_len_spec (size dst : Std.U8) (offset : Std.I32) :
    x64_encode.store_imm_len size dst offset ⦃ n => n.val = storeImmLen size dst offset ⦄ := by
  unfold x64_encode.store_imm_len
  simp only [bit_eq, bind_tc_ok]
  by_cases h1 : size = 1#u8 <;> by_cases h2 : size = 2#u8 <;>
    by_cases hb : basicRexB (bitU (size = 8#u8)) 0#u8 dst = true <;>
    (try simp_all [storeImmLen, basicRexL]) <;> step* <;>
      (try simp_all [basicRexL]) <;> (try scalar_tac)

@[local simp] theorem imm_fits32_eq (imm : Std.I64) :
    x64_encode.imm_fits32 imm = ok (immFits32B imm) := by
  unfold x64_encode.imm_fits32 immFits32B; split <;> rfl

@[local step] theorem emit_load_imm_spec (out : alloc.vec.Vec Std.U8) (dst : Std.U8)
    (imm : Std.I64) (h : out.val.length + 10 ≤ Usize.max) :
    x64_encode.emit_load_imm out dst imm ⦃ o => o.val = out.val ++ loadImmL dst imm ⦄ := by
  unfold x64_encode.emit_load_imm
  simp only [imm_fits32_eq, bind_tc_ok, lift]
  by_cases hf : immFits32B imm = true <;>
    by_cases hb : basicRexB 1#u8 0#u8 dst = true <;>
    (try simp_all [loadImmL, aluL, basicRexL]) <;> step* <;>
      (try simp_all [loadImmL, basicRexL, aluL]) <;> (try scalar_tac)

@[local step] theorem load_imm_len_spec (dst : Std.U8) (imm : Std.I64) :
    x64_encode.load_imm_len dst imm ⦃ n => n.val = (loadImmL dst imm).length ⦄ := by
  unfold x64_encode.load_imm_len
  simp only [imm_fits32_eq, bind_tc_ok]
  by_cases hf : immFits32B imm = true <;>
    by_cases hb : basicRexB 1#u8 0#u8 dst = true <;>
    (try simp_all [loadImmL, aluL, basicRexL, u32L, u64L]) <;> step* <;>
      (try simp_all [loadImmL, basicRexL, aluL, aluLen, u32L, u64L]) <;> (try scalar_tac)

/-! ## The opcode tables -/

def aluRROp : x64_ir.AluRR → Std.U8
  | .Add => 1#u8 | .Sub => 41#u8 | .Or => 9#u8 | .And => 33#u8
  | .Xor => 49#u8 | .Mov => 137#u8 | .Cmp => 57#u8 | .Test => 133#u8

def aluRIOp : x64_ir.AluRI → Std.U8
  | .Add => 129#u8 | .Or => 129#u8 | .And => 129#u8 | .Sub => 129#u8
  | .Xor => 129#u8 | .Cmp => 129#u8 | .Mov => 199#u8 | .Test => 247#u8

def aluRIExt : x64_ir.AluRI → Std.U8
  | .Add => 0#u8 | .Or => 1#u8 | .And => 4#u8 | .Sub => 5#u8
  | .Xor => 6#u8 | .Cmp => 7#u8 | .Mov => 0#u8 | .Test => 0#u8

def shiftExtU : x64_ir.ShiftOp → Std.U8
  | .Shl => 4#u8 | .Shr => 5#u8 | .Sar => 7#u8

def aluRMOp : x64_ir.AluRM → Std.U8
  | .Sub => 43#u8 | .Add => 3#u8 | .CmpMR => 57#u8 | .CmpRM => 59#u8 | .Or => 11#u8

def muldivExtU : x64_ir.MulDivKind → Bool → Std.U8
  | .Mul, _ => 4#u8
  | .Div, signed => if signed then 7#u8 else 6#u8
  | .Mod, signed => if signed then 7#u8 else 6#u8

@[local simp] theorem alu_rr_opcode_eq (op : x64_ir.AluRR) :
    x64_encode.alu_rr_opcode op = ok (aluRROp op) := by cases op <;> rfl
@[local simp] theorem alu_ri_opcode_eq (op : x64_ir.AluRI) :
    x64_encode.alu_ri_opcode op = ok (aluRIOp op) := by cases op <;> rfl
@[local simp] theorem alu_ri_ext_eq (op : x64_ir.AluRI) :
    x64_encode.alu_ri_ext op = ok (aluRIExt op) := by cases op <;> rfl
@[local simp] theorem shift_ext_eq (op : x64_ir.ShiftOp) :
    x64_encode.shift_ext op = ok (shiftExtU op) := by cases op <;> rfl
@[local simp] theorem alu_rm_opcode_eq (op : x64_ir.AluRM) :
    x64_encode.alu_rm_opcode op = ok (aluRMOp op) := by cases op <;> rfl
@[local simp] theorem muldiv_ext_eq (kind : x64_ir.MulDivKind) (signed : Bool) :
    x64_encode.muldiv_ext kind signed = ok (muldivExtU kind signed) := by
  cases kind <;> [rfl; (cases signed <;> rfl); (cases signed <;> rfl)]

/-! ## The remaining byte sequences -/

/-- `emit_muldiv_rcx`. -/
def muldivRcxL (w64 : Bool) (kind : x64_ir.MulDivKind) (signed : Bool) : List Std.U8 :=
  (if w64 then [rexByte 1#u8 0#u8 0#u8 0#u8] else [])
    ++ aluL false 247#u8 (muldivExtU kind signed) 1#u8

/-- `emit_movsx`. -/
def movsxL (from_ : Std.U8) (w64 : Bool) (src dst : Std.U8) : List Std.U8 :=
  (if w64 then [rexByte (bitU true) (highU dst) 0#u8 (highU src)]
   else if from_ = 8#u8 then [rexByte (bitU false) (highU dst) 0#u8 (highU src)]
   else basicRexL 0#u8 dst src)
    ++ (if from_ = 32#u8 then [99#u8]
        else if from_ = 8#u8 then [15#u8, 190#u8] else [15#u8, 191#u8])
    ++ [modrmB 192#u8 dst src]

/-- `emit_cmp_rcx_minus_one`. -/
def cmpRcxL (w64 : Bool) : List Std.U8 := (if w64 then [72#u8] else []) ++ [131#u8, 249#u8, 255#u8]

/-- `emit_call_reg`. -/
def callRegL (reg : Std.U8) : List Std.U8 :=
  (if reg &&& 8#u8 != 0#u8 then [65#u8] else []) ++ [255#u8, 208#u8 ||| (reg &&& 7#u8)]

/-- `emit_guest_load`. -/
def guestLoadL (size : Std.U8) (sxf : Bool) (base dst : Std.U8) (disp : Std.I32) : List Std.U8 :=
  if sxf then loadSxL size base dst disp else loadL size base dst disp

@[local step] theorem emit_muldiv_rcx_spec (out : alloc.vec.Vec Std.U8) (w64 : Bool)
    (kind : x64_ir.MulDivKind) (signed : Bool) (h : out.val.length + 4 ≤ Usize.max) :
    x64_encode.emit_muldiv_rcx out w64 kind signed ⦃ o =>
      o.val = out.val ++ muldivRcxL w64 kind signed ⦄ := by
  unfold x64_encode.emit_muldiv_rcx
  simp only [muldiv_ext_eq, bind_tc_ok, x64_ir.RCX]
  by_cases hw : w64 = true <;>
    (try simp_all [muldivRcxL]) <;> step* <;> (try simp_all [muldivRcxL, aluL, basicRexL]) <;>
    (try scalar_tac)

@[local step] theorem muldiv_rcx_len_spec (w64 : Bool) (kind : x64_ir.MulDivKind) (signed : Bool) :
    x64_encode.muldiv_rcx_len w64 kind signed ⦃ n => n.val = (muldivRcxL w64 kind signed).length ⦄ := by
  unfold x64_encode.muldiv_rcx_len
  simp only [muldiv_ext_eq, bind_tc_ok, x64_ir.RCX]
  by_cases hw : w64 = true <;>
    by_cases hb : basicRexB 0#u8 (muldivExtU kind signed) 1#u8 = true <;>
    (try simp_all [muldivRcxL, aluL, basicRexL]) <;> step* <;>
    (try simp_all [muldivRcxL, aluL, aluLen, basicRexL]) <;> (try scalar_tac)

@[local step] theorem emit_movsx_spec (out : alloc.vec.Vec Std.U8) (from_ : Std.U8) (w64 : Bool)
    (src dst : Std.U8) (h : out.val.length + 4 ≤ Usize.max) :
    x64_encode.emit_movsx out from_ w64 src dst ⦃ o =>
      o.val = out.val ++ movsxL from_ w64 src dst ⦄ := by
  unfold x64_encode.emit_movsx
  simp only [bit_eq, high_eq, bind_tc_ok]
  by_cases hw : w64 = true <;> by_cases h8 : from_ = 8#u8 <;> by_cases h32 : from_ = 32#u8 <;>
    by_cases hb : basicRexB 0#u8 dst src = true <;>
    (try simp_all [movsxL, basicRexL]) <;> step* <;>
    (try simp_all [movsxL, basicRexL]) <;> (try scalar_tac)

@[local step] theorem movsx_len_spec (from_ : Std.U8) (w64 : Bool) (src dst : Std.U8) :
    x64_encode.movsx_len from_ w64 src dst ⦃ n => n.val = (movsxL from_ w64 src dst).length ⦄ := by
  unfold x64_encode.movsx_len
  by_cases hw : w64 = true <;> by_cases h8 : from_ = 8#u8 <;> by_cases h32 : from_ = 32#u8 <;>
    by_cases hb : basicRexB 0#u8 dst src = true <;>
    (try simp_all [movsxL, basicRexL]) <;> step* <;>
    (try simp_all [movsxL, basicRexL]) <;> (try scalar_tac)

@[local step] theorem emit_cmp_rcx_minus_one_spec (out : alloc.vec.Vec Std.U8) (w64 : Bool)
    (h : out.val.length + 4 ≤ Usize.max) :
    x64_encode.emit_cmp_rcx_minus_one out w64 ⦃ o => o.val = out.val ++ cmpRcxL w64 ⦄ := by
  unfold x64_encode.emit_cmp_rcx_minus_one
  by_cases hw : w64 = true <;>
    (try simp_all [cmpRcxL]) <;> step* <;> (try simp_all [cmpRcxL]) <;> (try scalar_tac)

@[local step] theorem cmp_rcx_minus_one_len_spec (w64 : Bool) :
    x64_encode.cmp_rcx_minus_one_len w64 ⦃ n => n.val = (cmpRcxL w64).length ⦄ := by
  unfold x64_encode.cmp_rcx_minus_one_len
  by_cases hw : w64 = true <;>
    (try simp_all [cmpRcxL]) <;> step* <;> (try simp_all [cmpRcxL]) <;> (try scalar_tac)

@[local step] theorem emit_call_reg_spec (out : alloc.vec.Vec Std.U8) (reg : Std.U8)
    (h : out.val.length + 3 ≤ Usize.max) :
    x64_encode.emit_call_reg out reg ⦃ o => o.val = out.val ++ callRegL reg ⦄ := by
  unfold x64_encode.emit_call_reg
  simp only [lift, bind_tc_ok]
  by_cases hr : (reg &&& 8#u8 != 0#u8) = true <;>
    (try simp_all [callRegL]) <;> step* <;> (try simp_all [callRegL]) <;> (try scalar_tac)

@[local step] theorem call_reg_len_spec (reg : Std.U8) :
    x64_encode.call_reg_len reg ⦃ n => n.val = (callRegL reg).length ⦄ := by
  unfold x64_encode.call_reg_len
  simp only [lift, bind_tc_ok]
  by_cases hr : (reg &&& 8#u8 != 0#u8) = true <;>
    (try simp_all [callRegL]) <;> step* <;> (try simp_all [callRegL]) <;> (try scalar_tac)

@[local step] theorem emit_guest_load_spec (out : alloc.vec.Vec Std.U8) (size : Std.U8)
    (sxf : Bool) (base dst : Std.U8) (disp : Std.I32) (h : out.val.length + 9 ≤ Usize.max) :
    x64_encode.emit_guest_load out size sxf base dst disp ⦃ o =>
      o.val = out.val ++ guestLoadL size sxf base dst disp ⦄ := by
  unfold x64_encode.emit_guest_load guestLoadL
  split <;> step* <;> (try scalar_tac)

/-- The length of `emit_guest_load`. -/
def guestLoadLen (size : Std.U8) (sxf : Bool) (base dst : Std.U8) (disp : Std.I32) : Nat :=
  if sxf then loadSxLen size base disp else (loadL size base dst disp).length

@[local simp] theorem guestLoadL_length (size : Std.U8) (sxf : Bool) (base dst : Std.U8)
    (disp : Std.I32) :
    (guestLoadL size sxf base dst disp).length = guestLoadLen size sxf base dst disp := by
  unfold guestLoadL guestLoadLen; split <;> simp

@[local step] theorem guest_load_len_spec (size : Std.U8) (sxf : Bool) (base dst : Std.U8)
    (disp : Std.I32) :
    x64_encode.guest_load_len size sxf base dst disp ⦃ n =>
      n.val = guestLoadLen size sxf base dst disp ⦄ := by
  unfold x64_encode.guest_load_len guestLoadLen
  split <;> step* <;> (try simp_all)

/-! ## The helper table -/

/-- The five hundred and twelve zero bytes of the embedded helper table. -/
def helperTableL : List Std.U8 := List.replicate 512 0#u8

@[local step] theorem helper_table_len_spec : x64_encode.HELPER_TABLE_LEN ⦃ n => n.val = 512 ⦄ := by
  unfold x64_encode.HELPER_TABLE_LEN
  simp only [x64_ir.MAX_EXT_FUNCS, lift, bind_tc_ok]
  step <;> scalar_tac

theorem emit_helper_table_loop_spec (out : alloc.vec.Vec Std.U8) (k : Std.U32) (hk : k.val ≤ 64)
    (h : out.val.length + 8 * (64 - k.val) ≤ Usize.max) :
    x64_encode.emit_helper_table_loop out k ⦃ o =>
      o.val = out.val ++ List.replicate (8 * (64 - k.val)) 0#u8 ⦄ := by
  generalize hn : 64 - k.val = n
  induction n generalizing out k with
  | zero =>
    unfold x64_encode.emit_helper_table_loop
    rw [loop.eq_def]
    simp only [x64_encode.emit_helper_table_loop.body, x64_ir.MAX_EXT_FUNCS]
    rw [if_neg (by rw [UScalar.lt_equiv]; simp; omega)]
    simp [hn]
  | succ n ih =>
    unfold x64_encode.emit_helper_table_loop
    rw [loop.eq_def]
    simp only [x64_encode.emit_helper_table_loop.body, x64_ir.MAX_EXT_FUNCS]
    rw [if_pos (by rw [UScalar.lt_equiv]; simp; omega)]
    have hroom : out.val.length + 8 ≤ Usize.max := by omega
    obtain ⟨out1, hout1, hout1v⟩ := WP.spec_imp_exists (emit8_spec out 0#u64 hroom)
    simp only [hout1, bind_tc_ok]
    obtain ⟨k1, hk1, hk1v⟩ : ∃ k1 : Std.U32, k + 1#u32 = ok k1 ∧ k1.val = k.val + 1 := by
      have he := UScalar.add_equiv k 1#u32
      cases hkk : k + 1#u32 with
      | ok z => rw [hkk] at he; exact ⟨z, rfl, he.2.1⟩
      | fail e => rw [hkk] at he; simp [UScalar.inBounds, UScalarTy.numBits] at he; omega
      | div => rw [hkk] at he; exact he.elim
    simp only [hk1, bind_tc_ok]
    have hstep := ih out1 k1 (by omega) (by rw [hout1v]; simp [u64L]; omega) (by omega)
    unfold x64_encode.emit_helper_table_loop at hstep
    simp only [x64_encode.emit_helper_table_loop.body, x64_ir.MAX_EXT_FUNCS] at hstep
    refine WP.spec_mono hstep ?_
    intro o ho
    have hz : u64L 0#u64 = List.replicate 8 0#u8 := by simp [u64L, lo8]; rfl
    have hmul : 8 * (n + 1) = 8 + 8 * n := by omega
    rw [ho, hout1v, hmul, List.replicate_add, hz, List.append_assoc]

@[local step] theorem emit_helper_table_spec (out : alloc.vec.Vec Std.U8)
    (h : out.val.length + 512 ≤ Usize.max) :
    x64_encode.emit_helper_table out ⦃ o => o.val = out.val ++ helperTableL ⦄ := by
  unfold x64_encode.emit_helper_table
  have := emit_helper_table_loop_spec out 0#u32 (by simp) (by simpa using h)
  refine WP.spec_mono this ?_
  intro o ho
  rw [ho, helperTableL]
  norm_num

/-! ## The bytes of one primitive -/

/-- The bytes `encode_one` appends for `p`, as a function rather than as an effect. -/
def enc : x64_ir.PInsn → List Std.U8
  | .PcLabel _ => []
  | .Local _ => []
  | .ExitLabel => []
  | .RetpolineLabel => []
  | .Push r => basicRexL 0#u8 0#u8 r ++ [80#u8 ||| (r &&& 7#u8)]
  | .Pop r => basicRexL 0#u8 0#u8 r ++ [88#u8 ||| (r &&& 7#u8)]
  | .Alu w64 op src dst => aluL w64 (aluRROp op) src dst
  | .AluImm w64 op dst imm =>
      aluL w64 (aluRIOp op) (aluRIExt op) dst ++ u32L (IScalar.hcast .U32 imm)
  | .ShiftImm w64 op dst imm => aluL w64 193#u8 (shiftExtU op) dst ++ [IScalar.hcast .U8 imm]
  | .ShiftCl w64 op dst => aluL w64 211#u8 (shiftExtU op) dst
  | .Neg w64 dst => aluL w64 247#u8 3#u8 dst
  | .MulDivRcx w64 kind signed => muldivRcxL w64 kind signed
  | .MovSx from_ w64 src dst => movsxL from_ w64 src dst
  | .Bswap w64 dst => basicRexL (bitU w64) 0#u8 dst ++ [15#u8, 200#u8 ||| (dst &&& 7#u8)]
  | .Rol16 dst => 102#u8 :: (aluL false 193#u8 0#u8 dst ++ [8#u8])
  | .Cmov cc dst src =>
      basicRexL 1#u8 dst src ++ [15#u8, 64#u8 ||| (cc &&& 15#u8), modrmB 192#u8 dst src]
  | .LoadImm dst imm => loadImmL dst imm
  | .Pushfq => [156#u8]
  | .Popfq => [157#u8]
  | .Cqo => [72#u8, 153#u8]
  | .Cdq => [153#u8]
  | .CmpRcxMinusOne w64 => cmpRcxL w64
  | .CmpEaxImm imm => 61#u8 :: u32L imm
  | .Load size sxf base dst disp => guestLoadL size sxf base dst disp
  | .Store size src base disp => storeL size src base disp
  | .StoreImm size base disp imm => storeImmL size base disp imm
  | .AluRM op reg base disp => basicRexL 1#u8 reg base ++ aluRMOp op :: modrmDispL reg base disp
  | .StoreRspImm imm => 72#u8 :: 199#u8 :: 4#u8 :: 36#u8 :: u32L imm
  | .StoreRspRax => [72#u8, 137#u8, 4#u8, 36#u8]
  | .LockAlu op w64 src base disp =>
      240#u8 :: (basicRexL (bitU w64) src base ++ op :: modrmDispL src base disp)
  | .LockCmpxchg w64 src base disp =>
      240#u8 :: (basicRexL (bitU w64) src base ++ 15#u8 :: 177#u8 :: modrmDispL src base disp)
  | .Xchg w64 src base disp =>
      240#u8 :: (basicRexL (bitU w64) src base ++ 135#u8 :: modrmDispL src base disp)
  | .Jcc cc _ => 15#u8 :: cc :: u32L 0#u32
  | .Jmp _ => 233#u8 :: u32L 0#u32
  | .JmpNear _ => 235#u8 :: u32L 0#u32
  | .Call _ => 232#u8 :: u32L 0#u32
  | .Jcc8 cc _ => [112#u8 ||| (cc &&& 15#u8), 0#u8]
  | .Jmp8 _ => [235#u8, 0#u8]
  | .Ret => [195#u8]
  | .Pause => [243#u8, 144#u8]
  | .Ud2 => [15#u8, 11#u8]
  | .CallReg reg => callRegL reg
  | .RipLoadDispatcher dst =>
      rexByte 1#u8 0#u8 0#u8 0#u8 :: 139#u8 :: modrmB 0#u8 dst 5#u8 :: u32L 0#u32
  | .RipLeaHelperTable dst =>
      rexByte 1#u8 (highU dst) 0#u8 0#u8 :: 141#u8 :: modrmB 0#u8 dst 5#u8 :: u32L 0#u32
  | .DispatcherSlot addr => u64L addr
  | .HelperTable => helperTableL

/-- **The encoder writes `enc p`.** -/
theorem encode_one_spec (p : x64_ir.PInsn) (out : alloc.vec.Vec Std.U8)
    (h : out.val.length + 512 ≤ Usize.max) :
    x64_encode.encode_one p out ⦃ o => o.val = out.val ++ enc p ⦄ := by
  induction p <;>
    simp only [x64_encode.encode_one, enc, lift, bind_tc_ok, alu_rr_opcode_eq, alu_ri_opcode_eq,
      alu_ri_ext_eq, shift_ext_eq, alu_rm_opcode_eq, bit_eq, high_eq] <;>
    step* <;> (try simp_all) <;> (try scalar_tac)

/-- **`size_of` is the length of `enc`.** -/
theorem size_of_enc (p : x64_ir.PInsn) : x64_encode.size_of p ⦃ n => n.val = (enc p).length ⦄ := by
  induction p <;>
    simp only [x64_encode.size_of, enc, lift, bind_tc_ok, alu_ri_ext_eq, shift_ext_eq, bit_eq] <;>
    step* <;> (try simp_all [helperTableL, aluLen, guestLoadLen]) <;> (try scalar_tac)

/-- **The structural size is the number of bytes emitted.** -/
theorem size_of_spec {p : x64_ir.PInsn} {out out' : alloc.vec.Vec Std.U8} {n : Usize}
    (hroom : out.val.length + 512 ≤ Usize.max)
    (henc : x64_encode.encode_one p out = ok out')
    (hsize : x64_encode.size_of p = ok n) :
    out'.val.length = out.val.length + n.val := by
  obtain ⟨o, ho, hov⟩ := WP.spec_imp_exists (encode_one_spec p out hroom)
  rw [henc, ok.injEq] at ho
  obtain ⟨m, hm, hmv⟩ := WP.spec_imp_exists (size_of_enc p)
  rw [hsize, ok.injEq] at hm
  subst ho; subst hm
  rw [hov, hmv]; simp

/-! ## Pass one: the offsets -/

local instance : Inhabited x64_ir.PInsn := ⟨x64_ir.PInsn.Ret⟩

theorem usize_add_ok {x y : Usize} (h : x.val + y.val ≤ Usize.max) :
    ∃ z : Usize, x + y = ok z ∧ z.val = x.val + y.val := by
  have he := UScalar.add_equiv x y
  have hp : 0 < 2 ^ System.Platform.numBits := Nat.two_pow_pos _
  cases hxy : x + y with
  | ok z => rw [hxy] at he; exact ⟨z, rfl, he.2.1⟩
  | fail e =>
    rw [hxy] at he
    simp [UScalar.inBounds] at he
    simp [Usize.max, Usize.numBits, UScalarTy.numBits] at h
    omega
  | div => rw [hxy] at he; exact he.elim

theorem getBang_append_left {α} [Inhabited α] (a b : List α) (j : Nat) (h : j < a.length) :
    (a ++ b)[j]! = a[j]! := by
  simp [List.getElem!_eq_getElem?_getD, List.getElem?_append_left h]

theorem getBang_append_right {α} [Inhabited α] (a b : List α) (j : Nat) (h : a.length ≤ j) :
    (a ++ b)[j]! = b[j - a.length]! := by
  simp [List.getElem!_eq_getElem?_getD, List.getElem?_append_right h]

/-- The length of one primitive's encoding. -/
def encLen (p : x64_ir.PInsn) : Nat := (enc p).length

/-- The total length of a list of primitives' encodings. -/
def totalLen (l : List x64_ir.PInsn) : Nat := (l.map encLen).sum

@[local simp] theorem totalLen_append (a b : List x64_ir.PInsn) :
    totalLen (a ++ b) = totalLen a + totalLen b := by simp [totalLen]

@[local simp] theorem totalLen_nil : totalLen [] = 0 := rfl

theorem totalLen_take_succ (l : List x64_ir.PInsn) (i : Nat) (h : i < l.length) :
    totalLen (l.take (i + 1)) = totalLen (l.take i) + encLen l[i]! := by
  have hsplit : l.take (i + 1) = l.take i ++ [l[i]] := by
    rw [List.take_succ, List.getElem?_eq_getElem h]; rfl
  rw [hsplit, totalLen_append]
  simp [totalLen, List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem h]

theorem totalLen_take_le (l : List x64_ir.PInsn) (i : Nat) : totalLen (l.take i) ≤ totalLen l := by
  have h : totalLen l = totalLen (l.take i) + totalLen (l.drop i) := by
    rw [← totalLen_append, List.take_append_drop]
  omega

theorem totalLen_take_all (l : List x64_ir.PInsn) (i : Nat) (h : l.length ≤ i) :
    totalLen (l.take i) = totalLen l := by rw [List.take_of_length_le h]

theorem offsets_loop_spec (code : Slice x64_ir.PInsn) (starts : alloc.vec.Vec Std.U32)
    (off : Usize) (i : Usize)
    (hfit : totalLen code.val < 2 ^ 32) (hfitU : totalLen code.val ≤ Usize.max)
    (hi : i.val ≤ code.val.length)
    (hoff : off.val = totalLen (code.val.take i.val))
    (hlen : starts.val.length = i.val)
    (hprev : ∀ j < i.val, (starts.val[j]!).val = totalLen (code.val.take j)) :
    x64_encode.offsets_loop code starts off i ⦃ r =>
      r.1.val.length = code.val.length ∧ r.2.val = totalLen code.val ∧
      ∀ j < code.val.length, (r.1.val[j]!).val = totalLen (code.val.take j) ⦄ := by
  generalize hn : code.val.length - i.val = n
  induction n generalizing starts off i with
  | zero =>
    unfold x64_encode.offsets_loop
    rw [loop.eq_def]
    simp only [x64_encode.offsets_loop.body]
    rw [if_neg (by rw [UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length]; omega)]
    have hieq : i.val = code.val.length := by omega
    refine WP.exists_imp_spec ⟨(starts, off), rfl, ?_, ?_, ?_⟩
    · show starts.val.length = code.val.length
      omega
    · show off.val = totalLen code.val
      rw [hoff, hieq, totalLen_take_all _ _ (le_refl _)]
    · show ∀ j < code.val.length, (starts.val[j]!).val = totalLen (code.val.take j)
      intro j hj; exact hprev j (by omega)
  | succ n ih =>
    unfold x64_encode.offsets_loop
    rw [loop.eq_def]
    simp only [x64_encode.offsets_loop.body]
    rw [if_pos (by rw [UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length]; omega)]
    have hilt : i.val < code.val.length := by omega
    -- push the current offset
    have hcode : code.val.length ≤ Usize.max := code.property
    have hpush : starts.val.length < Usize.max := by omega
    obtain ⟨starts1, hs1, hs1v⟩ :=
      WP.spec_imp_exists (alloc.vec.Vec.push_spec starts (UScalar.cast .U32 off) hpush)
    -- the element and its size
    have hidx : Slice.index_usize code i = ok code.val[i.val]! := by
      unfold Slice.index_usize
      rw [show code[i]? = code.val[i.val]? from rfl, List.getElem?_eq_getElem hilt]
      simp [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem hilt]
    obtain ⟨sz, hsz, hszv⟩ := WP.spec_imp_exists (size_of_enc code.val[i.val]!)
    have hoff_le : totalLen (code.val.take i.val) ≤ totalLen code.val := totalLen_take_le _ _
    have hnext : totalLen (code.val.take (i.val + 1)) ≤ totalLen code.val := totalLen_take_le _ _
    have hsucc := totalLen_take_succ code.val i.val hilt
    have hsum : off.val + sz.val = totalLen (code.val.take (i.val + 1)) := by
      rw [hoff, hszv, show (enc code.val[i.val]!).length = encLen code.val[i.val]! from rfl, ← hsucc]
    obtain ⟨off1, ho1, ho1v⟩ := usize_add_ok (x := off) (y := sz) (by omega)
    obtain ⟨i4, hi4, hi4v0⟩ := usize_add_ok (x := i) (y := 1#usize) (by simp; omega)
    have hi4v : i4.val = i.val + 1 := by simpa using hi4v0
    simp only [lift, bind_tc_ok, hs1, hidx, hsz, ho1, hi4]
    have hoffcast : (UScalar.cast .U32 off).val = off.val := by
      rw [UScalar.cast_val_eq]
      have : off.val < 2 ^ 32 := by rw [hoff]; omega
      simp [UScalarTy.numBits]
      omega
    have hstep := ih starts1 off1 i4 (by omega)
      (by rw [ho1v, hi4v]; exact hsum)
      (by rw [hs1v]; simp only [List.length_append, List.length_cons, List.length_nil]; omega)
      (by
        intro j hj
        rw [hs1v]
        rcases Nat.lt_or_ge j i.val with hlt | hge
        · rw [getBang_append_left _ _ _ (by omega)]
          exact hprev j hlt
        · have hje : j = i.val := by omega
          subst hje
          rw [getBang_append_right _ _ _ (by omega), hlen, Nat.sub_self]
          simpa [hoffcast] using hoff)
      (by omega)
    unfold x64_encode.offsets_loop at hstep
    simp only [x64_encode.offsets_loop.body] at hstep
    exact hstep

/-- **Pass one records the running sum of the sizes.** -/
theorem offsets_spec (code : Slice x64_ir.PInsn) (starts : alloc.vec.Vec Std.U32)
    (hstarts : starts.val = [])
    (hfit : totalLen code.val < 2 ^ 32) (hfitU : totalLen code.val ≤ Usize.max)
    (hn32 : code.val.length < Usize.max) :
    x64_encode.offsets code starts ⦃ s =>
      s.val.length = code.val.length + 1 ∧
      ∀ j ≤ code.val.length, (s.val[j]!).val = totalLen (code.val.take j) ⦄ := by
  unfold x64_encode.offsets
  have hloop := offsets_loop_spec code starts 0#usize 0#usize hfit hfitU (by simp)
    (by simp) (by simp [hstarts]) (by simp)
  refine WP.spec_bind hloop ?_
  rintro ⟨rv, ro⟩ ⟨hr1, hr2, hr3⟩
  dsimp only at hr1 hr2 hr3 ⊢
  simp only [lift, bind_tc_ok]
  have hpush : rv.val.length < Usize.max := by rw [hr1]; omega
  obtain ⟨s, hs, hsv⟩ :=
    WP.spec_imp_exists (alloc.vec.Vec.push_spec rv (UScalar.cast .U32 ro) hpush)
  refine WP.exists_imp_spec ⟨s, hs, ?_, ?_⟩
  · rw [hsv]; simp [hr1]
  · intro j hj
    rw [hsv]
    rcases Nat.lt_or_ge j code.val.length with hlt | hge
    · rw [getBang_append_left _ _ _ (by omega)]
      exact hr3 j hlt
    · have hje : j = code.val.length := by omega
      subst hje
      rw [getBang_append_right _ _ _ (by omega), hr1, Nat.sub_self]
      simp only [List.getElem!_cons_zero]
      rw [UScalar.cast_val_eq, hr2, totalLen_take_all _ _ (le_refl _)]
      simp [UScalarTy.numBits]
      omega

end X64Enc

end async_ebpf_verified

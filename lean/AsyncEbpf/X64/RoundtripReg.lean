import AsyncEbpf.X64.Assemble

/-!
# The encoder, checked against the decoder: the register and immediate forms

`AsyncEbpf/X64/Assemble.lean` states `DecodesTo p` — the bytes `enc p` appended
at an arbitrary offset in an arbitrary buffer decode back to `p`'s `shape`, to
`(enc p).length` bytes and to the placeholder displacement zero — and proves it
for seventeen variant families over the shared machinery at the top of that
file. This file adds thirteen more, again with every operand symbolic and under
exactly the `RegsBounded` side conditions:

`Push`, `Pop`, `AluImm` (all eight operations — which spread over three
different opcode bytes, `81`, `c7` and `f7` — both widths, all sixteen
destinations and every immediate), `ShiftImm` (whose immediate the decoder
returns truncated to a byte), `MulDivRcx` (both widths, all three kinds and
both signednesses, with `Mul` reading back unsigned and `Mod` as `Div`),
`MovSx` (from eight, sixteen and thirty-two bits, both widths, all sixteen
registers in both positions), `Bswap`, `Rol16`, `Cmov` (all sixteen condition
codes, all sixteen registers in both positions), `LoadImm` (both the immediate
that fits in thirty-two bits, which reads back as the `AluImm … Mov` it shares
its bytes with, and the `movabs` form), `Jcc`, `Jcc8` and `CallReg`.

The families still to do are the memory forms — `Load`, `Store`, `StoreImm`,
`AluRM`, `StoreRspImm`, `StoreRspRax`, `LockCmpxchg`, `Xchg` — and the trailer
— `RipLoadDispatcher`, `RipLeaHelperTable`, `DispatcherSlot`, `HelperTable`.

The new machinery here is small: `bits64` and `u64of_lo8` for the eight
immediate bytes of a `movabs`, the three remaining cast round-trips, and one
entry-point lemma per branch of the decoder's opcode dispatch that the
seventeen did not already reach (`decode_one_byte_push`, `…_pop`, `…_jcc8`,
`…_loadImm`).
-/
open Aeneas Aeneas.Std Result

set_option maxHeartbeats 4000000
set_option maxRecDepth 100000

namespace async_ebpf_verified
namespace X64Enc

/-! ## Bitvector plumbing -/

/-- Prove a sixty-four-bit bitvector identity one bit at a time. -/
macro "bits64" : tactic => `(tactic|
  (ext i
   have h64 : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨ i = 6 ∨ i = 7 ∨ i = 8 ∨ i = 9 ∨ i = 10 ∨ i = 11 ∨ i = 12 ∨ i = 13 ∨ i = 14 ∨ i = 15 ∨ i = 16 ∨ i = 17 ∨ i = 18 ∨ i = 19 ∨ i = 20 ∨ i = 21 ∨ i = 22 ∨ i = 23 ∨ i = 24 ∨ i = 25 ∨ i = 26 ∨ i = 27 ∨ i = 28 ∨ i = 29 ∨ i = 30 ∨ i = 31 ∨ i = 32 ∨ i = 33 ∨ i = 34 ∨ i = 35 ∨ i = 36 ∨ i = 37 ∨ i = 38 ∨ i = 39 ∨ i = 40 ∨ i = 41 ∨ i = 42 ∨ i = 43 ∨ i = 44 ∨ i = 45 ∨ i = 46 ∨ i = 47 ∨ i = 48 ∨ i = 49 ∨ i = 50 ∨ i = 51 ∨ i = 52 ∨ i = 53 ∨ i = 54 ∨ i = 55 ∨ i = 56 ∨ i = 57 ∨ i = 58 ∨ i = 59 ∨ i = 60 ∨ i = 61 ∨ i = 62 ∨ i = 63 := by omega
   rcases h64 with h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h <;> subst h <;> simp))

theorem u64of_bv (y : BitVec 64) :
    ((((((((y.setWidth 8).setWidth 64 ||| ((y >>> 8).setWidth 8).setWidth 64 <<< 8)
      ||| ((y >>> 16).setWidth 8).setWidth 64 <<< 16)
      ||| ((y >>> 24).setWidth 8).setWidth 64 <<< 24)
      ||| ((y >>> 32).setWidth 8).setWidth 64 <<< 32)
      ||| ((y >>> 40).setWidth 8).setWidth 64 <<< 40)
      ||| ((y >>> 48).setWidth 8).setWidth 64 <<< 48)
      ||| ((y >>> 56).setWidth 8).setWidth 64 <<< 56) = y := by bits64

/-- The eight bytes `u64L` writes read back as the value they came from. -/
theorem u64of_lo8 (y : Std.U64) :
    u64of (lo8 y.bv) (lo8 (y.bv >>> 8)) (lo8 (y.bv >>> 16)) (lo8 (y.bv >>> 24))
      (lo8 (y.bv >>> 32)) (lo8 (y.bv >>> 40)) (lo8 (y.bv >>> 48)) (lo8 (y.bv >>> 56)) = y := by
  apply U64.bv_eq_imp_eq
  exact u64of_bv y.bv

/-- A sixty-four-bit immediate survives the trip through `u64`. -/
theorem hcast64_roundtrip (d : Std.I64) :
    (UScalar.hcast (src_ty := .U64) .I64 (IScalar.hcast (src_ty := .I64) .U64 d)) = d := by
  apply I64.bv_eq_imp_eq
  simp

/-- A sixty-four-bit immediate written as four bytes reads back as its low half. -/
theorem hcast32of64 (d : Std.I64) :
    (UScalar.hcast (src_ty := .U32) .I32 (IScalar.hcast (src_ty := .I64) .U32 d))
      = IScalar.cast .I32 d := by
  apply I32.bv_eq_imp_eq
  simp only [UScalar.hcast, IScalar.hcast, IScalar.cast]
  show BitVec.zeroExtend 32 (BitVec.signExtend 32 d.bv) = BitVec.signExtend 32 d.bv
  bits32

/-- A shift count written as one byte reads back truncated. -/
theorem sxB_hcast8 (d : Std.I32) : sxB (IScalar.hcast .U8 d) = d &&& 255#i32 := by
  apply I32.bv_eq_imp_eq
  simp only [sxB, UScalar.hcast, IScalar.hcast]
  show BitVec.zeroExtend 32 (BitVec.signExtend 8 d.bv) = d.bv &&& 255#32
  rw [BitVec.signExtend_eq_setWidth_of_le _ (by omega)]
  bits32

/-- Indexing past a legacy prefix byte and an optional REX prefix. -/
theorem get_cons_after (a : Std.U8) (L T : List Std.U8) (j : Nat) :
    (a :: (L ++ T))[1 + L.length + j]! = T[j]! := by
  rw [show 1 + L.length + j = (L.length + j) + 1 from by omega]
  simp only [List.getElem!_cons_succ]
  exact get_after L T j

/-! ## Opcode bytes that carry a register

`50+r`, `58+r`, `b8+r`, `0f c8+r` and `ff d0+r` fold the register's low three
bits into the opcode byte; `70+c` and `0f 40+c` fold a condition code's low
four. Each of these is a fact about all two hundred and fifty-six bytes. -/

theorem or80_facts (r : Std.U8) :
    notPfx (80#u8 ||| (r &&& 7#u8)) ∧ (80#u8 ||| (r &&& 7#u8)) ≠ 15#u8 ∧
      80 ≤ (80#u8 ||| (r &&& 7#u8)).val ∧ (80#u8 ||| (r &&& 7#u8)).val ≤ 87 ∧
      (80#u8 ||| (r &&& 7#u8)) &&& 7#u8 = r &&& 7#u8 :=
  u8_cases (P := fun r => notPfx (80#u8 ||| (r &&& 7#u8)) ∧ (80#u8 ||| (r &&& 7#u8)) ≠ 15#u8 ∧
      80 ≤ (80#u8 ||| (r &&& 7#u8)).val ∧ (80#u8 ||| (r &&& 7#u8)).val ≤ 87 ∧
      (80#u8 ||| (r &&& 7#u8)) &&& 7#u8 = r &&& 7#u8) (by decide) r

theorem or88_facts (r : Std.U8) :
    notPfx (88#u8 ||| (r &&& 7#u8)) ∧ (88#u8 ||| (r &&& 7#u8)) ≠ 15#u8 ∧
      80 ≤ (88#u8 ||| (r &&& 7#u8)).val ∧ (88#u8 ||| (r &&& 7#u8)).val ≤ 95 ∧
      ¬ ((88#u8 ||| (r &&& 7#u8)).val ≤ 87) ∧
      (88#u8 ||| (r &&& 7#u8)) &&& 7#u8 = r &&& 7#u8 :=
  u8_cases (P := fun r => notPfx (88#u8 ||| (r &&& 7#u8)) ∧ (88#u8 ||| (r &&& 7#u8)) ≠ 15#u8 ∧
      80 ≤ (88#u8 ||| (r &&& 7#u8)).val ∧ (88#u8 ||| (r &&& 7#u8)).val ≤ 95 ∧
      ¬ ((88#u8 ||| (r &&& 7#u8)).val ≤ 87) ∧
      (88#u8 ||| (r &&& 7#u8)) &&& 7#u8 = r &&& 7#u8) (by decide) r

/-! ## The opcode dispatch, where the seventeen did not reach -/

theorem decode_one_byte_push {bytes : Slice Std.U8} {pos : Usize} {p : x64_decode.Pfx}
    {op : Std.U8} {z : Usize} (h1 : 80 ≤ op.val) (h2 : op.val ≤ 87)
    (hz : p.at + 1#usize = ok z) :
    x64_decode.decode_one_byte bytes pos p op =
      x64_decode.finish (x64_ir.PInsn.Push ((op &&& 7#u8) ||| shlU p.b 3)) pos z 0#i64 := by
  unfold x64_decode.decode_one_byte
  simp only [ge_iff_le, UScalar.le_equiv]
  rw [if_pos (by scalar_tac : (80#u8).val ≤ op.val)]
  rw [if_pos (by scalar_tac : op.val ≤ (95#u8).val)]
  simp only [lift, shlU3, bind_tc_ok]
  rw [if_pos (by scalar_tac : op.val ≤ (87#u8).val)]
  rw [hz]
  simp only [bind_tc_ok]

theorem decode_one_byte_pop {bytes : Slice Std.U8} {pos : Usize} {p : x64_decode.Pfx}
    {op : Std.U8} {z : Usize} (h1 : 80 ≤ op.val) (h2 : op.val ≤ 95)
    (h3 : ¬ (op.val ≤ 87)) (hz : p.at + 1#usize = ok z) :
    x64_decode.decode_one_byte bytes pos p op =
      x64_decode.finish (x64_ir.PInsn.Pop ((op &&& 7#u8) ||| shlU p.b 3)) pos z 0#i64 := by
  unfold x64_decode.decode_one_byte
  simp only [ge_iff_le, UScalar.le_equiv]
  rw [if_pos (by scalar_tac : (80#u8).val ≤ op.val)]
  rw [if_pos (by scalar_tac : op.val ≤ (95#u8).val)]
  simp only [lift, shlU3, bind_tc_ok]
  rw [if_neg (by scalar_tac : ¬ (op.val ≤ (87#u8).val))]
  rw [hz]
  simp only [bind_tc_ok]

/-! ## Push and pop -/

theorem dec_push (r : Std.U8) (hr : r.val < 16) : DecodesTo (.Push r) := by
  intro bytes pos pre hb hat hfit
  obtain ⟨hnp, hne15, hlo, hhi, hand7⟩ := or80_facts r
  have hbs : enc (x64_ir.PInsn.Push r) = basicRexL 0#u8 0#u8 r ++ [80#u8 ||| (r &&& 7#u8)] := rfl
  rw [hbs] at hb
  set L := basicRexL 0#u8 0#u8 r with hL
  set T := [80#u8 ||| (r &&& 7#u8)] with hT
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hlen : (L ++ T).length = L.length + 1 := by simp [hT]
  have g0 : (L ++ T)[L.length + 0]! = 80#u8 ||| (r &&& 7#u8) := by rw [get_after]; simp [hT]
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex hb hat (by omega) (by simp [hT])
      (by rw [hT]; simpa using hnp) (hL ▸ basicRexL_case 0#u8 0#u8 r (by decide))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB (80#u8 ||| (r &&& 7#u8))) := by
    rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Push r) (disp := 0#i64)
      (pos := pos) (e := z1) (n := L.length + 1) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Push r, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock hne15]
    rw [decode_one_byte_push hlo hhi hz1]
    rw [hand7, hqb, reg_rejoin r hr]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

theorem dec_pop (r : Std.U8) (hr : r.val < 16) : DecodesTo (.Pop r) := by
  intro bytes pos pre hb hat hfit
  obtain ⟨hnp, hne15, hlo, hhi, hgt, hand7⟩ := or88_facts r
  have hbs : enc (x64_ir.PInsn.Pop r) = basicRexL 0#u8 0#u8 r ++ [88#u8 ||| (r &&& 7#u8)] := rfl
  rw [hbs] at hb
  set L := basicRexL 0#u8 0#u8 r with hL
  set T := [88#u8 ||| (r &&& 7#u8)] with hT
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hlen : (L ++ T).length = L.length + 1 := by simp [hT]
  have g0 : (L ++ T)[L.length + 0]! = 88#u8 ||| (r &&& 7#u8) := by rw [get_after]; simp [hT]
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex hb hat (by omega) (by simp [hT])
      (by rw [hT]; simpa using hnp) (hL ▸ basicRexL_case 0#u8 0#u8 r (by decide))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB (88#u8 ||| (r &&& 7#u8))) := by
    rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Pop r) (disp := 0#i64)
      (pos := pos) (e := z1) (n := L.length + 1) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Pop r, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock hne15]
    rw [decode_one_byte_pop hlo hhi hgt hz1]
    rw [hand7, hqb, reg_rejoin r hr]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

/-! ## The immediate ALU forms

`AluImm` spreads over three opcode bytes: `81 /ext` for the six arithmetic
operations, `c7 /0` for `Mov` — which it shares with a `LoadImm` that fits —
and `f7 /0` for `Test`. -/

theorem is_rip_of_byte {bytes : Slice Std.U8} {i : Usize} {c : Std.U8}
    (h : x64_decode.byte_at bytes i = ok (sxB c)) :
    x64_decode.is_rip bytes i = ok (decide (c &&& 199#u8 = 5#u8)) := by
  unfold x64_decode.is_rip
  rw [h]
  simp only [bind_tc_ok, lift]
  rw [if_pos (sxB_nonneg _)]
  simp only [sxB_back]

theorem decode_one_byte_aluImm81 {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    {op : x64_ir.AluRI} {reg rm ext : Std.U8} {v : Std.U32} {z1 z2 z6 : Usize}
    (hop : aluRIOp op = 129#u8)
    (hknown : x64_decode.is_alu_ri_ext ext = ok true)
    (hof : x64_decode.alu_ri_of ext = ok op)
    (hz1 : q.at + 1#usize = ok z1)
    (hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := true, reg := reg, rm := rm, ext := ext })
    (hz2 : q.at + 2#usize = ok z2)
    (hroom : x64_decode.have bytes z2 4#usize = ok true)
    (hread : x64_decode.read32 bytes z2 = ok v)
    (hz6 : q.at + 6#usize = ok z6) :
    x64_decode.decode_one_byte bytes pos q (aluRIOp op) =
      x64_decode.finish (x64_ir.PInsn.AluImm (q.w = 1#u8) op rm (UScalar.hcast .I32 v))
        pos z6 0#i64 := by
  rw [hop]
  rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
  rw [show x64_decode.alu_op 129#u8 = ok false from rfl]
  simp only [bind_tc_ok, reduceIte, reduceCtorEq]
  norm_num [x64_decode.decode_rest]
  simp only [hz1, hg, hknown, hz2, hroom, hread, hof, hz6, bind_tc_ok, lift, if_true]

theorem decode_one_byte_aluImmC7 {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    {reg rm c0 c1 : Std.U8} {v : Std.U32} {z1 z2 z6 : Usize}
    (hz1 : q.at + 1#usize = ok z1)
    (hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := true, reg := reg, rm := rm, ext := 0#u8 })
    (hmod : x64_decode.byte_at bytes z1 = ok (sxB c0))
    (hsib : x64_decode.byte_at bytes z2 = ok (sxB c1))
    (hz2 : q.at + 2#usize = ok z2)
    (hroom : x64_decode.have bytes z2 4#usize = ok true)
    (hread : x64_decode.read32 bytes z2 = ok v)
    (hz6 : q.at + 6#usize = ok z6) :
    x64_decode.decode_one_byte bytes pos q 199#u8 =
      x64_decode.finish (x64_ir.PInsn.AluImm (q.w = 1#u8) x64_ir.AluRI.Mov rm
        (UScalar.hcast .I32 v)) pos z6 0#i64 := by
  rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
  rw [show x64_decode.alu_op 199#u8 = ok false from rfl]
  simp only [bind_tc_ok, reduceIte, reduceCtorEq]
  norm_num [x64_decode.decode_move]
  simp only [hz1, hz2, is_rip_of_byte hmod, hroom, bind_tc_ok]
  norm_num [x64_decode.decode_store_imm]
  simp only [hz1, hg, hmod, hz2, hsib, hroom, hread, hz6, bind_tc_ok, lift, if_true]

theorem decode_one_byte_aluImmF7 {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    {reg rm : Std.U8} {v : Std.U32} {z1 z2 z6 : Usize}
    (hz1 : q.at + 1#usize = ok z1)
    (hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := true, reg := reg, rm := rm, ext := 0#u8 })
    (hz2 : q.at + 2#usize = ok z2)
    (hroom : x64_decode.have bytes z2 4#usize = ok true)
    (hread : x64_decode.read32 bytes z2 = ok v)
    (hz6 : q.at + 6#usize = ok z6) :
    x64_decode.decode_one_byte bytes pos q 247#u8 =
      x64_decode.finish (x64_ir.PInsn.AluImm (q.w = 1#u8) x64_ir.AluRI.Test rm
        (UScalar.hcast .I32 v)) pos z6 0#i64 := by
  rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
  rw [show x64_decode.alu_op 247#u8 = ok false from rfl]
  simp only [bind_tc_ok, reduceIte, reduceCtorEq]
  norm_num [x64_decode.decode_rest]
  unfold x64_decode.decode_unary
  simp only [hz1, hg, hz2, hroom, hread, hz6, bind_tc_ok, lift, if_true]

theorem dec_aluImm (w64 : Bool) (op : x64_ir.AluRI) (dst : Std.U8) (imm : Std.I32)
    (hdst : dst.val < 16) : DecodesTo (.AluImm w64 op dst imm) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.AluImm w64 op dst imm)
      = basicRexL (bitU w64) (aluRIExt op) dst
        ++ ([aluRIOp op, modrmB 192#u8 (aluRIExt op) dst]
            ++ u32L (IScalar.hcast .U32 imm)) := by
    show aluL w64 (aluRIOp op) (aluRIExt op) dst ++ u32L (IScalar.hcast .U32 imm) = _
    simp only [aluL, List.append_assoc]
  rw [hbs] at hb
  set L := basicRexL (bitU w64) (aluRIExt op) dst with hL
  set T := [aluRIOp op, modrmB 192#u8 (aluRIExt op) dst] ++ u32L (IScalar.hcast .U32 imm) with hT
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hlen : (L ++ T).length = L.length + 6 := by simp [hT, u32L]
  have g0 : (L ++ T)[L.length + 0]! = aluRIOp op := by rw [get_after]; simp [hT]
  have g1 : (L ++ T)[L.length + 1]! = modrmB 192#u8 (aluRIExt op) dst := by
    rw [get_after]; simp [hT]
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex hb hat (by omega) (by simp [hT, u32L])
      (by rw [hT]; simp only [List.cons_append, List.getElem!_cons_zero]; cases op <;> decide)
      (hL ▸ basicRexL_case (bitU w64) (aluRIExt op) dst (bitU_le _))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB (aluRIOp op)) := by
    rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT, u32L])
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
  obtain ⟨z6, hz6, hz6v0⟩ := usize_add_ok (x := q.at) (y := 6#usize) (by simp; omega)
  have hz6v : z6.val = pre.length + (L.length + 6) := by simp at hz6v0; omega
  have hmod : x64_decode.byte_at bytes z1 = ok (sxB (modrmB 192#u8 (aluRIExt op) dst)) := by
    rw [← g1]; exact byte_at_in (k := L.length + 1) hb (by omega) (by simp [hT, u32L])
  have hsib : x64_decode.byte_at bytes z2 = ok (sxB (L ++ T)[L.length + 2]!) :=
    byte_at_in (k := L.length + 2) hb (by omega) (by simp [hT, u32L])
  have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := true, reg := mReg (modrmB 192#u8 (aluRIExt op) dst) q.r, rm := dst,
           ext := aluRIExt op } := by
    have h := decode_reg2_eq (k := L.length + 1) (rex_r := q.r) (rex_b := q.b) hb (by omega)
      (by simp [hT, u32L]) (by rw [g1, modrmB_and192]; decide)
    rw [g1] at h
    rw [h, mExt_modrmB, mRm_modrmB _ _ _ _ hdst hqb,
      show aluRIExt op &&& 7#u8 = aluRIExt op from by cases op <;> decide]
  have hroom : x64_decode.have bytes z2 4#usize = ok true := by
    rw [have_at (k := L.length + 2) hb (by omega) (by simp; omega), hlen]
    simp
  have hread : x64_decode.read32 bytes z2 = ok (IScalar.hcast .U32 imm) := by
    rw [read32_at (k := L.length + 2) hb (by omega) (by rw [hlen]) (by omega)]
    rw [show (L ++ T)[L.length + 2]! = lo8 (IScalar.hcast (src_ty := .I32) .U32 imm).bv from by
        rw [get_after]; simp [hT, u32L],
      show (L ++ T)[L.length + 3]! = lo8 ((IScalar.hcast (src_ty := .I32) .U32 imm).bv >>> 8) from by
        rw [get_after]; simp [hT, u32L],
      show (L ++ T)[L.length + 4]! = lo8 ((IScalar.hcast (src_ty := .I32) .U32 imm).bv >>> 16) from by
        rw [get_after]; simp [hT, u32L],
      show (L ++ T)[L.length + 5]! = lo8 ((IScalar.hcast (src_ty := .I32) .U32 imm).bv >>> 24) from by
        rw [get_after]; simp [hT, u32L]]
    rw [u32of_lo8]
  have hknown : x64_decode.is_alu_ri_ext (aluRIExt op) = ok true := by cases op <;> rfl
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.AluImm w64 op dst imm) (disp := 0#i64)
      (pos := pos) (e := z6) (n := L.length + 6) (by omega)
  have hstep : x64_decode.decode_one_byte bytes pos q (aluRIOp op) =
      x64_decode.finish (x64_ir.PInsn.AluImm (q.w = 1#u8) op dst
        (UScalar.hcast .I32 (IScalar.hcast (src_ty := .I32) .U32 imm))) pos z6 0#i64 := by
    cases op <;> first
      | exact decode_one_byte_aluImm81 rfl hknown rfl hz1 hg hz2 hroom hread hz6
      | exact decode_one_byte_aluImmC7 hz1 hg hmod hsib hz2 hroom hread hz6
      | exact decode_one_byte_aluImmF7 hz1 hg hz2 hroom hread hz6
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.AluImm w64 op dst imm, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by cases op <;> decide)]
    rw [hstep, hqw, bitU_eq_one, hcast32_roundtrip]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

/-! ## The shifts by an immediate, and the sixteen-bit byte swap

Both are `c1`; the `66` prefix is what tells them apart. -/

theorem dec_shiftImm (w64 : Bool) (op : x64_ir.ShiftOp) (dst : Std.U8) (imm : Std.I32)
    (hdst : dst.val < 16) : DecodesTo (.ShiftImm w64 op dst imm) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.ShiftImm w64 op dst imm)
      = basicRexL (bitU w64) (shiftExtU op) dst
        ++ ([193#u8, modrmB 192#u8 (shiftExtU op) dst] ++ [IScalar.hcast .U8 imm]) := by
    show aluL w64 193#u8 (shiftExtU op) dst ++ [IScalar.hcast .U8 imm] = _
    simp only [aluL, List.append_assoc]
  rw [hbs] at hb
  set L := basicRexL (bitU w64) (shiftExtU op) dst with hL
  set T := [193#u8, modrmB 192#u8 (shiftExtU op) dst] ++ [IScalar.hcast .U8 imm] with hT
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hlen : (L ++ T).length = L.length + 3 := by simp [hT]
  have g0 : (L ++ T)[L.length + 0]! = 193#u8 := by rw [get_after]; simp [hT]
  have g1 : (L ++ T)[L.length + 1]! = modrmB 192#u8 (shiftExtU op) dst := by
    rw [get_after]; simp [hT]
  have g2 : (L ++ T)[L.length + 2]! = IScalar.hcast .U8 imm := by rw [get_after]; simp [hT]
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex hb hat (by omega) (by simp [hT])
      (by rw [hT]; simp only [List.cons_append, List.getElem!_cons_zero]; decide)
      (hL ▸ basicRexL_case (bitU w64) (shiftExtU op) dst (bitU_le _))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 193#u8) := by
    rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := q.at) (y := 3#usize) (by simp; omega)
  have hz3v : z3.val = pre.length + (L.length + 3) := by simp at hz3v0; omega
  have hbimm : x64_decode.byte_at bytes z2 = ok (sxB (IScalar.hcast .U8 imm)) := by
    rw [← g2]; exact byte_at_in (k := L.length + 2) hb (by omega) (by simp [hT])
  have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := true, reg := mReg (modrmB 192#u8 (shiftExtU op) dst) q.r, rm := dst,
           ext := shiftExtU op } := by
    have h := decode_reg2_eq (k := L.length + 1) (rex_r := q.r) (rex_b := q.b) hb (by omega)
      (by simp [hT]) (by rw [g1, modrmB_and192]; decide)
    rw [g1] at h
    rw [h, mExt_modrmB, mRm_modrmB _ _ _ _ hdst hqb,
      show shiftExtU op &&& 7#u8 = shiftExtU op from by cases op <;> decide]
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.ShiftImm w64 op dst (imm &&& 255#i32)) (disp := 0#i64)
      (pos := pos) (e := z3) (n := L.length + 3) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.ShiftImm w64 op dst (imm &&& 255#i32), len := ln,
                 disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 193#u8 = ok false from rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    unfold x64_decode.decode_shift
    simp only [hz1, hg, hz2, hbimm, bind_tc_ok, if_true]
    rw [if_neg (sxB_nonneg' _), ho16, if_neg (by simp)]
    rw [show x64_decode.is_shift_ext (shiftExtU op) = ok true from by cases op <;> rfl]
    simp only [bind_tc_ok, if_true]
    rw [show x64_decode.shift_of (shiftExtU op) = ok op from by cases op <;> rfl]
    simp only [hz3, bind_tc_ok]
    rw [hqw, bitU_eq_one, sxB_hcast8]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

theorem dec_rol16 (dst : Std.U8) (hdst : dst.val < 16) : DecodesTo (.Rol16 dst) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.Rol16 dst)
      = 102#u8 :: (basicRexL (bitU false) 0#u8 dst
        ++ ([193#u8, modrmB 192#u8 0#u8 dst] ++ [8#u8])) := by
    show 102#u8 :: (aluL false 193#u8 0#u8 dst ++ [8#u8]) = _
    simp only [aluL, List.append_assoc]
  rw [hbs] at hb
  set L := basicRexL (bitU false) 0#u8 dst with hL
  set T := [193#u8, modrmB 192#u8 0#u8 dst] ++ [8#u8] with hT
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hlen : (102#u8 :: (L ++ T)).length = 1 + L.length + 3 := by simp [hT]; omega
  have t0 : T[0]! = 193#u8 := by simp [hT]
  have t1 : T[1]! = modrmB 192#u8 0#u8 dst := by simp [hT]
  have t2 : T[2]! = 8#u8 := by simp [hT]
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_pfx_opt_rex (rexl := L) (rest := T) hb hat (by omega) (Or.inr (Or.inl rfl))
      (by simp [hT]) (by rw [t0]; decide)
      (hL ▸ basicRexL_case (bitU false) 0#u8 dst (by decide))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 193#u8) := by
    have h : x64_decode.byte_at bytes q.at
        = ok (sxB (102#u8 :: (L ++ T))[1 + L.length + 0]!) :=
      byte_at_in (pre := pre) (bs := 102#u8 :: (L ++ T)) (k := 1 + L.length + 0)
        hb (by omega) (by simp [hT]; omega)
    rw [h, get_cons_after, t0]
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (1 + L.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (1 + L.length + 2) := by simp at hz2v0; omega
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := q.at) (y := 3#usize) (by simp; omega)
  have hz3v : z3.val = pre.length + (1 + L.length + 3) := by simp at hz3v0; omega
  have hbimm : x64_decode.byte_at bytes z2 = ok (sxB 8#u8) := by
    have h : x64_decode.byte_at bytes z2
        = ok (sxB (102#u8 :: (L ++ T))[1 + L.length + 2]!) :=
      byte_at_in (pre := pre) (bs := 102#u8 :: (L ++ T)) (k := 1 + L.length + 2)
        hb (by omega) (by simp [hT]; omega)
    rw [h, get_cons_after, t2]
  have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := true, reg := mReg (modrmB 192#u8 0#u8 dst) q.r, rm := dst, ext := 0#u8 } := by
    have h := decode_reg2_eq (bytes := bytes) («at» := z1) (pre := pre)
      (bs := 102#u8 :: (L ++ T)) (k := 1 + L.length + 1) (rex_r := q.r) (rex_b := q.b)
      hb (by omega) (by simp [hT]; omega)
      (by rw [get_cons_after, t1, modrmB_and192]; decide)
    rw [get_cons_after, t1] at h
    rw [h, mExt_modrmB, mRm_modrmB _ _ _ _ hdst hqb,
      show (0#u8 : Std.U8) &&& 7#u8 = 0#u8 from by decide]
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Rol16 dst) (disp := 0#i64)
      (pos := pos) (e := z3) (n := 1 + L.length + 3) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Rol16 dst, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 (by rw [hlock]; decide) (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 193#u8 = ok false from rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    unfold x64_decode.decode_shift
    simp only [hz1, hg, hz2, hbimm, bind_tc_ok, if_true]
    rw [if_neg (sxB_nonneg' _), ho16, if_pos (by decide)]
    rw [if_pos (show sxB 8#u8 = 8#i32 from by simp only [sxB]; decide)]
    simp only [hz3, bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

/-! ## Comparing a byte the decoder sign-extended against a literal -/

theorem sxB_ge' {c : Std.U8} {m : Std.I32} (h : m.val ≤ (c.val : Int)) : sxB c ≥ m := by
  rw [ge_iff_le, IScalar.le_equiv, sxB_val]; exact h

theorem sxB_le' {c : Std.U8} {m : Std.I32} (h : (c.val : Int) ≤ m.val) : sxB c ≤ m := by
  rw [IScalar.le_equiv, sxB_val]; exact h

theorem sxB_nge' {c : Std.U8} {m : Std.I32} (h : (c.val : Int) < m.val) : ¬ (sxB c ≥ m) := by
  rw [ge_iff_le, IScalar.le_equiv, sxB_val]; omega

theorem sxB_nle' {c : Std.U8} {m : Std.I32} (h : m.val < (c.val : Int)) : ¬ (sxB c ≤ m) := by
  rw [IScalar.le_equiv, sxB_val]; omega

theorem sxB_ne' {c : Std.U8} {m : Std.I32} (h : (c.val : Int) ≠ m.val) : sxB c ≠ m := by
  intro hh
  exact h (by rw [← sxB_val]; exact congrArg IScalar.val hh)

/-! ## The `0f`-escaped opcodes -/

theorem decode_two_byte_bswap {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    {c : Std.U8} {z1 z2 : Usize}
    (hz1 : q.at + 1#usize = ok z1) (hsec : x64_decode.byte_at bytes z1 = ok (sxB c))
    (h1 : 200 ≤ c.val) (h2 : c.val ≤ 207) (hz2 : q.at + 2#usize = ok z2) :
    x64_decode.decode_two_byte bytes pos q =
      x64_decode.finish (x64_ir.PInsn.Bswap (q.w = 1#u8) ((c &&& 7#u8) ||| shlU q.b 3))
        pos z2 0#i64 := by
  unfold x64_decode.decode_two_byte
  simp only [hz1, hsec, bind_tc_ok]
  rw [if_neg (sxB_nonneg' _), if_neg (sxB_ne' (by simp; omega)),
    if_pos (sxB_ge' (by simp; omega)), if_neg (sxB_nle' (by simp; omega)),
    if_pos (sxB_ge' (by simp; omega)), if_neg (sxB_nle' (by simp; omega)),
    if_pos (sxB_ge' (by simp; omega)), if_pos (sxB_le' (by simp; omega))]
  simp only [lift, sxB_back, shlU3, hz2, bind_tc_ok]

theorem decode_two_byte_cmov {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    {c reg rm ext : Std.U8} {z1 z2 z3 : Usize}
    (hz1 : q.at + 1#usize = ok z1) (hsec : x64_decode.byte_at bytes z1 = ok (sxB c))
    (h1 : 64 ≤ c.val) (h2 : c.val ≤ 79) (hz2 : q.at + 2#usize = ok z2)
    (hg : x64_decode.decode_reg2 bytes z2 q.r q.b =
      ok { ok := true, reg := reg, rm := rm, ext := ext })
    (hz3 : q.at + 3#usize = ok z3) :
    x64_decode.decode_two_byte bytes pos q =
      x64_decode.finish (x64_ir.PInsn.Cmov (128#u8 ||| (c &&& 15#u8)) reg rm)
        pos z3 0#i64 := by
  unfold x64_decode.decode_two_byte
  simp only [hz1, hsec, bind_tc_ok]
  rw [if_neg (sxB_nonneg' _), if_neg (sxB_ne' (by simp; omega)),
    if_pos (sxB_ge' (by simp; omega)), if_pos (sxB_le' (by simp; omega))]
  simp only [hz2, hg, lift, sxB_back, hz3, bind_tc_ok, if_true]

theorem decode_two_byte_jcc {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    {c : Std.U8} {z1 z2 z6 : Usize} {v : Std.U32}
    (hz1 : q.at + 1#usize = ok z1) (hsec : x64_decode.byte_at bytes z1 = ok (sxB c))
    (h1 : 128 ≤ c.val) (h2 : c.val ≤ 143) (hz2 : q.at + 2#usize = ok z2)
    (hroom : x64_decode.have bytes z2 4#usize = ok true)
    (hread : x64_decode.read32 bytes z2 = ok v) (hsx : x64_decode.sx32 v = ok 0#i64)
    (hz6 : q.at + 6#usize = ok z6) :
    x64_decode.decode_two_byte bytes pos q =
      x64_decode.finish (x64_ir.PInsn.Jcc c (x64_ir.PTarget.Local 0#u32)) pos z6 0#i64 := by
  unfold x64_decode.decode_two_byte
  simp only [hz1, hsec, bind_tc_ok]
  rw [if_neg (sxB_nonneg' _), if_neg (sxB_ne' (by simp; omega)),
    if_pos (sxB_ge' (by simp; omega)), if_neg (sxB_nle' (by simp; omega)),
    if_pos (sxB_ge' (by simp; omega)), if_pos (sxB_le' (by simp; omega))]
  simp only [hz2, hroom, hread, hsx, lift, sxB_back, hz6, bind_tc_ok, if_true]

/-! ## The byte swap, the conditional move and the long conditional branch -/

theorem or200_facts (r : Std.U8) :
    (200#u8 ||| (r &&& 7#u8)) &&& 7#u8 = r &&& 7#u8 ∧
      200 ≤ (200#u8 ||| (r &&& 7#u8)).val ∧ (200#u8 ||| (r &&& 7#u8)).val ≤ 207 :=
  u8_cases (P := fun r => (200#u8 ||| (r &&& 7#u8)) &&& 7#u8 = r &&& 7#u8 ∧
      200 ≤ (200#u8 ||| (r &&& 7#u8)).val ∧ (200#u8 ||| (r &&& 7#u8)).val ≤ 207)
    (by decide) r

theorem or64cc_facts (cc : Std.U8) (h1 : 128 ≤ cc.val) (h2 : cc.val ≤ 143) :
    128#u8 ||| ((64#u8 ||| (cc &&& 15#u8)) &&& 15#u8) = cc ∧
      64 ≤ (64#u8 ||| (cc &&& 15#u8)).val ∧ (64#u8 ||| (cc &&& 15#u8)).val ≤ 79 :=
  u8_cases (P := fun cc => 128 ≤ cc.val → cc.val ≤ 143 →
      (128#u8 ||| ((64#u8 ||| (cc &&& 15#u8)) &&& 15#u8) = cc ∧
        64 ≤ (64#u8 ||| (cc &&& 15#u8)).val ∧ (64#u8 ||| (cc &&& 15#u8)).val ≤ 79))
    (by decide) cc h1 h2

theorem dec_bswap (w64 : Bool) (dst : Std.U8) (hdst : dst.val < 16) :
    DecodesTo (.Bswap w64 dst) := by
  intro bytes pos pre hb hat hfit
  obtain ⟨hand7, hlo, hhi⟩ := or200_facts dst
  have hbs : enc (x64_ir.PInsn.Bswap w64 dst)
      = basicRexL (bitU w64) 0#u8 dst ++ [15#u8, 200#u8 ||| (dst &&& 7#u8)] := rfl
  rw [hbs] at hb
  set L := basicRexL (bitU w64) 0#u8 dst with hL
  set T := [15#u8, 200#u8 ||| (dst &&& 7#u8)] with hT
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hlen : (L ++ T).length = L.length + 2 := by simp [hT]
  have g0 : (L ++ T)[L.length + 0]! = 15#u8 := by rw [get_after]; simp [hT]
  have g1 : (L ++ T)[L.length + 1]! = 200#u8 ||| (dst &&& 7#u8) := by rw [get_after]; simp [hT]
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex hb hat (by omega) (by simp [hT])
      (by rw [hT]; simp only [List.getElem!_cons_zero]; decide)
      (hL ▸ basicRexL_case (bitU w64) 0#u8 dst (bitU_le _))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 15#u8) := by
    rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
  have hsec : x64_decode.byte_at bytes z1 = ok (sxB (200#u8 ||| (dst &&& 7#u8))) := by
    rw [← g1]; exact byte_at_in (k := L.length + 1) hb (by omega) (by simp [hT])
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Bswap w64 dst) (disp := 0#i64)
      (pos := pos) (e := z2) (n := L.length + 2) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Bswap w64 dst, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_0f hb0 hlock]
    rw [decode_two_byte_bswap hz1 hsec hlo hhi hz2]
    rw [hand7, hqb, reg_rejoin dst hdst, hqw, bitU_eq_one]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

theorem dec_cmov (cc dst src : Std.U8) (hcc : 128 ≤ cc.val ∧ cc.val ≤ 143)
    (hdst : dst.val < 16) (hsrc : src.val < 16) : DecodesTo (.Cmov cc dst src) := by
  intro bytes pos pre hb hat hfit
  obtain ⟨hcclo, hcchi⟩ := hcc
  obtain ⟨hccback, hlo, hhi⟩ := or64cc_facts cc hcclo hcchi
  have hbs : enc (x64_ir.PInsn.Cmov cc dst src)
      = basicRexL 1#u8 dst src ++ [15#u8, 64#u8 ||| (cc &&& 15#u8), modrmB 192#u8 dst src] := rfl
  rw [hbs] at hb
  set L := basicRexL 1#u8 dst src with hL
  set T := [15#u8, 64#u8 ||| (cc &&& 15#u8), modrmB 192#u8 dst src] with hT
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hlen : (L ++ T).length = L.length + 3 := by simp [hT]
  have g0 : (L ++ T)[L.length + 0]! = 15#u8 := by rw [get_after]; simp [hT]
  have g1 : (L ++ T)[L.length + 1]! = 64#u8 ||| (cc &&& 15#u8) := by rw [get_after]; simp [hT]
  have g2 : (L ++ T)[L.length + 2]! = modrmB 192#u8 dst src := by rw [get_after]; simp [hT]
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex hb hat (by omega) (by simp [hT])
      (by rw [hT]; simp only [List.getElem!_cons_zero]; decide)
      (hL ▸ basicRexL_case 1#u8 dst src (by decide))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 15#u8) := by
    rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := q.at) (y := 3#usize) (by simp; omega)
  have hz3v : z3.val = pre.length + (L.length + 3) := by simp at hz3v0; omega
  have hsec : x64_decode.byte_at bytes z1 = ok (sxB (64#u8 ||| (cc &&& 15#u8))) := by
    rw [← g1]; exact byte_at_in (k := L.length + 1) hb (by omega) (by simp [hT])
  have hg : x64_decode.decode_reg2 bytes z2 q.r q.b =
      ok { ok := true, reg := dst, rm := src, ext := mExt (modrmB 192#u8 dst src) } := by
    have h := decode_reg2_eq (k := L.length + 2) (rex_r := q.r) (rex_b := q.b) hb (by omega)
      (by simp [hT]) (by rw [g2, modrmB_and192]; decide)
    rw [g2] at h
    rw [h, mReg_modrmB _ _ _ _ hdst hqr, mRm_modrmB _ _ _ _ hsrc hqb]
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Cmov cc dst src) (disp := 0#i64)
      (pos := pos) (e := z3) (n := L.length + 3) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Cmov cc dst src, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_0f hb0 hlock]
    rw [decode_two_byte_cmov hz1 hsec hlo hhi hz2 hg hz3]
    rw [hccback]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

theorem dec_jcc (cc : Std.U8) (t : x64_ir.PTarget) (hcc : 128 ≤ cc.val ∧ cc.val ≤ 143) :
    DecodesTo (.Jcc cc t) := by
  intro bytes pos pre hb hat hfit
  obtain ⟨hcclo, hcchi⟩ := hcc
  have hbs : enc (x64_ir.PInsn.Jcc cc t) = 15#u8 :: cc :: u32L 0#u32 := rfl
  have hu : u32L 0#u32 = [0#u8, 0#u8, 0#u8, 0#u8] := by decide
  rw [hbs, hu] at hb
  set B := 15#u8 :: cc :: [0#u8, 0#u8, 0#u8, 0#u8] with hB
  have hlen : B.length = 6 := by simp [hB]
  have hq := prefixes_plain hb hat (by simp [hB]) (by rw [hB]; simp only [List.getElem!_cons_zero]; decide)
  have hb0 : x64_decode.byte_at bytes pos = ok (sxB 15#u8) := by
    have h : x64_decode.byte_at bytes pos = ok (sxB B[0]!) :=
      byte_at_in (k := 0) hb (by omega) (by simp [hB])
    rwa [show B[0]! = 15#u8 from by simp [hB]] at h
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pos.val + 1 := by simpa using hz1v0
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := pos) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pos.val + 2 := by simpa using hz2v0
  obtain ⟨z6, hz6, hz6v0⟩ := usize_add_ok (x := pos) (y := 6#usize) (by simp; omega)
  have hz6v : z6.val = pos.val + 6 := by simpa using hz6v0
  have hsec : x64_decode.byte_at bytes z1 = ok (sxB cc) := by
    have h : x64_decode.byte_at bytes z1 = ok (sxB B[1]!) :=
      byte_at_in (k := 1) hb (by omega) (by simp [hB])
    rwa [show B[1]! = cc from by simp [hB]] at h
  have hroom : x64_decode.have bytes z2 4#usize = ok true := by
    rw [have_at (k := 2) hb (by omega) (by simp; omega), hlen]
    simp
  have hread : x64_decode.read32 bytes z2 = ok (u32of 0#u8 0#u8 0#u8 0#u8) := by
    rw [read32_at (k := 2) hb (by omega) (by rw [hlen]) (by omega)]
    simp only [hB, List.getElem!_cons_succ, List.getElem!_cons_zero]
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Jcc cc (x64_ir.PTarget.Local 0#u32)) (disp := 0#i64)
      (pos := pos) (e := z6) (n := 6) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Jcc cc (x64_ir.PTarget.Local 0#u32), len := ln,
                 disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_0f hb0 rfl]
    rw [decode_two_byte_jcc hz1 hsec hcclo hcchi hz2 hroom hread sx32_zero hz6]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hu, hlen.symm], rfl⟩

/-! ## The multiply and divide by RCX -/

theorem dec_mulDivRcx (w64 : Bool) (kind : x64_ir.MulDivKind) (signed : Bool) :
    DecodesTo (.MulDivRcx w64 kind signed) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.MulDivRcx w64 kind signed)
      = (if w64 then [rexByte 1#u8 0#u8 0#u8 0#u8] else [])
        ++ [247#u8, modrmB 192#u8 (muldivExtU kind signed) 1#u8] := by
    show muldivRcxL w64 kind signed = _
    unfold muldivRcxL aluL
    rw [show basicRexL (bitU false) (muldivExtU kind signed) 1#u8 = [] from by
      cases kind <;> cases signed <;> decide]
    simp only [List.nil_append]
  rw [hbs] at hb
  set L := (if w64 then [rexByte 1#u8 0#u8 0#u8 0#u8] else []) with hL
  set T := [247#u8, modrmB 192#u8 (muldivExtU kind signed) 1#u8] with hT
  have hrl : L.length ≤ 1 := by rw [hL]; cases w64 <;> simp
  have hlen : (L ++ T).length = L.length + 2 := by simp [hT]
  have g0 : (L ++ T)[L.length + 0]! = 247#u8 := by rw [get_after]; simp [hT]
  have g1 : (L ++ T)[L.length + 1]! = modrmB 192#u8 (muldivExtU kind signed) 1#u8 := by
    rw [get_after]; simp [hT]
  have hcase : RexCase L (bitU w64) 0#u8 0#u8 := by
    unfold RexCase
    cases w64
    · exact Or.inl ⟨by rw [hL]; simp, rfl, rfl, rfl⟩
    · exact Or.inr ⟨rexByte 1#u8 0#u8 0#u8 0#u8, by rw [hL]; simp, by decide, by decide,
        by decide, by decide, by decide⟩
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex hb hat (by omega) (by simp [hT])
      (by rw [hT]; simp only [List.getElem!_cons_zero]; decide) hcase
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 247#u8) := by
    rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
  have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := true, reg := mReg (modrmB 192#u8 (muldivExtU kind signed) 1#u8) q.r,
           rm := 1#u8, ext := muldivExtU kind signed } := by
    have h := decode_reg2_eq (k := L.length + 1) (rex_r := q.r) (rex_b := q.b) hb (by omega)
      (by simp [hT]) (by rw [g1, modrmB_and192]; decide)
    rw [g1] at h
    rw [h, mExt_modrmB, mRm_modrmB _ _ _ _ (by decide) (by rw [hqb]; decide),
      show muldivExtU kind signed &&& 7#u8 = muldivExtU kind signed from by
        cases kind <;> cases signed <;> decide]
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := shape (x64_ir.PInsn.MulDivRcx w64 kind signed)) (disp := 0#i64)
      (pos := pos) (e := z2) (n := L.length + 2) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := shape (x64_ir.PInsn.MulDivRcx w64 kind signed), len := ln,
                 disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 247#u8 = ok false from rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    unfold x64_decode.decode_unary
    simp only [hz1, hg, hz2, bind_tc_ok, if_true]
    rw [hqw, bitU_eq_one]
    cases kind <;> cases signed <;>
      simp only [muldivExtU, shape, if_true, if_false, bne_self_eq_false,
        Bool.false_eq_true] <;>
      exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

/-! ## The short conditional branch and the indirect call -/

theorem or112_facts (cc : Std.U8) (h1 : 128 ≤ cc.val) (h2 : cc.val ≤ 143) :
    notPfx (112#u8 ||| (cc &&& 15#u8)) ∧ (112#u8 ||| (cc &&& 15#u8)) ≠ 15#u8 ∧
      112 ≤ (112#u8 ||| (cc &&& 15#u8)).val ∧ (112#u8 ||| (cc &&& 15#u8)).val ≤ 127 ∧
      128#u8 ||| ((112#u8 ||| (cc &&& 15#u8)) &&& 15#u8) = cc :=
  u8_cases (P := fun cc => 128 ≤ cc.val → cc.val ≤ 143 →
      (notPfx (112#u8 ||| (cc &&& 15#u8)) ∧ (112#u8 ||| (cc &&& 15#u8)) ≠ 15#u8 ∧
        112 ≤ (112#u8 ||| (cc &&& 15#u8)).val ∧ (112#u8 ||| (cc &&& 15#u8)).val ≤ 127 ∧
        128#u8 ||| ((112#u8 ||| (cc &&& 15#u8)) &&& 15#u8) = cc)) (by decide) cc h1 h2

theorem decode_one_byte_jcc8 {bytes : Slice Std.U8} {pos : Usize} {p : x64_decode.Pfx}
    {op c : Std.U8} {z1 z2 : Usize} (h1 : 112 ≤ op.val) (h2 : op.val ≤ 127)
    (hz1 : p.at + 1#usize = ok z1) (hd : x64_decode.byte_at bytes z1 = ok (sxB c))
    (hz2 : p.at + 2#usize = ok z2) (hsx : x64_decode.sx8 (sxB c) = ok 0#i64) :
    x64_decode.decode_one_byte bytes pos p op =
      x64_decode.finish (x64_ir.PInsn.Jcc8 (128#u8 ||| (op &&& 15#u8)) 0#u32) pos z2 0#i64 := by
  unfold x64_decode.decode_one_byte
  simp only [ge_iff_le, UScalar.le_equiv]
  rw [if_pos (by scalar_tac : (80#u8).val ≤ op.val)]
  rw [if_neg (by scalar_tac : ¬ (op.val ≤ (95#u8).val))]
  rw [if_pos (by scalar_tac : (112#u8).val ≤ op.val)]
  rw [if_pos (by scalar_tac : op.val ≤ (127#u8).val)]
  simp only [hz1, hd, bind_tc_ok]
  rw [if_neg (sxB_nonneg' _)]
  simp only [lift, hz2, hsx, bind_tc_ok]

theorem dec_jcc8 (cc : Std.U8) (n : Std.U32) (hcc : 128 ≤ cc.val ∧ cc.val ≤ 143) :
    DecodesTo (.Jcc8 cc n) := by
  intro bytes pos pre hb hat hfit
  obtain ⟨hcclo, hcchi⟩ := hcc
  obtain ⟨hnp, hne15, hlo, hhi, hback⟩ := or112_facts cc hcclo hcchi
  have hbs : enc (x64_ir.PInsn.Jcc8 cc n) = [112#u8 ||| (cc &&& 15#u8), 0#u8] := rfl
  rw [hbs] at hb
  set B := [112#u8 ||| (cc &&& 15#u8), 0#u8] with hB
  have hq := prefixes_plain hb hat (by simp [hB])
    (by rw [hB]; simp only [List.getElem!_cons_zero]; exact hnp)
  have hb0 : x64_decode.byte_at bytes pos = ok (sxB (112#u8 ||| (cc &&& 15#u8))) := by
    have h : x64_decode.byte_at bytes pos = ok (sxB B[0]!) :=
      byte_at_in (k := 0) hb (by omega) (by simp [hB])
    rwa [show B[0]! = 112#u8 ||| (cc &&& 15#u8) from by simp [hB]] at h
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pos.val + 1 := by simpa using hz1v0
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := pos) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pos.val + 2 := by simpa using hz2v0
  have hd : x64_decode.byte_at bytes z1 = ok (sxB 0#u8) := by
    have h : x64_decode.byte_at bytes z1 = ok (sxB B[1]!) :=
      byte_at_in (k := 1) hb (by omega) (by simp [hB])
    rwa [show B[1]! = 0#u8 from by simp [hB]] at h
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Jcc8 cc 0#u32) (disp := 0#i64)
      (pos := pos) (e := z2) (n := 2) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Jcc8 cc 0#u32, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 rfl hne15]
    rw [decode_one_byte_jcc8 hlo hhi hz1 hd hz2 sx8_zero, hback]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs]; simp [hB], rfl⟩

theorem or208_facts (r : Std.U8) :
    (208#u8 ||| (r &&& 7#u8)) &&& 248#u8 = 208#u8 ∧
      (208#u8 ||| (r &&& 7#u8)) &&& 7#u8 = r &&& 7#u8 :=
  u8_cases (P := fun r => (208#u8 ||| (r &&& 7#u8)) &&& 248#u8 = 208#u8 ∧
      (208#u8 ||| (r &&& 7#u8)) &&& 7#u8 = r &&& 7#u8) (by decide) r

theorem callRegL_rex (r : Std.U8) :
    (if r &&& 8#u8 != 0#u8 then [65#u8] else []) = basicRexL 0#u8 0#u8 r :=
  u8_cases (P := fun r => (if r &&& 8#u8 != 0#u8 then [65#u8] else []) = basicRexL 0#u8 0#u8 r)
    (by decide) r

theorem dec_callReg (reg : Std.U8) (hreg : reg.val < 16) : DecodesTo (.CallReg reg) := by
  intro bytes pos pre hb hat hfit
  obtain ⟨hand248, hand7⟩ := or208_facts reg
  have hbs : enc (x64_ir.PInsn.CallReg reg)
      = basicRexL 0#u8 0#u8 reg ++ [255#u8, 208#u8 ||| (reg &&& 7#u8)] := by
    show callRegL reg = _
    unfold callRegL
    rw [callRegL_rex]
  rw [hbs] at hb
  set L := basicRexL 0#u8 0#u8 reg with hL
  set T := [255#u8, 208#u8 ||| (reg &&& 7#u8)] with hT
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hlen : (L ++ T).length = L.length + 2 := by simp [hT]
  have g0 : (L ++ T)[L.length + 0]! = 255#u8 := by rw [get_after]; simp [hT]
  have g1 : (L ++ T)[L.length + 1]! = 208#u8 ||| (reg &&& 7#u8) := by rw [get_after]; simp [hT]
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex hb hat (by omega) (by simp [hT])
      (by rw [hT]; simp only [List.getElem!_cons_zero]; decide)
      (hL ▸ basicRexL_case 0#u8 0#u8 reg (by decide))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 255#u8) := by
    rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
  have hhead : x64_decode.byte_at bytes z1 = ok (sxB (208#u8 ||| (reg &&& 7#u8))) := by
    rw [← g1]; exact byte_at_in (k := L.length + 1) hb (by omega) (by simp [hT])
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.CallReg reg) (disp := 0#i64)
      (pos := pos) (e := z2) (n := L.length + 2) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.CallReg reg, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 255#u8 = ok false from rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    simp only [hz1, hhead, bind_tc_ok, lift, sxB_back]
    rw [if_pos (show (0 : Int) ≤ (sxB (208#u8 ||| (reg &&& 7#u8))).val from by
      rw [sxB_val]; omega)]
    rw [hand248, if_pos rfl, hand7]
    simp only [shlU3, hz2, bind_tc_ok]
    rw [hqb, reg_rejoin reg hreg]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

/-! ## Loading an immediate

The immediate that fits in thirty-two bits is the same bytes as an
`AluImm … Mov`, and reads back as that; the wide one is `b8+r`. -/

theorem or184_facts (r : Std.U8) :
    notPfx (184#u8 ||| (r &&& 7#u8)) ∧ (184#u8 ||| (r &&& 7#u8)) ≠ 15#u8 ∧
      184 ≤ (184#u8 ||| (r &&& 7#u8)).val ∧ (184#u8 ||| (r &&& 7#u8)).val ≤ 191 ∧
      (184#u8 ||| (r &&& 7#u8)) &&& 7#u8 = r &&& 7#u8 :=
  u8_cases (P := fun r => notPfx (184#u8 ||| (r &&& 7#u8)) ∧ (184#u8 ||| (r &&& 7#u8)) ≠ 15#u8 ∧
      184 ≤ (184#u8 ||| (r &&& 7#u8)).val ∧ (184#u8 ||| (r &&& 7#u8)).val ≤ 191 ∧
      (184#u8 ||| (r &&& 7#u8)) &&& 7#u8 = r &&& 7#u8) (by decide) r

theorem decode_one_byte_loadImm {bytes : Slice Std.U8} {pos : Usize} {p : x64_decode.Pfx}
    {op : Std.U8} {v : Std.U64} {z1 z9 : Usize}
    (h1 : 184 ≤ op.val) (h2 : op.val ≤ 191) (hw : p.w = 1#u8)
    (hz1 : p.at + 1#usize = ok z1)
    (hroom : x64_decode.have bytes z1 8#usize = ok true)
    (hread : x64_decode.read64 bytes z1 = ok v)
    (hz9 : p.at + 9#usize = ok z9) :
    x64_decode.decode_one_byte bytes pos p op =
      x64_decode.finish (x64_ir.PInsn.LoadImm ((op &&& 7#u8) ||| shlU p.b 3)
        (UScalar.hcast .I64 v)) pos z9 0#i64 := by
  unfold x64_decode.decode_one_byte
  simp only [ge_iff_le, UScalar.le_equiv]
  rw [if_pos (by scalar_tac : (80#u8).val ≤ op.val)]
  rw [if_neg (by scalar_tac : ¬ (op.val ≤ (95#u8).val))]
  rw [if_pos (by scalar_tac : (112#u8).val ≤ op.val)]
  rw [if_neg (by scalar_tac : ¬ (op.val ≤ (127#u8).val))]
  rw [if_pos (by scalar_tac : (184#u8).val ≤ op.val)]
  rw [if_pos (by scalar_tac : op.val ≤ (191#u8).val)]
  simp only [hz1, hroom, hw, bind_tc_ok, if_true, lift, shlU3, hread, hz9]

theorem dec_loadImm (dst : Std.U8) (imm : Std.I64) (hdst : dst.val < 16) :
    DecodesTo (.LoadImm dst imm) := by
  intro bytes pos pre hb hat hfit
  by_cases hfits : immFits32B imm = true
  · -- the immediate that fits in thirty-two bits: the `c7 /0` form
    have hbs : enc (x64_ir.PInsn.LoadImm dst imm)
        = basicRexL (bitU true) 0#u8 dst
          ++ ([199#u8, modrmB 192#u8 0#u8 dst] ++ u32L (IScalar.hcast .U32 imm)) := by
      show loadImmL dst imm = _
      unfold loadImmL
      rw [if_pos hfits]
      simp only [aluL, List.append_assoc]
    rw [hbs] at hb
    set L := basicRexL (bitU true) 0#u8 dst with hL
    set T := [199#u8, modrmB 192#u8 0#u8 dst] ++ u32L (IScalar.hcast .U32 imm) with hT
    have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
    have hlen : (L ++ T).length = L.length + 6 := by simp [hT, u32L]
    have g0 : (L ++ T)[L.length + 0]! = 199#u8 := by rw [get_after]; simp [hT]
    have g1 : (L ++ T)[L.length + 1]! = modrmB 192#u8 0#u8 dst := by rw [get_after]; simp [hT]
    obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
      prefixes_opt_rex hb hat (by omega) (by simp [hT, u32L])
        (by rw [hT]; simp only [List.cons_append, List.getElem!_cons_zero]; decide)
        (hL ▸ basicRexL_case (bitU true) 0#u8 dst (by decide))
    have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 199#u8) := by
      rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT, u32L])
    obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
    have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
    obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
    have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
    obtain ⟨z6, hz6, hz6v0⟩ := usize_add_ok (x := q.at) (y := 6#usize) (by simp; omega)
    have hz6v : z6.val = pre.length + (L.length + 6) := by simp at hz6v0; omega
    have hmod : x64_decode.byte_at bytes z1 = ok (sxB (modrmB 192#u8 0#u8 dst)) := by
      rw [← g1]; exact byte_at_in (k := L.length + 1) hb (by omega) (by simp [hT, u32L])
    have hsib : x64_decode.byte_at bytes z2 = ok (sxB (L ++ T)[L.length + 2]!) :=
      byte_at_in (k := L.length + 2) hb (by omega) (by simp [hT, u32L])
    have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
        ok { ok := true, reg := mReg (modrmB 192#u8 0#u8 dst) q.r, rm := dst, ext := 0#u8 } := by
      have h := decode_reg2_eq (k := L.length + 1) (rex_r := q.r) (rex_b := q.b) hb (by omega)
        (by simp [hT, u32L]) (by rw [g1, modrmB_and192]; decide)
      rw [g1] at h
      rw [h, mExt_modrmB, mRm_modrmB _ _ _ _ hdst hqb,
        show (0#u8 : Std.U8) &&& 7#u8 = 0#u8 from by decide]
    have hroom : x64_decode.have bytes z2 4#usize = ok true := by
      rw [have_at (k := L.length + 2) hb (by omega) (by simp; omega), hlen]
      simp
    have hread : x64_decode.read32 bytes z2 = ok (IScalar.hcast .U32 imm) := by
      rw [read32_at (k := L.length + 2) hb (by omega) (by rw [hlen]) (by omega)]
      rw [show (L ++ T)[L.length + 2]! = lo8 (IScalar.hcast (src_ty := .I64) .U32 imm).bv from by
          rw [get_after]; simp [hT, u32L],
        show (L ++ T)[L.length + 3]!
            = lo8 ((IScalar.hcast (src_ty := .I64) .U32 imm).bv >>> 8) from by
          rw [get_after]; simp [hT, u32L],
        show (L ++ T)[L.length + 4]!
            = lo8 ((IScalar.hcast (src_ty := .I64) .U32 imm).bv >>> 16) from by
          rw [get_after]; simp [hT, u32L],
        show (L ++ T)[L.length + 5]!
            = lo8 ((IScalar.hcast (src_ty := .I64) .U32 imm).bv >>> 24) from by
          rw [get_after]; simp [hT, u32L]]
      rw [u32of_lo8]
    obtain ⟨ln, hln, hfin⟩ :=
      finish_spec (insn := x64_ir.PInsn.AluImm true x64_ir.AluRI.Mov dst (IScalar.cast .I32 imm))
        (disp := 0#i64) (pos := pos) (e := z6) (n := L.length + 6) (by omega)
    have hres : x64_decode.decode_one bytes pos =
        ok (some { insn := x64_ir.PInsn.AluImm true x64_ir.AluRI.Mov dst (IScalar.cast .I32 imm),
                   len := ln, disp := 0#i64 }) := by
      refine decode_one_eq hq ?_
      rw [decode_insn_plain hb0 hlock (by decide)]
      rw [decode_one_byte_aluImmC7 hz1 hg hmod hsib hz2 hroom hread hz6]
      rw [hqw, bitU_eq_one, hcast32of64]
      exact hfin
    refine ⟨_, hres, ?_, by rw [hln, hbs, hlen], rfl⟩
    show _ = shape (x64_ir.PInsn.LoadImm dst imm)
    simp only [shape]
    rw [if_pos hfits]
  · -- the wide immediate: `b8+r`
    simp only [Bool.not_eq_true] at hfits
    obtain ⟨hnp, hne15, hlo, hhi, hand7⟩ := or184_facts dst
    have hbs : enc (x64_ir.PInsn.LoadImm dst imm)
        = basicRexL 1#u8 0#u8 dst
          ++ ([184#u8 ||| (dst &&& 7#u8)] ++ u64L (IScalar.hcast .U64 imm)) := by
      show loadImmL dst imm = _
      unfold loadImmL
      rw [if_neg (by simp [hfits])]
      simp only [List.append_assoc]
    rw [hbs] at hb
    set L := basicRexL 1#u8 0#u8 dst with hL
    set T := [184#u8 ||| (dst &&& 7#u8)] ++ u64L (IScalar.hcast .U64 imm) with hT
    have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
    have hlen : (L ++ T).length = L.length + 9 := by simp [hT, u64L]
    have g0 : (L ++ T)[L.length + 0]! = 184#u8 ||| (dst &&& 7#u8) := by
      rw [get_after]; simp [hT]
    obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
      prefixes_opt_rex hb hat (by omega) (by simp [hT, u64L])
        (by rw [hT]; simp only [List.cons_append, List.getElem!_cons_zero]; exact hnp)
        (hL ▸ basicRexL_case 1#u8 0#u8 dst (by decide))
    have hb0 : x64_decode.byte_at bytes q.at = ok (sxB (184#u8 ||| (dst &&& 7#u8))) := by
      rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT, u64L])
    obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
    have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
    obtain ⟨z9, hz9, hz9v0⟩ := usize_add_ok (x := q.at) (y := 9#usize) (by simp; omega)
    have hz9v : z9.val = pre.length + (L.length + 9) := by simp at hz9v0; omega
    have hroom : x64_decode.have bytes z1 8#usize = ok true := by
      rw [have_at (k := L.length + 1) hb (by omega) (by simp; omega), hlen]
      simp
    have hread : x64_decode.read64 bytes z1 = ok (IScalar.hcast .U64 imm) := by
      rw [read64_at (k := L.length + 1) hb (by omega) (by rw [hlen]) (by omega)]
      rw [show (L ++ T)[L.length + 1]! = lo8 (IScalar.hcast (src_ty := .I64) .U64 imm).bv from by
          rw [get_after]; simp [hT, u64L],
        show (L ++ T)[L.length + 2]!
            = lo8 ((IScalar.hcast (src_ty := .I64) .U64 imm).bv >>> 8) from by
          rw [get_after]; simp [hT, u64L],
        show (L ++ T)[L.length + 3]!
            = lo8 ((IScalar.hcast (src_ty := .I64) .U64 imm).bv >>> 16) from by
          rw [get_after]; simp [hT, u64L],
        show (L ++ T)[L.length + 4]!
            = lo8 ((IScalar.hcast (src_ty := .I64) .U64 imm).bv >>> 24) from by
          rw [get_after]; simp [hT, u64L],
        show (L ++ T)[L.length + 5]!
            = lo8 ((IScalar.hcast (src_ty := .I64) .U64 imm).bv >>> 32) from by
          rw [get_after]; simp [hT, u64L],
        show (L ++ T)[L.length + 6]!
            = lo8 ((IScalar.hcast (src_ty := .I64) .U64 imm).bv >>> 40) from by
          rw [get_after]; simp [hT, u64L],
        show (L ++ T)[L.length + 7]!
            = lo8 ((IScalar.hcast (src_ty := .I64) .U64 imm).bv >>> 48) from by
          rw [get_after]; simp [hT, u64L],
        show (L ++ T)[L.length + 8]!
            = lo8 ((IScalar.hcast (src_ty := .I64) .U64 imm).bv >>> 56) from by
          rw [get_after]; simp [hT, u64L]]
      rw [u64of_lo8]
    obtain ⟨ln, hln, hfin⟩ :=
      finish_spec (insn := x64_ir.PInsn.LoadImm dst imm) (disp := 0#i64)
        (pos := pos) (e := z9) (n := L.length + 9) (by omega)
    have hres : x64_decode.decode_one bytes pos =
        ok (some { insn := x64_ir.PInsn.LoadImm dst imm, len := ln, disp := 0#i64 }) := by
      refine decode_one_eq hq ?_
      rw [decode_insn_plain hb0 hlock hne15]
      rw [decode_one_byte_loadImm hlo hhi hqw hz1 hroom hread hz9]
      rw [hand7, hqb, reg_rejoin dst hdst, hcast64_roundtrip]
      exact hfin
    refine ⟨_, hres, ?_, by rw [hln, hbs, hlen], rfl⟩
    show _ = shape (x64_ir.PInsn.LoadImm dst imm)
    simp only [shape]
    rw [if_neg (by simp [hfits])]

/-! ## The sign-extending moves

`MovSx` is `63 /r` from thirty-two bits and `0f be` / `0f bf` from eight and
sixteen; the eight-bit form always writes a REX prefix, so that the byte
registers it names are the uniform ones. -/

theorem rexCase_single (w r b : Std.U8) (hw : w.val ≤ 1) (hr : r.val ≤ 1) (hb : b.val ≤ 1) :
    RexCase [rexByte w r 0#u8 b] w r b :=
  Or.inr ⟨_, rfl, (rexByte_range w r 0#u8 b hw hr (by decide) hb).1,
    (rexByte_range w r 0#u8 b hw hr (by decide) hb).2,
    pfxW_rexByte _ _ _ _ hw hr (by decide) hb,
    pfxR_rexByte _ _ _ _ hw hr (by decide) hb,
    pfxB_rexByte _ _ _ _ hw hr (by decide) hb⟩

theorem movsx_rexCase (w64 : Bool) (src dst : Std.U8) :
    RexCase (if w64 then [rexByte (bitU true) (highU dst) 0#u8 (highU src)]
             else basicRexL 0#u8 dst src) (bitU w64) (highU dst) (highU src) := by
  cases w64
  · rw [if_neg (by simp)]
    exact basicRexL_case 0#u8 dst src (by decide)
  · rw [if_pos (by simp)]
    exact rexCase_single (bitU true) (highU dst) (highU src) (by decide) (highU_le _)
      (highU_le _)

theorem movsx_rexLen (w64 : Bool) (src dst : Std.U8) :
    (if w64 then [rexByte (bitU true) (highU dst) 0#u8 (highU src)]
     else basicRexL 0#u8 dst src).length ≤ 1 := by
  cases w64
  · rw [if_neg (by simp)]; exact basicRexL_length_le _ _ _
  · rw [if_pos (by simp)]; simp

theorem decode_two_byte_movsx8 {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    {reg rm ext : Std.U8} {z1 z2 z3 : Usize}
    (hz1 : q.at + 1#usize = ok z1) (hsec : x64_decode.byte_at bytes z1 = ok (sxB 190#u8))
    (hz2 : q.at + 2#usize = ok z2)
    (hg : x64_decode.decode_reg2 bytes z2 q.r q.b =
      ok { ok := true, reg := reg, rm := rm, ext := ext })
    (hz3 : q.at + 3#usize = ok z3) :
    x64_decode.decode_two_byte bytes pos q =
      x64_decode.finish (x64_ir.PInsn.MovSx 8#u8 (q.w = 1#u8) rm reg) pos z3 0#i64 := by
  unfold x64_decode.decode_two_byte
  simp only [hz1, hsec, bind_tc_ok]
  rw [if_neg (sxB_nonneg' _), if_neg (sxB_ne' (by decide)), if_pos (sxB_ge' (by decide)),
    if_neg (sxB_nle' (by decide)), if_pos (sxB_ge' (by decide)),
    if_neg (sxB_nle' (by decide)), if_neg (sxB_nge' (by decide)),
    if_neg (sxB_ne' (by decide)), if_neg (sxB_ne' (by decide)),
    if_pos (show sxB 190#u8 = 190#i32 from by simp only [sxB]; decide)]
  simp only [hz2, hg, hz3, bind_tc_ok, if_true]
  rw [if_pos (show sxB 190#u8 = 190#i32 from by simp only [sxB]; decide),
    if_pos (show sxB 190#u8 = 190#i32 from by simp only [sxB]; decide)]
  simp only [bind_tc_ok]

theorem decode_two_byte_movsx16 {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    {reg rm ext : Std.U8} {z1 z2 z3 : Usize}
    (hz1 : q.at + 1#usize = ok z1) (hsec : x64_decode.byte_at bytes z1 = ok (sxB 191#u8))
    (hz2 : q.at + 2#usize = ok z2)
    (hg : x64_decode.decode_reg2 bytes z2 q.r q.b =
      ok { ok := true, reg := reg, rm := rm, ext := ext })
    (hz3 : q.at + 3#usize = ok z3) :
    x64_decode.decode_two_byte bytes pos q =
      x64_decode.finish (x64_ir.PInsn.MovSx 16#u8 (q.w = 1#u8) rm reg) pos z3 0#i64 := by
  unfold x64_decode.decode_two_byte
  simp only [hz1, hsec, bind_tc_ok]
  rw [if_neg (sxB_nonneg' _), if_neg (sxB_ne' (by decide)), if_pos (sxB_ge' (by decide)),
    if_neg (sxB_nle' (by decide)), if_pos (sxB_ge' (by decide)),
    if_neg (sxB_nle' (by decide)), if_neg (sxB_nge' (by decide)),
    if_neg (sxB_ne' (by decide)), if_neg (sxB_ne' (by decide)),
    if_neg (sxB_ne' (by decide)),
    if_pos (show sxB 191#u8 = 191#i32 from by simp only [sxB]; decide)]
  simp only [hz2, hg, hz3, bind_tc_ok, if_true]
  rw [if_neg (sxB_ne' (by decide)), if_neg (sxB_ne' (by decide))]
  simp only [bind_tc_ok]

theorem dec_movSx (from_ : Std.U8) (w64 : Bool) (src dst : Std.U8)
    (hfrom : from_ = 8#u8 ∨ from_ = 16#u8 ∨ from_ = 32#u8)
    (hsrc : src.val < 16) (hdst : dst.val < 16) : DecodesTo (.MovSx from_ w64 src dst) := by
  rcases hfrom with rfl | rfl | rfl
  · -- from eight bits: `0f be /r`, always behind a REX prefix
    intro bytes pos pre hb hat hfit
    have hbs : enc (x64_ir.PInsn.MovSx 8#u8 w64 src dst)
        = [rexByte (bitU w64) (highU dst) 0#u8 (highU src)]
          ++ [15#u8, 190#u8, modrmB 192#u8 dst src] := by
      show movsxL 8#u8 w64 src dst = _
      cases w64 <;> simp [movsxL]
    rw [hbs] at hb
    set L := [rexByte (bitU w64) (highU dst) 0#u8 (highU src)] with hL
    set T := [15#u8, 190#u8, modrmB 192#u8 dst src] with hT
    have hrl : L.length ≤ 1 := by rw [hL]; simp
    have hlen : (L ++ T).length = L.length + 3 := by simp [hT]
    have g0 : (L ++ T)[L.length + 0]! = 15#u8 := by rw [get_after]; simp [hT]
    have g1 : (L ++ T)[L.length + 1]! = 190#u8 := by rw [get_after]; simp [hT]
    have g2 : (L ++ T)[L.length + 2]! = modrmB 192#u8 dst src := by rw [get_after]; simp [hT]
    obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
      prefixes_opt_rex hb hat (by omega) (by simp [hT])
        (by rw [hT]; simp only [List.getElem!_cons_zero]; decide)
        (hL ▸ rexCase_single (bitU w64) (highU dst) (highU src) (bitU_le _) (highU_le _)
          (highU_le _))
    have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 15#u8) := by
      rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
    obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
    have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
    obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
    have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
    obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := q.at) (y := 3#usize) (by simp; omega)
    have hz3v : z3.val = pre.length + (L.length + 3) := by simp at hz3v0; omega
    have hsec : x64_decode.byte_at bytes z1 = ok (sxB 190#u8) := by
      rw [← g1]; exact byte_at_in (k := L.length + 1) hb (by omega) (by simp [hT])
    have hg : x64_decode.decode_reg2 bytes z2 q.r q.b =
        ok { ok := true, reg := dst, rm := src, ext := mExt (modrmB 192#u8 dst src) } := by
      have h := decode_reg2_eq (k := L.length + 2) (rex_r := q.r) (rex_b := q.b) hb (by omega)
        (by simp [hT]) (by rw [g2, modrmB_and192]; decide)
      rw [g2] at h
      rw [h, mReg_modrmB _ _ _ _ hdst hqr, mRm_modrmB _ _ _ _ hsrc hqb]
    obtain ⟨ln, hln, hfin⟩ :=
      finish_spec (insn := x64_ir.PInsn.MovSx 8#u8 w64 src dst) (disp := 0#i64)
        (pos := pos) (e := z3) (n := L.length + 3) (by omega)
    have hres : x64_decode.decode_one bytes pos =
        ok (some { insn := x64_ir.PInsn.MovSx 8#u8 w64 src dst, len := ln, disp := 0#i64 }) := by
      refine decode_one_eq hq ?_
      rw [decode_insn_0f hb0 hlock]
      rw [decode_two_byte_movsx8 hz1 hsec hz2 hg hz3, hqw, bitU_eq_one]
      exact hfin
    exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩
  · -- from sixteen bits: `0f bf /r`
    intro bytes pos pre hb hat hfit
    have hbs : enc (x64_ir.PInsn.MovSx 16#u8 w64 src dst)
        = (if w64 then [rexByte (bitU true) (highU dst) 0#u8 (highU src)]
           else basicRexL 0#u8 dst src)
          ++ [15#u8, 191#u8, modrmB 192#u8 dst src] := by
      show movsxL 16#u8 w64 src dst = _
      cases w64 <;> simp [movsxL]
    rw [hbs] at hb
    set L := (if w64 then [rexByte (bitU true) (highU dst) 0#u8 (highU src)]
              else basicRexL 0#u8 dst src) with hL
    set T := [15#u8, 191#u8, modrmB 192#u8 dst src] with hT
    have hrl : L.length ≤ 1 := hL ▸ movsx_rexLen w64 src dst
    have hlen : (L ++ T).length = L.length + 3 := by simp [hT]
    have g0 : (L ++ T)[L.length + 0]! = 15#u8 := by rw [get_after]; simp [hT]
    have g1 : (L ++ T)[L.length + 1]! = 191#u8 := by rw [get_after]; simp [hT]
    have g2 : (L ++ T)[L.length + 2]! = modrmB 192#u8 dst src := by rw [get_after]; simp [hT]
    obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
      prefixes_opt_rex hb hat (by omega) (by simp [hT])
        (by rw [hT]; simp only [List.getElem!_cons_zero]; decide)
        (hL ▸ movsx_rexCase w64 src dst)
    have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 15#u8) := by
      rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
    obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
    have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
    obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
    have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
    obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := q.at) (y := 3#usize) (by simp; omega)
    have hz3v : z3.val = pre.length + (L.length + 3) := by simp at hz3v0; omega
    have hsec : x64_decode.byte_at bytes z1 = ok (sxB 191#u8) := by
      rw [← g1]; exact byte_at_in (k := L.length + 1) hb (by omega) (by simp [hT])
    have hg : x64_decode.decode_reg2 bytes z2 q.r q.b =
        ok { ok := true, reg := dst, rm := src, ext := mExt (modrmB 192#u8 dst src) } := by
      have h := decode_reg2_eq (k := L.length + 2) (rex_r := q.r) (rex_b := q.b) hb (by omega)
        (by simp [hT]) (by rw [g2, modrmB_and192]; decide)
      rw [g2] at h
      rw [h, mReg_modrmB _ _ _ _ hdst hqr, mRm_modrmB _ _ _ _ hsrc hqb]
    obtain ⟨ln, hln, hfin⟩ :=
      finish_spec (insn := x64_ir.PInsn.MovSx 16#u8 w64 src dst) (disp := 0#i64)
        (pos := pos) (e := z3) (n := L.length + 3) (by omega)
    have hres : x64_decode.decode_one bytes pos =
        ok (some { insn := x64_ir.PInsn.MovSx 16#u8 w64 src dst, len := ln, disp := 0#i64 }) := by
      refine decode_one_eq hq ?_
      rw [decode_insn_0f hb0 hlock]
      rw [decode_two_byte_movsx16 hz1 hsec hz2 hg hz3, hqw, bitU_eq_one]
      exact hfin
    exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩
  · -- from thirty-two bits: `63 /r`
    intro bytes pos pre hb hat hfit
    have hbs : enc (x64_ir.PInsn.MovSx 32#u8 w64 src dst)
        = (if w64 then [rexByte (bitU true) (highU dst) 0#u8 (highU src)]
           else basicRexL 0#u8 dst src)
          ++ [99#u8, modrmB 192#u8 dst src] := by
      show movsxL 32#u8 w64 src dst = _
      cases w64 <;> simp [movsxL]
    rw [hbs] at hb
    set L := (if w64 then [rexByte (bitU true) (highU dst) 0#u8 (highU src)]
              else basicRexL 0#u8 dst src) with hL
    set T := [99#u8, modrmB 192#u8 dst src] with hT
    have hrl : L.length ≤ 1 := hL ▸ movsx_rexLen w64 src dst
    have hlen : (L ++ T).length = L.length + 2 := by simp [hT]
    have g0 : (L ++ T)[L.length + 0]! = 99#u8 := by rw [get_after]; simp [hT]
    have g1 : (L ++ T)[L.length + 1]! = modrmB 192#u8 dst src := by rw [get_after]; simp [hT]
    obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
      prefixes_opt_rex hb hat (by omega) (by simp [hT])
        (by rw [hT]; simp only [List.getElem!_cons_zero]; decide)
        (hL ▸ movsx_rexCase w64 src dst)
    have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 99#u8) := by
      rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
    obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
    have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
    obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
    have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
    have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
        ok { ok := true, reg := dst, rm := src, ext := mExt (modrmB 192#u8 dst src) } := by
      have h := decode_reg2_eq (k := L.length + 1) (rex_r := q.r) (rex_b := q.b) hb (by omega)
        (by simp [hT]) (by rw [g1, modrmB_and192]; decide)
      rw [g1] at h
      rw [h, mReg_modrmB _ _ _ _ hdst hqr, mRm_modrmB _ _ _ _ hsrc hqb]
    obtain ⟨ln, hln, hfin⟩ :=
      finish_spec (insn := x64_ir.PInsn.MovSx 32#u8 w64 src dst) (disp := 0#i64)
        (pos := pos) (e := z2) (n := L.length + 2) (by omega)
    have hres : x64_decode.decode_one bytes pos =
        ok (some { insn := x64_ir.PInsn.MovSx 32#u8 w64 src dst, len := ln, disp := 0#i64 }) := by
      refine decode_one_eq hq ?_
      rw [decode_insn_plain hb0 hlock (by decide)]
      rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
      rw [show x64_decode.alu_op 99#u8 = ok false from rfl]
      simp only [bind_tc_ok, reduceIte, reduceCtorEq]
      norm_num [x64_decode.decode_rest]
      simp only [hz1, hg, hz2, bind_tc_ok, if_true]
      rw [hqw, bitU_eq_one]
      exact hfin
    exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

end X64Enc
end async_ebpf_verified

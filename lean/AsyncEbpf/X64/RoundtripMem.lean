import AsyncEbpf.X64.Assemble

/-!
# The memory forms, checked against the decoder

`AsyncEbpf/X64/Assemble.lean` states `DecodesTo p` — the bytes the encoder
appends for `p`, read back at the offset it appended them, give `p`'s shape,
its length and the placeholder displacement zero — and proves it for seventeen
variant families, `LockAlu` among them, over machinery that covers every ModRM
and displacement form the encoder writes. This file adds the twelve families
that reach memory or the trailer, over that same machinery: `decode_mem_eq`,
the prefix lemmas, `decode_reg2_ne` and `finish_spec`.

`dec_load`, `dec_store`, `dec_storeImm`, `dec_aluRM`, `dec_storeRspImm`,
`dec_storeRspRax`, `dec_lockCmpxchg`, `dec_xchg`, `dec_ripLoadDispatcher`,
`dec_ripLeaHelperTable`, `dec_dispatcherSlot` and `dec_helperTable`, each with
every operand symbolic — every base and destination register among the sixteen,
every displacement, every immediate, and every width the encoder writes — under
exactly the `RegsBounded` side conditions.

Two of the collisions `shape` records are here. A narrow `StoreImm` keeps only
as many bytes of its immediate as its width, so it reads back truncated; and
the RIP-relative load has no REX.R bit to carry a high destination, so
`RipLoadDispatcher dst` reads back as `RipLoadDispatcher (dst &&& 7)`.

Two of the twelve are not instructions at all: `DispatcherSlot` and
`HelperTable` are the trailer's data, and the decoder reads them as a last
resort, after every instruction encoding has failed. The proofs of
`dec_dispatcherSlot` and `dec_helperTable` say so: the eight bytes of an
aligned dispatcher address and the five hundred and twelve zero bytes of the
helper table both start with a zero byte, which begins no encoding the encoder
writes, so `decode_insn` returns nothing and `decode_data` runs — the first
falling through the five-hundred-and-twelve-zero-byte test to the eight-byte
slot, the second passing it.

`Load size sx` with `sx` and `size = 8` is the one form `DecodesTo` cannot be
stated for: the encoder writes no bytes for it. `enc_nil_of_emitsNothing`
records that — for it and for the four label primitives — and `dec_load`
excludes exactly that case.
-/
open Aeneas Aeneas.Std Result

set_option maxHeartbeats 4000000
set_option maxRecDepth 100000

namespace async_ebpf_verified
namespace X64Enc

/-! ## The primitives with no bytes -/

/-- **The encoder writes nothing for the five primitives `emitsNothing` names.** -/
theorem enc_nil_of_emitsNothing {p : x64_ir.PInsn} (h : emitsNothing p = true) : enc p = [] := by
  cases p
  case Load size sxf base dst disp =>
    simp only [emitsNothing, Bool.and_eq_true, decide_eq_true_eq] at h
    simp [enc, guestLoadL, loadSxL, h.1, h.2]
  all_goals first
    | rfl
    | (simp only [emitsNothing] at h; exact Bool.noConfusion h)

/-! ## The head of a ModRM byte the encoder wrote -/

theorem and199_and7 (x : Std.U8) : (x &&& 199#u8) &&& 7#u8 = x &&& 7#u8 :=
  u8_cases (P := fun x => (x &&& 199#u8) &&& 7#u8 = x &&& 7#u8) (by decide) x

theorem and199_and192 (x : Std.U8) : (x &&& 199#u8) &&& 192#u8 = x &&& 192#u8 :=
  u8_cases (P := fun x => (x &&& 199#u8) &&& 192#u8 = x &&& 192#u8) (by decide) x

/-- The first byte of `modrmDispL`, in the form the mask lemmas want. -/
theorem modrmDispL_zero (reg rm : Std.U8) (d : Std.I32) :
    ∃ md : Std.U8, ((md = 0#u8 ∧ needsDispB (rm &&& 15#u8) = false)
        ∨ md = 64#u8 ∨ md = 128#u8)
      ∧ (modrmDispL reg rm d)[0]! = modrmB md (reg &&& 15#u8) (rm &&& 15#u8) := by
  unfold modrmDispL
  by_cases h : d = 0#i32 ∧ needsDispB (rm &&& 15#u8) = false
  · rw [if_pos h]; exact ⟨0#u8, Or.inl ⟨rfl, h.2⟩, by simp⟩
  · rw [if_neg h]
    by_cases hn : nearDispB d = true
    · exact ⟨64#u8, Or.inr (Or.inl rfl), by simp [hn]⟩
    · simp only [Bool.not_eq_true] at hn
      exact ⟨128#u8, Or.inr (Or.inr rfl), by simp [hn]⟩

theorem modrmDispL_head_mod (reg rm : Std.U8) (d : Std.I32) :
    (modrmDispL reg rm d)[0]! &&& 192#u8 ≠ 192#u8 := by
  obtain ⟨md, hmd, hget⟩ := modrmDispL_zero reg rm d
  rw [hget, modrmB_and192]
  rcases hmd with ⟨rfl, -⟩ | rfl | rfl <;> decide

theorem modrmDispL_head_ne4 (reg rm : Std.U8) (d : Std.I32) :
    (modrmDispL reg rm d)[0]! ≠ 4#u8 := by
  obtain ⟨md, hmd, hget⟩ := modrmDispL_zero reg rm d
  rw [hget]
  rcases hmd with ⟨rfl, hnd⟩ | rfl | rfl
  · intro he
    have h7 : (modrmB 0#u8 (reg &&& 15#u8) (rm &&& 15#u8)) &&& 7#u8 = 4#u8 := by rw [he]; decide
    rw [modrmB_and7, and15_and7] at h7
    rw [needsDisp_iff] at hnd
    simp only [decide_eq_false_iff_not, not_or] at hnd
    exact hnd.1 h7
  · intro he
    have := modrmB_and192 64#u8 (reg &&& 15#u8) (rm &&& 15#u8)
    rw [he] at this
    revert this; decide
  · intro he
    have := modrmB_and192 128#u8 (reg &&& 15#u8) (rm &&& 15#u8)
    rw [he] at this
    revert this; decide

theorem modrmDispL_head_not_rip (reg rm : Std.U8) (d : Std.I32) :
    (modrmDispL reg rm d)[0]! &&& 199#u8 ≠ 5#u8 := by
  obtain ⟨md, hmd, hget⟩ := modrmDispL_zero reg rm d
  rw [hget]
  rcases hmd with ⟨rfl, hnd⟩ | rfl | rfl
  · intro he
    have h7 := and199_and7 (modrmB 0#u8 (reg &&& 15#u8) (rm &&& 15#u8))
    rw [he, modrmB_and7, and15_and7] at h7
    rw [needsDisp_iff] at hnd
    simp only [decide_eq_false_iff_not, not_or] at hnd
    exact hnd.2 (by rw [← h7]; decide)
  · intro he
    have h192 := and199_and192 (modrmB 64#u8 (reg &&& 15#u8) (rm &&& 15#u8))
    rw [he, modrmB_and192] at h192
    revert h192; decide
  · intro he
    have h192 := and199_and192 (modrmB 128#u8 (reg &&& 15#u8) (rm &&& 15#u8))
    rw [he, modrmB_and192] at h192
    revert h192; decide

theorem modrmDispL_pos (reg rm : Std.U8) (d : Std.I32) : 0 < (modrmDispL reg rm d).length := by
  rw [modrmDispL_length]
  exact (modrmDispLen_le rm d).1

/-! ## The locked exchange and compare-exchange -/

theorem dec_xchg (w64 : Bool) (src base : Std.U8) (disp : Std.I32)
    (hsrc : src.val < 16) (hbase : base.val < 16) :
    DecodesTo (.Xchg w64 src base disp) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.Xchg w64 src base disp)
      = 240#u8 :: (basicRexL (bitU w64) src base ++ 135#u8 :: modrmDispL src base disp) := rfl
  rw [hbs] at hb
  set L := basicRexL (bitU w64) src base with hL
  set M := modrmDispL src base disp with hM
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hml : M.length = modrmDispLen base disp := hM ▸ modrmDispL_length _ _ _
  have hmb := modrmDispLen_le base disp
  have hlen : (240#u8 :: (L ++ 135#u8 :: M)).length
      = 1 + L.length + 1 + modrmDispLen base disp := by simp [hml]; omega
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_pfx_opt_rex (rexl := L) (rest := 135#u8 :: M) hb hat (by omega) (Or.inl rfl)
      (by simp) (by simp only [List.getElem!_cons_zero]; decide)
      (hL ▸ basicRexL_case (bitU w64) src base (bitU_le _))
  have hgop : (240#u8 :: (L ++ 135#u8 :: M))[1 + L.length]! = 135#u8 := by
    rw [show 1 + L.length = L.length + 1 from by omega]
    simp only [List.getElem!_cons_succ]
    rw [getBang_append_right _ _ _ (by omega)]
    simp
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 135#u8) := by
    rw [← hgop]
    exact byte_at_in (pre := pre) (bs := 240#u8 :: (L ++ 135#u8 :: M)) (k := 1 + L.length)
      hb (by omega) (by omega)
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (1 + L.length + 1) := by simp at hz1v0; omega
  obtain ⟨ln0, hln0, hmem⟩ :=
    decode_mem_eq (bytes := bytes) («at» := z1) (pre := pre ++ (240#u8 :: L) ++ [135#u8])
      (bs := M) (rest := []) (reg := src) (rm := base) (d := disp)
      (rex_r := q.r) (rex_b := q.b) (by simp [hb]) (by simp; omega) (by simp [hM])
      (by simp; omega)
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := z1) (y := ln0) (by rw [hln0]; omega)
  have hz2v : z2.val = pre.length + (1 + L.length + 1 + modrmDispLen base disp) := by
    rw [hz2v0, hz1v, hln0]; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Xchg w64 src base disp) (disp := 0#i64)
      (pos := pos) (e := z2) (n := 1 + L.length + 1 + modrmDispLen base disp) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Xchg w64 src base disp, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_lock hb0 (by rw [hlock]; decide)]
    unfold x64_decode.decode_locked
    rw [if_neg (by decide : ¬((135#u8 : Std.U8) = 15#u8)), if_pos (rfl : (135#u8 : Std.U8) = 135#u8)]
    simp only [hz1, bind_tc_ok]
    rw [hmem]
    simp only [bind_tc_ok, if_true, hz2]
    rw [hqr, hqb, hqw, bitU_eq_one, reg_rejoin src hsrc, reg_rejoin base hbase]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

theorem dec_lockCmpxchg (w64 : Bool) (src base : Std.U8) (disp : Std.I32)
    (hsrc : src.val < 16) (hbase : base.val < 16) :
    DecodesTo (.LockCmpxchg w64 src base disp) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.LockCmpxchg w64 src base disp)
      = 240#u8 :: (basicRexL (bitU w64) src base ++ 15#u8 :: 177#u8
          :: modrmDispL src base disp) := rfl
  rw [hbs] at hb
  set L := basicRexL (bitU w64) src base with hL
  set M := modrmDispL src base disp with hM
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hml : M.length = modrmDispLen base disp := hM ▸ modrmDispL_length _ _ _
  have hmb := modrmDispLen_le base disp
  have hlen : (240#u8 :: (L ++ 15#u8 :: 177#u8 :: M)).length
      = 1 + L.length + 2 + modrmDispLen base disp := by simp [hml]; omega
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_pfx_opt_rex (rexl := L) (rest := 15#u8 :: 177#u8 :: M) hb hat (by omega) (Or.inl rfl)
      (by simp) (by simp only [List.getElem!_cons_zero]; decide)
      (hL ▸ basicRexL_case (bitU w64) src base (bitU_le _))
  have hgop : (240#u8 :: (L ++ 15#u8 :: 177#u8 :: M))[1 + L.length]! = 15#u8 := by
    rw [show 1 + L.length = L.length + 1 from by omega]
    simp only [List.getElem!_cons_succ]
    rw [getBang_append_right _ _ _ (by omega)]
    simp
  have hgop2 : (240#u8 :: (L ++ 15#u8 :: 177#u8 :: M))[1 + L.length + 1]! = 177#u8 := by
    rw [show 1 + L.length + 1 = L.length + 2 from by omega]
    simp only [List.getElem!_cons_succ]
    rw [getBang_append_right _ _ _ (by omega)]
    simp
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 15#u8) := by
    rw [← hgop]
    exact byte_at_in (pre := pre) (bs := 240#u8 :: (L ++ 15#u8 :: 177#u8 :: M))
      (k := 1 + L.length) hb (by omega) (by omega)
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (1 + L.length + 1) := by simp at hz1v0; omega
  have hb1 : x64_decode.byte_at bytes z1 = ok (sxB 177#u8) := by
    rw [← hgop2]
    exact byte_at_in (pre := pre) (bs := 240#u8 :: (L ++ 15#u8 :: 177#u8 :: M))
      (k := 1 + L.length + 1) hb (by omega) (by omega)
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (1 + L.length + 2) := by simp at hz2v0; omega
  obtain ⟨ln0, hln0, hmem⟩ :=
    decode_mem_eq (bytes := bytes) («at» := z2) (pre := pre ++ (240#u8 :: L) ++ [15#u8, 177#u8])
      (bs := M) (rest := []) (reg := src) (rm := base) (d := disp)
      (rex_r := q.r) (rex_b := q.b) (by simp [hb]) (by simp; omega) (by simp [hM])
      (by simp; omega)
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := z2) (y := ln0) (by rw [hln0]; omega)
  have hz3v : z3.val = pre.length + (1 + L.length + 2 + modrmDispLen base disp) := by
    rw [hz3v0, hz2v, hln0]; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.LockCmpxchg w64 src base disp) (disp := 0#i64)
      (pos := pos) (e := z3) (n := 1 + L.length + 2 + modrmDispLen base disp) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.LockCmpxchg w64 src base disp, len := ln,
                 disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_lock hb0 (by rw [hlock]; decide)]
    unfold x64_decode.decode_locked
    rw [if_pos (rfl : (15#u8 : Std.U8) = 15#u8)]
    simp only [hz1, bind_tc_ok]
    rw [hb1]
    simp only [bind_tc_ok]
    rw [if_pos (by decide : sxB 177#u8 = 177#i32)]
    simp only [hz2, bind_tc_ok]
    rw [hmem]
    simp only [bind_tc_ok, if_true, hz3]
    rw [hqr, hqb, hqw, bitU_eq_one, reg_rejoin src hsrc, reg_rejoin base hbase]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

/-! ## Reading a byte that may be past the end -/

theorem byte_at_ok (bytes : Slice Std.U8) (i : Usize) :
    ∃ v : Std.I32, x64_decode.byte_at bytes i = ok v := by
  unfold x64_decode.byte_at
  by_cases h : i < Slice.len bytes
  · rw [if_pos h]
    have hlt : i.val < bytes.val.length := by
      rw [UScalar.lt_equiv] at h
      simpa only [Slice.len_val, Slice.length] using h
    rw [slice_index_eq hlt]
    exact ⟨_, rfl⟩
  · rw [if_neg h]; exact ⟨_, rfl⟩

/-! ## The read-modify-write bounds checks -/

theorem dec_aluRM (op : x64_ir.AluRM) (reg base : Std.U8) (disp : Std.I32)
    (hreg : reg.val < 16) (hbase : base.val < 16) :
    DecodesTo (.AluRM op reg base disp) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.AluRM op reg base disp)
      = basicRexL 1#u8 reg base ++ aluRMOp op :: modrmDispL reg base disp := rfl
  rw [hbs] at hb
  set L := basicRexL 1#u8 reg base with hL
  set M := modrmDispL reg base disp with hM
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hml : M.length = modrmDispLen base disp := hM ▸ modrmDispL_length _ _ _
  have hmb := modrmDispLen_le base disp
  have hlen : (L ++ aluRMOp op :: M).length = L.length + 1 + modrmDispLen base disp := by
    simp [hml]; omega
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex (rexl := L) (rest := aluRMOp op :: M) hb hat (by omega)
      (by simp) (by simp only [List.getElem!_cons_zero]; cases op <;> decide)
      (hL ▸ basicRexL_case 1#u8 reg base (by decide))
  have hgop : (L ++ aluRMOp op :: M)[L.length + 0]! = aluRMOp op := by rw [get_after]; simp
  have hgm : (L ++ aluRMOp op :: M)[L.length + 1]! = M[0]! := by rw [get_after]; simp
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB (aluRMOp op)) := by
    rw [← hgop]
    exact byte_at_in (pre := pre) (bs := L ++ aluRMOp op :: M) (k := L.length + 0)
      hb (by omega) (by omega)
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  have hbm : x64_decode.byte_at bytes z1 = ok (sxB M[0]!) := by
    rw [← hgm]
    exact byte_at_in (pre := pre) (bs := L ++ aluRMOp op :: M) (k := L.length + 1)
      hb (by omega) (by omega)
  have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := false, reg := 0#u8, rm := 0#u8, ext := 0#u8 } := by
    refine decode_reg2_ne (k := L.length + 1) hb (by omega) (by omega) ?_
    rw [hgm, hM]; exact modrmDispL_head_mod reg base disp
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  obtain ⟨sib, hsib⟩ := byte_at_ok bytes z2
  obtain ⟨ln0, hln0, hmem⟩ :=
    decode_mem_eq (bytes := bytes) («at» := z1) (pre := pre ++ L ++ [aluRMOp op])
      (bs := M) (rest := []) (reg := reg) (rm := base) (d := disp)
      (rex_r := q.r) (rex_b := q.b) (by simp [hb]) (by simp; omega) (by simp [hM])
      (by simp; omega)
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := z1) (y := ln0) (by rw [hln0]; omega)
  have hz3v : z3.val = pre.length + (L.length + 1 + modrmDispLen base disp) := by
    rw [hz3v0, hz1v, hln0]; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.AluRM op reg base disp) (disp := 0#i64)
      (pos := pos) (e := z3) (n := L.length + 1 + modrmDispLen base disp) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.AluRM op reg base disp, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by cases op <;> decide)]
    rw [decode_one_byte_tail (by cases op <;> decide) (by cases op <;> decide)
      (by cases op <;> decide)]
    rw [show x64_decode.alu_op (aluRMOp op) = ok true from by cases op <;> rfl]
    simp only [bind_tc_ok, if_true]
    unfold x64_decode.decode_alu
    simp only [hz1, hz2, hg, hbm, hsib, bind_tc_ok]
    rw [show x64_decode.is_alu_rr (aluRMOp op) = ok (decide (aluRMOp op = 57#u8)) from by
      cases op <;> rfl]
    rw [show x64_decode.is_alu_rm (aluRMOp op) = ok true from by cases op <;> rfl]
    simp only [bind_tc_ok, reduceIte]
    rw [if_neg (show ¬(aluRMOp op = 137#u8) from by cases op <;> decide)]
    rw [hmem]
    simp only [bind_tc_ok, if_true]
    rw [if_neg (show ¬(aluRMOp op = 136#u8) from by cases op <;> decide)]
    rw [if_neg (show ¬(aluRMOp op = 137#u8) from by cases op <;> decide)]
    rw [show x64_decode.alu_rm_of (aluRMOp op) = ok op from by cases op <;> rfl]
    simp only [bind_tc_ok, hz3]
    rw [hqr, hqb, reg_rejoin reg hreg, reg_rejoin base hbase]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

/-! ## The ModRM byte at an offset -/

/-- The three readings the decoder takes of the ModRM byte and displacement the
encoder wrote at `z`: the byte itself, the register form's refusal, and the
memory form. -/
theorem mem_head {bytes : Slice Std.U8} {pre M R : List Std.U8} {z : Usize}
    {reg rm rex_r rex_b : Std.U8} {d : Std.I32}
    (hb : bytes.val = pre ++ (M ++ R)) (hz : z.val = pre.length)
    (hM : M = modrmDispL reg rm d) (hfit : pre.length + 16 ≤ Usize.max) :
    ∃ ln0 : Usize, ln0.val = modrmDispLen rm d ∧
      x64_decode.byte_at bytes z = ok (sxB M[0]!) ∧
      x64_decode.decode_reg2 bytes z rex_r rex_b =
        ok { ok := false, reg := 0#u8, rm := 0#u8, ext := 0#u8 } ∧
      x64_decode.decode_mem bytes z rex_r rex_b =
        ok { ok := true, reg := (reg &&& 7#u8) ||| shlU rex_r 3,
             base := (rm &&& 7#u8) ||| shlU rex_b 3, disp := d, len := ln0 } := by
  have hMpos : 0 < M.length := by rw [hM]; exact modrmDispL_pos reg rm d
  have hg0 : (M ++ R)[0]! = M[0]! := getBang_append_left _ _ _ hMpos
  have hmod : (M ++ R)[0]! &&& 192#u8 ≠ 192#u8 := by
    rw [hg0, hM]; exact modrmDispL_head_mod reg rm d
  obtain ⟨ln0, hln0, hmem⟩ :=
    decode_mem_eq (bytes := bytes) («at» := z) (pre := pre) (bs := M ++ R) (rest := R)
      (reg := reg) (rm := rm) (d := d) (rex_r := rex_r) (rex_b := rex_b)
      hb hz (by rw [hM]) hfit
  refine ⟨ln0, hln0, ?_, ?_, hmem⟩
  · rw [← hg0]; exact byte_at_in (k := 0) hb (by omega) (by simp; omega)
  · exact decode_reg2_ne (k := 0) hb (by omega) (by simp; omega) hmod

/-! ## The store's REX prefix -/

/-- The bytes `emit_store` writes for the REX prefix. -/
def storeRexL (size src dst : Std.U8) : List Std.U8 :=
  if storeRexB size src dst then
    [rexByte (bitU (size = 8#u8)) (highU src) 0#u8 (highU dst)] else []

theorem storeL_eq (size src dst : Std.U8) (offset : Std.I32) :
    storeL size src dst offset =
      (if size = 2#u8 then [102#u8] else [])
        ++ (storeRexL size src dst
            ++ ((if size = 1#u8 then 136#u8 else 137#u8) :: modrmDispL src dst offset)) := by
  unfold storeL storeRexL
  simp

theorem storeRexL_length_le (size src dst : Std.U8) : (storeRexL size src dst).length ≤ 1 := by
  unfold storeRexL; split <;> simp

theorem storeRexL_case (size src dst : Std.U8) :
    RexCase (storeRexL size src dst) (bitU (size = 8#u8)) (highU src) (highU dst) := by
  unfold RexCase storeRexL
  by_cases h : storeRexB size src dst = true
  · rw [if_pos h]
    refine Or.inr ⟨_, rfl, ?_, ?_, ?_, ?_, ?_⟩
    · exact (rexByte_range _ _ _ _ (bitU_le _) (highU_le _) (by decide) (highU_le _)).1
    · exact (rexByte_range _ _ _ _ (bitU_le _) (highU_le _) (by decide) (highU_le _)).2
    · exact pfxW_rexByte _ _ _ _ (bitU_le _) (highU_le _) (by decide) (highU_le _)
    · exact pfxR_rexByte _ _ _ _ (bitU_le _) (highU_le _) (by decide) (highU_le _)
    · exact pfxB_rexByte _ _ _ _ (bitU_le _) (highU_le _) (by decide) (highU_le _)
  · rw [if_neg h]
    simp only [Bool.not_eq_true, storeRexB, Bool.or_eq_false_iff, bne_eq_false_iff_eq,
      decide_eq_false_iff_not] at h
    obtain ⟨⟨⟨h8, hs⟩, hd⟩, h1⟩ := h
    refine Or.inl ⟨rfl, ?_, ?_, ?_⟩
    · simp only [bitU]; rw [if_neg (by simpa using h8)]
    · unfold highU; rw [if_neg (by simp [hs])]
    · unfold highU; rw [if_neg (by simp [hd])]

/-! ## The guest store -/

/-- The prefixes `emit_store` writes, read back. -/
theorem store_prefixes {bytes : Slice Std.U8} {pos : Usize} {pre : List Std.U8}
    {size src base : Std.U8} {disp : Std.I32}
    (_hsize : size = 1#u8 ∨ size = 2#u8 ∨ size = 4#u8 ∨ size = 8#u8)
    (hb : bytes.val = pre ++ enc (x64_ir.PInsn.Store size src base disp))
    (hat : pos.val = pre.length) (hfit : pre.length + 1024 ≤ Usize.max) :
    ∃ (q : x64_decode.Pfx) (A : List Std.U8),
      enc (x64_ir.PInsn.Store size src base disp)
        = A ++ ((if size = 1#u8 then 136#u8 else 137#u8) :: modrmDispL src base disp) ∧
      A.length ≤ 2 ∧
      x64_decode.prefixes bytes pos = ok q ∧ q.lock = false ∧
      q.op16 = decide (size = 2#u8) ∧ q.rep = false ∧
      q.w = bitU (size = 8#u8) ∧ q.r = highU src ∧ q.b = highU base ∧
      q.at.val = pre.length + A.length := by
  have henc : enc (x64_ir.PInsn.Store size src base disp) = storeL size src base disp := rfl
  have hrl := storeRexL_length_le size src base
  have hnp : notPfx (if size = 1#u8 then 136#u8 else 137#u8) := by split <;> decide
  by_cases h2 : size = 2#u8
  · have hb' : bytes.val = pre ++ (102#u8 :: (storeRexL size src base
        ++ ((if size = 1#u8 then 136#u8 else 137#u8) :: modrmDispL src base disp))) := by
      rw [hb, henc, storeL_eq, if_pos h2]; simp
    obtain ⟨q, hq, hl, ho, hr, hw, hrr, hbb, hqat⟩ :=
      prefixes_pfx_opt_rex (rexl := storeRexL size src base)
        (rest := (if size = 1#u8 then 136#u8 else 137#u8) :: modrmDispL src base disp)
        hb' hat (by omega) (Or.inr (Or.inl rfl)) (by simp)
        (by simp only [List.getElem!_cons_zero]; exact hnp) (storeRexL_case size src base)
    exact ⟨q, 102#u8 :: storeRexL size src base,
      by rw [henc, storeL_eq, if_pos h2]; simp,
      by simp only [List.length_cons]; omega, hq, hl, by rw [ho]; simp [h2], hr, hw, hrr, hbb,
      by simp only [List.length_cons]; omega⟩
  · have hb' : bytes.val = pre ++ (storeRexL size src base
        ++ ((if size = 1#u8 then 136#u8 else 137#u8) :: modrmDispL src base disp)) := by
      rw [hb, henc, storeL_eq, if_neg h2]; simp
    obtain ⟨q, hq, hl, ho, hr, hw, hrr, hbb, hqat⟩ :=
      prefixes_opt_rex (rexl := storeRexL size src base)
        (rest := (if size = 1#u8 then 136#u8 else 137#u8) :: modrmDispL src base disp)
        hb' hat (by omega) (by simp)
        (by simp only [List.getElem!_cons_zero]; exact hnp) (storeRexL_case size src base)
    exact ⟨q, storeRexL size src base,
      by rw [henc, storeL_eq, if_neg h2]; simp,
      by omega, hq, hl, by rw [ho]; simp [h2], hr, hw, hrr, hbb, hqat⟩

theorem sxB_ne_four {c : Std.U8} (h : c ≠ 4#u8) : sxB c ≠ 4#i32 := by
  rw [show (4#i32 : Std.I32) = sxB 4#u8 from by decide]
  exact sxB_ne h

theorem dec_store (size src base : Std.U8) (disp : Std.I32)
    (hsize : size = 1#u8 ∨ size = 2#u8 ∨ size = 4#u8 ∨ size = 8#u8)
    (hsrc : src.val < 16) (hbase : base.val < 16) :
    DecodesTo (.Store size src base disp) := by
  intro bytes pos pre hb hat hfit
  obtain ⟨q, A, henc, hAle, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    store_prefixes hsize hb hat hfit
  set o := (if size = 1#u8 then 136#u8 else 137#u8) with ho
  set M := modrmDispL src base disp with hM
  rw [henc] at hb
  have hml : M.length = modrmDispLen base disp := hM ▸ modrmDispL_length _ _ _
  have hmb := modrmDispLen_le base disp
  have hlen : (A ++ o :: M).length = A.length + 1 + modrmDispLen base disp := by
    simp [hml]; omega
  have hgop : (A ++ o :: M)[A.length + 0]! = o := by rw [get_after]; simp
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB o) := by
    rw [← hgop]
    exact byte_at_in (pre := pre) (bs := A ++ o :: M) (k := A.length + 0)
      hb (by omega) (by omega)
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (A.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  obtain ⟨sib, hsib⟩ := byte_at_ok bytes z2
  obtain ⟨ln0, hln0, hbm, hg, hmem⟩ :=
    mem_head (bytes := bytes) (pre := pre ++ A ++ [o]) (M := M) (R := [])
      (z := z1) (reg := src) (rm := base) (rex_r := q.r) (rex_b := q.b) (d := disp)
      (by simp [hb]) (by simp; omega) hM (by simp; omega)
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := z1) (y := ln0) (by rw [hln0]; omega)
  have hz3v : z3.val = pre.length + (A.length + 1 + modrmDispLen base disp) := by
    rw [hz3v0, hz1v, hln0]; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Store size src base disp) (disp := 0#i64)
      (pos := pos) (e := z3) (n := A.length + 1 + modrmDispLen base disp) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Store size src base disp, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by rw [ho]; split <;> decide)]
    rw [decode_one_byte_tail (by rw [ho]; split <;> decide) (by rw [ho]; split <;> decide)
      (by rw [ho]; split <;> decide)]
    rw [show x64_decode.alu_op o = ok true from by rw [ho]; split <;> rfl]
    simp only [bind_tc_ok, if_true]
    unfold x64_decode.decode_alu
    simp only [hz1, hz2, hg, hbm, hsib, bind_tc_ok]
    rw [show x64_decode.is_alu_rr o = ok (decide (o = 137#u8)) from by rw [ho]; split <;> rfl]
    rw [show x64_decode.is_alu_rm o = ok false from by rw [ho]; split <;> rfl]
    simp only [bind_tc_ok]
    rw [if_neg (show ¬((false : Bool) = true) from by decide)]
    by_cases h1 : size = 1#u8
    · have hoo : o = 136#u8 := by rw [ho, if_pos h1]
      rw [h1] at hfin
      simp only [if_neg (show ¬(o = 137#u8) from by rw [hoo]; decide)]
      rw [hmem]
      simp only [bind_tc_ok, if_true, if_pos hoo]
      simp only [bind_tc_ok, hz3]
      rw [hqr, hqb, reg_rejoin src hsrc, reg_rejoin base hbase, h1]
      exact hfin
    · have hoo : o = 137#u8 := by rw [ho, if_neg h1]
      have hsz : x64_decode.mem_size (bitU (size = 8#u8)) (decide (size = 2#u8)) = ok size := by
        rcases hsize with h|h|h|h
        · exact absurd h h1
        all_goals (subst h; rfl)
      simp only [if_pos hoo]
      rw [if_neg (sxB_ne_four (by rw [hM]; exact modrmDispL_head_ne4 src base disp))]
      rw [hmem]
      simp only [bind_tc_ok, if_true,
        if_neg (show ¬(o = 136#u8) from by rw [hoo]; decide)]
      rw [hqw, ho16, hsz]
      simp only [bind_tc_ok, hz3]
      rw [hqr, hqb, reg_rejoin src hsrc, reg_rejoin base hbase]
      exact hfin
  refine ⟨_, hres, rfl, ?_, rfl⟩
  rw [hln, henc, hlen]

/-! ## Immediates, read back -/

theorem signExtend_narrow (x : BitVec 32) (n : Nat) (h : n ≤ 32) :
    x.signExtend n = x.setWidth n := by
  apply BitVec.eq_of_getElem_eq; intro i hi
  rw [BitVec.getElem_signExtend hi, dif_pos (show i < 32 by omega), BitVec.getElem_setWidth]
  rw [BitVec.getLsbD_eq_getElem (by omega)]

/-- A byte of immediate, written and read back, is the immediate truncated. -/
theorem imm8_roundtrip (imm : Std.I32) :
    (UScalar.hcast (src_ty := .U8) .I32 (IScalar.hcast (src_ty := .I32) .U8 imm))
      = imm &&& 255#i32 := by
  apply I32.bv_eq_imp_eq
  simp only [IScalar.bv_and, UScalar.hcast_bv_eq, IScalar.hcast_bv_eq,
    UScalarTy.numBits, IScalarTy.numBits]
  rw [signExtend_narrow imm.bv 8 (by omega)]
  bits32

/-- Two bytes of immediate, written and read back, is the immediate truncated. -/
theorem imm16_roundtrip (imm : Std.I32) :
    ((UScalar.hcast (src_ty := .U8) .I32 (lo8 (IScalar.hcast (src_ty := .I32) .U16 imm).bv)
      ||| (⟨(UScalar.hcast (src_ty := .U8) .I32
              (lo8 ((IScalar.hcast (src_ty := .I32) .U16 imm).bv >>> 8))).bv <<< 8⟩ : Std.I32)))
      = imm &&& 65535#i32 := by
  apply I32.bv_eq_imp_eq
  simp only [lo8, IScalar.bv_or, IScalar.bv_and, UScalar.hcast_bv_eq, IScalar.hcast_bv_eq,
    UScalarTy.numBits, IScalarTy.numBits]
  rw [signExtend_narrow imm.bv 16 (by omega)]
  bits32

theorem shlI32_8 (x : Std.I32) : x <<< 8#i32 = ok (⟨x.bv <<< 8⟩ : Std.I32) := rfl

/-! ## Two more readings of the buffer -/

theorem have_ok {bytes : Slice Std.U8} {i n : Usize} (hfit : i.val + n.val ≤ Usize.max) :
    ∃ v : Bool, x64_decode.have bytes i n = ok v := by
  unfold x64_decode.have
  obtain ⟨z, hz, _⟩ := usize_add_ok hfit
  rw [hz]; exact ⟨_, rfl⟩

theorem is_rip_mem {bytes : Slice Std.U8} {z : Usize} {c : Std.U8}
    (h : x64_decode.byte_at bytes z = ok (sxB c)) :
    x64_decode.is_rip bytes z = ok (decide (c &&& 199#u8 = 5#u8)) := by
  unfold x64_decode.is_rip
  rw [h]
  simp only [bind_tc_ok, lift]
  rw [if_pos (sxB_nonneg _)]
  simp only [sxB_back]

/-! ## The store of an immediate -/

/-- The immediate bytes `emit_store_imm` writes. -/
def storeImmIL (size : Std.U8) (imm : Std.I32) : List Std.U8 :=
  if size = 1#u8 then [IScalar.hcast .U8 imm]
  else if size = 2#u8 then u16L (IScalar.hcast .U16 imm)
  else u32L (IScalar.hcast .U32 imm)

/-- How many of them there are. -/
def storeImmILen (size : Std.U8) : Nat :=
  if size = 1#u8 then 1 else if size = 2#u8 then 2 else 4

theorem storeImmIL_length (size : Std.U8) (imm : Std.I32) :
    (storeImmIL size imm).length = storeImmILen size := by
  unfold storeImmIL storeImmILen
  split
  · simp
  · split <;> simp [u16L, u32L]

theorem storeImmL_eq (size dst : Std.U8) (offset imm : Std.I32) :
    storeImmL size dst offset imm =
      (if size = 2#u8 then [102#u8] else [])
        ++ (basicRexL (bitU (size = 8#u8)) 0#u8 dst
            ++ ((if size = 1#u8 then 198#u8 else 199#u8)
                :: (modrmDispL 0#u8 dst offset ++ storeImmIL size imm))) := by
  unfold storeImmL storeImmIL
  simp

/-- The prefixes `emit_store_imm` writes, read back. -/
theorem storeImm_prefixes {bytes : Slice Std.U8} {pos : Usize} {pre : List Std.U8}
    {size base : Std.U8} {disp imm : Std.I32}
    (hb : bytes.val = pre ++ enc (x64_ir.PInsn.StoreImm size base disp imm))
    (hat : pos.val = pre.length) (hfit : pre.length + 1024 ≤ Usize.max) :
    ∃ (q : x64_decode.Pfx) (A : List Std.U8),
      enc (x64_ir.PInsn.StoreImm size base disp imm)
        = A ++ ((if size = 1#u8 then 198#u8 else 199#u8)
            :: (modrmDispL 0#u8 base disp ++ storeImmIL size imm)) ∧
      A.length ≤ 2 ∧
      x64_decode.prefixes bytes pos = ok q ∧ q.lock = false ∧
      q.op16 = decide (size = 2#u8) ∧ q.rep = false ∧
      q.w = bitU (size = 8#u8) ∧ q.r = 0#u8 ∧ q.b = highU base ∧
      q.at.val = pre.length + A.length := by
  have henc : enc (x64_ir.PInsn.StoreImm size base disp imm)
      = storeImmL size base disp imm := rfl
  have hrl := basicRexL_length_le (bitU (size = 8#u8)) 0#u8 base
  have hnp : notPfx (if size = 1#u8 then 198#u8 else 199#u8) := by split <;> decide
  have hcase : RexCase (basicRexL (bitU (size = 8#u8)) 0#u8 base)
      (bitU (size = 8#u8)) 0#u8 (highU base) := by
    have := basicRexL_case (bitU (size = 8#u8)) 0#u8 base (bitU_le _)
    rwa [show highU 0#u8 = 0#u8 from by decide] at this
  by_cases h2 : size = 2#u8
  · have hb' : bytes.val = pre ++ (102#u8 :: (basicRexL (bitU (size = 8#u8)) 0#u8 base
        ++ ((if size = 1#u8 then 198#u8 else 199#u8)
            :: (modrmDispL 0#u8 base disp ++ storeImmIL size imm)))) := by
      rw [hb, henc, storeImmL_eq, if_pos h2]; simp
    obtain ⟨q, hq, hl, ho, hr, hw, hrr, hbb, hqat⟩ :=
      prefixes_pfx_opt_rex (rexl := basicRexL (bitU (size = 8#u8)) 0#u8 base)
        (rest := (if size = 1#u8 then 198#u8 else 199#u8)
            :: (modrmDispL 0#u8 base disp ++ storeImmIL size imm))
        hb' hat (by omega) (Or.inr (Or.inl rfl)) (by simp)
        (by simp only [List.getElem!_cons_zero]; exact hnp) hcase
    exact ⟨q, 102#u8 :: basicRexL (bitU (size = 8#u8)) 0#u8 base,
      by rw [henc, storeImmL_eq, if_pos h2]; simp,
      by simp only [List.length_cons]; omega, hq, hl, by rw [ho]; simp [h2], hr, hw, hrr, hbb,
      by simp only [List.length_cons]; omega⟩
  · have hb' : bytes.val = pre ++ (basicRexL (bitU (size = 8#u8)) 0#u8 base
        ++ ((if size = 1#u8 then 198#u8 else 199#u8)
            :: (modrmDispL 0#u8 base disp ++ storeImmIL size imm))) := by
      rw [hb, henc, storeImmL_eq, if_neg h2]; simp
    obtain ⟨q, hq, hl, ho, hr, hw, hrr, hbb, hqat⟩ :=
      prefixes_opt_rex (rexl := basicRexL (bitU (size = 8#u8)) 0#u8 base)
        (rest := (if size = 1#u8 then 198#u8 else 199#u8)
            :: (modrmDispL 0#u8 base disp ++ storeImmIL size imm))
        hb' hat (by omega) (by simp)
        (by simp only [List.getElem!_cons_zero]; exact hnp) hcase
    exact ⟨q, basicRexL (bitU (size = 8#u8)) 0#u8 base,
      by rw [henc, storeImmL_eq, if_neg h2]; simp,
      by omega, hq, hl, by rw [ho]; simp [h2], hr, hw, hrr, hbb, hqat⟩

theorem get_imm (A M I : List Std.U8) (o : Std.U8) (j k : Nat)
    (hk : k = A.length + 1 + M.length + j) :
    (A ++ o :: (M ++ I))[k]! = I[j]! := by
  subst hk
  rw [show A.length + 1 + M.length + j = A.length + (M.length + j + 1) from by omega]
  rw [get_after]
  simp only [List.getElem!_cons_succ]
  rw [get_after]

theorem dec_storeImm (size base : Std.U8) (disp imm : Std.I32)
    (hsize : size = 1#u8 ∨ size = 2#u8 ∨ size = 4#u8 ∨ size = 8#u8)
    (hbase : base.val < 16) :
    DecodesTo (.StoreImm size base disp imm) := by
  intro bytes pos pre hb hat hfit
  obtain ⟨q, A, henc, hAle, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    storeImm_prefixes hb hat hfit
  set o := (if size = 1#u8 then 198#u8 else 199#u8) with ho
  set M := modrmDispL 0#u8 base disp with hM
  set I := storeImmIL size imm with hI
  set iv : Std.I32 := (if size = 1#u8 then imm &&& 255#i32
    else if size = 2#u8 then imm &&& 65535#i32 else imm) with hiv
  rw [henc] at hb
  have hml : M.length = modrmDispLen base disp := hM ▸ modrmDispL_length _ _ _
  have hmb := modrmDispLen_le base disp
  have hIl : I.length = storeImmILen size := hI ▸ storeImmIL_length _ _
  have hilb : 1 ≤ storeImmILen size ∧ storeImmILen size ≤ 4 := by
    unfold storeImmILen; split
    · omega
    · split <;> omega
  have hlen : (A ++ o :: (M ++ I)).length
      = A.length + 1 + modrmDispLen base disp + storeImmILen size := by
    simp only [List.length_append, List.length_cons, hml, hIl]; omega
  have hgop : (A ++ o :: (M ++ I))[A.length + 0]! = o := by rw [get_after]; simp
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB o) := by
    rw [← hgop]
    exact byte_at_in (pre := pre) (bs := A ++ o :: (M ++ I)) (k := A.length + 0)
      hb (by omega) (by omega)
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (A.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (A.length + 2) := by simp at hz2v0; omega
  obtain ⟨sib, hsib⟩ := byte_at_ok bytes z2
  obtain ⟨room, hroom⟩ := have_ok (bytes := bytes) (i := z2) (n := 4#usize) (by simp; omega)
  obtain ⟨ln0, hln0, hbm, hg, hmem⟩ :=
    mem_head (bytes := bytes) (pre := pre ++ A ++ [o]) (M := M) (R := I)
      (z := z1) (reg := 0#u8) (rm := base) (rex_r := q.r) (rex_b := q.b) (d := disp)
      (by simp [hb]) (by simp; omega) hM (by simp; omega)
  have hrip := is_rip_mem hbm
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := z1) (y := ln0) (by rw [hln0]; omega)
  have hz3v : z3.val = pre.length + (A.length + 1 + modrmDispLen base disp) := by
    rw [hz3v0, hz1v, hln0]; omega
  set ilU : Usize := (if size = 1#u8 then 1#usize else if size = 2#u8 then 2#usize else 4#usize)
    with hilU
  have hilv : ilU.val = storeImmILen size := by
    rw [hilU]; unfold storeImmILen; split
    · rfl
    · split <;> rfl
  have hil : (if size = 1#u8 then (ok 1#usize : Result Usize)
      else if size = 2#u8 then ok 2#usize else ok 4#usize) = ok ilU := by
    rw [hilU]; split
    · rfl
    · split <;> rfl
  have hfits : x64_decode.have bytes z3 ilU = ok true := by
    rw [have_at (pre := pre) (bs := A ++ o :: (M ++ I))
      (k := A.length + 1 + modrmDispLen base disp) hb (by omega) (by omega)]
    simp only [ok.injEq, decide_eq_true_eq, hlen, hilv]
    omega
  obtain ⟨z4, hz4, hz4v0⟩ := usize_add_ok (x := z3) (y := ilU) (by rw [hilv]; omega)
  have hz4v : z4.val
      = pre.length + (A.length + 1 + modrmDispLen base disp + storeImmILen size) := by
    rw [hz4v0, hz3v, hilv]; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.StoreImm size base disp iv)
      (disp := 0#i64) (pos := pos) (e := z4)
      (n := A.length + 1 + modrmDispLen base disp + storeImmILen size) (by omega)
  have hregz : ((0#u8 &&& 7#u8) ||| shlU q.r 3) = 0#u8 := by rw [hqr]; decide
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.StoreImm size base disp iv,
                 len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by rw [ho]; split <;> decide)]
    rw [decode_one_byte_tail (by rw [ho]; split <;> decide) (by rw [ho]; split <;> decide)
      (by rw [ho]; split <;> decide)]
    rw [show x64_decode.alu_op o = ok false from by rw [ho]; split <;> rfl]
    simp only [bind_tc_ok]
    rw [if_neg (show ¬((false : Bool) = true) from by decide)]
    simp only [if_neg (show ¬(o = 139#u8) from by rw [ho]; split <;> decide),
      if_neg (show ¬(o = 141#u8) from by rw [ho]; split <;> decide)]
    by_cases h1 : size = 1#u8
    · have hoo : o = 198#u8 := by rw [ho, if_pos h1]
      have hivv : iv = imm &&& 255#i32 := by rw [hiv, if_pos h1]
      have hsz : (if o = 198#u8 then (ok 1#u8 : Result Std.U8)
          else x64_decode.mem_size q.w q.op16) = ok size := by
        rw [if_pos hoo, h1]
      rw [if_pos hoo]
      unfold x64_decode.decode_move
      simp only [hz1, hz2, hrip, hroom, bind_tc_ok,
        if_neg (show ¬(o = 139#u8) from by rw [hoo]; decide),
        if_neg (show ¬(o = 141#u8) from by rw [hoo]; decide)]
      unfold x64_decode.decode_store_imm
      simp only [hz1, hz2, hg, hbm, hsib, hroom, bind_tc_ok,
        if_neg (show ¬(o = 199#u8) from by rw [hoo]; decide)]
      rw [hmem]
      simp only [bind_tc_ok]
      rw [hsz]
      simp only [bind_tc_ok]
      rw [hil]
      simp only [bind_tc_ok, hz3, hfits, if_true, hregz, bne_self_eq_false,
        Bool.false_eq_true, if_false, hz4]
      rw [hqb, reg_rejoin base hbase]
      rw [if_pos h1]
      rw [index_at (pre := pre) (bs := A ++ o :: (M ++ I))
        (k := A.length + 1 + modrmDispLen base disp) hb (by omega) (by omega)]
      rw [get_imm A M I o 0 _ (by omega)]
      rw [show I[0]! = IScalar.hcast (src_ty := .I32) .U8 imm from by
        rw [hI, storeImmIL, if_pos h1]; simp]
      simp only [bind_tc_ok, imm8_roundtrip]
      rw [← hivv]
      exact hfin
    · have hoo : o = 199#u8 := by rw [ho, if_neg h1]
      have hsz : (if o = 198#u8 then (ok 1#u8 : Result Std.U8)
          else x64_decode.mem_size q.w q.op16) = ok size := by
        rw [if_neg (show ¬(o = 198#u8) from by rw [hoo]; decide), hqw, ho16]
        rcases hsize with h|h|h|h
        · exact absurd h h1
        all_goals (subst h; rfl)
      rw [if_neg (show ¬(o = 198#u8) from by rw [hoo]; decide), if_pos hoo]
      unfold x64_decode.decode_move
      simp only [hz1, hz2, hrip, hroom, bind_tc_ok,
        if_neg (show ¬(o = 139#u8) from by rw [hoo]; decide),
        if_neg (show ¬(o = 141#u8) from by rw [hoo]; decide)]
      unfold x64_decode.decode_store_imm
      simp only [hz1, hz2, hg, hbm, hsib, hroom, bind_tc_ok, if_pos hoo]
      rw [if_neg (show ¬((false : Bool) = true) from by decide)]
      rw [if_neg (sxB_ne_four (by rw [hM]; exact modrmDispL_head_ne4 0#u8 base disp))]
      rw [hmem]
      simp only [bind_tc_ok]
      rw [hsz]
      simp only [bind_tc_ok]
      rw [hil]
      simp only [bind_tc_ok, hz3, hfits, if_true, hregz, bne_self_eq_false,
        Bool.false_eq_true, if_false, hz4]
      rw [hqb, reg_rejoin base hbase]
      rw [if_neg h1]
      by_cases h2 : size = 2#u8
      · have hivv : iv = imm &&& 65535#i32 := by rw [hiv, if_neg h1, if_pos h2]
        have hIL2 : storeImmILen size = 2 := by
          unfold storeImmILen; rw [if_neg h1, if_pos h2]
        rw [if_pos h2]
        obtain ⟨z5, hz5, hz5v0⟩ := usize_add_ok (x := z3) (y := 1#usize) (by simp; omega)
        have hz5v : z5.val = pre.length + (A.length + 1 + modrmDispLen base disp + 1) := by
          simp at hz5v0; omega
        rw [index_at (pre := pre) (bs := A ++ o :: (M ++ I))
          (k := A.length + 1 + modrmDispLen base disp) hb (by omega) (by omega)]
        simp only [bind_tc_ok, lift]
        rw [hz5]
        simp only [bind_tc_ok]
        rw [index_at (pre := pre) (bs := A ++ o :: (M ++ I))
          (k := A.length + 1 + modrmDispLen base disp + 1) hb (by omega) (by omega)]
        simp only [bind_tc_ok, shlI32_8]
        rw [get_imm A M I o 0 _ (by omega), get_imm A M I o 1 _ (by omega)]
        rw [show I[0]! = lo8 (IScalar.hcast (src_ty := .I32) .U16 imm).bv from by
          rw [hI, storeImmIL, if_neg h1, if_pos h2]; simp [u16L]]
        rw [show I[1]! = lo8 ((IScalar.hcast (src_ty := .I32) .U16 imm).bv >>> 8) from by
          rw [hI, storeImmIL, if_neg h1, if_pos h2]; simp [u16L]]
        have hkey : ∀ t : Std.I32, t = iv →
            x64_decode.finish (x64_ir.PInsn.StoreImm size base disp t) pos z4 0#i64
              = ok (some { insn := x64_ir.PInsn.StoreImm size base disp iv, len := ln,
                           disp := 0#i64 }) := by
          intro t ht; rw [ht]; exact hfin
        apply hkey
        rw [hivv]
        exact imm16_roundtrip imm
      · have hivv : iv = imm := by rw [hiv, if_neg h1, if_neg h2]
        have hIL4 : storeImmILen size = 4 := by
          unfold storeImmILen; rw [if_neg h1, if_neg h2]
        rw [if_neg h2]
        rw [read32_at (pre := pre) (bs := A ++ o :: (M ++ I))
          (k := A.length + 1 + modrmDispLen base disp) hb (by omega) (by omega) (by omega)]
        rw [get_imm A M I o 0 _ (by omega), get_imm A M I o 1 _ (by omega),
          get_imm A M I o 2 _ (by omega), get_imm A M I o 3 _ (by omega)]
        rw [show I = u32L (IScalar.hcast (src_ty := .I32) .U32 imm) from by
          rw [hI, storeImmIL, if_neg h1, if_neg h2]]
        simp only [u32L, List.getElem!_cons_zero, List.getElem!_cons_succ]
        rw [u32of_lo8]
        simp only [bind_tc_ok]
        rw [hcast32_roundtrip, ← hivv]
        exact hfin
  refine ⟨_, hres, ?_, ?_, rfl⟩
  · rw [hiv]; rfl
  · rw [hln, henc, hlen]

/-! ## The two literal host-stack forms -/

theorem rexCase_one (c w r b : Std.U8) (h1 : 64 ≤ c.val) (h2 : c.val ≤ 79)
    (hw : pfxW c = w) (hr : pfxR c = r) (hbb : pfxB c = b) : RexCase [c] w r b :=
  Or.inr ⟨c, rfl, h1, h2, hw, hr, hbb⟩

theorem dec_storeRspRax : DecodesTo x64_ir.PInsn.StoreRspRax := by
  intro bytes pos pre hb hat hfit
  have hbs : enc x64_ir.PInsn.StoreRspRax = [72#u8, 137#u8, 4#u8, 36#u8] := rfl
  rw [hbs] at hb
  have hb' : bytes.val = pre ++ ([72#u8] ++ [137#u8, 4#u8, 36#u8]) := by rw [hb]; simp
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex (rexl := [72#u8]) (rest := [137#u8, 4#u8, 36#u8]) hb' hat (by omega)
      (by simp) (by simp only [List.getElem!_cons_zero]; decide)
      (rexCase_one 72#u8 1#u8 0#u8 0#u8 (by decide) (by decide) (by decide) (by decide)
        (by decide))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 137#u8) := by
    have := byte_at_in (pre := pre) (bs := [72#u8, 137#u8, 4#u8, 36#u8]) (k := 1)
      hb (by simp at hqat ⊢; omega) (by simp)
    simpa using this
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp at hqat ⊢; omega)
  have hz1v : z1.val = pre.length + 2 := by simp at hz1v0 hqat; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp at hqat ⊢; omega)
  have hz2v : z2.val = pre.length + 3 := by simp at hz2v0 hqat; omega
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := q.at) (y := 3#usize) (by simp at hqat ⊢; omega)
  have hz3v : z3.val = pre.length + 4 := by simp at hz3v0 hqat; omega
  have hb1 : x64_decode.byte_at bytes z1 = ok (sxB 4#u8) := by
    have := byte_at_in (pre := pre) (bs := [72#u8, 137#u8, 4#u8, 36#u8]) (k := 2)
      hb (by omega) (by simp)
    simpa using this
  have hb2 : x64_decode.byte_at bytes z2 = ok (sxB 36#u8) := by
    have := byte_at_in (pre := pre) (bs := [72#u8, 137#u8, 4#u8, 36#u8]) (k := 3)
      hb (by omega) (by simp)
    simpa using this
  have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := false, reg := 0#u8, rm := 0#u8, ext := 0#u8 } := by
    refine decode_reg2_ne (pre := pre) (bs := [72#u8, 137#u8, 4#u8, 36#u8]) (k := 2)
      hb (by omega) (by simp) ?_
    simp only [List.getElem!_cons_succ, List.getElem!_cons_zero]
    decide
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.StoreRspRax) (disp := 0#i64)
      (pos := pos) (e := z3) (n := 4) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.StoreRspRax, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 137#u8 = ok true from rfl]
    simp only [bind_tc_ok, if_true]
    unfold x64_decode.decode_alu
    simp only [hz1, hz2, hg, hb1, hb2, bind_tc_ok]
    rw [show x64_decode.is_alu_rr 137#u8 = ok true from rfl]
    rw [show x64_decode.is_alu_rm 137#u8 = ok false from rfl]
    simp only [bind_tc_ok]
    rw [if_neg (show ¬((false : Bool) = true) from by decide)]
    simp only [if_true]
    rw [if_pos (show sxB 4#u8 = 4#i32 from by decide)]
    rw [if_pos (show sxB 36#u8 = 36#i32 from by decide)]
    rw [hqw, if_pos (rfl : (1#u8 : Std.U8) = 1#u8)]
    simp only [hz3, bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs]; simp, rfl⟩

theorem dec_storeRspImm (imm : Std.U32) : DecodesTo (.StoreRspImm imm) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.StoreRspImm imm)
      = 72#u8 :: 199#u8 :: 4#u8 :: 36#u8 :: u32L imm := rfl
  rw [hbs] at hb
  set BS := 72#u8 :: 199#u8 :: 4#u8 :: 36#u8 :: u32L imm with hBS
  have hlen : BS.length = 8 := by rw [hBS]; simp [u32L]
  have hv4 : (4#usize).val = 4 := rfl
  have hb' : bytes.val = pre ++ ([72#u8] ++ (199#u8 :: 4#u8 :: 36#u8 :: u32L imm)) := by
    rw [hb, hBS]; simp
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex (rexl := [72#u8]) (rest := 199#u8 :: 4#u8 :: 36#u8 :: u32L imm)
      hb' hat (by omega) (by simp)
      (by simp only [List.getElem!_cons_zero]; decide)
      (rexCase_one 72#u8 1#u8 0#u8 0#u8 (by decide) (by decide) (by decide) (by decide)
        (by decide))
  have hqatv : q.at.val = pre.length + 1 := by simpa using hqat
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 199#u8) := by
    have := byte_at_in (pre := pre) (bs := BS) (k := 1) hb (by omega) (by omega)
    simpa [hBS] using this
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + 2 := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + 3 := by simp at hz2v0; omega
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := q.at) (y := 3#usize) (by simp; omega)
  have hz3v : z3.val = pre.length + 4 := by simp at hz3v0; omega
  obtain ⟨z4, hz4, hz4v0⟩ := usize_add_ok (x := q.at) (y := 7#usize) (by simp; omega)
  have hz4v : z4.val = pre.length + 8 := by simp at hz4v0; omega
  have hb1 : x64_decode.byte_at bytes z1 = ok (sxB 4#u8) := by
    have := byte_at_in (pre := pre) (bs := BS) (k := 2) hb (by omega) (by omega)
    simpa [hBS] using this
  have hb2 : x64_decode.byte_at bytes z2 = ok (sxB 36#u8) := by
    have := byte_at_in (pre := pre) (bs := BS) (k := 3) hb (by omega) (by omega)
    simpa [hBS] using this
  have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := false, reg := 0#u8, rm := 0#u8, ext := 0#u8 } := by
    refine decode_reg2_ne (pre := pre) (bs := BS) (k := 2) hb (by omega) (by omega) ?_
    rw [hBS]
    simp only [List.getElem!_cons_succ, List.getElem!_cons_zero]
    decide
  have hrip := is_rip_mem hb1
  obtain ⟨room, hroom⟩ := have_ok (bytes := bytes) (i := z2) (n := 4#usize) (by simp; omega)
  have hwide : x64_decode.have bytes z3 4#usize = ok true := by
    rw [have_at (pre := pre) (bs := BS) (k := 4) hb (by omega) (by omega)]
    simp only [ok.injEq, decide_eq_true_eq, hlen]
    omega
  have hread : x64_decode.read32 bytes z3 = ok imm := by
    rw [read32_at (pre := pre) (bs := BS) (k := 4) hb (by omega) (by omega) (by omega)]
    rw [show BS[4]! = lo8 imm.bv from by rw [hBS]; simp [u32L],
      show BS[5]! = lo8 (imm.bv >>> 8) from by rw [hBS]; simp [u32L],
      show BS[6]! = lo8 (imm.bv >>> 16) from by rw [hBS]; simp [u32L],
      show BS[7]! = lo8 (imm.bv >>> 24) from by rw [hBS]; simp [u32L]]
    rw [u32of_lo8]
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.StoreRspImm imm) (disp := 0#i64)
      (pos := pos) (e := z4) (n := 8) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.StoreRspImm imm, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 199#u8 = ok false from rfl]
    simp only [bind_tc_ok]
    rw [if_neg (show ¬((false : Bool) = true) from by decide)]
    simp only [if_neg (show ¬((199#u8 : Std.U8) = 139#u8) from by decide),
      if_neg (show ¬((199#u8 : Std.U8) = 141#u8) from by decide),
      if_neg (show ¬((199#u8 : Std.U8) = 198#u8) from by decide)]
    unfold x64_decode.decode_move
    simp only [hz1, hz2, hrip, hroom, bind_tc_ok,
      if_neg (show ¬((199#u8 : Std.U8) = 139#u8) from by decide),
      if_neg (show ¬((199#u8 : Std.U8) = 141#u8) from by decide)]
    unfold x64_decode.decode_store_imm
    simp only [hz1, hz2, hg, hb1, hb2, hroom, bind_tc_ok]
    rw [if_neg (show ¬((false : Bool) = true) from by decide)]
    rw [if_pos (show sxB 4#u8 = 4#i32 from by decide)]
    rw [if_pos (show sxB 36#u8 = 36#i32 from by decide)]
    simp only [hz3, bind_tc_ok, hwide]
    rw [hqw, if_pos (rfl : (1#u8 : Std.U8) = 1#u8)]
    simp only [if_true]
    rw [hread]
    simp only [hz4, bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

/-! ## The two RIP-relative forms -/

theorem modrm_reg_eq {bytes : Slice Std.U8} {z : Usize} {c rex_r : Std.U8}
    (h : x64_decode.byte_at bytes z = ok (sxB c)) :
    x64_decode.modrm_reg bytes z rex_r = ok (mReg c rex_r) := by
  unfold x64_decode.modrm_reg
  rw [h]
  simp only [bind_tc_ok, lift]
  rw [if_pos (sxB_nonneg _)]
  simp only [sxB_back, shrU3_eq, shlU3, bind_tc_ok, mReg, mExt]

theorem modrmB_rip (dst : Std.U8) : (modrmB 0#u8 dst 5#u8) &&& 199#u8 = 5#u8 :=
  u8_cases (P := fun dst => (modrmB 0#u8 dst 5#u8) &&& 199#u8 = 5#u8) (by decide) dst

theorem mReg_modrmB_rip0 (dst : Std.U8) : mReg (modrmB 0#u8 dst 5#u8) 0#u8 = dst &&& 7#u8 :=
  u8_cases (P := fun dst => mReg (modrmB 0#u8 dst 5#u8) 0#u8 = dst &&& 7#u8) (by decide) dst

theorem dec_ripLoadDispatcher (dst : Std.U8) (_hdst : dst.val < 8) :
    DecodesTo (.RipLoadDispatcher dst) := by
  intro bytes pos pre hb hat hfit
  have hu : u32L 0#u32 = [0#u8, 0#u8, 0#u8, 0#u8] := by decide
  have hbs : enc (x64_ir.PInsn.RipLoadDispatcher dst)
      = rexByte 1#u8 0#u8 0#u8 0#u8 :: 139#u8 :: modrmB 0#u8 dst 5#u8
          :: [0#u8, 0#u8, 0#u8, 0#u8] := by
    show rexByte 1#u8 0#u8 0#u8 0#u8 :: 139#u8 :: modrmB 0#u8 dst 5#u8 :: u32L 0#u32 = _
    rw [hu]
  rw [hbs] at hb
  set BS := rexByte 1#u8 0#u8 0#u8 0#u8 :: 139#u8 :: modrmB 0#u8 dst 5#u8
      :: [0#u8, 0#u8, 0#u8, 0#u8] with hBS
  have hlen : BS.length = 7 := by rw [hBS]; simp
  have hv4 : (4#usize).val = 4 := rfl
  have hb' : bytes.val = pre ++ ([rexByte 1#u8 0#u8 0#u8 0#u8]
      ++ (139#u8 :: modrmB 0#u8 dst 5#u8 :: [0#u8, 0#u8, 0#u8, 0#u8])) := by
    rw [hb, hBS]; simp
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex (rexl := [rexByte 1#u8 0#u8 0#u8 0#u8])
      (rest := 139#u8 :: modrmB 0#u8 dst 5#u8 :: [0#u8, 0#u8, 0#u8, 0#u8])
      hb' hat (by omega) (by simp) (by simp only [List.getElem!_cons_zero]; decide)
      (rexCase_one _ 1#u8 0#u8 0#u8 (by decide) (by decide) (by decide) (by decide) (by decide))
  have hqatv : q.at.val = pre.length + 1 := by simpa using hqat
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 139#u8) := by
    have := byte_at_in (pre := pre) (bs := BS) (k := 1) hb (by omega) (by omega)
    simpa [hBS] using this
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + 2 := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + 3 := by simp at hz2v0; omega
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := q.at) (y := 6#usize) (by simp; omega)
  have hz3v : z3.val = pre.length + 7 := by simp at hz3v0; omega
  have hb1 : x64_decode.byte_at bytes z1 = ok (sxB (modrmB 0#u8 dst 5#u8)) := by
    have := byte_at_in (pre := pre) (bs := BS) (k := 2) hb (by omega) (by omega)
    simpa [hBS] using this
  have hrip : x64_decode.is_rip bytes z1 = ok true := by
    rw [is_rip_mem hb1, modrmB_rip]; simp
  have hroom : x64_decode.have bytes z2 4#usize = ok true := by
    rw [have_at (pre := pre) (bs := BS) (k := 3) hb (by omega) (by omega)]
    simp only [ok.injEq, decide_eq_true_eq, hlen]
    omega
  have hread : x64_decode.read32 bytes z2 = ok (u32of 0#u8 0#u8 0#u8 0#u8) := by
    rw [read32_at (pre := pre) (bs := BS) (k := 3) hb (by omega) (by omega) (by omega)]
    rw [show BS[3]! = 0#u8 from by rw [hBS]; simp,
      show BS[4]! = 0#u8 from by rw [hBS]; simp,
      show BS[5]! = 0#u8 from by rw [hBS]; simp,
      show BS[6]! = 0#u8 from by rw [hBS]; simp]
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.RipLoadDispatcher (dst &&& 7#u8)) (disp := 0#i64)
      (pos := pos) (e := z3) (n := 7) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.RipLoadDispatcher (dst &&& 7#u8), len := ln,
                 disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 139#u8 = ok false from rfl]
    simp only [bind_tc_ok]
    rw [if_neg (show ¬((false : Bool) = true) from by decide)]
    simp only [reduceIte]
    unfold x64_decode.decode_move
    simp only [hz1, hz2, hrip, hroom, bind_tc_ok, if_true]
    rw [modrm_reg_eq hb1, mReg_modrmB_rip0]
    simp only [hz3, bind_tc_ok]
    rw [hread]
    simp only [bind_tc_ok]
    rw [sx32_zero]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

theorem dec_ripLeaHelperTable (dst : Std.U8) (hdst : dst.val < 16) :
    DecodesTo (.RipLeaHelperTable dst) := by
  intro bytes pos pre hb hat hfit
  have hu : u32L 0#u32 = [0#u8, 0#u8, 0#u8, 0#u8] := by decide
  have hbs : enc (x64_ir.PInsn.RipLeaHelperTable dst)
      = rexByte 1#u8 (highU dst) 0#u8 0#u8 :: 141#u8 :: modrmB 0#u8 dst 5#u8
          :: [0#u8, 0#u8, 0#u8, 0#u8] := by
    show rexByte 1#u8 (highU dst) 0#u8 0#u8 :: 141#u8 :: modrmB 0#u8 dst 5#u8 :: u32L 0#u32 = _
    rw [hu]
  rw [hbs] at hb
  set BS := rexByte 1#u8 (highU dst) 0#u8 0#u8 :: 141#u8 :: modrmB 0#u8 dst 5#u8
      :: [0#u8, 0#u8, 0#u8, 0#u8] with hBS
  have hlen : BS.length = 7 := by rw [hBS]; simp
  have hv4 : (4#usize).val = 4 := rfl
  have hb' : bytes.val = pre ++ ([rexByte 1#u8 (highU dst) 0#u8 0#u8]
      ++ (141#u8 :: modrmB 0#u8 dst 5#u8 :: [0#u8, 0#u8, 0#u8, 0#u8])) := by
    rw [hb, hBS]; simp
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex (rexl := [rexByte 1#u8 (highU dst) 0#u8 0#u8])
      (rest := 141#u8 :: modrmB 0#u8 dst 5#u8 :: [0#u8, 0#u8, 0#u8, 0#u8])
      hb' hat (by omega) (by simp) (by simp only [List.getElem!_cons_zero]; decide)
      (rexCase_one _ 1#u8 (highU dst) 0#u8
        (rexByte_range _ _ _ _ (by decide) (highU_le _) (by decide) (by decide)).1
        (rexByte_range _ _ _ _ (by decide) (highU_le _) (by decide) (by decide)).2
        (pfxW_rexByte _ _ _ _ (by decide) (highU_le _) (by decide) (by decide))
        (pfxR_rexByte _ _ _ _ (by decide) (highU_le _) (by decide) (by decide))
        (pfxB_rexByte _ _ _ _ (by decide) (highU_le _) (by decide) (by decide)))
  have hqatv : q.at.val = pre.length + 1 := by simpa using hqat
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 141#u8) := by
    have := byte_at_in (pre := pre) (bs := BS) (k := 1) hb (by omega) (by omega)
    simpa [hBS] using this
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + 2 := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + 3 := by simp at hz2v0; omega
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := q.at) (y := 6#usize) (by simp; omega)
  have hz3v : z3.val = pre.length + 7 := by simp at hz3v0; omega
  have hb1 : x64_decode.byte_at bytes z1 = ok (sxB (modrmB 0#u8 dst 5#u8)) := by
    have := byte_at_in (pre := pre) (bs := BS) (k := 2) hb (by omega) (by omega)
    simpa [hBS] using this
  have hrip : x64_decode.is_rip bytes z1 = ok true := by
    rw [is_rip_mem hb1, modrmB_rip]; simp
  have hroom : x64_decode.have bytes z2 4#usize = ok true := by
    rw [have_at (pre := pre) (bs := BS) (k := 3) hb (by omega) (by omega)]
    simp only [ok.injEq, decide_eq_true_eq, hlen]
    omega
  have hread : x64_decode.read32 bytes z2 = ok (u32of 0#u8 0#u8 0#u8 0#u8) := by
    rw [read32_at (pre := pre) (bs := BS) (k := 3) hb (by omega) (by omega) (by omega)]
    rw [show BS[3]! = 0#u8 from by rw [hBS]; simp,
      show BS[4]! = 0#u8 from by rw [hBS]; simp,
      show BS[5]! = 0#u8 from by rw [hBS]; simp,
      show BS[6]! = 0#u8 from by rw [hBS]; simp]
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.RipLeaHelperTable dst) (disp := 0#i64)
      (pos := pos) (e := z3) (n := 7) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.RipLeaHelperTable dst, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 141#u8 = ok false from rfl]
    simp only [bind_tc_ok]
    rw [if_neg (show ¬((false : Bool) = true) from by decide)]
    simp only [if_neg (show ¬((141#u8 : Std.U8) = 139#u8) from by decide)]
    unfold x64_decode.decode_move
    simp only [hz1, hz2, hrip, hroom, bind_tc_ok,
      if_neg (show ¬((141#u8 : Std.U8) = 139#u8) from by decide), if_true]
    rw [hqr, modrm_reg_eq hb1, mReg_modrmB 0#u8 dst 5#u8 (highU dst) hdst rfl]
    simp only [hz3, bind_tc_ok]
    rw [hread]
    simp only [bind_tc_ok]
    rw [sx32_zero]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

/-! ## The trailer's data -/

macro "bits64mem" : tactic => `(tactic|
  (ext i
   have h64 : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨ i = 6 ∨ i = 7 ∨ i = 8 ∨ i = 9 ∨
     i = 10 ∨ i = 11 ∨ i = 12 ∨ i = 13 ∨ i = 14 ∨ i = 15 ∨ i = 16 ∨ i = 17 ∨ i = 18 ∨ i = 19 ∨
     i = 20 ∨ i = 21 ∨ i = 22 ∨ i = 23 ∨ i = 24 ∨ i = 25 ∨ i = 26 ∨ i = 27 ∨ i = 28 ∨ i = 29 ∨
     i = 30 ∨ i = 31 ∨ i = 32 ∨ i = 33 ∨ i = 34 ∨ i = 35 ∨ i = 36 ∨ i = 37 ∨ i = 38 ∨ i = 39 ∨
     i = 40 ∨ i = 41 ∨ i = 42 ∨ i = 43 ∨ i = 44 ∨ i = 45 ∨ i = 46 ∨ i = 47 ∨ i = 48 ∨ i = 49 ∨
     i = 50 ∨ i = 51 ∨ i = 52 ∨ i = 53 ∨ i = 54 ∨ i = 55 ∨ i = 56 ∨ i = 57 ∨ i = 58 ∨ i = 59 ∨
     i = 60 ∨ i = 61 ∨ i = 62 ∨ i = 63 := by omega
   rcases h64 with h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|
     h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h <;> subst h <;> simp))

/-- The eight bytes `u64L` writes read back as the value they came from. -/
theorem u64of_lo8_mem (y : Std.U64) :
    u64of (lo8 y.bv) (lo8 (y.bv >>> 8)) (lo8 (y.bv >>> 16)) (lo8 (y.bv >>> 24))
      (lo8 (y.bv >>> 32)) (lo8 (y.bv >>> 40)) (lo8 (y.bv >>> 48)) (lo8 (y.bv >>> 56)) = y := by
  apply U64.bv_eq_imp_eq
  simp only [u64of, lo8]
  bits64mem

theorem lo8_of_and255 {addr : Std.U64} (h : addr &&& 255#u64 = 0#u64) : lo8 addr.bv = 0#u8 := by
  have h' : addr.bv &&& 255#64 = 0#64 := by
    have := congrArg UScalar.bv h
    simpa using this
  apply U8.bv_eq_imp_eq
  simp only [lo8]
  have hset : addr.bv.setWidth 8 = (addr.bv &&& 255#64).setWidth 8 := by bits8
  rw [hset, h']
  rfl

theorem helper_table_len_val : x64_encode.HELPER_TABLE_LEN = ok 512#usize := by
  obtain ⟨n, hn, hnv⟩ := WP.spec_imp_exists helper_table_len_spec
  rw [hn]
  congr 1
  exact UScalar.eq_of_val_eq (by simpa using hnv)

theorem zeros_loop_stop (bytes : Slice Std.U8) (a n i : Usize) :
    x64_decode.zeros_loop bytes a n false i = ok false := by
  unfold x64_decode.zeros_loop
  rw [loop.eq_def]
  simp [x64_decode.zeros_loop.body]

theorem zeros_loop_all_zero {bytes : Slice Std.U8} {a : Usize} {pre : List Std.U8}
    (hb : bytes.val = pre ++ List.replicate 512 0#u8) (ha : a.val = pre.length)
    (hfit : pre.length + 512 ≤ Usize.max) :
    ∀ (m : Nat) (i : Usize), i.val + m = 512 →
      x64_decode.zeros_loop bytes a 512#usize true i = ok true := by
  intro m
  induction m with
  | zero =>
    intro i hi
    unfold x64_decode.zeros_loop
    rw [loop.eq_def]
    simp only [x64_decode.zeros_loop.body]
    rw [if_pos trivial]
    rw [if_neg (show ¬(i < 512#usize) from by rw [UScalar.lt_equiv]; simp; omega)]
  | succ m ih =>
    intro i hi
    unfold x64_decode.zeros_loop
    rw [loop.eq_def]
    simp only [x64_decode.zeros_loop.body]
    rw [if_pos trivial]
    rw [if_pos (show i < 512#usize from by rw [UScalar.lt_equiv]; simp; omega)]
    obtain ⟨i1, hi1, hi1v⟩ := usize_add_ok (x := a) (y := i) (by omega)
    rw [hi1]
    simp only [bind_tc_ok]
    rw [index_at (pre := pre) (bs := List.replicate 512 0#u8) (k := i.val) hb
      (by omega) (by simp; omega)]
    have hilt : i.val < 512 := by omega
    rw [show ((List.replicate 512 0#u8)[i.val]! : Std.U8) = 0#u8 from by
      rw [List.getElem!_eq_getElem?_getD, List.getElem?_replicate, if_pos hilt]; rfl]
    obtain ⟨i3, hi3, hi3v⟩ := usize_add_ok (x := i) (y := 1#usize) (by simp; omega)
    simp only [bind_tc_ok, bne_self_eq_false, Bool.false_eq_true, if_false, hi3]
    have := ih i3 (by simp at hi3v; omega)
    unfold x64_decode.zeros_loop at this
    exact this

theorem decode_rest_zero_byte (bytes : Slice Std.U8) (pos : Usize) (q : x64_decode.Pfx) :
    x64_decode.decode_rest bytes pos q 0#u8 = ok none := by
  norm_num [x64_decode.decode_rest]

/-- A zero byte starts no encoding the encoder writes. -/
theorem decode_insn_zero_byte {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    (hh : x64_decode.byte_at bytes q.at = ok (sxB 0#u8)) (hlock : q.lock = false) :
    x64_decode.decode_insn bytes pos q = ok none := by
  rw [decode_insn_plain hh hlock (by decide)]
  rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
  rw [show x64_decode.alu_op 0#u8 = ok false from rfl]
  simp only [bind_tc_ok]
  rw [if_neg (show ¬((false : Bool) = true) from by decide)]
  simp only [if_neg (show ¬((0#u8 : Std.U8) = 139#u8) from by decide),
    if_neg (show ¬((0#u8 : Std.U8) = 141#u8) from by decide),
    if_neg (show ¬((0#u8 : Std.U8) = 198#u8) from by decide),
    if_neg (show ¬((0#u8 : Std.U8) = 199#u8) from by decide)]
  exact decode_rest_zero_byte bytes pos q

theorem decode_one_of_data {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    (hq : x64_decode.prefixes bytes pos = ok q)
    (hi : x64_decode.decode_insn bytes pos q = ok none) :
    x64_decode.decode_one bytes pos = x64_decode.decode_data bytes pos := by
  unfold x64_decode.decode_one
  rw [hq]
  simp only [bind_tc_ok]
  rw [hi]
  simp only [bind_tc_ok]

theorem dec_helperTable : DecodesTo x64_ir.PInsn.HelperTable := by
  intro bytes pos pre hb hat hfit
  have hbs : enc x64_ir.PInsn.HelperTable = List.replicate 512 0#u8 := rfl
  rw [hbs] at hb
  have hlen : (List.replicate 512 0#u8).length = 512 := by simp
  have hv512 : (512#usize).val = 512 := rfl
  have h0 : ((List.replicate 512 0#u8)[0]! : Std.U8) = 0#u8 := by
    rw [List.getElem!_eq_getElem?_getD, List.getElem?_replicate, if_pos (by omega)]; rfl
  have hb' : bytes.val = pre ++ ([] ++ List.replicate 512 0#u8) := by rw [hb]; simp
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex (rexl := []) (rest := List.replicate 512 0#u8) hb' hat (by omega)
      (by omega) (by rw [h0]; decide) (Or.inl ⟨rfl, rfl, rfl, rfl⟩)
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 0#u8) := by
    rw [← h0]
    exact byte_at_in (pre := pre) (bs := List.replicate 512 0#u8) (k := 0)
      hb (by simp at hqat; omega) (by omega)
  have hhv : x64_decode.have bytes pos 512#usize = ok true := by
    rw [have_at (pre := pre) (bs := List.replicate 512 0#u8) (k := 0) hb (by omega) (by omega)]
    simp only [ok.injEq, decide_eq_true_eq, hlen, hv512]
    omega
  have hzt : x64_decode.zeros bytes pos 512#usize = ok true := by
    unfold x64_decode.zeros
    rw [hhv]
    simp only [bind_tc_ok]
    exact zeros_loop_all_zero hb hat (by omega) 512 0#usize (by simp)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.HelperTable, len := 512#usize, disp := 0#i64 }) := by
    rw [decode_one_of_data hq (decode_insn_zero_byte hb0 hlock)]
    unfold x64_decode.decode_data
    rw [helper_table_len_val]
    simp only [bind_tc_ok]
    rw [hzt]
    simp only [bind_tc_ok, if_true]
  exact ⟨_, hres, rfl, by rw [hbs, hlen, hv512], rfl⟩

theorem dec_dispatcherSlot (addr : Std.U64) (haddr : addr &&& 255#u64 = 0#u64) :
    DecodesTo (.DispatcherSlot addr) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.DispatcherSlot addr) = u64L addr := rfl
  rw [hbs] at hb
  have hlen : (u64L addr).length = 8 := rfl
  have hv512 : (512#usize).val = 512 := rfl
  have hv8 : (8#usize).val = 8 := rfl
  have h0 : (u64L addr)[0]! = (0#u8 : Std.U8) := by
    rw [show (u64L addr)[0]! = lo8 addr.bv from rfl]
    exact lo8_of_and255 haddr
  have hb' : bytes.val = pre ++ ([] ++ u64L addr) := by rw [hb]; simp
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex (rexl := []) (rest := u64L addr) hb' hat (by omega)
      (by rw [hlen]; omega) (by rw [h0]; decide) (Or.inl ⟨rfl, rfl, rfl, rfl⟩)
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 0#u8) := by
    rw [← h0]
    exact byte_at_in (pre := pre) (bs := u64L addr) (k := 0)
      hb (by simp at hqat; omega) (by rw [hlen]; omega)
  have hhv : x64_decode.have bytes pos 512#usize = ok false := by
    rw [have_at (pre := pre) (bs := u64L addr) (k := 0) hb (by omega) (by omega)]
    simp only [ok.injEq, decide_eq_false_iff_not, hlen, hv512]
    omega
  have hzf : x64_decode.zeros bytes pos 512#usize = ok false := by
    unfold x64_decode.zeros
    rw [hhv]
    simp only [bind_tc_ok]
    exact zeros_loop_stop bytes pos 512#usize 0#usize
  have hhv8 : x64_decode.have bytes pos 8#usize = ok true := by
    rw [have_at (pre := pre) (bs := u64L addr) (k := 0) hb (by omega) (by omega)]
    simp only [ok.injEq, decide_eq_true_eq, hlen, hv8]
    omega
  have hread : x64_decode.read64 bytes pos = ok addr := by
    rw [read64_at (pre := pre) (bs := u64L addr) (k := 0) hb (by omega) (by omega) (by omega)]
    rw [show (u64L addr)[0]! = lo8 addr.bv from rfl,
      show (u64L addr)[1]! = lo8 (addr.bv >>> 8) from rfl,
      show (u64L addr)[2]! = lo8 (addr.bv >>> 16) from rfl,
      show (u64L addr)[3]! = lo8 (addr.bv >>> 24) from rfl,
      show (u64L addr)[4]! = lo8 (addr.bv >>> 32) from rfl,
      show (u64L addr)[5]! = lo8 (addr.bv >>> 40) from rfl,
      show (u64L addr)[6]! = lo8 (addr.bv >>> 48) from rfl,
      show (u64L addr)[7]! = lo8 (addr.bv >>> 56) from rfl]
    rw [u64of_lo8_mem]
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.DispatcherSlot addr, len := 8#usize, disp := 0#i64 }) := by
    rw [decode_one_of_data hq (decode_insn_zero_byte hb0 hlock)]
    unfold x64_decode.decode_data
    rw [helper_table_len_val]
    simp only [bind_tc_ok]
    rw [hzf]
    simp only [bind_tc_ok]
    rw [if_neg (show ¬((false : Bool) = true) from by decide)]
    rw [hhv8]
    simp only [bind_tc_ok, if_true]
    rw [hread]
    simp only [bind_tc_ok]
  exact ⟨_, hres, rfl, by rw [hbs, hlen, hv8], rfl⟩

/-! ## The guest load -/

/-- The four `0f`-escaped loads. -/
theorem dec_load_0f {bytes : Slice Std.U8} {pos : Usize} {pre L M : List Std.U8}
    {second size base dst w : Std.U8} {sxf : Bool} {disp : Std.I32}
    (hb : bytes.val = pre ++ (L ++ (15#u8 :: second :: M)))
    (hat : pos.val = pre.length) (hfit : pre.length + 1024 ≤ Usize.max)
    (hLl : L.length ≤ 1) (hcase : RexCase L w (highU dst) (highU base))
    (hM : M = modrmDispL dst base disp)
    (hbase : base.val < 16) (hdst : dst.val < 16)
    (hsec : (second = 182#u8 ∧ size = 1#u8 ∧ sxf = false)
          ∨ (second = 183#u8 ∧ size = 2#u8 ∧ sxf = false)
          ∨ (second = 190#u8 ∧ size = 1#u8 ∧ sxf = true)
          ∨ (second = 191#u8 ∧ size = 2#u8 ∧ sxf = true)) :
    ∃ d : x64_decode.Decoded, x64_decode.decode_one bytes pos = ok (some d) ∧
      d.insn = x64_ir.PInsn.Load size sxf base dst disp ∧
      d.len.val = L.length + 2 + modrmDispLen base disp ∧ d.disp = 0#i64 := by
  have hml : M.length = modrmDispLen base disp := hM ▸ modrmDispL_length _ _ _
  have hmb := modrmDispLen_le base disp
  have hlen : (L ++ 15#u8 :: second :: M).length = L.length + 2 + modrmDispLen base disp := by
    simp only [List.length_append, List.length_cons, hml]; omega
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex (rexl := L) (rest := 15#u8 :: second :: M) hb hat (by omega)
      (by simp) (by simp only [List.getElem!_cons_zero]; decide) hcase
  have hgop : (L ++ 15#u8 :: second :: M)[L.length + 0]! = 15#u8 := by rw [get_after]; simp
  have hgsec : (L ++ 15#u8 :: second :: M)[L.length + 1]! = second := by rw [get_after]; simp
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 15#u8) := by
    rw [← hgop]
    exact byte_at_in (pre := pre) (bs := L ++ 15#u8 :: second :: M) (k := L.length + 0)
      hb (by omega) (by omega)
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  have hb1 : x64_decode.byte_at bytes z1 = ok (sxB second) := by
    rw [← hgsec]
    exact byte_at_in (pre := pre) (bs := L ++ 15#u8 :: second :: M) (k := L.length + 1)
      hb (by omega) (by omega)
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
  obtain ⟨ln0, hln0, hbm, hg, hmem⟩ :=
    mem_head (bytes := bytes) (pre := pre ++ L ++ [15#u8, second]) (M := M) (R := [])
      (z := z2) (reg := dst) (rm := base) (rex_r := q.r) (rex_b := q.b) (d := disp)
      (by simp [hb]) (by simp; omega) hM (by simp; omega)
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := z2) (y := ln0) (by rw [hln0]; omega)
  have hz3v : z3.val = pre.length + (L.length + 2 + modrmDispLen base disp) := by
    rw [hz3v0, hz2v, hln0]; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Load size sxf base dst disp) (disp := 0#i64)
      (pos := pos) (e := z3) (n := L.length + 2 + modrmDispLen base disp) (by omega)
  refine ⟨{ insn := x64_ir.PInsn.Load size sxf base dst disp, len := ln, disp := 0#i64 },
    ?_, rfl, hln, rfl⟩
  refine decode_one_eq hq ?_
  rw [decode_insn_0f hb0 hlock]
  unfold x64_decode.decode_two_byte
  simp only [hz1, hb1, hz2, bind_tc_ok]
  rw [if_neg (sxB_nonneg' _)]
  rcases hsec with ⟨rfl, rfl, rfl⟩ | ⟨rfl, rfl, rfl⟩ | ⟨rfl, rfl, rfl⟩ | ⟨rfl, rfl, rfl⟩
  · rw [if_neg (by decide : ¬(sxB 182#u8 = 11#i32)),
      if_pos (by decide : sxB 182#u8 ≥ 64#i32),
      if_neg (by decide : ¬(sxB 182#u8 ≤ 79#i32)),
      if_pos (by decide : sxB 182#u8 ≥ 128#i32),
      if_neg (by decide : ¬(sxB 182#u8 ≤ 143#i32)),
      if_neg (by decide : ¬(sxB 182#u8 ≥ 200#i32)),
      if_pos (by decide : sxB 182#u8 = 182#i32)]
    simp only [if_pos (by decide : sxB 182#u8 = 182#i32), bind_tc_ok]
    rw [hmem]
    simp only [bind_tc_ok, if_true, hz3]
    rw [hqr, hqb, reg_rejoin dst hdst, reg_rejoin base hbase]
    exact hfin
  · rw [if_neg (by decide : ¬(sxB 183#u8 = 11#i32)),
      if_pos (by decide : sxB 183#u8 ≥ 64#i32),
      if_neg (by decide : ¬(sxB 183#u8 ≤ 79#i32)),
      if_pos (by decide : sxB 183#u8 ≥ 128#i32),
      if_neg (by decide : ¬(sxB 183#u8 ≤ 143#i32)),
      if_neg (by decide : ¬(sxB 183#u8 ≥ 200#i32)),
      if_neg (by decide : ¬(sxB 183#u8 = 182#i32)),
      if_pos (by decide : sxB 183#u8 = 183#i32)]
    simp only [if_neg (by decide : ¬(sxB 183#u8 = 182#i32)), bind_tc_ok]
    rw [hmem]
    simp only [bind_tc_ok, if_true, hz3]
    rw [hqr, hqb, reg_rejoin dst hdst, reg_rejoin base hbase]
    exact hfin
  · rw [if_neg (by decide : ¬(sxB 190#u8 = 11#i32)),
      if_pos (by decide : sxB 190#u8 ≥ 64#i32),
      if_neg (by decide : ¬(sxB 190#u8 ≤ 79#i32)),
      if_pos (by decide : sxB 190#u8 ≥ 128#i32),
      if_neg (by decide : ¬(sxB 190#u8 ≤ 143#i32)),
      if_neg (by decide : ¬(sxB 190#u8 ≥ 200#i32)),
      if_neg (by decide : ¬(sxB 190#u8 = 182#i32)),
      if_neg (by decide : ¬(sxB 190#u8 = 183#i32)),
      if_pos (by decide : sxB 190#u8 = 190#i32)]
    simp only [if_pos (by decide : sxB 190#u8 = 190#i32), bind_tc_ok, hg]
    rw [if_neg (show ¬((false : Bool) = true) from by decide)]
    rw [hmem]
    simp only [bind_tc_ok, if_true, hz3]
    rw [hqr, hqb, reg_rejoin dst hdst, reg_rejoin base hbase]
    exact hfin
  · rw [if_neg (by decide : ¬(sxB 191#u8 = 11#i32)),
      if_pos (by decide : sxB 191#u8 ≥ 64#i32),
      if_neg (by decide : ¬(sxB 191#u8 ≤ 79#i32)),
      if_pos (by decide : sxB 191#u8 ≥ 128#i32),
      if_neg (by decide : ¬(sxB 191#u8 ≤ 143#i32)),
      if_neg (by decide : ¬(sxB 191#u8 ≥ 200#i32)),
      if_neg (by decide : ¬(sxB 191#u8 = 182#i32)),
      if_neg (by decide : ¬(sxB 191#u8 = 183#i32)),
      if_neg (by decide : ¬(sxB 191#u8 = 190#i32)),
      if_pos (by decide : sxB 191#u8 = 191#i32)]
    simp only [if_neg (by decide : ¬(sxB 191#u8 = 190#i32)), bind_tc_ok, hg]
    rw [if_neg (show ¬((false : Bool) = true) from by decide)]
    rw [hmem]
    simp only [bind_tc_ok, if_true, hz3]
    rw [hqr, hqb, reg_rejoin dst hdst, reg_rejoin base hbase]
    exact hfin

/-- The plain `8b` load. -/
theorem dec_load_8b {bytes : Slice Std.U8} {pos : Usize} {pre L M : List Std.U8}
    {size base dst w : Std.U8} {disp : Std.I32}
    (hb : bytes.val = pre ++ (L ++ (139#u8 :: M)))
    (hat : pos.val = pre.length) (hfit : pre.length + 1024 ≤ Usize.max)
    (hLl : L.length ≤ 1) (hcase : RexCase L w (highU dst) (highU base))
    (hM : M = modrmDispL dst base disp)
    (hbase : base.val < 16) (hdst : dst.val < 16)
    (hsz : x64_decode.mem_size w false = ok size) :
    ∃ d : x64_decode.Decoded, x64_decode.decode_one bytes pos = ok (some d) ∧
      d.insn = x64_ir.PInsn.Load size false base dst disp ∧
      d.len.val = L.length + 1 + modrmDispLen base disp ∧ d.disp = 0#i64 := by
  have hml : M.length = modrmDispLen base disp := hM ▸ modrmDispL_length _ _ _
  have hmb := modrmDispLen_le base disp
  have hlen : (L ++ 139#u8 :: M).length = L.length + 1 + modrmDispLen base disp := by
    simp only [List.length_append, List.length_cons, hml]; omega
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex (rexl := L) (rest := 139#u8 :: M) hb hat (by omega)
      (by simp) (by simp only [List.getElem!_cons_zero]; decide) hcase
  have hgop : (L ++ 139#u8 :: M)[L.length + 0]! = 139#u8 := by rw [get_after]; simp
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 139#u8) := by
    rw [← hgop]
    exact byte_at_in (pre := pre) (bs := L ++ 139#u8 :: M) (k := L.length + 0)
      hb (by omega) (by omega)
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
  obtain ⟨room, hroom⟩ := have_ok (bytes := bytes) (i := z2) (n := 4#usize) (by simp; omega)
  obtain ⟨ln0, hln0, hbm, hg, hmem⟩ :=
    mem_head (bytes := bytes) (pre := pre ++ L ++ [139#u8]) (M := M) (R := [])
      (z := z1) (reg := dst) (rm := base) (rex_r := q.r) (rex_b := q.b) (d := disp)
      (by simp [hb]) (by simp; omega) hM (by simp; omega)
  have hrip : x64_decode.is_rip bytes z1 = ok false := by
    rw [is_rip_mem hbm]
    have := hM ▸ modrmDispL_head_not_rip dst base disp
    simp only [ok.injEq, decide_eq_false_iff_not]
    exact this
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := z1) (y := ln0) (by rw [hln0]; omega)
  have hz3v : z3.val = pre.length + (L.length + 1 + modrmDispLen base disp) := by
    rw [hz3v0, hz1v, hln0]; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Load size false base dst disp) (disp := 0#i64)
      (pos := pos) (e := z3) (n := L.length + 1 + modrmDispLen base disp) (by omega)
  refine ⟨{ insn := x64_ir.PInsn.Load size false base dst disp, len := ln, disp := 0#i64 },
    ?_, rfl, hln, rfl⟩
  refine decode_one_eq hq ?_
  rw [decode_insn_plain hb0 hlock (by decide)]
  rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
  rw [show x64_decode.alu_op 139#u8 = ok false from rfl]
  simp only [bind_tc_ok]
  rw [if_neg (show ¬((false : Bool) = true) from by decide)]
  simp only [reduceIte]
  unfold x64_decode.decode_move
  simp only [hz1, hz2, hrip, hroom, bind_tc_ok]
  rw [if_neg (show ¬((false : Bool) = true) from by decide)]
  simp only [if_neg (show ¬((139#u8 : Std.U8) = 141#u8) from by decide), if_true]
  rw [hmem]
  simp only [bind_tc_ok, if_true]
  rw [hqw, hsz]
  simp only [bind_tc_ok, hz3]
  rw [hqr, hqb, reg_rejoin dst hdst, reg_rejoin base hbase]
  exact hfin

/-- The sign-extending four-byte load. -/
theorem dec_load_63 {bytes : Slice Std.U8} {pos : Usize} {pre L M : List Std.U8}
    {base dst w : Std.U8} {disp : Std.I32}
    (hb : bytes.val = pre ++ (L ++ (99#u8 :: M)))
    (hat : pos.val = pre.length) (hfit : pre.length + 1024 ≤ Usize.max)
    (hLl : L.length ≤ 1) (hcase : RexCase L w (highU dst) (highU base))
    (hM : M = modrmDispL dst base disp)
    (hbase : base.val < 16) (hdst : dst.val < 16) :
    ∃ d : x64_decode.Decoded, x64_decode.decode_one bytes pos = ok (some d) ∧
      d.insn = x64_ir.PInsn.Load 4#u8 true base dst disp ∧
      d.len.val = L.length + 1 + modrmDispLen base disp ∧ d.disp = 0#i64 := by
  have hml : M.length = modrmDispLen base disp := hM ▸ modrmDispL_length _ _ _
  have hmb := modrmDispLen_le base disp
  have hlen : (L ++ 99#u8 :: M).length = L.length + 1 + modrmDispLen base disp := by
    simp only [List.length_append, List.length_cons, hml]; omega
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex (rexl := L) (rest := 99#u8 :: M) hb hat (by omega)
      (by simp) (by simp only [List.getElem!_cons_zero]; decide) hcase
  have hgop : (L ++ 99#u8 :: M)[L.length + 0]! = 99#u8 := by rw [get_after]; simp
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 99#u8) := by
    rw [← hgop]
    exact byte_at_in (pre := pre) (bs := L ++ 99#u8 :: M) (k := L.length + 0)
      hb (by omega) (by omega)
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨ln0, hln0, hbm, hg, hmem⟩ :=
    mem_head (bytes := bytes) (pre := pre ++ L ++ [99#u8]) (M := M) (R := [])
      (z := z1) (reg := dst) (rm := base) (rex_r := q.r) (rex_b := q.b) (d := disp)
      (by simp [hb]) (by simp; omega) hM (by simp; omega)
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := z1) (y := ln0) (by rw [hln0]; omega)
  have hz3v : z3.val = pre.length + (L.length + 1 + modrmDispLen base disp) := by
    rw [hz3v0, hz1v, hln0]; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Load 4#u8 true base dst disp) (disp := 0#i64)
      (pos := pos) (e := z3) (n := L.length + 1 + modrmDispLen base disp) (by omega)
  refine ⟨{ insn := x64_ir.PInsn.Load 4#u8 true base dst disp, len := ln, disp := 0#i64 },
    ?_, rfl, hln, rfl⟩
  refine decode_one_eq hq ?_
  rw [decode_insn_plain hb0 hlock (by decide)]
  rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
  rw [show x64_decode.alu_op 99#u8 = ok false from rfl]
  simp only [bind_tc_ok]
  rw [if_neg (show ¬((false : Bool) = true) from by decide)]
  simp only [if_neg (show ¬((99#u8 : Std.U8) = 139#u8) from by decide),
    if_neg (show ¬((99#u8 : Std.U8) = 141#u8) from by decide),
    if_neg (show ¬((99#u8 : Std.U8) = 198#u8) from by decide),
    if_neg (show ¬((99#u8 : Std.U8) = 199#u8) from by decide)]
  unfold x64_decode.decode_rest
  rw [if_neg (show ¬((99#u8 : Std.U8) = 61#u8) from by decide)]
  rw [if_pos (rfl : (99#u8 : Std.U8) = 99#u8)]
  simp only [hz1, hg, bind_tc_ok]
  rw [if_neg (show ¬((false : Bool) = true) from by decide)]
  rw [hmem]
  simp only [bind_tc_ok, if_true, hz3]
  rw [hqr, hqb, reg_rejoin dst hdst, reg_rejoin base hbase]
  exact hfin

theorem dec_load (size : Std.U8) (sxf : Bool) (base dst : Std.U8) (disp : Std.I32)
    (hsize : size = 1#u8 ∨ size = 2#u8 ∨ size = 4#u8 ∨ size = 8#u8)
    (hbase : base.val < 16) (hdst : dst.val < 16)
    (hne : emitsNothing (x64_ir.PInsn.Load size sxf base dst disp) = false) :
    DecodesTo (.Load size sxf base dst disp) := by
  intro bytes pos pre hb hat hfit
  have hmb := modrmDispLen_le base disp
  cases sxf with
  | false =>
    rcases hsize with rfl | rfl | rfl | rfl
    · have hbs : enc (x64_ir.PInsn.Load 1#u8 false base dst disp)
          = basicRexL 0#u8 dst base ++ (15#u8 :: 182#u8 :: modrmDispL dst base disp) := by
        show guestLoadL 1#u8 false base dst disp = _
        unfold guestLoadL loadL bitU
        simp
      obtain ⟨d, h1, h2, h3, h4⟩ :=
        dec_load_0f (L := basicRexL 0#u8 dst base) (M := modrmDispL dst base disp)
          (by rw [hb, hbs]) hat hfit (basicRexL_length_le _ _ _)
          (basicRexL_case 0#u8 dst base (by decide)) rfl hbase hdst (Or.inl ⟨rfl, rfl, rfl⟩)
      exact ⟨d, h1, h2, by rw [h3, hbs]; simp [modrmDispL_length]; omega, h4⟩
    · have hbs : enc (x64_ir.PInsn.Load 2#u8 false base dst disp)
          = basicRexL 0#u8 dst base ++ (15#u8 :: 183#u8 :: modrmDispL dst base disp) := by
        show guestLoadL 2#u8 false base dst disp = _
        unfold guestLoadL loadL bitU
        simp
      obtain ⟨d, h1, h2, h3, h4⟩ :=
        dec_load_0f (L := basicRexL 0#u8 dst base) (M := modrmDispL dst base disp)
          (by rw [hb, hbs]) hat hfit (basicRexL_length_le _ _ _)
          (basicRexL_case 0#u8 dst base (by decide)) rfl hbase hdst
          (Or.inr (Or.inl ⟨rfl, rfl, rfl⟩))
      exact ⟨d, h1, h2, by rw [h3, hbs]; simp [modrmDispL_length]; omega, h4⟩
    · have hbs : enc (x64_ir.PInsn.Load 4#u8 false base dst disp)
          = basicRexL 0#u8 dst base ++ (139#u8 :: modrmDispL dst base disp) := by
        show guestLoadL 4#u8 false base dst disp = _
        unfold guestLoadL loadL bitU
        simp
      obtain ⟨d, h1, h2, h3, h4⟩ :=
        dec_load_8b (L := basicRexL 0#u8 dst base) (M := modrmDispL dst base disp) (size := 4#u8)
          (by rw [hb, hbs]) hat hfit (basicRexL_length_le _ _ _)
          (basicRexL_case 0#u8 dst base (by decide)) rfl hbase hdst
          (by unfold x64_decode.mem_size; norm_num)
      exact ⟨d, h1, h2, by rw [h3, hbs]; simp [modrmDispL_length]; omega, h4⟩
    · have hbs : enc (x64_ir.PInsn.Load 8#u8 false base dst disp)
          = basicRexL 1#u8 dst base ++ (139#u8 :: modrmDispL dst base disp) := by
        show guestLoadL 8#u8 false base dst disp = _
        unfold guestLoadL loadL bitU
        simp
      obtain ⟨d, h1, h2, h3, h4⟩ :=
        dec_load_8b (L := basicRexL 1#u8 dst base) (M := modrmDispL dst base disp) (size := 8#u8)
          (by rw [hb, hbs]) hat hfit (basicRexL_length_le _ _ _)
          (basicRexL_case 1#u8 dst base (by decide)) rfl hbase hdst
          (by unfold x64_decode.mem_size; norm_num)
      exact ⟨d, h1, h2, by rw [h3, hbs]; simp [modrmDispL_length]; omega, h4⟩
  | true =>
    rcases hsize with rfl | rfl | rfl | rfl
    · have hbs : enc (x64_ir.PInsn.Load 1#u8 true base dst disp)
          = basicRexL 1#u8 dst base ++ (15#u8 :: 190#u8 :: modrmDispL dst base disp) := by
        show guestLoadL 1#u8 true base dst disp = _
        unfold guestLoadL loadSxL
        simp
      obtain ⟨d, h1, h2, h3, h4⟩ :=
        dec_load_0f (L := basicRexL 1#u8 dst base) (M := modrmDispL dst base disp)
          (by rw [hb, hbs]) hat hfit (basicRexL_length_le _ _ _)
          (basicRexL_case 1#u8 dst base (by decide)) rfl hbase hdst
          (Or.inr (Or.inr (Or.inl ⟨rfl, rfl, rfl⟩)))
      exact ⟨d, h1, h2, by rw [h3, hbs]; simp [modrmDispL_length]; omega, h4⟩
    · have hbs : enc (x64_ir.PInsn.Load 2#u8 true base dst disp)
          = basicRexL 1#u8 dst base ++ (15#u8 :: 191#u8 :: modrmDispL dst base disp) := by
        show guestLoadL 2#u8 true base dst disp = _
        unfold guestLoadL loadSxL
        simp
      obtain ⟨d, h1, h2, h3, h4⟩ :=
        dec_load_0f (L := basicRexL 1#u8 dst base) (M := modrmDispL dst base disp)
          (by rw [hb, hbs]) hat hfit (basicRexL_length_le _ _ _)
          (basicRexL_case 1#u8 dst base (by decide)) rfl hbase hdst
          (Or.inr (Or.inr (Or.inr ⟨rfl, rfl, rfl⟩)))
      exact ⟨d, h1, h2, by rw [h3, hbs]; simp [modrmDispL_length]; omega, h4⟩
    · have hbs : enc (x64_ir.PInsn.Load 4#u8 true base dst disp)
          = basicRexL 1#u8 dst base ++ (99#u8 :: modrmDispL dst base disp) := by
        show guestLoadL 4#u8 true base dst disp = _
        unfold guestLoadL loadSxL
        simp
      obtain ⟨d, h1, h2, h3, h4⟩ :=
        dec_load_63 (L := basicRexL 1#u8 dst base) (M := modrmDispL dst base disp)
          (by rw [hb, hbs]) hat hfit (basicRexL_length_le _ _ _)
          (basicRexL_case 1#u8 dst base (by decide)) rfl hbase hdst
      exact ⟨d, h1, h2, by rw [h3, hbs]; simp [modrmDispL_length]; omega, h4⟩
    · exact absurd hne (by simp [emitsNothing])

end X64Enc
end async_ebpf_verified

import AsyncEbpf.X64.Encode

/-!
# The encoder, checked against the decoder

`src/verified/x64_decode.rs` is an independently written inverse of the
encoder: it reads the bytes at one instruction boundary and returns the
primitive that produced them, the number of bytes it consumed and the
displacement the instruction carried. This file runs it over the encoder's
output.

`shape` is what the decoder owes: the primitive itself, except that a branch
carries a placeholder target (its label is a fact about the whole function,
not about its bytes) and except for the four collisions the decoder's module
doc lists — a `LoadImm` that fits in thirty-two bits is the same bytes as an
`AluImm … Mov`, `Mod` is `Div` and `Mul` is unsigned, `ShiftImm` and the
narrow `StoreImm` truncate their immediate, and the RIP-relative load has no
REX.R bit to carry a high destination. `emitsNothing` is the five primitives
that encode to no bytes at all. `RegsBounded` is the side conditions the
encodings need of the operands: every register is one of the sixteen, every
width one the encoder writes, every condition code one of the sixteen `0x8*`
rows, the atomic's verbatim opcode byte not a prefix, and the dispatcher
address not the start of an instruction.

`DecodesTo p` is the per-primitive statement: in a buffer whose earlier bytes
are arbitrary, the bytes the encoder appended for `p`, read at the offset it
appended them, decode to `p`'s shape, to the length `size_of` gives, and to
the placeholder displacement zero. The proof is one lemma per variant family,
over the shared machinery at the top of the file: `byte_at`, `have`, `read32`
and `read64` over an arbitrary prefix, the prefix loop, the register-form and
memory-form ModRM readers, and the displacement round-trips.

## What is covered

`DecodesTo` is proved for seventeen variant families, with every operand
symbolic: `Ret`, `Pushfq`, `Popfq`, `Cdq`, `Cqo`, `Pause`, `Ud2`,
`CmpEaxImm`, `CmpRcxMinusOne`, `Alu` (all eight operations, both widths, all
sixteen registers in both positions), `ShiftCl`, `Neg`, `Jmp`, `Call`,
`Jmp8`, `JmpNear` and `LockAlu` (all four atomic opcodes, both widths, all
sixteen base and source registers, every displacement). The shared machinery
the rest would use is proved too and is the bulk of the file:
`decode_mem_eq`, which covers every ModRM and displacement form the encoder
writes — the short form, the one-byte displacement, the four-byte
displacement, the SIB byte for `RSP`/`R12` and the forced displacement for
`RBP`/`R13` — `decode_reg2_eq` for the register form, `prefixes_opt_rex` and
`prefixes_pfx_opt_rex` for the optional REX prefix behind an optional legacy
prefix, and `read32_at`/`read64_at`/`byte_at_in` for reading an arbitrary
buffer at an arbitrary offset. The remaining families — `Push`, `Pop`,
`AluImm`, `ShiftImm`, `MulDivRcx`, `MovSx`, `Bswap`, `Rol16`, `Cmov`,
`LoadImm`, `Load`, `Store`, `StoreImm`, `AluRM`, `StoreRspImm`,
`StoreRspRax`, `LockCmpxchg`, `Xchg`, `Jcc`, `Jcc8`, `CallReg`,
`RipLoadDispatcher`, `RipLeaHelperTable`, `DispatcherSlot` and `HelperTable`
— follow the same template over the same machinery and are not yet written,
so there is no theorem here that quantifies over every primitive.

## What this does and does not establish

It moves the encoder from trusted to checked *against a second table*. The
decoder's own table is the remaining trust: if both tables named the same
wrong byte for a primitive, the round-trip would still close. Two tables
written separately from the same manual agreeing on every encoding is what
this buys, and it is the same kind of evidence a disassembler-based test
gives, made total over all operands instead of over a sweep. It says nothing
about whether the bytes mean what the machine model says they mean; that is
`X64/Machine.lean`'s axiomatisation, and it is trusted here as it is there.
-/
open Aeneas Aeneas.Std Result

set_option maxHeartbeats 4000000
set_option maxRecDepth 100000

namespace async_ebpf_verified
namespace X64Enc

/-! ## Reading the buffer -/

/-- A byte as `byte_at` returns it. -/
def sxB (b : Std.U8) : Std.I32 := UScalar.hcast .I32 b

/-- Four bytes, little-endian, as `read32` returns them. -/
def u32of (b0 b1 b2 b3 : Std.U8) : Std.U32 :=
  ⟨((b0.bv.setWidth 32 ||| (b1.bv.setWidth 32 <<< 8)) ||| (b2.bv.setWidth 32 <<< 16))
    ||| (b3.bv.setWidth 32 <<< 24)⟩

theorem slice_index_eq {α} [Inhabited α] {v : Slice α} {i : Usize} (h : i.val < v.val.length) :
    Slice.index_usize v i = ok v.val[i.val]! := by
  unfold Slice.index_usize
  rw [show v[i]? = v.val[i.val]? from rfl, List.getElem?_eq_getElem h]
  simp [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem h]

theorem byte_at_in {bytes : Slice Std.U8} {i : Usize} {pre bs : List Std.U8} {k : Nat}
    (hb : bytes.val = pre ++ bs) (hi : i.val = pre.length + k) (hk : k < bs.length) :
    x64_decode.byte_at bytes i = ok (sxB bs[k]!) := by
  have hlt : i.val < bytes.val.length := by rw [hb]; simp; omega
  unfold x64_decode.byte_at
  rw [if_pos (by rw [UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length]; omega)]
  rw [slice_index_eq hlt, hb, hi, getBang_append_right _ _ _ (by omega)]
  simp [sxB]

theorem byte_at_out {bytes : Slice Std.U8} {i : Usize} {pre bs : List Std.U8} {k : Nat}
    (hb : bytes.val = pre ++ bs) (hi : i.val = pre.length + k) (hk : bs.length ≤ k) :
    x64_decode.byte_at bytes i = ok (-1)#i32 := by
  unfold x64_decode.byte_at
  rw [if_neg (by rw [UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length, hb]; simp; omega)]

theorem have_at {bytes : Slice Std.U8} {i n : Usize} {pre bs : List Std.U8} {k : Nat}
    (hb : bytes.val = pre ++ bs) (hi : i.val = pre.length + k)
    (hfit : i.val + n.val ≤ Usize.max) :
    x64_decode.have bytes i n = ok (decide (k + n.val ≤ bs.length)) := by
  unfold x64_decode.have
  obtain ⟨z, hz, hzv⟩ := usize_add_ok hfit
  rw [hz]
  simp only [bind_tc_ok, ok.injEq]
  have hlen : (Slice.len bytes).val = pre.length + bs.length := by
    rw [Slice.len_val]; simp only [Slice.length, hb]; simp
  simp only [decide_eq_decide]
  rw [UScalar.le_equiv, hlen, hzv, hi]
  omega

/-- Eight bytes, little-endian, as `read64` returns them. -/
def u64of (b0 b1 b2 b3 b4 b5 b6 b7 : Std.U8) : Std.U64 :=
  ⟨((((((b0.bv.setWidth 64 ||| (b1.bv.setWidth 64 <<< 8)) ||| (b2.bv.setWidth 64 <<< 16))
      ||| (b3.bv.setWidth 64 <<< 24)) ||| (b4.bv.setWidth 64 <<< 32))
      ||| (b5.bv.setWidth 64 <<< 40)) ||| (b6.bv.setWidth 64 <<< 48))
      ||| (b7.bv.setWidth 64 <<< 56)⟩

theorem index_at {bytes : Slice Std.U8} {i : Usize} {pre bs : List Std.U8} (k : Nat)
    (hb : bytes.val = pre ++ bs) (hi : i.val = pre.length + k) (hk : k < bs.length) :
    Slice.index_usize bytes i = ok bs[k]! := by
  have hlt : i.val < bytes.val.length := by rw [hb]; simp; omega
  rw [slice_index_eq hlt, hb, hi, getBang_append_right _ _ _ (by omega)]
  simp

theorem read32_at {bytes : Slice Std.U8} {i : Usize} {pre bs : List Std.U8} {k : Nat}
    (hb : bytes.val = pre ++ bs) (hi : i.val = pre.length + k) (hk : k + 4 ≤ bs.length)
    (hfit : i.val + 4 ≤ Usize.max) :
    x64_decode.read32 bytes i = ok (u32of bs[k]! bs[k + 1]! bs[k + 2]! bs[k + 3]!) := by
  unfold x64_decode.read32
  rw [have_at hb hi (by simpa using hfit)]
  simp only [bind_tc_ok]
  rw [if_pos (by simp; omega)]
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := i) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = i.val + 1 := by simpa using hz1v0
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := i) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = i.val + 2 := by simpa using hz2v0
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := i) (y := 3#usize) (by simp; omega)
  have hz3v : z3.val = i.val + 3 := by simpa using hz3v0
  have e0 : Slice.index_usize bytes i = ok bs[k]! := index_at k hb hi (by omega)
  have e1 : Slice.index_usize bytes z1 = ok bs[k + 1]! :=
    index_at (k + 1) hb (by omega) (by omega)
  have e2 : Slice.index_usize bytes z2 = ok bs[k + 2]! :=
    index_at (k + 2) hb (by omega) (by omega)
  have e3 : Slice.index_usize bytes z3 = ok bs[k + 3]! :=
    index_at (k + 3) hb (by omega) (by omega)
  simp only [e0, e1, e2, e3, hz1, hz2, hz3, bind_tc_ok, lift]
  rfl

theorem read64_at {bytes : Slice Std.U8} {i : Usize} {pre bs : List Std.U8} {k : Nat}
    (hb : bytes.val = pre ++ bs) (hi : i.val = pre.length + k) (hk : k + 8 ≤ bs.length)
    (hfit : i.val + 8 ≤ Usize.max) :
    x64_decode.read64 bytes i = ok (u64of bs[k]! bs[k + 1]! bs[k + 2]! bs[k + 3]! bs[k + 4]! bs[k + 5]! bs[k + 6]! bs[k + 7]!) := by
  unfold x64_decode.read64
  rw [have_at hb hi (by simpa using hfit)]
  simp only [bind_tc_ok]
  rw [if_pos (by simp; omega)]
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := i) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = i.val + 1 := by simpa using hz1v0
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := i) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = i.val + 2 := by simpa using hz2v0
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := i) (y := 3#usize) (by simp; omega)
  have hz3v : z3.val = i.val + 3 := by simpa using hz3v0
  obtain ⟨z4, hz4, hz4v0⟩ := usize_add_ok (x := i) (y := 4#usize) (by simp; omega)
  have hz4v : z4.val = i.val + 4 := by simpa using hz4v0
  obtain ⟨z5, hz5, hz5v0⟩ := usize_add_ok (x := i) (y := 5#usize) (by simp; omega)
  have hz5v : z5.val = i.val + 5 := by simpa using hz5v0
  obtain ⟨z6, hz6, hz6v0⟩ := usize_add_ok (x := i) (y := 6#usize) (by simp; omega)
  have hz6v : z6.val = i.val + 6 := by simpa using hz6v0
  obtain ⟨z7, hz7, hz7v0⟩ := usize_add_ok (x := i) (y := 7#usize) (by simp; omega)
  have hz7v : z7.val = i.val + 7 := by simpa using hz7v0
  have e0 : Slice.index_usize bytes i = ok bs[k]! := index_at k hb hi (by omega)
  have e1 : Slice.index_usize bytes z1 = ok bs[k + 1]! :=
    index_at (k + 1) hb (by omega) (by omega)
  have e2 : Slice.index_usize bytes z2 = ok bs[k + 2]! :=
    index_at (k + 2) hb (by omega) (by omega)
  have e3 : Slice.index_usize bytes z3 = ok bs[k + 3]! :=
    index_at (k + 3) hb (by omega) (by omega)
  have e4 : Slice.index_usize bytes z4 = ok bs[k + 4]! :=
    index_at (k + 4) hb (by omega) (by omega)
  have e5 : Slice.index_usize bytes z5 = ok bs[k + 5]! :=
    index_at (k + 5) hb (by omega) (by omega)
  have e6 : Slice.index_usize bytes z6 = ok bs[k + 6]! :=
    index_at (k + 6) hb (by omega) (by omega)
  have e7 : Slice.index_usize bytes z7 = ok bs[k + 7]! :=
    index_at (k + 7) hb (by omega) (by omega)
  simp only [e0, e1, e2, e3, e4, e5, e6, e7, hz1, hz2, hz3, hz4, hz5, hz6, hz7, bind_tc_ok, lift]
  rfl

/-! ## The prefixes -/

/-- The `W`, `R` and `B` bits a REX byte carries, as the decoder reads them. -/
def pfxW (c : Std.U8) : Std.U8 := (⟨c.bv >>> 3⟩ : Std.U8) &&& 1#u8
def pfxR (c : Std.U8) : Std.U8 := (⟨c.bv >>> 2⟩ : Std.U8) &&& 1#u8

def pfxB (c : Std.U8) : Std.U8 := c &&& 1#u8

/-- A byte that starts no prefix. -/
def notPfx (c : Std.U8) : Prop :=
  c ≠ 240#u8 ∧ c ≠ 102#u8 ∧ c ≠ 243#u8 ∧ ¬(64 ≤ c.val ∧ c.val ≤ 79)

instance (c : Std.U8) : Decidable (notPfx c) := by unfold notPfx; infer_instance

theorem prefixes_loop_stop {bytes : Slice Std.U8} {b b1 b2 : Bool} {i i1 i2 : Std.U8}
    {n i3 : Usize} :
    x64_decode.prefixes_loop bytes b b1 b2 i i1 i2 n i3 false = ok (b, b1, b2, i, i1, i2, i3) := by
  unfold x64_decode.prefixes_loop
  rw [loop.eq_def]
  simp [x64_decode.prefixes_loop.body]

theorem prefixes_loop_notPfx {bytes : Slice Std.U8} {b b1 b2 : Bool} {i i1 i2 : Std.U8}
    {i3 : Usize} {c : Std.U8}
    (hlt : i3.val < bytes.val.length) (hc : bytes.val[i3.val]! = c) (hn : notPfx c) :
    x64_decode.prefixes_loop bytes b b1 b2 i i1 i2 (Slice.len bytes) i3 true
      = ok (b, b1, b2, i, i1, i2, i3) := by
  obtain ⟨h1, h2, h3, h4⟩ := hn
  unfold x64_decode.prefixes_loop
  rw [loop.eq_def]
  simp only [x64_decode.prefixes_loop.body, if_true]
  rw [if_pos (by rw [UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length]; omega)]
  rw [slice_index_eq hlt, hc]
  simp only [bind_tc_ok]
  rw [if_neg h1, if_neg h2, if_neg h3]
  by_cases hge : 64 ≤ c.val
  · have hge' : c ≥ 64#u8 := by rw [ge_iff_le, UScalar.le_equiv]; simpa using hge
    have hgt : ¬ (c ≤ 79#u8) := by rw [UScalar.le_equiv]; simp; omega
    rw [if_pos hge', if_neg hgt]
    exact prefixes_loop_stop
  · have hge' : ¬ (c ≥ 64#u8) := by rw [ge_iff_le, UScalar.le_equiv]; simp; omega
    rw [if_neg hge']
    exact prefixes_loop_stop

theorem prefixes_loop_rex {bytes : Slice Std.U8} {b b1 b2 : Bool} {i i1 i2 : Std.U8}
    {i3 z : Usize} {c : Std.U8}
    (hlt : i3.val < bytes.val.length) (hc : bytes.val[i3.val]! = c)
    (hr : 64 ≤ c.val ∧ c.val ≤ 79) (hzok : i3 + 1#usize = ok z) :
    x64_decode.prefixes_loop bytes b b1 b2 i i1 i2 (Slice.len bytes) i3 true
      = ok (b, b1, b2, pfxW c, pfxR c, pfxB c, z) := by
  obtain ⟨hr1, hr2⟩ := hr
  have h1 : c ≠ 240#u8 := by intro hh; rw [hh] at hr2; simp at hr2
  have h2 : c ≠ 102#u8 := by intro hh; rw [hh] at hr2; simp at hr2
  have h3 : c ≠ 243#u8 := by intro hh; rw [hh] at hr2; simp at hr2
  have hge : c ≥ 64#u8 := by rw [ge_iff_le, UScalar.le_equiv]; simpa using hr1
  have hle : c ≤ 79#u8 := by rw [UScalar.le_equiv]; simpa using hr2
  unfold x64_decode.prefixes_loop
  rw [loop.eq_def]
  simp only [x64_decode.prefixes_loop.body, if_true]
  rw [if_pos (by rw [UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length]; omega)]
  rw [slice_index_eq hlt, hc]
  simp only [bind_tc_ok]
  rw [if_neg h1, if_neg h2, if_neg h3, if_pos hge, if_pos hle]
  simp only [hzok, bind_tc_ok, lift, pfxW, pfxR, pfxB]
  exact prefixes_loop_stop

/-- One prefix byte consumed: the loop carries on one byte further. -/
theorem prefixes_loop_pfx {bytes : Slice Std.U8} {b b1 b2 : Bool} {i i1 i2 : Std.U8}
    {i3 z : Usize} {c : Std.U8}
    (hlt : i3.val < bytes.val.length) (hc : bytes.val[i3.val]! = c) (hzok : i3 + 1#usize = ok z)
    (hpfx : c = 240#u8 ∨ c = 102#u8 ∨ c = 243#u8) :
    x64_decode.prefixes_loop bytes b b1 b2 i i1 i2 (Slice.len bytes) i3 true
      = x64_decode.prefixes_loop bytes (b || c = 240#u8) (b1 || c = 102#u8) (b2 || c = 243#u8)
          i i1 i2 (Slice.len bytes) z true := by
  unfold x64_decode.prefixes_loop
  conv_lhs => rw [loop.eq_def]
  simp only [x64_decode.prefixes_loop.body, if_true]
  rw [if_pos (by rw [UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length]; omega)]
  rw [slice_index_eq hlt, hc]
  simp only [bind_tc_ok]
  rcases hpfx with h | h | h <;> subst h <;> simp [hzok]

theorem buf_get {bytes : Slice Std.U8} {pre bs : List Std.U8} (hb : bytes.val = pre ++ bs)
    (k : Nat) (hk : k < bs.length) :
    bytes.val[pre.length + k]! = bs[k]! ∧ pre.length + k < bytes.val.length := by
  refine ⟨?_, ?_⟩
  · rw [hb, getBang_append_right _ _ _ (by omega)]; simp
  · rw [hb]; simp; omega

theorem prefixes_of_loop {bytes : Slice Std.U8} {«at» : Usize} {lk o16 rp : Bool}
    {w r bb : Std.U8} {q : Usize}
    (h : x64_decode.prefixes_loop bytes false false false 0#u8 0#u8 0#u8 (Slice.len bytes) «at» true
          = ok (lk, o16, rp, w, r, bb, q)) :
    x64_decode.prefixes bytes «at» =
      ok { lock := lk, op16 := o16, rep := rp, w := w, r := r, b := bb, «at» := q } := by
  unfold x64_decode.prefixes
  simp only [h, bind_tc_ok]
  rfl

/-- No prefix byte at all. -/
theorem prefixes_plain {bytes : Slice Std.U8} {«at» : Usize} {pre bs : List Std.U8}
    (hb : bytes.val = pre ++ bs) (hat : «at».val = pre.length)
    (h0 : 0 < bs.length) (hn : notPfx bs[0]!) :
    x64_decode.prefixes bytes «at» =
      ok { lock := false, op16 := false, rep := false, w := 0#u8, r := 0#u8, b := 0#u8,
           «at» := «at» } := by
  obtain ⟨hg, hl⟩ := buf_get hb 0 h0
  rw [Nat.add_zero] at hg hl
  exact prefixes_of_loop (prefixes_loop_notPfx (by omega) (by rw [hat]; exact hg) hn)

/-- One REX byte. -/
theorem prefixes_rex1 {bytes : Slice Std.U8} {«at» : Usize} {pre bs : List Std.U8}
    (hb : bytes.val = pre ++ bs) (hat : «at».val = pre.length)
    (h0 : 0 < bs.length) (hr : 64 ≤ (bs[0]!).val ∧ (bs[0]!).val ≤ 79)
    (hfit : pre.length + 1 ≤ Usize.max) :
    ∃ q : Usize, q.val = pre.length + 1 ∧
      x64_decode.prefixes bytes «at» =
        ok { lock := false, op16 := false, rep := false,
             w := pfxW bs[0]!, r := pfxR bs[0]!, b := pfxB bs[0]!, «at» := q } := by
  obtain ⟨hg, hl⟩ := buf_get hb 0 h0
  rw [Nat.add_zero] at hg hl
  obtain ⟨z, hz, hzv0⟩ := usize_add_ok (x := «at») (y := 1#usize) (by simp; omega)
  have hzv : z.val = pre.length + 1 := by simp at hzv0; omega
  exact ⟨z, hzv, prefixes_of_loop (prefixes_loop_rex (by omega) (by rw [hat]; exact hg) hr hz)⟩

/-- One legacy prefix byte, then a byte that starts no prefix. -/
theorem prefixes_p1 {bytes : Slice Std.U8} {«at» : Usize} {pre bs : List Std.U8}
    (hb : bytes.val = pre ++ bs) (hat : «at».val = pre.length)
    (h1 : 1 < bs.length) (hp : bs[0]! = 240#u8 ∨ bs[0]! = 102#u8 ∨ bs[0]! = 243#u8)
    (hn : notPfx bs[1]!) (hfit : pre.length + 1 ≤ Usize.max) :
    ∃ q : Usize, q.val = pre.length + 1 ∧
      x64_decode.prefixes bytes «at» =
        ok { lock := decide (bs[0]! = 240#u8), op16 := decide (bs[0]! = 102#u8),
             rep := decide (bs[0]! = 243#u8), w := 0#u8, r := 0#u8, b := 0#u8, «at» := q } := by
  obtain ⟨hg0, hl0⟩ := buf_get hb 0 (by omega)
  obtain ⟨hg1, hl1⟩ := buf_get hb 1 (by omega)
  rw [Nat.add_zero] at hg0 hl0
  obtain ⟨z, hz, hzv0⟩ := usize_add_ok (x := «at») (y := 1#usize) (by simp; omega)
  have hzv : z.val = pre.length + 1 := by simp at hzv0; omega
  refine ⟨z, hzv, prefixes_of_loop ?_⟩
  rw [prefixes_loop_pfx (c := bs[0]!) (by omega) (by rw [hat]; exact hg0) hz hp]
  simpa using prefixes_loop_notPfx (c := bs[1]!) (by omega) (by rw [hzv]; exact hg1) hn

/-- One legacy prefix byte, then a REX byte. -/
theorem prefixes_p1_rex {bytes : Slice Std.U8} {«at» : Usize} {pre bs : List Std.U8}
    (hb : bytes.val = pre ++ bs) (hat : «at».val = pre.length)
    (h1 : 1 < bs.length) (hp : bs[0]! = 240#u8 ∨ bs[0]! = 102#u8 ∨ bs[0]! = 243#u8)
    (hr : 64 ≤ (bs[1]!).val ∧ (bs[1]!).val ≤ 79) (hfit : pre.length + 2 ≤ Usize.max) :
    ∃ q : Usize, q.val = pre.length + 2 ∧
      x64_decode.prefixes bytes «at» =
        ok { lock := decide (bs[0]! = 240#u8), op16 := decide (bs[0]! = 102#u8),
             rep := decide (bs[0]! = 243#u8),
             w := pfxW bs[1]!, r := pfxR bs[1]!, b := pfxB bs[1]!, «at» := q } := by
  obtain ⟨hg0, hl0⟩ := buf_get hb 0 (by omega)
  obtain ⟨hg1, hl1⟩ := buf_get hb 1 (by omega)
  rw [Nat.add_zero] at hg0 hl0
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := «at») (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + 1 := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := z1) (y := 1#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + 2 := by simp at hz2v0; omega
  refine ⟨z2, hz2v, prefixes_of_loop ?_⟩
  rw [prefixes_loop_pfx (c := bs[0]!) (by omega) (by rw [hat]; exact hg0) hz1 hp]
  simpa using prefixes_loop_rex (c := bs[1]!) (by omega) (by rw [hz1v]; exact hg1) hr hz2

/-! ## ModRM -/

/-- A byte shifted right. -/
def shrU (x : Std.U8) (k : Nat) : Std.U8 := ⟨x.bv >>> k⟩

@[simp] theorem shrU3_eq (x : Std.U8) : x >>> 3#i32 = ok (shrU x 3) := rfl
@[simp] theorem shrU2_eq (x : Std.U8) : x >>> 2#i32 = ok (shrU x 2) := rfl

/-- The ModRM `reg` field alone. -/
def mExt (c : Std.U8) : Std.U8 := shrU c 3 &&& 7#u8
/-- The ModRM `reg` field with REX.R. -/
def mReg (c rex_r : Std.U8) : Std.U8 := mExt c ||| shlU rex_r 3
/-- The ModRM `rm` field with REX.B. -/
def mRm (c rex_b : Std.U8) : Std.U8 := (c &&& 7#u8) ||| shlU rex_b 3

theorem sxB_val (b : Std.U8) : (sxB b).val = (b.val : Int) := by
  have h := UScalar.hcast_inBounds_spec (src_ty := .U8) .I32 b (by scalar_tac)
  simpa [lift, sxB] using h

theorem sxB_nonneg (b : Std.U8) : sxB b ≥ 0#i32 := by
  rw [ge_iff_le, IScalar.le_equiv, sxB_val]
  simp

theorem sxB_back (b : Std.U8) : (IScalar.hcast .U8 (sxB b) : Std.U8) = b := by
  apply UScalar.eq_of_val_eq
  have h := IScalar.hcast_inBounds_spec (src_ty := .I32) .U8 (sxB b)
    ⟨by rw [sxB_val]; simp, by rw [sxB_val]; scalar_tac⟩
  simp only [lift, WP.spec_ok] at h
  rw [sxB_val] at h
  exact_mod_cast h

theorem bv_modrm_and192 (md r m : BitVec 8) :
    (((md &&& 192#8) ||| ((r &&& 7#8) <<< 3)) ||| (m &&& 7#8)) &&& 192#8 = md &&& 192#8 := by bits8

theorem bv_modrm_ext (md r m : BitVec 8) :
    ((((md &&& 192#8) ||| ((r &&& 7#8) <<< 3)) ||| (m &&& 7#8)) >>> 3) &&& 7#8 = r &&& 7#8 := by
  bits8

theorem bv_modrm_and7 (md r m : BitVec 8) :
    (((md &&& 192#8) ||| ((r &&& 7#8) <<< 3)) ||| (m &&& 7#8)) &&& 7#8 = m &&& 7#8 := by bits8

@[simp] theorem modrmB_and192 (md r m : Std.U8) : (modrmB md r m) &&& 192#u8 = md &&& 192#u8 := by
  apply U8.bv_eq_imp_eq; exact bv_modrm_and192 md.bv r.bv m.bv

@[simp] theorem modrmB_ext (md r m : Std.U8) : shrU (modrmB md r m) 3 &&& 7#u8 = r &&& 7#u8 := by
  apply U8.bv_eq_imp_eq; exact bv_modrm_ext md.bv r.bv m.bv

@[simp] theorem modrmB_and7 (md r m : Std.U8) : (modrmB md r m) &&& 7#u8 = m &&& 7#u8 := by
  apply U8.bv_eq_imp_eq; exact bv_modrm_and7 md.bv r.bv m.bv

theorem decode_reg2_eq {bytes : Slice Std.U8} {«at» : Usize} {pre bs : List Std.U8} {k : Nat}
    {rex_r rex_b : Std.U8} (hb : bytes.val = pre ++ bs) (hat : «at».val = pre.length + k)
    (hk : k < bs.length) (hmod : bs[k]! &&& 192#u8 = 192#u8) :
    x64_decode.decode_reg2 bytes «at» rex_r rex_b =
      ok { ok := true, reg := mReg bs[k]! rex_r, rm := mRm bs[k]! rex_b, ext := mExt bs[k]! } := by
  unfold x64_decode.decode_reg2
  rw [byte_at_in hb hat hk]
  simp only [bind_tc_ok, lift]
  rw [if_pos (sxB_nonneg _)]
  simp only [sxB_back]
  rw [if_pos hmod]
  simp only [shrU3_eq, shlU3, bind_tc_ok, lift, mReg, mRm, mExt]

theorem decode_reg2_ne {bytes : Slice Std.U8} {«at» : Usize} {pre bs : List Std.U8} {k : Nat}
    {rex_r rex_b : Std.U8} (hb : bytes.val = pre ++ bs) (hat : «at».val = pre.length + k)
    (hk : k < bs.length) (hmod : bs[k]! &&& 192#u8 ≠ 192#u8) :
    x64_decode.decode_reg2 bytes «at» rex_r rex_b =
      ok { ok := false, reg := 0#u8, rm := 0#u8, ext := 0#u8 } := by
  unfold x64_decode.decode_reg2
  rw [byte_at_in hb hat hk]
  simp only [bind_tc_ok, lift]
  rw [if_pos (sxB_nonneg _)]
  simp only [sxB_back]
  rw [if_neg hmod]

/-! ## Displacements -/

theorem disp8_bv (x : BitVec 32) (h1 : -128 ≤ x.toInt) (h2 : x.toInt ≤ 127) :
    ((((x.signExtend 8).zeroExtend 8).signExtend 64).signExtend 32) = x := by
  apply BitVec.eq_of_toInt_eq
  have e8 : (x.signExtend 8).toInt = x.toInt := by
    rw [BitVec.signExtend, BitVec.toInt_ofInt_eq_self (by omega) (by norm_num; omega)
      (by norm_num; omega)]
  have e64 : ((x.signExtend 8).signExtend 64).toInt = x.toInt := by
    rw [BitVec.signExtend, e8,
      BitVec.toInt_ofInt_eq_self (by omega) (by norm_num; omega) (by norm_num; omega)]
  have e32 : (((x.signExtend 8).signExtend 64).signExtend 32).toInt = x.toInt := by
    rw [BitVec.signExtend, e64,
      BitVec.toInt_ofInt_eq_self (by omega) (by norm_num; omega) (by norm_num; omega)]
  simp only [BitVec.zeroExtend_eq_setWidth, BitVec.setWidth_eq]
  exact e32

theorem u32of_bv (y : BitVec 32) :
    ((((y.setWidth 8).setWidth 32 ||| ((y >>> 8).setWidth 8).setWidth 32 <<< 8)
      ||| ((y >>> 16).setWidth 8).setWidth 32 <<< 16)
      ||| ((y >>> 24).setWidth 8).setWidth 32 <<< 24) = y := by bits32

theorem nearDisp_bounds (d : Std.I32) (h : nearDispB d = true) : -128 ≤ d.val ∧ d.val ≤ 127 := by
  unfold nearDispB at h
  split at h
  · rename_i hge
    rw [ge_iff_le, IScalar.le_equiv] at hge
    simp only [decide_eq_true_eq] at h
    rw [IScalar.le_equiv] at h
    simpa using ⟨hge, h⟩
  · simp at h

theorem disp8_roundtrip (d : Std.I32) (h : nearDispB d = true) :
    (IScalar.cast (src_ty := .I64) .I32 (IScalar.cast (src_ty := .I8) .I64
       (UScalar.hcast (src_ty := .U8) .I8 (IScalar.hcast (src_ty := .I32) .U8 d)))) = d := by
  obtain ⟨hlo, hhi⟩ := nearDisp_bounds d h
  simp only [IScalar.val] at hlo hhi
  apply I32.bv_eq_imp_eq
  exact disp8_bv d.bv hlo hhi

theorem u32of_lo8 (y : Std.U32) :
    u32of (lo8 y.bv) (lo8 (y.bv >>> 8)) (lo8 (y.bv >>> 16)) (lo8 (y.bv >>> 24)) = y := by
  apply U32.bv_eq_imp_eq
  exact u32of_bv y.bv

theorem sib_iff (rm : Std.U8) :
    (rm &&& 7#u8 = 4#u8) ↔ (rm &&& 15#u8 = 4#u8 ∨ rm &&& 15#u8 = 12#u8) :=
  u8_cases (P := fun rm => (rm &&& 7#u8 = 4#u8) ↔ (rm &&& 15#u8 = 4#u8 ∨ rm &&& 15#u8 = 12#u8))
    (by decide) rm

theorem rm5_iff (rm : Std.U8) :
    (rm &&& 7#u8 = 5#u8) ↔ (rm &&& 15#u8 = 5#u8 ∨ rm &&& 15#u8 = 13#u8) :=
  u8_cases (P := fun rm => (rm &&& 7#u8 = 5#u8) ↔ (rm &&& 15#u8 = 5#u8 ∨ rm &&& 15#u8 = 13#u8))
    (by decide) rm

theorem needsSib_iff (rm : Std.U8) : needsSibB (rm &&& 15#u8) = decide (rm &&& 7#u8 = 4#u8) := by
  unfold needsSibB
  simp only [decide_eq_decide]
  exact (sib_iff rm).symm

theorem needsDisp_iff (rm : Std.U8) :
    needsDispB (rm &&& 15#u8) = decide (rm &&& 7#u8 = 4#u8 ∨ rm &&& 7#u8 = 5#u8) := by
  unfold needsDispB
  simp only [decide_eq_decide]
  rw [sib_iff, rm5_iff]
  tauto

@[simp] theorem and15_and7 (r : Std.U8) : (r &&& 15#u8) &&& 7#u8 = r &&& 7#u8 :=
  u8_cases (P := fun r => (r &&& 15#u8) &&& 7#u8 = r &&& 7#u8) (by decide) r

/-- The short ModRM form: no displacement byte. -/
theorem decode_mem_short {bytes : Slice Std.U8} {«at» : Usize} {pre bs rest : List Std.U8}
    {reg rm rex_r rex_b : Std.U8} {d : Std.I32}
    (hb : bytes.val = pre ++ bs) (hat : «at».val = pre.length)
    (hbs : bs = modrmDispL reg rm d ++ rest)
    (hA : d = 0#i32 ∧ needsDispB (rm &&& 15#u8) = false) :
    x64_decode.decode_mem bytes «at» rex_r rex_b =
      ok { ok := true, reg := (reg &&& 7#u8) ||| shlU rex_r 3,
           base := (rm &&& 7#u8) ||| shlU rex_b 3, disp := d, len := 1#usize } := by
  obtain ⟨hd0, hnd⟩ := hA
  have hlist : modrmDispL reg rm d = [modrmB 0#u8 (reg &&& 15#u8) (rm &&& 15#u8)] := by
    unfold modrmDispL; rw [if_pos ⟨hd0, hnd⟩]
  rw [needsDisp_iff] at hnd
  simp only [decide_eq_false_iff_not, not_or] at hnd
  obtain ⟨hrm4, hrm5⟩ := hnd
  have hget : bs[0]! = modrmB 0#u8 (reg &&& 15#u8) (rm &&& 15#u8) := by
    rw [hbs, hlist]; simp
  have hlen : 0 < bs.length := by rw [hbs, hlist]; simp
  unfold x64_decode.decode_mem
  rw [byte_at_in hb (by omega) hlen, hget]
  simp only [bind_tc_ok, lift]
  rw [if_pos (sxB_nonneg _)]
  simp only [sxB_back, shrU3_eq, shlU3, bind_tc_ok, lift, modrmB_and192, modrmB_and7,
    modrmB_ext, and15_and7]
  rw [if_neg hrm4]
  simp only [bind_tc_ok]
  rw [if_neg hrm4]
  simp only [bind_tc_ok]
  rw [if_neg (show ¬((0#u8 : Std.U8) &&& 192#u8 = 192#u8) by decide)]
  rw [if_pos trivial]
  rw [if_pos (show (0#u8 : Std.U8) &&& 192#u8 = 0#u8 by decide)]
  rw [if_pos (show (rm &&& 7#u8 != 4#u8) = true by simpa using hrm4)]
  rw [if_pos (show (rm &&& 7#u8 != 5#u8) = true by simpa using hrm5)]
  rw [hd0]

/-- The one-byte-displacement ModRM form. -/
theorem decode_mem_near {bytes : Slice Std.U8} {«at» : Usize} {pre bs rest : List Std.U8}
    {reg rm rex_r rex_b : Std.U8} {d : Std.I32}
    (hb : bytes.val = pre ++ bs) (hat : «at».val = pre.length)
    (hbs : bs = modrmDispL reg rm d ++ rest)
    (hA : ¬(d = 0#i32 ∧ needsDispB (rm &&& 15#u8) = false))
    (hnear : nearDispB d = true) (hfit : pre.length + 8 ≤ Usize.max) :
    ∃ ln : Usize, ln.val = modrmDispLen rm d ∧
      x64_decode.decode_mem bytes «at» rex_r rex_b =
        ok { ok := true, reg := (reg &&& 7#u8) ||| shlU rex_r 3,
             base := (rm &&& 7#u8) ||| shlU rex_b 3, disp := d, len := ln } := by
  have hlist : modrmDispL reg rm d =
      modrmB 64#u8 (reg &&& 15#u8) (rm &&& 15#u8)
        :: ((if needsSibB (rm &&& 15#u8) then [36#u8] else []) ++ [IScalar.hcast .U8 d]) := by
    unfold modrmDispL; rw [if_neg hA]; simp only [hnear, if_true]
  have hmdl : modrmDispLen rm d = 1 + ((if needsSibB (rm &&& 15#u8) then 1 else 0) + 1) := by
    unfold modrmDispLen; rw [if_neg hA]; simp only [hnear, if_true]
  have hsibiff := needsSib_iff rm
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := «at») (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + 1 := by simp at hz1v0; omega
  unfold x64_decode.decode_mem
  by_cases hsib : needsSibB (rm &&& 15#u8) = true
  · -- with a SIB byte
    have hrm4 : rm &&& 7#u8 = 4#u8 := by rw [hsibiff] at hsib; simpa using hsib
    have hget0 : bs[0]! = modrmB 64#u8 (reg &&& 15#u8) (rm &&& 15#u8) := by
      rw [hbs, hlist, hsib]; simp
    have hget1 : bs[1]! = 36#u8 := by rw [hbs, hlist, hsib]; simp
    have hget2 : bs[2]! = IScalar.hcast .U8 d := by rw [hbs, hlist, hsib]; simp
    have hlen : 2 < bs.length := by rw [hbs, hlist, hsib]; simp
    obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := z1) (y := 1#usize) (by simp; omega)
    have hz2v : z2.val = pre.length + 2 := by simp at hz2v0; omega
    obtain ⟨ln, hln, hlnv0⟩ := usize_add_ok (x := 2#usize) (y := 1#usize) (by scalar_tac)
    have hlnval : ln.val = 3 := by simp at hlnv0; omega
    refine ⟨ln, by rw [hmdl]; simp [hsib, hlnval], ?_⟩
    rw [byte_at_in (k := 0) hb (by omega) (by omega), hget0]
    simp only [bind_tc_ok, lift]
    rw [if_pos (sxB_nonneg _)]
    simp only [sxB_back, shrU3_eq, shlU3, bind_tc_ok, lift, modrmB_and192, modrmB_and7,
      modrmB_ext, and15_and7]
    rw [if_pos hrm4]
    simp only [bind_tc_ok]
    rw [if_pos hrm4]
    simp only [hz1, bind_tc_ok]
    rw [byte_at_in (k := 1) hb (by omega) (by omega), hget1]
    simp only [bind_tc_ok]
    rw [if_neg (show ¬((64#u8 : Std.U8) &&& 192#u8 = 192#u8) by decide)]
    rw [if_pos (show (decide (sxB 36#u8 = 36#i32)) = true by decide)]
    rw [if_neg (show ¬((64#u8 : Std.U8) &&& 192#u8 = 0#u8) by decide)]
    rw [if_pos (show (64#u8 : Std.U8) &&& 192#u8 = 64#u8 by decide)]
    simp only [hz1, hz2, bind_tc_ok]
    rw [byte_at_in (k := 2) hb (by omega) (by omega), hget2]
    simp only [bind_tc_ok]
    rw [if_pos (sxB_nonneg _)]
    unfold x64_decode.sx8
    simp only [sxB_back, bind_tc_ok, lift, hln, disp8_roundtrip d hnear]
  · -- without a SIB byte
    have hrm4 : ¬ (rm &&& 7#u8 = 4#u8) := by
      rw [hsibiff] at hsib; simpa using hsib
    simp only [Bool.not_eq_true] at hsib
    have hget0 : bs[0]! = modrmB 64#u8 (reg &&& 15#u8) (rm &&& 15#u8) := by
      rw [hbs, hlist, hsib]; simp
    have hget1 : bs[1]! = IScalar.hcast .U8 d := by rw [hbs, hlist, hsib]; simp
    have hlen : 1 < bs.length := by rw [hbs, hlist, hsib]; simp
    obtain ⟨ln, hln, hlnv0⟩ := usize_add_ok (x := 2#usize) (y := 0#usize) (by scalar_tac)
    have hlnval : ln.val = 2 := by simp at hlnv0; omega
    refine ⟨ln, by rw [hmdl]; simp [hsib, hlnval], ?_⟩
    rw [byte_at_in (k := 0) hb (by omega) (by omega), hget0]
    simp only [bind_tc_ok, lift]
    rw [if_pos (sxB_nonneg _)]
    simp only [sxB_back, shrU3_eq, shlU3, bind_tc_ok, lift, modrmB_and192, modrmB_and7,
      modrmB_ext, and15_and7]
    rw [if_neg hrm4]
    simp only [bind_tc_ok]
    rw [if_neg hrm4]
    simp only [bind_tc_ok]
    rw [if_neg (show ¬((64#u8 : Std.U8) &&& 192#u8 = 192#u8) by decide)]
    rw [if_pos trivial]
    rw [if_neg (show ¬((64#u8 : Std.U8) &&& 192#u8 = 0#u8) by decide)]
    rw [if_pos (show (64#u8 : Std.U8) &&& 192#u8 = 64#u8 by decide)]
    obtain ⟨z1', hz1', hz1'v0⟩ := usize_add_ok (x := z1) (y := 0#usize) (by simp; omega)
    have hz1'v : z1'.val = pre.length + 1 := by simp at hz1'v0; omega
    simp only [hz1, hz1', bind_tc_ok]
    rw [byte_at_in (k := 1) hb (by omega) (by omega), hget1]
    simp only [bind_tc_ok]
    rw [if_pos (sxB_nonneg _)]
    unfold x64_decode.sx8
    simp only [sxB_back, bind_tc_ok, lift, hln, disp8_roundtrip d hnear]

theorem hcast32_bv (x : BitVec 32) : BitVec.zeroExtend 32 (BitVec.signExtend 32 x) = x := by
  simp

theorem hcast32_roundtrip (d : Std.I32) :
    (UScalar.hcast (src_ty := .U32) .I32 (IScalar.hcast (src_ty := .I32) .U32 d)) = d := by
  apply I32.bv_eq_imp_eq
  exact hcast32_bv d.bv

/-- The four-byte-displacement ModRM form. -/
theorem decode_mem_far {bytes : Slice Std.U8} {«at» : Usize} {pre bs rest : List Std.U8}
    {reg rm rex_r rex_b : Std.U8} {d : Std.I32}
    (hb : bytes.val = pre ++ bs) (hat : «at».val = pre.length)
    (hbs : bs = modrmDispL reg rm d ++ rest)
    (hnear : nearDispB d = false) (hfit : pre.length + 16 ≤ Usize.max) :
    ∃ ln : Usize, ln.val = modrmDispLen rm d ∧
      x64_decode.decode_mem bytes «at» rex_r rex_b =
        ok { ok := true, reg := (reg &&& 7#u8) ||| shlU rex_r 3,
             base := (rm &&& 7#u8) ||| shlU rex_b 3, disp := d, len := ln } := by
  have hA : ¬(d = 0#i32 ∧ needsDispB (rm &&& 15#u8) = false) := by
    rintro ⟨rfl, -⟩
    simp [nearDispB] at hnear
  have hlist : modrmDispL reg rm d =
      modrmB 128#u8 (reg &&& 15#u8) (rm &&& 15#u8)
        :: ((if needsSibB (rm &&& 15#u8) then [36#u8] else [])
            ++ u32L (IScalar.hcast .U32 d)) := by
    unfold modrmDispL; rw [if_neg hA]; simp only [hnear, if_false, Bool.false_eq_true]
  have hmdl : modrmDispLen rm d = 1 + ((if needsSibB (rm &&& 15#u8) then 1 else 0) + 4) := by
    unfold modrmDispLen; rw [if_neg hA]; simp only [hnear, if_false, Bool.false_eq_true]
  have hsibiff := needsSib_iff rm
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := «at») (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + 1 := by simp at hz1v0; omega
  unfold x64_decode.decode_mem
  by_cases hsib : needsSibB (rm &&& 15#u8) = true
  · have hrm4 : rm &&& 7#u8 = 4#u8 := by rw [hsibiff] at hsib; simpa using hsib
    have hget0 : bs[0]! = modrmB 128#u8 (reg &&& 15#u8) (rm &&& 15#u8) := by
      rw [hbs, hlist, hsib]; simp
    have hget1 : bs[1]! = 36#u8 := by rw [hbs, hlist, hsib]; simp
    have hlen : 6 ≤ bs.length := by rw [hbs, hlist, hsib]; simp [u32L_length]; try omega
    have hg0 : bs[2]! = lo8 (IScalar.hcast (src_ty := .I32) .U32 d).bv := by
      simp [hbs, hlist, hsib, u32L]
    have hg1 : bs[3]! = lo8 ((IScalar.hcast (src_ty := .I32) .U32 d).bv >>> 8) := by
      simp [hbs, hlist, hsib, u32L]
    have hg2 : bs[4]! = lo8 ((IScalar.hcast (src_ty := .I32) .U32 d).bv >>> 16) := by
      simp [hbs, hlist, hsib, u32L]
    have hg3 : bs[5]! = lo8 ((IScalar.hcast (src_ty := .I32) .U32 d).bv >>> 24) := by
      simp [hbs, hlist, hsib, u32L]
    obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := z1) (y := 1#usize) (by simp; omega)
    have hz2v : z2.val = pre.length + 2 := by simp at hz2v0; omega
    obtain ⟨ln, hln, hlnv0⟩ := usize_add_ok (x := 5#usize) (y := 1#usize) (by scalar_tac)
    have hlnval : ln.val = 6 := by simp at hlnv0; omega
    refine ⟨ln, by rw [hmdl]; simp [hsib, hlnval], ?_⟩
    rw [byte_at_in (k := 0) hb (by omega) (by omega), hget0]
    simp only [bind_tc_ok, lift]
    rw [if_pos (sxB_nonneg _)]
    simp only [sxB_back, shrU3_eq, shlU3, bind_tc_ok, lift, modrmB_and192, modrmB_and7,
      modrmB_ext, and15_and7]
    rw [if_pos hrm4]
    simp only [bind_tc_ok]
    rw [if_pos hrm4]
    simp only [hz1, bind_tc_ok]
    rw [byte_at_in (k := 1) hb (by omega) (by omega), hget1]
    simp only [bind_tc_ok]
    rw [if_neg (show ¬((128#u8 : Std.U8) &&& 192#u8 = 192#u8) by decide)]
    rw [if_pos (show (decide (sxB 36#u8 = 36#i32)) = true by decide)]
    rw [if_neg (show ¬((128#u8 : Std.U8) &&& 192#u8 = 0#u8) by decide)]
    rw [if_neg (show ¬((128#u8 : Std.U8) &&& 192#u8 = 64#u8) by decide)]
    simp only [hz1, hz2, bind_tc_ok]
    rw [have_at (k := 2) hb (by omega) (by simp; omega)]
    simp only [bind_tc_ok]
    rw [if_pos (show (decide (2 + (4#usize).val ≤ bs.length)) = true by
      simp only [decide_eq_true_eq]; scalar_tac)]
    rw [read32_at (k := 2) hb (by omega) (by omega) (by omega)]
    rw [hg0, hg1, hg2, hg3]
    simp only [bind_tc_ok, lift, hln]
    rw [u32of_lo8, hcast32_roundtrip]
  · have hrm4 : ¬ (rm &&& 7#u8 = 4#u8) := by rw [hsibiff] at hsib; simpa using hsib
    simp only [Bool.not_eq_true] at hsib
    have hget0 : bs[0]! = modrmB 128#u8 (reg &&& 15#u8) (rm &&& 15#u8) := by
      rw [hbs, hlist, hsib]; simp
    have hlen : 5 ≤ bs.length := by rw [hbs, hlist, hsib]; simp [u32L_length]; try omega
    have hg0 : bs[1]! = lo8 (IScalar.hcast (src_ty := .I32) .U32 d).bv := by
      simp [hbs, hlist, hsib, u32L]
    have hg1 : bs[2]! = lo8 ((IScalar.hcast (src_ty := .I32) .U32 d).bv >>> 8) := by
      simp [hbs, hlist, hsib, u32L]
    have hg2 : bs[3]! = lo8 ((IScalar.hcast (src_ty := .I32) .U32 d).bv >>> 16) := by
      simp [hbs, hlist, hsib, u32L]
    have hg3 : bs[4]! = lo8 ((IScalar.hcast (src_ty := .I32) .U32 d).bv >>> 24) := by
      simp [hbs, hlist, hsib, u32L]
    obtain ⟨ln, hln, hlnv0⟩ := usize_add_ok (x := 5#usize) (y := 0#usize) (by scalar_tac)
    have hlnval : ln.val = 5 := by simp at hlnv0; omega
    refine ⟨ln, by rw [hmdl]; simp [hsib, hlnval], ?_⟩
    rw [byte_at_in (k := 0) hb (by omega) (by omega), hget0]
    simp only [bind_tc_ok, lift]
    rw [if_pos (sxB_nonneg _)]
    simp only [sxB_back, shrU3_eq, shlU3, bind_tc_ok, lift, modrmB_and192, modrmB_and7,
      modrmB_ext, and15_and7]
    rw [if_neg hrm4]
    simp only [bind_tc_ok]
    rw [if_neg hrm4]
    simp only [bind_tc_ok]
    rw [if_neg (show ¬((128#u8 : Std.U8) &&& 192#u8 = 192#u8) by decide)]
    rw [if_pos trivial]
    rw [if_neg (show ¬((128#u8 : Std.U8) &&& 192#u8 = 0#u8) by decide)]
    rw [if_neg (show ¬((128#u8 : Std.U8) &&& 192#u8 = 64#u8) by decide)]
    obtain ⟨z1', hz1', hz1'v0⟩ := usize_add_ok (x := z1) (y := 0#usize) (by simp; omega)
    have hz1'v : z1'.val = pre.length + 1 := by simp at hz1'v0; omega
    simp only [hz1, hz1', bind_tc_ok]
    rw [have_at (k := 1) hb (by omega) (by simp; omega)]
    simp only [bind_tc_ok]
    rw [if_pos (show (decide (1 + (4#usize).val ≤ bs.length)) = true by
      simp only [decide_eq_true_eq]; scalar_tac)]
    rw [read32_at (k := 1) hb (by omega) (by omega) (by omega)]
    rw [hg0, hg1, hg2, hg3]
    simp only [bind_tc_ok, lift, hln]
    rw [u32of_lo8, hcast32_roundtrip]

/-- **The ModRM byte and displacement the encoder wrote read back as themselves.** -/
theorem decode_mem_eq {bytes : Slice Std.U8} {«at» : Usize} {pre bs rest : List Std.U8}
    {reg rm rex_r rex_b : Std.U8} {d : Std.I32}
    (hb : bytes.val = pre ++ bs) (hat : «at».val = pre.length)
    (hbs : bs = modrmDispL reg rm d ++ rest) (hfit : pre.length + 16 ≤ Usize.max) :
    ∃ ln : Usize, ln.val = modrmDispLen rm d ∧
      x64_decode.decode_mem bytes «at» rex_r rex_b =
        ok { ok := true, reg := (reg &&& 7#u8) ||| shlU rex_r 3,
             base := (rm &&& 7#u8) ||| shlU rex_b 3, disp := d, len := ln } := by
  by_cases hA : d = 0#i32 ∧ needsDispB (rm &&& 15#u8) = false
  · refine ⟨1#usize, ?_, decode_mem_short hb hat hbs hA⟩
    unfold modrmDispLen; rw [if_pos hA]; simp
  · by_cases hnear : nearDispB d = true
    · exact decode_mem_near hb hat hbs hA hnear (by omega)
    · simp only [Bool.not_eq_true] at hnear
      exact decode_mem_far hb hat hbs hnear hfit

/-! ## The shape a primitive reads back as -/

/-- The primitives the encoder writes no bytes for. -/
def emitsNothing : x64_ir.PInsn → Bool
  | .PcLabel _ => true
  | .Local _ => true
  | .ExitLabel => true
  | .RetpolineLabel => true
  | .Load size sxf _ _ _ => sxf && decide (size = 8#u8)
  | _ => false

/-- The decoder's canonical form of a primitive: a branch's label is not in its
bytes, and four encodings are shared by two primitives apiece. -/
def shape : x64_ir.PInsn → x64_ir.PInsn
  | .ShiftImm w64 op dst imm => .ShiftImm w64 op dst (imm &&& 255#i32)
  | .StoreImm size base disp imm =>
      .StoreImm size base disp
        (if size = 1#u8 then imm &&& 255#i32
         else if size = 2#u8 then imm &&& 65535#i32 else imm)
  | .LoadImm dst imm =>
      if immFits32B imm then .AluImm true .Mov dst (IScalar.cast .I32 imm)
      else .LoadImm dst imm
  | .MulDivRcx w64 kind signed =>
      match kind with
      | .Mul => .MulDivRcx w64 .Mul false
      | _ => .MulDivRcx w64 .Div signed
  | .Jcc cc _ => .Jcc cc (.Local 0#u32)
  | .Jmp _ => .Jmp (.Local 0#u32)
  | .JmpNear _ => .JmpNear (.Local 0#u32)
  | .Call _ => .Call (.Local 0#u32)
  | .Jcc8 cc _ => .Jcc8 cc 0#u32
  | .Jmp8 _ => .Jmp8 0#u32
  | .RipLoadDispatcher dst => .RipLoadDispatcher (dst &&& 7#u8)
  | p => p

/-- The side conditions the encodings need of a primitive's operands: every
register is one of the sixteen, every width is one the encoder writes, every
condition code is one of the sixteen `0x8*` rows, the atomic's verbatim opcode
byte is not a prefix, the dispatcher address does not start an instruction, and
the RIP-relative load has no REX.R bit to spare. -/
def RegsBounded : x64_ir.PInsn → Prop
  | .PcLabel _ => True
  | .Local _ => True
  | .ExitLabel => True
  | .RetpolineLabel => True
  | .Push r => r.val < 16
  | .Pop r => r.val < 16
  | .Alu _ _ src dst => src.val < 16 ∧ dst.val < 16
  | .AluImm _ _ dst _ => dst.val < 16
  | .ShiftImm _ _ dst _ => dst.val < 16
  | .ShiftCl _ _ dst => dst.val < 16
  | .Neg _ dst => dst.val < 16
  | .MulDivRcx _ _ _ => True
  | .MovSx from_ _ src dst =>
      (from_ = 8#u8 ∨ from_ = 16#u8 ∨ from_ = 32#u8) ∧ src.val < 16 ∧ dst.val < 16
  | .Bswap _ dst => dst.val < 16
  | .Rol16 dst => dst.val < 16
  | .Cmov cc dst src => (128 ≤ cc.val ∧ cc.val ≤ 143) ∧ dst.val < 16 ∧ src.val < 16
  | .LoadImm dst _ => dst.val < 16
  | .Pushfq => True
  | .Popfq => True
  | .Cqo => True
  | .Cdq => True
  | .CmpRcxMinusOne _ => True
  | .CmpEaxImm _ => True
  | .Load size _ base dst _ =>
      (size = 1#u8 ∨ size = 2#u8 ∨ size = 4#u8 ∨ size = 8#u8) ∧ base.val < 16 ∧ dst.val < 16
  | .Store size src base _ =>
      (size = 1#u8 ∨ size = 2#u8 ∨ size = 4#u8 ∨ size = 8#u8) ∧ src.val < 16 ∧ base.val < 16
  | .StoreImm size base _ _ =>
      (size = 1#u8 ∨ size = 2#u8 ∨ size = 4#u8 ∨ size = 8#u8) ∧ base.val < 16
  | .AluRM _ reg base _ => reg.val < 16 ∧ base.val < 16
  | .StoreRspImm _ => True
  | .StoreRspRax => True
  | .LockAlu op _ src base _ =>
      (op = 1#u8 ∨ op = 9#u8 ∨ op = 33#u8 ∨ op = 49#u8) ∧ src.val < 16 ∧ base.val < 16
  | .LockCmpxchg _ src base _ => src.val < 16 ∧ base.val < 16
  | .Xchg _ src base _ => src.val < 16 ∧ base.val < 16
  | .Jcc cc _ => 128 ≤ cc.val ∧ cc.val ≤ 143
  | .Jmp _ => True
  | .JmpNear _ => True
  | .Call _ => True
  | .Jcc8 cc _ => 128 ≤ cc.val ∧ cc.val ≤ 143
  | .Jmp8 _ => True
  | .Ret => True
  | .Pause => True
  | .Ud2 => True
  | .CallReg reg => reg.val < 16
  | .RipLoadDispatcher dst => dst.val < 8
  | .RipLeaHelperTable dst => dst.val < 16
  | .DispatcherSlot addr => addr &&& 255#u64 = 0#u64
  | .HelperTable => True

/-! ## The statement, one primitive at a time -/

/-- `DecodesTo p`: the bytes the encoder appends for `p`, read at the offset it
appended them, give `p`'s shape, its length and the placeholder displacement. -/
def DecodesTo (p : x64_ir.PInsn) : Prop :=
  ∀ (bytes : Slice Std.U8) (pos : Usize) (pre : List Std.U8),
    bytes.val = pre ++ enc p → pos.val = pre.length → pre.length + 1024 ≤ Usize.max →
    ∃ d : x64_decode.Decoded, x64_decode.decode_one bytes pos = ok (some d) ∧
      d.insn = shape p ∧ d.len.val = (enc p).length ∧ d.disp = 0#i64

theorem usize_sub_ok {x y : Usize} (h : y.val ≤ x.val) :
    ∃ z : Usize, x - y = ok z ∧ z.val = x.val - y.val := by
  have he := UScalar.sub_equiv x y
  cases hxy : x - y with
  | ok z => rw [hxy] at he; exact ⟨z, rfl, by omega⟩
  | fail e => rw [hxy] at he; omega
  | div => rw [hxy] at he; exact he.elim

theorem finish_spec {insn : x64_ir.PInsn} {pos e : Usize} {disp : Std.I64} {n : Nat}
    (h : e.val = pos.val + n) :
    ∃ ln : Usize, ln.val = n ∧
      x64_decode.finish insn pos e disp = ok (some { insn := insn, len := ln, disp := disp }) := by
  obtain ⟨z, hz, hzv⟩ := usize_sub_ok (x := e) (y := pos) (by omega)
  refine ⟨z, by omega, ?_⟩
  unfold x64_decode.finish
  rw [hz]
  rfl

theorem decode_one_eq {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    {d : x64_decode.Decoded}
    (hq : x64_decode.prefixes bytes pos = ok q)
    (hi : x64_decode.decode_insn bytes pos q = ok (some d)) :
    x64_decode.decode_one bytes pos = ok (some d) := by
  unfold x64_decode.decode_one
  rw [hq]
  simp only [bind_tc_ok]
  rw [hi]
  simp only [bind_tc_ok]

theorem sxB_ne {c e : Std.U8} (h : c ≠ e) : sxB c ≠ sxB e := by
  intro hc
  apply h
  apply UScalar.eq_of_val_eq
  have hv := congrArg IScalar.val hc
  rw [sxB_val, sxB_val] at hv
  omega

theorem sxB_nonneg' (c : Std.U8) : ¬ (sxB c < 0#i32) := by
  rw [not_lt, IScalar.le_equiv, sxB_val]
  simp

theorem decode_insn_plain {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx} {c : Std.U8}
    (hh : x64_decode.byte_at bytes q.at = ok (sxB c)) (hlock : q.lock = false)
    (hc : c ≠ 15#u8) :
    x64_decode.decode_insn bytes pos q = x64_decode.decode_one_byte bytes pos q c := by
  unfold x64_decode.decode_insn
  rw [hh]
  simp only [bind_tc_ok, lift]
  rw [if_neg (sxB_nonneg' c)]
  rw [hlock, if_neg (by simp)]
  rw [if_neg (show ¬ (sxB c = 15#i32) from by
    have := sxB_ne hc
    simpa [sxB] using this)]
  simp only [sxB_back]

theorem decode_insn_0f {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx}
    (hh : x64_decode.byte_at bytes q.at = ok (sxB 15#u8)) (hlock : q.lock = false) :
    x64_decode.decode_insn bytes pos q = x64_decode.decode_two_byte bytes pos q := by
  unfold x64_decode.decode_insn
  rw [hh]
  simp only [bind_tc_ok, lift]
  rw [if_neg (sxB_nonneg' _)]
  rw [hlock, if_neg (by simp)]
  rw [if_pos (show sxB 15#u8 = 15#i32 from by simp only [sxB]; decide)]

theorem decode_insn_lock {bytes : Slice Std.U8} {pos : Usize} {q : x64_decode.Pfx} {c : Std.U8}
    (hh : x64_decode.byte_at bytes q.at = ok (sxB c)) (hlock : q.lock = true) :
    x64_decode.decode_insn bytes pos q = x64_decode.decode_locked bytes pos q c := by
  unfold x64_decode.decode_insn
  rw [hh]
  simp only [bind_tc_ok, lift]
  rw [if_neg (sxB_nonneg' c)]
  rw [hlock, if_pos rfl]
  simp only [sxB_back]

theorem decode_one_byte_tail {bytes : Slice Std.U8} {pos : Usize} {p : x64_decode.Pfx}
    {op : Std.U8}
    (h1 : ¬(80 ≤ op.val ∧ op.val ≤ 95)) (h2 : ¬(112 ≤ op.val ∧ op.val ≤ 127))
    (h3 : ¬(184 ≤ op.val ∧ op.val ≤ 191)) :
    x64_decode.decode_one_byte bytes pos p op =
      (do let b ← x64_decode.alu_op op
          if b then x64_decode.decode_alu bytes pos p op
          else if op = 139#u8 then x64_decode.decode_move bytes pos p op
          else if op = 141#u8 then x64_decode.decode_move bytes pos p op
          else if op = 198#u8 then x64_decode.decode_move bytes pos p op
          else if op = 199#u8 then x64_decode.decode_move bytes pos p op
          else x64_decode.decode_rest bytes pos p op) := by
  unfold x64_decode.decode_one_byte
  simp only [ge_iff_le, UScalar.le_equiv]
  by_cases a : (80#u8).val ≤ op.val
  · rw [if_pos a, if_neg (by scalar_tac)]
    by_cases c : (112#u8).val ≤ op.val
    · rw [if_pos c, if_neg (by scalar_tac)]
      by_cases e : (184#u8).val ≤ op.val
      · rw [if_pos e, if_neg (by scalar_tac)]
      · rw [if_neg e]
    · rw [if_neg c, if_neg (by scalar_tac : ¬ ((184#u8).val ≤ op.val))]
  · rw [if_neg a, if_neg (by scalar_tac : ¬ ((112#u8).val ≤ op.val)),
      if_neg (by scalar_tac : ¬ ((184#u8).val ≤ op.val))]

/-! ## The primitives with no operands -/

theorem dec_ret : DecodesTo .Ret := by
  intro bytes pos pre hb hat hfit
  have hbs : enc x64_ir.PInsn.Ret = [195#u8] := rfl
  rw [hbs] at hb
  have hq := prefixes_plain hb hat (by simp) (by decide)
  have hbyte : x64_decode.byte_at bytes pos = ok (sxB 195#u8) :=
    byte_at_in (k := 0) hb (by omega) (by simp)
  obtain ⟨z, hz, hzv0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hzv : z.val = pos.val + 1 := by simpa using hzv0
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Ret) (disp := 0#i64) (n := 1) hzv
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Ret, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hbyte rfl (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 195#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    rw [hz]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by simp [hbs, hln], rfl⟩

theorem dec_pushfq : DecodesTo x64_ir.PInsn.Pushfq := by
  intro bytes pos pre hb hat hfit
  have hbs : enc x64_ir.PInsn.Pushfq = [156#u8] := rfl
  rw [hbs] at hb
  have hq := prefixes_plain hb hat (by simp) (by decide)
  have hbyte : x64_decode.byte_at bytes pos = ok (sxB 156#u8) :=
    byte_at_in (k := 0) hb (by omega) (by simp)
  obtain ⟨z, hz, hzv0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hzv : z.val = pos.val + 1 := by simpa using hzv0
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Pushfq) (disp := 0#i64) (n := 1) hzv
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Pushfq, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hbyte rfl (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 156#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    rw [hz]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by simp [hbs, hln], rfl⟩

theorem dec_popfq : DecodesTo x64_ir.PInsn.Popfq := by
  intro bytes pos pre hb hat hfit
  have hbs : enc x64_ir.PInsn.Popfq = [157#u8] := rfl
  rw [hbs] at hb
  have hq := prefixes_plain hb hat (by simp) (by decide)
  have hbyte : x64_decode.byte_at bytes pos = ok (sxB 157#u8) :=
    byte_at_in (k := 0) hb (by omega) (by simp)
  obtain ⟨z, hz, hzv0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hzv : z.val = pos.val + 1 := by simpa using hzv0
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Popfq) (disp := 0#i64) (n := 1) hzv
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Popfq, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hbyte rfl (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 157#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    rw [hz]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by simp [hbs, hln], rfl⟩

theorem dec_cdq : DecodesTo x64_ir.PInsn.Cdq := by
  intro bytes pos pre hb hat hfit
  have hbs : enc x64_ir.PInsn.Cdq = [153#u8] := rfl
  rw [hbs] at hb
  have hq := prefixes_plain hb hat (by simp) (by decide)
  have hbyte : x64_decode.byte_at bytes pos = ok (sxB 153#u8) :=
    byte_at_in (k := 0) hb (by omega) (by simp)
  obtain ⟨z, hz, hzv0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hzv : z.val = pos.val + 1 := by simpa using hzv0
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Cdq) (disp := 0#i64) (n := 1) hzv
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Cdq, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hbyte rfl (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 153#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    rw [hz]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by simp [hbs, hln], rfl⟩

theorem dec_cqo : DecodesTo .Cqo := by
  intro bytes pos pre hb hat hfit
  have hbs : enc x64_ir.PInsn.Cqo = [72#u8, 153#u8] := rfl
  rw [hbs] at hb
  obtain ⟨q1, hq1v, hq⟩ := prefixes_rex1 hb hat (by simp) (by decide) (by omega)
  have hbyte : x64_decode.byte_at bytes q1 = ok (sxB 153#u8) :=
    byte_at_in (k := 1) hb (by omega) (by simp)
  obtain ⟨z, hz, hzv0⟩ := usize_add_ok (x := q1) (y := 1#usize) (by simp; omega)
  have hzv : z.val = pos.val + 2 := by simp at hzv0; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Cqo) (disp := 0#i64) (n := 2) hzv
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Cqo, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hbyte rfl (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 153#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest, show pfxW [72#u8, 153#u8][0]! = 1#u8 from by decide]
    rw [hz]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by simp [hbs, hln], rfl⟩

theorem dec_pause : DecodesTo .Pause := by
  intro bytes pos pre hb hat hfit
  have hbs : enc x64_ir.PInsn.Pause = [243#u8, 144#u8] := rfl
  rw [hbs] at hb
  obtain ⟨q1, hq1v, hq⟩ :=
    prefixes_p1 hb hat (by simp) (by decide) (by decide) (by omega)
  have hbyte : x64_decode.byte_at bytes q1 = ok (sxB 144#u8) :=
    byte_at_in (k := 1) hb (by omega) (by simp)
  obtain ⟨z, hz, hzv0⟩ := usize_add_ok (x := q1) (y := 1#usize) (by simp; omega)
  have hzv : z.val = pos.val + 2 := by simp at hzv0; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Pause) (disp := 0#i64) (n := 2) hzv
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Pause, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hbyte rfl (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 144#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    rw [hz]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by simp [hbs, hln], rfl⟩

theorem dec_ud2 : DecodesTo .Ud2 := by
  intro bytes pos pre hb hat hfit
  have hbs : enc x64_ir.PInsn.Ud2 = [15#u8, 11#u8] := rfl
  rw [hbs] at hb
  have hq := prefixes_plain hb hat (by simp) (by decide)
  have hbyte0 : x64_decode.byte_at bytes pos = ok (sxB 15#u8) :=
    byte_at_in (k := 0) hb (by omega) (by simp)
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pos.val + 1 := by simpa using hz1v0
  have hbyte1 : x64_decode.byte_at bytes z1 = ok (sxB 11#u8) :=
    byte_at_in (k := 1) hb (by omega) (by simp)
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := pos) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pos.val + 2 := by simpa using hz2v0
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Ud2) (disp := 0#i64) (n := 2) hz2v
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Ud2, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_0f hbyte0 rfl]
    unfold x64_decode.decode_two_byte
    simp only [hz1, bind_tc_ok]
    rw [hbyte1]
    simp only [bind_tc_ok]
    rw [if_neg (sxB_nonneg' _)]
    rw [if_pos (show sxB 11#u8 = 11#i32 from by simp only [sxB]; decide)]
    rw [hz2]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by simp [hbs, hln], rfl⟩

theorem dec_cmpEaxImm (imm : Std.U32) : DecodesTo (.CmpEaxImm imm) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.CmpEaxImm imm) = 61#u8 :: u32L imm := rfl
  rw [hbs] at hb
  have hlen : (61#u8 :: u32L imm).length = 5 := by simp [u32L]
  have hq := prefixes_plain hb hat (by omega) (by simp only [List.getElem!_cons_zero]; decide)
  have hbyte : x64_decode.byte_at bytes pos = ok (sxB 61#u8) := by
    have := byte_at_in (k := 0) hb (by omega) (by omega)
    simpa using this
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pos.val + 1 := by simpa using hz1v0
  obtain ⟨z5, hz5, hz5v0⟩ := usize_add_ok (x := pos) (y := 5#usize) (by simp; omega)
  have hz5v : z5.val = pos.val + 5 := by simpa using hz5v0
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.CmpEaxImm imm) (disp := 0#i64) (n := 5) hz5v
  have hg : ∀ j, j < 4 → (61#u8 :: u32L imm)[1 + j]! = (u32L imm)[j]! := by
    intro j hj; simp
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.CmpEaxImm imm, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hbyte rfl (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 61#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    unfold x64_decode.decode_rest
    rw [if_pos rfl]
    simp only [hz1, bind_tc_ok]
    rw [have_at (k := 1) hb (by omega) (by simp; omega)]
    simp only [bind_tc_ok]
    rw [if_pos (show (decide (1 + (4#usize).val ≤ (61#u8 :: u32L imm).length)) = true from by
      simp only [decide_eq_true_eq]; scalar_tac)]
    rw [read32_at (k := 1) hb (by omega) (by omega) (by omega)]
    rw [show (61#u8 :: u32L imm)[1]! = lo8 imm.bv from by simp [u32L],
      show (61#u8 :: u32L imm)[2]! = lo8 (imm.bv >>> 8) from by simp [u32L],
      show (61#u8 :: u32L imm)[3]! = lo8 (imm.bv >>> 16) from by simp [u32L],
      show (61#u8 :: u32L imm)[4]! = lo8 (imm.bv >>> 24) from by simp [u32L]]
    rw [u32of_lo8]
    simp only [hz5, bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

theorem dec_cmpRcxMinusOne (w64 : Bool) : DecodesTo (.CmpRcxMinusOne w64) := by
  intro bytes pos pre hb hat hfit
  cases w64 with
  | false =>
    have hbs : enc (x64_ir.PInsn.CmpRcxMinusOne false) = [131#u8, 249#u8, 255#u8] := rfl
    rw [hbs] at hb
    have hq := prefixes_plain hb hat (by simp) (by decide)
    have hbyte : x64_decode.byte_at bytes pos = ok (sxB 131#u8) :=
      byte_at_in (k := 0) hb (by omega) (by simp)
    obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
    have hz1v : z1.val = pos.val + 1 := by simpa using hz1v0
    obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := pos) (y := 2#usize) (by simp; omega)
    have hz2v : z2.val = pos.val + 2 := by simpa using hz2v0
    obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := pos) (y := 3#usize) (by simp; omega)
    have hz3v : z3.val = pos.val + 3 := by simpa using hz3v0
    obtain ⟨ln, hln, hfin⟩ :=
      finish_spec (insn := x64_ir.PInsn.CmpRcxMinusOne false) (disp := 0#i64) (n := 3) hz3v
    have hres : x64_decode.decode_one bytes pos =
        ok (some { insn := x64_ir.PInsn.CmpRcxMinusOne false, len := ln, disp := 0#i64 }) := by
      refine decode_one_eq hq ?_
      rw [decode_insn_plain hbyte rfl (by decide)]
      rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
      rw [show x64_decode.alu_op 131#u8 = ok false from by rfl]
      simp only [bind_tc_ok, reduceIte, reduceCtorEq]
      norm_num [x64_decode.decode_rest]
      simp only [hz1, hz2, bind_tc_ok]
      rw [byte_at_in (k := 1) hb (by omega) (by simp),
        byte_at_in (k := 2) hb (by omega) (by simp)]
      simp only [bind_tc_ok]
      rw [if_pos (show sxB [131#u8, 249#u8, 255#u8][1]! = 249#i32 from by
        simp only [sxB]; decide)]
      rw [if_pos (show sxB [131#u8, 249#u8, 255#u8][2]! = 255#i32 from by
        simp only [sxB]; decide)]
      simp only [hz3, bind_tc_ok]
      exact hfin
    exact ⟨_, hres, rfl, by simp [hbs, hln], rfl⟩
  | true =>
    have hbs : enc (x64_ir.PInsn.CmpRcxMinusOne true) = [72#u8, 131#u8, 249#u8, 255#u8] := rfl
    rw [hbs] at hb
    obtain ⟨q1, hq1v, hq⟩ := prefixes_rex1 hb hat (by simp) (by decide) (by omega)
    have hbyte : x64_decode.byte_at bytes q1 = ok (sxB 131#u8) :=
      byte_at_in (k := 1) hb (by omega) (by simp)
    obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q1) (y := 1#usize) (by simp; omega)
    have hz2v : z2.val = pos.val + 2 := by simp at hz2v0; omega
    obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := q1) (y := 2#usize) (by simp; omega)
    have hz3v : z3.val = pos.val + 3 := by simp at hz3v0; omega
    obtain ⟨z4, hz4, hz4v0⟩ := usize_add_ok (x := q1) (y := 3#usize) (by simp; omega)
    have hz4v : z4.val = pos.val + 4 := by simp at hz4v0; omega
    obtain ⟨ln, hln, hfin⟩ :=
      finish_spec (insn := x64_ir.PInsn.CmpRcxMinusOne true) (disp := 0#i64) (n := 4) hz4v
    have hres : x64_decode.decode_one bytes pos =
        ok (some { insn := x64_ir.PInsn.CmpRcxMinusOne true, len := ln, disp := 0#i64 }) := by
      refine decode_one_eq hq ?_
      rw [decode_insn_plain hbyte rfl (by decide)]
      rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
      rw [show x64_decode.alu_op 131#u8 = ok false from by rfl]
      simp only [bind_tc_ok, reduceIte, reduceCtorEq]
      norm_num [x64_decode.decode_rest,
        show pfxW [72#u8, 131#u8, 249#u8, 255#u8][0]! = 1#u8 from by decide]
      simp only [hz2, hz3, bind_tc_ok]
      rw [byte_at_in (k := 2) hb (by omega) (by simp),
        byte_at_in (k := 3) hb (by omega) (by simp)]
      simp only [bind_tc_ok]
      rw [if_pos (show sxB [72#u8, 131#u8, 249#u8, 255#u8][2]! = 249#i32 from by
        simp only [sxB]; decide)]
      rw [if_pos (show sxB [72#u8, 131#u8, 249#u8, 255#u8][3]! = 255#i32 from by
        simp only [sxB]; decide)]
      simp only [hz4, bind_tc_ok]
      exact hfin
    exact ⟨_, hres, rfl, by simp [hbs, hln], rfl⟩

/-! ## The optional REX prefix -/

theorem shlU_highU (r : Std.U8) : shlU (highU r) 3 = r &&& 8#u8 :=
  u8_cases (P := fun r => shlU (highU r) 3 = r &&& 8#u8) (by decide) r

theorem reg_rejoin (r : Std.U8) (h : r.val < 16) : (r &&& 7#u8) ||| shlU (highU r) 3 = r :=
  u8_cases (P := fun r => r.val < 16 → (r &&& 7#u8) ||| shlU (highU r) 3 = r) (by decide) r h

theorem u8_le_one (w : Std.U8) (h : w.val ≤ 1) : w = 0#u8 ∨ w = 1#u8 :=
  u8_cases (P := fun w => w.val ≤ 1 → (w = 0#u8 ∨ w = 1#u8)) (by decide) w h

theorem highU_le (r : Std.U8) : (highU r).val ≤ 1 := by unfold highU; split <;> decide
theorem bitU_le (b : Bool) : (bitU b).val ≤ 1 := by cases b <;> decide

theorem rexByte_range (w r x b : Std.U8) (hw : w.val ≤ 1) (hr : r.val ≤ 1) (hx : x.val ≤ 1)
    (hb : b.val ≤ 1) : 64 ≤ (rexByte w r x b).val ∧ (rexByte w r x b).val ≤ 79 := by
  rcases u8_le_one w hw with rfl | rfl <;> rcases u8_le_one r hr with rfl | rfl <;>
    rcases u8_le_one x hx with rfl | rfl <;> rcases u8_le_one b hb with rfl | rfl <;> decide

theorem pfxW_rexByte (w r x b : Std.U8) (hw : w.val ≤ 1) (hr : r.val ≤ 1) (hx : x.val ≤ 1)
    (hb : b.val ≤ 1) : pfxW (rexByte w r x b) = w := by
  rcases u8_le_one w hw with rfl | rfl <;> rcases u8_le_one r hr with rfl | rfl <;>
    rcases u8_le_one x hx with rfl | rfl <;> rcases u8_le_one b hb with rfl | rfl <;> decide

theorem pfxR_rexByte (w r x b : Std.U8) (hw : w.val ≤ 1) (hr : r.val ≤ 1) (hx : x.val ≤ 1)
    (hb : b.val ≤ 1) : pfxR (rexByte w r x b) = r := by
  rcases u8_le_one w hw with rfl | rfl <;> rcases u8_le_one r hr with rfl | rfl <;>
    rcases u8_le_one x hx with rfl | rfl <;> rcases u8_le_one b hb with rfl | rfl <;> decide

theorem pfxB_rexByte (w r x b : Std.U8) (hw : w.val ≤ 1) (hr : r.val ≤ 1) (hx : x.val ≤ 1)
    (hb : b.val ≤ 1) : pfxB (rexByte w r x b) = b := by
  rcases u8_le_one w hw with rfl | rfl <;> rcases u8_le_one r hr with rfl | rfl <;>
    rcases u8_le_one x hx with rfl | rfl <;> rcases u8_le_one b hb with rfl | rfl <;> decide

/-- What the optional REX prefix in front of an opcode looks like. -/
def RexCase (rexl : List Std.U8) (w r b : Std.U8) : Prop :=
  (rexl = [] ∧ w = 0#u8 ∧ r = 0#u8 ∧ b = 0#u8) ∨
  (∃ c, rexl = [c] ∧ 64 ≤ c.val ∧ c.val ≤ 79 ∧ pfxW c = w ∧ pfxR c = r ∧ pfxB c = b)

theorem basicRexL_case (w src dst : Std.U8) (hw : w.val ≤ 1) :
    RexCase (basicRexL w src dst) w (highU src) (highU dst) := by
  unfold RexCase basicRexL
  by_cases h : basicRexB w src dst = true
  · rw [if_pos h]
    exact Or.inr ⟨_, rfl, (rexByte_range w (highU src) 0#u8 (highU dst) hw (highU_le _)
        (by decide) (highU_le _)).1,
      (rexByte_range w (highU src) 0#u8 (highU dst) hw (highU_le _) (by decide) (highU_le _)).2,
      pfxW_rexByte _ _ _ _ hw (highU_le _) (by decide) (highU_le _),
      pfxR_rexByte _ _ _ _ hw (highU_le _) (by decide) (highU_le _),
      pfxB_rexByte _ _ _ _ hw (highU_le _) (by decide) (highU_le _)⟩
  · rw [if_neg h]
    simp only [Bool.not_eq_true, basicRexB, Bool.or_eq_false_iff, bne_eq_false_iff_eq] at h
    obtain ⟨⟨hw0, hs⟩, hd⟩ := h
    refine Or.inl ⟨rfl, hw0, ?_, ?_⟩
    · unfold highU; rw [if_neg (by simp [hs])]
    · unfold highU; rw [if_neg (by simp [hd])]

/-- An opcode preceded by an optional REX prefix. -/
theorem prefixes_opt_rex {bytes : Slice Std.U8} {pos : Usize} {pre rexl rest : List Std.U8}
    {w r b : Std.U8}
    (hb : bytes.val = pre ++ (rexl ++ rest)) (hat : pos.val = pre.length)
    (hfit : pre.length + 1 ≤ Usize.max)
    (hrest : 0 < rest.length) (hnp : notPfx rest[0]!) (hcase : RexCase rexl w r b) :
    ∃ q : x64_decode.Pfx, x64_decode.prefixes bytes pos = ok q ∧
      q.lock = false ∧ q.op16 = false ∧ q.rep = false ∧
      q.w = w ∧ q.r = r ∧ q.b = b ∧ q.at.val = pre.length + rexl.length := by
  rcases hcase with ⟨he, hw, hr, hbb⟩ | ⟨c, he, hc1, hc2, hw, hr, hbb⟩
  · subst he; subst hw; subst hr; subst hbb
    simp only [List.nil_append] at hb ⊢
    exact ⟨_, prefixes_plain hb hat hrest hnp, rfl, rfl, rfl, rfl, rfl, rfl, by simp [hat]⟩
  · subst he; subst hw; subst hr; subst hbb
    have h0 : ([c] ++ rest)[0]! = c := by simp
    obtain ⟨q, hqv, hq⟩ :=
      prefixes_rex1 (bs := [c] ++ rest) hb hat (by simp) (by rw [h0]; exact ⟨hc1, hc2⟩) hfit
    exact ⟨_, hq, rfl, rfl, rfl, by rw [h0], by rw [h0], by rw [h0], by simp [hqv]⟩

/-- An opcode preceded by one legacy prefix byte and an optional REX prefix. -/
theorem prefixes_pfx_opt_rex {bytes : Slice Std.U8} {pos : Usize} {pre rexl rest : List Std.U8}
    {w r b pfx : Std.U8}
    (hb : bytes.val = pre ++ (pfx :: (rexl ++ rest))) (hat : pos.val = pre.length)
    (hfit : pre.length + 2 ≤ Usize.max)
    (hpfx : pfx = 240#u8 ∨ pfx = 102#u8 ∨ pfx = 243#u8)
    (hrest : 0 < rest.length) (hnp : notPfx rest[0]!) (hcase : RexCase rexl w r b) :
    ∃ q : x64_decode.Pfx, x64_decode.prefixes bytes pos = ok q ∧
      q.lock = decide (pfx = 240#u8) ∧ q.op16 = decide (pfx = 102#u8) ∧
      q.rep = decide (pfx = 243#u8) ∧
      q.w = w ∧ q.r = r ∧ q.b = b ∧ q.at.val = pre.length + 1 + rexl.length := by
  rcases hcase with ⟨he, hw, hr, hbb⟩ | ⟨c, he, hc1, hc2, hw, hr, hbb⟩
  · subst he; subst hw; subst hr; subst hbb
    simp only [List.nil_append] at hb ⊢
    have h0 : (pfx :: rest)[0]! = pfx := by simp
    have h1 : (pfx :: rest)[1]! = rest[0]! := by simp
    obtain ⟨q, hqv, hq⟩ :=
      prefixes_p1 (bs := pfx :: rest) hb hat (by simp; try omega) (by rw [h0]; exact hpfx)
        (by rw [h1]; exact hnp) (by omega)
    exact ⟨_, hq, by rw [h0], by rw [h0], by rw [h0], rfl, rfl, rfl, by simp [hqv]⟩
  · subst he; subst hw; subst hr; subst hbb
    have h0 : (pfx :: ([c] ++ rest))[0]! = pfx := by simp
    have h1 : (pfx :: ([c] ++ rest))[1]! = c := by simp
    obtain ⟨q, hqv, hq⟩ :=
      prefixes_p1_rex (bs := pfx :: ([c] ++ rest)) hb hat (by simp; try omega)
        (by rw [h0]; exact hpfx) (by rw [h1]; exact ⟨hc1, hc2⟩) (by omega)
    exact ⟨_, hq, by rw [h0], by rw [h0], by rw [h0], by rw [h1], by rw [h1], by rw [h1],
      by simp [hqv]⟩

/-! ## The register-to-register forms -/

theorem mExt_modrmB (md r m : Std.U8) : mExt (modrmB md r m) = r &&& 7#u8 := modrmB_ext md r m

theorem mReg_modrmB (md r m rex : Std.U8) (h : r.val < 16) (hrex : rex = highU r) :
    mReg (modrmB md r m) rex = r := by
  unfold mReg; rw [mExt_modrmB, hrex]; exact reg_rejoin r h

theorem mRm_modrmB (md r m rex : Std.U8) (h : m.val < 16) (hrex : rex = highU m) :
    mRm (modrmB md r m) rex = m := by
  unfold mRm; rw [modrmB_and7, hrex]; exact reg_rejoin m h

theorem bitU_eq_one (w64 : Bool) : decide (bitU w64 = 1#u8) = w64 := by cases w64 <;> decide

theorem get_after (a b : List Std.U8) (j : Nat) : (a ++ b)[a.length + j]! = b[j]! := by
  rw [getBang_append_right _ _ _ (by omega)]; simp

theorem dec_alu (w64 : Bool) (op : x64_ir.AluRR) (src dst : Std.U8)
    (hsrc : src.val < 16) (hdst : dst.val < 16) : DecodesTo (.Alu w64 op src dst) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.Alu w64 op src dst)
      = basicRexL (bitU w64) src dst ++ [aluRROp op, modrmB 192#u8 src dst] := rfl
  rw [hbs] at hb
  set L := basicRexL (bitU w64) src dst with hL
  set T := [aluRROp op, modrmB 192#u8 src dst] with hT
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hlen : (L ++ T).length = L.length + 2 := by simp [hT]
  have g0 : (L ++ T)[L.length + 0]! = aluRROp op := by rw [get_after]; simp [hT]
  have g1 : (L ++ T)[L.length + 1]! = modrmB 192#u8 src dst := by rw [get_after]; simp [hT]
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex hb hat (by omega) (by simp [hT]) (by rw [hT]; simp; cases op <;> decide)
      (hL ▸ basicRexL_case (bitU w64) src dst (bitU_le _))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB (aluRROp op)) := by
    rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
  have hb1 : x64_decode.byte_at bytes z1 = ok (sxB (modrmB 192#u8 src dst)) := by
    rw [← g1]; exact byte_at_in (k := L.length + 1) hb (by omega) (by simp [hT])
  have hb2 : x64_decode.byte_at bytes z2 = ok (-1)#i32 :=
    byte_at_out (pre := pre) (bs := L ++ T) (k := L.length + 2) hb hz2v (by simp [hT])
  have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := true, reg := mReg (modrmB 192#u8 src dst) q.r,
           rm := mRm (modrmB 192#u8 src dst) q.b, ext := mExt (modrmB 192#u8 src dst) } := by
    have := decode_reg2_eq (k := L.length + 1) (rex_r := q.r) (rex_b := q.b) hb (by omega)
      (by simp [hT]) (by rw [g1, modrmB_and192]; decide)
    rwa [g1] at this
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Alu w64 op src dst) (disp := 0#i64)
      (pos := pos) (e := z2) (n := L.length + 2) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Alu w64 op src dst, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by cases op <;> decide)]
    rw [decode_one_byte_tail (by cases op <;> decide) (by cases op <;> decide)
      (by cases op <;> decide)]
    rw [show x64_decode.alu_op (aluRROp op) = ok true from by cases op <;> rfl]
    simp only [bind_tc_ok, if_true]
    unfold x64_decode.decode_alu
    simp only [hz1, hz2, hg, hb1, hb2, bind_tc_ok]
    rw [show x64_decode.is_alu_rr (aluRROp op) = ok true from by cases op <;> rfl]
    simp only [bind_tc_ok]
    rw [show x64_decode.is_alu_rm (aluRROp op) = ok (decide (aluRROp op = 57#u8)) from by
      cases op <;> rfl]
    simp only [bind_tc_ok, if_true]
    rw [show x64_decode.alu_rr_of (aluRROp op) = ok op from by cases op <;> rfl]
    simp only [bind_tc_ok]
    rw [mReg_modrmB _ _ _ _ hsrc hqr, mRm_modrmB _ _ _ _ hdst hqb, hqw, bitU_eq_one]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

theorem dec_shiftCl (w64 : Bool) (op : x64_ir.ShiftOp) (dst : Std.U8) (hdst : dst.val < 16) :
    DecodesTo (.ShiftCl w64 op dst) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.ShiftCl w64 op dst)
      = basicRexL (bitU w64) (shiftExtU op) dst ++ [211#u8, modrmB 192#u8 (shiftExtU op) dst] := rfl
  rw [hbs] at hb
  set L := basicRexL (bitU w64) (shiftExtU op) dst with hL
  set T := [211#u8, modrmB 192#u8 (shiftExtU op) dst] with hT
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hlen : (L ++ T).length = L.length + 2 := by simp [hT]
  have g0 : (L ++ T)[L.length + 0]! = 211#u8 := by rw [get_after]; simp [hT]
  have g1 : (L ++ T)[L.length + 1]! = modrmB 192#u8 (shiftExtU op) dst := by
    rw [get_after]; simp [hT]
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex hb hat (by omega) (by simp [hT]) (by rw [hT]; simp; decide)
      (hL ▸ basicRexL_case (bitU w64) (shiftExtU op) dst (bitU_le _))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 211#u8) := by
    rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
  have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := true, reg := mReg (modrmB 192#u8 (shiftExtU op) dst) q.r,
           rm := mRm (modrmB 192#u8 (shiftExtU op) dst) q.b,
           ext := mExt (modrmB 192#u8 (shiftExtU op) dst) } := by
    have := decode_reg2_eq (k := L.length + 1) (rex_r := q.r) (rex_b := q.b) hb (by omega)
      (by simp [hT]) (by rw [g1, modrmB_and192]; decide)
    rwa [g1] at this
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.ShiftCl w64 op dst) (disp := 0#i64)
      (pos := pos) (e := z2) (n := L.length + 2) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.ShiftCl w64 op dst, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 211#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    simp only [hz1, hz2, hg, bind_tc_ok, mExt_modrmB]
    rw [show (shiftExtU op) &&& 7#u8 = shiftExtU op from by cases op <;> decide]
    rw [show x64_decode.is_shift_ext (shiftExtU op) = ok true from by cases op <;> rfl]
    simp only [bind_tc_ok, if_true]
    rw [show x64_decode.shift_of (shiftExtU op) = ok op from by cases op <;> rfl]
    simp only [bind_tc_ok]
    rw [mRm_modrmB _ _ _ _ hdst hqb, hqw, bitU_eq_one]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

theorem dec_neg (w64 : Bool) (dst : Std.U8) (hdst : dst.val < 16) : DecodesTo (.Neg w64 dst) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.Neg w64 dst)
      = basicRexL (bitU w64) 3#u8 dst ++ [247#u8, modrmB 192#u8 3#u8 dst] := rfl
  rw [hbs] at hb
  set L := basicRexL (bitU w64) 3#u8 dst with hL
  set T := [247#u8, modrmB 192#u8 3#u8 dst] with hT
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hlen : (L ++ T).length = L.length + 2 := by simp [hT]
  have g0 : (L ++ T)[L.length + 0]! = 247#u8 := by rw [get_after]; simp [hT]
  have g1 : (L ++ T)[L.length + 1]! = modrmB 192#u8 3#u8 dst := by rw [get_after]; simp [hT]
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_opt_rex hb hat (by omega) (by simp [hT]) (by rw [hT]; simp; decide)
      (hL ▸ basicRexL_case (bitU w64) 3#u8 dst (bitU_le _))
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB 247#u8) := by
    rw [← g0]; exact byte_at_in (k := L.length + 0) hb (by omega) (by simp [hT])
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (L.length + 1) := by simp at hz1v0; omega
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := q.at) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pre.length + (L.length + 2) := by simp at hz2v0; omega
  have hg : x64_decode.decode_reg2 bytes z1 q.r q.b =
      ok { ok := true, reg := mReg (modrmB 192#u8 3#u8 dst) q.r,
           rm := mRm (modrmB 192#u8 3#u8 dst) q.b, ext := mExt (modrmB 192#u8 3#u8 dst) } := by
    have := decode_reg2_eq (k := L.length + 1) (rex_r := q.r) (rex_b := q.b) hb (by omega)
      (by simp [hT]) (by rw [g1, modrmB_and192]; decide)
    rwa [g1] at this
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Neg w64 dst) (disp := 0#i64)
      (pos := pos) (e := z2) (n := L.length + 2) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Neg w64 dst, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 hlock (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 247#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    unfold x64_decode.decode_unary
    simp only [hz1, hz2, hg, bind_tc_ok, mExt_modrmB]
    rw [if_neg (by decide : ¬ ((3#u8 : Std.U8) &&& 7#u8 = 0#u8))]
    rw [if_pos (by decide : (3#u8 : Std.U8) &&& 7#u8 = 3#u8)]
    rw [mRm_modrmB _ _ _ _ hdst hqb, hqw, bitU_eq_one]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

/-! ## The branches -/

theorem sx32_zero : x64_decode.sx32 (u32of 0#u8 0#u8 0#u8 0#u8) = ok 0#i64 := by rfl
theorem sx8_zero : x64_decode.sx8 (sxB 0#u8) = ok 0#i64 := by rfl

theorem dec_jmp (t : x64_ir.PTarget) : DecodesTo (.Jmp t) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.Jmp t) = 233#u8 :: u32L 0#u32 := rfl
  have hu : u32L 0#u32 = [0#u8, 0#u8, 0#u8, 0#u8] := by decide
  rw [hbs, hu] at hb
  have hq := prefixes_plain hb hat (by simp) (by decide)
  have hb0 : x64_decode.byte_at bytes pos = ok (sxB 233#u8) := by
    have := byte_at_in (k := 0) hb (by omega) (by simp); simpa using this
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pos.val + 1 := by simpa using hz1v0
  obtain ⟨z5, hz5, hz5v0⟩ := usize_add_ok (x := pos) (y := 5#usize) (by simp; omega)
  have hz5v : z5.val = pos.val + 5 := by simpa using hz5v0
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Jmp (x64_ir.PTarget.Local 0#u32)) (disp := 0#i64)
      (pos := pos) (e := z5) (n := 5) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Jmp (x64_ir.PTarget.Local 0#u32), len := ln,
                 disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 rfl (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 233#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    simp only [hz1, bind_tc_ok]
    rw [have_at (k := 1) hb (by omega) (by simp; omega)]
    simp only [bind_tc_ok]
    rw [if_pos (by simp)]
    rw [read32_at (k := 1) hb (by omega) (by simp) (by omega)]
    simp only [hz5, bind_tc_ok, List.getElem!_cons_succ, List.getElem!_cons_zero]
    rw [sx32_zero]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hu]; simp, rfl⟩

theorem dec_call (t : x64_ir.PTarget) : DecodesTo (.Call t) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.Call t) = 232#u8 :: u32L 0#u32 := rfl
  have hu : u32L 0#u32 = [0#u8, 0#u8, 0#u8, 0#u8] := by decide
  rw [hbs, hu] at hb
  have hq := prefixes_plain hb hat (by simp) (by decide)
  have hb0 : x64_decode.byte_at bytes pos = ok (sxB 232#u8) := by
    have := byte_at_in (k := 0) hb (by omega) (by simp); simpa using this
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pos.val + 1 := by simpa using hz1v0
  obtain ⟨z5, hz5, hz5v0⟩ := usize_add_ok (x := pos) (y := 5#usize) (by simp; omega)
  have hz5v : z5.val = pos.val + 5 := by simpa using hz5v0
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Call (x64_ir.PTarget.Local 0#u32)) (disp := 0#i64)
      (pos := pos) (e := z5) (n := 5) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Call (x64_ir.PTarget.Local 0#u32), len := ln,
                 disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 rfl (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 232#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    simp only [hz1, bind_tc_ok]
    rw [have_at (k := 1) hb (by omega) (by simp; omega)]
    simp only [bind_tc_ok]
    rw [if_pos (by simp)]
    rw [read32_at (k := 1) hb (by omega) (by simp) (by omega)]
    simp only [hz5, bind_tc_ok, List.getElem!_cons_succ, List.getElem!_cons_zero]
    rw [sx32_zero]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hu]; simp, rfl⟩

theorem dec_jmp8 (n : Std.U32) : DecodesTo (.Jmp8 n) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.Jmp8 n) = [235#u8, 0#u8] := rfl
  rw [hbs] at hb
  have hq := prefixes_plain hb hat (by simp) (by decide)
  have hb0 : x64_decode.byte_at bytes pos = ok (sxB 235#u8) := by
    have := byte_at_in (k := 0) hb (by omega) (by simp); simpa using this
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pos.val + 1 := by simpa using hz1v0
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := pos) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pos.val + 2 := by simpa using hz2v0
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := pos) (y := 3#usize) (by simp; omega)
  have hz3v : z3.val = pos.val + 3 := by simpa using hz3v0
  obtain ⟨z4, hz4, hz4v0⟩ := usize_add_ok (x := pos) (y := 4#usize) (by simp; omega)
  have hz4v : z4.val = pos.val + 4 := by simpa using hz4v0
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.Jmp8 0#u32) (disp := 0#i64)
      (pos := pos) (e := z2) (n := 2) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.Jmp8 0#u32, len := ln, disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 rfl (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 235#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    unfold x64_decode.decode_short_jmp
    simp only [hz1, bind_tc_ok]
    rw [byte_at_in (k := 1) hb (by omega) (by simp)]
    simp only [bind_tc_ok]
    rw [if_neg (sxB_nonneg' _)]
    simp only [hz2, hz3, hz4, bind_tc_ok]
    rw [byte_at_out (pre := pre) (bs := [235#u8, 0#u8]) (k := 2) hb (by omega) (by simp),
      byte_at_out (pre := pre) (bs := [235#u8, 0#u8]) (k := 3) hb (by omega) (by simp),
      byte_at_out (pre := pre) (bs := [235#u8, 0#u8]) (k := 4) hb (by omega) (by simp)]
    simp only [bind_tc_ok]
    rw [if_neg (by decide : ¬ ((-1)#i32 = 0#i32))]
    simp only [bind_tc_ok, Bool.false_eq_true, if_false]
    rw [show [235#u8, 0#u8][1]! = 0#u8 from by simp, sx8_zero]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs]; simp, rfl⟩

theorem dec_jmpNear (t : x64_ir.PTarget) : DecodesTo (.JmpNear t) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.JmpNear t) = 235#u8 :: u32L 0#u32 := rfl
  have hu : u32L 0#u32 = [0#u8, 0#u8, 0#u8, 0#u8] := by decide
  rw [hbs, hu] at hb
  have hq := prefixes_plain hb hat (by simp) (by decide)
  have hb0 : x64_decode.byte_at bytes pos = ok (sxB 235#u8) := by
    have := byte_at_in (k := 0) hb (by omega) (by simp); simpa using this
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := pos) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pos.val + 1 := by simpa using hz1v0
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := pos) (y := 2#usize) (by simp; omega)
  have hz2v : z2.val = pos.val + 2 := by simpa using hz2v0
  obtain ⟨z3, hz3, hz3v0⟩ := usize_add_ok (x := pos) (y := 3#usize) (by simp; omega)
  have hz3v : z3.val = pos.val + 3 := by simpa using hz3v0
  obtain ⟨z4, hz4, hz4v0⟩ := usize_add_ok (x := pos) (y := 4#usize) (by simp; omega)
  have hz4v : z4.val = pos.val + 4 := by simpa using hz4v0
  obtain ⟨z5, hz5, hz5v0⟩ := usize_add_ok (x := pos) (y := 5#usize) (by simp; omega)
  have hz5v : z5.val = pos.val + 5 := by simpa using hz5v0
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.JmpNear (x64_ir.PTarget.Local 0#u32)) (disp := 0#i64)
      (pos := pos) (e := z5) (n := 5) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.JmpNear (x64_ir.PTarget.Local 0#u32), len := ln,
                 disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_plain hb0 rfl (by decide)]
    rw [decode_one_byte_tail (by decide) (by decide) (by decide)]
    rw [show x64_decode.alu_op 235#u8 = ok false from by rfl]
    simp only [bind_tc_ok, reduceIte, reduceCtorEq]
    norm_num [x64_decode.decode_rest]
    unfold x64_decode.decode_short_jmp
    simp only [hz1, bind_tc_ok]
    rw [byte_at_in (k := 1) hb (by omega) (by simp)]
    simp only [bind_tc_ok]
    rw [if_neg (sxB_nonneg' _)]
    simp only [hz2, hz3, hz4, hz5, bind_tc_ok]
    rw [byte_at_in (k := 2) hb (by omega) (by simp),
      byte_at_in (k := 3) hb (by omega) (by simp),
      byte_at_in (k := 4) hb (by omega) (by simp)]
    simp only [bind_tc_ok, List.getElem!_cons_succ, List.getElem!_cons_zero]
    rw [if_pos (by decide : sxB 0#u8 = 0#i32), if_pos (by decide : sxB 0#u8 = 0#i32)]
    simp only [show (decide (sxB 0#u8 = 0#i32)) = true from by decide, if_true]
    rw [sx8_zero]
    simp only [bind_tc_ok]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hu]; simp, rfl⟩

/-! ## A memory form: the locked read-modify-write -/

theorem dec_lockAlu (op : Std.U8) (w64 : Bool) (src base : Std.U8) (disp : Std.I32)
    (hop : op = 1#u8 ∨ op = 9#u8 ∨ op = 33#u8 ∨ op = 49#u8)
    (hsrc : src.val < 16) (hbase : base.val < 16) :
    DecodesTo (.LockAlu op w64 src base disp) := by
  intro bytes pos pre hb hat hfit
  have hbs : enc (x64_ir.PInsn.LockAlu op w64 src base disp)
      = 240#u8 :: (basicRexL (bitU w64) src base ++ op :: modrmDispL src base disp) := rfl
  rw [hbs] at hb
  set L := basicRexL (bitU w64) src base with hL
  set M := modrmDispL src base disp with hM
  have hrl : L.length ≤ 1 := hL ▸ basicRexL_length_le _ _ _
  have hml : M.length = modrmDispLen base disp := hM ▸ modrmDispL_length _ _ _
  have hmb := modrmDispLen_le base disp
  have hlen : (240#u8 :: (L ++ op :: M)).length = 1 + L.length + 1 + modrmDispLen base disp := by
    simp [hml]; omega
  obtain ⟨q, hq, hlock, ho16, hrep, hqw, hqr, hqb, hqat⟩ :=
    prefixes_pfx_opt_rex (rexl := L) (rest := op :: M) hb hat (by omega) (Or.inl rfl)
      (by simp) (by simp; rcases hop with h|h|h|h <;> rw [h] <;> decide)
      (hL ▸ basicRexL_case (bitU w64) src base (bitU_le _))
  have hgop : (240#u8 :: (L ++ op :: M))[1 + L.length]! = op := by
    rw [show 1 + L.length = L.length + 1 from by omega]
    simp only [List.getElem!_cons_succ]
    rw [getBang_append_right _ _ _ (by omega)]
    simp
  have hb0 : x64_decode.byte_at bytes q.at = ok (sxB op) := by
    rw [← hgop]
    exact byte_at_in (pre := pre) (bs := 240#u8 :: (L ++ op :: M)) (k := 1 + L.length)
      hb (by omega) (by omega)
  obtain ⟨z1, hz1, hz1v0⟩ := usize_add_ok (x := q.at) (y := 1#usize) (by simp; omega)
  have hz1v : z1.val = pre.length + (1 + L.length + 1) := by simp at hz1v0; omega
  obtain ⟨ln0, hln0, hmem⟩ :=
    decode_mem_eq (bytes := bytes) («at» := z1) (pre := pre ++ (240#u8 :: L) ++ [op])
      (bs := M) (rest := []) (reg := src) (rm := base) (d := disp)
      (rex_r := q.r) (rex_b := q.b) (by simp [hb]) (by simp; omega) (by simp [hM])
      (by simp; omega)
  obtain ⟨z2, hz2, hz2v0⟩ := usize_add_ok (x := z1) (y := ln0) (by rw [hln0]; omega)
  have hz2v : z2.val = pre.length + (1 + L.length + 1 + modrmDispLen base disp) := by
    rw [hz2v0, hz1v, hln0]; omega
  obtain ⟨ln, hln, hfin⟩ :=
    finish_spec (insn := x64_ir.PInsn.LockAlu op w64 src base disp) (disp := 0#i64)
      (pos := pos) (e := z2) (n := 1 + L.length + 1 + modrmDispLen base disp) (by omega)
  have hres : x64_decode.decode_one bytes pos =
      ok (some { insn := x64_ir.PInsn.LockAlu op w64 src base disp, len := ln,
                 disp := 0#i64 }) := by
    refine decode_one_eq hq ?_
    rw [decode_insn_lock hb0 (by rw [hlock]; decide)]
    unfold x64_decode.decode_locked
    rw [if_neg (by rcases hop with h|h|h|h <;> rw [h] <;> decide),
      if_neg (by rcases hop with h|h|h|h <;> rw [h] <;> decide)]
    simp only [hz1, bind_tc_ok]
    rw [hmem]
    simp only [bind_tc_ok, if_true, hz2]
    rw [hqr, hqb, hqw, bitU_eq_one, reg_rejoin src hsrc, reg_rejoin base hbase]
    exact hfin
  exact ⟨_, hres, rfl, by rw [hln, hbs, hlen], rfl⟩

end X64Enc
end async_ebpf_verified

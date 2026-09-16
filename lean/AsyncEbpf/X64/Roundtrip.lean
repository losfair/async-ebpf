import AsyncEbpf.X64.RoundtripReg
import AsyncEbpf.X64.RoundtripMem

/-!
# The roundtrip, over every primitive

`AsyncEbpf/X64/Encode.lean` pins the encoder to `enc`, a pure function from a
primitive to the bytes it appends (`encode_one_spec`), and to `size_of`, the
structural length of those bytes (`size_of_enc`).  `AsyncEbpf/X64/Assemble.lean`
states `DecodesTo p` — the bytes `enc p`, read at the offset the encoder wrote
them to, are what `x64_decode.decode_one` returns `p`'s `shape` from, with
`d.len` the number of bytes and `d.disp` the placeholder zero — and proves it,
together with `RoundtripReg.lean` and `RoundtripMem.lean`, for forty-two
primitive families, every operand symbolic.

This file closes over the `PInsn` type.  `decodesTo_all` is the case analysis:
every primitive the backend can emit, under the `RegsBounded` operand side
conditions the encodings need, is decoded back by the decoder to its shape and
its `size_of` length.  `enc_nil_of_emitsNothing`, restated here as
`enc_nil_of_emitsNothing'`, is its companion for the four remaining cases, so
the pair reads: a primitive either emits nothing, or it decodes back to its
shape.  `encode_decode` says the same of `x64_encode.encode_one` and
`x64_decode.decode_one` directly, with `enc` gone from the statement.

What this buys.  The decoder in `src/verified/x64_decode.rs` is written against
the Intel manual, independently of the encoder's table; the goldens no longer
carry the encoder's table alone.  Every byte the backend emits for an
instruction is one the decoder reads back as the instruction the encoder was
asked for, at the length the layout pass assumed, so an encoding that names the
wrong register, sets the wrong REX bit, picks the wrong displacement form or
miscounts its own bytes cannot pass both.  What remains trusted for the bytes is
the decoder's own table: the two agree, and the claim that what they agree on is
x86_64 rests on the decoder having been read against the manual.
-/
open Aeneas Aeneas.Std Result

set_option maxHeartbeats 1000000

namespace async_ebpf_verified

namespace X64Enc

/-! ## Every primitive at once -/

/-- **The roundtrip, over every primitive.**  A primitive the encoder emits
bytes for, whose operands satisfy the side conditions the encodings need, is
read back by the decoder — at the offset the encoder wrote it to — as that
primitive's shape, with the number of bytes the encoder appended and the
placeholder displacement zero. -/
theorem decodesTo_all (p : x64_ir.PInsn) (hb : RegsBounded p)
    (hne : emitsNothing p = false) : DecodesTo p := by
  cases p with
  | PcLabel _ => exact absurd hne (by simp [emitsNothing])
  | Local _ => exact absurd hne (by simp [emitsNothing])
  | ExitLabel => exact absurd hne (by simp [emitsNothing])
  | RetpolineLabel => exact absurd hne (by simp [emitsNothing])
  | Push r => exact dec_push r hb
  | Pop r => exact dec_pop r hb
  | Alu w64 op src dst => exact dec_alu w64 op src dst hb.1 hb.2
  | AluImm w64 op dst imm => exact dec_aluImm w64 op dst imm hb
  | ShiftImm w64 op dst imm => exact dec_shiftImm w64 op dst imm hb
  | ShiftCl w64 op dst => exact dec_shiftCl w64 op dst hb
  | Neg w64 dst => exact dec_neg w64 dst hb
  | MulDivRcx w64 kind signed => exact dec_mulDivRcx w64 kind signed
  | MovSx from_ w64 src dst => exact dec_movSx from_ w64 src dst hb.1 hb.2.1 hb.2.2
  | Bswap w64 dst => exact dec_bswap w64 dst hb
  | Rol16 dst => exact dec_rol16 dst hb
  | Cmov cc dst src => exact dec_cmov cc dst src hb.1 hb.2.1 hb.2.2
  | LoadImm dst imm => exact dec_loadImm dst imm hb
  | Pushfq => exact dec_pushfq
  | Popfq => exact dec_popfq
  | Cqo => exact dec_cqo
  | Cdq => exact dec_cdq
  | CmpRcxMinusOne w64 => exact dec_cmpRcxMinusOne w64
  | CmpEaxImm imm => exact dec_cmpEaxImm imm
  | Load size sxf base dst disp => exact dec_load size sxf base dst disp hb.1 hb.2.1 hb.2.2 hne
  | Store size src base disp => exact dec_store size src base disp hb.1 hb.2.1 hb.2.2
  | StoreImm size base disp imm => exact dec_storeImm size base disp imm hb.1 hb.2
  | AluRM op reg base disp => exact dec_aluRM op reg base disp hb.1 hb.2
  | StoreRspImm imm => exact dec_storeRspImm imm
  | StoreRspRax => exact dec_storeRspRax
  | LockAlu op w64 src base disp => exact dec_lockAlu op w64 src base disp hb.1 hb.2.1 hb.2.2
  | LockCmpxchg w64 src base disp => exact dec_lockCmpxchg w64 src base disp hb.1 hb.2
  | Xchg w64 src base disp => exact dec_xchg w64 src base disp hb.1 hb.2
  | Jcc cc t => exact dec_jcc cc t hb
  | Jmp t => exact dec_jmp t
  | JmpNear t => exact dec_jmpNear t
  | Call t => exact dec_call t
  | Jcc8 cc n => exact dec_jcc8 cc n hb
  | Jmp8 n => exact dec_jmp8 n
  | Ret => exact dec_ret
  | Pause => exact dec_pause
  | Ud2 => exact dec_ud2
  | CallReg reg => exact dec_callReg reg hb
  | RipLoadDispatcher dst => exact dec_ripLoadDispatcher dst hb
  | RipLeaHelperTable dst => exact dec_ripLeaHelperTable dst hb
  | DispatcherSlot addr => exact dec_dispatcherSlot addr hb
  | HelperTable => exact dec_helperTable

/-- **The companion.**  The primitives `decodesTo_all` does not cover are
exactly the ones the encoder writes no bytes for.  (This is
`enc_nil_of_emitsNothing`, restated here so the pair can be read together.) -/
theorem enc_nil_of_emitsNothing' {p : x64_ir.PInsn} (h : emitsNothing p = true) :
    enc p = [] := enc_nil_of_emitsNothing h

/-- **Either nothing or the shape.**  Every primitive, with no side condition
on `emitsNothing`: it emits no bytes, or its bytes decode back to its shape. -/
theorem enc_nil_or_decodesTo (p : x64_ir.PInsn) (hb : RegsBounded p) :
    enc p = [] ∨ DecodesTo p := by
  cases h : emitsNothing p with
  | true => exact Or.inl (enc_nil_of_emitsNothing h)
  | false => exact Or.inr (decodesTo_all p hb h)

/-! ## The same, over the extracted encoder and decoder -/

/-- **The roundtrip, with `enc` gone from the statement.**  Run the extracted
encoder on `p` at the end of `out`; then the extracted decoder, run on the
result at the offset the encoder started writing at, returns `p`'s shape, the
number of bytes the encoder appended, and the placeholder displacement zero. -/
theorem encode_decode (p : x64_ir.PInsn) (hb : RegsBounded p)
    (hne : emitsNothing p = false) (out : alloc.vec.Vec Std.U8) (pos : Usize)
    (hpos : pos.val = out.val.length) (hroom : out.val.length + 1024 ≤ Usize.max) :
    x64_encode.encode_one p out ⦃ out' =>
      ∃ d : x64_decode.Decoded,
        x64_decode.decode_one out'.slice pos = ok (some d) ∧
        d.insn = shape p ∧
        d.len.val = out'.val.length - out.val.length ∧
        d.disp = 0#i64 ⦄ := by
  obtain ⟨o, ho, hov⟩ := WP.spec_imp_exists (encode_one_spec p out (by omega))
  apply WP.exists_imp_spec
  refine ⟨o, ho, ?_⟩
  obtain ⟨d, hd1, hd2, hd3, hd4⟩ :=
    decodesTo_all p hb hne o.slice pos out.val hov hpos (by omega)
  exact ⟨d, hd1, hd2, by rw [hd3, hov]; simp, hd4⟩

end X64Enc

end async_ebpf_verified

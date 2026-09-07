import AsyncEbpf.Validate.Spec

/-!
# The decoder, pinned to bytes

`Spec` states instruction classes through the decoder. The decoder is a pure
function of one byte, so each class is checked here against an explicit byte
list by running it on all 256 values. These are the facts a reader wants next
to the spec: which opcodes the store-form exception covers, and that `lddw` is
the one two-slot instruction.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

/-- `st`, `stx`, and the two atomics: `src/jit/validate.rs`'s `ST`, `STX`,
`ATOMIC32` and `ATOMIC64` filter rows. -/
def storeFormBytes : List Nat :=
  [0x62, 0x6a, 0x72, 0x7a, 0x63, 0x6b, 0x73, 0x7b, 0xc3, 0xdb]

/-- A byte, as a `U8`. -/
def byte (n : Nat) (h : n < 256) : U8 :=
  U8.ofNatCore n (by simpa using h)

theorem byte_val (n : Nat) (h : n < 256) : (byte n h).val = n :=
  U8.ofNatCore_val_eq _

theorem eq_byte (x : U8) : x = byte x.val (by scalar_tac) := by
  apply UScalar.eq_of_val_eq
  rw [byte_val]

/-- One byte's worth of the store-form claim, as a `Bool` the kernel can run. -/
def storeFormCheck (n : Nat) (h : n < 256) : Bool :=
  match isa.decode (byte n h) with
  | ok (some op) =>
    match validate.is_store_form op with
    | ok true => storeFormBytes.contains n
    | _ => true
  | _ => true

theorem storeFormCheck_all : ∀ n : Fin 256, storeFormCheck n.val n.isLt = true := by
  with_unfolding_all decide +kernel

/-- The store forms are exactly the ten bytes of `storeFormBytes`. -/
theorem StoreForm_imp_mem (x : U8) (h : StoreForm x) : x.val ∈ storeFormBytes := by
  obtain ⟨op, hdec, hsf⟩ := h
  have hlt : x.val < 256 := by scalar_tac
  have hc := storeFormCheck_all ⟨x.val, hlt⟩
  unfold storeFormCheck at hc
  rw [← eq_byte x, hdec] at hc
  simp only [hsf] at hc
  simpa using hc

/-- One byte's worth of the `lddw` claim. -/
def lddwCheck (n : Nat) (h : n < 256) : Bool :=
  match isa.decode (byte n h) with
  | ok (some op) =>
    match validate.is_load_imm64 op with
    | ok true => n == 0x18
    | _ => true
  | _ => true

theorem lddwCheck_all : ∀ n : Fin 256, lddwCheck n.val n.isLt = true := by
  with_unfolding_all decide +kernel

/-- The one two-slot instruction is opcode `0x18`. -/
theorem IsLddw_imp_eq (x : U8) (h : IsLddw x) : x.val = 0x18 := by
  obtain ⟨op, hdec, hli⟩ := h
  have hlt : x.val < 256 := by scalar_tac
  have hc := lddwCheck_all ⟨x.val, hlt⟩
  unfold lddwCheck at hc
  rw [← eq_byte x, hdec] at hc
  simp only [hli] at hc
  simpa using hc

end async_ebpf_verified

namespace async_ebpf_verified

/-- Where the decoder sees an atomic, the filter row bounds the source at R9:
a fetching atomic writes its source, which must not be the frame pointer. -/
def atomicSrcCheck (n : Nat) (h : n < 256) : Bool :=
  match isa.decode (byte n h) with
  | ok (some (.Atomic _ _ _)) =>
    match validate.filter_for (byte n h) with
    | ok (some f) => decide (f.src_hi.val ≤ 9)
    | _ => false
  | _ => true

theorem atomicSrcCheck_all : ∀ n : Fin 256, atomicSrcCheck n.val n.isLt = true := by
  with_unfolding_all decide +kernel

theorem atomic_src_hi (x : U8) (w : isa.Width) (o : isa.AtomicOp) (b : Bool)
    (hdec : isa.decode x = ok (some (.Atomic w o b))) (f : validate.Filter)
    (hf : validate.filter_for x = ok (some f)) : f.src_hi.val ≤ 9 := by
  have hlt : x.val < 256 := by scalar_tac
  have hc := atomicSrcCheck_all ⟨x.val, hlt⟩
  unfold atomicSrcCheck at hc
  rw [← eq_byte x, hdec] at hc
  simp only [hf] at hc
  simpa using hc

end async_ebpf_verified

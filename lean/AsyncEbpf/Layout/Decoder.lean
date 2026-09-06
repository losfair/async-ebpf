import AsyncEbpf.Layout.Spec
import AsyncEbpf.Validate.Decoder

/-!
# The layout's byte classes agree with the decoder

The layout code reads successors off opcode bytes (`byteEdges`); the
semantics steps by decoded instructions. The two are reconciled here by
running the decoder on all 256 bytes: every edge the semantics can take out
of a decoded instruction is one the byte classification lists, and a `call`
decodes only from the byte `0x85`.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

/-- The edges the semantics takes out of a decoded instruction. -/
def opEdges : isa.Op → List Edge
  | .Exit => []
  | .LoadImm64 => [.skip]
  | .Ja _ => [.jump]
  | .Jmp _ _ _ => [.jump, .fall]
  | _ => [.fall]

/-- One byte's worth of the claim, as a `Bool` the kernel can run. -/
def edgesCheck (n : Nat) (h : n < 256) : Bool :=
  match isa.decode (byte n h) with
  | ok (some op) =>
    (opEdges op).all (fun e => decide (e ∈ byteEdges (byte n h))) &&
    (match op with
      | .Call => decide (byte n h = isa.OP_CALL)
      | _ => true)
  | _ => true

theorem edgesCheck_all : ∀ n : Fin 256, edgesCheck n.val n.isLt = true := by
  with_unfolding_all decide +kernel

theorem edgesCheck_of (x : U8) {op : isa.Op} (hdec : isa.decode x = ok (some op)) :
    (∀ e ∈ opEdges op, e ∈ byteEdges x) ∧
    (match op with | .Call => x = isa.OP_CALL | _ => True) := by
  have hlt : x.val < 256 := by scalar_tac
  have hc := edgesCheck_all ⟨x.val, hlt⟩
  unfold edgesCheck at hc
  rw [← eq_byte x, hdec] at hc
  simp only [Bool.and_eq_true, List.all_eq_true, decide_eq_true_iff] at hc
  refine ⟨hc.1, ?_⟩
  have := hc.2
  cases op <;> (try simp only at this ⊢) <;> first | trivial | exact of_decide_eq_true this

/-- Every edge the semantics takes is one the layout follows. -/
theorem opEdges_sub (x : U8) {op : isa.Op} (hdec : isa.decode x = ok (some op)) :
    ∀ e ∈ opEdges op, e ∈ byteEdges x :=
  (edgesCheck_of x hdec).1

/-- A `call` decodes only from `0x85`. -/
theorem decode_call_opcode (x : U8) (hdec : isa.decode x = ok (some .Call)) : x = isa.OP_CALL :=
  (edgesCheck_of x hdec).2

end async_ebpf_verified

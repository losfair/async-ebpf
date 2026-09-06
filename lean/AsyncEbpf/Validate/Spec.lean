import AsyncEbpf.EbpfValidate

/-!
# What an accepted program looks like

The statements here are the *specification* side of the validator proof. They
are written against the types Aeneas generated from `lean/ebpf_validate`
(`Insn`, `Op`, the decoder) but say nothing about how `validate` computes:
they describe the shape of a program the loader may hand to the JIT.

The headline property is `NoFramePointerWrite`: no instruction slot of an
accepted program names R10 as its destination unless the instruction is a
store form, whose destination is a memory base rather than a written register.
`frame_access` in `src/region_analysis.rs` calls this "the only part of the
claim the backend cannot re-derive for itself": it is the premise on which the
unchecked `FRAME` access path rests.

Instruction classes are stated through the decoder (`decode`, `is_store_form`,
`is_load_imm64`), which is a pure table over the opcode byte.
`AsyncEbpf.Validate.Decoder` pins that table down to the concrete bytes.
-/
open Aeneas Aeneas.Std Result

namespace ebpf_validate

/-- Slot `i` holds a two-slot `lddw`, as the decoder classifies it. -/
def IsLddw (opcode : U8) : Prop :=
  ∃ op, decode opcode = ok (some op) ∧ is_load_imm64 op = ok true

/-- Slot `i` holds a one-slot instruction. -/
def IsSingle (opcode : U8) : Prop :=
  ∃ op, decode opcode = ok (some op) ∧ is_load_imm64 op = ok false

/-- `Walk insns i j`: slot `j` is reached from slot `i` by stepping over
instructions, two slots at a time across an `lddw` whose second slot is not
an instruction. -/
inductive Walk (insns : List Insn) : Nat → Nat → Prop
  | refl (i : Nat) : Walk insns i i
  | next {i j : Nat} (hi : i < insns.length) :
      IsSingle insns[i].opcode → Walk insns (i + 1) j → Walk insns i j
  | lddw {i j : Nat} (hi : i < insns.length) :
      IsLddw insns[i].opcode → Walk insns (i + 2) j → Walk insns i j

/-- The instruction slots of a program: the slots reached from slot 0. -/
def InsnSlot (insns : List Insn) (j : Nat) : Prop := Walk insns 0 j

/-- The instructions whose destination field is a memory base: `st`, `stx`
and the atomics, as the decoder classifies them. -/
def StoreForm (opcode : U8) : Prop :=
  ∃ op, decode opcode = ok (some op) ∧ is_store_form op = ok true

/-- A defined instruction: one the decoder accepts. -/
def Decodes (opcode : U8) : Prop :=
  ∃ op, decode opcode = ok (some op)

/-- Slot `j` never assigns the frame pointer. -/
def NoFramePointerWrite (insns : List Insn) (j : Nat) (hj : j < insns.length) : Prop :=
  insns[j].dst.val ≤ 9 ∨ (insns[j].dst.val = 10 ∧ StoreForm insns[j].opcode)

/-- What the validator establishes for every instruction slot. -/
structure SlotOk (insns : List Insn) (j : Nat) (hj : j < insns.length) : Prop where
  decodes : Decodes insns[j].opcode
  src_bound : insns[j].src.val ≤ 10
  no_fp_write : NoFramePointerWrite insns j hj

/-- An accepted program: every instruction slot satisfies `SlotOk`. -/
def WellFormed (insns : List Insn) : Prop :=
  ∀ j (hj : j < insns.length), InsnSlot insns j → SlotOk insns j hj

end ebpf_validate

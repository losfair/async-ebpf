import AsyncEbpf.AsyncEbpfVerified

/-!
# What an accepted program looks like

The statements here are the *specification* side of the validator proof. They
are written against the types Aeneas generated from `src/verified`
(`Insn`, `Op`, the decoder) but say nothing about how `validate` computes:
they describe the shape of a program the loader may hand to the JIT.

`WellFormed` collects, for every instruction slot the validator walks:

* the slot decodes;
* register fields are in range, with the one exception the JIT depends on:
  R10 is a destination only in a store form, whose destination is a memory
  base rather than a written register (`frame_access` in
  `src/region_analysis.rs` calls "the guest never assigned R10" the only
  premise the backend cannot re-derive for itself);
* the structural rules: a jump lands on a real slot inside the program, so
  does a local call, and an `lddw` has its high half.

`AsyncEbpf.Semantics.Soundness` turns these into a statement about
execution: an accepted program never leaves its instruction slots and never
moves the frame pointer except through calls and returns.

Instruction classes are stated through the decoder (`isa.decode`,
`validate.is_store_form`, `validate.is_load_imm64`), which is a pure table
over the opcode byte. `AsyncEbpf.Validate.Decoder` pins that table down to
the concrete bytes.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

/-- Slot `i` holds a two-slot `lddw`, as the decoder classifies it. -/
def IsLddw (opcode : U8) : Prop :=
  ∃ op, isa.decode opcode = ok (some op) ∧ validate.is_load_imm64 op = ok true

/-- Slot `i` holds a one-slot instruction. -/
def IsSingle (opcode : U8) : Prop :=
  ∃ op, isa.decode opcode = ok (some op) ∧ validate.is_load_imm64 op = ok false

/-- `Walk insns i j`: slot `j` is reached from slot `i` by stepping over
instructions, two slots at a time across an `lddw` whose second slot is not
an instruction. -/
inductive Walk (insns : List isa.Insn) : Nat → Nat → Prop
  | refl (i : Nat) : Walk insns i i
  | next {i j : Nat} (hi : i < insns.length) :
      IsSingle insns[i].opcode → Walk insns (i + 1) j → Walk insns i j
  | lddw {i j : Nat} (hi : i < insns.length) :
      IsLddw insns[i].opcode → Walk insns (i + 2) j → Walk insns i j

/-- The instruction slots of a program: the slots reached from slot 0. -/
def InsnSlot (insns : List isa.Insn) (j : Nat) : Prop := Walk insns 0 j

/-- The instructions whose destination field is a memory base: `st`, `stx`
and the atomics, as the decoder classifies them. -/
def StoreForm (opcode : U8) : Prop :=
  ∃ op, isa.decode opcode = ok (some op) ∧ validate.is_store_form op = ok true

/-- A defined instruction: one the decoder accepts. -/
def Decodes (opcode : U8) : Prop :=
  ∃ op, isa.decode opcode = ok (some op)

/-! ## Structural rules -/

/-- A jump's displacement: `ja32` (opcode `0x06`) carries it in the
immediate, every other jump in the offset. -/
def jumpDisp (insn : isa.Insn) : Int :=
  if insn.opcode.val = 6 then insn.imm.val else insn.offset.val

/-- Where a jump at slot `j` lands, as an integer: `j + 1 + displacement`. -/
def jumpTargetInt (insn : isa.Insn) (j : Nat) : Int :=
  Int.ofNat (j + 1) + jumpDisp insn

/-- Where a local call at slot `j` lands. -/
def callTargetInt (insn : isa.Insn) (j : Nat) : Int :=
  Int.ofNat (j + 1) + insn.imm.val

/-- `t` names a slot of the program that is not the high half of an `lddw`:
those halves are the only slots with opcode byte zero. -/
def RealSlot (insns : List isa.Insn) (t : Int) : Prop :=
  0 ≤ t ∧ ∃ h : t.toNat < insns.length, insns[t.toNat].opcode.val ≠ 0

/-- The jump at slot `j` is not to itself and lands on a real slot. -/
def JumpOk (insns : List isa.Insn) (j : Nat) (insn : isa.Insn) : Prop :=
  jumpDisp insn ≠ -1 ∧ RealSlot insns (jumpTargetInt insn j)

/-- A `call` is a helper call, a local call to a real slot, or a
linker-tagged cross-section call. -/
def CallOk (insns : List isa.Insn) (j : Nat) (insn : isa.Insn) : Prop :=
  (insn.src.val = 0 ∨ insn.src.val = 1 ∨ insn.src.val = 2) ∧
  (insn.src.val = 1 → RealSlot insns (callTargetInt insn j))

/-- The high half of an `lddw` at `j` exists and is a zero word. -/
def LddwOk (insns : List isa.Insn) (j : Nat) : Prop :=
  ∃ h : j + 1 < insns.length, insns[j + 1].opcode.val = 0

/-- The structural rule for one decoded instruction. -/
def StructureOk (insns : List isa.Insn) (j : Nat) (insn : isa.Insn) (op : isa.Op) : Prop :=
  match op with
  | .LoadImm64 => LddwOk insns j
  | .Ja _ | .Jmp _ _ _ => JumpOk insns j insn
  | .Call => CallOk insns j insn
  | _ => True

/-! ## Per-slot facts -/

def IsAtomic (op : isa.Op) : Prop :=
  match op with
  | .Atomic _ _ _ => True
  | _ => False

/-- What the validator establishes for the instruction `op` decoded at
slot `j`. -/
structure SlotFacts (insns : List isa.Insn) (j : Nat) (hj : j < insns.length) (op : isa.Op) :
    Prop where
  src_bound : insns[j].src.val ≤ 10
  dst_bound : insns[j].dst.val ≤ 9 ∨ (insns[j].dst.val = 10 ∧ validate.is_store_form op = ok true)
  /-- A fetching atomic writes its source register, so R10 is refused there. -/
  atomic_src : IsAtomic op → insns[j].src.val ≤ 9
  structure_ok : StructureOk insns j insns[j] op

/-- Slot `j` decodes, and the validator's facts hold of what it decodes to. -/
def SlotOk (insns : List isa.Insn) (j : Nat) (hj : j < insns.length) : Prop :=
  ∃ op, isa.decode insns[j].opcode = ok (some op) ∧ SlotFacts insns j hj op

/-- An accepted program: every instruction slot satisfies `SlotOk`. -/
def WellFormed (insns : List isa.Insn) : Prop :=
  ∀ j (hj : j < insns.length), InsnSlot insns j → SlotOk insns j hj

/-- Slot `j` never assigns the frame pointer. -/
def NoFramePointerWrite (insns : List isa.Insn) (j : Nat) (hj : j < insns.length) : Prop :=
  insns[j].dst.val ≤ 9 ∨ (insns[j].dst.val = 10 ∧ StoreForm insns[j].opcode)

end async_ebpf_verified

import AsyncEbpf.AsyncEbpfVerified

/-!
# An operational semantics of eBPF

A small-step semantics of the instruction set the runtime implements, written
against the decoder Aeneas extracted from `src/verified/isa.rs` so that the
semantics and the runtime agree on which byte means which instruction.

## What is modelled

* The eleven 64-bit registers, the program counter, and a call stack. A
  local call saves `R6`–`R9` and the frame pointer and moves `R10` down by
  the frame stride; `exit` restores them. This is the calling convention the
  JIT implements (`src/jit/interp.rs` settled it by black-box probe).
* Every ALU and jump instruction, with the ISA's fine print: 32-bit
  operations compute on the low half and zero-extend, shift amounts are
  masked, division by zero is defined, `arsh` is arithmetic at its width,
  32-bit jumps compare the low halves, immediates are sign-extended before
  use, `lddw` takes its high half from the following slot.
* Faults and the two ways a program stops: `exit` with an empty call stack,
  and running off the end of the instruction stream, which the loader
  permits for a program without local calls.

## What is abstracted

Memory. A load yields *any* value of its width and a store changes nothing
the machine state records; a memory instruction may also fault. Helper calls
return any value in `R0` and may clobber `R1`–`R5`, or fault. These are
over-approximations: every real execution is one of the executions here, so
a property proved of all executions holds of the real ones. Provenance-aware
memory is the next layer, for the region-analysis proofs.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

deriving instance DecidableEq for isa.Width, isa.AluWidth, isa.Source, isa.AluOp, isa.JmpOp,
  isa.EndKind, isa.AtomicOp, isa.Op

namespace Sem

open isa

abbrev Word := BitVec 64

/-- The register file: `R0` … `R10`. -/
abbrev Regs := Fin 11 → Word

/-- The frame pointer register. -/
def R10 : Fin 11 := ⟨10, by decide⟩

/-- What a local call saves, and restores on `exit`. -/
structure Frame where
  /-- The slot after the call. -/
  ret : Nat
  /-- `R6`–`R9`, callee-saved by the implementation. -/
  saved : Fin 4 → Word
  /-- The caller's `R10`. -/
  fp : Word

structure State where
  regs : Regs
  pc : Nat
  stack : List Frame

/-- How a run ends. -/
inductive Outcome where
  /-- `exit` at depth zero, with the value of `R0`. -/
  | exited (r0 : Word)
  /-- Control fell off the end of the instruction stream. -/
  | fellOff
  /-- A memory access, a helper, or the guest-stack capacity refused. -/
  | fault

inductive Config where
  | next (s : State)
  | halt (o : Outcome)

/-- The machine's fixed parameters. -/
structure Params where
  /-- Bytes between successive values of `R10`. -/
  stride : Word
  /-- Local calls the guest stack has room for. -/
  maxDepth : Nat

/-! ## Arithmetic -/

/-- Immediates are sign-extended from 32 to 64 bits before use. -/
def imm64 (imm : I32) : Word := BitVec.signExtend 64 imm.bv

/-- The `offset` field, likewise. -/
def off64 (off : I16) : Word := BitVec.signExtend 64 off.bv

def low32 (w : Word) : BitVec 32 := w.truncate 32

def zext32 (w : BitVec 32) : Word := w.zeroExtend 64

/-- `BitVec.udiv`/`umod` already define division by zero the way the ISA
does: the quotient is zero and the remainder is the dividend. -/
def alu64 (op : AluOp) (a b : Word) : Word :=
  match op with
  | .Add => a + b
  | .Sub => a - b
  | .Mul => a * b
  | .Div => a / b
  | .Or => a ||| b
  | .And => a &&& b
  | .Lsh => a <<< (b &&& 63#64)
  | .Rsh => a >>> (b &&& 63#64)
  | .Neg => -a
  | .Mod => a % b
  | .Xor => a ^^^ b
  | .Mov => b
  | .Arsh => a.sshiftRight (b &&& 63#64).toNat

/-- The 32-bit forms compute on the low halves and zero-extend, `mod` by
zero included: the destination is truncated even when it is left alone. -/
def alu32 (op : AluOp) (a b : Word) : Word :=
  let a := low32 a
  let b := low32 b
  zext32 <| match op with
  | .Add => a + b
  | .Sub => a - b
  | .Mul => a * b
  | .Div => a / b
  | .Or => a ||| b
  | .And => a &&& b
  | .Lsh => a <<< (b &&& 31#32)
  | .Rsh => a >>> (b &&& 31#32)
  | .Neg => -a
  | .Mod => a % b
  | .Xor => a ^^^ b
  | .Mov => b
  | .Arsh => a.sshiftRight (b &&& 31#32).toNat

def alu (width : AluWidth) (op : AluOp) (a b : Word) : Word :=
  match width with
  | .W64 => alu64 op a b
  | .W32 => alu32 op a b

/-- `movsx`: `mov` from a sign-extended 8-, 16- or 32-bit source. The
`offset` field names the width; zero is a plain `mov`. -/
def movsx (width : AluWidth) (bits : Nat) (b : Word) : Word :=
  let v :=
    if bits = 8 then BitVec.signExtend 64 (b.truncate 8)
    else if bits = 16 then BitVec.signExtend 64 (b.truncate 16)
    else if bits = 32 then BitVec.signExtend 64 (b.truncate 32)
    else b
  match width with
  | .W64 => v
  | .W32 => zext32 (low32 v)

/-- Reverses the low `bytes` bytes and zero-extends. -/
def bswapBytes (bytes : Nat) (w : Word) : Word :=
  let byte (i : Nat) : Word := (w >>> (8 * i)) &&& 0xff#64
  (List.range bytes).foldl (fun acc i => acc ||| (byte i <<< (8 * (bytes - 1 - i)))) 0#64

/-- `le` is a truncation on a little-endian host, `be` and `bswap` reverse
the named number of bytes; all three zero-extend. -/
def endian (kind : EndKind) (bits : Nat) (w : Word) : Word :=
  let bytes := bits / 8
  match kind with
  | .Le => w &&& (BitVec.allOnes 64 >>> (64 - bits))
  | .Be | .Bswap => bswapBytes bytes w

/-- The comparison a conditional jump performs, at the named width. -/
def jumpTaken (width : AluWidth) (op : JmpOp) (a b : Word) : Bool :=
  match width with
  | .W64 => cmp op a b
  | .W32 => cmp op (zext32 (low32 a)) (zext32 (low32 b))
where
  cmp (op : JmpOp) (a b : Word) : Bool :=
    match op with
    | .Eq => a == b
    | .Gt => b.ult a
    | .Ge => b.ule a
    | .Set => (a &&& b) != 0#64
    | .Ne => a != b
    | .Sgt => b.slt a
    | .Sge => b.sle a
    | .Lt => a.ult b
    | .Le => a.ule b
    | .Slt => a.slt b
    | .Sle => a.sle b

/-- The atomic operation selector, from the immediate's high nibble, with the
fetch flag in its low bit. Mirrors `Insn::op_with_imm` in `src/verified/isa.rs`,
which the extraction does not see. -/
def atomicSelector (imm : I32) : Option (AtomicOp × Bool) :=
  let sel := (imm.bv &&& 0xf0#32).toNat
  let fetch := (imm.bv &&& 1#32) != 0#32
  let op : Option AtomicOp :=
    if sel = 0x00 then some .Add
    else if sel = 0x40 then some .Or
    else if sel = 0x50 then some .And
    else if sel = 0xa0 then some .Xor
    else if sel = 0xe0 then some .Xchg
    else if sel = 0xf0 then some .Cmpxchg
    else none
  op.map fun op => (op, fetch)

/-! ## Reading the program -/

/-- The instruction at slot `pc`, if the slot exists and decodes. -/
def decodeAt (insns : List Insn) (pc : Nat) : Option (Insn × Op) :=
  match insns[pc]? with
  | none => none
  | some insn =>
    match isa.decode insn.opcode with
    | ok (some op) => some (insn, op)
    | _ => none

/-- The 64-bit immediate of an `lddw` at `pc`: its own immediate is the low
half, the following slot's the high half. -/
def lddwImm (insns : List Insn) (pc : Nat) (lo : Insn) : Word :=
  let hi : BitVec 32 := match insns[pc + 1]? with
    | some h => h.imm.bv
    | none => 0#32
  (hi.zeroExtend 64 <<< 32) ||| lo.imm.bv.zeroExtend 64

/-- The register a `Fin 11` names, from a 4-bit field the validator has
bounded. Out-of-range fields never occur in an accepted program; they read
`R0` here so that the semantics is total. -/
def reg (n : U8) : Fin 11 :=
  if h : n.val < 11 then ⟨n.val, h⟩ else ⟨0, by decide⟩

def setReg (regs : Regs) (r : Fin 11) (v : Word) : Regs :=
  Function.update regs r v

/-- Jump displacement: `ja32` (opcode `0x06`) carries it in the immediate,
every other jump in the offset. The target is `pc + 1 + displacement` in
two's complement, so a target below zero wraps to a huge slot number, which
is off the end. -/
def jumpTarget (insn : Insn) (pc : Nat) : Nat :=
  let disp : Int := if insn.opcode.val = 6 then insn.imm.val else insn.offset.val
  (Int.ofNat (pc + 1) + disp).toNat

def callTarget (insn : Insn) (pc : Nat) : Nat :=
  (Int.ofNat (pc + 1) + insn.imm.val).toNat

def savedRegs (regs : Regs) : Fin 4 → Word :=
  fun i => regs ⟨6 + i.val, by omega⟩

def restoreRegs (regs : Regs) (f : Frame) : Regs :=
  fun r =>
    if h : 6 ≤ r.val ∧ r.val ≤ 9 then f.saved ⟨r.val - 6, by omega⟩
    else if r = R10 then f.fp
    else regs r

/-- Registers a helper may have changed: `R0` (its result) and the argument
registers `R1`–`R5`. Everything else survives the call. -/
def HelperClobber (before after : Regs) : Prop :=
  ∀ r : Fin 11, 6 ≤ r.val → after r = before r

/-- A value a load of `width` bytes can produce. -/
def LoadValue (width : Width) (signed : Bool) (v : Word) : Prop :=
  match width, signed with
  | .DW, _ => True
  | .W, false => v = zext32 (low32 v)
  | .W, true => v = BitVec.signExtend 64 (v.truncate 32)
  | .H, false => v = (v.truncate 16).zeroExtend 64
  | .H, true => v = BitVec.signExtend 64 (v.truncate 16)
  | .B, false => v = (v.truncate 8).zeroExtend 64
  | .B, true => v = BitVec.signExtend 64 (v.truncate 8)

/-- The second operand of an ALU or jump instruction. -/
def operand (regs : Regs) (insn : Insn) (source : Source) : Word :=
  match source with
  | .Imm => imm64 insn.imm
  | .Reg => regs (reg insn.src)

/-- What an ALU instruction writes to its destination. A `mov` with a
non-zero offset is `movsx`. -/
def aluResult (regs : Regs) (insn : Insn) (width : AluWidth) (op : AluOp) (source : Source) :
    Word :=
  if op = .Mov ∧ insn.offset.val ≠ 0
  then movsx width insn.offset.val.toNat (operand regs insn source)
  else alu width op (regs (reg insn.dst)) (operand regs insn source)

/-- Where a conditional jump continues. -/
def jmpNext (regs : Regs) (insn : Insn) (pc : Nat) (width : AluWidth) (op : JmpOp)
    (source : Source) : Nat :=
  if jumpTaken width op (regs (reg insn.dst)) (operand regs insn source)
  then jumpTarget insn pc
  else pc + 1

/-- The register file after an atomic whose previous memory contents were
`v`: `cmpxchg` writes them to `R0`, a fetching form to `src`. -/
def atomicRegs (regs : Regs) (insn : Insn) (op : AtomicOp) (fetch : Bool) (v : Word) : Regs :=
  if op = .Cmpxchg then setReg regs ⟨0, by decide⟩ v
  else if fetch then setReg regs (reg insn.src) v
  else regs

/-! ## The step relation -/

/-- One step of the machine. `Step P insns s c`: from `s`, the program
`insns` may move to `c`. Nondeterminism stands in for memory and helpers. -/
inductive Step (P : Params) (insns : List Insn) : State → Config → Prop
  /-- Fallthrough past the last slot. -/
  | fellOff (s : State) :
      s.pc = insns.length → Step P insns s (.halt .fellOff)

  | alu (s : State) (insn : Insn) (width : AluWidth) (op : AluOp) (source : Source) :
      decodeAt insns s.pc = some (insn, .Alu width op source) →
      Step P insns s (.next { s with
        regs := setReg s.regs (reg insn.dst) (aluResult s.regs insn width op source),
        pc := s.pc + 1 })

  | endian (s : State) (insn : Insn) (kind : EndKind) :
      decodeAt insns s.pc = some (insn, .End kind) →
      Step P insns s (.next { s with
        regs := setReg s.regs (reg insn.dst)
          (Sem.endian kind insn.imm.val.toNat (s.regs (reg insn.dst))),
        pc := s.pc + 1 })

  | loadImm64 (s : State) (insn : Insn) :
      decodeAt insns s.pc = some (insn, .LoadImm64) →
      Step P insns s (.next { s with
        regs := setReg s.regs (reg insn.dst) (lddwImm insns s.pc insn),
        pc := s.pc + 2 })

  /-- A load yields any value of its width. -/
  | load (s : State) (insn : Insn) (width : Width) (signed : Bool) (v : Word) :
      decodeAt insns s.pc = some (insn, .Load width signed) →
      LoadValue width signed v →
      Step P insns s (.next { s with regs := setReg s.regs (reg insn.dst) v, pc := s.pc + 1 })

  | storeImm (s : State) (insn : Insn) (width : Width) :
      decodeAt insns s.pc = some (insn, .StoreImm width) →
      Step P insns s (.next { s with pc := s.pc + 1 })

  | storeReg (s : State) (insn : Insn) (width : Width) :
      decodeAt insns s.pc = some (insn, .StoreReg width) →
      Step P insns s (.next { s with pc := s.pc + 1 })

  /-- A fetching atomic writes the previous memory contents to `src`, and
  `cmpxchg` writes them to `R0` instead; both are any value here. The
  non-fetching forms change no register. -/
  | atomic (s : State) (insn : Insn) (width : Width) (op : AtomicOp) (fetch : Bool)
      (v : Word) :
      decodeAt insns s.pc = some (insn, .Atomic width .Add false) →
      atomicSelector insn.imm = some (op, fetch) →
      Step P insns s (.next { s with regs := atomicRegs s.regs insn op fetch v, pc := s.pc + 1 })

  /-- Any memory instruction may fault. -/
  | memFault (s : State) (insn : Insn) (op : Op) :
      decodeAt insns s.pc = some (insn, op) →
      (match op with
        | .Load .. | .StoreImm .. | .StoreReg .. | .Atomic .. => True
        | _ => False) →
      Step P insns s (.halt .fault)

  | ja (s : State) (insn : Insn) (width : AluWidth) :
      decodeAt insns s.pc = some (insn, .Ja width) →
      Step P insns s (.next { s with pc := jumpTarget insn s.pc })

  | jmp (s : State) (insn : Insn) (width : AluWidth) (op : JmpOp) (source : Source) :
      decodeAt insns s.pc = some (insn, .Jmp width op source) →
      Step P insns s (.next { s with pc := jmpNext s.regs insn s.pc width op source })

  /-- A helper call (`src = 0`), or a cross-section call (`src = 2`), which
  this single-section semantics treats the same way: it returns to the next
  slot with `R0`–`R5` changed arbitrarily. -/
  | callExternal (s : State) (insn : Insn) (regs' : Regs) :
      decodeAt insns s.pc = some (insn, .Call) →
      insn.src.val ≠ 1 →
      HelperClobber s.regs regs' →
      Step P insns s (.next { s with regs := regs', pc := s.pc + 1 })

  | callFault (s : State) (insn : Insn) :
      decodeAt insns s.pc = some (insn, .Call) →
      insn.src.val ≠ 1 →
      Step P insns s (.halt .fault)

  /-- A local call: push a frame, move the frame pointer down one stride. -/
  | callLocal (s : State) (insn : Insn) :
      decodeAt insns s.pc = some (insn, .Call) →
      insn.src.val = 1 →
      s.stack.length < P.maxDepth →
      Step P insns s (.next {
        regs := setReg s.regs R10 (s.regs R10 - P.stride),
        pc := callTarget insn s.pc,
        stack := { ret := s.pc + 1, saved := savedRegs s.regs, fp := s.regs R10 } :: s.stack })

  /-- The guest stack has no room for another frame. -/
  | callExhausted (s : State) (insn : Insn) :
      decodeAt insns s.pc = some (insn, .Call) →
      insn.src.val = 1 →
      s.stack.length ≥ P.maxDepth →
      Step P insns s (.halt .fault)

  | exitTop (s : State) (insn : Insn) :
      decodeAt insns s.pc = some (insn, .Exit) →
      s.stack = [] →
      Step P insns s (.halt (.exited (s.regs ⟨0, by decide⟩)))

  | exitReturn (s : State) (insn : Insn) (f : Frame) (rest : List Frame) :
      decodeAt insns s.pc = some (insn, .Exit) →
      s.stack = f :: rest →
      Step P insns s (.next { regs := restoreRegs s.regs f, pc := f.ret, stack := rest })

/-- The state a program starts in: `R1` is the context pointer, `R10` the
frame pointer, everything else zero, as the entry trampoline sets them. -/
def initial (ctx fp : Word) : State :=
  { regs := fun r => if r.val = 1 then ctx else if r = R10 then fp else 0#64,
    pc := 0,
    stack := [] }

/-- States reachable from `s₀`. -/
inductive Reachable (P : Params) (insns : List Insn) (s₀ : State) : State → Prop
  | refl : Reachable P insns s₀ s₀
  | step {s s' : State} :
      Reachable P insns s₀ s → Step P insns s (.next s') → Reachable P insns s₀ s'

end Sem

end async_ebpf_verified

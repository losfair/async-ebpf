import AsyncEbpf.X64.Bytes

/-!
# An operational semantics of the x86_64 primitive instruction set

A small-step semantics of `x64_ir::PInsn`, the primitive layer of the x86_64
backend: one variant per distinct x86 instruction shape the backend emits,
extracted from `src/verified/x64_ir.rs` so that the semantics and the encoder
agree on what each shape is. `src/jit/emit/x86_64.rs` turns the same list into
bytes; that table is trusted, this is not.

## What is modelled

* The sixteen 64-bit registers, indexed by the number the ModRM/REX encoding
  uses, the four flags the backend branches on (`cf`, `zf`, `sf`, `of`), and
  byte-addressed memory (`AsyncEbpf/X64/Bytes.lean`).
* A program counter over the *list*, not over bytes: position `i` of the list
  has native address `P.codeBase + i`, and a branch names a label rather than
  a displacement, so no encoding is modelled and no fixup can be wrong here.
  The one place native addresses matter is the stack: a `call` pushes
  `codeBase + (pc + 1)`, and a `ret` reads the pushed word back.
* Each instruction's effect on registers, flags and memory with the fine
  print that matters: a 32-bit form computes on the low half and zero-extends
  into the full register, shift amounts are masked, compares and tests write
  no register, `push` moves `rsp` before it stores, `pop` reads before it
  moves.
* Calls out of the list. Every call the backend emits — the retpoline to the
  dispatcher, the lazy local-call resolver, a lazily compiled callee — leaves
  the code this list describes, and comes back under the SysV contract:
  `ExternalReturn` says what such a callee is allowed to have done.

## What is abstracted

Nondeterminism stands for everything the safety argument does not need, as it
does for memory in `Semantics/Machine.lean`. Where a constructor quantifies
over a `Flags` or a `Word`, every real execution is one of the executions
here, so a property proved of all of them holds of the real one.

* Flags after a shift, a rotate, a `neg`, a locked read-modify-write and a
  multiply/divide are arbitrary, and so are all but the zero flag after a
  `cmpxchg`. So are `rax` and `rdx` after `MulDivRcx`: the fix-ups the
  emitter wraps around a division are a correctness question, not a safety
  one, and reading its results as arbitrary is the weaker assumption.
* An external call may write every register except `rbx`, `rbp`, `r12`–`r15`
  and `rsp` (which it returns as it found it plus the popped return address),
  every flag, and every byte below the return address, sparing the four
  writable frame slots' complement above it and the descriptor.
* Non-memory faults — `ud2`, a divide by zero the emitter's fix-ups did not
  intercept, an alignment or lock violation — are not modelled: `Ud2` and the
  trailer data simply halt, and the rest cannot fault in this model. A fault
  ends the execution, so it can only remove behaviours, never add an access.
* The target register of `call reg` is not consulted. Every callee is
  described by `ExternalReturn`, and a callee inside this list would have to
  return through the same contract, so nothing is gained by reading it.
-/
open Aeneas

namespace async_ebpf_verified

namespace X64

abbrev Word := BitVec 64

/-- The flags the backend branches on. -/
structure Flags where
  cf : Bool
  zf : Bool
  sf : Bool
  of : Bool

/-- The machine state. Registers are indexed by the number the encoding uses,
so `regs 4` is `rsp`; an index above 15 never occurs in emitted code and
names a register of its own here, which keeps `regs` total. -/
structure State where
  regs : Nat → Word
  flags : Flags
  mem : Mem
  pc : Nat

/-- How a step ends. -/
inductive Config where
  /-- Another instruction of this list. -/
  | next (s : State)
  /-- `ret` with the stack at its entry depth: the function returned. -/
  | returned (s : State)
  /-- `ud2`, or control reaching the trailer's data. -/
  | halt

/-! ## Register names -/

abbrev RAX : Nat := 0
abbrev RCX : Nat := 1
abbrev RDX : Nat := 2
abbrev RBX : Nat := 3
abbrev RSP : Nat := 4
abbrev RBP : Nat := 5
abbrev RSI : Nat := 6
abbrev RDI : Nat := 7
abbrev R8 : Nat := 8
abbrev R9 : Nat := 9
abbrev R10 : Nat := 10
abbrev R11 : Nat := 11
abbrev R12 : Nat := 12
abbrev R13 : Nat := 13
abbrev R14 : Nat := 14
abbrev R15 : Nat := 15

/-- The machine's fixed parameters: where the code sits, what the entry
trampoline put in the registers, and the geometry of the two guest regions.
The guest regions are described twice over — in the descriptor and in the
derived slots below the frame pointer — and `Contract.lean` requires both
descriptions to be this one. -/
structure Params where
  /-- Position `i` of the instruction list has native address `codeBase + i`. -/
  codeBase : Word
  /-- `rsp` on entry. -/
  rsp0 : Word
  /-- `rbp` on entry; the frame slots are below it. -/
  rbp0 : Word
  /-- `r15` on entry: the native frame base. -/
  fp0 : Word
  /-- The memory descriptor's address. -/
  desc : Word
  /-- The helper table's address. -/
  tableBase : Word
  /-- The external dispatcher's address. -/
  dispatcher : Word
  /-- Guest stack: bottom, top, native base. -/
  sgb : Word
  sgt : Word
  snb : Word
  /-- Guest data: bottom, top, native base. -/
  dgb : Word
  dgt : Word
  dnb : Word
  /-- The local-call floors, guest and native. -/
  guestFloor : Word
  nativeFloor : Word
  /-- Guest stack bytes charged to one local function. -/
  frameSize : Nat
  /-- Guest-address distance between successive frame pointers. -/
  stride : Nat

/-! ## Widths -/

def lo32 (v : Word) : BitVec 32 := v.truncate 32

def zx32 (v : BitVec 32) : Word := v.zeroExtend 64

/-- What an operation of the given width leaves in a 64-bit register: the
whole result at 64 bits, its low half zero-extended at 32. Every 32-bit form
below computes at 64 bits and passes the result through here, which is the
same value because truncation commutes with `+`, `-` and the bitwise
operations. -/
def wr (w64 : Bool) (v : Word) : Word := if w64 then v else zx32 (lo32 v)

/-- Bytes an operation of the given width touches. -/
def opWidth (w64 : Bool) : Nat := if w64 then 8 else 4

/-! ## Flags -/

def addFlags {w : Nat} (a b : BitVec w) : Flags :=
  { cf := decide (2 ^ w ≤ a.toNat + b.toNat)
    zf := decide (a + b = 0#w)
    sf := (a + b).msb
    of := (a.msb == b.msb) && (!((a + b).msb == a.msb)) }

def subFlags {w : Nat} (a b : BitVec w) : Flags :=
  { cf := decide (a.toNat < b.toNat)
    zf := decide (a - b = 0#w)
    sf := (a - b).msb
    of := (!(a.msb == b.msb)) && (!((a - b).msb == a.msb)) }

def logicFlags {w : Nat} (r : BitVec w) : Flags :=
  { cf := false, zf := decide (r = 0#w), sf := r.msb, of := false }

/-- The flags an `add` (`sub = false`) or a `sub`, `cmp` or `neg`-style
subtraction leaves, at the named width: carry out or borrow, zero, the
result's sign bit, and signed overflow. -/
def flagsOfAddSub (w64 : Bool) (sub : Bool) (a b : Word) : Flags :=
  if w64 then (if sub then subFlags a b else addFlags a b)
  else (if sub then subFlags (lo32 a) (lo32 b) else addFlags (lo32 a) (lo32 b))

/-- The flags `and`, `or`, `xor` and `test` leave: carry and overflow
cleared, zero and sign from the result. -/
def flagsOfLogic (w64 : Bool) (r : Word) : Flags :=
  if w64 then logicFlags r else logicFlags (lo32 r)

/-- The word `pushfq` pushes, as far as this model tracks it. -/
def flagsWord (f : Flags) : Word :=
  (if f.cf then 1#64 else 0#64) ||| (if f.zf then 0x40#64 else 0#64) |||
    (if f.sf then 0x80#64 else 0#64) ||| (if f.of then 0x800#64 else 0#64)

/-- The flags `popfq` takes from a word. -/
def flagsOfWord (v : Word) : Flags :=
  { cf := v.getLsbD 0, zf := v.getLsbD 6, sf := v.getLsbD 7, of := v.getLsbD 11 }

/-- A condition code, as the low byte of the two-byte `jcc`/`cmovcc` opcode
(`x64_ir::cc`). A byte the backend never emits is never taken. -/
def cond (cc : Std.U8) (f : Flags) : Bool :=
  if cc.val = 0x82 then f.cf
  else if cc.val = 0x83 then !f.cf
  else if cc.val = 0x84 then f.zf
  else if cc.val = 0x85 then !f.zf
  else if cc.val = 0x86 then f.cf || f.zf
  else if cc.val = 0x87 then !f.cf && !f.zf
  else if cc.val = 0x8c then !(f.sf == f.of)
  else if cc.val = 0x8d then f.sf == f.of
  else if cc.val = 0x8e then f.zf || !(f.sf == f.of)
  else if cc.val = 0x8f then !f.zf && (f.sf == f.of)
  else false

/-! ## Reading the program -/

/-- Whether an instruction is the label a target names. -/
def isTarget (t : x64_ir.PTarget) (i : x64_ir.PInsn) : Bool :=
  match t, i with
  | .Pc p, .PcLabel q => p.val = q.val
  | .Exit, .ExitLabel => true
  | .Retpoline, .RetpolineLabel => true
  | .Local n, .Local m => n.val = m.val
  | _, _ => false

/-- Where a branch target sits in the list: the first label that matches it.
A target with no label has no position, and the step relation is then empty,
which is the encoder's "unresolved fixup" made into a stuck state. -/
def pos (code : List x64_ir.PInsn) (t : x64_ir.PTarget) : Option Nat :=
  code.findIdx? (isTarget t)

/-- The address in the trailer's dispatcher slot, which the retpoline loads
RIP-relative; zero when the list has no slot. -/
def dispatcherAddr (code : List x64_ir.PInsn) : Word :=
  match code.find? (fun i => match i with | .DispatcherSlot _ => true | _ => false) with
  | some (.DispatcherSlot a) => a.bv
  | _ => 0#64

/-! ## Operands -/

/-- `[base + disp]`, with the displacement sign-extended. -/
def addr (s : State) (base : Std.U8) (disp : Std.I32) : Word :=
  s.regs base.val + BitVec.signExtend 64 disp.bv

/-- The `n` low bytes of a register, the value a store of that width writes. -/
def storeVal (n : Nat) (v : Word) : BitVec (8 * n) := v.truncate (8 * n)

/-- What memory holds at `a` at the named width, zero-extended. -/
def memVal (w64 : Bool) (m : Mem) (a : Word) : Word :=
  BitVec.zeroExtend 64 (load (opWidth w64) m a)

/-- The value a load writes to its destination. -/
def loadExt (n : Nat) (sx : Bool) (m : Mem) (a : Word) : Word :=
  if sx then BitVec.signExtend 64 (load n m a) else BitVec.zeroExtend 64 (load n m a)

/-! ## State transformers -/

def wReg (s : State) (r : Std.U8) (v : Word) : State :=
  { s with regs := Function.update s.regs r.val v, pc := s.pc + 1 }

def wRegN (s : State) (r : Nat) (v : Word) : State :=
  { s with regs := Function.update s.regs r v, pc := s.pc + 1 }

def wFlags (s : State) (f : Flags) : State := { s with flags := f, pc := s.pc + 1 }

def wRegFlags (s : State) (r : Std.U8) (v : Word) (f : Flags) : State :=
  { s with regs := Function.update s.regs r.val v, flags := f, pc := s.pc + 1 }

def wNext (s : State) : State := { s with pc := s.pc + 1 }

/-- `rsp -= 8 ; [rsp] := v`, leaving the program counter alone: `push` and
`call` differ only in where they go next. -/
def push (s : State) (v : Word) : State :=
  { s with regs := Function.update s.regs RSP (s.regs RSP - 8#64),
           mem := store64 s.mem (s.regs RSP - 8#64) v }

/-- `rsp += 8`, leaving the word at the old top where it is. -/
def popRsp (s : State) : State :=
  { s with regs := Function.update s.regs RSP (s.regs RSP + 8#64) }

/-- The address a `call` at `s.pc` pushes. -/
def retAddr (P : Params) (s : State) : Word := P.codeBase + BitVec.ofNat 64 (s.pc + 1)

/-- The address the native position `i` of the list has. -/
def codeAddr (P : Params) (i : Nat) : Word := P.codeBase + BitVec.ofNat 64 i

/-! ## The instructions -/

/-- `Alu`: register-to-register arithmetic. `Cmp` and `Test` write no
register, `Mov` writes no flag. -/
def aluRRStep (w64 : Bool) (op : x64_ir.AluRR) (src dst : Std.U8) (s : State) : State :=
  let a := s.regs dst.val
  let b := s.regs src.val
  match op with
  | .Add => wRegFlags s dst (wr w64 (a + b)) (flagsOfAddSub w64 false a b)
  | .Sub => wRegFlags s dst (wr w64 (a - b)) (flagsOfAddSub w64 true a b)
  | .Or => wRegFlags s dst (wr w64 (a ||| b)) (flagsOfLogic w64 (a ||| b))
  | .And => wRegFlags s dst (wr w64 (a &&& b)) (flagsOfLogic w64 (a &&& b))
  | .Xor => wRegFlags s dst (wr w64 (a ^^^ b)) (flagsOfLogic w64 (a ^^^ b))
  | .Mov => wReg s dst (wr w64 b)
  | .Cmp => wFlags s (flagsOfAddSub w64 true a b)
  | .Test => wFlags s (flagsOfLogic w64 (a &&& b))

/-- `AluImm`: the immediate is sign-extended at 64 bits and taken as it
stands at 32, where only its low half is read anyway. -/
def aluImmStep (w64 : Bool) (op : x64_ir.AluRI) (dst : Std.U8) (imm : Std.I32)
    (s : State) : State :=
  let a := s.regs dst.val
  let b : Word := if w64 then BitVec.signExtend 64 imm.bv else BitVec.zeroExtend 64 imm.bv
  match op with
  | .Add => wRegFlags s dst (wr w64 (a + b)) (flagsOfAddSub w64 false a b)
  | .Sub => wRegFlags s dst (wr w64 (a - b)) (flagsOfAddSub w64 true a b)
  | .Or => wRegFlags s dst (wr w64 (a ||| b)) (flagsOfLogic w64 (a ||| b))
  | .And => wRegFlags s dst (wr w64 (a &&& b)) (flagsOfLogic w64 (a &&& b))
  | .Xor => wRegFlags s dst (wr w64 (a ^^^ b)) (flagsOfLogic w64 (a ^^^ b))
  | .Mov => wReg s dst (wr w64 b)
  | .Cmp => wFlags s (flagsOfAddSub w64 true a b)
  | .Test => wFlags s (flagsOfLogic w64 (a &&& b))

/-- The shift count x86 uses: the low byte, masked to the width. -/
def shiftAmount (w64 : Bool) (n : BitVec 8) : Nat :=
  n.toNat % (if w64 then 64 else 32)

/-- `shl`, `shr` (logical) and `sar` (arithmetic at the width), with the
32-bit forms computing on the low half and zero-extending. -/
def shiftResult (w64 : Bool) (op : x64_ir.ShiftOp) (v : Word) (amt : Nat) : Word :=
  if w64 then
    match op with
    | .Shl => v <<< amt
    | .Shr => v >>> amt
    | .Sar => v.sshiftRight amt
  else
    zx32 (match op with
      | .Shl => lo32 v <<< amt
      | .Shr => lo32 v >>> amt
      | .Sar => (lo32 v).sshiftRight amt)

/-- `movsx`, from 8, 16 or 32 source bits. A `from` the backend never emits
moves the source unchanged. -/
def movsx (bits : Nat) (w64 : Bool) (v : Word) : Word :=
  wr w64 <|
    if bits = 8 then BitVec.signExtend 64 (v.truncate 8)
    else if bits = 16 then BitVec.signExtend 64 (v.truncate 16)
    else if bits = 32 then BitVec.signExtend 64 (v.truncate 32)
    else v

/-- Reverses the low `bytes` bytes and zero-extends, as `Semantics/Machine.lean`
does for eBPF's `bswap`. -/
def bswapBytes (bytes : Nat) (w : Word) : Word :=
  let byte (i : Nat) : Word := (w >>> (8 * i)) &&& 0xff#64
  (List.range bytes).foldl (fun acc i => acc ||| (byte i <<< (8 * (bytes - 1 - i)))) 0#64

def bswap (w64 : Bool) (v : Word) : Word :=
  if w64 then bswapBytes 8 v else bswapBytes 4 v

/-- `rol r16, 8`: the low sixteen bits rotate, the upper forty-eight stay. -/
def rol16 (v : Word) : Word :=
  let lo := v &&& 0xffff#64
  (v &&& 0xffffffffffff0000#64) ||| (((lo <<< 8) ||| (lo >>> 8)) &&& 0xffff#64)

/-- The register-form opcode byte a `lock` prefix carries, as an operation.
A byte the backend never emits writes the value back unchanged. -/
def lockOp (op : Std.U8) (a b : Word) : Word :=
  if op.val = 0x01 then a + b
  else if op.val = 0x09 then a ||| b
  else if op.val = 0x21 then a &&& b
  else if op.val = 0x31 then a ^^^ b
  else a

/-- `AluRM`: the bounds-check forms, all at 64 bits. -/
def aluRMStep (op : x64_ir.AluRM) (reg base : Std.U8) (disp : Std.I32) (s : State) : State :=
  let v := load64 s.mem (addr s base disp)
  let r := s.regs reg.val
  match op with
  | .Sub => wRegFlags s reg (r - v) (subFlags r v)
  | .Add => wRegFlags s reg (r + v) (addFlags r v)
  | .Or => wRegFlags s reg (r ||| v) (logicFlags (r ||| v))
  | .CmpMR => wFlags s (subFlags v r)
  | .CmpRM => wFlags s (subFlags r v)

/-- `lock op [a], src`, at the operation's width. -/
def lockAluStep (op : Std.U8) (w64 : Bool) (src base : Std.U8) (disp : Std.I32)
    (s : State) (f : Flags) : State :=
  let a := addr s base disp
  let v := lockOp op (memVal w64 s.mem a) (s.regs src.val)
  { s with mem := store (opWidth w64) s.mem a (storeVal (opWidth w64) v),
           flags := f, pc := s.pc + 1 }

/-- `lock cmpxchg [a], src`: the accumulator decides, and the flag the
emitter's loop branches on is the comparison. -/
def cmpxchgStep (w64 : Bool) (src base : Std.U8) (disp : Std.I32)
    (s : State) (f : Flags) : State :=
  let a := addr s base disp
  let cur := memVal w64 s.mem a
  if cur = wr w64 (s.regs RAX) then
    { s with mem := store (opWidth w64) s.mem a (storeVal (opWidth w64) (s.regs src.val)),
             flags := { f with zf := true }, pc := s.pc + 1 }
  else
    { s with regs := Function.update s.regs RAX cur,
             flags := { f with zf := false }, pc := s.pc + 1 }

/-- `xchg [a], src`. -/
def xchgStep (w64 : Bool) (src base : Std.U8) (disp : Std.I32) (s : State) : State :=
  let a := addr s base disp
  { s with regs := Function.update s.regs src.val (memVal w64 s.mem a),
           mem := store (opWidth w64) s.mem a (storeVal (opWidth w64) (s.regs src.val)),
           pc := s.pc + 1 }

/-! ## The bytes an instruction touches

`accesses i s` is the list of `(base, length)` ranges the instruction at `s`
reads or writes, which is what memory safety is stated about. Every
instruction that names memory is here; the ones that do not have no entry,
and `RipLoadDispatcher` has none because the value it produces is a fact
about the list, not a load the model performs. -/
def accesses (i : x64_ir.PInsn) (s : State) : List (Word × Nat) :=
  match i with
  | .Push _ => [(s.regs RSP - 8#64, 8)]
  | .Pop _ => [(s.regs RSP, 8)]
  | .Pushfq => [(s.regs RSP - 8#64, 8)]
  | .Popfq => [(s.regs RSP, 8)]
  | .Load size sx base _ disp =>
      if sx ∧ size.val = 8 then [] else [(addr s base disp, size.val)]
  | .Store size _ base disp => [(addr s base disp, size.val)]
  | .StoreImm size base disp _ => [(addr s base disp, size.val)]
  | .AluRM _ _ base disp => [(addr s base disp, 8)]
  | .StoreRspImm _ => [(s.regs RSP, 8)]
  | .StoreRspRax => [(s.regs RSP, 8)]
  | .LockAlu _ w64 _ base disp => [(addr s base disp, opWidth w64)]
  | .LockCmpxchg w64 _ base disp => [(addr s base disp, opWidth w64)]
  | .Xchg w64 _ base disp => [(addr s base disp, opWidth w64)]
  | .Call _ => [(s.regs RSP - 8#64, 8)]
  | .CallReg _ => [(s.regs RSP - 8#64, 8)]
  | .Ret => [(s.regs RSP, 8)]
  | _ => []

/-! ## Leaving the list -/

/-- The 8-byte frame slots an external call may write: the spill, the address
spill, the accumulator spill and the parked group base. -/
def WritableSlot (P : Params) (a : Word) : Prop :=
  InRange (P.rbp0 - 16#64) 8 a ∨ InRange (P.rbp0 - 24#64) 8 a ∨
  InRange (P.rbp0 - 32#64) 8 a ∨ InRange (P.rbp0 - 144#64) 8 a

/-- What a callee outside this list may have done, on return.

This is the SysV contract, narrowed by what the runtime promises of the three
kinds of callee the backend reaches — the dispatcher through the retpoline,
the lazy local-call resolver and its stack-exhausted twin, and a lazily
compiled callee, which is another instance of this theorem. It returns to the
address on top of the stack, pops it, keeps the callee-saved registers,
leaves the caller's frame alone above the return address except for the four
writable slots, and leaves the descriptor alone. Everything else — the
caller-saved registers, the flags, the bytes below the return address — is
arbitrary. -/
structure ExternalReturn (P : Params) (code : List x64_ir.PInsn) (s s' : State) : Prop where
  /-- It returns to the pushed address, which is a position of this list. -/
  returnsHere : ∃ i : Nat, i < code.length ∧
    load64 s.mem (s.regs RSP) = codeAddr P i ∧ s'.pc = i
  /-- It pops that address. -/
  stackPopped : s'.regs RSP = s.regs RSP + 8#64
  /-- `rbx`, `rbp`, `r12`–`r15` survive. -/
  calleeSaved : ∀ r ∈ [RBX, RBP, R12, R13, R14, R15], s'.regs r = s.regs r
  /-- Nothing above the return address changes but the four writable slots. -/
  frameKept : ∀ a : Word, (s.regs RSP).toNat + 8 ≤ a.toNat → ¬ WritableSlot P a →
    s'.mem a = s.mem a
  /-- The descriptor is read-only. -/
  descKept : ∀ a : Word, P.desc.toNat ≤ a.toNat → a.toNat < P.desc.toNat + 200 →
    s'.mem a = s.mem a

/-! ## The step relation -/

/-- One step of the machine: from `s`, the list `code` may move to `c`. Each
constructor fetches the instruction at `s.pc`; a program counter off the end
of the list, and a branch to a label the list does not carry, are stuck. -/
inductive Step (P : Params) (code : List x64_ir.PInsn) : State → Config → Prop
  /-- The four label forms emit nothing. -/
  | pcLabel (s : State) (p : Std.U32) :
      code[s.pc]? = some (.PcLabel p) → Step P code s (.next (wNext s))
  | localLabel (s : State) (n : Std.U32) :
      code[s.pc]? = some (.Local n) → Step P code s (.next (wNext s))
  | exitLabel (s : State) :
      code[s.pc]? = some .ExitLabel → Step P code s (.next (wNext s))
  | retpolineLabel (s : State) :
      code[s.pc]? = some .RetpolineLabel → Step P code s (.next (wNext s))
  | pause (s : State) :
      code[s.pc]? = some .Pause → Step P code s (.next (wNext s))

  | push (s : State) (r : Std.U8) :
      code[s.pc]? = some (.Push r) →
      Step P code s (.next { push s (s.regs r.val) with pc := s.pc + 1 })

  /-- `pop` reads before it moves `rsp`, so `pop rsp` ends at `rsp + 8`. -/
  | pop (s : State) (r : Std.U8) :
      code[s.pc]? = some (.Pop r) →
      Step P code s (.next
        { s with regs := Function.update (Function.update s.regs r.val
                   (load64 s.mem (s.regs RSP))) RSP (s.regs RSP + 8#64),
                 pc := s.pc + 1 })

  | alu (s : State) (w64 : Bool) (op : x64_ir.AluRR) (src dst : Std.U8) :
      code[s.pc]? = some (.Alu w64 op src dst) →
      Step P code s (.next (aluRRStep w64 op src dst s))

  | aluImm (s : State) (w64 : Bool) (op : x64_ir.AluRI) (dst : Std.U8) (imm : Std.I32) :
      code[s.pc]? = some (.AluImm w64 op dst imm) →
      Step P code s (.next (aluImmStep w64 op dst imm s))

  /-- A shift's flags are arbitrary: the backend never reads them. -/
  | shiftImm (s : State) (w64 : Bool) (op : x64_ir.ShiftOp) (dst : Std.U8)
      (imm : Std.I32) (f : Flags) :
      code[s.pc]? = some (.ShiftImm w64 op dst imm) →
      Step P code s (.next (wRegFlags s dst
        (shiftResult w64 op (s.regs dst.val) (shiftAmount w64 (imm.bv.truncate 8))) f))

  | shiftCl (s : State) (w64 : Bool) (op : x64_ir.ShiftOp) (dst : Std.U8) (f : Flags) :
      code[s.pc]? = some (.ShiftCl w64 op dst) →
      Step P code s (.next (wRegFlags s dst
        (shiftResult w64 op (s.regs dst.val) (shiftAmount w64 ((s.regs RCX).truncate 8))) f))

  | neg (s : State) (w64 : Bool) (dst : Std.U8) (f : Flags) :
      code[s.pc]? = some (.Neg w64 dst) →
      Step P code s (.next (wRegFlags s dst (wr w64 (- s.regs dst.val)) f))

  /-- `mul`/`div`/`idiv` by `rcx`: an over-approximation. The emitter's
  fix-ups around it decide what the results are, and that is correctness, not
  safety; here the pair it writes and the flags are arbitrary. -/
  | mulDivRcx (s : State) (w64 : Bool) (kind : x64_ir.MulDivKind) (signed : Bool)
      (a d : Word) (f : Flags) :
      code[s.pc]? = some (.MulDivRcx w64 kind signed) →
      Step P code s (.next
        { s with regs := Function.update (Function.update s.regs RAX a) RDX d,
                 flags := f, pc := s.pc + 1 })

  | movsx (s : State) (bits : Std.U8) (w64 : Bool) (src dst : Std.U8) :
      code[s.pc]? = some (.MovSx bits w64 src dst) →
      Step P code s (.next (wReg s dst (movsx bits.val w64 (s.regs src.val))))

  | bswap (s : State) (w64 : Bool) (dst : Std.U8) :
      code[s.pc]? = some (.Bswap w64 dst) →
      Step P code s (.next (wReg s dst (bswap w64 (s.regs dst.val))))

  | rol16 (s : State) (dst : Std.U8) (f : Flags) :
      code[s.pc]? = some (.Rol16 dst) →
      Step P code s (.next (wRegFlags s dst (rol16 (s.regs dst.val)) f))

  | cmovTaken (s : State) (cc dst src : Std.U8) :
      code[s.pc]? = some (.Cmov cc dst src) →
      cond cc s.flags = true →
      Step P code s (.next (wReg s dst (s.regs src.val)))

  | cmovNotTaken (s : State) (cc dst src : Std.U8) :
      code[s.pc]? = some (.Cmov cc dst src) →
      cond cc s.flags = false →
      Step P code s (.next (wNext s))

  | loadImm (s : State) (dst : Std.U8) (imm : Std.I64) :
      code[s.pc]? = some (.LoadImm dst imm) →
      Step P code s (.next (wReg s dst imm.bv))

  | pushfq (s : State) :
      code[s.pc]? = some .Pushfq →
      Step P code s (.next { push s (flagsWord s.flags) with pc := s.pc + 1 })

  | popfq (s : State) :
      code[s.pc]? = some .Popfq →
      Step P code s (.next
        { popRsp s with flags := flagsOfWord (load64 s.mem (s.regs RSP)), pc := s.pc + 1 })

  | cqo (s : State) :
      code[s.pc]? = some .Cqo →
      Step P code s (.next (wRegN s RDX
        (if (s.regs RAX).msb then BitVec.allOnes 64 else 0#64)))

  | cdq (s : State) :
      code[s.pc]? = some .Cdq →
      Step P code s (.next (wRegN s RDX
        (if (lo32 (s.regs RAX)).msb then 0xffffffff#64 else 0#64)))

  | cmpRcxMinusOne (s : State) (w64 : Bool) :
      code[s.pc]? = some (.CmpRcxMinusOne w64) →
      Step P code s (.next (wFlags s
        (flagsOfAddSub w64 true (s.regs RCX) (BitVec.allOnes 64))))

  | cmpEaxImm (s : State) (imm : Std.U32) :
      code[s.pc]? = some (.CmpEaxImm imm) →
      Step P code s (.next (wFlags s
        (flagsOfAddSub false true (s.regs RAX) (zx32 imm.bv))))

  /-- A load of `size` bytes, zero- or sign-extended into the destination. -/
  | load (s : State) (size : Std.U8) (sx : Bool) (base dst : Std.U8) (disp : Std.I32) :
      code[s.pc]? = some (.Load size sx base dst disp) →
      ¬ (sx ∧ size.val = 8) →
      Step P code s (.next (wReg s dst (loadExt size.val sx s.mem (addr s base disp))))

  /-- The sign-extending eight-byte form encodes nothing, so it does nothing
  and touches no memory. -/
  | loadNop (s : State) (size : Std.U8) (sx : Bool) (base dst : Std.U8) (disp : Std.I32) :
      code[s.pc]? = some (.Load size sx base dst disp) →
      sx = true → size.val = 8 →
      Step P code s (.next (wNext s))

  | store (s : State) (size src base : Std.U8) (disp : Std.I32) :
      code[s.pc]? = some (.Store size src base disp) →
      Step P code s (.next
        { s with mem := store size.val s.mem (addr s base disp)
                   (storeVal size.val (s.regs src.val)),
                 pc := s.pc + 1 })

  /-- The immediate is sign-extended to a word first, so the eight-byte form
  stores `imm32` sign-extended, as `mov qword [m], imm32` does. -/
  | storeImm (s : State) (size base : Std.U8) (disp imm : Std.I32) :
      code[s.pc]? = some (.StoreImm size base disp imm) →
      Step P code s (.next
        { s with mem := store size.val s.mem (addr s base disp)
                   (storeVal size.val (BitVec.signExtend 64 imm.bv)),
                 pc := s.pc + 1 })

  | aluRM (s : State) (op : x64_ir.AluRM) (reg base : Std.U8) (disp : Std.I32) :
      code[s.pc]? = some (.AluRM op reg base disp) →
      Step P code s (.next (aluRMStep op reg base disp s))

  | storeRspImm (s : State) (imm : Std.U32) :
      code[s.pc]? = some (.StoreRspImm imm) →
      Step P code s (.next
        { s with mem := store64 s.mem (s.regs RSP) (BitVec.signExtend 64 imm.bv),
                 pc := s.pc + 1 })

  | storeRspRax (s : State) :
      code[s.pc]? = some .StoreRspRax →
      Step P code s (.next
        { s with mem := store64 s.mem (s.regs RSP) (s.regs RAX), pc := s.pc + 1 })

  | lockAlu (s : State) (op : Std.U8) (w64 : Bool) (src base : Std.U8) (disp : Std.I32)
      (f : Flags) :
      code[s.pc]? = some (.LockAlu op w64 src base disp) →
      Step P code s (.next (lockAluStep op w64 src base disp s f))

  | lockCmpxchg (s : State) (w64 : Bool) (src base : Std.U8) (disp : Std.I32) (f : Flags) :
      code[s.pc]? = some (.LockCmpxchg w64 src base disp) →
      Step P code s (.next (cmpxchgStep w64 src base disp s f))

  | xchg (s : State) (w64 : Bool) (src base : Std.U8) (disp : Std.I32) :
      code[s.pc]? = some (.Xchg w64 src base disp) →
      Step P code s (.next (xchgStep w64 src base disp s))

  | jccTaken (s : State) (cc : Std.U8) (t : x64_ir.PTarget) (i : Nat) :
      code[s.pc]? = some (.Jcc cc t) → cond cc s.flags = true → pos code t = some i →
      Step P code s (.next { s with pc := i })

  | jccNotTaken (s : State) (cc : Std.U8) (t : x64_ir.PTarget) :
      code[s.pc]? = some (.Jcc cc t) → cond cc s.flags = false →
      Step P code s (.next (wNext s))

  | jmp (s : State) (t : x64_ir.PTarget) (i : Nat) :
      code[s.pc]? = some (.Jmp t) → pos code t = some i →
      Step P code s (.next { s with pc := i })

  | jmpNear (s : State) (t : x64_ir.PTarget) (i : Nat) :
      code[s.pc]? = some (.JmpNear t) → pos code t = some i →
      Step P code s (.next { s with pc := i })

  | jcc8Taken (s : State) (cc : Std.U8) (n : Std.U32) (i : Nat) :
      code[s.pc]? = some (.Jcc8 cc n) → cond cc s.flags = true →
      pos code (.Local n) = some i →
      Step P code s (.next { s with pc := i })

  | jcc8NotTaken (s : State) (cc : Std.U8) (n : Std.U32) :
      code[s.pc]? = some (.Jcc8 cc n) → cond cc s.flags = false →
      Step P code s (.next (wNext s))

  | jmp8 (s : State) (n : Std.U32) (i : Nat) :
      code[s.pc]? = some (.Jmp8 n) → pos code (.Local n) = some i →
      Step P code s (.next { s with pc := i })

  /-- A call inside the list: push the return address and go. -/
  | call (s : State) (t : x64_ir.PTarget) (i : Nat) :
      code[s.pc]? = some (.Call t) → pos code t = some i →
      Step P code s (.next { push s (retAddr P s) with pc := i })

  /-- `ret` with `rsp` back at its entry value: the function returns to its
  caller, and where it goes is the caller's business. -/
  | retTop (s : State) :
      code[s.pc]? = some .Ret → s.regs RSP = P.rsp0 →
      Step P code s (.returned (popRsp s))

  /-- `ret` to a position of this list: the matching `call`'s return address. -/
  | retLocal (s : State) (i : Nat) :
      code[s.pc]? = some .Ret → s.regs RSP ≠ P.rsp0 →
      i < code.length → load64 s.mem (s.regs RSP) = codeAddr P i →
      Step P code s (.next { popRsp s with pc := i })

  /-- `ret` to an address outside the list: the retpoline, returning into the
  dispatcher. What comes back is another external callee. -/
  | retExternal (s s' : State) :
      code[s.pc]? = some .Ret → s.regs RSP ≠ P.rsp0 →
      (¬ ∃ i : Nat, i < code.length ∧ load64 s.mem (s.regs RSP) = codeAddr P i) →
      ExternalReturn P code (popRsp s) s' →
      Step P code s (.next s')

  /-- `call reg`: push the return address and leave the list. The target
  register is not consulted; every callee is `ExternalReturn`. -/
  | callReg (s s' : State) (r : Std.U8) :
      code[s.pc]? = some (.CallReg r) →
      ExternalReturn P code (push s (retAddr P s)) s' →
      Step P code s (.next s')

  /-- The RIP-relative pair. Both read the function's own trailer, whose
  contents are facts about the list, so neither is a load here. -/
  | ripLoadDispatcher (s : State) (dst : Std.U8) :
      code[s.pc]? = some (.RipLoadDispatcher dst) →
      Step P code s (.next (wReg s dst (dispatcherAddr code)))

  | ripLeaHelperTable (s : State) (dst : Std.U8) :
      code[s.pc]? = some (.RipLeaHelperTable dst) →
      Step P code s (.next (wReg s dst P.tableBase))

  | ud2 (s : State) : code[s.pc]? = some .Ud2 → Step P code s .halt
  | dispatcherSlot (s : State) (a : Std.U64) :
      code[s.pc]? = some (.DispatcherSlot a) → Step P code s .halt
  | helperTable (s : State) :
      code[s.pc]? = some .HelperTable → Step P code s .halt

/-- States reachable from `s₀` through `next`. -/
inductive Reachable (P : Params) (code : List x64_ir.PInsn) (s₀ : State) : State → Prop
  | refl : Reachable P code s₀ s₀
  | step {s s' : State} :
      Reachable P code s₀ s → Step P code s (.next s') → Reachable P code s₀ s'

theorem Reachable.trans {P code} {s₀ s₁ s₂ : State}
    (h₁ : Reachable P code s₀ s₁) (h₂ : Reachable P code s₁ s₂) : Reachable P code s₀ s₂ := by
  induction h₂ with
  | refl => exact h₁
  | step _ hs ih => exact .step ih hs

theorem Reachable.one {P code} {s s' : State} (h : Step P code s (.next s')) :
    Reachable P code s s' := .step .refl h

/-! ## Sanity lemmas

The shapes later proofs read off: which instructions touch no memory, what
the two stack primitives touch, and that a fetch pins the step. -/

@[simp] theorem accesses_alu (w64 op src dst s) :
    accesses (.Alu w64 op src dst) s = [] := rfl

@[simp] theorem accesses_aluImm (w64 op dst imm s) :
    accesses (.AluImm w64 op dst imm) s = [] := rfl

@[simp] theorem accesses_shiftImm (w64 op dst imm s) :
    accesses (.ShiftImm w64 op dst imm) s = [] := rfl

@[simp] theorem accesses_shiftCl (w64 op dst s) :
    accesses (.ShiftCl w64 op dst) s = [] := rfl

@[simp] theorem accesses_neg (w64 dst s) : accesses (.Neg w64 dst) s = [] := rfl

@[simp] theorem accesses_movsx (bits w64 src dst s) :
    accesses (.MovSx bits w64 src dst) s = [] := rfl

@[simp] theorem accesses_loadImm (dst imm s) : accesses (.LoadImm dst imm) s = [] := rfl

@[simp] theorem accesses_jcc (cc t s) : accesses (.Jcc cc t) s = [] := rfl

@[simp] theorem accesses_jmp (t s) : accesses (.Jmp t) s = [] := rfl

@[simp] theorem accesses_push (r s) : accesses (.Push r) s = [(s.regs RSP - 8#64, 8)] := rfl

@[simp] theorem accesses_pop (r s) : accesses (.Pop r) s = [(s.regs RSP, 8)] := rfl

@[simp] theorem accesses_ret (s) : accesses .Ret s = [(s.regs RSP, 8)] := rfl

@[simp] theorem accesses_call (t s) :
    accesses (.Call t) s = [(s.regs RSP - 8#64, 8)] := rfl

/-- A register-to-register ALU instruction determines the step it takes. -/
theorem step_alu {P code s c} {w64 op src dst}
    (hc : code[s.pc]? = some (.Alu w64 op src dst)) (h : Step P code s c) :
    c = .next (aluRRStep w64 op src dst s) := by
  cases h <;> simp_all

theorem step_aluImm {P code s c} {w64 op dst imm}
    (hc : code[s.pc]? = some (.AluImm w64 op dst imm)) (h : Step P code s c) :
    c = .next (aluImmStep w64 op dst imm s) := by
  cases h <;> simp_all

theorem step_push {P code s c} {r}
    (hc : code[s.pc]? = some (.Push r)) (h : Step P code s c) :
    c = .next { push s (s.regs r.val) with pc := s.pc + 1 } := by
  cases h <;> simp_all

theorem step_pop {P code s c} {r}
    (hc : code[s.pc]? = some (.Pop r)) (h : Step P code s c) :
    c = .next { s with
      regs := Function.update (Function.update s.regs r.val (load64 s.mem (s.regs RSP)))
        RSP (s.regs RSP + 8#64), pc := s.pc + 1 } := by
  cases h <;> simp_all

/-- A register-to-register ALU instruction changes no memory and advances by
one, whichever operation it is. -/
@[simp] theorem aluRRStep_mem (w64 op src dst s) : (aluRRStep w64 op src dst s).mem = s.mem := by
  cases op <;> rfl

@[simp] theorem aluRRStep_pc (w64 op src dst s) :
    (aluRRStep w64 op src dst s).pc = s.pc + 1 := by
  cases op <;> rfl

@[simp] theorem aluImmStep_mem (w64 op dst imm s) : (aluImmStep w64 op dst imm s).mem = s.mem := by
  cases op <;> rfl

@[simp] theorem aluImmStep_pc (w64 op dst imm s) :
    (aluImmStep w64 op dst imm s).pc = s.pc + 1 := by
  cases op <;> rfl

@[simp] theorem push_mem (s : State) (v : Word) :
    (push s v).mem = store64 s.mem (s.regs RSP - 8#64) v := rfl

@[simp] theorem push_rsp (s : State) (v : Word) : (push s v).regs RSP = s.regs RSP - 8#64 := by
  simp [push]

@[simp] theorem popRsp_rsp (s : State) : (popRsp s).regs RSP = s.regs RSP + 8#64 := by
  simp [popRsp]

@[simp] theorem popRsp_mem (s : State) : (popRsp s).mem = s.mem := rfl

/-- What a `push` put on the stack is what a `pop` at the new top reads, and
so what a `ret` reads after a `call`. -/
@[simp] theorem load64_push (s : State) (v : Word) :
    load64 (push s v).mem (s.regs RSP - 8#64) = v := by
  simp [push, load64_store64_same]

@[simp] theorem accesses_pushfq (s) : accesses .Pushfq s = [(s.regs RSP - 8#64, 8)] := rfl

@[simp] theorem accesses_popfq (s) : accesses .Popfq s = [(s.regs RSP, 8)] := rfl

@[simp] theorem accesses_storeRspRax (s) :
    accesses .StoreRspRax s = [(s.regs RSP, 8)] := rfl

@[simp] theorem accesses_store (size src base disp s) :
    accesses (.Store size src base disp) s = [(addr s base disp, size.val)] := rfl

@[simp] theorem accesses_aluRM (op reg base disp s) :
    accesses (.AluRM op reg base disp) s = [(addr s base disp, 8)] := rfl

end X64

end async_ebpf_verified

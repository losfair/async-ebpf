import AsyncEbpf.Loop
import AsyncEbpf.Layout.Proofs
import AsyncEbpf.X64.Machine

/-!
# The macro expansion, read off the generated definitions

`x64_expand::expand` turns a list of `MInsn` into a list of `PInsn` by
concatenating one fixed sequence per macro. This file says exactly which
sequence, and then resolves every label the sequences name.

## The mirror

`chunk cfg m trailerEpilogue label` is that sequence, written in Lean as a
list literal per `MInsn` variant, together with the next free local label.
It is a transparent definition: a later proof about one macro's contract
`simp`s it open and reads the primitives off. `flat cfg code` folds it along
the list from label `0`, `chunkStart` is where chunk `i` begins in the flat
list, `chunkLen` how long it is and `labelBase` the counter it started from.

`expand_one_spec` and `expand_spec` are the bridge: whatever the extracted
code returns, it returns `out` with `flat` appended, and the counter it
returns is the one `chunk` computes.

## Counters

The extracted code runs the local-label counter in `u32` and adds with an
overflow check, so a program with more than `2^31` macros makes it fail
rather than wrap. `chunk` runs the counter in `Nat` and converts at the
boundary with `u32`, which truncates.

That costs nothing on the `= ok …` side: `expand_one_spec` and `expand_spec`
are implications from the extracted call having succeeded, so its arithmetic
has already not overflowed and no bound on `code.length` appears in them.
The scalar casts inside the sequences are the extraction's own pure
`UScalar.cast`/`UScalar.hcast` — the ones it evaluates under `lift` — so
they match on the nose.

Where the truncation does show is in reading a `Local` label back as a
number: `chunk_locals` and `pos_local` carry the no-overflow side condition
(`(chunk …).2 < 2 ^ 32`, resp. `labelBase cfg code (i+1) < 2 ^ 32`) rather
than a hypothesis about the length of the list. A caller with a bound on the
macro count discharges it once through `labelBase_mono` and
`chunkNext_bounds`, which says a chunk advances the counter by at most two.

## Labels

`pos` (in `X64/Machine.lean`) resolves a `PTarget` to the position of the
first primitive that is its label. The four `pos_*` theorems pin all four
kinds:

* a `PcLabel n` primitive comes only from a `PcLabel n` macro and is its
  chunk's only primitive, so the first `PcLabel n` macro fixes `pos`;
* `ExitLabel` comes only from a trailer epilogue — an `Epilogue` the
  `Retpoline` follows — and is the first primitive of its chunk;
* `RetpolineLabel` comes only from a `Retpoline` macro, first in its chunk;
* a `Local n` primitive emitted by chunk `i` has `labelBase i ≤ n <
  labelBase (i+1)`, and the bases are monotone, so a local label belongs to
  exactly one chunk and `pos` is that chunk's start plus the offset.

`dispatcherAddr_flat` reads the trailer's dispatcher slot the same way.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified.X64

/- One `simp only` set drives every branch of a `<;>` chain below, so some
argument is unused in some branch; the linter flags that and it is fine. -/
set_option linter.unusedSimpArgs false

/-! ## Pure scalar constructors

The extraction's scalar types are bit-vector wrappers; these are the total
constructors the mirror uses where the extracted code goes through a checked
operation. `u32_val` and friends say that every value is in the image, which
is how a successful extracted operation is matched with a mirror constant. -/

/-- A `u32` from a natural number, truncating. -/
def u32 (n : Nat) : Std.U32 := ⟨BitVec.ofNat 32 n⟩

/-- An `i32` from an integer, truncating. -/
def i32 (n : Int) : Std.I32 := ⟨BitVec.ofInt 32 n⟩

theorem u32_val_eq (n : Nat) : (u32 n).val = n % 2 ^ 32 := rfl

@[simp] theorem u32_val (x : Std.U32) : u32 x.val = x := by
  have : x.bv = BitVec.ofNat 32 x.bv.toNat := by simp
  simp only [u32, Std.UScalar.val]
  exact congrArg Std.UScalar.mk this.symm

@[simp] theorem i32_val (x : Std.I32) : i32 x.val = x := by
  have : x.bv = BitVec.ofInt 32 x.bv.toInt := by simp
  simp only [i32, Std.IScalar.val]
  exact congrArg Std.IScalar.mk this.symm

theorem u32_eq_of_val {x : Std.U32} {n : Nat} (h : x.val = n) : x = u32 n := by
  rw [← h, u32_val]

theorem i32_eq_of_val {x : Std.I32} {n : Int} (h : x.val = n) : x = i32 n := by
  rw [← h, i32_val]

/-! ## The mirror -/

/-- `x64_ir::frame::derived_slot`: where the `i`th derived constant sits
below the frame pointer. -/
def derivedSlot (i : Nat) : Std.I32 := i32 (-136 + 8 * (i : Int))

/-- `x64_expand::derived_base`. -/
def derivedBase (stack : Bool) : Nat := if stack then 0 else 6

/-- `x64_expand::width_span_slot`. -/
def widthSpan (size : Std.U32) : Option Nat :=
  if size = 1#u32 then some 0
  else if size = 2#u32 then some 1
  else if size = 4#u32 then some 2
  else if size = 8#u32 then some 3
  else none

/-- `x64_expand::desc_bottom`. -/
def descBottom (stack : Bool) : Std.I32 :=
  if stack then x64_ir.memory.STACK_GUEST_BOTTOM else x64_ir.memory.DATA_GUEST_BOTTOM

/-- `x64_expand::desc_top`. -/
def descTop (stack : Bool) : Std.I32 :=
  if stack then x64_ir.memory.STACK_GUEST_TOP else x64_ir.memory.DATA_GUEST_TOP

/-- `x64_expand::desc_native_base`. -/
def descNativeBase (stack : Bool) : Std.I32 :=
  if stack then x64_ir.memory.STACK_NATIVE_BASE else x64_ir.memory.DATA_NATIVE_BASE

/-- `x64_ir::map_register`, the eBPF-to-x86 register map. -/
def mreg : Nat → Std.U8
  | 0 => x64_ir.RAX | 1 => x64_ir.RDI | 2 => x64_ir.RSI | 3 => x64_ir.RDX
  | 4 => x64_ir.R10 | 5 => x64_ir.R8 | 6 => x64_ir.RBX | 7 => x64_ir.R12
  | 8 => x64_ir.R13 | 9 => x64_ir.R14 | _ => x64_ir.R15

/-- `x64_expand::primitive_target`. -/
def ptargetOf : x64_ir.Target → x64_ir.PTarget
  | .Pc pc => .Pc pc
  | .Exit => .Exit

/-- `x64_ir::Cfg::native_frame_base_active`. -/
def framedActive (cfg : x64_ir.Cfg) : Bool :=
  if cfg.pointer_mask = 0#i32 then false else cfg.native_frame_base

/-- `x64_expand::is_mul`. -/
def isMul : x64_ir.MulDivKind → Bool | .Mul => true | _ => false
/-- `x64_expand::is_div`. -/
def isDiv : x64_ir.MulDivKind → Bool | .Div => true | _ => false
/-- `x64_expand::is_mod`. -/
def isMod : x64_ir.MulDivKind → Bool | .Mod => true | _ => false

/-- `x64_expand::alu_rr_of`. -/
def aluRrOf (op : Std.U8) : x64_ir.AluRR :=
  if op = 9#u8 then .Or else if op = 33#u8 then .And
  else if op = 49#u8 then .Xor else .Add

/-- `x64_expand::expand_guest_fp`: the guest value of eBPF `R10`. -/
def chunkGuestFp (dst : Std.U8) : List x64_ir.PInsn :=
  [ .Alu true .Mov x64_ir.R15 dst,
    .AluRM .Sub dst x64_ir.RBP x64_ir.frame.FRAME_DELTA_OFFSET ]

/-- `x64_expand::expand_prologue`. -/
def chunkPrologue (usage : Std.U16) (skip : Bool) (label : Nat) :
    List x64_ir.PInsn × Nat :=
  if skip then
    ([ .JmpNear (.Local (u32 label)),
       .AluImm true .Sub x64_ir.RSP 8#i32,
       .StoreRspImm (Std.UScalar.cast .U32 usage),
       .Local (u32 label) ], label + 1)
  else
    ([ .AluImm true .Sub x64_ir.RSP 8#i32,
       .StoreRspImm (Std.UScalar.cast .U32 usage) ], label)

/-- `x64_expand::expand_region_from_frame`. -/
def chunkRegionFromFrame (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    List x64_ir.PInsn :=
  [ .Alu true .Mov dst scratch,
    .AluRM .Sub scratch x64_ir.RBP (derivedSlot (derivedBase stack)),
    .AluRM .Add dst x64_ir.RBP (derivedSlot (derivedBase stack + 1)) ] ++
  (match widthSpan size with
   | some slot =>
     [ .Alu true .Xor x64_ir.R9 x64_ir.R9,
       .AluRM .CmpMR scratch x64_ir.RBP (derivedSlot (derivedBase stack + 2 + slot)),
       .Cmov x64_ir.cc.B dst x64_ir.R9 ]
   | none =>
     [ .Load 8#u8 false x64_ir.RBP x64_ir.R9 (derivedSlot (derivedBase stack + 2)),
       .AluImm true .Sub x64_ir.R9 (i32 ((Std.UScalar.hcast .I32 size).val - 1)),
       .Alu true .Cmp scratch x64_ir.R9,
       .AluImm true .Mov scratch 0#i32,
       .Cmov x64_ir.cc.B dst scratch ])

/-- `x64_expand::expand_region_via_descriptor`. -/
def chunkRegionViaDescriptor (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    List x64_ir.PInsn :=
  [ .Load 8#u8 false x64_ir.RBP scratch x64_ir.frame.FRAME_OFFSET,
    .AluRM .Sub dst scratch (descBottom stack),
    .Store 8#u8 dst x64_ir.RBP x64_ir.frame.SPILL_OFFSET,
    .AluRM .Add dst scratch (descNativeBase stack),
    .Load 8#u8 false scratch x64_ir.R9 (descTop stack) ] ++
  (if size != 0#u32 then [ .AluImm true .Sub x64_ir.R9 (Std.UScalar.hcast .I32 size) ] else []) ++
  [ .AluRM .Sub x64_ir.R9 scratch (descBottom stack),
    .Alu true .Xor scratch scratch,
    .AluRM .CmpRM x64_ir.R9 x64_ir.RBP x64_ir.frame.SPILL_OFFSET,
    .Cmov x64_ir.cc.B dst scratch ]

/-- `x64_expand::expand_region`. -/
def chunkRegion (cfg : x64_ir.Cfg) (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    List x64_ir.PInsn :=
  if cfg.frame_constants then chunkRegionFromFrame dst scratch size stack
  else chunkRegionViaDescriptor dst scratch size stack

/-- `x64_expand::expand_checked_addr`. -/
def chunkCheckedAddr (cfg : x64_ir.Cfg) (src dst scratch : Std.U8) (offset : Std.I32)
    (size : Std.U32) (hint : Std.U8) : List x64_ir.PInsn :=
  (if framedActive cfg then
     (if src = x64_ir.R15 then chunkGuestFp dst
      else if src != dst then [ .Alu true .Mov src dst ] else [])
   else (if src != dst then [ .Alu true .Mov src dst ] else [])) ++
  (if offset != 0#i32 then [ .AluImm true .Add dst offset ] else []) ++
  (if cfg.pointer_mask = 0#i32 then []
   else if hint = x64_ir.region.STACK then chunkRegion cfg dst scratch size true
   else if hint = x64_ir.region.DATA then chunkRegion cfg dst scratch size false
   else
     [ .Store 8#u8 dst x64_ir.RBP x64_ir.frame.ADDR_SPILL_OFFSET ] ++
     chunkRegion cfg dst scratch size true ++
     [ .Store 8#u8 dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET,
       .Load 8#u8 false x64_ir.RBP dst x64_ir.frame.ADDR_SPILL_OFFSET ] ++
     chunkRegion cfg dst scratch size false ++
     [ .AluRM .Or dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET ])

/-- `x64_expand::expand_muldiv_setup`. -/
def chunkMulDivSetup (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) : List x64_ir.PInsn :=
  (if dst != x64_ir.RAX then [ .Push x64_ir.RAX ] else []) ++
  (if dst != x64_ir.RDX then [ .Push x64_ir.RDX ] else []) ++
  (if reg then [ .Alu true .Mov src x64_ir.RCX ]
   else [ .LoadImm x64_ir.RCX (Std.IScalar.cast .I64 imm) ]) ++
  [ .Alu true .Mov dst x64_ir.RAX ] ++
  (if isDiv kind || isMod kind then
     [ .Alu w64 .Test x64_ir.RCX x64_ir.RCX ] ++
     (if isMod kind then [ .Push x64_ir.RAX ] else []) ++
     [ .Pushfq, .LoadImm x64_ir.RDX 1#i64, .Cmov x64_ir.cc.E x64_ir.RCX x64_ir.RDX ] ++
     (if signed then (if w64 then [ .Cqo ] else [ .Cdq ])
      else [ .Alu false .Xor x64_ir.RDX x64_ir.RDX ])
   else [])

/-- `x64_expand::expand_muldiv_overflow`. -/
def chunkMulDivOverflow (w64 div : Bool) (noOverflow afterDivide : Nat) :
    List x64_ir.PInsn :=
  [ .CmpRcxMinusOne w64, .Jcc8 x64_ir.cc.NE (u32 noOverflow) ] ++
  (if w64 then [ .LoadImm x64_ir.R11 core.num.I64.MIN,
                 .Alu true .Cmp x64_ir.R11 x64_ir.RAX ]
   else [ .CmpEaxImm 2147483648#u32 ]) ++
  [ .Jcc8 x64_ir.cc.NE (u32 noOverflow) ] ++
  (if div then [] else [ .Alu false .Xor x64_ir.RDX x64_ir.RDX ]) ++
  [ .Jmp8 (u32 afterDivide), .Local (u32 noOverflow) ]

/-- `x64_expand::expand_muldiv_finish`. -/
def chunkMulDivFinish (kind : x64_ir.MulDivKind) (dst : Std.U8) : List x64_ir.PInsn :=
  (if isDiv kind then [ .Popfq, .LoadImm x64_ir.RCX 0#i64,
                        .Cmov x64_ir.cc.E x64_ir.RAX x64_ir.RCX ]
   else if isMod kind then [ .Popfq, .Pop x64_ir.RCX,
                             .Cmov x64_ir.cc.E x64_ir.RDX x64_ir.RCX ]
   else []) ++
  (if dst != x64_ir.RDX then
     (if isMod kind then [ .Alu true .Mov x64_ir.RDX dst ] else []) ++ [ .Pop x64_ir.RDX ]
   else []) ++
  (if dst != x64_ir.RAX then
     (if isDiv kind || isMul kind then [ .Alu true .Mov x64_ir.RAX dst ] else []) ++
     [ .Pop x64_ir.RAX ]
   else [])

/-- `x64_expand::expand_muldivmod`. -/
def chunkMulDivMod (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) (label : Nat) : List x64_ir.PInsn × Nat :=
  if reg then
    ((chunkMulDivSetup kind w64 true signed src dst imm ++
      (if (isDiv kind || isMod kind) && signed then
         chunkMulDivOverflow w64 (isDiv kind) label (label + 1) else []) ++
      [ .MulDivRcx w64 kind signed ] ++
      (if (isDiv kind || isMod kind) && signed then [ .Local (u32 (label + 1)) ] else []) ++
      chunkMulDivFinish kind dst),
     if (isDiv kind || isMod kind) && signed then label + 2 else label)
  else if imm = 0#i32 then
    (if isDiv kind || isMul kind then ([ .Alu false .Xor dst dst ], label)
     else ([ .Alu true .Mov dst dst ], label))
  else
    ((chunkMulDivSetup kind w64 false signed src dst imm ++
      (if (isDiv kind || isMod kind) && signed then
         chunkMulDivOverflow w64 (isDiv kind) label (label + 1) else []) ++
      [ .MulDivRcx w64 kind signed ] ++
      (if (isDiv kind || isMod kind) && signed then [ .Local (u32 (label + 1)) ] else []) ++
      chunkMulDivFinish kind dst),
     if (isDiv kind || isMod kind) && signed then label + 2 else label)

/-- `x64_expand::expand_atomic_fetch_alu`. -/
def chunkAtomicFetchAlu (op : Std.U8) (w64 : Bool) (src base : Std.U8) (disp : Std.I32)
    (label : Nat) : List x64_ir.PInsn × Nat :=
  let actual := if src = x64_ir.RAX then (if base = x64_ir.R10 then x64_ir.R11 else x64_ir.R10)
                else src
  ((if src = x64_ir.RAX then [ .Push actual, .Alu true .Mov src actual ]
    else [ .Push x64_ir.RAX ]) ++
   [ .Load (if w64 then 8#u8 else 4#u8) false base x64_ir.RAX disp,
     .Local (u32 label),
     .Alu true .Mov x64_ir.RAX x64_ir.RCX,
     .Alu true (aluRrOf op) actual x64_ir.RCX,
     .LockCmpxchg w64 x64_ir.RCX base disp,
     .Jcc8 x64_ir.cc.NE (u32 label) ] ++
   (if src = x64_ir.RAX then [ .Pop actual ]
    else [ .Alu true .Mov x64_ir.RAX src, .Pop x64_ir.RAX ]),
   label + 1)

/-- The scrub of the registers backing eBPF `R1`–`R5` after a helper call. -/
def helperScrub : List x64_ir.PInsn :=
  [ .Alu true .Xor (mreg 1) (mreg 1), .Alu true .Xor (mreg 2) (mreg 2),
    .Alu true .Xor (mreg 3) (mreg 3), .Alu true .Xor (mreg 4) (mreg 4),
    .Alu true .Xor (mreg 5) (mreg 5) ]

/-- `x64_expand::expand_helper_call`. -/
def chunkHelperCall (idx : Std.U32) (label : Nat) : List x64_ir.PInsn × Nat :=
  ([ .RipLoadDispatcher x64_ir.RAX,
     .AluImm true .Cmp x64_ir.RAX 0#i32,
     .Jcc x64_ir.cc.NE (.Local (u32 label)),
     .AluImm false .Mov x64_ir.RAX (Std.UScalar.hcast .I32 idx),
     .ShiftImm true .Shl x64_ir.RAX 3#i32,
     .RipLeaHelperTable x64_ir.R10,
     .Alu true .Add x64_ir.R10 x64_ir.RAX,
     .Load 8#u8 false x64_ir.RAX x64_ir.RAX 0#i32,
     .Alu true .Mov x64_ir.VOLATILE_CTXT x64_ir.R9,
     .Jmp (.Local (u32 (label + 1))),
     .Local (u32 label),
     .LoadImm x64_ir.R9 (Std.UScalar.hcast .I64 (Std.UScalar.cast (.U64) idx)),
     .Local (u32 (label + 1)),
     .Call .Retpoline ] ++ helperScrub, label + 2)

/-- `x64_expand::expand_lazy_call_body`. -/
def chunkLazyCallBody (cfg : x64_ir.Cfg) (id : Std.U32) : List x64_ir.PInsn :=
  [ .Push (mreg 6), .Push (mreg 7), .Push (mreg 8), .Push (mreg 9),
    .Push (mreg 1), .Push (mreg 2), .Push (mreg 3), .Push (mreg 4), .Push (mreg 5),
    .Push x64_ir.VOLATILE_CTXT, .Push (mreg 0), .Push (mreg 0),
    .LoadImm x64_ir.RDI (Std.UScalar.hcast .I64 (Std.UScalar.cast (.U64) id)),
    .LoadImm x64_ir.RAX (Std.UScalar.hcast .I64 cfg.local_call_resolver),
    .CallReg x64_ir.RAX,
    .Alu true .Mov x64_ir.RAX x64_ir.RCX,
    .Pop (mreg 0), .Pop (mreg 0), .Pop x64_ir.VOLATILE_CTXT,
    .Pop (mreg 5), .Pop (mreg 4), .Pop (mreg 3), .Pop (mreg 2), .Pop (mreg 1),
    .CallReg x64_ir.RCX,
    .Pop (mreg 9), .Pop (mreg 8), .Pop (mreg 7), .Pop (mreg 6) ]

/-- `x64_expand::expand_lazy_local_call`. -/
def chunkLazyLocalCall (cfg : x64_ir.Cfg) (id : Std.U32) (label : Nat) :
    List x64_ir.PInsn × Nat :=
  ([ .Load 8#u8 false x64_ir.RBP x64_ir.RCX x64_ir.frame.FRAME_OFFSET,
     .Load 8#u8 false x64_ir.RCX x64_ir.RCX x64_ir.memory.LOCAL_CALL_GUEST_FLOOR,
     .Alu true .Cmp x64_ir.RCX x64_ir.R15,
     .Jcc x64_ir.cc.B (.Local (u32 label)),
     .Load 8#u8 false x64_ir.RBP x64_ir.RCX x64_ir.frame.FRAME_OFFSET,
     .Load 8#u8 false x64_ir.RCX x64_ir.RCX x64_ir.memory.LOCAL_CALL_NATIVE_FLOOR,
     .Alu true .Cmp x64_ir.RCX x64_ir.RSP,
     .Jcc x64_ir.cc.B (.Local (u32 label)),
     .AluImm true .Sub x64_ir.R15 (Std.UScalar.hcast .I32 cfg.stack_frame_stride) ] ++
   chunkLazyCallBody cfg id ++
   [ .AluImm true .Add x64_ir.R15 (Std.UScalar.hcast .I32 cfg.stack_frame_stride),
     .Jmp (.Local (u32 (label + 1))),
     .Local (u32 label),
     .LoadImm x64_ir.RAX (Std.UScalar.hcast .I64 cfg.local_call_stack_exhausted),
     .CallReg x64_ir.RAX,
     .Ud2,
     .Local (u32 (label + 1)) ], label + 2)

/-- `x64_expand::expand_retpoline`. -/
def chunkRetpoline (label : Nat) : List x64_ir.PInsn × Nat :=
  ([ .RetpolineLabel,
     .Call (.Local (u32 label)),
     .Local (u32 (label + 1)),
     .Pause,
     .Jmp (.Local (u32 (label + 1))),
     .Local (u32 label),
     .StoreRspRax,
     .Ret ], label + 2)

/-- One macro's expansion: the primitives it emits, and the next free local
label. `trailerEpilogue` is `starts_trailer`, which only an `Epilogue`
consults. -/
def chunk (cfg : x64_ir.Cfg) (m : x64_ir.MInsn) (trailerEpilogue : Bool) (label : Nat) :
    List x64_ir.PInsn × Nat :=
  match m with
  | .PcLabel pc => ([ .PcLabel pc ], label)
  | .Prologue usage skip => chunkPrologue usage skip label
  | .Epilogue =>
    ((if trailerEpilogue then [ .ExitLabel ] else []) ++
     [ .AluImm true .Add x64_ir.RSP 8#i32, .Ret ], label)
  | .Alu w64 op src dst => ([ .Alu w64 op src dst ], label)
  | .AluImm w64 op dst imm => ([ .AluImm w64 op dst imm ], label)
  | .ShiftImm w64 op dst imm => ([ .ShiftImm w64 op dst imm ], label)
  | .ShiftCl w64 op dst => ([ .ShiftCl w64 op dst ], label)
  | .Neg w64 dst => ([ .Neg w64 dst ], label)
  | .MovSx «from» w64 src dst => ([ .MovSx «from» w64 src dst ], label)
  | .Bswap w64 dst => ([ .Bswap w64 dst ], label)
  | .Rol16 dst => ([ .Rol16 dst ], label)
  | .LoadImm dst imm => ([ .LoadImm dst imm ], label)
  | .MulDivMod kind w64 reg signed src dst imm =>
    chunkMulDivMod kind w64 reg signed src dst imm label
  | .Jcc cc target => ([ .Jcc cc (ptargetOf target) ], label)
  | .Jmp target => ([ .Jmp (ptargetOf target) ], label)
  | .GuestFp dst => (chunkGuestFp dst, label)
  | .CheckedAddr src dst scratch offset size hint =>
    (chunkCheckedAddr cfg src dst scratch offset size hint, label)
  | .GroupBaseStore src =>
    ([ .Store 8#u8 src x64_ir.RBP x64_ir.frame.GROUP_BASE_OFFSET ], label)
  | .GroupBaseLoad dst =>
    ([ .Load 8#u8 false x64_ir.RBP dst x64_ir.frame.GROUP_BASE_OFFSET ], label)
  | .Load size sx base dst disp => ([ .Load size sx base dst disp ], label)
  | .Store size src base disp => ([ .Store size src base disp ], label)
  | .StoreImm size base disp imm => ([ .StoreImm size base disp imm ], label)
  | .AtomicAlu op w64 src base disp => ([ .LockAlu op w64 src base disp ], label)
  | .AtomicFetchAlu op w64 src base disp => chunkAtomicFetchAlu op w64 src base disp label
  | .AtomicXchg w64 src base disp => ([ .Xchg w64 src base disp ], label)
  | .AtomicCmpxchg w64 src base disp => ([ .LockCmpxchg w64 src base disp ], label)
  | .HelperCall idx => chunkHelperCall idx label
  | .LazyLocalCall id => chunkLazyLocalCall cfg id label
  | .Retpoline => chunkRetpoline label
  | .DispatcherSlot => ([ .DispatcherSlot cfg.dispatcher ], label)
  | .HelperTable => ([ .HelperTable ], label)

/-! ## Reading a push chain off the generated code

Every helper in `x64_expand` is a straight-line chain of `Vec::push`es,
possibly with a branch or a call to another helper in it. `Emits f L` says
`f` appends exactly `L`; `EmitsL` is the same for the helpers that also
return the next free label. The combinators below peel one link at a time,
so each spec is the chain read off the generated definition. -/

abbrev VecP := alloc.vec.Vec x64_ir.PInsn

/-- `f` appends exactly `L` to its argument whenever it succeeds. -/
def Emits (f : VecP → Result VecP) (L : List x64_ir.PInsn) : Prop :=
  ∀ v w, f v = ok w → w.val = v.val ++ L

/-- `Emits` for the helpers that also return the next free local label. -/
def EmitsL (f : VecP → Result (Std.U32 × VecP)) (L : List x64_ir.PInsn) (n : Nat) : Prop :=
  ∀ v k w, f v = ok (k, w) → w.val = v.val ++ L ∧ k.val = n

theorem Emits.last (x : x64_ir.PInsn) : Emits (fun v => alloc.vec.Vec.push v x) [x] := by
  intro v w h; exact vec_push_eq_ok h

theorem Emits.id : Emits (fun v => ok v) [] := by
  intro v w h; simp only [ok.injEq] at h; subst h; simp

theorem Emits.seq {f g : VecP → Result VecP} {L1 L2}
    (hf : Emits f L1) (hg : Emits g L2) : Emits (fun v => f v >>= g) (L1 ++ L2) := by
  intro v w hv
  obtain ⟨v1, h1, h2⟩ := bind_eq_ok hv
  rw [hg _ _ h2, hf _ _ h1, List.append_assoc]

theorem Emits.push {x : x64_ir.PInsn} {g : VecP → Result VecP} {L}
    (h : Emits g L) : Emits (fun v => alloc.vec.Vec.push v x >>= g) (x :: L) :=
  Emits.seq (Emits.last x) h

theorem Emits.congr {f : VecP → Result VecP} {L L'} (h : Emits f L) (e : L = L') :
    Emits f L' := e ▸ h

theorem Emits.bindPre {α : Type} {r : Result α} {body : α → VecP → Result VecP} {L}
    (h : ∀ c, r = ok c → Emits (body c) L) :
    Emits (fun v => r >>= fun c => body c v) L := by
  intro v w hv
  obtain ⟨c, h1, h2⟩ := bind_eq_ok hv
  exact h c h1 _ _ h2

theorem EmitsL.pure (k : Std.U32) : EmitsL (fun v => ok (k, v)) [] k.val := by
  intro v k1 w h; simp only [ok.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h; simp

theorem EmitsL.tail {r : Result Std.U32} {n : Nat} (hr : ∀ k, r = ok k → k.val = n) :
    EmitsL (fun v => r >>= fun k => ok (k, v)) [] n := by
  intro v k1 w h
  obtain ⟨k2, h1, h2⟩ := bind_eq_ok h
  simp only [ok.injEq, Prod.mk.injEq] at h2
  obtain ⟨rfl, rfl⟩ := h2
  exact ⟨by simp, hr _ h1⟩

theorem EmitsL.seq {f : VecP → Result VecP} {g : VecP → Result (Std.U32 × VecP)} {L1 L2 n}
    (hf : Emits f L1) (hg : EmitsL g L2 n) : EmitsL (fun v => f v >>= g) (L1 ++ L2) n := by
  intro v k w hv
  obtain ⟨v1, h1, h2⟩ := bind_eq_ok hv
  obtain ⟨he, hk⟩ := hg _ _ _ h2
  exact ⟨by rw [he, hf _ _ h1, List.append_assoc], hk⟩

theorem EmitsL.push {x : x64_ir.PInsn} {g : VecP → Result (Std.U32 × VecP)} {L n}
    (h : EmitsL g L n) : EmitsL (fun v => alloc.vec.Vec.push v x >>= g) (x :: L) n :=
  EmitsL.seq (Emits.last x) h

theorem EmitsL.congr {f : VecP → Result (Std.U32 × VecP)} {L L' n n'}
    (h : EmitsL f L n) (e : L = L') (e' : n = n') : EmitsL f L' n' := e ▸ e' ▸ h

theorem EmitsL.bindPre {α : Type} {r : Result α} {body : α → VecP → Result (Std.U32 × VecP)}
    {L n} (h : ∀ c, r = ok c → EmitsL (body c) L n) :
    EmitsL (fun v => r >>= fun c => body c v) L n := by
  intro v k w hv
  obtain ⟨c, h1, h2⟩ := bind_eq_ok hv
  exact h c h1 _ _ _ h2

/-! ## Scalar plumbing -/

theorem u32_add_eq {x y z : Std.U32} (h : x + y = ok z) : z.val = x.val + y.val := by
  have := Std.UScalar.add_equiv x y
  rw [h] at this; exact this.2.1

theorem usize_add_eq {x y z : Std.Usize} (h : x + y = ok z) : z.val = x.val + y.val := by
  have := Std.UScalar.add_equiv x y
  rw [h] at this; exact this.2.1

theorem i32_add_eq {x y z : Std.I32} (h : x + y = ok z) : z.val = x.val + y.val := by
  have := Std.IScalar.add_equiv x y
  rw [h] at this; exact this.2.1

theorem i32_sub_eq {x y z : Std.I32} (h : x - y = ok z) : z.val = x.val - y.val := by
  have := Std.IScalar.sub_equiv x y
  rw [h] at this; exact this.2.1

theorem i32_mul_eq {x y z : Std.I32} (h : x * y = ok z) : z.val = x.val * y.val := by
  have := Std.IScalar.mul_equiv x y
  have h' : Std.IScalar.mul x y = ok z := h
  rw [h'] at this; exact this.2.2.1

theorem usize_hcast_i32_val (x : Std.Usize) (hx : x.val < 2 ^ 31) :
    (Std.UScalar.hcast .I32 x).val = (x.val : Int) := by
  rw [Std.UScalar.hcast_val_eq]
  simp only [Std.IScalarTy.I32_numBits_eq]
  unfold Int.bmod
  push_cast
  have hx' : (x.val : Int) < 2147483648 := by
    have : (2:Nat) ^ 31 = 2147483648 := by norm_num
    rw [this] at hx; exact_mod_cast hx
  split <;> omega

/-! ## The generated constants -/

theorem derived_base_val {stack : Bool} {c : Std.Usize}
    (h : x64_expand.derived_base stack = ok c) : c.val = derivedBase stack := by
  unfold x64_expand.derived_base derivedBase at *
  cases stack <;> simp [global_simps] at h ⊢ <;> simp [← h]

theorem derivedBase_le (stack : Bool) : derivedBase stack ≤ 6 := by
  unfold derivedBase; cases stack <;> norm_num

theorem derived_slot_val {k : Std.Usize} {v : Std.I32} (hk : k.val < 2 ^ 31)
    (h : x64_ir.frame.derived_slot k = ok v) : v.val = -136 + 8 * (k.val : Int) := by
  unfold x64_ir.frame.derived_slot at h
  obtain ⟨i1, h1, h⟩ := bind_eq_ok h
  simp only [lift, ok.injEq] at h1; subst h1
  obtain ⟨i2, h2, h⟩ := bind_eq_ok h
  have hm := i32_mul_eq h2
  have ha := i32_add_eq h
  rw [ha, hm, usize_hcast_i32_val k hk]
  have : ((8#i32 : Std.I32)).val = 8 := by decide
  rw [this]
  have : ((-136)#i32 : Std.I32).val = -136 := by decide
  rw [this]
  ring

theorem width_span_eq {size : Std.U32} {s : Option Std.Usize}
    (h : x64_expand.width_span_slot size = ok s) : widthSpan size = s.map (·.val) := by
  unfold x64_expand.width_span_slot at h
  unfold widthSpan
  split_ifs at h ⊢ <;> simp only [ok.injEq] at h <;> subst h <;> simp

theorem widthSpan_le {size : Std.U32} {j : Nat} (h : widthSpan size = some j) : j ≤ 3 := by
  unfold widthSpan at h; split_ifs at h <;> simp_all

theorem usize_numBits_ge : (32:Nat) ≤ UScalarTy.Usize.numBits := by
  simp only [UScalarTy.numBits]
  cases System.Platform.numBits_eq <;> omega

theorem map_register_lit {r : Std.U8} {n : Nat} (hn : n < 11) (hr : r.val = n) :
    x64_ir.map_register r = ok (mreg n) := by
  unfold x64_ir.map_register
  simp only [lift, bind_tc_ok]
  have hw : n < 2 ^ UScalarTy.Usize.numBits := by
    have : (2:Nat)^32 ≤ 2 ^ UScalarTy.Usize.numBits :=
      Nat.pow_le_pow_right (by norm_num) usize_numBits_ge
    have : (2:Nat)^32 = 4294967296 := by norm_num
    omega
  have hc : (UScalar.cast .Usize r).val = n := by
    rw [UScalar.cast_val_eq, hr]; exact Nat.mod_eq_of_lt hw
  have hrem : (UScalar.cast .Usize r) % 11#usize
      = ok (⟨BitVec.umod (UScalar.cast .Usize r).bv (11#usize).bv⟩ : Std.Usize) := by
    show UScalar.rem _ _ = _
    simp [UScalar.rem]
  rw [hrem]
  simp only [bind_tc_ok]
  have hiv : (⟨BitVec.umod (UScalar.cast .Usize r).bv (11#usize).bv⟩ : Std.Usize).val = n := by
    simp only [UScalar.val]
    change (UScalar.cast .Usize r).val % (11#usize).val = n
    rw [hc]
    have : (11#usize : Std.Usize).val = 11 := by decide
    rw [this]; exact Nat.mod_eq_of_lt hn
  unfold Array.index_usize
  rw [show x64_ir.REGISTER_MAP[(⟨BitVec.umod (UScalar.cast .Usize r).bv (11#usize).bv⟩ : Std.Usize)]?
      = x64_ir.REGISTER_MAP.val[n]? from by rw [← hiv]; rfl]
  simp only [x64_ir.REGISTER_MAP, global_simps, Array.make_val]
  rcases n with _|_|_|_|_|_|_|_|_|_|_|n
  all_goals first | (exfalso; omega) | (simp [mreg, global_simps])

theorem desc_bottom_eq {stack : Bool} {c : Std.I32}
    (h : x64_expand.desc_bottom stack = ok c) : c = descBottom stack := by
  unfold x64_expand.desc_bottom descBottom at *
  cases stack <;> simp only [if_true, if_false, Bool.false_eq_true, ok.injEq] at h ⊢ <;> exact h.symm

theorem desc_top_eq {stack : Bool} {c : Std.I32}
    (h : x64_expand.desc_top stack = ok c) : c = descTop stack := by
  unfold x64_expand.desc_top descTop at *
  cases stack <;> simp only [if_true, if_false, Bool.false_eq_true, ok.injEq] at h ⊢ <;> exact h.symm

theorem desc_native_base_eq {stack : Bool} {c : Std.I32}
    (h : x64_expand.desc_native_base stack = ok c) : c = descNativeBase stack := by
  unfold x64_expand.desc_native_base descNativeBase at *
  cases stack <;> simp only [if_true, if_false, Bool.false_eq_true, ok.injEq] at h ⊢ <;> exact h.symm

/-! ## The macro sequences, one lemma per generated helper -/

theorem guestFp_emits (dst : Std.U8) :
    Emits (x64_expand.expand_guest_fp dst) (chunkGuestFp dst) := by
  unfold x64_expand.expand_guest_fp chunkGuestFp
  simp only [x64_expand.mov64, x64_expand.alu_rm, bind_tc_ok]
  exact Emits.push (Emits.last _)

theorem prologue_emits (usage : Std.U16) (skip : Bool) (label : Std.U32) :
    EmitsL (x64_expand.expand_prologue usage skip label)
      (chunkPrologue usage skip label.val).1 (chunkPrologue usage skip label.val).2 := by
  unfold x64_expand.expand_prologue chunkPrologue
  cases skip <;>
    simp only [Bool.false_eq_true, if_false, if_true, lift, bind_tc_ok, u32_val]
  · exact EmitsL.push (EmitsL.push (EmitsL.pure _))
  · refine EmitsL.push (EmitsL.push (EmitsL.push (EmitsL.push (EmitsL.tail ?_))))
    intro k hk; rw [u32_add_eq hk]; rfl

theorem retpoline_emits (label : Std.U32) :
    EmitsL (x64_expand.expand_retpoline label) (chunkRetpoline label.val).1
      (chunkRetpoline label.val).2 := by
  unfold x64_expand.expand_retpoline chunkRetpoline
  refine EmitsL.bindPre (fun capture hc => ?_)
  have hcv : capture = u32 (label.val + 1) := u32_eq_of_val (by rw [u32_add_eq hc]; rfl)
  subst hcv
  simp only [u32_val]
  refine EmitsL.push (EmitsL.push (EmitsL.push (EmitsL.push (EmitsL.push (EmitsL.push
    (EmitsL.push (EmitsL.push (EmitsL.tail ?_))))))))
  intro k hk; rw [u32_add_eq hk]; rfl

theorem regionFromFrame_emits (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    Emits (x64_expand.expand_region_from_frame dst scratch size stack)
      (chunkRegionFromFrame dst scratch size stack) := by
  unfold x64_expand.expand_region_from_frame chunkRegionFromFrame
  have hdb := derivedBase_le stack
  refine Emits.bindPre (fun base hbase => ?_)
  have hb : base.val = derivedBase stack := derived_base_val hbase
  refine Emits.bindPre (fun i0 hi0 => ?_)
  have hi0v : i0.val = derivedBase stack := by
    rw [usize_add_eq hi0, hb]; simp [global_simps]
  refine Emits.bindPre (fun bslot hbs => ?_)
  have hbsv : bslot.val = -136 + 8 * (i0.val : Int) := derived_slot_val (by omega) hbs
  have hbs' : bslot = derivedSlot (derivedBase stack) := by
    rw [← hi0v]; exact i32_eq_of_val hbsv
  subst hbs'
  refine Emits.bindPre (fun i1 hi1 => ?_)
  have hi1v : i1.val = derivedBase stack + 1 := by
    rw [usize_add_eq hi1, hb]; simp [global_simps]
  refine Emits.bindPre (fun dslot hds => ?_)
  have hdsv : dslot.val = -136 + 8 * (i1.val : Int) := derived_slot_val (by omega) hds
  have hds' : dslot = derivedSlot (derivedBase stack + 1) := by
    rw [← hi1v]; exact i32_eq_of_val hdsv
  subst hds'
  refine Emits.bindPre (fun i2 hi2 => ?_)
  have hi2v : i2.val = derivedBase stack + 2 := by
    rw [usize_add_eq hi2, hb]; simp [global_simps]
  refine Emits.bindPre (fun sbase hsb => ?_)
  have hsbv : sbase.val = -136 + 8 * (i2.val : Int) := derived_slot_val (by omega) hsb
  have hsb' : sbase = derivedSlot (derivedBase stack + 2) := by
    rw [← hi2v]; exact i32_eq_of_val hsbv
  subst hsb'
  simp only [x64_expand.mov64, x64_expand.alu_rm, x64_expand.load64, x64_expand.cmovb,
    lift, bind_tc_ok]
  refine Emits.push (Emits.push (Emits.push ?_))
  refine Emits.bindPre (fun span hspan => ?_)
  rw [width_span_eq hspan]
  cases span with
  | none =>
    simp only [Option.map_none]
    refine Emits.push ?_
    refine Emits.bindPre (fun i4 hi4 => ?_)
    have : i4 = i32 ((Std.UScalar.hcast .I32 size).val - 1) := by
      refine i32_eq_of_val ?_
      rw [i32_sub_eq hi4]
      have : ((1#i32 : Std.I32)).val = 1 := by decide
      rw [this]
    subst this
    exact Emits.push (Emits.push (Emits.push (Emits.last _)))
  | some slot =>
    simp only [Option.map_some]
    have hsl : slot.val ≤ 3 := widthSpan_le (by rw [width_span_eq hspan]; rfl)
    refine Emits.bindPre (fun i4 hi4 => ?_)
    refine Emits.bindPre (fun sslot hss => ?_)
    have hsslot : sslot = derivedSlot (derivedBase stack + 2 + slot.val) := by
      refine i32_eq_of_val ?_
      rw [i32_add_eq hss, hsbv, hi2v, i32_mul_eq hi4,
        usize_hcast_i32_val slot (by omega)]
      have h8 : ((8#i32 : Std.I32)).val = 8 := by decide
      rw [h8]
      push_cast
      ring
    subst hsslot
    exact Emits.push (Emits.push (Emits.last _))

theorem regionViaDescriptor_emits (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    Emits (x64_expand.expand_region_via_descriptor dst scratch size stack)
      (chunkRegionViaDescriptor dst scratch size stack) := by
  unfold x64_expand.expand_region_via_descriptor chunkRegionViaDescriptor
  refine Emits.bindPre (fun bo hbo => ?_)
  refine Emits.bindPre (fun tp hto => ?_)
  refine Emits.bindPre (fun nb hnb => ?_)
  have hbo' := desc_bottom_eq hbo; subst hbo'
  have hto' := desc_top_eq hto; subst hto'
  have hnb' := desc_native_base_eq hnb; subst hnb'
  simp only [x64_expand.alu_rm, x64_expand.load64, x64_expand.store64,
    x64_expand.cmovb, lift, bind_tc_ok]
  cases hz : (size != 0#u32) <;>
    simp only [Bool.false_eq_true, if_false, if_true, bind_tc_ok]
  · exact Emits.push (Emits.push (Emits.push (Emits.push (Emits.push (Emits.push
      (Emits.push (Emits.push (Emits.last _))))))))
  · exact Emits.push (Emits.push (Emits.push (Emits.push (Emits.push (Emits.push
      (Emits.push (Emits.push (Emits.push (Emits.last _)))))))))

theorem region_emits (cfg : x64_ir.Cfg) (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    Emits (x64_expand.expand_region cfg dst scratch size stack)
      (chunkRegion cfg dst scratch size stack) := by
  unfold x64_expand.expand_region chunkRegion
  split
  · exact regionFromFrame_emits dst scratch size stack
  · exact regionViaDescriptor_emits dst scratch size stack

/-- Discharges an `Emits` goal whose function is a straight chain of pushes,
possibly calling `expand_guest_fp` or `expand_region`. -/
macro "emit_chain" : tactic => `(tactic|
  repeat first
    | exact Emits.id
    | exact Emits.last _
    | exact guestFp_emits _
    | exact region_emits _ _ _ _ _
    | refine Emits.seq (guestFp_emits _) ?_
    | refine Emits.seq (region_emits _ _ _ _ _) ?_
    | refine Emits.push ?_)

/-- `emit_chain` for the label-returning helpers. -/
macro "emitL_chain" : tactic => `(tactic|
  repeat first
    | exact EmitsL.pure _
    | refine EmitsL.push ?_)

theorem nfba_eq {cfg : x64_ir.Cfg} {b : Bool}
    (h : x64_ir.Cfg.native_frame_base_active cfg = ok b) : b = framedActive cfg := by
  unfold x64_ir.Cfg.native_frame_base_active framedActive at *
  by_cases hp : cfg.pointer_mask = 0#i32 <;> simp_all

theorem checkedAddr_emits (cfg : x64_ir.Cfg) (src dst scratch : Std.U8) (offset : Std.I32)
    (size : Std.U32) (hint : Std.U8) :
    Emits (x64_expand.expand_checked_addr cfg src dst scratch offset size hint)
      (chunkCheckedAddr cfg src dst scratch offset size hint) := by
  unfold x64_expand.expand_checked_addr chunkCheckedAddr
  refine Emits.bindPre (fun framed hf => ?_)
  have hfv := nfba_eq hf; subst hfv
  simp only [x64_expand.mov64, x64_expand.store64, x64_expand.load64, x64_expand.alu_rm,
    lift, bind_tc_ok, bind_assoc_eq, List.append_assoc, List.nil_append,
    List.cons_append, List.singleton_append]
  split_ifs <;>
    (try simp only [bind_tc_ok, bind_assoc_eq, List.nil_append, List.append_assoc,
      List.cons_append, List.singleton_append]) <;> emit_chain

theorem muldivSetup_emits (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) :
    Emits (x64_expand.expand_muldiv_setup kind w64 reg signed src dst imm)
      (chunkMulDivSetup kind w64 reg signed src dst imm) := by
  unfold x64_expand.expand_muldiv_setup chunkMulDivSetup
  cases kind <;>
    simp only [x64_expand.is_div, x64_expand.is_mod, isDiv, isMod, x64_expand.mov64,
      x64_expand.cmove, lift, bind_tc_ok, bind_assoc_eq, Bool.or_self, Bool.false_or,
      Bool.or_false, Bool.true_or, Bool.false_eq_true, if_true, if_false, reduceIte,
      List.append_assoc, List.nil_append, List.cons_append, List.singleton_append] <;>
    (try split_ifs) <;>
    (try simp only [bind_tc_ok, bind_assoc_eq, List.nil_append, List.append_assoc,
      List.cons_append, List.singleton_append]) <;> emit_chain

theorem muldivOverflow_emits (w64 div : Bool) (noOv after : Std.U32) :
    Emits (x64_expand.expand_muldiv_overflow w64 div noOv after)
      (chunkMulDivOverflow w64 div noOv.val after.val) := by
  unfold x64_expand.expand_muldiv_overflow chunkMulDivOverflow
  simp only [u32_val, bind_tc_ok, bind_assoc_eq, List.append_assoc, List.nil_append,
    List.cons_append, List.singleton_append]
  split_ifs <;>
    (try simp only [bind_tc_ok, bind_assoc_eq, List.nil_append, List.append_assoc,
      List.cons_append, List.singleton_append]) <;> emit_chain

theorem muldivFinish_emits (kind : x64_ir.MulDivKind) (dst : Std.U8) :
    Emits (x64_expand.expand_muldiv_finish kind dst) (chunkMulDivFinish kind dst) := by
  unfold x64_expand.expand_muldiv_finish chunkMulDivFinish
  cases kind <;>
    simp only [x64_expand.is_div, x64_expand.is_mod, x64_expand.is_mul, isDiv, isMod, isMul,
      x64_expand.mov64, x64_expand.cmove, lift, bind_tc_ok, bind_assoc_eq, uncurry_apply_pair,
      Bool.or_self, Bool.false_or, Bool.or_false, Bool.true_or, Bool.false_eq_true,
      if_true, if_false, reduceIte, List.append_assoc, List.nil_append,
      List.cons_append, List.singleton_append] <;>
    (try split_ifs) <;>
    (try simp only [bind_tc_ok, bind_assoc_eq, List.nil_append, List.append_assoc,
      List.cons_append, List.singleton_append]) <;> emit_chain

theorem map_register_0 : x64_ir.map_register 0#u8 = ok (mreg 0) :=
  map_register_lit (by norm_num) rfl

theorem map_register_1 : x64_ir.map_register 1#u8 = ok (mreg 1) :=
  map_register_lit (by norm_num) rfl

theorem map_register_2 : x64_ir.map_register 2#u8 = ok (mreg 2) :=
  map_register_lit (by norm_num) rfl

theorem map_register_3 : x64_ir.map_register 3#u8 = ok (mreg 3) :=
  map_register_lit (by norm_num) rfl

theorem map_register_4 : x64_ir.map_register 4#u8 = ok (mreg 4) :=
  map_register_lit (by norm_num) rfl

theorem map_register_5 : x64_ir.map_register 5#u8 = ok (mreg 5) :=
  map_register_lit (by norm_num) rfl

theorem map_register_6 : x64_ir.map_register 6#u8 = ok (mreg 6) :=
  map_register_lit (by norm_num) rfl

theorem map_register_7 : x64_ir.map_register 7#u8 = ok (mreg 7) :=
  map_register_lit (by norm_num) rfl

theorem map_register_8 : x64_ir.map_register 8#u8 = ok (mreg 8) :=
  map_register_lit (by norm_num) rfl

theorem map_register_9 : x64_ir.map_register 9#u8 = ok (mreg 9) :=
  map_register_lit (by norm_num) rfl


theorem EmitsL.done {f : VecP → Result VecP} {L n} {k : Std.U32}
    (hf : Emits f L) (hk : k.val = n) :
    EmitsL (fun v => f v >>= fun w => ok (k, w)) L n := by
  intro v k1 w hv
  obtain ⟨v1, h1, h2⟩ := bind_eq_ok hv
  simp only [ok.injEq, Prod.mk.injEq] at h2; obtain ⟨rfl, rfl⟩ := h2
  exact ⟨hf _ _ h1, hk⟩

theorem EmitsL.pure_eq {k : Std.U32} {n : Nat} (h : k.val = n) :
    EmitsL (fun v => ok (k, v)) [] n := by
  intro v k1 w hh; simp only [ok.injEq, Prod.mk.injEq] at hh
  obtain ⟨rfl, rfl⟩ := hh; exact ⟨by simp, h⟩

theorem muldivOverflow_emits' (w64 div : Bool) (noOv after : Std.U32) (m n : Nat)
    (h1 : noOv.val = m) (h2 : after.val = n) :
    Emits (x64_expand.expand_muldiv_overflow w64 div noOv after)
      (chunkMulDivOverflow w64 div m n) := by
  subst h1; subst h2; exact muldivOverflow_emits w64 div noOv after

theorem muldivmod_emits (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) (label : Std.U32) :
    EmitsL (x64_expand.expand_muldivmod kind w64 reg signed src dst imm label)
      (chunkMulDivMod kind w64 reg signed src dst imm label.val).1
      (chunkMulDivMod kind w64 reg signed src dst imm label.val).2 := by
  unfold x64_expand.expand_muldivmod chunkMulDivMod
  cases kind <;> cases reg <;> cases signed <;>
    simp only [x64_expand.is_div, x64_expand.is_mod, x64_expand.is_mul, isDiv, isMod, isMul,
      x64_expand.mov64, lift, bind_tc_ok, bind_assoc_eq, uncurry_apply_pair,
      Bool.or_self, Bool.false_or, Bool.or_false, Bool.true_or, Bool.and_true, Bool.and_false,
      Bool.false_eq_true, if_true, if_false, reduceIte,
      List.append_assoc, List.nil_append, List.cons_append, List.singleton_append] <;>
    (try split_ifs) <;>
    (try simp only [bind_tc_ok, bind_assoc_eq, List.nil_append, List.append_assoc,
      List.cons_append, List.singleton_append]) <;>
    first
      | (emitL_chain; done)
      | (refine EmitsL.seq (muldivSetup_emits _ _ _ _ _ _ _) (EmitsL.bindPre (fun ad had => ?_))
         exact EmitsL.push (EmitsL.done (muldivFinish_emits _ _) rfl))
      | (refine EmitsL.seq (muldivSetup_emits _ _ _ _ _ _ _) (EmitsL.bindPre (fun ad had => ?_))
         have hadv : ad.val = label.val + 1 := by rw [u32_add_eq had]; rfl
         rw [← u32_eq_of_val hadv]
         refine EmitsL.seq (muldivOverflow_emits' _ _ _ _ _ _ rfl hadv)
           (EmitsL.bindPre (fun nx hnx => ?_))
         refine EmitsL.push (EmitsL.push (EmitsL.done (muldivFinish_emits _ _) ?_))
         rw [u32_add_eq hnx]; rfl)

theorem aluRrOf_eq (op : Std.U8) : x64_expand.alu_rr_of op = ok (aluRrOf op) := by
  unfold x64_expand.alu_rr_of aluRrOf
  split_ifs <;> rfl

theorem EmitsL.tail_add {x y : Std.U32} {n : Nat} (hn : x.val + y.val = n) :
    EmitsL (fun v => (x + y) >>= fun k => ok (k, v)) [] n :=
  EmitsL.tail (fun k hk => by rw [u32_add_eq hk]; exact hn)

theorem atomicFetchAlu_emits (op : Std.U8) (w64 : Bool) (src base : Std.U8) (disp : Std.I32)
    (label : Std.U32) :
    EmitsL (x64_expand.expand_atomic_fetch_alu op w64 src base disp label)
      (chunkAtomicFetchAlu op w64 src base disp label.val).1
      (chunkAtomicFetchAlu op w64 src base disp label.val).2 := by
  unfold x64_expand.expand_atomic_fetch_alu chunkAtomicFetchAlu
  simp only [x64_expand.mov64, aluRrOf_eq, u32_val, lift, bind_tc_ok, bind_assoc_eq,
    List.append_assoc, List.nil_append, List.cons_append, List.singleton_append]
  split_ifs <;>
    (try simp only [bind_tc_ok, bind_assoc_eq, List.nil_append, List.append_assoc,
      List.cons_append, List.singleton_append]) <;>
    (repeat first
      | exact EmitsL.tail_add rfl
      | refine EmitsL.push ?_)

theorem uscalar_add_eq {ty} {x y z : Std.UScalar ty} (h : x + y = ok z) :
    z.val = x.val + y.val := by
  have := Std.UScalar.add_equiv x y
  rw [h] at this; exact this.2.1

theorem EmitsL.done_add {f : VecP → Result VecP} {L n} {x y : Std.U32}
    (hf : Emits f L) (hn : x.val + y.val = n) :
    EmitsL (fun v => f v >>= fun w => (x + y) >>= fun k => ok (k, w)) L n := by
  intro v k1 w hv
  obtain ⟨v1, h1, h2⟩ := bind_eq_ok hv
  obtain ⟨k2, h3, h4⟩ := bind_eq_ok h2
  simp only [ok.injEq, Prod.mk.injEq] at h4; obtain ⟨rfl, rfl⟩ := h4
  exact ⟨hf _ _ h1, by rw [uscalar_add_eq h3]; exact hn⟩

/-- The scrub loop's invariant, one step on. -/
def ScrubPost (v : VecP) : ControlFlow (VecP × Std.U8) VecP → Prop
  | .cont x => 1 ≤ x.2.val ∧ x.2.val ≤ 6 ∧ x.1.val = v.val ++ helperScrub.take (x.2.val - 1)
  | .done y => y.val = v.val ++ helperScrub

/-- One step of the scrub loop at the end of a helper call. -/
theorem helperScrub_step (v out1 : VecP) (r : Std.U8)
    (h1 : 1 ≤ r.val) (h2 : r.val ≤ 6)
    (h3 : out1.val = v.val ++ helperScrub.take (r.val - 1))
    (res : ControlFlow (VecP × Std.U8) VecP)
    (hb : x64_expand.expand_helper_call_loop.body out1 r = ok res) : ScrubPost v res := by
  unfold x64_expand.expand_helper_call_loop.body at hb
  have h5 : (5#u8 : Std.U8).val = 5 := by decide
  split at hb
  · rename_i hle
    rw [UScalar.le_equiv] at hle
    have hrle : r.val ≤ 5 := by omega
    obtain_bind ⟨n, hn, hb⟩ := hb
    obtain_bind ⟨out2, hp, hb⟩ := hb
    obtain_bind ⟨r1, hr1, hb⟩ := hb
    simp only [ok.injEq] at hb; subst hb
    have hnv : n = mreg r.val := by
      have hm := map_register_lit (r := r) (n := r.val) (by omega) rfl
      rw [hm] at hn; simp only [ok.injEq] at hn; exact hn.symm
    subst hnv
    have hr1v : r1.val = r.val + 1 := by
      rw [uscalar_add_eq hr1]; have : (1#u8 : Std.U8).val = 1 := by decide
      omega
    have hpv := vec_push_eq_ok hp
    show 1 ≤ r1.val ∧ r1.val ≤ 6 ∧ out2.val = v.val ++ helperScrub.take (r1.val - 1)
    refine ⟨by omega, by omega, ?_⟩
    simp only [hpv, h3, hr1v, List.append_assoc]
    congr 1
    have : r.val = 1 ∨ r.val = 2 ∨ r.val = 3 ∨ r.val = 4 ∨ r.val = 5 := by omega
    rcases this with hh|hh|hh|hh|hh <;> rw [hh] <;> simp [helperScrub, mreg]
  · rename_i hgt
    simp only [ok.injEq] at hb; subst hb
    rw [UScalar.le_equiv] at hgt
    have hr6 : r.val = 6 := by omega
    show out1.val = v.val ++ helperScrub
    rw [h3, hr6]
    simp [helperScrub]

/-- The scrub loop appends exactly the five `xor`s. -/
theorem helperScrub_emits :
    Emits (fun v => x64_expand.expand_helper_call_loop v 1#u8) helperScrub := by
  intro v w h
  simp only at h
  unfold x64_expand.expand_helper_call_loop at h
  refine loop_ok_induction _
    (fun x : VecP × Std.U8 =>
      1 ≤ x.2.val ∧ x.2.val ≤ 6 ∧ x.1.val = v.val ++ helperScrub.take (x.2.val - 1))
    (fun y : VecP => y.val = v.val ++ helperScrub)
    ?_ _ _ ⟨by simp, by simp, by simp⟩ h
  rintro ⟨out1, r⟩ ⟨h1, h2, h3⟩ res hb
  have hs := helperScrub_step v out1 r h1 h2 h3 res hb
  cases res <;> exact hs

theorem helperCall_emits (idx label : Std.U32) :
    EmitsL (x64_expand.expand_helper_call idx label) (chunkHelperCall idx label.val).1
      (chunkHelperCall idx label.val).2 := by
  unfold x64_expand.expand_helper_call chunkHelperCall
  refine EmitsL.bindPre (fun converge hc => ?_)
  have hcv : converge = u32 (label.val + 1) := u32_eq_of_val (by rw [u32_add_eq hc]; rfl)
  subst hcv
  simp only [x64_expand.mov64, x64_expand.load64, u32_val, lift, bind_tc_ok, bind_assoc_eq,
    List.append_assoc, List.nil_append, List.cons_append, List.singleton_append]
  repeat first
    | exact EmitsL.done_add helperScrub_emits rfl
    | refine EmitsL.push ?_

theorem lazyCallBody_emits (cfg : x64_ir.Cfg) (id : Std.U32) :
    Emits (x64_expand.expand_lazy_call_body cfg id) (chunkLazyCallBody cfg id) := by
  unfold x64_expand.expand_lazy_call_body chunkLazyCallBody
  simp only [map_register_0, map_register_1, map_register_2, map_register_3, map_register_4,
    map_register_5, map_register_6, map_register_7, map_register_8, map_register_9,
    x64_expand.mov64, lift, bind_tc_ok, bind_assoc_eq]
  emit_chain

theorem lazyLocalCall_emits (cfg : x64_ir.Cfg) (id label : Std.U32) :
    EmitsL (x64_expand.expand_lazy_local_call cfg id label)
      (chunkLazyLocalCall cfg id label.val).1 (chunkLazyLocalCall cfg id label.val).2 := by
  unfold x64_expand.expand_lazy_local_call chunkLazyLocalCall
  refine EmitsL.bindPre (fun done1 hd => ?_)
  have hdv : done1 = u32 (label.val + 1) := u32_eq_of_val (by rw [u32_add_eq hd]; rfl)
  subst hdv
  simp only [x64_expand.mov64, x64_expand.load64, u32_val, lift, bind_tc_ok, bind_assoc_eq,
    List.append_assoc, List.nil_append, List.cons_append, List.singleton_append]
  repeat first
    | exact EmitsL.tail_add rfl
    | refine EmitsL.seq (lazyCallBody_emits _ _) ?_
    | refine EmitsL.push ?_

/-! ## One macro at a time -/

/-- Whether a macro is the retpoline. -/
def isRetpoline : x64_ir.MInsn → Bool
  | .Retpoline => true
  | _ => false

/-- `starts_trailer code i`: the macro after `i` is the retpoline. -/
def trailerAt (code : List x64_ir.MInsn) (i : Nat) : Bool :=
  match code[i + 1]? with
  | some m => isRetpoline m
  | none => false

/-- The same test read off the tail of a list. -/
def headTrailer (rest : List x64_ir.MInsn) : Bool :=
  match rest.head? with
  | some m => isRetpoline m
  | none => false

theorem slice_index_ok {α : Type} {v : Slice α} {i : Std.Usize} (hi : i.val < v.length) :
    Slice.index_usize v i = ok v.val[i.val] := by
  unfold Slice.index_usize
  rw [Slice.getElem?_Usize_eq, List.getElem?_eq_getElem hi]

theorem starts_trailer_eq {code : Slice x64_ir.MInsn} {i : Std.Usize} {b : Bool}
    (h : x64_expand.starts_trailer code i = ok b) : b = trailerAt code.val i.val := by
  unfold x64_expand.starts_trailer trailerAt at *
  have hcl : code.length = code.val.length := rfl
  obtain ⟨i1, hi1, h⟩ := bind_eq_ok h
  have hi1v : i1.val = i.val + 1 := by
    rw [uscalar_add_eq hi1]; have : (1#usize : Std.Usize).val = 1 := by decide
    omega
  split at h
  · rename_i hge
    simp only [ok.injEq] at h; subst h
    simp only [ge_iff_le, UScalar.le_equiv, Slice.len_val] at hge
    rw [List.getElem?_eq_none (by omega)]
  · rename_i hlt
    simp only [ge_iff_le, UScalar.le_equiv, Slice.len_val, not_le] at hlt
    obtain ⟨nxt, hn, h⟩ := bind_eq_ok h
    obtain ⟨_, hnv⟩ := index_usize_eq_ok hn
    rw [List.getElem?_eq_getElem (by omega)]
    rw [show code.val[i.val + 1] = nxt from by rw [hnv]; congr 1; omega]
    cases nxt <;> simp only [ok.injEq, isRetpoline] at h ⊢ <;> exact h.symm

theorem primitive_target_eq (t : x64_ir.Target) :
    x64_expand.primitive_target t = ok (ptargetOf t) := by
  cases t <;> rfl

/-- The chunk one macro expands to, read off `expand_one`. -/
theorem expand_one_emits (cfg : x64_ir.Cfg) (code : Slice x64_ir.MInsn) (i : Std.Usize)
    (label : Std.U32) (m : x64_ir.MInsn) (hm : Slice.index_usize code i = ok m) :
    EmitsL (x64_expand.expand_one cfg code i label)
      (chunk cfg m (trailerAt code.val i.val) label.val).1
      (chunk cfg m (trailerAt code.val i.val) label.val).2 := by
  unfold x64_expand.expand_one chunk
  rw [hm]
  simp only [bind_tc_ok]
  cases m <;>
    simp only [x64_expand.load64, x64_expand.mov64, x64_expand.add_rsp_8,
      primitive_target_eq, lift, bind_tc_ok, bind_assoc_eq,
      List.append_assoc, List.nil_append, List.cons_append, List.singleton_append] <;>
    first
      | exact EmitsL.done (Emits.last _) rfl
      | exact prologue_emits _ _ _
      | exact muldivmod_emits _ _ _ _ _ _ _ _
      | exact EmitsL.done (guestFp_emits _) rfl
      | exact EmitsL.done (checkedAddr_emits _ _ _ _ _ _ _) rfl
      | exact atomicFetchAlu_emits _ _ _ _ _ _
      | exact helperCall_emits _ _
      | exact lazyLocalCall_emits _ _ _
      | exact retpoline_emits _
      | (refine EmitsL.bindPre (fun tr htr => ?_)
         have htv := starts_trailer_eq htr
         subst htv
         split_ifs <;>
           (try simp only [bind_tc_ok, List.nil_append, List.cons_append]) <;>
           (repeat first
             | exact EmitsL.done (Emits.last _) rfl
             | refine EmitsL.push ?_))

/-- `expand_one` appends the macro's chunk and returns the chunk's next label. -/
theorem expand_one_spec {cfg : x64_ir.Cfg} {code : Slice x64_ir.MInsn} {i : Std.Usize}
    {label label' : Std.U32} {out out' : VecP} (hi : i.val < code.length)
    (h : x64_expand.expand_one cfg code i label out = ok (label', out')) :
    out'.val = out.val ++ (chunk cfg code.val[i.val] (trailerAt code.val i.val) label.val).1 ∧
    label'.val = (chunk cfg code.val[i.val] (trailerAt code.val i.val) label.val).2 :=
  expand_one_emits cfg code i label _ (slice_index_ok hi) out label' out' h

/-! ## The whole list -/

/-- The expansion of a whole macro list from a starting label: the chunks
concatenated, and the next free label. -/
def expandList (cfg : x64_ir.Cfg) : List x64_ir.MInsn → Nat → List x64_ir.PInsn × Nat
  | [], label => ([], label)
  | m :: rest, label =>
    ((chunk cfg m (headTrailer rest) label).1 ++
       (expandList cfg rest (chunk cfg m (headTrailer rest) label).2).1,
     (expandList cfg rest (chunk cfg m (headTrailer rest) label).2).2)

/-- What `expand` appends: every chunk, from label `0`. -/
def flat (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) : List x64_ir.PInsn :=
  (expandList cfg code 0).1

/-- The offset of, and the label counter before, chunk `i`. -/
def prefixState (cfg : x64_ir.Cfg) : List x64_ir.MInsn → Nat → Nat → Nat × Nat
  | _, label, 0 => (0, label)
  | [], label, _ + 1 => (0, label)
  | m :: rest, label, i + 1 =>
    ((chunk cfg m (headTrailer rest) label).1.length +
       (prefixState cfg rest (chunk cfg m (headTrailer rest) label).2 i).1,
     (prefixState cfg rest (chunk cfg m (headTrailer rest) label).2 i).2)

/-- Where chunk `i` starts in `flat`. -/
def chunkStart (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) : Nat :=
  (prefixState cfg code 0 i).1

/-- The local-label counter as chunk `i` starts. -/
def labelBase (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) : Nat :=
  (prefixState cfg code 0 i).2

/-- Chunk `i` itself; `([], labelBase)` past the end. -/
def chunkAt (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) :
    List x64_ir.PInsn × Nat :=
  match code[i]? with
  | some m => chunk cfg m (trailerAt code i) (labelBase cfg code i)
  | none => ([], labelBase cfg code i)

/-- How long chunk `i` is. -/
def chunkLen (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) : Nat :=
  (chunkAt cfg code i).1.length

theorem chunkAt_eq {cfg : x64_ir.Cfg} {code : List x64_ir.MInsn} {i : Nat} {m : x64_ir.MInsn}
    (hm : code[i]? = some m) :
    chunkAt cfg code i = chunk cfg m (trailerAt code i) (labelBase cfg code i) := by
  unfold chunkAt; rw [hm]

theorem trailerAt_cons (m : x64_ir.MInsn) (rest : List x64_ir.MInsn) :
    trailerAt (m :: rest) 0 = headTrailer rest := by
  unfold trailerAt headTrailer; cases rest <;> rfl

theorem trailerAt_cons_succ (m : x64_ir.MInsn) (rest : List x64_ir.MInsn) (i : Nat) :
    trailerAt (m :: rest) (i + 1) = trailerAt rest i := rfl

theorem headTrailer_drop (code : List x64_ir.MInsn) (i : Nat) :
    headTrailer (code.drop (i + 1)) = trailerAt code i := by
  unfold headTrailer trailerAt
  rw [List.head?_eq_getElem?, List.getElem?_drop]

theorem drop_append_len {α : Type} (l₁ l₂ : List α) (n : Nat) :
    (l₁ ++ l₂).drop (l₁.length + n) = l₂.drop n := by
  induction l₁ with
  | nil => simp
  | cons a t ih => simp [ih]

/-- The flat list past the first `i` chunks is the expansion of the rest. -/
theorem expandList_drop (cfg : x64_ir.Cfg) (i : Nat) :
    ∀ (code : List x64_ir.MInsn) (label : Nat),
      (expandList cfg code label).1.drop (prefixState cfg code label i).1
        = (expandList cfg (code.drop i) (prefixState cfg code label i).2).1 := by
  induction i with
  | zero => intro code label; simp [prefixState]
  | succ i ih =>
    intro code label
    cases code with
    | nil => simp [prefixState, expandList]
    | cons m rest =>
      simp only [prefixState, expandList, List.drop_succ_cons]
      rw [drop_append_len]
      exact ih rest _

theorem prefixState_succ (cfg : x64_ir.Cfg) (i : Nat) :
    ∀ (code : List x64_ir.MInsn) (label : Nat) (mi : x64_ir.MInsn), code[i]? = some mi →
      prefixState cfg code label (i + 1) =
        ((prefixState cfg code label i).1
           + (chunk cfg mi (trailerAt code i) (prefixState cfg code label i).2).1.length,
         (chunk cfg mi (trailerAt code i) (prefixState cfg code label i).2).2) := by
  induction i with
  | zero =>
    intro code label mi hm
    cases code with
    | nil => simp at hm
    | cons m rest =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at hm
      subst hm
      simp [prefixState, trailerAt_cons]
  | succ i ih =>
    intro code label mi hm
    cases code with
    | nil => simp at hm
    | cons m rest =>
      simp only [List.getElem?_cons_succ] at hm
      simp only [prefixState, trailerAt_cons_succ, ih rest _ mi hm]
      simp [Nat.add_assoc]

theorem prefixState_succ_none (cfg : x64_ir.Cfg) (i : Nat) :
    ∀ (code : List x64_ir.MInsn) (label : Nat), code[i]? = none →
      prefixState cfg code label (i + 1) = prefixState cfg code label i := by
  induction i with
  | zero =>
    intro code label hm
    cases code with
    | nil => simp [prefixState]
    | cons m rest => simp at hm
  | succ i ih =>
    intro code label hm
    cases code with
    | nil => simp [prefixState]
    | cons m rest =>
      simp only [List.getElem?_cons_succ] at hm
      simp only [prefixState, ih rest _ hm]

/-- Chunk `i + 1` starts where chunk `i` ends, and inherits its label. -/
theorem chunkStart_succ (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) :
    chunkStart cfg code (i + 1) = chunkStart cfg code i + chunkLen cfg code i ∧
    labelBase cfg code (i + 1) = (chunkAt cfg code i).2 := by
  cases hm : code[i]? with
  | none =>
    have h := prefixState_succ_none cfg i code 0 hm
    have hc : chunkAt cfg code i = ([], labelBase cfg code i) := by unfold chunkAt; rw [hm]
    refine ⟨?_, ?_⟩
    · show (prefixState cfg code 0 (i + 1)).1
        = (prefixState cfg code 0 i).1 + (chunkAt cfg code i).1.length
      rw [h, hc]; simp
    · show (prefixState cfg code 0 (i + 1)).2 = (chunkAt cfg code i).2
      rw [h, hc]; rfl
  | some mi =>
    have h := prefixState_succ cfg i code 0 mi hm
    have hc : chunkAt cfg code i = chunk cfg mi (trailerAt code i) (labelBase cfg code i) :=
      chunkAt_eq hm
    refine ⟨?_, ?_⟩
    · show (prefixState cfg code 0 (i + 1)).1
        = (prefixState cfg code 0 i).1 + (chunkAt cfg code i).1.length
      rw [h, hc]; rfl
    · show (prefixState cfg code 0 (i + 1)).2 = (chunkAt cfg code i).2
      rw [h, hc]; rfl

theorem chunkStart_step (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) :
    chunkStart cfg code (i + 1) = chunkStart cfg code i + chunkLen cfg code i :=
  (chunkStart_succ cfg code i).1

theorem labelBase_succ (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) :
    labelBase cfg code (i + 1) = (chunkAt cfg code i).2 :=
  (chunkStart_succ cfg code i).2

/-- Chunk starts are monotone. -/
theorem chunkStart_mono (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) {i j : Nat} (h : i ≤ j) :
    chunkStart cfg code i ≤ chunkStart cfg code j := by
  induction j with
  | zero => simp_all
  | succ j ih =>
    rcases Nat.lt_or_ge i (j + 1) with hlt | hge
    · have := ih (by omega)
      rw [chunkStart_step]; omega
    · have : i = j + 1 := by omega
      subst this; exact le_refl _

theorem prefixState_length (cfg : x64_ir.Cfg) :
    ∀ (code : List x64_ir.MInsn) (label : Nat),
      (prefixState cfg code label code.length).1 = (expandList cfg code label).1.length := by
  intro code
  induction code with
  | nil => intro label; simp [prefixState, expandList]
  | cons m rest ih =>
    intro label
    simp only [List.length_cons, prefixState, expandList, List.length_append, ih]

/-- The chunk starts exhaust the flat list. -/
theorem chunkStart_last (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) :
    chunkStart cfg code code.length = (flat cfg code).length :=
  prefixState_length cfg code 0

/-- The flat list, from chunk `i` on, is chunk `i` followed by the rest. -/
theorem chunk_at (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    (hi : i < code.length) :
    (flat cfg code).drop (chunkStart cfg code i)
      = (chunkAt cfg code i).1 ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) := by
  have hm : code[i]? = some code[i] := List.getElem?_eq_getElem hi
  have hps := prefixState_succ cfg i code 0 code[i] hm
  unfold flat chunkStart
  rw [expandList_drop cfg i code 0, expandList_drop cfg (i + 1) code 0,
    List.drop_eq_getElem_cons hi, hps]
  simp only [expandList, headTrailer_drop, chunkAt_eq hm, labelBase]

/-- Indexing inside chunk `i`. -/
theorem flat_get (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i k : Nat)
    (hk : k < chunkLen cfg code i) :
    (flat cfg code)[chunkStart cfg code i + k]? = (chunkAt cfg code i).1[k]? := by
  have hi : i < code.length := by
    by_contra hc
    have : code[i]? = none := List.getElem?_eq_none (by omega)
    unfold chunkLen chunkAt at hk; rw [this] at hk; simp at hk
  have := chunk_at cfg code i hi
  rw [← List.getElem?_drop, this, List.getElem?_append_left hk]

/-! ## `expand` -/

/-- The loop invariant of `expand`, one step on. -/
def ExpandPost (cfg : x64_ir.Cfg) (code : Slice x64_ir.MInsn) (out : VecP) :
    ControlFlow (VecP × Std.U32 × Std.Usize) VecP → Prop
  | .cont x => x.1.val ++ (expandList cfg (code.val.drop x.2.2.val) x.2.1.val).1
      = out.val ++ flat cfg code.val
  | .done y => y.val = out.val ++ flat cfg code.val

theorem expand_step (cfg : x64_ir.Cfg) (code : Slice x64_ir.MInsn) (out out1 : VecP)
    (label1 : Std.U32) (i1 : Std.Usize)
    (hinv : out1.val ++ (expandList cfg (code.val.drop i1.val) label1.val).1
      = out.val ++ flat cfg code.val)
    (res : ControlFlow (VecP × Std.U32 × Std.Usize) VecP)
    (hb : x64_expand.expand_loop.body cfg code out1 label1 i1 = ok res) :
    ExpandPost cfg code out res := by
  have hcl : code.length = code.val.length := rfl
  unfold x64_expand.expand_loop.body at hb
  dsimp only at hb
  split at hb
  · rename_i hlt
    simp only [UScalar.lt_equiv, Slice.len_val] at hlt
    have hi1 : i1.val < code.length := by omega
    obtain ⟨p, hp, hb⟩ := bind_eq_ok hb
    obtain ⟨i2, hi2, hb⟩ := bind_eq_ok hb
    simp only [ok.injEq] at hb
    subst hb
    obtain ⟨label2, out2⟩ := p
    obtain ⟨hout, hlab⟩ := expand_one_spec hi1 hp
    have hi2v : i2.val = i1.val + 1 := by
      rw [uscalar_add_eq hi2]
      have : (1#usize : Std.Usize).val = 1 := by decide
      omega
    show out2.val ++ (expandList cfg (code.val.drop i2.val) label2.val).1
      = out.val ++ flat cfg code.val
    have hdc : code.val.drop i1.val = code.val[i1.val] :: code.val.drop (i1.val + 1) :=
      List.drop_eq_getElem_cons (by omega)
    rw [hout, hlab, hi2v, ← hinv, hdc]
    simp only [expandList, headTrailer_drop, List.append_assoc]
  · rename_i hge
    simp only [ok.injEq] at hb
    subst hb
    simp only [UScalar.lt_equiv, Slice.len_val, not_lt] at hge
    show out1.val = out.val ++ flat cfg code.val
    have hnil : code.val.drop i1.val = [] := List.drop_eq_nil_of_le (by omega)
    rw [hnil] at hinv
    simp only [expandList, List.append_nil] at hinv
    exact hinv

/-- `expand` appends every chunk, in order, from label `0`. -/
theorem expand_spec {cfg : x64_ir.Cfg} {code : Slice x64_ir.MInsn} {out out' : VecP}
    (h : x64_expand.expand cfg code out = ok out') :
    out'.val = out.val ++ flat cfg code.val := by
  unfold x64_expand.expand x64_expand.expand_loop at h
  refine loop_ok_induction _
    (fun x : VecP × Std.U32 × Std.Usize =>
      x.1.val ++ (expandList cfg (code.val.drop x.2.2.val) x.2.1.val).1
        = out.val ++ flat cfg code.val)
    (fun y : VecP => y.val = out.val ++ flat cfg code.val)
    ?_ _ _ (by simp [flat]) h
  rintro ⟨out1, label1, i1⟩ hinv res hb
  have hs := expand_step cfg code out out1 label1 i1 hinv res hb
  cases res <;> exact hs

/-! ## Labels

`pos` is the first primitive that is the label a target names, so resolving a
label is: nothing before chunk `i` matches, nothing inside chunk `i` before
offset `k` matches, and the primitive at offset `k` does. -/

theorem findIdx?_eq_some_of {α : Type} {p : α → Bool} :
    ∀ (n : Nat) (l : List α),
      (∀ j, j < n → ∀ x, l[j]? = some x → p x = false) →
      (∀ x, l[n]? = some x → p x = true) →
      (∃ x, l[n]? = some x) → l.findIdx? p = some n := by
  intro n
  induction n with
  | zero =>
    intro l _ hhit hex
    obtain ⟨x, hx⟩ := hex
    cases l with
    | nil => simp at hx
    | cons a t =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at hx
      subst hx
      rw [List.findIdx?_cons, if_pos (hhit a (by simp))]
  | succ n ih =>
    intro l hbefore hhit hex
    obtain ⟨x, hx⟩ := hex
    cases l with
    | nil => simp at hx
    | cons a t =>
      have ha : p a = false := hbefore 0 (by omega) a (by simp)
      rw [List.findIdx?_cons, if_neg (by simp [ha])]
      rw [ih t (fun j hj y hy => hbefore (j + 1) (by omega) y (by simpa using hy))
        (fun y hy => hhit y (by simpa using hy)) ⟨x, by simpa using hx⟩]
      rfl

/-- Every position before chunk `i` is a position inside an earlier chunk. -/
theorem flat_lookup_lt (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) :
    ∀ j < chunkStart cfg code i, ∃ j' k, j' < i ∧ k < chunkLen cfg code j' ∧
      (flat cfg code)[j]? = (chunkAt cfg code j').1[k]? := by
  induction i with
  | zero => intro j hj; simp [chunkStart, prefixState] at hj
  | succ i ih =>
    intro j hj
    rw [chunkStart_step] at hj
    rcases Nat.lt_or_ge j (chunkStart cfg code i) with hlt | hge
    · obtain ⟨j', k, h1, h2, h3⟩ := ih j hlt
      exact ⟨j', k, by omega, h2, h3⟩
    · refine ⟨i, j - chunkStart cfg code i, by omega, by omega, ?_⟩
      have := flat_get cfg code i (j - chunkStart cfg code i) (by omega)
      rw [show chunkStart cfg code i + (j - chunkStart cfg code i) = j from by omega] at this
      exact this

/-- `pos` resolves to chunk `i` offset `k` when nothing earlier is that label. -/
theorem pos_chunk (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (t : x64_ir.PTarget)
    (i k : Nat) (hk : k < chunkLen cfg code i)
    (hbefore : ∀ j, j < i → ∀ x ∈ (chunkAt cfg code j).1, isTarget t x = false)
    (hin : ∀ j, j < k → ∀ x, (chunkAt cfg code i).1[j]? = some x → isTarget t x = false)
    (hhit : ∀ x, (chunkAt cfg code i).1[k]? = some x → isTarget t x = true) :
    pos (flat cfg code) t = some (chunkStart cfg code i + k) := by
  unfold pos
  refine findIdx?_eq_some_of _ _ ?_ ?_ ?_
  · intro j hj x hx
    rcases Nat.lt_or_ge j (chunkStart cfg code i) with hlt | hge
    · obtain ⟨j', k', h1, h2, h3⟩ := flat_lookup_lt cfg code i j hlt
      rw [h3] at hx
      exact hbefore j' h1 x (List.mem_of_getElem? hx)
    · have hj' : j - chunkStart cfg code i < k := by omega
      have := flat_get cfg code i (j - chunkStart cfg code i) (by omega)
      rw [show chunkStart cfg code i + (j - chunkStart cfg code i) = j from by omega] at this
      rw [this] at hx
      exact hin _ hj' x hx
  · intro x hx
    rw [flat_get cfg code i k hk] at hx
    exact hhit x hx
  · rw [flat_get cfg code i k hk]
    exact ⟨_, List.getElem?_eq_getElem hk⟩

/-! ## What a chunk's labels are -/

/-- A primitive that is not a label. -/
def notLabelB : x64_ir.PInsn → Bool
  | .PcLabel _ => false
  | .ExitLabel => false
  | .RetpolineLabel => false
  | .Local _ => false
  | .DispatcherSlot _ => false
  | _ => true

/-- The label primitives of a chunk, in order. -/
def labelsOf (L : List x64_ir.PInsn) : List x64_ir.PInsn := L.filter (fun x => !notLabelB x)

theorem labelsOf_append (a b : List x64_ir.PInsn) :
    labelsOf (a ++ b) = labelsOf a ++ labelsOf b := List.filter_append a b

theorem mem_labelsOf {x : x64_ir.PInsn} {L : List x64_ir.PInsn} (h : x ∈ L)
    (hx : notLabelB x = false) : x ∈ labelsOf L := by
  simp only [labelsOf, List.mem_filter, hx]
  exact ⟨h, by simp⟩

theorem labelsOf_nil_iff {L : List x64_ir.PInsn} :
    labelsOf L = [] ↔ ∀ x ∈ L, notLabelB x = true := by
  simp [labelsOf, List.filter_eq_nil_iff]

theorem labelsOf_guestFp (dst : Std.U8) : labelsOf (chunkGuestFp dst) = [] := rfl

theorem notLabel_guestFp (dst : Std.U8) : ∀ x ∈ chunkGuestFp dst, notLabelB x = true :=
  labelsOf_nil_iff.mp (labelsOf_guestFp dst)

theorem labelsOf_regionFromFrame (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    labelsOf (chunkRegionFromFrame dst scratch size stack) = [] := by
  unfold labelsOf chunkRegionFromFrame
  split <;> rfl

theorem labelsOf_regionViaDescriptor (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    labelsOf (chunkRegionViaDescriptor dst scratch size stack) = [] := by
  unfold labelsOf chunkRegionViaDescriptor
  split <;> rfl

theorem labelsOf_region (cfg : x64_ir.Cfg) (dst scratch : Std.U8) (size : Std.U32) (stack : Bool) :
    labelsOf (chunkRegion cfg dst scratch size stack) = [] := by
  unfold chunkRegion
  split
  · exact labelsOf_regionFromFrame _ _ _ _
  · exact labelsOf_regionViaDescriptor _ _ _ _

theorem notLabel_region (cfg : x64_ir.Cfg) (dst scratch : Std.U8) (size : Std.U32)
    (stack : Bool) : ∀ x ∈ chunkRegion cfg dst scratch size stack, notLabelB x = true :=
  labelsOf_nil_iff.mp (labelsOf_region cfg dst scratch size stack)

theorem labelsOf_checkedAddr (cfg : x64_ir.Cfg) (src dst scratch : Std.U8) (offset : Std.I32)
    (size : Std.U32) (hint : Std.U8) :
    labelsOf (chunkCheckedAddr cfg src dst scratch offset size hint) = [] := by
  unfold chunkCheckedAddr
  split_ifs <;>
    simp only [labelsOf_append, labelsOf_guestFp, labelsOf_region, List.append_nil,
      List.nil_append] <;>
    rfl

theorem labelsOf_muldivSetup (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) :
    labelsOf (chunkMulDivSetup kind w64 reg signed src dst imm) = [] := by
  unfold chunkMulDivSetup
  split_ifs <;> simp only [labelsOf_append, List.append_nil, List.nil_append] <;> rfl

theorem labelsOf_muldivFinish (kind : x64_ir.MulDivKind) (dst : Std.U8) :
    labelsOf (chunkMulDivFinish kind dst) = [] := by
  unfold chunkMulDivFinish
  split_ifs <;> simp only [labelsOf_append, List.append_nil, List.nil_append] <;> rfl

theorem labelsOf_lazyCallBody (cfg : x64_ir.Cfg) (id : Std.U32) :
    labelsOf (chunkLazyCallBody cfg id) = [] := rfl

theorem labelsOf_helperScrub : labelsOf helperScrub = [] := rfl

theorem labelsOf_muldivOverflow (w64 div : Bool) (noOv after : Nat) :
    labelsOf (chunkMulDivOverflow w64 div noOv after) = [x64_ir.PInsn.Local (u32 noOv)] := by
  unfold chunkMulDivOverflow
  split_ifs <;> simp only [labelsOf_append, List.append_nil, List.nil_append] <;> rfl

/-- The label primitives one macro emits, and nothing else. -/
def chunkLabels (cfg : x64_ir.Cfg) (m : x64_ir.MInsn) (tr : Bool) (l : Nat) :
    List x64_ir.PInsn :=
  match m with
  | .PcLabel pc => [ .PcLabel pc ]
  | .Prologue _ skip => if skip then [ .Local (u32 l) ] else []
  | .Epilogue => if tr then [ .ExitLabel ] else []
  | .MulDivMod kind _ reg signed _ _ imm =>
    if reg then
      (if (isDiv kind || isMod kind) && signed then
         [ .Local (u32 l), .Local (u32 (l + 1)) ] else [])
    else if imm = 0#i32 then []
    else
      (if (isDiv kind || isMod kind) && signed then
         [ .Local (u32 l), .Local (u32 (l + 1)) ] else [])
  | .AtomicFetchAlu _ _ _ _ _ => [ .Local (u32 l) ]
  | .HelperCall _ => [ .Local (u32 l), .Local (u32 (l + 1)) ]
  | .LazyLocalCall _ => [ .Local (u32 l), .Local (u32 (l + 1)) ]
  | .Retpoline => [ .RetpolineLabel, .Local (u32 (l + 1)), .Local (u32 l) ]
  | .DispatcherSlot => [ .DispatcherSlot cfg.dispatcher ]
  | _ => []

theorem labelsOf_chunk (cfg : x64_ir.Cfg) (m : x64_ir.MInsn) (tr : Bool) (l : Nat) :
    labelsOf (chunk cfg m tr l).1 = chunkLabels cfg m tr l := by
  cases m <;>
    simp only [chunk, chunkLabels, chunkPrologue, chunkMulDivMod, chunkAtomicFetchAlu,
      chunkHelperCall, chunkLazyLocalCall, chunkRetpoline, apply_ite Prod.fst] <;>
    (try split_ifs) <;>
    (try simp only [labelsOf_append, labelsOf_guestFp, labelsOf_checkedAddr,
      labelsOf_muldivSetup, labelsOf_muldivFinish, labelsOf_muldivOverflow,
      labelsOf_lazyCallBody, labelsOf_helperScrub, List.append_nil, List.nil_append]) <;>
    rfl

theorem u32_eq_iff {a b : Std.U32} : a.val = b.val ↔ a = b :=
  ⟨fun h => by rw [← u32_val a, ← u32_val b, h], fun h => by rw [h]⟩

theorem isTarget_pc_iff (n : Std.U32) (x : x64_ir.PInsn) :
    isTarget (.Pc n) x = true ↔ x = .PcLabel n := by
  cases x <;> simp [isTarget, eq_comm, u32_eq_iff]

theorem isTarget_exit_iff (x : x64_ir.PInsn) : isTarget .Exit x = true ↔ x = .ExitLabel := by
  cases x <;> simp [isTarget]

theorem isTarget_retpoline_iff (x : x64_ir.PInsn) :
    isTarget .Retpoline x = true ↔ x = .RetpolineLabel := by
  cases x <;> simp [isTarget]

theorem isTarget_local_iff (n : Std.U32) (x : x64_ir.PInsn) :
    isTarget (.Local n) x = true ↔ x = .Local n := by
  cases x <;> simp [isTarget, eq_comm, u32_eq_iff]

/-- A `PcLabel` primitive comes only from a `PcLabel` macro. -/
theorem chunk_pcLabel {cfg : x64_ir.Cfg} {m : x64_ir.MInsn} {tr : Bool} {l : Nat}
    {pc : Std.U32} (h : x64_ir.PInsn.PcLabel pc ∈ (chunk cfg m tr l).1) : m = .PcLabel pc := by
  have h' : x64_ir.PInsn.PcLabel pc ∈ chunkLabels cfg m tr l := by
    rw [← labelsOf_chunk]; exact mem_labelsOf h rfl
  cases m <;> simp only [chunkLabels] at h' <;> (try split_ifs at h') <;> simp_all

/-- An `ExitLabel` primitive comes only from a trailer epilogue. -/
theorem chunk_exitLabel {cfg : x64_ir.Cfg} {m : x64_ir.MInsn} {tr : Bool} {l : Nat}
    (h : x64_ir.PInsn.ExitLabel ∈ (chunk cfg m tr l).1) : m = .Epilogue ∧ tr = true := by
  have h' : x64_ir.PInsn.ExitLabel ∈ chunkLabels cfg m tr l := by
    rw [← labelsOf_chunk]; exact mem_labelsOf h rfl
  cases m <;> simp only [chunkLabels] at h' <;> (try split_ifs at h') <;> simp_all

/-- A `RetpolineLabel` primitive comes only from a `Retpoline` macro. -/
theorem chunk_retpolineLabel {cfg : x64_ir.Cfg} {m : x64_ir.MInsn} {tr : Bool} {l : Nat}
    (h : x64_ir.PInsn.RetpolineLabel ∈ (chunk cfg m tr l).1) : m = .Retpoline := by
  have h' : x64_ir.PInsn.RetpolineLabel ∈ chunkLabels cfg m tr l := by
    rw [← labelsOf_chunk]; exact mem_labelsOf h rfl
  cases m <;> simp only [chunkLabels] at h' <;> (try split_ifs at h') <;> simp_all

/-- A `DispatcherSlot` primitive comes only from a `DispatcherSlot` macro, and
carries the configured address. -/
theorem chunk_dispatcherSlot {cfg : x64_ir.Cfg} {m : x64_ir.MInsn} {tr : Bool} {l : Nat}
    {a : Std.U64} (h : x64_ir.PInsn.DispatcherSlot a ∈ (chunk cfg m tr l).1) :
    m = .DispatcherSlot ∧ a = cfg.dispatcher := by
  have h' : x64_ir.PInsn.DispatcherSlot a ∈ chunkLabels cfg m tr l := by
    rw [← labelsOf_chunk]; exact mem_labelsOf h rfl
  cases m <;> simp only [chunkLabels] at h' <;> (try split_ifs at h') <;> simp_all

/-- A chunk advances the local-label counter by at most two. -/
theorem chunkNext_bounds (cfg : x64_ir.Cfg) (m : x64_ir.MInsn) (tr : Bool) (l : Nat) :
    l ≤ (chunk cfg m tr l).2 ∧ (chunk cfg m tr l).2 ≤ l + 2 := by
  cases m <;>
    simp only [chunk, chunkPrologue, chunkMulDivMod, chunkAtomicFetchAlu, chunkHelperCall,
      chunkLazyLocalCall, chunkRetpoline, apply_ite Prod.snd] <;>
    (try split_ifs) <;> omega

/-- Every `Local` a chunk emits carries a label in `[l, next)`. -/
theorem chunk_locals {cfg : x64_ir.Cfg} {m : x64_ir.MInsn} {tr : Bool} {l : Nat}
    {q : Std.U32} (hb : (chunk cfg m tr l).2 < 2 ^ 32)
    (h : x64_ir.PInsn.Local q ∈ (chunk cfg m tr l).1) :
    l ≤ q.val ∧ q.val < (chunk cfg m tr l).2 := by
  have h' : x64_ir.PInsn.Local q ∈ chunkLabels cfg m tr l := by
    rw [← labelsOf_chunk]; exact mem_labelsOf h rfl
  clear h
  revert h' hb
  cases m <;>
    simp only [chunkLabels, chunk, chunkPrologue, chunkMulDivMod, chunkAtomicFetchAlu,
      chunkHelperCall, chunkLazyLocalCall, chunkRetpoline, apply_ite Prod.snd] <;>
    (try split_ifs) <;>
    intro hb h' <;>
    simp only [List.mem_cons, List.not_mem_nil, or_false, x64_ir.PInsn.Local.injEq,
      reduceCtorEq, false_or, or_false, or_self] at h' <;>
    (try rcases h' with rfl | rfl) <;>
    simp only [u32_val_eq, show (2:Nat) ^ 32 = 4294967296 from by norm_num] at hb ⊢ <;>
    omega

/-- Within one chunk no local label repeats. -/
theorem chunk_locals_nodup (cfg : x64_ir.Cfg) (m : x64_ir.MInsn) (tr : Bool) (l : Nat)
    (hb : (chunk cfg m tr l).2 < 2 ^ 32) : (labelsOf (chunk cfg m tr l).1).Nodup := by
  have hn := chunkNext_bounds cfg m tr l
  rw [labelsOf_chunk]
  revert hb hn
  cases m <;>
    simp only [chunkLabels, chunk, chunkPrologue, chunkMulDivMod, chunkAtomicFetchAlu,
      chunkHelperCall, chunkLazyLocalCall, chunkRetpoline, apply_ite Prod.snd] <;>
    (try split_ifs) <;>
    intro hb hn <;>
    simp_all [u32_val_eq, ← u32_eq_iff, show (2:Nat) ^ 32 = 4294967296 from by norm_num] <;>
    omega

/-- The label counter is monotone along the list. -/
theorem labelBase_mono (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) {i j : Nat} (h : i ≤ j) :
    labelBase cfg code i ≤ labelBase cfg code j := by
  induction j with
  | zero => simp_all
  | succ j ih =>
    rcases Nat.lt_or_ge i (j + 1) with hlt | hge
    · have h1 := ih (by omega)
      rw [labelBase_succ]
      unfold chunkAt
      cases hm : code[j]? with
      | none => simpa using h1
      | some mj =>
        have := (chunkNext_bounds cfg mj (trailerAt code j) (labelBase cfg code j)).1
        simp only []
        omega
    · have : i = j + 1 := by omega
      subst this; exact le_refl _

/-! ## Resolving the four kinds of label -/

theorem chunkAt_none {cfg : x64_ir.Cfg} {code : List x64_ir.MInsn} {j : Nat}
    (h : code[j]? = none) : (chunkAt cfg code j).1 = [] := by
  unfold chunkAt; rw [h]

/-- The `PcLabel` of the first `PcLabel n` macro is where `.Pc n` resolves. -/
theorem pos_pc (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) (n : Std.U32)
    (hbefore : ∀ j, j < i → code[j]? ≠ some (.PcLabel n))
    (hi : code[i]? = some (.PcLabel n)) :
    pos (flat cfg code) (.Pc n) = some (chunkStart cfg code i) := by
  have hc : chunkAt cfg code i = ([x64_ir.PInsn.PcLabel n], labelBase cfg code i) := by
    rw [chunkAt_eq hi]; rfl
  have := pos_chunk cfg code (.Pc n) i 0 (by simp [chunkLen, hc])
    (by
      intro j hj x hx
      by_contra hcon
      simp only [Bool.not_eq_false] at hcon
      rw [isTarget_pc_iff] at hcon
      subst hcon
      cases hm : code[j]? with
      | none => rw [chunkAt_none hm] at hx; simp at hx
      | some mj =>
        rw [chunkAt_eq hm] at hx
        exact hbefore j hj (by rw [hm, chunk_pcLabel hx]))
    (by intro j hj; exact absurd hj (Nat.not_lt_zero j))
    (by intro x hx; rw [hc] at hx; simp at hx; subst hx; rw [isTarget_pc_iff])
  simpa using this

/-- The trailer epilogue's `ExitLabel` is where `.Exit` resolves. -/
theorem pos_exit (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (t : Nat)
    (ht : code[t]? = some .Epilogue) (ht1 : code[t + 1]? = some .Retpoline)
    (hbefore : ∀ j, j < t → ¬(code[j]? = some .Epilogue ∧ trailerAt code j = true)) :
    pos (flat cfg code) .Exit = some (chunkStart cfg code t) := by
  have htr : trailerAt code t = true := by unfold trailerAt; rw [ht1]; rfl
  have hc : (chunkAt cfg code t).1 = x64_ir.PInsn.ExitLabel ::
      [x64_ir.PInsn.AluImm true .Add x64_ir.RSP 8#i32, x64_ir.PInsn.Ret] := by
    rw [chunkAt_eq ht]; simp [chunk, htr]
  have := pos_chunk cfg code .Exit t 0 (by simp [chunkLen, hc])
    (by
      intro j hj x hx
      by_contra hcon
      simp only [Bool.not_eq_false] at hcon
      rw [isTarget_exit_iff] at hcon
      subst hcon
      cases hm : code[j]? with
      | none => rw [chunkAt_none hm] at hx; simp at hx
      | some mj =>
        rw [chunkAt_eq hm] at hx
        obtain ⟨h1, h2⟩ := chunk_exitLabel hx
        exact hbefore j hj ⟨by rw [hm, h1], h2⟩)
    (by intro j hj; exact absurd hj (Nat.not_lt_zero j))
    (by intro x hx; rw [hc] at hx; simp at hx; subst hx; rw [isTarget_exit_iff])
  simpa using this

/-- The first `Retpoline` macro's `RetpolineLabel` is where `.Retpoline` resolves. -/
theorem pos_retpoline (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (t : Nat)
    (ht : code[t]? = some .Retpoline)
    (hbefore : ∀ j, j < t → code[j]? ≠ some .Retpoline) :
    pos (flat cfg code) .Retpoline = some (chunkStart cfg code t) := by
  have hc : (chunkAt cfg code t).1 = x64_ir.PInsn.RetpolineLabel ::
      (chunkRetpoline (labelBase cfg code t)).1.tail := by
    rw [chunkAt_eq ht]; rfl
  have := pos_chunk cfg code .Retpoline t 0 (by simp [chunkLen, hc, chunkRetpoline])
    (by
      intro j hj x hx
      by_contra hcon
      simp only [Bool.not_eq_false] at hcon
      rw [isTarget_retpoline_iff] at hcon
      subst hcon
      cases hm : code[j]? with
      | none => rw [chunkAt_none hm] at hx; simp at hx
      | some mj =>
        rw [chunkAt_eq hm] at hx
        exact hbefore j hj (by rw [hm, chunk_retpolineLabel hx]))
    (by intro j hj; exact absurd hj (Nat.not_lt_zero j))
    (by intro x hx; rw [hc] at hx; simp at hx; subst hx; rw [isTarget_retpoline_iff])
  simpa using this

/-- A local label resolves inside the chunk that emitted it. -/
theorem pos_local (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i k n : Nat)
    (hbound : labelBase cfg code (i + 1) < 2 ^ 32)
    (hk : k < chunkLen cfg code i)
    (hhit : (chunkAt cfg code i).1[k]? = some (.Local (u32 n)))
    (hfirst : ∀ j, j < k → (chunkAt cfg code i).1[j]? ≠ some (.Local (u32 n)))
    (hlo : labelBase cfg code i ≤ n) (hhi : n < labelBase cfg code (i + 1)) :
    pos (flat cfg code) (.Local (u32 n)) = some (chunkStart cfg code i + k) := by
  have hn32 : n < 2 ^ 32 := by omega
  have hnv : (u32 n).val = n := by rw [u32_val_eq]; exact Nat.mod_eq_of_lt hn32
  refine pos_chunk cfg code (.Local (u32 n)) i k hk ?_ ?_ ?_
  · intro j hj x hx
    by_contra hcon
    simp only [Bool.not_eq_false] at hcon
    rw [isTarget_local_iff] at hcon
    subst hcon
    cases hm : code[j]? with
    | none => rw [chunkAt_none hm] at hx; simp at hx
    | some mj =>
      rw [chunkAt_eq hm] at hx
      have hjb : (chunk cfg mj (trailerAt code j) (labelBase cfg code j)).2 < 2 ^ 32 := by
        have h1 : labelBase cfg code (j + 1) ≤ labelBase cfg code i :=
          labelBase_mono cfg code (by omega)
        have h2 : labelBase cfg code (j + 1)
            = (chunk cfg mj (trailerAt code j) (labelBase cfg code j)).2 := by
          rw [labelBase_succ, chunkAt_eq hm]
        omega
      obtain ⟨h1, h2⟩ := chunk_locals hjb hx
      have h3 : labelBase cfg code (j + 1)
          = (chunk cfg mj (trailerAt code j) (labelBase cfg code j)).2 := by
        rw [labelBase_succ, chunkAt_eq hm]
      have h4 : labelBase cfg code (j + 1) ≤ labelBase cfg code i :=
        labelBase_mono cfg code (by omega)
      rw [hnv] at h2
      omega
  · intro j hj x hx
    by_contra hcon
    simp only [Bool.not_eq_false] at hcon
    rw [isTarget_local_iff] at hcon
    subst hcon
    exact hfirst j hj hx
  · intro x hx
    rw [hhit] at hx
    simp only [Option.some.injEq] at hx
    subst hx
    rw [isTarget_local_iff]

/-! ## The dispatcher slot -/

theorem flat_mem {cfg : x64_ir.Cfg} {code : List x64_ir.MInsn} {x : x64_ir.PInsn}
    (h : x ∈ flat cfg code) : ∃ j, x ∈ (chunkAt cfg code j).1 := by
  obtain ⟨p, hp, rfl⟩ := List.getElem_of_mem h
  have hlt : p < chunkStart cfg code code.length := by
    rw [chunkStart_last]; exact hp
  obtain ⟨j, k, _, hk, hget⟩ := flat_lookup_lt cfg code code.length p hlt
  refine ⟨j, ?_⟩
  have : (flat cfg code)[p]? = some (flat cfg code)[p] := List.getElem?_eq_getElem hp
  rw [this] at hget
  exact List.mem_of_getElem? hget.symm

theorem dispSlot_of {y : x64_ir.PInsn}
    (hp : (match y with | .DispatcherSlot _ => true | _ => false) = true) :
    ∃ a, y = .DispatcherSlot a := by
  cases y <;> simp_all

/-- Every dispatcher slot in the flat list carries the configured address, so
the address the retpoline loads is that one whenever the trailer is there.
(No "first slot" side condition is needed: all of them agree.) -/
theorem dispatcherAddr_flat (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (t : Nat)
    (ht : code[t]? = some .DispatcherSlot) :
    dispatcherAddr (flat cfg code) = cfg.dispatcher.bv := by
  have hc : (chunkAt cfg code t).1 = [x64_ir.PInsn.DispatcherSlot cfg.dispatcher] := by
    rw [chunkAt_eq ht]; rfl
  have hmem : x64_ir.PInsn.DispatcherSlot cfg.dispatcher ∈ flat cfg code := by
    have hk : (0 : Nat) < chunkLen cfg code t := by simp [chunkLen, hc]
    have := flat_get cfg code t 0 hk
    rw [hc] at this
    simp only [List.getElem?_cons_zero] at this
    exact List.mem_of_getElem? this
  unfold dispatcherAddr
  cases hf : (flat cfg code).find?
      (fun i => match i with | .DispatcherSlot _ => true | _ => false) with
  | none =>
    rw [List.find?_eq_none] at hf
    have := hf _ hmem
    simp at this
  | some y =>
    have hy : y ∈ flat cfg code := List.mem_of_find?_eq_some hf
    have hp := List.find?_some hf
    obtain ⟨a, rfl⟩ := dispSlot_of hp
    obtain ⟨j, hj⟩ := flat_mem hy
    cases hm : code[j]? with
    | none => rw [chunkAt_none hm] at hj; simp at hj
    | some mj =>
      rw [chunkAt_eq hm] at hj
      rw [(chunk_dispatcherSlot hj).2]

/-- The same, as the natural number the configuration carries. -/
theorem dispatcherAddr_flat_ofNat (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (t : Nat)
    (ht : code[t]? = some .DispatcherSlot) :
    dispatcherAddr (flat cfg code) = BitVec.ofNat 64 cfg.dispatcher.val := by
  rw [dispatcherAddr_flat cfg code t ht]
  exact (BitVec.ofNat_toNat 64 cfg.dispatcher.bv).symm

/-! ## One lemma per macro

The shape a macro contract wants as a hypothesis: where the macro's chunk sits
in the flat list, how long it is, and what the counter does across it. The
single-primitive macros get the sharper `flat[chunkStart …]? = some …` form. -/

/-- The chunk of the macro at `i`, in place. -/
theorem flat_macro (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    (m : x64_ir.MInsn) (h : code[i]? = some m) :
    (flat cfg code).drop (chunkStart cfg code i)
        = (chunk cfg m (trailerAt code i) (labelBase cfg code i)).1
          ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) ∧
      chunkLen cfg code i = (chunk cfg m (trailerAt code i) (labelBase cfg code i)).1.length ∧
      labelBase cfg code (i + 1) = (chunk cfg m (trailerAt code i) (labelBase cfg code i)).2 := by
  have hi : i < code.length := by
    by_contra hc
    rw [List.getElem?_eq_none (by omega)] at h
    simp at h
  refine ⟨?_, ?_, ?_⟩
  · rw [chunk_at cfg code i hi, chunkAt_eq h]
  · unfold chunkLen; rw [chunkAt_eq h]
  · rw [labelBase_succ, chunkAt_eq h]

/-- A macro that expands to one primitive. -/
theorem flat_single (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    (m : x64_ir.MInsn) (x : x64_ir.PInsn) (h : code[i]? = some m)
    (hc : (chunk cfg m (trailerAt code i) (labelBase cfg code i)).1 = [x]) :
    (flat cfg code)[chunkStart cfg code i]? = some x ∧ chunkLen cfg code i = 1 := by
  obtain ⟨_, hlen, _⟩ := flat_macro cfg code i m h
  have hlen1 : chunkLen cfg code i = 1 := by rw [hlen, hc]; rfl
  refine ⟨?_, hlen1⟩
  have := flat_get cfg code i 0 (by omega)
  rw [chunkAt_eq h, hc] at this
  simpa using this

theorem flat_pcLabel (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) {pc : Std.U32}
    (h : code[i]? = some (.PcLabel pc)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.PcLabel pc) ∧ chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_alu (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {w64 : Bool} {op : x64_ir.AluRR} {src dst : Std.U8}
    (h : code[i]? = some (.Alu w64 op src dst)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.Alu w64 op src dst) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_aluImm (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {w64 : Bool} {op : x64_ir.AluRI} {dst : Std.U8} {imm : Std.I32}
    (h : code[i]? = some (.AluImm w64 op dst imm)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.AluImm w64 op dst imm) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_shiftImm (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {w64 : Bool} {op : x64_ir.ShiftOp} {dst : Std.U8} {imm : Std.I32}
    (h : code[i]? = some (.ShiftImm w64 op dst imm)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.ShiftImm w64 op dst imm) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_shiftCl (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {w64 : Bool} {op : x64_ir.ShiftOp} {dst : Std.U8}
    (h : code[i]? = some (.ShiftCl w64 op dst)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.ShiftCl w64 op dst) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_neg (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {w64 : Bool} {dst : Std.U8} (h : code[i]? = some (.Neg w64 dst)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.Neg w64 dst) ∧ chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_movSx (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {from_ : Std.U8} {w64 : Bool} {src dst : Std.U8}
    (h : code[i]? = some (.MovSx from_ w64 src dst)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.MovSx from_ w64 src dst) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_bswap (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {w64 : Bool} {dst : Std.U8} (h : code[i]? = some (.Bswap w64 dst)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.Bswap w64 dst) ∧ chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_rol16 (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) {dst : Std.U8}
    (h : code[i]? = some (.Rol16 dst)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.Rol16 dst) ∧ chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_loadImm (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {dst : Std.U8} {imm : Std.I64} (h : code[i]? = some (.LoadImm dst imm)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.LoadImm dst imm) ∧ chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_jcc (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {cc : Std.U8} {target : x64_ir.Target} (h : code[i]? = some (.Jcc cc target)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.Jcc cc (ptargetOf target)) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_jmp (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {target : x64_ir.Target} (h : code[i]? = some (.Jmp target)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.Jmp (ptargetOf target)) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_groupBaseStore (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {src : Std.U8} (h : code[i]? = some (.GroupBaseStore src)) :
    (flat cfg code)[chunkStart cfg code i]?
      = some (.Store 8#u8 src x64_ir.RBP x64_ir.frame.GROUP_BASE_OFFSET) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_groupBaseLoad (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {dst : Std.U8} (h : code[i]? = some (.GroupBaseLoad dst)) :
    (flat cfg code)[chunkStart cfg code i]?
      = some (.Load 8#u8 false x64_ir.RBP dst x64_ir.frame.GROUP_BASE_OFFSET) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_load (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {size : Std.U8} {sx : Bool} {base dst : Std.U8} {disp : Std.I32}
    (h : code[i]? = some (.Load size sx base dst disp)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.Load size sx base dst disp) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_store (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {size src base : Std.U8} {disp : Std.I32}
    (h : code[i]? = some (.Store size src base disp)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.Store size src base disp) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_storeImm (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {size base : Std.U8} {disp imm : Std.I32}
    (h : code[i]? = some (.StoreImm size base disp imm)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.StoreImm size base disp imm) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_atomicAlu (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {op : Std.U8} {w64 : Bool} {src base : Std.U8} {disp : Std.I32}
    (h : code[i]? = some (.AtomicAlu op w64 src base disp)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.LockAlu op w64 src base disp) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_atomicXchg (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {w64 : Bool} {src base : Std.U8} {disp : Std.I32}
    (h : code[i]? = some (.AtomicXchg w64 src base disp)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.Xchg w64 src base disp) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_atomicCmpxchg (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {w64 : Bool} {src base : Std.U8} {disp : Std.I32}
    (h : code[i]? = some (.AtomicCmpxchg w64 src base disp)) :
    (flat cfg code)[chunkStart cfg code i]? = some (.LockCmpxchg w64 src base disp) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

/-! The trailer's two data macros. -/

theorem flat_dispatcherSlot (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    (h : code[i]? = some .DispatcherSlot) :
    (flat cfg code)[chunkStart cfg code i]? = some (.DispatcherSlot cfg.dispatcher) ∧
    chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

theorem flat_helperTable (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    (h : code[i]? = some .HelperTable) :
    (flat cfg code)[chunkStart cfg code i]? = some .HelperTable ∧ chunkLen cfg code i = 1 :=
  flat_single cfg code i _ _ h rfl

/-! The multi-primitive macros, as the list their helper spells. -/

theorem flat_prologue (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {usage : Std.U16} {skip : Bool} (h : code[i]? = some (.Prologue usage skip)) :
    (flat cfg code).drop (chunkStart cfg code i)
        = (chunkPrologue usage skip (labelBase cfg code i)).1
          ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) ∧
      chunkLen cfg code i = (chunkPrologue usage skip (labelBase cfg code i)).1.length ∧
      labelBase cfg code (i + 1) = (chunkPrologue usage skip (labelBase cfg code i)).2 :=
  flat_macro cfg code i _ h

theorem flat_prologue_skip (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {usage : Std.U16} (h : code[i]? = some (.Prologue usage true)) :
    (flat cfg code).drop (chunkStart cfg code i)
        = [ .JmpNear (.Local (u32 (labelBase cfg code i))),
            .AluImm true .Sub x64_ir.RSP 8#i32,
            .StoreRspImm (Std.UScalar.cast .U32 usage),
            .Local (u32 (labelBase cfg code i)) ]
          ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) ∧
      chunkLen cfg code i = 4 ∧
      labelBase cfg code (i + 1) = labelBase cfg code i + 1 := by
  obtain ⟨h1, h2, h3⟩ := flat_prologue cfg code i h
  refine ⟨?_, ?_, ?_⟩ <;> simp_all [chunkPrologue]

theorem flat_prologue_plain (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {usage : Std.U16} (h : code[i]? = some (.Prologue usage false)) :
    (flat cfg code).drop (chunkStart cfg code i)
        = [ .AluImm true .Sub x64_ir.RSP 8#i32,
            .StoreRspImm (Std.UScalar.cast .U32 usage) ]
          ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) ∧
      chunkLen cfg code i = 2 ∧
      labelBase cfg code (i + 1) = labelBase cfg code i := by
  obtain ⟨h1, h2, h3⟩ := flat_prologue cfg code i h
  refine ⟨?_, ?_, ?_⟩ <;> simp_all [chunkPrologue]

theorem flat_epilogue_trailer (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (t : Nat)
    (ht : code[t]? = some .Epilogue) (ht1 : code[t + 1]? = some .Retpoline) :
    (flat cfg code).drop (chunkStart cfg code t)
        = [ .ExitLabel, .AluImm true .Add x64_ir.RSP 8#i32, .Ret ]
          ++ (flat cfg code).drop (chunkStart cfg code (t + 1)) ∧
      chunkLen cfg code t = 3 ∧ labelBase cfg code (t + 1) = labelBase cfg code t := by
  have htr : trailerAt code t = true := by unfold trailerAt; rw [ht1]; rfl
  obtain ⟨h1, h2, h3⟩ := flat_macro cfg code t _ ht
  rw [htr] at h1 h2 h3
  refine ⟨?_, ?_, ?_⟩ <;> simp_all [chunk]

theorem flat_epilogue_plain (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (t : Nat)
    (ht : code[t]? = some .Epilogue) (htr : trailerAt code t = false) :
    (flat cfg code).drop (chunkStart cfg code t)
        = [ .AluImm true .Add x64_ir.RSP 8#i32, .Ret ]
          ++ (flat cfg code).drop (chunkStart cfg code (t + 1)) ∧
      chunkLen cfg code t = 2 ∧ labelBase cfg code (t + 1) = labelBase cfg code t := by
  obtain ⟨h1, h2, h3⟩ := flat_macro cfg code t _ ht
  rw [htr] at h1 h2 h3
  refine ⟨?_, ?_, ?_⟩ <;> simp_all [chunk]

theorem flat_guestFp (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat) {dst : Std.U8}
    (h : code[i]? = some (.GuestFp dst)) :
    (flat cfg code).drop (chunkStart cfg code i)
        = chunkGuestFp dst ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) ∧
      chunkLen cfg code i = 2 ∧ labelBase cfg code (i + 1) = labelBase cfg code i := by
  obtain ⟨h1, h2, h3⟩ := flat_macro cfg code i _ h
  exact ⟨h1, by rw [h2]; rfl, h3⟩

theorem flat_checkedAddr (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {src dst scratch : Std.U8} {offset : Std.I32} {size : Std.U32} {hint : Std.U8}
    (h : code[i]? = some (.CheckedAddr src dst scratch offset size hint)) :
    (flat cfg code).drop (chunkStart cfg code i)
        = chunkCheckedAddr cfg src dst scratch offset size hint
          ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) ∧
      chunkLen cfg code i = (chunkCheckedAddr cfg src dst scratch offset size hint).length ∧
      labelBase cfg code (i + 1) = labelBase cfg code i :=
  flat_macro cfg code i _ h

theorem flat_mulDivMod (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {kind : x64_ir.MulDivKind} {w64 reg signed : Bool} {src dst : Std.U8} {imm : Std.I32}
    (h : code[i]? = some (.MulDivMod kind w64 reg signed src dst imm)) :
    (flat cfg code).drop (chunkStart cfg code i)
        = (chunkMulDivMod kind w64 reg signed src dst imm (labelBase cfg code i)).1
          ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) ∧
      chunkLen cfg code i
        = (chunkMulDivMod kind w64 reg signed src dst imm (labelBase cfg code i)).1.length ∧
      labelBase cfg code (i + 1)
        = (chunkMulDivMod kind w64 reg signed src dst imm (labelBase cfg code i)).2 :=
  flat_macro cfg code i _ h

theorem flat_atomicFetchAlu (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {op : Std.U8} {w64 : Bool} {src base : Std.U8} {disp : Std.I32}
    (h : code[i]? = some (.AtomicFetchAlu op w64 src base disp)) :
    (flat cfg code).drop (chunkStart cfg code i)
        = (chunkAtomicFetchAlu op w64 src base disp (labelBase cfg code i)).1
          ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) ∧
      chunkLen cfg code i
        = (chunkAtomicFetchAlu op w64 src base disp (labelBase cfg code i)).1.length ∧
      labelBase cfg code (i + 1) = labelBase cfg code i + 1 :=
  flat_macro cfg code i _ h

theorem flat_helperCall (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {idx : Std.U32} (h : code[i]? = some (.HelperCall idx)) :
    (flat cfg code).drop (chunkStart cfg code i)
        = (chunkHelperCall idx (labelBase cfg code i)).1
          ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) ∧
      chunkLen cfg code i = 19 ∧
      labelBase cfg code (i + 1) = labelBase cfg code i + 2 := by
  obtain ⟨h1, h2, h3⟩ := flat_macro cfg code i _ h
  exact ⟨h1, by rw [h2]; rfl, h3⟩

theorem flat_lazyLocalCall (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    {id : Std.U32} (h : code[i]? = some (.LazyLocalCall id)) :
    (flat cfg code).drop (chunkStart cfg code i)
        = (chunkLazyLocalCall cfg id (labelBase cfg code i)).1
          ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) ∧
      chunkLen cfg code i = 45 ∧
      labelBase cfg code (i + 1) = labelBase cfg code i + 2 := by
  obtain ⟨h1, h2, h3⟩ := flat_macro cfg code i _ h
  exact ⟨h1, by rw [h2]; rfl, h3⟩

theorem flat_retpoline (cfg : x64_ir.Cfg) (code : List x64_ir.MInsn) (i : Nat)
    (h : code[i]? = some .Retpoline) :
    (flat cfg code).drop (chunkStart cfg code i)
        = (chunkRetpoline (labelBase cfg code i)).1
          ++ (flat cfg code).drop (chunkStart cfg code (i + 1)) ∧
      chunkLen cfg code i = 8 ∧
      labelBase cfg code (i + 1) = labelBase cfg code i + 2 := by
  obtain ⟨h1, h2, h3⟩ := flat_macro cfg code i _ h
  exact ⟨h1, by rw [h2]; rfl, h3⟩

end async_ebpf_verified.X64

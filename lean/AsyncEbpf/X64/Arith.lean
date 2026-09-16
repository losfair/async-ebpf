import AsyncEbpf.X64.Simple
import AsyncEbpf.X64.CheckSpec

/-!
# The two macros that balance the native stack

`MulDivMod` and `AtomicFetchAlu` are the two macros whose expansions push and
pop. Everything else the backend emits either leaves `rsp` alone or is the
prologue/epilogue pair, so these two are where the depth bookkeeping of
`x64_check` — `depth_ok(st, 4)` and `depth_ok(st, 1)` — is spent, and they are
the only macros whose expansion branches inside itself.

## What is here

First the two lists, mirrored from `x64_expand::expand_muldivmod` and
`x64_expand::expand_atomic_fetch_alu` branch for branch, down to which local
label numbers are used and in which order. `AsyncEbpf/X64/Expand.lean` spells
the same sequences as `chunkMulDivMod`/`chunkAtomicFetchAlu`; the two
spellings are proved equal where the two halves are joined.

Then a small calculus for regions of an expansion, because neither macro fits
the one-primitive shape of `AsyncEbpf/X64/Simple.lean`:

* `Ctx P pre W d t` is `Agree` with the destination registers forgotten: the
  machine state `t` still has `rbp` where it was, `rsp` exactly `d` words
  below its entry value, the read-only bytes and the parked group base intact,
  and every register outside `W` still holding a value its *pre*-state tag
  admits. `W` is the set a region may have clobbered, `d` the depth it is at.
* `BlockOk P code b e pre Win Wout din dout` is `MacroOk`'s clauses for the
  sub-region `[b, e)`, stated over `Ctx` instead of `Agree`: what the region
  may touch, what it may *write*, where `rsp` is at every position of it,
  where control leaves it, and that it never returns. It composes:
  `blockOk_seq` puts two regions end to end, `blockOk_line` runs a
  straight-line list of primitives, and `blockOk_flat` runs a region of
  constant depth whose branches all land inside it — which is what a macro's
  internal `Jcc8`/`Jmp8` to its own locals is.
* `macroOk_of_blockOk` turns a balanced block (`dout = din = pre.depth`) back
  into a `MacroOk`, reading the post-state off `SetsTop` and the stack window
  off the depth `BlockOk` carries, through `macroOk_rsp_of_window`.

The two clauses `BlockOk` carries beyond safety cost the regions nothing new.
The only primitives of either expansion that write are the pushes and the
loop's `lock cmpxchg`: a push at depth `d + 1` writes the word `storeOk_stack`
makes writable, and `LineOk` already asks for the `d + 1 ≤ 16` that needs;
the compare-exchange writes through the same `GuestTag` its access goes
through, which is why `GuestTag` reads the address rule as a fact about reads
*and* writes. Everything else writes nothing. And the stack pointer is `rsp0 -
8·d` at every position, with `d ≤ 16`, which is exactly what `Ctx` says.

The division of labour is then: the pushes and pops are lines, the branchy
middle is flat, and the address rule enters only through `GuestTag`, which is
the `Checked`/frame case of `addr_ok` phrased as "whatever value a register
carrying this tag holds, the access through it is a `GuestOk` one". Because
`GuestTag` mentions the *pre*-state tag, a region may re-execute the access —
which is exactly what the compare-exchange loop does — as long as the base
register is not in `W`.

## The hole in the `AtomicFetchAlu` rule

The checker's rule for `AtomicFetchAlu` checks the address against the
pre-state and then writes `src`, `rax`, `rcx`, `r10` and `r11`. The expansion
loads into `rax` and copies `rax` into `rcx`, so with `base` equal to either
of those two the base register is clobbered before the loop's `lock cmpxchg`
dereferences it again, and the rule as it stands admits that. The lowering
never builds it — under the cage an atomic's address is resolved through
`CheckedAddr` into `r11` — but the checker does not know that, so
`macroOk_atomicFetchAlu` carries `base ≠ RAX` and `base ≠ RCX` as hypotheses
until `x64_check.rs` is tightened to refuse them. Nothing else is assumed:
`r10`/`r11` are written only as `actual_src`, which the expansion picks
different from `base`, and `src` is written only after the last access, so
both are handled inside the invariant rather than excluded.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-! ## The two expansions

Mirrors of `x64_expand::expand_muldivmod` and
`x64_expand::expand_atomic_fetch_alu`, written as list literals. The helpers
repeat the three `is_*` predicates and `alu_rr_of` under their own names so
that this file stands on its own. -/

/-- A `u32` from a natural number, truncating, as the local-label counter's
conversion. -/
def mdU32 (n : Nat) : Std.U32 := ⟨BitVec.ofNat 32 n⟩

/-- `x64_expand::is_mul`. -/
def mdIsMul : x64_ir.MulDivKind → Bool | .Mul => true | _ => false
/-- `x64_expand::is_div`. -/
def mdIsDiv : x64_ir.MulDivKind → Bool | .Div => true | _ => false
/-- `x64_expand::is_mod`. -/
def mdIsMod : x64_ir.MulDivKind → Bool | .Mod => true | _ => false

/-- `x64_expand::alu_rr_of`. -/
def mdAluRr (op : Std.U8) : x64_ir.AluRR :=
  if op = 9#u8 then .Or else if op = 33#u8 then .And
  else if op = 49#u8 then .Xor else .Add

/-- `x64_expand::expand_muldiv_setup`: the registers the divide clobbers are
saved, the divisor goes into `rcx` and the dividend into `rax`, and a zero
divisor is turned into one so that the divide cannot fault. -/
def mulDivSetupList (kind : x64_ir.MulDivKind) (w64 reg signed : Bool) (src dst : Std.U8)
    (imm : Std.I32) : List x64_ir.PInsn :=
  (if dst != x64_ir.RAX then [ .Push x64_ir.RAX ] else []) ++
  (if dst != x64_ir.RDX then [ .Push x64_ir.RDX ] else []) ++
  (if reg then [ .Alu true .Mov src x64_ir.RCX ]
   else [ .LoadImm x64_ir.RCX (Std.IScalar.cast .I64 imm) ]) ++
  [ .Alu true .Mov dst x64_ir.RAX ] ++
  (if mdIsDiv kind || mdIsMod kind then
     [ .Alu w64 .Test x64_ir.RCX x64_ir.RCX ] ++
     (if mdIsMod kind then [ .Push x64_ir.RAX ] else []) ++
     [ .Pushfq, .LoadImm x64_ir.RDX 1#i64, .Cmov x64_ir.cc.E x64_ir.RCX x64_ir.RDX ] ++
     (if signed then (if w64 then [ .Cqo ] else [ .Cdq ])
      else [ .Alu false .Xor x64_ir.RDX x64_ir.RDX ])
   else [])

/-- `x64_expand::expand_muldiv_overflow`: `INT_MIN / -1` wraps per RFC 9669
and faults on x86, so both operands are compared against it and the divide
skipped when both match. -/
def mulDivOverflowList (w64 div : Bool) (noOverflow afterDivide : Nat) : List x64_ir.PInsn :=
  [ .CmpRcxMinusOne w64, .Jcc8 x64_ir.cc.NE (mdU32 noOverflow) ] ++
  (if w64 then [ .LoadImm x64_ir.R11 core.num.I64.MIN,
                 .Alu true .Cmp x64_ir.R11 x64_ir.RAX ]
   else [ .CmpEaxImm 2147483648#u32 ]) ++
  [ .Jcc8 x64_ir.cc.NE (mdU32 noOverflow) ] ++
  (if div then [] else [ .Alu false .Xor x64_ir.RDX x64_ir.RDX ]) ++
  [ .Jmp8 (mdU32 afterDivide), .Local (mdU32 noOverflow) ]

/-- The branchy middle: the signed overflow block, the divide itself, and the
local label the overflow block jumps over it to. Everything here is at one
depth. -/
def mulDivMidList (kind : x64_ir.MulDivKind) (w64 signed : Bool) (label : Nat) :
    List x64_ir.PInsn :=
  (if (mdIsDiv kind || mdIsMod kind) && signed then
     mulDivOverflowList w64 (mdIsDiv kind) label (label + 1) else []) ++
  [ .MulDivRcx w64 kind signed ] ++
  (if (mdIsDiv kind || mdIsMod kind) && signed then [ .Local (mdU32 (label + 1)) ] else [])

/-- `x64_expand::expand_muldiv_finish`: the saved flags decide whether the
divisor was zero, eBPF's answer is substituted where it was, and the saved
registers are unwound. -/
def mulDivFinishList (kind : x64_ir.MulDivKind) (dst : Std.U8) : List x64_ir.PInsn :=
  (if mdIsDiv kind then [ .Popfq, .LoadImm x64_ir.RCX 0#i64,
                          .Cmov x64_ir.cc.E x64_ir.RAX x64_ir.RCX ]
   else if mdIsMod kind then [ .Popfq, .Pop x64_ir.RCX,
                               .Cmov x64_ir.cc.E x64_ir.RDX x64_ir.RCX ]
   else []) ++
  (if dst != x64_ir.RDX then
     (if mdIsMod kind then [ .Alu true .Mov x64_ir.RDX dst ] else []) ++ [ .Pop x64_ir.RDX ]
   else []) ++
  (if dst != x64_ir.RAX then
     (if mdIsDiv kind || mdIsMul kind then [ .Alu true .Mov x64_ir.RAX dst ] else []) ++
     [ .Pop x64_ir.RAX ]
   else [])

/-- `x64_expand::expand_muldivmod`. A multiply or divide by the immediate
zero is a short circuit — eBPF's answer is zero for `div` and `mul` and the
dividend for `mod`, and the self-move is emitted rather than elided. -/
def mulDivModList (kind : x64_ir.MulDivKind) (w64 reg signed : Bool) (src dst : Std.U8)
    (imm : Std.I32) (label : Nat) : List x64_ir.PInsn :=
  if reg then
    mulDivSetupList kind w64 true signed src dst imm ++ mulDivMidList kind w64 signed label ++
      mulDivFinishList kind dst
  else if imm = 0#i32 then
    (if mdIsDiv kind || mdIsMul kind then [ .Alu false .Xor dst dst ]
     else [ .Alu true .Mov dst dst ])
  else
    mulDivSetupList kind w64 false signed src dst imm ++ mulDivMidList kind w64 signed label ++
      mulDivFinishList kind dst

/-- The register the compare-exchange loop keeps the original source value
in: the source itself, or — when the source is `rax`, which the loop
overwrites — whichever of `r10`/`r11` is not the base. -/
def atomicFetchActual (src base : Std.U8) : Std.U8 :=
  if src = x64_ir.RAX then (if base = x64_ir.R10 then x64_ir.R11 else x64_ir.R10) else src

/-- The one push in front of the loop, and the copy that saves `rax`. -/
def atomicFetchHead (src actual : Std.U8) : List x64_ir.PInsn :=
  if src = x64_ir.RAX then [ .Push actual, .Alu true .Mov src actual ]
  else [ .Push x64_ir.RAX ]

/-- The loop itself: the initial load and the compare-exchange that retries
it. Both dereference `[base + disp]`, and the whole of it is at one depth. -/
def atomicFetchLoop (op : Std.U8) (w64 : Bool) (actual base : Std.U8) (disp : Std.I32)
    (label : Nat) : List x64_ir.PInsn :=
  [ .Load (if w64 then 8#u8 else 4#u8) false base x64_ir.RAX disp,
    .Local (mdU32 label),
    .Alu true .Mov x64_ir.RAX x64_ir.RCX,
    .Alu true (mdAluRr op) actual x64_ir.RCX,
    .LockCmpxchg w64 x64_ir.RCX base disp,
    .Jcc8 x64_ir.cc.NE (mdU32 label) ]

/-- The old value into the source register, and the pop. -/
def atomicFetchTail (src actual : Std.U8) : List x64_ir.PInsn :=
  if src = x64_ir.RAX then [ .Pop actual ]
  else [ .Alu true .Mov x64_ir.RAX src, .Pop x64_ir.RAX ]

/-- `x64_expand::expand_atomic_fetch_alu`. -/
def atomicFetchAluList (op : Std.U8) (w64 : Bool) (src base : Std.U8) (disp : Std.I32)
    (label : Nat) : List x64_ir.PInsn :=
  atomicFetchHead src (atomicFetchActual src base) ++
    atomicFetchLoop op w64 (atomicFetchActual src base) base disp label ++
    atomicFetchTail src (atomicFetchActual src base)

/-! ## The context a region of an expansion keeps

`Agree` pins every register to its tag; a region of one macro's expansion has
already overwritten some of them, and the checker's post-state will call those
`Top`. `Ctx` is `Agree` with that set — `W` — forgotten, and with the depth a
parameter rather than the abstract state's.

`rsp` is excluded from the register clause because the pushes move it; what
survives of it is the exact value, which is the clause above. -/

/-- What a region of an expansion keeps of the state it started in. -/
structure Ctx (P : Params) (pre : x64_check.State) (W : Nat → Prop) (d : Nat) (t : State) :
    Prop where
  /-- `rsp` is exactly `d` words below its entry value. -/
  rsp : t.regs RSP = P.rsp0 - BitVec.ofNat 64 (8 * d)
  /-- Which is inside the native stack window. -/
  bound : d ≤ 16
  /-- `rbp` never moves. -/
  rbp : t.regs RBP = P.rbp0
  /-- Every register the region has not written still holds a value its
  pre-state tag admits. -/
  regs : ∀ r, r ≠ RSP → ¬ W r → TagOk P (tagAt pre r) (t.regs r)
  /-- The bytes the entry trampoline filled in are still there. -/
  ro : RoMem P t.mem
  /-- And so is the parked group base. -/
  group : TagOk P pre.group (load64 t.mem (P.rbp0 - 144#64))

/-- Forgetting more registers is weaker. -/
theorem Ctx.mono {P pre W W' d} {t : State} (h : Ctx P pre W d t) (hW : ∀ r, W r → W' r) :
    Ctx P pre W' d t :=
  ⟨h.rsp, h.bound, h.rbp, fun r hr hW' => h.regs r hr (fun hx => hW' (hW r hx)), h.ro, h.group⟩

/-- The agreement gives the context at the depth the abstract state records,
whatever set is forgotten. -/
theorem agree_ctx {P : Params} {pre : x64_check.State} {s : State} (h : Agree P pre s)
    (W : Nat → Prop) : Ctx P pre W pre.depth.val s :=
  ⟨h.rsp, h.depth, h.rbp, fun r _ _ => agree_regs_any h r, h.ro, h.group⟩

/-- And the context at the depth the walk came in at gives the agreement with
the checker's post-state, as long as everything the region wrote is something
the rule turned into `Top`. -/
theorem ctx_agree {P : Params} {pre post : x64_check.State} {S W : Nat → Prop} {s t : State}
    (hag : Agree P pre s) (hS : SetsTop pre post S) (hWS : ∀ r, W r → S r)
    (h : Ctx P pre W pre.depth.val t) : Agree P post t := by
  have hdep : post.depth = pre.depth := hS.2.2.1
  have hgrp : post.group = pre.group := hS.2.2.2.1
  refine ⟨fun r hr => ?_, ?_, ?_, h.rbp, h.ro, ?_⟩
  · by_cases hSr : S r
    · rw [hS.1 r hSr]; trivial
    · rw [hS.2.1 r hSr]
      by_cases hrsp : r = RSP
      · subst hrsp
        rw [h.rsp, ← hag.rsp]
        exact agree_regs_any hag RSP
      · exact h.regs r hrsp (fun hx => hSr (hWS r hx))
  · rw [hdep]; exact h.rsp
  · rw [hdep]; exact h.bound
  · rw [hgrp]; exact h.group

/-! ## Regions of an expansion

`BlockOk` is `MacroOk` over `Ctx`. The extra clause in front — what the region
does when it is empty — is what makes `blockOk_seq` work for the conditional
segments of an expansion, which are empty on one side of their condition.

The `rsp` clause is stated as "some depth at most sixteen" rather than as the
region's own `din`/`dout`, because that is what a walk *inside* the region
gives — the pushes of a line have moved it — and it is the shape
`macroOk_rsp_of_window` consumes. -/

/-- The clauses of `MacroOk` for the sub-region `[b, e)` of one macro's
expansion, stated over `Ctx`: what the region may touch, what it may *write*,
where the stack pointer is at every position of it, where control leaves it,
and that it never returns. -/
def BlockOk (P : Params) (code : List x64_ir.PInsn) (b e : Nat) (pre : x64_check.State)
    (Win Wout : Nat → Prop) (din dout : Nat) : Prop :=
  b ≤ e ∧
  ∀ s : State, s.pc = b → Ctx P pre Win din s →
    (b = e → Ctx P pre Wout dout s) ∧
    ∀ s' : State, Stays P code (Range b e) s s' →
      (∀ c, Step P code s' c → ∀ i, code[s'.pc]? = some i →
        ∀ bn ∈ accesses i s', AccessOk P bn.1 bn.2) ∧
      (∀ c, Step P code s' c → ∀ i, code[s'.pc]? = some i →
        ∀ bn ∈ stores i s', StoreOk P bn.1 bn.2) ∧
      (∃ d : Nat, d ≤ 16 ∧ s'.regs RSP = P.rsp0 - BitVec.ofNat 64 (8 * d)) ∧
      (∀ s'', Step P code s' (.next s'') → ¬ Range b e s''.pc →
        s''.pc = e ∧ Ctx P pre Wout dout s'') ∧
      (∀ s'', ¬ Step P code s' (.returned s''))

/-- Weakening what the region promises about the registers. -/
theorem BlockOk.mono {P code b e pre Win Wout Wout' din dout}
    (h : BlockOk P code b e pre Win Wout din dout) (hW : ∀ r, Wout r → Wout' r) :
    BlockOk P code b e pre Win Wout' din dout := by
  refine ⟨h.1, fun s hs hc => ⟨fun hbe => ((h.2 s hs hc).1 hbe).mono hW, fun s' hsty => ?_⟩⟩
  obtain ⟨h1, hw, hr, h2, h3⟩ := (h.2 s hs hc).2 s' hsty
  exact ⟨h1, hw, hr, fun s'' hst hout => ⟨(h2 s'' hst hout).1, (h2 s'' hst hout).2.mono hW⟩, h3⟩

/-- The empty region. -/
theorem blockOk_nil {P code b pre Win Wout d} (hW : ∀ r, Win r → Wout r) :
    BlockOk P code b b pre Win Wout d d := by
  refine ⟨le_refl _, fun s hs hc => ⟨fun _ => hc.mono hW, fun s' hsty => ?_⟩⟩
  exact absurd hsty.inside_last (by simp only [Range, not_and, not_lt]; omega)

/-- Two regions end to end. -/
theorem blockOk_seq {P code b m e pre W0 W1 W2 d0 d1 d2}
    (h1 : BlockOk P code b m pre W0 W1 d0 d1) (h2 : BlockOk P code m e pre W1 W2 d1 d2) :
    BlockOk P code b e pre W0 W2 d0 d2 := by
  obtain ⟨hbm, h1⟩ := h1
  obtain ⟨hme, h2⟩ := h2
  refine ⟨le_trans hbm hme, fun s hs hc => ⟨fun hbe => ?_, fun s' hsty => ?_⟩⟩
  · have hbm' : b = m := by omega
    have hme' : m = e := by omega
    exact (h2 s (by rw [hs, hbm']) ((h1 s hs hc).1 hbm')).1 hme'
  · -- Split the walk at `m`.
    have key : ∀ u : State, Stays P code (Range b e) s u →
        (Stays P code (Range b m) s u ∧ Range b m u.pc) ∨
        (∃ v : State, v.pc = m ∧ Ctx P pre W1 d1 v ∧ Stays P code (Range m e) v u) := by
      intro u hu
      induction hu with
      | refl hin =>
        rcases Nat.lt_or_ge s.pc m with hlt | hge
        · exact Or.inl ⟨.refl ⟨by omega, hlt⟩, ⟨by omega, hlt⟩⟩
        · have hm : s.pc = m := by omega
          refine Or.inr ⟨s, hm, (h1 s hs hc).1 (by omega), .refl ?_⟩
          simp only [Range] at hin ⊢
          omega
      | step hprev hst hin ih =>
        rename_i t t'
        rcases ih with ⟨hsty1, hin1⟩ | ⟨v, hv, hcv, hsty2⟩
        · rcases Classical.em (Range b m t'.pc) with hr | hr
          · exact Or.inl ⟨.step hsty1 hst hr, hr⟩
          · obtain ⟨hpc, hct⟩ := ((h1 s hs hc).2 t hsty1).2.2.2.1 t' hst hr
            refine Or.inr ⟨t', hpc, hct, .refl ?_⟩
            simp only [Range] at hin ⊢
            omega
        · have hge : m ≤ t'.pc := by
            by_contra hlt
            have hout : ¬ Range m e t'.pc := by simp only [Range, not_and, not_lt]; omega
            have := ((h2 v hv hcv).2 t hsty2).2.2.2.1 t' hst hout
            simp only [Range] at hin
            omega
          refine Or.inr ⟨v, hv, hcv, .step hsty2 hst ?_⟩
          simp only [Range] at hin ⊢
          omega
    rcases key s' hsty with ⟨hsty1, hin1⟩ | ⟨v, hv, hcv, hsty2⟩
    · obtain ⟨g1, gw, gr, g2, g3⟩ := (h1 s hs hc).2 s' hsty1
      refine ⟨g1, gw, gr, fun s'' hst hout => ?_, g3⟩
      have hout1 : ¬ Range b m s''.pc := by
        simp only [Range, not_and, not_lt] at hout ⊢
        omega
      obtain ⟨hpc, hct⟩ := g2 s'' hst hout1
      have hme' : m = e := by
        simp only [Range, not_and, not_lt] at hout
        omega
      exact ⟨by omega, (h2 s'' (by omega) hct).1 hme'⟩
    · obtain ⟨g1, gw, gr, g2, g3⟩ := (h2 v hv hcv).2 s' hsty2
      refine ⟨g1, gw, gr, fun s'' hst hout => ?_, g3⟩
      have hout2 : ¬ Range m e s''.pc := by
        simp only [Range, not_and, not_lt] at hout ⊢
        omega
      exact g2 s'' hst hout2

/-! ## The primitives of a region

Each of these is one primitive: what it does to the context, and what it
touches. The stack ones are the only place the depth moves. -/

/-- A step reads an instruction, so a program counter off the end of the list
is stuck. -/
theorem step_fetch {P code} {s : State} {c : Config} (h : Step P code s c) :
    ∃ i, code[s.pc]? = some i := by
  cases h <;> exact ⟨_, by assumption⟩

/-- `rsp + 8` is the word one shallower. -/
theorem rsp_pop {P : Params} {d : Nat} :
    P.rsp0 - BitVec.ofNat 64 (8 * (d + 1)) + 8#64 = P.rsp0 - BitVec.ofNat 64 (8 * d) := by
  rw [← rsp_push (P := P) (d := d)]
  ring

/-- A store to the native stack misses the parked group base, which lives in
the frame scratch. -/
theorem groupBase_kept_stack {P : Params} (hL : Layout P) {d : Nat} (hd : d ≤ 16) (m : Mem)
    (v : Word) :
    load64 (store64 m (P.rsp0 - BitVec.ofNat 64 (8 * d)) v) (P.rbp0 - 144#64)
      = load64 m (P.rbp0 - 144#64) := by
  have hsw := hL.stackWindow_toNat
  have hroom := hL.stackRoom
  have hnw := hL.stackWindowNoWrap
  have hfo := hL.frameOffStack
  have hfs := hL.frameSlots_toNat
  have hr := hL.frameRoom
  simp only [stackWindowLen] at hnw
  simp only [RangesDisjoint, stackWindowLen] at hfo
  have hb : (P.rsp0 - BitVec.ofNat 64 (8 * d)).toNat = P.rsp0.toNat - 8 * d :=
    toNat_sub_ofNat (by omega) (by omega)
  have h144 : (P.rbp0 - 144#64).toNat = P.rbp0.toNat - 144 :=
    rbp_sub_toNat hL (j := 144) (by norm_num)
  exact load64_store_disjoint 8 m _ _ v (by omega) (by omega)
    (by simp only [RangesDisjoint, h144, hb]; omega)

/-- `push` moves `rsp` and nothing else. -/
theorem push_regs_ne (s : State) (v : Word) {r : Nat} (hr : r ≠ RSP) :
    (push s v).regs r = s.regs r := by
  simp [push, Function.update_of_ne hr]

/-- And so does `popRsp`. -/
theorem popRsp_regs_ne (s : State) {r : Nat} (hr : r ≠ RSP) :
    (popRsp s).regs r = s.regs r := by
  simp [popRsp, Function.update_of_ne hr]

/-- A region of one primitive that always falls through. -/
theorem blockOk_one {P : Params} {code : List x64_ir.PInsn} {b : Nat} {pre : x64_check.State}
    {Win Wout : Nat → Prop} {din dout : Nat} {i : x64_ir.PInsn}
    (hc : code[b]? = some i) (hne : i ≠ .Ret)
    (hadv : ∀ t t' : State, t.pc = b → Step P code t (.next t') → t'.pc = b + 1)
    (hsafe : ∀ t : State, t.pc = b → Ctx P pre Win din t →
      ∀ bn ∈ accesses i t, AccessOk P bn.1 bn.2)
    (hstore : ∀ t : State, t.pc = b → Ctx P pre Win din t →
      ∀ bn ∈ stores i t, StoreOk P bn.1 bn.2)
    (hpost : ∀ t t' : State, t.pc = b → Ctx P pre Win din t → Step P code t (.next t') →
      Ctx P pre Wout dout t') :
    BlockOk P code b (b + 1) pre Win Wout din dout := by
  refine ⟨by omega, fun s hs hcx => ⟨by omega, fun s' hsty => ?_⟩⟩
  have heq : s' = s := by
    refine stays_single ?_ hsty
    intro t t' ht hst
    exact hadv t t' ht hst
  subst heq
  refine ⟨?_, ?_, ⟨din, hcx.bound, hcx.rsp⟩, ?_, ?_⟩
  · intro c hst j hj bn hbn
    rw [hs, hc] at hj
    obtain rfl : j = i := by simpa using hj.symm
    exact hsafe s' hs hcx bn hbn
  · intro c hst j hj bn hbn
    rw [hs, hc] at hj
    obtain rfl : j = i := by simpa using hj.symm
    exact hstore s' hs hcx bn hbn
  · intro s'' hst _
    exact ⟨hadv s' s'' hs hst, hpost s' s'' hs hcx hst⟩
  · intro s'' hst
    exact not_step_returned hne (by rw [hs]; exact hc) hst

/-- A register-only primitive: the depth does not move, and the registers it
writes are ones the region has already given up. -/
theorem blockOk_regOnly {P : Params} {code : List x64_ir.PInsn} {b : Nat}
    {pre : x64_check.State} {Win Wout : Nat → Prop} {d : Nat} {i : x64_ir.PInsn}
    (hi : RegOnly i) (hc : code[b]? = some i) (hW : ∀ r ∈ writes i, Wout r)
    (hWin : ∀ r, Win r → Wout r) (hW4 : ¬ Wout RSP) (hW5 : ¬ Wout RBP) :
    BlockOk P code b (b + 1) pre Win Wout d d := by
  have hne : i ≠ .Ret := by rintro rfl; exact hi
  refine blockOk_one hc hne ?_ ?_ ?_ ?_
  · intro t t' ht hst
    obtain ⟨u, hu, hpc, -, -⟩ := step_regOnly hi (by rw [ht]; exact hc) hst
    cases hu
    rw [hpc, ht]
  · intro t _ _ bn hbn
    rw [accesses_regOnly hi] at hbn
    simp at hbn
  · intro t _ _ bn hbn
    rw [stores_regOnly hi] at hbn
    simp at hbn
  · intro t t' ht hct hst
    obtain ⟨u, hu, -, hmem, hregs⟩ := step_regOnly hi (by rw [ht]; exact hc) hst
    cases hu
    refine ⟨?_, hct.bound, ?_, ?_, ?_, ?_⟩
    · rw [hregs RSP (fun hx => hW4 (hW RSP hx))]; exact hct.rsp
    · rw [hregs RBP (fun hx => hW5 (hW RBP hx))]; exact hct.rbp
    · intro r hr hWr
      rw [hregs r (fun hx => hWr (hW r hx))]
      exact hct.regs r hr (fun hx => hWr (hWin r hx))
    · rw [hmem]; exact hct.ro
    · rw [hmem]; exact hct.group

/-- `push`: one word deeper, and the word it writes is inside the native
stack window. -/
theorem blockOk_push {P : Params} {code : List x64_ir.PInsn} {b : Nat} {pre : x64_check.State}
    {Win Wout : Nat → Prop} {d : Nat} {r : Std.U8} (hL : Layout P)
    (hc : code[b]? = some (.Push r)) (hd : d + 1 ≤ 16) (hWin : ∀ x, Win x → Wout x) :
    BlockOk P code b (b + 1) pre Win Wout d (d + 1) := by
  refine blockOk_one hc (by simp) ?_ ?_ ?_ ?_
  · intro t t' ht hst
    have hu := step_push (by rw [ht]; exact hc) hst
    simp only [Config.next.injEq] at hu
    subst hu
    rw [ht]
  · intro t ht hct bn hbn
    simp only [accesses_push, List.mem_singleton] at hbn
    subst hbn
    rw [hct.rsp, rsp_push]
    exact stack_slot_ok hL hd
  · intro t ht hct bn hbn
    simp only [stores_push, List.mem_singleton] at hbn
    subst hbn
    rw [hct.rsp, rsp_push]
    exact storeOk_stack hL (by omega) hd
  · intro t t' ht hct hst
    have hu := step_push (by rw [ht]; exact hc) hst
    simp only [Config.next.injEq] at hu
    subst hu
    refine ⟨?_, hd, ?_, ?_, ?_, ?_⟩
    · show (push t (t.regs r.val)).regs RSP = _
      rw [push_rsp, hct.rsp, rsp_push]
    · show (push t (t.regs r.val)).regs RBP = _
      rw [push_regs_ne _ _ (by simp [RBP, RSP])]
      exact hct.rbp
    · intro x hx hWx
      show TagOk P (tagAt pre x) ((push t (t.regs r.val)).regs x)
      rw [push_regs_ne _ _ hx]
      exact hct.regs x hx (fun hh => hWx (hWin x hh))
    · show RoMem P (push t (t.regs r.val)).mem
      rw [push_mem, hct.rsp, rsp_push]
      exact romem_store64_stack hL hct.ro hd (t.regs r.val)
    · show TagOk P pre.group (load64 (push t (t.regs r.val)).mem (P.rbp0 - 144#64))
      rw [push_mem, hct.rsp, rsp_push, groupBase_kept_stack hL hd]
      exact hct.group

/-- `pushfq`, which is a `push` of the flags. -/
theorem blockOk_pushfq {P : Params} {code : List x64_ir.PInsn} {b : Nat} {pre : x64_check.State}
    {Win Wout : Nat → Prop} {d : Nat} (hL : Layout P)
    (hc : code[b]? = some .Pushfq) (hd : d + 1 ≤ 16) (hWin : ∀ x, Win x → Wout x) :
    BlockOk P code b (b + 1) pre Win Wout d (d + 1) := by
  refine blockOk_one hc (by simp) ?_ ?_ ?_ ?_
  · intro t t' ht hst
    have hu := step_pushfq (by rw [ht]; exact hc) hst
    simp only [Config.next.injEq] at hu
    subst hu
    rw [ht]
  · intro t ht hct bn hbn
    simp only [accesses_pushfq, List.mem_singleton] at hbn
    subst hbn
    rw [hct.rsp, rsp_push]
    exact stack_slot_ok hL hd
  · intro t ht hct bn hbn
    simp only [stores_pushfq, List.mem_singleton] at hbn
    subst hbn
    rw [hct.rsp, rsp_push]
    exact storeOk_stack hL (by omega) hd
  · intro t t' ht hct hst
    have hu := step_pushfq (by rw [ht]; exact hc) hst
    simp only [Config.next.injEq] at hu
    subst hu
    refine ⟨?_, hd, ?_, ?_, ?_, ?_⟩
    · show (push t (flagsWord t.flags)).regs RSP = _
      rw [push_rsp, hct.rsp, rsp_push]
    · show (push t (flagsWord t.flags)).regs RBP = _
      rw [push_regs_ne _ _ (by simp [RBP, RSP])]
      exact hct.rbp
    · intro x hx hWx
      show TagOk P (tagAt pre x) ((push t (flagsWord t.flags)).regs x)
      rw [push_regs_ne _ _ hx]
      exact hct.regs x hx (fun hh => hWx (hWin x hh))
    · show RoMem P (push t (flagsWord t.flags)).mem
      rw [push_mem, hct.rsp, rsp_push]
      exact romem_store64_stack hL hct.ro hd (flagsWord t.flags)
    · show TagOk P pre.group (load64 (push t (flagsWord t.flags)).mem (P.rbp0 - 144#64))
      rw [push_mem, hct.rsp, rsp_push, groupBase_kept_stack hL hd]
      exact hct.group

/-- `pop`: one word shallower, and the register it writes is one the region
has already given up. -/
theorem blockOk_pop {P : Params} {code : List x64_ir.PInsn} {b : Nat} {pre : x64_check.State}
    {Win Wout : Nat → Prop} {d : Nat} {r : Std.U8} (hL : Layout P)
    (hc : code[b]? = some (.Pop r)) (hd : d + 1 ≤ 16) (hWr : Wout r.val)
    (hWin : ∀ x, Win x → Wout x) (hW4 : ¬ Wout RSP) (hW5 : ¬ Wout RBP) :
    BlockOk P code b (b + 1) pre Win Wout (d + 1) d := by
  refine blockOk_one hc (by simp) ?_ ?_ ?_ ?_
  · intro t t' ht hst
    have hu := step_pop (by rw [ht]; exact hc) hst
    simp only [Config.next.injEq] at hu
    subst hu
    rw [ht]
  · intro t ht hct bn hbn
    simp only [accesses_pop, List.mem_singleton] at hbn
    subst hbn
    rw [hct.rsp]
    exact stack_slot_ok hL hd
  · intro t _ _ bn hbn
    rw [stores_pop] at hbn
    simp at hbn
  · intro t t' ht hct hst
    have hu := step_pop (by rw [ht]; exact hc) hst
    simp only [Config.next.injEq] at hu
    subst hu
    -- The write set is what keeps the destination off `rsp`: `write` in the
    -- checker refuses register four, so a `pop` the region takes never pops
    -- into the stack pointer, and the popped value never wins over `rsp + 8`.
    have hne4 : r.val ≠ RSP := fun hx => hW4 (hx ▸ hWr)
    have hne5 : r.val ≠ RBP := fun hx => hW5 (hx ▸ hWr)
    refine ⟨?_, by omega, ?_, ?_, hct.ro, hct.group⟩
    · show Function.update (Function.update t.regs RSP (t.regs RSP + 8#64)) r.val
        (load64 t.mem (t.regs RSP)) RSP = _
      rw [Function.update_of_ne (Ne.symm hne4), Function.update_self, hct.rsp, rsp_pop]
    · show Function.update (Function.update t.regs RSP (t.regs RSP + 8#64)) r.val
        (load64 t.mem (t.regs RSP)) RBP = _
      rw [Function.update_of_ne (Ne.symm hne5), Function.update_of_ne (by simp [RBP, RSP])]
      exact hct.rbp
    · intro x hx hWx
      show TagOk P (tagAt pre x)
        (Function.update (Function.update t.regs RSP (t.regs RSP + 8#64)) r.val
          (load64 t.mem (t.regs RSP)) x)
      rw [Function.update_of_ne (show x ≠ r.val from fun hh => hWx (by rw [hh]; exact hWr)),
        Function.update_of_ne hx]
      exact hct.regs x hx (fun hh => hWx (hWin x hh))

/-- `popfq`, which is a `pop` into the flags. -/
theorem blockOk_popfq {P : Params} {code : List x64_ir.PInsn} {b : Nat} {pre : x64_check.State}
    {Win Wout : Nat → Prop} {d : Nat} (hL : Layout P)
    (hc : code[b]? = some .Popfq) (hd : d + 1 ≤ 16) (hWin : ∀ x, Win x → Wout x) :
    BlockOk P code b (b + 1) pre Win Wout (d + 1) d := by
  refine blockOk_one hc (by simp) ?_ ?_ ?_ ?_
  · intro t t' ht hst
    have hu := step_popfq (by rw [ht]; exact hc) hst
    simp only [Config.next.injEq] at hu
    subst hu
    rw [ht]
  · intro t ht hct bn hbn
    simp only [accesses_popfq, List.mem_singleton] at hbn
    subst hbn
    rw [hct.rsp]
    exact stack_slot_ok hL hd
  · intro t _ _ bn hbn
    rw [stores_popfq] at hbn
    simp at hbn
  · intro t t' ht hct hst
    have hu := step_popfq (by rw [ht]; exact hc) hst
    simp only [Config.next.injEq] at hu
    subst hu
    refine ⟨?_, by omega, ?_, ?_, hct.ro, hct.group⟩
    · show (popRsp t).regs RSP = _
      rw [popRsp_rsp, hct.rsp, rsp_pop]
    · show (popRsp t).regs RBP = _
      rw [popRsp_regs_ne _ (by simp [RBP, RSP])]
      exact hct.rbp
    · intro x hx hWx
      show TagOk P (tagAt pre x) ((popRsp t).regs x)
      rw [popRsp_regs_ne _ hx]
      exact hct.regs x hx (fun hh => hWx (hWin x hh))

/-! ## Straight-line stretches

`LineOk` is the check a list of primitives with no branches has to pass, and
`dRun` the depth it leaves behind. Both are structural, so a concrete list
reduces them by `simp`. -/

/-- What one primitive does to the depth. -/
def dStep (d : Nat) : x64_ir.PInsn → Nat
  | .Push _ => d + 1
  | .Pushfq => d + 1
  | .Pop _ => d - 1
  | .Popfq => d - 1
  | _ => d

/-- And what a list of them does. -/
def dRun (d : Nat) : List x64_ir.PInsn → Nat
  | [] => d
  | i :: rest => dRun (dStep d i) rest

/-- A straight-line stretch of primitives, each of which the region may take:
a push that fits, a pop of a register the region has given up, or a
register-only primitive whose destinations it has given up. -/
def LineOk (W : Nat → Prop) : Nat → List x64_ir.PInsn → Prop
  | _, [] => True
  | d, i :: rest =>
    (match i with
     | .Push _ => d + 1 ≤ 16
     | .Pushfq => d + 1 ≤ 16
     | .Pop r => 1 ≤ d ∧ W r.val
     | .Popfq => 1 ≤ d
     | j => RegOnly j ∧ ∀ r ∈ writes j, W r) ∧ LineOk W (dStep d i) rest

/-- Running a straight-line stretch. -/
theorem blockOk_line {P : Params} {code : List x64_ir.PInsn} {pre : x64_check.State}
    {W : Nat → Prop} (hL : Layout P) (hW4 : ¬ W RSP) (hW5 : ¬ W RBP) :
    ∀ (L : List x64_ir.PInsn) (b d : Nat), d ≤ 16 →
      (∀ k, k < L.length → code[b + k]? = L[k]?) → LineOk W d L →
      BlockOk P code b (b + L.length) pre W W d (dRun d L) := by
  intro L
  induction L with
  | nil =>
    intro b d _ _ _
    have hb : b + ([] : List x64_ir.PInsn).length = b := by simp
    rw [hb, show dRun d ([] : List x64_ir.PInsn) = d from rfl]
    exact blockOk_nil (fun _ hx => hx)
  | cons i rest ih =>
    intro b d hd hE hok
    obtain ⟨hone, hrest⟩ := hok
    have hc : code[b]? = some i := by
      have := hE 0 (by simp)
      simpa using this
    have hE' : ∀ k, k < rest.length → code[(b + 1) + k]? = rest[k]? := by
      intro k hk
      have := hE (k + 1) (by simp only [List.length_cons]; omega)
      simpa [Nat.add_comm, Nat.add_assoc, Nat.add_left_comm] using this
    have hlen : b + (i :: rest).length = (b + 1) + rest.length := by
      simp only [List.length_cons]; omega
    have hstep : BlockOk P code b (b + 1) pre W W d (dStep d i) := by
      match i with
      | .Push r => exact blockOk_push hL hc hone (fun _ hx => hx)
      | .Pushfq => exact blockOk_pushfq hL hc hone (fun _ hx => hx)
      | .Pop r =>
        obtain ⟨h1, h2⟩ := hone
        obtain ⟨e, rfl⟩ : ∃ e, d = e + 1 := ⟨d - 1, by omega⟩
        rw [show dStep (e + 1) (x64_ir.PInsn.Pop r) = e from by simp [dStep]]
        exact blockOk_pop hL hc hd h2 (fun _ hx => hx) hW4 hW5
      | .Popfq =>
        obtain ⟨e, rfl⟩ : ∃ e, d = e + 1 := ⟨d - 1, by omega⟩
        rw [show dStep (e + 1) x64_ir.PInsn.Popfq = e from by simp [dStep]]
        exact blockOk_popfq hL hc hd (fun _ hx => hx)
      | .PcLabel _ | .Local _ | .ExitLabel | .RetpolineLabel | .Pause | .Alu _ _ _ _
      | .AluImm _ _ _ _ | .ShiftImm _ _ _ _ | .ShiftCl _ _ _ | .Neg _ _ | .MovSx _ _ _ _
      | .Bswap _ _ | .Rol16 _ | .Cmov _ _ _ | .LoadImm _ _ | .Cqo | .Cdq
      | .CmpRcxMinusOne _ | .CmpEaxImm _ | .MulDivRcx _ _ _ | .RipLoadDispatcher _
      | .RipLeaHelperTable _ =>
        exact blockOk_regOnly hone.1 hc hone.2 (fun _ hx => hx) hW4 hW5
      | .Load _ _ _ _ _ | .Store _ _ _ _ | .StoreImm _ _ _ _ | .AluRM _ _ _ _
      | .StoreRspImm _ | .StoreRspRax | .LockAlu _ _ _ _ _ | .LockCmpxchg _ _ _ _
      | .Xchg _ _ _ _ | .Jcc _ _ | .Jmp _ | .JmpNear _ | .Call _ | .Jcc8 _ _ | .Jmp8 _
      | .Ret | .Ud2 | .CallReg _ | .DispatcherSlot _ | .HelperTable =>
        exact absurd hone.1 not_false
    have hdstep : dStep d i ≤ 16 := by
      match i with
      | .Push _ => exact hone
      | .Pushfq => exact hone
      | .Pop _ => simp only [dStep]; omega
      | .Popfq => simp only [dStep]; omega
      | .PcLabel _ | .Local _ | .ExitLabel | .RetpolineLabel | .Pause | .Alu _ _ _ _
      | .AluImm _ _ _ _ | .ShiftImm _ _ _ _ | .ShiftCl _ _ _ | .Neg _ _ | .MovSx _ _ _ _
      | .Bswap _ _ | .Rol16 _ | .Cmov _ _ _ | .LoadImm _ _ | .Cqo | .Cdq
      | .CmpRcxMinusOne _ | .CmpEaxImm _ | .MulDivRcx _ _ _ | .RipLoadDispatcher _
      | .RipLeaHelperTable _ | .Load _ _ _ _ _ | .Store _ _ _ _ | .StoreImm _ _ _ _
      | .AluRM _ _ _ _ | .StoreRspImm _ | .StoreRspRax | .LockAlu _ _ _ _ _
      | .LockCmpxchg _ _ _ _ | .Xchg _ _ _ _ | .Jcc _ _ | .Jmp _ | .JmpNear _ | .Call _
      | .Jcc8 _ _ | .Jmp8 _ | .Ret | .Ud2 | .CallReg _ | .DispatcherSlot _
      | .HelperTable => exact hd
    rw [hlen, show dRun d (i :: rest) = dRun (dStep d i) rest from rfl]
    exact blockOk_seq hstep (ih (b + 1) (dStep d i) hdstep hE' hrest)

/-! ## Regions of constant depth

The branchy part of an expansion — the signed overflow block of a divide, the
compare-exchange loop of a fetch-and-op — never moves `rsp`, so the context is
the same at every position of it and the invariant does not have to track
where control is. What it has to check is that every branch lands back inside,
and that every dereference goes through a register the region has not written.

`GuestTag` is the address rule, phrased so that it survives re-execution: it
speaks of the *pre*-state tag, so it holds of the base register at every
position of the region that has not written it. -/

/-- Whatever a register carrying this tag holds, the access through it is a
guest access, and a *write* through it is one this activation may make. This
is what `addr_ok` establishes: the three cases of the address rule are the
three cases of `tagOk_checked_window`/`frame_access_ok` for the read and of
`tagOk_checked_store`/`frame_store_ok` for the write, under the same
side-conditions. -/
def GuestTag (P : Params) (pre : x64_check.State) (base : Std.U8) (disp : Std.I32)
    (n : Nat) : Prop :=
  ∀ v : Word, TagOk P (tagAt pre base.val) v →
    GuestOk P (v + BitVec.signExtend 64 disp.bv) n ∧
      StoreOk P (v + BitVec.signExtend 64 disp.bv) n

/-- What a primitive of a constant-depth region has to be. -/
def FlatOk (P : Params) (code : List x64_ir.PInsn) (pre : x64_check.State) (b e : Nat)
    (W : Nat → Prop) : x64_ir.PInsn → Prop
  | .Jcc8 _ n => ∃ j, pos code (.Local n) = some j ∧ b ≤ j ∧ j ≤ e
  | .Jmp8 n => ∃ j, pos code (.Local n) = some j ∧ b ≤ j ∧ j ≤ e
  | .Load size sx base dst disp =>
      sx = false ∧ W dst.val ∧ base.val ≠ RSP ∧ ¬ W base.val ∧
        GuestTag P pre base disp size.val
  | .LockCmpxchg w64 _ base disp =>
      W RAX ∧ base.val ≠ RSP ∧ ¬ W base.val ∧ GuestTag P pre base disp (opWidth w64)
  | j => RegOnly j ∧ ∀ r ∈ writes j, W r

@[simp] theorem accesses_jcc8 (cc n s) : accesses (.Jcc8 cc n) s = [] := rfl
@[simp] theorem accesses_jmp8 (n s) : accesses (.Jmp8 n) s = [] := rfl

/-- `FlatOk`, read as the five shapes it admits. -/
theorem flatOk_cases {P : Params} {code : List x64_ir.PInsn} {pre : x64_check.State} {b e : Nat}
    {W : Nat → Prop} {i : x64_ir.PInsn} (hf : FlatOk P code pre b e W i) :
    (RegOnly i ∧ ∀ r ∈ writes i, W r) ∨
    (∃ cc n, i = .Jcc8 cc n ∧ ∃ j, pos code (.Local n) = some j ∧ b ≤ j ∧ j ≤ e) ∨
    (∃ n, i = .Jmp8 n ∧ ∃ j, pos code (.Local n) = some j ∧ b ≤ j ∧ j ≤ e) ∨
    (∃ (size base dst : Std.U8) (disp : Std.I32), i = .Load size false base dst disp ∧
      W dst.val ∧ base.val ≠ RSP ∧ ¬ W base.val ∧ GuestTag P pre base disp size.val) ∨
    (∃ (w64 : Bool) (src base : Std.U8) (disp : Std.I32), i = .LockCmpxchg w64 src base disp ∧
      W RAX ∧ base.val ≠ RSP ∧ ¬ W base.val ∧ GuestTag P pre base disp (opWidth w64)) := by
  unfold FlatOk at hf
  split at hf
  · rename_i cc n
    exact Or.inr (Or.inl ⟨cc, n, rfl, hf⟩)
  · rename_i n
    exact Or.inr (Or.inr (Or.inl ⟨n, rfl, hf⟩))
  · rename_i size sx base dst disp
    obtain ⟨rfl, h2, h3, h4, h5⟩ := hf
    exact Or.inr (Or.inr (Or.inr (Or.inl ⟨size, base, dst, disp, rfl, h2, h3, h4, h5⟩)))
  · rename_i w64 src base disp
    obtain ⟨h1, h2, h3, h4⟩ := hf
    exact Or.inr (Or.inr (Or.inr (Or.inr ⟨w64, src, base, disp, rfl, h1, h2, h3, h4⟩)))
  · exact Or.inl hf

/-- Running a region of constant depth whose branches all land inside it. -/
theorem blockOk_flat {P : Params} {code : List x64_ir.PInsn} {b e : Nat}
    {pre : x64_check.State} {W : Nat → Prop} {d : Nat} (hL : Layout P) (hbe : b ≤ e)
    (hW4 : ¬ W RSP) (hW5 : ¬ W RBP)
    (hins : ∀ k, b ≤ k → k < e → ∀ i, code[k]? = some i → FlatOk P code pre b e W i) :
    BlockOk P code b e pre W W d d := by
  -- Safety, one position at a time.
  have hsafe : ∀ t : State, Range b e t.pc → Ctx P pre W d t → ∀ i, code[t.pc]? = some i →
      ∀ bn ∈ accesses i t, AccessOk P bn.1 bn.2 := by
    intro t hr hct i hi bn hbn
    rcases flatOk_cases (hins t.pc hr.1 hr.2 i hi) with
      ⟨hro, -⟩ | ⟨cc, n, rfl, -⟩ | ⟨n, rfl, -⟩ |
      ⟨size, base, dst, disp, rfl, -, hbrsp, hbW, hg⟩ |
      ⟨w64, src, base, disp, rfl, -, hbrsp, hbW, hg⟩
    · rw [accesses_regOnly hro] at hbn; simp at hbn
    · simp at hbn
    · simp at hbn
    · rw [accesses_load, if_neg (by simp)] at hbn
      simp only [List.mem_singleton] at hbn
      subst hbn
      exact (hg (t.regs base.val) (hct.regs base.val hbrsp hbW)).1.access
    · simp only [accesses_lockCmpxchg, List.mem_singleton] at hbn
      subst hbn
      exact (hg (t.regs base.val) (hct.regs base.val hbrsp hbW)).1.access
  -- And what it writes: only the compare-exchange writes at all, and it
  -- writes through the checked base the address rule already placed.
  have hstore : ∀ t : State, Range b e t.pc → Ctx P pre W d t → ∀ i, code[t.pc]? = some i →
      ∀ bn ∈ stores i t, StoreOk P bn.1 bn.2 := by
    intro t hr hct i hi bn hbn
    rcases flatOk_cases (hins t.pc hr.1 hr.2 i hi) with
      ⟨hro, -⟩ | ⟨cc, n, rfl, -⟩ | ⟨n, rfl, -⟩ |
      ⟨size, base, dst, disp, rfl, -, hbrsp, hbW, hg⟩ |
      ⟨w64, src, base, disp, rfl, -, hbrsp, hbW, hg⟩
    · rw [stores_regOnly hro] at hbn; simp at hbn
    · rw [show stores (.Jcc8 cc n) t = [] from rfl] at hbn; simp at hbn
    · rw [show stores (.Jmp8 n) t = [] from rfl] at hbn; simp at hbn
    · rw [stores_load] at hbn; simp at hbn
    · simp only [stores_lockCmpxchg, List.mem_singleton] at hbn
      subst hbn
      exact (hg (t.regs base.val) (hct.regs base.val hbrsp hbW)).2
  -- One step inside the region.
  have hone : ∀ t t' : State, Range b e t.pc → Ctx P pre W d t → Step P code t (.next t') →
      Ctx P pre W d t' ∧ b ≤ t'.pc ∧ t'.pc ≤ e := by
    intro t t' hr hct hst
    have hr1 : b ≤ t.pc := hr.1
    have hr2 : t.pc < e := hr.2
    obtain ⟨i, hi⟩ := step_fetch hst
    rcases flatOk_cases (hins t.pc hr.1 hr.2 i hi) with
      ⟨hro, hwr⟩ | ⟨cc, n, rfl, j, hj, hj1, hj2⟩ | ⟨n, rfl, j, hj, hj1, hj2⟩ |
      ⟨size, base, dst, disp, rfl, hdst, hbrsp, hbW, hg⟩ |
      ⟨w64, src, base, disp, rfl, hax, hbrsp, hbW, hg⟩
    · obtain ⟨u, hu, hpc, hmem, hregs⟩ := step_regOnly hro hi hst
      cases hu
      refine ⟨⟨?_, hct.bound, ?_, ?_, ?_, ?_⟩, by omega, by omega⟩
      · rw [hregs RSP (fun hx => hW4 (hwr RSP hx))]; exact hct.rsp
      · rw [hregs RBP (fun hx => hW5 (hwr RBP hx))]; exact hct.rbp
      · intro r hrne hWr
        rw [hregs r (fun hx => hWr (hwr r hx))]
        exact hct.regs r hrne hWr
      · rw [hmem]; exact hct.ro
      · rw [hmem]; exact hct.group
    · rcases step_jcc8 hi hst with ⟨-, i', hi', hu⟩ | ⟨-, hu⟩
      · simp only [Config.next.injEq] at hu
        subst hu
        rw [hj] at hi'
        simp only [Option.some.injEq] at hi'
        subst hi'
        exact ⟨⟨hct.rsp, hct.bound, hct.rbp, hct.regs, hct.ro, hct.group⟩, by omega, by omega⟩
      · simp only [Config.next.injEq] at hu
        subst hu
        exact ⟨⟨hct.rsp, hct.bound, hct.rbp, hct.regs, hct.ro, hct.group⟩,
          by simp only [wNext]; omega, by simp only [wNext]; omega⟩
    · obtain ⟨i', hi', hu⟩ := step_jmp8 hi hst
      simp only [Config.next.injEq] at hu
      subst hu
      rw [hj] at hi'
      simp only [Option.some.injEq] at hi'
      subst hi'
      exact ⟨⟨hct.rsp, hct.bound, hct.rbp, hct.regs, hct.ro, hct.group⟩, by omega, by omega⟩
    · rcases step_load hi hst with ⟨-, hu⟩ | ⟨hbad, -, -⟩
      · simp only [Config.next.injEq] at hu
        subst hu
        refine ⟨⟨?_, hct.bound, ?_, ?_, hct.ro, hct.group⟩, by simp only [wReg]; omega,
          by simp only [wReg]; omega⟩
        · show Function.update t.regs dst.val _ RSP = _
          rw [Function.update_of_ne (fun hx => hW4 (by rw [hx]; exact hdst))]
          exact hct.rsp
        · show Function.update t.regs dst.val _ RBP = _
          rw [Function.update_of_ne (fun hx => hW5 (by rw [hx]; exact hdst))]
          exact hct.rbp
        · intro r hrne hWr
          show TagOk P (tagAt pre r) (Function.update t.regs dst.val _ r)
          rw [Function.update_of_ne (fun hx => hWr (by rw [hx]; exact hdst))]
          exact hct.regs r hrne hWr
      · simp at hbad
    · obtain ⟨f, hu⟩ := step_lockCmpxchg hi hst
      simp only [Config.next.injEq] at hu
      subst hu
      have hgok : GuestOk P (addr t base disp) (opWidth w64) :=
        (hg (t.regs base.val) (hct.regs base.val hbrsp hbW)).1
      simp only [cmpxchgStep]
      split
      · refine ⟨⟨hct.rsp, hct.bound, hct.rbp, hct.regs, ?_, ?_⟩,
          by show b ≤ t.pc + 1; omega, by show t.pc + 1 ≤ e; omega⟩
        · exact romem_store_guest hL hct.ro hgok
        · simpa only [groupBase_kept hL hgok] using hct.group
      · refine ⟨⟨?_, hct.bound, ?_, ?_, hct.ro, hct.group⟩,
          by show b ≤ t.pc + 1; omega, by show t.pc + 1 ≤ e; omega⟩
        · simp only []
          rw [Function.update_of_ne (show RSP ≠ RAX by decide)]
          exact hct.rsp
        · simp only []
          rw [Function.update_of_ne (show RBP ≠ RAX by decide)]
          exact hct.rbp
        · intro r hrne hWr
          simp only []
          rw [Function.update_of_ne (fun hx => hWr (by rw [hx]; exact hax))]
          exact hct.regs r hrne hWr
  refine ⟨hbe, fun s hs hcx => ⟨fun _ => hcx, fun s' hsty => ?_⟩⟩
  have hI : Ctx P pre W d s' := by
    refine stays_invariant (I := fun t => Ctx P pre W d t) hcx ?_ hsty
    intro t t' ht hin hst _
    exact (hone t t' hin ht hst).1
  have hin' : Range b e s'.pc := hsty.inside_last
  refine ⟨fun c hst i hi bn hbn => hsafe s' hin' hI i hi bn hbn,
    fun c hst i hi bn hbn => hstore s' hin' hI i hi bn hbn,
    ⟨d, hI.bound, hI.rsp⟩, ?_, ?_⟩
  · intro s'' hst hout
    obtain ⟨hc2, h1, h2⟩ := hone s' s'' hin' hI hst
    simp only [Range, not_and, not_lt] at hout
    have hin1 : b ≤ s'.pc := hin'.1
    exact ⟨by omega, hc2⟩
  · intro s'' hst
    obtain ⟨hr, -, -⟩ := step_returned_ret hst
    rcases flatOk_cases (hins s'.pc hin'.1 hin'.2 _ hr) with
      ⟨hro, -⟩ | ⟨cc, n, hbad, -⟩ | ⟨n, hbad, -⟩ | ⟨_, _, _, _, hbad, -⟩ | ⟨_, _, _, _, hbad, -⟩
    · exact hro
    · exact absurd hbad (by simp)
    · exact absurd hbad (by simp)
    · exact absurd hbad (by simp)
    · exact absurd hbad (by simp)

/-! ## From a balanced block to the macro contract -/

/-- A region that starts and ends at the depth the walk came in at, and whose
registers the rule turned into `Top`, is one macro's contract. -/
theorem macroOk_of_blockOk {P : Params} {code : List x64_ir.PInsn} {p q : Nat}
    {pre post : x64_check.State} {Win Wout S : Nat → Prop} (hL : Layout P)
    (hS : SetsTop pre post S) (hWS : ∀ r, Wout r → S r)
    (h : ∀ s₀ : State, Agree P pre s₀ →
      BlockOk P code p q pre Win Wout pre.depth.val pre.depth.val) :
    MacroOk P code p q pre post [] := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro s hs hag s' hsty c hst i hi bn hbn
    exact (((h s hag).2 s hs (agree_ctx hag Win)).2 s' hsty).1 c hst i hi bn hbn
  · intro s hs hag s' hsty s'' hst hout
    obtain ⟨hpc, hct⟩ := (((h s hag).2 s hs (agree_ctx hag Win)).2 s' hsty).2.2.2.1 s'' hst hout
    exact Or.inl ⟨hpc, ctx_agree hag hS hWS hct⟩
  · intro s hs hag s' hsty s'' hst
    exact absurd hst ((((h s hag).2 s hs (agree_ctx hag Win)).2 s' hsty).2.2.2.2 s'')
  · intro s hs hag s' hsty c hst i hi bn hbn
    exact (((h s hag).2 s hs (agree_ctx hag Win)).2 s' hsty).2.1 c hst i hi bn hbn
  · exact macroOk_rsp_of_window hL (fun s hs hag s' hsty =>
      (((h s hag).2 s hs (agree_ctx hag Win)).2 s' hsty).2.2.1)

/-- Reading a three-way split of one macro's expansion off the list. -/
theorem code_split {code : List x64_ir.PInsn} {p : Nat} {A M B : List x64_ir.PInsn}
    (hE : ∀ k, k < (A ++ M ++ B).length → code[p + k]? = (A ++ M ++ B)[k]?) :
    (∀ k, k < A.length → code[p + k]? = A[k]?) ∧
    (∀ k, k < M.length → code[(p + A.length) + k]? = M[k]?) ∧
    (∀ k, k < B.length → code[(p + A.length + M.length) + k]? = B[k]?) := by
  refine ⟨fun k hk => ?_, fun k hk => ?_, fun k hk => ?_⟩
  · rw [hE k (by simp only [List.length_append]; omega)]
    rw [List.getElem?_append_left (by simp only [List.length_append]; omega), List.getElem?_append_left hk]
  · have h := hE (A.length + k) (by simp only [List.length_append]; omega)
    rw [show p + (A.length + k) = p + A.length + k from by omega] at h
    rw [h, List.getElem?_append_left (by simp only [List.length_append]; omega),
      List.getElem?_append_right (by omega)]
    simp
  · have h := hE (A.length + M.length + k) (by simp only [List.length_append]; omega)
    rw [show p + (A.length + M.length + k) = p + A.length + M.length + k from by omega] at h
    rw [h, List.getElem?_append_right (by simp only [List.length_append]; omega)]
    simp

/-! ## `MulDivMod`

The rule is `depth_ok(st, 4)` and a write of `dst`, `rax`, `rcx`, `rdx` and
`r11`; the expansion pushes at most those four words — `rax`, `rdx`, `rax`
again for a modulo, and the flags — and pops every one of them back. The
pushes and pops are two straight lines with the signed overflow block, the
divide and the label it jumps to in between, and that middle is at one
depth. -/

theorem rcx_val : (x64_ir.RCX).val = RCX := by rw [x64_ir.RCX]; rfl
theorem rdx_val : (x64_ir.RDX).val = RDX := by rw [x64_ir.RDX]; rfl
theorem r10_val : (x64_ir.R10).val = R10 := by rw [x64_ir.R10]; rfl
theorem r11_val : (x64_ir.R11).val = R11 := by rw [x64_ir.R11]; rfl

/-- The registers the `MulDivMod` rule gives up. -/
def mdWrites (dst : Std.U8) : Nat → Prop :=
  fun r => r = dst.val ∨ r = RAX ∨ r = RCX ∨ r = RDX ∨ r = R11

/-- The registers the `AtomicFetchAlu` rule gives up. -/
def afaWrites (src : Std.U8) : Nat → Prop :=
  fun r => r = src.val ∨ r = RAX ∨ r = RCX ∨ r = R10 ∨ r = R11

/-- Resolving a local label of one macro's expansion, from the fact that its
own `Local` primitive is one of the expansion's. -/
theorem local_inside {code : List x64_ir.PInsn} {p : Nat} {A M B : List x64_ir.PInsn}
    (hpos : ∀ (n : Std.U32) (j : Nat), (A ++ M ++ B)[j]? = some (.Local n) →
      pos code (.Local n) = some (p + j)) :
    ∀ n : Std.U32, (x64_ir.PInsn.Local n) ∈ M →
      ∃ j, pos code (.Local n) = some j ∧
        p + A.length ≤ j ∧ j ≤ p + A.length + M.length := by
  intro n hmem
  obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hmem
  have hjlt : j < M.length := by
    by_contra hc
    rw [List.getElem?_eq_none (by omega)] at hj
    simp at hj
  refine ⟨p + (A.length + j), ?_, by omega, by omega⟩
  refine hpos n (A.length + j) ?_
  rw [List.getElem?_append_left (by simp only [List.length_append]; omega),
    List.getElem?_append_right (by omega)]
  simpa using hj

/-! ### Reading the two lists

`dRun` and `LineOk` both distribute over `++` and over the conditionals the
expansion is built from, which is what keeps the case analysis below linear in
the number of conditions rather than exponential. -/

@[simp] theorem dRun_nil (d : Nat) : dRun d [] = d := rfl

theorem dRun_cons (d : Nat) (i : x64_ir.PInsn) (L : List x64_ir.PInsn) :
    dRun d (i :: L) = dRun (dStep d i) L := rfl

@[simp] theorem dRun_append (d : Nat) (X Y : List x64_ir.PInsn) :
    dRun d (X ++ Y) = dRun (dRun d X) Y := by
  induction X generalizing d with
  | nil => rfl
  | cons i r ih => simp only [List.cons_append, dRun_cons, ih]

@[simp] theorem dRun_ite (c : Prop) [Decidable c] (X Y : List x64_ir.PInsn) (d : Nat) :
    dRun d (if c then X else Y) = if c then dRun d X else dRun d Y := by
  split <;> rfl

@[simp] theorem lineOk_nil (W : Nat → Prop) (d : Nat) : LineOk W d [] := trivial

@[simp] theorem lineOk_append (W : Nat → Prop) (d : Nat) (X Y : List x64_ir.PInsn) :
    LineOk W d (X ++ Y) ↔ (LineOk W d X ∧ LineOk W (dRun d X) Y) := by
  induction X generalizing d with
  | nil => simp [LineOk]
  | cons i r ih =>
    simp only [List.cons_append, LineOk, dRun_cons, ih, and_assoc]

@[simp] theorem lineOk_ite (W : Nat → Prop) (c : Prop) [Decidable c] (X Y : List x64_ir.PInsn)
    (d : Nat) : LineOk W d (if c then X else Y) ↔ if c then LineOk W d X else LineOk W d Y := by
  split <;> rfl

/-- The simp set that reduces one of the two expansions to primitives. -/
private theorem mulDiv_lineA (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) (d : Nat) (hd : d + 4 ≤ 16) :
    LineOk (mdWrites dst) d (mulDivSetupList kind w64 reg signed src dst imm) := by
  cases kind <;>
    simp only [mulDivSetupList, mdIsDiv, mdIsMod, Bool.or_self, Bool.or_false,
      Bool.false_or, if_true, lineOk_append, lineOk_ite, dRun_ite, dRun_append,
      dRun_nil, LineOk, dRun_cons, dStep, RegOnly, writes, mdWrites, rax_val,
      rcx_val, rdx_val, List.mem_cons, List.not_mem_nil, or_false,
      true_and, and_true, ite_self] <;>
    split_ifs <;>
    and_intros <;>
    first | trivial | omega

private theorem mulDiv_dRunA (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) (d : Nat) :
    dRun d (mulDivSetupList kind w64 reg signed src dst imm) ≤ d + 4 := by
  cases kind <;>
    simp only [mulDivSetupList, mdIsDiv, mdIsMod, Bool.or_self, Bool.or_false,
      Bool.false_or, if_true, dRun_ite, dRun_append, dRun_nil, dRun_cons, dStep,
      ite_self] <;>
    split_ifs <;> omega

private theorem mulDiv_lineB (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) (d : Nat) (hd : d + 4 ≤ 16) :
    LineOk (mdWrites dst) (dRun d (mulDivSetupList kind w64 reg signed src dst imm))
      (mulDivFinishList kind dst) := by
  cases kind <;>
    simp only [mulDivSetupList, mulDivFinishList, mdIsDiv, mdIsMod, mdIsMul, Bool.or_self,
      Bool.or_false, Bool.false_or, if_true, lineOk_append, lineOk_ite, dRun_ite,
      dRun_append, dRun_nil, LineOk, dRun_cons, dStep, RegOnly, writes, mdWrites,
      rax_val, rcx_val, rdx_val, List.mem_cons, List.not_mem_nil, or_false,
      true_and, and_true, ite_self] <;>
    split_ifs <;>
    and_intros <;>
    first | trivial | omega | simp

private theorem mulDiv_finB (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) (d : Nat) :
    dRun (dRun d (mulDivSetupList kind w64 reg signed src dst imm))
      (mulDivFinishList kind dst) = d := by
  cases kind <;>
    simp only [mulDivSetupList, mulDivFinishList, mdIsDiv, mdIsMod, mdIsMul, Bool.or_self,
      Bool.or_false, Bool.false_or, if_true, dRun_ite, dRun_append, dRun_nil,
      dRun_cons, dStep, ite_self] <;>
    split_ifs <;> first | exact (‹False›).elim | omega

private theorem mulDiv_flat {P : Params} {code : List x64_ir.PInsn} {pre : x64_check.State}
    {kind : x64_ir.MulDivKind} {w64 signed : Bool} {dst : Std.U8} {label b e : Nat}
    (hposM : ∀ n : Std.U32, (x64_ir.PInsn.Local n) ∈ mulDivMidList kind w64 signed label →
      ∃ j, pos code (.Local n) = some j ∧ b ≤ j ∧ j ≤ e)
    (i : x64_ir.PInsn) (hmem : i ∈ mulDivMidList kind w64 signed label) :
    FlatOk P code pre b e (mdWrites dst) i := by
  revert hmem
  cases kind <;> cases signed <;> cases w64 <;>
    simp only [mulDivMidList, mulDivOverflowList, mdIsDiv, mdIsMod, Bool.or_self,
      Bool.or_false, Bool.false_or, Bool.and_true, Bool.and_false, if_true,
      List.cons_append, List.nil_append] <;>
    intro hmem <;> fin_cases hmem <;>
    first
      | exact ⟨trivial, by simp [writes, mdWrites, rax_val, rdx_val, r11_val]⟩
      | exact hposM _ (by
          simp [mulDivMidList, mulDivOverflowList, mdIsDiv, mdIsMod])

/-! ### The contract

`live_step` for `MulDivMod` bounds the depth by four and turns `dst`, `rax`,
`rcx`, `rdx` and `r11` into `Top`; the expansion pushes at most those four
words and pops every one of them back, writes only those five registers, and
touches no guest memory. -/

/-- The body of `MulDivMod` that is not the immediate-zero short circuit:
setup, the branchy middle, the unwind. -/
private theorem macroOk_mulDivMod_main {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {pre post : x64_check.State} {kind : x64_ir.MulDivKind} {w64 reg signed : Bool}
    {src dst : Std.U8} {imm : Std.I32} {label : Nat}
    (hL : Layout P) (hdep : pre.depth.val + 4 ≤ 16) (hwr : Writable dst.val)
    (hS : SetsTop pre post (mdWrites dst))
    (hE : ∀ k, k < (mulDivSetupList kind w64 reg signed src dst imm ++
        mulDivMidList kind w64 signed label ++ mulDivFinishList kind dst).length →
      code[p + k]? = (mulDivSetupList kind w64 reg signed src dst imm ++
        mulDivMidList kind w64 signed label ++ mulDivFinishList kind dst)[k]?)
    (hpos : ∀ (n : Std.U32) (j : Nat),
      (mulDivSetupList kind w64 reg signed src dst imm ++
        mulDivMidList kind w64 signed label ++ mulDivFinishList kind dst)[j]? = some (.Local n) →
      pos code (.Local n) = some (p + j)) :
    MacroOk P code p (p + (mulDivSetupList kind w64 reg signed src dst imm ++
      mulDivMidList kind w64 signed label ++ mulDivFinishList kind dst).length) pre post [] := by
  have hW4 : ¬ mdWrites dst RSP := by
    rintro (h | h | h | h | h)
    · exact hwr.1 h.symm
    all_goals exact absurd h (by decide)
  have hW5 : ¬ mdWrites dst RBP := by
    rintro (h | h | h | h | h)
    · exact hwr.2.1 h.symm
    all_goals exact absurd h (by decide)
  obtain ⟨hEA, hEM, hEB⟩ := code_split hE
  have hposM := local_inside hpos
  have hdA16 : dRun pre.depth.val (mulDivSetupList kind w64 reg signed src dst imm) ≤ 16 := by
    have := mulDiv_dRunA kind w64 reg signed src dst imm pre.depth.val
    omega
  have h1 : BlockOk P code p (p + (mulDivSetupList kind w64 reg signed src dst imm).length) pre
      (mdWrites dst) (mdWrites dst) pre.depth.val
      (dRun pre.depth.val (mulDivSetupList kind w64 reg signed src dst imm)) :=
    blockOk_line hL hW4 hW5 _ p pre.depth.val (by omega) hEA
      (mulDiv_lineA kind w64 reg signed src dst imm pre.depth.val hdep)
  have h2 : BlockOk P code (p + (mulDivSetupList kind w64 reg signed src dst imm).length)
      (p + (mulDivSetupList kind w64 reg signed src dst imm).length +
        (mulDivMidList kind w64 signed label).length) pre (mdWrites dst) (mdWrites dst)
      (dRun pre.depth.val (mulDivSetupList kind w64 reg signed src dst imm))
      (dRun pre.depth.val (mulDivSetupList kind w64 reg signed src dst imm)) := by
    refine blockOk_flat hL (by omega) hW4 hW5 ?_
    intro k hk1 hk2 i hi
    refine mulDiv_flat hposM i ?_
    have hj : k = (p + (mulDivSetupList kind w64 reg signed src dst imm).length) +
        (k - (p + (mulDivSetupList kind w64 reg signed src dst imm).length)) := by omega
    rw [hj, hEM _ (by omega)] at hi
    exact List.mem_of_getElem? hi
  have h3 := blockOk_line (P := P) (pre := pre) hL hW4 hW5 (mulDivFinishList kind dst)
      (p + (mulDivSetupList kind w64 reg signed src dst imm).length +
        (mulDivMidList kind w64 signed label).length)
      (dRun pre.depth.val (mulDivSetupList kind w64 reg signed src dst imm)) hdA16 hEB
      (mulDiv_lineB kind w64 reg signed src dst imm pre.depth.val hdep)
  rw [mulDiv_finB kind w64 reg signed src dst imm pre.depth.val] at h3
  have hall := blockOk_seq h1 (blockOk_seq h2 h3)
  rw [show p + (mulDivSetupList kind w64 reg signed src dst imm ++
      mulDivMidList kind w64 signed label ++ mulDivFinishList kind dst).length
      = p + (mulDivSetupList kind w64 reg signed src dst imm).length +
        (mulDivMidList kind w64 signed label).length + (mulDivFinishList kind dst).length from by
    simp only [List.length_append]; omega]
  exact macroOk_of_blockOk hL hS (fun r h => h) (fun _ _ => hall)

/-- `MInsn.MulDivMod`: the multiply/divide/modulo macro.

`hE` reads the expansion off the primitive list at `p`, and `hpos` says that
every local label the expansion emits resolves to its own position in it,
which is what `AsyncEbpf/X64/Expand.lean` establishes of a chunk's locals. -/
theorem macroOk_mulDivMod {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {kind : x64_ir.MulDivKind} {w64 reg signed : Bool}
    {src dst : Std.U8} {imm : Std.I32} {label : Nat} {index : Std.Usize} {pcv : Std.U32}
    (hL : Layout P) (hlive : pre.alive = true)
    (hstep : x64_check.live_step cfg (.MulDivMod kind w64 reg signed src dst imm) index pcv pre
      = ok (.Ok (), post))
    (hE : ∀ k, k < (mulDivModList kind w64 reg signed src dst imm label).length →
      code[p + k]? = (mulDivModList kind w64 reg signed src dst imm label)[k]?)
    (hpos : ∀ (n : Std.U32) (j : Nat),
      (mulDivModList kind w64 reg signed src dst imm label)[j]? = some (.Local n) →
      pos code (.Local n) = some (p + j)) :
    MacroOk P code p
      (p + (mulDivModList kind w64 reg signed src dst imm label).length) pre post [] := by
  obtain ⟨hdep, hwr, hS⟩ := live_step_MulDivMod_spec hlive hstep
  have hS' : SetsTop pre post (mdWrites dst) := hS
  have hW4 : ¬ mdWrites dst RSP := by
    rintro (h | h | h | h | h)
    · exact hwr.1 h.symm
    all_goals exact absurd h (by decide)
  have hW5 : ¬ mdWrites dst RBP := by
    rintro (h | h | h | h | h)
    · exact hwr.2.1 h.symm
    all_goals exact absurd h (by decide)
  rw [mulDivModList] at hE hpos ⊢
  cases reg
  · -- an immediate operand
    simp only [Bool.false_eq_true, if_false] at hE hpos ⊢
    by_cases himm : imm = 0#i32
    · -- by zero: one register-only primitive
      rw [if_pos himm] at hE hpos ⊢
      have hone : ∀ i : x64_ir.PInsn, RegOnly i → writes i = [dst.val] →
          code[p]? = some i →
          MacroOk P code p (p + [i].length) pre post [] := by
        intro i hro hwrs hc
        refine macroOk_of_blockOk (Win := mdWrites dst) hL hS' (fun r h => h) (fun _ _ => ?_)
        have := blockOk_regOnly (P := P) (pre := pre) (Win := mdWrites dst)
          (Wout := mdWrites dst) (d := pre.depth.val) hro hc
          (by rw [hwrs]; intro r hr; simp at hr; exact Or.inl hr) (fun _ hx => hx) hW4 hW5
        simpa using this
      by_cases hk : mdIsDiv kind || mdIsMul kind
      · rw [if_pos hk] at hE hpos ⊢
        exact hone _ trivial rfl (by simpa using hE 0 (by simp))
      · rw [if_neg hk] at hE hpos ⊢
        exact hone _ trivial rfl (by simpa using hE 0 (by simp))
    · rw [if_neg himm] at hE hpos ⊢
      exact macroOk_mulDivMod_main hL hdep hwr hS' hE hpos
  · simp only [if_true] at hE hpos ⊢
    exact macroOk_mulDivMod_main hL hdep hwr hS' hE hpos

/-! ## `AtomicFetchAlu`

x86 has no atomic fetch-and-and/or/xor, so the backend emulates all four with
a compare-exchange loop. The rule checks the address once, against the
pre-state, and the loop then re-executes it; what makes that sound is that the
base register is not one the region writes, which is why `GuestTag` speaks of
the pre-state tag.

`base ≠ rax` and `base ≠ rcx` are hypotheses rather than facts: see the note
at the head of this file. -/

theorem i32_eq_iff_val {x y : Std.I32} : x = y ↔ x.val = y.val := by scalar_tac

theorem u8_val_ne {x y : Std.U8} (h : x ≠ y) : x.val ≠ y.val := by
  intro he; exact h (by scalar_tac)

/-- The address rule, as the fact a region can re-use at every position: a
register carrying this tag holds an address whose access is a guest one. -/
theorem guestTag_of_addrOk {P : Params} {cfg : x64_ir.Cfg} {pre : x64_check.State}
    {base : Std.U8} {disp : Std.I32} {n : Nat} (hL : Layout P) (hcfg : CfgOk P cfg)
    (hwid : WidthsOk pre) (hcage : cfg.pointer_mask ≠ 0#i32)
    (h : AddrOk cfg pre base disp.val n) : GuestTag P pre base disp n := by
  intro v hv
  rcases h with hz | ⟨w, hw, h1, h2⟩ | ⟨hb, hfp, -, -, h1, h2⟩
  · exact absurd (i32_eq_iff_val.mpr (by simpa using hz)) hcage
  · rw [hw] at hv
    exact ⟨tagOk_checked_window hL hv h1 (by omega) (hwid.1 base.val w hw),
      tagOk_checked_store hL hv h1 (by omega) (hwid.1 base.val w hw)⟩
  · rw [hb, hfp] at hv
    exact ⟨frame_access_ok hL hv (by rw [← hcfg]; exact h1) (by omega),
      frame_store_ok hL hv (by rw [← hcfg]; exact h1) (by omega)⟩

/-- `rsp` never carries a `Checked` tag that a macro could dereference
through: the native stack window is clear of both guest backings, and a
parked zero is ruled out by the room the entry contract leaves below `rsp`. -/
theorem checked_ne_rsp {P : Params} {pre : x64_check.State} {s : State} {w : Std.U32}
    (hL : Layout P) (hag : Agree P pre s) (hd : pre.depth.val + 1 ≤ 16) (hw : 1 ≤ w.val)
    (h : tagAt pre RSP = x64_check.Tag.Checked w) : False := by
  have hv := hag.regs RSP (by norm_num)
  rw [h, hag.rsp] at hv
  have hroom := hL.stackRoom
  have hsw := hL.stackWindow_toNat
  have hnw := hL.stackWindowNoWrap
  simp only [stackWindowLen] at hnw
  have hb : (P.rsp0 - BitVec.ofNat 64 (8 * pre.depth.val)).toNat
      = P.rsp0.toNat - 8 * pre.depth.val := toNat_sub_ofNat (by omega) (by omega)
  have hin : InRange (stackWindow P) stackWindowLen
      (P.rsp0 - BitVec.ofNat 64 (8 * pre.depth.val)) := by
    simp only [InRange, stackWindowLen]; omega
  rcases hv with hz | hs' | hd'
  · rw [hz] at hb
    simp only [BitVec.toNat_ofNat] at hb
    omega
  · exact notInRange_of_disjoint hL.stackNativeOffStack _ hin
      ⟨hs'.1, by have := hs'.2; omega⟩
  · exact notInRange_of_disjoint hL.dataNativeOffStack _ hin
      ⟨hd'.1, by have := hd'.2; omega⟩

/-- The registers the loop and the push in front of it may have written. `src`
is not among them unless it is `rax`, which is why a base register equal to
`src` survives the loop. -/
def afaMid (src actual : Std.U8) : Nat → Prop :=
  fun r => r = RAX ∨ r = RCX ∨ (src = x64_ir.RAX ∧ r = actual.val)

private theorem afa_flat {P : Params} {code : List x64_ir.PInsn} {pre : x64_check.State}
    {op : Std.U8} {w64 : Bool} {src base actual : Std.U8} {disp : Std.I32} {label b e : Nat}
    (hposM : ∀ n : Std.U32,
      (x64_ir.PInsn.Local n) ∈ atomicFetchLoop op w64 actual base disp label →
      ∃ j, pos code (.Local n) = some j ∧ b ≤ j ∧ j ≤ e)
    (hbsp : base.val ≠ RSP) (hbW : ¬ afaMid src actual base.val)
    (hg : GuestTag P pre base disp (if w64 then 8 else 4))
    (i : x64_ir.PInsn) (hmem : i ∈ atomicFetchLoop op w64 actual base disp label) :
    FlatOk P code pre b e (afaMid src actual) i := by
  revert hmem
  cases w64 <;>
    simp only [atomicFetchLoop, if_true, if_false, Bool.false_eq_true] <;>
    intro hmem <;> fin_cases hmem
  all_goals
    first
      | exact ⟨rfl, Or.inl rax_val, hbsp, hbW, by simpa [opWidth] using hg⟩
      | exact ⟨Or.inl rfl, hbsp, hbW, by simpa [opWidth] using hg⟩
      | exact hposM _ (by simp [atomicFetchLoop])
      | exact ⟨trivial, by simp [writes, afaMid, rcx_val]⟩

/-- `MInsn.AtomicFetchAlu`: the compare-exchange loop.

`hbaseAX` and `hbaseCX` are the two cases the checker's rule ought to refuse
and does not; the module docstring says why they are hypotheses here. -/
theorem macroOk_atomicFetchAlu {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {cfg : x64_ir.Cfg} {pre post : x64_check.State} {op : Std.U8} {w64 : Bool}
    {src base : Std.U8} {disp : Std.I32} {label : Nat} {index : Std.Usize} {pcv : Std.U32}
    (hL : Layout P) (hcage : cfg.pointer_mask ≠ 0#i32) (hcfg : CfgOk P cfg)
    (hwid : WidthsOk pre) (hlive : pre.alive = true)
    (hbaseAX : base.val ≠ RAX) (hbaseCX : base.val ≠ RCX)
    (hstep : x64_check.live_step cfg (.AtomicFetchAlu op w64 src base disp) index pcv pre
      = ok (.Ok (), post))
    (hE : ∀ k, k < (atomicFetchAluList op w64 src base disp label).length →
      code[p + k]? = (atomicFetchAluList op w64 src base disp label)[k]?)
    (hpos : ∀ (n : Std.U32) (j : Nat),
      (atomicFetchAluList op w64 src base disp label)[j]? = some (.Local n) →
      pos code (.Local n) = some (p + j)) :
    MacroOk P code p (p + (atomicFetchAluList op w64 src base disp label).length) pre post [] := by
  obtain ⟨haddr, hdep, hwr, hS⟩ := live_step_AtomicFetchAlu_spec hlive hstep
  have hS' : SetsTop pre post (afaWrites src) := hS.1
  set actual := atomicFetchActual src base with hactdef
  -- the register the loop keeps the source in is never the base
  have hact : src = x64_ir.RAX → actual.val ≠ base.val := by
    intro hsrc
    rw [hactdef, atomicFetchActual, if_pos hsrc]
    split
    · rename_i hb10
      rw [hb10, x64_ir.R11, x64_ir.R10]
      decide
    · rename_i hb10
      exact fun hc => hb10 (by
        have := u8_val_ne (x := base) (y := x64_ir.R10)
        by_contra hne
        exact this hne hc.symm)
  have hactval : src = x64_ir.RAX → actual.val = R10 ∨ actual.val = R11 := by
    intro hsrc
    rw [hactdef, atomicFetchActual, if_pos hsrc]
    split
    · exact Or.inr r11_val
    · exact Or.inl r10_val
  -- what the two halves of the expansion may have written
  have hmidW : ∀ r, afaMid src actual r → afaWrites src r := by
    rintro r (rfl | rfl | ⟨hsrc, rfl⟩)
    · exact Or.inr (Or.inl rfl)
    · exact Or.inr (Or.inr (Or.inl rfl))
    · rcases hactval hsrc with h | h
      · exact Or.inr (Or.inr (Or.inr (Or.inl h)))
      · exact Or.inr (Or.inr (Or.inr (Or.inr h)))
  have hW4 : ¬ afaWrites src RSP := by
    rintro (h | h | h | h | h)
    · exact hwr.1 h.symm
    all_goals exact absurd h (by decide)
  have hW5 : ¬ afaWrites src RBP := by
    rintro (h | h | h | h | h)
    · exact hwr.2.1 h.symm
    all_goals exact absurd h (by decide)
  have hM4 : ¬ afaMid src actual RSP := fun h => hW4 (hmidW _ h)
  have hM5 : ¬ afaMid src actual RBP := fun h => hW5 (hmidW _ h)
  have hbW : ¬ afaMid src actual base.val := by
    rintro (h | h | ⟨hsrc, h⟩)
    · exact hbaseAX h
    · exact hbaseCX h
    · exact hact hsrc h.symm
  have hg : GuestTag P pre base disp (if w64 then 8 else 4) := by
    have := guestTag_of_addrOk hL hcfg hwid hcage haddr
    simpa only [atomicSize] using this
  obtain ⟨hEA, hEM, hEB⟩ := code_split (A := atomicFetchHead src actual)
    (M := atomicFetchLoop op w64 actual base disp label) (B := atomicFetchTail src actual) hE
  have hposM := local_inside (A := atomicFetchHead src actual)
    (M := atomicFetchLoop op w64 actual base disp label) (B := atomicFetchTail src actual) hpos
  have hlineA : LineOk (afaMid src actual) pre.depth.val (atomicFetchHead src actual) := by
    simp only [atomicFetchHead]
    split_ifs with hsrc <;>
      simp only [LineOk, RegOnly, writes, afaMid, List.mem_cons, List.not_mem_nil,
        or_false] <;>
      and_intros <;>
      first | omega | trivial | (intro r hr; subst hr; exact Or.inr (Or.inr ⟨hsrc, rfl⟩))
  have hdA : dRun pre.depth.val (atomicFetchHead src actual) = pre.depth.val + 1 := by
    simp only [atomicFetchHead]
    split_ifs <;> simp [dRun, dStep]
  have hlineB : LineOk (afaWrites src) (pre.depth.val + 1) (atomicFetchTail src actual) := by
    simp only [atomicFetchTail]
    split_ifs with hsrc <;>
      simp only [LineOk, dStep, RegOnly, writes, List.mem_cons, List.not_mem_nil,
        or_false] <;>
      and_intros <;>
      first
        | omega
        | trivial
        | exact hmidW _ (Or.inr (Or.inr ⟨hsrc, rfl⟩))
        | exact Or.inr (Or.inl rax_val)
        | (intro r hr; subst hr; exact Or.inl rfl)
  have hdB : dRun (pre.depth.val + 1) (atomicFetchTail src actual) = pre.depth.val := by
    simp only [atomicFetchTail]
    split_ifs <;> simp [dRun, dStep]
  refine macroOk_of_blockOk (Win := afaMid src actual) hL hS' (fun r h => h)
    (fun s₀ hag => ?_)
  have hbsp : base.val ≠ RSP := by
    intro hb
    rcases haddr with hz | ⟨w, hwt, h1, h2⟩ | ⟨hfr, -, -, -, -, -⟩
    · exact hcage (i32_eq_iff_val.mpr (by simpa using hz))
    · rw [hb] at hwt
      refine checked_ne_rsp hL hag hdep ?_ hwt
      have : (4 : Int) ≤ (w.val : Int) := by
        simp only [atomicSize] at h2
        cases w64 <;> simp at h2 <;> omega
      omega
    · rw [hb] at hfr; exact absurd hfr (by decide)
  have h1 : BlockOk P code p (p + (atomicFetchHead src actual).length) pre
      (afaMid src actual) (afaMid src actual) pre.depth.val (pre.depth.val + 1) := by
    have := blockOk_line (P := P) (pre := pre) hL hM4 hM5 (atomicFetchHead src actual) p
      pre.depth.val (by omega) hEA hlineA
    rwa [hdA] at this
  have h2 : BlockOk P code (p + (atomicFetchHead src actual).length)
      (p + (atomicFetchHead src actual).length +
        (atomicFetchLoop op w64 actual base disp label).length) pre
      (afaMid src actual) (afaMid src actual) (pre.depth.val + 1) (pre.depth.val + 1) := by
    refine blockOk_flat hL (by omega) hM4 hM5 ?_
    intro k hk1 hk2 i hi
    refine afa_flat hposM hbsp hbW hg i ?_
    have hj : k = (p + (atomicFetchHead src actual).length) +
        (k - (p + (atomicFetchHead src actual).length)) := by omega
    rw [hj, hEM _ (by omega)] at hi
    exact List.mem_of_getElem? hi
  have h3 : BlockOk P code (p + (atomicFetchHead src actual).length +
      (atomicFetchLoop op w64 actual base disp label).length)
      (p + (atomicFetchHead src actual).length +
        (atomicFetchLoop op w64 actual base disp label).length +
        (atomicFetchTail src actual).length) pre (afaWrites src) (afaWrites src)
      (pre.depth.val + 1) pre.depth.val := by
    have := blockOk_line (P := P) (pre := pre) hL hW4 hW5 (atomicFetchTail src actual)
      (p + (atomicFetchHead src actual).length +
        (atomicFetchLoop op w64 actual base disp label).length) (pre.depth.val + 1)
      (by omega) hEB hlineB
    rwa [hdB] at this
  have hall := blockOk_seq h1 (blockOk_seq (h2.mono hmidW) h3)
  rw [show p + (atomicFetchAluList op w64 src base disp label).length
      = p + (atomicFetchHead src actual).length +
        (atomicFetchLoop op w64 actual base disp label).length +
        (atomicFetchTail src actual).length from by
    simp only [atomicFetchAluList, List.length_append, ← hactdef]; omega]
  exact hall

end X64

end async_ebpf_verified

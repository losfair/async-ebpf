import AsyncEbpf.X64.Expand
import AsyncEbpf.X64.CheckedAddr
import AsyncEbpf.X64.Arith
import AsyncEbpf.X64.Calls

/-!
# The x86_64 backend is memory-safe

This is what the rest of `AsyncEbpf/X64/` was for. `check_safe`: a macro list
that `x64_check::check` accepts expands to a primitive list that keeps the
entry contract of `AsyncEbpf/X64/Contract.lean` — from any state satisfying
`Entry`, every range any reachable step is about to touch is inside `Allowed`,
and if the function returns it returns with the stack balanced and the
callee-saved registers this model names still holding their entry values.
`expand_safe` says the same of what `x64_expand::expand` appends to an empty
vector; `lower_gate` reads `x64_lower::lower`'s own call to the checker off
the extracted definition; and `lower_safe` composes the three, so that what
the backend returns is safe.

## The glue

`Walk` packages a successful `check`: the chain of abstract states
`check_chain` hands out, the tables `scan` computed, and the facts about the
machine the checker does not look at. `Run` is `MacroOk` with the fallthrough
folded into the exit list, which is what makes the chaining uniform — every
way out of a macro's region is one entry of one list. `Walk.macro_run` proves
a `Run` for each macro and each state it may be entered in, by handing the
per-macro lemma of `Simple.lean`, `CheckedAddr.lean`, `Arith.lean` or
`Calls.lean` the hypotheses the walk and the expansion supply: where the
chunk sits (`flat_*`), how its local labels resolve (`pos_local`), what the
checker's rule established (`*_step_spec`).

`Walk.Reach` is the invariant — a reachable state is inside some macro's
region, having entered that macro at its first position in a state the macro
admits — and `Walk.contract` is the induction over `Reachable` that closes it.
A macro's region is its own chunk, except a helper call, whose `call
Retpoline` leaves the chunk and comes back, and whose region therefore also
holds the trailer's retpoline.

Two things are not local to one macro. `StateOk` — the frame register still
tagged `Fp`, every `Checked` width inside a page — is a property of the whole
chain and is carried by `Walk.stateOk_at`. And a macro may be entered in a
state the walk never arrived in: `PreAt` admits `enterState` at a `PcLabel`
some branch names and at the trailer's epilogue, which is where a branch to
`Exit` lands. A macro the walk left dead is entered only that way, and the
retpoline — which the trailer's epilogue kills the walk before — not at all.

## The hypotheses

Beyond the checker's verdict, `check_safe` asks for what the checker does not
see: `Layout P`, what the mappings and the entry trampoline promise; the cage
being on; the machine's frame size being the configured one; the machine's
dispatcher being the configured one and not an address inside this function;
the expansion fitting in the address space, and its local labels in a `u32`.

It also asks for `HasTrailer code`. The checker does not insist on the trailer
by itself — a list with no helper call does not need one — but a helper call
loads the dispatcher slot, which lives in the trailer, and branches over its
fallback path on the strength of that slot being non-null; with no slot the
fallback is reachable, and it loads through the embedded helper table, which
nothing in the model bounds. `lower` always emits the trailer, so `lower_safe`
discharges the hypothesis instead of carrying it.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-! ## Plumbing -/

/-- A region predicate can be replaced by an equivalent one. -/
theorem stays_iff {P : Params} {code : List x64_ir.PInsn} {I J : Nat → Prop}
    (h : ∀ x, I x ↔ J x) {s s' : State} (hs : Stays P code I s s') : Stays P code J s s' := by
  induction hs with
  | refl hi => exact .refl ((h _).mp hi)
  | step _ hst hi ih => exact .step ih hst ((h _).mp hi)

/-- The primitives of `C` sit at `p`, read off a `drop` equation. -/
theorem laid_of_drop {α : Type} {L C R : List α} {p : Nat} (h : L.drop p = C ++ R)
    (k : Nat) (hk : k < C.length) : L[p + k]? = C[k]? := by
  rw [← List.getElem?_drop, h, List.getElem?_append_left hk]

/-- Two indices of a list whose label sublist has no duplicates carry different
labels, so the first occurrence of a label inside a chunk is its only one. -/
theorem filter_nodup_index {α : Type} (p : α → Bool) :
    ∀ (l : List α) (j k : Nat) (x : α), (l.filter p).Nodup → p x = true →
      l[j]? = some x → l[k]? = some x → j = k := by
  intro l
  induction l with
  | nil => intro j k x _ _ hj _; simp at hj
  | cons b t ih =>
    intro j k x hnd hp hj hk
    have hsub : ∀ (m : Nat), t[m]? = some x → x ∈ t.filter p := by
      intro m hm
      exact List.mem_filter.mpr ⟨List.mem_of_getElem? hm, hp⟩
    match j, k with
    | 0, 0 => rfl
    | 0, (k + 1) =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at hj
      subst hj
      simp only [List.getElem?_cons_succ] at hk
      rw [List.filter_cons, if_pos hp] at hnd
      exact absurd (hsub k hk) (List.nodup_cons.mp hnd).1
    | (j + 1), 0 =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at hk
      subst hk
      simp only [List.getElem?_cons_succ] at hj
      rw [List.filter_cons, if_pos hp] at hnd
      exact absurd (hsub j hj) (List.nodup_cons.mp hnd).1
    | (j + 1), (k + 1) =>
      simp only [List.getElem?_cons_succ] at hj hk
      have hnd' : (t.filter p).Nodup := by
        rw [List.filter_cons] at hnd
        split at hnd
        · exact (List.nodup_cons.mp hnd).2
        · exact hnd
      exact congrArg (· + 1) (ih j k x hnd' hp hj hk)


/-- A `Local` label of chunk `i` resolves inside chunk `i`, at the offset it
sits at: the chunk's labels are distinct and lie in the chunk's own range. -/
theorem pos_local_of_chunk (cfg : x64_ir.Cfg) (M : List x64_ir.MInsn) (i : Nat)
    (hbound : labelBase cfg M (i + 1) < 2 ^ 32)
    {n : Std.U32} {k : Nat} (hk : (chunkAt cfg M i).1[k]? = some (.Local n)) :
    pos (flat cfg M) (.Local n) = some (chunkStart cfg M i + k) := by
  have hklt : k < (chunkAt cfg M i).1.length := List.getElem?_eq_some_iff.mp hk |>.1
  have hkl : k < chunkLen cfg M i := hklt
  cases hm : M[i]? with
  | none => rw [chunkAt_none hm] at hk; simp at hk
  | some m =>
    have hca : chunkAt cfg M i = chunk cfg m (trailerAt M i) (labelBase cfg M i) := chunkAt_eq hm
    have hnext : labelBase cfg M (i + 1) = (chunk cfg m (trailerAt M i) (labelBase cfg M i)).2 := by
      rw [labelBase_succ, hca]
    have hjb : (chunk cfg m (trailerAt M i) (labelBase cfg M i)).2 < 2 ^ 32 := by
      rw [← hnext]; exact hbound
    have hmem : x64_ir.PInsn.Local n ∈ (chunk cfg m (trailerAt M i) (labelBase cfg M i)).1 := by
      rw [← hca]; exact List.mem_of_getElem? hk
    obtain ⟨hlo, hhi⟩ := chunk_locals hjb hmem
    have hnu : (u32 n.val) = n := u32_val n
    have hhit : (chunkAt cfg M i).1[k]? = some (.Local (u32 n.val)) := by rw [hnu]; exact hk
    have hfirst : ∀ j, j < k → (chunkAt cfg M i).1[j]? ≠ some (.Local (u32 n.val)) := by
      intro j hj hcon
      rw [hnu] at hcon
      have hnd : ((chunkAt cfg M i).1.filter (fun x => !notLabelB x)).Nodup := by
        rw [hca]
        have := chunk_locals_nodup cfg m (trailerAt M i) (labelBase cfg M i) hjb
        simpa [labelsOf] using this
      have := filter_nodup_index (fun x => !notLabelB x) _ j k _ hnd (by simp [notLabelB]) hcon hk
      omega
    have := pos_local cfg M i k n.val hbound hkl hhit hfirst hlo (by rw [hnext]; exact hhi)
    rw [hnu] at this
    exact this

/-- `EnterShaped` pins every field, so it names `enterState`. -/
theorem enterShaped_eq {b : x64_check.State} (h : EnterShaped b) : b = enterState := by
  obtain ⟨ht, hd, hg, hal⟩ := h
  have hregs : b.regs = enterState.regs := by
    refine (Array.eq_iff _ _).mpr (List.ext_getElem ?_ ?_)
    · rw [regs_length, regs_length]
    · intro i h1 h2
      have e1 : b.regs.val[i] = tagAt b i := by
        simp only [tagAt, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h1,
          Option.getD_some]
      have e2 : enterState.regs.val[i] = tagAt enterState i := by
        simp only [tagAt, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h2,
          Option.getD_some]
      rw [e1, e2, ht i, tagAt_enterState]
  obtain ⟨r, d, g, al⟩ := b
  simp only at hregs hd hg hal
  subst hregs; subst hd; subst hg; subst hal
  rfl

@[simp] theorem enterState_alive : enterState.alive = true := rfl
@[simp] theorem enterState_depth : enterState.depth = 1#u32 := rfl
@[simp] theorem enterState_group : enterState.group = x64_check.Tag.Top := rfl

theorem enterState_fp : tagAt enterState 15 = x64_check.Tag.Fp := by simp



/-! ## Every chunk is non-empty

With the cage on, every macro expands to at least one primitive, so the chunk
starts are strictly increasing and every macro's range contains its own start.
The one macro that could expand to nothing is `CheckedAddr` with the cage off,
its source already in its destination and a zero displacement. -/

theorem chunkRegion_ne_nil (cfg : x64_ir.Cfg) (dst scratch : Std.U8) (size : Std.U32)
    (stack : Bool) : chunkRegion cfg dst scratch size stack ≠ [] := by
  unfold chunkRegion chunkRegionFromFrame chunkRegionViaDescriptor
  split <;> simp

theorem chunkCheckedAddr_ne_nil {cfg : x64_ir.Cfg} (hcage : cfg.pointer_mask ≠ 0#i32)
    (src dst scratch : Std.U8) (offset : Std.I32) (size : Std.U32) (hint : Std.U8) :
    chunkCheckedAddr cfg src dst scratch offset size hint ≠ [] := by
  have htail : (if cfg.pointer_mask = 0#i32 then []
      else if hint = x64_ir.region.STACK then chunkRegion cfg dst scratch size true
      else if hint = x64_ir.region.DATA then chunkRegion cfg dst scratch size false
      else
        [ (.Store 8#u8 dst x64_ir.RBP x64_ir.frame.ADDR_SPILL_OFFSET : x64_ir.PInsn) ] ++
        chunkRegion cfg dst scratch size true ++
        [ .Store 8#u8 dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET,
          .Load 8#u8 false x64_ir.RBP dst x64_ir.frame.ADDR_SPILL_OFFSET ] ++
        chunkRegion cfg dst scratch size false ++
        [ .AluRM .Or dst x64_ir.RBP x64_ir.frame.ACC_SPILL_OFFSET ]) ≠ [] := by
    rw [if_neg hcage]
    split
    · exact chunkRegion_ne_nil _ _ _ _ _
    · split
      · exact chunkRegion_ne_nil _ _ _ _ _
      · simp
  unfold chunkCheckedAddr
  intro hc
  rw [List.append_assoc, List.append_eq_nil_iff, List.append_eq_nil_iff] at hc
  exact htail hc.2.2

theorem ne_nil_append_left {α : Type} {b c : List α} (h : b ≠ []) : b ++ c ≠ [] := by
  simp [List.append_eq_nil_iff, h]

theorem ne_nil_append_right {α : Type} {b c : List α} (h : c ≠ []) : b ++ c ≠ [] := by
  simp [List.append_eq_nil_iff, h]

theorem chunkMulDivSetup_ne_nil (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) :
    chunkMulDivSetup kind w64 reg signed src dst imm ≠ [] := by
  unfold chunkMulDivSetup
  exact ne_nil_append_left (ne_nil_append_right (by simp))

theorem chunk_ne_nil {cfg : x64_ir.Cfg} (hcage : cfg.pointer_mask ≠ 0#i32)
    (m : x64_ir.MInsn) (tr : Bool) (l : Nat) : (chunk cfg m tr l).1 ≠ [] := by
  cases m
  case Prologue usage skip =>
    show (chunkPrologue usage skip l).1 ≠ []
    unfold chunkPrologue; split <;> simp
  case Epilogue =>
    show ((if tr then [x64_ir.PInsn.ExitLabel] else []) ++ _) ≠ []
    exact ne_nil_append_right (by simp)
  case MulDivMod kind w64 reg signed src dst imm =>
    show (chunkMulDivMod kind w64 reg signed src dst imm l).1 ≠ []
    unfold chunkMulDivMod
    split
    · exact ne_nil_append_left (ne_nil_append_left (ne_nil_append_left
        (ne_nil_append_left (chunkMulDivSetup_ne_nil _ _ _ _ _ _ _))))
    · split
      · split <;> simp
      · exact ne_nil_append_left (ne_nil_append_left (ne_nil_append_left
          (ne_nil_append_left (chunkMulDivSetup_ne_nil _ _ _ _ _ _ _))))
  case GuestFp dst => show chunkGuestFp dst ≠ []; simp [chunkGuestFp]
  case CheckedAddr src dst scratch offset size hint =>
    exact chunkCheckedAddr_ne_nil hcage _ _ _ _ _ _
  case AtomicFetchAlu op w64 src base disp =>
    show (chunkAtomicFetchAlu op w64 src base disp l).1 ≠ []
    unfold chunkAtomicFetchAlu
    exact ne_nil_append_left (ne_nil_append_right (by simp))
  case HelperCall idx =>
    show (chunkHelperCall idx l).1 ≠ []
    unfold chunkHelperCall; exact ne_nil_append_left (by simp)
  case LazyLocalCall id =>
    show (chunkLazyLocalCall cfg id l).1 ≠ []
    unfold chunkLazyLocalCall; exact ne_nil_append_left (by simp)
  case Retpoline =>
    show (chunkRetpoline l).1 ≠ []
    unfold chunkRetpoline; simp
  all_goals simp [chunk]

theorem chunkLen_pos {cfg : x64_ir.Cfg} (hcage : cfg.pointer_mask ≠ 0#i32)
    {M : List x64_ir.MInsn} {i : Nat} (hi : i < M.length) : 0 < chunkLen cfg M i := by
  have hm : M[i]? = some M[i] := List.getElem?_eq_getElem hi
  have he : chunkLen cfg M i = (chunk cfg M[i] (trailerAt M i) (labelBase cfg M i)).1.length := by
    unfold chunkLen; rw [chunkAt_eq hm]
  rw [he, List.length_pos_iff]
  exact chunk_ne_nil hcage _ _ _

/-- So the chunk starts strictly increase, and every macro's range holds its
own first position. -/
theorem chunkStart_lt {cfg : x64_ir.Cfg} (hcage : cfg.pointer_mask ≠ 0#i32)
    {M : List x64_ir.MInsn} {i : Nat} (hi : i < M.length) :
    chunkStart cfg M i < chunkStart cfg M (i + 1) := by
  rw [chunkStart_step]
  have := chunkLen_pos hcage hi
  omega

theorem chunkStart_strictMono {cfg : x64_ir.Cfg} (hcage : cfg.pointer_mask ≠ 0#i32)
    {M : List x64_ir.MInsn} {i j : Nat} (hj : j ≤ M.length) (hij : i < j) :
    chunkStart cfg M i < chunkStart cfg M j := by
  have h1 : chunkStart cfg M (i + 1) ≤ chunkStart cfg M j := chunkStart_mono cfg M (by omega)
  have h2 := chunkStart_lt hcage (M := M) (i := i) (by omega)
  omega

/-! ## What the glue asks of one macro

`Run` is `MacroOk` with the fallthrough folded into the exit list, which is
what makes the chaining uniform: every way out of a macro's region is one entry
of `nexts`. -/

/-- Running one macro's region: every step safe, every way out listed, every
return under the contract. -/
structure Run (P : Params) (code : List x64_ir.PInsn) (inside : Nat → Prop) (p : Nat)
    (pre : x64_check.State) (nexts : List (Nat × x64_check.State)) : Prop where
  safe : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code inside s s' →
    ∀ c, Step P code s' c → ∀ i, code[s'.pc]? = some i →
      ∀ bn ∈ accesses i s', AccessOk P bn.1 bn.2
  leave : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code inside s s' →
    ∀ s'', Step P code s' (.next s'') → ¬ inside s''.pc →
      ∃ e ∈ nexts, s''.pc = e.1 ∧ Agree P e.2 s''
  returns : ∀ s, s.pc = p → Agree P pre s → ∀ s', Stays P code inside s s' →
    ∀ s'', Step P code s' (.returned s'') →
      s''.regs RSP = P.rsp0 + 8#64 ∧ s''.regs RBP = P.rbp0 ∧ s''.regs R15 = P.fp0

theorem Run.congr {P : Params} {code : List x64_ir.PInsn} {I J : Nat → Prop} {p : Nat}
    {pre : x64_check.State} {nx : List (Nat × x64_check.State)}
    (h : ∀ x, I x ↔ J x) (r : Run P code I p pre nx) : Run P code J p pre nx := by
  refine ⟨?_, ?_, ?_⟩
  · intro s hs hag s' hst
    exact r.safe s hs hag s' (stays_iff (fun x => (h x).symm) hst)
  · intro s hs hag s' hst s'' hstep hout
    exact r.leave s hs hag s' (stays_iff (fun x => (h x).symm) hst) s'' hstep
      (fun hc => hout ((h _).mp hc))
  · intro s hs hag s' hst
    exact r.returns s hs hag s' (stays_iff (fun x => (h x).symm) hst)

theorem Run.ofMacroOkIn {P : Params} {code : List x64_ir.PInsn} {inside : Nat → Prop}
    {p q : Nat} {pre post : x64_check.State} {exits : List (Nat × x64_check.State)}
    (h : MacroOkIn P code inside p q pre post exits) :
    Run P code inside p pre ((q, post) :: exits) := by
  refine ⟨h.safe, ?_, h.returns⟩
  intro s hs hag s' hst s'' hstep hout
  rcases h.leave s hs hag s' hst s'' hstep hout with ⟨hpc, hag'⟩ | ⟨e, he, hpc, hag'⟩
  · exact ⟨(q, post), by simp, hpc, hag'⟩
  · exact ⟨e, by simp [he], hpc, hag'⟩

theorem Run.ofMacroOk {P : Params} {code : List x64_ir.PInsn} {p q : Nat}
    {pre post : x64_check.State} {exits : List (Nat × x64_check.State)}
    (h : MacroOk P code p q pre post exits) :
    Run P code (Range p q) p pre ((q, post) :: exits) :=
  Run.ofMacroOkIn ⟨h.safe, h.leave, h.returns⟩



/-! ## The walk

Everything the glue reads off a successful `check`, bundled: the chain of
abstract states, the label tables, and the side conditions of the theorem. -/

/-- A successful `check`, as the walk it performed together with the machine's
side conditions. -/
structure Walk (P : Params) (cfg : x64_ir.Cfg) (code : Slice x64_ir.MInsn) where
  labels : x64_check.Labels
  a : List x64_check.State
  pcs : List Std.U32
  hscan : x64_check.scan code = ok labels
  hentry : x64_check.entry_state = ok a[0]!
  hsteps : ∀ (j : Nat) (idx : Std.Usize), idx.val = j → j < code.val.length →
    x64_check.step cfg labels code idx pcs[j + 1]! a[j]! = ok (.Ok (), a[j + 1]!)
  hdead : (a[code.val.length]!).alive = false
  /-- The list ends in the four macros the trailer is made of. The checker
  does not insist on this by itself — a list with no helper call does not need
  one — but the helper call's dispatcher slot lives there, and without it the
  macro's fallback path, which loads through the embedded helper table, is
  reachable and unprovable. `lower` always emits the trailer. -/
  htrailer : HasTrailer code.val
  hL : Layout P
  hcage : cfg.pointer_mask ≠ 0#i32
  hcfg : CfgOk P cfg
  hdisp : P.dispatcher = BitVec.ofNat 64 cfg.dispatcher.val
  hdispCode : ∀ j, j < (flat cfg code.val).length → P.dispatcher ≠ codeAddr P j
  hflen : (flat cfg code.val).length < 2 ^ 64
  hlabels : labelBase cfg code.val code.val.length < 2 ^ 32

theorem exists_usize {j : Nat} (h : j ≤ Std.Usize.max) : ∃ idx : Std.Usize, idx.val = j := by
  have hb : j < 2 ^ Std.UScalarTy.Usize.numBits := by scalar_tac
  exact ⟨Std.Usize.ofNatCore j hb, Std.Usize.ofNatCore_val_eq hb⟩

variable {P : Params} {cfg : x64_ir.Cfg} {code : Slice x64_ir.MInsn}

theorem Walk.raw_step (W : Walk P cfg code) {j : Nat} (hj : j < code.val.length) :
    ∃ (idx : Std.Usize) (pcv : Std.U32), idx.val = j ∧
      x64_check.step cfg W.labels code idx pcv W.a[j]! = ok (.Ok (), W.a[j + 1]!) := by
  obtain ⟨idx, hidx⟩ := exists_usize (j := j) (by have := code.property; omega)
  exact ⟨idx, W.pcs[j + 1]!, hidx, W.hsteps j idx hidx hj⟩

/-- The rule the checker's `step` sends a macro to, as a predicate on the
macro rather than as a `match` in a goal. -/
def StepRule (cfg : x64_ir.Cfg) (code : Slice x64_ir.MInsn) (labels : x64_check.Labels)
    (idx : Std.Usize) (pcv : Std.U32) (pre post : x64_check.State) : x64_ir.MInsn → Prop
  | .PcLabel slot => x64_check.label_step labels slot idx pcv pre = ok (.Ok (), post)
  | .Prologue _ skip => x64_check.prologue_step skip idx pcv pre = ok (.Ok (), post)
  | .Jcc _ target => x64_check.branch_step labels target false idx pcv pre = ok (.Ok (), post)
  | .Jmp target => x64_check.branch_step labels target true idx pcv pre = ok (.Ok (), post)
  | .Retpoline => x64_check.retpoline_step code idx pcv pre = ok (.Ok (), post)
  | .DispatcherSlot => ∃ u, x64_check.data_step code idx pcv 1#usize = ok u ∧
      ((.Ok () : core.result.Result Unit x64_check.Unsafe), post) = (u, pre)
  | .HelperTable => ∃ u, x64_check.data_step code idx pcv 2#usize = ok u ∧
      ((.Ok () : core.result.Result Unit x64_check.Unsafe), post) = (u, pre)
  | m => x64_check.live_step cfg m idx pcv pre = ok (.Ok (), post)

/-- The rule the checker applied at macro `j`. -/
theorem Walk.dispatch (W : Walk P cfg code) {j : Nat} (hj : j < code.val.length)
    {m : x64_ir.MInsn} (hm : code.val[j]? = some m) :
    ∃ (idx : Std.Usize) (pcv : Std.U32), idx.val = j ∧
      StepRule cfg code W.labels idx pcv W.a[j]! W.a[j + 1]! m := by
  obtain ⟨idx, pcv, hidx, hst⟩ := W.raw_step hj
  obtain ⟨insn, hinsn, hmatch⟩ := step_dispatch hst
  rw [hidx] at hinsn
  have he : insn = m := Option.some.inj (hinsn.symm.trans hm)
  refine ⟨idx, pcv, hidx, ?_⟩
  subst he
  clear hinsn hm hst hidx
  cases insn <;> exact hmatch


/-! ## The two facts about the chain that are not local

The frame register's tag and the bound on every `Checked` width are properties
of the walk rather than of one macro: a macro lemma takes them as hypotheses
and this is where they are discharged, by induction along the chain. -/

/-- The frame register still carries `Fp`, and every checked width fits in a
page. -/
def StateOk (a : x64_check.State) : Prop :=
  tagAt a 15 = x64_check.Tag.Fp ∧ WidthsOk a

theorem widthsOk_of_tops {b : x64_check.State}
    (ht : ∀ k, tagAt b k = if k = 15 then x64_check.Tag.Fp else x64_check.Tag.Top)
    (hg : b.group = x64_check.Tag.Top) : WidthsOk b := by
  refine ⟨fun r w hw => ?_, fun w hw => ?_⟩
  · rw [ht r] at hw; split at hw <;> simp at hw
  · rw [hg] at hw; simp at hw

theorem stateOk_enter {b : x64_check.State} (h : EnterShaped b) : StateOk b :=
  ⟨by rw [h.1 15]; simp, widthsOk_of_tops h.1 h.2.2.1⟩

theorem stateOk_tagsKept {pre post : x64_check.State} (h : StateOk pre)
    (ht : ∀ k, tagAt post k = tagAt pre k) (hg : post.group = pre.group) : StateOk post := by
  refine ⟨by rw [ht 15]; exact h.1, fun r w hw => ?_, fun w hw => ?_⟩
  · rw [ht r] at hw; exact h.2.1 r w hw
  · rw [hg] at hw; exact h.2.2 w hw

theorem stateOk_setsTop {pre post : x64_check.State} {S : Nat → Prop} (h : StateOk pre)
    (hS : SetsTop pre post S) (h15 : ¬ S 15) : StateOk post := by
  refine ⟨by rw [hS.2.1 15 h15]; exact h.1, fun r w hw => ?_, fun w hw => ?_⟩
  · by_cases hr : S r
    · rw [hS.1 r hr] at hw; simp at hw
    · rw [hS.2.1 r hr] at hw; exact h.2.1 r w hw
  · rw [hS.2.2.2.1] at hw; exact h.2.2 w hw

theorem stateOk_write {pre post : x64_check.State} {r : Nat} (h : StateOk pre)
    (hwr : r ≠ 15) (hS : SetsTop pre post (· = r)) : StateOk post :=
  stateOk_setsTop h hS (fun hc => hwr hc.symm)

theorem stateOk_clobber {pre post : x64_check.State} (h : StateOk pre)
    (hS : ClobberCall pre post) : StateOk post := by
  have h15 : ¬ CallerSaved 15 := by simp [CallerSaved]
  refine ⟨by rw [hS.2.1 15 h15]; exact h.1, fun r w hw => ?_, fun w hw => ?_⟩
  · by_cases hr : CallerSaved r
    · rw [hS.1 r hr] at hw; simp at hw
    · rw [hS.2.1 r hr] at hw; exact h.2.1 r w hw
  · rw [hS.2.2.2.1] at hw; simp at hw

theorem live_step_post_dead {cfg : x64_ir.Cfg} {m : x64_ir.MInsn} {idx : Std.Usize}
    {pcv : Std.U32} {pre post : x64_check.State} (hd : pre.alive = false)
    (h : x64_check.live_step cfg m idx pcv pre = ok (.Ok (), post)) : post = pre := by
  rw [live_step_dead hd] at h
  simp only [ok.injEq, Prod.mk.injEq, true_and] at h
  exact h.symm

/-- Every rule keeps both facts. -/
theorem stateOk_step {cfg : x64_ir.Cfg} {code : Slice x64_ir.MInsn} {labels : x64_check.Labels}
    {idx : Std.Usize} {pcv : Std.U32} {pre post : x64_check.State} {m : x64_ir.MInsn}
    (h : StateOk pre) (hr : StepRule cfg code labels idx pcv pre post m) : StateOk post := by
  have hdeadcase : ∀ (m' : x64_ir.MInsn), pre.alive = false →
      x64_check.live_step cfg m' idx pcv pre = ok (.Ok (), post) → StateOk post := by
    intro m' hd hl; rw [live_step_post_dead hd hl]; exact h
  have hsame : post = pre → StateOk post := by rintro rfl; exact h
  cases m with
  | PcLabel slot =>
    rcases label_step_spec hr with ⟨-, hp⟩ | ⟨-, -, hE⟩
    · exact hsame hp
    · exact stateOk_enter hE
  | Prologue u skip => exact stateOk_enter (prologue_step_spec hr).2
  | Jcc cc target =>
    obtain ⟨-, -, -, ht, -, hg, -, -⟩ := branch_step_spec hr
    exact stateOk_tagsKept h ht hg
  | Jmp target =>
    obtain ⟨-, -, -, ht, -, hg, -, -⟩ := branch_step_spec hr
    exact stateOk_tagsKept h ht hg
  | Retpoline =>
    obtain ⟨-, hp⟩ := retpoline_step_spec hr
    subst hp; exact stateOk_tagsKept h (fun _ => rfl) rfl
  | DispatcherSlot =>
    obtain ⟨u, -, hu⟩ := hr
    exact hsame (by simpa using (Prod.mk.injEq _ _ _ _ ▸ hu).2)
  | HelperTable =>
    obtain ⟨u, -, hu⟩ := hr
    exact hsame (by simpa using (Prod.mk.injEq _ _ _ _ ▸ hu).2)
  | Epilogue =>
    by_cases hal : pre.alive = true
    · obtain ⟨-, -, hp⟩ := live_step_Epilogue_spec hal hr
      subst hp; exact stateOk_tagsKept h (fun _ => rfl) rfl
    · exact hdeadcase _ (by simpa using hal) hr
  | Alu w64 op src dst =>
    by_cases hal : pre.alive = true
    · obtain ⟨h1, h2⟩ := live_step_Alu_spec hal hr
      cases hw : AluRRWrites op
      · exact hsame (h2 hw)
      · exact stateOk_write h (h1 hw).1.2.2.1 (h1 hw).2
    · exact hdeadcase _ (by simpa using hal) hr
  | AluImm w64 op dst imm =>
    by_cases hal : pre.alive = true
    · obtain ⟨h1, h2⟩ := live_step_AluImm_spec hal hr
      cases hw : AluRIWrites op
      · exact hsame (h2 hw)
      · exact stateOk_write h (h1 hw).1.2.2.1 (h1 hw).2
    · exact hdeadcase _ (by simpa using hal) hr
  | ShiftImm w64 op dst imm =>
    by_cases hal : pre.alive = true
    · obtain ⟨hw, hS⟩ := live_step_ShiftImm_spec hal hr; exact stateOk_write h hw.2.2.1 hS
    · exact hdeadcase _ (by simpa using hal) hr
  | ShiftCl w64 op dst =>
    by_cases hal : pre.alive = true
    · obtain ⟨hw, hS⟩ := live_step_ShiftCl_spec hal hr; exact stateOk_write h hw.2.2.1 hS
    · exact hdeadcase _ (by simpa using hal) hr
  | Neg w64 dst =>
    by_cases hal : pre.alive = true
    · obtain ⟨hw, hS⟩ := live_step_Neg_spec hal hr; exact stateOk_write h hw.2.2.1 hS
    · exact hdeadcase _ (by simpa using hal) hr
  | MovSx from_ w64 src dst =>
    by_cases hal : pre.alive = true
    · obtain ⟨hw, hS⟩ := live_step_MovSx_spec hal hr; exact stateOk_write h hw.2.2.1 hS
    · exact hdeadcase _ (by simpa using hal) hr
  | Bswap w64 dst =>
    by_cases hal : pre.alive = true
    · obtain ⟨hw, hS⟩ := live_step_Bswap_spec hal hr; exact stateOk_write h hw.2.2.1 hS
    · exact hdeadcase _ (by simpa using hal) hr
  | Rol16 dst =>
    by_cases hal : pre.alive = true
    · obtain ⟨hw, hS⟩ := live_step_Rol16_spec hal hr; exact stateOk_write h hw.2.2.1 hS
    · exact hdeadcase _ (by simpa using hal) hr
  | LoadImm dst imm =>
    by_cases hal : pre.alive = true
    · obtain ⟨hw, hS⟩ := live_step_LoadImm_spec hal hr; exact stateOk_write h hw.2.2.1 hS
    · exact hdeadcase _ (by simpa using hal) hr
  | GuestFp dst =>
    by_cases hal : pre.alive = true
    · obtain ⟨hw, hS⟩ := live_step_GuestFp_spec hal hr; exact stateOk_write h hw.2.2.1 hS
    · exact hdeadcase _ (by simpa using hal) hr
  | MulDivMod kind w64 signed imm src dst d =>
    by_cases hal : pre.alive = true
    · obtain ⟨-, hw, hS⟩ := live_step_MulDivMod_spec hal hr
      refine stateOk_setsTop h hS ?_
      rintro (hc | hc | hc | hc | hc)
      · exact hw.2.2.1 hc.symm
      all_goals exact absurd hc (by decide)
    · exact hdeadcase _ (by simpa using hal) hr
  | CheckedAddr src dst scratch offset size hint =>
    by_cases hal : pre.alive = true
    · obtain ⟨-, hd9, hs9, hw1, hw2, hwd, hws, htd, hts, ht9, hkeep, -, hgrp, -⟩ :=
        live_step_CheckedAddr_spec hal hr
      refine ⟨?_, fun r w hw => ?_, fun w hw => ?_⟩
      · rw [hkeep 15 (fun hc => hwd.2.2.1 hc.symm) (fun hc => hws.2.2.1 hc.symm) (by decide)]
        exact h.1
      · by_cases h1 : r = dst.val
        · subst h1; rw [htd] at hw; split at hw
          · simp only [x64_check.Tag.Checked.injEq] at hw; subst hw; exact hw2
          · simp at hw
        · by_cases h2 : r = scratch.val
          · subst h2; rw [hts] at hw; simp at hw
          · by_cases h3 : r = 9
            · subst h3; rw [ht9] at hw; simp at hw
            · rw [hkeep r h1 h2 h3] at hw; exact h.2.1 r w hw
      · rw [hgrp] at hw; exact h.2.2 w hw
    · exact hdeadcase _ (by simpa using hal) hr
  | GroupBaseStore src =>
    by_cases hal : pre.alive = true
    · rw [live_step_GroupBaseStore_spec hal hr]
      refine ⟨h.1, fun r w hw => h.2.1 r w hw, fun w hw => ?_⟩
      exact h.2.1 src.val w hw
    · exact hdeadcase _ (by simpa using hal) hr
  | GroupBaseLoad dst =>
    by_cases hal : pre.alive = true
    · obtain ⟨hwd, htd, hkeep, -, hgrp, -⟩ := live_step_GroupBaseLoad_spec hal hr
      refine ⟨?_, fun r w hw => ?_, fun w hw => ?_⟩
      · rw [hkeep 15 (fun hc => hwd.2.2.1 hc.symm)]; exact h.1
      · by_cases h1 : r = dst.val
        · subst h1; rw [htd] at hw; exact h.2.2 w hw
        · rw [hkeep r h1] at hw; exact h.2.1 r w hw
      · rw [hgrp] at hw; exact h.2.2 w hw
    · exact hdeadcase _ (by simpa using hal) hr
  | Load size sx base dst disp =>
    by_cases hal : pre.alive = true
    · obtain ⟨-, hw, hS⟩ := live_step_Load_spec hal hr; exact stateOk_write h hw.2.2.1 hS
    · exact hdeadcase _ (by simpa using hal) hr
  | Store size src base disp =>
    by_cases hal : pre.alive = true
    · exact hsame (live_step_Store_spec hal hr).2
    · exact hdeadcase _ (by simpa using hal) hr
  | StoreImm size base disp imm =>
    by_cases hal : pre.alive = true
    · exact hsame (live_step_StoreImm_spec hal hr).2
    · exact hdeadcase _ (by simpa using hal) hr
  | AtomicAlu op w64 src base disp =>
    by_cases hal : pre.alive = true
    · exact hsame (live_step_AtomicAlu_spec hal hr).2
    · exact hdeadcase _ (by simpa using hal) hr
  | AtomicFetchAlu op w64 src base disp =>
    by_cases hal : pre.alive = true
    · obtain ⟨-, -, hw, hS, -⟩ := live_step_AtomicFetchAlu_spec hal hr
      refine stateOk_setsTop h hS ?_
      rintro (hc | hc | hc | hc | hc)
      · exact hw.2.2.1 hc.symm
      all_goals exact absurd hc (by decide)
    · exact hdeadcase _ (by simpa using hal) hr
  | AtomicXchg w64 src base disp =>
    by_cases hal : pre.alive = true
    · obtain ⟨-, hw, hS⟩ := live_step_AtomicXchg_spec hal hr; exact stateOk_write h hw.2.2.1 hS
    · exact hdeadcase _ (by simpa using hal) hr
  | AtomicCmpxchg w64 src base disp =>
    by_cases hal : pre.alive = true
    · obtain ⟨-, hS⟩ := live_step_AtomicCmpxchg_spec hal hr
      exact stateOk_write h (by decide) hS
    · exact hdeadcase _ (by simpa using hal) hr
  | HelperCall idx' =>
    by_cases hal : pre.alive = true
    · exact stateOk_clobber h (live_step_HelperCall_spec hal hr).2.2
    · exact hdeadcase _ (by simpa using hal) hr
  | LazyLocalCall id =>
    by_cases hal : pre.alive = true
    · exact stateOk_clobber h (live_step_LazyLocalCall_spec hal hr).2.2.2
    · exact hdeadcase _ (by simpa using hal) hr



/-- So along the whole chain. -/
theorem Walk.stateOk_at (W : Walk P cfg code) : ∀ j, j ≤ code.val.length → StateOk W.a[j]! := by
  intro j
  induction j with
  | zero =>
    intro _
    obtain ⟨-, hg, -, ht⟩ := entry_state_eq W.hentry
    exact ⟨by rw [ht 15]; simp, widthsOk_of_tops ht hg⟩
  | succ j ih =>
    intro hj
    have hjl : j < code.val.length := by omega
    have hm : code.val[j]? = some code.val[j] := List.getElem?_eq_getElem hjl
    obtain ⟨idx, pcv, -, hr⟩ := W.dispatch hjl hm
    exact stateOk_step (ih (by omega)) hr

/-! ## The trailer

`retpoline_step` admits a `Retpoline` macro only as part of a trailer, and a
trailer is the last four macros, so there is at most one of each of the four.
-/

/-- Every `Retpoline` macro carries the trailer, so it is the third from last. -/
theorem Walk.retpoline_trailerAt (W : Walk P cfg code) {r : Nat} (hr : r < code.val.length)
    (hm : code.val[r]? = some .Retpoline) : TrailerAt code.val r := by
  obtain ⟨idx, pcv, hidx, hst⟩ := W.dispatch hr hm
  have := (retpoline_step_spec hst).1
  rwa [hidx] at this

theorem Walk.retpoline_unique (W : Walk P cfg code) {r : Nat} (hr : r < code.val.length)
    (hm : code.val[r]? = some .Retpoline) : r + 3 = code.val.length :=
  (W.retpoline_trailerAt hr hm).2.1



/-! ## The four macro runs the glue proves for itself

`Simple.lean` states the epilogue and the unconditional branch as `MacroOk`s
whose `leave` clause is vacuous or always an exit; the glue needs to *know*
that, because a fallthrough into the dead state after them would break the
chain. The epilogue is also reached in `enterState` by a branch to `Exit`,
which is not the state the checker walked into it with. Both are restated
here over the invariant their proofs already run, and the trailer's two data
macros — which halt — get the run they never had. -/

@[simp] theorem enterState_depth_val : enterState.depth.val = 1 := rfl

/-- `add rsp, 8 ; ret`, with the exit label in front of it in the trailer.
Nothing leaves the range by a step; the only way on is the return. -/
theorem epilogue_run {P : Params} {code : List x64_ir.PInsn} {p e : Nat}
    {pre : x64_check.State} (hL : Layout P)
    (hd : pre.depth.val = 1) (hf : tagAt pre 15 = x64_check.Tag.Fp)
    (hlab : ∀ k, k < e → code[p + k]? = some .ExitLabel)
    (hc0 : code[p + e]? = some (.AluImm true x64_ir.AluRI.Add x64_ir.RSP 8#i32))
    (hc1 : code[p + e + 1]? = some .Ret) :
    Run P code (Range p (p + e + 2)) p pre [] := by
  have htop : AccessOk P P.rsp0 8 := by
    have := stack_slot_ok (P := P) (d := 0) hL (by norm_num)
    simpa using this
  set I : State → Prop := fun t =>
    ((∃ k, k ≤ e ∧ t.pc = p + k) ∧ Agree P pre t) ∨
      (t.pc = p + e + 1 ∧ t.regs RSP = P.rsp0 ∧ t.regs RBP = P.rbp0 ∧ t.regs R15 = P.fp0)
    with hI
  have hinv : ∀ s s' : State, s.pc = p → Agree P pre s →
      Stays P code (Range p (p + e + 2)) s s' → I s' := by
    intro s s' hs hag hsty
    refine stays_invariant (I := I) (Or.inl ⟨⟨0, by omega, by simpa using hs⟩, hag⟩) ?_ hsty
    rintro t t' (⟨⟨k, hk, ht⟩, hat⟩ | ⟨ht, h1, h2, h3⟩) _hin hstep _hin'
    · rcases Nat.lt_or_ge k e with hlt | hge
      · obtain ⟨u, hu, hpc, hmem, hregs⟩ :=
          step_regOnly (i := x64_ir.PInsn.ExitLabel) trivial (by rw [ht]; exact hlab k hlt) hstep
        cases hu
        exact Or.inl ⟨⟨k + 1, by omega, by rw [hpc, ht]; omega⟩,
          agree_same hat (fun r => hregs r (by simp [writes])) hmem⟩
      · have hke : k = e := by omega
        subst hke
        have hu := step_aluImm (by rw [ht]; exact hc0) hstep
        simp only [Config.next.injEq] at hu
        subst hu
        obtain ⟨e1, e2, e3, -⟩ := aluImm_addRsp t
        refine Or.inr ⟨by rw [e3, ht], ?_, ?_, ?_⟩
        · rw [e1, agree_depth_one hat hd]; ring
        · rw [e2 RBP (by simp [RBP, RSP])]; exact hat.rbp
        · rw [e2 R15 (by simp [R15, RSP])]; exact agree_fp hat hf
    · exfalso
      rcases step_ret (by rw [ht]; exact hc1) hstep with ⟨-, hbad⟩ | ⟨hne, -⟩ | ⟨hne, -⟩
      · simp at hbad
      · exact hne h1
      · exact hne h1
  refine ⟨?_, ?_, ?_⟩
  · intro s hs hag s' hsty c hstep ii hj bn hbn
    rcases hinv s s' hs hag hsty with ⟨⟨k, hk, ht⟩, hat⟩ | ⟨ht, h1, -, -⟩
    · rcases Nat.lt_or_ge k e with hlt | hge
      · rw [ht, hlab k hlt] at hj
        obtain rfl : ii = _ := by simpa using hj.symm
        rw [accesses_regOnly (i := x64_ir.PInsn.ExitLabel) trivial] at hbn
        simp at hbn
      · have hke : k = e := by omega
        subst hke
        rw [ht, hc0] at hj
        obtain rfl : ii = _ := by simpa using hj.symm
        simp at hbn
    · rw [ht, hc1] at hj
      obtain rfl : ii = _ := by simpa using hj.symm
      simp only [accesses_ret, List.mem_singleton] at hbn
      subst hbn
      rw [h1]; exact htop
  · intro s hs hag s' hsty s'' hstep hout
    exfalso
    rcases hinv s s' hs hag hsty with ⟨⟨k, hk, ht⟩, hat⟩ | ⟨ht, h1, -, -⟩
    · rcases Nat.lt_or_ge k e with hlt | hge
      · obtain ⟨u, hu, hpc, -, -⟩ :=
          step_regOnly (i := x64_ir.PInsn.ExitLabel) trivial (by rw [ht]; exact hlab k hlt) hstep
        cases hu
        exact hout (by simp only [Range, hpc, ht]; omega)
      · have hke : k = e := by omega
        subst hke
        have hu := step_aluImm (by rw [ht]; exact hc0) hstep
        simp only [Config.next.injEq] at hu
        subst hu
        exact hout (by simp only [Range, aluImmStep_pc, ht]; omega)
    · rcases step_ret (by rw [ht]; exact hc1) hstep with ⟨-, hbad⟩ | ⟨hne, -⟩ | ⟨hne, -⟩
      · simp at hbad
      · exact hne h1
      · exact hne h1
  · intro s hs hag s' hsty s'' hstep
    rcases hinv s s' hs hag hsty with ⟨⟨k, hk, ht⟩, hat⟩ | ⟨ht, h1, h2, h3⟩
    · exfalso
      have hr := (step_returned_ret hstep).1
      rcases Nat.lt_or_ge k e with hlt | hge
      · rw [ht, hlab k hlt] at hr; simp at hr
      · have hke : k = e := by omega
        subst hke
        rw [ht, hc0] at hr; simp at hr
    · obtain ⟨-, -, rfl⟩ := step_returned_ret hstep
      exact ⟨by rw [popRsp_rsp, h1], by simp [popRsp, RBP, RSP, h2],
        by simp [popRsp, R15, RSP, h3]⟩

/-- A `PcLabel` entered by a branch: it was already the state every branch
target is entered in, and it stays that state. -/
theorem pcLabel_entered_run {P : Params} {code : List x64_ir.PInsn} {p : Nat} {slot : Std.U32}
    (hc : code[p]? = some (.PcLabel slot)) :
    Run P code (Range p (p + 1)) p enterState [(p + 1, enterState)] := by
  refine ⟨?_, ?_, ?_⟩
  · intro s hs hag s' hsty c hstep ii hj bn hbn
    have heq := stays_regOnly (i := x64_ir.PInsn.PcLabel slot) trivial hc hsty
    subst heq
    rw [hs, hc] at hj
    obtain rfl : ii = _ := by simpa using hj.symm
    rw [accesses_regOnly (i := x64_ir.PInsn.PcLabel slot) trivial] at hbn
    simp at hbn
  · intro s hs hag s' hsty s'' hstep hout
    have heq := stays_regOnly (i := x64_ir.PInsn.PcLabel slot) trivial hc hsty
    subst heq
    obtain ⟨u, hu, hpc, hmem, hregs⟩ :=
      step_regOnly (i := x64_ir.PInsn.PcLabel slot) trivial (by rw [hs]; exact hc) hstep
    cases hu
    refine ⟨(p + 1, enterState), by simp, by rw [hpc, hs], ?_⟩
    refine agree_enterState ?_ ?_ ?_ ?_
    · rw [hregs RSP (by simp [writes]), agree_depth_one hag (by simp)]
    · rw [hregs R15 (by simp [writes]), agree_fp hag enterState_fp]
    · rw [hregs RBP (by simp [writes])]; exact hag.rbp
    · rw [hmem]; exact hag.ro
  · intro s hs hag s' hsty s'' hstep
    have heq := stays_regOnly (i := x64_ir.PInsn.PcLabel slot) trivial hc hsty
    subst heq
    have hr := (step_returned_ret hstep).1
    rw [hs, hc] at hr
    simp at hr

/-- An unconditional branch leaves its range at its target and nowhere else. -/
theorem jmp_run {P : Params} {code : List x64_ir.PInsn} {p t : Nat} {pt : x64_ir.PTarget}
    {pre : x64_check.State} (hd : pre.depth.val = 1) (hf : tagAt pre 15 = x64_check.Tag.Fp)
    (hc : code[p]? = some (.Jmp pt)) (hpos : pos code pt = some t) (hne : t ≠ p) :
    Run P code (Range p (p + 1)) p pre [(t, enterState)] := by
  have hstays : ∀ s s' : State, s.pc = p → Stays P code (Range p (p + 1)) s s' → s' = s := by
    intro s s' hs hst
    refine stays_leaves ?_ hst
    intro u u' hu hstep
    obtain ⟨i, hi, hux⟩ := step_jmp (by rw [hu]; exact hc) hstep
    simp only [Config.next.injEq] at hux
    subst hux
    rw [hpos] at hi
    simp only [Option.some.injEq] at hi
    subst hi
    simp only [Range, not_and, not_lt]
    omega
  refine ⟨?_, ?_, ?_⟩
  · intro s hs hag s' hsty c hstep ii hj bn hbn
    have heq := hstays s s' hs hsty; subst heq
    rw [hs, hc] at hj
    obtain rfl : ii = _ := by simpa using hj.symm
    simp at hbn
  · intro s hs hag s' hsty s'' hstep hout
    have heq := hstays s s' hs hsty; subst heq
    obtain ⟨i, hi, hux⟩ := step_jmp (by rw [hs]; exact hc) hstep
    simp only [Config.next.injEq] at hux
    subst hux
    rw [hpos] at hi
    simp only [Option.some.injEq] at hi
    subst hi
    refine ⟨(t, enterState), by simp, rfl, agree_enterState ?_ ?_ ?_ ?_⟩
    · exact agree_depth_one (s := s') hag hd
    · exact agree_fp (s := s') hag hf
    · exact hag.rbp
    · exact hag.ro
  · intro s hs hag s' hsty s'' hstep
    have heq := hstays s s' hs hsty; subst heq
    have hr := (step_returned_ret hstep).1
    rw [hs, hc] at hr
    simp at hr

theorem step_dispatcherSlot {P : Params} {code : List x64_ir.PInsn} {s : State} {c : Config}
    {a : Std.U64} (hc : code[s.pc]? = some (.DispatcherSlot a)) (h : Step P code s c) :
    c = .halt := by
  cases h <;> simp_all

theorem step_helperTable {P : Params} {code : List x64_ir.PInsn} {s : State} {c : Config}
    (hc : code[s.pc]? = some .HelperTable) (h : Step P code s c) : c = .halt := by
  cases h <;> simp_all

/-- A macro of one primitive that halts and touches nothing: the trailer's two
data macros. -/
theorem halt_run {P : Params} {code : List x64_ir.PInsn} {p : Nat} {pre : x64_check.State}
    {ii : x64_ir.PInsn} (hc : code[p]? = some ii) (hacc : ∀ s : State, accesses ii s = [])
    (hhalt : ∀ (s : State) (c : Config), code[s.pc]? = some ii → Step P code s c → c = .halt) :
    Run P code (Range p (p + 1)) p pre [] := by
  have hstays : ∀ s s' : State, s.pc = p → Stays P code (Range p (p + 1)) s s' → s' = s := by
    intro s s' hs hst
    refine stays_leaves ?_ hst
    intro u u' hu hstep
    exact absurd (hhalt u _ (by rw [hu]; exact hc) hstep) (by simp)
  refine ⟨?_, ?_, ?_⟩
  · intro s hs hag s' hsty c hstep jj hj bn hbn
    have heq := hstays s s' hs hsty; subst heq
    rw [hs, hc] at hj
    obtain rfl : jj = _ := by simpa using hj.symm
    rw [hacc] at hbn
    simp at hbn
  · intro s hs hag s' hsty s'' hstep hout
    have heq := hstays s s' hs hsty; subst heq
    exact absurd (hhalt s' _ (by rw [hs]; exact hc) hstep) (by simp)
  · intro s hs hag s' hsty s'' hstep
    have heq := hstays s s' hs hsty; subst heq
    exact absurd (hhalt s' _ (by rw [hs]; exact hc) hstep) (by simp)



/-! ## The invariant's vocabulary -/

/-- A macro a branch can land on, and so one that is entered in `enterState`:
a `PcLabel` some branch names — whose post-state is then `enterState` too — or
the trailer's epilogue, which carries the exit label. -/
def Entered (M : List x64_ir.MInsn) (a : List x64_check.State) (j : Nat) : Prop :=
  (∃ slot, M[j]? = some (.PcLabel slot) ∧ a[j + 1]! = enterState) ∨
  (M[j]? = some .Epilogue ∧ trailerAt M j = true)

/-- The abstract states macro `j` may be entered in: the one the checker's
walk arrived with, live, or `enterState` at a slot a branch can land on. -/
def PreAt (M : List x64_ir.MInsn) (a : List x64_check.State) (j : Nat)
    (α : x64_check.State) : Prop :=
  (α = a[j]! ∧ α.alive = true) ∨ (α = enterState ∧ Entered M a j)

def IsHelperCall (M : List x64_ir.MInsn) (j : Nat) : Prop :=
  ∃ idx, M[j]? = some (.HelperCall idx)

/-- The positions macro `j`'s expansion runs through: its own chunk, and — for
a helper call, whose `call Retpoline` leaves it and comes back — the
retpoline's chunk in the trailer. -/
def regionOf (cfg : x64_ir.Cfg) (M : List x64_ir.MInsn) (j : Nat) : Nat → Prop := fun x =>
  Range (chunkStart cfg M j) (chunkStart cfg M (j + 1)) x ∨
  (IsHelperCall M j ∧
    Range (chunkStart cfg M (M.length - 3)) (chunkStart cfg M (M.length - 2)) x)

theorem regionOf_of_not_helper {cfg : x64_ir.Cfg} {M : List x64_ir.MInsn} {j : Nat}
    (h : ¬ IsHelperCall M j) (x : Nat) :
    regionOf cfg M j x ↔ Range (chunkStart cfg M j) (chunkStart cfg M (j + 1)) x := by
  simp only [regionOf]
  constructor
  · rintro (h1 | ⟨h1, -⟩)
    · exact h1
    · exact absurd h1 h
  · exact Or.inl

/-- Where a way out of a macro may land: the start of a macro, in a state that
macro admits. -/
def Landing (cfg : x64_ir.Cfg) (M : List x64_ir.MInsn) (a : List x64_check.State)
    (e : Nat × x64_check.State) : Prop :=
  ∃ k, k < M.length ∧ e.1 = chunkStart cfg M k ∧ PreAt M a k e.2

theorem exists_least {q : Nat → Prop} (h : ∃ n, q n) : ∃ n, q n ∧ ∀ m, m < n → ¬ q m := by
  classical
  exact ⟨Nat.find h, Nat.find_spec h, fun m hm => Nat.find_min h hm⟩

/-- Chunk starts are injective, because no chunk is empty. -/
theorem chunkStart_inj {cfg : x64_ir.Cfg} (hcage : cfg.pointer_mask ≠ 0#i32)
    {M : List x64_ir.MInsn} {i j : Nat} (hi : i ≤ M.length) (hj : j ≤ M.length)
    (h : chunkStart cfg M i = chunkStart cfg M j) : i = j := by
  rcases Nat.lt_trichotomy i j with hlt | heq | hgt
  · exact absurd h (by have := chunkStart_strictMono hcage hj hlt; omega)
  · exact heq
  · exact absurd h (by have := chunkStart_strictMono hcage hi hgt; omega)

/-! ## Where a branch lands -/

/-- A branch to a labelled slot lands on the first `PcLabel` that marks it,
which the checker walked into `enterState`. -/
theorem Walk.landing_pc (W : Walk P cfg code) {slot : Std.U32}
    (hlab : x64_check.is_labelled W.labels slot = ok true)
    (htgt : x64_check.is_target W.labels slot = ok true) :
    ∃ k, k < code.val.length ∧
      pos (flat cfg code.val) (.Pc slot) = some (chunkStart cfg code.val k) ∧
      Entered code.val W.a k := by
  obtain ⟨i, hi, hmi⟩ := (scan_is_labelled W.hscan slot).mp hlab
  obtain ⟨k, hk, hmin⟩ := exists_least (q := fun j => code.val[j]? = some (x64_ir.MInsn.PcLabel slot))
    ⟨i, hmi⟩
  have hklt : k < code.val.length := List.getElem?_eq_some_iff.mp hk |>.1
  refine ⟨k, hklt, pos_pc cfg code.val k slot hmin hk, Or.inl ⟨slot, hk, ?_⟩⟩
  obtain ⟨idx, pcv, -, hst⟩ := W.dispatch hklt hk
  rcases label_step_spec hst with ⟨hnt, -⟩ | ⟨-, -, hE⟩
  · rw [htgt] at hnt; simp at hnt
  · exact enterShaped_eq hE

/-- A branch to `Exit` lands on the trailer's epilogue. -/
theorem Walk.landing_exit (W : Walk P cfg code) (htr : W.labels.trailer = true) :
    ∃ k, k < code.val.length ∧
      pos (flat cfg code.val) .Exit = some (chunkStart cfg code.val k) ∧
      Entered code.val W.a k := by
  obtain ⟨hlen4, hE, hR, -, -⟩ := hasTrailer_iff.mp ((scan_trailer W.hscan).mp htr)
  set n := code.val.length with hn
  have htrAt : trailerAt code.val (n - 4) = true := by
    unfold trailerAt
    rw [show n - 4 + 1 = n - 3 by omega, hR]
    rfl
  have hbefore : ∀ j, j < n - 4 →
      ¬ (code.val[j]? = some .Epilogue ∧ trailerAt code.val j = true) := by
    rintro j hj ⟨-, hjt⟩
    have hj1 : code.val[j + 1]? = some .Retpoline := by
      unfold trailerAt at hjt
      cases hm : code.val[j + 1]? with
      | none => rw [hm] at hjt; simp at hjt
      | some mm =>
        rw [hm] at hjt
        cases mm <;> simp_all [isRetpoline]
    have hj1lt : j + 1 < n := List.getElem?_eq_some_iff.mp hj1 |>.1
    have := W.retpoline_unique hj1lt hj1
    omega
  exact ⟨n - 4, by omega, pos_exit cfg code.val (n - 4) hE (by
    rw [show n - 4 + 1 = n - 3 by omega]; exact hR) hbefore, Or.inr ⟨hE, htrAt⟩⟩

/-- A macro a branch can land on is entered in `enterState`. -/
theorem landing_of_entered {cfg : x64_ir.Cfg} {M : List x64_ir.MInsn}
    {a : List x64_check.State} {k : Nat} (hk : k < M.length) (hE : Entered M a k) :
    Landing cfg M a (chunkStart cfg M k, enterState) :=
  ⟨k, hk, rfl, Or.inr ⟨rfl, hE⟩⟩

/-- And it is a `PcLabel` or the trailer's epilogue, so never a branch: no
branch has itself as its target. -/
theorem Entered.ne_of {M : List x64_ir.MInsn} {a : List x64_check.State} {k j : Nat}
    {m : x64_ir.MInsn} (hE : Entered M a k) (hm : M[j]? = some m)
    (h1 : ∀ s, m ≠ .PcLabel s) (h2 : m ≠ .Epilogue) : k ≠ j := by
  rintro rfl
  rcases hE with ⟨slot, hs, -⟩ | ⟨hs, -⟩
  · exact h1 slot (Option.some.inj (hm.symm.trans hs))
  · exact h2 (Option.some.inj (hm.symm.trans hs))

/-- Where a branch goes, whichever of the two kinds of target it names. -/
theorem Walk.branch_landing (W : Walk P cfg code) {target : x64_ir.Target}
    (hlab : ∀ n, target = .Pc n → x64_check.is_labelled W.labels n = ok true)
    (hex : target = .Exit → W.labels.trailer = true)
    (htgt : ∀ n, target = .Pc n → x64_check.is_target W.labels n = ok true) :
    ∃ k, k < code.val.length ∧
      pos (flat cfg code.val) (ptargetOf target) = some (chunkStart cfg code.val k) ∧
      Entered code.val W.a k := by
  cases target with
  | Pc n => exact W.landing_pc (hlab n rfl) (htgt n rfl)
  | Exit => exact W.landing_exit (hex rfl)



/-! ## From a macro lemma to a run -/

theorem not_helperCall_of {M : List x64_ir.MInsn} {j : Nat} {m : x64_ir.MInsn}
    (hmj : M[j]? = some m) (hne : ∀ idx, m ≠ .HelperCall idx) : ¬ IsHelperCall M j := by
  rintro ⟨idx, hc⟩
  rw [hmj] at hc
  exact hne idx (Option.some.inj hc)

theorem run_of_macroOk {j N : Nat} {α post : x64_check.State}
    {exits : List (Nat × x64_check.State)} (hnh : ¬ IsHelperCall code.val j)
    (hlen : chunkLen cfg code.val j = N)
    (h : MacroOk P (flat cfg code.val) (chunkStart cfg code.val j)
      (chunkStart cfg code.val j + N) α post exits) :
    Run P (flat cfg code.val) (regionOf cfg code.val j) (chunkStart cfg code.val j) α
      ((chunkStart cfg code.val (j + 1), post) :: exits) := by
  have hq : chunkStart cfg code.val (j + 1) = chunkStart cfg code.val j + N := by
    rw [chunkStart_step, hlen]
  have hiff : ∀ x, Range (chunkStart cfg code.val j) (chunkStart cfg code.val j + N) x ↔
      regionOf cfg code.val j x := fun x => by rw [regionOf_of_not_helper hnh x, hq]
  rw [hq]
  exact Run.congr hiff (Run.ofMacroOk h)

theorem run_of_run {j N : Nat} {α : x64_check.State}
    {nx : List (Nat × x64_check.State)} (hnh : ¬ IsHelperCall code.val j)
    (hlen : chunkLen cfg code.val j = N)
    (h : Run P (flat cfg code.val) (Range (chunkStart cfg code.val j)
      (chunkStart cfg code.val j + N)) (chunkStart cfg code.val j) α nx) :
    Run P (flat cfg code.val) (regionOf cfg code.val j) (chunkStart cfg code.val j) α nx := by
  have hq : chunkStart cfg code.val (j + 1) = chunkStart cfg code.val j + N := by
    rw [chunkStart_step, hlen]
  exact Run.congr (fun x => by rw [regionOf_of_not_helper hnh x, hq]) h

/-- The fallthrough always lands on the next macro, which the walk left live. -/
theorem Walk.fallthrough_landing (W : Walk P cfg code) {j : Nat} (hj : j < code.val.length)
    (hal : W.a[j + 1]!.alive = true) :
    Landing cfg code.val W.a (chunkStart cfg code.val (j + 1), W.a[j + 1]!) := by
  have hlt : j + 1 < code.val.length := by
    by_contra hc
    have he : j + 1 = code.val.length := by omega
    rw [he, W.hdead] at hal
    simp at hal
  exact ⟨j + 1, hlt, rfl, Or.inl ⟨rfl, hal⟩⟩

/-- The shape almost every macro takes: one contiguous run that falls through
to the next macro and nowhere else. -/
theorem Walk.simple_run (W : Walk P cfg code) {j N : Nat} (hj : j < code.val.length)
    (hnh : ¬ IsHelperCall code.val j) (hlen : chunkLen cfg code.val j = N)
    (hal : W.a[j + 1]!.alive = true)
    (h : MacroOk P (flat cfg code.val) (chunkStart cfg code.val j)
      (chunkStart cfg code.val j + N) W.a[j]! W.a[j + 1]! []) :
    ∃ nx, Run P (flat cfg code.val) (regionOf cfg code.val j) (chunkStart cfg code.val j)
        W.a[j]! nx ∧ ∀ e ∈ nx, Landing cfg code.val W.a e := by
  refine ⟨_, run_of_macroOk hnh hlen h, ?_⟩
  intro e he
  simp only [List.mem_cons, List.not_mem_nil, or_false] at he
  subst he
  exact W.fallthrough_landing hj hal



/-! ## The mirrors agree

The per-macro lemmas of `CheckedAddr.lean`, `Arith.lean` and `Calls.lean`
write each expansion out for themselves; `Expand.lean` writes the same
sequences as `chunk`. These are the four places the two spellings meet. -/

theorem checkedAddrList_eq_chunk (cfg : x64_ir.Cfg) (src dst scratch : Std.U8)
    (offset : Std.I32) (size : Std.U32) (hint : Std.U8) :
    checkedAddrList cfg src dst scratch offset size hint
      = chunkCheckedAddr cfg src dst scratch offset size hint := rfl

theorem mdIsDiv_eq (k : x64_ir.MulDivKind) : mdIsDiv k = isDiv k := by cases k <;> rfl
theorem mdIsMod_eq (k : x64_ir.MulDivKind) : mdIsMod k = isMod k := by cases k <;> rfl
theorem mdIsMul_eq (k : x64_ir.MulDivKind) : mdIsMul k = isMul k := by cases k <;> rfl

theorem mulDivSetupList_eq (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) :
    mulDivSetupList kind w64 reg signed src dst imm
      = chunkMulDivSetup kind w64 reg signed src dst imm := by
  unfold mulDivSetupList chunkMulDivSetup
  simp only [mdIsDiv_eq, mdIsMod_eq]

theorem mulDivOverflowList_eq (w64 div : Bool) (noOverflow afterDivide : Nat) :
    mulDivOverflowList w64 div noOverflow afterDivide
      = chunkMulDivOverflow w64 div noOverflow afterDivide := rfl

theorem mulDivFinishList_eq (kind : x64_ir.MulDivKind) (dst : Std.U8) :
    mulDivFinishList kind dst = chunkMulDivFinish kind dst := by
  unfold mulDivFinishList chunkMulDivFinish
  simp only [mdIsDiv_eq, mdIsMod_eq, mdIsMul_eq]

theorem mulDivModList_eq_chunk (kind : x64_ir.MulDivKind) (w64 reg signed : Bool)
    (src dst : Std.U8) (imm : Std.I32) (label : Nat) :
    mulDivModList kind w64 reg signed src dst imm label
      = (chunkMulDivMod kind w64 reg signed src dst imm label).1 := by
  unfold mulDivModList chunkMulDivMod mulDivMidList
  simp only [mulDivSetupList_eq, mulDivFinishList_eq, mulDivOverflowList_eq,
    mdIsDiv_eq, mdIsMod_eq, mdIsMul_eq, apply_ite Prod.fst]
  split <;> [skip; split] <;> simp [List.append_assoc, mdU32, u32]

theorem atomicFetchAluList_eq_chunk (op : Std.U8) (w64 : Bool) (src base : Std.U8)
    (disp : Std.I32) (label : Nat) :
    atomicFetchAluList op w64 src base disp label
      = (chunkAtomicFetchAlu op w64 src base disp label).1 := rfl

theorem helperCallList_eq_chunk (idx : Std.U32) (label : Nat) :
    helperCallList idx label = (chunkHelperCall idx label).1 := rfl

theorem retpolineList_eq_chunk (label : Nat) :
    retpolineList label = (chunkRetpoline label).1 := rfl

theorem lazyLocalCallList_eq_chunk (cfg : x64_ir.Cfg) (id : Std.U32) (label : Nat) :
    lazyLocalCallList cfg id label = (chunkLazyLocalCall cfg id label).1 := rfl



/-! ## Reading the chain at one macro

The small facts the case analysis below needs at every macro: where its chunk
sits, how long it is, how its local labels resolve, and that the walk is still
alive on the other side of it. -/

theorem Walk.alive_zero (W : Walk P cfg code) : W.a[0]!.alive = true :=
  (entry_state_eq W.hentry).2.2.1

/-- The macro list is not empty: the walk starts alive and ends dead. -/
theorem Walk.len_pos (W : Walk P cfg code) : 0 < code.val.length := by
  rcases Nat.eq_zero_or_pos code.val.length with h | h
  · exfalso
    have hd := W.hdead
    rw [h, W.alive_zero] at hd
    simp at hd
  · exact h

@[simp] theorem chunkStart_zero (cfg : x64_ir.Cfg) (M : List x64_ir.MInsn) :
    chunkStart cfg M 0 = 0 := by
  cases M <;> rfl

theorem Walk.startLt (W : Walk P cfg code) {j : Nat} (hj : j < code.val.length) :
    chunkStart cfg code.val j < chunkStart cfg code.val (j + 1) :=
  chunkStart_lt W.hcage hj

/-- Every macro's region contains its own first position. -/
theorem Walk.region_start (W : Walk P cfg code) {j : Nat} (hj : j < code.val.length) :
    regionOf cfg code.val j (chunkStart cfg code.val j) :=
  Or.inl ⟨le_refl _, W.startLt hj⟩

/-- The primitives of macro `j` sit at `chunkStart j`. -/
theorem Walk.laid (_W : Walk P cfg code) {j : Nat} {m : x64_ir.MInsn}
    (hm : code.val[j]? = some m) {k : Nat}
    (hk : k < (chunk cfg m (trailerAt code.val j) (labelBase cfg code.val j)).1.length) :
    (flat cfg code.val)[chunkStart cfg code.val j + k]?
      = (chunk cfg m (trailerAt code.val j) (labelBase cfg code.val j)).1[k]? :=
  laid_of_drop (flat_macro cfg code.val j m hm).1 k hk

theorem Walk.labelBound (W : Walk P cfg code) {j : Nat} (hj : j < code.val.length) :
    labelBase cfg code.val (j + 1) < 2 ^ 32 := by
  have h1 := labelBase_mono cfg code.val (i := j + 1) (j := code.val.length) (by omega)
  have h2 := W.hlabels
  omega

/-- A local label of macro `j` resolves inside macro `j`'s own chunk. -/
theorem Walk.posLocal (W : Walk P cfg code) {j : Nat} (hj : j < code.val.length) {k : Nat}
    {n : Std.U32} (hk : (chunkAt cfg code.val j).1[k]? = some (.Local n)) :
    pos (flat cfg code.val) (.Local n) = some (chunkStart cfg code.val j + k) :=
  pos_local_of_chunk cfg code.val j (W.labelBound hj) hk

/-- The retpoline's own macro is walked dead: the trailer's epilogue before it
killed the walk. -/
theorem Walk.retpoline_pre_dead (W : Walk P cfg code) {r : Nat} (hr : r < code.val.length)
    (hm : code.val[r]? = some .Retpoline) : W.a[r]!.alive = false := by
  obtain ⟨h1, -, hEp, -, -, -⟩ := W.retpoline_trailerAt hr hm
  have hrm : r - 1 < code.val.length := by omega
  obtain ⟨idx, pcv, -, hst⟩ := W.dispatch hrm hEp
  have hst' : x64_check.live_step cfg .Epilogue idx pcv W.a[r - 1]! = ok (.Ok (), W.a[r - 1 + 1]!) :=
    hst
  rw [show r - 1 + 1 = r by omega] at hst'
  by_cases hal : W.a[r - 1]!.alive = true
  · obtain ⟨-, -, hp⟩ := live_step_Epilogue_spec hal hst'
    rw [hp]
  · rw [live_step_post_dead (by simpa using hal) hst']
    simpa using hal

/-! ## Liveness along the chain

Only the three macros that do not fall through — the epilogue, the retpoline
and the unconditional branch — kill the walk. -/

theorem alive_of_setsTop {pre post : x64_check.State} {S : Nat → Prop}
    (h : SetsTop pre post S) (hal : pre.alive = true) : post.alive = true := by
  rw [h.2.2.2.2]; exact hal

theorem alive_of_clobber {pre post : x64_check.State} (h : ClobberCall pre post)
    (hal : pre.alive = true) : post.alive = true := by
  rw [h.2.2.2.2]; exact hal

theorem stepRule_alive {cfg : x64_ir.Cfg} {code : Slice x64_ir.MInsn}
    {labels : x64_check.Labels} {idx : Std.Usize} {pcv : Std.U32}
    {pre post : x64_check.State} {m : x64_ir.MInsn} (hal : pre.alive = true)
    (hr : StepRule cfg code labels idx pcv pre post m)
    (h1 : m ≠ .Epilogue) (h2 : m ≠ .Retpoline) (h3 : ∀ t, m ≠ .Jmp t) :
    post.alive = true := by
  have hsame : post = pre → post.alive = true := by rintro rfl; exact hal
  cases m with
  | PcLabel slot =>
    rcases label_step_spec hr with ⟨-, hp⟩ | ⟨-, -, hE⟩
    · exact hsame hp
    · exact hE.2.2.2
  | Prologue u skip => exact (prologue_step_spec hr).2.2.2.2
  | Jcc cc target =>
    obtain ⟨-, -, -, -, -, -, -, hu⟩ := branch_step_spec hr
    rw [hu rfl]; exact hal
  | Jmp target => exact absurd rfl (h3 target)
  | Retpoline => exact absurd rfl h2
  | Epilogue => exact absurd rfl h1
  | DispatcherSlot =>
    obtain ⟨u, -, hu⟩ := hr
    exact hsame (by simpa using (Prod.mk.injEq _ _ _ _ ▸ hu).2)
  | HelperTable =>
    obtain ⟨u, -, hu⟩ := hr
    exact hsame (by simpa using (Prod.mk.injEq _ _ _ _ ▸ hu).2)
  | Alu w64 op src dst =>
    obtain ⟨hw, hk⟩ := live_step_Alu_spec hal hr
    cases hb : AluRRWrites op
    · exact hsame (hk hb)
    · exact alive_of_setsTop (hw hb).2 hal
  | AluImm w64 op dst imm =>
    obtain ⟨hw, hk⟩ := live_step_AluImm_spec hal hr
    cases hb : AluRIWrites op
    · exact hsame (hk hb)
    · exact alive_of_setsTop (hw hb).2 hal
  | ShiftImm w64 op dst imm => exact alive_of_setsTop (live_step_ShiftImm_spec hal hr).2 hal
  | ShiftCl w64 op dst => exact alive_of_setsTop (live_step_ShiftCl_spec hal hr).2 hal
  | Neg w64 dst => exact alive_of_setsTop (live_step_Neg_spec hal hr).2 hal
  | MovSx from_ w64 src dst => exact alive_of_setsTop (live_step_MovSx_spec hal hr).2 hal
  | Bswap w64 dst => exact alive_of_setsTop (live_step_Bswap_spec hal hr).2 hal
  | Rol16 dst => exact alive_of_setsTop (live_step_Rol16_spec hal hr).2 hal
  | LoadImm dst imm => exact alive_of_setsTop (live_step_LoadImm_spec hal hr).2 hal
  | GuestFp dst => exact alive_of_setsTop (live_step_GuestFp_spec hal hr).2 hal
  | MulDivMod kind w64 signed imm src dst d =>
    exact alive_of_setsTop (live_step_MulDivMod_spec hal hr).2.2 hal
  | CheckedAddr src dst scratch offset size hint =>
    obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, hal'⟩ := live_step_CheckedAddr_spec hal hr
    rw [hal']; exact hal
  | GroupBaseStore src => rw [live_step_GroupBaseStore_spec hal hr]; exact hal
  | GroupBaseLoad dst =>
    obtain ⟨-, -, -, -, -, hal'⟩ := live_step_GroupBaseLoad_spec hal hr
    rw [hal']; exact hal
  | Load size sx base dst disp => exact alive_of_setsTop (live_step_Load_spec hal hr).2.2 hal
  | Store size src base disp => exact hsame (live_step_Store_spec hal hr).2
  | StoreImm size base disp imm => exact hsame (live_step_StoreImm_spec hal hr).2
  | AtomicAlu op w64 src base disp => exact hsame (live_step_AtomicAlu_spec hal hr).2
  | AtomicFetchAlu op w64 src base disp =>
    exact alive_of_setsTop (live_step_AtomicFetchAlu_spec hal hr).2.2.2.1 hal
  | AtomicXchg w64 src base disp =>
    exact alive_of_setsTop (live_step_AtomicXchg_spec hal hr).2.2 hal
  | AtomicCmpxchg w64 src base disp =>
    exact alive_of_setsTop (live_step_AtomicCmpxchg_spec hal hr).2 hal
  | HelperCall i' => exact alive_of_clobber (live_step_HelperCall_spec hal hr).2.2 hal
  | LazyLocalCall id => exact alive_of_clobber (live_step_LazyLocalCall_spec hal hr).2.2.2 hal

/-- So the walk is alive after every macro but the three that do not fall
through. -/
theorem Walk.alive_succ (W : Walk P cfg code) {j : Nat} (hj : j < code.val.length)
    {m : x64_ir.MInsn} (hm : code.val[j]? = some m) (hal : W.a[j]!.alive = true)
    (h1 : m ≠ .Epilogue) (h2 : m ≠ .Retpoline) (h3 : ∀ t, m ≠ .Jmp t) :
    W.a[j + 1]!.alive = true := by
  obtain ⟨idx, pcv, -, hr⟩ := W.dispatch hj hm
  exact stepRule_alive hal hr h1 h2 h3

/-- A macro that is neither a `PcLabel` nor the trailer's epilogue is entered
only in the state the walk arrived with. -/
theorem preAt_live {M : List x64_ir.MInsn} {a : List x64_check.State} {j : Nat}
    {α : x64_check.State} {m : x64_ir.MInsn} (hm : M[j]? = some m)
    (hnl : ∀ slot, m ≠ .PcLabel slot) (hne : m ≠ .Epilogue) (h : PreAt M a j α) :
    α = a[j]! ∧ α.alive = true := by
  rcases h with h | ⟨-, hE⟩
  · exact h
  · exfalso
    rcases hE with ⟨slot, hs, -⟩ | ⟨hs, -⟩
    · exact hnl slot (Option.some.inj (hm.symm.trans hs))
    · exact hne (Option.some.inj (hm.symm.trans hs))


/-! ## The trailer's four macros

`HasTrailer`, read off the last four positions, and the two facts about the
flat list that the helper call's contract asks for: where the retpoline's
landing pad sits, and what the dispatcher slot holds. -/

theorem Walk.len4 (W : Walk P cfg code) : 4 ≤ code.val.length :=
  (hasTrailer_iff.mp W.htrailer).1

theorem Walk.mEpilogue (W : Walk P cfg code) :
    code.val[code.val.length - 4]? = some .Epilogue :=
  (hasTrailer_iff.mp W.htrailer).2.1

theorem Walk.mRetpoline (W : Walk P cfg code) :
    code.val[code.val.length - 3]? = some .Retpoline :=
  (hasTrailer_iff.mp W.htrailer).2.2.1

theorem Walk.mDispatcherSlot (W : Walk P cfg code) :
    code.val[code.val.length - 2]? = some .DispatcherSlot :=
  (hasTrailer_iff.mp W.htrailer).2.2.2.1

theorem Walk.mHelperTable (W : Walk P cfg code) :
    code.val[code.val.length - 1]? = some .HelperTable :=
  (hasTrailer_iff.mp W.htrailer).2.2.2.2

/-- No macro before the last but three is the retpoline. -/
theorem Walk.retpoline_first (W : Walk P cfg code) :
    ∀ j, j < code.val.length - 3 → code.val[j]? ≠ some .Retpoline := by
  intro j hj hc
  have hjl : j < code.val.length := by have := W.len4; omega
  have := W.retpoline_unique hjl hc
  omega

theorem Walk.posRetpoline (W : Walk P cfg code) :
    pos (flat cfg code.val) .Retpoline
      = some (chunkStart cfg code.val (code.val.length - 3)) :=
  pos_retpoline cfg code.val _ W.mRetpoline W.retpoline_first

theorem Walk.dispAddr (W : Walk P cfg code) :
    dispatcherAddr (flat cfg code.val) = P.dispatcher := by
  rw [dispatcherAddr_flat_ofNat cfg code.val _ W.mDispatcherSlot]
  exact W.hdisp.symm

/-! ## One macro's run

What the glue proves of macro `j`: from any abstract state the macro may be
entered in, its expansion runs safely and every way out of it lands on a
macro that admits the state it arrives in. -/

/-- The statement, for one macro and one state it may be entered in. -/
def RunsTo (W : Walk P cfg code) (j : Nat) (α : x64_check.State) : Prop :=
  ∃ nx, Run P (flat cfg code.val) (regionOf cfg code.val j) (chunkStart cfg code.val j) α nx ∧
    ∀ e ∈ nx, Landing cfg code.val W.a e

/-- The helper call, whose region is its own nineteen positions together with
the trailer's retpoline. -/
theorem Walk.helperCall_run (W : Walk P cfg code) {j : Nat} (hj : j < code.val.length)
    {hidx : Std.U32} (hm : code.val[j]? = some (.HelperCall hidx))
    (hal : W.a[j]!.alive = true) {idx : Std.Usize} {pcv : Std.U32}
    (hrule : x64_check.live_step cfg (.HelperCall hidx) idx pcv W.a[j]!
      = ok (.Ok (), W.a[j + 1]!)) :
    RunsTo W j W.a[j]! := by
  have h4 := W.len4
  have hRet : code.val[code.val.length - 3]? = some .Retpoline := W.mRetpoline
  obtain ⟨hdropH, hlenH, -⟩ := flat_helperCall cfg code.val j hm
  obtain ⟨hdropR, hlenR, -⟩ := flat_retpoline cfg code.val (code.val.length - 3) hRet
  rw [← helperCallList_eq_chunk] at hdropH
  rw [← retpolineList_eq_chunk] at hdropR
  -- a helper call is none of the trailer's four macros, so it sits before them
  have hj4 : j + 1 < code.val.length - 3 := by
    rcases Nat.lt_or_ge j (code.val.length - 4) with h | h
    · omega
    · exfalso
      have hcases : j = code.val.length - 4 ∨ j = code.val.length - 3 ∨
          j = code.val.length - 2 ∨ j = code.val.length - 1 := by omega
      rcases hcases with h' | h' | h' | h' <;> rw [h'] at hm
      · rw [W.mEpilogue] at hm; simp at hm
      · rw [W.mRetpoline] at hm; simp at hm
      · rw [W.mDispatcherSlot] at hm; simp at hm
      · rw [W.mHelperTable] at hm; simp at hm
  have hstart : chunkStart cfg code.val (j + 1) = chunkStart cfg code.val j + 19 := by
    rw [chunkStart_step, hlenH]
  have hstartR : chunkStart cfg code.val (code.val.length - 2)
      = chunkStart cfg code.val (code.val.length - 3) + 8 := by
    rw [show code.val.length - 2 = code.val.length - 3 + 1 by omega, chunkStart_step, hlenR]
  have hdisjoint : chunkStart cfg code.val (code.val.length - 3) + 8
        ≤ chunkStart cfg code.val j ∨
      chunkStart cfg code.val j + 19 < chunkStart cfg code.val (code.val.length - 3) := by
    refine Or.inr ?_
    rw [← hstart]
    exact chunkStart_strictMono W.hcage (by omega) hj4
  -- the configured dispatcher is not null, so the branch over the fallback is taken
  have hdispNZ : P.dispatcher ≠ 0#64 := by
    have hd := (live_step_HelperCall_spec hal hrule).1
    have hlt : cfg.dispatcher.val < 2 ^ 64 := by scalar_tac
    rw [W.hdisp]
    intro hc
    refine hd ?_
    have := congrArg BitVec.toNat hc
    rw [BitVec.toNat_ofNat] at this
    simp only [BitVec.toNat_ofNat, Nat.zero_mod] at this
    omega
  have hmacro := macroOkIn_helperCall (P := P) (code := flat cfg code.val)
    (p := chunkStart cfg code.val j)
    (rp := chunkStart cfg code.val (code.val.length - 3))
    (label := labelBase cfg code.val j)
    (rlabel := labelBase cfg code.val (code.val.length - 3))
    W.hL W.hflen hal hrule
    (fun k hk => laid_of_drop hdropH k hk)
    (fun k hk => laid_of_drop hdropR k hk)
    W.posRetpoline
    (W.posLocal hj (k := 10) (by rw [chunkAt_eq hm]; rfl))
    (W.posLocal hj (k := 12) (by rw [chunkAt_eq hm]; rfl))
    (W.posLocal (j := code.val.length - 3) (by omega) (k := 5) (by rw [chunkAt_eq hRet]; rfl))
    (W.posLocal (j := code.val.length - 3) (by omega) (k := 2) (by rw [chunkAt_eq hRet]; rfl))
    W.dispAddr hdispNZ W.hdispCode hdisjoint
  simp only [helperCallList_length, retpolineList_length] at hmacro
  refine ⟨_, Run.congr ?_ (Run.ofMacroOkIn hmacro), ?_⟩
  · intro x
    simp only [regionOf, hstart, hstartR]
    constructor
    · rintro (h | h)
      · exact Or.inl h
      · exact Or.inr ⟨⟨hidx, hm⟩, h⟩
    · rintro (h | ⟨-, h⟩)
      · exact Or.inl h
      · exact Or.inr h
  · intro e he
    simp only [List.mem_cons, List.not_mem_nil, or_false] at he
    subst he
    rw [← hstart]
    exact W.fallthrough_landing hj
      (alive_of_clobber (live_step_HelperCall_spec hal hrule).2.2 hal)


/-! ## Every macro's run, one constructor at a time -/

theorem Walk.macro_run (W : Walk P cfg code) {j : Nat} (hj : j < code.val.length)
    {α : x64_check.State} (hpre : PreAt code.val W.a j α) : RunsTo W j α := by
  obtain ⟨m, hm⟩ : ∃ m, code.val[j]? = some m := ⟨code.val[j], List.getElem?_eq_getElem hj⟩
  obtain ⟨idx, pcv, hidx, hrule⟩ := W.dispatch hj hm
  cases m with
  | PcLabel slot =>
    obtain ⟨hc, hlen⟩ := flat_pcLabel cfg code.val j hm
    have hnh : ¬ IsHelperCall code.val j := not_helperCall_of hm (by simp)
    rcases hpre with ⟨rfl, hal⟩ | ⟨rfl, hE⟩
    · have halive := W.alive_succ hj hm hal (by simp) (by simp) (by simp)
      rcases label_step_spec hrule with ⟨hnt, -⟩ | ⟨htg, -, -⟩
      · exact W.simple_run hj hnh hlen halive (macroOk_pcLabel_plain hc hnt hrule)
      · exact W.simple_run hj hnh hlen halive (macroOk_pcLabel_target hal hc htg hrule)
    · have hent : W.a[j + 1]! = enterState := by
        rcases hE with ⟨slot', hs, he⟩ | ⟨hs, -⟩
        · exact he
        · exact absurd (Option.some.inj (hm.symm.trans hs)) (by simp)
      have halive : W.a[j + 1]!.alive = true := by rw [hent]; rfl
      refine ⟨_, run_of_run hnh hlen (pcLabel_entered_run hc), ?_⟩
      intro e he
      simp only [List.mem_cons, List.not_mem_nil, or_false] at he
      subst he
      have hL := W.fallthrough_landing hj halive
      rw [hent, chunkStart_step, hlen] at hL
      exact hL
  | Prologue usage skip =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    have hnh : ¬ IsHelperCall code.val j := not_helperCall_of hm (by simp)
    have halive := W.alive_succ hj hm hal (by simp) (by simp) (by simp)
    cases skip
    · obtain ⟨hdrop, hlen, -⟩ := flat_prologue_plain cfg code.val j hm
      have hc0 := laid_of_drop hdrop 0 (by norm_num)
      have hc1 := laid_of_drop hdrop 1 (by norm_num)
      simp only [List.getElem?_cons_zero, List.getElem?_cons_succ, Nat.add_zero] at hc0 hc1
      exact W.simple_run hj hnh hlen halive
        (macroOk_prologue W.hL hal (W.stateOk_at j (by omega)).1 hc0 hc1 hrule)
    · obtain ⟨hdrop, hlen, -⟩ := flat_prologue_skip cfg code.val j hm
      have hc0 := laid_of_drop hdrop 0 (by norm_num)
      have hc1 := laid_of_drop hdrop 1 (by norm_num)
      have hc2 := laid_of_drop hdrop 2 (by norm_num)
      have hc3 := laid_of_drop hdrop 3 (by norm_num)
      simp only [List.getElem?_cons_zero, List.getElem?_cons_succ, Nat.add_zero] at hc0 hc1 hc2 hc3
      have hpos : pos (flat cfg code.val) (.Local (u32 (labelBase cfg code.val j)))
          = some (chunkStart cfg code.val j + 3) := by
        refine W.posLocal hj (k := 3) ?_
        rw [chunkAt_eq hm]
        rfl
      exact W.simple_run hj hnh hlen halive
        (macroOk_prologue_skip W.hL hal hc0 hc1 hc2 hc3 hpos hrule)
  | Epilogue =>
    have hdf : α.depth.val = 1 ∧ tagAt α 15 = x64_check.Tag.Fp := by
      rcases hpre with ⟨rfl, hal⟩ | ⟨rfl, -⟩
      · obtain ⟨hd, hf, -⟩ := live_step_Epilogue_spec hal hrule
        exact ⟨by rw [hd]; rfl, hf⟩
      · exact ⟨rfl, enterState_fp⟩
    have hnh : ¬ IsHelperCall code.val j := not_helperCall_of hm (by simp)
    by_cases htr : trailerAt code.val j = true
    · have h1 : code.val[j + 1]? = some .Retpoline := by
        unfold trailerAt at htr
        cases hmm : code.val[j + 1]? with
        | none => rw [hmm] at htr; simp at htr
        | some mm => rw [hmm] at htr; cases mm <;> simp_all [isRetpoline]
      obtain ⟨hdrop, hlen, -⟩ := flat_epilogue_trailer cfg code.val j hm h1
      have hE0 : ∀ k, k < 1 → (flat cfg code.val)[chunkStart cfg code.val j + k]?
          = some x64_ir.PInsn.ExitLabel := by
        intro k hk
        obtain rfl : k = 0 := by omega
        simpa using laid_of_drop hdrop 0 (by norm_num)
      have hc0 := laid_of_drop hdrop 1 (by norm_num)
      have hc1 := laid_of_drop hdrop 2 (by norm_num)
      simp only [List.getElem?_cons_zero, List.getElem?_cons_succ] at hc0 hc1
      have hrun := epilogue_run (P := P) (e := 1) W.hL hdf.1 hdf.2 hE0 hc0
        (by rw [show chunkStart cfg code.val j + 1 + 1 = chunkStart cfg code.val j + 2 by omega]
            exact hc1)
      rw [show chunkStart cfg code.val j + 1 + 2 = chunkStart cfg code.val j + 3 by omega] at hrun
      exact ⟨[], run_of_run hnh hlen hrun, by simp⟩
    · obtain ⟨hdrop, hlen, -⟩ := flat_epilogue_plain cfg code.val j hm (by simpa using htr)
      have hc0 := laid_of_drop hdrop 0 (by norm_num)
      have hc1 := laid_of_drop hdrop 1 (by norm_num)
      simp only [List.getElem?_cons_zero, List.getElem?_cons_succ] at hc0 hc1
      have hrun := epilogue_run (P := P) (e := 0) W.hL hdf.1 hdf.2
        (fun k hk => absurd hk (by omega)) (by simpa using hc0) (by simpa using hc1)
      rw [show chunkStart cfg code.val j + 0 + 2 = chunkStart cfg code.val j + 2 by omega] at hrun
      exact ⟨[], run_of_run hnh hlen hrun, by simp⟩
  | Jcc cc target =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_jcc cfg code.val j hm
    have hnh : ¬ IsHelperCall code.val j := not_helperCall_of hm (by simp)
    have halive := W.alive_succ hj hm hal (by simp) (by simp) (by simp)
    obtain ⟨-, hlab, hex, -, -, -, -, -⟩ := branch_step_spec hrule
    have htgt : ∀ n, target = .Pc n → x64_check.is_target W.labels n = ok true := by
      intro n hn
      exact (scan_is_target W.hscan n).mpr ⟨j, .Jcc cc target, hj, hm, by rw [hn]; rfl⟩
    obtain ⟨k, hk, hpos, hE⟩ := W.branch_landing hlab hex htgt
    have hne : chunkStart cfg code.val k ≠ chunkStart cfg code.val j := by
      intro hc'
      exact hE.ne_of hm (by simp) (by simp)
        (chunkStart_inj W.hcage (by omega) (by omega) hc')
    refine ⟨_, run_of_macroOk hnh hlen (macroOk_jcc hal hc hpos hne hrule), ?_⟩
    intro e he
    simp only [List.mem_cons, List.not_mem_nil, or_false] at he
    rcases he with rfl | rfl
    · exact W.fallthrough_landing hj halive
    · exact landing_of_entered hk hE
  | Jmp target =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_jmp cfg code.val j hm
    have hnh : ¬ IsHelperCall code.val j := not_helperCall_of hm (by simp)
    obtain ⟨hdf, hlab, hex, -, -, -, -, -⟩ := branch_step_spec hrule
    obtain ⟨hd, hf⟩ := hdf hal
    have htgt : ∀ n, target = .Pc n → x64_check.is_target W.labels n = ok true := by
      intro n hn
      exact (scan_is_target W.hscan n).mpr ⟨j, .Jmp target, hj, hm, by rw [hn]; rfl⟩
    obtain ⟨k, hk, hpos, hE⟩ := W.branch_landing hlab hex htgt
    have hne : chunkStart cfg code.val k ≠ chunkStart cfg code.val j := by
      intro hc'
      exact hE.ne_of hm (by simp) (by simp)
        (chunkStart_inj W.hcage (by omega) (by omega) hc')
    refine ⟨_, run_of_run hnh hlen (jmp_run (by rw [hd]; rfl) hf hc hpos hne), ?_⟩
    intro e he
    simp only [List.mem_cons, List.not_mem_nil, or_false] at he
    subst he
    exact landing_of_entered hk hE
  | Retpoline =>
    exfalso
    rcases hpre with ⟨rfl, hal⟩ | ⟨-, hE⟩
    · rw [W.retpoline_pre_dead hj hm] at hal; simp at hal
    · rcases hE with ⟨slot, hs, -⟩ | ⟨hs, -⟩ <;>
        exact absurd (Option.some.inj (hm.symm.trans hs)) (by simp)
  | DispatcherSlot =>
    obtain ⟨hc, hlen⟩ := flat_dispatcherSlot cfg code.val j hm
    refine ⟨[], run_of_run (not_helperCall_of hm (by simp)) hlen
      (halt_run hc (fun _ => rfl) (fun _ _ h hst => step_dispatcherSlot h hst)), by simp⟩
  | HelperTable =>
    obtain ⟨hc, hlen⟩ := flat_helperTable cfg code.val j hm
    refine ⟨[], run_of_run (not_helperCall_of hm (by simp)) hlen
      (halt_run hc (fun _ => rfl) (fun _ _ h hst => step_helperTable h hst)), by simp⟩
  | Alu w64 op src dst =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_alu cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp)) (macroOk_alu hal hc hrule)
  | AluImm w64 op dst imm =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_aluImm cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp)) (macroOk_aluImm hal hc hrule)
  | ShiftImm w64 op dst imm =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_shiftImm cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp)) (macroOk_shiftImm hal hc hrule)
  | ShiftCl w64 op dst =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_shiftCl cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp)) (macroOk_shiftCl hal hc hrule)
  | Neg w64 dst =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_neg cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp)) (macroOk_neg hal hc hrule)
  | MovSx from_ w64 src dst =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_movSx cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp)) (macroOk_movSx hal hc hrule)
  | Bswap w64 dst =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_bswap cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp)) (macroOk_bswap hal hc hrule)
  | Rol16 dst =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_rol16 cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp)) (macroOk_rol16 hal hc hrule)
  | LoadImm dst imm =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_loadImm cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp)) (macroOk_loadImm hal hc hrule)
  | GuestFp dst =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hdrop, hlen, -⟩ := flat_guestFp cfg code.val j hm
    have hc0 := laid_of_drop hdrop 0 (by simp [chunkGuestFp])
    have hc1 := laid_of_drop hdrop 1 (by simp [chunkGuestFp])
    simp only [chunkGuestFp, List.getElem?_cons_zero, List.getElem?_cons_succ,
      Nat.add_zero] at hc0 hc1
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_guestFp W.hL hal hc0 hc1 hrule)
  | GroupBaseStore src =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_groupBaseStore cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_groupBaseStore W.hL hal hc hrule)
  | GroupBaseLoad dst =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_groupBaseLoad cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_groupBaseLoad W.hL hal hc hrule)
  | Load size sx base dst disp =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_load cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_load W.hL W.hcfg (W.stateOk_at j (by omega)).2 W.hcage hal hc hrule)
  | Store size src base disp =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_store cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_store W.hL W.hcfg (W.stateOk_at j (by omega)).2 W.hcage hal hc hrule)
  | StoreImm size base disp imm =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_storeImm cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_storeImm W.hL W.hcfg (W.stateOk_at j (by omega)).2 W.hcage hal hc hrule)
  | AtomicAlu op w64 src base disp =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_atomicAlu cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_atomicAlu W.hL W.hcfg (W.stateOk_at j (by omega)).2 W.hcage hal hc hrule)
  | AtomicXchg w64 src base disp =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_atomicXchg cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_atomicXchg W.hL W.hcfg (W.stateOk_at j (by omega)).2 W.hcage hal hc hrule)
  | AtomicCmpxchg w64 src base disp =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hc, hlen⟩ := flat_atomicCmpxchg cfg code.val j hm
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_atomicCmpxchg W.hL W.hcfg (W.stateOk_at j (by omega)).2 W.hcage hal hc hrule)
  | CheckedAddr src dst scratch offset size hint =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hdrop, hlen, -⟩ := flat_checkedAddr cfg code.val j hm
    rw [← checkedAddrList_eq_chunk] at hdrop hlen
    exact W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_checkedAddr W.hL W.hcage hal hrule (fun k hk => laid_of_drop hdrop k hk))
  | MulDivMod kind w64 reg signed src dst imm =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hdrop, hlen, -⟩ := flat_mulDivMod cfg code.val j hm
    rw [← mulDivModList_eq_chunk] at hdrop hlen
    refine W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_mulDivMod W.hL hal hrule (fun k hk => laid_of_drop hdrop k hk) ?_)
    intro nn k hk
    refine W.posLocal hj (k := k) ?_
    rw [chunkAt_eq hm]
    show (chunk cfg (.MulDivMod kind w64 reg signed src dst imm)
      (trailerAt code.val j) (labelBase cfg code.val j)).1[k]? = _
    rw [show (chunk cfg (x64_ir.MInsn.MulDivMod kind w64 reg signed src dst imm)
      (trailerAt code.val j) (labelBase cfg code.val j)).1
        = mulDivModList kind w64 reg signed src dst imm (labelBase cfg code.val j) from
      (mulDivModList_eq_chunk _ _ _ _ _ _ _ _).symm]
    exact hk
  | AtomicFetchAlu op w64 src base disp =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hdrop, hlen, -⟩ := flat_atomicFetchAlu cfg code.val j hm
    rw [← atomicFetchAluList_eq_chunk] at hdrop hlen
    obtain ⟨-, -, -, -, hbase⟩ := live_step_AtomicFetchAlu_spec hal hrule
    have hpm : cfg.pointer_mask.val ≠ 0 :=
      fun hc => W.hcage (CA.i32_eq_iff'.mpr (by simp [hc]))
    obtain ⟨hax, hcx⟩ := hbase hpm
    refine W.simple_run hj (not_helperCall_of hm (by simp)) hlen
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_atomicFetchAlu W.hL W.hcage W.hcfg (W.stateOk_at j (by omega)).2 hal hax hcx
        hrule (fun k hk => laid_of_drop hdrop k hk) ?_)
    intro nn k hk
    refine W.posLocal hj (k := k) ?_
    rw [chunkAt_eq hm]
    exact hk
  | LazyLocalCall id =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    obtain ⟨hdrop, hlen, -⟩ := flat_lazyLocalCall cfg code.val j hm
    rw [← lazyLocalCallList_eq_chunk] at hdrop
    have hlen' : chunkLen cfg code.val j
        = (lazyLocalCallList cfg id (labelBase cfg code.val j)).length :=
      hlen.trans (lazyLocalCallList_length cfg id _).symm
    refine W.simple_run hj (not_helperCall_of hm (by simp)) hlen'
      (W.alive_succ hj hm hal (by simp) (by simp) (by simp))
      (macroOk_lazyLocalCall W.hL W.hflen hal hrule (fun k hk => laid_of_drop hdrop k hk) ?_ ?_)
    · refine W.posLocal hj (k := 40) ?_
      rw [chunkAt_eq hm]
      rfl
    · refine W.posLocal hj (k := 44) ?_
      rw [chunkAt_eq hm]
      rfl
  | HelperCall hidx =>
    obtain ⟨rfl, hal⟩ := preAt_live hm (by simp) (by simp) hpre
    exact W.helperCall_run hj hm hal hrule


/-! ## The machine invariant

A state reachable from an entry state sits inside some macro's region, having
entered that macro at its first position in a state the macro admits. The
macro's `Run` carries the rest: every step inside the region is safe, a return
from it keeps the contract, and leaving it lands on the next macro in a state
that macro admits in turn. -/

/-- Where an execution is. -/
def Walk.Reach (W : Walk P cfg code) (s : State) : Prop :=
  ∃ (j : Nat) (α : x64_check.State) (sb : State),
    j < code.val.length ∧ PreAt code.val W.a j α ∧
      sb.pc = chunkStart cfg code.val j ∧ Agree P α sb ∧
      Stays P (flat cfg code.val) (regionOf cfg code.val j) sb s

/-- An entry state is at the first macro, in the state the checker started
its walk from. -/
theorem Walk.reach_entry (W : Walk P cfg code) {s : State} (h : Entry P s) : W.Reach s := by
  refine ⟨0, W.a[0]!, s, W.len_pos, Or.inl ⟨rfl, W.alive_zero⟩, ?_,
    agree_of_entry h W.hentry, Stays.refl ?_⟩
  · rw [h.atStart, chunkStart_zero]
  · have hr : regionOf cfg code.val 0 (chunkStart cfg code.val 0) := W.region_start W.len_pos
    rw [chunkStart_zero] at hr
    rw [h.atStart]
    exact hr

/-- And one step on it is still somewhere: inside the same region, or at the
start of the macro the way out named. -/
theorem Walk.reach_step (W : Walk P cfg code) {s s' : State} (h : W.Reach s)
    (hstep : Step P (flat cfg code.val) s (.next s')) : W.Reach s' := by
  obtain ⟨j, α, sb, hj, hpre, hsb, hag, hsty⟩ := h
  obtain ⟨nx, hrun, hland⟩ := W.macro_run hj hpre
  by_cases hin : regionOf cfg code.val j s'.pc
  · exact ⟨j, α, sb, hj, hpre, hsb, hag, .step hsty hstep hin⟩
  · obtain ⟨e, he, hpc, hage⟩ := hrun.leave sb hsb hag s hsty s' hstep hin
    obtain ⟨k, hk, hek, hprek⟩ := hland e he
    exact ⟨k, e.2, s', hk, hprek, by rw [hpc, hek], hage,
      Stays.refl (by rw [hpc, hek]; exact W.region_start hk)⟩

theorem Walk.reach_of (W : Walk P cfg code) {s s' : State} (hE : Entry P s)
    (hr : Reachable P (flat cfg code.val) s s') : W.Reach s' := by
  induction hr with
  | refl => exact W.reach_entry hE
  | step _ hst ih => exact W.reach_step ih hst

/-- So the expansion of a list the checker accepted keeps the contract. -/
theorem Walk.contract (W : Walk P cfg code) : Contract P (flat cfg code.val) := by
  constructor
  · intro s hE s' hr c hstep i hi bn hbn
    obtain ⟨j, α, sb, hj, hpre, hsb, hag, hsty⟩ := W.reach_of hE hr
    obtain ⟨nx, hrun, -⟩ := W.macro_run hj hpre
    exact hrun.safe sb hsb hag s' hsty c hstep i hi bn hbn
  · intro s hE s' hr s'' hstep
    obtain ⟨j, α, sb, hj, hpre, hsb, hag, hsty⟩ := W.reach_of hE hr
    obtain ⟨nx, hrun, -⟩ := W.macro_run hj hpre
    exact hrun.returns sb hsb hag s' hsty s'' hstep


/-! ## The theorem

A macro list the checker accepts expands to a primitive list that keeps the
entry contract of `AsyncEbpf/X64/Contract.lean`. -/

/-- **Memory safety of the x86-64 backend.** If `x64_check.check` accepts a
macro list, its expansion is safe and returns under the contract, from every
state satisfying `Entry`.

The hypotheses beyond the checker's verdict are the ones the checker does not
look at: the layout the entry trampoline and the mappings promise (`hL`), the
cage being on (`hcage`), the one number the machine and the configuration have
to agree on (`hcfg`), the dispatcher the configuration names being the one the
machine's parameters name (`hdisp`) and not being an address inside this
function (`hdispCode`), the expansion fitting in the address space (`hlen`)
and its local labels in a `u32` (`hlabels`), and the trailer (`htrailer`). -/
theorem check_safe {P : Params} {cfg : x64_ir.Cfg} {code : Slice x64_ir.MInsn}
    (hcheck : x64_check.check cfg code = ok (.Ok ()))
    (hL : Layout P) (hcage : cfg.pointer_mask ≠ 0#i32) (hcfg : CfgOk P cfg)
    (hdisp : P.dispatcher = BitVec.ofNat 64 cfg.dispatcher.val)
    (hdispCode : ∀ j, j < (flat cfg code.val).length → P.dispatcher ≠ codeAddr P j)
    (hlen : (flat cfg code.val).length < 2 ^ 64)
    (hlabels : labelBase cfg code.val code.val.length < 2 ^ 32)
    (htrailer : HasTrailer code.val) :
    Contract P (flat cfg code.val) := by
  obtain ⟨labels, hscan, a, pcs, -, -, hentry, -, -, hsteps, hdead⟩ := check_chain hcheck
  exact Walk.contract ⟨labels, a, pcs, hscan, hentry, hsteps, hdead, htrailer, hL, hcage,
    hcfg, hdisp, hdispCode, hlen, hlabels⟩

/-- The same, of what `x64_expand.expand` appends to an empty vector. -/
theorem expand_safe {P : Params} {cfg : x64_ir.Cfg} {code : Slice x64_ir.MInsn}
    {out0 out : alloc.vec.Vec x64_ir.PInsn}
    (hcheck : x64_check.check cfg code = ok (.Ok ()))
    (hexp : x64_expand.expand cfg code out0 = ok out) (h0 : out0.val = [])
    (hL : Layout P) (hcage : cfg.pointer_mask ≠ 0#i32) (hcfg : CfgOk P cfg)
    (hdisp : P.dispatcher = BitVec.ofNat 64 cfg.dispatcher.val)
    (hdispCode : ∀ j, j < out.val.length → P.dispatcher ≠ codeAddr P j)
    (hlen : out.val.length < 2 ^ 64)
    (hlabels : labelBase cfg code.val code.val.length < 2 ^ 32)
    (htrailer : HasTrailer code.val) :
    Contract P out.val := by
  have he : out.val = flat cfg code.val := by
    rw [expand_spec hexp, h0, List.nil_append]
  rw [he] at hdispCode hlen ⊢
  exact check_safe hcheck hL hcage hcfg hdisp hdispCode hlen hlabels htrailer


/-! ## The gate

`x64_lower.lower` ends in `x64_lower.gate`, which is `x64_check.check` on the
macro list it built, so a lowering that reports success is a list the checker
accepted. The same unfolding reads off the trailer: `lower_trailer` is the
last thing `lower` pushes, and it pushes exactly the four macros. -/

/-- Reading an `ok` of a pair or a triple, through whatever `match` produced
it. `exact` unfolds the `match`; `simp` does not always. -/
private theorem ok_eq {α : Type} {x y : α} (h : (ok x : Result α) = ok y) : x = y := by
  simp only [ok.injEq] at h; exact h

private theorem ok_triple_eq {α β γ : Type} {a a' : α} {b b' : β} {c c' : γ}
    (h : (ok (a, b, c) : Result (α × β × γ)) = ok (a', b', c')) : a = a' ∧ b = b' ∧ c = c' := by
  simp only [ok.injEq, Prod.mk.injEq] at h
  exact ⟨h.1, h.2.1, h.2.2⟩

private theorem lower_branch {r : core.result.Result Unit x64_lower.Reject}
    {cf : core.ops.control_flow.ControlFlow
      (core.result.Result core.convert.Infallible x64_lower.Reject) Unit}
    (h : core.result.Result.Insts.CoreOpsTry.branch r = ok cf) :
    (r = .Ok () ∧ cf = .Continue ()) ∨ (∃ e, r = .Err e ∧ cf = .Break (.Err e)) := by
  cases r with
  | Ok u => cases u; simp_all [core.result.Result.Insts.CoreOpsTry.branch]
  | Err e => simp_all [core.result.Result.Insts.CoreOpsTry.branch]

private theorem lower_no_break {e : x64_lower.Reject} {β : Type} {v w : β}
    (h : (do
      let r1 ←
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
          Unit (core.convert.FromSame x64_lower.Reject) (core.result.Result.Err e)
      ok (r1, v)) = ok (core.result.Result.Ok (), w)) : False := by
  simp [core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual] at h

/-- A successful `push` appends exactly its macro. -/
private def PushesM (r : Result (core.result.Result Unit x64_lower.Reject ×
    x64_lower.Lowering × alloc.vec.Vec x64_ir.MInsn))
    (out : alloc.vec.Vec x64_ir.MInsn) (m : x64_ir.MInsn) : Prop :=
  ∀ res st' out', r = ok (res, st', out') → res = .Ok () → out'.val = out.val ++ [m]

private theorem PushesM.err {e : x64_lower.Reject} {s : x64_lower.Lowering}
    {o out : alloc.vec.Vec x64_ir.MInsn} {m : x64_ir.MInsn} :
    PushesM (ok (.Err e, s, o)) out m := by
  intro res st' out' h hres
  simp only [ok.injEq, Prod.mk.injEq] at h
  rw [← h.1] at hres
  simp at hres

private theorem PushesM.push {out : alloc.vec.Vec x64_ir.MInsn} {m : x64_ir.MInsn}
    {s : x64_lower.Lowering} :
    PushesM (alloc.vec.Vec.push out m >>= fun o => ok (.Ok (), s, o)) out m := by
  intro res st' out' h _
  obtain ⟨o, ho, h2⟩ := bind_eq_ok h
  simp only [ok.injEq, Prod.mk.injEq] at h2
  rw [← h2.2.2]
  exact vec_push_eq_ok ho

private theorem PushesM.bindOf {α : Type} {r : Result α}
    {body : α → Result (core.result.Result Unit x64_lower.Reject ×
      x64_lower.Lowering × alloc.vec.Vec x64_ir.MInsn)}
    {out : alloc.vec.Vec x64_ir.MInsn} {m : x64_ir.MInsn}
    (h : ∀ c, PushesM (body c) out m) : PushesM (r >>= body) out m := by
  intro res st' out' hr hres
  obtain ⟨c, -, h2⟩ := bind_eq_ok hr
  exact h c res st' out' h2 hres

theorem push_append {st st' : x64_lower.Lowering} {out out' : alloc.vec.Vec x64_ir.MInsn}
    {m : x64_ir.MInsn} (h : x64_lower.push st out m = ok (.Ok (), st', out')) :
    out'.val = out.val ++ [m] := by
  have key : PushesM (x64_lower.push st out m) out m := by
    unfold x64_lower.push
    repeat' first
      | exact PushesM.err
      | exact PushesM.push
      | refine PushesM.bindOf (fun _ => ?_)
      | split
  exact key _ _ _ h rfl

theorem push_trailer_append {st st' : x64_lower.Lowering}
    {out out' : alloc.vec.Vec x64_ir.MInsn}
    (h : x64_lower.push_trailer st out = ok (.Ok (), st', out')) :
    out'.val = out.val ++ [.Epilogue, .Retpoline, .DispatcherSlot, .HelperTable] := by
  unfold x64_lower.push_trailer at h
  obtain ⟨⟨r0, st1, out1⟩, hp0, h2⟩ := bind_eq_ok h
  obtain ⟨cf0, hcf0, h3⟩ := bind_eq_ok h2
  rcases lower_branch hcf0 with ⟨rfl, rfl⟩ | ⟨e, rfl, rfl⟩
  case inr => exact (lower_no_break h3).elim
  obtain ⟨⟨r1, st2, out2⟩, hp1, h4⟩ := bind_eq_ok h3
  obtain ⟨cf1, hcf1, h5⟩ := bind_eq_ok h4
  rcases lower_branch hcf1 with ⟨rfl, rfl⟩ | ⟨e, rfl, rfl⟩
  case inr => exact (lower_no_break h5).elim
  obtain ⟨⟨r2, st3, out3⟩, hp2, h6⟩ := bind_eq_ok h5
  obtain ⟨cf2, hcf2, h7⟩ := bind_eq_ok h6
  rcases lower_branch hcf2 with ⟨rfl, rfl⟩ | ⟨e, rfl, rfl⟩
  case inr => exact (lower_no_break h7).elim
  rw [push_append h7, push_append hp2, push_append hp1, push_append hp0]
  simp

theorem lower_trailer_append {st st' : x64_lower.Lowering}
    {out out' : alloc.vec.Vec x64_ir.MInsn}
    (h : x64_lower.lower_trailer st out = ok (.Ok (), st', out')) :
    out'.val = out.val ++ [.Epilogue, .Retpoline, .DispatcherSlot, .HelperTable] := by
  unfold x64_lower.lower_trailer at h
  obtain ⟨⟨oc, st1, out1⟩, h1, h2⟩ := bind_eq_ok h
  cases oc with
  | Ok u =>
    obtain ⟨-, -, rfl⟩ := ok_triple_eq h2
    cases u
    exact push_trailer_append h1
  | Err e => exact absurd (ok_triple_eq h2).1 (by simp)

/-- `gate` is the checker. -/
theorem gate_check {cfg : x64_ir.Cfg} {out : alloc.vec.Vec x64_ir.MInsn}
    (h : x64_lower.gate cfg out = ok (.Ok ())) :
    x64_check.check cfg (alloc.vec.Vec.deref out) = ok (.Ok ()) := by
  unfold x64_lower.gate at h
  obtain ⟨r, hr, h1⟩ := bind_eq_ok h
  cases r with
  | Ok u => cases u; exact hr
  | Err e => exact absurd (ok_eq h1) (by simp)

/-- What a successful lowering leaves behind: a list the checker accepted,
ending in the trailer. -/
theorem lower_gate_trailer {cfg : x64_ir.Cfg} {insns : Slice isa.Insn}
    {entries external_calls : Slice Bool} {stack_usage : Slice Std.U16}
    {hints : Slice Std.U8} {plan : Slice x64_ir.PlanEntry} {resolver_ids : Slice Std.U32}
    {start_pc end_pc : Std.Usize} {out0 out : alloc.vec.Vec x64_ir.MInsn}
    (h : x64_lower.lower cfg insns entries external_calls stack_usage hints plan resolver_ids
      start_pc end_pc out0 = ok (.Ok (), out)) :
    x64_check.check cfg (alloc.vec.Vec.deref out) = ok (.Ok ()) ∧ HasTrailer out.val := by
  unfold x64_lower.lower at h
  obtain ⟨r0, -, h1⟩ := bind_eq_ok h
  obtain ⟨cf0, hcf0, h2⟩ := bind_eq_ok h1
  rcases lower_branch hcf0 with ⟨rfl, rfl⟩ | ⟨e0, rfl, rfl⟩
  case inr => exact (lower_no_break h2).elim
  obtain ⟨i1, -, h3⟩ := bind_eq_ok h2
  obtain ⟨barrier, -, h4⟩ := bind_eq_ok h3
  obtain ⟨barrier1, -, h5⟩ := bind_eq_ok h4
  obtain ⟨⟨r1, st1, out1⟩, -, h6⟩ := bind_eq_ok h5
  obtain ⟨cf1, hcf1, h7⟩ := bind_eq_ok h6
  rcases lower_branch hcf1 with ⟨rfl, rfl⟩ | ⟨e1, rfl, rfl⟩
  case inr => exact (lower_no_break h7).elim
  obtain ⟨⟨r2, st2, out2⟩, ht, h8⟩ := bind_eq_ok h7
  obtain ⟨cf2, hcf2, h9⟩ := bind_eq_ok h8
  rcases lower_branch hcf2 with ⟨rfl, rfl⟩ | ⟨e2, rfl, rfl⟩
  case inr => exact (lower_no_break h9).elim
  obtain ⟨r3, hr3, h10⟩ := bind_eq_ok h9
  simp only [ok.injEq, Prod.mk.injEq] at h10
  obtain ⟨rfl, rfl⟩ := h10
  exact ⟨gate_check hr3, out1.val, lower_trailer_append ht⟩

/-- A lowering that reports success hands the checker's verdict on. -/
theorem lower_gate {cfg : x64_ir.Cfg} {insns : Slice isa.Insn}
    {entries external_calls : Slice Bool} {stack_usage : Slice Std.U16}
    {hints : Slice Std.U8} {plan : Slice x64_ir.PlanEntry} {resolver_ids : Slice Std.U32}
    {start_pc end_pc : Std.Usize} {out0 out : alloc.vec.Vec x64_ir.MInsn}
    (h : x64_lower.lower cfg insns entries external_calls stack_usage hints plan resolver_ids
      start_pc end_pc out0 = ok (.Ok (), out)) :
    x64_check.check cfg (alloc.vec.Vec.deref out) = ok (.Ok ()) :=
  (lower_gate_trailer h).1

@[simp] theorem deref_val (out : alloc.vec.Vec x64_ir.MInsn) :
    (alloc.vec.Vec.deref out).val = out.val := by
  simp [alloc.vec.Vec.deref]

/-- **The backend, end to end.** Lower, expand, and the primitive list keeps
the entry contract. The trailer is no longer a hypothesis: `lower` emits it. -/
theorem lower_safe {P : Params} {cfg : x64_ir.Cfg} {insns : Slice isa.Insn}
    {entries external_calls : Slice Bool} {stack_usage : Slice Std.U16}
    {hints : Slice Std.U8} {plan : Slice x64_ir.PlanEntry} {resolver_ids : Slice Std.U32}
    {start_pc end_pc : Std.Usize} {out0 out : alloc.vec.Vec x64_ir.MInsn}
    {pout0 pir : alloc.vec.Vec x64_ir.PInsn}
    (hlower : x64_lower.lower cfg insns entries external_calls stack_usage hints plan
      resolver_ids start_pc end_pc out0 = ok (.Ok (), out))
    (hexp : x64_expand.expand cfg (alloc.vec.Vec.deref out) pout0 = ok pir)
    (h0 : pout0.val = [])
    (hL : Layout P) (hcage : cfg.pointer_mask ≠ 0#i32) (hcfg : CfgOk P cfg)
    (hdisp : P.dispatcher = BitVec.ofNat 64 cfg.dispatcher.val)
    (hdispCode : ∀ j, j < pir.val.length → P.dispatcher ≠ codeAddr P j)
    (hlen : pir.val.length < 2 ^ 64)
    (hlabels : labelBase cfg out.val out.val.length < 2 ^ 32) :
    Contract P pir.val := by
  obtain ⟨hcheck, htr⟩ := lower_gate_trailer hlower
  exact expand_safe hcheck hexp h0 hL hcage hcfg hdisp hdispCode hlen
    (by simpa using hlabels) (by simpa using htr)

end X64

end async_ebpf_verified

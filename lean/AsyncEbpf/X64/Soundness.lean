import AsyncEbpf.X64.Expand
import AsyncEbpf.X64.CheckedAddr
import AsyncEbpf.X64.Arith
import AsyncEbpf.X64.Calls

/-!
# The x86_64 backend is memory-safe

WIP.
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
    ∃ t, pos (flat cfg code.val) (.Pc slot) = some t ∧
      Landing cfg code.val W.a (t, enterState) := by
  obtain ⟨i, hi, hmi⟩ := (scan_is_labelled W.hscan slot).mp hlab
  obtain ⟨k, hk, hmin⟩ := exists_least (q := fun j => code.val[j]? = some (x64_ir.MInsn.PcLabel slot))
    ⟨i, hmi⟩
  have hklt : k < code.val.length := List.getElem?_eq_some_iff.mp hk |>.1
  refine ⟨chunkStart cfg code.val k, pos_pc cfg code.val k slot hmin hk, ?_⟩
  refine ⟨k, hklt, rfl, Or.inr ⟨rfl, Or.inl ⟨slot, hk, ?_⟩⟩⟩
  obtain ⟨idx, pcv, -, hst⟩ := W.dispatch hklt hk
  rcases label_step_spec hst with ⟨hnt, -⟩ | ⟨-, -, hE⟩
  · rw [htgt] at hnt; simp at hnt
  · exact enterShaped_eq hE

/-- A branch to `Exit` lands on the trailer's epilogue. -/
theorem Walk.landing_exit (W : Walk P cfg code) (htr : W.labels.trailer = true) :
    ∃ t, pos (flat cfg code.val) .Exit = some t ∧
      Landing cfg code.val W.a (t, enterState) := by
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
  refine ⟨chunkStart cfg code.val (n - 4), pos_exit cfg code.val (n - 4) hE (by
    rw [show n - 4 + 1 = n - 3 by omega]; exact hR) hbefore, ?_⟩
  exact ⟨n - 4, by omega, rfl, Or.inr ⟨rfl, Or.inr ⟨hE, htrAt⟩⟩⟩



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


end X64

end async_ebpf_verified

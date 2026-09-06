import AsyncEbpf.Semantics.Soundness
import AsyncEbpf.Layout.Proofs
import AsyncEbpf.Layout.Decoder

/-!
# Control never leaves a function except through a call or a return

The JIT translates one local function at a time, so it needs control to
stay inside the function it entered until a `call` or `exit`. `partition`
in `src/verified/layout.rs` is the check that promises this;
`layout_sound` is the promise, as a statement about execution:

along every execution of a program that both `validate` and `partition`
accept,

* the program counter is always on a slot the walk visited (so inside the
  function the walk assigned it to), and so is every return address on the
  call stack;
* every step either stays in the current function (`pc_to_func` agrees on
  the old and new pc), is a local call landing on a function start whose
  return address is in the caller's function, or is a return to the
  address the matching call pushed (`step_classification`).

`Reach`, `funcOf` and `starts` are the readings of `Layout` from
`Layout/Spec.lean`: `Reach L pc` is `reachable[pc]`, `funcOf L pc` is
`pc_to_func[pc]`.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

open Sem isa

/-- Execution stays on walked slots, and so do return addresses. -/
structure FnInv (insns : List Insn) (L : layout.Layout) (s : State) : Prop where
  pc : s.pc < insns.length → Reach L s.pc
  frames : ∀ f ∈ s.stack, f.ret < insns.length → Reach L f.ret

theorem FnInv.initial {insns : List Insn} {L : layout.Layout} (hL : LayoutOk insns L)
    (ctx top : Word) : FnInv insns L (initial ctx top) :=
  ⟨fun _ => hL.start_reach 0 0 hL.starts_zero, fun f hf => by simp [Sem.initial] at hf⟩

/-- An edge of the decoded instruction at `pc` names a byte-level successor. -/
theorem succB_of_edge {insns : List Insn} {pc : Nat} (hpc : pc < insns.length) {op : Op}
    (hdec : isa.decode insns[pc].opcode = ok (some op)) {e : Edge} (he : e ∈ opEdges op) :
    edgeTarget insns[pc] pc e ∈ succB insns pc := by
  simp only [succB, List.getElem?_eq_getElem hpc]
  exact List.mem_map.mpr ⟨e, opEdges_sub _ hdec e he, rfl⟩

/-- A local call on a walked slot lands on a walked function start. -/
theorem call_target_reach {insns : List Insn} {L : layout.Layout} (hL : LayoutOk insns L)
    {pc : Nat} (hpc : pc < insns.length) (hr : Reach L pc)
    (hdec : isa.decode insns[pc].opcode = ok (some .Call)) (hsrc : insns[pc].src.val = 1)
    (hnn : 0 ≤ callTargetInt insns[pc] pc) :
    callTarget insns[pc] pc ∈ starts L ∧ Reach L (callTarget insns[pc] pc) := by
  have hcall : CallsTo insns pc (callTarget insns[pc] pc) := by
    refine ⟨hpc, ⟨decode_call_opcode _ hdec, hsrc⟩, ?_⟩
    rw [callTarget_eq]
    omega
  have hmem := hL.call_start pc _ hr hcall
  refine ⟨hmem, ?_⟩
  obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp hmem
  exact hL.start_reach i _ hi

theorem preservation_fn {insns : List Insn} {L : layout.Layout} {top : Word} {P : Params}
    {s s' : State} (hwf : WellFormed insns) (hL : LayoutOk insns L)
    (hinv₀ : Inv insns top P s) (hinv : FnInv insns L s)
    (hstep : Step P insns s (.next s')) : FnInv insns L s' := by
  cases hstep with
  | alu insn width op source hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact ⟨fun _ => (hL.succ_same_func (hinv.pc hpc)
      (succB_of_edge hpc hdec (e := .fall) (by simp [opEdges]))).1, hinv.frames⟩
  | endian insn kind hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact ⟨fun _ => (hL.succ_same_func (hinv.pc hpc)
      (succB_of_edge hpc hdec (e := .fall) (by simp [opEdges]))).1, hinv.frames⟩
  | loadImm64 insn hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact ⟨fun _ => (hL.succ_same_func (hinv.pc hpc)
      (succB_of_edge hpc hdec (e := .skip) (by simp [opEdges]))).1, hinv.frames⟩
  | load insn width signed v hd _ =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact ⟨fun _ => (hL.succ_same_func (hinv.pc hpc)
      (succB_of_edge hpc hdec (e := .fall) (by simp [opEdges]))).1, hinv.frames⟩
  | storeImm insn width hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact ⟨fun _ => (hL.succ_same_func (hinv.pc hpc)
      (succB_of_edge hpc hdec (e := .fall) (by simp [opEdges]))).1, hinv.frames⟩
  | storeReg insn width hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact ⟨fun _ => (hL.succ_same_func (hinv.pc hpc)
      (succB_of_edge hpc hdec (e := .fall) (by simp [opEdges]))).1, hinv.frames⟩
  | atomic insn width op fetch v hd _ =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact ⟨fun _ => (hL.succ_same_func (hinv.pc hpc)
      (succB_of_edge hpc hdec (e := .fall) (by simp [opEdges]))).1, hinv.frames⟩
  | ja insn width hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact ⟨fun _ => (hL.succ_same_func (hinv.pc hpc)
      (succB_of_edge hpc hdec (e := .jump) (by simp [opEdges]))).1, hinv.frames⟩
  | jmp insn width op source hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    refine ⟨fun _ => ?_, hinv.frames⟩
    simp only [jmpNext]
    split
    · exact (hL.succ_same_func (hinv.pc hpc)
        (succB_of_edge hpc hdec (e := .jump) (by simp [opEdges]))).1
    · exact (hL.succ_same_func (hinv.pc hpc)
        (succB_of_edge hpc hdec (e := .fall) (by simp [opEdges]))).1
  | callExternal insn regs' hd _ _ =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact ⟨fun _ => (hL.succ_same_func (hinv.pc hpc)
      (succB_of_edge hpc hdec (e := .fall) (by simp [opEdges]))).1, hinv.frames⟩
  | callLocal insn hd hsrc _ =>
    obtain ⟨hpc, rfl, facts⟩ := facts_at hwf hinv₀ hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    have hst := facts.structure_ok
    simp only [StructureOk] at hst
    obtain ⟨_, hcall⟩ := hst
    obtain ⟨hnn, _⟩ := hcall hsrc
    refine ⟨fun _ => (call_target_reach hL hpc (hinv.pc hpc) hdec hsrc hnn).2, ?_⟩
    intro f hf
    simp only [List.mem_cons] at hf
    rcases hf with rfl | hf
    · exact fun _ => (hL.succ_same_func (hinv.pc hpc)
        (succB_of_edge hpc hdec (e := .fall) (by simp [opEdges]))).1
    · exact hinv.frames f hf
  | exitReturn insn f rest hd hstack =>
    refine ⟨fun h => hinv.frames f (by rw [hstack]; exact List.mem_cons_self) h, ?_⟩
    intro g hg
    exact hinv.frames g (by rw [hstack]; exact List.mem_cons_of_mem _ hg)

/-! ## The theorems -/

/-- Along every execution of a program `validate` and `partition` accept,
the program counter and every return address are on walked slots. -/
theorem layout_sound (config : validate.Config) (kh : Slice U32) (insns : Slice Insn)
    (ext : Slice Bool) (entries : Slice Usize) (L : layout.Layout)
    (hlen : insns.length < 2 ^ 63) (hne : 0 < insns.length)
    (hv : validate.validate config kh insns ext = ok (.Ok ()))
    (hp : layout.partition insns entries = ok (.Ok L))
    (P : Params) (ctx top : Word) :
    ∀ s, Reachable P insns.val (initial ctx top) s → FnInv insns.val L s := by
  have hwf := validate_ok_wellFormed config kh insns ext hlen hv
  have hL := partition_ok hlen hne hp
  intro s hr
  induction hr with
  | refl => exact FnInv.initial hL ctx top
  | step hr' hstep ih =>
    have hinv₀ := (validate_sound config kh insns ext hlen hv P ctx top _ hr').1
    exact preservation_fn hwf hL hinv₀ ih hstep

/-- Spelled out: the program counter never leaves the slots the walk
assigned to functions. -/
theorem layout_sound_pc (config : validate.Config) (kh : Slice U32) (insns : Slice Insn)
    (ext : Slice Bool) (entries : Slice Usize) (L : layout.Layout)
    (hlen : insns.length < 2 ^ 63) (hne : 0 < insns.length)
    (hv : validate.validate config kh insns ext = ok (.Ok ()))
    (hp : layout.partition insns entries = ok (.Ok L))
    (P : Params) (ctx top : Word) (s : State) (hr : Reachable P insns.val (initial ctx top) s)
    (hpc : s.pc < insns.length) : Reach L s.pc :=
  (layout_sound config kh insns ext entries L hlen hne hv hp P ctx top s hr).pc hpc

/-- Every step of an accepted program stays in its function, is a local
call to a function start that will return into the caller's function, or
is a return to the address the matching call pushed. -/
theorem step_classification (config : validate.Config) (kh : Slice U32) (insns : Slice Insn)
    (ext : Slice Bool) (entries : Slice Usize) (L : layout.Layout)
    (hlen : insns.length < 2 ^ 63) (hne : 0 < insns.length)
    (hv : validate.validate config kh insns ext = ok (.Ok ()))
    (hp : layout.partition insns entries = ok (.Ok L))
    (P : Params) (ctx top : Word) (s s' : State) (hr : Reachable P insns.val (initial ctx top) s)
    (hstep : Step P insns.val s (.next s')) :
    funcOf L s'.pc = funcOf L s.pc ∨
    (∃ insn, decodeAt insns.val s.pc = some (insn, .Call) ∧ insn.src.val = 1 ∧
      s'.pc ∈ starts L ∧ funcOf L (s.pc + 1) = funcOf L s.pc) ∨
    (∃ insn f rest, decodeAt insns.val s.pc = some (insn, .Exit) ∧ s.stack = f :: rest ∧
      s'.pc = f.ret) := by
  have hwf := validate_ok_wellFormed config kh insns ext hlen hv
  have hL := partition_ok hlen hne hp
  have hinv₀ := (validate_sound config kh insns ext hlen hv P ctx top s hr).1
  have hinv := layout_sound config kh insns ext entries L hlen hne hv hp P ctx top s hr
  -- Steps that follow a byte-level edge stay in the function.
  have same : ∀ {pc : Nat} (hpc : pc < insns.val.length) {op : Op},
      isa.decode insns.val[pc].opcode = ok (some op) → Reach L pc →
      ∀ {e : Edge}, e ∈ opEdges op → funcOf L (edgeTarget insns.val[pc] pc e) = funcOf L pc :=
    fun {_} hpc {_} hdec hr {_} he => (hL.succ_same_func hr (succB_of_edge hpc hdec he)).2
  cases hstep with
  | alu insn width op source hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact Or.inl (same hpc hdec (hinv.pc hpc) (e := .fall) (by simp [opEdges]))
  | endian insn kind hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact Or.inl (same hpc hdec (hinv.pc hpc) (e := .fall) (by simp [opEdges]))
  | loadImm64 insn hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact Or.inl (same hpc hdec (hinv.pc hpc) (e := .skip) (by simp [opEdges]))
  | load insn width signed v hd _ =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact Or.inl (same hpc hdec (hinv.pc hpc) (e := .fall) (by simp [opEdges]))
  | storeImm insn width hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact Or.inl (same hpc hdec (hinv.pc hpc) (e := .fall) (by simp [opEdges]))
  | storeReg insn width hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact Or.inl (same hpc hdec (hinv.pc hpc) (e := .fall) (by simp [opEdges]))
  | atomic insn width op fetch v hd _ =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact Or.inl (same hpc hdec (hinv.pc hpc) (e := .fall) (by simp [opEdges]))
  | ja insn width hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact Or.inl (same hpc hdec (hinv.pc hpc) (e := .jump) (by simp [opEdges]))
  | jmp insn width op source hd =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    left
    simp only [jmpNext]
    split
    · exact same hpc hdec (hinv.pc hpc) (e := .jump) (by simp [opEdges])
    · exact same hpc hdec (hinv.pc hpc) (e := .fall) (by simp [opEdges])
  | callExternal insn regs' hd _ _ =>
    obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
    exact Or.inl (same hpc hdec (hinv.pc hpc) (e := .fall) (by simp [opEdges]))
  | callLocal insn hd hsrc _ =>
    obtain ⟨hpc, rfl, facts⟩ := facts_at hwf hinv₀ hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    have hst := facts.structure_ok
    simp only [StructureOk] at hst
    obtain ⟨_, hcall⟩ := hst
    obtain ⟨hnn, _⟩ := hcall hsrc
    refine Or.inr (Or.inl ⟨_, hd, hsrc, (call_target_reach hL hpc (hinv.pc hpc) hdec hsrc hnn).1, ?_⟩)
    exact same hpc hdec (hinv.pc hpc) (e := .fall) (by simp [opEdges])
  | exitReturn insn f rest hd hstack =>
    exact Or.inr (Or.inr ⟨insn, f, rest, hd, hstack, rfl⟩)

end async_ebpf_verified

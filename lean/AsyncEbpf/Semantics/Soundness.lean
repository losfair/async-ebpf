import AsyncEbpf.Validate.Proofs
import AsyncEbpf.Semantics.Machine

/-!
# Validator soundness

`validate_sound`: a program the validator accepts never goes wrong under the
operational semantics. Precisely, along every execution from the entry
state:

* the program counter is on an instruction slot the validator walked, or
  exactly at the end of the instruction stream;
* the machine is never stuck: it can always take a step, halt at `exit`, or
  run off the end. In particular it never reaches an undefined instruction,
  never jumps or calls into the high half of an `lddw`, and never jumps or
  calls out of the program;
* every return address on the call stack is such a slot;
* the frame pointer `R10` is the frame base for the current call depth, so
  the only instructions that ever move it are local calls and returns.

The last point is what the JIT's unchecked frame-relative accesses rest on:
an access at `[R10 + k]` with `-F ≤ k < 0` is inside the current frame in
every execution of an accepted program.

The proof is the usual progress-and-preservation argument over an invariant
`Inv`, with `WellFormed` (what the validator proves per slot) supplying the
facts each step needs.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

open Sem isa

/-! ## Slots -/

theorem Walk.trans {insns : List Insn} {i j k : Nat}
    (h₁ : Walk insns i j) (h₂ : Walk insns j k) : Walk insns i k := by
  induction h₁ with
  | refl => exact h₂
  | next hi hs _ ih => exact Walk.next hi hs (ih h₂)
  | lddw hi hl _ ih => exact Walk.lddw hi hl (ih h₂)

theorem is_load_imm64_true {op : Op} (h : validate.is_load_imm64 op = ok true) :
    op = .LoadImm64 := by
  cases op <;> simp [validate.is_load_imm64] at h ⊢

theorem is_load_imm64_of_ne {op : Op} (h : op ≠ .LoadImm64) :
    validate.is_load_imm64 op = ok false := by
  cases op <;> simp [validate.is_load_imm64] at h ⊢

theorem decode_det {x : U8} {op op' : Op} (h : isa.decode x = ok (some op))
    (h' : isa.decode x = ok (some op')) : op = op' := by
  rw [h] at h'
  simp only [ok.injEq, Option.some.injEq] at h'
  exact h'

/-- Every slot of a well-formed program is an instruction slot or the high
half of an `lddw` on one. -/
theorem slots_cover {insns : List Insn} (hwf : WellFormed insns) :
    ∀ (t : Nat), t < insns.length →
      InsnSlot insns t ∨
      ∃ (j : Nat) (hj : j < insns.length), InsnSlot insns j ∧ IsLddw insns[j].opcode ∧ t = j + 1 := by
  intro t
  induction t with
  | zero => intro _; exact Or.inl (Walk.refl 0)
  | succ t ih =>
    intro ht
    have ht' : t < insns.length := by omega
    rcases ih ht' with hs | ⟨j, hj, hsj, hl, rfl⟩
    · obtain ⟨op, hdec, _⟩ := hwf t ht' hs
      by_cases hop : op = .LoadImm64
      · subst hop
        exact Or.inr ⟨t, ht', hs, ⟨_, hdec, rfl⟩, rfl⟩
      · have hsingle : IsSingle insns[t].opcode := ⟨op, hdec, is_load_imm64_of_ne hop⟩
        exact Or.inl (Walk.trans hs (Walk.next ht' hsingle (Walk.refl _)))
    · exact Or.inl (Walk.trans hsj (Walk.lddw hj hl (Walk.refl _)))

/-- A real slot (one whose opcode byte is not zero) is an instruction slot. -/
theorem realSlot_isSlot {insns : List Insn} (hwf : WellFormed insns) {t : Int}
    (h : RealSlot insns t) : InsnSlot insns t.toNat := by
  obtain ⟨_, ht, hnz⟩ := h
  rcases slots_cover hwf t.toNat ht with hs | ⟨j, hj, hsj, ⟨op', hdec', hl'⟩, heq⟩
  · exact hs
  · exfalso
    obtain ⟨op, hdec, facts⟩ := hwf j hj hsj
    have := decode_det hdec hdec'
    subst this
    have := is_load_imm64_true hl'
    subst this
    have hst := facts.structure_ok
    simp only [StructureOk] at hst
    obtain ⟨_, hz⟩ := hst
    simp only [heq] at hnz
    exact hnz hz

/-! ## Reading the program, in the semantics and in the spec -/

theorem decodeAt_some {insns : List Insn} {pc : Nat} {insn : Insn} {op : Op}
    (h : decodeAt insns pc = some (insn, op)) :
    ∃ hpc : pc < insns.length, insn = insns[pc] ∧ isa.decode insn.opcode = ok (some op) := by
  unfold decodeAt at h
  split at h
  · simp at h
  · rename_i insn' hget
    split at h
    · rename_i op' hdec
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      rw [List.getElem?_eq_some_iff] at hget
      obtain ⟨hpc, hx⟩ := hget
      exact ⟨hpc, hx.symm, hdec⟩
    · simp at h

theorem decodeAt_of {insns : List Insn} {pc : Nat} (hpc : pc < insns.length) {op : Op}
    (hdec : isa.decode insns[pc].opcode = ok (some op)) :
    decodeAt insns pc = some (insns[pc], op) := by
  unfold decodeAt
  rw [List.getElem?_eq_getElem hpc]
  simp only
  rw [hdec]

theorem jumpTarget_eq (insn : Insn) (pc : Nat) :
    jumpTarget insn pc = (jumpTargetInt insn pc).toNat := rfl

theorem callTarget_eq (insn : Insn) (pc : Nat) :
    callTarget insn pc = (callTargetInt insn pc).toNat := rfl

/-! ## Registers -/

theorem reg_ne_R10 {n : U8} (h : n.val ≤ 9) : reg n ≠ R10 := by
  intro heq
  have hv := congrArg Fin.val heq
  unfold reg at hv
  split at hv <;> simp only [R10] at hv <;> omega

theorem setReg_R10_of_ne {regs : Regs} {r : Fin 11} {v : Word} (h : r ≠ R10) :
    setReg regs r v R10 = regs R10 := by
  simp [setReg, Function.update_of_ne (Ne.symm h)]

theorem restoreRegs_R10 (regs : Regs) (f : Frame) : restoreRegs regs f R10 = f.fp := by
  simp [restoreRegs, R10]

theorem atomicRegs_R10 {regs : Regs} {insn : Insn} {op : AtomicOp} {fetch : Bool} {v : Word}
    (h : insn.src.val ≤ 9) : atomicRegs regs insn op fetch v R10 = regs R10 := by
  unfold atomicRegs
  split
  · exact setReg_R10_of_ne (by intro h; have := congrArg Fin.val h; simp [R10] at this)
  · split
    · exact setReg_R10_of_ne (reg_ne_R10 h)
    · rfl

theorem helperClobber_R10 {before after : Regs} (h : HelperClobber before after) :
    after R10 = before R10 :=
  h R10 (by simp [R10])

/-! ## The invariant -/

/-- The frame base at call depth `k`: the entry frame pointer, one stride
lower per active call. -/
def fpAt (top stride : Word) : Nat → Word
  | 0 => top
  | k + 1 => fpAt top stride k - stride

/-- Every frame on the stack was pushed at its depth and returns to a slot. -/
inductive FramesOk (insns : List Insn) (top stride : Word) : List Frame → Prop
  | nil : FramesOk insns top stride []
  | cons {f : Frame} {rest : List Frame} :
      f.fp = fpAt top stride rest.length →
      f.ret ≤ insns.length →
      (f.ret < insns.length → InsnSlot insns f.ret) →
      FramesOk insns top stride rest →
      FramesOk insns top stride (f :: rest)

structure Inv (insns : List Insn) (top : Word) (P : Params) (s : State) : Prop where
  pc_le : s.pc ≤ insns.length
  pc_slot : s.pc < insns.length → InsnSlot insns s.pc
  fp : s.regs R10 = fpAt top P.stride s.stack.length
  frames : FramesOk insns top P.stride s.stack

theorem Inv.initial (insns : List Insn) (P : Params) (ctx top : Word) :
    Inv insns top P (initial ctx top) := by
  refine ⟨Nat.zero_le _, fun _ => Walk.refl 0, ?_, FramesOk.nil⟩
  unfold Sem.initial
  simp [R10, fpAt]

/-! ## Preservation -/

/-- The facts about the instruction at the current slot, from `WellFormed`. -/
theorem facts_at {insns : List Insn} {top : Word} {P : Params} {s : State}
    (hwf : WellFormed insns) (hinv : Inv insns top P s) {insn : Insn} {op : Op}
    (hd : decodeAt insns s.pc = some (insn, op)) :
    ∃ hpc : s.pc < insns.length, insn = insns[s.pc] ∧ SlotFacts insns s.pc hpc op := by
  obtain ⟨hpc, rfl, hdec⟩ := decodeAt_some hd
  obtain ⟨op', hdec', facts⟩ := hwf s.pc hpc (hinv.pc_slot hpc)
  have := decode_det hdec' hdec
  subst this
  exact ⟨hpc, rfl, facts⟩

/-- The slot after a one-slot instruction is an instruction slot. -/
theorem slot_next {insns : List Insn} {pc : Nat} (hpc : pc < insns.length)
    (hs : InsnSlot insns pc) {op : Op} (hdec : isa.decode insns[pc].opcode = ok (some op))
    (hop : op ≠ .LoadImm64) : InsnSlot insns (pc + 1) :=
  Walk.trans hs (Walk.next hpc ⟨op, hdec, is_load_imm64_of_ne hop⟩ (Walk.refl _))

/-- The slot after an `lddw` is an instruction slot. -/
theorem slot_lddw {insns : List Insn} {pc : Nat} (hpc : pc < insns.length)
    (hs : InsnSlot insns pc) (hdec : isa.decode insns[pc].opcode = ok (some .LoadImm64)) :
    InsnSlot insns (pc + 2) :=
  Walk.trans hs (Walk.lddw hpc ⟨_, hdec, rfl⟩ (Walk.refl _))

/-- A destination the validator admits for a non-store instruction is below R10. -/
theorem dst_le_9 {insns : List Insn} {j : Nat} {hj : j < insns.length} {op : Op}
    (facts : SlotFacts insns j hj op) (hns : validate.is_store_form op = ok false) :
    insns[j].dst.val ≤ 9 := by
  rcases facts.dst_bound with h | ⟨_, h⟩
  · exact h
  · rw [hns] at h
    simp at h

theorem preservation {insns : List Insn} {top : Word} {P : Params} {s s' : State}
    (hwf : WellFormed insns) (hinv : Inv insns top P s)
    (hstep : Step P insns s (.next s')) : Inv insns top P s' := by
  cases hstep with
  | alu insn width op source hd =>
    obtain ⟨hpc, rfl, facts⟩ := facts_at hwf hinv hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    refine ⟨by dsimp only; omega, fun _ => slot_next hpc (hinv.pc_slot hpc) hdec (by simp), ?_, hinv.frames⟩
    simp only
    rw [setReg_R10_of_ne (reg_ne_R10 (dst_le_9 facts rfl))]
    exact hinv.fp
  | endian insn kind hd =>
    obtain ⟨hpc, rfl, facts⟩ := facts_at hwf hinv hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    refine ⟨by dsimp only; omega, fun _ => slot_next hpc (hinv.pc_slot hpc) hdec (by simp), ?_, hinv.frames⟩
    simp only
    rw [setReg_R10_of_ne (reg_ne_R10 (dst_le_9 facts rfl))]
    exact hinv.fp
  | loadImm64 insn hd =>
    obtain ⟨hpc, rfl, facts⟩ := facts_at hwf hinv hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    have hst := facts.structure_ok
    simp only [StructureOk] at hst
    obtain ⟨hlt, _⟩ := hst
    refine ⟨by dsimp only; omega, fun _ => slot_lddw hpc (hinv.pc_slot hpc) hdec, ?_, hinv.frames⟩
    simp only
    rw [setReg_R10_of_ne (reg_ne_R10 (dst_le_9 facts rfl))]
    exact hinv.fp
  | load insn width signed v hd _ =>
    obtain ⟨hpc, rfl, facts⟩ := facts_at hwf hinv hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    refine ⟨by dsimp only; omega, fun _ => slot_next hpc (hinv.pc_slot hpc) hdec (by simp), ?_, hinv.frames⟩
    simp only
    rw [setReg_R10_of_ne (reg_ne_R10 (dst_le_9 facts rfl))]
    exact hinv.fp
  | storeImm insn width hd =>
    obtain ⟨hpc, rfl, _⟩ := facts_at hwf hinv hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    exact ⟨by dsimp only; omega, fun _ => slot_next hpc (hinv.pc_slot hpc) hdec (by simp), hinv.fp, hinv.frames⟩
  | storeReg insn width hd =>
    obtain ⟨hpc, rfl, _⟩ := facts_at hwf hinv hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    exact ⟨by dsimp only; omega, fun _ => slot_next hpc (hinv.pc_slot hpc) hdec (by simp), hinv.fp, hinv.frames⟩
  | atomic insn width op fetch v hd _ =>
    obtain ⟨hpc, rfl, facts⟩ := facts_at hwf hinv hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    refine ⟨by dsimp only; omega, fun _ => slot_next hpc (hinv.pc_slot hpc) hdec (by simp), ?_, hinv.frames⟩
    simp only
    rw [atomicRegs_R10 (facts.atomic_src (by simp [IsAtomic]))]
    exact hinv.fp
  | ja insn width hd =>
    obtain ⟨hpc, rfl, facts⟩ := facts_at hwf hinv hd
    have hst := facts.structure_ok
    simp only [StructureOk] at hst
    obtain ⟨_, hreal⟩ := hst
    have hslot := realSlot_isSlot hwf hreal
    obtain ⟨_, hlt, _⟩ := hreal
    refine ⟨?_, fun _ => ?_, hinv.fp, hinv.frames⟩
    · simp only [jumpTarget_eq]; omega
    · simp only [jumpTarget_eq]; exact hslot
  | jmp insn width op source hd =>
    obtain ⟨hpc, rfl, facts⟩ := facts_at hwf hinv hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    have hst := facts.structure_ok
    simp only [StructureOk] at hst
    obtain ⟨_, hreal⟩ := hst
    have hslot := realSlot_isSlot hwf hreal
    obtain ⟨_, hlt, _⟩ := hreal
    refine ⟨?_, fun _ => ?_, hinv.fp, hinv.frames⟩
    · simp only [jmpNext]
      split
      · simp only [jumpTarget_eq]; omega
      · omega
    · simp only [jmpNext]
      split
      · simp only [jumpTarget_eq]; exact hslot
      · exact slot_next hpc (hinv.pc_slot hpc) hdec (by simp)
  | callExternal insn regs' hd _ hcl =>
    obtain ⟨hpc, rfl, _⟩ := facts_at hwf hinv hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    refine ⟨by dsimp only; omega, fun _ => slot_next hpc (hinv.pc_slot hpc) hdec (by simp), ?_, hinv.frames⟩
    simp only
    rw [helperClobber_R10 hcl]
    exact hinv.fp
  | callLocal insn hd hsrc _ =>
    obtain ⟨hpc, rfl, facts⟩ := facts_at hwf hinv hd
    obtain ⟨_, _, hdec⟩ := decodeAt_some hd
    have hst := facts.structure_ok
    simp only [StructureOk] at hst
    obtain ⟨_, hcall⟩ := hst
    have hreal := hcall hsrc
    have hslot := realSlot_isSlot hwf hreal
    obtain ⟨_, hlt, _⟩ := hreal
    refine ⟨?_, fun _ => ?_, ?_, ?_⟩
    · simp only [callTarget_eq]; omega
    · simp only [callTarget_eq]; exact hslot
    · simp only [List.length_cons, fpAt]
      rw [← hinv.fp]
      simp [setReg]
    · exact FramesOk.cons hinv.fp (by dsimp only; omega)
        (fun _ => slot_next hpc (hinv.pc_slot hpc) hdec (by simp)) hinv.frames
  | exitReturn insn f rest hd hstack =>
    have hfr := hinv.frames
    rw [hstack] at hfr
    cases hfr with
    | cons hfp hret hretslot hrest =>
      refine ⟨hret, hretslot, ?_, hrest⟩
      simp only
      rw [restoreRegs_R10]
      exact hfp

/-! ## Progress -/

theorem progress {insns : List Insn} {top : Word} {P : Params} {s : State}
    (hwf : WellFormed insns) (hinv : Inv insns top P s) : ∃ c, Step P insns s c := by
  by_cases hend : s.pc = insns.length
  · exact ⟨_, Step.fellOff s hend⟩
  · have hpc : s.pc < insns.length := by have := hinv.pc_le; omega
    obtain ⟨op, hdec, facts⟩ := hwf s.pc hpc (hinv.pc_slot hpc)
    have hd := decodeAt_of hpc hdec
    cases op with
    | Alu width op source => exact ⟨_, Step.alu s _ width op source hd⟩
    | End kind => exact ⟨_, Step.endian s _ kind hd⟩
    | Load width signed => exact ⟨_, Step.memFault s _ _ hd (by simp)⟩
    | StoreImm width => exact ⟨_, Step.memFault s _ _ hd (by simp)⟩
    | StoreReg width => exact ⟨_, Step.memFault s _ _ hd (by simp)⟩
    | LoadImm64 => exact ⟨_, Step.loadImm64 s _ hd⟩
    | Atomic width op fetch => exact ⟨_, Step.memFault s _ _ hd (by simp)⟩
    | Ja width => exact ⟨_, Step.ja s _ width hd⟩
    | Jmp width op source => exact ⟨_, Step.jmp s _ width op source hd⟩
    | Call =>
      by_cases hsrc : insns[s.pc].src.val = 1
      · by_cases hdepth : s.stack.length < P.maxDepth
        · exact ⟨_, Step.callLocal s _ hd hsrc hdepth⟩
        · exact ⟨_, Step.callExhausted s _ hd hsrc (by omega)⟩
      · exact ⟨_, Step.callExternal s _ s.regs hd hsrc (fun _ _ => rfl)⟩
    | Exit =>
      cases hstack : s.stack with
      | nil => exact ⟨_, Step.exitTop s _ hd hstack⟩
      | cons f rest => exact ⟨_, Step.exitReturn s _ f rest hd hstack⟩

/-! ## The theorem -/

/-- Along every execution of an accepted program, the invariant holds and the
machine can take a step. -/
theorem validate_sound (config : validate.Config) (kh : Slice U32) (insns : Slice Insn)
    (ext : Slice Bool) (hlen : insns.length < 2 ^ 63)
    (h : validate.validate config kh insns ext = ok (.Ok ()))
    (P : Params) (ctx top : Word) :
    ∀ s, Reachable P insns.val (initial ctx top) s →
      Inv insns.val top P s ∧ ∃ c, Step P insns.val s c := by
  have hwf := validate_ok_wellFormed config kh insns ext hlen h
  intro s hr
  have hinv : Inv insns.val top P s := by
    induction hr with
    | refl => exact Inv.initial _ _ _ _
    | step _ hstep ih => exact preservation hwf ih hstep
  exact ⟨hinv, progress hwf hinv⟩

/-- Spelled out: the program counter never leaves the instruction slots. -/
theorem validate_sound_pc (config : validate.Config) (kh : Slice U32) (insns : Slice Insn)
    (ext : Slice Bool) (hlen : insns.length < 2 ^ 63)
    (h : validate.validate config kh insns ext = ok (.Ok ()))
    (P : Params) (ctx top : Word) (s : State) (hr : Reachable P insns.val (initial ctx top) s) :
    s.pc = insns.val.length ∨ (s.pc < insns.val.length ∧ InsnSlot insns.val s.pc) := by
  have hinv := (validate_sound config kh insns ext hlen h P ctx top s hr).1
  by_cases hend : s.pc = insns.val.length
  · exact Or.inl hend
  · have : s.pc < insns.val.length := by have := hinv.pc_le; omega
    exact Or.inr ⟨this, hinv.pc_slot this⟩

/-- Spelled out: `R10` is always the frame base of the current call depth. -/
theorem validate_sound_frame_pointer (config : validate.Config) (kh : Slice U32)
    (insns : Slice Insn) (ext : Slice Bool) (hlen : insns.length < 2 ^ 63)
    (h : validate.validate config kh insns ext = ok (.Ok ()))
    (P : Params) (ctx top : Word) (s : State) (hr : Reachable P insns.val (initial ctx top) s) :
    s.regs R10 = fpAt top P.stride s.stack.length :=
  (validate_sound config kh insns ext hlen h P ctx top s hr).1.fp

end async_ebpf_verified

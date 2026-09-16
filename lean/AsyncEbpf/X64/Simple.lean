import AsyncEbpf.X64.Run

/-!
# The simple macros

One `MacroOk` theorem per macro whose expansion is a handful of primitives and
whose rule is about registers, the frame scratch or a single guest access.
The four heavy ones — `CheckedAddr`, `HelperCall`, `LazyLocalCall` and the
push-balancing pair `MulDivMod`/`AtomicFetchAlu` — are proved elsewhere against
the same template.

Each theorem's hypotheses are of three kinds:

* the expansion, as `code[p]? = some (…primitive…)` for each position of the
  macro's range — read off `expand_one` in `src/verified/x64_expand.rs`;
* the checker's rule, in the extracted form `step` dispatches to
  (`x64_check.live_step`, `label_step`, `prologue_step`, `branch_step`), with
  `pre.alive = true`, because the glue never enters a macro the walk found
  dead;
* `Layout P`, and for the three address rules `WidthsOk pre`, which is the one
  fact about `Checked` widths that is not local to a macro.

A note on the cage. `addr_ok` admits *every* address when `cfg.pointer_mask`
is zero: the emitted code is raw, the runtime promised nothing about guest
memory, and `Safe` is then simply false for a guest access. So the three
address lemmas below carry the hypothesis `cfg.pointer_mask ≠ 0#i32`, and a
function lowered with the cage off is outside this theorem — which is what the
runtime's own documentation says of it.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

namespace X64

/-! ## Reading the checker's per-macro rules

`live_step` dispatches on the macro and, for the ones here, reduces to a
`write` or an `addr_ok`. Each lemma below is that reduction. -/

theorem live_alu {cfg : x64_ir.Cfg} {w64 : Bool} {op : x64_ir.AluRR} {src dst : Std.U8}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.Alu w64 op src dst) index pcv pre = ok (.Ok (), post)) :
    x64_check.write pre dst index pcv = ok (.Ok (), post) ∨
      (x64_check.alu_rr_writes op = ok false ∧ post = pre) := by
  unfold x64_check.live_step at h
  rw [ha] at h
  simp only [if_true] at h
  cases hb : x64_check.alu_rr_writes op with
  | ok b =>
    rw [hb] at h
    simp only [bind_tc_ok] at h
    cases b
    · simp only [Bool.false_eq_true, if_false, ok.injEq, Prod.mk.injEq] at h
      exact Or.inr ⟨rfl, h.2.symm⟩
    · simp only [if_true] at h
      exact Or.inl h
  | fail e => rw [hb] at h; simp at h
  | div => rw [hb] at h; simp at h

theorem live_aluImm {cfg : x64_ir.Cfg} {w64 : Bool} {op : x64_ir.AluRI} {dst : Std.U8}
    {imm : Std.I32} {index : Usize} {pcv : Std.U32} {pre post : x64_check.State}
    (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.AluImm w64 op dst imm) index pcv pre = ok (.Ok (), post)) :
    x64_check.write pre dst index pcv = ok (.Ok (), post) ∨
      (x64_check.alu_ri_writes op = ok false ∧ post = pre) := by
  unfold x64_check.live_step at h
  rw [ha] at h
  simp only [if_true] at h
  cases hb : x64_check.alu_ri_writes op with
  | ok b =>
    rw [hb] at h
    simp only [bind_tc_ok] at h
    cases b
    · simp only [Bool.false_eq_true, if_false, ok.injEq, Prod.mk.injEq] at h
      exact Or.inr ⟨rfl, h.2.symm⟩
    · simp only [if_true] at h
      exact Or.inl h
  | fail e => rw [hb] at h; simp at h
  | div => rw [hb] at h; simp at h

theorem live_shiftImm {cfg : x64_ir.Cfg} {w64 : Bool} {op : x64_ir.ShiftOp} {dst : Std.U8}
    {imm : Std.I32} {index : Usize} {pcv : Std.U32} {pre post : x64_check.State}
    (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.ShiftImm w64 op dst imm) index pcv pre = ok (.Ok (), post)) :
    x64_check.write pre dst index pcv = ok (.Ok (), post) := by
  unfold x64_check.live_step at h; rw [ha] at h; simpa using h

theorem live_shiftCl {cfg : x64_ir.Cfg} {w64 : Bool} {op : x64_ir.ShiftOp} {dst : Std.U8}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.ShiftCl w64 op dst) index pcv pre = ok (.Ok (), post)) :
    x64_check.write pre dst index pcv = ok (.Ok (), post) := by
  unfold x64_check.live_step at h; rw [ha] at h; simpa using h

theorem live_neg {cfg : x64_ir.Cfg} {w64 : Bool} {dst : Std.U8}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.Neg w64 dst) index pcv pre = ok (.Ok (), post)) :
    x64_check.write pre dst index pcv = ok (.Ok (), post) := by
  unfold x64_check.live_step at h; rw [ha] at h; simpa using h

theorem live_movSx {cfg : x64_ir.Cfg} {from_ : Std.U8} {w64 : Bool} {src dst : Std.U8}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.MovSx from_ w64 src dst) index pcv pre = ok (.Ok (), post)) :
    x64_check.write pre dst index pcv = ok (.Ok (), post) := by
  unfold x64_check.live_step at h; rw [ha] at h; simpa using h

theorem live_bswap {cfg : x64_ir.Cfg} {w64 : Bool} {dst : Std.U8}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.Bswap w64 dst) index pcv pre = ok (.Ok (), post)) :
    x64_check.write pre dst index pcv = ok (.Ok (), post) := by
  unfold x64_check.live_step at h; rw [ha] at h; simpa using h

theorem live_rol16 {cfg : x64_ir.Cfg} {dst : Std.U8}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.Rol16 dst) index pcv pre = ok (.Ok (), post)) :
    x64_check.write pre dst index pcv = ok (.Ok (), post) := by
  unfold x64_check.live_step at h; rw [ha] at h; simpa using h

theorem live_loadImm {cfg : x64_ir.Cfg} {dst : Std.U8} {imm : Std.I64}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.LoadImm dst imm) index pcv pre = ok (.Ok (), post)) :
    x64_check.write pre dst index pcv = ok (.Ok (), post) := by
  unfold x64_check.live_step at h; rw [ha] at h; simpa using h

theorem live_guestFp {cfg : x64_ir.Cfg} {dst : Std.U8}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.GuestFp dst) index pcv pre = ok (.Ok (), post)) :
    x64_check.write pre dst index pcv = ok (.Ok (), post) := by
  unfold x64_check.live_step at h; rw [ha] at h; simpa using h

/-! ## The `stores` clause

Most macros write nothing at all, and `macroOk_no_stores` is their whole
proof: show that every primitive of the range writes nothing and the clause
follows. The ones that do write — the guest store, the atomics, the parked
group base and the prologue's push — each have their own rule, and it is the
rule that already placed the access in a region, read again through
`StoreOk` instead of `AccessOk`. -/

/-- The `stores` clause of a macro no primitive of which writes memory. -/
theorem macroOk_no_stores {P : Params} {code : List x64_ir.PInsn} {p q : Nat}
    {pre : x64_check.State}
    (h : ∀ (u : State) (i : x64_ir.PInsn), Range p q u.pc → code[u.pc]? = some i →
      stores i u = []) :
    ∀ s : State, s.pc = p → Agree P pre s → ∀ s', Stays P code (Range p q) s s' →
      ∀ c, Step P code s' c → ∀ i, code[s'.pc]? = some i →
        ∀ bn ∈ stores i s', StoreOk P bn.1 bn.2 := by
  intro s hs hag s' hsty c hstep i hi bn hbn
  rw [h s' i hsty.inside_last hi] at hbn
  simp at hbn

/-! ## The macros of one register-only primitive -/

/-- The walk inside a one-primitive region of a register-only macro never
moves: the single step leaves the region. -/
theorem stays_regOnly {P : Params} {code : List x64_ir.PInsn} {p : Nat} {i : x64_ir.PInsn}
    (hi : RegOnly i) (hc : code[p]? = some i) {s s' : State}
    (h : Stays P code (Range p (p + 1)) s s') : s' = s := by
  refine stays_single ?_ h
  intro t t' ht hst
  obtain ⟨u, hu, hpc, -, -⟩ := step_regOnly hi (by rw [ht]; exact hc) hst
  cases hu
  rw [hpc, ht]

/-- A macro that expands to one register-only primitive writing `r`, which is
what the checker's `write` admitted. -/
theorem macroOk_regOnly_write {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {pre post : x64_check.State} {i : x64_ir.PInsn} {r : Std.U8} {index : Usize}
    {pcv : Std.U32} (hL : Layout P) (hi : RegOnly i) (hwr : writes i = [r.val])
    (hc : code[p]? = some i)
    (hw : x64_check.write pre r index pcv = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rw [stays_regOnly hi hc hsty]
    exact rsp_window_of_agree hL hag
  case stores =>
    refine macroOk_no_stores (fun u jj hin hjj => ?_)
    have hu : u.pc = p := by simp only [Range] at hin; omega
    rw [hu, hc] at hjj
    obtain rfl : jj = _ := by simpa using hjj.symm
    exact stores_regOnly hi u
  · intro s hs hag s' hstays c hstep j hj bn hbn
    have heq := stays_regOnly hi hc hstays
    subst heq
    rw [hs, hc] at hj
    obtain rfl : j = i := by simpa using hj.symm
    rw [accesses_regOnly hi] at hbn
    simp at hbn
  · intro s hs hag s' hstays s'' hstep hout
    have heq := stays_regOnly hi hc hstays
    subst heq
    obtain ⟨u, hu, hpc, hmem, hregs⟩ := step_regOnly hi (by rw [hs]; exact hc) hstep
    cases hu
    refine Or.inl ⟨by rw [hpc, hs], agree_write hag hw (fun r' hr' => hregs r' ?_) hmem⟩
    rw [hwr]; simpa using hr'
  · intro s hs hag s' hstays s'' hstep
    have heq := stays_regOnly hi hc hstays
    subst heq
    obtain ⟨u, hu, -, -, -⟩ := step_regOnly hi (by rw [hs]; exact hc) hstep
    simp at hu

/-- A macro that expands to one register-only primitive the checker learns
nothing from: a label, a `pause`, a compare or a test. -/
theorem macroOk_regOnly_keep {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {pre : x64_check.State} {i : x64_ir.PInsn} (hL : Layout P) (hi : RegOnly i)
    (hc : code[p]? = some i)
    (hkeep : ∀ t t' : State, t.pc = p → Step P code t (.next t') → ∀ r, t'.regs r = t.regs r) :
    MacroOk P code p (p + 1) pre pre [] := by
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rw [stays_regOnly hi hc hsty]
    exact rsp_window_of_agree hL hag
  case stores =>
    refine macroOk_no_stores (fun u jj hin hjj => ?_)
    have hu : u.pc = p := by simp only [Range] at hin; omega
    rw [hu, hc] at hjj
    obtain rfl : jj = _ := by simpa using hjj.symm
    exact stores_regOnly hi u
  · intro s hs hag s' hstays c hstep j hj bn hbn
    have heq := stays_regOnly hi hc hstays
    subst heq
    rw [hs, hc] at hj
    obtain rfl : j = i := by simpa using hj.symm
    rw [accesses_regOnly hi] at hbn
    simp at hbn
  · intro s hs hag s' hstays s'' hstep hout
    have heq := stays_regOnly hi hc hstays
    subst heq
    obtain ⟨u, hu, hpc, hmem, -⟩ := step_regOnly hi (by rw [hs]; exact hc) hstep
    cases hu
    exact Or.inl ⟨by rw [hpc, hs], agree_same hag (hkeep _ _ hs hstep) hmem⟩
  · intro s hs hag s' hstays s'' hstep
    have heq := stays_regOnly hi hc hstays
    subst heq
    obtain ⟨u, hu, -, -, -⟩ := step_regOnly hi (by rw [hs]; exact hc) hstep
    simp at hu

/-- The common case of it: the primitive writes no register at all. -/
theorem macroOk_regOnly_id {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {pre : x64_check.State} {i : x64_ir.PInsn} (hL : Layout P) (hi : RegOnly i)
    (hwr : writes i = []) (hc : code[p]? = some i) :
    MacroOk P code p (p + 1) pre pre [] := by
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rw [stays_regOnly hi hc hsty]
    exact rsp_window_of_agree hL hag
  case stores =>
    refine macroOk_no_stores (fun u jj hin hjj => ?_)
    have hu : u.pc = p := by simp only [Range] at hin; omega
    rw [hu, hc] at hjj
    obtain rfl : jj = _ := by simpa using hjj.symm
    exact stores_regOnly hi u
  · intro s hs hag s' hstays c hstep j hj bn hbn
    have heq := stays_regOnly hi hc hstays
    subst heq
    rw [hs, hc] at hj
    obtain rfl : j = i := by simpa using hj.symm
    rw [accesses_regOnly hi] at hbn
    simp at hbn
  · intro s hs hag s' hstays s'' hstep hout
    have heq := stays_regOnly hi hc hstays
    subst heq
    obtain ⟨u, hu, hpc, hmem, hregs⟩ := step_regOnly hi (by rw [hs]; exact hc) hstep
    cases hu
    exact Or.inl ⟨by rw [hpc, hs], agree_same hag (fun r => hregs r (by rw [hwr]; simp)) hmem⟩
  · intro s hs hag s' hstays s'' hstep
    have heq := stays_regOnly hi hc hstays
    subst heq
    obtain ⟨u, hu, -, -, -⟩ := step_regOnly hi (by rw [hs]; exact hc) hstep
    simp at hu

/-- A local label of one macro's expansion. -/
theorem macroOk_localLabel {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {pre : x64_check.State} {n : Std.U32} (hL : Layout P) (hc : code[p]? = some (.Local n)) :
    MacroOk P code p (p + 1) pre pre [] :=
  macroOk_regOnly_id (i := .Local n) hL trivial rfl hc

/-- The exit label the trailer's epilogue carries. -/
theorem macroOk_exitLabel {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {pre : x64_check.State} (hL : Layout P) (hc : code[p]? = some .ExitLabel) :
    MacroOk P code p (p + 1) pre pre [] :=
  macroOk_regOnly_id (i := .ExitLabel) hL trivial rfl hc

/-! ## The register macros

`expand_one` emits one primitive for each of these, with the macro's own
operands, and the checker's rule is `write` on the destination. -/

theorem macroOk_alu {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {w64 : Bool} {op : x64_ir.AluRR} {src dst : Std.U8}
    {index : Usize} {pcv : Std.U32} (hL : Layout P) (ha : pre.alive = true)
    (hc : code[p]? = some (.Alu w64 op src dst))
    (h : x64_check.live_step cfg (.Alu w64 op src dst) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  rcases live_alu ha h with hw | ⟨hb, rfl⟩
  · exact macroOk_regOnly_write (i := .Alu w64 op src dst) hL trivial rfl hc hw
  · -- A compare or a test writes nothing at all.
    have hop : op = .Cmp ∨ op = .Test := by
      cases op <;> simp [x64_check.alu_rr_writes] at hb ⊢
    refine macroOk_regOnly_keep (i := .Alu w64 op src dst) hL trivial hc ?_
    intro t t' ht hst r
    have := step_alu (by rw [ht]; exact hc) hst
    simp only [Config.next.injEq] at this
    subst this
    rcases hop with rfl | rfl <;> simp [aluRRStep, wFlags]

theorem macroOk_aluImm {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {w64 : Bool} {op : x64_ir.AluRI} {dst : Std.U8}
    {imm : Std.I32} {index : Usize} {pcv : Std.U32} (hL : Layout P) (ha : pre.alive = true)
    (hc : code[p]? = some (.AluImm w64 op dst imm))
    (h : x64_check.live_step cfg (.AluImm w64 op dst imm) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  rcases live_aluImm ha h with hw | ⟨hb, rfl⟩
  · exact macroOk_regOnly_write (i := .AluImm w64 op dst imm) hL trivial rfl hc hw
  · have hop : op = .Cmp ∨ op = .Test := by
      cases op <;> simp [x64_check.alu_ri_writes] at hb ⊢
    refine macroOk_regOnly_keep (i := .AluImm w64 op dst imm) hL trivial hc ?_
    intro t t' ht hst r
    have := step_aluImm (by rw [ht]; exact hc) hst
    simp only [Config.next.injEq] at this
    subst this
    rcases hop with rfl | rfl <;> simp [aluImmStep, wFlags]

theorem macroOk_shiftImm {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {w64 : Bool} {op : x64_ir.ShiftOp} {dst : Std.U8}
    {imm : Std.I32} {index : Usize} {pcv : Std.U32} (hL : Layout P) (ha : pre.alive = true)
    (hc : code[p]? = some (.ShiftImm w64 op dst imm))
    (h : x64_check.live_step cfg (.ShiftImm w64 op dst imm) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] :=
  macroOk_regOnly_write (i := .ShiftImm w64 op dst imm) hL trivial rfl hc (live_shiftImm ha h)

theorem macroOk_shiftCl {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {w64 : Bool} {op : x64_ir.ShiftOp} {dst : Std.U8}
    {index : Usize} {pcv : Std.U32} (hL : Layout P) (ha : pre.alive = true)
    (hc : code[p]? = some (.ShiftCl w64 op dst))
    (h : x64_check.live_step cfg (.ShiftCl w64 op dst) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] :=
  macroOk_regOnly_write (i := .ShiftCl w64 op dst) hL trivial rfl hc (live_shiftCl ha h)

theorem macroOk_neg {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {w64 : Bool} {dst : Std.U8}
    {index : Usize} {pcv : Std.U32} (hL : Layout P) (ha : pre.alive = true)
    (hc : code[p]? = some (.Neg w64 dst))
    (h : x64_check.live_step cfg (.Neg w64 dst) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] :=
  macroOk_regOnly_write (i := .Neg w64 dst) hL trivial rfl hc (live_neg ha h)

theorem macroOk_movSx {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {from_ : Std.U8} {w64 : Bool} {src dst : Std.U8}
    {index : Usize} {pcv : Std.U32} (hL : Layout P) (ha : pre.alive = true)
    (hc : code[p]? = some (.MovSx from_ w64 src dst))
    (h : x64_check.live_step cfg (.MovSx from_ w64 src dst) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] :=
  macroOk_regOnly_write (i := .MovSx from_ w64 src dst) hL trivial rfl hc (live_movSx ha h)

theorem macroOk_bswap {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {w64 : Bool} {dst : Std.U8}
    {index : Usize} {pcv : Std.U32} (hL : Layout P) (ha : pre.alive = true)
    (hc : code[p]? = some (.Bswap w64 dst))
    (h : x64_check.live_step cfg (.Bswap w64 dst) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] :=
  macroOk_regOnly_write (i := .Bswap w64 dst) hL trivial rfl hc (live_bswap ha h)

theorem macroOk_rol16 {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {dst : Std.U8} {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (ha : pre.alive = true) (hc : code[p]? = some (.Rol16 dst))
    (h : x64_check.live_step cfg (.Rol16 dst) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] :=
  macroOk_regOnly_write (i := .Rol16 dst) hL trivial rfl hc (live_rol16 ha h)

theorem macroOk_loadImm {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {dst : Std.U8} {imm : Std.I64} {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (ha : pre.alive = true) (hc : code[p]? = some (.LoadImm dst imm))
    (h : x64_check.live_step cfg (.LoadImm dst imm) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] :=
  macroOk_regOnly_write (i := .LoadImm dst imm) hL trivial rfl hc (live_loadImm ha h)

/-! ## The address rule

`addr_ok` admits an access three ways, and with the cage on only two of them:
through a `Checked` base with the access inside its window, or through the
frame register into the frame window. The lemmas below read that off the
extracted code and turn it into a `GuestOk`. -/

theorem ineg_val {ty} {x y : Std.IScalar ty} (h : Std.IScalar.neg x = ok y) : y.val = -x.val := by
  have := Std.IScalar.tryMk_eq ty (-x.val)
  unfold Std.IScalar.neg at h
  rw [h] at this
  exact this.1

theorem hcast_I64_val {ty : Std.UScalarTy} (x : Std.UScalar ty) (h : (x.val : Int) < 2 ^ 63) :
    (Std.UScalar.hcast Std.IScalarTy.I64 x).val = (x.val : Int) := by
  have hb0 : (0 : Int) ≤ (x.val : Int) := by positivity
  simp only [Std.IScalar.val, Std.UScalar.hcast, BitVec.toInt_setWidth,
    BitVec.truncate_eq_setWidth]
  rw [Int.bmod]
  norm_num
  omega

theorem frame_ok_cases {cfg : x64_ir.Cfg} {pre : x64_check.State} {base : Std.U8}
    {disp size : Std.I64} (h : x64_check.frame_ok cfg pre base disp size = ok true) :
    base.val = 15 ∧ tagAt pre 15 = .Fp ∧
      -((cfg.stack_frame_size.val : Int)) ≤ disp.val ∧ disp.val + size.val ≤ 0 := by
  unfold x64_check.frame_ok at h
  split at h
  · rename_i hb
    cases hfi : x64_check.frame_intact pre with
    | ok b =>
      rw [hfi] at h
      simp only [bind_tc_ok] at h
      cases b
      · simp at h
      · simp only [if_true] at h
        have hfp := frame_intact_eq hfi
        have hbv : base.val = 15 := by rw [hb, frame_val]
        split at h
        · split at h
          · simp only [lift, bind_tc_ok] at h
            cases hneg : (-.(Std.UScalar.hcast Std.IScalarTy.I64 cfg.stack_frame_size)) with
            | ok i1 =>
              rw [hneg] at h
              simp only [bind_tc_ok] at h
              have hi1 := ineg_val hneg
              rw [hcast_I64_val _ (by scalar_tac)] at hi1
              split at h
              · rename_i hge
                cases hadd : disp + size with
                | ok i2 =>
                  rw [hadd] at h
                  simp only [bind_tc_ok, ok.injEq, decide_eq_true_eq] at h
                  have hv := Std.IScalar.add_equiv disp size
                  rw [hadd] at hv
                  have hle : i2.val ≤ (0#i64 : Std.I64).val :=
                    (Std.IScalar.le_equiv i2 0#i64).mp h
                  refine ⟨hbv, hfp, ?_, ?_⟩
                  · have := (Std.IScalar.le_equiv i1 disp).mp hge
                    omega
                  · simp only [Std.IScalar.val] at hle
                    scalar_tac
                | fail e => rw [hadd] at h; simp at h
                | div => rw [hadd] at h; simp at h
              · simp at h
            | fail e => rw [hneg] at h; simp at h
            | div => rw [hneg] at h; simp at h
          · simp at h
        · simp at h
    | fail e => rw [hfi] at h; simp at h
    | div => rw [hfi] at h; simp at h
  · simp at h

theorem checked_ok_cases {pre : x64_check.State} {base : Std.U8}
    {disp size : Std.I64} (h : x64_check.checked_ok pre base disp size = ok true) :
    ∃ w : Std.U32, tagAt pre base.val = .Checked w ∧ 0 ≤ disp.val ∧
      disp.val + size.val ≤ (w.val : Int) := by
  unfold x64_check.checked_ok at h
  cases ht : x64_check.tag_of pre base with
  | ok t =>
    rw [ht] at h
    simp only [bind_tc_ok] at h
    have hte := tag_of_eq ht
    cases t with
    | Top => simp at h
    | Fp => simp at h
    | Checked w =>
      simp only at h
      split at h
      · rename_i hge
        cases hadd : disp + size with
        | ok i =>
          rw [hadd] at h
          simp only [lift, bind_tc_ok, ok.injEq, decide_eq_true_eq] at h
          have hv := Std.IScalar.add_equiv disp size
          rw [hadd] at hv
          have hle : i.val ≤ (UScalar.hcast IScalarTy.I64 w).val :=
            (Std.IScalar.le_equiv i (UScalar.hcast IScalarTy.I64 w)).mp h
          have hw : (UScalar.hcast IScalarTy.I64 w).val = (w.val : Int) :=
            hcast_I64_val w (by scalar_tac)
          refine ⟨w, hte.symm, by scalar_tac, ?_⟩
          rw [hw] at hle
          omega
        | fail e => rw [hadd] at h; simp at h
        | div => rw [hadd] at h; simp at h
      · simp at h
  | fail e => rw [ht] at h; simp at h
  | div => rw [ht] at h; simp at h

theorem addr_ok_cases {cfg : x64_ir.Cfg} {pre : x64_check.State} {base : Std.U8}
    {disp : Std.I32} {size : Std.U32} (hmask : cfg.pointer_mask ≠ 0#i32)
    (h : x64_check.addr_ok cfg pre base disp size = ok true) :
    (∃ w : Std.U32, tagAt pre base.val = .Checked w ∧ 0 ≤ disp.val ∧
        disp.val + (size.val : Int) ≤ (w.val : Int)) ∨
      (base.val = 15 ∧ tagAt pre 15 = .Fp ∧
        -((cfg.stack_frame_size.val : Int)) ≤ disp.val ∧ disp.val + (size.val : Int) ≤ 0) := by
  unfold x64_check.addr_ok at h
  rw [if_neg hmask] at h
  simp only [lift, bind_tc_ok] at h
  have hd : (Std.IScalar.cast Std.IScalarTy.I64 disp).val = disp.val := by simp
  have hz : (Std.UScalar.hcast Std.IScalarTy.I64 size).val = (size.val : Int) :=
    hcast_I64_val size (by scalar_tac)
  cases hck : x64_check.checked_ok pre base (Std.IScalar.cast Std.IScalarTy.I64 disp)
      (Std.UScalar.hcast Std.IScalarTy.I64 size) with
  | ok b =>
    rw [hck] at h
    simp only [bind_tc_ok] at h
    cases b
    · simp only [Bool.false_eq_true, if_false] at h
      have := frame_ok_cases h
      rw [hd, hz] at this
      exact Or.inr this
    · obtain ⟨w, hw, h1, h2⟩ := checked_ok_cases hck
      rw [hd] at h1
      rw [hd, hz] at h2
      exact Or.inl ⟨w, hw, h1, h2⟩
  | fail e => rw [hck] at h; simp at h
  | div => rw [hck] at h; simp at h

/-- The three cases of `addr_ok`, as a single fact about the address the
machine computes. -/
theorem guestOk_addr {P : Params} {cfg : x64_ir.Cfg} {pre : x64_check.State} {s : State}
    {base : Std.U8} {disp : Std.I32} {size : Std.U32} {n : Nat}
    (hL : Layout P) (hcfg : CfgOk P cfg) (hag : Agree P pre s) (hwid : WidthsOk pre)
    (hmask : cfg.pointer_mask ≠ 0#i32) (hn : (n : Int) = (size.val : Int))
    (h : x64_check.addr_ok cfg pre base disp size = ok true) :
    GuestOk P (addr s base disp) n := by
  rcases addr_ok_cases hmask h with ⟨w, hw, h1, h2⟩ | ⟨hb, hfp, h1, h2⟩
  · have hlt : base.val < 16 := tagAt_range (by rw [hw]; simp)
    have hv := hag.regs base.val hlt
    rw [hw] at hv
    exact tagOk_checked_window hL hv h1 (by omega) (hwid.1 base.val w hw)
  · have hv := hag.regs 15 (by norm_num)
    rw [hfp] at hv
    simp only [addr, hb]
    exact frame_access_ok hL hv (by rw [← hcfg]; exact h1) (by omega)

/-- The same three cases for a store: every address the rules admit is one
this activation may *write*. The parked zero lands on the first page, a
checked base inside a guest backing, the frame fast path inside the stack's
backing; all three are writable, and none of them is the read-only part of the
frame scratch, the entry word or the descriptor. -/
theorem storeOk_addr {P : Params} {cfg : x64_ir.Cfg} {pre : x64_check.State} {s : State}
    {base : Std.U8} {disp : Std.I32} {size : Std.U32} {n : Nat}
    (hL : Layout P) (hcfg : CfgOk P cfg) (hag : Agree P pre s) (hwid : WidthsOk pre)
    (hmask : cfg.pointer_mask ≠ 0#i32) (hn : (n : Int) = (size.val : Int))
    (h : x64_check.addr_ok cfg pre base disp size = ok true) :
    StoreOk P (addr s base disp) n := by
  rcases addr_ok_cases hmask h with ⟨w, hw, h1, h2⟩ | ⟨hb, hfp, h1, h2⟩
  · have hlt : base.val < 16 := tagAt_range (by rw [hw]; simp)
    have hv := hag.regs base.val hlt
    rw [hw] at hv
    exact tagOk_checked_store hL hv h1 (by omega) (hwid.1 base.val w hw)
  · have hv := hag.regs 15 (by norm_num)
    rw [hfp] at hv
    simp only [addr, hb]
    exact frame_store_ok hL hv (by rw [← hcfg]; exact h1) (by omega)

/-! ## The macros of one guest access -/

/-- Nothing but `ret` returns. -/
theorem not_step_returned {P : Params} {code : List x64_ir.PInsn} {s s'' : State}
    {i : x64_ir.PInsn} (hne : i ≠ .Ret) (hc : code[s.pc]? = some i)
    (h : Step P code s (.returned s'')) : False := by
  have hr := (step_returned_ret h).1
  rw [hc] at hr
  exact hne (by simpa using hr)

/-- A macro of one primitive that makes one guest access. `hpost` is the only
macro-specific part: what the primitive did to the state. -/
theorem macroOk_guestOne {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {cfg : x64_ir.Cfg} {pre post : x64_check.State} {i : x64_ir.PInsn} {base : Std.U8}
    {disp : Std.I32} {size : Std.U32} {n : Nat}
    (hL : Layout P) (hcfg : CfgOk P cfg) (hwid : WidthsOk pre)
    (hmask : cfg.pointer_mask ≠ 0#i32) (hc : code[p]? = some i) (hne : i ≠ .Ret)
    (hok : x64_check.addr_ok cfg pre base disp size = ok true)
    (hn : (n : Int) = (size.val : Int))
    (hacc : ∀ (t : State) (bn : Word × Nat), bn ∈ accesses i t →
      bn.1 = addr t base disp ∧ bn.2 = n)
    (hstr : ∀ (t : State) (bn : Word × Nat), bn ∈ stores i t →
      bn.1 = addr t base disp ∧ bn.2 = n)
    (hadv : ∀ t t' : State, code[t.pc]? = some i → Step P code t (.next t') →
      t'.pc = t.pc + 1)
    (hpost : ∀ t t' : State, code[t.pc]? = some i → Agree P pre t →
      GuestOk P (addr t base disp) n → Step P code t (.next t') → Agree P post t') :
    MacroOk P code p (p + 1) pre post [] := by
  have hstays : ∀ s s' : State, s.pc = p → Stays P code (Range p (p + 1)) s s' → s' = s := by
    intro s s' hs hst
    refine stays_single ?_ hst
    intro t t' ht hstep
    rw [hadv t t' (by rw [ht]; exact hc) hstep, ht]
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rw [hstays s s' hs hsty]
    exact rsp_window_of_agree hL hag
  case stores =>
    intro s hs hag s' hsty c hstep j hj bn hbn
    have heq := hstays s s' hs hsty
    subst heq
    rw [hs, hc] at hj
    obtain rfl : j = i := by simpa using hj.symm
    obtain ⟨h1, h2⟩ := hstr s' bn hbn
    rw [h1, h2]
    exact storeOk_addr hL hcfg hag hwid hmask hn hok
  · intro s hs hag s' hsty c hstep j hj bn hbn
    have heq := hstays s s' hs hsty
    subst heq
    rw [hs, hc] at hj
    obtain rfl : j = i := by simpa using hj.symm
    obtain ⟨h1, h2⟩ := hacc s' bn hbn
    rw [h1, h2]
    exact (guestOk_addr hL hcfg hag hwid hmask hn hok).access
  · intro s hs hag s' hsty s'' hstep hout
    have heq := hstays s s' hs hsty
    subst heq
    refine Or.inl ⟨?_, hpost s' s'' (by rw [hs]; exact hc) hag
      (guestOk_addr hL hcfg hag hwid hmask hn hok) hstep⟩
    rw [hadv s' s'' (by rw [hs]; exact hc) hstep, hs]
  · intro s hs hag s' hsty s'' hstep
    have heq := hstays s s' hs hsty
    subst heq
    exact absurd hstep (fun hx => not_step_returned hne (by rw [hs]; exact hc) hx)

/-! ## Guest loads, stores and atomics

One primitive each, all with the same address rule. Each carries the
hypothesis `cfg.pointer_mask ≠ 0#i32`: with the cage off `addr_ok` admits
every address, the emitted access is raw, and `Safe` is simply false for it —
a function lowered with the cage off is outside this theorem. -/

theorem live_load {cfg : x64_ir.Cfg} {size : Std.U8} {sx : Bool} {base dst : Std.U8}
    {disp : Std.I32} {index : Usize} {pcv : Std.U32} {pre post : x64_check.State}
    (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.Load size sx base dst disp) index pcv pre
      = ok (.Ok (), post)) :
    x64_check.addr_ok cfg pre base disp (Std.UScalar.cast .U32 size) = ok true ∧
      x64_check.write pre dst index pcv = ok (.Ok (), post) := by
  unfold x64_check.live_step at h
  rw [ha] at h
  simp only [if_true, lift, bind_tc_ok] at h
  cases hb : x64_check.addr_ok cfg pre base disp (Std.UScalar.cast .U32 size) with
  | ok b =>
    rw [hb] at h
    simp only [bind_tc_ok] at h
    cases b
    · simp [x64_check.reject] at h
    · exact ⟨rfl, by simpa using h⟩
  | fail e => rw [hb] at h; simp at h
  | div => rw [hb] at h; simp at h

theorem live_store {cfg : x64_ir.Cfg} {size src base : Std.U8} {disp : Std.I32}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.Store size src base disp) index pcv pre
      = ok (.Ok (), post)) :
    x64_check.addr_ok cfg pre base disp (Std.UScalar.cast .U32 size) = ok true ∧ post = pre := by
  unfold x64_check.live_step at h
  rw [ha] at h
  simp only [if_true, lift, bind_tc_ok] at h
  cases hb : x64_check.addr_ok cfg pre base disp (Std.UScalar.cast .U32 size) with
  | ok b =>
    rw [hb] at h
    simp only [bind_tc_ok] at h
    cases b
    · simp [x64_check.reject] at h
    · simp only [if_true, ok.injEq, Prod.mk.injEq] at h
      exact ⟨rfl, h.2.symm⟩
  | fail e => rw [hb] at h; simp at h
  | div => rw [hb] at h; simp at h

theorem live_storeImm {cfg : x64_ir.Cfg} {size base : Std.U8} {disp imm : Std.I32}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.StoreImm size base disp imm) index pcv pre
      = ok (.Ok (), post)) :
    x64_check.addr_ok cfg pre base disp (Std.UScalar.cast .U32 size) = ok true ∧ post = pre := by
  unfold x64_check.live_step at h
  rw [ha] at h
  simp only [if_true, lift, bind_tc_ok] at h
  cases hb : x64_check.addr_ok cfg pre base disp (Std.UScalar.cast .U32 size) with
  | ok b =>
    rw [hb] at h
    simp only [bind_tc_ok] at h
    cases b
    · simp [x64_check.reject] at h
    · simp only [if_true, ok.injEq, Prod.mk.injEq] at h
      exact ⟨rfl, h.2.symm⟩
  | fail e => rw [hb] at h; simp at h
  | div => rw [hb] at h; simp at h

theorem live_atomicAlu {cfg : x64_ir.Cfg} {op : Std.U8} {w64 : Bool} {src base : Std.U8}
    {disp : Std.I32} {index : Usize} {pcv : Std.U32} {pre post : x64_check.State}
    (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.AtomicAlu op w64 src base disp) index pcv pre
      = ok (.Ok (), post)) :
    x64_check.addr_ok cfg pre base disp (if w64 then 8#u32 else 4#u32) = ok true ∧
      post = pre := by
  unfold x64_check.live_step at h
  rw [ha] at h
  simp only [if_true, x64_check.atomic_size] at h
  cases hb : x64_check.addr_ok cfg pre base disp (if w64 then 8#u32 else 4#u32) with
  | ok b =>
    rw [show (if w64 then ok (8#u32) else ok (4#u32)) = ok (if w64 then 8#u32 else 4#u32) by
      cases w64 <;> rfl] at h
    simp only [bind_tc_ok] at h
    rw [hb] at h
    simp only [bind_tc_ok] at h
    cases b
    · simp [x64_check.reject] at h
    · simp only [if_true, ok.injEq, Prod.mk.injEq] at h
      exact ⟨rfl, h.2.symm⟩
  | fail e =>
    rw [show (if w64 then ok (8#u32) else ok (4#u32)) = ok (if w64 then 8#u32 else 4#u32) by
      cases w64 <;> rfl, bind_tc_ok, hb] at h
    simp at h
  | div =>
    rw [show (if w64 then ok (8#u32) else ok (4#u32)) = ok (if w64 then 8#u32 else 4#u32) by
      cases w64 <;> rfl, bind_tc_ok, hb] at h
    simp at h

theorem live_atomicXchg {cfg : x64_ir.Cfg} {w64 : Bool} {src base : Std.U8}
    {disp : Std.I32} {index : Usize} {pcv : Std.U32} {pre post : x64_check.State}
    (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.AtomicXchg w64 src base disp) index pcv pre
      = ok (.Ok (), post)) :
    x64_check.addr_ok cfg pre base disp (if w64 then 8#u32 else 4#u32) = ok true ∧
      x64_check.write pre src index pcv = ok (.Ok (), post) := by
  unfold x64_check.live_step at h
  rw [ha] at h
  simp only [if_true, x64_check.atomic_size] at h
  rw [show (if w64 then ok (8#u32) else ok (4#u32)) = ok (if w64 then 8#u32 else 4#u32) by
    cases w64 <;> rfl] at h
  simp only [bind_tc_ok] at h
  cases hb : x64_check.addr_ok cfg pre base disp (if w64 then 8#u32 else 4#u32) with
  | ok b =>
    rw [hb] at h
    simp only [bind_tc_ok] at h
    cases b
    · simp [x64_check.reject] at h
    · exact ⟨rfl, by simpa using h⟩
  | fail e => rw [hb] at h; simp at h
  | div => rw [hb] at h; simp at h

theorem live_atomicCmpxchg {cfg : x64_ir.Cfg} {w64 : Bool} {src base : Std.U8}
    {disp : Std.I32} {index : Usize} {pcv : Std.U32} {pre post : x64_check.State}
    (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.AtomicCmpxchg w64 src base disp) index pcv pre
      = ok (.Ok (), post)) :
    x64_check.addr_ok cfg pre base disp (if w64 then 8#u32 else 4#u32) = ok true ∧
      x64_check.write pre x64_ir.RAX index pcv = ok (.Ok (), post) := by
  unfold x64_check.live_step at h
  rw [ha] at h
  simp only [if_true, x64_check.atomic_size] at h
  rw [show (if w64 then ok (8#u32) else ok (4#u32)) = ok (if w64 then 8#u32 else 4#u32) by
    cases w64 <;> rfl] at h
  simp only [bind_tc_ok] at h
  cases hb : x64_check.addr_ok cfg pre base disp (if w64 then 8#u32 else 4#u32) with
  | ok b =>
    rw [hb] at h
    simp only [bind_tc_ok] at h
    cases b
    · simp [x64_check.reject] at h
    · exact ⟨rfl, by simpa using h⟩
  | fail e => rw [hb] at h; simp at h
  | div => rw [hb] at h; simp at h

theorem rax_val : (x64_ir.RAX).val = RAX := by rw [x64_ir.RAX]; rfl

theorem macroOk_load {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {size : Std.U8} {sx : Bool} {base dst : Std.U8}
    {disp : Std.I32} {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (hcfg : CfgOk P cfg) (hwid : WidthsOk pre)
    (hmask : cfg.pointer_mask ≠ 0#i32) (ha : pre.alive = true)
    (hc : code[p]? = some (.Load size sx base dst disp))
    (h : x64_check.live_step cfg (.Load size sx base dst disp) index pcv pre
      = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  obtain ⟨hok, hw⟩ := live_load ha h
  refine macroOk_guestOne (n := size.val) hL hcfg hwid hmask hc (by simp) hok (by simp)
    ?_ (fun t bn hbn => absurd hbn (by simp)) ?_ ?_
  · intro t bn hbn
    rw [accesses_load] at hbn
    split at hbn <;> simp_all
  · intro t t' hcode hstep
    rcases step_load hcode hstep with ⟨-, hu⟩ | ⟨-, -, hu⟩ <;>
      · simp only [Config.next.injEq] at hu
        subst hu
        simp [wReg, wNext]
  · intro t t' hcode hag hg hstep
    rcases step_load hcode hstep with ⟨-, hu⟩ | ⟨-, -, hu⟩ <;>
      · simp only [Config.next.injEq] at hu
        subst hu
        exact agree_write hag hw (fun r' hr' => by
          simp [wReg, wNext, Function.update_of_ne hr']) rfl

theorem macroOk_store {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {size src base : Std.U8} {disp : Std.I32}
    {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (hcfg : CfgOk P cfg) (hwid : WidthsOk pre)
    (hmask : cfg.pointer_mask ≠ 0#i32) (ha : pre.alive = true)
    (hc : code[p]? = some (.Store size src base disp))
    (h : x64_check.live_step cfg (.Store size src base disp) index pcv pre
      = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  obtain ⟨hok, rfl⟩ := live_store ha h
  refine macroOk_guestOne (n := size.val) hL hcfg hwid hmask hc (by simp) hok (by simp)
    ?_ (by intro t bn hbn; simp at hbn; simp [hbn]) ?_ ?_
  · intro t bn hbn; simp at hbn; simp [hbn]
  · intro t t' hcode hstep
    have hu := step_store hcode hstep
    simp only [Config.next.injEq] at hu
    subst hu
    rfl
  · intro t t' hcode hag hg hstep
    have hu := step_store hcode hstep
    simp only [Config.next.injEq] at hu
    subst hu
    exact agree_store hag (fun r => rfl) (romem_store_guest hL hag.ro hg)
      (by simpa only [groupBase_kept hL hg] using hag.group)

theorem macroOk_storeImm {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {size base : Std.U8} {disp imm : Std.I32}
    {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (hcfg : CfgOk P cfg) (hwid : WidthsOk pre)
    (hmask : cfg.pointer_mask ≠ 0#i32) (ha : pre.alive = true)
    (hc : code[p]? = some (.StoreImm size base disp imm))
    (h : x64_check.live_step cfg (.StoreImm size base disp imm) index pcv pre
      = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  obtain ⟨hok, rfl⟩ := live_storeImm ha h
  refine macroOk_guestOne (n := size.val) hL hcfg hwid hmask hc (by simp) hok (by simp)
    ?_ (by intro t bn hbn; simp at hbn; simp [hbn]) ?_ ?_
  · intro t bn hbn; simp at hbn; simp [hbn]
  · intro t t' hcode hstep
    have hu := step_storeImm hcode hstep
    simp only [Config.next.injEq] at hu
    subst hu
    rfl
  · intro t t' hcode hag hg hstep
    have hu := step_storeImm hcode hstep
    simp only [Config.next.injEq] at hu
    subst hu
    exact agree_store hag (fun r => rfl) (romem_store_guest hL hag.ro hg)
      (by simpa only [groupBase_kept hL hg] using hag.group)

theorem atomic_width (w64 : Bool) :
    ((opWidth w64 : Nat) : Int) = (((if w64 then 8#u32 else 4#u32) : Std.U32).val : Int) := by
  cases w64 <;> rfl

theorem macroOk_atomicAlu {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {op : Std.U8} {w64 : Bool} {src base : Std.U8}
    {disp : Std.I32} {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (hcfg : CfgOk P cfg) (hwid : WidthsOk pre)
    (hmask : cfg.pointer_mask ≠ 0#i32) (ha : pre.alive = true)
    (hc : code[p]? = some (.LockAlu op w64 src base disp))
    (h : x64_check.live_step cfg (.AtomicAlu op w64 src base disp) index pcv pre
      = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  obtain ⟨hok, rfl⟩ := live_atomicAlu ha h
  refine macroOk_guestOne (n := opWidth w64) hL hcfg hwid hmask hc (by simp) hok
    (atomic_width w64) ?_ (by intro t bn hbn; simp at hbn; simp [hbn]) ?_ ?_
  · intro t bn hbn; simp at hbn; simp [hbn]
  · intro t t' hcode hstep
    obtain ⟨f, hu⟩ := step_lockAlu hcode hstep
    simp only [Config.next.injEq] at hu
    subst hu
    simp only [lockAluStep]
  · intro t t' hcode hag hg hstep
    obtain ⟨f, hu⟩ := step_lockAlu hcode hstep
    simp only [Config.next.injEq] at hu
    subst hu
    simp only [lockAluStep]
    refine agree_store hag (fun r => rfl) (romem_store_guest hL hag.ro hg) ?_
    simpa only [groupBase_kept hL hg] using hag.group

theorem macroOk_atomicXchg {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {w64 : Bool} {src base : Std.U8}
    {disp : Std.I32} {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (hcfg : CfgOk P cfg) (hwid : WidthsOk pre)
    (hmask : cfg.pointer_mask ≠ 0#i32) (ha : pre.alive = true)
    (hc : code[p]? = some (.Xchg w64 src base disp))
    (h : x64_check.live_step cfg (.AtomicXchg w64 src base disp) index pcv pre
      = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  obtain ⟨hok, hw⟩ := live_atomicXchg ha h
  obtain ⟨-, -, -, -, -, hgrp, -, -⟩ := write_ok hw
  refine macroOk_guestOne (n := opWidth w64) hL hcfg hwid hmask hc (by simp) hok
    (atomic_width w64) ?_ (by intro t bn hbn; simp at hbn; simp [hbn]) ?_ ?_
  · intro t bn hbn; simp at hbn; simp [hbn]
  · intro t t' hcode hstep
    have hu := step_xchg hcode hstep
    simp only [Config.next.injEq] at hu
    subst hu
    simp only [xchgStep]
  · intro t t' hcode hag hg hstep
    have hu := step_xchg hcode hstep
    simp only [Config.next.injEq] at hu
    subst hu
    simp only [xchgStep]
    refine agree_write_store hag hw (fun r' hr' => ?_) (romem_store_guest hL hag.ro hg) ?_
    · simp only []
      rw [Function.update_of_ne hr']
    · rw [hgrp]
      simpa only [groupBase_kept hL hg] using hag.group

theorem macroOk_atomicCmpxchg {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {cfg : x64_ir.Cfg} {pre post : x64_check.State} {w64 : Bool} {src base : Std.U8}
    {disp : Std.I32} {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (hcfg : CfgOk P cfg) (hwid : WidthsOk pre)
    (hmask : cfg.pointer_mask ≠ 0#i32) (ha : pre.alive = true)
    (hc : code[p]? = some (.LockCmpxchg w64 src base disp))
    (h : x64_check.live_step cfg (.AtomicCmpxchg w64 src base disp) index pcv pre
      = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  obtain ⟨hok, hw⟩ := live_atomicCmpxchg ha h
  obtain ⟨-, -, -, -, -, hgrp, -, -⟩ := write_ok hw
  refine macroOk_guestOne (n := opWidth w64) hL hcfg hwid hmask hc (by simp) hok
    (atomic_width w64) ?_ (by intro t bn hbn; simp at hbn; simp [hbn]) ?_ ?_
  · intro t bn hbn; simp at hbn; simp [hbn]
  · intro t t' hcode hstep
    obtain ⟨f, hu⟩ := step_lockCmpxchg hcode hstep
    simp only [Config.next.injEq] at hu
    subst hu
    simp only [cmpxchgStep]
    split <;> rfl
  · intro t t' hcode hag hg hstep
    obtain ⟨f, hu⟩ := step_lockCmpxchg hcode hstep
    simp only [Config.next.injEq] at hu
    subst hu
    simp only [cmpxchgStep]
    split
    · refine agree_write_store hag hw (fun r' hr' => rfl) (romem_store_guest hL hag.ro hg) ?_
      rw [hgrp]
      simpa only [groupBase_kept hL hg] using hag.group
    · refine agree_write_store hag hw (fun r' hr' => ?_) hag.ro ?_
      · simp only []
        rw [Function.update_of_ne (by rw [rax_val] at hr'; exact hr')]
      · rw [hgrp]; exact hag.group

/-! ## The frame-slot macros

`GroupBaseStore`, `GroupBaseLoad` and `GuestFp` reach into the frame scratch
through `rbp`, which the generated code never writes. -/

theorem rbp_val : (x64_ir.RBP).val = RBP := by rw [x64_ir.RBP]; rfl
theorem r15_val : (x64_ir.R15).val = R15 := by rw [x64_ir.R15]; rfl
theorem groupBase_val : (x64_ir.frame.GROUP_BASE_OFFSET).val = -144 := by
  rw [x64_ir.frame.GROUP_BASE_OFFSET]; decide
theorem frameDelta_val : (x64_ir.frame.FRAME_DELTA_OFFSET).val = -40 := by
  rw [x64_ir.frame.FRAME_DELTA_OFFSET]; decide

@[simp] theorem storeVal_eight (v : Word) : storeVal 8 v = v := BitVec.setWidth_eq v

/-- The address `[rbp - 144]` names, in the two spellings the proofs use. -/
theorem addr_groupBase {P : Params} {a : x64_check.State} {s : State} (h : Agree P a s) :
    addr s x64_ir.RBP x64_ir.frame.GROUP_BASE_OFFSET = P.rbp0 - 144#64 := by
  rw [addr_rbp h rbp_val]
  exact rbp_slot (by norm_num) (by norm_num) groupBase_val

theorem live_groupBaseStore {cfg : x64_ir.Cfg} {src : Std.U8} {index : Usize} {pcv : Std.U32}
    {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.GroupBaseStore src) index pcv pre = ok (.Ok (), post)) :
    post = { pre with group := tagAt pre src.val } := by
  unfold x64_check.live_step at h
  rw [ha] at h
  simp only [if_true] at h
  cases ht : x64_check.tag_of pre src with
  | ok t =>
    rw [ht] at h
    simp only [bind_tc_ok, ok.injEq, Prod.mk.injEq] at h
    rw [← h.2, tag_of_eq ht, ha]
  | fail e => rw [ht] at h; simp at h
  | div => rw [ht] at h; simp at h

theorem macroOk_groupBaseStore {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {cfg : x64_ir.Cfg} {pre post : x64_check.State} {src : Std.U8} {index : Usize}
    {pcv : Std.U32} (hL : Layout P) (ha : pre.alive = true)
    (hc : code[p]? = some (.Store 8#u8 src x64_ir.RBP x64_ir.frame.GROUP_BASE_OFFSET))
    (h : x64_check.live_step cfg (.GroupBaseStore src) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  have hpost := live_groupBaseStore ha h
  subst hpost
  have hstays : ∀ s s' : State, s.pc = p → Stays P code (Range p (p + 1)) s s' → s' = s := by
    intro s s' hs hst
    refine stays_single ?_ hst
    intro t t' ht hstep
    have hu := step_store (by rw [ht]; exact hc) hstep
    simp only [Config.next.injEq] at hu
    subst hu
    rw [ht]
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rw [hstays s s' hs hsty]
    exact rsp_window_of_agree hL hag
  case stores =>
    intro s hs hag s' hsty c hstep j hj bn hbn
    have heq := hstays s s' hs hsty; subst heq
    rw [hs, hc] at hj
    obtain rfl : j = _ := by simpa using hj.symm
    simp only [stores_store, List.mem_singleton] at hbn
    subst hbn
    exact frame_slot_store (j := 144) hL hag rbp_val (by norm_num)
      (by rw [groupBase_val]; norm_num) (by norm_num)
  · intro s hs hag s' hsty c hstep j hj bn hbn
    have heq := hstays s s' hs hsty; subst heq
    rw [hs, hc] at hj
    obtain rfl : j = _ := by simpa using hj.symm
    simp only [accesses_store, List.mem_singleton] at hbn
    subst hbn
    exact frame_access hL hag rbp_val (by rw [groupBase_val]; norm_num)
      (by rw [groupBase_val]; norm_num)
  · intro s hs hag s' hsty s'' hstep hout
    have heq := hstays s s' hs hsty; subst heq
    have hu := step_store (by rw [hs]; exact hc) hstep
    simp only [Config.next.injEq] at hu
    subst hu
    refine Or.inl ⟨by rw [hs], ?_⟩
    have haddr := addr_groupBase (a := pre) hag
    refine ⟨fun r hr => hag.regs r hr, hag.rsp, hag.depth, hag.rbp, ?_, ?_⟩
    · show RoMem P (store (8#u8).val s'.mem _ (storeVal (8#u8).val (s'.regs src.val)))
      rw [show (8#u8 : Std.U8).val = 8 from rfl, storeVal_eight, haddr,
        show (144#64 : Word) = BitVec.ofNat 64 144 from rfl]
      exact romem_store64_slot hL hag.ro (by norm_num) _
    · show TagOk P (tagAt pre src.val)
        (load64 (store (8#u8).val s'.mem _ (storeVal (8#u8).val (s'.regs src.val)))
          (P.rbp0 - 144#64))
      rw [show (8#u8 : Std.U8).val = 8 from rfl, storeVal_eight, haddr]
      rw [show store 8 s'.mem (P.rbp0 - 144#64) (s'.regs src.val)
        = store64 s'.mem (P.rbp0 - 144#64) (s'.regs src.val) from rfl, load64_store64_same]
      exact agree_regs_any hag src.val
  · intro s hs hag s' hsty s'' hstep
    have heq := hstays s s' hs hsty; subst heq
    have hr := (step_returned_ret hstep).1
    rw [hs, hc] at hr
    simp at hr

@[simp] theorem loadExt_eight (m : Mem) (a : Word) : loadExt 8 false m a = load64 m a :=
  BitVec.setWidth_eq _

theorem live_groupBaseLoad {cfg : x64_ir.Cfg} {dst : Std.U8} {index : Usize} {pcv : Std.U32}
    {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg (.GroupBaseLoad dst) index pcv pre = ok (.Ok (), post)) :
    ∃ st1, x64_check.write pre dst index pcv = ok (.Ok (), st1) ∧
      x64_check.set_tag st1 dst st1.group = ok post := by
  unfold x64_check.live_step at h
  rw [ha] at h
  simp only [if_true] at h
  cases hwr : x64_check.write pre dst index pcv with
  | ok rst =>
    obtain ⟨r, st1⟩ := rst
    rw [hwr] at h
    simp only [bind_tc_ok] at h
    cases r with
    | Ok u =>
      cases u
      refine ⟨st1, rfl, ?_⟩
      replace h : (do let st2 ← x64_check.set_tag st1 dst st1.group
                      ok ((core.result.Result.Ok () : core.result.Result Unit x64_check.Unsafe),
                        st2)) = ok (.Ok (), post) := h
      cases hs : x64_check.set_tag st1 dst st1.group with
      | ok st2 => rw [hs] at h; simp only [bind_tc_ok, ok.injEq, Prod.mk.injEq] at h; rw [h.2]
      | fail e => rw [hs] at h; simp at h
      | div => rw [hs] at h; simp at h
    | Err u =>
      replace h : (do
          let r1 ←
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
              Unit (core.convert.FromSame x64_check.Unsafe) (core.result.Result.Err u)
          ok (r1, st1)) = ok (.Ok (), post) := h
      simp [core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual]
        at h
  | fail e => rw [hwr] at h; simp at h
  | div => rw [hwr] at h; simp at h

theorem macroOk_groupBaseLoad {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {cfg : x64_ir.Cfg} {pre post : x64_check.State} {dst : Std.U8} {index : Usize}
    {pcv : Std.U32} (hL : Layout P) (ha : pre.alive = true)
    (hc : code[p]? = some (.Load 8#u8 false x64_ir.RBP dst x64_ir.frame.GROUP_BASE_OFFSET))
    (h : x64_check.live_step cfg (.GroupBaseLoad dst) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  obtain ⟨st1, hw, hset⟩ := live_groupBaseLoad ha h
  obtain ⟨hn4, hn5, hn15, hlt, hd1, hg1, -, ht1⟩ := write_ok hw
  obtain ⟨hd2, hg2, -, ht2⟩ := set_tag_eq hlt hset
  have hstays : ∀ s s' : State, s.pc = p → Stays P code (Range p (p + 1)) s s' → s' = s := by
    intro s s' hs hst
    refine stays_single ?_ hst
    intro t t' ht hstep
    rcases step_load (by rw [ht]; exact hc) hstep with ⟨-, hu⟩ | ⟨hbad, -, -⟩
    · simp only [Config.next.injEq] at hu
      subst hu
      simp [wReg, ht]
    · simp at hbad
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rw [hstays s s' hs hsty]
    exact rsp_window_of_agree hL hag
  case stores =>
    refine macroOk_no_stores (fun u jj hin hjj => ?_)
    have hu : u.pc = p := by simp only [Range] at hin; omega
    rw [hu, hc] at hjj
    obtain rfl : jj = _ := by simpa using hjj.symm
    rfl
  · intro s hs hag s' hsty c hstep j hj bn hbn
    have heq := hstays s s' hs hsty; subst heq
    rw [hs, hc] at hj
    obtain rfl : j = _ := by simpa using hj.symm
    simp only [accesses_load] at hbn
    rw [if_neg (by simp)] at hbn
    simp only [List.mem_singleton] at hbn
    subst hbn
    exact frame_access hL hag rbp_val (by rw [groupBase_val]; norm_num)
      (by rw [groupBase_val]; norm_num)
  · intro s hs hag s' hsty s'' hstep hout
    have heq := hstays s s' hs hsty; subst heq
    rcases step_load (by rw [hs]; exact hc) hstep with ⟨-, hu⟩ | ⟨hbad, -, -⟩
    · simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ⟨by simp [wReg, hs], ?_⟩
      have haddr := addr_groupBase (a := pre) hag
      refine ⟨fun r hr => ?_, ?_, ?_, ?_, hag.ro, ?_⟩
      · rw [ht2 r]
        by_cases hcd : r = dst.val
        · subst hcd
          rw [if_pos rfl, hg1]
          show TagOk P pre.group (Function.update s'.regs dst.val _ dst.val)
          rw [Function.update_self]
          simp only [show (8#u8 : Std.U8).val = 8 from rfl, loadExt_eight, haddr]
          exact hag.group
        · rw [if_neg hcd, ht1 r, if_neg hcd]
          show TagOk P (tagAt pre r) (Function.update s'.regs dst.val _ r)
          rw [Function.update_of_ne hcd]
          exact hag.regs r hr
      · show Function.update s'.regs dst.val _ RSP = _
        rw [Function.update_of_ne (by simpa [RSP] using Ne.symm hn4), hd2, hd1]
        exact hag.rsp
      · rw [hd2, hd1]; exact hag.depth
      · show Function.update s'.regs dst.val _ RBP = _
        rw [Function.update_of_ne (by simpa [RBP] using Ne.symm hn5)]
        exact hag.rbp
      · rw [hg2, hg1]; exact hag.group
    · simp at hbad
  · intro s hs hag s' hsty s'' hstep
    have heq := hstays s s' hs hsty; subst heq
    have hr := (step_returned_ret hstep).1
    rw [hs, hc] at hr
    simp at hr

/-! ## `GuestFp`

`mov dst, r15 ; sub dst, [rbp - 40]`: two primitives, the second reading the
stack delta out of the frame scratch. -/

theorem rsp_val : (x64_ir.RSP).val = RSP := by rw [x64_ir.RSP]; rfl

theorem macroOk_guestFp {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {dst : Std.U8} {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (ha : pre.alive = true)
    (hc0 : code[p]? = some (.Alu true x64_ir.AluRR.Mov x64_ir.R15 dst))
    (hc1 : code[p + 1]? = some (.AluRM x64_ir.AluRM.Sub dst x64_ir.RBP
      x64_ir.frame.FRAME_DELTA_OFFSET))
    (h : x64_check.live_step cfg (.GuestFp dst) index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 2) pre post [] := by
  have hw := live_guestFp ha h
  obtain ⟨hn4, hn5, hn15, hlt, hd, hg, -, ht⟩ := write_ok hw
  have htop : tagAt post dst.val = x64_check.Tag.Top := by rw [ht]; simp
  set I : State → Prop :=
    fun t => (t.pc = p ∧ Agree P pre t) ∨ (t.pc = p + 1 ∧ Agree P post t) with hI
  have hinv : ∀ s s' : State, s.pc = p → Agree P pre s →
      Stays P code (Range p (p + 2)) s s' → I s' := by
    intro s s' hs hag hsty
    refine stays_invariant (I := I) (Or.inl ⟨hs, hag⟩) ?_ hsty
    rintro t t' (⟨ht, hat⟩ | ⟨ht, hat⟩) hin hstep hin'
    · have hu := step_alu (by rw [ht]; exact hc0) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inr ⟨by simp [aluRRStep, wReg, ht], ?_⟩
      exact agree_write hat hw (fun r' hr' => by
        simp [aluRRStep, wReg, Function.update_of_ne hr']) rfl
    · have hu := step_aluRM (by rw [ht]; exact hc1) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      exfalso
      simp only [Range, aluRMStep_pc, ht] at hin'
      omega
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rcases hinv s s' hs hag hsty with ⟨-, hat⟩ | ⟨-, hat⟩ <;>
      exact rsp_window_of_agree hL hat
  case stores =>
    refine macroOk_no_stores (fun u jj hin hjj => ?_)
    have hu : u.pc = p ∨ u.pc = p + 1 := by simp only [Range] at hin; omega
    rcases hu with hu | hu
    · rw [hu, hc0] at hjj
      obtain rfl : jj = _ := by simpa using hjj.symm
      rfl
    · rw [hu, hc1] at hjj
      obtain rfl : jj = _ := by simpa using hjj.symm
      rfl
  · intro s hs hag s' hsty c hstep j hj bn hbn
    rcases hinv s s' hs hag hsty with ⟨ht, hat⟩ | ⟨ht, hat⟩
    · rw [ht, hc0] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp at hbn
    · rw [ht, hc1] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp only [accesses_aluRM, List.mem_singleton] at hbn
      subst hbn
      exact frame_access hL hat rbp_val (by rw [frameDelta_val]; norm_num)
        (by rw [frameDelta_val]; norm_num)
  · intro s hs hag s' hsty s'' hstep hout
    rcases hinv s s' hs hag hsty with ⟨ht, hat⟩ | ⟨ht, hat⟩
    · exfalso
      have hu := step_alu (by rw [ht]; exact hc0) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      exact hout (by simp only [Range, aluRRStep_pc, ht]; omega)
    · have hu := step_aluRM (by rw [ht]; exact hc1) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ⟨by simp [ht], ?_⟩
      exact agree_write_top hat htop (by simpa [RSP] using hn4) (by simpa [RBP] using hn5)
        (fun r' hr' => aluRMStep_regs_ne _ _ _ _ _ hr') rfl
  · intro s hs hag s' hsty s'' hstep
    have hr := (step_returned_ret hstep).1
    rcases hinv s s' hs hag hsty with ⟨ht, -⟩ | ⟨ht, -⟩
    · rw [ht, hc0] at hr; simp at hr
    · rw [ht, hc1] at hr; simp at hr

/-! ## Labels and branches

A `PcLabel` emits one label primitive and nothing else. A label nothing
branches to is a position; a label a branch can land on is an entry, and the
checker's state there is `enterState` whichever path reached it. A branch
emits one `jcc` or `jmp` and lists its target as an exit, entered in
`enterState` too. -/

theorem label_notTarget {labels : x64_check.Labels} {slot : Std.U32} {index : Usize}
    {pcv : Std.U32} {pre post : x64_check.State}
    (hnt : x64_check.is_target labels slot = ok false)
    (h : x64_check.label_step labels slot index pcv pre = ok (.Ok (), post)) : post = pre := by
  unfold x64_check.label_step at h
  rw [hnt] at h
  simp only [bind_tc_ok, Bool.false_eq_true, if_false, ok.injEq, Prod.mk.injEq] at h
  exact h.2.symm

theorem label_target {labels : x64_check.Labels} {slot : Std.U32} {index : Usize}
    {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (htg : x64_check.is_target labels slot = ok true)
    (h : x64_check.label_step labels slot index pcv pre = ok (.Ok (), post)) :
    pre.depth.val = 1 ∧ tagAt pre 15 = x64_check.Tag.Fp ∧ post = enterState := by
  unfold x64_check.label_step at h
  rw [htg] at h
  simp only [bind_tc_ok, if_true, ha] at h
  split at h
  · simp [x64_check.reject] at h
  · rename_i hdep
    have hd : pre.depth.val = 1 := by simpa using hdep
    cases hfi : x64_check.frame_intact pre with
    | ok b =>
      rw [hfi] at h
      simp only [bind_tc_ok] at h
      cases b
      · simp [x64_check.reject] at h
      · cases he : x64_check.enter pre with
        | ok st1 =>
          rw [he] at h
          simp only [bind_tc_ok, if_true, ok.injEq, Prod.mk.injEq] at h
          exact ⟨hd, frame_intact_eq hfi, by rw [← h.2, enter_eq he]⟩
        | fail e => rw [he] at h; simp at h
        | div => rw [he] at h; simp at h
    | fail e => rw [hfi] at h; simp at h
    | div => rw [hfi] at h; simp at h

/-- A label nothing branches to. -/
theorem macroOk_pcLabel_plain {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {labels : x64_check.Labels} {slot : Std.U32} {index : Usize} {pcv : Std.U32}
    {pre post : x64_check.State} (hL : Layout P) (hc : code[p]? = some (.PcLabel slot))
    (hnt : x64_check.is_target labels slot = ok false)
    (h : x64_check.label_step labels slot index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  rw [label_notTarget hnt h]
  exact macroOk_regOnly_id (i := .PcLabel slot) hL trivial rfl hc

/-- A label a branch can land on: whatever the walk arrived with, the state
after it is `enterState`, and the machine state agrees with it because the
walk arrived at depth one with the frame register intact. -/
theorem macroOk_pcLabel_target {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {labels : x64_check.Labels} {slot : Std.U32} {index : Usize} {pcv : Std.U32}
    {pre post : x64_check.State} (hL : Layout P) (ha : pre.alive = true)
    (hc : code[p]? = some (.PcLabel slot))
    (htg : x64_check.is_target labels slot = ok true)
    (h : x64_check.label_step labels slot index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [] := by
  obtain ⟨hd, hf, rfl⟩ := label_target ha htg h
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rw [stays_regOnly (i := x64_ir.PInsn.PcLabel slot) trivial hc hsty]
    exact rsp_window_of_agree hL hag
  case stores =>
    refine macroOk_no_stores (fun u jj hin hjj => ?_)
    have hu : u.pc = p := by simp only [Range] at hin; omega
    rw [hu, hc] at hjj
    obtain rfl : jj = _ := by simpa using hjj.symm
    rfl
  · intro s hs hag s' hsty c hstep j hj bn hbn
    have heq := stays_regOnly (i := .PcLabel slot) trivial hc hsty; subst heq
    rw [hs, hc] at hj
    obtain rfl : j = _ := by simpa using hj.symm
    rw [accesses_regOnly (i := .PcLabel slot) trivial] at hbn
    simp at hbn
  · intro s hs hag s' hsty s'' hstep hout
    have heq := stays_regOnly (i := .PcLabel slot) trivial hc hsty; subst heq
    obtain ⟨u, hu, hpc, hmem, hregs⟩ :=
      step_regOnly (i := .PcLabel slot) trivial (by rw [hs]; exact hc) hstep
    cases hu
    refine Or.inl ⟨by rw [hpc, hs], ?_⟩
    refine agree_enterState ?_ ?_ ?_ ?_
    · rw [hregs RSP (by simp [writes]), agree_depth_one hag hd]
    · rw [hregs R15 (by simp [writes]), agree_fp hag hf]
    · rw [hregs RBP (by simp [writes])]; exact hag.rbp
    · rw [hmem]; exact hag.ro
  · intro s hs hag s' hsty s'' hstep
    have heq := stays_regOnly (i := .PcLabel slot) trivial hc hsty; subst heq
    have hr := (step_returned_ret hstep).1
    rw [hs, hc] at hr
    simp at hr

/-- The same label reached by a jump, which arrives in `enterState`. -/
theorem macroOk_pcLabel_target_entered {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {labels : x64_check.Labels} {slot : Std.U32} {index : Usize} {pcv : Std.U32}
    {post : x64_check.State} (hL : Layout P) (hc : code[p]? = some (.PcLabel slot))
    (htg : x64_check.is_target labels slot = ok true)
    (h : x64_check.label_step labels slot index pcv enterState = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) enterState post [] :=
  macroOk_pcLabel_target hL (by simp [enterState]) hc htg h

theorem branch_live {labels : x64_check.Labels} {target : x64_ir.Target} {unc : Bool}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.branch_step labels target unc index pcv pre = ok (.Ok (), post)) :
    pre.depth.val = 1 ∧ tagAt pre 15 = x64_check.Tag.Fp ∧
      post = (if unc then { pre with alive := false } else pre) := by
  have key : ∀ lb : Result Bool,
      (do let landable ← lb
          if landable = true then
            (if unc = true then
              ok ((core.result.Result.Ok () : core.result.Result Unit x64_check.Unsafe),
                { pre with alive := false })
             else ok (core.result.Result.Ok (), pre))
          else (do let u ← x64_check.reject index pcv
                   ok (core.result.Result.Err u, pre))) = ok (.Ok (), post) →
      post = (if unc then { pre with alive := false } else pre) := by
    intro lb hlb
    cases hb : lb with
    | ok b2 =>
      rw [hb] at hlb
      simp only [bind_tc_ok] at hlb
      cases b2
      · simp [x64_check.reject] at hlb
      · cases unc <;> simp_all
    | fail e => rw [hb] at hlb; simp at hlb
    | div => rw [hb] at hlb; simp at hlb
  unfold x64_check.branch_step at h
  rw [ha] at h
  simp only [if_true] at h
  split at h
  · simp [x64_check.reject] at h
  · rename_i hdep
    have hd : pre.depth.val = 1 := by simpa using hdep
    cases hfi : x64_check.frame_intact pre with
    | ok b =>
      rw [hfi] at h
      simp only [bind_tc_ok] at h
      cases b
      · simp [x64_check.reject] at h
      · refine ⟨hd, frame_intact_eq hfi, ?_⟩
        simp only [if_true] at h
        cases target with
        | Pc n =>
          simp only [x64_check.target_of, bind_tc_ok] at h
          exact key (if (1#u8 : Std.U8) = 1#u8 then x64_check.is_labelled labels n
            else ok labels.trailer) h
        | Exit =>
          simp only [x64_check.target_of, bind_tc_ok] at h
          exact key (if (2#u8 : Std.U8) = 1#u8 then x64_check.is_labelled labels 0#u32
            else ok labels.trailer) h
    | fail e => rw [hfi] at h; simp at h
    | div => rw [hfi] at h; simp at h

/-- A conditional branch. The target is an exit, entered in `enterState`; the
fallthrough is the next macro, with the state unchanged. `t ≠ p` is the
encoder's own invariant that a label is never the branch that names it, and it
is what keeps the two exits of `leave` apart. -/
theorem macroOk_jcc {P : Params} {code : List x64_ir.PInsn} {p t : Nat}
    {labels : x64_check.Labels} {target : x64_ir.Target} {pt : x64_ir.PTarget}
    {cc : Std.U8} {index : Usize} {pcv : Std.U32} {pre post : x64_check.State}
    (hL : Layout P) (ha : pre.alive = true) (hc : code[p]? = some (.Jcc cc pt))
    (hpos : pos code pt = some t) (hne : t ≠ p)
    (h : x64_check.branch_step labels target false index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [(t, enterState)] := by
  obtain ⟨hd, hf, hp⟩ := branch_live ha h
  simp only [Bool.false_eq_true, if_false] at hp
  subst hp
  have hstays : ∀ s s' : State, s.pc = p → Stays P code (Range p (p + 1)) s s' → s' = s := by
    intro s s' hs hst
    refine stays_leaves ?_ hst
    intro u u' hu hstep
    rcases step_jcc (by rw [hu]; exact hc) hstep with ⟨-, i, hi, hux⟩ | ⟨-, hux⟩ <;>
      · simp only [Config.next.injEq] at hux
        subst hux
        simp only [Range, wNext, hu, not_and, not_lt]
        first
          | (rw [hpos] at hi; simp only [Option.some.injEq] at hi; subst hi; omega)
          | omega
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rw [hstays s s' hs hsty]
    exact rsp_window_of_agree hL hag
  case stores =>
    refine macroOk_no_stores (fun u jj hin hjj => ?_)
    have hu : u.pc = p := by simp only [Range] at hin; omega
    rw [hu, hc] at hjj
    obtain rfl : jj = _ := by simpa using hjj.symm
    rfl
  · intro s hs hag s' hsty c hstep j hj bn hbn
    have heq := hstays s s' hs hsty; subst heq
    rw [hs, hc] at hj
    obtain rfl : j = _ := by simpa using hj.symm
    simp at hbn
  · intro s hs hag s' hsty s'' hstep hout
    have heq := hstays s s' hs hsty; subst heq
    rcases step_jcc (by rw [hs]; exact hc) hstep with ⟨-, i, hi, hux⟩ | ⟨-, hux⟩
    · simp only [Config.next.injEq] at hux
      subst hux
      rw [hpos] at hi
      simp only [Option.some.injEq] at hi
      subst hi
      refine Or.inr ⟨(t, enterState), by simp, rfl, agree_enterState ?_ ?_ ?_ ?_⟩
      · exact agree_depth_one (s := s') hag hd
      · exact agree_fp (s := s') hag hf
      · exact hag.rbp
      · exact hag.ro
    · simp only [Config.next.injEq] at hux
      subst hux
      exact Or.inl ⟨by simp [wNext, hs], agree_same hag (fun r => rfl) rfl⟩
  · intro s hs hag s' hsty s'' hstep
    have heq := hstays s s' hs hsty; subst heq
    have hr := (step_returned_ret hstep).1
    rw [hs, hc] at hr
    simp at hr

/-- An unconditional branch: the target is the only way out. -/
theorem macroOk_jmp {P : Params} {code : List x64_ir.PInsn} {p t : Nat}
    {labels : x64_check.Labels} {target : x64_ir.Target} {pt : x64_ir.PTarget}
    {index : Usize} {pcv : Std.U32} {pre post : x64_check.State}
    (hL : Layout P) (ha : pre.alive = true) (hc : code[p]? = some (.Jmp pt))
    (hpos : pos code pt = some t) (hne : t ≠ p)
    (h : x64_check.branch_step labels target true index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 1) pre post [(t, enterState)] := by
  obtain ⟨hd, hf, hp⟩ := branch_live ha h
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
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rw [hstays s s' hs hsty]
    exact rsp_window_of_agree hL hag
  case stores =>
    refine macroOk_no_stores (fun u jj hin hjj => ?_)
    have hu : u.pc = p := by simp only [Range] at hin; omega
    rw [hu, hc] at hjj
    obtain rfl : jj = _ := by simpa using hjj.symm
    rfl
  · intro s hs hag s' hsty c hstep j hj bn hbn
    have heq := hstays s s' hs hsty; subst heq
    rw [hs, hc] at hj
    obtain rfl : j = _ := by simpa using hj.symm
    simp at hbn
  · intro s hs hag s' hsty s'' hstep hout
    have heq := hstays s s' hs hsty; subst heq
    obtain ⟨i, hi, hux⟩ := step_jmp (by rw [hs]; exact hc) hstep
    simp only [Config.next.injEq] at hux
    subst hux
    rw [hpos] at hi
    simp only [Option.some.injEq] at hi
    subst hi
    refine Or.inr ⟨(t, enterState), by simp, rfl, agree_enterState ?_ ?_ ?_ ?_⟩
    · exact agree_depth_one (s := s') hag hd
    · exact agree_fp (s := s') hag hf
    · exact hag.rbp
    · exact hag.ro
  · intro s hs hag s' hsty s'' hstep
    have heq := hstays s s' hs hsty; subst heq
    have hr := (step_returned_ret hstep).1
    rw [hs, hc] at hr
    simp at hr

/-! ## The prologue and the epilogue

`sub rsp, 8 ; mov qword [rsp], usage` and `add rsp, 8 ; ret`, with a near jump
around the prologue where the previous instruction can fall into it, and the
exit label in front of the trailer's epilogue. These are the two macros that
move `rsp`, so they are where `Agree.rsp` is established and spent. -/

theorem signExtend_eight : (BitVec.signExtend 64 (8#i32 : Std.I32).bv : Word) = 8#64 := by
  decide

theorem aluImm_addRsp (t : State) :
    (aluImmStep true x64_ir.AluRI.Add x64_ir.RSP 8#i32 t).regs RSP = t.regs RSP + 8#64 ∧
      (∀ r, r ≠ RSP → (aluImmStep true x64_ir.AluRI.Add x64_ir.RSP 8#i32 t).regs r = t.regs r) ∧
      (aluImmStep true x64_ir.AluRI.Add x64_ir.RSP 8#i32 t).pc = t.pc + 1 ∧
      (aluImmStep true x64_ir.AluRI.Add x64_ir.RSP 8#i32 t).mem = t.mem := by
  refine ⟨?_, ?_, rfl, rfl⟩
  · simp only [aluImmStep, wRegFlags, if_true, wr, signExtend_eight, rsp_val]
    rw [Function.update_self]
  · intro r hr
    simp only [aluImmStep, wRegFlags, if_true, wr, signExtend_eight, rsp_val]
    rw [Function.update_of_ne hr]

theorem aluImm_subRsp (t : State) :
    (aluImmStep true x64_ir.AluRI.Sub x64_ir.RSP 8#i32 t).regs RSP = t.regs RSP - 8#64 ∧
      (∀ r, r ≠ RSP → (aluImmStep true x64_ir.AluRI.Sub x64_ir.RSP 8#i32 t).regs r = t.regs r) ∧
      (aluImmStep true x64_ir.AluRI.Sub x64_ir.RSP 8#i32 t).pc = t.pc + 1 ∧
      (aluImmStep true x64_ir.AluRI.Sub x64_ir.RSP 8#i32 t).mem = t.mem := by
  refine ⟨?_, ?_, rfl, rfl⟩
  · simp only [aluImmStep, wRegFlags, if_true, wr, signExtend_eight, rsp_val]
    rw [Function.update_self]
  · intro r hr
    simp only [aluImmStep, wRegFlags, if_true, wr, signExtend_eight, rsp_val]
    rw [Function.update_of_ne hr]

theorem live_epilogue {cfg : x64_ir.Cfg} {index : Usize} {pcv : Std.U32}
    {pre post : x64_check.State} (ha : pre.alive = true)
    (h : x64_check.live_step cfg .Epilogue index pcv pre = ok (.Ok (), post)) :
    pre.depth.val = 1 ∧ tagAt pre 15 = x64_check.Tag.Fp ∧
      post = { pre with alive := false } := by
  unfold x64_check.live_step at h
  rw [ha] at h
  simp only [if_true] at h
  split at h
  · simp [x64_check.reject] at h
  · rename_i hdep
    have hd : pre.depth.val = 1 := by simpa using hdep
    cases hfi : x64_check.frame_intact pre with
    | ok b =>
      rw [hfi] at h
      simp only [bind_tc_ok] at h
      cases b
      · simp [x64_check.reject] at h
      · simp only [if_true, ok.injEq, Prod.mk.injEq] at h
        exact ⟨hd, frame_intact_eq hfi, h.2.symm⟩
    | fail e => rw [hfi] at h; simp at h
    | div => rw [hfi] at h; simp at h

/-- The epilogue: `add rsp, 8 ; ret`. Nothing leaves the region except by
returning, and it returns with the stack balanced and the three registers the
caller expects still holding their entry values. -/
theorem macroOk_epilogue {P : Params} {code : List x64_ir.PInsn} {p : Nat} {cfg : x64_ir.Cfg}
    {pre post : x64_check.State} {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (ha : pre.alive = true)
    (hc0 : code[p]? = some (.AluImm true x64_ir.AluRI.Add x64_ir.RSP 8#i32))
    (hc1 : code[p + 1]? = some .Ret)
    (h : x64_check.live_step cfg .Epilogue index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 2) pre post [] := by
  obtain ⟨hd, hf, -⟩ := live_epilogue ha h
  have htop : AccessOk P P.rsp0 8 := by
    have := stack_slot_ok (P := P) (d := 0) hL (by norm_num)
    simpa using this
  set I : State → Prop := fun t =>
    (t.pc = p ∧ Agree P pre t) ∨
      (t.pc = p + 1 ∧ t.regs RSP = P.rsp0 ∧ t.regs RBP = P.rbp0 ∧ t.regs R15 = P.fp0) with hI
  have hinv : ∀ s s' : State, s.pc = p → Agree P pre s →
      Stays P code (Range p (p + 2)) s s' → I s' := by
    intro s s' hs hag hsty
    refine stays_invariant (I := I) (Or.inl ⟨hs, hag⟩) ?_ hsty
    rintro t t' (⟨ht, hat⟩ | ⟨ht, h1, h2, h3⟩) hin hstep hin'
    · have hu := step_aluImm (by rw [ht]; exact hc0) hstep
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
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rcases hinv s s' hs hag hsty with ⟨-, hat⟩ | ⟨-, h1, -, -⟩
    · exact rsp_window_of_agree hL hat
    · exact rsp_window_of_rsp0 h1
  case stores =>
    refine macroOk_no_stores (fun u jj hin hjj => ?_)
    have hu : u.pc = p ∨ u.pc = p + 1 := by simp only [Range] at hin; omega
    rcases hu with hu | hu
    · rw [hu, hc0] at hjj
      obtain rfl : jj = _ := by simpa using hjj.symm
      rfl
    · rw [hu, hc1] at hjj
      obtain rfl : jj = _ := by simpa using hjj.symm
      rfl
  · intro s hs hag s' hsty c hstep j hj bn hbn
    rcases hinv s s' hs hag hsty with ⟨ht, hat⟩ | ⟨ht, h1, -, -⟩
    · rw [ht, hc0] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp at hbn
    · rw [ht, hc1] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp only [accesses_ret, List.mem_singleton] at hbn
      subst hbn
      rw [h1]
      exact htop
  · intro s hs hag s' hsty s'' hstep hout
    exfalso
    rcases hinv s s' hs hag hsty with ⟨ht, hat⟩ | ⟨ht, h1, -, -⟩
    · have hu := step_aluImm (by rw [ht]; exact hc0) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      exact hout (by simp only [Range, aluImmStep_pc, ht]; omega)
    · rcases step_ret (by rw [ht]; exact hc1) hstep with ⟨-, hbad⟩ | ⟨hne, -⟩ | ⟨hne, -⟩
      · simp at hbad
      · exact hne h1
      · exact hne h1
  · intro s hs hag s' hsty s'' hstep
    rcases hinv s s' hs hag hsty with ⟨ht, hat⟩ | ⟨ht, h1, h2, h3⟩
    · exfalso
      have hr := (step_returned_ret hstep).1
      rw [ht, hc0] at hr
      simp at hr
    · obtain ⟨-, -, rfl⟩ := step_returned_ret hstep
      exact ⟨by rw [popRsp_rsp, h1], by simp [popRsp, RBP, RSP, h2], by
        simp [popRsp, R15, RSP, h3]⟩

/-- The trailer's epilogue, which carries the exit label every branch to
`Target::Exit` lands on. -/
theorem macroOk_epilogue_exit {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {cfg : x64_ir.Cfg} {pre post : x64_check.State} {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (ha : pre.alive = true)
    (hcE : code[p]? = some .ExitLabel)
    (hc0 : code[p + 1]? = some (.AluImm true x64_ir.AluRI.Add x64_ir.RSP 8#i32))
    (hc1 : code[p + 2]? = some .Ret)
    (h : x64_check.live_step cfg .Epilogue index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 3) pre post [] := by
  obtain ⟨hd, hf, -⟩ := live_epilogue ha h
  have htop : AccessOk P P.rsp0 8 := by
    have := stack_slot_ok (P := P) (d := 0) hL (by norm_num)
    simpa using this
  set I : State → Prop := fun t =>
    ((t.pc = p ∨ t.pc = p + 1) ∧ Agree P pre t) ∨
      (t.pc = p + 2 ∧ t.regs RSP = P.rsp0 ∧ t.regs RBP = P.rbp0 ∧ t.regs R15 = P.fp0) with hI
  have hinv : ∀ s s' : State, s.pc = p → Agree P pre s →
      Stays P code (Range p (p + 3)) s s' → I s' := by
    intro s s' hs hag hsty
    refine stays_invariant (I := I) (Or.inl ⟨Or.inl hs, hag⟩) ?_ hsty
    rintro t t' (⟨ht | ht, hat⟩ | ⟨ht, h1, h2, h3⟩) hin hstep hin'
    · obtain ⟨u, hu, hpc, hmem, hregs⟩ :=
        step_regOnly (i := .ExitLabel) trivial (by rw [ht]; exact hcE) hstep
      cases hu
      exact Or.inl ⟨Or.inr (by rw [hpc, ht]),
        agree_same hat (fun r => hregs r (by simp [writes])) hmem⟩
    · have hu := step_aluImm (by rw [ht]; exact hc0) hstep
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
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rcases hinv s s' hs hag hsty with ⟨-, hat⟩ | ⟨-, h1, -, -⟩
    · exact rsp_window_of_agree hL hat
    · exact rsp_window_of_rsp0 h1
  case stores =>
    refine macroOk_no_stores (fun u jj hin hjj => ?_)
    have hu : u.pc = p ∨ u.pc = p + 1 ∨ u.pc = p + 2 := by simp only [Range] at hin; omega
    rcases hu with hu | hu | hu
    · rw [hu, hcE] at hjj
      obtain rfl : jj = _ := by simpa using hjj.symm
      rfl
    · rw [hu, hc0] at hjj
      obtain rfl : jj = _ := by simpa using hjj.symm
      rfl
    · rw [hu, hc1] at hjj
      obtain rfl : jj = _ := by simpa using hjj.symm
      rfl
  · intro s hs hag s' hsty c hstep j hj bn hbn
    rcases hinv s s' hs hag hsty with ⟨ht | ht, hat⟩ | ⟨ht, h1, -, -⟩
    · rw [ht, hcE] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      rw [accesses_regOnly (i := .ExitLabel) trivial] at hbn
      simp at hbn
    · rw [ht, hc0] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp at hbn
    · rw [ht, hc1] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp only [accesses_ret, List.mem_singleton] at hbn
      subst hbn
      rw [h1]
      exact htop
  · intro s hs hag s' hsty s'' hstep hout
    exfalso
    rcases hinv s s' hs hag hsty with ⟨ht | ht, hat⟩ | ⟨ht, h1, -, -⟩
    · obtain ⟨u, hu, hpc, -, -⟩ :=
        step_regOnly (i := .ExitLabel) trivial (by rw [ht]; exact hcE) hstep
      cases hu
      exact hout (by simp only [Range, hpc, ht]; omega)
    · have hu := step_aluImm (by rw [ht]; exact hc0) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      exact hout (by simp only [Range, aluImmStep_pc, ht]; omega)
    · rcases step_ret (by rw [ht]; exact hc1) hstep with ⟨-, hbad⟩ | ⟨hne, -⟩ | ⟨hne, -⟩
      · simp at hbad
      · exact hne h1
      · exact hne h1
  · intro s hs hag s' hsty s'' hstep
    rcases hinv s s' hs hag hsty with ⟨ht | ht, hat⟩ | ⟨ht, h1, h2, h3⟩
    · exfalso
      have hr := (step_returned_ret hstep).1
      rw [ht, hcE] at hr
      simp at hr
    · exfalso
      have hr := (step_returned_ret hstep).1
      rw [ht, hc0] at hr
      simp at hr
    · obtain ⟨-, -, rfl⟩ := step_returned_ret hstep
      exact ⟨by rw [popRsp_rsp, h1], by simp [popRsp, RBP, RSP, h2], by
        simp [popRsp, R15, RSP, h3]⟩

theorem agree_depth_zero {P : Params} {a : x64_check.State} {s : State} (h : Agree P a s)
    (hd : a.depth.val = 0) : s.regs RSP = P.rsp0 := by
  rw [h.rsp, hd]; simp

theorem prologue_plain {index : Usize} {pcv : Std.U32} {pre post : x64_check.State}
    (ha : pre.alive = true)
    (h : x64_check.prologue_step false index pcv pre = ok (.Ok (), post)) :
    pre.depth.val = 0 ∧ post = enterState := by
  unfold x64_check.prologue_step x64_check.prologue_ok at h
  rw [ha] at h
  simp only [if_true, Bool.false_eq_true, if_false] at h
  split at h
  · rename_i hdep
    simp only [bind_tc_ok, if_true] at h
    cases he : x64_check.enter pre with
    | ok st1 =>
      rw [he] at h
      simp only [bind_tc_ok, ok.injEq, Prod.mk.injEq] at h
      exact ⟨by rw [hdep]; rfl, by rw [← h.2, enter_eq he]⟩
    | fail e => rw [he] at h; simp at h
    | div => rw [he] at h; simp at h
  · simp [x64_check.reject] at h

theorem prologue_skip {index : Usize} {pcv : Std.U32} {pre post : x64_check.State}
    (ha : pre.alive = true)
    (h : x64_check.prologue_step true index pcv pre = ok (.Ok (), post)) :
    pre.depth.val = 1 ∧ tagAt pre 15 = x64_check.Tag.Fp ∧ post = enterState := by
  unfold x64_check.prologue_step x64_check.prologue_ok at h
  rw [ha] at h
  simp only [if_true] at h
  split at h
  · simp [x64_check.reject] at h
  · rename_i hdep
    have hd : pre.depth.val = 1 := by simpa using hdep
    cases hfi : x64_check.frame_intact pre with
    | ok b =>
      rw [hfi] at h
      simp only [bind_tc_ok] at h
      cases b
      · simp [x64_check.reject] at h
      · simp only [if_true] at h
        cases he : x64_check.enter pre with
        | ok st1 =>
          rw [he] at h
          simp only [bind_tc_ok, ok.injEq, Prod.mk.injEq] at h
          exact ⟨hd, frame_intact_eq hfi, by rw [← h.2, enter_eq he]⟩
        | fail e => rw [he] at h; simp at h
        | div => rw [he] at h; simp at h
    | fail e => rw [hfi] at h; simp at h
    | div => rw [hfi] at h; simp at h

theorem rsp0_slot {P : Params} : P.rsp0 - 8#64 = P.rsp0 - BitVec.ofNat 64 (8 * 1) := by
  norm_num

/-- The plain prologue, entered at depth zero: `sub rsp, 8 ; mov qword [rsp],
usage`. `tagAt pre 15 = Fp` is what depth zero means — the walk is still at
its entry state — and the glue supplies it. -/
theorem macroOk_prologue {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {pre post : x64_check.State} {imm : Std.U32} {index : Usize} {pcv : Std.U32}
    (hL : Layout P) (ha : pre.alive = true) (hfp : tagAt pre 15 = x64_check.Tag.Fp)
    (hc0 : code[p]? = some (.AluImm true x64_ir.AluRI.Sub x64_ir.RSP 8#i32))
    (hc1 : code[p + 1]? = some (.StoreRspImm imm))
    (h : x64_check.prologue_step false index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 2) pre post [] := by
  obtain ⟨hd, rfl⟩ := prologue_plain ha h
  set I : State → Prop := fun t =>
    (t.pc = p ∧ Agree P pre t) ∨
      (t.pc = p + 1 ∧ t.regs RSP = P.rsp0 - 8#64 ∧ t.regs RBP = P.rbp0 ∧
        t.regs R15 = P.fp0 ∧ RoMem P t.mem) with hI
  have hinv : ∀ s s' : State, s.pc = p → Agree P pre s →
      Stays P code (Range p (p + 2)) s s' → I s' := by
    intro s s' hs hag hsty
    refine stays_invariant (I := I) (Or.inl ⟨hs, hag⟩) ?_ hsty
    rintro t t' (⟨ht, hat⟩ | ⟨ht, h1, h2, h3, h4⟩) hin hstep hin'
    · have hu := step_aluImm (by rw [ht]; exact hc0) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      obtain ⟨e1, e2, e3, e4⟩ := aluImm_subRsp t
      refine Or.inr ⟨by rw [e3, ht], ?_, ?_, ?_, ?_⟩
      · rw [e1, agree_depth_zero hat hd]
      · rw [e2 RBP (by simp [RBP, RSP])]; exact hat.rbp
      · rw [e2 R15 (by simp [R15, RSP])]; exact agree_fp hat hfp
      · rw [e4]; exact hat.ro
    · exfalso
      have hu := step_storeRspImm (by rw [ht]; exact hc1) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      simp only [Range, ht] at hin'
      omega
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    rcases hinv s s' hs hag hsty with ⟨-, hat⟩ | ⟨-, h1, -, -, -⟩
    · exact rsp_window_of_agree hL hat
    · exact rsp_window_of_depth (d := 1) hL (by rw [h1, rsp0_slot]) (by norm_num)
  case stores =>
    intro s hs hag s' hsty c hstep j hj bn hbn
    rcases hinv s s' hs hag hsty with ⟨ht, hat⟩ | ⟨ht, h1, -, -, -⟩
    · rw [ht, hc0] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp at hbn
    · rw [ht, hc1] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp only [stores_storeRspImm, List.mem_singleton] at hbn
      subst hbn
      rw [h1, rsp0_slot]
      exact storeOk_stack hL (by norm_num) (by norm_num)
  · intro s hs hag s' hsty c hstep j hj bn hbn
    rcases hinv s s' hs hag hsty with ⟨ht, hat⟩ | ⟨ht, h1, -, -, -⟩
    · rw [ht, hc0] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp at hbn
    · rw [ht, hc1] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp only [accesses_storeRspImm, List.mem_singleton] at hbn
      subst hbn
      rw [h1, rsp0_slot]
      exact stack_slot_ok hL (by norm_num)
  · intro s hs hag s' hsty s'' hstep hout
    rcases hinv s s' hs hag hsty with ⟨ht, hat⟩ | ⟨ht, h1, h2, h3, h4⟩
    · exfalso
      have hu := step_aluImm (by rw [ht]; exact hc0) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      exact hout (by simp only [Range, aluImmStep_pc, ht]; omega)
    · have hu := step_storeRspImm (by rw [ht]; exact hc1) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      refine Or.inl ⟨by simp [ht], agree_enterState ?_ ?_ ?_ ?_⟩
      · exact h1
      · exact h3
      · exact h2
      · show RoMem P (store64 s'.mem (s'.regs RSP) _)
        rw [h1, rsp0_slot]
        exact romem_store64_stack hL h4 (by norm_num) _
  · intro s hs hag s' hsty s'' hstep
    exfalso
    have hr := (step_returned_ret hstep).1
    rcases hinv s s' hs hag hsty with ⟨ht, -⟩ | ⟨ht, -, -, -, -⟩
    · rw [ht, hc0] at hr; simp at hr
    · rw [ht, hc1] at hr; simp at hr

/-- The skippable prologue, fallen into at depth one: a near jump over the
push, which the previous instruction already made. -/
theorem macroOk_prologue_skip {P : Params} {code : List x64_ir.PInsn} {p : Nat}
    {pre post : x64_check.State} {imm : Std.U32} {l : Std.U32} {index : Usize}
    {pcv : Std.U32} (hL : Layout P) (ha : pre.alive = true)
    (hc0 : code[p]? = some (.JmpNear (.Local l)))
    (_hc1 : code[p + 1]? = some (.AluImm true x64_ir.AluRI.Sub x64_ir.RSP 8#i32))
    (_hc2 : code[p + 2]? = some (.StoreRspImm imm))
    (hc3 : code[p + 3]? = some (.Local l))
    (hpos : pos code (.Local l) = some (p + 3))
    (h : x64_check.prologue_step true index pcv pre = ok (.Ok (), post)) :
    MacroOk P code p (p + 4) pre post [] := by
  obtain ⟨hd, hfp, rfl⟩ := prologue_skip ha h
  set I : State → Prop := fun t =>
    (t.pc = p ∨ t.pc = p + 3) ∧ t.regs RSP = P.rsp0 - 8#64 ∧ t.regs RBP = P.rbp0 ∧
      t.regs R15 = P.fp0 ∧ RoMem P t.mem with hI
  have hinv : ∀ s s' : State, s.pc = p → Agree P pre s →
      Stays P code (Range p (p + 4)) s s' → I s' := by
    intro s s' hs hag hsty
    refine stays_invariant (I := I)
      ⟨Or.inl hs, agree_depth_one hag hd, hag.rbp, agree_fp hag hfp, hag.ro⟩ ?_ hsty
    rintro t t' ⟨ht | ht, h1, h2, h3, h4⟩ hin hstep hin'
    · obtain ⟨i, hi, hu⟩ := step_jmpNear (by rw [ht]; exact hc0) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      rw [hpos] at hi
      simp only [Option.some.injEq] at hi
      subst hi
      exact ⟨Or.inr rfl, h1, h2, h3, h4⟩
    · exfalso
      obtain ⟨u, hu, hpc, -, -⟩ :=
        step_regOnly (i := .Local l) trivial (by rw [ht]; exact hc3) hstep
      cases hu
      simp only [Range, hpc, ht] at hin'
      omega
  refine ⟨?_, ?_, ?_, ?stores, ?rsp⟩
  case rsp =>
    intro s hs hag s' hsty
    obtain ⟨-, h1, -, -, -⟩ := hinv s s' hs hag hsty
    exact rsp_window_of_depth (d := 1) hL (by rw [h1, rsp0_slot]) (by norm_num)
  case stores =>
    intro s hs hag s' hsty c hstep j hj bn hbn
    obtain ⟨ht | ht, -, -, -, -⟩ := hinv s s' hs hag hsty
    · rw [ht, hc0] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp at hbn
    · rw [ht, hc3] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp [stores] at hbn
  · intro s hs hag s' hsty c hstep j hj bn hbn
    obtain ⟨ht | ht, -, -, -, -⟩ := hinv s s' hs hag hsty
    · rw [ht, hc0] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      simp at hbn
    · rw [ht, hc3] at hj
      obtain rfl : j = _ := by simpa using hj.symm
      rw [accesses_regOnly (i := .Local l) trivial] at hbn
      simp at hbn
  · intro s hs hag s' hsty s'' hstep hout
    obtain ⟨ht | ht, h1, h2, h3, h4⟩ := hinv s s' hs hag hsty
    · exfalso
      obtain ⟨i, hi, hu⟩ := step_jmpNear (by rw [ht]; exact hc0) hstep
      simp only [Config.next.injEq] at hu
      subst hu
      rw [hpos] at hi
      simp only [Option.some.injEq] at hi
      subst hi
      exact hout (by simp only [Range]; omega)
    · obtain ⟨u, hu, hpc, hmem, hregs⟩ :=
        step_regOnly (i := .Local l) trivial (by rw [ht]; exact hc3) hstep
      cases hu
      refine Or.inl ⟨by rw [hpc, ht], agree_enterState ?_ ?_ ?_ ?_⟩
      · rw [hregs RSP (by simp [writes])]; exact h1
      · rw [hregs R15 (by simp [writes])]; exact h3
      · rw [hregs RBP (by simp [writes])]; exact h2
      · rw [hmem]; exact h4
  · intro s hs hag s' hsty s'' hstep
    exfalso
    have hr := (step_returned_ret hstep).1
    obtain ⟨ht | ht, -, -, -, -⟩ := hinv s s' hs hag hsty
    · rw [ht, hc0] at hr; simp at hr
    · rw [ht, hc3] at hr; simp at hr

end X64

end async_ebpf_verified

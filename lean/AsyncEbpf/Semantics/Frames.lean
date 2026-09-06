import AsyncEbpf.Semantics.Soundness
import AsyncEbpf.Stack.Proofs

/-!
# Unchecked frame accesses stay in mapped memory

The JIT emits an `R10`-relative access with no bounds check when the region
analysis' `in_frame_window` admits it. This file shows that such an access
lands in a mapped island of the guarded guest stack, in every execution of
an accepted program, and that the floor test the JIT emits before a local
call is the depth test of the semantics.

`StackParams` says how the machine's parameters come from a `FrameLayout`
in the runtime's native-frame-base mode: `R10` starts at the top of the
highest island (`base + root_frame_offset`), moves one stride per local
call, and the guest stack admits `frame_count - 1` calls.

* `frame_pointer_on_island`: at every reachable state the frame pointer is
  the top of island `frame_count - 1 - depth`;
* `frame_access_mapped`: every access `in_frame_window` admits at such a
  state satisfies `island_access`, the test the runtime's checked path
  applies;
* `floor_iff_depth`: the JIT's floor test (`R10 ≥ base + local_call_floor`)
  passes exactly when the semantics allows another call.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

open Sem

/-! ## Depth -/

/-- The call depth never exceeds `maxDepth`. -/
theorem depth_le {P : Params} {insns : List isa.Insn} {s₀ s : State}
    (hr : Reachable P insns s₀ s) (h0 : s₀.stack.length ≤ P.maxDepth) :
    s.stack.length ≤ P.maxDepth := by
  induction hr with
  | refl => exact h0
  | step _ hstep ih =>
    cases hstep with
    | callLocal _ _ _ hdepth => simp only [List.length_cons]; omega
    | exitReturn _ _ _ _ hstack =>
      have := ih
      rw [hstack] at this
      simp only [List.length_cons] at this
      simp only
      omega
    | _ => exact ih

/-! ## The frame pointer as a number -/

theorem fpAt_toNat (top stride : Word) (k : Nat) (h : k * stride.toNat ≤ top.toNat) :
    (fpAt top stride k).toNat = top.toNat - k * stride.toNat := by
  induction k with
  | zero => simp [fpAt]
  | succ k ih =>
    have hk : k * stride.toNat ≤ top.toNat := by
      rw [Nat.succ_mul] at h
      omega
    simp only [fpAt]
    rw [BitVec.toNat_sub_of_le, ih hk, Nat.succ_mul]
    · omega
    · rw [BitVec.le_def, ih hk]
      rw [Nat.succ_mul] at h
      omega

/-! ## The machine built from a layout -/

/-- The machine parameters the runtime derives from a `FrameLayout` when
`R10` holds native addresses: the entry frame pointer is the top of the
highest island at `base`, calls move it one stride, and the stack admits
`frame_count - 1` of them. -/
structure StackParams (L : stack.FrameLayout) (base : Nat) (P : Params) (top : Word) : Prop where
  stride : P.stride.toNat = L.frame_stride.val
  depth : P.maxDepth + 1 = L.frame_count.val
  top : top.toNat = base + ((L.frame_count.val - 1) * L.frame_stride.val + L.frame_size.val)

theorem StackParams.of_root {L : stack.FrameLayout} {base : Nat} {P : Params} {top : Word}
    {r : Usize} (hroot : stack.root_frame_offset L = ok (some r))
    (hstride : P.stride.toNat = L.frame_stride.val) (hdepth : P.maxDepth + 1 = L.frame_count.val)
    (htop : top.toNat = base + r.val) : StackParams L base P top :=
  ⟨hstride, hdepth, by rw [htop, (root_on_island hroot).2]⟩

/-- At every reachable state, the frame pointer is the top of island
`frame_count - 1 - depth`. -/
theorem frame_pointer_on_island {L : stack.FrameLayout} {base : Nat} {P : Params} {top : Word}
    (hSP : StackParams L base P top) {insns : List isa.Insn} {ctx : Word} {s : State}
    (hr : Reachable P insns (initial ctx top) s) (hinv : Inv insns top P s) :
    base ≤ (s.regs R10).toNat ∧
    OnIsland L (L.frame_count.val - 1 - s.stack.length) ((s.regs R10).toNat - base) := by
  have hdepth : s.stack.length ≤ P.maxDepth := depth_le hr (by simp [Sem.initial])
  have hd := hSP.depth
  obtain ⟨j, hj⟩ : ∃ j, L.frame_count.val - 1 = j + s.stack.length :=
    ⟨L.frame_count.val - 1 - s.stack.length, by omega⟩
  have hfp := hinv.fp
  have hk : s.stack.length * P.stride.toNat ≤ top.toNat := by
    rw [hSP.top, hSP.stride, hj, Nat.add_mul]
    omega
  rw [hfp, fpAt_toNat _ _ _ hk, hSP.stride, hSP.top]
  have hjeq : L.frame_count.val - 1 - s.stack.length = j := by omega
  rw [hjeq, hj, Nat.add_mul]
  refine ⟨by omega, by omega, ?_⟩
  omega

/-- In every execution of an accepted program, every access `in_frame_window`
admits lies in a mapped island: `island_access` accepts it. -/
theorem frame_access_mapped (config : validate.Config) (kh : Slice U32) (insns : Slice isa.Insn)
    (ext : Slice Bool) (hlen : insns.length < 2 ^ 63)
    (hv : validate.validate config kh insns ext = ok (.Ok ()))
    {L : stack.FrameLayout} (hstride : 0 < L.frame_stride.val)
    (hsize : L.frame_size.val ≤ L.frame_stride.val)
    {base : Nat} {P : Params} {ctx top : Word} (hSP : StackParams L base P top)
    {s : State} (hr : Reachable P insns.val (initial ctx top) s)
    {F : U16} (hF : F.val = L.frame_size.val) {off : I16} {w : U8} (hw0 : 0 < w.val)
    (hw : stack.in_frame_window F off w = ok true)
    {a size : Usize} (ha : (a.val : Int) = ((s.regs R10).toNat - base : Nat) + off.val)
    (hsz : size.val = w.val) :
    stack.island_access L a size = ok true :=
  frame_window_mapped hstride hsize
    (frame_pointer_on_island hSP hr (validate_sound config kh insns ext hlen hv P ctx top s hr).1).2
    hF hw0 hw ha hsz

/-- The floor test the JIT emits before a local call, `R10 ≥ base + floor`,
passes exactly when the semantics admits another frame. -/
theorem floor_iff_depth (config : validate.Config) (kh : Slice U32) (insns : Slice isa.Insn)
    (ext : Slice Bool) (hlen : insns.length < 2 ^ 63)
    (hv : validate.validate config kh insns ext = ok (.Ok ()))
    {L : stack.FrameLayout} (hstride : 0 < L.frame_stride.val)
    {base : Nat} {P : Params} {ctx top : Word} (hSP : StackParams L base P top)
    {s : State} (hr : Reachable P insns.val (initial ctx top) s)
    {floor : Usize} (hfloor : stack.local_call_floor L = ok (some floor)) :
    base + floor.val ≤ (s.regs R10).toNat ↔ s.stack.length < P.maxDepth := by
  have hinv := (validate_sound config kh insns ext hlen hv P ctx top s hr).1
  obtain ⟨hge, hisl⟩ := frame_pointer_on_island hSP hr hinv
  have hiff := floor_iff hstride hisl
  have hd := hSP.depth
  rw [local_call_floor_ok hfloor]
  constructor
  · intro h
    have h1 : 1 ≤ L.frame_count.val - 1 - s.stack.length := hiff.mp (by omega)
    omega
  · intro h
    have h1 : L.frame_size.val + L.frame_stride.val ≤ (s.regs R10).toNat - base :=
      hiff.mpr (by omega)
    omega

end async_ebpf_verified

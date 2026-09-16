import AsyncEbpf.X64.Assemble

/-!
# The two-pass assembler, in closed form

`src/verified/x64_encode.rs` assembles a list of primitives in two passes:
`offsets` measures every primitive, `collect_labels` records where each label
landed, and the main loop encodes each primitive with `encode_one` and then
`patch`es the one displacement it carries. This file gives that whole
pipeline a closed form and proves the extracted code matches it.

* `labelLoc` is where a `PTarget` landed — the start offset of the *last*
  primitive carrying that label, since `collect_labels` overwrites `pc`,
  `local`, `exit` and `retpoline` as it walks. `dispatcherLoc` and
  `helperTableLoc` are the *first* `DispatcherSlot` and `HelperTable`, which
  `collect_labels` keeps instead.
* `relocAt code here p` is the byte list a primitive starting at `here`
  contributes: `enc p`, except that a branch or RIP-relative form carries the
  little-endian two's complement of `loc - (site + 4)` (rel32) or
  `loc - (site + 1)` (rel8) at its displacement site. It fails with `missing`
  when the target carries no label and with `range` when a rel8 displacement
  does not fit in a byte. `relocOne code i` is `relocAt` at primitive `i`.
* `relocated code` concatenates those, left to right, stopping at the first
  failure — which is exactly where the assembler's loop stops.

`assemble_spec` is the whole statement: `assemble code out` appends
`relocated code` to `out` and returns `Ok`, or returns the error `relocated`
names. The corollaries spell out what a downstream proof needs:

1. `assemble_ok_length` — the appended region is `totalLen code` bytes long.
2. `assemble_ok_bytes` — primitive `i` sits at
   `out.length + totalLen (code.take i)`, occupies `encLen code[i]` bytes and
   holds `relocOne code i`, which by definition is `enc code[i]` with the four
   (or one) displacement bytes replaced.
3. `assemble_ok_labels` — success implies every branch and RIP-relative form
   names a label the list defines (`reqLoc … = some l → l.isSome`) and every
   rel8 displacement lies in `[-128, 127]`.
4. `assemble_missing_label` — an unlabelled branch makes success impossible,
   so the assembler never silently resolves a branch to a displacement of
   zero the way the fixup pass it replaces did; `assemble_error_missing` is
   the sharper form, naming `MissingLabel` when the first failing site is the
   unlabelled one.

The route there is `pc_label_count_spec` / `local_label_count_spec` (the
tables are wide enough for every number the list labels), `collect_labels_spec`
with the invariant `LabelsInv`, `labelsMatch_of_inv` (`target_loc` answers
exactly `labelLoc`, with `-1` for an unlabelled target), `put32_at` / `put8_at`
(the in-place patch replaces exactly those bytes), `write_rel32_spec` /
`write_rel8_spec` and `patch_spec`.

Everything is proved against the extraction, over `enc`, `encLen`, `totalLen`,
`encode_one_spec`, `size_of_enc` and `offsets_spec` from
`AsyncEbpf/X64/Encode.lean`. `loop_step` and `loop_done` unroll one iteration
of an extracted loop into a plain `Result` equation, which is how each of the
four loops here is driven.

Two side conditions run through the statements. `out.length + totalLen code +
512 ≤ Usize.max` is the Aeneas model of `Vec::push`, threaded exactly as
`Encode.lean` threads it. `∀ j < code.length, lkindNum code[j] < Usize.max`
says no `PcLabel`/`Local` carries `u32::MAX` as its number: `collect_labels`
computes `number as usize + 1`, which Aeneas models as failing on overflow.
It is vacuous on a 64-bit target, where `Usize.max = 2^64 - 1`.
-/

open Aeneas Aeneas.Std Result

set_option maxHeartbeats 4000000
set_option maxRecDepth 100000
set_option Aeneas.Deprecated.progressWarning false

namespace async_ebpf_verified

namespace X64Enc

attribute [local instance] instInhabitedPInsn

/-! ## Little-endian two's complement -/

/-- The four bytes of the little-endian two's complement of `d`. -/
def i32L (d : Int) : List Std.U8 := u32L ⟨BitVec.ofInt 32 d⟩

/-- The one byte of the two's complement of `d`. -/
def i8B (d : Int) : Std.U8 := ⟨BitVec.ofInt 8 d⟩

@[local simp] theorem i32L_len (d : Int) : (i32L d).length = 4 := rfl

@[local simp] theorem u32L_len' (x : Std.U32) : (u32L x).length = 4 := rfl

theorem u32L_zero : u32L 0#u32 = [0#u8, 0#u8, 0#u8, 0#u8] := by
  simp [u32L, lo8]; rfl

/-! ## Where the labels landed -/

/-- `p` labels the slot `k`. -/
def isPcLabel (k : Nat) : x64_ir.PInsn → Bool
  | .PcLabel pc => pc.val == k
  | _ => false

/-- `p` labels the local `k`. -/
def isLocalLabel (k : Nat) : x64_ir.PInsn → Bool
  | .Local n => n.val == k
  | _ => false

/-- `p` is the exit epilogue's label. -/
def isExitLabel : x64_ir.PInsn → Bool
  | .ExitLabel => true
  | _ => false

/-- `p` is the retpoline's label. -/
def isRetpolineLabel : x64_ir.PInsn → Bool
  | .RetpolineLabel => true
  | _ => false

/-- `p` is a dispatcher slot. -/
def isDispatcherSlot : x64_ir.PInsn → Bool
  | .DispatcherSlot _ => true
  | _ => false

/-- `p` is the helper table. -/
def isHelperTable : x64_ir.PInsn → Bool
  | .HelperTable => true
  | _ => false

/-- The start offset of the **last** of the first `m` primitives satisfying `f`. -/
def lastLoc (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) : Nat → Option Nat
  | 0 => none
  | m + 1 => if f code[m]! then some (totalLen (code.take m)) else lastLoc code f m

/-- The start offset of the **first** of the first `m` primitives satisfying `f`. -/
def firstLoc (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) : Nat → Option Nat
  | 0 => none
  | m + 1 =>
    match firstLoc code f m with
    | some x => some x
    | none => if f code[m]! then some (totalLen (code.take m)) else none

/-- Where label `t` landed, as `collect_labels` records it: the start offset of
the last primitive carrying it, or `none` when the list never labels it. -/
def labelLoc (code : List x64_ir.PInsn) (t : x64_ir.PTarget) : Option Nat :=
  match t with
  | .Pc pc => lastLoc code (isPcLabel pc.val) code.length
  | .Exit => lastLoc code isExitLabel code.length
  | .Retpoline => lastLoc code isRetpolineLabel code.length
  | .Local n => lastLoc code (isLocalLabel n.val) code.length

/-- Where the dispatcher slot the RIP-relative load names landed: the **first**
`DispatcherSlot`, which `collect_labels` keeps. -/
def dispatcherLoc (code : List x64_ir.PInsn) : Option Nat :=
  firstLoc code isDispatcherSlot code.length

/-- Where the helper table landed: the **first** `HelperTable`. -/
def helperTableLoc (code : List x64_ir.PInsn) : Option Nat :=
  firstLoc code isHelperTable code.length

/-! ## The relocated bytes -/

/-- Why a displacement could not be written. -/
inductive RelErr where
  /-- The target carries no label. -/
  | missing
  /-- A `rel8` displacement is outside `[-128, 127]`. -/
  | range
deriving DecidableEq, Repr

/-- The four bytes a `rel32` site at `site` reaching `loc` carries. -/
def rel32Bytes (loc : Option Nat) (site : Nat) : Except RelErr (List Std.U8) :=
  match loc with
  | none => .error .missing
  | some l => .ok (i32L ((l : Int) - ((site : Int) + 4)))

/-- The byte a `rel8` site at `site` reaching `loc` carries, or a refusal. -/
def rel8Byte (loc : Option Nat) (site : Nat) : Except RelErr Std.U8 :=
  match loc with
  | none => .error .missing
  | some l =>
    if -128 ≤ (l : Int) - ((site : Int) + 1) ∧ (l : Int) - ((site : Int) + 1) ≤ 127 then
      .ok (i8B ((l : Int) - ((site : Int) + 1)))
    else .error .range

/-- The bytes a primitive starting at `here` contributes: `enc p`, with the
displacement of a branch or RIP-relative form filled in. -/
def relocAt (code : List x64_ir.PInsn) (here : Nat) (p : x64_ir.PInsn) :
    Except RelErr (List Std.U8) :=
  match p with
  | .Jcc cc t => (rel32Bytes (labelLoc code t) (here + 2)).map fun d => 15#u8 :: cc :: d
  | .Jmp t => (rel32Bytes (labelLoc code t) (here + 1)).map fun d => 233#u8 :: d
  | .Call t => (rel32Bytes (labelLoc code t) (here + 1)).map fun d => 232#u8 :: d
  | .JmpNear t => (rel8Byte (labelLoc code t) (here + 1)).map fun b =>
      [235#u8, b, 0#u8, 0#u8, 0#u8]
  | .Jcc8 cc t => (rel8Byte (labelLoc code (.Local t)) (here + 1)).map fun b =>
      [112#u8 ||| (cc &&& 15#u8), b]
  | .Jmp8 t => (rel8Byte (labelLoc code (.Local t)) (here + 1)).map fun b => [235#u8, b]
  | .RipLoadDispatcher dst => (rel32Bytes (dispatcherLoc code) (here + 3)).map fun d =>
      rexByte 1#u8 0#u8 0#u8 0#u8 :: 139#u8 :: modrmB 0#u8 dst 5#u8 :: d
  | .RipLeaHelperTable dst => (rel32Bytes (helperTableLoc code) (here + 3)).map fun d =>
      rexByte 1#u8 (highU dst) 0#u8 0#u8 :: 141#u8 :: modrmB 0#u8 dst 5#u8 :: d
  | p => .ok (enc p)

/-- The bytes primitive `i` contributes. -/
def relocOne (code : List x64_ir.PInsn) (i : Nat) : Except RelErr (List Std.U8) :=
  relocAt code (totalLen (code.take i)) code[i]!

/-- The bytes of the first `m` primitives, stopping at the first failure. -/
def relocAux (code : List x64_ir.PInsn) : Nat → Except RelErr (List Std.U8)
  | 0 => .ok []
  | m + 1 =>
    match relocAux code m, relocOne code m with
    | .ok a, .ok b => .ok (a ++ b)
    | .error e, _ => .error e
    | _, .error e => .error e

/-- **The relocated byte list**: the encoder's concatenation with every
displacement patched, or the first failure. -/
def relocated (code : List x64_ir.PInsn) : Except RelErr (List Std.U8) :=
  relocAux code code.length

/-- The primitives that carry a displacement the assembler patches. -/
def hasDisp : x64_ir.PInsn → Bool
  | .Jcc _ _ | .Jmp _ | .Call _ | .JmpNear _ | .Jcc8 _ _ | .Jmp8 _
  | .RipLoadDispatcher _ | .RipLeaHelperTable _ => true
  | _ => false

/-- Where the label a primitive's displacement names landed, when it has one. -/
def reqLocAt (code : List x64_ir.PInsn) : x64_ir.PInsn → Option (Option Nat)
  | .Jcc _ t | .Jmp t | .Call t | .JmpNear t => some (labelLoc code t)
  | .Jcc8 _ t | .Jmp8 t => some (labelLoc code (.Local t))
  | .RipLoadDispatcher _ => some (dispatcherLoc code)
  | .RipLeaHelperTable _ => some (helperTableLoc code)
  | _ => none

/-- Where the label primitive `i`'s displacement names landed, when it has one. -/
def reqLoc (code : List x64_ir.PInsn) (i : Nat) : Option (Option Nat) :=
  reqLocAt code code[i]!

/-- The `rel8` site of a primitive starting at `here`: the site offset and where
its target landed. -/
def rel8SiteAt (code : List x64_ir.PInsn) (here : Nat) :
    x64_ir.PInsn → Option (Nat × Option Nat)
  | .JmpNear t => some (here + 1, labelLoc code t)
  | .Jcc8 _ t | .Jmp8 t => some (here + 1, labelLoc code (.Local t))
  | _ => none

/-- The `rel8` sites: the site offset and where its target landed. -/
def rel8Site (code : List x64_ir.PInsn) (i : Nat) : Option (Nat × Option Nat) :=
  rel8SiteAt code (totalLen (code.take i)) code[i]!

/-- A primitive with no displacement contributes its encoding unchanged. -/
theorem relocOne_of_not_hasDisp (code : List x64_ir.PInsn) (i : Nat)
    (h : hasDisp code[i]! = false) : relocOne code i = .ok (enc code[i]!) := by
  unfold relocOne relocAt
  cases hp : code[i]! <;> simp_all [hasDisp]

/-- A `map` that produced an `ok` came from an `ok`. -/
theorem except_map_ok {α β : Type} {e : Except RelErr α} {f : α → β} {b : β}
    (h : e.map f = .ok b) : ∃ a, e = .ok a ∧ b = f a := by
  cases e <;> simp_all [Except.map]

/-- A `rel32` site carries four bytes. -/
theorem rel32Bytes_length {loc : Option Nat} {site : Nat} {d : List Std.U8}
    (h : rel32Bytes loc site = .ok d) : d.length = 4 := by
  unfold rel32Bytes at h
  split at h
  · simp at h
  · rw [Except.ok.injEq] at h; subst h; simp

/-- Whatever a primitive contributes is as long as its encoding. -/
theorem relocOne_length (code : List x64_ir.PInsn) (i : Nat) {b : List Std.U8}
    (h : relocOne code i = .ok b) : b.length = encLen code[i]! := by
  unfold relocOne relocAt at h
  cases hp : code[i]! <;> rw [hp] at h <;>
    (try obtain ⟨d, hd, rfl⟩ := except_map_ok h) <;>
    (try have hl := rel32Bytes_length hd) <;>
    simp_all [encLen, enc]

/-! ## Patching a displacement in place -/

@[local simp] theorem vec_set_val {α : Type} (v : alloc.vec.Vec α) (i : Usize) (x : α) :
    (v.set i x).val = v.val.set i.val x := alloc.vec.Vec.set_val_eq v i x

theorem set4 (pre suf : List Std.U8) (a b c d a' b' c' d' : Std.U8) (k : Nat)
    (hk : k = pre.length) :
    ((((pre ++ [a, b, c, d] ++ suf).set k a').set (k + 1) b').set (k + 2) c').set (k + 3) d'
      = pre ++ [a', b', c', d'] ++ suf := by
  subst hk; simp [List.set_append]

theorem set1 (pre suf : List Std.U8) (a a' : Std.U8) (k : Nat) (hk : k = pre.length) :
    (pre ++ a :: suf).set k a' = pre ++ a' :: suf := by
  subst hk; simp [List.set_append]

/-- **`put32` replaces the four bytes at `at`.** -/
theorem put32_at (out : alloc.vec.Vec Std.U8) (pre suf : List Std.U8) (w v : Std.U32)
    (at_ : Usize) (hval : out.val = pre ++ u32L w ++ suf) (hat : at_.val = pre.length) :
    x64_encode.put32 out at_ v ⦃ o => o.val = pre ++ u32L v ++ suf ⦄ := by
  have hlen : out.val.length = pre.length + 4 + suf.length := by rw [hval]; simp; omega
  have hmaxU : out.val.length ≤ Usize.max := out.property
  unfold x64_encode.put32
  simp only [alloc.vec.Vec.index_mut_slice_index, lift, bind_tc_ok]
  step
  rw [if_pos (by scalar_tac)]
  step* <;>
    (try (simp only [*, vec_set_val, List.length_set, alloc.vec.Vec.length,
            List.length_append, u32L_len']; scalar_tac))
  simp only [*, vec_set_val, u32L]
  rw [set4 _ _ _ _ _ _ _ _ _ _ _ rfl]
  simp [lo8, UScalar.cast, bv8_and255, *]

/-- **`put8` replaces the byte at `at`.** -/
theorem put8_at (out : alloc.vec.Vec Std.U8) (pre suf : List Std.U8) (w v : Std.U8)
    (at_ : Usize) (hval : out.val = pre ++ w :: suf) (hat : at_.val = pre.length) :
    x64_encode.put8 out at_ v ⦃ o => o.val = pre ++ v :: suf ⦄ := by
  have hlen : out.val.length = pre.length + 1 + suf.length := by rw [hval]; simp; omega
  unfold x64_encode.put8
  simp only [alloc.vec.Vec.index_mut_slice_index]
  rw [if_pos (by scalar_tac)]
  step
  simp only [index_mut_back_post, vec_set_val, hval]
  rw [set1 _ _ _ _ _ (by omega)]

/-! ## Writing a displacement -/

/-- The value `target_loc` returns: the label's offset, or `-1`. -/
def locVal : Option Nat → Int
  | none => -1
  | some l => (l : Int)

/-- The error code the assembler's loop carries for each refusal. -/
def errCode : RelErr → Std.U32
  | .missing => x64_encode.ERR_MISSING
  | .range => x64_encode.ERR_RANGE

theorem hcast_u32_i64 (x : Std.I64) :
    (IScalar.hcast .U32 x : Std.U32) = ⟨BitVec.ofInt 32 x.val⟩ := rfl

theorem hcast_u8_i64 (x : Std.I64) :
    (IScalar.hcast .U8 x : Std.U8) = ⟨BitVec.ofInt 8 x.val⟩ := rfl

theorem usize_hcast_i64 (x : Usize) (h : x.val < 2 ^ 32) :
    (UScalar.hcast .I64 x : Std.I64).val = (x.val : Int) := by
  have hx : (x.val : Int) < 2 ^ 32 := by exact_mod_cast h
  have h32 : ((2:Int) ^ 32) = 4294967296 := by norm_num
  have h63 : ((2:Int) ^ 63) = 9223372036854775808 := by norm_num
  rw [UScalar.hcast_val_eq]
  show Int.bmod (x.val : Int) (2 ^ 64) = _
  exact Arith.Int.bmod_pow2_eq_of_inBounds' 64 _ (by omega) (by omega) (by omega)

theorem i64_add_ok {x y : Std.I64} (h : IScalar.inBounds .I64 (x.val + y.val)) :
    ∃ z : Std.I64, x + y = ok z ∧ z.val = x.val + y.val := by
  have he := IScalar.add_equiv x y
  cases hxy : x + y with
  | ok z => rw [hxy] at he; exact ⟨z, rfl, he.2.1⟩
  | fail e => rw [hxy] at he; exact absurd h he
  | div => rw [hxy] at he; exact he.elim

theorem i64_sub_ok {x y : Std.I64} (h : IScalar.inBounds .I64 (x.val - y.val)) :
    ∃ z : Std.I64, x - y = ok z ∧ z.val = x.val - y.val := by
  have he := IScalar.sub_equiv x y
  cases hxy : x - y with
  | ok z => rw [hxy] at he; exact ⟨z, rfl, he.2.1⟩
  | fail e => rw [hxy] at he; exact absurd h he
  | div => rw [hxy] at he; exact he.elim

/-- **`write_rel32` writes `loc - (site + 4)`, or refuses when there is no label.** -/
theorem write_rel32_spec (out : alloc.vec.Vec Std.U8) (base site : Usize) (loc : Std.I64)
    (pre suf : List Std.U8) (w : Std.U32) (l : Option Nat)
    (hval : out.val = pre ++ u32L w ++ suf)
    (hat : base.val + site.val = pre.length)
    (hbs : base.val + site.val ≤ Usize.max)
    (hsite : site.val < 2 ^ 32)
    (hl : ∀ x, l = some x → x < 2 ^ 32)
    (hloc : loc.val = locVal l) :
    x64_encode.write_rel32 out base site loc ⦃ r =>
      match rel32Bytes l site.val with
      | .ok d => r.1 = x64_encode.ERR_NONE ∧ r.2.val = pre ++ d ++ suf
      | .error e => r.1 = errCode e ∧ r.2 = out ⦄ := by
  unfold x64_encode.write_rel32
  cases l with
  | none =>
    rw [if_pos (by rw [IScalar.lt_equiv]; simp [hloc, locVal])]
    refine WP.exists_imp_spec ⟨_, rfl, ?_⟩
    simp [rel32Bytes, errCode]
  | some x =>
    have hx : loc.val = (x : Int) := by rw [hloc]; rfl
    have hx32 : x < 2 ^ 32 := hl x rfl
    have hx32' : (x : Int) < 4294967296 := by exact_mod_cast hx32
    have hs32' : (site.val : Int) < 4294967296 := by exact_mod_cast hsite
    have hs0 : (0:Int) ≤ (site.val : Int) := by positivity
    have hx0 : (0:Int) ≤ (x : Int) := by positivity
    rw [if_neg (by rw [IScalar.lt_equiv]; simp [hx])]
    simp only [lift, bind_tc_ok]
    have hsi : (UScalar.hcast .I64 site : Std.I64).val = (site.val : Int) :=
      usize_hcast_i64 site hsite
    obtain ⟨i1, hi1, hi1v⟩ := i64_add_ok (x := (UScalar.hcast .I64 site : Std.I64)) (y := 4#i64)
      (by simp only [hsi]; constructor <;> [skip; skip] <;> simp <;> omega)
    obtain ⟨rel, hrel, hrelv⟩ := i64_sub_ok (x := loc) (y := i1)
      (by simp only [hx, hi1v, hsi]; constructor <;> simp <;> omega)
    obtain ⟨i2, hi2, hi2v⟩ := usize_add_ok (x := base) (y := site) hbs
    simp only [hi1, hrel, hi2, bind_tc_ok]
    have hrelv' : rel.val = (x : Int) - ((site.val : Int) + 4) := by
      rw [hrelv, hx, hi1v, hsi]; simp
    refine WP.spec_bind (put32_at out pre suf w (IScalar.hcast .U32 rel) i2 hval
      (by omega)) ?_
    intro o ho
    simp only [rel32Bytes]
    exact WP.exists_imp_spec ⟨_, rfl, rfl, by rw [ho, i32L, hcast_u32_i64, hrelv']⟩

/-- **`write_rel8` writes `loc - (site + 1)`, or refuses.** -/
theorem write_rel8_spec (out : alloc.vec.Vec Std.U8) (base site : Usize) (loc : Std.I64)
    (pre suf : List Std.U8) (w : Std.U8) (l : Option Nat)
    (hval : out.val = pre ++ w :: suf)
    (hat : base.val + site.val = pre.length)
    (hbs : base.val + site.val ≤ Usize.max)
    (hsite : site.val < 2 ^ 32)
    (hl : ∀ x, l = some x → x < 2 ^ 32)
    (hloc : loc.val = locVal l) :
    x64_encode.write_rel8 out base site loc ⦃ r =>
      match rel8Byte l site.val with
      | .ok b => r.1 = x64_encode.ERR_NONE ∧ r.2.val = pre ++ b :: suf
      | .error e => r.1 = errCode e ∧ r.2 = out ⦄ := by
  unfold x64_encode.write_rel8
  cases l with
  | none =>
    rw [if_pos (by rw [IScalar.lt_equiv]; simp [hloc, locVal])]
    refine WP.exists_imp_spec ⟨_, rfl, ?_⟩
    simp [rel8Byte, errCode]
  | some x =>
    have hx : loc.val = (x : Int) := by rw [hloc]; rfl
    have hx32 : x < 2 ^ 32 := hl x rfl
    have hx32' : (x : Int) < 4294967296 := by exact_mod_cast hx32
    have hs32' : (site.val : Int) < 4294967296 := by exact_mod_cast hsite
    have hs0 : (0:Int) ≤ (site.val : Int) := by positivity
    have hx0 : (0:Int) ≤ (x : Int) := by positivity
    rw [if_neg (by rw [IScalar.lt_equiv]; simp [hx])]
    simp only [lift, bind_tc_ok]
    have hsi : (UScalar.hcast .I64 site : Std.I64).val = (site.val : Int) :=
      usize_hcast_i64 site hsite
    obtain ⟨i1, hi1, hi1v⟩ := i64_add_ok (x := (UScalar.hcast .I64 site : Std.I64)) (y := 1#i64)
      (by simp only [hsi]; constructor <;> simp <;> omega)
    obtain ⟨rel, hrel, hrelv⟩ := i64_sub_ok (x := loc) (y := i1)
      (by simp only [hx, hi1v, hsi]; constructor <;> simp <;> omega)
    simp only [hi1, hrel, bind_tc_ok]
    have hrelv' : rel.val = (x : Int) - ((site.val : Int) + 1) := by
      rw [hrelv, hx, hi1v, hsi]; simp
    by_cases hlo : rel < (-128)#i64
    · rw [if_pos hlo]
      simp only [rel8Byte]
      rw [if_neg (by simp only [← hrelv']; scalar_tac)]
      exact WP.exists_imp_spec ⟨_, rfl, rfl, rfl⟩
    · rw [if_neg hlo]
      rw [IScalar.lt_equiv] at hlo
      by_cases hhi : rel > 127#i64
      · rw [if_pos hhi]
        simp only [rel8Byte]
        rw [if_neg (by simp only [← hrelv']; scalar_tac)]
        exact WP.exists_imp_spec ⟨_, rfl, rfl, rfl⟩
      · rw [if_neg hhi]
        have hrb : rel8Byte (some x) site.val
            = .ok (i8B ((x : Int) - ((site.val : Int) + 1))) := by
          simp only [rel8Byte]
          rw [if_pos (by simp only [← hrelv']; scalar_tac)]
        rw [hrb]
        simp only [lift, bind_tc_ok]
        obtain ⟨i2, hi2, hi2v⟩ := usize_add_ok (x := base) (y := site) hbs
        simp only [hi2, bind_tc_ok]
        refine WP.spec_bind (put8_at out pre suf w (IScalar.hcast .U8 rel) i2 hval
          (by omega)) ?_
        intro o ho
        exact WP.exists_imp_spec ⟨_, rfl, rfl, by rw [ho, i8B, hcast_u8_i64, hrelv']⟩

/-! ## Pass one: the label tables -/

/-- The tag `label_kind` returns. -/
def lkindTag : x64_ir.PInsn → Nat
  | .PcLabel _ => 1
  | .Local _ => 2
  | .ExitLabel => 3
  | .RetpolineLabel => 4
  | .DispatcherSlot _ => 5
  | .HelperTable => 6
  | _ => 0

/-- The number `label_kind` returns. -/
def lkindNum : x64_ir.PInsn → Nat
  | .PcLabel pc => pc.val
  | .Local n => n.val
  | _ => 0

theorem label_kind_spec (p : x64_ir.PInsn) :
    ∃ kd : Std.U8, ∃ nm : Std.U32, x64_encode.label_kind p = ok (kd, nm) ∧
      kd.val = lkindTag p ∧ nm.val = lkindNum p := by
  cases p <;> refine ⟨_, _, rfl, ?_, ?_⟩ <;> simp [lkindTag, lkindNum]

@[local simp] theorem isPcLabel_iff (k : Nat) (p : x64_ir.PInsn) :
    isPcLabel k p = true ↔ (lkindTag p = 1 ∧ lkindNum p = k) := by
  cases p <;> simp [isPcLabel, lkindTag, lkindNum]

@[local simp] theorem isLocalLabel_iff (k : Nat) (p : x64_ir.PInsn) :
    isLocalLabel k p = true ↔ (lkindTag p = 2 ∧ lkindNum p = k) := by
  cases p <;> simp [isLocalLabel, lkindTag, lkindNum]

@[local simp] theorem isExitLabel_iff (p : x64_ir.PInsn) :
    isExitLabel p = true ↔ lkindTag p = 3 := by
  cases p <;> simp [isExitLabel, lkindTag]

@[local simp] theorem isRetpolineLabel_iff (p : x64_ir.PInsn) :
    isRetpolineLabel p = true ↔ lkindTag p = 4 := by
  cases p <;> simp [isRetpolineLabel, lkindTag]

@[local simp] theorem isDispatcherSlot_iff (p : x64_ir.PInsn) :
    isDispatcherSlot p = true ↔ lkindTag p = 5 := by
  cases p <;> simp [isDispatcherSlot, lkindTag]

@[local simp] theorem isHelperTable_iff (p : x64_ir.PInsn) :
    isHelperTable p = true ↔ lkindTag p = 6 := by
  cases p <;> simp [isHelperTable, lkindTag]

theorem lastLoc_none (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) (m : Nat)
    (h : ∀ j < m, f code[j]! = false) : lastLoc code f m = none := by
  induction m with
  | zero => rfl
  | succ m ih =>
    have hm : f code[m]! = false := h m (by omega)
    unfold lastLoc
    rw [if_neg (by rw [hm]; simp)]
    exact ih (fun j hj => h j (by omega))

theorem lastLoc_le (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) (m x : Nat)
    (h : lastLoc code f m = some x) : x ≤ totalLen code := by
  induction m with
  | zero => simp [lastLoc] at h
  | succ m ih =>
    unfold lastLoc at h
    split at h
    · rw [Option.some.injEq] at h; subst h; exact totalLen_take_le _ _
    · exact ih h

theorem firstLoc_le (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) (m x : Nat)
    (h : firstLoc code f m = some x) : x ≤ totalLen code := by
  induction m with
  | zero => simp [firstLoc] at h
  | succ m ih =>
    unfold firstLoc at h
    split at h
    · rename_i y hy; rw [Option.some.injEq] at h; subst h; exact ih hy
    · split at h
      · rw [Option.some.injEq] at h; subst h; exact totalLen_take_le _ _
      · simp at h

theorem labelLoc_le (code : List x64_ir.PInsn) (t : x64_ir.PTarget) (x : Nat)
    (h : labelLoc code t = some x) : x ≤ totalLen code := by
  unfold labelLoc at h
  cases t <;> exact lastLoc_le _ _ _ _ h

theorem slice_idx_eq {α} [Inhabited α] {code : Slice α} {i : Usize} (h : i.val < code.val.length) :
    Slice.index_usize code i = ok code.val[i.val]! := by
  unfold Slice.index_usize
  rw [show code[i]? = code.val[i.val]? from rfl, List.getElem?_eq_getElem h]
  simp [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem h]

/-! ### Unrolling an extracted loop

`loop_step` and `loop_done` turn one iteration into a plain `Result` equation,
so that every loop below is driven by a lemma about its *body* alone. -/

theorem loop_step {α β : Type} (body : α → Result (ControlFlow α β)) (x x' : α)
    (h : body x = ok (.cont x')) : loop body x = loop body x' := by
  conv_lhs => rw [loop.eq_def]
  simp [h]

theorem loop_done {α β : Type} (body : α → Result (ControlFlow α β)) (x : α) (y : β)
    (h : body x = ok (.done y)) : loop body x = ok y := by
  conv_lhs => rw [loop.eq_def]
  simp [h]

theorem pc_count_body_done (code : Slice x64_ir.PInsn) (n i : Usize)
    (h : code.val.length ≤ i.val) :
    x64_encode.pc_label_count_loop.body code n i = ok (.done n) := by
  unfold x64_encode.pc_label_count_loop.body
  rw [if_neg (by rw [UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length]; omega)]

theorem local_count_body_done (code : Slice x64_ir.PInsn) (n i : Usize)
    (h : code.val.length ≤ i.val) :
    x64_encode.local_label_count_loop.body code n i = ok (.done n) := by
  unfold x64_encode.local_label_count_loop.body
  rw [if_neg (by rw [UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length]; omega)]

theorem pc_count_body_cont (code : Slice x64_ir.PInsn) (n i : Usize)
    (hilt : i.val < code.val.length)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max) :
    ∃ n1 i4 : Usize, x64_encode.pc_label_count_loop.body code n i = ok (.cont (n1, i4)) ∧
      i4.val = i.val + 1 ∧ n.val ≤ n1.val ∧
      (lkindTag code.val[i.val]! = 1 → lkindNum code.val[i.val]! < n1.val) := by
  have hcl : code.val.length ≤ Usize.max := code.property
  unfold x64_encode.pc_label_count_loop.body
  rw [if_pos (by rw [UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length]; omega)]
  obtain ⟨kd, nm, hk, hkv, hnv⟩ := label_kind_spec code.val[i.val]!
  obtain ⟨i4, hi4, hi4v0⟩ := usize_add_ok (x := i) (y := 1#usize) (by simp; omega)
  have hi4v : i4.val = i.val + 1 := by simpa using hi4v0
  by_cases htag : lkindTag code.val[i.val]! = 1
  · have hkd1 : kd = 1#u8 := by rw [UScalar.eq_equiv, hkv, htag]; simp
    have hcv : (UScalar.cast .Usize nm : Usize).val = nm.val := by simp
    obtain ⟨kk, hkk, hkkv⟩ := usize_add_ok (x := (UScalar.cast .Usize nm : Usize)) (y := 1#usize)
      (by rw [hcv]; have := hnum i.val hilt; simp; omega)
    have hkkv' : kk.val = nm.val + 1 := by rw [hkkv, hcv]; simp
    by_cases hgt : kk > n
    · have hgtv : n.val < kk.val := (UScalar.lt_equiv n kk).mp hgt
      refine ⟨kk, i4, ?_, hi4v, by omega, fun _ => by omega⟩
      simp only [slice_idx_eq hilt, hk, bind_tc_ok]
      simp [lift, hkd1, hkk, hi4, hgt, hgtv]
    · have hgtv : ¬ (n.val < kk.val) := fun h => hgt ((UScalar.lt_equiv n kk).mpr h)
      refine ⟨n, i4, ?_, hi4v, le_refl _, fun _ => by omega⟩
      simp only [slice_idx_eq hilt, hk, bind_tc_ok]
      simp [lift, hkd1, hkk, hi4, hgt, hgtv]
  · have hkd1 : ¬ kd = 1#u8 := by rw [UScalar.eq_equiv, hkv]; simpa using htag
    refine ⟨n, i4, ?_, hi4v, le_refl _, fun h => absurd h htag⟩
    simp only [slice_idx_eq hilt, hk, bind_tc_ok]
    simp [hi4, hkd1]

theorem local_count_body_cont (code : Slice x64_ir.PInsn) (n i : Usize)
    (hilt : i.val < code.val.length)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max) :
    ∃ n1 i4 : Usize, x64_encode.local_label_count_loop.body code n i = ok (.cont (n1, i4)) ∧
      i4.val = i.val + 1 ∧ n.val ≤ n1.val ∧
      (lkindTag code.val[i.val]! = 2 → lkindNum code.val[i.val]! < n1.val) := by
  have hcl : code.val.length ≤ Usize.max := code.property
  unfold x64_encode.local_label_count_loop.body
  rw [if_pos (by rw [UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length]; omega)]
  obtain ⟨kd, nm, hk, hkv, hnv⟩ := label_kind_spec code.val[i.val]!
  obtain ⟨i4, hi4, hi4v0⟩ := usize_add_ok (x := i) (y := 1#usize) (by simp; omega)
  have hi4v : i4.val = i.val + 1 := by simpa using hi4v0
  by_cases htag : lkindTag code.val[i.val]! = 2
  · have hkd1 : kd = 2#u8 := by rw [UScalar.eq_equiv, hkv, htag]; simp
    have hcv : (UScalar.cast .Usize nm : Usize).val = nm.val := by simp
    obtain ⟨kk, hkk, hkkv⟩ := usize_add_ok (x := (UScalar.cast .Usize nm : Usize)) (y := 1#usize)
      (by rw [hcv]; have := hnum i.val hilt; simp; omega)
    have hkkv' : kk.val = nm.val + 1 := by rw [hkkv, hcv]; simp
    by_cases hgt : kk > n
    · have hgtv : n.val < kk.val := (UScalar.lt_equiv n kk).mp hgt
      refine ⟨kk, i4, ?_, hi4v, by omega, fun _ => by omega⟩
      simp only [slice_idx_eq hilt, hk, bind_tc_ok]
      simp [lift, hkd1, hkk, hi4, hgt, hgtv]
    · have hgtv : ¬ (n.val < kk.val) := fun h => hgt ((UScalar.lt_equiv n kk).mpr h)
      refine ⟨n, i4, ?_, hi4v, le_refl _, fun _ => by omega⟩
      simp only [slice_idx_eq hilt, hk, bind_tc_ok]
      simp [lift, hkd1, hkk, hi4, hgt, hgtv]
  · have hkd1 : ¬ kd = 2#u8 := by rw [UScalar.eq_equiv, hkv]; simpa using htag
    refine ⟨n, i4, ?_, hi4v, le_refl _, fun h => absurd h htag⟩
    simp only [slice_idx_eq hilt, hk, bind_tc_ok]
    simp [hi4, hkd1]

/-- **`pc_label_count` is past every slot number the list labels.** -/
theorem pc_label_count_loop_spec (code : Slice x64_ir.PInsn) (n i : Usize)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max)
    (hi : i.val ≤ code.val.length)
    (hinv : ∀ j < i.val, lkindTag code.val[j]! = 1 → lkindNum code.val[j]! < n.val) :
    x64_encode.pc_label_count_loop code n i ⦃ m =>
      ∀ j < code.val.length, lkindTag code.val[j]! = 1 → lkindNum code.val[j]! < m.val ⦄ := by
  generalize hd : code.val.length - i.val = d
  induction d generalizing n i with
  | zero =>
    rw [show x64_encode.pc_label_count_loop code n i = ok n from
      loop_done _ _ _ (pc_count_body_done code n i (by omega))]
    exact WP.exists_imp_spec ⟨n, rfl, fun j hj => hinv j (by omega)⟩
  | succ d ih =>
    have hilt : i.val < code.val.length := by omega
    obtain ⟨n1, i4, hb, hi4v, hmono, hnew⟩ := pc_count_body_cont code n i hilt hnum
    rw [show x64_encode.pc_label_count_loop code n i = x64_encode.pc_label_count_loop code n1 i4
      from loop_step _ _ _ hb]
    refine ih n1 i4 (by omega) (fun j hj htj => ?_) (by omega)
    rcases Nat.lt_or_ge j i.val with hlt | hge
    · have := hinv j hlt htj; omega
    · have hje : j = i.val := by omega
      subst hje; exact hnew htj

theorem pc_label_count_spec (code : Slice x64_ir.PInsn)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max) :
    x64_encode.pc_label_count code ⦃ m =>
      ∀ j < code.val.length, lkindTag code.val[j]! = 1 → lkindNum code.val[j]! < m.val ⦄ :=
  pc_label_count_loop_spec code 0#usize 0#usize hnum (by simp) (by simp)

/-- **`local_label_count` is past every local number the list labels.** -/
theorem local_label_count_loop_spec (code : Slice x64_ir.PInsn) (n i : Usize)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max)
    (hi : i.val ≤ code.val.length)
    (hinv : ∀ j < i.val, lkindTag code.val[j]! = 2 → lkindNum code.val[j]! < n.val) :
    x64_encode.local_label_count_loop code n i ⦃ m =>
      ∀ j < code.val.length, lkindTag code.val[j]! = 2 → lkindNum code.val[j]! < m.val ⦄ := by
  generalize hd : code.val.length - i.val = d
  induction d generalizing n i with
  | zero =>
    rw [show x64_encode.local_label_count_loop code n i = ok n from
      loop_done _ _ _ (local_count_body_done code n i (by omega))]
    exact WP.exists_imp_spec ⟨n, rfl, fun j hj => hinv j (by omega)⟩
  | succ d ih =>
    have hilt : i.val < code.val.length := by omega
    obtain ⟨n1, i4, hb, hi4v, hmono, hnew⟩ := local_count_body_cont code n i hilt hnum
    rw [show x64_encode.local_label_count_loop code n i
      = x64_encode.local_label_count_loop code n1 i4 from loop_step _ _ _ hb]
    refine ih n1 i4 (by omega) (fun j hj htj => ?_) (by omega)
    rcases Nat.lt_or_ge j i.val with hlt | hge
    · have := hinv j hlt htj; omega
    · have hje : j = i.val := by omega
      subst hje; exact hnew htj

theorem local_label_count_spec (code : Slice x64_ir.PInsn)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max) :
    x64_encode.local_label_count code ⦃ m =>
      ∀ j < code.val.length, lkindTag code.val[j]! = 2 → lkindNum code.val[j]! < m.val ⦄ :=
  local_label_count_loop_spec code 0#usize 0#usize hnum (by simp) (by simp)

/-! ### `collect_labels` -/

theorem lastLoc_succ (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) (m : Nat) :
    lastLoc code f (m + 1)
      = if f code[m]! then some (totalLen (code.take m)) else lastLoc code f m := rfl

theorem firstLoc_succ (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) (m : Nat) :
    firstLoc code f (m + 1)
      = match firstLoc code f m with
        | some x => some x
        | none => if f code[m]! then some (totalLen (code.take m)) else none := rfl

theorem lastLoc_skip (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) (m : Nat)
    (h : f code[m]! = false) : lastLoc code f (m + 1) = lastLoc code f m := by
  rw [lastLoc_succ, h]; simp

theorem lastLoc_hit (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) (m : Nat)
    (h : f code[m]! = true) : lastLoc code f (m + 1) = some (totalLen (code.take m)) := by
  rw [lastLoc_succ]; exact if_pos h

theorem firstLoc_skip (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) (m : Nat)
    (h : f code[m]! = false) : firstLoc code f (m + 1) = firstLoc code f m := by
  rw [firstLoc_succ]
  cases hh : firstLoc code f m with
  | none => rw [h]; simp
  | some x => rfl

theorem firstLoc_hit_none (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) (m : Nat)
    (h : f code[m]! = true) (hn : firstLoc code f m = none) :
    firstLoc code f (m + 1) = some (totalLen (code.take m)) := by
  rw [firstLoc_succ, hn]; exact if_pos h

theorem firstLoc_keep (code : List x64_ir.PInsn) (f : x64_ir.PInsn → Bool) (m x : Nat)
    (hs : firstLoc code f m = some x) : firstLoc code f (m + 1) = some x := by
  rw [firstLoc_succ, hs]

theorem getBang_set_eq {α} [Inhabited α] (l : List α) (j : Nat) (x : α) (h : j < l.length) :
    (l.set j x)[j]! = x := by
  simp [List.getElem!_eq_getElem?_getD, List.getElem?_set, h]

theorem getBang_set_ne {α} [Inhabited α] (l : List α) (j k : Nat) (x : α) (h : k ≠ j) :
    (l.set j x)[k]! = l[k]! := by
  simp [List.getElem!_eq_getElem?_getD, List.getElem?_set, h]

theorem vec_index_mut_eq {α} [Inhabited α] (v : alloc.vec.Vec α) (i : Usize)
    (h : i.val < v.val.length) :
    alloc.vec.Vec.index_mut_usize v i = ok (v.val[i.val]!, alloc.vec.Vec.set v i) := by
  unfold alloc.vec.Vec.index_mut_usize alloc.vec.Vec.index_usize
  rw [show v[i.val]? = v.val[i.val]? from rfl, List.getElem?_eq_getElem h]
  simp [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem h]

/-- The invariant `collect_labels` maintains: after `m` primitives each table
entry holds the label's last (or, for the two data labels, first) offset. -/
def LabelsInv (code : List x64_ir.PInsn) (np nl m : Nat)
    (v : alloc.vec.Vec Std.U32) (v1 : alloc.vec.Vec Bool)
    (v2 : alloc.vec.Vec Std.U32) (v3 : alloc.vec.Vec Bool)
    (e : Std.U32) (be : Bool) (rp : Std.U32) (brp : Bool)
    (dp : Std.U32) (bdp : Bool) (ht : Std.U32) (bht : Bool) : Prop :=
  v.val.length = np ∧ v1.val.length = np ∧ v2.val.length = nl ∧ v3.val.length = nl ∧
  (∀ k < np, (if v1.val[k]! then some (v.val[k]!).val else none)
      = lastLoc code (isPcLabel k) m) ∧
  (∀ k < nl, (if v3.val[k]! then some (v2.val[k]!).val else none)
      = lastLoc code (isLocalLabel k) m) ∧
  ((if be then some e.val else none) = lastLoc code isExitLabel m) ∧
  ((if brp then some rp.val else none) = lastLoc code isRetpolineLabel m) ∧
  ((if bdp then some dp.val else none) = firstLoc code isDispatcherSlot m) ∧
  ((if bht then some ht.val else none) = firstLoc code isHelperTable m)

@[local simp] theorem u8v1 : (1#u8).val = 1 := rfl
@[local simp] theorem u8v2 : (2#u8).val = 2 := rfl
@[local simp] theorem u8v3 : (3#u8).val = 3 := rfl
@[local simp] theorem u8v4 : (4#u8).val = 4 := rfl
@[local simp] theorem u8v5 : (5#u8).val = 5 := rfl
@[local simp] theorem u8v6 : (6#u8).val = 6 := rfl

theorem pc_false (k : Nat) (p : x64_ir.PInsn) (h : lkindTag p ≠ 1) : isPcLabel k p = false := by
  simp only [Bool.eq_false_iff, ne_eq, isPcLabel_iff]; tauto

theorem pc_false_num (k : Nat) (p : x64_ir.PInsn) (h : lkindNum p ≠ k) :
    isPcLabel k p = false := by
  simp only [Bool.eq_false_iff, ne_eq, isPcLabel_iff]; tauto

theorem pc_true (p : x64_ir.PInsn) (h : lkindTag p = 1) : isPcLabel (lkindNum p) p = true :=
  (isPcLabel_iff _ _).mpr ⟨h, rfl⟩

theorem lc_false (k : Nat) (p : x64_ir.PInsn) (h : lkindTag p ≠ 2) :
    isLocalLabel k p = false := by
  simp only [Bool.eq_false_iff, ne_eq, isLocalLabel_iff]; tauto

theorem lc_false_num (k : Nat) (p : x64_ir.PInsn) (h : lkindNum p ≠ k) :
    isLocalLabel k p = false := by
  simp only [Bool.eq_false_iff, ne_eq, isLocalLabel_iff]; tauto

theorem lc_true (p : x64_ir.PInsn) (h : lkindTag p = 2) : isLocalLabel (lkindNum p) p = true :=
  (isLocalLabel_iff _ _).mpr ⟨h, rfl⟩

theorem ex_false (p : x64_ir.PInsn) (h : lkindTag p ≠ 3) : isExitLabel p = false := by
  simp only [Bool.eq_false_iff, ne_eq, isExitLabel_iff]; tauto

theorem rp_false (p : x64_ir.PInsn) (h : lkindTag p ≠ 4) : isRetpolineLabel p = false := by
  simp only [Bool.eq_false_iff, ne_eq, isRetpolineLabel_iff]; tauto

theorem ds_false (p : x64_ir.PInsn) (h : lkindTag p ≠ 5) : isDispatcherSlot p = false := by
  simp only [Bool.eq_false_iff, ne_eq, isDispatcherSlot_iff]; tauto

theorem hts_false (p : x64_ir.PInsn) (h : lkindTag p ≠ 6) : isHelperTable p = false := by
  simp only [Bool.eq_false_iff, ne_eq, isHelperTable_iff]; tauto

theorem ex_true (p : x64_ir.PInsn) (h : lkindTag p = 3) : isExitLabel p = true :=
  (isExitLabel_iff p).mpr h

theorem rp_true (p : x64_ir.PInsn) (h : lkindTag p = 4) : isRetpolineLabel p = true :=
  (isRetpolineLabel_iff p).mpr h

theorem ds_true (p : x64_ir.PInsn) (h : lkindTag p = 5) : isDispatcherSlot p = true :=
  (isDispatcherSlot_iff p).mpr h

theorem hts_true (p : x64_ir.PInsn) (h : lkindTag p = 6) : isHelperTable p = true :=
  (isHelperTable_iff p).mpr h

theorem pcInv_skip {code : List x64_ir.PInsn} {np m : Nat} {v : alloc.vec.Vec Std.U32}
    {v1 : alloc.vec.Vec Bool}
    (h : ∀ k < np, (if v1.val[k]! then some (v.val[k]!).val else none)
      = lastLoc code (isPcLabel k) m) (htg : lkindTag code[m]! ≠ 1) :
    ∀ k < np, (if v1.val[k]! then some (v.val[k]!).val else none)
      = lastLoc code (isPcLabel k) (m + 1) := by
  intro k hk; rw [lastLoc_skip _ _ _ (pc_false k _ htg)]; exact h k hk

theorem lcInv_skip {code : List x64_ir.PInsn} {nl m : Nat} {v2 : alloc.vec.Vec Std.U32}
    {v3 : alloc.vec.Vec Bool}
    (h : ∀ k < nl, (if v3.val[k]! then some (v2.val[k]!).val else none)
      = lastLoc code (isLocalLabel k) m) (htg : lkindTag code[m]! ≠ 2) :
    ∀ k < nl, (if v3.val[k]! then some (v2.val[k]!).val else none)
      = lastLoc code (isLocalLabel k) (m + 1) := by
  intro k hk; rw [lastLoc_skip _ _ _ (lc_false k _ htg)]; exact h k hk

theorem exInv_skip {code : List x64_ir.PInsn} {m : Nat} {e : Std.U32} {be : Bool}
    (h : (if be then some e.val else none) = lastLoc code isExitLabel m)
    (htg : lkindTag code[m]! ≠ 3) :
    (if be then some e.val else none) = lastLoc code isExitLabel (m + 1) := by
  rw [lastLoc_skip _ _ _ (ex_false _ htg)]; exact h

theorem rpInv_skip {code : List x64_ir.PInsn} {m : Nat} {rp : Std.U32} {brp : Bool}
    (h : (if brp then some rp.val else none) = lastLoc code isRetpolineLabel m)
    (htg : lkindTag code[m]! ≠ 4) :
    (if brp then some rp.val else none) = lastLoc code isRetpolineLabel (m + 1) := by
  rw [lastLoc_skip _ _ _ (rp_false _ htg)]; exact h

theorem dsInv_skip {code : List x64_ir.PInsn} {m : Nat} {dp : Std.U32} {bdp : Bool}
    (h : (if bdp then some dp.val else none) = firstLoc code isDispatcherSlot m)
    (htg : lkindTag code[m]! ≠ 5) :
    (if bdp then some dp.val else none) = firstLoc code isDispatcherSlot (m + 1) := by
  rw [firstLoc_skip _ _ _ (ds_false _ htg)]; exact h

theorem htInv_skip {code : List x64_ir.PInsn} {m : Nat} {ht : Std.U32} {bht : Bool}
    (h : (if bht then some ht.val else none) = firstLoc code isHelperTable m)
    (htg : lkindTag code[m]! ≠ 6) :
    (if bht then some ht.val else none) = firstLoc code isHelperTable (m + 1) := by
  rw [firstLoc_skip _ _ _ (hts_false _ htg)]; exact h

/-- **One step of `collect_labels` keeps the invariant.** -/
theorem collect_body_cont
    (code : Slice x64_ir.PInsn) (starts : Slice Std.U32) (np nl n : Usize)
    (v : alloc.vec.Vec Std.U32) (v1 : alloc.vec.Vec Bool)
    (v2 : alloc.vec.Vec Std.U32) (v3 : alloc.vec.Vec Bool)
    (e : Std.U32) (be : Bool) (rp : Std.U32) (brp : Bool)
    (dp : Std.U32) (bdp : Bool) (ht : Std.U32) (bht : Bool) (i4 : Usize)
    (hn : n.val = code.val.length) (hilt : i4.val < code.val.length)
    (hstarts : ∀ j ≤ code.val.length, (starts.val[j]!).val = totalLen (code.val.take j))
    (hsl : code.val.length < starts.val.length)
    (hnp : ∀ j < code.val.length, lkindTag code.val[j]! = 1 → lkindNum code.val[j]! < np.val)
    (hnl : ∀ j < code.val.length, lkindTag code.val[j]! = 2 → lkindNum code.val[j]! < nl.val)
    (hinv : LabelsInv code.val np.val nl.val i4.val v v1 v2 v3 e be rp brp dp bdp ht bht) :
    ∃ (v' : alloc.vec.Vec Std.U32) (v1' : alloc.vec.Vec Bool)
      (v2' : alloc.vec.Vec Std.U32) (v3' : alloc.vec.Vec Bool)
      (e' : Std.U32) (be' : Bool) (rp' : Std.U32) (brp' : Bool)
      (dp' : Std.U32) (bdp' : Bool) (ht' : Std.U32) (bht' : Bool) (i9 : Usize),
      x64_encode.collect_labels_loop.body code starts np nl n v v1 v2 v3 e be rp brp dp bdp ht
          bht i4
        = ok (.cont (v', v1', v2', v3', e', be', rp', brp', dp', bdp', ht', bht', i9)) ∧
      i9.val = i4.val + 1 ∧
      LabelsInv code.val np.val nl.val (i4.val + 1) v' v1' v2' v3' e' be' rp' brp' dp' bdp'
        ht' bht' := by
  obtain ⟨hvl, hv1l, hv2l, hv3l, hpc, hlc, he, hrp, hdp, hht⟩ := hinv
  have hcl : code.val.length ≤ Usize.max := code.property
  have hhv : (starts.val[i4.val]!).val = totalLen (code.val.take i4.val) :=
    hstarts i4.val (by omega)
  obtain ⟨kd, nm, hk, hkv, hnv⟩ := label_kind_spec code.val[i4.val]!
  obtain ⟨i9, hi9, hi9v0⟩ := usize_add_ok (x := i4) (y := 1#usize) (by simp; omega)
  have hi9v : i9.val = i4.val + 1 := by simpa using hi9v0
  have hidxs : Slice.index_usize starts i4 = ok starts.val[i4.val]! := slice_idx_eq (by omega)
  have hidxc : Slice.index_usize code i4 = ok code.val[i4.val]! := slice_idx_eq (by omega)
  have hkcv : (UScalar.cast .Usize nm : Usize).val = nm.val := by simp
  unfold x64_encode.collect_labels_loop.body
  rw [if_pos (show i4 < n by rw [UScalar.lt_equiv]; omega)]
  simp only [hidxs, hidxc, hk, bind_tc_ok, lift]
  by_cases htag1 : lkindTag code.val[i4.val]! = 1
  · have hkd : kd = 1#u8 := by rw [UScalar.eq_equiv, hkv, htag1]; simp
    have hklt : nm.val < np.val := by rw [hnv]; exact hnp _ hilt htag1
    have hklt' : (UScalar.cast .Usize nm : Usize) < np := by
      rw [UScalar.lt_equiv, hkcv]; exact hklt
    refine ⟨alloc.vec.Vec.set v (UScalar.cast .Usize nm) starts.val[i4.val]!,
      alloc.vec.Vec.set v1 (UScalar.cast .Usize nm) true, v2, v3, e, be, rp, brp, dp, bdp,
      ht, bht, i9, ?_, hi9v, ?_⟩
    · simp [hkd, hklt, hi9,
        vec_index_mut_eq v (UScalar.cast .Usize nm) (by rw [hkcv, hvl]; exact hklt),
        vec_index_mut_eq v1 (UScalar.cast .Usize nm) (by rw [hkcv, hv1l]; exact hklt)]
    · refine ⟨by simp [hvl], by simp [hv1l], hv2l, hv3l, ?_, lcInv_skip hlc (by omega),
        exInv_skip he (by omega), rpInv_skip hrp (by omega), dsInv_skip hdp (by omega),
        htInv_skip hht (by omega)⟩
      intro k hk'
      simp only [vec_set_val, hkcv]
      by_cases hkq : k = nm.val
      · subst hkq
        rw [getBang_set_eq _ _ _ (by omega), getBang_set_eq _ _ _ (by omega)]
        rw [lastLoc_hit _ _ _ (by rw [hnv]; exact pc_true _ htag1)]
        simp <;> simpa using hhv
      · rw [getBang_set_ne _ _ _ _ hkq, getBang_set_ne _ _ _ _ hkq,
          lastLoc_skip _ _ _ (pc_false_num _ _ (by rw [← hnv]; omega))]
        exact hpc k hk'
  · have hkdn1 : ¬ kd = 1#u8 := by rw [UScalar.eq_equiv, hkv]; simpa using htag1
    by_cases htag2 : lkindTag code.val[i4.val]! = 2
    · have hkd : kd = 2#u8 := by rw [UScalar.eq_equiv, hkv, htag2]; simp
      have hklt : nm.val < nl.val := by rw [hnv]; exact hnl _ hilt htag2
      have hklt' : (UScalar.cast .Usize nm : Usize) < nl := by
        rw [UScalar.lt_equiv, hkcv]; exact hklt
      refine ⟨v, v1, alloc.vec.Vec.set v2 (UScalar.cast .Usize nm) starts.val[i4.val]!,
        alloc.vec.Vec.set v3 (UScalar.cast .Usize nm) true, e, be, rp, brp, dp, bdp,
        ht, bht, i9, ?_, hi9v, ?_⟩
      · simp [hkd, hkdn1, hklt, hi9,
          vec_index_mut_eq v2 (UScalar.cast .Usize nm) (by rw [hkcv, hv2l]; exact hklt),
          vec_index_mut_eq v3 (UScalar.cast .Usize nm) (by rw [hkcv, hv3l]; exact hklt)]
      · refine ⟨hvl, hv1l, by simp [hv2l], by simp [hv3l], pcInv_skip hpc (by omega), ?_,
          exInv_skip he (by omega), rpInv_skip hrp (by omega), dsInv_skip hdp (by omega),
          htInv_skip hht (by omega)⟩
        intro k hk'
        simp only [vec_set_val, hkcv]
        by_cases hkq : k = nm.val
        · subst hkq
          rw [getBang_set_eq _ _ _ (by omega), getBang_set_eq _ _ _ (by omega)]
          rw [lastLoc_hit _ _ _ (by rw [hnv]; exact lc_true _ htag2)]
          simp <;> simpa using hhv
        · rw [getBang_set_ne _ _ _ _ hkq, getBang_set_ne _ _ _ _ hkq,
            lastLoc_skip _ _ _ (lc_false_num _ _ (by rw [← hnv]; omega))]
          exact hlc k hk'
    · have hkdn2 : ¬ kd = 2#u8 := by rw [UScalar.eq_equiv, hkv]; simpa using htag2
      by_cases htag3 : lkindTag code.val[i4.val]! = 3
      · have hkd : kd = 3#u8 := by rw [UScalar.eq_equiv, hkv, htag3]; simp
        refine ⟨v, v1, v2, v3, starts.val[i4.val]!, true, rp, brp, dp, bdp, ht, bht, i9,
          by simp [hkd, hkdn1, hkdn2, hi9], hi9v, ?_⟩
        refine ⟨hvl, hv1l, hv2l, hv3l, pcInv_skip hpc (by omega), lcInv_skip hlc (by omega), ?_,
          rpInv_skip hrp (by omega), dsInv_skip hdp (by omega), htInv_skip hht (by omega)⟩
        rw [lastLoc_hit _ _ _ (ex_true _ htag3)]; simp <;> simpa using hhv
      · have hkdn3 : ¬ kd = 3#u8 := by rw [UScalar.eq_equiv, hkv]; simpa using htag3
        by_cases htag4 : lkindTag code.val[i4.val]! = 4
        · have hkd : kd = 4#u8 := by rw [UScalar.eq_equiv, hkv, htag4]; simp
          refine ⟨v, v1, v2, v3, e, be, starts.val[i4.val]!, true, dp, bdp, ht, bht, i9,
            by simp [hkd, hkdn1, hkdn2, hkdn3, hi9], hi9v, ?_⟩
          refine ⟨hvl, hv1l, hv2l, hv3l, pcInv_skip hpc (by omega), lcInv_skip hlc (by omega),
            exInv_skip he (by omega), ?_, dsInv_skip hdp (by omega), htInv_skip hht (by omega)⟩
          rw [lastLoc_hit _ _ _ (rp_true _ htag4)]; simp <;> simpa using hhv
        · have hkdn4 : ¬ kd = 4#u8 := by rw [UScalar.eq_equiv, hkv]; simpa using htag4
          by_cases htag5 : lkindTag code.val[i4.val]! = 5
          · have hkd : kd = 5#u8 := by rw [UScalar.eq_equiv, hkv, htag5]; simp
            refine ⟨v, v1, v2, v3, e, be, rp, brp, (if bdp then dp else starts.val[i4.val]!),
              true, ht, bht, i9,
              by cases bdp <;> simp [hkd, hkdn1, hkdn2, hkdn3, hkdn4, hi9], hi9v, ?_⟩
            refine ⟨hvl, hv1l, hv2l, hv3l, pcInv_skip hpc (by omega), lcInv_skip hlc (by omega),
              exInv_skip he (by omega), rpInv_skip hrp (by omega), ?_,
              htInv_skip hht (by omega)⟩
            cases hb : bdp with
            | true =>
              rw [hb] at hdp; simp only [if_true, reduceIte]
              rw [firstLoc_keep _ _ _ _ hdp.symm]
            | false =>
              rw [hb] at hdp; simp only [if_false, reduceIte]
              rw [firstLoc_hit_none _ _ _ (ds_true _ htag5) hdp.symm]
              simp <;> simpa using hhv
          · have hkdn5 : ¬ kd = 5#u8 := by rw [UScalar.eq_equiv, hkv]; simpa using htag5
            by_cases htag6 : lkindTag code.val[i4.val]! = 6
            · have hkd : kd = 6#u8 := by rw [UScalar.eq_equiv, hkv, htag6]; simp
              refine ⟨v, v1, v2, v3, e, be, rp, brp, dp, bdp,
                (if bht then ht else starts.val[i4.val]!), true, i9,
                by cases bht <;> simp [hkd, hkdn1, hkdn2, hkdn3, hkdn4, hkdn5, hi9], hi9v, ?_⟩
              refine ⟨hvl, hv1l, hv2l, hv3l, pcInv_skip hpc (by omega), lcInv_skip hlc (by omega),
                exInv_skip he (by omega), rpInv_skip hrp (by omega), dsInv_skip hdp (by omega),
                ?_⟩
              cases hb : bht with
              | true =>
                rw [hb] at hht; simp only [if_true, reduceIte]
                rw [firstLoc_keep _ _ _ _ hht.symm]
              | false =>
                rw [hb] at hht; simp only [if_false, reduceIte]
                rw [firstLoc_hit_none _ _ _ (hts_true _ htag6) hht.symm]
                simp <;> simpa using hhv
            · have hkdn6 : ¬ kd = 6#u8 := by rw [UScalar.eq_equiv, hkv]; simpa using htag6
              exact ⟨v, v1, v2, v3, e, be, rp, brp, dp, bdp, ht, bht, i9,
                by simp [hkdn1, hkdn2, hkdn3, hkdn4, hkdn5, hkdn6, hi9], hi9v,
                ⟨hvl, hv1l, hv2l, hv3l, pcInv_skip hpc (by omega), lcInv_skip hlc (by omega),
                  exInv_skip he (by omega), rpInv_skip hrp (by omega), dsInv_skip hdp (by omega),
                  htInv_skip hht (by omega)⟩⟩

theorem collect_body_done
    (code : Slice x64_ir.PInsn) (starts : Slice Std.U32) (np nl n : Usize)
    (v : alloc.vec.Vec Std.U32) (v1 : alloc.vec.Vec Bool)
    (v2 : alloc.vec.Vec Std.U32) (v3 : alloc.vec.Vec Bool)
    (e : Std.U32) (be : Bool) (rp : Std.U32) (brp : Bool)
    (dp : Std.U32) (bdp : Bool) (ht : Std.U32) (bht : Bool) (i4 : Usize)
    (h : n.val ≤ i4.val) :
    x64_encode.collect_labels_loop.body code starts np nl n v v1 v2 v3 e be rp brp dp bdp ht
        bht i4
      = ok (.done (v, v1, v2, v3, e, be, rp, brp, dp, bdp, ht, bht)) := by
  unfold x64_encode.collect_labels_loop.body
  rw [if_neg (by rw [UScalar.lt_equiv]; omega)]

/-- **`collect_labels`' loop establishes the invariant for the whole list.** -/
theorem collect_labels_loop_spec
    (code : Slice x64_ir.PInsn) (starts : Slice Std.U32) (np nl n : Usize)
    (v : alloc.vec.Vec Std.U32) (v1 : alloc.vec.Vec Bool)
    (v2 : alloc.vec.Vec Std.U32) (v3 : alloc.vec.Vec Bool)
    (e : Std.U32) (be : Bool) (rp : Std.U32) (brp : Bool)
    (dp : Std.U32) (bdp : Bool) (ht : Std.U32) (bht : Bool) (i4 : Usize)
    (hn : n.val = code.val.length) (hi : i4.val ≤ code.val.length)
    (hstarts : ∀ j ≤ code.val.length, (starts.val[j]!).val = totalLen (code.val.take j))
    (hsl : code.val.length < starts.val.length)
    (hnp : ∀ j < code.val.length, lkindTag code.val[j]! = 1 → lkindNum code.val[j]! < np.val)
    (hnl : ∀ j < code.val.length, lkindTag code.val[j]! = 2 → lkindNum code.val[j]! < nl.val)
    (hinv : LabelsInv code.val np.val nl.val i4.val v v1 v2 v3 e be rp brp dp bdp ht bht) :
    x64_encode.collect_labels_loop code starts np nl v v1 v2 v3 e be rp brp dp bdp ht bht n i4
      ⦃ r => LabelsInv code.val np.val nl.val code.val.length r.1 r.2.1 r.2.2.1 r.2.2.2.1
          r.2.2.2.2.1 r.2.2.2.2.2.1 r.2.2.2.2.2.2.1 r.2.2.2.2.2.2.2.1 r.2.2.2.2.2.2.2.2.1
          r.2.2.2.2.2.2.2.2.2.1 r.2.2.2.2.2.2.2.2.2.2.1 r.2.2.2.2.2.2.2.2.2.2.2 ⦄ := by
  generalize hd : code.val.length - i4.val = d
  induction d generalizing v v1 v2 v3 e be rp brp dp bdp ht bht i4 with
  | zero =>
    have hie : i4.val = code.val.length := by omega
    rw [show x64_encode.collect_labels_loop code starts np nl v v1 v2 v3 e be rp brp dp bdp ht
        bht n i4 = ok (v, v1, v2, v3, e, be, rp, brp, dp, bdp, ht, bht) from
      loop_done _ _ _ (collect_body_done code starts np nl n v v1 v2 v3 e be rp brp dp bdp ht
        bht i4 (by omega))]
    exact WP.exists_imp_spec ⟨_, rfl, by rw [← hie]; exact hinv⟩
  | succ d ih =>
    have hilt : i4.val < code.val.length := by omega
    obtain ⟨v', v1', v2', v3', e', be', rp', brp', dp', bdp', ht', bht', i9, hb, hi9v, hinv'⟩ :=
      collect_body_cont code starts np nl n v v1 v2 v3 e be rp brp dp bdp ht bht i4 hn hilt
        hstarts hsl hnp hnl hinv
    rw [show x64_encode.collect_labels_loop code starts np nl v v1 v2 v3 e be rp brp dp bdp ht
        bht n i4
      = x64_encode.collect_labels_loop code starts np nl v' v1' v2' v3' e' be' rp' brp' dp'
        bdp' ht' bht' n i9 from loop_step _ _ _ hb]
    exact ih v' v1' v2' v3' e' be' rp' brp' dp' bdp' ht' bht' i9 (by omega)
      (by rw [hi9v]; exact hinv') (by omega)

theorem vec_index_eq {α} [Inhabited α] (v : alloc.vec.Vec α) (i : Usize)
    (h : i.val < v.val.length) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i = ok v.val[i.val]! := by
  rw [alloc.vec.Vec.index_slice_index]
  unfold alloc.vec.Vec.index_usize
  rw [show v[i.val]? = v.val[i.val]? from rfl, List.getElem?_eq_getElem h]
  simp [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem h]

theorem u32_hcast_i64 (x : Std.U32) : (UScalar.hcast .I64 x : Std.I64).val = (x.val : Int) := by
  have h : x.val < 2 ^ 32 := by scalar_tac
  have hx : (x.val : Int) < 2 ^ 32 := by exact_mod_cast h
  have h32 : ((2:Int) ^ 32) = 4294967296 := by norm_num
  have h63 : ((2:Int) ^ 63) = 9223372036854775808 := by norm_num
  rw [UScalar.hcast_val_eq]
  show Int.bmod (x.val : Int) (2 ^ 64) = _
  exact Arith.Int.bmod_pow2_eq_of_inBounds' 64 _ (by omega) (by omega) (by omega)

@[local simp] theorem getBang_replicate {α} [Inhabited α] (n k : Nat) (x : α) :
    (List.replicate n x)[k]! = if k < n then x else default := by
  by_cases h : k < n
  · simp [List.getElem!_eq_getElem?_getD, List.getElem?_replicate, h]
  · simp [List.getElem!_eq_getElem?_getD, List.getElem?_replicate, h]

/-- **`collect_labels` records where every label landed.** -/
theorem collect_labels_spec (code : Slice x64_ir.PInsn) (starts : Slice Std.U32)
    (hstarts : ∀ j ≤ code.val.length, (starts.val[j]!).val = totalLen (code.val.take j))
    (hsl : code.val.length < starts.val.length)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max) :
    x64_encode.collect_labels code starts ⦃ labels => ∃ np nl : Nat,
      LabelsInv code.val np nl code.val.length labels.pc labels.pc_set labels.local
        labels.local_set labels.exit labels.exit_set labels.retpoline labels.retpoline_set
        labels.dispatcher labels.dispatcher_set labels.helper_table labels.helper_table_set ∧
      (∀ j < code.val.length, lkindTag code.val[j]! = 1 → lkindNum code.val[j]! < np) ∧
      (∀ j < code.val.length, lkindTag code.val[j]! = 2 → lkindNum code.val[j]! < nl) ⦄ := by
  unfold x64_encode.collect_labels
  refine WP.spec_bind (pc_label_count_spec code hnum) ?_
  intro np hnp
  refine WP.spec_bind (local_label_count_spec code hnum) ?_
  intro nl hnl
  refine WP.spec_bind (alloc.vec.from_elem_spec core.clone.CloneU32 0#u32 np (by rfl)) ?_
  rintro v ⟨hv, hvl⟩
  refine WP.spec_bind (alloc.vec.from_elem_spec core.clone.CloneBool false np (by rfl)) ?_
  rintro v1 ⟨hv1, hv1l⟩
  refine WP.spec_bind (alloc.vec.from_elem_spec core.clone.CloneU32 0#u32 nl (by rfl)) ?_
  rintro v2 ⟨hv2, hv2l⟩
  refine WP.spec_bind (alloc.vec.from_elem_spec core.clone.CloneBool false nl (by rfl)) ?_
  rintro v3 ⟨hv3, hv3l⟩
  rw [if_pos (show Slice.len starts > Slice.len code by
    rw [gt_iff_lt, UScalar.lt_equiv]; simp only [Slice.len_val, Slice.length]; omega)]
  have hinv0 : LabelsInv code.val np.val nl.val 0 v v1 v2 v3 0#u32 false 0#u32 false 0#u32
      false 0#u32 false := by
    refine ⟨by simp [hv], by simp [hv1], by simp [hv2], by simp [hv3], ?_, ?_, rfl, rfl, rfl, rfl⟩
    · intro k hk; simp [hv1, hk, lastLoc]
    · intro k hk; simp [hv3, hk, lastLoc]
  refine WP.spec_bind (collect_labels_loop_spec code starts np nl (Slice.len code) v v1 v2 v3
    0#u32 false 0#u32 false 0#u32 false 0#u32 false 0#usize (by simp) (by simp) hstarts hsl
    hnp hnl (by simpa using hinv0)) ?_
  rintro ⟨v4, v5, v6, v7, e1, be1, rp1, brp1, dp1, bdp1, ht1, bht1⟩ hinv'
  exact WP.exists_imp_spec ⟨_, rfl, np.val, nl.val, hinv', hnp, hnl⟩

@[local simp] theorem i64_neg1 : ((-1)#i64).val = -1 := rfl

theorem locVal_of (b : Bool) (x : Std.U32) (l : Option Nat)
    (h : (if b then some x.val else none) = l) :
    (if b then (x.val : Int) else -1) = locVal l := by
  subst h; cases b <;> rfl

/-- **What `target_loc` answers**: exactly `labelLoc`, with `-1` for an unlabelled target. -/
def LabelsMatch (code : List x64_ir.PInsn) (labels : x64_encode.Labels) : Prop :=
  (∀ t : x64_ir.PTarget, ∃ w : Std.I64,
      x64_encode.target_loc labels t = ok w ∧ w.val = locVal (labelLoc code t)) ∧
  ((if labels.dispatcher_set then (labels.dispatcher.val : Int) else -1)
      = locVal (dispatcherLoc code)) ∧
  ((if labels.helper_table_set then (labels.helper_table.val : Int) else -1)
      = locVal (helperTableLoc code))

theorem labelsMatch_of_inv (code : List x64_ir.PInsn) (labels : x64_encode.Labels) (np nl : Nat)
    (hinv : LabelsInv code np nl code.length labels.pc labels.pc_set labels.local
      labels.local_set labels.exit labels.exit_set labels.retpoline labels.retpoline_set
      labels.dispatcher labels.dispatcher_set labels.helper_table labels.helper_table_set)
    (hnp : ∀ j < code.length, lkindTag code[j]! = 1 → lkindNum code[j]! < np)
    (hnl : ∀ j < code.length, lkindTag code[j]! = 2 → lkindNum code[j]! < nl) :
    LabelsMatch code labels := by
  obtain ⟨hvl, hv1l, hv2l, hv3l, hpc, hlc, he, hrp, hdp, hht⟩ := hinv
  refine ⟨?_, locVal_of _ _ _ hdp, locVal_of _ _ _ hht⟩
  intro t
  cases t with
  | Pc pc =>
    have hkv : (UScalar.cast .Usize pc : Usize).val = pc.val := by simp
    simp only [labelLoc]
    by_cases hlt : pc.val < np
    · have hb1 : (UScalar.cast .Usize pc : Usize) < alloc.vec.Vec.len labels.pc := by
        rw [UScalar.lt_equiv]
        simp only [alloc.vec.Vec.len_val, alloc.vec.Vec.length, hkv]; omega
      have hidx1 : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Bool)
          labels.pc_set (UScalar.cast .Usize pc) = ok labels.pc_set.val[pc.val]! := by
        rw [show labels.pc_set.val[pc.val]! = labels.pc_set.val[(UScalar.cast .Usize pc : Usize).val]!
          from by rw [hkv]]
        exact vec_index_eq _ _ (by rw [hkv]; omega)
      have hidx2 : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Std.U32)
          labels.pc (UScalar.cast .Usize pc) = ok labels.pc.val[pc.val]! := by
        rw [show labels.pc.val[pc.val]! = labels.pc.val[(UScalar.cast .Usize pc : Usize).val]!
          from by rw [hkv]]
        exact vec_index_eq _ _ (by rw [hkv]; omega)
      have hp := hpc pc.val hlt
      cases hbb : labels.pc_set.val[pc.val]! with
      | true =>
        refine ⟨UScalar.hcast .I64 labels.pc.val[pc.val]!, ?_, ?_⟩
        · simp only [x64_encode.target_loc, lift, bind_tc_ok]
          rw [if_pos hb1, hidx1, bind_tc_ok, if_pos hbb, hidx2, bind_tc_ok]
        · rw [u32_hcast_i64, ← hp, hbb]; rfl
      | false =>
        refine ⟨(-1)#i64, ?_, ?_⟩
        · simp only [x64_encode.target_loc, lift, bind_tc_ok]
          rw [if_pos hb1, hidx1, bind_tc_ok, if_neg (by rw [hbb]; simp)]
        · rw [← hp, hbb]; rfl
    · have hb1 : ¬ (UScalar.cast .Usize pc : Usize) < alloc.vec.Vec.len labels.pc := by
        rw [UScalar.lt_equiv]
        simp only [alloc.vec.Vec.len_val, alloc.vec.Vec.length, hkv]; omega
      refine ⟨(-1)#i64, ?_, ?_⟩
      · simp only [x64_encode.target_loc, lift, bind_tc_ok]
        rw [if_neg hb1]
      · rw [lastLoc_none code (isPcLabel pc.val) code.length ?_]
        · rfl
        · intro j hj
          cases hbb : isPcLabel pc.val code[j]! with
          | false => rfl
          | true =>
            obtain ⟨h1, h2⟩ := (isPcLabel_iff _ _).mp hbb
            exact absurd (h2 ▸ hnp j hj h1) hlt
  | Exit =>
    simp only [labelLoc]
    cases hb : labels.exit_set with
    | true =>
      exact ⟨UScalar.hcast .I64 labels.exit,
        by simp only [x64_encode.target_loc]; rw [if_pos hb],
        by rw [u32_hcast_i64, ← he, hb]; rfl⟩
    | false =>
      exact ⟨(-1)#i64, by simp only [x64_encode.target_loc]; rw [if_neg (by rw [hb]; simp)],
        by rw [← he, hb]; rfl⟩
  | Retpoline =>
    simp only [labelLoc]
    cases hb : labels.retpoline_set with
    | true =>
      exact ⟨UScalar.hcast .I64 labels.retpoline,
        by simp only [x64_encode.target_loc]; rw [if_pos hb],
        by rw [u32_hcast_i64, ← hrp, hb]; rfl⟩
    | false =>
      exact ⟨(-1)#i64, by simp only [x64_encode.target_loc]; rw [if_neg (by rw [hb]; simp)],
        by rw [← hrp, hb]; rfl⟩
  | Local ln =>
    have hkv : (UScalar.cast .Usize ln : Usize).val = ln.val := by simp
    simp only [labelLoc]
    by_cases hlt : ln.val < nl
    · have hb1 : (UScalar.cast .Usize ln : Usize) < alloc.vec.Vec.len labels.local := by
        rw [UScalar.lt_equiv]
        simp only [alloc.vec.Vec.len_val, alloc.vec.Vec.length, hkv]; omega
      have hidx1 : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Bool)
          labels.local_set (UScalar.cast .Usize ln) = ok labels.local_set.val[ln.val]! := by
        rw [show labels.local_set.val[ln.val]!
          = labels.local_set.val[(UScalar.cast .Usize ln : Usize).val]! from by rw [hkv]]
        exact vec_index_eq _ _ (by rw [hkv]; omega)
      have hidx2 : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Std.U32)
          labels.local (UScalar.cast .Usize ln) = ok labels.local.val[ln.val]! := by
        rw [show labels.local.val[ln.val]!
          = labels.local.val[(UScalar.cast .Usize ln : Usize).val]! from by rw [hkv]]
        exact vec_index_eq _ _ (by rw [hkv]; omega)
      have hp := hlc ln.val hlt
      cases hbb : labels.local_set.val[ln.val]! with
      | true =>
        refine ⟨UScalar.hcast .I64 labels.local.val[ln.val]!, ?_, ?_⟩
        · simp only [x64_encode.target_loc, lift, bind_tc_ok]
          rw [if_pos hb1, hidx1, bind_tc_ok, if_pos hbb, hidx2, bind_tc_ok]
        · rw [u32_hcast_i64, ← hp, hbb]; rfl
      | false =>
        refine ⟨(-1)#i64, ?_, ?_⟩
        · simp only [x64_encode.target_loc, lift, bind_tc_ok]
          rw [if_pos hb1, hidx1, bind_tc_ok, if_neg (by rw [hbb]; simp)]
        · rw [← hp, hbb]; rfl
    · have hb1 : ¬ (UScalar.cast .Usize ln : Usize) < alloc.vec.Vec.len labels.local := by
        rw [UScalar.lt_equiv]
        simp only [alloc.vec.Vec.len_val, alloc.vec.Vec.length, hkv]; omega
      refine ⟨(-1)#i64, ?_, ?_⟩
      · simp only [x64_encode.target_loc, lift, bind_tc_ok]
        rw [if_neg hb1]
      · rw [lastLoc_none code (isLocalLabel ln.val) code.length ?_]
        · rfl
        · intro j hj
          cases hbb : isLocalLabel ln.val code[j]! with
          | false => rfl
          | true =>
            obtain ⟨h1, h2⟩ := (isLocalLabel_iff _ _).mp hbb
            exact absurd (h2 ▸ hnl j hj h1) hlt

/-- **`patch` fills in the displacement `relocAt` names.** -/
theorem patch_spec (labels : x64_encode.Labels) (code : List x64_ir.PInsn)
    (hlab : LabelsMatch code labels)
    (out : alloc.vec.Vec Std.U8) (base here : Usize) (A : List Std.U8) (p : x64_ir.PInsn)
    (hval : out.val = A ++ enc p)
    (hA : A.length = base.val + here.val)
    (hlenp : here.val + encLen p ≤ totalLen code)
    (hfit : totalLen code < 2 ^ 32)
    (hmax : out.val.length ≤ Usize.max) :
    x64_encode.patch labels out base here p ⦃ r =>
      match relocAt code here.val p with
      | .ok b => r.1 = x64_encode.ERR_NONE ∧ r.2.val = A ++ b
      | .error e => r.1 = errCode e ∧ r.2 = out ⦄ := by
  have hp32 : (2 : Nat) ^ 32 = 4294967296 := by norm_num
  have hdisp : ∃ w : Std.I64,
      (if labels.dispatcher_set then ok (UScalar.hcast .I64 labels.dispatcher)
        else ok ((-1)#i64)) = ok w ∧ w.val = locVal (dispatcherLoc code) := by
    obtain ⟨-, hd, -⟩ := hlab
    cases hb : labels.dispatcher_set with
    | true => exact ⟨_, if_pos rfl, by rw [u32_hcast_i64, ← hd, hb]; rfl⟩
    | false => exact ⟨_, if_neg (by simp), by rw [← hd, hb]; rfl⟩
  have hhelp : ∃ w : Std.I64,
      (if labels.helper_table_set then ok (UScalar.hcast .I64 labels.helper_table)
        else ok ((-1)#i64)) = ok w ∧ w.val = locVal (helperTableLoc code) := by
    obtain ⟨-, -, hd⟩ := hlab
    cases hb : labels.helper_table_set with
    | true => exact ⟨_, if_pos rfl, by rw [u32_hcast_i64, ← hd, hb]; rfl⟩
    | false => exact ⟨_, if_neg (by simp), by rw [← hd, hb]; rfl⟩
  cases p
  case Jcc cc t =>
    have hn : encLen (x64_ir.PInsn.Jcc cc t) = 6 := by simp [encLen, enc, u32L]
    rw [hn] at hlenp
    have hout : out.val.length = A.length + 6 := by rw [hval]; simp [enc, u32L]
    obtain ⟨wv, hwv, hwvv⟩ := hlab.1 t
    obtain ⟨st, hst, hstv0⟩ := usize_add_ok (x := here) (y := 2#usize) (by simp; omega)
    have hstv : st.val = here.val + 2 := by simpa using hstv0
    have hvv : out.val = (A ++ [15#u8, cc]) ++ u32L 0#u32 ++ [] := by rw [hval]; simp [enc]
    simp only [x64_encode.patch, hwv, hst, bind_tc_ok]
    refine WP.spec_mono (write_rel32_spec out base st wv (A ++ [15#u8, cc]) [] 0#u32 (labelLoc code t)
      hvv (by simp; omega) (by omega) (by omega)
      (fun x hx => lt_of_le_of_lt (labelLoc_le code _ x hx) hfit) hwvv) ?_
    rintro ⟨err, o⟩ hr
    rw [hstv] at hr
    simp only [relocAt, Except.map]
    cases hrb : rel32Bytes (labelLoc code t) (here.val + 2) with
    | error ee => rw [hrb] at hr; exact ⟨hr.1, hr.2⟩
    | ok d => rw [hrb] at hr; exact ⟨hr.1, by rw [hr.2]; simp⟩
  case Jmp t =>
    have hn : encLen (x64_ir.PInsn.Jmp t) = 5 := by simp [encLen, enc, u32L]
    rw [hn] at hlenp
    have hout : out.val.length = A.length + 5 := by rw [hval]; simp [enc, u32L]
    obtain ⟨wv, hwv, hwvv⟩ := hlab.1 t
    obtain ⟨st, hst, hstv0⟩ := usize_add_ok (x := here) (y := 1#usize) (by simp; omega)
    have hstv : st.val = here.val + 1 := by simpa using hstv0
    have hvv : out.val = (A ++ [233#u8]) ++ u32L 0#u32 ++ [] := by rw [hval]; simp [enc]
    simp only [x64_encode.patch, hwv, hst, bind_tc_ok]
    refine WP.spec_mono (write_rel32_spec out base st wv (A ++ [233#u8]) [] 0#u32 (labelLoc code t)
      hvv (by simp; omega) (by omega) (by omega)
      (fun x hx => lt_of_le_of_lt (labelLoc_le code _ x hx) hfit) hwvv) ?_
    rintro ⟨err, o⟩ hr
    rw [hstv] at hr
    simp only [relocAt, Except.map]
    cases hrb : rel32Bytes (labelLoc code t) (here.val + 1) with
    | error ee => rw [hrb] at hr; exact ⟨hr.1, hr.2⟩
    | ok d => rw [hrb] at hr; exact ⟨hr.1, by rw [hr.2]; simp⟩
  case Call t =>
    have hn : encLen (x64_ir.PInsn.Call t) = 5 := by simp [encLen, enc, u32L]
    rw [hn] at hlenp
    have hout : out.val.length = A.length + 5 := by rw [hval]; simp [enc, u32L]
    obtain ⟨wv, hwv, hwvv⟩ := hlab.1 t
    obtain ⟨st, hst, hstv0⟩ := usize_add_ok (x := here) (y := 1#usize) (by simp; omega)
    have hstv : st.val = here.val + 1 := by simpa using hstv0
    have hvv : out.val = (A ++ [232#u8]) ++ u32L 0#u32 ++ [] := by rw [hval]; simp [enc]
    simp only [x64_encode.patch, hwv, hst, bind_tc_ok]
    refine WP.spec_mono (write_rel32_spec out base st wv (A ++ [232#u8]) [] 0#u32 (labelLoc code t)
      hvv (by simp; omega) (by omega) (by omega)
      (fun x hx => lt_of_le_of_lt (labelLoc_le code _ x hx) hfit) hwvv) ?_
    rintro ⟨err, o⟩ hr
    rw [hstv] at hr
    simp only [relocAt, Except.map]
    cases hrb : rel32Bytes (labelLoc code t) (here.val + 1) with
    | error ee => rw [hrb] at hr; exact ⟨hr.1, hr.2⟩
    | ok d => rw [hrb] at hr; exact ⟨hr.1, by rw [hr.2]; simp⟩
  case RipLoadDispatcher dst =>
    have hn : encLen (x64_ir.PInsn.RipLoadDispatcher dst) = 7 := by simp [encLen, enc, u32L]
    rw [hn] at hlenp
    have hout : out.val.length = A.length + 7 := by rw [hval]; simp [enc, u32L]
    obtain ⟨wv, hwv, hwvv⟩ := hdisp
    obtain ⟨st, hst, hstv0⟩ := usize_add_ok (x := here) (y := 3#usize) (by simp; omega)
    have hstv : st.val = here.val + 3 := by simpa using hstv0
    have hvv : out.val = (A ++ [rexByte 1#u8 0#u8 0#u8 0#u8, 139#u8, modrmB 0#u8 dst 5#u8]) ++ u32L 0#u32 ++ [] := by rw [hval]; simp [enc]
    simp only [x64_encode.patch, hwv, hst, bind_tc_ok]
    refine WP.spec_mono (write_rel32_spec out base st wv (A ++ [rexByte 1#u8 0#u8 0#u8 0#u8, 139#u8, modrmB 0#u8 dst 5#u8]) [] 0#u32 (dispatcherLoc code)
      hvv (by simp; omega) (by omega) (by omega)
      (fun x hx => lt_of_le_of_lt (firstLoc_le code _ _ x hx) hfit) hwvv) ?_
    rintro ⟨err, o⟩ hr
    rw [hstv] at hr
    simp only [relocAt, Except.map]
    cases hrb : rel32Bytes (dispatcherLoc code) (here.val + 3) with
    | error ee => rw [hrb] at hr; exact ⟨hr.1, hr.2⟩
    | ok d => rw [hrb] at hr; exact ⟨hr.1, by rw [hr.2]; simp⟩
  case RipLeaHelperTable dst =>
    have hn : encLen (x64_ir.PInsn.RipLeaHelperTable dst) = 7 := by simp [encLen, enc, u32L]
    rw [hn] at hlenp
    have hout : out.val.length = A.length + 7 := by rw [hval]; simp [enc, u32L]
    obtain ⟨wv, hwv, hwvv⟩ := hhelp
    obtain ⟨st, hst, hstv0⟩ := usize_add_ok (x := here) (y := 3#usize) (by simp; omega)
    have hstv : st.val = here.val + 3 := by simpa using hstv0
    have hvv : out.val = (A ++ [rexByte 1#u8 (highU dst) 0#u8 0#u8, 141#u8, modrmB 0#u8 dst 5#u8]) ++ u32L 0#u32 ++ [] := by rw [hval]; simp [enc]
    simp only [x64_encode.patch, hwv, hst, bind_tc_ok]
    refine WP.spec_mono (write_rel32_spec out base st wv (A ++ [rexByte 1#u8 (highU dst) 0#u8 0#u8, 141#u8, modrmB 0#u8 dst 5#u8]) [] 0#u32 (helperTableLoc code)
      hvv (by simp; omega) (by omega) (by omega)
      (fun x hx => lt_of_le_of_lt (firstLoc_le code _ _ x hx) hfit) hwvv) ?_
    rintro ⟨err, o⟩ hr
    rw [hstv] at hr
    simp only [relocAt, Except.map]
    cases hrb : rel32Bytes (helperTableLoc code) (here.val + 3) with
    | error ee => rw [hrb] at hr; exact ⟨hr.1, hr.2⟩
    | ok d => rw [hrb] at hr; exact ⟨hr.1, by rw [hr.2]; simp⟩
  case JmpNear t =>
    have hn : encLen (x64_ir.PInsn.JmpNear t) = 5 := by simp [encLen, enc, u32L]
    rw [hn] at hlenp
    have hout : out.val.length = A.length + 5 := by rw [hval]; simp [enc, u32L]
    obtain ⟨wv, hwv, hwvv⟩ := hlab.1 t
    obtain ⟨st, hst, hstv0⟩ := usize_add_ok (x := here) (y := 1#usize) (by simp; omega)
    have hstv : st.val = here.val + 1 := by simpa using hstv0
    have hvv : out.val = (A ++ [235#u8]) ++ 0#u8 :: ([0#u8, 0#u8, 0#u8]) := by rw [hval]; simp [enc, u32L_zero]
    simp only [x64_encode.patch, hwv, hst, bind_tc_ok]
    refine WP.spec_mono (write_rel8_spec out base st wv (A ++ [235#u8]) ([0#u8, 0#u8, 0#u8]) 0#u8 (labelLoc code t)
      hvv (by simp; omega) (by omega) (by omega)
      (fun x hx => lt_of_le_of_lt (labelLoc_le code _ x hx) hfit) hwvv) ?_
    rintro ⟨err, o⟩ hr
    rw [hstv] at hr
    simp only [relocAt, Except.map]
    cases hrb : rel8Byte (labelLoc code t) (here.val + 1) with
    | error ee => rw [hrb] at hr; exact ⟨hr.1, hr.2⟩
    | ok d => rw [hrb] at hr; exact ⟨hr.1, by rw [hr.2]; simp⟩
  case Jcc8 cc t =>
    have hn : encLen (x64_ir.PInsn.Jcc8 cc t) = 2 := by simp [encLen, enc, u32L]
    rw [hn] at hlenp
    have hout : out.val.length = A.length + 2 := by rw [hval]; simp [enc, u32L]
    obtain ⟨wv, hwv, hwvv⟩ := hlab.1 (x64_ir.PTarget.Local t)
    obtain ⟨st, hst, hstv0⟩ := usize_add_ok (x := here) (y := 1#usize) (by simp; omega)
    have hstv : st.val = here.val + 1 := by simpa using hstv0
    have hvv : out.val = (A ++ [112#u8 ||| (cc &&& 15#u8)]) ++ 0#u8 :: ([]) := by rw [hval]; simp [enc, u32L_zero]
    simp only [x64_encode.patch, hwv, hst, bind_tc_ok]
    refine WP.spec_mono (write_rel8_spec out base st wv (A ++ [112#u8 ||| (cc &&& 15#u8)]) ([]) 0#u8 (labelLoc code (x64_ir.PTarget.Local t))
      hvv (by simp; omega) (by omega) (by omega)
      (fun x hx => lt_of_le_of_lt (labelLoc_le code _ x hx) hfit) hwvv) ?_
    rintro ⟨err, o⟩ hr
    rw [hstv] at hr
    simp only [relocAt, Except.map]
    cases hrb : rel8Byte (labelLoc code (x64_ir.PTarget.Local t)) (here.val + 1) with
    | error ee => rw [hrb] at hr; exact ⟨hr.1, hr.2⟩
    | ok d => rw [hrb] at hr; exact ⟨hr.1, by rw [hr.2]; simp⟩
  case Jmp8 t =>
    have hn : encLen (x64_ir.PInsn.Jmp8 t) = 2 := by simp [encLen, enc, u32L]
    rw [hn] at hlenp
    have hout : out.val.length = A.length + 2 := by rw [hval]; simp [enc, u32L]
    obtain ⟨wv, hwv, hwvv⟩ := hlab.1 (x64_ir.PTarget.Local t)
    obtain ⟨st, hst, hstv0⟩ := usize_add_ok (x := here) (y := 1#usize) (by simp; omega)
    have hstv : st.val = here.val + 1 := by simpa using hstv0
    have hvv : out.val = (A ++ [235#u8]) ++ 0#u8 :: ([]) := by rw [hval]; simp [enc, u32L_zero]
    simp only [x64_encode.patch, hwv, hst, bind_tc_ok]
    refine WP.spec_mono (write_rel8_spec out base st wv (A ++ [235#u8]) ([]) 0#u8 (labelLoc code (x64_ir.PTarget.Local t))
      hvv (by simp; omega) (by omega) (by omega)
      (fun x hx => lt_of_le_of_lt (labelLoc_le code _ x hx) hfit) hwvv) ?_
    rintro ⟨err, o⟩ hr
    rw [hstv] at hr
    simp only [relocAt, Except.map]
    cases hrb : rel8Byte (labelLoc code (x64_ir.PTarget.Local t)) (here.val + 1) with
    | error ee => rw [hrb] at hr; exact ⟨hr.1, hr.2⟩
    | ok d => rw [hrb] at hr; exact ⟨hr.1, by rw [hr.2]; simp⟩
  all_goals exact WP.exists_imp_spec ⟨_, rfl, rfl, hval⟩

/-! ### The main loop -/

@[local simp] theorem err_none_val : x64_encode.ERR_NONE.val = 0 := by
  unfold x64_encode.ERR_NONE; rfl

@[local simp] theorem err_missing_val : x64_encode.ERR_MISSING.val = 1 := by
  unfold x64_encode.ERR_MISSING; rfl

@[local simp] theorem err_range_val : x64_encode.ERR_RANGE.val = 2 := by
  unfold x64_encode.ERR_RANGE; rfl

theorem errCode_ne_none (e : RelErr) : ¬ errCode e = x64_encode.ERR_NONE := by
  cases e <;> (rw [UScalar.eq_equiv]; simp [errCode])

theorem relocAux_succ (code : List x64_ir.PInsn) (m : Nat) :
    relocAux code (m + 1)
      = match relocAux code m, relocOne code m with
        | .ok a, .ok b => .ok (a ++ b)
        | .error e, _ => .error e
        | _, .error e => .error e := rfl

theorem relocAux_error_mono (code : List x64_ir.PInsn) (m m' : Nat) (e : RelErr)
    (h : relocAux code m = .error e) (hm : m ≤ m') : relocAux code m' = .error e := by
  induction m' with
  | zero => have hz : m = 0 := by omega
            subst hz; exact h
  | succ k ih =>
    rcases Nat.lt_or_ge k m with hk | hk
    · have hz : m = k + 1 := by omega
      subst hz; exact h
    · rw [relocAux_succ, ih hk]

theorem relocAux_length (code : List x64_ir.PInsn) (m : Nat) (b : List Std.U8)
    (hm : m ≤ code.length) (h : relocAux code m = .ok b) :
    b.length = totalLen (code.take m) := by
  induction m generalizing b with
  | zero => simp [relocAux] at h; subst h; simp [totalLen]
  | succ k ih =>
    rw [relocAux_succ] at h
    cases hk : relocAux code k with
    | error e => rw [hk] at h; simp at h
    | ok a =>
      cases hb : relocOne code k with
      | error e => rw [hk, hb] at h; simp at h
      | ok bi =>
        rw [hk, hb] at h
        simp only [Except.ok.injEq] at h
        subst h
        rw [List.length_append, ih a (by omega) hk, relocOne_length code k hb,
          totalLen_take_succ code k (by omega)]

theorem relocAux_split (code : List x64_ir.PInsn) (m i : Nat) (b : List Std.U8)
    (hi : i < m) (hm : m ≤ code.length) (h : relocAux code m = .ok b) :
    ∃ a c bi, b = a ++ bi ++ c ∧ a.length = totalLen (code.take i) ∧
      relocOne code i = .ok bi := by
  induction m generalizing b with
  | zero => omega
  | succ k ih =>
    rw [relocAux_succ] at h
    cases hk : relocAux code k with
    | error e => rw [hk] at h; simp at h
    | ok a =>
      cases hb : relocOne code k with
      | error e => rw [hk, hb] at h; simp at h
      | ok bi =>
        rw [hk, hb] at h
        simp only [Except.ok.injEq] at h
        subst h
        rcases Nat.lt_or_ge i k with hik | hik
        · obtain ⟨a', c', bi', ha, hal, hr⟩ := ih a hik (by omega) hk
          exact ⟨a', c' ++ bi, bi', by rw [ha]; simp, hal, hr⟩
        · have hie : i = k := by omega
          subst hie
          exact ⟨a, [], bi, by simp, relocAux_length code i a (by omega) hk, hb⟩

theorem assemble_body_done_i
    (code : Slice x64_ir.PInsn) (starts : alloc.vec.Vec Std.U32) (labels : x64_encode.Labels)
    (base n : Usize) (out : alloc.vec.Vec Std.U8) (err : Std.U32) (i : Usize)
    (h : n.val ≤ i.val) :
    x64_encode.assemble_loop.body code starts labels base n out err i = ok (.done (out, err)) := by
  unfold x64_encode.assemble_loop.body
  rw [if_neg (by rw [UScalar.lt_equiv]; omega)]

theorem assemble_body_done_e
    (code : Slice x64_ir.PInsn) (starts : alloc.vec.Vec Std.U32) (labels : x64_encode.Labels)
    (base n : Usize) (out : alloc.vec.Vec Std.U8) (err : Std.U32) (i : Usize)
    (h : ¬ err = x64_encode.ERR_NONE) :
    x64_encode.assemble_loop.body code starts labels base n out err i = ok (.done (out, err)) := by
  unfold x64_encode.assemble_loop.body
  by_cases hi : i < n
  · rw [if_pos hi, if_neg h]
  · rw [if_neg hi]

theorem assemble_body_cont
    (code : Slice x64_ir.PInsn) (starts : alloc.vec.Vec Std.U32) (labels : x64_encode.Labels)
    (base n : Usize) (out0 out : alloc.vec.Vec Std.U8) (i : Usize) (b : List Std.U8)
    (hn : n.val = code.val.length) (hi : i.val < code.val.length)
    (hbase : base.val = out0.val.length)
    (hstarts : ∀ j ≤ code.val.length, (starts.val[j]!).val = totalLen (code.val.take j))
    (hsl : code.val.length < starts.val.length)
    (hlab : LabelsMatch code.val labels)
    (hfit : totalLen code.val < 2 ^ 32)
    (hroom : out0.val.length + totalLen code.val + 512 ≤ Usize.max)
    (hb : relocAux code.val i.val = .ok b) (houtv : out.val = out0.val ++ b) :
    ∃ (out2 : alloc.vec.Vec Std.U8) (err1 : Std.U32) (i2 : Usize),
      x64_encode.assemble_loop.body code starts labels base n out x64_encode.ERR_NONE i
        = ok (.cont (out2, err1, i2)) ∧ i2.val = i.val + 1 ∧
      ((err1 = x64_encode.ERR_NONE ∧ ∃ b', relocAux code.val (i.val + 1) = .ok b' ∧
          out2.val = out0.val ++ b')
        ∨ (∃ e, err1 = errCode e ∧ relocAux code.val (i.val + 1) = .error e)) := by
  have hcl : code.val.length ≤ Usize.max := code.property
  have hblen : b.length = totalLen (code.val.take i.val) :=
    relocAux_length code.val i.val b (by omega) hb
  have htl : totalLen (code.val.take i.val) + encLen code.val[i.val]! ≤ totalLen code.val := by
    have h1 := totalLen_take_succ code.val i.val hi
    have h2 := totalLen_take_le code.val (i.val + 1)
    omega
  have houtlen : out.val.length = out0.val.length + totalLen (code.val.take i.val) := by
    rw [houtv]; simp [hblen]
  obtain ⟨out1, ho1, ho1v⟩ := WP.spec_imp_exists
    (encode_one_spec code.val[i.val]! out (by omega))
  have ho1len : out1.val.length = out0.val.length + totalLen (code.val.take i.val)
      + encLen code.val[i.val]! := by
    rw [ho1v]; simp [houtlen, encLen]
  have hidx : Slice.index_usize code i = ok code.val[i.val]! := slice_idx_eq (by omega)
  have hsidx : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Std.U32) starts i
      = ok starts.val[i.val]! := vec_index_eq _ _ (by omega)
  have hherev : (UScalar.cast .Usize starts.val[i.val]! : Usize).val
      = totalLen (code.val.take i.val) := by
    rw [UScalar.cast_val_mod_pow_of_inBounds_eq]
    · exact hstarts i.val (by omega)
    · have := hstarts i.val (by omega)
      have h2 := totalLen_take_le code.val i.val
      have := (starts.val[i.val]!).hBounds
      scalar_tac
  obtain ⟨⟨err1, out2⟩, hpatch, hpost⟩ := WP.spec_imp_exists
    (patch_spec labels code.val hlab out1 base (UScalar.cast .Usize starts.val[i.val]!)
      (out0.val ++ b) code.val[i.val]! (by rw [ho1v, houtv])
      (by simp [hblen, hbase]; simpa using (hstarts i.val (by omega)).symm)
      (by rw [hherev]; exact htl) hfit (by omega))
  obtain ⟨i2, hi2, hi2v0⟩ := usize_add_ok (x := i) (y := 1#usize) (by simp; omega)
  have hi2v : i2.val = i.val + 1 := by simpa using hi2v0
  have hro : relocAt code.val (UScalar.cast .Usize starts.val[i.val]! : Usize).val
      code.val[i.val]! = relocOne code.val i.val := by rw [hherev]; rfl
  refine ⟨out2, err1, i2, ?_, hi2v, ?_⟩
  · unfold x64_encode.assemble_loop.body
    rw [if_pos (show i < n by rw [UScalar.lt_equiv]; omega), if_pos rfl]
    simp only [hidx, hsidx, ho1, hpatch, hi2, bind_tc_ok, lift]
    rfl
  · rw [hro] at hpost
    cases hr : relocOne code.val i.val with
    | error e =>
      rw [hr] at hpost
      exact Or.inr ⟨e, hpost.1, by rw [relocAux_succ, hb, hr]⟩
    | ok bi =>
      rw [hr] at hpost
      exact Or.inl ⟨hpost.1, b ++ bi, by rw [relocAux_succ, hb, hr], by rw [hpost.2]; simp⟩

@[local simp] theorem vec_deref_val {α : Type} (v : alloc.vec.Vec α) :
    (alloc.vec.Vec.deref v).val = v.val := by simp [alloc.vec.Vec.deref]

/-- **The assembler's loop appends `relocated`, or stops at the first refusal.** -/
theorem assemble_loop_spec
    (code : Slice x64_ir.PInsn) (starts : alloc.vec.Vec Std.U32) (labels : x64_encode.Labels)
    (base n : Usize) (out0 out : alloc.vec.Vec Std.U8) (err : Std.U32) (i : Usize)
    (hn : n.val = code.val.length) (hi : i.val ≤ code.val.length)
    (hbase : base.val = out0.val.length)
    (hstarts : ∀ j ≤ code.val.length, (starts.val[j]!).val = totalLen (code.val.take j))
    (hsl : code.val.length < starts.val.length)
    (hlab : LabelsMatch code.val labels)
    (hfit : totalLen code.val < 2 ^ 32)
    (hroom : out0.val.length + totalLen code.val + 512 ≤ Usize.max)
    (hinv : (err = x64_encode.ERR_NONE ∧ ∃ b, relocAux code.val i.val = .ok b ∧
              out.val = out0.val ++ b)
        ∨ (∃ e, err = errCode e ∧ relocAux code.val i.val = .error e)) :
    x64_encode.assemble_loop code out starts labels base n err i ⦃ r =>
      (r.2 = x64_encode.ERR_NONE ∧ ∃ b, relocated code.val = .ok b ∧ r.1.val = out0.val ++ b)
      ∨ (∃ e, r.2 = errCode e ∧ relocated code.val = .error e) ⦄ := by
  generalize hd : code.val.length - i.val = d
  induction d generalizing out err i with
  | zero =>
    have hie : i.val = code.val.length := by omega
    rw [show x64_encode.assemble_loop code out starts labels base n err i = ok (out, err) from
      loop_done _ _ _ (assemble_body_done_i code starts labels base n out err i (by omega))]
    refine WP.exists_imp_spec ⟨_, rfl, ?_⟩
    rcases hinv with ⟨he, b, hb, hov⟩ | ⟨e, he, hb⟩
    · exact Or.inl ⟨he, b, by rw [relocated, ← hie]; exact hb, hov⟩
    · exact Or.inr ⟨e, he, by rw [relocated, ← hie]; exact hb⟩
  | succ d ih =>
    have hilt : i.val < code.val.length := by omega
    rcases hinv with ⟨he, b, hb, hov⟩ | ⟨e, he, hb⟩
    · obtain ⟨out2, err1, i2, hbody, hi2v, hnext⟩ :=
        assemble_body_cont code starts labels base n out0 out i b hn hilt hbase hstarts hsl
          hlab hfit hroom hb hov
      rw [he, show x64_encode.assemble_loop code out starts labels base n x64_encode.ERR_NONE i
          = x64_encode.assemble_loop code out2 starts labels base n err1 i2 from
        loop_step _ _ _ hbody]
      exact ih out2 err1 i2 (by omega) (by rw [hi2v]; exact hnext) (by omega)
    · rw [show x64_encode.assemble_loop code out starts labels base n err i = ok (out, err) from
        loop_done _ _ _ (assemble_body_done_e code starts labels base n out err i
          (by rw [he]; exact errCode_ne_none e))]
      exact WP.exists_imp_spec ⟨_, rfl, Or.inr ⟨e, he,
        relocAux_error_mono code.val i.val code.val.length e hb (by omega)⟩⟩

/-! ## The whole assembler -/

/-- **`assemble code out` appends `relocated code` to `out`**, and returns the
error `relocated` names when it has one: `MissingLabel` when a branch names a
label the list never defines, `RelocationOutOfRange` when a `rel8`
displacement does not fit in a byte. -/
theorem assemble_spec (code : Slice x64_ir.PInsn) (out : alloc.vec.Vec Std.U8)
    (hfit : totalLen code.val < 2 ^ 32)
    (hroom : out.val.length + totalLen code.val + 512 ≤ Usize.max)
    (hn : code.val.length < Usize.max)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max) :
    x64_encode.assemble code out ⦃ r =>
      match r.1 with
      | .Ok _ => ∃ bytes, relocated code.val = .ok bytes ∧ r.2.val = out.val ++ bytes ∧
          bytes.length = totalLen code.val
      | .Err .MissingLabel => relocated code.val = .error .missing
      | .Err .RelocationOutOfRange => relocated code.val = .error .range ⦄ := by
  have hp32 : (2 : Nat) ^ 32 = 4294967296 := by norm_num
  unfold x64_encode.assemble
  refine WP.spec_bind (offsets_spec code (alloc.vec.Vec.new Std.U32) rfl hfit (by omega) hn) ?_
  rintro starts ⟨hslen, hstarts⟩
  refine WP.spec_bind (collect_labels_spec code (alloc.vec.Vec.deref starts)
    (by simpa using hstarts) (by simp; omega) hnum) ?_
  rintro labels ⟨np, nl, hinv, hnp, hnl⟩
  rw [if_pos (show alloc.vec.Vec.len starts > Slice.len code by
    rw [gt_iff_lt, UScalar.lt_equiv]
    simp only [alloc.vec.Vec.len_val, alloc.vec.Vec.length, Slice.len_val, Slice.length]
    omega)]
  have hlab : LabelsMatch code.val labels := labelsMatch_of_inv code.val labels np nl hinv hnp hnl
  refine WP.spec_bind (assemble_loop_spec code starts labels (alloc.vec.Vec.len out)
    (Slice.len code) out out x64_encode.ERR_NONE 0#usize (by simp) (by simp) (by simp)
    hstarts (by omega) hlab hfit hroom (Or.inl ⟨rfl, [], rfl, by simp⟩)) ?_
  have hne_nm : ¬ (x64_encode.ERR_NONE = x64_encode.ERR_MISSING) := by
    rw [UScalar.eq_equiv]; simp
  have hne_nr : ¬ (x64_encode.ERR_NONE = x64_encode.ERR_RANGE) := by rw [UScalar.eq_equiv]; simp
  have hne_rm : ¬ (x64_encode.ERR_RANGE = x64_encode.ERR_MISSING) := by
    rw [UScalar.eq_equiv]; simp
  rintro ⟨o1, err⟩ hres
  rcases hres with ⟨he, bs, hrel, hov⟩ | ⟨e, he, hrel⟩
  · have he' : err = x64_encode.ERR_NONE := he
    have hov' : o1.val = out.val ++ bs := hov
    refine WP.exists_imp_spec ⟨(core.result.Result.Ok (), o1),
      by simp [he', hne_nm, hne_nr], bs, hrel, hov', ?_⟩
    rw [← totalLen_take_all code.val code.val.length (le_refl _)]
    exact relocAux_length code.val code.val.length bs (le_refl _) hrel
  · have he' : err = errCode e := he
    cases e with
    | missing =>
      exact WP.exists_imp_spec
        ⟨(core.result.Result.Err x64_encode.AsmError.MissingLabel, o1),
          by simp [he', errCode], hrel⟩
    | range =>
      exact WP.exists_imp_spec
        ⟨(core.result.Result.Err x64_encode.AsmError.RelocationOutOfRange, o1),
          by simp [he', errCode, hne_rm], hrel⟩

/-! ## What a downstream proof needs -/

theorem rel32Bytes_isSome {loc : Option Nat} {site : Nat} {d : List Std.U8}
    (h : rel32Bytes loc site = .ok d) : loc.isSome := by
  unfold rel32Bytes at h; cases loc <;> simp_all

theorem rel8Byte_isSome {loc : Option Nat} {site : Nat} {d : Std.U8}
    (h : rel8Byte loc site = .ok d) : loc.isSome := by
  unfold rel8Byte at h; cases loc <;> simp_all

theorem rel8Byte_range {site l : Nat} {d : Std.U8} (h : rel8Byte (some l) site = .ok d) :
    -128 ≤ (l : Int) - ((site : Int) + 1) ∧ (l : Int) - ((site : Int) + 1) ≤ 127 := by
  simp only [rel8Byte] at h
  split at h
  · omega
  · simp at h

theorem relocAt_ok_reqLoc (code : List x64_ir.PInsn) (here : Nat) (p : x64_ir.PInsn)
    (bi : List Std.U8) (h : relocAt code here p = .ok bi) (l : Option Nat)
    (hq : reqLocAt code p = some l) : l.isSome := by
  cases p <;> simp only [relocAt, reqLocAt] at h hq <;>
    first
      | contradiction
      | (obtain ⟨d, hd, -⟩ := except_map_ok h
         injection hq with hq
         subst hq
         first | exact rel32Bytes_isSome hd | exact rel8Byte_isSome hd)

theorem relocAt_ok_rel8 (code : List x64_ir.PInsn) (here : Nat) (p : x64_ir.PInsn)
    (bi : List Std.U8) (h : relocAt code here p = .ok bi) (site l : Nat)
    (hq : rel8SiteAt code here p = some (site, some l)) :
    -128 ≤ (l : Int) - ((site : Int) + 1) ∧ (l : Int) - ((site : Int) + 1) ≤ 127 := by
  cases p <;> simp only [relocAt, rel8SiteAt] at h hq <;>
    first
      | contradiction
      | (obtain ⟨d, hd, -⟩ := except_map_ok h
         injection hq with hq
         injection hq with hq1 hq2
         subst hq1
         rw [hq2] at hd
         exact rel8Byte_range hd)

theorem relocOne_ok_reqLoc (code : List x64_ir.PInsn) (i : Nat) (bi : List Std.U8)
    (h : relocOne code i = .ok bi) (l : Option Nat) (hq : reqLoc code i = some l) :
    l.isSome :=
  relocAt_ok_reqLoc code (totalLen (code.take i)) code[i]! bi h l hq

theorem relocOne_ok_rel8 (code : List x64_ir.PInsn) (i : Nat) (bi : List Std.U8)
    (h : relocOne code i = .ok bi) (site l : Nat) (hq : rel8Site code i = some (site, some l)) :
    -128 ≤ (l : Int) - ((site : Int) + 1) ∧ (l : Int) - ((site : Int) + 1) ≤ 127 :=
  relocAt_ok_rel8 code (totalLen (code.take i)) code[i]! bi h site l hq

theorem assemble_ok (code : Slice x64_ir.PInsn) (out out' : alloc.vec.Vec Std.U8)
    (hfit : totalLen code.val < 2 ^ 32)
    (hroom : out.val.length + totalLen code.val + 512 ≤ Usize.max)
    (hn : code.val.length < Usize.max)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max)
    (hok : x64_encode.assemble code out = ok (core.result.Result.Ok (), out')) :
    ∃ bytes, relocated code.val = .ok bytes ∧ out'.val = out.val ++ bytes ∧
      bytes.length = totalLen code.val := by
  obtain ⟨r, hr, hP⟩ := WP.spec_imp_exists (assemble_spec code out hfit hroom hn hnum)
  rw [hok, ok.injEq] at hr
  subst hr
  exact hP

/-- **1. On success the appended region is `totalLen code` bytes long.** -/
theorem assemble_ok_length (code : Slice x64_ir.PInsn) (out out' : alloc.vec.Vec Std.U8)
    (hfit : totalLen code.val < 2 ^ 32)
    (hroom : out.val.length + totalLen code.val + 512 ≤ Usize.max)
    (hn : code.val.length < Usize.max)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max)
    (hok : x64_encode.assemble code out = ok (core.result.Result.Ok (), out')) :
    out'.val.length = out.val.length + totalLen code.val := by
  obtain ⟨bytes, -, hov, hbl⟩ := assemble_ok code out out' hfit hroom hn hnum hok
  rw [hov]; simp [hbl]

/-- **2. Primitive `i` sits at `out.length + totalLen (code.take i)` and holds
`relocOne code i` — `enc code[i]` with its displacement patched.** -/
theorem assemble_ok_bytes (code : Slice x64_ir.PInsn) (out out' : alloc.vec.Vec Std.U8)
    (hfit : totalLen code.val < 2 ^ 32)
    (hroom : out.val.length + totalLen code.val + 512 ≤ Usize.max)
    (hn : code.val.length < Usize.max)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max)
    (hok : x64_encode.assemble code out = ok (core.result.Result.Ok (), out'))
    (i : Nat) (hi : i < code.val.length) :
    ∃ pre bi suf, out'.val = pre ++ bi ++ suf ∧
      pre.length = out.val.length + totalLen (code.val.take i) ∧
      relocOne code.val i = .ok bi ∧ bi.length = encLen code.val[i]! := by
  obtain ⟨bytes, hrel, hov, -⟩ := assemble_ok code out out' hfit hroom hn hnum hok
  obtain ⟨a, c, bi, hb, hal, hone⟩ :=
    relocAux_split code.val code.val.length i bytes hi (le_refl _) hrel
  exact ⟨out.val ++ a, bi, c, by rw [hov, hb]; simp, by simp [hal], hone,
    relocOne_length code.val i hone⟩

/-- **3. Success implies every branch and RIP-relative form names a label the
list defines, and every `rel8` displacement fits in a byte.** -/
theorem assemble_ok_labels (code : Slice x64_ir.PInsn) (out out' : alloc.vec.Vec Std.U8)
    (hfit : totalLen code.val < 2 ^ 32)
    (hroom : out.val.length + totalLen code.val + 512 ≤ Usize.max)
    (hn : code.val.length < Usize.max)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max)
    (hok : x64_encode.assemble code out = ok (core.result.Result.Ok (), out')) :
    (∀ i < code.val.length, ∀ l, reqLoc code.val i = some l → l.isSome) ∧
    (∀ i < code.val.length, ∀ site l, rel8Site code.val i = some (site, some l) →
      -128 ≤ (l : Int) - ((site : Int) + 1) ∧ (l : Int) - ((site : Int) + 1) ≤ 127) := by
  obtain ⟨bytes, hrel, -, -⟩ := assemble_ok code out out' hfit hroom hn hnum hok
  constructor
  · intro i hi l hq
    obtain ⟨-, -, bi, -, -, hone⟩ :=
      relocAux_split code.val code.val.length i bytes hi (le_refl _) hrel
    exact relocOne_ok_reqLoc code.val i bi hone l hq
  · intro i hi site l hq
    obtain ⟨-, -, bi, -, -, hone⟩ :=
      relocAux_split code.val code.val.length i bytes hi (le_refl _) hrel
    exact relocOne_ok_rel8 code.val i bi hone site l hq

/-- **4. An unlabelled branch is a refusal.** The assembler never silently
resolves it to a displacement of zero, as the fixup pass this replaces did. -/
theorem assemble_missing_label (code : Slice x64_ir.PInsn) (out : alloc.vec.Vec Std.U8)
    (hfit : totalLen code.val < 2 ^ 32)
    (hroom : out.val.length + totalLen code.val + 512 ≤ Usize.max)
    (hn : code.val.length < Usize.max)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max)
    (i : Nat) (hi : i < code.val.length) (h : reqLoc code.val i = some none) :
    ¬ ∃ out', x64_encode.assemble code out = ok (core.result.Result.Ok (), out') := by
  rintro ⟨out', hok⟩
  obtain ⟨hl, -⟩ := assemble_ok_labels code out out' hfit hroom hn hnum hok
  have := hl i hi none h
  simp at this

/-- The sharper form: when the *first* failing site is an unlabelled branch,
the error is exactly `MissingLabel`. -/
theorem assemble_error_missing (code : Slice x64_ir.PInsn) (out : alloc.vec.Vec Std.U8)
    (hfit : totalLen code.val < 2 ^ 32)
    (hroom : out.val.length + totalLen code.val + 512 ≤ Usize.max)
    (hn : code.val.length < Usize.max)
    (hnum : ∀ j < code.val.length, lkindNum code.val[j]! < Usize.max)
    (h : relocated code.val = .error .missing) :
    ∃ out', x64_encode.assemble code out
      = ok (core.result.Result.Err x64_encode.AsmError.MissingLabel, out') := by
  obtain ⟨r, hr, hP⟩ := WP.spec_imp_exists (assemble_spec code out hfit hroom hn hnum)
  obtain ⟨res, o⟩ := r
  cases res with
  | Ok u =>
    obtain ⟨bytes, hrel, -, -⟩ := hP
    rw [h] at hrel; simp at hrel
  | Err e =>
    cases e with
    | MissingLabel => exact ⟨o, hr⟩
    | RelocationOutOfRange => rw [h] at hP; simp at hP

end X64Enc

end async_ebpf_verified

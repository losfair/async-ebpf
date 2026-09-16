import AsyncEbpf.AsyncEbpfVerified

/-!
# Byte-addressed memory

The memory the x86_64 machine model executes over: a total function from
64-bit addresses to bytes. `load` reads `n` of them little-endian, `store`
writes `n` of them; both are defined for every `n`, so no width is a special
case and the eight-byte forms the code generator uses are specialisations
rather than a separate definition.

The four lemmas below are what the safety proofs need of memory, and all four
are about *ranges*: reading back what was just written, reading across a write
that missed, and commuting two writes that miss each other. Disjointness is
stated on `toNat` with the hypothesis that neither range wraps past `2^64`,
which is how the entry contract states the layout of the regions; without it
"the range `[a, a + n)`" is not a range at all.
-/
namespace async_ebpf_verified

namespace X64

/-- Memory: every 64-bit address holds a byte. -/
abbrev Mem := BitVec 64 → BitVec 8

/-- Byte `i` of a natural number, little-endian. -/
def byteAt (x : Nat) (i : Nat) : BitVec 8 := BitVec.ofNat 8 (x / 2 ^ (8 * i))

/-- The value `n` little-endian bytes at `a` denote, as a natural number. -/
def loadNat : Nat → Mem → BitVec 64 → Nat
  | 0, _, _ => 0
  | n + 1, m, a => (m a).toNat + 256 * loadNat n m (a + 1#64)

/-- `n` bytes at `a`, little-endian. -/
def load (n : Nat) (m : Mem) (a : BitVec 64) : BitVec (8 * n) :=
  BitVec.ofNat (8 * n) (loadNat n m a)

/-- `v` written as `n` little-endian bytes at `a`. The bytes written are
exactly the addresses `x` with `(x - a).toNat < n`, which is the range
`[a, a + n)` and stays a set of `n` distinct addresses even where it wraps. -/
def store (n : Nat) (m : Mem) (a : BitVec 64) (v : BitVec (8 * n)) : Mem :=
  fun x => if (x - a).toNat < n then byteAt v.toNat (x - a).toNat else m x

/-! ## Ranges

`[b, b + n)` and the disjointness of two such ranges, on `toNat`. Every
statement below that mentions two ranges takes the hypothesis that neither
wraps past `2^64`, without which "the range `[b, b + n)`" is not a range.
-/

/-- The address `a` lies in `[b, b + n)`. -/
def InRange (b : BitVec 64) (n : Nat) (a : BitVec 64) : Prop :=
  b.toNat ≤ a.toNat ∧ a.toNat < b.toNat + n

/-- `[b₁, b₁ + n₁)` and `[b₂, b₂ + n₂)` do not meet. -/
def RangesDisjoint (b₁ : BitVec 64) (n₁ : Nat) (b₂ : BitVec 64) (n₂ : Nat) : Prop :=
  b₁.toNat + n₁ ≤ b₂.toNat ∨ b₂.toNat + n₂ ≤ b₁.toNat

theorem RangesDisjoint.symm {b₁ n₁ b₂ n₂} (h : RangesDisjoint b₁ n₁ b₂ n₂) :
    RangesDisjoint b₂ n₂ b₁ n₁ := Or.symm h

/-! ## Arithmetic -/

private theorem add_ofNat_succ (a : BitVec 64) (i : Nat) :
    a + 1#64 + BitVec.ofNat 64 i = a + BitVec.ofNat 64 (i + 1) := by
  apply BitVec.eq_of_toNat_eq
  simp only [BitVec.toNat_add, BitVec.toNat_ofNat, Nat.mod_add_mod, Nat.add_mod_mod]
  congr 1
  omega

private theorem add_sub_self (a b : BitVec 64) : a + b - a = b := by ring

/-- Splitting a residue at a byte boundary. -/
private theorem mod_mul_split (x k : Nat) :
    x % (256 * k) = x % 256 + 256 * (x / 256 % k) := by
  have h1 : x % (256 * k) % 256 = x % 256 := Nat.mod_mod_of_dvd x ⟨k, rfl⟩
  have h2 : x % (256 * k) / 256 = x / 256 % k := Nat.mod_mul_right_div_self x 256 k
  omega

/-- The address `n` bytes above `a`, when the range does not wrap. -/
private theorem toNat_add_ofNat {a : BitVec 64} {i : Nat} (h : a.toNat + i < 2 ^ 64) :
    (a + BitVec.ofNat 64 i).toNat = a.toNat + i := by
  have hlt := a.isLt
  rw [BitVec.toNat_add, BitVec.toNat_ofNat]
  omega

/-! ## Reading bytes -/

/-- A load only reads the `n` bytes of its range. -/
theorem loadNat_congr : ∀ (n : Nat) (m₁ m₂ : Mem) (a : BitVec 64),
    (∀ i < n, m₁ (a + BitVec.ofNat 64 i) = m₂ (a + BitVec.ofNat 64 i)) →
    loadNat n m₁ a = loadNat n m₂ a
  | 0, _, _, _, _ => rfl
  | n + 1, m₁, m₂, a, h => by
    have h0 : m₁ a = m₂ a := by
      have := h 0 (Nat.succ_pos n)
      simpa using this
    have hrest : ∀ i < n, m₁ (a + 1#64 + BitVec.ofNat 64 i)
        = m₂ (a + 1#64 + BitVec.ofNat 64 i) := by
      intro i hi
      rw [add_ofNat_succ]
      exact h (i + 1) (by omega)
    simp [loadNat, h0, loadNat_congr n m₁ m₂ (a + 1#64) hrest]

/-- A load of bytes that spell out `x` reads `x` back, modulo its width. -/
theorem loadNat_eq : ∀ (n : Nat) (m : Mem) (a : BitVec 64) (x : Nat),
    (∀ i < n, m (a + BitVec.ofNat 64 i) = byteAt x i) →
    loadNat n m a = x % 2 ^ (8 * n)
  | 0, _, _, x, _ => by
    simp only [loadNat, Nat.mul_zero, pow_zero, Nat.mod_one]
  | n + 1, m, a, x, h => by
    have h0 : m a = BitVec.ofNat 8 x := by
      have := h 0 (Nat.succ_pos n)
      simpa [byteAt] using this
    have hrest : ∀ i < n, m (a + 1#64 + BitVec.ofNat 64 i) = byteAt (x / 256) i := by
      intro i hi
      rw [add_ofNat_succ]
      rw [h (i + 1) (by omega)]
      simp only [byteAt]
      congr 1
      rw [Nat.div_div_eq_div_mul]
      congr 1
      rw [show (8 : Nat) * (i + 1) = 8 * i + 8 by ring, pow_add]
      ring
    have hIH := loadNat_eq n m (a + 1#64) (x / 256) hrest
    have hw : (8 : Nat) * (n + 1) = 8 * n + 8 := by ring
    rw [loadNat, h0, hIH, hw, pow_add]
    have : (2 : Nat) ^ 8 = 256 := by norm_num
    rw [this, show (2:Nat) ^ (8 * n) * 256 = 256 * 2 ^ (8 * n) by ring,
      mod_mul_split x (2 ^ (8 * n))]
    simp [BitVec.toNat_ofNat]

/-! ## The lemmas the proofs use -/

/-- A store is read back by a load of the same range. -/
theorem load_store_same (n : Nat) (m : Mem) (a : BitVec 64) (v : BitVec (8 * n))
    (hn : n ≤ 2 ^ 64) : load n (store n m a v) a = v := by
  have hb : ∀ i < n, store n m a v (a + BitVec.ofNat 64 i) = byteAt v.toNat i := by
    intro i hi
    have hsub : a + BitVec.ofNat 64 i - a = BitVec.ofNat 64 i := add_sub_self _ _
    have hi' : (BitVec.ofNat 64 i).toNat = i := by
      rw [BitVec.toNat_ofNat]; exact Nat.mod_eq_of_lt (by omega)
    simp only [store, hsub, hi']
    rw [if_pos hi]
  apply BitVec.eq_of_toNat_eq
  have hv : v.toNat % 2 ^ (8 * n) = v.toNat := Nat.mod_eq_of_lt v.isLt
  rw [load, BitVec.toNat_ofNat, loadNat_eq n _ a v.toNat hb, hv, hv]

/-- A store outside the range a load reads is invisible to it. -/
theorem load_store_disjoint (n k : Nat) (m : Mem) (a b : BitVec 64) (v : BitVec (8 * k))
    (ha : a.toNat + n ≤ 2 ^ 64) (hb : b.toNat + k ≤ 2 ^ 64)
    (hd : RangesDisjoint a n b k) :
    load n (store k m b v) a = load n m a := by
  have hd' : a.toNat + n ≤ b.toNat ∨ b.toNat + k ≤ a.toNat := hd
  have hcong : ∀ i < n, store k m b v (a + BitVec.ofNat 64 i) = m (a + BitVec.ofNat 64 i) := by
    intro i hi
    have hx : (a + BitVec.ofNat 64 i).toNat = a.toNat + i := toNat_add_ofNat (by omega)
    have hsub : (a + BitVec.ofNat 64 i - b).toNat
        = (2 ^ 64 - b.toNat + (a + BitVec.ofNat 64 i).toNat) % 2 ^ 64 := BitVec.toNat_sub _ _
    have hblt := b.isLt
    rw [hx] at hsub
    simp only [store]
    rw [if_neg (by omega)]
  simp only [load]
  rw [loadNat_congr n _ m a hcong]

/-- Stores to disjoint ranges commute. -/
theorem store_store_comm (n k : Nat) (m : Mem) (a b : BitVec 64)
    (v : BitVec (8 * n)) (w : BitVec (8 * k))
    (ha : a.toNat + n ≤ 2 ^ 64) (hb : b.toNat + k ≤ 2 ^ 64)
    (hd : RangesDisjoint a n b k) :
    store n (store k m b w) a v = store k (store n m a v) b w := by
  funext x
  have hd' : a.toNat + n ≤ b.toNat ∨ b.toNat + k ≤ a.toNat := hd
  have hxa : (x - a).toNat = (2 ^ 64 - a.toNat + x.toNat) % 2 ^ 64 := BitVec.toNat_sub _ _
  have hxb : (x - b).toNat = (2 ^ 64 - b.toNat + x.toNat) % 2 ^ 64 := BitVec.toNat_sub _ _
  have hxlt := x.isLt
  have halt := a.isLt
  have hblt := b.isLt
  have hnot : ¬ ((x - a).toNat < n ∧ (x - b).toNat < k) := by omega
  simp only [store]
  by_cases h1 : (x - a).toNat < n
  · rw [if_pos h1, if_neg (by omega), if_pos h1]
  · rw [if_neg h1]
    by_cases h2 : (x - b).toNat < k
    · rw [if_pos h2, if_pos h2]
    · rw [if_neg h2, if_neg h2, if_neg h1]

/-! ## The eight-byte forms -/

/-- The eight-byte load, the only width the machine's stack traffic uses. -/
def load64 (m : Mem) (a : BitVec 64) : BitVec 64 := load 8 m a

/-- The eight-byte store. -/
def store64 (m : Mem) (a : BitVec 64) (v : BitVec 64) : Mem := store 8 m a v

theorem load64_store64_same (m : Mem) (a : BitVec 64) (v : BitVec 64) :
    load64 (store64 m a v) a = v :=
  load_store_same 8 m a v (by norm_num)

theorem load64_store64_disjoint (m : Mem) (a b : BitVec 64) (v : BitVec 64)
    (ha : a.toNat + 8 ≤ 2 ^ 64) (hb : b.toNat + 8 ≤ 2 ^ 64)
    (hd : RangesDisjoint a 8 b 8) :
    load64 (store64 m b v) a = load64 m a :=
  load_store_disjoint 8 8 m a b v ha hb hd

/-- A store that misses an eight-byte load leaves it alone, at any width. -/
theorem load64_store_disjoint (k : Nat) (m : Mem) (a b : BitVec 64) (v : BitVec (8 * k))
    (ha : a.toNat + 8 ≤ 2 ^ 64) (hb : b.toNat + k ≤ 2 ^ 64)
    (hd : RangesDisjoint a 8 b k) :
    load64 (store k m b v) a = load64 m a :=
  load_store_disjoint 8 k m a b v ha hb hd

theorem store64_store64_comm (m : Mem) (a b : BitVec 64) (v w : BitVec 64)
    (ha : a.toNat + 8 ≤ 2 ^ 64) (hb : b.toNat + 8 ≤ 2 ^ 64)
    (hd : RangesDisjoint a 8 b 8) :
    store64 (store64 m b w) a v = store64 (store64 m a v) b w :=
  store_store_comm 8 8 m a b v w ha hb hd

end X64

end async_ebpf_verified

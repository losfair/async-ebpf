import AsyncEbpf.AsyncEbpfVerified

/-!
# Reasoning about extracted loops

Aeneas turns a `while` into `loop body x`, the least fixed point of the loop
body. `loop_ok_induction` is the one rule the proofs need for it: a property
`P` of the loop state that every body step preserves, and which implies `Q` of
the result whenever the body finishes, holds of any value the loop returns.
There is no termination argument in it; the rule is proved by fixed-point
induction, so it says nothing about a loop that never finishes, which is
exactly the strength of the `= ok …` statements it is used in.
-/
open Aeneas Aeneas.Std Result

namespace async_ebpf_verified

theorem admissible_eq_ok_imp {β : Type} (Q : β → Prop) :
    Lean.Order.admissible (fun (r : Result β) => ∀ y, r = ok y → Q y) := by
  apply Lean.Order.admissible_flatOrder (b := Result.div)
  intro y h
  cases h

/-- Loop induction: `P` is an invariant of `body`, `Q` follows from `P` at
every exit, so `Q` holds of whatever `loop body` returns. -/
theorem loop_ok_induction {α β : Type} (body : α → Result (ControlFlow α β))
    (P : α → Prop) (Q : β → Prop)
    (hstep : ∀ x, P x → ∀ r, body x = ok r →
      (match r with | .cont x' => P x' | .done y => Q y)) :
    ∀ x y, P x → loop body x = ok y → Q y := by
  apply loop.fixpoint_induct
    (motive := fun (loop' : α → Result β) => ∀ x y, P x → loop' x = ok y → Q y)
  · apply Lean.Order.admissible_pi_apply (P := fun x r => ∀ y, P x → r = ok y → Q y)
    intro x
    by_cases hx : P x
    · have : (fun r : Result β => ∀ y, P x → r = ok y → Q y) = fun r => ∀ y, r = ok y → Q y := by
        funext r; simp [hx]
      rw [this]
      exact admissible_eq_ok_imp Q
    · have : (fun r : Result β => ∀ y, P x → r = ok y → Q y) = fun _ => True := by
        funext r; simp [hx]
      rw [this]
      exact Lean.Order.admissible_const_true
  · intro f ih x y hx h
    simp only at h
    rcases hb : body x with r | e | _ <;> simp [hb] at h
    have := hstep x hx r hb
    cases r with
    | cont x' => exact ih x' y this h
    | done y' => simp only [ok.injEq] at h; subst h; exact this

end async_ebpf_verified

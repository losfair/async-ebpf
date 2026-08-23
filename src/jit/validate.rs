//! What the loader accepts, and the exact words it uses to refuse.
//!
//! # Two layers, deliberately overlapping
//!
//! Load-time checking is split in two. The split is worth knowing about because
//! the *composition* is what callers observe — which layer speaks first decides
//! the message.
//!
//! * [`check_operand_filter`] is per-opcode data: a table of register bounds,
//!   offset bounds and immediate bounds, with a handful of enumerated sets. It
//!   knows nothing about the program around the instruction.
//! * [`validate`] is the whole-program layer — jump targets, `lddw` pairing,
//!   call targets, helper indices — plus a second, coarser pass over registers.
//!
//! The two overlap on purpose. R10 is the frame pointer, frame-relative
//! addressing emits `[r10 + k]` with no runtime bounds check, and "the guest
//! never assigned R10" is the one premise the backend cannot re-derive for
//! itself. It should not rest on a single line in a single function. So both
//! layers refuse a write to R10, by different routes.
//!
//! # Order of operations
//!
//! For one instruction the checks run strictly in this order:
//!
//! 1. the opcode match — an unknown opcode, and the per-opcode structural rules
//!    (endian immediates, `lddw` pairing, jump targets, call targets, atomic
//!    selectors);
//! 2. `src > 10`;
//! 3. `dst > 9`, unless the instruction is a store and `dst == 10`;
//! 4. the operand filter table.
//!
//! Any reordering changes which message a doubly-invalid instruction produces,
//! and `program.rs` surfaces those verbatim. The recorded decision sweeps at the
//! bottom of this file fold every rejection message into a digest character for
//! character, so a reordering shows up as a changed golden rather than passing
//! unnoticed.
//!
//! # Surprising rules
//!
//! A few rules below are surprising, and each is labelled where it lives. Where
//! the reason behind one is not recoverable, the comment says so rather than
//! inventing one — the `div`/`mod` offset bound that no backend reads, and the
//! 32-bit atomic immediate that is range-bounded where the 64-bit one is
//! enumerated, are the two of those.
//!
//! Others are noted at their site: the `>=` at `MAX_INSTS`, the dead `lddw`
//! source bound, the unreachable "Invalid instruction opcode" arm, and the
//! 32-bit wrapping arithmetic in the local call target.
//!
//! # The empty program
//!
//! [`validate`] accepts a zero-length program: its loop does not run and its
//! sub-program check finds no local call, so there is nothing here to object to.
//! The refusal belongs one layer up, in `Translator::load`, which will not
//! assemble an empty program. See
//! `tests::decisions::the_empty_program_is_refused_by_the_loader_not_the_validator`.

use super::isa::{cls, opcode, AluOp, AluWidth, Insn, Op};
use super::{abi, Config};

// ---------------------------------------------------------------------------
// Layer 1: the per-opcode operand filter
// ---------------------------------------------------------------------------

/// Which operand values one opcode admits: the register, offset and immediate
/// ranges accepted for one opcode.
///
/// A field an opcode does not use is bounded `0..=0` — "reserved, must be zero"
/// — rather than left unconstrained. Every bound is written out explicitly at
/// each use below, and there is deliberately no zero-valued `Default`: silently
/// defaulting a bound to "reserved" or to "anything" are both mistakes this
/// table must not be able to make quietly.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct Filter {
  /// Inclusive bounds on the source register nibble.
  src: (u8, u8),
  /// Inclusive bounds on the destination register nibble.
  dst: (u8, u8),
  /// Inclusive bounds on the offset, used when [`Filter::offset_enum`] is empty.
  offset: (i16, i16),
  /// The only legal offsets, when non-empty. Takes precedence over the bounds.
  offset_enum: &'static [i16],
  /// Inclusive bounds on the immediate, used when [`Filter::imm_enum`] is empty.
  imm: (i32, i32),
  /// The only legal immediates, when non-empty. Takes precedence.
  imm_enum: &'static [i32],
}

const fn filter(src: (u8, u8), dst: (u8, u8), offset: (i16, i16), imm: (i32, i32)) -> Filter {
  Filter {
    src,
    dst,
    offset,
    offset_enum: &[],
    imm,
    imm_enum: &[],
  }
}

const ANY_OFF: (i16, i16) = (i16::MIN, i16::MAX);
const NO_OFF: (i16, i16) = (0, 0);
const ANY_IMM: (i32, i32) = (i32::MIN, i32::MAX);
const NO_IMM: (i32, i32) = (0, 0);

/// `add r_d, imm` and friends: no source register, any immediate.
const ALU_IMM: Filter = filter((0, 0), (0, 9), NO_OFF, ANY_IMM);
/// `add r_d, r_s`: no immediate. The source may be R10 — reading the frame
/// pointer is allowed, only writing it is not.
const ALU_REG: Filter = filter((0, 10), (0, 9), NO_OFF, NO_IMM);
/// `div` and `mod`, the only ALU opcodes whose offset may be non-zero.
///
/// The eBPF ISA gives that offset bit to a signed flavour of the operation.
/// This tree has no signed division or modulo — [`Op`] names no such opcode, and
/// both JIT backends derive the operation from the ALU nibble without ever
/// reading `inst.offset`. The `0..=1` bound is therefore slack: a `div` with
/// offset 1 loads, and then executes as an unsigned division. The bound stays
/// wide anyway, because tightening it to `0..=0` would start rejecting programs
/// that load today — a breaking change for embedders, not a fix.
const DIV_IMM: Filter = filter((0, 0), (0, 9), (0, 1), ANY_IMM);
const DIV_REG: Filter = filter((0, 10), (0, 9), (0, 1), NO_IMM);
/// `neg`: one operand, in the destination.
const NEG: Filter = filter((0, 0), (0, 9), NO_OFF, NO_IMM);
/// `le`/`be`/`bswap`. [`validate`] narrows this to exactly 16, 32 and 64 before
/// the filter ever sees it, so the `0..=64` range here is slack that is never
/// observable.
const ENDIAN: Filter = filter((0, 0), (0, 9), NO_OFF, (0, 64));
/// `movsx32`: the offset carries the source width being sign-extended from.
/// Zero is a plain `mov`.
const MOVSX32: Filter = Filter {
  offset_enum: &[0, 8, 16],
  ..ALU_REG
};
/// `movsx64`: as above, and 32 is additionally meaningful at 64-bit width.
const MOVSX64: Filter = Filter {
  offset_enum: &[0, 8, 16, 32],
  ..ALU_REG
};
/// `ldx`, plain and sign-extending: reads `[src + offset]`, so the source may
/// be the frame pointer but the destination may not.
const LDX: Filter = filter((0, 10), (0, 9), ANY_OFF, NO_IMM);
/// `st`: stores the immediate to `[dst + offset]`, so the *destination* is a
/// memory base and R10 is legal there.
const ST: Filter = filter((0, 0), (0, 10), ANY_OFF, ANY_IMM);
/// `stx`: as `st`, and the stored value may itself be the frame pointer.
const STX: Filter = filter((0, 10), (0, 10), ANY_OFF, NO_IMM);
/// `lddw`. The `0..=6` source bound is the eBPF ISA's map-descriptor extension,
/// which this tree does not implement: [`validate`] rejects any non-zero source
/// first, so sources 1 through 6 are dead here and this bound never speaks.
const LDDW: Filter = filter((0, 6), (0, 9), NO_OFF, ANY_IMM);
/// The second slot of a `lddw`, carrying the high half of the immediate.
/// Unreachable through [`validate`], which sees a bare opcode `0x00` as an
/// unknown opcode and never looks it up here; the row exists so that every byte
/// the encoder can emit is described rather than absent.
const LDDW_HIGH: Filter = filter((0, 0), (0, 0), NO_OFF, ANY_IMM);
/// `ja`: the displacement is in the offset.
const JA: Filter = filter((0, 0), (0, 0), ANY_OFF, NO_IMM);
/// `ja32`: the displacement is in the immediate, and the offset must be zero.
const JA32: Filter = filter((0, 0), (0, 0), NO_OFF, ANY_IMM);
/// Conditional jump against an immediate.
const JMP_IMM: Filter = filter((0, 0), (0, 9), ANY_OFF, ANY_IMM);
/// Conditional jump against a register.
const JMP_REG: Filter = filter((0, 10), (0, 9), ANY_OFF, NO_IMM);
/// `call`: source 0 is a helper, 1 is a local function. 2 (call by BTF id) is
/// refused by [`validate`] with its own message before reaching here, so this
/// bound never speaks.
const CALL: Filter = filter((0, 1), (0, 0), NO_OFF, ANY_IMM);
/// `exit` takes no operands at all.
const EXIT: Filter = filter((0, 0), (0, 0), NO_OFF, NO_IMM);
/// 32-bit atomic RMW. The source is bounded at R9, not R10: a fetching atomic
/// writes its previous memory contents back into the *source* register, which
/// would be the one write to the frame pointer neither layer otherwise refuses.
/// The non-fetching forms do not write the source, so the bound is stricter than
/// strictly necessary: this table is keyed by opcode alone and so cannot vary a
/// bound with the immediate's FETCH bit, and refusing R10 for every form is the
/// safe way to settle that.
///
/// Note the immediate is a plain `0..=255` range here, not the enumeration the
/// 64-bit form gets: a 32-bit atomic with immediate `0x02` passes both this
/// filter and [`check_atomic_selector`] (which masks with `0xf0`), even though
/// `0x02` names no operation. That the two widths are bounded differently is
/// deliberate and is left alone — tightening this one would refuse programs that
/// load today — but no reason for the difference is recorded.
const ATOMIC32: Filter = filter((0, 9), (0, 10), ANY_OFF, (0, 255));
/// 64-bit atomic RMW, with the enumeration the 32-bit form lacks.
const ATOMIC64: Filter = Filter {
  imm_enum: &[0x00, 0x01, 0x40, 0x41, 0x50, 0x51, 0xa0, 0xa1, 0xe1, 0xf1],
  ..filter((0, 9), (0, 10), ANY_OFF, NO_IMM)
};

/// The filter table, as data: which opcodes share each shape.
///
/// There is one row per *shape*, listing the opcodes that share it, and the
/// grouping is presentation only: [`build_filters`] flattens it back to one
/// independent entry per opcode, and every opcode ends up with exactly the
/// bounds its row gives it. All 120 entries are accounted for by
/// [`tests::the_filter_table_covers_exactly_the_defined_opcodes`], which is what
/// catches an opcode gaining a decoder entry but no filter row.
#[rustfmt::skip]
const FILTER_GROUPS: &[(&[u8], Filter)] = &[
  // ALU and ALU64: add, sub, mul, or, and, lsh, rsh, xor, mov, arsh.
  (&[0x04, 0x14, 0x24, 0x44, 0x54, 0x64, 0x74, 0xa4, 0xb4, 0xc4,
     0x07, 0x17, 0x27, 0x47, 0x57, 0x67, 0x77, 0xa7, 0xb7, 0xc7], ALU_IMM),
  (&[0x0c, 0x1c, 0x2c, 0x4c, 0x5c, 0x6c, 0x7c, 0xac, 0xcc,
     0x0f, 0x1f, 0x2f, 0x4f, 0x5f, 0x6f, 0x7f, 0xaf, 0xcf], ALU_REG),
  // div and mod, the only ALU opcodes admitting a non-zero offset.
  (&[0x34, 0x94, 0x37, 0x97], DIV_IMM),
  (&[0x3c, 0x9c, 0x3f, 0x9f], DIV_REG),
  (&[0x84, 0x87], NEG),
  // le, bswap, be.
  (&[0xd4, 0xd7, 0xdc], ENDIAN),
  (&[0xbc], MOVSX32),
  (&[0xbf], MOVSX64),
  // ldx w/h/b/dw and the three sign-extending forms.
  (&[0x61, 0x69, 0x71, 0x79, 0x81, 0x89, 0x91], LDX),
  (&[0x62, 0x6a, 0x72, 0x7a], ST),
  (&[0x63, 0x6b, 0x73, 0x7b], STX),
  (&[0x18], LDDW),
  (&[0x00], LDDW_HIGH),
  (&[0x05], JA),
  (&[0x06], JA32),
  // Conditional jumps, JMP class then JMP32 class.
  (&[0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0xa5, 0xb5, 0xc5, 0xd5,
     0x16, 0x26, 0x36, 0x46, 0x56, 0x66, 0x76, 0xa6, 0xb6, 0xc6, 0xd6], JMP_IMM),
  (&[0x1d, 0x2d, 0x3d, 0x4d, 0x5d, 0x6d, 0x7d, 0xad, 0xbd, 0xcd, 0xdd,
     0x1e, 0x2e, 0x3e, 0x4e, 0x5e, 0x6e, 0x7e, 0xae, 0xbe, 0xce, 0xde], JMP_REG),
  (&[0x85], CALL),
  (&[0x95], EXIT),
  (&[0xc3], ATOMIC32),
  (&[0xdb], ATOMIC64),
];

/// The table above, flattened to a direct lookup.
const FILTERS: [Option<Filter>; 256] = build_filters();

const fn build_filters() -> [Option<Filter>; 256] {
  let mut table = [None; 256];
  let mut group = 0;
  while group < FILTER_GROUPS.len() {
    let (opcodes, shape) = FILTER_GROUPS[group];
    let mut k = 0;
    while k < opcodes.len() {
      table[opcodes[k] as usize] = Some(shape);
      k += 1;
    }
    group += 1;
  }
  table
}

/// Applies the operand filter to one instruction.
///
/// The wording of these messages is interface, not diagnostics. Note `{:2X}`:
/// uppercase, minimum width two, *space* padded — so opcode `0x05` renders as
/// `" 5"`, not `"05"`. Callers compare these strings, so the padding is
/// load-bearing.
fn check_operand_filter(insn: &Insn) -> Result<(), String> {
  let opcode = insn.opcode;
  let Some(f) = FILTERS[opcode as usize] else {
    // Unreachable in practice: `validate()`'s opcode `switch` refuses every
    // byte this table lacks an entry for, and does so first. Kept because the C
    // keeps it, and because a future opcode added to `Op` but not to the table
    // should say so rather than be waved through.
    return Err(format!("Invalid instruction opcode {opcode:2X}."));
  };

  if insn.dst < f.dst.0 || insn.dst > f.dst.1 {
    return Err(format!(
      "Invalid destination register {} for opcode {opcode:2X}.",
      insn.dst
    ));
  }
  if insn.src < f.src.0 || insn.src > f.src.1 {
    return Err(format!(
      "Invalid source register {} for opcode {opcode:2X}.",
      insn.src
    ));
  }

  let imm_ok = if f.imm_enum.is_empty() {
    insn.imm >= f.imm.0 && insn.imm <= f.imm.1
  } else {
    f.imm_enum.contains(&insn.imm)
  };
  if !imm_ok {
    return Err(format!(
      "Invalid immediate value {} for opcode {opcode:2X}.",
      insn.imm
    ));
  }

  let offset_ok = if f.offset_enum.is_empty() {
    insn.offset >= f.offset.0 && insn.offset <= f.offset.1
  } else {
    f.offset_enum.contains(&insn.offset)
  };
  if !offset_ok {
    return Err(format!(
      "Invalid offset value {} for opcode {opcode:2X}.",
      insn.offset
    ));
  }

  Ok(())
}

// ---------------------------------------------------------------------------
// Layer 2: whole-program validation
// ---------------------------------------------------------------------------

/// Validates a decoded program, returning `ubpf_load`'s rejection message.
///
/// Mirrors `validate()` in `ubpf_vm.c`. The caller has already established that
/// the byte length was a multiple of eight.
pub fn validate(config: &Config, insns: &[Insn]) -> Result<(), String> {
  // The C's bound is `>=`, not `>`: a program of exactly `UBPF_MAX_INSTS`
  // instructions is refused. `Translator::load` checks `>` before calling here,
  // so the two together reproduce `>=` — but this must not depend on that, and
  // stating it here is what makes the boundary testable in one place.
  if insns.len() >= abi::MAX_INSTS as usize {
    return Err(format!("too many instructions (max {})", abi::MAX_INSTS));
  }

  // `validate()` next calls `ubpf_calculate_stack_usage_for_local_func(vm, 0)`,
  // and again for every local call target below. Its only failure mode is a
  // stack usage that is not 16-byte aligned. `async-ebpf` never registers a
  // custom stack-usage calculator, so every function is charged the constant
  // `LOCAL_FUNCTION_STACK_SIZE` — see `stack.rs`, which carries a `const`
  // assertion that the constant is aligned. The check can therefore never fire
  // and is not reproduced as a runtime test.

  let num_insns = insns.len();
  let mut i = 0usize;
  while i < num_insns {
    let insn = insns[i];
    // Set for the store forms only. Its sole effect is to admit R10 as a
    // destination in the register check below, because those are the opcodes
    // whose destination is a memory base rather than a written register.
    let mut store = false;
    // `lddw` consumes the following slot as well.
    let mut skip_next = false;

    let Some(op) = insn.op() else {
      return Err(format!("unknown opcode 0x{:02x} at PC {i}", insn.opcode));
    };

    match op {
      // `neg` has no source operand; a non-zero source field is a malformed
      // encoding rather than an unknown one, and gets its own message.
      Op::Alu {
        op: AluOp::Neg,
        width,
        ..
      } => {
        if insn.src != 0 {
          let name = match width {
            AluWidth::W32 => "neg",
            AluWidth::W64 => "neg64",
          };
          return Err(format!("invalid src field for {name} op at PC {i}"));
        }
      }

      // The byte width to convert is in the immediate, and only three widths
      // exist. The operand filter's `0..=64` range never gets to disagree.
      Op::End(_) => {
        if insn.imm != 16 && insn.imm != 32 && insn.imm != 64 {
          return Err(format!("invalid endian immediate at PC {i}"));
        }
      }

      Op::LoadImm64 => {
        if insn.src != 0 {
          return Err(format!("invalid source register for LDDW at PC {i}"));
        }
        if i + 1 >= num_insns || insns[i + 1].opcode != 0 {
          return Err(format!("incomplete lddw at PC {i}"));
        }
        // A local patch: the second half is pure immediate payload, so every
        // other field of it must be zero. Without this the register and offset
        // nibbles of the high word are unvalidated bits that no layer inspects,
        // since the slot is skipped entirely below.
        let high = insns[i + 1];
        if high.dst != 0 || high.src != 0 || high.offset != 0 {
          return Err(format!("invalid lddw second half at PC {}", i + 1));
        }
        skip_next = true;
      }

      Op::StoreImm { .. } | Op::StoreReg { .. } => store = true,

      Op::Atomic { .. } => {
        store = true;
        check_atomic_selector(&insn, i)?;
      }

      Op::Ja { .. } | Op::Jmp { .. } => {
        // `ja32` puts its displacement in the immediate; everything else uses
        // the offset.
        let displacement = if insn.opcode == opcode::JA32 {
          insn.imm
        } else {
          insn.offset as i32
        };
        // A displacement of -1 targets the jump itself.
        if displacement == -1 {
          return Err(format!("infinite loop at PC {i}"));
        }
        let target = i as i64 + 1 + displacement as i64;
        if target < 0 || target >= num_insns as i64 {
          return Err(format!("jump out of bounds at PC {i}"));
        }
        // Opcode zero at the target means the high half of a `lddw` — or a
        // stray zero word, which this reports the same way.
        if insns[target as usize].opcode == 0 {
          return Err(format!("jump to middle of lddw at PC {i}"));
        }
      }

      Op::Call => check_call(config, &insn, i, num_insns)?,

      // Nothing structural to check.
      Op::Exit | Op::Alu { .. } | Op::Load { .. } => {}
    }

    if insn.src > 10 {
      return Err(format!("invalid source register at PC {i}"));
    }
    // R10 is the frame pointer and read-only. The store forms name it as a
    // memory base rather than writing it, so they are the exception.
    if insn.dst > 9 && !(store && insn.dst == 10) {
      return Err(format!("invalid destination register at PC {i}"));
    }

    check_operand_filter(&insn)?;

    i += 1 + usize::from(skip_next);
  }

  check_self_contained_sub_programs(insns)
}

/// Checks the operation selector an atomic store carries in its immediate.
///
/// Ports the two nearly-identical `switch` blocks in `validate()`. Only the
/// high nibble selects the operation; the low bits carry the FETCH flag, and
/// anything else in them is ignored here (the operand filter is what bounds
/// them, and only for the 64-bit form).
///
/// Both widths report an unrecognised selector the same way, naming the
/// immediate that was not understood. The immediate is the whole content of the
/// diagnosis — the opcode only says which width — so leaving it out would make
/// the message useless for the reader trying to work out what they wrote.
fn check_atomic_selector(insn: &Insn, pc: usize) -> Result<(), String> {
  use super::isa::{alu, atomic};

  // Both faults name the immediate, because the immediate is the whole
  // diagnosis: the selector lives there, and the opcode says only which width
  // the access is. Naming the opcode instead tells the reader something they
  // already know.
  let selector = insn.imm as u32 as u8;
  let unknown = || format!("invalid atomic operation {selector:#04x} at PC {pc}");
  let needs_fetch =
    || format!("atomic operation {selector:#04x} at PC {pc} requires the fetch flag");

  let fetch = insn.imm & atomic::OP_FETCH != 0;
  match (insn.imm & alu::MASK as i32) as u8 {
    alu::ADD | alu::OR | alu::AND | alu::XOR => Ok(()),
    // Exchange and compare-exchange only exist in fetching form: the whole
    // point of them is the value they return.
    op if op as i32 == atomic::OP_XCHG & !atomic::OP_FETCH
      || op as i32 == atomic::OP_CMPXCHG & !atomic::OP_FETCH =>
    {
      if fetch {
        Ok(())
      } else {
        Err(needs_fetch())
      }
    }
    _ => Err(unknown()),
  }
}

/// Checks one `call` instruction.
///
/// The source field is the call *kind*, not a register.
fn check_call(config: &Config, insn: &Insn, pc: usize, num_insns: usize) -> Result<(), String> {
  match insn.src {
    // Helper call: the immediate is an index the embedder must recognise.
    0 => {
      if insn.imm < 0 {
        return Err(format!("invalid call immediate at PC {pc}"));
      }
      let known = match (config.dispatcher, config.dispatcher_validate) {
        (Some(_), Some(check)) => {
          // The C passes the VM itself as the cookie. Nothing here has one, and
          // no validator in this tree reads it; a null pointer keeps the
          // signature honest about that.
          // SAFETY: the callback is supplied by the embedder alongside the
          // dispatcher and is required to tolerate being asked about any index.
          unsafe { check(insn.imm as u32, std::ptr::null()) }
        }
        // With no dispatcher the C falls back to its per-index `ext_funcs`
        // table, populated only by `ubpf_register`. `async-ebpf` never calls
        // it, so that table is empty and every helper index is unknown.
        (None, _) => false,
        (Some(_), None) => {
          debug_assert!(
            false,
            "Config::dispatcher without dispatcher_validate; the C would call \
             a null function pointer"
          );
          false
        }
      };
      if !known {
        return Err(format!(
          "call to nonexistent function {} at PC {pc}",
          insn.imm as u32
        ));
      }
    }

    // Local call: the immediate is a relative instruction displacement.
    1 => {
      // The C computes `i + (inst.imm + 1)` in `int`, so an immediate of
      // `INT32_MAX` wraps to `INT32_MIN` before the add. Wrapping arithmetic
      // reproduces that; the result is far out of range either way, but the
      // reported target number differs.
      let target = (pc as i32).wrapping_add(insn.imm.wrapping_add(1));
      if target < 0 || target >= num_insns as i32 {
        return Err(format!(
          "call to local function (at PC {pc}) is out of bounds (target: {target})"
        ));
      }
      // The C then calls `ubpf_calculate_stack_usage_for_local_func` on the
      // target; see the note in `validate` for why that cannot fail here.
    }

    2 => {
      return Err(format!(
        "call to external function by BTF ID (at PC {pc}) is not supported"
      ))
    }

    // The source nibble reaches 15, and the `src > 10` check has not run yet.
    _ => return Err(format!("call (at PC {pc}) contains invalid type value")),
  }
  Ok(())
}

/// Rejects programs whose sub-programs are not self-contained.
///
/// Ports `check_for_self_contained_sub_programs`. A local call target is taken
/// to start a sub-program, and a sub-program runs to the next start or to the
/// end of the program. Within one sub-program every jump must land inside it,
/// and the sub-program must end in `exit` or with an unconditional jump as its
/// second-to-last instruction.
///
/// Two details of the C that are easy to miss and are reproduced here:
///
/// * The start-index array is `calloc`'d one longer than the number of local
///   calls and only the call targets are written, so the extra slot stays zero.
///   The effect — deliberate, given the sizing — is that index 0 is always a
///   sub-program start, which is what makes the main program one.
/// * The whole function is skipped when the program contains no local call at
///   all. A straight-line program is therefore *not* required to terminate; it
///   may run off the end of the instruction stream. That is uBPF's behaviour and
///   this reproduces it.
fn check_self_contained_sub_programs(insns: &[Insn]) -> Result<(), String> {
  let num_insns = insns.len();

  let mut starts: Vec<usize> = insns
    .iter()
    .enumerate()
    .filter(|(_, insn)| insn.is_local_call())
    .map(|(i, insn)| {
      // `validate` established this lands inside the program.
      (i as u32).wrapping_add(1).wrapping_add(insn.imm as u32) as usize
    })
    .collect();
  if starts.is_empty() {
    return Ok(());
  }
  // The zeroed extra slot described above.
  starts.push(0);
  starts.sort_unstable();
  starts.dedup();

  for (n, &start) in starts.iter().enumerate() {
    let end = starts.get(n + 1).copied().unwrap_or(num_insns);

    for j in start..end {
      let insn = insns[j];
      if insn.class() != cls::JMP && insn.class() != cls::JMP32 {
        continue;
      }
      // A call leaves and returns; an exit ends the sub-program. Neither is a
      // jump within it. Note this catches helper calls too, by opcode alone.
      if insn.opcode == opcode::CALL || insn.opcode == opcode::EXIT {
        continue;
      }
      let displacement = if insn.opcode == opcode::JA32 {
        insn.imm as i64
      } else {
        insn.offset as i64
      };
      let target = j as i64 + 1 + displacement;
      if target < start as i64 || target > end as i64 - 1 {
        return Err(format!("jump out of bounds at PC {j}"));
      }
    }

    // `end > start` always: the starts are distinct and sorted, every local
    // call target is inside the program, and 0 is always present.
    let ends_with_exit = insns[end - 1].opcode == opcode::EXIT;
    let ends_with_jump = end >= start + 2
      && (insns[end - 2].opcode == opcode::JA || insns[end - 2].opcode == opcode::JA32);
    if !ends_with_exit && !ends_with_jump {
      return Err(format!(
        "sub-program does not end with EXIT or unconditional jump at PC {}",
        end - 1
      ));
    }
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::jit::isa::Insn;

  fn insn(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Insn {
    Insn {
      opcode,
      dst,
      src,
      offset,
      imm,
    }
  }

  fn exit() -> Insn {
    insn(opcode::EXIT, 0, 0, 0, 0)
  }

  #[test]
  fn the_filter_table_covers_exactly_the_defined_opcodes() {
    // The C table has one entry per named opcode plus one for the `lddw` high
    // half, which is not an opcode at all. Any other shape means the table and
    // the decoder have drifted apart.
    for byte in 0u8..=255 {
      let has_filter = FILTERS[byte as usize].is_some();
      let is_defined = Op::from_opcode(byte).is_some();
      let expected = is_defined || byte == 0;
      assert_eq!(
        has_filter, expected,
        "opcode {byte:#04x}: filter present = {has_filter}, expected {expected}"
      );
    }
    assert_eq!(
      FILTERS.iter().filter(|f| f.is_some()).count(),
      120,
      "the C table has exactly 120 entries"
    );
  }

  #[test]
  fn the_opcode_is_rendered_the_way_printf_renders_it() {
    // `%2X` is space padded, not zero padded. Getting this wrong produces
    // messages that differ from the C by one character.
    let err = check_operand_filter(&insn(opcode::JA, 0, 0, 0, 7)).unwrap_err();
    assert_eq!(err, "Invalid immediate value 7 for opcode  5.");
    let err = check_operand_filter(&insn(0xc3, 0, 0, 0, 999)).unwrap_err();
    assert_eq!(err, "Invalid immediate value 999 for opcode C3.");
  }

  #[test]
  fn a_program_with_no_local_calls_need_not_terminate() {
    // uBPF really does accept this: the sub-program check is skipped entirely
    // when there is no local call, so nothing requires a trailing `exit`.
    let config = Config::default();
    assert_eq!(validate(&config, &[insn(0xb7, 0, 0, 0, 1)]), Ok(()));
    // And an empty program is accepted too.
    assert_eq!(validate(&config, &[]), Ok(()));
  }

  #[test]
  fn the_frame_pointer_may_be_a_store_base_but_never_a_destination() {
    let config = Config::default();
    // `stxdw [r10 + 0], r1` — R10 as a memory base.
    assert_eq!(
      validate(&config, &[insn(0x7b, 10, 1, 0, 0), exit()]),
      Ok(())
    );
    // `ldxdw r10, [r1 + 0]` — R10 written.
    assert_eq!(
      validate(&config, &[insn(0x79, 10, 1, 0, 0), exit()]),
      Err("invalid destination register at PC 0".to_string())
    );
  }

  // -------------------------------------------------------------------------
  // What the loader accepts, recorded
  // -------------------------------------------------------------------------

  /// Generated and enumerated programs, with every accept/reject decision — and
  /// the exact wording of every rejection — rolled into checked-in digests.
  ///
  /// What the validator accepts is a security boundary: loosening it silently
  /// lets a program through that the emitters were never written to handle, and
  /// tightening it silently breaks embedders. Neither shows up in a behavioural
  /// test, because the programs involved are ones nobody writes on purpose.
  ///
  /// So the decisions are pinned instead. Each sweep below folds its outcomes
  /// into one digest — acceptance, and the rejection message character for
  /// character — and any change to any of them fails the sweep. The message is
  /// part of it because embedders match on those strings.
  mod decisions {
    use super::*;
    use crate::jit::golden::{self, SweepDigest};
    use crate::jit::{Target, TranslateError, Translator};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::sync::Arc;

    /// Programs decided per configuration in the default run. The full sweep is
    /// behind `#[ignore]`; `ASYNC_EBPF_VALIDATE_PROGRAMS` overrides both.
    const DEFAULT_PROGRAMS: usize = 12_000;
    const EXHAUSTIVE_PROGRAMS: usize = 120_000;

    fn program_count(default: usize) -> usize {
      std::env::var("ASYNC_EBPF_VALIDATE_PROGRAMS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
    }

    /// The seed is fixed so a failure reproduces, and overridable so a longer
    /// hunt can be run from a different corner of the space.
    fn seed(default: u64) -> u64 {
      std::env::var("ASYNC_EBPF_VALIDATE_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
    }

    /// Whether this run is the one the goldens describe: the default seed, the
    /// default program count, and nothing overridden from the environment.
    fn is_the_recorded_run(
      programs: usize,
      default_programs: usize,
      s: u64,
      default_seed: u64,
    ) -> bool {
      programs == default_programs && s == default_seed
    }

    /// Accepts every helper index, so that `call <imm>` resolves and the rules
    /// past it are reached.
    unsafe extern "C" fn accept_every_helper(_index: u32, _vm: *const std::ffi::c_void) -> bool {
      true
    }

    /// Never called: the validator only asks whether a dispatcher is present.
    unsafe extern "C" fn never_called_dispatcher(
      _: u64,
      _: u64,
      _: u64,
      _: u64,
      _: u64,
      _: u32,
      _: *mut std::ffi::c_void,
    ) -> u64 {
      unreachable!("validation never executes anything")
    }

    /// The two configurations that change what `validate` accepts.
    ///
    /// Nothing else in [`Config`] reaches the validator: the pointer cage, the
    /// frame base and the bounds checks are all translation-time. The one live
    /// axis is whether a helper dispatcher is registered, which decides whether
    /// `call <imm>` resolves at all.
    fn configs() -> Vec<(&'static str, Config)> {
      vec![
        (
          "dispatcher registered",
          Config {
            target: Target::X86_64,
            dispatcher: Some(never_called_dispatcher),
            dispatcher_validate: Some(accept_every_helper),
            ..Default::default()
          },
        ),
        ("no dispatcher", Config::default()),
      ]
    }

    /// Folds one program's load decision into a digest.
    ///
    /// The decision is recorded in the same shape as a translation outcome, so
    /// that one sweep mechanism covers both: acceptance is an empty success,
    /// and a rejection carries its message verbatim, so a wording change shows
    /// up as a changed digest rather than passing unnoticed.
    fn add_decision(digest: &mut SweepDigest, config: &Config, insns: &[Insn]) {
      let code = Insn::encode_all(insns);
      let outcome = match Translator::load(Arc::new(config.clone()), &code) {
        Ok(_) => Ok(Vec::new()),
        Err(e) => Err(TranslateError::Failed(e.0)),
      };
      digest.add(&outcome);
    }

    /// Closes a sweep and writes it back.
    ///
    /// The store is keyed by architecture and these decisions are the same on
    /// every one of them, so they all land in one file under a `validate-`
    /// prefix rather than being recorded twice.
    fn finish(digest: SweepDigest, label: &str) {
      digest.finish(label, Target::X86_64);
      golden::flush();
    }

    // --- generation ------------------------------------------------------

    /// Immediates that are legal for a 64-bit atomic, and hence for a 32-bit
    /// one as well.
    const ATOMIC_IMMS: [i32; 10] = [0x00, 0x01, 0x40, 0x41, 0x50, 0x51, 0xa0, 0xa1, 0xe1, 0xf1];

    /// A value that stresses the boundaries as often as the middle.
    fn interesting_i32(rng: &mut StdRng) -> i32 {
      match rng.gen_range(0..6) {
        0 => 0,
        1 => rng.gen_range(-4i32..=4),
        2 => i32::MIN,
        3 => i32::MAX,
        4 => rng.gen_range(0..=255),
        _ => rng.gen(),
      }
    }

    fn interesting_i16(rng: &mut StdRng) -> i16 {
      match rng.gen_range(0..5) {
        0 => 0,
        1 => rng.gen_range(-4i16..=4),
        2 => i16::MIN,
        3 => i16::MAX,
        _ => rng.gen(),
      }
    }

    /// Where a jump or call still has to be pointed at something.
    #[derive(Copy, Clone, PartialEq, Eq)]
    enum Hole {
      /// A jump; the target must stay inside the enclosing block.
      Jump,
      /// A local call; the target must be another block's first instruction.
      LocalCall,
    }

    /// Builds a program that both validators must accept.
    ///
    /// The shape is deliberate rather than random: a chain of blocks, each
    /// ending in `exit`, with jumps confined to their own block and local calls
    /// aimed at block starts. That is exactly the structure
    /// `check_for_self_contained_sub_programs` demands, and generating it
    /// directly is what makes "valid programs are accepted" an assertion rather
    /// than a hope.
    fn generate_valid(rng: &mut StdRng) -> Vec<Insn> {
      let num_blocks = rng.gen_range(1..=3usize);
      let mut insns: Vec<Insn> = Vec::new();
      let mut block_starts: Vec<usize> = Vec::new();
      // (pc, kind, block index)
      let mut holes: Vec<(usize, Hole, usize)> = Vec::new();

      for block in 0..num_blocks {
        block_starts.push(insns.len());
        let body_len = rng.gen_range(0..=7usize);
        for _ in 0..body_len {
          match rng.gen_range(0..14) {
            0 => insns.push(alu_imm(rng)),
            1 => insns.push(alu_reg(rng)),
            2 => insns.push(div_or_mod(rng)),
            3 => insns.push(movsx(rng)),
            4 => insns.push(neg_or_endian(rng)),
            5 => insns.push(ldx(rng)),
            6 => insns.push(st(rng)),
            7 => insns.push(stx(rng)),
            8 => insns.push(atomic(rng)),
            9 => {
              // `lddw` and its high half, which must be all zero but for the
              // immediate.
              insns.push(insn(
                opcode::LDDW,
                rng.gen_range(0..=9),
                0,
                0,
                interesting_i32(rng),
              ));
              insns.push(insn(0, 0, 0, 0, interesting_i32(rng)));
            }
            10 => {
              // Helper call. Accepted only where a dispatcher is registered;
              // the comparison covers both.
              insns.push(insn(opcode::CALL, 0, 0, 0, rng.gen_range(0..64)));
            }
            11 | 12 => {
              holes.push((insns.len(), Hole::Jump, block));
              insns.push(jump_skeleton(rng));
            }
            _ => {
              if num_blocks > 1 {
                holes.push((insns.len(), Hole::LocalCall, block));
                insns.push(insn(opcode::CALL, 0, 1, 0, 0));
              } else {
                insns.push(alu_imm(rng));
              }
            }
          }
        }
        insns.push(exit());
      }

      let block_end = |block: usize, total: usize| -> usize {
        block_starts.get(block + 1).copied().unwrap_or(total)
      };

      let total = insns.len();
      for (pc, hole, block) in holes {
        match hole {
          Hole::Jump => {
            let start = block_starts[block];
            let end = block_end(block, total);
            // Legal landing slots: inside the block, not the jump itself (a
            // displacement of -1 is refused outright), and not the high half of
            // a `lddw`.
            let candidates: Vec<usize> = (start..end)
              .filter(|&t| t != pc && insns[t].opcode != 0)
              .collect();
            let Some(&target) = candidates.get(rng.gen_range(0..candidates.len().max(1))) else {
              // A one-instruction block: nowhere to jump. Make it a `mov`.
              insns[pc] = insn(0xb7, 0, 0, 0, 0);
              continue;
            };
            let displacement = target as i32 - pc as i32 - 1;
            if insns[pc].opcode == opcode::JA32 {
              insns[pc].imm = displacement;
            } else {
              insns[pc].offset = displacement as i16;
            }
          }
          Hole::LocalCall => {
            let target = block_starts[rng.gen_range(1..block_starts.len())];
            insns[pc].imm = target as i32 - pc as i32 - 1;
          }
        }
      }

      insns
    }

    fn alu_imm(rng: &mut StdRng) -> Insn {
      const OPS: [u8; 20] = [
        0x04, 0x14, 0x24, 0x44, 0x54, 0x64, 0x74, 0xa4, 0xb4, 0xc4, 0x07, 0x17, 0x27, 0x47, 0x57,
        0x67, 0x77, 0xa7, 0xb7, 0xc7,
      ];
      insn(
        OPS[rng.gen_range(0..OPS.len())],
        rng.gen_range(0..=9),
        0,
        0,
        interesting_i32(rng),
      )
    }

    fn alu_reg(rng: &mut StdRng) -> Insn {
      const OPS: [u8; 18] = [
        0x0c, 0x1c, 0x2c, 0x4c, 0x5c, 0x6c, 0x7c, 0xac, 0xcc, 0x0f, 0x1f, 0x2f, 0x4f, 0x5f, 0x6f,
        0x7f, 0xaf, 0xcf,
      ];
      insn(
        OPS[rng.gen_range(0..OPS.len())],
        rng.gen_range(0..=9),
        rng.gen_range(0..=10),
        0,
        0,
      )
    }

    fn div_or_mod(rng: &mut StdRng) -> Insn {
      const IMM_OPS: [u8; 4] = [0x34, 0x94, 0x37, 0x97];
      const REG_OPS: [u8; 4] = [0x3c, 0x9c, 0x3f, 0x9f];
      let offset = rng.gen_range(0..=1);
      if rng.gen() {
        insn(
          IMM_OPS[rng.gen_range(0..4)],
          rng.gen_range(0..=9),
          0,
          offset,
          interesting_i32(rng),
        )
      } else {
        insn(
          REG_OPS[rng.gen_range(0..4)],
          rng.gen_range(0..=9),
          rng.gen_range(0..=10),
          offset,
          0,
        )
      }
    }

    fn movsx(rng: &mut StdRng) -> Insn {
      if rng.gen() {
        insn(
          0xbc,
          rng.gen_range(0..=9),
          rng.gen_range(0..=10),
          [0, 8, 16][rng.gen_range(0..3)],
          0,
        )
      } else {
        insn(
          0xbf,
          rng.gen_range(0..=9),
          rng.gen_range(0..=10),
          [0, 8, 16, 32][rng.gen_range(0..4)],
          0,
        )
      }
    }

    fn neg_or_endian(rng: &mut StdRng) -> Insn {
      match rng.gen_range(0..5) {
        0 => insn(0x84, rng.gen_range(0..=9), 0, 0, 0),
        1 => insn(0x87, rng.gen_range(0..=9), 0, 0, 0),
        n => insn(
          [0xd4, 0xd7, 0xdc][n - 2],
          rng.gen_range(0..=9),
          0,
          0,
          [16, 32, 64][rng.gen_range(0..3)],
        ),
      }
    }

    fn ldx(rng: &mut StdRng) -> Insn {
      const OPS: [u8; 7] = [0x61, 0x69, 0x71, 0x79, 0x81, 0x89, 0x91];
      insn(
        OPS[rng.gen_range(0..7)],
        rng.gen_range(0..=9),
        rng.gen_range(0..=10),
        interesting_i16(rng),
        0,
      )
    }

    fn st(rng: &mut StdRng) -> Insn {
      const OPS: [u8; 4] = [0x62, 0x6a, 0x72, 0x7a];
      insn(
        OPS[rng.gen_range(0..4)],
        rng.gen_range(0..=10),
        0,
        interesting_i16(rng),
        interesting_i32(rng),
      )
    }

    fn stx(rng: &mut StdRng) -> Insn {
      const OPS: [u8; 4] = [0x63, 0x6b, 0x73, 0x7b];
      insn(
        OPS[rng.gen_range(0..4)],
        rng.gen_range(0..=10),
        rng.gen_range(0..=10),
        interesting_i16(rng),
        0,
      )
    }

    fn atomic(rng: &mut StdRng) -> Insn {
      insn(
        if rng.gen() { 0xc3 } else { 0xdb },
        rng.gen_range(0..=10),
        rng.gen_range(0..=9),
        interesting_i16(rng),
        ATOMIC_IMMS[rng.gen_range(0..ATOMIC_IMMS.len())],
      )
    }

    /// A jump with its displacement left at zero, to be filled in once the
    /// layout is known.
    fn jump_skeleton(rng: &mut StdRng) -> Insn {
      const IMM_OPS: [u8; 22] = [
        0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0xa5, 0xb5, 0xc5, 0xd5, 0x16, 0x26, 0x36, 0x46,
        0x56, 0x66, 0x76, 0xa6, 0xb6, 0xc6, 0xd6,
      ];
      const REG_OPS: [u8; 22] = [
        0x1d, 0x2d, 0x3d, 0x4d, 0x5d, 0x6d, 0x7d, 0xad, 0xbd, 0xcd, 0xdd, 0x1e, 0x2e, 0x3e, 0x4e,
        0x5e, 0x6e, 0x7e, 0xae, 0xbe, 0xce, 0xde,
      ];
      match rng.gen_range(0..4) {
        0 => insn(opcode::JA, 0, 0, 0, 0),
        1 => insn(opcode::JA32, 0, 0, 0, 0),
        2 => insn(
          IMM_OPS[rng.gen_range(0..IMM_OPS.len())],
          rng.gen_range(0..=9),
          0,
          0,
          interesting_i32(rng),
        ),
        _ => insn(
          REG_OPS[rng.gen_range(0..REG_OPS.len())],
          rng.gen_range(0..=9),
          rng.gen_range(0..=10),
          0,
          0,
        ),
      }
    }

    /// Applies exactly one corruption to a valid program.
    ///
    /// One mutation at a time is the point: it keeps the rest of the program
    /// well-formed, so the *first* rule to fire is the one under test and the
    /// messages stay comparable rather than both collapsing onto whatever the
    /// earliest instruction happens to violate.
    fn mutate(rng: &mut StdRng, insns: &mut Vec<Insn>) {
      if insns.is_empty() {
        return;
      }
      let at = rng.gen_range(0..insns.len());
      match rng.gen_range(0..10) {
        // An arbitrary opcode byte, defined or not.
        0 => insns[at].opcode = rng.gen(),
        // A register number out of range, or merely the wrong one.
        1 => insns[at].dst = rng.gen_range(0..=15),
        2 => insns[at].src = rng.gen_range(0..=15),
        // Offsets and immediates: bad atomic selectors, bad endian widths,
        // out-of-range jumps and out-of-range call targets all come from here.
        3 => insns[at].offset = interesting_i16(rng),
        4 => insns[at].imm = interesting_i32(rng),
        // A wholly random word.
        5 => insns[at] = Insn::from_u64(rng.gen()),
        // Tear a `lddw` pair, in whichever way.
        6 => {
          if let Some(pc) = (0..insns.len()).find(|&p| insns[p].is_lddw()) {
            let high = pc + 1;
            match rng.gen_range(0..4) {
              0 => insns[high].opcode = rng.gen_range(1..=255),
              1 => insns[high].dst = rng.gen_range(1..=15),
              2 => insns[high].src = rng.gen_range(1..=15),
              _ => insns[high].offset = interesting_i16(rng).max(1),
            }
          } else {
            insns[at].opcode = rng.gen();
          }
        }
        // Aim a jump or call at the high half of a `lddw`.
        7 => {
          if let Some(high) = (0..insns.len()).find(|&p| insns[p].opcode == 0) {
            let opcode = insns[at].opcode;
            let displacement = high as i32 - at as i32 - 1;
            if opcode == opcode::JA32 || opcode == opcode::CALL {
              insns[at].imm = displacement;
            } else {
              insns[at].offset = displacement as i16;
            }
          } else {
            insns[at].imm = interesting_i32(rng);
          }
        }
        // Drop the last instruction: tears a trailing `lddw`, pushes jumps out
        // of range, and strips the terminating `exit`.
        8 => {
          // Never down to nothing: `ubpf_load` refuses a zero-length program
          // before `validate()` ever sees it. See
          // [`the_empty_program_is_the_one_documented_divergence`].
          if insns.len() > 1 {
            insns.pop();
          }
        }
        // Reorder, which reliably breaks the sub-program layout.
        9 => {
          let other = rng.gen_range(0..insns.len());
          insns.swap(at, other);
        }
        _ => unreachable!(),
      }
    }

    /// A program of pure noise, with the opcode biased towards defined bytes so
    /// that the run gets past the opcode `switch` often enough to exercise
    /// anything else.
    fn generate_random(rng: &mut StdRng) -> Vec<Insn> {
      let len = rng.gen_range(1..=6);
      (0..len)
        .map(|_| {
          let mut insn = Insn::from_u64(rng.gen());
          if rng.gen_bool(0.7) {
            loop {
              let byte: u8 = rng.gen();
              if Op::from_opcode(byte).is_some() {
                insn.opcode = byte;
                break;
              }
            }
          }
          insn.dst &= 0x0f;
          insn.src &= 0x0f;
          insn
        })
        .collect()
    }

    /// `programs` generated programs, decided under both configurations.
    ///
    /// A quarter are left valid, a quarter are pure noise, and half carry
    /// exactly one corruption of an otherwise valid program — one at a time, so
    /// the *first* rule to fire is the one under test rather than everything
    /// collapsing onto whatever the earliest instruction violates.
    fn run_generated(programs: usize, seed: u64) -> SweepDigest {
      let mut rng = StdRng::seed_from_u64(seed);
      let configs = configs();
      let dispatcher_config = &configs[0].1;
      let mut digest = SweepDigest::new();

      for n in 0..programs {
        let valid = generate_valid(&mut rng);

        // The happy path is an assertion, not a hope: with a dispatcher
        // registered, everything `generate_valid` produces must load. If this
        // fires the generator is wrong, and the sweep below would be recording
        // rejection paths only.
        let code = Insn::encode_all(&valid);
        if let Err(e) = Translator::load(Arc::new(dispatcher_config.clone()), &code) {
          panic!(
            "generator produced a program the loader rejects: {}\n{valid:#?}",
            e.0
          );
        }

        let program = match n % 4 {
          0 => valid,
          3 => generate_random(&mut rng),
          _ => {
            let mut m = valid;
            mutate(&mut rng, &mut m);
            m
          }
        };

        for (_, config) in &configs {
          add_decision(&mut digest, config, &program);
        }
      }
      digest
    }

    #[test]
    fn generated_programs_are_decided_as_recorded() {
      let programs = program_count(DEFAULT_PROGRAMS);
      let s = seed(0x5eed_1234_abcd_0001);
      let digest = run_generated(programs, s);
      // A sweep in which nothing was accepted, or in which nothing was
      // rejected, would pin an answer to a question nobody asked.
      let (cases, accepted) = (digest.cases(), digest.translated());
      assert!(
        accepted > cases / 8 && accepted < cases,
        "{accepted} of {cases} programs were accepted; the generator has \
         stopped producing a mix of valid and invalid programs"
      );
      if is_the_recorded_run(programs, DEFAULT_PROGRAMS, s, 0x5eed_1234_abcd_0001) {
        finish(digest, "validate-generated-programs");
      }
    }

    /// The long run, ten times the volume from a different corner of the space.
    ///
    /// It carries no golden of its own: it is not part of any ordinary run, so
    /// a recorded expectation for it would go stale unnoticed. What it checks is
    /// that the loader reaches a decision for every one of a hundred and twenty
    /// thousand programs without panicking, and that the generator is still
    /// producing a mixture.
    ///
    /// `cargo test --features testing --lib jit::validate -- --ignored`
    #[test]
    #[ignore = "slow; the recorded sweep covers the same generators at lower volume"]
    fn many_generated_programs_are_all_decided() {
      let digest = run_generated(
        program_count(EXHAUSTIVE_PROGRAMS),
        seed(0x5eed_1234_abcd_0002),
      );
      let (cases, accepted) = (digest.cases(), digest.translated());
      assert!(
        accepted > cases / 8 && accepted < cases,
        "{accepted} of {cases} programs were accepted"
      );
    }

    /// Every opcode byte against every register pairing.
    ///
    /// The generated programs above reach the operand filter often, but only
    /// where a mutation happened to land. This sweeps it directly: 256 opcodes
    /// times 16 destinations times a source drawn from the interesting values —
    /// R0, R9 (the usual bound), R10 (the frame pointer) and R11 (the first
    /// value out of range) — which is what actually pins the per-opcode
    /// register bounds and the order the two register checks run in.
    #[test]
    fn every_opcode_and_register_pairing_is_decided_as_recorded() {
      let config = configs().remove(0).1;
      let mut digest = SweepDigest::new();
      for opcode in 0u8..=255 {
        for dst in 0u8..=15 {
          for src in [0u8, 9, 10, 11] {
            for (offset, imm) in [(0i16, 0i32), (1, 16)] {
              let program = [insn(opcode, dst, src, offset, imm), exit()];
              add_decision(&mut digest, &config, &program);
            }
          }
        }
      }
      assert_eq!(digest.cases(), 256 * 16 * 4 * 2);
      assert!(digest.translated() > 0, "no pairing was accepted at all");
      finish(digest, "validate-opcode-register-pairings");
    }

    /// The offset and immediate bounds, per opcode.
    #[test]
    fn every_opcode_and_operand_extreme_is_decided_as_recorded() {
      let config = configs().remove(0).1;
      let offsets = [0i16, 1, 2, 8, 16, 32, -1, i16::MIN, i16::MAX];
      let imms = [
        0i32,
        1,
        2,
        16,
        32,
        64,
        0x40,
        0x41,
        0xa1,
        0xe0,
        0xe1,
        0xf1,
        0xff,
        0x100,
        -1,
        i32::MIN,
        i32::MAX,
      ];
      let mut digest = SweepDigest::new();
      for opcode in 0u8..=255 {
        for offset in offsets {
          for imm in imms {
            let program = [insn(opcode, 0, 0, offset, imm), exit()];
            add_decision(&mut digest, &config, &program);
          }
        }
      }
      assert_eq!(digest.cases(), 256 * offsets.len() * imms.len());
      assert!(digest.translated() > 0, "no operand extreme was accepted");
      finish(digest, "validate-opcode-operand-extremes");
    }

    /// The `MAX_INSTS` boundary, which the generators never reach.
    ///
    /// The ceiling itself is asserted outright rather than only digested: a
    /// program of exactly [`abi::MAX_INSTS`] instructions is one too many, and
    /// that is the boundary an embedder actually runs into.
    #[test]
    fn the_instruction_limit_is_decided_as_recorded() {
      let config = configs().remove(0).1;
      let mut digest = SweepDigest::new();
      for len in [
        abi::MAX_INSTS as usize - 1,
        abi::MAX_INSTS as usize,
        abi::MAX_INSTS as usize + 1,
      ] {
        let mut program = vec![insn(0xb7, 0, 0, 0, 0); len];
        *program.last_mut().unwrap() = exit();
        add_decision(&mut digest, &config, &program);
      }
      assert_eq!(
        digest.translated(),
        1,
        "exactly one of the three lengths is inside the {} instruction ceiling",
        abi::MAX_INSTS
      );
      finish(digest, "validate-instruction-limit");
    }

    /// Hand-written cases for rules the generators reach rarely or never.
    #[test]
    fn hand_picked_corner_cases_are_decided_as_recorded() {
      let cases: Vec<Vec<Insn>> = vec![
        // A jump to itself.
        vec![insn(opcode::JA, 0, 0, -1, 0), exit()],
        vec![insn(opcode::JA32, 0, 0, 0, -1), exit()],
        // A `lddw` as the final instruction, with no room for its high half.
        vec![insn(opcode::LDDW, 0, 0, 0, 1)],
        // A `lddw` whose high half is a real instruction.
        vec![insn(opcode::LDDW, 0, 0, 0, 1), exit(), exit()],
        // A `lddw` with a source register, which upstream's table would allow.
        vec![insn(opcode::LDDW, 0, 1, 0, 1), insn(0, 0, 0, 0, 0), exit()],
        // Call kinds 2 and 3.
        vec![insn(opcode::CALL, 0, 2, 0, 0), exit()],
        vec![insn(opcode::CALL, 0, 3, 0, 0), exit()],
        vec![insn(opcode::CALL, 0, 15, 0, 0), exit()],
        // A negative helper index.
        vec![insn(opcode::CALL, 0, 0, 0, -1), exit()],
        // A local call whose immediate overflows the C's `int` arithmetic.
        vec![insn(opcode::CALL, 0, 1, 0, i32::MAX), exit()],
        vec![insn(opcode::CALL, 0, 1, 0, i32::MIN), exit()],
        // A local call landing on the high half of a `lddw`. The sub-program
        // check sees the boundary, not the pair.
        vec![
          insn(opcode::CALL, 0, 1, 0, 1),
          insn(opcode::LDDW, 0, 0, 0, 1),
          insn(0, 0, 0, 0, 0),
          exit(),
        ],
        // A local call to itself.
        vec![insn(opcode::CALL, 0, 1, 0, -1), exit()],
        // A sub-program that does not end in `exit`.
        vec![
          insn(opcode::CALL, 0, 1, 0, 1),
          exit(),
          insn(0xb7, 0, 0, 0, 0),
        ],
        // A sub-program ending in an unconditional jump instead.
        vec![
          insn(opcode::CALL, 0, 1, 0, 1),
          exit(),
          insn(opcode::JA, 0, 0, 0, 0),
          insn(0xb7, 0, 0, 0, 0),
        ],
        // A jump out of one sub-program into another. In range for `validate`,
        // refused by the self-containment check.
        vec![
          insn(opcode::CALL, 0, 1, 0, 1),
          exit(),
          insn(opcode::JA, 0, 0, -3, 0),
          exit(),
        ],
      ];
      let mut digest = SweepDigest::new();
      let n = cases.len();
      for program in cases {
        for (_, config) in configs() {
          add_decision(&mut digest, &config, &program);
        }
      }
      assert_eq!(digest.cases(), n * 2);
      finish(digest, "validate-corner-cases");
    }

    /// `lddw` and its high half, exhaustively over the fields that matter.
    ///
    /// The pairing rule is the only place a single instruction reaches across a
    /// slot boundary, and the tree carries a local patch ("Validate LDDW
    /// second-half instruction fields") that constrains the high half. It is
    /// also where the C's reported PC goes off by one, so both halves' register
    /// nibbles are swept.
    #[test]
    fn every_lddw_pairing_is_decided_as_recorded() {
      let config = configs().remove(0).1;
      let mut digest = SweepDigest::new();
      for dst in 0u8..=15 {
        for src in [0u8, 1, 6, 7, 10, 11] {
          for high_opcode in [0u8, 0x95, 0x18, 0x01] {
            for high_dst in [0u8, 1, 15] {
              for high_src in [0u8, 1, 15] {
                for high_offset in [0i16, 1, -1] {
                  let program = [
                    insn(opcode::LDDW, dst, src, 0, 0x1234),
                    insn(high_opcode, high_dst, high_src, high_offset, -1),
                    exit(),
                  ];
                  add_decision(&mut digest, &config, &program);
                }
              }
            }
          }
        }
      }
      assert_eq!(digest.cases(), 16 * 6 * 4 * 3 * 3 * 3);
      assert!(digest.translated() > 0, "no lddw pairing was accepted");
      finish(digest, "validate-lddw-pairings");
    }

    /// Every four-instruction program over an alphabet chosen to stress the
    /// sub-program partition.
    ///
    /// `check_for_self_contained_sub_programs` is the least local rule in the
    /// file: the partition depends on the whole set of local call targets, and
    /// the termination rule looks at the last *two* slots of each part. Random
    /// generation reaches it, but only sparsely. Enumerating a small alphabet
    /// exhaustively is what actually covers the boundary arithmetic — including
    /// calls that target the middle of a `lddw` and parts of length one.
    #[test]
    fn every_short_program_over_a_control_flow_alphabet_is_decided_as_recorded() {
      let config = configs().remove(0).1;
      let no_dispatcher = Config::default();
      let alphabet: Vec<Insn> = vec![
        insn(0xb7, 0, 0, 0, 0),
        exit(),
        insn(opcode::JA, 0, 0, 0, 0),
        insn(opcode::JA, 0, 0, 1, 0),
        insn(opcode::JA, 0, 0, -2, 0),
        insn(opcode::JA32, 0, 0, 0, 1),
        insn(opcode::JA32, 0, 0, 0, -3),
        insn(opcode::CALL, 0, 1, 0, 0),
        insn(opcode::CALL, 0, 1, 0, 1),
        insn(opcode::CALL, 0, 1, 0, 2),
        insn(opcode::CALL, 0, 1, 0, -2),
        insn(opcode::CALL, 0, 0, 0, 3),
        insn(opcode::LDDW, 0, 0, 0, 7),
        insn(0, 0, 0, 0, 9),
      ];
      let n = alphabet.len();
      let mut digest = SweepDigest::new();
      for a in 0..n {
        for b in 0..n {
          for c in 0..n {
            for d in 0..n {
              let program = [alphabet[a], alphabet[b], alphabet[c], alphabet[d]];
              add_decision(&mut digest, &config, &program);
              // The alphabet contains a helper call, which is the one thing the
              // configuration changes, so it is worth both passes here.
              add_decision(&mut digest, &no_dispatcher, &program);
            }
          }
        }
      }
      assert_eq!(digest.cases(), n.pow(4) * 2);
      assert!(
        digest.translated() > 0,
        "no four-instruction program was accepted"
      );
      finish(digest, "validate-control-flow-alphabet");
    }

    /// The zero-length program, and which layer refuses it.
    ///
    /// [`validate`] accepts an empty program: its loop does not run and the
    /// sub-program check finds no local call. There is nothing invalid about
    /// it, and saying otherwise here would put an allocation failure inside a
    /// validator — a lie about which layer refused and why.
    ///
    /// The refusal belongs one layer up, in [`Translator::load`], which cannot
    /// give out a zero-length mapping for the bytecode and reports "out of
    /// memory". That message is the one embedders see, so it is pinned
    /// literally rather than digested.
    #[test]
    fn the_empty_program_is_refused_by_the_loader_not_the_validator() {
      let config = configs().remove(0).1;
      assert_eq!(validate(&config, &[]), Ok(()));
      assert_eq!(
        Translator::load(Arc::new(config), &[]).err().map(|e| e.0),
        Some("program is empty".to_string())
      );
    }

    /// Every atomic selector, at both widths, against both opcodes.
    #[test]
    fn every_atomic_selector_is_decided_as_recorded() {
      let config = configs().remove(0).1;
      let mut digest = SweepDigest::new();
      for opcode in [0xc3u8, 0xdb] {
        for imm in -1i32..=0x120 {
          let program = [insn(opcode, 1, 2, 0, imm), exit()];
          add_decision(&mut digest, &config, &program);
        }
      }
      assert_eq!(digest.cases(), 2 * 0x122);
      // Both the accepted and the refused selectors have to be represented, or
      // the sweep has stopped straddling the filter it exists to pin.
      assert!(
        digest.translated() > 0 && digest.translated() < digest.cases(),
        "{} of {} selectors were accepted",
        digest.translated(),
        digest.cases()
      );
      finish(digest, "validate-atomic-selectors");
    }
  }
}

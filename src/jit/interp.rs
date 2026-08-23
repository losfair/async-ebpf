//! A reference eBPF interpreter, for tests only.
//!
//! # Why this exists
//!
//! The primary oracle for the JIT port is byte-for-byte comparison against the
//! vendored C. That oracle is silent about one class of defect: a bug faithfully
//! reproduced from the C. Byte equality proves the port is a port; it proves
//! nothing about whether the thing being ported computes the right answer.
//!
//! This interpreter is the second opinion. It is written **from the instruction
//! set** — from [`crate::jit::isa`] and from the published eBPF semantics — and
//! deliberately *not* from `ubpf_vm.c`'s interpreter, which was never read while
//! writing it. Copying that would reproduce its bugs and make this layer
//! worthless.
//!
//! Consequently, where this disagrees with the C, neither side is automatically
//! right. The disagreement is the result; it wants investigating, not silencing.
//!
//! # Deliberately naive
//!
//! Plain `[u64; 11]` registers, `Vec<u8>` for memory, a linear `match`, no
//! pointer cage, no fast paths. Every semantic decision is meant to be readable
//! straight off the source. Clarity beats speed here by a wide margin.
//!
//! # Semantics implemented, and confidence in each
//!
//! High confidence (these are stated plainly by the ISA and are load-bearing
//! everywhere):
//!
//! * Every 32-bit ALU operation computes on the low 32 bits and **zero-extends**
//!   the result into the upper half. That includes `mov32`, `neg32`, and a
//!   32-bit shift by a multiple of 32, which is a no-op on the low half but
//!   still clears the top half.
//! * Shift amounts are masked: `& 63` for 64-bit, `& 31` for 32-bit. eBPF has no
//!   trapping or saturating shift.
//! * Division and modulo by zero are *defined*: `div` yields 0, `mod` leaves the
//!   destination unchanged (subject to the 32-bit zero-extension rule above).
//!   They do not fault.
//! * `arsh` shifts the destination arithmetically at the operating width, so
//!   `arsh32` propagates bit 31, not bit 63, and then zero-extends.
//! * JMP32-class comparisons look only at the low 32 bits of both operands.
//! * Immediates are sign-extended from 32 to 64 bits before use, including for
//!   *unsigned* 64-bit comparisons — `jgt r1, -1` compares against
//!   `0xffff_ffff_ffff_ffff`.
//! * `lddw` takes its low half from its own `imm` and its high half from the
//!   `imm` of the following slot, which is not itself an instruction.
//! * `cmpxchg` compares against `R0` and writes the **previous** memory value
//!   back to `R0` whether or not the exchange happened.
//!
//! Reasoned out, and worth a reviewer's attention (each is flagged again at its
//! implementation site):
//!
//! * `div`/`mod` are **unsigned only** in this ISA generation. The signed
//!   `sdiv`/`smod` of ISA v4 are distinguished by `offset == 1`, and
//!   [`crate::jit::isa`] does not decode that — `Op::Alu` has no signed division.
//!   So `INT_MIN / -1` here is the *unsigned* division of `0x8000…` by
//!   `0xffff…`, which is 0. See [`tests::int_min_over_minus_one_is_unsigned`].
//! * `le`/`be` are implemented for a little-endian host: `le` is a truncation to
//!   the named width, `be` is a byte reversal of that width. Both zero-extend.
//!   `bswap` reverses unconditionally. A big-endian host would need `le` and
//!   `be` swapped; uBPF targets x86_64 and aarch64 only.
//! * A local `call` preserves `R6`–`R9` and `R10` and clobbers everything else.
//!   The eBPF calling convention names `R6`–`R9` callee-saved, but nothing in
//!   the *bytecode* saves them: the preservation is performed by the
//!   implementation — a JIT's per-function prologue — so whether it happens at
//!   the bytecode level is an implementation property rather than an ISA one,
//!   and it could plausibly have gone either way. It was settled by black-box
//!   probe rather than by assumption: the C interpreter, driven through
//!   `ubpf_exec` with a callee that overwrites each register in turn, restores
//!   `R6`–`R9` and lets `R0`, `R1` and `R5` through.
//!   [`Interpreter::not_preserving_callee_saved`] selects the other behaviour
//!   for an implementation that turns out to differ.
//! * Helper calls do not clobber `R1`–`R5`; only `R0` changes. A host ABI would
//!   clobber them, but the ISA only promises they are *arguments*. Probing the C
//!   interpreter agrees: `R1` survives a helper call there.
//! * Unaligned access faults by default, and this is the one place the default
//!   is knowingly *stricter* than the C, which was probed and reads an unaligned
//!   word happily. Faulting catches a class of test-program bug that would
//!   otherwise pass silently; [`Interpreter::allowing_unaligned`] turns it off,
//!   and an execution-differential test against the C wants that.
//! * A write to `R10` is permitted here. The validator rejects such programs, so
//!   this only matters for hand-written test inputs.

use crate::jit::abi;
use crate::jit::isa::{
  AluOp, AluWidth, AtomicOp, EndKind, Insn, JmpOp, Op, Source, Width, NUM_REGS, REG_FP,
};

/// Guest address the interpreter's stack region starts at, by default.
pub const DEFAULT_STACK_BASE: u64 = 0x1_0000_0000;
/// Guest address the interpreter's data region starts at, by default.
pub const DEFAULT_MEM_BASE: u64 = 0x2_0000_0000;
/// Instructions executed before a run is abandoned, by default. A malformed
/// program must terminate rather than hang the test suite.
pub const DEFAULT_STEP_BUDGET: u64 = 1_000_000;

/// One helper invocation, in the order it happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelperCall {
  /// The `imm` of the `call`, i.e. the helper index.
  pub index: u32,
  /// `R1` through `R5` as the helper saw them.
  pub args: [u64; 5],
  /// What the dispatcher returned, which became `R0`.
  pub ret: u64,
}

/// Why a memory access failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FaultKind {
  /// The access, in whole or in part, lay outside both regions.
  OutOfBounds,
  /// The address was not a multiple of the access width.
  Unaligned,
}

/// How a run ended.
///
/// Plain owned data with `PartialEq`, so an execution-differential test can
/// compare a JIT run's outcome against an interpreted one directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Termination {
  /// `exit` at call depth zero. Carries `R0`.
  Exit(u64),
  /// A load, store or atomic touched memory it may not.
  Fault {
    pc: usize,
    addr: u64,
    len: usize,
    kind: FaultKind,
  },
  /// The step budget ran out. Almost always an unintended loop.
  StepBudget,
  /// A local `call` beyond the depth limit.
  CallDepthExceeded { pc: usize },
  /// The program is not executable: an undefined opcode, a register number out
  /// of range, a jump leaving the program, a truncated `lddw`.
  Invalid { pc: usize, reason: String },
}

/// Everything a run produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
  /// How it ended, including the return value on a normal exit.
  pub termination: Termination,
  /// The data region as the program left it.
  pub memory: Vec<u8>,
  /// The stack region as the program left it.
  pub stack: Vec<u8>,
  /// Helper calls, in order.
  pub helpers: Vec<HelperCall>,
  /// Instructions retired.
  pub steps: u64,
  /// The final register file, for tests that want to look inside.
  pub regs: [u64; NUM_REGS],
}

impl Run {
  /// `R0` if the program exited normally, `None` otherwise.
  pub fn return_value(&self) -> Option<u64> {
    match self.termination {
      Termination::Exit(v) => Some(v),
      _ => None,
    }
  }
}

/// A configured machine, ready to run one program once.
pub struct Interpreter<'a> {
  insns: &'a [Insn],
  memory: Vec<u8>,
  stack: Vec<u8>,
  mem_base: u64,
  stack_base: u64,
  args: Option<[u64; 5]>,
  step_budget: u64,
  max_call_depth: usize,
  frame_size: u64,
  check_alignment: bool,
  preserve_callee_saved: bool,
}

/// A suspended caller, for local calls.
struct Frame {
  return_pc: usize,
  saved_fp: u64,
  /// `R6`–`R9`, saved unless [`Interpreter::not_preserving_callee_saved`] was
  /// used.
  saved_callee: Option<[u64; 4]>,
}

impl<'a> Interpreter<'a> {
  /// A machine over `insns` with `memory` as its data region.
  ///
  /// `R1` and `R2` default to the data region's base and length, which is the
  /// convention every eBPF program in this tree is written to.
  pub fn new(insns: &'a [Insn], memory: Vec<u8>) -> Self {
    Self {
      insns,
      memory,
      stack: vec![0; abi::EBPF_STACK_SIZE as usize],
      mem_base: DEFAULT_MEM_BASE,
      stack_base: DEFAULT_STACK_BASE,
      args: None,
      step_budget: DEFAULT_STEP_BUDGET,
      max_call_depth: abi::MAX_CALL_DEPTH as usize,
      frame_size: abi::LOCAL_FUNCTION_STACK_SIZE as u64,
      check_alignment: true,
      preserve_callee_saved: true,
    }
  }

  /// Sets `R1`–`R5` at entry explicitly.
  pub fn with_args(mut self, args: [u64; 5]) -> Self {
    self.args = Some(args);
    self
  }

  /// Places the two regions at chosen guest addresses, so a differential test
  /// can hand the JIT the same numbers.
  pub fn with_bases(mut self, stack_base: u64, mem_base: u64) -> Self {
    self.stack_base = stack_base;
    self.mem_base = mem_base;
    self
  }

  /// Resizes the stack region.
  pub fn with_stack_size(mut self, bytes: usize) -> Self {
    self.stack = vec![0; bytes];
    self
  }

  /// Caps instructions retired.
  pub fn with_step_budget(mut self, steps: u64) -> Self {
    self.step_budget = steps;
    self
  }

  /// Caps local call nesting.
  pub fn with_max_call_depth(mut self, depth: usize) -> Self {
    self.max_call_depth = depth;
    self
  }

  /// Stops treating a misaligned access as a fault.
  pub fn allowing_unaligned(mut self) -> Self {
    self.check_alignment = false;
    self
  }

  /// Lets `R6`–`R9` flow through a local call unchanged, instead of the default
  /// save-and-restore. See the module docs: which of the two an implementation
  /// does is not settled by the ISA, so both are available.
  pub fn not_preserving_callee_saved(mut self) -> Self {
    self.preserve_callee_saved = false;
    self
  }

  /// Runs to completion, dispatching helper calls through `helper`.
  ///
  /// `helper` receives the helper index and `R1`–`R5`; its return value becomes
  /// `R0`. Every call is recorded in [`Run::helpers`] in order.
  pub fn run(mut self, mut helper: impl FnMut(u32, [u64; 5]) -> u64) -> Run {
    let mut regs = [0u64; NUM_REGS];
    let args = self
      .args
      .unwrap_or([self.mem_base, self.memory.len() as u64, 0, 0, 0]);
    regs[1..6].copy_from_slice(&args);
    // R10 is the frame pointer: it points one past the top of the stack region,
    // and guest accesses are at negative displacements from it.
    regs[REG_FP as usize] = self.stack_base + self.stack.len() as u64;

    let mut helpers = Vec::new();
    let mut frames: Vec<Frame> = Vec::new();
    let mut steps = 0u64;
    let mut pc = 0usize;

    let termination = loop {
      if steps >= self.step_budget {
        break Termination::StepBudget;
      }
      steps += 1;

      let Some(&insn) = self.insns.get(pc) else {
        break invalid(pc, "pc left the program without an exit");
      };
      let Some(op) = insn.op_with_imm() else {
        break invalid(pc, format!("undefined encoding {:#04x}", insn.opcode));
      };
      if insn.dst as usize >= NUM_REGS || insn.src as usize >= NUM_REGS {
        break invalid(pc, "register number out of range");
      }
      let dst = insn.dst as usize;
      let src = insn.src as usize;
      let this_pc = pc;
      // Everything below either falls through to the next slot or overwrites
      // `pc`, so advancing here keeps the jump arms free of `+ 1`s.
      pc += 1;

      match op {
        Op::Alu { width, op, source } => {
          // The immediate is sign-extended to 64 bits first. For a 32-bit
          // operation only the low half survives, which makes the extension
          // invisible there, but for ALU64 it is the whole point: `add r0, -1`
          // must add `0xffff_ffff_ffff_ffff`.
          let operand = match source {
            Source::Imm => insn.imm as i64 as u64,
            Source::Reg => regs[src],
          };
          // `div`/`mod` carry their signedness in the offset field rather than
          // in a distinct opcode; every other operation ignores it.
          regs[dst] = alu_signed(width, op, regs[dst], operand, is_signed_divmod(&insn));
        }

        Op::End(kind) => match end(kind, regs[dst], insn.imm) {
          Some(v) => regs[dst] = v,
          None => break invalid(this_pc, format!("byte-order width {}", insn.imm)),
        },

        Op::LoadImm64 => {
          // The second slot is not an instruction: it carries the high 32 bits
          // of the immediate and is skipped.
          let Some(&high) = self.insns.get(pc) else {
            break invalid(this_pc, "lddw is missing its second slot");
          };
          regs[dst] = (insn.imm as u32 as u64) | ((high.imm as u32 as u64) << 32);
          pc += 1;
        }

        Op::Load { width, signed } => {
          let addr = regs[src].wrapping_add(insn.offset as i64 as u64);
          match self.load(addr, width) {
            Ok(raw) => {
              regs[dst] = if signed { sign_extend(raw, width) } else { raw };
            }
            Err(kind) => break fault(this_pc, addr, width, kind),
          }
        }

        Op::StoreImm { width } => {
          let addr = regs[dst].wrapping_add(insn.offset as i64 as u64);
          // The immediate is sign-extended to 64 bits and then truncated to the
          // access width, so `stb [r1], -1` writes `0xff`.
          if let Err(kind) = self.store(addr, width, insn.imm as i64 as u64) {
            break fault(this_pc, addr, width, kind);
          }
        }

        Op::StoreReg { width } => {
          let addr = regs[dst].wrapping_add(insn.offset as i64 as u64);
          if let Err(kind) = self.store(addr, width, regs[src]) {
            break fault(this_pc, addr, width, kind);
          }
        }

        Op::Atomic { width, op, fetch } => {
          let addr = regs[dst].wrapping_add(insn.offset as i64 as u64);
          let old = match self.load(addr, width) {
            Ok(v) => v,
            Err(kind) => break fault(this_pc, addr, width, kind),
          };
          let value = regs[src];
          // Every atomic computes at the access width; `truncate` keeps the
          // 32-bit forms from letting the upper half of a register leak in.
          let (new, store) = match op {
            AtomicOp::Add => (truncate(old.wrapping_add(value), width), true),
            AtomicOp::Or => (truncate(old | value, width), true),
            AtomicOp::And => (truncate(old & value, width), true),
            AtomicOp::Xor => (truncate(old ^ value, width), true),
            AtomicOp::Xchg => (truncate(value, width), true),
            // cmpxchg compares the loaded value against R0 at the access width,
            // and stores only on a match.
            AtomicOp::Cmpxchg => {
              let matched = old == truncate(regs[0], width);
              (truncate(value, width), matched)
            }
          };
          if store {
            if let Err(kind) = self.store(addr, width, new) {
              break fault(this_pc, addr, width, kind);
            }
          }
          if fetch {
            // The previous value goes to R0 for cmpxchg — always, match or not —
            // and to the source register for everything else.
            if op == AtomicOp::Cmpxchg {
              regs[0] = old;
            } else {
              regs[src] = old;
            }
          }
        }

        Op::Ja { width } => {
          // JMP-class `ja` jumps by `offset`; the JMP32-class form exists to
          // reach further and takes its displacement from `imm` instead.
          let disp = match width {
            AluWidth::W64 => insn.offset as i64,
            AluWidth::W32 => insn.imm as i64,
          };
          match branch(pc, disp, self.insns.len()) {
            Some(target) => pc = target,
            None => break invalid(this_pc, "jump target outside the program"),
          }
        }

        Op::Jmp { width, op, source } => {
          let operand = match source {
            Source::Imm => insn.imm as i64 as u64,
            Source::Reg => regs[src],
          };
          if compare(width, op, regs[dst], operand) {
            match branch(pc, insn.offset as i64, self.insns.len()) {
              Some(target) => pc = target,
              None => break invalid(this_pc, "jump target outside the program"),
            }
          }
        }

        Op::Call if insn.is_local_call() => {
          if frames.len() + 1 > self.max_call_depth {
            break Termination::CallDepthExceeded { pc: this_pc };
          }
          let Some(target) = branch(pc, insn.imm as i64, self.insns.len()) else {
            break invalid(this_pc, "local call target outside the program");
          };
          let fp = &mut regs[REG_FP as usize];
          let saved_fp = *fp;
          // Each nested function gets its own frame below the caller's.
          *fp = saved_fp - self.frame_size;
          frames.push(Frame {
            return_pc: pc,
            saved_fp,
            saved_callee: if self.preserve_callee_saved {
              Some([regs[6], regs[7], regs[8], regs[9]])
            } else {
              None
            },
          });
          pc = target;
        }

        Op::Call => {
          let args = [regs[1], regs[2], regs[3], regs[4], regs[5]];
          let index = insn.imm as u32;
          let ret = helper(index, args);
          helpers.push(HelperCall { index, args, ret });
          regs[0] = ret;
        }

        Op::Exit => match frames.pop() {
          None => break Termination::Exit(regs[0]),
          Some(frame) => {
            regs[REG_FP as usize] = frame.saved_fp;
            if let Some(saved) = frame.saved_callee {
              regs[6..10].copy_from_slice(&saved);
            }
            pc = frame.return_pc;
          }
        },
      }
    };

    Run {
      termination,
      memory: self.memory,
      stack: self.stack,
      helpers,
      steps,
      regs,
    }
  }

  /// Locates `len` bytes at `addr` in one of the two regions.
  ///
  /// An access that straddles the end of a region, or falls between them, or
  /// wraps the address space, is out of bounds. There is no third region and no
  /// pointer cage: this is the whole memory model.
  fn locate(&mut self, addr: u64, len: usize) -> Result<&mut [u8], FaultKind> {
    if self.check_alignment && addr % len as u64 != 0 {
      return Err(FaultKind::Unaligned);
    }
    let end = addr.checked_add(len as u64).ok_or(FaultKind::OutOfBounds)?;
    let region = |base: u64, region_len: usize| -> Option<usize> {
      if addr >= base && end <= base + region_len as u64 {
        Some((addr - base) as usize)
      } else {
        None
      }
    };
    if let Some(off) = region(self.stack_base, self.stack.len()) {
      return Ok(&mut self.stack[off..off + len]);
    }
    if let Some(off) = region(self.mem_base, self.memory.len()) {
      return Ok(&mut self.memory[off..off + len]);
    }
    Err(FaultKind::OutOfBounds)
  }

  /// Reads `width` bytes little-endian, zero-extended to 64 bits.
  fn load(&mut self, addr: u64, width: Width) -> Result<u64, FaultKind> {
    let bytes = self.locate(addr, width.bytes())?;
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
  }

  /// Writes the low `width` bytes of `value`, little-endian.
  fn store(&mut self, addr: u64, width: Width, value: u64) -> Result<(), FaultKind> {
    let bytes = self.locate(addr, width.bytes())?;
    let n = bytes.len();
    bytes.copy_from_slice(&value.to_le_bytes()[..n]);
    Ok(())
  }
}

fn invalid(pc: usize, reason: impl Into<String>) -> Termination {
  Termination::Invalid {
    pc,
    reason: reason.into(),
  }
}

fn fault(pc: usize, addr: u64, width: Width, kind: FaultKind) -> Termination {
  Termination::Fault {
    pc,
    addr,
    len: width.bytes(),
    kind,
  }
}

/// Resolves a relative branch. `next` is the slot after the branch, since eBPF
/// displacements are counted from there.
fn branch(next: usize, disp: i64, len: usize) -> Option<usize> {
  let target = next as i64 + disp;
  // Landing exactly at `len` is still off the end: there is no instruction
  // there, and falling into it would be an exit the program never wrote.
  (0..len as i64).contains(&target).then_some(target as usize)
}

/// Keeps only the low `width` bytes of `value`.
fn truncate(value: u64, width: Width) -> u64 {
  match width {
    Width::B => value as u8 as u64,
    Width::H => value as u16 as u64,
    Width::W => value as u32 as u64,
    Width::DW => value,
  }
}

/// Sign-extends the low `width` bytes of `value` to 64 bits.
fn sign_extend(value: u64, width: Width) -> u64 {
  match width {
    Width::B => value as u8 as i8 as i64 as u64,
    Width::H => value as u16 as i16 as i64 as u64,
    Width::W => value as u32 as i32 as i64 as u64,
    Width::DW => value,
  }
}

/// One ALU operation.
///
/// The 32-bit arm computes in `u32` and widens with `as u64`, which is a zero
/// extension — that single conversion is the whole of the "32-bit ALU
/// zero-extends" rule, applied uniformly to every operation including `mov` and
/// a shift whose masked amount is zero.
/// Whether a `div`/`mod` is the signed flavour.
///
/// There is no separate `sdiv`/`smod` opcode in this ISA generation — `ebpf.h`
/// names none, which makes it easy to conclude the operation does not exist.
/// It does: signedness rides in the *offset field* of the ordinary `div`/`mod`
/// opcode, and both JIT backends read it
/// (`is_signed = (offset == 1)`, `ubpf_jit_x86_64.c:1907`,
/// `ubpf_jit_arm64.c:2535`). The validator's filter bounds that offset at
/// `0..=1`, so both flavours load.
///
/// Note that the C *interpreter* does not implement this at all — `is_signed`
/// appears nowhere in `ubpf_vm.c`. So the vendored tree's JIT and interpreter
/// genuinely disagree about what `div r1, r2` with `offset == 1` computes. This
/// interpreter follows the JIT, because its job is to be an oracle for the JIT.
pub fn is_signed_divmod(insn: &Insn) -> bool {
  insn.offset == 1
}

fn alu_signed(width: AluWidth, op: AluOp, dst: u64, operand: u64, signed: bool) -> u64 {
  match width {
    AluWidth::W64 => match op {
      AluOp::Add => dst.wrapping_add(operand),
      AluOp::Sub => dst.wrapping_sub(operand),
      AluOp::Mul => dst.wrapping_mul(operand),
      // Division by zero is defined to produce zero, and modulo by zero to
      // leave the destination alone. Neither faults.
      //
      // The signed flavours additionally have to survive `INT_MIN / -1`, whose
      // true quotient is not representable. Both backends special-case it: the
      // result wraps to `INT_MIN` for division and is 0 for modulo, which is
      // what `wrapping_div`/`wrapping_rem` already do. Doing it with plain `/`
      // would panic in debug and trap on x86 `idiv` — the reason the C emits an
      // explicit overflow check around it.
      AluOp::Div if signed => {
        if operand == 0 {
          0
        } else {
          (dst as i64).wrapping_div(operand as i64) as u64
        }
      }
      AluOp::Mod if signed => {
        if operand == 0 {
          dst
        } else {
          (dst as i64).wrapping_rem(operand as i64) as u64
        }
      }
      AluOp::Div => {
        if operand == 0 {
          0
        } else {
          dst / operand
        }
      }
      AluOp::Mod => {
        if operand == 0 {
          dst
        } else {
          dst % operand
        }
      }
      AluOp::Or => dst | operand,
      AluOp::And => dst & operand,
      AluOp::Xor => dst ^ operand,
      // Shift amounts are taken modulo the register width; there is no
      // saturation and no fault for an over-wide shift.
      AluOp::Lsh => dst << (operand & 63),
      AluOp::Rsh => dst >> (operand & 63),
      AluOp::Arsh => ((dst as i64) >> (operand & 63)) as u64,
      AluOp::Neg => (dst as i64).wrapping_neg() as u64,
      AluOp::Mov => operand,
    },
    AluWidth::W32 => {
      let a = dst as u32;
      let b = operand as u32;
      let r = match op {
        AluOp::Add => a.wrapping_add(b),
        AluOp::Sub => a.wrapping_sub(b),
        AluOp::Mul => a.wrapping_mul(b),
        AluOp::Div if signed => {
          if b == 0 {
            0
          } else {
            (a as i32).wrapping_div(b as i32) as u32
          }
        }
        AluOp::Mod if signed => {
          if b == 0 {
            a
          } else {
            (a as i32).wrapping_rem(b as i32) as u32
          }
        }
        AluOp::Div => {
          if b == 0 {
            0
          } else {
            a / b
          }
        }
        AluOp::Mod => {
          if b == 0 {
            a
          } else {
            a % b
          }
        }
        AluOp::Or => a | b,
        AluOp::And => a & b,
        AluOp::Xor => a ^ b,
        AluOp::Lsh => a << (b & 31),
        AluOp::Rsh => a >> (b & 31),
        // `arsh32` propagates bit 31, not bit 63: the destination's upper half
        // takes no part in the shift and is then zeroed by the widening below.
        AluOp::Arsh => ((a as i32) >> (b & 31)) as u32,
        AluOp::Neg => (a as i32).wrapping_neg() as u32,
        AluOp::Mov => b,
      };
      r as u64
    }
  }
}

/// `le` / `be` / `bswap`, whose width lives in the immediate.
///
/// Written for a little-endian host, where "convert to little-endian" is the
/// identity on the bytes and leaves only the truncation to the named width, and
/// "convert to big-endian" is a reversal of that width. All three zero-extend:
/// a 16-bit conversion leaves 48 zero bits above the result, which is the corner
/// a JIT is most likely to get wrong by reversing in place.
fn end(kind: EndKind, dst: u64, imm: i32) -> Option<u64> {
  Some(match (kind, imm) {
    (EndKind::Le, 16) => dst as u16 as u64,
    (EndKind::Le, 32) => dst as u32 as u64,
    (EndKind::Le, 64) => dst,
    (EndKind::Be, 16) | (EndKind::Bswap, 16) => (dst as u16).swap_bytes() as u64,
    (EndKind::Be, 32) | (EndKind::Bswap, 32) => (dst as u32).swap_bytes() as u64,
    (EndKind::Be, 64) | (EndKind::Bswap, 64) => dst.swap_bytes(),
    _ => return None,
  })
}

/// One conditional-jump predicate.
///
/// The 32-bit arm truncates *both* operands first, so a JMP32 comparison cannot
/// see the upper half of either register, and its signed forms compare `i32`s —
/// which is not the same as comparing the sign-extended 64-bit values would be
/// only if the truncation were skipped.
fn compare(width: AluWidth, op: JmpOp, dst: u64, operand: u64) -> bool {
  match width {
    AluWidth::W64 => {
      let (a, b) = (dst, operand);
      let (sa, sb) = (a as i64, b as i64);
      match op {
        JmpOp::Eq => a == b,
        JmpOp::Ne => a != b,
        JmpOp::Gt => a > b,
        JmpOp::Ge => a >= b,
        JmpOp::Lt => a < b,
        JmpOp::Le => a <= b,
        JmpOp::Set => a & b != 0,
        JmpOp::Sgt => sa > sb,
        JmpOp::Sge => sa >= sb,
        JmpOp::Slt => sa < sb,
        JmpOp::Sle => sa <= sb,
      }
    }
    AluWidth::W32 => {
      let (a, b) = (dst as u32, operand as u32);
      let (sa, sb) = (a as i32, b as i32);
      match op {
        JmpOp::Eq => a == b,
        JmpOp::Ne => a != b,
        JmpOp::Gt => a > b,
        JmpOp::Ge => a >= b,
        JmpOp::Lt => a < b,
        JmpOp::Le => a <= b,
        JmpOp::Set => a & b != 0,
        JmpOp::Sgt => sa > sb,
        JmpOp::Sge => sa >= sb,
        JmpOp::Slt => sa < sb,
        JmpOp::Sle => sa <= sb,
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::jit::isa::{alu, atomic, cls, jmp, mode, opcode, size, src as srcbit};

  // ---- assembly helpers -------------------------------------------------

  fn i(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Insn {
    Insn {
      opcode,
      dst,
      src,
      offset,
      imm,
    }
  }

  fn exit() -> Insn {
    i(opcode::EXIT, 0, 0, 0, 0)
  }

  fn mov64(dst: u8, imm: i32) -> Insn {
    i(cls::ALU64 | srcbit::IMM | alu::MOV, dst, 0, 0, imm)
  }

  fn lddw(dst: u8, value: u64) -> [Insn; 2] {
    [
      i(opcode::LDDW, dst, 0, 0, value as u32 as i32),
      i(0, 0, 0, 0, (value >> 32) as u32 as i32),
    ]
  }

  fn alu64_imm(op: u8, dst: u8, imm: i32) -> Insn {
    i(cls::ALU64 | srcbit::IMM | op, dst, 0, 0, imm)
  }

  fn alu64_reg(op: u8, dst: u8, src: u8) -> Insn {
    i(cls::ALU64 | srcbit::REG | op, dst, src, 0, 0)
  }

  fn alu32_imm(op: u8, dst: u8, imm: i32) -> Insn {
    i(cls::ALU | srcbit::IMM | op, dst, 0, 0, imm)
  }

  fn alu32_reg(op: u8, dst: u8, src: u8) -> Insn {
    i(cls::ALU | srcbit::REG | op, dst, src, 0, 0)
  }

  fn exec(insns: &[Insn]) -> Run {
    Interpreter::new(insns, Vec::new()).run(|_, _| 0)
  }

  /// Runs a program that must exit normally, and returns `R0`.
  fn r0(insns: &[Insn]) -> u64 {
    let run = exec(insns);
    match run.termination {
      Termination::Exit(v) => v,
      other => panic!("expected a normal exit, got {other:?}"),
    }
  }

  /// `r0 = a op b` at 64 bits, both operands in registers.
  fn eval64(op: u8, a: u64, b: u64) -> u64 {
    let mut p = Vec::new();
    p.extend(lddw(0, a));
    p.extend(lddw(1, b));
    p.push(alu64_reg(op, 0, 1));
    p.push(exit());
    r0(&p)
  }

  /// `r0 = a op b` at 32 bits, both operands in registers. `a` is loaded as a
  /// full 64-bit value so the zero-extension of the result is observable.
  fn eval32(op: u8, a: u64, b: u64) -> u64 {
    let mut p = Vec::new();
    p.extend(lddw(0, a));
    p.extend(lddw(1, b));
    p.push(alu32_reg(op, 0, 1));
    p.push(exit());
    r0(&p)
  }

  // ---- division and modulo ----------------------------------------------

  #[test]
  fn division_by_zero_yields_zero_and_does_not_fault() {
    assert_eq!(eval64(alu::DIV, 42, 0), 0);
    assert_eq!(eval32(alu::DIV, 42, 0), 0);
    // The immediate form takes the same path.
    assert_eq!(r0(&[mov64(0, 42), alu64_imm(alu::DIV, 0, 0), exit()]), 0);
    assert_eq!(r0(&[mov64(0, 42), alu32_imm(alu::DIV, 0, 0), exit()]), 0);
  }

  #[test]
  fn modulo_by_zero_leaves_the_destination_alone() {
    assert_eq!(eval64(alu::MOD, 42, 0), 42);
    // ...but the 32-bit form still zero-extends, so a destination with high
    // bits set comes back truncated rather than untouched. This is the corner a
    // JIT gets wrong by branching around the whole instruction.
    assert_eq!(eval32(alu::MOD, 0xdead_beef_0000_002a, 0), 0x2a);
    assert_eq!(
      eval64(alu::MOD, 0xdead_beef_0000_002a, 0),
      0xdead_beef_0000_002a
    );
  }

  #[test]
  fn int_min_over_minus_one_is_unsigned() {
    // This ISA generation has no signed division: `Op::Alu` carries no signed
    // flavour and the decoder ignores `offset`, where ISA v4 would put the
    // sdiv/smod marker. So the classic `INT_MIN / -1` overflow trap cannot
    // arise from the semantics — but a JIT that reaches for x86 `idiv` here
    // gets #DE, which is exactly what this pins.
    //
    // 0x8000_0000_0000_0000 / 0xffff_ffff_ffff_ffff unsigned is 0, remainder
    // the dividend itself.
    assert_eq!(eval64(alu::DIV, 1 << 63, u64::MAX), 0);
    assert_eq!(eval64(alu::MOD, 1 << 63, u64::MAX), 1 << 63);
    // At 32 bits: 0x8000_0000 / 0xffff_ffff = 0, remainder 0x8000_0000.
    assert_eq!(eval32(alu::DIV, 0x8000_0000, 0xffff_ffff), 0);
    assert_eq!(eval32(alu::MOD, 0x8000_0000, 0xffff_ffff), 0x8000_0000);
    // And with the operands as sign-extended immediates, where the 64-bit form
    // sees a genuine -1.
    let p = [
      lddw(0, 1 << 63)[0],
      lddw(0, 1 << 63)[1],
      alu64_imm(alu::DIV, 0, -1),
      exit(),
    ];
    assert_eq!(r0(&p), 0);
  }

  // ---- shifts ------------------------------------------------------------

  #[test]
  fn sixty_four_bit_shifts_mask_the_amount_to_six_bits() {
    let x = 0x0123_4567_89ab_cdefu64;
    assert_eq!(eval64(alu::LSH, x, 32), x << 32);
    assert_eq!(eval64(alu::LSH, x, 63), x << 63);
    // 64 & 63 == 0, so a shift by the register width is the identity.
    assert_eq!(eval64(alu::LSH, x, 64), x);
    assert_eq!(eval64(alu::LSH, x, 65), x << 1);
    assert_eq!(eval64(alu::LSH, x, 127), x << 63);
    assert_eq!(eval64(alu::RSH, x, 32), x >> 32);
    assert_eq!(eval64(alu::RSH, x, 64), x);
    assert_eq!(eval64(alu::RSH, x, 65), x >> 1);
    assert_eq!(eval64(alu::ARSH, x, 64), x);
  }

  #[test]
  fn thirty_two_bit_shifts_mask_to_five_bits_and_zero_extend() {
    let x = 0xdead_beef_89ab_cdefu64;
    let lo = x as u32;
    // 32 & 31 == 0: the low half is unchanged, but the upper half is cleared,
    // so this is emphatically not a no-op.
    assert_eq!(eval32(alu::LSH, x, 32), lo as u64);
    assert_eq!(eval32(alu::LSH, x, 31), ((lo << 31) as u64) & 0xffff_ffff);
    assert_eq!(eval32(alu::LSH, x, 33), (lo << 1) as u64);
    assert_eq!(eval32(alu::LSH, x, 64), lo as u64);
    assert_eq!(eval32(alu::RSH, x, 32), lo as u64);
    assert_eq!(eval32(alu::RSH, x, 33), (lo >> 1) as u64);
    assert_eq!(eval32(alu::ARSH, x, 32), lo as u64);
  }

  #[test]
  fn arsh_propagates_the_sign_of_the_operating_width() {
    // 64-bit: bit 63 fills.
    assert_eq!(eval64(alu::ARSH, 0x8000_0000_0000_0000, 63), u64::MAX);
    assert_eq!(
      eval64(alu::ARSH, 0x8000_0000_0000_0000, 4),
      0xf800_0000_0000_0000
    );
    // 32-bit: bit 31 fills the low half, and the result zero-extends, so the
    // answer is never sign-extended past bit 31.
    assert_eq!(eval32(alu::ARSH, 0x0000_0000_8000_0000, 31), 0xffff_ffff);
    assert_eq!(eval32(alu::ARSH, 0xffff_ffff_8000_0000, 4), 0xf800_0000);
    // A negative-looking 64-bit value whose low half is positive shifts as a
    // positive 32-bit number.
    assert_eq!(eval32(alu::ARSH, 0xffff_ffff_4000_0000, 4), 0x0400_0000);
  }

  // ---- 32-bit zero extension --------------------------------------------

  #[test]
  fn every_thirty_two_bit_alu_operation_zero_extends() {
    // Each destination starts with garbage in the upper half; after any 32-bit
    // ALU operation the upper half must be zero.
    let dirty = 0xdead_beef_0000_0007u64;
    let ops = [
      alu::ADD,
      alu::SUB,
      alu::MUL,
      alu::DIV,
      alu::OR,
      alu::AND,
      alu::LSH,
      alu::RSH,
      alu::MOD,
      alu::XOR,
      alu::MOV,
      alu::ARSH,
    ];
    for op in ops {
      let got = eval32(op, dirty, 3);
      assert_eq!(
        got >> 32,
        0,
        "op {op:#04x} left the upper half set: {got:#x}"
      );
    }
    // `neg32` takes no operand and must zero-extend too.
    let p = [
      lddw(0, dirty)[0],
      lddw(0, dirty)[1],
      alu32_imm(alu::NEG, 0, 0),
      exit(),
    ];
    assert_eq!(r0(&p), 0xffff_fff9);
    // ...and specifically `mov32`, which is the one most often emitted as a
    // plain 64-bit move.
    assert_eq!(eval32(alu::MOV, dirty, 0x1234), 0x1234);
    let p = [
      lddw(0, dirty)[0],
      lddw(0, dirty)[1],
      alu32_imm(alu::MOV, 0, -1),
      exit(),
    ];
    assert_eq!(r0(&p), 0xffff_ffff, "mov32 of -1 must not sign-extend");
  }

  #[test]
  fn sixty_four_bit_operations_keep_the_upper_half() {
    let dirty = 0xdead_beef_0000_0007u64;
    assert_eq!(eval64(alu::ADD, dirty, 1), dirty + 1);
    assert_eq!(eval64(alu::MOV, dirty, 0x1234), 0x1234);
    assert_eq!(
      r0(&[mov64(0, -1), exit()]),
      u64::MAX,
      "mov64 sign-extends its immediate"
    );
  }

  // ---- byte order --------------------------------------------------------

  #[test]
  fn le_truncates_and_be_reverses_at_each_width() {
    let x = 0x0123_4567_89ab_cdefu64;
    let le = |w: i32| {
      let mut p = lddw(0, x).to_vec();
      p.push(i(opcode::LE, 0, 0, 0, w));
      p.push(exit());
      r0(&p)
    };
    let be = |w: i32| {
      let mut p = lddw(0, x).to_vec();
      p.push(i(opcode::BE, 0, 0, 0, w));
      p.push(exit());
      r0(&p)
    };
    let bswap = |w: i32| {
      let mut p = lddw(0, x).to_vec();
      p.push(i(opcode::BSWAP, 0, 0, 0, w));
      p.push(exit());
      r0(&p)
    };

    // `le` on a little-endian host keeps the byte order and truncates. The
    // upper 48 bits at width 16 must be *zero*, not preserved.
    assert_eq!(le(16), 0xcdef);
    assert_eq!(le(32), 0x89ab_cdef);
    assert_eq!(le(64), x);
    // `be` reverses the named width and zero-extends.
    assert_eq!(be(16), 0xefcd);
    assert_eq!(be(32), 0xefcd_ab89);
    assert_eq!(be(64), 0xefcd_ab89_6745_2301);
    // `bswap` is unconditional and matches `be` on this host.
    assert_eq!(bswap(16), 0xefcd);
    assert_eq!(bswap(32), 0xefcd_ab89);
    assert_eq!(bswap(64), 0xefcd_ab89_6745_2301);
  }

  #[test]
  fn an_undefined_byte_order_width_is_rejected() {
    let run = exec(&[i(opcode::LE, 0, 0, 0, 24), exit()]);
    assert!(matches!(
      run.termination,
      Termination::Invalid { pc: 0, .. }
    ));
  }

  // ---- memory ------------------------------------------------------------

  /// A machine with sixteen bytes of data, `R1` pointing at them.
  fn with_mem(insns: &[Insn], mem: Vec<u8>) -> Run {
    Interpreter::new(insns, mem).run(|_, _| 0)
  }

  #[test]
  fn loads_zero_extend_and_sign_extending_loads_do_not() {
    let mem = vec![0xff, 0xfe, 0xfd, 0xfc, 0x80, 0x00, 0x00, 0x00];
    // ldxb r0, [r1+0]
    let ldxb = i(cls::LDX | mode::MEM | size::B, 0, 1, 0, 0);
    let ldxbsx = i(cls::LDX | mode::MEMSX | size::B, 0, 1, 0, 0);
    let ldxh = i(cls::LDX | mode::MEM | size::H, 0, 1, 0, 0);
    let ldxhsx = i(cls::LDX | mode::MEMSX | size::H, 0, 1, 0, 0);
    let ldxw = i(cls::LDX | mode::MEM | size::W, 0, 1, 0, 0);
    let ldxwsx = i(cls::LDX | mode::MEMSX | size::W, 0, 1, 0, 0);
    let val = |insn: Insn| {
      with_mem(&[insn, exit()], mem.clone())
        .return_value()
        .unwrap()
    };

    assert_eq!(val(ldxb), 0xff);
    assert_eq!(val(ldxbsx), 0xffff_ffff_ffff_ffff);
    assert_eq!(val(ldxh), 0xfeff);
    assert_eq!(val(ldxhsx), 0xffff_ffff_ffff_feff);
    assert_eq!(val(ldxw), 0xfcfd_feff);
    assert_eq!(val(ldxwsx), 0xffff_ffff_fcfd_feff);
    // A word whose top bit is clear sign-extends to itself.
    let ldxwsx4 = i(cls::LDX | mode::MEMSX | size::W, 0, 1, 4, 0);
    assert_eq!(val(ldxwsx4), 0x80);
  }

  #[test]
  fn stores_truncate_the_value_to_the_access_width() {
    // stw [r1+0], -1  then  stb [r1+4], 0x1ff
    let p = [
      i(cls::ST | mode::MEM | size::W, 1, 0, 0, -1),
      i(cls::ST | mode::MEM | size::B, 1, 0, 4, 0x1ff),
      exit(),
    ];
    let run = with_mem(&p, vec![0; 8]);
    assert_eq!(run.memory, vec![0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0]);
  }

  #[test]
  fn an_out_of_bounds_access_faults_instead_of_panicking() {
    // Read one byte past the end of an eight-byte region.
    let p = [i(cls::LDX | mode::MEM | size::B, 0, 1, 8, 0), exit()];
    let run = with_mem(&p, vec![0; 8]);
    assert_eq!(
      run.termination,
      Termination::Fault {
        pc: 0,
        addr: DEFAULT_MEM_BASE + 8,
        len: 1,
        kind: FaultKind::OutOfBounds,
      }
    );
    // A doubleword whose first byte is in range but whose last is not.
    let p = [i(cls::LDX | mode::MEM | size::DW, 0, 1, 8, 0), exit()];
    let run = with_mem(&p, vec![0; 12]);
    assert!(matches!(
      run.termination,
      Termination::Fault {
        kind: FaultKind::OutOfBounds,
        ..
      }
    ));
    // A wholly unrelated address.
    let p = [
      mov64(1, 0),
      i(cls::LDX | mode::MEM | size::B, 0, 1, 0, 0),
      exit(),
    ];
    let run = with_mem(&p, vec![0; 8]);
    assert!(matches!(
      run.termination,
      Termination::Fault {
        addr: 0,
        kind: FaultKind::OutOfBounds,
        ..
      }
    ));
  }

  #[test]
  fn an_unaligned_access_faults_unless_alignment_checks_are_off() {
    let p = [i(cls::LDX | mode::MEM | size::W, 0, 1, 1, 0), exit()];
    let run = with_mem(&p, vec![0xaa; 8]);
    assert_eq!(
      run.termination,
      Termination::Fault {
        pc: 0,
        addr: DEFAULT_MEM_BASE + 1,
        len: 4,
        kind: FaultKind::Unaligned,
      }
    );
    let run = Interpreter::new(&p, vec![0xaa; 8])
      .allowing_unaligned()
      .run(|_, _| 0);
    assert_eq!(run.return_value(), Some(0xaaaa_aaaa));
  }

  #[test]
  fn the_stack_is_addressable_below_the_frame_pointer() {
    // stdw [r10-8], 0x2a ; ldxdw r0, [r10-8]
    let p = [
      i(cls::ST | mode::MEM | size::DW, 10, 0, -8, 0x2a),
      i(cls::LDX | mode::MEM | size::DW, 0, 10, -8, 0),
      exit(),
    ];
    let run = exec(&p);
    assert_eq!(run.return_value(), Some(0x2a));
    let top = run.stack.len();
    assert_eq!(&run.stack[top - 8..], &[0x2a, 0, 0, 0, 0, 0, 0, 0]);
    // One past the frame pointer is off the end of the stack region.
    let p = [i(cls::LDX | mode::MEM | size::B, 0, 10, 0, 0), exit()];
    assert!(matches!(
      exec(&p).termination,
      Termination::Fault {
        kind: FaultKind::OutOfBounds,
        ..
      }
    ));
  }

  // ---- lddw --------------------------------------------------------------

  #[test]
  fn lddw_assembles_a_sixty_four_bit_immediate_from_two_slots() {
    assert_eq!(r0(&[lddw(0, 0)[0], lddw(0, 0)[1], exit()]), 0);
    let v = 0xfedc_ba98_7654_3210u64;
    let p = [lddw(0, v)[0], lddw(0, v)[1], exit()];
    assert_eq!(r0(&p), v);
    // Both halves are taken *unsigned* from their slots: a high half with the
    // top bit set must not sign-extend, and a low half with the top bit set
    // must not bleed ones into the high half.
    let v = 0x8000_0000_8000_0000u64;
    let p = [lddw(0, v)[0], lddw(0, v)[1], exit()];
    assert_eq!(r0(&p), v);
    // The second slot is skipped, not executed: here it would otherwise decode
    // as something with a wild opcode.
    let p = [
      i(opcode::LDDW, 0, 0, 0, 7),
      i(0xff, 15, 15, 0, 0),
      alu64_imm(alu::ADD, 0, 1),
      exit(),
    ];
    assert_eq!(r0(&p), 8);
    // A truncated lddw is invalid rather than a read past the end.
    let run = exec(&[i(opcode::LDDW, 0, 0, 0, 7)]);
    assert!(matches!(
      run.termination,
      Termination::Invalid { pc: 0, .. }
    ));
  }

  // ---- jumps -------------------------------------------------------------

  #[test]
  fn jmp32_compares_only_the_low_half() {
    // r1 = 0x1_0000_0000, r2 = 0. The two are unequal at 64 bits and equal at
    // 32; jeq32 must take the branch, jeq must not.
    let prelude = |op_class: u8, op: u8| {
      let mut p = lddw(1, 0x1_0000_0000).to_vec();
      p.push(mov64(2, 0));
      p.push(mov64(0, 0));
      p.push(i(op_class | srcbit::REG | op, 1, 2, 1, 0));
      p.push(exit());
      p.push(mov64(0, 1));
      p.push(exit());
      r0(&p)
    };
    assert_eq!(prelude(cls::JMP32, jmp::JEQ), 1);
    assert_eq!(prelude(cls::JMP, jmp::JEQ), 0);
  }

  #[test]
  fn signed_and_unsigned_comparisons_are_distinct() {
    // r1 = -1. Unsigned it is the largest value; signed it is the smallest.
    let cmp = |op_class: u8, op: u8, lhs: i32, rhs: i32| {
      let mut p = vec![mov64(1, lhs), mov64(0, 0)];
      p.push(i(op_class | srcbit::IMM | op, 1, 0, 1, rhs));
      p.push(exit());
      p.push(mov64(0, 1));
      p.push(exit());
      r0(&p) == 1
    };
    // 64-bit: -1 > 1 unsigned, -1 < 1 signed.
    assert!(cmp(cls::JMP, jmp::JGT, -1, 1));
    assert!(!cmp(cls::JMP, jmp::JSGT, -1, 1));
    assert!(cmp(cls::JMP, jmp::JSLT, -1, 1));
    assert!(!cmp(cls::JMP, jmp::JLT, -1, 1));
    // 32-bit: the same, on the low half.
    assert!(cmp(cls::JMP32, jmp::JGT, -1, 1));
    assert!(!cmp(cls::JMP32, jmp::JSGT, -1, 1));
    assert!(cmp(cls::JMP32, jmp::JSLT, -1, 1));
    // A 64-bit unsigned comparison against an immediate sign-extends the
    // immediate first: `r1 == 0xffff_ffff_ffff_ffff` is true when r1 is -1,
    // whereas a 32-bit compare only checks the low half.
    assert!(cmp(cls::JMP, jmp::JEQ, -1, -1));
    assert!(cmp(cls::JMP32, jmp::JEQ, -1, -1));
    // jset masks.
    assert!(cmp(cls::JMP, jmp::JSET, 0b1010, 0b0010));
    assert!(!cmp(cls::JMP, jmp::JSET, 0b1010, 0b0100));
  }

  #[test]
  fn jset32_ignores_the_upper_half() {
    let mut p = lddw(1, 0x1_0000_0000).to_vec();
    p.push(mov64(0, 0));
    p.push(i(cls::JMP32 | srcbit::IMM | jmp::JSET, 1, 0, 1, -1));
    p.push(exit());
    p.push(mov64(0, 1));
    p.push(exit());
    assert_eq!(r0(&p), 0, "no bit of the low half is set");
  }

  #[test]
  fn ja_uses_offset_and_ja32_uses_the_immediate() {
    // ja +1 skips the `mov r0, 9`.
    let p = [mov64(0, 0), i(opcode::JA, 0, 0, 1, 0), mov64(0, 9), exit()];
    assert_eq!(r0(&p), 0);
    let p = [
      mov64(0, 0),
      i(opcode::JA32, 0, 0, 0, 1),
      mov64(0, 9),
      exit(),
    ];
    assert_eq!(r0(&p), 0);
    // A backwards jump is how a loop is written; the step budget catches it.
    let p = [i(opcode::JA, 0, 0, -1, 0)];
    let run = Interpreter::new(&p, Vec::new())
      .with_step_budget(100)
      .run(|_, _| 0);
    assert_eq!(run.termination, Termination::StepBudget);
    assert_eq!(run.steps, 100);
  }

  #[test]
  fn a_jump_out_of_the_program_is_invalid() {
    let p = [i(opcode::JA, 0, 0, 100, 0), exit()];
    assert!(matches!(
      exec(&p).termination,
      Termination::Invalid { pc: 0, .. }
    ));
    let p = [i(opcode::JA, 0, 0, -5, 0), exit()];
    assert!(matches!(
      exec(&p).termination,
      Termination::Invalid { pc: 0, .. }
    ));
  }

  #[test]
  fn falling_off_the_end_without_an_exit_is_invalid() {
    let p = [mov64(0, 1)];
    assert!(matches!(
      exec(&p).termination,
      Termination::Invalid { pc: 1, .. }
    ));
  }

  // ---- atomics -----------------------------------------------------------

  fn atomic(width_bits: u8, imm: i32, offset: i16) -> Insn {
    i(cls::STX | mode::ATOMIC | width_bits, 1, 2, offset, imm)
  }

  /// Runs one atomic against eight bytes of memory preloaded with `initial`,
  /// with `R2` holding `value` and `R0` holding `r0`. Returns the memory
  /// doubleword, `R0` and `R2` afterwards.
  fn atomic_case(
    width_bits: u8,
    imm: i32,
    initial: u64,
    value: u64,
    r0_in: u64,
  ) -> (u64, u64, u64) {
    let mut p = lddw(0, r0_in).to_vec();
    p.extend(lddw(2, value));
    p.push(atomic(width_bits, imm, 0));
    p.push(exit());
    let run = Interpreter::new(&p, initial.to_le_bytes().to_vec()).run(|_, _| 0);
    assert!(
      matches!(run.termination, Termination::Exit(_)),
      "{:?}",
      run.termination
    );
    let mem = u64::from_le_bytes(run.memory[..8].try_into().unwrap());
    (mem, run.regs[0], run.regs[2])
  }

  #[test]
  fn atomic_arithmetic_without_fetch_leaves_the_registers_alone() {
    let cases = [
      (alu::ADD, 0x0000_0000_0000_1100u64),
      (alu::OR, 0x0000_0000_0000_10ffu64),
      (alu::AND, 0x0000_0000_0000_0001u64),
      (alu::XOR, 0x0000_0000_0000_10feu64),
    ];
    for (op, expected) in cases {
      let (mem, r0, r2) = atomic_case(size::DW, op as i32, 0x1001, 0xff, 0);
      assert_eq!(mem, expected, "op {op:#04x}");
      assert_eq!(r0, 0);
      assert_eq!(r2, 0xff, "no fetch: the source register is untouched");
    }
  }

  #[test]
  fn a_fetching_atomic_returns_the_previous_value_in_the_source_register() {
    let (mem, _, r2) = atomic_case(
      size::DW,
      alu::ADD as i32 | atomic::OP_FETCH,
      0x1001,
      0xff,
      0,
    );
    assert_eq!(mem, 0x1100);
    assert_eq!(r2, 0x1001, "the source register gets the value from before");
  }

  #[test]
  fn a_thirty_two_bit_atomic_touches_only_four_bytes_and_zero_extends() {
    // The upper word of memory must survive, and the fetched value must be the
    // low word zero-extended rather than the whole doubleword.
    let (mem, _, r2) = atomic_case(
      size::W,
      alu::ADD as i32 | atomic::OP_FETCH,
      0xaaaa_aaaa_0000_1001,
      0xff,
      0,
    );
    assert_eq!(mem, 0xaaaa_aaaa_0000_1100);
    assert_eq!(r2, 0x1001);
    // A 32-bit add that carries out of the low word must not touch the high
    // word: 0xffff_ffff + 1 wraps to 0.
    let (mem, _, _) = atomic_case(size::W, alu::ADD as i32, 0xaaaa_aaaa_ffff_ffff, 1, 0);
    assert_eq!(mem, 0xaaaa_aaaa_0000_0000);
    // A 32-bit source register with junk in its upper half contributes only its
    // low word.
    let (mem, _, _) = atomic_case(size::W, alu::OR as i32, 0, 0xdead_beef_0000_00ff, 0);
    assert_eq!(mem, 0xff);
  }

  #[test]
  fn xchg_swaps_memory_and_the_source_register() {
    let (mem, _, r2) = atomic_case(size::DW, atomic::OP_XCHG, 0x1001, 0xff, 0);
    assert_eq!(mem, 0xff);
    assert_eq!(r2, 0x1001);
    // At 32 bits the upper word of memory survives and the fetch zero-extends.
    let (mem, _, r2) = atomic_case(size::W, atomic::OP_XCHG, 0xaaaa_aaaa_0000_1001, 0xff, 0);
    assert_eq!(mem, 0xaaaa_aaaa_0000_00ff);
    assert_eq!(r2, 0x1001);
  }

  #[test]
  fn cmpxchg_compares_against_r0_and_returns_the_previous_value_in_r0() {
    // Match: memory takes the source, R0 takes the previous value (which is
    // what it already held).
    let (mem, r0, r2) = atomic_case(size::DW, atomic::OP_CMPXCHG, 0x1001, 0xff, 0x1001);
    assert_eq!(mem, 0xff);
    assert_eq!(r0, 0x1001);
    assert_eq!(r2, 0xff, "cmpxchg never writes the source register");
    // No match: memory is unchanged, and R0 is *overwritten* with the previous
    // value rather than left holding the expectation. A JIT that only writes R0
    // on the failing path, or only on the succeeding one, fails one of these.
    let (mem, r0, _) = atomic_case(size::DW, atomic::OP_CMPXCHG, 0x1001, 0xff, 0x2002);
    assert_eq!(mem, 0x1001);
    assert_eq!(r0, 0x1001);
    // 32-bit: the comparison uses only the low word of R0, so an R0 with junk
    // in its upper half still matches...
    let (mem, r0, _) = atomic_case(
      size::W,
      atomic::OP_CMPXCHG,
      0xaaaa_aaaa_0000_1001,
      0xff,
      0xdead_beef_0000_1001,
    );
    assert_eq!(mem, 0xaaaa_aaaa_0000_00ff);
    assert_eq!(r0, 0x1001, "and R0 comes back zero-extended, not merged");
  }

  #[test]
  fn an_atomic_on_a_bad_address_faults() {
    let p = [mov64(1, 0), atomic(size::DW, alu::ADD as i32, 0), exit()];
    let run = with_mem(&p, vec![0; 8]);
    assert!(matches!(
      run.termination,
      Termination::Fault {
        kind: FaultKind::OutOfBounds,
        ..
      }
    ));
  }

  // ---- calls -------------------------------------------------------------

  #[test]
  fn helper_calls_are_dispatched_and_traced_in_order() {
    let call = |idx: i32| i(opcode::CALL, 0, 0, 0, idx);
    let p = [
      mov64(1, 11),
      mov64(2, 22),
      call(7),
      mov64(1, 33),
      call(9),
      exit(),
    ];
    let mut seen = Vec::new();
    let run = Interpreter::new(&p, Vec::new()).run(|idx, args| {
      seen.push((idx, args[0]));
      idx as u64 * 100
    });
    assert_eq!(seen, vec![(7, 11), (9, 33)]);
    assert_eq!(run.return_value(), Some(900));
    assert_eq!(
      run.helpers,
      vec![
        HelperCall {
          index: 7,
          args: [11, 22, 0, 0, 0],
          ret: 700,
        },
        HelperCall {
          index: 9,
          args: [33, 22, 0, 0, 0],
          ret: 900,
        },
      ]
    );
  }

  #[test]
  fn a_local_call_transfers_control_and_gives_the_callee_its_own_frame() {
    // r0 = 1; call +2 (to slot 4); exit
    //   callee: r0 += 1; stack write; exit
    let p = [
      mov64(0, 1),
      i(opcode::CALL, 0, 1, 0, 1),
      exit(),
      // callee at slot 3:
      alu64_imm(alu::ADD, 0, 1),
      i(cls::ST | mode::MEM | size::DW, 10, 0, -8, 0x5a),
      exit(),
    ];
    let run = exec(&p);
    assert_eq!(run.return_value(), Some(2));
    // The callee's frame sits one `LOCAL_FUNCTION_STACK_SIZE` below the
    // caller's, so its `[r10-8]` is not the caller's.
    let top = run.stack.len();
    let frame = abi::LOCAL_FUNCTION_STACK_SIZE as usize;
    assert_eq!(run.stack[top - frame - 8], 0x5a);
    assert_eq!(run.stack[top - 8], 0, "the caller's frame is untouched");
    // R10 is restored on return.
    assert_eq!(
      run.regs[10],
      DEFAULT_STACK_BASE + run.stack.len() as u64,
      "the frame pointer comes back"
    );
  }

  #[test]
  fn a_local_call_preserves_the_callee_saved_registers() {
    // The callee clobbers r6. The caller must not see the clobber — this is the
    // calling convention, and is what the C interpreter was observed to do.
    // `not_preserving_callee_saved` selects the other reading.
    let p = [
      mov64(6, 1),
      // The callee begins at slot 4, two past the slot after the call.
      i(opcode::CALL, 0, 1, 0, 2),
      i(cls::ALU64 | srcbit::REG | alu::MOV, 0, 6, 0, 0),
      exit(),
      mov64(6, 2),
      exit(),
    ];
    assert_eq!(r0(&p), 1);
    let run = Interpreter::new(&p, Vec::new())
      .not_preserving_callee_saved()
      .run(|_, _| 0);
    assert_eq!(run.return_value(), Some(2));
  }

  #[test]
  fn a_local_call_does_not_preserve_the_argument_registers() {
    // r1 is not callee-saved, so the callee's write to it is visible after the
    // return. Same program shape as the test above, on a register the
    // convention does not protect.
    let p = [
      mov64(1, 1),
      i(opcode::CALL, 0, 1, 0, 2),
      i(cls::ALU64 | srcbit::REG | alu::MOV, 0, 1, 0, 0),
      exit(),
      mov64(1, 2),
      exit(),
    ];
    assert_eq!(r0(&p), 2);
  }

  #[test]
  fn local_calls_stop_at_the_depth_limit() {
    // A self-recursive function with no base case.
    let p = [i(opcode::CALL, 0, 1, 0, -1), exit()];
    let run = Interpreter::new(&p, Vec::new())
      .with_max_call_depth(4)
      .run(|_, _| 0);
    assert_eq!(run.termination, Termination::CallDepthExceeded { pc: 0 });
    // Exactly four calls got through before the fifth was refused.
    assert_eq!(run.steps, 5);
  }

  #[test]
  fn a_local_call_out_of_the_program_is_invalid() {
    let p = [i(opcode::CALL, 0, 1, 0, 100), exit()];
    assert!(matches!(
      exec(&p).termination,
      Termination::Invalid { pc: 0, .. }
    ));
  }

  // ---- miscellaneous -----------------------------------------------------

  #[test]
  fn an_undefined_opcode_is_invalid_rather_than_a_panic() {
    let run = exec(&[i(0xa1, 0, 0, 0, 0), exit()]);
    assert!(matches!(
      run.termination,
      Termination::Invalid { pc: 0, .. }
    ));
  }

  #[test]
  fn a_register_number_out_of_range_is_invalid() {
    let run = exec(&[i(cls::ALU64 | srcbit::REG | alu::MOV, 11, 0, 0, 0), exit()]);
    assert!(matches!(
      run.termination,
      Termination::Invalid { pc: 0, .. }
    ));
  }

  #[test]
  fn the_entry_registers_describe_the_data_region() {
    let p = [i(cls::ALU64 | srcbit::REG | alu::MOV, 0, 2, 0, 0), exit()];
    let run = with_mem(&p, vec![0; 24]);
    assert_eq!(run.return_value(), Some(24), "R2 is the region length");
    let p = [i(cls::ALU64 | srcbit::REG | alu::MOV, 0, 1, 0, 0), exit()];
    let run = with_mem(&p, vec![0; 24]);
    assert_eq!(run.return_value(), Some(DEFAULT_MEM_BASE));
    // ...unless overridden.
    let run = Interpreter::new(&p, vec![0; 24])
      .with_args([5, 6, 7, 8, 9])
      .run(|_, _| 0);
    assert_eq!(run.return_value(), Some(5));
  }

  #[test]
  fn a_program_that_only_exits_returns_zero() {
    let run = exec(&[exit()]);
    assert_eq!(run.termination, Termination::Exit(0));
    assert_eq!(run.steps, 1);
  }
}

#[cfg(test)]
mod signed_divmod_tests {
  use super::*;
  use crate::jit::isa::{alu as alu_bits, cls, opcode, src as src_bits};

  fn divmod(op_bits: u8, width_cls: u8, dst_init: u64, operand: u64, signed: bool) -> u64 {
    let program = [
      Insn {
        opcode: opcode::LDDW,
        dst: 1,
        src: 0,
        offset: 0,
        imm: dst_init as u32 as i32,
      },
      Insn {
        opcode: 0,
        dst: 0,
        src: 0,
        offset: 0,
        imm: (dst_init >> 32) as u32 as i32,
      },
      Insn {
        opcode: opcode::LDDW,
        dst: 2,
        src: 0,
        offset: 0,
        imm: operand as u32 as i32,
      },
      Insn {
        opcode: 0,
        dst: 0,
        src: 0,
        offset: 0,
        imm: (operand >> 32) as u32 as i32,
      },
      Insn {
        opcode: width_cls | src_bits::REG | op_bits,
        dst: 1,
        src: 2,
        offset: if signed { 1 } else { 0 },
        imm: 0,
      },
      Insn {
        opcode: cls::ALU64 | src_bits::REG | alu_bits::MOV,
        dst: 0,
        src: 1,
        offset: 0,
        imm: 0,
      },
      Insn {
        opcode: opcode::EXIT,
        dst: 0,
        src: 0,
        offset: 0,
        imm: 0,
      },
    ];
    match Interpreter::new(&program, vec![0; 64])
      .run(|_, _| 0)
      .termination
    {
      Termination::Exit(v) => v,
      other => panic!("unexpected termination: {other:?}"),
    }
  }

  /// The corner the C emits an explicit overflow check for: on x86 `idiv`,
  /// `INT_MIN / -1` raises #DE rather than producing a value. Both backends
  /// special-case it so the result wraps.
  #[test]
  fn signed_division_of_the_minimum_by_minus_one_wraps_instead_of_trapping() {
    assert_eq!(
      divmod(
        alu_bits::DIV,
        cls::ALU64,
        i64::MIN as u64,
        -1i64 as u64,
        true
      ),
      i64::MIN as u64
    );
    assert_eq!(
      divmod(
        alu_bits::MOD,
        cls::ALU64,
        i64::MIN as u64,
        -1i64 as u64,
        true
      ),
      0
    );
    // And at 32 bits, where the result is zero-extended.
    assert_eq!(
      divmod(
        alu_bits::DIV,
        cls::ALU,
        i32::MIN as u32 as u64,
        -1i32 as u32 as u64,
        true
      ),
      i32::MIN as u32 as u64
    );
  }

  #[test]
  fn the_offset_field_selects_between_signed_and_unsigned_division() {
    // -6 / 2. Unsigned reads the dividend as a huge positive number; signed
    // gives -3. Same opcode, same operands, different offset.
    let dividend = -6i64 as u64;
    assert_eq!(
      divmod(alu_bits::DIV, cls::ALU64, dividend, 2, true),
      -3i64 as u64
    );
    assert_eq!(
      divmod(alu_bits::DIV, cls::ALU64, dividend, 2, false),
      dividend / 2
    );
    assert_ne!(
      divmod(alu_bits::DIV, cls::ALU64, dividend, 2, true),
      divmod(alu_bits::DIV, cls::ALU64, dividend, 2, false),
      "signed and unsigned division must not coincide on this input"
    );
  }

  #[test]
  fn signed_division_still_defines_division_by_zero() {
    assert_eq!(divmod(alu_bits::DIV, cls::ALU64, -6i64 as u64, 0, true), 0);
    assert_eq!(
      divmod(alu_bits::MOD, cls::ALU64, -6i64 as u64, 0, true),
      -6i64 as u64
    );
  }

  #[test]
  fn signed_modulo_takes_the_sign_of_the_dividend() {
    assert_eq!(
      divmod(alu_bits::MOD, cls::ALU64, -7i64 as u64, 2, true),
      -1i64 as u64
    );
    assert_eq!(divmod(alu_bits::MOD, cls::ALU64, 7, -2i64 as u64, true), 1);
  }
}

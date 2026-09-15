//! Each macro's fixed native sequence.
//!
//! [`expand`] turns a list of [`MInsn`] into a list of [`PInsn`], one primitive
//! per x86 instruction. There are no decisions left at this layer: a macro's
//! expansion depends on the macro's own operands and on the four
//! configuration facts [`Cfg`] carries, and on nothing else. That is what lets
//! each macro's contract be proved once, with its operands symbolic, against
//! the sequence written here.
//!
//! Positions are labels. Branches inside one macro's expansion name
//! [`PTarget::Local`] labels drawn from a counter that runs across the whole
//! function, so no two expansions can collide; the encoder resolves them along
//! with the slot and trailer labels.

use super::x64_ir::{
  cc, frame, map_register, memory, region, AluRI, AluRM, AluRR, Cfg, MInsn, MulDivKind, PInsn,
  PTarget, ShiftOp, Size, Target, R10, R11, R15, R9, RAX, RBP, RCX, RDI, RDX, RSP, VOLATILE_CTXT,
};

/// Expands every macro in `code`.
pub fn expand(cfg: &Cfg, code: &[MInsn], out: &mut Vec<PInsn>) {
  let mut label: u32 = 0;
  let mut i: usize = 0;
  while i < code.len() {
    label = expand_one(cfg, code, i, label, out);
    i += 1;
  }
}

/// Expands the macro at `i`, returning the next free local label.
fn expand_one(cfg: &Cfg, code: &[MInsn], i: usize, label: u32, out: &mut Vec<PInsn>) -> u32 {
  let m = code[i];
  match m {
    MInsn::PcLabel(pc) => {
      out.push(PInsn::PcLabel(pc));
      label
    }
    MInsn::Prologue { usage, skip } => expand_prologue(usage, skip, label, out),
    MInsn::Epilogue => {
      // The trailer's epilogue is where the exit label goes: every `Jcc` to
      // the exit lands on it, and the retpoline follows it immediately.
      let trailer = starts_trailer(code, i);
      if trailer {
        out.push(PInsn::ExitLabel);
      }
      out.push(add_rsp_8());
      out.push(PInsn::Ret);
      label
    }
    MInsn::Alu { w64, op, src, dst } => {
      out.push(PInsn::Alu { w64, op, src, dst });
      label
    }
    MInsn::AluImm { w64, op, dst, imm } => {
      out.push(PInsn::AluImm { w64, op, dst, imm });
      label
    }
    MInsn::ShiftImm { w64, op, dst, imm } => {
      out.push(PInsn::ShiftImm { w64, op, dst, imm });
      label
    }
    MInsn::ShiftCl { w64, op, dst } => {
      out.push(PInsn::ShiftCl { w64, op, dst });
      label
    }
    MInsn::Neg { w64, dst } => {
      out.push(PInsn::Neg { w64, dst });
      label
    }
    MInsn::MovSx {
      from,
      w64,
      src,
      dst,
    } => {
      out.push(PInsn::MovSx {
        from,
        w64,
        src,
        dst,
      });
      label
    }
    MInsn::Bswap { w64, dst } => {
      out.push(PInsn::Bswap { w64, dst });
      label
    }
    MInsn::Rol16 { dst } => {
      out.push(PInsn::Rol16 { dst });
      label
    }
    MInsn::LoadImm { dst, imm } => {
      out.push(PInsn::LoadImm { dst, imm });
      label
    }
    MInsn::MulDivMod {
      kind,
      w64,
      reg,
      signed,
      src,
      dst,
      imm,
    } => expand_muldivmod(kind, w64, reg, signed, src, dst, imm, label, out),
    MInsn::Jcc { cc, target } => {
      out.push(PInsn::Jcc {
        cc,
        target: primitive_target(target),
      });
      label
    }
    MInsn::Jmp { target } => {
      out.push(PInsn::Jmp {
        target: primitive_target(target),
      });
      label
    }
    MInsn::GuestFp { dst } => {
      expand_guest_fp(dst, out);
      label
    }
    MInsn::CheckedAddr {
      src,
      dst,
      scratch,
      offset,
      size,
      region: hint,
    } => {
      expand_checked_addr(cfg, src, dst, scratch, offset, size, hint, out);
      label
    }
    MInsn::GroupBaseStore { src } => {
      out.push(PInsn::Store {
        size: 8,
        src,
        base: RBP,
        disp: frame::GROUP_BASE_OFFSET,
      });
      label
    }
    MInsn::GroupBaseLoad { dst } => {
      out.push(load64(RBP, dst, frame::GROUP_BASE_OFFSET));
      label
    }
    MInsn::Load {
      size,
      sx,
      base,
      dst,
      disp,
    } => {
      out.push(PInsn::Load {
        size,
        sx,
        base,
        dst,
        disp,
      });
      label
    }
    MInsn::Store {
      size,
      src,
      base,
      disp,
    } => {
      out.push(PInsn::Store {
        size,
        src,
        base,
        disp,
      });
      label
    }
    MInsn::StoreImm {
      size,
      base,
      disp,
      imm,
    } => {
      out.push(PInsn::StoreImm {
        size,
        base,
        disp,
        imm,
      });
      label
    }
    MInsn::AtomicAlu {
      op,
      w64,
      src,
      base,
      disp,
    } => {
      out.push(PInsn::LockAlu {
        op,
        w64,
        src,
        base,
        disp,
      });
      label
    }
    MInsn::AtomicFetchAlu {
      op,
      w64,
      src,
      base,
      disp,
    } => expand_atomic_fetch_alu(op, w64, src, base, disp, label, out),
    MInsn::AtomicXchg {
      w64,
      src,
      base,
      disp,
    } => {
      out.push(PInsn::Xchg {
        w64,
        src,
        base,
        disp,
      });
      label
    }
    MInsn::AtomicCmpxchg {
      w64,
      src,
      base,
      disp,
    } => {
      out.push(PInsn::LockCmpxchg {
        w64,
        src,
        base,
        disp,
      });
      label
    }
    MInsn::HelperCall { idx } => expand_helper_call(idx, label, out),
    MInsn::LazyLocalCall { id } => expand_lazy_local_call(cfg, id, label, out),
    MInsn::Retpoline => expand_retpoline(label, out),
    MInsn::DispatcherSlot => {
      out.push(PInsn::DispatcherSlot {
        addr: cfg.dispatcher,
      });
      label
    }
    MInsn::HelperTable => {
      out.push(PInsn::HelperTable);
      label
    }
  }
}

/// Whether the epilogue at `i` is the trailer's, which the retpoline follows.
fn starts_trailer(code: &[MInsn], i: usize) -> bool {
  let len = code.len();
  if i + 1 >= len {
    return false;
  }
  let next = code[i + 1];
  match next {
    MInsn::Retpoline => true,
    _ => false,
  }
}

/// Where a macro branch goes, as the encoder names it.
fn primitive_target(target: Target) -> PTarget {
  match target {
    Target::Pc(pc) => PTarget::Pc(pc),
    Target::Exit => PTarget::Exit,
  }
}

// ---------------------------------------------------------------------------
// Small shapes, spelled once
// ---------------------------------------------------------------------------

fn add_rsp_8() -> PInsn {
  PInsn::AluImm {
    w64: true,
    op: AluRI::Add,
    dst: RSP,
    imm: 8,
  }
}

fn mov64(src: u8, dst: u8) -> PInsn {
  PInsn::Alu {
    w64: true,
    op: AluRR::Mov,
    src,
    dst,
  }
}

fn load64(base: u8, dst: u8, disp: i32) -> PInsn {
  PInsn::Load {
    size: 8,
    sx: false,
    base,
    dst,
    disp,
  }
}

fn store64(src: u8, base: u8, disp: i32) -> PInsn {
  PInsn::Store {
    size: 8,
    src,
    base,
    disp,
  }
}

fn alu_rm(op: AluRM, reg: u8, base: u8, disp: i32) -> PInsn {
  PInsn::AluRM {
    op,
    reg,
    base,
    disp,
  }
}

/// `cmovb dst, src`, the branchless substitution of address zero.
fn cmovb(dst: u8, src: u8) -> PInsn {
  PInsn::Cmov {
    cc: cc::B,
    dst,
    src,
  }
}

/// `cmove dst, src`, the divide-by-zero and overflow fix-ups.
fn cmove(dst: u8, src: u8) -> PInsn {
  PInsn::Cmov {
    cc: cc::E,
    dst,
    src,
  }
}

// ---------------------------------------------------------------------------
// Prologue
// ---------------------------------------------------------------------------

/// `sub rsp, 8 ; mov qword [rsp], usage`, preceded where needed by a near jump
/// around it for a previous instruction that can fall into this entry.
///
/// Adjusting by 8 keeps the 16-byte alignment, because the `call` that reached
/// here already pushed a return address.
fn expand_prologue(usage: u16, skip: bool, label: u32, out: &mut Vec<PInsn>) -> u32 {
  let after = label;
  if skip {
    out.push(PInsn::JmpNear {
      target: PTarget::Local(after),
    });
  }
  out.push(PInsn::AluImm {
    w64: true,
    op: AluRI::Sub,
    dst: RSP,
    imm: 8,
  });
  out.push(PInsn::StoreRspImm { imm: usage as u32 });
  if skip {
    out.push(PInsn::Local(after));
    return label + 1;
  }
  label
}

// ---------------------------------------------------------------------------
// The pointer cage
// ---------------------------------------------------------------------------

/// The *guest* value of eBPF `R10`. Under a native frame base the register
/// mapped to it holds a host address; a program that reads it as a value must
/// still see a guest one.
fn expand_guest_fp(dst: u8, out: &mut Vec<PInsn>) {
  out.push(mov64(R15, dst));
  out.push(alu_rm(AluRM::Sub, dst, RBP, frame::FRAME_DELTA_OFFSET));
}

/// The span slot for an access `size` bytes wide, or `None` for a width the
/// precomputed spans do not cover.
fn width_span_slot(size: u32) -> Option<usize> {
  if size == 1 {
    return Some(0);
  }
  if size == 2 {
    return Some(1);
  }
  if size == 4 {
    return Some(2);
  }
  if size == 8 {
    return Some(3);
  }
  None
}

/// The descriptor displacement of one region's guest bottom.
fn desc_bottom(stack: bool) -> i32 {
  if stack {
    return memory::STACK_GUEST_BOTTOM;
  }
  memory::DATA_GUEST_BOTTOM
}

/// The descriptor displacement of one region's guest top.
fn desc_top(stack: bool) -> i32 {
  if stack {
    return memory::STACK_GUEST_TOP;
  }
  memory::DATA_GUEST_TOP
}

/// The descriptor displacement of one region's native base.
fn desc_native_base(stack: bool) -> i32 {
  if stack {
    return memory::STACK_NATIVE_BASE;
  }
  memory::DATA_NATIVE_BASE
}

/// The base index of one region's block of derived frame constants.
fn derived_base(stack: bool) -> usize {
  if stack {
    return frame::DERIVED_STACK_BASE;
  }
  frame::DERIVED_DATA_BASE
}

/// Bounds-checks `[dst, dst + size)` against one guest region and translates
/// `dst`, reading the region's bounds from the constants the embedder derived
/// once per invocation.
///
/// Branchless: a final `cmov` substitutes address zero when out of range, so
/// no mis-speculated path performs a transient out-of-bounds access.
fn expand_region_from_frame(dst: u8, scratch: u8, size: u32, stack: bool, out: &mut Vec<PInsn>) {
  let base = derived_base(stack);
  let bottom_slot = frame::derived_slot(base + frame::DERIVED_BOTTOM);
  let delta_slot = frame::derived_slot(base + frame::DERIVED_DELTA);
  let span_base = frame::derived_slot(base + frame::DERIVED_SPAN);

  // off = guest - bottom, kept in a register for the comparison below.
  out.push(mov64(dst, scratch));
  out.push(alu_rm(AluRM::Sub, scratch, RBP, bottom_slot));

  // Translate unconditionally; the cmov below undoes it when out of range.
  out.push(alu_rm(AluRM::Add, dst, RBP, delta_slot));

  let span = width_span_slot(size);
  match span {
    Some(slot) => {
      let span_slot = span_base + (slot as i32) * 8;
      // Zero the fault address before the compare, which sets the flags.
      out.push(PInsn::Alu {
        w64: true,
        op: AluRR::Xor,
        src: R9,
        dst: R9,
      });
      // The memory operand is the left-hand side, so the carry flag is set
      // exactly when the span is below the offset, i.e. out of range.
      out.push(alu_rm(AluRM::CmpMR, scratch, RBP, span_slot));
      out.push(cmovb(dst, R9));
    }
    None => {
      // An access group covers any width up to a page rather than one of the
      // four the precomputed spans hold, so narrow the width-1 span instead.
      out.push(load64(RBP, R9, span_base));
      out.push(PInsn::AluImm {
        w64: true,
        op: AluRI::Sub,
        dst: R9,
        imm: size as i32 - 1,
      });
      // Both remaining registers are live across the compare, so the fault
      // address is zeroed after it with a move, which leaves the flags alone.
      out.push(PInsn::Alu {
        w64: true,
        op: AluRR::Cmp,
        src: scratch,
        dst: R9,
      });
      out.push(PInsn::AluImm {
        w64: true,
        op: AluRI::Mov,
        dst: scratch,
        imm: 0,
      });
      out.push(cmovb(dst, scratch));
    }
  }
}

/// The same check, reading the region's bounds through the memory descriptor
/// whose address lives below the frame pointer.
fn expand_region_via_descriptor(
  dst: u8,
  scratch: u8,
  size: u32,
  stack: bool,
  out: &mut Vec<PInsn>,
) {
  let bottom_off = desc_bottom(stack);
  let top_off = desc_top(stack);
  let base_off = desc_native_base(stack);

  out.push(load64(RBP, scratch, frame::FRAME_OFFSET));

  // off = dst - bottom; spill it, then translated = off + base, kept in dst.
  out.push(alu_rm(AluRM::Sub, dst, scratch, bottom_off));
  out.push(store64(dst, RBP, frame::SPILL_OFFSET));
  out.push(alu_rm(AluRM::Add, dst, scratch, base_off));

  // span = (top - size) - bottom
  out.push(load64(scratch, R9, top_off));
  if size != 0 {
    out.push(PInsn::AluImm {
      w64: true,
      op: AluRI::Sub,
      dst: R9,
      imm: size as i32,
    });
  }
  out.push(alu_rm(AluRM::Sub, R9, scratch, bottom_off));

  // Zero the fault address before the compare, which sets the flags.
  out.push(PInsn::Alu {
    w64: true,
    op: AluRR::Xor,
    src: scratch,
    dst: scratch,
  });
  out.push(alu_rm(AluRM::CmpRM, R9, RBP, frame::SPILL_OFFSET));
  out.push(cmovb(dst, scratch));
}

fn expand_region(cfg: &Cfg, dst: u8, scratch: u8, size: u32, stack: bool, out: &mut Vec<PInsn>) {
  if cfg.frame_constants {
    expand_region_from_frame(dst, scratch, size, stack, out);
  } else {
    expand_region_via_descriptor(dst, scratch, size, stack, out);
  }
}

/// Resolves `[src + offset]` to a native address in `dst`, emitting whatever
/// check that needs.
fn expand_checked_addr(
  cfg: &Cfg,
  src: u8,
  dst: u8,
  scratch: u8,
  offset: i32,
  size: u32,
  hint: u8,
  out: &mut Vec<PInsn>,
) {
  let framed = cfg.native_frame_base_active();
  if framed && src == R15 {
    // Everything below works in guest space, so recover the guest frame
    // pointer before starting.
    expand_guest_fp(dst, out);
  } else if src != dst {
    out.push(mov64(src, dst));
  }

  if offset != 0 {
    out.push(PInsn::AluImm {
      w64: true,
      op: AluRI::Add,
      dst,
      imm: offset,
    });
  }

  if cfg.pointer_mask == 0 {
    return;
  }
  if hint == region::STACK {
    expand_region(cfg, dst, scratch, size, true, out);
    return;
  }
  if hint == region::DATA {
    expand_region(cfg, dst, scratch, size, false, out);
    return;
  }

  // Unknown region: probe both branchlessly. The two guest ranges are
  // disjoint, so at most one candidate is non-zero and or-ing them recovers
  // the address, or zero — a guaranteed faulting access — when neither
  // matches.
  out.push(store64(dst, RBP, frame::ADDR_SPILL_OFFSET));
  expand_region(cfg, dst, scratch, size, true, out);
  out.push(store64(dst, RBP, frame::ACC_SPILL_OFFSET));
  out.push(load64(RBP, dst, frame::ADDR_SPILL_OFFSET));
  expand_region(cfg, dst, scratch, size, false, out);
  out.push(alu_rm(AluRM::Or, dst, RBP, frame::ACC_SPILL_OFFSET));
}

// ---------------------------------------------------------------------------
// Multiply / divide / modulo
// ---------------------------------------------------------------------------

fn is_mul(kind: MulDivKind) -> bool {
  match kind {
    MulDivKind::Mul => true,
    _ => false,
  }
}

fn is_mod(kind: MulDivKind) -> bool {
  match kind {
    MulDivKind::Mod => true,
    _ => false,
  }
}

fn is_div(kind: MulDivKind) -> bool {
  match kind {
    MulDivKind::Div => true,
    _ => false,
  }
}

/// Multiply, divide or modulo.
///
/// eBPF and x86 disagree about division by zero — eBPF yields 0 for `div` and
/// the dividend for `mod`, x86 faults — and about `INT_MIN / -1`, which eBPF
/// wraps and x86 faults on. Most of what is emitted here is fixing that up.
fn expand_muldivmod(
  kind: MulDivKind,
  w64: bool,
  reg: bool,
  signed: bool,
  src: u8,
  dst: u8,
  imm: i32,
  label: u32,
  out: &mut Vec<PInsn>,
) -> u32 {
  let mul = is_mul(kind);
  let div = is_div(kind);
  let mod_ = is_mod(kind);

  if !reg && imm == 0 {
    if div || mul {
      out.push(PInsn::Alu {
        w64: false,
        op: AluRR::Xor,
        src: dst,
        dst,
      });
    } else {
      // Modulo by zero yields the dividend, so this is a self-move — emitted
      // rather than elided.
      out.push(mov64(dst, dst));
    }
    return label;
  }

  expand_muldiv_setup(kind, w64, reg, signed, src, dst, imm, out);

  let no_overflow = label;
  let after_divide = label + 1;
  let mut next = label;
  if (div || mod_) && signed {
    expand_muldiv_overflow(w64, div, no_overflow, after_divide, out);
    next = label + 2;
  }

  out.push(PInsn::MulDivRcx { w64, kind, signed });

  if (div || mod_) && signed {
    out.push(PInsn::Local(after_divide));
  }

  expand_muldiv_finish(kind, dst, out);
  next
}

/// Saves the registers the divide clobbers, puts the divisor in RCX and the
/// dividend in RAX, and arranges for a zero divisor not to fault.
fn expand_muldiv_setup(
  kind: MulDivKind,
  w64: bool,
  reg: bool,
  signed: bool,
  src: u8,
  dst: u8,
  imm: i32,
  out: &mut Vec<PInsn>,
) {
  let div = is_div(kind);
  let mod_ = is_mod(kind);

  if dst != RAX {
    out.push(PInsn::Push(RAX));
  }
  if dst != RDX {
    out.push(PInsn::Push(RDX));
  }

  // Divisor into RCX.
  if reg {
    out.push(mov64(src, RCX));
  } else {
    out.push(PInsn::LoadImm {
      dst: RCX,
      imm: imm as i64,
    });
  }

  // Dividend into RAX.
  out.push(mov64(dst, RAX));

  if !(div || mod_) {
    return;
  }

  out.push(PInsn::Alu {
    w64,
    op: AluRR::Test,
    src: RCX,
    dst: RCX,
  });

  if mod_ {
    out.push(PInsn::Push(RAX));
  }
  out.push(PInsn::Pushfq);

  // Set the divisor to 1 if it is zero, so the divide does not fault; the
  // saved flags say afterwards whether it was.
  out.push(PInsn::LoadImm { dst: RDX, imm: 1 });
  out.push(cmove(RCX, RDX));

  if signed {
    if w64 {
      out.push(PInsn::Cqo);
    } else {
      out.push(PInsn::Cdq);
    }
  } else {
    out.push(PInsn::Alu {
      w64: false,
      op: AluRR::Xor,
      src: RDX,
      dst: RDX,
    });
  }
}

/// `INT_MIN / -1` faults on x86 but wraps per RFC 9669, so the two operands
/// are compared against it and the divide skipped when both match.
fn expand_muldiv_overflow(
  w64: bool,
  div: bool,
  no_overflow: u32,
  after_divide: u32,
  out: &mut Vec<PInsn>,
) {
  out.push(PInsn::CmpRcxMinusOne { w64 });
  out.push(PInsn::Jcc8 {
    cc: cc::NE,
    target: no_overflow,
  });

  if w64 {
    out.push(PInsn::LoadImm {
      dst: R11,
      imm: i64::MIN,
    });
    out.push(PInsn::Alu {
      w64: true,
      op: AluRR::Cmp,
      src: R11,
      dst: RAX,
    });
  } else {
    out.push(PInsn::CmpEaxImm { imm: 0x8000_0000 });
  }
  out.push(PInsn::Jcc8 {
    cc: cc::NE,
    target: no_overflow,
  });

  // For a divide the result is INT_MIN, which is already in RAX; a modulo
  // yields zero.
  if !div {
    out.push(PInsn::Alu {
      w64: false,
      op: AluRR::Xor,
      src: RDX,
      dst: RDX,
    });
  }
  out.push(PInsn::Jmp8 {
    target: after_divide,
  });
  out.push(PInsn::Local(no_overflow));
}

/// Restores the saved flags, substitutes eBPF's division-by-zero results, and
/// unwinds the saved registers.
fn expand_muldiv_finish(kind: MulDivKind, dst: u8, out: &mut Vec<PInsn>) {
  let mul = is_mul(kind);
  let div = is_div(kind);
  let mod_ = is_mod(kind);

  if div || mod_ {
    out.push(PInsn::Popfq);
    if div {
      // Zero flag set means the divisor was zero; substitute eBPF's result.
      out.push(PInsn::LoadImm { dst: RCX, imm: 0 });
      out.push(cmove(RAX, RCX));
    } else {
      out.push(PInsn::Pop(RCX));
      out.push(cmove(RDX, RCX));
    }
  }

  if dst != RDX {
    if mod_ {
      out.push(mov64(RDX, dst));
    }
    out.push(PInsn::Pop(RDX));
  }
  if dst != RAX {
    if div || mul {
      out.push(mov64(RAX, dst));
    }
    out.push(PInsn::Pop(RAX));
  }
}

// ---------------------------------------------------------------------------
// Atomics
// ---------------------------------------------------------------------------

/// The register-form ALU operation an atomic's opcode byte names.
fn alu_rr_of(op: u8) -> AluRR {
  if op == 0x09 {
    return AluRR::Or;
  }
  if op == 0x21 {
    return AluRR::And;
  }
  if op == 0x31 {
    return AluRR::Xor;
  }
  AluRR::Add
}

/// x86 has no atomic fetch-and-and/or/xor, and no 64-bit fetch-add that also
/// yields the old value in the right place, so all four are emulated with a
/// compare-exchange loop.
fn expand_atomic_fetch_alu(
  op: u8,
  w64: bool,
  src: u8,
  base: u8,
  disp: i32,
  label: u32,
  out: &mut Vec<PInsn>,
) -> u32 {
  // Compare-exchange overwrites RAX. If RAX is the source, keep the original
  // in whichever of R10/R11 is not the base.
  let actual_src = if src == RAX {
    if base == R10 {
      R11
    } else {
      R10
    }
  } else {
    src
  };

  if src == RAX {
    out.push(PInsn::Push(actual_src));
    out.push(mov64(src, actual_src));
  } else {
    out.push(PInsn::Push(RAX));
  }

  let size: Size = if w64 { 8 } else { 4 };
  out.push(PInsn::Load {
    size,
    sx: false,
    base,
    dst: RAX,
    disp,
  });

  let top = label;
  out.push(PInsn::Local(top));
  out.push(mov64(RAX, RCX));
  // Always the 64-bit form, even for the 32-bit variants: the compare-exchange
  // below is what narrows the operation, and the high half of RCX is dead.
  out.push(PInsn::Alu {
    w64: true,
    op: alu_rr_of(op),
    src: actual_src,
    dst: RCX,
  });
  out.push(PInsn::LockCmpxchg {
    w64,
    src: RCX,
    base,
    disp,
  });
  out.push(PInsn::Jcc8 {
    cc: cc::NE,
    target: top,
  });

  if src == RAX {
    out.push(PInsn::Pop(actual_src));
  } else {
    out.push(mov64(RAX, src));
    out.push(PInsn::Pop(RAX));
  }
  label + 1
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

/// The helper-call sequence.
///
/// The generated code decides at *run* time which of two paths to take: if the
/// dispatcher slot holds an address, control goes there with the helper index
/// as a sixth argument; otherwise the helper is looked up in the embedded
/// table by index.
fn expand_helper_call(idx: u32, label: u32, out: &mut Vec<PInsn>) -> u32 {
  let external = label;
  let converge = label + 1;

  out.push(PInsn::RipLoadDispatcher { dst: RAX });
  out.push(PInsn::AluImm {
    w64: true,
    op: AluRI::Cmp,
    dst: RAX,
    imm: 0,
  });
  out.push(PInsn::Jcc {
    cc: cc::NE,
    target: PTarget::Local(external),
  });

  // Default dispatcher: index into the embedded helper table.
  out.push(PInsn::AluImm {
    w64: false,
    op: AluRI::Mov,
    dst: RAX,
    imm: idx as i32,
  });
  out.push(PInsn::ShiftImm {
    w64: true,
    op: ShiftOp::Shl,
    dst: RAX,
    imm: 3,
  });
  out.push(PInsn::RipLeaHelperTable { dst: R10 });
  out.push(PInsn::Alu {
    w64: true,
    op: AluRR::Add,
    src: R10,
    dst: RAX,
  });
  out.push(load64(RAX, RAX, 0));

  // A registered helper takes five arguments and a context, which is the
  // sixth argument and goes in R9 on SysV.
  out.push(mov64(VOLATILE_CTXT, R9));
  out.push(PInsn::Jmp {
    target: PTarget::Local(converge),
  });

  // External dispatcher: six arguments, the last being the helper index.
  out.push(PInsn::Local(external));
  out.push(PInsn::LoadImm {
    dst: R9,
    imm: idx as u64 as i64,
  });

  // Control flow converges for the call.
  out.push(PInsn::Local(converge));
  out.push(PInsn::Call {
    target: PTarget::Retpoline,
  });

  // The result is in RAX. The registers backing eBPF R1-R5 are all
  // caller-saved and the helper path used them freely — the dispatcher, and
  // whatever it suspended into, up to the whole run loop — so the guest may
  // read anything here except host state. Scrub them to zero.
  let mut r: u8 = 1;
  while r <= 5 {
    let n = map_register(r);
    out.push(PInsn::Alu {
      w64: true,
      op: AluRR::Xor,
      src: n,
      dst: n,
    });
    r += 1;
  }
  label + 2
}

/// A local call whose target has not been compiled yet: ask the resolver at
/// run time, then call what it returns.
fn expand_lazy_local_call(cfg: &Cfg, id: u32, label: u32, out: &mut Vec<PInsn>) -> u32 {
  let exhausted = label;
  let done = label + 1;

  // The register mapped to R10 is already a native pointer into the
  // per-invocation guest stack. Refuse the call unless subtracting one frame
  // still leaves a complete frame below the callee's R10, and independently
  // reserve enough native stack for the persistent call frame and the
  // non-returning exhaustion callback.
  out.push(load64(RBP, RCX, frame::FRAME_OFFSET));
  out.push(load64(RCX, RCX, memory::LOCAL_CALL_GUEST_FLOOR));
  out.push(PInsn::Alu {
    w64: true,
    op: AluRR::Cmp,
    src: RCX,
    dst: R15,
  });
  out.push(PInsn::Jcc {
    cc: cc::B,
    target: PTarget::Local(exhausted),
  });

  out.push(load64(RBP, RCX, frame::FRAME_OFFSET));
  out.push(load64(RCX, RCX, memory::LOCAL_CALL_NATIVE_FLOOR));
  out.push(PInsn::Alu {
    w64: true,
    op: AluRR::Cmp,
    src: RCX,
    dst: RSP,
  });
  out.push(PInsn::Jcc {
    cc: cc::B,
    target: PTarget::Local(exhausted),
  });

  // Every local function has the same fixed guest-frame charge. Keeping R10
  // independent of host stack bookkeeping is what lets the coroutine suspend
  // across the call.
  out.push(PInsn::AluImm {
    w64: true,
    op: AluRI::Sub,
    dst: R15,
    imm: cfg.stack_frame_stride as i32,
  });

  expand_lazy_call_body(cfg, id, out);

  out.push(PInsn::AluImm {
    w64: true,
    op: AluRI::Add,
    dst: R15,
    imm: cfg.stack_frame_stride as i32,
  });
  out.push(PInsn::Jmp {
    target: PTarget::Local(done),
  });

  out.push(PInsn::Local(exhausted));
  out.push(PInsn::LoadImm {
    dst: RAX,
    imm: cfg.local_call_stack_exhausted as i64,
  });
  out.push(PInsn::CallReg(RAX));
  // The callback is declared divergent. Trap if an invalid embedder returns.
  out.push(PInsn::Ud2);
  out.push(PInsn::Local(done));
  label + 2
}

/// Saves the guest registers across the resolver call, asks the resolver, then
/// enters the callee and restores them.
fn expand_lazy_call_body(cfg: &Cfg, id: u32, out: &mut Vec<PInsn>) {
  out.push(PInsn::Push(map_register(6)));
  out.push(PInsn::Push(map_register(7)));
  out.push(PInsn::Push(map_register(8)));
  out.push(PInsn::Push(map_register(9)));

  // The resolver is a host call. Preserve the eBPF argument registers across
  // it, so the lazily compiled callee sees the R1-R5 the local call passed.
  out.push(PInsn::Push(map_register(1)));
  out.push(PInsn::Push(map_register(2)));
  out.push(PInsn::Push(map_register(3)));
  out.push(PInsn::Push(map_register(4)));
  out.push(PInsn::Push(map_register(5)));
  // Keep the host stack aligned for the resolver call. R11 is not a guest
  // register and is restored only to keep this sequence balanced.
  out.push(PInsn::Push(VOLATILE_CTXT));

  // eBPF R0 is mapped to RAX, which is also the host return register, so the
  // resolver's return value would otherwise be visible to the callee as a host
  // code pointer. Pushed twice to keep the host stack 16-byte aligned.
  out.push(PInsn::Push(map_register(0)));
  out.push(PInsn::Push(map_register(0)));

  out.push(PInsn::LoadImm {
    dst: RDI,
    imm: id as u64 as i64,
  });
  out.push(PInsn::LoadImm {
    dst: RAX,
    imm: cfg.local_call_resolver as i64,
  });
  out.push(PInsn::CallReg(RAX));

  // Stash the resolved callee address in RCX, which is mapped to no eBPF
  // register, and restore eBPF R0.
  out.push(mov64(RAX, RCX));
  out.push(PInsn::Pop(map_register(0)));
  out.push(PInsn::Pop(map_register(0)));

  out.push(PInsn::Pop(VOLATILE_CTXT));
  out.push(PInsn::Pop(map_register(5)));
  out.push(PInsn::Pop(map_register(4)));
  out.push(PInsn::Pop(map_register(3)));
  out.push(PInsn::Pop(map_register(2)));
  out.push(PInsn::Pop(map_register(1)));

  out.push(PInsn::CallReg(RCX));

  out.push(PInsn::Pop(map_register(9)));
  out.push(PInsn::Pop(map_register(8)));
  out.push(PInsn::Pop(map_register(7)));
  out.push(PInsn::Pop(map_register(6)));
}

/// The retpoline `call *rax` stand-in, adapted from Intel's guidance.
fn expand_retpoline(label: u32, out: &mut Vec<PInsn>) -> u32 {
  let landing = label;
  let capture = label + 1;

  out.push(PInsn::RetpolineLabel);
  out.push(PInsn::Call {
    target: PTarget::Local(landing),
  });

  out.push(PInsn::Local(capture));
  out.push(PInsn::Pause);
  out.push(PInsn::Jmp {
    target: PTarget::Local(capture),
  });

  out.push(PInsn::Local(landing));
  out.push(PInsn::StoreRspRax);
  out.push(PInsn::Ret);
  label + 2
}

//! The x86_64 backend.
//!
//! Translates one function at a time. uBPF's whole-program entry point, its
//! interpreter, its constant blinding, its eagerly relocated local call, its
//! per-index helper table and its unwind helper are all absent: the runtime
//! compiles one local function on first call, dispatches every helper through
//! the registered dispatcher, and calls every local callee through the lazy
//! resolver, so none of them has a live caller.
//!
//! # Changing what this emits
//!
//! Every byte this backend produces for the canonical cases is recorded in
//! `src/jit/goldens/x86_64.txt`, so any change to code generation shows up as a
//! diff there. That is deliberate: the diff is the deliverable, and an
//! unexplained one means something moved that nobody meant to move.
//!
//! # Shape of the emitted function
//!
//! ```text
//!   [per-function prologue]  push the callee's guest stack usage
//!   [instruction stream]     each EXIT emits its own `add rsp, 8 ; ret`
//!   retpoline
//!   external dispatcher address     (8 bytes)
//! ```

use crate::jit::abi;
use crate::jit::isa::{
  cls, opcode, AluOp, AluWidth, AtomicOp, EndKind, Insn, JmpOp, Op, Source, Width,
};
use crate::jit::patch::{JitState, OpenGroup, PatchTarget, Progress};
use crate::jit::{Config, PlanEntry, TranslateError, TranslationInputs, Translator};

// ---------------------------------------------------------------------------
// Native registers
// ---------------------------------------------------------------------------

const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBX: u8 = 3;
const RSP: u8 = 4;
/// Also names `RIP`, which shares this number in RIP-relative ModRM.
const RBP: u8 = 5;
const RSI: u8 = 6;
const RDI: u8 = 7;
const R8: u8 = 8;
const R9: u8 = 9;
const R10: u8 = 10;
const R11: u8 = 11;
const R12: u8 = 12;
const R13: u8 = 13;
const R14: u8 = 14;
const R15: u8 = 15;

/// Where the entry code parks the embedder's context pointer.
const VOLATILE_CTXT: u8 = R11;
/// eBPF `R4` maps here, and shifts need RCX; the helper-call sequence moves it
/// out of the way.
const RCX_ALT: u8 = R10;

/// eBPF register to x86 register, SysV flavour.
/// The Windows map differs and is not ported: this crate is Linux/OpenBSD only.
/// The *structure* is kept — eBPF `R0`-`R5` land on caller-saved registers and
/// `R6`-`R10` on callee-saved ones — because the helper-call sequence relies on
/// it to know what it does not have to preserve.
/// `R15` must stay mapped to eBPF `R10`: the frame-access fast path and the
/// local-call frame adjustment both name it directly.
const REGISTER_MAP: [u8; crate::jit::isa::NUM_REGS] = [
  // Scratch registers.
  RAX, RDI, RSI, RDX, R10, R8, // Non-volatile registers.
  RBX, R12, R13, R14, R15,
];

/// The x86 register for an eBPF register.
/// Wraps modularly rather than panicking, so a register number the
/// validator should have rejected wraps rather than trapping in a release build
///. Reproduced.
fn map_register(r: u8) -> u8 {
  REGISTER_MAP[(r as usize) % crate::jit::isa::NUM_REGS]
}

/// The eBPF register mapped to `native`, if any. The map is injective, so this
/// is exact.
fn unmap_register(native: u8) -> Option<u8> {
  REGISTER_MAP
    .iter()
    .position(|&x| x == native)
    .map(|i| i as u8)
}

/// Operand size, mirroring `enum operand_size`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum S {
  S8,
  S16,
  S32,
  S64,
}

impl S {
  fn from_width(w: Width) -> S {
    match w {
      Width::B => S::S8,
      Width::H => S::S16,
      Width::W => S::S32,
      Width::DW => S::S64,
    }
  }

  /// Previously recomputed at every call site as
  /// `size == S64 ? 8 : size == S32 ? 4 : size == S16 ? 2 : 1`.
  fn bytes(self) -> i32 {
    match self {
      S::S8 => 1,
      S::S16 => 2,
      S::S32 => 4,
      S::S64 => 8,
    }
  }
}

/// Where one guest region's bounds can be found.
struct GuestRegion {
  desc_bottom: i32,
  desc_top: i32,
  desc_native_base: i32,
  slot_bottom: i32,
  slot_delta: i32,
  slot_span: i32,
}

const STACK_REGION: GuestRegion = GuestRegion {
  desc_bottom: abi::memory::STACK_GUEST_BOTTOM,
  desc_top: abi::memory::STACK_GUEST_TOP,
  desc_native_base: abi::memory::STACK_NATIVE_BASE,
  slot_bottom: abi::derived_slot(abi::DERIVED_STACK_BASE + abi::DERIVED_BOTTOM),
  slot_delta: abi::derived_slot(abi::DERIVED_STACK_BASE + abi::DERIVED_DELTA),
  slot_span: abi::derived_slot(abi::DERIVED_STACK_BASE + abi::DERIVED_SPAN),
};

const DATA_REGION: GuestRegion = GuestRegion {
  desc_bottom: abi::memory::DATA_GUEST_BOTTOM,
  desc_top: abi::memory::DATA_GUEST_TOP,
  desc_native_base: abi::memory::DATA_NATIVE_BASE,
  slot_bottom: abi::derived_slot(abi::DERIVED_DATA_BASE + abi::DERIVED_BOTTOM),
  slot_delta: abi::derived_slot(abi::DERIVED_DATA_BASE + abi::DERIVED_DELTA),
  slot_span: abi::derived_slot(abi::DERIVED_DATA_BASE + abi::DERIVED_SPAN),
};

/// x86 ALU opcodes used by the atomic forms.
const X64_ALU_ADD: u8 = 0x01;
const X64_ALU_OR: u8 = 0x09;
const X64_ALU_AND: u8 = 0x21;
const X64_ALU_XOR: u8 = 0x31;

/// Entry point: emit the instruction stream, then the trailer, then resolve
/// every fixup the two recorded.
pub fn translate_range(
  t: &Translator,
  inputs: &TranslationInputs<'_>,
  buffer: &mut [u8],
) -> Result<usize, TranslateError> {
  let mut e = Emit {
    st: JitState::new(buffer, t.insns().len()),
    t,
    cfg: t.config(),
    inputs,
    errmsg: None,
    retpoline_loc: 0,
    retpoline_calls: Vec::new(),
  };
  e.run()
}

struct Emit<'buf, 'ctx, 'in_> {
  st: JitState<'buf>,
  t: &'ctx Translator,
  cfg: &'ctx Config,
  inputs: &'ctx TranslationInputs<'in_>,
  /// Set alongside a [`Progress`] where the message needs information only
  /// the detecting site has.
  errmsg: Option<String>,
  /// Offset of the retpoline thunk, which the trailer places after the body.
  retpoline_loc: u32,
  /// `call rel32` displacement fields awaiting [`Self::retpoline_loc`]. Kept
  /// here rather than in the shared state because the thunk is x86_64's alone.
  retpoline_calls: Vec<u32>,
}

// ---------------------------------------------------------------------------
// Primitive emission
// ---------------------------------------------------------------------------

impl Emit<'_, '_, '_> {
  /// Once the translation has failed,
  /// nothing more is written *and the offset does not advance*. The check is
  /// here rather than in [`JitState`] because the shared state is also used by
  /// the arm64 backend.
  #[inline]
  fn emit_n(&mut self, value: u64, n: usize) {
    if !self.st.ok() {
      return;
    }
    self.st.emit_bytes(value, n);
  }

  #[inline]
  fn emit1(&mut self, x: u8) {
    self.emit_n(x as u64, 1);
  }

  #[inline]
  fn emit2(&mut self, x: u16) {
    self.emit_n(x as u64, 2);
  }

  #[inline]
  fn emit4(&mut self, x: u32) {
    self.emit_n(x as u64, 4);
  }

  #[inline]
  fn emit8(&mut self, x: u64) {
    self.emit_n(x, 8);
  }

  #[inline]
  fn offset(&self) -> u32 {
    self.st.offset
  }

  /// Reserves four bytes for a jump displacement and records the fixup.
  /// Returns where the displacement starts.
  fn emit_jump_address_reloc(&mut self, target: PatchTarget) -> u32 {
    let at = self.offset();
    self.st.note_jump(at, target);
    self.emit4(0);
    at
  }

  fn emit_modrm(&mut self, md: u8, r: u8, m: u8) {
    self.emit1((md & 0xc0) | ((r & 7) << 3) | (m & 7));
  }

  fn emit_modrm_reg2reg(&mut self, r: u8, m: u8) {
    self.emit_modrm(0xc0, r, m);
  }

  /// ModRM plus displacement, with the zero-displacement shortcut.
  /// Two irregular
  /// cases matter:
  /// * `RBP`/`R13` cannot encode a bare `[base]`, so they always get an
  ///   explicit displacement even when it is zero;
  /// * `R12` needs a SIB byte, emitted as `0x24`.
  /// `RSP` and `R12` share the low three bits that ModRM encodes, and both
  /// therefore need the SIB byte. No caller passes `RSP` as a base today — the
  /// sequences that address the host stack emit their ModRM and SIB bytes
  /// literally — so emitting it for `R12` alone happens to produce correct code;
  /// it would misencode the moment one did.
  fn emit_modrm_and_displacement(&mut self, reg: u8, rm: u8, d: i32) {
    let rm = rm & 0xf;
    let reg = reg & 0xf;

    if d == 0 && rm != RSP && rm != RBP && rm != R12 && rm != R13 {
      self.emit_modrm(0x00, reg, rm);
      return;
    }

    let near_disp = (-128..=127).contains(&d);
    let md = if near_disp { 0x40 } else { 0x80 };

    self.emit_modrm(md, reg, rm);
    if rm == R12 || rm == RSP {
      self.emit1(0x24);
    }

    if near_disp {
      self.emit1(d as u8);
    } else {
      self.emit4(d as u32);
    }
  }

  fn emit_rex(&mut self, w: u8, r: u8, x: u8, b: u8) {
    self.emit1(0x40 | (w << 3) | (r << 2) | (x << 1) | b);
  }

  /// REX carrying only the high bits of `src`/`dst`, skipped when no bit would
  /// be set.
  fn emit_basic_rex(&mut self, w: u8, src: u8, dst: u8) {
    if w != 0 || (src & 8) != 0 || (dst & 8) != 0 {
      self.emit_rex(w, u8::from(src & 8 != 0), 0, u8::from(dst & 8 != 0));
    }
  }

  fn emit_push(&mut self, r: u8) {
    self.emit_basic_rex(0, 0, r);
    self.emit1(0x50 | (r & 7));
  }

  fn emit_pop(&mut self, r: u8) {
    self.emit_basic_rex(0, 0, r);
    self.emit1(0x58 | (r & 7));
  }

  fn emit_alu32(&mut self, op: u8, src: u8, dst: u8) {
    self.emit_basic_rex(0, src, dst);
    self.emit1(op);
    self.emit_modrm_reg2reg(src, dst);
  }

  fn emit_alu32_imm32(&mut self, op: u8, src: u8, dst: u8, imm: i32) {
    self.emit_alu32(op, src, dst);
    self.emit4(imm as u32);
  }

  fn emit_alu32_imm8(&mut self, op: u8, src: u8, dst: u8, imm: i32) {
    // The displacement is a signed byte, so the immediate is truncated here.
    self.emit_alu32(op, src, dst);
    self.emit1(imm as u8);
  }

  /// `and dst, 0xffffffff` — the zero-extension every 32-bit ALU op ends with.
  fn emit_truncate_u32(&mut self, dst: u8) {
    self.emit_alu32_imm32(0x81, 4, dst, u32::MAX as i32);
  }

  fn emit_alu64(&mut self, op: u8, src: u8, dst: u8) {
    self.emit_basic_rex(1, src, dst);
    self.emit1(op);
    self.emit_modrm_reg2reg(src, dst);
  }

  fn emit_alu64_imm32(&mut self, op: u8, src: u8, dst: u8, imm: i32) {
    self.emit_alu64(op, src, dst);
    self.emit4(imm as u32);
  }

  fn emit_alu64_imm8(&mut self, op: u8, src: u8, dst: u8, imm: i32) {
    self.emit_alu64(op, src, dst);
    self.emit1(imm as u8);
  }

  fn emit_mov(&mut self, src: u8, dst: u8) {
    self.emit_alu64(0x89, src, dst);
  }

  fn emit_cmp_imm32(&mut self, dst: u8, imm: i32) {
    self.emit_alu64_imm32(0x81, 7, dst, imm);
  }

  fn emit_cmp32_imm32(&mut self, dst: u8, imm: i32) {
    self.emit_alu32_imm32(0x81, 7, dst, imm);
  }

  fn emit_cmp(&mut self, src: u8, dst: u8) {
    self.emit_alu64(0x39, src, dst);
  }

  fn emit_cmp32(&mut self, src: u8, dst: u8) {
    self.emit_alu32(0x39, src, dst);
  }

  fn emit_jcc(&mut self, code: u8, target: PatchTarget) -> u32 {
    self.emit1(0x0f);
    self.emit1(code);
    self.emit_jump_address_reloc(target)
  }

  /// A near jump emits the two-byte `0xeb rel8` form but still reserves a
  /// *four*-byte placeholder, so three bytes are wasted after every one. They
  /// are never executed — the jump is unconditional and lands past them — so
  /// this costs code size and nothing else. Narrowing the reservation would
  /// shift the offset of everything after it, so it is a self-contained change
  /// to make on its own and measure, not a tidy-up to fold into something else.
  fn emit_jmp(&mut self, target: PatchTarget) -> u32 {
    let near = matches!(
      target,
      PatchTarget::EbpfPc { near: true, .. } | PatchTarget::JitOffset { near: true, .. }
    );
    self.emit1(if near { 0xeb } else { 0xe9 });
    self.emit_jump_address_reloc(target)
  }

  fn emit_call(&mut self, target: PatchTarget) -> u32 {
    self.emit1(0xe8);
    let call_src = self.offset();
    self.emit_jump_address_reloc(target);
    call_src
  }

  fn emit_ret(&mut self) {
    self.emit1(0xc3);
  }

  fn emit_pause(&mut self) {
    self.emit1(0xf3);
    self.emit1(0x90);
  }

  /// `load [src + offset] -> dst`, zero-extending for the narrow widths.
  fn emit_load(&mut self, size: S, src: u8, dst: u8, offset: i32) {
    self.emit_basic_rex(u8::from(size == S::S64), dst, src);

    match size {
      S::S8 => {
        self.emit1(0x0f);
        self.emit1(0xb6);
      }
      S::S16 => {
        self.emit1(0x0f);
        self.emit1(0xb7);
      }
      S::S32 | S::S64 => self.emit1(0x8b),
    }

    self.emit_modrm_and_displacement(dst, src, offset);
  }

  /// `load [src + offset] -> dst`, sign-extending to 64 bits.
  /// `S64` emits nothing at all (there is no `ldxdwsx` encoding,
  /// so no caller reaches it).
  fn emit_load_sx(&mut self, size: S, src: u8, dst: u8, offset: i32) {
    match size {
      S::S8 | S::S16 => {
        self.emit_basic_rex(1, dst, src);
        self.emit1(0x0f);
        self.emit1(if size == S::S8 { 0xbe } else { 0xbf });
        self.emit_modrm_and_displacement(dst, src, offset);
      }
      S::S32 => {
        self.emit_basic_rex(1, dst, src);
        self.emit1(0x63);
        self.emit_modrm_and_displacement(dst, src, offset);
      }
      S::S64 => {}
    }
  }

  /// Materialises a 64-bit immediate, preferring the sign-extended 32-bit form.
  fn emit_load_imm(&mut self, dst: u8, imm: i64) {
    if (i32::MIN as i64..=i32::MAX as i64).contains(&imm) {
      self.emit_alu64_imm32(0xc7, 0, dst, imm as i32);
    } else {
      self.emit_basic_rex(1, 0, dst);
      self.emit1(0xb8 | (dst & 7));
      self.emit8(imm as u64);
    }
  }

  /// `op reg, [base + offset]` at 64 bits, for the `0x2B`/`0x03`/`0x39`/`0x3B`/
  /// `0x0B` forms the bounds check uses.
  fn emit_alu64_mem(&mut self, op: u8, reg: u8, base: u8, offset: i32) {
    self.emit_basic_rex(1, reg, base);
    self.emit1(op);
    self.emit_modrm_and_displacement(reg, base, offset);
  }

  /// `cmovcc dst, src` at 64 bits.
  fn emit_cmov(&mut self, cc: u8, dst: u8, src: u8) {
    self.emit_basic_rex(1, dst, src);
    self.emit1(0x0f);
    self.emit1(cc);
    self.emit_modrm_reg2reg(dst, src);
  }

  /// `store src -> [dst + offset]`.
  /// The `size == S8` term in the REX condition is what makes a byte store
  /// through `SIL`/`DIL`/`SPL`/`BPL` name the right register: without a REX
  /// prefix those encodings mean `AH`/`CH`/`DH`/`BH`.
  fn emit_store(&mut self, size: S, src: u8, dst: u8, offset: i32) {
    if size == S::S16 {
      self.emit1(0x66);
    }
    let rexw = u8::from(size == S::S64);
    if rexw != 0 || (src & 8) != 0 || (dst & 8) != 0 || size == S::S8 {
      self.emit_rex(rexw, u8::from(src & 8 != 0), 0, u8::from(dst & 8 != 0));
    }
    self.emit1(if size == S::S8 { 0x88 } else { 0x89 });
    self.emit_modrm_and_displacement(src, dst, offset);
  }

  /// `store imm -> [dst + offset]`.
  fn emit_store_imm32(&mut self, size: S, dst: u8, offset: i32, imm: i32) {
    if size == S::S16 {
      self.emit1(0x66);
    }
    self.emit_basic_rex(u8::from(size == S::S64), 0, dst);
    self.emit1(if size == S::S8 { 0xc6 } else { 0xc7 });
    self.emit_modrm_and_displacement(0, dst, offset);
    match size {
      S::S32 | S::S64 => self.emit4(imm as u32),
      S::S16 => self.emit2(imm as u16),
      S::S8 => self.emit1(imm as u8),
    }
  }

  /// `mov dst, [rip + dispatcher_slot]`, with the displacement deferred.
  fn emit_dispatcher_slot_load(&mut self, dst: u8) {
    self.emit_rex(1, 0, 0, 0);
    self.emit1(0x8b);
    self.emit_modrm(0, dst, 0x05);

    let at = self.offset();
    self.st.note_load(at);
    self.emit4(0);
  }

  fn emit_indirect_call_rax(&mut self) {
    self.emit1(0xff);
    self.emit1(0xd0);
  }

  fn emit_indirect_call_reg(&mut self, reg: u8) {
    if reg & 8 != 0 {
      self.emit1(0x41);
    }
    self.emit1(0xff);
    self.emit1(0xd0 | (reg & 7));
  }
}

// ---------------------------------------------------------------------------
// The pointer cage
// ---------------------------------------------------------------------------

impl Emit<'_, '_, '_> {
  /// The same check as [`Self::emit_single_region_address_via_descriptor`],
  /// reading the region's bounds from the frame constants the embedder derived
  /// once per invocation.
  fn emit_single_region_address_from_frame(
    &mut self,
    dst: u8,
    scratch: u8,
    size: i32,
    bottom_slot: i32,
    delta_slot: i32,
    span_base: i32,
  ) {
    // off = guest - bottom, kept in a register for the comparison below.
    self.emit_mov(dst, scratch);
    self.emit_alu64_mem(0x2B, scratch, RBP, bottom_slot);

    // Translate unconditionally; the CMOV below undoes it when out of range.
    self.emit_alu64_mem(0x03, dst, RBP, delta_slot);

    if let Some(slot) = width_span_slot(size) {
      let zero = R9;
      let span_slot = span_base + (slot as i32) * 8;

      // Zero the fault address before the compare, which sets the flags.
      self.emit_alu64(0x31, zero, zero);

      // 0x39 is `CMP r/m64, r64`, so the memory operand is the left-hand side:
      // CF is set iff span < off, i.e. iff out of range.
      self.emit_alu64_mem(0x39, scratch, RBP, span_slot);
      self.emit_cmov(0x42, dst, zero); // cmovb dst, 0
    } else {
      // An access group covers any width up to a page rather than one of the
      // four the precomputed spans hold, so narrow the width-1 span instead.
      let span = R9;
      self.emit_load(S::S64, RBP, span, span_base);
      self.emit_alu64_imm32(0x81, 5, span, size - 1);

      // Both remaining registers are live across the compare, so the fault
      // address is zeroed after it with a MOV, which leaves the flags alone.
      self.emit_alu64(0x39, scratch, span);
      self.emit_alu64_imm32(0xc7, 0, scratch, 0);
      self.emit_cmov(0x42, dst, scratch);
    }
  }

  /// Bounds-check `[dst, dst+size)` against one guest region described by the
  /// memory descriptor at `[RBP - 8]`, then translate `dst`. Branchless: a
  /// final CMOV substitutes address 0 when out of range, so no mis-speculated
  /// path performs a transient out-of-bounds access.
  fn emit_single_region_address_via_descriptor(
    &mut self,
    dst: u8,
    scratch: u8,
    size: i32,
    bottom_off: i32,
    top_off: i32,
    base_off: i32,
  ) {
    let span = R9;

    self.emit_load(S::S64, RBP, scratch, abi::FRAME_OFFSET);

    // off = dst - bottom; spill it, then translated = off + base (kept in dst).
    self.emit_alu64_mem(0x2B, dst, scratch, bottom_off);
    self.emit_store(S::S64, dst, RBP, abi::SPILL_OFFSET);
    self.emit_alu64_mem(0x03, dst, scratch, base_off);

    // span = (top - size) - bottom
    self.emit_load(S::S64, scratch, span, top_off);
    if size != 0 {
      self.emit_alu64_imm32(0x81, 5, span, size);
    }
    self.emit_alu64_mem(0x2B, span, scratch, bottom_off);

    // Zero the fault address before the compare, which sets the flags.
    self.emit_alu64(0x31, scratch, scratch);

    self.emit_alu64_mem(0x3B, span, RBP, abi::SPILL_OFFSET);
    self.emit_cmov(0x42, dst, scratch);
  }

  fn emit_single_region_address(&mut self, dst: u8, scratch: u8, size: i32, region: &GuestRegion) {
    if self.cfg.frame_constants {
      self.emit_single_region_address_from_frame(
        dst,
        scratch,
        size,
        region.slot_bottom,
        region.slot_delta,
        region.slot_span,
      );
    } else {
      self.emit_single_region_address_via_descriptor(
        dst,
        scratch,
        size,
        region.desc_bottom,
        region.desc_top,
        region.desc_native_base,
      );
    }
  }

  /// Materialises the *guest* value of eBPF `R10` into `dst`.
  /// Under a native frame base the register mapped to `R10` holds a host
  /// address; a program that reads `R10` as a value must still see a guest one.
  fn emit_guest_frame_pointer(&mut self, dst: u8) {
    self.emit_mov(map_register(crate::jit::isa::REG_FP), dst);
    self.emit_alu64_mem(0x2B, dst, RBP, abi::FRAME_DELTA_OFFSET);
  }

  /// True when `[base + offset]`, `size` bytes wide, is a frame access that
  /// needs no bounds check at all.
  /// This is the one place a runtime check is traded for a static argument, so
  /// three of the four conditions are re-derived here rather than taken from
  /// the hint.
  fn emit_frame_access_ok(&self, region_hint: u8, base: u8, offset: i32, size: i32) -> bool {
    if !self.cfg.native_frame_base_active() || region_hint != abi::region::FRAME {
      return false;
    }
    if base != map_register(crate::jit::isa::REG_FP) {
      return false;
    }
    // offset + size <= 0
    if offset > -size {
      return false;
    }
    if offset < -(abi::LOCAL_FUNCTION_STACK_SIZE as i32) {
      return false;
    }
    true
  }

  /// Resolves `[src + offset]` to a native address in `dst`, emitting whatever
  /// check that needs.
  #[allow(clippy::too_many_arguments)]
  fn emit_masked_address_with_offset(
    &mut self,
    src: u8,
    dst: u8,
    scratch: u8,
    offset: i32,
    size: i32,
    store: bool,
    region_hint: u8,
  ) {
    debug_assert_ne!(dst, scratch);

    if self.cfg.native_frame_base_active() && src == map_register(crate::jit::isa::REG_FP) {
      // Everything below works in guest space, so recover the guest frame
      // pointer before starting.
      self.emit_guest_frame_pointer(dst);
    } else if src != dst {
      self.emit_mov(src, dst);
    }

    if offset != 0 {
      self.emit_alu64_imm32(0x81, 0, dst, offset);
    }

    if self.cfg.pointer_mask != 0 {
      // Stores are confined to the active stack regardless of the hint, which
      // is what preserves the read-only guarantee for the data region.
      if store || region_hint == abi::region::STACK {
        self.emit_single_region_address(dst, scratch, size, &STACK_REGION);
        return;
      }
      if region_hint == abi::region::DATA {
        self.emit_single_region_address(dst, scratch, size, &DATA_REGION);
        return;
      }

      // Unknown region: probe both branchlessly. The two guest ranges are
      // disjoint, so at most one candidate is non-zero and OR-ing them recovers
      // the address (or 0, a guaranteed faulting access, when neither matches).
      self.emit_store(S::S64, dst, RBP, abi::ADDR_SPILL_OFFSET);
      self.emit_single_region_address(dst, scratch, size, &STACK_REGION);
      self.emit_store(S::S64, dst, RBP, abi::ACC_SPILL_OFFSET);
      self.emit_load(S::S64, RBP, dst, abi::ADDR_SPILL_OFFSET);
      self.emit_single_region_address(dst, scratch, size, &DATA_REGION);
      self.emit_alu64_mem(0x0B, dst, RBP, abi::ACC_SPILL_OFFSET);
    }
  }

  /// The plan entry for `pc`, or `None` when there is no usable plan.
  fn access_plan_entry(&self, pc: usize) -> Option<PlanEntry> {
    self.inputs.plan_entry(self.cfg, pc).copied()
  }

  /// Resolves `[base + offset]` to a native address and returns the register it
  /// was left in together with the displacement to use with it. Mirrors
  /// `emit_checked_address`.
  /// The access plan chooses between the group-member and group-leader paths,
  /// and it is not taken on trust: every condition the backend can see for
  /// itself is re-derived here, and any failure drops through to an ordinary
  /// checked access. A plan that is wrong — or hostile — costs speed and
  /// nothing else.
  #[allow(clippy::too_many_arguments)]
  fn emit_checked_address(
    &mut self,
    pc: usize,
    base: u8,
    offset: i32,
    width: i32,
    store: bool,
    region_hint: u8,
    addr_reg: u8,
    scratch_reg: u8,
  ) -> (u8, i32) {
    if self.emit_frame_access_ok(region_hint, base, offset, width) {
      return (base, offset);
    }

    if self.cfg.pointer_mask == 0 {
      return (base, offset);
    }

    let plan = self.access_plan_entry(pc);
    let base_ebpf = unmap_register(base);

    if let Some(plan) = plan.filter(|p| p.role == abi::plan_role::MEMBER) {
      // `group` is `Some` only while the backend has established that the
      // leader ran and that nothing has redefined the base since:
      // `note_register_written` closes the group outright when the base is
      // overwritten, and the `written` mask below rejects the same access on its
      // own. Both are tested here and on aarch64, so neither backend depends on
      // which half of `OpenGroup` does the invalidating.
      let usable = match (&self.st.group, base_ebpf) {
        (Some(g), Some(base_ebpf)) => {
          g.leader_pc == plan.leader_pc
            && base_ebpf == g.base_reg
            && g.written & (1u16 << base_ebpf) == 0
            && plan.delta as u64 + width as u64 <= g.span as u64
            && g.lo as i64 + plan.delta as i64 == offset as i64
            // A store cannot ride a window checked against the read-only data
            // region.
            && (!store || g.region == abi::region::STACK)
        }
        _ => false,
      };
      if usable {
        self.emit_load(S::S64, RBP, addr_reg, abi::GROUP_BASE_OFFSET);
        return (addr_reg, plan.delta as i32);
      }
      // Fall through to a checked access. The group stays open: a member the
      // backend declined does not invalidate the parked base for the ones
      // after it.
    }

    if let Some(plan) = plan.filter(|p| p.role == abi::plan_role::LEADER) {
      let usable = base_ebpf.is_some()
        && plan.span > 0
        && plan.span <= abi::MAX_GROUP_SPAN
        && plan.delta as u64 + width as u64 <= plan.span as u64
        && plan.lo as i64 + plan.delta as i64 == offset as i64
        && plan.region != abi::region::FRAME
        && (!store || plan.region == abi::region::STACK);
      if usable {
        self.emit_masked_address_with_offset(
          base,
          addr_reg,
          scratch_reg,
          plan.lo,
          plan.span as i32,
          store,
          plan.region,
        );
        self.emit_store(S::S64, addr_reg, RBP, abi::GROUP_BASE_OFFSET);
        self.st.group = Some(OpenGroup {
          leader_pc: pc as u32,
          span: plan.span,
          lo: plan.lo,
          base_reg: base_ebpf.expect("checked above"),
          region: plan.region,
          written: 0,
        });
        return (addr_reg, plan.delta as i32);
      }
    }

    self.emit_masked_address_with_offset(
      base,
      addr_reg,
      scratch_reg,
      offset,
      width,
      store,
      region_hint,
    );
    (addr_reg, 0)
  }

  fn emit_masked_load(&mut self, size: S, src: u8, dst: u8, offset: i32, hint: u8, pc: usize) {
    let width = size.bytes();
    let (addr, disp) = self.emit_checked_address(pc, src, offset, width, false, hint, R11, RCX);
    self.emit_load(size, addr, dst, disp);
  }

  fn emit_masked_load_sx(&mut self, size: S, src: u8, dst: u8, offset: i32, hint: u8, pc: usize) {
    let width = size.bytes();
    let (addr, disp) = self.emit_checked_address(pc, src, offset, width, false, hint, R11, RCX);
    self.emit_load_sx(size, addr, dst, disp);
  }

  fn emit_masked_store(&mut self, size: S, src: u8, dst: u8, offset: i32, hint: u8, pc: usize) {
    let width = size.bytes();
    // A program storing R10 stores a pointer, and under a native frame base the
    // register holds the host one. Recover the guest value — but only after the
    // address is resolved below, which uses RCX as its scratch.
    let store_guest_frame_pointer =
      self.cfg.native_frame_base_active() && src == map_register(crate::jit::isa::REG_FP);
    let (addr, disp) = self.emit_checked_address(pc, dst, offset, width, true, hint, R11, RCX);

    let mut src = src;
    if store_guest_frame_pointer {
      self.emit_guest_frame_pointer(RCX);
      src = RCX;
    }
    self.emit_store(size, src, addr, disp);
  }

  fn emit_masked_store_imm32(
    &mut self,
    size: S,
    dst: u8,
    offset: i32,
    imm: i32,
    hint: u8,
    pc: usize,
  ) {
    let width = size.bytes();
    // RCX carries the address here and R11 is the scratch, the other way round
    // from the register forms, because the immediate still needs a register of
    // its own once the address is resolved.
    let (addr, disp) = self.emit_checked_address(pc, dst, offset, width, true, hint, RCX, R11);

    if addr == dst {
      // No translation was needed, so the guest displacement stands.
      self.emit_store_imm32(size, addr, disp, imm);
    } else {
      self.emit_load_imm(R11, imm as i64);
      self.emit_store(size, R11, addr, disp);
    }
  }
}

/// The span slot for an access `size` bytes wide, or `None` for a width the
/// precomputed spans do not cover.
/// The span-slot lookup returns 3 for anything that is not 1, 2 or 4; the
/// caller guards with an explicit `size == 1 || ... || size == 8` test, so the
/// `default` arm is only ever reached with 8. Returning `None` instead makes
/// the guard and the lookup one decision.
fn width_span_slot(size: i32) -> Option<usize> {
  if size < 0 {
    return None;
  }
  abi::span_slot_index(size as usize)
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

impl Emit<'_, '_, '_> {
  /// The helper-call sequence, SysV only.
  ///
  /// uBPF decided at *run* time between the registered dispatcher and a lookup
  /// in an embedded per-index helper table. This crate never registers
  /// individual helpers, and [`crate::jit::validate`] refuses a helper call when
  /// no dispatcher is configured — so a `call` only ever reaches here with a
  /// non-null slot, and the table, the runtime test and the branch around it are
  /// gone. The dispatcher takes six arguments, the last being the helper index.
  fn emit_dispatched_external_helper_call(&mut self, idx: u32) {
    self.emit_dispatcher_slot_load(RAX);
    self.emit_load_imm(R9, idx as u64 as i64);
    self.emit_retpoline_call();

    // The result is in RAX.
  }

  /// A local call whose target has not been compiled yet: ask the resolver at
  /// run time, then call what it returns.
  fn emit_lazy_local_call(&mut self, call_pc: usize) {
    let resolver = match self.cfg.local_call_resolver {
      Some(r) if call_pc < self.inputs.resolver_ids.len() => r,
      _ => {
        self.st.fail(Progress::UnexpectedInstruction);
        return;
      }
    };
    let id = self.inputs.resolver_ids[call_pc];

    // Match the normal local-call frame setup: `sub r15, [rsp]` moves R10 down
    // by the current function's stack usage. Emitted literally because the
    // ModRM+SIB pair for an `[rsp]` base is not what
    // `emit_modrm_and_displacement` produces.
    self.emit1(0x4c);
    self.emit1(0x2B);
    self.emit1(0x3C);
    self.emit1(0x24);

    self.emit_push(map_register(6));
    self.emit_push(map_register(7));
    self.emit_push(map_register(8));
    self.emit_push(map_register(9));

    // The resolver is a host call. Preserve the BPF argument registers across
    // it so the lazily compiled callee sees the R1-R5 the original local call
    // would have passed.
    self.emit_push(map_register(1));
    self.emit_push(map_register(2));
    self.emit_push(map_register(3));
    self.emit_push(map_register(4));
    self.emit_push(map_register(5));
    // Keep the host stack aligned for the resolver call. R11 is not a guest
    // register and is restored only to keep this sequence balanced.
    self.emit_push(VOLATILE_CTXT);

    // BPF R0 is mapped to RAX, which is also the host return register, so the
    // resolver's return value would otherwise be visible to the callee as a
    // host code pointer. Pushed twice to keep the host stack 16-byte aligned.
    self.emit_push(map_register(0));
    self.emit_push(map_register(0));

    self.emit_load_imm(RDI, id as u64 as i64);
    self.emit_load_imm(RAX, resolver as usize as u64 as i64);
    self.emit_indirect_call_rax();

    // Stash the resolved callee address in RCX, which is not mapped to any eBPF
    // register, and restore BPF R0.
    self.emit_mov(RAX, RCX);
    self.emit_pop(map_register(0));
    self.emit_pop(map_register(0));

    self.emit_pop(VOLATILE_CTXT);
    self.emit_pop(map_register(5));
    self.emit_pop(map_register(4));
    self.emit_pop(map_register(3));
    self.emit_pop(map_register(2));
    self.emit_pop(map_register(1));

    self.emit_indirect_call_reg(RCX);

    self.emit_pop(map_register(9));
    self.emit_pop(map_register(8));
    self.emit_pop(map_register(7));
    self.emit_pop(map_register(6));

    // `add r15, [rsp]`
    self.emit1(0x4c);
    self.emit1(0x03);
    self.emit1(0x3C);
    self.emit1(0x24);
  }
}

// ---------------------------------------------------------------------------
// Atomics
// ---------------------------------------------------------------------------

impl Emit<'_, '_, '_> {
  fn emit_atomic_alu(&mut self, opcode: u8, is_64bit: bool, src: u8, dst: u8, offset: i32) {
    self.emit1(0xf0); // lock
    self.emit_basic_rex(u8::from(is_64bit), src, dst);
    self.emit1(opcode);
    self.emit_modrm_and_displacement(src, dst, offset);
  }

  /// `lock cmpxchg [dst + offset], src`, which compares against RAX and leaves
  /// the previous value there.
  fn emit_atomic_cmp_exch_with_rax(&mut self, is_64bit: bool, src: u8, dst: u8, offset: i32) {
    self.emit1(0xf0);
    self.emit_basic_rex(u8::from(is_64bit), src, dst);
    self.emit1(0x0f);
    self.emit1(0xb1);
    self.emit_modrm_and_displacement(src, dst, offset);
  }

  /// `xchg [dst + offset], src`, which is implicitly locked.
  fn emit_atomic_exchange(&mut self, is_64bit: bool, src: u8, dst: u8, offset: i32) {
    self.emit1(0xf0);
    self.emit_basic_rex(u8::from(is_64bit), src, dst);
    self.emit1(0x87);
    self.emit_modrm_and_displacement(src, dst, offset);
  }

  /// x86 has no atomic fetch-and-and/or/xor, and no 64-bit fetch-add that also
  /// yields the old value in the right place, so all four are emulated with a
  /// compare-exchange loop.
  fn emit_atomic_fetch_alu(&mut self, is_64bit: bool, opcode: u8, src: u8, dst: u8, offset: i32) {
    // Compare-exchange overwrites RAX. If RAX is the source, keep the original
    // in whichever of R10/R11 is not the destination.
    let actual_src = if src == RAX {
      if dst == R10 {
        R11
      } else {
        R10
      }
    } else {
      src
    };

    if src != RAX {
      self.emit_push(RAX);
    } else {
      self.emit_push(actual_src);
      self.emit_mov(src, actual_src);
    }

    self.emit_load(if is_64bit { S::S64 } else { S::S32 }, dst, RAX, offset);

    let loop_start = self.offset();

    self.emit_mov(RAX, RCX);
    // Always the 64-bit form, even for the 32-bit variants: the compare-exchange
    // below is what narrows the operation, and the high half of RCX is dead.
    self.emit_alu64(opcode, actual_src, RCX);

    self.emit_atomic_cmp_exch_with_rax(is_64bit, RCX, dst, offset);

    // `jne loop_start`, whose displacement is computed from the position of the
    // displacement byte itself.
    self.emit1(0x75);
    let rel = loop_start.wrapping_sub(self.offset()).wrapping_sub(1);
    self.emit1(rel as u8);

    if src != RAX {
      self.emit_mov(RAX, src);
      self.emit_pop(RAX);
    } else {
      self.emit_pop(actual_src);
    }
  }
}

// ---------------------------------------------------------------------------
// Multiply / divide / modulo
// ---------------------------------------------------------------------------

impl Emit<'_, '_, '_> {
  ///
  /// eBPF and x86 disagree about division by zero (eBPF yields 0 for `div` and
  /// the dividend for `mod`; x86 faults) and about `INT_MIN / -1` (eBPF wraps;
  /// x86 faults), so most of what is emitted here is fixing that up.
  fn emit_muldivmod(&mut self, op: u8, src: u8, dst: u8, imm: i32, offset: i16) {
    let alu_op = op & 0xf0;
    let mul = alu_op == 0x20;
    let div = alu_op == 0x30;
    let mod_ = alu_op == 0x90;
    let is64 = (op & cls::MASK) == cls::ALU64;
    let reg = (op & 0x08) == 0x08;
    let is_signed = offset == 1;

    // Short circuit for imm == 0.
    if !reg && imm == 0 {
      if div || mul {
        self.emit_alu32(0x31, dst, dst);
      } else {
        // Modulo by zero yields the dividend, so this is a self-move — which
        // emitted rather than elided.
        self.emit_mov(dst, dst);
      }
      return;
    }

    if dst != RAX {
      self.emit_push(RAX);
    }
    if dst != RDX {
      self.emit_push(RDX);
    }

    // Divisor into RCX.
    if !reg {
      self.emit_load_imm(RCX, imm as i64);
    } else {
      self.emit_mov(src, RCX);
    }

    // Dividend into RAX.
    self.emit_mov(dst, RAX);

    if div || mod_ {
      if is64 {
        self.emit_alu64(0x85, RCX, RCX);
      } else {
        self.emit_alu32(0x85, RCX, RCX);
      }

      if mod_ {
        self.emit_push(RAX);
      }

      self.emit1(0x9c); // pushfq

      // Set the divisor to 1 if it is zero, so the divide does not fault; the
      // saved flags say afterwards whether it was.
      self.emit_load_imm(RDX, 1);
      self.emit1(0x48);
      self.emit1(0x0f);
      self.emit1(0x44);
      self.emit1(0xca); // cmove rcx, rdx

      if is_signed {
        if is64 {
          self.emit1(0x48);
          self.emit1(0x99); // cqo
        } else {
          self.emit1(0x99); // cdq
        }
      } else {
        self.emit_alu32(0x31, RDX, RDX);
      }
    }

    // INT_MIN / -1 faults on x86 but wraps per RFC 9669.
    let mut overflow_jump_source = 0u32;
    if (div || mod_) && is_signed {
      if is64 {
        self.emit1(0x48);
        self.emit1(0x83);
        self.emit1(0xf9);
        self.emit1(0xff); // cmp rcx, -1
      } else {
        self.emit1(0x83);
        self.emit1(0xf9);
        self.emit1(0xff); // cmp ecx, -1
      }
      self.emit1(0x75); // jne
      let jne_source = self.offset();
      self.emit1(0x00);

      if is64 {
        self.emit1(0x49);
        self.emit1(0xbb);
        self.emit8(0x8000_0000_0000_0000); // mov r11, INT64_MIN
        self.emit1(0x4c);
        self.emit1(0x39);
        self.emit1(0xd8); // cmp rax, r11
      } else {
        self.emit1(0x3d);
        self.emit4(0x8000_0000); // cmp eax, INT32_MIN
      }
      self.emit1(0x75); // jne
      let jne2_source = self.offset();
      self.emit1(0x00);

      if div {
        // The result is INT_MIN, which is already in RAX.
      } else {
        self.emit_alu32(0x31, RDX, RDX);
      }
      self.emit1(0xeb); // jmp short, over the divide
      overflow_jump_source = self.offset();
      self.emit1(0x00);

      let here = self.offset();
      self.patch_rel8(jne_source, here);
      self.patch_rel8(jne2_source, here);
    }

    if is64 {
      self.emit_rex(1, 0, 0, 0);
    }

    // /4 = MUL, /6 = DIV, /7 = IDIV.
    let modrm_reg = if mul {
      4
    } else if is_signed {
      7
    } else {
      6
    };
    self.emit_alu32(0xf7, modrm_reg, RCX);

    if (div || mod_) && is_signed && overflow_jump_source != 0 {
      let here = self.offset();
      self.patch_rel8(overflow_jump_source, here);
    }

    if div || mod_ {
      self.emit1(0x9d); // popfq

      if div {
        // Zero flag set means the divisor was zero; substitute the eBPF result.
        self.emit_load_imm(RCX, 0);
        self.emit1(0x48);
        self.emit1(0x0f);
        self.emit1(0x44);
        self.emit1(0xc1); // cmove rax, rcx
      } else {
        self.emit_pop(RCX);
        self.emit1(0x48);
        self.emit1(0x0f);
        self.emit1(0x44);
        self.emit1(0xd1); // cmove rdx, rcx
      }
    }

    if dst != RDX {
      if mod_ {
        self.emit_mov(RDX, dst);
      }
      self.emit_pop(RDX);
    }
    if dst != RAX {
      if div || mul {
        self.emit_mov(RAX, dst);
      }
      self.emit_pop(RAX);
    }
  }

  /// Back-patches a one-byte relative displacement written earlier.
  /// Writing the buffer directly would be out of bounds when the
  /// emit that reserved the byte had already run out of buffer. Going through
  /// `patch_bytes` bounds-checks; the guard on `ok()` keeps the emitted bytes
  /// identical in every case where the translation actually succeeds.
  fn patch_rel8(&mut self, at: u32, target: u32) {
    if !self.st.ok() {
      return;
    }
    let rel = target.wrapping_sub(at).wrapping_sub(1);
    self.st.patch_bytes(at, rel as u64, 1);
  }
}

// ---------------------------------------------------------------------------
// Trailer: retpoline, dispatcher slot
// ---------------------------------------------------------------------------

impl Emit<'_, '_, '_> {
  /// `call retpoline`, whose displacement the trailer fills in.
  fn emit_retpoline_call(&mut self) {
    self.emit1(0xe8);
    let at = self.offset();
    self.retpoline_calls.push(at);
    self.emit4(0);
  }

  /// The retpoline `call *%rax` stand-in, adapted from Intel's guidance.
  fn emit_retpoline(&mut self) -> u32 {
    let retpoline_target = self.offset();
    let label1_call_offset = self.emit_call(PatchTarget::EbpfPc { pc: 0, near: false });

    let capture_ret_spec = self.offset();
    self.emit_pause();
    self.emit_jmp(PatchTarget::JitOffset {
      offset: capture_ret_spec,
      near: false,
    });

    // label1: mov [rsp], rax ; ret
    let label1 = self.offset();
    self.emit1(0x48);
    self.emit1(0x89);
    self.emit1(0x04);
    self.emit1(0x24);
    self.emit_ret();

    self.st.retarget_jumps(
      label1_call_offset,
      PatchTarget::JitOffset {
        offset: label1,
        near: false,
      },
    );

    retpoline_target
  }

  /// The eight bytes holding the external dispatcher's address.
  fn emit_dispatched_external_helper_address(&mut self) -> u32 {
    let at = self.offset();
    let addr = self.cfg.dispatcher.map_or(0u64, |f| f as usize as u64);
    self.emit8(addr);
    at
  }
}

// ---------------------------------------------------------------------------
// Relocation
// ---------------------------------------------------------------------------

impl Emit<'_, '_, '_> {
  /// Writes every deferred displacement. Returns false where one does not
  /// encode, which the caller turns into a failure.
  fn resolve(&mut self) -> bool {
    let jumps = std::mem::take(&mut self.st.jumps);
    for jump in &jumps {
      let (target_loc, is_near) = match jump.target {
        PatchTarget::EbpfPc { pc, near } => (self.pc_loc(pc), near),
        // Both fields were once held in one struct, preferring the JIT offset only
        // when it is non-zero, falling back to `pc_locs[ebpf_target_pc]`. Every
        // site that sets a JIT offset leaves the eBPF pc at 0, so a zero JIT
        // offset means `pc_locs[0]`.
        PatchTarget::JitOffset { offset, near } => {
          if offset != 0 {
            (offset, near)
          } else {
            (self.pc_loc(0), near)
          }
        }
      };

      if is_near {
        let rel = target_loc as i64 - (jump.offset_loc as i64 + 1);
        if !(-128..128).contains(&rel) {
          return false;
        }
        self
          .st
          .patch_bytes(jump.offset_loc, rel as i8 as u8 as u64, 1);
      } else {
        let rel = target_loc.wrapping_sub(jump.offset_loc.wrapping_add(4));
        self.st.patch_bytes(jump.offset_loc, rel as u64, 4);
      }
    }
    self.st.jumps = jumps;

    for at in std::mem::take(&mut self.retpoline_calls) {
      let rel = self.retpoline_loc.wrapping_sub(at.wrapping_add(4));
      self.st.patch_bytes(at, rel as u64, 4);
    }

    let loads = std::mem::take(&mut self.st.loads);
    for at in &loads {
      let rel = self.st.dispatcher_loc.wrapping_sub(at.wrapping_add(4));
      self.st.patch_bytes(*at, rel as u64, 4);
    }
    self.st.loads = loads;

    true
  }

  fn pc_loc(&self, pc: u32) -> u32 {
    self.st.pc_locs.get(pc as usize).copied().unwrap_or(0)
  }
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/// eBPF registers `inst` may overwrite.
/// Naming too many registers only ends access groups early; naming too few
/// would let a group keep addressing a base that has changed, so every class
/// that writes anything is listed.
fn written_registers_mask(inst: Insn) -> u16 {
  match inst.opcode & cls::MASK {
    cls::LD | cls::LDX | cls::ALU | cls::ALU64 => 1u16 << inst.dst,
    cls::STX => {
      // A fetching atomic writes its source register, and CMPXCHG writes R0.
      // Plain stores write nothing.
      if (inst.opcode & 0xe0) == 0xc0 {
        (1u16 << inst.src) | 1
      } else {
        0
      }
    }
    cls::JMP | cls::JMP32 => {
      // A call clobbers R0-R5 either way; the group ends at the call anyway.
      if inst.opcode == opcode::CALL {
        0x3f
      } else {
        0
      }
    }
    _ => 0,
  }
}

/// True when `inst` reads its source register as a *value* rather than as a
/// memory base or a mode selector.
/// `STX` is deliberately absent even though it does read a value source:
/// `emit_masked_store` handles it itself, because the address computation it
/// performs first would clobber the scratch register the value would sit in.
fn reads_src_as_value(inst: Insn) -> bool {
  match inst.opcode & cls::MASK {
    cls::ALU | cls::ALU64 => (inst.opcode & 0x08) == 0x08,
    cls::JMP | cls::JMP32 => {
      // CALL and EXIT put a mode selector in the source field rather than a
      // register number, and JA has no source operand at all.
      if inst.opcode == opcode::CALL
        || inst.opcode == opcode::EXIT
        || inst.opcode == opcode::JA
        || inst.opcode == opcode::JA32
      {
        return false;
      }
      (inst.opcode & 0x08) == 0x08
    }
    _ => false,
  }
}

impl Emit<'_, '_, '_> {
  fn run(&mut self) -> Result<usize, TranslateError> {
    let insns = self.t.insns();
    let num_insts = insns.len();
    let start_pc = self.inputs.start_pc;
    let end_pc = self.inputs.end_pc;

    if end_pc > num_insts || start_pc >= end_pc {
      return Err(TranslateError::Failed(format!(
        "Invalid function range [{start_pc}, {end_pc})"
      )));
    }

    // In function-granular mode the emitted prologue/epilogue assume the range
    // is exactly one local function: the prologue is only emitted at a function
    // entry, but the EXIT/epilogue always pops a frame. A start that is not an
    // entry, or an end that splits a function, would unbalance the host stack.
    if !(start_pc == 0 || self.t.is_local_func_entry(start_pc)) {
      return Err(TranslateError::Failed(format!(
        "Function range start {start_pc} is not a local function entry"
      )));
    }
    if end_pc != num_insts && !self.t.is_local_func_entry(end_pc) {
      return Err(TranslateError::Failed(format!(
        "Function range end {end_pc} is not a local function boundary"
      )));
    }

    // There is no whole-program prologue: the embedder's own entry code
    // establishes the frame, and each function's prologue is emitted at its
    // entry below.

    self.mark_barriers(start_pc, end_pc, num_insts);

    if let Some(msg) = self.emit_instructions(start_pc, end_pc) {
      return Err(TranslateError::Failed(msg));
    }

    if !self.st.ok() {
      return Err(self.status_error());
    }

    // No shared exit stub: every `EXIT` emits its own epilogue inline, and with
    // uBPF's unwind helper gone nothing else branches to one.
    self.retpoline_loc = self.emit_retpoline();
    self.st.dispatcher_loc = self.emit_dispatched_external_helper_address();

    // Everything above is emitted after the per-instruction error check, so an
    // overflow here would otherwise be reported as success. That is not merely
    // untidy: a patch site whose location was recorded just before the overflow
    // is still in the jump table, and `resolve` would write four bytes at it.
    if !self.st.ok() {
      return Err(if self.st.status == Progress::NotEnoughSpace {
        TranslateError::OutOfSpace
      } else {
        TranslateError::Failed("Failure to emit the function epilogue".to_string())
      });
    }

    if !self.resolve() {
      return Err(TranslateError::Failed(
        "Could not patch the relative addresses in the JIT'd code".to_string(),
      ));
    }

    Ok(self.offset() as usize)
  }

  /// Turns the recorded [`Progress`] into the error reported for it.
  fn status_error(&self) -> TranslateError {
    match self.st.status {
      Progress::NotEnoughSpace => TranslateError::OutOfSpace,
      // These two carry a message from the detecting site, because it names the
      // instruction. The lazy local-call guard sets only the status, so this
      // provides a fallback for it.
      Progress::UnexpectedInstruction => {
        TranslateError::Failed(self.errmsg.clone().unwrap_or_else(|| {
          "Unexpected instruction or missing local-call resolver during JIT compilation".to_string()
        }))
      }
      Progress::UnknownInstruction => {
        TranslateError::Failed(self.errmsg.clone().unwrap_or_default())
      }
      other => other
        .into_error(crate::jit::Target::X86_64)
        .unwrap_or(TranslateError::Failed(String::new())),
    }
  }

  /// Marks every instruction a branch can land on, which closes any access
  /// group open across it.
  fn mark_barriers(&mut self, start_pc: usize, end_pc: usize, num_insts: usize) {
    for i in start_pc..end_pc {
      let inst = self.t.insns()[i];

      // A local function entry is reached by `call`, never by falling into it,
      // so a group must not span one.
      if self.t.is_local_func_entry(i) {
        self.st.mark_barrier(i);
      }

      let class = inst.opcode & cls::MASK;
      if class != cls::JMP && class != cls::JMP32 {
        continue;
      }
      // Nothing falls through an EXIT, an unconditional jump or a call, so
      // whatever follows is entered from somewhere else. The bound is written
      // `group_barrier` has `num_insts + 1` slots, so the
      // instruction one past the end has one too.
      #[allow(clippy::int_plus_one)]
      if i + 1 <= num_insts {
        self.st.mark_barrier(i + 1);
      }
      if inst.opcode == opcode::CALL || inst.opcode == opcode::EXIT {
        continue;
      }
      let delta = if inst.opcode == opcode::JA32 {
        inst.imm as i64
      } else {
        inst.offset as i64
      };
      let target = i as i64 + 1 + delta;
      if target >= 0 && target <= num_insts as i64 {
        self.st.mark_barrier(target as usize);
      }
    }
  }

  /// The main loop. Returns `Some(message)` for the paths that report
  /// immediately with an error rather than recording a status and breaking.
  fn emit_instructions(&mut self, start_pc: usize, end_pc: usize) -> Option<String> {
    let mut i = start_pc;
    while i < end_pc {
      if !self.st.ok() {
        break;
      }

      let inst = self.t.insns()[i];

      // A branch can land here, so no group can span it.
      if self.st.is_barrier(i) {
        self.st.close_group();
      }

      let dst = map_register(inst.dst);
      let mut src = map_register(inst.src);

      let region_hint = self.inputs.hint(i);

      // Use i64 throughout to avoid signed overflow with large immediates.
      let target_pc_64 = if inst.opcode == opcode::JA32 {
        i as i64 + inst.imm as i64 + 1
      } else {
        i as i64 + inst.offset as i64 + 1
      };
      let target_pc = target_pc_64 as u32;

      // A relative branch is resolved against `pc_locs[target_pc]`, and in
      // function-granular mode only entries inside the range are ever written,
      // so a target outside it would silently retarget the branch to the top of
      // the emitted buffer.
      let branch_cls = inst.opcode & cls::MASK;
      if (branch_cls == cls::JMP || branch_cls == cls::JMP32)
        && inst.opcode != opcode::CALL
        && inst.opcode != opcode::EXIT
        && ((target_pc as usize) < start_pc || target_pc as usize >= end_pc)
      {
        self.st.fail(Progress::UnexpectedInstruction);
        self.errmsg = Some(format!(
          "jump target {target_pc} at PC {i} is outside the translation range [{start_pc}, {end_pc})"
        ));
        break;
      }

      let tgt = PatchTarget::EbpfPc {
        pc: target_pc,
        near: false,
      };

      // If the previous instruction could fall through to this one and this one
      // starts a local function, there has to be a way to jump around the code
      // that manipulates the host stack.
      let mut fallthrough_jump_source = None;
      if i != start_pc && self.t.is_local_func_entry(i) {
        let prev = self.t.insns()[i - 1];
        if prev.has_fallthrough() {
          fallthrough_jump_source = Some(self.emit_jmp(PatchTarget::EbpfPc { pc: 0, near: true }));
        }
      }

      // The top of the host stack always holds the guest stack usage of the
      // currently-executing eBPF function, so a function entry pushes its own.
      // Adjusting by 8 keeps the 16-byte alignment, because the `call` that got
      // here already pushed a return address.
      if i == 0 || self.t.is_local_func_entry(i) {
        let stack_usage = self.t.stack_usage_for(i);
        self.emit_alu64_imm32(0x81, 5, RSP, 8);
        // `mov qword [rsp], stack_usage`, whose ModRM+SIB pair for an `[rsp]`
        // base is emitted literally.
        self.emit1(0x48);
        self.emit1(0xC7);
        self.emit1(0x04);
        self.emit1(0x24);
        self.emit4(stack_usage as u32);
      }

      if let Some(source) = fallthrough_jump_source {
        let here = self.offset();
        self.st.retarget_jumps(
          source,
          PatchTarget::JitOffset {
            offset: here,
            near: true,
          },
        );
      }
      self.st.pc_locs[i] = self.offset();

      // Under a native frame base the register mapped to eBPF R10 holds a host
      // address, so an instruction reading R10 as a value must see the guest
      // one. This has to come *after* `pc_locs[i]` is recorded: a branch landing
      // here has to run the materialisation too.
      if self.cfg.native_frame_base_active()
        && inst.src == crate::jit::isa::REG_FP
        && reads_src_as_value(inst)
      {
        self.emit_guest_frame_pointer(RCX);
        src = RCX;
      }

      if let Some(msg) = self.emit_one(i, inst, dst, src, region_hint, tgt, &mut i) {
        return Some(msg);
      }

      // A 32-bit ALU instruction zero-extends its result. The `end` family is
      // excluded, which is why `le`/`be` do their own truncation.
      if (inst.opcode & cls::MASK) == cls::ALU && (inst.opcode & 0xf0) != 0xd0 {
        self.emit_truncate_u32(dst);
      }

      // After the instruction has used its operands, note what it overwrote: an
      // access whose destination is its own base is still valid, but nothing
      // addressing that base afterwards is.
      let mask = written_registers_mask(inst);
      for reg in 0..16u8 {
        if mask & (1u16 << reg) != 0 {
          self.st.note_register_written(reg);
        }
      }

      i += 1;
    }
    None
  }

  /// One instruction. `pc_cursor` is the driver's loop variable, which `lddw`
  /// advances past its second slot, which is data rather than an instruction.
  #[allow(clippy::too_many_arguments)]
  fn emit_one(
    &mut self,
    pc: usize,
    inst: Insn,
    dst: u8,
    src: u8,
    region_hint: u8,
    tgt: PatchTarget,
    pc_cursor: &mut usize,
  ) -> Option<String> {
    let op = match inst.op() {
      Some(op) => op,
      None => {
        self.st.fail(Progress::UnknownInstruction);
        self.errmsg = Some(format!(
          "Unknown instruction at PC {pc}: opcode {:02x}",
          inst.opcode
        ));
        return None;
      }
    };

    match op {
      // ------------------------------------------------------------------
      // ALU
      // ------------------------------------------------------------------
      Op::Alu {
        width,
        op: alu,
        source,
      } => {
        let w64 = width == AluWidth::W64;
        match alu {
          AluOp::Mul | AluOp::Div | AluOp::Mod => {
            self.emit_muldivmod(inst.opcode, src, dst, inst.imm, inst.offset);
          }
          AluOp::Neg => {
            if w64 {
              self.emit_alu64(0xf7, 3, dst);
            } else {
              self.emit_alu32(0xf7, 3, dst);
            }
          }
          AluOp::Mov => match (w64, source) {
            (false, Source::Imm) => self.emit_alu32_imm32(0xc7, 0, dst, inst.imm),
            (true, Source::Imm) => self.emit_load_imm(dst, inst.imm as i64),
            (false, Source::Reg) => {
              // MOVSX flavours selected by the offset field (RFC 9669).
              if inst.offset == 8 {
                // The explicit REX is what makes a byte source name SIL/DIL/SPL/
                // BPL rather than AH/CH/DH/BH, so it is emitted even when no
                // high-register bit is set.
                self.emit_rex(0, u8::from(dst & 8 != 0), 0, u8::from(src & 8 != 0));
                self.emit1(0x0f);
                self.emit1(0xbe);
                self.emit_modrm_reg2reg(dst, src);
              } else if inst.offset == 16 {
                self.emit_basic_rex(0, dst, src);
                self.emit1(0x0f);
                self.emit1(0xbf);
                self.emit_modrm_reg2reg(dst, src);
              } else {
                self.emit_mov(src, dst);
              }
            }
            (true, Source::Reg) => {
              if inst.offset == 8 {
                self.emit_basic_rex(1, dst, src);
                self.emit1(0x0f);
                self.emit1(0xbe);
                self.emit_modrm_reg2reg(dst, src);
              } else if inst.offset == 16 {
                self.emit_basic_rex(1, dst, src);
                self.emit1(0x0f);
                self.emit1(0xbf);
                self.emit_modrm_reg2reg(dst, src);
              } else if inst.offset == 32 {
                self.emit_basic_rex(1, dst, src);
                self.emit1(0x63);
                self.emit_modrm_reg2reg(dst, src);
              } else {
                self.emit_mov(src, dst);
              }
            }
          },
          AluOp::Lsh | AluOp::Rsh | AluOp::Arsh => {
            let ext = match alu {
              AluOp::Lsh => 4,
              AluOp::Rsh => 5,
              _ => 7,
            };
            match source {
              Source::Imm => {
                if w64 {
                  self.emit_alu64_imm8(0xc1, ext, dst, inst.imm);
                } else {
                  self.emit_alu32_imm8(0xc1, ext, dst, inst.imm);
                }
              }
              Source::Reg => {
                self.emit_mov(src, RCX);
                if w64 {
                  self.emit_alu64(0xd3, ext, dst);
                } else {
                  self.emit_alu32(0xd3, ext, dst);
                }
              }
            }
          }
          AluOp::Add | AluOp::Sub | AluOp::Or | AluOp::And | AluOp::Xor => {
            // (immediate extension, register-form opcode)
            let (ext, reg_op) = match alu {
              AluOp::Add => (0, 0x01),
              AluOp::Sub => (5, 0x29),
              AluOp::Or => (1, 0x09),
              AluOp::And => (4, 0x21),
              _ => (6, 0x31),
            };
            match source {
              Source::Imm => {
                if w64 {
                  self.emit_alu64_imm32(0x81, ext, dst, inst.imm);
                } else {
                  self.emit_alu32_imm32(0x81, ext, dst, inst.imm);
                }
              }
              Source::Reg => {
                if w64 {
                  self.emit_alu64(reg_op, src, dst);
                } else {
                  self.emit_alu32(reg_op, src, dst);
                }
              }
            }
          }
        }
      }

      // ------------------------------------------------------------------
      // Byte order
      // ------------------------------------------------------------------
      Op::End(EndKind::Le) => {
        // x86 is already little-endian, so this is a truncation and nothing
        // else. An immediate other than 16 or 32 emits nothing at all.
        if inst.imm == 16 {
          self.emit_alu32_imm32(0x81, 4, dst, 0xffff);
        } else if inst.imm == 32 {
          self.emit_alu32_imm32(0x81, 4, dst, 0xffff_ffffu32 as i32);
        }
      }
      Op::End(EndKind::Be) => {
        if inst.imm == 16 {
          self.emit1(0x66); // 16-bit override
          self.emit_alu32_imm8(0xc1, 0, dst, 8); // rol
          self.emit_alu32_imm32(0x81, 4, dst, 0xffff);
        } else if inst.imm == 32 || inst.imm == 64 {
          self.emit_basic_rex(u8::from(inst.imm == 64), 0, dst);
          self.emit1(0x0f);
          self.emit1(0xc8 | (dst & 7));
        }
      }
      Op::End(EndKind::Bswap) => {
        if inst.imm == 16 {
          self.emit1(0x66);
          self.emit_alu32_imm8(0xc1, 0, dst, 8);
          self.emit_alu64_imm32(0x81, 4, dst, 0xffff);
        } else if inst.imm == 32 {
          self.emit_basic_rex(0, 0, dst);
          self.emit1(0x0f);
          self.emit1(0xc8 | (dst & 7));
          // Zero-extend to 64 bits.
          self.emit_alu32(0x89, dst, dst);
        } else if inst.imm == 64 {
          self.emit_basic_rex(1, 0, dst);
          self.emit1(0x0f);
          self.emit1(0xc8 | (dst & 7));
        }
      }

      // ------------------------------------------------------------------
      // Control flow
      // ------------------------------------------------------------------
      Op::Ja { .. } => {
        self.emit_jmp(tgt);
      }
      Op::Jmp {
        width,
        op: cond,
        source,
      } => {
        let w64 = width == AluWidth::W64;
        let code = match cond {
          JmpOp::Eq => 0x84,
          JmpOp::Gt => 0x87,
          JmpOp::Ge => 0x83,
          JmpOp::Lt => 0x82,
          JmpOp::Le => 0x86,
          JmpOp::Set => 0x85,
          JmpOp::Ne => 0x85,
          JmpOp::Sgt => 0x8f,
          JmpOp::Sge => 0x8d,
          JmpOp::Slt => 0x8c,
          JmpOp::Sle => 0x8e,
        };
        match (cond, source) {
          (JmpOp::Set, Source::Imm) => {
            if w64 {
              self.emit_alu64_imm32(0xf7, 0, dst, inst.imm);
            } else {
              self.emit_alu32_imm32(0xf7, 0, dst, inst.imm);
            }
          }
          (JmpOp::Set, Source::Reg) => {
            if w64 {
              self.emit_alu64(0x85, src, dst);
            } else {
              self.emit_alu32(0x85, src, dst);
            }
          }
          (_, Source::Imm) => {
            if w64 {
              self.emit_cmp_imm32(dst, inst.imm);
            } else {
              self.emit_cmp32_imm32(dst, inst.imm);
            }
          }
          (_, Source::Reg) => {
            if w64 {
              self.emit_cmp(src, dst);
            } else {
              self.emit_cmp32(src, dst);
            }
          }
        }
        self.emit_jcc(code, tgt);
      }

      Op::Call => {
        // RCX is reserved for shifts, so the register mapped to eBPF R4 has to
        // move out of the way before the host call.
        if inst.src == 0 {
          self.emit_mov(RCX_ALT, RCX);
          self.emit_dispatched_external_helper_call(inst.imm as u32);
        } else if inst.src == 1 {
          // Local calls are always compiled lazily; uBPF's eager
          // `emit_local_call` is not ported.
          self.emit_lazy_local_call(pc);
        }
        // A source field other than 0 or 1 emits nothing at all. Unreachable:
        // the operand filter bounds `call`'s source to 0..=1.
      }

      Op::Exit => {
        // Pop the guest stack usage this function pushed, then return.
        self.emit_alu64_imm32(0x81, 0, RSP, 8);
        self.emit_ret();
      }

      // ------------------------------------------------------------------
      // Memory
      // ------------------------------------------------------------------
      Op::Load { width, signed } => {
        let size = S::from_width(width);
        if signed {
          self.emit_masked_load_sx(size, src, dst, inst.offset as i32, region_hint, pc);
        } else {
          self.emit_masked_load(size, src, dst, inst.offset as i32, region_hint, pc);
        }
      }
      Op::StoreImm { width } => {
        self.emit_masked_store_imm32(
          S::from_width(width),
          dst,
          inst.offset as i32,
          inst.imm,
          region_hint,
          pc,
        );
      }
      Op::StoreReg { width } => {
        self.emit_masked_store(
          S::from_width(width),
          src,
          dst,
          inst.offset as i32,
          region_hint,
          pc,
        );
      }

      Op::LoadImm64 => {
        // The second slot is not an instruction but the high half of the
        // immediate, so the driver's cursor skips it — the advance inside the
        // `case`, which the `for` then increments again.
        //
        // A `lddw` in the last slot would send the high-half fetch
        // one past the end of the program; the validator refuses that, so the
        // zero fallback below is unreachable rather than a behaviour change.
        *pc_cursor += 1;
        let second = self.t.insns().get(*pc_cursor).copied().unwrap_or(Insn {
          opcode: 0,
          dst: 0,
          src: 0,
          offset: 0,
          imm: 0,
        });
        let imm = (inst.imm as u32 as u64) | ((second.imm as u32 as u64) << 32);
        self.emit_load_imm(dst, imm as i64);
      }

      Op::Atomic { width, .. } => {
        // The atomic *selector* is not in the opcode — it is the immediate's
        // high nibble, with the fetch flag in its low bit. `Op::from_opcode`
        // therefore cannot fill it in, and `Insn::op_with_imm` is what does,
        // masking the immediate's high nibble
        // does. That masking is load-bearing: `imm = 0x02` names a plain atomic
        // add and `imm = 0xe0` an exchange without the fetch flag, and the
        // validator's filter for 32-bit atomics lets both through.
        let is64 = width == Width::DW;
        let mut atomic_dst = dst;
        let mut atomic_offset = inst.offset as i32;
        if self.cfg.pointer_mask != 0 {
          // The hint is forced to UNKNOWN, but `store` is true, so this is a
          // stack-region check regardless: an atomic is a write.
          self.emit_masked_address_with_offset(
            dst,
            R11,
            RCX,
            inst.offset as i32,
            if is64 { 8 } else { 4 },
            true,
            abi::region::UNKNOWN,
          );
          atomic_dst = R11;
          atomic_offset = 0;
        }

        let (selector, fetch) = match inst.op_with_imm() {
          Some(Op::Atomic { op, fetch, .. }) => (op, fetch),
          _ => {
            // Returns immediately here, skipping the epilogue entirely.
            return Some(format!(
              "Error: unknown atomic opcode {} at PC {pc}\n",
              inst.imm
            ));
          }
        };

        match selector {
          AtomicOp::Add | AtomicOp::Or | AtomicOp::And | AtomicOp::Xor => {
            let x64_op = match selector {
              AtomicOp::Add => X64_ALU_ADD,
              AtomicOp::Or => X64_ALU_OR,
              AtomicOp::And => X64_ALU_AND,
              _ => X64_ALU_XOR,
            };
            if fetch {
              self.emit_atomic_fetch_alu(is64, x64_op, src, atomic_dst, atomic_offset);
            } else {
              self.emit_atomic_alu(x64_op, is64, src, atomic_dst, atomic_offset);
            }
          }
          // The fetch flag is ignored for these two: both always yield the
          // previous value, one in the source register and one in R0.
          AtomicOp::Xchg => {
            self.emit_atomic_exchange(is64, src, atomic_dst, atomic_offset);
            if !is64 {
              self.emit_truncate_u32(src);
            }
          }
          AtomicOp::Cmpxchg => {
            self.emit_atomic_cmp_exch_with_rax(is64, src, atomic_dst, atomic_offset);
            if !is64 {
              self.emit_truncate_u32(map_register(0));
            }
          }
        }
      }
    }

    None
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use std::sync::Arc;

  use crate::jit::golden;
  use crate::jit::isa::{alu, jmp, mode, opcode, size, src as srcbit, Insn};
  use crate::jit::{Dispatcher, LocalCallResolver, Target};

  // -----------------------------------------------------------------------
  // Instructions
  // -----------------------------------------------------------------------

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

  /// `mov64 dst, imm`
  fn movi(dst: u8, imm: i32) -> Insn {
    insn(cls::ALU64 | alu::MOV, dst, 0, 0, imm)
  }

  // -----------------------------------------------------------------------
  // Configurations
  // -----------------------------------------------------------------------

  /// Stand-in addresses for the helper dispatcher and the local-call resolver.
  /// Both are materialised as immediates in the emitted code: the dispatcher's
  /// address is parked in the trailer, and the lazy local-call sequence loads
  /// the resolver's into RAX. Whatever address a configuration carries
  /// therefore ends up in the bytes a golden records.
  /// That rules out pointing them at real functions. A function item's address
  /// is only fixed *within* one run of a position-independent executable — the
  /// loader picks a different base every time — so a golden holding one would
  /// churn on every run. These are fixed sentinels instead. Nothing here
  /// executes translated code, so they are never called, and only two things
  /// about them matter: that they are non-null, and that they are the same on
  /// every run.
  const DISPATCHER_ADDRESS: usize = 0x0000_7f00_d15b_a000;
  const RESOLVER_ADDRESS: usize = 0x0000_7f00_0e50_1000;

  fn dispatcher() -> Dispatcher {
    // SAFETY: never called. The value is materialised as an immediate and
    // compared as bytes, which is all any test here does with it.
    unsafe { std::mem::transmute::<usize, Dispatcher>(DISPATCHER_ADDRESS) }
  }

  fn local_call_resolver() -> LocalCallResolver {
    // SAFETY: as above.
    unsafe { std::mem::transmute::<usize, LocalCallResolver>(RESOLVER_ADDRESS) }
  }

  /// Accepts every helper index, so that helper-call emission is exercised
  /// rather than refused at load time.
  /// Unlike the two addresses above, this one really is called — the validator
  /// asks it whether a helper index exists — so it has to be a real function.
  /// Its address never reaches the emitted code.
  unsafe extern "C" fn accept_every_helper(_idx: u32, _vm: *const std::ffi::c_void) -> bool {
    true
  }

  /// The configuration every sweep entry is built from.
  fn base_config(target: Target) -> Config {
    Config {
      target,
      dispatcher: Some(dispatcher()),
      dispatcher_validate: Some(accept_every_helper),
      local_call_resolver: Some(local_call_resolver()),
      ..Default::default()
    }
  }

  /// The configuration sweep every test below runs over.
  /// The emitted code depends on the pointer cage, the native frame base, the
  /// frame constants and the region hints, and those features *interact* —
  /// which is exactly where the emitter is hardest to get right. Sweeping them
  /// is not optional.
  fn sweep(target: Target) -> Vec<(&'static str, Config)> {
    let base = base_config(target);
    vec![
      (
        "no cage",
        Config {
          pointer_mask: 0,
          pointer_offset: 0,
          ..base.clone()
        },
      ),
      (
        "cage only",
        Config {
          pointer_mask: 0x0fff_ffff,
          pointer_offset: 0x1_0000_0000,
          ..base.clone()
        },
      ),
      (
        "cage + native frame base",
        Config {
          pointer_mask: 0x0fff_ffff,
          pointer_offset: 0x1_0000_0000,
          native_frame_base: true,
          ..base.clone()
        },
      ),
      (
        "cage + frame constants",
        Config {
          pointer_mask: 0x0fff_ffff,
          pointer_offset: 0x1_0000_0000,
          frame_constants: true,
          ..base.clone()
        },
      ),
      (
        // What `async-ebpf` actually runs.
        "production",
        Config {
          pointer_mask: 0x0fff_ffff,
          pointer_offset: 0x1_0000_0000,
          native_frame_base: true,
          frame_constants: true,
          ..base
        },
      ),
    ]
  }

  /// The one configuration `async-ebpf` actually runs.
  fn production_config() -> Config {
    sweep(Target::X86_64)
      .into_iter()
      .find(|(name, _)| *name == "production")
      .expect("the sweep has a production configuration")
      .1
  }

  /// A sweep entry's name, as the label a golden is filed under.
  /// The label is part of the golden key, so renaming a sweep entry rewrites
  /// every golden it owns. The names are fixed for that reason.
  fn slug(name: &str) -> String {
    let mut out = String::new();
    let mut pending = false;
    for c in name.chars() {
      if c.is_ascii_alphanumeric() {
        if pending && !out.is_empty() {
          out.push('-');
        }
        out.push(c.to_ascii_lowercase());
        pending = false;
      } else {
        pending = true;
      }
    }
    out
  }

  /// [`TranslationInputs`] covering a whole program, with no hints or plan.
  fn plain_inputs(num_insns: usize) -> TranslationInputs<'static> {
    TranslationInputs {
      hints: &[],
      plan: &[],
      resolver_ids: &[],
      start_pc: 0,
      end_pc: num_insns,
    }
  }

  /// The buffer every check translates into: comfortably more than anything
  /// here needs, so that a golden records a whole function rather than an
  /// out-of-space refusal.
  const CAPACITY: usize = 262_144;

  // -----------------------------------------------------------------------
  // Goldens
  // -----------------------------------------------------------------------

  /// Writes back any golden file this process modified.
  /// The test runner gives each test its own thread and runs nothing at process
  /// exit, so the write hangs off a thread-local destructor: a thread that
  /// touched a golden flushes when it finishes. [`golden::flush`] does nothing
  /// unless a file actually changed, which outside a recording run it never
  /// does.
  /// The guard has to be armed on *every* path that can record something, not
  /// just the common one. The store is process-wide, so a thread that records
  /// the last entry and then exits without a destructor leaves that entry
  /// unwritten unless some other armed thread happens to outlive it — which is
  /// a race, and one that silently drops exactly the entries a recording run
  /// exists to produce.
  struct FlushGoldens;

  impl Drop for FlushGoldens {
    fn drop(&mut self) {
      golden::flush();
    }
  }

  thread_local! {
    static FLUSH_GOLDENS: FlushGoldens = const { FlushGoldens };
  }

  fn arm_flush() {
    FLUSH_GOLDENS.with(|_| ());
  }

  /// Checks one translation against its golden, or records it.
  /// Everything here goes through this rather than calling [`golden::check`]
  /// directly, so that the flush guard is armed on every recording path.
  fn check_one(
    label: &str,
    config: &Config,
    code: &[u8],
    inputs: &TranslationInputs<'_>,
    capacity: usize,
  ) -> bool {
    arm_flush();
    golden::check(label, config, code, inputs, capacity)
  }

  /// Runs one program through the whole x86_64 configuration sweep, checking
  /// each configuration's output against its golden — or recording it.
  /// Returns whether any configuration actually produced code, which
  /// [`check_prog`] uses to reject a test that has quietly degraded into "every
  /// configuration refused the program".
  #[track_caller]
  fn check(code: &[u8], inputs: &TranslationInputs<'_>) -> bool {
    let mut emitted = false;
    for (name, config) in sweep(Target::X86_64) {
      emitted |= check_one(&slug(name), &config, code, inputs, CAPACITY);
    }
    emitted
  }

  /// A whole test's worth of cases, rolled up into one golden line.
  /// A test that walks a cross-product — every opcode against every operand
  /// shape, every base register against every destination, each of those under
  /// six configurations — would otherwise record tens of thousands of entries.
  /// That is neither reviewable nor reasonable to keep in the repository, and
  /// it drowns the cases a reader might actually want to read the bytes of.
  /// The digest keeps the whole cross-product as a single line. It still fails
  /// when any case changes; what it gives up is naming *which* case, which is
  /// why the small canonical programs keep a golden apiece instead.
  struct Sweep {
    digest: golden::SweepDigest,
    translated: usize,
    cases: usize,
  }

  impl Sweep {
    fn new() -> Self {
      arm_flush();
      Self {
        digest: golden::SweepDigest::new(),
        translated: 0,
        cases: 0,
      }
    }

    /// Runs one program through the whole configuration sweep, folding every
    /// configuration's outcome into the digest.
    /// Returns whether any configuration produced code, so a caller can still
    /// assert it is exercising the emitter rather than agreeing about a
    /// refusal.
    fn check(&mut self, code: &[u8], inputs: &TranslationInputs<'_>) -> bool {
      let mut emitted = false;
      for (_, config) in sweep(Target::X86_64) {
        let out = emit_outcome(&config, code, inputs);
        emitted |= out.is_ok();
        self.digest.add(&out);
      }
      self.cases += 1;
      if emitted {
        self.translated += 1;
      }
      emitted
    }

    /// As [`Sweep::check`], and additionally insists the program really was
    /// translated.
    /// Without this a test whose program the validator happens to refuse would
    /// still pass: a refusal folds into the digest just as an emission does,
    /// and a suite that agrees with itself about refusing everything tests
    /// nothing.
    #[track_caller]
    fn check_prog(&mut self, insns: &[Insn]) {
      let code = Insn::encode_all(insns);
      let inputs = plain_inputs(insns.len());
      assert!(
        self.check(&code, &inputs),
        "no configuration translated this program; it is being rejected rather \
         than exercising the emitter:\n{insns:#?}\n{}",
        refusal_report(&code, &inputs)
      );
    }

    /// Programs where some configuration produced code, and programs tried.
    fn translated(&self) -> usize {
      self.translated
    }

    fn cases(&self) -> usize {
      self.cases
    }

    /// Records or checks the rolled-up digest.
    fn finish(self, label: &str) {
      self.digest.finish(label, Target::X86_64);
    }

    /// As [`Sweep::finish`], for a sweep that ignores each case's outcome as it
    /// goes: without a per-case assertion, something has to insist the sweep
    /// reached the emitter at all rather than being refused throughout.
    fn finish_exercised(self, label: &str) {
      assert!(
        self.translated > 0,
        "not one of the {} programs in `{label}` translated under any \
         configuration; the sweep is recording refusals rather than code",
        self.cases
      );
      self.digest.finish(label, Target::X86_64);
    }
  }

  /// Why no configuration translated a program, recomputed for the assertion
  /// message. Only ever called on the failing path.
  fn refusal_report(code: &[u8], inputs: &TranslationInputs<'_>) -> String {
    sweep(Target::X86_64)
      .into_iter()
      .map(|(name, config)| {
        let what = match Translator::load(Arc::new(config), code) {
          Err(e) => format!("refused at load: {e}"),
          Ok(t) => {
            let mut buf = vec![0u8; CAPACITY];
            match t.translate_range(inputs, &mut buf) {
              Ok(len) => format!("translated {len} bytes"),
              Err(e) => format!("refused while translating: {e}"),
            }
          }
        };
        format!("  {name}: {what}")
      })
      .collect::<Vec<_>>()
      .join("\n")
  }

  /// As [`check`], and additionally insists the program really was translated.
  /// Without this a test whose program the validator happens to refuse would
  /// still pass: a refusal is recorded and compared just as an emission is, and
  /// a suite that agrees with itself about refusing everything tests nothing.
  #[track_caller]
  fn check_prog(insns: &[Insn]) {
    let code = Insn::encode_all(insns);
    let inputs = plain_inputs(insns.len());
    assert!(
      check(&code, &inputs),
      "no configuration translated this program; it is being rejected rather \
       than exercising the emitter:\n{insns:#?}\n{}",
      refusal_report(&code, &inputs)
    );
  }

  /// One translation's raw outcome.
  /// The randomised sweeps fold hundreds of thousands of these into a single
  /// digest instead of recording a golden apiece, and there a program that
  /// stops loading has to be a distinguishable outcome rather than a silent
  /// skip.
  fn emit_outcome(
    config: &Config,
    code: &[u8],
    inputs: &TranslationInputs<'_>,
  ) -> Result<Vec<u8>, TranslateError> {
    arm_flush();
    golden::translate_one(config, code, inputs, CAPACITY)
      .unwrap_or_else(|| Err(TranslateError::Failed("did not load".to_string())))
  }

  /// Bytes one configuration emits for one translation, which must succeed.
  /// Recording a golden says only that the output has not changed; this is what
  /// a test uses to assert that a fast path was actually *taken*.
  fn emitted_len(
    config: &Config,
    code: &[u8],
    inputs: &TranslationInputs<'_>,
    capacity: usize,
  ) -> usize {
    let t = Translator::load(Arc::new(config.clone()), code).expect("program must load");
    let mut buf = vec![0u8; capacity];
    t.translate_range(inputs, &mut buf).expect("must translate")
  }

  /// As [`emitted_len`], under the production configuration.
  fn production_len(code: &[u8], inputs: &TranslationInputs<'_>) -> usize {
    emitted_len(&production_config(), code, inputs, CAPACITY)
  }

  // -----------------------------------------------------------------------
  // Structure
  // -----------------------------------------------------------------------

  #[test]
  fn the_register_map_is_injective_and_pins_r10_to_r15() {
    let mut seen = std::collections::BTreeSet::new();
    for r in 0..crate::jit::isa::NUM_REGS as u8 {
      assert!(
        seen.insert(map_register(r)),
        "register map is not injective"
      );
      assert_eq!(unmap_register(map_register(r)), Some(r));
    }
    // The frame-access fast path and the local-call frame adjustment both name
    // R15 directly, so this mapping is load-bearing.
    assert_eq!(map_register(crate::jit::isa::REG_FP), R15);
    // RCX and R11 are the scratch registers, so nothing may map to them.
    assert_eq!(unmap_register(RCX), None);
    assert_eq!(unmap_register(R11), None);
    assert_eq!(unmap_register(R9), None);
  }

  #[test]
  fn the_minimal_program_matches() {
    check_prog(&[movi(0, 42), exit()]);
  }

  #[test]
  fn a_function_granular_callee_does_not_skip_its_own_prologue() {
    // The preceding, unreachable JA is conservatively considered to have
    // fallthrough. That needs a bypass in whole-program translation, but not
    // when this buffer begins at the local callee itself.
    let insns = vec![
      insn(opcode::CALL, 0, 1, 0, 3), // pc 0 -> pc 4
      exit(),
      insn(opcode::JA, 0, 0, 0, 0),
      insn(opcode::CALL, 0, 0, 0, 0),
      movi(0, 7),
      exit(),
    ];
    let code = Insn::encode_all(&insns);
    let config = Config {
      target: Target::X86_64,
      dispatcher: Some(dispatcher()),
      dispatcher_validate: Some(accept_every_helper),
      local_call_resolver: Some(local_call_resolver()),
      ..Default::default()
    };
    let translator = Translator::load(Arc::new(config), &code).unwrap();
    let resolver_ids = [1u32; 6];
    let inputs = TranslationInputs {
      resolver_ids: &resolver_ids,
      start_pc: 4,
      end_pc: 6,
      ..Default::default()
    };
    let mut out = vec![0u8; CAPACITY];
    translator.translate_range(&inputs, &mut out).unwrap();

    assert_ne!(
      out[0], 0xeb,
      "the callee entry jumped past its own prologue"
    );
  }

  // -----------------------------------------------------------------------
  // ALU
  // -----------------------------------------------------------------------

  #[test]
  fn every_alu_op_matches_at_both_widths_and_both_sources() {
    let mut s = Sweep::new();
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
    for class in [cls::ALU, cls::ALU64] {
      for op in ops {
        // The register forms take no immediate and the immediate forms take no
        // source register; the validator refuses anything else.
        for imm in [0i32, 1, 7, -1, i32::MIN, i32::MAX] {
          s.check_prog(&[insn(class | op, 1, 0, 0, imm), exit()]);
        }
        for src in [0u8, 2, 9, 10] {
          s.check_prog(&[insn(class | op | srcbit::REG, 1, src, 0, 0), exit()]);
        }
      }
    }
    s.finish("every_alu_op_matches_at_both_widths_and_both_sources");
  }

  #[test]
  fn signed_division_and_modulo_match() {
    let mut s = Sweep::new();
    for class in [cls::ALU, cls::ALU64] {
      for op in [alu::DIV, alu::MOD] {
        // `offset == 1` selects the signed flavour (RFC 9669), which is where
        // the INT_MIN / -1 fixup lives.
        for imm in [1i32, -1, 3, 0] {
          s.check_prog(&[insn(class | op, 1, 0, 1, imm), exit()]);
        }
        s.check_prog(&[insn(class | op | srcbit::REG, 1, 2, 1, 0), exit()]);
      }
    }
    s.finish("signed_division_and_modulo_match");
  }

  #[test]
  fn muldivmod_matches_for_every_destination_register() {
    let mut s = Sweep::new();
    // The sequence pushes RAX and RDX conditionally on the destination, so each
    // eBPF register that maps onto one of them takes a different path.
    for dst in 0..10u8 {
      for op in [alu::MUL, alu::DIV, alu::MOD] {
        s.check_prog(&[insn(cls::ALU64 | op, dst, 0, 0, 7), exit()]);
        s.check_prog(&[insn(cls::ALU64 | op | srcbit::REG, dst, 2, 0, 0), exit()]);
        s.check_prog(&[insn(cls::ALU | op, dst, 0, 0, 7), exit()]);
      }
    }
    s.finish("muldivmod_matches_for_every_destination_register");
  }

  #[test]
  fn neg_matches_at_both_widths() {
    let mut s = Sweep::new();
    for dst in 0..10u8 {
      s.check_prog(&[insn(cls::ALU | alu::NEG, dst, 0, 0, 0), exit()]);
      s.check_prog(&[insn(cls::ALU64 | alu::NEG, dst, 0, 0, 0), exit()]);
    }
    s.finish("neg_matches_at_both_widths");
  }

  #[test]
  fn sign_extending_moves_match() {
    let mut s = Sweep::new();
    for offset in [0i16, 8, 16, 32] {
      for dst in 0..10u8 {
        s.check_prog(&[
          insn(cls::ALU64 | alu::MOV | srcbit::REG, dst, 2, offset, 0),
          exit(),
        ]);
        // The 32-bit form only defines 8 and 16.
        if offset != 32 {
          s.check_prog(&[
            insn(cls::ALU | alu::MOV | srcbit::REG, dst, 2, offset, 0),
            exit(),
          ]);
        }
      }
    }
    s.finish("sign_extending_moves_match");
  }

  #[test]
  fn byte_order_conversions_match_at_every_width() {
    let mut s = Sweep::new();
    for imm in [16i32, 32, 64] {
      for dst in 0..10u8 {
        s.check_prog(&[insn(opcode::LE, dst, 0, 0, imm), exit()]);
        s.check_prog(&[insn(opcode::BE, dst, 0, 0, imm), exit()]);
        s.check_prog(&[insn(opcode::BSWAP, dst, 0, 0, imm), exit()]);
      }
    }
    s.finish("byte_order_conversions_match_at_every_width");
  }

  // -----------------------------------------------------------------------
  // Jumps
  // -----------------------------------------------------------------------

  #[test]
  fn every_conditional_jump_matches_at_both_widths_and_both_sources() {
    let mut s = Sweep::new();
    let ops = [
      jmp::JEQ,
      jmp::JGT,
      jmp::JGE,
      jmp::JSET,
      jmp::JNE,
      jmp::JSGT,
      jmp::JSGE,
      jmp::JLT,
      jmp::JLE,
      jmp::JSLT,
      jmp::JSLE,
    ];
    for class in [cls::JMP, cls::JMP32] {
      for op in ops {
        // Immediate form: no source register. Register form: no immediate.
        for (src, imm) in [(0u8, 7i32), (2, 0)] {
          let source = if src == 0 { srcbit::IMM } else { srcbit::REG };
          s.check_prog(&[
            insn(class | op | source, 1, src, 1, imm),
            movi(0, 1),
            exit(),
          ]);
          // A backward branch, which exercises the negative displacement. It
          // has to reach past the instruction before it: the validator refuses
          // a displacement of -1 as an infinite loop.
          s.check_prog(&[
            movi(0, 1),
            movi(0, 2),
            insn(class | op | source, 1, src, -2, imm),
            exit(),
          ]);
        }
      }
    }
    s.finish("every_conditional_jump_matches_at_both_widths_and_both_sources");
  }

  #[test]
  fn unconditional_jumps_match_in_both_encodings() {
    check_prog(&[insn(opcode::JA, 0, 0, 1, 0), movi(0, 1), exit()]);
    check_prog(&[insn(opcode::JA32, 0, 0, 0, 1), movi(0, 1), exit()]);
    // Jumping to the instruction that follows, i.e. a displacement of zero.
    check_prog(&[insn(opcode::JA, 0, 0, 0, 0), exit()]);
  }

  #[test]
  fn a_jump_out_of_the_translation_range_is_rejected_the_same_way() {
    // The whole program loads; only the sub-range translation refuses it, and
    // it must refuse it under every configuration.
    let insns = [insn(opcode::JA, 0, 0, 1, 0), movi(0, 1), exit()];
    let code = Insn::encode_all(&insns);
    let inputs = TranslationInputs {
      start_pc: 0,
      end_pc: 1,
      ..Default::default()
    };
    assert!(
      !check(&code, &inputs),
      "the branch leaves the range, so no configuration may translate it"
    );
  }

  // -----------------------------------------------------------------------
  // Memory
  // -----------------------------------------------------------------------

  #[test]
  fn loads_and_stores_match_at_every_width() {
    let mut s = Sweep::new();
    for sz in [size::B, size::H, size::W, size::DW] {
      for offset in [0i16, 1, 8, -8, 127, 128, -128, -129, 4096, -4096] {
        s.check_prog(&[insn(cls::LDX | mode::MEM | sz, 1, 2, offset, 0), exit()]);
        s.check_prog(&[insn(cls::STX | mode::MEM | sz, 1, 2, offset, 0), exit()]);
        s.check_prog(&[insn(cls::ST | mode::MEM | sz, 1, 0, offset, 0x55), exit()]);
      }
    }
    s.finish("loads_and_stores_match_at_every_width");
  }

  #[test]
  fn sign_extending_loads_match() {
    let mut s = Sweep::new();
    for sz in [size::B, size::H, size::W] {
      for offset in [0i16, 4, -4, 1000] {
        s.check_prog(&[insn(cls::LDX | mode::MEMSX | sz, 1, 2, offset, 0), exit()]);
      }
    }
    s.finish("sign_extending_loads_match");
  }

  #[test]
  fn memory_access_matches_for_every_base_and_destination_register() {
    let mut s = Sweep::new();
    // R6-R9 map onto RBX/R12/R13/R14 and R10 onto R15: R12 needs a SIB byte as
    // a base and R13 needs an explicit zero displacement, and the byte forms of
    // RSI/RDI need a REX prefix to name SIL/DIL. This is where a hand-written
    // encoder goes wrong.
    for base in 0..11u8 {
      for other in [0u8, 1, 6, 7, 8, 9] {
        // A load may read through R10 but may not write it.
        s.check_prog(&[
          insn(cls::LDX | mode::MEM | size::B, other, base, 0, 0),
          exit(),
        ]);
        s.check_prog(&[
          insn(cls::LDX | mode::MEM | size::DW, other, base, 0, 0),
          exit(),
        ]);
      }
      for other in 0..11u8 {
        // A store may name R10 on either side; storing it exercises the
        // guest-frame-pointer recovery.
        s.check_prog(&[
          insn(cls::STX | mode::MEM | size::B, base, other, 0, 0),
          exit(),
        ]);
        s.check_prog(&[
          insn(cls::STX | mode::MEM | size::DW, base, other, 0, 0),
          exit(),
        ]);
      }
    }
    s.finish("memory_access_matches_for_every_base_and_destination_register");
  }

  #[test]
  fn store_immediates_match_for_every_base_register() {
    let mut s = Sweep::new();
    for base in 0..11u8 {
      for sz in [size::B, size::H, size::W, size::DW] {
        s.check_prog(&[insn(cls::ST | mode::MEM | sz, base, 0, 0, -1), exit()]);
        s.check_prog(&[insn(cls::ST | mode::MEM | sz, base, 0, 16, 0x1234), exit()]);
      }
    }
    s.finish("store_immediates_match_for_every_base_register");
  }

  // -----------------------------------------------------------------------
  // Atomics
  // -----------------------------------------------------------------------

  #[test]
  fn every_atomic_matches_at_both_widths() {
    let mut s = Sweep::new();
    let selectors = [
      alu::ADD as i32,
      alu::OR as i32,
      alu::AND as i32,
      alu::XOR as i32,
      alu::ADD as i32 | 1,
      alu::OR as i32 | 1,
      alu::AND as i32 | 1,
      alu::XOR as i32 | 1,
      0xe1,
      0xf1,
    ];
    for op in [opcode::ATOMIC_STORE, opcode::ATOMIC32_STORE] {
      for sel in selectors {
        for offset in [0i16, 8, -8] {
          s.check_prog(&[insn(op, 1, 2, offset, sel), exit()]);
        }
      }
    }
    s.finish("every_atomic_matches_at_both_widths");
  }

  #[test]
  fn non_canonical_atomic_selectors_match() {
    let mut s = Sweep::new();
    // The atomic decode switches on `imm & 0xf0` and reads the fetch flag out
    // of bit 0, so bits 1 through 3 are dead and several immediates that name
    // no operation in the ISA still emit code. The validator's filter for
    // 32-bit atomics bounds the immediate at 0..=255 rather than enumerating
    // it, so these reach the backend on programs that load.
    //
    //   0x02  -> plain atomic add, no fetch
    //   0x0f  -> atomic add *with* fetch
    //   0x4e  -> atomic or, no fetch
    //   0xe3  -> exchange, the two dead bits set
    //   0xff  -> compare-exchange, likewise
    //
    // 0xe0 and 0xf0 — exchange and compare-exchange with the fetch flag clear —
    // are included too, but the *validator* refuses those at both widths, so
    // they never reach the emitter through a program that loads. The backend
    // would handle them; here that refusal is what is pinned.
    for sel in [
      0x02i32, 0x0f, 0xe0, 0xf0, 0x4e, 0x53, 0xa8, 0xff, 0xe3, 0xf3,
    ] {
      for op in [opcode::ATOMIC_STORE, opcode::ATOMIC32_STORE] {
        for offset in [0i16, 8] {
          let insns = [insn(op, 1, 2, offset, sel), exit()];
          let code = Insn::encode_all(&insns);
          // The 64-bit form's filter enumerates its immediates, so some of
          // these load only at 32-bit width; `check` pins whichever way each
          // one goes.
          s.check(&code, &plain_inputs(insns.len()));
        }
      }
    }
    // At 32-bit width every one of them must actually translate, which is what
    // makes this test more than a record of refusals.
    for sel in [0x02i32, 0x0f, 0x4e, 0x53, 0xa8, 0xe3, 0xff] {
      s.check_prog(&[insn(opcode::ATOMIC32_STORE, 1, 2, 0, sel), exit()]);
    }
    s.finish("non_canonical_atomic_selectors_match");
  }

  #[test]
  fn an_unknown_atomic_selector_is_refused_identically() {
    let mut s = Sweep::new();
    // `imm & 0xf0` landing on a nibble the decode does not name is the one
    // place translation is abandoned mid-instruction, returning without
    // emitting an epilogue at all.
    for sel in [
      0x10i32, 0x20, 0x30, 0x60, 0x70, 0x80, 0x90, 0xb0, 0xc0, 0xd0,
    ] {
      for op in [opcode::ATOMIC_STORE, opcode::ATOMIC32_STORE] {
        let insns = [insn(op, 1, 2, 0, sel), exit()];
        let code = Insn::encode_all(&insns);
        s.check(&code, &plain_inputs(insns.len()));
      }
    }
    s.finish("an_unknown_atomic_selector_is_refused_identically");
  }

  #[test]
  fn fetching_atomics_match_when_the_source_is_r0() {
    let mut s = Sweep::new();
    // R0 maps to RAX, which the compare-exchange loop clobbers, so the sequence
    // takes a different path and shuffles through R10/R11 instead.
    for op in [opcode::ATOMIC_STORE, opcode::ATOMIC32_STORE] {
      for sel in [alu::ADD as i32 | 1, alu::XOR as i32 | 1] {
        for dst in 0..10u8 {
          s.check_prog(&[insn(op, dst, 0, 0, sel), exit()]);
        }
      }
    }
    s.finish("fetching_atomics_match_when_the_source_is_r0");
  }

  // -----------------------------------------------------------------------
  // Calls
  // -----------------------------------------------------------------------

  #[test]
  fn helper_calls_match() {
    for idx in [0i32, 1, 3, 63] {
      check_prog(&[movi(1, 0), insn(opcode::CALL, 0, 0, 0, idx), exit()]);
    }
  }

  #[test]
  fn a_local_call_without_a_resolver_id_fails_the_same_way() {
    // A lazy local call needs a resolver id for its call site; with none, there
    // is nothing to resolve the call against and it is refused.
    let insns = [insn(opcode::CALL, 0, 1, 0, 1), exit(), movi(0, 7), exit()];
    let code = Insn::encode_all(&insns);
    assert!(
      !check(&code, &plain_inputs(insns.len())),
      "with no resolver ids there is nothing to resolve the call against, so \
       the lazy local call must be refused"
    );
  }

  #[test]
  fn a_local_call_with_a_resolver_id_matches() {
    let insns = [insn(opcode::CALL, 0, 1, 0, 1), exit(), movi(0, 7), exit()];
    let code = Insn::encode_all(&insns);
    let ids = [11u32, 22, 33, 44];
    let inputs = TranslationInputs {
      resolver_ids: &ids,
      start_pc: 0,
      end_pc: insns.len(),
      ..Default::default()
    };
    assert!(check(&code, &inputs));
  }

  #[test]
  fn translating_one_local_function_of_a_program_matches() {
    // Two functions; translate only the second, which is a strict sub-range.
    let insns = [
      insn(opcode::CALL, 0, 1, 0, 1),
      exit(),
      movi(0, 7),
      insn(cls::ALU64 | alu::ADD, 0, 0, 0, 1),
      exit(),
    ];
    let code = Insn::encode_all(&insns);
    let ids = [1u32, 2, 3, 4, 5];
    for (start, end) in [(0usize, 2usize), (2, 5)] {
      let inputs = TranslationInputs {
        resolver_ids: &ids,
        start_pc: start,
        end_pc: end,
        ..Default::default()
      };
      assert!(check(&code, &inputs), "nothing was translated");
    }
  }

  #[test]
  fn a_range_that_is_not_a_function_boundary_is_rejected_the_same_way() {
    let insns = [insn(opcode::CALL, 0, 1, 0, 1), exit(), movi(0, 7), exit()];
    let code = Insn::encode_all(&insns);
    for (start, end) in [(1usize, 4usize), (0, 3), (3, 3), (0, 99)] {
      let inputs = TranslationInputs {
        start_pc: start,
        end_pc: end,
        ..Default::default()
      };
      assert!(
        !check(&code, &inputs),
        "the range is not a function, so it must be refused"
      );
    }
  }

  #[test]
  fn a_fallthrough_into_a_local_function_entry_matches() {
    // The instruction before the entry falls through, so a jump around the
    // per-function prologue has to be emitted.
    // Reaching a local function entry by falling into it takes some arranging.
    // The validator requires each sub-program to end in EXIT or to carry an
    // unconditional jump in its second-to-last slot, and refuses a jump that
    // crosses a sub-program boundary — but only EXIT counts as not falling
    // through, so a sub-program ending in a `ja` followed by an ordinary
    // instruction both validates and falls through. That is the shape the
    // backend's bypass jump exists for.
    let insns = [
      insn(opcode::CALL, 0, 1, 0, 2),
      insn(opcode::JA, 0, 0, 0, 0),
      movi(0, 1),
      movi(0, 7),
      exit(),
    ];
    let code = Insn::encode_all(&insns);
    let ids = [1u32, 2, 3, 4, 5];
    let inputs = TranslationInputs {
      resolver_ids: &ids,
      start_pc: 0,
      end_pc: insns.len(),
      ..Default::default()
    };
    assert!(
      check(&code, &inputs),
      "nothing was translated\n{}",
      refusal_report(&code, &inputs)
    );
  }

  // -----------------------------------------------------------------------
  // lddw
  // -----------------------------------------------------------------------

  #[test]
  fn lddw_matches_for_small_and_large_immediates() {
    for (lo, hi) in [
      (0i32, 0i32),
      (1, 0),
      (-1, 0),
      (0x1234_5678, 0x9abc_def0u32 as i32),
      (0, 1),
    ] {
      check_prog(&[
        insn(opcode::LDDW, 3, 0, 0, lo),
        insn(0, 0, 0, 0, hi),
        exit(),
      ]);
    }
  }

  // -----------------------------------------------------------------------
  // Region hints and access plans
  // -----------------------------------------------------------------------

  #[test]
  fn every_region_hint_matches() {
    let mut s = Sweep::new();
    for hint in [
      abi::region::UNKNOWN,
      abi::region::STACK,
      abi::region::DATA,
      abi::region::FRAME,
    ] {
      for base in [1u8, 10] {
        for offset in [0i16, -8, -4096, -4097, 8] {
          for sz in [size::B, size::W, size::DW] {
            let insns = [insn(cls::LDX | mode::MEM | sz, 1, base, offset, 0), exit()];
            let code = Insn::encode_all(&insns);
            let hints = [hint, abi::region::UNKNOWN];
            let inputs = TranslationInputs {
              hints: &hints,
              start_pc: 0,
              end_pc: insns.len(),
              ..Default::default()
            };
            assert!(s.check(&code, &inputs), "nothing was translated");
          }
        }
      }
    }
    s.finish("every_region_hint_matches");
  }

  #[test]
  fn a_well_formed_access_plan_matches() {
    // Two loads off R2 at +0 and +8, grouped: the first leads, the second
    // rides the base it parked.
    let insns = [
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
      insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
      exit(),
    ];
    let code = Insn::encode_all(&insns);
    for region in [abi::region::STACK, abi::region::DATA] {
      let plan = [
        PlanEntry {
          role: abi::plan_role::LEADER,
          region,
          delta: 0,
          span: 16,
          lo: 0,
          leader_pc: 0,
        },
        PlanEntry {
          role: abi::plan_role::MEMBER,
          region,
          delta: 8,
          span: 16,
          lo: 0,
          leader_pc: 0,
        },
        PlanEntry::default(),
      ];
      let inputs = TranslationInputs {
        plan: &plan,
        start_pc: 0,
        end_pc: insns.len(),
        ..Default::default()
      };
      assert!(check(&code, &inputs), "nothing was translated");
    }
  }

  #[test]
  fn a_well_formed_access_plan_is_actually_taken() {
    // A recorded golden is not enough on its own: a plan the backend silently
    // declined would record perfectly stable bytes, and neither the leader nor
    // the member path would ever be exercised. A grouped pair has to come out
    // shorter than the same pair checked one access at a time.
    let insns = [
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
      insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
      exit(),
    ];
    let code = Insn::encode_all(&insns);
    let plan = [
      PlanEntry {
        role: abi::plan_role::LEADER,
        region: abi::region::STACK,
        delta: 0,
        span: 16,
        lo: 0,
        leader_pc: 0,
      },
      PlanEntry {
        role: abi::plan_role::MEMBER,
        region: abi::region::STACK,
        delta: 8,
        span: 16,
        lo: 0,
        leader_pc: 0,
      },
      PlanEntry::default(),
    ];
    let planned = TranslationInputs {
      plan: &plan,
      start_pc: 0,
      end_pc: insns.len(),
      ..Default::default()
    };
    let unplanned = plain_inputs(insns.len());

    assert!(check(&code, &planned));
    assert!(check(&code, &unplanned));
    assert!(
      production_len(&code, &planned) < production_len(&code, &unplanned),
      "the access plan did not shorten the emitted code, so the group paths \
       were never exercised: planned {} vs unplanned {}",
      production_len(&code, &planned),
      production_len(&code, &unplanned)
    );
  }

  #[test]
  fn the_frame_hint_is_actually_taken() {
    // Same argument as above for the one hint that removes the check rather
    // than narrowing it.
    let insns = [insn(cls::LDX | mode::MEM | size::DW, 1, 10, -8, 0), exit()];
    let code = Insn::encode_all(&insns);
    let framed = [abi::region::FRAME, abi::region::UNKNOWN];
    let unknown = [abi::region::UNKNOWN, abi::region::UNKNOWN];
    let mk = |hints: &'static [u8]| TranslationInputs {
      hints,
      start_pc: 0,
      end_pc: 2,
      ..Default::default()
    };
    let framed: &'static [u8] = Box::leak(Box::new(framed));
    let unknown: &'static [u8] = Box::leak(Box::new(unknown));
    assert!(check(&code, &mk(framed)));
    assert!(check(&code, &mk(unknown)));
    assert!(
      production_len(&code, &mk(framed)) < production_len(&code, &mk(unknown)),
      "the frame hint did not remove the bounds check"
    );
  }

  #[test]
  fn stores_match_under_every_region_hint() {
    let mut s = Sweep::new();
    // The store paths are not the load paths: a store is pinned to the stack
    // region whatever the hint says, and the immediate form swaps the address
    // and scratch registers around.
    for hint in [
      abi::region::UNKNOWN,
      abi::region::STACK,
      abi::region::DATA,
      abi::region::FRAME,
    ] {
      for base in [1u8, 10] {
        for offset in [0i16, -8, -4096, -4097] {
          for sz in [size::B, size::H, size::W, size::DW] {
            for insn_ in [
              insn(cls::STX | mode::MEM | sz, base, 2, offset, 0),
              insn(cls::ST | mode::MEM | sz, base, 0, offset, 0x33),
            ] {
              let insns = [insn_, exit()];
              let code = Insn::encode_all(&insns);
              let hints = [hint, abi::region::UNKNOWN];
              let inputs = TranslationInputs {
                hints: &hints,
                start_pc: 0,
                end_pc: insns.len(),
                ..Default::default()
              };
              assert!(s.check(&code, &inputs), "nothing was translated");
            }
          }
        }
      }
    }
    s.finish("stores_match_under_every_region_hint");
  }

  #[test]
  fn atomics_match_for_every_base_register() {
    let mut s = Sweep::new();
    // The cage rewrites the base into R11 and the scratch is RCX, so a base
    // that already maps onto one of them would collide; none does, and this is
    // what checks that.
    for base in 0..11u8 {
      for src in 0..10u8 {
        for op in [opcode::ATOMIC_STORE, opcode::ATOMIC32_STORE] {
          s.check_prog(&[insn(op, base, src, 0, 0), exit()]);
          s.check_prog(&[insn(op, base, src, 8, 0x01), exit()]);
        }
      }
    }
    s.finish("atomics_match_for_every_base_register");
  }

  #[test]
  fn a_hostile_access_plan_is_declined_identically() {
    let insns = [
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
      insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
      insn(cls::STX | mode::MEM | size::DW, 2, 3, 8, 0),
      exit(),
    ];
    let code = Insn::encode_all(&insns);

    // Every one of these must make the backend fall back to a checked access,
    // at exactly the places the plan stops being self-consistent.
    let hostile: [[PlanEntry; 4]; 8] = [
      // A span of zero.
      plan3(abi::plan_role::LEADER, abi::region::STACK, 0, 0, 0, 0),
      // A span wider than a page.
      plan3(abi::plan_role::LEADER, abi::region::STACK, 0, 8192, 0, 0),
      // The access does not fit inside the window.
      plan3(abi::plan_role::LEADER, abi::region::STACK, 0, 4, 0, 0),
      // `lo + delta` is not the displacement the instruction names.
      plan3(abi::plan_role::LEADER, abi::region::STACK, 0, 64, 32, 0),
      // A leader claiming the frame region, which is never groupable.
      plan3(abi::plan_role::LEADER, abi::region::FRAME, 0, 64, 0, 0),
      // A member naming a leader that never ran.
      plan3(abi::plan_role::MEMBER, abi::region::STACK, 8, 64, 0, 99),
      // A member whose delta lands outside the leader's window.
      plan3(abi::plan_role::MEMBER, abi::region::STACK, 4096, 64, 0, 0),
      // A store riding a window checked against the read-only data region.
      plan3(abi::plan_role::LEADER, abi::region::DATA, 0, 64, 0, 0),
    ];
    for plan in hostile {
      let inputs = TranslationInputs {
        plan: &plan,
        start_pc: 0,
        end_pc: insns.len(),
        ..Default::default()
      };
      assert!(check(&code, &inputs), "nothing was translated");
    }
  }

  /// Builds a three-instruction plan whose first entry carries the parameters
  /// under test and whose second is a member of it.
  fn plan3(role: u8, region: u8, delta: u16, span: u32, lo: i32, leader_pc: u32) -> [PlanEntry; 4] {
    [
      PlanEntry {
        role,
        region,
        delta,
        span,
        lo,
        leader_pc,
      },
      PlanEntry {
        role: abi::plan_role::MEMBER,
        region,
        delta: 8,
        span,
        lo,
        leader_pc: 0,
      },
      PlanEntry {
        role: abi::plan_role::MEMBER,
        region,
        delta: 8,
        span,
        lo,
        leader_pc: 0,
      },
      PlanEntry::default(),
    ]
  }

  #[test]
  fn a_group_broken_by_a_barrier_or_a_redefined_base_is_declined_identically() {
    // A branch lands between the leader and the member, and separately the base
    // register is rewritten between them. Both must close the group.
    let programs: [Vec<Insn>; 2] = [
      vec![
        insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
        insn(cls::JMP | jmp::JEQ, 1, 0, 0, 0),
        insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
        exit(),
      ],
      vec![
        insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
        insn(cls::ALU64 | alu::ADD, 2, 0, 0, 1),
        insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
        exit(),
      ],
    ];
    for insns in programs {
      let code = Insn::encode_all(&insns);
      let plan = [
        PlanEntry {
          role: abi::plan_role::LEADER,
          region: abi::region::STACK,
          delta: 0,
          span: 16,
          lo: 0,
          leader_pc: 0,
        },
        PlanEntry::default(),
        PlanEntry {
          role: abi::plan_role::MEMBER,
          region: abi::region::STACK,
          delta: 8,
          span: 16,
          lo: 0,
          leader_pc: 0,
        },
        PlanEntry::default(),
      ];
      let inputs = TranslationInputs {
        plan: &plan,
        start_pc: 0,
        end_pc: insns.len(),
        ..Default::default()
      };
      assert!(check(&code, &inputs), "nothing was translated");
    }
  }

  // -----------------------------------------------------------------------
  // Exhaustive opcode census
  // -----------------------------------------------------------------------

  #[test]
  fn every_defined_opcode_emits_code() {
    let mut s = Sweep::new();
    // Translation switches on the raw opcode byte, with everything unhandled
    // reported as an unknown instruction. Sweeping all 256 values is what pins
    // the boundary of that set, including the encodings it must refuse.
    // Each opcode admits a different operand shape, so every byte is tried
    // against a spread of them: one that suits an immediate form, one a
    // register form, one an endian width, one a branch displacement, and so on.
    // A byte counts as covered when any shape translates.
    let candidates: [(u8, u8, i16, i32); 8] = [
      (1, 0, 0, 7),  // immediate ALU, `st`, conditional jump against an immediate
      (1, 2, 0, 0),  // register ALU, `ldx`, `stx`, conditional jump against a register
      (0, 0, 0, 0),  // `exit`, and anything taking no operands
      (1, 0, 0, 16), // `le` / `be` / `bswap`
      (1, 2, 1, 0),  // the signed `div` / `mod` flavour, and a forward branch
      (0, 0, 1, 0),  // `ja`
      (0, 0, 0, 1),  // `ja32`, helper `call`
      (1, 2, 0, 1),  // atomic read-modify-write with the fetch bit
    ];

    let mut translated = 0usize;
    for byte in 0u16..=255 {
      let byte = byte as u8;
      let mut covered = false;
      for (dst, src, offset, imm) in candidates {
        let insns = if byte == opcode::LDDW {
          vec![insn(byte, dst, 0, 0, imm), insn(0, 0, 0, 0, 0), exit()]
        } else {
          vec![insn(byte, dst, src, offset, imm), movi(0, 1), exit()]
        };
        let code = Insn::encode_all(&insns);
        let ids = vec![1u32; insns.len()];
        let inputs = TranslationInputs {
          resolver_ids: &ids,
          start_pc: 0,
          end_pc: insns.len(),
          ..Default::default()
        };
        covered |= s.check(&code, &inputs);
      }
      if covered {
        translated += 1;
      }
    }
    // Most of the census is meant to *emit* something; if the operands chosen
    // above ever stopped satisfying the validator this would quietly become a
    // test that only pins refusals.
    assert!(
      translated >= 110,
      "only {translated} of the 119 defined opcode bytes were translated at \
       all; the census has degraded into a record of refusals"
    );
    s.finish("every_defined_opcode_emits_code");
  }

  #[test]
  fn out_of_space_is_reported_identically() {
    // A buffer too small for the whole function must come back as
    // `OutOfSpace`, and the capacity at which that stops happening is itself
    // worth pinning: it moves whenever the prologue or the trailer changes
    // size. That makes this a sweep over capacities rather than a set of named
    // cases — and the capacity is not part of a golden key, so a rolled-up
    // digest is also the only shape that does not collide with itself.
    let insns = [movi(0, 42), exit()];
    let code = Insn::encode_all(&insns);
    let inputs = plain_inputs(insns.len());
    let mut digest = golden::SweepDigest::new();
    arm_flush();
    for capacity in [0usize, 1, 8, 64, 512, 600] {
      for (_, config) in sweep(Target::X86_64) {
        digest.add(
          &golden::translate_one(&config, &code, &inputs, capacity)
            .expect("the program loads under every configuration"),
        );
      }
    }
    // The largest capacity is over the whole function, so this cannot degrade
    // into a sweep that only ever records `OutOfSpace`.
    assert!(
      digest.translated() > 0,
      "no capacity was large enough to translate the program"
    );
    digest.finish("out_of_space_is_reported_identically", Target::X86_64);
  }

  /// A deterministic xorshift, so a failure is reproducible from the seed
  /// printed in the assertion.
  struct Rng(u64);

  impl Rng {
    fn next(&mut self) -> u64 {
      self.0 ^= self.0 << 13;
      self.0 ^= self.0 >> 7;
      self.0 ^= self.0 << 17;
      self.0
    }
    fn below(&mut self, n: u64) -> u64 {
      self.next() % n
    }
    fn reg(&mut self, max: u8) -> u8 {
      self.below(max as u64 + 1) as u8
    }
  }

  #[test]
  fn randomised_programs_hints_and_plans_match() {
    // The hand-written cases above each aim at one path. This aims at their
    // *interactions*: a plan whose leader is three instructions from its
    // member, a hint that contradicts the plan's region, a group closed by a
    // branch nobody was thinking about. The plans are generated without regard
    // for whether they are sane, which is the point — a wrong or hostile plan
    // has to be declined, not obeyed.
    //
    // The seed range is kept small so this stays a fast test; it was run over
    // 60,000 seeds (360,000 diffs) while the port was being written, with no
    // divergence. Widen the range here to reproduce that.
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
    // Deliberately includes non-canonical selectors: the decode masks with
    // 0xf0 and reads the fetch flag out of bit 0, so 0x02, 0x0f, 0xe0 and 0xf0
    // all name operations even though the ISA does not spell them that way.
    let atomic_selectors = [
      0i32, 1, 0x02, 0x0f, 0x40, 0x41, 0x4e, 0x50, 0x51, 0xa0, 0xa1, 0xe1, 0xe3, 0xf1, 0xff, 0x30,
    ];
    let sizes = [size::B, size::H, size::W, size::DW];
    let jump_ops = [
      jmp::JEQ,
      jmp::JGT,
      jmp::JGE,
      jmp::JSET,
      jmp::JNE,
      jmp::JSGT,
      jmp::JSGE,
      jmp::JLT,
      jmp::JLE,
      jmp::JSLT,
      jmp::JSLE,
    ];

    let mut s = Sweep::new();

    for seed in 1..=500u64 {
      let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
      let len = 3 + rng.below(22) as usize;

      let mut insns = Vec::with_capacity(len + 1);
      for i in 0..len {
        let class32 = rng.below(2) == 0;
        let alu_class = if class32 { cls::ALU } else { cls::ALU64 };
        let op = ops[rng.below(ops.len() as u64) as usize];
        let sz = sizes[rng.below(4) as usize];
        // Only jump forwards, and never past the trailing `exit`.
        let room = (len - i) as i16;
        let jump_class = if rng.below(2) == 0 {
          cls::JMP
        } else {
          cls::JMP32
        };
        let jump_op = jump_ops[rng.below(jump_ops.len() as u64) as usize];
        let endian = [opcode::LE, opcode::BE, opcode::BSWAP][rng.below(3) as usize];
        insns.push(match rng.below(14) {
          0 => insn(alu_class | op, rng.reg(9), 0, 0, rng.next() as i32),
          1 => insn(alu_class | op | srcbit::REG, rng.reg(9), rng.reg(10), 0, 0),
          2 => insn(
            cls::LDX | mode::MEM | sz,
            rng.reg(9),
            rng.reg(10),
            rng.next() as i16,
            0,
          ),
          3 => insn(
            cls::STX | mode::MEM | sz,
            rng.reg(10),
            rng.reg(10),
            rng.next() as i16,
            0,
          ),
          4 => insn(
            cls::ST | mode::MEM | sz,
            rng.reg(10),
            0,
            rng.next() as i16,
            rng.next() as i32,
          ),
          5 => insn(
            if rng.below(2) == 0 {
              opcode::ATOMIC_STORE
            } else {
              opcode::ATOMIC32_STORE
            },
            rng.reg(10),
            rng.reg(9),
            rng.next() as i16,
            atomic_selectors[rng.below(atomic_selectors.len() as u64) as usize],
          ),
          6 => insn(
            endian,
            rng.reg(9),
            0,
            0,
            [16, 32, 64][rng.below(3) as usize],
          ),
          7 => insn(opcode::CALL, 0, 0, 0, rng.below(64) as i32),
          8 => insn(
            cls::LDX | mode::MEMSX | [size::B, size::H, size::W][rng.below(3) as usize],
            rng.reg(9),
            rng.reg(10),
            rng.next() as i16,
            0,
          ),
          9 => insn(
            alu_class | alu::MOV | srcbit::REG,
            rng.reg(9),
            rng.reg(10),
            // 32 is only a defined sign-extension width at 64-bit class.
            if class32 {
              [0i16, 8, 16][rng.below(3) as usize]
            } else {
              [0i16, 8, 16, 32][rng.below(4) as usize]
            },
            0,
          ),
          10 => insn(alu_class | alu::NEG, rng.reg(9), 0, 0, 0),
          11 => insn(
            alu_class | [alu::DIV, alu::MOD][rng.below(2) as usize] | srcbit::REG,
            rng.reg(9),
            rng.reg(10),
            rng.below(2) as i16,
            0,
          ),
          12 => {
            // `ja` forwards; `ja32` carries its displacement in the immediate.
            let hop = rng.below(room.max(1) as u64) as i32;
            if rng.below(2) == 0 {
              insn(opcode::JA, 0, 0, hop as i16, 0)
            } else {
              insn(opcode::JA32, 0, 0, 0, hop)
            }
          }
          _ => {
            // A conditional jump takes either a source register or an
            // immediate, never both.
            let hop = rng.below(room.max(1) as u64) as i16;
            if rng.below(2) == 0 {
              insn(
                jump_class | jump_op | srcbit::REG,
                rng.reg(9),
                rng.reg(10),
                hop,
                0,
              )
            } else {
              insn(jump_class | jump_op, rng.reg(9), 0, hop, rng.next() as i32)
            }
          }
        });
      }
      insns.push(exit());

      let code = Insn::encode_all(&insns);
      let hints: Vec<u8> = (0..insns.len()).map(|_| rng.below(4) as u8).collect();
      let plan: Vec<PlanEntry> = (0..insns.len())
        .map(|_| PlanEntry {
          role: rng.below(3) as u8,
          region: rng.below(4) as u8,
          delta: rng.below(64) as u16,
          span: rng.below(8192) as u32,
          lo: rng.next() as i16 as i32,
          leader_pc: rng.below(insns.len() as u64) as u32,
        })
        .collect();
      let ids: Vec<u32> = (0..insns.len()).map(|_| rng.next() as u32).collect();

      let inputs = TranslationInputs {
        hints: &hints,
        plan: &plan,
        resolver_ids: &ids,
        start_pc: 0,
        end_pc: insns.len(),
      };

      s.check(&code, &inputs);
    }

    assert!(
      s.translated() * 2 >= s.cases(),
      "only {} of {} random programs translated; the generator is producing \
       programs the validator refuses rather than exercising the emitter",
      s.translated(),
      s.cases()
    );
    s.finish("randomised_programs_hints_and_plans_match");
  }

  #[test]
  fn deep_register_pressure_matches() {
    // Every eBPF register as both source and destination of a 64-bit ALU op,
    // which is where the REX bits and the ModRM low three bits interact.
    let mut insns = Vec::new();
    for dst in 0..10u8 {
      for src in 0..11u8 {
        insns.push(insn(cls::ALU64 | alu::ADD | srcbit::REG, dst, src, 0, 0));
        insns.push(insn(cls::ALU | alu::XOR | srcbit::REG, dst, src, 0, 0));
      }
    }
    insns.push(exit());
    check_prog(&insns);
  }

  // -----------------------------------------------------------------------
  // Adversarial audit additions
  // -----------------------------------------------------------------------

  /// A two-function range translated into a buffer that runs out *inside the
  /// second function's per-function prologue* must return
  /// `TranslateError::OutOfSpace` rather than panic.
  ///
  /// This was a real defect, and worth keeping a test for even though what
  /// tripped it is gone. The emitter used to measure each prologue by
  /// differencing `offset` and assert that every one came out the same length;
  /// once the buffer was full, `offset` stopped moving and the second
  /// measurement was partial, so capacities 91..=101 tripped a debug assertion
  /// under every configuration in the sweep. The measurement existed only to
  /// let uBPF's eagerly relocated local call skip a callee's prologue, and went
  /// with it. `out_of_space_is_reported_identically` only ever translates a
  /// *single* function, so this shape is not covered there.
  ///
  /// Nothing is recorded here: the property under test is that the emitter
  /// returns rather than panics, which no output can express.
  #[test]
  fn audit_out_of_space_inside_a_later_function_prologue() {
    let insns = [insn(opcode::CALL, 0, 1, 0, 1), exit(), movi(0, 7), exit()];
    let code = Insn::encode_all(&insns);
    let ids = [1u32, 2, 3, 4];
    let mut panicked = Vec::new();
    for capacity in 0..420usize {
      for (name, config) in sweep(Target::X86_64) {
        let code = code.clone();
        let ids = ids;
        let outcome = std::panic::catch_unwind(move || {
          let inputs = TranslationInputs {
            resolver_ids: &ids,
            start_pc: 0,
            end_pc: 4,
            ..Default::default()
          };
          let t = crate::jit::Translator::load(std::sync::Arc::new(config), &code)
            .expect("program must load");
          let mut buf = vec![0u8; capacity];
          let _ = t.translate_range(&inputs, &mut buf);
        });
        if outcome.is_err() {
          panicked.push((capacity, name));
        }
      }
    }
    assert!(
      panicked.is_empty(),
      "the emitter panicked instead of reporting out-of-space at {} capacities, \
       first {:?}",
      panicked.len(),
      &panicked[..panicked.len().min(8)]
    );
  }

  /// Access plans whose fields sit at, or past, their limits.
  /// The randomised sweep draws `delta` from `0..64`, `span` from `0..8192` and
  /// `lo` from the `i16` range, so the u16/u32/i32 extremes — and the exact
  /// boundaries `span == MAX_GROUP_SPAN` and `delta + width == span` — are
  /// outside the shape it generates.
  #[test]
  fn audit_access_plans_at_their_limits() {
    let mut s = Sweep::new();
    // Two doubleword loads off R2. The leader's window is picked per case; the
    // member's displacement is whatever `lo + delta` says it must be.
    let cases: [(i32, u16, u32, i32, u16, u32); 12] = [
      // (leader lo, leader delta, span, member offset, member delta, span)
      // The window is exactly one page and the member sits at its very end.
      (-4088, 0, 4096, 0, 4088, 4096),
      // One byte past the end of the window: must be declined.
      (-4089, 0, 4096, 0, 4089, 4096),
      // A span exactly on each precomputed width slot.
      (0, 0, 8, 0, 0, 8),
      (0, 0, 4, 0, 0, 4),
      (0, 0, 2, 0, 0, 2),
      (0, 0, 1, 0, 0, 1),
      // One past the page limit.
      (-4088, 0, 4097, 0, 4088, 4097),
      // `delta` at its type maximum.
      (0, u16::MAX, 4096, 0, u16::MAX, 4096),
      // `span` at its type maximum.
      (0, 0, u32::MAX, 8, 8, u32::MAX),
      // `lo` at the extremes of its type.
      (i32::MIN, 0, 16, 8, 8, 16),
      (i32::MAX, 0, 16, 8, 8, 16),
      // `lo + delta` overflowing i32 if it were computed in 32 bits.
      (i32::MAX, u16::MAX, 4096, 8, u16::MAX, 4096),
    ];
    for (lo, ldelta, lspan, moff, mdelta, mspan) in cases {
      let leader_off = (lo as i64 + ldelta as i64).clamp(i16::MIN as i64, i16::MAX as i64) as i16;
      let insns = [
        insn(cls::LDX | mode::MEM | size::DW, 1, 2, leader_off, 0),
        insn(cls::LDX | mode::MEM | size::DW, 3, 2, moff as i16, 0),
        insn(cls::STX | mode::MEM | size::DW, 2, 3, moff as i16, 0),
        exit(),
      ];
      let code = Insn::encode_all(&insns);
      for region in [
        abi::region::STACK,
        abi::region::DATA,
        abi::region::FRAME,
        abi::region::UNKNOWN,
      ] {
        for leader_pc in [0u32, 1, 2, 3, u32::MAX] {
          let plan = [
            PlanEntry {
              role: abi::plan_role::LEADER,
              region,
              delta: ldelta,
              span: lspan,
              lo,
              leader_pc,
            },
            PlanEntry {
              role: abi::plan_role::MEMBER,
              region,
              delta: mdelta,
              span: mspan,
              lo,
              leader_pc,
            },
            PlanEntry {
              role: abi::plan_role::MEMBER,
              region,
              delta: mdelta,
              span: mspan,
              lo,
              leader_pc,
            },
            PlanEntry::default(),
          ];
          let inputs = TranslationInputs {
            plan: &plan,
            start_pc: 0,
            end_pc: insns.len(),
            ..Default::default()
          };
          s.check(&code, &inputs);
        }
      }
    }
    s.finish_exercised("audit_access_plans_at_their_limits");
  }

  /// Region hints outside the four defined values, and plan regions likewise.
  /// Every existing test draws hints from `0..4`; the byte comes from analysis
  /// the backend does not own, so the whole `u8` range has to agree.
  #[test]
  fn audit_region_hints_outside_the_defined_set() {
    let mut s = Sweep::new();
    let insns = [
      insn(cls::LDX | mode::MEM | size::DW, 1, 10, -8, 0),
      insn(cls::STX | mode::MEM | size::B, 2, 1, 0, 0),
      insn(opcode::ATOMIC_STORE, 1, 2, 0, 0),
      exit(),
    ];
    let code = Insn::encode_all(&insns);
    for hint in [0u8, 1, 2, 3, 4, 5, 7, 8, 15, 16, 127, 128, 200, 254, 255] {
      let hints = [hint; 4];
      let inputs = TranslationInputs {
        hints: &hints,
        start_pc: 0,
        end_pc: insns.len(),
        ..Default::default()
      };
      assert!(s.check(&code, &inputs), "hint {hint} translated nothing");
    }
    // And the same byte arriving through an access plan's region field.
    for region in [4u8, 5, 127, 200, 255] {
      let plan = [
        PlanEntry {
          role: abi::plan_role::LEADER,
          region,
          delta: 8,
          span: 64,
          lo: -16,
          leader_pc: 0,
        },
        PlanEntry {
          role: abi::plan_role::MEMBER,
          region,
          delta: 16,
          span: 64,
          lo: -16,
          leader_pc: 0,
        },
        PlanEntry::default(),
        PlanEntry::default(),
      ];
      let inputs = TranslationInputs {
        plan: &plan,
        start_pc: 0,
        end_pc: insns.len(),
        ..Default::default()
      };
      assert!(
        s.check(&code, &inputs),
        "plan region {region} translated nothing"
      );
    }
    // Plan roles outside {NONE, LEADER, MEMBER} too.
    for role in [3u8, 4, 127, 255] {
      let plan = [
        PlanEntry {
          role,
          region: abi::region::STACK,
          delta: 0,
          span: 64,
          lo: -8,
          leader_pc: 0,
        },
        PlanEntry {
          role,
          region: abi::region::STACK,
          delta: 0,
          span: 64,
          lo: 0,
          leader_pc: 0,
        },
        PlanEntry::default(),
        PlanEntry::default(),
      ];
      let inputs = TranslationInputs {
        plan: &plan,
        start_pc: 0,
        end_pc: insns.len(),
        ..Default::default()
      };
      assert!(
        s.check(&code, &inputs),
        "plan role {role} translated nothing"
      );
    }
    s.finish("audit_region_hints_outside_the_defined_set");
  }

  /// The frame fast path's two boundary conditions, swept exactly.
  /// `emit_frame_access_ok` accepts `-4096 <= offset` and `offset + size <= 0`.
  /// The existing tests probe `{0, -8, -4096, -4097, 8}` at three widths, which
  /// misses `offset == -size` (the largest accepted offset for each width) and
  /// `offset == -size + 1` (the smallest rejected one).
  #[test]
  fn audit_frame_access_boundaries() {
    let mut s = Sweep::new();
    for (sz, width) in [(size::B, 1i16), (size::H, 2), (size::W, 4), (size::DW, 8)] {
      for offset in [
        -width - 1,
        -width,
        -width + 1,
        0,
        1,
        -4095,
        -4096,
        -4097,
        -4098,
        i16::MIN,
        i16::MAX,
      ] {
        for op in [
          insn(cls::LDX | mode::MEM | sz, 1, 10, offset, 0),
          insn(cls::STX | mode::MEM | sz, 10, 1, offset, 0),
          insn(cls::ST | mode::MEM | sz, 10, 0, offset, 0x7f),
        ] {
          let insns = [op, exit()];
          let code = Insn::encode_all(&insns);
          for hint in [abi::region::FRAME, abi::region::STACK] {
            let hints = [hint, hint];
            let inputs = TranslationInputs {
              hints: &hints,
              start_pc: 0,
              end_pc: insns.len(),
              ..Default::default()
            };
            s.check(&code, &inputs);
          }
        }
      }
    }
    s.finish_exercised("audit_frame_access_boundaries");
  }

  /// A `lddw` in the last slot of a sub-range, whose high half therefore lives
  /// in the *next* function.
  /// `lddw_matches_for_small_and_large_immediates` only ever puts one in the
  /// middle of a whole-program range, so the fetch past the range end — where a
  /// zero instruction stands in for the half that is not there — is never
  /// exercised.
  #[test]
  fn audit_lddw_at_the_end_of_a_range() {
    let mut s = Sweep::new();
    // pc0 call->3, pc1 lddw, pc2 <imm high half>, pc3 movi, pc4 exit.
    let programs: [Vec<Insn>; 2] = [
      vec![
        insn(opcode::CALL, 0, 1, 0, 2),
        insn(opcode::LDDW, 3, 0, 0, -1),
        insn(0, 0, 0, 0, -1),
        movi(0, 7),
        exit(),
      ],
      // And with the `lddw` as the very last slot of the whole program.
      vec![movi(0, 1), insn(opcode::LDDW, 3, 0, 0, 0x1234_5678)],
    ];
    for insns in programs {
      let code = Insn::encode_all(&insns);
      let ids = vec![1u32; insns.len()];
      for (start, end) in [(0usize, insns.len()), (0, 2), (0, 1)] {
        if end > insns.len() {
          continue;
        }
        let inputs = TranslationInputs {
          resolver_ids: &ids,
          start_pc: start,
          end_pc: end,
          ..Default::default()
        };
        s.check(&code, &inputs);
      }
    }
    // Nothing here translates: the validator refuses every one of these,
    // and the digest is what pins that refusal.
    s.finish("audit_lddw_at_the_end_of_a_range");
  }

  /// Helper indices the census never reaches: negative, past the highest index
  /// the runtime registers, and the two integer extremes.
  #[test]
  fn audit_helper_call_indices_at_the_extremes() {
    let mut s = Sweep::new();
    for imm in [
      -1i32,
      0,
      63,
      64,
      65,
      255,
      256,
      1000,
      i32::MAX,
      i32::MIN,
      -2,
      3,
    ] {
      let insns = [movi(1, 0), insn(opcode::CALL, 0, 0, 0, imm), exit()];
      let code = Insn::encode_all(&insns);
      s.check(&code, &plain_inputs(insns.len()));
    }
    // A source field that names neither a helper nor a local call, for which
    // nothing at all is emitted.
    for src in [2u8, 3, 7, 8, 15] {
      let insns = [insn(opcode::CALL, 0, src, 0, 1), exit()];
      let code = Insn::encode_all(&insns);
      let ids = [1u32; 2];
      let inputs = TranslationInputs {
        resolver_ids: &ids,
        start_pc: 0,
        end_pc: insns.len(),
        ..Default::default()
      };
      s.check(&code, &inputs);
    }
    s.finish_exercised("audit_helper_call_indices_at_the_extremes");
  }

  /// Register fields above `R10`, which `map_register` folds with `% 11`.
  /// Every existing test stays inside `0..=10`. The field is four bits wide on
  /// the wire, so a hostile program can name 11 through 15; if the validator
  /// lets any of those through, the fold is what decides where they land.
  #[test]
  fn audit_register_fields_above_r10() {
    let mut s = Sweep::new();
    for r in 11u8..=15 {
      for insn_ in [
        insn(cls::ALU64 | alu::ADD | srcbit::REG, r, 1, 0, 0),
        insn(cls::ALU64 | alu::ADD | srcbit::REG, 1, r, 0, 0),
        insn(cls::LDX | mode::MEM | size::DW, r, 1, 0, 0),
        insn(cls::LDX | mode::MEM | size::DW, 1, r, 0, 0),
        insn(cls::STX | mode::MEM | size::DW, r, 1, 0, 0),
        insn(cls::ST | mode::MEM | size::DW, r, 0, 0, 1),
        insn(opcode::ATOMIC_STORE, r, 1, 0, 1),
        insn(cls::ALU64 | alu::DIV | srcbit::REG, r, 1, 0, 0),
      ] {
        let insns = [insn_, exit()];
        let code = Insn::encode_all(&insns);
        s.check(&code, &plain_inputs(insns.len()));
      }
    }
    // Nothing here translates: the validator refuses every one of these,
    // and the digest is what pins that refusal.
    s.finish("audit_register_fields_above_r10");
  }

  /// Branch displacements at the `i16` extremes, and `ja32` at the `i32` ones.
  /// The randomised generator only ever jumps forwards and never past the
  /// trailing `exit`, so the wrapping in `target_pc_64 as u32` and the
  /// range rejection that follows it are only ever seen with small numbers.
  #[test]
  fn audit_branch_displacements_at_the_extremes() {
    let mut s = Sweep::new();
    for off in [i16::MIN, i16::MIN + 1, -2, -1, 0, 1, i16::MAX - 1, i16::MAX] {
      for op in [
        insn(opcode::JA, 0, 0, off, 0),
        insn(cls::JMP | jmp::JEQ, 1, 0, off, 0),
        insn(cls::JMP32 | jmp::JNE | srcbit::REG, 1, 2, off, 0),
      ] {
        let insns = [movi(0, 1), op, movi(0, 2), exit()];
        let code = Insn::encode_all(&insns);
        s.check(&code, &plain_inputs(insns.len()));
      }
    }
    for imm in [i32::MIN, -1, 0, 1, 2, i32::MAX] {
      let insns = [movi(0, 1), insn(opcode::JA32, 0, 0, 0, imm), exit()];
      let code = Insn::encode_all(&insns);
      s.check(&code, &plain_inputs(insns.len()));
    }
    s.finish_exercised("audit_branch_displacements_at_the_extremes");
  }

  /// A group whose base register is rewritten under it, then named again.
  /// The group is closed outright on a write to the base, rather than kept open
  /// against a written-register mask. Those are only the same decision if
  /// nothing later re-reads the state that closing it throws away.
  #[test]
  fn audit_a_group_whose_base_is_rewritten_and_then_named_again() {
    let insns = [
      // Leader off R2.
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
      // Redefine R2.
      insn(cls::ALU64 | alu::ADD, 2, 0, 0, 8),
      // A member naming the same leader and the same base.
      insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
      // A member naming the same leader but a different base.
      insn(cls::LDX | mode::MEM | size::DW, 4, 5, 8, 0),
      // And a member again on the original base.
      insn(cls::LDX | mode::MEM | size::DW, 6, 2, 8, 0),
      exit(),
    ];
    let code = Insn::encode_all(&insns);
    let plan = vec![
      PlanEntry {
        role: abi::plan_role::LEADER,
        region: abi::region::STACK,
        delta: 0,
        span: 64,
        lo: 0,
        leader_pc: 0,
      },
      PlanEntry::default(),
      PlanEntry {
        role: abi::plan_role::MEMBER,
        region: abi::region::STACK,
        delta: 8,
        span: 64,
        lo: 0,
        leader_pc: 0,
      },
      PlanEntry {
        role: abi::plan_role::MEMBER,
        region: abi::region::STACK,
        delta: 8,
        span: 64,
        lo: 0,
        leader_pc: 0,
      },
      PlanEntry {
        role: abi::plan_role::MEMBER,
        region: abi::region::STACK,
        delta: 8,
        span: 64,
        lo: 0,
        leader_pc: 0,
      },
      PlanEntry::default(),
    ];
    let inputs = TranslationInputs {
      plan: &plan,
      start_pc: 0,
      end_pc: insns.len(),
      ..Default::default()
    };
    assert!(check(&code, &inputs), "nothing was translated");
  }

  /// The set of opcode bytes `Op::from_opcode` accepts, against the frozen
  /// list of the 119 the backend is meant to handle.
  /// `every_defined_opcode_emits_code` proves the same thing only for bytes
  /// whose *operands* satisfy the validator in one of eight candidate shapes; a
  /// byte the validator refuses in all eight is invisible to it. This compares
  /// the decoder against the list directly, with no program in the way.
  #[test]
  fn audit_the_decoded_opcode_set_matches_what_the_emitter_handles() {
    // Every opcode byte translation has an arm for. A byte added here without a
    // corresponding arm, or the other way round, is what this test exists to
    // catch.
    const HANDLED: [u8; 119] = [
      0x04, 0x05, 0x06, 0x07, 0x0c, 0x0f, 0x14, 0x15, 0x16, 0x17, 0x18, 0x1c, 0x1d, 0x1e, 0x1f,
      0x24, 0x25, 0x26, 0x27, 0x2c, 0x2d, 0x2e, 0x2f, 0x34, 0x35, 0x36, 0x37, 0x3c, 0x3d, 0x3e,
      0x3f, 0x44, 0x45, 0x46, 0x47, 0x4c, 0x4d, 0x4e, 0x4f, 0x54, 0x55, 0x56, 0x57, 0x5c, 0x5d,
      0x5e, 0x5f, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
      0x6f, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
      0x81, 0x84, 0x85, 0x87, 0x89, 0x91, 0x94, 0x95, 0x97, 0x9c, 0x9f, 0xa4, 0xa5, 0xa6, 0xa7,
      0xac, 0xad, 0xae, 0xaf, 0xb4, 0xb5, 0xb6, 0xb7, 0xbc, 0xbd, 0xbe, 0xbf, 0xc3, 0xc4, 0xc5,
      0xc6, 0xc7, 0xcc, 0xcd, 0xce, 0xcf, 0xd4, 0xd5, 0xd6, 0xd7, 0xdb, 0xdc, 0xdd, 0xde,
    ];
    let expected: std::collections::BTreeSet<u8> = HANDLED.into_iter().collect();
    let decoded: std::collections::BTreeSet<u8> = (0u16..=255)
      .map(|b| b as u8)
      .filter(|b| crate::jit::isa::Op::from_opcode(*b).is_some())
      .collect();
    let extra: Vec<String> = decoded
      .difference(&expected)
      .map(|b| format!("{b:#04x}"))
      .collect();
    let missing: Vec<String> = expected
      .difference(&decoded)
      .map(|b| format!("{b:#04x}"))
      .collect();
    assert!(
      extra.is_empty() && missing.is_empty(),
      "the decoded opcode set has moved.\n  decoded but not listed: {extra:?}\n  \
       listed but not decoded: {missing:?}"
    );
  }

  /// The plan fast paths must actually be *taken* at the page-sized extreme,
  /// not merely agreed about.
  #[test]
  fn audit_a_page_wide_group_is_actually_taken() {
    let insns = [
      insn(cls::LDX | mode::MEM | size::DW, 1, 2, -4088, 0),
      insn(cls::LDX | mode::MEM | size::DW, 3, 2, 0, 0),
      exit(),
    ];
    let code = Insn::encode_all(&insns);
    let plan = [
      PlanEntry {
        role: abi::plan_role::LEADER,
        region: abi::region::STACK,
        delta: 0,
        span: 4096,
        lo: -4088,
        leader_pc: 0,
      },
      PlanEntry {
        role: abi::plan_role::MEMBER,
        region: abi::region::STACK,
        delta: 4088,
        span: 4096,
        lo: -4088,
        leader_pc: 0,
      },
      PlanEntry::default(),
    ];
    let planned = TranslationInputs {
      plan: &plan,
      start_pc: 0,
      end_pc: insns.len(),
      ..Default::default()
    };
    assert!(check(&code, &planned));
    assert!(check(&code, &plain_inputs(insns.len())));
    assert!(
      production_len(&code, &planned) < production_len(&code, &plain_inputs(insns.len())),
      "a page-wide group with delta at the very end of the window was declined, \
       so this case never exercised the member path"
    );
  }

  /// A second randomised sweep, in the shapes the first one cannot generate.
  /// `randomised_programs_hints_and_plans_match` builds one straight-line
  /// function, never emits a local call or an `lddw`, always translates the
  /// whole program, and draws plan fields from small ranges (`delta < 64`,
  /// `span < 8192`, `lo` in the `i16` range). This one does the opposite of each
  /// of those: two local functions with a real `call src=1` between them,
  /// `lddw` in the mix, a translation range that is sometimes a strict
  /// sub-range, and plan fields drawn from the whole of their types.
  #[test]
  fn audit_randomised_multi_function_programs_and_wide_plans_match() {
    let sizes = [size::B, size::H, size::W, size::DW];
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
    let jump_ops = [
      jmp::JEQ,
      jmp::JGT,
      jmp::JGE,
      jmp::JSET,
      jmp::JNE,
      jmp::JSGT,
      jmp::JSGE,
      jmp::JLT,
      jmp::JLE,
      jmp::JSLT,
      jmp::JSLE,
    ];

    let mut s = Sweep::new();

    // Kept small so this stays a fast test. It has been run over 20,000 seeds
    // in release and 6,000 in debug with overflow checks on, with no panic and
    // no unexplained refusal; set `AUDIT_SEEDS` to reproduce that. The rolled-up
    // golden covers a fixed number of cases, so it is only compared at the
    // default count — a widened run still exercises the emitter, it just has
    // nothing to compare itself against.
    const DEFAULT_SEEDS: u64 = 400;
    let seeds: u64 = std::env::var("AUDIT_SEEDS")
      .ok()
      .and_then(|s| s.parse().ok())
      .unwrap_or(DEFAULT_SEEDS);
    for seed in 1..=seeds {
      let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) | 1);

      // Body of the first function, then the call, then `exit`; then the second
      // function's body and its own `exit`.
      let body = |rng: &mut Rng, room: i16, out: &mut Vec<Insn>| {
        let n = 1 + rng.below(6) as usize;
        for k in 0..n {
          let class32 = rng.below(2) == 0;
          let alu_class = if class32 { cls::ALU } else { cls::ALU64 };
          let op = ops[rng.below(ops.len() as u64) as usize];
          let sz = sizes[rng.below(4) as usize];
          let left = room - k as i16;
          match rng.below(9) {
            0 => out.push(insn(alu_class | op, rng.reg(9), 0, 0, rng.next() as i32)),
            1 => out.push(insn(
              cls::LDX | mode::MEM | sz,
              rng.reg(9),
              rng.reg(10),
              rng.next() as i16,
              0,
            )),
            2 => out.push(insn(
              cls::STX | mode::MEM | sz,
              rng.reg(10),
              rng.reg(10),
              rng.next() as i16,
              0,
            )),
            3 => out.push(insn(
              cls::ST | mode::MEM | sz,
              rng.reg(10),
              0,
              rng.next() as i16,
              rng.next() as i32,
            )),
            4 => out.push(insn(
              if rng.below(2) == 0 {
                opcode::ATOMIC_STORE
              } else {
                opcode::ATOMIC32_STORE
              },
              rng.reg(10),
              rng.reg(9),
              rng.next() as i16,
              [0i32, 1, 0x41, 0x51, 0xa1, 0xe1, 0xf1][rng.below(7) as usize],
            )),
            5 => {
              // `lddw` occupies two slots; only emit it when there is room.
              if left >= 2 {
                out.push(insn(opcode::LDDW, rng.reg(9), 0, 0, rng.next() as i32));
                out.push(insn(0, 0, 0, 0, rng.next() as i32));
              } else {
                out.push(movi(rng.reg(9), rng.next() as i32));
              }
            }
            6 => out.push(insn(opcode::CALL, 0, 0, 0, rng.below(64) as i32)),
            7 => {
              let hop = rng.below(left.max(1) as u64) as i16;
              out.push(insn(
                cls::JMP | jump_ops[rng.below(jump_ops.len() as u64) as usize],
                rng.reg(9),
                0,
                hop,
                rng.next() as i32,
              ));
            }
            _ => out.push(insn(
              alu_class | op | srcbit::REG,
              rng.reg(9),
              rng.reg(10),
              0,
              0,
            )),
          }
        }
      };

      let mut first = Vec::new();
      body(&mut rng, 6, &mut first);
      let mut second = Vec::new();
      body(&mut rng, 6, &mut second);

      // pc of the second function's entry: after the first body, the call and
      // the first `exit`.
      let entry = first.len() + 2;
      let mut insns = first;
      // `call src=1` with imm = entry - pc - 1.
      let call_pc = insns.len();
      insns.push(insn(opcode::CALL, 0, 1, 0, (entry - call_pc - 1) as i32));
      insns.push(exit());
      insns.extend(second);
      insns.push(exit());

      let code = Insn::encode_all(&insns);
      let n = insns.len();

      let hints: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
      let plan: Vec<PlanEntry> = (0..n)
        .map(|_| PlanEntry {
          role: rng.next() as u8,
          region: rng.next() as u8,
          // The whole of each field's type, not a narrow window of it.
          delta: rng.next() as u16,
          span: rng.next() as u32,
          lo: rng.next() as i32,
          leader_pc: rng.next() as u32,
        })
        .collect();
      // Sometimes short, so the "no plan entry for this pc" path is taken too.
      let plan = &plan[..if rng.below(4) == 0 { n / 2 } else { n }];
      let ids: Vec<u32> = (0..n).map(|_| rng.next() as u32).collect();
      let ids = &ids[..if rng.below(8) == 0 { n / 2 } else { n }];

      for (start, end) in [(0usize, n), (0, entry), (entry, n)] {
        let inputs = TranslationInputs {
          hints: &hints,
          plan,
          resolver_ids: ids,
          start_pc: start,
          end_pc: end,
        };
        s.check(&code, &inputs);
      }
    }

    assert!(
      s.translated() * 4 >= s.cases(),
      "only {} of {} random multi-function programs translated; the generator \
       is producing programs the validator refuses rather than exercising the \
       emitter",
      s.translated(),
      s.cases()
    );
    if seeds == DEFAULT_SEEDS {
      s.finish("audit_randomised_multi_function_programs_and_wide_plans_match");
    }
  }

  /// The `LoadImm64` arm's zero fallback claims to be unreachable because the
  /// validator refuses a `lddw` in the program's last slot. Check that, rather
  /// than trusting it: the fallback is the only thing standing between such a
  /// program and a read past the end of the instruction array.
  #[test]
  fn audit_a_trailing_lddw_is_refused_at_load() {
    for tail in [
      vec![movi(0, 1), insn(opcode::LDDW, 3, 0, 0, 7)],
      vec![insn(opcode::LDDW, 3, 0, 0, 7)],
      vec![movi(0, 1), exit(), insn(opcode::LDDW, 3, 0, 0, 7)],
    ] {
      let code = Insn::encode_all(&tail);
      for (name, config) in sweep(Target::X86_64) {
        let loaded = Translator::load(Arc::new(config), &code);
        assert!(
          loaded.is_err(),
          "a program whose last slot is a `lddw` loaded under {name:?}; the \
           emitter would then fetch past the end of the instruction array"
        );
      }
    }
  }

  /// Every capacity from nothing to comfortably past the end, over a spread of
  /// programs, on the Rust side alone: the emitter must return `Ok` or `Err`,
  /// never panic — not on a `debug_assert`, not on an arithmetic overflow.
  /// Nothing is recorded here either: what is under test is that the emitter
  /// answers at all.
  ///
  /// The multi-function programs in the list are here because they used to be
  /// the ones that panicked — see
  /// `audit_out_of_space_inside_a_later_function_prologue` for what they hit.
  #[test]
  fn audit_no_capacity_makes_the_emitter_panic() {
    let programs: Vec<Vec<Insn>> = vec![
      vec![movi(0, 42), exit()],
      // Signed division, whose two rel8 back-patches are the shape that lands
      // out of bounds when the buffer ends between emitting the branch and
      // patching it.
      vec![insn(cls::ALU64 | alu::DIV, 1, 0, 1, -1), exit()],
      vec![insn(cls::ALU | alu::MOD, 1, 0, 1, -1), exit()],
      // A fetching atomic, whose loop branch is computed from `offset`.
      vec![insn(opcode::ATOMIC_STORE, 1, 0, 0, 0x01), exit()],
      // Two local functions, so a later prologue is measured.
      vec![insn(opcode::CALL, 0, 1, 0, 1), exit(), movi(0, 7), exit()],
      // Three, so a third prologue is too.
      vec![
        insn(opcode::CALL, 0, 1, 0, 1),
        exit(),
        insn(opcode::CALL, 0, 1, 0, 1),
        exit(),
        movi(0, 7),
        exit(),
      ],
      // A helper call, with its RIP-relative load of the dispatcher slot.
      vec![movi(1, 0), insn(opcode::CALL, 0, 0, 0, 3), exit()],
      // A forward and a backward branch.
      vec![
        movi(0, 1),
        insn(cls::JMP | jmp::JEQ, 1, 0, 1, 0),
        movi(0, 2),
        insn(cls::JMP | jmp::JNE, 1, 0, -3, 0),
        exit(),
      ],
      // A grouped pair of accesses.
      vec![
        insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
        insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
        exit(),
      ],
    ];
    let plan = [
      PlanEntry {
        role: abi::plan_role::LEADER,
        region: abi::region::STACK,
        delta: 0,
        span: 16,
        lo: 0,
        leader_pc: 0,
      },
      PlanEntry {
        role: abi::plan_role::MEMBER,
        region: abi::region::STACK,
        delta: 8,
        span: 16,
        lo: 0,
        leader_pc: 0,
      },
      PlanEntry::default(),
      PlanEntry::default(),
      PlanEntry::default(),
      PlanEntry::default(),
    ];
    let mut panicked = Vec::new();
    for (pi, insns) in programs.iter().enumerate() {
      let code = Insn::encode_all(insns);
      let n = insns.len();
      for capacity in 0..900usize {
        for (name, config) in sweep(Target::X86_64) {
          let code = code.clone();
          let ids = vec![7u32; n];
          let hints = vec![abi::region::UNKNOWN; n];
          let plan = plan;
          let outcome = std::panic::catch_unwind(move || {
            let inputs = TranslationInputs {
              hints: &hints,
              plan: &plan[..n.min(plan.len())],
              resolver_ids: &ids,
              start_pc: 0,
              end_pc: n,
            };
            let t = match crate::jit::Translator::load(std::sync::Arc::new(config), &code) {
              Ok(t) => t,
              Err(_) => return,
            };
            let mut buf = vec![0u8; capacity];
            let _ = t.translate_range(&inputs, &mut buf);
          });
          if outcome.is_err() {
            panicked.push((pi, capacity, name));
          }
        }
      }
    }
    assert!(
      panicked.is_empty(),
      "the emitter panicked at {} (program, capacity, config) combinations; \
       first {:?}",
      panicked.len(),
      &panicked[..panicked.len().min(10)]
    );
  }

  /// A branch whose target is the *second slot of an `lddw`*.
  /// That slot is never given a `pc_locs` entry — the driver skips past it — so
  /// the branch resolves against a zero slot and is retargeted to offset 0 of
  /// the emitted function, which is the per-function prologue. Stable bytes say
  /// nothing about that; what matters is whether such a program can load at
  /// all.
  #[test]
  fn audit_a_branch_into_the_middle_of_an_lddw() {
    let insns = [
      movi(1, 0),
      // Targets pc 3, which is the high half of the `lddw` at pc 2.
      insn(cls::JMP | jmp::JEQ, 1, 0, 1, 0),
      insn(opcode::LDDW, 2, 0, 0, 1),
      insn(0, 0, 0, 0, 0),
      exit(),
    ];
    let code = Insn::encode_all(&insns);
    let loads = Translator::load(Arc::new(production_config()), &code).is_ok();
    // Whatever the answer, the emitted bytes are pinned.
    check(&code, &plain_inputs(insns.len()));
    assert!(
      !loads,
      "a branch into the second slot of an `lddw` loaded; the branch is then \
       resolved against pc_locs[3] == 0 and jumps to offset 0 of the function, \
       which re-runs the per-function prologue"
    );
  }

  /// Configurations the sweep never builds.
  /// [`sweep`] fixes five points in a space with rather more dimensions than
  /// that: it never turns the external dispatcher off, and never sets
  /// `native_frame_base` or `frame_constants` while the cage is *disabled*.
  /// Each of those changes what is emitted, or what is emitted around it.
  #[test]
  fn audit_configurations_outside_the_sweep() {
    let base = base_config(Target::X86_64);

    let mut configs: Vec<(String, Config)> = Vec::new();

    // No external dispatcher at all: the trailer's dispatcher slot holds 0, and
    // the validator refuses every helper call, so no program that reads the
    // slot can load. What the sweep is pinning here is the rest of the emitted
    // code under that configuration.
    configs.push((
      "no dispatcher".into(),
      Config {
        pointer_mask: 0x0fff_ffff,
        pointer_offset: 0x1_0000_0000,
        native_frame_base: true,
        frame_constants: true,
        dispatcher: None,
        dispatcher_validate: None,
        ..base.clone()
      },
    ));

    // The frame promises made while the cage is off, which is what
    // `native_frame_base_active()` and `access_plans_active()` are for.
    for (nfb, fc) in [(true, false), (false, true), (true, true)] {
      configs.push((
        format!("no cage, native_frame_base={nfb}, frame_constants={fc}"),
        Config {
          pointer_mask: 0,
          pointer_offset: 0,
          native_frame_base: nfb,
          frame_constants: fc,
          ..base.clone()
        },
      ));
    }

    // A pointer mask other than the one the sweep uses, including the sign bit.
    for mask in [1i32, -1, i32::MIN, i32::MAX] {
      configs.push((
        format!("pointer mask {mask:#x}"),
        Config {
          pointer_mask: mask,
          pointer_offset: 0x1_0000_0000,
          native_frame_base: true,
          frame_constants: true,
          ..base.clone()
        },
      ));
    }

    let programs: Vec<Vec<Insn>> = vec![
      vec![movi(1, 0), insn(opcode::CALL, 0, 0, 0, 0), exit()],
      vec![movi(1, 0), insn(opcode::CALL, 0, 0, 0, 1), exit()],
      vec![movi(1, 0), insn(opcode::CALL, 0, 0, 0, 3), exit()],
      vec![movi(1, 0), insn(opcode::CALL, 0, 0, 0, 63), exit()],
      vec![insn(cls::LDX | mode::MEM | size::DW, 1, 10, -8, 0), exit()],
      vec![insn(cls::STX | mode::MEM | size::B, 1, 10, 0, 0), exit()],
      vec![insn(opcode::ATOMIC_STORE, 1, 2, 8, 0x01), exit()],
      vec![
        insn(cls::LDX | mode::MEM | size::DW, 1, 2, 0, 0),
        insn(cls::LDX | mode::MEM | size::DW, 3, 2, 8, 0),
        exit(),
      ],
      vec![insn(opcode::CALL, 0, 1, 0, 1), exit(), movi(0, 7), exit()],
    ];
    let plan = [
      PlanEntry {
        role: abi::plan_role::LEADER,
        region: abi::region::STACK,
        delta: 0,
        span: 16,
        lo: 0,
        leader_pc: 0,
      },
      PlanEntry {
        role: abi::plan_role::MEMBER,
        region: abi::region::STACK,
        delta: 8,
        span: 16,
        lo: 0,
        leader_pc: 0,
      },
      PlanEntry::default(),
      PlanEntry::default(),
    ];
    let mut emitted = 0usize;
    let mut refused: Vec<String> = Vec::new();
    let mut digest = golden::SweepDigest::new();
    arm_flush();
    for insns in &programs {
      let code = Insn::encode_all(insns);
      let n = insns.len();
      let ids = vec![9u32; n];
      let hints = vec![abi::region::FRAME; n];
      for (name, config) in &configs {
        let inputs = TranslationInputs {
          hints: &hints,
          plan: &plan[..n.min(plan.len())],
          resolver_ids: &ids,
          start_pc: 0,
          end_pc: n,
        };
        let out = emit_outcome(config, &code, &inputs);
        if out.is_ok() {
          emitted += 1;
        } else {
          refused.push(format!("{name}: {out:?}"));
        }
        digest.add(&out);
      }
    }
    digest.finish("audit_configurations_outside_the_sweep", Target::X86_64);
    // Agreement about a refusal is not agreement about the emitted code.
    assert!(
      emitted * 2 >= programs.len() * configs.len(),
      "only {emitted} of {} (program, config) pairs actually emitted code; \
       refusals: {:#?}",
      programs.len() * configs.len(),
      &refused[..refused.len().min(20)]
    );
  }

  /// A program big enough that branch displacements need all four bytes and
  /// `pc_locs` is exercised at scale.
  /// Every existing test program is a handful of instructions; the randomised
  /// sweep caps at 25. Nothing checks that a function whose emitted body runs to
  /// tens of kilobytes still resolves its relocations identically.
  #[test]
  fn audit_a_large_function_matches() {
    let mut insns = Vec::new();
    // A long forward branch over the whole body, and a long backward one at the
    // end, with plenty of bounds-checked accesses in between to inflate it.
    insns.push(insn(cls::JMP | jmp::JNE, 1, 0, 4000, 1));
    for k in 0..4000u32 {
      let dst = (k % 10) as u8;
      match k % 5 {
        0 => insns.push(insn(cls::ALU64 | alu::ADD, dst, 0, 0, k as i32)),
        1 => insns.push(insn(
          cls::LDX | mode::MEM | size::DW,
          dst,
          2,
          (k % 400) as i16,
          0,
        )),
        2 => insns.push(insn(
          cls::STX | mode::MEM | size::W,
          2,
          dst,
          (k % 400) as i16,
          0,
        )),
        3 => insns.push(insn(cls::ALU | alu::XOR | srcbit::REG, dst, 3, 0, 0)),
        _ => insns.push(insn(cls::ALU64 | alu::MUL, dst, 0, 0, 3)),
      }
    }
    insns.push(insn(cls::JMP | jmp::JEQ, 1, 0, -4001, 1));
    insns.push(exit());

    let code = Insn::encode_all(&insns);
    let n = insns.len();
    let hints: Vec<u8> = (0..n).map(|i| (i % 4) as u8).collect();
    let plan: Vec<PlanEntry> = (0..n)
      .map(|i| {
        if i % 5 == 1 {
          PlanEntry {
            role: abi::plan_role::LEADER,
            region: abi::region::STACK,
            delta: 0,
            span: 2048,
            lo: (i as i32 % 400),
            leader_pc: i as u32,
          }
        } else {
          PlanEntry::default()
        }
      })
      .collect();
    let inputs = TranslationInputs {
      hints: &hints,
      plan: &plan,
      start_pc: 0,
      end_pc: n,
      ..Default::default()
    };
    let capacity = 8 * 1024 * 1024;
    for (name, config) in sweep(Target::X86_64) {
      assert!(
        check_one(&slug(name), &config, &code, &inputs, capacity),
        "the large function did not translate under {name:?}"
      );
      let len = emitted_len(&config, &code, &inputs, capacity);
      assert!(
        len > 30_000,
        "the large program did not translate into a large function under \
         {name:?}: {len} bytes"
      );
    }
  }
}

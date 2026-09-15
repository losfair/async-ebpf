//! The x86_64 backend's encoder.
//!
//! Translating one function happens in three layers, and only the last of them
//! is here:
//!
//! ```text
//!   eBPF program + hints + plan
//!     │  verified::x64_lower::lower    the decisions
//!     ▼
//!   Vec<MInsn>   macro instructions
//!     │  verified::x64_expand::expand  each macro's native sequence
//!     ▼
//!   Vec<PInsn>   one per x86 instruction
//!     │  encode                        bytes, and the relative-branch fixups
//!     ▼
//!   bytes in the code arena
//! ```
//!
//! The first two layers are in the verified core, which `lean/AsyncEbpf/X64/`
//! is about; see `docs/jit-memory-safety.md`. This module is the adapter around
//! them: it builds the three descriptions they take from the [`Translator`],
//! renders each [`Reject`] as the message embedders match on, and encodes the
//! primitives. [`encode`] is a table with no decisions left in it — which is
//! what makes it reviewable by reading the goldens.
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
//!   [instruction stream]
//!   exit_loc:  add rsp, 8 ; ret
//!   retpoline
//!   external dispatcher address     (8 bytes)
//!   helper table                    (64 * 8 bytes)
//! ```
//!
//! Everything after the instruction stream is emitted unconditionally, which is
//! why even a two-instruction program is around 600 bytes.
//!
//! # Reporting order
//!
//! A function whose *lowering* fails is refused before the buffer is consulted,
//! so a program that would never translate is no longer reported as
//! `OutOfSpace` when the buffer is also too small. `OutOfSpace` is terminal for
//! the whole program and a translation failure is terminal for one function, so
//! the two are not interchangeable to the caller.

use crate::jit::abi;
use crate::jit::{Config, TranslateError, TranslationInputs, Translator};

use crate::verified::x64_expand::expand;
use crate::verified::x64_ir::{
  AluRI, AluRM, AluRR, Cfg, MulDivKind, PInsn, PTarget, ShiftOp, Size, MAX_EXT_FUNCS,
};
use crate::verified::x64_lower::{lower, Reject};

use crate::verified::x64_ir::{R12, R13, RBP, RCX, RSP};

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/// Entry point: lower, expand, encode.
pub fn translate_range(
  t: &Translator,
  inputs: &TranslationInputs<'_>,
  buffer: &mut [u8],
) -> Result<usize, TranslateError> {
  let config = t.config();
  let cfg = translation_config(config);
  let insns = t.insns();

  // The core reads the per-function guest stack charge out of a table, so fill
  // in every entry the range can reach. A range the core will refuse is
  // clamped here rather than indexed past the end.
  let mut stack_usage = vec![0u16; insns.len()];
  let last = inputs.end_pc.min(insns.len());
  let mut i = inputs.start_pc;
  while i < last {
    if i == 0 || t.is_local_func_entry(i) {
      stack_usage[i] = t.stack_usage_for(i);
    }
    i += 1;
  }

  let mut macros = Vec::new();
  let lowered = lower(
    &cfg,
    insns,
    t.local_func_entries(),
    t.external_local_calls(),
    &stack_usage,
    inputs.hints,
    inputs.plan,
    inputs.resolver_ids,
    inputs.start_pc,
    inputs.end_pc,
    &mut macros,
  );
  if let Err(reject) = lowered {
    return Err(TranslateError::Failed(render(reject, inputs)));
  }

  let mut primitives = Vec::new();
  expand(&cfg, &macros, &mut primitives);
  encode(&primitives, buffer)
}

/// The facts about a [`Config`] the backend consults.
fn translation_config(config: &Config) -> Cfg {
  Cfg {
    pointer_mask: config.pointer_mask,
    native_frame_base: config.native_frame_base,
    frame_constants: config.frame_constants,
    stack_frame_size: config.stack_frame_size,
    stack_frame_stride: config.stack_frame_stride,
    dispatcher: match config.dispatcher {
      Some(f) => f as usize as u64,
      None => 0,
    },
    // The unset index is -1, so a `call -1` really does take the unwind path
    // when no index is configured.
    unwind_helper_index: match config.unwind_helper_index {
      Some(i) => i as i32,
      None => -1,
    },
    has_local_call_callbacks: config.local_call_resolver.is_some()
      && config.local_call_stack_exhausted.is_some(),
    local_call_resolver: match config.local_call_resolver {
      Some(f) => f as usize as u64,
      None => 0,
    },
    local_call_stack_exhausted: match config.local_call_stack_exhausted {
      Some(f) => f as usize as u64,
      None => 0,
    },
  }
}

/// The message for one refusal, worded exactly as embedders expect.
///
/// The wording is compared by callers and folded into the recorded decision
/// digests, so it is part of the contract rather than a diagnostic detail.
fn render(reject: Reject, inputs: &TranslationInputs<'_>) -> String {
  let start_pc = inputs.start_pc;
  let end_pc = inputs.end_pc;
  match reject {
    Reject::InvalidRange => format!("Invalid function range [{start_pc}, {end_pc})"),
    Reject::RangeStartNotEntry => {
      format!("Function range start {start_pc} is not a local function entry")
    }
    Reject::RangeEndNotBoundary => {
      format!("Function range end {end_pc} is not a local function boundary")
    }
    Reject::JumpOutOfRange { pc, target } => format!(
      "jump target {target} at PC {pc} is outside the translation range [{start_pc}, {end_pc})"
    ),
    Reject::UnknownInstruction { pc, opcode } => {
      format!("Unknown instruction at PC {pc}: opcode {opcode:02x}")
    }
    // The trailing newline is part of this one.
    Reject::UnknownAtomic { pc, imm } => {
      format!("Error: unknown atomic opcode {imm} at PC {pc}\n")
    }
    Reject::UnexpectedInstruction => {
      "Unexpected instruction or missing local-call runtime callbacks during JIT compilation"
        .to_string()
    }
    // No full stop, unlike aarch64's wording of the same three.
    Reject::TooManyJumps => "Too many jump instructions".to_string(),
    Reject::TooManyLoads => "Too many load instructions".to_string(),
    Reject::TooManyLeas => "Too many LEA calculations".to_string(),
    Reject::TrailerFailed => "Failure to emit the function epilogue".to_string(),
    Reject::Unsafe { pc } => {
      format!("generated code failed the memory-safety check at PC {pc}")
    }
  }
}

// ---------------------------------------------------------------------------
// Fixups
// ---------------------------------------------------------------------------

/// What a reserved displacement is measured against.
#[derive(Copy, Clone)]
enum Site {
  /// A branch, whose target the primitive names.
  Branch(PTarget),
  /// The eight bytes of the trailer holding the dispatcher's address.
  Dispatcher,
  /// The trailer's helper address table.
  HelperTable,
}

/// How a reserved displacement is written.
#[derive(Copy, Clone)]
enum Width {
  /// Four bytes, measured from just past them.
  Rel32,
  /// One byte, measured from just past it, with three bytes of padding after.
  /// Out of range refuses the function.
  Rel8Padded,
  /// One byte, measured from just past it, with nothing after.
  Rel8,
}

struct Fixup {
  at: u32,
  width: Width,
  site: Site,
}

// ---------------------------------------------------------------------------
// The encoder
// ---------------------------------------------------------------------------

/// Encodes a primitive list, writing it into `buffer`.
///
/// The bytes are built in full first and copied out once, so a buffer too small
/// is one comparison rather than a partially written function.
pub fn encode(code: &[PInsn], buffer: &mut [u8]) -> Result<usize, TranslateError> {
  let mut e = Enc::new(code);
  let mut i = 0;
  while i < code.len() {
    e.one(code[i]);
    i += 1;
  }
  if !e.resolve() {
    return Err(TranslateError::Failed(
      "Could not patch the relative addresses in the JIT'd code".to_string(),
    ));
  }
  if e.buf.len() > buffer.len() {
    return Err(TranslateError::OutOfSpace);
  }
  buffer[..e.buf.len()].copy_from_slice(&e.buf);
  Ok(e.buf.len())
}

struct Enc {
  buf: Vec<u8>,
  /// Native offset of each eBPF slot that was labelled. A slot that was never
  /// labelled reads as zero, as the fixup pass has always treated it.
  pc_locs: Vec<u32>,
  local_locs: Vec<u32>,
  exit_loc: u32,
  retpoline_loc: u32,
  dispatcher_loc: u32,
  helper_table_loc: u32,
  fixups: Vec<Fixup>,
}

impl Enc {
  fn new(code: &[PInsn]) -> Enc {
    let mut max_pc = 0u32;
    let mut max_local = 0u32;
    for insn in code {
      match *insn {
        PInsn::PcLabel(pc) => {
          if pc >= max_pc {
            max_pc = pc + 1;
          }
        }
        PInsn::Local(n) => {
          if n >= max_local {
            max_local = n + 1;
          }
        }
        _ => {}
      }
    }
    Enc {
      buf: Vec::new(),
      pc_locs: vec![0; max_pc as usize],
      local_locs: vec![0; max_local as usize],
      exit_loc: 0,
      retpoline_loc: 0,
      dispatcher_loc: 0,
      helper_table_loc: 0,
      fixups: Vec::new(),
    }
  }

  // -------------------------------------------------------------------------
  // Bytes
  // -------------------------------------------------------------------------

  #[inline]
  fn emit1(&mut self, x: u8) {
    self.buf.push(x);
  }

  #[inline]
  fn emit2(&mut self, x: u16) {
    self.buf.extend_from_slice(&x.to_le_bytes());
  }

  #[inline]
  fn emit4(&mut self, x: u32) {
    self.buf.extend_from_slice(&x.to_le_bytes());
  }

  #[inline]
  fn emit8(&mut self, x: u64) {
    self.buf.extend_from_slice(&x.to_le_bytes());
  }

  #[inline]
  fn offset(&self) -> u32 {
    self.buf.len() as u32
  }

  fn emit_modrm(&mut self, md: u8, r: u8, m: u8) {
    self.emit1((md & 0xc0) | ((r & 7) << 3) | (m & 7));
  }

  fn emit_modrm_reg2reg(&mut self, r: u8, m: u8) {
    self.emit_modrm(0xc0, r, m);
  }

  /// ModRM plus displacement, with the zero-displacement shortcut. Two
  /// irregular cases matter:
  ///
  /// * `RBP`/`R13` cannot encode a bare `[base]`, so they always get an
  ///   explicit displacement even when it is zero;
  /// * `R12` needs a SIB byte, emitted as `0x24`.
  ///
  /// `RSP` and `R12` share the low three bits that ModRM encodes, and both
  /// therefore need the SIB byte. No caller passes `RSP` as a base — the
  /// sequences that address the host stack emit their ModRM and SIB bytes
  /// literally — so emitting it for `R12` alone produces correct code.
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

  fn emit_alu(&mut self, w64: bool, op: u8, src: u8, dst: u8) {
    self.emit_basic_rex(u8::from(w64), src, dst);
    self.emit1(op);
    self.emit_modrm_reg2reg(src, dst);
  }

  /// `load [src + offset] -> dst`, zero-extending for the narrow widths.
  fn emit_load(&mut self, size: Size, src: u8, dst: u8, offset: i32) {
    self.emit_basic_rex(u8::from(size == 8), dst, src);
    if size == 1 {
      self.emit1(0x0f);
      self.emit1(0xb6);
    } else if size == 2 {
      self.emit1(0x0f);
      self.emit1(0xb7);
    } else {
      self.emit1(0x8b);
    }
    self.emit_modrm_and_displacement(dst, src, offset);
  }

  /// `load [src + offset] -> dst`, sign-extending to 64 bits. The
  /// doubleword form emits nothing at all: there is no `ldxdwsx` encoding, so
  /// no caller reaches it.
  fn emit_load_sx(&mut self, size: Size, src: u8, dst: u8, offset: i32) {
    if size == 8 {
      return;
    }
    self.emit_basic_rex(1, dst, src);
    if size == 4 {
      self.emit1(0x63);
    } else {
      self.emit1(0x0f);
      self.emit1(if size == 1 { 0xbe } else { 0xbf });
    }
    self.emit_modrm_and_displacement(dst, src, offset);
  }

  /// `store src -> [dst + offset]`.
  ///
  /// The byte-width term in the REX condition is what makes a byte store
  /// through `SIL`/`DIL`/`SPL`/`BPL` name the right register: without a REX
  /// prefix those encodings mean `AH`/`CH`/`DH`/`BH`.
  fn emit_store(&mut self, size: Size, src: u8, dst: u8, offset: i32) {
    if size == 2 {
      self.emit1(0x66);
    }
    let rexw = u8::from(size == 8);
    if rexw != 0 || (src & 8) != 0 || (dst & 8) != 0 || size == 1 {
      self.emit_rex(rexw, u8::from(src & 8 != 0), 0, u8::from(dst & 8 != 0));
    }
    self.emit1(if size == 1 { 0x88 } else { 0x89 });
    self.emit_modrm_and_displacement(src, dst, offset);
  }

  /// `store imm -> [dst + offset]`.
  fn emit_store_imm(&mut self, size: Size, dst: u8, offset: i32, imm: i32) {
    if size == 2 {
      self.emit1(0x66);
    }
    self.emit_basic_rex(u8::from(size == 8), 0, dst);
    self.emit1(if size == 1 { 0xc6 } else { 0xc7 });
    self.emit_modrm_and_displacement(0, dst, offset);
    if size == 1 {
      self.emit1(imm as u8);
    } else if size == 2 {
      self.emit2(imm as u16);
    } else {
      self.emit4(imm as u32);
    }
  }

  /// Materialises a 64-bit immediate, preferring the sign-extended 32-bit
  /// form.
  fn emit_load_imm(&mut self, dst: u8, imm: i64) {
    if (i32::MIN as i64..=i32::MAX as i64).contains(&imm) {
      self.emit_alu(true, 0xc7, 0, dst);
      self.emit4(imm as u32);
      return;
    }
    self.emit_basic_rex(1, 0, dst);
    self.emit1(0xb8 | (dst & 7));
    self.emit8(imm as u64);
  }

  /// Reserves the bytes a relative displacement needs and records its fixup.
  fn reserve(&mut self, width: Width, site: Site) {
    let at = self.offset();
    self.fixups.push(Fixup { at, width, site });
    // A near jump still reserves four bytes, so three are wasted after every
    // one. They are never executed — the jump is unconditional and lands past
    // them — so this costs code size and nothing else.
    match width {
      Width::Rel8 => self.emit1(0),
      _ => self.emit4(0),
    }
  }

  // -------------------------------------------------------------------------
  // One primitive
  // -------------------------------------------------------------------------

  fn one(&mut self, insn: PInsn) {
    match insn {
      PInsn::PcLabel(pc) => {
        let here = self.offset();
        self.pc_locs[pc as usize] = here;
      }
      PInsn::Local(n) => {
        let here = self.offset();
        self.local_locs[n as usize] = here;
      }
      PInsn::ExitLabel => self.exit_loc = self.offset(),
      PInsn::RetpolineLabel => self.retpoline_loc = self.offset(),

      PInsn::Push(r) => {
        self.emit_basic_rex(0, 0, r);
        self.emit1(0x50 | (r & 7));
      }
      PInsn::Pop(r) => {
        self.emit_basic_rex(0, 0, r);
        self.emit1(0x58 | (r & 7));
      }
      PInsn::Alu { w64, op, src, dst } => self.emit_alu(w64, alu_rr_opcode(op), src, dst),
      PInsn::AluImm { w64, op, dst, imm } => {
        let (opcode, ext) = alu_ri_opcode(op);
        self.emit_alu(w64, opcode, ext, dst);
        self.emit4(imm as u32);
      }
      PInsn::ShiftImm { w64, op, dst, imm } => {
        self.emit_alu(w64, 0xc1, shift_ext(op), dst);
        // The shift count is a byte, so the immediate is truncated here.
        self.emit1(imm as u8);
      }
      PInsn::ShiftCl { w64, op, dst } => self.emit_alu(w64, 0xd3, shift_ext(op), dst),
      PInsn::Neg { w64, dst } => self.emit_alu(w64, 0xf7, 3, dst),
      PInsn::MulDivRcx { w64, kind, signed } => {
        if w64 {
          self.emit_rex(1, 0, 0, 0);
        }
        // `/4` is MUL, `/6` DIV and `/7` IDIV.
        let ext = match kind {
          MulDivKind::Mul => 4,
          _ => {
            if signed {
              7
            } else {
              6
            }
          }
        };
        self.emit_alu(false, 0xf7, ext, RCX);
      }
      PInsn::MovSx {
        from,
        w64,
        src,
        dst,
      } => {
        // The explicit REX is what makes a byte source name `SIL`/`DIL`/
        // `SPL`/`BPL` rather than `AH`/`CH`/`DH`/`BH`, so it is emitted even
        // when no high-register bit is set.
        if w64 || from == 8 {
          self.emit_rex(
            u8::from(w64),
            u8::from(dst & 8 != 0),
            0,
            u8::from(src & 8 != 0),
          );
        } else {
          self.emit_basic_rex(0, dst, src);
        }
        if from == 32 {
          self.emit1(0x63);
        } else {
          self.emit1(0x0f);
          self.emit1(if from == 8 { 0xbe } else { 0xbf });
        }
        self.emit_modrm_reg2reg(dst, src);
      }
      PInsn::Bswap { w64, dst } => {
        self.emit_basic_rex(u8::from(w64), 0, dst);
        self.emit1(0x0f);
        self.emit1(0xc8 | (dst & 7));
      }
      PInsn::Rol16 { dst } => {
        self.emit1(0x66);
        self.emit_alu(false, 0xc1, 0, dst);
        self.emit1(8);
      }
      PInsn::Cmov { cc, dst, src } => {
        self.emit_basic_rex(1, dst, src);
        self.emit1(0x0f);
        // `cmovcc` is the `0x4x` row of the same condition table the near
        // `jcc` forms name in the `0x8x` row.
        self.emit1(0x40 | (cc & 0x0f));
        self.emit_modrm_reg2reg(dst, src);
      }
      PInsn::LoadImm { dst, imm } => self.emit_load_imm(dst, imm),
      PInsn::Pushfq => self.emit1(0x9c),
      PInsn::Popfq => self.emit1(0x9d),
      PInsn::Cqo => {
        self.emit1(0x48);
        self.emit1(0x99);
      }
      PInsn::Cdq => self.emit1(0x99),
      PInsn::CmpRcxMinusOne { w64 } => {
        if w64 {
          self.emit1(0x48);
        }
        self.emit1(0x83);
        self.emit1(0xf9);
        self.emit1(0xff);
      }
      PInsn::CmpEaxImm { imm } => {
        self.emit1(0x3d);
        self.emit4(imm);
      }

      PInsn::Load {
        size,
        sx,
        base,
        dst,
        disp,
      } => {
        if sx {
          self.emit_load_sx(size, base, dst, disp);
        } else {
          self.emit_load(size, base, dst, disp);
        }
      }
      PInsn::Store {
        size,
        src,
        base,
        disp,
      } => self.emit_store(size, src, base, disp),
      PInsn::StoreImm {
        size,
        base,
        disp,
        imm,
      } => self.emit_store_imm(size, base, disp, imm),
      PInsn::AluRM {
        op,
        reg,
        base,
        disp,
      } => {
        self.emit_basic_rex(1, reg, base);
        self.emit1(alu_rm_opcode(op));
        self.emit_modrm_and_displacement(reg, base, disp);
      }
      PInsn::StoreRspImm { imm } => {
        // The ModRM/SIB pair for an `[rsp]` base is emitted literally.
        self.emit1(0x48);
        self.emit1(0xc7);
        self.emit1(0x04);
        self.emit1(0x24);
        self.emit4(imm);
      }
      PInsn::StoreRspRax => {
        self.emit1(0x48);
        self.emit1(0x89);
        self.emit1(0x04);
        self.emit1(0x24);
      }

      PInsn::LockAlu {
        op,
        w64,
        src,
        base,
        disp,
      } => {
        self.emit1(0xf0);
        self.emit_basic_rex(u8::from(w64), src, base);
        self.emit1(op);
        self.emit_modrm_and_displacement(src, base, disp);
      }
      PInsn::LockCmpxchg {
        w64,
        src,
        base,
        disp,
      } => {
        self.emit1(0xf0);
        self.emit_basic_rex(u8::from(w64), src, base);
        self.emit1(0x0f);
        self.emit1(0xb1);
        self.emit_modrm_and_displacement(src, base, disp);
      }
      PInsn::Xchg {
        w64,
        src,
        base,
        disp,
      } => {
        // `xchg` with a memory operand is implicitly locked; the prefix is
        // emitted anyway.
        self.emit1(0xf0);
        self.emit_basic_rex(u8::from(w64), src, base);
        self.emit1(0x87);
        self.emit_modrm_and_displacement(src, base, disp);
      }

      PInsn::Jcc { cc, target } => {
        self.emit1(0x0f);
        self.emit1(cc);
        self.reserve(Width::Rel32, Site::Branch(target));
      }
      PInsn::Jmp { target } => {
        self.emit1(0xe9);
        self.reserve(Width::Rel32, Site::Branch(target));
      }
      PInsn::JmpNear { target } => {
        self.emit1(0xeb);
        self.reserve(Width::Rel8Padded, Site::Branch(target));
      }
      PInsn::Call { target } => {
        self.emit1(0xe8);
        self.reserve(Width::Rel32, Site::Branch(target));
      }
      PInsn::Jcc8 { cc, target } => {
        self.emit1(0x70 | (cc & 0x0f));
        self.reserve(Width::Rel8, Site::Branch(PTarget::Local(target)));
      }
      PInsn::Jmp8 { target } => {
        self.emit1(0xeb);
        self.reserve(Width::Rel8, Site::Branch(PTarget::Local(target)));
      }
      PInsn::Ret => self.emit1(0xc3),
      PInsn::Pause => {
        self.emit1(0xf3);
        self.emit1(0x90);
      }
      PInsn::Ud2 => {
        self.emit1(0x0f);
        self.emit1(0x0b);
      }
      PInsn::CallReg(reg) => {
        if reg & 8 != 0 {
          self.emit1(0x41);
        }
        self.emit1(0xff);
        self.emit1(0xd0 | (reg & 7));
      }
      PInsn::RipLoadDispatcher { dst } => {
        // The REX `R` bit is zero: the only destination is RAX.
        self.emit_rex(1, 0, 0, 0);
        self.emit1(0x8b);
        self.emit_modrm(0, dst, 0x05);
        self.reserve(Width::Rel32, Site::Dispatcher);
      }
      PInsn::RipLeaHelperTable { dst } => {
        self.emit_rex(1, u8::from(dst & 8 != 0), 0, 0);
        self.emit1(0x8d);
        self.emit_modrm(0, dst, 0x05);
        self.reserve(Width::Rel32, Site::HelperTable);
      }

      PInsn::DispatcherSlot { addr } => {
        self.dispatcher_loc = self.offset();
        self.emit8(addr);
      }
      PInsn::HelperTable => {
        self.helper_table_loc = self.offset();
        // `async-ebpf` never registers individual helpers — it uses the
        // dispatcher — so every entry is null. The table is emitted anyway
        // because the default dispatch path indexes into it and the trailer's
        // layout is part of the ABI the runtime patches through.
        let mut k = 0;
        while k < MAX_EXT_FUNCS {
          self.emit8(0);
          k += 1;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Relocation
  // -------------------------------------------------------------------------

  /// Where a fixup's site landed.
  fn site_loc(&self, site: Site) -> u32 {
    match site {
      Site::Dispatcher => self.dispatcher_loc,
      Site::HelperTable => self.helper_table_loc,
      Site::Branch(PTarget::Exit) => self.exit_loc,
      Site::Branch(PTarget::Retpoline) => self.retpoline_loc,
      Site::Branch(PTarget::Local(n)) => self.local_locs[n as usize],
      // A slot that was never labelled resolves to the top of the function.
      Site::Branch(PTarget::Pc(pc)) => self.pc_locs.get(pc as usize).copied().unwrap_or(0),
    }
  }

  /// Writes every reserved displacement. Returns false when a near jump does
  /// not reach, which the caller turns into a failure.
  fn resolve(&mut self) -> bool {
    let fixups = std::mem::take(&mut self.fixups);
    for fixup in &fixups {
      let target = self.site_loc(fixup.site);
      let at = fixup.at as usize;
      match fixup.width {
        Width::Rel32 => {
          let rel = target.wrapping_sub(fixup.at.wrapping_add(4));
          self.buf[at..at + 4].copy_from_slice(&rel.to_le_bytes());
        }
        Width::Rel8Padded => {
          let rel = target as i64 - (fixup.at as i64 + 1);
          if !(-128..128).contains(&rel) {
            return false;
          }
          self.buf[at] = rel as i8 as u8;
        }
        Width::Rel8 => {
          let rel = target.wrapping_sub(fixup.at).wrapping_sub(1);
          self.buf[at] = rel as u8;
        }
      }
    }
    self.fixups = fixups;
    true
  }
}

/// The register-form opcode byte for each ALU operation.
fn alu_rr_opcode(op: AluRR) -> u8 {
  match op {
    AluRR::Add => 0x01,
    AluRR::Sub => 0x29,
    AluRR::Or => 0x09,
    AluRR::And => 0x21,
    AluRR::Xor => 0x31,
    AluRR::Mov => 0x89,
    AluRR::Cmp => 0x39,
    AluRR::Test => 0x85,
  }
}

/// The opcode byte and ModRM extension for each immediate-form operation.
fn alu_ri_opcode(op: AluRI) -> (u8, u8) {
  match op {
    AluRI::Add => (0x81, 0),
    AluRI::Or => (0x81, 1),
    AluRI::And => (0x81, 4),
    AluRI::Sub => (0x81, 5),
    AluRI::Xor => (0x81, 6),
    AluRI::Cmp => (0x81, 7),
    AluRI::Mov => (0xc7, 0),
    AluRI::Test => (0xf7, 0),
  }
}

fn shift_ext(op: ShiftOp) -> u8 {
  match op {
    ShiftOp::Shl => 4,
    ShiftOp::Shr => 5,
    ShiftOp::Sar => 7,
  }
}

/// The opcode byte for each `op reg, [mem]` form the bounds checks use.
fn alu_rm_opcode(op: AluRM) -> u8 {
  match op {
    AluRM::Sub => 0x2b,
    AluRM::Add => 0x03,
    AluRM::CmpMR => 0x39,
    AluRM::CmpRM => 0x3b,
    AluRM::Or => 0x0b,
  }
}

/// From one local-call guard site to the next: four saved callee registers,
/// the call return address, and the callee's eight-byte prologue slot.
const NATIVE_STACK_DELTA: usize = 4 * 8 + 8 + 8;
const _: () = assert!(NATIVE_STACK_DELTA <= abi::NATIVE_LOCAL_CALL_BUDGET);

#[cfg(test)]
mod tests {
  use super::*;

  use std::sync::Arc;

  use crate::jit::golden;
  use crate::jit::isa::{alu, cls, jmp, mode, opcode, size, src as srcbit, Insn};
  use crate::jit::{Dispatcher, LocalCallResolver, LocalCallStackExhausted, PlanEntry, Target};
  // The register map and its two lookups live with the instruction set.
  use crate::verified::x64_ir::{map_register, unmap_register, R11, R15, R9, REGISTER_MAP};

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
  const STACK_EXHAUSTED_ADDRESS: usize = 0x0000_7f00_57ac_0000;

  fn dispatcher() -> Dispatcher {
    // SAFETY: never called. The value is materialised as an immediate and
    // compared as bytes, which is all any test here does with it.
    unsafe { std::mem::transmute::<usize, Dispatcher>(DISPATCHER_ADDRESS) }
  }

  fn local_call_resolver() -> LocalCallResolver {
    // SAFETY: as above.
    unsafe { std::mem::transmute::<usize, LocalCallResolver>(RESOLVER_ADDRESS) }
  }

  fn local_call_stack_exhausted() -> LocalCallStackExhausted {
    // SAFETY: as above.
    unsafe { std::mem::transmute::<usize, LocalCallStackExhausted>(STACK_EXHAUSTED_ADDRESS) }
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
      local_call_stack_exhausted: Some(local_call_stack_exhausted()),
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
          ..base.clone()
        },
      ),
      (
        "production + unwind helper",
        Config {
          pointer_mask: 0x0fff_ffff,
          pointer_offset: 0x1_0000_0000,
          native_frame_base: true,
          frame_constants: true,
          unwind_helper_index: Some(3),
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
  /// every golden it owns. The six names are fixed for that reason.
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
    assert_eq!(REGISTER_MAP.len(), crate::jit::isa::NUM_REGS);
    for r in 0..crate::jit::isa::NUM_REGS as u8 {
      assert!(
        seen.insert(map_register(r)),
        "register map is not injective"
      );
      assert_eq!(unmap_register(map_register(r)), r);
    }
    // The frame-access fast path and the local-call frame adjustment both name
    // R15 directly, so this mapping is load-bearing.
    assert_eq!(map_register(crate::jit::isa::REG_FP), R15);
    // RCX and R11 are the scratch registers, so nothing may map to them; the
    // core spells "no eBPF register" as 16.
    assert_eq!(unmap_register(RCX), 16);
    assert_eq!(unmap_register(R11), 16);
    assert_eq!(unmap_register(R9), 16);
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
      local_call_stack_exhausted: Some(local_call_stack_exhausted()),
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
  fn guarded_local_call_uses_sparse_frame_stride() {
    let insns = [insn(opcode::CALL, 0, 1, 0, 1), exit(), movi(0, 7), exit()];
    let code = Insn::encode_all(&insns);
    let ids = [11u32, 22, 33, 44];
    let inputs = TranslationInputs {
      resolver_ids: &ids,
      start_pc: 0,
      end_pc: insns.len(),
      ..Default::default()
    };
    let mut config = base_config(Target::X86_64);
    config.stack_frame_stride = 65_536;
    assert!(check_one(
      "guarded local call stride",
      &config,
      &code,
      &inputs,
      CAPACITY
    ));
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
    // Stores use the same region hints as loads; the immediate form still swaps
    // the address and scratch registers around.
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
    let hostile: [[PlanEntry; 4]; 7] = [
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

  /// FAILING — left in place, ignored, as a record of a real defect.
  /// A two-function range translated into a buffer that runs out *inside the
  /// second function's per-function prologue* trips
  /// `debug_assert_eq!(self.st.prolog_size, size)` in `emit_instructions`
  /// instead of returning `TranslateError::OutOfSpace`. Capacities 91..=101
  /// panic under every configuration in the sweep.
  /// The cause is that once the buffer is full, `self.offset()` stops tracking
  /// what the prologue *would* have measured, so `self.offset() - prolog_start`
  /// is a partial size. The assertion needs a `self.st.ok()` guard; nothing
  /// about how `emit_bytes` treats `offset` on failure removes it (the
  /// range of failing capacities merely shifts).
  /// `out_of_space_is_reported_identically` only ever translates a *single*
  /// function, so the second per-function prologue is never reached with a
  /// buffer that runs out inside it.
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

  /// Helper indices the census never reaches: negative, past the table, and the
  /// two integer extremes — plus the interaction with the unwind index, whose
  /// unset state is `-1`.
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
  /// FAILING — ignored, same root cause as
  /// `audit_out_of_space_inside_a_later_function_prologue`: every panic this
  /// finds is the `debug_assert_eq!(self.st.prolog_size, size)` in
  /// `emit_instructions`, and every program that trips it has more than one
  /// local function. The single-function programs in the list are clean.
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
      // A helper call, with its RIP-relative load and LEA fixups.
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
  /// [`sweep`] fixes six points in a space with rather more dimensions
  /// than that: it never turns the external dispatcher off, never sets
  /// `native_frame_base` or `frame_constants` while the cage is *disabled*,
  /// and only ever tries one unwind index. Each of those changes what is
  /// emitted, or what is emitted around it.
  #[test]
  fn audit_configurations_outside_the_sweep() {
    let base = base_config(Target::X86_64);

    let mut configs: Vec<(String, Config)> = Vec::new();

    // No external dispatcher at all: the trailer's dispatcher slot holds 0 and
    // the run-time branch in the helper-call sequence takes the table path.
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

    // Unwind indices other than 3, including the two that collide with the
    // "unset" sentinel once it has been narrowed to an `int`.
    for idx in [0u32, 1, 63, 64, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
      configs.push((
        format!("unwind index {idx:#x}"),
        Config {
          pointer_mask: 0x0fff_ffff,
          pointer_offset: 0x1_0000_0000,
          native_frame_base: true,
          frame_constants: true,
          unwind_helper_index: Some(idx),
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

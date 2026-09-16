//! The x86_64 primitive model, run against the hardware.
//!
//! `verified::x64_sim` claims to be an executable copy of
//! `lean/AsyncEbpf/X64/Machine.lean`. This test generates random straight-line
//! lists of primitives, assembles them with the verified encoder, runs the
//! bytes on the CPU and runs the same list through the model from the same
//! state, and compares all sixteen registers, the four flags and the scratch
//! memory. A mismatch is a bug in the model or in the encoder.
//!
//! ## What the generator emits
//!
//! Only the deterministic primitives, and only shapes that cannot fault:
//!
//! * register-only forms — `Alu`, `AluImm`, `ShiftImm`, `ShiftCl`, `Neg`,
//!   `MovSx`, `Bswap`, `Rol16`, `Cmov`, `LoadImm`, `Cqo`, `Cdq`,
//!   `CmpRcxMinusOne`, `CmpEaxImm` — writing any register but `rsp`, `rbp`
//!   and [`BASE`], the reserved scratch pointer;
//! * `Load`, `Store`, `StoreImm`, `AluRM`, `LockAlu`, `LockCmpxchg` and
//!   `Xchg` through [`BASE`], at displacements that keep every access inside
//!   the scratch buffer's data half. The locked forms are given naturally
//!   aligned addresses, so no split lock can reach the kernel's detector;
//! * `Push`, `Pop`, `Pushfq`, `Popfq`, `StoreRspImm` and `StoreRspRax` on a
//!   guest stack inside the same buffer, in balanced brackets, so the list
//!   ends at the `rsp` it started with;
//! * `MulDivRcx`, always after a `LoadImm` into `rcx` that makes the divisor
//!   non-zero, with the dividend prepared — `rdx` zeroed for `div`, sign
//!   extended by `Cqo`/`Cdq` for `idiv` — so no `#DE` is reachable, and with
//!   `-1` kept out of `idiv`'s divisor so the one overflowing quotient never
//!   arises;
//! * `Jcc8` and `Jmp8` forward over a few register-only primitives, and the
//!   label forms and `Pause`, which emit nothing.
//!
//! Every shift, rotate, multiply and divide is followed by a `cmp` that
//! defines all four flags. The architecture leaves some of theirs undefined
//! and processors differ on them (`div` on an Intel core leaves the flags
//! alone; on an AMD core it does not), which is why the Lean model reads
//! them as arbitrary; the test compares only what the model promises.
//!
//! Not emitted: `Call`, `Ret`, `Ud2`, `CallReg`, the two RIP-relative forms
//! and the trailer data, which either leave the list or halt.
//!
//! ## How the native run works
//!
//! One RW page is the scratch buffer: `[0, 2048)` is data, `[2048, 4096)` is
//! the guest stack, whose top is at 3072. [`BASE`] points at 1024, so
//! displacements reach either side of it.
//!
//! The bytes are `prologue ++ body ++ epilogue`, where the prologue and the
//! epilogue are hand-assembled here and commented byte by byte:
//!
//! * the prologue loads the sixteen registers and the flags from a `Regs`
//!   whose address it carries as a `movabs` immediate. It sets the flags with
//!   `add al, 0x7f` (overflow) and `sahf` (the rest) rather than `popfq`, so
//!   that it needs no stack and writes no memory — the guest stack must
//!   contain exactly what the model thinks it contains;
//! * the epilogue saves `rax` and the flags on the guest stack, `movabs`es
//!   the out-`Regs` address into `rax`, writes the other fifteen registers,
//!   the entry `rsp` and the flag bytes, then restores the host `rsp` from a
//!   slot in the caller's frame and jumps to `x64_sim_resume`, which pops the
//!   callee-saved registers the trampoline pushed and returns.
//!
//! The trampoline itself only saves the callee-saved registers, stashes the
//! host `rsp` in the caller's frame — not in a static, so that two threads may
//! run this at once — and jumps to the code.

use crate::verified::x64_encode::assemble;
use crate::verified::x64_ir::{cc, AluRI, AluRM, AluRR, MulDivKind, PInsn, PTarget, ShiftOp};
use crate::verified::x64_sim::{run, Outcome, Sim};

// ---------------------------------------------------------------------------
// The trampoline
// ---------------------------------------------------------------------------

std::arch::global_asm!(
  r#"
  .text
  .p2align 4
  .globl x64_sim_trampoline
x64_sim_trampoline:
  push rbp
  push rbx
  push r12
  push r13
  push r14
  push r15
  mov qword ptr [rsi], rsp
  jmp rdi

  .p2align 4
  .globl x64_sim_resume
x64_sim_resume:
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbx
  pop rbp
  ret
"#
);

extern "C" {
  /// Saves the callee-saved registers, stashes `rsp` at `host_rsp`, and jumps
  /// to `code`. The code returns by jumping to `x64_sim_resume`.
  fn x64_sim_trampoline(code: *const u8, host_rsp: *mut u64);
  /// Pops what the trampoline pushed and returns to its caller.
  fn x64_sim_resume();
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/// The reserved scratch pointer: the only base register a generated memory
/// access uses, and the one register the generator never writes.
const BASE: u8 = 13;
/// Where `BASE` points, as an offset into the buffer.
const BASE_OFF: usize = 1024;
/// The data half, compared byte for byte after every case.
const DATA_END: usize = 2048;
/// The guest stack's top, as an offset into the buffer.
const STACK_TOP: usize = 3072;
/// The whole scratch buffer.
const BUF_LEN: usize = 4096;
/// Room for one case's bytes.
const CODE_LEN: usize = 1 << 16;

const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RSP: u8 = 4;
const RBP: u8 = 5;

/// Every register a generated primitive may write.
const WRITABLE: [u8; 13] = [0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 14, 15];

/// The condition codes the backend emits.
const CCS: [u8; 10] = [
  cc::B,
  cc::AE,
  cc::E,
  cc::NE,
  cc::BE,
  cc::A,
  cc::L,
  cc::GE,
  cc::LE,
  cc::G,
];

/// The register file and flags the prologue loads and the epilogue writes.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Regs {
  r: [u64; 16],
  /// On the way in: `al` is the overflow flag and `ah` is a `sahf` byte. On
  /// the way out: `al` is `seto`'s byte and `ah` is `lahf`'s.
  flags: u64,
}

impl Regs {
  /// The word the prologue's `mov ax, [rcx + 128]` reads.
  fn from_flags(cf: bool, zf: bool, sf: bool, of: bool) -> u64 {
    let mut ah: u64 = 0x02;
    if cf {
      ah |= 0x01;
    }
    if zf {
      ah |= 0x40;
    }
    if sf {
      ah |= 0x80;
    }
    (ah << 8) | u64::from(of)
  }

  /// The four flags the epilogue's `seto`/`lahf` pair left.
  fn to_flags(self) -> (bool, bool, bool, bool) {
    (
      (self.flags >> 8) & 1 == 1,
      (self.flags >> 14) & 1 == 1,
      (self.flags >> 15) & 1 == 1,
      self.flags & 1 == 1,
    )
  }
}

// ---------------------------------------------------------------------------
// The hand-assembled prologue and epilogue
// ---------------------------------------------------------------------------

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
  out.extend_from_slice(bytes);
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
  out.extend_from_slice(&v.to_le_bytes());
}

/// `mov <reg>, [rcx + off]`, with `off` in `0..=127`.
fn mov_reg_from_rcx(out: &mut Vec<u8>, reg: u8, off: u8) {
  put(
    out,
    &[
      0x48 | ((reg & 8) >> 1), // REX.W, plus REX.R for r8-r15
      0x8b,                    // mov r64, r/m64
      0x40 | ((reg & 7) << 3) | 1,
      off, // mod = 01 (disp8), rm = rcx
    ],
  );
}

/// `mov [rax + off], <reg>`, with `off` in `0..=127`.
fn mov_to_rax_slot(out: &mut Vec<u8>, reg: u8, off: u8) {
  put(
    out,
    &[
      0x48 | ((reg & 8) >> 1), // REX.W, plus REX.R for r8-r15
      0x89,                    // mov r/m64, r64
      0x40 | ((reg & 7) << 3), // mod = 01 (disp8), rm = rax
      off,
    ],
  );
}

/// Loads every register and the four flags from the `Regs` at `regs`.
///
/// The order is forced: the flags need a scratch register and `rax` is the
/// only one whose low half `lahf`'s inverse reads, so the flags go first,
/// then everything but the pointer, then `rax`, then the pointer register
/// itself. Nothing here writes memory and nothing but the flag pair writes a
/// flag, so the state the body starts from is exactly the `Regs`.
fn prologue(regs: u64) -> Vec<u8> {
  let mut out = Vec::new();
  put(&mut out, &[0x48, 0xb9]); // movabs rcx, imm64
  put_u64(&mut out, regs);
  put(&mut out, &[0x66, 0x8b, 0x81, 0x80, 0x00, 0x00, 0x00]); // mov ax, [rcx + 128]
  put(&mut out, &[0x04, 0x7f]); // add al, 0x7f      -> of
  put(&mut out, &[0x9e]); // sahf              -> cf, zf, sf
  let mut r: u8 = 2;
  while r < 16 {
    // Everything but rax (loaded last but one) and rcx (the pointer).
    mov_reg_from_rcx(&mut out, r, r * 8);
    r += 1;
  }
  mov_reg_from_rcx(&mut out, RSP, RSP * 8);
  mov_reg_from_rcx(&mut out, RAX, 0);
  mov_reg_from_rcx(&mut out, RCX, 8);
  out
}

/// Writes every register and the four flags to the `Regs` at `out_regs`,
/// restores the host `rsp` from `host_rsp`, and jumps to `x64_sim_resume`.
///
/// `push`, `mov`, `lea`, `movabs` and `seto` leave the flags alone, so the
/// `seto`/`lahf` pair at the top is the only flag reader and it runs before
/// anything else can disturb them. The two pushes are the only memory this
/// writes below the guest stack pointer.
fn epilogue(out_regs: u64, host_rsp: u64, resume: u64) -> Vec<u8> {
  let mut out = Vec::new();
  put(&mut out, &[0x50]); // push rax          [rsp + 8] = guest rax
  put(&mut out, &[0x0f, 0x90, 0xc0]); // seto al           al = of
  put(&mut out, &[0x9f]); // lahf              ah = cf, zf, sf
  put(&mut out, &[0x50]); // push rax          [rsp] = the flag bytes
  put(&mut out, &[0x48, 0xb8]); // movabs rax, imm64
  put_u64(&mut out, out_regs);
  let mut r: u8 = 1;
  while r < 16 {
    if r != RSP {
      mov_to_rax_slot(&mut out, r, r * 8);
    }
    r += 1;
  }
  put(&mut out, &[0x48, 0x8b, 0x4c, 0x24, 0x08]); // mov rcx, [rsp + 8]
  put(&mut out, &[0x48, 0x89, 0x48, 0x00]); // mov [rax + 0], rcx
  put(&mut out, &[0x48, 0x8b, 0x0c, 0x24]); // mov rcx, [rsp]
  put(&mut out, &[0x48, 0x89, 0x88, 0x80, 0x00, 0x00, 0x00]); // mov [rax + 128], rcx
  put(&mut out, &[0x48, 0x8d, 0x4c, 0x24, 0x10]); // lea rcx, [rsp + 16]
  put(&mut out, &[0x48, 0x89, 0x48, 0x20]); // mov [rax + 32], rcx
  put(&mut out, &[0x48, 0xb9]); // movabs rcx, imm64
  put_u64(&mut out, host_rsp);
  put(&mut out, &[0x48, 0x8b, 0x21]); // mov rsp, [rcx]
  put(&mut out, &[0x48, 0xb9]); // movabs rcx, imm64
  put_u64(&mut out, resume);
  put(&mut out, &[0xff, 0xe1]); // jmp rcx
  out
}

// ---------------------------------------------------------------------------
// Mapped pages
// ---------------------------------------------------------------------------

struct Mapping {
  ptr: *mut u8,
  len: usize,
}

impl Mapping {
  fn new(len: usize) -> Mapping {
    let ptr = unsafe {
      libc::mmap(
        std::ptr::null_mut(),
        len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
      )
    };
    assert!(ptr != libc::MAP_FAILED, "mmap failed");
    Mapping {
      ptr: ptr as *mut u8,
      len,
    }
  }

  fn addr(&self) -> u64 {
    self.ptr as u64
  }

  fn protect(&self, prot: i32) {
    let rc = unsafe { libc::mprotect(self.ptr as *mut libc::c_void, self.len, prot) };
    assert_eq!(rc, 0, "mprotect failed");
  }

  fn bytes(&self) -> &[u8] {
    unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
  }

  fn write(&self, at: usize, src: &[u8]) {
    assert!(at + src.len() <= self.len);
    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr.add(at), src.len()) };
  }
}

impl Drop for Mapping {
  fn drop(&mut self) {
    unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
  }
}

// ---------------------------------------------------------------------------
// The random generator
// ---------------------------------------------------------------------------

/// SplitMix64: a seeded, reproducible stream, written out so that a failing
/// case can be replayed from its seed alone.
struct Rng {
  state: u64,
}

impl Rng {
  fn new(seed: u64) -> Rng {
    Rng { state: seed }
  }

  fn next(&mut self) -> u64 {
    self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = self.state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
  }

  fn below(&mut self, n: u64) -> u64 {
    self.next() % n
  }

  fn flip(&mut self) -> bool {
    self.next() & 1 == 1
  }

  fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
    xs[(self.next() % xs.len() as u64) as usize]
  }

  /// A register the generator may write.
  fn wreg(&mut self) -> u8 {
    self.pick(&WRITABLE)
  }

  /// Any register, as a source.
  fn areg(&mut self) -> u8 {
    (self.next() % 16) as u8
  }

  /// A value with the edges the flag definitions care about over-represented.
  fn value(&mut self) -> u64 {
    match self.below(10) {
      0 => 0,
      1 => 1,
      2 => u64::MAX,
      3 => 1u64 << 63,
      4 => 1u64 << 31,
      5 => 0xffff_ffff,
      6 => 0x7fff_ffff,
      7 => self.next() & 0xff,
      _ => self.next(),
    }
  }
}

// ---------------------------------------------------------------------------
// Generating one case
// ---------------------------------------------------------------------------

struct Program {
  code: Vec<PInsn>,
  /// The next unused local label number.
  label: u32,
  /// Whether the list pushes a flags word, whose low bits are all the model
  /// knows of `RFLAGS` — the hardware writes the rest, so the stack half
  /// cannot then be compared.
  pushes_flags: bool,
  /// Whether the list already carries the singleton exit label.
  used_exit: bool,
}

impl Program {
  fn new() -> Program {
    Program {
      code: Vec::new(),
      label: 0,
      pushes_flags: false,
      used_exit: false,
    }
  }

  fn push(&mut self, p: PInsn) {
    self.code.push(p);
  }
}

fn shift_op(g: &mut Rng) -> ShiftOp {
  match g.below(3) {
    0 => ShiftOp::Shl,
    1 => ShiftOp::Shr,
    _ => ShiftOp::Sar,
  }
}

fn alu_rr_op(g: &mut Rng) -> AluRR {
  match g.below(8) {
    0 => AluRR::Add,
    1 => AluRR::Sub,
    2 => AluRR::Or,
    3 => AluRR::And,
    4 => AluRR::Xor,
    5 => AluRR::Mov,
    6 => AluRR::Cmp,
    _ => AluRR::Test,
  }
}

fn alu_ri_op(g: &mut Rng) -> AluRI {
  match g.below(8) {
    0 => AluRI::Add,
    1 => AluRI::Or,
    2 => AluRI::And,
    3 => AluRI::Sub,
    4 => AluRI::Xor,
    5 => AluRI::Cmp,
    6 => AluRI::Mov,
    _ => AluRI::Test,
  }
}

/// An immediate, with the boundaries the 32-bit forms sign-extend across.
fn imm32(g: &mut Rng) -> i32 {
  match g.below(8) {
    0 => 0,
    1 => 1,
    2 => -1,
    3 => i32::MIN,
    4 => i32::MAX,
    5 => (g.next() & 0xff) as i32,
    _ => g.next() as u32 as i32,
  }
}

/// A displacement that keeps a `size`-byte access inside the data half.
fn disp(g: &mut Rng, size: u8) -> i32 {
  let room = (DATA_END - size as usize) as u64;
  (g.below(room + 1) as i64 - BASE_OFF as i64) as i32
}

/// The same, naturally aligned, for the locked forms.
fn aligned_disp(g: &mut Rng, size: u8) -> i32 {
  let slots = DATA_END as u64 / size as u64;
  ((g.below(slots) * size as u64) as i64 - BASE_OFF as i64) as i32
}

fn size_of(g: &mut Rng) -> u8 {
  match g.below(4) {
    0 => 1,
    1 => 2,
    2 => 4,
    _ => 8,
  }
}

/// A `cmp` that defines all four flags and writes no register, emitted
/// after every primitive whose flags the architecture leaves undefined — a
/// shift, a rotate, a multiply or a divide. The Lean model reads those flags
/// as arbitrary, and processors really do differ: an Intel core leaves
/// `div`'s flags where they were, an AMD core does not. What the model
/// promises is compared; what it does not is defined away before anything
/// can observe it.
fn settle_flags(g: &mut Rng, p: &mut Program) {
  p.push(PInsn::AluImm {
    w64: g.flip(),
    op: AluRI::Cmp,
    dst: g.areg(),
    imm: imm32(g),
  });
}

/// One primitive that touches neither memory nor the stack, for the bodies a
/// `Jcc8` jumps over and for the bulk of every list.
fn gen_reg_only(g: &mut Rng, p: &mut Program) {
  match g.below(12) {
    0 => {
      let dst = g.wreg();
      let src = g.areg();
      p.push(PInsn::Alu {
        w64: g.flip(),
        op: alu_rr_op(g),
        src,
        dst,
      });
    }
    1 => {
      let dst = g.wreg();
      p.push(PInsn::AluImm {
        w64: g.flip(),
        op: alu_ri_op(g),
        dst,
        imm: imm32(g),
      });
    }
    2 => {
      let dst = g.wreg();
      p.push(PInsn::ShiftImm {
        w64: g.flip(),
        op: shift_op(g),
        dst,
        imm: (g.next() & 0xff) as i32,
      });
      settle_flags(g, p);
    }
    3 => {
      let dst = g.wreg();
      p.push(PInsn::ShiftCl {
        w64: g.flip(),
        op: shift_op(g),
        dst,
      });
      settle_flags(g, p);
    }
    4 => {
      let dst = g.wreg();
      p.push(PInsn::Neg { w64: g.flip(), dst });
    }
    5 => {
      let dst = g.wreg();
      let src = g.areg();
      let from = g.pick(&[8u8, 16, 32]);
      // `movsx r32, r/m32` is the one shape the encoder writes as a plain
      // move; the backend only emits the 64-bit form from 32 bits.
      let w64 = if from == 32 { true } else { g.flip() };
      p.push(PInsn::MovSx {
        from,
        w64,
        src,
        dst,
      });
    }
    6 => {
      let dst = g.wreg();
      p.push(PInsn::Bswap { w64: g.flip(), dst });
    }
    7 => {
      let dst = g.wreg();
      p.push(PInsn::Rol16 { dst });
      settle_flags(g, p);
    }
    8 => {
      let dst = g.wreg();
      let src = g.areg();
      let cc = g.pick(&CCS);
      p.push(PInsn::Cmov { cc, dst, src });
    }
    9 => {
      let dst = g.wreg();
      let imm = g.value() as i64;
      p.push(PInsn::LoadImm { dst, imm });
    }
    10 => {
      if g.flip() {
        p.push(PInsn::Cqo);
      } else {
        p.push(PInsn::Cdq);
      }
    }
    _ => {
      if g.flip() {
        p.push(PInsn::CmpRcxMinusOne { w64: g.flip() });
      } else {
        p.push(PInsn::CmpEaxImm {
          imm: g.next() as u32,
        });
      }
    }
  }
}

/// `mul`/`div`/`idiv`, with the operands prepared so that no `#DE` is
/// reachable: a non-zero divisor, a zero high half for `div`, and the sign
/// extension `Cqo`/`Cdq` produces for `idiv`, whose only overflowing quotient
/// needs a divisor of `-1`.
fn gen_muldiv(g: &mut Rng, p: &mut Program) {
  let w64 = g.flip();
  let kind = match g.below(3) {
    0 => MulDivKind::Mul,
    1 => MulDivKind::Div,
    _ => MulDivKind::Mod,
  };
  let is_mul = matches!(kind, MulDivKind::Mul);
  let signed = !is_mul && g.flip();
  let mut divisor = g.value() as i64;
  if !is_mul {
    // Non-zero at the width the instruction reads, and never `-1` under
    // `idiv`, which is the one divisor with an overflowing quotient.
    if divisor == 0 || (!w64 && (divisor as u64) & 0xffff_ffff == 0) {
      divisor = 3;
    }
    if signed && (divisor == -1 || (!w64 && (divisor as u64) & 0xffff_ffff == 0xffff_ffff)) {
      divisor = 7;
    }
  }
  p.push(PInsn::LoadImm {
    dst: RCX,
    imm: divisor,
  });
  if !is_mul {
    if signed {
      // Sign-extends `rax` into `rdx`, so the dividend is `rax` itself.
      if w64 {
        p.push(PInsn::Cqo);
      } else {
        p.push(PInsn::Cdq);
      }
    } else {
      // A zero high half makes every unsigned quotient fit.
      p.push(PInsn::LoadImm { dst: RDX, imm: 0 });
    }
  }
  p.push(PInsn::MulDivRcx { w64, kind, signed });
  settle_flags(g, p);
}

/// A balanced stack bracket: a few pushes, a few register-only primitives, the
/// matching pops. `rsp` is where it started by the end of it, which is what
/// lets the epilogue know where the guest stack is — and no branch ever jumps
/// over one of these, so the balance holds whichever way a branch went.
fn gen_stack(g: &mut Rng, p: &mut Program) {
  match g.below(4) {
    0 => {
      p.push(PInsn::Pushfq);
      p.push(PInsn::Popfq);
      p.pushes_flags = true;
    }
    1 => {
      // Up to four deep, so that the words below the epilogue's own two-slot
      // scratch window are compared as memory and not only through the
      // registers they come back in.
      let depth = 1 + g.below(4);
      let mut i = 0;
      while i < depth {
        let a = g.areg();
        p.push(PInsn::Push(a));
        i += 1;
      }
      let n = g.below(3);
      let mut k = 0;
      while k < n {
        gen_reg_only(g, p);
        k += 1;
      }
      let mut j = 0;
      while j < depth {
        let c = g.wreg();
        p.push(PInsn::Pop(c));
        j += 1;
      }
    }
    2 => {
      // `mov qword [rsp], imm32` and `mov [rsp], rax` write the word above
      // the stack pointer, which is inside the buffer and below its end.
      if g.flip() {
        p.push(PInsn::StoreRspImm {
          imm: g.next() as u32,
        });
      } else {
        p.push(PInsn::StoreRspRax);
      }
    }
    _ => {
      let a = g.areg();
      let b = g.wreg();
      p.push(PInsn::Push(a));
      p.push(PInsn::Pop(b));
    }
  }
}

/// A memory primitive through the reserved base register.
fn gen_memory(g: &mut Rng, p: &mut Program) {
  match g.below(7) {
    0 => {
      let size = size_of(g);
      let sx = g.flip();
      let dst = g.wreg();
      p.push(PInsn::Load {
        size,
        sx,
        base: BASE,
        dst,
        disp: disp(g, size),
      });
    }
    1 => {
      let size = size_of(g);
      let src = g.areg();
      p.push(PInsn::Store {
        size,
        src,
        base: BASE,
        disp: disp(g, size),
      });
    }
    2 => {
      let size = size_of(g);
      p.push(PInsn::StoreImm {
        size,
        base: BASE,
        disp: disp(g, size),
        imm: imm32(g),
      });
    }
    3 => {
      let op = match g.below(5) {
        0 => AluRM::Sub,
        1 => AluRM::Add,
        2 => AluRM::Or,
        3 => AluRM::CmpMR,
        _ => AluRM::CmpRM,
      };
      let reg = g.wreg();
      p.push(PInsn::AluRM {
        op,
        reg,
        base: BASE,
        disp: disp(g, 8),
      });
    }
    4 => {
      let w64 = g.flip();
      let size = if w64 { 8 } else { 4 };
      let op = g.pick(&[0x01u8, 0x09, 0x21, 0x31]);
      let src = g.areg();
      p.push(PInsn::LockAlu {
        op,
        w64,
        src,
        base: BASE,
        disp: aligned_disp(g, size),
      });
    }
    5 => {
      let w64 = g.flip();
      let size = if w64 { 8 } else { 4 };
      let d = aligned_disp(g, size);
      let src = g.areg();
      // Half the time the accumulator is preloaded with what the location
      // holds, which is the path that stores; otherwise the comparison fails
      // and the path that rewrites `rax` runs.
      if g.flip() {
        p.push(PInsn::Load {
          size,
          sx: false,
          base: BASE,
          dst: RAX,
          disp: d,
        });
      }
      p.push(PInsn::LockCmpxchg {
        w64,
        src,
        base: BASE,
        disp: d,
      });
    }
    _ => {
      let w64 = g.flip();
      let size = if w64 { 8 } else { 4 };
      let src = g.wreg();
      p.push(PInsn::Xchg {
        w64,
        src,
        base: BASE,
        disp: aligned_disp(g, size),
      });
    }
  }
}

/// A forward branch over a few register-only primitives, in every shape the
/// model resolves: the two short forms the expansions use, the two long
/// forms, the padded near form, and all three kinds of label a target names.
fn gen_branch(g: &mut Rng, p: &mut Program) {
  let n = p.label;
  p.label += 1;
  // At most one exit label per list: two of them would make "the first label
  // that matches" mean one thing to the model and another to the encoder,
  // which keeps a single position for the singleton labels.
  let kind = if p.used_exit { g.below(2) } else { g.below(3) };
  let (target, label) = match kind {
    0 => (PTarget::Local(n), PInsn::Local(n)),
    1 => (PTarget::Pc(n), PInsn::PcLabel(n)),
    _ => {
      p.used_exit = true;
      (PTarget::Exit, PInsn::ExitLabel)
    }
  };
  let cc = g.pick(&CCS);
  match g.below(5) {
    0 => match target {
      PTarget::Local(m) => p.push(PInsn::Jcc8 { cc, target: m }),
      _ => p.push(PInsn::Jcc { cc, target }),
    },
    1 => match target {
      PTarget::Local(m) => p.push(PInsn::Jmp8 { target: m }),
      _ => p.push(PInsn::Jmp { target }),
    },
    2 => p.push(PInsn::Jcc { cc, target }),
    3 => p.push(PInsn::Jmp { target }),
    _ => p.push(PInsn::JmpNear { target }),
  }
  let n = 1 + g.below(3);
  let mut i = 0;
  while i < n {
    gen_reg_only(g, p);
    i += 1;
  }
  p.push(label);
}

fn gen_program(g: &mut Rng) -> Program {
  let mut p = Program::new();
  let chunks = 10 + g.below(16);
  let mut i = 0;
  while i < chunks {
    match g.below(16) {
      0..=5 => gen_reg_only(g, &mut p),
      6 => gen_muldiv(g, &mut p),
      7 | 8 => gen_stack(g, &mut p),
      9..=12 => gen_memory(g, &mut p),
      13 => gen_branch(g, &mut p),
      14 => p.push(PInsn::Pause),
      _ => {
        let label = p.label;
        p.label += 1;
        p.push(PInsn::Local(label));
      }
    }
    i += 1;
  }
  p
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

/// The primitive shapes this test claims to cover. The random test counts
/// them and fails if the generator ever stops producing one, so the list above
/// is checked rather than merely asserted.
const KINDS: [&str; 40] = [
  "PcLabel",
  "Local",
  "ExitLabel",
  "Push",
  "Pop",
  "Pushfq",
  "Popfq",
  "Alu",
  "AluImm",
  "ShiftImm",
  "ShiftCl",
  "Neg",
  "Mul",
  "Div",
  "Idiv",
  "MovSx",
  "Bswap",
  "Rol16",
  "Cmov",
  "LoadImm",
  "Cqo",
  "Cdq",
  "CmpRcxMinusOne",
  "CmpEaxImm",
  "Load",
  "LoadSx",
  "Store",
  "StoreImm",
  "AluRM",
  "StoreRspImm",
  "StoreRspRax",
  "LockAlu",
  "LockCmpxchg",
  "Xchg",
  "Jcc",
  "Jmp",
  "JmpNear",
  "Jcc8",
  "Jmp8",
  "Pause",
];

/// Where a primitive counts. Anything the generator never emits — the calls,
/// the returns, `ud2`, the RIP-relative pair and the trailer — lands past the
/// end of [`KINDS`] and is ignored.
fn kind_index(p: &PInsn) -> usize {
  match p {
    PInsn::PcLabel(_) => 0,
    PInsn::Local(_) => 1,
    PInsn::ExitLabel => 2,
    PInsn::Push(_) => 3,
    PInsn::Pop(_) => 4,
    PInsn::Pushfq => 5,
    PInsn::Popfq => 6,
    PInsn::Alu { .. } => 7,
    PInsn::AluImm { .. } => 8,
    PInsn::ShiftImm { .. } => 9,
    PInsn::ShiftCl { .. } => 10,
    PInsn::Neg { .. } => 11,
    PInsn::MulDivRcx { kind, signed, .. } => match kind {
      MulDivKind::Mul => 12,
      _ => {
        if *signed {
          14
        } else {
          13
        }
      }
    },
    PInsn::MovSx { .. } => 15,
    PInsn::Bswap { .. } => 16,
    PInsn::Rol16 { .. } => 17,
    PInsn::Cmov { .. } => 18,
    PInsn::LoadImm { .. } => 19,
    PInsn::Cqo => 20,
    PInsn::Cdq => 21,
    PInsn::CmpRcxMinusOne { .. } => 22,
    PInsn::CmpEaxImm { .. } => 23,
    PInsn::Load { sx, .. } => {
      if *sx {
        25
      } else {
        24
      }
    }
    PInsn::Store { .. } => 26,
    PInsn::StoreImm { .. } => 27,
    PInsn::AluRM { .. } => 28,
    PInsn::StoreRspImm { .. } => 29,
    PInsn::StoreRspRax => 30,
    PInsn::LockAlu { .. } => 31,
    PInsn::LockCmpxchg { .. } => 32,
    PInsn::Xchg { .. } => 33,
    PInsn::Jcc { .. } => 34,
    PInsn::Jmp { .. } => 35,
    PInsn::JmpNear { .. } => 36,
    PInsn::Jcc8 { .. } => 37,
    PInsn::Jmp8 { .. } => 38,
    PInsn::Pause => 39,
    _ => KINDS.len(),
  }
}

// ---------------------------------------------------------------------------
// Running one case
// ---------------------------------------------------------------------------

struct Harness {
  buf: Mapping,
  code: Mapping,
  /// Where the trampoline stashes the host `rsp`; the epilogue reads it back.
  host_rsp: Box<u64>,
  regs_in: Box<Regs>,
  regs_out: Box<Regs>,
}

impl Harness {
  fn new() -> Harness {
    Harness {
      buf: Mapping::new(BUF_LEN),
      code: Mapping::new(CODE_LEN),
      host_rsp: Box::new(0),
      regs_in: Box::new(Regs::default()),
      regs_out: Box::new(Regs::default()),
    }
  }

  /// Runs `code` on the CPU from `regs` with `mem` in the scratch buffer, and
  /// returns what came back and what the buffer holds.
  fn run_native(&mut self, code: &[PInsn], regs: Regs, mem: &[u8]) -> (Regs, Vec<u8>) {
    let mut bytes = prologue(&*self.regs_in as *const Regs as u64);
    assemble(code, &mut bytes).expect("the encoder refused a generated list");
    let ep = epilogue(
      &mut *self.regs_out as *mut Regs as u64,
      &mut *self.host_rsp as *mut u64 as u64,
      x64_sim_resume as unsafe extern "C" fn() as usize as u64,
    );
    bytes.extend_from_slice(&ep);
    assert!(bytes.len() <= CODE_LEN, "generated case does not fit");

    *self.regs_in = regs;
    *self.regs_out = Regs::default();
    self.buf.write(0, mem);
    self.code.protect(libc::PROT_READ | libc::PROT_WRITE);
    self.code.write(0, &bytes);
    self.code.protect(libc::PROT_READ | libc::PROT_EXEC);
    unsafe {
      x64_sim_trampoline(self.code.ptr, &mut *self.host_rsp as *mut u64);
    }
    self.code.protect(libc::PROT_READ | libc::PROT_WRITE);
    (*self.regs_out, self.buf.bytes().to_vec())
  }
}

/// What the two runs disagreed about, if anything.
///
/// `stack` says whether the guest stack half of the buffer is comparable; the
/// sixteen bytes below the final `rsp` never are, because they are where the
/// epilogue saved `rax` and the flag bytes.
fn compare(
  code: &[PInsn],
  regs_in: &Regs,
  native: &Regs,
  native_mem: &[u8],
  sim: &Sim,
  stack: bool,
) -> Option<String> {
  let mut bad = String::new();
  let mut i = 0;
  while i < 16 {
    if native.r[i] != sim.regs[i] {
      bad.push_str(&format!(
        "  r{}: native {:#018x} sim {:#018x}\n",
        i, native.r[i], sim.regs[i]
      ));
    }
    i += 1;
  }
  let (cf, zf, sf, of) = native.to_flags();
  if cf != sim.cf || zf != sim.zf || sf != sim.sf || of != sim.of {
    bad.push_str(&format!(
      "  flags: native cf={} zf={} sf={} of={}, sim cf={} zf={} sf={} of={}\n",
      cf, zf, sf, of, sim.cf, sim.zf, sim.sf, sim.of
    ));
  }
  let end = if stack { BUF_LEN } else { DATA_END };
  // The epilogue's two pushes, as offsets into the buffer.
  let saved_hi = (native.r[RSP as usize].wrapping_sub(sim.mem_base)) as usize;
  let saved_lo = saved_hi.saturating_sub(16);
  let mut a = 0;
  let mut shown = 0;
  while a < end {
    let scratch = a >= saved_lo && a < saved_hi;
    if !scratch && native_mem[a] != sim.mem[a] && shown < 8 {
      bad.push_str(&format!(
        "  mem[{}]: native {:#04x} sim {:#04x}\n",
        a, native_mem[a], sim.mem[a]
      ));
      shown += 1;
    }
    a += 1;
  }
  if bad.is_empty() {
    None
  } else {
    let mut msg = String::from("native and model disagree\n");
    msg.push_str(&bad);
    msg.push_str(&format!("  in: {:?}\n", regs_in));
    let mut k = 0;
    while k < code.len() {
      msg.push_str(&format!("  [{}] {:?}\n", k, code[k]));
      k += 1;
    }
    Some(msg)
  }
}

/// Runs one list both ways from one starting state and returns the complaint,
/// if any. The stack half of the buffer is compared unless the list pushed a
/// flags word: `Pushfq` writes the four flags the model knows and the
/// hardware writes all of `RFLAGS`, so those eight bytes are allowed to
/// differ.
fn run_case(
  h: &mut Harness,
  code: &[PInsn],
  regs: Regs,
  mem: &[u8],
  stack: bool,
) -> Option<String> {
  let buf_addr = h.buf.addr();
  let code_addr = h.code.addr();
  let (cf, zf, sf, of) = regs.to_flags();
  let mut sim = Sim {
    regs: regs.r,
    cf,
    zf,
    sf,
    of,
    mem_base: buf_addr,
    mem: mem.to_vec(),
    pc: 0,
    code_base: code_addr,
  };
  let outcome = run(code, &mut sim, code.len() + 2);
  assert_eq!(
    outcome,
    Outcome::Halt,
    "the model did not run the list to its end"
  );
  let (native, native_mem) = h.run_native(code, regs, mem);
  compare(code, &regs, &native, &native_mem, &sim, stack)
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

const CASES: usize = 20000;
const SEED: u64 = 0x5eed_1234_abcd_0001;

#[test]
fn the_model_agrees_with_the_hardware_on_random_primitive_lists() {
  let mut h = Harness::new();
  let mut g = Rng::new(SEED);
  let buf_addr = h.buf.addr();
  let mut seen = [0usize; KINDS.len()];
  let mut case = 0;
  while case < CASES {
    let p = gen_program(&mut g);
    let mut k = 0;
    while k < p.code.len() {
      let idx = kind_index(&p.code[k]);
      if idx < KINDS.len() {
        seen[idx] += 1;
      }
      k += 1;
    }
    let mut mem = vec![0u8; BUF_LEN];
    let mut i = 0;
    while i < BUF_LEN {
      mem[i] = g.next() as u8;
      i += 1;
    }
    let mut regs = Regs::default();
    let mut r = 0;
    while r < 16 {
      regs.r[r] = g.value();
      r += 1;
    }
    regs.r[RSP as usize] = buf_addr + STACK_TOP as u64;
    regs.r[RBP as usize] = g.value();
    regs.r[BASE as usize] = buf_addr + BASE_OFF as u64;
    regs.flags = Regs::from_flags(g.flip(), g.flip(), g.flip(), g.flip());
    let complaint = run_case(&mut h, &p.code, regs, &mem, !p.pushes_flags);
    if let Some(msg) = complaint {
      panic!("case {} (seed {:#x}):\n{}", case, SEED, msg);
    }
    case += 1;
  }
  let mut missing = String::new();
  let mut k = 0;
  while k < KINDS.len() {
    if seen[k] == 0 {
      missing.push_str(KINDS[k]);
      missing.push(' ');
    }
    k += 1;
  }
  assert!(missing.is_empty(), "never generated: {}", missing);
}

/// The flag definitions the Lean model pins down exactly, at the values that
/// decide them: zero, one, the two extremes and the sign boundaries.
#[test]
fn the_model_agrees_with_the_hardware_on_flag_edge_values() {
  let mut h = Harness::new();
  let buf_addr = h.buf.addr();
  let mem = vec![0u8; BUF_LEN];
  let edges: [u64; 12] = [
    0,
    1,
    2,
    0x7fff_ffff,
    0x8000_0000,
    0x8000_0001,
    0xffff_ffff,
    0x1_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    0x8000_0000_0000_0001,
    0xffff_ffff_ffff_ffff,
  ];
  let ops: [AluRR; 7] = [
    AluRR::Add,
    AluRR::Sub,
    AluRR::Or,
    AluRR::And,
    AluRR::Xor,
    AluRR::Cmp,
    AluRR::Test,
  ];
  let imm_ops: [AluRI; 7] = [
    AluRI::Add,
    AluRI::Sub,
    AluRI::Or,
    AluRI::And,
    AluRI::Xor,
    AluRI::Cmp,
    AluRI::Test,
  ];
  let imms: [i32; 6] = [0, 1, -1, i32::MIN, i32::MAX, 0x7fff_ffff - 1];

  let mut checked = 0;
  for w64 in [false, true] {
    for op in ops {
      for a in edges {
        for b in edges {
          let code = vec![PInsn::Alu {
            w64,
            op,
            src: RCX,
            dst: RAX,
          }];
          let mut regs = Regs::default();
          regs.r[RAX as usize] = a;
          regs.r[RCX as usize] = b;
          regs.r[RSP as usize] = buf_addr + STACK_TOP as u64;
          regs.r[BASE as usize] = buf_addr + BASE_OFF as u64;
          regs.flags = Regs::from_flags(true, true, true, true);
          if let Some(msg) = run_case(&mut h, &code, regs, &mem, true) {
            panic!("alu edge case:\n{}", msg);
          }
          checked += 1;
        }
      }
    }
    for op in imm_ops {
      for a in edges {
        for imm in imms {
          let code = vec![PInsn::AluImm {
            w64,
            op,
            dst: RAX,
            imm,
          }];
          let mut regs = Regs::default();
          regs.r[RAX as usize] = a;
          regs.r[RSP as usize] = buf_addr + STACK_TOP as u64;
          regs.r[BASE as usize] = buf_addr + BASE_OFF as u64;
          regs.flags = Regs::from_flags(false, false, false, false);
          if let Some(msg) = run_case(&mut h, &code, regs, &mem, true) {
            panic!("alu-immediate edge case:\n{}", msg);
          }
          checked += 1;
        }
      }
    }
  }
  assert!(checked > 2000);
}

// ---------------------------------------------------------------------------
// The model on its own
//
// The shapes the differential harness deliberately never generates: the ones
// that leave the list, the ones that fault, and the one place the Lean model
// parts company with the hardware.
// ---------------------------------------------------------------------------

/// A model state over a small mapped range at a round address.
fn model(code_base: u64) -> Sim {
  Sim {
    regs: [0; 16],
    cf: false,
    zf: false,
    sf: false,
    of: false,
    mem_base: 0x1_0000,
    mem: vec![0; 256],
    pc: 0,
    code_base,
  }
}

#[test]
fn a_call_pushes_the_next_position_and_a_ret_reads_it_back() {
  let code = vec![
    PInsn::Call {
      target: PTarget::Local(1),
    },
    PInsn::Jmp {
      target: PTarget::Exit,
    },
    PInsn::Local(1),
    PInsn::Ret,
    PInsn::ExitLabel,
  ];
  let mut s = model(0x4000_0000);
  s.regs[RSP as usize] = 0x1_0080;
  assert_eq!(run(&code, &mut s, 16), Outcome::Halt);
  // `call` pushed `code_base + 1`, `ret` went there, `jmp` reached the exit
  // label and the list ran out.
  assert_eq!(s.regs[RSP as usize], 0x1_0080);
  assert_eq!(s.pc, code.len());
  let pushed = u64::from_le_bytes(s.mem[0x78..0x80].try_into().unwrap());
  assert_eq!(pushed, 0x4000_0001);
}

#[test]
fn a_ret_to_an_address_outside_the_list_is_unsupported() {
  let code = vec![PInsn::Ret];
  let mut s = model(0x4000_0000);
  s.regs[RSP as usize] = 0x1_0000;
  // The stack holds zero, which is not a position of this list.
  assert_eq!(run(&code, &mut s, 4), Outcome::Unsupported);
}

#[test]
fn a_branch_to_a_label_the_list_does_not_carry_is_unsupported() {
  let code = vec![PInsn::Jmp {
    target: PTarget::Local(7),
  }];
  let mut s = model(0);
  assert_eq!(run(&code, &mut s, 4), Outcome::Unsupported);
}

#[test]
fn an_access_outside_the_mapped_range_faults() {
  let below = vec![PInsn::Load {
    size: 8,
    sx: false,
    base: 0,
    dst: 1,
    disp: 0,
  }];
  let mut s = model(0);
  s.regs[0] = 0x1_0000 - 1;
  assert_eq!(run(&below, &mut s, 4), Outcome::Fault);
  // The faulting instruction left the state alone.
  assert_eq!(s.pc, 0);
  assert_eq!(s.regs[1], 0);

  let above = vec![PInsn::Store {
    size: 2,
    src: 1,
    base: 0,
    disp: 0,
  }];
  let mut s = model(0);
  s.regs[0] = 0x1_0000 + 255;
  assert_eq!(run(&above, &mut s, 4), Outcome::Fault);

  // The last byte in range is fine.
  let mut s = model(0);
  s.regs[0] = 0x1_0000 + 254;
  assert_eq!(run(&above, &mut s, 4), Outcome::Halt);
}

#[test]
fn a_divide_the_hardware_would_trap_on_faults() {
  let div = vec![PInsn::MulDivRcx {
    w64: true,
    kind: MulDivKind::Div,
    signed: false,
  }];
  // Divisor zero.
  let mut s = model(0);
  assert_eq!(run(&div, &mut s, 4), Outcome::Fault);
  // Quotient too large: rdx >= rcx.
  let mut s = model(0);
  s.regs[RDX as usize] = 2;
  s.regs[RCX as usize] = 2;
  assert_eq!(run(&div, &mut s, 4), Outcome::Fault);
  // And the one signed overflow: the most negative dividend over -1.
  let idiv = vec![PInsn::MulDivRcx {
    w64: true,
    kind: MulDivKind::Div,
    signed: true,
  }];
  let mut s = model(0);
  s.regs[RDX as usize] = 0x8000_0000_0000_0000;
  s.regs[RAX as usize] = 0;
  s.regs[RCX as usize] = u64::MAX;
  assert_eq!(run(&idiv, &mut s, 4), Outcome::Fault);
}

#[test]
fn the_primitives_that_leave_the_list_are_not_executed() {
  let mut s = model(0);
  assert_eq!(run(&[PInsn::Ud2], &mut s, 4), Outcome::Halt);
  let mut s = model(0);
  assert_eq!(
    run(&[PInsn::DispatcherSlot { addr: 7 }], &mut s, 4),
    Outcome::Halt
  );
  let mut s = model(0);
  assert_eq!(run(&[PInsn::HelperTable], &mut s, 4), Outcome::Halt);
  let mut s = model(0);
  assert_eq!(run(&[PInsn::CallReg(0)], &mut s, 4), Outcome::Unsupported);
  let mut s = model(0);
  assert_eq!(
    run(&[PInsn::RipLoadDispatcher { dst: 0 }], &mut s, 4),
    Outcome::Unsupported
  );
  let mut s = model(0);
  assert_eq!(
    run(&[PInsn::RipLeaHelperTable { dst: 0 }], &mut s, 4),
    Outcome::Unsupported
  );
}

#[test]
fn pop_rsp_lands_on_the_popped_word() {
  // `Step.pop` moves `rsp` before it writes the destination, as the hardware
  // does, so `pop rsp` ends holding the popped word and not `rsp + 8`. The
  // backend never emits it, and the differential harness never generates it.
  let code = vec![PInsn::Pop(RSP)];
  let mut s = model(0);
  s.regs[RSP as usize] = 0x1_0000;
  let mut i = 0;
  while i < 8 {
    s.mem[i] = 0xaa;
    i += 1;
  }
  assert_eq!(run(&code, &mut s, 4), Outcome::Halt);
  assert_eq!(s.regs[RSP as usize], 0xaaaa_aaaa_aaaa_aaaa);
}

#[test]
fn the_step_budget_leaves_a_runnable_machine_alone() {
  let code = vec![
    PInsn::Pause,
    PInsn::Pause,
    PInsn::Pause,
    PInsn::Pause,
    PInsn::Pause,
  ];
  let mut s = model(0);
  assert_eq!(run(&code, &mut s, 2), Outcome::Next);
  assert_eq!(s.pc, 2);
  assert_eq!(run(&code, &mut s, 8), Outcome::Halt);
}

//! aarch64 JIT relocation-range tests.
//!
//! Conditional branches on arm64 carry a signed 19-bit immediate (±1 MiB
//! reach). A program large enough to push the exit stub past that must be
//! refused rather than mis-encoded.
//!
//! These go through [`crate::jit::Translator`] directly rather than
//! `ProgramLoader`, because the loader's own 1 MiB code buffer rejects
//! oversized programs before the relocation logic is ever reached.
//!
//! These are the end-to-end shape of the limit: a whole program, loaded and
//! translated, refused or not. The *bytes* either side of the same boundary are
//! pinned separately, by the straddle tests in [`crate::jit::emit::aarch64`],
//! which walk the last few sizes that fit and the first few that do not and
//! record each one. Between them, a branch that stops encoding and a branch
//! that encodes the wrong displacement are both caught.

use std::sync::Arc;

use crate::jit::{
  isa::{opcode, Insn},
  Config, Target, TranslateError, TranslationInputs, Translator,
};

const UNWIND_HELPER_INDEX: u32 = 1;

const EBPF_OP_MOV64_IMM: u8 = 0xb7;
const EBPF_OP_ATOMIC_STORE: u8 = 0xdb;

/// Bytes the translated output is allowed to occupy. Well past what any of
/// these programs needs, so running out of buffer never masks the range check
/// these tests are about.
const CAPACITY: usize = 16 << 20;

fn insn(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Insn {
  Insn {
    opcode,
    dst,
    src,
    offset,
    imm,
  }
}

/// A stand-in dispatcher.
///
/// Never called: these tests translate and never execute what they emit. Its
/// address does reach the emitted code as an immediate, which is why the tests
/// here assert outcomes rather than bytes — a function's address moves with
/// every build.
unsafe extern "C" fn stub_dispatcher(
  _arg1: u64,
  _arg2: u64,
  _arg3: u64,
  _arg4: u64,
  _arg5: u64,
  _index: u32,
  _cookie: *mut std::ffi::c_void,
) -> u64 {
  0
}

unsafe extern "C" fn stub_validator(_index: u32, _vm: *const std::ffi::c_void) -> bool {
  true
}

fn config(target: Target) -> Config {
  Config {
    target,
    dispatcher: Some(stub_dispatcher),
    dispatcher_validate: Some(stub_validator),
    unwind_helper_index: Some(UNWIND_HELPER_INDEX),
    ..Default::default()
  }
}

/// A call to the unwind helper makes the JIT emit a conditional branch to the
/// exit stub, which is placed after the program body — so the branch has to
/// span all of the filler. Each atomic add expands to several arm64
/// instructions, putting the exit stub well past the ±1 MiB reach.
fn oversized_program(filler: usize) -> Vec<Insn> {
  let mut prog = vec![
    insn(opcode::CALL, 0, 0, 0, UNWIND_HELPER_INDEX as i32),
    insn(EBPF_OP_MOV64_IMM, 1, 0, 0, 0),
    insn(EBPF_OP_MOV64_IMM, 2, 0, 0, 0),
  ];
  prog.extend(std::iter::repeat(insn(EBPF_OP_ATOMIC_STORE, 1, 2, 0, 0)).take(filler));
  prog.push(insn(EBPF_OP_MOV64_IMM, 0, 0, 0, 0));
  prog.push(insn(opcode::EXIT, 0, 0, 0, 0));
  prog
}

fn translate(target: Target, prog: &[Insn]) -> Result<usize, TranslateError> {
  let code = Insn::encode_all(prog);
  let translator =
    Translator::load(Arc::new(config(target)), &code).expect("the program must load");
  let inputs = TranslationInputs {
    start_pc: 0,
    end_pc: prog.len(),
    ..Default::default()
  };
  let mut buf = vec![0u8; CAPACITY];
  translator.translate_range(&inputs, &mut buf)
}

#[test]
fn an_out_of_range_conditional_branch_is_refused() {
  let prog = oversized_program(65000);
  let err = translate(Target::Aarch64, &prog)
    .expect_err("expected translation to fail for an out-of-range conditional branch");
  // The exact wording, not merely that something failed: it is what an
  // embedder sees, and it names which reach was exceeded.
  assert_eq!(
    err,
    TranslateError::Failed(
      "Branch or load target out of range in the JIT'd code (the program is too large for \
       arm64 PC-relative addressing)."
        .to_string()
    ),
    "translation failed for an unexpected reason"
  );
}

/// The complement, so the test above is known to be measuring the branch range
/// and not merely that very large programs fail for some reason.
#[test]
fn a_program_just_inside_the_branch_range_still_translates() {
  let prog = oversized_program(1000);
  let len =
    translate(Target::Aarch64, &prog).expect("a program well inside the range must translate");
  // ...and the two sizes really do sit either side of the reach rather than
  // both being far from it: this one fills a healthy fraction of the 1 MiB a
  // conditional branch spans, so the refusal above is the boundary being
  // crossed and not some unrelated cap.
  assert!(
    (1 << 14..1 << 20).contains(&len),
    "the in-range program emitted {len} bytes, which is no longer a useful \
     distance below the 1 MiB conditional-branch reach"
  );
}

/// x86_64 has a 32-bit displacement on conditional branches, so the same
/// program that overflows arm64's 19-bit immediate translates fine there.
/// Pins that the refusal is architecture-specific rather than a size cap.
#[test]
fn the_same_program_translates_for_x86_64() {
  let prog = oversized_program(65000);
  translate(Target::X86_64, &prog).expect("x86_64 has the reach for this program");
}

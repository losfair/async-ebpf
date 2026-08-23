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
//! They used to go through the raw uBPF bindings, and could only check the
//! host's own backend. Translation is pure computation over a byte buffer, so
//! the Rust translator will emit aarch64 code on any host — which means this
//! now runs everywhere instead of only on arm64 CI.

use std::sync::Arc;

use crate::jit::{
  isa::{opcode, Insn},
  Config, Target, TranslateError, TranslationInputs, Translator,
};

const UNWIND_HELPER_INDEX: u32 = 1;

const EBPF_OP_MOV64_IMM: u8 = 0xb7;
const EBPF_OP_ATOMIC_STORE: u8 = 0xdb;

fn insn(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Insn {
  Insn {
    opcode,
    dst,
    src,
    offset,
    imm,
  }
}

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
  let mut buf = vec![0u8; 16 << 20];
  translator.translate_range(&inputs, &mut buf)
}

#[test]
fn an_out_of_range_conditional_branch_is_refused() {
  let prog = oversized_program(65000);
  let err = translate(Target::Aarch64, &prog)
    .expect_err("expected translation to fail for an out-of-range conditional branch");
  match err {
    TranslateError::Failed(msg) => assert!(
      msg.contains("out of range"),
      "translation failed for an unexpected reason: {msg}"
    ),
    TranslateError::OutOfSpace => panic!("ran out of buffer rather than reaching the range check"),
  }
}

/// The complement, so the test above is known to be measuring the branch range
/// and not merely that very large programs fail for some reason.
#[test]
fn a_program_just_inside_the_branch_range_still_translates() {
  let prog = oversized_program(1000);
  translate(Target::Aarch64, &prog).expect("a program well inside the range must translate");
}

/// x86_64 has a 32-bit displacement on conditional branches, so the same
/// program that overflows arm64's 19-bit immediate translates fine there.
/// Pins that the refusal is architecture-specific rather than a size cap.
#[test]
fn the_same_program_translates_for_x86_64() {
  let prog = oversized_program(65000);
  translate(Target::X86_64, &prog).expect("x86_64 has the reach for this program");
}

/// The vendored C must agree, on both counts.
#[cfg(feature = "oracle")]
#[test]
fn the_c_agrees_about_the_relocation_range() {
  use crate::jit::oracle::COracle;

  for (filler, should_fail) in [(65000usize, true), (1000, false)] {
    let prog = oversized_program(filler);
    let code = Insn::encode_all(&prog);
    let cfg = config(Target::Aarch64);
    let c = COracle::load(&cfg, &code).expect("the program must load in the C");
    let inputs = TranslationInputs {
      start_pc: 0,
      end_pc: prog.len(),
      ..Default::default()
    };
    let c_out = c.translate(Target::Aarch64, &inputs, 16 << 20);
    let rust_out = translate(Target::Aarch64, &prog);
    assert_eq!(
      c_out.is_err(),
      should_fail,
      "the C disagreed about whether {filler} filler instructions overflow the branch range"
    );
    assert_eq!(
      c_out.map(|v| v.len()),
      rust_out,
      "backends disagree for {filler} filler instructions"
    );
  }
}

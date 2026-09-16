//! Entrypoints are the object's exported functions - its global (or weak)
//! `STT_FUNC` symbols - not its section names.
//!
//! Section-named entrypoints forced every entry function into a section of its
//! own, and LLVM refuses a function that shares its section's name (the
//! section symbol takes it), so the section could never be called what the
//! function was. They also made `.text` an entrypoint in its own right, which
//! is why the compile pipeline used to strip it and every non-entry function
//! needed a named section too. Naming entrypoints by symbol removes both
//! constraints: functions live wherever the compiler puts them, `static` ones
//! stay internal, and the rest are callable by name.

use std::{any::Any, sync::Arc};

use elf::{endian::LittleEndian, ElfBytes};

use super::raw_elf::{
  build_elf, load_raw_elf, symbol_record_offset, Insn, DATA_SYM_INDEX, ENTRY_SYM, ENTRY_SYM_INDEX,
  SEC_TEXT,
};
use crate::{
  error::{Error, RuntimeError},
  program::{DummyProgramEventListener, PreemptionEnabled, Program, ProgramLoader},
  test_util::{compile_ebpf, gt_env, timeslice_config, TokioTimeslicer},
};

const SHF_EXECINSTR: u64 = 1 << 2;
const STT_FUNC: u8 = 2;

fn load(binary: &[u8]) -> Program {
  let (_, t_env) = gt_env();
  ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .load(&mut rand::thread_rng(), binary)
  .unwrap()
  .pin_to_current_thread(t_env)
}

async fn run(program: &Program, entrypoint: &str) -> Result<i64, Error> {
  let mut resources: [&mut dyn Any; 0] = [];
  program
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      entrypoint,
      &mut resources,
      &[],
      &PreemptionEnabled::new(program.thread_env()),
    )
    .await
}

fn assert_not_an_entrypoint(result: Result<i64, Error>) {
  assert!(
    matches!(
      result,
      Err(Error(RuntimeError::InvalidArgument("entrypoint not found")))
    ),
    "expected a missing entrypoint, got {result:?}"
  );
}

/// Functions need no section attribute: whatever lands in `.text` is loaded
/// as it is, every non-`static` function is an entrypoint under its own name,
/// and neither a `static` function nor a section is.
#[tokio::test]
async fn exported_functions_are_entrypoints_wherever_they_live() {
  let binary = compile_ebpf(
    br#"
      static int __attribute__((noinline)) helper(int x) { return x + 7; }
      int first(void) { return 1; }
      int entry(void) { return helper(35); }
      int __attribute__((weak)) weak_entry(void) { return 5; }
      static int __attribute__((noinline, section("aside"))) far_helper(int x) { return x * 2; }
      int doubled(void) { return far_helper(21); }
    "#
    .to_vec(),
  )
  .await
  .unwrap();

  // The pipeline keeps `.text`, and that is where the unattributed functions
  // are - not all of them at its first instruction.
  let parsed = ElfBytes::<LittleEndian>::minimal_parse(&binary).unwrap();
  let (Some(sections), Some(section_names)) = parsed.section_headers_with_strtab().unwrap() else {
    panic!("section table missing");
  };
  let (text_index, text) = sections
    .iter()
    .enumerate()
    .find(|(_, section)| section_names.get(section.sh_name as usize).ok() == Some(".text"))
    .expect(".text was stripped from the object");
  assert!(text.sh_flags & SHF_EXECINSTR != 0 && text.sh_size > 0);
  let (symtab, symbol_names) = parsed.symbol_table().unwrap().unwrap();
  let text_functions: Vec<(String, u64)> = symtab
    .iter()
    .filter(|symbol| symbol.st_symtype() == STT_FUNC && symbol.st_shndx as usize == text_index)
    .map(|symbol| {
      (
        symbol_names
          .get(symbol.st_name as usize)
          .unwrap()
          .to_string(),
        symbol.st_value,
      )
    })
    .collect();
  for name in ["first", "entry", "weak_entry", "doubled", "helper"] {
    assert!(
      text_functions
        .iter()
        .any(|(candidate, _)| candidate == name),
      "{name} is not in .text: {text_functions:?}"
    );
  }
  assert!(
    text_functions
      .iter()
      .any(|(name, value)| name == "entry" && *value != 0)
      || text_functions
        .iter()
        .any(|(name, value)| name == "first" && *value != 0),
    "both entrypoints sit at the first instruction: {text_functions:?}"
  );

  let program = load(&binary);
  for name in ["first", "entry", "weak_entry", "doubled"] {
    assert!(program.has_entrypoint(name), "{name} is not an entrypoint");
  }
  assert_eq!(run(&program, "first").await.unwrap(), 1);
  assert_eq!(run(&program, "entry").await.unwrap(), 42);
  assert_eq!(run(&program, "weak_entry").await.unwrap(), 5);
  assert_eq!(run(&program, "doubled").await.unwrap(), 42);

  for name in ["helper", "far_helper", ".text", "aside"] {
    assert!(!program.has_entrypoint(name), "{name} is an entrypoint");
    assert_not_an_entrypoint(run(&program, name).await);
  }
}

/// An exported function is still an ordinary local callee: the host enters it
/// with the entry signature, guest code with the call site's, and both work.
#[tokio::test]
async fn an_entrypoint_may_also_be_called_locally() {
  let binary = compile_ebpf(
    br#"
      int __attribute__((noinline)) seven(void) { return 7; }
      int entry(void) { return seven() + 35; }
    "#
    .to_vec(),
  )
  .await
  .unwrap();
  let program = load(&binary);

  assert_eq!(run(&program, "entry").await.unwrap(), 42);
  assert_eq!(run(&program, "seven").await.unwrap(), 7);
  assert_eq!(run(&program, "entry").await.unwrap(), 42);
}

/// Two exported symbols may name one function; the entrypoint is reachable
/// under either.
#[tokio::test]
async fn aliases_of_one_function_are_both_entrypoints() {
  let mut elf = build_elf(&[Insn::mov64_imm(0, 9), Insn::exit()], &[]);
  // Turn the unused data symbol into a second global function at PC 0.
  let record = symbol_record_offset(&elf, DATA_SYM_INDEX);
  elf[record + 4] = 0x12; // GLOBAL / FUNC
  elf[record + 6..record + 8].copy_from_slice(&(SEC_TEXT as u16).to_le_bytes());
  elf[record + 8..record + 16].copy_from_slice(&0u64.to_le_bytes());
  elf[record + 16..record + 24].copy_from_slice(&16u64.to_le_bytes());

  let program = load(&elf);
  assert_eq!(run(&program, ENTRY_SYM).await.unwrap(), 9);
  assert_eq!(run(&program, "DATA_SYM").await.unwrap(), 9);
}

/// A function symbol has to name an instruction of its section: anything
/// unaligned or past the end is a malformed object, not a function.
#[test]
fn a_function_symbol_outside_its_section_is_refused() {
  let elf = build_elf(&[Insn::exit()], &[]);
  let value_field = symbol_record_offset(&elf, ENTRY_SYM_INDEX) + 8;

  for bad_value in [4u64, 8] {
    let mut malformed = elf.clone();
    malformed[value_field..value_field + 8].copy_from_slice(&bad_value.to_le_bytes());
    let err = load_raw_elf(&malformed).expect_err("a wild function symbol must not load");
    let err = format!("{err:?}");
    assert!(
      err.contains("unaligned or outside its code section"),
      "unexpected load error for symbol value {bad_value}: {err}"
    );
  }
}

/// The second slot of an `lddw` is not an instruction, so a function cannot
/// start there.
#[test]
fn a_function_symbol_inside_lddw_is_refused() {
  let [lo, hi] = Insn::lddw_data(0, 0);
  let elf = build_elf(&[lo, hi, Insn::exit()], &[0u8; 8]);
  let value_field = symbol_record_offset(&elf, ENTRY_SYM_INDEX) + 8;

  let mut malformed = elf.clone();
  malformed[value_field..value_field + 8].copy_from_slice(&8u64.to_le_bytes());
  load_raw_elf(&malformed).expect_err("a function starting inside lddw must not load");
}

/// Two exported functions with one name would make the entrypoint ambiguous;
/// no compiler emits that, so it is refused rather than resolved.
#[test]
fn duplicate_exported_function_names_are_refused() {
  let mut elf = build_elf(&[Insn::exit()], &[]);
  let entry_record = symbol_record_offset(&elf, ENTRY_SYM_INDEX);
  let entry_name = elf[entry_record..entry_record + 4].to_vec();
  // Turn the unused data symbol into a second global function that reuses the
  // entry function's name.
  let record = symbol_record_offset(&elf, DATA_SYM_INDEX);
  elf[record..record + 4].copy_from_slice(&entry_name);
  elf[record + 4] = 0x12; // GLOBAL / FUNC
  elf[record + 6..record + 8].copy_from_slice(&(SEC_TEXT as u16).to_le_bytes());
  elf[record + 8..record + 16].copy_from_slice(&0u64.to_le_bytes());

  let err = load_raw_elf(&elf).expect_err("duplicate exported names must not load");
  let err = format!("{err:?}");
  assert!(
    err.contains("more than one exported function shares a name"),
    "unexpected load error: {err}"
  );
}

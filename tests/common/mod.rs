#![allow(dead_code)]

use std::{sync::Arc, time::Duration};

use async_ebpf::{
  helpers::Helper,
  program::{DummyProgramEventListener, GlobalEnv, PreemptionEnabled, ProgramLoader},
  test_util::{timeslice_config, TokioTimeslicer},
};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Clone)]
pub struct Insn {
  pub value: u64,
  pub reloc: Option<&'static str>,
}

impl Insn {
  pub fn raw(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Self {
    Self {
      value: opcode as u64
        | ((dst as u64) << 8)
        | ((src as u64) << 12)
        | ((offset as u16 as u64) << 16)
        | ((imm as u32 as u64) << 32),
      reloc: None,
    }
  }
  pub fn exit() -> Self {
    Self::raw(0x95, 0, 0, 0, 0)
  }
  pub fn call(name: &'static str) -> Self {
    Self {
      value: Self::raw(0x85, 0, 1, 0, 0).value,
      reloc: Some(name),
    }
  }
  pub fn mov64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0xb7, dst, 0, 0, imm)
  }
  pub fn mov64_reg(dst: u8, src: u8) -> Self {
    Self::raw(0xbf, dst, src, 0, 0)
  }
  pub fn add64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x07, dst, 0, 0, imm)
  }
  pub fn add64_reg(dst: u8, src: u8) -> Self {
    Self::raw(0x0f, dst, src, 0, 0)
  }
  pub fn sub64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x17, dst, 0, 0, imm)
  }
  pub fn sub64_reg(dst: u8, src: u8) -> Self {
    Self::raw(0x1f, dst, src, 0, 0)
  }
  pub fn and64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x57, dst, 0, 0, imm)
  }
  pub fn lsh64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x67, dst, 0, 0, imm)
  }
  pub fn rsh64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x77, dst, 0, 0, imm)
  }
  pub fn mov32_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0xb4, dst, 0, 0, imm)
  }
  pub fn jeq_imm(dst: u8, imm: i32, offset: i16) -> Self {
    Self::raw(0x15, dst, 0, offset, imm)
  }
  pub fn jne_imm(dst: u8, imm: i32, offset: i16) -> Self {
    Self::raw(0x55, dst, 0, offset, imm)
  }
  pub fn ja(offset: i16) -> Self {
    Self::raw(0x05, 0, 0, offset, 0)
  }
  pub fn call_helper(imm: i32) -> Self {
    Self::raw(0x85, 0, 0, 0, imm)
  }
  pub fn call_local(imm: i32) -> Self {
    Self::raw(0x85, 0, 1, 0, imm)
  }
  pub fn ldx_dw(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x79, dst, src, offset, 0)
  }
  pub fn ldx_w(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x61, dst, src, offset, 0)
  }
  pub fn ldx_h(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x69, dst, src, offset, 0)
  }
  pub fn ldx_b(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x71, dst, src, offset, 0)
  }
  pub fn stx_dw(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x7b, dst, src, offset, 0)
  }
  pub fn stx_w(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x63, dst, src, offset, 0)
  }
  pub fn stx_b(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x73, dst, src, offset, 0)
  }
  pub fn st_dw(dst: u8, offset: i16, imm: i32) -> Self {
    Self::raw(0x7a, dst, 0, offset, imm)
  }
  pub fn st_b(dst: u8, offset: i16, imm: i32) -> Self {
    Self::raw(0x72, dst, 0, offset, imm)
  }
  pub fn lddw(dst: u8, imm: u64) -> [Self; 2] {
    [
      Self::raw(0x18, dst, 0, 0, imm as u32 as i32),
      Self::raw(0x00, 0, 0, 0, (imm >> 32) as u32 as i32),
    ]
  }
  /// `lddw` that carries an R_BPF_64_64 relocation against `sym`.
  pub fn lddw_reloc(dst: u8, sym: &'static str, addend: u64) -> [Self; 2] {
    [
      Self {
        value: Self::raw(0x18, dst, 0, 0, addend as u32 as i32).value,
        reloc: Some(sym),
      },
      Self::raw(0x00, 0, 0, 0, (addend >> 32) as u32 as i32),
    ]
  }
}

pub fn insns(v: Vec<Vec<Insn>>) -> Vec<Insn> {
  v.into_iter().flatten().collect()
}

pub struct Built {
  pub elf: Vec<u8>,
}

/// Loads and runs `code` as a program named "test" through the public safe API.
pub fn run_program_with(
  code: &[Insn],
  helpers: &'static [(&'static str, Helper)],
  calldata: &[u8],
  strict: bool,
  seed: u64,
) -> Result<i64, async_ebpf::error::Error> {
  let elf = build_elf(code, &helpers.iter().map(|x| x.0).collect::<Vec<_>>());
  run_elf(&elf, helpers, calldata, strict, seed)
}

pub fn run_elf(
  elf: &[u8],
  helpers: &'static [(&'static str, Helper)],
  calldata: &[u8],
  strict: bool,
  seed: u64,
) -> Result<i64, async_ebpf::error::Error> {
  let mut rng = StdRng::seed_from_u64(seed);
  let loader = ProgramLoader::new(&mut rng, Arc::new(DummyProgramEventListener), &[helpers])
    .require_static_region_analysis(strict);
  let program = loader.load(&mut rng, elf)?;

  let global = unsafe { GlobalEnv::new() };
  let thread = global.init_thread(Duration::from_millis(100));
  let program = program.pin_to_current_thread(thread);
  let mut resources: [&mut dyn std::any::Any; 0] = [];
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_time()
    .build()
    .unwrap();

  runtime.block_on(program.run(
    &timeslice_config(),
    &TokioTimeslicer,
    "test",
    &mut resources,
    calldata,
    &PreemptionEnabled::new(thread),
  ))
}

pub fn build_elf(code: &[Insn], external_symbols: &[&str]) -> Vec<u8> {
  build_elf_with_data(code, external_symbols, &[])
}

/// Builds a BPF relocatable ELF with one executable section named `test`,
/// optionally with an allocated read-only data section named `rodata` whose
/// symbol `DATA_SYM` is at offset 0.
pub fn build_elf_with_data(code: &[Insn], external_symbols: &[&str], rodata: &[u8]) -> Vec<u8> {
  const SHN_UNDEF: u16 = 0;
  const SHT_PROGBITS: u32 = 1;
  const SHT_SYMTAB: u32 = 2;
  const SHT_STRTAB: u32 = 3;
  const SHT_REL: u32 = 9;
  const SHF_ALLOC: u64 = 1 << 1;
  const SHF_EXECINSTR: u64 = 1 << 2;
  const R_BPF_64_32: u64 = 10;
  const R_BPF_64_64: u64 = 1;

  // shstrtab layout
  let mut shstrtab = vec![0u8];
  let add_shname = |s: &str, t: &mut Vec<u8>| {
    let off = t.len() as u32;
    t.extend_from_slice(s.as_bytes());
    t.push(0);
    off
  };
  let name_test = add_shname("test", &mut shstrtab);
  let name_reltest = add_shname(".reltest", &mut shstrtab);
  let name_symtab = add_shname(".symtab", &mut shstrtab);
  let name_strtab = add_shname(".strtab", &mut shstrtab);
  let name_shstrtab = add_shname(".shstrtab", &mut shstrtab);
  let name_rodata = add_shname("rodata", &mut shstrtab);

  // symbols: index 0 = null; 1..=n = external; then DATA_SYM (if rodata)
  let mut strtab = vec![0u8];
  let mut sym_name_offsets = Vec::new();
  for name in external_symbols {
    let offset = strtab.len() as u32;
    strtab.extend_from_slice(name.as_bytes());
    strtab.push(0);
    sym_name_offsets.push(offset);
  }
  let data_sym_off = {
    let offset = strtab.len() as u32;
    strtab.extend_from_slice(b"DATA_SYM");
    strtab.push(0);
    offset
  };
  let data_sym_index = external_symbols.len() + 1;

  let mut text = Vec::with_capacity(code.len() * 8);
  let mut rels = Vec::new();
  for (index, insn) in code.iter().enumerate() {
    text.extend_from_slice(&insn.value.to_le_bytes());
    if let Some(name) = insn.reloc {
      if name == "DATA_SYM" {
        let r_info = ((data_sym_index as u64) << 32) | R_BPF_64_64;
        rels.extend_from_slice(&((index * 8) as u64).to_le_bytes());
        rels.extend_from_slice(&r_info.to_le_bytes());
      } else {
        let sym = external_symbols
          .iter()
          .position(|candidate| *candidate == name)
          .map(|i| i + 1)
          .unwrap_or(0);
        let r_info = ((sym as u64) << 32) | R_BPF_64_32;
        rels.extend_from_slice(&((index * 8) as u64).to_le_bytes());
        rels.extend_from_slice(&r_info.to_le_bytes());
      }
    }
  }

  // symtab: null + externals (SHN_UNDEF) + DATA_SYM (section index 6 = rodata)
  let mut symtab = vec![0u8; 24];
  for name_offset in &sym_name_offsets {
    symtab.extend_from_slice(&name_offset.to_le_bytes());
    symtab.push(0x10);
    symtab.push(0);
    symtab.extend_from_slice(&SHN_UNDEF.to_le_bytes());
    symtab.extend_from_slice(&0u64.to_le_bytes());
    symtab.extend_from_slice(&0u64.to_le_bytes());
  }
  // DATA_SYM: st_value = 0, st_size = rodata.len()
  symtab.extend_from_slice(&data_sym_off.to_le_bytes());
  symtab.push(0x10);
  symtab.push(0);
  symtab.extend_from_slice(&6u16.to_le_bytes()); // rodata is section index 6
  symtab.extend_from_slice(&0u64.to_le_bytes());
  symtab.extend_from_slice(&(rodata.len() as u64).to_le_bytes());

  let mut elf = vec![0u8; 64];
  let text_offset = append_aligned(&mut elf, &text, 8);
  let rel_offset = append_aligned(&mut elf, &rels, 8);
  let symtab_offset = append_aligned(&mut elf, &symtab, 8);
  let strtab_offset = append_aligned(&mut elf, &strtab, 1);
  let shstrtab_offset = append_aligned(&mut elf, &shstrtab, 1);
  let rodata_offset = append_aligned(&mut elf, rodata, 8);
  let shoff = align_vec(&mut elf, 8);

  let mut sections = Vec::new();
  sections.extend_from_slice(&[0u8; 64]);
  write_section(
    &mut sections,
    name_test,
    SHT_PROGBITS,
    SHF_ALLOC | SHF_EXECINSTR,
    text_offset,
    text.len(),
    0,
    0,
    8,
    0,
  );
  write_section(
    &mut sections,
    name_reltest,
    SHT_REL,
    0,
    rel_offset,
    rels.len(),
    3,
    1,
    8,
    16,
  );
  write_section(
    &mut sections,
    name_symtab,
    SHT_SYMTAB,
    0,
    symtab_offset,
    symtab.len(),
    4,
    1,
    8,
    24,
  );
  write_section(
    &mut sections,
    name_strtab,
    SHT_STRTAB,
    0,
    strtab_offset,
    strtab.len(),
    0,
    0,
    1,
    0,
  );
  write_section(
    &mut sections,
    name_shstrtab,
    SHT_STRTAB,
    0,
    shstrtab_offset,
    shstrtab.len(),
    0,
    0,
    1,
    0,
  );
  write_section(
    &mut sections,
    name_rodata,
    SHT_PROGBITS,
    SHF_ALLOC,
    rodata_offset,
    rodata.len(),
    0,
    0,
    8,
    0,
  );
  elf.extend_from_slice(&sections);

  write_elf_header(&mut elf[..64], shoff, 7);
  elf
}

fn append_aligned(out: &mut Vec<u8>, data: &[u8], align: usize) -> u64 {
  let offset = align_vec(out, align);
  out.extend_from_slice(data);
  offset
}

fn align_vec(out: &mut Vec<u8>, align: usize) -> u64 {
  let padding = (align - (out.len() % align)) % align;
  out.resize(out.len() + padding, 0);
  out.len() as u64
}

#[allow(clippy::too_many_arguments)]
fn write_section(
  out: &mut Vec<u8>,
  name: u32,
  ty: u32,
  flags: u64,
  offset: u64,
  size: usize,
  link: u32,
  info: u32,
  addralign: u64,
  entsize: u64,
) {
  out.extend_from_slice(&name.to_le_bytes());
  out.extend_from_slice(&ty.to_le_bytes());
  out.extend_from_slice(&flags.to_le_bytes());
  out.extend_from_slice(&0u64.to_le_bytes());
  out.extend_from_slice(&offset.to_le_bytes());
  out.extend_from_slice(&(size as u64).to_le_bytes());
  out.extend_from_slice(&link.to_le_bytes());
  out.extend_from_slice(&info.to_le_bytes());
  out.extend_from_slice(&addralign.to_le_bytes());
  out.extend_from_slice(&entsize.to_le_bytes());
}

fn write_elf_header(header: &mut [u8], shoff: u64, shnum: u16) {
  header[0..4].copy_from_slice(b"\x7fELF");
  header[4] = 2;
  header[5] = 1;
  header[6] = 1;
  header[16..18].copy_from_slice(&1u16.to_le_bytes());
  header[18..20].copy_from_slice(&247u16.to_le_bytes());
  header[20..24].copy_from_slice(&1u32.to_le_bytes());
  header[40..48].copy_from_slice(&shoff.to_le_bytes());
  header[52..54].copy_from_slice(&64u16.to_le_bytes());
  header[58..60].copy_from_slice(&64u16.to_le_bytes());
  header[60..62].copy_from_slice(&shnum.to_le_bytes());
  header[62..64].copy_from_slice(&5u16.to_le_bytes());
}

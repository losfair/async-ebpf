//! Scaffolding for tests that need instruction-level control over the loaded
//! program.
//!
//! `compile_ebpf` cannot express what a few tests need — the register state the
//! guest observes at entry, or one specific atomic encoding — so those tests
//! hand-assemble a BPF relocatable ELF instead and load it through the normal
//! public API. The object has one executable section named `test` and one
//! allocated read-only section whose symbol `DATA_SYM` sits at offset 0, so a
//! `lddw` carrying an `R_BPF_64_64` relocation against it yields a data-region
//! pointer.

use std::{any::Any, sync::Arc};

use crate::{
  error::Error,
  program::{DummyProgramEventListener, PreemptionEnabled, ProgramLoader},
  test_util::{gt_env, timeslice_config, TokioTimeslicer},
};

/// Symbol the read-only data section exports at offset 0.
const DATA_SYM: &str = "DATA_SYM";

/// Symbol helper calls relocate against; resolved by name in the loader's
/// registered helper tables.
const HELPER_SYM: &str = "h";

/// One instruction slot, plus whether it carries a relocation against
/// [`DATA_SYM`].
#[derive(Clone, Copy)]
pub(crate) struct Insn {
  pub(crate) value: u64,
  data_reloc: bool,
  helper_reloc: bool,
}

impl Insn {
  pub(crate) fn raw(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Self {
    Self {
      value: opcode as u64
        | ((dst as u64) << 8)
        | ((src as u64) << 12)
        | ((offset as u16 as u64) << 16)
        | ((imm as u32 as u64) << 32),
      data_reloc: false,
      helper_reloc: false,
    }
  }

  pub(crate) fn exit() -> Self {
    Self::raw(0x95, 0, 0, 0, 0)
  }

  pub(crate) fn mov64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0xb7, dst, 0, 0, imm)
  }

  pub(crate) fn mov64_reg(dst: u8, src: u8) -> Self {
    Self::raw(0xbf, dst, src, 0, 0)
  }

  pub(crate) fn add64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x07, dst, 0, 0, imm)
  }

  pub(crate) fn or64_reg(dst: u8, src: u8) -> Self {
    Self::raw(0x4f, dst, src, 0, 0)
  }

  pub(crate) fn ldx_dw(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x79, dst, src, offset, 0)
  }

  pub(crate) fn ldx_b(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x71, dst, src, offset, 0)
  }

  pub(crate) fn stx_dw(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x7b, dst, src, offset, 0)
  }

  /// Local call to `pc + imm + 1`.
  pub(crate) fn call_local(imm: i32) -> Self {
    Self::raw(0x85, 0, 1, 0, imm)
  }

  /// Call the helper registered under [`HELPER_SYM`].
  pub(crate) fn call_helper() -> Self {
    let mut call = Self::raw(0x85, 0, 0, 0, 0);
    call.helper_reloc = true;
    call
  }

  /// `lddw dst, &DATA_SYM + addend`, as the two slots it occupies.
  pub(crate) fn lddw_data(dst: u8, addend: u64) -> [Self; 2] {
    let mut lo = Self::raw(0x18, dst, 0, 0, addend as u32 as i32);
    lo.data_reloc = true;
    [lo, Self::raw(0x00, 0, 0, 0, (addend >> 32) as u32 as i32)]
  }
}

/// Loads `elf` and returns whatever the loader made of it, without running.
pub(crate) fn load_raw_elf(elf: &[u8]) -> Result<(), Error> {
  ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .load(&mut rand::thread_rng(), elf)
  .map(|_| ())
}

/// Appends `extra` copies of the `test` section header, each describing exactly
/// the same bytes.
///
/// Nothing in ELF requires two section headers to describe disjoint ranges, so
/// this is how one code blob is made to cost the loader N times over: 64 bytes
/// of header buys a full analyze-and-translate pass.
pub(crate) fn duplicate_code_section_header(elf: &[u8], extra: usize) -> Vec<u8> {
  const SEC_TEXT: usize = 1;

  let mut elf = elf.to_vec();
  let shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
  let shnum = u16::from_le_bytes(elf[60..62].try_into().unwrap()) as usize;
  let text_header = elf[shoff + SEC_TEXT * 64..shoff + (SEC_TEXT + 1) * 64].to_vec();

  // The headers sit last, so the copies can simply be appended.
  assert_eq!(
    shoff + shnum * 64,
    elf.len(),
    "section headers are not last"
  );
  for _ in 0..extra {
    elf.extend_from_slice(&text_header);
  }
  let shnum = u16::try_from(shnum + extra).unwrap();
  elf[60..62].copy_from_slice(&shnum.to_le_bytes());
  elf
}

/// Loads `code` as the program `test` and runs it to completion.
pub(crate) async fn run_raw(
  code: &[Insn],
  rodata: &[u8],
  calldata: &[u8],
  require_static_regions: bool,
) -> Result<i64, Error> {
  run_raw_with_helpers(code, rodata, calldata, require_static_regions, &[]).await
}

/// [`run_raw`] using the contiguous stack compatibility layout.
pub(crate) async fn run_raw_contiguous(
  code: &[Insn],
  rodata: &[u8],
  calldata: &[u8],
  require_static_regions: bool,
) -> Result<i64, Error> {
  run_raw_configured(
    code,
    rodata,
    calldata,
    require_static_regions,
    &[],
    Some(false),
  )
  .await
}

/// [`run_raw`] with helper tables registered on the loader.
pub(crate) async fn run_raw_with_helpers(
  code: &[Insn],
  rodata: &[u8],
  calldata: &[u8],
  require_static_regions: bool,
  helpers: &[&[(&'static str, crate::helpers::Helper)]],
) -> Result<i64, Error> {
  run_raw_configured(
    code,
    rodata,
    calldata,
    require_static_regions,
    helpers,
    None,
  )
  .await
}

async fn run_raw_configured(
  code: &[Insn],
  rodata: &[u8],
  calldata: &[u8],
  require_static_regions: bool,
  helpers: &[&[(&'static str, crate::helpers::Helper)]],
  guarded_stack_frames: Option<bool>,
) -> Result<i64, Error> {
  let (_, t_env) = gt_env();
  let elf = build_elf(code, rodata);

  let loader = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    helpers,
  );
  let loader = match guarded_stack_frames {
    Some(enabled) => loader.with_guarded_stack_frames(enabled),
    None => loader,
  };
  let program = loader
    .require_static_region_analysis(require_static_regions)
    .load(&mut rand::thread_rng(), &elf)?
    .pin_to_current_thread(t_env);

  let mut resources: [&mut dyn Any; 0] = [];
  program
    .run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut resources,
      calldata,
      &PreemptionEnabled::new(t_env),
    )
    .await
}

pub(crate) fn build_elf(code: &[Insn], rodata: &[u8]) -> Vec<u8> {
  const SHT_PROGBITS: u32 = 1;
  const SHT_SYMTAB: u32 = 2;
  const SHT_STRTAB: u32 = 3;
  const SHT_REL: u32 = 9;
  const SHF_ALLOC: u64 = 1 << 1;
  const SHF_EXECINSTR: u64 = 1 << 2;
  const R_BPF_64_64: u64 = 1;
  const R_BPF_64_32: u64 = 10;

  // Section header string table, in the order the headers are written below.
  let mut shstrtab = vec![0u8];
  let shname = |name: &str, table: &mut Vec<u8>| {
    let offset = table.len() as u32;
    table.extend_from_slice(name.as_bytes());
    table.push(0);
    offset
  };
  let name_text = shname("test", &mut shstrtab);
  let name_rel = shname(".reltest", &mut shstrtab);
  let name_symtab = shname(".symtab", &mut shstrtab);
  let name_strtab = shname(".strtab", &mut shstrtab);
  let name_shstrtab = shname(".shstrtab", &mut shstrtab);
  let name_rodata = shname("rodata", &mut shstrtab);

  // Section header indices, in the order the headers are written below.
  const SEC_TEXT: u32 = 1;
  const SEC_SYMTAB: u32 = 3;
  const SEC_STRTAB: u32 = 4;
  const SEC_RODATA: u16 = 5;
  const SEC_SHSTRTAB: u16 = 6;
  const SEC_COUNT: u16 = 7;

  // Symbol table: index 0 is the mandatory null entry, index 1 is DATA_SYM,
  // index 2 is the undefined helper symbol.
  const DATA_SYM_INDEX: u32 = 1;
  const HELPER_SYM_INDEX: u32 = 2;
  let mut strtab = vec![0u8];
  let data_sym_name = strtab.len() as u32;
  strtab.extend_from_slice(DATA_SYM.as_bytes());
  strtab.push(0);
  let helper_sym_name = strtab.len() as u32;
  strtab.extend_from_slice(HELPER_SYM.as_bytes());
  strtab.push(0);

  let mut symtab = vec![0u8; 24];
  symtab.extend_from_slice(&data_sym_name.to_le_bytes());
  symtab.push(0x10); // st_info: GLOBAL / NOTYPE
  symtab.push(0); // st_other
  symtab.extend_from_slice(&SEC_RODATA.to_le_bytes());
  symtab.extend_from_slice(&0u64.to_le_bytes()); // st_value
  symtab.extend_from_slice(&(rodata.len() as u64).to_le_bytes()); // st_size
  symtab.extend_from_slice(&helper_sym_name.to_le_bytes());
  symtab.push(0x10); // st_info: GLOBAL / NOTYPE
  symtab.push(0); // st_other
  symtab.extend_from_slice(&0u16.to_le_bytes()); // st_shndx: SHN_UNDEF
  symtab.extend_from_slice(&0u64.to_le_bytes());
  symtab.extend_from_slice(&0u64.to_le_bytes());

  let mut text = Vec::with_capacity(code.len() * 8);
  let mut rels = Vec::new();
  for (index, insn) in code.iter().enumerate() {
    text.extend_from_slice(&insn.value.to_le_bytes());
    if insn.data_reloc {
      rels.extend_from_slice(&((index * 8) as u64).to_le_bytes());
      rels.extend_from_slice(&(((DATA_SYM_INDEX as u64) << 32) | R_BPF_64_64).to_le_bytes());
    }
    if insn.helper_reloc {
      rels.extend_from_slice(&((index * 8) as u64).to_le_bytes());
      rels.extend_from_slice(&(((HELPER_SYM_INDEX as u64) << 32) | R_BPF_64_32).to_le_bytes());
    }
  }

  let mut elf = vec![0u8; 64];
  let text_offset = append_aligned(&mut elf, &text, 8);
  let rel_offset = append_aligned(&mut elf, &rels, 8);
  let symtab_offset = append_aligned(&mut elf, &symtab, 8);
  let strtab_offset = append_aligned(&mut elf, &strtab, 1);
  let shstrtab_offset = append_aligned(&mut elf, &shstrtab, 1);
  let rodata_offset = append_aligned(&mut elf, rodata, 8);
  let shoff = align(&mut elf, 8);

  let mut headers = vec![0u8; 64]; // the null section header
  write_section_header(
    &mut headers,
    name_text,
    SHT_PROGBITS,
    SHF_ALLOC | SHF_EXECINSTR,
    text_offset,
    text.len(),
    0,
    0,
    8,
    0,
  );
  write_section_header(
    &mut headers,
    name_rel,
    SHT_REL,
    0,
    rel_offset,
    rels.len(),
    SEC_SYMTAB,
    SEC_TEXT,
    8,
    16,
  );
  write_section_header(
    &mut headers,
    name_symtab,
    SHT_SYMTAB,
    0,
    symtab_offset,
    symtab.len(),
    SEC_STRTAB,
    1,
    8,
    24,
  );
  write_section_header(
    &mut headers,
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
  write_section_header(
    &mut headers,
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
  write_section_header(
    &mut headers,
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
  elf.extend_from_slice(&headers);

  debug_assert_eq!(headers.len() / 64, SEC_COUNT as usize);
  write_elf_header(&mut elf[..64], shoff, SEC_COUNT, SEC_SHSTRTAB);
  elf
}

fn append_aligned(out: &mut Vec<u8>, data: &[u8], alignment: usize) -> u64 {
  let offset = align(out, alignment);
  out.extend_from_slice(data);
  offset
}

fn align(out: &mut Vec<u8>, alignment: usize) -> u64 {
  let padding = (alignment - (out.len() % alignment)) % alignment;
  out.resize(out.len() + padding, 0);
  out.len() as u64
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_section_header(
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
  out.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
  out.extend_from_slice(&offset.to_le_bytes());
  out.extend_from_slice(&(size as u64).to_le_bytes());
  out.extend_from_slice(&link.to_le_bytes());
  out.extend_from_slice(&info.to_le_bytes());
  out.extend_from_slice(&addralign.to_le_bytes());
  out.extend_from_slice(&entsize.to_le_bytes());
}

pub(crate) fn write_elf_header(header: &mut [u8], shoff: u64, shnum: u16, shstrndx: u16) {
  const ET_REL: u16 = 1;
  const EM_BPF: u16 = 247;

  header[0..4].copy_from_slice(b"\x7fELF");
  header[4] = 2; // ELFCLASS64
  header[5] = 1; // ELFDATA2LSB
  header[6] = 1; // EV_CURRENT
  header[16..18].copy_from_slice(&ET_REL.to_le_bytes());
  header[18..20].copy_from_slice(&EM_BPF.to_le_bytes());
  header[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
  header[40..48].copy_from_slice(&shoff.to_le_bytes());
  header[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
  header[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
  header[60..62].copy_from_slice(&shnum.to_le_bytes());
  header[62..64].copy_from_slice(&shstrndx.to_le_bytes());
}

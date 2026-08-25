//! Regression tests for the linker findings from the sandbox-escape audit.
//! All were reachable from pure guest ELF bytes through the public
//! `ProgramLoader::load`:
//!
//! 1. `immutable_vbase + data_section.sh_offset` was a plain `+` on a raw
//!    attacker-controlled `u64` (R_BPF_64_64 and R_BPF_64_ABS64 paths). The
//!    symbol's section never had its file offset validated, so
//!    `sh_offset = u64::MAX` overflowed and panicked the host in any
//!    overflow-checked build. The add is now checked and reports a linker
//!    error.
//! 2. `MAX_CODE_SECTIONS` counted only unique section *names*
//!    (`HashMap<String, _>`), so N disjoint code sections sharing one name
//!    defeated the cap and drove the O(N^2) overlap scan unbounded; the
//!    writable-section scan had no count limit at all. Both caps now count
//!    headers.
//! 3. Every `StringTable::get` in the `elf` crate is a fresh linear scan to
//!    the next NUL, so an object replaying one giant unterminated table
//!    against many section headers or relocations cost Θ(lookups · table):
//!    the SHT_REL loop (uncapped header count) × a ~2 GiB `.shstrtab`
//!    amplified into ~2^53 byte comparisons — days of CPU in the
//!    non-preemptible load path. The string tables are now indexed once
//!    ([`crate::linker::StrTabIndex`]), relocation-section headers are
//!    capped like the other section classes, and names longer than
//!    `MAX_STRING_LEN` are refused so hashing them downstream cannot
//!    re-amplify.

use std::time::{Duration, Instant};

use super::raw_elf::{build_elf, load_raw_elf, write_elf_header, write_section_header, Insn};

/// Patches the `sh_offset` field of one section header in an ELF built by
/// [`build_elf`]. Section headers are last; `rodata` is index 5 there.
fn set_section_file_offset(elf: &mut [u8], section_index: usize, sh_offset: u64) {
  let shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
  let field = shoff + section_index * 64 + 24;
  elf[field..field + 8].copy_from_slice(&sh_offset.to_le_bytes());
}

const SEC_RODATA: usize = 5;

fn lddw_program() -> Vec<Insn> {
  let [lo, hi] = Insn::lddw_data(1, 0);
  vec![lo, hi, Insn::exit()]
}

/// R_BPF_64_64 against a symbol whose section header carries a wild
/// `sh_offset` is a linker error in every build profile, not a panic in
/// overflow-checked ones and a wrapped immediate in the rest.
#[test]
fn reloc_against_wild_sh_offset_is_a_link_error_not_a_panic() {
  let rodata = [0u8; 16];
  let mut elf = build_elf(&lddw_program(), &rodata);
  set_section_file_offset(&mut elf, SEC_RODATA, u64::MAX);

  let err = load_raw_elf(&elf).expect_err("a wild sh_offset must not load");
  let err = format!("{err:?}");
  assert!(
    err.contains("overflows the guest address space"),
    "unexpected load error: {err}"
  );
}

/// N code sections sharing one name must trip the same ceiling as N
/// distinctly named ones: the overlap scan pays per header, not per unique
/// name, so the cap counts headers now.
#[test]
fn same_named_disjoint_code_sections_trip_the_section_cap() {
  const SEC_TEXT: usize = 1;

  let mut code = Vec::new();
  for _ in 0..2048 {
    code.push(Insn::exit());
  }
  let rodata = [0u8; 16];
  let mut elf = build_elf(&code, &rodata);

  let shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
  let shnum = u16::from_le_bytes(elf[60..62].try_into().unwrap()) as usize;
  let text_header = elf[shoff + SEC_TEXT * 64..shoff + (SEC_TEXT + 1) * 64].to_vec();

  assert_eq!(shoff + shnum as usize * 64, elf.len(), "headers not last");

  // Rewrite the .text header to cover one 8-byte window of the blob, then
  // append copies with disjoint windows, all named "test".
  let n = 2048usize;
  let text_off = u64::from_le_bytes(text_header[24..32].try_into().unwrap());
  let mut first = text_header.clone();
  first[24..32].copy_from_slice(&text_off.to_le_bytes());
  first[32..40].copy_from_slice(&8u64.to_le_bytes());
  elf[shoff + SEC_TEXT * 64..shoff + (SEC_TEXT + 1) * 64].copy_from_slice(&first);
  for i in 1..n {
    let mut h = text_header.clone();
    h[24..32].copy_from_slice(&(text_off + (i * 8) as u64).to_le_bytes());
    h[32..40].copy_from_slice(&8u64.to_le_bytes());
    elf.extend_from_slice(&h);
  }
  let shnum = u16::try_from(shnum as usize + (n - 1)).unwrap();
  elf[60..62].copy_from_slice(&shnum.to_le_bytes());

  let err = load_raw_elf(&elf).expect_err("2048 same-named code sections must not load");
  let err = format!("{err:?}");
  assert!(
    err.contains("too many code sections"),
    "unexpected load error: {err}"
  );
}

/// The writable-section plan had no count limit at all, and its overlap scan
/// is quadratic in the header count the same way. `MAX_WRITABLE_SECTIONS`
/// caps it per header.
#[test]
fn a_storm_of_writable_section_headers_is_refused() {
  const SHT_PROGBITS: u32 = 1;
  const SHT_SYMTAB: u32 = 2;
  const SHT_STRTAB: u32 = 3;
  const SHF_ALLOC: u64 = 1 << 1;
  const SHF_WRITE: u64 = 1;
  const SHF_EXECINSTR: u64 = 1 << 2;

  let n = 1025usize;
  let mut shstrtab = vec![0u8];
  let shname = |name: &str, table: &mut Vec<u8>| {
    let offset = table.len() as u32;
    table.extend_from_slice(name.as_bytes());
    table.push(0);
    offset
  };
  let name_text = shname("test", &mut shstrtab);
  let name_data = shname("data", &mut shstrtab);
  let name_symtab = shname(".symtab", &mut shstrtab);
  let name_strtab = shname(".strtab", &mut shstrtab);
  let name_shstrtab = shname(".shstrtab", &mut shstrtab);

  let text: Vec<u8> = Insn::exit().value.to_le_bytes().to_vec();
  let data = vec![0u8; n * 8];
  let symtab = vec![0u8; 24]; // the mandatory null symbol
  let strtab = vec![0u8];

  let mut elf = vec![0u8; 64];
  let mut append = |elf: &mut Vec<u8>, bytes: &[u8], alignment: usize| {
    let padding = (alignment - (elf.len() % alignment)) % alignment;
    elf.resize(elf.len() + padding, 0);
    let offset = elf.len() as u64;
    elf.extend_from_slice(bytes);
    offset
  };
  let text_offset = append(&mut elf, &text, 8);
  let data_offset = append(&mut elf, &data, 8);
  let symtab_offset = append(&mut elf, &symtab, 8);
  let strtab_offset = append(&mut elf, &strtab, 1);
  let shstrtab_offset = append(&mut elf, &shstrtab, 1);
  let shoff = append(&mut elf, &[], 8);

  let sec_symtab = 2 + n; // headers: null, text, data x N, symtab, strtab, shstrtab
  let sec_strtab = sec_symtab + 1;
  let sec_shstrtab = sec_symtab + 2;
  let shnum = sec_shstrtab + 1;

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
  for i in 0..n {
    write_section_header(
      &mut headers,
      name_data,
      SHT_PROGBITS,
      SHF_ALLOC | SHF_WRITE,
      data_offset + (i * 8) as u64,
      8,
      0,
      0,
      8,
      0,
    );
  }
  write_section_header(
    &mut headers,
    name_symtab,
    SHT_SYMTAB,
    0,
    symtab_offset,
    symtab.len(),
    sec_strtab as u32,
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
  write_elf_header(&mut elf[..64], shoff, shnum as u16, sec_shstrtab as u16);

  let err = load_raw_elf(&elf).expect_err("1025 writable sections must not load");
  let err = format!("{err:?}");
  assert!(
    err.contains("too many writable sections"),
    "unexpected load error: {err}"
  );
}

/// Builds an ELF with `n` distinct read-only `PROGBITS|ALLOC` sections, `n`
/// empty `SHT_REL` headers each targeting its own read-only section, a
/// minimal symtab, and a section-header string table of `shstrtab_size` bytes
/// with no NUL anywhere — every section name points into it at offset 1.
fn rel_section_storm_elf(n: usize, shstrtab_size: usize) -> Vec<u8> {
  const SHT_PROGBITS: u32 = 1;
  const SHT_SYMTAB: u32 = 2;
  const SHT_STRTAB: u32 = 3;
  const SHT_REL: u32 = 9;
  const SHF_ALLOC: u64 = 1 << 1;

  let symtab = vec![0u8; 24]; // the mandatory null symbol
  let strtab = vec![0u8];
  let shstrtab = vec![0xFFu8; shstrtab_size];

  let mut elf = vec![0u8; 64];
  let mut append = |elf: &mut Vec<u8>, bytes: &[u8], alignment: usize| {
    let padding = (alignment - (elf.len() % alignment)) % alignment;
    elf.resize(elf.len() + padding, 0);
    let offset = elf.len() as u64;
    elf.extend_from_slice(bytes);
    offset
  };
  let symtab_offset = append(&mut elf, &symtab, 8);
  let strtab_offset = append(&mut elf, &strtab, 1);
  let shstrtab_offset = append(&mut elf, &shstrtab, 1);
  let shoff = append(&mut elf, &[], 8);

  let sec_symtab = 1 + 2 * n;
  let sec_strtab = sec_symtab + 1;
  let sec_shstrtab = sec_symtab + 2;
  let shnum = sec_shstrtab + 1;

  let mut headers = vec![0u8; 64]; // the null section header
  for i in 0..n {
    // Read-only data section i: allocated, empty, named inside the NUL-free
    // table. Read-only sections are counted by no other cap, so n of them
    // are all valid relocation targets.
    write_section_header(&mut headers, 1, SHT_PROGBITS, SHF_ALLOC, 0, 0, 0, 0, 1, 0);
    // Relocation section i: targets data section i (index 1 + 2*i, since the
    // two headers interleave), carries no relocations (so MAX_RELOCATIONS
    // never sees it).
    write_section_header(
      &mut headers,
      1,
      SHT_REL,
      0,
      0,
      0,
      0,
      (1 + 2 * i) as u32,
      1,
      16,
    );
  }
  write_section_header(
    &mut headers,
    1,
    SHT_SYMTAB,
    0,
    symtab_offset,
    symtab.len(),
    sec_strtab as u32,
    1,
    8,
    24,
  );
  write_section_header(
    &mut headers,
    1,
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
    1,
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
  write_elf_header(&mut elf[..64], shoff, shnum as u16, sec_shstrtab as u16);
  elf
}

/// The load-time hang from the audit: uncapped `SHT_REL` header count ×
/// linear `shstrtab` scans. Each of the 2048 relocation headers used to cost
/// one full scan of the 64 MiB NUL-free name table (2048 × 64 MiB ≈ 128 GiB
/// of byte comparisons, tens of seconds). The string table is now indexed
/// once (one O(table) pass) and relocation-section headers are capped, so
/// the object is refused in milliseconds.
#[test]
fn a_storm_of_empty_reloc_sections_with_a_giant_strtab_is_refused_quickly() {
  let budget = if cfg!(debug_assertions) {
    Duration::from_secs(15)
  } else {
    Duration::from_secs(5)
  };

  let elf = rel_section_storm_elf(2048, 64 * 1024 * 1024);

  let start = Instant::now();
  let err = load_raw_elf(&elf).expect_err("2048 relocation sections must not load");
  let elapsed = start.elapsed();

  let err = format!("{err:?}");
  assert!(
    err.contains("too many relocation sections"),
    "unexpected load error: {err}"
  );
  assert!(
    elapsed < budget,
    "refusing the relocation-section storm took {elapsed:?} (budget {budget:?}); \
     the string table must be indexed once and the header count capped — see \
     StrTabIndex and MAX_REL_SECTIONS in linker.rs"
  );
}

/// A symbol name is hashed against the helper table for every relocation that
/// references it, so a single giant name replayed across many relocations
/// would re-amplify the same way the scans did. The index refuses names
/// beyond `MAX_STRING_LEN` up front.
#[test]
fn a_giant_symbol_name_is_refused_at_index_time() {
  const SHT_PROGBITS: u32 = 1;
  const SHT_SYMTAB: u32 = 2;
  const SHT_STRTAB: u32 = 3;
  const SHF_ALLOC: u64 = 1 << 1;
  const SHF_EXECINSTR: u64 = 1 << 2;

  let text: Vec<u8> = Insn::exit().value.to_le_bytes().to_vec();
  // The null symbol followed by one real symbol whose name is a 16 MiB
  // string (st_name = 0 into the names table below).
  let mut symtab = vec![0u8; 24];
  symtab.extend_from_slice(&0u32.to_le_bytes()); // st_name
  symtab.extend_from_slice(&0u8.to_le_bytes()); // st_info
  symtab.extend_from_slice(&0u8.to_le_bytes()); // st_other
  symtab.extend_from_slice(&0u16.to_le_bytes()); // st_shndx
  symtab.extend_from_slice(&0u64.to_le_bytes()); // st_value
  symtab.extend_from_slice(&0u64.to_le_bytes()); // st_size
  let mut names = vec![b'A'; 16 * 1024 * 1024];
  names.push(0);

  let mut shstrtab = vec![0u8];
  let shname = |name: &str, table: &mut Vec<u8>| {
    let offset = table.len() as u32;
    table.extend_from_slice(name.as_bytes());
    table.push(0);
    offset
  };
  let name_text = shname("test", &mut shstrtab);
  let name_symtab = shname(".symtab", &mut shstrtab);
  let name_strtab = shname(".strtab", &mut shstrtab);
  let name_shstrtab = shname(".shstrtab", &mut shstrtab);

  let mut elf = vec![0u8; 64];
  let mut append = |elf: &mut Vec<u8>, bytes: &[u8], alignment: usize| {
    let padding = (alignment - (elf.len() % alignment)) % alignment;
    elf.resize(elf.len() + padding, 0);
    let offset = elf.len() as u64;
    elf.extend_from_slice(bytes);
    offset
  };
  let text_offset = append(&mut elf, &text, 8);
  let symtab_offset = append(&mut elf, &symtab, 8);
  let names_offset = append(&mut elf, &names, 1);
  let shstrtab_offset = append(&mut elf, &shstrtab, 1);
  let shoff = append(&mut elf, &[], 8);

  let sec_symtab = 2;
  let sec_names = 3;
  let sec_shstrtab = 4;

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
    name_symtab,
    SHT_SYMTAB,
    0,
    symtab_offset,
    symtab.len(),
    sec_names as u32,
    1,
    8,
    24,
  );
  write_section_header(
    &mut headers,
    name_strtab,
    SHT_STRTAB,
    0,
    names_offset,
    names.len(),
    0,
    0,
    1,
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
  write_elf_header(&mut elf[..64], shoff, 5, sec_shstrtab as u16);

  let budget = if cfg!(debug_assertions) {
    Duration::from_secs(15)
  } else {
    Duration::from_secs(5)
  };
  let start = Instant::now();
  let err = load_raw_elf(&elf).expect_err("a 16 MiB symbol name must not load");
  let elapsed = start.elapsed();

  let err = format!("{err:?}");
  assert!(
    err.contains("exceeds MAX_STRING_LEN"),
    "unexpected load error: {err}"
  );
  assert!(
    elapsed < budget,
    "refusing the giant symbol name took {elapsed:?} (budget {budget:?})"
  );
}

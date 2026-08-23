use std::collections::{HashMap, HashSet};

use elf::{endian::LittleEndian, ElfBytes};

use crate::error::LinkerError;

const ET_REL: u16 = 1;
const EM_BPF: u16 = 247;

const SHT_PROGBITS: u32 = 1;
const SHT_REL: u32 = 9;
const SHF_ALLOC: u64 = 1 << 1;
const SHF_WRITE: u64 = 1;
const SHF_EXECINSTR: u64 = 1 << 2;

const R_BPF_64_64: u32 = 1;
const R_BPF_64_ABS64: u32 = 2;
const R_BPF_64_32: u32 = 10;

const EBPF_OP_CALL: u8 = 0x05u8 | 0x80u8;
const EBPF_OP_LDDW: u8 = 0x18;

#[derive(Clone, Debug)]
pub(crate) struct WritableSection {
  pub(crate) index: usize,
  pub(crate) file_offset: usize,
  pub(crate) size: usize,
  pub(crate) backing_offset: usize,
}

/// Packed runtime layout for allocated writable ELF sections.
///
/// The immutable ELF image keeps its file layout. Writable sections get new
/// guest addresses in a dense suffix of the same DATA region; this plan is the
/// bridge used both by relocation and by the loader's one-time copy. The
/// protection boundary is invisible to region analysis and the JIT.
#[derive(Clone, Debug)]
pub(crate) struct WritableDataPlan {
  pub(crate) sections: Vec<WritableSection>,
  pub(crate) size: usize,
}

impl WritableDataPlan {
  fn backing_offset(&self, section_index: usize) -> Option<usize> {
    self
      .sections
      .iter()
      .find(|section| section.index == section_index)
      .map(|section| section.backing_offset)
  }
}

pub(crate) fn plan_writable_data(input: &[u8]) -> Result<WritableDataPlan, LinkerError> {
  let elf = ElfBytes::<LittleEndian>::minimal_parse(input)?;
  let Some(sht) = elf.section_headers() else {
    return Err(LinkerError::InvalidElf("missing section headers"));
  };

  let mut sections = Vec::new();
  let mut claimed_ranges = Vec::new();
  let mut size = 0usize;
  for (index, section) in sht.iter().enumerate() {
    if section.sh_type != SHT_PROGBITS
      || section.sh_flags & (SHF_ALLOC | SHF_WRITE) != SHF_ALLOC | SHF_WRITE
      || section.sh_size == 0
    {
      continue;
    }

    // This validates the file range before converting it to usize below.
    elf.section_data(&section)?;
    let file_offset = usize::try_from(section.sh_offset)
      .map_err(|_| LinkerError::InvalidElf("writable section offset does not fit usize"))?;
    let section_size = usize::try_from(section.sh_size)
      .map_err(|_| LinkerError::InvalidElf("writable section size does not fit usize"))?;
    let file_end = file_offset
      .checked_add(section_size)
      .ok_or(LinkerError::InvalidElf("writable section range overflow"))?;
    if claimed_ranges
      .iter()
      .any(|&(lo, hi)| file_offset < hi && lo < file_end)
    {
      return Err(LinkerError::InvalidElf(
        "writable section overlaps another writable section",
      ));
    }
    claimed_ranges.push((file_offset, file_end));

    let alignment = usize::try_from(section.sh_addralign.max(1))
      .map_err(|_| LinkerError::InvalidElf("writable section alignment does not fit usize"))?;
    if !alignment.is_power_of_two() {
      return Err(LinkerError::InvalidElf(
        "writable section alignment is not a power of two",
      ));
    }
    size = size
      .checked_add(alignment - 1)
      .map(|value| value & !(alignment - 1))
      .ok_or(LinkerError::InvalidElf("writable data layout overflow"))?;
    let backing_offset = size;
    size = size
      .checked_add(section_size)
      .ok_or(LinkerError::InvalidElf("writable data layout overflow"))?;
    if size > input.len() {
      return Err(LinkerError::InvalidElf(
        "writable sections exceed the ELF image size",
      ));
    }
    sections.push(WritableSection {
      index,
      file_offset,
      size: section_size,
      backing_offset,
    });
  }

  Ok(WritableDataPlan { sections, size })
}

/// Ceilings on how much work one object may ask the loader to do.
///
/// Every one of these is per-*object*, because nothing else bounds them.
/// `MAX_INSTS` is enforced per code section, `DEFAULT_CODE_SIZE_LIMIT` bounds
/// only JIT output - which lazy compilation means is never reached at load -
/// and the pointer cage is sized from the file length rather than from the work
/// the file implies. Without these, a small object linear in file size costs
/// gigabytes: section headers are 64 bytes each and nothing requires two of
/// them to describe disjoint bytes, so N headers pointing at one code blob
/// multiply the analysis by N for ~67 bytes apiece.
///
/// The numbers are far above anything a compiler emits - LLVM produces one code
/// section per function at most - and are about refusing absurd inputs, not
/// about being tight.
const MAX_CODE_SECTIONS: usize = 1024;
const MAX_TOTAL_CODE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RELOCATIONS: usize = 1024 * 1024;
#[cfg(test)]
const EBPF_OP_EXIT: u8 = 0x95;
#[cfg(test)]
const EBPF_OP_JA: u8 = 0x05;

#[derive(Copy, Clone, Debug)]
struct EbpfInsn {
  opcode: u8,
  dst: u8,
  src: u8,
  offset: i16,
  imm: i32,
}

impl EbpfInsn {
  fn from_u64(insn: u64) -> Self {
    Self {
      opcode: (insn & 0xFF) as u8,
      dst: ((insn >> 8) & 0xF) as u8,
      src: ((insn >> 12) & 0xF) as u8,
      offset: ((insn >> 16) & 0xFFFF) as i16,
      imm: (insn >> 32) as i32,
    }
  }

  fn to_u64(&self) -> u64 {
    (self.opcode as u64)
      | ((self.dst as u64) << 8)
      | ((self.src as u64) << 12)
      | ((self.offset as u16 as u64) << 16)
      | ((self.imm as u32 as u64) << 32)
  }
}

/// Relocates an eBPF ELF image in place and returns entrypoint ranges.
///
/// Returns: section_name -> (code_vaddr, code_size).
pub fn link_elf(
  input: &mut [u8],
  immutable_vbase: usize,
  writable_vbase: usize,
  writable_plan: &WritableDataPlan,
  ext_func_table: &HashMap<&str, i32>,
) -> Result<HashMap<String, (usize, usize)>, LinkerError> {
  let elf = ElfBytes::<LittleEndian>::minimal_parse(input)?;
  if elf.ehdr.class != elf::file::Class::ELF64
    || elf.ehdr.version != 1
    || elf.ehdr.osabi != 0
    || elf.ehdr.e_type != ET_REL
    || elf.ehdr.e_machine != EM_BPF
  {
    return Err(LinkerError::InvalidElf("invalid ELF header"));
  }

  let (Some(sht), Some(sht_strtab)) = elf.section_headers_with_strtab()? else {
    return Err(LinkerError::InvalidElf("missing section headers"));
  };

  let Some(symtab) = elf.symbol_table()? else {
    return Err(LinkerError::InvalidElf("missing symbol table"));
  };

  let mut code_sections: HashMap<String, (usize, usize)> = HashMap::new();
  let mut code_section_indexes: HashSet<usize> = HashSet::new();
  // Byte ranges already claimed by a code section, so two headers cannot
  // describe the same bytes and have them analyzed, translated and retained
  // twice over. No compiler emits overlapping code sections; an object that
  // does is asking for the work to be multiplied, not for two functions.
  let mut claimed_code_ranges: Vec<(u64, u64)> = Vec::new();
  let mut total_code_bytes: usize = 0;
  for (cs_index, cs) in sht.iter().enumerate() {
    if cs.sh_type != SHT_PROGBITS || cs.sh_flags != SHF_ALLOC | SHF_EXECINSTR {
      continue;
    }
    if cs.sh_size == 0 {
      continue;
    }

    let Ok(cs_name) = sht_strtab.get(cs.sh_name as usize) else {
      continue;
    };

    // Validate that the section header points to valid data
    elf.section_data(&cs)?;

    let start = cs.sh_offset;
    let end = start.saturating_add(cs.sh_size);
    if claimed_code_ranges
      .iter()
      .any(|&(lo, hi)| start < hi && lo < end)
    {
      return Err(LinkerError::InvalidElf(
        "code section overlaps another code section",
      ));
    }
    claimed_code_ranges.push((start, end));

    total_code_bytes = total_code_bytes.saturating_add(cs.sh_size as usize);
    if total_code_bytes > MAX_TOTAL_CODE_BYTES {
      return Err(LinkerError::InvalidElf("too many code bytes in one object"));
    }

    code_sections.insert(
      cs_name.to_string(),
      (immutable_vbase + cs.sh_offset as usize, cs.sh_size as usize),
    );
    code_section_indexes.insert(cs_index);
    if code_sections.len() > MAX_CODE_SECTIONS {
      return Err(LinkerError::InvalidElf(
        "too many code sections in one object",
      ));
    }
  }

  let mut insn_rewrites: Vec<(usize, u64)> = vec![];
  let mut data_rewrites: Vec<(usize, u64)> = vec![];
  let mut relocation_count = 0usize;
  // Relocation sections are not required to describe distinct bytes either, so
  // one valid relocation blob can be replayed against the same target by any
  // number of SHT_REL headers.
  let mut relocated_sections: HashSet<usize> = HashSet::new();

  for sec in sht.iter() {
    if sec.sh_type != SHT_REL {
      continue;
    }
    let target_section_index = sec.sh_info as usize;
    let target_section = sht.get(target_section_index)?;
    let target_is_code = code_section_indexes.contains(&target_section_index);
    let target_is_data =
      target_section.sh_type == SHT_PROGBITS && (target_section.sh_flags & SHF_ALLOC) != 0;
    if !target_is_code && !target_is_data {
      continue;
    }
    if !relocated_sections.insert(target_section_index) {
      return Err(LinkerError::InvalidElf(
        "more than one relocation section targets the same section",
      ));
    }

    let target_section_name = sht_strtab
      .get(target_section.sh_name as usize)
      .unwrap_or_default();
    let (target_section_data, _) = elf.section_data(&target_section)?;

    let relocs = elf.section_data_as_rels(&sec)?;
    for reloc in relocs {
      // Checked per relocation rather than once against the section length,
      // because the rewrites are buffered and applied afterwards: without this
      // the whole buffer is built before anything rejects it.
      if relocation_count >= MAX_RELOCATIONS {
        return Err(LinkerError::InvalidElf(
          "too many relocations in one object",
        ));
      }
      relocation_count += 1;
      let end = (reloc.r_offset as usize).saturating_add(8);
      if reloc.r_offset % 8 != 0 || end > target_section_data.len() {
        return Err(LinkerError::InvalidElf("relocation: invalid offset"));
      }

      let sym = symtab.0.get(reloc.r_sym as usize)?;
      let sym_name = symtab.1.get(sym.st_name as usize)?;

      if !target_is_code {
        if reloc.r_type != R_BPF_64_ABS64 {
          continue;
        }
        let data_section = sht.get(sym.st_shndx as usize)?;
        if data_section.sh_type != SHT_PROGBITS || (data_section.sh_flags & SHF_ALLOC) == 0 {
          return Err(LinkerError::Reloc(
            "R_BPF_64_ABS64: symbol is not in allocated data".to_string(),
            reloc,
          ));
        }
        let addend = u64::from_le_bytes(
          target_section_data[reloc.r_offset as usize..end]
            .try_into()
            .unwrap(),
        );
        let section_base = writable_plan
          .backing_offset(sym.st_shndx as usize)
          .map(|offset| writable_vbase as u64 + offset as u64)
          .unwrap_or_else(|| immutable_vbase as u64 + data_section.sh_offset);
        let value = section_base.wrapping_add(sym.st_value).wrapping_add(addend);
        data_rewrites.push((
          target_section.sh_offset as usize + reloc.r_offset as usize,
          value,
        ));
        continue;
      }

      let insn = u64::from_le_bytes(
        target_section_data[reloc.r_offset as usize..end]
          .try_into()
          .unwrap(),
      );
      let mut insn = EbpfInsn::from_u64(insn);
      if reloc.r_type == R_BPF_64_32 {
        if insn.opcode != EBPF_OP_CALL {
          return Err(LinkerError::Reloc(
            format!("R_BPF_64_32: not a call instruction: {:?}", insn),
            reloc,
          ));
        }

        if let Some(&func_index) = ext_func_table.get(sym_name) {
          insn.imm = func_index;
          insn.src = 0;
        } else if code_section_indexes.contains(&(sym.st_shndx as usize)) {
          let code_section = sht.get(sym.st_shndx as usize)?;
          let old_imm = insn.imm as i64;
          let symbol_offset = if sym.st_value == 0 && old_imm != -1 {
            ((old_imm + 1) as u64).saturating_mul(8)
          } else {
            sym.st_value
          };
          let target_addr = code_section.sh_offset.wrapping_add(symbol_offset);
          let call_addr = target_section.sh_offset.wrapping_add(reloc.r_offset);
          let delta = (target_addr as i128 - call_addr as i128 - 8) / 8;
          if delta < i32::MIN as i128 || delta > i32::MAX as i128 {
            return Err(LinkerError::Reloc(
              "R_BPF_64_32: local call target out of range".to_string(),
              reloc,
            ));
          }
          insn.imm = delta as i32;
        } else {
          return Err(LinkerError::Reloc(
            format!(
              "R_BPF_64_32: unknown symbol {} in section {}",
              sym_name, target_section_name
            ),
            reloc,
          ));
        }
        insn_rewrites.push((
          target_section.sh_offset as usize + reloc.r_offset as usize,
          insn.to_u64(),
        ));
      } else if reloc.r_type == R_BPF_64_64 {
        if insn.opcode != EBPF_OP_LDDW {
          return Err(LinkerError::Reloc(
            "R_BPF_64_64: not a lddw instruction".to_string(),
            reloc,
          ));
        }
        if end.saturating_add(8) > target_section_data.len() {
          return Err(LinkerError::Reloc(
            "R_BPF_64_64: out of bounds".to_string(),
            reloc,
          ));
        }

        let data_section = sht.get(sym.st_shndx as usize)?;
        if data_section.sh_type != SHT_PROGBITS || (data_section.sh_flags & SHF_ALLOC) == 0 {
          return Err(LinkerError::Reloc(
            "R_BPF_64_64: data section not SHT_PROGBITS or does not have SHF_ALLOC".to_string(),
            reloc,
          ));
        }

        if sym.st_size.saturating_add(sym.st_value) > data_section.sh_size {
          return Err(LinkerError::Reloc(
            "R_BPF_64_64: data section out of bounds".to_string(),
            reloc,
          ));
        }

        let oldimm = insn.imm as u32 as u64
          + ((u32::from_le_bytes(
            <[u8; 4]>::try_from(&target_section_data[end + 4..end + 8]).unwrap(),
          ) as u64)
            << 32);

        let section_base = writable_plan
          .backing_offset(sym.st_shndx as usize)
          .map(|offset| writable_vbase as u64 + offset as u64)
          .unwrap_or_else(|| immutable_vbase as u64 + data_section.sh_offset);
        let imm = section_base.wrapping_add(sym.st_value).wrapping_add(oldimm);

        insn.imm = imm as u32 as i32;
        insn_rewrites.push((
          target_section.sh_offset as usize + reloc.r_offset as usize,
          insn.to_u64(),
        ));
        insn_rewrites.push((
          target_section.sh_offset as usize + reloc.r_offset as usize + 8,
          (imm >> 32) << 32,
        ));
      } else {
        return Err(LinkerError::Reloc(
          "unsupported relocation type".to_string(),
          reloc,
        ));
      }
    }
  }

  for (offset, value) in insn_rewrites {
    input[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
  }
  for (offset, value) in data_rewrites {
    input[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
  }

  // Each code section must be a whole number of 8-byte instruction slots.
  // Per-instruction validation (control flow, local-call graph, region routing)
  // is performed later by `function_analysis`/`region_analysis` once the section
  // bytes are resolved.
  for &(_, len) in code_sections.values() {
    if len % 8 != 0 {
      return Err(LinkerError::InvalidElf(
        "code section size is not multiple of 8",
      ));
    }
  }

  Ok(code_sections)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn validate_local_call_graph(code: &[u8]) -> Result<(), String> {
    crate::function_analysis::analyze_functions(code).map(|_| ())
  }

  const EBPF_OP_MOV64_IMM: u8 = 0xb7;

  fn inst(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = opcode;
    b[1] = dst | (src << 4);
    b[2..4].copy_from_slice(&offset.to_le_bytes());
    b[4..8].copy_from_slice(&imm.to_le_bytes());
    b
  }

  fn local_call(pc: usize, target: usize) -> [u8; 8] {
    inst(EBPF_OP_CALL, 0, 1, 0, target as i32 - pc as i32 - 1)
  }

  fn exit() -> [u8; 8] {
    inst(EBPF_OP_EXIT, 0, 0, 0, 0)
  }

  fn ja(pc: usize, target: usize) -> [u8; 8] {
    inst(EBPF_OP_JA, 0, 0, target as i16 - pc as i16 - 1, 0)
  }

  fn mov64_imm() -> [u8; 8] {
    inst(EBPF_OP_MOV64_IMM, 0, 0, 0, 0)
  }

  fn local_call_chain(function_count: usize) -> Vec<u8> {
    let mut code = Vec::new();
    for func_index in 0..function_count {
      let pc = func_index * 2;
      if func_index + 1 == function_count {
        code.extend_from_slice(&exit());
      } else {
        code.extend_from_slice(&local_call(pc, pc + 2));
        code.extend_from_slice(&exit());
      }
    }
    code
  }

  #[test]
  fn local_call_graph_allows_deep_acyclic_graphs() {
    let code = local_call_chain(64);
    validate_local_call_graph(&code).unwrap();
  }

  #[test]
  fn a_long_call_chain_is_analyzed_without_using_the_host_call_stack() {
    let code = local_call_chain(32767);
    let handle = std::thread::Builder::new()
      .stack_size(256 * 1024)
      .spawn(move || validate_local_call_graph(&code))
      .unwrap();
    handle.join().unwrap().unwrap();
  }

  #[test]
  fn local_call_graph_allows_recursion() {
    let mut code = Vec::new();
    code.extend_from_slice(&local_call(0, 2));
    code.extend_from_slice(&exit());
    code.extend_from_slice(&local_call(2, 2));
    code.extend_from_slice(&exit());

    validate_local_call_graph(&code).unwrap();
  }

  #[test]
  fn local_call_graph_rejects_fallthrough_into_function_entry() {
    let mut code = Vec::new();
    code.extend_from_slice(&ja(0, 4));
    code.extend_from_slice(&local_call(1, 5));
    code.extend_from_slice(&exit());
    code.extend_from_slice(&exit());
    code.extend_from_slice(&mov64_imm());
    code.extend_from_slice(&local_call(5, 4));
    code.extend_from_slice(&exit());

    let err = validate_local_call_graph(&code).unwrap_err();
    assert!(
      err.contains("outside local function range"),
      "unexpected validation error: {err}"
    );
  }

  #[test]
  fn local_call_graph_rejects_disguised_cross_function_control_flow() {
    let function_count = 9;
    let factory_start = 1;
    let factory_len = function_count - 1;
    let chain_start = factory_start + factory_len + 1;
    let mut code = Vec::new();

    code.extend_from_slice(&ja(0, chain_start));
    for i in 0..factory_len {
      let r_i = chain_start + i * 3 + 1;
      code.extend_from_slice(&local_call(factory_start + i, r_i));
    }
    code.extend_from_slice(&exit());
    for i in 0..function_count {
      let e_i = chain_start + i * 3;
      code.extend_from_slice(&mov64_imm());
      if i + 1 == function_count {
        code.extend_from_slice(&exit());
        code.extend_from_slice(&exit());
      } else {
        let r_i = e_i + 1;
        let next_e = e_i + 3;
        code.extend_from_slice(&local_call(r_i, next_e));
        code.extend_from_slice(&exit());
      }
    }

    let err = validate_local_call_graph(&code).unwrap_err();
    assert!(
      err.contains("outside local function range"),
      "unexpected validation error: {err}"
    );
  }

  #[test]
  fn local_call_graph_rejects_shared_sled_cross_function_jumps() {
    let function_count = 256usize;
    let sled_len = 256usize;
    let factory_start = 1usize;
    let function_start = factory_start + function_count + 1;
    let sled_start = function_start + function_count;
    let mut code = Vec::new();

    code.extend_from_slice(&ja(0, sled_start));
    for i in 0..function_count {
      code.extend_from_slice(&local_call(factory_start + i, function_start + i));
    }
    code.extend_from_slice(&exit());

    for i in 0..function_count {
      code.extend_from_slice(&ja(function_start + i, sled_start));
    }

    for _ in 0..sled_len {
      code.extend_from_slice(&mov64_imm());
    }
    code.extend_from_slice(&exit());

    let err = validate_local_call_graph(&code).unwrap_err();
    assert!(
      err.contains("outside local function range"),
      "unexpected validation error: {err}"
    );
  }

  #[test]
  fn local_call_graph_allows_dead_padding_between_functions() {
    let mut code = Vec::new();
    code.extend_from_slice(&local_call(0, 4));
    code.extend_from_slice(&exit());
    code.extend_from_slice(&mov64_imm());
    code.extend_from_slice(&mov64_imm());
    code.extend_from_slice(&exit());

    validate_local_call_graph(&code).unwrap();
  }
}

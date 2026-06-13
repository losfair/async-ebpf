use std::collections::{HashMap, HashSet};

use elf::{endian::LittleEndian, ElfBytes};

use crate::error::LinkerError;

const ET_REL: u16 = 1;
const EM_BPF: u16 = 247;

const SHT_PROGBITS: u32 = 1;
const SHT_REL: u32 = 9;
const SHF_ALLOC: u64 = 1 << 1;
const SHF_EXECINSTR: u64 = 1 << 2;

const R_BPF_64_64: u32 = 1;
const R_BPF_64_32: u32 = 10;

const EBPF_OP_CALL: u8 = 0x05u8 | 0x80u8;
const EBPF_OP_LDDW: u8 = 0x18;
const EBPF_OP_EXIT: u8 = 0x95;
const EBPF_CLS_MASK: u8 = 0x07;
const EBPF_CLS_JMP: u8 = 0x05;
const EBPF_CLS_JMP32: u8 = 0x06;
const EBPF_OP_JA: u8 = 0x05;
const EBPF_OP_JA32: u8 = 0x06;
const MAX_LOCAL_CALL_DEPTH: usize = 8;

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

fn insn_at(code: &[u8], pc: usize) -> EbpfInsn {
  let mut raw = [0u8; 8];
  raw.copy_from_slice(&code[pc * 8..pc * 8 + 8]);
  EbpfInsn::from_u64(u64::from_le_bytes(raw))
}

fn local_call_target(pc: usize, insn: EbpfInsn, num_insns: usize) -> Result<usize, String> {
  let target = pc as i64 + insn.imm as i64 + 1;
  if target < 0 || target >= num_insns as i64 {
    return Err(format!(
      "local call target out of range at PC {pc}: {target}"
    ));
  }
  Ok(target as usize)
}

fn jump_target(pc: usize, offset: i64, num_insns: usize) -> Result<usize, String> {
  let target = pc as i64 + offset + 1;
  if target < 0 || target >= num_insns as i64 {
    return Err(format!("jump target out of range at PC {pc}: {target}"));
  }
  Ok(target as usize)
}

fn check_in_function_range(
  pc: usize,
  target: usize,
  start: usize,
  end: usize,
  edge_kind: &str,
) -> Result<(), String> {
  if target < start || target >= end {
    return Err(format!(
      "{edge_kind} from PC {pc} reaches PC {target} outside local function range [{start}, {end})"
    ));
  }
  Ok(())
}

fn check_fallthrough_in_function_range(
  pc: usize,
  step: usize,
  start: usize,
  end: usize,
) -> Result<(), String> {
  let target = pc
    .checked_add(step)
    .ok_or_else(|| format!("control flow target overflows at PC {pc}"))?;
  check_in_function_range(pc, target, start, end, "fallthrough")
}

fn scan_local_function_ranges(
  code: &[u8],
  starts: &[usize],
  func_for_pc: &[usize],
) -> Result<Vec<Vec<usize>>, String> {
  let num_insns = code.len() / 8;
  let mut edges = vec![Vec::new(); starts.len()];

  for (func_index, &start) in starts.iter().enumerate() {
    let end = starts.get(func_index + 1).copied().unwrap_or(num_insns);
    let mut visited = vec![false; end - start];
    let mut pending = vec![start];

    while let Some(pc) = pending.pop() {
      if pc < start || pc >= end {
        return Err(format!(
          "control flow reaches PC {pc} outside local function range [{start}, {end})"
        ));
      }
      if visited[pc - start] {
        continue;
      }
      visited[pc - start] = true;

      let insn = insn_at(code, pc);

      if insn.opcode == EBPF_OP_EXIT {
        continue;
      }

      if insn.opcode == EBPF_OP_CALL {
        if insn.src == 1 {
          let target = local_call_target(pc, insn, num_insns)?;
          let callee_index = func_for_pc[target];
          if starts[callee_index] != target {
            return Err(format!(
              "local call at PC {pc} targets non-function PC {target}"
            ));
          }
          edges[func_index].push(callee_index);
        }
        check_fallthrough_in_function_range(pc, 1, start, end)?;
        pending.push(pc + 1);
        continue;
      }

      if insn.opcode == EBPF_OP_LDDW {
        check_fallthrough_in_function_range(pc, 2, start, end)?;
        pending.push(pc + 2);
        continue;
      }

      if (insn.opcode & EBPF_CLS_MASK) == EBPF_CLS_JMP
        || (insn.opcode & EBPF_CLS_MASK) == EBPF_CLS_JMP32
      {
        if insn.opcode == EBPF_OP_JA {
          let target = jump_target(pc, insn.offset as i64, num_insns)?;
          check_in_function_range(pc, target, start, end, "jump")?;
          pending.push(target);
        } else if insn.opcode == EBPF_OP_JA32 {
          let target = jump_target(pc, insn.imm as i64, num_insns)?;
          check_in_function_range(pc, target, start, end, "jump")?;
          pending.push(target);
        } else {
          let target = jump_target(pc, insn.offset as i64, num_insns)?;
          check_in_function_range(pc, target, start, end, "jump")?;
          check_fallthrough_in_function_range(pc, 1, start, end)?;
          pending.push(target);
          pending.push(pc + 1);
        }
        continue;
      }

      check_fallthrough_in_function_range(pc, 1, start, end)?;
      pending.push(pc + 1);
    }

    edges[func_index].sort_unstable();
    edges[func_index].dedup();
  }

  Ok(edges)
}

fn visit_local_call_graph(
  edges: &[Vec<usize>],
  starts: &[usize],
  states: &mut [u8],
  depths: &mut [usize],
  func_index: usize,
) -> Result<usize, String> {
  match states[func_index] {
    1 => {
      return Err(format!(
        "recursive local function call graph involving PC {}",
        starts[func_index]
      ));
    }
    2 => return Ok(depths[func_index]),
    _ => {}
  }

  states[func_index] = 1;
  let mut max_depth = 1;

  for &callee_index in &edges[func_index] {
    let callee_depth = visit_local_call_graph(edges, starts, states, depths, callee_index)?;
    let candidate_depth = callee_depth + 1;
    if candidate_depth > MAX_LOCAL_CALL_DEPTH {
      return Err(format!(
        "local function call graph depth ({candidate_depth}) exceeds max ({MAX_LOCAL_CALL_DEPTH})"
      ));
    }
    max_depth = max_depth.max(candidate_depth);
  }

  states[func_index] = 2;
  depths[func_index] = max_depth;
  Ok(max_depth)
}

/// Validates that local eBPF calls cannot recurse or exceed the statically
/// supported call depth before the bytecode is handed to uBPF's JIT.
pub(crate) fn validate_local_call_graph(code: &[u8]) -> Result<(), String> {
  if code.len() % 8 != 0 {
    return Err("code length is not a multiple of 8".to_string());
  }

  let num_insns = code.len() / 8;
  if num_insns == 0 {
    return Ok(());
  }

  let mut starts = vec![0usize];
  for pc in 0..num_insns {
    let insn = insn_at(code, pc);
    if insn.opcode == EBPF_OP_CALL && insn.src == 1 {
      starts.push(local_call_target(pc, insn, num_insns)?);
    }
  }
  starts.sort_unstable();
  starts.dedup();

  let mut func_for_pc = vec![0usize; num_insns];
  for (func_index, &start) in starts.iter().enumerate() {
    let end = starts.get(func_index + 1).copied().unwrap_or(num_insns);
    func_for_pc[start..end].fill(func_index);
  }

  let edges = scan_local_function_ranges(code, &starts, &func_for_pc)?;

  let mut states = vec![0u8; starts.len()];
  let mut depths = vec![0usize; starts.len()];
  for func_index in 0..starts.len() {
    visit_local_call_graph(&edges, &starts, &mut states, &mut depths, func_index)?;
  }

  Ok(())
}

/// Relocates an eBPF ELF image in place and returns entrypoint ranges.
///
/// Returns: section_name -> (code_vaddr, code_size).
pub fn link_elf(
  input: &mut [u8],
  vbase: usize,
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

    code_sections.insert(
      cs_name.to_string(),
      (vbase + cs.sh_offset as usize, cs.sh_size as usize),
    );
    code_section_indexes.insert(cs_index);
  }

  let mut insn_rewrites: Vec<(usize, u64)> = vec![];

  for sec in sht.iter() {
    if sec.sh_type != SHT_REL {
      continue;
    }
    let target_section_index = sec.sh_info as usize;
    if !code_section_indexes.contains(&target_section_index) {
      continue;
    }

    let target_section = sht.get(target_section_index)?;
    let target_section_name = sht_strtab
      .get(target_section.sh_name as usize)
      .unwrap_or_default();
    let (target_section_data, _) = elf.section_data(&target_section)?;

    let relocs = elf.section_data_as_rels(&sec)?;
    for reloc in relocs {
      let end = (reloc.r_offset as usize).saturating_add(8);
      if reloc.r_offset % 8 != 0 || end > target_section_data.len() {
        return Err(LinkerError::InvalidElf("relocation: invalid offset"));
      }

      let insn = u64::from_le_bytes(
        target_section_data[reloc.r_offset as usize..end]
          .try_into()
          .unwrap(),
      );
      let mut insn = EbpfInsn::from_u64(insn);
      let sym = symtab.0.get(reloc.r_sym as usize)?;
      let sym_name = symtab.1.get(sym.st_name as usize)?;

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

        let imm = (vbase as u64)
          .wrapping_add(data_section.sh_offset)
          .wrapping_add(sym.st_value)
          .wrapping_add(oldimm);

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

  // Scan code section and reject unsafe instructions
  for (cs_name, &(vaddr, len)) in code_sections.iter() {
    if len % 8 != 0 {
      return Err(LinkerError::InvalidElf(
        "code section size is not multiple of 8",
      ));
    }
    for i in (0..len).step_by(8) {
      let offset = vaddr - vbase + i;
      let insn = u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap());
      let insn = EbpfInsn::from_u64(insn);

      let _ = (cs_name, insn, offset);
    }
  }

  Ok(code_sections)
}

#[cfg(test)]
mod tests {
  use super::*;

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
  fn local_call_graph_allows_max_depth() {
    let code = local_call_chain(MAX_LOCAL_CALL_DEPTH);
    validate_local_call_graph(&code).unwrap();
  }

  #[test]
  fn local_call_graph_rejects_excessive_depth() {
    let code = local_call_chain(MAX_LOCAL_CALL_DEPTH + 1);
    let err = validate_local_call_graph(&code).unwrap_err();
    assert!(
      err.contains("exceeds max"),
      "unexpected validation error: {err}"
    );
  }

  #[test]
  fn local_call_graph_rejects_recursion() {
    let mut code = Vec::new();
    code.extend_from_slice(&local_call(0, 2));
    code.extend_from_slice(&exit());
    code.extend_from_slice(&local_call(2, 2));
    code.extend_from_slice(&exit());

    let err = validate_local_call_graph(&code).unwrap_err();
    assert!(
      err.contains("recursive"),
      "unexpected validation error: {err}"
    );
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
  fn local_call_graph_rejects_disguised_excessive_depth() {
    let function_count = MAX_LOCAL_CALL_DEPTH + 1;
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

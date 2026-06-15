use std::collections::BTreeSet;

const EBPF_OP_CALL: u8 = 0x05u8 | 0x80u8;
const EBPF_OP_LDDW: u8 = 0x18;
const EBPF_OP_EXIT: u8 = 0x95;
const EBPF_CLS_MASK: u8 = 0x07;
const EBPF_CLS_JMP: u8 = 0x05;
const EBPF_CLS_JMP32: u8 = 0x06;
const EBPF_OP_JA: u8 = 0x05;
const EBPF_OP_JA32: u8 = 0x06;
const MAX_LOCAL_CALL_DEPTH: usize = 8;

#[derive(Clone, Debug)]
pub(crate) struct FunctionLayout {
  pub(crate) functions: Vec<FunctionInfo>,
  pub(crate) pc_to_func: Vec<usize>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct FunctionInfo {
  pub(crate) start_pc: usize,
  pub(crate) end_pc: usize,
  pub(crate) callees: Vec<usize>,
  pub(crate) callers: Vec<usize>,
}

#[derive(Copy, Clone, Debug)]
struct EbpfInsn {
  opcode: u8,
  offset: i16,
  imm: i32,
}

impl EbpfInsn {
  fn from_u64(insn: u64) -> Self {
    Self {
      opcode: (insn & 0xFF) as u8,
      offset: ((insn >> 16) & 0xFFFF) as i16,
      imm: (insn >> 32) as i32,
    }
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
        if insn_at(code, pc).opcode == EBPF_OP_CALL && insn_src(code, pc) == 1 {
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

fn insn_src(code: &[u8], pc: usize) -> u8 {
  code[pc * 8 + 1] >> 4
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

pub(crate) fn analyze_functions(code: &[u8]) -> Result<FunctionLayout, String> {
  if code.len() % 8 != 0 {
    return Err("code length is not a multiple of 8".to_string());
  }

  let num_insns = code.len() / 8;
  if num_insns == 0 {
    return Ok(FunctionLayout {
      functions: Vec::new(),
      pc_to_func: Vec::new(),
    });
  }

  let mut starts = BTreeSet::from([0usize]);
  for pc in 0..num_insns {
    let insn = insn_at(code, pc);
    if insn.opcode == EBPF_OP_CALL && insn_src(code, pc) == 1 {
      starts.insert(local_call_target(pc, insn, num_insns)?);
    }
  }
  let starts = starts.into_iter().collect::<Vec<_>>();

  let mut pc_to_func = vec![0usize; num_insns];
  for (func_index, &start) in starts.iter().enumerate() {
    let end = starts.get(func_index + 1).copied().unwrap_or(num_insns);
    pc_to_func[start..end].fill(func_index);
  }

  let edges = scan_local_function_ranges(code, &starts, &pc_to_func)?;

  let mut states = vec![0u8; starts.len()];
  let mut depths = vec![0usize; starts.len()];
  for func_index in 0..starts.len() {
    visit_local_call_graph(&edges, &starts, &mut states, &mut depths, func_index)?;
  }

  let mut callers = vec![Vec::new(); starts.len()];
  for (caller, callees) in edges.iter().enumerate() {
    for &callee in callees {
      callers[callee].push(caller);
    }
  }

  let functions = starts
    .iter()
    .enumerate()
    .map(|(i, &start_pc)| FunctionInfo {
      start_pc,
      end_pc: starts.get(i + 1).copied().unwrap_or(num_insns),
      callees: edges[i].clone(),
      callers: callers[i].clone(),
    })
    .collect();

  Ok(FunctionLayout {
    functions,
    pc_to_func,
  })
}

pub(crate) fn validate_local_call_graph(code: &[u8]) -> Result<(), String> {
  analyze_functions(code).map(|_| ())
}

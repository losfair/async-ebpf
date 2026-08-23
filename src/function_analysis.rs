use std::collections::{BTreeSet, VecDeque};

use crate::region_analysis::{function_live_in, RegMask};

const EBPF_OP_CALL: u8 = 0x05u8 | 0x80u8;
const EBPF_OP_LDDW: u8 = 0x18;
const EBPF_OP_EXIT: u8 = 0x95;
const EBPF_CLS_MASK: u8 = 0x07;
const EBPF_CLS_JMP: u8 = 0x05;
const EBPF_CLS_JMP32: u8 = 0x06;
const EBPF_OP_JA: u8 = 0x05;
const EBPF_OP_JA32: u8 = 0x06;
#[derive(Clone, Debug)]
pub(crate) struct FunctionLayout {
  pub(crate) functions: Vec<FunctionInfo>,
  pub(crate) pc_to_func: Vec<usize>,
  /// Per function, the registers whose incoming kind it can observe. Used to
  /// mask the pointer signature a call site hands its callee, so specialization
  /// keys off what the callee actually reads rather than the caller's whole
  /// register file. See [`function_live_in`].
  pub(crate) arg_masks: Vec<RegMask>,
}

impl FunctionLayout {
  /// A single-function layout that masks nothing, for callers that only have a
  /// code fragment and no call graph to derive masks from.
  #[cfg(any(test, feature = "testing"))]
  pub(crate) fn unmasked(num_insns: usize) -> Self {
    Self {
      functions: Vec::new(),
      pc_to_func: vec![0; num_insns],
      arg_masks: vec![crate::region_analysis::ALL_SIGNATURE_REGS],
    }
  }
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

/// Computes the least fixed point of the per-function live-in equations.
///
/// Starting at the empty masks is important: these masks control lazy JIT
/// specialization, so an all-register over-approximation can multiply native
/// variants at every call around a recursive component. `function_live_in` is
/// monotone in its callee summaries. Each successful update therefore only
/// adds bits, and a changed callee needs to wake only its direct callers. With
/// a finite `RegMask`, every function can change at most once per register bit.
fn live_in_fixed_point(
  code: &[u8],
  starts: &[usize],
  pc_to_func: &[usize],
  callers: &[Vec<usize>],
) -> Vec<RegMask> {
  let num_insns = code.len() / 8;
  let mut arg_masks = vec![0 as RegMask; starts.len()];
  let mut pending = (0..starts.len()).collect::<VecDeque<_>>();
  let mut queued = vec![true; starts.len()];

  while let Some(func_index) = pending.pop_front() {
    queued[func_index] = false;
    let start = starts[func_index];
    let end = starts.get(func_index + 1).copied().unwrap_or(num_insns);
    let computed = function_live_in(code, start, end, &|target| {
      pc_to_func
        .get(target)
        .and_then(|&callee| arg_masks.get(callee).copied())
        .unwrap_or(crate::region_analysis::ALL_SIGNATURE_REGS)
    });

    // The transfer function is monotone, so a recomputation after callee masks
    // grow cannot lose bits. Keep the union in release builds as a safe
    // backstop if that invariant is accidentally broken by a future change.
    debug_assert_eq!(arg_masks[func_index] & !computed, 0);
    let next = arg_masks[func_index] | computed;
    if next == arg_masks[func_index] {
      continue;
    }
    arg_masks[func_index] = next;
    for &caller in &callers[func_index] {
      if !queued[caller] {
        queued[caller] = true;
        pending.push_back(caller);
      }
    }
  }

  arg_masks
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
      arg_masks: Vec::new(),
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

  let mut callers = vec![Vec::new(); starts.len()];
  for (caller, callees) in edges.iter().enumerate() {
    for &callee in callees {
      callers[callee].push(caller);
    }
  }

  let arg_masks = live_in_fixed_point(code, &starts, &pc_to_func, &callers);

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
    arg_masks,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  fn insn(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[0] = opcode;
    bytes[1] = dst | (src << 4);
    bytes[2..4].copy_from_slice(&offset.to_le_bytes());
    bytes[4..8].copy_from_slice(&imm.to_le_bytes());
    bytes
  }

  fn local_call(pc: usize, target: usize) -> [u8; 8] {
    insn(EBPF_OP_CALL, 0, 1, 0, target as i32 - pc as i32 - 1)
  }

  fn exit() -> [u8; 8] {
    insn(EBPF_OP_EXIT, 0, 0, 0, 0)
  }

  #[test]
  fn an_unused_recursive_component_has_empty_live_in_masks() {
    let code = [local_call(0, 2), exit(), local_call(2, 0), exit()].concat();
    let layout = analyze_functions(&code).unwrap();

    assert_eq!(layout.arg_masks, vec![0, 0]);
  }

  #[test]
  fn live_in_bits_propagate_all_the_way_around_a_recursive_component() {
    // The queue initially visits A then B then C. Only C directly reads R8,
    // so reaching A requires two caller wakeups after C is first analyzed:
    // C -> B -> A. A one-pass treatment of the cycle misses both callers.
    let code = [
      local_call(0, 2),
      exit(),
      local_call(2, 4),
      exit(),
      local_call(4, 0),
      insn(0x71, 0, 8, 0, 0), // r0 = *(u8 *)r8
      exit(),
    ]
    .concat();
    let layout = analyze_functions(&code).unwrap();

    assert_eq!(layout.arg_masks, vec![1 << 8; 3]);
  }
}

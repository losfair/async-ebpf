use std::collections::{BTreeSet, HashMap};

use crate::region_analysis::{
  program_live_in, CrossSectionCallSite, LiveInSection, RegMask, ALL_SIGNATURE_REGS,
};

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
  /// register file. See [`program_live_in`].
  pub(crate) arg_masks: Vec<RegMask>,
  /// Per cross-section call site in this section, keyed by the call's pc, the
  /// argument mask of the callee that lives in another section.
  ///
  /// A section-local callee is found through `pc_to_func` and `arg_masks`; a
  /// cross-section one is in a different layout entirely, so its mask is
  /// projected back onto the call site here. Filled by [`analyze_program`],
  /// which is the only thing that sees every section at once; empty for a
  /// lone fragment, whose cross-section call sites then mask nothing.
  pub(crate) cross_section_arg_masks: HashMap<usize, RegMask>,
}

impl FunctionLayout {
  /// A single-function layout that masks nothing, for callers that only have a
  /// code fragment and no call graph to derive masks from.
  #[cfg(any(test, feature = "testing"))]
  pub(crate) fn unmasked(num_insns: usize) -> Self {
    Self {
      functions: Vec::new(),
      pc_to_func: vec![0; num_insns],
      arg_masks: vec![ALL_SIGNATURE_REGS],
      cross_section_arg_masks: HashMap::new(),
    }
  }
}

/// One code section handed to [`analyze_program`].
pub(crate) struct SectionInput<'a> {
  pub(crate) code: &'a [u8],
  /// Function roots supplied by the container: the targets of calls from other
  /// sections. They delimit functions just like section-local call targets do.
  pub(crate) entries: &'a [usize],
}

/// One local call whose callee is in another section.
///
/// Section indices are positions in the slice handed to [`analyze_program`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct CrossSectionEdge {
  pub(crate) caller_section: usize,
  pub(crate) call_pc: usize,
  pub(crate) callee_section: usize,
  pub(crate) callee_pc: usize,
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

/// Fills in every layout's argument masks from one whole-program solve.
///
/// Starting the masks at empty is important: they control lazy JIT
/// specialization, so an all-register over-approximation multiplies native
/// variants at every call around a recursive component. [`program_live_in`]
/// computes the least fixed point and explains why it solves all the sections
/// together rather than one function at a time.
///
/// Cross-section edges are part of that graph and not a special case. Cutting
/// them - summarising an external callee as "reads everything" - would be sound
/// but expensive twice over: the call site stops masking, *and* the caller's own
/// mask saturates, which propagates to every function transitively above it.
fn live_in_fixed_point(
  sections: &[SectionInput<'_>],
  layouts: &mut [FunctionLayout],
  cross_section_calls: &[CrossSectionEdge],
) {
  // Resolve each cross-section call's callee to a function index. Every
  // `callee_pc` reached here was also supplied as one of the callee section's
  // entries, so it opens a function; a caller that passes the two out of step
  // drops the edge and gets the conservative mask rather than a panic.
  let call_sites = cross_section_calls
    .iter()
    .filter_map(|edge| {
      let callee_function = *layouts
        .get(edge.callee_section)?
        .pc_to_func
        .get(edge.callee_pc)?;
      Some(CrossSectionCallSite {
        caller_section: edge.caller_section,
        call_pc: edge.call_pc,
        callee_section: edge.callee_section,
        callee_function,
      })
    })
    .collect::<Vec<_>>();

  let masks = {
    let starts = layouts
      .iter()
      .map(|layout| {
        layout
          .functions
          .iter()
          .map(|function| function.start_pc)
          .collect::<Vec<_>>()
      })
      .collect::<Vec<_>>();
    let inputs = sections
      .iter()
      .zip(layouts.iter())
      .zip(&starts)
      .map(|((section, layout), starts)| LiveInSection {
        code: section.code,
        starts,
        pc_to_func: &layout.pc_to_func,
      })
      .collect::<Vec<_>>();
    program_live_in(&inputs, &call_sites)
  };

  for (layout, masks) in layouts.iter_mut().zip(masks) {
    layout.arg_masks = masks;
  }
  // Project each callee's mask back onto its call site, so per-function region
  // analysis can mask a cross-section call without holding the whole program.
  for site in &call_sites {
    let mask = layouts[site.callee_section].arg_masks[site.callee_function];
    layouts[site.caller_section]
      .cross_section_arg_masks
      .insert(site.call_pc, mask);
  }
}

/// Analyzes a code fragment that has no container-supplied roots.
///
/// The loader always has a section's cross-section entries to hand and calls
/// [`analyze_program`] directly; this shorthand exists for tests and fixtures
/// that hold a bare fragment and no ELF around it.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn analyze_functions(code: &[u8]) -> Result<FunctionLayout, String> {
  let mut layouts =
    analyze_program(&[SectionInput { code, entries: &[] }], &[]).map_err(|(_, message)| message)?;
  Ok(layouts.remove(0))
}

/// Analyzes the local functions of every code section, and the call graph
/// between them.
///
/// One layout is returned per input section, in the same order. Errors carry
/// the index of the offending section so the caller can name it.
pub(crate) fn analyze_program(
  sections: &[SectionInput<'_>],
  cross_section_calls: &[CrossSectionEdge],
) -> Result<Vec<FunctionLayout>, (usize, String)> {
  // Partition first, for every section: the whole-program fixed point below
  // needs one section's function boundaries to settle a mask in another, so no
  // section's masks can be computed until all the boundaries are known.
  let mut layouts = Vec::with_capacity(sections.len());
  for (index, section) in sections.iter().enumerate() {
    layouts.push(partition_section(section).map_err(|message| (index, message))?);
  }
  live_in_fixed_point(sections, &mut layouts, cross_section_calls);
  Ok(layouts)
}

/// Splits one section into local functions and records the calls between them,
/// leaving the argument masks for the whole-program fixed point to fill in.
fn partition_section(section: &SectionInput<'_>) -> Result<FunctionLayout, String> {
  let SectionInput { code, entries } = *section;
  if code.len() % 8 != 0 {
    return Err("code length is not a multiple of 8".to_string());
  }

  let num_insns = code.len() / 8;
  if num_insns == 0 {
    return Ok(FunctionLayout {
      functions: Vec::new(),
      pc_to_func: Vec::new(),
      arg_masks: Vec::new(),
      cross_section_arg_masks: HashMap::new(),
    });
  }

  let mut starts = BTreeSet::from([0usize]);
  for &entry in entries {
    if entry >= num_insns {
      return Err(format!(
        "function entry PC {entry} is outside a program of {num_insns} instructions"
      ));
    }
    starts.insert(entry);
  }
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
    arg_masks: vec![ALL_SIGNATURE_REGS; starts.len()],
    cross_section_arg_masks: HashMap::new(),
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

  fn cross_section_call() -> [u8; 8] {
    // The linker zeroes a cross-section call's immediate: its callee is named
    // by the relocation metadata, not by a displacement.
    insn(EBPF_OP_CALL, 0, 2, 0, 0)
  }

  #[test]
  fn a_cross_section_callee_masks_its_call_site_to_what_it_reads() {
    // Section 0 does nothing but call into section 1, which reads R8 alone.
    // Summarising the external callee as "reads everything" would leave both
    // the call site and section 0's own mask saturated.
    let caller = [cross_section_call(), exit()].concat();
    let callee = [insn(0x71, 0, 8, 0, 0), exit()].concat(); // r0 = *(u8 *)r8
    let layouts = analyze_program(
      &[
        SectionInput {
          code: &caller,
          entries: &[],
        },
        SectionInput {
          code: &callee,
          entries: &[0],
        },
      ],
      &[CrossSectionEdge {
        caller_section: 0,
        call_pc: 0,
        callee_section: 1,
        callee_pc: 0,
      }],
    )
    .unwrap();

    assert_eq!(layouts[1].arg_masks, vec![1 << 8]);
    assert_eq!(layouts[0].cross_section_arg_masks.get(&0), Some(&(1 << 8)));
    // And the caller's own mask is the callee's, not everything: the
    // imprecision would otherwise propagate to every function above it.
    assert_eq!(layouts[0].arg_masks, vec![1 << 8]);
  }

  #[test]
  fn live_in_bits_propagate_around_a_component_that_spans_sections() {
    // A calls B calls A, across the section boundary in both directions, and
    // only B reads R8. Cutting the cross-section edges would settle A at "reads
    // everything"; solving the two sections together settles both at R8.
    let a = [cross_section_call(), exit()].concat();
    let b = [
      cross_section_call(),
      insn(0x71, 0, 8, 0, 0), // r0 = *(u8 *)r8
      exit(),
    ]
    .concat();
    let layouts = analyze_program(
      &[
        SectionInput {
          code: &a,
          entries: &[0],
        },
        SectionInput {
          code: &b,
          entries: &[0],
        },
      ],
      &[
        CrossSectionEdge {
          caller_section: 0,
          call_pc: 0,
          callee_section: 1,
          callee_pc: 0,
        },
        CrossSectionEdge {
          caller_section: 1,
          call_pc: 0,
          callee_section: 0,
          callee_pc: 0,
        },
      ],
    )
    .unwrap();

    assert_eq!(layouts[0].arg_masks, vec![1 << 8]);
    assert_eq!(layouts[1].arg_masks, vec![1 << 8]);
  }

  #[test]
  fn a_cross_section_call_with_no_edge_still_masks_nothing() {
    // A fragment analyzed outside the loader has no cross-section call graph,
    // so its external callees stay at the conservative summary.
    let code = [cross_section_call(), exit()].concat();
    let layout = analyze_functions(&code).unwrap();

    assert_eq!(layout.arg_masks, vec![ALL_SIGNATURE_REGS]);
    assert!(layout.cross_section_arg_masks.is_empty());
  }
}

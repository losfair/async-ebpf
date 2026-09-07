use std::collections::HashMap;

use crate::jit::isa::Insn;
use crate::region_analysis::{
  program_live_in, CrossSectionCallSite, LiveInSection, RegMask, ALL_SIGNATURE_REGS,
};
use crate::verified::layout::{partition, LayoutReject};
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
  /// Per slot of the section, the registers live at its entry: what the
  /// region analysis projects each state onto. Empty (all registers) until
  /// [`analyze_program`] has solved the whole program.
  pub(crate) slot_live_in: Vec<RegMask>,
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
      slot_live_in: vec![ALL_SIGNATURE_REGS; num_insns],
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

/// The message for a refused layout, worded as the linker's callers expect.
fn render(reject: LayoutReject, num_insns: usize) -> String {
  match reject {
    LayoutReject::EntryOutOfRange { entry } => {
      format!("function entry PC {entry} is outside a program of {num_insns} instructions")
    }
    LayoutReject::LocalCallTargetOutOfRange { pc, target } => {
      format!("local call target out of range at PC {pc}: {target}")
    }
    LayoutReject::JumpTargetOutOfRange { pc, target } => {
      format!("jump target out of range at PC {pc}: {target}")
    }
    LayoutReject::ControlFlowOutside { pc, start, end } => {
      format!("control flow reaches PC {pc} outside local function range [{start}, {end})")
    }
    LayoutReject::JumpOutside {
      pc,
      target,
      start,
      end,
    } => {
      format!("jump from PC {pc} reaches PC {target} outside local function range [{start}, {end})")
    }
    LayoutReject::FallthroughOutside {
      pc,
      target,
      start,
      end,
    } => format!(
      "fallthrough from PC {pc} reaches PC {target} outside local function range [{start}, {end})"
    ),
    LayoutReject::LocalCallNonFunction { pc, target } => {
      format!("local call at PC {pc} targets non-function PC {target}")
    }
  }
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

  let live_in = {
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

  for ((layout, masks), slots) in layouts.iter_mut().zip(live_in.masks).zip(live_in.slots) {
    layout.arg_masks = masks;
    layout.slot_live_in = slots;
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
///
/// The partition and the closure check are `verified::layout::partition`,
/// whose Lean proofs establish that control never leaves a function except
/// through a call; this only decodes, renders the rejection, and derives the
/// call graph from the slots the walk reached.
fn partition_section(section: &SectionInput<'_>) -> Result<FunctionLayout, String> {
  let SectionInput { code, entries } = *section;
  let Some(insns) = Insn::decode_all(code) else {
    return Err("code length is not a multiple of 8".to_string());
  };

  let num_insns = insns.len();
  if num_insns == 0 {
    return Ok(FunctionLayout {
      functions: Vec::new(),
      pc_to_func: Vec::new(),
      arg_masks: Vec::new(),
      cross_section_arg_masks: HashMap::new(),
      slot_live_in: Vec::new(),
    });
  }

  let layout = partition(&insns, entries).map_err(|reject| render(reject, num_insns))?;

  // The call graph: every reachable local call, whose target the walk has
  // established is a function start.
  let mut edges = vec![Vec::new(); layout.starts.len()];
  for (pc, insn) in insns.iter().enumerate() {
    if layout.reachable[pc] && insn.is_local_call() {
      let target = (pc as i64 + insn.imm as i64 + 1) as usize;
      edges[layout.pc_to_func[pc]].push(layout.pc_to_func[target]);
    }
  }
  for callees in &mut edges {
    callees.sort_unstable();
    callees.dedup();
  }
  let mut callers = vec![Vec::new(); layout.starts.len()];
  for (caller, callees) in edges.iter().enumerate() {
    for &callee in callees {
      callers[callee].push(caller);
    }
  }

  let functions = layout
    .starts
    .iter()
    .enumerate()
    .map(|(i, &start_pc)| FunctionInfo {
      start_pc,
      end_pc: layout.starts.get(i + 1).copied().unwrap_or(num_insns),
      callees: edges[i].clone(),
      callers: callers[i].clone(),
    })
    .collect();

  Ok(FunctionLayout {
    functions,
    pc_to_func: layout.pc_to_func,
    arg_masks: vec![ALL_SIGNATURE_REGS; layout.starts.len()],
    cross_section_arg_masks: HashMap::new(),
    slot_live_in: vec![ALL_SIGNATURE_REGS; num_insns],
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::verified::isa::{OP_CALL as EBPF_OP_CALL, OP_EXIT as EBPF_OP_EXIT};

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

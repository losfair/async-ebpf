//! Static region analysis for eBPF memory accesses.
//!
//! Classifies the pointer operand of every load, store, and atomic as pointing
//! into the per-invocation stack, the shared data region, or neither
//! ("unknown"). The JIT consumes the result as
//! [`crate::jit::TranslationInputs::hints`], and emits a single-region bounds
//! check and address translation for confidently classified accesses instead of
//! probing both regions.
//!
//! ## Provenance
//!
//! Pointer provenance in this runtime is narrow:
//!  * Stack pointers derive from `R10` (the frame pointer) or the entry `ctx`
//!    argument in `R1`, which points at the calldata living on the guest stack.
//!  * Data pointers are produced exclusively by `lddw` instructions whose
//!    64-bit immediate was patched by an `R_BPF_64_64` relocation to an address
//!    inside the data region `[data_bottom, data_top)`.
//!  * Pointer arithmetic with a scalar preserves the region.
//!
//! ## Soundness
//!
//! This pass is a *precision optimization, not a security boundary*. The stack
//! and data guest ranges are disjoint and the JIT always retains a
//! single-region bounds check, so a misclassified access can only fault
//! spuriously — never access out of bounds or cross between regions. Accesses that
//! cannot be classified confidently are left `UNKNOWN` and fall back to the
//! original dual-region probe.
//!
//! The analysis is a standard forward dataflow over the instruction-slot CFG
//! with a per-register lattice and a meet at control-flow joins, run one
//! function at a time (`verified::fixpoint::solve`) from the signature the
//! caller passes, with every state projected onto the slot's live-in
//! registers. Any slot still unreached keeps its registers `Uninit` and
//! yields `UNKNOWN` hints — safe, just unoptimized.

use std::collections::HashMap;

use crate::verified::fixpoint;
use crate::verified::isa::Insn;
use crate::verified::region::{
  self as core, entry_signature, mask_signature, signature_from_state,
};
pub(crate) use crate::verified::region::{
  PointerSignature, RegMask, ALL_SIGNATURE_REGS, R10, REGION_UNKNOWN,
};
#[cfg(any(test, feature = "testing"))]
pub(crate) use crate::verified::region::{
  RegKind, StackKind, NUM_REGS, REGION_DATA, REGION_FRAME, REGION_STACK,
};

// eBPF opcode encoding helpers.
const EBPF_CLS_MASK: u8 = 0x07;
const EBPF_CLS_LD: u8 = 0x00;
const EBPF_CLS_LDX: u8 = 0x01;
const EBPF_CLS_ST: u8 = 0x02;
const EBPF_CLS_STX: u8 = 0x03;
const EBPF_CLS_ALU: u8 = 0x04;
const EBPF_CLS_JMP: u8 = 0x05;
const EBPF_CLS_JMP32: u8 = 0x06;
const EBPF_CLS_ALU64: u8 = 0x07;

#[cfg(test)]
const EBPF_SRC_REG: u8 = 0x08;
#[cfg(test)]
const EBPF_ALU_OP_ADD: u8 = 0x00;
#[cfg(test)]
const EBPF_ALU_OP_MOV: u8 = 0xb0;

#[cfg(test)]
const EBPF_OP_LDDW: u8 = EBPF_CLS_LD | 0x18; // LD | IMM | DW
#[cfg(test)]
const EBPF_OP_JA: u8 = EBPF_CLS_JMP; // JMP | JA (mode 0)
#[cfg(test)]
const EBPF_OP_JA32: u8 = EBPF_CLS_JMP32;
const EBPF_OP_CALL: u8 = EBPF_CLS_JMP | 0x80; // JMP | CALL
const EBPF_OP_EXIT: u8 = EBPF_CLS_JMP | 0x90; // JMP | EXIT

impl PointerSignature {
  pub(crate) fn entry() -> Self {
    entry_signature()
  }

  #[cfg(any(test, feature = "testing"))]
  pub(crate) fn from_regs_for_testing(regs: [RegKind; NUM_REGS]) -> Self {
    Self { regs }
  }
}

/// An instruction as the access-plan builder reads it: register numbers
/// widened to indices. Control flow goes through `verified::isa::Insn`.
#[derive(Clone, Copy)]
struct Inst {
  opcode: u8,
  dst: usize,
  src: usize,
  offset: i16,
  /// Read by the tests' whole-program successor reference only.
  #[cfg_attr(not(test), allow(dead_code))]
  imm: i32,
}

fn decode(slot: &[u8]) -> Inst {
  Inst {
    opcode: slot[0],
    dst: (slot[1] & 0x0f) as usize,
    src: (slot[1] >> 4) as usize,
    offset: i16::from_le_bytes([slot[2], slot[3]]),
    imm: i32::from_le_bytes([slot[4], slot[5], slot[6], slot[7]]),
  }
}

fn access_width(opcode: u8) -> usize {
  core::access_width(opcode) as usize
}

/// Warns at most once per analysis when the spill-slot cap refuses an offset.
fn warn_cap_reached(cap_warning_emitted: &mut bool) {
  if !*cap_warning_emitted {
    tracing::warn!(
      max_tracked_slots = core::MAX_TRACKED_SLOTS,
      "region analysis spill-slot tracking cap reached; additional offsets will use dynamic \
       region routing"
    );
    *cap_warning_emitted = true;
  }
}

/// Result of the region analysis for one code section.
#[cfg(any(test, feature = "testing"))]
pub struct RegionAnalysis {
  /// Per-instruction-slot load region hint for the JIT (`REGION_*`). Non-load
  /// slots are [`REGION_UNKNOWN`].
  #[allow(dead_code)]
  pub hints: Vec<u8>,
  /// Slots of memory-access instructions (load, store, atomic) whose pointer
  /// could not be resolved to a single region. Empty iff every access is
  /// statically routable.
  pub unresolved: Vec<usize>,
}

pub(crate) struct FunctionRegionAnalysis {
  pub(crate) hints: Vec<u8>,
  /// Per-slot access grouping, parallel to `hints`. See [`PlanEntry`].
  pub(crate) plan: Vec<PlanEntry>,
  pub(crate) unresolved: Vec<usize>,
  pub(crate) call_signatures: std::collections::HashMap<usize, PointerSignature>,
}

/// Analyzes every memory access of one code section the way the loader
/// does: function by function, each from every masked signature some call
/// site hands it, starting with the entry signature at slot 0. A slot's hint
/// is the one its specializations agree on, `UNKNOWN` where they differ;
/// `unresolved` is their union.
///
/// `code` is the relocated bytecode, 8 bytes per slot, indexed the same way the
/// JIT indexes it — `lddw` occupies two slots, and the second is not an
/// instruction. `data_lo`/`data_hi` are the guest data region bounds used to
/// recognize relocated data pointers.
#[cfg(any(test, feature = "testing"))]
pub fn analyze(code: &[u8], data_lo: u64, data_hi: u64) -> RegionAnalysis {
  let num_slots = code.len() / 8;
  let mut hints = vec![REGION_UNKNOWN; num_slots];
  let mut unresolved = std::collections::BTreeSet::new();
  if num_slots == 0 {
    return RegionAnalysis {
      hints,
      unresolved: Vec::new(),
    };
  }
  let insns = decode_section(code);
  let layout = crate::function_analysis::analyze_functions(code)
    .unwrap_or_else(|_| crate::function_analysis::FunctionLayout::unmasked(num_slots));
  let bounds = |function: usize| -> (usize, usize) {
    layout
      .functions
      .get(function)
      .map_or((0, num_slots), |f| (f.start_pc, f.end_pc))
  };

  let mut seen = vec![false; num_slots];
  let mut done = std::collections::HashSet::new();
  let mut pending = vec![(0usize, entry_signature())];
  while let Some((function, signature)) = pending.pop() {
    if !done.insert((function, signature)) {
      continue;
    }
    let (start, end) = bounds(function);
    let result = analyze_function(
      code,
      start,
      end,
      signature,
      data_lo,
      data_hi,
      &layout,
      crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
    );
    for pc in start..end {
      let is_reached_access = result.hints[pc] != REGION_UNKNOWN || result.unresolved.contains(&pc);
      if !is_reached_access {
        continue;
      }
      if !seen[pc] {
        seen[pc] = true;
        hints[pc] = result.hints[pc];
      } else if hints[pc] != result.hints[pc] {
        hints[pc] = REGION_UNKNOWN;
      }
    }
    unresolved.extend(result.unresolved);
    for (pc, callee_signature) in result.call_signatures {
      let inst = insns[pc];
      if inst.src != 1 {
        continue;
      }
      let target = (pc as i64 + 1 + inst.imm as i64) as usize;
      if let Some(&callee) = layout.pc_to_func.get(target) {
        pending.push((callee, callee_signature));
      }
    }
  }

  RegionAnalysis {
    hints,
    unresolved: unresolved.into_iter().collect(),
  }
}

/// Analyzes the function `[start_pc, end_pc)` of a section from the
/// signature `incoming`.
///
/// The fixed point is `verified::fixpoint::solve`, over the section decoded
/// as the verified core reads it and the per-slot live-in table of
/// `layout`; this decodes, warns once if the spill-slot cap bit, classifies
/// every reached access from its settled state, computes the masked
/// signature each local call hands its callee, and groups accesses into the
/// plan. A layout whose live-in table does not cover the section (a
/// fragment analyzed outside the loader) projects nothing.
pub(crate) fn analyze_function(
  code: &[u8],
  start_pc: usize,
  end_pc: usize,
  incoming: PointerSignature,
  data_lo: u64,
  data_hi: u64,
  layout: &crate::function_analysis::FunctionLayout,
  frame_size: u16,
) -> FunctionRegionAnalysis {
  let num_slots = code.len() / 8;
  let mut hints = vec![REGION_UNKNOWN; num_slots];
  let mut unresolved = Vec::new();
  let mut call_signatures = std::collections::HashMap::new();
  let insns = decode_section(code);
  if start_pc >= end_pc || end_pc > num_slots {
    return FunctionRegionAnalysis {
      hints,
      plan: vec![PlanEntry::default(); num_slots],
      unresolved,
      call_signatures,
    };
  }

  let everything;
  let live: &[RegMask] = if layout.slot_live_in.len() == num_slots {
    &layout.slot_live_in
  } else {
    everything = vec![ALL_SIGNATURE_REGS; num_slots];
    &everything
  };
  let fixpoint::Solution {
    states,
    reached,
    refused,
  } = fixpoint::solve(&insns, start_pc, end_pc, &incoming, live, data_lo, data_hi);
  if refused {
    warn_cap_reached(&mut false);
  }

  for pc in start_pc..end_pc {
    if !reached[pc] {
      continue;
    }
    let insn = insns[pc];
    if insn.opcode == EBPF_OP_CALL && (insn.src == 1 || insn.src == 2) {
      let mask = if insn.src == 1 {
        let target = (pc as i64 + 1 + insn.imm as i64) as usize;
        layout
          .pc_to_func
          .get(target)
          .and_then(|&callee| layout.arg_masks.get(callee).copied())
          .unwrap_or(ALL_SIGNATURE_REGS)
      } else {
        // A cross-section callee lives in another section's layout, so its
        // mask is carried here per call site by the whole-program fixed point.
        // The fallback is only reached by a fragment analyzed outside the
        // loader, which has no cross-section call graph to consult.
        layout
          .cross_section_arg_masks
          .get(&pc)
          .copied()
          .unwrap_or(ALL_SIGNATURE_REGS)
      };
      call_signatures.insert(pc, mask_signature(&signature_from_state(&states[pc]), mask));
    }
    let (is_access, hint, region) = core::classify(&states[pc], &insn, frame_size);
    if !is_access {
      continue;
    }
    hints[pc] = hint;
    if region == REGION_UNKNOWN {
      unresolved.push(pc);
    }
  }

  // Grouping runs last: it keys off the hints the loop above just settled.
  let plan = build_access_plan(code, &insns, start_pc, end_pc, num_slots, &hints, &reached);

  FunctionRegionAnalysis {
    hints,
    plan,
    unresolved,
    call_signatures,
  }
}

/// Where a local call sends control, as seen from inside one code section.
///
/// A section-local call names its callee by a displacement this buffer can
/// resolve. A cross-section call cannot: its immediate was zeroed by the
/// linker and its callee lives in another section, so the call *site* is the
/// only handle on it from here, and the caller is the one holding the map from
/// site to callee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum CallSite {
  /// A `src == 1` call entering `target_pc` in this same buffer.
  Local { target_pc: usize },
  /// A linker-tagged `src == 2` call at `call_pc`, whose callee is elsewhere.
  CrossSection { call_pc: usize },
}

/// Registers whose incoming kind the function `[start_pc, end_pc)` can observe,
/// i.e. those it may read before writing, transitively through its callees.
///
/// This is the mask [`PointerSignature::masked`] applies, and it is what keeps
/// per-signature specialization affordable. A signature is the caller's whole
/// abstract register file, so without it a callee is split every time the
/// caller's incidental live state differs - a stale `R2` from an earlier helper
/// call, a pointer the caller happens to be holding in `R6` - and because those
/// registers survive calls, the splits compound down the graph. Masking a
/// register that is not live-in costs no precision: it is overwritten before
/// any read on every path, so no hint, no unresolved access and no onward
/// signature can depend on it.
///
/// `callee_live_in` reports a call site's callee summary. This solves one
/// function against summaries it is *given*; the runtime instead solves every
/// function and every summary together, in [`program_live_in`]. This is kept
/// as the readable statement of the per-function equations, and
/// `program_live_in_agrees_with_the_per_function_solver` pins the two to the
/// same answer.
#[cfg(test)]
pub(crate) fn function_live_in(
  code: &[u8],
  start_pc: usize,
  end_pc: usize,
  callee_live_in: &dyn Fn(CallSite) -> RegMask,
) -> RegMask {
  let num_slots = code.len() / 8;
  if start_pc >= end_pc || end_pc > num_slots {
    return ALL_SIGNATURE_REGS;
  }

  let insns = decode_section(code);

  // Only reachable instructions can read anything; walking dead code would add
  // uses that no execution can perform.
  let mut reachable = vec![false; num_slots];
  let mut pending = vec![start_pc];
  reachable[start_pc] = true;
  while let Some(pc) = pending.pop() {
    for succ in successors_of(&insns, pc, start_pc, end_pc) {
      if !reachable[succ] {
        reachable[succ] = true;
        pending.push(succ);
      }
    }
  }

  // Backward liveness to a fixpoint, worklist-driven. The all-slots sweep
  // needed one pass per backward edge on a path: a hostile acyclic "ladder"
  // CFG (`ja +1; ja +1; ja -2` repeated) forces ~n/3 passes over all n slots,
  // Θ(n²) — measured ~17 s at the 65535-instruction maximum, inside the
  // non-preemptible load path. Re-processing only predecessors of a changed
  // slot makes every register bit traverse every edge at most once (a
  // `RegMask` has ten signature bits, so a slot can change at most ten
  // times): O(bits · edges), with the same least fixed point the sweep
  // computed. The unit test `worklist_live_in_is_bit_identical_to_the_sweep`
  // pins the two to agree.
  let span = end_pc - start_pc;
  let mut edges = vec![Vec::new(); span];
  let mut predecessors = vec![Vec::new(); span];
  for pc in start_pc..end_pc {
    if !reachable[pc] {
      continue;
    }
    for succ in successors_of(&insns, pc, start_pc, end_pc) {
      edges[pc - start_pc].push(succ);
      predecessors[succ - start_pc].push(pc);
    }
  }
  let mut live = vec![0 as RegMask; num_slots];
  // Seeded in program order so a LIFO worklist starts at the last slot and
  // forward edges converge on the first visit, like the old reverse sweep; a
  // change re-queues only the predecessors it can affect.
  let mut work: Vec<usize> = (start_pc..end_pc).filter(|&pc| reachable[pc]).collect();
  while let Some(pc) = work.pop() {
    let inst = insns[pc];
    let mut live_out = 0;
    for &succ in &edges[pc - start_pc] {
      live_out |= live[succ];
    }
    let callee = if inst.opcode == EBPF_OP_CALL {
      match inst.src {
        1 => callee_live_in(CallSite::Local {
          target_pc: (pc as i64 + 1 + inst.imm as i64) as usize,
        }),
        2 => callee_live_in(CallSite::CrossSection { call_pc: pc }),
        _ => 0,
      }
    } else {
      0
    };
    let (uses, defs) = core::uses_and_defs(&inst, callee);
    let next = uses | (live_out & !defs);
    if next != live[pc] {
      live[pc] = next;
      work.extend_from_slice(&predecessors[pc - start_pc]);
    }
  }

  live[start_pc]
}

/// What [`program_live_in`] solves: per section, one mask per function
/// (the liveness of its entry slot, the mask its call sites apply) and one
/// mask per slot (what `verified::fixpoint::solve` projects onto). An
/// unreachable slot's mask is empty; the analysis never visits one.
pub(crate) struct LiveIn {
  pub(crate) masks: Vec<Vec<RegMask>>,
  pub(crate) slots: Vec<Vec<RegMask>>,
}

/// One code section, already partitioned into local functions, as
/// [`program_live_in`] sees it.
pub(crate) struct LiveInSection<'a> {
  pub(crate) code: &'a [u8],
  /// Function start slots, strictly ascending from 0. Function `i` spans
  /// `starts[i]` up to `starts[i + 1]`, or to the end of the section.
  pub(crate) starts: &'a [usize],
  /// The function owning each slot, as `FunctionLayout::pc_to_func`.
  pub(crate) pc_to_func: &'a [usize],
}

/// A call site whose callee the caller's own bytes cannot name: the linker
/// zeroed its immediate and identified the callee in metadata instead.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CrossSectionCallSite {
  pub(crate) caller_section: usize,
  pub(crate) call_pc: usize,
  pub(crate) callee_section: usize,
  pub(crate) callee_function: usize,
}

/// Least fixed point of the live-in equations over every function in the
/// program at once. One mask per function, per section, in input order.
///
/// # Why this is one flat solve and not a solve per function
///
/// The equations are two-level only in appearance. A function's mask *is* the
/// liveness of its own entry slot, and a call site's `uses` *is* the mask of
/// its callee's entry slot. Written out, that is a single monotone backward
/// dataflow problem over every slot in the program whose only unusual edge
/// runs from a call site to its callee's entry.
///
/// Solving it as a per-function inner fixed point wrapped in a per-function
/// outer one is what made it quadratic. The inner solve starts from nothing
/// every time any callee's mask grows, and each restart costs the whole
/// function, so a function with `m` callees whose masks settle one at a time is
/// re-analyzed `m` times at O(span) each. A caller of a chain of `m` functions
/// is Theta(m . span). Condensing the call graph into strongly connected
/// components and solving in reverse topological order would fix a chain -
/// including the shape the budget tests use, which is a DAG - but not a cycle
/// spanning those same functions, where an SCC still re-runs the inner solve
/// once per member. Flattening needs no such case split.
///
/// Flattened, nothing restarts because nothing is discarded between visits.
/// Every slot's liveness only grows, and it is capped at ten signature bits, so
/// each bit crosses each edge at most once: O(bits · edges), linear in the
/// program.
///
/// The space is linear in the program too, which the per-function solve was
/// not: the predecessor index and the callee array span every slot at once,
/// where that one held a function's worth. That is why the indices here are
/// `u32` and why the callee lookup is an array rather than a map.
///
/// Linear is not the same as cheap at the ceiling. On the largest object
/// `link_elf` admits — 128 sections of 65,534 slots, 64 MiB of code, needing
/// no relocations at all — a shape built to make every mask bit propagate
/// separately costs this function 2.1 s and 219 MB, and `analyze_program`
/// around it 4.0 s and 868 MB. That is on the non-preemptible load path, and
/// the analysis is most of what loading such an object costs. It is far below
/// what the per-function solve charged (11.7 s and 301 MB for this function on
/// the same input, and superlinearly worse as the object grows), but it is not
/// nothing, and a caller that admits objects this large should know the shape
/// of the bill.
pub(crate) fn program_live_in(
  sections: &[LiveInSection<'_>],
  cross_section_calls: &[CrossSectionCallSite],
) -> LiveIn {
  let conservative = || -> LiveIn {
    LiveIn {
      masks: sections
        .iter()
        .map(|section| vec![ALL_SIGNATURE_REGS; section.starts.len()])
        .collect(),
      slots: sections
        .iter()
        .map(|section| vec![ALL_SIGNATURE_REGS; section.code.len() / 8])
        .collect(),
    }
  };

  // Slot and function ids run consecutively across sections, so one worklist
  // covers the program.
  let mut slot_base = Vec::with_capacity(sections.len() + 1);
  let mut func_base = Vec::with_capacity(sections.len() + 1);
  let mut total_slots = 0usize;
  let mut total_funcs = 0usize;
  for section in sections {
    slot_base.push(total_slots);
    func_base.push(total_funcs);
    total_slots += section.code.len() / 8;
    total_funcs += section.starts.len();
  }
  slot_base.push(total_slots);
  func_base.push(total_funcs);

  // Ids are `u32` to keep the predecessor index compact. The linker caps a
  // program at 64 MiB of code, i.e. 8M slots, so this cannot bind in practice;
  // a caller that ignores that cap gets the conservative summary, not a wrong
  // one. Same for a `starts` array that does not partition its section: every
  // walk below assumes `starts[i] < starts[i + 1] <= num_slots`.
  if total_slots >= (u32::MAX - 1) as usize {
    return conservative();
  }
  for section in sections {
    let num_slots = section.code.len() / 8;
    if section.pc_to_func.len() != num_slots {
      return conservative();
    }
    let partitions = section.starts.windows(2).all(|pair| pair[0] < pair[1])
      && section.starts.last().is_none_or(|&last| last < num_slots)
      && section.starts.first().is_none_or(|&first| first == 0);
    if !partitions {
      return conservative();
    }
    // `bounds` indexes `starts` by a `pc_to_func` entry, and the whole-program
    // ids below are derived from it, so an entry naming no function of this
    // section is refused here rather than panicking or silently naming a
    // function in the next one.
    if section
      .pc_to_func
      .iter()
      .any(|&function| function >= section.starts.len())
    {
      return conservative();
    }
  }
  if total_funcs == 0 {
    return conservative();
  }

  let bounds = |si: usize, fi: usize| -> (usize, usize) {
    let section = &sections[si];
    let end = section
      .starts
      .get(fi + 1)
      .copied()
      .unwrap_or(section.code.len() / 8);
    (section.starts[fi], end)
  };

  let section_insns: Vec<Vec<Insn>> = sections
    .iter()
    .map(|section| decode_section(section.code))
    .collect();

  // Reachable slots only. This is a speedup, not a correctness requirement:
  // liveness runs backward, and every successor of a reachable slot is itself
  // reachable, so an unreachable slot's liveness can only ever flow to other
  // unreachable slots and never reaches a function entry. Skipping them also
  // keeps this identical to `function_live_in`, which filters the same way.
  let mut reachable = vec![false; total_slots];
  let mut stack: Vec<usize> = Vec::new();
  for (si, section) in sections.iter().enumerate() {
    let base = slot_base[si];
    for fi in 0..section.starts.len() {
      let (start, end) = bounds(si, fi);
      reachable[base + start] = true;
      stack.push(start);
      while let Some(pc) = stack.pop() {
        for succ in successors_of(&section_insns[si], pc, start, end) {
          if !reachable[base + succ] {
            reachable[base + succ] = true;
            stack.push(succ);
          }
        }
      }
    }
  }

  // Each call site's callee, indexed by global slot id. Dense rather than a
  // map: this is read on every worklist pop, and at the linker's ceiling a
  // hash table over 4M call sites costs both more memory (~106 MB against 34)
  // and a lookup per pop, which is what makes the per-pop cost degrade as the
  // working set leaves cache.
  //
  // `NOT_A_CALL` is a slot that contributes no callee summary; `UNRESOLVED` is
  // a call whose target this analysis cannot name, which reads everything. The
  // loader's own validation refuses the latter long before here, so it is a
  // backstop. Both sentinels are outside the id space: the bail above keeps
  // `total_funcs <= total_slots < u32::MAX - 1`.
  const NOT_A_CALL: u32 = u32::MAX;
  const UNRESOLVED: u32 = u32::MAX - 1;
  let mut callee_of = vec![NOT_A_CALL; total_slots];
  let mut cross_callee: HashMap<u32, u32> = HashMap::new();
  for call in cross_section_calls {
    if call.caller_section >= sections.len() || call.callee_section >= sections.len() {
      continue;
    }
    if call.callee_function >= sections[call.callee_section].starts.len() {
      continue;
    }
    // A call site outside its own section would alias a slot in a later one:
    // global slot ids are only injective while every `call_pc` is inside the
    // section it is attributed to, and the aliased slot's callee would be
    // silently rebound - narrowing a mask rather than widening it.
    if call.call_pc >= sections[call.caller_section].code.len() / 8 {
      continue;
    }
    cross_callee.insert(
      (slot_base[call.caller_section] + call.call_pc) as u32,
      (func_base[call.callee_section] + call.callee_function) as u32,
    );
  }
  for (si, section) in sections.iter().enumerate() {
    let num_slots = section.code.len() / 8;
    let base = slot_base[si];
    for pc in 0..num_slots {
      if !reachable[base + pc] {
        continue;
      }
      let inst = section_insns[si][pc];
      if inst.opcode != EBPF_OP_CALL {
        continue;
      }
      let callee = match inst.src {
        1 => {
          // A wild displacement wraps to something enormous, which `get`
          // rejects along with every other out-of-range target.
          let target = (pc as i64 + 1 + inst.imm as i64) as usize;
          section
            .pc_to_func
            .get(target)
            .map_or(UNRESOLVED, |&callee| (func_base[si] + callee) as u32)
        }
        2 => cross_callee
          .get(&((base + pc) as u32))
          .copied()
          .unwrap_or(UNRESOLVED),
        _ => continue,
      };
      callee_of[base + pc] = callee;
    }
  }

  // The global slot each function starts at: a function's mask is exactly the
  // liveness of that slot, which is what makes this one dataflow problem.
  let mut func_start_slot = vec![0u32; total_funcs];
  for (si, section) in sections.iter().enumerate() {
    for (fi, &start) in section.starts.iter().enumerate() {
      func_start_slot[func_base[si] + fi] = (slot_base[si] + start) as u32;
    }
  }

  // Predecessors, and the call sites reading each function's entry, both as
  // flat CSR arrays. Built once for the whole program: rebuilding a
  // `Vec<Vec<_>>` per function per visit is the cost this solve exists to
  // avoid.
  let mut pred_offset = vec![0u32; total_slots + 1];
  let mut caller_offset = vec![0u32; total_funcs + 1];
  let for_each_edge = |mut on_pred: Box<dyn FnMut(usize, usize) + '_>,
                       mut on_caller: Box<dyn FnMut(usize, usize) + '_>| {
    for (si, section) in sections.iter().enumerate() {
      let num_slots = section.code.len() / 8;
      let base = slot_base[si];
      for pc in 0..num_slots {
        if !reachable[base + pc] {
          continue;
        }
        let (start, end) = bounds(si, section.pc_to_func[pc]);
        for succ in successors_of(&section_insns[si], pc, start, end) {
          on_pred(base + succ, base + pc);
        }
        let callee = callee_of[base + pc];
        if callee != NOT_A_CALL && callee != UNRESOLVED {
          on_caller(callee as usize, base + pc);
        }
      }
    }
  };
  for_each_edge(
    Box::new(|succ, _| pred_offset[succ + 1] += 1),
    Box::new(|callee, _| caller_offset[callee + 1] += 1),
  );
  for i in 0..total_slots {
    pred_offset[i + 1] += pred_offset[i];
  }
  for i in 0..total_funcs {
    caller_offset[i + 1] += caller_offset[i];
  }
  let mut pred_entries = vec![0u32; pred_offset[total_slots] as usize];
  let mut caller_entries = vec![0u32; caller_offset[total_funcs] as usize];
  {
    let mut pred_cursor = pred_offset.clone();
    let mut caller_cursor = caller_offset.clone();
    for_each_edge(
      Box::new(|succ, pred| {
        pred_entries[pred_cursor[succ] as usize] = pred as u32;
        pred_cursor[succ] += 1;
      }),
      Box::new(|callee, call_slot| {
        caller_entries[caller_cursor[callee] as usize] = call_slot as u32;
        caller_cursor[callee] += 1;
      }),
    );
  }

  let mut live = vec![0 as RegMask; total_slots];
  let mut queued = vec![false; total_slots];
  // Seeded in ascending program order so a LIFO worklist starts at the last
  // slot and forward edges converge on the first visit. This is a constant
  // factor either way, and not always the right one - descending seeding is
  // about twice as fast on a call-heavy program at the size ceiling and about
  // 20% slower on the call-chain shape the budget tests use.
  let mut work: Vec<u32> = (0..total_slots as u32)
    .filter(|&slot| reachable[slot as usize])
    .collect();
  for &slot in &work {
    queued[slot as usize] = true;
  }

  while let Some(slot) = work.pop() {
    let slot = slot as usize;
    queued[slot] = false;
    // `slot_base` is ascending, so the owning section is the last base at or
    // below this slot. A section with no slots contributes none, and so is
    // never selected.
    let si = slot_base.partition_point(|&base| base <= slot) - 1;
    let section = &sections[si];
    let pc = slot - slot_base[si];
    let fi = section.pc_to_func[pc];
    let (start, end) = bounds(si, fi);

    let inst = section_insns[si][pc];
    let mut live_out = 0;
    for succ in successors_of(&section_insns[si], pc, start, end) {
      live_out |= live[slot_base[si] + succ];
    }
    let callee = match callee_of[slot] {
      NOT_A_CALL => 0,
      UNRESOLVED => ALL_SIGNATURE_REGS,
      callee => live[func_start_slot[callee as usize] as usize],
    };
    let (uses, defs) = core::uses_and_defs(&inst, callee);
    // Monotone: `uses` grows with the callee summary and `live_out` with the
    // successors, both of which only ever gain bits. The union with the
    // previous value is therefore a no-op today, and is kept because it is
    // what makes termination independent of that property: without it, a
    // future non-monotone change loops forever here, on the load path, rather
    // than returning a slightly imprecise mask.
    let computed = uses | (live_out & !defs);
    debug_assert_eq!(live[slot] & !computed, 0);
    let next = live[slot] | computed;
    if next == live[slot] {
      continue;
    }
    live[slot] = next;

    let mut wake = |target: usize| {
      if !queued[target] {
        queued[target] = true;
        work.push(target as u32);
      }
    };
    for i in pred_offset[slot]..pred_offset[slot + 1] {
      wake(pred_entries[i as usize] as usize);
    }
    // A function's mask is its entry slot's liveness, so growing that slot is
    // what wakes its call sites - anywhere in the program.
    if start == pc {
      let func = func_base[si] + fi;
      for i in caller_offset[func]..caller_offset[func + 1] {
        wake(caller_entries[i as usize] as usize);
      }
    }
  }

  LiveIn {
    masks: sections
      .iter()
      .enumerate()
      .map(|(si, section)| {
        (0..section.starts.len())
          .map(|fi| live[func_start_slot[func_base[si] + fi] as usize])
          .collect()
      })
      .collect(),
    slots: sections
      .iter()
      .enumerate()
      .map(|(si, section)| live[slot_base[si]..slot_base[si] + section.code.len() / 8].to_vec())
      .collect(),
  }
}

/// The in-function successors of `pc`, as `verified::fixpoint::solve` walks
/// them: the live-in table and the access plan are built on the same edges
/// the region analysis runs over, by construction.
fn successors_of(
  insns: &[Insn],
  pc: usize,
  start_pc: usize,
  end_pc: usize,
) -> impl Iterator<Item = usize> {
  let (count, first, second) = fixpoint::function_successors(insns, pc, start_pc, end_pc);
  [first, second].into_iter().take(count)
}

/// The section's instructions as the verified core reads them. `code` is
/// whole slots; a trailing partial slot is not an instruction.
fn decode_section(code: &[u8]) -> Vec<Insn> {
  let num_slots = code.len() / 8;
  Insn::decode_all(&code[..num_slots * 8]).expect("whole slots decode")
}

/// One entry per instruction slot, handed to the JIT alongside the region hints
/// as [`crate::jit::TranslationInputs::plan`].
///
/// A *group* is a run of memory accesses sharing one base register, so all of
/// their addresses lie within a bounded window around that register's value.
/// The first access is the group's **leader**: it bounds-checks the whole window
/// once and parks the translated base in the frame. Every later **member** reads
/// that base back and accesses it at a constant displacement - two instructions
/// instead of a full check.
///
/// The plan is advisory. The backend re-derives every condition it can see for
/// itself and emits an ordinary checked access when any of them fails, so a
/// wrong plan costs speed, not safety.
/// The plan entry type is [`crate::jit::PlanEntry`] itself: the analysis builds
/// the same struct the backend reads, so there is nothing to keep in step.
pub(crate) use crate::jit::PlanEntry;

pub(crate) const PLAN_ROLE_LEADER: u8 = 1;
pub(crate) const PLAN_ROLE_MEMBER: u8 = 2;

/// Widest window a group may span.
///
/// A failed check yields base 0, so a member then dereferences `[0 + delta]`.
/// That has to land inside the runtime's guard window - the range the SIGSEGV
/// handler claims as a guest fault rather than a host crash - which bounds
/// `delta`, and with it the span, at one page.
pub(crate) const MAX_GROUP_SPAN: i32 = 4096;

/// A group under construction.
struct OpenGroup {
  base: usize,
  leader_pc: usize,
  /// `(pc, displacement)` of each access so far.
  members: Vec<(usize, i32)>,
  /// The region all members so far agree on, if any.
  region: Option<u8>,
  lo: i32,
  hi: i32,
}

fn close_group(open: &mut Option<OpenGroup>, plan: &mut [PlanEntry]) {
  let Some(g) = open.take() else { return };
  if g.members.len() < 2 {
    return;
  }
  let region = g.region.unwrap_or(REGION_UNKNOWN);
  let span = (g.hi - g.lo) as u32;
  for (i, &(pc, disp)) in g.members.iter().enumerate() {
    plan[pc] = PlanEntry {
      role: if i == 0 {
        PLAN_ROLE_LEADER
      } else {
        PLAN_ROLE_MEMBER
      },
      region,
      delta: (disp - g.lo) as u16,
      span,
      lo: g.lo,
      leader_pc: g.leader_pc as u32,
    };
  }
}

/// Registers `inst` may overwrite. Over-approximating only ends groups early;
/// under-approximating would let a group keep using a base that has changed.
fn written_registers(inst: &Inst) -> Vec<usize> {
  match inst.opcode & EBPF_CLS_MASK {
    EBPF_CLS_LD | EBPF_CLS_LDX | EBPF_CLS_ALU | EBPF_CLS_ALU64 => vec![inst.dst],
    // A fetching atomic writes its source register, and CMPXCHG writes R0.
    EBPF_CLS_STX if inst.opcode & 0xe0 == 0xc0 => vec![inst.src, 0],
    EBPF_CLS_JMP | EBPF_CLS_JMP32 if inst.opcode == EBPF_OP_CALL => (0..6).collect(),
    _ => Vec::new(),
  }
}

/// Assigns the accesses in `[start_pc, end_pc)` to groups.
///
/// The rule is deliberately local: a group is a straight-line run inside one
/// basic block, off a base register that nothing redefines along the way. That
/// covers the shape compilers actually emit - a struct initialised field by
/// field, a loop body touching several members of one object - without having to
/// reason about what a branch or a call might have done to the base.
///
/// Frame accesses are left out: `R10` addressing is already unchecked, so a
/// window would save nothing.
fn build_access_plan(
  code: &[u8],
  insns: &[Insn],
  start_pc: usize,
  end_pc: usize,
  num_slots: usize,
  hints: &[u8],
  reached: &[bool],
) -> Vec<PlanEntry> {
  let mut plan = vec![PlanEntry::default(); num_slots];

  // Anything a branch can land on ends the previous group: the base would not
  // have been established on the path that jumped in. Calls end it too - a
  // local callee runs in the same host frame and would overwrite the parked
  // base, and a helper call can suspend the guest entirely.
  let mut is_target = vec![false; num_slots];
  for pc in start_pc..end_pc {
    if !reached[pc] {
      continue;
    }
    let inst = insns[pc];
    let cls = inst.opcode & EBPF_CLS_MASK;
    if (cls == EBPF_CLS_JMP || cls == EBPF_CLS_JMP32) && inst.opcode != EBPF_OP_EXIT {
      for succ in successors_of(insns, pc, start_pc, end_pc) {
        is_target[succ] = true;
      }
    }
  }

  let mut open: Option<OpenGroup> = None;
  let mut written: u16 = 0;

  for pc in start_pc..end_pc {
    if !reached[pc] {
      close_group(&mut open, &mut plan);
      written = 0;
      continue;
    }
    if is_target[pc] {
      close_group(&mut open, &mut plan);
      written = 0;
    }

    let inst = decode(&code[pc * 8..pc * 8 + 8]);
    let cls = inst.opcode & EBPF_CLS_MASK;
    let is_atomic = cls == EBPF_CLS_STX && inst.opcode & 0xe0 == 0xc0;
    let base = match cls {
      EBPF_CLS_LDX => Some(inst.src),
      EBPF_CLS_ST | EBPF_CLS_STX => Some(inst.dst),
      _ => None,
    };

    // Atomics both read and write, and the backend routes them through the full
    // check, so they neither join nor start a group.
    if let Some(base) = base.filter(|_| !is_atomic) {
      if base != R10 {
        let width = access_width(inst.opcode) as i32;
        let disp = inst.offset as i32;
        let extends = open.as_ref().is_some_and(|g| {
          g.base == base
            && written & (1 << base) == 0
            && g.hi.max(disp + width) - g.lo.min(disp) <= MAX_GROUP_SPAN
        });
        if !extends {
          close_group(&mut open, &mut plan);
          written = 0;
          open = Some(OpenGroup {
            base,
            leader_pc: pc,
            members: Vec::new(),
            region: None,
            lo: disp,
            hi: disp + width,
          });
        }
        let g = open.as_mut().expect("a group is open");
        g.members.push((pc, disp));
        g.lo = g.lo.min(disp);
        g.hi = g.hi.max(disp + width);
        // Members that disagree on a region leave the group to the dual-region
        // probe, which covers both.
        g.region = Some(match g.region {
          None => hints[pc],
          Some(prev) if prev == hints[pc] => prev,
          Some(_) => REGION_UNKNOWN,
        });
      }
    }

    // Record what this instruction overwrites, after using it: an access whose
    // destination is its own base is still valid, but nothing after it is.
    for reg in written_registers(&inst) {
      written |= 1 << reg;
      if open.as_ref().is_some_and(|g| g.base == reg) {
        close_group(&mut open, &mut plan);
        written = 0;
      }
    }
  }
  close_group(&mut open, &mut plan);

  plan
}

#[cfg(test)]
mod tests {
  use super::*;

  // Builders for raw eBPF instruction slots.
  fn slot(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> [u8; 8] {
    let mut s = [0u8; 8];
    s[0] = opcode;
    s[1] = (dst & 0x0f) | (src << 4);
    s[2..4].copy_from_slice(&offset.to_le_bytes());
    s[4..8].copy_from_slice(&imm.to_le_bytes());
    s
  }

  fn flatten(slots: &[[u8; 8]]) -> Vec<u8> {
    slots.iter().flatten().copied().collect()
  }

  const DATA_LO: u64 = 0x10000;
  const DATA_HI: u64 = 0x20000;

  /// `function_live_in` over a whole fragment, with callees reporting `callee`.
  fn live_in(code: &[u8], callee: RegMask) -> RegMask {
    function_live_in(code, 0, code.len() / 8, &|_| callee)
  }

  // ---------------------------------------------------------------------
  // Audit scaffolding (added while reviewing the access plan / frame hint).
  // ---------------------------------------------------------------------

  /// Whole-fragment `analyze_function` from the ordinary entry signature.
  fn analyze_fn(code: &[u8]) -> FunctionRegionAnalysis {
    analyze_function(
      code,
      0,
      code.len() / 8,
      PointerSignature::entry(),
      DATA_LO,
      DATA_HI,
      &crate::function_analysis::FunctionLayout::unmasked(code.len() / 8),
      crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
    )
  }

  fn plan_of(code: &[u8]) -> Vec<PlanEntry> {
    analyze_fn(code).plan
  }

  /// `(role, region, delta, span, lo, leader_pc)` for a slot, for terse asserts.
  fn entry(p: &PlanEntry) -> (u8, u8, u16, u32, i32, u32) {
    (p.role, p.region, p.delta, p.span, p.lo, p.leader_pc)
  }

  const LDXB: u8 = EBPF_CLS_LDX | 0x10;
  const LDXH: u8 = EBPF_CLS_LDX | 0x08;
  const LDXW: u8 = EBPF_CLS_LDX | 0x00;
  const LDXDW: u8 = EBPF_CLS_LDX | 0x18;
  const LDXWSX: u8 = EBPF_CLS_LDX | 0x80; // MEMSX | W
  const LDXHSX: u8 = EBPF_CLS_LDX | 0x88;
  const LDXBSX: u8 = EBPF_CLS_LDX | 0x90;
  const STDW: u8 = EBPF_CLS_ST | 0x18;
  const STXDW: u8 = EBPF_CLS_STX | 0x18;
  const ATOMIC_DW: u8 = EBPF_CLS_STX | 0xc0 | 0x18;
  const MOV64_REG: u8 = EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV;
  const ADD64_IMM: u8 = EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD;
  const JEQ_IMM: u8 = EBPF_CLS_JMP | 0x10;

  /// `r1 = r10; r1 += -1024` - a base that is stack-derived but is not `R10`
  /// itself, so accesses off it are grouped rather than taking the frame path.
  fn base_off_frame() -> [[u8; 8]; 2] {
    [
      slot(MOV64_REG, 1, 10, 0, 0),
      slot(ADD64_IMM, 1, 0, 0, -1024),
    ]
  }

  /// Every accepted `LDX`/`ST`/`STX` opcode form, with the width the backend
  /// uses for it. The frame window test and the group span both depend on
  /// `access_width` agreeing with the backend for every one of them.
  #[test]
  fn access_width_matches_every_accepted_opcode_form() {
    for (opcode, want) in [
      (LDXB, 1),
      (LDXH, 2),
      (LDXW, 4),
      (LDXDW, 8),
      (LDXBSX, 1),
      (LDXHSX, 2),
      (LDXWSX, 4),
      (EBPF_CLS_ST | 0x10, 1),
      (EBPF_CLS_ST | 0x08, 2),
      (EBPF_CLS_ST | 0x00, 4),
      (STDW, 8),
      (EBPF_CLS_STX | 0x10, 1),
      (EBPF_CLS_STX | 0x08, 2),
      (EBPF_CLS_STX | 0x00, 4),
      (STXDW, 8),
      (EBPF_CLS_STX | 0xc0 | 0x00, 4), // ATOMIC32
      (ATOMIC_DW, 8),
    ] {
      assert_eq!(access_width(opcode), want, "opcode {opcode:#04x}");
    }
  }

  /// The default frame window is closed at the bottom and open at the top, for
  /// every width.
  #[test]
  fn frame_hint_window_boundaries() {
    const W: i16 = crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE as i16;
    for (opcode, width) in [(LDXB, 1i16), (LDXH, 2), (LDXW, 4), (LDXDW, 8)] {
      for (offset, want_frame) in [
        (-W, true),          // lowest byte of the window
        (-W - 1, false),     // one byte below it
        (-width, true),      // ends exactly at R10
        (-width + 1, false), // would cross R10
        (0i16, false),
        (1, false),
      ] {
        let code = flatten(&[
          slot(opcode, 0, 10, offset, 0),
          slot(EBPF_OP_EXIT, 0, 0, 0, 0),
        ]);
        let hints = analyze_fn(&code).hints;
        let want = if want_frame {
          REGION_FRAME
        } else {
          REGION_STACK
        };
        assert_eq!(
          hints[0], want,
          "opcode {opcode:#04x} width {width} offset {offset}"
        );
      }
    }
  }

  #[test]
  fn configured_frame_size_changes_the_unchecked_window() {
    let code = flatten(&[slot(LDXDW, 0, 10, -8192, 0), slot(EBPF_OP_EXIT, 0, 0, 0, 0)]);
    let result = analyze_function(
      &code,
      0,
      code.len() / 8,
      PointerSignature::entry(),
      DATA_LO,
      DATA_HI,
      &crate::function_analysis::FunctionLayout::unmasked(code.len() / 8),
      8192,
    );
    assert_eq!(result.hints[0], REGION_FRAME);
  }

  /// The sign-extended loads carry their width in the same bits, so they get
  /// the same window - `ldxwsx [r10-4]` fits, `ldxwsx [r10-3]` does not.
  #[test]
  fn sign_extended_loads_use_their_real_width_in_the_frame_window() {
    for (opcode, width) in [(LDXBSX, 1i16), (LDXHSX, 2), (LDXWSX, 4)] {
      for (offset, want) in [(-width, REGION_FRAME), (-width + 1, REGION_STACK)] {
        let code = flatten(&[
          slot(opcode, 0, 10, offset, 0),
          slot(EBPF_OP_EXIT, 0, 0, 0, 0),
        ]);
        assert_eq!(
          analyze_fn(&code).hints[0],
          want,
          "opcode {opcode:#04x} offset {offset}"
        );
      }
    }
  }

  /// Stores and atomics get the same region hint as loads. Only the narrower
  /// frame fast path remains specific to non-atomic frame accesses.
  #[test]
  fn stores_receive_their_statically_classified_region() {
    let code = flatten(&[
      slot(STDW, 10, 0, -8, 0),      // st [r10-8], 0      -> FRAME
      slot(STXDW, 10, 1, -16, 0),    // stx [r10-16], r1   -> FRAME
      slot(STDW, 10, 0, -8192, 0),   // outside the window -> STACK
      slot(ATOMIC_DW, 10, 2, -8, 1), // atomic -> STACK, never FRAME
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze_fn(&code).hints;
    assert_eq!(hints[0], REGION_FRAME);
    assert_eq!(hints[1], REGION_FRAME);
    assert_eq!(hints[2], REGION_STACK);
    assert_eq!(hints[3], REGION_STACK);
  }

  /// A group's window is the convex hull of its members, and every member's
  /// delta is measured from the hull's low bound - including the leader, which
  /// need not be the lowest.
  #[test]
  fn group_deltas_are_measured_from_the_windows_low_bound() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXB, 2, 1, 5, 0),  // leader, disp 5, width 1
      slot(LDXDW, 3, 1, 8, 0), // disp 8, width 8 -> hi = 16
      slot(LDXH, 4, 1, 0, 0),  // disp 0, width 2 -> lo = 0
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let code = flatten(&slots);
    let plan = plan_of(&code);
    assert_eq!(
      entry(&plan[2]),
      (PLAN_ROLE_LEADER, REGION_STACK, 5, 16, 0, 2)
    );
    assert_eq!(
      entry(&plan[3]),
      (PLAN_ROLE_MEMBER, REGION_STACK, 8, 16, 0, 2)
    );
    assert_eq!(
      entry(&plan[4]),
      (PLAN_ROLE_MEMBER, REGION_STACK, 0, 16, 0, 2)
    );
    // What the backend re-derives: delta + width <= span, for every member.
    for (pc, width) in [(2usize, 1u32), (3, 8), (4, 2)] {
      assert!(plan[pc].delta as u32 + width <= plan[pc].span);
    }
  }

  /// The span cap is inclusive, and one byte past it starts a new group.
  #[test]
  fn the_span_cap_is_inclusive() {
    let build = |far: i16| {
      let mut slots = base_off_frame().to_vec();
      slots.extend([
        slot(LDXB, 2, 1, 0, 0),
        slot(LDXB, 3, 1, far, 0),
        slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      ]);
      plan_of(&flatten(&slots))
    };
    let plan = build(4095); // hull [0, 4096) - exactly the cap
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(
      entry(&plan[3]),
      (PLAN_ROLE_MEMBER, REGION_STACK, 4095, 4096, 0, 2)
    );

    let plan = build(4096); // hull [0, 4097) - over the cap
    assert_eq!(plan[2].role, 0);
    assert_eq!(plan[3].role, 0);
  }

  /// The extreme displacements an `i16` offset can hold must not overflow the
  /// span arithmetic; they just refuse to group.
  #[test]
  fn extreme_displacements_do_not_overflow_the_span() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, i16::MIN, 0),
      slot(LDXDW, 3, 1, i16::MAX, 0),
      slot(LDXDW, 4, 1, i16::MIN, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    for pc in 2..5 {
      assert_eq!(plan[pc].role, 0, "slot {pc}");
    }
  }

  /// Stores participate in the same region agreement as loads.
  #[test]
  fn a_store_keeps_the_groups_data_region() {
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 1, 0, 0, DATA_LO as i32),
      slot(0, 0, 0, 0, 0),
      slot(LDXDW, 2, 1, 0, 0), // hint DATA
      slot(LDXDW, 3, 1, 8, 0), // hint DATA
      slot(STDW, 1, 0, 16, 0), // same DATA base
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze_fn(&code);
    assert_eq!(result.hints[2], REGION_DATA);
    assert_eq!(result.hints[3], REGION_DATA);
    assert_eq!(result.hints[4], REGION_DATA);
    assert_eq!(result.plan[2].region, REGION_DATA);
    assert_eq!(result.plan[3].region, REGION_DATA);
    assert_eq!(result.plan[4].region, REGION_DATA);
  }

  /// The window a group covers never reaches from one guest region into the
  /// other. The cage's inter-region guard is what guarantees it.
  #[test]
  fn a_group_window_cannot_span_two_guest_regions() {
    // The narrowest guard the cage can randomize to, on the smallest page size
    // it will accept.
    const MIN_INTER_REGION_GUARD: i32 = 16 * 4096;
    assert!(
      MAX_GROUP_SPAN <= MIN_INTER_REGION_GUARD,
      "a single group window could straddle the stack and data regions"
    );
  }

  /// A group without a store takes the loads' region, and a group whose loads
  /// cannot be routed stays UNKNOWN so the backend probes both.
  #[test]
  fn a_load_only_group_takes_the_loads_region() {
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 1, 0, 0, DATA_LO as i32),
      slot(0, 0, 0, 0, 0),
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&code);
    assert_eq!(plan[2].region, REGION_DATA);
    assert_eq!(plan[3].region, REGION_DATA);

    // r6 is Scalar at entry, so nothing routes.
    let code = flatten(&[
      slot(LDXDW, 2, 6, 0, 0),
      slot(LDXDW, 3, 6, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&code);
    assert_eq!(plan[0].region, REGION_UNKNOWN);
    assert_eq!(plan[0].role, PLAN_ROLE_LEADER);
  }

  /// An `R10` access in the middle of a run neither joins the group nor closes
  /// it: it needs no base of its own and touches nothing the group parked.
  #[test]
  fn a_frame_access_between_members_keeps_the_group_open() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 3, 10, -8, 0), // frame access, ungrouped
      slot(LDXDW, 4, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[3].role, 0);
    assert_eq!(
      entry(&plan[4]),
      (PLAN_ROLE_MEMBER, REGION_STACK, 8, 16, 0, 2)
    );
  }

  /// An atomic is routed through the full check, so it neither joins a group
  /// nor ends one - but it does write its source register, which does.
  #[test]
  fn an_atomic_does_not_join_a_group_but_its_write_closes_one() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(ATOMIC_DW, 1, 3, 16, 1), // atomic fetch_add through r1, writes r3
      slot(LDXDW, 4, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[3].role, 0, "the atomic itself is never grouped");
    assert_eq!(plan[4].role, PLAN_ROLE_MEMBER);
    // The window covers only the two loads; the atomic's own displacement is
    // not in it.
    assert_eq!(plan[2].span, 16);

    // An atomic whose source is the base closes the group.
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(ATOMIC_DW, 6, 1, 0, 1), // fetch writes r1
      slot(LDXDW, 4, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, 0);
    assert_eq!(plan[4].role, 0);
  }

  /// A `lddw` in the middle of a run of accesses splits the group in two,
  /// because its second slot is never reached by the dataflow. Nothing unsafe -
  /// but both halves lose their window.
  #[test]
  fn a_lddw_between_accesses_dissolves_the_group() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(EBPF_OP_LDDW, 3, 0, 0, 0), // two slots
      slot(0, 0, 0, 0, 0),
      slot(LDXDW, 4, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    // Both accesses are left ungrouped: the group is closed at the unreached
    // second slot with a single member, and the one after it never gets a
    // partner.
    assert_eq!(plan[2].role, 0, "the group did not survive the lddw");
    assert_eq!(plan[5].role, 0);

    // Without the lddw the very same pair does group, which is the point.
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(MOV64_REG, 3, 0, 0, 0),
      slot(LDXDW, 4, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[4].role, PLAN_ROLE_MEMBER);
  }

  /// The second slot of a `lddw` is never decoded as an access, so it can
  /// neither lead nor join a group even when its bit pattern would say so.
  #[test]
  fn the_second_slot_of_a_lddw_is_never_an_access() {
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 1, 0, 0, DATA_LO as i32),
      slot(0, 0, 0, 0, 0),
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze_fn(&code);
    assert_eq!(result.plan[1], PlanEntry::default());
    assert_eq!(result.hints[1], REGION_UNKNOWN);
    assert!(!result.unresolved.contains(&1));
    assert_eq!(result.plan[2].role, PLAN_ROLE_LEADER);
  }

  /// Unreachable slots get no plan entry, so the backend - which walks the
  /// whole range regardless of reachability - falls back to a checked access.
  #[test]
  fn unreachable_accesses_get_no_plan_entry() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(LDXDW, 4, 1, 16, 0), // dead
      slot(LDXDW, 5, 1, 24, 0), // dead
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[3].role, PLAN_ROLE_MEMBER);
    assert_eq!(plan[5], PlanEntry::default());
    assert_eq!(plan[6], PlanEntry::default());
  }

  /// Every landing site of a conditional branch - target and fall-through -
  /// ends the group before it.
  #[test]
  fn both_edges_of_a_conditional_branch_are_barriers() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(JEQ_IMM, 3, 0, 1, 0), // -> slot 5 (skipping slot 4)
      slot(LDXDW, 4, 1, 8, 0),   // fall-through, and a barrier itself
      slot(LDXDW, 5, 1, 16, 0),  // branch target
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    for pc in [2usize, 4, 5] {
      assert_eq!(plan[pc].role, 0, "slot {pc} should not be grouped");
    }
  }

  /// A backward branch target ends the group that ran into it.
  #[test]
  fn a_backward_branch_target_is_a_barrier() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),    // slot 2: loop head, a branch target
      slot(LDXDW, 3, 1, 8, 0),    // slot 3
      slot(JEQ_IMM, 4, 0, -3, 0), // slot 4: back to slot 2
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER, "the loop body still groups");
    assert_eq!(plan[3].role, PLAN_ROLE_MEMBER);
  }

  /// A branch whose target lands outside the function is dropped rather than
  /// indexing out of the barrier array.
  #[test]
  fn an_out_of_range_branch_target_is_dropped() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(EBPF_OP_JA, 0, 0, i16::MIN, 0), // wildly out of range, backwards
      slot(LDXDW, 3, 1, 8, 0),             // unreachable after the JA
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots)); // must not panic
    assert_eq!(plan[2].role, 0);
  }

  /// The barrier pre-pass ignores unreachable branches, so a group can span a
  /// slot the backend treats as a landing site. Safe - the backend closes the
  /// group itself and the member falls back to a checked access - but it means
  /// the two barrier sets are not identical.
  #[test]
  fn an_unreachable_branch_leaves_no_barrier() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(EBPF_OP_JA, 0, 0, 2, 0),   // slot 2: -> slot 5
      slot(JEQ_IMM, 0, 0, 3, 0),      // slot 3: dead; its target would be slot 7
      slot(EBPF_OP_EXIT, 0, 0, 0, 0), // slot 4: dead
      slot(LDXDW, 2, 1, 0, 0),        // slot 5
      slot(LDXDW, 3, 1, 8, 0),        // slot 6
      slot(LDXDW, 4, 1, 16, 0),       // slot 7: the dead branch's target
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[5].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[6].role, PLAN_ROLE_MEMBER);
    // Slot 7 is in the group even though the backend's barrier table marks it.
    assert_eq!(plan[7].role, PLAN_ROLE_MEMBER);
  }

  /// Both a helper call and a local call end the group at their return slot.
  #[test]
  fn a_call_ends_the_group_at_its_return_slot() {
    for src in [0u8, 1] {
      let mut slots = base_off_frame().to_vec();
      slots.extend([
        slot(MOV64_REG, 6, 10, 0, 0),
        slot(ADD64_IMM, 6, 0, 0, -1024),
        slot(LDXDW, 2, 6, 0, 0),
        slot(LDXDW, 3, 6, 8, 0),
        slot(EBPF_OP_CALL, 0, src, 0, 2), // -> slot 9 when local
        slot(LDXDW, 4, 6, 16, 0),
        slot(LDXDW, 5, 6, 24, 0),
        slot(EBPF_OP_EXIT, 0, 0, 0, 0),
        slot(EBPF_OP_EXIT, 0, 0, 0, 0), // callee
      ]);
      let code = flatten(&slots);
      let plan = analyze_function(
        &code,
        0,
        9,
        PointerSignature::entry(),
        DATA_LO,
        DATA_HI,
        &crate::function_analysis::FunctionLayout::unmasked(code.len() / 8),
        crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
      )
      .plan;
      assert_eq!(plan[4].role, PLAN_ROLE_LEADER, "src {src}");
      assert_eq!(plan[5].role, PLAN_ROLE_MEMBER, "src {src}");
      assert_eq!(plan[5].span, 16, "src {src}: the window stops at the call");
      assert_eq!(plan[7].role, PLAN_ROLE_LEADER, "src {src}");
      assert_eq!(plan[7].leader_pc, 7, "src {src}");
      assert_eq!(plan[8].role, PLAN_ROLE_MEMBER, "src {src}");
    }
  }

  /// A group of one is no group at all.
  #[test]
  fn a_lone_access_is_not_a_group() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([slot(LDXDW, 2, 1, 0, 0), slot(EBPF_OP_EXIT, 0, 0, 0, 0)]);
    assert_eq!(plan_of(&flatten(&slots))[2], PlanEntry::default());
  }

  /// `hints` and `plan` are always as long as the whole program's slot count,
  /// including on the early-return path, because the backend indexes both by
  /// absolute PC.
  #[test]
  fn hints_and_plan_always_cover_every_slot() {
    let code = flatten(&[
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let slots = code.len() / 8;
    let layout = crate::function_analysis::FunctionLayout::unmasked(slots);
    for (start, end) in [(0, slots), (1, 2), (2, 2), (1, 0), (0, slots + 1)] {
      let r = analyze_function(
        &code,
        start,
        end,
        PointerSignature::entry(),
        DATA_LO,
        DATA_HI,
        &layout,
        crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
      );
      assert_eq!(r.hints.len(), slots, "[{start}, {end})");
      assert_eq!(r.plan.len(), slots, "[{start}, {end})");
    }
  }

  /// The plan is built over `[start_pc, end_pc)` only: no entry is written
  /// outside the function the backend is about to translate.
  #[test]
  fn the_plan_is_confined_to_the_function_being_analyzed() {
    let code = flatten(&[
      slot(LDXDW, 2, 1, 0, 0), // another function's body
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(LDXDW, 2, 1, 0, 0), // the function under analysis
      slot(LDXDW, 3, 1, 8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let slots = code.len() / 8;
    let plan = analyze_function(
      &code,
      3,
      slots,
      PointerSignature::entry(),
      DATA_LO,
      DATA_HI,
      &crate::function_analysis::FunctionLayout::unmasked(slots),
      crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
    )
    .plan;
    assert_eq!(plan[0], PlanEntry::default());
    assert_eq!(plan[1], PlanEntry::default());
    assert_eq!(plan[3].role, PLAN_ROLE_LEADER);
    assert_eq!(plan[3].leader_pc, 3);
    assert_eq!(plan[4].role, PLAN_ROLE_MEMBER);
  }

  /// An access whose destination is its own base ends the group after it, but
  /// is itself still a valid member.
  #[test]
  fn a_load_into_its_own_base_ends_the_group_after_it() {
    let mut slots = base_off_frame().to_vec();
    slots.extend([
      slot(LDXDW, 2, 1, 0, 0),
      slot(LDXDW, 1, 1, 8, 0), // r1 = *(u64 *)(r1 + 8)
      slot(LDXDW, 3, 1, 16, 0),
      slot(LDXDW, 4, 1, 24, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let plan = plan_of(&flatten(&slots));
    assert_eq!(plan[2].role, PLAN_ROLE_LEADER);
    assert_eq!(
      entry(&plan[3]),
      (PLAN_ROLE_MEMBER, REGION_STACK, 8, 16, 0, 2)
    );
    assert_eq!(
      plan[4].role, PLAN_ROLE_LEADER,
      "a fresh group off the new r1"
    );
    assert_eq!(plan[4].leader_pc, 4);
    assert_eq!(plan[5].role, PLAN_ROLE_MEMBER);
  }

  /// The frame hint's one unverifiable claim is that `R10` still holds the
  /// frame pointer. The loader refuses every assignment to it, but the analysis
  /// checks rather than assumes - so an assignment must suppress the hint.
  #[test]
  fn an_assignment_to_r10_suppresses_the_frame_hint() {
    // `r10 = r1` (the ctx: a stack pointer, but not this frame's base).
    let code = flatten(&[
      slot(MOV64_REG, 10, 1, 0, 0),
      slot(LDXDW, 0, 10, -8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(analyze_fn(&code).hints[1], REGION_STACK);

    // `r10 = <data>` - not even a stack pointer any more.
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 10, 0, 0, DATA_LO as i32),
      slot(0, 0, 0, 0, 0),
      slot(LDXDW, 0, 10, -8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(analyze_fn(&code).hints[2], REGION_DATA);

    // A fetching atomic writes its source, so `r10` as a source kills it too.
    let code = flatten(&[
      slot(ATOMIC_DW, 1, 10, 0, 1),
      slot(LDXDW, 0, 10, -8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(analyze_fn(&code).hints[1], REGION_UNKNOWN);
  }

  /// The hint is decided from the state *entering* the access, not the state
  /// leaving it. `ldx r10, [r10 - 8]` is the sharp case: R10 is the frame
  /// pointer when the address is formed and something else immediately after,
  /// so the two states disagree and only the entering one is right.
  ///
  /// (The loader refuses this instruction; it is here because it is the only
  /// shape that tells the two readings apart.)
  #[test]
  fn the_frame_hint_reads_the_state_entering_the_access() {
    let code = flatten(&[
      slot(LDXDW, 10, 10, -8, 0),
      slot(LDXDW, 0, 10, -8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze_fn(&code).hints;
    // Entering slot 0, R10 is still the frame pointer.
    assert_eq!(hints[0], REGION_FRAME);
    // Leaving it, R10 holds a value read out of guest memory, so the next
    // access through it is not a frame access at all.
    assert_eq!(hints[1], REGION_UNKNOWN);
  }

  /// `R10` displaced and restored is still the frame pointer, and the offset
  /// tracking is what says so - the hint follows the tracked displacement, not
  /// the mere fact that the register is `R10`.
  #[test]
  fn the_frame_hint_follows_r10s_tracked_displacement() {
    let code = flatten(&[
      slot(ADD64_IMM, 10, 0, 0, -8),
      slot(LDXDW, 0, 10, -8, 0), // r10 is displaced here: no frame hint
      slot(ADD64_IMM, 10, 0, 0, 8),
      slot(LDXDW, 1, 10, -8, 0), // restored: frame hint again
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze_fn(&code).hints;
    assert_eq!(hints[1], REGION_STACK);
    assert_eq!(hints[3], REGION_FRAME);
  }

  /// A join that cannot agree on `R10` suppresses the hint on the merged path.
  #[test]
  fn a_join_that_loses_r10_suppresses_the_frame_hint() {
    let code = flatten(&[
      slot(JEQ_IMM, 0, 0, 1, 0),      // -> slot 2
      slot(ADD64_IMM, 10, 0, 0, -16), // only on the fall-through
      slot(LDXDW, 0, 10, -8, 0),      // join: r10 is Current(None)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(analyze_fn(&code).hints[2], REGION_STACK);
  }

  /// The hint is for `R10` itself, never a register derived from it: a copy
  /// holds a guest address at run time, so its displacement is not a native one.
  #[test]
  fn a_copy_of_r10_does_not_get_the_frame_hint() {
    let code = flatten(&[
      slot(MOV64_REG, 1, 10, 0, 0),
      slot(LDXDW, 0, 1, -8, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(analyze_fn(&code).hints[1], REGION_STACK);
  }

  /// A local callee's `R10` is its own frame pointer, not the caller's, so the
  /// frame hint has to be re-established from the callee's entry.
  #[test]
  fn a_callees_frame_hint_is_its_own() {
    let code = flatten(&[
      slot(EBPF_OP_CALL, 0, 1, 0, 1), // -> slot 2
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(LDXDW, 0, 10, -8, 0), // callee
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let slots = code.len() / 8;
    let layout = crate::function_analysis::FunctionLayout::unmasked(slots);
    // Whatever signature the caller hands over, `apply_to_state` pins R10.
    let mut regs = [RegKind::Unknown; NUM_REGS];
    regs[R10] = RegKind::Unknown;
    let r = analyze_function(
      &code,
      2,
      slots,
      PointerSignature { regs },
      DATA_LO,
      DATA_HI,
      &layout,
      crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
    );
    assert_eq!(r.hints[2], REGION_FRAME);
  }

  /// Every register an instruction can overwrite has to end a group based on
  /// it. This walks the forms the backend's own mask lists.
  #[test]
  fn written_registers_covers_every_writing_form() {
    let cases: [(&str, [u8; 8], &[usize]); 9] = [
      ("lddw", slot(EBPF_OP_LDDW, 4, 0, 0, 0), &[4]),
      ("ldxdw", slot(LDXDW, 4, 1, 0, 0), &[4]),
      ("alu64 add", slot(ADD64_IMM, 4, 0, 0, 1), &[4]),
      (
        "alu32 mov",
        slot(EBPF_CLS_ALU | EBPF_ALU_OP_MOV, 4, 0, 0, 1),
        &[4],
      ),
      ("byteswap le", slot(EBPF_CLS_ALU | 0xd0, 4, 0, 0, 64), &[4]),
      ("bswap64", slot(EBPF_CLS_ALU64 | 0xd0, 4, 0, 0, 64), &[4]),
      ("atomic fetch", slot(ATOMIC_DW, 1, 4, 0, 1), &[4, 0]),
      (
        "call helper",
        slot(EBPF_OP_CALL, 0, 0, 0, 1),
        &[0, 1, 2, 3, 4, 5],
      ),
      (
        "call local",
        slot(EBPF_OP_CALL, 0, 1, 0, 1),
        &[0, 1, 2, 3, 4, 5],
      ),
    ];
    for (name, s, want) in cases {
      let got = written_registers(&decode(&s));
      for reg in want {
        assert!(got.contains(reg), "{name}: expected r{reg} in {got:?}");
      }
    }
    // Plain stores write nothing.
    for s in [slot(STDW, 1, 0, 0, 0), slot(STXDW, 1, 2, 0, 0)] {
      assert!(written_registers(&decode(&s)).is_empty());
    }
  }

  #[test]
  fn a_register_read_before_it_is_written_is_live_in() {
    let code = flatten(&[
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0), // r0 = *(u64*)(r6)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(live_in(&code, 0), 1 << 6);
  }

  #[test]
  fn a_register_overwritten_before_every_read_is_not_live_in() {
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_MOV, 6, 0, 0, 0), // r6 = 0
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0),              // r0 = *(u64*)(r6)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(live_in(&code, 0), 0);
  }

  #[test]
  fn a_register_a_previous_call_clobbered_is_not_live_in() {
    // The load reads R1, but the local call ahead of it leaves R0-R5 clobbered,
    // so the caller's incoming R1 can never reach it. The callee here reads
    // nothing.
    let code = flatten(&[
      slot(EBPF_OP_CALL, 0, 1, 0, 2),        // call -> slot 3
      slot(EBPF_CLS_LDX | 0x18, 0, 1, 0, 0), // r0 = *(u64*)(r1)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0), // callee
    ]);
    assert_eq!(function_live_in(&code, 0, 3, &|_| 0), 0);
  }

  #[test]
  fn a_call_contributes_whatever_its_callee_reads() {
    let code = flatten(&[
      slot(EBPF_OP_CALL, 0, 1, 0, 1), // call -> slot 2
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0), // callee, reported as reading r7
    ]);
    assert_eq!(function_live_in(&code, 0, 2, &|_| 1 << 7), 1 << 7);
  }

  #[test]
  fn a_cross_section_call_conservatively_reads_signature_registers() {
    let code = flatten(&[
      slot(EBPF_OP_CALL, 0, 2, 0, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(
      function_live_in(&code, 0, 2, &|_| ALL_SIGNATURE_REGS),
      ALL_SIGNATURE_REGS
    );
  }

  /// The all-slots fixpoint sweep [`function_live_in`] used before the
  /// worklist, kept verbatim so the two can be proven to agree bit for bit.
  fn sweep_live_in(
    code: &[u8],
    start_pc: usize,
    end_pc: usize,
    callee_live_in: &dyn Fn(CallSite) -> RegMask,
  ) -> RegMask {
    let num_slots = code.len() / 8;
    if start_pc >= end_pc || end_pc > num_slots {
      return ALL_SIGNATURE_REGS;
    }
    let insns = decode_section(code);
    let mut reachable = vec![false; num_slots];
    let mut pending = vec![start_pc];
    reachable[start_pc] = true;
    while let Some(pc) = pending.pop() {
      for succ in successors_of(&insns, pc, start_pc, end_pc) {
        if !reachable[succ] {
          reachable[succ] = true;
          pending.push(succ);
        }
      }
    }
    let mut live = vec![0 as RegMask; num_slots];
    loop {
      let mut changed = false;
      for pc in (start_pc..end_pc).rev() {
        if !reachable[pc] {
          continue;
        }
        let inst = insns[pc];
        let mut live_out = 0;
        for succ in successors_of(&insns, pc, start_pc, end_pc) {
          live_out |= live[succ];
        }
        let callee = if inst.opcode == EBPF_OP_CALL {
          match inst.src {
            1 => callee_live_in(CallSite::Local {
              target_pc: (pc as i64 + 1 + inst.imm as i64) as usize,
            }),
            2 => callee_live_in(CallSite::CrossSection { call_pc: pc }),
            _ => 0,
          }
        } else {
          0
        };
        let (uses, defs) = core::uses_and_defs(&inst, callee);
        let next = uses | (live_out & !defs);
        if next != live[pc] {
          live[pc] = next;
          changed = true;
        }
      }
      if !changed {
        break;
      }
    }
    live[start_pc]
  }

  #[test]
  fn worklist_live_in_is_bit_identical_to_the_sweep() {
    // The masks are precision-only inputs to per-signature specialization, so
    // a single bit of difference would change which variants the loader
    // builds. Exercise the hostile ladder shape the sweep was quadratic on,
    // plus a deterministic spread of random fragments (any bytes are safe:
    // decode, successors and uses_and_defs are total).
    fn ladder(n: usize) -> Vec<u8> {
      let mut code = Vec::with_capacity((n + 2) * 8);
      let mut pc = 0;
      while pc + 3 <= n {
        code.extend_from_slice(&slot(EBPF_OP_JA, 0, 0, 1, 0)); // ja +1
        code.extend_from_slice(&slot(EBPF_OP_JA, 0, 0, 1, 0)); // ja +1
        code.extend_from_slice(&slot(EBPF_OP_JA, 0, 0, -2, 0)); // ja -2
        pc += 3;
      }
      while pc < n {
        code.extend_from_slice(&slot(EBPF_OP_JA, 0, 0, 1, 0));
        pc += 1;
      }
      // A register use after the ladder makes every live bit cross every
      // backward edge on the way to the entry. Register form (`| EBPF_SRC_REG`),
      // so the source nibble is the read register.
      code.extend_from_slice(&slot(
        EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_ADD,
        0,
        6,
        0,
        0,
      ));
      code.extend_from_slice(&slot(EBPF_OP_EXIT, 0, 0, 0, 0));
      code
    }

    for n in [2usize, 3, 7, 64, 1000, 4096] {
      let code = ladder(n);
      assert_eq!(
        function_live_in(&code, 0, code.len() / 8, &|_| 0),
        sweep_live_in(&code, 0, code.len() / 8, &|_| 0),
        "worklist diverged from the sweep on the {n}-slot ladder"
      );
    }

    // A small deterministic PRNG so the spread is identical on every host.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next_u8 = move || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      (state >> 32) as u8
    };
    for _ in 0..1000 {
      let n = (next_u8() as usize % 60) + 1;
      let mut code = Vec::with_capacity(n * 8);
      for _ in 0..n * 8 {
        code.push(next_u8());
      }
      assert_eq!(
        function_live_in(&code, 0, n, &|_| 0),
        sweep_live_in(&code, 0, n, &|_| 0),
        "worklist diverged from the sweep on a random {n}-slot fragment"
      );
    }
  }

  /// Naive whole-program Kleene iteration over the same equations
  /// [`program_live_in`] solves: recompute every function from the current
  /// summaries until nothing moves. No worklist, no predecessor index, no
  /// caller index, no global-id arithmetic - it shares none of the machinery
  /// the real solver's speed depends on, which is what makes it worth
  /// comparing against.
  fn sweep_program_live_in(
    sections: &[LiveInSection<'_>],
    cross_section_calls: &[CrossSectionCallSite],
  ) -> Vec<Vec<RegMask>> {
    let mut masks: Vec<Vec<RegMask>> = sections
      .iter()
      .map(|section| vec![0 as RegMask; section.starts.len()])
      .collect();
    loop {
      let snapshot = masks.clone();
      for (si, section) in sections.iter().enumerate() {
        let num_slots = section.code.len() / 8;
        for fi in 0..section.starts.len() {
          let start = section.starts[fi];
          let end = section.starts.get(fi + 1).copied().unwrap_or(num_slots);
          masks[si][fi] = function_live_in(section.code, start, end, &|site| match site {
            CallSite::Local { target_pc } => section
              .pc_to_func
              .get(target_pc)
              .and_then(|&callee| snapshot[si].get(callee).copied())
              .unwrap_or(ALL_SIGNATURE_REGS),
            CallSite::CrossSection { call_pc } => cross_section_calls
              .iter()
              .find(|call| call.caller_section == si && call.call_pc == call_pc)
              .map(|call| snapshot[call.callee_section][call.callee_function])
              .unwrap_or(ALL_SIGNATURE_REGS),
          });
        }
      }
      if masks == snapshot {
        return masks;
      }
    }
  }

  /// The flat whole-program solver must agree with the per-function one, bit
  /// for bit, on every program.
  ///
  /// [`program_live_in`] flattens two nested fixed points into one worklist to
  /// escape a quadratic; this pins that the flattening did not also change the
  /// answer. The bytes are random from a structured alphabet rather than valid
  /// eBPF: both solvers decode the same bytes the same way, so anything that
  /// decodes exercises the equations, and the odd shapes a fuzzer finds are
  /// exactly the ones hand-written cases miss.
  #[test]
  fn program_live_in_agrees_with_the_per_function_solver() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state
    };
    let mut below = |n: u64| next() % n;

    let mut with_cross_calls = 0usize;
    for _ in 0..3000 {
      let section_count = 1 + below(3) as usize;
      let mut codes: Vec<Vec<u8>> = Vec::new();
      let mut starts: Vec<Vec<usize>> = Vec::new();
      let mut pc_to_func: Vec<Vec<usize>> = Vec::new();
      for _ in 0..section_count {
        let num_slots = 1 + below(12) as usize;
        let mut code = Vec::new();
        for _ in 0..num_slots {
          let dst = below(11) as u8;
          let src = below(11) as u8;
          let offset = below(9) as i16 - 4;
          let imm = below(9) as i32 - 4;
          let opcode = match below(9) {
            0 => EBPF_OP_EXIT,
            1 => EBPF_OP_CALL,
            2 => EBPF_OP_CALL,
            3 => EBPF_OP_JA,
            4 => EBPF_OP_JA32,
            5 => EBPF_CLS_JMP | 0x50, // jset, a conditional
            6 => EBPF_OP_LDDW,
            7 => EBPF_CLS_LDX | 0x18,
            _ => EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_ADD,
          };
          code.extend_from_slice(&slot(opcode, dst, src, offset, imm));
        }
        // Any strictly ascending set containing 0 is a legal partition; the
        // loader derives one from call targets, but the solvers take it as
        // given, so exercise arbitrary ones.
        let mut section_starts = vec![0usize];
        for pc in 1..num_slots {
          if below(3) == 0 {
            section_starts.push(pc);
          }
        }
        let mut owner = vec![0usize; num_slots];
        for (fi, &start) in section_starts.iter().enumerate() {
          let end = section_starts.get(fi + 1).copied().unwrap_or(num_slots);
          owner[start..end].fill(fi);
        }
        codes.push(code);
        starts.push(section_starts);
        pc_to_func.push(owner);
      }

      // At most one edge per call site: the solvers disagree on which of two
      // edges at one site wins, and the loader refuses that object anyway
      // ("more than one cross-section relocation targets call PC").
      let mut cross_section_calls: Vec<CrossSectionCallSite> = Vec::new();
      for caller_section in 0..section_count {
        for call_pc in 0..codes[caller_section].len() / 8 {
          if below(4) != 0 {
            continue;
          }
          let callee_section = below(section_count as u64) as usize;
          let callee_function = below(starts[callee_section].len() as u64) as usize;
          cross_section_calls.push(CrossSectionCallSite {
            caller_section,
            call_pc,
            callee_section,
            callee_function,
          });
        }
      }
      if !cross_section_calls.is_empty() {
        with_cross_calls += 1;
      }

      let sections = (0..section_count)
        .map(|si| LiveInSection {
          code: &codes[si],
          starts: &starts[si],
          pc_to_func: &pc_to_func[si],
        })
        .collect::<Vec<_>>();

      assert_eq!(
        program_live_in(&sections, &cross_section_calls).masks,
        sweep_program_live_in(&sections, &cross_section_calls),
        "flat solver diverged from the per-function sweep on {codes:?} \
         starts {starts:?} cross calls {cross_section_calls:?}"
      );
    }
    assert!(
      with_cross_calls > 1000,
      "only {with_cross_calls} generated programs had a cross-section call"
    );
  }

  /// Successor slots in the whole-program CFG, in which a local call also enters
  /// its callee. Slot indices, not byte offsets.
  ///
  /// Nothing treats the program as one CFG any more; this is the reference
  /// `function_successors_agree_with_composing_the_whole_program_walk`
  /// composes with the function filter.
  fn whole_program_successors(pc: usize, inst: &Inst, num_slots: usize) -> Vec<usize> {
    let fallthrough = if inst.opcode == EBPF_OP_LDDW {
      pc + 2
    } else {
      pc + 1
    };
    let cls = inst.opcode & EBPF_CLS_MASK;
    let mut out = Vec::new();
    let mut push = |s: usize| {
      if s < num_slots {
        out.push(s);
      }
    };

    if cls == EBPF_CLS_JMP || cls == EBPF_CLS_JMP32 {
      if inst.opcode == EBPF_OP_EXIT {
        return out;
      }
      if inst.opcode == EBPF_OP_CALL {
        match inst.src {
          // Helper call: returns to the next instruction.
          0 => push(fallthrough),
          // Local eBPF call: returns to the next instruction and also enters the
          // callee at pc+imm+1. The callee inherits the (clobbered) caller state,
          // which preserves R10=Stack and the callee-saved R6-R9, so callee
          // stack accesses remain analyzable; arg-derived accesses (R1-R5, now
          // Unknown) are conservatively unresolved.
          1 => {
            push(fallthrough);
            push((pc as i64 + 1 + inst.imm as i64) as usize);
          }
          // A linker-tagged cross-section local call returns here but its callee
          // is represented outside this section's CFG.
          2 => push(fallthrough),
          // Other forms branch to exit; no fallthrough.
          _ => {}
        }
        return out;
      }
      // JA32 is the only jump whose target is the 32-bit imm; every other jump
      // (JA and all conditional JMP/JMP32 forms) uses the 16-bit offset. This
      // matches how the JIT/linker resolve branch targets.
      let target = if inst.opcode == EBPF_OP_JA32 {
        pc as i64 + 1 + inst.imm as i64
      } else {
        pc as i64 + 1 + inst.offset as i64
      } as usize;
      push(target);
      if inst.opcode != EBPF_OP_JA && inst.opcode != EBPF_OP_JA32 {
        push(fallthrough); // conditional branch also falls through
      }
      return out;
    }

    push(fallthrough);
    out
  }

  /// `verified::fixpoint::function_successors` must agree with composing the
  /// whole-program `successors` the way the per-function walk used to:
  /// override a local call's edges with its fallthrough, then keep only what
  /// lands in `[start_pc, end_pc)`.
  ///
  /// The randomized differential above cannot see this. Its reference,
  /// `sweep_program_live_in`, reaches the same successor function the solver
  /// and the region analysis use, so a successor bug appears identically on
  /// both sides and cancels. That blindness is real: a mutation giving `call`
  /// with `src == 3` a fallthrough edge passes the whole suite without this
  /// test.
  #[test]
  fn function_successors_agree_with_composing_the_whole_program_walk() {
    fn expected(
      pc: usize,
      inst: &Inst,
      num_slots: usize,
      start_pc: usize,
      end_pc: usize,
    ) -> Vec<usize> {
      let mut succs = whole_program_successors(pc, inst, num_slots);
      // A local callee is a separate function, so the call contributes only
      // its return edge.
      if inst.opcode == EBPF_OP_CALL && inst.src == 1 {
        succs.clear();
        if pc + 1 < num_slots {
          succs.push(pc + 1);
        }
      }
      succs.retain(|&succ| succ >= start_pc && succ < end_pc);
      succs
    }

    let offsets = [i16::MIN, -3, -1, 0, 1, 2, i16::MAX];
    let imms = [i32::MIN, -4, -1, 0, 1, 3, i32::MAX];
    let ranges = [(1, 0, 1), (4, 0, 4), (6, 2, 5), (8, 3, 4), (9, 0, 9)];
    let mut cases = 0usize;
    for opcode in 0..=255u8 {
      for src in 0..16u8 {
        for &offset in &offsets {
          for &imm in &imms {
            for &(num_slots, start_pc, end_pc) in &ranges {
              let raw = slot(opcode, 0, src, offset, imm);
              let inst = decode(&raw);
              let insns = vec![Insn::from_u64(u64::from_le_bytes(raw)); num_slots];
              for pc in start_pc..end_pc {
                let got: Vec<usize> = successors_of(&insns, pc, start_pc, end_pc).collect();
                assert_eq!(
                  got,
                  expected(pc, &inst, num_slots, start_pc, end_pc),
                  "opcode {opcode:#04x} src {src} offset {offset} imm {imm} \
                   pc {pc} in [{start_pc}, {end_pc}) of {num_slots}"
                );
                cases += 1;
              }
            }
          }
        }
      }
    }
    assert!(cases > 1_000_000, "only {cases} cases");
  }

  /// A `starts` array that does not partition its section takes the
  /// conservative bail rather than being walked.
  #[test]
  fn a_starts_array_that_does_not_partition_takes_the_conservative_bail() {
    let code = flatten(&[
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0), // r0 = *(u64*)(r6)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    // Not ascending, does not begin at 0, and out of range: each on its own
    // must be refused.
    for starts in [&[1usize, 0][..], &[1][..], &[0, 2][..]] {
      let sections = [LiveInSection {
        code: &code,
        starts,
        pc_to_func: &[0, 0],
      }];
      assert_eq!(
        program_live_in(&sections, &[]).masks,
        vec![vec![ALL_SIGNATURE_REGS; starts.len()]],
        "starts {starts:?} was not refused"
      );
    }
  }

  /// A cross-section call site outside the section it is attributed to must be
  /// dropped, not folded into whichever section its global slot id lands in.
  ///
  /// Slot ids are assigned per section and concatenated, so they are injective
  /// only while every `call_pc` is inside its own section. An out-of-range one
  /// aliases a real slot in a later section and rebinds *that* slot's callee,
  /// which narrows a mask - the unsafe direction, since a callee would then be
  /// specialized on fewer registers than it can observe.
  #[test]
  fn a_cross_section_call_outside_its_own_section_is_dropped() {
    let first = flatten(&[slot(EBPF_OP_EXIT, 0, 0, 0, 0)]);
    let second = flatten(&[
      slot(EBPF_OP_CALL, 0, 2, 0, 0), // no edge names this one
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let sections = [
      LiveInSection {
        code: &first,
        starts: &[0],
        pc_to_func: &[0],
      },
      LiveInSection {
        code: &second,
        starts: &[0],
        pc_to_func: &[0, 0],
      },
    ];
    // `call_pc: 1` does not exist in section 0, which has one slot. Its global
    // id is section 1's slot 0 - the untagged call above.
    let stray = [CrossSectionCallSite {
      caller_section: 0,
      call_pc: 1,
      callee_section: 0,
      callee_function: 0,
    }];

    assert_eq!(
      program_live_in(&sections, &stray).masks,
      vec![vec![0], vec![ALL_SIGNATURE_REGS]],
      "a stray call site rebound an unrelated section's call"
    );
  }

  /// A `pc_to_func` entry naming no function of its section takes the
  /// conservative bail the guard block promises, rather than panicking in
  /// `bounds` or silently naming a function in the next section.
  #[test]
  fn a_pc_to_func_entry_outside_its_section_takes_the_conservative_bail() {
    let code = flatten(&[
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0), // r0 = *(u64*)(r6)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let sections = [LiveInSection {
      code: &code,
      starts: &[0],
      pc_to_func: &[0, 7],
    }];

    assert_eq!(
      program_live_in(&sections, &[]).masks,
      vec![vec![ALL_SIGNATURE_REGS]]
    );
  }

  #[test]
  fn exit_does_not_make_r0_live_in() {
    // A function that returns without assigning R0 hands its caller's R0 back,
    // but the caller models any call's result as a fresh scalar - so the
    // incoming kind is not observable and must not force a specialization.
    // Counting R0 here would put it in the mask of nearly every function.
    let code = flatten(&[slot(EBPF_OP_EXIT, 0, 0, 0, 0)]);
    assert_eq!(live_in(&code, 0), 0);
  }

  #[test]
  fn a_dead_read_does_not_make_a_register_live_in() {
    // The load is unreachable, so no execution can observe r6.
    let code = flatten(&[
      slot(EBPF_OP_JA, 0, 0, 1, 0),          // goto slot 2
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0), // r0 = *(u64*)(r6)  (dead)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(live_in(&code, 0), 0);
  }

  #[test]
  fn a_read_on_either_branch_makes_a_register_live_in() {
    let code = flatten(&[
      slot(EBPF_CLS_JMP | 0x50, 0, 0, 1, 0), // jset r0, 0 -> slot 2
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(EBPF_CLS_LDX | 0x18, 0, 8, 0, 0), // r0 = *(u64*)(r8)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(live_in(&code, 0), 1 << 8 | 1);
  }

  #[test]
  fn stack_load_via_r10_is_routed_to_stack() {
    // r2 = r10; r2 += -8; r0 = *(u64*)(r2 + 0); exit
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 2, 10, 0, 0),
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 2, 0, 0, -8),
      slot(EBPF_CLS_LDX | 0x18, 0, 2, 0, 0), // LDXDW
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[2], REGION_STACK);
  }

  #[test]
  fn ctx_load_via_r1_is_routed_to_stack() {
    // r0 = *(u64*)(r1 + 0); exit  -- r1 is the ctx (calldata on the stack)
    let code = flatten(&[
      slot(EBPF_CLS_LDX | 0x18, 0, 1, 0, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[0], REGION_STACK);
  }

  #[test]
  fn data_pointer_load_is_routed_to_data() {
    // r1 = <data addr> (lddw, 2 slots); r0 = *(u8*)(r1 + 0); exit
    let addr = (DATA_LO + 0x40) as i32;
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 1, 0, 0, addr),
      slot(0, 0, 0, 0, 0),                   // lddw high half
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0), // LDXB
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[2], REGION_DATA);
  }

  #[test]
  fn loaded_pointer_is_unknown() {
    // r2 = *(u64*)(r10 - 8); r0 = *(u64*)(r2 + 0); exit
    // r2 comes from memory, so the second load cannot be classified.
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 2, 10, 0, 0),
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 2, 0, 0, -8),
      slot(EBPF_CLS_LDX | 0x18, 2, 2, 0, 0),
      slot(EBPF_CLS_LDX | 0x18, 0, 2, 0, 0),
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[3], REGION_UNKNOWN);
  }

  #[test]
  fn ambiguous_join_is_unknown() {
    // if (r1 == 0) goto +2
    //   r2 = r10           (stack)
    //   goto +1
    // r2 = <data addr lddw low only via mov imm? use lddw>  -> here mimic data
    // We construct: r2 = r10 on one path, r2 stays data on the other, then load.
    // Path A: slot0 cond jump to slot3; slot1 r2=r10; slot2 ja to slot5(load)...
    // Simpler: two predecessors of the load with different kinds.
    let code = flatten(&[
      // 0: if r1 == 0 goto +3 (to slot 4)
      slot(EBPF_CLS_JMP | 0x10, 1, 0, 3, 0), // JEQ_IMM
      // 1: r2 = r10  (stack)
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 2, 10, 0, 0),
      // 2: goto +2 (to slot 5)
      slot(EBPF_OP_JA, 0, 0, 2, 0),
      // 3: padding (unreachable)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      // 4: r2 = 12345 (scalar)
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_MOV, 2, 0, 0, 12345),
      // 5: r0 = *(u64*)(r2 + 0)  -- r2 is Stack on one path, Scalar on the other
      slot(EBPF_CLS_LDX | 0x18, 0, 2, 0, 0),
      // 6: exit
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[5], REGION_UNKNOWN);
  }

  #[test]
  fn spilled_arg_pointer_is_recovered_via_fill() {
    // The -O2 BPF backend spills the argument pointer (R1, ctx => stack) to a
    // stack slot and reloads it before dereferencing:
    //   *(u64*)(r10 - 8) = r1
    //   r1 = *(u64*)(r10 - 8)
    //   r0 = *(u64*)(r1 + 0)
    //   exit
    let code = flatten(&[
      slot(EBPF_CLS_STX | 0x18, 10, 1, -8, 0), // spill r1
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0), // fill r1
      slot(EBPF_CLS_LDX | 0x18, 0, 1, 0, 0),   // deref
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[2], REGION_STACK);
    assert!(result.unresolved.is_empty());
  }

  #[test]
  fn data_pointer_indexed_by_loaded_value_stays_data() {
    // Mirrors the unrolled `zs_strcmp` tail `literal[i]`, where `i` was derived
    // from a byte loaded out of a stack buffer. The loaded value is a scalar
    // index, so `data_ptr + i` must remain routable to the data region.
    let addr = DATA_LO as i32;
    let code = flatten(&[
      slot(EBPF_CLS_LDX | 0x10, 3, 10, -16, 0), // r3 = *(u8*)(r10-16)  [index from stack data]
      slot(EBPF_OP_LDDW, 1, 0, 0, addr),        // r1 = <data literal>
      slot(0, 0, 0, 0, 0),                      // lddw high half
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_ADD, 1, 3, 0, 0), // r1 += r3
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0),    // r0 = *(u8*)(r1)  [literal[i]]
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[4], REGION_DATA);
    assert!(result.unresolved.is_empty());
  }

  #[test]
  fn call_return_used_as_index_keeps_pointer_region() {
    // Mirrors `bp += len; *bp = ...` where `len` is a helper return value. The
    // return is a scalar index, so the store through `stack_ptr + len` stays
    // routable to the stack.
    let code = flatten(&[
      slot(EBPF_OP_CALL, 0, 0, 0, 1), // r0 = helper()  -> scalar
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_ADD, 6, 0, 0, 0), // r6 += r0
      slot(EBPF_CLS_STX | 0x10, 6, 1, 0, 0), // *(u8*)(r6) = r1
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn stack_byte_read_after_call_indexes_data_pointer() {
    // Mirrors the inlined `zs_strcmp(buf, literal)` tail where `buf` was filled
    // by a helper: a byte is loaded from a stack slot after the call and used as
    // the index into the literal. A scalar stack spill must still read back as a
    // scalar, keeping `literal[i]` routable to data.
    let code = flatten(&[
      slot(EBPF_CLS_STX | 0x10, 10, 6, -32, 0), // *(u8*)(r10-32) = r6  (spill a scalar)
      slot(EBPF_OP_CALL, 0, 0, 0, 1),           // call helper
      slot(EBPF_CLS_LDX | 0x10, 2, 10, -32, 0), // r2 = *(u8*)(r10-32)  [byte index]
      slot(EBPF_OP_LDDW, 1, 0, 0, DATA_LO as i32), // r1 = <data literal>
      slot(0, 0, 0, 0, 0),                      // lddw high half
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_ADD, 1, 2, 0, 0), // r1 += r2
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0),    // r0 = *(u8*)(r1)  [literal[i]]
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[6], REGION_DATA);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn spilled_stack_pointer_survives_helper_call() {
    // Mirrors generated Caddy middleware: a stack buffer pointer is spilled,
    // helper calls run, then the pointer is reloaded for later host matching.
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 6, 0, 0, -64),               // r6 = &stack_buf
      slot(EBPF_CLS_STX | 0x18, 10, 6, -8, 0),                            // spill stack pointer
      slot(EBPF_OP_CALL, 0, 0, 0, 1),                                     // helper call
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0),                            // reload stack pointer
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0), // dereference stack buffer
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[5], REGION_STACK);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn spilled_stack_pointer_survives_stack_alias_store() {
    // A write through `r7 = r10 - 64` is a stack-buffer write. It should not
    // erase an unrelated pointer spill that later reloads the same stack buffer
    // pointer.
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 6, 0, 0, -64),               // r6 = &stack_buf
      slot(EBPF_CLS_STX | 0x18, 10, 6, -8, 0),                            // spill stack pointer
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 7, 10, 0, 0), // r7 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 7, 0, 0, -64),               // r7 = &stack_buf
      slot(EBPF_CLS_ST | 0x10, 7, 0, 0, 1),                               // *(u8*)r7 = 1
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0),                            // reload stack pointer
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0), // dereference stack buffer
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[7], REGION_STACK);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn stack_alias_store_invalidates_overlapping_pointer_spill() {
    // The write through `r7 = r10 - 8` overlaps the tracked spill at `r10 - 8`,
    // so reloading that slot must not recover the stale stack pointer.
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 6, 0, 0, -64),               // r6 = &stack_buf
      slot(EBPF_CLS_STX | 0x18, 10, 6, -8, 0),                            // spill stack pointer
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 7, 10, 0, 0), // r7 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 7, 0, 0, -8),                // r7 = &spill
      slot(EBPF_CLS_ST | 0x18, 7, 0, 0, 0),                               // overwrite spill
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0),                            // reload overwritten slot
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0), // stale deref must be unresolved
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[7], REGION_UNKNOWN);
    assert_eq!(result.unresolved, vec![7]);
  }

  #[test]
  fn direct_partial_stack_store_invalidates_pointer_spill() {
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 6, 0, 0, -64),               // r6 = &stack_buf
      slot(EBPF_CLS_STX | 0x18, 10, 6, -8, 0),                            // spill stack pointer
      slot(EBPF_CLS_ST | 0x10, 10, 0, -7, 0), // partial overwrite of spill
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0), // reload overwritten slot
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0),  // stale deref must be unresolved
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[5], REGION_UNKNOWN);
    assert_eq!(result.unresolved, vec![5]);
  }

  #[test]
  fn known_stack_alias_store_updates_pointer_spill() {
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 6, 0, 0, -64),               // r6 = &stack_buf
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 7, 10, 0, 0), // r7 = r10
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 7, 0, 0, -8),                // r7 = &spill
      slot(EBPF_CLS_STX | 0x18, 7, 6, 0, 0),                              // spill through alias
      slot(EBPF_CLS_LDX | 0x18, 1, 10, -8, 0),                            // reload stack pointer
      slot(EBPF_CLS_LDX | 0x10, 0, 1, 0, 0), // dereference stack buffer
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[6], REGION_STACK);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn foreign_stack_store_does_not_invalidate_current_frame_spill() {
    let code = flatten(&[
      slot(EBPF_CLS_STX | 0x18, 10, 1, -8, 0), // spill foreign stack pointer
      slot(EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD, 1, 0, 0, 1), // r1 += 1
      slot(EBPF_CLS_ST | 0x10, 1, 0, 0, 0),    // write through foreign stack
      slot(EBPF_CLS_LDX | 0x18, 2, 10, -8, 0), // reload foreign stack pointer
      slot(EBPF_CLS_LDX | 0x10, 0, 2, 0, 0),   // dereference it
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let mut regs = [RegKind::Uninit; NUM_REGS];
    regs[1] = RegKind::Stack(StackKind::Foreign);
    regs[R10] = RegKind::Stack(StackKind::Current(Some(0)));
    let result = analyze_function(
      &code,
      0,
      code.len() / 8,
      PointerSignature { regs },
      DATA_LO,
      DATA_HI,
      &crate::function_analysis::FunctionLayout::unmasked(code.len() / 8),
      crate::jit::abi::LOCAL_FUNCTION_STACK_SIZE,
    );
    assert_eq!(result.hints[4], REGION_STACK);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn ja32_target_follows_imm_not_offset() {
    // JA32 jumps to pc+imm+1. Here imm routes control to the real load (r6 is a
    // stack pointer); the misleading offset=0 would fall onto a poison block
    // that reassigns r6 to a data pointer. The load must be classified from the
    // imm path (stack), not the offset path (data).
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 6, 10, 0, 0), // r6 = r10 (stack)
      slot(EBPF_OP_JA32, 0, 0, 0, 2), // goto slot 4 (pc+imm+1); offset=0 would target slot 2
      slot(EBPF_OP_LDDW, 6, 0, 0, DATA_LO as i32), // poison: r6 = <data> (only reached if offset is used)
      slot(0, 0, 0, 0, 0),                         // lddw high half
      slot(EBPF_CLS_LDX | 0x18, 0, 6, 0, 0),       // r0 = *(u64*)(r6)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let hints = analyze(&code, DATA_LO, DATA_HI).hints;
    assert_eq!(hints[4], REGION_STACK);
  }

  #[test]
  fn unresolved_lists_unclassifiable_accesses() {
    // A clean stack load (slot 1) is resolved; a load through a
    // loaded-from-memory pointer (slot 3) is not.
    let code = flatten(&[
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 2, 10, 0, 0),
      slot(EBPF_CLS_LDX | 0x18, 3, 2, 0, 0), // r3 = *(u64*)(r2)  [resolved: stack]
      slot(EBPF_CLS_ALU64 | EBPF_SRC_REG | EBPF_ALU_OP_MOV, 4, 3, 0, 0),
      slot(EBPF_CLS_LDX | 0x18, 0, 4, 0, 0), // r0 = *(u64*)(r4)  [unresolved]
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.unresolved, vec![3]);
  }

  /// `BPF_ATOMIC | CMPXCHG` writes the previous memory contents into R0, so a
  /// data pointer materialized there before the instruction must not survive it.
  #[test]
  fn atomic_cmpxchg_clobbers_r0() {
    const ATOMIC_DW: u8 = EBPF_CLS_STX | 0xc0 | 0x18;
    const CMPXCHG_FETCH: i32 = 0xf1;
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 0, 0, 0, DATA_LO as i32), // r0 = <data>
      slot(0, 0, 0, 0, 0),                         // lddw high half
      slot(ATOMIC_DW, 10, 2, -16, CMPXCHG_FETCH),  // r0 = old(*(u64*)(r10-16))
      slot(EBPF_CLS_LDX | 0x10, 1, 0, 0, 0),       // r1 = *(u8*)(r0)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[3], REGION_UNKNOWN);
    assert_eq!(result.unresolved, vec![3]);
  }

  /// The CMPXCHG rule is narrow: every other atomic writes only `src`, so an
  /// unrelated pointer register stays routable across it.
  #[test]
  fn atomic_fetch_add_leaves_r0_alone() {
    const ATOMIC_DW: u8 = EBPF_CLS_STX | 0xc0 | 0x18;
    const ADD_FETCH: i32 = 0x01;
    let code = flatten(&[
      slot(EBPF_OP_LDDW, 0, 0, 0, DATA_LO as i32),
      slot(0, 0, 0, 0, 0),
      slot(ATOMIC_DW, 10, 2, -16, ADD_FETCH), // r2 = old(...); r0 untouched
      slot(EBPF_CLS_LDX | 0x10, 1, 0, 0, 0),  // r1 = *(u8*)(r0)
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert_eq!(result.hints[3], REGION_DATA);
    assert!(
      result.unresolved.is_empty(),
      "unexpected unresolved: {:?}",
      result.unresolved
    );
  }

  #[test]
  fn unreachable_memory_accesses_are_not_unresolved() {
    let code = flatten(&[
      slot(EBPF_OP_EXIT, 0, 0, 0, 0),
      slot(EBPF_CLS_LDX | 0x18, 0, 4, 0, 0), // dead: r0 = *(u64*)(r4)
    ]);
    let result = analyze(&code, DATA_LO, DATA_HI);
    assert!(result.unresolved.is_empty());
  }
}

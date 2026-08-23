//! The eBPF JIT: validation, decoding, and native code generation.
//!
//! # Using it
//!
//! [`Translator::load`](crate::jit::Translator::load) validates a program once
//! and keeps the decoded instructions, the set of slots that begin local
//! functions, and the per-function stack usage.
//! [`Translator::translate_range`](crate::jit::Translator::translate_range) then
//! compiles a half-open instruction range into a caller-supplied buffer and
//! reports how many bytes it wrote. Ranges rather than whole programs, because
//! the runtime compiles one local function at a time, on first call, into an
//! arena it manages itself.
//!
//! Everything the analysis knows about a range beyond the bytecode — region
//! hints, the access plan, the lazy-call resolver ids — arrives through
//! [`TranslationInputs`](crate::jit::TranslationInputs) and is borrowed for
//! exactly that one call. Everything fixed for the life of the program — the
//! target, the pointer cage, the helper dispatcher — lives in
//! [`Config`](crate::jit::Config), which is built once and immutable afterwards.
//!
//! Translation is pure computation over a byte buffer: it allocates no
//! executable memory, patches nothing already running, and depends on the host
//! only through [`Config::target`](crate::jit::Config::target), which either
//! host can set to either value. Making the result runnable is the caller's job,
//! and on aarch64 that includes
//! [`clear_instruction_cache`](crate::jit::clear_instruction_cache).
//!
//! # Layout
//!
//! * [`isa`](crate::jit::isa) — the wire format and the one opcode decode.
//! * [`abi`](crate::jit::abi) — the frame contract shared with the entry
//!   trampoline.
//! * [`validate`](crate::jit::validate) — what `Translator::load` accepts.
//! * [`stack`](crate::jit::stack) — per-local-function stack usage.
//! * [`patch`](crate::jit::patch) — the code buffer and jump fixups.
//! * [`emit`](crate::jit::emit) — the two backends.
//! * `interp` — a reference interpreter, for tests only.

pub mod abi;
pub mod isa;

#[cfg(test)]
mod audit;

pub mod emit;
pub mod patch;
pub mod stack;
pub mod validate;

#[cfg(any(test, feature = "testing"))]
pub mod interp;

// Checked-in expected code generation. `cfg(test)` rather than the `testing`
// feature, so its dependencies stay dev-only.
#[cfg(test)]
pub mod golden;

use std::sync::Arc;

use isa::Insn;

/// Which architecture to emit code for.
///
/// Translation is pure computation over a byte buffer, so either target can be
/// produced from either host — which is what lets the byte-level tests cover
/// both backends on a single CI runner. Only *executing* the result requires a
/// matching host.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum Target {
  X86_64,
  Aarch64,
}

impl Target {
  /// The target matching the host this was compiled for.
  pub const fn host() -> Target {
    #[cfg(target_arch = "x86_64")]
    {
      Target::X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
      Target::Aarch64
    }
  }
}

/// The external helper dispatcher the JIT emits calls to.
///
/// Five guest arguments, then the helper index, then an opaque cookie. The index
/// precedes the cookie — the emitted call sequence loads them into that argument
/// order, so getting it backwards would compile and then pass a pointer where an
/// index belongs.
pub type Dispatcher =
  unsafe extern "C" fn(u64, u64, u64, u64, u64, u32, *mut std::ffi::c_void) -> u64;

/// Validates that a helper index is one the embedder registered.
///
/// The second argument is an opaque cookie for the embedder's own use;
/// [`validate`] has none to give and passes null.
pub type DispatcherValidate = unsafe extern "C" fn(u32, *const std::ffi::c_void) -> bool;

/// Resolves a lazily-compiled local call target, returning the callee's native
/// code address.
pub type LocalCallResolver = unsafe extern "C" fn(u32) -> u64;

/// Everything about a translation that is fixed for the life of a program.
///
/// Built once and immutable afterwards, so the fields that only mean something
/// together — the dispatcher and its validator, the pointer cage and the two
/// features that depend on it — cannot drift into an incoherent combination
/// between one translation and the next.
#[derive(Clone)]
pub struct Config {
  /// Emit code for this architecture.
  pub target: Target,

  /// Mask and offset applied to every guest load/store address as
  /// `(address & mask) + offset`. Zero disables the pointer cage entirely, which
  /// also disables every feature below that depends on it.
  pub pointer_mask: i32,
  pub pointer_offset: usize,

  /// The embedder's entry code puts a *native* frame base in `R10` rather than a
  /// guest address, and parks `native_base - guest_bottom` at
  /// [`abi::FRAME_DELTA_OFFSET`]. Enables region hint [`abi::region::FRAME`].
  pub native_frame_base: bool,

  /// The embedder's entry code fills in the twelve derived bounds-check
  /// constants below the frame pointer. Enables access plans.
  pub frame_constants: bool,


  /// Helper dispatch. Both must be set together or neither.
  pub dispatcher: Option<Dispatcher>,
  pub dispatcher_validate: Option<DispatcherValidate>,

  /// Helper index whose zero return unwinds the whole program, or `None`.
  pub unwind_helper_index: Option<u32>,

  /// Called to resolve a lazily-compiled local call target.
  pub local_call_resolver: Option<LocalCallResolver>,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      target: Target::host(),
      pointer_mask: 0,
      pointer_offset: 0,
      native_frame_base: false,
      frame_constants: false,
      // Safe default: a caller that has not set up a pointer cage should have
      // to say explicitly that it wants unchecked guest accesses.
      dispatcher: None,
      dispatcher_validate: None,
      unwind_helper_index: None,
      local_call_resolver: None,
    }
  }
}

impl Config {
  /// Whether the native-frame-base fast path is live. The pointer cage has to be
  /// on for the frame base to mean anything: without it the backend does not
  /// translate guest addresses at all, so there is no shift for the entry code
  /// to have pre-applied.
  pub const fn native_frame_base_active(&self) -> bool {
    self.pointer_mask != 0 && self.native_frame_base
  }

  /// Whether access plans are honoured. A plan only saves work relative to a
  /// check the cage would otherwise emit, and its members read the leader's
  /// translated base out of the frame constants.
  pub const fn access_plans_active(&self) -> bool {
    self.pointer_mask != 0 && self.frame_constants
  }
}

/// One access-plan entry per instruction slot.
///
/// A *group* is a run of memory accesses sharing a base register. The group's
/// **leader** bounds-checks the whole window once and parks the translated base
/// in the frame; each **member** reads that base back and accesses it at a
/// constant displacement.
///
/// The plan is advisory. Before emitting a member the backend re-derives, from
/// the instruction stream it is already walking, that the named leader is the
/// one most recently emitted, that no branch can land between the two, that
/// nothing redefined the base register in between, and that the access lies
/// inside the checked window. Any failure emits an ordinary checked access
/// instead, so a plan that is wrong — or hostile — costs speed and nothing else.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct PlanEntry {
  /// One of [`abi::plan_role`].
  pub role: u8,
  /// Region the leader checks against, as for the region hints.
  pub region: u8,
  /// This access's displacement from the window's low bound.
  pub delta: u16,
  /// Bytes the leader's check covers.
  pub span: u32,
  /// The low bound, as a displacement from the base register.
  pub lo: i32,
  /// The leader that established the base; leaders name themselves.
  pub leader_pc: u32,
}

/// What the analysis tells the JIT about one function, beyond the bytecode.
///
/// All of it is borrowed for exactly one translation: these describe one range
/// of one function under one specialization, so nothing may outlive the call
/// that consumes them.
#[derive(Copy, Clone, Default)]
pub struct TranslationInputs<'a> {
  /// Per-instruction region routing hints, one byte per slot. Empty disables.
  pub hints: &'a [u8],
  /// Per-instruction access plan. Empty disables.
  pub plan: &'a [PlanEntry],
  /// Per-call-site lazy resolver ids, one per instruction slot. Empty disables.
  pub resolver_ids: &'a [u32],
  /// Half-open instruction range to translate.
  pub start_pc: usize,
  pub end_pc: usize,
}

impl<'a> TranslationInputs<'a> {
  /// The region hint for `pc`, or [`abi::region::UNKNOWN`] where there is none.
  pub fn hint(&self, pc: usize) -> u8 {
    self.hints.get(pc).copied().unwrap_or(abi::region::UNKNOWN)
  }

  /// The plan entry for `pc`, if plans are active and one exists.
  pub fn plan_entry(&self, config: &Config, pc: usize) -> Option<&'a PlanEntry> {
    if !config.access_plans_active() {
      return None;
    }
    self.plan.get(pc)
  }
}

/// Why a translation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TranslateError {
  /// The function translates; the buffer was not big enough to hold it. The
  /// caller's code arena treats this as terminal for the whole program, so it
  /// must stay distinguishable from a genuine failure.
  OutOfSpace,
  /// The function does not translate at all.
  Failed(String),
}

impl std::fmt::Display for TranslateError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      TranslateError::OutOfSpace => write!(f, "out of space"),
      TranslateError::Failed(msg) => write!(f, "{msg}"),
    }
  }
}

/// Why a program was rejected at load time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadError(pub String);

impl std::fmt::Display for LoadError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

/// A validated eBPF program, ready to translate.
///
/// Holds only what code generation needs: the decoded instructions, where the
/// local functions start, and their stack usage. One of these is built per
/// section at load time and then translated from repeatedly, once per function
/// variant.
pub struct Translator {
  config: Arc<Config>,
  insns: Box<[Insn]>,
  /// Slots that are the entry point of a local function, i.e. the target of some
  /// `call` with `src == 1`.
  local_func_entries: Box<[bool]>,
  /// Memoised per-local-function stack usage, indexed by entry pc.
  stack_usage: stack::StackUsage,
}

impl Translator {
  /// Validates `code` and prepares it for translation.
  ///
  /// `code.len()` must be a multiple of 8. Rejection messages are surfaced
  /// verbatim by callers and matched on by tests, so their wording is part of
  /// the interface rather than a diagnostic detail.
  pub fn load(config: Arc<Config>, code: &[u8]) -> Result<Translator, LoadError> {
    if code.len() % 8 != 0 {
      return Err(LoadError("code_len must be a multiple of 8".to_string()));
    }
    // A zero-length program is rejected here rather than in [`validate`],
    // because there is nothing for the validator to object to: its
    // per-instruction loop does not run and its sub-program check finds no
    // local call. So the empty case has to be caught by whoever assembles the
    // program, which is this function.
    //
    // The message is a poor description of the problem and is deliberately left
    // alone: it is the wording callers and tests already match on. Changing it
    // is an interface change, not a wording fix.
    if code.is_empty() {
      return Err(LoadError("out of memory".to_string()));
    }
    let insns = Insn::decode_all(code).expect("length checked above");
    if insns.len() > abi::MAX_INSTS as usize {
      return Err(LoadError(format!(
        "too many instructions (max {})",
        abi::MAX_INSTS
      )));
    }

    validate::validate(&config, &insns).map_err(LoadError)?;

    // Mark the targets of local call instructions: they begin local functions,
    // and the backend needs to know where those start.
    let mut local_func_entries = vec![false; insns.len()].into_boxed_slice();
    for (i, insn) in insns.iter().enumerate() {
      if insn.is_local_call() {
        // `validate` establishes that the target is in range, but this must not
        // depend on that: a permissive validator, or a future one that reports
        // the problem differently, would otherwise turn a bad program into an
        // out-of-bounds index here rather than a rejection.
        let target = i as i64 + insn.imm as i64 + 1;
        if target < 0 || target as usize >= local_func_entries.len() {
          return Err(LoadError(format!(
            "local call at pc {i} targets {target}, outside the program"
          )));
        }
        local_func_entries[target as usize] = true;
      }
    }

    let insns = insns.into_boxed_slice();
    let stack_usage = stack::StackUsage::new(insns.len());

    Ok(Translator {
      config,
      insns,
      local_func_entries,
      stack_usage,
    })
  }

  /// The program's instructions.
  pub fn insns(&self) -> &[Insn] {
    &self.insns
  }

  /// Whether the slot at `pc` begins a local function.
  pub fn is_local_func_entry(&self, pc: usize) -> bool {
    self.local_func_entries.get(pc).copied().unwrap_or(false)
  }

  /// This program's configuration.
  pub fn config(&self) -> &Config {
    &self.config
  }

  /// Stack bytes the local function beginning at `pc` uses.
  pub fn stack_usage_for(&self, pc: usize) -> u16 {
    self.stack_usage.for_function(&self.insns, pc)
  }

  /// Translates `inputs.start_pc .. inputs.end_pc` into `buffer`, returning the
  /// number of bytes written.
  ///
  /// The range must begin at pc 0 or at a local function entry and end at a
  /// local function entry or at the end of the program, and every jump it
  /// contains must stay inside it — the emitted code is self-contained, so a
  /// branch to a pc translated into some other buffer has nowhere to go and is
  /// rejected rather than emitted.
  pub fn translate_range(
    &self,
    inputs: &TranslationInputs<'_>,
    buffer: &mut [u8],
  ) -> Result<usize, TranslateError> {
    emit::translate(self, inputs, buffer)
  }

  /// Translates the whole program, with no analysis inputs. Only used by tests;
  /// the runtime always translates one function at a time, with hints and a
  /// plan.
  pub fn translate_all(&self, buffer: &mut [u8]) -> Result<usize, TranslateError> {
    let inputs = TranslationInputs {
      start_pc: 0,
      end_pc: self.insns.len(),
      ..Default::default()
    };
    self.translate_range(&inputs, buffer)
  }
}

/// Synchronises a newly written JIT code range with the instruction cache.
///
/// Architectures with non-coherent data and instruction caches, such as aarch64,
/// require this after writing native code and before executing it. x86_64 has a
/// coherent instruction cache and needs nothing.
///
/// # Safety
/// `buffer` must point at `size` bytes of mapped memory.
pub unsafe fn clear_instruction_cache(buffer: *mut u8, size: usize) {
  icache::clear(buffer, size)
}

pub mod icache;

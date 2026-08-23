//! The C oracle: drive `vendor/ubpf` over the same input as the Rust backend.
//!
//! Through the migration the Rust JIT is required to emit **byte-identical**
//! machine code to the C for every program and every configuration. This module
//! is what makes that requirement checkable — and, while the port is being
//! written, what makes it *debuggable*: a failing case comes back as two byte
//! strings and the offset where they first differ.
//!
//! # Why this can cover both architectures on one host
//!
//! `ubpf_create()` selects a backend with `#if defined(__x86_64__)`, but the
//! CMake build compiles *both* `ubpf_jit_x86_64.c` and `ubpf_jit_arm64.c` into
//! the library unconditionally. Translation writes machine code into a byte
//! buffer and never executes it, so calling `ubpf_translate_function_arm64`
//! directly on an x86_64 host is perfectly well defined. Only running the result
//! needs a matching host.
//!
//! That is what lets a single CI runner byte-diff both backends.
//!
//! Available under `--features oracle`, and in `cfg(test)`.

use std::ffi::CStr;

use super::{Config, PlanEntry, Target, TranslateError, TranslationInputs, Translator};

/// A C `struct ubpf_vm`, configured to match a [`Config`] and loaded with code.
#[derive(Debug)]
pub struct COracle {
  vm: *mut ubpf_sys::ubpf_vm,
}

// The C VM is not shared across threads by this harness; each instance is owned
// by the test that made it.
unsafe impl Send for COracle {}

impl COracle {
  /// Builds a C VM configured exactly as `config` describes and loads `code`
  /// into it.
  ///
  /// Returns the C's rejection message if `ubpf_load` refuses the program,
  /// which is what the validator differential compares against.
  pub fn load(config: &Config, code: &[u8]) -> Result<COracle, String> {
    // SAFETY: every pointer handed to the C below points at a live local or at
    // `code`, which outlives the call; the VM is freed in `Drop`.
    unsafe {
      let vm = ubpf_sys::ubpf_create();
      assert!(!vm.is_null(), "ubpf_create failed");
      let oracle = COracle { vm };

      ubpf_sys::ubpf_toggle_bounds_check(vm, config.bounds_check);
      ubpf_sys::ubpf_set_jit_pointer_mask_and_offset(
        vm,
        config.pointer_mask,
        config.pointer_offset,
      );
      ubpf_sys::ubpf_set_native_frame_base(vm, config.native_frame_base);
      ubpf_sys::ubpf_set_frame_constants(vm, config.frame_constants);

      if let (Some(dispatcher), Some(validate)) = (config.dispatcher, config.dispatcher_validate) {
        let rc = ubpf_sys::ubpf_register_external_dispatcher(
          vm,
          Some(std::mem::transmute::<
            super::Dispatcher,
            unsafe extern "C" fn(u64, u64, u64, u64, u64, ::std::os::raw::c_uint, *mut std::ffi::c_void) -> u64,
          >(dispatcher)),
          Some(std::mem::transmute::<
            super::DispatcherValidate,
            unsafe extern "C" fn(u32, *const ubpf_sys::ubpf_vm) -> bool,
          >(validate)),
        );
        assert_eq!(rc, 0, "ubpf_register_external_dispatcher failed");
      }

      if let Some(idx) = config.unwind_helper_index {
        let rc = ubpf_sys::ubpf_set_unwind_function_index(vm, idx);
        assert_eq!(rc, 0, "ubpf_set_unwind_function_index failed");
      }

      let mut errmsg = std::ptr::null_mut();
      let rc = ubpf_sys::ubpf_load(
        vm,
        code.as_ptr() as *const _,
        code.len() as u32,
        &mut errmsg,
      );
      if rc != 0 {
        return Err(take_errmsg(errmsg));
      }
      debug_assert!(errmsg.is_null());
      Ok(oracle)
    }
  }

  /// Translates `inputs.start_pc .. inputs.end_pc` for `target`, into a buffer
  /// of `capacity` bytes.
  ///
  /// Calls the architecture-specific translator directly rather than going
  /// through `ubpf_translate_function_ex`, whose backend is fixed at compile
  /// time by the host.
  pub fn translate(
    &self,
    target: Target,
    inputs: &TranslationInputs<'_>,
    capacity: usize,
  ) -> Result<Vec<u8>, TranslateError> {
    let mut buffer = vec![0u8; capacity];
    let mut size = capacity;

    // SAFETY: the slices live for the duration of the call and are cleared out
    // of the VM before returning, exactly as `program.rs` does.
    unsafe {
      ubpf_sys::ubpf_set_region_hints(self.vm, inputs.hints.as_ptr(), inputs.hints.len());
      ubpf_sys::ubpf_set_access_plan(
        self.vm,
        inputs.plan.as_ptr() as *const ubpf_sys::ubpf_access_plan_entry,
        inputs.plan.len(),
      );
      if !inputs.resolver_ids.is_empty() {
        ubpf_sys::ubpf_set_lazy_local_call_resolver(
          self.vm,
          Some(oracle_local_call_resolver),
          inputs.resolver_ids.as_ptr(),
          inputs.resolver_ids.len(),
        );
      }

      let result = match target {
        Target::X86_64 => ubpf_sys::ubpf_translate_function_x86_64(
          self.vm,
          buffer.as_mut_ptr(),
          &mut size,
          ubpf_sys::JitMode_ExtendedJitMode,
          inputs.start_pc as u32,
          inputs.end_pc as u32,
        ),
        Target::Aarch64 => ubpf_sys::ubpf_translate_function_arm64(
          self.vm,
          buffer.as_mut_ptr(),
          &mut size,
          ubpf_sys::JitMode_ExtendedJitMode,
          inputs.start_pc as u32,
          inputs.end_pc as u32,
        ),
      };

      ubpf_sys::ubpf_set_region_hints(self.vm, std::ptr::null(), 0);
      ubpf_sys::ubpf_set_access_plan(self.vm, std::ptr::null(), 0);
      ubpf_sys::ubpf_set_lazy_local_call_resolver(self.vm, None, std::ptr::null(), 0);

      let errmsg = take_errmsg(result.errmsg);
      match result.compile_result {
        ubpf_sys::upbf_jit_result_t_UBPF_JIT_COMPILE_SUCCESS => {
          buffer.truncate(size);
          Ok(buffer)
        }
        ubpf_sys::upbf_jit_result_t_UBPF_JIT_COMPILE_OUT_OF_SPACE => {
          Err(TranslateError::OutOfSpace)
        }
        _ => Err(TranslateError::Failed(errmsg)),
      }
    }
  }
}

impl Drop for COracle {
  fn drop(&mut self) {
    // SAFETY: `vm` came from `ubpf_create` and is dropped exactly once.
    unsafe { ubpf_sys::ubpf_destroy(self.vm) }
  }
}

/// Takes ownership of a C-allocated error string, freeing it.
fn take_errmsg(ptr: *mut std::os::raw::c_char) -> String {
  if ptr.is_null() {
    return String::new();
  }
  // SAFETY: uBPF allocates these with malloc and hands ownership to the caller.
  unsafe {
    let msg = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    libc::free(ptr as *mut _);
    msg
  }
}

/// Stand-in resolver. The JIT only ever materialises its *address* as an
/// immediate, so it is never called during translation — but the address is
/// baked into the emitted code, which means both backends must be handed the
/// same one for the bytes to match. [`diff`] arranges that.
unsafe extern "C" fn oracle_local_call_resolver(_id: u32) -> u64 {
  unreachable!("the oracle never executes translated code")
}

/// Stand-in dispatcher, for the same reason.
unsafe extern "C" fn oracle_dispatcher(
  _a: u64,
  _b: u64,
  _c: u64,
  _d: u64,
  _e: u64,
  _idx: u32,
  _cookie: *mut std::ffi::c_void,
) -> u64 {
  unreachable!("the oracle never executes translated code")
}

/// Stand-in helper validator. Accepts everything, so that helper-call emission
/// is exercised rather than rejected at load time.
unsafe extern "C" fn oracle_dispatcher_validate(_idx: u32, _vm: *const std::ffi::c_void) -> bool {
  true
}

/// A [`Config`] wired to the harness's own stand-in callbacks.
///
/// Both backends must see the *same* function addresses, because the JIT
/// materialises them as immediates in the emitted code. Using this constructor
/// on both sides is what makes the comparison meaningful.
pub fn oracle_config(target: Target) -> Config {
  Config {
    target,
    dispatcher: Some(oracle_dispatcher),
    dispatcher_validate: Some(oracle_dispatcher_validate),
    local_call_resolver: Some(oracle_local_call_resolver),
    ..Default::default()
  }
}

/// The result of comparing the two backends on one input.
#[derive(Debug)]
pub enum Diff {
  /// Both emitted the same bytes.
  Same { len: usize },
  /// Both failed, in the same way.
  SameError(TranslateError),
  /// The emitted code differs.
  Bytes {
    c: Vec<u8>,
    rust: Vec<u8>,
    /// First differing byte offset, or `None` when one is a prefix of the other.
    first: Option<usize>,
  },
  /// One succeeded where the other failed, or they failed differently.
  Outcome {
    c: Result<usize, TranslateError>,
    rust: Result<usize, TranslateError>,
  },
  /// The two disagreed about whether the program loads at all.
  Load { c: Option<String>, rust: Option<String> },
}

impl Diff {
  pub fn is_same(&self) -> bool {
    matches!(self, Diff::Same { .. } | Diff::SameError(_))
  }
}

impl std::fmt::Display for Diff {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Diff::Same { len } => write!(f, "identical ({len} bytes)"),
      Diff::SameError(e) => write!(f, "both failed identically: {e}"),
      Diff::Load { c, rust } => write!(
        f,
        "load disagreement\n     C: {c:?}\n  Rust: {rust:?}"
      ),
      Diff::Outcome { c, rust } => write!(
        f,
        "outcome disagreement\n     C: {c:?}\n  Rust: {rust:?}"
      ),
      Diff::Bytes { c, rust, first } => {
        writeln!(f, "byte mismatch: C emitted {}, Rust {}", c.len(), rust.len())?;
        match first {
          Some(at) => {
            let lo = at.saturating_sub(16);
            let hi_c = (at + 16).min(c.len());
            let hi_r = (at + 16).min(rust.len());
            writeln!(f, "  first difference at offset {at} ({at:#x})")?;
            writeln!(f, "     C [{lo}..{hi_c}]: {}", hex(&c[lo..hi_c]))?;
            write!(f, "  Rust [{lo}..{hi_r}]: {}", hex(&rust[lo..hi_r]))
          }
          None => write!(f, "  one output is a prefix of the other"),
        }
      }
    }
  }
}

fn hex(bytes: &[u8]) -> String {
  bytes
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect::<Vec<_>>()
    .join(" ")
}

/// Translates `code` through both backends and compares.
///
/// This is the workhorse of the port. A failing case prints the first differing
/// offset with context on both sides, which is usually enough to name the
/// instruction that went wrong.
pub fn diff(config: &Config, code: &[u8], inputs: &TranslationInputs<'_>, capacity: usize) -> Diff {
  let c_loaded = COracle::load(config, code);
  let rust_loaded = Translator::load(std::sync::Arc::new(config.clone()), code);

  let (c_vm, rust_vm) = match (c_loaded, rust_loaded) {
    (Ok(c), Ok(r)) => (c, r),
    (Err(c), Err(_r)) => {
      // Both rejected. The validator differential compares the messages; here
      // it is enough that neither produced code.
      return Diff::SameError(TranslateError::Failed(c));
    }
    (Err(c), Ok(_)) => {
      return Diff::Load {
        c: Some(c),
        rust: None,
      }
    }
    (Ok(_), Err(r)) => {
      return Diff::Load {
        c: None,
        rust: Some(r.0),
      }
    }
  };

  let c_out = c_vm.translate(config.target, inputs, capacity);
  let mut rust_buf = vec![0u8; capacity];
  let rust_out = rust_vm
    .translate_range(inputs, &mut rust_buf)
    .map(|len| {
      rust_buf.truncate(len);
      rust_buf.clone()
    });

  match (c_out, rust_out) {
    (Ok(c), Ok(r)) => {
      if c == r {
        Diff::Same { len: c.len() }
      } else {
        let first = c.iter().zip(r.iter()).position(|(a, b)| a != b);
        Diff::Bytes { c, rust: r, first }
      }
    }
    (Err(a), Err(b)) if a == b => Diff::SameError(a),
    (c, r) => Diff::Outcome {
      c: c.map(|v| v.len()),
      rust: r.map(|v| v.len()),
    },
  }
}

/// Asserts that both backends agree on `code`, printing a readable diff if not.
#[track_caller]
pub fn assert_same(config: &Config, code: &[u8], inputs: &TranslationInputs<'_>, capacity: usize) {
  let d = diff(config, code, inputs, capacity);
  assert!(
    d.is_same(),
    "backends disagree for target {:?}\n{d}\n  program:\n{}",
    config.target,
    disasm_source(code)
  );
}

/// Renders the eBPF input, so a failure names the program that produced it.
fn disasm_source(code: &[u8]) -> String {
  super::isa::Insn::decode_all(code)
    .map(|insns| {
      insns
        .iter()
        .enumerate()
        .map(|(i, insn)| format!("    {i:4}: {insn:?}"))
        .collect::<Vec<_>>()
        .join("\n")
    })
    .unwrap_or_else(|| "    <not a multiple of 8 bytes>".to_string())
}

/// Builds [`TranslationInputs`] covering a whole program with no hints or plan.
pub fn plain_inputs(num_insns: usize) -> TranslationInputs<'static> {
  TranslationInputs {
    hints: &[],
    plan: &[],
    resolver_ids: &[],
    start_pc: 0,
    end_pc: num_insns,
  }
}

/// The configuration sweep the differential test runs over.
///
/// The emitted code depends on the pointer cage, the native frame base, the
/// frame constants and the region hints, and those features *interact* — which
/// is exactly where a port goes wrong. Sweeping them is not optional.
pub fn config_sweep(target: Target) -> Vec<(&'static str, Config)> {
  let base = oracle_config(target);
  vec![
    (
      "no cage",
      Config {
        pointer_mask: 0,
        pointer_offset: 0,
        bounds_check: true,
        ..base.clone()
      },
    ),
    (
      "cage only",
      Config {
        pointer_mask: 0x0fff_ffff,
        pointer_offset: 0x1_0000_0000,
        bounds_check: false,
        ..base.clone()
      },
    ),
    (
      "cage + native frame base",
      Config {
        pointer_mask: 0x0fff_ffff,
        pointer_offset: 0x1_0000_0000,
        bounds_check: false,
        native_frame_base: true,
        ..base.clone()
      },
    ),
    (
      "cage + frame constants",
      Config {
        pointer_mask: 0x0fff_ffff,
        pointer_offset: 0x1_0000_0000,
        bounds_check: false,
        frame_constants: true,
        ..base.clone()
      },
    ),
    (
      // What `async-ebpf` actually runs.
      "production",
      Config {
        pointer_mask: 0x0fff_ffff,
        pointer_offset: 0x1_0000_0000,
        bounds_check: false,
        native_frame_base: true,
        frame_constants: true,
        ..base.clone()
      },
    ),
    (
      "production + unwind helper",
      Config {
        pointer_mask: 0x0fff_ffff,
        pointer_offset: 0x1_0000_0000,
        bounds_check: false,
        native_frame_base: true,
        frame_constants: true,
        unwind_helper_index: Some(3),
        ..base
      },
    ),
  ]
}

/// Both architectures, so a test written once covers both backends.
pub const TARGETS: [Target; 2] = [Target::X86_64, Target::Aarch64];

/// A convenience wrapper: run `code` through the whole sweep on both targets.
#[track_caller]
pub fn assert_same_everywhere(code: &[u8], inputs: &TranslationInputs<'_>) {
  let num_insns = code.len() / 8;
  let capacity = 65536.max(num_insns * 256);
  for target in TARGETS {
    for (name, config) in config_sweep(target) {
      let d = diff(&config, code, inputs, capacity);
      assert!(
        d.is_same(),
        "backends disagree for {target:?} under {name:?}\n{d}\n  program:\n{}",
        disasm_source(code)
      );
    }
  }
}

/// Unused-warning suppression for the plan type, which callers construct.
#[allow(dead_code)]
fn _plan_entry_is_public(_: PlanEntry) {}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::jit::isa::{opcode, Insn};

  /// `mov r0, 42; exit`
  fn trivial() -> Vec<u8> {
    Insn::encode_all(&[
      Insn { opcode: 0xb7, dst: 0, src: 0, offset: 0, imm: 42 },
      Insn { opcode: opcode::EXIT, dst: 0, src: 0, offset: 0, imm: 0 },
    ])
  }

  #[test]
  fn the_c_oracle_emits_code_for_both_targets_from_this_host() {
    // The point of the whole harness: aarch64 machine code is produced on an
    // x86_64 host, and vice versa. If this ever regresses to "only the host
    // arch works", the cross-arch half of the differential silently stops
    // testing anything.
    let code = trivial();
    let inputs = plain_inputs(code.len() / 8);
    let mut sizes = Vec::new();
    for target in TARGETS {
      let vm = COracle::load(&oracle_config(target), &code).expect("trivial program must load");
      let out = vm
        .translate(target, &inputs, 65536)
        .unwrap_or_else(|e| panic!("C failed to translate for {target:?}: {e}"));
      assert!(!out.is_empty(), "{target:?} produced no code");
      sizes.push((target, out.len()));
    }
    // Sanity: the two backends should not coincidentally emit the same length
    // for a program this small, which would suggest one call is silently
    // dispatching to the other.
    assert_ne!(
      sizes[0].1, sizes[1].1,
      "both targets emitted {} bytes; is the arch dispatch working? {sizes:?}",
      sizes[0].1
    );
  }

  #[test]
  fn the_c_oracle_rejects_a_program_the_way_ubpf_load_does() {
    // A jump past the end of the program. uBPF does accept a program that
    // does not end in `exit`, so that is not the case to use here.
    let code = Insn::encode_all(&[
      Insn { opcode: opcode::JA, dst: 0, src: 0, offset: 99, imm: 0 },
      Insn { opcode: opcode::EXIT, dst: 0, src: 0, offset: 0, imm: 0 },
    ]);
    let err = COracle::load(&oracle_config(Target::X86_64), &code)
      .expect_err("a program that runs off the end must be rejected");
    assert!(!err.is_empty(), "rejection carried no message");
  }

  #[test]
  fn out_of_space_is_distinguishable_from_failure() {
    let code = trivial();
    let inputs = plain_inputs(code.len() / 8);
    let vm = COracle::load(&oracle_config(Target::X86_64), &code).unwrap();
    let err = vm
      .translate(Target::X86_64, &inputs, 8)
      .expect_err("8 bytes cannot hold a prologue");
    assert_eq!(err, TranslateError::OutOfSpace);
  }
}

//! Checked-in expected code generation.
//!
//! # What a golden file does and does not tell you
//!
//! A golden answers *is this output the same as last time?* It does not answer
//! *is this output correct?* Nothing checked into a file can. That limit is
//! worth stating plainly, because a large green golden suite is easy to mistake
//! for a correctness argument.
//!
//! Correctness lives elsewhere: [`super::interp`] is a reference interpreter
//! written from the instruction set rather than from this backend, and it is
//! what execution is checked against. The goldens are here to make an
//! *unintended* change to code generation impossible to merge quietly.
//!
//! # Format
//!
//! `src/jit/goldens/{x86_64,aarch64}.txt`, one entry per line:
//!
//! ```text
//! <key>|<len>:<hex-of-emitted-bytes>
//! <key>|err:<message>
//! sweep.<name>|<cases>:<translated>:<digest>
//! ```
//!
//! Outputs up to [`FULL_HEX_LIMIT`] are recorded in full, so a codegen change
//! shows up in review as the bytes that changed rather than as an opaque
//! digest. Larger ones fall back to a length and a hash; a four-thousand
//! instruction function emits around 100 KB and would otherwise swamp the file.
//!
//! Keys are content-addressed over the program, the translation inputs and the
//! configuration. They therefore do not depend on test order or test names, and
//! a test that changes the program it emits looks up a key that is simply
//! absent rather than silently comparing against an unrelated entry.
//!
//! Randomised sweeps roll up into one line each. Per-case goldens are right for
//! named tests and hopeless for hundreds of thousands of programs; the cost is
//! that a sweep tells you *that* something changed, not which case.
//!
//! # Updating
//!
//! `ASYNC_EBPF_UPDATE_GOLDENS=1 cargo test --features testing`. The resulting
//! diff is the deliverable of any change to code generation, and reviewing it is
//! the point — unexplained churn here is the signal that something changed which
//! nobody intended.

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::{Config, PlanEntry, Target, TranslateError, TranslationInputs, Translator};

use sha2::{Digest, Sha256};

/// Accumulating hash used to key goldens and to roll up sweeps.
///
/// Nothing here is a security boundary; what a checked-in file needs is a
/// digest that is stable across compiler versions, which rules out
/// `DefaultHasher` and makes a real hash the least surprising choice.
#[derive(Clone, Default)]
struct Hasher(Sha256);

impl Hasher {
  fn update(&mut self, bytes: &[u8]) {
    self.0.update(bytes);
  }

  fn finish(self) -> String {
    self
      .0
      .finalize()
      .iter()
      .map(|b| format!("{b:02x}"))
      .collect()
  }
}

fn stable_hash(bytes: &[u8]) -> String {
  let mut h = Hasher::default();
  h.update(bytes);
  h.finish()
}

/// Renders bytes as lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
  bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether this run should rewrite the golden files instead of checking them.
pub fn updating() -> bool {
  std::env::var_os("ASYNC_EBPF_UPDATE_GOLDENS").is_some()
}

/// Whether this run should additionally drop entries nothing looked up.
///
/// Separate from plain updating, and opt-in, because it is only correct for a
/// run of the *whole* suite: a filtered run touches a fraction of the entries,
/// and pruning against that would delete everything else. Renaming or removing
/// a test otherwise leaves its entry behind for ever, so:
///
/// ```text
/// ASYNC_EBPF_UPDATE_GOLDENS=prune cargo test --features testing
/// ```
pub fn pruning() -> bool {
  std::env::var("ASYNC_EBPF_UPDATE_GOLDENS")
    .map(|v| v == "prune")
    .unwrap_or(false)
}

fn golden_path(target: Target) -> std::path::PathBuf {
  let arch = match target {
    Target::X86_64 => "x86_64",
    Target::Aarch64 => "aarch64",
  };
  std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("src/jit/goldens")
    .join(format!("{arch}.txt"))
}

struct Store {
  entries: BTreeMap<String, String>,
  /// Keys this process looked up or recorded. Used only by the prune mode.
  seen: std::collections::BTreeSet<String>,
  dirty: bool,
}

/// Takes the store lock, ignoring poisoning.
///
/// A golden mismatch reports by panicking, and a panic while the lock is held
/// poisons it. The data behind it is a plain map that was only being read, so
/// it is still perfectly good — but `unwrap()` on the next lock would turn one
/// honest mismatch into a second panic, and `flush` runs from a `Drop`, where a
/// panic aborts the process. That is how a single reportable failure became a
/// SIGABRT and a screenful of unrelated ones.
fn lock(m: &'static Mutex<Store>) -> std::sync::MutexGuard<'static, Store> {
  m.lock().unwrap_or_else(|e| e.into_inner())
}

fn store(target: Target) -> &'static Mutex<Store> {
  use std::sync::OnceLock;
  static X86: OnceLock<Mutex<Store>> = OnceLock::new();
  static ARM: OnceLock<Mutex<Store>> = OnceLock::new();
  let cell = match target {
    Target::X86_64 => &X86,
    Target::Aarch64 => &ARM,
  };
  cell.get_or_init(|| {
    let mut entries = BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string(golden_path(target)) {
      for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
          continue;
        }
        if let Some((k, v)) = line.split_once('|') {
          entries.insert(k.to_string(), v.to_string());
        }
      }
    }
    Mutex::new(Store {
      entries,
      seen: Default::default(),
      dirty: false,
    })
  })
}

/// Writes back any golden file this process modified.
///
/// Called from a `Drop` guard registered by the test harness rather than at
/// process exit, because Rust's test runner does not run atexit hooks reliably.
pub fn flush() {
  for target in [Target::X86_64, Target::Aarch64] {
    let mut guard = lock(store(target));
    if pruning() {
      let seen = guard.seen.clone();
      let before = guard.entries.len();
      guard.entries.retain(|k, _| seen.contains(k));
      if guard.entries.len() != before {
        guard.dirty = true;
      }
    }
    if !guard.dirty {
      continue;
    }
    // Reported rather than asserted: `flush` runs from a `Drop` guard, where a
    // panic aborts the process instead of failing a test.
    if guard.entries.len() > MAX_ENTRIES {
      eprintln!(
        "{:?} golden file would hold {} entries, over the {MAX_ENTRIES} ceiling.\n\n\
         `check` is for a bounded set of named cases. A test looping over a large \
         cross-product should fold its outcomes into a `SweepDigest` instead, \
         which records one line however many cases it covers.",
        target,
        guard.entries.len()
      );
      panic!("golden file over the {MAX_ENTRIES}-entry ceiling");
    }
    let path = golden_path(target);
    let _ = std::fs::create_dir_all(path.parent().unwrap());
    let mut out = String::new();
    out.push_str(
      "# Generated: the machine code this backend is expected to emit.\n\
       #\n\
       # Regenerate with ASYNC_EBPF_UPDATE_GOLDENS=1 cargo test --features testing.\n\
       # A diff here means code generation changed. That is fine when it was\n\
       # intended and the diff is part of the change being reviewed; an\n\
       # unexplained one means something moved that nobody meant to move.\n",
    );
    for (k, v) in &guard.entries {
      out.push_str(k);
      out.push('|');
      out.push_str(v);
      out.push('\n');
    }
    std::fs::write(&path, out).expect("failed to write golden file");
    guard.dirty = false;
  }
}

/// A stable, content-addressed key for one translation.
///
/// Includes everything that can change the emitted bytes, so two different
/// inputs cannot collide onto one entry and a changed input looks up a missing
/// key rather than comparing against an unrelated one.
pub fn key(label: &str, config: &Config, code: &[u8], inputs: &TranslationInputs<'_>) -> String {
  let mut h = Hasher::default();
  h.update(code);
  h.update(&(inputs.start_pc as u64).to_le_bytes());
  h.update(&(inputs.end_pc as u64).to_le_bytes());
  h.update(inputs.hints);
  for e in inputs.plan {
    h.update(&[e.role, e.region]);
    h.update(&e.delta.to_le_bytes());
    h.update(&e.span.to_le_bytes());
    h.update(&e.lo.to_le_bytes());
    h.update(&e.leader_pc.to_le_bytes());
  }
  for id in inputs.resolver_ids {
    h.update(&id.to_le_bytes());
  }
  h.update(&config.pointer_mask.to_le_bytes());
  h.update(&(config.pointer_offset as u64).to_le_bytes());
  h.update(&[
    config.native_frame_base as u8,
    config.frame_constants as u8,
    config.dispatcher.is_some() as u8,
    config.local_call_resolver.is_some() as u8,
  ]);
  format!("{label}.{}", &h.finish()[..24])
}

/// The outcome of a translation, rendered so that a failure and a success are
/// distinguishable in the golden file.
/// Bytes above this are recorded as a length and a hash rather than in full.
///
/// Below it the golden holds the actual machine code, so a codegen change shows
/// up in review as the bytes that changed rather than as an opaque digest.
///
/// The limit is low on purpose. Typical emitted functions run to a few hundred
/// bytes, so a generous limit means nearly every entry is recorded in full and
/// the file grows with the *product* of cases and code size - at 1 KB it
/// reached 24 MB for one architecture. Full hex is worth having for the small
/// canonical cases a reviewer might actually read; beyond that a hash carries
/// the same regression signal for a fortieth of the bytes.
const FULL_HEX_LIMIT: usize = 128;

/// Per-case entries permitted in one golden file.
///
/// A ceiling rather than a guideline, because the failure it prevents is
/// gradual: [`check`] is for a bounded set of named cases, and it is very easy
/// to point a loop over a large cross-product at it and grow the file by a
/// megabyte without noticing. Cross-products belong in a [`SweepDigest`], which
/// records one line however many cases it folds in.
const MAX_ENTRIES: usize = 3000;

pub fn outcome_digest(out: &Result<Vec<u8>, TranslateError>) -> String {
  match out {
    Ok(bytes) if bytes.len() <= FULL_HEX_LIMIT => format!("{}:{}", bytes.len(), to_hex(bytes)),
    Ok(bytes) => format!("{}:h{}", bytes.len(), &stable_hash(bytes)[..32]),
    Err(TranslateError::OutOfSpace) => "err:OutOfSpace".to_string(),
    // Error text is short, so it is recorded verbatim: a message regression is
    // then legible in the diff instead of being a changed hash.
    Err(TranslateError::Failed(msg)) => format!("err:{msg}"),
  }
}

/// Checks one translation against its golden, or records it.
///
/// Returns `true` if the case translated successfully, so callers can keep
/// asserting that a test is exercising the emitter rather than agreeing about a
/// refusal — the check that stopped an early round of emitter tests from
/// passing while translating almost nothing.
pub fn check(
  label: &str,
  config: &Config,
  code: &[u8],
  inputs: &TranslationInputs<'_>,
  capacity: usize,
) -> bool {
  // A program refused at load is recorded too, with its refusal message. It
  // would be easy to return early here and record nothing - the caller's own
  // assertion already covers "was it refused?" - but then a case that is still
  // refused for a newly *different* reason reads as unchanged, and cases whose
  // whole purpose is to be refused would contribute nothing to the file at all.
  let (translated, digest) = match Translator::load(std::sync::Arc::new(config.clone()), code) {
    Err(e) => (false, format!("load-err:{}", e.0)),
    Ok(translator) => {
      let mut buf = vec![0u8; capacity];
      let out = translator.translate_range(inputs, &mut buf).map(|len| {
        buf.truncate(len);
        buf
      });
      (out.is_ok(), outcome_digest(&out))
    }
  };

  let k = key(label, config, code, inputs);

  let mut guard = lock(store(config.target));
  guard.seen.insert(k.clone());
  if updating() {
    if guard.entries.get(&k) != Some(&digest) {
      guard.entries.insert(k, digest);
      guard.dirty = true;
    }
    return translated;
  }
  let verdict = match guard.entries.get(&k) {
    Some(expected) if *expected == digest => Ok(translated),
    Some(expected) => Err(Some(expected.clone())),
    None => Err(None),
  };
  drop(guard);
  match verdict {
    Ok(translated) => translated,
    Err(Some(expected)) => panic!(
      "golden mismatch for {label} on {:?}\n  expected: {expected}\n  actual:   {digest}\n\n\
       Code generation changed. If that was intended, regenerate with\n  \
       ASYNC_EBPF_UPDATE_GOLDENS=1 cargo test --features testing\n\
       and make the resulting diff part of the change being reviewed.",
      config.target
    ),
    Err(None) => panic!(
      "no golden recorded for {label} on {:?} (key {k})\n\n\
       This input is new. Record it with\n  \
       ASYNC_EBPF_UPDATE_GOLDENS=1 cargo test --features testing",
      config.target
    ),
  }
}

/// Loads and translates one case, returning `None` if the program does not
/// load at all.
///
/// Shared by [`check`] and by sweeps, so a sweep folding hundreds of thousands
/// of outcomes into one digest goes through exactly the same path as a named
/// per-case golden.
pub fn translate_one(
  config: &Config,
  code: &[u8],
  inputs: &TranslationInputs<'_>,
  capacity: usize,
) -> Option<Result<Vec<u8>, TranslateError>> {
  let translator = Translator::load(std::sync::Arc::new(config.clone()), code).ok()?;
  let mut buf = vec![0u8; capacity];
  Some(translator.translate_range(inputs, &mut buf).map(|len| {
    buf.truncate(len);
    buf
  }))
}

/// Accumulates a digest across a whole randomised sweep.
///
/// Per-case goldens are right for named tests and hopeless for a sweep of
/// hundreds of thousands of programs. One rolling digest keeps the whole sweep
/// as a single reviewable line, at the cost of saying only *that* something
/// changed rather than which case.
#[derive(Default)]
pub struct SweepDigest {
  hasher: Hasher,
  cases: usize,
  translated: usize,
}

impl SweepDigest {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn add(&mut self, out: &Result<Vec<u8>, TranslateError>) {
    self.cases += 1;
    if out.is_ok() {
      self.translated += 1;
    }
    self.hasher.update(outcome_digest(out).as_bytes());
  }

  pub fn translated(&self) -> usize {
    self.translated
  }

  pub fn cases(&self) -> usize {
    self.cases
  }

  /// Compares the accumulated digest against its golden, or records it.
  pub fn finish(self, label: &str, target: Target) {
    let digest = format!(
      "{}:{}:{}",
      self.cases,
      self.translated,
      self.hasher.finish()
    );
    let k = format!("sweep.{label}");
    let mut guard = lock(store(target));
    guard.seen.insert(k.clone());
    if updating() {
      if guard.entries.get(&k) != Some(&digest) {
        guard.entries.insert(k, digest);
        guard.dirty = true;
      }
      return;
    }
    let verdict = match guard.entries.get(&k) {
      Some(expected) if *expected == digest => Ok(()),
      Some(expected) => Err(Some(expected.clone())),
      None => Err(None),
    };
    drop(guard);
    match verdict {
      Ok(()) => {}
      Err(Some(expected)) => panic!(
        "sweep golden mismatch for {label} on {target:?}\n  expected: {expected}\n  actual:   {digest}\n\n\
         The three fields are case count, successful-translation count, and a digest\n\
         over every outcome. A change in the first two means the sweep itself\n\
         changed; a change only in the third means code generation did.\n\n\
         Regenerate with ASYNC_EBPF_UPDATE_GOLDENS=1 cargo test --features testing"
      ),
      Err(None) => panic!("no sweep golden recorded for {label} on {target:?}"),
    }
  }
}

/// Unused-warning suppression for the plan type, which callers construct.
#[allow(dead_code)]
fn _plan_entry_is_used(_: PlanEntry) {}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn the_hash_is_stable_and_accumulates() {
    // A standard vector, so a change of algorithm is caught rather than
    // silently rehashing every golden into a file that no longer matches.
    assert_eq!(
      stable_hash(b"abc"),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // The accumulating form must agree with the one-shot form, since keys are
    // built from several pieces.
    let mut h = Hasher::default();
    h.update(b"foo");
    h.update(b"bar");
    assert_eq!(h.finish(), stable_hash(b"foobar"));
  }

  #[test]
  fn a_small_output_is_recorded_as_readable_bytes() {
    // The point of the size rule: normal cases are reviewable as hex.
    assert_eq!(outcome_digest(&Ok(vec![0x48, 0x89, 0xe5])), "3:4889e5");
    let big = vec![0u8; FULL_HEX_LIMIT + 1];
    let d = outcome_digest(&Ok(big));
    assert!(d.starts_with(&format!("{}:h", FULL_HEX_LIMIT + 1)), "{d}");
  }

  #[test]
  fn the_key_separates_inputs_that_change_the_emitted_bytes() {
    let code = vec![0u8; 16];
    let base = Config::default();
    let plain = TranslationInputs {
      start_pc: 0,
      end_pc: 2,
      ..Default::default()
    };
    let k = key("t", &base, &code, &plain);

    // A different range, hint set, or cage setting must not share a key.
    let other_range = TranslationInputs { end_pc: 1, ..plain };
    assert_ne!(k, key("t", &base, &code, &other_range));

    let hints = [1u8, 2];
    let hinted = TranslationInputs {
      hints: &hints,
      ..plain
    };
    assert_ne!(k, key("t", &base, &code, &hinted));

    let caged = Config {
      pointer_mask: 0xfff,
      ..base.clone()
    };
    assert_ne!(k, key("t", &caged, &code, &plain));

    let framed = Config {
      native_frame_base: true,
      ..base.clone()
    };
    assert_ne!(k, key("t", &framed, &code, &plain));

    // And the same input must be stable across calls.
    assert_eq!(k, key("t", &base, &code, &plain));
  }

  /// A program refused at load must be recorded, and distinguishably.
  ///
  /// Deliberately does not go through [`check`]: that would mean setting the
  /// update environment variable, and the test runner shares one environment
  /// across threads, so every test running concurrently would briefly see
  /// update mode and record instead of verifying.
  #[test]
  fn a_load_refusal_is_recorded_and_is_distinct() {
    use crate::jit::isa::{opcode, Insn};
    // A jump past the end of the program: refused at load, not at translation.
    let code = Insn::encode_all(&[
      Insn {
        opcode: opcode::JA,
        dst: 0,
        src: 0,
        offset: 99,
        imm: 0,
      },
      Insn {
        opcode: opcode::EXIT,
        dst: 0,
        src: 0,
        offset: 0,
        imm: 0,
      },
    ]);
    let config = Config::default();
    let err = match Translator::load(std::sync::Arc::new(config.clone()), &code) {
      Err(e) => e,
      Ok(_) => panic!("a jump past the end must be refused at load"),
    };
    assert!(!err.0.is_empty(), "a refusal carried no message");

    // The shape `check` records for it, and its distinctness from every
    // translation outcome.
    let recorded = format!("load-err:{}", err.0);
    assert!(recorded.starts_with("load-err:"));
    assert_ne!(recorded, outcome_digest(&Err(TranslateError::OutOfSpace)));
    assert_ne!(recorded, outcome_digest(&Ok(vec![])));
    assert_ne!(
      recorded,
      outcome_digest(&Err(TranslateError::Failed(err.0.clone()))),
      "a load refusal must not read the same as a translation failure carrying \
       the same message"
    );

    // And `check` reports it as not translated, whichever mode it is in.
    let inputs = TranslationInputs {
      start_pc: 0,
      end_pc: 2,
      ..Default::default()
    };
    assert!(super::translate_one(&config, &code, &inputs, 4096).is_none());
  }

  #[test]
  fn a_failure_and_a_success_do_not_share_a_digest() {
    let ok = outcome_digest(&Ok(vec![1, 2, 3]));
    let oos = outcome_digest(&Err(TranslateError::OutOfSpace));
    let failed = outcome_digest(&Err(TranslateError::Failed("boom".into())));
    assert_ne!(ok, oos);
    assert_ne!(ok, failed);
    assert_ne!(oos, failed);
    // Different messages are distinguishable, so an error-text regression shows.
    assert_ne!(
      failed,
      outcome_digest(&Err(TranslateError::Failed("bang".into())))
    );
    // And an empty success is not the same as a failure.
    assert_ne!(outcome_digest(&Ok(vec![])), oos);
  }
}

//! Adversarial tests added by an integration/safety-boundary audit.
//!
//! Nothing here is production logic. Every test in this module is a question
//! about the *boundary*: what `Translator::load` and `translate_range` do with
//! bytecode and analysis inputs an attacker controls, and whether the frame
//! contract in [`super::abi`] is actually tied to the three other places that
//! restate it.

#![cfg(test)]

use super::abi;
use super::isa::Insn;
use super::{Config, PlanEntry, Target, TranslationInputs, Translator};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// The frame ABI contract
// ---------------------------------------------------------------------------

/// `abi.rs` claims to be "the single definition" of a layout also stated in the
/// `global_asm!` trampolines and in `JitMemory`. It is not tied to either: the
/// trampolines use literal displacements in a raw string (no `const` operands)
/// and `JitMemory`'s layout assertions use literal offsets too.
///
/// Until that is fixed, this test is the tie. It reads `program.rs` at compile
/// time and asserts that every displacement the trampolines use is the one
/// `abi.rs` names. If someone edits `abi.rs` without editing the trampoline —
/// exactly the failure the module doc warns about, which produces a legitimate
/// guest corrupting host memory rather than a test failure — this fails.
mod trampoline_contract {
  use super::*;

  const PROGRAM_RS: &str = include_str!("../program.rs");

  /// Everything between `async_ebpf_entry_trampoline:` and the matching
  /// `.size` directive, for whichever trampoline `arch` names.
  fn trampoline(arch: &str) -> &'static str {
    // Both trampolines are in one file; split on the architecture-specific
    // opening instruction rather than on the cfg attribute.
    let anchor = match arch {
      "x86_64" => "mov r9, rdi",
      "aarch64" => "bti c",
      _ => unreachable!(),
    };
    let start = PROGRAM_RS
      .find(anchor)
      .unwrap_or_else(|| panic!("no {arch} trampoline found in program.rs"));
    let rest = &PROGRAM_RS[start..];
    let end = rest
      .find(".size async_ebpf_entry_trampoline")
      .expect("trampoline has no .size terminator");
    &rest[..end]
  }

  fn assert_contains(arch: &str, needle: &str) {
    let body = trampoline(arch);
    assert!(
      body.contains(needle),
      "the {arch} entry trampoline no longer contains `{needle}`; it and \
       crate::jit::abi have drifted, and the symptom of that is a legitimate \
       guest program corrupting host memory rather than a failing test"
    );
  }

  #[test]
  fn the_x86_64_trampoline_uses_the_displacements_abi_names() {
    assert_eq!(abi::FRAME_OFFSET, -8);
    assert_contains("x86_64", "mov [rbp - 8], rax");

    assert_eq!(abi::FRAME_DELTA_OFFSET, -40);
    assert_contains("x86_64", "mov [rbp - 40], rdx");

    assert_eq!(abi::GROUP_BASE_OFFSET, -144);
    assert_contains("x86_64", "mov qword ptr [rbp - 144], 0");

    assert_eq!(abi::FRAME_RESERVED, 160);
    assert_contains("x86_64", "sub rsp, 160");

    // The twelve derived slots are copied sixteen bytes at a time, from the
    // descriptor's `derived` field (offset 48) into [rbp-136, rbp-40).
    assert_eq!(abi::derived_slot(0), -136);
    assert_eq!(abi::DERIVED_SLOTS, 12);
    for pair in 0..abi::DERIVED_SLOTS / 2 {
      let src = 48 + pair * 16;
      let dst = abi::derived_slot(pair * 2);
      assert_contains("x86_64", &format!("movdqu xmm0, [rax + {src}]"));
      assert_contains("x86_64", &format!("movdqu [rbp - {}], xmm0", -dst));
    }
    // ...and the last one must land exactly at the frame-delta slot, i.e. the
    // block is contiguous and does not overrun into it.
    assert_eq!(
      abi::derived_slot(abi::DERIVED_SLOTS - 1) + 8,
      abi::FRAME_DELTA_OFFSET
    );

    // `[rax + 16]` is JitMemory::stack_native_base, which the trampoline reads
    // to build the frame delta.
    assert_eq!(abi::memory::STACK_NATIVE_BASE, 16);
    assert_contains("x86_64", "mov rdx, [rax + 16]");
  }

  #[test]
  fn the_aarch64_trampoline_uses_the_displacements_abi_names() {
    assert_contains("aarch64", "str x6, [x29, #-8]");
    assert_contains("aarch64", "str x7, [x29, #-40]");
    assert_contains("aarch64", "str xzr, [x29, #-144]");
    assert_contains("aarch64", "sub sp, sp, #160");
    assert_contains("aarch64", "ldr x7, [x6, #16]");

    for pair in 0..abi::DERIVED_SLOTS / 2 {
      let src = 48 + pair * 16;
      let dst = -abi::derived_slot(pair * 2);
      assert_contains("aarch64", &format!("ldp x7, x16, [x6, #{src}]"));
      assert_contains("aarch64", &format!("stp x7, x16, [x29, #-{dst}]"));
    }
  }

  /// Every slot the backend addresses off the frame pointer has to be inside
  /// the window the prologue reserved, or the generated code writes below the
  /// host stack pointer.
  #[test]
  fn every_frame_slot_is_inside_the_reserved_window() {
    let slots = {
      let mut v = vec![
        abi::FRAME_OFFSET,
        abi::SPILL_OFFSET,
        abi::ADDR_SPILL_OFFSET,
        abi::ACC_SPILL_OFFSET,
        abi::FRAME_DELTA_OFFSET,
        abi::GROUP_BASE_OFFSET,
      ];
      for i in 0..abi::DERIVED_SLOTS {
        v.push(abi::derived_slot(i));
      }
      v
    };
    for slot in slots {
      assert!(slot < 0, "slot {slot} is not below the frame pointer");
      assert!(
        slot >= -abi::FRAME_RESERVED,
        "slot {slot} is below the {} bytes the prologue reserves",
        abi::FRAME_RESERVED
      );
      assert_eq!(slot % 8, 0, "slot {slot} is not 8-byte aligned");
    }
    assert_eq!(
      abi::FRAME_RESERVED % 16,
      0,
      "the reserved frame is not a multiple of 16, so SP loses its alignment"
    );
  }

  /// No two distinct uses may name the same slot.
  #[test]
  fn the_frame_slots_do_not_overlap() {
    let mut slots = vec![
      abi::FRAME_OFFSET,
      abi::SPILL_OFFSET,
      abi::ADDR_SPILL_OFFSET,
      abi::ACC_SPILL_OFFSET,
      abi::FRAME_DELTA_OFFSET,
      abi::GROUP_BASE_OFFSET,
    ];
    for i in 0..abi::DERIVED_SLOTS {
      slots.push(abi::derived_slot(i));
    }
    let before = slots.len();
    slots.sort_unstable();
    slots.dedup();
    assert_eq!(before, slots.len(), "two frame slots collide: {slots:?}");
  }
}

// ---------------------------------------------------------------------------
// Panic-freedom on hostile input
// ---------------------------------------------------------------------------

unsafe extern "C" fn accept_every_helper(_index: u32, _cookie: *const std::ffi::c_void) -> bool {
  true
}

unsafe extern "C" fn never_called_dispatcher(
  _: u64,
  _: u64,
  _: u64,
  _: u64,
  _: u64,
  _: u32,
  _: *mut std::ffi::c_void,
) -> u64 {
  unreachable!("translation never executes what it emits")
}

unsafe extern "C" fn never_called_resolver(_: u32) -> u64 {
  unreachable!("translation never executes what it emits")
}

/// The nastiest configuration the runtime actually uses: cage on, native frame
/// base on, frame constants on, every helper index accepted.
fn hostile_config(target: Target) -> Arc<Config> {
  Arc::new(Config {
    target,
    pointer_mask: 0x0fff_ffff,
    pointer_offset: 0x1_0000_0000,
    native_frame_base: true,
    frame_constants: true,
    dispatcher: Some(never_called_dispatcher),
    dispatcher_validate: Some(accept_every_helper),
    unwind_helper_index: None,
    local_call_resolver: Some(never_called_resolver),
  })
}

/// xorshift64*, so the corpus is reproducible without a dependency.
struct Rng(u64);

impl Rng {
  fn next(&mut self) -> u64 {
    let mut x = self.0;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    self.0 = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
  }

  fn below(&mut self, n: usize) -> usize {
    (self.next() % n as u64) as usize
  }
}

fn ins(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Insn {
  Insn {
    opcode,
    dst,
    src,
    offset,
    imm,
  }
}

fn interesting_i16(rng: &mut Rng) -> i16 {
  const V: [i16; 9] = [0, 1, -1, 8, 16, 32, -8, i16::MIN, i16::MAX];
  V[rng.below(V.len())]
}

fn interesting_i32(rng: &mut Rng) -> i32 {
  const V: [i32; 11] = [0, 1, -1, 8, 16, 32, 64, 4096, -4096, i32::MIN, i32::MAX];
  V[rng.below(V.len())]
}

/// One well-formed straight-line instruction, drawn from every class the
/// backends lower differently.
fn valid_body_insn(rng: &mut Rng) -> Vec<Insn> {
  const ALU_IMM: [u8; 22] = [
    0x04, 0x14, 0x24, 0x44, 0x54, 0x64, 0x74, 0xa4, 0xb4, 0xc4, 0x07, 0x17, 0x27, 0x47, 0x57, 0x67,
    0x77, 0xa7, 0xb7, 0xc7, 0x34, 0x37,
  ];
  const ALU_REG: [u8; 22] = [
    0x0c, 0x1c, 0x2c, 0x4c, 0x5c, 0x6c, 0x7c, 0xac, 0xbc, 0xcc, 0x0f, 0x1f, 0x2f, 0x4f, 0x5f, 0x6f,
    0x7f, 0xaf, 0xbf, 0xcf, 0x3c, 0x3f,
  ];
  const LDX: [u8; 7] = [0x61, 0x69, 0x71, 0x79, 0x81, 0x89, 0x91];
  const ST: [u8; 4] = [0x62, 0x6a, 0x72, 0x7a];
  const STX: [u8; 4] = [0x63, 0x6b, 0x73, 0x7b];
  const ATOMIC_IMM: [i32; 10] = [0x00, 0x01, 0x40, 0x41, 0x50, 0x51, 0xa0, 0xa1, 0xe1, 0xf1];

  let d = rng.below(10) as u8;
  let s = rng.below(11) as u8;
  match rng.below(10) {
    0 => vec![ins(
      ALU_IMM[rng.below(ALU_IMM.len())],
      d,
      0,
      0,
      interesting_i32(rng),
    )],
    // `movsx` carries the source width in the offset.
    1 => vec![ins(
      if rng.below(2) == 0 { 0xbc } else { 0xbf },
      d,
      s,
      [0, 8, 16][rng.below(3)],
      0,
    )],
    2 => vec![ins(ALU_REG[rng.below(ALU_REG.len())], d, s, 0, 0)],
    3 => vec![ins(
      [0xd4, 0xdc, 0xd7][rng.below(3)],
      d,
      0,
      0,
      [16, 32, 64][rng.below(3)],
    )],
    4 => vec![ins(
      LDX[rng.below(LDX.len())],
      d,
      s,
      interesting_i16(rng),
      0,
    )],
    5 => vec![ins(
      ST[rng.below(ST.len())],
      rng.below(11) as u8,
      0,
      interesting_i16(rng),
      interesting_i32(rng),
    )],
    6 => vec![ins(
      STX[rng.below(STX.len())],
      rng.below(11) as u8,
      s,
      interesting_i16(rng),
      0,
    )],
    7 => vec![ins(
      if rng.below(2) == 0 { 0xc3 } else { 0xdb },
      rng.below(11) as u8,
      rng.below(10) as u8,
      interesting_i16(rng),
      ATOMIC_IMM[rng.below(ATOMIC_IMM.len())],
    )],
    // `lddw` and its high half.
    8 => vec![
      ins(0x18, d, 0, 0, interesting_i32(rng)),
      ins(0x00, 0, 0, 0, interesting_i32(rng)),
    ],
    // A helper call; `accept_every_helper` admits any index.
    _ => vec![ins(0x85, 0, 0, 0, (rng.below(64)) as i32)],
  }
}

/// A program that loads: a body of well-formed instructions, jumps patched to
/// land on a real instruction boundary inside the program, and a trailing exit.
fn valid_program(rng: &mut Rng, target_len: usize) -> Vec<Insn> {
  const JMP_IMM: [u8; 11] = [
    0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0xa5, 0xb5, 0xc5, 0xd5,
  ];
  const JMP_REG: [u8; 11] = [
    0x1d, 0x2d, 0x3d, 0x4d, 0x5d, 0x6d, 0x7d, 0xad, 0xbd, 0xcd, 0xdd,
  ];

  let mut insns: Vec<Insn> = Vec::new();
  // Instruction slots a jump may legally land on: not the high half of a
  // `lddw`, and not the slot the jump itself occupies.
  let mut boundaries: Vec<usize> = Vec::new();
  let mut jump_sites: Vec<usize> = Vec::new();

  while insns.len() < target_len {
    boundaries.push(insns.len());
    if rng.below(5) == 0 {
      jump_sites.push(insns.len());
      let (opcode, src) = match rng.below(4) {
        0 => (0x05u8, 0u8),                          // ja
        1 => (0x06, 0),                              // ja32
        2 => (JMP_IMM[rng.below(JMP_IMM.len())], 0), // conditional, immediate
        _ => (JMP_REG[rng.below(JMP_REG.len())], 1), // conditional, register
      };
      let dst = rng.below(10) as u8;
      let s = if src == 1 { rng.below(11) as u8 } else { 0 };
      let imm = if src == 1 { 0 } else { interesting_i32(rng) };
      insns.push(ins(opcode, dst, s, 0, if opcode == 0x06 { 0 } else { imm }));
    } else {
      insns.extend(valid_body_insn(rng));
    }
  }
  insns.push(ins(0x95, 0, 0, 0, 0)); // exit
  boundaries.push(insns.len() - 1);

  // Patch the jumps to land on a boundary that is neither themselves nor the
  // slot immediately behind them (a displacement of -1 is "infinite loop").
  for site in jump_sites {
    let mut tries = 0;
    loop {
      let landing = boundaries[rng.below(boundaries.len())];
      let displacement = landing as i64 - site as i64 - 1;
      tries += 1;
      if displacement != -1 || tries > 8 {
        let displacement = if displacement == -1 { 1 } else { displacement } as i32;
        // A `ja32` carries the displacement in the immediate, everything else
        // in the offset.
        if insns[site].opcode == 0x06 {
          insns[site].imm = displacement;
        } else {
          insns[site].offset = displacement as i16;
        }
        break;
      }
    }
  }
  // A displacement patched to `1` may now point past the exit; clamp anything
  // out of range back onto the exit itself.
  let last = insns.len() - 1;
  for site in 0..insns.len() {
    let opcode = insns[site].opcode;
    let class = opcode & 0x07;
    if (class != 0x05 && class != 0x06) || opcode == 0x85 || opcode == 0x95 {
      continue;
    }
    let displacement = if opcode == 0x06 {
      insns[site].imm as i64
    } else {
      insns[site].offset as i64
    };
    let landing = site as i64 + 1 + displacement;
    let bad = landing < 0
      || landing >= insns.len() as i64
      || insns[landing as usize].opcode == 0
      || displacement == -1;
    if bad {
      let fixed = last as i64 - site as i64 - 1;
      let fixed = if fixed == -1 { 0 } else { fixed };
      if opcode == 0x06 {
        insns[site].imm = fixed as i32;
      } else {
        insns[site].offset = fixed as i16;
      }
    }
  }
  insns
}

/// A program with local functions: a main body that calls each sub-program,
/// then the sub-programs laid out after it, each ending in `exit`. This is the
/// shape that fills `local_calls`, `pc_locs` and the lazy-resolver table, none
/// of which `valid_program` reaches.
fn program_with_local_calls(rng: &mut Rng, target_len: usize) -> Vec<Insn> {
  let subs = 1 + rng.below(3);
  let mut main: Vec<Insn> = Vec::new();
  for _ in 0..target_len.max(1) {
    if rng.below(3) == 0 {
      // Placeholder for a local call, patched once the layout is known.
      main.push(ins(0x85, 0, 1, 0, 0));
    } else {
      main.extend(valid_body_insn(rng));
    }
  }
  main.push(ins(0x95, 0, 0, 0, 0));

  let mut bodies: Vec<Vec<Insn>> = Vec::new();
  for _ in 0..subs {
    let mut body: Vec<Insn> = Vec::new();
    for _ in 0..1 + rng.below(4) {
      body.extend(valid_body_insn(rng));
    }
    body.push(ins(0x95, 0, 0, 0, 0));
    bodies.push(body);
  }

  let mut starts = Vec::new();
  let mut insns = main;
  for body in bodies {
    starts.push(insns.len());
    insns.extend(body);
  }

  for pc in 0..insns.len() {
    if insns[pc].opcode == 0x85 && insns[pc].src == 1 {
      let target = starts[rng.below(starts.len())];
      insns[pc].imm = (target as i64 - pc as i64 - 1) as i32;
    }
  }
  insns
}

/// Applies exactly one corruption, so the rest of the program stays
/// well-formed and the corrupted instruction is the one under test.
fn mutate(rng: &mut Rng, insns: &mut Vec<Insn>) {
  if insns.is_empty() {
    return;
  }
  let at = rng.below(insns.len());
  match rng.below(8) {
    0 => insns[at].opcode = rng.next() as u8,
    1 => insns[at].dst = rng.below(16) as u8,
    2 => insns[at].src = rng.below(16) as u8,
    3 => insns[at].offset = interesting_i16(rng),
    4 => insns[at].imm = interesting_i32(rng),
    5 => insns[at] = Insn::from_u64(rng.next()),
    6 => {
      if insns.len() > 1 {
        insns.pop();
      }
    }
    _ => {
      let other = rng.below(insns.len());
      insns.swap(at, other);
    }
  }
}

/// Entirely random bytes, for the decoder and the unknown-opcode paths.
fn random_bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
  let mut out = Vec::with_capacity(len * 8);
  for _ in 0..len {
    out.extend_from_slice(&rng.next().to_le_bytes());
  }
  out
}

fn hostile_plan(rng: &mut Rng, len: usize) -> Vec<PlanEntry> {
  (0..len)
    .map(|_| PlanEntry {
      role: (rng.next() % 4) as u8,
      region: (rng.next() % 5) as u8,
      delta: rng.next() as u16,
      span: match rng.below(3) {
        0 => u32::MAX,
        1 => abi::MAX_GROUP_SPAN,
        _ => rng.next() as u32,
      },
      lo: rng.next() as i32,
      leader_pc: match rng.below(3) {
        0 => u32::MAX,
        1 => rng.next() as u32,
        _ => rng.below(len.max(1)) as u32,
      },
    })
    .collect()
}

/// Every combination of hostile bytecode, hostile analysis inputs, hostile
/// buffer size and both targets. A panic anywhere in here is a denial of
/// service reachable from attacker-supplied bytecode, and in a debug build an
/// arithmetic overflow counts.
static LOADED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static TRANSLATED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[test]
fn no_hostile_program_makes_the_translator_panic() {
  // Miri interprets rather than executes, so a sweep sized for native runs
  // takes hours there - this one and the opcode census below timed a CI job out
  // at thirty minutes. CI no longer runs Miri at all, so nothing here depends
  // on these branches; they exist so that running `cargo miri test` by hand
  // stays feasible (the census drops from 23.7 minutes to about 90 seconds)
  // rather than appearing to hang. The coverage floor below scales with the
  // count, so a reduced run still refuses to pass vacuously.
  let iterations: u32 = if cfg!(miri) { 60 } else { 8000 };
  let mut rng = Rng(0x1234_5678_9abc_def0);
  for target in [Target::X86_64, Target::Aarch64] {
    let config = hostile_config(target);
    for iteration in 0..iterations {
      let len = 1 + rng.below(24);
      let code = match iteration % 5 {
        0 => random_bytes(&mut rng, len),
        1 => {
          let mut p = valid_program(&mut rng, len);
          mutate(&mut rng, &mut p);
          Insn::encode_all(&p)
        }
        2 => {
          let mut p = program_with_local_calls(&mut rng, len);
          mutate(&mut rng, &mut p);
          Insn::encode_all(&p)
        }
        3 => Insn::encode_all(&program_with_local_calls(&mut rng, len)),
        _ => Insn::encode_all(&valid_program(&mut rng, len)),
      };

      let Ok(translator) = Translator::load(config.clone(), &code) else {
        continue;
      };
      LOADED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
      let num = translator.insns().len();

      // The runtime always passes a full-program range, but the analysis
      // inputs are attacker-influenced, so vary them freely.
      let hints: Vec<u8> = (0..num).map(|_| (rng.next() % 6) as u8).collect();
      let plan = hostile_plan(&mut rng, num);
      let resolver_ids: Vec<u32> = (0..num).map(|_| rng.next() as u32).collect();

      for buf_len in [0usize, 1, 7, 64, 4096, 1 << 16] {
        let mut buf = vec![0u8; buf_len];
        let inputs = TranslationInputs {
          hints: &hints,
          plan: &plan,
          resolver_ids: &resolver_ids,
          start_pc: 0,
          end_pc: num,
        };
        if translator.translate_range(&inputs, &mut buf).is_ok() {
          TRANSLATED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
      }

      // Truncated analysis inputs: the C indexed these by pc against a length
      // it was told, so a short slice is the classic out-of-bounds.
      let mut buf = vec![0u8; 1 << 16];
      let inputs = TranslationInputs {
        hints: &hints[..num / 2],
        plan: &plan[..num / 2],
        resolver_ids: &resolver_ids[..num / 2],
        start_pc: 0,
        end_pc: num,
      };
      let _ = translator.translate_range(&inputs, &mut buf);
    }
  }
  // A fuzz test whose corpus stops reaching the emitters is worse than no
  // test at all, so assert the coverage rather than hoping for it.
  let loaded = LOADED.load(std::sync::atomic::Ordering::Relaxed);
  let translated = TRANSLATED.load(std::sync::atomic::Ordering::Relaxed);
  // Scales with `iterations` so the floor keeps its meaning under Miri: it is
  // here to catch a generator that quietly stops producing loadable programs,
  // which is how a sweep like this turns green while testing nothing.
  let floor = (iterations as usize) / 4;
  assert!(
    loaded > floor && translated > floor,
    "the generator stopped producing loadable programs: {loaded} loaded, \
     {translated} translated, floor {floor}"
  );
}

/// The same sweep with sub-ranges, including ones that are not function
/// boundaries. `translate_range` is supposed to reject those rather than index
/// past the end of `pc_locs`.
#[test]
fn no_hostile_translation_range_makes_the_translator_panic() {
  let mut rng = Rng(0x0fed_cba9_8765_4321);
  for target in [Target::X86_64, Target::Aarch64] {
    let config = hostile_config(target);
    for _ in 0..1500u32 {
      let len = 1 + rng.below(12);
      let code = Insn::encode_all(&valid_program(&mut rng, len));
      let Ok(translator) = Translator::load(config.clone(), &code) else {
        continue;
      };
      let num = translator.insns().len();
      let mut buf = vec![0u8; 1 << 16];
      for start_pc in 0..=num + 2 {
        for end_pc in 0..=num + 2 {
          let inputs = TranslationInputs {
            hints: &[],
            plan: &[],
            resolver_ids: &[],
            start_pc,
            end_pc,
          };
          let _ = translator.translate_range(&inputs, &mut buf);
        }
      }
    }
  }
}

/// Exhaustive over the whole opcode byte for a single instruction, in every
/// register/offset/immediate corner that has ever mattered.
#[test]
fn every_opcode_byte_loads_or_is_refused_without_panicking() {
  // See `no_hostile_program_makes_the_translator_panic`: under Miri the full
  // cross-product is ~100k load attempts and took 23.7 minutes. Every opcode
  // byte is still covered; only the operand corners per byte are thinned.
  let (dst_src, offsets, imms): (&[(u8, u8)], &[i16], &[i32]) = if cfg!(miri) {
    (&[(0, 0), (10, 10)], &[0, i16::MIN], &[0, i32::MIN])
  } else {
    (
      &[(0, 0), (9, 10), (10, 10), (15, 15), (10, 0)],
      &[0, -1, 1, i16::MIN, i16::MAX],
      &[0, -1, 1, i32::MIN, i32::MAX, 16, 32, 64],
    )
  };
  for target in [Target::X86_64, Target::Aarch64] {
    let config = hostile_config(target);
    for opcode in 0u8..=255 {
      for &(dst, src) in dst_src {
        for &offset in offsets {
          for &imm in imms {
            let insns = [
              Insn {
                opcode,
                dst,
                src,
                offset,
                imm,
              },
              Insn {
                opcode: super::isa::opcode::EXIT,
                dst: 0,
                src: 0,
                offset: 0,
                imm: 0,
              },
            ];
            let code = Insn::encode_all(&insns);
            if let Ok(translator) = Translator::load(config.clone(), &code) {
              let mut buf = vec![0u8; 1 << 14];
              let _ = translator.translate_all(&mut buf);
            }
          }
        }
      }
    }
  }
}

/// `lddw` occupying the last slot: the classic "read one past the end" bug.
/// The validator must refuse it, and if it ever stops doing so the emitters
/// must still not index past the instruction stream.
#[test]
fn a_lddw_in_the_last_slot_is_refused_rather_than_read_past() {
  use super::isa::opcode;
  for target in [Target::X86_64, Target::Aarch64] {
    let config = hostile_config(target);
    for prefix in 0..3usize {
      let mut insns = vec![
        Insn {
          opcode: 0xb7u8,
          dst: 0,
          src: 0,
          offset: 0,
          imm: 0,
        };
        prefix
      ];
      insns.push(Insn {
        opcode: opcode::LDDW,
        dst: 0,
        src: 0,
        offset: 0,
        imm: 1,
      });
      let code = Insn::encode_all(&insns);
      let err = Translator::load(config.clone(), &code)
        .err()
        .expect("a trailing lddw has no high half and must be refused");
      assert_eq!(err.0, format!("incomplete lddw at PC {prefix}"));
    }
  }
}

/// A local `call` whose displacement is at the extremes of the immediate. The
/// C computed the target in `int`; `Translator::load` computes it in `i64` and
/// re-checks. Neither may panic and neither may mark a slot outside the
/// program.
#[test]
fn extreme_local_call_displacements_are_refused_without_overflowing() {
  use super::isa::opcode;
  for target in [Target::X86_64, Target::Aarch64] {
    let config = hostile_config(target);
    for &imm in &[
      i32::MIN,
      i32::MIN + 1,
      -1,
      0,
      1,
      i32::MAX - 1,
      i32::MAX,
      -70000,
      70000,
    ] {
      for pc in 0..3usize {
        let mut insns = vec![
          Insn {
            opcode: 0xb7u8,
            dst: 0,
            src: 0,
            offset: 0,
            imm: 0,
          };
          pc
        ];
        insns.push(Insn {
          opcode: opcode::CALL,
          dst: 0,
          src: 1,
          offset: 0,
          imm,
        });
        insns.push(Insn {
          opcode: opcode::EXIT,
          dst: 0,
          src: 0,
          offset: 0,
          imm: 0,
        });
        let code = Insn::encode_all(&insns);
        // Whatever the answer, it must be an answer.
        if let Ok(t) = Translator::load(config.clone(), &code) {
          let target_pc = pc as i64 + imm as i64 + 1;
          assert!(
            (0..t.insns().len() as i64).contains(&target_pc),
            "load accepted a local call at pc {pc} with imm {imm}, targeting \
             {target_pc}, which is outside the program"
          );
          let mut buf = vec![0u8; 1 << 14];
          let _ = t.translate_all(&mut buf);
        }
      }
    }
  }
}

/// A program at and around the instruction-count ceiling. The C's bound is
/// `>=` and `Translator::load`'s is `>`; together they must reject exactly
/// `MAX_INSTS` and above, and neither may allocate or index off the end.
#[test]
fn the_instruction_ceiling_is_enforced_without_panicking() {
  use super::isa::opcode;
  let config = hostile_config(Target::X86_64);
  for &len in &[
    abi::MAX_INSTS as usize - 1,
    abi::MAX_INSTS as usize,
    abi::MAX_INSTS as usize + 1,
  ] {
    let insns = vec![
      Insn {
        opcode: opcode::EXIT,
        dst: 0,
        src: 0,
        offset: 0,
        imm: 0,
      };
      len
    ];
    let code = Insn::encode_all(&insns);
    let outcome = Translator::load(config.clone(), &code);
    if len >= abi::MAX_INSTS as usize {
      assert!(outcome.is_err(), "{len} instructions must be refused");
    } else {
      assert!(outcome.is_ok(), "{len} instructions must be accepted");
    }
  }
}

/// A code length that is not a multiple of eight, and the empty program.
#[test]
fn malformed_code_lengths_are_refused() {
  let config = hostile_config(Target::X86_64);
  for len in 0..24usize {
    let code = vec![0x95u8; len];
    let outcome = Translator::load(config.clone(), &code);
    if len == 0 {
      assert_eq!(
        outcome.err().map(|e| e.0),
        Some("program is empty".to_string())
      );
    } else if len % 8 != 0 {
      assert_eq!(
        outcome.err().map(|e| e.0),
        Some("code_len must be a multiple of 8".to_string())
      );
    }
  }
}

// ---------------------------------------------------------------------------
// The patch-table ceilings
// ---------------------------------------------------------------------------

/// Every patch table stops growing at the instruction ceiling.
///
/// A program can hold at most [`abi::MAX_INSTS`] instructions, so no correct
/// program needs more fixups than that, and a table allowed to grow further is
/// a table that accepts a program the loader should have refused. These were
/// once `1 << 20` — sixteen times too high — which let a program with between
/// 65536 and 1048575 jump fixups translate into a megabyte of code instead of
/// being refused. Three jump fixups are emitted per helper call, so 21846
/// helper calls was enough to reach it, well inside the instruction ceiling.
#[test]
fn the_patch_table_ceilings_are_the_instruction_ceiling() {
  use super::patch::{MAX_JUMPS, MAX_LEAS, MAX_LOADS, MAX_LOCAL_CALLS};
  let ceiling = abi::MAX_INSTS as usize;
  assert_eq!(MAX_JUMPS, ceiling, "jump table ceiling");
  assert_eq!(MAX_LOADS, ceiling, "load table ceiling");
  assert_eq!(MAX_LEAS, ceiling, "lea table ceiling");
  assert_eq!(MAX_LOCAL_CALLS, ceiling, "local call table ceiling");
}

/// A program of nothing but helper calls, sized so that the jump-fixup table
/// crosses the ceiling above.
fn helper_call_storm(calls: usize) -> Vec<u8> {
  let mut insns: Vec<Insn> = (0..calls).map(|_| ins(0x85, 0, 0, 0, 1)).collect();
  insns.push(ins(0x95, 0, 0, 0, 0));
  Insn::encode_all(&insns)
}

/// The executed form of the test above: a program that really does overrun the
/// jump-fixup table has to be refused, by name, rather than translated.
///
/// The ceiling is a number in one file and the refusal is a code path in
/// another; this is what ties them together.
#[test]
fn a_jump_fixup_storm_is_refused() {
  // Three jump fixups per helper call: the jcc past the default dispatcher,
  // the jmp past the external one, and the retpoline call. Two calls past the
  // ceiling divided by three is the smallest program that overruns it.
  let calls = abi::MAX_INSTS as usize / 3 + 2;
  let code = helper_call_storm(calls);
  let config = hostile_config(Target::X86_64);

  let translator = Translator::load(config, &code).expect("the program must load");
  let inputs = TranslationInputs {
    hints: &[],
    plan: &[],
    resolver_ids: &[],
    start_pc: 0,
    end_pc: translator.insns().len(),
  };
  let mut buf = vec![0u8; 1 << 24];
  let outcome = translator.translate_range(&inputs, &mut buf);

  // The wording embedders see, and the reason it is this one: the table that
  // overflowed is the jump table.
  assert_eq!(
    outcome,
    Err(super::TranslateError::Failed(
      "Too many jump instructions".to_string()
    )),
    "a {calls}-helper-call program emits {} jump fixups against a ceiling of {}",
    calls * 3,
    abi::MAX_INSTS
  );

  // ...and the same program one call shorter still fits, so the refusal is the
  // ceiling and not merely "large programs fail".
  let code = helper_call_storm(abi::MAX_INSTS as usize / 3 - 1);
  let translator = Translator::load(hostile_config(Target::X86_64), &code).expect("must load");
  let inputs = TranslationInputs {
    hints: &[],
    plan: &[],
    resolver_ids: &[],
    start_pc: 0,
    end_pc: translator.insns().len(),
  };
  assert!(
    translator.translate_range(&inputs, &mut buf).is_ok(),
    "a program just inside the ceiling must still translate"
  );
}

// ---------------------------------------------------------------------------
// Progress::into_error
// ---------------------------------------------------------------------------

/// `Progress::into_error` is reached from exactly one place: the `other` arm of
/// `x86_64::Emit::status_error`. Its strings are the ones an embedder sees when
/// a program is refused, so they are part of the interface and are pinned here
/// character for character rather than left to whatever the code happens to
/// say. Two of them were wrong once, and this is what would have caught it.
#[test]
fn into_error_reports_the_documented_strings() {
  use super::patch::Progress;
  use super::TranslateError::{Failed, OutOfSpace};

  assert_eq!(Progress::Ok.into_error(crate::jit::Target::X86_64), None);
  assert_eq!(
    Progress::NotEnoughSpace.into_error(crate::jit::Target::X86_64),
    Some(OutOfSpace)
  );
  assert_eq!(
    Progress::TooManyJumps.into_error(crate::jit::Target::X86_64),
    Some(Failed("Too many jump instructions".into()))
  );
  assert_eq!(
    Progress::TooManyLoads.into_error(crate::jit::Target::X86_64),
    Some(Failed("Too many load instructions".into()))
  );
  assert_eq!(
    Progress::TooManyLocalCalls.into_error(crate::jit::Target::X86_64),
    Some(Failed("Too many local calls".into()))
  );
  // "Too many LEA calculations", not "Too many lea instructions": the wording
  // is deliberately not parallel with the three above.
  assert_eq!(
    Progress::TooManyLeas.into_error(crate::jit::Target::X86_64),
    Some(Failed("Too many LEA calculations".into()))
  );
  // Empty on purpose. An out-of-range relocation is only ever reported by the
  // aarch64 resolver, which writes its own message where the error is detected
  // — it has the pc and the opcode, and this does not — and does not come
  // through `into_error` at all.
  assert_eq!(
    Progress::RelocationOutOfRange.into_error(crate::jit::Target::X86_64),
    Some(Failed(String::new()))
  );
}

// ---------------------------------------------------------------------------
// Constants restated in more than one module
// ---------------------------------------------------------------------------

/// `abi::region` says its values "are shared with `crate::region_analysis`",
/// and `abi::plan_role` mirrors the analysis's roles. Neither is actually
/// shared: both are declared twice. `program.rs` ties only `MAX_GROUP_SPAN`.
/// A drift here reroutes an access — and `region::FRAME` is the hint that
/// suppresses the bounds check entirely.
#[test]
fn the_region_and_plan_constants_agree_with_the_analysis() {
  use crate::region_analysis as ra;
  assert_eq!(abi::region::UNKNOWN, ra::REGION_UNKNOWN);
  assert_eq!(abi::region::STACK, ra::REGION_STACK);
  assert_eq!(abi::region::DATA, ra::REGION_DATA);
  assert_eq!(abi::region::FRAME, ra::REGION_FRAME);
  assert_eq!(abi::plan_role::LEADER, ra::PLAN_ROLE_LEADER);
  assert_eq!(abi::plan_role::MEMBER, ra::PLAN_ROLE_MEMBER);
  assert_eq!(abi::MAX_GROUP_SPAN as i32, ra::MAX_GROUP_SPAN);
}

/// `JitMemory`'s `const _` block pins its field offsets with literals rather
/// than with `abi::memory::*`. Restate the tie here, where it can be checked.
#[test]
fn the_memory_descriptor_offsets_are_the_ones_abi_names() {
  assert_eq!(abi::memory::STACK_GUEST_BOTTOM, 0);
  assert_eq!(abi::memory::STACK_GUEST_TOP, 8);
  assert_eq!(abi::memory::STACK_NATIVE_BASE, 16);
  assert_eq!(abi::memory::DATA_GUEST_BOTTOM, 24);
  assert_eq!(abi::memory::DATA_GUEST_TOP, 32);
  assert_eq!(abi::memory::DATA_NATIVE_BASE, 40);
  // The derived block begins immediately after the six descriptor fields and
  // is exactly `DERIVED_SLOTS` words long; the trampolines copy it wholesale.
  assert_eq!(abi::DERIVED_SLOTS * 8 + 48, 144);
}

// ---------------------------------------------------------------------------
// icache: the CTR_EL0 decode
// ---------------------------------------------------------------------------

/// `icache.rs`'s aarch64 module is `#[cfg(target_arch = "aarch64")]`, so on an
/// x86_64 host nothing in it is even compiled. This pins the arithmetic the
/// comment there documents — `DminLine` at bits 19:16, `IminLine` at bits 3:0,
/// each `log2` of the line size in *words* — against real `CTR_EL0` values, so
/// a transposition of the two fields is caught on every host rather than only
/// on the one whose D and I line sizes happen to differ.
#[test]
fn the_ctr_el0_decode_matches_real_hardware() {
  fn decode(ctr: u64) -> (usize, usize) {
    let dmin = 4usize << ((ctr >> 16) & 0xf);
    let imin = 4usize << (ctr & 0xf);
    (dmin, imin)
  }

  // Apple M1 (DminLine = 4 -> 64B, IminLine = 4 -> 64B).
  assert_eq!(decode(0x8444_c004), (64, 64));
  // Cortex-A72 / Graviton (both 64B).
  assert_eq!(decode(0x8444_c004).0, 64);
  // A part whose two line sizes differ: DminLine = 4 (64B), IminLine = 3
  // (32B). Swapping the two fields would give (32, 64) here.
  assert_eq!(decode(0x8404_c003), (64, 32));
  // The extremes of both fields.
  assert_eq!(decode(0x0000_0000), (4, 4));
  assert_eq!(decode(0x000f_000f), (4 << 15, 4 << 15));

  for ctr in [0x8444_c004u64, 0x8404_c003, 0x0000_0000] {
    let (d, i) = decode(ctr);
    assert!(d.is_power_of_two() && i.is_power_of_two());
    assert!(d >= 4 && i >= 4);
  }
}

/// The rounding both loops in `icache::clear` use, restated as a property: the
/// half-open range `[start & !(line-1), end)` stepped by `line` must touch the
/// line containing every byte of `[start, start + size)`.
#[test]
fn the_icache_loop_rounding_covers_every_line_of_an_unaligned_range() {
  for &line in &[4usize, 32, 64, 128, 2048] {
    for &start in &[0usize, 1, 3, 63, 64, 65, 4095, 0x1_0000_0003] {
      for &size in &[1usize, 3, 4, 63, 64, 65, 4096, 4090] {
        let end = start + size;
        let mut covered = start & !(line - 1);
        let mut lines = Vec::new();
        while covered < end {
          lines.push(covered);
          covered += line;
        }
        for byte in [start, start + size / 2, end - 1] {
          let want = byte & !(line - 1);
          assert!(
            lines.contains(&want),
            "line {want:#x} containing byte {byte:#x} is not maintained for \
             start={start:#x} size={size} line={line}"
          );
        }
      }
    }
  }
}

/// `icache::clear` on aarch64 is the one thing here that can only be checked on
/// the machine it targets.
#[cfg(target_arch = "aarch64")]
#[test]
fn the_host_reports_a_sane_cache_geometry() {
  let ctr: u64;
  // SAFETY: CTR_EL0 is readable from EL0, or emulated by the kernel.
  unsafe {
    std::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack));
  }
  let dmin = 4usize << ((ctr >> 16) & 0xf);
  let imin = 4usize << (ctr & 0xf);
  assert!(
    (4..=2048).contains(&dmin) && (4..=2048).contains(&imin),
    "CTR_EL0 = {ctr:#x} decodes to implausible line sizes {dmin}/{imin}; \
     `icache::clear` would round the range start outside the mapping"
  );
}

#![allow(dead_code)]

use std::{
  sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
  },
  time::Duration,
};

use async_ebpf::{
  helpers::Helper,
  program::{DummyProgramEventListener, GlobalEnv, HelperScope, PreemptionEnabled, ProgramLoader},
  test_util::{region_analysis as ra, timeslice_config, TokioTimeslicer},
};
use rand::{rngs::StdRng, SeedableRng};

const MAX_INSNS: usize = 96;
const MAX_REGION_INSNS: usize = 128;
const REGION_DATA_LO: u64 = 0x10000;
const REGION_DATA_HI: u64 = 0x20000;
const SENTINEL_VALUE: u64 = 0x5147_494a_5f53_4146;
const SENTINEL_ATTACK_VALUE: u64 = 0xa55a_0000_dead_beef;

static HOST_SENTINEL: AtomicU64 = AtomicU64::new(SENTINEL_VALUE);
static HELPERS: &'static [(&'static str, Helper)] = &[("leak_host_ptr", leak_host_ptr)];

pub fn run_memory_safety_case(data: &[u8]) {
  let code = generated_program(data, false);
  run_program(&code, data);
}

pub fn run_host_pointer_escape_case(data: &[u8]) {
  HOST_SENTINEL.store(SENTINEL_VALUE, Ordering::SeqCst);
  let code = generated_program(data, true);
  let _ = run_program(&code, data);
  assert_eq!(HOST_SENTINEL.load(Ordering::SeqCst), SENTINEL_VALUE);
}

pub fn run_region_analysis_case(data: &[u8]) {
  region_analysis_smoke(data);
  region_unreachable_tail_is_ignored(data);
  region_current_stack_alias_tracking(data);
  region_current_stack_overwrite_invalidates(data);
  region_foreign_stack_store_preserves_current_frame_spill(data);
  region_local_call_signature_foreignizes_stack_args(data);
  region_pointer_tag_polymorphism(data);
}

fn run_program(code: &[Insn], data: &[u8]) -> Option<i64> {
  let elf = build_elf(code, &["leak_host_ptr"]);
  let mut rng = StdRng::seed_from_u64(seed(data));
  let loader = ProgramLoader::new(&mut rng, Arc::new(DummyProgramEventListener), &[HELPERS]);
  let program = loader.load(&mut rng, &elf).ok()?;

  let global = unsafe { GlobalEnv::new() };
  let thread = global.init_thread(Duration::from_millis(100));
  let program = program.pin_to_current_thread(thread);
  let mut resources: [&mut dyn std::any::Any; 0] = [];
  let calldata_len = data.len().min(512);
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_time()
    .build()
    .ok()?;

  runtime
    .block_on(program.run(
      &timeslice_config(),
      &TokioTimeslicer,
      "test",
      &mut resources,
      &data[..calldata_len],
      &PreemptionEnabled::new(thread),
    ))
    .ok()
}

fn region_analysis_smoke(data: &[u8]) {
  let code = insns_to_bytes(&generated_region_program(data));
  let slots = code.len() / 8;
  let section = ra::analyze_section(&code, REGION_DATA_LO, REGION_DATA_HI);
  assert_region_result(&section.hints, &section.unresolved, slots);

  if slots > 0 {
    let start = data.first().copied().unwrap_or(0) as usize % slots;
    let available = slots - start;
    let len = 1 + data.get(1).copied().unwrap_or(0) as usize % available;
    let function = ra::analyze_function(
      &code,
      start,
      start + len,
      ra::entry_signature(),
      REGION_DATA_LO,
      REGION_DATA_HI,
    );
    assert_region_result(&function.hints, &function.unresolved, slots);
    for (pc, _) in function.call_signatures {
      assert!(pc >= start && pc < start + len);
    }
  }
}

fn region_unreachable_tail_is_ignored(data: &[u8]) {
  let mut code = vec![
    Insn::exit(),
    Insn::ldx_dw(0, 4, skew_i16(data, 0)),
    Insn::stx_dw(5, 4, skew_i16(data, 1)),
    Insn::mov64_reg(1, 4),
    Insn::ldx_b(0, 1, skew_i16(data, 2)),
  ];
  append_random_dead_tail(&mut code, data);
  let bytes = insns_to_bytes(&code);

  let section = ra::analyze_section(&bytes, REGION_DATA_LO, REGION_DATA_HI);
  assert!(
    section.unresolved.is_empty(),
    "unreachable section slots were reported unresolved: {:?}",
    section.unresolved
  );

  let function = ra::analyze_function(
    &bytes,
    0,
    code.len(),
    ra::entry_signature(),
    REGION_DATA_LO,
    REGION_DATA_HI,
  );
  assert!(
    function.unresolved.is_empty(),
    "unreachable function slots were reported unresolved: {:?}",
    function.unresolved
  );
}

fn region_current_stack_alias_tracking(data: &[u8]) {
  let buffer_off = -64 - ((byte(data, 0) % 32) as i32);
  let write_off = (byte(data, 1) % 8) as i16;
  let code = vec![
    Insn::mov64_reg(6, 10),
    Insn::add64_imm(6, buffer_off),
    Insn::stx_dw(10, 6, -8),
    Insn::call_helper(1),
    Insn::mov64_reg(7, 10),
    Insn::add64_imm(7, buffer_off),
    Insn::st_b(7, write_off, byte(data, 2) as i32),
    Insn::ldx_dw(1, 10, -8),
    Insn::ldx_b(0, 1, write_off),
    Insn::exit(),
  ];
  let bytes = insns_to_bytes(&code);
  let result = ra::analyze_section(&bytes, REGION_DATA_LO, REGION_DATA_HI);
  assert_eq!(result.hints[8], ra::STACK);
  assert!(
    result.unresolved.is_empty(),
    "stack alias tracking lost a routable pointer: {:?}",
    result.unresolved
  );
}

fn region_current_stack_overwrite_invalidates(data: &[u8]) {
  let code = vec![
    Insn::mov64_reg(6, 10),
    Insn::add64_imm(6, -64 - ((byte(data, 0) % 32) as i32)),
    Insn::stx_dw(10, 6, -8),
    Insn::mov64_reg(7, 10),
    Insn::add64_imm(7, -8 + ((byte(data, 1) % 7) as i32)),
    Insn::st_b(7, 0, byte(data, 2) as i32),
    Insn::ldx_dw(1, 10, -8),
    Insn::ldx_b(0, 1, 0),
    Insn::exit(),
  ];
  let bytes = insns_to_bytes(&code);
  let result = ra::analyze_section(&bytes, REGION_DATA_LO, REGION_DATA_HI);
  assert_eq!(result.hints[7], ra::UNKNOWN);
  assert!(
    result.unresolved.contains(&7),
    "overwritten pointer spill was still treated as routable: {:?}",
    result.unresolved
  );
}

fn region_foreign_stack_store_preserves_current_frame_spill(data: &[u8]) {
  let code = vec![
    Insn::stx_dw(10, 1, -8),
    Insn::add64_imm(1, (byte(data, 0) % 8) as i32),
    Insn::st_b(1, skew_i16(data, 1), byte(data, 2) as i32),
    Insn::ldx_dw(2, 10, -8),
    Insn::ldx_b(0, 2, skew_i16(data, 3)),
    Insn::exit(),
  ];
  let bytes = insns_to_bytes(&code);
  let result = ra::analyze_function(
    &bytes,
    0,
    code.len(),
    signature_with_r1(ra::PointerTag::ForeignStack),
    REGION_DATA_LO,
    REGION_DATA_HI,
  );
  assert_eq!(result.hints[4], ra::STACK);
  assert!(
    result.unresolved.is_empty(),
    "foreign stack write invalidated a current-frame spill: {:?}",
    result.unresolved
  );
}

fn region_local_call_signature_foreignizes_stack_args(data: &[u8]) {
  let callee_start = 5usize;
  let call_imm = callee_start as i32 - 3;
  let code = vec![
    Insn::mov64_reg(1, 10),
    Insn::add64_imm(1, -96 - ((byte(data, 0) % 32) as i32)),
    Insn::call_local(call_imm),
    Insn::mov64_imm(0, 0),
    Insn::exit(),
    Insn::stx_dw(10, 1, -8),
    Insn::st_b(1, skew_i16(data, 1), byte(data, 2) as i32),
    Insn::ldx_dw(2, 10, -8),
    Insn::ldx_b(0, 2, skew_i16(data, 3)),
    Insn::exit(),
  ];
  let bytes = insns_to_bytes(&code);
  let caller = ra::analyze_function(
    &bytes,
    0,
    callee_start,
    ra::entry_signature(),
    REGION_DATA_LO,
    REGION_DATA_HI,
  );
  let Some((_, callee_signature)) = caller.call_signatures.first().copied() else {
    panic!("local call signature was not recorded");
  };
  let callee = ra::analyze_function(
    &bytes,
    callee_start,
    code.len(),
    callee_signature,
    REGION_DATA_LO,
    REGION_DATA_HI,
  );
  assert_eq!(callee.hints[8], ra::STACK);
  assert!(
    callee.unresolved.is_empty(),
    "callee lost caller-frame stack provenance: {:?}",
    callee.unresolved
  );
}

fn region_pointer_tag_polymorphism(data: &[u8]) {
  let mut code = Vec::new();
  push_lddw(&mut code, 6, REGION_DATA_LO + 0x40 + (byte(data, 0) as u64));
  code.extend([
    Insn::stx_dw(10, 1, -8),
    Insn::ldx_dw(2, 10, -8),
    Insn::add64_imm(2, (byte(data, 1) % 8) as i32),
    Insn::ldx_b(0, 2, 0),
    Insn::exit(),
  ]);
  let bytes = insns_to_bytes(&code);

  let stack = ra::analyze_function(
    &bytes,
    2,
    code.len(),
    signature_with_r1(ra::PointerTag::ForeignStack),
    REGION_DATA_LO,
    REGION_DATA_HI,
  );
  assert_eq!(stack.hints[5], ra::STACK);
  assert!(stack.unresolved.is_empty());

  let data_region = ra::analyze_function(
    &bytes,
    2,
    code.len(),
    signature_with_r1(ra::PointerTag::Data),
    REGION_DATA_LO,
    REGION_DATA_HI,
  );
  assert_eq!(data_region.hints[5], ra::DATA);
  assert!(data_region.unresolved.is_empty());
}

fn generated_region_program(data: &[u8]) -> Vec<Insn> {
  let mut out = Vec::with_capacity(MAX_REGION_INSNS);
  let mut chunks = data.chunks_exact(4);
  for chunk in chunks.by_ref().take(MAX_REGION_INSNS - 2) {
    match chunk[0] % 32 {
      0 => out.push(Insn::mov64_imm(
        chunk[1] % 11,
        i16::from_le_bytes([chunk[2], chunk[3]]) as i32,
      )),
      1 => out.push(Insn::mov64_reg(chunk[1] % 11, chunk[2] % 11)),
      2 => out.push(Insn::add64_imm(chunk[1] % 11, small_i32(chunk[2]))),
      3 => out.push(Insn::sub64_imm(chunk[1] % 11, small_i32(chunk[2]))),
      4 => out.push(Insn::ldx_dw(
        chunk[1] % 11,
        chunk[2] % 11,
        skew_i16(chunk, 3),
      )),
      5 => out.push(Insn::ldx_b(
        chunk[1] % 11,
        chunk[2] % 11,
        skew_i16(chunk, 3),
      )),
      6 => out.push(Insn::stx_dw(
        chunk[1] % 11,
        chunk[2] % 11,
        skew_i16(chunk, 3),
      )),
      7 => out.push(Insn::st_b(
        chunk[1] % 11,
        skew_i16(chunk, 2),
        chunk[3] as i32,
      )),
      8 => out.push(Insn::call_helper((chunk[1] % 7) as i32)),
      9 => {
        if out.len() + 2 < MAX_REGION_INSNS {
          push_lddw(
            &mut out,
            chunk[1] % 11,
            REGION_DATA_LO + ((chunk[2] as u64) << 4) + (chunk[3] as u64),
          );
        }
      }
      10 => out.push(Insn::jeq_imm(
        chunk[1] % 11,
        chunk[2] as i32,
        bounded_branch(chunk[3]),
      )),
      11 => out.push(Insn::ja(bounded_branch(chunk[3]))),
      12 => out.push(Insn::and64_imm(chunk[1] % 11, chunk[2] as i32)),
      13 => out.push(Insn::or64_imm(chunk[1] % 11, chunk[2] as i32)),
      14 => out.push(Insn::xor64_imm(chunk[1] % 11, chunk[2] as i32)),
      15 => out.push(Insn::lsh64_imm(chunk[1] % 11, (chunk[2] & 63) as i32)),
      16 => out.push(Insn::rsh64_imm(chunk[1] % 11, (chunk[2] & 63) as i32)),
      17 => out.push(Insn::atomic_add_dw(
        chunk[1] % 11,
        chunk[2] % 11,
        skew_i16(chunk, 3),
        false,
      )),
      18 => out.push(Insn::atomic_add_dw(
        chunk[1] % 11,
        chunk[2] % 11,
        skew_i16(chunk, 3),
        true,
      )),
      19 => out.push(Insn::ldx_w_sx(
        chunk[1] % 11,
        chunk[2] % 11,
        skew_i16(chunk, 3),
      )),
      20 => out.push(Insn::ldx_h_sx(
        chunk[1] % 11,
        chunk[2] % 11,
        skew_i16(chunk, 3),
      )),
      21 => out.push(Insn::ldx_b_sx(
        chunk[1] % 11,
        chunk[2] % 11,
        skew_i16(chunk, 3),
      )),
      22 => out.push(Insn::exit()),
      _ => {
        out.push(Insn::mov64_reg(6, 10));
        out.push(Insn::add64_imm(6, -8 - ((chunk[1] % 64) as i32)));
      }
    }
    if out.len() >= MAX_REGION_INSNS - 2 {
      break;
    }
  }
  out.truncate(MAX_REGION_INSNS - 1);
  out.push(Insn::exit());
  out
}

fn assert_region_result(hints: &[u8], unresolved: &[usize], slots: usize) {
  assert_eq!(hints.len(), slots);
  let mut previous = None;
  for &pc in unresolved {
    assert!(pc < slots);
    if let Some(previous) = previous {
      assert!(previous < pc, "unresolved slots are not sorted and unique");
    }
    previous = Some(pc);
  }
  for &hint in hints {
    assert!(hint == ra::UNKNOWN || hint == ra::STACK || hint == ra::DATA || hint == ra::FRAME);
  }
}

fn signature_with_r1(tag: ra::PointerTag) -> ra::FunctionSignature {
  let mut tags = [ra::PointerTag::Uninit; ra::NUM_REGS];
  tags[1] = tag;
  tags[10] = ra::PointerTag::CurrentStack(0);
  ra::signature_from_tags(tags)
}

fn push_lddw(out: &mut Vec<Insn>, dst: u8, imm: u64) {
  out.push(Insn::raw(0x18, dst, 0, 0, imm as u32 as i32));
  out.push(Insn::raw(0, 0, 0, 0, (imm >> 32) as u32 as i32));
}

fn append_random_dead_tail(out: &mut Vec<Insn>, data: &[u8]) {
  for chunk in data.chunks_exact(3).take(8) {
    match chunk[0] % 4 {
      0 => out.push(Insn::ldx_dw(
        chunk[1] % 11,
        chunk[2] % 11,
        skew_i16(chunk, 0),
      )),
      1 => out.push(Insn::stx_dw(
        chunk[1] % 11,
        chunk[2] % 11,
        skew_i16(chunk, 0),
      )),
      2 => out.push(Insn::call_helper(chunk[1] as i32)),
      _ => out.push(Insn::exit()),
    }
  }
}

fn insns_to_bytes(insns: &[Insn]) -> Vec<u8> {
  insns
    .iter()
    .flat_map(|insn| insn.value.to_le_bytes())
    .collect()
}

fn byte(data: &[u8], index: usize) -> u8 {
  data.get(index).copied().unwrap_or(0)
}

fn small_i32(byte: u8) -> i32 {
  (byte as i32 % 33) - 16
}

fn skew_i16(data: &[u8], index: usize) -> i16 {
  (byte(data, index) as i16 % 33) - 16
}

fn bounded_branch(byte: u8) -> i16 {
  (byte as i16 % 5) - 2
}

fn generated_program(data: &[u8], include_host_pointer_attack: bool) -> Vec<Insn> {
  let mut out = Vec::with_capacity(MAX_INSNS);

  if include_host_pointer_attack {
    out.push(Insn::call("leak_host_ptr"));
    out.push(Insn::mov64_reg(1, 0));
    out.push(Insn::mov64_imm(2, SENTINEL_ATTACK_VALUE as i32));
    out.push(Insn::stx_dw(1, 2, 0));
  }

  let mut chunks = data.chunks_exact(4);
  for chunk in chunks
    .by_ref()
    .take(MAX_INSNS.saturating_sub(out.len() + 1))
  {
    let op = chunk[0] % 24;
    let imm = i16::from_le_bytes([chunk[1], chunk[2]]) as i32;
    let small = ((chunk[3] % 96) as i16) - 48;
    match op {
      0 => out.push(Insn::mov64_imm(0, imm)),
      1 => {
        out.push(Insn::mov64_reg(2, 10));
        out.push(Insn::add64_imm(2, -8 - ((chunk[3] % 64) as i32)));
        out.push(Insn::ldx_dw(0, 2, small));
      }
      2 => {
        out.push(Insn::mov64_reg(2, 10));
        out.push(Insn::add64_imm(2, -8 - ((chunk[3] % 64) as i32)));
        out.push(Insn::mov64_imm(3, imm));
        out.push(Insn::stx_dw(2, 3, small));
      }
      3 => {
        out.push(Insn::mov64_imm(2, imm));
        out.push(Insn::ldx_dw(0, 2, small));
      }
      4 => {
        out.push(Insn::mov64_imm(2, imm));
        out.push(Insn::mov64_imm(3, imm.rotate_left(7)));
        out.push(Insn::stx_dw(2, 3, small));
      }
      5 => {
        out.push(Insn::mov64_reg(2, 1));
        out.push(Insn::add64_imm(2, imm));
        out.push(Insn::ldx_b(0, 2, small));
      }
      6 => {
        out.push(Insn::mov64_reg(2, 1));
        out.push(Insn::add64_imm(2, imm));
        out.push(Insn::st_b(2, small, chunk[3] as i32));
      }
      7 => out.push(Insn::add64_imm(0, imm)),
      8 => out.push(Insn::xor64_imm(0, imm)),
      9 => out.push(Insn::and64_imm(0, imm | 1)),
      10 => out.push(Insn::or64_imm(0, imm)),
      11 => {
        out.push(Insn::mov64_imm(2, imm));
        out.push(Insn::jeq_imm(2, imm, 1));
        out.push(Insn::mov64_imm(0, imm.wrapping_neg()));
      }
      12 => {
        out.push(Insn::mov64_reg(2, 10));
        out.push(Insn::add64_imm(2, -8));
        out.push(Insn::st_dw(2, 0, imm));
        out.push(Insn::ldx_dw(0, 2, 0));
      }
      13 => out.push(Insn::call("leak_host_ptr")),
      14 => out.push(Insn::mov64_reg(0, 1)),
      15 => out.push(Insn::mov64_reg(0, 10)),
      16 => out.push(Insn::lsh64_imm(0, (chunk[3] & 63) as i32)),
      17 => out.push(Insn::rsh64_imm(0, (chunk[3] & 63) as i32)),
      18 => {
        out.push(Insn::mov64_reg(2, 10));
        out.push(Insn::add64_imm(2, -8 - ((chunk[3] % 64) as i32)));
        out.push(Insn::ldx_w_sx(0, 2, small));
      }
      19 => {
        out.push(Insn::mov64_reg(2, 10));
        out.push(Insn::add64_imm(2, -8 - ((chunk[3] % 64) as i32)));
        out.push(Insn::ldx_h_sx(0, 2, small));
      }
      20 => {
        out.push(Insn::mov64_reg(2, 10));
        out.push(Insn::add64_imm(2, -8 - ((chunk[3] % 64) as i32)));
        out.push(Insn::ldx_b_sx(0, 2, small));
      }
      21 => {
        out.push(Insn::mov64_reg(2, 10));
        out.push(Insn::add64_imm(2, -8));
        out.push(Insn::mov64_imm(3, imm));
        out.push(Insn::atomic_add_dw(2, 3, 0, false));
      }
      22 => {
        out.push(Insn::mov64_reg(2, 10));
        out.push(Insn::add64_imm(2, -8));
        out.push(Insn::mov64_imm(3, imm));
        out.push(Insn::atomic_add_dw(2, 3, 0, true));
      }
      _ => out.push(Insn::rsh64_imm(0, (chunk[3] & 63) as i32)),
    }
    if out.len() >= MAX_INSNS - 1 {
      break;
    }
  }

  out.truncate(MAX_INSNS - 1);
  out.push(Insn::exit());
  out
}

fn seed(data: &[u8]) -> u64 {
  let mut seed = 0xcbf2_9ce4_8422_2325u64;
  for &byte in data.iter().take(64) {
    seed ^= byte as u64;
    seed = seed.wrapping_mul(0x1000_0000_01b3);
  }
  seed
}

fn leak_host_ptr(_: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
  Ok((&HOST_SENTINEL as *const AtomicU64) as u64)
}

#[derive(Clone)]
struct Insn {
  value: u64,
  reloc: Option<&'static str>,
}

impl Insn {
  fn raw(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Self {
    Self {
      value: opcode as u64
        | ((dst as u64) << 8)
        | ((src as u64) << 12)
        | ((offset as u16 as u64) << 16)
        | ((imm as u32 as u64) << 32),
      reloc: None,
    }
  }

  fn exit() -> Self {
    Self::raw(0x95, 0, 0, 0, 0)
  }

  fn call(name: &'static str) -> Self {
    Self {
      value: Self::raw(0x85, 0, 1, 0, 0).value,
      reloc: Some(name),
    }
  }

  fn mov64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0xb7, dst, 0, 0, imm)
  }

  fn mov64_reg(dst: u8, src: u8) -> Self {
    Self::raw(0xbf, dst, src, 0, 0)
  }

  fn add64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x07, dst, 0, 0, imm)
  }

  fn sub64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x17, dst, 0, 0, imm)
  }

  fn and64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x57, dst, 0, 0, imm)
  }

  fn or64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x47, dst, 0, 0, imm)
  }

  fn xor64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0xa7, dst, 0, 0, imm)
  }

  fn lsh64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x67, dst, 0, 0, imm)
  }

  fn rsh64_imm(dst: u8, imm: i32) -> Self {
    Self::raw(0x77, dst, 0, 0, imm)
  }

  fn jeq_imm(dst: u8, imm: i32, offset: i16) -> Self {
    Self::raw(0x15, dst, 0, offset, imm)
  }

  fn ja(offset: i16) -> Self {
    Self::raw(0x05, 0, 0, offset, 0)
  }

  fn call_helper(imm: i32) -> Self {
    Self::raw(0x85, 0, 0, 0, imm)
  }

  fn call_local(imm: i32) -> Self {
    Self::raw(0x85, 0, 1, 0, imm)
  }

  fn ldx_dw(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x79, dst, src, offset, 0)
  }

  fn ldx_b(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x71, dst, src, offset, 0)
  }

  fn ldx_w_sx(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x81, dst, src, offset, 0)
  }

  fn ldx_h_sx(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x89, dst, src, offset, 0)
  }

  fn ldx_b_sx(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x91, dst, src, offset, 0)
  }

  fn stx_dw(dst: u8, src: u8, offset: i16) -> Self {
    Self::raw(0x7b, dst, src, offset, 0)
  }

  fn st_dw(dst: u8, offset: i16, imm: i32) -> Self {
    Self::raw(0x7a, dst, 0, offset, imm)
  }

  fn st_b(dst: u8, offset: i16, imm: i32) -> Self {
    Self::raw(0x72, dst, 0, offset, imm)
  }

  fn atomic_add_dw(dst: u8, src: u8, offset: i16, fetch: bool) -> Self {
    let imm = if fetch { 0x01 } else { 0x00 };
    Self::raw(0xdb, dst, src, offset, imm)
  }
}

fn build_elf(code: &[Insn], external_symbols: &[&'static str]) -> Vec<u8> {
  const SHN_UNDEF: u16 = 0;
  const SHT_PROGBITS: u32 = 1;
  const SHT_SYMTAB: u32 = 2;
  const SHT_STRTAB: u32 = 3;
  const SHT_REL: u32 = 9;
  const SHF_ALLOC: u64 = 1 << 1;
  const SHF_EXECINSTR: u64 = 1 << 2;
  const R_BPF_64_32: u64 = 10;

  let shstrtab = Vec::from(&b"\0test\0.reltest\0.symtab\0.strtab\0.shstrtab\0"[..]);
  let name_test = 1u32;
  let name_reltest = 6u32;
  let name_symtab = 15u32;
  let name_strtab = 23u32;
  let name_shstrtab = 31u32;

  let mut strtab = vec![0u8];
  let symbol_name_offsets: Vec<u32> = external_symbols
    .iter()
    .map(|name| {
      let offset = strtab.len() as u32;
      strtab.extend_from_slice(name.as_bytes());
      strtab.push(0);
      offset
    })
    .collect();

  let mut text = Vec::with_capacity(code.len() * 8);
  let mut rels = Vec::new();
  for (index, insn) in code.iter().enumerate() {
    text.extend_from_slice(&insn.value.to_le_bytes());
    if let Some(name) = insn.reloc {
      let sym = external_symbols
        .iter()
        .position(|candidate| *candidate == name)
        .map(|i| i + 1)
        .unwrap_or(0);
      let r_info = ((sym as u64) << 32) | R_BPF_64_32;
      rels.extend_from_slice(&((index * 8) as u64).to_le_bytes());
      rels.extend_from_slice(&r_info.to_le_bytes());
    }
  }

  let mut symtab = vec![0u8; 24];
  for name_offset in symbol_name_offsets {
    symtab.extend_from_slice(&name_offset.to_le_bytes());
    symtab.push(0x10);
    symtab.push(0);
    symtab.extend_from_slice(&SHN_UNDEF.to_le_bytes());
    symtab.extend_from_slice(&0u64.to_le_bytes());
    symtab.extend_from_slice(&0u64.to_le_bytes());
  }

  let mut elf = vec![0u8; 64];
  let text_offset = append_aligned(&mut elf, &text, 8);
  let rel_offset = append_aligned(&mut elf, &rels, 8);
  let symtab_offset = append_aligned(&mut elf, &symtab, 8);
  let strtab_offset = append_aligned(&mut elf, &strtab, 1);
  let shstrtab_offset = append_aligned(&mut elf, &shstrtab, 1);
  let shoff = align_vec(&mut elf, 8);

  let mut sections = Vec::new();
  sections.extend_from_slice(&[0u8; 64]);
  write_section(
    &mut sections,
    name_test,
    SHT_PROGBITS,
    SHF_ALLOC | SHF_EXECINSTR,
    text_offset,
    text.len(),
    0,
    0,
    8,
    0,
  );
  write_section(
    &mut sections,
    name_reltest,
    SHT_REL,
    0,
    rel_offset,
    rels.len(),
    3,
    1,
    8,
    16,
  );
  write_section(
    &mut sections,
    name_symtab,
    SHT_SYMTAB,
    0,
    symtab_offset,
    symtab.len(),
    4,
    1,
    8,
    24,
  );
  write_section(
    &mut sections,
    name_strtab,
    SHT_STRTAB,
    0,
    strtab_offset,
    strtab.len(),
    0,
    0,
    1,
    0,
  );
  write_section(
    &mut sections,
    name_shstrtab,
    SHT_STRTAB,
    0,
    shstrtab_offset,
    shstrtab.len(),
    0,
    0,
    1,
    0,
  );
  elf.extend_from_slice(&sections);

  write_elf_header(&mut elf[..64], shoff, 6);
  elf
}

fn append_aligned(out: &mut Vec<u8>, data: &[u8], align: usize) -> u64 {
  let offset = align_vec(out, align);
  out.extend_from_slice(data);
  offset
}

fn align_vec(out: &mut Vec<u8>, align: usize) -> u64 {
  let padding = (align - (out.len() % align)) % align;
  out.resize(out.len() + padding, 0);
  out.len() as u64
}

#[allow(clippy::too_many_arguments)]
fn write_section(
  out: &mut Vec<u8>,
  name: u32,
  ty: u32,
  flags: u64,
  offset: u64,
  size: usize,
  link: u32,
  info: u32,
  addralign: u64,
  entsize: u64,
) {
  out.extend_from_slice(&name.to_le_bytes());
  out.extend_from_slice(&ty.to_le_bytes());
  out.extend_from_slice(&flags.to_le_bytes());
  out.extend_from_slice(&0u64.to_le_bytes());
  out.extend_from_slice(&offset.to_le_bytes());
  out.extend_from_slice(&(size as u64).to_le_bytes());
  out.extend_from_slice(&link.to_le_bytes());
  out.extend_from_slice(&info.to_le_bytes());
  out.extend_from_slice(&addralign.to_le_bytes());
  out.extend_from_slice(&entsize.to_le_bytes());
}

fn write_elf_header(header: &mut [u8], shoff: u64, shnum: u16) {
  header[0..4].copy_from_slice(b"\x7fELF");
  header[4] = 2;
  header[5] = 1;
  header[6] = 1;
  header[16..18].copy_from_slice(&1u16.to_le_bytes());
  header[18..20].copy_from_slice(&247u16.to_le_bytes());
  header[20..24].copy_from_slice(&1u32.to_le_bytes());
  header[40..48].copy_from_slice(&shoff.to_le_bytes());
  header[52..54].copy_from_slice(&64u16.to_le_bytes());
  header[58..60].copy_from_slice(&64u16.to_le_bytes());
  header[60..62].copy_from_slice(&shnum.to_le_bytes());
  header[62..64].copy_from_slice(&5u16.to_le_bytes());
}

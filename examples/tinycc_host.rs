use std::{any::Any, env, fs, sync::Arc, time::Duration};

use async_ebpf::{
  helpers::Helper,
  program::{
    DummyProgramEventListener, GlobalEnv, HelperScope, PreemptionEnabled, ProgramLoader,
    TimesliceConfig,
  },
  test_util::TokioTimeslicer,
};

#[derive(Default)]
struct EmittedElf(Vec<u8>);

#[derive(Default)]
struct GuestInput(Vec<u8>);

fn input_copy(scope: &HelperScope, ptr: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
  let mut dst = scope.user_memory_mut(ptr, len)?;
  scope.with_resource_mut::<GuestInput, _>(|input| match input {
    Ok(input) if input.0.len() == len as usize => {
      dst.copy_from_slice(&input.0);
      Ok(len)
    }
    _ => Err(()),
  })
}

fn write_output(
  scope: &HelperScope,
  ptr: u64,
  len: u64,
  _: u64,
  _: u64,
  _: u64,
) -> Result<u64, ()> {
  let bytes = scope.user_memory(ptr, len)?;
  scope.with_resource_mut::<EmittedElf, _>(|output| match output {
    Ok(output) => {
      output.0.extend_from_slice(bytes);
      Ok(len)
    }
    Err(()) => Err(()),
  })
}

fn fatal(scope: &HelperScope, ptr: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
  let message = scope.user_memory(ptr, len)?;
  eprintln!("tinycc guest error: {}", String::from_utf8_lossy(message));
  Err(())
}

const TINYCC_HELPERS: &[(&str, Helper)] = &[
  ("tcc_ebpf_input_copy", input_copy),
  ("tcc_ebpf_write", write_output),
  ("tcc_ebpf_fatal", fatal),
];

fn main() -> anyhow::Result<()> {
  let object = env::args()
    .nth(1)
    .expect("usage: tinycc_host TINYCC_BPF_OBJECT [SOURCE_OR_SOURCE_FILE] [OUTPUT_ELF]");
  let source_arg = env::args()
    .nth(2)
    .unwrap_or_else(|| "int add(int a, int b) { return a + b; }".to_string());
  let output_path = env::args().nth(3);
  let guest_stack_size = env::var("TCC_EBPF_STACK_SIZE")
    .ok()
    .map(|value| value.parse())
    .transpose()?
    .unwrap_or(8 * 1024 * 1024);
  let mut source = fs::read(&source_arg).unwrap_or_else(|_| source_arg.into_bytes());
  source.push(0);
  anyhow::ensure!(
    source.len() + 64 * 1024 + 512 <= guest_stack_size,
    "source exceeds guest stack capacity"
  );
  let mut calldata = vec![0u8; 512];
  calldata[..8].copy_from_slice(&(source.len() as u64).to_ne_bytes());

  let binary = fs::read(object)?;
  let global_env = unsafe { GlobalEnv::new() };
  let thread_env = global_env.init_thread(Duration::from_secs(3600));
  let loader = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[TINYCC_HELPERS],
  )
  .with_guest_stack_size(guest_stack_size)
  .with_writable_data(true)
  .with_instruction_limit(1_000_000)
  .with_code_size_limit(64 * 1024 * 1024);
  let program = loader
    .load(&mut rand::thread_rng(), &binary)?
    .pin_to_current_thread(thread_env);
  let preemption = PreemptionEnabled::new(program.thread_env());
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()?;
  let mut input = GuestInput(source);
  let mut emitted = EmittedElf::default();
  let mut resources: [&mut dyn Any; 2] = [&mut input, &mut emitted];
  let result = runtime.block_on(program.run(
    &TimesliceConfig {
      max_run_time_before_throttle: Duration::from_secs(120),
      max_run_time_before_yield: Duration::from_secs(120),
      throttle_duration: Duration::from_millis(1),
    },
    &TokioTimeslicer,
    ".text",
    &mut resources,
    &calldata,
    &preemption,
  ))?;
  if let Some(path) = output_path {
    fs::write(path, &emitted.0)?;
  }
  println!("tinycc result: {result:#x}");
  println!("tinycc emitted ELF bytes: {}", emitted.0.len());
  Ok(())
}

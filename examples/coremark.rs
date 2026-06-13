use std::{
  env, fs,
  path::{Path, PathBuf},
  process::Command,
  sync::Arc,
  time::{Duration, Instant},
};

use async_ebpf::{
  program::{DummyProgramEventListener, PreemptionEnabled, ProgramLoader, TimesliceConfig},
  test_util::{gt_env, TokioTimeslicer},
};

const COREMARK_REF: &str = "1f483d5";
const COREMARK_SOURCES: &[&str] = &["core_list_join.c", "core_matrix.c", "core_state.c"];

fn main() -> anyhow::Result<()> {
  let iterations = env::args()
    .nth(1)
    .map(|x| x.parse::<u64>())
    .transpose()?
    .unwrap_or(10);
  let mhz = env::args().nth(2).map(|x| x.parse::<f64>()).transpose()?;

  let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  let bpf_dir = repo.join("coremark-bpf");
  let coremark_dir = find_coremark_dir(&repo)?;
  let work_dir = repo.join("target/coremark-bpf");
  fs::create_dir_all(&work_dir)?;

  let obj = compile_coremark(&bpf_dir, &coremark_dir, &work_dir)?;

  let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()?;
  let binary = std::fs::read(obj)?;
  let (_, t_env) = gt_env();

  let loader = ProgramLoader::new(
    &mut rand::thread_rng(),
    Arc::new(DummyProgramEventListener),
    &[],
  )
  .with_code_size_limit(4 * 1024 * 1024);
  let prog = loader
    .load(&mut rand::thread_rng(), &binary)?
    .pin_to_current_thread(t_env);
  let preemption = PreemptionEnabled::new(prog.thread_env());

  let elapsed = rt.block_on(async {
    let calldata = iterations.to_le_bytes();
    let started = Instant::now();
    let ret = prog
      .run(
        &TimesliceConfig {
          max_run_time_before_throttle: Duration::from_secs(120),
          max_run_time_before_yield: Duration::from_millis(5),
          throttle_duration: Duration::from_millis(1),
        },
        &TokioTimeslicer,
        "coremark",
        &mut [],
        &calldata,
        &preemption,
      )
      .await?;
    Ok::<_, async_ebpf::error::Error>((ret as u64, started.elapsed()))
  })?;

  let (ret, elapsed) = elapsed;
  let errors = (ret >> 48) & 0xffff;
  let crclist = (ret >> 32) & 0xffff;
  let crcmatrix = (ret >> 16) & 0xffff;
  let crcstate = ret & 0xffff;
  let secs = elapsed.as_secs_f64();
  let per_sec = iterations as f64 / secs;
  println!("async-ebpf CoreMark");
  println!("iterations: {iterations}");
  println!("elapsed_secs: {secs:.6}");
  println!("iterations_per_sec: {per_sec:.6}");
  println!("crclist: 0x{crclist:04x}");
  println!("crcmatrix: 0x{crcmatrix:04x}");
  println!("crcstate: 0x{crcstate:04x}");
  println!(
    "crc_validation: {}",
    if errors == 0 { "pass" } else { "fail" }
  );
  if errors != 0 {
    anyhow::bail!(
      "CoreMark CRC validation failed: errors={errors}, crclist=0x{crclist:04x}, crcmatrix=0x{crcmatrix:04x}, crcstate=0x{crcstate:04x}"
    );
  }
  if let Some(mhz) = mhz {
    println!("coremark_per_mhz: {:.9}", per_sec / mhz);
  }

  Ok(())
}

fn find_coremark_dir(repo: &Path) -> anyhow::Result<PathBuf> {
  if let Some(path) = env::var_os("COREMARK_DIR") {
    return Ok(PathBuf::from(path));
  }

  for candidate in [repo.join("target/coremark"), PathBuf::from("/tmp/coremark")] {
    if candidate.join("core_list_join.c").is_file() {
      return Ok(candidate);
    }
  }

  anyhow::bail!(
    "CoreMark sources not found; clone https://github.com/eembc/coremark at {COREMARK_REF} and set COREMARK_DIR"
  );
}

fn compile_coremark(
  bpf_dir: &Path,
  coremark_dir: &Path,
  work_dir: &Path,
) -> anyhow::Result<PathBuf> {
  let input = prepare_coremark_sources(bpf_dir, coremark_dir, work_dir)?;
  let linked = work_dir.join("coremark-linked.bc");
  let optimized = work_dir.join("coremark-opt.bc");
  let object = work_dir.join("coremark.o");

  run(
    Command::new("clang")
      .arg("-target")
      .arg("bpf")
      .arg("-emit-llvm")
      .arg("-O3")
      .arg("-mllvm")
      .arg("-inline-threshold=100000")
      .arg("-fno-builtin")
      .arg("-fno-stack-protector")
      .arg("-Wall")
      .arg("-Wno-pointer-to-int-cast")
      .arg("-Wno-int-to-pointer-cast")
      .arg("-c")
      .arg(&input)
      .arg("-o")
      .arg(&linked),
  )?;

  run(
    Command::new("opt")
      .arg("-O2")
      .arg("-o")
      .arg(&optimized)
      .arg(&linked),
  )?;
  run(
    Command::new("llc")
      .arg("-march=bpf")
      .arg("-bpf-stack-size=4096")
      .arg("-mcpu=v3")
      .arg("-filetype=obj")
      .arg("-o")
      .arg(&object)
      .arg(&optimized),
  )?;

  Ok(object)
}

fn prepare_coremark_sources(
  bpf_dir: &Path,
  coremark_dir: &Path,
  work_dir: &Path,
) -> anyhow::Result<PathBuf> {
  // The generated sources adapt upstream CoreMark to async-ebpf's BPF runtime.
  // Keep coremark-bpf/README.md in sync with the patches below.
  let source_dir = work_dir.join("src");
  if source_dir.exists() {
    fs::remove_dir_all(&source_dir)?;
  }
  fs::create_dir_all(&source_dir)?;

  for source in ["coremark.h", "coremark_entry.c", "core_util_min.c"] {
    fs::copy(bpf_dir.join(source), source_dir.join(source))?;
  }

  for source in COREMARK_SOURCES {
    let path = coremark_dir.join(source);
    let mut contents = fs::read_to_string(&path)?;
    contents = match *source {
      "core_list_join.c" => patch_core_list_join(contents)?,
      "core_matrix.c" => patch_core_matrix(contents)?,
      "core_state.c" => patch_core_state(contents)?,
      _ => unreachable!(),
    };
    fs::write(source_dir.join(source), contents)?;
  }

  let all = source_dir.join("coremark_all.c");
  fs::write(
    &all,
    r#"#include "coremark.h"
#include "coremark_entry.c"
#include "core_util_min.c"
#include "core_list_join.c"
#include "core_matrix.c"
#include "core_state.c"
"#,
  )?;

  Ok(all)
}

fn patch_core_list_join(mut contents: String) -> anyhow::Result<String> {
  replace_required(
    &mut contents,
    r#"list_head *core_list_undo_remove(list_head *item_removed,
                                 list_head *item_modified);
list_head *core_list_insert_new(list_head * insert_point,
                                list_data * info,
                                list_head **memblock,
                                list_data **datablock,
                                list_head * memblock_end,
                                list_data * datablock_end);
typedef ee_s32 (*list_cmp)(list_data *a, list_data *b, core_results *res);
list_head *core_list_mergesort(list_head *   list,
                               list_cmp      cmp,
                               core_results *res);
"#,
    r#"list_head *core_list_undo_remove(list_head *item_removed,
                                 list_head *item_modified);
#define CMP_IDX 0
#define CMP_COMPLEX 1

list_head *core_list_insert_new(list_head * insert_point,
                                list_data * info,
                                list_alloc_state *alloc);
list_head *core_list_mergesort(list_head *   list,
                               ee_s32        cmp,
                               core_results *res);
"#,
  )?;
  replace_required(
    &mut contents,
    r#"                retval = core_bench_state(res->size,
                                          res->memblock[3],
                                          res->seed1,
                                          res->seed2,
                                          dtype,
                                          res->crc);
"#,
    r#"                state_bench_args state_args;
                state_args.blksize = res->size;
                state_args.memblock = res->memblock[3];
                state_args.seed1 = res->seed1;
                state_args.seed2 = res->seed2;
                retval = core_bench_state(&state_args,
                                          dtype,
                                          res->crc);
"#,
  )?;
  replace_required(
    &mut contents,
    "        list = core_list_mergesort(list, cmp_complex, res);",
    "        list = core_list_mergesort(list, CMP_COMPLEX, res);",
  )?;
  replace_required(
    &mut contents,
    "    list = core_list_mergesort(list, cmp_idx, NULL);",
    "    list = core_list_mergesort(list, CMP_IDX, NULL);",
  )?;
  replace_required(
    &mut contents,
    "    list_data *datablock_end = datablock + size;\n    /* some useful variables */",
    "    list_data *datablock_end = datablock + size;\n    list_alloc_state alloc;\n    /* some useful variables */",
  )?;
  replace_required(
    &mut contents,
    "    list_head *finder, *list = memblock;\n    list_data  info;",
    "    list_head *finder, *list = memblock;\n    list_data  info;\n    alloc.memblock = &memblock;\n    alloc.datablock = &datablock;\n    alloc.memblock_end = memblock_end;\n    alloc.datablock_end = datablock_end;",
  )?;
  replace_required(
    &mut contents,
    r#"    core_list_insert_new(
        list, &info, &memblock, &datablock, memblock_end, datablock_end);
"#,
    "    core_list_insert_new(list, &info, &alloc);\n",
  )?;
  replace_required(
    &mut contents,
    r#"        core_list_insert_new(
            list, &info, &memblock, &datablock, memblock_end, datablock_end);
"#,
    "        core_list_insert_new(list, &info, &alloc);\n",
  )?;
  replace_required(
    &mut contents,
    "    list = core_list_mergesort(list, cmp_idx, NULL);",
    "    list = core_list_mergesort(list, CMP_IDX, NULL);",
  )?;
  replace_required(
    &mut contents,
    r#"core_list_insert_new(list_head * insert_point,
                     list_data * info,
                     list_head **memblock,
                     list_data **datablock,
                     list_head * memblock_end,
                     list_data * datablock_end)
{
    list_head *newitem;

    if ((*memblock + 1) >= memblock_end)
        return NULL;
    if ((*datablock + 1) >= datablock_end)
        return NULL;

    newitem = *memblock;
    (*memblock)++;
    newitem->next      = insert_point->next;
    insert_point->next = newitem;

    newitem->info = *datablock;
    (*datablock)++;
"#,
    r#"core_list_insert_new(list_head * insert_point,
                     list_data * info,
                     list_alloc_state *alloc)
{
    list_head *newitem;

    if ((*(alloc->memblock) + 1) >= alloc->memblock_end)
        return NULL;
    if ((*(alloc->datablock) + 1) >= alloc->datablock_end)
        return NULL;

    newitem = *(alloc->memblock);
    (*(alloc->memblock))++;
    newitem->next      = insert_point->next;
    insert_point->next = newitem;

    newitem->info = *(alloc->datablock);
    (*(alloc->datablock))++;
"#,
  )?;
  replace_required(
    &mut contents,
    "core_list_mergesort(list_head *list, list_cmp cmp, core_results *res)",
    "core_list_mergesort(list_head *list, ee_s32 cmp, core_results *res)",
  )?;
  replace_required(
    &mut contents,
    "                else if (cmp(p->info, q->info, res) <= 0)",
    r#"                else if ((cmp == CMP_COMPLEX ? cmp_complex(p->info, q->info, res)
                                             : cmp_idx(p->info, q->info, res))
                         <= 0)"#,
  )?;

  Ok(contents)
}

fn patch_core_matrix(mut contents: String) -> anyhow::Result<String> {
  replace_required(
    &mut contents,
    "            seed         = ((order * seed) % 65536);",
    "            seed         = (ee_s32)(((ee_u32)(order * seed)) % 65536U);",
  )?;
  Ok(contents)
}

fn patch_core_state(mut contents: String) -> anyhow::Result<String> {
  replace_required(
    &mut contents,
    r#"core_bench_state(ee_u32 blksize,
                 ee_u8 *memblock,
                 ee_s16 seed1,
                 ee_s16 seed2,
                 ee_s16 step,
                 ee_u16 crc)
{
    ee_u32 final_counts[NUM_CORE_STATES];
    ee_u32 track_counts[NUM_CORE_STATES];
    ee_u8 *p = memblock;
"#,
    r#"core_bench_state(state_bench_args *args,
                 ee_s16 step,
                 ee_u16 crc)
{
    ee_u32 final_counts[NUM_CORE_STATES];
    ee_u32 track_counts[NUM_CORE_STATES];
    ee_u32 blksize = args->blksize;
    ee_u8 *memblock = args->memblock;
    ee_s16 seed1 = args->seed1;
    ee_s16 seed2 = args->seed2;
    ee_u8 *p = memblock;
"#,
  )?;
  replace_required(
    &mut contents,
    r#"/* Default initialization patterns */
static ee_u8 *intpat[4]
    = { (ee_u8 *)"5012", (ee_u8 *)"1234", (ee_u8 *)"-874", (ee_u8 *)"+122" };
static ee_u8 *floatpat[4] = { (ee_u8 *)"35.54400",
                              (ee_u8 *)".1234500",
                              (ee_u8 *)"-110.700",
                              (ee_u8 *)"+0.64400" };
static ee_u8 *scipat[4]   = { (ee_u8 *)"5.500e+3",
                            (ee_u8 *)"-.123e-2",
                            (ee_u8 *)"-87e+832",
                            (ee_u8 *)"+0.6e-12" };
static ee_u8 *errpat[4]   = { (ee_u8 *)"T0.3e-1F",
                            (ee_u8 *)"-T.T++Tq",
                            (ee_u8 *)"1T3.4e4z",
                            (ee_u8 *)"34.0e-T^" };
"#,
    r#"static ee_u8
state_pattern_char(ee_u32 kind, ee_u32 index, ee_u32 pos)
{
    unsigned long long pattern = 0;
    if (kind == 0)
    {
        switch (index)
        {
            case 0: pattern = 0x32313035ULL; break;
            case 1: pattern = 0x34333231ULL; break;
            case 2: pattern = 0x3437382dULL; break;
            default: pattern = 0x3232312bULL; break;
        }
    }
    else if (kind == 1)
    {
        switch (index)
        {
            case 0: pattern = 0x30303434352e3533ULL; break;
            case 1: pattern = 0x303035343332312eULL; break;
            case 2: pattern = 0x3030372e3031312dULL; break;
            default: pattern = 0x30303434362e302bULL; break;
        }
    }
    else if (kind == 2)
    {
        switch (index)
        {
            case 0: pattern = 0x332b653030352e35ULL; break;
            case 1: pattern = 0x322d653332312e2dULL; break;
            case 2: pattern = 0x3233382b6537382dULL; break;
            default: pattern = 0x32312d65362e302bULL; break;
        }
    }
    else
    {
        switch (index)
        {
            case 0: pattern = 0x46312d65332e3054ULL; break;
            case 1: pattern = 0x71542b2b542e542dULL; break;
            case 2: pattern = 0x7a3465342e335431ULL; break;
            default: pattern = 0x5e542d65302e3433ULL; break;
        }
    }
    switch (pos)
    {
        case 0: return (ee_u8)pattern;
        case 1: return (ee_u8)(pattern >> 8);
        case 2: return (ee_u8)(pattern >> 16);
        case 3: return (ee_u8)(pattern >> 24);
        case 4: return (ee_u8)(pattern >> 32);
        case 5: return (ee_u8)(pattern >> 40);
        case 6: return (ee_u8)(pattern >> 48);
        default: return (ee_u8)(pattern >> 56);
    }
}
"#,
  )?;
  replace_required(
    &mut contents,
    "    ee_u8 *buf = 0;",
    "    ee_u32 kind = 0, pat_idx = 0;",
  )?;
  replace_required(
    &mut contents,
    "                *(p + total + i) = buf[i];",
    "                *(p + total + i) = state_pattern_char(kind, pat_idx, i);",
  )?;
  replace_required(
    &mut contents,
    "                buf  = intpat[(seed >> 3) & 0x3];",
    "                kind = 0;\n                pat_idx = (seed >> 3) & 0x3;",
  )?;
  replace_required(
    &mut contents,
    "                buf  = floatpat[(seed >> 3) & 0x3];",
    "                kind = 1;\n                pat_idx = (seed >> 3) & 0x3;",
  )?;
  replace_required(
    &mut contents,
    "                buf  = scipat[(seed >> 3) & 0x3];",
    "                kind = 2;\n                pat_idx = (seed >> 3) & 0x3;",
  )?;
  replace_required(
    &mut contents,
    "                buf  = errpat[(seed >> 3) & 0x3];",
    "                kind = 3;\n                pat_idx = (seed >> 3) & 0x3;",
  )?;
  Ok(contents)
}

fn replace_required(contents: &mut String, from: &str, to: &str) -> anyhow::Result<()> {
  if !contents.contains(from) {
    anyhow::bail!("failed to patch CoreMark source; pattern not found");
  }
  *contents = contents.replacen(from, to, 1);
  Ok(())
}

fn run(cmd: &mut Command) -> anyhow::Result<()> {
  let status = cmd.status()?;
  if !status.success() {
    anyhow::bail!("command failed with {status}: {cmd:?}");
  }
  Ok(())
}

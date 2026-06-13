#include "coremark.h"

static void init_coremark(core_results *res,
                          ee_u8 *stack_memblock,
                          ee_u32 iterations);

unsigned long long
entry(unsigned long long *iterations_ptr)
{
  core_results results;
  ee_u8 stack_memblock[TOTAL_DATA_SIZE * MULTITHREAD];
  unsigned long long iterations = *iterations_ptr;

  if (iterations == 0) {
    iterations = 1;
  }
  if (iterations > 0xffffffffULL) {
    iterations = 0xffffffffULL;
  }

  init_coremark(&results, stack_memblock, (ee_u32)iterations);
  iterate(&results);

  if (results.crclist != 0xe714) {
    results.err++;
  }
  if (results.crcmatrix != 0x1fd7) {
    results.err++;
  }
  if (results.crcstate != 0x8e3a) {
    results.err++;
  }

  return ((unsigned long long)(ee_u16)results.err << 48)
    | ((unsigned long long)results.crclist << 32)
    | ((unsigned long long)results.crcmatrix << 16)
    | (unsigned long long)results.crcstate;
}

static void
init_coremark(core_results *res, ee_u8 *stack_memblock, ee_u32 iterations)
{
  ee_u16 i, j = 0, num_algorithms = 0;

  res->seed1 = 0;
  res->seed2 = 0;
  res->seed3 = 0x66;
  res->iterations = iterations;
  res->execs = ALL_ALGORITHMS_MASK;
  res->memblock[0] = stack_memblock;
  res->size = TOTAL_DATA_SIZE;
  res->err = 0;

  for (i = 0; i < NUM_ALGORITHMS; i++) {
    if ((1 << (ee_u32)i) & res->execs) {
      num_algorithms++;
    }
  }
  res->size = res->size / num_algorithms;

  for (i = 0; i < NUM_ALGORITHMS; i++) {
    if ((1 << (ee_u32)i) & res->execs) {
      res->memblock[i + 1] = (char *)(res->memblock[0]) + res->size * j;
      j++;
    }
  }

  res->list = core_list_init(res->size, res->memblock[1], res->seed1);
  core_init_matrix(res->size,
                   res->memblock[2],
                   (ee_s32)res->seed1 | (((ee_s32)res->seed2) << 16),
                   &(res->mat));
  core_init_state(res->size, res->seed1, res->memblock[3]);
}

void *
iterate(void *pres)
{
  ee_u32 i;
  ee_u16 crc;
  core_results *res = (core_results *)pres;
  ee_u32 iterations = res->iterations;
  res->crc = 0;
  res->crclist = 0;
  res->crcmatrix = 0;
  res->crcstate = 0;

  for (i = 0; i < iterations; i++) {
    crc = core_bench_list(res, 1);
    res->crc = crcu16(crc, res->crc);
    crc = core_bench_list(res, -1);
    res->crc = crcu16(crc, res->crc);
    if (i == 0) {
      res->crclist = res->crc;
    }
  }
  return (void *)0;
}

/*
 * Minimal CoreMark header for async-ebpf benchmarking.
 *
 * This intentionally omits CoreMark's hosted port layer. The benchmark runner
 * times execution on the Rust host and passes a fixed iteration count through
 * eBPF calldata.
 */
#ifndef COREMARK_H
#define COREMARK_H

#ifndef TOTAL_DATA_SIZE
#define TOTAL_DATA_SIZE 2000
#endif

#ifndef CORE_DEBUG
#define CORE_DEBUG 0
#endif

#if defined(__clang__)
#pragma clang section text = "coremark"
#endif

#define MEM_STATIC 0
#define MEM_MALLOC 1
#define MEM_STACK 2

#define MEM_METHOD MEM_STACK
#define MULTITHREAD 1

typedef signed short ee_s16;
typedef unsigned short ee_u16;
typedef signed int ee_s32;
typedef unsigned char ee_u8;
typedef unsigned int ee_u32;
typedef unsigned long long ee_ptr_int;
typedef unsigned int ee_size_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

#define align_mem(x) (void *)(4 + (((ee_ptr_int)(x)-1) & ~3ULL))

void *iterate(void *pres);

ee_u16 crcu8(ee_u8 data, ee_u16 crc);
ee_u16 crc16(ee_s16 newval, ee_u16 crc);
ee_u16 crcu16(ee_u16 newval, ee_u16 crc);
ee_u16 crcu32(ee_u32 newval, ee_u16 crc);

#define ID_LIST (1 << 0)
#define ID_MATRIX (1 << 1)
#define ID_STATE (1 << 2)
#define ALL_ALGORITHMS_MASK (ID_LIST | ID_MATRIX | ID_STATE)
#define NUM_ALGORITHMS 3

typedef struct list_data_s {
  ee_s16 data16;
  ee_s16 idx;
} list_data;

typedef struct list_head_s {
  struct list_head_s *next;
  struct list_data_s *info;
} list_head;

#define MATDAT_INT 1
typedef ee_s16 MATDAT;
typedef ee_s32 MATRES;

typedef struct MAT_PARAMS_S {
  int N;
  MATDAT *A;
  MATDAT *B;
  MATRES *C;
} mat_params;

typedef enum CORE_STATE {
  CORE_START = 0,
  CORE_INVALID,
  CORE_S1,
  CORE_S2,
  CORE_INT,
  CORE_FLOAT,
  CORE_EXPONENT,
  CORE_SCIENTIFIC,
  NUM_CORE_STATES
} core_state_e;

typedef struct RESULTS_S {
  ee_s16 seed1;
  ee_s16 seed2;
  ee_s16 seed3;
  void *memblock[4];
  ee_u32 size;
  ee_u32 iterations;
  ee_u32 execs;
  struct list_head_s *list;
  mat_params mat;
  ee_u16 crc;
  ee_u16 crclist;
  ee_u16 crcmatrix;
  ee_u16 crcstate;
  ee_s16 err;
} core_results;

typedef struct STATE_BENCH_ARGS_S {
  ee_u32 blksize;
  ee_u8 *memblock;
  ee_s16 seed1;
  ee_s16 seed2;
} state_bench_args;

typedef struct LIST_ALLOC_STATE_S {
  list_head **memblock;
  list_data **datablock;
  list_head *memblock_end;
  list_data *datablock_end;
} list_alloc_state;

list_head *core_list_init(ee_u32 blksize, list_head *memblock, ee_s16 seed);
ee_u16 core_bench_list(core_results *res, ee_s16 finder_idx);

void core_init_state(ee_u32 size, ee_s16 seed, ee_u8 *p);
ee_u16 core_bench_state(state_bench_args *args, ee_s16 step, ee_u16 crc);

ee_u32 core_init_matrix(ee_u32 blksize,
                        void *memblk,
                        ee_s32 seed,
                        mat_params *p);
ee_u16 core_bench_matrix(mat_params *p, ee_s16 seed, ee_u16 crc);

#endif

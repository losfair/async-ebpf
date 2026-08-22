// Copyright (c) Will Hawkins
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Generic x86-64 code generation functions
 */

#ifndef UBPF_JIT_SUPPORT_H
#define UBPF_JIT_SUPPORT_H

#include <stdint.h>
#include <sys/types.h>
#include "ubpf_int.h"

enum JitProgress
{
    NoError,
    TooManyJumps,
    TooManyLoads,
    TooManyLeas,
    TooManyLocalCalls,
    NotEnoughSpace,
    UnexpectedInstruction,
    UnknownInstruction,
    RelocationOutOfRange
};


/*
 * During the process of JITing, the targets of program-control
 * instructions are not always known. The functions of below
 * make it possible to emit program-control instructions with
 * temporary targets and then fixup those instructions when their
 * targets are known. Some of the targets are _special_ (SpecialTarget)
 * and others are _regular_ (RegularTarget). No matter what, however,
 * during JITing, the targets of program-control instructions are
 * PatchableTargets.
 */
enum SpecialTarget
{
    Exit,
    Enter,
    Retpoline,
    ExternalDispatcher,
    LoadHelperTable,
};

struct RegularTarget
{
    /* Which eBPF PC should this target. The ultimate offset will be determined
     * automatically unless ... */
    uint32_t ebpf_target_pc;
    /* ... the JIT target_offset is set which overrides the automatic lookup. */
    uint32_t jit_target_pc;
    /* Whether or not this target is _near_ the source. */
    bool near;
};

struct PatchableTarget
{
    bool is_special;
    union
    {
        enum SpecialTarget special;
        struct RegularTarget regular;
    } target;
};

#define DECLARE_PATCHABLE_TARGET(x) \
    struct PatchableTarget x; \
    memset(&x, 0, sizeof(struct PatchableTarget));

#define DECLARE_PATCHABLE_SPECIAL_TARGET(x, tgt) \
    struct PatchableTarget x; \
    memset(&x, 0, sizeof(struct PatchableTarget)); \
    x.is_special = true; \
    x.target.special = tgt; \

#define DECLARE_PATCHABLE_REGULAR_EBPF_TARGET(x, tgt) \
    struct PatchableTarget x; \
    memset(&x, 0, sizeof(struct PatchableTarget)); \
    x.is_special = false; \
    x.target.regular.ebpf_target_pc = tgt;

#define DECLARE_PATCHABLE_REGULAR_JIT_TARGET(x, tgt) \
    struct PatchableTarget x; \
    memset(&x, 0, sizeof(struct PatchableTarget)); \
    x.is_special = false; \
    x.target.regular.jit_target_pc = tgt;


struct patchable_relative
{
    /* Where in the JIT'd instruction stream should the actual
     * target be written once it is determined.
     */
    uint32_t offset_loc;

    /* How to calculate the actual target.
     */
    struct PatchableTarget target;
};

struct jit_state
{
    uint8_t* buf;
    uint32_t offset;
    uint32_t size;
    uint32_t* pc_locs;
    uint32_t exit_loc;
    uint32_t entry_loc;
    uint32_t unwind_loc;
    /* The offset (from the start of the JIT'd code) to the location
     * of the retpoline (if retpoline support is enabled).
     */
    uint32_t retpoline_loc;
    /* The offset (from the start of the JIT'd code) to the location
     * of the address of the external helper dispatcher. The address
     * at that location during execution may be null if no external
     * helper dispatcher is registered. See commentary in ubpf_jit_x86_64.c.
     */
    uint32_t dispatcher_loc;
    /* The offset (from the start of the JIT'd code) to the location
     * of a consecutive series of XXXX addresses that contain pointers
     * to external helper functions. The address' position in the sequence
     * corresponds to the index of the helper function. Addresses may
     * be null but validation guarantees that (at the time the eBPF program
     * is loaded), if a helper function is called, there is an appropriately
     * registered handler. See commentary in ubpf_jit_x86_64.c.
     */
    uint32_t helper_table_loc;
    enum JitProgress jit_status;
    enum JitMode jit_mode;
    struct patchable_relative* jumps;
    struct patchable_relative* loads;
    struct patchable_relative* leas;
    struct patchable_relative* local_calls;
    int num_jumps;
    int num_loads;
    int num_leas;
    int num_local_calls;
    /* Allocated entry counts for the four patch tables above. They start empty
     * and grow on demand; see reserve_patchable_relatives.
     */
    uint32_t jumps_capacity;
    uint32_t loads_capacity;
    uint32_t leas_capacity;
    uint32_t local_calls_capacity;
    /* Allocated entry count of pc_locs, which is indexed by absolute eBPF PC. */
    uint32_t pc_locs_capacity;
    uint32_t stack_size;
    size_t bpf_function_prolog_size; // Count of bytes emitted at the start of the function.

    /* State of the open access group, if any. See ubpf_set_access_plan().
     *
     * A group's members address the base its leader checked and parked, so the
     * backend has to know that the leader really did run: that it is the most
     * recent one emitted, that no branch can land between the two, and that
     * nothing has redefined the base register in between. The plan says all
     * this, but the plan is not trusted - these fields are what the backend
     * derives for itself while walking the instruction stream.
     */
    int64_t group_leader_pc; /* -1 when no group is open. */
    uint32_t group_span;     /* Bytes the open group's leader checked. */
    int group_base_reg;      /* eBPF register the open group is based on. */
    uint8_t group_region;    /* Region the open group's leader checked against. */
    uint16_t group_written;  /* eBPF registers written since that leader. */
    /* One byte per instruction slot: non-zero where a branch can land, which
     * closes any open group. Indexed by absolute eBPF PC. */
    uint8_t* group_barrier;
};

/**
 * @brief Prepare the scratch state for one translation.
 *
 * @param[in] num_insts Length in instructions of the eBPF program being
 * translated. pc_locs is indexed by absolute eBPF PC, so it is sized from this;
 * the patch tables start empty and grow as they are appended to.
 */
int
initialize_jit_state_result(
    struct jit_state* state,
    struct ubpf_jit_result* compile_result,
    uint8_t* buffer,
    uint32_t size,
    enum JitMode jit_mode,
    uint32_t num_insts,
    char** errmsg);

/**
 * @brief Ensure a patch table can hold @p needed entries, growing it if not.
 *
 * @retval true The table has room for @p needed entries.
 * @retval false @p needed exceeds UBPF_MAX_INSTS, or the table could not grow.
 */
bool
reserve_patchable_relatives(struct patchable_relative** table, uint32_t* capacity, int needed);

void
release_jit_state_result(struct jit_state* state, struct ubpf_jit_result* compile_result);

/** @brief Add an entry to the given patchable relative table.
 *
 * Emitting an entry into the patchable relative table means that resolution of the target
 * address can be postponed until all the instructions are emitted. Note: This function does
 * not emit any instructions -- it simply updates metadata to guide resolution after code generation.
 *
 * @param[in] table The relative patchable table to update.
 * @param[in] offset The offset in the JIT'd code where the to-be-resolved target begins.
 * @param[in] index A spot in the _table_ to add/update according to the given parameters.
 */
void
emit_patchable_relative(struct patchable_relative* table, uint32_t offset, struct PatchableTarget target, size_t index);

void
note_load(struct jit_state* state, struct PatchableTarget target);

void
note_lea(struct jit_state* state, struct PatchableTarget target);

void
emit_jump_target(struct jit_state* state, uint32_t jump_src);

void
modify_patchable_relatives_target(
    struct patchable_relative* table,
    size_t table_size,
    uint32_t src_offset,
    struct PatchableTarget target);

/**
 * @brief Generate a cryptographically secure random 64-bit value for constant blinding.
 *
 * This function uses platform-specific secure random number generators to generate
 * a random value that will be used to blind immediate constants in JIT compiled code.
 *
 * @return A 64-bit random value.
 */
uint64_t
ubpf_generate_blinding_constant(void);

#endif

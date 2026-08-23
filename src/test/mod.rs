mod access_groups;
mod atomics;
mod audit_escape;
mod basic;
mod entry_isolation;
mod frame_addressing;
mod lazy_local_call;
// Asserts arm64-specific encoding limits; on x86-64 the same program is
// translatable (rel32 reaches ±2 GiB), so there is nothing to reject.
#[cfg(target_arch = "aarch64")]
mod jit_limits;
mod loader_limits;
mod preemption;
mod raw_elf;
mod runtime_state;
mod stores;

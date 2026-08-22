mod atomics;
mod basic;
mod entry_isolation;
// Asserts arm64-specific encoding limits; on x86-64 the same program is
// translatable (rel32 reaches ±2 GiB), so there is nothing to reject.
#[cfg(target_arch = "aarch64")]
mod jit_limits;
mod preemption;
mod raw_elf;

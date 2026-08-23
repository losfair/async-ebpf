/*
 * Bindgen entry point for the vendored uBPF oracle.
 *
 * `ubpf.h` alone is not enough: the differential harness calls the two
 * architecture-specific translators directly, and those are declared in the
 * internal header. Both `ubpf_jit_x86_64.c` and `ubpf_jit_arm64.c` are compiled
 * into the library unconditionally - only the function-pointer selection in
 * `ubpf_create()` is `#if`-gated - so emitting aarch64 machine code on an
 * x86_64 host (and vice versa) is a matter of calling the right symbol.
 * Translation is pure computation over a byte buffer, which is what lets the
 * byte-level differential test cover both backends from either host.
 */

#include <ubpf.h>

#include "ubpf_int.h"

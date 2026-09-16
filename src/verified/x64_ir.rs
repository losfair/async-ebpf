//! The x86_64 backend's two instruction sets.
//!
//! The backend used to write bytes straight from the eBPF instruction it was
//! translating. It now goes through two typed layers, both in the verified
//! core, so that the code generation the Lean proofs describe is the code
//! generation that runs:
//!
//! ```text
//!   eBPF program + hints + plan
//!     │  x64_lower::lower          (the decisions: which sequence, which check)
//!     ▼
//!   Vec<MInsn>   the macro instructions, one per emitted "idea"
//!     │  x64_check::check          (the memory-safety gate; proved sound)
//!     │  x64_expand::expand        (each macro's fixed native sequence)
//!     ▼
//!   Vec<PInsn>   the primitive instructions, one per x86 instruction
//!     │  jit::emit::x86_64::encode (bytes, and the relative-branch fixups)
//!     ▼
//!   bytes in the code arena
//! ```
//!
//! [`MInsn`] is what the checker reads. A macro is a sequence whose *internal*
//! structure the checker never looks at: a bounds check, a helper call, a lazy
//! local call, a division. The checker only knows each macro's contract: what
//! it requires of the abstract state, which registers it writes, whether it
//! touches guest memory. `lean/AsyncEbpf/X64/` proves each contract against
//! the macro's expansion, once, with the macro's operands symbolic.
//!
//! [`PInsn`] is what the encoder writes and what the Lean machine model
//! executes. One variant per distinct x86 instruction shape the backend uses;
//! the encoder is a table from these to bytes with no decisions left in it.
//!
//! Neither layer knows a byte offset. Control flow names eBPF slots and
//! labels; the encoder resolves them.

/// Native registers, numbered as in the ModRM/REX encoding.
pub const RAX: u8 = 0;
pub const RCX: u8 = 1;
pub const RDX: u8 = 2;
pub const RBX: u8 = 3;
pub const RSP: u8 = 4;
pub const RBP: u8 = 5;
pub const RSI: u8 = 6;
pub const RDI: u8 = 7;
pub const R8: u8 = 8;
pub const R9: u8 = 9;
pub const R10: u8 = 10;
pub const R11: u8 = 11;
pub const R12: u8 = 12;
pub const R13: u8 = 13;
pub const R14: u8 = 14;
pub const R15: u8 = 15;

/// Where the entry code parks the embedder's context pointer.
pub const VOLATILE_CTXT: u8 = R11;
/// eBPF `R4` maps here, and shifts need RCX; the helper-call sequence moves
/// it out of the way.
pub const RCX_ALT: u8 = R10;

/// eBPF register to x86 register, SysV flavour. eBPF `R0`-`R5` land on
/// caller-saved registers and `R6`-`R10` on callee-saved ones; the helper-call
/// sequence relies on that to know what it need not preserve. `R15` must stay
/// mapped to eBPF `R10`: the frame fast path and the local-call frame
/// adjustment both name it.
pub const REGISTER_MAP: [u8; 11] = [RAX, RDI, RSI, RDX, R10, R8, RBX, R12, R13, R14, R15];

/// The x86 register for an eBPF register. Wraps modularly rather than
/// panicking, so a register number the validator should have refused maps to
/// something rather than trapping.
pub fn map_register(r: u8) -> u8 {
  REGISTER_MAP[(r as usize) % 11]
}

/// The eBPF register mapped to `native`, or 16 when there is none. The map is
/// injective, so this is exact.
pub fn unmap_register(native: u8) -> u8 {
  let mut i: usize = 0;
  let mut found: u8 = 16;
  while i < 11 {
    if REGISTER_MAP[i] == native {
      found = i as u8;
    }
    i += 1;
  }
  found
}

/// One access-plan entry per instruction slot; see `region_analysis`.
///
/// A *group* is a run of memory accesses sharing a base register. The group's
/// **leader** bounds-checks the whole window once and parks the translated base
/// in the frame; each **member** reads that base back and accesses it at a
/// constant displacement. The plan is advisory: the lowering re-derives every
/// condition it can see for itself, and the checker re-derives the ones that
/// matter for safety from the abstract state alone.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, Default, PartialEq, Eq))]
#[repr(C)]
pub struct PlanEntry {
  /// One of [`plan_role`].
  pub role: u8,
  /// Region the leader checks against, as for the region hints.
  pub region: u8,
  /// This access's displacement from the window's low bound.
  pub delta: u16,
  /// Bytes the leader's check covers.
  pub span: u32,
  /// The low bound, as a displacement from the base register.
  pub lo: i32,
  /// The leader that established the base; leaders name themselves.
  pub leader_pc: u32,
}

/// Access plan roles.
pub mod plan_role {
  pub const NONE: u8 = 0;
  pub const LEADER: u8 = 1;
  pub const MEMBER: u8 = 2;
}

/// Per-instruction region routing hints, shared with `region_analysis`.
pub mod region {
  pub const UNKNOWN: u8 = 0;
  pub const STACK: u8 = 1;
  pub const DATA: u8 = 2;
  pub const FRAME: u8 = 3;
}

/// Widest window one access group may cover; see `abi::MAX_GROUP_SPAN`.
pub const MAX_GROUP_SPAN: u32 = 4096;

/// Frame slots below the frame pointer; see `abi`. Restated here so the
/// verified core has no dependency outside itself; `abi` asserts agreement.
pub mod frame {
  pub const FRAME_OFFSET: i32 = -8;
  pub const SPILL_OFFSET: i32 = -16;
  pub const ADDR_SPILL_OFFSET: i32 = -24;
  pub const ACC_SPILL_OFFSET: i32 = -32;
  pub const FRAME_DELTA_OFFSET: i32 = -40;
  pub const GROUP_BASE_OFFSET: i32 = -144;
  pub const FRAME_RESERVED: i32 = 160;
  /// The frame displacement of derived slot `i` (twelve slots, `-136..-48`).
  pub const fn derived_slot(i: usize) -> i32 {
    -136 + (i as i32) * 8
  }
  pub const DERIVED_STACK_BASE: usize = 0;
  pub const DERIVED_DATA_BASE: usize = 6;
  pub const DERIVED_BOTTOM: usize = 0;
  pub const DERIVED_DELTA: usize = 1;
  pub const DERIVED_SPAN: usize = 2;
}

/// Byte offsets into the memory descriptor whose address lives at
/// `[rbp + frame::FRAME_OFFSET]`; see `abi::memory`.
pub mod memory {
  pub const STACK_GUEST_BOTTOM: i32 = 0;
  pub const STACK_GUEST_TOP: i32 = 8;
  pub const STACK_NATIVE_BASE: i32 = 16;
  pub const DATA_GUEST_BOTTOM: i32 = 24;
  pub const DATA_GUEST_TOP: i32 = 32;
  pub const DATA_NATIVE_BASE: i32 = 40;
  pub const LOCAL_CALL_GUEST_FLOOR: i32 = 144;
  pub const LOCAL_CALL_NATIVE_FLOOR: i32 = 152;
}

/// Registered external helpers; the helper table has this many slots.
pub const MAX_EXT_FUNCS: u32 = 64;

/// The facts about a `jit::Config` the backend consults.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub struct Cfg {
  /// Non-zero enables the pointer cage: every guest access is bounds-checked
  /// and translated. Zero emits raw accesses, and the checker then vouches
  /// for nothing about guest memory.
  pub pointer_mask: i32,
  /// The entry code puts a *native* frame base in the register mapped to
  /// eBPF `R10`. Enables the `FRAME` fast path.
  pub native_frame_base: bool,
  /// The entry code fills in the derived bounds-check constants below the
  /// frame pointer, so a check reads them there rather than through the
  /// descriptor. Enables access plans.
  pub frame_constants: bool,
  /// Guest stack bytes charged to every local function.
  pub stack_frame_size: u16,
  /// Guest-address distance between successive local-function frame pointers.
  pub stack_frame_stride: u32,
  /// Address of the external dispatcher, or 0 for none.
  pub dispatcher: u64,
  /// Helper index whose zero return unwinds the whole program; `-1` for none.
  pub unwind_helper_index: i32,
  /// Whether both local-call callbacks are registered.
  pub has_local_call_callbacks: bool,
  /// Address of the lazy local-call resolver.
  pub local_call_resolver: u64,
  /// Address of the stack-exhausted callback, which never returns.
  pub local_call_stack_exhausted: u64,
}

impl Cfg {
  /// Whether the native-frame-base fast path is live.
  pub fn native_frame_base_active(&self) -> bool {
    self.pointer_mask != 0 && self.native_frame_base
  }

  /// Whether access plans are honoured.
  pub fn access_plans_active(&self) -> bool {
    self.pointer_mask != 0 && self.frame_constants
  }
}

/// Access width in bytes: 1, 2, 4 or 8.
pub type Size = u8;

/// Register-to-register ALU operations, at 32 or 64 bits.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub enum AluRR {
  Add,
  Sub,
  Or,
  And,
  Xor,
  Mov,
  Cmp,
  Test,
}

/// Register-with-immediate ALU operations (`0x81 /ext imm32`, plus the mov
/// and test immediates).
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub enum AluRI {
  Add,
  Or,
  And,
  Sub,
  Xor,
  Cmp,
  /// `mov r, imm32` (`0xc7 /0`); sign-extended at 64 bits.
  Mov,
  /// `test r, imm32` (`0xf7 /0`).
  Test,
}

#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub enum ShiftOp {
  Shl,
  Shr,
  Sar,
}

#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub enum MulDivKind {
  Mul,
  Div,
  Mod,
}

/// Where a branch goes. Only these two are reachable from the macro layer:
/// a translated eBPF slot, or the function's exit epilogue.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub enum Target {
  Pc(u32),
  Exit,
}

/// The macro instruction set.
///
/// Every variant that names a destination register writes it. The checker's
/// contract for each variant is stated on it; `x64_check` implements the
/// contracts and `lean/AsyncEbpf/X64/Check.lean` proves them sound.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub enum MInsn {
  /// The native location of eBPF slot `pc` is here. A branch to
  /// [`Target::Pc`] lands here.
  PcLabel(u32),

  /// The per-function prologue: `sub rsp, 8 ; mov qword [rsp], usage`. With
  /// `skip`, a near jump over it comes first, for a function entry the
  /// previous instruction may fall into. Contract: from a dead state (or the
  /// start of the range) the native stack depth becomes one; a live state
  /// falling into a skippable prologue must already be at depth one.
  Prologue {
    usage: u16,
    skip: bool,
  },

  /// `add rsp, 8 ; ret`. Contract: depth one, the frame pointer register
  /// untouched; the state after it is dead.
  Epilogue,

  /// Register-only arithmetic. Contract: writes `dst` unless the op is a
  /// compare or test; never `rsp`, `rbp` or the frame register.
  Alu {
    w64: bool,
    op: AluRR,
    src: u8,
    dst: u8,
  },
  AluImm {
    w64: bool,
    op: AluRI,
    dst: u8,
    imm: i32,
  },
  /// `shift dst, imm8` (`0xc1 /ext`); the immediate is truncated to a byte.
  ShiftImm {
    w64: bool,
    op: ShiftOp,
    dst: u8,
    imm: i32,
  },
  /// `shift dst, cl` (`0xd3 /ext`).
  ShiftCl {
    w64: bool,
    op: ShiftOp,
    dst: u8,
  },
  Neg {
    w64: bool,
    dst: u8,
  },
  /// `movsx`: `from` is 8, 16 or 32 source bits; `w64` selects the 64-bit
  /// destination form.
  MovSx {
    from: u8,
    w64: bool,
    src: u8,
    dst: u8,
  },
  /// `bswap` (`0f c8+r`).
  Bswap {
    w64: bool,
    dst: u8,
  },
  /// `rol r16, 8` (`66 c1 /0 08`), the 16-bit byte swap.
  Rol16 {
    dst: u8,
  },
  /// A 64-bit immediate, through the sign-extended form where it fits.
  LoadImm {
    dst: u8,
    imm: i64,
  },

  /// Multiply, divide or modulo, with eBPF's division-by-zero and
  /// `INT_MIN / -1` fixed up. `reg` selects a register divisor (`src`) over
  /// the immediate; `signed` the `sdiv`/`smod` forms. Contract: writes `dst`,
  /// `rax`, `rcx`, `rdx` and `r11`; pushes and pops balance, at most four
  /// slots deep; no guest memory.
  MulDivMod {
    kind: MulDivKind,
    w64: bool,
    reg: bool,
    signed: bool,
    src: u8,
    dst: u8,
    imm: i32,
  },

  /// Conditional branch (`0f 8x rel32`). Contract: depth one, frame register
  /// untouched, the target labelled.
  Jcc {
    cc: u8,
    target: Target,
  },
  /// Unconditional branch (`e9 rel32`). Contract as [`MInsn::Jcc`]; dead after.
  Jmp {
    target: Target,
  },

  /// `mov dst, r15 ; sub dst, [rbp - 40]`: the guest value of eBPF `R10`.
  GuestFp {
    dst: u8,
  },

  /// Resolve `[src + offset]`, `size` bytes wide, to a native address in
  /// `dst`, using `scratch` and `r9`, and the spill slots. `region` is a
  /// [`region`] routing hint. Under the cage
  /// the result is 0 or a native address whose `size`-byte window lies inside
  /// one guest region. `STACK` and `DATA` check that one region; any other
  /// hint probes both. Contract: `dst`, `scratch` and `r9` distinct from each
  /// other and from `rsp`, `rbp` and the frame register, and `size` between
  /// one byte and [`MAX_GROUP_SPAN`]; afterwards `dst`
  /// holds a checked address of `size` bytes, `scratch` and `r9` anything,
  /// and the three spill slots anything.
  CheckedAddr {
    src: u8,
    dst: u8,
    scratch: u8,
    offset: i32,
    size: u32,
    region: u8,
  },

  /// `mov [rbp - 144], src`: park a group leader's translated base.
  GroupBaseStore {
    src: u8,
  },
  /// `mov dst, [rbp - 144]`: read the parked base back for a member.
  GroupBaseLoad {
    dst: u8,
  },

  /// A guest load `[base + disp]` into `dst`, zero- or sign-extending.
  /// Contract: `base` holds a checked address of `w` bytes with
  /// `0 <= disp` and `disp + size <= w`; or `base` is the frame register,
  /// the native frame base is live, and `[disp, disp + size)` lies in
  /// `[-stack_frame_size, 0)`; or the cage is off.
  Load {
    size: Size,
    sx: bool,
    base: u8,
    dst: u8,
    disp: i32,
  },
  /// A guest store of `src`. Address contract as [`MInsn::Load`].
  Store {
    size: Size,
    src: u8,
    base: u8,
    disp: i32,
  },
  /// A guest store of an immediate. Address contract as [`MInsn::Load`].
  StoreImm {
    size: Size,
    base: u8,
    disp: i32,
    imm: i32,
  },

  /// `lock op [base + disp], src` for add, or, and, xor (`op` is the x86
  /// register-form opcode). Address contract as [`MInsn::Load`] at the
  /// operation's width; writes nothing.
  AtomicAlu {
    op: u8,
    w64: bool,
    src: u8,
    base: u8,
    disp: i32,
  },
  /// The fetching forms of the above, emulated with a compare-exchange loop.
  /// Writes `src`, `rax`, `rcx`, `r10` and `r11`; one push, balanced. Under
  /// the cage `base` is neither `rax` nor `rcx`, which the loop rewrites
  /// before it dereferences `base` again.
  AtomicFetchAlu {
    op: u8,
    w64: bool,
    src: u8,
    base: u8,
    disp: i32,
  },
  /// `xchg [base + disp], src`. Writes `src`.
  AtomicXchg {
    w64: bool,
    src: u8,
    base: u8,
    disp: i32,
  },
  /// `lock cmpxchg [base + disp], src`. Writes `rax`.
  AtomicCmpxchg {
    w64: bool,
    src: u8,
    base: u8,
    disp: i32,
  },

  /// Call external helper `idx` through the dispatcher. Contract: the
  /// dispatcher is registered; writes every register but `rsp`, `rbp` and
  /// the frame register, and every writable frame slot; two pushes deep.
  HelperCall {
    idx: u32,
  },

  /// A lazily-resolved local call through resolver slot `id`. Contract:
  /// the callbacks are registered; writes every register but `rsp`, `rbp`
  /// and the frame register, and the writable frame slots; the frame
  /// register is moved down one stride for the callee and restored;
  /// thirteen pushes deep.
  LazyLocalCall {
    id: u32,
  },

  /// The trailer, in this order and last: the retpoline the helper call
  /// goes through, the eight-byte dispatcher address, and the helper table.
  Retpoline,
  DispatcherSlot,
  HelperTable,
}

/// Where a primitive branch goes.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub enum PTarget {
  /// A translated eBPF slot.
  Pc(u32),
  /// The exit epilogue.
  Exit,
  /// The retpoline.
  Retpoline,
  /// A label local to one macro's expansion.
  Local(u32),
}

/// The primitive instruction set: one variant per x86 instruction shape the
/// backend emits. The encoder maps each to bytes; `lean/AsyncEbpf/X64/
/// Machine.lean` gives each its semantics.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub enum PInsn {
  /// Positions, for the encoder. They emit nothing.
  PcLabel(u32),
  Local(u32),
  ExitLabel,
  RetpolineLabel,

  Push(u8),
  Pop(u8),
  Alu {
    w64: bool,
    op: AluRR,
    src: u8,
    dst: u8,
  },
  AluImm {
    w64: bool,
    op: AluRI,
    dst: u8,
    imm: i32,
  },
  ShiftImm {
    w64: bool,
    op: ShiftOp,
    dst: u8,
    imm: i32,
  },
  ShiftCl {
    w64: bool,
    op: ShiftOp,
    dst: u8,
  },
  Neg {
    w64: bool,
    dst: u8,
  },
  /// `mul rcx` / `div rcx` / `idiv rcx`, at 32 or 64 bits.
  MulDivRcx {
    w64: bool,
    kind: MulDivKind,
    signed: bool,
  },
  MovSx {
    from: u8,
    w64: bool,
    src: u8,
    dst: u8,
  },
  Bswap {
    w64: bool,
    dst: u8,
  },
  Rol16 {
    dst: u8,
  },
  /// `cmovcc dst, src` at 64 bits.
  Cmov {
    cc: u8,
    dst: u8,
    src: u8,
  },
  LoadImm {
    dst: u8,
    imm: i64,
  },
  Pushfq,
  Popfq,
  Cqo,
  Cdq,
  /// `cmp rcx, -1` / `cmp ecx, -1` (`83 f9 ff`).
  CmpRcxMinusOne {
    w64: bool,
  },
  /// `cmp eax, imm32` (`3d imm32`).
  CmpEaxImm {
    imm: u32,
  },

  /// `[base + disp]` load into `dst`, zero-extending. `sx` sign-extends; the
  /// sign-extending 8-byte form encodes nothing.
  Load {
    size: Size,
    sx: bool,
    base: u8,
    dst: u8,
    disp: i32,
  },
  Store {
    size: Size,
    src: u8,
    base: u8,
    disp: i32,
  },
  StoreImm {
    size: Size,
    base: u8,
    disp: i32,
    imm: i32,
  },
  /// `op reg, [base + disp]` at 64 bits, for the bounds-check forms.
  AluRM {
    op: AluRM,
    reg: u8,
    base: u8,
    disp: i32,
  },
  /// `mov qword [rsp], imm32`.
  StoreRspImm {
    imm: u32,
  },
  /// `mov [rsp], rax`.
  StoreRspRax,

  LockAlu {
    op: u8,
    w64: bool,
    src: u8,
    base: u8,
    disp: i32,
  },
  LockCmpxchg {
    w64: bool,
    src: u8,
    base: u8,
    disp: i32,
  },
  Xchg {
    w64: bool,
    src: u8,
    base: u8,
    disp: i32,
  },

  /// `0f cc rel32`, a recorded fixup.
  Jcc {
    cc: u8,
    target: PTarget,
  },
  /// `e9 rel32`, a recorded fixup.
  Jmp {
    target: PTarget,
  },
  /// `eb rel8` followed by three bytes of padding, a recorded fixup.
  JmpNear {
    target: PTarget,
  },
  /// `e8 rel32`, a recorded fixup.
  Call {
    target: PTarget,
  },
  /// `7x rel8`, resolved directly to a local label.
  Jcc8 {
    cc: u8,
    target: u32,
  },
  /// `eb rel8`, resolved directly to a local label.
  Jmp8 {
    target: u32,
  },
  Ret,
  Pause,
  Ud2,
  /// `call rax` / `call reg`.
  CallReg(u8),
  /// `mov dst, [rip + dispatcher slot]`.
  RipLoadDispatcher {
    dst: u8,
  },
  /// `lea dst, [rip + helper table]`.
  RipLeaHelperTable {
    dst: u8,
  },

  /// Eight bytes of data: the dispatcher address.
  DispatcherSlot {
    addr: u64,
  },
  /// Sixty-four null helper addresses.
  HelperTable,
}

/// The `op reg, [mem]` forms the bounds checks use.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "extract"), derive(Debug, PartialEq, Eq))]
pub enum AluRM {
  /// `sub reg, [mem]` (`2b`).
  Sub,
  /// `add reg, [mem]` (`03`).
  Add,
  /// `cmp [mem], reg` (`39`): CF iff `[mem] < reg`.
  CmpMR,
  /// `cmp reg, [mem]` (`3b`): CF iff `reg < [mem]`.
  CmpRM,
  /// `or reg, [mem]` (`0b`).
  Or,
}

/// Condition codes, spelled as the low byte of the two-byte near `jcc`
/// opcode. The short `jcc` and `cmovcc` forms name the same conditions in the
/// `0x7x` and `0x4x` rows, and the encoder derives them from the low nibble.
pub mod cc {
  pub const B: u8 = 0x82;
  pub const AE: u8 = 0x83;
  pub const E: u8 = 0x84;
  pub const NE: u8 = 0x85;
  pub const BE: u8 = 0x86;
  pub const A: u8 = 0x87;
  pub const L: u8 = 0x8c;
  pub const GE: u8 = 0x8d;
  pub const LE: u8 = 0x8e;
  pub const G: u8 = 0x8f;
}

/// Ceiling on each relative-branch fixup table; see `patch::MAX_JUMPS`.
pub const MAX_JUMPS: u32 = 65536;
pub const MAX_LOADS: u32 = 65536;
pub const MAX_LEAS: u32 = 65536;

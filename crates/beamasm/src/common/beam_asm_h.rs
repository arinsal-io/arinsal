//! Port of erts/emulator/beam/jit/beam_asm.h (function prologue, native function wrapper and
//! breakpoint flag definitions), OTP-29.1.1, with the `BEAMASM` sizes it depends on from
//! code_ix.h (`ErtsCodeInfo`), beam_code.h (`BEAM_NATIVE_MIN_FUNC_SZ`) and erl_nif.c
//! (`ErtsNifBeamStub`). As in erts, one header serves both targets; the sizes that differ are
//! chosen by target architecture.

pub use arinsal_term::ErtsCodeInfo;

/// `sizeof(ErtsCodeInfo)`: the `i_func_info` block in front of every function's code.
pub const FUNC_INFO_BYTES: usize = core::mem::size_of::<ErtsCodeInfo>();
const _: () = assert!(FUNC_INFO_BYTES == 40);

/// `offsetof(ErtsCodeInfo, u.metadata.breakpoint_flag)`: the last byte of the metadata word
/// (`raise_function_clause[sizeof(BeamInstr) - 1]` precedes it).
// Port of erts/emulator/beam/code_ix.h:104-125 (ErtsCodeInfo, BEAMASM), OTP-29.1.1.
pub const BREAKPOINT_FLAG_OFFSET: usize = core::mem::size_of::<usize>() - 1;

/// Number of bytes emitted at a function's first label for tracing and NIF loading.
// Port of erts/emulator/beam/jit/beam_asm.h:124-130 (BEAM_ASM_FUNC_PROLOGUE_SIZE), OTP-29.1.1.
#[cfg(target_arch = "aarch64")]
pub const BEAM_ASM_FUNC_PROLOGUE_SIZE: usize = 12;
/// Number of bytes emitted at a function's first label for tracing and NIF loading.
// Port of erts/emulator/beam/jit/beam_asm.h:124-130 (BEAM_ASM_FUNC_PROLOGUE_SIZE), OTP-29.1.1.
#[cfg(not(target_arch = "aarch64"))]
pub const BEAM_ASM_FUNC_PROLOGUE_SIZE: usize = 8;

/// Size in bytes of an `ErtsNativeFunc`/`call_nif` prologue (`call_bif_nif`).
// Port of erts/emulator/beam/jit/beam_asm.h:132-137 (BEAM_ASM_NFUNC_SIZE), OTP-29.1.1.
#[cfg(target_arch = "aarch64")]
pub const BEAM_ASM_NFUNC_SIZE: usize = BEAM_ASM_FUNC_PROLOGUE_SIZE + 4;
/// Size in bytes of an `ErtsNativeFunc`/`call_nif` prologue (`call_bif_nif`).
// Port of erts/emulator/beam/jit/beam_asm.h:132-137 (BEAM_ASM_NFUNC_SIZE), OTP-29.1.1.
#[cfg(not(target_arch = "aarch64"))]
pub const BEAM_ASM_NFUNC_SIZE: usize = BEAM_ASM_FUNC_PROLOGUE_SIZE + 8;

/// `enum erts_asm_bp_flag`: what the breakpoint trampoline of a function does.
// Port of erts/emulator/beam/jit/beam_asm.h:172-178 (erts_asm_bp_flag), OTP-29.1.1.
pub const ERTS_ASM_BP_FLAG_NONE: u8 = 0;
/// See [`ERTS_ASM_BP_FLAG_NONE`]: a NIF is being loaded (`erts_call_nif_early`).
pub const ERTS_ASM_BP_FLAG_CALL_NIF_EARLY: u8 = 1 << 0;
/// See [`ERTS_ASM_BP_FLAG_NONE`]: a call breakpoint (`erts_generic_breakpoint`).
pub const ERTS_ASM_BP_FLAG_BP: u8 = 1 << 1;
/// See [`ERTS_ASM_BP_FLAG_NONE`]: both.
pub const ERTS_ASM_BP_FLAG_BP_NIF_CALL_NIF_EARLY: u8 =
    ERTS_ASM_BP_FLAG_CALL_NIF_EARLY | ERTS_ASM_BP_FLAG_BP;

/// Minimum size, in words, of a function `load_nif` can replace: its body must hold the
/// `call_nif` stub that `load_nif_1st_finisher` copies over it.
// Port of erts/emulator/beam/beam_code.h:44-48 (BEAM_NATIVE_MIN_FUNC_SZ, BEAMASM), OTP-29.1.1.
pub const BEAM_NATIVE_MIN_FUNC_SZ: usize = 30;

/// Size of `ErtsNifBeamStub.code.call_nif` (`BEAMASM`).
// Port of erts/emulator/beam/erl_nif.c:4628-4641 (ErtsNifBeamStub), OTP-29.1.1.
pub const NIF_STUB_CODE_BYTES: usize = 64;
const _: () = assert!(NIF_STUB_CODE_BYTES <= BEAM_NATIVE_MIN_FUNC_SZ * 8);

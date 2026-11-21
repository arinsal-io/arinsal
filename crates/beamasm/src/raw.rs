//! Port of the runtime ABIs in `erts/emulator/beam/erl_bits.c`, `beam_jit_bs.cpp`,
//! `beam_jit_common.cpp`, and the ARM `instr_*.cpp` / `process_main.cpp` sources.
//! Raw declarations and the native-entry trampoline used by AArch64 BeamAsm and its fixtures.

use crate::{ExitReason, NativeEntry, ProcessHeader, SchedulerRegisters};
use core::ffi::c_void;

/// Code address of an erts runtime symbol for BeamAsm `runtime_call`.
///
/// `f` is an `extern "C"` function item coerced to `*const ()` at the call site. This does
/// not call the function; generated code calls the C symbol.
#[inline(always)]
pub fn addr(f: *const ()) -> usize {
    f as usize
}

// Port of erts/emulator/beam/jit/beam_jit_common.cpp:679-704, OTP-29.1.1.
unsafe extern "C" {
    /// `beam_jit_load_nif(Process *, ErtsCodePtr, Eterm *)`.
    pub fn beam_jit_load_nif(
        c_p: *mut ProcessHeader,
        instruction: usize,
        registers: *mut u64,
    ) -> i32;
}

// Port of erts/emulator/beam/jit/arm/instr_common.cpp and instr_guard_bifs.cpp (`extern "C"
// { #include "erl_bif_op.h" #include "erl_map.h" }`), OTP-29.1.1: the runtime functions
// the guard emitters call by address (`runtime_call`). The VM defines them with these erts
// names and C signatures, the same symbols the x86 backend links (x86/rt.rs).
unsafe extern "C" {
    /// `Eterm erl_is_function(Process *p, Eterm term, Eterm arity)` (erl_bif_op.h).
    pub fn erl_is_function(c_p: *mut ProcessHeader, term: u64, arity: u64) -> u64;
    /// `Eterm get_map_element(Eterm map, Eterm key)` (beam_common.h): the value, or
    /// THE_NON_VALUE.
    pub fn get_map_element(map: u64, key: u64) -> u64;
    /// `Eterm get_map_element_hash(Eterm map, Eterm key, erts_ihash_t hx)` (beam_common.h).
    pub fn get_map_element_hash(map: u64, key: u64, hash: u64) -> u64;
    /// `const Export *apply(Process *p, Eterm *reg, ErtsCodePtr I, Uint flags)`
    /// (beam_common.h); the export address, or null after setting the process exception.
    pub fn apply(c_p: *mut ProcessHeader, reg: *mut u64, i: usize, flags: u64) -> usize;
    /// `const Export *fixed_apply(Process *p, Eterm *reg, Uint arity, ErtsCodePtr I,
    /// Uint flags)` (beam_common.h); the export address, or null after setting the process
    /// exception.
    pub fn fixed_apply(
        c_p: *mut ProcessHeader,
        reg: *mut u64,
        arity: u64,
        i: usize,
        flags: u64,
    ) -> usize;
}

// Port of erts/emulator/beam/jit/arm/instr_bif.cpp (emit_i_length_common:
// `runtime_call<..., erts_trapping_length_1>`), OTP-29.1.1.
unsafe extern "C" {
    /// `Eterm erts_trapping_length_1(Process *p, Eterm *args)` (erl_bif_guard.c): the length,
    /// or THE_NON_VALUE with `freason` TRAP (state updated in `args`) or an error.
    pub fn erts_trapping_length_1(c_p: *mut ProcessHeader, args: *mut u64) -> u64;
}

// Port of erts/emulator/beam/jit/arm/instr_bif.cpp (emit_i_bif_body_shared:
// `runtime_call<ErtsCodeMFA *(*)(void *), ubif2mfa>`), OTP-29.1.1.
unsafe extern "C" {
    /// `ErtsCodeMFA *ubif2mfa(void *uf)` (beam_common.c): the MFA of a `bif.tab` ubif.
    pub fn ubif2mfa(function: *const c_void) -> *const arinsal_term::ErtsCodeMfa;
}

// Port of erts/emulator/beam/jit/arm/instr_arith.cpp (`runtime_call<..., erts_mixed_plus>` and
// the other erl_arith.c entries), OTP-29.1.1: the arithmetic runtime functions the emitters and
// global fragments call by address. Each returns THE_NON_VALUE (or 0) on failure with the
// exception in `c_p->freason`; the VM defines them in erl_arith.rs, the symbols x86 links.
unsafe extern "C" {
    /// `Eterm erts_mixed_plus(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_mixed_plus(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mixed_minus(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_mixed_minus(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mixed_times(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_mixed_times(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mixed_div(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_mixed_div(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_mul_add(Process *p, Eterm arg1, Eterm arg2, Eterm arg3, Eterm *pp)`.
    pub fn erts_mul_add(
        c_p: *mut ProcessHeader,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        pp: *mut u64,
    ) -> u64;
    /// `int erts_int_div_rem(Process *p, Eterm arg1, Eterm arg2, Eterm *q, Eterm *r)`.
    pub fn erts_int_div_rem(
        c_p: *mut ProcessHeader,
        arg1: u64,
        arg2: u64,
        q: *mut u64,
        r: *mut u64,
    ) -> i32;
    /// `Eterm erts_unary_minus(Process *p, Eterm arg1)`.
    pub fn erts_unary_minus(c_p: *mut ProcessHeader, arg1: u64) -> u64;
    /// `Eterm erts_band(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_band(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bor(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_bor(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bxor(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_bxor(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bsl(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_bsl(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bsr(Process *p, Eterm arg1, Eterm arg2)`.
    pub fn erts_bsr(c_p: *mut ProcessHeader, arg1: u64, arg2: u64) -> u64;
    /// `Eterm erts_bnot(Process *p, Eterm arg)`.
    pub fn erts_bnot(c_p: *mut ProcessHeader, arg: u64) -> u64;
    /// `Eterm beam_jit_int128_to_big(Process *p, Uint sign, Uint low, Uint high)`
    /// (beam_jit_common.cpp).
    pub fn beam_jit_int128_to_big(c_p: *mut ProcessHeader, sign: u64, low: u64, high: u64) -> u64;
}

// Port of erts/emulator/beam/jit/arm/instr_bs.cpp runtime_call targets and their
// erl_bits.c / beam_jit_common.cpp declarations, OTP-29.1.1. The VM defines these Rust ports
// with the original runtime names and argument order.
unsafe extern "C" {
    /// `ErlSubBits *erts_bs_start_match_3(Process *, Eterm)`.
    pub fn erts_bs_start_match_3(c_p: *mut ProcessHeader, value: u64) -> *mut u64;
    /// `Eterm erts_bs_get_integer_2(Process *, Uint, unsigned, ErlSubBits *)`.
    pub fn erts_bs_get_integer_2(
        c_p: *mut ProcessHeader,
        num_bits: u64,
        flags: u32,
        sub_bits: *mut u64,
    ) -> u64;
    /// `Eterm erts_bs_get_binary_2(Process *, Uint, ErlSubBits *)`.
    pub fn erts_bs_get_binary_2(c_p: *mut ProcessHeader, num_bits: u64, sub_bits: *mut u64) -> u64;
    /// `Eterm erts_bs_get_float_2(Process *, Uint, unsigned, ErlSubBits *)`.
    pub fn erts_bs_get_float_2(
        c_p: *mut ProcessHeader,
        num_bits: u64,
        flags: u32,
        sub_bits: *mut u64,
    ) -> u64;
    /// `Eterm erts_bs_get_utf8(ErlSubBits *)`.
    pub fn erts_bs_get_utf8(sub_bits: *mut u64) -> u64;
    /// `Eterm erts_bs_get_utf16(ErlSubBits *, Uint)`.
    pub fn erts_bs_get_utf16(sub_bits: *mut u64, flags: u64) -> u64;
    /// `Eterm erts_build_sub_bitstring(Eterm **, Eterm, const BinRef *, const byte *, Uint, Uint)`.
    pub fn erts_build_sub_bitstring(
        hp: *mut *mut u64,
        br_flags: u64,
        br: *const u64,
        base: *const u8,
        offset: u64,
        size: u64,
    ) -> u64;
    /// `int erts_cmp_bits(const byte *, Uint, const byte *, Uint, Uint)`.
    pub fn erts_cmp_bits(
        a: *const u8,
        a_offset: u64,
        b: *const u8,
        b_offset: u64,
        size: u64,
    ) -> i32;
    /// `Eterm beam_jit_bs_get_integer(Process *, Eterm *, Eterm, Uint, Uint, Uint)`.
    pub fn beam_jit_bs_get_integer(
        c_p: *mut ProcessHeader,
        reg: *mut u64,
        context: u64,
        flags: u64,
        size: u64,
        live: u64,
    ) -> u64;
    /// `Eterm beam_jit_bs_init_bits(Process *, Eterm *, ErlBitsState *, Uint, Uint, unsigned)`.
    pub fn beam_jit_bs_init_bits(
        c_p: *mut ProcessHeader,
        reg: *mut u64,
        ebs: *mut u64,
        num_bits: u64,
        alloc: u64,
        live: u32,
    ) -> u64;
    /// `void beam_jit_bs_construct_fail_info(Process *, Uint, Eterm, Eterm)`.
    pub fn beam_jit_bs_construct_fail_info(
        c_p: *mut ProcessHeader,
        packed_error_info: u64,
        arg3: u64,
        arg1: u64,
    );
    /// `Sint beam_jit_bs_bit_size(Eterm)`; `-1` means the term is not a bitstring.
    pub fn beam_jit_bs_bit_size(term: u64) -> i64;
    /// `Eterm erts_bs_append_checked(Process *, Eterm *, Uint, Uint, Uint, Uint)`.
    pub fn erts_bs_append_checked(
        c_p: *mut ProcessHeader,
        reg: *mut u64,
        live: u64,
        build_size_in_bits: u64,
        extra_words: u64,
        unit: u64,
    ) -> u64;
    /// `Eterm erts_bs_private_append_checked(ErlBitsState *, Process *, Eterm, Uint)`.
    pub fn erts_bs_private_append_checked(
        ebs: *mut u64,
        c_p: *mut ProcessHeader,
        bin: u64,
        extra_bits: u64,
    ) -> u64;
    /// `Eterm erts_bs_init_writable(Process *, Eterm)`.
    pub fn erts_bs_init_writable(c_p: *mut ProcessHeader, size: u64) -> u64;
    /// `int erts_bs_put_integer_be(ErlBitsState *, Eterm, Uint)`.
    pub fn erts_bs_put_integer_be(ebs: *mut u64, value: u64, num_bits: u64) -> i32;
    /// `int erts_bs_put_integer_le(ErlBitsState *, Eterm, Uint)`.
    pub fn erts_bs_put_integer_le(ebs: *mut u64, value: u64, num_bits: u64) -> i32;
    /// `int erts_bs_put_binary(ErlBitsState *, Process *, Eterm, Uint)`.
    pub fn erts_bs_put_binary(
        ebs: *mut u64,
        c_p: *mut ProcessHeader,
        value: u64,
        num_bits: u64,
    ) -> i32;
    /// `int erts_bs_put_binary_all(ErlBitsState *, Process *, Eterm, Uint)`.
    pub fn erts_bs_put_binary_all(
        ebs: *mut u64,
        c_p: *mut ProcessHeader,
        value: u64,
        unit: u64,
    ) -> i32;
    /// `void beam_jit_bs_put_binary_all(ErlBitsState *, Process *, Eterm)`.
    pub fn beam_jit_bs_put_binary_all(ebs: *mut u64, c_p: *mut ProcessHeader, value: u64);
    /// `Eterm erts_bs_put_float(ErlBitsState *, Process *, Eterm, Uint, int)`.
    pub fn erts_bs_put_float(
        ebs: *mut u64,
        c_p: *mut ProcessHeader,
        value: u64,
        num_bits: u64,
        flags: i32,
    ) -> u64;
    /// `int erts_bs_put_utf16(ErlBitsState *, Eterm, Uint)`.
    pub fn erts_bs_put_utf16(ebs: *mut u64, value: u64, flags: u64) -> i32;
    /// `void erts_bs_put_string(ErlBitsState *, byte *, Uint)`.
    pub fn erts_bs_put_string(ebs: *mut u64, source: *const u8, num_bytes: u64);
}

// Port of erts/emulator/beam/jit/arm/instr_map.cpp runtime call prototypes, OTP-29.1.1: the map
// runtime functions the map emitters and global fragments call by address (beam_common.c,
// erl_map.c, beam_jit_common.cpp); the VM defines the symbols x86 links.
unsafe extern "C" {
    /// `Eterm erts_gc_new_map(Process *, Eterm *, Uint, Uint, const Eterm *)`.
    pub fn erts_gc_new_map(
        c_p: *mut ProcessHeader,
        reg: *mut u64,
        live: u64,
        n: u64,
        data: *const u64,
    ) -> u64;
    /// `Eterm erts_gc_update_map_assoc(Process *, Eterm *, Uint, Uint, const Eterm *)`.
    pub fn erts_gc_update_map_assoc(
        c_p: *mut ProcessHeader,
        reg: *mut u64,
        live: u64,
        n: u64,
        data: *const u64,
    ) -> u64;
    /// `Eterm erts_gc_update_map_exact(Process *, Eterm *, Uint, Uint, const Eterm *)`.
    pub fn erts_gc_update_map_exact(
        c_p: *mut ProcessHeader,
        reg: *mut u64,
        live: u64,
        n: u64,
        data: *const u64,
    ) -> u64;
    /// `Uint beam_jit_get_map_elements(Eterm, Eterm *, Eterm *, Uint, Eterm *)`.
    pub fn beam_jit_get_map_elements(
        map: u64,
        reg: *mut u64,
        stack: *mut u64,
        n: u64,
        fs: *mut u64,
    ) -> u64;
    /// `Eterm erts_maps_put(Process *, Eterm, Eterm, Eterm)`.
    pub fn erts_maps_put(c_p: *mut ProcessHeader, key: u64, value: u64, map: u64) -> u64;
    /// `int erts_maps_update(Process *, Eterm, Eterm, Eterm, Eterm *)`.
    pub fn erts_maps_update(
        c_p: *mut ProcessHeader,
        key: u64,
        value: u64,
        map: u64,
        result: *mut u64,
    ) -> i32;
}

// Port of erts/emulator/beam/jit/arm/instr_records.cpp runtime call prototypes, OTP-29.1.1: the
// erl_record.c functions the record emitters call by address; the VM defines the symbols x86
// links. Each returns THE_NON_VALUE (or false) on failure with the exception in `c_p->freason`.
unsafe extern "C" {
    /// `bool erl_get_record_elements(Process *, Eterm *, Eterm, Uint, const Eterm *)`.
    pub fn erl_get_record_elements(
        c_p: *mut ProcessHeader,
        reg: *mut u64,
        source: u64,
        count: usize,
        elements: *const u64,
    ) -> bool;
    /// `Eterm erl_create_local_native_record(Process *, Eterm *, Eterm, Uint, Uint, const Eterm *)`.
    pub fn erl_create_local_native_record(
        c_p: *mut ProcessHeader,
        reg: *mut u64,
        definition: u64,
        live: u64,
        count: usize,
        elements: *const u64,
    ) -> u64;
    /// `Eterm erl_create_native_record(Process *, Eterm *, Eterm, Uint, Uint, const Eterm *)`.
    pub fn erl_create_native_record(
        c_p: *mut ProcessHeader,
        reg: *mut u64,
        definition_id: u64,
        live: u64,
        count: usize,
        elements: *const u64,
    ) -> u64;
    /// `Eterm erl_update_native_record(Process *, Eterm *, Eterm, Uint, Uint, const Eterm *)`.
    pub fn erl_update_native_record(
        c_p: *mut ProcessHeader,
        reg: *mut u64,
        source: u64,
        live: u64,
        count: usize,
        elements: *const u64,
    ) -> u64;
    /// `Eterm erl_get_local_record_field(Process *, Eterm, Eterm, Eterm)`.
    pub fn erl_get_local_record_field(
        c_p: *mut ProcessHeader,
        source: u64,
        definition_id: u64,
        name: u64,
    ) -> u64;
    /// `Eterm erl_get_record_field(Process *, Eterm, Eterm, Eterm)`.
    pub fn erl_get_record_field(
        c_p: *mut ProcessHeader,
        source: u64,
        definition_id: u64,
        name: u64,
    ) -> u64;
}

#[cfg(any(test, feature = "test-runtime-stubs"))]
mod test_stubs {
    use super::ProcessHeader;

    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_load_nif(_: *mut ProcessHeader, _: usize, _: *mut u64) -> i32 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erl_is_function(_: *mut ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn get_map_element(_: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn ubif2mfa(_: *const core::ffi::c_void) -> *const arinsal_term::ErtsCodeMfa {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_trapping_length_1(_: *mut ProcessHeader, _: *mut u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn get_map_element_hash(_: u64, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    /// Fixture for BeamAsm apply tests: `c_p->id` holds the Export* the emitter dispatches.
    #[unsafe(no_mangle)]
    extern "C" fn apply(c_p: *mut ProcessHeader, _: *mut u64, _: usize, _: u64) -> usize {
        super::process_header_mut(c_p, |header| header.self_pid as usize)
    }

    /// Fixture for BeamAsm fixed-apply tests: records arity in `fvalue` and returns the Export*.
    #[unsafe(no_mangle)]
    extern "C" fn fixed_apply(
        c_p: *mut ProcessHeader,
        _: *mut u64,
        arity: u64,
        _: usize,
        _: u64,
    ) -> usize {
        super::process_header_mut(c_p, |header| {
            header.exc.fvalue = arity;
            header.self_pid as usize
        })
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_mixed_plus(_: *mut ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_mixed_minus(_: *mut ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_mixed_times(_: *mut ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_mixed_div(_: *mut ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_mul_add(_: *mut ProcessHeader, _: u64, _: u64, _: u64, _: *mut u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_int_div_rem(
        _: *mut ProcessHeader,
        _: u64,
        _: u64,
        _: *mut u64,
        _: *mut u64,
    ) -> i32 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_unary_minus(_: *mut ProcessHeader, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_band(_: *mut ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bor(_: *mut ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bxor(_: *mut ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bsl(_: *mut ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bsr(_: *mut ProcessHeader, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bnot(_: *mut ProcessHeader, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_int128_to_big(_: *mut ProcessHeader, _: u64, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_gc_new_map(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_gc_update_map_assoc(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_gc_update_map_exact(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_get_map_elements(
        _: u64,
        _: *mut u64,
        _: *mut u64,
        _: u64,
        _: *mut u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erl_get_record_elements(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: usize,
        _: *const u64,
    ) -> bool {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erl_create_local_native_record(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: usize,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erl_create_native_record(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: usize,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erl_update_native_record(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: usize,
        _: *const u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erl_get_local_record_field(_: *mut ProcessHeader, _: u64, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erl_get_record_field(_: *mut ProcessHeader, _: u64, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_maps_put(_: *mut ProcessHeader, _: u64, _: u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_maps_update(
        _: *mut ProcessHeader,
        _: u64,
        _: u64,
        _: u64,
        _: *mut u64,
    ) -> i32 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_start_match_3(_: *mut ProcessHeader, _: u64) -> *mut u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_get_integer_2(_: *mut ProcessHeader, _: u64, _: u32, _: *mut u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_get_binary_2(_: *mut ProcessHeader, _: u64, _: *mut u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_get_float_2(_: *mut ProcessHeader, _: u64, _: u32, _: *mut u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_get_utf8(_: *mut u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_get_utf16(_: *mut u64, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_build_sub_bitstring(
        _: *mut *mut u64,
        _: u64,
        _: *const u64,
        _: *const u8,
        _: u64,
        _: u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_cmp_bits(_: *const u8, _: u64, _: *const u8, _: u64, _: u64) -> i32 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_bs_get_integer(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: u64,
        _: u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_bs_init_bits(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: *mut u64,
        _: u64,
        _: u64,
        _: u32,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_bs_construct_fail_info(_: *mut ProcessHeader, _: u64, _: u64, _: u64) {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_bs_bit_size(_: u64) -> i64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_append_checked(
        _: *mut ProcessHeader,
        _: *mut u64,
        _: u64,
        _: u64,
        _: u64,
        _: u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_private_append_checked(
        _: *mut u64,
        _: *mut ProcessHeader,
        _: u64,
        _: u64,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_init_writable(_: *mut ProcessHeader, _: u64) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_put_integer_be(_: *mut u64, _: u64, _: u64) -> i32 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_put_integer_le(_: *mut u64, _: u64, _: u64) -> i32 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_put_binary(_: *mut u64, _: *mut ProcessHeader, _: u64, _: u64) -> i32 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_put_binary_all(
        _: *mut u64,
        _: *mut ProcessHeader,
        _: u64,
        _: u64,
    ) -> i32 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn beam_jit_bs_put_binary_all(_: *mut u64, _: *mut ProcessHeader, _: u64) {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_put_float(
        _: *mut u64,
        _: *mut ProcessHeader,
        _: u64,
        _: u64,
        _: i32,
    ) -> u64 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_put_utf16(_: *mut u64, _: u64, _: u64) -> i32 {
        unreachable!("byte-test fixture")
    }

    #[unsafe(no_mangle)]
    extern "C" fn erts_bs_put_string(_: *mut u64, _: *const u8, _: u64) {
        unreachable!("byte-test fixture")
    }
}

/// Returns the tagged word for a test-owned term whose heap remains live.
pub fn term_bits(term: arinsal_term::Term) -> u64 {
    term.tagged_word()
}

/// Rebuilds a term from a tagged word a test fixture built, for the typed X register array.
pub fn fixture_term(bits: u64) -> arinsal_term::Term {
    // SAFETY: Fixtures pass immediates or tagged pointers into heaps they retain for the call.
    unsafe { arinsal_term::Term::from_raw_bits(bits) }
}

/// Tagged words of typed registers, for comparing them with fixture words.
pub fn fixture_words(terms: &[arinsal_term::Term]) -> Vec<u64> {
    terms.iter().map(|term| term.tagged_word()).collect()
}

/// Stores fixture words into typed registers.
pub fn set_fixture_words(terms: &mut [arinsal_term::Term], words: &[u64]) {
    for (term, &word) in terms.iter_mut().zip(words) {
        *term = fixture_term(word);
    }
}

/// Reads a tuple view for a test-owned term with a live owner heap.
pub fn tuple_ref(term: arinsal_term::Term) -> Option<arinsal_term::TupleRef<'static>> {
    // SAFETY: Integration fixtures retain their heap for the full native helper call.
    unsafe { term.tuple_ref() }
}

/// Reads a cons cell for a test-owned term with a live owner heap.
pub fn cons_ref(term: arinsal_term::Term) -> Option<(arinsal_term::Term, arinsal_term::Term)> {
    // SAFETY: Integration fixtures retain their heap for the full native helper call.
    unsafe { term.cons_ref() }
}

/// Reads a binary view for a test-owned term with a live owner heap.
pub fn binary_bit_len(term: arinsal_term::Term) -> Option<usize> {
    // SAFETY: Integration fixtures retain their heap for the full native helper call.
    unsafe { term.binary_ref() }.map(|view| view.bit_len())
}

/// Reads a flat map view for a test-owned term with a live owner heap.
pub fn flatmap_ref(term: arinsal_term::Term) -> Option<arinsal_term::FlatMapRef<'static>> {
    // SAFETY: Integration fixtures retain their heap for the full native helper call.
    unsafe { term.flatmap_ref() }
}

/// Reads a fun view for a test-owned term with a live owner heap.
pub fn fun_ref(term: arinsal_term::Term) -> Option<arinsal_term::FunRef<'static>> {
    // SAFETY: Integration fixtures retain their heap for the full native helper call.
    unsafe { term.fun_ref() }
}

/// Exposes a native process header to a C ABI hook during its call.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn process_header_mut<R>(
    pointer: *mut ProcessHeader,
    f: impl FnOnce(&mut ProcessHeader) -> R,
) -> R {
    // SAFETY: The BeamAsm entry bridge passes the unique live header pointer for this invocation.
    unsafe { f(&mut *pointer) }
}

/// Exposes the scheduler registers behind the `reg` pointer (x19, `x_reg_array`) native code
/// passed to a C ABI hook during its call.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn scheduler_registers_mut<R>(
    reg: *mut u64,
    f: impl FnOnce(&mut SchedulerRegisters) -> R,
) -> R {
    // SAFETY: native code passes `reg` (load_x_reg_array) of the unique live register area.
    unsafe { f(&mut *SchedulerRegisters::from_reg(reg)) }
}

/// Copies initialized test heap words into a new allocation.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn copy_words(source: *const u64, destination: *mut u64, count: usize) {
    // SAFETY: Test GC hooks pass live, disjoint allocations and the initialized source prefix.
    unsafe { core::ptr::copy_nonoverlapping(source, destination, count) }
}

/// Reads a heap word from a tagged boxed pointer in a retained test fixture.
pub fn read_heap_word(tagged: u64, index: usize) -> u64 {
    let pointer = (tagged & !7) as *const u64;
    // SAFETY: The test fixture retains the allocated object and callers select a valid field.
    unsafe { *pointer.add(index) }
}

/// Per-call exit fragment result passed between the assembly bridge and Rust.
#[repr(C)]
#[derive(Default)]
struct NativeExit {
    kind: u64,
    target: usize,
    resume: usize,
}

/// Enters generated native code with BeamAsm's pinned register map.
///
/// Native code returns to the private exit fragment with `x0 = 0` for return,
/// `x0 = 2` and `x1 = target_pc` for an unported function, or any other value
/// to use reductions (`fcalls <= 0` yields).
///
/// # Safety
/// `code_ptr` must point to executable AArch64 code that follows the BeamAsm
/// register contract and returns to the bridge exit address in `x30`.
// Port of erts/emulator/beam/jit/arm/process_main.cpp:235-317, OTP-29.1.1
pub(super) fn enter_native(
    header: &mut ProcessHeader,
    regs: &mut SchedulerRegisters,
    entry: &NativeEntry<'_>,
) -> ExitReason {
    let code_ptr = entry.memory.ptr_at(entry.offset).cast::<c_void>();
    // SAFETY: a NativeEntry is only created by `finalize` and borrows its live code mapping.
    unsafe { enter_native_raw(header, regs, code_ptr) }
}

/// Enters generated code by raw address through the process-wide pinned-register trampoline.
/// Callers keep code alive themselves (the VM's native code registry).
///
/// # Safety
/// `code_ptr` must point into a live executable mapping produced by the module assembler, at a
/// function entry that follows the BeamAsm register contract.
// Inlined so the scheduler's slice calls the trampoline directly: one host frame fewer to
// return through after a switch-out (see the VM's `Executor::run`).
#[inline(always)]
pub unsafe fn enter_native_raw(
    header: &mut ProcessHeader,
    regs: &mut SchedulerRegisters,
    code_ptr: *const c_void,
) -> ExitReason {
    #[cfg(target_arch = "aarch64")]
    {
        let mut exit = NativeExit::default();
        // SAFETY: The assembly bridge saves host callee-saved registers, loads the documented
        // ProcessHeader/SchedulerRegisters layout, branches to code_ptr, and returns via its exit label.
        unsafe { arinsal_enter_native(header, regs, code_ptr, &mut exit) };
        match exit.kind {
            2 => ExitReason::CallUnported {
                target_pc: exit.target,
                resume_pc: exit.resume,
            },
            // A return into the bridge is a return even when it used the last reduction;
            // yields leave through the same fragment with kind 1 in the marker slot and `c_p->i` set.
            0 => ExitReason::Returned,
            _ => ExitReason::Yield,
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (header, regs, code_ptr);
        ExitReason::Unsupported
    }
}

#[cfg(target_arch = "aarch64")]
// The pointer exposes the fixed C-layout prefix; trailing BIF bookkeeping is Rust-only.
#[allow(improper_ctypes)]
unsafe extern "C" {
    pub fn arinsal_enter_native_return();
    /// erts `beam_return_trace`: the return address of a return_trace frame.
    pub fn arinsal_return_trace();
    /// erts `beam_exception_trace`: the return address of an exception_trace frame.
    pub fn arinsal_exception_trace();
    /// erts `beam_return_to_trace`: the return address of a return_to frame.
    pub fn arinsal_return_to_trace();
    /// erts `beam_call_trace_return`: the return address of a call time/memory frame.
    pub fn arinsal_call_trace_return();
    fn arinsal_enter_native(
        header: *mut ProcessHeader,
        regs: *mut SchedulerRegisters,
        code: *const c_void,
        exit: *mut NativeExit,
    );
}

/// `f_reg_array` lies past `add`'s 12-bit immediate: the bridge adds this 4 KiB-page part
/// and addresses the float registers from it.
const F_PAGE: u32 = crate::arm::beam_asm::F_REG_ARRAY_REF & !4095;

// Mach-O prepends an underscore to C symbols and uses @PAGE/@PAGEOFF; ELF uses neither.
#[cfg(target_vendor = "apple")]
macro_rules! asm_sym {
    ($name:literal) => {
        concat!("_", $name)
    };
}
#[cfg(not(target_vendor = "apple"))]
macro_rules! asm_sym {
    ($name:literal) => {
        $name
    };
}
/// `labels[dispatch_nif]` of process_main: the global fragment a schedule-in branches to when
/// `c_p->i` points at an `ErtsNativeFunc` trampoline holding `op_call_nif_WWW`. The entry
/// trampoline below is this port's process_main, so it reads the label from here.
// Port of erts/emulator/beam/jit/arm/process_main.cpp:250-267 (`labels[dispatch_nif]`),
// OTP-29.1.1.
#[unsafe(no_mangle)]
pub static ARINSAL_PROCESS_MAIN_DISPATCH_NIF: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Publishes the global fragments process_main dispatches to on schedule-in.
pub fn set_process_main_labels(dispatch_nif: usize) {
    ARINSAL_PROCESS_MAIN_DISPATCH_NIF
        .store(dispatch_nif as u64, core::sync::atomic::Ordering::Release);
}

#[cfg(target_vendor = "apple")]
macro_rules! asm_load_dispatch_nif {
    () => {
        concat!(
            "adrp x2, _ARINSAL_PROCESS_MAIN_DISPATCH_NIF@PAGE\n",
            "ldr x2, [x2, _ARINSAL_PROCESS_MAIN_DISPATCH_NIF@PAGEOFF]"
        )
    };
}
#[cfg(not(target_vendor = "apple"))]
macro_rules! asm_load_dispatch_nif {
    () => {
        concat!(
            "adrp x2, ARINSAL_PROCESS_MAIN_DISPATCH_NIF\n",
            "ldr x2, [x2, :lo12:ARINSAL_PROCESS_MAIN_DISPATCH_NIF]"
        )
    };
}

#[cfg(target_vendor = "apple")]
macro_rules! asm_load_enter_native_return {
    () => {
        concat!(
            "adrp x30, _arinsal_enter_native_return@PAGE\n",
            "add x30, x30, _arinsal_enter_native_return@PAGEOFF"
        )
    };
}
#[cfg(not(target_vendor = "apple"))]
macro_rules! asm_load_enter_native_return {
    () => {
        concat!(
            "adrp x30, arinsal_enter_native_return\n",
            "add x30, x30, :lo12:arinsal_enter_native_return"
        )
    };
}

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    // Port of erts/emulator/beam/jit/beam_jit_main.cpp:255-270 (the `erts_beamasm` trace
    // return addresses) and jit/arm/instr_trace.cpp (emit_return_trace, emit_i_return_to_trace,
    // emit_i_call_trace_return), OTP-29.1.1: one return address per trace frame kind. Each
    // passes its kind (`TRACE_FRAME_*`) to the shared Rust hook in x1.
    concat!(".global ", asm_sym!("arinsal_return_trace")),
    concat!(asm_sym!("arinsal_return_trace"), ":"),
    "mov x1, #0",
    "b 1f",
    concat!(".global ", asm_sym!("arinsal_exception_trace")),
    concat!(asm_sym!("arinsal_exception_trace"), ":"),
    "mov x1, #1",
    "b 1f",
    concat!(".global ", asm_sym!("arinsal_return_to_trace")),
    concat!(asm_sym!("arinsal_return_to_trace"), ":"),
    "mov x1, #2",
    "b 1f",
    concat!(".global ", asm_sym!("arinsal_call_trace_return")),
    concat!(asm_sym!("arinsal_call_trace_return"), ":"),
    "mov x1, #3",
    "1:",
    // Publish the BEAM cursors and register cache before the Rust trace hook.
    "str x20, [x21, #8]",
    "str x23, [x21, #0]",
    "str w22, [x21, #32]",
    "stp x25, x26, [x19, #{x0}]",
    "stp x27, x28, [x19, #{x2}]",
    "stp x15, x16, [x19, #{x4}]",
    "add x15, x19, #{f_page}",
    "stp d8, d9, [x15, #{f0}]",
    "stp d10, d11, [x15, #{f1}]",
    "stp d12, d13, [x15, #{f2}]",
    "stp d14, d15, [x15, #{f3}]",
    "mov x0, x21",
    // `reg`: the hook roots and reloads the X registers through it.
    "add x2, x19, #{x0}",
    "ldr x16, [x19, #{trace_hook}]",
    "blr x16",
    "mov x14, x0",
    "ldr x20, [x21, #8]",
    "ldr x23, [x21, #0]",
    "ldr w22, [x21, #32]",
    "ldp x25, x26, [x19, #{x0}]",
    "ldp x27, x28, [x19, #{x2}]",
    "ldp x15, x16, [x19, #{x4}]",
    "add x17, x19, #{f_page}",
    "ldp d8, d9, [x17, #{f0}]",
    "ldp d10, d11, [x17, #{f1}]",
    "ldp d12, d13, [x17, #{f2}]",
    "ldp d14, d15, [x17, #{f3}]",
    // A hook that hands the return to the scheduler leaves the exit target and resume
    // address in tmp_mem[0..2] and returns the exit fragment; x1/x2 are free at a return.
    "ldr x1, [x19, #{tmp_mem0}]",
    "ldr x2, [x19, #{tmp_mem1}]",
    "br x14",
    trace_hook = const crate::arm::beam_asm::tmp_mem_ref(5),
    tmp_mem0 = const crate::arm::beam_asm::tmp_mem_ref(0),
    tmp_mem1 = const crate::arm::beam_asm::tmp_mem_ref(1),
    x0 = const crate::arm::beam_asm::x_ref(0),
    x2 = const crate::arm::beam_asm::x_ref(2),
    x4 = const crate::arm::beam_asm::x_ref(4),
    f_page = const F_PAGE,
    f0 = const crate::arm::beam_asm::F_REG_ARRAY_REF - F_PAGE,
    f1 = const crate::arm::beam_asm::F_REG_ARRAY_REF - F_PAGE + 16,
    f2 = const crate::arm::beam_asm::F_REG_ARRAY_REF - F_PAGE + 32,
    f3 = const crate::arm::beam_asm::F_REG_ARRAY_REF - F_PAGE + 48,
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    concat!(".global ", asm_sym!("arinsal_enter_native")),
    concat!(asm_sym!("arinsal_enter_native"), ":"),
    // Port of erts/emulator/beam/jit/arm/process_main.cpp:235-317, OTP-29.1.1.
    // Keep this entry trampoline and the exit fragment below shared across entries.
    // Preserve AAPCS64 callee-saved GPRs, frame/link registers, and d8-d15.
    "stp x29, x30, [sp, #-16]!",
    "stp x19, x20, [sp, #-16]!",
    "stp x21, x22, [sp, #-16]!",
    "stp x23, x24, [sp, #-16]!",
    "stp x25, x26, [sp, #-16]!",
    "stp x27, x28, [sp, #-16]!",
    "stp d8, d9, [sp, #-16]!",
    "stp d10, d11, [sp, #-16]!",
    "stp d12, d13, [sp, #-16]!",
    "stp d14, d15, [sp, #-16]!",
    "sub sp, sp, #16",
    "str x3, [sp, #0]",
    // x19 is `scheduler_registers`, the start of the register file
    // (process_main.cpp:61-73); x21 is c_p.
    "mov x19, x1",
    "mov x21, x0",
    "ldr x20, [x21, #8]",
    "ldr w22, [x21, #32]",
    "ldr x23, [x21, #0]",
    // Port of erts/emulator/beam/jit/arm/process_main.cpp:236-247, OTP-29.1.1: the runtime
    // already resolved the process's code index (save_calls or the active one).
    "ldr x24, [x19, #{active_code_ix}]",
    "ldp x25, x26, [x19, #{x0}]",
    "ldp x27, x28, [x19, #{x2}]",
    "ldp x15, x16, [x19, #{x4}]",
    "add x14, x19, #{f_page}",
    "ldp d8, d9, [x14, #{f0}]",
    "ldp d10, d11, [x14, #{f1}]",
    "ldp d12, d13, [x14, #{f2}]",
    "ldp d14, d15, [x14, #{f3}]",
    // The native function's RET lands at the ABI exit fragment.
    asm_load_enter_native_return!(),
    // Runtime error fragments use this slot after runtime hooks replace x30.
    "str x30, [x19, #{exit_fragment}]",
    // Port of erts/emulator/beam/jit/arm/process_main.cpp:250-267, OTP-29.1.1: a process
    // returning from a dirty or scheduled NIF has `c_p->i` (x2, which the runtime stored in
    // `c_p->i`) on an `ErtsNativeFunc` trampoline, encoded as UDF(op_call_nif_WWW), UDF(0),
    // which native code never emits; it continues in `dispatch_nif`.
    "ldr x9, [x2]",
    "cmp x9, #{op_call_nif}",
    "b.ne 3f",
    asm_load_dispatch_nif!(),
    "3:",
    // A call entered from the scheduler returns to its caller's continuation, so the
    // callee's frame holds that real CP instead of the bridge (`entry_return`).
    "ldr x9, [x19, #{entry_return}]",
    "cbz x9, 1f",
    "mov x30, x9",
    "str xzr, [x19, #{entry_return}]",
    // Port of erts/emulator/beam/jit/arm/process_main.cpp:284-288, OTP-29.1.1.
    // A scheduler re-entry can target a BIF continuation, whose result is in XREG0.
    "ldr x0, [x19, #{x0}]",
    "br x2",
    "1:",
    "ldr x0, [x19, #{x0}]",
    // The call pushes the exit fragment's address on the return-address predictor, so the
    // native function's RET to it and the fragment's own RET back to the Rust caller are both
    // predicted. A `br` here leaves the predictor one entry short and every RET up the
    // scheduler's call chain after a switch-out mispredicts.
    "blr x2",
    // This label must directly follow the `blr x2` above: its link value is the exit fragment.
    concat!(".global ", asm_sym!("arinsal_enter_native_return")),
    concat!(asm_sym!("arinsal_enter_native_return"), ":"),
    // The marker distinguishes an interpreter handoff without adding work to each BEAM return.
    "ldr x9, [x19, #{exit_marker}]",
    // Consume the marker so a later plain return is not taken for a handoff.
    "str xzr, [x19, #{exit_marker}]",
    "cbnz x9, 1f",
    "mov x0, xzr",
    "b 2f",
    "1:",
    "mov x0, x9",
    "2:",
    // Spill native process state and all six register-backed X registers.
    "str x23, [x21, #0]",
    "str x20, [x21, #8]",
    "str w22, [x21, #32]",
    "stp x25, x26, [x19, #{x0}]",
    "stp x27, x28, [x19, #{x2}]",
    "stp x15, x16, [x19, #{x4}]",
    "add x14, x19, #{f_page}",
    "stp d8, d9, [x14, #{f0}]",
    "stp d10, d11, [x14, #{f1}]",
    "stp d12, d13, [x14, #{f2}]",
    "stp d14, d15, [x14, #{f3}]",
    // Keep the output pointer in this bridge's own stack frame across native code.
    "ldr x9, [sp, #0]",
    "stp x0, x1, [x9]",
    "str x2, [x9, #16]",
    "add sp, sp, #16",
    "ldp d14, d15, [sp], #16",
    "ldp d12, d13, [sp], #16",
    "ldp d10, d11, [sp], #16",
    "ldp d8, d9, [sp], #16",
    "ldp x27, x28, [sp], #16",
    "ldp x25, x26, [sp], #16",
    "ldp x23, x24, [sp], #16",
    "ldp x21, x22, [sp], #16",
    "ldp x19, x20, [sp], #16",
    "ldp x29, x30, [sp], #16",
    "ret",
    active_code_ix = const crate::arm::beam_asm::sched_ref(core::mem::offset_of!(SchedulerRegisters, active_code_ix)),
    op_call_nif = const arinsal_term::OP_CALL_NIF_WWW,
    entry_return = const crate::arm::beam_asm::sched_ref(core::mem::offset_of!(SchedulerRegisters, entry_return)),
    exit_fragment = const crate::arm::beam_asm::tmp_mem_ref(4),
    exit_marker = const crate::arm::beam_asm::tmp_mem_ref(3),
    x0 = const crate::arm::beam_asm::x_ref(0),
    x2 = const crate::arm::beam_asm::x_ref(2),
    x4 = const crate::arm::beam_asm::x_ref(4),
    f_page = const F_PAGE,
    f0 = const crate::arm::beam_asm::F_REG_ARRAY_REF - F_PAGE,
    f1 = const crate::arm::beam_asm::F_REG_ARRAY_REF - F_PAGE + 16,
    f2 = const crate::arm::beam_asm::F_REG_ARRAY_REF - F_PAGE + 32,
    f3 = const crate::arm::beam_asm::F_REG_ARRAY_REF - F_PAGE + 48,
);

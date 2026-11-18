//! The C ABI symbol of `erts_gc_after_bif_call_lhf`, which the BIF call fragments call by
//! name (`runtime_call<..., erts_gc_after_bif_call_lhf>`).
//!
//! Port of erts/emulator/beam/erl_gc.c (erts_gc_after_bif_call_lhf), OTP-29.1.1.

use arinsal_beamasm::ProcessHeader;

/// `Eterm erts_gc_after_bif_call_lhf(Process *p, ErlHeapFragment *live_hf_end, Eterm result,
/// Eterm *regs, Uint arity)`. `c_p` is the running process and `regs` its X register array
/// (`load_x_reg_array`), as every BIF call fragment passes them.
// Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf), OTP-29.1.1.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn erts_gc_after_bif_call_lhf(
    c_p: *mut ProcessHeader,
    live_hf_end: usize,
    result: u64,
    regs: *mut u64,
    arity: u64,
) -> u64 {
    let Some((p, registers)) = crate::native_hooks::enter_runtime_after_bif(c_p, regs) else {
        return result;
    };
    crate::erl_gc::erts_gc_after_bif_call_lhf(
        p,
        live_hf_end,
        result,
        &mut registers.x_reg_array,
        arity as usize,
    )
}

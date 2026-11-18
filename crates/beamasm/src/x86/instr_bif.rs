//! Port of erts/emulator/beam/jit/x86/instr_bif.cpp, OTP-29.1.1: light and regular BIF calls,
//! NIF calls, and their shared global fragments. The export trampoline from
//! `beam_asm_global.cpp` also lives here because it enters `call_bif_shared`.

use arinsal_x64::enc::{CondCode, Mem, byte_ptr, dword_ptr, qword_ptr};

use super::beam_asm::register::{
    ACTIVE_CODE_IX, ARG1, ARG1D, ARG2, ARG2D, ARG3, ARG4, ARG5, ARG5D, ARG6, C_P, E, FCALLS, HTOP,
    RET,
};
use super::beam_asm::{
    AsmError, ERTS_SAVE_CALLS_CODE_IX, Update, get_x_ref, process, process_ref, tmp_mem_q,
};
use super::beam_asm_global::{BEAM_ASM_FUNC_PROLOGUE_SIZE, BeamGlobalAssembler, GlobalLabels};
use super::beam_asm_module::{BeamModuleAssembler, ErtsCodeInfo, arg_word};
pub use super::rt::{
    beam_jit_call_bif, beam_jit_call_nif, erts_call_nif_early, erts_gc_after_bif_call_lhf,
    erts_printable_return_address,
};
use crate::common::args::ArgVal;

/// `offsetof(Export, is_bif_traced)`.
// Port of erts/emulator/beam/export.h:57-58 (Export.is_bif_traced), OTP-29.1.1.
const EXPORT_IS_BIF_TRACED: i32 =
    core::mem::offset_of!(arinsal_term::ExportEntry, is_bif_traced) as i32;
/// `offsetof(Export, info.mfa)`.
const EXPORT_MFA: i32 = arinsal_term::EXPORT_MFA_OFFSET as i32;
/// `offsetof(Export, info.mfa.arity)`.
const EXPORT_MFA_ARITY: i32 =
    EXPORT_MFA + core::mem::offset_of!(arinsal_term::ErtsCodeMfa, arity) as i32;
/// `offsetof(Export, trampoline.common.op)`.
const EXPORT_TRAMPOLINE_OP: i32 = arinsal_term::EXPORT_TRAMPOLINE_OP_OFFSET as i32;
/// `offsetof(Export, trampoline.bif.address)`.
const EXPORT_TRAMPOLINE_BIF_ADDRESS: i32 =
    (core::mem::offset_of!(arinsal_term::ExportEntry, trampoline)
        + core::mem::offset_of!(arinsal_term::ExportTrampoline, address)) as i32;

/// `BEAM_ASM_NFUNC_SIZE` for x86-64.
// Port of erts/emulator/beam/jit/beam_asm.h:132-136 (BEAM_ASM_NFUNC_SIZE), OTP-29.1.1.
const BEAM_ASM_NFUNC_SIZE: i32 = BEAM_ASM_FUNC_PROLOGUE_SIZE as i32 + 8;
/// `offsetof(ErtsNativeFunc, trampoline.info.mfa) - offsetof(...call_bif_nif)`.
const NATIVE_FUNC_MFA_FROM_CALL: i32 =
    core::mem::offset_of!(ErtsCodeInfo, mfa) as i32 - core::mem::size_of::<ErtsCodeInfo>() as i32;
/// `offsetof(ErtsNativeFunc, trampoline.dfunc) - offsetof(...call_bif_nif)`.
const NATIVE_FUNC_DFUNC_FROM_CALL: i32 = BEAM_ASM_NFUNC_SIZE;

/// `F_FORCE_GC | F_DISABLE_GC` of `c_p->flags`.
// Port of erts/emulator/beam/erl_process.h (F_FORCE_GC, F_DISABLE_GC), OTP-29.1.1.
const F_FORCE_OR_DISABLE_GC: i64 =
    (arinsal_term::pflags::F_FORCE_GC | arinsal_term::pflags::F_DISABLE_GC) as i64;

impl BeamGlobalAssembler {
    /// Calls a light BIF through its `(c_p, reg, I)` function: `ARG3` is the entry address
    /// of the call site, `ARG4` the `Export`, `RET` the BIF function. Traced BIFs and
    /// `save_calls` go through the export entry instead; a desired collection after the
    /// call runs `erts_gc_after_bif_call_lhf`.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:420-671 (emit_call_light_bif_shared),
    // OTP-29.1.1. Release build: no `debug_call_light_bif`, no `ERTS_CCONV_DEBUG`
    // trampoline, no `ERTS_MSACC_EXTENDED_STATES`.
    pub(crate) fn emit_call_light_bif_shared(&mut self) -> Result<(), AsmError> {
        let (entry_mem, export_mem, mbuf_mem) = (tmp_mem_q(0), tmp_mem_q(1), tmp_mem_q(2));
        let context_switch_simplified = self.label(GlobalLabels::ContextSwitchSimplified);
        let raise_exception_shared = self.label(GlobalLabels::RaiseExceptionShared);
        let a = &mut self.asm;
        let trace = a.new_label();
        let r#yield = a.new_label();

        a.emit_enter_frame()?;

        // Spill everything we may need on the error and GC paths.
        a.emit(|e| e.mov_rm(ARG1, process_ref(process::MBUF, 8)))?;
        a.emit(|e| e.mov_mr(entry_mem, ARG3))?;
        a.emit(|e| e.mov_mr(export_mem, ARG4))?;
        a.emit(|e| e.mov_mr(mbuf_mem, ARG1))?;

        // Check if we should trace this bif call or handle save_calls. Both variants dispatch
        // through the export entry.
        a.emit(|e| e.cmp_mi(dword_ptr(ARG4, EXPORT_IS_BIF_TRACED), 0))?;
        a.jcc(CondCode::NE, trace)?;
        a.emit(|e| e.cmp_ri(ACTIVE_CODE_IX, i64::from(ERTS_SAVE_CALLS_CODE_IX)))?;
        a.jcc(CondCode::E, trace)?;

        a.emit(|e| e.dec_r(FCALLS))?;
        a.jcc(CondCode::LE, r#yield)?;

        {
            let check_bif_return = a.new_label();
            let gc_after_bif_call = a.new_label();
            let spec = Update::REDUCTIONS.union(Update::STACK).union(Update::HEAP);

            a.emit_enter_runtime(spec)?;

            // Call the BIF proper. ARG3 and RET have been set earlier.
            a.emit(|e| e.mov_rr(ARG1, C_P))?;
            a.load_x_reg_array(ARG2)?;
            a.emit(|e| e.mov_rr(ARG4, RET))?;
            a.dynamic_runtime_call(ARG4)?;

            // The active code index is updated in case another process has loaded new code:
            // the result of this BIF may be observable on both ends.
            a.emit_leave_runtime(spec.union(Update::CODE_INDEX))?;

            // ERTS_IS_GC_DESIRED_INTERNAL
            {
                // Test whether GC is forced.
                a.emit(|e| e.test_mi(process_ref(process::FLAGS, 4), F_FORCE_OR_DISABLE_GC))?;
                a.jcc(CondCode::NE, gc_after_bif_call)?;

                // Test if binary heap size should trigger GC.
                a.emit(|e| e.mov_rm(ARG1, process_ref(process::BIN_VHEAP_SZ, 8)))?;
                a.emit(|e| e.cmp_mr(process_ref(process::OFF_HEAP_OVERHEAD, 8), ARG1))?;
                a.jcc(CondCode::A, gc_after_bif_call)?;

                // Test if heap fragment size is larger than remaining heap size. erts writes
                // `x86::qword_ptr(HTOP, ARG2, 0, 3)`: asmjit's operands are (base, index,
                // shift, offset), so this is shift 0 and displacement 3, as erts emits it.
                a.emit(|e| e.mov_rm(ARG2, process_ref(process::MBUF_SZ, 8)))?;
                a.emit(|e| e.lea(ARG1, Mem::base_index(HTOP, ARG2, 0, 3, 8)))?;
                a.emit(|e| e.cmp_rr(E, ARG1))?;
                a.jcc(CondCode::L, gc_after_bif_call)?;
            }

            // ! FALL THROUGH !
            a.bind(check_bif_return)?;
            {
                let trap = a.new_label();
                let error = a.new_label();

                a.emit_test_the_non_value(RET)?;
                a.short_jcc(CondCode::E, trap)?;

                a.emit(|e| e.mov_mr(get_x_ref(0, 8), RET))?;

                a.emit_leave_frame()?;
                a.emit(|e| e.ret())?;

                a.bind(trap)?;
                {
                    a.emit(|e| {
                        e.cmp_mi(
                            process_ref(process::FREASON, 8),
                            arinsal_term::exc::TRAP as i64,
                        )
                    })?;
                    a.short_jcc(CondCode::NE, error)?;

                    // Trap out, our return address is on the Erlang stack. The BIF_TRAP
                    // macros all set up c_p->arity and c_p->current, so we can use a
                    // simplified context switch.
                    a.emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
                    a.jmp(context_switch_simplified)?;
                }

                a.bind(error)?;
                {
                    a.emit(|e| e.mov_rm(ARG2, entry_mem))?;
                    a.emit(|e| e.mov_rm(ARG4, export_mem))?;
                    a.emit(|e| e.add_ri(ARG4, i64::from(EXPORT_MFA)))?;

                    // Overwrite the return address with the entry address to ensure that only
                    // the entry address ends up in the stack trace.
                    const {
                        assert!(matches!(
                            super::beam_asm::FRAME_LAYOUT,
                            super::beam_asm::FrameLayout::Ra
                        ))
                    };
                    a.emit(|e| e.mov_mr(qword_ptr(E, 0), ARG2))?;

                    a.jmp(raise_exception_shared)?;
                }
            }

            a.bind(gc_after_bif_call)?;
            {
                a.emit(|e| e.mov_rm(ARG2, mbuf_mem))?;
                a.emit(|e| e.mov_rm(ARG5, export_mem))?;
                a.emit(|e| e.movzx_rm(ARG5D, byte_ptr(ARG5, EXPORT_MFA_ARITY)))?;

                a.emit_enter_runtime(spec)?;

                a.emit(|e| e.mov_rr(ARG1, C_P))?;
                a.emit(|e| e.mov_rr(ARG3, RET))?;
                a.load_x_reg_array(ARG4)?;
                a.runtime_call(erts_gc_after_bif_call_lhf as *const () as usize)?;

                a.emit_leave_runtime(spec)?;

                a.jmp(check_bif_return)?;
            }
        }

        a.bind(trace)?;
        {
            // Tail call the export entry instead of the BIF. With the native stack as the
            // Erlang stack our return address is already on the Erlang stack.
            a.emit_leave_frame()?;
            let destination = a.emit_setup_dispatchable_call_active(ARG4)?;
            a.emit(|e| e.jmp_m(destination))?;
        }

        a.bind(r#yield)?;
        {
            a.emit(|e| e.movzx_rm(ARG2D, byte_ptr(ARG4, EXPORT_MFA_ARITY)))?;
            a.emit(|e| e.lea(ARG4, qword_ptr(ARG4, EXPORT_MFA)))?;
            a.emit(|e| e.mov_mr(process_ref(process::ARITY, 1), ARG2.r8()))?;
            a.emit(|e| e.mov_mr(process_ref(process::CURRENT, 8), ARG4))?;

            // We'll find our way back through ARG3 (entry address).
            a.emit_unwind_frame()?;

            a.jmp(context_switch_simplified)
        }
    }

    /// Completes a BIF or NIF call: dispatches a value, trap, hibernate, or exception result.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:711-817 (emit_bif_nif_epilogue),
    // OTP-29.1.1. Release build with `NATIVE_ERLANG_STACK`; no `ERTS_MSACC_EXTENDED_STATES`.
    pub(crate) fn emit_bif_nif_epilogue(&mut self) -> Result<(), AsmError> {
        let (check_trap, trap, error) = (
            self.asm.new_label(),
            self.asm.new_label(),
            self.asm.new_label(),
        );
        let do_schedule = self.label(GlobalLabels::DoSchedule);
        let context_switch = self.label(GlobalLabels::ContextSwitchSimplified);
        let raise_exception = self.label(GlobalLabels::RaiseExceptionShared);
        let a = &mut self.asm;

        a.emit_leave_runtime(
            Update::REDUCTIONS
                .union(Update::STACK)
                .union(Update::HEAP)
                .union(Update::CODE_INDEX),
        )?;
        a.emit_test_the_non_value(RET)?;
        a.short_jcc(CondCode::E, check_trap)?;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), RET))?;
        a.emit_leave_frame()?;
        a.emit(|e| e.ret())?;

        a.bind(check_trap)?;
        a.emit(|e| {
            e.cmp_mi(
                process_ref(process::FREASON, 8),
                arinsal_term::exc::TRAP as i64,
            )
        })?;
        a.jcc(CondCode::NE, error)?;
        a.emit(|e| e.mov_rm(ARG1D, process_ref(process::FLAGS, 4)))?;
        a.emit(|e| e.mov_rr(ARG2D, ARG1D))?;
        a.emit(|e| e.and_ri(ARG2D, arinsal_term::pflags::F_HIBERNATE_SCHED as i64))?;
        a.short_jcc(CondCode::E, trap)?;
        a.emit(|e| {
            e.and_ri(
                ARG1D,
                (!arinsal_term::pflags::F_HIBERNATE_SCHED) as i32 as i64,
            )
        })?;
        a.emit(|e| e.mov_mr(process_ref(process::FLAGS, 4), ARG1D))?;
        a.jmp(do_schedule)?;

        a.bind(trap)?;
        a.emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
        a.jmp(context_switch)?;

        a.bind(error)?;
        a.emit(|e| e.mov_rr(ARG2, E))?;
        a.emit_enter_runtime(Update::STACK)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.runtime_call(erts_printable_return_address as *const () as usize)?;
        a.emit_leave_runtime(Update::STACK)?;
        a.emit(|e| e.mov_rr(ARG2, RET))?;
        a.emit(|e| e.mov_rm(ARG4, process_ref(process::CURRENT, 8)))?;
        a.jmp(raise_exception)
    }

    /// Calls a BIF through `beam_jit_call_bif(c_p, reg, I, func, arity)`.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:819-870 (emit_call_bif_shared),
    // OTP-29.1.1. Release build without `ERTS_MSACC_EXTENDED_STATES`.
    pub(crate) fn emit_call_bif_shared(&mut self) -> Result<(), AsmError> {
        {
            let a = &mut self.asm;
            a.emit(|e| e.mov_mr(process_ref(process::CURRENT, 8), ARG2))?;
            a.emit(|e| {
                e.movzx_rm(
                    ARG5D,
                    byte_ptr(
                        ARG2,
                        core::mem::offset_of!(arinsal_term::ErtsCodeMfa, arity) as i32,
                    ),
                )
            })?;
            a.emit(|e| e.mov_mr(process_ref(process::ARITY, 1), ARG5.r8()))?;
            a.emit(|e| e.mov_mr(process_ref(process::I, 8), ARG3))?;

            let spec = Update::REDUCTIONS.union(Update::STACK).union(Update::HEAP);
            a.emit_enter_runtime(spec)?;
            a.emit(|e| e.mov_rr(ARG1, C_P))?;
            a.load_x_reg_array(ARG2)?;
            a.runtime_call(beam_jit_call_bif as *const () as usize)?;
        }
        self.emit_bif_nif_epilogue()
    }

    /// Unpacks an `ErtsNativeFunc` BIF trampoline and tail-calls `call_bif_shared`.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:872-889 (emit_dispatch_bif),
    // OTP-29.1.1.
    pub(crate) fn emit_dispatch_bif(&mut self) -> Result<(), AsmError> {
        let target = self.label(GlobalLabels::CallBifShared);
        let a = &mut self.asm;
        a.emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
        a.emit(|e| e.lea(ARG2, Mem::base_disp(ARG3, NATIVE_FUNC_MFA_FROM_CALL, 8)))?;
        a.emit(|e| e.mov_rm(ARG4, qword_ptr(ARG3, NATIVE_FUNC_DFUNC_FROM_CALL)))?;
        a.jmp(target)
    }

    /// Runs the early NIF loader on the function whose breakpoint trampoline called here.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:929-976 (emit_call_nif_early),
    // OTP-29.1.1. Release build; no `DEBUG` alignment trap.
    pub(crate) fn emit_call_nif_early(&mut self) -> Result<(), AsmError> {
        let call_nif_shared = self.label(GlobalLabels::CallNifShared);
        let a = &mut self.asm;
        a.emit(|e| e.mov_rm(ARG2, qword_ptr(arinsal_x64::enc::RSP, 0)))?;
        a.emit(|e| e.sub_ri(ARG2, (8 + core::mem::size_of::<ErtsCodeInfo>()) as i64))?;
        a.emit_enter_runtime(Update::NONE)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.runtime_call(erts_call_nif_early as *const () as usize)?;
        a.emit_leave_runtime(Update::NONE)?;
        a.emit(|e| e.add_ri(arinsal_x64::enc::RSP, 8))?;
        a.emit_enter_frame()?;
        a.emit(|e| e.mov_rr(ARG3, RET))?;
        a.jmp(call_nif_shared)
    }

    /// Calls the NIF function and passes its result through the common epilogue.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:978-1013 (emit_call_nif_shared),
    // OTP-29.1.1. Release build without `ERTS_MSACC_EXTENDED_STATES`.
    pub(crate) fn emit_call_nif_shared(&mut self) -> Result<(), AsmError> {
        {
            let a = &mut self.asm;
            let spec = Update::REDUCTIONS.union(Update::STACK).union(Update::HEAP);
            a.emit_enter_runtime(spec)?;
            a.emit(|e| e.mov_rr(ARG1, C_P))?;
            a.emit(|e| e.mov_rr(ARG2, ARG3))?;
            a.load_x_reg_array(ARG3)?;
            a.emit(|e| {
                e.mov_rm(
                    ARG4,
                    qword_ptr(ARG2, 8 + BEAM_ASM_FUNC_PROLOGUE_SIZE as i32),
                )
            })?;
            a.emit(|e| {
                e.mov_rm(
                    ARG5,
                    qword_ptr(ARG2, 16 + BEAM_ASM_FUNC_PROLOGUE_SIZE as i32),
                )
            })?;
            a.emit(|e| {
                e.mov_rm(
                    ARG6,
                    qword_ptr(ARG2, 24 + BEAM_ASM_FUNC_PROLOGUE_SIZE as i32),
                )
            })?;
            a.runtime_call(beam_jit_call_nif as *const () as usize)?;
        }
        self.emit_bif_nif_epilogue()
    }

    /// Dispatches an `ErtsNativeFunc` NIF trampoline through the shared NIF caller.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1015-1025 (emit_dispatch_nif),
    // OTP-29.1.1.
    pub(crate) fn emit_dispatch_nif(&mut self) -> Result<(), AsmError> {
        let target = self.label(GlobalLabels::CallNifShared);
        let a = &mut self.asm;
        a.emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
        a.jmp(target)
    }

    /// Checks reductions before entering a NIF and switches to the scheduler on exhaustion.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1027-1057
    // (emit_call_nif_yield_helper), OTP-29.1.1. Arinsal has no code-atag runtime option.
    pub(crate) fn emit_call_nif_yield_helper(&mut self) -> Result<(), AsmError> {
        let (yield_label, shared) = (
            self.asm.new_label(),
            self.label(GlobalLabels::CallNifShared),
        );
        let context_switch = self.label(GlobalLabels::ContextSwitchSimplified);
        let a = &mut self.asm;

        a.emit(|e| e.dec_r(FCALLS))?;
        a.short_jcc(CondCode::L, yield_label)?;
        a.jmp(shared)?;

        a.bind(yield_label)?;
        let arity_offset = NATIVE_FUNC_MFA_FROM_CALL
            + core::mem::offset_of!(arinsal_term::ErtsCodeMfa, arity) as i32;
        a.emit(|e| e.movzx_rm(ARG1D, byte_ptr(ARG3, arity_offset)))?;
        a.emit(|e| e.mov_mr(process_ref(process::ARITY, 1), ARG1.r8()))?;
        a.emit(|e| e.lea(ARG1, Mem::base_disp(ARG3, NATIVE_FUNC_MFA_FROM_CALL, 8)))?;
        a.emit(|e| e.mov_mr(process_ref(process::CURRENT, 8), ARG1))?;
        a.emit(|e| e.add_ri(ARG3, (BEAM_ASM_NFUNC_SIZE + 3 * 8) as i64))?;
        a.jmp(context_switch)
    }

    /// Routes export trampoline entries to generic breakpoints, BIFs, or the error handler.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:170-263
    // (emit_export_trampoline), OTP-29.1.1. Release build with `NATIVE_ERLANG_STACK`.
    pub(crate) fn emit_export_trampoline(&mut self) -> Result<(), AsmError> {
        let (call_bif, error_handler) = (self.asm.new_label(), self.asm.new_label());
        let generic_bp = self.label(GlobalLabels::GenericBpGlobal);
        let call_bif_shared = self.label(GlobalLabels::CallBifShared);
        let raise_exception = self.label(GlobalLabels::RaiseException);
        let a = &mut self.asm;

        a.emit(|e| e.mov_rm(ARG1, qword_ptr(RET, EXPORT_TRAMPOLINE_OP)))?;
        a.emit(|e| e.cmp_ri(ARG1, arinsal_term::OP_I_GENERIC_BREAKPOINT as i64))?;
        a.jcc(CondCode::E, generic_bp)?;
        a.emit(|e| e.cmp_ri(ARG1, arinsal_term::OP_CALL_BIF_W as i64))?;
        a.jcc(CondCode::E, call_bif)?;
        a.emit(|e| e.cmp_ri(ARG1, arinsal_term::OP_CALL_ERROR_HANDLER as i64))?;
        a.jcc(CondCode::E, error_handler)?;
        a.emit(|e| e.ud2())?;

        a.bind(call_bif)?;
        a.emit(|e| e.lea(ARG2, qword_ptr(RET, EXPORT_MFA)))?;
        a.emit(|e| e.mov_rm(ARG3, process_ref(process::I, 8)))?;
        a.emit(|e| e.mov_rm(ARG4, qword_ptr(RET, EXPORT_TRAMPOLINE_BIF_ADDRESS)))?;
        a.emit_enter_frame()?;
        a.jmp(call_bif_shared)?;

        a.bind(error_handler)?;
        a.emit(|e| e.lea(ARG2, qword_ptr(RET, EXPORT_MFA)))?;
        a.emit(|e| e.mov_mr(tmp_mem_q(0), ARG2))?;
        a.emit_enter_frame()?;
        a.emit_enter_runtime(Update::REDUCTIONS.union(Update::HEAP_ALLOC))?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.load_x_reg_array(ARG3)?;
        a.mov_imm(
            ARG4,
            arinsal_term::Term::atom(arinsal_term::atoms::UNDEFINED_FUNCTION).word(),
        )?;
        a.runtime_call(super::rt::call_error_handler as *const () as usize)?;
        a.emit_leave_runtime(Update::REDUCTIONS.union(Update::HEAP_ALLOC))?;
        a.emit_leave_frame()?;
        a.emit(|e| e.mov_rm(ARG4, tmp_mem_q(0)))?;
        a.emit(|e| e.test_rr(RET, RET))?;
        a.jcc(CondCode::E, raise_exception)?;
        let destination = a.emit_setup_dispatchable_call_active(RET)?;
        a.emit(|e| e.jmp_m(destination))
    }
}

impl BeamModuleAssembler {
    /// Emits the heavy-BIF entry and its module-local dispatch thunk.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:891-910 (emit_call_bif), OTP-29.1.1.
    pub fn emit_call_bif(&mut self, function: ArgVal) -> Result<(), AsmError> {
        let function = arg_word(function)?;
        let current = self
            .current_label()
            .ok_or(AsmError::Operand("call_bif without function label"))?;
        let entry = self.asm.new_label();
        let mfa_offset = -(core::mem::size_of::<arinsal_term::ErtsCodeMfa>() as i32);

        self.asm.emit_enter_frame()?;
        self.asm.bind(entry)?;
        self.asm
            .a
            .emit_rip_label(current, |e| e.lea(ARG2, Mem::rip(mfa_offset, 8)))?;
        self.asm
            .a
            .emit_rip_label(entry, |e| e.lea(ARG3, Mem::rip(0, 8)))?;
        self.asm.mov_imm(ARG4, function)?;
        let fragment = self.ga_get(GlobalLabels::CallBifShared)?;
        let target = self.resolve_fragment(fragment);
        self.asm.jmp(target)
    }

    /// Emits the position-independent `call_nif` stub with its three native-function words.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1059-1093 (emit_call_nif), OTP-29.1.1.
    pub fn emit_call_nif(
        &mut self,
        function: ArgVal,
        nif_module: ArgVal,
        dirty_function: ArgVal,
    ) -> Result<(), AsmError> {
        let (function, nif_module, dirty_function) = (
            arg_word(function)?,
            arg_word(nif_module)?,
            arg_word(dirty_function)?,
        );
        let current = self
            .current_label()
            .ok_or(AsmError::Operand("call_nif without function label"))?;
        let current_offset = self
            .current_label_offset()
            .ok_or(AsmError::Operand("call_nif without function label"))?;
        let entry = self.asm.new_label();
        let dispatch = self.asm.new_label();

        self.asm.bind(entry)?;
        self.asm.emit_enter_frame()?;
        self.asm.short_jmp(dispatch)?;
        self.asm.align_code(8)?;
        self.asm.a.embed_u64(function)?;
        self.asm.a.embed_u64(nif_module)?;
        self.asm.a.embed_u64(dirty_function)?;
        debug_assert_eq!(
            self.asm.a.offset() - current_offset,
            (BEAM_ASM_NFUNC_SIZE + 3 * 8) as usize
        );

        self.asm.bind(dispatch)?;
        self.asm
            .a
            .emit_rip_label(current, |e| e.lea(ARG3, Mem::rip(0, 8)))?;
        self.asm
            .pic_jmp(self.ga_get(GlobalLabels::CallNifYieldHelper)?)
    }

    /// `call_light_bif(Bif, Exp)`: `Bif` is the address of the BIF's `(c_p, reg, I)` function,
    /// `Exp` its import.
    // Port of erts/emulator/beam/jit/x86/instr_bif.cpp:673-689 (emit_call_light_bif),
    // OTP-29.1.1.
    pub fn emit_call_light_bif(&mut self, bif: ArgVal, exp: ArgVal) -> Result<(), AsmError> {
        let ArgVal::Word(bif) = bif else {
            return Err(AsmError::Operand("call_light_bif: Bif must be a word"));
        };
        if !matches!(exp, ArgVal::Export(_)) {
            return Err(AsmError::Operand("call_light_bif: Exp must be an export"));
        }
        let entry = self.asm.new_label();

        self.asm.align_erlang_cp()?;
        self.asm.bind(entry)?;

        self.mov_arg_to_reg(ARG4, exp)?;
        self.asm.emit(|e| e.mov_ri(RET, bif as i64))?;
        self.asm
            .a
            .emit_rip_label(entry, |e| e.lea(ARG3, Mem::rip(0, 8)))?;

        let fragment = self.ga_get(GlobalLabels::CallLightBifShared)?;
        let target = self.resolve_fragment(fragment);
        self.asm.fragment_call(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86::beam_asm_global::GLOBAL_LABELS;
    use crate::x86::jdump::{erts_dump, gnu_as};
    use arinsal_x64::buf::Section;
    use similar_asserts::assert_eq;

    /// The lines of each `call_light_bif_be` block from the entry label to its thunk call.
    fn blocks(dump: &str, fill: u8) -> Vec<(u64, Vec<String>)> {
        const NOPS: [&str; 3] = ["0x90", "0x66, 0x90", "0x0f, 0x1f, 0x00"];
        let is_call_alignment_nop = |line: &str| {
            matches!(
                line.to_ascii_lowercase().replace(' ', "").as_str(),
                ".byte0x90" | ".byte0x66,0x90" | ".byte0x0f,0x1f,0x00"
            )
        };
        let lines: Vec<&str> = dump.lines().map(str::trim).collect();
        let mut out = Vec::new();
        for (i, _) in lines
            .iter()
            .enumerate()
            .filter(|(_, l)| **l == "# call_light_bif_be")
        {
            let entry = lines[i + 2].trim_end_matches(':');
            let mut text = vec!["Lentry:".to_string()];
            let mut bif = None;
            for line in &lines[i + 3..] {
                if line.starts_with('#') || line.ends_with(':') {
                    continue;
                }
                if let Some(target) = line.strip_prefix("call ") {
                    assert!(target.parse::<u64>().is_ok(), "{line}");
                    // +JDdump prints the fragment target address. Reconstruct the five-byte
                    // module thunk call and its CP padding, as BeamModuleAssembler does.
                    while text.last().is_some_and(|line| is_call_alignment_nop(line)) {
                        text.pop();
                    }
                    let prefix_len = gnu_as(&text).expect("GNU as for call prefix").len();
                    let padding = (4 - (prefix_len + 5) % 4) % 4;
                    if padding > 0 {
                        text.push(format!(".byte {}", NOPS[padding - 1]));
                    }
                    text.push(format!(".byte 0xe8, {fill}, {fill}, {fill}, {fill}"));
                    break;
                }
                if let Some(value) = line.strip_prefix("mov rax, ") {
                    bif = value.parse::<u64>().ok();
                }
                text.push(if *line == format!("lea rdx, qword ptr [{entry}]") {
                    "lea rdx, [rip+Lentry]".to_string()
                } else {
                    crate::x86::jdump::erts_to_arinsal(line)
                });
            }
            out.push((bif.expect("BIF address"), text));
        }
        out
    }

    fn op_body(dump: &str, op: &str) -> Option<Vec<String>> {
        let target = format!("# {op}");
        let mut active = false;
        let mut body = Vec::new();
        for line in dump.lines().map(str::trim) {
            if active && let Some(header) = line.strip_prefix("# ") {
                let token = header.split_whitespace().next().unwrap_or_default();
                if !token.is_empty()
                    && token
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                {
                    break;
                }
            }
            if line == target {
                active = true;
            } else if active && !line.is_empty() && !line.starts_with('#') {
                body.push(line.to_owned());
            }
        }
        active.then_some(body)
    }

    fn module_with_function(call_nif_helper: Option<usize>) -> BeamModuleAssembler {
        let mut addresses: Vec<_> = GLOBAL_LABELS
            .iter()
            .enumerate()
            .map(|(index, _)| Some(0x7000_0000 + 64 * index))
            .collect();
        if let Some(helper) = call_nif_helper {
            addresses[GlobalLabels::CallNifYieldHelper as usize] = Some(helper);
        }
        let mut module = BeamModuleAssembler::with_fragment_addresses(16, addresses);
        module
            .emit_i_func_info(
                ArgVal::Word(1),
                ArgVal::Immediate(0),
                ArgVal::Immediate(0),
                ArgVal::Word(0),
            )
            .unwrap();
        module.emit_i_func_label(ArgVal::Label(1)).unwrap();
        module.emit_i_breakpoint_trampoline().unwrap();
        module
    }

    #[test]
    fn call_bif_matches_erts_dump() {
        let Some(dump) = erts_dump("code") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let body = op_body(&dump, "call_bif_mfa_aaI").expect("code module has a call_bif");
        let function = body
            .iter()
            .find_map(|line| {
                line.strip_prefix("mov rcx, ")
                    .and_then(|value| value.parse::<u64>().ok())
            })
            .expect("call_bif dump has the BIF function address");
        let entry = body
            .first()
            .and_then(|line| line.strip_suffix(':'))
            .expect("call_bif starts with its entry label");
        let expected = vec![
            "mfa:".to_owned(),
            ".zero 32".to_owned(),
            format!("{entry}:"),
            "lea rsi, [rip+mfa]".to_owned(),
            format!("lea rdx, [rip+{entry}]"),
            format!("movabs rcx, {function}"),
            "{disp32} jmp thunk".to_owned(),
            "thunk:".to_owned(),
        ];
        if crate::x86::jdump::gnu_as(&[]).is_none() {
            eprintln!("skipping byte comparison: GNU binutils unavailable");
            return;
        }
        let mut expected = crate::x86::jdump::gnu_as(&expected).unwrap();
        expected.drain(..32);
        let expected_len = expected.len();
        expected[expected_len - 4..].fill(0);

        let mut module = module_with_function(None);
        let start = module.asm.a.offset();
        module.emit_call_bif(ArgVal::Word(function)).unwrap();
        let end = module.asm.a.offset();
        module.emit_dispatch_table().unwrap();
        let mut actual = module.asm.a.bytes(Section::Code)[start..end].to_vec();
        let actual_len = actual.len();
        actual[actual_len - 4..].fill(0);
        assert_eq!(actual, expected, "{body:?}");
    }

    #[test]
    fn call_nif_matches_erts_dump() {
        let Some(dump) = erts_dump("erl_tracer") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let body = op_body(&dump, "call_nif_WWW").expect("erl_tracer has a call_nif");
        let words: Vec<u64> = body
            .iter()
            .filter_map(|line| line.strip_prefix(".dq "))
            .map(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).unwrap())
            .collect();
        assert_eq!(words.len(), 3, "{body:?}");
        let helper = body
            .iter()
            .find_map(|line| {
                line.strip_prefix("mov r9, ")
                    .and_then(|value| value.parse::<u64>().ok())
            })
            .expect("call_nif dump has its helper address");
        let expected: Vec<String> = vec![
            "function:".to_owned(),
            ".zero 8".to_owned(),
            "entry:".to_owned(),
            "short jmp dispatch".to_owned(),
            "align 8".to_owned(),
            format!(".quad {:#x}", words[0]),
            format!(".quad {:#x}", words[1]),
            format!(".quad {:#x}", words[2]),
            "dispatch:".to_owned(),
            "lea rdx, [rip+function]".to_owned(),
            format!("movabs r9, {helper}"),
            "jmp r9".to_owned(),
        ]
        .into_iter()
        .map(|line| match line.as_str() {
            "align 8" => ".balign 8".to_owned(),
            _ if line.starts_with(".quad ") => line,
            _ if line.starts_with(".dq ") => line.replacen(".dq ", ".quad ", 1),
            _ => crate::x86::jdump::erts_to_arinsal(&line),
        })
        .collect();
        if crate::x86::jdump::gnu_as(&[]).is_none() {
            eprintln!("skipping byte comparison: GNU binutils unavailable");
            return;
        }
        let mut expected = crate::x86::jdump::gnu_as(&expected).unwrap();
        expected.drain(..8);

        let mut module = module_with_function(Some(helper as usize));
        let start = module.asm.a.offset();
        module
            .emit_call_nif(
                ArgVal::Word(words[0]),
                ArgVal::Word(words[1]),
                ArgVal::Word(words[2]),
            )
            .unwrap();
        let end = module.asm.a.offset();
        let actual = module.asm.a.bytes(Section::Code)[start..end].to_vec();
        assert_eq!(actual, expected, "{body:?}");
    }

    // Differential check against erts: every `call_light_bif` site of a few boot modules
    // encodes the same instructions (the import patch, the BIF address, the entry address, the
    // padding that makes the return address a CP and the fragment call).
    #[test]
    fn call_light_bif_matches_erts_dump() {
        let dumps: Vec<String> = ["lists", "erlang", "gen_server", "code_server"]
            .iter()
            .filter_map(|m| erts_dump(m))
            .collect();
        if dumps.is_empty() || gnu_as(&[]).is_none() {
            eprintln!("skipping: `erl +JDdump true` or GNU binutils unavailable");
            return;
        }
        let mut compared = 0;
        for dump in &dumps {
            for ((bif, zeros), (_, ones)) in blocks(dump, 0).into_iter().zip(blocks(dump, 255)) {
                let (zeros, ones) = (gnu_as(&zeros).unwrap(), gnu_as(&ones).unwrap());
                let addresses = (0..GLOBAL_LABELS.len())
                    .map(|i| Some(0x7000_0000 + 64 * i))
                    .collect();
                let mut m = BeamModuleAssembler::with_fragment_addresses(16, addresses);
                m.emit_call_light_bif(ArgVal::Word(bif), ArgVal::Export(0))
                    .unwrap();
                let ours = m.asm.a.bytes(Section::Code);
                assert_eq!(ours.len(), zeros.len(), "{bif:#x}");
                assert!(
                    ours.iter()
                        .zip(zeros.iter().zip(&ones))
                        .all(|(o, (z, f))| z != f || o == z),
                    "{bif:#x}: {ours:02x?} vs {zeros:02x?}"
                );
                compared += 1;
            }
        }
        eprintln!("compared {compared} call_light_bif blocks");
        assert!(compared >= 100, "compared {compared}");
    }
}

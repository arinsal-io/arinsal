//! Port of erts/emulator/beam/jit/x86/beam_asm_global.hpp.pl (`class BeamGlobalAssembler`,
//! its label table and emitter table) and erts/emulator/beam/jit/x86/beam_asm_global.cpp
//! (the constructor's label predeclaration), plus the global fragments whose whole body is
//! portable with the encoder forms available today, OTP-29.1.1:
//! jit/x86/instr_common.cpp (emit_i_test_yield_shared) and jit/x86/instr_guard_bifs.cpp
//! (emit_handle_element_error, emit_handle_hd_error, emit_handle_map_get_badkey,
//! emit_handle_map_get_badmap, emit_handle_map_size_error, emit_handle_node_error).
//!
//! erts emits every fragment of `emitPtrs` in enum order, each aligned to 8 bytes and bound
//! to its predeclared label, so fragments jump to each other freely. A fragment is listed in
//! [`BeamGlobalAssembler::emit_ptr`] only once its whole erts body is ported.

use arinsal_term::{ErtsCodeMfa, Term, atoms};
use arinsal_x64::buf::Label;
use arinsal_x64::enc::qword_ptr;

use arinsal_x64::enc::CondCode;

use super::beam_asm::register::{ARG1, ARG2, ARG2D, ARG3, ARG4, C_P, RET};
use super::beam_asm::{AsmError, BeamAssembler, Update, get_x_ref, process, process_ref};
pub use super::rt::{call_error_handler, erts_garbage_collect_nobump, handle_error};
use crate::exc::{EXC_BADARG, EXC_BADKEY, EXC_BADMAP};

/// erts `BeamGlobalAssembler::GlobalLabels`: one label per global fragment, in the order of
/// `beam_global_funcs` (the order the fragments are emitted in), then the labels bound inside
/// `process_main` and `i_line_breakpoint_trampoline_shared`.
// Port of erts/emulator/beam/jit/x86/beam_asm_global.hpp.pl (beam_global_funcs,
// internal_labels, decl_enums), OTP-29.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u32)]
pub enum GlobalLabels {
    /// `apply_fun_shared`.
    ApplyFunShared,
    /// `arith_compare_shared`.
    ArithCompareShared,
    /// `arith_eq_shared`.
    ArithEqShared,
    /// `bif_nif_epilogue`.
    BifNifEpilogue,
    /// `bif_element_shared`.
    BifElementShared,
    /// `bif_export_trap`.
    BifExportTrap,
    /// `bs_create_bin_error_shared`.
    BsCreateBinErrorShared,
    /// `bs_size_check_shared`.
    BsSizeCheckShared,
    /// `bs_get_tail_shared`.
    BsGetTailShared,
    /// `bs_get_utf8_shared`.
    BsGetUtf8Shared,
    /// `bs_get_utf8_short_shared`.
    BsGetUtf8ShortShared,
    /// `bs_init_bits_shared`.
    BsInitBitsShared,
    /// `call_bif_shared`.
    CallBifShared,
    /// `call_light_bif_shared`.
    CallLightBifShared,
    /// `call_nif_early`.
    CallNifEarly,
    /// `call_nif_shared`.
    CallNifShared,
    /// `call_nif_yield_helper`.
    CallNifYieldHelper,
    /// `catch_end_shared`.
    CatchEndShared,
    /// `check_float_error`.
    CheckFloatError,
    /// `construct_utf8_shared`.
    ConstructUtf8Shared,
    /// `dispatch_bif`.
    DispatchBif,
    /// `dispatch_nif`.
    DispatchNif,
    /// `dispatch_return`.
    DispatchReturn,
    /// `dispatch_save_calls_export`.
    DispatchSaveCallsExport,
    /// `dispatch_save_calls_fun`.
    DispatchSaveCallsFun,
    /// `export_trampoline`.
    ExportTrampoline,
    /// `garbage_collect`.
    GarbageCollect,
    /// `generic_bp_global`.
    GenericBpGlobal,
    /// `generic_bp_local`.
    GenericBpLocal,
    /// `get_sint64_shared`.
    GetSint64Shared,
    /// `debug_bp`.
    DebugBp,
    /// `fconv_shared`.
    FconvShared,
    /// `handle_call_fun_error`.
    HandleCallFunError,
    /// `handle_element_error`.
    HandleElementError,
    /// `handle_hd_error`.
    HandleHdError,
    /// `handle_map_get_badkey`.
    HandleMapGetBadkey,
    /// `handle_map_get_badmap`.
    HandleMapGetBadmap,
    /// `handle_map_size_error`.
    HandleMapSizeError,
    /// `handle_node_error`.
    HandleNodeError,
    /// `i_band_body_shared`.
    IBandBodyShared,
    /// `i_band_guard_shared`.
    IBandGuardShared,
    /// `i_bif_body_shared`.
    IBifBodyShared,
    /// `i_bif_guard_shared`.
    IBifGuardShared,
    /// `i_bor_body_shared`.
    IBorBodyShared,
    /// `i_bor_guard_shared`.
    IBorGuardShared,
    /// `i_bnot_body_shared`.
    IBnotBodyShared,
    /// `i_bnot_guard_shared`.
    IBnotGuardShared,
    /// `i_breakpoint_trampoline_shared`.
    IBreakpointTrampolineShared,
    /// `i_bsl_guard_shared`.
    IBslGuardShared,
    /// `i_bsl_body_shared`.
    IBslBodyShared,
    /// `i_bsr_guard_shared`.
    IBsrGuardShared,
    /// `i_bsr_body_shared`.
    IBsrBodyShared,
    /// `i_bxor_body_shared`.
    IBxorBodyShared,
    /// `i_bxor_guard_shared`.
    IBxorGuardShared,
    /// `i_func_info_shared`.
    IFuncInfoShared,
    /// `i_get_map_element_shared`.
    IGetMapElementShared,
    /// `i_get_map_element_hash_shared`.
    IGetMapElementHashShared,
    /// `i_load_nif_shared`.
    ILoadNifShared,
    /// `i_length_guard_shared`.
    ILengthGuardShared,
    /// `i_length_body_shared`.
    ILengthBodyShared,
    /// `i_line_breakpoint_trampoline_shared`.
    ILineBreakpointTrampolineShared,
    /// `i_loop_rec_shared`.
    ILoopRecShared,
    /// `i_test_yield_shared`.
    ITestYieldShared,
    /// `int_div_rem_body_shared`.
    IntDivRemBodyShared,
    /// `int_div_rem_guard_shared`.
    IntDivRemGuardShared,
    /// `is_eq_exact_list_shared`.
    IsEqExactListShared,
    /// `is_eq_exact_shallow_boxed_shared`.
    IsEqExactShallowBoxedShared,
    /// `is_in_range_shared`.
    IsInRangeShared,
    /// `is_ge_lt_shared`.
    IsGeLtShared,
    /// `minus_body_shared`.
    MinusBodyShared,
    /// `minus_guard_shared`.
    MinusGuardShared,
    /// `mul_add_body_shared`.
    MulAddBodyShared,
    /// `mul_add_guard_shared`.
    MulAddGuardShared,
    /// `mul_body_shared`.
    MulBodyShared,
    /// `mul_guard_shared`.
    MulGuardShared,
    /// `new_map_shared`.
    NewMapShared,
    /// `plus_body_shared`.
    PlusBodyShared,
    /// `plus_guard_shared`.
    PlusGuardShared,
    /// `process_exit`.
    ProcessExit,
    /// `process_main`.
    ProcessMain,
    /// `raise_exception`.
    RaiseException,
    /// `raise_exception_null_exp`.
    RaiseExceptionNullExp,
    /// `raise_exception_shared`.
    RaiseExceptionShared,
    /// `raise_shared`.
    RaiseShared,
    /// `store_unaligned`.
    StoreUnaligned,
    /// `unary_minus_body_shared`.
    UnaryMinusBodyShared,
    /// `unary_minus_guard_shared`.
    UnaryMinusGuardShared,
    /// `unloaded_fun`.
    UnloadedFun,
    /// `update_map_assoc_shared`.
    UpdateMapAssocShared,
    /// `update_map_exact_guard_shared`.
    UpdateMapExactGuardShared,
    /// `update_map_exact_body_shared`.
    UpdateMapExactBodyShared,
    /// `update_map_single_assoc_shared`.
    UpdateMapSingleAssocShared,
    /// `update_map_single_exact_body_shared`.
    UpdateMapSingleExactBodyShared,
    /// `context_switch`.
    ContextSwitch,
    /// `context_switch_simplified`.
    ContextSwitchSimplified,
    /// `do_schedule`.
    DoSchedule,
    /// `i_line_breakpoint_cleanup`.
    ILineBreakpointCleanup,
}

/// Number of global fragments (`emitPtrs.size()`).
pub const GLOBAL_FRAGMENT_COUNT: usize = 93;

/// Every label, in enum order.
pub const GLOBAL_LABELS: [GlobalLabels; 97] = [
    GlobalLabels::ApplyFunShared,
    GlobalLabels::ArithCompareShared,
    GlobalLabels::ArithEqShared,
    GlobalLabels::BifNifEpilogue,
    GlobalLabels::BifElementShared,
    GlobalLabels::BifExportTrap,
    GlobalLabels::BsCreateBinErrorShared,
    GlobalLabels::BsSizeCheckShared,
    GlobalLabels::BsGetTailShared,
    GlobalLabels::BsGetUtf8Shared,
    GlobalLabels::BsGetUtf8ShortShared,
    GlobalLabels::BsInitBitsShared,
    GlobalLabels::CallBifShared,
    GlobalLabels::CallLightBifShared,
    GlobalLabels::CallNifEarly,
    GlobalLabels::CallNifShared,
    GlobalLabels::CallNifYieldHelper,
    GlobalLabels::CatchEndShared,
    GlobalLabels::CheckFloatError,
    GlobalLabels::ConstructUtf8Shared,
    GlobalLabels::DispatchBif,
    GlobalLabels::DispatchNif,
    GlobalLabels::DispatchReturn,
    GlobalLabels::DispatchSaveCallsExport,
    GlobalLabels::DispatchSaveCallsFun,
    GlobalLabels::ExportTrampoline,
    GlobalLabels::GarbageCollect,
    GlobalLabels::GenericBpGlobal,
    GlobalLabels::GenericBpLocal,
    GlobalLabels::GetSint64Shared,
    GlobalLabels::DebugBp,
    GlobalLabels::FconvShared,
    GlobalLabels::HandleCallFunError,
    GlobalLabels::HandleElementError,
    GlobalLabels::HandleHdError,
    GlobalLabels::HandleMapGetBadkey,
    GlobalLabels::HandleMapGetBadmap,
    GlobalLabels::HandleMapSizeError,
    GlobalLabels::HandleNodeError,
    GlobalLabels::IBandBodyShared,
    GlobalLabels::IBandGuardShared,
    GlobalLabels::IBifBodyShared,
    GlobalLabels::IBifGuardShared,
    GlobalLabels::IBorBodyShared,
    GlobalLabels::IBorGuardShared,
    GlobalLabels::IBnotBodyShared,
    GlobalLabels::IBnotGuardShared,
    GlobalLabels::IBreakpointTrampolineShared,
    GlobalLabels::IBslGuardShared,
    GlobalLabels::IBslBodyShared,
    GlobalLabels::IBsrGuardShared,
    GlobalLabels::IBsrBodyShared,
    GlobalLabels::IBxorBodyShared,
    GlobalLabels::IBxorGuardShared,
    GlobalLabels::IFuncInfoShared,
    GlobalLabels::IGetMapElementShared,
    GlobalLabels::IGetMapElementHashShared,
    GlobalLabels::ILoadNifShared,
    GlobalLabels::ILengthGuardShared,
    GlobalLabels::ILengthBodyShared,
    GlobalLabels::ILineBreakpointTrampolineShared,
    GlobalLabels::ILoopRecShared,
    GlobalLabels::ITestYieldShared,
    GlobalLabels::IntDivRemBodyShared,
    GlobalLabels::IntDivRemGuardShared,
    GlobalLabels::IsEqExactListShared,
    GlobalLabels::IsEqExactShallowBoxedShared,
    GlobalLabels::IsInRangeShared,
    GlobalLabels::IsGeLtShared,
    GlobalLabels::MinusBodyShared,
    GlobalLabels::MinusGuardShared,
    GlobalLabels::MulAddBodyShared,
    GlobalLabels::MulAddGuardShared,
    GlobalLabels::MulBodyShared,
    GlobalLabels::MulGuardShared,
    GlobalLabels::NewMapShared,
    GlobalLabels::PlusBodyShared,
    GlobalLabels::PlusGuardShared,
    GlobalLabels::ProcessExit,
    GlobalLabels::ProcessMain,
    GlobalLabels::RaiseException,
    GlobalLabels::RaiseExceptionNullExp,
    GlobalLabels::RaiseExceptionShared,
    GlobalLabels::RaiseShared,
    GlobalLabels::StoreUnaligned,
    GlobalLabels::UnaryMinusBodyShared,
    GlobalLabels::UnaryMinusGuardShared,
    GlobalLabels::UnloadedFun,
    GlobalLabels::UpdateMapAssocShared,
    GlobalLabels::UpdateMapExactGuardShared,
    GlobalLabels::UpdateMapExactBodyShared,
    GlobalLabels::UpdateMapSingleAssocShared,
    GlobalLabels::UpdateMapSingleExactBodyShared,
    GlobalLabels::ContextSwitch,
    GlobalLabels::ContextSwitchSimplified,
    GlobalLabels::DoSchedule,
    GlobalLabels::ILineBreakpointCleanup,
];

/// erts `BeamGlobalAssembler::labelNames`, indexed by [`GlobalLabels`].
// Port of erts/emulator/beam/jit/x86/beam_asm_global.hpp.pl (decl_label_names), OTP-29.1.1.
pub const LABEL_NAMES: [&str; 97] = [
    "apply_fun_shared",
    "arith_compare_shared",
    "arith_eq_shared",
    "bif_nif_epilogue",
    "bif_element_shared",
    "bif_export_trap",
    "bs_create_bin_error_shared",
    "bs_size_check_shared",
    "bs_get_tail_shared",
    "bs_get_utf8_shared",
    "bs_get_utf8_short_shared",
    "bs_init_bits_shared",
    "call_bif_shared",
    "call_light_bif_shared",
    "call_nif_early",
    "call_nif_shared",
    "call_nif_yield_helper",
    "catch_end_shared",
    "check_float_error",
    "construct_utf8_shared",
    "dispatch_bif",
    "dispatch_nif",
    "dispatch_return",
    "dispatch_save_calls_export",
    "dispatch_save_calls_fun",
    "export_trampoline",
    "garbage_collect",
    "generic_bp_global",
    "generic_bp_local",
    "get_sint64_shared",
    "debug_bp",
    "fconv_shared",
    "handle_call_fun_error",
    "handle_element_error",
    "handle_hd_error",
    "handle_map_get_badkey",
    "handle_map_get_badmap",
    "handle_map_size_error",
    "handle_node_error",
    "i_band_body_shared",
    "i_band_guard_shared",
    "i_bif_body_shared",
    "i_bif_guard_shared",
    "i_bor_body_shared",
    "i_bor_guard_shared",
    "i_bnot_body_shared",
    "i_bnot_guard_shared",
    "i_breakpoint_trampoline_shared",
    "i_bsl_guard_shared",
    "i_bsl_body_shared",
    "i_bsr_guard_shared",
    "i_bsr_body_shared",
    "i_bxor_body_shared",
    "i_bxor_guard_shared",
    "i_func_info_shared",
    "i_get_map_element_shared",
    "i_get_map_element_hash_shared",
    "i_load_nif_shared",
    "i_length_guard_shared",
    "i_length_body_shared",
    "i_line_breakpoint_trampoline_shared",
    "i_loop_rec_shared",
    "i_test_yield_shared",
    "int_div_rem_body_shared",
    "int_div_rem_guard_shared",
    "is_eq_exact_list_shared",
    "is_eq_exact_shallow_boxed_shared",
    "is_in_range_shared",
    "is_ge_lt_shared",
    "minus_body_shared",
    "minus_guard_shared",
    "mul_add_body_shared",
    "mul_add_guard_shared",
    "mul_body_shared",
    "mul_guard_shared",
    "new_map_shared",
    "plus_body_shared",
    "plus_guard_shared",
    "process_exit",
    "process_main",
    "raise_exception",
    "raise_exception_null_exp",
    "raise_exception_shared",
    "raise_shared",
    "store_unaligned",
    "unary_minus_body_shared",
    "unary_minus_guard_shared",
    "unloaded_fun",
    "update_map_assoc_shared",
    "update_map_exact_guard_shared",
    "update_map_exact_body_shared",
    "update_map_single_assoc_shared",
    "update_map_single_exact_body_shared",
    "context_switch",
    "context_switch_simplified",
    "do_schedule",
    "i_line_breakpoint_cleanup",
];

impl GlobalLabels {
    /// The label's name, `labelNames[label]`.
    pub const fn name(self) -> &'static str {
        LABEL_NAMES[self as usize]
    }
}

/// An emitter of `emitPtrs`.
pub type EmitFn = fn(&mut BeamGlobalAssembler) -> Result<(), AsmError>;

/// erts `class BeamGlobalAssembler : public BeamAssembler`.
// Port of erts/emulator/beam/jit/x86/beam_asm_global.hpp.pl (class BeamGlobalAssembler),
// OTP-29.1.1.
#[derive(Debug)]
pub struct BeamGlobalAssembler {
    /// The `BeamAssembler` base.
    pub asm: BeamAssembler,
    /// `labels`: one predeclared label per [`GlobalLabels`].
    labels: Vec<Label>,
}

/// `ErtsCodeMFA` a global fragment raises with (`static ErtsCodeMFA mfa` in its emitter).
const fn bif_mfa(function: arinsal_term::Atom, arity: u64) -> ErtsCodeMfa {
    ErtsCodeMfa {
        module: Term::atom(atoms::ERLANG).word(),
        function: Term::atom(function).word(),
        arity,
    }
}

// Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp (the `static ErtsCodeMFA mfa` of
// emit_handle_element_error, emit_handle_hd_error, emit_handle_map_get_badkey/badmap,
// emit_handle_map_size_error, emit_handle_node_error), OTP-29.1.1.
static ELEMENT_MFA: ErtsCodeMfa = bif_mfa(atoms::ELEMENT, 2);
static HD_MFA: ErtsCodeMfa = bif_mfa(atoms::HD, 1);
static MAP_GET_BADKEY_MFA: ErtsCodeMfa = bif_mfa(atoms::MAP_GET, 2);
static MAP_GET_BADMAP_MFA: ErtsCodeMfa = bif_mfa(atoms::MAP_GET, 2);
static MAP_SIZE_MFA: ErtsCodeMfa = bif_mfa(atoms::MAP_SIZE, 1);
static NODE_MFA: ErtsCodeMfa = bif_mfa(atoms::NODE, 1);

fn mfa_address(mfa: &'static ErtsCodeMfa) -> u64 {
    std::ptr::from_ref(mfa) as u64
}

/// `BEAM_ASM_FUNC_PROLOGUE_SIZE` on x86-64.
// Port of erts/emulator/beam/jit/beam_asm.h:126-130, OTP-29.1.1.
pub const BEAM_ASM_FUNC_PROLOGUE_SIZE: u32 = 8;

/// `TEST_YIELD_RETURN_OFFSET` for the `RA` frame layout without code allocation tags
/// (`erts_alcu_enable_code_atags` is an undocumented `+M` option Arinsal does not have).
// Port of erts/emulator/beam/jit/x86/instr_common.cpp:3199-3202, OTP-29.1.1.
pub const TEST_YIELD_RETURN_OFFSET: u32 = BEAM_ASM_FUNC_PROLOGUE_SIZE + 16;

impl BeamGlobalAssembler {
    /// The labels of every fragment declared up front, so global functions can refer to each
    /// other freely without any order dependencies; no fragment is emitted yet.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:39-46
    // (BeamGlobalAssembler::BeamGlobalAssembler, the `labelNames` loop), OTP-29.1.1.
    pub fn declare_labels() -> Self {
        let mut asm = BeamAssembler::new();
        let labels = GLOBAL_LABELS.iter().map(|_| asm.new_label()).collect();
        Self { asm, labels }
    }

    /// `labels[lbl]`.
    pub fn label(&self, label: GlobalLabels) -> Label {
        self.labels[label as usize]
    }

    /// `emitPtrs[label]`, for the fragments ported so far.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.hpp.pl (decl_emitPtrs), OTP-29.1.1.
    pub fn emit_ptr(label: GlobalLabels) -> Option<EmitFn> {
        use GlobalLabels as G;
        Some(match label {
            G::HandleElementError => Self::emit_handle_element_error,
            G::HandleHdError => Self::emit_handle_hd_error,
            G::HandleMapGetBadkey => Self::emit_handle_map_get_badkey,
            G::HandleMapGetBadmap => Self::emit_handle_map_get_badmap,
            G::HandleMapSizeError => Self::emit_handle_map_size_error,
            G::HandleNodeError => Self::emit_handle_node_error,
            G::ITestYieldShared => Self::emit_i_test_yield_shared,
            G::BifExportTrap => Self::emit_bif_export_trap,
            G::DispatchReturn => Self::emit_dispatch_return,
            G::DispatchSaveCallsFun => Self::emit_dispatch_save_calls_fun,
            G::IFuncInfoShared => Self::emit_i_func_info_shared,
            G::IBreakpointTrampolineShared => Self::emit_i_breakpoint_trampoline_shared,
            G::RaiseException => Self::emit_raise_exception,
            G::RaiseExceptionNullExp => Self::emit_raise_exception_null_exp,
            G::ProcessExit => Self::emit_process_exit,
            G::RaiseExceptionShared => Self::emit_raise_exception_shared,
            G::RaiseShared => Self::emit_raise_shared,
            G::CatchEndShared => Self::emit_catch_end_shared,
            G::DispatchSaveCallsExport => Self::emit_dispatch_save_calls_export,
            G::UnloadedFun => Self::emit_unloaded_fun,
            G::HandleCallFunError => Self::emit_handle_call_fun_error,
            G::BsSizeCheckShared => Self::emit_bs_size_check_shared,
            G::BsGetTailShared => Self::emit_bs_get_tail_shared,
            G::BsGetUtf8Shared => Self::emit_bs_get_utf8_shared,
            G::BsCreateBinErrorShared => Self::emit_bs_create_bin_error_shared,
            G::GetSint64Shared => Self::emit_get_sint64_shared,
            G::ConstructUtf8Shared => Self::emit_construct_utf8_shared,
            G::StoreUnaligned => Self::emit_store_unaligned,
            _ => return None,
        })
    }

    /// Emits the fragment table: every fragment of `emitPtrs` in enum order, aligned to 8
    /// bytes and bound to its predeclared label. Fragments not ported yet are absent.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:35-55
    // (BeamGlobalAssembler::BeamGlobalAssembler, up to codegen), OTP-29.1.1.
    pub fn new() -> Result<Self, AsmError> {
        let mut ga = Self::declare_labels();
        for label in &GLOBAL_LABELS[..GLOBAL_FRAGMENT_COUNT] {
            if let Some(emit) = Self::emit_ptr(*label) {
                ga.asm.align_code(8)?;
                ga.asm.bind(ga.label(*label))?;
                emit(&mut ga)?;
            }
        }
        Ok(ga)
    }

    /// `get_<fragment>()` once the global code is placed at `base`: `getCode(labels[label])`.
    /// `None` for a fragment not emitted.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.hpp.pl (decl_get_funcs) and
    // jit/beam_jit_common.hpp (BeamAssemblerCommon::getCode), OTP-29.1.1.
    pub fn get(&self, base: usize, label: GlobalLabels) -> Option<usize> {
        let location = self.asm.a.label_location(self.label(label))?;
        Some(base + location.offset)
    }

    /// The `AsmRange` of every emitted fragment, as code offsets: from its label to the next
    /// fragment's label, the last one to the end of the code.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:67-90 (the `ranges` loop),
    // OTP-29.1.1.
    pub fn ranges(&self) -> Vec<(GlobalLabels, std::ops::Range<usize>)> {
        let starts: Vec<(GlobalLabels, usize)> = GLOBAL_LABELS[..GLOBAL_FRAGMENT_COUNT]
            .iter()
            .filter_map(|label| {
                let location = self.asm.a.label_location(self.label(*label))?;
                Some((*label, location.offset))
            })
            .collect();
        let end = self.asm.a.section_offset(arinsal_x64::buf::Section::Code);
        starts
            .iter()
            .enumerate()
            .map(|(i, (label, start))| {
                let stop = starts.get(i + 1).map_or(end, |next| next.1);
                (*label, *start..stop)
            })
            .collect()
    }

    /// Handles trapping to exports from C code: `c_p->current` points into the MFA of an
    /// export entry; continues at its dispatch address as `call_ext` would.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:143-154 (emit_bif_export_trap),
    // OTP-29.1.1.
    fn emit_bif_export_trap(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit(|e| e.mov_rm(RET, process_ref(process::CURRENT, 8)))?;
        a.emit(|e| e.sub_ri(RET, i64::from(arinsal_term::EXPORT_MFA_OFFSET)))?;
        a.emit_leave_frame()?;
        let target = a.emit_setup_dispatchable_call_active(RET)?;
        a.emit(|e| e.jmp_m(target))
    }

    /// `raise_exception_null_exp`: `raise_exception` without an MFA.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:338-341
    // (emit_raise_exception_null_exp), OTP-29.1.1.
    fn emit_raise_exception_null_exp(&mut self) -> Result<(), AsmError> {
        self.asm.mov_imm(ARG4, 0)?;
        let label = self.label(GlobalLabels::RaiseException);
        self.asm.jmp(label)
    }

    /// Throws from a global fragment: the return address on the machine stack, aligned to a
    /// CP, becomes the error address of a fake call frame.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:343-366 (emit_raise_exception),
    // OTP-29.1.1.
    fn emit_raise_exception(&mut self) -> Result<(), AsmError> {
        const CPMASK: i64 = 3;
        let a = &mut self.asm;
        a.emit(|e| e.pop_r(ARG2))?;
        a.emit(|e| e.and_ri(ARG2, !CPMASK))?;
        a.emit(|e| e.push_r(ARG2))?;
        const {
            assert!(matches!(
                super::beam_asm::FRAME_LAYOUT,
                super::beam_asm::FrameLayout::Ra
            ))
        };
        let label = self.label(GlobalLabels::RaiseExceptionShared);
        self.asm.jmp(label)
    }

    /// Ends a process whose exception has no handler: `handle_error` with no error address
    /// and no MFA; a null handler schedules out.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:304-323 (emit_process_exit),
    // OTP-29.1.1.
    fn emit_process_exit(&mut self) -> Result<(), AsmError> {
        let spec = Update::HEAP_ALLOC.union(Update::REDUCTIONS);
        let a = &mut self.asm;
        a.emit_enter_runtime(spec)?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.mov_imm(ARG2, 0)?;
        a.mov_imm(ARG4, 0)?;
        a.load_x_reg_array(ARG3)?;
        a.runtime_call(handle_error as *const () as usize)?;
        a.emit_leave_runtime(spec)?;
        a.emit(|e| e.test_rr(RET, RET))?;
        let do_schedule = self.label(GlobalLabels::DoSchedule);
        self.asm.jcc(CondCode::E, do_schedule)?;
        // End of process.
        self.asm.emit(|e| e.ud2())
    }

    /// Resolves the exception of `c_p` at error address `ARG2` (a CP or null) with MFA `ARG4`
    /// to its handler and continues there, or schedules out without one.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:356-385
    // (emit_raise_exception_shared), OTP-29.1.1.
    fn emit_raise_exception_shared(&mut self) -> Result<(), AsmError> {
        const CPMASK: i64 = 3;
        let a = &mut self.asm;
        let crash = a.new_label();
        a.emit_enter_runtime(Update::HEAP_ALLOC)?;
        // The error address must be a valid CP or NULL.
        a.emit(|e| e.test_ri(ARG2D, CPMASK))?;
        a.short_jcc(CondCode::NE, crash)?;
        // ARG2 and ARG4 must be set prior to jumping here.
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.load_x_reg_array(ARG3)?;
        a.runtime_call(handle_error as *const () as usize)?;
        a.emit_leave_runtime(Update::HEAP_ALLOC)?;
        a.emit(|e| e.test_rr(RET, RET))?;
        let do_schedule = self.label(GlobalLabels::DoSchedule);
        self.asm.jcc(CondCode::E, do_schedule)?;
        self.asm.emit(|e| e.jmp_r(RET))?;
        self.asm.bind(crash)?;
        // Error address is not a CP or NULL or ARG2 and ARG4 are unset.
        self.asm.emit(|e| e.ud2())
    }

    /// `a.jmp(labels[target])`.
    fn jmp_later_fragment(&mut self, target: GlobalLabels) -> Result<(), AsmError> {
        let label = self.label(target);
        self.asm.jmp(label)
    }

    /// ARG3 = return address, `current_label + TEST_YIELD_RETURN_OFFSET`.
    // Port of erts/emulator/beam/jit/x86/instr_common.cpp:3204-3215
    // (emit_i_test_yield_shared), OTP-29.1.1.
    pub fn emit_i_test_yield_shared(&mut self) -> Result<(), AsmError> {
        let mfa_offset =
            -(TEST_YIELD_RETURN_OFFSET as i32) - core::mem::size_of::<ErtsCodeMfa>() as i32;
        let arity_offset = core::mem::offset_of!(ErtsCodeMfa, arity) as i32;
        let a = &mut self.asm;
        a.emit(|e| e.lea(ARG2, qword_ptr(ARG3, mfa_offset)))?;
        a.emit(|e| e.mov_mr(process_ref(process::CURRENT, 8), ARG2))?;
        a.emit(|e| e.movzx_rm(ARG2D, arinsal_x64::enc::byte_ptr(ARG2, arity_offset)))?;
        a.emit(|e| e.mov_mr(process_ref(process::ARITY, 1), ARG2.r8()))?;
        self.jmp_later_fragment(GlobalLabels::ContextSwitchSimplified)
    }

    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:275-284
    // (emit_handle_element_error), OTP-29.1.1.
    fn emit_handle_element_error(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), ARG1))?;
        a.emit(|e| e.mov_mr(get_x_ref(1, 8), ARG2))?;
        a.emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADARG as i64))?;
        a.emit(|e| e.mov_ri(ARG4, mfa_address(&ELEMENT_MFA) as i64))?;
        self.jmp_later_fragment(GlobalLabels::RaiseException)
    }

    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:513-520 (emit_handle_hd_error),
    // OTP-29.1.1.
    fn emit_handle_hd_error(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), RET))?;
        a.emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADARG as i64))?;
        a.emit(|e| e.mov_ri(ARG4, mfa_address(&HD_MFA) as i64))?;
        self.jmp_later_fragment(GlobalLabels::RaiseException)
    }

    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:598-606
    // (emit_handle_map_get_badkey), OTP-29.1.1.
    fn emit_handle_map_get_badkey(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), ARG2))?;
        a.emit(|e| e.mov_mr(get_x_ref(1, 8), ARG1))?;
        a.emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADKEY as i64))?;
        a.emit(|e| e.mov_mr(process_ref(process::FVALUE, 8), ARG2))?;
        a.emit(|e| e.mov_ri(ARG4, mfa_address(&MAP_GET_BADKEY_MFA) as i64))?;
        self.jmp_later_fragment(GlobalLabels::RaiseException)
    }

    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:588-596
    // (emit_handle_map_get_badmap), OTP-29.1.1.
    fn emit_handle_map_get_badmap(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), ARG2))?;
        a.emit(|e| e.mov_mr(get_x_ref(1, 8), ARG1))?;
        a.emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADMAP as i64))?;
        a.emit(|e| e.mov_mr(process_ref(process::FVALUE, 8), ARG1))?;
        a.emit(|e| e.mov_ri(ARG4, mfa_address(&MAP_GET_BADMAP_MFA) as i64))?;
        self.jmp_later_fragment(GlobalLabels::RaiseException)
    }

    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:693-701
    // (emit_handle_map_size_error), OTP-29.1.1.
    fn emit_handle_map_size_error(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), RET))?;
        a.emit(|e| e.mov_mr(process_ref(process::FVALUE, 8), RET))?;
        a.emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADMAP as i64))?;
        a.emit(|e| e.mov_ri(ARG4, mfa_address(&MAP_SIZE_MFA) as i64))?;
        self.jmp_later_fragment(GlobalLabels::RaiseException)
    }

    // Port of erts/emulator/beam/jit/x86/instr_guard_bifs.cpp:842-849 (emit_handle_node_error),
    // OTP-29.1.1.
    fn emit_handle_node_error(&mut self) -> Result<(), AsmError> {
        let a = &mut self.asm;
        a.emit(|e| e.mov_mr(get_x_ref(0, 8), ARG1))?;
        a.emit(|e| e.mov_mi(process_ref(process::FREASON, 8), EXC_BADARG as i64))?;
        a.emit(|e| e.mov_ri(ARG4, mfa_address(&NODE_MFA) as i64))?;
        self.jmp_later_fragment(GlobalLabels::RaiseException)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_x64::buf::Section;

    #[test]
    fn label_table_matches_generator() {
        assert_eq!(GLOBAL_LABELS.len(), LABEL_NAMES.len());
        for (index, label) in GLOBAL_LABELS.iter().enumerate() {
            assert_eq!(*label as usize, index);
        }
        assert_eq!(GlobalLabels::ApplyFunShared.name(), "apply_fun_shared");
        assert_eq!(
            GlobalLabels::UpdateMapSingleExactBodyShared as usize,
            GLOBAL_FRAGMENT_COUNT - 1
        );
        assert_eq!(GlobalLabels::ContextSwitch as usize, GLOBAL_FRAGMENT_COUNT);
        assert_eq!(
            GlobalLabels::ILineBreakpointCleanup.name(),
            "i_line_breakpoint_cleanup"
        );
    }

    /// The instruction lines of fragment `name` in the erts dump.
    fn fragment_lines<'a>(dump: &'a str, name: &str) -> Vec<&'a str> {
        let head = format!("global::{name}:");
        dump.lines()
            .skip_while(|line| line.trim() != head)
            .skip(1)
            .map(str::trim)
            .take_while(|line| *line != "align 8" && !line.starts_with("global::"))
            .filter(|line| !line.starts_with('#'))
            .collect()
    }

    /// Rewrites erts' static addresses to Arinsal's: the MFA or `the_active_code_index` an
    /// absolute `mov` loads (asmjit's `mov r64, imm` is 32-bit when the value fits).
    fn rewrite(line: &str, address: Option<u64>) -> String {
        let line = crate::x86::jdump::erts_to_arinsal(line);
        if let Some(address) = address
            && let Some((dst, value)) = line.strip_prefix("mov ").and_then(|r| r.split_once(", "))
            && value.parse::<u64>().is_ok_and(|v| v > u64::from(u32::MAX))
        {
            let reg = arinsal_x64::enc::Gp::q(match dst {
                "rcx" => 1,
                "rdi" => 7,
                other => panic!("absolute load into {other}"),
            });
            return if address <= u64::from(u32::MAX) {
                format!(
                    "mov {}, {address}",
                    ["ecx", "edi"][usize::from(reg.id == 7)]
                )
            } else {
                format!("movabs {dst}, {address}")
            };
        }
        line
    }

    // Differential check against erts: the fragment table is emitted in the order of the
    // `global::` labels of `erl +JDdump true`, and every fragment the constructor emits encodes
    // the same instructions as erts' (with Arinsal's process and scheduler register layouts and
    // static addresses), jumps to other fragments compared by form.
    #[test]
    fn fragments_match_erts_dump() {
        let Some(dump) = crate::x86::jdump::erts_dump("beam_asm_global") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let dumped: Vec<&str> = dump
            .lines()
            .filter_map(|l| l.strip_prefix("global::")?.strip_suffix(':'))
            .collect();
        let mut fragments: Vec<&str> = LABEL_NAMES[..GLOBAL_FRAGMENT_COUNT].to_vec();
        // The internal labels are bound inside process_main, right after its label.
        let main = fragments.iter().position(|n| *n == "process_main").unwrap();
        fragments.splice(
            main + 1..main + 1,
            ["context_switch", "context_switch_simplified", "do_schedule"],
        );
        let line_bp = fragments
            .iter()
            .position(|n| *n == "i_line_breakpoint_trampoline_shared")
            .unwrap();
        fragments.insert(line_bp + 1, "i_line_breakpoint_cleanup");
        assert_eq!(dumped, fragments);

        let active = &raw const crate::x86::rt::the_active_code_index as u64;
        let address = |label: GlobalLabels| -> Option<u64> {
            use GlobalLabels as G;
            Some(match label {
                G::HandleElementError => mfa_address(&ELEMENT_MFA),
                G::HandleHdError => mfa_address(&HD_MFA),
                G::HandleMapGetBadkey => mfa_address(&MAP_GET_BADKEY_MFA),
                G::HandleMapGetBadmap => mfa_address(&MAP_GET_BADMAP_MFA),
                G::HandleMapSizeError => mfa_address(&MAP_SIZE_MFA),
                G::HandleNodeError => mfa_address(&NODE_MFA),
                G::DispatchSaveCallsFun | G::DispatchSaveCallsExport | G::UnloadedFun => active,
                _ => return None,
            })
        };
        if crate::x86::jdump::gnu_as(&[]).is_none() {
            eprintln!("skipping byte comparison: GNU binutils unavailable");
            return;
        }
        let ga = BeamGlobalAssembler::new().unwrap();
        let code = ga.asm.a.bytes(Section::Code);
        let ranges = ga.ranges();
        let unbound: Vec<&str> = GLOBAL_LABELS
            .iter()
            .filter(|label| ga.asm.a.label_location(ga.label(**label)).is_none())
            .map(|label| label.name())
            .collect();
        assert!(ranges.len() >= 21);
        for (label, range) in ranges {
            assert_eq!(range.start % 8, 0);
            let lines: Vec<String> = fragment_lines(&dump, label.name())
                .into_iter()
                .map(|l| rewrite(l, address(label)))
                // `offsetof(Export, info.mfa)`: 64 in erts, Arinsal's `ExportEntry.mfa`.
                .map(|l| match (label, l.as_str()) {
                    (GlobalLabels::BifExportTrap, "sub rax, 64") => {
                        format!("sub rax, {}", arinsal_term::EXPORT_MFA_OFFSET)
                    }
                    _ => l,
                })
                .collect();
            // erts' range runs to the next fragment; its last bytes are `align 8` padding.
            let ours = &code[range.clone()];
            let matched = (1..=ours.len()).rev().any(|n| {
                crate::x86::jdump::matches_with_global_jumps(&lines, &ours[..n], &unbound)
                    == Some(true)
                    && ours[n..].len() < 8
            });
            assert!(matched, "{label:?}: {lines:?} vs {:02x?}", ours);
        }
    }

    #[test]
    fn exception_reasons_match_erts() {
        // freason immediates of erts' handle_*_error fragments in the 29.1.1 dump.
        assert_eq!(EXC_BADARG, 3152);
        assert_eq!(EXC_BADMAP, 18512);
        assert_eq!(EXC_BADKEY, 19536);
    }

    #[test]
    fn unported_fragments_are_absent() {
        assert!(BeamGlobalAssembler::emit_ptr(GlobalLabels::ProcessMain).is_none());
        assert!(BeamGlobalAssembler::emit_ptr(GlobalLabels::ContextSwitch).is_none());
    }
}

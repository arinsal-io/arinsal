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
use super::rt::addr;
pub use super::rt::{call_error_handler, erts_garbage_collect_nobump, handle_error};
pub use crate::common::process_offsets::ProcessOffsets;
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
    /// `ptrs`: the executable address of every label, filled by [`Self::codegen`].
    ptrs: Vec<Option<usize>>,
    /// The `offsetof` values of the VM's `Process` the fragments compile in.
    pub(crate) offsets: ProcessOffsets,
    /// The native exit fragment `emit_process_main` binds (Arinsal's exit protocol, see
    /// `x86::process_main`).
    pub(crate) native_exit: Option<Label>,
}

/// `ErtsCodeMFA` a global fragment raises with (`static ErtsCodeMFA mfa` in its emitter).
const fn bif_mfa(function: arinsal_term::Atom, arity: usize) -> ErtsCodeMfa {
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

/// `TEST_YIELD_RETURN_OFFSET` for the `RA` frame layout without code allocation tags
/// (`erts_alcu_enable_code_atags` is an undocumented `+M` option Arinsal does not have).
// Port of erts/emulator/beam/jit/x86/instr_common.cpp:3199-3202, OTP-29.1.1.
pub const TEST_YIELD_RETURN_OFFSET: u32 =
    crate::common::beam_asm_h::BEAM_ASM_FUNC_PROLOGUE_SIZE as u32 + 16;

impl BeamGlobalAssembler {
    /// The labels of every fragment declared up front, so global functions can refer to each
    /// other freely without any order dependencies; no fragment is emitted yet.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:39-46
    // (BeamGlobalAssembler::BeamGlobalAssembler, the `labelNames` loop), OTP-29.1.1.
    pub fn declare_labels(offsets: ProcessOffsets) -> Self {
        let mut asm = BeamAssembler::new();
        let labels = GLOBAL_LABELS.iter().map(|_| asm.new_label()).collect();
        Self {
            asm,
            labels,
            ptrs: Vec::new(),
            offsets,
            native_exit: None,
        }
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
            G::GarbageCollect => Self::emit_garbage_collect,
            // Port of erts/emulator/beam/jit/x86/instr_bif.cpp fragment emitters,
            // OTP-29.1.1.
            G::BifNifEpilogue => Self::emit_bif_nif_epilogue,
            G::CallBifShared => Self::emit_call_bif_shared,
            G::CallLightBifShared => Self::emit_call_light_bif_shared,
            G::CallNifEarly => Self::emit_call_nif_early,
            G::CallNifShared => Self::emit_call_nif_shared,
            G::CallNifYieldHelper => Self::emit_call_nif_yield_helper,
            G::DispatchBif => Self::emit_dispatch_bif,
            G::DispatchNif => Self::emit_dispatch_nif,
            G::ExportTrampoline => Self::emit_export_trampoline,
            G::GenericBpGlobal => Self::emit_generic_bp_global,
            G::ProcessMain => Self::emit_process_main,
            G::ILoopRecShared => Self::emit_i_loop_rec_shared,
            G::ApplyFunShared => Self::emit_apply_fun_shared,
            G::ILineBreakpointTrampolineShared => Self::emit_i_line_breakpoint_trampoline_shared,
            G::BifElementShared => Self::emit_bif_element_shared,
            G::CheckFloatError => Self::emit_check_float_error,
            G::FconvShared => Self::emit_fconv_shared,
            G::IBifBodyShared => Self::emit_i_bif_body_shared,
            G::IBifGuardShared => Self::emit_i_bif_guard_shared,
            G::ILengthBodyShared => Self::emit_i_length_body_shared,
            G::ILengthGuardShared => Self::emit_i_length_guard_shared,
            G::ILoadNifShared => Self::emit_i_load_nif_shared,
            // Port of erts/emulator/beam/jit/x86/instr_trace.cpp fragment emitters,
            // OTP-29.1.1.
            G::GenericBpLocal => Self::emit_generic_bp_local,
            G::DebugBp => Self::emit_debug_bp,
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
            G::BsGetUtf8ShortShared => Self::emit_bs_get_utf8_short_shared,
            G::BsCreateBinErrorShared => Self::emit_bs_create_bin_error_shared,
            G::BsInitBitsShared => Self::emit_bs_init_bits_shared,
            G::GetSint64Shared => Self::emit_get_sint64_shared,
            G::ConstructUtf8Shared => Self::emit_construct_utf8_shared,
            G::StoreUnaligned => Self::emit_store_unaligned,
            // Port of erts/emulator/beam/jit/x86/instr_common.cpp shared comparison fragments,
            // OTP-29.1.1.
            G::IsEqExactListShared => Self::emit_is_eq_exact_list_shared,
            G::IsEqExactShallowBoxedShared => Self::emit_is_eq_exact_shallow_boxed_shared,
            G::ArithEqShared => Self::emit_arith_eq_shared,
            G::ArithCompareShared => Self::emit_arith_compare_shared,
            G::IsInRangeShared => Self::emit_is_in_range_shared,
            G::IsGeLtShared => Self::emit_is_ge_lt_shared,
            // Port of erts/emulator/beam/jit/x86/instr_map.cpp map fragments, OTP-29.1.1.
            G::IGetMapElementShared => Self::emit_i_get_map_element_shared,
            G::IGetMapElementHashShared => Self::emit_i_get_map_element_hash_shared,
            G::NewMapShared => Self::emit_new_map_shared,
            G::UpdateMapAssocShared => Self::emit_update_map_assoc_shared,
            G::UpdateMapSingleAssocShared => Self::emit_update_map_single_assoc_shared,
            G::UpdateMapExactGuardShared => Self::emit_update_map_exact_guard_shared,
            G::UpdateMapExactBodyShared => Self::emit_update_map_exact_body_shared,
            G::UpdateMapSingleExactBodyShared => Self::emit_update_map_single_exact_body_shared,
            // Port of erts/emulator/beam/jit/x86/instr_arith.cpp fragment registrations,
            // OTP-29.1.1.
            G::IBandBodyShared => Self::emit_i_band_body_shared,
            G::IBandGuardShared => Self::emit_i_band_guard_shared,
            G::IBorBodyShared => Self::emit_i_bor_body_shared,
            G::IBorGuardShared => Self::emit_i_bor_guard_shared,
            G::IBnotBodyShared => Self::emit_i_bnot_body_shared,
            G::IBnotGuardShared => Self::emit_i_bnot_guard_shared,
            G::IBslBodyShared => Self::emit_i_bsl_body_shared,
            G::IBslGuardShared => Self::emit_i_bsl_guard_shared,
            G::IBsrBodyShared => Self::emit_i_bsr_body_shared,
            G::IBsrGuardShared => Self::emit_i_bsr_guard_shared,
            G::IBxorBodyShared => Self::emit_i_bxor_body_shared,
            G::IBxorGuardShared => Self::emit_i_bxor_guard_shared,
            G::IntDivRemBodyShared => Self::emit_int_div_rem_body_shared,
            G::IntDivRemGuardShared => Self::emit_int_div_rem_guard_shared,
            G::MinusBodyShared => Self::emit_minus_body_shared,
            G::MinusGuardShared => Self::emit_minus_guard_shared,
            G::MulAddBodyShared => Self::emit_mul_add_body_shared,
            G::MulAddGuardShared => Self::emit_mul_add_guard_shared,
            G::MulBodyShared => Self::emit_mul_body_shared,
            G::MulGuardShared => Self::emit_mul_guard_shared,
            G::PlusBodyShared => Self::emit_plus_body_shared,
            G::PlusGuardShared => Self::emit_plus_guard_shared,
            G::UnaryMinusBodyShared => Self::emit_unary_minus_body_shared,
            G::UnaryMinusGuardShared => Self::emit_unary_minus_guard_shared,
            _ => return None,
        })
    }

    /// Emits the fragment table: every fragment of `emitPtrs` in enum order, aligned to 8
    /// bytes and bound to its predeclared label. Fragments not ported yet are absent.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:35-55
    // (BeamGlobalAssembler::BeamGlobalAssembler, up to codegen), OTP-29.1.1.
    pub fn new(offsets: ProcessOffsets) -> Result<Self, AsmError> {
        let mut ga = Self::declare_labels(offsets);
        for label in &GLOBAL_LABELS[..GLOBAL_FRAGMENT_COUNT] {
            if let Some(emit) = Self::emit_ptr(*label) {
                ga.asm.align_code(8)?;
                ga.asm.bind(ga.label(*label))?;
                emit(&mut ga)?;
            }
        }
        Ok(ga)
    }

    /// Moves the emitted fragments into executable memory and publishes `ptrs`, last so that
    /// global code can only refer to its labels. The returned span holds the global code for
    /// as long as the emulator runs (erts never releases it). `beamasm_metadata_insert` (the
    /// gdb/perf ranges) is not done: Arinsal has no JIT metadata registry yet.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:57-100
    // (BeamGlobalAssembler::BeamGlobalAssembler, from codegen), OTP-29.1.1.
    pub fn codegen(&mut self) -> Result<arinsal_x64::exec::CodeMemory, AsmError> {
        // `VirtMem::flush_instruction_cache` is a no-op on x86-64 and the dual mapping keeps
        // the RX view executable, so `protect_jit_memory` has nothing to change.
        let memory = self.asm.codegen()?;
        self.ptrs = self
            .labels
            .iter()
            .map(|label| self.asm.get_code(*label))
            .collect();
        Ok(memory)
    }

    /// `get_<fragment>()` after [`Self::codegen`]: `ptrs[label]`.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.hpp.pl (decl_get_funcs), OTP-29.1.1.
    pub fn get_ptr(&self, label: GlobalLabels) -> Option<usize> {
        self.ptrs.get(label as usize).copied().flatten()
    }

    /// `ptrs` indexed by [`GlobalLabels`], for the module assemblers' `ga`.
    pub fn ptrs(&self) -> &[Option<usize>] {
        &self.ptrs
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

    /// `ARG3` = HTOP + S_RESERVED + bytes needed, `ARG4` = live registers: collects garbage,
    /// returning to the caller, or schedules out when the process is exiting.
    // Port of erts/emulator/beam/jit/x86/beam_asm_global.cpp:100-155 (emit_garbage_collect),
    // OTP-29.1.1.
    fn emit_garbage_collect(&mut self) -> Result<(), AsmError> {
        use super::beam_asm::register::{ARG1D, ARG5D, FCALLS, HTOP, RETD};
        use super::process_main::ERTS_PSFLG_EXITING;
        let state = arinsal_x64::enc::dword_ptr(C_P, self.offsets.state as i32);
        let a = &mut self.asm;
        let exiting = a.new_label();
        a.emit_enter_frame()?;
        // ARG3 to words needed, cancelling the S_RESERVED of the GC check (the GC adds it).
        a.emit(|e| e.sub_rr(ARG3, HTOP))?;
        a.emit(|e| e.shr_ri(ARG3, 3))?;
        a.emit(|e| e.lea(ARG2, qword_ptr(ARG3, -(arinsal_term::S_RESERVED as i32))))?;
        // Our return address in c_p->i, to tell where we crashed during GC.
        const {
            assert!(matches!(
                super::beam_asm::FRAME_LAYOUT,
                super::beam_asm::FrameLayout::Ra
            ))
        };
        a.emit(|e| e.mov_rm(RET, qword_ptr(arinsal_x64::enc::RSP, 0)))?;
        a.emit(|e| e.mov_mr(process_ref(process::I, 8), RET))?;
        a.emit_enter_runtime(Update::STACK.union(Update::HEAP))?;
        a.emit(|e| e.mov_rr(ARG1, C_P))?;
        a.load_x_reg_array(ARG3)?;
        a.emit(|e| e.mov_rr(ARG5D, FCALLS))?;
        a.runtime_call(addr(erts_garbage_collect_nobump as *const ()))?;
        a.emit(|e| e.sub_rr(FCALLS, RETD))?;
        a.emit_leave_runtime(Update::STACK.union(Update::HEAP))?;
        a.emit(|e| e.mov_rm(ARG1D, state))?;
        a.emit(|e| e.test_ri(ARG1D, i64::from(ERTS_PSFLG_EXITING)))?;
        a.short_jcc(CondCode::NE, exiting)?;
        a.emit_leave_frame()?;
        a.emit(|e| e.ret())?;
        a.bind(exiting)?;
        a.emit_unwind_frame()?;
        let do_schedule = self.label(GlobalLabels::DoSchedule);
        self.asm.jmp(do_schedule)
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
        a.runtime_call(addr(handle_error as *const ()))?;
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
        a.runtime_call(addr(handle_error as *const ()))?;
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
        let mut lines: Vec<_> = dump
            .lines()
            .skip_while(|line| line.trim() != head)
            .skip(1)
            .map(str::trim)
            .take_while(|line| *line != "align 8" && !line.starts_with("global::"))
            .filter(|line| !line.starts_with('#'))
            .collect();

        // `aligned_call(OperandType)` emits a sizing call, rewinds the AsmJit cursor, then
        // emits padding and the final call. JDdump logs the sizing call even though the
        // rewind overwrites it in the code buffer; compare the final bytes, not that log entry.
        let mut index = 0;
        while index < lines.len() {
            if lines[index].starts_with("call ") {
                let mut next = index + 1;
                while next < lines.len()
                    && (lines[next].starts_with(".byte ") || lines[next].starts_with(".db "))
                {
                    next += 1;
                }
                if next < lines.len()
                    && lines[next].starts_with("call ")
                    && lines[next] == lines[index]
                {
                    lines.remove(index);
                    continue;
                }
            }
            index += 1;
        }
        lines
    }

    /// Rewrites erts' static addresses to Arinsal's: the MFA or `the_active_code_index` an
    /// absolute `mov` loads (asmjit's `mov r64, imm` is 32-bit when the value fits).
    fn rewrite(line: &str, addresses: &mut std::vec::IntoIter<u64>) -> String {
        let line = crate::x86::jdump::erts_to_arinsal(line);
        if line
            .strip_prefix("call ")
            .and_then(|target| target.parse::<u64>().ok())
            .is_some()
        {
            return ".byte 0x40, 0xe8, 0, 0, 0, 0".to_owned();
        }
        if let Some((dst, value)) = line.strip_prefix("mov ").and_then(|r| r.split_once(", "))
            && value.parse::<u64>().is_ok_and(|v| v > u64::from(u32::MAX))
            && let Some(address) = addresses.next()
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
        let addresses = |label: GlobalLabels| -> Vec<u64> {
            use GlobalLabels as G;
            match label {
                G::ApplyFunShared => vec![mfa_address(&crate::x86::instr_fun::APPLY2_MFA)],
                G::HandleElementError => vec![mfa_address(&ELEMENT_MFA)],
                G::HandleHdError => vec![mfa_address(&HD_MFA)],
                G::HandleMapGetBadkey => vec![mfa_address(&MAP_GET_BADKEY_MFA)],
                G::HandleMapGetBadmap => vec![mfa_address(&MAP_GET_BADMAP_MFA)],
                G::HandleMapSizeError => vec![mfa_address(&MAP_SIZE_MFA)],
                G::HandleNodeError => vec![mfa_address(&NODE_MFA)],
                G::DispatchSaveCallsFun
                | G::DispatchSaveCallsExport
                | G::UnloadedFun
                | G::ILoopRecShared
                | G::BifNifEpilogue
                | G::CallBifShared
                | G::CallLightBifShared
                | G::CallNifShared => {
                    vec![active]
                }
                G::PlusBodyShared => vec![mfa_address(&crate::x86::instr_arith::PLUS_MFA)],
                G::MinusBodyShared => vec![mfa_address(&crate::x86::instr_arith::MINUS_MFA)],
                G::UnaryMinusBodyShared => {
                    vec![mfa_address(&crate::x86::instr_arith::UNARY_MINUS_MFA)]
                }
                G::MulAddBodyShared => vec![
                    mfa_address(&crate::x86::instr_arith::PLUS_MFA),
                    mfa_address(&crate::x86::instr_arith::TIMES_MFA),
                ],
                G::IBandBodyShared => vec![mfa_address(&crate::x86::instr_arith::BAND_MFA)],
                G::IBorBodyShared => vec![mfa_address(&crate::x86::instr_arith::BOR_MFA)],
                G::IBxorBodyShared => vec![mfa_address(&crate::x86::instr_arith::BXOR_MFA)],
                G::IBnotBodyShared => vec![mfa_address(&crate::x86::instr_arith::BNOT_MFA)],
                G::IBslBodyShared => vec![mfa_address(&crate::x86::instr_arith::BSL_MFA)],
                G::IBsrBodyShared => vec![mfa_address(&crate::x86::instr_arith::BSR_MFA)],
                G::ILengthBodyShared => vec![mfa_address(&crate::x86::instr_bif::LENGTH_MFA)],
                G::ILoadNifShared => vec![mfa_address(&crate::x86::instr_bif::LOAD_NIF_MFA)],
                G::ILineBreakpointTrampolineShared => {
                    vec![crate::x86::raw::line_breakpoint_prepare() as u64]
                }
                G::ILineBreakpointCleanup => {
                    vec![crate::x86::raw::line_breakpoint_cleanup() as u64]
                }
                _ => Vec::new(),
            }
        };
        if crate::x86::jdump::gnu_as(&[]).is_none() {
            eprintln!("skipping byte comparison: GNU binutils unavailable");
            return;
        }
        let ga = BeamGlobalAssembler::new(ProcessOffsets::ERTS_X86_64).unwrap();
        let code = ga.asm.a.bytes(Section::Code);
        let mut ranges = ga.ranges();
        let line_bp_index = ranges
            .iter()
            .position(|(label, _)| *label == GlobalLabels::ILineBreakpointTrampolineShared)
            .unwrap();
        let (line_bp, line_bp_range) = ranges.remove(line_bp_index);
        let cleanup_offset = ga
            .asm
            .a
            .label_location(ga.label(GlobalLabels::ILineBreakpointCleanup))
            .unwrap()
            .offset;
        ranges.insert(
            line_bp_index,
            (line_bp, line_bp_range.start..cleanup_offset),
        );
        ranges.insert(
            line_bp_index + 1,
            (
                GlobalLabels::ILineBreakpointCleanup,
                cleanup_offset..line_bp_range.end,
            ),
        );
        let unbound: Vec<&str> = GLOBAL_LABELS
            .iter()
            .filter(|label| ga.asm.a.label_location(ga.label(**label)).is_none())
            .map(|label| label.name())
            .collect();
        assert!(ranges.len() >= 21);
        for (label, range) in ranges {
            assert_eq!(range.start % 8, 0);
            if label == GlobalLabels::ProcessMain {
                // Compared piecewise by `process_main_matches_erts_dump`.
                continue;
            }
            let mut static_addresses = addresses(label).into_iter();
            let lines: Vec<String> = fragment_lines(&dump, label.name())
                .into_iter()
                .map(|l| rewrite(l, &mut static_addresses))
                .map(|line| {
                    let line = if let Some(data) = line.strip_prefix(".dq ") {
                        format!(".quad {data}")
                    } else {
                        line
                    };
                    match (label, line.as_str()) {
                        (GlobalLabels::CallLightBifShared, "cmp dword ptr [rcx+36], 0") => format!(
                            "cmp dword ptr [rcx+{}], 0",
                            core::mem::offset_of!(arinsal_term::ExportEntry, is_bif_traced)
                        ),
                        (GlobalLabels::CallLightBifShared, "add rcx, 64") => {
                            format!("add rcx, {}", arinsal_term::EXPORT_MFA_OFFSET)
                        }
                        (GlobalLabels::CallLightBifShared, "movzx r8d, byte ptr [r8+80]") => {
                            format!(
                                "movzx r8d, byte ptr [r8+{}]",
                                arinsal_term::EXPORT_MFA_OFFSET
                                    + core::mem::offset_of!(arinsal_term::ErtsCodeMfa, arity)
                                        as u32
                            )
                        }
                        (GlobalLabels::CallLightBifShared, "movzx esi, byte ptr [rcx+80]") => {
                            format!(
                                "movzx esi, byte ptr [rcx+{}]",
                                arinsal_term::EXPORT_MFA_OFFSET
                                    + core::mem::offset_of!(arinsal_term::ErtsCodeMfa, arity)
                                        as u32
                            )
                        }
                        (GlobalLabels::CallLightBifShared, "lea rcx, qword ptr [rcx+64]") => {
                            format!(
                                "lea rcx, qword ptr [rcx+{}]",
                                arinsal_term::EXPORT_MFA_OFFSET
                            )
                        }
                        (GlobalLabels::GenericBpGlobal, "lea rsi, qword ptr [rax+48]") => format!(
                            "lea rsi, qword ptr [rax+{}]",
                            arinsal_term::EXPORT_INFO_OFFSET
                        ),
                        _ => line.replace("[L", "[rip + L"),
                    }
                })
                .collect();
            let mut lines_with_alignment: Vec<String> = Vec::with_capacity(lines.len());
            for line in lines {
                if line == "align 16" {
                    // erts aligns this fragment's embedded constants by their absolute
                    // code address. The fragment may start at offset 8 mod 16 in this table.
                    const NOPS: [&str; 9] = [
                        "0x90",
                        "0x66, 0x90",
                        "0x0f, 0x1f, 0x00",
                        "0x0f, 0x1f, 0x40, 0x00",
                        "0x0f, 0x1f, 0x44, 0x00, 0x00",
                        "0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00",
                        "0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00",
                        "0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00",
                        "0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00",
                    ];
                    let prefix_for_size: Vec<String> = lines_with_alignment
                        .iter()
                        .map(|prefix_line| {
                            let Some((op, _)) = prefix_line.split_once(" global::") else {
                                return prefix_line.clone();
                            };
                            match op {
                                "jmp" => ".byte 0xe9, 0, 0, 0, 0".to_string(),
                                "short jmp" => ".byte 0xeb, 0".to_string(),
                                "jz" => ".byte 0x0f, 0x84, 0, 0, 0, 0".to_string(),
                                "jnz" => ".byte 0x0f, 0x85, 0, 0, 0, 0".to_string(),
                                "short jz" => ".byte 0x74, 0".to_string(),
                                "short jnz" => ".byte 0x75, 0".to_string(),
                                other => panic!("unknown global jump `{other}`"),
                            }
                        })
                        .collect();
                    let prefix_len = crate::x86::jdump::gnu_as(&prefix_for_size)
                        .expect("GNU as for alignment prefix")
                        .len();
                    let mut padding = (16 - (range.start + prefix_len) % 16) % 16;
                    while padding > 0 {
                        let length = padding.min(NOPS.len());
                        lines_with_alignment.push(format!(".byte {}", NOPS[length - 1]));
                        padding -= length;
                    }
                } else {
                    lines_with_alignment.push(line);
                }
            }
            // erts' range runs to the next fragment; its last bytes are `align 8` padding.
            let ours = &code[range.clone()];
            let matched = (1..=ours.len()).rev().any(|n| {
                crate::x86::jdump::matches_with_global_jumps(
                    &lines_with_alignment,
                    &ours[..n],
                    &unbound,
                ) == Some(true)
                    && ours[n..].len() < 8
            });
            assert!(
                matched,
                "{label:?}: {lines_with_alignment:?} vs {:02x?}",
                ours
            );
        }
    }

    /// The schedule-out half of erts' `process_main` text, from `do_schedule_local` to the
    /// `copy_out_registers` call and the FCALLS store that follows in this port
    /// (`schedule_out`; erts computes `reds_used` there instead, see `x86::process_main`).
    /// `fill` is the byte the displacements to code elsewhere are written with.
    fn schedule_out_text(dump: &str, fill: u8) -> Vec<String> {
        let main = fragment_lines(dump, "process_main");
        let from = |text: &str| main.iter().position(|l| *l == text).unwrap();
        let at = |i: usize| crate::x86::jdump::erts_to_arinsal(main[i]);
        // L215 (context_switch_local) up to `short jmp L217` after `Process exiting`.
        let local = from("movzx edi, byte ptr [rdx-8]") - 1;
        let exiting = from("mov qword ptr [r13+464], 0");
        let do_schedule_local = main[exiting + 1].strip_prefix("short jmp ").unwrap();
        let fill_disp = if fill == 0 { "rip+0" } else { "rip-1" };
        let mut text = vec![
            format!("{do_schedule_local}:"),
            "{disp32} jmp Lsched".into(),
        ];
        for i in local..=exiting + 1 {
            let line = at(i);
            text.push(match line.as_str() {
                "lea rdi, qword ptr [global::process_exit]" => format!("lea rdi, [{fill_disp}]"),
                _ => line,
            });
        }
        let not_exiting = main[local..]
            .iter()
            .find_map(|l| l.strip_prefix("short jz "))
            .unwrap();
        // reds_used and copy_out_registers run at slice_ended (`slice_ended_text`).
        text.push(format!("{not_exiting}:"));
        text.push("Lsched:".into());
        text.push(crate::x86::jdump::erts_to_arinsal(
            "mov dword ptr [r13+120], r14d",
        ));
        text
    }

    /// erts' reds_used + `copy_out_registers` tail of `not_exiting` (L219), which the port
    /// runs at `slice_ended`; the call's displacement is `fill`.
    fn slice_ended_text(dump: &str, fill: u8) -> Vec<String> {
        let main = fragment_lines(dump, "process_main");
        // The second load of def_arg_reg[5]; the first is do_schedule_local's.
        let from = main
            .iter()
            .rposition(|l| *l == "mov rdx, qword ptr [r13+184]")
            .unwrap();
        let call = from + 5;
        assert!(main[call].starts_with("call "), "{}", main[call]);
        let mut text: Vec<String> = main[from..call]
            .iter()
            .map(|l| crate::x86::jdump::erts_to_arinsal(l))
            .collect();
        text.push(format!(
            ".byte 0x40, 0xe8, {fill:#04x}, {fill:#04x}, {fill:#04x}, {fill:#04x}"
        ));
        text.push(crate::x86::jdump::erts_to_arinsal(main[call + 1]));
        text
    }

    /// Finds `zeros` in `code` where the bytes `zeros` and `ones` agree on (the others are
    /// displacements to code elsewhere).
    fn find_masked(code: &[u8], zeros: &[u8], ones: &[u8]) -> Option<usize> {
        (0..=code.len().checked_sub(zeros.len())?).find(|&at| {
            code[at..at + zeros.len()]
                .iter()
                .zip(zeros.iter().zip(ones))
                .all(|(o, (z, f))| z != f || o == z)
        })
    }

    // process_main against erts' text: the prologue (with Arinsal's register file size, see
    // Step E in `x86::process_main`) and the schedule-out half; the three entry points bound
    // where erts binds them.
    #[test]
    fn process_main_matches_erts_dump() {
        let Some(dump) = crate::x86::jdump::erts_dump("beam_asm_global") else {
            eprintln!("skipping: `erl +JDdump true` unavailable");
            return;
        };
        let main = fragment_lines(&dump, "process_main");
        let size = core::mem::size_of::<crate::SchedulerRegisters>() + 64;
        let prologue = main[..4]
            .iter()
            .map(|l| {
                crate::x86::jdump::erts_to_arinsal(l)
                    .replace("16592", &size.to_string())
                    .replace("rsp+64", &format!("rsp+{}", crate::X_REG_ARRAY_OFFSET))
            })
            .collect::<Vec<_>>();
        let (Some(prologue), Some(zeros), Some(ones), Some(tail_zeros), Some(tail_ones)) = (
            crate::x86::jdump::gnu_as(&prologue),
            crate::x86::jdump::gnu_as(&schedule_out_text(&dump, 0)),
            crate::x86::jdump::gnu_as(&schedule_out_text(&dump, 0xff)),
            crate::x86::jdump::gnu_as(&slice_ended_text(&dump, 0)),
            crate::x86::jdump::gnu_as(&slice_ended_text(&dump, 0xff)),
        ) else {
            eprintln!("skipping byte comparison: GNU binutils unavailable");
            return;
        };
        let ga = BeamGlobalAssembler::new(ProcessOffsets::ERTS_X86_64).unwrap();
        let code = ga.asm.a.bytes(Section::Code);
        let (_, range) = ga
            .ranges()
            .into_iter()
            .find(|(label, _)| *label == GlobalLabels::ProcessMain)
            .unwrap();
        let ours = &code[range.clone()];
        assert_eq!(&ours[..prologue.len()], &prologue[..]);
        assert!(
            find_masked(ours, &zeros, &ones).is_some(),
            "{:02x?}\nnot in\n{:02x?}",
            zeros,
            ours
        );
        assert!(
            find_masked(ours, &tail_zeros, &tail_ones).is_some(),
            "{:02x?}\nnot in\n{:02x?}",
            tail_zeros,
            ours
        );
        let main = ga.asm.a.label_location(ga.label(GlobalLabels::ProcessMain));
        for (entry, name) in [
            (GlobalLabels::ContextSwitch, "context_switch"),
            (
                GlobalLabels::ContextSwitchSimplified,
                "context_switch_simplified",
            ),
            (GlobalLabels::DoSchedule, "do_schedule"),
        ] {
            let at = ga.asm.a.label_location(ga.label(entry)).unwrap().offset;
            assert!(at > main.unwrap().offset && at < range.end, "{name}");
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
    fn internal_labels_are_not_fragments() {
        assert!(BeamGlobalAssembler::emit_ptr(GlobalLabels::ExportTrampoline).is_some());
        // Bound inside process_main, not fragments of their own.
        assert!(BeamGlobalAssembler::emit_ptr(GlobalLabels::ContextSwitch).is_none());
    }
}

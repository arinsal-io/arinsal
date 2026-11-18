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

use super::beam_asm::register::{ARG1, ARG2, ARG2D, ARG3, ARG4, RET};
use super::beam_asm::{AsmError, BeamAssembler, get_x_ref, process, process_ref};
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
            _ => return None,
        })
    }

    /// `a.jmp(labels[target])` to a fragment emitted after the current one. asmjit encodes a
    /// jump to a label that is not bound yet as `jmp rel32`.
    fn jmp_later_fragment(&mut self, target: GlobalLabels) -> Result<(), AsmError> {
        let label = self.label(target);
        Ok(self.asm.a.jmp_near(label)?)
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
    use std::path::Path;
    use std::process::Command;

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

    /// `beam_asm_global.asm` written by `erl +JDdump true`, or `None` without `erl`.
    fn erts_global_dump() -> Option<String> {
        let dir = std::env::temp_dir().join(format!("arinsal-x86-jdump-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let status = Command::new("erl")
            .args(["+JDdump", "true", "-noshell", "-eval", "halt()."])
            .current_dir(&dir)
            .status()
            .ok()?;
        let text = status
            .success()
            .then(|| std::fs::read_to_string(dir.join("beam_asm_global.asm")).ok())
            .flatten();
        let _ = std::fs::remove_dir_all(&dir);
        text
    }

    /// The instruction lines of fragment `name` in the erts dump.
    fn fragment_lines<'a>(dump: &'a str, name: &str) -> Vec<&'a str> {
        let head = format!("global::{name}:");
        dump.lines()
            .skip_while(|line| line.trim() != head)
            .skip(1)
            .map(str::trim)
            .take_while(|line| *line != "align 8" && !line.starts_with("global::"))
            .collect()
    }

    /// Assembles Intel-syntax `lines` with GNU `as`; `None` without binutils.
    fn gnu_as(lines: &[String]) -> Option<Vec<u8>> {
        let dir = std::env::temp_dir().join(format!(
            "arinsal-x86-as-{}-{}",
            std::process::id(),
            lines.len()
        ));
        std::fs::create_dir_all(&dir).ok()?;
        let src = format!(
            ".intel_syntax noprefix\n.text\n{}\n.skip 256\n__later_fragment:\n",
            lines.join("\n")
        );
        let (s, o, bin) = (dir.join("f.s"), dir.join("f.o"), dir.join("f.bin"));
        std::fs::write(&s, src).ok()?;
        let ok = |cmd: &mut Command| cmd.status().map(|s| s.success()).unwrap_or(false);
        let built = ok(Command::new("as").arg("--64").arg("-o").arg(&o).arg(&s))
            && ok(Command::new("objcopy")
                .args(["-O", "binary", "-j", ".text"])
                .arg(&o)
                .arg(&bin));
        let bytes = built.then(|| std::fs::read(Path::new(&bin)).ok()).flatten();
        let _ = std::fs::remove_dir_all(&dir);
        bytes.map(|mut b| {
            b.truncate(b.len() - 256);
            b
        })
    }

    /// erts' `Process` offsets in the 29.1.1 x86-64 dump, as Arinsal's `ProcessHeader` has them.
    const ERTS_PROCESS_OFFSETS: [(i32, i32); 4] = [
        (104, process::FREASON),
        (112, process::FVALUE),
        (464, process::CURRENT),
        (133, process::ARITY),
    ];

    /// Rewrites one erts dump line to Arinsal's process layout and MFA address.
    fn rewrite(line: &str, mfa: Option<u64>) -> String {
        let mut line = line.trim_start_matches("rex ").to_string();
        for (erts, ours) in ERTS_PROCESS_OFFSETS {
            line = line.replace(&format!("[r13+{erts}]"), &format!("[r13+{ours}]"));
        }
        if let (Some(rest), Some(mfa)) = (line.strip_prefix("mov rcx, "), mfa)
            && rest.parse::<u64>().is_ok()
        {
            // asmjit's `mov r64, imm` takes the zero-extending 32-bit form when it can.
            line = if mfa <= u64::from(u32::MAX) {
                format!("mov ecx, {mfa}")
            } else {
                format!("movabs rcx, {mfa}")
            };
        }
        if line.starts_with("jmp global::") {
            line = "jmp __later_fragment".to_string();
        }
        line
    }

    // Differential check against erts: the fragment table is emitted in the order of the
    // `global::` labels of `erl +JDdump true`, and every ported fragment encodes the same
    // instructions as erts' (with Arinsal's process field offsets and static MFA addresses).
    #[test]
    fn fragments_match_erts_dump() {
        let Some(dump) = erts_global_dump() else {
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

        let cases: [(GlobalLabels, Option<&'static ErtsCodeMfa>); 7] = [
            (GlobalLabels::ITestYieldShared, None),
            (GlobalLabels::HandleElementError, Some(&ELEMENT_MFA)),
            (GlobalLabels::HandleHdError, Some(&HD_MFA)),
            (GlobalLabels::HandleMapGetBadkey, Some(&MAP_GET_BADKEY_MFA)),
            (GlobalLabels::HandleMapGetBadmap, Some(&MAP_GET_BADMAP_MFA)),
            (GlobalLabels::HandleMapSizeError, Some(&MAP_SIZE_MFA)),
            (GlobalLabels::HandleNodeError, Some(&NODE_MFA)),
        ];
        for (label, mfa) in cases {
            let lines: Vec<String> = fragment_lines(&dump, label.name())
                .into_iter()
                .map(|l| rewrite(l, mfa.map(mfa_address)))
                .collect();
            let Some(expected) = gnu_as(&lines) else {
                eprintln!("skipping byte comparison: GNU binutils unavailable");
                return;
            };
            let mut ga = BeamGlobalAssembler::declare_labels();
            let emit = BeamGlobalAssembler::emit_ptr(label).unwrap();
            emit(&mut ga).unwrap();
            let ours = ga.asm.a.bytes(Section::Code);
            // The trailing `jmp rel32` targets a fragment emitted later; compare its opcode
            // and length, not the displacement.
            let n = ours.len();
            assert_eq!(n, expected.len(), "{label:?}: {lines:?}");
            assert_eq!(ours[..n - 4], expected[..n - 4], "{label:?}: {lines:?}");
            assert_eq!(ours[n - 5], 0xe9);
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

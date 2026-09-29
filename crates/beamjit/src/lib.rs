#![forbid(unsafe_code)]
//! Function-level compiler from OTP 29 BEAM operations to the BeamAsm emitter.

use arinsal_beam::{self as beam, BeamFile};
use arinsal_beamasm::{
    NativeEntry, ProcessHeader, SchedulerRegisters,
    arith::ArithHelper,
    construct::GcHook,
    fun::FunCallTag,
    guard::{GuardHelper, GuardHelper3},
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
};
use arinsal_beamops::{self as beamops, SpecificOp, SpecificOperand};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

/// Runtime values and helper entry points needed while compiling a module.
pub trait ModuleEnv {
    /// Resolve a one-based BEAM atom index to an OTP tagged atom word.
    fn atom(&self, beam: &BeamFile, index: u32) -> Result<u64, String>;
    /// Resolve a zero-based literal index to an OTP tagged term word.
    fn literal(&self, beam: &BeamFile, index: u32) -> Result<u64, String>;
    /// Resolve an import table index to a code/export value.
    fn import(&self, beam: &BeamFile, index: u32) -> Result<u32, String>;
    /// Return the stable VM-owned dispatch slot for an external import.
    fn export_entry(&self, _beam: &BeamFile, _index: u32) -> Result<usize, String> {
        Err("module environment has no external dispatch slots".into())
    }
    /// Return the retained `FunEntry` pointer for a lambda-table index.
    fn lambda_fun_entry(&self, _beam: &BeamFile, index: u32) -> Result<(usize, u8), String> {
        Err(format!("module environment has no lambda entry {index}"))
    }
    /// Publish a native trampoline while preserving the interpreter dispatch entry.
    fn publish_lambda_target(
        &self,
        _beam: &BeamFile,
        _index: u32,
        _target: usize,
    ) -> Result<(), String> {
        Ok(())
    }
    /// Return the process-wide export trampoline emitted by the VM.
    fn export_trampoline(&self) -> usize {
        0
    }
    /// Return the process-wide light-BIF fragment emitted by the VM.
    fn light_bif_fragment(&self) -> usize {
        0
    }
    /// Return the VM's native generic breakpoint helper.
    fn breakpoint_helper(&self) -> usize {
        0
    }
    /// Arithmetic slow path used for bignums and exceptional operands.
    fn arithmetic_helper(&self) -> ArithHelper;
    /// Guard slow path used for term comparisons and guard BIFs.
    fn guard_helper(&self) -> GuardHelper;
    /// Guard slow path for checks that compare a tuple tag as well as its arity.
    fn guard_helper3(&self) -> GuardHelper3;
    /// Heap slow path used by allocating native operations.
    fn gc_hook(&self) -> GcHook;
    /// Map lookup slow path. It returns zero when the key is absent.
    fn map_lookup_helper(&self) -> MapLookupHelper;
    /// Dispatches an OTP BIF function body using the current X registers.
    fn bif_mfa_helper(&self) -> BifMfaHelper;
    /// Executes a bit syntax matching slow path.
    fn bs_match_helper(&self) -> arinsal_beamasm::bs_match::BsMatchHelper;
    /// Runtime callbacks for map creation and updates.
    fn map_runtime(&self) -> arinsal_beamasm::map::MapRuntime;
    /// Runtime callbacks used by the bitstring constructor.
    fn bs_construct_helpers(
        &self,
    ) -> (
        arinsal_beamasm::bs_construct::BsConstructHelper,
        arinsal_beamasm::bs_construct::BsConstructErrorHelper,
    );
    /// Resolves native exception records and returns zero for scheduler dispatch.
    fn exception_resolver(&self) -> arinsal_beamasm::catch::ExceptionResolver;
    /// Resolves a fun term to a native entry for `i_call_fun` / `i_call_fun2`.
    fn fun_resolver(&self) -> arinsal_beamasm::fun::FunResolver {
        unused_fun_resolver
    }
}

extern "C" fn unused_fun_resolver(_process: *mut ProcessHeader, _fun: u64, _arity: u32) -> usize {
    0
}

/// Runtime lookup for map element instructions.
pub type MapLookupHelper =
    unsafe extern "C" fn(*mut ProcessHeader, *mut SchedulerRegisters, u64, u64, u64, u64) -> u64;

/// Runtime dispatcher for BIF entry functions.
pub type BifMfaHelper =
    unsafe extern "C" fn(*mut ProcessHeader, *mut SchedulerRegisters, u64, u64, u64) -> u64;

/// The one authoritative table of specific operations currently emitted here.
#[derive(Clone, Copy, Debug)]
pub struct PortedOp {
    /// OTP specific-op name.
    pub name: &'static str,
    emitter: EmitterKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EmitterKind {
    Metadata,
    Move,
    Swap,
    Allocate,
    AllocateZero,
    Deallocate,
    Trim,
    InitYregs,
    Return,
    DeallocateReturn,
    MoveDeallocateReturn,
    Call,
    CallLast,
    CallOnly,
    Plus,
    Minus,
    Times,
    IntDiv,
    Rem,
    Band,
    Bor,
    Bxor,
    Bsl,
    Bsr,
    Bnot,
    UnaryMinus,
    Guard,
    Construct,
    Heap,
    Fused,
    CallExternal,
    GuardBif,
    SelectVal,
    SelectTupleArity,
    JumpOnVal,
    SelectVal2,
    SelectTupleArity2,
    JumpOnValZero,
    Jump,
    Swap2,
    Swap3,
    Swap4,
    GetTupleElementSwap,
    MulAdd,
    LengthSetup,
    Length,
    PairedRangeGuard,
    MapLookup,
    MapElements,
    BifMfa,
    BsMatch,
    MapUpdate,
    MapCreate,
    BsConstruct,
    Fun,
    Catch,
}

/// Operations that have an emitter in the current module assembler slice.
pub static PORTED_OPS: &[PortedOp] = &[
    PortedOp {
        name: "i_func_label",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "i_func_info",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "label",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "aligned_label",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "line",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "func_line",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "empty_func_line",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "func_prologue",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "i_flush_stubs",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "i_test_yield",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "i_breakpoint_trampoline",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "i_move",
        emitter: EmitterKind::Move,
    },
    PortedOp {
        name: "move",
        emitter: EmitterKind::Move,
    },
    PortedOp {
        name: "swap",
        emitter: EmitterKind::Swap,
    },
    PortedOp {
        name: "allocate",
        emitter: EmitterKind::Allocate,
    },
    PortedOp {
        name: "allocate_zero",
        emitter: EmitterKind::AllocateZero,
    },
    PortedOp {
        name: "deallocate",
        emitter: EmitterKind::Deallocate,
    },
    PortedOp {
        name: "trim",
        emitter: EmitterKind::Trim,
    },
    PortedOp {
        name: "init_yregs",
        emitter: EmitterKind::InitYregs,
    },
    PortedOp {
        name: "return",
        emitter: EmitterKind::Return,
    },
    PortedOp {
        name: "deallocate_return",
        emitter: EmitterKind::DeallocateReturn,
    },
    PortedOp {
        name: "move_deallocate_return",
        emitter: EmitterKind::MoveDeallocateReturn,
    },
    PortedOp {
        name: "i_call",
        emitter: EmitterKind::Call,
    },
    PortedOp {
        name: "i_call_last",
        emitter: EmitterKind::CallLast,
    },
    PortedOp {
        name: "i_call_only",
        emitter: EmitterKind::CallOnly,
    },
    PortedOp {
        name: "i_plus",
        emitter: EmitterKind::Plus,
    },
    PortedOp {
        name: "i_minus",
        emitter: EmitterKind::Minus,
    },
    PortedOp {
        name: "i_times",
        emitter: EmitterKind::Times,
    },
    PortedOp {
        name: "i_mul_add",
        emitter: EmitterKind::MulAdd,
    },
    PortedOp {
        name: "i_int_div",
        emitter: EmitterKind::IntDiv,
    },
    PortedOp {
        name: "i_rem",
        emitter: EmitterKind::Rem,
    },
    PortedOp {
        name: "i_band",
        emitter: EmitterKind::Band,
    },
    PortedOp {
        name: "i_bor",
        emitter: EmitterKind::Bor,
    },
    PortedOp {
        name: "i_bxor",
        emitter: EmitterKind::Bxor,
    },
    PortedOp {
        name: "i_bsl",
        emitter: EmitterKind::Bsl,
    },
    PortedOp {
        name: "i_bsr",
        emitter: EmitterKind::Bsr,
    },
    PortedOp {
        name: "i_bnot",
        emitter: EmitterKind::Bnot,
    },
    PortedOp {
        name: "i_unary_minus",
        emitter: EmitterKind::UnaryMinus,
    },
    // Guard and data operations already implemented by BeamModuleAssembler.
    PortedOp {
        name: "is_integer",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_atom",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_float",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_boolean",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_binary",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_bitstring",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_number",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_pid",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_port",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_reference",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_function",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_function2",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_list",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_nonempty_list",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_nil",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_map",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_tuple",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "i_is_tuple",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "i_test_arity",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "test_arity",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_tagged_tuple",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "i_is_tuple_of_arity",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "i_is_tuple_of_arity_ff",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "i_is_tagged_tuple",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "i_is_tagged_tuple_ff",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_eq_exact",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_ne_exact",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_eq",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_ne",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_lt",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_ge",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "put_list",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "put_list2",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "put_tuple2",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "get_list",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "get_hd",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "get_tl",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "load_tuple_ptr",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "i_get_tuple_element",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "get_tuple_element",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "set_tuple_element",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "update_record",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "update_record_in_place",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "get_two_tuple_elements",
        emitter: EmitterKind::Construct,
    },
    PortedOp {
        name: "test_heap",
        emitter: EmitterKind::Heap,
    },
    PortedOp {
        name: "allocate_heap",
        emitter: EmitterKind::Heap,
    },
    PortedOp {
        name: "allocate_heap_zero",
        emitter: EmitterKind::Heap,
    },
    PortedOp {
        name: "store_two_values",
        emitter: EmitterKind::Fused,
    },
    PortedOp {
        name: "load_two_xregs",
        emitter: EmitterKind::Fused,
    },
    PortedOp {
        name: "move_trim",
        emitter: EmitterKind::Fused,
    },
    PortedOp {
        name: "move_call_last",
        emitter: EmitterKind::Fused,
    },
    PortedOp {
        name: "put_list_deallocate",
        emitter: EmitterKind::Fused,
    },
    PortedOp {
        name: "i_call_ext",
        emitter: EmitterKind::CallExternal,
    },
    PortedOp {
        name: "i_call_ext_last",
        emitter: EmitterKind::CallExternal,
    },
    PortedOp {
        name: "i_call_ext_only",
        emitter: EmitterKind::CallExternal,
    },
    PortedOp {
        name: "call_light_bif",
        emitter: EmitterKind::CallExternal,
    },
    PortedOp {
        name: "bif_hd",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_tl",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_element",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_node",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_bit_size",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_byte_size",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_tuple_size",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_map_get",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_is_map_key",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_max",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_min",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_map_size",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_is_eq_exact",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_is_ne_exact",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_is_ge",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_is_lt",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_length",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_self",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "self",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_abs",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "move_two_trim",
        emitter: EmitterKind::Fused,
    },
    PortedOp {
        name: "move_call_ext_last",
        emitter: EmitterKind::Fused,
    },
    PortedOp {
        name: "mark_unreachable",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "int_code_end",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "is_int_ge",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_int_in_range",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_in_range",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_ge_lt",
        emitter: EmitterKind::PairedRangeGuard,
    },
    PortedOp {
        name: "is_ge_ge",
        emitter: EmitterKind::PairedRangeGuard,
    },
    PortedOp {
        name: "i_get_map_element",
        emitter: EmitterKind::MapLookup,
    },
    PortedOp {
        name: "i_get_map_element_hash",
        emitter: EmitterKind::MapLookup,
    },
    PortedOp {
        name: "i_get_map_elements",
        emitter: EmitterKind::MapElements,
    },
    PortedOp {
        name: "get_map_elements",
        emitter: EmitterKind::MapElements,
    },
    PortedOp {
        name: "update_map_assoc",
        emitter: EmitterKind::MapUpdate,
    },
    PortedOp {
        name: "update_map_exact",
        emitter: EmitterKind::MapUpdate,
    },
    PortedOp {
        name: "i_new_small_map_lit",
        emitter: EmitterKind::MapCreate,
    },
    PortedOp {
        name: "call_bif_mfa",
        emitter: EmitterKind::BifMfa,
    },
    PortedOp {
        name: "i_bs_start_match3",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_match",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_match_test_heap",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_get_binary2",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_create_bin",
        emitter: EmitterKind::BsConstruct,
    },
    PortedOp {
        name: "i_m_div",
        emitter: EmitterKind::IntDiv,
    },
    PortedOp {
        name: "catch",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "try",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "catch_end",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "try_case",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "try_end",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "try_end_deallocate",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "case_end",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "badmatch",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "if_end",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "badrecord",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "i_make_fun3",
        emitter: EmitterKind::Fun,
    },
    PortedOp {
        name: "i_lambda_trampoline",
        emitter: EmitterKind::Fun,
    },
    PortedOp {
        name: "i_call_fun",
        emitter: EmitterKind::Fun,
    },
    PortedOp {
        name: "i_call_fun_last",
        emitter: EmitterKind::Fun,
    },
    PortedOp {
        name: "i_call_fun2",
        emitter: EmitterKind::Fun,
    },
    PortedOp {
        name: "i_call_fun2_last",
        emitter: EmitterKind::Fun,
    },
    PortedOp {
        name: "send",
        emitter: EmitterKind::Fun,
    },
    PortedOp {
        name: "i_bs_get_position",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "bs_set_position",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "bs_get_tail",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "swap2",
        emitter: EmitterKind::Swap2,
    },
    PortedOp {
        name: "swap3",
        emitter: EmitterKind::Swap3,
    },
    PortedOp {
        name: "swap4",
        emitter: EmitterKind::Swap4,
    },
    PortedOp {
        name: "get_tuple_element_swap",
        emitter: EmitterKind::GetTupleElementSwap,
    },
    PortedOp {
        name: "i_length_setup",
        emitter: EmitterKind::LengthSetup,
    },
    PortedOp {
        name: "i_length",
        emitter: EmitterKind::Length,
    },
    PortedOp {
        name: "bif_and",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_or",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "bif_not",
        emitter: EmitterKind::GuardBif,
    },
    PortedOp {
        name: "i_select_val_lins",
        emitter: EmitterKind::SelectVal,
    },
    PortedOp {
        name: "i_select_val_bins",
        emitter: EmitterKind::SelectVal,
    },
    PortedOp {
        name: "i_select_val2",
        emitter: EmitterKind::SelectVal2,
    },
    PortedOp {
        name: "i_select_tuple_arity",
        emitter: EmitterKind::SelectTupleArity,
    },
    PortedOp {
        name: "i_select_tuple_arity2",
        emitter: EmitterKind::SelectTupleArity2,
    },
    PortedOp {
        name: "i_jump_on_val",
        emitter: EmitterKind::JumpOnVal,
    },
    PortedOp {
        name: "i_jump_on_val_zero",
        emitter: EmitterKind::JumpOnValZero,
    },
    PortedOp {
        name: "jump",
        emitter: EmitterKind::Jump,
    },
];

/// A successfully compiled BEAM function.
pub struct CompiledFunction {
    /// Function name from the BEAM function metadata.
    pub name: String,
    /// Function arity.
    pub arity: u8,
    /// Entry label in the source module.
    pub label: u32,
}

/// A function retained for interpreter execution, with the opcode blockers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnportedFunction {
    /// Function name when metadata was available.
    pub name: String,
    /// Function arity when metadata was available.
    pub arity: u8,
    /// Function entry label.
    pub label: u32,
    /// Unique missing specific-op names in bytecode order.
    pub missing_ops: Vec<String>,
}

/// Parsed module, native function entries, and function-level interpreter fallback list.
pub struct CompiledModule {
    /// Module name.
    pub name: String,
    /// Native functions that can be entered while this object is alive.
    pub functions: Vec<CompiledFunction>,
    /// Functions with one or more operations outside this emitter slice.
    pub unported: Vec<UnportedFunction>,
    /// Owns the executable mapping containing `functions` entries.
    pub native: FinalizedModule,
}

impl CompiledModule {
    /// Returns a safe native entry handle tied to this module's executable mapping.
    pub fn entry(&self, function: &CompiledFunction) -> Option<NativeEntry<'_>> {
        self.native.entry(function.label)
    }
}

/// Parse, specialize, and emit every function whose operations have emitters.
pub fn compile_module_with_env(
    beam_bytes: &[u8],
    env: &impl ModuleEnv,
) -> Result<CompiledModule, CompileError> {
    compile_module_with_env_and_funcs(beam_bytes, env, None)
}

/// Parse, specialize, and emit selected functions whose operations have emitters.
///
/// When `function_allowlist` is present, only exact `name/arity` entries are compiled.
pub fn compile_module_with_env_and_funcs(
    beam_bytes: &[u8],
    env: &impl ModuleEnv,
    function_allowlist: Option<&str>,
) -> Result<CompiledModule, CompileError> {
    let beam = beam::parse(beam_bytes).map_err(|error| CompileError::Parse(error.to_string()))?;
    let specialized = beamops::transform_module(&beam);
    let mut candidates = Vec::new();
    let mut unported = Vec::new();

    for ops in specialized {
        let (name, arity, label) = function_identity(&ops, &beam);
        if function_allowlist.is_some_and(|list| !function_allowlist_contains(list, &name, arity)) {
            unported.push(UnportedFunction {
                name,
                arity,
                label,
                missing_ops: vec!["excluded by ARINSAL_BEAMASM_FUNCS".to_owned()],
            });
            continue;
        }
        if beam.module == "init" && name == "get_flag" && arity == 3 {
            unported.push(UnportedFunction {
                name,
                arity,
                label,
                missing_ops: vec!["native continuation bridge".to_owned()],
            });
            continue;
        }
        let blockers = missing_ops(&ops);
        if !blockers.is_empty() {
            unported.push(UnportedFunction {
                name,
                arity,
                label,
                missing_ops: blockers,
            });
            continue;
        }
        candidates.push((name, arity, label, ops));
    }

    // Probe each function before laying out the module. Dropping one late emitter error and
    // restarting the whole module for every blocked function makes OTP loading quadratic.
    let mut emit_failures = Vec::new();
    candidates.retain(|(name, arity, label, ops)| {
        let mut probe = BeamModuleAssembler::new();
        if let Some(op) = ops
            .iter()
            .find(|op| emit_op(&mut probe, op, &beam, env).is_err())
        {
            emit_failures.push(UnportedFunction {
                name: name.clone(),
                arity: *arity,
                label: *label,
                missing_ops: vec![op.name().to_owned()],
            });
            false
        } else {
            true
        }
    });
    unported.extend(emit_failures);

    let mut assembler;
    let mut compiled = Vec::new();

    loop {
        let native_labels = candidates
            .iter()
            .flat_map(|(_, _, label, ops)| {
                std::iter::once(*label).chain(ops.iter().filter_map(|op| match op.name() {
                    "label" | "aligned_label" => as_u32(op.operands().first()),
                    _ => None,
                }))
            })
            .collect::<BTreeSet<_>>();
        let mut removed = false;
        let mut index = 0;
        while index < candidates.len() {
            let blocked_call = candidates[index].3.iter().find_map(|op| {
                call_target(op)
                    .filter(|target| !native_labels.contains(target))
                    .map(|_| op.name().to_owned())
            });
            if let Some(op) = blocked_call {
                let (name, arity, label, _) = candidates.remove(index);
                unported.push(UnportedFunction {
                    name,
                    arity,
                    label,
                    missing_ops: vec![op],
                });
                removed = true;
            } else {
                index += 1;
            }
        }
        if removed {
            continue;
        }

        // Fun creators stay native even when a lambda body is still interpreted:
        // make_fun3_entry stores the shared FunEntry, and unpublished
        // dispatch_target slots fall through to the call_fun resolver (same
        // shape as OTP's unloaded/dispatchable path). Whole-module fallback is
        // reserved for hard assemble failures below, not for missing trampolines.

        assembler = BeamModuleAssembler::new();
        assembler.enable_dump(&beam.module);
        for lambda in &beam.lambdas {
            if !native_labels.contains(&lambda.label) {
                continue;
            }
            let total_arity = u8::try_from(lambda.arity).map_err(|_| {
                CompileError::Assemble(format!(
                    "{} lambda {} has invalid total arity {}",
                    beam.module, lambda.index, lambda.arity
                ))
            })?;
            let num_free = u8::try_from(lambda.num_free).map_err(|_| {
                CompileError::Assemble(format!(
                    "{} lambda {} has invalid free variable count {}",
                    beam.module, lambda.index, lambda.num_free
                ))
            })?;
            assembler
                .register_lambda(lambda.index, lambda.label, total_arity, num_free)
                .map_err(|error| {
                    CompileError::Assemble(format!(
                        "{} lambda {}: {error:?}",
                        beam.module, lambda.index
                    ))
                })?;
        }
        compiled.clear();
        let mut failure_index = None;
        let mut failure_reason = None;

        for (index, (name, arity, label, ops)) in candidates.iter().enumerate() {
            assembler.begin_dump_function(name, *arity);
            let dump_enabled = assembler.dump_enabled();
            for op in ops {
                let start = if dump_enabled {
                    assembler.code_offset()
                } else {
                    0
                };
                if let Err(error) = emit_op(&mut assembler, op, &beam, env) {
                    failure_index = Some(index);
                    failure_reason = Some((
                        op.name().to_owned(),
                        format!("{error}; operands {:?}", op.operands()),
                    ));
                    break;
                }
                if dump_enabled {
                    let end = assembler.code_offset();
                    assembler.record_dump_instruction(
                        format!("{} {:?}", op.name(), op.operands()),
                        start,
                        end,
                    );
                }
            }
            if failure_index.is_some() {
                break;
            }
            compiled.push((name.clone(), *arity, *label));
        }

        if let Some(index) = failure_index {
            let (op, _reason) = failure_reason.unwrap();
            let (name, arity, label, _) = candidates.remove(index);
            unported.push(UnportedFunction {
                name,
                arity,
                label,
                missing_ops: vec![op],
            });
            continue;
        }
        assembler
            .emit_missing_lambda_trampolines()
            .map_err(|error| CompileError::Assemble(format!("{}: {error:?}", beam.module)))?;
        break;
    }

    let native = assembler
        .finalize()
        .map_err(|error| CompileError::Assemble(format!("{}: {error:?}", beam.module)))?;
    for (&index, &target) in &native.lambda_entries {
        env.publish_lambda_target(&beam, index, target as usize)
            .map_err(|error| CompileError::Assemble(format!("{}: {error}", beam.module)))?;
    }
    let mut functions = Vec::with_capacity(compiled.len());
    for (name, arity, label) in compiled {
        if native.entries.contains_key(&label) {
            functions.push(CompiledFunction { name, arity, label });
        } else {
            unported.push(UnportedFunction {
                name,
                arity,
                label,
                missing_ops: vec!["i_func_label".to_owned()],
            });
        }
    }
    Ok(CompiledModule {
        name: beam.module,
        functions,
        unported,
        native,
    })
}

fn function_allowlist_contains(list: &str, name: &str, arity: u8) -> bool {
    list.split(',').map(str::trim).any(|entry| {
        entry
            .rsplit_once('/')
            .is_some_and(|(allowed_name, allowed_arity)| {
                allowed_name == name && allowed_arity.parse::<u8>().ok() == Some(arity)
            })
    })
}

/// Report missing operations in order, without counting repeated uses twice.
pub fn missing_ops(ops: &[SpecificOp]) -> Vec<String> {
    let known = PORTED_OPS.iter().map(|op| op.name).collect::<BTreeSet<_>>();
    let mut missing = BTreeSet::new();
    let mut ordered = Vec::new();
    for op in ops {
        let unsupported_register = !supports_extended_x(op.name())
            && op.operands().iter().any(contains_unsupported_x_register);
        if (!known.contains(op.name()) || unsupported_register)
            && missing.insert(op.name().to_owned())
        {
            ordered.push(op.name().to_owned());
        }
    }
    ordered
}

fn supports_extended_x(name: &str) -> bool {
    matches!(
        name,
        "i_move"
            | "move"
            | "store_two_values"
            | "load_two_xregs"
            | "move_trim"
            | "move_call_last"
            | "move_two_trim"
            | "move_call_ext_last"
            | "swap"
            | "swap2"
            | "swap3"
            | "swap4"
            | "put_list"
            | "put_tuple2"
            | "get_list"
            | "get_hd"
            | "get_tl"
            | "load_tuple_ptr"
            | "get_tuple_element"
            | "i_get_tuple_element"
            | "get_two_tuple_elements"
            | "get_map_elements"
            | "i_bs_match"
            | "i_m_div"
            | "i_make_fun3"
            | "i_bs_start_match3"
            | "i_bs_match_test_heap"
            | "i_bs_get_position"
            | "bs_set_position"
            | "bs_get_tail"
            | "i_bs_get_binary2"
            | "i_bs_create_bin"
            | "i_length_setup"
            | "i_length"
            | "i_plus"
            | "i_minus"
            | "i_times"
            | "i_mul_add"
            | "i_int_div"
            | "i_rem"
            | "i_band"
            | "i_bor"
            | "i_bxor"
            | "i_bsl"
            | "i_bsr"
            | "i_bnot"
            | "i_unary_minus"
            | "bif_and"
            | "bif_or"
            | "bif_not"
            | "bif_hd"
            | "bif_tl"
            | "bif_element"
            | "bif_node"
            | "bif_bit_size"
            | "bif_byte_size"
            | "bif_tuple_size"
            | "bif_map_get"
            | "bif_is_map_key"
            | "bif_max"
            | "bif_min"
            | "bif_map_size"
            | "bif_is_eq_exact"
            | "bif_is_ne_exact"
            | "bif_is_ge"
            | "bif_is_lt"
            | "bif_length"
            | "bif_self"
            | "self"
            | "bif_abs"
            | "i_get_map_element"
            | "i_get_map_element_hash"
            | "i_get_map_elements"
    ) || is_inline_guard(name)
}

fn uses_emitter_spills(name: &str) -> bool {
    matches!(
        name,
        "i_bs_match"
            | "i_bs_start_match3"
            | "i_bs_match_test_heap"
            | "i_bs_get_position"
            | "bs_set_position"
            | "bs_get_tail"
            | "i_bs_get_binary2"
            | "i_bs_create_bin"
            | "get_map_elements"
            | "i_m_div"
            | "i_make_fun3"
            | "i_plus"
            | "i_minus"
            | "i_times"
            | "i_mul_add"
            | "i_int_div"
            | "i_rem"
            | "i_band"
            | "i_bor"
            | "i_bxor"
            | "i_bsl"
            | "i_bsr"
            | "i_bnot"
            | "i_unary_minus"
            | "bif_and"
            | "bif_or"
            | "bif_not"
            | "bif_hd"
            | "bif_tl"
            | "bif_element"
            | "bif_node"
            | "bif_bit_size"
            | "bif_byte_size"
            | "bif_tuple_size"
            | "bif_map_get"
            | "bif_is_map_key"
            | "bif_max"
            | "bif_min"
            | "bif_map_size"
            | "bif_is_eq_exact"
            | "bif_is_ne_exact"
            | "bif_is_ge"
            | "bif_is_lt"
            | "bif_length"
            | "bif_self"
            | "self"
            | "bif_abs"
    )
}

fn is_inline_guard(name: &str) -> bool {
    matches!(
        name,
        "is_integer"
            | "is_atom"
            | "is_float"
            | "is_boolean"
            | "is_binary"
            | "is_bitstring"
            | "is_number"
            | "is_pid"
            | "is_port"
            | "is_reference"
            | "is_function"
            | "is_function2"
            | "is_list"
            | "is_nonempty_list"
            | "is_nil"
            | "is_map"
            | "is_tuple"
            | "i_is_tuple"
            | "i_test_arity"
            | "test_arity"
            | "is_tagged_tuple"
            | "i_is_tuple_of_arity"
            | "i_is_tagged_tuple"
            | "is_eq_exact"
            | "is_ne_exact"
            | "is_eq"
            | "is_ne"
            | "is_lt"
            | "is_ge"
            | "is_int_in_range"
            | "is_in_range"
            | "is_int_ge"
    )
}

fn contains_unsupported_x_register(operand: &SpecificOperand) -> bool {
    match operand {
        SpecificOperand::X(index) => *index >= 6,
        SpecificOperand::List(values) => values.iter().any(contains_unsupported_x_register),
        _ => false,
    }
}

/// Compile all `.beam` files under one or more directories and print a coverage summary.
pub fn coverage(directories: &[String]) -> Result<(), CompileError> {
    let mut files = Vec::new();
    for directory in directories {
        collect_beams(Path::new(directory), &mut files)?;
    }
    files.sort();
    let mut module_count = 0usize;
    let mut functions = 0usize;
    let mut native_functions = 0usize;
    let mut blocked: BTreeMap<String, usize> = BTreeMap::new();
    for path in files {
        let bytes = fs::read(&path)
            .map_err(|error| CompileError::Io(path.display().to_string(), error.to_string()))?;
        let beam = beam::parse(&bytes).map_err(|error| CompileError::Parse(error.to_string()))?;
        let specialized = beamops::transform_module(&beam);
        module_count += 1;
        let mut labels = BTreeSet::new();
        let mut candidates = Vec::new();
        for ops in specialized {
            let (name, arity, label) = function_identity(&ops, &beam);
            labels.extend(ops.iter().filter_map(|op| match op.name() {
                "i_func_label" | "label" | "aligned_label" => as_u32(op.operands().first()),
                _ => None,
            }));
            let missing = missing_ops(&ops);
            candidates.push((name, arity, label, ops, missing));
        }
        let mut is_native = candidates
            .iter()
            .map(|(_, _, _, _, missing)| missing.is_empty())
            .collect::<Vec<_>>();
        for (index, (_, _, _, ops, _)) in candidates.iter().enumerate() {
            if is_native[index]
                && ops
                    .iter()
                    .filter_map(call_target)
                    .any(|target| !labels.contains(&target))
            {
                is_native[index] = false;
            }
        }
        functions += candidates.len();
        for (index, (_, _, _, _, missing)) in candidates.into_iter().enumerate() {
            if is_native[index] {
                native_functions += 1;
            } else {
                for op in missing {
                    *blocked.entry(op).or_default() += 1;
                }
            }
        }
    }
    let percent = if functions == 0 {
        0.0
    } else {
        (native_functions as f64 * 100.0) / functions as f64
    };
    println!(
        "Modules: {module_count}; functions: {functions}; fully native: {native_functions} ({percent:.2}%)"
    );
    println!("Top missing ops (functions blocked):");
    let mut ranking = blocked.into_iter().collect::<Vec<_>>();
    ranking.sort_by(|(a_name, a_count), (b_name, b_count)| {
        b_count.cmp(a_count).then_with(|| a_name.cmp(b_name))
    });
    for (name, count) in ranking.into_iter().take(30) {
        println!("{count:>8}  {name}");
    }
    Ok(())
}

fn collect_beams(path: &Path, result: &mut Vec<std::path::PathBuf>) -> Result<(), CompileError> {
    let entries = fs::read_dir(path)
        .map_err(|error| CompileError::Io(path.display().to_string(), error.to_string()))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| CompileError::Io(path.display().to_string(), error.to_string()))?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_beams(&entry_path, result)?;
        } else if entry_path
            .extension()
            .is_some_and(|extension| extension == "beam")
        {
            result.push(entry_path);
        }
    }
    Ok(())
}

fn function_identity(ops: &[SpecificOp], beam: &BeamFile) -> (String, u8, u32) {
    let mut label = 0;
    let mut name = "<unknown>".to_owned();
    let mut arity = 0;
    for op in ops {
        match op.name() {
            "i_func_label" => label = as_u32(op.operands().first()).unwrap_or(label),
            "i_func_info" if op.operands().len() >= 4 => {
                if let Some(index) = as_u32(op.operands().get(2)) {
                    name = beam.atom(index).unwrap_or("<unknown>").to_owned();
                }
                arity = as_u32(op.operands().get(3)).unwrap_or(0).min(255) as u8;
            }
            _ => {}
        }
    }
    (name, arity, label)
}

fn as_u32(value: Option<&SpecificOperand>) -> Option<u32> {
    match value? {
        SpecificOperand::Label(value)
        | SpecificOperand::Atom(value)
        | SpecificOperand::Export(value)
        | SpecificOperand::Literal(value) => Some(*value),
        SpecificOperand::Unsigned(value) => u32::try_from(*value).ok(),
        SpecificOperand::SmallInt(value) => u32::try_from(*value).ok(),
        _ => None,
    }
}

fn call_target(op: &SpecificOp) -> Option<u32> {
    match op.name() {
        "i_call" | "i_call_only" => as_u32(op.operands().first()),
        "i_call_last" => as_u32(op.operands().first()),
        "move_call_last" => as_u32(op.operands().get(2)),
        _ => None,
    }
}

/// Maps `i_call_fun2` Safe operand: atom → Dynamic, lambda index → Lambda(id).
// Port of erts/emulator/beam/jit/arm/ops.tab:879-880 (`aF`) and instr_fun.cpp:402-423, OTP-29.1.1.
fn fun_call_tag(value: Option<&SpecificOperand>, beam: &BeamFile) -> Result<FunCallTag, EmitError> {
    match value.ok_or_else(|| EmitError::Operand("missing call_fun2 tag".to_owned()))? {
        SpecificOperand::Atom(index) => {
            let name = beam
                .atom(*index)
                .ok_or_else(|| EmitError::Operand(format!("unknown call_fun2 atom {index}")))?;
            if name == "safe" || name == "unsafe" {
                Ok(FunCallTag::Dynamic)
            } else {
                Err(EmitError::Operand(format!(
                    "unsupported call_fun2 tag atom {name}"
                )))
            }
        }
        SpecificOperand::SmallInt(index) => {
            let index = u32::try_from(*index).map_err(|_| {
                EmitError::Operand("call_fun2 lambda index out of range".to_owned())
            })?;
            Ok(FunCallTag::Lambda(index))
        }
        SpecificOperand::Unsigned(index) => {
            let index = u32::try_from(*index).map_err(|_| {
                EmitError::Operand("call_fun2 lambda index out of range".to_owned())
            })?;
            Ok(FunCallTag::Lambda(index))
        }
        _ => Err(EmitError::Operand(
            "call_fun2 tag must be atom or lambda index".to_owned(),
        )),
    }
}

fn arg(
    value: Option<&SpecificOperand>,
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<ArgVal, String> {
    match value.ok_or_else(|| "missing operand".to_owned())? {
        SpecificOperand::X(index) if *index < 6 => Ok(ArgVal::X(*index as u8)),
        SpecificOperand::X(_) => Err("X register index exceeds assembler cache".to_owned()),
        SpecificOperand::Y(index) => Ok(ArgVal::Y(*index)),
        SpecificOperand::Label(index) => Ok(ArgVal::Label(*index)),
        SpecificOperand::Atom(index) => env.atom(beam, *index).map(ArgVal::Immediate),
        SpecificOperand::Export(index) => env.import(beam, *index).map(ArgVal::Export),
        SpecificOperand::Literal(index) => env.literal(beam, *index).map(ArgVal::Literal),
        SpecificOperand::SmallInt(value) => {
            Ok(ArgVal::Immediate((*value as u64).wrapping_shl(4) | 0xf))
        }
        SpecificOperand::Unsigned(value) => Ok(ArgVal::Immediate(*value)),
        SpecificOperand::Nil => Ok(ArgVal::Immediate(0x3b)),
        _ => Err("operand form is not accepted by the module assembler".to_owned()),
    }
}

#[derive(Clone, Copy)]
enum MoveArg {
    X(u32),
    Value(ArgVal),
}

fn move_arg(
    value: Option<&SpecificOperand>,
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<MoveArg, String> {
    match value.ok_or_else(|| "missing operand".to_owned())? {
        SpecificOperand::X(index) => Ok(MoveArg::X(*index)),
        operand => arg(Some(operand), beam, env).map(MoveArg::Value),
    }
}

fn emit_extended_move(
    assembler: &mut BeamModuleAssembler,
    source: Option<&SpecificOperand>,
    destination: Option<&SpecificOperand>,
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<(), arinsal_beamasm::module::ModuleError> {
    use arinsal_a64::enc::Gpr;

    let source = move_arg(source, beam, env)
        .map_err(|_| arinsal_beamasm::module::ModuleError::InvalidOperand("invalid move source"))?;
    let destination = move_arg(destination, beam, env).map_err(|_| {
        arinsal_beamasm::module::ModuleError::InvalidOperand("invalid move destination")
    })?;
    let high_register = matches!(source, MoveArg::X(index) if index >= 6)
        || matches!(destination, MoveArg::X(index) if index >= 6);
    if !high_register {
        let source = match source {
            MoveArg::X(index) => ArgVal::X(index as u8),
            MoveArg::Value(value) => value,
        };
        let destination = match destination {
            MoveArg::X(index) => ArgVal::X(index as u8),
            MoveArg::Value(value) => value,
        };
        return assembler.move_(source, destination);
    }

    let source_offset = match source {
        MoveArg::X(index) if index >= 6 => Some(register_offset(index)?),
        _ => None,
    };
    let destination_offset = match destination {
        MoveArg::X(index) if index >= 6 => Some(register_offset(index)?),
        _ => None,
    };
    assembler.emit_raw(|encoder| {
        if let Some(offset) = source_offset {
            encoder.ldr_uoff(Gpr::x(8), Gpr::x(19), offset)?;
        } else {
            let source_register = match source {
                MoveArg::X(index) => Gpr::x([25, 26, 27, 28, 15, 16][index as usize]),
                MoveArg::Value(ArgVal::Y(index)) => {
                    let offset = index
                        .checked_mul(8)
                        .ok_or(arinsal_a64::enc::EncodeError::InvalidRegister(Gpr::x(31)))?;
                    encoder.ldr_uoff(Gpr::x(8), Gpr::x(20), offset)?;
                    Gpr::x(8)
                }
                MoveArg::Value(ArgVal::Immediate(value) | ArgVal::Literal(value)) => {
                    encoder.mov_const(Gpr::x(8), value)?;
                    Gpr::x(8)
                }
                MoveArg::Value(ArgVal::Export(value)) => {
                    encoder.mov_const(Gpr::x(8), u64::from(value))?;
                    Gpr::x(8)
                }
                MoveArg::Value(ArgVal::Label(_)) => {
                    return Err(arinsal_a64::enc::EncodeError::InvalidRegister(Gpr::x(31)));
                }
                MoveArg::Value(_) => {
                    return Err(arinsal_a64::enc::EncodeError::InvalidRegister(Gpr::x(31)));
                }
            };
            if source_register != Gpr::x(8) {
                encoder.mov_reg(Gpr::x(8), source_register)?;
            }
        }

        if let Some(offset) = destination_offset {
            encoder.str_uoff(Gpr::x(8), Gpr::x(19), offset)?;
        } else {
            match destination {
                MoveArg::X(index) => {
                    encoder.mov_reg(Gpr::x([25, 26, 27, 28, 15, 16][index as usize]), Gpr::x(8))?;
                }
                MoveArg::Value(ArgVal::Y(index)) => {
                    let offset = index
                        .checked_mul(8)
                        .ok_or(arinsal_a64::enc::EncodeError::InvalidRegister(Gpr::x(31)))?;
                    encoder.str_uoff(Gpr::x(8), Gpr::x(20), offset)?;
                }
                _ => return Err(arinsal_a64::enc::EncodeError::InvalidRegister(Gpr::x(31))),
            }
        }
        Ok(())
    })?;
    Ok(())
}

fn register_offset(index: u32) -> Result<u32, arinsal_beamasm::module::ModuleError> {
    if index >= 1024 {
        return Err(arinsal_beamasm::module::ModuleError::InvalidOperand(
            "X register index exceeds scheduler register array",
        ));
    }
    index
        .checked_mul(8)
        .ok_or(arinsal_beamasm::module::ModuleError::InvalidOperand(
            "X register offset overflow",
        ))
}

fn validate_extended_x(args: &[SpecificOperand]) -> Result<(), EmitError> {
    for operand in args {
        match operand {
            SpecificOperand::X(index) if *index >= 1024 => {
                return Err(EmitError::Operand(
                    "X register index exceeds scheduler register array".to_owned(),
                ));
            }
            SpecificOperand::List(items) => validate_extended_x(items)?,
            _ => {}
        }
    }
    Ok(())
}

fn has_extended_x(args: &[SpecificOperand]) -> bool {
    args.iter().any(|operand| match operand {
        SpecificOperand::X(index) => *index >= 6,
        SpecificOperand::List(items) => has_extended_x(items),
        _ => false,
    })
}

fn collect_extended_x(args: &[SpecificOperand], indexes: &mut BTreeSet<u32>) {
    for operand in args {
        match operand {
            SpecificOperand::X(index) if *index >= 6 => {
                indexes.insert(*index);
            }
            SpecificOperand::List(items) => collect_extended_x(items, indexes),
            _ => {}
        }
    }
}

fn remap_spilled_x(operand: &mut SpecificOperand, spills: &BTreeMap<u32, u32>, count: u32) {
    match operand {
        SpecificOperand::X(index) if *index >= 6 => {
            if let Some(slot) = spills.get(index) {
                *operand = SpecificOperand::Y(*slot);
            }
        }
        SpecificOperand::Y(index) => *index = index.saturating_add(count),
        SpecificOperand::List(items) => {
            for item in items {
                remap_spilled_x(item, spills, count);
            }
        }
        _ => {}
    }
}

fn raw_move_arg(
    operand: Option<&SpecificOperand>,
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<MoveArg, EmitError> {
    move_arg(operand, beam, env).map_err(EmitError::Operand)
}

fn raw_load_arg(
    encoder: &mut arinsal_a64::enc::Emitter,
    source: MoveArg,
    destination: arinsal_a64::enc::Gpr,
) -> Result<(), arinsal_a64::enc::EncodeError> {
    use arinsal_a64::enc::{EncodeError, Gpr};
    match source {
        MoveArg::X(index) if index < 6 => encoder.mov_reg(
            destination,
            Gpr::x([25, 26, 27, 28, 15, 16][index as usize]),
        ),
        MoveArg::X(index) => encoder.ldr_uoff(destination, Gpr::x(19), index.saturating_mul(8)),
        MoveArg::Value(ArgVal::Y(index)) => {
            encoder.ldr_uoff(destination, Gpr::x(20), index.saturating_mul(8))
        }
        MoveArg::Value(ArgVal::Immediate(value) | ArgVal::Literal(value)) => {
            encoder.mov_const(destination, value)
        }
        MoveArg::Value(ArgVal::Export(value)) => encoder.mov_const(destination, u64::from(value)),
        _ => Err(EncodeError::InvalidRegister(Gpr::x(31))),
    }
}

fn raw_store_arg(
    encoder: &mut arinsal_a64::enc::Emitter,
    destination: MoveArg,
    source: arinsal_a64::enc::Gpr,
) -> Result<(), arinsal_a64::enc::EncodeError> {
    use arinsal_a64::enc::{EncodeError, Gpr};
    match destination {
        MoveArg::X(index) if index < 6 => {
            encoder.mov_reg(Gpr::x([25, 26, 27, 28, 15, 16][index as usize]), source)
        }
        MoveArg::X(index) => encoder.str_uoff(source, Gpr::x(19), index.saturating_mul(8)),
        MoveArg::Value(ArgVal::Y(index)) => {
            encoder.str_uoff(source, Gpr::x(20), index.saturating_mul(8))
        }
        _ => Err(EncodeError::InvalidRegister(Gpr::x(31))),
    }
}

struct MapLookupSpec {
    map: MoveArg,
    key: MoveArg,
    hash: u32,
    hashed: bool,
    destination: MoveArg,
    fail: u32,
    helper: MapLookupHelper,
    stable_map: bool,
}

// Port of erts/emulator/beam/jit/arm/instr_map.cpp:362-393 and 511-539, OTP-29.1.1.
fn emit_map_lookup(
    assembler: &mut BeamModuleAssembler,
    spec: MapLookupSpec,
) -> Result<(), EmitError> {
    use arinsal_a64::enc::Gpr;

    assembler.emit_raw(|encoder| {
        if !spec.stable_map {
            raw_load_arg(encoder, spec.map, Gpr::x(24))?;
        }
        raw_load_arg(encoder, spec.key, Gpr::x(11))?;
        encoder.mov_const(Gpr::x(12), u64::from(spec.hash))?;
        encoder.mov_const(Gpr::x(13), u64::from(spec.hashed))?;
        encoder.str_uoff(Gpr::x(20), Gpr::x(21), 8)?;
        encoder.str_uoff(Gpr::x(23), Gpr::x(21), 0)?;
        encoder.str_uoff(Gpr::w(22), Gpr::x(21), 32)?;
        for (index, reg) in [25, 26, 27, 28, 15, 16].into_iter().enumerate() {
            encoder.str_uoff(Gpr::x(reg), Gpr::x(19), (index as u32) * 8)?;
        }
        encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
        encoder.mov_reg(Gpr::x(1), Gpr::x(19))?;
        encoder.mov_reg(Gpr::x(2), Gpr::x(24))?;
        encoder.mov_reg(Gpr::x(3), Gpr::x(11))?;
        encoder.mov_reg(Gpr::x(4), Gpr::x(12))?;
        encoder.mov_reg(Gpr::x(5), Gpr::x(13))?;
        encoder.mov_const(Gpr::x(17), spec.helper as usize as u64)?;
        encoder.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
        encoder.blr(Gpr::x(17))?;
        encoder.mov_reg(Gpr::x(14), Gpr::x(0))?;
        encoder.ldr_uoff(Gpr::x(20), Gpr::x(21), 8)?;
        encoder.ldr_uoff(Gpr::x(23), Gpr::x(21), 0)?;
        encoder.ldr_uoff(Gpr::w(22), Gpr::x(21), 32)?;
        encoder.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
        for (index, reg) in [25, 26, 27, 28, 15, 16].into_iter().enumerate() {
            encoder.ldr_uoff(Gpr::x(reg), Gpr::x(19), (index as u32) * 8)?;
        }
        Ok(())
    })?;
    // Preserve XREG0: it can remain live as an input across this lookup.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:362-390, OTP-29.1.1.
    assembler.branch_if_zero_register(Gpr::x(14), spec.fail)?;
    assembler.emit_raw(|encoder| raw_store_arg(encoder, spec.destination, Gpr::x(14)))?;
    Ok(())
}

fn emit_extended_put_list(
    assembler: &mut BeamModuleAssembler,
    args: &[SpecificOperand],
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<(), EmitError> {
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:707-722, OTP-29.1.1.
    use arinsal_a64::enc::Gpr;
    validate_extended_x(args)?;
    let head = raw_move_arg(args.first(), beam, env)?;
    let tail = raw_move_arg(args.get(1), beam, env)?;
    let destination = raw_move_arg(args.get(2), beam, env)?;
    assembler.emit_raw(|encoder| {
        raw_load_arg(encoder, head, Gpr::x(8))?;
        raw_load_arg(encoder, tail, Gpr::x(9))?;
        encoder.stp_post(Gpr::x(8), Gpr::x(9), Gpr::x(23), 16)?;
        encoder.sub_imm(Gpr::x(10), Gpr::x(23), 15, false)?;
        raw_store_arg(encoder, destination, Gpr::x(10))
    })?;
    Ok(())
}

fn emit_extended_put_tuple(
    assembler: &mut BeamModuleAssembler,
    args: &[SpecificOperand],
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<(), EmitError> {
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:794-872, OTP-29.1.1.
    use arinsal_a64::enc::Gpr;
    let Some(SpecificOperand::List(elements)) = args.get(1) else {
        return Err(EmitError::Operand(
            "put_tuple2 expects an element list".to_owned(),
        ));
    };
    validate_extended_x(args)?;
    let destination = raw_move_arg(args.first(), beam, env)?;
    let elements = elements
        .iter()
        .map(|element| raw_move_arg(Some(element), beam, env))
        .collect::<Result<Vec<_>, _>>()?;
    let tuple_words = u64::try_from(elements.len())
        .map_err(|_| EmitError::Operand("tuple arity overflow".to_owned()))?;
    let tagged_offset = tuple_words
        .checked_add(1)
        .and_then(|words| words.checked_mul(8))
        .and_then(|bytes| bytes.checked_sub(2))
        .ok_or_else(|| EmitError::Operand("tuple size overflow".to_owned()))?;
    assembler.emit_raw(|encoder| {
        encoder.mov_const(Gpr::x(8), tuple_words << 6)?;
        encoder.str_post(Gpr::x(8), Gpr::x(23), 8)?;
        for element in elements {
            raw_load_arg(encoder, element, Gpr::x(8))?;
            encoder.str_post(Gpr::x(8), Gpr::x(23), 8)?;
        }
        encoder.mov_const(Gpr::x(9), tagged_offset)?;
        encoder.sub_reg(
            Gpr::x(10),
            Gpr::x(23),
            Gpr::x(9),
            arinsal_a64::enc::Shift::Lsl,
            0,
        )?;
        raw_store_arg(encoder, destination, Gpr::x(10))
    })?;
    Ok(())
}

fn emit_extended_get_list(
    assembler: &mut BeamModuleAssembler,
    args: &[SpecificOperand],
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<(), EmitError> {
    use arinsal_a64::enc::Gpr;
    validate_extended_x(args)?;
    let source = raw_move_arg(args.first(), beam, env)?;
    let head = raw_move_arg(args.get(1), beam, env)?;
    let tail = raw_move_arg(args.get(2), beam, env)?;
    let same_destination = args.get(1) == args.get(2);
    assembler.emit_raw(|encoder| {
        raw_load_arg(encoder, source, Gpr::x(8))?;
        encoder.and_imm(Gpr::x(9), Gpr::x(8), !7)?;
        if same_destination {
            encoder.ldr_uoff(Gpr::x(10), Gpr::x(9), 8)?;
            raw_store_arg(encoder, tail, Gpr::x(10))
        } else {
            encoder.ldp(Gpr::x(10), Gpr::x(11), Gpr::x(9), 0)?;
            raw_store_arg(encoder, head, Gpr::x(10))?;
            raw_store_arg(encoder, tail, Gpr::x(11))
        }
    })?;
    Ok(())
}

fn emit_extended_list_field(
    assembler: &mut BeamModuleAssembler,
    args: &[SpecificOperand],
    beam: &BeamFile,
    env: &impl ModuleEnv,
    offset: u32,
) -> Result<(), EmitError> {
    use arinsal_a64::enc::Gpr;
    validate_extended_x(args)?;
    let source = raw_move_arg(args.first(), beam, env)?;
    let destination = raw_move_arg(args.get(1), beam, env)?;
    assembler.emit_raw(|encoder| {
        raw_load_arg(encoder, source, Gpr::x(8))?;
        encoder.and_imm(Gpr::x(9), Gpr::x(8), !7)?;
        encoder.ldr_uoff(Gpr::x(10), Gpr::x(9), offset)?;
        raw_store_arg(encoder, destination, Gpr::x(10))
    })?;
    Ok(())
}

fn number(value: Option<&SpecificOperand>) -> Result<u32, String> {
    as_u32(value).ok_or_else(|| "expected nonnegative integer operand".to_owned())
}

fn count_at_least(args: &[SpecificOperand], minimum: usize, name: &str) -> Result<(), EmitError> {
    if args.len() < minimum {
        Err(EmitError::Operand(format!(
            "{name} expects at least {minimum} operands, got {}",
            args.len()
        )))
    } else {
        Ok(())
    }
}

fn allocation_words(value: Option<&SpecificOperand>) -> Result<u32, String> {
    let Some(SpecificOperand::Allocations(items)) = value else {
        return Err("expected allocation descriptor".to_owned());
    };
    items
        .iter()
        .try_fold(0_u32, |total, (kind, count)| {
            let words = match kind {
                0 | 2 => *count,
                1 => count.saturating_mul(2),
                _ => return None,
            };
            total.checked_add(u32::try_from(words).ok()?)
        })
        .ok_or_else(|| "allocation descriptor size overflow".to_owned())
}

fn count_or_allocation_words(value: Option<&SpecificOperand>) -> Result<u32, String> {
    if matches!(value, Some(SpecificOperand::Allocations(_))) {
        allocation_words(value)
    } else {
        number(value)
    }
}

fn tuple_byte_offset(value: Option<&SpecificOperand>) -> Result<u32, String> {
    // ARM tuple loads use zero-based positions after the tuple header word.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:378-389, OTP-29.1.1.
    number(value)?
        .checked_add(1)
        .ok_or_else(|| "tuple element offset overflow".to_owned())?
        .checked_mul(8)
        .ok_or_else(|| "tuple element offset overflow".to_owned())
}

fn emit_op(
    assembler: &mut BeamModuleAssembler,
    op: &SpecificOp,
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<(), EmitError> {
    let mut remapped_args = op.operands().to_vec();
    let mut guard_spill_bytes = 0_u32;
    if ported(op.name()) == Some(EmitterKind::Guard)
        && is_inline_guard(op.name())
        && has_extended_x(op.operands())
    {
        validate_extended_x(op.operands())?;
        let mut indexes = BTreeSet::new();
        collect_extended_x(op.operands(), &mut indexes);
        let spills = indexes
            .iter()
            .enumerate()
            .map(|(slot, index)| (*index, slot as u32))
            .collect::<BTreeMap<_, _>>();
        let count = u32::try_from(spills.len())
            .map_err(|_| EmitError::Operand("too many spilled X registers".to_owned()))?;
        guard_spill_bytes = count
            .checked_mul(8)
            .ok_or_else(|| EmitError::Operand("guard spill size overflow".to_owned()))?;
        assembler.emit_raw(|encoder| {
            use arinsal_a64::enc::Gpr;
            encoder.sub_imm(Gpr::x(20), Gpr::x(20), guard_spill_bytes as u16, false)?;
            for (index, slot) in &spills {
                encoder.ldr_uoff(Gpr::x(8), Gpr::x(19), index * 8)?;
                encoder.str_uoff(Gpr::x(8), Gpr::x(20), slot * 8)?;
            }
            Ok(())
        })?;
        for operand in &mut remapped_args {
            remap_spilled_x(operand, &spills, count);
        }
    }
    let mut emitter_spills = BTreeMap::new();
    let mut emitter_spill_bytes = 0_u32;
    if uses_emitter_spills(op.name()) && has_extended_x(op.operands()) {
        validate_extended_x(op.operands())?;
        let mut indexes = BTreeSet::new();
        collect_extended_x(op.operands(), &mut indexes);
        emitter_spills = indexes
            .iter()
            .enumerate()
            .map(|(slot, index)| (*index, slot as u32))
            .collect();
        let count = u32::try_from(emitter_spills.len())
            .map_err(|_| EmitError::Operand("too many spilled X registers".to_owned()))?;
        emitter_spill_bytes = count
            .checked_mul(8)
            .ok_or_else(|| EmitError::Operand("emitter spill size overflow".to_owned()))?;
        assembler.emit_raw(|encoder| {
            use arinsal_a64::enc::Gpr;
            encoder.sub_imm(Gpr::x(20), Gpr::x(20), emitter_spill_bytes as u16, false)?;
            for (index, slot) in &emitter_spills {
                encoder.ldr_uoff(Gpr::x(8), Gpr::x(19), index * 8)?;
                encoder.str_uoff(Gpr::x(8), Gpr::x(20), slot * 8)?;
            }
            Ok(())
        })?;
        for operand in &mut remapped_args {
            remap_spilled_x(operand, &emitter_spills, count);
        }
    }
    let args = if guard_spill_bytes == 0 {
        if emitter_spill_bytes == 0 {
            op.operands()
        } else {
            &remapped_args
        }
    } else {
        &remapped_args
    };
    let value = |index| arg(args.get(index), beam, env).map_err(EmitError::Operand);
    let count = |expected| {
        if args.len() == expected {
            Ok(())
        } else {
            Err(EmitError::Operand(format!(
                "{} expects {expected} operands, got {}",
                op.name(),
                args.len()
            )))
        }
    };
    let n = |index| number(args.get(index)).map_err(EmitError::Operand);
    let helper = env.arithmetic_helper();
    if matches!(op.name(), "i_get_map_elements" | "get_map_elements") {
        count_at_least(args, 3, op.name())?;
        let size = usize::try_from(n(2)?)
            .map_err(|_| EmitError::Operand("map element size overflows usize".to_owned()))?;
        if !size.is_multiple_of(3) || args.len() != 3 + size {
            return Err(EmitError::Operand(
                "i_get_map_elements expects key/destination/hash triples".to_owned(),
            ));
        }
        // Port of erts/emulator/beam/jit/arm/instr_map.cpp:391-490, OTP-29.1.1.
        let triples = args[3..]
            .iter()
            .map(|operand| arg(Some(operand), beam, env).map_err(EmitError::Operand))
            .collect::<Result<Vec<_>, _>>()?;
        return assembler
            .emit_i_get_map_elements(n(0)?, value(1)?, &triples, env.map_runtime())
            .map_err(EmitError::from);
    }
    if has_extended_x(args) {
        match op.name() {
            "swap" | "swap2" | "swap3" | "swap4" => {
                validate_extended_x(args)?;
                let pair_count = match op.name() {
                    "swap" => 1,
                    "swap2" => 2,
                    "swap3" => 3,
                    _ => 4,
                };
                count(pair_count + 1)?;
                for index in 0..pair_count {
                    let left = raw_move_arg(args.get(index), beam, env)?;
                    let right = raw_move_arg(args.get(index + 1), beam, env)?;
                    assembler.emit_raw(|encoder| {
                        use arinsal_a64::enc::Gpr;
                        raw_load_arg(encoder, left, Gpr::x(8))?;
                        raw_load_arg(encoder, right, Gpr::x(9))?;
                        raw_store_arg(encoder, left, Gpr::x(9))?;
                        raw_store_arg(encoder, right, Gpr::x(8))
                    })?;
                }
                return Ok(());
            }
            "put_list" => {
                count(3)?;
                return emit_extended_put_list(assembler, args, beam, env);
            }
            "put_tuple2" => {
                count(2)?;
                return emit_extended_put_tuple(assembler, args, beam, env);
            }
            "get_list" => {
                count(3)?;
                return emit_extended_get_list(assembler, args, beam, env);
            }
            "get_hd" => {
                count(2)?;
                return emit_extended_list_field(assembler, args, beam, env, 0);
            }
            "get_tl" => {
                count(2)?;
                return emit_extended_list_field(assembler, args, beam, env, 8);
            }
            "load_tuple_ptr" => {
                count(1)?;
                validate_extended_x(args)?;
                let source = raw_move_arg(args.first(), beam, env)?;
                assembler.emit_raw(|encoder| {
                    use arinsal_a64::enc::Gpr;
                    raw_load_arg(encoder, source, Gpr::x(8))?;
                    encoder.and_imm(Gpr::x(9), Gpr::x(8), !7)?;
                    raw_store_arg(encoder, source, Gpr::x(9))
                })?;
                return Ok(());
            }
            "get_tuple_element" | "i_get_tuple_element" => {
                count(3)?;
                validate_extended_x(args)?;
                let source = raw_move_arg(args.first(), beam, env)?;
                let destination = raw_move_arg(args.get(2), beam, env)?;
                let offset = tuple_byte_offset(args.get(1))?;
                assembler.emit_raw(|encoder| {
                    use arinsal_a64::enc::Gpr;
                    raw_load_arg(encoder, source, Gpr::x(8))?;
                    encoder.and_imm(Gpr::x(9), Gpr::x(8), !7)?;
                    encoder.ldr_uoff(Gpr::x(10), Gpr::x(9), offset)?;
                    raw_store_arg(encoder, destination, Gpr::x(10))
                })?;
                return Ok(());
            }
            "get_two_tuple_elements" => {
                count(4)?;
                validate_extended_x(args)?;
                let source = raw_move_arg(args.first(), beam, env)?;
                let first = raw_move_arg(args.get(2), beam, env)?;
                let second = raw_move_arg(args.get(3), beam, env)?;
                let offset = tuple_byte_offset(args.get(1))?;
                assembler.emit_raw(|encoder| {
                    use arinsal_a64::enc::Gpr;
                    raw_load_arg(encoder, source, Gpr::x(8))?;
                    encoder.and_imm(Gpr::x(9), Gpr::x(8), !7)?;
                    encoder.ldr_uoff(Gpr::x(10), Gpr::x(9), offset)?;
                    encoder.ldr_uoff(Gpr::x(11), Gpr::x(9), offset.saturating_add(8))?;
                    raw_store_arg(encoder, first, Gpr::x(10))?;
                    raw_store_arg(encoder, second, Gpr::x(11))
                })?;
                return Ok(());
            }
            _ => {}
        }
    }
    let result = match ported(op.name()).expect("dispatch only follows capability validation") {
        EmitterKind::Metadata => match op.name() {
            "i_func_label" | "label" => {
                count(1)?;
                assembler.emit_i_func_label(n(0)?)
            }
            "func_prologue" => {
                count(2)?;
                // Port of erts/emulator/beam/jit/arm/ops.tab:905-906, OTP-29.1.1.
                assembler.emit_i_entry_label(n(0)?)
            }
            "aligned_label" => {
                count(2)?;
                assembler.emit_i_entry_label(n(0)?)
            }
            "i_func_info" => {
                count(4)?;
                assembler.emit_i_func_info(n(0)?, n(1)?, n(2)?, n(3)?.min(255) as u8)
            }
            "i_breakpoint_trampoline" => {
                // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:224-237, OTP-29.1.1.
                assembler.emit_i_breakpoint_trampoline(env.breakpoint_helper())
            }
            "i_test_yield" => {
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3097-3115, OTP-29.1.1.
                assembler.test_yield()
            }
            _ => Ok(()),
        },
        EmitterKind::Move => {
            count(2)?;
            emit_extended_move(assembler, args.first(), args.get(1), beam, env)?;
            Ok(())
        }
        EmitterKind::Swap => {
            count(2)?;
            assembler.swap(value(0)?, value(1)?)
        }
        EmitterKind::Swap2 => {
            count(3)?;
            // Port of erts/emulator/beam/jit/arm/ops.tab:408-411, OTP-29.1.1.
            assembler.swap(value(0)?, value(1)?)?;
            assembler.swap(value(1)?, value(2)?)
        }
        EmitterKind::Swap3 | EmitterKind::Swap4 => {
            let swaps = if matches!(ported(op.name()), Some(EmitterKind::Swap3)) {
                3
            } else {
                4
            };
            count(swaps + 1)?;
            for index in 0..swaps {
                assembler.swap(value(index)?, value(index + 1)?)?;
            }
            Ok(())
        }
        EmitterKind::GetTupleElementSwap => {
            count(4)?;
            let offset = tuple_byte_offset(args.get(1))?;
            assembler.emit_get_tuple_element(value(0)?, offset, value(2)?)?;
            assembler.swap(value(2)?, value(3)?)
        }
        EmitterKind::LengthSetup => {
            count(3)?;
            let live = n(1)?;
            emit_extended_move(
                assembler,
                args.get(2),
                Some(&SpecificOperand::X(live)),
                beam,
                env,
            )
        }
        EmitterKind::Length => {
            count(3)?;
            let live = n(1)?;
            if live >= 6 {
                return Err(EmitError::Operand(
                    "length live-register index exceeds native cache".to_owned(),
                ));
            }
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:320-339, OTP-29.1.1.
            let _ = live;
            assembler.emit_bif_length(ArgVal::X(live as u8), value(2)?, env.guard_helper())
        }
        EmitterKind::Allocate => {
            count(2)?;
            assembler.allocate_checked(n(0)?, n(1)?, env.gc_hook())
        }
        EmitterKind::AllocateZero => {
            count(2)?;
            assembler.allocate_zero_checked(n(0)?, n(1)?, env.gc_hook())
        }
        EmitterKind::Deallocate => {
            count(1)?;
            assembler.deallocate(n(0)?)
        }
        EmitterKind::Trim => {
            count(2)?;
            assembler.trim(n(0)?, n(1)?)
        }
        EmitterKind::InitYregs => {
            if args.len() == 2 {
                Ok(assembler.init_yregs(n(0)?, n(1)?)?)
            } else if let [SpecificOperand::List(registers)] = args {
                for register in registers {
                    let SpecificOperand::Y(index) = register else {
                        return Err(EmitError::Operand(
                            "init_yregs list must contain Y registers".to_owned(),
                        ));
                    };
                    assembler.init_yregs(*index, 1)?;
                }
                Ok(())
            } else {
                Err(arinsal_beamasm::module::ModuleError::InvalidOperand(
                    "init_yregs expects two counts or a Y-register list",
                ))
            }
        }
        EmitterKind::Return => {
            count(0)?;
            assembler.return_()
        }
        EmitterKind::DeallocateReturn => {
            count(1)?;
            assembler.deallocate_return(n(0)?)
        }
        EmitterKind::MoveDeallocateReturn => {
            if args.is_empty() {
                assembler.move_deallocate_return(ArgVal::Y(0), ArgVal::X(0), 1)
            } else {
                count(3)?;
                assembler.move_deallocate_return(value(0)?, value(1)?, n(2)?)
            }
        }
        EmitterKind::Call => {
            count(1)?;
            assembler.call(n(0)?)
        }
        EmitterKind::CallLast => {
            count(2)?;
            assembler.call_last(n(0)?, n(1)?)
        }
        EmitterKind::CallOnly => {
            count(1)?;
            assembler.call_only(n(0)?)
        }
        EmitterKind::Plus => {
            count(5)?;
            assembler.emit_i_plus_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Minus => {
            count(5)?;
            assembler.emit_i_minus_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Times => {
            count(5)?;
            assembler.emit_i_times_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::MulAdd => {
            count(6)?;
            // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:542-588, OTP-29.1.1.
            let destination = value(5)?;
            let fail = n(0)?;
            assembler.emit_i_times_with_fail(value(1)?, value(2)?, destination, fail, helper)?;
            if args.get(3) == args.get(5) {
                if matches!(args.get(4), Some(SpecificOperand::Other)) {
                    Ok(())
                } else {
                    assembler.emit_i_plus_with_fail(
                        destination,
                        value(4)?,
                        destination,
                        fail,
                        helper,
                    )
                }
            } else if args.get(4) == args.get(5) {
                assembler.emit_i_plus_with_fail(destination, value(3)?, destination, fail, helper)
            } else {
                Err(arinsal_beamasm::module::ModuleError::InvalidOperand(
                    "i_mul_add destination must alias one addend",
                ))
            }
        }
        EmitterKind::IntDiv => {
            count(5)?;
            assembler.emit_i_int_div_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Rem => {
            count(5)?;
            assembler.emit_i_rem_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Band => {
            count(5)?;
            assembler.emit_i_band_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Bor => {
            count(5)?;
            assembler.emit_i_bor_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Bxor => {
            count(5)?;
            assembler.emit_i_bxor_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Bsl => {
            count(5)?;
            assembler.emit_i_bsl_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Bsr => {
            count(5)?;
            assembler.emit_i_bsr_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Bnot => {
            count(4)?;
            assembler.emit_i_bnot_with_fail(value(2)?, value(3)?, n(0)?, helper)
        }
        EmitterKind::UnaryMinus => {
            count(4)?;
            assembler.emit_i_unary_minus_with_fail(value(2)?, value(3)?, n(0)?, helper)
        }
        EmitterKind::Guard => {
            let fail = n(0)?;
            let source_index = usize::from(op.name().ends_with("_ff")) + 1;
            let source = value(source_index)?;
            if matches!(op.name(), "is_int_in_range" | "is_in_range") {
                count(4)?;
                if fail == 0 {
                    return Err(EmitError::Operand(
                        "range guard requires a failure label".to_owned(),
                    ));
                }
                let helper = env.guard_helper();
                if op.name() == "is_int_in_range" {
                    assembler.emit_is_integer(source, fail)?;
                }
                assembler.emit_is_ge(source, value(2)?, fail, helper)?;
                assembler.emit_is_ge(value(3)?, source, fail, helper)?;
                return Ok(());
            }
            if op.name() == "i_is_tuple_of_arity_ff" {
                count(4)?;
                assembler.emit_is_tuple(source, fail)?;
                assembler.emit_test_arity(source, value(3)?, n(1)?)?;
                return Ok(());
            }
            if op.name() == "i_is_tagged_tuple_ff" {
                count(5)?;
                assembler.emit_is_tuple(source, fail)?;
                assembler.emit_is_tagged_tuple(source, value(3)?, value(4)?, n(1)?)?;
                return Ok(());
            }
            match op.name() {
                "is_integer" => assembler.emit_is_integer(source, fail)?,
                "is_atom" => assembler.emit_is_atom(source, fail)?,
                "is_float" => assembler.emit_is_float(source, fail)?,
                "is_boolean" => assembler.emit_is_boolean(source, fail)?,
                "is_binary" => assembler.emit_is_binary(source, fail)?,
                "is_bitstring" => assembler.emit_is_bitstring(source, fail)?,
                "is_number" => assembler.emit_is_number(source, fail)?,
                "is_pid" => assembler.emit_is_pid(source, fail)?,
                "is_port" => assembler.emit_is_port(source, fail)?,
                "is_reference" => assembler.emit_is_reference(source, fail)?,
                "is_function" => assembler.emit_is_function(source, fail)?,
                "is_function2" => assembler.emit_is_function2_guard(source, value(2)?, fail)?,
                "is_list" => assembler.emit_is_list(source, fail)?,
                "is_nonempty_list" => assembler.emit_is_nonempty_list(source, fail)?,
                "is_nil" => assembler.emit_is_nil(source, fail)?,
                "is_map" => assembler.emit_is_map(source, fail)?,
                "is_tuple" | "i_is_tuple" => assembler.emit_is_tuple(source, fail)?,
                "test_arity" | "i_test_arity" | "i_is_tuple_of_arity" => {
                    assembler.emit_test_arity(source, value(2)?, fail)?;
                }
                "is_tagged_tuple" | "i_is_tagged_tuple" => {
                    assembler.emit_is_tagged_tuple(source, value(2)?, value(3)?, fail)?;
                }
                "is_eq_exact" | "is_ne_exact" | "is_eq" | "is_ne" | "is_lt" | "is_ge"
                | "is_int_ge" => {
                    let lhs = value(1)?;
                    let rhs = value(2)?;
                    match op.name() {
                        "is_eq_exact" => {
                            assembler.emit_is_eq_exact(lhs, rhs, fail, env.guard_helper())?
                        }
                        "is_ne_exact" => {
                            assembler.emit_is_ne_exact(lhs, rhs, fail, env.guard_helper())?
                        }
                        "is_eq" => assembler.emit_is_eq(lhs, rhs, fail, env.guard_helper())?,
                        "is_ne" => assembler.emit_is_ne(lhs, rhs, fail, env.guard_helper())?,
                        "is_lt" => assembler.emit_is_lt(lhs, rhs, fail, env.guard_helper())?,
                        "is_ge" | "is_int_ge" => {
                            assembler.emit_is_ge(lhs, rhs, fail, env.guard_helper())?
                        }
                        _ => return Err(EmitError::Operand(format!("unknown op {}", op.name()))),
                    }
                }
                _ => {
                    return Err(EmitError::Operand(format!(
                        "no guard emitter for {}",
                        op.name()
                    )));
                }
            }
            if guard_spill_bytes != 0 {
                assembler.emit_raw(|encoder| {
                    encoder.add_imm(
                        arinsal_a64::enc::Gpr::x(20),
                        arinsal_a64::enc::Gpr::x(20),
                        guard_spill_bytes as u16,
                        false,
                    )
                })?;
            }
            Ok(())
        }
        EmitterKind::PairedRangeGuard => {
            count(5)?;
            // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2696-2755, OTP-29.1.1.
            let source = value(2)?;
            assembler.emit_is_ge(source, value(3)?, n(0)?, env.guard_helper())?;
            if op.name() == "is_ge_lt" {
                assembler.emit_is_lt(source, value(4)?, n(1)?, env.guard_helper())?;
            } else {
                assembler.emit_is_ge(source, value(4)?, n(1)?, env.guard_helper())?;
            }
            Ok(())
        }
        EmitterKind::MapLookup => {
            // Port of erts/emulator/beam/jit/arm/instr_map.cpp:362-393 and 511-539,
            // OTP-29.1.1. The VM hook performs the map representation-specific lookup.
            let (key_at, hash_at, destination_at, hashed) = if op.name() == "i_get_map_element_hash"
            {
                count(5)?;
                (2, Some(3), 4, true)
            } else {
                count(4)?;
                (2, None, 3, false)
            };
            emit_map_lookup(
                assembler,
                MapLookupSpec {
                    map: raw_move_arg(args.get(1), beam, env)?,
                    key: raw_move_arg(args.get(key_at), beam, env)?,
                    hash: hash_at.map(&n).transpose()?.unwrap_or(0),
                    hashed,
                    destination: raw_move_arg(args.get(destination_at), beam, env)?,
                    fail: n(0)?,
                    helper: env.map_lookup_helper(),
                    stable_map: false,
                },
            )?;
            Ok(())
        }
        EmitterKind::MapElements => unreachable!("map elements were emitted before dispatch"),
        EmitterKind::MapUpdate => {
            let runtime = env.map_runtime();
            if op.name() == "update_map_assoc" {
                count_at_least(args, 4, op.name())?;
                let size = usize::try_from(n(3)?)
                    .map_err(|_| EmitError::Operand("map update size overflow".to_owned()))?;
                if args.len() != 4 + size {
                    return Err(EmitError::Operand("map update size mismatch".to_owned()));
                }
                let updates = args[4..]
                    .iter()
                    .map(|item| arg(Some(item), beam, env).map_err(EmitError::Operand))
                    .collect::<Result<Vec<_>, _>>()?;
                assembler.emit_update_map_assoc(value(0)?, value(1)?, n(2)?, &updates, runtime)
            } else {
                count_at_least(args, 5, op.name())?;
                let size = usize::try_from(n(4)?)
                    .map_err(|_| EmitError::Operand("map update size overflow".to_owned()))?;
                if args.len() != 5 + size {
                    return Err(EmitError::Operand("map update size mismatch".to_owned()));
                }
                let updates = args[5..]
                    .iter()
                    .map(|item| arg(Some(item), beam, env).map_err(EmitError::Operand))
                    .collect::<Result<Vec<_>, _>>()?;
                assembler.emit_update_map_exact(
                    value(0)?,
                    n(1)?,
                    value(2)?,
                    n(3)?,
                    &updates,
                    runtime,
                )
            }
        }
        EmitterKind::MapCreate => {
            count_at_least(args, 4, op.name())?;
            let value_count = usize::try_from(n(2)?)
                .map_err(|_| EmitError::Operand("map literal size overflow".to_owned()))?;
            if args.len() != 4 + value_count {
                return Err(EmitError::Operand("map literal size mismatch".to_owned()));
            }
            let values = args[4..]
                .iter()
                .map(|item| arg(Some(item), beam, env).map_err(EmitError::Operand))
                .collect::<Result<Vec<_>, _>>()?;
            assembler.emit_i_new_small_map_lit(value(0)?, value(3)?, &values)
        }
        EmitterKind::BsConstruct => {
            use arinsal_beamasm::bs_construct::{BsSegment, BsSegmentKind};
            count_at_least(args, 4, op.name())?;
            let tail = &args[4..];
            if !tail.len().is_multiple_of(6) {
                return Err(EmitError::Operand(
                    "binary segments must have six operands".to_owned(),
                ));
            }
            let mut segments = Vec::with_capacity(tail.len() / 6);
            for fields in tail.as_chunks::<6>().0 {
                let name = match fields.first() {
                    Some(SpecificOperand::Atom(index)) => beam.atom(*index),
                    _ => None,
                }
                .ok_or_else(|| {
                    EmitError::Operand("binary segment kind must be an atom".to_owned())
                })?;
                let kind = match name {
                    "integer" => BsSegmentKind::Integer,
                    "binary" => BsSegmentKind::Binary,
                    "float" => BsSegmentKind::Float,
                    "utf8" => BsSegmentKind::Utf8,
                    "append" => BsSegmentKind::Append,
                    "string" => BsSegmentKind::String,
                    "private_append" => BsSegmentKind::PrivateAppend,
                    _ => return Err(EmitError::Operand(format!("unknown binary segment {name}"))),
                };
                segments.push(BsSegment {
                    kind,
                    src: arg(fields.get(4), beam, env).map_err(EmitError::Operand)?,
                    size: arg(fields.get(5), beam, env).map_err(EmitError::Operand)?,
                    unit: number(fields.get(2)).map_err(EmitError::Operand)?,
                    flags: number(fields.get(3)).map_err(EmitError::Operand)?,
                });
            }
            let (helper, error_helper) = env.bs_construct_helpers();
            assembler.emit_i_bs_create_bin(Some(n(0)?), value(3)?, &segments, helper, error_helper)
        }
        EmitterKind::Catch => {
            use arinsal_beamasm::catch::ExceptionResolver;
            let resolver: ExceptionResolver = env.exception_resolver();
            match op.name() {
                "catch" | "try" => {
                    count(2)?;
                    assembler.emit_catch(value(0)?, n(1)?)
                }
                "catch_end" => {
                    count(1)?;
                    assembler.emit_catch_end(value(0)?)
                }
                "try_case" | "try_end" => {
                    count(1)?;
                    assembler.emit_try_case(value(0)?)
                }
                "try_end_deallocate" => {
                    count(2)?;
                    assembler.emit_try_end_deallocate(value(0)?, n(1)?)
                }
                "badmatch" => {
                    count(1)?;
                    assembler.emit_badmatch(value(0)?, resolver)
                }
                "case_end" => {
                    count(1)?;
                    assembler.emit_case_end(value(0)?, resolver)
                }
                "if_end" => {
                    count(0)?;
                    assembler.emit_if_end(resolver)
                }
                "badrecord" => {
                    count(1)?;
                    assembler.emit_badrecord(value(0)?, resolver)
                }
                _ => Err(arinsal_beamasm::module::ModuleError::InvalidOperand(
                    "unknown exception op",
                )),
            }
        }
        EmitterKind::Fun => match op.name() {
            "i_lambda_trampoline" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:167-205, OTP-29.1.1.
                assembler.emit_i_lambda_trampoline(
                    n(0)?,
                    n(1)?,
                    n(2)?.min(u8::MAX as u32) as u8,
                    n(3)?.min(u8::MAX as u32) as u8,
                )
            }
            "i_make_fun3" => {
                count_at_least(args, 4, op.name())?;
                // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:211-251, OTP-29.1.1.
                let environment_values = args[4..]
                    .iter()
                    .map(|item| arg(Some(item), beam, env).map_err(EmitError::Operand))
                    .collect::<Result<Vec<_>, _>>()?;
                if environment_values.len() != n(3)? as usize {
                    return Err(EmitError::Operand(
                        "fun environment size mismatch".to_owned(),
                    ));
                }
                let (entry, entry_arity) = env
                    .lambda_fun_entry(beam, n(0)?)
                    .map_err(EmitError::Operand)?;
                if entry_arity != n(2)?.min(u8::MAX as u32) as u8 {
                    return Err(EmitError::Operand(
                        "lambda table arity differs from make_fun3".to_owned(),
                    ));
                }
                assembler.emit_i_make_fun3_entry(value(1)?, entry, entry_arity, &environment_values)
            }
            "i_call_fun" => {
                count(1)?;
                // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:457-462, OTP-29.1.1.
                let arity = n(0)?.min(u8::MAX as u32) as u8;
                assembler.emit_i_call_fun(arity, env.fun_resolver())
            }
            "i_call_fun_last" => {
                count(2)?;
                // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:464-470, OTP-29.1.1.
                let arity = n(0)?.min(u8::MAX as u32) as u8;
                assembler.emit_i_call_fun_last(arity, n(1)?, env.fun_resolver())
            }
            "i_call_fun2" => {
                count(3)?;
                // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:402-423, OTP-29.1.1.
                let tag = fun_call_tag(args.first(), beam)?;
                let arity = n(1)?.min(u8::MAX as u32) as u8;
                assembler.emit_i_call_fun2(tag, arity, value(2)?, env.fun_resolver())
            }
            "i_call_fun2_last" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:425-455, OTP-29.1.1.
                let tag = fun_call_tag(args.first(), beam)?;
                let arity = n(1)?.min(u8::MAX as u32) as u8;
                assembler.emit_i_call_fun2_last(tag, arity, value(2)?, n(3)?, env.fun_resolver())
            }
            "send" => {
                count(0)?;
                // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:595-610, OTP-29.1.1.
                assembler.emit_send(
                    env.light_bif_fragment(),
                    arinsal_beamasm::dispatch::SEND_DISPATCH_IDENTITY,
                )
            }
            _ => unreachable!(),
        },
        EmitterKind::BifMfa => {
            count(3)?;
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:819-839, OTP-29.1.1.
            let module = raw_move_arg(args.first(), beam, env)?;
            let function = raw_move_arg(args.get(1), beam, env)?;
            let arity = n(2)?;
            let helper = env.bif_mfa_helper();
            assembler.emit_raw(|encoder| {
                use arinsal_a64::enc::Gpr;
                raw_load_arg(encoder, module, Gpr::x(12))?;
                raw_load_arg(encoder, function, Gpr::x(13))?;
                encoder.str_uoff(Gpr::x(20), Gpr::x(21), 8)?;
                encoder.str_uoff(Gpr::x(23), Gpr::x(21), 0)?;
                encoder.str_uoff(Gpr::w(22), Gpr::x(21), 32)?;
                for (index, reg) in [25, 26, 27, 28, 15, 16].into_iter().enumerate() {
                    encoder.str_uoff(Gpr::x(reg), Gpr::x(19), (index as u32) * 8)?;
                }
                encoder.mov_reg(Gpr::x(0), Gpr::x(21))?;
                encoder.mov_reg(Gpr::x(1), Gpr::x(19))?;
                encoder.mov_reg(Gpr::x(2), Gpr::x(12))?;
                encoder.mov_reg(Gpr::x(3), Gpr::x(13))?;
                encoder.mov_const(Gpr::x(4), u64::from(arity))?;
                encoder.mov_const(Gpr::x(17), helper as usize as u64)?;
                encoder.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
                encoder.blr(Gpr::x(17))?;
                encoder.mov_reg(Gpr::x(14), Gpr::x(0))?;
                encoder.ldr_uoff(Gpr::x(20), Gpr::x(21), 8)?;
                encoder.ldr_uoff(Gpr::x(23), Gpr::x(21), 0)?;
                encoder.ldr_uoff(Gpr::w(22), Gpr::x(21), 32)?;
                encoder.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
                for (index, reg) in [25, 26, 27, 28, 15, 16].into_iter().enumerate() {
                    encoder.ldr_uoff(Gpr::x(reg), Gpr::x(19), (index as u32) * 8)?;
                }
                encoder.mov_reg(Gpr::x(25), Gpr::x(14))
            })?;
            assembler.return_()
        }
        EmitterKind::Construct => match op.name() {
            "put_list" => {
                count(3)?;
                assembler.emit_put_list(value(0)?, value(1)?, value(2)?)
            }
            "put_list2" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:775-792, OTP-29.1.1.
                assembler.emit_put_list(value(0)?, value(2)?, value(3)?)?;
                assembler.emit_put_list(value(1)?, value(3)?, value(3)?)
            }
            "put_tuple2" => {
                count(2)?;
                let elements = match args.get(1) {
                    Some(SpecificOperand::List(values)) => values
                        .iter()
                        .map(|item| arg(Some(item), beam, env).map_err(EmitError::Operand))
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => {
                        return Err(EmitError::Operand(
                            "put_tuple2 expects a variable operand list".to_owned(),
                        ));
                    }
                };
                assembler.emit_put_tuple2(value(0)?, &elements)
            }
            "get_list" => {
                count(3)?;
                assembler.emit_get_list(value(0)?, value(1)?, value(2)?)
            }
            "get_hd" => {
                count(2)?;
                assembler.emit_get_hd(value(0)?, value(1)?)
            }
            "get_tl" => {
                count(2)?;
                assembler.emit_get_tl(value(0)?, value(1)?)
            }
            "load_tuple_ptr" => {
                count(1)?;
                assembler.emit_load_tuple_ptr(value(0)?, value(0)?)
            }
            "get_tuple_element" | "i_get_tuple_element" => {
                count(3)?;
                let offset = tuple_byte_offset(args.get(1))?;
                assembler.emit_get_tuple_element(value(0)?, offset, value(2)?)
            }
            "get_two_tuple_elements" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:408-421, OTP-29.1.1.
                let offset = tuple_byte_offset(args.get(1))?;
                assembler.emit_get_tuple_element(value(0)?, offset, value(2)?)?;
                assembler.emit_get_tuple_element(value(0)?, offset.saturating_add(8), value(3)?)
            }
            "set_tuple_element" => {
                count(3)?;
                assembler.emit_set_tuple_element(
                    value(0)?,
                    value(1)?,
                    tuple_byte_offset(args.get(2))?,
                )
            }
            "update_record" => {
                count(5)?;
                let arity = n(1)?;
                let updates = match args.get(4) {
                    Some(SpecificOperand::List(values)) if values.len() % 2 == 0 => values
                        .chunks(2)
                        .map(|pair| Ok((number(pair.first())?, arg(pair.get(1), beam, env)?)))
                        .collect::<Result<Vec<_>, String>>()?,
                    _ => {
                        return Err(EmitError::Operand(
                            "update_record expects index/value pairs".to_owned(),
                        ));
                    }
                };
                assembler.emit_update_record(value(2)?, value(3)?, arity, &updates)
            }
            "update_record_in_place" => {
                if args.len() < 4 || !(args.len() - 4).is_multiple_of(2) {
                    return Err(EmitError::Operand(
                        "update_record_in_place expects index/value pairs".to_owned(),
                    ));
                }
                let arity = n(0)?;
                let updates = args[4..]
                    .chunks(2)
                    .map(|pair| Ok((number(pair.first())?, arg(pair.get(1), beam, env)?)))
                    .collect::<Result<Vec<_>, String>>()?;
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1000-1096, OTP-29.1.1.
                assembler.emit_update_record_in_place(value(1)?, value(2)?, arity, &updates)
            }
            _ => return Err(EmitError::Operand(format!("unknown op {}", op.name()))),
        },
        EmitterKind::Heap => {
            let hook = env.gc_hook();
            match op.name() {
                "test_heap" => {
                    count(2)?;
                    let (words, live) =
                        if matches!(args.first(), Some(SpecificOperand::Allocations(_))) {
                            (allocation_words(args.first())?, number(args.get(1))?)
                        } else {
                            (number(args.first())?, number(args.get(1))?)
                        };
                    assembler.emit_test_heap(words, live, hook)
                }
                "allocate_heap" => {
                    count(3)?;
                    assembler.emit_allocate_heap(
                        count_or_allocation_words(args.first())?,
                        count_or_allocation_words(args.get(1))?,
                        count_or_allocation_words(args.get(2))?,
                        hook,
                    )
                }
                "allocate_heap_zero" => {
                    count(3)?;
                    assembler.emit_allocate_heap_zero(
                        count_or_allocation_words(args.first())?,
                        count_or_allocation_words(args.get(1))?,
                        count_or_allocation_words(args.get(2))?,
                        hook,
                    )
                }
                _ => return Err(EmitError::Operand(format!("unknown op {}", op.name()))),
            }
        }
        EmitterKind::Fused => match op.name() {
            "store_two_values" | "load_two_xregs" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:602-630, OTP-29.1.1.
                emit_extended_move(assembler, args.first(), args.get(1), beam, env)?;
                emit_extended_move(assembler, args.get(2), args.get(3), beam, env)
            }
            "move_trim" => {
                count(3)?;
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:559-600, OTP-29.1.1.
                emit_extended_move(assembler, args.first(), args.get(1), beam, env)?;
                assembler.trim(n(2)?, 0)
            }
            "move_call_last" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/instr_call.cpp:83-115, OTP-29.1.1.
                emit_extended_move(assembler, args.first(), args.get(1), beam, env)?;
                assembler.call_last(n(2)?, n(3)?)
            }
            "put_list_deallocate" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:723-773, OTP-29.1.1.
                assembler.emit_put_list(value(0)?, value(1)?, value(2)?)?;
                assembler.deallocate(n(3)?)
            }
            "move_two_trim" => {
                count(5)?;
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:521-557, OTP-29.1.1.
                emit_extended_move(assembler, args.first(), args.get(1), beam, env)?;
                emit_extended_move(assembler, args.get(2), args.get(3), beam, env)?;
                assembler.trim(n(4)?, 0)
            }
            "move_call_ext_last" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/ops.tab:852 and instr_call.cpp:175-200, OTP-29.1.1.
                emit_extended_move(assembler, args.first(), args.get(1), beam, env)?;
                let import = n(2)?;
                let entry = env.export_entry(beam, import).map_err(EmitError::Operand)?;
                assembler.deallocate(n(3)?)?;
                assembler.dispatch_export(entry, true)
            }
            _ => return Err(EmitError::Operand(format!("unknown op {}", op.name()))),
        },
        EmitterKind::CallExternal => match op.name() {
            "i_call_ext" => {
                count(1)?;
                let import = n(0)?;
                let entry = env.export_entry(beam, import).map_err(EmitError::Operand)?;
                assembler.dispatch_export(entry, false)
            }
            "i_call_ext_only" => {
                count(1)?;
                let import = n(0)?;
                let entry = env.export_entry(beam, import).map_err(EmitError::Operand)?;
                assembler.dispatch_export(entry, true)
            }
            "call_light_bif" => {
                count(2)?;
                let import = n(1)?;
                let entry = env.export_entry(beam, import).map_err(EmitError::Operand)?;
                assembler.dispatch_light_bif(env.light_bif_fragment(), entry)
            }
            "i_call_ext_last" => {
                count(2)?;
                let import = n(0)?;
                let entry = env.export_entry(beam, import).map_err(EmitError::Operand)?;
                assembler.deallocate(n(1)?)?;
                assembler.dispatch_export(entry, true)
            }
            _ => return Err(EmitError::Operand(format!("unknown op {}", op.name()))),
        },
        EmitterKind::GuardBif => {
            let arith_helper = env.arithmetic_helper();
            match op.name() {
                "bif_and" => {
                    count(4)?;
                    return assembler
                        .emit_i_band(value(1)?, value(2)?, value(3)?, arith_helper)
                        .map_err(EmitError::from);
                }
                "bif_or" => {
                    count(4)?;
                    return assembler
                        .emit_i_bor(value(1)?, value(2)?, value(3)?, arith_helper)
                        .map_err(EmitError::from);
                }
                "bif_not" => {
                    count(3)?;
                    return assembler
                        .emit_i_bnot(value(1)?, value(2)?, arith_helper)
                        .map_err(EmitError::from);
                }
                _ => {}
            }
            let runtime = env.guard_helper();
            match op.name() {
                "bif_hd" | "bif_tl" => {
                    count(2)?;
                    if op.name() == "bif_hd" {
                        assembler.emit_bif_hd(value(0)?, value(1)?, runtime)
                    } else {
                        assembler.emit_bif_tl(value(0)?, value(1)?, runtime)
                    }
                }
                "bif_element" => {
                    count(4)?;
                    assembler.emit_bif_element(value(1)?, value(2)?, value(3)?, runtime)
                }
                "bif_node" | "bif_bit_size" | "bif_byte_size" | "bif_tuple_size"
                | "bif_map_size" | "bif_length" | "bif_abs" => {
                    count(3)?;
                    let source = value(1)?;
                    let destination = value(2)?;
                    match op.name() {
                        "bif_node" => assembler.emit_bif_node(source, destination, runtime),
                        "bif_bit_size" => assembler.emit_bif_bit_size(source, destination, runtime),
                        "bif_byte_size" => {
                            assembler.emit_bif_byte_size(source, destination, runtime)
                        }
                        "bif_tuple_size" => {
                            assembler.emit_bif_tuple_size(source, destination, runtime)
                        }
                        "bif_map_size" => assembler.emit_bif_map_size(source, destination, runtime),
                        "bif_length" => assembler.emit_bif_length(source, destination, runtime),
                        _ => assembler.emit_bif_abs(source, destination, runtime),
                    }
                }
                "bif_map_get" | "bif_is_map_key" => {
                    let (key_at, map_at, dest_at) = if op.name() == "bif_map_get" {
                        count(4)?;
                        (1, 2, 3)
                    } else {
                        count(5)?;
                        (2, 3, 4)
                    };
                    if op.name() == "bif_map_get" {
                        assembler.emit_bif_map_get(
                            value(key_at)?,
                            value(map_at)?,
                            value(dest_at)?,
                            runtime,
                        )
                    } else {
                        assembler.emit_bif_is_map_key(
                            value(key_at)?,
                            value(map_at)?,
                            value(dest_at)?,
                            runtime,
                        )
                    }
                }
                "bif_max" | "bif_min" => {
                    count(3)?;
                    if op.name() == "bif_max" {
                        assembler.emit_bif_max(value(0)?, value(1)?, value(2)?, runtime)
                    } else {
                        assembler.emit_bif_min(value(0)?, value(1)?, value(2)?, runtime)
                    }
                }
                "bif_self" | "self" => {
                    count(1)?;
                    assembler.emit_bif_self(value(0)?, runtime)
                }
                _ => return Err(EmitError::Operand(format!("unknown op {}", op.name()))),
            }
            .map_err(EmitError::from)?;
            Ok(())
        }
        EmitterKind::SelectVal | EmitterKind::SelectTupleArity => {
            count_at_least(args, 3, op.name())?;
            let size = usize::try_from(n(2)?)
                .map_err(|_| EmitError::Operand("select size overflows usize".to_owned()))?;
            if !size.is_multiple_of(2) || args.len() != 3 + size {
                return Err(EmitError::Operand(format!(
                    "{} size does not match its value and label pairs",
                    op.name()
                )));
            }
            let is_tuple_arity = matches!(ported(op.name()), Some(EmitterKind::SelectTupleArity));
            let payload = args[3..]
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    if is_tuple_arity && i % 2 == 0 {
                        match item {
                            SpecificOperand::SmallInt(val) => Ok(ArgVal::Immediate(*val as u64)),
                            SpecificOperand::Unsigned(val) => Ok(ArgVal::Immediate(*val)),
                            _ => arg(Some(item), beam, env).map_err(EmitError::Operand),
                        }
                    } else {
                        arg(Some(item), beam, env).map_err(EmitError::Operand)
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut pairs = payload
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| pair[0])
                .chain(payload.as_chunks::<2>().0.iter().map(|pair| pair[1]))
                .collect::<Vec<_>>();
            if matches!(ported(op.name()), Some(EmitterKind::SelectVal)) {
                if op.name() == "i_select_val_lins" {
                    assembler.emit_i_select_val_lins(value(0)?, value(1)?, size, &pairs)
                } else {
                    // Port of erts/emulator/beam/jit/arm/instr_select.cpp:107-190,
                    // OTP-29.1.1. Atom words are process-local here, so order
                    // the pairs by the words the emitted comparison sees.
                    let count = pairs.len() / 2;
                    let mut order = (0..count).collect::<Vec<_>>();
                    order.sort_by_key(|&index| match pairs[index] {
                        ArgVal::Immediate(value) | ArgVal::Literal(value) => value,
                        _ => 0,
                    });
                    let values = order.iter().map(|&index| pairs[index]).collect::<Vec<_>>();
                    let labels = order
                        .iter()
                        .map(|&index| pairs[index + count])
                        .collect::<Vec<_>>();
                    pairs = values.into_iter().chain(labels).collect();
                    assembler.emit_i_select_val_bins(value(0)?, value(1)?, size, &pairs)
                }
            } else {
                assembler.emit_i_select_tuple_arity(value(0)?, value(1)?, size, &pairs)
            }
        }
        EmitterKind::SelectVal2 | EmitterKind::SelectTupleArity2 => {
            count(6)?;
            let src = value(0)?;
            let fail = value(1)?;
            let is_tuple_arity = matches!(ported(op.name()), Some(EmitterKind::SelectTupleArity2));
            let first = if is_tuple_arity {
                match args.get(2) {
                    Some(SpecificOperand::SmallInt(val)) => ArgVal::Immediate(*val as u64),
                    Some(SpecificOperand::Unsigned(val)) => ArgVal::Immediate(*val),
                    _ => value(2)?,
                }
            } else {
                value(2)?
            };
            let first_label = value(3)?;
            let second = if is_tuple_arity {
                match args.get(4) {
                    Some(SpecificOperand::SmallInt(val)) => ArgVal::Immediate(*val as u64),
                    Some(SpecificOperand::Unsigned(val)) => ArgVal::Immediate(*val),
                    _ => value(4)?,
                }
            } else {
                value(4)?
            };
            let second_label = value(5)?;
            if matches!(ported(op.name()), Some(EmitterKind::SelectVal2)) {
                assembler.emit_i_select_val2(src, fail, first, first_label, second, second_label)
            } else {
                assembler.emit_i_select_tuple_arity2(
                    src,
                    fail,
                    first,
                    first_label,
                    second,
                    second_label,
                )
            }
        }
        EmitterKind::JumpOnVal | EmitterKind::JumpOnValZero => {
            let (base, size_at, target_at) = if op.name() == "i_jump_on_val" {
                count_at_least(args, 5, op.name())?;
                (
                    n(2)? as u64,
                    usize::try_from(n(3)?).map_err(|_| {
                        EmitError::Operand("jump table size overflows usize".to_owned())
                    })?,
                    4,
                )
            } else {
                count_at_least(args, 3, op.name())?;
                (
                    0,
                    usize::try_from(n(2)?).map_err(|_| {
                        EmitError::Operand("jump table size overflows usize".to_owned())
                    })?,
                    3,
                )
            };
            if args.len() != target_at + size_at {
                return Err(EmitError::Operand(
                    "jump table size does not match destinations".to_owned(),
                ));
            }
            let targets = args[target_at..]
                .iter()
                .map(|item| arg(Some(item), beam, env).map_err(EmitError::Operand))
                .collect::<Result<Vec<_>, _>>()?;
            if op.name() == "i_jump_on_val" {
                assembler.emit_i_jump_on_val(value(0)?, value(1)?, base, size_at, &targets)
            } else {
                assembler.emit_i_jump_on_val_zero(value(0)?, value(1)?, size_at, &targets)
            }
        }
        EmitterKind::Jump => {
            count(1)?;
            // Port of erts/emulator/beam/jit/arm/instr_common.cpp:1127-1129, OTP-29.1.1.
            assembler.jump(n(0)?)
        }
        EmitterKind::BsMatch => {
            let helper = env.bs_match_helper();
            match op.name() {
                "i_bs_start_match3" => {
                    count(4)?;
                    assembler.emit_i_bs_start_match3(
                        value(0)?,
                        n(1)?,
                        n(2)?,
                        value(3)?,
                        helper,
                        env.gc_hook(),
                    )
                }
                "i_bs_match_test_heap" => {
                    count_at_least(args, 4, op.name())?;
                    assembler.emit_i_bs_match_test_heap(value(1)?, n(2)?, n(3)?, n(0)?, helper)
                }
                "i_bs_match" => {
                    count_at_least(args, 2, op.name())?;
                    let ctx = value(1)?;
                    let fail = n(0)?;
                    let mut at = 2;
                    while at < args.len() {
                        let Some(SpecificOperand::Atom(index)) = args.get(at) else {
                            return Err(EmitError::Operand(
                                "bitstring match expects command atoms".to_owned(),
                            ));
                        };
                        let Some(name) = index
                            .checked_sub(1)
                            .and_then(|index| beam.atoms.get(index as usize))
                            .map(String::as_str)
                        else {
                            return Err(EmitError::Operand(
                                "bitstring match command atom is out of range".to_owned(),
                            ));
                        };
                        match name {
                            "ensure_exactly" => {
                                let bits = number(args.get(at + 1))?;
                                assembler.emit_bs_match_ensure_exactly(ctx, bits, fail)?;
                                at += 2;
                            }
                            "ensure_at_least" => {
                                let bits = number(args.get(at + 1))?;
                                let unit = number(args.get(at + 2))?;
                                assembler.emit_bs_match_ensure_at_least(ctx, bits, unit, fail)?;
                                at += 3;
                            }
                            "skip" => {
                                let bits = number(args.get(at + 1))?;
                                assembler.emit_bs_match_skip(ctx, bits)?;
                                at += 2;
                            }
                            other => {
                                return Err(EmitError::Operand(format!(
                                    "unsupported bitstring match command {other}"
                                )));
                            }
                        }
                    }
                    Ok(())
                }
                "i_bs_get_position" => {
                    count(2)?;
                    assembler.emit_i_bs_get_position(value(0)?, value(1)?, helper)
                }
                "bs_set_position" => {
                    count(2)?;
                    assembler.emit_i_bs_set_position(value(0)?, value(1)?, helper)
                }
                "bs_get_tail" => {
                    count(3)?;
                    assembler.emit_bs_get_tail(value(0)?, value(1)?, n(2)?, helper)
                }
                "i_bs_get_binary2" => {
                    count(6)?;
                    assembler.emit_i_bs_get_binary2(
                        value(0)?,
                        n(1)?,
                        value(3)?,
                        n(4)?,
                        value(5)?,
                        helper,
                    )
                }
                _ => Err(arinsal_beamasm::module::ModuleError::InvalidOperand(
                    "unknown bit syntax match op",
                )),
            }
        }
    };
    if emitter_spill_bytes != 0 && result.is_ok() {
        assembler.emit_raw(|encoder| {
            use arinsal_a64::enc::Gpr;
            for (index, slot) in &emitter_spills {
                encoder.ldr_uoff(Gpr::x(8), Gpr::x(20), slot * 8)?;
                encoder.str_uoff(Gpr::x(8), Gpr::x(19), index * 8)?;
            }
            encoder.add_imm(Gpr::x(20), Gpr::x(20), emitter_spill_bytes as u16, false)
        })?;
    }
    result.map_err(|error| EmitError::Assembler(format!("{error:?}")))
}

fn ported(name: &str) -> Option<EmitterKind> {
    PORTED_OPS
        .iter()
        .find(|op| op.name == name)
        .map(|op| op.emitter)
}

/// Error returned for invalid input files or module-wide emission failures.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// BEAM parser error.
    #[error("BEAM parse failed: {0}")]
    Parse(String),
    /// Module assembler failed while finalizing code.
    #[error("module assembly failed: {0}")]
    Assemble(String),
    /// Coverage traversal or file loading failed.
    #[error("I/O at {0}: {1}")]
    Io(String, String),
}

#[derive(Debug)]
enum EmitError {
    Operand(String),
    Assembler(String),
}
impl From<String> for EmitError {
    fn from(error: String) -> Self {
        Self::Operand(error)
    }
}
impl From<arinsal_beamasm::module::ModuleError> for EmitError {
    fn from(error: arinsal_beamasm::module::ModuleError) -> Self {
        Self::Assembler(format!("{error:?}"))
    }
}
impl std::fmt::Display for EmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operand(value) | Self::Assembler(value) => f.write_str(value),
        }
    }
}
/// Calls a compiled function through the safe BeamAsm process bridge.
pub fn enter_native(
    module: &CompiledModule,
    function: &CompiledFunction,
    header: &mut arinsal_beamasm::ProcessHeader,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
) -> arinsal_beamasm::ExitReason {
    let entry = module
        .entry(function)
        .expect("compiled function label must exist in its owning module");
    arinsal_beamasm::enter_native(header, registers, &entry)
}

/// Operation-to-emitter lookup used by coverage consumers.
pub fn emitter_for(name: &str) -> bool {
    ported(name).is_some()
}

#[cfg(test)]
mod function_allowlist_tests {
    use super::function_allowlist_contains;

    #[test]
    fn matches_exact_name_and_arity_entries() {
        assert!(function_allowlist_contains(
            "with/2,fix_file_opts/1",
            "with",
            2
        ));
        assert!(!function_allowlist_contains("with/2", "with", 1));
        assert!(!function_allowlist_contains("with/2", "with_1", 2));
        assert!(!function_allowlist_contains("broken,with/nope", "with", 2));
    }
}

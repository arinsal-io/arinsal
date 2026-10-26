#![forbid(unsafe_code)]
//! Function-level compiler from OTP 29 BEAM operations to the BeamAsm emitter.

use arinsal_beam::{self as beam, BeamFile};
use arinsal_beamasm::{
    NativeEntry, ProcessHeader, SchedulerRegisters,
    arith::ArithHelper,
    construct::GcHook,
    fun::FunCallTag,
    guard::{CompareShared, EqLiteral, GuardHelper, GuardHelper3},
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
    types::{ArgType, TypedArg},
};
use arinsal_beamops::{
    self as beamops, LiteralElement, NewLiteral, OpSink, SpecificOp, SpecificOperand,
    TransformArena, erts_tables,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

thread_local! {
    static COMPILE_ARENA: RefCell<TransformArena> = RefCell::new(TransformArena::new());
}

mod eq_literal;
use eq_literal::classify_eq_literal;

/// Runtime values and helper entry points needed while compiling a module.
pub trait ModuleEnv {
    /// Resolve a global atom index to an OTP tagged atom word.
    fn atom(&self, beam: &BeamFile, index: u32) -> Result<u64, String>;
    /// Resolve a zero-based literal index to an OTP tagged term word.
    fn literal(&self, beam: &BeamFile, index: u32) -> Result<u64, String>;
    /// Register the word of the literal at `index`, one that the load added after the literals
    /// of the file (`beamfile_add_literal`); `literal` then resolves it.
    fn add_literal(&self, _index: u32, _word: u64) -> Result<(), String> {
        Err("module environment cannot hold literals added by the load".into())
    }
    /// Resolve an import table index to a code/export value.
    fn import(&self, beam: &BeamFile, index: u32) -> Result<u32, String>;
    /// Return the stable VM-owned dispatch slot for an external import.
    fn export_entry(&self, _beam: &BeamFile, _index: u32) -> Result<usize, String> {
        Err("module environment has no external dispatch slots".into())
    }
    /// Build a bignum literal for an integer outside the small range.
    fn integer_literal(&self, _value: i64) -> Result<u64, String> {
        Err("module environment cannot build integer literals".into())
    }
    /// The fun of the lambda at `lambda` in the lambda table when it has no free variables
    /// (`erts_fun_entry_put` of the module's fun entry); created with the module.
    fn zero_capture_fun(&self, _beam: &BeamFile, _lambda: u32) -> Result<u64, String> {
        Err("module environment has no fun entries".into())
    }
    /// Build a bignum literal from decimal text (integers outside `i64`).
    fn bigint_literal(&self, _decimal: &str) -> Result<u64, String> {
        Err("module environment cannot build bignum literals".into())
    }
    /// Return the retained storage address for a function coverage probe.
    fn function_coverage_probe(&self, _function: &str, _arity: u8) -> Option<CoverageProbe> {
        None
    }
    /// Return the retained storage address for an executable-line coverage probe.
    fn line_coverage_probe(&self, _location: u32, _cover_id: u32) -> Option<CoverageProbe> {
        None
    }
    /// Build a tuple literal (for example the key tuple of a small map literal) from tagged
    /// element words and return its tagged word.
    fn tuple_literal(&self, _elements: &[u64]) -> Result<u64, String> {
        Err("module environment cannot build tuple literals".into())
    }
    /// Order literal map keys (tagged words) as flatmap keys, returning the permutation.
    fn sort_map_keys(&self, _keys: &[u64]) -> Result<Vec<usize>, String> {
        Err("module environment cannot order map keys".into())
    }
    /// Hash a literal map key while compiling its lookup triplet.
    // Port of erts/emulator/beam/beam_transform_helpers.c:54-110, OTP-29.1.1.
    fn map_key_hash(&self, key: ArgVal) -> u64 {
        arinsal_beamasm::map::literal_key_hash(key)
    }
    /// Return the retained `FunEntry` pointer for a lambda-table index.
    fn lambda_fun_entry(&self, _beam: &BeamFile, index: u32) -> Result<(usize, u8), String> {
        Err(format!("module environment has no lambda entry {index}"))
    }
    /// Return the runtime hook that restores the exception class for `raise/2`.
    fn raise_class_helper(&self) -> usize {
        0
    }
    /// Return the performance counter function native `os:perf_counter/0` calls
    /// (`erts_sys_perf_counter`).
    fn sys_perf_counter(&self) -> usize {
        0
    }
    /// Return the address of the word holding the local node name atom
    /// (`erts_this_node->sysname`).
    fn this_node_sysname(&self) -> usize {
        0
    }
    /// Return the runtime hook that materializes an Erlang stacktrace.
    fn build_stacktrace_helper(&self) -> Option<arinsal_beamasm::catch::BuildStacktraceHook> {
        None
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
    /// Return the light-BIF fragment for exports the helper dispatches (no BIF pointer).
    fn light_bif_helper_fragment(&self) -> usize {
        self.light_bif_fragment()
    }
    /// The BIF the export entry at `entry` publishes for `call_light_bif_shared`, or zero when
    /// the helper dispatches it.
    fn light_bif_func(&self, _entry: usize) -> usize {
        0
    }
    /// Fragment for `i_breakpoint_trampoline`.
    ///
    /// erts does not route it through `call_light_bif_shared`; the trampoline calls
    /// `erts_generic_breakpoint` with its own arguments.
    fn breakpoint_fragment(&self) -> usize {
        self.light_bif_fragment()
    }
    /// Process-wide `(dispatch_return, i_test_yield_shared, context_switch_simplified)`
    /// fragments, or `None` when the environment has none (each module then keeps its own).
    fn yield_fragments(&self) -> Option<(usize, usize, usize)> {
        None
    }
    /// Process-wide `(raise_shared, raise_exception)` fragments, or `None` when the
    /// environment has none (each `raise` then carries the exception transfer inline).
    fn raise_fragments(&self) -> Option<(usize, usize)> {
        None
    }
    /// Process-wide `(handle_map_get_badmap, handle_map_get_badkey, handle_map_size_error)`
    /// fragments, or `None` when the environment has none (each failing `map_get/2` and
    /// `map_size/1` then carries its error path inline).
    fn map_error_fragments(&self) -> Option<(usize, usize, usize)> {
        None
    }
    /// Fragment called by `i_line_breakpoint_trampoline` when line instrumentation is enabled.
    fn line_breakpoint_fragment(&self) -> usize {
        0
    }
    /// Return the two-register shared fragment used by `send/2`.
    fn send_fragment(&self) -> usize {
        self.light_bif_fragment()
    }
    /// Resolve a loader-patched NIF body to its native runtime trampoline.
    fn native_body(&self, _name: &str, _arity: u8) -> Option<(usize, usize)> {
        None
    }
    /// Reserve the call-NIF body of a function that a later `load_nif` may replace.
    fn dynamic_nif_body(&self, _name: &str, _arity: u8) -> Option<(usize, usize)> {
        None
    }
    /// Runtime helper that reads the process dictionary with exact key equality.
    fn process_dictionary_get_helper(&self) -> usize {
        0
    }
    /// Arithmetic slow path used for bignums and exceptional operands.
    fn arithmetic_helper(&self) -> ArithHelper;
    /// Guard slow path used for term comparisons and guard BIFs.
    fn guard_helper(&self) -> GuardHelper;
    /// Process-wide comparison fragments. The default is unset; the VM installs the real ones.
    fn compare_shared(&self) -> CompareShared {
        CompareShared::default()
    }
    /// Resolves an atom name to its VM term word, or `None` when the VM has no such atom.
    fn atom_word_by_name(&self, _name: &str) -> Option<u64> {
        None
    }
    /// Classifies a literal compared with `=:=` / `=/=`. The owned literal is decoded from the
    /// module's literal table; the default treats every literal as `Generic`-decidable.
    fn eq_literal(&self, beam: &BeamFile, index: u32) -> Result<EqLiteral, String> {
        let term = beam.literal(index).map_err(|error| error.to_string())?;
        Ok(classify_eq_literal(&term, &|name| {
            self.atom_word_by_name(name)
        }))
    }
    /// Guard slow path for checks that compare a tuple tag as well as its arity.
    fn guard_helper3(&self) -> GuardHelper3;
    /// Heap slow path used by allocating native operations.
    fn gc_hook(&self) -> GcHook;
    /// Map lookup slow path. It returns zero when the key is absent.
    fn map_lookup_helper(&self) -> MapLookupHelper;
    /// Dispatches an OTP BIF function body using the current X registers.
    fn bif_mfa_helper(&self) -> BifMfaHelper;
    /// Return a dispatch slot that calls the BIF itself (never its module's stub body) through
    /// the export trampoline, for `call_bif_mfa`.
    fn bif_mfa_entry(&self, _module: &str, _function: &str, _arity: u8) -> Result<usize, String> {
        Err("module environment has no BIF dispatch slots".into())
    }
    /// Executes a bit syntax matching slow path.
    fn bs_match_helper(&self) -> arinsal_beamasm::bs_match::BsMatchHelper;
    /// Runtime callbacks for map creation and updates.
    fn map_runtime(&self) -> arinsal_beamasm::map::MapRuntime;
    /// Runtime callbacks of the native record instructions.
    fn record_runtime(&self) -> arinsal_beamasm::records::RecordRuntime {
        arinsal_beamasm::records::RecordRuntime {
            get_field: unused_record_field,
            get_local_field: unused_record_field,
            create_local: unused_record_create,
            create: unused_record_create,
            get_elements: unused_record_elements,
            update: unused_record_create,
        }
    }
    /// Runtime hook calling a plain BIF by export identity.
    fn bif_identity_helper(&self) -> arinsal_beamasm::bif::BifIdentityHelper {
        unused_bif_identity as *const () as usize
    }
    /// Export identity of an import that is a plain (pure or heap-allocating) BIF, if it is one.
    fn plain_bif_identity(&self, _beam: &BeamFile, _index: u32) -> Option<usize> {
        None
    }
    /// Runtime hook for the field-decoding `bs_match` commands.
    fn bs_match_cmd_helper(&self) -> arinsal_beamasm::bs_match::BsMatchCmdHelper {
        unused_bs_match_cmd
    }
    /// Runtime hook that builds the binary of `bs_create_bin` from staged segments.
    fn bs_create_bin_helper(&self) -> arinsal_beamasm::bs_construct::BsCreateBinHelper;
    /// Register a string-table constant for `i_bs_match_string` and return its handle.
    fn match_string(&self, _bytes: &[u8]) -> Result<u64, String> {
        Err("module environment cannot register match strings".into())
    }
    /// Build a binary literal from bytes and return its tagged word.
    fn binary_literal(&self, _bytes: &[u8]) -> Result<u64, String> {
        Err("module environment cannot build binary literals".into())
    }
    /// Resolves native exception records and returns zero for scheduler dispatch.
    fn exception_resolver(&self) -> arinsal_beamasm::catch::ExceptionResolver;
    /// Runtime callbacks of the receive instructions.
    fn receive_hooks(&self) -> arinsal_beamasm::receive::ReceiveHooks {
        arinsal_beamasm::receive::ReceiveHooks {
            recv_marker_reserve: unused_recv_reserve,
            recv_marker_bind: unused_recv_bind,
            recv_marker_clear: unused_recv_one,
            recv_marker_use: unused_recv_one,
            loop_rec_shared: 0,
            remove_message: unused_remove_message,
            set_save_next: unused_recv_header,
            wait_unlocked_shared: 0,
            wait_locked_shared: 0,
            take_receive_lock: unused_recv_header,
            wait_timeout: unused_wait_timeout,
            timeout_locked: unused_recv_header,
            timeout: unused_recv_header,
        }
    }
    /// Runtime hook creating the writable binary of `bs_init_writable`.
    fn bs_init_writable_helper(&self) -> arinsal_beamasm::bs_construct::BsInitWritableHelper {
        unused_bs_init_writable
    }
    /// Runtime hook converting a bignum to IEEE-754 bits for `fconv`.
    fn big_to_float_helper(&self) -> arinsal_beamasm::float::BigToFloat {
        unused_big_to_float
    }
    /// Runtime hook pairing an error reason with its stacktrace for `catch_end`.
    fn add_stacktrace_helper(&self) -> arinsal_beamasm::catch::AddStacktraceHook {
        unused_add_stacktrace
    }
    /// Runtime entry points for `apply`, `apply/2` and `apply/3`.
    fn apply_runtime(&self) -> arinsal_beamasm::misc::ApplyRuntime {
        arinsal_beamasm::misc::ApplyRuntime {
            resolver: unused_apply_resolver,
            apply3_resolver: unused_apply3_resolver,
            apply_fun_shared: 0,
            fun_resolver: unused_fun_resolver,
            apply2_fragment: 0,
            apply3_fragment: 0,
        }
    }
    /// Resolves a fun term to a native entry for `i_call_fun` / `i_call_fun2`.
    fn fun_resolver(&self) -> arinsal_beamasm::fun::FunResolver {
        unused_fun_resolver
    }
}

/// Native coverage storage selected by the loaded module's OTP coverage mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageProbe {
    /// Stable address of the byte flag or machine-word counter.
    pub address: usize,
    /// Byte flags are set to a nonzero value; counters are atomically incremented.
    pub flags: bool,
}

extern "C" fn unused_add_stacktrace(
    _process: *mut ProcessHeader,
    _reason: u64,
    _trace: u64,
) -> u64 {
    0
}

extern "C" fn unused_recv_reserve(_process: *mut ProcessHeader) -> u64 {
    0
}

extern "C" fn unused_recv_bind(_process: *mut ProcessHeader, _marker: u64, _reference: u64) {}

extern "C" fn unused_recv_one(_process: *mut ProcessHeader, _reference: u64) {}

extern "C" fn unused_remove_message(
    _process: *mut ProcessHeader,
    fcalls: i32,
    _unused: usize,
) -> i32 {
    fcalls
}

extern "C" fn unused_recv_header(_process: *mut ProcessHeader) {}

extern "C" fn unused_wait_timeout(
    _process: *mut ProcessHeader,
    _timeout: u64,
    _next: usize,
) -> i32 {
    0
}

extern "C" fn unused_bif_identity(
    _p: *mut ProcessHeader,
    _i: u64,
    _a: u64,
    _b: u64,
    _c: u64,
) -> u64 {
    0
}

extern "C" fn unused_record_field(
    _p: *mut ProcessHeader,
    _s: u64,
    _i: u64,
    _f: u64,
    _r: u64,
) -> u64 {
    0
}

extern "C" fn unused_record_create(
    _p: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    _id: u64,
    _live: u64,
    _count: u64,
    _base: u64,
) -> u64 {
    0
}

extern "C" fn unused_record_elements(
    _p: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    _src: u64,
    _count: u64,
    _base: u64,
) -> u64 {
    0
}

extern "C" fn unused_bs_match_cmd(_process: *mut ProcessHeader, _kind: u64, _live: u64) -> u64 {
    0
}

extern "C" fn unused_bs_init_writable(_process: *mut ProcessHeader, _size: u64) -> u64 {
    0
}

extern "C" fn unused_big_to_float(_process: *mut ProcessHeader, _term: u64) -> u64 {
    0
}

extern "C" fn unused_apply_resolver(_process: *mut ProcessHeader, _arity: u32) -> usize {
    0
}

extern "C" fn unused_apply3_resolver(_process: *mut ProcessHeader) -> usize {
    0
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
    ProcessDictionaryGet,
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
    Apply,
    Float,
    Receive,
    Bif,
    Records,
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
        name: "executable_line",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "on_load",
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
        name: "nif_start",
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
        name: "i_nif_padding",
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
        name: "i_debug_line",
        emitter: EmitterKind::Metadata,
    },
    PortedOp {
        name: "i_line_breakpoint_trampoline",
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
        name: "get",
        emitter: EmitterKind::ProcessDictionaryGet,
    },
    PortedOp {
        name: "i_get",
        emitter: EmitterKind::ProcessDictionaryGet,
    },
    PortedOp {
        name: "i_get_hash",
        emitter: EmitterKind::ProcessDictionaryGet,
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
        name: "i_yield",
        emitter: EmitterKind::CallExternal,
    },
    PortedOp {
        name: "i_hibernate",
        emitter: EmitterKind::CallExternal,
    },
    PortedOp {
        name: "i_perf_counter",
        emitter: EmitterKind::CallExternal,
    },
    PortedOp {
        name: "i_load_nif",
        emitter: EmitterKind::CallExternal,
    },
    PortedOp {
        name: "i_call_on_load_function",
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
        name: "is_any_native_record",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_native_record",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "is_record_accessible",
        emitter: EmitterKind::Guard,
    },
    PortedOp {
        name: "get_record_field",
        emitter: EmitterKind::Records,
    },
    PortedOp {
        name: "i_get_record_elements",
        emitter: EmitterKind::Records,
    },
    PortedOp {
        name: "i_create_local_native_record",
        emitter: EmitterKind::Records,
    },
    PortedOp {
        name: "i_create_native_record",
        emitter: EmitterKind::Records,
    },
    PortedOp {
        name: "i_update_native_record",
        emitter: EmitterKind::Records,
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
        name: "new_map",
        emitter: EmitterKind::MapCreate,
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
        name: "bs_get_integer2",
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
        name: "i_bs_get_bin_and_tail",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_get_utf8",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_get_utf16",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_get_float2",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "get_float2",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_skip_utf8",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_skip_utf16",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_validate_unicode_retract",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_match_string",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_skip_bits2",
        emitter: EmitterKind::BsMatch,
    },
    PortedOp {
        name: "i_bs_create_bin",
        emitter: EmitterKind::BsConstruct,
    },
    PortedOp {
        name: "i_rem_div",
        emitter: EmitterKind::Rem,
    },
    PortedOp {
        name: "i_div_rem",
        emitter: EmitterKind::Rem,
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
        name: "bs_init_writable",
        emitter: EmitterKind::BsConstruct,
    },
    PortedOp {
        name: "try_end_move_deallocate",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "try_case_end",
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
        name: "raise",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "raw_raise",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "node",
        emitter: EmitterKind::Catch,
    },
    PortedOp {
        name: "build_stacktrace",
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
        name: "apply",
        emitter: EmitterKind::Apply,
    },
    PortedOp {
        name: "i_bif1",
        emitter: EmitterKind::Bif,
    },
    PortedOp {
        name: "i_bif2",
        emitter: EmitterKind::Bif,
    },
    PortedOp {
        name: "i_bif3",
        emitter: EmitterKind::Bif,
    },
    PortedOp {
        name: "nofail_bif1",
        emitter: EmitterKind::Bif,
    },
    PortedOp {
        name: "nofail_bif2",
        emitter: EmitterKind::Bif,
    },
    PortedOp {
        name: "recv_marker_reserve",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "recv_marker_bind",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "recv_marker_clear",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "recv_marker_use",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "i_loop_rec",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "remove_message",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "loop_rec_end",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "wait_unlocked",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "wait_locked",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "wait_timeout_unlocked",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "wait_timeout_locked",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "timeout",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "timeout_locked",
        emitter: EmitterKind::Receive,
    },
    PortedOp {
        name: "fload",
        emitter: EmitterKind::Float,
    },
    PortedOp {
        name: "fstore",
        emitter: EmitterKind::Float,
    },
    PortedOp {
        name: "fconv",
        emitter: EmitterKind::Float,
    },
    PortedOp {
        name: "i_fadd",
        emitter: EmitterKind::Float,
    },
    PortedOp {
        name: "i_fsub",
        emitter: EmitterKind::Float,
    },
    PortedOp {
        name: "i_fmul",
        emitter: EmitterKind::Float,
    },
    PortedOp {
        name: "i_fdiv",
        emitter: EmitterKind::Float,
    },
    PortedOp {
        name: "i_fnegate",
        emitter: EmitterKind::Float,
    },
    PortedOp {
        name: "apply_last",
        emitter: EmitterKind::Apply,
    },
    PortedOp {
        name: "i_apply",
        emitter: EmitterKind::Apply,
    },
    PortedOp {
        name: "i_apply_last",
        emitter: EmitterKind::Apply,
    },
    PortedOp {
        name: "i_apply_only",
        emitter: EmitterKind::Apply,
    },
    PortedOp {
        name: "i_apply_fun",
        emitter: EmitterKind::Apply,
    },
    PortedOp {
        name: "i_apply_fun_last",
        emitter: EmitterKind::Apply,
    },
    PortedOp {
        name: "i_apply_fun_only",
        emitter: EmitterKind::Apply,
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
    /// What kept the function out, for logs.
    pub missing_ops: Vec<String>,
    /// Why the function is not native.
    pub reason: FallbackReason,
}

/// Why a function was left out of the native code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FallbackReason {
    /// The caller intentionally excluded this function from native compilation.
    Excluded,
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
        self.native.function_entry(function.label)
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
    compile_parsed_module_with_env_and_funcs(&beam, env, function_allowlist)
}

/// [`compile_module_with_env_and_funcs`] for a module the caller has already parsed.
pub fn compile_parsed_module_with_env_and_funcs(
    beam: &BeamFile,
    env: &impl ModuleEnv,
    function_allowlist: Option<&str>,
) -> Result<CompiledModule, CompileError> {
    compile_parsed_module_with_options(beam, env, function_allowlist, false)
}

/// Compile a parsed module with the OTP line-breakpoint rewrite enabled when requested.
pub fn compile_parsed_module_with_options(
    beam: &BeamFile,
    env: &impl ModuleEnv,
    function_allowlist: Option<&str>,
    line_breakpoints: bool,
) -> Result<CompiledModule, CompileError> {
    COMPILE_ARENA.with(|arena| {
        compile_parsed_module_with_options_in_arena(
            beam,
            env,
            function_allowlist,
            line_breakpoints,
            &mut arena.borrow_mut(),
        )
    })
}

/// The words of a literal the load added after the file's own (`beamfile_add_literal`): key
/// tuples, bignums and the funs of lambdas without free variables. The environment holds them
/// under their literal index, like the literals of the file.
fn resolve_new_literal(
    beam: &BeamFile,
    env: &impl ModuleEnv,
    index: u32,
    literal: &NewLiteral,
) -> Result<(), String> {
    let word = match literal {
        // The environment has the record definitions after the literals of the file.
        NewLiteral::Record { .. } => return Ok(()),
        NewLiteral::Bignum(text) => env.bigint_literal(text),
        // The fun entry of a lambda without free variables is created with the module.
        NewLiteral::FunPlaceholder { lambda } => env.zero_capture_fun(beam, *lambda),
        NewLiteral::Tuple(elements) => elements
            .iter()
            .map(|element| match element {
                LiteralElement::Atom(atom) => env.atom(beam, *atom),
                LiteralElement::Small(value) => Ok(((*value as u64) << 4) | 0xf),
                LiteralElement::Nil => Ok(0x3b),
                LiteralElement::Literal(literal) => env.literal(beam, *literal),
            })
            .collect::<Result<Vec<_>, _>>()
            .and_then(|words| env.tuple_literal(&words)),
    }?;
    env.add_literal(index, word)
}

/// The operation of `beamasm_emit`: a generic operation number with its operands.
struct OpView<'a> {
    id: u16,
    operands: &'a [SpecificOperand],
}

impl OpView<'_> {
    fn name(&self) -> &'static str {
        beamops::generic_op_name(self.id)
    }

    fn operands(&self) -> &[SpecificOperand] {
        self.operands
    }
}

/// The function being emitted.
struct CurrentFunction {
    name: String,
    arity: u8,
    /// Its operations are not emitted: it is excluded, or its body is a native stub.
    skip: bool,
    native_body: Option<(usize, usize)>,
    /// A `load_nif` can replace it (`may_load_nif` and `are_nifs` of erts).
    nif_candidate: bool,
}

/// The module assembler as the receiver of `load_code`: the functions are emitted one after
/// the other as the operations arrive (`beamasm_emit` of erts), with no pass over them first.
struct ModuleCompiler<'a, E: ModuleEnv> {
    beam: &'a BeamFile,
    env: &'a E,
    assembler: BeamModuleAssembler,
    /// Index in the code summary of the next function to start.
    next_function: usize,
    current: Option<CurrentFunction>,
    compiled: Vec<CompiledFunction>,
    unported: Vec<UnportedFunction>,
    function_allowlist: Option<&'a str>,
    skip_functions: Option<String>,
    may_load_nif: bool,
    has_nif_start: bool,
}

impl<E: ModuleEnv> ModuleCompiler<'_, E> {
    fn excluded(&self, name: &str, arity: u8) -> bool {
        self.function_allowlist
            .is_some_and(|list| !function_allowlist_contains(list, name, arity))
            || self
                .skip_functions
                .as_deref()
                .is_some_and(|list| function_allowlist_contains(list, name, arity))
    }

    /// `i_func_label` starts the next function of the code summary.
    fn begin_function(&mut self, label: u32) -> Result<(), String> {
        let function = self
            .beam
            .summary
            .functions
            .get(self.next_function)
            .ok_or_else(|| format!("function label {label} has no function in the Code chunk"))?;
        self.next_function += 1;
        let name = self
            .beam
            .atom(function.function_atom)
            .unwrap_or("<unknown>")
            .to_owned();
        let arity = function.arity.min(255) as u8;
        let nif_stub = function.nif_stub;
        if self.excluded(&name, arity) {
            self.unported.push(UnportedFunction {
                name: name.clone(),
                arity,
                label,
                missing_ops: vec!["excluded by ARINSAL_BEAMASM_FUNCS".to_owned()],
                reason: FallbackReason::Excluded,
            });
            self.current = Some(CurrentFunction {
                name,
                arity,
                skip: true,
                native_body: None,
                nif_candidate: false,
            });
            return Ok(());
        }
        self.assembler.begin_dump_function(&name, arity);
        self.compiled.push(CompiledFunction {
            name: name.clone(),
            arity,
            label,
        });
        let native_body = self.env.native_body(&name, arity);
        // Port of erts/emulator/beam/jit/arm/generators.tab:403-412 and asm_load.c:185-190
        // (may_load_nif, are_nifs), OTP-29.1.1: functions a load_nif can replace.
        let nif_candidate =
            native_body.is_none() && self.may_load_nif && (!self.has_nif_start || nif_stub);
        self.current = Some(CurrentFunction {
            name,
            arity,
            skip: false,
            native_body,
            nif_candidate,
        });
        Ok(())
    }
}

impl<E: ModuleEnv> OpSink for ModuleCompiler<'_, E> {
    fn new_literal(&mut self, index: u32, literal: &NewLiteral) -> Result<(), String> {
        resolve_new_literal(self.beam, self.env, index, literal)
    }

    fn emit(&mut self, op: u16, operands: &[SpecificOperand]) -> Result<(), String> {
        let id = i32::from(op);
        let view = OpView { id: op, operands };
        if id == erts_tables::GENOP_I_FUNC_LABEL_1 {
            let label = as_u32(operands.first()).ok_or("i_func_label without a label")?;
            self.begin_function(label)?;
        }
        // Veneers are flushed before every function, whether it is emitted or not, so they
        // never land in a prologue (ops.tab: i_flush_stubs).
        let flush = id == erts_tables::GENOP_I_FLUSH_STUBS_0;
        let Self {
            assembler,
            current,
            beam,
            env,
            ..
        } = self;
        let (name, arity, native_body, nif_candidate) = match current.as_ref() {
            Some(function) if function.skip && !flush => return Ok(()),
            Some(function) => (
                function.name.as_str(),
                function.arity,
                function.native_body,
                function.nif_candidate,
            ),
            None => ("<module>", 0, None, false),
        };
        let dump_enabled = assembler.dump_enabled();
        let start = if dump_enabled {
            assembler.code_offset()
        } else {
            0
        };
        let mut ends_function = false;
        // A statically known NIF function ends with its call-NIF body (instr_bif.cpp:863).
        if let Some((identity, helper)) =
            native_body.filter(|_| id == erts_tables::GENOP_NIF_START_0)
        {
            assembler
                .check_pending_stubs()
                .map_err(|e| format!("{e:?}"))?;
            assembler
                .emit_native_body(identity, helper, usize::from(arity))
                .map_err(|error| format!("{name}/{arity}: nif_start: {error:?}"))?;
            ends_function = true;
        } else {
            emit_op(assembler, &view, beam, *env, name, arity)
                .map_err(|error| describe(&view, &error))?;
            if nif_candidate
                && id == erts_tables::GENOP_I_BREAKPOINT_TRAMPOLINE_0
                && let Some((identity, helper)) = env.dynamic_nif_body(name, arity)
            {
                assembler
                    .emit_nif_patch_site(identity, helper, usize::from(arity))
                    .map_err(|error| format!("{name}/{arity}: i_nif_padding: {error:?}"))?;
            }
        }
        if dump_enabled {
            let end = assembler.code_offset();
            assembler.record_dump_instruction(
                format!("{} {:?}", view.name(), view.operands()),
                start,
                end,
            );
        }
        if ends_function && let Some(function) = current.as_mut() {
            function.skip = true;
        }
        Ok(())
    }
}

fn describe(op: &OpView<'_>, error: &EmitError) -> String {
    format!("{}: {error}; operands {:?}", op.name(), op.operands())
}

fn compile_parsed_module_with_options_in_arena(
    beam: &BeamFile,
    env: &impl ModuleEnv,
    function_allowlist: Option<&str>,
    line_breakpoints: bool,
    transform_arena: &mut TransformArena,
) -> Result<CompiledModule, CompileError> {
    let fail = |error: String| CompileError::Assemble(format!("{}: {error}", beam.module));
    let summary = &beam.summary;
    let skip_functions = std::env::var("ARINSAL_JIT_SKIPF").ok();
    let mut assembler = BeamModuleAssembler::new();
    assembler.set_exception_resolver(env.exception_resolver() as usize);
    if let Some((dispatch_return, test_yield, context_switch)) = env.yield_fragments() {
        assembler.set_yield_fragments(dispatch_return, test_yield, context_switch);
    }
    let shared = env.compare_shared();
    if shared.arith != 0 {
        assembler.set_arith_compare_shared(shared.arith);
    }
    if shared.element_guard != 0 {
        assembler.set_element_guard_shared(shared.element_guard);
    }
    if let Some((raise_shared, raise_exception)) = env.raise_fragments() {
        assembler.set_raise_fragments(raise_shared, raise_exception);
    }
    if let Some((badmap, badkey, size_error)) = env.map_error_fragments() {
        assembler.set_map_error_fragments(badmap, badkey, size_error);
    }
    assembler.enable_dump(&beam.module);
    let may_load_nif = beam.imports.iter().any(|import| {
        import.arity == 2
            && beam.atom(import.module_atom) == Some("erlang")
            && beam.atom(import.function_atom) == Some("load_nif")
    });
    let mut compiler = ModuleCompiler {
        beam,
        env,
        assembler,
        next_function: 0,
        current: None,
        compiled: Vec::new(),
        unported: Vec::new(),
        function_allowlist,
        skip_functions,
        may_load_nif,
        has_nif_start: summary.functions.iter().any(|function| function.nif_stub),
    };
    // The lambdas of functions that are emitted get their table entries first, so the
    // `make_fun` and `call_fun` operations find them.
    let excluded_labels = summary
        .functions
        .iter()
        .filter(|function| {
            let name = beam.atom(function.function_atom).unwrap_or("<unknown>");
            compiler.excluded(name, function.arity.min(255) as u8)
        })
        .map(|function| function.entry_label)
        .collect::<LabelSet>();
    for lambda in &beam.lambdas {
        if excluded_labels.contains(&lambda.label) {
            continue;
        }
        let total_arity = u8::try_from(lambda.arity).map_err(|_| {
            fail(format!(
                "lambda {} has invalid total arity {}",
                lambda.index, lambda.arity
            ))
        })?;
        let num_free = u8::try_from(lambda.num_free).map_err(|_| {
            fail(format!(
                "lambda {} has invalid free variable count {}",
                lambda.index, lambda.num_free
            ))
        })?;
        compiler
            .assembler
            .register_lambda(lambda.index, lambda.label, total_arity, num_free)
            .map_err(|error| fail(format!("lambda {}: {error:?}", lambda.index)))?;
    }
    beamops::load_code(beam, line_breakpoints, true, transform_arena, &mut compiler)
        .map_err(|error| fail(error.to_string()))?;

    let ModuleCompiler {
        mut assembler,
        compiled,
        unported,
        ..
    } = compiler;
    assembler
        .emit_missing_lambda_trampolines()
        .map_err(|error| fail(format!("{error:?}")))?;
    let native = assembler
        .finalize()
        .map_err(|error| fail(format!("{error:?}")))?;
    for (&index, &target) in &native.lambda_entries {
        env.publish_lambda_target(beam, index, target as usize)
            .map_err(&fail)?;
    }
    for function in &compiled {
        if !native.entries.contains_key(&function.label) {
            return Err(fail(format!(
                "function {}/{} has no native entry",
                function.name, function.arity
            )));
        }
    }
    let functions = compiled;
    Ok(CompiledModule {
        name: beam.module.clone(),
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

/// FNV-1a over an operation name: the index is read once per instruction, and SipHash costs more
/// than the lookup is worth for a key of a dozen bytes.
#[derive(Default, Clone, Copy)]
struct OpNameHasher(u64);

impl std::hash::Hasher for OpNameHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        let mut hash = if self.0 == 0 {
            0xcbf2_9ce4_8422_2325
        } else {
            self.0
        };
        for byte in bytes {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.0 = hash;
    }
}

type PortedIndex = std::collections::HashMap<
    &'static str,
    EmitterKind,
    std::hash::BuildHasherDefault<OpNameHasher>,
>;

fn ported_index() -> &'static PortedIndex {
    static INDEX: std::sync::OnceLock<PortedIndex> = std::sync::OnceLock::new();
    INDEX.get_or_init(|| PORTED_OPS.iter().map(|op| (op.name, op.emitter)).collect())
}

/// Report missing operations in order, without counting repeated uses twice.
pub fn missing_ops(ops: &[SpecificOp]) -> Vec<String> {
    let known = ported_index();
    let mut missing = BTreeSet::new();
    let mut ordered = Vec::new();
    for op in ops {
        let name = op.name();
        if !known.contains_key(name) && missing.insert(name) {
            ordered.push(name.to_owned());
        }
    }
    ordered
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
        let specialized = beamops::transform_module(&beam)
            .map_err(|error| CompileError::Assemble(format!("{}: {error}", beam.module)))?;
        module_count += 1;
        let mut labels = BTreeSet::new();
        let mut candidates = Vec::new();
        for ops in specialized {
            let (name, arity, label) = function_identity(&ops);
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

fn function_identity(ops: &[SpecificOp]) -> (String, u8, u32) {
    let mut label = 0;
    let mut name = "<unknown>".to_owned();
    let mut arity = 0;
    for op in ops {
        match op.name() {
            "i_func_label" => label = as_u32(op.operands().first()).unwrap_or(label),
            "i_func_info" if op.operands().len() >= 4 => {
                if let Some(index) = as_u32(op.operands().get(2)) {
                    name = beamops::atom_name(index).unwrap_or("<unknown>").to_owned();
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
        "i_call" | "i_call_only" | "i_call_last" => as_u32(op.operands().first()),
        "move_call_last" => as_u32(op.operands().get(2)),
        _ => None,
    }
}

/// A set of BEAM labels: dense `u32`s, so a bitmap indexed by label.
#[derive(Default)]
struct LabelSet(Vec<bool>);

impl LabelSet {
    fn contains(&self, label: &u32) -> bool {
        self.0.get(*label as usize).copied().unwrap_or(false)
    }
}

impl FromIterator<u32> for LabelSet {
    fn from_iter<I: IntoIterator<Item = u32>>(labels: I) -> Self {
        let mut set = Vec::new();
        for label in labels {
            let index = label as usize;
            if set.len() <= index {
                set.resize(index + 1, false);
            }
            set[index] = true;
        }
        Self(set)
    }
}

/// Maps `i_call_fun2` Safe operand: atom → Dynamic, lambda index → Lambda(id).
// Port of erts/emulator/beam/jit/arm/ops.tab:879-880 (`aF`) and instr_fun.cpp:402-423, OTP-29.1.1.
fn fun_call_tag(value: Option<&SpecificOperand>) -> Result<FunCallTag, EmitError> {
    match value.ok_or_else(|| EmitError::Operand("missing call_fun2 tag".to_owned()))? {
        SpecificOperand::Atom(index) => {
            let name = beamops::atom_name(*index)
                .ok_or_else(|| EmitError::Operand(format!("unknown call_fun2 atom {index}")))?;
            if name == "safe" {
                Ok(FunCallTag::DynamicSafe)
            } else if name == "unsafe" {
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

/// `ArgXRegister(index)`: cached below 6, otherwise in the scheduler's X register array.
fn x_register(index: u32) -> Result<ArgVal, String> {
    match index {
        0..6 => Ok(ArgVal::X(index as u8)),
        // Port of erts/emulator/beam/jit/arm/beam_asm.hpp:252-259 (getXRef), OTP-29.1.1.
        6..1024 => Ok(ArgVal::XMemory(index)),
        _ => Err("X register index exceeds scheduler register array".to_owned()),
    }
}

fn arg(
    value: Option<&SpecificOperand>,
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<ArgVal, String> {
    match value.ok_or_else(|| "missing operand".to_owned())? {
        SpecificOperand::X(index) | SpecificOperand::TypedX { index, .. } => x_register(*index),
        SpecificOperand::Y(index) | SpecificOperand::TypedY { index, .. } => Ok(ArgVal::Y(*index)),
        SpecificOperand::Label(index) => Ok(ArgVal::Label(*index)),
        SpecificOperand::Atom(index) => env.atom(beam, *index).map(ArgVal::Immediate),
        SpecificOperand::Export(index) => env.import(beam, *index).map(ArgVal::Export),
        SpecificOperand::Literal(index) => env.literal(beam, *index).map(ArgVal::Literal),
        // Integers outside the 60-bit small range are bignum literals (OTP's loader moves them
        // into the literal table).
        SpecificOperand::SmallInt(value) if (-(1_i64 << 59)..(1_i64 << 59)).contains(value) => {
            Ok(ArgVal::Immediate((*value as u64).wrapping_shl(4) | 0xf))
        }
        SpecificOperand::SmallInt(value) => env.integer_literal(*value).map(ArgVal::Literal),
        SpecificOperand::Unsigned(value) => Ok(ArgVal::Immediate(*value)),
        SpecificOperand::Nil => Ok(ArgVal::Immediate(0x3b)),
        _ => Err("operand form is not accepted by the module assembler".to_owned()),
    }
}

/// The compile-time shape of an `=:=` / `=/=` right operand that is a literal; any other operand
/// is `Generic`.
fn eq_literal_operand(
    value: Option<&SpecificOperand>,
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<EqLiteral, String> {
    match value {
        // A literal the load added (a bignum) compares like any boxed term.
        Some(SpecificOperand::Literal(index)) if (*index as usize) < beam.literals.len() => {
            env.eq_literal(beam, *index)
        }
        _ => Ok(EqLiteral::Generic),
    }
}

fn typed_arg(
    value: Option<&SpecificOperand>,
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<arinsal_beamasm::types::TypedArg, String> {
    Ok(arinsal_beamasm::types::TypedArg::new(
        arg(value, beam, env)?,
        operand_type(value, beam),
    ))
}

/// The compiler type of an operand: its `Type` chunk entry for a typed register, the type of a
/// literal, otherwise `Any`.
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:229-282 (getTypeEntry, getTypeUnion),
// OTP-29.1.1.
fn operand_type(value: Option<&SpecificOperand>, beam: &BeamFile) -> ArgType {
    match value {
        Some(
            SpecificOperand::TypedX { type_index, .. } | SpecificOperand::TypedY { type_index, .. },
        ) => beam
            .types
            .as_ref()
            .and_then(|table| table.entries.get(*type_index as usize))
            .map_or(ArgType::ANY, |entry| ArgType {
                union_bits: entry.union_bits,
                min: entry.lower_bound,
                max: entry.upper_bound,
            }),
        Some(SpecificOperand::Literal(index)) => {
            beam.literals
                .get(*index as usize)
                .map_or(ArgType::ANY, |literal| ArgType {
                    union_bits: literal_type_union(&literal.0),
                    min: None,
                    max: None,
                })
        }
        _ => ArgType::ANY,
    }
}

/// Whether OTP's Type chunk proves a BIF's map operand is exactly a map.
fn operand_is_exact_map(value: Option<&SpecificOperand>, beam: &BeamFile) -> bool {
    operand_type(value, beam).union_bits == arinsal_beamasm::types::type_id::MAP
}

/// Whether a typed BIF operand may be immediate, matching erts `maybe_one_of`.
fn operand_maybe_one_of(value: Option<&SpecificOperand>, beam: &BeamFile, mask: u16) -> bool {
    operand_type(value, beam).union_bits & mask != 0
}

/// The type union of an external-term-format literal, from its outermost tag.
fn literal_type_union(etf: &[u8]) -> u16 {
    use arinsal_beamasm::types::type_id;
    match etf.get(1) {
        Some(97 | 98 | 110 | 111) => type_id::INTEGER,
        Some(70 | 99) => type_id::FLOAT,
        Some(100 | 115 | 118 | 119) => type_id::ATOM,
        Some(106) => type_id::NIL,
        Some(104 | 105) => type_id::TUPLE,
        Some(107 | 108) => type_id::CONS,
        Some(109 | 77) => type_id::BITSTRING,
        Some(116) => type_id::MAP,
        Some(88 | 103) => type_id::PID,
        Some(101 | 102 | 120) => type_id::PORT,
        Some(90 | 114 | 82) => type_id::REFERENCE,
        Some(112 | 113 | 117) => type_id::FUN,
        _ => type_id::ANY,
    }
}

/// Orders a map instruction's key/value vector by flatmap key order.
// Port of erts/emulator/beam/beam_transform_helpers.c:54-110 (beam_load_map_key_sort),
// OTP-29.1.1: a single pair is already sorted; several pairs need literal keys.
/// `Live` of a bit-syntax match command: `nil` when the command cannot allocate.
fn number(value: Option<&SpecificOperand>) -> Result<u32, String> {
    as_u32(value).ok_or_else(|| "expected nonnegative integer operand".to_owned())
}

/// Operand that is either an untagged unsigned count (tagged small here) or a term.
fn small_or_arg(
    value: Option<&SpecificOperand>,
    beam: &BeamFile,
    env: &impl ModuleEnv,
) -> Result<ArgVal, EmitError> {
    match value {
        Some(SpecificOperand::Unsigned(n)) if *n < (1 << 59) => {
            Ok(ArgVal::Immediate((n << 4) | 0xf))
        }
        Some(SpecificOperand::Unsigned(_)) => Err(EmitError::Operand(
            "unsigned operand does not fit a small integer".to_owned(),
        )),
        other => arg(other, beam, env).map_err(EmitError::Operand),
    }
}

/// Decode a `bs_match` flags operand (a literal list of atoms, or nil) to `BSF_*` bits, tagged.
fn bs_flags(value: Option<&SpecificOperand>, beam: &BeamFile) -> Result<u64, EmitError> {
    let mut bits = 0u64;
    if let Some(SpecificOperand::Unsigned(flags)) = value {
        bits = *flags;
    }
    if let Some(SpecificOperand::SmallInt(flags)) = value {
        bits = *flags as u64;
    }
    if let Some(SpecificOperand::Literal(index)) = value {
        let term = beam
            .literal(*index)
            .map_err(|error| EmitError::Operand(error.to_string()))?;
        let mut current = &term;
        while let arinsal_etf::OwnedTerm::List { elems, tail } = current {
            for elem in elems {
                if let arinsal_etf::OwnedTerm::Atom(name) = elem {
                    match name.as_str() {
                        "little" => bits |= 2,
                        "signed" => bits |= 4,
                        "native" => bits |= 16,
                        _ => {}
                    }
                }
            }
            current = tail;
        }
    }
    Ok((bits << 4) | 0xf)
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

fn tuple_byte_offset(value: Option<&SpecificOperand>) -> Result<u32, String> {
    // ARM tuple loads use zero-based positions after the tuple header word.
    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:378-389, OTP-29.1.1.
    number(value)?
        .checked_add(1)
        .ok_or_else(|| "tuple element offset overflow".to_owned())?
        .checked_mul(8)
        .ok_or_else(|| "tuple element offset overflow".to_owned())
}

fn erlang_get_import(beam: &BeamFile, index: u32) -> bool {
    let Some(import) = beam.imports.get(index as usize) else {
        return false;
    };
    beam.atom(import.module_atom) == Some("erlang")
        && beam.atom(import.function_atom) == Some("get")
        && import.arity == 1
}

fn emit_op(
    assembler: &mut BeamModuleAssembler,
    op: &OpView<'_>,
    beam: &BeamFile,
    env: &impl ModuleEnv,
    function: &str,
    arity: u8,
) -> Result<(), EmitError> {
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:452 (BeamModuleAssembler::emit),
    // OTP-29.1.1: `tbz`/`tbnz` reach only ±32KB, so each instruction flushes a veneer before a
    // forward short branch (such as `is_map`'s boxed test) falls out of range.
    assembler.check_pending_stubs()?;
    let args = op.operands();
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
    if op.name() == "i_get_map_elements" {
        count_at_least(args, 3, op.name())?;
        let size = usize::try_from(n(2)?)
            .map_err(|_| EmitError::Operand("map element size overflows usize".to_owned()))?;
        if !size.is_multiple_of(3) || args.len() != 3 + size {
            return Err(EmitError::Operand(
                "i_get_map_elements expects key/destination/hash triples".to_owned(),
            ));
        }
        // Port of beam/ops.tab:1190-1195 and erts/emulator/beam/jit/arm/instr_map.cpp:391-490,
        // OTP-29.1.1. The loader-sorted key triplets carry their internal hashes.
        let triples = args[3..]
            .iter()
            .map(|operand| arg(Some(operand), beam, env).map_err(EmitError::Operand))
            .collect::<Result<Vec<_>, _>>()?;
        let result =
            assembler.emit_i_get_map_elements(n(0)?, value(1)?, &triples, env.map_runtime());
        return result.map_err(|error| EmitError::Assembler(format!("{error:?}")));
    }
    // Guard-context arithmetic branches to its failure label instead of raising.
    assembler.set_arith_fail(0);
    if matches!(
        ported_op(op),
        Some(
            EmitterKind::Plus
                | EmitterKind::Minus
                | EmitterKind::Times
                | EmitterKind::IntDiv
                | EmitterKind::Rem
                | EmitterKind::Band
                | EmitterKind::Bor
                | EmitterKind::Bxor
                | EmitterKind::Bsl
                | EmitterKind::Bsr
                | EmitterKind::Bnot
                | EmitterKind::UnaryMinus
                | EmitterKind::MulAdd
        )
    ) && let Some(fail) = args.first().and_then(|operand| as_u32(Some(operand)))
    {
        assembler.set_arith_fail(fail);
    }
    let Some(emitter) = ported_op(op) else {
        return Err(EmitError::Operand(format!(
            "no emitter for operation {}",
            op.name()
        )));
    };
    let result = match emitter {
        EmitterKind::Metadata => match op.name() {
            "i_flush_stubs" => {
                count(0)?;
                assembler.flush_yield_stubs()
            }
            "i_nif_padding" => {
                count(0)?;
                // erts pads the end of a function that a later `load_nif` can replace
                // (beam_asm_module.cpp:163, emit_i_nif_padding). This assembler reserves the
                // call-NIF patch site after the function's breakpoint trampoline instead (see
                // `emit_nif_patch_site` in the function loop), so there is nothing to pad.
                Ok(())
            }
            "i_func_label" => {
                count(1)?;
                assembler.emit_i_func_label(n(0)?)
            }
            "label" => {
                count(1)?;
                assembler.emit_label(n(0)?)
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
                let atom = |index: usize| match args.get(index) {
                    Some(SpecificOperand::Atom(value)) => {
                        env.atom(beam, *value).map_err(EmitError::Operand)
                    }
                    _ => Err(EmitError::Operand(
                        "i_func_info expects atom operands".to_owned(),
                    )),
                };
                assembler.emit_i_func_info(n(0)?, atom(1)?, atom(2)?, n(3)?.min(255) as u8)
            }
            "line" | "func_line" | "executable_line" => {
                // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp (emit_line,
                // emit_func_line, emit_executable_line) for the code and of
                // erts/emulator/beam/jit/asm_load.c (add_line_entry) for the line table,
                // OTP-29.1.1: `line` flushes a pending exception return address first;
                // `func_line` keeps a duplicate entry, the others skip a repeat of the
                // previous location.
                let is_line = op.name() == "line";
                let is_func_line = op.name() == "func_line";
                count(if op.name() == "executable_line" { 2 } else { 1 })?;
                if is_line {
                    assembler.flush_last_error()?;
                }
                let location = n(0)?;
                if let Some(item) = beam.lines.as_ref().and_then(|table| {
                    location
                        .checked_sub(1)
                        .and_then(|index| table.items.get(index as usize))
                }) && let Ok(line) = u32::try_from(item.line)
                {
                    let file = if item.name_index == 0 {
                        format!("{}.erl", beam.module)
                    } else {
                        beam.lines
                            .as_ref()
                            .and_then(|table| table.names.get(item.name_index as usize - 1))
                            .filter(|name| !name.is_empty())
                            .cloned()
                            .unwrap_or_else(|| format!("{}.erl", beam.module))
                    };
                    assembler.record_line(u64::from(location), file, line, is_func_line);
                }
                if op.name() == "executable_line" {
                    let cover_id = n(1)?;
                    if let Some(probe) = env.line_coverage_probe(location, cover_id) {
                        assembler.emit_coverage(probe.address, probe.flags)?;
                    }
                }
                Ok(())
            }
            "i_breakpoint_trampoline" => {
                // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:224-237, OTP-29.1.1.
                assembler.emit_i_breakpoint_trampoline(env.breakpoint_fragment())
            }
            "i_debug_line" => {
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3203-3222, OTP-29.1.1.
                count(3)?;
                let line = beam
                    .lines
                    .as_ref()
                    .and_then(|table| {
                        n(0).ok()?
                            .checked_sub(1)
                            .and_then(|index| table.items.get(index as usize))
                    })
                    .and_then(|item| u32::try_from(item.line).ok())
                    .unwrap_or(0);
                let live = u16::try_from(n(2)?)
                    .map_err(|_| EmitError::Operand("debug line live exceeds u16".into()))?;
                assembler.emit_i_debug_line(line, live)?;
                // Each i_debug_line is a distinct line-table entry, duplicates included
                // (asm_load.c:714-737).
                if line != 0 {
                    let file = beam
                        .lines
                        .as_ref()
                        .and_then(|table| {
                            let item = table.items.get(n(0).ok()?.checked_sub(1)? as usize)?;
                            if item.name_index == 0 {
                                None
                            } else {
                                table
                                    .names
                                    .get(item.name_index as usize - 1)
                                    .filter(|name| !name.is_empty())
                                    .cloned()
                            }
                        })
                        .unwrap_or_else(|| format!("{}.erl", beam.module));
                    assembler.record_line(u64::from(n(0)?), file, line, true);
                }
                Ok(())
            }
            "i_line_breakpoint_trampoline" => {
                // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:337-348, OTP-29.1.1.
                count(0)?;
                assembler.emit_i_line_breakpoint_trampoline(env.line_breakpoint_fragment())
            }
            "i_test_yield" => {
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:3097-3115, OTP-29.1.1.
                count(0)?;
                assembler.test_yield()?;
                // Port of erts/emulator/beam/jit/asm_load.c:757-769, OTP-29.1.1.
                if let Some(probe) = env.function_coverage_probe(function, arity) {
                    assembler.emit_coverage(probe.address, probe.flags)?;
                }
                Ok(())
            }
            "nif_start" => {
                // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:627, OTP-29.1.1.
                count(0)?;
                Ok(())
            }
            _ => Ok(()),
        },
        EmitterKind::Move => {
            count(2)?;
            assembler.move_(value(0)?, value(1)?)
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
            let swaps = if matches!(ported_op(op), Some(EmitterKind::Swap3)) {
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
            assembler.emit_get_tuple_element_swap(value(0)?, offset, value(2)?, value(3)?)
        }
        EmitterKind::LengthSetup => {
            count(3)?;
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:198-228, OTP-29.1.1.
            assembler.emit_i_length_setup(n(0)?, n(1)?, value(2)?)
        }
        EmitterKind::Length => {
            count(3)?;
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:320-339, OTP-29.1.1.
            assembler.emit_bif_length(n(0)?, n(1)?, value(2)?, env.guard_helper())
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
            // `init_yregs I *`: the count, then the registers.
            count_at_least(args, 1, op.name())?;
            let registers = n(0)? as usize;
            if args.len() != 1 + registers {
                return Err(EmitError::Operand(
                    "init_yregs expects a count and that many Y registers".to_owned(),
                ));
            }
            let mut indices = Vec::with_capacity(registers);
            for register in &args[1..] {
                let SpecificOperand::Y(index) = register else {
                    return Err(EmitError::Operand(
                        "init_yregs list must contain Y registers".to_owned(),
                    ));
                };
                indices.push(*index);
            }
            assembler.init_yregs_list(&indices)?;
            Ok(())
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
        EmitterKind::ProcessDictionaryGet => {
            let destination = if matches!(op.name(), "get" | "i_get") {
                count(2)?;
                value(1)?
            } else {
                count(3)?;
                value(2)?
            };
            // Port of erts/emulator/beam/jit/arm/instr_common.cpp:319-329, OTP-29.1.1.
            assembler.emit_process_dictionary_get(
                value(0)?,
                destination,
                env.process_dictionary_get_helper(),
            )
        }
        EmitterKind::Plus => {
            count(5)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
            assembler.emit_i_plus_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Minus => {
            count(5)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
            assembler.emit_i_minus_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Times => {
            count(5)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
            assembler.emit_i_times_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::MulAdd => {
            count(6)?;
            // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:542-731, OTP-29.1.1.
            assembler.set_arith_types4([
                operand_type(args.get(1), beam),
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
                operand_type(args.get(4), beam),
            ]);
            assembler.emit_i_mul_add_with_fail(
                value(1)?,
                value(2)?,
                value(3)?,
                value(4)?,
                value(5)?,
                n(0)?,
                helper,
            )
        }
        EmitterKind::IntDiv if op.name() == "i_m_div" => {
            count(5)?;
            assembler.emit_i_m_div(value(2)?, value(3)?, value(4)?, helper)
        }
        EmitterKind::IntDiv => {
            count(5)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
            assembler.emit_i_int_div_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Rem if op.name() == "i_div_rem" => {
            // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1055-1065, OTP-29.1.1.
            count(6)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
            assembler.emit_i_div_rem_with_fail(
                value(2)?,
                value(3)?,
                value(4)?,
                value(5)?,
                n(0)?,
                helper,
            )
        }
        EmitterKind::Rem if op.name() == "i_rem_div" => {
            // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:1043-1053, OTP-29.1.1.
            count(6)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
            assembler.emit_i_rem_div_with_fail(
                value(2)?,
                value(3)?,
                value(4)?,
                value(5)?,
                n(0)?,
                helper,
            )
        }
        EmitterKind::Rem => {
            count(5)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
            assembler.emit_i_rem_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Band => {
            count(5)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
            assembler.emit_i_band_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Bor => {
            count(5)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
            assembler.emit_i_bor_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Bxor => {
            count(5)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
            assembler.emit_i_bxor_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Bsl => {
            count(5)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
            assembler.emit_i_bsl_with_fail(value(2)?, value(3)?, value(4)?, n(0)?, helper)
        }
        EmitterKind::Bsr => {
            count(5)?;
            assembler.set_arith_types(
                operand_type(args.get(2), beam),
                operand_type(args.get(3), beam),
            );
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
            'body: {
                if op.name() == "is_in_range" {
                    // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2537-2634, OTP-29.1.1.
                    count(5)?;
                    let helper = env.guard_helper();
                    let source = TypedArg::new(value(2)?, operand_type(args.get(2), beam));
                    assembler.emit_is_ge(source, value(3)?, fail, helper)?;
                    assembler.emit_is_ge(value(4)?, source, n(1)?, helper)?;
                    break 'body;
                }
                let source_index = usize::from(op.name().ends_with("_ff")) + 1;
                let source = value(source_index)?;
                let typed_source =
                    TypedArg::new(source, operand_type(args.get(source_index), beam));
                if op.name() == "is_int_in_range" {
                    count(4)?;
                    if fail == 0 {
                        return Err(EmitError::Operand(
                            "range guard requires a failure label".to_owned(),
                        ));
                    }
                    assembler.emit_is_int_in_range(
                        typed_source,
                        value(2)?,
                        value(3)?,
                        fail,
                        env.guard_helper(),
                    )?;
                    break 'body;
                }
                if op.name() == "i_is_tuple_of_arity_ff" {
                    count(4)?;
                    assembler.emit_is_tuple_of_arity(typed_source, value(3)?, fail, n(1)?)?;
                    break 'body;
                }
                if op.name() == "i_is_tagged_tuple_ff" {
                    count(5)?;
                    assembler.emit_is_tagged_tuple_ff(
                        typed_source,
                        value(3)?,
                        value(4)?,
                        fail,
                        n(1)?,
                    )?;
                    break 'body;
                }
                match op.name() {
                    "is_integer" => assembler.emit_is_integer(typed_source, fail)?,
                    "is_atom" => assembler.emit_is_atom(typed_source, fail)?,
                    "is_float" => assembler.emit_is_float(typed_source, fail)?,
                    "is_boolean" => assembler.emit_is_boolean(typed_source, fail)?,
                    "is_binary" => assembler.emit_is_binary(typed_source, fail)?,
                    "is_bitstring" => assembler.emit_is_bitstring(typed_source, fail)?,
                    "is_number" => assembler.emit_is_number(typed_source, fail)?,
                    "is_pid" => assembler.emit_is_pid(typed_source, fail)?,
                    "is_port" => assembler.emit_is_port(typed_source, fail)?,
                    "is_reference" => assembler.emit_is_reference(typed_source, fail)?,
                    "is_function" => assembler.emit_is_function(typed_source, fail)?,
                    "is_function2" => assembler.emit_is_function2_guard_with_helper(
                        typed_source,
                        value(2)?,
                        fail,
                        env.guard_helper(),
                    )?,
                    "is_any_native_record" => assembler.emit_is_any_native_record(fail, source)?,
                    "is_native_record" => {
                        // Port of erts/emulator/beam/jit/arm/instr_records.cpp:29-71, OTP-29.1.1.
                        count(4)?;
                        assembler.emit_is_native_record(fail, source, value(2)?, value(3)?)?;
                    }
                    "is_record_accessible" => {
                        // Port of erts/emulator/beam/jit/arm/instr_records.cpp:73-115, OTP-29.1.1.
                        count(3)?;
                        let external = matches!(
                            args.get(2),
                            Some(SpecificOperand::Atom(index)) if beamops::atom_name(*index) == Some("external")
                        );
                        let module = beamops::global_atom_index(&beam.module).ok_or_else(|| {
                            EmitError::Operand("module name is not an atom".to_owned())
                        })?;
                        let module = env.atom(beam, module).map_err(EmitError::Operand)?;
                        assembler.emit_is_record_accessible(
                            fail,
                            source,
                            external,
                            ArgVal::Immediate(module),
                        )?;
                    }
                    "is_list" => assembler.emit_is_list(typed_source, fail)?,
                    "is_nonempty_list" => assembler.emit_is_nonempty_list(typed_source, fail)?,
                    "is_nil" => assembler.emit_is_nil(typed_source, fail)?,
                    "is_map" => assembler.emit_is_map(typed_source, fail)?,
                    "is_tuple" | "i_is_tuple" => assembler.emit_is_tuple(typed_source, fail)?,
                    "i_is_tuple_of_arity" => {
                        assembler.emit_is_tuple_of_arity(typed_source, value(2)?, fail, fail)?;
                    }
                    "test_arity" | "i_test_arity" => {
                        assembler.emit_test_arity(typed_source, value(2)?, fail)?;
                    }
                    "is_tagged_tuple" | "i_is_tagged_tuple" => {
                        assembler.emit_is_tagged_tuple(typed_source, value(2)?, value(3)?, fail)?;
                    }
                    "is_eq_exact" | "is_ne_exact" | "is_eq" | "is_ne" | "is_lt" | "is_ge"
                    | "is_int_ge" => {
                        let lhs = value(1)?;
                        let rhs = value(2)?;
                        match op.name() {
                            "is_eq_exact" => assembler.emit_is_eq_exact(
                                typed_arg(args.get(1), beam, env)?,
                                typed_arg(args.get(2), beam, env)?,
                                fail,
                                &eq_literal_operand(args.get(2), beam, env)?,
                                env.compare_shared().eq,
                            )?,
                            "is_ne_exact" => assembler.emit_is_ne_exact(
                                typed_arg(args.get(1), beam, env)?,
                                typed_arg(args.get(2), beam, env)?,
                                fail,
                                &eq_literal_operand(args.get(2), beam, env)?,
                                env.compare_shared().eq,
                            )?,
                            "is_eq" => assembler.emit_is_eq(
                                typed_arg(args.get(1), beam, env)?,
                                typed_arg(args.get(2), beam, env)?,
                                fail,
                                env.guard_helper(),
                            )?,
                            "is_ne" => assembler.emit_is_ne(
                                typed_arg(args.get(1), beam, env)?,
                                typed_arg(args.get(2), beam, env)?,
                                fail,
                                env.guard_helper(),
                            )?,
                            "is_lt" => assembler.emit_is_lt(
                                typed_arg(args.get(1), beam, env)?,
                                typed_arg(args.get(2), beam, env)?,
                                fail,
                                env.guard_helper(),
                            )?,
                            "is_ge" => assembler.emit_is_ge(
                                typed_arg(args.get(1), beam, env)?,
                                typed_arg(args.get(2), beam, env)?,
                                fail,
                                env.guard_helper(),
                            )?,
                            // Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_is_int_ge),
                            // OTP-29.1.1: fails unless the source is an integer AND >= Min.
                            "is_int_ge" => assembler.emit_is_int_ge(
                                TypedArg::new(lhs, operand_type(args.get(1), beam)),
                                rhs,
                                fail,
                                env.guard_helper(),
                            )?,
                            _ => {
                                return Err(EmitError::Operand(format!(
                                    "unknown op {}",
                                    op.name()
                                )));
                            }
                        }
                    }
                    _ => {
                        return Err(EmitError::Operand(format!(
                            "no guard emitter for {}",
                            op.name()
                        )));
                    }
                }
            }
            Ok(())
        }
        EmitterKind::PairedRangeGuard => {
            count(5)?;
            // Port of erts/emulator/beam/jit/arm/instr_common.cpp:2696-2755, OTP-29.1.1.
            let source = TypedArg::new(value(2)?, operand_type(args.get(2), beam));
            assembler.emit_is_ge(source, value(3)?, n(0)?, env.guard_helper())?;
            if op.name() == "is_ge_lt" {
                // `is_ge_lt` is `is_ge Src A` followed by `is_lt B Src` (instr_common.cpp:2713-2716).
                assembler.emit_is_lt(value(4)?, source, n(1)?, env.guard_helper())?;
            } else {
                assembler.emit_is_ge(source, value(4)?, n(1)?, env.guard_helper())?;
            }
            Ok(())
        }
        EmitterKind::MapLookup => {
            // Port of erts/emulator/beam/jit/arm/instr_map.cpp:362-390 and 511-542,
            // OTP-29.1.1: immediate keys are looked up inline, others in the runtime.
            let runtime = env.map_runtime();
            if op.name() == "i_get_map_element_hash" {
                count(5)?;
                // The hash is the loader's `hashmap_make_hash` of the key (gen.get_map_element).
                assembler.emit_i_get_map_element_hash(
                    n(0)?,
                    value(1)?,
                    value(2)?,
                    value(3)?,
                    value(4)?,
                    runtime,
                )?;
            } else {
                count(4)?;
                assembler.emit_i_get_map_element(
                    n(0)?,
                    value(1)?,
                    value(2)?,
                    value(3)?,
                    runtime,
                )?;
            }
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
        EmitterKind::MapCreate if op.name() == "new_map" => {
            // Port of erts/emulator/beam/jit/arm/instr_map.cpp:228-265, OTP-29.1.1.
            count_at_least(args, 3, op.name())?;
            let size = usize::try_from(n(2)?)
                .map_err(|_| EmitError::Operand("map size overflow".to_owned()))?;
            if size % 2 != 0 || args.len() != 3 + size {
                return Err(EmitError::Operand("new_map size mismatch".to_owned()));
            }
            let pairs = args[3..]
                .iter()
                .map(|item| arg(Some(item), beam, env).map_err(EmitError::Operand))
                .collect::<Result<Vec<_>, _>>()?;
            assembler.emit_new_map(value(0)?, n(1)?, &pairs, env.map_runtime())
        }
        EmitterKind::MapCreate => {
            // Port of erts/emulator/beam/jit/arm/generators.tab:250-300 (gen.new_small_map_lit)
            // and instr_map.cpp:258-305, OTP-29.1.1: the sorted literal keys are one tuple
            // literal; only the values are operands.
            count_at_least(args, 4, op.name())?;
            let size = usize::try_from(n(3)?)
                .map_err(|_| EmitError::Operand("map literal size overflow".to_owned()))?;
            if args.len() != 4 + size {
                return Err(EmitError::Operand("map literal size mismatch".to_owned()));
            }
            let values = args[4..]
                .iter()
                .map(|item| arg(Some(item), beam, env).map_err(EmitError::Operand))
                .collect::<Result<Vec<_>, _>>()?;
            let words = u32::try_from(values.len() + 3)
                .map_err(|_| EmitError::Operand("map literal size overflow".to_owned()))?;
            assembler.emit_test_heap(words, n(1)?, env.gc_hook())?;
            assembler.emit_i_new_small_map_lit(value(0)?, value(2)?, &values)
        }
        EmitterKind::BsConstruct if op.name() == "bs_init_writable" => {
            count(0)?;
            // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:985-1000, OTP-29.1.1.
            assembler.emit_bs_init_writable(ArgVal::X(0), env.bs_init_writable_helper())
        }
        EmitterKind::BsConstruct => {
            use arinsal_beamasm::bs_construct::{BsSegment, BsSegmentKind};
            // Port of erts/emulator/beam/jit/arm/generators.tab:441-530 and instr_bs.cpp:1442,
            // OTP-29.1.1: `Fail Alloc Live Dst` followed by six-operand segments.
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
                    Some(SpecificOperand::Atom(index)) => beamops::atom_name(*index),
                    _ => None,
                }
                .ok_or_else(|| {
                    EmitError::Operand("binary segment kind must be an atom".to_owned())
                })?;
                let unit = number(fields.get(2)).map_err(EmitError::Operand)?;
                let flags = number(fields.get(3)).map_err(EmitError::Operand)?;
                let size_is_units = matches!(fields.get(5), Some(SpecificOperand::Unsigned(_)));
                let size = arg(fields.get(5), beam, env).map_err(EmitError::Operand)?;
                if name == "string" {
                    // erts_bs_put_string copies the bytes; a binary segment of the same
                    // bytes builds the same bits.
                    let start = number(fields.get(4)).map_err(EmitError::Operand)? as usize;
                    let length = match fields.get(5) {
                        Some(SpecificOperand::Unsigned(n)) => *n as usize,
                        Some(SpecificOperand::SmallInt(n)) => *n as usize,
                        _ => {
                            return Err(EmitError::Operand("string segment length".to_owned()));
                        }
                    };
                    let bytes = beam
                        .strings
                        .get(start..start.saturating_add(length))
                        .ok_or_else(|| EmitError::Operand("string table range".to_owned()))?;
                    let literal = env.binary_literal(bytes).map_err(EmitError::Operand)?;
                    segments.push(BsSegment {
                        kind: BsSegmentKind::Binary,
                        index: number(fields.get(1)).map_err(EmitError::Operand)?,
                        src: ArgVal::Literal(literal),
                        size: ArgVal::Immediate(length as u64),
                        size_is_units: true,
                        unit: 8,
                        flags: 0,
                    });
                    continue;
                }
                let kind = match name {
                    "integer" => BsSegmentKind::Integer,
                    "float" => BsSegmentKind::Float,
                    "binary" => BsSegmentKind::Binary,
                    "append" => BsSegmentKind::Append,
                    "private_append" => BsSegmentKind::PrivateAppend,
                    "utf8" => BsSegmentKind::Utf8,
                    "utf16" => BsSegmentKind::Utf16,
                    "utf32" => BsSegmentKind::Utf32,
                    _ => return Err(EmitError::Operand(format!("unknown binary segment {name}"))),
                };
                segments.push(BsSegment {
                    kind,
                    index: number(fields.get(1)).map_err(EmitError::Operand)?,
                    src: arg(fields.get(4), beam, env).map_err(EmitError::Operand)?,
                    size,
                    size_is_units,
                    unit,
                    flags,
                });
            }
            assembler.emit_i_bs_create_bin(
                n(0)?,
                n(1)?,
                n(2)?,
                value(3)?,
                &segments,
                env.bs_create_bin_helper(),
            )
        }
        EmitterKind::Bif => {
            // Port of erts/emulator/beam/jit/arm/ops.tab:812-836 and instr_bif.cpp:110-200.
            let (arity, has_fail) = match op.name() {
                "i_bif1" => (1, true),
                "i_bif2" => (2, true),
                "i_bif3" => (3, true),
                "nofail_bif1" => (1, false),
                _ => (2, false),
            };
            count(arity + 2 + usize::from(has_fail))?;
            let (fail, bif_at) = if has_fail {
                (n(arity)?, arity + 1)
            } else {
                (0, arity)
            };
            let Some(import) = as_u32(args.get(bif_at)) else {
                return Err(EmitError::Operand(
                    "BIF operand must be an import".to_owned(),
                ));
            };
            let mut sources = Vec::with_capacity(arity);
            for index in 0..arity {
                sources.push(value(index)?);
            }
            // Port of erts/emulator/beam/jit/arm/ops.tab:768 (`bif erlang:get/1` => `get`)
            // and common_generators.tab (`gen.get` => `i_get`), OTP-29.1.1.
            if arity == 1 && erlang_get_import(beam, import) {
                return assembler
                    .emit_process_dictionary_get(
                        sources[0],
                        value(bif_at + 1)?,
                        env.process_dictionary_get_helper(),
                    )
                    .map_err(EmitError::from);
            }
            let identity = env
                .plain_bif_identity(beam, import)
                .ok_or_else(|| EmitError::Operand("BIF import is not a plain BIF".to_owned()))?;
            assembler.emit_bif_by_identity(
                identity,
                &sources,
                fail,
                value(bif_at + 1)?,
                env.bif_identity_helper(),
            )
        }
        EmitterKind::Records => {
            // Port of erts/emulator/beam/jit/arm/instr_records.cpp:117-274, OTP-29.1.1.
            let runtime = env.record_runtime();
            // Key/value pairs, sorted in flatmap key order like the loader's `map_key_sort`.
            let sorted_pairs = |first: usize| -> Result<Vec<(ArgVal, ArgVal)>, EmitError> {
                let size = usize::try_from(n(first - 1)?)
                    .map_err(|_| EmitError::Operand("record operand size overflow".to_owned()))?;
                if size % 2 != 0 || args.len() != first + size {
                    return Err(EmitError::Operand(format!("{} size mismatch", op.name())));
                }
                let mut pairs = Vec::with_capacity(size / 2);
                for pair in args[first..].as_chunks::<2>().0 {
                    let key = arg(Some(&pair[0]), beam, env).map_err(EmitError::Operand)?;
                    let ArgVal::Immediate(key_word) = key else {
                        return Err(EmitError::Operand(
                            "native record field names must be atoms".to_owned(),
                        ));
                    };
                    pairs.push((key_word, key, arg(Some(&pair[1]), beam, env)?));
                }
                let words: Vec<u64> = pairs.iter().map(|(word, _, _)| *word).collect();
                let order = env.sort_map_keys(&words).map_err(EmitError::Operand)?;
                Ok(order
                    .into_iter()
                    .map(|index| (pairs[index].1, pairs[index].2))
                    .collect())
            };
            match op.name() {
                "get_record_field" => {
                    count(5)?;
                    assembler.emit_get_record_field(
                        n(0)?,
                        value(1)?,
                        value(2)?,
                        value(3)?,
                        value(4)?,
                        runtime,
                    )
                }
                "i_get_record_elements" => {
                    count_at_least(args, 3, op.name())?;
                    let pairs = sorted_pairs(3)?;
                    let keys: Vec<ArgVal> = pairs.iter().map(|(key, _)| *key).collect();
                    let dsts: Vec<ArgVal> = pairs.iter().map(|(_, dst)| *dst).collect();
                    assembler.emit_i_get_record_elements(n(0)?, value(1)?, &keys, &dsts, runtime)
                }
                "i_create_local_native_record" | "i_create_native_record" => {
                    count_at_least(args, 4, op.name())?;
                    let staged: Vec<ArgVal> = sorted_pairs(4)?
                        .into_iter()
                        .flat_map(|(key, val)| [key, val])
                        .collect();
                    if op.name() == "i_create_local_native_record" {
                        assembler.emit_i_create_local_native_record(
                            value(0)?,
                            value(1)?,
                            n(2)?,
                            &staged,
                            runtime,
                        )
                    } else {
                        assembler.emit_i_create_native_record(
                            value(0)?,
                            value(1)?,
                            n(2)?,
                            &staged,
                            runtime,
                        )
                    }
                }
                "i_update_native_record" => {
                    count_at_least(args, 4, op.name())?;
                    let staged: Vec<ArgVal> = sorted_pairs(4)?
                        .into_iter()
                        .flat_map(|(key, val)| [key, val])
                        .collect();
                    assembler.emit_i_update_native_record(
                        value(0)?,
                        value(1)?,
                        n(2)?,
                        &staged,
                        runtime,
                    )
                }
                _ => return Err(EmitError::Operand(format!("unknown op {}", op.name()))),
            }
        }
        EmitterKind::Receive => {
            // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:25-295, OTP-29.1.1.
            let hooks = env.receive_hooks();
            match op.name() {
                "recv_marker_reserve" => {
                    count(1)?;
                    assembler.emit_recv_marker_reserve(value(0)?, hooks)
                }
                "recv_marker_bind" => {
                    count(2)?;
                    assembler.emit_recv_marker_bind(value(0)?, value(1)?, hooks)
                }
                "recv_marker_clear" => {
                    count(1)?;
                    assembler.emit_recv_marker_clear(value(0)?, hooks)
                }
                "recv_marker_use" => {
                    count(1)?;
                    assembler.emit_recv_marker_use(value(0)?, hooks)
                }
                "i_loop_rec" => {
                    count(1)?;
                    assembler.emit_i_loop_rec(n(0)?, hooks)
                }
                "remove_message" => {
                    count(0)?;
                    assembler.emit_remove_message(hooks)
                }
                "loop_rec_end" => {
                    count(1)?;
                    assembler.emit_loop_rec_end(n(0)?, hooks)
                }
                "wait_unlocked" => {
                    count(1)?;
                    assembler.emit_wait_unlocked(n(0)?, hooks)
                }
                "wait_locked" => {
                    count(1)?;
                    assembler.emit_wait_locked(n(0)?, hooks)
                }
                "wait_timeout_unlocked" => {
                    count(2)?;
                    assembler.emit_wait_timeout_unlocked(value(0)?, n(1)?, hooks)
                }
                "wait_timeout_locked" => {
                    count(2)?;
                    assembler.emit_wait_timeout_locked(value(0)?, n(1)?, hooks)
                }
                "timeout" => {
                    count(0)?;
                    assembler.emit_timeout(hooks)
                }
                _ => {
                    count(0)?;
                    assembler.emit_timeout_locked(hooks)
                }
            }
        }
        EmitterKind::Float => {
            // Port of erts/emulator/beam/jit/arm/instr_float.cpp:55-232, OTP-29.1.1.
            let fr = |index: usize| -> Result<u8, EmitError> {
                match args.get(index) {
                    Some(SpecificOperand::FloatRegister(register)) => u8::try_from(*register)
                        .map_err(|_| EmitError::Operand("float register out of range".to_owned())),
                    _ => Err(EmitError::Operand("expected a float register".to_owned())),
                }
            };
            match op.name() {
                "fload" => {
                    count(2)?;
                    assembler.emit_fload_native(value(0)?, fr(1)?)
                }
                "fstore" => {
                    count(2)?;
                    assembler.emit_fstore_native(fr(0)?, value(1)?)
                }
                "fconv" => {
                    count(2)?;
                    assembler.emit_fconv_native(value(0)?, fr(1)?, env.big_to_float_helper())
                }
                "i_fnegate" => {
                    count(2)?;
                    assembler.emit_i_fnegate(fr(0)?, fr(1)?)
                }
                name => {
                    count(3)?;
                    let float_op = match name {
                        "i_fadd" => arinsal_beamasm::float::FloatOp::Add,
                        "i_fsub" => arinsal_beamasm::float::FloatOp::Sub,
                        "i_fmul" => arinsal_beamasm::float::FloatOp::Mul,
                        _ => arinsal_beamasm::float::FloatOp::Div,
                    };
                    assembler.emit_float_instr(float_op, fr(0)?, fr(1)?, fr(2)?)
                }
            }
            .map_err(EmitError::from)?;
            Ok(())
        }
        EmitterKind::Apply => {
            use arinsal_beamasm::misc::{ApplyKind, emit_apply_call, emit_apply_tail};
            let runtime = env.apply_runtime();
            // Port of erts/emulator/beam/jit/arm/instr_call.cpp:205-320, OTP-29.1.1.
            let (kind, tail, dealloc) = match op.name() {
                "apply" => (ApplyKind::Fixed(n(0)?), false, None),
                "apply_last" => (ApplyKind::Fixed(n(0)?), true, Some(1)),
                "i_apply" => (ApplyKind::Apply3, false, None),
                "i_apply_last" => (ApplyKind::Apply3, true, Some(0)),
                "i_apply_only" => (ApplyKind::Apply3, true, None),
                "i_apply_fun" => (ApplyKind::Apply2, false, None),
                "i_apply_fun_last" => (ApplyKind::Apply2, true, Some(0)),
                _ => (ApplyKind::Apply2, true, None),
            };
            count(match op.name() {
                "apply_last" => 2,
                "apply" | "i_apply_last" | "i_apply_fun_last" => 1,
                _ => 0,
            })?;
            if tail {
                let deallocate = match dealloc {
                    Some(index) => n(index)?,
                    None => 0,
                };
                emit_apply_tail(assembler, kind, runtime, deallocate)
            } else {
                emit_apply_call(assembler, kind, runtime)
            }
            .map_err(EmitError::from)?;
            Ok(())
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
                    assembler.emit_catch_end(value(0)?, env.gc_hook(), env.add_stacktrace_helper())
                }
                "try_case" => {
                    count(1)?;
                    assembler.emit_try_case(value(0)?)
                }
                "try_end" => {
                    count(1)?;
                    assembler.emit_try_end(value(0)?)
                }
                "try_end_deallocate" => {
                    count(1)?;
                    assembler.emit_try_end_deallocate(n(0)?)
                }
                "try_end_move_deallocate" => {
                    count(3)?;
                    assembler.emit_try_end_move_deallocate(value(0)?, value(1)?, n(2)?)
                }
                "try_case_end" => {
                    count(1)?;
                    assembler.emit_try_case_end(value(0)?, resolver)
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
                "raise" => {
                    count(2)?;
                    assembler.emit_i_raise(value(0)?, value(1)?, env.raise_class_helper(), resolver)
                }
                "raw_raise" => {
                    count(0)?;
                    assembler.emit_raw_raise(resolver)
                }
                "node" => {
                    count(1)?;
                    assembler.emit_node(value(0)?, env.this_node_sysname())
                }
                "build_stacktrace" => {
                    count(0)?;
                    assembler.emit_build_stacktrace(
                        env.build_stacktrace_helper().ok_or_else(|| {
                            EmitError::Operand("missing stacktrace helper".into())
                        })?,
                    )
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
                let tag = fun_call_tag(args.first())?;
                let arity = n(1)?.min(u8::MAX as u32) as u8;
                let func = arg(args.get(2), beam, env).map_err(EmitError::Operand)?;
                assembler.emit_i_call_fun2(tag, arity, func, env.fun_resolver())
            }
            "i_call_fun2_last" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:425-455, OTP-29.1.1.
                let tag = fun_call_tag(args.first())?;
                let arity = n(1)?.min(u8::MAX as u32) as u8;
                let func = arg(args.get(2), beam, env).map_err(EmitError::Operand)?;
                assembler.emit_i_call_fun2_last(tag, arity, func, n(3)?, env.fun_resolver())
            }
            "send" => {
                count(0)?;
                // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:595-610, OTP-29.1.1.
                assembler.emit_send(
                    env.send_fragment(),
                    arinsal_beamasm::dispatch::SEND_DISPATCH_IDENTITY,
                )
            }
            _ => unreachable!(),
        },
        EmitterKind::BifMfa => {
            count(3)?;
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:819-839, OTP-29.1.1:
            // the stub body tail-calls the BIF through the shared BIF call path.
            let name = |at: usize| match args.get(at) {
                Some(SpecificOperand::Atom(index)) => beamops::atom_name(*index),
                _ => None,
            };
            if let (Some(module), Some(function)) = (name(0), name(1))
                && let Ok(arity) = u8::try_from(n(2)?)
                && let Ok(entry) = env.bif_mfa_entry(module, function, arity)
            {
                return assembler
                    .dispatch_export(entry, true)
                    .map_err(EmitError::from);
            }
            let arity = n(2)?;
            let helper = env.bif_mfa_helper();
            assembler.mov_arg_to_reg(arinsal_a64::enc::Gpr::x(12), value(0)?)?;
            assembler.mov_arg_to_reg(arinsal_a64::enc::Gpr::x(13), value(1)?)?;
            assembler.emit_raw(|encoder| {
                use arinsal_a64::enc::Gpr;
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
                assembler.emit_put_list2(value(0)?, value(1)?, value(2)?, value(3)?)
            }
            "put_tuple2" => {
                // `put_tuple2 S A *`: the destination, the element count, the elements.
                count_at_least(args, 2, op.name())?;
                if args.len() != 2 + n(1)? as usize {
                    return Err(EmitError::Operand(
                        "put_tuple2 expects its element count operands".to_owned(),
                    ));
                }
                let elements = args[2..]
                    .iter()
                    .map(|item| arg(Some(item), beam, env).map_err(EmitError::Operand))
                    .collect::<Result<Vec<_>, _>>()?;
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
                assembler.emit_get_two_tuple_elements(value(0)?, offset, value(2)?, value(3)?)
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
                count_at_least(args, 5, op.name())?;
                let arity = n(1)?;
                let pairs = &args[5..];
                if pairs.len() != n(4)? as usize || !pairs.len().is_multiple_of(2) {
                    return Err(EmitError::Operand(
                        "update_record expects index/value pairs".to_owned(),
                    ));
                }
                let updates = pairs
                    .chunks(2)
                    .map(|pair| Ok((number(pair.first())?, arg(pair.get(1), beam, env)?)))
                    .collect::<Result<Vec<_>, String>>()?;
                let reuse = matches!(
                    args.first(),
                    Some(SpecificOperand::Atom(index)) if beamops::atom_name(*index) == Some("reuse")
                );
                assembler.emit_update_record(reuse, value(2)?, value(3)?, arity, &updates)
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
                    let (words, live) = (number(args.first())?, number(args.get(1))?);
                    assembler.emit_test_heap(words, live, hook)
                }
                "allocate_heap" => {
                    count(3)?;
                    assembler.emit_allocate_heap(
                        number(args.first())?,
                        number(args.get(1))?,
                        number(args.get(2))?,
                        hook,
                    )
                }
                "allocate_heap_zero" => {
                    count(3)?;
                    assembler.emit_allocate_heap_zero(
                        number(args.first())?,
                        number(args.get(1))?,
                        number(args.get(2))?,
                        hook,
                    )
                }
                _ => return Err(EmitError::Operand(format!("unknown op {}", op.name()))),
            }
        }
        EmitterKind::Fused => match op.name() {
            "store_two_values" => {
                count(4)?;
                assembler.emit_store_two_values(value(0)?, value(1)?, value(2)?, value(3)?)
            }
            "load_two_xregs" => {
                count(4)?;
                assembler.emit_load_two_xregs(value(0)?, value(1)?, value(2)?, value(3)?)
            }
            "move_trim" => {
                count(3)?;
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:559-600, OTP-29.1.1.
                assembler.move_trim(value(0)?, value(1)?, n(2)?)
            }
            "move_call_last" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/instr_call.cpp:83-115, OTP-29.1.1.
                assembler.move_call_last(value(0)?, value(1)?, n(2)?, n(3)?)
            }
            "put_list_deallocate" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:723-773, OTP-29.1.1.
                assembler.emit_put_list_deallocate(value(0)?, value(1)?, value(2)?, n(3)?)
            }
            "move_two_trim" => {
                count(5)?;
                // Port of erts/emulator/beam/jit/arm/instr_common.cpp:521-557, OTP-29.1.1: both
                // Y sources are read before either destination is written, then the frame is
                // trimmed.
                let (ArgVal::Y(src1), ArgVal::Y(src2)) = (value(0)?, value(2)?) else {
                    return Err(EmitError::Operand(
                        "move_two_trim sources must be Y registers".into(),
                    ));
                };
                assembler.move_two_trim(src1, value(1)?, src2, value(3)?, n(4)?)
            }
            "move_call_ext_last" => {
                count(4)?;
                // Port of erts/emulator/beam/jit/arm/ops.tab:852 and instr_call.cpp:175-200, OTP-29.1.1.
                assembler.move_(value(0)?, value(1)?)?;
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
            "i_yield" => {
                count(0)?;
                assembler.emit_i_yield()
            }
            "i_perf_counter" => {
                count(0)?;
                assembler.emit_i_perf_counter(env.sys_perf_counter(), env.gc_hook())
            }
            "i_hibernate" | "i_load_nif" | "i_call_on_load_function" => {
                // Port of erts/emulator/beam/jit/arm/ops.tab:660-680, 612-641, OTP-29.1.1: the
                // loader turns these BIF calls into instructions. They keep their
                // scheduler-visible behaviour by calling the BIF's export, whose import the
                // module still carries.
                count(0)?;
                let (module, function, arity) = match op.name() {
                    "i_hibernate" => ("erlang", "hibernate", 0),
                    "i_load_nif" => ("erlang", "load_nif", 2),
                    _ => ("erlang", "call_on_load_function", 1),
                };
                // The export of these BIFs names their own stub body in `erlang` once
                // that module is native, so enter the BIF itself like `call_bif_mfa` does.
                let entry = match env.bif_mfa_entry(module, function, arity) {
                    Ok(entry) => entry,
                    Err(_) => {
                        let import = beam
                            .imports
                            .iter()
                            .position(|import| {
                                import.arity == u32::from(arity)
                                    && beam.atom(import.module_atom) == Some(module)
                                    && beam.atom(import.function_atom) == Some(function)
                            })
                            .ok_or_else(|| {
                                EmitError::Operand(format!(
                                    "import {module}:{function}/{arity} is missing"
                                ))
                            })?;
                        let import = u32::try_from(import)
                            .map_err(|_| EmitError::Operand("import index overflow".to_owned()))?;
                        env.export_entry(beam, import).map_err(EmitError::Operand)?
                    }
                };
                assembler.dispatch_export(entry, false)
            }
            "call_light_bif" => {
                count(2)?;
                let import = n(1)?;
                let entry = env.export_entry(beam, import).map_err(EmitError::Operand)?;
                if beam.imports.get(import as usize).is_none() {
                    return Err(EmitError::Operand("light BIF import is missing".to_owned()));
                }
                let bif = env.light_bif_func(entry);
                let fragment = if bif != 0 {
                    env.light_bif_fragment()
                } else {
                    env.light_bif_helper_fragment()
                };
                assembler.dispatch_light_bif(fragment, entry, bif)
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
            let runtime = env.guard_helper();
            match op.name() {
                "bif_and" => {
                    count(4)?;
                    assembler.emit_bif_and(n(0)?, value(1)?, value(2)?, value(3)?, runtime)
                }
                "bif_or" => {
                    count(4)?;
                    assembler.emit_bif_or(n(0)?, value(1)?, value(2)?, value(3)?, runtime)
                }
                "bif_not" => {
                    count(3)?;
                    assembler.emit_bif_not(n(0)?, value(1)?, value(2)?, runtime)
                }
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
                    assembler.emit_bif_element(
                        n(0)?,
                        typed_arg(args.get(1), beam, env)?,
                        typed_arg(args.get(2), beam, env)?,
                        value(3)?,
                        runtime,
                    )
                }
                "bif_node" | "bif_bit_size" | "bif_byte_size" | "bif_tuple_size"
                | "bif_map_size" | "bif_length" | "bif_abs" => {
                    count(3)?;
                    let source = value(1)?;
                    let destination = value(2)?;
                    match op.name() {
                        "bif_node" => assembler.emit_bif_node(n(0)?, source, destination, runtime),
                        "bif_bit_size" => {
                            assembler.emit_bif_bit_size(n(0)?, source, destination, runtime)
                        }
                        "bif_byte_size" => {
                            assembler.emit_bif_byte_size(n(0)?, source, destination, runtime)
                        }
                        "bif_tuple_size" => {
                            assembler.emit_bif_tuple_size(n(0)?, source, destination, runtime)
                        }
                        "bif_map_size" => assembler.emit_bif_map_size_typed(
                            n(0)?,
                            typed_arg(args.get(1), beam, env)?,
                            destination,
                            runtime,
                        ),
                        "bif_length" => {
                            assembler.emit_bif_length_helper(n(0)?, source, destination, runtime)
                        }
                        _ => assembler.emit_bif_abs(n(0)?, source, destination, runtime),
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
                            n(0)?,
                            value(key_at)?,
                            value(map_at)?,
                            value(dest_at)?,
                            runtime,
                            operand_is_exact_map(args.get(map_at), beam),
                            operand_maybe_one_of(
                                args.get(key_at),
                                beam,
                                arinsal_beamasm::types::type_id::MAYBE_IMMEDIATE,
                            ),
                            env.map_runtime(),
                        )
                    } else {
                        assembler.emit_bif_is_map_key_typed(
                            n(1)?,
                            typed_arg(args.get(key_at), beam, env)?,
                            typed_arg(args.get(map_at), beam, env)?,
                            value(dest_at)?,
                            runtime,
                            env.map_runtime(),
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
                "bif_is_eq_exact" | "bif_is_ne_exact" | "bif_is_ge" | "bif_is_lt" => {
                    count(3)?;
                    // Port of erts/emulator/beam/jit/arm/ops.tab:819-840 and
                    // instr_guard_bifs.cpp:157-262, OTP-29.1.1.
                    let operation = match op.name() {
                        "bif_is_eq_exact" => 19,
                        "bif_is_ne_exact" => 20,
                        "bif_is_lt" => 23,
                        _ => 24,
                    };
                    assembler.emit_bif_compare(
                        operation,
                        typed_arg(args.first(), beam, env)?,
                        typed_arg(args.get(1), beam, env)?,
                        value(2)?,
                        env.compare_shared(),
                    )
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
            let is_tuple_arity = matches!(ported_op(op), Some(EmitterKind::SelectTupleArity));
            let payload = args[3..]
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    if is_tuple_arity && i < size / 2 {
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
            // The loader's gen.select_val and gen.select_tuple_arity (generators.tab) already
            // sorted the values (beam_load_sort_select_vals) and laid the operands out as the
            // emitter takes them: all values, then all labels.
            let pairs = payload;
            if matches!(ported_op(op), Some(EmitterKind::SelectVal)) {
                let source = arg(args.first(), beam, env).map_err(EmitError::Operand)?;
                // Port of erts/emulator/beam/jit/arm/instr_select.cpp:107-190, OTP-29.1.1.
                if op.name() == "i_select_val_lins" {
                    assembler.emit_i_select_val_lins(source, value(1)?, size, &pairs)
                } else {
                    assembler.emit_i_select_val_bins(source, value(1)?, size, &pairs)
                }
            } else {
                let source = arg(args.first(), beam, env).map_err(EmitError::Operand)?;
                assembler.emit_i_select_tuple_arity(source, value(1)?, size, &pairs)
            }
        }
        EmitterKind::SelectVal2 | EmitterKind::SelectTupleArity2 => {
            count(6)?;
            let src = arg(args.first(), beam, env).map_err(EmitError::Operand)?;
            let fail = value(1)?;
            let is_tuple_arity = matches!(ported_op(op), Some(EmitterKind::SelectTupleArity2));
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
            if matches!(ported_op(op), Some(EmitterKind::SelectVal2)) {
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
                // The base is a full machine word, so a negative base arrives as its
                // two's-complement bit pattern.
                let base = match args.get(2) {
                    Some(SpecificOperand::Unsigned(word)) => *word,
                    Some(SpecificOperand::SmallInt(word)) => *word as u64,
                    _ => {
                        return Err(EmitError::Operand(
                            "jump table base must be an integer".to_owned(),
                        ));
                    }
                };
                (
                    base,
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
            let source = arg(args.first(), beam, env).map_err(EmitError::Operand)?;
            if op.name() == "i_jump_on_val" {
                assembler.emit_i_jump_on_val(source, value(1)?, base, size_at, &targets)
            } else {
                assembler.emit_i_jump_on_val_zero(source, value(1)?, size_at, &targets)
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
                "bs_get_integer2" => {
                    // Fail Ms Live Sz Unit Flags Dst
                    count(7)?;
                    let flags = bs_flags(args.get(5), beam)?;
                    let size = small_or_arg(args.get(3), beam, env)?;
                    let unit = small_or_arg(args.get(4), beam, env)?;
                    assembler.emit_bs_match_command(
                        0,
                        n(2)?,
                        &[value(1)?, ArgVal::Immediate(flags), size, unit],
                        n(0)?,
                        Some(value(6)?),
                        env.bs_match_cmd_helper(),
                    )
                }
                "i_bs_match" | "i_bs_match_test_heap" => {
                    use arinsal_beamasm::bs_segments::BsmCommand;
                    count_at_least(args, 2, op.name())?;
                    let ctx = value(1)?;
                    let fail = n(0)?;
                    let mut at = 2;
                    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:2916-2940 (Need, Live):
                    // the heap test of `i_bs_match_test_heap` is merged into the segment list.
                    let (mut need, mut live) = (0u64, 0u32);
                    if op.name() == "i_bs_match_test_heap" {
                        count_at_least(args, 4, op.name())?;
                        need = u64::from(number(args.get(2)).map_err(EmitError::Operand)?);
                        live = n(3)?;
                        at = 4;
                    }
                    let word = |index: usize| -> Result<u64, EmitError> {
                        match args.get(index) {
                            Some(SpecificOperand::Unsigned(word)) => Ok(*word),
                            Some(SpecificOperand::SmallInt(word)) => Ok(*word as u64),
                            _ => Err(EmitError::Operand(
                                "bitstring match command expects an integer operand".to_owned(),
                            )),
                        }
                    };
                    let live_at = |index: usize| -> Result<Option<u32>, EmitError> {
                        if matches!(args.get(index), Some(SpecificOperand::Nil)) {
                            Ok(None)
                        } else {
                            n(index).map(Some)
                        }
                    };
                    // `bs_get_flags`: native endianness is little on this target.
                    let raw_flags = |index: usize| -> Result<u64, EmitError> {
                        let flags = bs_flags(args.get(index), beam)? >> 4;
                        Ok(if flags & 16 != 0 {
                            (flags & !16) | 2
                        } else {
                            flags
                        })
                    };
                    let mut commands = Vec::new();
                    while at < args.len() {
                        let Some(SpecificOperand::Atom(index)) = args.get(at) else {
                            return Err(EmitError::Operand(
                                "bitstring match expects command atoms".to_owned(),
                            ));
                        };
                        let Some(name) = beamops::atom_name(*index) else {
                            return Err(EmitError::Operand(
                                "bitstring match command atom is out of range".to_owned(),
                            ));
                        };
                        match name {
                            "ensure_exactly" => {
                                commands.push(BsmCommand::EnsureExactly {
                                    size: word(at + 1)?,
                                });
                                at += 2;
                            }
                            "ensure_at_least" => {
                                commands.push(BsmCommand::EnsureAtLeast {
                                    size: word(at + 1)?,
                                    unit: word(at + 2)?,
                                });
                                at += 3;
                            }
                            "skip" => {
                                commands.push(BsmCommand::Skip {
                                    size: word(at + 1)?,
                                });
                                at += 2;
                            }
                            "integer" | "binary" => {
                                // {Name, Live, Flags, Size, Unit, Dst}
                                let (live, flags, size, unit, dst) = (
                                    live_at(at + 1)?,
                                    raw_flags(at + 2)?,
                                    word(at + 3)?,
                                    word(at + 4)?,
                                    value(at + 5)?,
                                );
                                commands.push(if name == "integer" {
                                    BsmCommand::Integer {
                                        live,
                                        flags,
                                        size,
                                        unit,
                                        dst,
                                    }
                                } else {
                                    BsmCommand::Binary {
                                        live,
                                        flags,
                                        size,
                                        unit,
                                        dst,
                                    }
                                });
                                at += 6;
                            }
                            "get_tail" => {
                                // {Name, Live, Unit, Dst}
                                commands.push(BsmCommand::GetTail {
                                    live: live_at(at + 1)?,
                                    dst: value(at + 3)?,
                                });
                                at += 4;
                            }
                            "=:=" => {
                                // {Name, Live, Bits, Value}
                                commands.push(BsmCommand::Eq {
                                    live: live_at(at + 1)?,
                                    size: word(at + 2)?,
                                    value: word(at + 3)?,
                                });
                                at += 4;
                            }
                            other => {
                                return Err(EmitError::Operand(format!(
                                    "unsupported bitstring match command {other}"
                                )));
                            }
                        }
                    }
                    assembler.emit_i_bs_match_segments(
                        ctx,
                        fail,
                        need,
                        live,
                        &commands,
                        helper,
                        env.bs_match_cmd_helper(),
                        env.gc_hook(),
                    )
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
                    assembler.emit_bs_get_tail(value(0)?, value(1)?, n(2)?, helper, env.gc_hook())
                }
                "i_bs_get_binary2" => {
                    count(6)?;
                    assembler.emit_i_bs_get_binary2(
                        value(0)?,
                        n(1)?,
                        n(2)?,
                        value(3)?,
                        n(4)?,
                        value(5)?,
                        helper,
                        env.gc_hook(),
                    )
                }
                "i_bs_get_bin_and_tail" => {
                    count(7)?;
                    // Port of erts/emulator/beam/jit/arm/ops.tab:992-997 and
                    // instr_bs.cpp:506-577,407-455, OTP-29.1.1.
                    assembler.emit_i_bs_get_binary2(
                        value(0)?,
                        n(1)?,
                        n(2)?,
                        value(3)?,
                        n(4)?,
                        value(5)?,
                        helper,
                        env.gc_hook(),
                    )?;
                    assembler.emit_bs_get_tail(value(0)?, value(6)?, n(2)?, helper, env.gc_hook())
                }
                "i_bs_get_utf8" => {
                    count(3)?;
                    assembler.emit_i_bs_get_utf8(value(0)?, n(1)?, value(2)?, helper)
                }
                "i_bs_skip_utf8" => {
                    count(2)?;
                    assembler.emit_i_bs_skip_utf8(value(0)?, n(1)?, helper)
                }
                "i_bs_skip_utf16" => {
                    count(3)?;
                    assembler.emit_i_bs_skip_utf16(value(0)?, n(1)?, value(2)?, helper)
                }
                "i_bs_validate_unicode_retract" => {
                    count(3)?;
                    assembler.emit_i_bs_validate_unicode_retract(n(0)?, value(1)?, value(2)?)
                }
                "i_bs_get_utf16" => {
                    count(4)?;
                    assembler.emit_i_bs_get_utf16(value(0)?, n(1)?, value(2)?, value(3)?, helper)
                }
                "i_bs_get_float2" => {
                    count(6)?;
                    assembler.emit_i_bs_get_float2(
                        value(0)?,
                        n(1)?,
                        n(2)?,
                        value(3)?,
                        n(4)?,
                        value(5)?,
                        helper,
                        env.gc_hook(),
                    )
                }
                "get_float2" => {
                    count(7)?;
                    // Port of erts/emulator/beam/jit/arm/generators.tab:57-71 (gen.get_float2)
                    // with $NativeEndian resolved for a little-endian host, OTP-29.1.1.
                    let flags = bs_flags(args.get(5), beam)? >> 4;
                    let flags = if flags & 16 != 0 {
                        (flags & !16) | 2
                    } else {
                        flags
                    };
                    let unit_and_flags = u32::try_from((u64::from(n(4)?) << 3) | flags)
                        .map_err(|_| EmitError::Operand("float unit overflow".to_owned()))?;
                    assembler.emit_i_bs_get_float2(
                        value(1)?,
                        n(0)?,
                        n(2)?,
                        value(3)?,
                        unit_and_flags,
                        value(6)?,
                        helper,
                        env.gc_hook(),
                    )
                }
                "i_bs_match_string" => {
                    count(4)?;
                    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:191-234, OTP-29.1.1: the
                    // constant lives in the module's string table; the hook gets it as a
                    // registered constant.
                    let bits = n(2)?;
                    let start = usize::try_from(n(3)?)
                        .map_err(|_| EmitError::Operand("string offset overflow".to_owned()))?;
                    let end = start.saturating_add(usize::try_from(bits.div_ceil(8)).unwrap_or(0));
                    let bytes = beam.strings.get(start..end).ok_or_else(|| {
                        EmitError::Operand("match string is outside the string table".to_owned())
                    })?;
                    let constant = env.match_string(bytes).map_err(EmitError::Operand)?;
                    assembler.emit_i_bs_match_string(
                        value(0)?,
                        n(1)?,
                        ArgVal::Immediate((u64::from(bits) << 4) | 0xf),
                        ArgVal::Immediate((constant << 4) | 0xf),
                        helper,
                    )
                }
                "i_bs_skip_bits2" => {
                    count(4)?;
                    assembler.emit_i_bs_skip_bits2(value(0)?, value(1)?, n(3)?, n(2)?)
                }
                _ => Err(arinsal_beamasm::module::ModuleError::InvalidOperand(
                    "unknown bit syntax match op",
                )),
            }
        }
    };
    result.map_err(|error| EmitError::Assembler(format!("{error:?}")))
}

fn ported(name: &str) -> Option<EmitterKind> {
    ported_index().get(name).copied()
}

/// The emitter of `op`, from a table indexed by the generic operation number.
fn ported_op(op: &OpView<'_>) -> Option<EmitterKind> {
    static TABLE: std::sync::OnceLock<Vec<Option<EmitterKind>>> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        (0..beamops::NUM_GENERIC_OPS)
            .map(|id| ported(beamops::generic_op_name(id as u16)))
            .collect()
    });
    table.get(usize::from(op.id)).copied().flatten()
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

/// Orders a `select_val` pair list (all values, then all labels) by the raw word each value
/// compares as, for the linear and the binary search alike.
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

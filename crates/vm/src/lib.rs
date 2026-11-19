//! Single-process BEAM interpreter for OTP 29 generic bytecode.
mod atom_cache;
mod beam_catches;
mod beam_jit_common;
mod beam_jit_main;
mod beamasm_integration;
mod bif_traps;
mod big;
mod fun_dispatch;
// c_boot: Launcher entry point for the preloaded OTP boot process.
mod beam_common;
mod bif_dispatch;
mod bif_table;
pub mod boot;
mod calls;
mod check_io;
mod child_setup;
mod code_ix;
mod ddll;
mod debug_env;
#[cfg(feature = "difftest")]
mod difftest;
mod dirty;
mod dist;
mod erl_arith;
mod erl_bits;
mod erl_gc;
mod erl_init;
mod erl_map;
mod erl_nfunc_sched;
mod erl_osenv;
mod erl_poll;
mod erl_trace;
mod exceptions;
mod export;
mod interp;
mod load;
mod native_bridge;
mod proc_create;
// ---- vm_funs ----
mod funs;
mod lists;
mod monitor_link;
mod process;
mod raw;
mod register;
/// Run the persistent child-setup helper mode selected by the CLI.
#[doc(hidden)]
pub use child_setup::run_child_setup;
/// Run one staged child exec request selected by the CLI.
#[doc(hidden)]
pub use child_setup::run_child_setup_exec;
pub use process::{
    ERTS_MESSAGE_TERM_OFFSET, PROCESS_FLAGS_OFFSET, PROCESS_MBUF_OFFSET, PROCESS_MBUF_SZ_OFFSET,
    PROCESS_SIGQ_CONT_OFFSET, PROCESS_SIGQ_FIRST_OFFSET, PROCESS_SIGQ_LAST_OFFSET,
    PROCESS_SIGQ_MQ_LEN_OFFSET, PROCESS_SIGQ_SAVE_OFFSET, PROCESS_STATE_OFFSET, ScheduledResult,
};
mod inet_drv;
// g_inet_udp
mod inet_udp;
pub(crate) mod node_tables;
mod port;
mod ram_file_drv;
mod receive;
mod seq_trace;
mod signals;
mod spawn_drv;
mod suspend;
mod sys_signals;
mod trace;
mod trace_bp;
mod utils;
// ---- vm_maps_bits ----
mod bits;
mod native_helpers;
mod native_hooks;
mod native_records;
mod natives;
pub use bif_table::has_function as bif_table_has_function;
pub use calls::call_bif;
pub use native_bridge::install_crash_dump;
#[cfg(target_arch = "aarch64")]
pub use native_hooks::{
    arinsal_beamasm_arith, arinsal_beamasm_bif_mfa, arinsal_beamasm_gc, arinsal_beamasm_guard,
    arinsal_beamasm_guard3, arinsal_beamasm_map_lookup,
};
pub use natives::implemented_natives;
#[doc(hidden)]
pub use natives::tty::registered_callers as tty_registered_callers;
mod stacktrace;

use arinsal_beam::BeamFile;
use arinsal_beamasm::{ExitReason, ProcessHeader, SchedulerRegisters};
// vm_binparse2
use arinsal_bifs::Ctx;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_loader::{ImportClass, Module};
use arinsal_term::{GcStats, ProcessHeap, Term};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

pub(crate) use calls::ImportOutcome;
pub(crate) use interp::{RunState, XREG_POISON, gc_stress_enabled, xreg_poison_enabled};
pub(crate) use load::CodeMeta;
pub use native_bridge::{
    NativeFile, NativeFunction, NativeLine, NativeLines, arinsal_native_raise, native_function_at,
    register_native_function, run_native,
};
pub use proc_create::Process;
#[cfg(feature = "instr-count")]
pub(crate) use proc_create::ProcessStats;

#[cfg(test)]
mod boot_loop1_shared_tests {
    use super::*;
    use arinsal_difftest::RefErl;
    use arinsal_term::TermBuilder;

    #[test]
    fn collection_roots_only_the_live_registers() {
        let mut process = Process::new();
        // `reg`, the register array the caller holds.
        let mut reg = [Term::NIL; 2];
        process.ensure_objv(2, &mut reg[..0]).unwrap();
        let value = TermBuilder::new(&mut process.heap)
            .tuple(&[Term::NIL])
            .unwrap();
        reg[0] = value;
        reg[1] = value;
        let allocation_to_force_gc = process.heap.free_words() + 1;
        process
            .ensure_objv(allocation_to_force_gc, &mut reg[..1])
            .unwrap();
        assert_ne!(reg[0], Term::NIL);
        // Port of erts/emulator/beam/erl_gc.c (setup_rootset), OTP-29.1.1: only the live prefix
        // is rewritten and the dead registers above it are left as they are, so the stale x1 must
        // be made live again before the next, wider collection.
        reg[1] = reg[0];
        let allocation_to_force_wider_gc = process.heap.free_words() + 1;
        process
            .ensure_objv(allocation_to_force_wider_gc, &mut reg)
            .unwrap();
    }

    #[test]
    fn loaded_module_is_in_the_active_code_tables() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping shared code publication test");
            return;
        };
        let beam = reference
            .compile_named(
                "boot_loop1_shared",
                "-module(boot_loop1_shared). -export([run/0]). run() -> ok.",
                &[],
            )
            .unwrap();
        let mut vm = Vm {};
        let id = vm.load_bytes(&beam).unwrap();
        let code = crate::code_ix::code_tables(crate::code_ix::erts_active_code_ix());
        assert_eq!(code.modules[id].name, "boot_loop1_shared");
    }
}

/// A VM limitation, Erlang exception, or module loading failure.
#[derive(Debug)]
pub enum VmError {
    /// The current BIF exhausted its scheduler slice and must resume later.
    Yield,
    /// The current BIF or NIF must be retried on a dirty scheduler of this kind.
    /// Port of erts/emulator/beam/erl_nif.c:5000 (schedule_dirty_nif / erts_schedule_bif), OTP-29.1.1.
    Dirty(arinsal_sched::DirtyKind),
    /// Instruction or external service not implemented yet.
    Unsupported(String),
    /// Erlang exception reason and current top frame.
    Exception { reason: String, frame: String },
    /// Erlang exception whose top stack frame carries erts error metadata.
    ExceptionInfo {
        /// Exception reason.
        reason: String,
        /// Current top frame.
        frame: String,
        /// `error_info` map to attach to the top stack frame.
        info: Box<arinsal_etf::OwnedTerm>,
    },
    /// Exception awaiting BEAM handler dispatch.
    Trap(exceptions::Trap),
    /// Uncaught Erlang exception with a symbolic stack trace.
    Raised(Box<exceptions::Raised>),
    /// Invalid or missing module.
    Load(String),
    /// The BIF traps to an Erlang export: the caller makes this call and its result is the BIF's.
    /// Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP*: `c_p->i` is the export, the arguments
    /// are its X registers, freason TRAP), OTP-29.1.1.
    TrapExport(ExportTrap),
}

/// An Erlang export a BIF traps to, with the arguments it is called with.
#[derive(Debug)]
pub struct ExportTrap {
    /// The stable export entry that dispatches the continuation after code replacement.
    pub entry: std::sync::Arc<arinsal_term::ExportEntry>,
    /// Parsed continuation metadata for Arinsal's interpreter and trap handler.
    pub(crate) target: &'static crate::bif_traps::ContinuationTarget,
    /// Arguments, X0 onwards.
    pub args: Vec<Term>,
    /// `erts_set_gc_state(c_p, 0)` before the trap: the continuation state holds process-heap
    /// terms, so the process is not collected while it is parked.
    pub(crate) gc_disabled: bool,
}

impl ExportTrap {
    /// Builds a BIF export trap from the runtime's stable export entry.
    // Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP* names the Export*), OTP-29.1.1.
    pub(crate) fn new(process: &Process, continuation: &'static str, args: Vec<Term>) -> Self {
        let target = crate::bif_traps::continuation_target(continuation);
        Self {
            entry: process.trap_export_entry(target),
            target,
            args,
            gc_disabled: false,
        }
    }
}
impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yield => f.write_str("scheduler yield"),
            Self::Dirty(kind) => write!(f, "dirty scheduler migration ({kind:?})"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
            Self::Exception { reason, frame } => {
                write!(f, "** exception error: {reason}\n  in function {frame}")
            }
            Self::ExceptionInfo { reason, frame, .. } => {
                write!(f, "** exception error: {reason}\n  in function {frame}")
            }
            Self::Trap(_) => write!(f, "unhandled BEAM exception"),
            Self::Raised(raised) => raised.fmt(f),
            Self::Load(s) => write!(f, "{s}"),
            Self::TrapExport(trap) => write!(
                f,
                "trap to {}:{}/{}",
                arinsal_term::global_atoms()
                    .text(trap.entry.module())
                    .unwrap_or("?"),
                arinsal_term::global_atoms()
                    .text(trap.entry.function())
                    .unwrap_or("?"),
                trap.entry.arity()
            ),
        }
    }
}
impl std::error::Error for VmError {}

/// Interpreter counters and collection time for a single evaluation.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Total executed opcodes, enabled with `instr-count`.
    pub instructions: u64,
    /// Executed opcodes by name, enabled with `instr-count`.
    pub opcodes: HashMap<&'static str, u64>,
    /// Generic decoded instructions by opcode, enabled with `instr-count`.
    pub generic_opcodes: HashMap<&'static str, u64>,
    /// Collection counters.
    pub gc: GcStats,
    /// Number of process heap words at completion.
    pub heap_words: usize,
}
/// Evaluation result retaining its process heap. The VM and any source argument
/// heaps must remain alive while reading a result that refers to their terms.
pub struct EvalResult {
    /// Returned Erlang term.
    pub term: Term,
    /// Execution counters.
    pub stats: Stats,
    _process: Process,
}

/// Lazy module loader and single-process execution engine.
pub struct Vm {}

#[test]
fn cli_help_non_pollable_registration_fires_once() {
    use std::os::fd::AsRawFd;
    use std::sync::mpsc;
    use std::time::Duration;

    let input = std::fs::File::open("/dev/null").unwrap();
    let (tx, rx) = mpsc::channel();
    let registration = check_io::register(
        input.as_raw_fd(),
        check_io::InterestSet {
            readable: true,
            writable: false,
        },
        move |_, ready| {
            let _ = tx.send(ready);
        },
    )
    .unwrap();
    assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap().readable);
    check_io::deregister(registration);
    assert!(rx.try_recv().is_err());
}

/// Port of erts/emulator/beam/erl_init.c (erts_exit): the one place a node's OS process ends,
/// where the BeamAsm statistics are printed before `exit`.
pub fn erts_exit(status: i32) -> ! {
    #[cfg(target_arch = "aarch64")]
    beamasm_integration::print_stats();
    std::process::exit(status)
}

impl Vm {
    /// Registers a native function for this VM and removes it when its code is purged.
    pub fn register_native_function(
        &mut self,
        function: NativeFunction,
    ) -> Result<(), &'static str> {
        native_bridge::register_native_function(function)
    }

    /// Paths currently searched for lazy module loading: the boot code path.
    pub fn paths(&self) -> Vec<PathBuf> {
        crate::erl_init::erts_boot_paths()
    }
    /// Parse and load every BEAM file beneath a directory, reporting errors.
    pub fn load_file(&mut self, path: &Path) -> Result<usize, VmError> {
        let bytes = std::fs::read(path).map_err(|e| VmError::Load(e.to_string()))?;
        self.load_bytes(&bytes)
    }
}

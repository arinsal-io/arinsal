//! Single-process BEAM interpreter for OTP 29 generic bytecode.
mod arith;
mod beamasm_integration;
// c_boot: Launcher entry point for the preloaded OTP boot process.
mod bif_dispatch;
pub mod boot;
mod calls;
mod check_io;
mod compare;
#[cfg(feature = "difftest")]
mod difftest;
mod dist;
mod exceptions;
mod floats;
mod interp;
mod load;
mod native_bridge;
mod proc_create;
// ---- vm_funs ----
mod funs;
mod lists;
mod process;
pub use process::ScheduledResult;
mod inet_drv;
// g_inet_udp
mod inet_udp;
pub(crate) mod node_tables;
mod port;
mod receive;
mod seq_trace;
mod signals;
mod trace;
mod trace_bp;
// ---- vm_maps_bits ----
mod bits;
mod maps;
mod native_helpers;
mod native_hooks;
mod natives;
pub use calls::call_bif;
pub use native_hooks::{
    arinsal_beamasm_arith, arinsal_beamasm_bif_mfa, arinsal_beamasm_gc, arinsal_beamasm_guard,
    arinsal_beamasm_guard3, arinsal_beamasm_map_lookup,
};
pub use natives::implemented_natives;
mod stacktrace;
mod tuples;

use arinsal_beam::BeamFile;
use arinsal_beamasm::{ExitReason, ProcessHeader, SchedulerRegisters};
// vm_binparse2
use arinsal_bifs::Ctx;
use arinsal_bifs::FragmentingHeap;
use arinsal_bits::MatchOps;
use arinsal_loader::{
    Arg, FastBif, GenericOp, ImportClass, ImportFastOp, Instr, Module, SelectTable,
};
use arinsal_spec::Opcode;
use arinsal_term::{
    GcStats, ProcessHeap, Term, TermBuilder, TermKind, cmp, exact_eq, is_match_context, loose_eq,
    match_position,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::{Arc, Mutex, OnceLock};

pub(crate) use calls::ImportOutcome;
pub(crate) use interp::{RunState, gc_stress_enabled};
pub(crate) use load::{CodeMeta, ExportIndex, SharedCode};
pub(crate) use native_bridge::native_function_for;
pub use native_bridge::{
    NativeFunction, NativeLine, arinsal_native_raise, native_function_at, register_native_function,
    run_native,
};
pub use proc_create::Process;
#[cfg(feature = "instr-count")]
pub(crate) use proc_create::ProcessStats;
pub(crate) use proc_create::native_continuation_term;

#[cfg(test)]
mod boot_loop1_shared_tests {
    use super::*;
    use arinsal_difftest::RefErl;

    #[test]
    fn collection_clears_dead_registers_before_conservative_scan() {
        let mut process = Process::with_registers(2, 0);
        process.ensure(2, 0).unwrap();
        let value = TermBuilder::new(&mut process.heap)
            .tuple(&[Term::NIL])
            .unwrap();
        process.x[0] = value;
        process.x[1] = value;
        let allocation_to_force_gc = process.heap.free_words() + 1;
        process.ensure(allocation_to_force_gc, 1).unwrap();
        assert_ne!(process.x[0], Term::NIL);
        assert_eq!(process.x[1], Term::NIL);
        let allocation_to_force_wider_gc = process.heap.free_words() + 1;
        process.ensure(allocation_to_force_wider_gc, 2).unwrap();
    }

    #[test]
    fn prepared_module_is_visible_to_other_scheduler_replicas() {
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
        let parsed = arinsal_beam::parse(&beam).unwrap();
        let shared = Arc::new(Mutex::new(SharedCode::blank()));
        let mut first = Vm::shared_replica(Arc::clone(&shared), &[]);
        let mut second = Vm::shared_replica(Arc::clone(&shared), &[]);
        let id = first.load_beam(&parsed).unwrap();
        second.sync_module(id);
        assert_eq!(second.modules[id].name, "boot_loop1_shared");
        assert_eq!(shared.lock().unwrap().modules.len(), id + 1);
    }
}

/// A VM limitation, Erlang exception, or module loading failure.
#[derive(Debug)]
pub enum VmError {
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
}
impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
pub struct Vm {
    paths: Vec<PathBuf>,
    pub(crate) otp_root: Option<PathBuf>,
    pub(crate) modules: Vec<Arc<Module>>,
    loaded: HashMap<String, usize>,
    old: HashMap<String, usize>,
    pending_on_load: HashMap<String, usize>,
    purge_prepared: std::collections::HashSet<String>,
    deleted: std::collections::HashSet<String>,
    code_meta: Vec<Option<Arc<CodeMeta>>>,
    code_epoch: Option<Arc<std::sync::atomic::AtomicU64>>,
    seen_epoch: u64,
    beamasm_targets: beamasm_integration::NativeTargetCache,
    registers: Vec<(usize, usize)>,
    native_fns: Vec<arinsal_bifs::BifFn>,
    loaded_nifs: std::collections::HashSet<String>,
    shared: Option<Arc<Mutex<SharedCode>>>,
    // ---- vm_exc ----
    backtrace_depth: usize,
    // g_code_fix: global export index, reclaimable module slots, code-server filenames.
    exports: ExportIndex,
    free_ids: Vec<usize>,
    module_live: Vec<bool>,
    module_files: HashMap<String, arinsal_etf::OwnedTerm>,
    condemned: Vec<usize>,
    // g_code_fix: a module entry survives purge, so later delete_module stays true.
    known_modules: HashSet<String>,
    // Mode applies to modules loaded after code:set_coverage_mode/1.
    pub(crate) coverage_mode: arinsal_loader::CoverageMode,
}

#[test]
fn cli_help_dev_null_is_ready_once() {
    use std::os::fd::AsRawFd;

    let input = std::fs::File::open("/dev/null").unwrap();
    let interest = check_io::InterestSet {
        readable: true,
        writable: false,
    };
    for _ in 0..2 {
        let (fd, ready) = check_io::wait_any(&[(input.as_raw_fd(), interest)])
            .unwrap()
            .unwrap();
        assert_eq!(fd, input.as_raw_fd());
        assert!(ready.readable);
    }
}

#[test]
fn cli_help_regular_file_is_ready_through_eof() {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    let path = std::env::temp_dir().join(format!("arinsal-cli-help-{}", std::process::id()));
    std::fs::write(&path, b"data").unwrap();
    let mut input = std::fs::File::open(&path).unwrap();
    let interest = check_io::InterestSet {
        readable: true,
        writable: false,
    };
    let mut bytes = [0; 8];
    for expected in [b"data".as_slice(), b"".as_slice()] {
        let (fd, ready) = check_io::wait_any(&[(input.as_raw_fd(), interest)])
            .unwrap()
            .unwrap();
        assert_eq!(fd, input.as_raw_fd());
        assert!(ready.readable);
        let n = input.read(&mut bytes).unwrap();
        assert_eq!(&bytes[..n], expected);
    }
    std::fs::remove_file(path).unwrap();
}

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

impl Drop for Vm {
    fn drop(&mut self) {
        beamasm_integration::print_stats();
    }
}
impl Vm {
    /// Paths currently searched for lazy module loading.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
    /// Parse and load every BEAM file beneath a directory, reporting errors.
    pub fn load_file(&mut self, path: &Path) -> Result<usize, VmError> {
        let bytes = std::fs::read(path).map_err(|e| VmError::Load(e.to_string()))?;
        self.load_bytes(&bytes)
    }
}

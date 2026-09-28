//! VM-facing system native bindings: statistics and literal retirement.
//!
//! Return shapes follow `statistics_1` in `erts/emulator/beam/erl_bif_info.c`
//! (OTP-29.1.1). Reduction totals are completed scheduler quanta plus the
//! current slice. `microstate_accounting` stays `undefined` until
//! `system_flag(microstate_accounting, true)`, matching the documented erts
//! default.

use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_bifs::Ctx;
use arinsal_pterm::RetiredArea;
use arinsal_sched::RunCtx;
use arinsal_term::{Term, TermBuilder, TermKind, copy_term, global_atoms};
use std::collections::HashSet;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

#[path = "alloc_info.rs"]
mod alloc_info;

const QUANTUM: u32 = 4_000;
// Header subtags from arinsal-term/src/lib.rs. They are crate-private there.
const ARITY: u64 = 0x00;
const FUN: u64 = 0x14;
const RECORD: u64 = 0x1c;
const SUB_BITS: u64 = 0x24;
const MAP: u64 = 0x2c;

static COMPLETED_REDUCTIONS: AtomicU64 = AtomicU64::new(0);
static LAST_REDUCTIONS: AtomicU64 = AtomicU64::new(0);
static LAST_EXACT_REDUCTIONS: AtomicU64 = AtomicU64::new(0);
static CONTEXT_SWITCHES: AtomicU64 = AtomicU64::new(0);
static GC_COUNT: AtomicU64 = AtomicU64::new(0);
static GC_WORDS: AtomicU64 = AtomicU64::new(0);
static LAST_RUNTIME_MS: AtomicU64 = AtomicU64::new(0);
static LAST_WALL_MS: AtomicU64 = AtomicU64::new(0);
static CPU_ORIGIN_NS: OnceLock<u64> = OnceLock::new();
static WALL_ORIGIN: OnceLock<Instant> = OnceLock::new();
static MICROSTATE: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
struct SchedBase {
    started: Instant,
    cpu_ns: u64,
}
static SCHED_WALL: Mutex<Option<SchedBase>> = Mutex::new(None);
static SYSTEM_LOGGER: OnceLock<Mutex<Term>> = OnceLock::new();

/// Count one finished reduction quantum. Called once per yield, not per opcode.
pub(crate) fn note_quantum(reductions: u32) {
    COMPLETED_REDUCTIONS.fetch_add(u64::from(reductions), Ordering::Relaxed);
    CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
}

/// Record a collection and acknowledge persistent-term literals this process may hold.
pub(crate) fn after_collection(
    process: &mut Process,
    live_x: usize,
    collections: u64,
    words_reclaimed: u64,
) {
    GC_COUNT.fetch_add(collections, Ordering::Relaxed);
    GC_WORDS.fetch_add(words_reclaimed, Ordering::Relaxed);
    if arinsal_pterm::global_store().has_retired() {
        let _ = salvage_retired(process, live_x);
    }
}

/// System and persistent-term BIFs this family dispatches.
///
/// `system_info/1` and the `nodes/2` visible-map fast path stay outside the
/// table: those arms return `None` for selectors they do not handle.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("persistent_term", "put", 2),
    ("persistent_term", "put_new", 2),
    ("persistent_term", "get", 0),
    ("persistent_term", "get", 1),
    ("persistent_term", "get", 2),
    ("persistent_term", "erase", 1),
    ("persistent_term", "info", 0),
    ("erts_internal", "erase_persistent_terms", 0),
    ("erlang", "nodes", 0),
    ("erlang", "display", 1),
    ("erlang", "display_string", 2),
    ("erts_internal", "term_to_string", 2),
    ("erlang", "statistics", 1),
    ("erlang", "bump_reductions", 1),
    ("erts_internal", "garbage_collect", 1),
    ("erlang", "system_flag", 2),
    ("erts_internal", "scheduler_wall_time", 1),
    ("erlang", "dt_spread_tag", 1),
    ("erlang", "dt_restore_tag", 1),
];

pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

type Handler =
    fn(&mut Vm, &mut Process, &mut RunCtx<'_, Message>, &[Term]) -> Result<Term, VmError>;

pub(crate) fn handler(module: &str, function: &str, arity: u8) -> Option<Handler> {
    match (module, function, arity) {
        ("erlang", "nodes", 0) => Some(call_nodes0),
        ("erlang", "display", 1) => Some(call_display),
        ("erlang", "display_string", 2) => Some(call_display_string),
        ("erts_internal", "term_to_string", 2) => Some(call_term_to_string),
        ("erlang", "statistics", 1) => Some(call_statistics),
        ("erlang", "bump_reductions", 1) => Some(call_bump_reductions),
        ("erts_internal", "garbage_collect", 1) => Some(call_garbage_collect),
        ("erlang", "system_flag", 2) => Some(call_system_flag),
        ("erts_internal", "scheduler_wall_time", 1) => Some(call_scheduler_wall_time),
        ("erlang", "dt_spread_tag", 1) => Some(call_dt_spread_tag),
        ("erlang", "dt_restore_tag", 1) => Some(call_dt_restore_tag),
        _ => None,
    }
}

fn call_nodes0(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    _args: &[Term],
) -> Result<Term, VmError> {
    Ok(Term::NIL)
}

fn call_display(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    display(args[0])
}

fn call_display_string(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    display_string(args)
}

fn call_term_to_string(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    term_to_string(process, args)
}

fn call_statistics(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    statistics(vm, process, Some(ctx), args[0])
}

fn call_bump_reductions(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:5403 (bump_reductions_1), OTP-29.1.1.
    // The BIF consumes at most one scheduler quantum and returns `true`.
    let reductions = args[0]
        .as_small()
        .filter(|value| *value >= 0)
        .ok_or_else(badarg)?;
    process.reductions -= reductions.min(QUANTUM as i64) as i32;
    Ok(atom("true"))
}

fn call_garbage_collect(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    garbage_collect(process, args[0])
}

fn call_system_flag(
    vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    system_flag(vm, process, args)
}

fn call_scheduler_wall_time(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:5306 (erts_internal_scheduler_wall_time_1), OTP-29.1.1.
    // Any term other than `true` disables accounting. The previous flag is returned.
    set_scheduler_wall_enabled(atom_name(args[0]).as_deref() == Some("true"))
}

fn call_dt_spread_tag(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:6032 (dt_spread_tag_1), OTP-29.1.1.
    // Without DTrace the BIF checks the boolean and returns `true`.
    if args[0] != atom("true") && args[0] != atom("false") {
        return Err(badarg());
    }
    Ok(atom("true"))
}

fn call_dt_restore_tag(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:6066 (dt_restore_tag_1), OTP-29.1.1.
    // Without DTrace only `true` is accepted, and the BIF returns `true`.
    if args[0] != atom("true") {
        return Err(badarg());
    }
    Ok(atom("true"))
}

pub(super) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    args.with_values(process, |process, values| {
        call_values(vm, process, ctx, module, function, values)
    })
}

fn call_values(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    let arity = args.len() as u8;
    if let Some(bif) = arinsal_pterm::lookup(module, function, arity) {
        debug_assert!(
            recognizes(module, function, arity),
            "persistent_term {module}:{function}/{arity} is dispatched but not listed"
        );
        let result = {
            let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
            let mut bif_ctx = Ctx::new(&mut heap);
            bif(&mut bif_ctx, args)
        };
        return Some(result.map_err(|error| {
            crate::exceptions::direct_bif_error(process, module, function, args, error)
        }));
    }
    if let Some(handle) = handler(module, function, arity) {
        return Some(handle(vm, process, ctx, args));
    }
    match (module, function, args.len()) {
        // boot_loop1: rpc and global query peer nodes while this VM is non-distributed.
        // `node::call` handles the general case first; this arm remains for a direct call.
        ("erlang", "nodes", 2)
            if args[0]
                .as_atom()
                .and_then(|atom| global_atoms().text(atom))
                .as_deref()
                == Some("visible")
                && args[1].classify() == TermKind::Map =>
        {
            Some(Ok(Term::NIL))
        }
        // Port of erts/emulator/beam/bif.c:5929-6119 (DTrace BIFs without
        // USE_VM_PROBES), OTP-29.1.1.
        ("erlang", "dt_get_tag" | "dt_get_tag_data", 0) => Some(Ok(atom("undefined"))),
        ("erlang", "dt_put_tag", 1) => Some(Ok(atom("undefined"))),
        ("erlang", "dt_spread_tag", 1) => {
            Some(if args[0] == atom("true") || args[0] == atom("false") {
                Ok(atom("true"))
            } else {
                Err(badarg())
            })
        }
        ("erlang", "dt_restore_tag", 1) => Some(if args[0] == atom("true") {
            Ok(atom("true"))
        } else {
            Err(badarg())
        }),
        ("erlang", "dt_prepend_vm_tag_data" | "dt_append_vm_tag_data", 1) => Some(Ok(args[0])),
        // Port of erts/emulator/beam/dist.c:6670, OTP-29.1.1. Local peers
        // always advertise the Unicode I/O distribution flag.
        ("net_kernel", "dflag_unicode_io", 1) => Some(match args[0].classify() {
            TermKind::Pid if args[0].as_pid().is_some() => Ok(atom("true")),
            TermKind::Pid => Ok(atom("false")),
            _ => Err(badarg()),
        }),
        ("erlang", "system_info", 1) => alloc_info::system_info(vm, process, ctx, args[0])
            .or_else(|| system_info(vm, process, args[0])),
        _ => None,
    }
}

// Port of erts/emulator/beam/bif.c:4144 (display_1) and :4156
// (erts_internal_term_to_string_2), OTP-29.1.1.
// boot_loop2: init formats fatal boot errors before io_lib is available.
fn display(term: Term) -> Result<Term, VmError> {
    let owned = arinsal_term::to_owned(term).map_err(|_| badarg())?;
    let rendered = print_otp_term(&owned, i32::MAX as usize);
    write!(std::io::stdout().lock(), "{rendered}\r\n")
        .map_err(|error| VmError::Unsupported(format!("display write: {error}")))?;
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}

fn term_to_string(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let limit = if atom_name(args[1]).as_deref() == Some("undefined") {
        i32::MAX as usize
    } else {
        usize::try_from(args[1].as_small().ok_or_else(badarg)?)
            .ok()
            .filter(|limit| *limit > 1 && *limit < i32::MAX as usize)
            .ok_or_else(badarg)?
    };
    let owned = arinsal_term::to_owned(args[0]).map_err(|_| badarg())?;
    let rendered = print_otp_term(&owned, limit);
    let bytes = rendered
        .bytes()
        .map(|byte| Term::small(i64::from(byte)).unwrap());
    TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .list_from_iter(bytes)
        .map_err(|error| VmError::Unsupported(format!("term_to_string allocation: {error:?}")))
}

fn print_otp_term(term: &arinsal_etf::OwnedTerm, limit: usize) -> String {
    use arinsal_etf::OwnedTerm;

    fn printable_string(items: &[OwnedTerm]) -> Option<String> {
        if items.is_empty() {
            return None;
        }
        let mut text = String::with_capacity(items.len());
        for item in items {
            let OwnedTerm::Int(code) = item else {
                return None;
            };
            let Ok(byte) = u8::try_from(*code) else {
                return None;
            };
            if byte < b' ' && !matches!(byte, b'\n' | b'\r' | b'\t') || byte == 127 {
                return None;
            }
            text.push(char::from(byte));
        }
        Some(text)
    }

    fn render(term: &OwnedTerm, remaining: &mut usize, out: &mut String) -> bool {
        if *remaining == 0 {
            return false;
        }
        *remaining -= 1;
        match term {
            OwnedTerm::Tuple(items) => {
                out.push('{');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    if !render(item, remaining, out) {
                        return false;
                    }
                }
                out.push('}');
            }
            OwnedTerm::List { elems, tail } => {
                if matches!(tail.as_ref(), OwnedTerm::Nil)
                    && let Some(text) = printable_string(elems)
                {
                    out.push('"');
                    for byte in text.bytes() {
                        if *remaining == 0 {
                            return false;
                        }
                        *remaining -= 1;
                        match byte {
                            b'\n' => out.push_str("\\n"),
                            b'"' => out.push_str("\\\""),
                            _ => out.push(char::from(byte)),
                        }
                    }
                    out.push('"');
                } else {
                    out.push('[');
                    for (index, item) in elems.iter().enumerate() {
                        if index > 0 {
                            out.push(',');
                        }
                        if !render(item, remaining, out) {
                            return false;
                        }
                    }
                    if !matches!(tail.as_ref(), OwnedTerm::Nil) {
                        out.push('|');
                        if !render(tail, remaining, out) {
                            return false;
                        }
                    }
                    out.push(']');
                }
            }
            OwnedTerm::Map(pairs) => {
                out.push_str("#{");
                for (index, (key, value)) in pairs.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    if !render(key, remaining, out) {
                        return false;
                    }
                    out.push_str("=>");
                    if !render(value, remaining, out) {
                        return false;
                    }
                }
                out.push('}');
            }
            OwnedTerm::Binary(bytes)
                if !bytes.is_empty() && bytes.iter().all(|byte| (32..127).contains(byte)) =>
            {
                out.push_str("<<\"");
                for byte in bytes {
                    if *remaining == 0 {
                        return false;
                    }
                    *remaining -= 1;
                    if *byte == b'"' {
                        out.push('\\');
                    }
                    out.push(char::from(*byte));
                }
                out.push_str("\">>");
            }
            OwnedTerm::Binary(bytes) => {
                out.push_str("<<");
                for (index, byte) in bytes.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    if *remaining == 0 {
                        return false;
                    }
                    *remaining -= 1;
                    out.push_str(&byte.to_string());
                }
                out.push_str(">>");
            }
            OwnedTerm::Float(value) => {
                let formatted = format!("{value:.6e}");
                let (mantissa, exponent) = formatted.split_once('e').unwrap();
                let exponent = exponent.parse::<i32>().unwrap_or(0);
                out.push_str(&format!("{mantissa}e{exponent:+03}"));
            }
            OwnedTerm::Atom(name) => {
                out.push_str(&term.to_string());
                *remaining = remaining.saturating_sub(name.len());
                if *remaining == 0 {
                    return false;
                }
            }
            _ => out.push_str(&term.to_string()),
        }
        true
    }

    let mut out = String::new();
    let mut remaining = limit;
    if !render(term, &mut remaining, &mut out) || remaining == 0 {
        out.push_str("... ");
    }
    out
}

// Port of erts/emulator/beam/bif.c:4192 (display_string_2), OTP-29.1.1.
// boot_loop1: logger_simple_h writes directly to stdout after a boot failure.
fn display_string(args: &[Term]) -> Result<Term, VmError> {
    use arinsal_etf::OwnedTerm;

    fn append_string(value: &OwnedTerm, bytes: &mut Vec<u8>) -> Result<(), VmError> {
        match value {
            OwnedTerm::Nil => Ok(()),
            OwnedTerm::List { elems, tail } => {
                for element in elems {
                    append_string(element, bytes)?;
                }
                append_string(tail, bytes)
            }
            OwnedTerm::Int(codepoint) => {
                let c = u32::try_from(*codepoint)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or_else(badarg)?;
                let mut buffer = [0; 4];
                bytes.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
                Ok(())
            }
            OwnedTerm::Binary(binary) => {
                bytes.extend_from_slice(binary);
                Ok(())
            }
            _ => Err(badarg()),
        }
    }

    let destination = args[0]
        .as_atom()
        .and_then(|atom| global_atoms().text(atom))
        .ok_or_else(badarg)?;
    let value = arinsal_term::to_owned(args[1]).map_err(|_| badarg())?;
    let mut bytes = Vec::new();
    append_string(&value, &mut bytes)?;
    match destination.as_ref() {
        "stdout" => std::io::stdout().lock().write_all(&bytes),
        "stderr" => std::io::stderr().lock().write_all(&bytes),
        _ => return Err(badarg()),
    }
    .map_err(|error| VmError::Unsupported(format!("display_string write: {error}")))?;
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}

// boot_loop1: init:has_small_memory/0 probes this before loading kernel modules.
fn system_info(vm: &Vm, process: &mut Process, selector: Term) -> Option<Result<Term, VmError>> {
    let owned_selector = arinsal_term::to_owned(selector).ok();
    if let Some(arinsal_etf::OwnedTerm::Tuple(parts)) = owned_selector.as_ref()
        && let [
            arinsal_etf::OwnedTerm::Atom(name),
            arinsal_etf::OwnedTerm::Atom(kind),
        ] = parts.as_slice()
        && name == "wordsize"
    {
        return Some(match kind.as_str() {
            "internal" | "external" => Ok(Term::small(8).unwrap()),
            _ => Err(badarg()),
        });
    }
    let name = selector
        .as_atom()
        .and_then(|atom| global_atoms().text(atom));
    match name.as_deref() {
        Some("debug_compiled") => Some(Ok(Term::atom(arinsal_term::atoms::FALSE))),
        Some("check_io") => Some(check_io_info(process)),
        Some("ethread_info") => Some(ethread_info(process)),
        // Port of erts/emulator/beam/erl_bif_info.c:2773 (system_info_1), OTP-29.1.1.
        Some("schedulers_online") => Some(with_flags(|flags| {
            non_neg(process, flags.schedulers_online as u64)
        })),
        Some("dirty_cpu_schedulers_online") => Some(with_flags(|flags| {
            non_neg(process, flags.dirty_cpu_online as u64)
        })),
        Some("fullsweep_after") => Some(with_flags(|flags| {
            tagged(process, "fullsweep_after", u64::from(flags.fullsweep_after))
        })),
        Some("min_heap_size") => Some(with_flags(|flags| {
            tagged(process, "min_heap_size", flags.min_heap_size as u64)
        })),
        Some("min_bin_vheap_size") => Some(with_flags(|flags| {
            tagged(
                process,
                "min_bin_vheap_size",
                flags.min_bin_vheap_size as u64,
            )
        })),
        Some("max_heap_size") => Some(with_flags(|flags| max_heap_map(process, flags.max_heap))),
        Some("multi_scheduling") => Some(with_flags(|flags| Ok(atom(flags.multi)))),
        Some("sequential_tracer") => Some(crate::seq_trace::system_tracer_info(process)),
        Some("allocated_areas") => Some(memory_areas(vm, process)),
        _ if selector.classify() == TermKind::Tuple => Some(Err(badarg())),
        _ => None,
    }
}

// Port of erts/emulator/beam/erl_bif_info.c:5487 (erts_get_ethread_info), OTP-29.1.1.
fn ethread_info(process: &mut Process) -> Result<Term, VmError> {
    use arinsal_etf::OwnedTerm as O;

    fn list(items: Vec<O>) -> O {
        O::List {
            elems: items,
            tail: Box::new(O::Nil),
        }
    }
    fn string(value: &str) -> O {
        list(value.bytes().map(|byte| O::Int(i64::from(byte))).collect())
    }
    fn atomic_entry(label: &str, width: &str, name: &str, operations: &[&str]) -> O {
        O::Tuple(vec![
            string(label),
            string(name),
            list(
                operations
                    .iter()
                    .map(|operation| string(&format!("ethr_native_atomic{width}_{operation}()")))
                    .collect(),
            ),
        ])
    }

    let bit_ops = [
        "or_retold_relb",
        "or_retold_acqb",
        "or_retold",
        "and_retold_relb",
        "and_retold_acqb",
        "and_retold",
        "read_acqb",
        "read",
        "add_return_relb",
        "add_return_acqb",
        "add_return",
        "set_relb",
        "set",
        "cmpxchg_acqb",
        "cmpxchg",
    ];
    let double_word_ops = [
        "read_acqb",
        "read",
        "set_relb",
        "set",
        "cmpxchg_acqb",
        "cmpxchg",
    ];
    let entries = vec![
        atomic_entry(
            "32-bit native atomics",
            "32",
            "gcc_atomic_and_sync_builtins",
            &bit_ops,
        ),
        atomic_entry(
            "64-bit native atomics",
            "64",
            "gcc_atomic_and_sync_builtins",
            &bit_ops,
        ),
        O::Tuple(vec![
            string("Double word native atomics"),
            string("gcc_atomic_and_sync_builtins"),
            list(
                double_word_ops
                    .iter()
                    .map(|operation| string(&format!("ethr_native_su_dw_atomic_{operation}()")))
                    .collect(),
            ),
        ]),
        O::Tuple(vec![string("Native spinlocks"), string("native-atomics")]),
        O::Tuple(vec![
            string("Native rw-spinlocks"),
            string("native-atomics"),
        ]),
    ];
    arinsal_term::from_owned(
        &list(entries),
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .map_err(|error| VmError::Unsupported(format!("ethread_info result: {error:?}")))
}

fn memory_areas(vm: &Vm, process: &mut Process) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_bif_info.c:2773 (allocated_areas selector), OTP-29.1.1.
    snapshot_process(process, process.gc_live);
    let values = memory_values(vm, process);
    let value = |name: &str| {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
            .unwrap_or(0)
    };
    let (_, persistent) = arinsal_pterm::global_store().info();
    let external_bytes = persistent as u64;
    let external_size = non_neg(process, external_bytes)?;
    let external = tuple(process, &[atom("external_alloc"), external_size])?;
    let allocated_atoms = non_neg(process, value("atom"))?;
    let used_atoms = non_neg(process, value("atom_used"))?;
    let atoms = tuple(process, &[atom("atom_space"), allocated_atoms, used_atoms])?;
    let processes = non_neg(process, value("processes"))?;
    let processes = tuple(process, &[atom("process_table"), processes])?;
    let ets_size = non_neg(process, value("ets"))?;
    let ets = tuple(process, &[atom("ets_misc"), ets_size])?;
    let code_size = non_neg(process, value("code"))?;
    let code = tuple(process, &[atom("loaded_code"), code_size])?;
    let areas = [external, atoms, processes, ets, code];
    cons_list(process, &areas)
}

fn memory_values(vm: &Vm, process: &Process) -> [(&'static str, u64); 9] {
    let (processes, processes_used, binary) = arinsal_pterm::global_store().process_memory_totals();
    let (atom, atom_used) = atom_bytes();
    let code = code_bytes(vm);
    let ets = ets_bytes(process);
    let (_, persistent) = arinsal_pterm::global_store().info();
    let system = atom
        .saturating_add(binary)
        .saturating_add(code)
        .saturating_add(ets)
        .saturating_add(persistent as u64);
    let total = processes.saturating_add(system);
    [
        ("total", total),
        ("processes", processes),
        ("processes_used", processes_used),
        ("system", system),
        ("atom", atom),
        ("atom_used", atom_used),
        ("binary", binary),
        ("code", code),
        ("ets", ets),
    ]
}

fn snapshot_process(process: &mut Process, _live_x: usize) {
    let word = std::mem::size_of::<usize>();
    let extra = std::mem::size_of::<Process>() + process.x.len() * word + process.fr.len() * word;
    let capacity = process
        .heap
        .total_heap_size_words()
        .saturating_mul(word)
        .saturating_add(extra) as u64;
    let used_words =
        process.heap.used_words() + process.heap.old_used_words() + process.heap.stack_words();
    let used = used_words.saturating_mul(word).saturating_add(extra) as u64;
    arinsal_pterm::global_store().set_process_memory(
        &process._persistent_terms,
        capacity,
        used,
        process.heap.off_heap_binary_bytes(),
    );
}

fn code_bytes(vm: &Vm) -> u64 {
    vm.modules
        .iter()
        .map(|module| {
            let code = std::mem::size_of_val(module.code.as_ref());
            let generic = std::mem::size_of_val(module.generic.as_slice());
            let names: usize = module.functions.iter().map(|(_, name, _)| name.len()).sum();
            (code + generic + module.strings.len() + names + module.name.len()) as u64
        })
        .sum()
}

fn ets_bytes(process: &Process) -> u64 {
    let Some(runtime) = &process.runtime else {
        return 0;
    };
    let registry = runtime.ets.lock().expect("ets registry");
    let words: usize = registry
        .all()
        .into_iter()
        .map(|id| {
            registry
                .get(id)
                .map(|table| table.memory_words())
                .unwrap_or(0)
        })
        .sum();
    words as u64 * std::mem::size_of::<usize>() as u64
}

fn atom_bytes() -> (u64, u64) {
    let count = global_atoms().len();
    let predefined = arinsal_term::atoms::PREDEFINED;
    let text: usize = predefined.iter().map(|name| name.len()).sum();
    let extra = count.saturating_sub(predefined.len()).saturating_mul(8);
    let entries = count.saturating_mul(std::mem::size_of::<usize>() * 6);
    let used = (text + extra + entries) as u64;
    let allocated = used.saturating_add((count as u64).saturating_mul(16));
    (allocated, used.min(allocated))
}

fn statistics(
    _vm: &Vm,
    process: &mut Process,
    ctx: Option<&RunCtx<'_, Message>>,
    key: Term,
) -> Result<Term, VmError> {
    let Some(name) = atom_name(key) else {
        return Err(badarg());
    };
    match name.as_ref() {
        "runtime" => {
            let (total, delta) = since(runtime_ms(), &LAST_RUNTIME_MS);
            pair(process, total, delta)
        }
        "wall_clock" => {
            let (total, delta) = since(wall_ms(), &LAST_WALL_MS);
            pair(process, total, delta)
        }
        "reductions" => {
            let (total, delta) = since(reduction_total(ctx), &LAST_REDUCTIONS);
            pair(process, total, delta)
        }
        "exact_reductions" => {
            let (total, delta) = since(reduction_total(ctx), &LAST_EXACT_REDUCTIONS);
            pair(process, total, delta)
        }
        "context_switches" => pair(process, CONTEXT_SWITCHES.load(Ordering::Relaxed), 0),
        "garbage_collection" => triple(
            process,
            GC_COUNT.load(Ordering::Relaxed),
            GC_WORDS.load(Ordering::Relaxed),
            0,
        ),
        "io" => io_counters(process),
        "run_queue" => non_neg(process, run_queue(process)),
        "total_run_queue_lengths" | "total_run_queue_lengths_all" => {
            non_neg(process, run_queue(process))
        }
        "run_queue_lengths" => int_list(process, &queue_slots(1, run_queue(process))),
        "run_queue_lengths_all" => int_list(process, &queue_slots(2, run_queue(process))),
        "active_tasks" => int_list(process, &queue_slots(1, active_tasks(process))),
        "active_tasks_all" => int_list(process, &queue_slots(2, active_tasks(process))),
        "total_active_tasks" | "total_active_tasks_all" => non_neg(process, active_tasks(process)),
        "run_queues" => int_tuple(process, &queue_slots(2, run_queue(process))),
        "scheduler_wall_time" => scheduler_wall(process, false),
        "scheduler_wall_time_all" => scheduler_wall(process, true),
        "microstate_accounting" => microstate(process),
        _ => Err(badarg()),
    }
}

fn system_flag(vm: &mut Vm, process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:4972 (system_flag_2), OTP-29.1.1.
    let Some(name) = atom_name(args[0]) else {
        return Err(badarg());
    };
    match name.as_ref() {
        "multi_scheduling" => multi_scheduling(args[1]),
        "schedulers_online" => schedulers_online(args[1], false),
        "dirty_cpu_schedulers_online" => schedulers_online(args[1], true),
        "fullsweep_after" => fullsweep_after(args[1]),
        "min_heap_size" => heap_minimum(args[1], true),
        "min_bin_vheap_size" => heap_minimum(args[1], false),
        "max_heap_size" => max_heap_flag(process, args[1]),
        "debug_flags" => Ok(atom("true")),
        "backtrace_depth" => backtrace_depth(vm, args[1]),
        "trace_control_word" => trace_control_word(args[1]),
        "sequential_tracer" => crate::seq_trace::set_system_tracer(vm, process, args[1]),
        "reset_seq_trace" => {
            crate::seq_trace::clear_all();
            Ok(atom("true"))
        }
        "scheduler_wall_time" => set_scheduler_wall(args[1]),
        "microstate_accounting" => set_microstate(args[1]),
        "outstanding_system_requests_limit" => outstanding_limit(args[1]),
        "scheduling_statistics" => scheduling_statistics(args[1]),
        "time_offset" if atom_name(args[1]).as_deref() == Some("finalize") => Ok(atom("final")),
        "system_logger" => set_system_logger(args[1]),
        _ => Err(badarg()),
    }
}

pub(crate) fn set_system_logger(value: Term) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_trace.c:2486, OTP-29.1.1.
    if value != atom("logger") && value != atom("undefined") && value.as_pid().is_none() {
        return Err(badarg());
    }
    let slot = SYSTEM_LOGGER.get_or_init(|| Mutex::new(atom("logger")));
    let mut current = slot.lock().expect("system logger");
    Ok(std::mem::replace(&mut *current, value))
}

fn set_scheduler_wall(value: Term) -> Result<Term, VmError> {
    let enable = match atom_name(value).as_deref() {
        Some("true") => true,
        Some("false") => false,
        _ => return Err(badarg()),
    };
    set_scheduler_wall_enabled(enable)
}

fn set_scheduler_wall_enabled(enable: bool) -> Result<Term, VmError> {
    let mut state = SCHED_WALL.lock().expect("scheduler wall time");
    let previous = state.is_some();
    if enable {
        if state.is_none() {
            *state = Some(SchedBase {
                started: Instant::now(),
                cpu_ns: cpu_ns(),
            });
        }
    } else {
        *state = None;
    }
    Ok(atom(if previous { "true" } else { "false" }))
}

struct SystemFlags {
    fullsweep_after: u16,
    min_heap_size: i64,
    min_bin_vheap_size: i64,
    max_heap: crate::process::MaxHeap,
    schedulers_online: usize,
    dirty_cpu_online: usize,
    trace_word: i64,
    outstanding: u64,
    multi: &'static str,
}

pub(crate) struct GcSpawnDefaults {
    pub(crate) fullsweep_after: u16,
    pub(crate) max_heap_size: crate::process::MaxHeap,
}

pub(crate) fn gc_spawn_defaults() -> GcSpawnDefaults {
    with_flags(|flags| GcSpawnDefaults {
        fullsweep_after: flags.fullsweep_after,
        max_heap_size: flags.max_heap,
    })
}

pub(crate) fn normalize_spawn_heap_minimum(requested: Option<usize>, binary: bool) -> usize {
    with_flags(|flags| {
        let minimum = if binary {
            flags.min_bin_vheap_size
        } else {
            flags.min_heap_size
        } as usize;
        match requested {
            Some(size) if size > minimum => {
                next_heap_size(i64::try_from(size).unwrap_or(i64::MAX)) as usize
            }
            _ => minimum,
        }
    })
}

fn with_flags<T>(body: impl FnOnce(&mut SystemFlags) -> T) -> T {
    static FLAGS: OnceLock<Mutex<SystemFlags>> = OnceLock::new();
    let flags = FLAGS.get_or_init(|| {
        let cpus = logical_processors();
        Mutex::new(SystemFlags {
            // Port of erl_init.c:1328-1332 (`ERL_FULLSWEEP_AFTER`), OTP-29.1.1.
            fullsweep_after: std::env::var("ERL_FULLSWEEP_AFTER")
                .ok()
                .map(|value| value.trim().parse::<i64>().unwrap_or(0) as u16)
                .unwrap_or(u16::MAX),
            min_heap_size: 233,
            min_bin_vheap_size: 46_422,
            max_heap: crate::process::MaxHeap::default(),
            schedulers_online: cpus,
            dirty_cpu_online: cpus,
            trace_word: 0,
            outstanding: (cpus as u64).saturating_mul(2),
            multi: "enabled",
        })
    });
    body(&mut flags.lock().expect("system flags"))
}

// Port of erts/emulator/beam/erl_gc.c:265 (heap size table) and :311
// (erts_next_heap_size), OTP-29.1.1.
fn next_heap_size(size: i64) -> i64 {
    static SIZES: OnceLock<Vec<i64>> = OnceLock::new();
    let sizes = SIZES.get_or_init(|| {
        let mut sizes = Vec::with_capacity(154);
        sizes.push(12);
        sizes.push(38);
        for index in 2..23 {
            let next = sizes[index - 1] + sizes[index - 2] + 1;
            sizes.push(next);
        }
        let max = (1i64 << 53) / 8;
        while sizes.len() < 154 {
            let prev = *sizes.last().unwrap();
            let next = prev + prev / 5;
            if next <= prev || next > max {
                break;
            }
            sizes.push(next);
        }
        sizes
    });
    if size < sizes[0] {
        return sizes[0];
    }
    match sizes.binary_search(&size) {
        Ok(index) => sizes[index],
        Err(index) => sizes.get(index).copied().unwrap_or(*sizes.last().unwrap()),
    }
}

fn multi_scheduling(value: Term) -> Result<Term, VmError> {
    let next = match atom_name(value).as_deref() {
        Some("block") => "blocked",
        Some("unblock") => "enabled",
        Some("block_normal") => "blocked_normal",
        Some("unblock_normal") => "enabled",
        _ => return Err(badarg()),
    };
    with_flags(|flags| {
        flags.multi = next;
        Ok(atom(next))
    })
}

fn schedulers_online(value: Term, dirty: bool) -> Result<Term, VmError> {
    let requested = value.as_small().ok_or_else(badarg)?;
    let cpus = logical_processors() as i64;
    if requested < 1 || requested > cpus {
        return Err(badarg());
    }
    with_flags(|flags| {
        // Port of erts/emulator/beam/bif.c:5015 and :5178
        // (system_flag_2 scheduler controls), OTP-29.1.1.
        // Normal schedulers bound the number of dirty CPU schedulers online.
        let previous = if dirty {
            if requested as usize > flags.schedulers_online {
                return Err(badarg());
            }
            let previous = flags.dirty_cpu_online;
            flags.dirty_cpu_online = requested as usize;
            previous
        } else {
            let previous = flags.schedulers_online;
            flags.schedulers_online = requested as usize;
            flags.dirty_cpu_online = flags.dirty_cpu_online.min(flags.schedulers_online);
            previous
        };
        Term::small(previous as i64).ok_or_else(badarg)
    })
}

fn fullsweep_after(value: Term) -> Result<Term, VmError> {
    let requested = value.as_small().filter(|n| *n >= 0).ok_or_else(badarg)?;
    let stored = u16::try_from(requested).unwrap_or(u16::MAX);
    with_flags(|flags| {
        let previous = flags.fullsweep_after;
        flags.fullsweep_after = stored;
        Ok(Term::small(i64::from(previous)).unwrap())
    })
}

fn heap_minimum(value: Term, heap: bool) -> Result<Term, VmError> {
    let requested = value.as_small().filter(|n| *n >= 0).ok_or_else(badarg)?;
    let rounded = next_heap_size(requested);
    with_flags(|flags| {
        let slot = if heap {
            &mut flags.min_heap_size
        } else {
            &mut flags.min_bin_vheap_size
        };
        let previous = *slot;
        *slot = rounded;
        Term::small(previous).ok_or_else(badarg)
    })
}

fn backtrace_depth(vm: &mut Vm, value: Term) -> Result<Term, VmError> {
    let requested = value.as_small().filter(|n| *n >= 0).ok_or_else(badarg)?;
    let previous = vm.backtrace_depth;
    vm.backtrace_depth = (requested as usize).min(64);
    Term::small(previous as i64).ok_or_else(badarg)
}

fn trace_control_word(value: Term) -> Result<Term, VmError> {
    let requested = value.as_small().ok_or_else(badarg)?;
    with_flags(|flags| {
        let previous = flags.trace_word;
        flags.trace_word = requested;
        Term::small(previous).ok_or_else(badarg)
    })
}

fn outstanding_limit(value: Term) -> Result<Term, VmError> {
    let requested = value.as_small().filter(|n| *n > 0).ok_or_else(badarg)?;
    with_flags(|flags| {
        let previous = flags.outstanding;
        flags.outstanding = requested as u64;
        Term::small(i64::try_from(previous).unwrap_or(i64::MAX)).ok_or_else(badarg)
    })
}

fn scheduling_statistics(value: Term) -> Result<Term, VmError> {
    match atom_name(value).as_deref() {
        Some("enable" | "disable" | "clear") => Ok(atom("true")),
        _ => Err(badarg()),
    }
}

fn max_heap_flag(process: &mut Process, value: Term) -> Result<Term, VmError> {
    let parsed = parse_system_max_heap(value)?;
    let previous = with_flags(|flags| {
        let old = flags.max_heap;
        if parsed.size < flags.min_heap_size as u64 && parsed.size != 0 {
            return Err(badarg());
        }
        flags.max_heap = parsed;
        Ok(old)
    })?;
    max_heap_map(process, previous)
}

fn parse_system_max_heap(value: Term) -> Result<crate::process::MaxHeap, VmError> {
    let mut limit = crate::process::MaxHeap::default();
    if let Some(size) = value.as_small() {
        if size < 0 {
            return Err(badarg());
        }
        limit.size = size as u64;
        return Ok(limit);
    }
    if value.classify() != TermKind::Map {
        return Err(badarg());
    }
    // SAFETY: The flag map stays rooted in the caller's registers.
    let map = unsafe { value.flatmap_ref() }.ok_or_else(badarg)?;
    let size = map
        .get(atom("size"))
        .and_then(|term| term.as_small())
        .filter(|size| *size >= 0)
        .ok_or_else(badarg)?;
    limit.size = size as u64;
    let boolean = |key: &str| -> Result<Option<bool>, VmError> {
        match map.get(atom(key)) {
            None => Ok(None),
            Some(term) if term == atom("true") => Ok(Some(true)),
            Some(term) if term == atom("false") => Ok(Some(false)),
            Some(_) => Err(badarg()),
        }
    };
    if let Some(kill) = boolean("kill")? {
        limit.kill = kill;
    }
    if let Some(log) = boolean("error_logger")? {
        limit.log = log;
    }
    if let Some(include) = boolean("include_shared_binaries")? {
        limit.include_shared_binaries = include;
    }
    Ok(limit)
}

fn max_heap_map(process: &mut Process, limit: crate::process::MaxHeap) -> Result<Term, VmError> {
    let size = Term::small(i64::try_from(limit.size).map_err(|_| badarg())?).ok_or_else(badarg)?;
    let pairs = [
        (
            atom("error_logger"),
            atom(if limit.log { "true" } else { "false" }),
        ),
        (
            atom("include_shared_binaries"),
            atom(if limit.include_shared_binaries {
                "true"
            } else {
                "false"
            }),
        ),
        (
            atom("kill"),
            atom(if limit.kill { "true" } else { "false" }),
        ),
        (atom("size"), size),
    ];
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&pairs)
        .map_err(|error| VmError::Unsupported(format!("max_heap_size map: {error:?}")))
}

fn set_microstate(value: Term) -> Result<Term, VmError> {
    let previous = MICROSTATE.load(Ordering::Relaxed);
    match atom_name(value).as_deref() {
        Some("true") => MICROSTATE.store(true, Ordering::Relaxed),
        Some("false") => MICROSTATE.store(false, Ordering::Relaxed),
        Some("reset") => {}
        _ => return Err(badarg()),
    }
    Ok(atom(if previous { "true" } else { "false" }))
}

fn garbage_collect(process: &mut Process, arg: Term) -> Result<Term, VmError> {
    let major = match atom_name(arg).as_deref() {
        Some("major") => true,
        Some("minor") => false,
        _ => return Err(badarg()),
    };
    if major {
        process.heap.set_fullsweep_after(0);
    }
    let live = 1;
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8257 (on-heap mailbox roots), OTP-29.1.1.
    let collected = process.collect_heap_roots(live, &mut [], 0);
    if major {
        process.heap.set_fullsweep_after(u16::MAX);
    }
    let gc = collected.map_err(|error| VmError::Unsupported(format!("GC {error:?}")))?;
    process.stats.gc.collections += gc.collections;
    process.stats.gc.nanoseconds += gc.nanoseconds;
    after_collection(process, live, gc.collections, gc.words_reclaimed);
    Ok(atom("true"))
}

fn salvage_retired(process: &mut Process, live_x: usize) -> Result<(), VmError> {
    let store = arinsal_pterm::global_store();
    let areas = store.retired_areas(&process._persistent_terms);
    if areas.is_empty() {
        return Ok(());
    }
    let copied = rewrite_roots(process, live_x, &areas)?;
    drop(areas);
    store.release_retired(&process._persistent_terms, u64::from(copied));
    Ok(())
}

fn rewrite_roots(
    process: &mut Process,
    live_x: usize,
    areas: &[RetiredArea],
) -> Result<u32, VmError> {
    let mut copied = 0_u32;
    let live = live_x.min(process.x.len());
    for index in 0..live {
        let term = process.x[index];
        let (term, did) = rewrite_root(process, term, areas)?;
        process.x[index] = term;
        copied += u32::from(did);
    }
    let depth = process.heap.stack_words();
    for index in 0..depth {
        let Some(term) = process.heap.stack_get(index) else {
            continue;
        };
        let (term, did) = rewrite_root(process, term, areas)?;
        process.heap.stack_set(index, term);
        copied += u32::from(did);
    }
    // Off-heap message fragments remain owned by the queue and are not roots.
    // Port of erts/emulator/beam/erl_proc_sig_queue.c:8460 (off-heap queue GC handling), OTP-29.1.1.
    let (indices, mut inbox) = process.inbox.gc_root_snapshot();
    for term in &mut inbox {
        let (updated, did) = rewrite_root(process, *term, areas)?;
        *term = updated;
        copied += u32::from(did);
    }
    process.inbox.update_gc_roots(&indices, &inbox);
    Ok(copied)
}

fn rewrite_root(
    process: &mut Process,
    term: Term,
    areas: &[RetiredArea],
) -> Result<(Term, bool), VmError> {
    if !references_retired(term, areas) {
        return Ok((term, false));
    }
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let copied = copy_term(term, &mut heap)
        .map_err(|error| VmError::Unsupported(format!("literal copy {error:?}")))?;
    Ok((copied, true))
}

fn references_retired(term: Term, areas: &[RetiredArea]) -> bool {
    let mut stack = vec![term];
    let mut seen = HashSet::new();
    while let Some(term) = stack.pop() {
        if !term.is_pointer() {
            continue;
        }
        // SAFETY: a pointer term addresses an aligned heap word while the process is stopped.
        let addr = unsafe { term.raw_ptr() as usize };
        if !seen.insert(addr) {
            continue;
        }
        if areas.iter().any(|area| area.contains(term)) {
            return true;
        }
        push_children(term, &mut stack);
    }
    false
}

/// Rebuild a tagged word stored inside a live boxed object.
fn term_word(word: u64) -> Term {
    // SAFETY: `Term` is a single-field tuple struct over the heap word.
    unsafe { std::mem::transmute(word) }
}

fn push_children(term: Term, out: &mut Vec<Term>) {
    if term.classify() == TermKind::List {
        // SAFETY: list classification means a live cons cell on a stable heap.
        if let Some((head, tail)) = unsafe { term.cons_ref() } {
            out.push(head);
            out.push(tail);
        }
        return;
    }
    let Some(header) = term.header() else {
        return;
    };
    let tag = header & 63;
    // SAFETY: header() only succeeds for a live boxed term.
    let ptr = unsafe { term.raw_ptr() };
    match tag {
        ARITY => {
            // SAFETY: the arity header describes this live tuple.
            if let Some(tuple) = unsafe { term.tuple_ref() } {
                out.extend(tuple.iter());
            }
        }
        MAP => {
            // SAFETY: boxed_object_words requires this live map header.
            let words = unsafe { arinsal_term::boxed_object_words(header, ptr) };
            let start = if (header >> 6) & 3 == 1 { 1 } else { 2 };
            for index in start..words {
                // SAFETY: the child range is inside this initialized map.
                let child = term_word(unsafe { *ptr.add(index) });
                if child.is_pointer() {
                    out.push(child);
                }
            }
        }
        SUB_BITS => {
            // SAFETY: SUB_BITS word four is its original term.
            out.push(term_word(unsafe { *ptr.add(4) }));
        }
        FUN => {
            // SAFETY: the fun view is valid while the process heap is stable.
            if let Some(fun) = unsafe { term.fun_ref() } {
                let mut index = 0;
                while let Some(value) = fun.free(index) {
                    out.push(value);
                    index += 1;
                }
            }
        }
        RECORD => {
            // SAFETY: the record view is valid while the process heap is stable.
            if let Some(record) = unsafe { term.record_ref() } {
                for index in 0..record.len() {
                    if let Some(value) = record.value(index) {
                        out.push(value);
                    }
                }
            }
        }
        _ => {}
    }
}

fn reduction_total(ctx: Option<&RunCtx<'_, Message>>) -> u64 {
    let slice = ctx
        .map(|ctx| u64::from(QUANTUM.saturating_sub(ctx.remaining())))
        .unwrap_or(0);
    COMPLETED_REDUCTIONS.load(Ordering::Relaxed) + slice
}

fn since(total: u64, last: &AtomicU64) -> (u64, u64) {
    let previous = last.swap(total, Ordering::Relaxed);
    (total, total.saturating_sub(previous))
}

fn cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes the timespec we own and does not retain it.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + ts.tv_nsec as u64
}

fn runtime_ms() -> u64 {
    let now = cpu_ns();
    let origin = *CPU_ORIGIN_NS.get_or_init(|| now);
    now.saturating_sub(origin) / 1_000_000
}

fn wall_ms() -> u64 {
    let origin = *WALL_ORIGIN.get_or_init(Instant::now);
    u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn logical_processors() -> usize {
    std::thread::available_parallelism().map_or(1, |count| count.get())
}

fn live_processes(process: &Process) -> usize {
    process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler().ok())
        .map(|scheduler| scheduler.live_count())
        .unwrap_or(0)
}

fn run_queue(process: &Process) -> u64 {
    live_processes(process).saturating_sub(1) as u64
}

fn active_tasks(process: &Process) -> u64 {
    live_processes(process) as u64
}

fn queue_slots(extra: usize, head: u64) -> Vec<u64> {
    let mut slots = vec![0; logical_processors() + extra];
    if let Some(slot) = slots.first_mut() {
        *slot = head;
    }
    slots
}

fn scheduler_wall(process: &mut Process, include_dirty_io: bool) -> Result<Term, VmError> {
    let base = *SCHED_WALL.lock().expect("scheduler wall time");
    let Some(base) = base else {
        return Ok(atom("undefined"));
    };
    let total_us = u64::try_from(base.started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let active_us = cpu_ns().saturating_sub(base.cpu_ns) / 1_000;
    let n = logical_processors() as u64;
    let mut entries = Vec::new();
    for id in 1..=n {
        let active = if id == 1 { active_us } else { 0 };
        entries.push(triple(process, id, active, total_us)?);
    }
    for id in 1..=n {
        entries.push(triple(process, n + id, 0, total_us)?);
    }
    if include_dirty_io {
        for id in 1..=n {
            entries.push(triple(process, 2 * n + id, 0, total_us)?);
        }
    }
    cons_list(process, &entries)
}

fn microstate(process: &mut Process) -> Result<Term, VmError> {
    if !MICROSTATE.load(Ordering::Relaxed) {
        return Ok(atom("undefined"));
    }
    let n = logical_processors() as i64;
    let gc = i64::try_from(GC_COUNT.load(Ordering::Relaxed)).unwrap_or(i64::MAX);
    let emulator = i64::try_from(runtime_ms().saturating_mul(1_000)).unwrap_or(i64::MAX);
    let sleep = i64::try_from(
        wall_ms()
            .saturating_mul(1_000)
            .saturating_sub(runtime_ms() * 1_000),
    )
    .unwrap_or(0);
    let mut entries = Vec::new();
    for id in 1..=n {
        let active = if id == 1 { emulator } else { 0 };
        entries.push(msacc_entry(process, id, "scheduler", active, gc, sleep)?);
    }
    for id in 1..=n {
        entries.push(msacc_entry(
            process,
            id,
            "dirty_cpu_scheduler",
            0,
            0,
            sleep,
        )?);
    }
    for id in 1..=n {
        entries.push(msacc_entry(process, id, "dirty_io_scheduler", 0, 0, sleep)?);
    }
    entries.push(msacc_entry(process, 1, "aux", 0, 0, sleep)?);
    entries.push(msacc_entry(process, 0, "poll", 0, 0, sleep)?);
    entries.push(msacc_entry(process, 0, "async", 0, 0, sleep)?);
    cons_list(process, &entries)
}

fn msacc_entry(
    process: &mut Process,
    id: i64,
    kind: &str,
    emulator: i64,
    gc: i64,
    sleep: i64,
) -> Result<Term, VmError> {
    let counters = map(
        process,
        &[
            ("aux", small(0)),
            ("check_io", small(0)),
            ("emulator", small(emulator)),
            ("gc", small(gc)),
            ("other", small(0)),
            ("port", small(0)),
            ("sleep", small(sleep)),
        ],
    )?;
    map(
        process,
        &[
            ("counters", counters),
            ("id", small(id)),
            ("type", atom(kind)),
        ],
    )
}

fn io_counters(process: &mut Process) -> Result<Term, VmError> {
    // Port byte totals stay zero until port read/write paths publish counters.
    let input = tagged(process, "input", 0)?;
    let output = tagged(process, "output", 0)?;
    tuple(process, &[input, output])
}

fn small(value: i64) -> Term {
    Term::small(value).unwrap_or(Term::NIL)
}

fn check_io_info(process: &mut Process) -> Result<Term, VmError> {
    // Port of erts_check_io_info in erts/emulator/sys/common/erl_check_io.c:2675,
    // OTP-29.1.1. The fallback and scheduler sets are part of OTP's Mac layout.
    let entries = [
        (
            "select", "false", 13_536, "true", "false", "false", "true", 0, 2,
        ),
        (
            "kqueue", "kqueue", 56, "false", "false", "true", "false", 0, 1,
        ),
        (
            "kqueue", "kqueue", 65_592, "false", "false", "true", "false", 1, 1,
        ),
    ];
    let mut sets = Vec::with_capacity(entries.len());
    for (primary, kernel_poll, memory, lazy, batch, concurrent, fallback, poll_threads, set_size) in
        entries
    {
        let properties = [
            ("name", atom("erts_poll")),
            ("primary", atom(primary)),
            ("kernel_poll", atom(kernel_poll)),
            ("memory_size", non_neg(process, memory)?),
            ("total_poll_set_size", small(set_size)),
            ("lazy_updates", atom(lazy)),
            ("pending_updates", small(0)),
            ("batch_updates", atom(batch)),
            ("concurrent_updates", atom(concurrent)),
            ("fallback", atom(fallback)),
            ("max_fds", non_neg(process, 1_048_576)?),
            ("active_fds", small(0)),
            ("poll_threads", small(poll_threads)),
        ];
        let properties = properties
            .iter()
            .map(|(key, value)| tuple(process, &[atom(key), *value]))
            .collect::<Result<Vec<_>, _>>()?;
        sets.push(cons_list(process, &properties)?);
    }
    cons_list(process, &sets)
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("runtime atom"))
}

fn atom_name(term: Term) -> Option<std::sync::Arc<str>> {
    global_atoms().text(term.as_atom()?)
}

fn non_neg(process: &mut Process, value: u64) -> Result<Term, VmError> {
    if let Ok(value) = i64::try_from(value)
        && let Some(term) = Term::small(value)
    {
        return Ok(term);
    }
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    TermBuilder::new(&mut heap)
        .int_from_bigint(&num_bigint::BigInt::from(value))
        .map_err(|_| badarg())
}

fn pair(process: &mut Process, a: u64, b: u64) -> Result<Term, VmError> {
    let a = non_neg(process, a)?;
    let b = non_neg(process, b)?;
    tuple(process, &[a, b])
}

fn triple(process: &mut Process, a: u64, b: u64, c: u64) -> Result<Term, VmError> {
    let a = non_neg(process, a)?;
    let b = non_neg(process, b)?;
    let c = non_neg(process, c)?;
    tuple(process, &[a, b, c])
}

fn tagged(process: &mut Process, name: &str, value: u64) -> Result<Term, VmError> {
    let value = non_neg(process, value)?;
    tuple(process, &[atom(name), value])
}

fn tuple(process: &mut Process, terms: &[Term]) -> Result<Term, VmError> {
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    TermBuilder::new(&mut heap)
        .tuple(terms)
        .map_err(|_| badarg())
}

fn cons_list(process: &mut Process, terms: &[Term]) -> Result<Term, VmError> {
    let mut list = Term::NIL;
    for term in terms.iter().rev() {
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        list = TermBuilder::new(&mut heap)
            .cons(*term, list)
            .map_err(|_| badarg())?;
    }
    Ok(list)
}

fn int_list(process: &mut Process, values: &[u64]) -> Result<Term, VmError> {
    let mut terms = Vec::with_capacity(values.len());
    for value in values {
        terms.push(non_neg(process, *value)?);
    }
    cons_list(process, &terms)
}

fn int_tuple(process: &mut Process, values: &[u64]) -> Result<Term, VmError> {
    let mut terms = Vec::with_capacity(values.len());
    for value in values {
        terms.push(non_neg(process, *value)?);
    }
    tuple(process, &terms)
}

fn map(process: &mut Process, pairs: &[(&str, Term)]) -> Result<Term, VmError> {
    let pairs: Vec<(Term, Term)> = pairs
        .iter()
        .map(|(key, value)| (atom(key), *value))
        .collect();
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    arinsal_maps::from_list(&pairs, &mut heap).map_err(|_| badarg())
}

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom("badarg")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_difftest::{CallResult, RefErl};
    #[test]
    fn garbage_collect_result_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping garbage_collect differential test");
            return;
        };
        for mode in ["major", "minor"] {
            let expected =
                reference.call("erts_internal", "garbage_collect", &[OwnedTerm::atom(mode)]);
            let term = Term::atom(global_atoms().intern(mode).unwrap());
            let actual = garbage_collect(&mut Process::new(), term)
                .and_then(|term| to_owned(term).map_err(|_| badarg()));
            assert_eq!(expected, CallResult::Ok(actual.unwrap()));
        }
    }

    #[test]
    fn debug_compiled_system_info_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping system_info differential test");
            return;
        };
        let expected = reference.call(
            "erlang",
            "system_info",
            &[OwnedTerm::atom("debug_compiled")],
        );
        let selector = Term::atom(global_atoms().intern("debug_compiled").unwrap());
        let actual = system_info(&Vm::new([]), &mut Process::new(), selector)
            .unwrap()
            .unwrap();
        assert_eq!(expected, CallResult::Ok(to_owned(actual).unwrap()));
    }

    #[test]
    fn check_io_info_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping check_io info differential test");
            return;
        };
        let expected = reference.call("erlang", "system_info", &[OwnedTerm::atom("check_io")]);
        let selector = Term::atom(global_atoms().intern("check_io").unwrap());
        let mut process = Process::new();
        let actual = system_info(&Vm::new([]), &mut process, selector)
            .unwrap()
            .unwrap();
        let CallResult::Ok(expected) = expected else {
            panic!("OTP check_io system_info failed: {expected:?}");
        };
        let mut expected = expected;
        let mut actual = to_owned(actual).unwrap();
        normalize_check_io_counters(&mut expected);
        normalize_check_io_counters(&mut actual);
        assert_eq!(expected, actual);
    }

    fn normalize_check_io_counters(term: &mut OwnedTerm) {
        match term {
            OwnedTerm::List { elems, tail } => {
                for elem in elems {
                    normalize_check_io_counters(elem);
                }
                normalize_check_io_counters(tail);
            }
            OwnedTerm::Tuple(elems) => {
                if elems.len() == 2
                    && matches!(
                        &elems[0],
                        OwnedTerm::Atom(key)
                            if matches!(
                                key.as_str(),
                                "total_poll_set_size"
                                    | "pending_updates"
                                    | "active_fds"
                                    | "poll_threads"
                            )
                    )
                {
                    elems[1] = OwnedTerm::Atom("volatile_counter".into());
                }
                for elem in elems {
                    normalize_check_io_counters(elem);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn wordsize_and_ethread_info_system_selectors_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping system_info selector differential test");
            return;
        };
        for selector in [
            OwnedTerm::Tuple(vec![
                OwnedTerm::atom("wordsize"),
                OwnedTerm::atom("internal"),
            ]),
            OwnedTerm::Tuple(vec![
                OwnedTerm::atom("wordsize"),
                OwnedTerm::atom("external"),
            ]),
            OwnedTerm::atom("ethread_info"),
        ] {
            let expected = reference.call("erlang", "system_info", std::slice::from_ref(&selector));
            let mut heap = VecHeap::new();
            let selector_term = from_owned(&selector, &mut heap).unwrap();
            let mut process = Process::new();
            let actual = system_info(&Vm::new([]), &mut process, selector_term)
                .unwrap()
                .unwrap();
            assert_eq!(expected, CallResult::Ok(to_owned(actual).unwrap()));
        }
    }

    #[test]
    fn display_string_empty_matches_otp() {
        let Ok(reference) = std::process::Command::new("erl")
            .args([
                "-noshell",
                "-eval",
                "io:format(\"~p~n\", [erlang:display_string(stderr, [])]), halt().",
            ])
            .output()
        else {
            eprintln!("erl unavailable; skipping display_string differential test");
            return;
        };
        assert!(reference.status.success());
        let actual = display_string(&[
            Term::atom(global_atoms().intern("stderr").unwrap()),
            Term::NIL,
        ])
        .unwrap();
        assert_eq!(reference.stdout, b"true\n");
        assert_eq!(to_owned(actual).unwrap(), OwnedTerm::atom("true"));
    }
    use arinsal_etf::OwnedTerm;
    use arinsal_term::{VecHeap, from_owned, to_owned};

    #[test]
    fn statistics_shapes_and_badarg_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping statistics differential test");
            return;
        };
        for key in [
            "runtime",
            "wall_clock",
            "reductions",
            "exact_reductions",
            "run_queue",
            "run_queue_lengths",
            "total_run_queue_lengths",
            "context_switches",
            "garbage_collection",
            "io",
            "scheduler_wall_time",
            "total_active_tasks",
            "active_tasks",
        ] {
            let expected = reference.call("erlang", "statistics", &[OwnedTerm::atom(key)]);
            let mut input_heap = VecHeap::new();
            let input = from_owned(&OwnedTerm::atom(key), &mut input_heap).unwrap();
            let mut process = Process::new();
            let vm = Vm::new([]);
            let actual = statistics(&vm, &mut process, None, input)
                .and_then(|term| to_owned(term).map_err(|_| badarg()));
            match (actual, expected) {
                (Ok(OwnedTerm::Int(_)), CallResult::Ok(OwnedTerm::Int(_)))
                | (Ok(OwnedTerm::Tuple(_)), CallResult::Ok(OwnedTerm::Tuple(_)))
                | (Ok(OwnedTerm::List { .. }), CallResult::Ok(OwnedTerm::List { .. }))
                | (Ok(OwnedTerm::Atom(_)), CallResult::Ok(OwnedTerm::Atom(_))) => {}
                (actual, expected) => {
                    panic!("statistics({key}) shape mismatch: {actual:?} / {expected:?}")
                }
            }
        }
        let mut heap = VecHeap::new();
        let micro = from_owned(&OwnedTerm::atom("microstate_accounting"), &mut heap).unwrap();
        let actual = statistics(&Vm::new([]), &mut Process::new(), None, micro)
            .and_then(|term| to_owned(term).map_err(|_| badarg()))
            .expect("microstate");
        assert_eq!(actual, OwnedTerm::atom("undefined"));
        let invalid = from_owned(&OwnedTerm::atom("invalid"), &mut heap).unwrap();
        assert!(statistics(&Vm::new([]), &mut Process::new(), None, invalid).is_err());
    }
}

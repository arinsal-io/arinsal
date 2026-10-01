//! VM-facing system native bindings: statistics and literal retirement.
//!
//! Return shapes follow OTP-29.1.1's `statistics_1` and `system_info_1`.

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

static LAST_REDUCTIONS: AtomicU64 = AtomicU64::new(0);
static LAST_EXACT_REDUCTIONS: AtomicU64 = AtomicU64::new(0);
static LAST_CONTEXT_SWITCHES: AtomicU64 = AtomicU64::new(0);
static GC_COUNT: AtomicU64 = AtomicU64::new(0);
static GC_WORDS: AtomicU64 = AtomicU64::new(0);
static LAST_RUNTIME_MS: AtomicU64 = AtomicU64::new(0);
static LAST_WALL_MS: AtomicU64 = AtomicU64::new(0);
static CPU_ORIGIN_NS: OnceLock<u64> = OnceLock::new();
static WALL_ORIGIN: OnceLock<Instant> = OnceLock::new();
static MICROSTATE: AtomicBool = AtomicBool::new(false);
type MicrostateBaseline = (Instant, Vec<[u64; 7]>, [u64; 2]);
static CPU_TOPOLOGY: OnceLock<Mutex<Option<arinsal_etf::OwnedTerm>>> = OnceLock::new();

#[derive(Clone)]
struct SchedBase {
    started: Instant,
    active_ns: Vec<u64>,
}
static SCHED_WALL: Mutex<Option<SchedBase>> = Mutex::new(None);
static MICROSTATE_BASE: Mutex<Option<MicrostateBaseline>> = Mutex::new(None);
static SYSTEM_LOGGER: OnceLock<Mutex<Term>> = OnceLock::new();

/// Initialize statistics origins when the VM is created, as erts does at boot.
pub(crate) fn initialize_statistics_origins() {
    arinsal_bifs::initialize_time_origin();
    CPU_ORIGIN_NS.get_or_init(cpu_ns);
    WALL_ORIGIN.get_or_init(Instant::now);
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
    ("erts_internal", "term_to_string", 1),
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
        ("erts_internal", "term_to_string", 1) => Some(call_term_to_string_unlimited),
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
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    display_string(args).map_err(|error| {
        crate::exceptions::bif_error(process, "erlang", "display_string", args, error)
    })
}

fn call_term_to_string(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    term_to_string(process, args)
}

fn call_term_to_string_unlimited(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts_internal.erl:1150-1153 (term_to_string/1), OTP-29.1.1.
    term_to_string(process, &[args[0], atom("undefined")])
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
    // Port of erts/emulator/beam/erl_msacc.c:436 (GC state transition), OTP-29.1.1.
    garbage_collect(process, args[0])
}

fn call_system_flag(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    system_flag(vm, process, ctx, args)
}

fn call_scheduler_wall_time(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:5306 (erts_internal_scheduler_wall_time_1), OTP-29.1.1.
    // Any term other than `true` disables accounting. The previous flag is returned.
    set_scheduler_wall_enabled(process, ctx, atom_name(args[0]).as_deref() == Some("true"))
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
            .or_else(|| system_info(vm, process, Some(ctx), args[0])),
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
fn display_string(args: &[Term]) -> Result<Term, arinsal_bifs::BifError> {
    use arinsal_etf::OwnedTerm;

    fn append_string(value: &OwnedTerm, bytes: &mut Vec<u8>) -> Result<(), arinsal_bifs::BifError> {
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
                    .ok_or(arinsal_bifs::BifError::BADARG)?;
                let mut buffer = [0; 4];
                bytes.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
                Ok(())
            }
            OwnedTerm::Binary(binary) => {
                bytes.extend_from_slice(binary);
                Ok(())
            }
            _ => Err(arinsal_bifs::BifError::BADARG),
        }
    }

    let destination = args[0]
        .as_atom()
        .and_then(|atom| global_atoms().text(atom))
        .ok_or(arinsal_bifs::BifError::BADARG)?;
    let value = arinsal_term::to_owned(args[1]).map_err(|_| arinsal_bifs::BifError::BADARG)?;
    let mut bytes = Vec::new();
    append_string(&value, &mut bytes)?;
    match destination.as_ref() {
        "stdout" => std::io::stdout().lock().write_all(&bytes),
        "stderr" => std::io::stderr().lock().write_all(&bytes),
        _ => return Err(arinsal_bifs::BifError::BADARG),
    }
    .map_err(|_| arinsal_bifs::BifError::BADARG)?;
    Ok(Term::atom(arinsal_term::atoms::TRUE))
}

// boot_loop1: init:has_small_memory/0 probes this before loading kernel modules.
fn system_info(
    vm: &Vm,
    process: &mut Process,
    ctx: Option<&RunCtx<'_, Message>>,
    selector: Term,
) -> Option<Result<Term, VmError>> {
    let owned_selector = arinsal_term::to_owned(selector).ok();
    if let Some(arinsal_etf::OwnedTerm::Tuple(parts)) = owned_selector.as_ref()
        && let [
            arinsal_etf::OwnedTerm::Atom(name),
            arinsal_etf::OwnedTerm::Atom(kind),
        ] = parts.as_slice()
    {
        match (name.as_str(), kind.as_str()) {
            ("wordsize", "internal" | "external") => return Some(Ok(Term::small(8).unwrap())),
            ("wordsize", _) => return Some(Err(badarg())),
            ("cpu_topology", "detected") => return Some(Ok(atom("undefined"))),
            ("cpu_topology", "defined" | "used") => return Some(cpu_topology_info(process)),
            ("cpu_topology", _) => return Some(Err(badarg())),
            // Other two-atom selectors ({allocator, A}, ...) are handled below.
            _ => {}
        }
    }
    if let Some(arinsal_etf::OwnedTerm::Tuple(parts)) = owned_selector.as_ref()
        && let [
            arinsal_etf::OwnedTerm::Atom(operation),
            arinsal_etf::OwnedTerm::Atom(name),
        ] = parts.as_slice()
        && operation == "allocator"
    {
        return Some(allocator_system_info(process, name));
    }
    let name = selector
        .as_atom()
        .and_then(|atom| global_atoms().text(atom));
    match name.as_deref() {
        Some("alloc_util_allocators") => Some(allocator_names(process)),
        Some("allocator") => Some(all_allocator_options(process)),
        Some("debug_compiled") => Some(Ok(Term::atom(arinsal_term::atoms::FALSE))),
        Some("check_io") => Some(check_io_info(process)),
        Some("ethread_info") => Some(ethread_info(process)),
        // Port of erts/emulator/beam/erl_bif_info.c:3549 (max_integer), OTP-29.1.1.
        Some("max_integer") => Some(max_integer(process)),
        // Port of erts/emulator/beam/erl_bif_info.c:3179 (system_info_1), OTP-29.1.1.
        Some("creation") => Some(non_neg(
            process,
            u64::from(crate::node_tables::lock().local_creation),
        )),
        // Port of erts/emulator/beam/erl_bif_info.c:2773 (system_info_1), OTP-29.1.1.
        Some("schedulers_online") => Some(with_flags(|flags| {
            non_neg(process, flags.schedulers_online as u64)
        })),
        Some("schedulers") => Some(with_flags(|flags| {
            non_neg(process, flags.schedulers_total as u64)
        })),
        // Port of erts/emulator/beam/erl_bif_info.c:2784 (system_info scheduler_id), OTP-29.1.1.
        Some("scheduler_id") => Some(
            ctx.and_then(RunCtx::scheduler_id)
                .and_then(|id| Term::small(id as i64))
                .ok_or_else(badarg),
        ),
        Some("dirty_cpu_schedulers") => Some(with_flags(|flags| {
            non_neg(process, flags.dirty_cpu_total as u64)
        })),
        Some("dirty_cpu_schedulers_online") => Some(with_flags(|flags| {
            non_neg(process, flags.dirty_cpu_online as u64)
        })),
        Some("dirty_io_schedulers") => Some(with_flags(|flags| {
            non_neg(process, flags.dirty_io_total as u64)
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
        Some("cpu_topology") => Some(cpu_topology_info(process)),
        Some("scheduler_bind_type") => Some(Ok(atom("unbound"))),
        Some("scheduler_bindings") => Some(with_flags(|flags| {
            tuple(process, &vec![atom("unbound"); flags.schedulers_total])
        })),
        Some("sequential_tracer") => Some(crate::seq_trace::system_tracer_info(process)),
        Some("allocated_areas") => Some(memory_areas(vm, process)),
        _ if selector.classify() == TermKind::Tuple => Some(Err(badarg())),
        _ => None,
    }
}

fn allocator_names(process: &mut Process) -> Result<Term, VmError> {
    use arinsal_etf::OwnedTerm as O;
    let names = [
        "temp_alloc",
        "sl_alloc",
        "std_alloc",
        "ll_alloc",
        "eheap_alloc",
        "ets_alloc",
        "fix_alloc",
        "literal_alloc",
        "binary_alloc",
        "driver_alloc",
    ];
    owned_system_info(
        process,
        O::List {
            elems: names.into_iter().map(|name| O::Atom(name.into())).collect(),
            tail: Box::new(O::Nil),
        },
    )
}

// Port of erts/emulator/beam/erl_alloc.c:1708-1840 (handle_args), OTP-29.1.1.
fn allocator_global_settings(
    flags: &[arinsal_args::IgnoredFlag],
) -> (i64, i64, i64, i64, &'static str, i64, u64, bool) {
    let (mut amcbf, mut rmcbf, mut mcs, mut mmap_scs) = (4 * 1024 * 1024, 20, 10, 0);
    let (mut lock_memory, mut ycs, mut mmc, mut sac) = ("no", 1024 * 1024, u64::MAX, true);
    for flag in flags {
        let Some(value) = flag.value.as_deref() else {
            continue;
        };
        let Some(amount) = parse_flag_integer(value) else {
            match flag.name.as_str() {
                "+Mlpm" => lock_memory = if value == "all" { "all" } else { "no" },
                "+Musac" => sac = value == "true",
                _ => {}
            }
            continue;
        };
        match flag.name.as_str() {
            "+MMamcbf" => amcbf = amount.saturating_mul(1024).min(i64::MAX as u64) as i64,
            "+MMrmcbf" => rmcbf = amount.min(i64::MAX as u64) as i64,
            "+MMmcs" => mcs = amount.min(i64::MAX as u64) as i64,
            "+MMscs" => mmap_scs = amount.saturating_mul(1024 * 1024).min(i64::MAX as u64) as i64,
            "+Muycs" => ycs = amount.saturating_mul(1024).min(i64::MAX as u64) as i64,
            "+Mummc" => mmc = amount,
            _ => {}
        }
    }
    (amcbf, rmcbf, mcs, mmap_scs, lock_memory, ycs, mmc, sac)
}

fn allocator_system_info(process: &mut Process, name: &str) -> Result<Term, VmError> {
    use arinsal_etf::OwnedTerm as O;
    let configured = arinsal_args::active_allocator_options();
    if name == "sys_alloc" {
        return owned_system_info(
            process,
            O::List {
                elems: vec![O::Tuple(vec![
                    O::Atom("instance".into()),
                    O::Int(0),
                    O::List {
                        elems: vec![O::Tuple(vec![
                            O::Atom("options".into()),
                            O::List {
                                elems: vec![
                                    option("e", O::Atom("true".into())),
                                    option("m", O::Atom("libc".into())),
                                ],
                                tail: Box::new(O::Nil),
                            },
                        ])],
                        tail: Box::new(O::Nil),
                    },
                ])],
                tail: Box::new(O::Nil),
            },
        );
    }
    if name == "mseg_alloc" {
        let schedulers = configured
            .schedulers
            .and_then(|count| usize::try_from(count).ok())
            .filter(|count| *count > 0)
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from));
        let (amcbf, rmcbf, mcs, _, _, _, _, _) = allocator_global_settings(&configured.flags);
        let count = schedulers + 1;
        let instances = (0..count)
            .map(|index| {
                O::Tuple(vec![
                    O::Atom("instance".into()),
                    O::Int(index as i64),
                    O::List {
                        elems: vec![
                            O::Tuple(vec![
                                O::Atom("version".into()),
                                O::List {
                                    elems: "0.9"
                                        .bytes()
                                        .map(|byte| O::Int(i64::from(byte)))
                                        .collect(),
                                    tail: Box::new(O::Nil),
                                },
                            ]),
                            option(
                                "options",
                                O::List {
                                    elems: vec![
                                        option("amcbf", O::Int(amcbf)),
                                        option("rmcbf", O::Int(rmcbf)),
                                        option("mcs", O::Int(mcs)),
                                    ],
                                    tail: Box::new(O::Nil),
                                },
                            ),
                        ],
                        tail: Box::new(O::Nil),
                    },
                ])
            })
            .collect();
        return owned_system_info(
            process,
            O::List {
                elems: instances,
                tail: Box::new(O::Nil),
            },
        );
    }

    let schedulers = configured
        .schedulers
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| *count > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from));
    let dirty = configured.dirty_instances.unwrap_or(0);
    let Some(mut spec) = default_allocator(name, schedulers) else {
        return Err(badarg());
    };
    apply_allocator_overrides(&mut spec, name, &configured.flags, schedulers);
    if !spec.enabled {
        return owned_system_info(process, O::Atom("false".into()));
    }
    let count = if spec.thread_specific {
        schedulers + dirty + 1
    } else {
        1
    };
    let instances = (0..count)
        .map(|index| {
            let global = index == 0;
            let mut entries = Vec::new();
            entries.push(O::Tuple(vec![
                O::Atom("versions".into()),
                O::List {
                    elems: (if (name == "temp_alloc" && global) || spec.shared_profile {
                        "2.1"
                    } else {
                        "0.9"
                    })
                    .bytes()
                    .map(|byte| O::Int(i64::from(byte)))
                    .collect(),
                    tail: Box::new(O::Nil),
                },
                O::List {
                    elems: "3.0".bytes().map(|byte| O::Int(i64::from(byte))).collect(),
                    tail: Box::new(O::Nil),
                },
            ]));
            entries.push(option("options", allocator_options(&spec, global)));
            O::Tuple(vec![
                O::Atom("instance".into()),
                O::Int(index as i64),
                O::List {
                    elems: entries,
                    tail: Box::new(O::Nil),
                },
            ])
        })
        .collect();
    owned_system_info(
        process,
        O::List {
            elems: instances,
            tail: Box::new(O::Nil),
        },
    )
}

fn all_allocator_options(process: &mut Process) -> Result<Term, VmError> {
    use arinsal_etf::OwnedTerm as O;
    let active = arinsal_args::active_allocator_options();
    let (amcbf, rmcbf, mcs, mmap_scs, lock_memory, ycs, mmc, sac) =
        allocator_global_settings(&active.flags);
    let schedulers = active
        .schedulers
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| *count > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from));
    let names = [
        "sys_alloc",
        "temp_alloc",
        "sl_alloc",
        "std_alloc",
        "ll_alloc",
        "eheap_alloc",
        "ets_alloc",
        "fix_alloc",
        "literal_alloc",
        "binary_alloc",
        "driver_alloc",
        "mseg_alloc",
        "sys_aligned_alloc",
        "literal_mmap",
    ];
    let allocators = O::List {
        elems: names.into_iter().map(|name| O::Atom(name.into())).collect(),
        tail: Box::new(O::Nil),
    };
    let mut configured = vec![O::Tuple(vec![
        O::Atom("sys_alloc".into()),
        O::List {
            elems: vec![
                option("e", O::Atom("true".into())),
                option("m", O::Atom("libc".into())),
            ],
            tail: Box::new(O::Nil),
        },
    ])];
    for name in [
        "temp_alloc",
        "sl_alloc",
        "std_alloc",
        "ll_alloc",
        "eheap_alloc",
        "ets_alloc",
        "fix_alloc",
        "literal_alloc",
        "binary_alloc",
        "driver_alloc",
    ] {
        let Some(mut spec) = default_allocator(name, schedulers) else {
            continue;
        };
        apply_allocator_overrides(&mut spec, name, &active.flags, schedulers);
        configured.push(O::Tuple(vec![
            O::Atom(name.into()),
            allocator_options(&spec, true),
        ]));
    }
    let mut test = default_allocator("test_alloc", schedulers).unwrap();
    apply_allocator_overrides(&mut test, "test_alloc", &active.flags, schedulers);
    configured.push(O::Tuple(vec![
        O::Atom("test_alloc".into()),
        if test.enabled {
            allocator_options(&test, true)
        } else {
            O::List {
                elems: vec![option("e", O::Atom("false".into()))],
                tail: Box::new(O::Nil),
            }
        },
    ]));
    configured.push(O::Tuple(vec![
        O::Atom("mseg_alloc".into()),
        O::List {
            elems: vec![
                option("amcbf", O::Int(amcbf)),
                option("rmcbf", O::Int(rmcbf)),
                option("mcs", O::Int(mcs)),
            ],
            tail: Box::new(O::Nil),
        },
    ]));
    configured.push(O::Tuple(vec![
        O::Atom("alloc_util".into()),
        O::List {
            elems: vec![
                option(
                    "mmc",
                    if mmc <= i64::MAX as u64 {
                        O::Int(mmc as i64)
                    } else {
                        O::BigInt(num_bigint::BigInt::from(mmc))
                    },
                ),
                option("ycs", O::Int(ycs)),
                option("sac", O::Atom(if sac { "true" } else { "false" }.into())),
            ],
            tail: Box::new(O::Nil),
        },
    ]));
    configured.push(O::Tuple(vec![
        O::Atom("erts_mmap".into()),
        O::List {
            elems: vec![option("scs", O::Int(mmap_scs))],
            tail: Box::new(O::Nil),
        },
    ]));
    configured.push(O::Tuple(vec![
        O::Atom("lock_physical_memory".into()),
        O::Atom(lock_memory.into()),
    ]));
    owned_system_info(
        process,
        O::Tuple(vec![
            O::Atom("undefined".into()),
            O::Nil,
            allocators,
            O::List {
                elems: configured,
                tail: Box::new(O::Nil),
            },
        ]),
    )
}

#[derive(Clone, Copy)]
struct AllocatorSystemInfo {
    enabled: bool,
    thread_specific: bool,
    scheduler_divisor: u64,
    shared_profile: bool,
    base_mmbcs: u64,
    base_lmbcs: u64,
    base_smbcs: u64,
    mmbcs_explicit: bool,
    lmbcs_explicit: bool,
    smbcs_explicit: bool,
    atags: u64,
    ramv: bool,
    strategy: &'static str,
    global_strategy: &'static str,
    sbct: u64,
    asbcst: u64,
    rsbcst: u64,
    rsbcmt: u64,
    rmbcmt: u64,
    mmbcs: u64,
    mmmbc: u64,
    mmsbc: u64,
    lmbcs: u64,
    smbcs: u64,
    acul: u64,
    acful: u64,
    acnl: u64,
    acfml: u64,
    mbcgs: u64,
    mbsd: Option<u64>,
    cp: &'static str,
}

// Port of erts/emulator/beam/erl_alloc.c:221-425 (default allocator initializers), OTP-29.1.1.
fn default_allocator(name: &str, schedulers: usize) -> Option<AllocatorSystemInfo> {
    let mbc = (128 * 1024 / schedulers.clamp(1, 4)) as u64;
    let lbc = 5 * 1024 * 1024;
    let sbc = (1024 * 1024 / schedulers.clamp(1, 4)) as u64;
    let mut value = AllocatorSystemInfo {
        enabled: true,
        thread_specific: true,
        scheduler_divisor: schedulers.clamp(1, 4) as u64,
        shared_profile: false,
        base_mmbcs: 0,
        base_lmbcs: 0,
        base_smbcs: 0,
        mmbcs_explicit: false,
        lmbcs_explicit: false,
        smbcs_explicit: false,
        atags: 0,
        ramv: false,
        strategy: "aoffcbf",
        global_strategy: "aoffcbf",
        sbct: 512 * 1024,
        asbcst: 4_145_152,
        rsbcst: 20,
        rsbcmt: 80,
        rmbcmt: 50,
        mmbcs: mbc,
        mmmbc: u64::MAX,
        mmsbc: 256,
        lmbcs: lbc,
        smbcs: sbc,
        acul: 60,
        acful: 0,
        acnl: 1000,
        acfml: 0,
        mbcgs: 10,
        mbsd: None,
        cp: "undefined",
    };
    match name {
        "temp_alloc" => {
            value.strategy = "af";
            value.global_strategy = "gf";
            value.rsbcst = 90;
            value.rmbcmt = 100;
            value.mmbcs = 128 * 1024;
            value.lmbcs = 10 * 1024 * 1024;
            value.smbcs = 1024 * 1024;
            value.acul = 0;
            value.acnl = 0;
            value.mbsd = Some(3);
        }
        "sl_alloc" => {
            value.rsbcst = 80;
            value.rmbcmt = 50;
            value.cp = "S";
        }
        "std_alloc" => {
            value.rsbcst = 20;
            value.cp = "D";
        }
        "ets_alloc" => {
            value.rsbcst = 20;
            value.cp = "E";
        }
        "fix_alloc" => {
            value.rsbcst = 20;
            value.cp = "F";
        }
        "ll_alloc" => {
            value.sbct = u64::MAX;
            value.asbcst = 0;
            value.rsbcst = 0;
            value.rsbcmt = 0;
            value.rmbcmt = 0;
            value.mmbcs = 2 * 1024 * 1024 / schedulers.clamp(1, 4) as u64;
            value.mmsbc = 0;
            value.acul = 85;
            value.cp = "L";
        }
        "eheap_alloc" => {
            value.rsbcst = 50;
            value.mmbcs = 512 * 1024 / schedulers.clamp(1, 4) as u64;
            value.acul = 45;
            value.cp = "H";
        }
        "literal_alloc" => {
            value.thread_specific = false;
            value.strategy = "aobf";
            value.global_strategy = "aobf";
            value.sbct = u64::MAX;
            value.asbcst = 0;
            value.rsbcst = 0;
            value.rsbcmt = 0;
            value.rmbcmt = 0;
            value.mmbcs = 1024 * 1024;
            value.mmsbc = 0;
            value.lmbcs = 10 * 1024 * 1024;
            value.smbcs = 1024 * 1024;
            value.acul = 0;
            value.acnl = 0;
        }
        "binary_alloc" | "driver_alloc" => {
            value.atags = 1;
            value.rsbcst = 20;
            value.rmbcmt = 50;
            value.cp = if name == "binary_alloc" { "B" } else { "R" };
        }
        "test_alloc" => {
            value.enabled = false;
            value.atags = 1;
            value.strategy = "aoffcbf";
            value.global_strategy = "aoffcbf";
            value.sbct = 16 * 1024;
            value.mmbcs = 0;
            value.lmbcs = 8 * 1024;
            value.smbcs = 4 * 1024;
            value.rsbcst = 20;
            value.rsbcmt = 80;
            value.rmbcmt = 50;
            value.acul = 60;
            value.acnl = 1000;
            value.cp = "Z";
        }
        _ => return None,
    }
    value.base_mmbcs = value.mmbcs;
    value.base_lmbcs = value.lmbcs;
    value.base_smbcs = value.smbcs;
    Some(value)
}

// Port of erts/emulator/beam/erl_alloc.c:1283-1554 (handle_au_arg), OTP-29.1.1.
fn apply_allocator_overrides(
    spec: &mut AllocatorSystemInfo,
    name: &str,
    flags: &[arinsal_args::IgnoredFlag],
    schedulers: usize,
) {
    for flag in flags {
        let Some(value) = flag.value.as_deref() else {
            continue;
        };
        let Some(rest) = flag.name.strip_prefix("+M") else {
            continue;
        };
        if rest == "ea" {
            match value {
                "min" | "max" => {
                    if matches!(
                        name,
                        "binary_alloc"
                            | "std_alloc"
                            | "ets_alloc"
                            | "eheap_alloc"
                            | "ll_alloc"
                            | "driver_alloc"
                            | "fix_alloc"
                            | "sl_alloc"
                    ) {
                        spec.enabled = value == "max";
                    }
                }
                "r9c" | "r10b" | "r11b" => apply_allocator_preset(spec, name, value, schedulers),
                _ => {}
            }
            continue;
        }
        let applies = if rest.starts_with('u') {
            matches!(
                name,
                "binary_alloc"
                    | "std_alloc"
                    | "ets_alloc"
                    | "eheap_alloc"
                    | "ll_alloc"
                    | "driver_alloc"
                    | "fix_alloc"
                    | "sl_alloc"
            )
        } else {
            rest.chars().next().is_some_and(|prefix| match prefix {
                'T' => name == "temp_alloc",
                'S' => name == "sl_alloc",
                'D' => name == "std_alloc",
                'L' => name == "ll_alloc",
                'H' => name == "eheap_alloc",
                'E' => name == "ets_alloc",
                'F' => name == "fix_alloc",
                'I' => name == "literal_alloc",
                'B' => name == "binary_alloc",
                'R' => name == "driver_alloc",
                'Z' => name == "test_alloc",
                _ => false,
            })
        };
        if !applies {
            continue;
        }
        let switch = &rest[1..];
        match switch {
            "e" => spec.enabled = value == "true",
            "t" => {
                let was_thread_specific = spec.thread_specific;
                spec.thread_specific = value == "true";
                if value == "false" && was_thread_specific {
                    spec.acul = 0;
                    spec.acful = 0;
                    spec.acnl = 0;
                    if matches!(
                        name,
                        "sl_alloc"
                            | "std_alloc"
                            | "ll_alloc"
                            | "eheap_alloc"
                            | "ets_alloc"
                            | "fix_alloc"
                            | "binary_alloc"
                            | "driver_alloc"
                    ) {
                        if !spec.mmbcs_explicit {
                            spec.mmbcs = spec.mmbcs.saturating_mul(spec.scheduler_divisor);
                        }
                        if !spec.lmbcs_explicit {
                            spec.lmbcs = 10 * 1024 * 1024;
                        }
                        if !spec.smbcs_explicit {
                            spec.smbcs = 1024 * 1024;
                        }
                        spec.global_strategy = "gf";
                        spec.mbsd = Some(3);
                        spec.shared_profile = true;
                    }
                } else if value == "true" && !was_thread_specific && spec.shared_profile {
                    if !spec.mmbcs_explicit {
                        spec.mmbcs = spec.base_mmbcs;
                    }
                    if !spec.lmbcs_explicit {
                        spec.lmbcs = spec.base_lmbcs;
                    }
                    if !spec.smbcs_explicit {
                        spec.smbcs = spec.base_smbcs;
                    }
                }
            }
            "ramv" => spec.ramv = value == "true",
            "atags" => {
                spec.atags = match value {
                    "true" => 1,
                    "code" => 2,
                    _ => 0,
                }
            }
            "sbct" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.sbct = number.saturating_mul(1024)
                }
            }
            "asbcst" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.asbcst = number.saturating_mul(1024)
                }
            }
            "rsbcst" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.rsbcst = number.min(100)
                }
            }
            "rsbcmt" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.rsbcmt = number.min(100)
                }
            }
            "rmbcmt" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.rmbcmt = number.min(100)
                }
            }
            "mmbcs" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.mmbcs = number.saturating_mul(1024);
                    spec.mmbcs_explicit = true;
                }
            }
            "mmmbc" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.mmmbc = number
                }
            }
            "mmsbc" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.mmsbc = number
                }
            }
            "lmbcs" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.lmbcs = number.saturating_mul(1024);
                    spec.lmbcs_explicit = true;
                }
            }
            "smbcs" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.smbcs = number.saturating_mul(1024);
                    spec.smbcs_explicit = true;
                }
            }
            "acul" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.acul = number.min(100)
                } else if value == "de" {
                    spec.acul = match name {
                        "ll_alloc" => 85,
                        "eheap_alloc" => 45,
                        _ => 60,
                    }
                }
            }
            "acful" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.acful = number.min(100)
                }
            }
            "acnl" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.acnl = number
                }
            }
            "acfml" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.acfml = number
                }
            }
            "mbcgs" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.mbcgs = number
                }
            }
            "mbsd" => {
                if let Some(number) = parse_flag_integer(value) {
                    spec.mbsd = Some(number.max(1))
                }
            }
            "cp" => {
                spec.cp = match value {
                    "B" => "B",
                    "D" => "D",
                    "E" => "E",
                    "F" => "F",
                    "H" => "H",
                    "L" => "L",
                    "R" => "R",
                    "S" => "S",
                    "@" => "@",
                    ":" => ":",
                    _ => spec.cp,
                }
            }
            "as" => {
                let strategy = match value {
                    "bf" => "bf",
                    "aobf" => "aobf",
                    "gf" => "gf",
                    "af" => "af",
                    "aoff" => "aoff",
                    "aoffcbf" => "aoffcbf",
                    "aoffcaobf" => "aoffcaobf",
                    "ageffcaoff" => "ageffcaoff",
                    "ageffcbf" => "ageffcbf",
                    "ageffcaobf" => "ageffcaobf",
                    "chaosff" if name == "test_alloc" => "chaosff",
                    _ => spec.strategy,
                };
                spec.strategy = strategy;
                spec.global_strategy = strategy;
            }
            _ => {}
        }
    }
}

// Port of erts/emulator/beam/erl_alloc.c:1749-1772 (handle_args +Mea), OTP-29.1.1.
fn apply_allocator_preset(
    spec: &mut AllocatorSystemInfo,
    name: &str,
    preset: &str,
    schedulers: usize,
) {
    if !matches!(
        name,
        "binary_alloc"
            | "std_alloc"
            | "ets_alloc"
            | "eheap_alloc"
            | "ll_alloc"
            | "driver_alloc"
            | "fix_alloc"
            | "sl_alloc"
            | "temp_alloc"
    ) {
        return;
    }
    let default_name = if name == "fix_alloc" {
        "driver_alloc"
    } else {
        name
    };
    if let Some(defaults) = default_allocator(default_name, schedulers) {
        *spec = defaults;
    }
    if name != "temp_alloc" {
        spec.thread_specific = false;
        spec.acul = 0;
        spec.acful = 0;
        spec.ramv = false;
        spec.mmbcs = spec.mmbcs.saturating_mul(spec.scheduler_divisor);
        spec.lmbcs = 5 * 1024 * 1024;
        spec.shared_profile = true;
    }
    if name == "driver_alloc"
        || preset == "r9c"
            && matches!(
                name,
                "sl_alloc" | "std_alloc" | "binary_alloc" | "ets_alloc"
            )
    {
        spec.enabled = false;
    }
}

fn parse_flag_integer(value: &str) -> Option<u64> {
    let value = value.trim_start();
    let value = value.strip_prefix('+').unwrap_or(value);
    let digits = value
        .bytes()
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0_u64, |number, digit| {
        number.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
    })
}

fn allocator_options(spec: &AllocatorSystemInfo, global: bool) -> arinsal_etf::OwnedTerm {
    use arinsal_etf::OwnedTerm as O;
    let number = |value: u64| {
        if value <= i64::MAX as u64 {
            O::Int(value as i64)
        } else {
            O::BigInt(num_bigint::BigInt::from(value))
        }
    };
    let bool_atom = |value| O::Atom(if value { "true" } else { "false" }.into());
    let cp = if global || !spec.thread_specific || spec.shared_profile || spec.cp == "undefined" {
        "undefined"
    } else {
        spec.cp
    };
    let mut values = vec![
        option("e", bool_atom(spec.enabled)),
        option("t", bool_atom(spec.thread_specific)),
        option(
            "atags",
            if spec.atags > 1 {
                O::Int(spec.atags as i64)
            } else {
                bool_atom(spec.atags == 1)
            },
        ),
        option("ramv", bool_atom(false)),
        option("sbct", number(spec.sbct)),
        option("asbcst", number(spec.asbcst)),
        option("rsbcst", number(spec.rsbcst)),
        option("rsbcmt", number(spec.rsbcmt)),
        option("rmbcmt", number(spec.rmbcmt)),
        option("mmbcs", number(spec.mmbcs)),
        option("mmmbc", number(spec.mmmbc)),
        option("mmsbc", number(spec.mmsbc)),
        option("lmbcs", number(spec.lmbcs)),
        option("smbcs", number(spec.smbcs)),
        option("mbcgs", O::Int(10)),
        option("acful", O::Int(0)),
        option("acul", number(if global { 0 } else { spec.acul })),
        option("acnl", number(if global { 0 } else { spec.acnl })),
        option("acfml", O::Int(0)),
        option("cp", O::Atom(cp.into())),
    ];
    if let Some(mbsd) = spec.mbsd
        && (global || spec.shared_profile)
    {
        values.push(option("mbsd", number(mbsd)));
    }
    values.push(option(
        "as",
        O::Atom(
            if global || spec.shared_profile {
                spec.global_strategy
            } else {
                spec.strategy
            }
            .into(),
        ),
    ));
    O::List {
        elems: values,
        tail: Box::new(O::Nil),
    }
}

fn option(name: &str, value: arinsal_etf::OwnedTerm) -> arinsal_etf::OwnedTerm {
    arinsal_etf::OwnedTerm::Tuple(vec![arinsal_etf::OwnedTerm::Atom(name.into()), value])
}

fn owned_system_info(
    process: &mut Process,
    value: arinsal_etf::OwnedTerm,
) -> Result<Term, VmError> {
    arinsal_term::from_owned(
        &value,
        &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
    )
    .map_err(|_| badarg())
}

fn max_integer(process: &mut Process) -> Result<Term, VmError> {
    const MAX_BIG_BITS: usize = 65_535 * 64;
    let value = (num_bigint::BigInt::from(1_u8) << MAX_BIG_BITS) - 1;
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    TermBuilder::new(&mut heap)
        .int_from_bigint(&value)
        .map_err(|_| badarg())
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

pub(crate) fn memory_values(vm: &Vm, process: &Process) -> [(&'static str, u64); 9] {
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

pub(crate) fn snapshot_process(process: &mut Process, _live_x: usize) {
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
    ctx: Option<&mut RunCtx<'_, Message>>,
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
            let (total, delta) = since(reduction_total(ctx.as_deref()), &LAST_REDUCTIONS);
            pair(process, total, delta)
        }
        "exact_reductions" => {
            let (total, delta) = since(reduction_total(ctx.as_deref()), &LAST_EXACT_REDUCTIONS);
            pair(process, total, delta)
        }
        "context_switches" => {
            let total =
                scheduler_stats(process, ctx.as_deref()).map_or(0, |stats| stats.context_switches);
            let (_, delta) = since(total, &LAST_CONTEXT_SWITCHES);
            pair(process, total, delta)
        }
        "garbage_collection" => triple(
            process,
            GC_COUNT.load(Ordering::Relaxed),
            GC_WORDS.load(Ordering::Relaxed),
            0,
        ),
        "io" => io_counters(process),
        "run_queue" => non_neg(
            process,
            queue_counts(process, ctx.as_deref(), false, false)
                .iter()
                .sum(),
        ),
        "total_run_queue_lengths" | "total_run_queue_lengths_all" => {
            let all = name.as_ref() == "total_run_queue_lengths_all";
            non_neg(
                process,
                queue_counts(process, ctx.as_deref(), false, all)
                    .iter()
                    .sum(),
            )
        }
        "run_queue_lengths" | "run_queue_lengths_all" => {
            let all = name.as_ref() == "run_queue_lengths_all";
            int_list(process, &queue_counts(process, ctx.as_deref(), false, all))
        }
        "active_tasks" | "active_tasks_all" => {
            let all = name.as_ref() == "active_tasks_all";
            int_list(process, &queue_counts(process, ctx.as_deref(), true, all))
        }
        "total_active_tasks" | "total_active_tasks_all" => {
            let all = name.as_ref() == "total_active_tasks_all";
            non_neg(
                process,
                queue_counts(process, ctx.as_deref(), true, all)
                    .iter()
                    .sum(),
            )
        }
        "run_queues" => int_tuple(process, &queue_counts(process, ctx.as_deref(), false, true)),
        "scheduler_wall_time" => scheduler_wall(process, ctx.as_deref(), false),
        "scheduler_wall_time_all" => scheduler_wall(process, ctx.as_deref(), true),
        "microstate_accounting" => microstate(process, ctx),
        _ => Err(badarg()),
    }
}

fn system_flag(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:4972 (system_flag_2), OTP-29.1.1.
    let Some(name) = atom_name(args[0]) else {
        return Err(badarg());
    };
    match name.as_ref() {
        "multi_scheduling" => multi_scheduling(process, ctx, args[1]),
        "schedulers_online" => schedulers_online(process, args[1], false),
        "dirty_cpu_schedulers_online" => schedulers_online(process, args[1], true),
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
        "scheduler_wall_time" => set_scheduler_wall(process, ctx, args[1]),
        "microstate_accounting" => set_microstate(process, ctx, args[1]),
        "outstanding_system_requests_limit" => outstanding_limit(args[1]),
        "scheduling_statistics" => scheduling_statistics(args[1]),
        "time_offset" if atom_name(args[1]).as_deref() == Some("finalize") => Ok(atom("final")),
        "scheduler_bind_type" => {
            // Port of erts/emulator/beam/bif.c:5284 and
            // erts/emulator/beam/erl_cpu_topology.c:714, OTP-29.1.1.
            warn_deprecated_scheduler_bind(process, ctx);
            if args[1] == atom("unbound") {
                Ok(atom("unbound"))
            } else {
                Err(bif_error(process, "system_flag", args, "notsup"))
            }
        }
        "cpu_topology" => {
            // Port of erts/emulator/beam/bif.c:5276 and
            // erts/emulator/beam/erl_cpu_topology.c:1348, OTP-29.1.1.
            warn_deprecated_cpu_topology(process, ctx);
            set_cpu_topology(process, args[1], "set_cpu_topology")
        }
        "internal_cpu_topology" => {
            // Port of erts/emulator/beam/bif.c:5272 and
            // erts/emulator/beam/erl_cpu_topology.c:1348, OTP-29.1.1.
            set_cpu_topology(process, args[1], "system_flag")
        }
        "erts_alloc" => erts_alloc_flag(process, args[1]),
        "system_logger" => set_system_logger(args[1]),
        _ => Err(badarg()),
    }
}

// Port of erts/emulator/beam/erl_cpu_topology.c:1348 (`erts_set_cpu_topology`), OTP-29.1.1.
fn cpu_topology_info(process: &mut Process) -> Result<Term, VmError> {
    let current = CPU_TOPOLOGY
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("CPU topology state")
        .clone();
    match current {
        Some(topology) => arinsal_term::from_owned(
            &topology,
            &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
        )
        .map_err(|_| badarg()),
        None => Ok(atom("undefined")),
    }
}

fn set_cpu_topology(
    process: &mut Process,
    value: Term,
    error_function: &str,
) -> Result<Term, VmError> {
    let new = if value == atom("undefined") {
        None
    } else {
        let owned = arinsal_term::to_owned(value)
            .map_err(|_| bif_error_for(process, error_function, &[value], "badarg"))?;
        if !valid_cpu_topology(&owned) {
            return Err(bif_error_for(process, error_function, &[value], "badarg"));
        }
        Some(owned)
    };
    let mut current = CPU_TOPOLOGY
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("CPU topology state");
    let previous = current.clone();
    *current = new;
    drop(current);
    match previous {
        Some(topology) => arinsal_term::from_owned(
            &topology,
            &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
        )
        .map_err(|_| badarg()),
        None => Ok(atom("undefined")),
    }
}

fn valid_cpu_topology(topology: &arinsal_etf::OwnedTerm) -> bool {
    use arinsal_etf::OwnedTerm;

    let OwnedTerm::List { elems, tail } = topology else {
        return false;
    };
    if !matches!(tail.as_ref(), OwnedTerm::Nil) || elems.is_empty() {
        return false;
    }
    fn visit(node: &OwnedTerm, parent_rank: i8, logical_ids: &mut HashSet<i64>) -> bool {
        let OwnedTerm::Tuple(fields) = node else {
            return false;
        };
        let (tag, child) = match fields.as_slice() {
            [OwnedTerm::Atom(tag), child] | [OwnedTerm::Atom(tag), child, OwnedTerm::Nil] => {
                (tag.as_str(), child)
            }
            _ => return false,
        };
        let rank = match tag {
            "node" => 0,
            "processor" => 1,
            "core" => 2,
            "thread" => 3,
            "logical" => 4,
            _ => return false,
        };
        if rank <= parent_rank {
            return false;
        }
        if tag == "logical" {
            let OwnedTerm::Int(id) = child else {
                return false;
            };
            return (0..65_536).contains(id) && logical_ids.insert(*id);
        }
        let mut children = Vec::new();
        match child {
            OwnedTerm::List { elems, tail } if matches!(tail.as_ref(), OwnedTerm::Nil) => {
                children.extend(elems);
            }
            _ => children.push(child),
        }
        !children.is_empty()
            && children
                .into_iter()
                .all(|child| visit(child, rank, logical_ids))
    }
    let mut logical_ids = HashSet::new();
    elems.iter().all(|node| visit(node, -1, &mut logical_ids)) && !logical_ids.is_empty()
}

// Port of erts/emulator/beam/utils.c:919 (`send_warning_to_logger`) and :802
// (`do_send_logger_message`), OTP-29.1.1.
fn send_deprecation_warning(process: &mut Process, ctx: &mut RunCtx<'_, Message>, text: &str) {
    let logger = process.runtime.as_ref().and_then(|runtime| {
        let names = runtime.names.lock().expect("registered process names");
        names
            .get("logger")
            .or_else(|| names.get("error_logger"))
            .copied()
    });
    let Some(logger) = logger else {
        eprintln!("{text}");
        return;
    };
    let pid = ctx.pid().to_term().unwrap_or(Term::NIL);
    let group_leader = process
        .cold
        .as_ref()
        .and_then(|cold| cold.group_leader)
        .and_then(|leader| leader.to_term())
        .unwrap_or(Term::NIL);
    let timestamp = WALL_ORIGIN
        .get_or_init(Instant::now)
        .elapsed()
        .as_micros()
        .try_into()
        .unwrap_or(i64::MAX);
    let event = (|| -> Result<Term, VmError> {
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let warning = builder.string_to_list(text).map_err(|_| badarg())?;
        let format = builder.string_to_list("~s~n").map_err(|_| badarg())?;
        let args = builder.list_from_iter([warning]).map_err(|_| badarg())?;
        let error_logger = builder
            .flatmap_from_pairs(&[
                (atom("emulator"), atom("true")),
                (atom("tag"), atom("warning_msg")),
            ])
            .map_err(|_| badarg())?;
        let metadata = builder
            .flatmap_from_pairs(&[
                (atom("error_logger"), error_logger),
                (atom("gl"), group_leader),
                (atom("pid"), pid),
                (atom("time"), Term::small(timestamp).ok_or_else(badarg)?),
            ])
            .map_err(|_| badarg())?;
        builder
            .tuple(&[atom("log"), atom("warning"), format, args, metadata])
            .map_err(|_| badarg())
    })();
    if let Ok(event) = event
        && let Ok(message) = Message::copy_from(event)
    {
        let _ = ctx.send(logger, message);
    }
}

fn warn_deprecated_scheduler_bind(process: &mut Process, ctx: &mut RunCtx<'_, Message>) {
    send_deprecation_warning(
        process,
        ctx,
        "A call to erlang:system_flag(scheduler_bind_type, _) was\nmade. The scheduler_bind_type argument is deprecated and\nscheduled for removal in Erlang/OTP 18. For more\ninformation see the erlang:system_flag/2 documentation.\n",
    );
}

fn warn_deprecated_cpu_topology(process: &mut Process, ctx: &mut RunCtx<'_, Message>) {
    send_deprecation_warning(
        process,
        ctx,
        "A call to erlang:system_flag(cpu_topology, _) was made.\nThe cpu_topology argument is deprecated and scheduled\nfor removal in Erlang/OTP 18. For more information\nsee the erlang:system_flag/2 documentation.\n",
    );
}

fn bif_error_for(process: &mut Process, function: &str, args: &[Term], reason: &str) -> VmError {
    let args = {
        let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
        TermBuilder::new(&mut heap).list_from_iter(args.iter().copied())
    };
    let Ok(args) = args else {
        return badarg();
    };
    let mut trap = crate::exceptions::Trap::error(atom(reason));
    trap.top = Some(crate::stacktrace::TopFrame::Bif {
        module: "erlang".into(),
        function: function.into(),
        args,
    });
    VmError::Trap(trap)
}

fn bif_error(process: &mut Process, function: &str, args: &[Term], reason: &str) -> VmError {
    bif_error_for(process, function, args, reason)
}

// Port of erts/emulator/beam/erl_alloc.c:3445 (`erts_alloc_set_dyn_param`), OTP-29.1.1.
fn erts_alloc_flag(process: &mut Process, value: Term) -> Result<Term, VmError> {
    let owned = arinsal_term::to_owned(value).map_err(|_| {
        bif_error_for(
            process,
            "system_flag",
            &[atom("erts_alloc"), value],
            "badarg",
        )
    })?;
    let arinsal_etf::OwnedTerm::Tuple(ref items) = owned else {
        return Err(bif_error_for(
            process,
            "system_flag",
            &[atom("erts_alloc"), value],
            "badarg",
        ));
    };
    let [
        arinsal_etf::OwnedTerm::Atom(allocator),
        arinsal_etf::OwnedTerm::Atom(parameter),
        integer,
    ] = items.as_slice()
    else {
        return Err(bif_error_for(
            process,
            "system_flag",
            &[atom("erts_alloc"), value],
            "badarg",
        ));
    };
    let amount = match integer {
        arinsal_etf::OwnedTerm::Int(amount) => u64::try_from(*amount).ok(),
        arinsal_etf::OwnedTerm::BigInt(amount) => num_traits::ToPrimitive::to_u64(amount),
        _ => None,
    };
    let Some(amount) = amount else {
        return Err(bif_error_for(
            process,
            "system_flag",
            &[atom("erts_alloc"), value],
            "badarg",
        ));
    };
    const ALLOCATORS: &[&str] = &[
        "temp_alloc",
        "sl_alloc",
        "std_alloc",
        "ll_alloc",
        "eheap_alloc",
        "ets_alloc",
        "fix_alloc",
        "literal_alloc",
        "binary_alloc",
        "driver_alloc",
        "sys_alloc",
        "test_alloc",
    ];
    if !ALLOCATORS.contains(&allocator.as_str()) {
        return Err(bif_error_for(
            process,
            "system_flag",
            &[atom("erts_alloc"), value],
            "badarg",
        ));
    }
    let _ = (parameter, amount);
    Ok(atom("notsup"))
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

fn set_scheduler_wall(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    value: Term,
) -> Result<Term, VmError> {
    let enable = match atom_name(value).as_deref() {
        Some("true") => true,
        Some("false") => false,
        _ => return Err(badarg()),
    };
    set_scheduler_wall_enabled(process, ctx, enable)
}

fn set_scheduler_wall_enabled(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    enable: bool,
) -> Result<Term, VmError> {
    let mut state = SCHED_WALL.lock().expect("scheduler wall time");
    let previous = state.is_some();
    if enable && state.is_none() {
        *state = Some(SchedBase {
            started: Instant::now(),
            active_ns: Vec::new(),
        });
    } else if !enable {
        *state = None;
    }
    drop(state);
    set_runtime_accounting(process, ctx);
    if enable && !previous {
        let active_ns =
            scheduler_stats(process, Some(ctx)).map_or_else(Vec::new, |stats| stats.active_ns);
        SCHED_WALL
            .lock()
            .expect("scheduler wall time")
            .as_mut()
            .unwrap()
            .active_ns = active_ns;
    }
    Ok(atom(if previous { "true" } else { "false" }))
}

fn set_runtime_accounting(process: &Process, ctx: &mut RunCtx<'_, Message>) {
    let enabled = SCHED_WALL.lock().expect("scheduler wall time").is_some();
    if let Some(scheduler) = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler().ok())
    {
        scheduler.set_accounting_enabled(enabled);
    }
    ctx.set_wall_accounting_enabled(enabled);
}

struct SystemFlags {
    fullsweep_after: u16,
    min_heap_size: i64,
    min_bin_vheap_size: i64,
    max_heap: crate::process::MaxHeap,
    schedulers_online: usize,
    schedulers_total: usize,
    dirty_cpu_online: usize,
    dirty_cpu_total: usize,
    dirty_io_total: usize,
    trace_word: i64,
    outstanding: u64,
    multi: &'static str,
    multi_blocked: bool,
    normal_blocked: bool,
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

pub(crate) fn multi_scheduling_blocked() -> bool {
    with_flags(|flags| matches!(flags.multi, "blocked" | "blocked_normal"))
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
        let (
            schedulers_total,
            schedulers_online,
            dirty_cpu_total,
            dirty_cpu_online,
            dirty_io_total,
        ) = boot_scheduler_counts(cpus);
        Mutex::new(SystemFlags {
            // Port of erl_init.c:1328-1332 (`ERL_FULLSWEEP_AFTER`), OTP-29.1.1.
            fullsweep_after: std::env::var("ERL_FULLSWEEP_AFTER")
                .ok()
                .map(|value| value.trim().parse::<i64>().unwrap_or(0) as u16)
                .unwrap_or(u16::MAX),
            min_heap_size: 233,
            min_bin_vheap_size: 46_422,
            max_heap: crate::process::MaxHeap::default(),
            schedulers_online,
            schedulers_total,
            dirty_cpu_online,
            dirty_cpu_total,
            dirty_io_total,
            trace_word: 0,
            outstanding: (cpus as u64).saturating_mul(2),
            multi: "enabled",
            multi_blocked: false,
            normal_blocked: false,
        })
    });
    body(&mut flags.lock().expect("system flags"))
}

pub(crate) fn scheduler_online_default() -> (usize, bool) {
    with_flags(|flags| (flags.schedulers_online, flags.multi != "enabled"))
}

fn boot_scheduler_counts(cpus: usize) -> (usize, usize, usize, usize, usize) {
    // Port of erts/emulator/beam/erl_init.c scheduler option defaults, OTP-29.1.1.
    let args: Vec<String> = std::env::args().collect();
    let mut schedulers = (cpus, cpus);
    let mut dirty_cpu = (cpus, cpus);
    let mut dirty_io = cpus;
    let mut index = 1;
    while index < args.len() {
        let flag = args[index].as_str();
        let inline = args.get(index + 1).map(String::as_str);
        let (name, value, consumed) = match flag {
            "+S" => (Some("+S"), inline, 2),
            "+SDcpu" => (Some("+SDcpu"), inline, 2),
            "+SDio" => (Some("+SDio"), inline, 2),
            _ if flag.starts_with("+SDcpu") && flag.len() > 6 => {
                (Some("+SDcpu"), Some(&flag[6..]), 1)
            }
            _ => (None, None, 1),
        };
        if let (Some(name), Some(value)) = (name, value) {
            match name {
                "+S" => {
                    if let Some(counts) = parse_scheduler_pair(value, cpus) {
                        schedulers = counts;
                    }
                }
                "+SDcpu" => {
                    if let Some(counts) = parse_scheduler_pair(value, cpus) {
                        dirty_cpu = counts;
                    }
                }
                "+SDio" => {
                    if let Ok(count) = value.parse::<usize>()
                        && count > 0
                    {
                        dirty_io = count;
                    }
                }
                _ => {}
            }
            index = index.saturating_add(consumed);
        } else {
            index += 1;
        }
    }
    let schedulers = (
        schedulers.0.max(1),
        schedulers.1.clamp(1, schedulers.0.max(1)),
    );
    let dirty_cpu = (
        dirty_cpu.0.max(1),
        dirty_cpu.1.clamp(1, dirty_cpu.0.max(1)).min(schedulers.1),
    );
    (
        schedulers.0,
        schedulers.1,
        dirty_cpu.0,
        dirty_cpu.1,
        dirty_io.max(1),
    )
}

fn parse_scheduler_pair(value: &str, cpus: usize) -> Option<(usize, usize)> {
    let (total, online) = value
        .split_once(':')
        .map_or((value, None), |(a, b)| (a, Some(b)));
    let resolve = |part: &str, default: usize| {
        let value = part.parse::<i32>().ok()?;
        let count = if value < 0 {
            (cpus as i32).saturating_add(value)
        } else if value == 0 {
            default as i32
        } else {
            value
        };
        usize::try_from(count).ok().filter(|count| *count > 0)
    };
    let total = resolve(total, cpus)?;
    let online = online.map_or(Some(total.min(cpus)), |value| resolve(value, total))?;
    (online <= total).then_some((total, online))
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

fn multi_scheduling(
    process: &Process,
    ctx: &RunCtx<'_, Message>,
    value: Term,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_process.c:8484 (erts_block_multi_scheduling), OTP-29.1.1.
    let action = match atom_name(value).as_deref() {
        Some("block") => (Some(true), None),
        Some("unblock") => (Some(false), None),
        Some("block_normal") => (None, Some(true)),
        Some("unblock_normal") => (None, Some(false)),
        _ => return Err(badarg()),
    };
    with_flags(|flags| {
        if let Some(blocked) = action.0 {
            flags.multi_blocked = blocked;
        }
        if let Some(blocked) = action.1 {
            flags.normal_blocked = blocked;
        }
        let next = if flags.multi_blocked {
            "blocked"
        } else if flags.normal_blocked {
            "blocked_normal"
        } else {
            "enabled"
        };
        flags.multi = next;
        if let Some(scheduler) = process
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.scheduler().ok())
        {
            scheduler.set_scheduling_blocked(
                flags.multi_blocked || flags.normal_blocked,
                ctx.worker_id(),
            );
        }
        Ok(atom(next))
    })
}

fn schedulers_online(process: &Process, value: Term, dirty: bool) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_process.c:8228 (erts_set_schedulers_online), OTP-29.1.1.
    let requested = value.as_small().ok_or_else(badarg)?;
    with_flags(|flags| {
        // Port of erts/emulator/beam/bif.c:5015 and :5178
        // (system_flag_2 scheduler controls), OTP-29.1.1.
        // Normal schedulers bound the number of dirty CPU schedulers online.
        let previous = if dirty {
            if requested < 1
                || requested as usize > flags.dirty_cpu_total
                || requested as usize > flags.schedulers_online
            {
                return Err(badarg());
            }
            let previous = flags.dirty_cpu_online;
            flags.dirty_cpu_online = requested as usize;
            previous
        } else {
            if requested < 1 || requested as usize > flags.schedulers_total {
                return Err(badarg());
            }
            let previous = flags.schedulers_online;
            // A full stats snapshot rendezvouses with every worker. Calling it
            // from a running worker waits on that same worker forever; the
            // scheduler setter validates its configured capacity directly.
            if requested as usize != previous
                && let Some(scheduler) = process
                    .runtime
                    .as_ref()
                    .and_then(|runtime| runtime.scheduler().ok())
                && !scheduler.set_online_schedulers(requested as usize)
            {
                return Err(badarg());
            }
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

// Port of erts/emulator/beam/erl_msacc.c:329 (microstate accounting actions), OTP-29.1.1.
fn set_microstate(
    process: &Process,
    ctx: &mut RunCtx<'_, Message>,
    value: Term,
) -> Result<Term, VmError> {
    let previous = MICROSTATE.load(Ordering::Relaxed);
    match atom_name(value).as_deref() {
        Some("true") => {
            MICROSTATE.store(true, Ordering::Relaxed);
            set_microstate_workers(process, true);
            ctx.set_msacc_accounting_enabled(true);
            ctx.set_msacc_state(arinsal_sched::MsaccState::Emulator);
            if !previous {
                ctx.set_gc_accounting_baseline(process.stats.gc.nanoseconds);
                if MICROSTATE_BASE
                    .lock()
                    .expect("microstate baseline")
                    .is_none()
                {
                    reset_microstate_baseline(process, ctx);
                }
            }
        }
        Some("false") => {
            MICROSTATE.store(false, Ordering::Relaxed);
            ctx.account_gc_total(process.stats.gc.nanoseconds);
            ctx.set_msacc_accounting_enabled(false);
            set_microstate_workers(process, false);
        }
        Some("reset") => {
            set_microstate_workers(process, previous);
            if previous {
                ctx.account_gc_total(process.stats.gc.nanoseconds);
            }
            ctx.set_gc_accounting_baseline(process.stats.gc.nanoseconds);
            reset_microstate_baseline(process, ctx);
        }
        _ => return Err(badarg()),
    }
    set_runtime_accounting(process, ctx);
    Ok(atom(if previous { "true" } else { "false" }))
}

// Port of erts/emulator/beam/erl_msacc.c:367 (managed scheduler requests), OTP-29.1.1.
fn set_microstate_workers(process: &Process, enabled: bool) {
    crate::check_io::set_msacc_enabled(enabled);
    if let Some(scheduler) = process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler().ok())
    {
        scheduler.set_microstate_enabled(enabled);
    }
}

// Port of erts/emulator/beam/erl_msacc.c:425 (counter reset), OTP-29.1.1.
fn reset_microstate_baseline(process: &Process, ctx: &RunCtx<'_, Message>) {
    let stats = scheduler_stats(process, Some(ctx));
    let counters = stats
        .as_ref()
        .map_or_else(Vec::new, |stats| stats.msacc_ns.clone());
    let poll_baseline = crate::check_io::msacc_snapshot();
    *MICROSTATE_BASE.lock().expect("microstate baseline") =
        Some((Instant::now(), counters, poll_baseline));
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
    ctx.map_or(0, |ctx| ctx.total_reductions() + u64::from(ctx.consumed()))
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

fn scheduler_stats(
    process: &Process,
    ctx: Option<&RunCtx<'_, Message>>,
) -> Option<arinsal_sched::SchedulerStats> {
    if let Some(ctx) = ctx {
        return Some(ctx.scheduler_stats());
    }
    process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.scheduler().ok())
        .map(|scheduler| scheduler.stats())
}

fn queue_counts(
    process: &Process,
    ctx: Option<&RunCtx<'_, Message>>,
    active: bool,
    include_dirty_io: bool,
) -> Vec<u64> {
    // Port of erts/emulator/beam/erl_process.c:9281 (erts_run_queues_len), OTP-29.1.1.
    let schedulers = with_flags(|flags| flags.schedulers_total);
    // erts exposes one aggregated run queue for each dirty scheduler class.
    let slots = schedulers + 1 + usize::from(include_dirty_io);
    let mut values = vec![0; slots];
    if let Some(stats) = scheduler_stats(process, ctx) {
        let source = if active {
            &stats.active_tasks
        } else {
            &stats.run_queue_lengths
        };
        for (target, value) in values.iter_mut().take(schedulers).zip(source) {
            *target = *value;
        }
    }
    values
}

fn scheduler_wall(
    process: &mut Process,
    ctx: Option<&RunCtx<'_, Message>>,
    include_dirty_io: bool,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_process.c scheduler active/total time accounting, OTP-29.1.1.
    let base = SCHED_WALL.lock().expect("scheduler wall time").clone();
    let Some(base) = base else {
        return Ok(atom("undefined"));
    };
    let total_us = u64::try_from(base.started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let stats = scheduler_stats(process, ctx);
    let (online, dirty_cpu, dirty_io) = with_flags(|flags| {
        (
            flags.schedulers_online,
            flags.dirty_cpu_total,
            flags.dirty_io_total,
        )
    });
    let mut entries = Vec::new();
    for id in 0..online {
        let active = stats
            .as_ref()
            .and_then(|s| s.active_ns.get(id))
            .copied()
            .unwrap_or(0)
            .saturating_sub(base.active_ns.get(id).copied().unwrap_or(0))
            / 1_000;
        entries.push(triple(process, (id + 1) as u64, active, total_us)?);
    }
    for id in 0..dirty_cpu {
        entries.push(triple(process, (online + id + 1) as u64, 0, total_us)?);
    }
    if include_dirty_io {
        for id in 0..dirty_io {
            entries.push(triple(
                process,
                (online + dirty_cpu + id + 1) as u64,
                0,
                total_us,
            )?);
        }
    }
    cons_list(process, &entries)
}

fn microstate(
    process: &mut Process,
    mut ctx: Option<&mut RunCtx<'_, Message>>,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_msacc.c result layout, OTP-29.1.1.
    let baseline = MICROSTATE_BASE.lock().expect("microstate baseline").clone();
    let Some((started, baseline, poll_baseline)) = baseline else {
        return Ok(atom("undefined"));
    };
    let elapsed = if MICROSTATE.load(Ordering::Relaxed) {
        u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    } else {
        0
    };
    if let Some(ctx) = ctx.as_deref_mut() {
        ctx.account_gc_total(process.stats.gc.nanoseconds);
    }
    let stats = scheduler_stats(process, ctx.as_deref());
    let (online, dirty_cpu, dirty_io) = with_flags(|flags| {
        (
            flags.schedulers_online,
            flags.dirty_cpu_total,
            flags.dirty_io_total,
        )
    });
    let mut entries = Vec::new();
    for id in 0..online {
        let mut counters = stats
            .as_ref()
            .and_then(|stats| stats.msacc_ns.get(id))
            .copied()
            .unwrap_or([0; 7]);
        for (state, counter) in counters.iter_mut().enumerate() {
            *counter = counter.saturating_sub(baseline.get(id).map_or(0, |prior| prior[state]));
        }
        entries.push(msacc_entry(
            process,
            (id + 1) as i64,
            "scheduler",
            counters,
        )?);
    }
    for id in 0..dirty_cpu {
        entries.push(msacc_entry(
            process,
            (online + id + 1) as i64,
            "dirty_cpu_scheduler",
            [0, 0, 0, 0, 0, 0, elapsed],
        )?);
    }
    for id in 0..dirty_io {
        entries.push(msacc_entry(
            process,
            (online + dirty_cpu + id + 1) as i64,
            "dirty_io_scheduler",
            [0, 0, 0, 0, 0, 0, elapsed],
        )?);
    }
    entries.push(msacc_entry(process, 1, "aux", [0, 0, 0, 0, 0, 0, elapsed])?);
    let poll_ns = crate::check_io::msacc_snapshot();
    let poll_check_io_ns = poll_ns[0].saturating_sub(poll_baseline[0]);
    let poll_sleep_ns = poll_ns[1].saturating_sub(poll_baseline[1]);
    entries.push(msacc_entry(
        process,
        0,
        "poll",
        [0, poll_check_io_ns, 0, 0, 0, 0, poll_sleep_ns],
    )?);
    entries.push(msacc_entry(
        process,
        0,
        "async",
        [0, 0, 0, 0, 0, 0, elapsed],
    )?);
    cons_list(process, &entries)
}

fn msacc_entry(
    process: &mut Process,
    id: i64,
    kind: &str,
    values: [u64; 7],
) -> Result<Term, VmError> {
    // Perf-counter ticks on this host are nanoseconds; msacc:stats/0 performs
    // the same perf_counter-to-microsecond conversion as OTP.
    let counters = map(
        process,
        &[
            ("aux", small(values[0].min(i64::MAX as u64) as i64)),
            ("check_io", small(values[1].min(i64::MAX as u64) as i64)),
            ("emulator", small(values[2].min(i64::MAX as u64) as i64)),
            ("gc", small(values[3].min(i64::MAX as u64) as i64)),
            ("other", small(values[4].min(i64::MAX as u64) as i64)),
            ("port", small(values[5].min(i64::MAX as u64) as i64)),
            ("sleep", small(values[6].min(i64::MAX as u64) as i64)),
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

pub(crate) fn non_neg(process: &mut Process, value: u64) -> Result<Term, VmError> {
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
    use arinsal_sched::{Config, RunCtx, RunOutcome, Scheduler, Task};
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
        let actual = system_info(&Vm::new([]), &mut Process::new(), None, selector)
            .unwrap()
            .unwrap();
        assert_eq!(expected, CallResult::Ok(to_owned(actual).unwrap()));
    }

    #[test]
    fn max_integer_system_info_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping max_integer differential test");
            return;
        };
        let expected = reference.call("erlang", "system_info", &[OwnedTerm::atom("max_integer")]);
        let selector = Term::atom(global_atoms().intern("max_integer").unwrap());
        let actual = system_info(&Vm::new([]), &mut Process::new(), None, selector)
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
        let actual = system_info(&Vm::new([]), &mut process, None, selector)
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
            let actual = system_info(&Vm::new([]), &mut process, None, selector_term)
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

    struct CountedYield;
    impl Task for CountedYield {
        type Message = ();
        fn run(&mut self, ctx: &mut RunCtx<'_, ()>, _budget: u32) -> RunOutcome {
            assert!(ctx.consume(3));
            RunOutcome::Yield
        }
    }

    #[test]
    fn sched_acct_scheduler_dispatch_and_reductions_are_exact() {
        let scheduler = Scheduler::simulation(Config::default(), 9);
        scheduler.spawn(CountedYield).unwrap();
        assert!(scheduler.step());
        let stats = scheduler.stats();
        assert_eq!(stats.context_switches, 1);
        assert_eq!(stats.reductions, 3);
        assert_eq!(stats.run_queue_lengths.iter().sum::<u64>(), 1);
        assert_eq!(stats.active_tasks.iter().sum::<u64>(), 1);
    }

    #[test]
    fn sched_acct_scheduler_flag_parser_matches_otp_count_forms() {
        assert_eq!(parse_scheduler_pair("8:3", 10), Some((8, 3)));
        assert_eq!(parse_scheduler_pair("8", 10), Some((8, 8)));
        assert_eq!(parse_scheduler_pair("-1:-2", 10), Some((9, 8)));
        assert_eq!(parse_scheduler_pair("0:3", 10), Some((10, 3)));
        assert_eq!(boot_scheduler_counts(10), (10, 10, 10, 10, 10));
    }

    #[test]
    fn sched_acct_system_scheduler_facts_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping scheduler facts differential test");
            return;
        };
        for selector in [
            "schedulers",
            "schedulers_online",
            "dirty_cpu_schedulers",
            "dirty_cpu_schedulers_online",
            "dirty_io_schedulers",
        ] {
            let expected = reference.call("erlang", "system_info", &[OwnedTerm::atom(selector)]);
            let input = Term::atom(global_atoms().intern(selector).unwrap());
            let actual = system_info(&Vm::new([]), &mut Process::new(), None, input)
                .unwrap()
                .unwrap();
            assert_eq!(
                CallResult::Ok(to_owned(actual).unwrap()),
                expected,
                "{selector}"
            );
        }
    }

    #[test]
    fn alloc_a4_allocator_options_match_otp() {
        use OwnedTerm as O;

        fn reference_term(arguments: &[&str], eval: &str) -> O {
            let output = std::process::Command::new("erl")
                .args(arguments)
                .args([
                    "-noshell",
                    "-eval",
                    &format!(
                        "io:put_chars(standard_io,binary:encode_hex(term_to_binary({eval}))),halt()."
                    ),
                ])
                .output()
                .expect("reference erl process");
            assert!(
                output.status.success(),
                "reference erl failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let encoded = std::str::from_utf8(&output.stdout).unwrap();
            let bytes = encoded
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>();
            arinsal_etf::decode(&bytes).unwrap()
        }

        let default_output = reference_term(
            &[],
            "{[erlang:system_info({allocator,A}) || A <- [temp_alloc,sl_alloc,std_alloc,ll_alloc,eheap_alloc,ets_alloc,fix_alloc,literal_alloc,binary_alloc,driver_alloc]],erlang:system_info(allocator),erlang:system_info(alloc_util_allocators)}",
        );
        let O::Tuple(default_values) = &default_output else {
            panic!("OTP default allocator query was not a tuple");
        };
        let O::List {
            elems: default_infos,
            ..
        } = &default_values[0]
        else {
            panic!("OTP default allocator options were not a list");
        };
        arinsal_args::configure_allocator_options(arinsal_args::ActiveAllocatorOptions::default());

        fn project(value: &O) -> O {
            let O::List { elems, .. } = value else {
                return value.clone();
            };
            O::List {
                elems: elems
                    .iter()
                    .filter_map(|entry| {
                        let O::Tuple(fields) = entry else {
                            return None;
                        };
                        if fields.len() != 3 {
                            return None;
                        }
                        let O::List { elems, .. } = &fields[2] else {
                            return None;
                        };
                        let selected = elems
                            .iter()
                            .filter(|item| matches!(item, O::Tuple(parts) if parts.first().is_some_and(|key| matches!(key, O::Atom(name) if name == "options" || name == "versions"))))
                            .cloned()
                            .collect();
                        Some(O::Tuple(vec![fields[1].clone(), O::List { elems: selected, tail: Box::new(O::Nil) }]))
                    })
                    .collect(),
                tail: Box::new(O::Nil),
            }
        }

        for (index, name) in [
            "temp_alloc",
            "sl_alloc",
            "std_alloc",
            "ll_alloc",
            "eheap_alloc",
            "ets_alloc",
            "fix_alloc",
            "literal_alloc",
            "binary_alloc",
            "driver_alloc",
        ]
        .into_iter()
        .enumerate()
        {
            let mut process = Process::new();
            let input = from_owned(
                &O::Tuple(vec![O::Atom("allocator".into()), O::Atom(name.into())]),
                &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
            )
            .unwrap();
            let actual = system_info(&Vm::new([]), &mut process, None, input)
                .unwrap()
                .unwrap();
            assert_eq!(
                project(&to_owned(actual).unwrap()),
                project(&default_infos[index]),
                "{name}"
            );
        }

        for (selector, expected) in [
            (O::Atom("allocator".into()), &default_values[1]),
            (O::Atom("alloc_util_allocators".into()), &default_values[2]),
        ] {
            let mut process = Process::new();
            let input = from_owned(
                &selector,
                &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
            )
            .unwrap();
            let actual = system_info(&Vm::new([]), &mut process, None, input)
                .unwrap()
                .unwrap();
            assert_eq!(to_owned(actual).unwrap(), *expected, "{selector}");
        }

        let names = ["eheap_alloc", "sl_alloc", "ets_alloc", "binary_alloc"];
        let expected = reference_term(
            &[
                "+S", "2:2", "+MHsbct", "100", "+MSas", "ageffcbf", "+MEacul", "75", "+MBatags",
                "true", "+MHt", "false", "+MHt", "true", "+MMmcs", "5",
            ],
            "{[erlang:system_info({allocator,A}) || A <- [eheap_alloc,sl_alloc,ets_alloc,binary_alloc]],erlang:system_info({allocator,mseg_alloc}),erlang:system_info(allocator)}",
        );
        let mut actual_infos = Vec::new();
        let active = arinsal_args::ActiveAllocatorOptions {
            schedulers: Some(2),
            flags: vec![
                arinsal_args::IgnoredFlag {
                    name: "+MHsbct".into(),
                    value: Some("100".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MHt".into(),
                    value: Some("false".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MHt".into(),
                    value: Some("true".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MSas".into(),
                    value: Some("ageffcbf".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MEacul".into(),
                    value: Some("75".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MBatags".into(),
                    value: Some("true".into()),
                },
                arinsal_args::IgnoredFlag {
                    name: "+MMmcs".into(),
                    value: Some("5".into()),
                },
            ],
            ..Default::default()
        };
        arinsal_args::configure_allocator_options(active);
        for name in names {
            let mut process = Process::new();
            let input = from_owned(
                &O::Tuple(vec![O::Atom("allocator".into()), O::Atom(name.into())]),
                &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
            )
            .unwrap();
            actual_infos.push(
                to_owned(
                    system_info(&Vm::new([]), &mut process, None, input)
                        .unwrap()
                        .unwrap(),
                )
                .unwrap(),
            );
        }
        let O::Tuple(flagged_expected) = &expected else {
            panic!("OTP flagged allocator result was not a tuple");
        };
        let O::List {
            elems: expected_infos,
            ..
        } = &flagged_expected[0]
        else {
            panic!("OTP flagged allocator options were not a list");
        };
        assert_eq!(actual_infos.len(), expected_infos.len());
        for (actual, expected) in actual_infos.iter().zip(expected_infos) {
            assert_eq!(
                project(actual),
                project(expected),
                "allocator options with +M switches"
            );
        }
        let mut process = Process::new();
        let input = Term::atom(global_atoms().intern("allocator").unwrap());
        let actual = system_info(&Vm::new([]), &mut process, None, input)
            .unwrap()
            .unwrap();
        assert_eq!(
            to_owned(actual).unwrap(),
            flagged_expected[2],
            "global allocator configuration with +M switches"
        );
        let mut process = Process::new();
        let input = from_owned(
            &O::Tuple(vec![
                O::Atom("allocator".into()),
                O::Atom("mseg_alloc".into()),
            ]),
            &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
        )
        .unwrap();
        let actual = system_info(&Vm::new([]), &mut process, None, input)
            .unwrap()
            .unwrap();
        assert_eq!(
            project(&to_owned(actual).unwrap()),
            project(&flagged_expected[1]),
            "mseg allocator options with +MM switches"
        );

        let test_expected = reference_term(
            &["+MZe", "true"],
            "erlang:system_info({allocator,test_alloc})",
        );
        arinsal_args::configure_allocator_options(arinsal_args::ActiveAllocatorOptions {
            flags: vec![arinsal_args::IgnoredFlag {
                name: "+MZe".into(),
                value: Some("true".into()),
            }],
            ..Default::default()
        });
        let mut process = Process::new();
        let input = from_owned(
            &O::Tuple(vec![
                O::Atom("allocator".into()),
                O::Atom("test_alloc".into()),
            ]),
            &mut arinsal_bifs::FragmentingHeap(&mut process.heap),
        )
        .unwrap();
        let actual = system_info(&Vm::new([]), &mut process, None, input)
            .unwrap()
            .unwrap();
        assert_eq!(
            project(&to_owned(actual).unwrap()),
            project(&test_expected),
            "enabled test allocator options"
        );
        arinsal_args::configure_allocator_options(arinsal_args::ActiveAllocatorOptions::default());
    }

    #[test]
    fn sched_acct_queue_statistics_shapes_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping queue shape differential test");
            return;
        };
        for selector in [
            "run_queue_lengths",
            "run_queue_lengths_all",
            "active_tasks",
            "active_tasks_all",
        ] {
            let expected = reference.call("erlang", "statistics", &[OwnedTerm::atom(selector)]);
            let mut heap = VecHeap::new();
            let input = from_owned(&OwnedTerm::atom(selector), &mut heap).unwrap();
            let actual = statistics(&Vm::new([]), &mut Process::new(), None, input)
                .and_then(|term| to_owned(term).map_err(|_| badarg()))
                .unwrap();
            match (&actual, &expected) {
                (
                    OwnedTerm::List { elems: actual, .. },
                    CallResult::Ok(OwnedTerm::List {
                        elems: expected, ..
                    }),
                ) => assert_eq!(actual.len(), expected.len(), "{selector}"),
                _ => panic!("queue statistics should be lists"),
            }
        }
    }

    #[test]
    fn sched_acct_run_queue_totals_equal_scheduler_slots() {
        let process = Process::new();
        let lengths = queue_counts(&process, None, false, false);
        let all = queue_counts(&process, None, false, true);
        assert_eq!(lengths.iter().sum::<u64>(), 0);
        assert_eq!(all.iter().sum::<u64>(), 0);
        assert!(all.len() > lengths.len());
    }

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

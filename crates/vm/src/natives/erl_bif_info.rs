//! The process inspection and system information BIFs of erl_bif_info.c.
//!
//! Port of erts/emulator/beam/erl_bif_info.c (is_process_alive_1, is_process_alive_trap,
//! system_info_1), OTP-29.1.1. Each BIF is `bif_table[].f` with `(c_p, reg, I)`.

use crate::natives::bif::{badarg, bif_ret};
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_sched::Pid;
use arinsal_term::{HeapAlloc, HeapReservation, Term, TermBuilder, atoms, global_atoms};
use num_bigint::BigInt;

/// `is_process_alive_trap`: `erts_export_put(am_erts_internal, am_is_process_alive, 1)`, the
/// Erlang function that sends the `is alive` request through the target's signal queue and
/// waits for the answer.
// Port of erts/emulator/beam/erl_bif_info.c (erts_bif_info_init: is_process_alive_trap),
// OTP-29.1.1.
const IS_PROCESS_ALIVE_TRAP: &str = "erts_internal:is_process_alive/1";

/// `ERTS_MONOTONIC_TIME_START_EXTERNAL`, the lower bound of external monotonic time.
// Port of erts/emulator/beam/erl_time.h (ERTS_MONOTONIC_TIME_START_EXTERNAL), OTP-29.1.1.
const MONOTONIC_TIME_START_EXTERNAL: i64 = (-(1_i64 << 59) / 1_000_000_000) * 1_000_000_000;
/// `ERTS_MONOTONIC_TIME_END_EXTERNAL`, the upper bound of external monotonic time.
// Port of erts/emulator/beam/erl_time.h (ERTS_MONOTONIC_TIME_END_EXTERNAL), OTP-29.1.1.
const MONOTONIC_TIME_END_EXTERNAL: i64 =
    MONOTONIC_TIME_START_EXTERNAL + ((i64::MAX / 1_000_000_000) * 1_000_000_000 - 1_000_000_000);

/// `is_process_alive/1`.
// Port of erts/emulator/beam/erl_bif_info.c (is_process_alive_1), OTP-29.1.1.
pub(crate) extern "C" fn is_process_alive_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let [arg] = crate::bif_table::bif_args::<1>(reg);
    if let Some(pid) = Pid::from_term(arg) {
        if arg.tagged_word() == process.heap.abi.self_pid {
            return crate::native_hooks::raw(Term::atom(atoms::TRUE));
        }
        let Some(scheduler) = process
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.scheduler_if_started())
        else {
            return bif_ret(c_p, i, Err(badarg()));
        };
        // erts_proc_lookup_raw, then `rp->state`: an exiting process or one with signals in
        // its queue traps to `is_process_alive_trap`, which orders the answer after them.
        let found = if process.on_managed {
            scheduler.is_quiet_word(arg.tagged_word())
        } else {
            scheduler.is_quiet_from(pid, false)
        };
        let result = match found {
            None => atoms::FALSE,
            Some(true) => atoms::TRUE,
            Some(false) => return bif_ret(c_p, i, Err(alive_trap(process, arg))),
        };
        // ERTS_PROC_HAS_INCOMING_SIGNALS(BIF_P): signals from the inspected process to us must
        // be handled before the answer. erts traps to `erts_bif_handle_signals_return/2`
        // (ERTS_BIF_HANDLE_SIGNALS_FROM_RETURN), which has no port here; the alive request
        // orders the answer after them too.
        let own_quiet = match process.signal_probe() {
            Some(probe) => probe.is_quiet(),
            None => process
                .self_pid
                .is_some_and(|me| scheduler.is_quiet_from(me, process.on_managed) == Some(true)),
        };
        if !own_quiet {
            return bif_ret(c_p, i, Err(alive_trap(process, arg)));
        }
        return crate::native_hooks::raw(Term::atom(result));
    }
    // is_external_pid of this node's old incarnation: `am_false`.
    if let Ok(arinsal_etf::OwnedTerm::Pid { node, .. }) = &arinsal_term::to_owned(arg)
        && node == crate::node_tables::this_node().0
    {
        return crate::native_hooks::raw(Term::atom(atoms::FALSE));
    }
    bif_ret(c_p, i, Err(badarg()))
}

/// `BIF_TRAP1(is_process_alive_trap, BIF_P, BIF_ARG_1)`.
#[cold]
#[inline(never)]
fn alive_trap(process: &mut crate::Process, pid: Term) -> VmError {
    VmError::TrapExport(crate::ExportTrap::new(
        process,
        IS_PROCESS_ALIVE_TRAP,
        vec![pid],
    ))
}

/// `system_info/1` called with only the process and its argument registers.
// Port of erts/emulator/beam/erl_bif_info.c (system_info_1), OTP-29.1.1.
pub(crate) extern "C" fn system_info_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let [selector] = crate::bif_table::bif_args::<1>(reg);
    if let Some(item) = system_info_body_item(process, selector) {
        process.heap.note_bif_entry();
        return bif_ret(c_p, i, item);
    }
    crate::native_helpers::process_bif_light(c_p, reg, i)
}

/// Selectors answered directly by `system_info_1`, before allocator aux-work or trap paths.
// Port of erts/emulator/beam/erl_bif_info.c (system_info_1), OTP-29.1.1.
pub(crate) fn system_info_body_item(
    process: &mut Process,
    selector: Term,
) -> Option<Result<Term, VmError>> {
    let name = selector
        .as_atom()
        .and_then(|atom| global_atoms().text(atom));
    if matches!(name, Some("allocator" | "alloc_util_allocators")) {
        return None;
    }
    if let Some(item) =
        name.and_then(|name| crate::natives::sys::system_info_process_item(process, name))
    {
        return Some(item);
    }
    if let Some(item) = crate::natives::sys::system_info_topology_item(process, selector) {
        return Some(item);
    }
    system_info_light_item(process, selector)
}

/// `system_info/1` from the generated-code process entry.
// Port of erts/emulator/beam/erl_bif_info.c (system_info_1), OTP-29.1.1.
pub(crate) fn system_info_light(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [selector] = args else {
        return None;
    };
    if let Some(name) = selector
        .as_atom()
        .and_then(|atom| global_atoms().text(atom))
        && let Some(item) = crate::natives::sys::system_info_process_item(process, name)
    {
        return match item {
            Ok(value) => Some(Ok(value)),
            Err(VmError::Trap(trap)) => Some(Err(trap)),
            Err(_) => None,
        };
    }
    system_info_light_item(process, *selector).map(|item| {
        item.map_err(|error| match error {
            VmError::Trap(trap) => trap,
            _ => crate::exceptions::Trap::error(Term::atom(atoms::SYSTEM_LIMIT)),
        })
    })
}

/// The selectors `system_info_1` answers from process-independent build and runtime state.
// Port of erts/emulator/beam/erl_bif_info.c (system_info_1), OTP-29.1.1.
pub(crate) fn system_info_light_item(
    process: &mut Process,
    key: Term,
) -> Option<Result<Term, VmError>> {
    system_info_light_name(key).map(|name| system_info_result(process, name))
}

fn system_info_light_name(key: Term) -> Option<&'static str> {
    let name = key.as_atom().and_then(|atom| global_atoms().text(atom))?;
    matches!(
        name,
        "otp_release"
            | "version"
            | "system_version"
            | "wordsize"
            | "start_time"
            | "end_time"
            | "break_ignored"
            | "async_dist"
            | "eager_check_io"
            | "dynamic_trace"
            | "dynamic_trace_probes"
            | "c_compiler_used"
            | "delayed_node_table_gc"
            | "context_reductions"
            | "logical_processors"
            | "logical_processors_available"
            | "logical_processors_online"
            | "outstanding_system_requests_limit"
            | "process_limit"
            | "port_limit"
            | "ets_limit"
            | "machine"
            | "system_architecture"
            | "emu_flavor"
            | "build_type"
            | "emu_type"
            | "os_type"
            | "os_version"
            | "endian"
            | "heap_type"
            | "time_correction"
            | "message_queue_data"
            | "kernel_poll"
            | "time_offset"
            | "time_warp_mode"
            | "os_monotonic_time_source"
            | "os_system_time_source"
            | "smp_support"
            | "constant_pool_support"
            | "hipe_architecture"
            | "ets_realloc_moves"
            | "compat_rel"
            | "snifs"
    )
    .then_some(name)
}

fn system_info_result(process: &mut Process, key: &str) -> Result<Term, VmError> {
    // Port of HAllocX/erts_heap_alloc: BIF heap allocation moves to a heap fragment if the
    // young heap cannot fit the next object.
    let mut heap = HeapReservation::new(&mut process.heap, 0).map_err(|_| system_limit())?;
    system_info_with_heap(&mut heap, key)
}

fn system_info_with_heap<H: HeapAlloc + ?Sized>(heap: &mut H, key: &str) -> Result<Term, VmError> {
    let info = arinsal_alloc::cpuinfo::cpu_info();
    let (cpus, online) = arinsal_alloc::cpuinfo::default_schedulers();
    let (cpus, online) = (cpus as u64, online as u64);
    match key {
        "otp_release" => string(heap, env!("ARINSAL_OTP_RELEASE")),
        "version" => string(heap, env!("ARINSAL_ERTS_VERSION")),
        "system_version" => string(
            heap,
            &format!(
                "Erlang/OTP {} [erts-{}] [arinsal {}] [{}-bit] [smp:{cpus}:{online}] [ds:{cpus}:{online}:10] [async-threads:1] [jit]\n",
                env!("ARINSAL_OTP_RELEASE"),
                env!("ARINSAL_ERTS_VERSION"),
                env!("CARGO_PKG_VERSION"),
                std::mem::size_of::<usize>() * 8
            ),
        ),
        "wordsize" => integer(heap, std::mem::size_of::<usize>() as u64),
        // Port of erts/emulator/beam/erl_bif_info.c:2855-2858 (start_time, end_time) and
        // erl_time_sup.c (make_time_val), OTP-29.1.1.
        "start_time" => signed(heap, MONOTONIC_TIME_START_EXTERNAL),
        "end_time" => signed(heap, MONOTONIC_TIME_END_EXTERNAL),
        // Port of erts/emulator/beam/erl_bif_info.c (system_info_1: break_ignored reads
        // `ignore_break`, +Bi), OTP-29.1.1.
        "break_ignored" => Ok(atom(
            if arinsal_args::active_emulator_flags().ignore_break {
                "true"
            } else {
                "false"
            },
        )),
        // Port of erts/emulator/beam/erl_bif_info.c:2980 (system_info_1: async_dist reads
        // `erts_default_spo_flags & SPO_ASYNC_DIST`, +pad), OTP-29.1.1.
        "async_dist" => Ok(atom(
            if arinsal_args::active_emulator_flags().async_dist == Some(true) {
                "true"
            } else {
                "false"
            },
        )),
        "dynamic_trace_probes" => Ok(atom("false")),
        "eager_check_io" => Ok(atom("true")),
        // No DTrace, SystemTap or LTTng support is compiled in.
        "dynamic_trace" => Ok(atom("none")),
        // Port of erts/emulator/beam/erl_bif_info.c:3426 (delayed_node_table_gc, +zdntgc),
        // OTP-29.1.1. This is the boot value used by the node table.
        "delayed_node_table_gc" => {
            match arinsal_args::active_emulator_flags().delayed_node_table_gc {
                Some(arinsal_args::DelayedNodeTableGc::Infinity) => Ok(atom("infinity")),
                Some(arinsal_args::DelayedNodeTableGc::Seconds(seconds)) => {
                    integer(heap, u64::from(seconds))
                }
                None => integer(heap, 60),
            }
        }
        "c_compiler_used" => c_compiler_used(heap),
        "context_reductions" => integer(heap, 4000),
        "schedulers" => integer(heap, cpus),
        "schedulers_online" => integer(heap, online),
        "logical_processors" => integer(heap, info.configured as u64),
        "logical_processors_available" => integer(heap, info.available as u64),
        "logical_processors_online" => integer(heap, info.online as u64),
        "dirty_cpu_schedulers" => integer(heap, cpus),
        "dirty_cpu_schedulers_online" => integer(heap, online),
        "dirty_io_schedulers" => integer(heap, 10),
        // Port of erts/emulator/beam/erl_bif_info.c:2876 and
        // erts/emulator/beam/erl_init.c:1354, OTP-29.1.1.
        "outstanding_system_requests_limit" => integer(heap, cpus.saturating_mul(2)),
        "thread_pool_size" => integer(heap, 1),
        "process_limit" => integer(
            heap,
            u64::from(arinsal_term::ptab::process_table_layout().max()),
        ),
        "atom_limit" => integer(heap, global_atoms().limit() as u64),
        "port_limit" => integer(
            heap,
            u64::from(arinsal_term::ptab::port_table_layout().max()),
        ),
        "ets_limit" => integer(heap, 8192),
        "fullsweep_after" => tagged_integer(heap, "fullsweep_after", 65_535),
        "min_heap_size" => tagged_integer(
            heap,
            "min_heap_size",
            arinsal_term::erts_next_heap_size(233, 0).unwrap() as i64,
        ),
        "min_bin_vheap_size" => tagged_integer(
            heap,
            "min_bin_vheap_size",
            arinsal_term::erts_next_heap_size(46_422, 0).unwrap() as i64,
        ),
        "max_heap_size" => {
            let map_items = [
                (atom("size"), Term::small(0).unwrap()),
                (atom("kill"), atom("true")),
                (atom("error_logger"), atom("true")),
                (atom("include_shared_binaries"), atom("false")),
            ];
            arinsal_maps::from_list(&map_items, heap).map_err(|_| system_limit())
        }
        "atom_count" => integer(heap, global_atoms().len() as u64),
        "machine" => string(heap, "BEAM"),
        // Port of erts/emulator/beam/erl_bif_info.c:3019-3024 (system_architecture) and
        // erts/emulator/utils/make_version:74 (ERLANG_ARCHITECTURE), OTP-29.1.1.
        "system_architecture" => string(heap, env!("ARINSAL_SYSTEM_ARCHITECTURE")),
        // Port of erts/emulator/beam/erl_bif_info.c (system_info emu_flavor), OTP-29.1.1.
        "emu_flavor" => Ok(atom("jit")),
        "build_type" | "emu_type" => Ok(atom(env!("ARINSAL_BUILD_TYPE"))),
        "os_type" => Ok(arinsal_bifs::os_type()),
        "endian" => Ok(atom(if cfg!(target_endian = "little") {
            "little"
        } else {
            "big"
        })),
        "heap_type" => Ok(atom("private")),
        "garbage_collection" => {
            let entries = [
                ("max_heap_size", 0),
                (
                    "min_bin_vheap_size",
                    arinsal_term::erts_next_heap_size(46_422, 0).unwrap() as i64,
                ),
                (
                    "min_heap_size",
                    arinsal_term::erts_next_heap_size(233, 0).unwrap() as i64,
                ),
                ("fullsweep_after", 65_535),
            ];
            let mut list = Term::NIL;
            for (name, value) in entries.into_iter().rev() {
                let pair = tuple(
                    heap,
                    &[atom(name), Term::small(value).expect("small integer")],
                )?;
                list = TermBuilder::new(heap)
                    .cons(pair, list)
                    .map_err(|_| system_limit())?;
            }
            Ok(list)
        }
        "alloc_util_allocators" => atom_list(
            heap,
            &[
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
            ],
        ),
        "multi_scheduling" => Ok(atom("enabled")),
        "message_queue_data" => Ok(atom("on_heap")),
        "time_correction" => Ok(atom("true")),
        "kernel_poll" => Ok(atom(if env!("ARINSAL_KERNEL_POLL") == "true" {
            "true"
        } else {
            "false"
        })),
        "time_offset" => Ok(atom("volatile")),
        "time_warp_mode" => Ok(atom("multi_time_warp")),
        // Proplist shape of erl_time_sup.c (erts_monotonic_time_source / system time source).
        // Native ticks are nanoseconds, so resolution is 1e9 rather than the raw OS counter.
        "os_monotonic_time_source" => clock_source(heap, monotonic_clock_id(), true),
        "os_system_time_source" => clock_source(heap, "CLOCK_REALTIME", false),
        "os_version" => Ok(arinsal_bifs::os_version()),
        // Port of erts/emulator/beam/erl_bif_info.c (smp_support, constant_pool_support,
        // hipe_architecture, ets_realloc_moves, compat_rel), OTP-29.1.1.
        "smp_support" | "constant_pool_support" => Ok(atom("true")),
        "hipe_architecture" => Ok(atom("undefined")),
        "ets_realloc_moves" => Ok(atom("false")),
        "compat_rel" => Ok(Term::small(29).expect("small")),
        "snifs" => {
            let mut list = Term::NIL;
            for bif in arinsal_spec::BIFS.iter() {
                if !bif.module.contains('.') {
                    let entry = tuple(
                        heap,
                        &[
                            atom(bif.module),
                            atom(bif.name),
                            Term::small(i64::from(bif.arity)).expect("small arity"),
                        ],
                    )?;
                    list = TermBuilder::new(heap)
                        .cons(entry, list)
                        .map_err(|_| system_limit())?;
                }
            }
            Ok(list)
        }
        _ => unreachable!("system_info_light_item filters selectors"),
    }
}

fn c_compiler_used<H: HeapAlloc + ?Sized>(heap: &mut H) -> Result<Term, VmError> {
    let name = env!("ARINSAL_C_COMPILER");
    let version = env!("ARINSAL_C_COMPILER_VERSION");
    let version = if version == "undefined" {
        atom("undefined")
    } else if name == "msc" || name == "gnuc" && !version.contains(',') {
        integer(heap, version.parse().map_err(|_| system_limit())?)?
    } else {
        let values = version
            .split(',')
            .map(|component| {
                component
                    .parse::<u64>()
                    .map(|value| integer(heap, value))
                    .unwrap_or_else(|_| Err(system_limit()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        tuple(heap, &values)?
    };
    tuple(heap, &[atom(name), version])
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("system_info atom"))
}

fn integer<H: HeapAlloc + ?Sized>(heap: &mut H, value: u64) -> Result<Term, VmError> {
    if let Ok(value) = i64::try_from(value)
        && let Some(term) = Term::small(value)
    {
        return Ok(term);
    }
    TermBuilder::new(heap)
        .int_from_bigint(&BigInt::from(value))
        .map_err(|_| system_limit())
}

fn signed<H: HeapAlloc + ?Sized>(heap: &mut H, value: i64) -> Result<Term, VmError> {
    if let Some(term) = Term::small(value) {
        return Ok(term);
    }
    TermBuilder::new(heap)
        .int_from_bigint(&BigInt::from(value))
        .map_err(|_| system_limit())
}

fn string<H: HeapAlloc + ?Sized>(heap: &mut H, value: &str) -> Result<Term, VmError> {
    let mut tail = Term::NIL;
    for ch in value.chars().rev() {
        let code = i64::from(ch as u32);
        tail = TermBuilder::new(heap)
            .cons(Term::small(code).ok_or_else(system_limit)?, tail)
            .map_err(|_| system_limit())?;
    }
    Ok(tail)
}

fn tuple<H: HeapAlloc + ?Sized>(heap: &mut H, elements: &[Term]) -> Result<Term, VmError> {
    TermBuilder::new(heap)
        .tuple(elements)
        .map_err(|_| system_limit())
}

fn atom_list<H: HeapAlloc + ?Sized>(heap: &mut H, names: &[&str]) -> Result<Term, VmError> {
    let mut list = Term::NIL;
    for name in names.iter().rev() {
        list = TermBuilder::new(heap)
            .cons(atom(name), list)
            .map_err(|_| system_limit())?;
    }
    Ok(list)
}

fn tagged_integer<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    key: &str,
    value: i64,
) -> Result<Term, VmError> {
    tuple(
        heap,
        &[atom(key), Term::small(value).ok_or_else(system_limit)?],
    )
}

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        atoms::SYSTEM_LIMIT,
    )))
}

fn monotonic_clock_id() -> &'static str {
    if cfg!(target_os = "macos") {
        "CLOCK_UPTIME_RAW"
    } else {
        "CLOCK_MONOTONIC"
    }
}

fn clock_source<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    clock_id: &str,
    monotonic: bool,
) -> Result<Term, VmError> {
    let resolution = Term::small(1_000_000_000).expect("nanosecond resolution fits");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let time = integer(heap, u64::try_from(nanos).unwrap_or(u64::MAX))?;
    let mut pairs = vec![
        pair(heap, "function", atom("clock_gettime"))?,
        pair(heap, "clock_id", atom(clock_id))?,
        pair(heap, "resolution", resolution)?,
    ];
    if monotonic {
        pairs.push(pair(heap, "used_resolution", resolution)?);
        pairs.push(pair(heap, "extended", atom("no"))?);
    }
    pairs.push(pair(heap, "parallel", atom("yes"))?);
    pairs.push(pair(heap, "time", time)?);
    let mut list = Term::NIL;
    for entry in pairs.into_iter().rev() {
        list = TermBuilder::new(heap)
            .cons(entry, list)
            .map_err(|_| system_limit())?;
    }
    Ok(list)
}

fn pair<H: HeapAlloc + ?Sized>(heap: &mut H, key: &str, value: Term) -> Result<Term, VmError> {
    tuple(heap, &[atom(key), value])
}

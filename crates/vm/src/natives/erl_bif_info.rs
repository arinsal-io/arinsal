//! The process inspection and system information BIFs of erl_bif_info.c.
//!
//! Port of erts/emulator/beam/erl_bif_info.c (is_process_alive_1, is_process_alive_trap,
//! system_info_1, process_info_1, erts_internal_is_process_alive_2, get_module_info_1/2,
//! erts_internal_is_system_process_1, erts_internal_process_display_2,
//! erts_internal_system_check_1, erts_debug_lcnt_*, error_logger_warning_map_0,
//! erts_debug_get_internal_state_1, erts_debug_set_internal_state_2,
//! process_info_2), OTP-29.1.1.
//! Each BIF is `bif_table[].f` with `(c_p, reg, I)`.

use crate::natives::bif::{badarg, bif_ret, with_sched};
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
        let found = if process.on_normal_scheduler() {
            scheduler.is_quiet_word(arg.tagged_word())
        } else {
            scheduler.is_quiet(pid)
        };
        let result = match found {
            None => atoms::FALSE,
            Some(true) => atoms::TRUE,
            Some(false) => return bif_ret(c_p, i, Err(alive_trap(process, arg))),
        };
        // ERTS_PROC_HAS_INCOMING_SIGNALS(BIF_P): signals from the inspected process to us must
        // be handled before the answer.
        // Port of erts/emulator/beam/erl_bif_info.c:4096-4102
        // (`ERTS_BIF_HANDLE_SIGNALS_FROM_RETURN`), OTP-29.1.1.
        let incoming = match process.signal_probe() {
            Some(probe) => probe.has_incoming_signals(),
            None => process.self_pid().is_some_and(|me| {
                scheduler
                    .with_proc_state(me, |state| {
                        state.load(std::sync::atomic::Ordering::Acquire)
                            & (arinsal_sched::psflg::SIG_Q | arinsal_sched::psflg::SIG_IN_Q)
                            != 0
                    })
                    .unwrap_or(false)
            }),
        };
        if incoming {
            return bif_ret(
                c_p,
                i,
                Err(crate::natives::sys::handle_signals_from_return(
                    process,
                    arg,
                    Term::atom(result),
                )),
            );
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

/// `process_info/2`.
// Port of erts/emulator/beam/erl_bif_info.c (process_info_2 → process_info_bif), OTP-29.1.1.
pub(crate) extern "C" fn process_info_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [pid, item] = crate::bif_table::bif_args::<2>(reg);
    let result = with_sched(process, reg, |vm, process, ctx| {
        crate::natives::proc::process_info_call(Some(&*vm), process, ctx, pid, Some(item))
    })
    .flatten();
    bif_ret(c_p, i, result)
}

/// `system_info/1`.
// Port of erts/emulator/beam/erl_bif_info.c (system_info_1), OTP-29.1.1.
pub(crate) extern "C" fn system_info_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let [selector] = crate::bif_table::bif_args::<1>(reg);
    process.heap.note_bif_entry();
    let item = system_info_body(process, selector);
    bif_ret(c_p, i, item)
}

/// The body of `system_info_1`: every selector is answered here, including the allocator
/// requests that send aux work and the `{allocator, _}` / `{allocator_sizes, _}` traps.
// Port of erts/emulator/beam/erl_bif_info.c (system_info_1, info_1_tuple), OTP-29.1.1.
pub(crate) fn system_info_body(process: &mut Process, selector: Term) -> Result<Term, VmError> {
    if let Some(item) = system_info_body_item(process, selector) {
        return item;
    }
    // erl_bif_info.c info_1_tuple: memory_internal, allocator and allocator_sizes.
    if let Some(item) = crate::natives::sys::alloc_info::system_info(process, selector) {
        return item;
    }
    let owned_selector = arinsal_term::to_owned(selector).ok();
    if let Some(arinsal_etf::OwnedTerm::Tuple(parts)) = owned_selector.as_ref()
        && let [
            arinsal_etf::OwnedTerm::Atom(operation),
            arinsal_etf::OwnedTerm::Atom(name),
        ] = parts.as_slice()
        && operation == "allocator"
    {
        return crate::natives::sys::allocator_system_info(process, name);
    }
    let name = selector
        .as_atom()
        .and_then(|atom| global_atoms().text(atom));
    match name {
        // Port of erts/emulator/beam/erl_bif_info.c:2949-2954, OTP-29.1.1.
        Some("info" | "procs" | "loaded" | "dist") => {
            crate::natives::sys::system_info_dump(process, name.unwrap())
        }
        // Port of erts/emulator/beam/erl_bif_info.c:2784 (system_info scheduler_id), OTP-29.1.1.
        Some("scheduler_id") => {
            let scheduler_id = crate::proc_create::raw::erts_psd_get_word(
                &process.psd,
                crate::proc_create::raw::ERTS_PSD_SCHED_ID,
            );
            Term::small(scheduler_id as i64)
                .filter(|_| scheduler_id != 0)
                .ok_or_else(badarg)
        }
        // Port of erts/emulator/beam/erl_bif_info.c:2879 (allocated_areas), OTP-29.1.1.
        Some("allocated_areas") => crate::natives::sys::memory_areas(process),
        _ => Err(badarg()),
    }
}

/// Selectors answered by `system_info_1` from the process and runtime state.
// Port of erts/emulator/beam/erl_bif_info.c (system_info_1), OTP-29.1.1.
pub(crate) fn system_info_body_item(
    process: &mut Process,
    selector: Term,
) -> Option<Result<Term, VmError>> {
    let name = selector
        .as_atom()
        .and_then(|atom| global_atoms().text(atom));
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
            arinsal_term::erts_next_heap_size(233, 0) as i64,
        ),
        "min_bin_vheap_size" => tagged_integer(
            heap,
            "min_bin_vheap_size",
            arinsal_term::erts_next_heap_size(46_422, 0) as i64,
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
                    arinsal_term::erts_next_heap_size(46_422, 0) as i64,
                ),
                (
                    "min_heap_size",
                    arinsal_term::erts_next_heap_size(233, 0) as i64,
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

/// `fun_info/2`: `{What, Value}` for one item of a fun.
// Port of erts/emulator/beam/erl_bif_info.c (fun_info_2), OTP-29.1.1.
pub(crate) extern "C" fn fun_info_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [fun, what] = crate::bif_table::bif_args::<2>(reg);
    // `is_not_any_fun(fun)`.
    let Some(view) = arinsal_term::raw::fun_view(fun) else {
        return crate::natives::bif::bif_badarg(c_p);
    };
    let Some(key) = what.as_atom().and_then(|atom| global_atoms().text(atom)) else {
        return crate::natives::bif::bif_badarg(c_p);
    };
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let result = fun_info_value(process, fun, &view, key).and_then(|value| match value {
        Some(value) => {
            let mut heap =
                HeapReservation::new(&mut process.heap, 0).map_err(|_| system_limit())?;
            tuple(&mut heap, &[what, value])
        }
        None => Err(badarg()),
    });
    bif_ret(c_p, i, result)
}

/// The value `fun_info_2` pairs with `key`, or `None` for an unknown key (`BIF_ERROR`).
// Port of erts/emulator/beam/erl_bif_info.c (fun_info_2: the `switch (what)`), OTP-29.1.1.
fn fun_info_value(
    process: &mut Process,
    fun: Term,
    view: &arinsal_term::FunRef<'_>,
    key: &str,
) -> Result<Option<Term>, VmError> {
    use arinsal_term::FunRef;
    // erts_get_fun_mfa(fe, erts_active_code_ix()) for a local fun, the export's MFA otherwise;
    // NULL for an unloaded local fun.
    let (module, name) = match view {
        FunRef::Local { entry, .. } => (
            entry.module,
            crate::erl_fun::erts_get_fun_mfa(entry)
                .map(|mfa| crate::native_hooks::from_raw(mfa.function)),
        ),
        FunRef::Export { entry } => (entry.module(), Some(Term::atom(entry.function()))),
    };
    let local = matches!(view, FunRef::Local { .. });
    let undefined = Term::atom(atoms::UNDEFINED);
    let small = |value: i64| Term::small(value).ok_or_else(system_limit);
    let mut heap = HeapReservation::new(&mut process.heap, 0).map_err(|_| system_limit())?;
    let value = match (view, key) {
        (_, "type") => atom(if local { "local" } else { "external" }),
        // erts_init_process_id for a local fun: set by erl_first_process_otp before any
        // process runs.
        (FunRef::Local { .. }, "pid") => process
            .runtime
            .and_then(|runtime| runtime.init_process_id.get().copied())
            .and_then(|pid| pid.to_term())
            .expect("erts_init_process_id is set before any process runs"),
        (_, "module") => Term::atom(module),
        (FunRef::Local { entry, .. }, "new_index") => small(i64::from(entry.index))?,
        (FunRef::Local { entry, .. }, "new_uniq") => TermBuilder::new(&mut heap)
            .binary(&entry.uniq)
            .map_err(|_| system_limit())?,
        (FunRef::Local { entry, .. }, "index") => small(i64::from(entry.old_index))?,
        (FunRef::Local { entry, .. }, "uniq") => small(i64::from(entry.old_uniq))?,
        (FunRef::Local { free_vars, .. }, "env") => {
            let mut list = Term::NIL;
            for &word in free_vars.iter().rev() {
                list = TermBuilder::new(&mut heap)
                    .cons(crate::native_hooks::from_raw(word), list)
                    .map_err(|_| system_limit())?;
            }
            list
        }
        (FunRef::Local { .. }, "refc") => small(1)?,
        (FunRef::Export { .. }, "pid" | "new_index" | "new_uniq" | "index" | "uniq" | "refc") => {
            undefined
        }
        (FunRef::Export { .. }, "env") => Term::NIL,
        (_, "arity") => small(i64::from(fun.fun_arity().unwrap_or(0)))?,
        // Name must be `[]` for unloaded funs.
        (_, "name") => name.unwrap_or(Term::NIL),
        _ => return Ok(None),
    };
    Ok(Some(value))
}

/// `fun_info_mfa/1`: `{Module, Function, Arity}` of a fun.
// Port of erts/emulator/beam/erl_bif_info.c (fun_info_mfa_1), OTP-29.1.1.
pub(crate) extern "C" fn fun_info_mfa_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    use arinsal_term::FunRef;
    let [fun] = crate::bif_table::bif_args::<1>(reg);
    let Some(view) = arinsal_term::raw::fun_view(fun) else {
        return crate::natives::bif::bif_badarg(c_p);
    };
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let (module, name) = match view {
        // An unloaded fun reports its module and `[]` as its name.
        FunRef::Local { entry, .. } => (
            entry.module,
            crate::erl_fun::erts_get_fun_mfa(entry)
                .map_or(Term::NIL, |mfa| crate::native_hooks::from_raw(mfa.function)),
        ),
        FunRef::Export { entry } => (entry.module(), Term::atom(entry.function())),
    };
    let result = Term::small(i64::from(fun.fun_arity().unwrap_or(0)))
        .ok_or_else(system_limit)
        .and_then(|arity| {
            let mut heap =
                HeapReservation::new(&mut process.heap, 0).map_err(|_| system_limit())?;
            tuple(&mut heap, &[Term::atom(module), name, arity])
        });
    bif_ret(c_p, i, result)
}

/// `process_info/1`: `process_info_bif` with `pi_1_keys_list`.
// Port of erts/emulator/beam/erl_bif_info.c:1560 (process_info_1), OTP-29.1.1.
pub(crate) extern "C" fn process_info_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [pid] = crate::bif_table::bif_args::<1>(reg);
    let result = crate::natives::bif::with_sched(process, reg, |_vm, process, ctx| {
        crate::natives::proc::process_info_call(None, process, ctx, pid, None)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

/// `erts_internal:is_process_alive/2`.
// Port of erts/emulator/beam/erl_bif_info.c:4049 (erts_internal_is_process_alive_2), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_is_process_alive_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [pid, reference] = crate::bif_table::bif_args::<2>(reg);
    if Pid::from_term(pid).is_none() || reference.local_ref_numbers().is_none() {
        return crate::natives::bif::bif_badarg(c_p);
    }
    let result = crate::natives::bif::with_sched(process, reg, |_vm, process, ctx| {
        crate::signals::is_process_alive_2(process, ctx, pid, reference)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

/// `get_module_info/1`.
// Port of erts/emulator/beam/erl_bif_info.c:6010 (get_module_info_1), OTP-29.1.1.
pub(crate) extern "C" fn get_module_info_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = crate::bif_table::bif_args::<1>(reg);
    bif_ret(c_p, i, crate::natives::code::module_info(process, &args))
}

/// `get_module_info/2`.
// Port of erts/emulator/beam/erl_bif_info.c:6021 (get_module_info_2), OTP-29.1.1.
pub(crate) extern "C" fn get_module_info_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = crate::bif_table::bif_args::<2>(reg);
    bif_ret(c_p, i, crate::natives::code::module_info(process, &args))
}

/// `erts_internal:is_system_process/1`.
// Port of erts/emulator/beam/erl_bif_info.c:4932 (erts_internal_is_system_process_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_is_system_process_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let [target] = crate::bif_table::bif_args::<1>(reg);
    if let Some(pid) = Pid::from_term(target) {
        let is_system = process
            .runtime
            .and_then(|runtime| runtime.scheduler().ok())
            .and_then(|scheduler| scheduler.static_flags(pid))
            .is_some_and(|flags| flags & crate::proc_create::ERTS_STC_FLG_SYSTEM_PROC != 0);
        return crate::native_hooks::raw(Term::atom(if is_system {
            atoms::TRUE
        } else {
            atoms::FALSE
        }));
    }
    if let Ok(arinsal_etf::OwnedTerm::Pid { node, .. }) = &arinsal_term::to_owned(target)
        && node == crate::node_tables::this_node().0
    {
        return crate::native_hooks::raw(Term::atom(atoms::FALSE));
    }
    crate::natives::bif::bif_badarg(c_p)
}

/// `erts_internal:process_display/2`.
// Port of erts/emulator/beam/erl_bif_info.c:4133 (erts_internal_process_display_2), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_process_display_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [target, display] = crate::bif_table::bif_args::<2>(reg);
    let result = crate::natives::bif::with_sched(process, reg, |_vm, process, ctx| {
        crate::natives::proc::process_display_call("erts_internal", process, ctx, target, display)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

/// `erts_internal:system_check/1`.
// Port of erts/emulator/beam/erl_bif_info.c:4949 (erts_internal_system_check_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_system_check_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [selector] = crate::bif_table::bif_args::<1>(reg);
    if selector != crate::atom_cache::put("schedulers") {
        return crate::natives::bif::bif_badarg(c_p);
    }
    let result = crate::natives::bif::with_sched(process, reg, |_vm, process, ctx| {
        erts_system_check_request(process, ctx)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

/// `erts_system_check_request`: one reply from each scheduler, then trap to
/// `erts_internal:gather_system_check_result/1`.
// Port of erts/emulator/beam/erl_process.c:1459 (erts_system_check_request) and
// erl_bif_info.c:4952-4956 (`BIF_TRAP1(gather_system_check_res_trap, …)`), OTP-29.1.1.
fn erts_system_check_request(
    process: &mut Process,
    ctx: &mut arinsal_sched::RunCtx<'_, crate::Process>,
) -> Result<Term, VmError> {
    let runtime = process.runtime.ok_or_else(badarg)?;
    let caller = ctx.pid();
    let id = process.next_ref();
    let reference = crate::signals::reference(process, id)?;
    let owned = arinsal_term::to_owned(reference).map_err(|_| system_limit())?;
    runtime
        .scheduler()?
        .erts_schedule_multi_misc_aux_work(move |_| {
            let Ok(message) = crate::process::Message::from_owned(&owned) else {
                return;
            };
            if let Ok(scheduler) = runtime.scheduler() {
                let _ = scheduler.send(caller, caller, message);
            }
        });
    Err(VmError::TrapExport(crate::ExportTrap::new(
        process,
        "erts_internal:gather_system_check_result/1",
        vec![reference],
    )))
}

/// `erts_debug:lcnt_clear/0` without `ERTS_ENABLE_LOCK_COUNT`.
// Port of erts/emulator/beam/erl_bif_info.c:6302 (erts_debug_lcnt_clear_0), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_lcnt_clear_0(
    _c_p: *mut ProcessHeader,
    _reg: *mut u64,
    _i: u64,
) -> u64 {
    crate::native_hooks::raw(Term::atom(atoms::ERROR))
}

/// `erts_debug:lcnt_collect/0` without `ERTS_ENABLE_LOCK_COUNT`.
// Port of erts/emulator/beam/erl_bif_info.c:6313 (erts_debug_lcnt_collect_0), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_lcnt_collect_0(
    _c_p: *mut ProcessHeader,
    _reg: *mut u64,
    _i: u64,
) -> u64 {
    crate::native_hooks::raw(Term::atom(atoms::ERROR))
}

/// `erts_debug:lcnt_control/1` without `ERTS_ENABLE_LOCK_COUNT`.
// Port of erts/emulator/beam/erl_bif_info.c:6348 (erts_debug_lcnt_control_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_lcnt_control_1(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    _i: u64,
) -> u64 {
    crate::natives::bif::bif_badarg(c_p)
}

/// `erts_debug:lcnt_control/2` without `ERTS_ENABLE_LOCK_COUNT`.
// Port of erts/emulator/beam/erl_bif_info.c:6375 (erts_debug_lcnt_control_2), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_lcnt_control_2(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    _i: u64,
) -> u64 {
    crate::natives::bif::bif_badarg(c_p)
}

/// `error_logger:warning_map/0`.
// Port of erts/emulator/beam/erl_bif_info.c:4327 (error_logger_warning_map_0), OTP-29.1.1.
pub(crate) extern "C" fn error_logger_warning_map_0(
    _c_p: *mut ProcessHeader,
    _reg: *mut u64,
    _i: u64,
) -> u64 {
    crate::native_hooks::raw(Term::atom(atoms::WARNING))
}

/// `erts_debug:get_internal_state/1`.
// Port of erts/emulator/beam/erl_bif_info.c:4339 (erts_debug_get_internal_state_1), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_get_internal_state_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [selector] = crate::bif_table::bif_args::<1>(reg);
    let result = crate::natives::bif::with_sched(process, reg, |vm, process, ctx| {
        crate::natives::erts_debug::internal_state_get(vm, process, ctx, selector)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

/// `erts_debug:set_internal_state/2`.
// Port of erts/emulator/beam/erl_bif_info.c:5036 (erts_debug_set_internal_state_2), OTP-29.1.1.
pub(crate) extern "C" fn erts_debug_set_internal_state_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [selector, value] = crate::bif_table::bif_args::<2>(reg);
    let result = crate::natives::bif::with_sched(process, reg, |_vm, process, ctx| {
        crate::natives::erts_debug::internal_state_set(process, ctx, selector, value)
    })
    .flatten();
    bif_ret(c_p, i, result)
}

//! Operating-system and stable runtime information BIFs.

use std::ffi::OsString;
use std::time::Instant;

use arinsal_term::{Term, TermBuilder, global_atoms};

use crate::pure::{Heap, atom_name, tuple_build};
use crate::{BifError, Ctx};

static PERF_START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
static EMU_FLAVOR_JIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Records whether the VM runs BeamAsm (`jit`) or the interpreter (`emu`).
pub fn set_emu_flavor_jit(jit: bool) {
    EMU_FLAVOR_JIT.store(jit, std::sync::atomic::Ordering::Relaxed);
}

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    let f = match (module, name, arity) {
        ("erlang", "system_info", 1) => v.entry::<bodies::system_info>(),
        ("erts_internal", "no_aux_work_threads", 0) => v.entry::<bodies::no_aux_work_threads>(),
        ("os", "getenv", 1) => v.entry::<bodies::getenv>(),
        ("os", "getpid", 0) => v.entry::<bodies::getpid>(),
        ("os", "perf_counter", 0) => v.entry::<bodies::perf_counter>(),
        _ => return None,
    };
    if module == "os" || arinsal_spec::bif_lookup(module, name, arity).is_some() {
        Some(f)
    } else {
        None
    }
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("short runtime atom"))
}
fn integer(ctx: &mut Ctx<'_>, value: u64) -> Result<Term, BifError> {
    if let Ok(value) = i64::try_from(value)
        && let Some(term) = Term::small(value)
    {
        return Ok(term);
    }
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .int_from_bigint(&num_bigint::BigInt::from(value))
        .map_err(|_| BifError::SystemLimit)
}
fn string(ctx: &mut Ctx<'_>, value: &str) -> Result<Term, BifError> {
    let mut tail = Term::NIL;
    for ch in value.chars().rev() {
        let code = i64::from(ch as u32);
        tail = TermBuilder::new(&mut Heap(&mut ctx.heap))
            .cons(Term::small(code).ok_or(BifError::SystemLimit)?, tail)
            .map_err(|_| BifError::SystemLimit)?;
    }
    Ok(tail)
}

// Port of erts/emulator/beam/erl_bif_info.c:2773 (system_info_1), OTP-29.1.1.
fn system_info(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let key = atom_name(args[0]).ok_or(BifError::BADARG)?;
    let cpus = std::thread::available_parallelism().map_or(1, usize::from) as u64;
    match key {
        "otp_release" => string(ctx, "29"),
        "version" => string(ctx, "17.1"),
        "system_version" => string(
            ctx,
            &format!(
                "Erlang/OTP 29 [erts-17.1] [arinsal {}] [{}-bit] [smp:{cpus}:{cpus}] [ds:{cpus}:{cpus}:10] [async-threads:1] [jit]\n",
                env!("CARGO_PKG_VERSION"),
                std::mem::size_of::<usize>() * 8
            ),
        ),
        "wordsize" => integer(ctx, std::mem::size_of::<usize>() as u64),
        // Port of erts/emulator/beam/erl_bif_info.c:2773 (system_info_1), OTP-29.1.1.
        "start_time" => Term::small(-(1_i64 << 59)).ok_or(BifError::SystemLimit),
        "context_reductions" => integer(ctx, 4000),
        "schedulers"
        | "schedulers_online"
        | "logical_processors"
        | "logical_processors_available"
        | "logical_processors_online" => integer(ctx, cpus),
        "dirty_cpu_schedulers" | "dirty_cpu_schedulers_online" => integer(ctx, cpus),
        "dirty_io_schedulers" => integer(ctx, cpus),
        // Port of erts/emulator/beam/erl_bif_info.c:2876 and
        // erts/emulator/beam/erl_init.c:1354, OTP-29.1.1.
        "outstanding_system_requests_limit" => integer(ctx, cpus.saturating_mul(2)),
        "thread_pool_size" => integer(ctx, 1),
        "process_limit" => integer(
            ctx,
            u64::from(arinsal_term::ptab::process_table_layout().max()),
        ),
        "atom_limit" => integer(ctx, global_atoms().limit() as u64),
        "port_limit" => integer(
            ctx,
            u64::from(arinsal_term::ptab::port_table_layout().max()),
        ),
        "ets_limit" => integer(ctx, 8192),
        "fullsweep_after" => tagged_integer(ctx, "fullsweep_after", 65_535),
        "min_heap_size" => tagged_integer(ctx, "min_heap_size", 233),
        "min_bin_vheap_size" => tagged_integer(ctx, "min_bin_vheap_size", 46_422),
        "max_heap_size" => {
            let map_items = [
                (atom("size"), Term::small(0).unwrap()),
                (atom("kill"), atom("true")),
                (atom("error_logger"), atom("true")),
                (atom("include_shared_binaries"), atom("false")),
            ];
            let mut heap = Heap(&mut ctx.heap);
            arinsal_maps::from_list(&map_items, &mut heap).map_err(|_| BifError::SystemLimit)
        }
        "atom_count" | "process_count" | "port_count" => integer(ctx, 0),
        "machine" => string(ctx, "BEAM"),
        // Port of erts/emulator/beam/erl_bif_info.c (system_info emu_flavor), OTP-29.1.1.
        "emu_flavor" => Ok(atom(
            if EMU_FLAVOR_JIT.load(std::sync::atomic::Ordering::Relaxed) {
                "jit"
            } else {
                "emu"
            },
        )),
        "build_type" | "emu_type" => Ok(atom("opt")),
        "os_type" => Ok(tuple_build(ctx, &[atom("unix"), atom("darwin")])),
        "endian" => Ok(atom(if cfg!(target_endian = "little") {
            "little"
        } else {
            "big"
        })),
        "heap_type" => Ok(atom("private")),
        "garbage_collection" => {
            let entries = [
                ("max_heap_size", 0),
                ("min_bin_vheap_size", 46_422),
                ("min_heap_size", 233),
                ("fullsweep_after", 65_535),
            ];
            let mut list = Term::NIL;
            for (name, value) in entries.into_iter().rev() {
                let pair = tuple_build(ctx, &[atom(name), Term::small(value).unwrap()]);
                list = TermBuilder::new(&mut Heap(&mut ctx.heap))
                    .cons(pair, list)
                    .map_err(|_| BifError::SystemLimit)?;
            }
            Ok(list)
        }
        "alloc_util_allocators" => atom_list(
            ctx,
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
        "time_correction" | "kernel_poll" => Ok(atom("true")),
        "time_offset" => Ok(atom("volatile")),
        "time_warp_mode" => Ok(atom("multi_time_warp")),
        // Proplist shape of erl_time_sup.c (erts_monotonic_time_source / system time source).
        // Native ticks are nanoseconds, so resolution is 1e9 rather than the raw OS counter.
        "os_monotonic_time_source" => clock_source(ctx, monotonic_clock_id(), true),
        "os_system_time_source" => clock_source(ctx, "CLOCK_REALTIME", false),
        "os_version" => {
            let vals = if cfg!(target_os = "macos") {
                [25, 6, 0]
            } else {
                [0, 0, 0]
            };
            Ok(tuple_build(ctx, &vals.map(|n| Term::small(n).unwrap())))
        }
        "scheduler_bind_type" => Ok(atom("unbound")),
        "thread_support" | "smp_support" | "async_threads" => Ok(atom("true")),
        // Port of erts/emulator/beam/erl_bif_info.c:2742-2768 (build_snifs_term), OTP-29.1.1.
        "snifs" => {
            let mut list = Term::NIL;
            for bif in arinsal_spec::BIFS.iter() {
                if !bif.module.contains('.') {
                    let entry = tuple_build(
                        ctx,
                        &[
                            atom(bif.module),
                            atom(bif.name),
                            Term::small(i64::from(bif.arity)).unwrap(),
                        ],
                    );
                    list = TermBuilder::new(&mut Heap(&mut ctx.heap))
                        .cons(entry, list)
                        .map_err(|_| BifError::SystemLimit)?;
                }
            }
            Ok(list)
        }
        _ => Err(BifError::BADARG),
    }
}

fn atom_list(ctx: &mut Ctx<'_>, names: &[&str]) -> Result<Term, BifError> {
    let mut list = Term::NIL;
    for name in names.iter().rev() {
        list = TermBuilder::new(&mut Heap(&mut ctx.heap))
            .cons(atom(name), list)
            .map_err(|_| BifError::SystemLimit)?;
    }
    Ok(list)
}

fn no_aux_work_threads(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_process.c:9234 and :6219-6223, OTP-29.1.1.
    // The runtime uses one standard auxiliary worker and no dirty allocator instances.
    let schedulers = std::thread::available_parallelism().map_or(1, usize::from) as u64;
    integer(ctx, schedulers.saturating_add(1))
}

fn tagged_integer(ctx: &mut Ctx<'_>, key: &str, value: i64) -> Result<Term, BifError> {
    Ok(tuple_build(
        ctx,
        &[atom(key), Term::small(value).ok_or(BifError::SystemLimit)?],
    ))
}

fn os_string(ctx: &mut Ctx<'_>, value: OsString) -> Result<Term, BifError> {
    string(ctx, &value.to_string_lossy())
}
fn getenv(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let chars = crate::pure::list(args[0])?;
    let mut name = String::new();
    for ch in chars {
        let code = ch
            .as_small()
            .filter(|n| (0..=0x10ffff).contains(n))
            .ok_or(BifError::BADARG)?;
        name.push(char::from_u32(code as u32).ok_or(BifError::BADARG)?);
    }
    match std::env::var_os(name) {
        Some(value) => os_string(ctx, value),
        None => Ok(atom("false")),
    }
}
fn getpid(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    // SAFETY: getpid has no preconditions and does not retain pointers.
    string(ctx, &unsafe { libc::getpid() }.to_string())
}
fn monotonic_clock_id() -> &'static str {
    if cfg!(target_os = "macos") {
        "CLOCK_UPTIME_RAW"
    } else {
        "CLOCK_MONOTONIC"
    }
}

fn clock_source(ctx: &mut Ctx<'_>, clock_id: &str, monotonic: bool) -> Result<Term, BifError> {
    let resolution = Term::small(1_000_000_000).expect("nanosecond resolution fits");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let time = integer(ctx, u64::try_from(nanos).unwrap_or(u64::MAX))?;
    let mut pairs = vec![
        pair(ctx, "function", atom("clock_gettime"))?,
        pair(ctx, "clock_id", atom(clock_id))?,
        pair(ctx, "resolution", resolution)?,
    ];
    if monotonic {
        pairs.push(pair(ctx, "used_resolution", resolution)?);
        pairs.push(pair(ctx, "extended", atom("no"))?);
    }
    pairs.push(pair(ctx, "parallel", atom("yes"))?);
    pairs.push(pair(ctx, "time", time)?);
    let mut list = Term::NIL;
    for entry in pairs.into_iter().rev() {
        list = TermBuilder::new(&mut Heap(&mut ctx.heap))
            .cons(entry, list)
            .map_err(|_| BifError::SystemLimit)?;
    }
    Ok(list)
}

fn pair(ctx: &mut Ctx<'_>, key: &str, value: Term) -> Result<Term, BifError> {
    Ok(tuple_build(ctx, &[atom(key), value]))
}

/// The performance counter in nanoseconds (`erts_sys_perf_counter`); native
/// `os:perf_counter/0` calls it directly.
// Port of erts/emulator/sys/unix/erl_unix_sys.h:286-296 (erts_sys_perf_counter), OTP-29.1.1.
pub extern "C" fn sys_perf_counter() -> u64 {
    let nanos = PERF_START.get_or_init(Instant::now).elapsed().as_nanos();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

fn perf_counter(ctx: &mut Ctx<'_>, _args: &[Term]) -> Result<Term, BifError> {
    integer(ctx, sys_perf_counter())
}

crate::bif_bodies!(
    system_info,
    no_aux_work_threads,
    getenv,
    getpid,
    perf_counter,
);

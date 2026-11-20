//! OTP startup through the first process used by ERTS.

use crate::{Vm, VmError};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms};
use std::path::Path;

/// Starts the node ([`erl_start`]) and turns the calling (main) thread into
/// `erts_sys_main_thread`: it returns only when the node could not be started. The node ends
/// through `erts_exit` (`halt/2`, or a system process terminating).
pub fn run(
    root: &Path,
    boot_args: &[String],
    workers: usize,
) -> Result<std::convert::Infallible, VmError> {
    run_with_debugger_flags(root, boot_args, workers, false, true, None)
}

/// Creates the eval carrier's pipes and returns the boot arguments that start it on the node
/// (`-pa <code_dir> -run arinsal_eval_carrier start R W`, `code_dir` holding
/// `arinsal_eval_carrier.beam`): an embedder appends them to the command line before
/// [`erl_start`], and [`Vm::eval_scheduled`] then evaluates in processes of the node and
/// receives results over that port. Callable once per OS process.
pub fn eval_carrier_args(code_dir: &Path) -> Result<Vec<String>, VmError> {
    crate::process::eval_carrier_args(code_dir)
}

/// Seed the VM's OS environment table (erlexec `set_env` for PATH and `-env`).
pub fn seed_environment(vars: &[(String, String)]) {
    crate::erl_osenv::seed(vars);
}

/// [`run`] with the emulator's debugger startup flags.
// Port of erts/emulator/beam/erl_init.c:1295-2617 (erl_start ending in
// `erts_sys_main_thread()`), OTP-29.1.1.
pub fn run_with_debugger_flags(
    root: &Path,
    boot_args: &[String],
    workers: usize,
    debugger_support: bool,
    line_breakpoints: bool,
    distribution_buffer_busy_limit_kb: Option<u64>,
) -> Result<std::convert::Infallible, VmError> {
    let _vm = erl_start(
        root,
        boot_args,
        workers,
        debugger_support,
        line_breakpoints,
        distribution_buffer_busy_limit_kb,
    )?;
    crate::sys_signals::erts_sys_main_thread()
}

/// Starts the node and returns once its scheduler threads run: the runtime initialisation, the
/// preloaded modules, `erl_init:start(init, BootArgs)` as the first process, which boots OTP
/// (`init:boot/1`), and the system processes. The returned `Vm` loads and evaluates in the
/// running node.
// Port of erts/emulator/beam/erl_init.c (erl_start: erl_init, load_preloaded,
// erl_first_process_otp), OTP-29.1.1.
pub fn erl_start(
    root: &Path,
    boot_args: &[String],
    workers: usize,
    debugger_support: bool,
    line_breakpoints: bool,
    distribution_buffer_busy_limit_kb: Option<u64>,
) -> Result<Vm, VmError> {
    // Port of erts/emulator/sys/common/erl_sys_common_misc.c (erts_init_sys_common_misc):
    // the locale is read once at boot and decides the native file name encoding.
    crate::natives::erl_unicode::set_locale_utf8(arinsal_nif_tty::locale_is_utf8());
    // Port of erl_init.c:138 and :2223 (`+t` into `erts_atom_table_size`), OTP-29.1.1.
    // Read before `erl_init_atoms`, which publishes the process-wide table.
    if let Some(limit) = arinsal_args::active_emulator_flags().atom_limit {
        arinsal_term::set_atom_table_limit(usize::try_from(limit).unwrap_or(usize::MAX));
    }
    let async_threads = arinsal_args::active_emulator_flags()
        .async_threads
        .unwrap_or(1)
        .max(1) as usize;
    // Port of erts/emulator/beam/erl_init.c:925, 1162-1163 (+A), OTP-29.1.1.
    arinsal_drv::set_async_threads(async_threads);
    // Port of erts/emulator/beam/erl_init.c:303 (erl_init -> erts_init_node_tables), OTP-29.1.1.
    crate::node_tables::init_node_tab_delete_delay(
        arinsal_args::active_emulator_flags().delayed_node_table_gc,
    );
    // Port of erts/emulator/beam/erl_init.c (erl_start): `if (ignore_break) erts_set_ignore_break()`.
    // Restart will not reinstall the break handler.
    let flags = arinsal_args::active_emulator_flags();
    if !flags.ignore_break && !flags.no_break_handler {
        crate::natives::tty::start_break_menu();
    }
    if flags.replace_intr {
        crate::natives::tty::replace_intr();
    }
    crate::node_tables::lock().set_distribution_buffer_busy_limit(
        distribution_buffer_busy_limit_kb
            .unwrap_or(1024)
            .saturating_mul(1024),
    );
    // `load_preloaded` is the VM's only file-based loading step; init and code_server handle
    // the boot path after the first process starts.
    let erts_ebin = root.join("lib/erts-17.1/ebin");
    let (mut vm, runtime) = crate::erl_init::erl_init(
        root.to_path_buf(),
        workers,
        debugger_support,
        line_breakpoints,
    )?;
    // Port of erts/emulator/sys/unix/sys.c (erts_sys_unix_later_init) and erl_init.c
    // (init_break_handler): the signal dispatcher and dispositions exist before init runs.
    crate::sys_signals::install_boot_signals(runtime)?;

    load_preloaded(&mut vm, &erts_ebin)?;

    let mut input_heap = VecHeap::new();
    let boot_list =
        {
            let mut builder = TermBuilder::new(&mut input_heap);
            let mut args = Vec::with_capacity(boot_args.len());
            for argument in boot_args {
                args.push(builder.binary(argument.as_bytes()).map_err(|e| {
                    VmError::Load(format!("cannot construct boot argument: {e:?}"))
                })?);
            }
            builder
                .list_from_iter(args)
                .map_err(|e| VmError::Load(format!("cannot construct boot arguments: {e:?}")))?
        };
    let init = global_atoms()
        .intern("init")
        .map_err(|error| VmError::Load(format!("cannot intern init: {error:?}")))?;
    vm.erl_first_process_otp(runtime, Term::atom(init), boot_list)?;
    vm.erl_system_processes_otp(runtime)?;
    runtime.erts_start_schedulers()?;
    Ok(vm)
}

/// Loads the preloaded modules into one staging code index and commits it once.
// Port of erts/emulator/beam/erl_init.c:508 (load_preloaded) and erl_start's
// `erts_end_staging_code_ix(); erts_commit_staging_code_ix();`, OTP-29.1.1: modules load in
// the generated preload.c order, each name interned first.
fn load_preloaded(vm: &mut Vm, erts_ebin: &Path) -> Result<(), VmError> {
    let staging = crate::code_ix::global().start_staging();
    for module in PRELOADED {
        let path = erts_ebin.join(format!("{module}.beam"));
        if crate::calls::trace_boot_enabled() {
            eprintln!("arinsal boot: load {}", path.display());
        }
        global_atoms()
            .intern(module)
            .map_err(|error| VmError::Load(format!("cannot intern {module}: {error:?}")))?;
        let bytes = std::fs::read(&path).map_err(|e| VmError::Load(e.to_string()))?;
        vm.load_bytes(&preload_strip(&bytes))?;
    }
    staging
        .end()
        .ok_or_else(|| VmError::Load("load_preloaded: staging area not open".into()))?
        .commit();
    Ok(())
}

/// The beam a preloaded module is compiled into: only the chunks the loader needs, in chunk-id
/// order. Line, debug and attribute chunks are dropped, so frames of preloaded modules have no
/// file or line (`init:start_it/1` is `{init,start_it,1,[]}`), as in erl.
// Port of erts/emulator/utils/make_preload (beam_strip), OTP-29.1.1.
fn preload_strip(beam: &[u8]) -> Vec<u8> {
    const NEEDED: [&[u8; 4]; 8] = [
        b"Code", b"AtU8", b"ImpT", b"ExpT", b"StrT", b"FunT", b"LitT", b"Type",
    ];
    // A compressed module is not an IFF form: make_preload leaves it as it is.
    if beam.len() < 12 || &beam[..4] != b"FOR1" || &beam[8..12] != b"BEAM" {
        return beam.to_vec();
    }
    let mut chunks = std::collections::BTreeMap::new();
    let mut rest = &beam[12..];
    while rest.len() >= 8 {
        let id: [u8; 4] = rest[..4].try_into().expect("four bytes");
        let size = u32::from_be_bytes(rest[4..8].try_into().expect("four bytes")) as usize;
        let padded = size.div_ceil(4) * 4;
        let end = (8 + padded).min(rest.len());
        chunks.insert(id, &rest[..end]);
        rest = &rest[end..];
    }
    let body: Vec<u8> = chunks
        .iter()
        .filter(|(id, _)| NEEDED.contains(id))
        .flat_map(|(_, chunk)| chunk.iter().copied())
        .collect();
    let mut out = Vec::with_capacity(body.len() + 12);
    out.extend_from_slice(b"FOR1");
    out.extend_from_slice(
        &u32::try_from(body.len() + 4)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(b"BEAM");
    out.extend_from_slice(&body);
    out
}

/// Preloaded modules in the order of `PRELOAD_BEAM`.
// Port of erts/emulator/Makefile.in:804-828 (ESOCK_PRELOAD_BEAM, PRELOAD_BEAM), OTP-29.1.1.
const PRELOADED: [&str; 22] = [
    "erts_code_purger",
    "erl_init",
    "init",
    "prim_buffer",
    "prim_eval",
    "prim_inet",
    "prim_file",
    "zlib",
    "socket_registry",
    "prim_socket",
    "prim_net",
    "prim_zip",
    "erl_prim_loader",
    "erlang",
    "erts_internal",
    "erl_tracer",
    "erts_literal_area_collector",
    "erts_trace_cleaner",
    "erts_dirty_process_signal_handler",
    "atomics",
    "counters",
    "persistent_term",
];

/// `os:type()` flavor: the lower-cased `uname` sysname.
// Port of erts/emulator/sys/unix/sys.c:855 (os_flavor), OTP-29.1.1.
const OS_FLAVOR: &str = if cfg!(target_os = "macos") {
    "darwin"
} else if cfg!(target_os = "linux") {
    "linux"
} else if cfg!(target_os = "freebsd") {
    "freebsd"
} else if cfg!(target_os = "openbsd") {
    "openbsd"
} else if cfg!(target_os = "netbsd") {
    "netbsd"
} else {
    std::env::consts::OS
};

/// The global literals the owners' inits build.
///
/// Port of erts/emulator/beam/erl_init.c (erl_init): os_info_init (erts_bif_info_init),
/// init_dist and beamfile_init each build their global literal.
pub(crate) fn erl_init_global_literals() {
    arinsal_term::init_global_literals();
    arinsal_bifs::os_info_init();
    crate::dist::init_dist_dflags_record();
    arinsal_loader::beamfile_init();
}

/// Intern the atoms that erts' C initialisation creates after the static atom
/// table and before the preloaded modules load, in `erl_init()` call order.
///
/// Atom indices decide flatmap key order and the HAMT hash of atom keys, so
/// these must get the same indices as in erts.
pub(crate) fn erl_init_atoms() -> Result<(), VmError> {
    let groups: [&[&str]; 9] = [
        // Port of erts/emulator/beam/jit/beam_jit_main.cpp:273 (beamasm_init), OTP-29.1.1.
        &["erts_beamasm"],
        // Port of erts/emulator/beam/erl_bif_info.c:6418 (os_info_init), OTP-29.1.1.
        &["unix", OS_FLAVOR],
        // Port of erts/emulator/beam/erl_db.c:4732 (init_db), OTP-29.1.1.
        &[
            "select_delete_trap",
            "count_trap",
            "replace_trap",
            "select_trap",
            "delete_trap",
        ],
        // Port of erts/emulator/beam/io.c (erts_init_io): sys_drivers.c:291 (forker
        // driver), drivers/common/inet_drv.c:4526 (inet_init) and
        // drivers/common/ram_file_drv.c:156 (ram_file_init), OTP-29.1.1.
        &[
            "spawn_forker",
            "inet",
            "unspec",
            "tcp",
            "udp",
            "inet_async",
            "inet_reply",
            "tcp_passive",
            "tcp_closed",
            "tcp_error",
            "udp_passive",
            "udp_error",
            "empty_out_q",
            "tos",
            "tclass",
            "ttl",
            "sendfile",
            "tcp_inet",
            "udp_inet",
            "ram_file_drv",
        ],
        // Port of erts/emulator/beam/erl_bif_chksum.c:46 (erts_init_bif_chksum) and
        // erl_unicode.c:79 (erts_init_unicode), OTP-29.1.1.
        &[
            "md5_trap",
            "characters_to_utf8_trap",
            "characters_to_list_trap_1",
            "characters_to_list_trap_2",
            "characters_to_list_trap_3",
            "characters_to_list_trap_4",
        ],
        // Port of erts/emulator/beam/erl_process.c:781 (erts_late_init_process), OTP-29.1.1.
        &[
            "process_max",
            "process_high",
            "process_normal",
            "process_low",
        ],
        // Port of erts/emulator/beam/packet_parser.c:235 (packet_parser_init), OTP-29.1.1.
        &[
            "Cache-Control",
            "Connection",
            "Date",
            "Pragma",
            "Transfer-Encoding",
            "Upgrade",
            "Via",
            "Accept",
            "Accept-Charset",
            "Accept-Encoding",
            "Accept-Language",
            "Authorization",
            "From",
            "Host",
            "If-Modified-Since",
            "If-Match",
            "If-None-Match",
            "If-Range",
            "If-Unmodified-Since",
            "Max-Forwards",
            "Proxy-Authorization",
            "Range",
            "Referer",
            "User-Agent",
            "Age",
            "Location",
            "Proxy-Authenticate",
            "Public",
            "Retry-After",
            "Server",
            "Vary",
            "Warning",
            "Www-Authenticate",
            "Allow",
            "Content-Base",
            "Content-Encoding",
            "Content-Language",
            "Content-Length",
            "Content-Location",
            "Content-Md5",
            "Content-Range",
            "Content-Type",
            "Etag",
            "Expires",
            "Last-Modified",
            "Accept-Ranges",
            "Set-Cookie",
            "Set-Cookie2",
            "X-Forwarded-For",
            "Cookie",
            "Keep-Alive",
            "Proxy-Connection",
            "OPTIONS",
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "DELETE",
            "TRACE",
        ],
        // Port of erts/emulator/beam/erl_nif.c:5311 (static_nifs_init), OTP-29.1.1.
        &[
            "prim_tty",
            "prim_buffer",
            "zlib",
            "zstd",
            "prim_socket",
            "prim_net",
        ],
        // Port of erts/emulator/beam/erl_msacc.c:80 (erts_msacc_init), OTP-29.1.1.
        &["aux", "check_io", "gc", "other", "sleep"],
    ];
    for name in groups.into_iter().flatten() {
        global_atoms()
            .intern(name)
            .map_err(|error| VmError::Load(format!("cannot intern {name}: {error:?}")))?;
    }
    Ok(())
}

/// The node of this test process, started as `arinsal -noshell -noinput` ([`erl_start`]) and
/// returned once `init:get_status()` is `{started, started}`: erts has no bare VM to evaluate
/// in. Each test runs in its own OS process (nextest), so every test gets a fresh node.
#[cfg(test)]
pub(crate) fn test_node() -> std::sync::MutexGuard<'static, Vm> {
    static NODE: std::sync::OnceLock<std::sync::Mutex<Vm>> = std::sync::OnceLock::new();
    NODE.get_or_init(|| {
        let root = arinsal_difftest::reference::otp_root().expect("OTP root (erl on PATH)");
        let mut env: std::collections::BTreeMap<String, String> = std::env::vars().collect();
        env.insert("ERL_ROOTDIR".into(), root.display().to_string());
        let mut argv = vec!["arinsal".to_owned(), "-noshell".into(), "-noinput".into()];
        let carrier = concat!(env!("CARGO_MANIFEST_DIR"), "/eval_carrier");
        argv.extend(eval_carrier_args(Path::new(carrier)).expect("eval carrier"));
        let launch = arinsal_args::parse(&argv, &env)
            .unwrap_or_else(|error| panic!("test node arguments: {error:?}"));
        arinsal_args::configure_emulator_flags(launch.emulator.clone());
        let workers = arinsal_alloc::cpuinfo::default_schedulers().0.max(1);
        let mut vm = erl_start(
            Path::new(&launch.root_dir),
            &launch.boot_args,
            workers,
            false,
            true,
            None,
        )
        .expect("start test node");
        let init = Term::atom(global_atoms().intern("init").expect("intern init"));
        for _ in 0..12_000 {
            // `init:get_status/0` calls the registered `init`, which `init:boot/1` registers first.
            let registered = vm
                .eval_scheduled("erlang", "whereis", &[init], 1)
                .expect("erlang:whereis(init)")
                .text
                != "undefined";
            if registered
                && vm
                    .eval_scheduled("init", "get_status", &[], 1)
                    .expect("init:get_status()")
                    .text
                    == "{started,started}"
            {
                return std::sync::Mutex::new(vm);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("test node did not finish booting");
    })
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
}

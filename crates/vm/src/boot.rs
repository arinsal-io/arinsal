//! OTP startup through the first process used by ERTS.

use crate::{ScheduledResult, Vm, VmError};
use arinsal_term::{Term, TermBuilder, VecHeap, global_atoms};
use std::path::{Path, PathBuf};

/// Start `erl_init:start(init, BootArgs)` with OTP's preloaded code available.
pub fn run(
    root: &Path,
    boot_args: &[String],
    extra_paths: &[PathBuf],
    workers: usize,
) -> Result<ScheduledResult, VmError> {
    run_with_debugger_flags(root, boot_args, extra_paths, workers, false, true, None)
}

/// Seed the VM's OS environment table (erlexec `set_env` for PATH and `-env`).
pub fn seed_environment(vars: &[(String, String)]) {
    crate::natives::env::seed(vars);
}

/// Start OTP after applying the emulator's debugger startup flags.
pub fn run_with_debugger_flags(
    root: &Path,
    boot_args: &[String],
    extra_paths: &[PathBuf],
    workers: usize,
    debugger_support: bool,
    line_breakpoints: bool,
    distribution_buffer_busy_limit_kb: Option<u64>,
) -> Result<ScheduledResult, VmError> {
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
    erl_init_atoms()?;
    crate::trace_bp::configure_debugger(debugger_support, line_breakpoints);
    // g_erl_flags: -pa / -pz / -path and ERL_LIBS. boot_loop2 should keep this
    // block; it only chooses the loader path before preloaded modules load.
    // Port of erts/preloaded/src/init.erl:1259 (path_flags) and
    // lib/kernel/src/code_server.erl:127 (get_user_lib_dirs), OTP-29.1.1.
    let code_path = arinsal_args::arguments_from_boot(boot_args).code_path();
    crate::node_tables::lock().set_distribution_buffer_busy_limit(
        distribution_buffer_busy_limit_kb
            .unwrap_or(1024)
            .saturating_mul(1024),
    );
    let mut paths = Vec::new();
    if let Some(replace) = code_path.replace {
        paths.extend(replace.into_iter().map(PathBuf::from));
    } else {
        paths.extend(code_path.prepend.into_iter().map(PathBuf::from));
        if code_path.interactive {
            paths.extend(user_lib_dirs());
        }
        paths.extend(extra_paths.iter().cloned());
        // elixir_loop1: Elixir's start/2 later adds these to code_server, but
        // the VM loader must see them in every scheduler replica as well.
        if let Some(root) = boot_args
            .windows(2)
            .find(|pair| pair[0] == "-elixir_root")
            .map(|pair| PathBuf::from(&pair[1]))
        {
            // Port of Elixir 1.20.4 lib/elixir/src/elixir.erl:68 (start/2).
            for app in ["elixir", "mix", "logger", "iex", "ex_unit", "eex"] {
                let path = root.join(app).join("ebin");
                if path.is_dir() {
                    paths.push(path);
                }
            }
        }
        let lib = root.join("lib");
        if let Ok(entries) = std::fs::read_dir(&lib) {
            let mut app_paths: Vec<_> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path().join("ebin"))
                .filter(|path| path.is_dir())
                .collect();
            app_paths.sort();
            paths.extend(app_paths);
        }
        paths.extend(code_path.append.into_iter().map(PathBuf::from));
    }
    let erts_ebin = root.join("lib/erts-17.1/ebin");
    paths.push(erts_ebin.clone());
    let mut vm = Vm::new_with_otp_root(paths, root.to_path_buf());

    // Port of erts/emulator/beam/erl_init.c:518-535 (load_preloaded), OTP-29.1.1:
    // modules load in the generated preload.c order, each name interned first.
    for module in PRELOADED {
        let path = erts_ebin.join(format!("{module}.beam"));
        if crate::calls::trace_boot_enabled() {
            eprintln!("arinsal boot: load {}", path.display());
        }
        global_atoms()
            .intern(module)
            .map_err(|error| VmError::Load(format!("cannot intern {module}: {error:?}")))?;
        vm.load_file(&path)?;
    }

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
        .map_err(|error| VmError::Load(format!("cannot intern init atom: {error:?}")))?;
    vm.eval_scheduled(
        "erl_init",
        "start",
        &[Term::atom(init), boot_list],
        workers.max(1),
        None,
    )
}

// Port of lib/kernel/src/code_server.erl:127 (get_user_lib_dirs), OTP-29.1.1.
fn user_lib_dirs() -> Vec<PathBuf> {
    let Ok(raw) = std::env::var("ERL_LIBS") else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    for dir in raw.split(':') {
        if dir.is_empty() {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut found = Vec::new();
        for entry in entries.filter_map(Result::ok) {
            let ebin = entry.path().join("ebin");
            if ebin.is_dir() {
                found.insert(0, ebin);
            }
        }
        paths.extend(found);
    }
    paths
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

/// Intern the atoms that erts' C initialisation creates after the static atom
/// table and before the preloaded modules load, in `erl_init()` call order.
///
/// Atom indices decide flatmap key order and the HAMT hash of atom keys, so
/// these must get the same indices as in erts.
fn erl_init_atoms() -> Result<(), VmError> {
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

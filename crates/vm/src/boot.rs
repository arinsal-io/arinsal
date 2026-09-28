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
    run_with_debugger_flags(root, boot_args, extra_paths, workers, false, true)
}

/// Start OTP after applying the emulator's debugger startup flags.
pub fn run_with_debugger_flags(
    root: &Path,
    boot_args: &[String],
    extra_paths: &[PathBuf],
    workers: usize,
    debugger_support: bool,
    line_breakpoints: bool,
) -> Result<ScheduledResult, VmError> {
    crate::trace_bp::configure_debugger(debugger_support, line_breakpoints);
    // g_erl_flags: -pa / -pz / -path and ERL_LIBS. boot_loop2 should keep this
    // block; it only chooses the loader path before preloaded modules load.
    // Port of erts/preloaded/src/init.erl:1259 (path_flags) and
    // lib/kernel/src/code_server.erl:127 (get_user_lib_dirs), OTP-29.1.1.
    let code_path = arinsal_args::arguments_from_boot(boot_args).code_path();
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
    let mut vm = Vm::new(paths);

    // The OTP installation's ebin directory contains the 22 fixed preloaded modules.
    for entry in std::fs::read_dir(&erts_ebin).map_err(|error| {
        VmError::Load(format!(
            "cannot read preloaded modules {}: {error}",
            erts_ebin.display()
        ))
    })? {
        let path = entry
            .map_err(|error| VmError::Load(error.to_string()))?
            .path();
        if path
            .extension()
            .is_some_and(|extension| extension == "beam")
        {
            if std::env::var_os("ARINSAL_TRACE_BOOT").is_some() {
                eprintln!("arinsal boot: load {}", path.display());
            }
            vm.load_file(&path)?;
        }
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

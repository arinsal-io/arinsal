use std::ffi::OsString;
use std::process::{Command, Stdio};

/// Re-exec a comparison without Cargo's test-binary-only dynamic-loader paths.
#[allow(dead_code)]
pub(crate) fn isolate_dyld_environment(test_name: &str) -> bool {
    const CHILD_MARKER: &str = "ARINSAL_DYLD_ENV_CHILD";
    if std::env::var_os(CHILD_MARKER).is_some() {
        return true;
    }

    let dyld_vars: Vec<OsString> = std::env::vars_os()
        .filter_map(|(key, _)| key.to_string_lossy().starts_with("DYLD_").then_some(key))
        .collect();
    if dyld_vars.is_empty() {
        return true;
    }

    let mut command = Command::new("timeout");
    command
        .arg("120")
        .arg(std::env::current_exe().expect("current test executable"))
        .args([test_name, "--nocapture"])
        .env(CHILD_MARKER, "1");
    for key in dyld_vars {
        command.env_remove(key);
    }
    let output = command.output().expect("start isolated test process");
    assert!(
        output.status.success(),
        "isolated {test_name} exited {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

const RESULT_MARKER: &str = "ARINSAL_RESULT:";

/// Run `expr` as `-eval` in a one-shot VM `program` (erl or the arinsal CLI) with `dir` on the
/// code path, and decode the result. The VM boots OTP like erl does, so its atom table, and
/// with it erts' hash order for atom keys, matches erl. `None` when the program cannot run.
fn eval_once(
    program: &std::path::Path,
    flags: &[&str],
    dir: &std::path::Path,
    expr: &str,
) -> Option<arinsal_etf::OwnedTerm> {
    let script = format!(
        "io:format(\"~s~s~n\", [\"{RESULT_MARKER}\", binary:encode_hex(term_to_binary(({expr})))]), halt()."
    );
    // Keep one-shot evaluations independent of the test runner's terminal and input descriptors.
    let output = Command::new("timeout")
        .stdin(Stdio::null())
        .args(["-s", "KILL", "120"])
        .arg(program)
        .args(flags)
        .args(["-noshell", "-noinput", "-pa"])
        .arg(dir)
        .args(["-eval", &script])
        .output()
        .ok()?;
    if !output.status.success() {
        eprintln!(
            "{} exited {:?}: {}{}",
            program.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    let output = String::from_utf8(output.stdout).ok()?;
    // The logger prints its reports (deprecation warnings and the like) to the same stdout, as
    // in erl, so the result is the marked line, not the first one.
    let hex = output
        .lines()
        .find_map(|line| line.strip_prefix(RESULT_MARKER))?
        .trim();
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
        .collect::<Option<_>>()?;
    arinsal_etf::decode(&bytes).ok()
}

/// The reference result of `expr` from a fresh one-shot erl after compiling `source` as `module`.
/// `None` when `erlc` or `erl` is not available.
#[allow(dead_code)]
pub(crate) fn erl_once(module: &str, source: &str, expr: &str) -> Option<arinsal_etf::OwnedTerm> {
    let dir =
        std::env::temp_dir().join(format!("arinsal-erl-once-{}-{module}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let file = dir.join(format!("{module}.erl"));
    std::fs::write(&file, source).ok()?;
    let compiled = Command::new("erlc")
        .arg("-o")
        .arg(&dir)
        .arg(&file)
        .output()
        .ok()?;
    let result = if compiled.status.success() {
        eval_once(std::path::Path::new("erl"), &[], &dir, expr)
    } else {
        None
    };
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// The arinsal result of `expr` in a one-shot CLI with the `beam` of `module` on the code path.
/// The CLI is the `arinsal` binary next to the test executable, as `port_exec_helper` finds it.
/// Panics when that binary is missing: build it with `cargo build -p arinsal-cli`.
#[allow(dead_code)]
pub(crate) fn arinsal_once(module: &str, beam: &[u8], expr: &str) -> arinsal_etf::OwnedTerm {
    let cli =
        arinsal_cli_binary().expect("arinsal CLI not built; run `cargo build -p arinsal-cli`");
    let dir =
        std::env::temp_dir().join(format!("arinsal-cli-once-{}-{module}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create one-shot code dir");
    std::fs::write(dir.join(format!("{module}.beam")), beam).expect("write beam");
    let result = eval_once(&cli, &[], &dir, expr);
    let _ = std::fs::remove_dir_all(&dir);
    result.unwrap_or_else(|| panic!("arinsal one-shot failed for {expr}"))
}

fn arinsal_cli_binary() -> Option<std::path::PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let mut directory = executable.parent();
    while let Some(parent) = directory {
        let candidate = parent.join("arinsal");
        if candidate.is_file() {
            return Some(candidate);
        }
        directory = parent.parent();
    }
    None
}

/// Compile `source` as `module` with `erlc` and return the beam bytes. `None` when `erlc` is not
/// available.
#[allow(dead_code)]
pub(crate) fn erl_beam(module: &str, source: &str) -> Option<Vec<u8>> {
    let dir =
        std::env::temp_dir().join(format!("arinsal-erl-beam-{}-{module}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let file = dir.join(format!("{module}.erl"));
    std::fs::write(&file, source).ok()?;
    let compiled = Command::new("erlc")
        .arg("-o")
        .arg(&dir)
        .arg(&file)
        .output()
        .ok()?;
    let beam = if compiled.status.success() {
        std::fs::read(dir.join(format!("{module}.beam"))).ok()
    } else {
        None
    };
    let _ = std::fs::remove_dir_all(&dir);
    beam
}

/// The test binary's one node. erts runs one node per OS process (erl_init.c, erl_start) and an
/// OTP suite runs all its cases in it; a case loads its module here and evaluates in it. A case
/// that needs different emulator flags starts a separate OS process, never a second `Vm`.
#[allow(dead_code)]
pub(crate) fn node() -> std::sync::MutexGuard<'static, arinsal_vm::Vm> {
    static NODE: std::sync::OnceLock<std::sync::Mutex<arinsal_vm::Vm>> = std::sync::OnceLock::new();
    NODE.get_or_init(|| {
        let mut vm = arinsal_vm::Vm::new([]);
        // `erl` starts its default number of normal schedulers at node boot. Start the shared
        // node's scheduler with that same total so later cases can pin processes to any scheduler.
        let schedulers = arinsal_alloc::cpuinfo::default_schedulers().0;
        let selector = arinsal_term::Term::atom(
            arinsal_term::global_atoms()
                .intern("schedulers")
                .expect("intern scheduler selector"),
        );
        vm.eval_scheduled("erlang", "system_info", &[selector], schedulers.max(1))
            .expect("start shared node with default schedulers");
        std::sync::Mutex::new(vm)
    })
    .lock()
    // A failed case must not fail the cases after it.
    .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Load `beam` as the current code of its module the way a CT suite reloads a same-name module:
/// `erts_code_purger:purge/1` and `erlang:delete_module/1` (what code_server runs for
/// `code:purge/1` and `code:delete/1`), then `load_bytes`.
#[allow(dead_code)]
pub(crate) fn load_fresh(vm: &mut arinsal_vm::Vm, beam: &[u8]) {
    use arinsal_term::{Term, global_atoms};
    let module = arinsal_beam::parse(beam).expect("parse beam").module;
    let atom = Term::atom(global_atoms().intern(&module).unwrap());
    // Both report false when the module has no such code, the state of a first load.
    for (m, function) in [
        ("erts_code_purger", "purge"),
        ("erlang", "delete_module"),
        ("erts_code_purger", "purge"),
    ] {
        vm.eval_scheduled(m, function, &[atom], 1)
            .unwrap_or_else(|error| panic!("{m}:{function}({module}): {error:?}"));
    }
    vm.load_bytes(beam).expect("load module");
}

/// Run `expr` in a separate `arinsal` OS process, as an erts test runs a peer node: `flags` are
/// emulator flags (`+D`), `beams` are put on the code path. For cases that need a fresh node or
/// different emulator flags; the test binary's own node stays untouched. Panics when the
/// `arinsal` binary is missing (`cargo build -p arinsal-cli`).
#[allow(dead_code)]
pub(crate) fn peer_eval(flags: &[&str], beams: &[&[u8]], expr: &str) -> arinsal_etf::OwnedTerm {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let cli =
        arinsal_cli_binary().expect("arinsal CLI not built; run `cargo build -p arinsal-cli`");
    let dir = std::env::temp_dir().join(format!(
        "arinsal-peer-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create peer code dir");
    for beam in beams {
        let module = arinsal_beam::parse(beam).expect("parse beam").module;
        std::fs::write(dir.join(format!("{module}.beam")), beam).expect("write beam");
    }
    let result = eval_once(&cli, flags, &dir, expr);
    let _ = std::fs::remove_dir_all(&dir);
    result.unwrap_or_else(|| panic!("arinsal peer failed for {expr}"))
}

/// The test binary's node with every `.beam` in `dir` loaded as current code, standing in for
/// `-pa dir` on a node that loads modules lazily from its code path.
#[allow(dead_code)]
pub(crate) fn node_with_dir(
    dir: &std::path::Path,
) -> std::sync::MutexGuard<'static, arinsal_vm::Vm> {
    let mut vm = node();
    for entry in std::fs::read_dir(dir).expect("read code dir") {
        let path = entry.expect("code dir entry").path();
        if path.extension().is_some_and(|ext| ext == "beam") {
            load_fresh(&mut vm, &std::fs::read(&path).expect("read beam"));
        }
    }
    vm
}

/// [`peer_eval`] over a code directory that already holds the beams (`-pa dir`).
#[allow(dead_code)]
pub(crate) fn peer_eval_dir(
    flags: &[&str],
    dir: &std::path::Path,
    expr: &str,
) -> arinsal_etf::OwnedTerm {
    let cli =
        arinsal_cli_binary().expect("arinsal CLI not built; run `cargo build -p arinsal-cli`");
    eval_once(&cli, flags, dir, expr).unwrap_or_else(|| panic!("arinsal peer failed for {expr}"))
}

use std::ffi::OsString;
use std::process::Command;

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
        .args(["--exact", test_name, "--nocapture"])
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

/// Run `expr` as `-eval` in a one-shot VM `program` (erl or the arinsal CLI) with `dir` on the
/// code path, and decode the result. The VM boots OTP like erl does, so its atom table, and
/// with it erts' hash order for atom keys, matches erl. `None` when the program cannot run.
fn eval_once(
    program: &std::path::Path,
    dir: &std::path::Path,
    expr: &str,
) -> Option<arinsal_etf::OwnedTerm> {
    let script =
        format!("io:format(\"~s~n\", [binary:encode_hex(term_to_binary(({expr})))]), halt().");
    let output = Command::new("timeout")
        .args(["-s", "KILL", "120"])
        .arg(program)
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &script])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let hex = String::from_utf8(output.stdout).ok()?;
    let hex = hex.trim();
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
        eval_once(std::path::Path::new("erl"), &dir, expr)
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
    let result = eval_once(&cli, &dir, expr);
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

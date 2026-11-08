//! Differential tests: modules compiled natively with BeamAsm print what `erl` prints.

use similar_asserts::assert_eq;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const MODULES: &[&str] = &[
    "beamasm_ops",
    "beamasm_bits_a",
    "beamasm_bits_b",
    "beamasm_hibernate",
    "beamasm_epp",
    "beamasm_sched",
    "beamasm_eq_exact",
    "beamasm_map_elements",
    "beamasm_map_callee",
    "beamasm_caught_bif_error",
    "beamasm_exceptions",
];

fn compile_fixtures() -> Option<PathBuf> {
    if !cfg!(target_arch = "aarch64") {
        eprintln!("skipped: BeamAsm generates AArch64 code");
        return None;
    }
    if Command::new("erlc").arg("-v").output().is_err() {
        eprintln!("skipped: erlc is not available");
        return None;
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "arinsal-beamasm-differential-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for module in MODULES {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{module}.erl"));
        let status = Command::new("erlc")
            .arg("-o")
            .arg(&dir)
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success(), "erlc failed for {module}");
    }
    Some(dir)
}

fn reference(dir: &Path, module: &str) -> Output {
    Command::new("timeout")
        .args(["120", "erl", "-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &format!("{module}:run(), halt().")])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("erl must be available")
}

fn native(dir: &Path, module: &str) -> Output {
    Command::new("timeout")
        .args(["120", env!("CARGO_BIN_EXE_arinsal"), "-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &format!("{module}:run(), halt().")])
        .env("ARINSAL_BEAMASM", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
}

fn interpreted(dir: &Path, module: &str) -> Output {
    Command::new("timeout")
        .args(["120", env!("CARGO_BIN_EXE_arinsal"), "-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &format!("{module}:run(), halt().")])
        .env("ARINSAL_BEAMASM", "1")
        .env("ARINSAL_INTERP", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
}

fn compile_far_branch_fixture() -> Option<PathBuf> {
    if !cfg!(target_arch = "aarch64") || Command::new("erlc").arg("-v").output().is_err() {
        eprintln!("skipped: far-branch differential requires AArch64 and erlc");
        return None;
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "arinsal-beamasm-far-branch-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let effects = (0..5_000)
        .map(|value| format!("erlang:put({value},{value})"))
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        "-module(beamasm_far_branch).\n-export([run/1]).\nrun(X) when is_tuple(X) -> begin {effects}, ok end;\nrun(_) -> no.\n"
    );
    let source_path = dir.join("beamasm_far_branch.erl");
    std::fs::write(&source_path, source).unwrap();
    let status = Command::new("timeout")
        .args(["120", "erlc", "-o"])
        .arg(&dir)
        .arg(&source_path)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "erlc failed for the generated far-branch module"
    );
    Some(dir)
}

fn run_eval(dir: &Path, executable: &str, expression: &str, beamasm: bool) -> Output {
    let mut command = Command::new("timeout");
    command
        .args(["120", executable, "-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", expression])
        .stdin(std::process::Stdio::null());
    if beamasm {
        command.env("ARINSAL_BEAMASM", "1");
    }
    command.output().unwrap()
}

#[test]
fn native_modules_print_what_erl_prints() {
    let Some(dir) = compile_fixtures() else {
        return;
    };
    for module in MODULES {
        let expected = reference(&dir, module);
        assert!(expected.status.success(), "{module}: erl failed");
        let actual = native(&dir, module);
        assert!(
            actual.status.success(),
            "{module}: BeamAsm failed: {actual:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&actual.stdout),
            String::from_utf8_lossy(&expected.stdout),
            "{module}: BeamAsm output differs from erl"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn caught_bif_error_stacktrace_matches_jit_interpreter_and_otp() {
    let Some(dir) = compile_fixtures() else {
        return;
    };
    let expected = reference(&dir, "beamasm_caught_bif_error");
    assert!(expected.status.success(), "erl failed: {expected:?}");
    let interpreted = interpreted(&dir, "beamasm_caught_bif_error");
    assert!(
        interpreted.status.success(),
        "interpreter failed: {interpreted:?}"
    );
    let actual = native(&dir, "beamasm_caught_bif_error");
    assert!(actual.status.success(), "BeamAsm failed: {actual:?}");
    assert_eq!(
        String::from_utf8_lossy(&interpreted.stdout),
        String::from_utf8_lossy(&expected.stdout),
        "interpreter output differs from erl"
    );
    assert_eq!(
        String::from_utf8_lossy(&actual.stdout),
        String::from_utf8_lossy(&expected.stdout),
        "BeamAsm output differs from erl"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn generated_far_beam_fail_branch_matches_erl() {
    let Some(dir) = compile_far_branch_fixture() else {
        return;
    };
    let expression = "io:format(\"~p~n\",[beamasm_far_branch:run({})]),halt().";
    let expected = run_eval(&dir, "erl", expression, false);
    assert!(expected.status.success(), "erl failed: {expected:?}");
    let actual = run_eval(&dir, env!("CARGO_BIN_EXE_arinsal"), expression, true);
    assert!(actual.status.success(), "BeamAsm failed: {actual:?}");
    assert_eq!(
        String::from_utf8_lossy(&actual.stdout),
        String::from_utf8_lossy(&expected.stdout),
        "BeamAsm output differs from erl"
    );
    let _ = std::fs::remove_dir_all(dir);
}

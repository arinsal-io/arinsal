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
];

/// OTP modules compiled natively alongside a fixture, for fixtures that exercise them.
fn native_modules(module: &str) -> String {
    match module {
        // epp's state record is updated with update_record_in_place.
        "beamasm_epp" => format!("{module},epp"),
        // The group leader handles the io request while multi-scheduling is blocked.
        "beamasm_sched" => format!("{module},group"),
        "beamasm_map_elements" => format!("{module},beamasm_map_callee"),
        _ => module.to_owned(),
    }
}

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
    Command::new("erl")
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &format!("{module}:run(), halt().")])
        .output()
        .expect("erl must be available")
}

fn native(dir: &Path, module: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_arinsal"))
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &format!("{module}:run(), halt().")])
        .env("ARINSAL_BEAMASM", "1")
        .env("ARINSAL_BEAMASM_MODULES", native_modules(module))
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
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
        assert_eq!(
            String::from_utf8_lossy(&actual.stdout),
            String::from_utf8_lossy(&expected.stdout),
            "{module}: BeamAsm output differs from erl"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

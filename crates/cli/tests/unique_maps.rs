//! Differential test of the `ARINSAL_UNIQUE_MAPS` experiment: loops that update a map in place
//! must print what `erl` prints in situations where the old map is still referenced.

use similar_asserts::assert_eq;
use std::path::PathBuf;
use std::process::{Command, Output};

fn compile() -> Option<PathBuf> {
    if !cfg!(target_arch = "aarch64") {
        eprintln!("skipped: BeamAsm generates AArch64 code");
        return None;
    }
    if Command::new("erlc").arg("-v").output().is_err() {
        eprintln!("skipped: erlc is not available");
        return None;
    }
    let dir = std::env::temp_dir().join(format!("arinsal-unique-maps-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unique_maps.erl");
    let status = Command::new("erlc")
        .arg("-o")
        .arg(&dir)
        .arg(source)
        .status()
        .unwrap();
    assert!(status.success(), "erlc failed");
    Some(dir)
}

fn run(program: &str, dir: &PathBuf, unique: Option<&str>) -> Output {
    let mut command = Command::new("timeout");
    command
        .args(["120", program, "-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", "unique_maps:run(), halt()."])
        .stdin(std::process::Stdio::null());
    if program != "erl" {
        command.env("ARINSAL_BEAMASM", "1");
        if let Some(value) = unique {
            command.env("ARINSAL_UNIQUE_MAPS", value);
            command.env("ARINSAL_UNIQUE_MAPS_TRACE", "1");
        }
    }
    command.output().unwrap()
}

#[test]
fn in_place_map_updates_match_erl() {
    let Some(dir) = compile() else {
        return;
    };
    let expected = run("erl", &dir, None);
    assert!(expected.status.success(), "erl failed: {expected:?}");
    let off = run(env!("CARGO_BIN_EXE_arinsal"), &dir, None);
    assert_eq!(
        String::from_utf8_lossy(&off.stdout),
        String::from_utf8_lossy(&expected.stdout),
        "switch off differs from erl"
    );
    let on = run(env!("CARGO_BIN_EXE_arinsal"), &dir, Some("1"));
    assert!(on.status.success(), "switch on failed: {on:?}");
    assert_eq!(
        String::from_utf8_lossy(&on.stdout),
        String::from_utf8_lossy(&expected.stdout),
        "switch on differs from erl"
    );
    // The fixture must actually exercise the in-place path.
    let stderr = String::from_utf8_lossy(&on.stderr);
    let marked = stderr
        .lines()
        .filter(|line| line.starts_with("unique_maps: unique_maps marks"))
        .count();
    assert!(marked >= 4, "too few marked functions ({marked}): {stderr}");
    let _ = std::fs::remove_dir_all(dir);
}

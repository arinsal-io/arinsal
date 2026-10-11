//! Compare boot-visible defaults with the installed OTP 29.1.1 emulator.

use similar_asserts::assert_eq;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const PROBE: &str = include_str!("fixtures/defaults_probe.erl");
static NEXT_PROBE: AtomicUsize = AtomicUsize::new(0);

fn probe_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "arinsal-defaults-{}-{}",
        std::process::id(),
        NEXT_PROBE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create probe directory");
    std::fs::write(dir.join("defaults_probe.erl"), PROBE).expect("write probe");
    let output = Command::new("erlc")
        .args([
            "-o",
            dir.to_str().unwrap(),
            dir.join("defaults_probe.erl").to_str().unwrap(),
        ])
        .output()
        .expect("compile probe with OTP 29 erlc");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    dir
}

fn run(
    runtime: &str,
    dir: &std::path::Path,
    function: &str,
    flags: [&str; 3],
) -> BTreeMap<String, String> {
    let binary = if runtime == "erl" {
        "erl"
    } else {
        env!("CARGO_BIN_EXE_arinsal")
    };
    let mut command = if runtime == "erl" {
        Command::new(binary)
    } else {
        let mut command = Command::new("timeout");
        command.arg("30").arg(binary);
        command
    };
    let output = command
        .args([
            "-noshell",
            "-pa",
            dir.to_str().unwrap(),
            "-eval",
            &format!("defaults_probe:{function}()."),
        ])
        .env("ERL_AFLAGS", flags[0])
        .env("ERL_FLAGS", flags[1])
        .env("ERL_ZFLAGS", flags[2])
        .env("ERL_OTP29_FLAGS", "")
        .env("ERL_CRASH_DUMP", "/dev/null")
        .output()
        .expect("run probe");
    assert!(
        output.status.success(),
        "{runtime} exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("UTF-8 probe output")
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('=').expect("key=value probe line");
            (key.to_owned(), value.to_owned())
        })
        .collect()
}

#[test]
fn default_boot_values_match_otp() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("erl unavailable; skipping defaults differential");
        return;
    }
    let dir = probe_dir();
    for flags in [
        ["", "", ""],
        [
            "-kernel shell_history disabled",
            "-kernel logger_level warning",
            "-kernel net_ticktime 70",
        ],
    ] {
        let expected = run("erl", &dir, "run", flags);
        let actual = run("arinsal", &dir, "run", flags);
        for (key, value) in expected {
            // D2 covers exact process memory sizes; D6 covers emulator identity.
            if matches!(
                key.as_str(),
                "process_stack_bytes" | "emu_flavor" | "emu_type"
            ) {
                continue;
            }
            assert_eq!(actual.get(&key), Some(&value), "{key} with {flags:?}");
        }
    }
}

#[test]
fn system_flag_round_trips_match_otp() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("erl unavailable; skipping system_flag differential");
        return;
    }
    let dir = probe_dir();
    let expected = run("erl", &dir, "round_trips", ["", "", ""]);
    let actual = run("arinsal", &dir, "round_trips", ["", "", ""]);
    for (key, value) in expected {
        assert_eq!(actual.get(&key), Some(&value), "{key}");
    }
}

#[test]
fn resource_flags_match_otp() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("erl unavailable; skipping resource flag differential");
        return;
    }
    let dir = probe_dir();
    let flags = ["+S 2:2 +SDcpu 1:1", "+A 4 +P 2000000", "+Q 200000 +hms 377"];
    let expected = run("erl", &dir, "run", flags);
    let actual = run("arinsal", &dir, "run", flags);
    for (key, value) in expected {
        if matches!(
            key.as_str(),
            "process_stack_bytes" | "emu_flavor" | "emu_type"
        ) {
            continue;
        }
        assert_eq!(actual.get(&key), Some(&value), "{key} with {flags:?}");
    }
}

#[test]
fn invalid_resource_flag_diagnostics_match_otp() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("erl unavailable; skipping invalid resource flag differential");
        return;
    }
    for (flag, value) in [
        ("+hmbs", "invalid"),
        ("+hmqd", "invalid"),
        ("+hmax", "-1"),
        ("+hmaxk", "invalid"),
        ("+hmaxel", "invalid"),
        ("+hmaxib", "invalid"),
        ("+zdbbl", "0"),
        ("+zdbbl", "2097152"),
    ] {
        let expected = Command::new("erl")
            .args([flag, value, "-noshell", "-eval", "halt()."])
            .output()
            .unwrap();
        let actual = Command::new("timeout")
            .args([
                "30",
                env!("CARGO_BIN_EXE_arinsal"),
                flag,
                value,
                "-noshell",
                "-eval",
                "halt().",
            ])
            .output()
            .unwrap();
        assert_eq!(
            actual.status.code(),
            expected.status.code(),
            "{flag} {value}"
        );
        let first_line = |output: &std::process::Output| {
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned()
        };
        assert_eq!(first_line(&actual), first_line(&expected), "{flag} {value}");
    }
}

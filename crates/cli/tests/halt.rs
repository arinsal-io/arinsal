use std::fs;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "arinsal-halt-{}-{stamp}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("halt_fixture.erl");
    fs::write(
        &source,
        "-module(halt_fixture).\n-export([zero/0,three/0,string/0,option/0,timeout/0,no_flush/0,abort/0]).\nzero() -> erlang:halt().\nthree() -> erlang:halt(3).\nstring() -> erlang:halt(\"boom\").\noption() -> erlang:halt(5,[{flush_timeout,0}]).\ntimeout() -> erlang:halt(7,[{flush_timeout,1000}]).\nno_flush() -> erlang:halt(6,[{flush,false}]).\nabort() -> erlang:halt(abort).\n",
    )
    .unwrap();
    let status = Command::new("erlc")
        .args(["-o", dir.to_str().unwrap(), source.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    (dir, source)
}

fn arinsal(dir: &std::path::Path, function: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_arinsal"))
        .args([
            "eval",
            "-pa",
            dir.to_str().unwrap(),
            "halt_fixture",
            function,
        ])
        .output()
        .unwrap()
}

fn reference_eval(dir: &std::path::Path, function: &str) -> Output {
    Command::new("erl")
        .args([
            "-noshell",
            "-pa",
            dir.to_str().unwrap(),
            "-eval",
            &format!("halt_fixture:{function}()."),
        ])
        .output()
        .unwrap()
}

#[test]
fn halt_status_and_string_output_match_otp() {
    for function in ["zero", "three", "string", "option", "timeout", "no_flush"] {
        let (dir, _) = fixture();
        let expected = reference_eval(&dir, function);
        let actual = arinsal(&dir, function);
        assert_eq!(actual.status.code(), expected.status.code(), "{function}");
        assert_eq!(actual.stdout, expected.stdout, "{function} stdout");
        assert_eq!(actual.stderr, expected.stderr, "{function} stderr");
        let _ = fs::remove_dir_all(dir);
    }
}

#[cfg(unix)]
#[test]
fn halt_abort_signal_matches_otp() {
    use std::os::unix::process::ExitStatusExt;

    let (dir, _) = fixture();
    let expected = reference_eval(&dir, "abort");
    let actual = arinsal(&dir, "abort");
    assert_eq!(actual.status.signal(), expected.status.signal());
    assert_eq!(actual.stdout, expected.stdout);
    assert_eq!(actual.stderr, expected.stderr);
    let _ = fs::remove_dir_all(dir);
}

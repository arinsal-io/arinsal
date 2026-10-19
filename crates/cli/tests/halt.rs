use similar_asserts::assert_eq;
use std::fs;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const ERL: &str = "erl";
const ERLC: &str = "erlc";
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

const SOURCE: &str = r#"
-module(halt_fixture).
-export([status0/0, status1/0, status255/0, flush_output/0, no_flush/0,
         busy_timeout/0, string/0, non_main/0, abort/0]).
status0() -> erlang:halt(0).
status1() -> erlang:halt(1).
status255() -> erlang:halt(255).
flush_output() -> io:format("before"), erlang:halt(0).
no_flush() -> io:format("before"), erlang:halt(0, [{flush, false}]).
busy_timeout() ->
    Port = open_port({spawn, "cat"}, [binary]),
    true = port_command(Port, binary:copy(<<$x>>, 16 * 1024 * 1024)),
    erlang:halt(0, [{flush_timeout, 0}]).
string() -> io:format("before"), erlang:halt("msg", [{flush, false}]).
non_main() -> spawn(fun() -> erlang:halt(7) end), receive after 10000 -> ok end.
abort() -> erlang:halt(abort).
"#;

fn fixture() -> std::path::PathBuf {
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
    fs::write(&source, SOURCE).unwrap();
    let status = Command::new("timeout")
        .args(["30", ERLC, "-o"])
        .arg(&dir)
        .arg(&source)
        .status()
        .expect("run OTP 29 erlc under timeout");
    assert!(status.success());
    dir
}

fn arinsal(dir: &std::path::Path, function: &str) -> Output {
    Command::new("timeout")
        .args([
            "30",
            env!("CARGO_BIN_EXE_arinsal"),
            "eval",
            "--schedulers",
            "3",
            "-pa",
        ])
        .arg(dir)
        .args(["halt_fixture", function])
        .current_dir(dir)
        .output()
        .expect("run arinsal under timeout")
}

fn arinsal_boot(
    dir: &std::path::Path,
    function: &str,
    dump_path: Option<&std::path::Path>,
) -> Output {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut command = Command::new("timeout");
    command
        .args(["30", env!("CARGO_BIN_EXE_arinsal"), "-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &format!("halt_fixture:{function}().")])
        .current_dir(root);
    if let Some(path) = dump_path {
        command.env("ERL_CRASH_DUMP", path);
    }
    command.output().expect("run booted arinsal under timeout")
}

fn reference_eval(dir: &std::path::Path, function: &str) -> Output {
    Command::new("timeout")
        .args(["30", ERL, "-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &format!("halt_fixture:{function}().")])
        .current_dir(dir)
        .output()
        .expect("run OTP 29 erl under timeout")
}

fn reference_eval_with_dump(
    dir: &std::path::Path,
    function: &str,
    dump_path: &std::path::Path,
) -> Output {
    Command::new("timeout")
        .args(["30", ERL, "-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &format!("halt_fixture:{function}().")])
        .env("ERL_CRASH_DUMP", dump_path)
        .current_dir(dir)
        .output()
        .expect("run OTP 29 erl under timeout")
}

fn assert_output_matches(expected: &Output, actual: &Output, context: &str) {
    assert_eq!(
        actual.status.code(),
        expected.status.code(),
        "{context} status"
    );
    assert_eq!(actual.stdout, expected.stdout, "{context} stdout");
    assert_eq!(actual.stderr, expected.stderr, "{context} stderr");
}

#[test]
fn halt_exit_status_output_and_port_timeout_match_otp_29() {
    for function in [
        "status0",
        "status1",
        "status255",
        "busy_timeout",
        "non_main",
    ] {
        let dir = fixture();
        let expected = reference_eval(&dir, function);
        let actual = arinsal(&dir, function);
        assert_output_matches(&expected, &actual, function);
        let _ = fs::remove_dir_all(dir);
    }

    for function in ["flush_output", "no_flush"] {
        let dir = fixture();
        let expected = reference_eval(&dir, function);
        let actual = arinsal_boot(&dir, function, None);
        assert_output_matches(&expected, &actual, function);
        let _ = fs::remove_dir_all(dir);
    }
}

#[test]
fn halt_string_writes_slogan_and_crash_dump_like_otp_29() {
    let dir = fixture();
    let dump_path = dir.join("erl_crash.dump");
    let expected = reference_eval_with_dump(&dir, "string", &dump_path);
    let expected_dump = fs::read(&dump_path).unwrap();
    fs::remove_file(&dump_path).unwrap();
    let actual = arinsal_boot(&dir, "string", Some(&dump_path));
    assert_output_matches(&expected, &actual, "string");
    let actual_dump = fs::read(&dump_path).unwrap();
    assert!(expected_dump.starts_with(b"=erl_crash_dump:0.5\n"));
    assert!(actual_dump.starts_with(b"=erl_crash_dump:0.5\n"));
    assert!(
        expected_dump
            .windows(b"Slogan: msg\n".len())
            .any(|line| line == b"Slogan: msg\n")
    );
    assert!(
        actual_dump
            .windows(b"Slogan: msg\n".len())
            .any(|line| line == b"Slogan: msg\n")
    );
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn halt_abort_signal_and_output_match_otp_29() {
    use std::os::unix::process::ExitStatusExt;

    let dir = fixture();
    let expected = reference_eval(&dir, "abort");
    let actual = arinsal(&dir, "abort");
    assert_eq!(actual.status.signal(), expected.status.signal());
    assert_eq!(actual.stdout, expected.stdout);
    assert_eq!(actual.stderr, expected.stderr);
    let _ = fs::remove_dir_all(dir);
}

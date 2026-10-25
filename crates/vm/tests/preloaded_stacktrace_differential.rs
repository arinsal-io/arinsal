//! Stacktraces through the frames of preloaded modules against OTP 29.1.1. erts loads the
//! preloaded modules from beams stripped to their code chunks (`make_preload`), so their frames
//! have no file or line: `{init,start_it,1,[]}`. The runtimes are started as programs so the
//! stack holds the real `init` and `erl_eval` frames.

use arinsal_difftest::RefErl;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MODULE: &str = "preloaded_trace";

const SOURCE: &str = r#"
-module(preloaded_trace).
-export([bif/0, error_call/0, undef/0, prim_loader/0, deep/0]).

bif() -> try element(5, {a}) catch error:badarg:St -> St end.
error_call() -> try erlang:error(oops, [1, 2]) catch error:oops:St -> St end.
undef() -> try preloaded_trace:missing(1) catch error:undef:St -> St end.
prim_loader() -> try erl_prim_loader:get_file(1) catch C:R:St -> {C, R, St} end.
deep() -> try lists:foldl(fun(X, _) -> element(X, {a}) end, ok, [1, 2]) catch error:badarg:St -> St end.
"#;

fn run(program: &Path, dir: &Path, module: &str, function: &str) -> (bool, String) {
    let eval = format!("io:format(\"~p~n\", [{module}:{function}()]), halt().");
    let root = arinsal_difftest::reference::otp_root();
    let mut command = if program == Path::new("erl") {
        match &root {
            Some(root) => Command::new(root.join("bin/erl")),
            None => Command::new("erl"),
        }
    } else {
        let mut command = Command::new(program);
        if let Some(root) = &root {
            command.env("ERL_ROOTDIR", root);
        }
        command
    };
    command
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &eval])
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", program.display()));
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().expect("output");
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                return (
                    output.status.success(),
                    if output.status.success() || stderr.is_empty() {
                        stdout
                    } else {
                        format!("{stdout}\n{stderr}").trim().to_string()
                    },
                );
            }
            Ok(None) if started.elapsed() > Duration::from_secs(60) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{} timed out in {function}", program.display());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("wait {}: {error}", program.display()),
        }
    }
}

fn compare(function: &str) {
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping preloaded stacktrace differential test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .unwrap_or_else(|error| panic!("compile {MODULE}: {error:?}"));
    let dir = std::env::temp_dir().join(format!("{MODULE}_{}_{function}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{MODULE}.beam")), beam).unwrap();
    let (erl_ok, expected) = run(Path::new("erl"), &dir, MODULE, function);
    let (ok, actual) = run(&arinsal, &dir, MODULE, function);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(erl_ok, "erl failed in {function}: {expected}");
    assert!(ok, "arinsal failed in {function}: {actual}");
    similar_asserts::assert_eq!(expected, actual, "{function}");
}

#[test]
fn bif_failure_trace_through_init_matches_erts() {
    compare("bif");
}

#[test]
fn error_with_args_trace_through_init_matches_erts() {
    compare("error_call");
}

#[test]
fn undef_trace_through_init_matches_erts() {
    compare("undef");
}

#[test]
fn preloaded_module_frame_matches_erts() {
    compare("prim_loader");
}

#[test]
fn trace_through_a_fun_in_lists_matches_erts() {
    compare("deep");
}

//! `process_info(P, backtrace)` must list one return address per frame like erts: a call the
//! scheduler performs for native code (spawn, apply, funs) leaves only the caller's real
//! continuation, and a process's first frame returns to `<terminate process normally>`.
//! The backtrace of a waiting or runnable process has no `arity = N` line and no register
//! lines: the target prints it while it handles the signal, so it is a running process.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use arinsal_difftest::RefErl;

const MODULE: &str = r#"
-module(bt_return_addrs).
-export([run/0, a/1, b/1, c/2, d/1]).

run() ->
    Self = self(),
    Procs = [spawn(bt_return_addrs, a, [1]),
             spawn(fun() -> b(2) end),
             spawn(erlang, apply, [fun bt_return_addrs:a/1, [3]]),
             spawn(fun() -> apply(bt_return_addrs, c, [4, Self]) end),
             spawn(bt_return_addrs, d, [5]),
             spawn(fun() -> wait() end)],
    receive ready -> ok end,
    timer:sleep(100),
    io:format("~p~n", [[frames(P) || P <- Procs]]).

frames(P) ->
    {backtrace, B} = process_info(P, backtrace),
    exit(P, kill),
    [function(Line) || Line <- string:split(binary_to_list(B), "\n", all),
                       string:find(Line, "Return addr") =/= nomatch].

%% The code offsets differ between erts and Arinsal; the function names must not.
function(Line) ->
    [_, Description] = string:split(Line, " ("),
    hd(string:split(Description, " + ")).

a(N) -> [b(N) | wait()].
b(N) -> {N, wait()}.
c(N, Parent) -> Parent ! ready, {a(N)}.
d(N) -> F = fun bt_return_addrs:a/1, [F(N)].
wait() -> receive stop -> ok end.
"#;

fn run(program: &std::path::Path, dir: &std::path::Path) -> String {
    run_eval(program, dir, "bt_return_addrs:run(), halt().")
}

fn run_eval(program: &std::path::Path, dir: &std::path::Path, eval: &str) -> String {
    let mut child = Command::new(program)
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", eval])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", program.display()));
    let started = Instant::now();
    while child.try_wait().expect("wait").is_none() {
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{} did not finish", program.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().expect("output");
    assert!(
        output.status.success(),
        "{} failed ({:?}): {}",
        program.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn backtrace_return_addresses_match_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping backtrace return address test");
        return;
    };
    let module = reference
        .compile_named("bt_return_addrs", MODULE, &[])
        .expect("compile bt_return_addrs");
    drop(reference);
    let dir = std::env::temp_dir().join(format!("arinsal-bt-return-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join("bt_return_addrs.beam"), &module).expect("write beam");
    let expected = run(std::path::Path::new("erl"), &dir);
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release/arinsal");
    assert!(bin.is_file(), "build target/release/arinsal first");
    let actual = run(&bin, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        expected.contains("<terminate process normally>"),
        "unexpected erl output: {expected}"
    );
    assert_eq!(actual, expected);
}

const ARITY_MODULE: &str = r#"
-module(bt_arity_lines).
-export([run/0, spin/0, wait/3]).

run() ->
    Waiting = spawn(bt_arity_lines, wait, [a, {b, c}, [d]]),
    Runnable = spawn(bt_arity_lines, spin, []),
    timer:sleep(100),
    Result = [{waiting, shape(Waiting)}, {runnable, shape(Runnable)}],
    exit(Waiting, kill),
    exit(Runnable, kill),
    io:format("~p~n", [Result]).

shape(P) ->
    {backtrace, B} = process_info(P, backtrace),
    Lines = string:split(binary_to_list(B), "\n", all),
    {length([L || "arity = " ++ _ = L <- Lines]),
     length([L || "   " ++ _ = L <- Lines]),
     [L || "Program counter" ++ _ = L <- Lines] =/= []}.

spin() -> spin().
wait(_A, _B, _C) -> receive stop -> ok end.
"#;

#[test]
fn backtrace_of_a_waiting_or_runnable_process_has_no_arity_lines() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping backtrace arity line test");
        return;
    };
    let module = reference
        .compile_named("bt_arity_lines", ARITY_MODULE, &[])
        .expect("compile bt_arity_lines");
    drop(reference);
    let dir = std::env::temp_dir().join(format!("arinsal-bt-arity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join("bt_arity_lines.beam"), &module).expect("write beam");
    let eval = "bt_arity_lines:run(), halt().";
    let expected = run_eval(std::path::Path::new("erl"), &dir, eval);
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release/arinsal");
    assert!(bin.is_file(), "build target/release/arinsal first");
    let actual = run_eval(&bin, &dir, eval);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        expected, "[{waiting,{0,0,true}},{runnable,{0,0,true}}]",
        "unexpected erl output"
    );
    assert_eq!(actual, expected);
}

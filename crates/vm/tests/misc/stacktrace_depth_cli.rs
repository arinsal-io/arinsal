//! Raw stacktraces at every `backtrace_depth` must hold the same frames as erts when
//! code runs under `erl_eval`, `apply/3`, funs, tail calls and spawned processes.
//! Each frame holds exactly one CP, so every continuation counts once against `max_depth`
//! (beam_common.c:883, OTP-29.1.1).

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use arinsal_difftest::RefErl;

const MODULE: &str = r#"
-module(bt_depth_cli).
-export([run/0, a/1]).
-compile(nowarn_deprecated_catch).

run() ->
    Old = erlang:system_flag(backtrace_depth, 8),
    Rows = [row(D) || D <- [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 20]],
    erlang:system_flag(backtrace_depth, Old),
    io:format("~w~n", [Rows]).

row(D) ->
    erlang:system_flag(backtrace_depth, D),
    Self = self(),
    spawn(fun() -> Self ! {spawned, catch a(1)} end),
    Spawned = receive {spawned, R} -> R end,
    Eval = fun(Text) ->
                   {ok, Tokens, _} = erl_scan:string(Text),
                   {ok, Exprs} = erl_parse:parse_exprs(Tokens),
                   catch erl_eval:exprs(Exprs, [])
           end,
    Fun = fun() -> error(reason) end,
    Cases = [Spawned,
             catch apply(bt_depth_cli, a, [1]),
             catch tail(3),
             Eval("bt_depth_cli:a(2)."),
             Eval("error(z)."),
             Eval("F = fun() -> error(e) end, F()."),
             catch Fun(),
             catch lists:map(fun(X) -> a(X) end, [1]),
             catch erlang:atom_to_list(id(1)),
             catch apply(fun bt_depth_cli:a/1, [1]),
             try Fun() catch error:reason:S -> {'EXIT', {reason, S}} end],
    {D, [strip(C) || C <- Cases]}.

strip({'EXIT', {_, Stack}}) ->
    [{M, F, if is_list(A) -> length(A); true -> A end, line(M, Loc)}
     || {M, F, A, Loc} <- Stack].

%% Preloaded `init` has no line table in erl; only this module's lines are compared.
line(bt_depth_cli, Loc) -> proplists:get_value(line, Loc);
line(_, _) -> none.

id(X) -> X.

tail(0) -> a(0);
tail(N) -> tail(N - 1).

a(X) -> b(X), ok.

b(X) -> error({b, X}).
"#;

const EVAL: &str = "bt_depth_cli:run(), halt().";

fn run(program: &std::path::Path, dir: &std::path::Path) -> String {
    let mut child = Command::new(program)
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", EVAL])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", program.display()));
    let started = Instant::now();
    while child.try_wait().expect("wait").is_none() {
        if started.elapsed() > Duration::from_secs(120) {
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
fn limited_stacktraces_through_eval_apply_and_tail_calls_match_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping backtrace depth CLI test");
        return;
    };
    let module = reference
        .compile_named("bt_depth_cli", MODULE, &[])
        .expect("compile bt_depth_cli");
    drop(reference);
    let dir = std::env::temp_dir().join(format!("arinsal-bt-depth-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join("bt_depth_cli.beam"), &module).expect("write beam");
    let expected = run(std::path::Path::new("erl"), &dir);
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release/arinsal");
    assert!(bin.is_file(), "build target/release/arinsal first");
    let actual = run(&bin, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        expected.starts_with("[{0,"),
        "unexpected erl output: {expected}"
    );
    assert_eq!(actual, expected);
}

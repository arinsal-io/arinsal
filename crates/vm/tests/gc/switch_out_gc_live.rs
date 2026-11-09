//! A collection run when a process switches out must root only its exact live X
//! registers, like erts' `scheduler_gc_proc` with `c_p->arity`. Dead registers above
//! that count keep pointers into heaps that earlier collections freed; rooting them
//! made the copier read stale words ("invalid boxed subtag" panics).

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use arinsal_difftest::{CallResult, RefErl};

const STALE: &str = r#"
-module(sol_stale_x).
-export([run/0, echo/0]).

run() ->
    Echo = spawn(sol_stale_x, echo, []),
    Sum = loop(Echo, 2000, 0),
    exit(Echo, kill),
    Sum.

echo() ->
    receive
        {ping, From} -> From ! pong, echo();
        {From, K} -> From ! {big, seq(1, K)}, echo()
    end.

seq(I, K) when I > K -> [];
seq(I, K) -> [I | seq(I + 1, K)].

loop(_Echo, 0, Sum) -> Sum;
loop(Echo, N, Sum) ->
    T = [{N, I} || I <- seq(1, 16)],
    [A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16] = T,
    loop(Echo, N - 1, Sum + wide(Echo, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11,
                                 A12, A13, A14, A15, A16)).

%% X2..X16 hold heap pointers; the last call leaves them dead.
wide(Echo, A1, _A2, _A3, _A4, _A5, _A6, _A7, _A8, _A9, _A10, _A11, _A12, _A13, _A14,
     _A15, _A16) ->
    churn(Echo, A1).

%% Minor collections free the heaps the dead registers point into; the reply
%% arrives as a heap fragment, so the next wait switches out wanting a GC.
churn(Echo, A) ->
    _ = build(A, 3000, []),
    Echo ! {self(), 5000},
    receive {big, L} -> wait(Echo, L) end.

build(_A, 0, Acc) -> Acc;
build(A, I, Acc) -> build(A, I - 1, [{I, A} | Acc]).

wait(Echo, L) ->
    Echo ! {ping, self()},
    receive pong -> len(L, 0) end.

len([], N) -> N;
len([_ | T], N) -> len(T, N + 1).
"#;

/// Runs `sol_stale_x:run()` in a booted `target/release/arinsal` node: the crash
/// depends on the boot-time heap layout, which an in-process `Vm` does not have,
/// and the debug build's heap verification makes the loop too slow.
fn run_cli(dir: &std::path::Path) -> String {
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release/arinsal");
    assert!(bin.is_file(), "build target/release/arinsal first");
    let mut child = Command::new(&bin)
        .arg("-noshell")
        .arg("-pa")
        .arg(dir)
        .args(["-eval", "io:format(\"~p~n\", [sol_stale_x:run()]), halt()."])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn arinsal");
    let started = Instant::now();
    while child.try_wait().expect("wait arinsal").is_none() {
        if started.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("sol_stale_x:run did not finish");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().expect("arinsal output");
    assert!(
        output.status.success(),
        "arinsal failed ({:?}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn switch_out_gc_roots_only_live_registers() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping switch-out GC live register test");
        return;
    };
    let module = reference
        .compile_named("sol_stale_x", STALE, &[])
        .expect("compile sol_stale_x");
    reference
        .load("sol_stale_x", &module)
        .expect("load sol_stale_x");
    let expected = match reference.call("sol_stale_x", "run", &[]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("erl sol_stale_x:run failed: {other:?}"),
    };
    let dir = std::env::temp_dir().join(format!("arinsal-switch-out-gc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join("sol_stale_x.beam"), &module).expect("write beam");
    // Each run hits thousands of switch-outs that want a collection; looping the
    // node a few times makes a stale-root read all but certain before the fix.
    for _ in 0..3 {
        assert_eq!(run_cli(&dir), expected);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

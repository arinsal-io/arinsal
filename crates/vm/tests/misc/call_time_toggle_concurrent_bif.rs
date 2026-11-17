//! Turning a trace pattern on and off on a BIF while other schedulers call it must not corrupt
//! their stacks: a light BIF call that falls back to the executor accounts its frame by the call
//! kind (`call_light_bif_shared` passes the call site entry), never by the previous call's.

use arinsal_difftest::RefErl;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MODULE: &str = "bif_toggle_concurrent";
const SOURCE: &str = r#"
-module(bif_toggle_concurrent).
-export([run/0, worker/1]).

run() ->
    ets:new(t, [named_table, public]),
    Big = lists:seq(1, 300),
    ets:insert(t, {a, Big, #{x => Big}}),
    Workers = [spawn_monitor(bif_toggle_concurrent, worker, [Big]) || _ <- lists:seq(1, 4)],
    [begin
         1 = erlang:trace_pattern({ets, lookup, 2}, true, [call_time]),
         receive after 5 -> ok end,
         1 = erlang:trace_pattern({ets, lookup, 2}, false, [call_time])
     end || _ <- lists:seq(1, 100)],
    [exit(Pid, kill) || {Pid, _} <- Workers],
    Reasons = [receive {'DOWN', Ref, process, Pid, Reason} -> Reason end
               || {Pid, Ref} <- Workers],
    case lists:usort(Reasons) of
        [killed] -> ok;
        Other -> {error, Other}
    end.

worker(Big) ->
    [{a, Big, #{x := Big}}] = ets:lookup(t, a),
    worker(Big).
"#;

fn run_arinsal(directory: &Path) -> std::process::Output {
    let executable = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/arinsal");
    assert!(executable.is_file(), "build target/release/arinsal first");
    let mut child = Command::new(&executable)
        .args(["-noshell", "-pa"])
        .arg(directory)
        .args([
            "-eval",
            &format!("io:format(\"RESULT=~p~n\", [{MODULE}:run()]), halt()."),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn arinsal");
    let started = Instant::now();
    loop {
        if child.try_wait().expect("wait for child").is_some() {
            return child.wait_with_output().expect("read child output");
        }
        if started.elapsed() >= Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("arinsal did not finish within 120 seconds");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn toggling_a_bif_trace_pattern_while_other_schedulers_call_it_does_not_crash() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile fixture");
    let directory = std::env::temp_dir().join(format!("arinsal-bif-toggle-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create temporary code path");
    std::fs::write(directory.join(format!("{MODULE}.beam")), beam).expect("write fixture BEAM");
    let output = run_arinsal(&directory);
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        output.status.success(),
        "arinsal failed ({:?}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "RESULT=ok");
}

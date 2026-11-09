use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const SOURCE: &str = r#"
-module(timer_plain_messages_release).
-export([run/0]).

run() ->
    {send_after_receive(), send_after_outer_queue(), start_timer_receive(), cancel_after_fire()}.

send_after_receive() ->
    _ = erlang:send_after(2, self(), tick),
    receive tick -> received after 1000 -> timeout end.

send_after_outer_queue() ->
    Ref = erlang:send_after(2, self(), outer_tick),
    wait_until_fired(Ref),
    receive outer_tick -> outer_queue_message after 0 -> missing end.

wait_until_fired(Ref) ->
    case erlang:read_timer(Ref) of
        false -> ok;
        _ -> wait_until_fired(Ref)
    end.

start_timer_receive() ->
    Ref = erlang:start_timer(2, self(), start_tick),
    receive {timeout, Ref, start_tick} -> received after 1000 -> timeout end.

cancel_after_fire() ->
    Ref = erlang:send_after(2, self(), cancel_tick),
    wait_until_fired(Ref),
    Canceled = erlang:cancel_timer(Ref),
    Message = receive cancel_tick -> received after 0 -> missing end,
    {Canceled, Message}.
"#;

fn timed(program: &str, args: &[&str], cwd: &std::path::Path) -> Output {
    Command::new("timeout")
        .arg("60")
        .arg(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|error| panic!("run {program}: {error}"))
}

fn successful_output(output: Output, label: &str) -> String {
    assert!(
        output.status.success(),
        "{label} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 runtime output")
}

#[test]
fn timer_bif_messages_match_erts_in_release_runtime() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("arinsal-timer-{}-{nonce}", std::process::id()));
    let ebin = dir.join("ebin");
    fs::create_dir_all(&ebin).expect("create temporary beam directory");
    let source = dir.join("timer_plain_messages_release.erl");
    fs::write(&source, SOURCE).expect("write Erlang source");
    let source_arg = source.to_str().expect("source path utf8");
    let ebin_arg = ebin.to_str().expect("ebin path utf8");
    let compile = timed("erlc", &["-o", ebin_arg, source_arg], &dir);
    assert!(
        compile.status.success(),
        "erlc failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let expression = "io:format(\"~tp~n\", [timer_plain_messages_release:run()]), halt().";
    let expected = successful_output(
        timed(
            "erl",
            &["-noshell", "-pa", ebin_arg, "-eval", expression],
            &dir,
        ),
        "erts",
    );
    let release = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/arinsal");
    assert!(
        release.is_file(),
        "release binary missing: {}",
        release.display()
    );
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let actual = successful_output(
        timed(
            release.to_str().expect("release path utf8"),
            &["-noshell", "-pa", ebin_arg, "-eval", expression],
            &repository,
        ),
        "Arinsal release",
    );
    let _ = fs::remove_dir_all(&dir);
    similar_asserts::assert_eq!(expected.trim(), actual.trim());
}

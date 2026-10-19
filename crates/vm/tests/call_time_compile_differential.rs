//! Call-time tracing must not drop a deferred Unicode conversion.

use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use similar_asserts::assert_eq;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MODULE: &str = "call_time_compile_diff";
const SOURCE: &str = r#"
-module(call_time_compile_diff).
-export([deferred_unicode/0, deferred_md5/0, deferred_bif_starts/0, compile_lint/0]).

deferred_unicode() ->
    1 = erlang:trace_pattern({unicode, characters_to_list, 2}, true, [call_time]),
    erlang:trace(all, true, [call]),
    Result = unicode:characters_to_list(binary:copy(<<$a>>, 50000), utf8),
    erlang:trace(all, false, [call]),
    1 = erlang:trace_pattern({unicode, characters_to_list, 2}, false, [call_time]),
    case length(Result) of 50000 -> ok; Other -> {error, Other} end.

deferred_md5() ->
    1 = erlang:trace_pattern({erlang, md5, 1}, true, [call_time]),
    erlang:trace(all, true, [call]),
    Result = erlang:md5(binary:copy(<<$a>>, 50000)),
    erlang:trace(all, false, [call]),
    1 = erlang:trace_pattern({erlang, md5, 1}, false, [call_time]),
    case Result of <<_:128>> -> ok; Other -> {error, Other} end.

deferred_bif_starts() ->
    Data = binary:copy(<<$a>>, 50000),
    List = lists:duplicate(50000, $a),
    Patterns = [{erlang, length, 1}, {erlang, phash2, 1}, {erlang, phash2, 2},
                {erlang, crc32, 1}, {erlang, adler32, 1},
                {unicode, characters_to_binary, 2}],
    [1 = erlang:trace_pattern(Pattern, true, [call_time]) || Pattern <- Patterns],
    erlang:trace(all, true, [call]),
    Result = {length(List), is_integer(erlang:phash2(List)),
              is_integer(erlang:phash2(List, 16#ffffffff)),
              is_integer(erlang:crc32(Data)), is_integer(erlang:adler32(Data)),
              byte_size(unicode:characters_to_binary(List, utf8))},
    erlang:trace(all, false, [call]),
    [1 = erlang:trace_pattern(Pattern, false, [call_time]) || Pattern <- Patterns],
    case Result of {50000, true, true, true, true, 50000} -> ok; Other -> {error, Other} end.

compile_lint() ->
    File = filename:join(code:lib_dir(stdlib, src), "erl_lint.erl"),
    Options = [binary, no_spawn_compiler_process, return_errors, report_errors],
    {CompileResult, {call_time, Profile}} =
        tprof:profile(fun() -> compile:file(File, Options) end,
                      #{type => call_time, report => return}),
    CompileStatus = case CompileResult of
        {ok, erl_lint, _Beam} -> ok;
        {ok, erl_lint} -> ok;
        {error, Errors, Warnings} -> {error, length(Errors), length(Warnings)};
        Other -> Other
    end,
    HasLint = lists:any(fun({erl_lint, _, _, _}) -> true; (_) -> false end, Profile),
    case {CompileStatus, Profile =/= [], HasLint} of
        {ok, true, true} -> ok;
        Failure -> {error, Failure}
    end.
"#;

fn with_timeout(mut child: std::process::Child, program: &Path) -> std::process::Output {
    let started = Instant::now();
    loop {
        if child.try_wait().expect("wait for child").is_some() {
            return child.wait_with_output().expect("read child output");
        }
        if started.elapsed() >= Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{} did not finish within 120 seconds", program.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn run_arinsal(directory: &Path, function: &str) -> String {
    let executable = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/arinsal");
    assert!(executable.is_file(), "build target/release/arinsal first");
    let child = Command::new(&executable)
        .args(["-noshell", "-pa"])
        .arg(directory)
        .args([
            "-eval",
            &format!("io:format(\"RESULT=~p~n\", [{MODULE}:{function}()]), halt()."),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", executable.display()));
    let output = with_timeout(child, &executable);
    assert!(
        output.status.success(),
        "arinsal {function} failed ({:?}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn compare(function: &str) {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile fixture");
    reference.load(MODULE, &beam).expect("load reference");
    let expected = reference
        .call_opts(
            MODULE,
            function,
            &[],
            &CallOptions {
                timeout_ms: Some(120_000),
                ..CallOptions::default()
            },
        )
        .result;

    let directory = std::env::temp_dir().join(format!(
        "arinsal-call-time-{}-{function}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create temporary code path");
    std::fs::write(directory.join(format!("{MODULE}.beam")), beam).expect("write fixture BEAM");
    let actual = run_arinsal(&directory, function);
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(expected, CallResult::Ok(OwnedTerm::Atom("ok".into())));
    assert_eq!(actual, "RESULT=ok", "{function} output from Arinsal");
}

#[test]
fn deferred_unicode_conversion_matches_erts_under_call_time_tracing() {
    compare("deferred_unicode");
}

#[test]
fn deferred_md5_matches_erts_under_call_time_tracing() {
    compare("deferred_md5");
}

#[test]
fn deferred_bif_starts_match_erts_under_call_time_tracing() {
    compare("deferred_bif_starts");
}

#[test]
fn erl_lint_compiles_under_tprof_call_time_with_per_function_data() {
    compare("compile_lint");
}

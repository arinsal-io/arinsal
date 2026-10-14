//! The `zstd` module (`lib/stdlib/src/zstd.erl`) loads its built-in NIF library and behaves like
//! erl 29.1.1 (`erts/emulator/nifs/common/zstd_nif.c`).

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use arinsal_difftest::RefErl;

const MODULE: &str = "zstd_compat_probe";

const SOURCE: &str = r#"
-module(zstd_compat_probe).
-export([oneshot/0, lifecycle/0]).

inputs() ->
    Text = iolist_to_binary(lists:duplicate(2000, <<"the quick brown fox jumps over the lazy dog ">>)),
    Mixed = iolist_to_binary([<<N:32>> || N <- lists:seq(1, 5000)]),
    [<<>>, <<"hello">>, binary_to_list(<<"iolist input">>), [<<"io">>, [<<"list">>, $!]], Text, Mixed].

oneshot() ->
    Rows = [row(Level, Data) || Level <- [1, 3, 19], Data <- inputs()],
    io:format("~w~n", [Rows]),
    Default = [iolist_to_binary(zstd:compress(Data)) || Data <- inputs()],
    io:format("~w~n", [[erlang:md5(C) || C <- Default]]).

lifecycle() ->
    Data = <<"abcabcabcabc">>,
    {ok, CCtx} = zstd:context(compress),
    {ok, DCtx} = zstd:context(decompress),
    Calls = fun(C, D) ->
        [
            fun() -> zstd:compress(Data, C) end,
            fun() -> zstd:stream(C, Data) end,
            fun() -> zstd:flush(C) end,
            fun() -> zstd:finish(C, Data) end,
            fun() -> zstd:set_parameter(C, compressionLevel, 14) end,
            fun() -> zstd:set_parameter(C, dictionary, <<"abc">>) end,
            fun() -> zstd:get_parameter(C, compressionLevel) end,
            fun() -> zstd:reset(C) end,
            fun() -> zstd:close(C) end,
            fun() -> zstd:decompress(Data, D) end,
            fun() -> zstd:stream(D, Data) end,
            fun() -> zstd:finish(D, Data) end,
            fun() -> zstd:reset(D) end,
            fun() -> zstd:close(D) end
        ]
    end,
    Foreign = in_other_process(fun() -> [attempt(F) || F <- Calls(CCtx, DCtx)] end),
    Owner = [attempt(F) || F <- Calls(CCtx, DCtx)],
    io:format("~w~n~w~n", [Foreign, Owner]),
    {Created, Dead} = created_elsewhere(),
    io:format("~w~n", [Created]),
    io:format("~w~n", [Dead]),
    io:format("~w~n", [closed()]).

in_other_process(Fun) ->
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() -> Parent ! {self(), Fun()} end),
    receive
        {Pid, Result} ->
            erlang:demonitor(Ref, [flush]),
            Result
    end.

attempt(Fun) ->
    try
        Fun(),
        ok
    catch
        Class:Reason -> {Class, Reason}
    end.

created_elsewhere() ->
    Parent = self(),
    Creator = spawn(fun() ->
        {ok, C} = zstd:context(compress),
        Parent ! {ctx, C},
        receive stop -> ok end
    end),
    Ctx = receive {ctx, C} -> C end,
    Alive = [
        attempt(fun() -> zstd:compress(<<"abc">>, Ctx) end),
        attempt(fun() -> zstd:close(Ctx) end)
    ],
    Mon = erlang:monitor(process, Creator),
    Creator ! stop,
    receive {'DOWN', Mon, process, Creator, _} -> ok end,
    Dead = [
        attempt(fun() -> zstd:compress(<<"abc">>, Ctx) end),
        attempt(fun() -> zstd:close(Ctx) end)
    ],
    {Alive, Dead}.

closed() ->
    {ok, C} = zstd:context(compress),
    {ok, D} = zstd:context(decompress),
    ok = zstd:close(C),
    ok = zstd:close(D),
    [
        attempt(fun() -> zstd:close(C) end),
        attempt(fun() -> zstd:stream(C, <<"a">>) end),
        attempt(fun() -> zstd:flush(C) end),
        attempt(fun() -> zstd:finish(C, <<"a">>) end),
        attempt(fun() -> zstd:reset(C) end),
        attempt(fun() -> zstd:set_parameter(C, compressionLevel, 3) end),
        attempt(fun() -> zstd:get_parameter(C, compressionLevel) end),
        attempt(fun() -> zstd:compress(<<"a">>, C) end),
        attempt(fun() -> zstd:close(D) end),
        attempt(fun() -> zstd:reset(D) end),
        attempt(fun() -> zstd:stream(D, <<"a">>) end),
        attempt(fun() -> zstd:finish(D, <<"a">>) end),
        attempt(fun() -> zstd:decompress(<<"a">>, D) end)
    ].

row(Level, Data) ->
    Compressed = iolist_to_binary(zstd:compress(Data, #{compressionLevel => Level})),
    Plain = iolist_to_binary(Data),
    Back = iolist_to_binary(zstd:decompress(Compressed)),
    {Level, byte_size(Plain), byte_size(Compressed), erlang:md5(Compressed), Back =:= Plain}.
"#;

type Run = (bool, String, String);

fn run(program: &Path, args: &[&str], dir: &Path) -> Run {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A temp dir has no .tool-versions: pin both runtimes to the reference OTP root.
    if let Some(root) = arinsal_difftest::reference::otp_root() {
        if program == Path::new("erl") {
            command = Command::new(root.join("bin/erl"));
            command
                .args(args)
                .current_dir(dir)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        } else {
            command.env("ERL_ROOTDIR", root);
        }
    }
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", program.display()));
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().expect("output");
                return (
                    output.status.success(),
                    String::from_utf8_lossy(&output.stdout).trim().to_string(),
                    String::from_utf8_lossy(&output.stderr).trim().to_string(),
                );
            }
            Ok(None) if started.elapsed() > Duration::from_secs(120) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{} timed out", program.display());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("wait {}: {error}", program.display()),
        }
    }
}

/// Runs `Module:Function()` on erl and on Arinsal and returns both outputs.
fn both(function: &str) -> Option<(Run, Run)> {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping zstd differential test");
        return None;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile zstd probe");
    drop(reference);
    let dir = std::env::temp_dir().join(format!("arinsal-zstd-compat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join(format!("{MODULE}.beam")), &beam).expect("write beam");
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let eval = format!("{MODULE}:{function}(), halt().");
    let args = [
        "-noshell",
        "-pa",
        dir.to_str().expect("utf-8 path"),
        "-eval",
        &eval,
    ];
    let expected = run(Path::new("erl"), &args, &dir);
    let actual = run(&arinsal, &args, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    Some((expected, actual))
}

#[test]
fn oneshot_compress_decompress_matches_erl() {
    let Some((expected, actual)) = both("oneshot") else {
        return;
    };
    assert!(expected.0, "erl failed: {}", expected.2);
    assert!(
        expected.1.contains(",true}"),
        "erl output has no round trip: {}",
        expected.1
    );
    assert!(actual.0, "arinsal failed: {}\n{}", actual.2, actual.1);
    similar_asserts::assert_eq!(actual.1, expected.1, "stderr {}", actual.2);
}

/// Every context NIF checks the calling process after it checked the handle: a context used by
/// a process other than its creator raises `not_on_controlling_process`, a closed one raises
/// `badarg`, and neither depends on whether the creator is still alive.
#[test]
fn context_owner_and_close_match_erl() {
    let Some((expected, actual)) = both("lifecycle") else {
        return;
    };
    assert!(expected.0, "erl failed: {}", expected.2);
    assert!(
        expected.1.contains("not_on_controlling_process") && expected.1.contains("badarg"),
        "erl output lacks the errors under test: {}",
        expected.1
    );
    assert!(actual.0, "arinsal failed: {}\n{}", actual.2, actual.1);
    similar_asserts::assert_eq!(actual.1, expected.1, "stderr {}", actual.2);
}

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

const PARAM_MODULE: &str = "zstd_param_probe";

const PARAM_SOURCE: &str = r##"
-module(zstd_param_probe).
-export([parameters/0, bad_parameters/0, pledged/0, corrupt/0, levels/0]).

attempt(Fun) ->
    try
        Fun()
    catch
        Class:Reason -> {Class, Reason}
    end.

s(B) when is_binary(B), byte_size(B) > 64 -> {bin, byte_size(B), erlang:md5(B)};
s(R) when is_reference(R) -> reference;
s(L) when is_list(L) -> [s(E) || E <- L];
s(T) when is_tuple(T) -> list_to_tuple([s(E) || E <- tuple_to_list(T)]);
s(T) -> T.

out(Label, Term) -> io:format("~w ~0p~n", [Label, s(Term)]).

in_other_process(Fun) ->
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() -> Parent ! {self(), Fun()} end),
    receive
        {Pid, Result} ->
            erlang:demonitor(Ref, [flush]),
            Result
    end.

text(N) ->
    iolist_to_binary(lists:duplicate(N, <<"the quick brown fox jumps over the lazy dog ">>)).

noise(Size) ->
    {Bytes, _} = lists:foldl(
        fun(_, {Acc, X}) ->
            Y = (X * 1103515245 + 12345) band 16#7fffffff,
            {[(Y bsr 16) band 255 | Acc], Y}
        end,
        {[], 42},
        lists:seq(1, Size)
    ),
    list_to_binary(Bytes).

ckeys() ->
    [compressionLevel, windowLog, hashLog, chainLog, searchLog, minMatch, targetLength, strategy,
     targetCBlockSize, enableLongDistanceMatching, ldmHashLog, ldmMinMatch, ldmBucketSizeLog,
     ldmHashRateLog, contentSizeFlag, checksumFlag, dictIDFlag].

strategies() ->
    [default, fast, dfast, greedy, lazy, lazy2, btlazy2, btopt, btultra, btultra2].

values() ->
    [{compressionLevel, [-5, 0, 1, 7, 19, 22, 1000, -1000]},
     {windowLog, [10, 15, 20, 27]},
     {hashLog, [6, 15, 22]},
     {chainLog, [6, 14, 22]},
     {searchLog, [1, 3, 9]},
     {minMatch, [3, 4, 7]},
     {targetLength, [0, 32, 131072]},
     {strategy, strategies()},
     {targetCBlockSize, [0, 1340, 2048, 131072]},
     {enableLongDistanceMatching, [true, false]},
     {ldmHashLog, [6, 16, 24]},
     {ldmMinMatch, [4, 32, 4096]},
     {ldmBucketSizeLog, [1, 4, 8]},
     {ldmHashRateLog, [0, 5, 20]},
     {contentSizeFlag, [true, false]},
     {checksumFlag, [true, false]},
     {dictIDFlag, [true, false]}].

parameters() ->
    {ok, Fresh} = zstd:context(compress),
    out(defaults, [{K, attempt(fun() -> zstd:get_parameter(Fresh, K) end)} || K <- ckeys()]),
    {ok, DFresh} = zstd:context(decompress),
    out(decompress_default, attempt(fun() -> zstd:get_parameter(DFresh, windowLogMax) end)),
    Sample = text(500),
    lists:foreach(
        fun({Key, Vals}) ->
            lists:foreach(
                fun(Val) ->
                    {ok, C} = zstd:context(compress),
                    Set = attempt(fun() -> zstd:set_parameter(C, Key, Val) end),
                    Get = attempt(fun() -> zstd:get_parameter(C, Key) end),
                    Out = attempt(fun() ->
                        Packed = iolist_to_binary(zstd:compress(Sample, #{Key => Val})),
                        {byte_size(Packed), erlang:md5(Packed),
                         iolist_to_binary(zstd:decompress(Packed)) =:= Sample}
                    end),
                    out(roundtrip, {Key, Val, Set, Get, Out}),
                    ok = zstd:close(C)
                end,
                Vals
            )
        end,
        values()
    ),
    {ok, All} = zstd:context(compress),
    Sets = [{K, V, attempt(fun() -> zstd:set_parameter(All, K, V) end)}
            || {K, [V | _]} <- values()],
    out(set_all, Sets),
    out(get_all, [{K, attempt(fun() -> zstd:get_parameter(All, K) end)} || K <- ckeys()]),
    Packed = attempt(fun() -> iolist_to_binary(zstd:compress(Sample, All)) end),
    out(after_all, Packed),
    Big = noise(300000),
    Frame = iolist_to_binary(zstd:compress(Big, #{windowLog => 17})),
    lists:foreach(
        fun(Val) ->
            {ok, D} = zstd:context(decompress),
            Set = attempt(fun() -> zstd:set_parameter(D, windowLogMax, Val) end),
            Get = attempt(fun() -> zstd:get_parameter(D, windowLogMax) end),
            Back = attempt(fun() -> iolist_to_binary(zstd:decompress(Frame, D)) =:= Big end),
            out(windowLogMax, {Val, Set, Get, Back})
        end,
        [0, 10, 15, 17, 20, 27, 30, 31]
    ),
    out(window_too_small, attempt(fun() ->
        zstd:decompress(Frame, #{windowLogMax => 10})
    end)).

bad_parameters() ->
    {ok, C} = zstd:context(compress),
    {ok, D} = zstd:context(decompress),
    BadKeys = [foo, 1, <<"compressionLevel">>, "compressionLevel", {compressionLevel}, [], 1.5,
               'CompressionLevel', windowLogMax, pledged],
    out(bad_keys_compress, [{K, attempt(fun() -> zstd:set_parameter(C, K, 1) end),
                              attempt(fun() -> zstd:get_parameter(C, K) end)} || K <- BadKeys]),
    out(bad_keys_decompress, [{K, attempt(fun() -> zstd:set_parameter(D, K, 1) end),
                                attempt(fun() -> zstd:get_parameter(D, K) end)}
                              || K <- BadKeys -- [windowLogMax]]),
    out(compress_keys_on_decompress, [{K, attempt(fun() -> zstd:set_parameter(D, K, 1) end),
                                        attempt(fun() -> zstd:get_parameter(D, K) end)}
                                      || K <- ckeys()]),
    out(bad_key_bad_value, [attempt(fun() -> zstd:set_parameter(C, foo, bar) end),
                            attempt(fun() -> zstd:set_parameter(D, foo, bar) end),
                            attempt(fun() -> zstd:set_parameter(D, windowLogMax, bar) end),
                            attempt(fun() -> zstd:set_parameter(D, windowLogMax, 1.0) end)]),
    BadStrategy = [nope, 1, "fast", {fast}, 'Fast', true, 1.0, <<"fast">>],
    BadBool = [1, 0, yes, undefined, "true", <<"true">>, {true}, 1.0],
    BadInt = [a, 1.0, "1", <<1>>, true, {1}, 1 bsl 31, -(1 bsl 31) - 1, 1 bsl 40, -(1 bsl 40),
              1 bsl 64, 1 bsl 100, (1 bsl 31) - 1, -(1 bsl 31)],
    Classes = [{strategy, BadStrategy}, {enableLongDistanceMatching, BadBool},
               {contentSizeFlag, BadBool}, {checksumFlag, BadBool}, {dictIDFlag, BadBool},
               {compressionLevel, BadInt}, {windowLog, BadInt}, {targetLength, BadInt}],
    lists:foreach(
        fun({Key, Vals}) ->
            out(bad_values, {Key, [{V, attempt(fun() -> zstd:set_parameter(C, Key, V) end)}
                                   || V <- Vals]})
        end,
        Classes
    ),
    out(still_default, [{K, attempt(fun() -> zstd:get_parameter(C, K) end)} || K <- ckeys()]),
    Bounds = [{windowLog, 99}, {windowLog, 9}, {windowLog, 32}, {hashLog, 100}, {hashLog, 5},
              {chainLog, 100}, {chainLog, 5}, {searchLog, 100}, {searchLog, 0}, {minMatch, 100},
              {minMatch, 2}, {targetLength, -1}, {targetLength, 1 bsl 30}, {targetCBlockSize, 1},
              {targetCBlockSize, 1 bsl 30}, {ldmHashLog, 100}, {ldmMinMatch, 1},
              {ldmBucketSizeLog, 100}, {ldmHashRateLog, 100}, {compressionLevel, 1000},
              {compressionLevel, -(1 bsl 31)}],
    out(bounds, [{K, V, attempt(fun() -> zstd:set_parameter(C, K, V) end),
                  attempt(fun() -> zstd:get_parameter(C, K) end)} || {K, V} <- Bounds]),
    out(dbounds, [{V, attempt(fun() -> zstd:set_parameter(D, windowLogMax, V) end),
                   attempt(fun() -> zstd:get_parameter(D, windowLogMax) end)}
                  || V <- [100, -1, 0, 9, 10, 31, 32, 1 bsl 31, (1 bsl 31) - 1]]),
    {ok, K1} = zstd:context(compress),
    out(unchanged_after_failure, [
        attempt(fun() -> zstd:set_parameter(K1, compressionLevel, 5) end),
        attempt(fun() -> zstd:set_parameter(K1, compressionLevel, nope) end),
        attempt(fun() -> zstd:set_parameter(K1, windowLog, 99) end),
        attempt(fun() -> zstd:get_parameter(K1, compressionLevel) end),
        attempt(fun() -> zstd:get_parameter(K1, windowLog) end)
    ]),
    {ok, K2} = zstd:context(compress),
    out(set_after_stream, [
        attempt(fun() -> zstd:stream(K2, <<"abc">>) end),
        attempt(fun() -> zstd:set_parameter(K2, compressionLevel, 5) end),
        attempt(fun() -> zstd:set_parameter(K2, windowLog, 20) end),
        attempt(fun() -> zstd:set_parameter(K2, checksumFlag, true) end),
        attempt(fun() -> zstd:get_parameter(K2, compressionLevel) end),
        attempt(fun() -> zstd:get_parameter(K2, windowLog) end),
        attempt(fun() -> zstd:reset(K2) end),
        attempt(fun() -> zstd:set_parameter(K2, compressionLevel, 5) end),
        attempt(fun() -> zstd:get_parameter(K2, compressionLevel) end)
    ]),
    ok = zstd:close(C),
    ok = zstd:close(D),
    out(closed, [attempt(fun() -> zstd:set_parameter(C, foo, 1) end),
                 attempt(fun() -> zstd:set_parameter(C, compressionLevel, nope) end),
                 attempt(fun() -> zstd:set_parameter(C, compressionLevel, 1) end),
                 attempt(fun() -> zstd:get_parameter(C, foo) end),
                 attempt(fun() -> zstd:get_parameter(C, compressionLevel) end),
                 attempt(fun() -> zstd:set_parameter(D, foo, bar) end),
                 attempt(fun() -> zstd:set_parameter(D, windowLogMax, 10) end),
                 attempt(fun() -> zstd:set_parameter(D, windowLogMax, bar) end),
                 attempt(fun() -> zstd:get_parameter(D, foo) end),
                 attempt(fun() -> zstd:get_parameter(D, windowLogMax) end)]),
    {ok, {compress, CRef}} = zstd:context(compress),
    {ok, {decompress, DRef}} = zstd:context(decompress),
    Wrong = [{compress, DRef}, {decompress, CRef}, {compress, foo}, {decompress, make_ref()},
             {compress, binary_to_term(term_to_binary(CRef))},
             {decompress, binary_to_term(term_to_binary(DRef))}, {compress, <<1, 2, 3>>},
             {compress, 1}],
    out(wrong_type, [{Index, attempt(fun() -> zstd:set_parameter(W, compressionLevel, 3) end),
                         attempt(fun() -> zstd:set_parameter(W, foo, bar) end),
                         attempt(fun() -> zstd:set_parameter(W, windowLogMax, 10) end),
                         attempt(fun() -> zstd:get_parameter(W, compressionLevel) end),
                         attempt(fun() -> zstd:get_parameter(W, windowLogMax) end),
                         attempt(fun() -> zstd:set_parameter(W, pledgedSrcSize, 3) end),
                         attempt(fun() -> zstd:stream(W, <<"a">>) end),
                         attempt(fun() -> zstd:flush(W) end),
                         attempt(fun() -> zstd:finish(W, <<"a">>) end),
                         attempt(fun() -> zstd:reset(W) end),
                         attempt(fun() -> zstd:close(W) end),
                         attempt(fun() -> zstd:compress(<<"a">>, W) end),
                         attempt(fun() -> zstd:decompress(<<"a">>, W) end)}
                     || {Index, W} <- lists:zip(lists:seq(1, length(Wrong)), Wrong)]),
    {ok, Owned} = zstd:context(compress),
    {ok, DOwned} = zstd:context(decompress),
    out(foreign, in_other_process(fun() ->
        [attempt(fun() -> zstd:set_parameter(Owned, foo, 1) end),
         attempt(fun() -> zstd:set_parameter(Owned, compressionLevel, nope) end),
         attempt(fun() -> zstd:get_parameter(Owned, foo) end),
         attempt(fun() -> zstd:set_parameter(DOwned, foo, bar) end),
         attempt(fun() -> zstd:set_parameter(DOwned, windowLogMax, bar) end),
         attempt(fun() -> zstd:get_parameter(DOwned, foo) end),
         attempt(fun() -> zstd:set_parameter(Owned, pledgedSrcSize, -1) end),
         attempt(fun() -> zstd:set_parameter(Owned, pledgedSrcSize, 5) end)]
    end)),
    out(owner_unaffected, [attempt(fun() -> zstd:set_parameter(Owned, compressionLevel, 4) end),
                           attempt(fun() -> zstd:get_parameter(Owned, compressionLevel) end)]).

pledged() ->
    Abc = <<"abc">>,
    Unpledged = iolist_to_binary(zstd:compress(Abc)),
    out(unpledged, Unpledged),
    {ok, A} = zstd:context(compress),
    out(a_pledge, attempt(fun() -> zstd:set_parameter(A, pledgedSrcSize, 100) end)),
    out(a_stream, attempt(fun() -> zstd:stream(A, Abc) end)),
    out(a_finish, attempt(fun() -> zstd:finish(A, <<>>) end)),
    out(a_reuse, attempt(fun() -> zstd:finish(A, Abc) end)),
    {ok, B} = zstd:context(compress),
    out(b_pledge, attempt(fun() -> zstd:set_parameter(B, pledgedSrcSize, 2) end)),
    out(b_stream, attempt(fun() -> zstd:stream(B, Abc) end)),
    out(b_finish, attempt(fun() -> zstd:finish(B, <<>>) end)),
    out(b_repledge, attempt(fun() -> zstd:set_parameter(B, pledgedSrcSize, 3) end)),
    out(b_reuse, attempt(fun() -> zstd:finish(B, Abc) end)),
    out(b_header, attempt(fun() -> zstd:get_frame_header(iolist_to_binary(
        element(2, zstd:finish(B, Abc)))) end)),
    {ok, C} = zstd:context(compress),
    out(c_pledge, attempt(fun() -> zstd:set_parameter(C, pledgedSrcSize, 3) end)),
    {done, CFrame} = zstd:finish(C, Abc),
    out(c_frame, iolist_to_binary(CFrame)),
    out(c_header, zstd:get_frame_header(iolist_to_binary(CFrame))),
    out(c_after, attempt(fun() -> iolist_to_binary(element(2, zstd:finish(C, Abc))) end)),
    {ok, E} = zstd:context(compress),
    out(e_pledge, attempt(fun() -> zstd:set_parameter(E, pledgedSrcSize, 100) end)),
    out(e_reset, attempt(fun() -> zstd:reset(E) end)),
    out(e_finish, attempt(fun() -> zstd:finish(E, Abc) end)),
    {ok, F} = zstd:context(compress),
    out(f_pledge_short, attempt(fun() -> zstd:set_parameter(F, pledgedSrcSize, 4) end)),
    out(f_finish_short, attempt(fun() -> zstd:finish(F, Abc) end)),
    out(f_compress_after, attempt(fun() -> iolist_to_binary(zstd:compress(Abc, F)) end)),
    out(f_compress_after_2, attempt(fun() -> iolist_to_binary(zstd:compress(Abc, F)) end)),
    Sizes = [0, 1, 3, 1 bsl 32, (1 bsl 64) - 2, (1 bsl 64) - 1, 1 bsl 64, 1 bsl 100, -1, -(1 bsl 64),
             a, 1.0, "3", <<3>>, {3}, []],
    out(pledge_values, [{Sz, attempt(fun() ->
                                         {ok, P} = zstd:context(compress),
                                         zstd:set_parameter(P, pledgedSrcSize, Sz)
                                     end)} || Sz <- Sizes]),
    {ok, D} = zstd:context(decompress),
    out(decompress_pledge, attempt(fun() -> zstd:set_parameter(D, pledgedSrcSize, 3) end)),
    {ok, G} = zstd:context(compress),
    ok = zstd:close(G),
    out(closed_pledge, [attempt(fun() -> zstd:set_parameter(G, pledgedSrcSize, 3) end),
                        attempt(fun() -> zstd:set_parameter(G, pledgedSrcSize, -1) end),
                        attempt(fun() -> zstd:set_parameter(G, pledgedSrcSize, a) end)]),
    {ok, H} = zstd:context(compress),
    out(foreign_pledge, in_other_process(fun() ->
        [attempt(fun() -> zstd:set_parameter(H, pledgedSrcSize, 3) end),
         attempt(fun() -> zstd:set_parameter(H, pledgedSrcSize, -1) end)]
    end)),
    Big = text(300),
    {ok, I} = zstd:context(compress),
    out(i_one_shot, [attempt(fun() -> iolist_to_binary(zstd:compress(Big, I)) end),
                     attempt(fun() -> iolist_to_binary(zstd:compress(Big, I)) end)]),
    {ok, J} = zstd:context(compress),
    out(j_stream_overflow, [
        attempt(fun() -> zstd:set_parameter(J, pledgedSrcSize, 10) end),
        attempt(fun() -> zstd:stream(J, text(1)) end),
        attempt(fun() -> zstd:finish(J, <<>>) end),
        attempt(fun() -> zstd:set_parameter(J, pledgedSrcSize, 10) end),
        attempt(fun() -> zstd:stream(J, <<"0123456789">>) end),
        attempt(fun() -> zstd:flush(J) end),
        attempt(fun() -> zstd:finish(J, <<>>) end)
    ]).

corrupt() ->
    Text = text(70),
    Frame = iolist_to_binary(zstd:compress(Text)),
    Check = iolist_to_binary(zstd:compress(Text, #{checksumFlag => true})),
    Size = byte_size(Frame),
    CSize = byte_size(Check),
    out(sizes, {Size, CSize}),
    Flip = fun(Bin, Pos) ->
        <<Head:Pos/binary, Byte, Tail/binary>> = Bin,
        <<Head/binary, (Byte bxor 16#ff), Tail/binary>>
    end,
    lists:foreach(
        fun({Label, F, FSize}) ->
            Positions = lists:usort([0, 1, 3, 4, 5, 6, 8, 12, FSize div 2, FSize - 8, FSize - 5,
                                     FSize - 4, FSize - 1]),
            out(Label, [{Pos, attempt(fun() -> zstd:decompress(Flip(F, Pos)) end)}
                        || Pos <- Positions, Pos >= 0, Pos < FSize])
        end,
        [{flipped, Frame, Size}, {flipped_checksum, Check, CSize}]
    ),
    Lengths = lists:usort([0, 1, 3, 4, 5, 6, 8, Size div 2, Size - 1, Size]),
    out(truncated, [{L, attempt(fun() -> zstd:decompress(binary:part(Frame, 0, L)) end)}
                    || L <- Lengths]),
    out(truncated_checksum, [{L, attempt(fun() -> zstd:decompress(binary:part(Check, 0, L)) end)}
                             || L <- [CSize - 4, CSize - 1]]),
    Garbage = [<<"not a frame at all">>, <<0>>, <<>>, <<1, 2, 3>>, <<16#28, 16#B5, 16#2F>>,
               <<16#28, 16#B5, 16#2F, 16#FD>>, [<<"not">>, " a frame"], [], [<<>>],
               binary:copy(<<255>>, 100)],
    out(garbage, [{G, attempt(fun() -> zstd:decompress(G) end)} || G <- Garbage]),
    out(trailing, [attempt(fun() -> zstd:decompress([Frame, <<"junk">>]) end),
                   attempt(fun() -> zstd:decompress([Frame, <<16#28, 16#B5>>]) end),
                   attempt(fun() -> zstd:decompress([Frame, Frame]) end),
                   attempt(fun() -> zstd:decompress(<<Frame/binary, Check/binary>>) end)]),
    Skip = <<16#184D2A50:32/little, 3:32/little, 1, 2, 3>>,
    out(skippable, [attempt(fun() -> zstd:decompress(Skip) end),
                    attempt(fun() -> zstd:decompress([Skip, Frame]) end),
                    attempt(fun() -> zstd:decompress([Frame, Skip]) end)]),
    {ok, D} = zstd:context(decompress),
    Bad = Flip(Check, CSize div 2),
    out(ctx_after_error, [
        attempt(fun() -> zstd:decompress(Bad, D) end),
        attempt(fun() -> zstd:decompress(Check, D) end),
        attempt(fun() -> zstd:decompress(<<"garbage here">>, D) end),
        attempt(fun() -> zstd:decompress(Frame, D) end)
    ]),
    {ok, S} = zstd:context(decompress),
    out(stream_error_then_reuse, [
        attempt(fun() -> zstd:stream(S, binary:part(Check, 0, 10)) end),
        attempt(fun() -> zstd:stream(S, Bad) end),
        attempt(fun() -> zstd:finish(S, Check) end),
        attempt(fun() -> zstd:finish(S, <<"garbage here">>) end),
        attempt(fun() -> zstd:finish(S, Frame) end)
    ]),
    {ok, K} = zstd:context(compress),
    out(compress_ctx_error_reuse, [
        attempt(fun() -> zstd:stream(K, Text) end),
        attempt(fun() -> zstd:set_parameter(K, compressionLevel, 3) end),
        attempt(fun() -> zstd:finish(K, <<>>) end),
        attempt(fun() -> zstd:set_parameter(K, compressionLevel, 3) end),
        attempt(fun() -> zstd:compress(Text, K) end)
    ]).

levels() ->
    Inputs = [<<>>, <<"abc">>, binary:copy(<<"x">>, 64), binary:copy(<<"y">>, 65), text(24),
              noise(20000)],
    Levels = [-22, -20, -5, -1, 0, 1, 3, 9, 15, 19, 22],
    lists:foreach(
        fun(Level) ->
            Rows = [begin
                        Packed = iolist_to_binary(zstd:compress(Data, #{compressionLevel => Level})),
                        {byte_size(Data), byte_size(Packed), erlang:md5(Packed),
                         iolist_to_binary(zstd:decompress(Packed)) =:= Data}
                    end || Data <- Inputs],
            {ok, C} = zstd:context(compress),
            ok = zstd:set_parameter(C, compressionLevel, Level),
            ViaCtx = [erlang:md5(iolist_to_binary(zstd:compress(Data, C))) || Data <- Inputs],
            out(level, {Level, Rows, ViaCtx, zstd:get_parameter(C, compressionLevel)})
        end,
        Levels
    ).
"##;

/// Runs `Module:Function()` of the parameter probe on erl and on Arinsal.
fn param_both(function: &str) -> Option<(Run, Run)> {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping zstd differential test");
        return None;
    };
    let beam = reference
        .compile_named(PARAM_MODULE, PARAM_SOURCE, &[])
        .expect("compile zstd parameter probe");
    drop(reference);
    let dir = std::env::temp_dir().join(format!(
        "arinsal-zstd-param-{}-{function}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join(format!("{PARAM_MODULE}.beam")), &beam).expect("write beam");
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let eval = format!("{PARAM_MODULE}:{function}(), halt().");
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

/// Both runtimes print the same lines, and erl's output shows the behavior under test.
fn assert_param_matches(function: &str, markers: &[&str]) {
    let Some((expected, actual)) = param_both(function) else {
        return;
    };
    assert!(expected.0, "erl failed: {}\n{}", expected.2, expected.1);
    for marker in markers {
        assert!(
            expected.1.contains(marker),
            "erl output lacks {marker}: {}",
            expected.1
        );
    }
    assert!(actual.0, "arinsal failed: {}\n{}", actual.2, actual.1);
    similar_asserts::assert_eq!(actual.1, expected.1, "stderr {}", actual.2);
}

/// Defaults, set/get round trips and the effect on the compressed bytes for all 17 compress
/// parameters (every strategy atom, both booleans) and `windowLogMax`. The boolean getters
/// always return `false`.
#[test]
fn parameter_round_trips_match_erl() {
    assert_param_matches(
        "parameters",
        &[
            "roundtrip {strategy,btultra2,ok,btultra2,",
            "roundtrip {checksumFlag,true,ok,false,",
            "windowLogMax {17,ok,17,true}",
            "Frame requires too much memory",
        ],
    );
}

/// Bad keys and values, the `badarg` / `invalid_key` / `invalid_value` / zstd error choice and
/// its order, closed, foreign and wrong-type contexts.
#[test]
fn bad_parameters_match_erl() {
    assert_param_matches(
        "bad_parameters",
        &[
            "{badarg,{invalid_key,foo}}",
            "{badarg,{invalid_value,",
            "{zstd_error,<<\"Parameter is out of bound\">>}",
            "not_on_controlling_process",
            "{error,badarg}",
        ],
    );
}

/// A pledged source size that the stream does not meet raises a zstd error and resets the
/// session, and invalid sizes raise `badarg`.
#[test]
fn pledged_source_size_matches_erl() {
    assert_param_matches(
        "pledged",
        &[
            "Src size is incorrect",
            "{-1,{error,badarg}}",
            "{1.0,{error,badarg}}",
        ],
    );
}

/// Corrupted, truncated and garbage frames, and a context that is used again after an error.
#[test]
fn corrupted_frames_match_erl() {
    assert_param_matches("corrupt", &["zstd_error", "Unknown frame descriptor"]);
}

/// One-shot compression at negative, default and high levels, and the same level set on a context.
#[test]
fn one_shot_levels_match_erl() {
    assert_param_matches("levels", &["level {-22,", "level {22,"]);
}

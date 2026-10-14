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

const DICT_MODULE: &str = "zstd_dict_probe";

const DICT_SOURCE: &str = r#"
-module(zstd_dict_probe).
-export([roundtrip/1, ids/1, load_ref/1, frames/1, errors/1, lifecycle/1]).

dict(File) ->
    {ok, Dict} = file:read_file(File),
    Dict.

texts() ->
    Text = iolist_to_binary(lists:duplicate(300, <<"the quick brown fox jumps over the lazy dog ">>)),
    Mixed = iolist_to_binary([<<N:32>> || N <- lists:seq(1, 4000)]),
    [<<"hello dictionary world">>, Text, Mixed].

attempt(Fun) ->
    try
        {ok, Fun()}
    catch
        Class:Reason -> {Class, text(Reason)}
    end.

text({zstd_error, Message}) when is_binary(Message) -> {zstd_error, binary_to_atom(Message)};
text(Reason) -> Reason.

in_other_process(Fun) ->
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() -> Parent ! {self(), Fun()} end),
    receive
        {Pid, Result} ->
            erlang:demonitor(Ref, [flush]),
            Result
    end.

unaligned(Bin) ->
    <<_:3, Rest/bitstring>> = <<0:3, Bin/binary>>,
    Rest.

bin(Iolist) -> iolist_to_binary(Iolist).

roundtrip(File) ->
    Dict = dict(File),
    {ok, DDict} = zstd:dict(decompress, Dict),
    Rows = [row(Dict, DDict, Level, Data) || Level <- [-5, 0, 3, 19], Data <- texts()],
    io:format("~w~n~w~n", [zstd:get_dict_id(Dict), Rows]).

row(Dict, DDict, Level, Data) ->
    {ok, CDict} = zstd:dict(compress, Dict, #{compressionLevel => Level}),
    ByRef = bin(zstd:compress(Data, #{dictionary => CDict})),
    ByLoad = bin(zstd:compress(Data, #{dictionary => Dict, compressionLevel => Level})),
    ByUnaligned = bin(zstd:compress(Data, #{dictionary => unaligned(Dict), compressionLevel => Level})),
    ByList = bin(zstd:compress(Data, #{dictionary => [binary_to_list(binary:part(Dict, 0, 100)), binary:part(Dict, 100, byte_size(Dict) - 100)], compressionLevel => Level})),
    Back = [bin(zstd:decompress(C, #{dictionary => D})) =:= Data
            || C <- [ByRef, ByLoad], D <- [DDict, Dict, unaligned(Dict)]],
    {Level, byte_size(ByRef), erlang:md5(ByRef), erlang:md5(ByLoad), ByLoad =:= ByList,
     ByLoad =:= ByUnaligned, zstd:get_dict_id(ByRef), Back}.

ids(File) ->
    Dict = dict(File),
    {ok, CDict} = zstd:dict(compress, Dict, #{compressionLevel => -5}),
    {ok, DDict} = zstd:dict(decompress, Dict),
    {ok, CRaw} = zstd:dict(compress, <<"raw content dictionary, no magic number">>),
    {ok, DRaw} = zstd:dict(decompress, <<>>),
    {ok, DShort} = zstd:dict(decompress, <<1, 2, 3>>),
    {CTag, CRef} = CDict,
    {DTag, DRef} = DDict,
    {ok, {compress, CtxRef}} = zstd:context(compress),
    Frame = bin(zstd:compress(<<"abc">>, #{dictionary => CDict})),
    Plain = bin(zstd:compress(<<"abc">>)),
    Garbage = <<255, 254, 253, 252, 251, 250, 249, 248, 247, 246>>,
    Split = [binary:part(Dict, 0, 10), [binary_to_list(binary:part(Dict, 10, 5)), binary:part(Dict, 15, byte_size(Dict) - 15)]],
    Ids = [attempt(fun() -> zstd:get_dict_id(X) end)
           || X <- [CDict, DDict, CRaw, DRaw, DShort, Dict, Split, binary_to_list(Dict), unaligned(Dict),
                    Frame, [Frame], binary_to_list(Frame), unaligned(Frame), [binary:part(Frame, 0, 3), binary:part(Frame, 3, byte_size(Frame) - 3)],
                    Plain, <<>>, [], Garbage, <<1, 2, 3>>]],
    Bad = [attempt(fun() -> zstd:get_dict_id(X) end)
           || X <- [{CTag, DRef}, {DTag, CRef}, {cdict, make_ref()}, {ddict, make_ref()}, {cdict, CtxRef}, {ddict, CtxRef},
                    {cdict, 5}, atom, 5, <<1:3>>, <<1, 2, 3, 4, 5, 6:3>>, [a], [256], [-1], [<<1:3>>], {a, b}, [Frame | 5]]],
    io:format("~w~n~w~n", [Ids, Bad]).

load_ref(File) ->
    Dict = dict(File),
    Data = hd(tl(texts())),
    {ok, CDict} = zstd:dict(compress, Dict, #{compressionLevel => 3}),
    {ok, CDict9} = zstd:dict(compress, Dict, #{compressionLevel => 9}),
    {ok, DDict} = zstd:dict(decompress, Dict),
    {cdict, CRef} = CDict,
    {ddict, DRef} = DDict,
    {ok, C} = zstd:context(compress),
    {ok, D} = zstd:context(decompress),
    Sets = fun(Ctx, Values) -> [attempt(fun() -> zstd:set_parameter(Ctx, dictionary, V) end) || V <- Values] end,
    Loads = Sets(C, [Dict, [Dict], <<>>, [], "", Dict, [<<1:3>>], atom, 5, {a, b}, {cdict, 5}, [Dict | <<>>], [[], [[]]]]),
    Refs = Sets(C, [CDict, {cdict, DRef}, {cdict, make_ref()}, {ddict, CRef}, CDict9, {cdict, CRef}]),
    Used = bin(zstd:compress(Data, C)),
    DLoads = Sets(D, [Dict, <<>>, Dict, [], unaligned(Dict), 5]),
    DRefs = Sets(D, [DDict, {ddict, CRef}, {ddict, make_ref()}, {cdict, DRef}]),
    Back = bin(zstd:decompress(Used, D)),
    %% the dictionary is dropped before the load, and a load refused mid-stream keeps the context usable
    {ok, M} = zstd:context(compress, #{dictionary => CDict}),
    {continue, Part1} = zstd:stream(M, <<"first part of the stream ">>),
    MidLoad = Sets(M, [Dict, <<>>, CDict9, {cdict, DRef}]),
    {continue, Part2} = zstd:stream(M, <<"second part of the stream">>),
    {done, Tail} = zstd:finish(M, <<>>),
    Frame = bin([Part1, Part2, Tail]),
    {ok, MD} = zstd:context(decompress, #{dictionary => DDict}),
    {continue, DPart} = zstd:stream(MD, binary:part(Frame, 0, 20)),
    MidDLoad = Sets(MD, [Dict, <<>>, DDict, {ddict, CRef}]),
    {done, DTail} = zstd:finish(MD, binary:part(Frame, 20, byte_size(Frame) - 20)),
    Reset = bin(zstd:compress(Data, M)),
    io:format("~w~n~w~n~w~n~w~n~w~n~w~n~w~n~w~n~w~n~w~n~w~n",
              [Loads, Refs, {byte_size(Used), erlang:md5(Used)}, DLoads, DRefs, Back =:= Data,
               MidLoad, {byte_size(Frame), erlang:md5(Frame), bin([DPart, DTail])},
               MidDLoad, {byte_size(Reset), erlang:md5(Reset)}, zstd:get_dict_id(Frame)]).

frames(File) ->
    Dict = dict(File),
    {ok, CDict} = zstd:dict(compress, Dict),
    Data = bin(lists:duplicate(100, <<"frame header data ">>)),
    OneShot = bin(zstd:compress(Data)),
    {ok, S} = zstd:context(compress),
    {continue, S1} = zstd:stream(S, binary:part(Data, 0, 500)),
    {done, S2} = zstd:finish(S, binary:part(Data, 500, byte_size(Data) - 500)),
    Streamed = bin([S1, S2]),
    Checked = bin(zstd:compress(Data, #{checksumFlag => true})),
    WithDict = bin(zstd:compress(Data, #{dictionary => CDict, checksumFlag => true})),
    NoSize = bin(zstd:compress(Data, #{contentSizeFlag => false, dictIDFlag => false})),
    Skippable = <<16#184D2A50:32/little, 4:32/little, 1, 2, 3, 4>>,
    Skip2 = <<16#184D2A5F:32/little, 0:32/little>>,
    {ok, #{headerSize := HeaderSize}} = zstd:get_frame_header(WithDict),
    Prefixes = [binary:part(WithDict, 0, N) || N <- lists:seq(5, HeaderSize)],
    Full = [OneShot, Streamed, Checked, WithDict, NoSize, Skippable, Skip2, [OneShot], binary_to_list(OneShot),
            unaligned(OneShot), [binary:part(OneShot, 0, 3), binary:part(OneShot, 3, 9)],
            [<<40, 181>> | <<47, 253, 0, 88>>], <<40, 181, 47, 253, 0, 88>>, <<40, 181, 47, 253, 0>>,
            <<40, 181, 47, 253, 32, 3, 25, 0, 0, 97, 98, 99>>],
    Garbage = [<<1, 2, 3>>, <<1, 2, 3, 4, 5>>, <<"garbage bytes here">>, <<255, 255, 255, 255, 255, 255, 255, 255, 255, 255>>,
               <<0, 0, 0, 0, 0, 0>>, [<<1, 2>>, <<3, 4, 5>>], <<"not a frame">>],
    NotBinary = [atom, 5, {a}, <<1:3>>, <<40, 181, 47, 253, 0, 88, 1:1>>, [a], [256], [-1], [<<1:3>>], [<<40, 181, 47, 253, 0, 88>> | 5], 1.5, make_ref()],
    Header = fun(X) ->
        case attempt(fun() -> zstd:get_frame_header(X) end) of
            {ok, {ok, Map}} -> {ok, maps:to_list(Map)};
            {ok, {error, Message}} -> {error, binary_to_atom(Message)};
            Other -> Other
        end
    end,
    io:format("~w~n~w~n~w~n~w~n~w~n",
              [[Header(X) || X <- Full], [Header(X) || X <- Prefixes], [Header(X) || X <- Garbage], [Header(X) || X <- NotBinary],
               zstd:get_dict_id(WithDict)]).

errors(File) ->
    Dict = dict(File),
    Other = <<"another raw content dictionary, it has no zstd magic number">>,
    Data = hd(tl(texts())),
    {ok, CDict} = zstd:dict(compress, Dict, #{compressionLevel => 2}),
    {ok, DDict} = zstd:dict(decompress, Dict),
    {ok, DOther} = zstd:dict(decompress, Other),
    Compressed = bin(zstd:compress(Data, #{dictionary => CDict})),
    Mismatch = [attempt(fun() -> bin(zstd:decompress(Compressed, Params)) =:= Data end)
                || Params <- [#{}, #{dictionary => Other}, #{dictionary => DOther}, #{dictionary => <<>>}, #{dictionary => [<<>>]},
                              #{dictionary => Dict}, #{dictionary => DDict}]],
    {ok, D} = zstd:context(decompress, #{dictionary => DDict}),
    ok = zstd:set_parameter(D, dictionary, <<>>),
    AfterReset = attempt(fun() -> zstd:finish(D, Compressed) end),
    ok = zstd:set_parameter(D, dictionary, DOther),
    StreamMismatch = attempt(fun() -> zstd:stream(D, Compressed) end),
    Created = [attempt(fun() -> case zstd:dict(Mode, X, Opts) of {ok, {Tag, Ref}} when is_reference(Ref) -> Tag; Bad -> Bad end end)
               || {Mode, X, Opts} <- [{compress, [1, 2, 3], #{}}, {decompress, [1, 2, 3], #{}}, {compress, <<1:3>>, #{}},
                                      {decompress, <<1:3>>, #{}}, {compress, atom, #{}}, {decompress, 5, #{}},
                                      {compress, <<>>, #{}}, {decompress, <<>>, #{}}, {compress, <<1, 2, 3>>, #{}},
                                      {decompress, <<1, 2, 3>>, #{}}, {compress, Dict, #{compressionLevel => foo}},
                                      {compress, Dict, #{compressionLevel => 1 bsl 40}}, {compress, Dict, #{compressionLevel => 1000}},
                                      {compress, Dict, #{compressionLevel => -1000}}, {compress, Dict, #{compressionLevel => 1.0}},
                                      {compress, unaligned(Dict), #{compressionLevel => 3}}, {decompress, unaligned(Dict), #{}},
                                      {compress, Dict, #{compressionLevel => 22}}, {compress, Dict, #{compressionLevel => -(1 bsl 31)}},
                                      {compress, Dict, #{compressionLevel => (1 bsl 31) - 1}}, {compress, Dict, #{compressionLevel => 1 bsl 31}}]],
    {ok, C} = zstd:context(compress),
    {ok, C2} = zstd:context(decompress),
    ok = zstd:close(C),
    ok = zstd:close(C2),
    Closed = [attempt(fun() -> zstd:set_parameter(Ctx, dictionary, V) end) || Ctx <- [C, C2], V <- [Dict, CDict, DDict, <<>>, atom]],
    {ok, FC} = zstd:context(compress),
    {ok, FD} = zstd:context(decompress),
    Foreign = in_other_process(fun() ->
        [attempt(fun() -> zstd:set_parameter(Ctx, dictionary, V) end)
         || Ctx <- [FC, FD], V <- [Dict, CDict, DDict, {cdict, make_ref()}, {ddict, make_ref()}, atom]]
    end),
    Wrong = [attempt(fun() -> zstd:set_parameter(Ctx, dictionary, V) end)
             || Ctx <- [FC, FD], V <- [CDict, DDict, {cdict, element(2, FC)}, {ddict, element(2, FD)}]],
    io:format("~w~n~w~n~w~n~w~n~w~n~w~n~w~n~w~n", [Mismatch, AfterReset, StreamMismatch, Created, Closed, Foreign, Wrong, zstd:get_dict_id(Compressed)]).

lifecycle(File) ->
    Dict = dict(File),
    Data = hd(tl(texts())),
    Make = fun(Level) ->
        {ok, CD} = zstd:dict(compress, Dict, #{compressionLevel => Level}),
        {ok, DD} = zstd:dict(decompress, Dict),
        {ok, C} = zstd:context(compress, #{dictionary => CD}),
        {ok, D} = zstd:context(decompress, #{dictionary => DD}),
        {C, D}
    end,
    {C, D} = Make(3),
    Churn = [Make(L) || L <- lists:seq(1, 50)],
    erlang:garbage_collect(),
    [begin {ok, _} = zstd:dict(compress, Dict), {ok, _} = zstd:dict(decompress, Dict) end || _ <- lists:seq(1, 200)],
    erlang:garbage_collect(),
    F1 = bin(zstd:compress(Data, C)),
    B1 = bin(zstd:decompress(F1, D)),
    ok = zstd:reset(C),
    F2 = bin(zstd:compress(Data, C)),
    {ok, NewC} = zstd:dict(compress, Dict, #{compressionLevel => 19}),
    ok = zstd:set_parameter(C, dictionary, NewC),
    erlang:garbage_collect(),
    F3 = bin(zstd:compress(Data, C)),
    ok = zstd:set_parameter(C, dictionary, Dict),
    erlang:garbage_collect(),
    F4 = bin(zstd:compress(Data, C)),
    {ok, NewD} = zstd:dict(decompress, Dict),
    ok = zstd:set_parameter(D, dictionary, NewD),
    erlang:garbage_collect(),
    B3 = bin(zstd:decompress(F3, D)),
    ok = zstd:set_parameter(D, dictionary, Dict),
    erlang:garbage_collect(),
    B4 = bin(zstd:decompress(F4, D)),
    Shared = [zstd:get_dict_id(F) || F <- [F1, F2, F3, F4]],
    ok = zstd:close(C),
    ok = zstd:close(D),
    erlang:garbage_collect(),
    After = [attempt(fun() -> zstd:compress(Data, C) end), attempt(fun() -> zstd:decompress(F1, D) end),
             attempt(fun() -> zstd:set_parameter(C, dictionary, NewC) end), attempt(fun() -> zstd:close(D) end)],
    NewBack = bin(zstd:decompress(F3, #{dictionary => NewD})),
    io:format("~w~n~w~n~w~n~w~n~w~n",
              [[{byte_size(F), erlang:md5(F)} || F <- [F1, F2, F3, F4]], [X =:= Data || X <- [B1, B3, B4, NewBack]],
               Shared, After, length(Churn)]).
"#;

/// Runs `zstd_dict_probe:Function(DictFile)` on erl and on Arinsal and returns both outputs.
fn both_dict(function: &str) -> Option<(Run, Run)> {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping zstd differential test");
        return None;
    };
    let beam = reference
        .compile_named(DICT_MODULE, DICT_SOURCE, &[])
        .expect("compile zstd dictionary probe");
    drop(reference);
    let dir = std::env::temp_dir().join(format!(
        "arinsal-zstd-dict-{}-{function}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join(format!("{DICT_MODULE}.beam")), &beam).expect("write beam");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zstd_dict");
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let eval = format!(
        "{DICT_MODULE}:{function}(\"{}\"), halt().",
        fixture.to_str().expect("utf-8 path")
    );
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

/// Compares the dictionary probe `function` on erl and on Arinsal; `needles` must appear in the
/// reference output, which proves the probe reached the behavior it names.
fn dict_probe_matches_erl(function: &str, needles: &[&str]) {
    let Some((expected, actual)) = both_dict(function) else {
        return;
    };
    assert!(expected.0, "erl failed: {}\n{}", expected.2, expected.1);
    for needle in needles {
        assert!(
            expected.1.contains(needle),
            "erl output lacks {needle}: {}",
            expected.1
        );
    }
    assert!(actual.0, "arinsal failed: {}\n{}", actual.2, actual.1);
    similar_asserts::assert_eq!(actual.1, expected.1, "stderr {}", actual.2);
}

/// A dictionary by reference (`zstd:dict/2,3`) or by load (a binary, an iolist or an unaligned
/// binary), used to compress and to decompress, in every combination.
#[test]
fn dictionary_by_ref_and_by_load_match_erl() {
    dict_probe_matches_erl("roundtrip", &["true,true,true,true,true,true]"]);
}

/// The dictionary id from a compress dictionary, a decompress dictionary, a dictionary binary or
/// iolist and a frame, and the errors for anything else.
#[test]
fn dictionary_ids_match_erl() {
    dict_probe_matches_erl("ids", &["{ok,", "{error,badarg}"]);
}

/// `ref_*` and `load_*` argument order, replacement, a load refused mid-stream and the type
/// checks between the two dictionary resource types.
#[test]
fn dictionary_load_and_ref_match_erl() {
    dict_probe_matches_erl("load_ref", &["{error,badarg}", "Operation not authorized"]);
}

/// `get_frame_header/1` on a full frame, a truncated header, garbage and non-iolists.
#[test]
fn frame_header_matches_erl() {
    dict_probe_matches_erl(
        "frames",
        &[
            "frameContentSize",
            "Unknown frame descriptor",
            "ZSTD_skippableFrame",
        ],
    );
}

/// The dictionary mismatch error and the argument errors of the dictionary NIFs.
#[test]
fn dictionary_errors_match_erl() {
    dict_probe_matches_erl(
        "errors",
        &["Dictionary mismatch", "not_on_controlling_process"],
    );
}

/// A dictionary referenced by a context outlives every other reference to it and is released by
/// replacement, close and garbage collection.
#[test]
fn dictionary_lifecycle_matches_erl() {
    dict_probe_matches_erl("lifecycle", &["true,true,true,true", "badarg"]);
}

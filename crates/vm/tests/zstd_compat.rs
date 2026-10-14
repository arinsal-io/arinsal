//! The `zstd` module (`lib/stdlib/src/zstd.erl`) loads its built-in NIF library and behaves like
//! erl 29.1.1 (`erts/emulator/nifs/common/zstd_nif.c`).

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use arinsal_difftest::RefErl;

const MODULE: &str = "zstd_compat_probe";

const SOURCE: &str = r#"
-module(zstd_compat_probe).
-export([oneshot/0, lifecycle/0, streams/0, corrupt/0, raw/0, reductions/0]).

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

data(N) ->
    _ = rand:seed(exsss, {1, 2, 3}),
    Half = N div 2,
    Text = binary:part(iolist_to_binary(lists:duplicate(N div 40 + 1, <<"the quick brown fox jumps over the lazy dog ">>)), 0, Half),
    iolist_to_binary([Text, rand:bytes(N - Half)]).

random(N) ->
    _ = rand:seed(exsss, {4, 5, 6}),
    rand:bytes(N).

sum(Bin) when is_binary(Bin) -> {byte_size(Bin), erlang:md5(Bin)}.

shape({continue, Out}) -> {continue, sum(Out)};
shape({continue, Rem, Out}) -> {continue, byte_size(Rem), binary:referenced_byte_size(Rem), sum(Rem), sum(Out)};
shape({done, Out}) -> {done, sum(Out)};
shape({flush, Out}) -> {flush, sum(Out)};
shape(Other) -> Other.

att(Fun) ->
    try shape(Fun()) catch Class:Reason -> {Class, Reason} end.

pieces(Data, Size) when byte_size(Data) =< Size -> [Data];
pieces(Data, Size) ->
    <<Head:Size/binary, Tail/binary>> = Data,
    [Head | pieces(Tail, Size)].

with_empty(Pieces) -> [<<>>] ++ lists:flatmap(fun(P) -> [P, <<>>] end, Pieces).

stream_all(Ctx, Data) ->
    case zstd:stream(Ctx, Data) of
        {continue, Rem, Out} = R ->
            {Shapes, Outs} = stream_all(Ctx, Rem),
            {[shape(R) | Shapes], [Out | Outs]};
        {continue, Out} = R ->
            {[shape(R)], [Out]}
    end.

feed(Ctx, Chunks) ->
    {Shapes, Outs} = lists:foldl(
        fun(Chunk, {ShapesAcc, OutsAcc}) ->
            {S, O} = stream_all(Ctx, Chunk),
            {lists:reverse(S, ShapesAcc), lists:reverse(O, OutsAcc)}
        end, {[], []}, Chunks),
    {lists:reverse(Shapes), lists:reverse(Outs)}.

compress_run(Data, Chunks) ->
    {ok, Ctx} = zstd:context(compress),
    {Shapes, Outs} = feed(Ctx, Chunks),
    Flushed = zstd:flush(Ctx),
    {done, Tail} = zstd:finish(Ctx, <<>>),
    TailBins = lists:flatten([Tail]),
    Compressed = iolist_to_binary(Outs ++ [element(2, Flushed)] ++ TailBins),
    ok = zstd:close(Ctx),
    Back = iolist_to_binary(zstd:decompress(Compressed)),
    {Shapes, shape(Flushed), [byte_size(B) || B <- TailBins], sum(Compressed), Back =:= Data}.

decompress_run(_Compressed, Chunks) ->
    {ok, Ctx} = zstd:context(decompress),
    {Shapes, Outs} = feed(Ctx, Chunks),
    {done, Tail} = zstd:finish(Ctx, <<>>),
    TailBins = lists:flatten([Tail]),
    ok = zstd:close(Ctx),
    {Shapes, [byte_size(B) || B <- TailBins], sum(iolist_to_binary(Outs ++ TailBins))}.

digest(Term) -> erlang:md5(term_to_binary(Term)).

streams() ->
    Sizes = [0, 1, 100, 1000, 70000, 300000],
    lists:foreach(
        fun(Size) ->
            Data = data(Size),
            Rand = random(Size),
            lists:foreach(
                fun(D) ->
                    Full = [compress_run(D, P) || P <- [[D], with_empty([D]), pieces(D, 65536)]],
                    Hashed = [digest(compress_run(D, P)) || P <- [pieces(D, 1000), with_empty(pieces(D, 1000))]],
                    io:format("c ~w ~w ~w~n", [Size, Full, Hashed])
                end, [Data, Rand]),
            Compressed = iolist_to_binary(zstd:compress(Data, #{compressionLevel => 3})),
            DFull = [decompress_run(Compressed, pieces(Compressed, N)) || N <- [1000, 131072, 1 bsl 30]],
            DHashed = [digest(decompress_run(Compressed, pieces(Compressed, N))) || N <- [1, 7, 997], Size =< 1000 orelse N >= 997],
            DEmpties = [decompress_run(Compressed, with_empty(pieces(Compressed, N))) || N <- [1 bsl 30]],
            io:format("d ~w ~w ~w ~w~n", [Size, DFull, DHashed, DEmpties])
        end, Sizes).

corrupt() ->
    Good = iolist_to_binary(zstd:compress(data(1000))),
    Flip = fun(Pos) ->
        <<Head:Pos/binary, B, Tail/binary>> = Good,
        <<Head/binary, (B bxor 255), Tail/binary>>
    end,
    Last = byte_size(Good) - 1,
    Flipped = [{Pos, att(fun() -> sum(iolist_to_binary(zstd:decompress(Flip(Pos)))) end)}
               || Pos <- [0, 3, 4, 5, 6, 8, 10, 100, 500, Last]],
    Truncated = [{N, att(fun() -> sum(iolist_to_binary(zstd:decompress(binary:part(Good, 0, N)))) end)}
                 || N <- [0, 1, 4, 5, 6, 20, Last]],
    Garbage = [att(fun() -> zstd:decompress(G) end) || G <- [<<1, 2, 3, 4, 5, 6, 7, 8>>, <<"not zstd at all">>]],
    StreamFlipped = [begin
        {ok, Ctx} = zstd:context(decompress),
        R = att(fun() -> {done, Out} = zstd:finish(Ctx, Flip(Pos)), sum(iolist_to_binary(Out)) end),
        Again = att(fun() -> sum(iolist_to_binary(zstd:decompress(Good, Ctx))) end),
        {Pos, R, Again}
    end || Pos <- [0, 5, 6, 100, 500, Last]],
    Reuse = begin
        {ok, DCtx} = zstd:context(decompress),
        First = att(fun() -> zstd:decompress(Flip(100), DCtx) end),
        Second = att(fun() -> sum(iolist_to_binary(zstd:decompress(Good, DCtx))) end),
        {First, Second}
    end,
    io:format("~w~n~w~n~w~n~w~n~w~n", [Flipped, Truncated, Garbage, StreamFlipped, Reuse]).

raw() ->
    Data = data(300000),
    Rand = random(300000),
    Small = data(100),
    Compress = fun(Fun) -> R = zstd:nif_init_compress(), X = att(fun() -> Fun(R) end), ok = zstd:nif_compress_close(R), X end,
    Decompress = fun(Fun) -> R = zstd:nif_init_decompress(), X = att(fun() -> Fun(R) end), ok = zstd:nif_decompress_close(R), X end,
    EndOps = [0, 1, 2, 3, 5, -1, 16#7fffffff, 1 bsl 31, 1 bsl 40, true, false, ok, 1.5, <<2>>, "2", {2}],
    CompressOps = [{Op, [Compress(fun(R) -> zstd:nif_compress_stream(R, D, Op) end) || D <- [<<>>, Small, Data, Rand]]} || Op <- EndOps],
    BadData = [Compress(fun(R) -> zstd:nif_compress_stream(R, D, 0) end) || D <- ["abc", abc, <<1:3>>, <<1, 2, 3, 4:4>>, {1}, [<<1>>], 7]],
    Mid = binary:part(Data, 5, 200000),
    Offsets = [{aligned_sub, Mid}, {unaligned, unaligned(Mid)}, {unaligned_rand, unaligned(Rand)}],
    Unaligned = [{Name, Compress(fun(R) -> loop_compress(R, B, 2) end)} || {Name, B} <- Offsets]
        ++ [{Name, Compress(fun(R) -> loop_compress(R, B, 0) end)} || {Name, B} <- Offsets],
    Frame = iolist_to_binary(zstd:compress(Data)),
    SmallFrame = iolist_to_binary(zstd:compress(Small)),
    EmptyFrame = iolist_to_binary(zstd:compress(<<>>)),
    Unknown = begin
        {ok, C} = zstd:context(compress),
        {continue, A} = zstd:stream(C, Data),
        {done, B} = zstd:finish(C, <<>>),
        iolist_to_binary([A, B])
    end,
    DecompressOps = [{Op, [Decompress(fun(R) -> zstd:nif_decompress_stream(R, F, Op) end) || F <- [<<>>, Frame, SmallFrame, EmptyFrame, Unknown, binary:part(Frame, 0, 30)]]}
                     || Op <- [0, 1, 2, 5, true, false, ok, 1.5]],
    DecompressBad = [Decompress(fun(R) -> zstd:nif_decompress_stream(R, D, 0) end) || D <- ["abc", abc, <<1:3>>, {1}, [<<1>>]]],
    DecompressLoop = [{Name, Decompress(fun(R) -> loop_decompress(R, F, 2) end)}
                      || {Name, F} <- [{frame, Frame}, {small, SmallFrame}, {unknown, Unknown}, {unaligned, unaligned(Frame)}, {sub, binary:part(Frame, 0, byte_size(Frame))}]],
    Special = begin
        D1 = zstd:nif_init_decompress(),
        S1 = [att(fun() -> zstd:nif_decompress_stream(D1, <<>>, true) end) || _ <- [1, 2]],
        S2 = att(fun() -> zstd:nif_decompress_stream(D1, <<>>, false) end),
        S3 = att(fun() -> zstd:nif_decompress_stream(D1, <<>>, true) end),
        S4 = att(fun() -> zstd:nif_decompress_stream(D1, binary:part(Frame, 0, 30), 0) end),
        S5 = att(fun() -> zstd:nif_decompress_stream(D1, <<>>, true) end),
        S6 = att(fun() -> zstd:nif_decompress_stream(D1, <<>>, foo) end),
        S7 = att(fun() -> zstd:nif_decompress_stream(D1, <<>>, true) end),
        S8 = att(fun() -> zstd:nif_decompress_stream(D1, Frame, 2) end),
        {S1, S2, S3, S4, S5, S6, S7, S8}
    end,
    PledgeReset = begin
        C1 = zstd:nif_init_compress(),
        ok = zstd:nif_set_pledged(C1, 5),
        P1 = att(fun() -> zstd:nif_compress_stream(C1, <<"abcdefghij">>, foo) end),
        P2 = att(fun() -> zstd:nif_compress_stream(C1, <<"abcdefghij">>, 2) end),
        ok = zstd:nif_set_pledged(C1, 5),
        P3 = att(fun() -> zstd:nif_compress_stream(C1, <<"abcdefghij">>, 0) end),
        P4 = att(fun() -> zstd:nif_compress_stream(C1, <<>>, 2) end),
        P5 = att(fun() -> zstd:nif_compress_stream(C1, <<"abcdefghij">>, 2) end),
        {P1, P2, P3, P4, P5}
    end,
    io:format("~w~n~w~n~w~n~w~n~w~n~w~n~w~n~w~n", [CompressOps, BadData, Unaligned, DecompressOps, DecompressBad, DecompressLoop, Special, PledgeReset]).

unaligned(Bin) ->
    Size = byte_size(Bin),
    <<_:3, B:Size/binary, _:5>> = <<7:3, Bin/binary, 0:5>>,
    B.

loop_compress(R, Data, Op) ->
    loop_compress(R, Data, Op, [], []).

loop_compress(R, Data, Op, Shapes, Outs) ->
    case zstd:nif_compress_stream(R, Data, Op) of
        {continue, Rem, Out} = Res ->
            loop_compress(R, Rem, Op, [shape(Res) | Shapes], [Out | Outs]);
        {continue, Out} = Res when Op =:= 0 ->
            {done, Tail} = zstd:finish({compress, R}, <<>>),
            TailBins = lists:flatten([Tail]),
            finished([shape(Res) | Shapes], lists:reverse(TailBins) ++ [Out | Outs]);
        {flush, Out} = Res ->
            loop_compress(R, <<>>, Op, [shape(Res) | Shapes], [Out | Outs]);
        {_, Out} = Res ->
            finished([shape(Res) | Shapes], [Out | Outs])
    end.

finished(Shapes, Outs) ->
    {lists:reverse(Shapes), sum(iolist_to_binary(lists:reverse(Outs)))}.

loop_decompress(R, Data, Op) ->
    loop_decompress(R, Data, Op, [], []).

loop_decompress(R, Data, Op, Shapes, Outs) ->
    case zstd:nif_decompress_stream(R, Data, Op) of
        {continue, Rem, Out} = Res ->
            loop_decompress(R, Rem, Op, [shape(Res) | Shapes], [Out | Outs]);
        {flush, Out} = Res ->
            loop_decompress(R, <<>>, Op, [shape(Res) | Shapes], [Out | Outs]);
        {_, Out} = Res ->
            finished([shape(Res) | Shapes], [Out | Outs])
    end.

reductions() ->
    Data = random(1 bsl 20),
    Sizes = [0, 1000, 5000, 20000, 50000, 120000, 200000, 1 bsl 20],
    Deltas = [begin
        {ok, {compress, Ref}} = zstd:context(compress),
        Chunk = binary:part(Data, 0, Size),
        {reductions, Before} = process_info(self(), reductions),
        Res = zstd:nif_compress_stream(Ref, Chunk, 0),
        {reductions, After} = process_info(self(), reductions),
        {Size, element(1, Res), After - Before}
    end || Size <- Sizes],
    {_, _, Base} = hd(Deltas),
    Rows = [{Size, Tag, case Size =< 50000 of true -> Delta - Base; false -> (Delta - Base) div 500 end} || {Size, Tag, Delta} <- Deltas],
    io:format("~w~n", [Rows]).

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

/// Local wrappers appended to `zstd.erl`: the NIF stubs are local functions of the module, and a
/// call from another module to one is not the call `zstd.erl` itself makes.
const NIF_WRAPPERS: &str = r#"
nif_init_compress() -> init_compress_nif().
nif_init_decompress() -> init_decompress_nif().
nif_compress_stream(R, D, E) -> compress_stream_nif(R, D, E).
nif_decompress_stream(R, D, E) -> decompress_stream_nif(R, D, E).
nif_compress_close(R) -> compress_close_nif(R).
nif_decompress_close(R) -> decompress_close_nif(R).
nif_set_pledged(R, N) -> set_pledged_src_size_nif(R, N).
"#;

/// The `zstd` module of the reference OTP with every function exported, so a probe can call the
/// NIFs (`zstd:compress_stream_nif/3`, ...) directly with arguments `zstd.erl` never passes.
fn zstd_with_nifs_exported(reference: &RefErl) -> Vec<u8> {
    let root = arinsal_difftest::reference::otp_root().expect("OTP root");
    let stdlib = std::fs::read_dir(root.join("lib"))
        .expect("OTP lib dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("stdlib-"))
        })
        .expect("stdlib directory");
    let source = std::fs::read_to_string(stdlib.join("src/zstd.erl"))
        .expect("zstd.erl source")
        .lines()
        .filter(|line| !line.starts_with("-define("))
        .collect::<Vec<_>>()
        .join("\n")
        .replace("?ZSTD_e_continue", "0")
        .replace("?ZSTD_e_flush", "1")
        .replace("?ZSTD_e_end", "2");
    let source = format!("{source}\n{NIF_WRAPPERS}");
    reference
        .compile_named(
            "zstd",
            &source,
            &[
                arinsal_etf::OwnedTerm::atom("export_all"),
                arinsal_etf::OwnedTerm::atom("nowarn_export_all"),
            ],
        )
        .expect("compile zstd")
}

/// Runs `Module:Function()` on erl and on Arinsal and returns both outputs.
fn both(function: &str) -> Option<(Run, Run)> {
    both_with(function, false)
}

/// Like [`both`]; with `nifs` the probe runs against [`zstd_with_nifs_exported`].
fn both_with(function: &str, nifs: bool) -> Option<(Run, Run)> {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping zstd differential test");
        return None;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile zstd probe");
    let exported = nifs.then(|| zstd_with_nifs_exported(&reference));
    drop(reference);
    let dir = std::env::temp_dir().join(format!(
        "arinsal-zstd-compat-{}-{function}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    if let Some(beam) = exported {
        std::fs::write(dir.join("zstd.beam"), &beam).expect("write zstd beam");
    }
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

fn assert_same(function: &str, nifs: bool, needles: &[&str]) {
    let Some((expected, actual)) = both_with(function, nifs) else {
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

/// Streaming compress and decompress through `zstd:stream/2`, `flush/1` and `finish/2` with
/// chunks of several sizes, empty chunks and inputs larger than the internal output buffer:
/// the returned tags, the remainder sub-binaries (including the size of the binary they
/// reference) and every output byte match erl.
#[test]
fn streaming_chunks_match_erl() {
    assert_same("streams", false, &["c 300000", "d 300000", "continue"]);
}

/// A corrupted, truncated or garbage frame raises the same error term as erl, and the context
/// is usable again afterwards.
#[test]
fn corrupted_frames_match_erl() {
    assert_same("corrupt", false, &["zstd_error"]);
}

/// The stream NIFs called directly: every end op, bad end ops and bad data, sub-binary and
/// unaligned inputs with their remainders, the `true` shortcut, and the session reset after an
/// exception.
#[test]
fn stream_nifs_match_erl() {
    assert_same("raw", true, &["zstd_error", "badarg", "unaligned"]);
}

/// `enif_consume_timeslice` after each stream NIF call: the reductions a call charges grow with
/// the bytes it consumed, `min(100, max(1, consumed / 1024))` percent of a time slice, 40
/// reductions per percent.
#[test]
fn stream_reductions_match_erl() {
    assert_same("reductions", true, &["{5000,continue,"]);
}

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_max_heap_diff).
-export([run/0]).

run() -> [
    probe(Name, Fun, Wrap)
 || {Name, Fun} <- cases(), Wrap <- [plain, save_calls, catch_save_calls]
].

cases() -> [
    {build_and_bif, fun build_and_bif/0},
    {build_bin_and_bif, fun build_bin_and_bif/0},
    {build_bin_on_heap_known_size, fun build_bin_on_heap_known_size/0},
    {build_bin_on_heap_unknown_small_size, fun build_bin_on_heap_unknown_small_size/0},
    {build_bin_on_heap_unknown_size, fun build_bin_on_heap_unknown_size/0},
    {build_bin_append_known_binary, fun build_bin_append_known_binary/0},
    {build_bin_append_unknown_binary, fun build_bin_append_unknown_binary/0},
    {build_bin_append_unknown_binary_guard, fun build_bin_append_unknown_binary_guard/0},
    {build_bin_append_writable_binary_extra, fun build_bin_append_writable_binary_extra/0},
    {build_bin_append_unknown_binary_extra, fun build_bin_append_unknown_binary_extra/0},
    {build_and_recv_timeout, fun build_and_recv_timeout/0},
    {build_and_recv_msg, fun build_and_recv_msg/0},
    {bif_and_recv_timeout, fun bif_and_recv_timeout/0},
    {bif_and_recv_msg, fun bif_and_recv_msg/0},
    {bs_match_integer_known_size, fun bs_match_integer_known_size/0},
    {bs_match_integer_unknown_size, fun bs_match_integer_unknown_size/0}
].

probe(Name, Fun, Wrap) ->
    SpawnFun = case Wrap of
        plain -> Fun;
        save_calls -> fun() -> process_flag(save_calls, 10), Fun() end;
        catch_save_calls -> fun() -> process_flag(save_calls, 10), catch Fun() end
    end,
    {Pid, Ref} = spawn_opt(SpawnFun, [monitor,
        {max_heap_size, #{size => 233, kill => true, error_logger => false}}]),
    receive {'DOWN', Ref, process, Pid, Reason} -> {Name, Wrap, Reason}
    after 5000 -> timeout
    end.

build_and_bif() -> build_and_bif(1000, []).
build_and_bif(0, Acc) -> Acc;
build_and_bif(N, Acc0) ->
    Acc = [0 | Acc0],
    _ = erlang:crc32(Acc),
    build_and_bif(N - 1, Acc).

build_bin_and_bif() -> build_bin_and_bif(1000, <<>>).
build_bin_and_bif(0, Acc) -> Acc;
build_bin_and_bif(N, Acc0) ->
    Acc = <<0, Acc0/binary>>,
    _ = erlang:crc32(Acc),
    build_bin_and_bif(N - 1, Acc).

build_bin_on_heap_known_size() ->
    Data = id(1),
    A = erlang:make_tuple(233 - 3 * 8, a),
    B = <<Data:64/unit:8>>,
    C = <<Data:64/unit:8>>,
    D = <<Data:64/unit:8>>,
    E = <<Data:64/unit:8>>,
    exit({A, B, C, D, E}).

build_bin_on_heap_unknown_small_size() ->
    Size = id(64),
    true = is_integer(Size) andalso Size =< 64,
    A = erlang:make_tuple(233 - 3 * 8, a),
    B = <<0:Size/unit:8>>,
    C = <<0:Size/unit:8>>,
    D = <<0:Size/unit:8>>,
    E = <<0:Size/unit:8>>,
    exit({A, B, C, D, E}).

build_bin_on_heap_unknown_size() ->
    Size = id(64),
    A = erlang:make_tuple(233 - 3 * 8, a),
    B = <<0:Size/unit:8>>,
    C = <<0:Size/unit:8>>,
    D = <<0:Size/unit:8>>,
    E = <<0:Size/unit:8>>,
    exit({A, B, C, D, E}).

build_bin_append_known_binary() ->
    A = erlang:make_tuple(233 - 3 * 8, a),
    Bin = id(<<>>),
    true = is_binary(Bin),
    B = <<Bin/binary, "abc">>,
    C = <<B/binary, "abc">>,
    D = <<C/binary, "abc">>,
    E = <<D/binary, "abc">>,
    exit({A, B, C, D, E}).

build_bin_append_unknown_binary() ->
    A = erlang:make_tuple(233 - 3 * 8, a),
    Bin = id(<<>>),
    B = <<Bin/binary, "abc">>,
    C = <<(id(B))/binary, "abc">>,
    D = <<(id(C))/binary, "abc">>,
    E = <<(id(D))/binary, "abc">>,
    exit({A, B, C, D, E}).

build_bin_append_unknown_binary_guard() ->
    A = erlang:make_tuple(233 - 3 * 8, a),
    Bin = id(<<>>),
    if
        byte_size(<<Bin/binary, "abc">>) =:= 0 -> ok;
        byte_size(<<Bin/binary, "abc">>) =:= 0 -> ok;
        byte_size(<<Bin/binary, "abc">>) =:= 0 -> ok;
        byte_size(<<Bin/binary, "abc">>) =:= 0 -> ok;
        true -> exit(A)
    end.

build_bin_append_writable_binary_extra() ->
    A = erlang:make_tuple(233 - 3 * 8, a),
    Bin = id(<<>>),
    Size = id(0),
    B = <<Bin/binary, 1:8>>,
    C = <<B/binary, 0:Size>>,
    exit({A, B, C, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}).

build_bin_append_unknown_binary_extra() ->
    A = erlang:make_tuple(233 - 3 * 8, a),
    Bin = id(<<>>),
    B = <<Bin/binary, 0:0>>,
    exit({A, B, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}).

build_and_recv_timeout() -> build_and_recv_timeout(1000, []).
build_and_recv_timeout(0, Acc0) -> Acc0;
build_and_recv_timeout(N, Acc0) ->
    Acc = [0 | Acc0],
    receive after 1 -> ok end,
    build_and_recv_timeout(N - 1, Acc).

build_and_recv_msg() -> build_and_recv_msg(1000, []).
build_and_recv_msg(0, Acc0) -> Acc0;
build_and_recv_msg(N, Acc0) ->
    Acc = [0 | Acc0],
    receive _ -> ok after 0 -> ok end,
    build_and_recv_msg(N - 1, Acc).

bif_and_recv_timeout() ->
    Bin = <<0:1000/unit:8>>,
    List = binary_to_list(Bin),
    receive after 1 -> ok end,
    List.

bif_and_recv_msg() ->
    Bin = <<0:1000/unit:8>>,
    List = binary_to_list(Bin),
    receive _ -> ok after 0 -> ok end,
    List.

bs_match_integer_known_size() ->
    Size = 233 * 8,
    Bin = id(<<255:Size/little-unit:8>>),
    <<N:Size/big-unit:8>> = Bin,
    exit(N).

bs_match_integer_unknown_size() ->
    Size = id(233 * 8),
    Bin = id(<<255:Size/little-unit:8>>),
    <<N:Size/big-unit:8>> = Bin,
    exit(N).

id(Value) -> Value.
"#;

#[test]
fn max_heap_kill_is_immediate_across_exit_paths() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping max heap differential");
        return;
    };
    let beam = reference
        .compile_named("proc_max_heap_diff", SOURCE, &[])
        .expect("compile max heap differential");
    reference
        .load("proc_max_heap_diff", &beam)
        .expect("load max heap differential");
    let expected = reference.call("proc_max_heap_diff", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load max heap differential");
    let actual = vm
        .eval_scheduled("proc_max_heap_diff", "run", &[], 2, None)
        .expect("run max heap differential")
        .term;

    let names = [
        "build_and_bif",
        "build_bin_and_bif",
        "build_bin_on_heap_known_size",
        "build_bin_on_heap_unknown_small_size",
        "build_bin_on_heap_unknown_size",
        "build_bin_append_known_binary",
        "build_bin_append_unknown_binary",
        "build_bin_append_unknown_binary_guard",
        "build_bin_append_writable_binary_extra",
        "build_bin_append_unknown_binary_extra",
        "build_and_recv_timeout",
        "build_and_recv_msg",
        "bif_and_recv_timeout",
        "bif_and_recv_msg",
        "bs_match_integer_known_size",
        "bs_match_integer_unknown_size",
    ];
    let expected_reasons = OwnedTerm::List {
        elems: names
            .into_iter()
            .flat_map(|name| {
                ["plain", "save_calls", "catch_save_calls"].map(|wrapper| {
                    OwnedTerm::Tuple(vec![
                        OwnedTerm::atom(name),
                        OwnedTerm::atom(wrapper),
                        OwnedTerm::atom("killed"),
                    ])
                })
            })
            .collect(),
        tail: Box::new(OwnedTerm::Nil),
    };
    let expected_arin = expected_reasons.clone();
    similar_asserts::assert_eq!(expected, CallResult::Ok(expected_reasons), "erts max heap");
    let actual_owned = actual;
    if actual_owned != expected_arin {
        eprintln!("Arinsal max heap outcomes: {actual_owned:#?}");
    }
    similar_asserts::assert_eq!(expected_arin, actual_owned, "Arinsal max heap");
}

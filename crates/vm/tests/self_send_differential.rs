use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const MODULE: &str = "self_send_probe";
const SOURCE: &str = r#"
-module(self_send_probe).
-export([run/1, worker/2]).

literal() -> [{literal, 1, 2, 3, 4, 5, 6, 7, 8}, <<"literal binary kept in the literal area">>, #{1 => a, 2 => b}].

run(Kind) ->
    Parent = self(),
    Pid = spawn(fun() -> worker(Parent, Kind) end),
    receive {result, Pid, Result} -> Result end.

worker(Parent, Kind) ->
    {_, Before} = lists:keyfind(minor_gcs, 1, element(2, process_info(self(), garbage_collection))),
    Value = workload(Kind),
    {_, After} = lists:keyfind(minor_gcs, 1, element(2, process_info(self(), garbage_collection))),
    Info = case Kind of
        K when K =:= 6; K =:= 7 -> process_info(self(), [message_queue_len, message_queue_data]);
        _ -> {After - Before, process_info(self(), [heap_size, total_heap_size, message_queue_len, message_queue_data])}
    end,
    Parent ! {result, self(), {Value, Info}}.

workload(0) -> loop_immediate(100000, 0);
workload(1) -> loop_tuple(50000, 0);
workload(2) -> loop_list(300, lists:seq(1, 1000), 0);
workload(3) -> loop_literal(20000, 0);
workload(4) -> loop_binary(200, binary:copy(<<1>>, 100000), 0);
workload(5) -> queue_then_collect(500);
workload(6) ->
    process_flag(message_queue_data, off_heap),
    loop_tuple(20000, 0);
workload(7) ->
    seq_trace:set_token(send, true),
    Value = loop_tuple(2000, 0),
    seq_trace:reset_trace(),
    Value;
workload(8) -> loop_map_and_fun(2000, 0);
workload(9) ->
    self() ! {a, [1, 2, 3]},
    self() ! {b, {c, d}},
    self() ! literal(),
    {process_info(self(), [message_queue_len, messages]), flush()};
workload(10) -> selective(200, []).

loop_immediate(0, Sum) -> Sum;
loop_immediate(N, Sum) ->
    self() ! N,
    receive M -> loop_immediate(N - 1, Sum + M) end.

loop_tuple(0, Sum) -> Sum;
loop_tuple(N, Sum) ->
    self() ! {self(), N},
    receive {_, M} -> loop_tuple(N - 1, Sum + M) end.

loop_list(0, _List, Sum) -> Sum;
loop_list(N, List, Sum) ->
    self() ! {N, List},
    receive {N, Received} when Received =:= List -> loop_list(N - 1, List, Sum + length(Received)) end.

loop_literal(0, Sum) -> Sum;
loop_literal(N, Sum) ->
    self() ! {literal(), {N}, literal()},
    receive {Lit, {M}, Lit} -> Lit = literal(), loop_literal(N - 1, Sum + M) end.

loop_binary(0, _Bin, Sum) -> Sum;
loop_binary(N, Bin, Sum) ->
    self() ! {bin, Bin, binary:part(Bin, 10, 20)},
    receive {bin, Whole, Part} when Whole =:= Bin ->
        Part = binary:part(Bin, 10, 20),
        loop_binary(N - 1, Bin, Sum + byte_size(Whole) + byte_size(Part))
    end.

queue_then_collect(Count) ->
    [self() ! {I, lists:seq(1, 50), {I}} || I <- lists:seq(1, Count)],
    Length = element(2, process_info(self(), message_queue_len)),
    erlang:garbage_collect(),
    [self() ! {late, I} || I <- lists:seq(1, 20)],
    erlang:garbage_collect(self(), [{type, major}]),
    Sum = drain(Count, 0),
    Late = [receive {late, I} -> I end || I <- lists:seq(1, 20)],
    {Length, Sum, Late}.

drain(0, Sum) -> Sum;
drain(N, Sum) ->
    I = receive {I0, List, {I0}} when length(List) =:= 50 -> I0 end,
    drain(N - 1, Sum + I).

loop_map_and_fun(0, Sum) -> Sum;
loop_map_and_fun(N, Sum) ->
    Map = maps:from_list([{K, N + K} || K <- lists:seq(1, 40)]),
    Fun = fun(X) -> X + N end,
    self() ! {Map, Fun},
    receive {Received, F} when map_size(Received) =:= 40 -> loop_map_and_fun(N - 1, Sum + F(maps:get(40, Received))) end.

selective(0, Acc) -> lists:sum(Acc);
selective(N, Acc) ->
    self() ! {first, N},
    self() ! {second, [N, N]},
    receive {second, [X, X]} -> ok end,
    receive {first, Y} -> selective(N - 1, [X + Y | Acc]) end.

flush() ->
    receive M -> [M | flush()] after 0 -> [] end.
"#;

const KINDS: [(i64, &str); 11] = [
    (0, "immediate"),
    (1, "small tuple"),
    (2, "large list"),
    (3, "literal-containing"),
    (4, "refc binary"),
    (5, "queued across collections"),
    (6, "off-heap queue"),
    (7, "seq trace token"),
    (8, "map and fun"),
    (9, "process_info messages"),
    (10, "selective receive"),
];

#[test]
fn self_send_matches_otp() {
    let reference = RefErl::start().expect("start OTP 29.1.1");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile self send probe");
    reference.load(MODULE, &beam).expect("load self send probe");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load probe into Arinsal");

    for (kind, name) in KINDS {
        let expected = match reference.call(MODULE, "run", &[OwnedTerm::Int(kind)]) {
            CallResult::Ok(term) => term,
            other => panic!("OTP {name} failed: {other:?}"),
        };
        let outcome = vm
            .eval_scheduled(
                MODULE,
                "run",
                &[Term::small(kind).expect("workload id")],
                1,
                None,
            )
            .unwrap_or_else(|error| panic!("Arinsal {name} failed: {error:?}"));
        similar_asserts::assert_eq!(expected, outcome.term, "self send {name}");
    }
}

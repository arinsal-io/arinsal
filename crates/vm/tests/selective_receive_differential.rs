use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(selective_receive_diff).
-export([scenario/2]).

payload(I, Size) -> {I, lists:seq(1, Size), list_to_binary(lists:duplicate(Size, I rem 256))}.

fill(Fun) ->
    {Pid, Ref} = spawn_monitor(fun() -> Fun(), exit(normal) end),
    receive {'DOWN', Ref, process, Pid, _} -> ok end.

sum({I, List, Binary}) -> I + lists:sum(List) + byte_size(Binary) + binary:first(Binary).

drain(Acc) ->
    receive {m, I, Payload} -> drain([{I, sum(Payload)} | Acc])
    after 0 -> lists:reverse(Acc)
    end.

scenario(0, Size) ->
    Self = self(),
    fill(fun() -> [Self ! {m, I, payload(I, Size)} || I <- lists:seq(1, 40)] end),
    drain([]);
scenario(1, Size) ->
    Self = self(),
    fill(fun() ->
                 Self ! {a, payload(1, Size)}, Self ! {b, payload(2, Size)},
                 Self ! {c, payload(3, Size)}, Self ! {d, payload(4, Size)},
                 Self ! {e, payload(5, Size)}
         end),
    C = receive {c, P3} -> sum(P3) end,
    A = receive {a, P1} -> sum(P1) end,
    E = receive {e, P5} -> sum(P5) end,
    Len = process_info(self(), message_queue_len),
    B = receive {b, P2} -> sum(P2) end,
    D = receive {d, P4} -> sum(P4) end,
    {C, A, E, Len, B, D, process_info(self(), message_queue_len)};
scenario(2, Size) ->
    Self = self(),
    fill(fun() -> [Self ! {old, I, payload(I, Size)} || I <- lists:seq(1, 6)] end),
    Ref = make_ref(),
    Echo = spawn_link(fun() -> receive {From, R} -> From ! {R, payload(99, Size)} end end),
    Echo ! {Self, Ref},
    Answer = receive {Ref, P} -> sum(P) end,
    Len1 = process_info(self(), message_queue_len),
    Fill = fill(fun() -> Self ! {old, 7, payload(7, Size)} end),
    First = receive {old, I1, P1} -> {I1, sum(P1)} end,
    Rest = [receive {old, I, Pi} -> {I, sum(Pi)} end || I <- lists:seq(2, 7)],
    {Answer, Len1, Fill, First, Rest, process_info(self(), message_queue_len)};
scenario(3, Size) ->
    Self = self(),
    fill(fun() -> Self ! {x, payload(1, Size)}, Self ! {y, payload(2, Size)} end),
    Timed = receive {nothing, _} -> wrong after 0 -> timed_out end,
    Y = receive {y, P2} -> sum(P2) end,
    Z = receive {z, _} -> wrong after 0 -> timed_out end,
    X = receive {x, P1} -> sum(P1) end,
    {Timed, Y, Z, X, process_info(self(), message_queue_len)};
scenario(4, Size) ->
    Self = self(),
    Senders = [spawn_monitor(fun() ->
                                     [Self ! {s, S, I, payload(I, Size)} || I <- lists:seq(1, 30)]
                             end) || S <- lists:seq(1, 4)],
    Got = [receive {s, Sx, Ix, P} -> {Sx, Ix, sum(P)} end || _ <- lists:seq(1, 120)],
    [receive {'DOWN', R, process, Pid, _} -> ok end || {Pid, R} <- Senders],
    PerSender = [[I || {S, I, _} <- Got, S =:= Id] || Id <- lists:seq(1, 4)],
    {PerSender, lists:sum([V || {_, _, V} <- Got])};
scenario(5, Size) ->
    Self = self(),
    fill(fun() -> [Self ! {m, I, payload(I, Size)} || I <- lists:seq(1, 8)] end),
    Lens = [begin
                receive {m, I, P} -> {I, sum(P), element(2, process_info(self(), message_queue_len))} end
            end || I <- lists:seq(1, 8)],
    garbage_collect(),
    {Lens, process_info(self(), messages)};
scenario(6, Size) ->
    Self = self(),
    fill(fun() -> [Self ! {m, I, payload(I, Size)} || I <- lists:seq(1, 10)] end),
    H1 = receive {m, 1, P1} -> sum(P1) end,
    garbage_collect(),
    M = receive {m, 6, P6} -> sum(P6) end,
    H2 = receive {m, 2, P2} -> sum(P2) end,
    garbage_collect(),
    Tail = receive {m, 10, P10} -> sum(P10) end,
    {H1, M, H2, Tail, drain([])};
scenario(7, Size) ->
    Self = self(),
    Tokened = spawn_monitor(fun() ->
                                    seq_trace:set_token(label, 7),
                                    Self ! {m, 1, payload(1, Size)}
                            end),
    {TPid, TRef} = Tokened,
    receive {'DOWN', TRef, process, TPid, _} -> ok end,
    fill(fun() -> Self ! {m, 2, payload(2, Size)} end),
    {m, 1, P1} = receive {m, 1, _} = M1 -> M1 end,
    T1 = seq_trace:get_token(label),
    {m, 2, P2} = receive {m, 2, _} = M2 -> M2 end,
    T2 = seq_trace:get_token(label),
    {sum(P1), T1, sum(P2), T2};
scenario(8, Size) ->
    Self = self(),
    process_flag(priority, high),
    fill(fun() -> [Self ! {m, I, payload(I, Size)} || I <- lists:seq(1, 5)] end),
    Ref = make_ref(),
    Self ! {Ref, self_sent},
    Self ! {m, 6, payload(6, Size)},
    A = receive {m, 1, Pa} -> sum(Pa) end,
    Marked = receive {Ref, What} -> What end,
    Rest = drain([]),
    {A, Marked, Rest}.
"#;

#[test]
fn selective_receive_scenarios_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping selective receive differential scenarios");
        return;
    };
    let beam = reference
        .compile_named("selective_receive_diff", SOURCE, &[])
        .unwrap();
    reference.load("selective_receive_diff", &beam).unwrap();
    for size in [3, 200] {
        for scenario in 0..=8 {
            let expected = reference.call(
                "selective_receive_diff",
                "scenario",
                &[OwnedTerm::Int(scenario), OwnedTerm::Int(size)],
            );
            let mut vm = Vm::new([]);
            vm.load_bytes(&beam).unwrap();
            let actual = vm
                .eval_scheduled(
                    "selective_receive_diff",
                    "scenario",
                    &[Term::small(scenario).unwrap(), Term::small(size).unwrap()],
                    4,
                    Some(0x5eed),
                )
                .unwrap_or_else(|error| panic!("scenario {scenario} size {size}: {error}"));
            assert_eq!(
                expected,
                CallResult::Ok(actual.term),
                "scenario {scenario} size {size}"
            );
        }
    }
}

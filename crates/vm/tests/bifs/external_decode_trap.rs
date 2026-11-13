//! `binary_to_term/1,2` of external.c on big inputs: results, reductions and schedule-ins of
//! the call against the real `erl` (`+S 1` scheduler of `RefErl` and of `eval_scheduled`).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use similar_asserts::assert_eq;

const MODULE: &str = "external_decode_trap_test";

const SOURCE: &str = r#"-module(external_decode_trap_test).
-export([run/1]).
term(list) -> lists:seq(1, 1000000);
term(floats) -> [float(N) || N <- lists:seq(1, 200000)];
term(tuple) -> deep(100000, a);
term(binary) -> binary:copy(<<1, 2, 3>>, 500000);
term(small) -> {a, [1, 2, 3], <<"x">>};
term(mixed) -> [{N, <<N:32>>, #{N => N}} || N <- lists:seq(1, 20000)].
deep(0, T) -> T;
deep(N, T) -> deep(N - 1, {T}).
encode(list, plain) -> term_to_binary(term(list));
encode(list, compressed) -> term_to_binary(term(list), [{compressed, 6}]);
encode(floats, plain) -> term_to_binary(term(floats));
encode(tuple, plain) -> term_to_binary(term(tuple));
encode(binary, compressed) -> term_to_binary(term(binary), [{compressed, 9}]);
encode(small, plain) -> term_to_binary(term(small));
encode(mixed, plain) -> term_to_binary(term(mixed));
encode(mixed, compressed) -> term_to_binary(term(mixed), [{compressed, 1}]);
encode(list, bad) -> B = term_to_binary(term(list)), binary:part(B, 0, byte_size(B) - 5).
cases() ->
    [{list, plain, []}, {list, plain, [safe]}, {list, plain, [used]},
     {list, compressed, []}, {list, compressed, [used]}, {floats, plain, []},
     {tuple, plain, [safe]}, {binary, compressed, []}, {small, plain, []},
     {mixed, plain, [safe, used]}, {mixed, compressed, []}, {list, bad, [used]}].
reds() -> element(2, process_info(self(), reductions)).
run(Index) ->
    {T, Enc, Opts} = lists:nth(Index, cases()),
    Bin = encode(T, Enc),
    Parent = self(),
    %% A heap that holds the result: the decode charges no collection in either runtime.
    Pid = spawn_opt(fun() ->
        receive start ->
            erlang:garbage_collect(),
            R0 = reds(),
            Res = try binary_to_term(Bin, Opts) of V -> {ok, V}
                  catch error:Reason -> {error, Reason} end,
            R1 = reds(),
            Parent ! {done, self(), R1 - R0, Res}
        end
    end, [{min_heap_size, 16000000}]),
    1 = erlang:trace(Pid, true, [running, {tracer, Parent}]),
    Pid ! start,
    receive
        {done, Pid, Delta, Res} ->
            Ref = erlang:trace_delivered(Pid),
            Ins = count_in(Pid, Ref, 0),
            Check = case Res of
                {ok, V} -> {ok, V =:= expected(T, Opts, Bin)};
                Other -> Other
            end,
            {Check, Delta, Ins}
    after 60000 -> exit(Pid, kill), timeout
    end.
expected(T, Opts, Bin) ->
    V = term(T),
    case lists:member(used, Opts) of
        true -> {V, byte_size(Bin)};
        false -> V
    end.
count_in(Pid, Ref, N) ->
    receive
        {trace, Pid, in, _} -> count_in(Pid, Ref, N + 1);
        {trace_delivered, Pid, Ref} -> N;
        _ -> count_in(Pid, Ref, N)
    after 30000 -> -1
    end.
"#;

#[test]
fn binary_to_term_matches_otp_on_big_inputs() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    for index in 1..=12i64 {
        let CallResult::Ok(expected) = reference.call(MODULE, "run", &[OwnedTerm::Int(index)])
        else {
            panic!("OTP failed case {index}");
        };
        let actual = vm
            .eval_scheduled(MODULE, "run", &[Term::small(index).unwrap()], 1)
            .unwrap_or_else(|error| panic!("Arinsal failed case {index}: {error:?}"))
            .term;
        eprintln!("case {index}: erl {expected:?} arinsal {actual:?}");
        let (OwnedTerm::Tuple(e), OwnedTerm::Tuple(a)) = (&expected, &actual) else {
            panic!("case {index}: not tuples");
        };
        assert_eq!(e[0], a[0], "case {index}: result");
        // The same units as erts (one per term in `decoded_size` and `dec_term`, 128 per
        // reduction): within 2% plus the BIF call itself.
        let (OwnedTerm::Int(e_reds), OwnedTerm::Int(a_reds)) = (&e[1], &a[1]) else {
            panic!("case {index}: reductions");
        };
        assert!(
            (e_reds - a_reds).abs() <= e_reds / 50 + 10,
            "case {index}: reductions erl {e_reds} arinsal {a_reds}"
        );
        // Schedule-ins are exact: the `!` of the result yields as in erts and the
        // `trace_delivered` reply goes through the system message dispatcher.
        let (OwnedTerm::Int(e_in), OwnedTerm::Int(a_in)) = (&e[2], &a[2]) else {
            panic!("case {index}: schedule-ins");
        };
        assert_eq!(e_in, a_in, "case {index}: schedule-ins");
    }
}

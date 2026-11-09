use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(sensitive_scen).
-export([scenario/1]).
scenario(0) ->
    put(foo, bar), self() ! hello,
    false = process_flag(sensitive, true),
    Hidden = [process_info(self(), dictionary), process_info(self(), messages),
              process_info(self(), {dictionary, foo})],
    true = process_flag(sensitive, false),
    {value, {foo, bar}} = lists:keysearch(foo, 1, element(2, process_info(self(), dictionary))),
    {messages, [hello]} = process_info(self(), messages),
    Hidden;
scenario(1) ->
    0 = process_flag(save_calls, 10),
    L = f([1, 2, 3]),
    {last_calls, C} = process_info(self(), last_calls),
    10 = process_flag(save_calls, 0),
    {last_calls, false} = process_info(self(), last_calls),
    {L, C};
scenario(2) ->
    process_flag(save_calls, 10),
    false = process_flag(sensitive, true),
    {last_calls, C1} = process_info(self(), last_calls),
    _ = f([1, 2, 3]),
    {last_calls, C2} = process_info(self(), last_calls),
    true = process_flag(sensitive, false),
    {C1, C1 =:= C2};
scenario(3) ->
    false = process_flag(sensitive, true),
    {backtrace, Hidden} = process_info(self(), backtrace),
    true = process_flag(sensitive, false),
    {backtrace, Shown} = process_info(self(), backtrace),
    {Hidden, byte_size(Shown) > 20};
scenario(4) ->
    P = spawn(fun() -> waiter(0) end),
    wait_until_waiting(P, 100),
    {current_stacktrace, [{M, F, A, _} | _]} = process_info(P, current_stacktrace),
    {current_function, MFA} = process_info(P, current_function),
    exit(P, kill),
    {M, F, A, MFA};
scenario(5) ->
    process_flag(save_calls, 20),
    self() ! a, receive a -> ok end,
    receive after 0 -> ok end,
    _ = lists:seq(1, 3), _ = erlang:apply(lists, reverse, [[1]]),
    F = fun lists:sort/1, _ = F([2, 1]),
    _ = atom_to_list(abc), _ = erlang:phash2(x),
    {last_calls, C} = process_info(self(), last_calls),
    C;
scenario(6) ->
    %% Remote calls of a process that saves calls are recorded while other processes,
    %% including ones running the same code, are not affected.
    Parent = self(),
    P = spawn(fun() -> _ = lists:seq(1, 2), Parent ! {self(), process_info(self(), last_calls)} end),
    Other = receive {P, R} -> R end,
    process_flag(save_calls, 3),
    [lists:reverse([I]) || I <- [1, 2, 3, 4]],
    {last_calls, C} = process_info(self(), last_calls),
    0 = process_flag(save_calls, 0) - 3,
    {Other, C}.
f(X) -> lists:reverse(X).
waiter(N) -> receive stop -> ok; _ -> waiter(N + 1) end.
wait_until_waiting(_P, 0) -> ok;
wait_until_waiting(P, N) ->
    case process_info(P, status) of
        {status, waiting} -> ok;
        _ -> receive after 10 -> wait_until_waiting(P, N - 1) end
    end.
"#;

#[test]
fn sensitive_save_calls_and_stack_scenarios_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping sensitive/save_calls differential scenarios");
        return;
    };
    let beam = reference
        .compile_named("sensitive_scen", SOURCE, &[])
        .unwrap();
    reference.load("sensitive_scen", &beam).unwrap();
    for scenario in 0..7 {
        let expected = reference.call("sensitive_scen", "scenario", &[OwnedTerm::Int(scenario)]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled(
            "sensitive_scen",
            "scenario",
            &[Term::small(scenario).unwrap()],
            1,
            Some(71),
        );
        assert_eq!(
            expected,
            CallResult::Ok(
                actual
                    .unwrap_or_else(|e| panic!("scenario {scenario}: {e}"))
                    .term
            ),
            "scenario {scenario}"
        );
    }
}

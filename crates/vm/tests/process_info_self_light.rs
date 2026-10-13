mod common;

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

// Self-item results from the light path (`process_info_light`) and the executor fallback must
// match erl. Pids and heap sizes differ between runtimes, and erl's calling process carries a
// link from its eval harness that arinsal's does not, so those are checked by shape or delta.
const SOURCE: &str = r#"
-module(process_info_self_light).
-export([scenario/1]).
scenario(0) ->
    self() ! a, self() ! {b, 1}, put(k, v), process_flag(trap_exit, true),
    process_info(self(), [message_queue_len, trap_exit, messages, dictionary, status, registered_name]);
scenario(1) -> process_info(self(), registered_name);
scenario(2) ->
    register(light_reg, self()),
    R = process_info(self(), registered_name),
    unregister(light_reg),
    R;
scenario(3) ->
    register(light_reg, self()),
    R = process_info(self(), [registered_name, message_queue_len]),
    unregister(light_reg),
    R;
scenario(4) -> {reductions, R} = process_info(self(), reductions), true = is_integer(R), ok;
scenario(5) ->
    {links, Before} = process_info(self(), links),
    Child = spawn_link(fun() -> receive stop -> ok end end),
    {links, After} = process_info(self(), links),
    true = lists:member(Child, After),
    Child ! stop,
    length(After) - length(Before);
scenario(6) ->
    P = spawn(fun() -> receive stop -> ok end end),
    R = monitor(process, P),
    {monitors, [{process, Mon}]} = process_info(self(), monitors),
    true = Mon =:= P,
    P ! stop,
    true = erlang:demonitor(R, [flush]),
    ok;
scenario(7) ->
    L = process_info(self(), [monitors, heap_size, total_heap_size, stack_size, reductions]),
    [{monitors, []}, {heap_size, H}, {total_heap_size, T}, {stack_size, S}, {reductions, R}] = L,
    true = is_integer(H) andalso is_integer(T) andalso is_integer(S) andalso is_integer(R),
    ok;
scenario(8) -> process_info(self(), [message_queue_len, current_function]);
scenario(9) -> try process_info(self(), not_an_item) catch error:badarg -> badarg end;
scenario(10) -> process_info(self(), []);
scenario(11) ->
    [self() ! {m, N} || N <- lists:seq(1, 100)],
    {messages, Msgs} = process_info(self(), messages),
    {message_queue_len, Len} = process_info(self(), message_queue_len),
    Msgs = [{m, N} || N <- lists:seq(1, 100)],
    flush(), Len;
scenario(12) ->
    [put({key, N}, N) || N <- lists:seq(1, 50)],
    {dictionary, D} = process_info(self(), dictionary),
    [erase({key, N}) || N <- lists:seq(1, 50)],
    lists:sort(D);
scenario(13) ->
    self() ! first, self() ! second,
    receive first -> ok end,
    process_info(self(), [messages, message_queue_len]);
scenario(14) -> process_info(self(), dictionary);
scenario(15) -> process_info(self(), [status, trap_exit]);
scenario(16) ->
    register(light_reg, self()),
    {registered_name, Name} = process_info(self(), registered_name),
    unregister(light_reg),
    Name;
scenario(17) -> process_info(self(), messages);
scenario(18) -> {current_function, {process_info_self_light, scenario, 1}} = process_info(self(), current_function), ok;
scenario(19) -> process_info(self(), [trap_exit, message_queue_len, registered_name, dictionary, messages, status]);
scenario(20) ->
    process_flag(trap_exit, true), R = process_info(self(), trap_exit), process_flag(trap_exit, false), R;
scenario(21) -> lists:sort(process_info(self(), [status, trap_exit, message_queue_len]));
scenario(22) ->
    put(k1, 1), put(k2, 2), put(k3, 3),
    {dictionary, D} = process_info(self(), dictionary),
    [erase(K) || K <- [k1, k2, k3]],
    D;
scenario(23) ->
    put(k1, 1), put(k2, 2), put(k3, 3),
    R = process_info(self(), [dictionary, current_function]),
    [erase(K) || K <- [k1, k2, k3]],
    R;
scenario(24) ->
    Parent = self(), Ref = make_ref(),
    spawn(fun() ->
        [put({key, N}, N) || N <- lists:seq(1, 50)],
        {dictionary, D} = process_info(self(), dictionary),
        Parent ! {Ref, D}
    end),
    receive {Ref, D} -> D end;
scenario(25) ->
    Parent = self(), Ref = make_ref(),
    spawn(fun() ->
        [put({key, N}, N) || N <- lists:seq(1, 50)],
        R = process_info(self(), [dictionary, current_function]),
        Parent ! {Ref, R}
    end),
    receive {Ref, R} -> R end.

flush() -> receive _ -> flush() after 0 -> ok end.
"#;

fn run_scenarios(scenarios: &[i64]) -> Vec<String> {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process_info self-item differential scenarios");
        return Vec::new();
    };
    let beam = reference
        .compile_named("process_info_self_light", SOURCE, &[])
        .unwrap();
    reference.load("process_info_self_light", &beam).unwrap();
    let mut mismatches = Vec::new();
    for &scenario in scenarios {
        let expected = reference.call(
            "process_info_self_light",
            "scenario",
            &[OwnedTerm::Int(scenario)],
        );
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled(
            "process_info_self_light",
            "scenario",
            &[Term::small(scenario).unwrap()],
            1,
            Some(71),
        );
        let actual = CallResult::Ok(
            actual
                .unwrap_or_else(|e| panic!("scenario {scenario}: {e}"))
                .term,
        );
        if expected != actual {
            mismatches.push(format!(
                "scenario {scenario}: erl {expected:?} vm {actual:?}"
            ));
        }
    }
    mismatches
}

#[test]
fn process_info_self_items_match_otp_29() {
    let scenarios: Vec<i64> = (0..=21).collect();
    let mismatches = run_scenarios(&scenarios);
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

// Dictionary order with 50 keys: erts' linear hash order, reversed by erts_dictionary_copy.
// Scenarios 24 and 25 run in a child process, so both sides start from an empty dictionary.
#[test]
fn process_info_dictionary_order_matches_otp_29() {
    // Scenarios 24 and 25 read the dictionary order, so the expected values come from a fresh
    // one-shot erl (see `common::erl_once`).
    let Some(beam) = common::erl_beam("process_info_self_light", SOURCE) else {
        eprintln!("erlc unavailable; skipping process_info dictionary order scenarios");
        return;
    };
    for scenario in [24_i64, 25] {
        let expr = format!("process_info_self_light:scenario({scenario})");
        let Some(expected) = common::erl_once("process_info_self_light", SOURCE, &expr) else {
            eprintln!("erl unavailable; skipping process_info dictionary order scenarios");
            return;
        };
        let actual = common::arinsal_once("process_info_self_light", &beam, &expr);
        assert_eq!(expected, actual, "scenario {scenario}");
    }
}

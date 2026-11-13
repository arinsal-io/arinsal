//! `process_info(self(), Item)` and `group_leader/0` answered by their light entries must give
//! what `erl` gives: the counters with and without queued signals, and the fallbacks.

use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

const SOURCE: &str = r#"
-module(light_bif_self).
-export([run/0, timers/0, info/0, fun_info_loop/1]).
run() ->
    A = process_info(self(), message_queue_len),
    self() ! a, self() ! b,
    B = process_info(self(), message_queue_len),
    receive a -> ok end,
    C = process_info(self(), message_queue_len),
    D = process_info(self(), status),
    E = process_info(self(), [message_queue_len, status]),
    F = (catch process_info(self(), bogus)),
    G = element(1, process_info(self(), heap_size)),
    H = process_info(self(), registered_name),
    P = spawn(fun() -> receive stop -> ok end end),
    I = process_info(P, message_queue_len),
    P ! stop,
    J = group_leader() =:= group_leader(),
    K = is_pid(group_leader()),
    L = (group_leader() =:= element(2, process_info(self(), group_leader))),
    {A, B, C, D, E, element(1, F), G, H, I, J, K, L}.
info() ->
    {W1, D1} = statistics(wall_clock),
    {R1, _} = statistics(runtime),
    {GC1, _, _} = statistics(garbage_collection),
    {{input, I}, {output, O}} = statistics(io),
    {Mega, Seconds, Micros} = os:timestamp(),
    {is_integer(W1), is_integer(D1), is_integer(R1), is_integer(GC1), is_integer(I), is_integer(O),
     module_loaded(light_bif_self), module_loaded(no_such_module_xyz),
     erlang:function_exported(light_bif_self, info, 0), erlang:function_exported(light_bif_self, info, 7),
     erlang:function_exported(no_such_module_xyz, f, 0), erlang:function_exported(light_bif_self, nope, 1),
     element(1, (catch module_loaded(1))), element(1, (catch erlang:function_exported(lists, reverse, a))),
     element(1, (catch statistics(bogus_item))), is_integer(element(1, statistics(reductions))),
     is_integer(statistics(run_queue)), element(2, statistics(context_switches)) =:= 0,
     is_tuple(statistics(exact_reductions)),
     erlang:fun_info(fun lists:map/2, arity) =:= {arity, 2},
     is_list(process_info(self())),
     is_integer(erlang:system_info(process_count)), is_list(nodes()), is_list(registered()),
     is_pid(list_to_pid("<0.1.0>")),
     is_integer(Mega) andalso is_integer(Seconds) andalso Seconds >= 0 andalso Seconds < 1000000 andalso
     is_integer(Micros) andalso Micros >= 0 andalso Micros < 1000000}.
fun_info_loop(0) -> ok;
fun_info_loop(N) ->
    {arity, 2} = erlang:fun_info(fun lists:map/2, arity),
    fun_info_loop(N - 1).
timers() ->
    T1 = erlang:start_timer(100000, self(), hello),
    R1 = erlang:read_timer(T1),
    C1 = erlang:cancel_timer(T1),
    C2 = erlang:cancel_timer(T1),
    R2 = erlang:read_timer(T1),
    T2 = erlang:send_after(100000, self(), x),
    C3 = erlang:cancel_timer(T2, [{info, false}]),
    T3 = erlang:send_after(1, self(), later),
    M1 = receive later -> got after 2000 -> timeout end,
    T4 = erlang:start_timer(1, self(), y),
    M2 = receive {timeout, T4, y} -> got after 2000 -> timeout end,
    Dead = spawn(fun() -> ok end),
    erlang:yield(), timer:sleep(20),
    T5 = erlang:send_after(10, Dead, never),
    B1 = (catch erlang:send_after(foo, self(), a)),
    B2 = (catch erlang:start_timer(-1, self(), a)),
    B3 = (catch erlang:cancel_timer(notaref)),
    {is_reference(T1), is_integer(R1), R1 =< 100000, is_integer(C1), C2, R2, is_reference(T2),
     C3, is_reference(T3), M1, M2, is_reference(T5), element(1, B1), element(1, B2),
     element(1, B3)}.
"#;

#[test]
fn self_counters_and_group_leader_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping light_bif_self differential test");
        return;
    };
    let beam = reference
        .compile_named("light_bif_self", SOURCE, &[])
        .unwrap();
    reference.load("light_bif_self", &beam).unwrap();
    let expected = reference.call("light_bif_self", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("light_bif_self", "run", &[], 2)
        .unwrap_or_else(|error| panic!("run: {error}"));
    assert_eq!(CallResult::Ok(actual.term), expected);
}

#[test]
fn bif_timers_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping light_bif_self timer differential test");
        return;
    };
    let beam = reference
        .compile_named("light_bif_self", SOURCE, &[])
        .unwrap();
    reference.load("light_bif_self", &beam).unwrap();
    let expected = reference.call("light_bif_self", "timers", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("light_bif_self", "timers", &[], 2)
        .unwrap_or_else(|error| panic!("timers: {error}"));
    assert_eq!(CallResult::Ok(actual.term), expected);
}

#[test]
fn statistics_and_code_queries_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping light_bif_self info differential test");
        return;
    };
    let beam = reference
        .compile_named("light_bif_self", SOURCE, &[])
        .unwrap();
    reference.load("light_bif_self", &beam).unwrap();
    let expected = reference.call("light_bif_self", "info", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("light_bif_self", "info", &[], 2)
        .unwrap_or_else(|error| panic!("info: {error}"));
    assert_eq!(CallResult::Ok(actual.term), expected);
}

#[test]
fn fun_info_arity_repeated_calls_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping repeated fun_info differential test");
        return;
    };
    let beam = reference
        .compile_named("light_bif_self", SOURCE, &[])
        .unwrap();
    reference.load("light_bif_self", &beam).unwrap();
    let expected = reference.call(
        "light_bif_self",
        "fun_info_loop",
        &[arinsal_etf::OwnedTerm::Int(2000)],
    );
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(
            "light_bif_self",
            "fun_info_loop",
            &[arinsal_term::Term::small(2000).unwrap()],
            2,
        )
        .unwrap_or_else(|error| panic!("fun_info_loop: {error}"));
    assert_eq!(CallResult::Ok(actual.term), expected);
}

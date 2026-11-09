use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r##"
-module(pid_port_follow_diff).
-export([printing/0, errors/0, next_port/0, port_wrap/0, port_reuse/0]).

printing() ->
    P = open_port({spawn, "cat"}, []),
    PortText = erlang:port_to_list(P),
    PortPrint = lists:flatten(io_lib:format("~p", [P])),
    PortRoundTrip = list_to_port(PortText) =:= P,
    EtfRoundTrip = binary_to_term(term_to_binary(P)) =:= P,
    Pid = self(),
    PidText = erlang:pid_to_list(Pid),
    PidPrint = lists:flatten(io_lib:format("~p", [Pid])),
    PidRoundTrip = list_to_pid(PidText) =:= Pid,
    true = port_close(P),
    {lists:prefix("#Port<0.", PortText), PortPrint =:= PortText,
     PortRoundTrip, EtfRoundTrip,
     lists:prefix("<0.", PidText), PidPrint =:= PidText, PidRoundTrip}.

errors() ->
    [top(fun() -> list_to_pid("bad") end),
     top(fun() -> list_to_port("bad") end),
     top(fun() -> list_to_ref("bad") end)].

top(F) ->
    try F() of
        Value -> {ok, Value}
    catch
        error:Reason:Stack ->
            [{Module, Function, Args, Info} | _] = Stack,
            {Reason, Module, Function, length(Args), Info}
    end.

next_port() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Next0 = erts_debug:get_internal_state(next_port),
    P = open_port({spawn, "cat"}, []),
    Next1 = erts_debug:get_internal_state(next_port),
    true = port_close(P),
    {Next1 =:= Next0 + 1,
     erlang:port_to_list(P) =:= "#Port<0." ++ integer_to_list(Next0) ++ ">"}.

port_wrap() ->
    erts_debug:set_internal_state(available_internal_state, true),
    erts_debug:set_internal_state(next_port, (1 bsl 60) - 2),
    First = erts_debug:get_internal_state(next_port),
    P = open_port({spawn, "cat"}, []),
    Second = erts_debug:get_internal_state(next_port),
    Q = open_port({spawn, "cat"}, []),
    FirstMatches = erlang:port_to_list(P) =:=
        "#Port<0." ++ integer_to_list(First) ++ ">",
    SecondMatches = erlang:port_to_list(Q) =:=
        "#Port<0." ++ integer_to_list(Second) ++ ">",
    true = port_close(P),
    true = port_close(Q),
    {FirstMatches, SecondMatches, Second > First}.

port_reuse() ->
    erts_debug:set_internal_state(available_internal_state, true),
    P = open_port({spawn, "cat"}, []),
    Text = erlang:port_to_list(P),
    [_, Number] = string:tokens(Text, ".>"),
    Id = list_to_integer(Number),
    true = port_close(P),
    erts_debug:set_internal_state(next_port, Id - 1),
    Q = open_port({spawn, "cat"}, []),
    Reused = erlang:port_to_list(Q) =:= Text,
    true = port_close(Q),
    Reused.
"##;

fn assert_same(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping pid/port differential {function}");
        return;
    };
    let beam = reference
        .compile_named("pid_port_follow_diff", SOURCE, &[])
        .unwrap();
    reference.load("pid_port_follow_diff", &beam).unwrap();
    let expected = reference.call("pid_port_follow_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("pid_port_follow_diff", function, &[], 2, Some(37))
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn local_pid_port_printing_and_round_trips_match_otp_29() {
    assert_same("printing");
}

#[test]
fn pid_port_ref_error_info_matches_otp_29() {
    assert_same("errors");
}

#[test]
fn port_allocator_starts_after_forker_like_otp_29() {
    assert_same("next_port");
}

#[test]
fn port_allocator_wrap_matches_otp_29() {
    assert_same("port_wrap");
}

#[test]
fn port_allocator_reuses_deleted_ids_like_otp_29() {
    assert_same("port_reuse");
}

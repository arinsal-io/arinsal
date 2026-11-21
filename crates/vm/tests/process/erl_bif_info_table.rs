//! Differential tests for erl_bif_info.c BIFs moved onto `bif_table`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;

const SOURCE: &str = r#"
-module(erl_bif_info_table).
-export([run/1]).

err(F) ->
    try F() of
        Value -> {ok, Value}
    catch
        error:Reason -> {error, Reason}
    end.

run(process_info_1) ->
    Info = process_info(self()),
    true = is_list(Info),
    {status, running} = lists:keyfind(status, 1, Info),
    Dead = list_to_pid("<0.9999.0>"),
    {process_info(Dead), err(fun() -> process_info(not_a_pid) end)};
run(is_process_alive_2) ->
    R = make_ref(),
    ok = erts_internal:is_process_alive(self(), R),
    Alive = receive {R, true} -> true after 1000 -> timeout end,
    Dead = list_to_pid("<0.9999.0>"),
    R2 = make_ref(),
    ok = erts_internal:is_process_alive(Dead, R2),
    DeadReply = receive {R2, false} -> false after 1000 -> timeout end,
    {Alive, DeadReply,
     err(fun() -> erts_internal:is_process_alive(not_a_pid, make_ref()) end),
     err(fun() -> erts_internal:is_process_alive(self(), not_a_ref) end)};
run(module_info) ->
    Info = erlang:get_module_info(erlang),
    true = is_list(Info),
    erlang = erlang:get_module_info(erlang, module),
    true = is_list(erlang:get_module_info(erlang, exports)),
    {err(fun() -> erlang:get_module_info(not_a_module) end),
     err(fun() -> erlang:get_module_info(erlang, not_a_key) end)};
run(system_process) ->
    {erts_internal:is_system_process(self()),
     err(fun() -> erts_internal:is_system_process(not_a_pid) end)};
run(process_display) ->
    {erts_internal:process_display(self(), backtrace),
     erts_internal:process_display(self(), nope),
     erts_internal:process_display(not_a_pid, backtrace)};
run(lcnt) ->
    {erts_debug:lcnt_clear(),
     erts_debug:lcnt_collect(),
     err(fun() -> erts_debug:lcnt_control(mask) end),
     err(fun() -> erts_debug:lcnt_control(mask, []) end),
     erts_internal:system_check(schedulers),
     err(fun() -> erts_internal:system_check(nope) end)};
run(warning_map) ->
    error_logger:warning_map();
run(internal_state) ->
    {err(fun() -> erts_debug:get_internal_state(reds_left) end),
     erts_debug:set_internal_state(available_internal_state, true),
     erts_debug:get_internal_state(available_internal_state),
     erts_debug:set_internal_state(available_internal_state, false)}.
"#;

fn assert_case(reference: &RefErl, name: &str) {
    let beam = reference
        .compile_named("erl_bif_info_table", SOURCE, &[])
        .expect("compile erl_bif_info_table");
    reference
        .load("erl_bif_info_table", &beam)
        .expect("load into erl");
    let expected = reference.call("erl_bif_info_table", "run", &[OwnedTerm::Atom(name.into())]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled(
            "erl_bif_info_table",
            "run",
            &[Term::atom(
                arinsal_term::global_atoms()
                    .intern(name)
                    .expect("intern case name"),
            )],
            1,
        )
        .unwrap_or_else(|error| panic!("{name}: {error}"));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term), "{name}");
}

fn with_erl(test: &str, case: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping {test}");
        return;
    };
    assert_case(&reference, case);
}

#[test]
fn process_info_1_matches_otp() {
    with_erl("process_info/1", "process_info_1");
}

#[test]
fn is_process_alive_2_matches_otp() {
    with_erl("is_process_alive/2", "is_process_alive_2");
}

#[test]
fn module_info_table_matches_otp() {
    with_erl("get_module_info", "module_info");
}

#[test]
fn is_system_process_matches_otp() {
    with_erl("is_system_process/1", "system_process");
}

#[test]
fn process_display_matches_otp() {
    with_erl("process_display/2", "process_display");
}

#[test]
fn lcnt_matches_otp() {
    with_erl("lcnt", "lcnt");
}

#[test]
fn warning_map_matches_otp() {
    with_erl("warning_map", "warning_map");
}

#[test]
fn internal_state_table_matches_otp() {
    with_erl("internal_state", "internal_state");
}

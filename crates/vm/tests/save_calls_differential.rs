use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(save_calls_differential).
-export([repro/0, suite_calls/0, suite_exact/0, do_bipp/0, do_bopp/1, do_bepp/0,
         do_bipp_suite/0, do_bopp_suite/1, do_bepp_suite/0]).

repro() ->
    0 = process_flag(save_calls, 10),
    lists:map(fun erlang:abs/1, [-1]),
    process_info(self(), last_calls).

suite_calls() ->
    process_flag(save_calls, 10),
    save_calls_differential:do_bipp(),
    process_info(self(), last_calls).

suite_exact() ->
    0 = erlang:process_flag(self(), save_calls, 0),
    {last_calls, false} = process_info(self(), last_calls),
    erlang:process_flag(self(), save_calls, 10),
    {last_calls, _L1} = process_info(self(), last_calls),
    save_calls_differential:do_bipp_suite(),
    {last_calls, L2} = process_info(self(), last_calls),
    L21 = lists:filter(fun suite_is_local_function/1, L2),
    {L2, L21}.

do_bipp() ->
    _ = abs(-1),
    F = fun erlang:abs/1,
    _ = F(-2),
    _ = lists:reverse([a]),
    do_bopp(0),
    self() ! saved_call_message,
    do_bopp(0),
    save_calls_differential:do_bopp(0),
    do_bopp(3),
    apply(save_calls_differential, do_bepp, []).

do_bopp(T) ->
    receive
        _ -> ok
    after T -> ok
    end.

do_bepp() -> ok.

do_bipp_suite() ->
    do_bopp_suite(0),
    do_bapp_suite(),
    save_calls_differential:do_bopp_suite(0),
    do_bopp_suite(3),
    apply(save_calls_differential, do_bepp_suite, []).

do_bapp_suite() -> self() ! heffaklump.

do_bopp_suite(T) ->
    receive
        _ -> ok
    after T -> ok
    end.

do_bepp_suite() -> ok.

suite_is_local_function({save_calls_differential, _, _}) -> true;
suite_is_local_function({_, _, _}) -> false;
suite_is_local_function(_) -> true.
"#;

#[test]
fn save_calls_matches_otp_for_export_fun_bif_and_message_entries() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping save_calls differential scenarios");
        return;
    };
    let beam = reference
        .compile_named("save_calls_differential", SOURCE, &[])
        .unwrap();
    reference.load("save_calls_differential", &beam).unwrap();

    for function in ["suite_exact", "suite_calls", "repro"] {
        let expected = reference.call("save_calls_differential", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled("save_calls_differential", function, &[], 1, Some(71));
        similar_asserts::assert_eq!(
            expected,
            CallResult::Ok(
                actual
                    .unwrap_or_else(|error| panic!("{function}: {error}"))
                    .term
            ),
            "save_calls scenario {function}"
        );
    }
}

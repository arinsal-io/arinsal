use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

/// The interpreter counts a few more instructions around the call than BEAMASM and erts do.
const SLACK: i64 = 16;

const MODULE: &str = "binary_copy_reductions_test";

const SOURCE: &str = r#"-module(binary_copy_reductions_test).
-export([copy_4k/0, copy_64k/0, copy_100k/0, copy_300k/0, copy_odd_size/0, copy_1m/0,
         copy_loop_limit/0, copy_loop_limit_unaligned/0, copy_unaligned_source/0]).

copy_4k() -> measure(fun() -> binary:copy(<<0, 1, 255, 17>>, 1000) end).
copy_64k() -> measure(fun() -> binary:copy(<<0, 1, 255, 17>>, 16000) end).
copy_100k() -> measure(fun() -> binary:copy(<<0, 1, 255, 17>>, 25000) end).
copy_300k() -> measure(fun() -> binary:copy(<<0, 1, 255, 17>>, 75000) end).
copy_odd_size() -> measure(fun() -> binary:copy(<<0, 1, 255, 17, 9>>, 60001) end).
copy_1m() -> measure(fun() -> binary:copy(<<0, 1, 255, 17>>, 262144) end).

copy_loop_limit() ->
    _ = erts_debug:set_internal_state(available_internal_state, true),
    erts_debug:set_internal_state(binary_loop_limit, 800),
    try
        measure(fun() -> binary:copy(<<0, 1, 255, 17>>, 100000) end)
    after
        erts_debug:set_internal_state(binary_loop_limit, default)
    end.

copy_loop_limit_unaligned() ->
    _ = erts_debug:set_internal_state(available_internal_state, true),
    erts_debug:set_internal_state(binary_loop_limit, 801),
    try
        measure(fun() -> binary:copy(<<0, 1, 255, 17>>, 100) end)
    after
        erts_debug:set_internal_state(binary_loop_limit, default)
    end.

copy_unaligned_source() ->
    _ = erts_debug:set_internal_state(available_internal_state, true),
    erts_debug:set_internal_state(binary_loop_limit, 801),
    <<_:3, Source:24/bitstring, _/bitstring>> = <<0:3, 5, 6, 7, 0:5>>,
    try
        measure(fun() -> binary:copy(Source, 1000) end)
    after
        erts_debug:set_internal_state(binary_loop_limit, default)
    end.

measure(Fun) ->
    Parent = self(),
    Pid = spawn(fun() ->
        receive go -> ok end,
        erlang:yield(),
        {reductions, R0} = process_info(self(), reductions),
        Result = Fun(),
        {reductions, R1} = process_info(self(), reductions),
        Parent ! {measured, R1 - R0, is_binary(Result) orelse is_list(Result)}
    end),
    1 = erlang:trace(Pid, true, [running, {tracer, Parent}]),
    Pid ! go,
    receive
        {measured, Reds, true} -> {Reds, schedule_ins(Pid, 0)}
    after 10000 -> timeout
    end.

schedule_ins(Pid, Count) ->
    receive
        {trace, Pid, in, _} -> schedule_ins(Pid, Count + 1);
        {trace, Pid, _, _} -> schedule_ins(Pid, Count)
    after 200 -> Count
    end.
"#;

fn measured(term: &OwnedTerm) -> (i64, i64) {
    let OwnedTerm::Tuple(elems) = term else {
        panic!("probe did not return a tuple: {term:?}");
    };
    let (OwnedTerm::Int(reds), OwnedTerm::Int(slices)) = (&elems[0], &elems[1]) else {
        panic!("probe returned {term:?}");
    };
    (*reds, *slices)
}

#[test]
fn binary_copy_reductions_and_slices_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    let cases = [
        "copy_4k",
        "copy_64k",
        "copy_100k",
        "copy_300k",
        "copy_odd_size",
        "copy_1m",
        "copy_loop_limit",
        "copy_loop_limit_unaligned",
        "copy_unaligned_source",
    ];
    for (index, function) in cases.iter().enumerate() {
        let CallResult::Ok(expected) = reference.call(MODULE, function, &[]) else {
            panic!("OTP {function} failed");
        };
        let actual = vm
            .eval_scheduled_reductions(MODULE, function, &[], 1, Some(0xB300 + index as u64), 4_000)
            .unwrap();
        let (expected_reds, expected_slices) = measured(&expected);
        let (actual_reds, actual_slices) = measured(&actual.term);
        assert_eq!(
            expected_slices, actual_slices,
            "{function}: scheduler slices"
        );
        assert!(
            (expected_reds..=expected_reds + SLACK).contains(&actual_reds),
            "{function}: OTP reductions {expected_reds}, Arinsal reductions {actual_reds}"
        );
    }
}

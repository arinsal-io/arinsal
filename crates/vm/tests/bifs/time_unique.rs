use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use similar_asserts::assert_eq;

const MODULE: &str = "time_unique_diff";
const SOURCE: &str = r#"
-module(time_unique_diff).
-export([clock_values/0, unit_values/0, clock_loop/1, calendar_values/0, dst_values/0,
         current_calendar/0, now_values/0,
         errors/0, identities/0, concurrent_identities/0]).

clock_values() ->
    {erlang:system_time(), erlang:system_time(1000), erlang:system_time(137),
     os:system_time(), os:system_time(1000), os:system_time(137),
     erlang:monotonic_time(), erlang:monotonic_time(1000),
     erlang:monotonic_time(137), erlang:time_offset(),
     erlang:time_offset(1000), erlang:time_offset(137),
     erlang:timestamp(), os:timestamp(), erlang:now(),
     erts_internal:time_unit(), erts_internal:perf_counter_unit(),
     erlang:convert_time_unit(-500, native, microsecond),
     erlang:convert_time_unit(123456789, 137, 1000),
     erlang:convert_time_unit(1000000000, perf_counter, microsecond)}.

unit_values() ->
    Units = [native, nanosecond, nano_seconds, microsecond, micro_seconds,
             millisecond, milli_seconds, second, seconds,
             1000000000, 1000000, 1000, 1],
    {erlang:system_time(), [erlang:system_time(U) || U <- Units],
     os:system_time(), [os:system_time(U) || U <- Units],
     erlang:monotonic_time(), [erlang:monotonic_time(U) || U <- Units],
     erlang:time_offset(), [erlang:time_offset(U) || U <- Units]}.

clock_loop(0) -> ok;
clock_loop(N) ->
    _ = erlang:monotonic_time(137),
    _ = erlang:system_time(137),
    _ = erlang:time_offset(137),
    clock_loop(N - 1).

calendar_one(S) ->
    U = erlang:posixtime_to_universaltime(S),
    L = erlang:universaltime_to_localtime(U),
    {S, U, erlang:universaltime_to_posixtime(U), L,
     erlang:localtime_to_universaltime(L, undefined)}.

calendar_values() -> [calendar_one(S) || S <- lists:seq(-500, 499)].

dst_values() ->
    [erlang:localtime_to_universaltime({{Y, M, D}, {H, 30, 0}}, Flag)
     || {{Y, M, D}, H} <- [{{2020, 1, 1}, 12}, {{2020, 7, 1}, 12},
                           {{2020, 3, 29}, 2}, {{2020, 10, 25}, 2}],
        Flag <- [true, false, undefined]].

current_calendar() ->
    {erlang:time(), erlang:date(), erlang:localtime(), erlang:universaltime()}.

now_values() -> [erlang:now() || _ <- lists:seq(1, 100)].

report(Fun) ->
    try Fun() of Value -> {ok, Value}
    catch error:Reason:Stack ->
        Location = element(4, hd(Stack)),
        {error, Reason, proplists:get_value(error_info, Location, undefined)}
    end.

errors() ->
    {report(fun() -> erlang:system_time(bogus) end),
     report(fun() -> erlang:system_time(0) end),
     report(fun() -> erlang:monotonic_time(-1) end),
     report(fun() -> erlang:time_offset(bogus) end),
     report(fun() -> erlang:localtime_to_universaltime({{2020, 1, 1}, {0, 0, 0}}, bad) end),
     report(fun() -> erlang:posixtime_to_universaltime(1.5) end),
     report(fun() -> erlang:universaltime_to_localtime({{1900, 7, 1}, {12, 0, 0}}) end),
     report(fun() -> erlang:localtime_to_universaltime({{1900, 7, 1}, {12, 0, 0}}, false) end),
     report(fun() -> erlang:unique_integer([bogus]) end),
     report(fun() -> erlang:unique_integer([positive | bad]) end)}.

identities() ->
    N = 1000,
    Refs = [make_ref() || _ <- lists:seq(1, N)],
    Positive = [erlang:unique_integer([positive]) || _ <- lists:seq(1, N)],
    Monotonic = [erlang:unique_integer([positive, monotonic]) || _ <- lists:seq(1, N)],
    Negative = [erlang:unique_integer() || _ <- lists:seq(1, N)],
    {lists:all(fun erlang:is_reference/1, Refs),
     length(lists:usort(Refs)) =:= N,
     lists:all(fun(X) -> X > 0 end, Positive),
     length(lists:usort(Positive)) =:= N,
     lists:all(fun(X) -> X > 0 end, Monotonic),
     lists:all(fun({A, B}) -> A < B end,
              lists:zip(lists:sublist(Monotonic, N - 1), tl(Monotonic))),
     lists:all(fun(X) -> X < 0 end, Negative),
     length(lists:usort(Negative)) =:= N}.

concurrent_identities() ->
    Parent = self(),
    N = 32,
    [spawn(fun() -> Parent ! {identity, erlang:make_ref(),
                              erlang:unique_integer([positive]),
                              erlang:unique_integer([positive, monotonic])} end)
     || _ <- lists:seq(1, N)],
    Values = collect(N, []),
    {length(lists:usort([R || {R, _, _} <- Values])) =:= N,
     length(lists:usort([U || {_, U, _} <- Values])) =:= N,
     length(lists:usort([M || {_, _, M} <- Values])) =:= N}.

collect(0, Values) -> Values;
collect(N, Values) ->
    receive {identity, Ref, Unique, Monotonic} ->
        collect(N - 1, [{Ref, Unique, Monotonic} | Values])
    end.
"#;

fn run(reference: &RefErl, function: &str) -> OwnedTerm {
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, function, &[]);
    let CallResult::Ok(expected) = expected else {
        panic!("OTP {MODULE}:{function}/0 failed: {expected:?}");
    };
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, function, &[], 1)
        .unwrap_or_else(|error| panic!("Arinsal {MODULE}:{function}/0 failed: {error}"));
    if function != "clock_values" && function != "current_calendar" {
        assert_eq!(expected, actual.term, "{function}");
    }
    actual.term
}

fn int(value: &OwnedTerm) -> i128 {
    match value {
        OwnedTerm::Int(value) => i128::from(*value),
        OwnedTerm::BigInt(value) => num_traits::ToPrimitive::to_i128(value).unwrap(),
        other => panic!("expected integer, got {other:?}"),
    }
}

fn timestamp_micros(value: &OwnedTerm) -> i128 {
    let OwnedTerm::Tuple(parts) = value else {
        panic!("expected timestamp tuple, got {value:?}");
    };
    assert_eq!(parts.len(), 3);
    int(&parts[0]) * 1_000_000_000_000 + int(&parts[1]) * 1_000_000 + int(&parts[2])
}

fn tuple(value: &OwnedTerm) -> &[OwnedTerm] {
    let OwnedTerm::Tuple(parts) = value else {
        panic!("expected tuple, got {value:?}");
    };
    parts
}

fn assert_increasing_now(value: &OwnedTerm) {
    let OwnedTerm::List { elems, tail } = value else {
        panic!("now/0 values were not a list: {value:?}");
    };
    assert_eq!(**tail, OwnedTerm::Nil);
    let micros = elems.iter().map(timestamp_micros).collect::<Vec<_>>();
    assert!(micros.windows(2).all(|pair| pair[0] < pair[1]));
}

fn assert_unit_values(value: &OwnedTerm) {
    let fields = tuple(value);
    assert_eq!(fields.len(), 8);
    let frequencies = [
        1_000_000_000_i128,
        1_000_000_000,
        1_000_000_000,
        1_000_000,
        1_000_000,
        1_000,
        1_000,
        1,
        1,
        1_000_000_000,
        1_000_000,
        1_000,
        1,
    ];
    for (base, values) in [(0, 1), (2, 3), (4, 5), (6, 7)] {
        let OwnedTerm::List { elems, tail } = &fields[values] else {
            panic!(
                "unit conversion results must be a list: {:?}",
                fields[values]
            );
        };
        assert_eq!(**tail, OwnedTerm::Nil);
        assert_eq!(elems.len(), frequencies.len());
        let native = int(&fields[base]);
        for (converted, frequency) in elems.iter().zip(frequencies) {
            let expected = (native * frequency).div_euclid(1_000_000_000);
            let delta = (int(converted) - expected).abs();
            assert!(
                delta <= frequency,
                "unit conversion delta {delta} for {frequency}/s"
            );
        }
    }
}

#[test]
fn time_bifs_match_otp_values_and_clock_relations() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping time BIF differential test");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "clock_values", &[]);
    let CallResult::Ok(expected) = expected else {
        panic!("OTP clock snapshot failed: {expected:?}");
    };
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "clock_values", &[], 1)
        .unwrap()
        .term;
    let actual = tuple(&actual);
    let expected = tuple(&expected);
    assert_eq!(actual.len(), 20);
    assert_eq!(expected.len(), 20);

    for index in [0, 1, 2, 3, 4, 5] {
        assert!((int(&actual[index]) - int(&expected[index])).abs() < 2_000_000_000);
    }
    for values in [actual, expected] {
        for (nanos, millis) in [(0, 1), (3, 4), (6, 7), (9, 10)] {
            let diff = int(&values[nanos]).div_euclid(1_000_000) - int(&values[millis]);
            assert!(diff.abs() <= 1, "clock fields {nanos}/{millis}: {diff}");
        }
        let diff = int(&values[6]) + int(&values[9]) - int(&values[0]);
        assert!(
            diff.abs() < 100_000_000,
            "monotonic + offset mismatch: {diff}"
        );
        assert_eq!(int(&values[15]), 1_000_000_000);
        assert_eq!(int(&values[16]), 1_000_000_000);
        assert_eq!(int(&values[17]), -1);
        assert_eq!(int(&values[18]), 901_144_445);
        assert_eq!(int(&values[19]), 1_000_000);
        for (nanos, converted) in [(0, 2), (3, 5)] {
            let scaled = int(&values[nanos]) * 137 / 1_000_000_000;
            assert!((scaled - int(&values[converted])).abs() <= 137);
        }
        let system_us = int(&values[0]).div_euclid(1_000);
        for timestamp in [&values[12], &values[13], &values[14]] {
            assert!((timestamp_micros(timestamp) - system_us).abs() < 2_000_000);
        }
    }
}

#[test]
fn time_bif_traps_resume_and_calendar_conversions_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping time trap/calendar differential test");
        return;
    };
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "calendar_values", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "calendar_values", &[], 1)
        .unwrap()
        .term;
    assert_eq!(expected, CallResult::Ok(actual), "calendar conversions");

    let CallResult::Ok(before) = reference.call(MODULE, "current_calendar", &[]) else {
        panic!("OTP current calendar failed");
    };
    let actual = vm
        .eval_scheduled(MODULE, "current_calendar", &[], 1)
        .unwrap()
        .term;
    let CallResult::Ok(after) = reference.call(MODULE, "current_calendar", &[]) else {
        panic!("OTP current calendar failed");
    };
    assert!(
        actual == before || actual == after,
        "{actual:?} not between {before:?} and {after:?}"
    );

    let expected_errors = reference.call(MODULE, "errors", &[]);
    let actual_errors = vm.eval_scheduled(MODULE, "errors", &[], 1).unwrap().term;
    assert_eq!(expected_errors, CallResult::Ok(actual_errors));

    let CallResult::Ok(expected_units) = reference.call(MODULE, "unit_values", &[]) else {
        panic!("OTP unit conversions failed");
    };
    let actual_units = vm
        .eval_scheduled(MODULE, "unit_values", &[], 1)
        .unwrap()
        .term;
    assert_unit_values(&expected_units);
    assert_unit_values(&actual_units);

    let expected_dst = reference.call(MODULE, "dst_values", &[]);
    let actual_dst = vm
        .eval_scheduled(MODULE, "dst_values", &[], 1)
        .unwrap()
        .term;
    assert_eq!(expected_dst, CallResult::Ok(actual_dst));

    let CallResult::Ok(reference_now) = reference.call(MODULE, "now_values", &[]) else {
        panic!("OTP now/0 values failed");
    };
    assert_increasing_now(&reference_now);
    let now_values = vm
        .eval_scheduled(MODULE, "now_values", &[], 1)
        .unwrap()
        .term;
    assert_increasing_now(&now_values);

    let expected_loop = reference.call(MODULE, "clock_loop", &[arinsal_etf::OwnedTerm::Int(2_000)]);
    let actual_loop = vm
        .eval_scheduled_reductions(
            MODULE,
            "clock_loop",
            &[arinsal_term::Term::small(2_000).unwrap()],
            1,
            1,
        )
        .unwrap();
    assert_eq!(expected_loop, CallResult::Ok(actual_loop.term));
}

#[test]
fn unique_bifs_match_otp_and_remain_unique_across_schedulers() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping unique BIF differential test");
        return;
    };
    let expected = run(&reference, "identities");
    assert_eq!(expected, OwnedTerm::Tuple(vec![OwnedTerm::atom("true"); 8]));
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "concurrent_identities", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "concurrent_identities", &[], 1)
        .unwrap()
        .term;
    assert_eq!(expected, CallResult::Ok(actual.clone()));
    assert_eq!(actual, OwnedTerm::Tuple(vec![OwnedTerm::atom("true"); 3]));
}

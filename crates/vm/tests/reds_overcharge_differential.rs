//! Reductions charged by BIFs that Arinsal over- or under-charged against erts OTP-29.1.1.
//!
//! Every case runs one BIF call in a process whose heap is large enough that no garbage
//! collection happens inside the window, and compares the reductions consumed by the call
//! (net of an empty fun call in the same process) and the number of times the process was
//! scheduled in against the reference `erl`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "reds_overcharge_test";

/// Allowed deviation per scheduled-in slice: the yield point of a trapping BIF is
/// reached a few instructions earlier or later depending on the call overhead.
const SLACK_PER_SLICE: i64 = 4;

/// A case: name, sizes, heap words per unit of size, input builder, call.
struct Case {
    name: &'static str,
    sizes: &'static [usize],
    heap_factor: usize,
    build: &'static str,
    call: &'static str,
}

const fn case(
    name: &'static str,
    sizes: &'static [usize],
    heap_factor: usize,
    build: &'static str,
    call: &'static str,
) -> Case {
    Case {
        name,
        sizes,
        heap_factor,
        build,
        call,
    }
}

const WORDS: &[usize] = &[1, 10, 100, 1_000, 10_000];
const ARITH_CASES: &[Case] = &[
    case("bignum_mul", WORDS, 1, "big(N)", "In * In"),
    case("bignum_mul_small", WORDS, 1, "big(N)", "In * 3"),
    case(
        "bignum_div_small",
        WORDS,
        1,
        "big(N)",
        "In div 12345678901234567",
    ),
    case(
        "bignum_div_big",
        WORDS,
        1,
        "{big(N), big(max(1, N div 2))}",
        "element(1, In) div element(2, In)",
    ),
    case(
        "bignum_rem_big",
        WORDS,
        1,
        "{big(N), big(max(1, N div 2))}",
        "element(1, In) rem element(2, In)",
    ),
];

const STD: &[usize] = &[1, 1_000, 100_000, 1_000_000];
const IOLIST_CASES: &[Case] = &[
    case(
        "iolist_size_deep",
        STD,
        14,
        "deep(N)",
        "erlang:iolist_size(In)",
    ),
    case(
        "iolist_size_flat",
        STD,
        4,
        "flat(N)",
        "erlang:iolist_size(In)",
    ),
    case(
        "list_to_bitstring",
        STD,
        4,
        "flat(N)",
        "erlang:list_to_bitstring(In)",
    ),
    case(
        "list_to_bitstring_deep",
        STD,
        14,
        "deep(N)",
        "erlang:list_to_bitstring(In)",
    ),
];

const TO_100K: &[usize] = &[1, 1_000, 100_000];
const BIG_BIN: &[usize] = &[4_000_000];
const T2B_CASES: &[Case] = &[
    case("t2b_bin", STD, 1, "bytes(N)", "erlang:term_to_binary(In)"),
    case("t2b_ints", STD, 4, "seq(N)", "erlang:term_to_binary(In)"),
    case(
        "t2b_tuples",
        TO_100K,
        12,
        "tuples(N)",
        "erlang:term_to_binary(In)",
    ),
    case(
        "t2b_iovec_ints",
        TO_100K,
        4,
        "seq(N)",
        "erlang:term_to_iovec(In)",
    ),
    case(
        "t2b_bin_big",
        BIG_BIN,
        1,
        "bytes(N)",
        "erlang:term_to_binary(In)",
    ),
    case(
        "t2b_iovec_bin_big",
        BIG_BIN,
        1,
        "bytes(N)",
        "erlang:term_to_iovec(In)",
    ),
    case(
        "external_size_bin",
        STD,
        1,
        "bytes(N)",
        "erlang:external_size(In)",
    ),
    case(
        "external_size_ints",
        STD,
        4,
        "seq(N)",
        "erlang:external_size(In)",
    ),
];

const MATCHING_CASES: &[Case] = &[
    case(
        "binary_match_1",
        STD,
        1,
        "bytes(N)",
        "binary:match(In, <<250>>)",
    ),
    case(
        "binary_match_multi",
        STD,
        1,
        "bytes(N)",
        "binary:match(In, <<250, 251, 252>>)",
    ),
    case(
        "binary_match_list",
        STD,
        1,
        "bytes(N)",
        "binary:match(In, [<<250, 251>>, <<249>>])",
    ),
    case(
        "binary_matches_1",
        STD,
        12,
        "bytes(N)",
        "binary:matches(In, <<7>>)",
    ),
    case(
        "binary_split_all",
        STD,
        12,
        "bytes(N)",
        "binary:split(In, <<7>>, [global])",
    ),
];

fn function_name(case: &Case, size: usize) -> String {
    format!("{}_{size}", case.name)
}

fn source(cases: &[Case]) -> String {
    let mut exports = Vec::new();
    let mut bodies = String::new();
    for case in cases {
        for &size in case.sizes {
            let function = function_name(case, size);
            exports.push(format!("{function}/0"));
            let words = case.heap_factor * size + 100_000;
            bodies.push_str(&format!(
                "{function}() ->\n    measure({size}, {words}, fun(N) -> {} end, fun(In) -> {} end).\n\n",
                case.build, case.call
            ));
        }
    }
    format!(
        r#"-module({MODULE}).
-export([{exports}]).

seq(N) -> lists:seq(1, N).

flat(N) -> [I rem 256 || I <- lists:seq(1, N)].

bytes(N) -> list_to_binary([I rem 200 || I <- lists:seq(1, N)]).

kv(N) -> [{{I, I}} || I <- lists:seq(1, N)].

tuples(N) -> [{{I, foo, "ab", <<"x">>}} || I <- lists:seq(1, N)].

deep(N) -> [[I rem 200, <<"ab">>, [I rem 100]] || I <- lists:seq(1, N)].

big(N) -> (1 bsl (N * 64)) - 1.

{bodies}
measure(N, Words, Build, Run) ->
    Parent = self(),
    Pid = spawn_opt(fun() ->
        In = Build(N),
        Empty = fun(_) -> ok end,
        _ = baseline(Empty, In),
        Base = baseline(Empty, In),
        Parent ! ready,
        receive go -> ok end,
        erlang:yield(),
        {{reductions, R0}} = process_info(self(), reductions),
        _ = Run(In),
        {{reductions, R1}} = process_info(self(), reductions),
        {{garbage_collection, GC}} = process_info(self(), garbage_collection),
        Parent ! {{measured, R1 - R0 - Base, proplists:get_value(minor_gcs, GC)}}
    end, [{{min_heap_size, Words}}, {{min_bin_vheap_size, Words}}]),
    1 = erlang:trace(Pid, true, [running, {{tracer, Parent}}]),
    receive ready -> ok after 60000 -> exit(no_ready) end,
    drain(Pid),
    Pid ! go,
    receive
        {{measured, Reds, Gcs}} -> {{Reds, schedule_ins(Pid, 0), Gcs}}
    after 60000 -> timeout
    end.

baseline(Fun, In) ->
    {{reductions, B0}} = process_info(self(), reductions),
    _ = Fun(In),
    {{reductions, B1}} = process_info(self(), reductions),
    B1 - B0.

drain(Pid) ->
    receive
        {{trace, Pid, _, _}} -> drain(Pid)
    after 300 -> ok
    end.

schedule_ins(Pid, Count) ->
    receive
        {{trace, Pid, in, _}} -> schedule_ins(Pid, Count + 1);
        {{trace, Pid, _, _}} -> schedule_ins(Pid, Count)
    after 300 -> Count
    end.
"#,
        exports = exports.join(", ")
    )
}

fn measured(term: &OwnedTerm) -> (i64, i64, i64) {
    let OwnedTerm::Tuple(elems) = term else {
        panic!("probe did not return a tuple: {term:?}");
    };
    let (OwnedTerm::Int(reds), OwnedTerm::Int(ins), OwnedTerm::Int(gcs)) =
        (&elems[0], &elems[1], &elems[2])
    else {
        panic!("probe returned {term:?}");
    };
    (*reds, *ins, *gcs)
}

fn check(cases: &[Case], seed: u64) {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = source(cases);
    let beam = reference.compile_named(MODULE, &source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    let filter = std::env::var("REDS_CASES").ok();
    let mut failures = Vec::new();
    let mut index = seed;
    for case in cases {
        for &size in case.sizes {
            index += 1;
            if filter
                .as_deref()
                .is_some_and(|f| !f.split(',').any(|c| c == case.name))
            {
                continue;
            }
            let function = function_name(case, size);
            let CallResult::Ok(expected) = reference.call(MODULE, &function, &[]) else {
                panic!("OTP {function} failed");
            };
            let actual = vm
                .eval_scheduled_reductions(MODULE, &function, &[], 1, Some(index), 4_000)
                .unwrap();
            let (expected_reds, expected_ins, expected_gcs) = measured(&expected);
            let (actual_reds, actual_ins, actual_gcs) = measured(&actual.term);
            eprintln!(
                "{function}: erl reds {expected_reds} ins {expected_ins} gcs {expected_gcs}; \
                 arinsal reds {actual_reds} ins {actual_ins} gcs {actual_gcs}"
            );
            let tolerance = SLACK_PER_SLICE * expected_ins;
            if expected_ins != actual_ins
                || !(expected_reds - tolerance..=expected_reds + tolerance).contains(&actual_reds)
            {
                failures.push(format!(
                    "{function}: erl reds {expected_reds} ins {expected_ins}, arinsal reds {actual_reds} ins {actual_ins}"
                ));
            }
        }
    }
    assert_eq!(Vec::<String>::new(), failures);
}

#[test]
fn arith_bifs_charge_like_otp() {
    check(ARITH_CASES, 0xC000);
}

#[test]
fn iolist_bifs_charge_like_otp() {
    check(IOLIST_CASES, 0xC100);
}

#[test]
fn t2b_bifs_charge_like_otp() {
    check(T2B_CASES, 0xC200);
}

#[test]
fn matching_bifs_charge_like_otp() {
    check(MATCHING_CASES, 0xC300);
}

#[test]
fn list_to_bitstring_values_match_otp_across_yields() {
    use arinsal_difftest::{CompareMode, compare};
    let source = r#"-module(reds_l2b_values).
-export([small/0, odd/0, large/0, tail/0, bad_unit/0, size/0]).

small() -> erlang:list_to_bitstring([1, <<2:3>>, [<<7:5>>, 255, <<1, 2, 3>>], <<5:7>>, 9, <<1:1>>]).

odd() -> erlang:list_to_bitstring([[<<I:3>> || I <- lists:seq(0, 7)], <<1:1>>, [[<<1, 2>>], 3, <<3:2>>]]).

large() ->
    L = [[I rem 256, <<(I rem 7):3>>, [<<I:5>>, <<1, 2, 3, 4, 5>>]] || I <- lists:seq(1, 60000)],
    B = erlang:list_to_bitstring([L, <<1:1>>]),
    {bit_size(B), erlang:phash2(B), B}.

tail() -> erlang:list_to_bitstring([1, 2 | <<3:5>>]).

bad_unit() ->
    try erlang:list_to_binary([1, <<1:3>>]) catch error:badarg -> badarg end.

size() ->
    {element(1, catch erlang:iolist_size([[1, <<1:3>>]])), element(1, catch erlang:iolist_size([1 | 2])),
     erlang:iolist_size([<<1, 2>>, 3 | <<4>>]),
     erlang:iolist_size([[I rem 256, <<I>>] || I <- lists:seq(1, 70000)])}.
"#;
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named("reds_l2b_values", source, &[])
        .unwrap();
    reference.load("reds_l2b_values", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for function in ["small", "odd", "large", "tail", "bad_unit", "size"] {
        let expected = reference.call("reds_l2b_values", function, &[]);
        let actual = vm
            .eval_scheduled("reds_l2b_values", function, &[], 1, Some(7))
            .unwrap_or_else(|error| panic!("{function}: {}", &format!("{error:?}")[..200]));
        compare(&CallResult::Ok(actual.term), &expected, CompareMode::Exact)
            .unwrap_or_else(|error| panic!("{function}: {error:?}"));
    }
}

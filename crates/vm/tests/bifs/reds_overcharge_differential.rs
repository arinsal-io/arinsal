//! Reductions charged by BIFs that Arinsal over- or under-charged against erts OTP-29.1.1.
//!
//! Every case runs one BIF call in a process whose heap is large enough that no garbage
//! collection happens inside the window, and compares the reductions consumed by the call
//! (net of an empty fun call in the same process) and the number of times the process was
//! scheduled in against the reference `erl`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
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
    /// `{M, F, A}` call-traced (local) in the measured process while the call runs.
    trace: Option<&'static str>,
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
        trace: None,
    }
}

const fn traced_case(
    name: &'static str,
    sizes: &'static [usize],
    heap_factor: usize,
    build: &'static str,
    call: &'static str,
    mfa: &'static str,
) -> Case {
    Case {
        name,
        sizes,
        heap_factor,
        build,
        call,
        trace: Some(mfa),
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

const SMALL: &[usize] = &[2, 3, 8, 16, 100];
const ETS_CASES: &[Case] = &[
    case(
        "ets_insert_set",
        TO_100K,
        6,
        "{ets:new(t, [set]), kv(N)}",
        "ets:insert(element(1, In), element(2, In))",
    ),
    case(
        "ets_insert_small",
        SMALL,
        6,
        "{ets:new(t, [set]), kv(N)}",
        "ets:insert(element(1, In), element(2, In))",
    ),
    case(
        "ets_insert_ordered",
        TO_100K,
        6,
        "{ets:new(t, [ordered_set]), kv(N)}",
        "ets:insert(element(1, In), element(2, In))",
    ),
    case(
        "ets_insert_bag",
        TO_100K,
        6,
        "{ets:new(t, [bag]), kv(N)}",
        "ets:insert(element(1, In), element(2, In))",
    ),
];

const LISTS: &[usize] = &[1, 1_000, 100_000, 400_000];
/// erl_bif_lists.c: short, long (trapping) and improper lists.
const LIST_CASES: &[Case] = &[
    case("reverse", LISTS, 4, "seq(N)", "lists:reverse(In, [])"),
    case(
        "reverse_improper",
        LISTS,
        6,
        "improper(N)",
        "catch lists:reverse(In, [])",
    ),
    case("member_miss", LISTS, 4, "seq(N)", "lists:member(0, In)"),
    case(
        "member_boxed_miss",
        LISTS,
        4,
        "seq(N)",
        "lists:member({0}, In)",
    ),
    case(
        "member_improper",
        LISTS,
        6,
        "improper(N)",
        "catch lists:member(0, In)",
    ),
    case("keyfind_miss", LISTS, 6, "kv(N)", "lists:keyfind(0, 1, In)"),
    case(
        "keyfind_float",
        LISTS,
        6,
        "kv(N)",
        "lists:keyfind(0.0, 1, In)",
    ),
    case(
        "keymember_miss",
        LISTS,
        6,
        "kv(N)",
        "lists:keymember(0, 2, In)",
    ),
    case(
        "keysearch_last",
        LISTS,
        6,
        "{kv(N), N}",
        "lists:keysearch(element(2, In), 1, element(1, In))",
    ),
    case(
        "keyfind_improper",
        LISTS,
        8,
        "kv(N) ++ x",
        "catch lists:keyfind(0, 1, In)",
    ),
    case("plusplus", LISTS, 6, "seq(N)", "In ++ [x]"),
    case("plusplus_nil", LISTS, 4, "seq(N)", "In ++ []"),
    case("append", LISTS, 6, "seq(N)", "erlang:append(In, [x])"),
    case(
        "plusplus_improper",
        LISTS,
        8,
        "improper(N)",
        "catch In ++ [x]",
    ),
    case(
        "minusminus_short_rhs",
        LISTS,
        6,
        "seq(N)",
        "In -- [1, 2, 3]",
    ),
    case(
        "minusminus_short_lhs",
        LISTS,
        6,
        "{[1, 2, 3], seq(N)}",
        "element(1, In) -- element(2, In)",
    ),
    case(
        "minusminus_set",
        LISTS,
        12,
        "{seq(N), lists:reverse(seq(N))}",
        "element(1, In) -- element(2, In)",
    ),
    case(
        "subtract_set",
        LISTS,
        12,
        "{seq(N), seq(N div 2)}",
        "erlang:subtract(element(1, In), element(2, In))",
    ),
    case(
        "minusminus_improper",
        LISTS,
        8,
        "{improper(N), [1]}",
        "catch element(1, In) -- element(2, In)",
    ),
];

const MAPS: &[usize] = &[1, 32, 33, 1_000, 100_000];
/// Above 128 keys, `erts_qsort` seeds its pivot from scheduler-local random state (up to 128 the
/// seed is fixed and only addresses vary), so constructor charges vary
/// between runs on both sides: both are sampled and their distributions compared.
const MAP_BUILD_SIZES: &[usize] = &[1, 32, 33, 1_000, 100_000];
const MAP_BUILD_REFERENCE_SAMPLES: usize = 20;
/// erl_map.c: the YCF-yielding constructors and projections, flat and hashmap.
const MAP_CASES: &[Case] = &[
    case(
        "from_list",
        MAP_BUILD_SIZES,
        10,
        "kv(N)",
        "maps:from_list(In)",
    ),
    case(
        "from_keys",
        MAP_BUILD_SIZES,
        8,
        "seq(N)",
        "maps:from_keys(In, v)",
    ),
    // Ten copies of every key: equal hashes take the region, duplicate-key and last-wins loops
    // of hashmap_from_unsorted_array (nested loops, 2 and 4 units per iteration).
    case(
        "from_list_dups",
        &[1_000, 100_000],
        10,
        "dupkv(N)",
        "maps:from_list(In)",
    ),
    case(
        "from_keys_dups",
        &[1_000, 100_000],
        8,
        "dupkeys(N)",
        "maps:from_keys(In, v)",
    ),
    // The first N keys, in trie order, of a 300000-key map: consecutive in hash order, so they
    // share their first two HAMT levels and the chunked builder runs the deep-prefix loops
    // (d < dn, collision nodes) from the start.
    case(
        "from_list_prefix",
        &[1_000],
        10,
        "prefixkv(N)",
        "maps:from_list(In)",
    ),
    case(
        "from_keys_prefix",
        &[1_000],
        8,
        "prefixkeys(N)",
        "maps:from_keys(In, v)",
    ),
    case(
        "from_list_badarg",
        MAPS,
        10,
        "kv(N) ++ [x]",
        "catch maps:from_list(In)",
    ),
    case(
        "keys",
        MAPS,
        8,
        "maps:from_keys(seq(N), v)",
        "maps:keys(In)",
    ),
    case(
        "values",
        MAPS,
        8,
        "maps:from_keys(seq(N), v)",
        "maps:values(In)",
    ),
    case("keys_badmap", &[1], 4, "seq(N)", "catch maps:keys(In)"),
];

const ONE: &[usize] = &[1];
const SELECT: &[usize] = &[1, 10_000, 100_000];
/// Long trap chains: a trap export that ran its own trap at once would recurse per slice.
const CHAIN: &[usize] = &[1, 100_000, 1_000_000];
/// bif.h BIF_TRAP*: every trap is a context switch (instr_bif.cpp, context_switch_simplified),
/// and `beam_bif_export_trap` calls the trap export on schedule-in, whichever way the trapping
/// BIF was reached (static call, apply, call trace) and whether the export is a BIF that traps
/// again or an Erlang function.
const TRAP_CASES: &[Case] = &[
    case(
        "demonitor_flush",
        ONE,
        4,
        "make_ref()",
        "erlang:demonitor(In, [flush])",
    ),
    case(
        "demonitor_flush_apply",
        ONE,
        4,
        "{erlang, make_ref()}",
        "apply(element(1, In), demonitor, [element(2, In), [flush]])",
    ),
    traced_case(
        "demonitor_flush_traced",
        ONE,
        4,
        "make_ref()",
        "erlang:demonitor(In, [flush])",
        "{erlang, demonitor, 2}",
    ),
    case(
        "reverse_apply",
        CHAIN,
        4,
        "{lists, seq(N)}",
        "apply(element(1, In), reverse, [element(2, In), []])",
    ),
    traced_case(
        "reverse_traced",
        CHAIN,
        4,
        "seq(N)",
        "lists:reverse(In, [])",
        "{lists, reverse, 2}",
    ),
    case(
        "re_run_global",
        STD,
        8,
        "begin {match, _} = re:run(<<7>>, <<7>>, [global]), bytes(N) end",
        "re:run(In, <<7>>, [global])",
    ),
    case(
        "re_run_global_apply",
        STD,
        8,
        "begin {match, _} = re:run(<<7>>, <<7>>, [global]), {re, bytes(N)} end",
        "apply(element(1, In), run, [element(2, In), <<7>>, [global]])",
    ),
    traced_case(
        "re_run_global_traced",
        STD,
        8,
        "begin {match, _} = re:run(<<7>>, <<7>>, [global]), bytes(N) end",
        "re:run(In, <<7>>, [global])",
        "{re, run, 3}",
    ),
    traced_case(
        "demonitor_flush_apply_traced",
        ONE,
        4,
        "{erlang, make_ref()}",
        "apply(element(1, In), demonitor, [element(2, In), [flush]])",
        "{erlang, demonitor, 2}",
    ),
    case(
        "ets_select_hash",
        SELECT,
        12,
        "begin T = ets:new(t, [set]), true = ets:insert(T, kv(N)), T end",
        "ets:select(In, [{'_', [], ['$_']}])",
    ),
    case(
        "ets_select_hash_apply",
        CHAIN,
        12,
        "begin T = ets:new(t, [set]), true = ets:insert(T, kv(N)), {ets, T} end",
        "apply(element(1, In), select, [element(2, In), [{'_', [], ['$_']}]])",
    ),
    case(
        "ets_select_ordered",
        SELECT,
        12,
        "begin T = ets:new(t, [ordered_set]), true = ets:insert(T, kv(N)), T end",
        "ets:select(In, [{'_', [], ['$_']}])",
    ),
    traced_case(
        "ets_select_hash_traced",
        SELECT,
        12,
        "begin T = ets:new(t, [set]), true = ets:insert(T, kv(N)), T end",
        "ets:select(In, [{'_', [], ['$_']}])",
        "{ets, select, 2}",
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
            let (measure, trace) = match case.trace {
                Some(mfa) => ("measure_traced", format!(", {mfa}")),
                None => ("measure", String::new()),
            };
            bodies.push_str(&format!(
                "{function}() ->\n    {measure}({size}, {words}, fun(N) -> {} end, fun(In) -> {} end{trace}).\n\n",
                case.build, case.call
            ));
        }
    }
    format!(
        r#"-module({MODULE}).
-export([{exports}]).

seq(N) -> lists:seq(1, N).

improper(N) -> lists:foldl(fun(I, Acc) -> [I | Acc] end, tail, lists:seq(1, N)).

flat(N) -> [I rem 256 || I <- lists:seq(1, N)].

bytes(N) -> list_to_binary([I rem 200 || I <- lists:seq(1, N)]).

kv(N) -> [{{I, I}} || I <- lists:seq(1, N)].

dupkeys(N) -> [I rem (N div 10) || I <- lists:seq(1, N)].

dupkv(N) -> [{{K, I}} || {{K, I}} <- lists:zip(dupkeys(N), lists:seq(1, N))].

prefixkeys(N) ->
    lists:sublist(maps:keys(maps:from_keys(lists:seq(1, 300000), v)), N).

prefixkv(N) -> [{{K, K}} || K <- prefixkeys(N)].

tuples(N) -> [{{I, foo, "ab", <<"x">>}} || I <- lists:seq(1, N)].

deep(N) -> [[I rem 200, <<"ab">>, [I rem 100]] || I <- lists:seq(1, N)].

big(N) -> (1 bsl (N * 64)) - 1.

{bodies}
measure(N, Words, Build, Run) ->
    measure(N, Words, Build, Run, [running]).

measure_traced(N, Words, Build, Run, MFA) ->
    erlang:trace_pattern(MFA, true, [local]),
    Result = measure(N, Words, Build, Run, [running, call]),
    erlang:trace_pattern(MFA, false, [local]),
    Result.

measure(N, Words, Build, Run, Flags) ->
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
    1 = erlang:trace(Pid, true, [{{tracer, Parent}} | Flags]),
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

/// min / median / max of one measured quantity over the samples of a case.
#[derive(Clone, Copy)]
struct Range {
    min: i64,
    median: i64,
    max: i64,
}

impl Range {
    fn of(mut values: Vec<i64>) -> Self {
        values.sort_unstable();
        Self {
            min: values[0],
            median: values[values.len() / 2],
            max: values[values.len() - 1],
        }
    }

    fn contains(&self, value: i64) -> bool {
        (self.min..=self.max).contains(&value)
    }
}

impl std::fmt::Display for Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..={} (median {})", self.min, self.max, self.median)
    }
}

struct Spread {
    reds: Range,
    ins: Range,
}

impl Spread {
    fn of(samples: &[(i64, i64, i64)]) -> Self {
        Self {
            reds: Range::of(samples.iter().map(|s| s.0).collect()),
            ins: Range::of(samples.iter().map(|s| s.1).collect()),
        }
    }
}

fn check(cases: &[Case]) {
    check_with(cases, &[]);
}

/// [`check`] against a reference node started with `erl_args`.
fn check_with(cases: &[Case], erl_args: &[&str]) {
    let reference =
        RefErl::start_with_erl_args(erl_args).expect("OTP 29.1.1 is required for this test");
    let source = source(cases);
    let beam = reference.compile_named(MODULE, &source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();

    let filter = std::env::var("REDS_CASES").ok();
    let mut failures = Vec::new();
    for case in cases {
        for &size in case.sizes {
            if filter
                .as_deref()
                .is_some_and(|f| !f.split(',').any(|c| c == case.name))
            {
                continue;
            }
            let function = function_name(case, size);
            let random_pivot = size > 128
                && matches!(
                    case.name,
                    "from_list"
                        | "from_keys"
                        | "from_list_dups"
                        | "from_keys_dups"
                        | "from_list_prefix"
                        | "from_keys_prefix"
                );
            let sample_count = if random_pivot {
                MAP_BUILD_REFERENCE_SAMPLES
            } else {
                1
            };
            let mut expected_samples = Vec::with_capacity(sample_count);
            let mut actual_samples = Vec::with_capacity(sample_count);
            for _ in 0..sample_count {
                let CallResult::Ok(expected) = reference.call(MODULE, &function, &[]) else {
                    panic!("OTP {function} failed");
                };
                expected_samples.push(measured(&expected));
                let actual = vm
                    .eval_scheduled_reductions(MODULE, &function, &[], 1, 4_000)
                    .unwrap();
                actual_samples.push(measured(&actual.term));
            }
            let expected = Spread::of(&expected_samples);
            let actual = Spread::of(&actual_samples);
            eprintln!(
                "{function}: erl reds {} ins {} gcs {}; arinsal reds {} ins {} gcs {}",
                expected.reds,
                expected.ins,
                expected_samples[0].2,
                actual.reds,
                actual.ins,
                actual_samples[0].2
            );
            let passed = if random_pivot {
                // Both runtimes draw the qsort pivot at random: compare the distributions.
                expected.reds.contains(actual.reds.median)
                    && actual.reds.contains(expected.reds.median)
                    && expected.ins.contains(actual.ins.median)
                    && actual.ins.contains(expected.ins.median)
            } else {
                let tolerance = SLACK_PER_SLICE * expected.ins.max;
                expected.ins.min == actual.ins.min
                    && (expected.reds.min - tolerance..=expected.reds.min + tolerance)
                        .contains(&actual.reds.min)
            };
            if !passed {
                failures.push(format!(
                    "{function}: erl reds {} ins {}, arinsal reds {} ins {}",
                    expected.reds, expected.ins, actual.reds, actual.ins
                ));
            }
        }
    }
    assert_eq!(Vec::<String>::new(), failures);
}

#[test]
fn arith_bifs_charge_like_otp() {
    check(ARITH_CASES);
}

#[test]
fn iolist_bifs_charge_like_otp() {
    check(IOLIST_CASES);
}

#[test]
fn t2b_bifs_charge_like_otp() {
    check(T2B_CASES);
}

#[test]
fn matching_bifs_charge_like_otp() {
    check(MATCHING_CASES);
}

// The trapping list BIFs yield on the reductions left in the slice; with one scheduler on both
// sides the slices start at the same budget.
#[test]
fn list_bifs_charge_like_otp() {
    check_with(LIST_CASES, &["+S", "1"]);
}

// The YCF driver sizes each slice from the reductions left, as the list BIFs do.
#[test]
fn map_bifs_charge_like_otp() {
    check_with(MAP_CASES, &["+S", "1"]);
}

// Each BIF_TRAP schedules the process out once, on every path to the trapping BIF.
#[test]
fn bif_traps_schedule_out_like_otp() {
    check_with(TRAP_CASES, &["+S", "1"]);
}

#[test]
fn ets_bifs_charge_like_otp() {
    check(ETS_CASES);
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
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    for function in ["small", "odd", "large", "tail", "bad_unit", "size"] {
        let expected = reference.call("reds_l2b_values", function, &[]);
        let actual = vm
            .eval_scheduled("reds_l2b_values", function, &[], 1)
            .unwrap_or_else(|error| panic!("{function}: {}", &format!("{error:?}")[..200]));
        compare(&CallResult::Ok(actual.term), &expected, CompareMode::Exact)
            .unwrap_or_else(|error| panic!("{function}: {error:?}"));
    }
}

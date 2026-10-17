use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const SEMANTICS: &str = r#"semantics() ->
    Long = lists:seq(1, 300000),
    Bad = Long ++ improper,
    T = fun(F) -> try F() catch error:R -> {err, R} end end,
    G = fun(L) when length(L) > 250000 -> big; (_) -> small end,
    Err = fun(L) -> try length(L) catch error:E:St -> {E, [{M, F, is_list(A)} || {M, F, A, _} <- [hd(St)]]} end end,
    Keep = fun(A, B, C, D) -> {A, length(B), C, D, length(B) + length(A)} end,
    Uni = [I rem 3000 + 100 || I <- lists:seq(1, 120000)],
    UniBin = unicode:characters_to_binary(Uni),
    Cut = binary:part(UniBin, 0, byte_size(UniBin) - 1),
    [unicode:characters_to_binary(Uni), unicode:characters_to_list(UniBin),
     unicode:characters_to_binary(Uni ++ [16#D800 | Uni]),
     unicode:characters_to_binary([Uni, <<255>>, Uni]),
     unicode:characters_to_binary([Uni, Cut], utf8),
     unicode:characters_to_list(Cut), unicode:characters_to_list(<<UniBin/binary, 255, UniBin/binary>>),
     unicode:characters_to_list([Uni, UniBin, [Uni | UniBin]], latin1),
     unicode:characters_to_binary(Uni, latin1), unicode:characters_to_binary([[Uni], [], [<<"x">>]]),
     unicode:characters_to_list(lists:duplicate(100000, 255), latin1),
     unicode:characters_to_list(<<(binary:copy(<<"abc">>, 70000))/binary>>),
     G(Long), G(lists:seq(1, 10)), G(Bad), Err(Bad), Err(improper),
     Keep(Long, Long, 3, 4), erlang:crc32([lists:duplicate(100000, 5), <<1, 2, 3>>, [255 | <<4>>]]),
          erlang:md5([<<1>>, lists:duplicate(70000, 7), <<2>>])]
    ++ [T(fun() -> erlang:crc32([Long, a]) end), T(fun() -> erlang:phash2(Long, 0) end),
        erlang:phash2({Long, <<1:3>>, #{a => Long}, fun() -> ok end}),
        erlang:phash2(lists:duplicate(100000, 300)),
        erlang:phash2(<<1:5, (list_to_binary(lists:duplicate(50000, 9)))/bits>>),
        erlang:phash2(Long, 4294967296)].

"#;

const MODULE: &str = "reds_size_bifs_test";

/// The interpreter counts a few more instructions around the call than BEAMASM and erts do.
const SLACK: i64 = 16;

/// Sizes of the input in the no-GC window.
const DEFAULT_SIZES: [(&str, usize); 4] = [
    ("1", 1),
    ("1k", 1_000),
    ("100k", 100_000),
    ("1m", 1_000_000),
];

/// One BIF under test: its name, how the input of size `N` is built, the call and how the
/// result is reduced to the value compared with OTP (`None` compares the result itself).
const CASES: &[(&str, &str, &str, Option<&str>)] = &[
    ("length", "lists:seq(1, N)", "erlang:length(In)", None),
    (
        "length_apply",
        "lists:seq(1, N)",
        "apply(erlang, length, [In])",
        None,
    ),
    ("crc32", "bin(N)", "erlang:crc32(In)", None),
    ("crc32_2", "bin(N)", "erlang:crc32(7, In)", None),
    ("adler32", "bin(N)", "erlang:adler32(In)", None),
    ("adler32_2", "bin(N)", "erlang:adler32(7, In)", None),
    ("md5", "bin(N)", "erlang:md5(In)", None),
    ("crc32_list", "binl(N)", "erlang:crc32(In)", None),
    ("md5_list", "binl(N)", "erlang:md5(In)", None),
    ("phash2_list", "lists:seq(1, N)", "erlang:phash2(In)", None),
    (
        "phash2_list_2",
        "lists:seq(1, N)",
        "erlang:phash2(In, 1000)",
        None,
    ),
    (
        "phash2_tuples",
        "[{I, x, y} || I <- lists:seq(1, N)]",
        "erlang:phash2(In)",
        None,
    ),
    ("phash2_bin", "bin(N)", "erlang:phash2(In)", None),
    ("phash2_str", "binl(N)", "erlang:phash2(In)", None),
    (
        "uni_to_bin",
        "uni_list(N)",
        "unicode:characters_to_binary(In)",
        None,
    ),
    (
        "uni_to_bin_ascii",
        "ascii_list(N)",
        "unicode:characters_to_binary(In)",
        None,
    ),
    (
        "uni_to_bin_latin1",
        "ascii_list(N)",
        "unicode:characters_to_binary(In, latin1)",
        None,
    ),
    (
        "uni_to_bin_bin",
        "uni_bin(N)",
        "unicode:characters_to_binary(In)",
        None,
    ),
    (
        "uni_to_bin_deep",
        "uni_deep(N)",
        "unicode:characters_to_binary(In)",
        None,
    ),
    (
        "uni_to_list_bin",
        "uni_bin(N)",
        "unicode:characters_to_list(In)",
        None,
    ),
    (
        "uni_to_list_ascii",
        "ascii_bin(N)",
        "unicode:characters_to_list(In)",
        None,
    ),
    (
        "uni_to_list_latin1",
        "ascii_bin(N)",
        "unicode:characters_to_list(In, latin1)",
        None,
    ),
    (
        "uni_to_list_list",
        "uni_list(N)",
        "unicode:characters_to_list(In)",
        None,
    ),
    (
        "uni_to_bin_chunks",
        "uni_chunks(N)",
        "unicode:characters_to_binary(In)",
        None,
    ),
    (
        "uni_to_bin_latin1_high",
        "latin1_list(N)",
        "unicode:characters_to_binary(In, latin1)",
        None,
    ),
    (
        "uni_to_list_chunks",
        "uni_chunks(N)",
        "unicode:characters_to_list(In)",
        None,
    ),
    (
        "uni_to_list_latin1_high",
        "latin1_bin(N)",
        "unicode:characters_to_list(In, latin1)",
        None,
    ),
    (
        "uni_to_list_bin_mixed",
        "uni_bin(N)",
        "unicode:characters_to_list(In, utf8)",
        None,
    ),
];

/// Large inputs are only run where the call is linear and the structure is light.
/// `REDS_SIZES=200000,300000` replaces the sizes for a local investigation.
fn sizes() -> Vec<(String, usize)> {
    match std::env::var("REDS_SIZES") {
        Ok(list) => list
            .split(',')
            .filter_map(|size| size.trim().parse::<usize>().ok())
            .map(|size| (size.to_string(), size))
            .collect(),
        Err(_) => DEFAULT_SIZES
            .iter()
            .map(|(label, size)| (label.to_string(), *size))
            .collect(),
    }
}

fn skipped(name: &str, size: usize) -> bool {
    size > 100_000
        && (name.ends_with("_list") || name.ends_with("_str") || name.starts_with("ets_"))
}

fn source() -> String {
    let mut exports = Vec::new();
    let mut bodies = String::new();
    for (name, build, call, post) in CASES {
        for (label, size) in sizes() {
            if skipped(name, size) {
                continue;
            }
            let function = format!("{name}_{label}");
            let post = match post {
                Some(post) => format!("fun post_{post}/1"),
                None => "fun post_hash/1".to_string(),
            };
            exports.push(format!("{function}/0"));
            bodies.push_str(&format!(
                "{function}() ->\n    measure({size}, fun(N) -> {build} end, fun(In) -> {call} end, {post}).\n\n"
            ));
        }
    }
    format!(
        r#"-module({MODULE}).
-export([{exports}, semantics/0]).

{semantics}
bin(N) -> binary:copy(<<0, 1, 2, 3, 255, 17, 9, 200>>, (N + 7) div 8).

binl(N) -> [I rem 256 || I <- lists:seq(1, N)].

ets_set(N) -> ets_fill(ets:new(t, [set, public]), N).

ets_ordered(N) -> ets_fill(ets:new(t, [ordered_set, public]), N).

ets_fill(T, N) ->
    true = ets:insert(T, [{{I, I}} || I <- lists:seq(1, N)]),
    T.

uni_list(N) -> [uni_char(I) || I <- lists:seq(1, N)].

uni_char(I) ->
    case I rem 4 of
        0 -> 16#10000 + I rem 4096;
        1 -> 16#800 + I rem 4096;
        2 -> 16#80 + I rem 1000;
        3 -> 97 + I rem 26
    end.

ascii_list(N) -> [97 + I rem 26 || I <- lists:seq(1, N)].

uni_bin(N) -> unicode:characters_to_binary(uni_list(N)).

uni_chunks(N) -> chunks(unicode:characters_to_binary(uni_list(N)), 37).

chunks(<<>>, _) -> [];
chunks(Bin, K) when byte_size(Bin) =< K -> [Bin];
chunks(Bin, K) ->
    {{A, B}} = split_binary(Bin, K),
    [A | chunks(B, K)].

latin1_list(N) -> [I rem 256 || I <- lists:seq(1, N)].

latin1_bin(N) -> list_to_binary(latin1_list(N)).

ascii_bin(N) -> list_to_binary(ascii_list(N)).

uni_deep(N) -> uni_deep(uni_list(N), 100).

uni_deep([], _) -> [];
uni_deep(L, K) ->
    try lists:split(K, L) of
        {{A, B}} -> [A | uni_deep(B, K)]
    catch
        error:_ -> [L]
    end.

send_to(Msg) ->
    Rx = spawn(fun() -> receive stop -> ok end end),
    {{Rx, Msg}}.

send({{Rx, Msg}}) -> Rx ! Msg.

send_erlang({{Rx, Msg}}) -> erlang:send(Rx, Msg).

post_hash(R) when is_integer(R) -> R;
post_hash(R) -> erlang:phash2(R, 4294967296).

post_length(R) -> length(R).

post_chunk({{Rows, _}}) -> length(Rows).

post_sent(_) -> sent.

{bodies}
measure(N, Build, Run, Post) ->
    Parent = self(),
    Words = 8 * N + 100000,
    Pid = spawn_opt(fun() ->
        In = Build(N),
        Parent ! ready,
        receive go -> ok end,
        erlang:yield(),
        {{reductions, R0}} = process_info(self(), reductions),
        Result = Run(In),
        {{reductions, R1}} = process_info(self(), reductions),
        {{garbage_collection, GC}} = process_info(self(), garbage_collection),
        erlang:yield(),
        Parent ! {{measured, R1 - R0, true, proplists:get_value(minor_gcs, GC), Post(Result)}},
        erlang:yield()
    end, [{{min_heap_size, Words}}, {{min_bin_vheap_size, Words}}]),
    1 = erlang:trace(Pid, true, [running, {{tracer, Parent}}]),
    receive ready -> ok after 20000 -> exit(no_ready) end,
    drain(Pid),
    Pid ! go,
    receive
        {{measured, Reds, true, Gcs, Value}} -> {{Reds, schedule_ins(Pid, 0), Gcs, Value}}
    after 20000 -> timeout
    end.

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
        exports = exports.join(", "),
        semantics = SEMANTICS
    )
}

fn measured(term: &OwnedTerm) -> (i64, i64, i64, &OwnedTerm) {
    let OwnedTerm::Tuple(elems) = term else {
        panic!("probe did not return a tuple: {term:?}");
    };
    let (OwnedTerm::Int(reds), OwnedTerm::Int(ins), OwnedTerm::Int(gcs)) =
        (&elems[0], &elems[1], &elems[2])
    else {
        panic!("probe returned {term:?}");
    };
    (*reds, *ins, *gcs, &elems[3])
}

fn functions() -> Vec<String> {
    let mut names = Vec::new();
    for (name, _, _, _) in CASES {
        for (label, size) in sizes() {
            if skipped(name, size) {
                continue;
            }
            names.push(format!("{name}_{label}"));
        }
    }
    names
}

#[test]
fn trapped_calls_return_what_otp_returns() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = source();
    let beam = reference.compile_named(MODULE, &source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let CallResult::Ok(expected) = reference.call(MODULE, "semantics", &[]) else {
        panic!("OTP semantics failed");
    };
    let actual = vm
        .eval_scheduled_reductions(MODULE, "semantics", &[], 1, Some(0xB5FF), 4_000)
        .unwrap();
    assert_eq!(expected, actual.term);
}

#[test]
fn size_proportional_bifs_charge_and_yield_like_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let source = source();
    let beam = reference.compile_named(MODULE, &source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    let mut failures = Vec::new();
    let filter = std::env::var("REDS_FILTER").unwrap_or_default();
    for (index, function) in functions().iter().enumerate() {
        if !function.contains(&filter) {
            continue;
        }
        let CallResult::Ok(expected) = reference.call(MODULE, function, &[]) else {
            panic!("OTP {function} failed");
        };
        let actual = vm
            .eval_scheduled_reductions(MODULE, function, &[], 1, Some(0xB500 + index as u64), 4_000)
            .unwrap();
        let (expected_reds, expected_ins, expected_gcs, expected_value) = measured(&expected);
        let (actual_reds, actual_ins, actual_gcs, actual_value) = measured(&actual.term);
        eprintln!(
            "{function}: erl reds {expected_reds} ins {expected_ins} gcs {expected_gcs}; \
             arinsal reds {actual_reds} ins {actual_ins} gcs {actual_gcs}"
        );
        let tolerance = SLACK + 4 * expected_ins;
        if expected_value != actual_value {
            failures.push(format!("{function}: the result differs from OTP"));
        }
        // OTP sometimes takes one extra schedule-in (and the 4 reductions it costs) on the long
        // latin1 and unicode conversions; it never takes fewer.
        let ins_slack = i64::from(expected_ins > 5);
        if !(0..=ins_slack).contains(&(expected_ins - actual_ins))
            || !(expected_reds - tolerance..=expected_reds + tolerance).contains(&actual_reds)
        {
            failures.push(format!(
                "{function}: erl reds {expected_reds} ins {expected_ins}, arinsal reds {actual_reds} ins {actual_ins}"
            ));
        }
    }
    assert_eq!(Vec::<String>::new(), failures);
}

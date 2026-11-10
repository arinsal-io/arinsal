//! Reductions, slice budget and GC timing of BIFs reached through `apply/3`, `apply/2` and an
//! export fun, against erts OTP-29.1.1.
//!
//! erts charges such a call only the BIF's own `BUMP_REDS` (the apply and the export's
//! `call_bif_mfa` stub take nothing from FCALLS) and collects after the BIF when the heap
//! fragments call for it. A fresh process runs `N` applies of a size-proportional BIF; the
//! test compares the reductions it used, how often it was scheduled in, and its minor GCs.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "reds_apply_bif_test";

/// A case: name, `N` applies, the BIF's module and function, the builder of `In`, the call
/// (with `In`, `M` and `F` bound), and the process's `min_heap_size`.
struct Case {
    name: &'static str,
    n: usize,
    module: &'static str,
    function: &'static str,
    build: &'static str,
    call: &'static str,
    words: usize,
}

const BIG: usize = 1_000_000;
const SMALL: usize = 233;

const fn case(
    name: &'static str,
    n: usize,
    (module, function): (&'static str, &'static str),
    build: &'static str,
    call: &'static str,
    words: usize,
) -> Case {
    Case {
        name,
        n,
        module,
        function,
        build,
        call,
        words,
    }
}

/// `In` is the whole argument list, so `apply(M, F, In)` stays a variable `i_apply` (the
/// runtime path) and `apply(M, F, [X])` a fixed `apply 1` (the export's native entry).
// Not asserted yet (open deviations on other paths, see the apply_bif_charge_gc report):
// lists:member/2 through a variable apply/3 (trapping handler path),
// tuple_to_list/1, setelement/3 and bitstring_to_list/1 (the BIFs' own charges), and
// list_to_tuple/1 through apply/2 of an export fun.
const CASES: &[Case] = &[
    // Variable-arity apply/3: the export of a plain BIF without native code.
    case(
        "list_to_tuple_var",
        4_000,
        ("erlang", "list_to_tuple"),
        "[lists:seq(1, 64)]",
        "apply(M, F, In)",
        SMALL,
    ),
    case(
        "make_tuple_var",
        4_000,
        ("erlang", "make_tuple"),
        "[64, x]",
        "apply(M, F, In)",
        SMALL,
    ),
    // Variable-arity apply/3 of a trapping BIF: the handler path.
    case(
        "length_var",
        3_000,
        ("erlang", "length"),
        "[lists:seq(1, 2000)]",
        "apply(M, F, In)",
        BIG,
    ),
    // Fixed-arity apply, apply/2 of an export fun, and a call of an export fun.
    case(
        "list_to_tuple_fixed",
        4_000,
        ("erlang", "list_to_tuple"),
        "lists:seq(1, 64)",
        "apply(M, F, [In])",
        SMALL,
    ),
    case(
        "member_fixed",
        3_000,
        ("lists", "member"),
        "lists:seq(1, 300)",
        "apply(M, F, [1000, In])",
        BIG,
    ),
    case(
        "keymember_fixed",
        2_000,
        ("lists", "keymember"),
        "[{I, I} || I <- lists:seq(1, 500)]",
        "apply(M, F, [1000, 1, In])",
        BIG,
    ),
    case(
        "length_apply2",
        3_000,
        ("erlang", "length"),
        "[lists:seq(1, 2000)]",
        "apply(fun M:F/1, In)",
        BIG,
    ),
    case(
        "keyfind_export_fun",
        3_000,
        ("lists", "keyfind"),
        "[{I, I} || I <- lists:seq(1, 200)]",
        "(fun M:F/3)(400, 1, In)",
        BIG,
    ),
];

fn source() -> String {
    let mut exports = Vec::new();
    let mut bodies = String::new();
    for case in CASES {
        let Case {
            name,
            n,
            module,
            function,
            build,
            call,
            words,
        } = case;
        exports.push(format!("{name}/0"));
        bodies.push_str(&format!(
            "{name}() ->\n    measure({n}, fun() -> {build} end, \
             fun(In, M, F) -> {call} end, {module}, {function}, {words}).\n\n"
        ));
    }
    format!(
        r#"-module({MODULE}).
-export([{exports}]).

{bodies}
measure(N, Build, Run, M, F, Words) ->
    Parent = self(),
    Pid = spawn_opt(fun() ->
        In = Build(),
        Parent ! ready,
        receive go -> ok end,
        erlang:yield(),
        {{garbage_collection, GC0}} = process_info(self(), garbage_collection),
        {{reductions, R0}} = process_info(self(), reductions),
        loop(N, Run, In, M, F),
        {{reductions, R1}} = process_info(self(), reductions),
        {{garbage_collection, GC1}} = process_info(self(), garbage_collection),
        Gcs = proplists:get_value(minor_gcs, GC1) - proplists:get_value(minor_gcs, GC0),
        Parent ! {{measured, R1 - R0, Gcs}}
    end, [{{min_heap_size, Words}}]),
    1 = erlang:trace(Pid, true, [running, {{tracer, Parent}}]),
    receive ready -> ok after 60000 -> exit(no_ready) end,
    drain(Pid),
    Pid ! go,
    receive
        {{measured, Reds, Gcs}} -> {{Reds, schedule_ins(Pid, 0), Gcs}}
    after 60000 -> timeout
    end.

loop(0, _Run, _In, _M, _F) -> ok;
loop(K, Run, In, M, F) ->
    _ = Run(In, M, F),
    loop(K - 1, Run, In, M, F).

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

#[test]
fn apply_bif_reductions_slices_and_gc_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, &source(), &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let mut expected_all = Vec::new();
    let mut actual_all = Vec::new();
    for (index, name) in CASES.iter().map(|case| case.name).enumerate() {
        let CallResult::Ok(expected) = reference.call(MODULE, name, &[]) else {
            panic!("OTP {name} failed");
        };
        let actual = vm
            .eval_scheduled_reductions(MODULE, name, &[], 1, Some(0xA900 + index as u64), 4_000)
            .unwrap();
        let expected = measured(&expected);
        let actual = measured(&actual.term);
        eprintln!("{name}: erl (reds, ins, gcs) {expected:?}; arinsal {actual:?}");
        expected_all.push((name, expected));
        actual_all.push((name, actual));
    }
    assert_eq!(expected_all, actual_all);
}

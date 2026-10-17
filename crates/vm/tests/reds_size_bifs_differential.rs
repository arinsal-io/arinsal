use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "reds_size_bifs_test";

/// The interpreter counts a few more instructions around the call than BEAMASM and erts do.
const SLACK: i64 = 16;

/// Sizes of the input in the no-GC window.
const SIZES: [(&str, usize); 4] = [
    ("1", 1),
    ("1k", 1_000),
    ("100k", 100_000),
    ("1m", 1_000_000),
];

/// One BIF under test: its name, how the input of size `N` is built and the call.
const CASES: &[(&str, &str, &str)] = &[
    ("crc32", "bin(N)", "erlang:crc32(In)"),
    ("crc32_2", "bin(N)", "erlang:crc32(7, In)"),
    ("adler32", "bin(N)", "erlang:adler32(In)"),
    ("adler32_2", "bin(N)", "erlang:adler32(7, In)"),
    ("md5", "bin(N)", "erlang:md5(In)"),
    ("crc32_list", "binl(N)", "erlang:crc32(In)"),
    ("md5_list", "binl(N)", "erlang:md5(In)"),
];

fn source() -> String {
    let mut exports = Vec::new();
    let mut bodies = String::new();
    for (name, build, call) in CASES {
        for (label, size) in SIZES {
            if size > 100_000 && name.ends_with("_list") {
                continue;
            }
            let function = format!("{name}_{label}");
            exports.push(format!("{function}/0"));
            bodies.push_str(&format!(
                "{function}() ->\n    measure({size}, fun(N) -> {build} end, fun(In) -> {call} end).\n\n"
            ));
        }
    }
    format!(
        r#"-module({MODULE}).
-export([{exports}]).

bin(N) -> binary:copy(<<0, 1, 2, 3, 255, 17, 9, 200>>, (N + 7) div 8).

binl(N) -> [I rem 256 || I <- lists:seq(1, N)].

{bodies}
measure(N, Build, Run) ->
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
        Parent ! {{measured, R1 - R0, is_integer(Result) orelse is_binary(Result),
                  proplists:get_value(minor_gcs, GC)}}
    end, [{{min_heap_size, Words}}, {{min_bin_vheap_size, Words}}]),
    1 = erlang:trace(Pid, true, [running, {{tracer, Parent}}]),
    receive ready -> ok after 20000 -> exit(no_ready) end,
    drain(Pid),
    Pid ! go,
    receive
        {{measured, Reds, true, Gcs}} -> {{Reds, schedule_ins(Pid, 0), Gcs}}
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

fn functions() -> Vec<String> {
    let mut names = Vec::new();
    for (name, _, _) in CASES {
        for (label, size) in SIZES {
            if size > 100_000 && name.ends_with("_list") {
                continue;
            }
            names.push(format!("{name}_{label}"));
        }
    }
    names
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
    for (index, function) in functions().iter().enumerate() {
        let CallResult::Ok(expected) = reference.call(MODULE, function, &[]) else {
            panic!("OTP {function} failed");
        };
        let actual = vm
            .eval_scheduled_reductions(MODULE, function, &[], 1, Some(0xB500 + index as u64), 4_000)
            .unwrap();
        let (expected_reds, expected_ins, expected_gcs) = measured(&expected);
        let (actual_reds, actual_ins, actual_gcs) = measured(&actual.term);
        eprintln!(
            "{function}: erl reds {expected_reds} ins {expected_ins} gcs {expected_gcs}; \
             arinsal reds {actual_reds} ins {actual_ins} gcs {actual_gcs}"
        );
        let tolerance = SLACK + 4 * expected_ins;
        if expected_ins != actual_ins
            || !(expected_reds - tolerance..=expected_reds + tolerance).contains(&actual_reds)
        {
            failures.push(format!(
                "{function}: erl reds {expected_reds} ins {expected_ins}, arinsal reds {actual_reds} ins {actual_ins}"
            ));
        }
    }
    assert_eq!(Vec::<String>::new(), failures);
}

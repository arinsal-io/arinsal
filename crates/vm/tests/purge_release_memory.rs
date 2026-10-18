//! Repeated purge releases code and literal storage like OTP 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, VecHeap, from_owned};
use arinsal_vm::Vm;

const PROBE: &str = r#"
-module(purge_release_probe).
-export([measure/2]).

measure(Bin, Count) ->
    ensure_purger(),
    settle(),
    Before = observe(),
    churn(Bin, Count),
    settle(),
    {Before, observe()}.

churn(_, 0) -> ok;
churn(Bin, Count) ->
    {module, purge_release_target} = erlang:load_module(purge_release_target, Bin),
    true = erlang:delete_module(purge_release_target),
    true = erlang:purge_module(purge_release_target),
    churn(Bin, Count - 1).

settle() ->
    erts_debug:set_internal_state(available_internal_state, true),
    erlang:garbage_collect(),
    receive after 1 -> ok end,
    erts_debug:set_internal_state(wait, deallocations),
    erts_debug:set_internal_state(wait, deallocations),
    ok.

ensure_purger() ->
    case whereis(erts_code_purger) of
        undefined ->
            spawn(erts_code_purger, start, []),
            wait_purger();
        _ -> ok
    end.

wait_purger() ->
    case whereis(erts_code_purger) of
        undefined -> receive after 10 -> ok end, wait_purger();
        _ -> ok
    end.

observe() ->
    {erlang:memory(code), erlang:memory(total), erlang:memory(binary),
     byte_size(erlang:system_info(loaded))}.
"#;

fn integer(term: &OwnedTerm) -> i64 {
    match term {
        OwnedTerm::Int(value) => *value,
        other => panic!("expected integer memory observation, got {other:?}"),
    }
}

fn metrics(term: &OwnedTerm) -> [i64; 4] {
    let OwnedTerm::Tuple(fields) = term else {
        panic!("expected memory observation tuple, got {term:?}");
    };
    similar_asserts::assert_eq!(fields.len(), 4);
    std::array::from_fn(|index| integer(&fields[index]))
}

fn observed_pair(term: &OwnedTerm) -> ([i64; 4], [i64; 4]) {
    let OwnedTerm::Tuple(fields) = term else {
        panic!("expected before/after tuple, got {term:?}");
    };
    similar_asserts::assert_eq!(fields.len(), 2);
    (metrics(&fields[0]), metrics(&fields[1]))
}

#[test]
fn one_thousand_large_literal_purges_match_erts_memory_growth() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping purge memory differential test");
        return;
    };
    let literal = "purge-literal-".repeat(8192);
    let target = reference
        .compile_named(
            "purge_release_target",
            &format!(
                "-module(purge_release_target).\n-export([value/0]).\nvalue() -> <<\"{literal}\">>.\n"
            ),
            &[],
        )
        .expect("compile large literal module");
    let probe = reference
        .compile_named("purge_release_probe", PROBE, &[])
        .expect("compile purge probe");
    reference.load("purge_release_probe", &probe).unwrap();

    let mut vm = Vm::new([]);
    vm.load_bytes(&probe).unwrap();
    let mut input_heap = VecHeap::new();
    let binary = from_owned(&OwnedTerm::Binary(target.clone()), &mut input_heap).unwrap();
    let count = Term::small(100).unwrap();
    let mut first_expected = None;
    let mut last_expected = None;
    let mut first_actual = None;
    let mut last_actual = None;

    for _ in 0..10 {
        let expected = reference.call(
            "purge_release_probe",
            "measure",
            &[OwnedTerm::Binary(target.clone()), OwnedTerm::Int(100)],
        );
        let CallResult::Ok(expected) = expected else {
            panic!("OTP purge memory probe failed: {expected:?}");
        };
        let (before, after) = observed_pair(&expected);
        first_expected.get_or_insert(before);
        last_expected = Some(after);

        let actual = vm
            .eval_scheduled("purge_release_probe", "measure", &[binary, count], 1, None)
            .unwrap_or_else(|error| panic!("Arinsal purge memory probe failed: {error}"));
        let (before, after) = observed_pair(&actual.term);
        first_actual.get_or_insert(before);
        last_actual = Some(after);
    }

    let first_expected = first_expected.unwrap();
    let last_expected = last_expected.unwrap();
    let first_actual = first_actual.unwrap();
    let last_actual = last_actual.unwrap();
    let expected_growth = std::array::from_fn::<_, 4, _>(|index| {
        last_expected[index].saturating_sub(first_expected[index])
    });
    let actual_growth = std::array::from_fn::<_, 4, _>(|index| {
        last_actual[index].saturating_sub(first_actual[index])
    });

    for (index, name, limit) in [
        (0, "code", 256 * 1024),
        (1, "total", 2 * 1024 * 1024),
        (2, "binary", 256 * 1024),
        (3, "system_info(loaded)", 1024),
    ] {
        assert!(
            actual_growth[index] <= expected_growth[index].max(0) + limit,
            "{name} growth exceeds OTP: OTP {} bytes, Arinsal {} bytes (headroom {limit})",
            expected_growth[index],
            actual_growth[index]
        );
    }
}

//! Repeated purge releases code and literal storage like OTP 29.1.1.

use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, VecHeap, from_owned};
use arinsal_vm::Vm;

const PROBE: &str = r#"
-module(purge_release_probe).
-export([measure/2, measure_workers/2]).

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

measure_workers(Bin, Count) ->
    ensure_purger(),
    settle_once(),
    Before = memory_binary(),
    {module, purge_release_target} = erlang:load_module(purge_release_target, Bin),
    Initial = purge_release_target:binary(),
    Size = byte_size(Initial),
    Check = erlang:md5(Initial),
    {refc_binary, Size, _, _} = erts_debug:get_internal_state({binary_info, Initial}),
    true = erlang:delete_module(purge_release_target),
    false = erlang:check_process_code(self(), purge_release_target),
    true = erlang:purge_module(purge_release_target),
    churn_workers(Bin, Check, Count),
    wait_literal_collector(),
    settle_once(),
    {Before, memory_binary()}.

%% code_SUITE waits once; a second wait must not be needed to see the frees.
settle_once() ->
    erts_debug:set_internal_state(available_internal_state, true),
    erlang:garbage_collect(),
    erts_debug:set_internal_state(wait, deallocations),
    ok.

memory_binary() ->
    try erlang:memory(binary) catch error:notsup -> 0 end.

churn_workers(_, _, 0) -> ok;
churn_workers(Bin, Check, Count) ->
    {module, purge_release_target} = erlang:load_module(purge_release_target, Bin),
    Parent = self(),
    Workers = [spawn_link(fun() -> hold_literal(Parent, Check, NumRefs) end)
               || NumRefs <- lists:seq(1, 10)],
    [receive {started, Pid} -> ok after 5000 -> exit({timeout, started, Pid}) end
     || Pid <- Workers],
    true = erlang:delete_module(purge_release_target),
    Checkers = [spawn_monitor(fun() ->
                                  false = erlang:check_process_code(Pid, purge_release_target)
                              end) || Pid <- Workers],
    [receive {'DOWN', Ref, process, Checker, normal} -> ok
     after 5000 -> exit({timeout, checker_down, Checker}) end
     || {Checker, Ref} <- Checkers],
    true = erlang:purge_module(purge_release_target),
    [begin monitor(process, Pid), Pid ! purged end || Pid <- Workers],
    [receive {'DOWN', Ref, process, Pid, normal} -> ok
     after 5000 -> exit({timeout, worker_down, Pid}) end
     || Pid <- Workers],
    churn_workers(Bin, Check, Count - 1).

hold_literal(Parent, Check, NumRefs) ->
    Bin = purge_release_target:binary(),
    Bins = lists:duplicate(NumRefs, Bin),
    {bits, Bits} = purge_release_target:bits(),
    Parent ! {started, self()},
    receive
        purged ->
            true = (erlang:md5(Bin) =:= Check),
            [Bin = B || B <- Bins],
            <<42:13, Bin/binary>> = Bits,
            erlang:garbage_collect()
    end.

wait_literal_collector() ->
    case find_literal_collector(processes()) of
        undefined -> ok;
        Pid ->
            Ref = make_ref(),
            Pid ! {get_status, Ref, self()},
            receive
                {Ref, idle} -> ok;
                {Ref, working} ->
                    receive after 1 -> ok end,
                    wait_literal_collector()
            after 5000 -> exit(literal_collector_timeout)
            end
    end.

find_literal_collector([]) -> undefined;
find_literal_collector([Pid | Pids]) ->
    case process_info(Pid, initial_call) of
        {initial_call, {erts_literal_area_collector, start, 0}} -> Pid;
        _ -> find_literal_collector(Pids)
    end.
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

#[test]
fn literal_binaries_held_by_processes_are_released_after_purge() {
    let reference = RefErl::start().expect("OTP 29.1.1 erl is required");
    let target_source =
        include_str!("../../../tests/otp/erts/emulator/test/code_SUITE_data/literals.erl");
    let source_path =
        std::env::temp_dir().join(format!("arinsal-purge-literals-{}.erl", std::process::id()));
    std::fs::write(&source_path, target_source).expect("write literal module source");
    let compiled = reference.eval(&format!(
        "{{ok, literals, Beam}} = compile:file(\"{}\", [binary]), Beam",
        source_path.display()
    ));
    let _ = std::fs::remove_file(&source_path);
    let target = match compiled.expect("compile large literal module") {
        OwnedTerm::Binary(ref binary) => binary.clone(),
        other => panic!("expected compiled BEAM binary, got {other:?}"),
    };
    let probe_source = PROBE.replace("purge_release_target", "literals");
    let probe = reference
        .compile_named("purge_release_probe", &probe_source, &[])
        .expect("compile purge probe");
    reference.load("purge_release_probe", &probe).unwrap();

    let mut vm = Vm::new([]);
    vm.load_bytes(&probe).expect("load probe");
    let mut input_heap = VecHeap::new();
    let binary = from_owned(&OwnedTerm::Binary(target.clone()), &mut input_heap).unwrap();
    let workers = std::thread::available_parallelism().map_or(1, usize::from);
    let count = Term::small(10).unwrap();
    let expected = reference
        .call_opts(
            "purge_release_probe",
            "measure_workers",
            &[OwnedTerm::Binary(target), OwnedTerm::Int(10)],
            &CallOptions {
                timeout_ms: Some(30_000),
                ..CallOptions::default()
            },
        )
        .result;
    let CallResult::Ok(expected) = expected else {
        panic!("OTP worker literal purge probe failed: {expected:?}");
    };
    let actual = vm
        .eval_scheduled(
            "purge_release_probe",
            "measure_workers",
            &[binary, count],
            workers,
            None,
        )
        .unwrap_or_else(|error| panic!("Arinsal worker literal purge probe failed: {error}"));

    let binary_pair = |term: &OwnedTerm| {
        let OwnedTerm::Tuple(fields) = term else {
            panic!("expected binary memory pair, got {term:?}");
        };
        assert_eq!(fields.len(), 2);
        let [OwnedTerm::Int(before), OwnedTerm::Int(after)] = fields.as_slice() else {
            panic!("expected integer binary memory pair, got {fields:?}");
        };
        (*before, *after)
    };
    let (expected_before, expected_after) = binary_pair(&expected);
    let (actual_before, actual_after) = binary_pair(&actual.term);
    let expected_growth = expected_after.saturating_sub(expected_before).max(0);
    let actual_growth = actual_after.saturating_sub(actual_before).max(0);
    eprintln!(
        "worker literal binary growth: OTP {expected_growth} bytes, Arinsal {actual_growth} bytes"
    );
    assert!(
        actual_growth <= expected_growth + 64 * 1024,
        "binary growth exceeds OTP after worker-held purges: OTP {expected_growth} bytes, Arinsal {actual_growth} bytes"
    );
}

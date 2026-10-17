use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(reds_after_bif).
-export([run/0]).
id(X) -> X.
l_plain(0) -> ok;
l_plain(I) -> l_plain(I - 1).
l_sysinfo(0) -> ok;
l_sysinfo(I) -> erlang:system_info(schedulers), l_sysinfo(I - 1).
l_ostype(0) -> ok;
l_ostype(I) -> os:type(), l_ostype(I - 1).
l_upd_exact(0, _) -> ok;
l_upd_exact(I, M) -> _ = M#{a := I, b := I}, l_upd_exact(I - 1, M).
l_upd_assoc(0, _) -> ok;
l_upd_assoc(I, M) -> _ = M#{c => I, d => I, e => I}, l_upd_assoc(I - 1, M).
l_upd_one(0, _) -> ok;
l_upd_one(I, M) -> _ = M#{a := I}, l_upd_one(I - 1, M).
l_cat(0, _, _) -> ok;
l_cat(I, A, B) -> _ = <<A/binary, B/binary>>, l_cat(I - 1, A, B).
l_append(0, _) -> ok;
l_append(I, B) -> _ = <<B/binary, 7>>, l_append(I - 1, B).
l_format(0) -> ok;
l_format(I) -> _ = io_lib:format("~w ~s", [I, "x"]), l_format(I - 1).
cases() ->
    M = id(#{a => 1, b => 2}),
    A = id(<<"abc">>),
    B = id(<<"defg">>),
    [{plain, fun() -> l_plain(20000) end},
     {system_info, fun() -> l_sysinfo(20000) end},
     {os_type, fun() -> l_ostype(20000) end},
     {map_update_exact_two, fun() -> l_upd_exact(20000, M) end},
     {map_update_assoc_three, fun() -> l_upd_assoc(20000, M) end},
     {map_update_exact_one, fun() -> l_upd_one(20000, M) end},
     {binary_concat, fun() -> l_cat(20000, A, B) end},
     {binary_append, fun() -> l_append(20000, A) end},
     {io_lib_format, fun() -> l_format(2000) end}].
observe({Name, Fun}) ->
    Parent = self(),
    Pid = spawn_opt(fun() ->
        receive start ->
            {reductions, Before} = process_info(self(), reductions),
            _ = Fun(),
            {reductions, After} = process_info(self(), reductions),
            Parent ! {done, self(), After - Before}
        end
    end, [{min_heap_size, 4000000}]),
    1 = erlang:trace(Pid, true, [running, {tracer, Parent}]),
    Pid ! start,
    receive
        {done, Pid, Delta} ->
            Ref = erlang:trace_delivered(Pid),
            {Name, Delta, count_in(Pid, Ref, 0)}
    after 60000 ->
        exit(Pid, kill),
        {Name, timeout, 0}
    end.
count_in(Pid, Ref, Count) ->
    receive
        {trace, Pid, in, _} -> count_in(Pid, Ref, Count + 1);
        {trace_delivered, Pid, Ref} -> Count;
        _ -> count_in(Pid, Ref, Count)
    after 60000 ->
        0
    end.
run() -> [observe(Case) || Case <- cases()].
"#;

fn rows(term: &OwnedTerm) -> Vec<(String, i64, i64)> {
    let OwnedTerm::List { elems, .. } = term else {
        panic!("not a list: {term:?}");
    };
    elems
        .iter()
        .map(|elem| {
            let OwnedTerm::Tuple(fields) = elem else {
                panic!("not a tuple: {elem:?}");
            };
            let [
                OwnedTerm::Atom(name),
                OwnedTerm::Int(reds),
                OwnedTerm::Int(ins),
            ] = &fields[..]
            else {
                panic!("unexpected row: {elem:?}");
            };
            (name.clone(), *reds, *ins)
        })
        .collect()
}

// Loops around instructions and BIFs that publish the process header again must charge their
// reductions and be preempted like on erts.
#[test]
fn reductions_and_preemption_survive_bif_and_instruction_helpers() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping reductions differential test");
        return;
    };
    let beam = reference
        .compile_named("reds_after_bif", SOURCE, &[])
        .unwrap();
    reference.load("reds_after_bif", &beam).unwrap();
    let CallResult::Ok(expected) = reference.call("reds_after_bif", "run", &[]) else {
        panic!("reference run failed");
    };

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("reds_after_bif", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("reductions run: {error}"));

    let (expected, actual) = (rows(&expected), rows(&actual.term));
    assert_eq!(expected.len(), actual.len());
    let mut mismatches = Vec::new();
    for ((name, want_reds, want_ins), (_, got_reds, got_ins)) in expected.iter().zip(&actual) {
        assert!(
            *want_reds > 10_000,
            "{name}: reference reductions {want_reds} too small"
        );
        if (want_reds - got_reds).abs() > *want_reds / 100 {
            mismatches.push(format!("{name}: reductions {got_reds}, erts {want_reds}"));
        }
        if (want_ins - got_ins).abs() > 1 + want_ins / 50 {
            mismatches.push(format!("{name}: schedule-ins {got_ins}, erts {want_ins}"));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

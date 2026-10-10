use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

#[test]
fn yield_emits_one_schedule_out_and_in_pair_per_call() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping yield trace differential test");
        return;
    };
    let source = r#"
-module(yield_trace).
-export([run/0]).
run() ->
    Parent = self(),
    Pid = spawn(fun() ->
        receive go ->
            {ok, true} = call_yield(middle),
            true = call_yield(final),
            true = call_yield(),
            true = apply(erlang, yield, []),
            exit(normal)
        end
    end),
    1 = erlang:trace(Pid, true, [running, procs, {tracer, Parent}]),
    Pid ! go,
    collect(Pid, []).
call_yield(middle) -> {ok, erlang:yield()};
call_yield(final) -> case self() of Self when is_pid(Self) -> erlang:yield() end.
call_yield() -> erlang:yield().
collect(Pid, Acc) ->
    receive
        {trace, Pid, in, _} -> collect(Pid, [in | Acc]);
        {trace, Pid, out, _} -> collect(Pid, [out | Acc]);
        {trace, Pid, exit, _} -> lists:reverse([exit | Acc])
    after 5000 -> timeout
    end.
"#;
    let beam = reference.compile_named("yield_trace", source, &[]).unwrap();
    reference.load("yield_trace", &beam).unwrap();
    let expected = reference.call("yield_trace", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("yield_trace", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("yield trace run: {error}"));

    assert_eq!(expected, CallResult::Ok(actual.term));
    assert_eq!(
        expected,
        CallResult::Ok(OwnedTerm::List {
            elems: vec![
                OwnedTerm::atom("in"),
                OwnedTerm::atom("out"),
                OwnedTerm::atom("in"),
                OwnedTerm::atom("out"),
                OwnedTerm::atom("in"),
                OwnedTerm::atom("out"),
                OwnedTerm::atom("in"),
                OwnedTerm::atom("out"),
                OwnedTerm::atom("in"),
                OwnedTerm::atom("exit"),
            ],
            tail: Box::new(OwnedTerm::Nil),
        })
    );
}

#[test]
fn large_trapping_bifs_still_yield_with_reductions_and_trace() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping large trap yield differential test");
        return;
    };
    let source = r#"
-module(trap_lazy_yield).
-export([run/0]).
run() ->
    Values = lists:seq(1, 200000),
    Encoded = term_to_binary(Values),
    Pairs = [{N, N} || N <- lists:seq(1, 60000)],
    Checks = [
        observe(term_to_binary, fun() -> term_to_binary(Values) end),
        observe(term_to_iovec, fun() -> term_to_iovec(Values) end),
        observe(binary_to_term, fun() -> binary_to_term(Encoded) end),
        observe(list_to_binary, fun() -> list_to_binary(lists:duplicate(200000, 97)) end),
        observe(binary_copy, fun() -> binary:copy(<<7>>, 600000 + (length(Values) rem 2)) end),
        observe(from_list, fun() -> maps:from_list(Pairs) end)
    ],
    [Name || {Name, Yielded, Reductions} <- Checks, Yielded andalso Reductions > 0].
observe(Name, Fun) ->
    Parent = self(),
    Pid = spawn(fun() ->
        receive start ->
            {reductions, Before} = process_info(self(), reductions),
            _ = Fun(),
            {reductions, After} = process_info(self(), reductions),
            Parent ! {done, self(), After - Before}
        end
    end),
    1 = erlang:trace(Pid, true, [running, {tracer, Parent}]),
    Pid ! start,
    receive
        {done, Pid, Delta} ->
            Ref = erlang:trace_delivered(Pid),
            {Name, count_out(Pid, Ref, 0) > 0, Delta}
    after 30000 ->
        exit(Pid, kill),
        {Name, false, 0}
    end.
count_out(Pid, Ref, Count) ->
    receive
        {trace, Pid, out, _} -> count_out(Pid, Ref, Count + 1);
        {trace_delivered, Pid, Ref} -> Count;
        _ -> count_out(Pid, Ref, Count)
    after 30000 ->
        0
    end.
"#;
    let beam = reference
        .compile_named("trap_lazy_yield", source, &[])
        .unwrap();
    reference.load("trap_lazy_yield", &beam).unwrap();
    let expected = reference.call("trap_lazy_yield", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("trap_lazy_yield", "run", &[], 2, Some(7))
        .unwrap_or_else(|error| panic!("large trapping BIF yields: {error}"));

    assert_eq!(expected, CallResult::Ok(actual.term.clone()));
    assert_eq!(
        actual.term,
        OwnedTerm::List {
            elems: vec![
                OwnedTerm::atom("term_to_binary"),
                OwnedTerm::atom("term_to_iovec"),
                OwnedTerm::atom("binary_to_term"),
                OwnedTerm::atom("list_to_binary"),
                OwnedTerm::atom("binary_copy"),
                OwnedTerm::atom("from_list"),
            ],
            tail: Box::new(OwnedTerm::Nil),
        }
    );
}

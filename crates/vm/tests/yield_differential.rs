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

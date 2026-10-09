use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, decode, encode};
use arinsal_vm::Vm;

#[test]
fn scheduler_binding_and_errors_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping scheduler-binding differential test");
        return;
    };
    let source = r#"
-module(sched_bind_probe).
-export([run/0]).

caught(Fun) ->
    try {ok, Fun()}
    catch Class:Reason -> {Class, Reason}
    end.

spin(0, Acc) -> Acc;
spin(N, Acc) -> spin(N - 1, Acc + 1).

observe() ->
    Before = erlang:system_info(scheduler_id),
    _ = spin(20000, 0),
    receive after 0 -> ok end,
    After = erlang:system_info(scheduler_id),
    {Before, After}.

run() ->
    Count = erlang:system_info(schedulers),
    Parent = self(),
    Targets = lists:seq(1, min(2, Count)),
    [spawn_opt(fun() -> Parent ! {bound, N, observe()} end,
               [{scheduler, N}]) || N <- Targets],
    Bound = lists:sort([receive {bound, N, Seen} -> {N, Seen}
                        after 5000 -> timeout end || _ <- Targets]),
    Previous1 = process_flag(scheduler, 1),
    First = observe(),
    Previous2 = process_flag(scheduler, 2),
    Second = observe(),
    Previous0 = process_flag(scheduler, 0),
    {Bound, {Previous1, First, Previous2, Second, Previous0},
     caught(fun() -> is_pid(spawn_opt(fun() -> ok end, [{scheduler, 0}])) end),
     caught(fun() -> spawn_opt(fun() -> ok end, [{scheduler, Count + 1}]) end),
     caught(fun() -> spawn_opt(fun() -> ok end, [{scheduler, -1}]) end),
     caught(fun() -> spawn_opt(fun() -> ok end, [{scheduler, 1.0}]) end),
     caught(fun() -> process_flag(scheduler, Count + 1) end),
     caught(fun() -> process_flag(scheduler, -1) end),
     caught(fun() -> process_flag(scheduler, 1.0) end),
     caught(fun() -> process_info(self(), scheduler) end)}.
"#;
    let beam = reference
        .compile_named("sched_bind_probe", source, &[])
        .expect("compile scheduler binding probe");
    reference.load("sched_bind_probe", &beam).unwrap();
    let expected = reference.call("sched_bind_probe", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("sched_bind_probe", "run", &[], 2, None)
        .unwrap_or_else(|error| panic!("scheduler binding VM error: {error:?}"));
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

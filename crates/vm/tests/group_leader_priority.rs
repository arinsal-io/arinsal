use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(group_leader_priority_diff).
-export([run/0, saturated/0, badarg/0]).
run() ->
    Parent = self(),
    Leader = spawn(fun() -> receive stop -> ok end end),
    Target = spawn(fun() -> receive check -> Parent ! {leader, group_leader()} end end),
    true = group_leader(Leader, Target),
    Target ! check,
    Result = receive {leader, Actual} -> Actual =:= Leader after 1000 -> timeout end,
    Leader ! stop,
    Result.
badarg() ->
    try erlang:group_leader(not_a_pid, self())
    catch error:badarg -> badarg end.
saturated() ->
    process_flag(priority, max),
    Leader = spawn(fun() -> receive stop -> ok end end),
    Target = spawn_opt(fun() -> receive stop -> ok end end,
                       [{priority, normal}]),
    Parent = self(),
    Tokens = [spawn_opt(fun() -> Parent ! ready, tok_loop() end,
                        [{priority, high}]) ||
                 _ <- lists:seq(1, 2 * erlang:system_info(schedulers))],
    [receive ready -> ok end || _ <- Tokens],
    true = erlang:group_leader(Leader, Target),
    {group_leader, Actual} = process_info(Target, group_leader),
    exit(Target, kill),
    [exit(Token, kill) || Token <- Tokens],
    Leader ! stop,
    Actual =:= Leader.
tok_loop() -> receive stop -> ok after 0 -> tok_loop() end.
"#;

#[test]
fn group_leader_remote_update_and_badarg_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping group_leader differential test");
        return;
    };
    let beam = reference
        .compile_named("group_leader_priority_diff", SOURCE, &[])
        .unwrap();
    reference.load("group_leader_priority_diff", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    for function in ["run", "saturated", "badarg"] {
        let expected = reference.call("group_leader_priority_diff", function, &[]);
        let actual = vm
            .eval_scheduled("group_leader_priority_diff", function, &[], 4, Some(0x6a11))
            .unwrap_or_else(|error| panic!("{function}: {error:?}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}

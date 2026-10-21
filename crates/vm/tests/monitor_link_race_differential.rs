//! Monitor and link races against OTP: workers monitor and link short-lived peers, demonitor
//! (with flush) and unlink some of them while the peers exit, and check that every monitor left
//! gets exactly one DOWN, every link left exactly one EXIT, and that the monitor and link
//! bookkeeping on both ends is empty afterwards. Run on one scheduler and on four.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::{Vm, VmError};

const SOURCE: &str = r#"
-module(monitor_link_race).
-export([run/0]).

run() ->
    Self = self(),
    Workers = [spawn(fun() -> worker(Self, 60, I) end) || I <- lists:seq(1, 8)],
    Results = [receive {done, W, R} -> R after 30000 -> timeout end || W <- Workers],
    Target = spawn(fun() -> receive stop -> ok end end),
    Refs = [erlang:monitor(process, Target) || _ <- lists:seq(1, 5)],
    {monitored_by, Watchers} = process_info(Target, monitored_by),
    {monitors, Monitors} = process_info(self(), monitors),
    [true = erlang:demonitor(Ref, [flush]) || Ref <- tl(Refs)],
    {monitors, Left} = process_info(self(), monitors),
    Target ! stop,
    Down = receive {'DOWN', _, process, Target, normal} -> down after 5000 -> timeout end,
    {[R || R <- Results, R =/= ok], length(Watchers), length(Monitors), length(Left), Down,
     process_info(self(), monitors)}.

worker(Parent, Rounds, Seed) ->
    process_flag(trap_exit, true),
    rand:seed(exsss, {Seed, Seed * 7, Seed * 13}),
    R = round_loop(Rounds),
    Final = case {R, process_info(self(), monitors), process_info(self(), links)} of
                {ok, {monitors, []}, {links, []}} -> ok;
                Other -> Other
            end,
    Parent ! {done, self(), Final}.

round_loop(0) -> ok;
round_loop(N) ->
    Peers = [spawn(fun peer/0) || _ <- lists:seq(1, 4)],
    Refs = [{erlang:monitor(process, P), P} || P <- Peers],
    Linked = [P || P <- Peers, rand:uniform(2) =:= 1],
    [link(P) || P <- Linked],
    {Keep, Drop} = lists:partition(fun(_) -> rand:uniform(2) =:= 1 end, Refs),
    [true = erlang:demonitor(Ref, [flush]) || {Ref, _} <- Drop],
    Unlinked = [P || P <- Linked, rand:uniform(3) =:= 1],
    [unlink(P) || P <- Unlinked],
    [P ! {stop, {reason, N}} || P <- Peers],
    Downs = [receive {'DOWN', Ref, process, P, Why} -> Why after 5000 -> timeout end
             || {Ref, P} <- Keep],
    Exits = [receive {'EXIT', P, Why} -> Why after 5000 -> timeout end
             || P <- Linked -- Unlinked],
    Extra = receive {'DOWN', _, _, _, _} = D -> D after 0 -> none end,
    ExtraExit = receive {'EXIT', _, _} = E -> E after 0 -> none end,
    case {Downs -- [{reason, N} || _ <- Keep], Exits -- [{reason, N} || _ <- Exits],
          Extra, ExtraExit} of
        {[], [], none, none} -> round_loop(N - 1);
        Other -> {bad, N, Other}
    end.

peer() ->
    receive {stop, Why} -> exit(Why) end.
"#;

fn run_on(vm_workers: usize, beam: &[u8]) -> CallResult {
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).expect("load VM module");
    match vm.eval_scheduled("monitor_link_race", "run", &[], vm_workers, None) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    }
}

#[test]
fn monitor_and_link_races_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named("monitor_link_race", SOURCE, &[])
        .expect("compile differential");
    reference
        .load("monitor_link_race", &beam)
        .expect("load reference module");
    let expected = reference.call("monitor_link_race", "run", &[]);
    for workers in [1, 4] {
        let actual = run_on(workers, &beam);
        compare(&expected, &actual, CompareMode::Exact).unwrap_or_else(|diff| {
            panic!("monitor/link races differ with {workers} schedulers: {diff}")
        });
    }
}

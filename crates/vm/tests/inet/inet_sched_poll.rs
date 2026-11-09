use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

// Descriptors re-enabled more than ten times are polled by the schedulers; streams stay
// complete and ordered across the migration.
const SOURCE: &str = r#"
-module(inet_sched_poll).
-export([t/0]).
%% A socket re-enabled with {active, once} far more than ten times moves to the scheduler
%% pollset; the stream must arrive complete and in order, in active-once, active and passive
%% modes, with the owner idle between bursts (the scheduler sleeps in the pollset).
t() ->
  catch ets:new(ac_tab, [named_table, public, set]),
  [run(Mode, N) || Mode <- [once, true, false], N <- [30, 300]].
run(Mode, N) ->
  {ok, L} = gen_tcp:listen(0, [{tcp_module, inet_tcp}, binary, {ip,{127,0,0,1}}, {active,false}, {packet,2}, {reuseaddr,true}]),
  {ok, P} = inet:port(L), Self = self(),
  spawn_link(fun() -> {ok, C} = gen_tcp:connect({127,0,0,1}, P, [{tcp_module, inet_tcp}, binary,{active,false},{packet,2}]),
      [begin ok = gen_tcp:send(C, <<I:32>>), (I rem 50 =:= 0) andalso timer:sleep(5) end || I <- lists:seq(1, N)],
      receive stop -> ok after 10000 -> ok end, gen_tcp:close(C), Self ! done end),
  {ok, S} = gen_tcp:accept(L),
  ok = inet:setopts(S, [{active, Mode}]),
  Got = [recv(S, Mode) || _ <- lists:seq(1, N)],
  gen_tcp:close(S), gen_tcp:close(L),
  {Mode, N, Got =:= [<<I:32>> || I <- lists:seq(1, N)]}.
recv(S, false) -> {ok, B} = gen_tcp:recv(S, 0, 5000), B;
recv(S, Mode) -> receive {tcp, S, B} -> (Mode =:= once andalso inet:setopts(S, [{active, once}])), B after 5000 -> timeout end.
"#;

#[test]
fn scheduler_polled_sockets_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping scheduler poll differential test");
        return;
    };
    let beam = reference
        .compile_named("inet_sched_poll", SOURCE, &[])
        .expect("compile inet_sched_poll");
    reference
        .load("inet_sched_poll", &beam)
        .expect("load inet_sched_poll");
    let expected = reference.call("inet_sched_poll", "t", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled("inet_sched_poll", "t", &[], 2, None)
        .expect("Arinsal inet_sched_poll");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

//! Regression tests for yielding ETS table deletion and process exit (ets_SUITE
//! delete_large_tab, t_delete_all_objects_trap and the exit_*_owner cases): the work is split
//! into slices of reductions, visible as scheduling trace events like in erts.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ets_yield_diff).
-export([delete_trap/0, delete_all_trap/0, exit_yields/0, results_survive/0]).
collect(Tracer) ->
  receive {Tracer, Msgs} -> Msgs end.
tracer_loop(Parent, Acc) ->
  receive done -> Parent ! {self(), lists:reverse(Acc)};
          M -> tracer_loop(Parent, [M | Acc])
  end.
fill(T, N) -> ets:insert(T, [{I, I} || I <- lists:seq(1, N)]).
%% ets:delete/1 of a large table traps as ets:delete_trap/1 and ends with the table gone.
delete_trap() ->
  [begin
     T = ets:new(t, Opts),
     fill(T, 50000),
     Me = self(),
     Tr2 = spawn(fun() -> tracer_loop(Me, []) end),
     erlang:trace(self(), true, [running, {tracer, Tr2}]),
     true = ets:delete(T),
     erlang:trace(self(), false, [running]),
     Tr2 ! done,
     Msgs = collect(Tr2),
     Outs = [M || {trace, _, out, {ets, delete_trap, 1}} = M <- Msgs],
     {length(Outs) >= 5, ets:info(T)}
   end || Opts <- [[set], [ordered_set], [bag], [ordered_set, {write_concurrency, true}]]].
%% ets:delete_all_objects/1 traps as ets:internal_delete_all/2 and returns true.
delete_all_trap() ->
  [begin
     T = ets:new(t, Opts),
     fill(T, 50000),
     Me = self(),
     Tr = spawn(fun() -> tracer_loop(Me, []) end),
     erlang:trace(self(), true, [running, {tracer, Tr}]),
     Res = ets:delete_all_objects(T),
     erlang:trace(self(), false, [running]),
     Tr ! done,
     Msgs = collect(Tr),
     Outs = [M || {trace, _, out, {ets, internal_delete_all, 2}} = M <- Msgs],
     {Res, length(Outs) >= 5, ets:info(T, size)}
   end || Opts <- [[set], [ordered_set], [duplicate_bag]]].
%% A process owning big tables yields while exiting: out_exiting/in_exiting events, then
%% out_exited, and its tables are gone afterwards.
exit_yields() ->
  Me = self(),
  P = spawn(fun() ->
              Ts = [ets:new(t, [set, public]) || _ <- lists:seq(1, 3)],
              [fill(T, 30000) || T <- Ts],
              Me ! {tables, Ts},
              receive stop -> ok end
            end),
  Ts = receive {tables, X} -> X end,
  1 = erlang:trace(P, true, [exiting]),
  exit(P, bang),
  Seq = exit_seq(P, []),
  Gone = [ets:info(T) || T <- Ts],
  {Seq, Gone}.
exit_seq(P, Acc) ->
  receive
    {trace, P, out_exited, 0} -> count(lists:reverse([out_exited | Acc]));
    {trace, P, What, 0} -> exit_seq(P, [What | Acc])
  after 10000 -> timeout
  end.
count(Events) ->
  {length([E || E = out_exiting <- Events]) >= 3, lists:last(Events)}.
%% Many small tables owned by the exiting process, some fixed by other processes.
results_survive() ->
  Me = self(),
  P = spawn(fun() ->
              Owner = self(),
              T = ets:new(f, [public, bag]),
              fill(T, 1000),
              [ets:new(list_to_atom("yt" ++ integer_to_list(I)), [named_table]) || I <- lists:seq(1, 200)],
              Fixer = spawn(fun() -> ets:safe_fixtable(T, true), Owner ! fixed, receive stop -> ok end end),
              receive fixed -> ok end,
              ets:delete_all_objects(T),
              Me ! {ready, T, Fixer},
              receive stop -> ok end
            end),
  {T, Fixer} = receive {ready, T0, F0} -> {T0, F0} end,
  exit(P, kill),
  MRef = monitor(process, P),
  receive {'DOWN', MRef, process, P, R} -> R end,
  Gone = ets:info(T),
  exit(Fixer, kill),
  {Gone, [ets:whereis(list_to_atom("yt" ++ integer_to_list(I))) || I <- lists:seq(1, 200)]}.
"#;

#[test]
fn ets_yield_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ets_yield differential scenarios");
        return;
    };
    let beam = reference
        .compile_named("ets_yield_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_yield_diff", &beam).unwrap();
    for function in [
        "delete_trap",
        "delete_all_trap",
        "exit_yields",
        "results_survive",
    ] {
        let expected = reference.call("ets_yield_diff", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("ets_yield_diff", function, &[], 2, Some(81))
            .unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}

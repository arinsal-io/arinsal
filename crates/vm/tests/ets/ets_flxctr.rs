//! `ets:info` size and memory of tables with centralized and decentralized counters, after
//! concurrent inserts and deletes: the snapshot protocol of erl_flxctr.c, against `erl`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const SOURCE: &str = r#"
-module(ets_flxctr_diff).
-export([quiet/0, concurrent/0, repeated/0, info_list/0, trap_args/0, info_deleted/0]).
kinds() ->
  [{set, [set, public]},
   {set_decentralized, [set, public, {write_concurrency, true}, {decentralized_counters, true}]},
   {set_auto, [set, public, {write_concurrency, auto}]},
   {ordered, [ordered_set, public]},
   {ordered_cacheline, [ordered_set, public, {write_concurrency, true}]},
   {ordered_centralized, [ordered_set, public, {write_concurrency, true}, {decentralized_counters, false}]},
   {bag, [bag, public, {write_concurrency, true}, {decentralized_counters, true}]}].
%% Quiet tables: every kind reports the same size, and memory once objects are in.
quiet() ->
  [begin
     T = ets:new(t, Opts),
     E = {ets:info(T, size), ets:info(T, memory) > 0},
     ets:insert(T, [{I, I} || I <- lists:seq(1, 1000)]),
     ets:delete(T, 7),
     {Name, E, ets:info(T, size), ets:info(T, memory) > 1000, ets:info(T, decentralized_counters)}
   end || {Name, Opts} <- kinds()].
%% Inserts from several processes, then the exact size from the snapshot.
concurrent() ->
  [begin
     T = ets:new(t, Opts),
     Me = self(),
     Ps = [spawn_link(fun() ->
                          [ets:insert(T, {{W, I}, I}) || I <- lists:seq(1, 2000)],
                          [ets:delete(T, {W, I}) || I <- lists:seq(1, 2000, 2)],
                          Me ! {done, self()}
                      end) || W <- lists:seq(1, 8)],
     [receive {done, P} -> ok end || P <- Ps],
     {Name, ets:info(T, size), ets:info(T, memory) > 8000, proplists:get_value(size, ets:info(T))}
   end || {Name, Opts} <- kinds()].
%% Size reads racing with the writers: every read is a consistent snapshot, so it never
%% exceeds the final size and never shrinks while only inserting.
repeated() ->
  [begin
     T = ets:new(t, Opts),
     Me = self(),
     Ps = [spawn_link(fun() ->
                          [ets:insert(T, {{W, I}, I}) || I <- lists:seq(1, 1500)],
                          Me ! {done, self()}
                      end) || W <- lists:seq(1, 4)],
     Sizes = poll(T, Ps, []),
     [receive {done, P} -> ok end || P <- Ps],
     Final = ets:info(T, size),
     {Name, Final, lists:all(fun(S) -> S =< Final end, Sizes), monotonic(Sizes)}
   end || {Name, Opts} <- kinds()].
poll(T, Ps, Acc) ->
  case erlang:is_process_alive(hd(Ps)) of
    true -> poll(T, Ps, [ets:info(T, size) | Acc]);
    false -> lists:reverse(Acc)
  end.
monotonic([A, B | Rest]) -> A =< B andalso monotonic([B | Rest]);
monotonic(_) -> true.
info_list() ->
  [begin
     T = ets:new(t, Opts),
     ets:insert(T, [{I, I} || I <- lists:seq(1, 100)]),
     I = ets:info(T),
     {Name, proplists:get_value(size, I), proplists:get_value(memory, I) > 100}
   end || {Name, Opts} <- kinds()].
%% The trap state of ets:info/1 and /2 is not a user value.
trap_args() ->
  T = ets:new(t, [set, public, {write_concurrency, true}, {decentralized_counters, true}]),
  ets:insert(T, {a, 1}),
  R = try ets:info(T, no_such_item) catch error:badarg -> badarg end,
  {R, ets:info(T, size), ets:info(T, name), try ets:info(make_ref(), size) catch error:badarg -> badarg end}.
info_deleted() ->
  T = ets:new(t, [set, public, {write_concurrency, true}, {decentralized_counters, true}]),
  ets:delete(T),
  {ets:info(T), ets:info(T, size), ets:info(T, memory)}.
"#;

#[test]
fn ets_flxctr_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ets_flxctr differential scenarios");
        return;
    };
    let beam = reference
        .compile_named("ets_flxctr_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_flxctr_diff", &beam).unwrap();
    for function in [
        "quiet",
        "concurrent",
        "repeated",
        "info_list",
        "trap_args",
        "info_deleted",
    ] {
        let expected = reference.call("ets_flxctr_diff", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("ets_flxctr_diff", function, &[], 4, None)
            .unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}

//! maps:from_list/1, maps:from_keys/2, maps:keys/1 and maps:values/1 yield inside big inputs
//! (YCF-transformed in erts) and must return exactly what erts returns, including the entry
//! order of the projections, duplicate handling and maps that shrink back to flatmaps.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(maps_yield_diff).
-export([build/0, trap_count/0]).
%% Keys of several shapes so that many hash prefixes occur (atoms are left out: their
%% internal hash differs from erts, which changes only the entry order).
keys(N) ->
  [case I rem 5 of
     0 -> I;
     1 -> {I, I};
     2 -> integer_to_binary(I);
     3 -> I * 1.5;
     4 -> [I, I + 1]
   end || I <- lists:seq(1, N)].
build() ->
  [begin
     Ks = keys(N),
     Pairs = [{K, I} || {I, K} <- lists:zip(lists:seq(1, length(Ks)), Ks)],
     M1 = maps:from_list(Pairs),
     M2 = maps:from_keys(Ks, v),
     Dups = maps:from_list([{I rem 40, I} || I <- lists:seq(1, N)]),
     Same = maps:from_keys(lists:duplicate(N, x), y),
     H = fun erlang:phash2/1,
     {N, map_size(M1), H(M1), H(M2), H(Dups), H(Same), H(maps:keys(M1)), H(maps:values(M1)),
      H(maps:keys(M2)), H(maps:values(M2)), H(maps:keys(Dups)), H(maps:values(Dups)),
      M1 =:= maps:from_list(maps:to_list(M1)), maps:keys(M1) =:= [K || {K, _} <- maps:to_list(M1)]}
   end || N <- [0, 1, 32, 33, 34, 100, 129, 1000, 5000, 20000]].
%% Number of schedule-outs inside the four BIFs for a 60000 element input.
trap_count() ->
  Ks = lists:seq(1, 60000),
  Pairs = [{K, K} || K <- Ks],
  [begin
     Me = self(),
     Tr = spawn(fun() -> tracer(Me, 0) end),
     {Pid, Mon} = spawn_monitor(fun() ->
        erlang:trace(self(), true, [running, {tracer, Tr}]),
        F(),
        ok end),
     receive {'DOWN', Mon, process, Pid, normal} -> ok end,
     TD = erlang:trace_delivered(Pid),
     receive {trace_delivered, Pid, TD} -> ok end,
     Tr ! {done, Fn},
     receive {Fn, Outs} -> Outs > 2 end
   end || {Fn, F} <- [{from_list, fun() -> maps:from_list(Pairs) end},
                      {from_keys, fun() -> maps:from_keys(Ks, v) end},
                      {keys, fun() -> maps:keys(maps:from_keys(Ks, v)) end},
                      {values, fun() -> maps:values(maps:from_list(Pairs)) end}]].
tracer(Me, N) ->
  receive
    {trace, _, out, {maps, F, _}} when F =:= from_list; F =:= from_keys; F =:= keys; F =:= values ->
      tracer(Me, N + 1);
    {trace, _, _, _} -> tracer(Me, N);
    {done, Fn} -> Me ! {Fn, N}
  end.
"#;

#[test]
fn yielding_map_constructors_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping maps_yield differential scenarios");
        return;
    };
    let beam = reference
        .compile_named("maps_yield_diff", SOURCE, &[])
        .unwrap();
    reference.load("maps_yield_diff", &beam).unwrap();
    for function in ["build", "trap_count"] {
        let expected = reference.call("maps_yield_diff", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("maps_yield_diff", function, &[], 2, Some(7))
            .unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}

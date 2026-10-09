//! A traced process migrating between schedulers reports every `in` event with the function it
//! resumes in (or 0), so each `out` is followed by an `in` of the same function like in erts.
//! Regression: the `in` event was resolved before the scheduler's code replica was current and
//! lost its MFA field, which the maps_SUITE trapping checks saw as `other_sched_mismatch`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(trace_sched_in_diff).
-export([pairs/0]).
tracer_loop(Parent, Acc) ->
  receive done -> Parent ! {self(), lists:reverse(Acc)};
          M -> tracer_loop(Parent, [M | Acc])
  end.
%% Every `in` has a 4th element (MFA or 0) and every `out F` is directly followed by `in F`
%% (the first `out` is the one from the trace call itself).
pairs() ->
  Me = self(),
  Tr = spawn(fun() -> tracer_loop(Me, []) end),
  {Pid, Mon} = spawn_monitor(
    fun() ->
      erlang:trace(self(), true, [running, {tracer, Tr}]),
      _ = [{X, X} || X <- [X || {_, X} <- lists:sort([{rand:uniform(), N} || N <- lists:seq(1, 60000)])]],
      ok
    end),
  receive {'DOWN', Mon, process, Pid, R} -> normal = R end,
  TD = erlang:trace_delivered(Pid),
  receive {trace_delivered, Pid, TD} -> ok end,
  Tr ! done,
  Msgs = receive {Tr, L} -> L end,
  Shapes = lists:usort([tuple_size(M) || M <- Msgs]),
  {Shapes, unmatched(Msgs)}.
unmatched([{trace, _, out, F}, {trace, _, in, F} | T]) -> unmatched(T);
unmatched([_ | T]) -> 1 + unmatched(T);
unmatched([]) -> 0.
"#;

#[test]
fn scheduled_in_events_keep_their_function() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping trace_sched_in differential scenario");
        return;
    };
    let beam = reference
        .compile_named("trace_sched_in_diff", SOURCE, &[])
        .unwrap();
    reference.load("trace_sched_in_diff", &beam).unwrap();
    let expected = reference.call("trace_sched_in_diff", "pairs", &[]);
    for _ in 0..4 {
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("trace_sched_in_diff", "pairs", &[], 4, None)
            .unwrap_or_else(|error| panic!("pairs: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term));
    }
}

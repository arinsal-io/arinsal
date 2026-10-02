//! Differential regression tests for ets_SUITE fixes (error_info causes, partly bound
//! ordered_set keys, hash table reset on delete_all_objects, excessive match spec nesting).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ets_rest_diff).
-export([access_causes/0, partly_bound/0, delete_all_memory/0, nesting/0]).
cause(F) ->
  try F(), none
  catch error:Reason:St ->
    [{_,_,_,I}|_] = St,
    {Reason, maps:get(cause, proplists:get_value(error_info, I, #{}), none)}
  end.
calls(T) ->
  [fun() -> ets:match(T, <<1,2,3>>, bad_limit) end,
   fun() -> ets:match_object(T, <<1,2,3>>, bad_limit) end,
   fun() -> ets:select(T, bad_match_spec, bad_limit) end,
   fun() -> ets:select(T, [{{'$1','$2','$3'},[],['$$']}], bad_limit) end,
   fun() -> ets:select_reverse(T, bad_match_spec, bad_limit) end,
   fun() -> ets:setopts(T, bad_opts) end,
   fun() -> ets:delete_all_objects(T) end,
   fun() -> ets:delete(T) end].
access_causes() ->
  T = ets:new(t, [set, private]),
  Parent = self(),
  {Pid, Ref} = spawn_monitor(fun() -> exit([cause(F) || F <- calls(T)]) end),
  Other = receive {'DOWN', Ref, process, Pid, R} -> R end,
  Bad = [cause(F) || F <- calls(make_ref())],
  ets:delete(T),
  Dead = [cause(F) || F <- calls(T)],
  Parent ! done,
  {Other, Bad, Dead}.
partly_bound() ->
  [run_pb(Opts) || Opts <- [[ordered_set], [ordered_set, {write_concurrency, true}, {read_concurrency, true}]]].
run_pb(Opts) ->
  T = ets:new(pb, Opts),
  Keys = [{A, B, N} || A <- [a, b, 1, 1.0, "s", [x|y]], B <- [a, b, {z, 2}], N <- lists:seq(1, 6)],
  ets:insert(T, [{K, K} || K <- Keys]),
  Pats = [{'_', '_'}, {{a, '_', '_'}, '_'}, {{a, a, '_'}, '_'}, {{a, a, 3}, '_'},
          {{1, '_', 2}, '_'}, {{'$1', {z, '_'}, '_'}, '_'}, {{"s", '_', '_'}, '_'},
          {{[x|'_'], '_', '_'}, '_'}, {{'_', a, 3}, '_'}, {{1.0, b, 6}, '_'}],
  [{P, ets:match_object(T, P), ets:select_count(T, [{P, [], [true]}]),
    ets:select_reverse(T, [{P, [], ['$_']}]), chunk(ets:match(T, P, 5))} || P <- Pats]
  ++ [ets:select(T, [{{{a, '_', '_'}, '_'}, [], [x]}, {{{b, b, '_'}, '_'}, [], [y]}])].
chunk({L, _Continuation}) -> L;
chunk(Other) -> Other.
delete_all_memory() ->
  [begin
     T = ets:new(m, Opts),
     ets:insert(T, [{I, I} || I <- lists:seq(1, 20000)]),
     Big = ets:info(T, memory),
     ets:delete_all_objects(T),
     {Big > ets:info(T, memory), ets:info(T, memory), ets:info(T, size)}
   end || Opts <- [[set], [bag], [duplicate_bag]]].
nesting() ->
  Mk = fun(_F, N) when N < 0 -> true;
          (F, N) -> {'orelse', {'==', N, '$1'}, F(F, N - 1)}
       end,
  MS = [{{'$1', '$2'}, [Mk(Mk, 1000000)], [{{'$1', blipp}}]}],
  Compile = try ets:match_spec_compile(MS), compiled catch error:system_limit -> system_limit end,
  Replace = try ets:select_replace(ets:new(t, [ordered_set]), MS), compiled
            catch error:system_limit -> system_limit end,
  {Compile, Replace}.
"#;

#[test]
fn ets_rest_matches_otp_29() {
    // The excessive-nesting scenario copies a million-deep term, which needs a deep Rust stack.
    std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(run_scenarios)
        .unwrap()
        .join()
        .unwrap();
}

fn run_scenarios() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ets_rest differential scenarios");
        return;
    };
    let beam = reference
        .compile_named("ets_rest_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_rest_diff", &beam).unwrap();
    for function in [
        "access_causes",
        "partly_bound",
        "delete_all_memory",
        "nesting",
    ] {
        let expected = reference.call("ets_rest_diff", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("ets_rest_diff", function, &[], 2, Some(81))
            .unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}

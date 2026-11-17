use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use similar_asserts::assert_eq;

const MODULE: &str = "traced_bif_lookup_differential";
const SOURCE: &str = r#"
-module(traced_bif_lookup_differential).
-export([run/3]).

run(Id, Mode, ViaApply) ->
    {Module, Function, Args} = spec(Id),
    Mfa = {Module, Function, length(Args)},
    UseApply = ViaApply =:= apply,
    trace_one(Id, Args, Mfa, UseApply, Mode).

spec(1) -> {unicode, characters_to_binary, ["Aλ", unicode]};
spec(2) -> {lists, reverse, [[1,2,3], [4]]};
spec(3) -> {math, sqrt, [4]};
spec(4) -> {erlang, system_info, [wordsize]};
spec(5) -> {binary, match, [<<"banana">>, <<"ana">>]};
spec(6) ->
    Ref = atomics:new(1, []),
    ok = atomics:put(Ref, 1, 10),
    {atomics, add, [Ref, 1, 1]}.

trace_one(Id, Args, {Module, Function, Arity} = Mfa, ViaApply, Pattern) ->
    Parent = self(),
    Tracer = spawn(fun() -> collect(Parent, []) end),
    Worker = spawn(fun() ->
        Parent ! {ready, self()},
        receive go ->
            Result = invoke(Id, ViaApply, Module, Function, Args),
            Parent ! {done, self(), Result},
            Tracer ! {barrier, self()},
            receive finish -> ok end
        end
    end),
    receive {ready, Worker} -> ok after 1000 -> exit(worker_start_timeout) end,
    _ = Module:module_info(exports),
    TraceFlags = [Pattern],
    _ = erlang:trace_pattern(Mfa, false, TraceFlags),
    _ = erlang:trace_pattern(Mfa, true, TraceFlags),
    1 = erlang:trace(Worker, true, [call, {tracer, Tracer}]),
    Worker ! go,
    Result = receive {done, Worker, Value} -> Value after 1000 -> exit(bif_call_timeout) end,
    Info = case Pattern of
        call_count -> normalize_info(erlang:trace_info(Mfa, call_count));
        call_time -> normalize_info(erlang:trace_info(Mfa, call_time))
    end,
    _ = erlang:trace(Worker, false, [call]),
    _ = erlang:trace_pattern(Mfa, false, TraceFlags),
    Worker ! finish,
    Events = receive {events, Tracer, Calls} -> Calls after 1000 -> exit(trace_timeout) end,
    {Result, Info, Events, Arity}.

normalize_info({call_count, Count}) -> {call_count, Count};
normalize_info({call_time, Rows}) ->
    {call_time, [Count || {_Pid, Count, _Time, _Calls} <- Rows]}.

collect(Parent, Acc) ->
    receive
        {trace, _Pid, call, {Module, Function, Args}} ->
            collect(Parent, [{Module, Function, length(Args)} | Acc]);
        {barrier, _Pid} -> Parent ! {events, self(), lists:reverse(Acc)}
    end.

invoke(_Id, true, Module, Function, Args) -> apply(Module, Function, Args);
invoke(1, false, _Module, _Function, [Characters, Encoding]) -> unicode:characters_to_binary(Characters, Encoding);
invoke(2, false, _Module, _Function, [List, Tail]) -> lists:reverse(List, Tail);
invoke(3, false, _Module, _Function, [Number]) -> math:sqrt(Number);
invoke(4, false, _Module, _Function, [Selector]) -> erlang:system_info(Selector);
invoke(5, false, _Module, _Function, [Subject, Pattern]) -> binary:match(Subject, Pattern);
invoke(6, false, _Module, _Function, [Ref, Index, Increment]) -> atomics:add(Ref, Index, Increment).
"#;

const IDS: &[i64] = &[1, 2, 3, 4, 5, 6];
const MODES: &[&str] = &["call_time", "call_count"];
const ROUTES: &[&str] = &["direct", "apply"];

fn atom(value: &str) -> O {
    O::atom(value)
}

#[test]
fn traced_bif_table_results_and_trace_info_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();

    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    for &id in IDS {
        for &mode in MODES {
            for &route in ROUTES {
                let arguments = [O::Int(id), atom(mode), atom(route)];
                eprintln!("differential {id} {mode} {route}: reference");
                let expected = reference.call(MODULE, "run", &arguments);
                eprintln!("differential {id} {mode} {route}: arinsal");
                let actual = vm
                    .eval_scheduled(
                        MODULE,
                        "run",
                        &[
                            arinsal_term::Term::small(id).unwrap(),
                            arinsal_term::Term::atom(
                                arinsal_term::global_atoms().intern(mode).unwrap(),
                            ),
                            arinsal_term::Term::atom(
                                arinsal_term::global_atoms().intern(route).unwrap(),
                            ),
                        ],
                        1,
                    )
                    .unwrap_or_else(|error| panic!("BIF {id}, {mode}, {route}: {error:?}"));
                eprintln!("differential {id} {mode} {route}: compare");
                assert_eq!(
                    expected,
                    CallResult::Ok(actual.term.clone()),
                    "BIF {id}, {mode}, {route}"
                );
            }
        }
    }
}

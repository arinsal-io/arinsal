//! Exception and return_to call tracing of local functions and BIFs (including `apply`d ones)
//! reports the same events as erts, in the interpreter and under the JIT.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(call_trace_exc_diff).
-export([c/1, all/0, exc_top/3, slave/2]).
-export([match/2, clause/2, id/1, undef/1, lists_reverse/2]).

exc_top(Func, Args, Catch) ->
    case Catch of
        true ->
            try exc_jump(Func, Args) of V -> {value, V}
            catch C:R -> {C, R} end;
        false -> {value, exc_jump(Func, Args)}
    end.
exc_jump(Func, Args) -> exc(Func, Args, jump).
exc(Func, Args, jump) -> exc(Func, Args, do);
exc(Func, Args, do) -> exc(Func, Args).

exc({erlang,apply}, [{M,F},A]) -> erlang:apply(M, F, id(A));
exc({erlang,apply}, [F,A]) -> erlang:apply(F, id(A));
exc({erlang,error}, [E]) -> erlang:error(id(E));
exc({erlang,exit}, [E]) -> erlang:exit(id(E));
exc({erlang,throw}, [E]) -> erlang:throw(id(E));
exc({erlang,'++'}, [A,B]) -> erlang:'++'(A, id(B));
exc({call_trace_exc_diff,match}, [A,B]) -> match(A, id(B));
exc({call_trace_exc_diff,clause}, [A,B]) -> clause(A, id(B));
exc({call_trace_exc_diff,id}, [E]) -> id(id(E));
exc({call_trace_exc_diff,undef}, [E]) -> undef(id(E));
exc({call_trace_exc_diff,lists_reverse}, [A,B]) -> lists_reverse(A, id(B));
exc(Func, [A,B]) when is_function(Func, 2) -> Func(A, id(B)).

match(A, A) -> A.
clause(A, B) when A == B -> A.
id(X) -> X.
undef(X) -> call_trace_exc_diff:undefined_fun(X).
lists_reverse(A, B) -> lists:reverse(A, B).

slave(Dest, Sync) ->
    Dest ! Sync,
    receive
        {From, Tag, {exc, F, A, C}} ->
            Res = try exc_top(F, A, C) catch Cl:Re -> {crash, {Cl, Re}} end,
            From ! {Tag, Res},
            slave(From, Tag);
        die -> exit(done)
    end.

strip(T) ->
    L = tuple_to_list(T),
    L1 = case hd(L) of trace_ts -> lists:droplast(L); trace -> L end,
    case tl(tl(L1)) of
        [call, {M,F,A}] -> {call, M, F, A};
        L2 -> list_to_tuple(L2)
    end.

collect(Pid) ->
    receive
        M when element(2, M) =:= Pid -> [strip(M) | collect(Pid)];
        _ -> collect(Pid)
    after 300 -> []
    end.

cases() ->
    Ref = refatom,
    [{{erlang,exit},[done]}, {{erlang,error},[1.0]}, {{erlang,error},[Ref,[]]},
             {{erlang,throw},[4711]}, {{erlang,'++'},[[17],seventeen]},
             {{erlang,'++'},[Ref,[125.125]]}, {{call_trace_exc_diff,match},[ref,Ref]}, {{call_trace_exc_diff,match},[Ref,Ref]},
             {{call_trace_exc_diff,clause},[ref,Ref]}, {{call_trace_exc_diff,clause},[Ref,Ref]}, {{call_trace_exc_diff,id},[4711.0]},
             {{call_trace_exc_diff,undef},[[Ref|Ref]]}, {{call_trace_exc_diff,lists_reverse},[[1,2,3],[]]},
             {{erlang,apply},[{erlang,exit},[done]]},
             {{erlang,apply},[{call_trace_exc_diff,id},[7]]},
             {{erlang,apply},[{erlang,'++'},[[1],[2]]]},
             {{erlang,apply},[fun(F,A) -> exc(F,A) end, [{call_trace_exc_diff,id},[8]]]}].

all() -> [one(C) || C <- cases()].
one(C) -> {C, [t(C, Catch, Flags) || Catch <- [true,false], Flags <- [[call,return_to],[meta]]]}.
c(N) -> one(lists:nth(N, cases())).

t({F, A}, Catch, Flags) -> t(F, A, Catch, Flags).
t(F, A, Catch, Flags) ->
    Self = self(),
    Sync = make_ref(),
    Pid = spawn(fun () -> slave(Self, Sync) end),
    receive Sync -> ok end,
    {PFlags, PatFlags} = case Flags of
                             [meta] -> {[], [{meta, Self}]};
                             _ -> {Flags, [local]} end,
    case PFlags of [] -> ok; _ -> erlang:trace(Pid, true, PFlags) end,
    Ms = [{'_',[],[{exception_trace}]}],
    erlang:trace_pattern({call_trace_exc_diff,'_','_'}, Ms, PatFlags),
    erlang:trace_pattern({call_trace_exc_diff,slave,'_'}, false, PatFlags),
    [erlang:trace_pattern({erlang,BF,BA}, Ms, PatFlags) || {BF,BA} <- [{exit,1},{error,1},{error,2},{throw,1},{'++',2}]],
    erlang:trace_pattern({lists,reverse,2}, Ms, PatFlags),
    Tag = make_ref(),
    Mref = erlang:monitor(process, Pid),
    Pid ! {self(), Tag, {exc, F, A, Catch}},
    R = receive {Tag, Res} -> Res; {'DOWN', Mref, process, _, Why} -> {down, Why} end,
    Ev = collect(Pid),
    erlang:trace_pattern({'_','_','_'}, false, PatFlags),
    case PFlags of [] -> ok; _ -> erlang:trace(Pid, false, PFlags) end,
    exit(Pid, kill),
    {R, Ev}.


"#;

fn run(reference: &RefErl, case: i64) -> (CallResult, OwnedTerm) {
    let beam = reference
        .compile_named("call_trace_exc_diff", SOURCE, &[])
        .expect("compile fixture");
    reference
        .load("call_trace_exc_diff", &beam)
        .expect("load reference");
    let arguments = [OwnedTerm::Int(case)];
    let expected = reference.call("call_trace_exc_diff", "c", &arguments);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load VM fixture");
    let term = arinsal_term::Term::small(case).expect("small argument");
    let actual = vm
        .eval_scheduled("call_trace_exc_diff", "c", &[term], 1, None)
        .unwrap_or_else(|error| panic!("case {case}: {error}"));
    (expected, actual.term)
}

#[test]
fn exception_and_return_to_events_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping call trace exception test");
        return;
    };
    // Case 12 calls an undefined function, which goes through the code server of a booted node.
    for case in (1..=17).filter(|case| *case != 12) {
        let (expected, actual) = run(&reference, case);
        assert_eq!(expected, CallResult::Ok(actual), "case {case}");
    }
}

-module(trace_error_stack_reserve).
-export([run/0, error_stacktrace_test/0, stk/3, tail/3, do_error_2/1, id/1]).

run() ->
    Tracer = spawn_link(fun() -> receive after infinity -> ok end end),
    Mprog = [{'_', [], [{exception_trace}]}],
    erlang:trace_pattern({trace_error_stack_reserve, '_', '_'}, Mprog, [local]),
    erlang:trace_pattern({erlang, error, 2}, Mprog, [local]),
    erlang:trace_pattern({erlang, error, 1}, Mprog, [local]),
    erlang:trace(all, true, [call, return_to, timestamp, {tracer, Tracer}]),
    try error_stacktrace_test()
    after
        erlang:trace(all, false, [call, return_to, timestamp, {tracer, Tracer}]),
        erlang:trace_pattern({erlang, error, 2}, false, [local]),
        erlang:trace_pattern({erlang, error, 1}, false, [local]),
        erlang:trace_pattern({trace_error_stack_reserve, '_', '_'}, false, [local]),
        unlink(Tracer),
        exit(Tracer, kill),
        Mon = erlang:monitor(process, Tracer),
        receive {'DOWN', Mon, process, Tracer, _} -> ok end
    end,
    ok.

error_stacktrace_test() ->
    Type = apply_const_last,
    {Pid, Mon} = spawn_monitor(fun() -> stk([a, b, c, d], Type, error_2) end),
    receive {'DOWN', Mon, process, Pid, Reason} -> Reason end.

stk([_|Rest], Type, Func) -> stk(Rest, Type, Func), id(ok);
stk([], Type, Func) ->
    put(erlang, erlang),
    put(tail, []),
    tail(Type, Func, jump),
    id(ok).

tail(Type, Func, jump) -> tail(Type, Func, do);
tail(Type, error_2, do) -> do_error_2(Type).

id(Value) -> Value.

do_error_2(apply_const_last) -> erlang:apply(erlang, error, [oops, [apply_const_last]]).

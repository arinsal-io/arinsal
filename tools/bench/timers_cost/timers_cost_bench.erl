-module(timers_cost_bench).
-export([run/2, run/3, lateness/2]).

run(Op, N) ->
    run(Op, N, 0).

run(Op, N, Round) ->
    Load = [spawn(fun busy/0) || _ <- lists:seq(1, 2)],
    timer:sleep(20),
    {Empty, Work} = case Round rem 2 of
        0 ->
            E = timed(fun() -> loop_empty(N) end),
            W = timed(fun() -> operation(Op, N) end),
            {E, W};
        1 ->
            W = timed(fun() -> operation(Op, N) end),
            E = timed(fun() -> loop_empty(N) end),
            {E, W}
    end,
    [exit(Pid, kill) || Pid <- Load],
    {Op, N, Empty, Work}.

lateness(Type, N) ->
    Load = [spawn(fun busy/0) || _ <- lists:seq(1, 2)],
    DelayNs = 100000000,
    _ = [begin
             Requested = erlang:monotonic_time(nanosecond),
             case Type of
                 send_after -> erlang:send_after(100, self(), {timer_lateness, Requested});
                 start_timer -> erlang:start_timer(100, self(), {timer_lateness, Requested})
             end
         end || _ <- lists:seq(1, N)],
    Sorted = lists:sort(collect_lateness(Type, N, DelayNs, [])),
    [exit(Pid, kill) || Pid <- Load],
    {Type, N, percentile(Sorted, 50), percentile(Sorted, 99)}.

collect_lateness(_Type, 0, _DelayNs, Values) -> Values;
collect_lateness(Type, N, DelayNs, Values) ->
    Requested = receive
        {timer_lateness, Req} when Type =:= send_after -> Req;
        {timeout, _Ref, {timer_lateness, Req}} when Type =:= start_timer -> Req
    after 10000 -> erlang:error(timer_timeout)
    end,
    Late = erlang:max(0, erlang:monotonic_time(nanosecond) - Requested - DelayNs),
    collect_lateness(Type, N - 1, DelayNs, [Late | Values]).

percentile(Values, Percent) ->
    lists:nth((length(Values) * Percent + 99) div 100, Values).

busy() -> busy(0).
busy(N) -> busy(N bxor 1).

timed(F) ->
    Start = erlang:monotonic_time(nanosecond),
    F(),
    erlang:monotonic_time(nanosecond) - Start.

loop_empty(0) -> ok;
loop_empty(N) -> loop_empty(N - 1).

operation(send_after_cancel, N) -> send_cancel(N);
operation(start_timer_cancel, N) -> start_cancel(N);
operation(receive_after_0, N) -> receive_zero(N);
operation(receive_after_1_message, N) -> receive_message(N);
operation(concurrent_10000, _N) -> concurrent().

send_cancel(0) -> ok;
send_cancel(N) ->
    Ref = erlang:send_after(1000, self(), m),
    _ = erlang:cancel_timer(Ref),
    send_cancel(N - 1).

start_cancel(0) -> ok;
start_cancel(N) ->
    Ref = erlang:start_timer(1000, self(), m),
    _ = erlang:cancel_timer(Ref),
    start_cancel(N - 1).

receive_zero(0) -> ok;
receive_zero(N) ->
    receive after 0 -> ok end,
    receive_zero(N - 1).

receive_message(0) -> ok;
receive_message(N) ->
    self() ! m,
    receive m -> ok after 1 -> erlang:error(missed_message) end,
    receive_message(N - 1).

concurrent() ->
    Start = erlang:monotonic_time(nanosecond),
    [erlang:send_after(100, self(), m) || _ <- lists:seq(1, 10000)],
    collect(10000),
    erlang:monotonic_time(nanosecond) - Start.

collect(0) -> ok;
collect(N) -> receive m -> collect(N - 1) after 10000 -> erlang:error(timer_timeout) end.

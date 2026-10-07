%% Common Test hook that aborts a test case after a per-case time limit.
%% The runner derives the limits from the reference erl run, so a hanging
%% case costs seconds instead of the suite's own (often 30 min) timetrap.
-module(arinsal_case_timeout_cth).
-export([init/2, pre_init_per_testcase/4, post_end_per_testcase/5]).

init(_Id, Opts) ->
    {ok, #{limits => proplists:get_value(limits, Opts, #{}),
           default => proplists:get_value(default, Opts, 60000),
           watchdogs => #{}}}.

pre_init_per_testcase(_Suite, TC, Config, #{limits := L, default := D, watchdogs := W} = S) ->
    Ms = maps:get(TC, L, D),
    Dog = spawn(fun() ->
                        receive stop -> ok
                        after Ms -> ct:abort_current_testcase({arinsal_case_timeout, TC, Ms})
                        end
                end),
    {Config, S#{watchdogs := W#{TC => Dog}}}.

post_end_per_testcase(_Suite, TC, _Config, Return, #{watchdogs := W} = S) ->
    case maps:take(TC, W) of
        {Dog, W1} -> Dog ! stop, {Return, S#{watchdogs := W1}};
        error -> {Return, S}
    end.

%% Test backend: no processes, just bookkeeping and a line in the project's log.
-module(arinsal_cloud_stub).
-behaviour(arinsal_cloud_backend).

-export([start/1, stop/1, info/1]).

start(#{port := Port, log := Log}) ->
    arinsal_cloud_log:write(Log, "stub output\n"),
    {ok, #{id => make_ref(), port => Port}, 42}.

stop(_) ->
    ok.

info(_) ->
    #{backend => stub}.

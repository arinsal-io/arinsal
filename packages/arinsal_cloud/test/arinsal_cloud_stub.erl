%% Test backend: no processes, just bookkeeping.
-module(arinsal_cloud_stub).
-behaviour(arinsal_cloud_backend).

-export([start/1, stop/1, info/1]).

start(#{port := Port}) ->
    {ok, #{id => make_ref(), port => Port}, 42}.

stop(_) ->
    ok.

info(_) ->
    #{backend => stub}.

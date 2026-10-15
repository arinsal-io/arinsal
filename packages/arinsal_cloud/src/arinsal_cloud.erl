%% Entry point: `erl -s arinsal_cloud` boots the manager.
-module(arinsal_cloud).

-export([start/0, stop/0]).

start() ->
    case application:ensure_all_started(arinsal_cloud) of
        {ok, _} -> ok;
        {error, Reason} -> erlang:error({arinsal_cloud_start_failed, Reason})
    end.

stop() ->
    application:stop(arinsal_cloud).

-module(arinsal_cloud_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_Type, _Args) ->
    arinsal_cloud_sup:start_link().

stop(_State) ->
    ok.

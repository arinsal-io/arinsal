%% Placeholder for the in-namespace boot, owned by the namespace-kernel stream. Replace this
%% module (keep the name and `start/3`); drop `implemented/0` or return `true` from it and
%% `backend => auto` starts picking the namespace backend.
%%
%% The real `start/3` spawns `erl_init:start` inside `Ns` and returns the pid of that process.
%%
%% BootPlan is the map from `arinsal_cloud_boot:boot_plan/1`. Opts keys:
%%   group_leader := pid()             log collector for every process of the project
%%   os_env := [{string(), string()}]  environment the release reads with os:getenv
-module(arinsal_ns_boot).

-export([start/3, implemented/0]).

-spec start(pos_integer(), map(), map()) -> pid().
start(_Ns, _BootPlan, _Opts) ->
    erlang:error(not_implemented).

-spec implemented() -> boolean().
implemented() ->
    false.

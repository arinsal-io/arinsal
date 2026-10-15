%% Stands in for `arinsal_ns_boot` in the namespace backend tests: spawns one process in the
%% namespace that prints a line (to its group leader) and waits.
-module(arinsal_cloud_test_boot).

-export([start/3, implemented/0, run/2]).

start(Ns, #{release := {Name, _}}, #{group_leader := Log, os_env := Env}) ->
    {ok, arinsal_ns:spawn(Ns, ?MODULE, run, [Name, proplists:get_value("PORT", Env)],
                          [{group_leader, Log}])}.

implemented() ->
    true.

run(Name, Port) ->
    io:format("hello from ~s on ~s~n", [Name, Port]),
    receive stop -> ok end.

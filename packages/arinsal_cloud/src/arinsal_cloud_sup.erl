-module(arinsal_cloud_sup).
-behaviour(supervisor).

-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Children = [
        #{id => arinsal_cloud_log_sup, start => {arinsal_cloud_log_sup, start_link, []}, type => supervisor},
        #{id => arinsal_cloud_projects, start => {arinsal_cloud_projects, start_link, []}},
        #{id => arinsal_cloud_http, start => {arinsal_cloud_http, start_link, []}}
    ],
    {ok, {#{strategy => one_for_all, intensity => 3, period => 10}, Children}}.

-module(arinsal_cloud_log_sup).
-behaviour(supervisor).

-export([start_link/0, start_log/1, stop_log/1, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% Start the log process of one project; `Opts` is passed to `arinsal_cloud_log:start_link/1`.
start_log(Opts) ->
    supervisor:start_child(?MODULE, [Opts]).

stop_log(Pid) ->
    supervisor:terminate_child(?MODULE, Pid).

init([]) ->
    Child = #{id => log, start => {arinsal_cloud_log, start_link, []}, restart => temporary},
    {ok, {#{strategy => simple_one_for_one, intensity => 5, period => 10}, [Child]}}.

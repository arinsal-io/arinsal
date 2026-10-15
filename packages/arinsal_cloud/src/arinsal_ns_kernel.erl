%% The kernel application of a namespace. `arinsal_ns_boot` starts `application_controller` with
%% kernel's app spec pointing `mod` here, so starting `kernel` inside a namespace brings up only
%% what holds per-project state: the Logger configuration (the `logger` table is created by
%% logger_server, started before the application controller) and `kernel_sup` with `logger_sup`
%% (handler watcher only) and an empty `kernel_safe_sup`. code_server, file_server_2, inet_db, user and the other kernel
%% services stay shared in root.
-module(arinsal_ns_kernel).
-behaviour(application).
-behaviour(supervisor).

-export([start/2, stop/1, init/1]).

start(_Type, _Args) ->
    ok = logger:internal_init_logger(),
    case supervisor:start_link({local, kernel_sup}, ?MODULE, top) of
        {ok, Pid} ->
            ok = logger:add_handlers(kernel),
            {ok, Pid, []};
        Error ->
            Error
    end.

stop(_State) ->
    ok.

init(top) ->
    LoggerSup = #{id => logger_sup,
                  start => {supervisor, start_link, [{local, logger_sup}, ?MODULE, logger]},
                  restart => permanent,
                  shutdown => infinity,
                  type => supervisor,
                  modules => [logger_sup]},
    SafeSup = #{id => kernel_safe_sup,
                start => {supervisor, start_link, [{local, kernel_safe_sup}, ?MODULE, safe]},
                restart => permanent,
                shutdown => infinity,
                type => supervisor,
                modules => [?MODULE]},
    {ok, {#{strategy => one_for_all, intensity => 0, period => 1}, [LoggerSup, SafeSup]}};
init(logger) ->
    %% logger_sup without logger_proxy: the proxy registers itself as the system logger
    %% (`system_flag`, root only), and VM-generated events go to root's Logger.
    Watcher = #{id => logger_handler_watcher,
                start => {logger_handler_watcher, start_link, []},
                shutdown => brutal_kill},
    {ok, {#{strategy => one_for_one, intensity => 1, period => 5}, [Watcher]}};
init(safe) ->
    {ok, {#{strategy => one_for_one, intensity => 4, period => 3600}, []}}.

%% Backend on the `arinsal_ns` natives: every project is a namespace of this node.
%%
%% Steps of `start/1`: boot plan from the release, `arinsal_ns:create/3`, `arinsal_ns:expose/1`
%% on the project's log collector (so processes of the namespace can reach it), then
%% `arinsal_ns_boot:start(Ns, BootPlan, Opts)` with `group_leader` = the log collector and
%% `os_env` = the project env. `stop/1` destroys the namespace.
%%
%% The natives are not visible to `erlang:function_exported/3` (the module `arinsal_ns` does not
%% exist as code), so availability is probed with a call that cannot fail when they exist. The
%% calls that were not merged when this was written (`expose/1`, `destroy/1`, `info/1`) are
%% guarded: a missing function (`undef`) is treated as a no-op, and destroy falls back to killing
%% the boot process.
%%
%% App env: `ns_limits` (map with `max_processes`, `max_bytes` for `arinsal_ns:create/3`) and
%% `ns_boot` (module to call instead of `arinsal_ns_boot`, for tests).
-module(arinsal_cloud_ns).
-behaviour(arinsal_cloud_backend).

-export([start/1, stop/1, info/1, natives_available/0, usable/0]).

%% True when the `arinsal_ns` natives exist in this runtime.
-spec natives_available() -> boolean().
natives_available() ->
    try arinsal_ns:'of'(self()) of
        _ -> true
    catch
        error:undef -> false
    end.

%% True when this backend can run projects: natives present and the in-namespace boot implemented
%% (the stub `arinsal_ns_boot` says it is not; a module without `implemented/0` counts as real).
-spec usable() -> boolean().
usable() ->
    natives_available() andalso boot_implemented().

boot_implemented() ->
    Boot = boot_module(),
    _ = code:ensure_loaded(Boot),
    case erlang:function_exported(Boot, implemented, 0) of
        true -> Boot:implemented();
        false -> true
    end.

boot_module() ->
    application:get_env(arinsal_cloud, ns_boot, arinsal_ns_boot).

start(#{tenant := Tenant, project := Project, release_dir := Dir, log := Log, env := Env,
        key := Key, notify := Notify}) ->
    case natives_available() of
        false ->
            {error, ns_natives_missing};
        true ->
            case arinsal_cloud_boot:boot_plan(Dir) of
                {ok, Plan} ->
                    Limits = application:get_env(arinsal_cloud, ns_limits, #{}),
                    case arinsal_ns:create(Tenant, Project, Limits#{os_env => Env}) of
                        {ok, Ns} -> boot(Ns, Plan, Log, Env, Key, Notify);
                        {error, Reason} -> {error, {ns_create, Reason}}
                    end;
                {error, Reason} ->
                    {error, {boot_plan, Reason}}
            end
    end.

boot(Ns, Plan, Log, Env, Key, Notify) ->
    try
        guarded(fun() -> arinsal_ns:expose(Log) end),
        case (boot_module()):start(Ns, Plan, #{group_leader => Log, os_env => Env}) of
            {ok, Pid} ->
                Watcher = spawn(fun() -> watch(Key, Notify, Ns, Pid) end),
                {ok, #{id => Ns, ns => Ns, pid => Pid, watcher => Watcher}, Ns};
            {error, Failure} ->
                destroy(Ns, undefined),
                {error, {boot_failed, Failure}}
        end
    catch
        Class:Reason ->
            destroy(Ns, undefined),
            {error, {boot_failed, {Class, Reason}}}
    end.

stop(#{ns := Ns, pid := Pid, watcher := Watcher}) ->
    Watcher ! stop,
    destroy(Ns, Pid),
    ok.

info(#{ns := Ns}) ->
    Base = #{backend => ns, ns => Ns},
    try arinsal_ns:info(Ns) of
        Info when is_map(Info) -> maps:merge(Base, Info);
        _ -> Base
    catch
        error:undef -> Base
    end.

destroy(Ns, Pid) ->
    try
        arinsal_ns:destroy(Ns),
        ok
    catch
        error:undef when is_pid(Pid) -> exit(Pid, kill), ok;
        error:undef -> ok
    end.

guarded(Fun) ->
    try Fun() catch error:undef -> ok end.

watch(Key, Notify, Ns, Pid) ->
    Ref = erlang:monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, Reason} -> Notify ! {project_exit, Key, Ns, Reason};
        stop -> ok
    end.

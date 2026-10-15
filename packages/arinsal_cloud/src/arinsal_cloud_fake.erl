%% Backend for stock ERTS, where the `arinsal_ns` natives do not exist. Every project runs in its
%% own OS process: `erl -boot <release>/releases/<vsn>/start` with the host's OTP, so several
%% projects of the same release can run side by side.
%%
%% Limits: isolation is the OS process, not a namespace; the release has to be built with
%% `include_erts: false` against the same OTP as the manager; the project's stdout and stderr go
%% to the project's log collector; there is no same-node mode yet (it needs the boot plan).
-module(arinsal_cloud_fake).
-behaviour(arinsal_cloud_backend).

-export([start/1, stop/1, info/1]).
-export([os_owner/6]).

start(#{release_dir := Dir, env := Env, key := Key, log := Log, notify := Notify}) ->
    case arinsal_cloud_projects:release_version(Dir) of
        {ok, Vsn} ->
            case erl_executable() of
                false ->
                    {error, no_erl_executable};
                Erl ->
                    VsnDir = filename:join([Dir, "releases", Vsn]),
                    Args = ["-noshell", "-noinput", "-mode", "embedded",
                            "-boot", filename:join(VsnDir, "start"),
                            "-boot_var", "RELEASE_LIB", filename:join(Dir, "lib"),
                            "-config", filename:join(VsnDir, "sys")],
                    Ref = make_ref(),
                    Owner = spawn(?MODULE, os_owner, [self(), Ref, {Erl, Args, Env}, Log, Key, Notify]),
                    receive
                        {Ref, {ok, OsPid}} ->
                            {ok, #{id => Owner, owner => Owner, os_pid => OsPid}, undefined};
                        {Ref, {error, Reason}} ->
                            {error, Reason}
                    after 10000 ->
                        exit(Owner, kill),
                        {error, spawn_timeout}
                    end
            end;
        {error, Reason} ->
            {error, {release_version, Reason}}
    end.

stop(#{owner := Owner}) ->
    Ref = make_ref(),
    Owner ! {stop, self(), Ref},
    receive
        {Ref, stopped} -> ok
    after 15000 ->
        exit(Owner, kill),
        ok
    end.

info(#{os_pid := OsPid}) ->
    Rss = string:trim(os:cmd("ps -o rss= -p " ++ integer_to_list(OsPid))),
    #{backend => fake, os_pid => OsPid,
      rss_kb => case string:to_integer(Rss) of {N, _} when is_integer(N) -> N; _ -> null end}.

erl_executable() ->
    case application:get_env(arinsal_cloud, erl) of
        {ok, Path} -> Path;
        undefined -> os:find_executable("erl")
    end.

%% Owns the port and reports an unexpected exit of the OS process.
os_owner(Parent, Ref, {Erl, Args, Env}, Log, Key, Notify) ->
    try open_port({spawn_executable, Erl},
                  [{args, Args}, {env, Env}, binary, exit_status, stderr_to_stdout, use_stdio]) of
        Port ->
            {os_pid, OsPid} = erlang:port_info(Port, os_pid),
            Parent ! {Ref, {ok, OsPid}},
            os_loop(Port, OsPid, Log, Key, Notify)
    catch
        Class:Reason ->
            Parent ! {Ref, {error, {open_port, {Class, Reason}}}}
    end.

os_loop(Port, OsPid, Log, Key, Notify) ->
    receive
        {Port, {data, Data}} ->
            arinsal_cloud_log:write(Log, Data),
            os_loop(Port, OsPid, Log, Key, Notify);
        {Port, {exit_status, Status}} ->
            Notify ! {project_exit, Key, self(), {exit_status, Status}};
        {stop, From, Ref} ->
            os:cmd("kill " ++ integer_to_list(OsPid)),
            drain(Port, OsPid, Log, 5000),
            From ! {Ref, stopped}
    end.

drain(Port, OsPid, Log, Timeout) ->
    receive
        {Port, {data, Data}} ->
            arinsal_cloud_log:write(Log, Data),
            drain(Port, OsPid, Log, Timeout);
        {Port, {exit_status, _}} ->
            ok
    after Timeout ->
        os:cmd("kill -9 " ++ integer_to_list(OsPid)),
        ok
    end.

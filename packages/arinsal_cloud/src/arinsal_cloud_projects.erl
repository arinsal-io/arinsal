%% Project registry keyed by {Tenant, Project}.
%%
%% States: starting | running | failed (stopped and stopping arrive with the stop/start
%% operations). A deploy runs in a worker process so the registry stays responsive; the caller
%% waits for the result. While a project is starting, another deploy of it answers
%% `{error, busy}`. Redeploying a running project stops the old copy once the new tarball is
%% known good.
%%
%% App env read here: data_dir, ready_timeout_ms (default 30000, 0 disables the wait for the
%% project's port), project_env (extra {Name, Value} string pairs).
-module(arinsal_cloud_projects).
-behaviour(gen_server).

-export([start_link/0, deploy/3, list/0]).
-export([valid_name/1, project_dir/2, unpack/3, release_version/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-type key() :: {binary(), binary()}.

-record(p, {
    key :: key(),
    state = starting :: starting | running | failed,
    ns :: pos_integer() | undefined,
    handle :: map() | undefined,
    release_dir :: file:filename() | undefined,
    version :: binary() | undefined,
    port :: inet:port_number() | undefined,
    started_at :: integer() | undefined,
    last_request_at :: integer() | undefined,
    error :: term(),
    waiter :: gen_server:from() | undefined,
    worker :: reference() | undefined
}).

-record(st, {projects = #{} :: #{key() => #p{}}, backend :: module(), data_dir :: file:filename()}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% `Tar` is the tar.gz of a release built with `include_erts: false` (it holds `lib/` and
%% `releases/`). Returns the project map once the project listens on its port.
-spec deploy(binary(), binary(), binary()) -> {ok, map()} | {error, term()}.
deploy(Tenant, Project, Tar) ->
    gen_server:call(?MODULE, {deploy, Tenant, Project, Tar}, 300000).

-spec list() -> [map()].
list() ->
    gen_server:call(?MODULE, list).

-spec valid_name(term()) -> boolean().
valid_name(Name) when is_binary(Name) ->
    re:run(Name, <<"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$">>, [{capture, none}]) =:= match;
valid_name(_) ->
    false.

project_dir(DataDir, {Tenant, Project}) ->
    filename:join([DataDir, binary_to_list(Tenant), binary_to_list(Project)]).

%% The version comes from `releases/start_erl.data` ("<erts> <vsn>"), else from the only
%% directory under `releases/` that holds a `start.boot`.
-spec release_version(file:filename()) -> {ok, string()} | {error, term()}.
release_version(ReleaseDir) ->
    case file:read_file(filename:join([ReleaseDir, "releases", "start_erl.data"])) of
        {ok, Data} ->
            case string:lexemes(binary_to_list(Data), " \r\n") of
                [_Erts, Vsn | _] -> {ok, Vsn};
                _ -> {error, bad_start_erl_data}
            end;
        {error, _} ->
            case filelib:wildcard(filename:join([ReleaseDir, "releases", "*", "start.boot"])) of
                [Boot] -> {ok, filename:basename(filename:dirname(Boot))};
                [] -> {error, no_release};
                _ -> {error, ambiguous_release}
            end
    end.

%% init

init([]) ->
    process_flag(trap_exit, true),
    DataDir = filename:absname(application:get_env(arinsal_cloud, data_dir, "arinsal-cloud-data")),
    ok = filelib:ensure_path(DataDir),
    {ok, #st{backend = arinsal_cloud_backend:select(), data_dir = DataDir}}.

handle_call({deploy, T, P, Tar}, From, S) ->
    case valid_name(T) andalso valid_name(P) of
        false ->
            {reply, {error, bad_name}, S};
        true ->
            Key = {T, P},
            case maps:find(Key, S#st.projects) of
                {ok, #p{state = starting}} ->
                    {reply, {error, busy}, S};
                Found ->
                    Proj = case Found of
                        {ok, Existing} -> Existing;
                        error -> #p{key = Key}
                    end,
                    {noreply, start_deploy(Key, Proj, Tar, From, S)}
            end
    end;
handle_call(list, _From, S) ->
    {reply, lists:sort([to_map(P) || P <- maps:values(S#st.projects)]), S};
handle_call(_Request, _From, S) ->
    {reply, {error, badcall}, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info({worker_done, Key, Ref, Result}, S) ->
    case maps:find(Key, S#st.projects) of
        {ok, #p{worker = Ref, waiter = Waiter} = Proj} ->
            {Reply, Proj1} = finish(Result, Proj),
            gen_server:reply(Waiter, Reply),
            {noreply, put_proj(Proj1#p{waiter = undefined, worker = undefined}, S)};
        _ ->
            {noreply, S}
    end;
handle_info({project_exit, Key, Id, Reason}, S) ->
    case maps:find(Key, S#st.projects) of
        {ok, #p{state = running, handle = #{id := Id} = H} = Proj} ->
            Backend = S#st.backend,
            spawn(fun() -> try Backend:stop(H) catch _:_ -> ok end end),
            {noreply, put_proj(Proj#p{state = failed, handle = undefined, ns = undefined,
                                      error = {exited, Reason}}, S)};
        _ ->
            {noreply, S}
    end;
handle_info(_Info, S) ->
    {noreply, S}.

terminate(_Reason, #st{projects = Projects, backend = Backend}) ->
    maps:foreach(fun
        (_, #p{handle = undefined}) -> ok;
        (_, #p{handle = H}) -> Backend:stop(H)
    end, Projects),
    ok.

%% helpers

put_proj(#p{key = Key} = Proj, S) ->
    S#st{projects = maps:put(Key, Proj, S#st.projects)}.

start_deploy(Key, #p{handle = Old} = Proj, Tar, From, S) ->
    Self = self(),
    Ref = make_ref(),
    Backend = S#st.backend,
    Dir = project_dir(S#st.data_dir, Key),
    Stop = fun() -> case Old of undefined -> ok; _ -> Backend:stop(Old) end end,
    spawn(fun() ->
        Result = try
            case unpack(Dir, Tar, Stop) of
                {ok, Vsn, RelDir} -> run(Backend, Key, Proj, RelDir, Vsn);
                {error, Reason} -> {error, {bad_release, Reason}}
            end
        catch
            Class:Reason2 -> {error, {Class, Reason2}}
        end,
        Self ! {worker_done, Key, Ref, Result}
    end),
    put_proj(Proj#p{state = starting, handle = undefined, ns = undefined, worker = Ref,
                    waiter = From, error = undefined}, S).

finish({ok, #{handle := H, ns := Ns, version := Vsn, release_dir := Dir, port := Port}}, Proj) ->
    Now = erlang:system_time(millisecond),
    Proj1 = Proj#p{state = running, handle = H, ns = Ns, version = Vsn, release_dir = Dir, port = Port,
                   started_at = Now, last_request_at = Now},
    {{ok, to_map(Proj1)}, Proj1};
finish({error, Reason}, Proj) ->
    Error = case Reason of
        {bad_release, _} -> Reason;
        _ -> {start_failed, Reason}
    end,
    {{error, Error}, Proj#p{state = failed, handle = undefined, ns = undefined, error = Reason}}.

%% Runs in a worker: allocate the port, start the backend and wait for the port.
run(Backend, {Tenant, Project} = Key, Proj, RelDir, Vsn) ->
    Port = free_port(Proj#p.port),
    PortStr = integer_to_list(Port),
    Env = [{"PORT", PortStr}, {"RT_PORT", PortStr} | application:get_env(arinsal_cloud, project_env, [])],
    Spec = #{key => Key, tenant => Tenant, project => Project, release_dir => RelDir, version => Vsn,
             port => Port, env => Env, notify => whereis(?MODULE)},
    case Backend:start(Spec) of
        {ok, Handle, Ns} ->
            case wait_ready(Port, application:get_env(arinsal_cloud, ready_timeout_ms, 30000)) of
                ok ->
                    {ok, #{handle => Handle, ns => Ns, version => Vsn, release_dir => RelDir, port => Port}};
                {error, Reason} ->
                    try Backend:stop(Handle) catch _:_ -> ok end,
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Each project listens on its own 127.0.0.1 port. Ask the OS for a free one, and keep the
%% project's previous port on redeploy when it is still free.
free_port(Preferred) ->
    Opts = [{ip, {127, 0, 0, 1}}, {reuseaddr, true}],
    case Preferred of
        undefined -> pick_port(Opts);
        _ ->
            case gen_tcp:listen(Preferred, Opts) of
                {ok, L} -> gen_tcp:close(L), Preferred;
                {error, _} -> pick_port(Opts)
            end
    end.

pick_port(Opts) ->
    {ok, L} = gen_tcp:listen(0, Opts),
    {ok, Port} = inet:port(L),
    gen_tcp:close(L),
    Port.

wait_ready(_Port, 0) ->
    ok;
wait_ready(Port, Timeout) ->
    wait_ready(Port, erlang:monotonic_time(millisecond) + Timeout, Timeout).

wait_ready(Port, Deadline, Timeout) ->
    case gen_tcp:connect({127, 0, 0, 1}, Port, [], 500) of
        {ok, Sock} ->
            gen_tcp:close(Sock),
            ok;
        {error, _} ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    {error, {not_ready, Timeout}};
                false ->
                    timer:sleep(100),
                    wait_ready(Port, Deadline, Timeout)
            end
    end.

%% Unpack a release tarball into <ProjDir>/<version>. Returns the version and release dir.
%% `BeforeSwap` runs once the tarball is known good, right before the version directory is
%% replaced (the caller stops the running copy there). Other version directories are removed
%% afterwards.
unpack(ProjDir, Tar, BeforeSwap) ->
    Incoming = filename:join(ProjDir, ".incoming"),
    _ = file:del_dir_r(Incoming),
    ok = filelib:ensure_path(Incoming),
    try
        ok = check_tar(Tar),
        ok = erl_tar:extract({binary, Tar}, [compressed, {cwd, Incoming}]),
        {ok, Vsn} = release_version(Incoming),
        match = re:run(Vsn, "^[A-Za-z0-9][A-Za-z0-9._+-]{0,62}$", [{capture, none}]),
        Dest = filename:join(ProjDir, Vsn),
        ok = BeforeSwap(),
        _ = file:del_dir_r(Dest),
        ok = file:rename(Incoming, Dest),
        prune(ProjDir, Vsn),
        {ok, list_to_binary(Vsn), Dest}
    catch
        error:{badmatch, {error, Reason}} -> {error, Reason};
        error:{badmatch, Other} -> {error, Other};
        throw:{unsafe, Name} -> {error, {unsafe_path, Name}};
        Class:Reason2 -> {error, {Class, Reason2}}
    after
        file:del_dir_r(Incoming)
    end.

check_tar(Tar) ->
    case erl_tar:table({binary, Tar}, [compressed]) of
        {ok, Names} ->
            lists:foreach(fun(Name) ->
                case filename:pathtype(Name) =/= relative orelse lists:member("..", filename:split(Name)) of
                    true -> throw({unsafe, Name});
                    false -> ok
                end
            end, Names);
        {error, Reason} ->
            {error, Reason}
    end.

prune(ProjDir, Vsn) ->
    case file:list_dir(ProjDir) of
        {ok, Names} ->
            lists:foreach(fun(N) -> file:del_dir_r(filename:join(ProjDir, N)) end,
                          [N || N <- Names, N =/= Vsn]),
            ok;
        _ ->
            ok
    end.

to_map(#p{key = {Tenant, Project}, state = State, ns = Ns, release_dir = Dir, version = Vsn, port = Port,
          started_at = Started, last_request_at = Last, error = Error}) ->
    #{
        tenant => Tenant,
        project => Project,
        state => State,
        ns => Ns,
        release_dir => Dir,
        version => Vsn,
        port => Port,
        url => case Port of
            undefined -> undefined;
            _ -> iolist_to_binary(["http://127.0.0.1:", integer_to_list(Port)])
        end,
        started_at => Started,
        last_request_at => Last,
        error => Error
    }.

%% Project registry keyed by {Tenant, Project}.
%%
%% States: stopped | starting | running | stopping | failed. Deploy, start, stop and delete run in a
%% worker process so the registry stays responsive; callers wait for the result. While a project is
%% starting or stopping, other operations on it answer `{error, busy}`.
%%
%% Idle stop is a follow-up.
%%
%% App env read here: data_dir, ready_timeout_ms (default 30000, 0 disables the
%% wait for the project's port), project_env (extra {Name, Value} string pairs), log_lines.
-module(arinsal_cloud_projects).
-behaviour(gen_server).

-export([start_link/0, deploy/3, start/2, stop/2, delete/2, list/0, get/2, logs/3]).
-export([valid_name/1, project_dir/2, unpack/3, release_version/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-type key() :: {binary(), binary()}.

-record(p, {
    key :: key(),
    state = stopped :: stopped | starting | running | stopping | failed,
    phase :: start | stop | delete | undefined,
    ns :: pos_integer() | undefined,
    handle :: map() | undefined,
    release_dir :: file:filename() | undefined,
    version :: binary() | undefined,
    port :: inet:port_number() | undefined,
    started_at :: integer() | undefined,
    last_request_at :: integer() | undefined,
    error :: term(),
    log :: pid(),
    waiters = [] :: [gen_server:from()],
    worker :: reference() | undefined
}).

-record(st, {projects = #{} :: #{key() => #p{}}, backend :: module(), data_dir :: file:filename()}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec deploy(binary(), binary(), binary()) -> {ok, map()} | {error, term()}.
deploy(Tenant, Project, Tar) ->
    call({deploy, Tenant, Project, Tar}).

-spec start(binary(), binary()) -> {ok, map()} | {error, term()}.
start(Tenant, Project) ->
    call({start, Tenant, Project}).

-spec stop(binary(), binary()) -> ok | {error, term()}.
stop(Tenant, Project) ->
    call({stop, Tenant, Project}).

-spec delete(binary(), binary()) -> ok | {error, term()}.
delete(Tenant, Project) ->
    call({delete, Tenant, Project}).

-spec list() -> [map()].
list() ->
    gen_server:call(?MODULE, list).

-spec get(binary(), binary()) -> {ok, map()} | {error, not_found}.
get(Tenant, Project) ->
    gen_server:call(?MODULE, {get, Tenant, Project}).

%% Opts: n (default 100), since (sequence number from a previous call).
-spec logs(binary(), binary(), map()) -> {ok, [binary()], non_neg_integer()} | {error, not_found}.
logs(Tenant, Project, Opts) ->
    case gen_server:call(?MODULE, {log_pid, Tenant, Project}) of
        {ok, Pid} ->
            {Lines, Next} = arinsal_cloud_log:lines(Pid, Opts),
            {ok, Lines, Next};
        {error, _} = Error ->
            Error
    end.

call(Request) ->
    gen_server:call(?MODULE, Request, 300000).

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
    Backend = arinsal_cloud_backend:select(),
    {ok, #st{backend = Backend, data_dir = DataDir}}.

%% calls

handle_call({deploy, T, P, Tar}, From, S) ->
    with_key(T, P, From, S, fun(Key) ->
        case busy(Key, S) of
            true -> {reply, {error, busy}, S};
            false ->
                {Proj, S1} = ensure(Key, S),
                Old = Proj#p.handle,
                Dir = project_dir(S#st.data_dir, Key),
                Fun = fun() ->
                    case unpack(Dir, Tar, fun() -> stop_handle(S#st.backend, Old, Proj#p.log) end) of
                        {ok, Vsn, RelDir} ->
                            case run(S#st.backend, Key, Proj, RelDir, Vsn) of
                                {ok, Result} -> prune(Dir, Vsn), {ok, Result};
                                Error -> Error
                            end;
                        {error, Reason} ->
                            {error, {bad_release, Reason}}
                    end
                end,
                {noreply, begin_work(Key, start, Fun, From, Proj#p{handle = undefined, ns = undefined}, S1)}
        end
    end);
handle_call({start, T, P}, From, S) ->
    with_key(T, P, From, S, fun(Key) ->
        case maps:find(Key, S#st.projects) of
            error ->
                {reply, {error, not_found}, S};
            {ok, #p{state = running} = Proj} ->
                {reply, {ok, to_map(Proj, S)}, S};
            {ok, #p{state = State}} when State =:= starting; State =:= stopping ->
                {reply, {error, busy}, S};
            {ok, #p{release_dir = undefined}} ->
                {reply, {error, no_release}, S};
            {ok, #p{release_dir = RelDir, version = Vsn} = Proj} ->
                Fun = fun() -> run(S#st.backend, Key, Proj, RelDir, Vsn) end,
                {noreply, begin_work(Key, start, Fun, From, Proj, S)}
        end
    end);
handle_call({stop, T, P}, From, S) ->
    with_key(T, P, From, S, fun(Key) ->
        case maps:find(Key, S#st.projects) of
            error ->
                {reply, {error, not_found}, S};
            {ok, #p{state = running, handle = H} = Proj} ->
                Fun = fun() -> stop_handle(S#st.backend, H, Proj#p.log), ok end,
                {noreply, begin_work(Key, stop, Fun, From, Proj, S)};
            {ok, #p{state = State}} when State =:= starting; State =:= stopping ->
                {reply, {error, busy}, S};
            {ok, Proj} ->
                {reply, ok, put_proj(Proj#p{state = stopped, error = undefined}, S)}
        end
    end);
handle_call({delete, T, P}, From, S) ->
    with_key(T, P, From, S, fun(Key) ->
        case maps:find(Key, S#st.projects) of
            error ->
                {reply, {error, not_found}, S};
            {ok, #p{state = State}} when State =:= starting; State =:= stopping ->
                {reply, {error, busy}, S};
            {ok, #p{handle = H} = Proj} ->
                Dir = project_dir(S#st.data_dir, Key),
                Fun = fun() ->
                    stop_handle(S#st.backend, H, Proj#p.log),
                    file:del_dir_r(Dir),
                    file:del_dir(filename:dirname(Dir)),
                    ok
                end,
                {noreply, begin_work(Key, delete, Fun, From, Proj, S)}
        end
    end);
handle_call(list, _From, S) ->
    Projects = lists:sort([to_map(P, S, false) || P <- maps:values(S#st.projects)]),
    {reply, Projects, S};
handle_call({get, T, P}, _From, S) ->
    case maps:find({T, P}, S#st.projects) of
        {ok, Proj} -> {reply, {ok, to_map(Proj, S)}, S};
        error -> {reply, {error, not_found}, S}
    end;
handle_call({log_pid, T, P}, _From, S) ->
    case maps:find({T, P}, S#st.projects) of
        {ok, #p{log = Log}} -> {reply, {ok, Log}, S};
        error -> {reply, {error, not_found}, S}
    end;
handle_call(_Request, _From, S) ->
    {reply, {error, badcall}, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

%% worker results

handle_info({worker_done, Key, Ref, Result}, S) ->
    case maps:find(Key, S#st.projects) of
        {ok, #p{worker = Ref, phase = Phase, waiters = Waiters} = Proj} ->
            {Reply, Proj1, S1} = finish(Phase, Result, Proj, S),
            [gen_server:reply(W, Reply) || W <- Waiters],
            {noreply, case Phase of
                delete -> S1;
                _ -> put_proj(Proj1#p{waiters = [], worker = undefined, phase = undefined}, S1)
            end};
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
    maps:foreach(fun(_, #p{handle = H, log = Log}) -> stop_handle(Backend, H, Log) end, Projects),
    ok.

%% helpers

with_key(T, P, _From, S, Fun) ->
    case valid_name(T) andalso valid_name(P) of
        true -> Fun({T, P});
        false -> {reply, {error, bad_name}, S}
    end.

busy(Key, S) ->
    case maps:find(Key, S#st.projects) of
        {ok, #p{state = State}} -> State =:= starting orelse State =:= stopping;
        error -> false
    end.

ensure(Key, S) ->
    case maps:find(Key, S#st.projects) of
        {ok, Proj} ->
            {Proj, S};
        error ->
            LogFile = filename:join(project_dir(S#st.data_dir, Key), "out.log"),
            {ok, Log} = arinsal_cloud_log_sup:start_log(#{
                file => LogFile,
                max_lines => application:get_env(arinsal_cloud, log_lines, 1000)
            }),
            Proj = #p{key = Key, log = Log},
            {Proj, put_proj(Proj, S)}
    end.

put_proj(#p{key = Key} = Proj, S) ->
    S#st{projects = maps:put(Key, Proj, S#st.projects)}.

begin_work(Key, Phase, Fun, From, Proj, S) ->
    Self = self(),
    Ref = make_ref(),
    spawn(fun() ->
        Result = try Fun() catch Class:Reason -> {error, {Class, Reason}} end,
        Self ! {worker_done, Key, Ref, Result}
    end),
    State = case Phase of start -> starting; _ -> stopping end,
    Waiters = case From of undefined -> []; _ -> [From] end,
    put_proj(Proj#p{state = State, phase = Phase, worker = Ref, waiters = Waiters, error = undefined}, S).

finish(start, {ok, #{handle := H, ns := Ns, version := Vsn, release_dir := Dir, port := Port}}, Proj, S) ->
    Now = now_ms(),
    Proj1 = Proj#p{state = running, handle = H, ns = Ns, version = Vsn, release_dir = Dir, port = Port,
                   started_at = Now, last_request_at = Now},
    {{ok, to_map(Proj1, S)}, Proj1, S};
finish(start, {error, Reason}, Proj, S) ->
    Proj1 = Proj#p{state = failed, handle = undefined, ns = undefined, error = Reason},
    Error = case Reason of
        {bad_release, _} -> Reason;
        _ -> {start_failed, Reason}
    end,
    {{error, Error}, Proj1, S};
finish(stop, ok, Proj, S) ->
    {ok, Proj#p{state = stopped, handle = undefined, ns = undefined, started_at = undefined}, S};
finish(stop, {error, Reason}, Proj, S) ->
    {{error, Reason}, Proj#p{state = failed, error = Reason}, S};
finish(delete, ok, #p{key = Key, log = Log}, S) ->
    try arinsal_cloud_log_sup:stop_log(Log) catch _:_ -> ok end,
    {ok, undefined, S#st{projects = maps:remove(Key, S#st.projects)}};
finish(delete, {error, Reason}, Proj, S) ->
    {{error, Reason}, Proj#p{state = failed, error = Reason}, S}.

stop_handle(_Backend, undefined, _Log) ->
    ok;
stop_handle(Backend, Handle, Log) ->
    note(Log, "stopping"),
    Backend:stop(Handle).

%% Lifecycle lines go into the project's log next to its own output.
note(Log, Text) ->
    arinsal_cloud_log:write(Log, ["[manager] ", Text, "\n"]).

now_ms() ->
    erlang:system_time(millisecond).

%% Runs in a worker: allocate the port, start the backend and wait for the port.
run(Backend, {Tenant, Project} = Key, Proj, RelDir, Vsn) ->
    Port = free_port(Proj#p.port),
    PortStr = integer_to_list(Port),
    Env = [{"PORT", PortStr}, {"RT_PORT", PortStr} | application:get_env(arinsal_cloud, project_env, [])],
    note(Proj#p.log, io_lib:format("starting version ~s on 127.0.0.1:~b", [Vsn, Port])),
    Spec = #{key => Key, tenant => Tenant, project => Project, release_dir => RelDir, version => Vsn,
             port => Port, env => Env, log => Proj#p.log, notify => whereis(?MODULE)},
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

%% Unpack a release tarball into <ProjDir>/<version>. Returns the release dir and version.
%% `BeforeSwap` runs once the tarball is known good, right before the version directory is
%% replaced (the caller stops the running copy there).
unpack(ProjDir, Tar, BeforeSwap) ->
    Incoming = filename:join(ProjDir, ".incoming"),
    _ = file:del_dir_r(Incoming),
    ok = filelib:ensure_path(Incoming),
    try
        ok = check_tar(Tar),
        ok = erl_tar:extract({binary, Tar}, [compressed, {cwd, Incoming}]),
        {ok, Vsn} = release_version(Incoming),
        true = re:run(Vsn, "^[A-Za-z0-9][A-Za-z0-9._+-]{0,62}$", [{capture, none}]) =:= match,
        Dest = filename:join(ProjDir, Vsn),
        ok = BeforeSwap(),
        _ = file:del_dir_r(Dest),
        ok = file:rename(Incoming, Dest),
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
                Parts = filename:split(Name),
                case filename:pathtype(Name) =/= relative orelse lists:member("..", Parts) of
                    true -> throw({unsafe, Name});
                    false -> ok
                end
            end, Names);
        {error, Reason} ->
            {error, Reason}
    end.

%% Keep only the new version's directory and out.log.
prune(ProjDir, Vsn) ->
    Keep = [binary_to_list(Vsn), "out.log"],
    case file:list_dir(ProjDir) of
        {ok, Names} ->
            [file:del_dir_r(filename:join(ProjDir, N)) || N <- Names, not lists:member(N, Keep)],
            ok;
        _ ->
            ok
    end.

to_map(Proj, S) ->
    to_map(Proj, S, true).

to_map(#p{key = {Tenant, Project}, state = State, ns = Ns, release_dir = Dir, version = Vsn, port = Port,
          started_at = Started, last_request_at = Last, error = Error, handle = Handle}, S, Details) ->
    Base = #{
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
    },
    case Details andalso Handle =/= undefined of
        true -> Base#{info => backend_info(S#st.backend, Handle)};
        false -> Base
    end.

backend_info(Backend, Handle) ->
    try Backend:info(Handle) catch Class:Reason -> #{error => {Class, Reason}} end.

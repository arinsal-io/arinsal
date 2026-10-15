%% Boots a Mix release inside a namespace without a second kernel.
%%
%% `prepare/1` and `start/3` run in root (the manager). `prepare/1` loads into the base every
%% module of the plan that is identical to the module root's code path would load, and the
%% release's dependencies into a shared dep domain (see there). `start/3` spawns
%% the namespace's `init` (`ns_init/4`) with the project's group leader and waits until the
%% project's applications are started.
%%
%% Inside the namespace, `ns_init` registers as `init` (the namespace's own name table) and:
%%   0. copies root's persistent terms of the shared services, starts its own file_server_2;
%%   1. loads every module of the plan into the namespace's code domain (`prepare_loading` in
%%      batches, then `finish_loading`; base and dependency modules dedup to no-ops);
%%   2. sets the project's OS environment in the namespace's env overlay (the backend also
%%      passes it to `arinsal_ns:create/3`);
%%   3. starts `logger` (logger_server) and `application_controller` with the kernel app spec
%%      whose `mod` is `arinsal_ns_kernel`, so starting `kernel` brings up only Logger;
%%   4. loads every app of the plan from its own `.app` file, sets the plan's env (persistent),
%%      and starts the apps in plan order;
%%   5. answers the `init` protocol (arguments, status, stop) for the life of the project.
%%
%% code_server, inet_db, erl_prim_loader, user, standard_error, erl_signal_server and
%% timer_server stay in root; `expose_root_services/0` makes them reachable from namespaces.
%% file_server_2 runs per namespace: it spawns the io server of every `file:open/2`, and an io
%% server in root could not answer a namespace process.
-module(arinsal_ns_boot).

-export([prepare/1, start/3, expose_root_services/0]).
-export([ns_init/4, ns_main/4]).

-define(BOOT_TIMEOUT, 60000).
-define(LOAD_BATCH, 64).
-define(ROOT_SERVICES, [code_server, inet_db, erl_prim_loader, user,
                        standard_error, erl_signal_server, timer_server, kernel_refc,
                        inet_gethost_native,
                        global_name_server]).

%% Sets the SHARED bit on the root services a namespace kernel reaches by name. Called once by
%% the manager at start; services that are not running are skipped.
-spec expose_root_services() -> ok.
expose_root_services() ->
    [ok = arinsal_ns:expose(Pid) || Pid <- [whereis(Name) || Name <- ?ROOT_SERVICES], is_pid(Pid)],
    ok.

%% Runs in root before the namespace is created. The release's dependency modules (everything
%% but the project's own app and its consolidated protocols) are loaded once into a dep domain
%% registered under the hash of their (module, md5) set, so every deployment with the same
%% dependencies shares them. Returns the options for `arinsal_ns:create/3` (`dep_domain`) and
%% the plan for `start/3`, which then loads only the project's own modules.
-spec prepare(map()) -> {ok, map(), map()} | {error, term()}.
prepare(#{modules := Modules0, release := {Name, _}} = Plan) ->
    Modules = without_preloaded(Modules0),
    _ = preload_base(Modules),
    {Own, Deps} = lists:partition(fun({_, Path}) -> own_module(Path, Name) end, Modules),
    Hash = arinsal_code:deployment_hash([{M, md5(Path)} || {M, Path} <- Deps]),
    case global:trans({?MODULE, Hash}, fun() -> dep_domain(Hash, Deps) end) of
        {ok, Domain} -> {ok, #{dep_domain => Domain}, Plan#{modules := Own}};
        {error, Reason} -> {error, {dep_domain, Reason}}
    end.

dep_domain(Hash, Deps) ->
    case arinsal_code:dep_domain(Hash) of
        {ok, Domain} ->
            {ok, Domain};
        none ->
            Beams = [{M, Bin} || {M, Path} <- Deps, not erlang:module_loaded(M),
                                 {ok, Bin} <- [file:read_file(Path)]],
            Domain = arinsal_code:new_dep_domain(Hash),
            case arinsal_code:load(Domain, Beams) of
                ok -> {ok, Domain};
                {error, Reason} -> {error, Reason}
            end
    end.

%% A module of the project itself: its beam is in `lib/<Name>-<Vsn>/ebin`, or it is a
%% consolidated protocol (`releases/<Vsn>/consolidated`), which depends on the project's impls.
own_module(Path0, Name) ->
    Path = to_list(Path0),
    Dir = filename:dirname(Path),
    filename:basename(Dir) =:= "consolidated" orelse
        lists:prefix(to_list(Name) ++ "-", filename:basename(filename:dirname(Dir))).

%% Preloaded modules (erlang, erts_internal, prim_*) are always in the base; some of them are
%% root only, even their module_info.
without_preloaded(Modules) ->
    Preloaded = erlang:pre_loaded(),
    [{M, P} || {M, P} <- Modules, not lists:member(M, Preloaded)].

-spec start(pos_integer(), map(), map()) -> {ok, pid()} | {error, term()}.
start(Ns, #{modules := Modules0} = Plan0, #{group_leader := Leader} = Opts) ->
    expose_root_services(),
    Modules = without_preloaded(Modules0),
    Plan = Plan0#{modules := Modules},
    _ = preload_base(Modules),
    {module, _} = code:ensure_loaded(arinsal_ns_kernel),
    Cfg = #{kernel_app => kernel_app(),
            arguments => root_arguments(),
            os_env => maps:get(os_env, Opts, [])},
    %% A namespace process cannot send to a root pid that is not exposed; a message to an
    %% alias passes, so the boot reports back through one.
    Ref = alias([explicit_unalias]),
    Pid = arinsal_ns:spawn(Ns, ?MODULE, ns_init, [Ref, Ref, Plan, Cfg],
                           [{group_leader, Leader}]),
    try
        wait_booted(Ref, erlang:monitor(process, Pid), Pid, spawned)
    after
        unalias(Ref)
    end.

wait_booted(Ref, Mon, Pid, Step) ->
    receive
        {Ref, step, Next} ->
            wait_booted(Ref, Mon, Pid, Next);
        {Ref, booted, Init} ->
            erlang:demonitor(Mon, [flush]),
            {ok, Init};
        {Ref, failed, Reason} ->
            erlang:demonitor(Mon, [flush]),
            {error, Reason};
        {Ref, handover, Next} ->
            erlang:demonitor(Mon, [flush]),
            wait_booted(Ref, erlang:monitor(process, Next), Next, Step);
        {'DOWN', Mon, process, Pid, Reason} ->
            {error, {boot_exit, Step, Reason}}
    after ?BOOT_TIMEOUT ->
            {error, {boot_timeout, Step}}
    end.

%% Modules root's code path resolves to a beam with the same md5 are loaded into the base, so
%% every namespace shares one (natively compiled) instance and the namespace load dedups.
preload_base(Modules) ->
    Root = code:root_dir(),
    [code:ensure_loaded(M) || {M, Path} <- Modules,
                              not erlang:module_loaded(M),
                              same_as_root(M, Path, Root)].

same_as_root(M, Path, Root) ->
    case code:which(M) of
        RootPath when is_list(RootPath) ->
            lists:prefix(Root, RootPath) andalso RootPath =:= binary_to_list(Path)
                orelse md5(RootPath) =:= md5(Path);
        _ ->
            false
    end.

md5(Path) ->
    case beam_lib:md5(to_list(Path)) of
        {ok, {_, Md5}} -> Md5;
        _ -> undefined
    end.

%% persistent_term is per namespace. The runtime reads OTP system keys (code_server, erl_prim_loader,
%% prim_socket, ...) through to the root store, so nothing is copied here.

kernel_app() ->
    File = filename:join(code:lib_dir(kernel), "ebin/kernel.app"),
    {ok, [{application, kernel, Props}]} = file:consult(File),
    {application, kernel, lists:keystore(mod, 1, Props, {mod, {arinsal_ns_kernel, []}})}.

%% Flags the namespace's `init` answers with: the ones that describe the installation.
root_arguments() ->
    [{K, V} || {K, V} <- init:get_arguments(), lists:member(K, [root, bindir, progname, home])].

%% ---------------------------------------------------------------------------------------------
%% In the namespace

%% First process of the namespace. When the namespace does not give its processes a code chain
%% yet, it creates the domain and hands over to a chained process.
-spec ns_init(reference(), reference(), map(), map()) -> ok.
ns_init(Parent, Ref, Plan, Cfg) ->
    Chain = try arinsal_code:chain(self()) catch _:_ -> [0] end,
    case Chain of
        [D | _] when D =/= 0 ->
            ns_main(Parent, Ref, Plan, Cfg);
        _ ->
            Domain = arinsal_code:new_domain(0),
            Next = arinsal_code:spawn([Domain, 0], ?MODULE, ns_main, [Parent, Ref, Plan, Cfg]),
            Parent ! {Ref, handover, Next},
            ok
    end.

-spec ns_main(reference(), reference(), map(), map()) -> no_return().
ns_main(Parent, Ref, Plan, Cfg) ->
    register(init, self()),
    process_flag(trap_exit, true),
    Init = self(),
    %% Like OTP's init, the boot runs in its own process so `init` can answer the requests the
    %% application controller and the apps send while they start. The boot process stays alive:
    %% it is the parent of logger_server and the application controller.
    Boot = spawn_link(fun() -> boot_process(Init, Parent, Ref, Plan, Cfg) end),
    loop(#{args => maps:get(arguments, Cfg), status => {starting, starting}, boot => Boot}).

boot_process(Init, Parent, Ref, Plan, Cfg) ->
    put(boot_report, Parent),
    put(boot_ref, Ref),
    try boot(Plan, Cfg) of
        ok ->
            Init ! {self(), booted},
            Parent ! {Ref, booted, Init},
            receive after infinity -> ok end
    catch
        Class:Reason:Stack ->
            Parent ! {Ref, failed, {Class, Reason, Stack}},
            exit(boot_failed)
    end.

boot(#{modules := Modules, apps := Apps, env := Env, ebins := Ebins}, Cfg) ->
    step(file_server),
    {ok, _} = file_server:start_link(),
    step(load_modules),
    ok = load_modules(Modules),
    [os:putenv(K, V) || {K, V} <- maps:get(os_env, Cfg)],
    step(logger_server),
    {ok, _} = logger_server:start_link(),
    step(application_controller),
    {ok, _} = start_ac(maps:get(kernel_app, Cfg)),
    step(load_apps),
    Names = [Name || #{name := Name} <- Apps],
    [ok = load_app(Name, Ebins) || Name <- Names, Name =/= kernel],
    [ok = application:set_env(App, K, V, [{persistent, true}]) || {App, KVs} <- Env, {K, V} <- KVs],
    [ok = start_app(App) || #{type := Type} = App <- Apps, Type =/= load, Type =/= none],
    ok.

%% Tells `start/3` how far the boot got, for the error on a timeout or an exit.
step(Step) ->
    get(boot_report) ! {get(boot_ref), step, Step},
    ok.

start_ac(KernelApp) ->
    case application_controller:start(KernelApp) of
        {ok, Pid} -> {ok, Pid};
        Reason -> erlang:error({application_controller, Reason})
    end.

start_app(#{name := Name, type := Type}) ->
    step({start, Name}),
    case application:start(Name, Type) of
        ok -> ok;
        {error, {already_started, Name}} -> ok;
        {error, Reason} -> erlang:error({start_app, Name, Reason})
    end.

%% The release's ebins are not on root's code path, so each app spec is read from its own
%% `.app` file; base apps fall back to root's code path.
load_app(Name, Ebins) ->
    File = atom_to_list(Name) ++ ".app",
    Candidates = [filename:join(to_list(E), File) || E <- Ebins],
    Spec = case [P || P <- Candidates, filelib:is_regular(P)] of
               [Path | _] ->
                   {ok, [{application, Name, _} = S]} = file:consult(Path),
                   S;
               [] ->
                   Name
           end,
    case application:load(Spec) of
        ok -> ok;
        {error, {already_loaded, Name}} -> ok;
        {error, Reason} -> erlang:error({load_app, Name, Reason})
    end.

load_modules(Modules) ->
    load_batches(Modules, []).

load_batches([], []) ->
    ok;
load_batches([], Acc) ->
    finish(Acc);
load_batches([{M, Path} | Rest], Acc) when length(Acc) >= ?LOAD_BATCH ->
    ok = finish(Acc),
    load_batches([{M, Path} | Rest], []);
load_batches([{M, Path} | Rest], Acc) ->
    {ok, Bin} = file:read_file(Path),
    case already_here(M, Bin) of
        true ->
            load_batches(Rest, Acc);
        false ->
            case erlang:prepare_loading(M, Bin) of
                {error, Reason} -> erlang:error({prepare_loading, M, Reason});
                Prepared -> load_batches(Rest, [{M, Prepared} | Acc])
            end
    end.

%% A module the chain already resolves to an identical instance is skipped before it is parsed;
%% finish_loading would dedup it anyway.
already_here(M, Bin) ->
    try
        erlang:module_loaded(M) andalso
            {ok, {M, M:module_info(md5)}} =:= beam_lib:md5(Bin)
    catch
        %% A module whose natives are root only (erl_ddll) answers even module_info with
        %% notsup; it is loaded in the base and the namespace cannot use it anyway.
        error:notsup -> true
    end.

finish(Acc) ->
    {Mods, Prepared} = lists:unzip(lists:reverse(Acc)),
    case erlang:finish_loading(Prepared) of
        ok -> ok;
        {Reason, Bad} -> erlang:error({finish_loading, Reason, Bad, length(Mods)})
    end.

loop(#{args := Args, status := Status, boot := Boot} = S) ->
    receive
        {Boot, booted} -> loop(S#{status := {started, started}});
        {'EXIT', Boot, Reason} -> exit(Reason);
        {From, get_plain_arguments} -> From ! {init, []}, loop(S);
        {From, get_arguments} -> From ! {init, Args}, loop(S);
        {From, {get_argument, Arg}} -> From ! {init, argument(Arg, Args)}, loop(S);
        {From, get_status} -> From ! {init, Status}, loop(S);
        {From, script_id} -> From ! {init, {"ns", "0"}}, loop(S);
        {From, {notify_when_started, _}} -> From ! {init, started}, loop(S);
        {From, {ensure_loaded, _}} -> From ! {init, not_allowed}, loop(S);
        {From, {get_configfd, _}} -> From ! {init, none}, loop(S);
        {From, get_script_name} -> From ! {init, none}, loop(S);
        %% `init:stop/0,1` and `halt` inside a namespace destroy the namespace.
        {stop, _} -> erlang:halt();
        {'EXIT', _, _} -> loop(S);
        _ -> loop(S)
    end.

argument(Arg, Args) ->
    case [V || {K, V} <- Args, K =:= Arg] of
        [] -> error;
        Vs -> {ok, Vs}
    end.

to_list(B) when is_binary(B) -> binary_to_list(B);
to_list(L) -> L.

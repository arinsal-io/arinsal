%% Turns an unpacked Mix release (`include_erts: false`) into a boot plan.
%%
%% The plan is read from `releases/<vsn>/start.boot`, the compiled boot script of the release:
%%   modules  all {Module, BeamPath} the script would `primLoad`, resolved against the script's
%%            `path` instructions (so `$ROOT` applications come from the host runtime and
%%            `$RELEASE_LIB` ones from the release). Protocol consolidation beams win because the
%%            script puts that directory first. Base applications are included; deduplication
%%            against what the namespace already shares is the runtime's job.
%%   apps     the applications started by the script, in start order
%%   env      application env from `releases/<vsn>/sys.config`
%%   ebins    ordered, existing code path directories
%%   release  {Name, Vsn}
%%
%% Out of scope: `config/runtime.exs` and other config providers (they are not evaluated), and
%% `vm.args`.
-module(arinsal_cloud_boot).

-export([boot_plan/1, boot_plan/2, release_version/1]).

-type plan() :: #{
    release := {binary(), binary()},
    modules := [{module(), binary()}],
    apps := [#{name := atom(), vsn := binary(), type := atom()}],
    env := [{atom(), [{atom(), term()}]}],
    ebins := [binary()]
}.
-export_type([plan/0]).

-spec boot_plan(file:filename()) -> {ok, plan()} | {error, term()}.
boot_plan(ReleaseDir) ->
    boot_plan(ReleaseDir, #{}).

%% Opts: root => directory used for `$ROOT` (default `code:root_dir()`).
-spec boot_plan(file:filename(), map()) -> {ok, plan()} | {error, term()}.
boot_plan(ReleaseDir, Opts) ->
    Root = maps:get(root, Opts, code:root_dir()),
    try
        {ok, Vsn} = release_version(ReleaseDir),
        VsnDir = filename:join([ReleaseDir, "releases", Vsn]),
        {Name, Instrs} = read_boot(VsnDir),
        Vars = #{"ROOT" => to_list(Root), "RELEASE_LIB" => filename:join(ReleaseDir, "lib")},
        {Modules, Ebins} = modules(Instrs, Vars),
        {ok, #{
            release => {to_bin(Name), to_bin(Vsn)},
            modules => Modules,
            apps => apps(Instrs),
            env => read_env(VsnDir),
            ebins => Ebins
        }}
    catch
        throw:{error, _} = Error -> Error;
        error:{badmatch, {error, Reason}} -> {error, Reason};
        Class:Reason:_ -> {error, {Class, Reason}}
    end.

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
            Boots = filelib:wildcard(filename:join([ReleaseDir, "releases", "*", "start.boot"])),
            case Boots of
                [Boot] -> {ok, filename:basename(filename:dirname(Boot))};
                [] -> {error, no_release};
                _ -> {error, ambiguous_release}
            end
    end.

read_boot(VsnDir) ->
    case file:read_file(filename:join(VsnDir, "start.boot")) of
        {ok, Bin} ->
            try binary_to_term(Bin) of
                {script, {Name, _Vsn}, Instrs} when is_list(Instrs) -> {Name, Instrs};
                _ -> throw({error, bad_boot_script})
            catch
                error:badarg -> throw({error, bad_boot_script})
            end;
        {error, _} ->
            case file:consult(filename:join(VsnDir, "start.script")) of
                {ok, [{script, {Name, _Vsn}, Instrs}]} -> {Name, Instrs};
                _ -> throw({error, no_boot_script})
            end
    end.

modules(Instrs, Vars) ->
    {Acc, _Seen, Ebins} = modules(Instrs, Vars, [], [], #{}, []),
    {lists:reverse(Acc), [to_bin(E) || E <- Ebins]}.

modules([], _Vars, _Path, Acc, Seen, Ebins) ->
    {Acc, Seen, Ebins};
modules([{path, Dirs} | Rest], Vars, _Path, Acc, Seen, Ebins) ->
    Resolved = [resolve(D, Vars) || D <- Dirs],
    New = [D || D <- Resolved, not lists:member(D, Ebins), filelib:is_dir(D)],
    modules(Rest, Vars, Resolved, Acc, Seen, Ebins ++ New);
modules([{primLoad, Mods} | Rest], Vars, Path, Acc, Seen, Ebins) ->
    {Acc1, Seen1} = lists:foldl(fun(M, {A, S}) ->
        case maps:is_key(M, S) of
            true ->
                {A, S};
            false ->
                case find_beam(M, Path) of
                    undefined -> {A, S};
                    File -> {[{M, to_bin(File)} | A], S#{M => true}}
                end
        end
    end, {Acc, Seen}, Mods),
    modules(Rest, Vars, Path, Acc1, Seen1, Ebins);
modules([_ | Rest], Vars, Path, Acc, Seen, Ebins) ->
    modules(Rest, Vars, Path, Acc, Seen, Ebins).

find_beam(Mod, Path) ->
    File = atom_to_list(Mod) ++ ".beam",
    lists:foldl(fun
        (Dir, undefined) ->
            Candidate = filename:join(Dir, File),
            case filelib:is_regular(Candidate) of
                true -> Candidate;
                false -> undefined
            end;
        (_, Found) ->
            Found
    end, undefined, Path).

resolve("$" ++ Rest, Vars) ->
    {Var, Tail} = lists:splitwith(fun(C) -> C =/= $/ end, Rest),
    case maps:find(Var, Vars) of
        {ok, Base} -> normalize(filename:join(Base, string:trim(Tail, leading, "/")));
        error -> throw({error, {unknown_boot_var, Var}})
    end;
resolve(Dir, _Vars) ->
    Dir.

normalize(Path) ->
    Parts = lists:foldl(fun
        ("..", [_ | Up]) -> Up;
        (Part, Acc) -> [Part | Acc]
    end, [], filename:split(Path)),
    filename:join(lists:reverse(Parts)).

apps(Instrs) ->
    Vsns = lists:foldl(fun
        ({apply, {application, load, [{application, App, Keys}]}}, Acc) ->
            Acc#{App => proplists:get_value(vsn, Keys, "")};
        (_, Acc) ->
            Acc
    end, #{}, Instrs),
    [#{name => App, vsn => to_bin(maps:get(App, Vsns, "")), type => Type}
     || {apply, {application, start_boot, [App, Type]}} <- Instrs].

read_env(VsnDir) ->
    case file:consult(filename:join(VsnDir, "sys.config")) of
        {ok, [Config]} when is_list(Config) ->
            [{App, KVs} || {App, KVs} <- Config, is_atom(App), is_list(KVs)];
        _ ->
            []
    end.

to_list(B) when is_binary(B) -> binary_to_list(B);
to_list(L) when is_list(L) -> L.

to_bin(B) when is_binary(B) -> B;
to_bin(A) when is_atom(A) -> atom_to_binary(A);
to_bin(L) when is_list(L) -> unicode:characters_to_binary(L).

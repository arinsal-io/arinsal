-module(arinsal_cloud_boot_tests).
-include_lib("eunit/include/eunit.hrl").

-export([make_release/2]).

tmp(Name) ->
    Dir = filename:join(["/tmp", "arinsal_cloud_eunit_" ++ integer_to_list(erlang:unique_integer([positive])) ++ Name]),
    ok = filelib:ensure_path(Dir),
    Dir.

touch(Path) ->
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, <<>>).

%% A release shaped like Mix's: start.boot with `$ROOT` and `$RELEASE_LIB` paths.
make_release(Dir, Vsn) ->
    Root = filename:join(Dir, "root"),
    Rel = filename:join(Dir, "rel"),
    touch(filename:join([Root, "lib", "kernel-1", "ebin", "kmod.beam"])),
    touch(filename:join([Rel, "lib", "foo-1.0", "ebin", "foo.beam"])),
    touch(filename:join([Rel, "lib", "foo-1.0", "ebin", "foo_sup.beam"])),
    touch(filename:join([Rel, "lib", "elixir-1.0", "ebin", "elixir.beam"])),
    touch(filename:join([Rel, "releases", Vsn, "consolidated", "foo_proto.beam"])),
    ok = file:write_file(filename:join([Rel, "releases", "start_erl.data"]), "17.1 " ++ Vsn),
    ok = file:write_file(filename:join([Rel, "releases", Vsn, "sys.config"]),
                         "%% coding: utf-8\n[{foo,[{port,1},{name,<<\"x\">>}]},{logger,[{level,warning}]}].\n"),
    Script = {script, {"foo", Vsn}, [
        {preLoaded, [erlang]},
        {path, ["$ROOT/lib/kernel-1/ebin"]},
        {primLoad, [kmod]},
        {kernel_load_completed},
        {path, ["$RELEASE_LIB/../releases/" ++ Vsn ++ "/consolidated", "$RELEASE_LIB/elixir-1.0/ebin"]},
        {primLoad, [foo_proto, elixir]},
        {path, ["$RELEASE_LIB/foo-1.0/ebin"]},
        {primLoad, [foo, foo_sup, not_on_disk, kmod]},
        {apply, {application, load, [{application, kernel, [{vsn, "1"}]}]}},
        {apply, {application, load, [{application, foo, [{vsn, "1.0"}]}]}},
        {apply, {application, load, [{application, iex, [{vsn, "1.0"}]}]}},
        {apply, {application, start_boot, [kernel, permanent]}},
        {apply, {application, start_boot, [foo, temporary]}}
    ]},
    ok = file:write_file(filename:join([Rel, "releases", Vsn, "start.boot"]), term_to_binary(Script)),
    {Rel, Root}.

boot_plan_test() ->
    Dir = tmp("boot"),
    {Rel, Root} = make_release(Dir, "1.2.3"),
    {ok, Plan} = arinsal_cloud_boot:boot_plan(Rel, #{root => Root}),
    #{release := {<<"foo">>, <<"1.2.3">>}, modules := Mods, apps := Apps, env := Env, ebins := Ebins} = Plan,
    ?assertEqual([kmod, foo_proto, elixir, foo, foo_sup], [M || {M, _} <- Mods]),
    ?assertEqual(<<(list_to_binary(Root))/binary, "/lib/kernel-1/ebin/kmod.beam">>, proplists:get_value(kmod, Mods)),
    ?assertEqual(<<(list_to_binary(Rel))/binary, "/releases/1.2.3/consolidated/foo_proto.beam">>,
                 proplists:get_value(foo_proto, Mods)),
    ?assertEqual([#{name => kernel, vsn => <<"1">>, type => permanent},
                  #{name => foo, vsn => <<"1.0">>, type => temporary}], Apps),
    ?assertEqual([{foo, [{port, 1}, {name, <<"x">>}]}, {logger, [{level, warning}]}], Env),
    ?assertEqual(4, length(Ebins)),
    ?assert(lists:member(list_to_binary(filename:join(Rel, "lib/foo-1.0/ebin")), Ebins)),
    file:del_dir_r(Dir).

script_fallback_test() ->
    Dir = tmp("script"),
    {Rel, Root} = make_release(Dir, "0.1.0"),
    VsnDir = filename:join([Rel, "releases", "0.1.0"]),
    {ok, Bin} = file:read_file(filename:join(VsnDir, "start.boot")),
    ok = file:write_file(filename:join(VsnDir, "start.script"), io_lib:format("~p.~n", [binary_to_term(Bin)])),
    ok = file:delete(filename:join(VsnDir, "start.boot")),
    ok = file:delete(filename:join([Rel, "releases", "start_erl.data"])),
    ?assertMatch({error, no_release}, arinsal_cloud_boot:boot_plan(Rel, #{root => Root})),
    ok = file:write_file(filename:join(VsnDir, "start.boot"), <<>>),
    ?assertMatch({error, bad_boot_script}, arinsal_cloud_boot:boot_plan(Rel, #{root => Root})),
    ok = file:write_file(filename:join([Rel, "releases", "start_erl.data"]), "17.1 0.1.0"),
    ok = file:delete(filename:join(VsnDir, "start.boot")),
    ?assertMatch({ok, #{modules := [_ | _]}}, arinsal_cloud_boot:boot_plan(Rel, #{root => Root})),
    file:del_dir_r(Dir).

missing_release_test() ->
    Dir = tmp("missing"),
    ?assertEqual({error, no_release}, arinsal_cloud_boot:boot_plan(Dir)),
    file:del_dir_r(Dir).

unknown_boot_var_test() ->
    Dir = tmp("var"),
    {Rel, Root} = make_release(Dir, "1.0.0"),
    Script = {script, {"foo", "1.0.0"}, [{path, ["$NOPE/x"]}]},
    ok = file:write_file(filename:join([Rel, "releases", "1.0.0", "start.boot"]), term_to_binary(Script)),
    ?assertEqual({error, {unknown_boot_var, "NOPE"}}, arinsal_cloud_boot:boot_plan(Rel, #{root => Root})),
    file:del_dir_r(Dir).

%% Against a real `mix release` of poc/multitenancy/bench/rest. The ExUnit wrapper builds it (with
%% stock OTP) and passes the directory in ARINSAL_CLOUD_REST_RELEASE; without it these are skipped.

real_release_test_() ->
    case os:getenv("ARINSAL_CLOUD_REST_RELEASE") of
        false -> [];
        Dir -> {timeout, 60, fun() -> real_release(Dir) end}
    end.

real_release(Dir) ->
    {ok, Plan} = arinsal_cloud_boot:boot_plan(Dir),
    #{release := Release, modules := Mods, apps := Apps, env := Env, ebins := Ebins} = Plan,
    ?assertEqual({<<"rt">>, <<"0.1.0">>}, Release),
    Names = [maps:get(name, A) || A <- Apps],
    ?assertEqual(kernel, hd(Names)),
    ?assertEqual(rt, lists:last(Names)),
    [?assert(lists:member(App, Names)) || App <- [stdlib, elixir, logger, bandit, plug, jason]],
    ?assert(index(elixir, Names) < index(logger, Names)),
    ?assert(index(bandit, Names) < index(rt, Names)),
    ?assert(index(plug, Names) < index(rt, Names)),
    ?assertEqual(#{name => rt, vsn => <<"0.1.0">>, type => permanent}, lists:last(Apps)),
    ?assertEqual([{logger, [{level, warning}]}], Env),
    %% modules of every lib/*/ebin the script loads
    RtBeam = proplists:get_value('Elixir.RT.Router', Mods),
    ?assertEqual(list_to_binary(filename:join([Dir, "lib", "rt-0.1.0", "ebin", "Elixir.RT.Router.beam"])), RtBeam),
    BanditBeam = proplists:get_value('Elixir.Bandit', Mods),
    ?assertMatch({_, _}, binary:match(BanditBeam, <<"/lib/bandit-">>)),
    %% base applications come from the host runtime ($ROOT), not from the release
    KernelBeam = proplists:get_value(application_controller, Mods),
    ?assertEqual(list_to_binary(filename:join(code:lib_dir(kernel), "ebin/application_controller.beam")), KernelBeam),
    %% Elixir protocols come from the consolidation directory
    Enumerable = proplists:get_value('Elixir.Enumerable', Mods),
    ?assertMatch({_, _}, binary:match(Enumerable, <<"/releases/0.1.0/consolidated/">>)),
    ?assertEqual(length(Mods), length(lists:usort([M || {M, _} <- Mods]))),
    [?assert(filelib:is_regular(binary_to_list(Beam))) || {_, Beam} <- Mods],
    [?assert(filelib:is_dir(binary_to_list(E))) || E <- Ebins],
    ?assert(length(Mods) > 500).

index(Item, List) ->
    length(lists:takewhile(fun(X) -> X =/= Item end, List)).

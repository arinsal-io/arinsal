-module(arinsal_cloud_ns_tests).
-include_lib("eunit/include/eunit.hrl").

%% The stub boot module says it is not implemented, so `auto` keeps the fake backend.
select_test_() ->
    {setup,
     fun() -> application:unset_env(arinsal_cloud, ns_boot) end,
     fun(_) -> application:unset_env(arinsal_cloud, backend) end,
     [
        fun() ->
            application:set_env(arinsal_cloud, backend, auto),
            ?assertNot(arinsal_ns_boot:implemented()),
            ?assertEqual(arinsal_cloud_fake, arinsal_cloud_backend:select())
        end,
        fun() ->
            application:set_env(arinsal_cloud, backend, fake),
            ?assertEqual(arinsal_cloud_fake, arinsal_cloud_backend:select()),
            application:set_env(arinsal_cloud, backend, ns),
            ?assertEqual(arinsal_cloud_ns, arinsal_cloud_backend:select()),
            application:set_env(arinsal_cloud, backend, arinsal_cloud_stub),
            ?assertEqual(arinsal_cloud_stub, arinsal_cloud_backend:select())
        end,
        fun() ->
            application:set_env(arinsal_cloud, ns_boot, arinsal_cloud_test_boot),
            application:set_env(arinsal_cloud, backend, auto),
            Expected = case arinsal_cloud_ns:natives_available() of
                true -> arinsal_cloud_ns;
                false -> arinsal_cloud_fake
            end,
            ?assertEqual(Expected, arinsal_cloud_backend:select()),
            application:unset_env(arinsal_cloud, ns_boot)
        end
     ]}.

stub_boot_raises_test() ->
    ?assertError(not_implemented, arinsal_ns_boot:start(1, #{}, #{})).

without_natives_test() ->
    case arinsal_cloud_ns:natives_available() of
        true -> ok;
        false ->
            ?assertEqual({error, ns_natives_missing},
                         arinsal_cloud_ns:start(#{tenant => <<"t">>, project => <<"p">>, release_dir => "/nope",
                                                  log => self(), env => [], key => {<<"t">>, <<"p">>}, notify => self()}))
    end.

backend_test_() ->
    case arinsal_cloud_ns:natives_available() of
        false -> [];
        true -> {timeout, 60, fun backend/0}
    end.

backend() ->
    Tmp = "/tmp/arinsal_cloud_ns_eunit_" ++ integer_to_list(erlang:unique_integer([positive])),
    {Rel, _} = arinsal_cloud_boot_tests:make_release(Tmp, "1.0.0"),
    application:set_env(arinsal_cloud, ns_boot, arinsal_cloud_test_boot),
    {ok, Log} = arinsal_cloud_log:start_link(#{}),
    Name = integer_to_binary(erlang:unique_integer([positive])),
    Key = {<<"nstest">>, Name},
    Spec = #{key => Key, tenant => <<"nstest">>, project => Name, release_dir => Rel, version => <<"1.0.0">>,
             port => 4321, env => [{"PORT", "4321"}], log => Log, notify => self()},
    {ok, Handle, Ns} = arinsal_cloud_ns:start(Spec),
    ?assert(is_integer(Ns) andalso Ns > 0),
    #{pid := Pid} = Handle,
    ?assertEqual(Ns, arinsal_ns:'of'(Pid)),
    ?assertNotEqual(0, arinsal_ns:'of'(Pid)),
    ?assertMatch(#{backend := ns, ns := Ns}, arinsal_cloud_ns:info(Handle)),
    case exposed() of
        true ->
            %% the log collector is reachable from the namespace once `expose/1` exists
            ok = wait_log(Log, <<"hello from rt on 4321"/utf8>>, 50);
        false ->
            ok
    end,
    ok = arinsal_cloud_ns:stop(Handle),
    ok = wait_dead(Pid, 50),
    %% a missing release is reported, not raised
    ?assertMatch({error, {boot_plan, _}}, arinsal_cloud_ns:start(Spec#{release_dir => "/nonexistent"})),
    %% a boot module that raises destroys the namespace again and reports it
    application:unset_env(arinsal_cloud, ns_boot),
    ?assertMatch({error, {boot_failed, {error, not_implemented}}},
                 arinsal_cloud_ns:start(Spec#{project => <<Name/binary, "x">>})),
    arinsal_cloud_log:stop(Log),
    file:del_dir_r(Tmp).

exposed() ->
    try arinsal_ns:expose(self()) of
        _ -> true
    catch
        error:undef -> false
    end.

wait_log(_Log, _Line, 0) ->
    timeout;
wait_log(Log, Line, N) ->
    {Lines, _} = arinsal_cloud_log:lines(Log, #{n => 100}),
    case lists:member(Line, Lines) of
        true -> ok;
        false -> timer:sleep(100), wait_log(Log, Line, N - 1)
    end.

wait_dead(_Pid, 0) ->
    timeout;
wait_dead(Pid, N) ->
    %% the manager must be exposed to ask about a namespace process; probing through a monitor
    %% avoids a request/reply
    Ref = erlang:monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    after 100 ->
        erlang:demonitor(Ref, [flush]),
        wait_dead(Pid, N - 1)
    end.

%% Deploy, stop, start and delete through the registry with the namespace backend.
registry_test_() ->
    case arinsal_cloud_ns:natives_available() of
        false -> [];
        true -> {timeout, 60, fun registry/0}
    end.

registry() ->
    Tmp = "/tmp/arinsal_cloud_ns_reg_" ++ integer_to_list(erlang:unique_integer([positive])),
    {Rel, _} = arinsal_cloud_boot_tests:make_release(Tmp, "1.0.0"),
    TarFile = Tmp ++ ".tar.gz",
    ok = erl_tar:create(TarFile, [{"lib", filename:join(Rel, "lib")}, {"releases", filename:join(Rel, "releases")}],
                        [compressed]),
    {ok, Tar} = file:read_file(TarFile),
    _ = application:stop(arinsal_cloud),
    application:set_env(arinsal_cloud, data_dir, Tmp ++ "_data"),
    application:set_env(arinsal_cloud, admin_port, 0),
    application:set_env(arinsal_cloud, backend, ns),
    application:set_env(arinsal_cloud, ns_boot, arinsal_cloud_test_boot),
    application:set_env(arinsal_cloud, ready_timeout_ms, 0),
    {ok, Sup} = arinsal_cloud_sup:start_link(),
    unlink(Sup),
    try
        T = <<"nsreg">>,
        P = integer_to_binary(erlang:unique_integer([positive])),
        {ok, #{state := running, ns := Ns, info := Info}} = begin
            {ok, _} = arinsal_cloud_projects:deploy(T, P, Tar),
            arinsal_cloud_projects:get(T, P)
        end,
        ?assert(is_integer(Ns) andalso Ns > 0),
        ?assertMatch(#{backend := ns, ns := Ns}, Info),
        ok = arinsal_cloud_projects:stop(T, P),
        ?assertMatch({ok, #{state := stopped, ns := undefined}}, arinsal_cloud_projects:get(T, P)),
        {ok, #{state := running, ns := Ns2}} = arinsal_cloud_projects:start(T, P),
        ?assert(is_integer(Ns2)),
        ok = arinsal_cloud_projects:delete(T, P),
        ?assertEqual({error, not_found}, arinsal_cloud_projects:get(T, P))
    after
        exit(Sup, shutdown),
        timer:sleep(100),
        application:unset_env(arinsal_cloud, backend),
        application:unset_env(arinsal_cloud, ns_boot),
        application:unset_env(arinsal_cloud, admin_port),
        application:unset_env(arinsal_cloud, data_dir),
        file:del_dir_r(Tmp),
        file:del_dir_r(Tmp ++ "_data"),
        file:delete(TarFile)
    end.

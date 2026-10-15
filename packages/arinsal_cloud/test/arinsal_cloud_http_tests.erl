-module(arinsal_cloud_http_tests).
-include_lib("eunit/include/eunit.hrl").

route_test_() ->
    [
        ?_assertEqual(list, arinsal_cloud_http:route(<<"GET">>, [<<"projects">>])),
        ?_assertEqual(method_not_allowed, arinsal_cloud_http:route(<<"POST">>, [<<"projects">>])),
        ?_assertEqual({deploy, <<"a">>, <<"b">>},
                      arinsal_cloud_http:route(<<"PUT">>, [<<"projects">>, <<"a">>, <<"b">>])),
        ?_assertEqual(method_not_allowed,
                      arinsal_cloud_http:route(<<"GET">>, [<<"projects">>, <<"a">>, <<"b">>])),
        ?_assertEqual(not_found, arinsal_cloud_http:route(<<"GET">>, [])),
        ?_assertEqual(not_found, arinsal_cloud_http:route(<<"GET">>, [<<"other">>])),
        ?_assertEqual(not_found, arinsal_cloud_http:route(<<"GET">>, [<<"projects">>, <<"a">>])),
        ?_assertEqual(not_found,
                      arinsal_cloud_http:route(<<"PUT">>, [<<"projects">>, <<"a">>, <<"b">>, <<"x">>]))
    ].

json_safe_test() ->
    Term = #{state => running, ns => undefined, release_dir => "/tmp/x", info => #{pid => self()},
             error => {start_failed, {bad_release, eof}}, list => [1, 2], port => 80},
    Json = iolist_to_binary(json:encode(arinsal_cloud_http:json_safe(Term))),
    Decoded = json:decode(Json),
    ?assertEqual(<<"running">>, maps:get(<<"state">>, Decoded)),
    ?assertEqual(null, maps:get(<<"ns">>, Decoded)),
    ?assertEqual(<<"/tmp/x">>, maps:get(<<"release_dir">>, Decoded)),
    ?assertEqual([<<"start_failed">>, [<<"bad_release">>, <<"eof">>]], maps:get(<<"error">>, Decoded)),
    ?assertEqual([1, 2], maps:get(<<"list">>, Decoded)),
    ?assert(is_binary(maps:get(<<"pid">>, maps:get(<<"info">>, Decoded)))).

valid_name_test_() ->
    [
        ?_assert(arinsal_cloud_projects:valid_name(<<"acme">>)),
        ?_assert(arinsal_cloud_projects:valid_name(<<"a-b_9">>)),
        ?_assertNot(arinsal_cloud_projects:valid_name(<<"..">>)),
        ?_assertNot(arinsal_cloud_projects:valid_name(<<"a/b">>)),
        ?_assertNot(arinsal_cloud_projects:valid_name(<<>>)),
        ?_assertNot(arinsal_cloud_projects:valid_name("acme"))
    ].

%% Deploy and list through the socket, with a stub backend.

http_flow_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(Ctx) -> {timeout, 60, fun() -> flow(Ctx) end} end}.

setup() ->
    Dir = "/tmp/arinsal_cloud_http_eunit_" ++ integer_to_list(erlang:unique_integer([positive])),
    _ = application:stop(arinsal_cloud),
    application:set_env(arinsal_cloud, data_dir, Dir),
    application:set_env(arinsal_cloud, admin_port, 0),
    application:set_env(arinsal_cloud, backend, arinsal_cloud_stub),
    application:set_env(arinsal_cloud, ready_timeout_ms, 0),
    {ok, Sup} = arinsal_cloud_sup:start_link(),
    unlink(Sup),
    #{dir => Dir, sup => Sup, port => arinsal_cloud_http:port()}.

cleanup(#{dir := Dir, sup := Sup}) ->
    exit(Sup, shutdown),
    timer:sleep(100),
    file:del_dir_r(Dir),
    application:unset_env(arinsal_cloud, backend),
    application:unset_env(arinsal_cloud, admin_port),
    application:unset_env(arinsal_cloud, data_dir).

flow(#{port := Port, dir := Dir}) ->
    ?assertEqual({200, []}, req(Port, "GET", "/projects", <<>>)),
    Tar = release_tar("2.0.0", [{"lib/foo-1/ebin/foo.beam", <<>>}]),
    {200, Acme} = req(Port, "PUT", "/projects/acme/shop", Tar),
    ?assertMatch(#{<<"state">> := <<"running">>, <<"ns">> := 42, <<"version">> := <<"2.0.0">>,
                   <<"tenant">> := <<"acme">>, <<"project">> := <<"shop">>}, Acme),
    {200, Globex} = req(Port, "PUT", "/projects/globex/shop", Tar),
    PortA = maps:get(<<"port">>, Acme),
    PortG = maps:get(<<"port">>, Globex),
    ?assertNotEqual(PortA, PortG),
    ?assertEqual(<<"http://127.0.0.1:", (integer_to_binary(PortA))/binary>>, maps:get(<<"url">>, Acme)),
    {200, List} = req(Port, "GET", "/projects", <<>>),
    ?assertEqual([<<"acme">>, <<"globex">>], [maps:get(<<"tenant">>, P) || P <- List]),
    ?assert(filelib:is_regular(filename:join([Dir, "acme", "shop", "2.0.0", "lib", "foo-1", "ebin", "foo.beam"]))),
    %% redeploy keeps the port and replaces the version directory
    Tar2 = release_tar("2.1.0", []),
    {200, Again} = req(Port, "PUT", "/projects/acme/shop", Tar2),
    ?assertEqual(PortA, maps:get(<<"port">>, Again)),
    ?assertEqual(<<"2.1.0">>, maps:get(<<"version">>, Again)),
    ?assertNot(filelib:is_dir(filename:join([Dir, "acme", "shop", "2.0.0"]))),
    %% errors
    ?assertMatch({400, #{<<"error">> := [<<"bad_release">>, _]}}, req(Port, "PUT", "/projects/acme/bad", <<"not a tarball">>)),
    Evil = tar([{"../evil", <<"x">>}]),
    ?assertMatch({400, #{<<"error">> := [<<"bad_release">>, [<<"unsafe_path">>, _]]}},
                 req(Port, "PUT", "/projects/acme/evil", Evil)),
    ?assertMatch({400, #{<<"error">> := <<"bad_name">>}}, req(Port, "PUT", "/projects/acme/..", Tar)),
    ?assertMatch({405, _}, req(Port, "POST", "/projects", <<>>)),
    ?assertMatch({404, _}, req(Port, "GET", "/nope", <<>>)).

release_tar(Vsn, Extra) ->
    tar([{"releases/start_erl.data", list_to_binary("17.1 " ++ Vsn)},
         {"releases/" ++ Vsn ++ "/sys.config", <<"[].">>} | Extra]).

tar(Entries) ->
    File = "/tmp/arinsal_cloud_eunit_tar_" ++ integer_to_list(erlang:unique_integer([positive])) ++ ".tar.gz",
    {ok, Tar} = erl_tar:open(File, [write, compressed]),
    lists:foreach(fun({Name, Bin}) -> ok = erl_tar:add(Tar, Bin, Name, [{mode, 8#644}]) end, Entries),
    ok = erl_tar:close(Tar),
    {ok, Bin} = file:read_file(File),
    file:delete(File),
    Bin.

req(Port, Method, Path, Body) ->
    {ok, Sock} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}, {packet, raw}]),
    ok = gen_tcp:send(Sock, [Method, " ", Path, " HTTP/1.1\r\nHost: x\r\nContent-Length: ",
                             integer_to_list(byte_size(Body)), "\r\n\r\n", Body]),
    Resp = recv_all(Sock, <<>>),
    gen_tcp:close(Sock),
    [Head, Payload] = binary:split(Resp, <<"\r\n\r\n">>),
    [<<"HTTP/1.1 ", Status:3/binary, _/binary>> | _] = binary:split(Head, <<"\r\n">>),
    {binary_to_integer(Status), json:decode(Payload)}.

recv_all(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 30000) of
        {ok, Data} -> recv_all(Sock, <<Acc/binary, Data/binary>>);
        {error, closed} -> Acc
    end.

-module(arinsal_cloud_log_tests).
-include_lib("eunit/include/eunit.hrl").

io_protocol_test() ->
    File = "/tmp/arinsal_cloud_log_eunit_" ++ integer_to_list(erlang:unique_integer([positive])) ++ "/out.log",
    {ok, Log} = arinsal_cloud_log:start_link(#{file => File, max_lines => 3}),
    {ok, Proc} = (fun() ->
        Parent = self(),
        Pid = spawn(fun() ->
            group_leader(Log, self()),
            io:format("one~ntw"),
            io:put_chars(["o", $\n, "three\n"]),
            io:format("~ts~n", [[1090, 1077, 1089, 1090]]),
            Parent ! {done, self()}
        end),
        receive {done, Pid} -> {ok, Pid} after 2000 -> timeout end
    end)(),
    ?assert(is_pid(Proc)),
    {Lines, Next} = arinsal_cloud_log:lines(Log, #{n => 100}),
    ?assertEqual([<<"two">>, <<"three">>, <<"тест"/utf8>>], Lines),
    ?assertEqual(4, Next),
    ?assertEqual({[<<"тест"/utf8>>], 4}, arinsal_cloud_log:lines(Log, #{n => 1})),
    ?assertEqual({[<<"тест"/utf8>>], 4}, arinsal_cloud_log:lines(Log, #{n => 100, since => 3})),
    ?assertEqual({[], 4}, arinsal_cloud_log:lines(Log, #{n => 100, since => 4})),
    arinsal_cloud_log:write(Log, <<"raw par">>),
    arinsal_cloud_log:write(Log, <<"tial\n">>),
    ?assertEqual({[<<"raw partial">>], 5}, arinsal_cloud_log:lines(Log, #{n => 1})),
    arinsal_cloud_log:stop(Log),
    {ok, Written} = file:read_file(File),
    ?assertEqual(<<"one\ntwo\nthree\nтест\nraw partial\n"/utf8>>, Written),
    file:del_dir_r(filename:dirname(File)).

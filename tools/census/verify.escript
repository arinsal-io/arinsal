#!/usr/bin/env escript
%%! -noshell

main(_) ->
    Root = filename:dirname(filename:dirname(filename:dirname(escript:script_name()))),
    Dir = filename:join([Root,"docs","census"]),
    Scenarios = [bench,boot,hello,elixir,iex,mix],
    lists:foreach(fun(S) ->
        Name = atom_to_list(S),
        Rows = csv(filename:join(Dir,"dynamic-"++Name++".csv")),
        true = Rows =/= [],
        {ok,[_]} = file:consult(filename:join(Dir,"snapshot-"++Name++"-stop.term")),
        {ok,[_]} = file:consult(filename:join(Dir,"port-opens-"++Name++".term"))
    end,Scenarios),
    true = member(["erlang","spawn","3","1000","bif"],
                  csv(filename:join(Dir,"dynamic-bench.csv"))),
    true = member(["math","sqrt","1","bif"],
                  csv(filename:join(Dir,"bench-imports.csv"))),
    15 = length([ok || ["prim_net",_,_] <- csv(filename:join(Dir,"nifs.csv"))]),
    true = member(["prim_file","read_file_nif","1","nif"],
                  [drop_calls(R) || R <- csv(filename:join(Dir,"dynamic-boot.csv"))]),
    true = member(["prim_buffer","new","0","nif"],
                  [drop_calls(R) || R <- csv(filename:join(Dir,"dynamic-mix.csv"))]),
    {ok,[BootPorts]} = file:consult(filename:join(Dir,"port-opens-boot.term")),
    true = lists:member([{spawn_driver,"udp_inet"},[binary]],BootPorts),
    {ok,[MixPorts]} = file:consult(filename:join(Dir,"port-opens-mix.term")),
    true = lists:any(fun([{spawn_driver,"tcp_inet"}|_])->true;(_)->false end,MixPorts),
    Bifs = csv(filename:join(Dir,"bif-inventory.csv")),
    553 = length([ok || [_,_,_,"true",_,_,_] <- Bifs]),
    Mods = csv(filename:join(Dir,"boot-modules.csv")),
    true = member(["preloaded","init"],Mods),
    true = member(["preloaded","erl_prim_loader"],Mods),
    true = lists:any(fun([_,"code_server"])->true;(_)->false end,Mods),
    {ok,MixLog} = file:read_file(filename:join([Root,"tmp","census","mix_test.log"])),
    true = binary:match(MixLog,<<"2 passed">>) =/= nomatch,
    true = binary:match(MixLog,<<"Compiling 1 file">>) =/= nomatch,
    io:format("verify: 6 scenarios, 553 BIF declarations, boot UDP port, Mix TCP ports, fresh Mix tests passed~n").

csv(Path) ->
    {ok,Bin} = file:read_file(Path),
    [_|Lines] = string:split(binary_to_list(Bin),"\n",all),
    [string:split(Line,",",all) || Line <- Lines,Line =/= ""].

drop_calls([M,F,A,_,Kind]) -> [M,F,A,Kind].

member(Item,List) -> lists:member(Item,List).

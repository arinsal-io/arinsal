-module(census_hook).
-export([start/0, mark/0, stop/0, snapshot/1]).

start() ->
    Root = os:getenv("CENSUS_ROOT"),
    Scenario = os:getenv("CENSUS_SCENARIO"),
    case {Root,Scenario,whereis(census_tracer)} of
        {false,_,_} -> ok;
        {_,false,_} -> ok;
        {_,_,Pid} when is_pid(Pid) -> ok;
        _ ->
            Pid = spawn(fun() -> collect(#{},[],0,Root,Scenario) end),
            true = register(census_tracer,Pid),
            install_patterns(Root),
            _ = erlang:trace(all,true,[call,set_on_spawn,{tracer,Pid}]),
            _ = erlang:trace(Pid,false,[call]),
            ok
    end.

stop() ->
    _ = erlang:trace(self(),false,[call]),
    case whereis(census_tracer) of
        undefined -> ok;
        Pid ->
            _ = erlang:trace(all,false,[call,set_on_spawn]),
            Ref = erlang:trace_delivered(all),
            receive {trace_delivered,all,Ref} -> ok after 30000 -> exit(trace_flush_timeout) end,
            snapshot(stop),
            Pid ! {finish,self(),nif_set()},
            receive {census_done,Pid} -> ok after 30000 -> exit(census_write_timeout) end
    end.

mark() ->
    Pid = whereis(census_tracer),
    Ref = erlang:trace_delivered(all),
    receive {trace_delivered,all,Ref} -> ok after 30000 -> exit(trace_flush_timeout) end,
    Pid ! {mark,self()},
    receive {census_marked,Pid} -> ok after 30000 -> exit(census_mark_timeout) end.

snapshot(Stage) ->
    case {os:getenv("CENSUS_ROOT"),os:getenv("CENSUS_SCENARIO")} of
        {false,_} -> ok;
        {_,false} -> ok;
        {Root,Scenario} ->
            Ports = [{erlang:port_to_list(P),erlang:port_info(P,name),
                      case erlang:port_info(P,connected) of
                          {connected,Owner} -> pid_to_list(Owner);
                          _ -> undefined
                      end}
                     || P <- erlang:ports()],
            Tables = [{ets:info(T,name),pid_to_list(ets:info(T,owner)),ets:info(T,size)} || T <- ets:all()],
            Processes = [{N,pid_to_list(whereis(N))} || N <- registered()],
            Data = #{ports=>Ports,ets=>Tables,registered=>Processes,
                     loaded=>[M || {M,_} <- code:all_loaded()],
                     persistent_term=>persistent_term:info(),
                     nif_modules=>nif_modules()},
            File = filename:join([Root,"docs","census",
                                  "snapshot-"++Scenario++"-"++atom_to_list(Stage)++".term"]),
            ok = prim_file:write_file(File,io_lib:format("~p.~n",[Data]))
    end.

install_patterns(Root) ->
    Spec = filename:join([Root,"spec","otp-29.1.1","bif.tab"]),
    {ok,Bin} = prim_file:read_file(Spec),
    BifMods = [list_to_atom(M) || Line <- string:split(binary_to_list(Bin),"\n",all),
                                  {match,[M]} <- [re:run(Line,
                                     "^(?:bif|ubif|hbif|gcbif) +([^: ]+):",
                                     [{capture,all_but_first,list}])]],
    {ok,NifBin} = prim_file:read_file(filename:join([Root,"docs","census","nifs.csv"])),
    NifRows = [{list_to_atom(M),list_to_atom(F),list_to_integer(A)} ||
                  Line <- tl(string:split(binary_to_list(NifBin),"\n",all)),
                  [M,F,A] <- [string:split(Line,",",all)]],
    NifMods = [M || {M,_,_} <- NifRows],
    {ok,PrimBin} = prim_file:read_file(filename:join([Root,"docs","census","prim-modules.csv"])),
    PrimMods = [list_to_atom(M) || M <- tl(string:split(binary_to_list(PrimBin),"\n",all)),
                                  M =/= ""],
    Mods = lists:usort([erts_internal|BifMods++NifMods++PrimMods]),
    lists:foreach(fun(M) -> _ = erlang:trace_pattern({M,'_','_'},true,[global]) end,Mods),
    lists:foreach(fun(M) -> _ = erlang:trace_pattern({M,'_','_'},true,[local]) end,
                  [erts_internal|PrimMods]),
    lists:foreach(fun(Key) -> _ = erlang:trace_pattern(Key,true,[local]) end,NifRows).

collect(Counts,Ports,Seq,Root,Scenario) ->
    receive
        {mark,From} ->
            From ! {census_marked,self()},
            collect(#{},[],0,Root,Scenario);
        {trace,_,call,{M,F,Args}} when is_list(Args) ->
            A = length(Args),
            Key = {M,F,A},
            Updated = maps:update_with(Key,fun({N,First})->{N+1,First} end,
                                       {1,Seq},Counts),
            NewPorts = case Key of
                           {erts_internal,open_port,2} -> [Args|Ports];
                           _ -> Ports
                       end,
            collect(Updated,NewPorts,Seq+1,Root,Scenario);
        {finish,From,Nifs} ->
            Sorted = lists:sort(fun({_,{_,A}},{_,{_,B}})->A=<B end,maps:to_list(Counts)),
            Rows = [io_lib:format("~s,~s,~B,~B,~s~n",[atom_to_list(M),atom_to_list(F),A,N,Kind]) ||
                       {{M0,F0,A}=Key,{N,_}} <- Sorted,
                       Kind <- [kind(Key,Nifs)], Kind =/= "plain",
                       M <- [M0], F <- [F0]],
            File = filename:join([Root,"docs","census","dynamic-"++Scenario++".csv"]),
            ok = file:write_file(File,["module,function,arity,calls,kind\n"|Rows]),
            PortFile = filename:join([Root,"docs","census","port-opens-"++Scenario++".term"]),
            ok = file:write_file(PortFile,io_lib:format("~p.~n",[lists:reverse(Ports)])),
            From ! {census_done,self()};
        _ -> collect(Counts,Ports,Seq,Root,Scenario)
    end.

kind({M,F,A}=Key,Nifs) ->
    case {maps:is_key(Key,Nifs),erlang:is_builtin(M,F,A)} of
        {true,_} -> "nif";
        {_,true} -> "bif";
        _ when M =:= os, F =:= cmd, A =:= 1 -> "port_api";
        _ -> case M =:= erts_internal orelse lists:prefix("prim_",atom_to_list(M)) of
                 true -> "internal";
                 false -> "plain"
             end
    end.

nif_set() ->
    maps:from_list([{{M,F,A},true} || {M,_} <- code:all_loaded(),
                                     {F,A} <- module_nifs(M)]).

nif_modules() ->
    [{M,module_nifs(M)} || {M,_} <- code:all_loaded(), module_nifs(M) =/= []].

module_nifs(M) ->
    try M:module_info(nifs)
    catch _:_ -> [] end.

#!/usr/bin/env escript
%%! -noshell

main(_) ->
    Root = filename:dirname(filename:dirname(filename:dirname(escript:script_name()))),
    Otp = code:root_dir(),
    Elixir = os:getenv("ARINSAL_ELIXIR_ROOT", discover_elixir_root()),
    Files = lists:sort(filelib:wildcard(filename:join([Otp, "lib", "*", "ebin", "*.beam"])) ++
                       filelib:wildcard(filename:join([Elixir, "lib", "*", "ebin", "*.beam"]))),
    Spec = spec(filename:join([Root, "spec", "otp-29.1.1", "bif.tab"])),
    {Rows, Nifs, NifModules, Errors} = lists:foldl(fun(F, Acc) -> scan(F, Otp, Elixir, Acc) end,
                                                  {#{}, #{}, #{}, []}, Files),
    AllNifs = runtime_nifs(NifModules,Nifs),
    Output = filename:join([Root, "docs", "census"]),
    ok = filelib:ensure_dir(filename:join(Output, "static.csv")),
    Sorted = lists:sort(maps:to_list(Rows)),
    Csv = ["module,function,arity,kind,used_by_apps,used_by_modules_count\n" |
           [begin
                {Runtime, Apps, Users} = Value,
                Kind = kind(Key, Runtime, Spec, AllNifs),
                io_lib:format("~s,~s,~B,~s,~s,~B~n",
                              [atom_to_list(M), atom_to_list(F), A, Kind,
                               string:join(lists:sort(maps:keys(Apps)), ";"), maps:size(Users)])
            end || {{M,F,A}=Key, Value} <- Sorted]],
    ok = file:write_file(filename:join(Output, "static.csv"), Csv),
    NifCsv = ["module,function,arity\n" |
              [io_lib:format("~s,~s,~B~n", [M,F,A]) || {M,F,A} <- lists:sort(maps:keys(AllNifs))]],
    ok = file:write_file(filename:join(Output, "nifs.csv"), NifCsv),
    NifModuleCsv = ["module,load_nif_import,on_load_attribute,declared_nifs,runtime_nifs\n" |
                    [io_lib:format("~s,~s,~s,~B,~B~n",
                                   [atom_to_list(M),boolean(Load),boolean(OnLoad),N,
                                    length([ok || {M0,_,_} <- maps:keys(AllNifs),M0 =:= M])]) ||
                        {M,{Load,OnLoad,N}} <- lists:sort(maps:to_list(NifModules))]],
    ok = file:write_file(filename:join(Output,"nif-modules.csv"),NifModuleCsv),
    PrimModules = lists:usort([filename:basename(F,".beam") || F <- Files,
                              lists:prefix(Otp,F),
                              lists:prefix("prim_",filename:basename(F,".beam"))]),
    ok = file:write_file(filename:join(Output,"prim-modules.csv"),
                         ["module\n"|[M++"\n" || M <- PrimModules]]),
    Inventory = ["module,function,arity,in_bif_tab,imported,used_by_apps,used_by_modules_count\n" |
                 [begin
                      {_,Apps,Users} = maps:get(Key,Rows,{false,#{},#{}}),
                      io_lib:format("~s,~s,~B,~s,~s,~s,~B~n",
                                    [atom_to_list(M),atom_to_list(F),A,
                                     boolean(maps:is_key(Key,Spec)),boolean(maps:is_key(Key,Rows)),
                                     string:join(lists:sort(maps:keys(Apps)),";"),maps:size(Users)])
                  end || {M,F,A}=Key <- lists:usort(maps:keys(Spec) ++
                      [K || {K,{true,_,_}} <- Sorted])]],
    ok = file:write_file(filename:join(Output,"bif-inventory.csv"),Inventory),
    BootCandidates = boot_static(Otp,Files,Output,Spec,AllNifs),
    {Disasm,DisasmExceptions} = verify_disasm(),
    Counts = lists:foldl(fun({Key,{Runtime,_,_}}, Acc) ->
                                 K = kind(Key,Runtime,Spec,AllNifs),
                                 maps:update_with(K, fun(N)->N+1 end, 1, Acc)
                         end, #{}, Sorted),
    Summary = io_lib:format("# Static census\n\nOTP: `~s`  \nElixir: `~s`  \n"
                            "BEAM files: ~B  \nUnique imports: ~B  \nNIF declarations: ~B  \n"
                            "NIF functions after runtime discovery: ~B  \nNIF candidate modules: ~B  \n"
                            "Read errors: ~B  \nBoot-script static BIF candidates: ~B  \n"
                            "Disassembled BIF/gc_bif instructions checked: ~B  \n"
                            "Disassembler pseudo-BIFs without an import: `~p`\n\n"
                            "Kinds: `~p`\n\n"
                            "Preloaded modules: `~p`. Their BEAM files are in `lib/erts-17.1/ebin`.\n",
                            [Otp, Elixir, length(Files), maps:size(Rows), maps:size(Nifs),
                             maps:size(AllNifs),
                             maps:size(NifModules),
                             length(Errors), BootCandidates, Disasm, DisasmExceptions,
                             Counts, erlang:pre_loaded()]),
    ok = file:write_file(filename:join(Output, "static-summary.md"), Summary),
    lists:foreach(fun(E)->io:format(standard_error,"scan error: ~p~n",[E]) end, lists:reverse(Errors)),
    io:format("static: ~B BEAM files, ~B imports, ~B NIF declarations, ~B runtime NIFs, ~B errors~n",
              [length(Files),maps:size(Rows),maps:size(Nifs),maps:size(AllNifs),length(Errors)]),
    case Errors of [] -> ok; _ -> halt(1) end.

spec(Path) ->
    {ok, Bin} = file:read_file(Path),
    lists:foldl(fun(Line, Acc) ->
                        case re:run(Line, "^(?:bif|ubif|hbif|gcbif) +([^: ]+):(.+)/([0-9]+)(?:\\s|$)",
                                    [{capture, all_but_first, list}]) of
                            {match,[M,F,A]} -> maps:put({read_atom(M),read_atom(F),list_to_integer(A)},true,Acc);
                            nomatch -> Acc
                        end
                end, #{}, string:split(binary_to_list(Bin), "\n", all)).

read_atom(Text) ->
    {ok,Tokens,_} = erl_scan:string(Text++"."),
    {ok,Atom} = erl_parse:parse_term(Tokens),
    Atom.

scan(Path, Otp, Elixir, {Rows,Nifs,NifModules,Errors}) ->
    case beam_lib:chunks(Path, [imports]) of
        {ok,{Mod,Chunks}} ->
            App = app(Path,Otp,Elixir),
            Imports = proplists:get_value(imports,Chunks,[]),
            Forms = case beam_lib:chunks(Path,[abstract_code]) of
                        {ok,{_,[{abstract_code,{raw_abstract_v1,F}}]}} -> F;
                        _ -> []
                    end,
            NifList = lists:append([L || {attribute,_,nifs,L} <- Forms]),
            OnLoad = lists:any(fun({attribute,_,on_load,_})->true;(_)->false end,Forms),
            LoadNif = lists:member({erlang,load_nif,2},Imports),
            NifModules2 = case LoadNif orelse OnLoad orelse NifList =/= [] of
                              true -> maps:put(Mod,{LoadNif,OnLoad,length(NifList)},NifModules);
                              false -> NifModules
                          end,
            Nifs2 = lists:foldl(fun({F,A},Map)->maps:put({Mod,F,A},true,Map) end,Nifs,NifList),
            Rows2 = lists:foldl(fun({M,F,A}=Key,Map) ->
                                        {_,Apps,Users} = maps:get(Key,Map,{false,#{},#{}}),
                                        maps:put(Key,{erlang:is_builtin(M,F,A),
                                                      maps:put(App,true,Apps),
                                                      maps:put(Mod,true,Users)},Map)
                                end,Rows,lists:usort(Imports)),
            {Rows2,Nifs2,NifModules2,Errors};
        Error -> {Rows,Nifs,NifModules,[{Path,Error}|Errors]}
    end.

app(Path, Otp, Elixir) ->
    Base = case lists:prefix(Otp, Path) of true -> Otp; false -> Elixir end,
    Rel = lists:nthtail(length(Base)+1,Path),
    case filename:split(Rel) of
        ["lib",Name|_] -> Name;
        _ -> "unknown"
    end.

kind(Key, Runtime, Spec, Nifs) ->
    case {maps:is_key(Key,Nifs),Runtime,maps:is_key(Key,Spec)} of
        {true,_,_} -> "nif";
        {false,true,true} -> "bif_runtime+spec";
        {false,true,false} -> "bif_runtime_only";
        {false,false,true} -> "bif_spec_only";
        _ -> "erlang"
    end.

boolean(true) -> "true";
boolean(false) -> "false".

runtime_nifs(NifModules,Nifs) ->
    maps:fold(fun(M,_,Acc) ->
                      try
                          case code:ensure_loaded(M) of
                              {module,M} ->
                                  L = M:module_info(nifs),
                                  lists:foldl(fun({F,A},Map)->maps:put({M,F,A},true,Map) end,Acc,L);
                              _ -> Acc
                          end
                      catch _:_ -> Acc end
              end,Nifs,NifModules).

verify_disasm() ->
    Results = [begin
                   Path = code:which(M),
                   {ok,{_,C}} = beam_lib:chunks(Path,[imports]),
                   Imports = proplists:get_value(imports,C),
                   {beam_file,_,_,_,_,Code} = beam_disasm:file(Path),
                   Builtins = [{F,length(Args)} || {function,_,_,_,Instructions} <- Code,
                                                  Instruction <- Instructions,
                                                  {F,Args} <- [disasm_bif(Instruction)],
                                                  F =/= none],
                   Missing = lists:usort([{M,F,A} || {F,A} <- Builtins,
                                                    not lists:member({erlang,F,A},Imports)]),
                   {length(Builtins),Missing}
               end || M <- [lists,maps,erl_eval]],
    {lists:sum([N || {N,_} <- Results]),lists:usort(lists:append([E || {_,E} <- Results]))}.

disasm_bif({bif,F,_,Args,_}) -> {F,Args};
disasm_bif({gc_bif,F,_,_,Args,_}) -> {F,Args};
disasm_bif(_) -> {none,[]}.

boot_static(Otp,Files,Output,Spec,Nifs) ->
    Script = filename:join([Otp,"releases","29","start.script"]),
    {ok,[{script,_,Commands}]} = file:consult(Script),
    Modules = lists:usort(lists:append([case C of
        {preLoaded,L} -> [{preloaded,M} || M <- L];
        {primLoad,L} -> [{prim_load,M} || M <- L];
        {kernelProcess,_,{M,_,_}} -> [{kernel_process,M}];
        _ -> []
    end || C <- Commands])),
    ModuleCsv = ["phase,module\n" |
                 [io_lib:format("~s,~s~n",[Phase,M]) ||
                     {P,M0} <- Modules,Phase <- [atom_to_list(P)],M <- [atom_to_list(M0)]]],
    ok = file:write_file(filename:join(Output,"boot-modules.csv"),ModuleCsv),
    Paths = maps:from_list([{list_to_atom(filename:basename(F,".beam")),F} ||
                             F <- Files,lists:prefix(Otp,F)]),
    Imports = lists:append([begin
        Path = maps:get(M,Paths),
        {ok,{_,Chunks}} = beam_lib:chunks(Path,[imports]),
        [{M,Key} || Key <- proplists:get_value(imports,Chunks,[])]
    end || {_,M} <- Modules]),
    Csv = ["caller,module,function,arity,kind\n" |
           [io_lib:format("~s,~s,~s,~B,~s~n",
                          [Caller,M,F,A,kind(Key,erlang:is_builtin(M0,F0,A),Spec,Nifs)]) ||
               {Caller0,{M0,F0,A}=Key} <- lists:usort(Imports),
               Caller <- [atom_to_list(Caller0)], M <- [atom_to_list(M0)],
               F <- [atom_to_list(F0)]]],
    ok = file:write_file(filename:join(Output,"boot-imports.csv"),Csv),
    Candidate = lists:usort([Key || {_,{M,F,A}=Key} <- Imports,
                                   erlang:is_builtin(M,F,A) orelse maps:is_key(Key,Spec)]),
    length(Candidate).

discover_elixir_root() ->
    Ebin = string:trim(os:cmd("elixir -e 'IO.write(:code.lib_dir(:elixir))' 2>/dev/null")),
    case Ebin of
        [] -> "";
        _ -> filename:dirname(filename:dirname(Ebin))
    end.

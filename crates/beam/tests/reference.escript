#!/usr/bin/env escript
%%! -noshell
main(Paths) -> lists:foreach(fun report/1, Paths).
report(Path) ->
    {ok, _, Chunks} = beam_lib:all_chunks(Path),
    {ok, {_, Table}} = beam_lib:chunks(Path, [atoms, imports, exports]),
    Atoms = length(proplists:get_value(atoms, Table)),
    Imports = length(proplists:get_value(imports, Table)),
    Exports = length(proplists:get_value(exports, Table)),
    Lambdas = case proplists:get_value("FunT", Chunks) of undefined -> 0; <<N:32, _/binary>> -> N end,
    <<_Sub:32, _Version:32, _Max:32, Labels:32, Functions:32, _/binary>> = proplists:get_value("Code", Chunks),
    {beam_file, _, _, _, _, Fs} = beam_disasm:file(Path),
    Ops = [atom_to_list(op(I)) || {function, _, _, _, Is} <- Fs, I <- Is],
    io:format("~s\t~B\t~B\t~B\t~B\t~B\t~B\t~B\t~s~n", [Path, Atoms, Imports, Exports, Lambdas, Functions, Labels, length(Ops), string:join(Ops, ",")]).

op({test, Name, _, _}) -> Name;
op({test, Name, _, _, _}) -> Name;
op({test, Name, _, _, _, _}) -> Name;
op({test, Name, _, _, _, _, _}) -> Name;
op({bif, raise, _, _, _}) -> raise;
op({bif, Name, _, _Args, _}) when Name =:= fadd; Name =:= fsub; Name =:= fmul; Name =:= fdiv; Name =:= fnegate -> Name;
op({bif, _, _, Args, _}) -> list_to_atom("bif" ++ integer_to_list(length(Args)));
op({gc_bif, _, _, _, Args, _}) -> list_to_atom("gc_bif" ++ integer_to_list(length(Args)));
op(I) when is_atom(I) -> I;
op(I) -> element(1, I).

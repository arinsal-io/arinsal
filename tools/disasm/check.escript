#!/usr/bin/env escript
%%! -noshell
%% Compare parsed Erlang terms, reporting the first operand-level difference.

main([Manifest, DumpDir, RenderDir]) ->
    ok = load_raw_type_index_disassembler(DumpDir),
    {ok, Bytes} = file:read_file(Manifest),
    Paths = [binary_to_list(P) || P <- binary:split(Bytes, <<"\n">>, [global]), P =/= <<>>],
    {Good, Bad} = lists:foldl(fun({N, Path}, {G, B}) ->
        case check(N, Path, DumpDir, RenderDir) of
            ok -> io:format("PASS ~s~n", [Path]), {G+1, B};
            {error, Reason} ->
                io:format("FAIL ~s ~w~n", [Path, Reason]),
                {G, B+1}
        end
    end, {0, 0}, lists:zip(lists:seq(1, length(Paths)), Paths)),
    io:format("checked ~B modules: ~B passed, ~B mismatches~n", [length(Paths), Good, Bad]),
    case Bad of 0 -> ok; _ -> halt(1) end;
main(_) ->
    io:format(standard_error, "usage: check.escript <manifest> <dumpdir> <renderdir>~n", []),
    halt(2).

check(N, Path, DumpDir, RenderDir) ->
    try
        Etf = filename:join(DumpDir, integer_to_list(N) ++ ".etf"),
        Erl = filename:join(RenderDir, integer_to_list(N) ++ ".erl"),
        {ok, Bin} = file:read_file(Etf),
        {beam_file, _, _, _, _, Functions} = binary_to_term(Bin),
        {ok, Rendered} = file:consult(Erl),
        TypeMap = type_map(Path),
        case compare_functions(Functions, Rendered, TypeMap, 1) of
            ok -> compare_type_indices(Path, Rendered);
            Error -> Error
        end
    catch Class:Reason:Stack -> {error, {Class, Reason, lists:sublist(Stack, 2)}}
    end.

type_map(Path) ->
    case beam_lib:chunks(Path, ["Type"]) of
        {ok, {_, [{"Type", <<Version:32, _Count:32, Data/binary>>}]}} ->
            Converted = beam_types:convert_ext(Version, Data),
            type_map_1(Converted, []);
        {error, beam_lib, {missing_chunk, _, _}} -> []
    end.
type_map_1(<<>>, Acc) -> lists:reverse(Acc);
type_map_1(Data, Acc) ->
    {Type, Rest} = beam_types:decode_ext(Data),
    type_map_1(Rest, [Type|Acc]).

norm({literal_etf, _Index, Bytes}, _) -> {literal, binary_to_term(Bytes)};
norm({float, Value}, _) -> {literal, Value};
norm({literal, Value}, _) -> {literal, Value};
norm({tr, Reg, {type_index, Index}}, Map) -> {tr, norm(Reg, Map), lists:nth(Index+1, Map)};
norm({tr, Reg, Type}, Map) -> {tr, norm(Reg, Map), Type};
norm(Term, Map) when is_tuple(Term) -> list_to_tuple([norm(E, Map) || E <- tuple_to_list(Term)]);
norm(Term, Map) when is_list(Term) -> [norm(E, Map) || E <- Term];
norm(Term, _) -> Term.

compare_functions([], [], _, _) -> ok;
compare_functions([F|Fs], [R|Rs], Map, N) ->
    {function, Name, Arity, Entry, Is} = F,
    case R of
        {function, Name, Arity, Entry, Js} ->
            case compare_instrs(Is, Js, Map, 1) of
                ok -> compare_functions(Fs, Rs, Map, N+1);
                Error -> {error, {function, N, Name, Arity, Error}}
            end;
        _ -> {error, {function_header, N, {Name, Arity, Entry}, R}}
    end;
compare_functions(Fs, Rs, _, N) -> {error, {function_count, N, length(Fs), length(Rs)}}.

compare_instrs([], [], _, _) -> ok;
compare_instrs([I|Is], [J|Js], Map, N) ->
    Expected = norm(I, Map),
    Actual = norm(J, Map),
    case Expected =:= Actual of
        true -> compare_instrs(Is, Js, Map, N+1);
        false -> {instruction, N, Expected, Actual}
    end;
compare_instrs(Is, Js, _, N) -> {instruction_count, N, length(Is), length(Js)}.

%% OTP's decoder normally substitutes the decoded type for the raw index.
%% A temporary copy with that single substitution removed checks the exact
%% encoded indices without changing the reference implementation on disk.
load_raw_type_index_disassembler(WorkDir) ->
    SourceDir = "$HOME/dev/beam/ref/otp-29/lib/compiler/src",
    Source = filename:join(SourceDir, "beam_disasm.erl"),
    {ok, Bytes} = file:read_file(Source),
    M1 = binary:replace(Bytes, <<"-module(beam_disasm).">>, <<"-module(beam_disasm_raw).">>),
    M2 = binary:replace(M1,
        <<"{#tr{r=Reg,t=gb_trees:get(TypeIdx, Types)}, RestBs}.">>,
        <<"{#tr{r=Reg,t=TypeIdx}, RestBs}.">>),
    M3 = binary:replace(M2,
        <<"case gb_trees:get(LitIndex, Literals) of">>,
        <<"put(arinsal_literal_indices, [LitIndex | case get(arinsal_literal_indices) of undefined -> []; Previous -> Previous end]), case gb_trees:get(LitIndex, Literals) of">>),
    true = M1 =/= Bytes,
    true = M2 =/= M1,
    true = M3 =/= M2,
    Copy = filename:join(WorkDir, "beam_disasm_raw.erl"),
    ok = file:write_file(Copy, M3),
    Installed = "$HOME/.asdf/installs/erlang/29.1.1/lib/compiler-10.0.6/src",
    {ok, beam_disasm_raw, Binary} = compile:file(Copy, [binary, {i, SourceDir}, {i, Installed}]),
    {module, beam_disasm_raw} = code:load_binary(beam_disasm_raw, Copy, Binary),
    ok.

compare_type_indices(Path, Rendered) ->
    erase(arinsal_literal_indices),
    {beam_file, _, _, _, _, Raw} = beam_disasm_raw:file(Path),
    Expected = raw_type_indices(Raw),
    Actual = rendered_type_indices(Rendered),
    case Expected =:= Actual of
        true -> compare_literal_indices(Rendered);
        false ->
            Pos = first_index_difference(Expected, Actual, 1),
            {error, {typed_register_index, Pos, at(Pos, Expected), at(Pos, Actual)}}
    end.

raw_type_indices(Term) -> lists:reverse(raw_type_indices(Term, [])).
raw_type_indices({literal, _}, Acc) -> Acc;
raw_type_indices({tr, Reg, Index}, Acc) -> [{Reg, Index}|Acc];
raw_type_indices(Term, Acc) when is_tuple(Term) ->
    lists:foldl(fun(E, A) -> raw_type_indices(E, A) end, Acc, tuple_to_list(Term));
raw_type_indices(Term, Acc) when is_list(Term) ->
    lists:foldl(fun(E, A) -> raw_type_indices(E, A) end, Acc, Term);
raw_type_indices(_, Acc) -> Acc.

rendered_type_indices(Term) -> lists:reverse(rendered_type_indices(Term, [])).
rendered_type_indices({literal_etf, _, _}, Acc) -> Acc;
rendered_type_indices({tr, Reg, {type_index, Index}}, Acc) -> [{Reg, Index}|Acc];
rendered_type_indices(Term, Acc) when is_tuple(Term) ->
    lists:foldl(fun(E, A) -> rendered_type_indices(E, A) end, Acc, tuple_to_list(Term));
rendered_type_indices(Term, Acc) when is_list(Term) ->
    lists:foldl(fun(E, A) -> rendered_type_indices(E, A) end, Acc, Term);
rendered_type_indices(_, Acc) -> Acc.

first_index_difference([A|As], [B|Bs], N) when A =:= B ->
    first_index_difference(As, Bs, N+1);
first_index_difference(_, _, N) -> N.

at(N, Items) when N =< length(Items) -> lists:nth(N, Items);
at(_, _) -> missing.

compare_literal_indices(Rendered) ->
    Expected = case get(arinsal_literal_indices) of
        undefined -> [];
        Reversed -> lists:reverse(Reversed)
    end,
    Actual = rendered_literal_indices(Rendered),
    case Expected =:= Actual of
        true -> ok;
        false ->
            Pos = first_index_difference(Expected, Actual, 1),
            {error, {literal_index, Pos, at(Pos, Expected), at(Pos, Actual)}}
    end.

rendered_literal_indices(Term) -> lists:reverse(rendered_literal_indices(Term, [])).
rendered_literal_indices({literal_etf, Index, _}, Acc) -> [Index|Acc];
rendered_literal_indices(Term, Acc) when is_tuple(Term) ->
    lists:foldl(fun(E, A) -> rendered_literal_indices(E, A) end, Acc, tuple_to_list(Term));
rendered_literal_indices(Term, Acc) when is_list(Term) ->
    lists:foldl(fun(E, A) -> rendered_literal_indices(E, A) end, Acc, Term);
rendered_literal_indices(_, Acc) -> Acc.

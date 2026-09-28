#!/usr/bin/env escript
%%! -noshell
%% Materialize ETF literals and OTP type records in Rust-rendered terms.

main([Path, Rendered]) ->
    try
        {ok, Functions} = file:consult(Rendered),
        Types = types(Path),
        lists:foreach(fun(F) -> io:format("~w.~n", [expand(F, Types)]) end, Functions)
    catch Class:Reason ->
        io:format(standard_error, "~p: ~p~n", [Class, Reason]),
        halt(1)
    end;
main(_) ->
    io:format(standard_error, "usage: expand.escript <beam> <rendered>~n", []),
    halt(2).

types(Path) ->
    case beam_lib:chunks(Path, ["Type"]) of
        {ok, {_, [{"Type", <<Version:32, _Count:32, Data/binary>>}]}} ->
            types_1(beam_types:convert_ext(Version, Data), []);
        {error, beam_lib, {missing_chunk, _, _}} -> []
    end.
types_1(<<>>, Acc) -> lists:reverse(Acc);
types_1(Data, Acc) ->
    {Type, Rest} = beam_types:decode_ext(Data),
    types_1(Rest, [Type|Acc]).

expand({literal_etf, _Index, Bytes}, _) ->
    Value = binary_to_term(Bytes),
    case is_float(Value) of true -> {float, Value}; false -> {literal, Value} end;
expand({tr, Reg, {type_index, Index}}, Types) ->
    {tr, expand(Reg, Types), lists:nth(Index+1, Types)};
expand(Term, Types) when is_tuple(Term) ->
    list_to_tuple([expand(E, Types) || E <- tuple_to_list(Term)]);
expand(Term, Types) when is_list(Term) -> [expand(E, Types) || E <- Term];
expand(Term, _) -> Term.

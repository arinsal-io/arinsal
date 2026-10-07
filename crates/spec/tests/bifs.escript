#!/usr/bin/env escript
%%! -noshell
main([Path]) ->
    {ok, Bin} = file:read_file(Path),
    Lines = binary:split(Bin, <<"\n">>, [global]),
    lists:foreach(fun(Line) ->
        S = string:trim(binary_to_list(Line)),
        case S of
            [] -> ok;
            [$# | _] -> ok;
            _ ->
                [_, MFA | _] = string:tokens(S, " \t"),
                {match, [M, F0, A0]} = re:run(MFA, "^([^:]+):(.+)/([0-9]+)$", [{capture, all_but_first, list}]),
                {ok, Tokens, _} = erl_scan:string(F0 ++ "."),
                {ok, F} = erl_parse:parse_term(Tokens),
                A = list_to_integer(A0),
                B = erlang:is_builtin(list_to_atom(M), F, A),
                io:format("~s:~s/~B ~p~n", [M, F0, A, B])
        end
    end, Lines).

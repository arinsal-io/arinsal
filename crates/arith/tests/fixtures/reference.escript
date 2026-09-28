#!/usr/bin/env escript
%%! -noshell
main([Input, Output]) ->
    "29" = erlang:system_info(otp_release),
    {ok, Version} = file:read_file(filename:join([code:root_dir(), "releases", "29", "OTP_VERSION"])),
    "29.1.1" = string:trim(binary_to_list(Version)),
    {ok, Data} = file:read_file(Input),
    Lines = binary:split(Data, <<"\n">>, [global]),
    Results = [evaluate(Line) || Line <- Lines, Line =/= <<>>],
    ok = file:write_file(Output, Results).

evaluate(Line) ->
    [OpBin, ABin, BBin] = binary:split(Line, <<"\t">>, [global]),
    Op = binary_to_atom(OpBin),
    A = parse(ABin),
    Args = case BBin of <<>> -> [A]; _ -> [A, parse(BBin)] end,
    try
        V = erlang:apply(erlang, Op, Args),
        [<<"O\t">>, binary:encode_hex(term_to_binary(V)), <<"\n">>]
    catch
        error:Reason -> [<<"E\t">>, atom_to_binary(Reason), <<"\n">>]
    end.

parse(Bin) ->
    {ok, Tokens, _} = erl_scan:string(binary_to_list(Bin) ++ "."),
    {ok, Term} = erl_parse:parse_term(Tokens),
    Term.

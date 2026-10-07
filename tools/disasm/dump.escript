#!/usr/bin/env escript
%%! -noshell
%% Dump the exact beam_disasm:file/1 result as ETF.

main(["--batch", Manifest, OutDir]) ->
    ok = filelib:ensure_dir(filename:join(OutDir, "dummy")),
    {ok, Bytes} = file:read_file(Manifest),
    Paths = [binary_to_list(P) || P <- binary:split(Bytes, <<"\n">>, [global]), P =/= <<>>],
    Jobs = lists:zip(lists:seq(1, length(Paths)), Paths),
    Workers = max(1, erlang:system_info(schedulers_online)),
    Results = run_batch(Jobs, OutDir, Workers, []),
    Failures = [E || {error, _} = E <- Results],
    io:format("dumped ~B modules; ~B failures~n", [length(Paths), length(Failures)]),
    lists:foreach(fun(E) -> io:format(standard_error, "~p~n", [E]) end, Failures),
    case Failures of [] -> ok; _ -> halt(1) end;
main([Path, Out]) ->
    case dump(Path, Out) of
        ok -> ok;
        {error, Error} -> io:format(standard_error, "~p~n", [Error]), halt(1)
    end;
main(_) ->
    io:format(standard_error, "usage: dump.escript <beam> <out> | --batch <manifest> <outdir>~n", []),
    halt(2).

run_batch([], _, _, Acc) -> lists:reverse(Acc);
run_batch(Jobs, OutDir, Workers, Acc) ->
    {Now, Rest} = lists:split(min(Workers, length(Jobs)), Jobs),
    Parent = self(),
    [spawn(fun() ->
                   Out = filename:join(OutDir, integer_to_list(N) ++ ".etf"),
                   Parent ! {self(), N, dump(Path, Out)}
           end) || {N, Path} <- Now],
    Results = [receive {_, N, Result} -> {N, Result} end || _ <- Now],
    run_batch(Rest, OutDir, Workers, Results ++ Acc).

dump(Path, Out) ->
    try
        ok = filelib:ensure_dir(Out),
        Result = beam_disasm:file(Path),
        case Result of
            {beam_file, _, _, _, _, _} -> file:write_file(Out, term_to_binary(Result));
            Error -> {error, {Path, Error}}
        end
    catch Class:Reason:Stack -> {error, {Path, Class, Reason, Stack}}
    end.

-module(microbench).
-export([run/0]).

-define(COUNT, 100000).

run() ->
    Payloads = [small_atom, tuple_self, bin_1k, bin_64k, map_100, list_1000, nested_tuple_20],
    
    io:format("~-15s | ~15s | ~15s~n", ["Payload", "Enc (us/op)", "Dec (us/op)"]),
    io:format("~50c~n", [$-]),
    lists:foreach(fun(P) ->
        Term = dist_rtt:payload(P),
        Bin = erlang:term_to_binary(Term),
        
        %% Warmup
        do_encode(Term, 1000),
        do_decode(Bin, 1000),
        
        {TE, _} = timer:tc(fun() -> do_encode(Term, ?COUNT) end),
        {TD, _} = timer:tc(fun() -> do_decode(Bin, ?COUNT) end),
        
        io:format("~-15w | ~15.3f | ~15.3f~n", 
                  [P, TE / ?COUNT, TD / ?COUNT])
    end, Payloads).

do_encode(_Term, 0) -> ok;
do_encode(Term, N) ->
    _ = erlang:term_to_binary(Term),
    do_encode(Term, N-1).

do_decode(_Bin, 0) -> ok;
do_decode(Bin, N) ->
    _ = erlang:binary_to_term(Bin),
    do_decode(Bin, N-1).

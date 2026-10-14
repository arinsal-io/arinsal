-module(beamasm_bits_c).
-export([run/0]).

run() ->
    <<A:1, B:1, C:1, D:1, E:1, F:1, G:1, H:1>> = <<16#d3>>,
    io:format("~p~n", [{A, B, C, D, E, F, G, H}]),
    io:format("~p~n", [<<(<<1, 2>>)/binary, (<<3, 4>>)/binary>>]),
    Prefix = binary:copy(<<1>>, 50),
    Suffix = binary:copy(<<2>>, 50),
    io:format("~p~n", [<<Prefix/binary, Suffix/binary>>]),
    io:format("~p~n", [binary:part(Prefix, 7, 8)]),
    Prefix10K = binary:copy(<<1>>, 5120),
    Suffix10K = binary:copy(<<2>>, 5120),
    LongConcat = <<Prefix10K/binary, Suffix10K/binary>>,
    io:format("~p~n", [{byte_size(LongConcat), erlang:crc32(LongConcat)}]),
    io:format("~p~n", [append_loop(10, <<>>)]),
    io:format("~p~n", [private_append_loop(10, <<>>)]).

append_loop(0, Acc) -> Acc;
append_loop(N, Acc) -> append_loop(N - 1, <<Acc/binary, (N band 255):8>>).

private_append_loop(0, Acc) -> Acc;
private_append_loop(N, Acc) ->
    private_append_loop(N - 1, <<Acc/binary, (N band 255):8>>).

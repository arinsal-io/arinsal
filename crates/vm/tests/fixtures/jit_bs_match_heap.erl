-module(jit_bs_match_heap).
-export([run/0]).

%% Clauses whose exact-size match is followed by a heap test with a smaller live count than the
%% match context index; the failing clause still needs the later arguments.
run() ->
    Cfg = #{switches => [], strict => false},
    Inputs = [<<>>, <<"-">>, <<"--">>, <<"--foo">>, <<"-x">>, <<"-xy">>, <<"abc">>,
              <<1,2,3,4>>, <<1,2,3,4,5,6,7,8,9>>, <<255>>, <<"no-foo">>, <<"no-">>],
    [{I, next([I], Cfg), next([I, <<"x">>], Cfg), heads([I | I], Cfg, 3),
      dash(I, Cfg, [rest]), ints(I, Cfg, tag), tail(I, Cfg, {k, 1}),
      utf(I, Cfg), str(I, Cfg, 7), skip(I, Cfg, x)} || I <- Inputs].

dash(<<"--">>, _C, _R) -> {dashdash};
dash(<<"-">>, _C, _R) -> {dash};
dash(<<"-", X>>, _C, R) -> {short, X, R};
dash(<<"--", Opt/binary>>, C, R) -> {long, Opt, C, R};
dash(B, C, R) -> {other, B, C, R}.

ints(<<A:8, B:8>>, _C, _T) -> {two, A + B};
ints(<<A:16, B:16>>, _C, T) -> {four, A, B, T};
ints(<<A:32/little, Rest/binary>>, C, T) -> {le, A, Rest, C, T};
ints(B, C, T) -> {nomatch, byte_size(B), C, T}.

tail(<<_, Rest/binary>>, _C, _K) when byte_size(Rest) =:= 0 -> {one};
tail(<<H:3/binary, T/binary>>, C, K) -> {three, H, T, C, K};
tail(B, C, K) -> {short, B, C, K}.

utf(<<C/utf8>>, _Cfg) -> {cp, C};
utf(<<C/utf8, R/binary>>, Cfg) -> {cps, C, R, Cfg};
utf(B, Cfg) -> {bad, B, Cfg}.

str(<<"no-">>, _C, _N) -> {no};
str(<<"no-", R/binary>>, C, N) -> {neg, R, C, N};
str(<<"abc">>, _C, N) -> {abc, N};
str(B, C, N) -> {plain, B, C, N}.

skip(<<_:8, _:8>>, _C, _X) -> {skipped2};
skip(<<_:8, X:8, _/binary>>, C, Y) -> {second, X, C, Y};
skip(B, C, Y) -> {none, B, C, Y}.

%% The binary comes out of a list cell, so the match context sits above the live arguments.
next([], _C) -> stop;
next([<<"--">> | _] = Argv, _C) -> {error, Argv};
next([<<"-">> | _] = Argv, _C) -> {error, Argv};
next([<<"- ", _/binary>> | _] = Argv, _C) -> {error, Argv};
next([<<"--", Opt/binary>> | Rest], C) -> {long, Opt, Rest, C};
next([<<"-", Opt/binary>> | Rest], C) -> {short, Opt, Rest, C};
next(Argv, C) -> {plain, Argv, C}.

heads([<<A:8>> | _], _C, _N) -> {byte, A};
heads([<<A:16>> | T], _C, _N) -> {word, A, T};
heads([<<_:8, B/binary>> | T], C, N) -> {more, B, T, C, N};
heads(L, C, N) -> {other, L, C, N}.

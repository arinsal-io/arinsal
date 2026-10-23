-module(nb).
-export([main/0,noop/1,add/2,bsum/1,lsum/1,dnoop/1]).
-on_load(init/0).
init() -> erlang:load_nif("./nb", 0).
noop(_) -> erlang:nif_error(x). add(_,_) -> erlang:nif_error(x). bsum(_) -> erlang:nif_error(x). lsum(_) -> erlang:nif_error(x). dnoop(_) -> erlang:nif_error(x).
eadd(X,Y) -> X+Y.
enoop(X) -> X.
loop(_,0,A) -> A; loop(F,N,A) -> loop(F,N-1,F(A)).
t(Name,F,N) -> {T,_}=timer:tc(fun()-> loop(F,N,1) end), io:format("~-28s ~6.1f ns/call~n",[Name,T*1000/N]).
main() ->
  N=10000000,
  t("erlang local fun noop", fun(X)->enoop(X) end, N),
  t("NIF noop", fun(X)->noop(X) end, N),
  t("erlang add", fun(X)->eadd(X,1) end, N),
  t("NIF add (get_long x2, make)", fun(X)->add(X,1) end, N),
  t("dirty NIF noop", fun(X)->dnoop(X) end, 200000),
  B=crypto_bytes(), L=lists:seq(1,1000),
  t("NIF bsum 1KB binary", fun(X)->bsum(B), X end, 1000000),
  t("erlang bsum 1KB binary", fun(X)->esum(B,0), X end, 100000),
  t("NIF lsum 1000-list", fun(X)->lsum(L), X end, 100000),
  t("erlang lists:sum 1000", fun(X)->lists:sum(L), X end, 100000),
  halt().
crypto_bytes() -> list_to_binary([I rem 256 || I <- lists:seq(1,1024)]).
esum(<<C,R/binary>>,S) -> esum(R,S+C); esum(<<>>,S) -> S.

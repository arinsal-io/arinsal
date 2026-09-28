-module(off).
-export([main/0]).
t(Name,F) -> {T,R}=timer:tc(F), io:format("~-48s ~10.2f ms  ~P~n",[Name,T/1000,R,4]).
skip_select(T,Off,Lim) -> {L,C}=ets:select(T,[{'$1',[],['$1']}],1000), skip(L,C,Off,Lim).
skip(L,C,Off,Lim) when length(L) =< Off -> case sel(C) of '$end_of_table' -> []; {L2,C2} -> skip(L2,C2,Off-length(L),Lim) end;
skip(L,_,Off,Lim) -> lists:sublist(lists:nthtail(Off,L),Lim).
next_n(_,K,0) -> K; next_n(T,K,N) -> next_n(T,ets:next(T,K),N-1).
main() ->
  N=10000000, T=ets:new(t,[ordered_set,public]),
  {TI,_}=timer:tc(fun()-> ets:insert(T,[{I,I*2}||I<-lists:seq(1,N)]) end), io:format("insert ~p: ~p ms~n",[N,TI div 1000]),
  [begin
     t(io_lib:format("select+skip offset ~p",[Off]), fun()-> skip_select(T,Off,5) end),
     t(io_lib:format("ets:slot offset ~p",[Off]), fun()-> ets:slot(T,Off) end),
     t(io_lib:format("first+next offset ~p",[Off]), fun()-> next_n(T,ets:first(T),Off) end),
     t(io_lib:format("select guard Key > ~p limit 5",[Off]), fun()-> element(1,ets:select(T,[{{'$1','_'},[{'>','$1',Off}],['$1']}],5)) end),
     t(io_lib:format("keyset: ets:next x5 from key ~p",[Off]), fun()-> kn(T,Off,5,[]) end)
   end || Off <- [99900, 1000000, 9999000]],
  mnesia:start(), mnesia:create_table(m,[{type,ordered_set},{ram_copies,[node()]}]),
  M=1000000, [mnesia:dirty_write({m,I,I}) || I <- lists:seq(1,M)],
  t("mnesia 1M: select limit 1000 + skip to 999900", fun()-> mnesia:activity(async_dirty, fun()-> {L,C}=mnesia:select(m,[{{m,'$1','_'},[],['$1']}],1000,read), skip(L,C,999900,5) end) end),
  halt().
sel(C) when element(1,C)==mnesia_select -> mnesia:select(C); sel(C) -> ets:select(C).
kn(_,_,0,A) -> lists:reverse(A); kn(T,K,N,A) -> K2=ets:next(T,K), kn(T,K2,N-1,[K2|A]).

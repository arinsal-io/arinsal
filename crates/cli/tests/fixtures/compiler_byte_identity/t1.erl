-module(t1).
-export([go/0]).

go() ->
    [cbm_tail(id(<<16:16, "16">>)),
     cbm_tail(<<1:1, "1">>),
     cbm_tail(id(<<1:1, "1">>)),
     cbm_tail(<<1:1, "1">>)].

cbm_tail(<<0:16, Rest/binary>>) -> Rest;
cbm_tail(<<16:16, Rest/binary>>) -> Rest;
cbm_tail(<<_:1, Rest/binary>>) -> Rest.

id(X) -> X.

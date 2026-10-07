-module(arinsal_term_hash_fixture).
-export([make/1]).

make(X) -> fun() -> X end.

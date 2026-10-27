-module(emit_facts).
-export([a/0, b/1, c/2, init/0, nif1/0, nif2/1]).
-nifs([nif1/0, nif2/1]).
-on_load(init/0).

a() -> 1.
b(X) -> X + 1.
c(X, Y) -> {X, Y}.
init() -> erlang:load_nif("emit_facts", 0).
nif1() -> erlang:nif_error(nif_not_loaded).
nif2(_) -> erlang:nif_error(nif_not_loaded).

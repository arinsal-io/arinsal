%% Backend behaviour of the manager: how a project is actually run.
%% `arinsal_cloud_fake` is the stock-ERTS implementation. The `arinsal_ns` backend is a
%% follow-up; `select/0` will pick it when the natives exist.
-module(arinsal_cloud_backend).

-export([select/0]).

-type spec() :: #{
    key := {binary(), binary()},
    tenant := binary(),
    project := binary(),
    release_dir := file:filename(),
    version := binary(),
    port := inet:port_number(),
    env := [{string(), string()}],
    log := pid(),
    notify := pid()
}.
-type handle() :: map().

-export_type([spec/0, handle/0]).

%% Start the project. The returned namespace is `undefined` for backends without one.
%% The backend sends `{project_exit, Key, maps:get(id, Handle), Reason}` to `notify` when the
%% project dies on its own (best effort).
-callback start(spec()) -> {ok, handle(), Ns :: pos_integer() | undefined} | {error, term()}.
-callback stop(handle()) -> ok.
-callback info(handle()) -> map().

%% App env `backend`: `auto` (default) or a module implementing this behaviour.
-spec select() -> module().
select() ->
    case application:get_env(arinsal_cloud, backend, auto) of
        auto -> arinsal_cloud_fake;
        Mod when is_atom(Mod) -> Mod
    end.

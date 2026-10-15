%% Backend behaviour of the manager: how a project is actually run.
%%
%%   arinsal_cloud_ns    namespaces of this node, needs the `arinsal_ns` natives
%%   arinsal_cloud_fake  one OS process per project, works on any runtime
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

%% App env `backend`:
%%   fake  always the OS-process backend
%%   ns    always the namespace backend (projects fail to start without the natives)
%%   auto  (default) the namespace backend when it is usable, else fake; usable means the natives
%%         exist and `arinsal_ns_boot` is not the placeholder
%%   Mod   any module implementing this behaviour
-spec select() -> module().
select() ->
    case application:get_env(arinsal_cloud, backend, auto) of
        auto ->
            case arinsal_cloud_ns:usable() of
                true -> arinsal_cloud_ns;
                false -> arinsal_cloud_fake
            end;
        fake -> arinsal_cloud_fake;
        ns -> arinsal_cloud_ns;
        Mod when is_atom(Mod) -> Mod
    end.

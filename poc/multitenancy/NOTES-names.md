# NOTES-names: per-namespace registered names

## Chunk 1: register table (done)
- `NsEntry` (crates/vm/src/namespace.rs) holds a `OnceLock<RegisterTable>`, created on the first
  `register/2` in that namespace. Namespace 0 keeps `Runtime.reg` and its code path.
- Helpers on `Runtime` (crates/vm/src/register.rs):
  - `reg_for(ns)`: table that `register`, `unregister` and `registered/0` use (`None` for an unknown ns);
  - `whereis_in(ns, name)`: own table first; on a miss, root's table, and only a process whose
    ns word has `NS_SHARED`. `ns == 0` is one branch to the old lookup.
  - `whereis_proc_in`, `whereis_proc_str_in`: the same for pid-only callers.
- Sites switched to the process's ns: `whereis/1` (JIT light path and BIF), `register/2` and
  `unregister/1` (light and full), `registered/0`, send to a name and `{Name, node()}`,
  `send_after`/`start_timer` to a name (resolved at fire time in the creator's ns),
  `monitor(process, Name)`, and the name release at process exit (`exit_stage3`).
- Rules in a namespace:
  - ports cannot be registered (`badarg`) and are invisible, root only for now (port monitor by
    name finds nothing);
  - `register(Name, Pid)` needs `Pid` in the same ns (`badarg` otherwise), so a tenant cannot put a
    root pid into its table;
  - the same name can exist in several namespaces and in root at the same time.

## Not covered
- Root-side lookups that serve the runtime itself (`logger`, `erl_signal_server`, `code_server`,
  dist, trace, `erts_code_purger`) still use root's table on purpose.
- `enif_whereis_pid/port` resolve in root's table (the NIF hook has no process).
- A destroyed ns keeps its (empty after process exit) table; nothing frees it.
- Named ETS, `persistent_term` scope, env overlay, RootOnly natives and halt are later chunks.

## Chunk 2: ETS (done)
- `TableOptions.ns` (crates/ets/src/lib.rs) records the creator's namespace next to `owner`.
  `Registry.names` is keyed by `(ns, Atom)`; `whereis` stays the ns 0 lookup, `whereis_in(ns, name)`
  and `all_in(ns)` are new. `rename`, `detach` and `create` use the table's ns.
- VM (crates/vm/src/natives/ets.rs): `Who { ns, rt }` is passed to `resolve`, `handle`, `allowed`.
  - By tid: a table of another ns is `Missing` (badarg, `ets:info` gives `undefined`), unless it
    is a root table whose owner has the SHARED bit; then reads work.
  - By name: own ns first, then root names of SHARED owners (`whereis_named`). `ets:whereis/1` the same.
  - Writes (and anything with `write == true` in `allowed`) to a table of another ns are refused.
  - The per-scheduler table cache (`with_cached_table`, the BeamAsm direct path) declines tables of
    another ns, so those calls take the registry path and the checks above.
  - `ets:all/0` lists only the caller's ns (root sees only its own tables too).
  - `give_away/3` and the `heir` option of `new/2` and `setopts/2` need a live pid of the same ns, else badarg.
- Gaps: a table survives only as long as its owner (no ns-level free on destroy besides owner exit);
  `erlang:system_info(ets_count)` and the ETS memory statistic are node-wide; heir hand-over at owner
  exit is not rechecked (the heir was checked when set).

## Run
```
export CARGO_TARGET_DIR=/Users/sts/dev/sq/arinsal-prs/target-mt-names
export PATH=/Users/sts/dev/sq/arinsal-prs/bin:/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:$PATH
cargo test -p arinsal-vm --test ns_names
cargo test -p arinsal-vm --test ns_ets
cargo test -p arinsal-vm --test ns_core
cargo test -p arinsal-vm --lib register
```
Tests: ns_register_same_name_two_ns, ns_whereis_isolated, ns_whereis_shared_root_fallback,
ns_send_to_name_resolves_in_own_ns, ns_registered_filtered, ns_root_names_unchanged,
ns_register_cleared_on_exit, ns_register_foreign_pid_badarg.

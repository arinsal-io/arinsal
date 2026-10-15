# Code domains: notes (stream `code`)

## Chunk 1 (done): domains, process chain, dynamic calls

What exists:

- `crates/vm/src/code_domains.rs`: `DomainId = u32` (0 = base), `DomainChain = Arc<[DomainId]>`
  (always ends with 0), and `Domains`, the overlay `(DomainId, Atom) -> module id` plus the chain of
  each domain. `Domains` lives in `CodeTables.domains` (a `SharedTable`), so it is staged and
  published with the code indexes like the other tables.
- `Process.code_chain: Option<DomainChain>` on the VM process (`proc_create.rs`). `None` is root.
  `erl_create_process` copies it to the child next to `group_leader`/`parent`. The ns stream's
  `arinsal_ns:spawn` should set it the same way `arinsal_code:spawn` does (set on the parent
  around `erl_create_process`, or directly on the child).
- Loading into a domain: `Vm::load_into_domain`. Instances go to free module slots through
  `CodeTables::alloc_in_domain`, which skips the node's export index, and are never compiled by
  BeamAsm. A replaced instance is pushed to `condemned`. `-on_load` modules are refused
  (`{error, {on_load, [M]}}`).
- Natives (in the `code` family list, `natives/code.rs` forwards `arinsal_code:*`):
  - `arinsal_code:new_domain(Parent | [Parent]) -> DomainId`; the chain is
    `[New | parents' non-base domains] ++ [0]`.
  - `arinsal_code:load(Domain, [{Mod, Beam}]) -> ok | {error, {Reason, [Mod]}}`.
  - `arinsal_code:spawn(Chain, M, F, A) -> pid()`; a trailing 0 is added when missing, `[0]` is
    a root spawn.
  - `arinsal_code:chain(Pid) -> [DomainId]`, only for `self()` for now (badarg otherwise).
  - "Root only" is checked as "the caller has no chain"; switch to the ns word after merge.
- Dynamic resolution through the process chain, one `code_chain.is_some()` branch on each path:
  - interpreter `call_named_untraced` (apply/2,3, `apply` instruction, export funs, error-handler
    re-entry): the domain lookup runs before `unloaded_on_load`/`load_named_traced`;
  - `resolve_run_process` (interpreter spawn start);
  - BeamAsm resolvers `arinsal_beamasm_apply_resolver`, `arinsal_beamasm_apply3_resolver`
    (also the `beam_run_process` start) and the export-fun branch of the call_fun resolver: a
    process with a chain falls back to the interpreter fragment, which resolves through the
    chain. Root keeps the native fast path.
  - local funs of a domain instance: `resolve_local_fun` falls back to `domain_local_fun` when
    the base has no instance (normally the dispatch cached at `make_fun` hits first).

Test: `cargo test --release -p arinsal-vm --test ns_code` (needs OTP 29 `erlc` on PATH):

- `ns_code_two_domains_same_module_name`: domains 1 and 2 each load `w`; workers spawned with
  `[1,0]` and `[2,0]` get their own `w` through `M:f()` with a runtime `M`, `apply/3`, nested
  `erlang:apply`, `spawn(M, g, ...)` and a fun returned by `w`; root does not see `w`. Passes with
  BeamAsm and with `ARINSAL_INTERP=1`.
- `ns_code_root_unchanged`: timing of 2M dynamic and 1M static calls at ns 0 (release, best of 5).
  Before: 2.78 ms / 2.15 ms. After: 2.84-3.12 ms / 1.95-2.28 ms over four runs, within noise.

Note for the test author: `M = w, M:f()` is constant-folded by erlc into a static `w:f()`; pass
the module in at run time to exercise the dynamic path.

## Chunk 2 (done): static imports and lookup natives

- `arinsal_loader::Module.domain: u32` (0 = base) records the instance's domain. `load_into_domain`
  sets it before the instance is shared, so it never changes.
- Static calls: `call_import_general` probes the caller instance's domain chain
  (`Vm::caller_domain_module`) right before the base `loaded.get`. A hit is cached in the import
  slot by `remember_export`, like a base hit; the cache stays valid because the instance's chain
  is fixed, and a staging commit (new generation) invalidates it as before. A miss falls through
  to the unchanged base path. Base instances (`domain == 0`) skip the probe, so root pays one
  compare on an import cache miss and nothing on a hit.
- Native code guard: `NativeTargetCache::function_for_target` and the first-run native start in
  `process.rs` return no native entry for a domain instance, so it never enters native code
  registered under a base module of the same name.
- Lookup natives through the process chain (`CodeTables::module_in_chain`, `Vm::module_for_process`):
  `erlang:module_loaded/1`, `function_exported/3` (both the executor and the light native
  versions) and `erlang:get_module_info/1,2`. `get_module_info(M, exports)` of a domain instance
  lists the instance's own export table (domain modules are not in the node's export index).
- Tests (both with BeamAsm and `ARINSAL_INTERP=1`):
  - `ns_code_two_domains_same_module_name` now also loads module `a` into each domain, whose
    `run/0` calls `w:f()` and `lists:reverse/1` statically: each domain gets its own `w`, the base
    call works;
  - `ns_code_lookup_natives_follow_chain`: a domain process sees `w` through the three natives,
    root does not (`false`, `false`, `badarg`);
  - `ns_code_root_unchanged`: 2.90-3.05 ms / 1.96-2.01 ms over four runs (baseline 2.78 / 2.15).

## Chunk 3 (done): loading into the caller's domain

- `erlang:prepare_loading/2` records the preparing process's domain (first element of its chain,
  0 for root) on the prepared code. `erlang:finish_loading/1` loads prepared code of a non-zero
  domain into that domain (`Vm::install_in_domain`), synchronously, without the staging/barrier
  protocol of base loads (domain code is never native, so no code barrier is owed). Mixing
  domains in one `finish_loading` is `badarg`. Because the domain travels with the prepared
  code, `code:load_binary/3` works too: the caller prepares, `code_server` (root) finishes, and
  the module lands in the caller's domain. `erlang:load_module/2` is prepare + finish in the
  caller.
- `install_in_domain` (also behind `arinsal_code:load/2`), all or nothing:
  - md5 dedup: a module whose name the domain's chain already resolves to an instance with the
    same md5 (this domain, an outer domain, or the base) is skipped; when every module is
    skipped nothing is staged, so code memory and the code generation do not change;
  - base shadowing: a name the chain resolves to a base instance with a different md5 is
    `{not_allowed, [M]}` from `finish_loading`, i.e. `{error, not_allowed}` from
    `erlang:load_module/2` and `code:load_binary/3`;
  - allowlist: a consolidated Elixir protocol over a base protocol (both export
    `__protocol__/1`). Each project consolidates its protocols over its own implementations,
    so its domain needs its own copy; base code keeps calling the base protocol;
  - a name only an outer non-base domain defines is shadowed by this domain; a name this
    domain already has is replaced (old instance to `condemned`); `-on_load` modules are
    refused (`on_load`); duplicates in one batch are `duplicated`.
- `code:is_loaded/1` and `code:which/1` are answered by `code_server` from its own ETS table
  (`code_server:is_loaded/1`), not by a native. The code server records every module it
  finished loading, whatever the domain, so after a domain's `code:load_binary/3` root's
  `code:is_loaded(w)` says `{file, "w.beam"}` while `erlang:module_loaded(w)` says `false`.
  Fixing that needs a per-ns code server or a chain-aware `is_loaded`; left as is.
- From `code_server.erl` (read, not tested here): its `load_binary` also calls `erlang:module_loaded/1` and `do_purge/1` in root
  for the module name, and refuses modules in sticky directories (`sticky_directory`) before
  `finish_loading` runs. So `code:load_binary(lists, ...)` from a domain gets
  `{error, sticky_directory}`, and a base module of the same name gets its old code purged.
- (Closed in chunk 4: names the base has not loaded are compared with root's code path.)
- Tests (with BeamAsm and `ARINSAL_INTERP=1`):
  - `ns_code_load_into_caller_domain`: on a booted CLI node (needs `cargo build --release -p
    arinsal-cli`), a chained process loads `w` with `code:load_binary/3` and calls it; root
    sees `module_loaded(w) = false` and `w:f()` is `undef`;
  - `ns_code_md5_dedup`: a domain process loads `dd` (identical to base) and `dep` (identical to
    an outer domain): `{module, _}` for both, `erlang:memory(code)` grows by 0; loading a new
    module grows it;
  - `ns_code_base_not_shadowable`: `erlang:load_module(lists, Fake)` from a domain is
    `{error, not_allowed}` and both the domain and root keep the base `lists`; a protocol
    module `pp` shadows the base one in the domain only.
  - `ns_code_root_unchanged`: 2.88 ms / 2.21 ms (baseline 2.78 / 2.15).

## Chunk 4 (done): domains wired to namespaces

- `NsEntry.code_chain: Option<DomainChain>` is fixed at `arinsal_ns:create/3`:
  - default: a fresh domain over the base, chain `[NsDomain, 0]`;
  - `dep_domain => D` (or a list): a fresh domain over `D`, chain `[NsDomain, D, 0]`;
  - `code_chain => [..]`: that chain as given (trailing 0 added; one domain id stands for its
    own chain; `[0]` is the base only). Both options together are `badarg`.
  - `arinsal_ns:info/1` reports it as `code_chain => [DomainId]`, so the boot step can load
    the release into `hd(code_chain)` with `arinsal_code:load/2` (or by loading from inside the
    namespace, which goes to the same domain).
- `erl_create_process`: with `so.ns` set (`arinsal_ns:spawn/4,5`) the child takes the ns entry's
  chain; otherwise it inherits the parent's. So a process in ns N always has N's chain.
  `arinsal_code:spawn/4` and the other `arinsal_code` writers stay root-only test helpers: they
  now refuse a caller with `ns != 0` as well as one with a chain.
- Root code path check in `install_in_domain`: for a name the chain does not see, the first
  `<name>.beam` on the VM's code path (`Vm.paths`: the explicit paths, `.` and OTP's
  `lib/*/ebin`, not paths `code_server` adds later) is compared by module md5. The md5 and
  whether the beam is a protocol are cached per file path, process wide; the path search is one
  `stat` per directory per module, uncached. Same md5: the base loads that file (once, shared
  by every domain) and the domain load is a no-op. Different md5: `not_allowed`, unless both
  are protocols.
- New rule from MT_BRIEF: hook points in ERTS-ported files now carry `// arl: <what>`. I marked
  every hook of the code stream. The names I added before the rule (`code_chain`, `domain`,
  `domains`, `alloc_in_domain`, the `Prepared.domain` field) are left for the final rename pass.
- Tests (with BeamAsm and `ARINSAL_INTERP=1`, plus `ns_core` and `ns_names` still green):
  - `ns_code_ns_spawn_gets_chain`: ns created with `dep_domain => D`; its chain is
    `[Own, D, 0]`; a process from `arinsal_ns:spawn/4` reaches the ns's `w` and `a` (dynamic,
    spawn MFA, fun, static) and `dep` from `D`, and its spawned child has the same chain;
    `code_chain => [0]` gives `[0]`;
  - `ns_code_unloaded_base_name_not_allowed`: on a fresh VM (`orddict` not loaded), a domain
    load of a fake `orddict` is `not_allowed`; the real OTP `orddict` loads into the base
    (`module_loaded` true for root, code grows); a second domain loading it adds 0 bytes.
  - `ns_code_root_unchanged`: 2.93 ms / 2.28 ms (baseline 2.78 / 2.15).

## Chunk 5 (done): dep domains and dropping domains

- Registry (in `Domains`, staged with the code tables):
  - `arinsal_code:new_dep_domain(Hash) -> Id` (root only) creates a domain over the base and
    registers it under `Hash`; called again with the same hash it returns the same id.
  - `arinsal_code:dep_domain(Hash) -> {ok, Id} | none`.
  - `arinsal_code:deployment_hash([{Mod, Md5}]) -> binary()`: md5 over the pairs sorted by
    module name, each as `<<(byte_size(Name)):16, Name/binary, Md5/binary>>`. The same in
    Erlang: `erlang:md5([<<(byte_size(N)):16, N/binary, M/binary>> || {N, M} <-
    lists:sort([{atom_to_binary(Mod), Md5} || {Mod, Md5} <- Mods])])`. The boot step passes
    the release's non-app modules with their module md5 (`beam_lib:md5/1` or
    `Mod:module_info(md5)`), then `dep_domain/1`, else `new_dep_domain/1` + `load/2`, then
    `arinsal_ns:create(T, P, #{dep_domain => Id})`.
- Refcount: `arinsal_ns:create/3` takes a reference on every registered dep domain its chain
  uses (all but its own first domain, or the whole chain for an explicit `code_chain`).
  Domains made with `arinsal_code:new_domain/1` are not refcounted and never dropped.
- Dropping, on the first `close` of a namespace (`root_only::destroy_namespace`, so both
  `arinsal_ns:destroy/1` and a `halt` inside the namespace):
  - the namespace's own domain (when `create` made it) and every dep domain whose refcount
    reaches 0 are dropped at once: chain, names and hash leave the overlay, so no chain can
    name them and no later load or `arinsal_code:spawn` accepts them (`badarg`);
  - their instances go to `Domains.retired` under the namespace id, and are moved to
    `condemned` once that namespace has no process left (`reap_retired_code`, run on
    destroy, `arinsal_ns:create` and every `arinsal_code` call). The next purge `complete`
    frees condemned slots that the purging process does not reference. So memory release is
    deferred to the next purge in root; I did not test the release end to end.
- Tests (with BeamAsm and `ARINSAL_INTERP=1`; `ns_core`, `ns_env`, `ns_ets`, `ns_heap`,
  `ns_names`, `ns_pterm` still green):
  - `ns_code_dep_domain_shared`: hash registry round trip; `dep` loaded once into the dep
    domain; two namespaces with `dep_domain => D` both call `dep:f()` through `[Own, D, 0]`;
    code memory grows only by the one load; after destroying one namespace D is still
    registered and used by the other; after the second, `dep_domain(Hash)` is `none`;
  - `ns_code_drop_domain_on_destroy`: after `destroy`, `load/2` and `arinsal_code:spawn/4` on
    the old domain are `badarg`; a new namespace gets a new domain and loads a different `w`.
  - `ns_code_root_unchanged`: 2.88-2.97 ms / 2.00 ms (baseline 2.78 / 2.15).
- `md-5` is now a dependency of `arinsal-vm` (already in the lockfile through the loader).

## What I learned for the next chunks

### Static imports (implemented in chunk 2)
- Interpreter: `call_import` -> `call_import_general` (calls.rs). The cache check is
  `cached_import_jump(p.module, index)`, keyed by the caller instance and the code generation.
  On a miss the module is looked up with `self.code.loaded.get(module_name)` (~calls.rs 1006),
  then `unloaded_on_load`, then `load_named_traced`. The domain probe belongs right before the
  `loaded.get`, keyed by the caller instance's domain; `remember_export(p.module, ...)` then
  caches it per instance and stays valid because the chain of an instance never changes.
- The caller's domain is not recorded on the instance yet. Plan: a `pub domain: u32` field on
  `arinsal_loader::Module` (constructed at loader lib.rs ~1624, cloned at ~427), set in
  `load_into_domain` before `Arc::new`. A side map would also work but costs a hash per miss.
- The same field is needed to keep domain instances out of native code by name:
  `NativeTargetCache::function_for_target` (beamasm_integration.rs ~83) and the first-run path in
  process.rs (~1342) look up native functions by module *name* when the instance has no native
  range, so a domain module that shares a name with a compiled base module (allowed protocol
  shadowing) would enter the base module's native code. Guard both with `module.domain != 0`.
- A static call from a BeamAsm-compiled base module goes through the per-node dispatch slot of
  its MFA. Base modules only resolve in the base, so that is correct as long as domain modules
  are never published there (they are not).

### BeamAsm
- Dispatch targets are keyed by `(scope, Mfa)` (`dispatch_entry`, `export_get_or_make_stub`,
  `import_entries`), leaked and shared by every caller in the node; `publish_module` and
  `refresh_import_slots` set their addresses per code index. Making domain modules native means
  a `(scope, domain, Mfa)` key, import slots per domain, and refreshing every dependent chain
  on load. That touches compile-time import binding in beamjit too.
- Decision for the PoC: non-zero domains stay interpreted. Dynamic calls from native base code
  in a chained process already fall back to the interpreter (above). Cost: app code runs
  interpreted. As a rough guide, the root timing loop takes 175 ms with `ARINSAL_INTERP=1`
  against ~3 ms native. OTP/Elixir base code stays native.

### Open items for follow-up chunks
- `code:is_loaded/1`, `code:which/1` and the rest of `code_server` answer from root's view.
- Stage 2 sharing (closure classes across dep versions) is not started.
- `arinsal_code:chain/1` for other processes needs a process_info-style request.
- NIFs (`load_nif` finds the caller module in the base), native records and `-on_load` in
  domains are not handled.

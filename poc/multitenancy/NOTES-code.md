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

## What I learned for the next chunks

### Static imports
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
- Static imports through the instance chain (above), then `erlang:module_loaded/1`,
  `function_exported/3` (+ their `_light` native versions in natives/code.rs ~559/~580) and
  `get_module_info` (natives/code.rs ~430) through the process chain.
- `prepare_loading`/`finish_loading` into the caller's domain (branch in `finish_stage` before
  `stage_prepared`), md5 dedup against the visible chain (`CodeMeta.md5`), `{error, not_allowed}`
  for shadowing a base module. Proposed allowlist: consolidated Elixir protocols (both modules
  export `__protocol__/1`). Also dedup into the base when the root code path has a beam with the
  same md5.
- Dep domains: hash registry (`dep_domain/1`), reverse map dep -> dependents, drop of a domain
  (remove overlay entries, push ids to `condemned`; the next purge frees unreferenced slots).
- `arinsal_code:chain/1` for other processes needs a process_info-style request.
- NIFs (`load_nif` finds the caller module in the base), native records and `-on_load` in
  domains are not handled.

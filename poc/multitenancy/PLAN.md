# Multi-tenant Arinsal: PoC plan

Goal: one Arinsal node runs a manager, and users deploy many Mix projects into it, isolated by tenant.
The node works like a small cloud: deploy, list, stop, logs, with per-project caps.

Why: the measurements in [bench/RESULTS.md](bench/RESULTS.md) on stock ERTS show:

| | memory | start |
|---|---|---|
| a project in a shared node | ~0.2-0.55 MB | ~0.1-1 ms |
| a node per project | ~125 MB | ~300 ms |

The PoC must show the same on Arinsal with real isolation. The mechanism is described in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Rules for the branch

- Branch `poc/multitenancy`; everything (code, benches, notes) lives here.
- Namespace 0 (root) behaves 1:1 with ERTS, and the existing compat and OTP suites keep passing.
  There is no on/off switch: root is the "off" state, so there is one test matrix.
- No new `unsafe` above the census baseline. Tests and sockets bind 127.0.0.1 only.
- Conventional Commits in English.

## Scope

In:
- the ns word and the delivery check;
- per-ns names;
- code domains with md5 dedup;
- booting a release inside a ns;
- the manager with deploy, list, stop, and logs;
- counters and hard caps;
- idle stop.

Out, for after the PoC:
- ingress proxy and socket handoff (projects keep their own 127.0.0.1 listener with 1 acceptor, ~26 KB);
- weighted scheduling;
- atom quota;
- heap-snapshot suspend/resume;
- cross-project visibility within a tenant;
- partial uploads by hash;
- the rebar3 plugin.

## Steps

Each step ends with tests and a note in `NOTES.md`.

### 0. Baseline (gate)
- Build the release binary and the `erl` shim.
- Run `bench/rest` (Bandit + Plug + Jason) and `bench/phxn` (Phoenix 1.8) as plain apps on Arinsal.
- Fix or list the blockers. Record footprint, idle CPU, and rps next to the ERTS numbers.
- Exit: both apps answer HTTP on Arinsal.

### 1. Namespace word and delivery check (sched)
- Add an ns word and a SHARED bit on `sched::Process`, `ns` on `RunCtx`, and `any_ns` on `Inner`.
- Check in `deliver_live`/`deliver_process`.
- Add process count and cap in `ProcessTable::insert`/`remove`, and reductions where a slice is accounted.
- Exit:
  - cross-ns send, link, monitor, and exit are refused;
  - root and SHARED rules hold;
  - delivery microbench at ns 0 shows no change.

### 2. Namespace table and natives (vm)
- Add `crates/vm/src/namespace.rs` with the entry table on `Runtime`.
- Mirror the ns on the VM process and inherit it on spawn.
- Natives: `arinsal_ns:create/spawn/destroy/expose/info/list`.
- Exit: spawning into a ns and destroying it leaves no processes behind.

### 3. Names and root-only natives
- Per-ns `RegisterTable` with the SHARED fallback.
- ETS names keyed by `(ns, Atom)`, `Table.ns` checked on access, and the give_away/heir check.
- `pterm` scope per ns, an env overlay, and filters on `processes/0` and `registered/0`.
- Timers check the ns when created.
- RootOnly bit at classify time; `halt` from a ns destroys that ns.
- Exit: an isolation test per surface listed in ARCHITECTURE.md sections 2, 3, and 6.

### 4. Code domains
- Overlays in `CodeTables`, and chain lookups in module resolution, `remember_export`, and fun dispatch.
- Loading into the caller's domain with md5 dedup.
- The BeamAsm dispatch key gets the domain, and slots refresh on load.
- Exit:
  - two namespaces run different `MyApp.Worker` modules;
  - a second project with the same deps adds only its own modules to code memory;
  - the ns 0 code path is unchanged.

### 5. Boot inside a namespace
- Generate the ns boot script and add `arinsal_ns_kernel` (Erlang, in repo).
- Spawn `erl_init:start` in the ns.
- Measure memory per project right away; the target is ~0.5 MB.
- Exit: `bench/rest` and `bench/phxn` releases boot inside namespaces, and many copies run in one node.

### 6. Manager and CLI
- `packages/arinsal_cloud` runs in root:
  - admin HTTP on 127.0.0.1 with deploy, list, stop, and logs;
  - it is the group leader of ns processes;
  - an idle timer stops idle projects.
- Mix tasks in `packages/arinsal`: `mix arinsal.deploy` (posts the release), `list`, `stop`, and `logs`.
- Exit: the demo below runs end to end.

### 7. Heap accounting, caps, and measurements
- Count the live-heap delta after GC and destroy a ns over its byte cap.
- Repeat the RESULTS.md scenarios on Arinsal, root vs ns:
  - memory per project;
  - idle CPU;
  - cold start;
  - load with 100 projects.
- Exit targets:
  - 1000 REST projects idle in one node;
  - isolation tests green;
  - ns overhead <= 5% rps and p99.

## Demo

```sh
arinsal cloud --admin 127.0.0.1:7000
cd bench/rest && mix arinsal.deploy --tenant acme --project shop
cd bench/rest && mix arinsal.deploy --tenant globex --project shop
cd bench/phxn && mix arinsal.deploy --tenant acme --project web
mix arinsal.list
curl 127.0.0.1:<port from list>/t/1/items/1
```

## Order

- Step 0 gates everything.
- Steps 1-3 (runtime isolation) and step 4 (code) touch different files and can run in parallel.
- Step 5 needs 1-4.
- Step 6 can start against step 2's natives.
- Step 7 runs last.

# Multi-tenant Arinsal: PoC plan

Goal: one Arinsal node runs a manager, and users deploy many Mix projects into it, isolated by tenant.
The node works like a small cloud: deploy, list, stop, env, logs, with per-project quotas.

Why: the measurements in [bench/RESULTS.md](bench/RESULTS.md) on stock ERTS show that a project in a shared node
costs ~0.2-0.55 MB and starts in ~0.1-1 ms. A node per project costs ~125 MB and ~300 ms.
The PoC must show that the same holds on Arinsal with real isolation turned on.

## Rules for the branch

- Branch `poc/multitenancy`; everything (code, benches, notes) lives here.
- Tenancy is gated: the root namespace behaves 1:1 with ERTS, and the existing compat and OTP suites keep passing
  with tenancy on and off.
- No new `unsafe` above the census baseline. Tests and sockets bind 127.0.0.1 only.
- Conventional Commits in English.

## Model

- **Namespace** = `(tenant_id, project_id)`. A tenant is the security boundary; a project is the naming boundary.
- Projects of the same tenant see each other like connected nodes (`{Name, :"billing@acme"}`); nothing crosses tenants.
- **Mechanism in the runtime** (BIFs in an `arinsal_ns` module): create, bind_modules, spawn, destroy, suspend,
  resume, info, list.
- **Policy in the manager** (an OTP app in the root namespace): project state machine, ingress routing,
  quotas, admin API. Namespaces belong to the runtime, so a manager restart does not touch tenants.

## Phases

Each phase ends with tests and a short note in `poc/multitenancy/NOTES.md`.

### Phase 0: baseline (gate)
- Build the release binary and the `erl` shim.
- Run `bench/rest` (Bandit + Plug + Jason) and `bench/phxn` (Phoenix 1.8) as plain apps on Arinsal.
- Fix or list the blockers. Record footprint, idle CPU, and rps next to the ERTS numbers.
- Exit: both apps answer HTTP on Arinsal.

### Phase 1: namespace core
- Namespace table on the node: ids, quotas, counters.
- A process carries a namespace id, inherited on spawn. Root id 0 means today's behaviour.
- Isolated by namespace:
  - send, link, monitor, and exit signals (dropped across tenants, allowed across projects of one tenant);
  - register, whereis, and registered;
  - named ETS tables;
  - persistent_term (the per-scope stores already exist);
  - application env;
  - `os:getenv` and `System.get_env`;
  - processes, process_info, and erlang:ports.
- Atoms stay shared, with a creation counter and a quota per tenant.
- Exit: an isolation test per point, plus a microbench per checked op (tenancy on vs off).

### Phase 2: code namespaces
- Content-addressed module store: the module md5 maps to loaded code, refcounted.
- Each namespace has a binding table from module name to hash, with a fallback to the shared base (OTP, Elixir).
  Base modules cannot be rebound.
- The loader resolves imports in the namespace. Dynamic calls, `apply`, MFA spawns, and external funs use the
  caller's namespace.
- `arinsal_ns:bind_modules/2` loads a module only when its hash is missing.
- Exit:
  - two projects run different `MyApp.Worker` modules side by side;
  - a second project with the same deps adds only its own modules to code memory.

### Phase 3: OTP inside a namespace
- Start a minimal kernel set inside the namespace: application_controller, logger forwarding to the host with
  namespace metadata, and a code_server view over the binding table.
  Because register is per namespace, OTP code that calls these by name finds the namespace's instance.
- Boot from the project's `start.boot`:
  - instead of primLoad for base apps, bind the shared base;
  - bind the project modules;
  - start the apps through the namespace application_controller;
  - turn sys.config and runtime config into namespace env.
- `vm.args` maps to quotas. `schedulers_online` is virtual per namespace, so partitioned libraries
  (Registry, PubSub) start one partition instead of twelve.
- Exit: `bench/phxn` boots from its release inside a namespace, and two copies run in one node.

### Phase 4: manager, ingress, CLI
- `arinsal_cloud` app in the root namespace:
  - project states: stopped, starting, running, stopping, failed;
  - admin HTTP API on 127.0.0.1 (deploy, list, stop, env, logs);
  - ingress listener routing by Host, `<project>.<tenant>.localhost`.
- Ingress for the PoC is a reverse proxy to a per-project listener on an ephemeral 127.0.0.1 port. Acceptors are
  overridden to a small pool. Stretch goal: socket handoff into the namespace with no per-project listener.
- Start command: `arinsal cloud` (or `arinsal -s arinsal_cloud`).
- Mix tasks in `packages/arinsal`:
  - `mix arinsal.deploy` builds a deterministic prod release at a canonical path, sends the module hashes,
    uploads only the missing beams plus boot, app, and config files, and creates or replaces the project;
  - `mix arinsal.list`, `mix arinsal.stop`, `mix arinsal.env`, and `mix arinsal.logs`.
- rebar3 plugin after the PoC; the upload protocol stays the same.
- Exit: the demo from this file's last section runs end to end.

### Phase 5: quotas and scheduling
- Reduction budget per namespace with weights (deficit round robin; over-budget processes park until the next
  epoch) plus an optional hard cap.
- Memory accounting per namespace: heaps after GC, ETS, and off-heap binaries charged to the creator.
  A namespace that exceeds its quota is destroyed.
- Process and atom quotas.
- Exit:
  - fairness: 1000 busy processes vs 1 gives ~50/50 at equal weights and ~75/25 at 3:1;
  - abuse suites (spawn bomb, memory bomb, atom flood) kill only their namespace.

### Phase 6: idle eviction
- PoC version: stop an idle project and cold-start it from its release on the next request.
  The process tree starts in ~0.1-1 ms per the ERTS measurements.
- After the PoC: heap snapshot suspend/resume that keeps pids.
- Exit: the first request to an evicted project p50 < 5 ms.

### Phase 7: measurements and demo
- Repeat the RESULTS.md scenarios on Arinsal:
  - memory per project;
  - idle CPU;
  - cold start through ingress;
  - load with 100 projects;
  - tenancy on vs off.
- Exit targets:
  - 1000 REST projects idle in one node;
  - isolation suites green;
  - tenancy overhead <= 5% rps and p99;
  - redeploying a project uploads only changed modules.

## Demo

```sh
arinsal cloud --admin 127.0.0.1:7000 --ingress 127.0.0.1:8080
cd bench/rest && mix arinsal.deploy --tenant acme --project shop
cd bench/phxn && mix arinsal.deploy --tenant acme --project web
cd bench/rest && mix arinsal.deploy --tenant globex --project shop
curl shop.acme.localhost:8080/t/1/items/1
curl shop.globex.localhost:8080/t/1/items/1
mix arinsal.list
```

## Order and parallel work

- Phase 0 gates everything.
- After it:
  - phases 1 and 2 run in parallel (separate crates and files);
  - phase 4's CLI and manager can start against a stub runtime API;
  - phase 3 needs 1 and 2;
  - phases 5 and 6 need 3;
  - phase 7 runs last.

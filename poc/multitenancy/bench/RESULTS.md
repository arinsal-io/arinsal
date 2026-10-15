# Tenant density on stock ERTS (OTP 29, Homebrew), macOS arm64, 12 cores, 24 GB

Tenant app: 1 supervisor + 5 gen_server + 1 ETS table. `entries` = rows per worker state and in ETS.
Memory: macOS phys_footprint of beam.smp + erl_child_setup we launched. No distribution, no epmd.
Idle CPU: delta of CPU time over 60 s after 20 s warmup (ps resolution 10 ms).

## Idle cost

| config | footprint | erlang:memory total | idle CPU / min | idle wakeups / min |
|---|---|---|---|---|
| one node, 0 tenants | 65.8 MB | 45.8 MB | 10 ms | 0 |
| one node, 10k empty tenants (entries=0) | 333 MB | 297 MB | not measured | not measured |
| one node, 1k tenants (entries=100) | 231.7 MB | 205.2 MB | 10 ms | 1 |
| one node, 10k tenants (entries=100) | 1467.7 MB | 1399.1 MB | 0 ms | 0 |
| one node, 10k tenants, hibernated | 2182.8 MB | 1353.7 MB | 0 ms | 0 |
| 20 nodes x 1 tenant, default flags | 1302.0 MB | 20 x 45.9 MB | 30 ms total | 6 total |
| 20 nodes x 1 tenant, +S 1 and no busy wait | 1148.1 MB | 20 x 40.8 MB | 10 ms total | 4 total |

Per tenant:
- namespace, empty app: ~26 KB
- namespace, ~40 KB live state: ~140 KB
- node per tenant: 57 MB (tuned) to 65 MB (default)

## Cold start

- Node boot to first eval (no app): p50 ~88 ms (default and tuned alike, 15 runs).
- Tenant suspend (dump state, term_to_binary, write + datasync, kill tree) and resume
  (read, binary_to_term, rebuild tree, every worker answers a call):

| state on disk | suspend p50 / p99 | resume p50 / p99 | wake from hibernate p50 |
|---|---|---|---|
| 6.5 KB | 0.45 / 2.1 ms | 0.09 / 0.2 ms | 23 us |
| 176 KB | 1.4 / 2.7 ms | 0.9 / 2.1 ms | 173 us |
| 1.9 MB | 9.3 / 10.9 ms | 7.3 / 7.8 ms | 1.5 ms |

## Caveats

- macOS, not Linux; repeat on Linux with PSS before quoting numbers externally.
- Resume reads from a warm page cache (purge needs sudo).
- Suspend is an app-level dump; pids change after resume. A runtime-level snapshot could keep pids.
- The namespace model is simulated without isolation checks or per-tenant system services.
- Node boot excludes starting the tenant app; namespace resume includes it.

Reproduce: `erlc dens.erl && python3 measure.py && ./coldstart.sh`

# Realistic tenant: REST API (Elixir 1.20.4 prod release, Bandit + Plug + Jason + telemetry_poller)

Tenant = supervisor + Store (ETS, 200 items) + rate limiter GenServer + Task.Supervisor + telemetry_poller (10 s).
Routes: GET /items, GET /items/:id, POST /items. Shared-node mode: one Bandit, `/t/:tenant/...` routed to the tenant.
Node mode: one release per tenant with its own Bandit. RELEASE_DISTRIBUTION=none. Code: `rest/`, `rest_measure.py`, `loadgen.exs`.

## Idle (all tenants warmed with a request, 20 s settle, 60 s window)

| config | footprint | idle CPU / min |
|---|---|---|
| shared node, 0 tenants | 132.8 MB | 130 ms |
| shared node, 1k tenants | 291.8 MB | 340 ms |
| shared node, 10k tenants | 1848.8 MB | 1500 ms |
| 20 nodes, default flags | 2646.5 MB | 3250 ms |
| 20 nodes, +S 1 and no busy wait | 2463.6 MB | 250 ms |

Per tenant: shared node ~172 KB and ~0.14 ms CPU/min. Node per tenant: 123-132 MB and 12-162 ms CPU/min.

## Cold start

- Node per tenant, release boot to first HTTP 200: p50 296 ms (267-302, 10 runs).
- Shared node, first request to a suspended tenant (resume from file inside the request):

| snapshot | suspend p50 | first request p50 / p99 | warm request p50 |
|---|---|---|---|
| 16.7 KB (200 items) | 0.42 ms | 0.25 / 0.73 ms | 0.07 ms |
| 456 KB (5000 items) | 2.77 ms | 3.0 / 13.9 ms | 0.11 ms |

## Load: 100 tenants, 64 keep-alive connections, uniform tenants, GET /items/:id, 20 s, loadgen on the same box (+S 4)

| config | rps | p50 | p99 | p99.9 | footprint |
|---|---|---|---|---|---|
| shared node, 100 tenants | 115,720 | 0.52 ms | 1.24 ms | 1.54 ms | 163 MB |
| 100 nodes, default flags | 66,627 | 0.85 ms | 2.65 ms | 3.76 ms | 13.7 GB |
| 100 nodes, +S 1 and no busy wait | 73,437 | 0.87 ms | 2.16 ms | 3.09 ms | 12.6 GB |

Caveat: in node mode the loadgen keeps up to 64 connections per node (one port per tenant), in shared mode 64 total.
That is inherent to the topology, but it adds socket overhead to the node case.

# Isolation cost inputs (stock ERTS, no runtime changes)

Ops per REST request that would get a namespace check (2000 requests, call_count + send trace):
sends 6.0, persistent_term:get 8.0, ets:lookup 7.0, Registry.lookup 2.0, GenServer.call 2.0, spawns ~0.
Dynamic calls (Plug pipeline `mod.call/2`) are not countable with call_count; estimated 5-15 per request.

In-memory code by group (bare erl, modules loaded per group):

| group | modules | code | atoms |
|---|---|---|---|
| Elixir + Logger | 282 | 6718 KB | 240 KB |
| deps (Plug, Bandit, Jason, telemetry...) | 206 | 2210 KB | 50 KB |
| the app itself | 6 | 47 KB | 0 |

# Shared dependencies

## Module overlap across Phoenix versions (beam_lib:md5, deterministic prod builds, deps resolved to the same versions)

| vs 1.8.15 | phoenix modules identical | all deps, bytes identical |
|---|---|---|
| 1.8.14 | 87/93 | 3861/4462 KB (87%) |
| 1.8.10 | 79/92 | 3485/4467 KB (78%) |
| 1.8.0 | 57/92 | 2998/4430 KB (68%) |
| 1.7.21 | 39/88 | 2763/4323 KB (64%) |

Same-version deps still differ in 7 modules (Plug.Router, Plug.Debugger, Plug.ErrorHandler, Jason.Decoder.Unescape,
Phoenix.Tracker, ThousandIsland.Handler...): every one embeds the absolute build path as a literal. A canonical build path
makes same-version deps 100% shared and raises the numbers above.

## 50 Phoenix 1.8.15 projects in one node (Endpoint + Router + Controller + PubSub + telemetry_poller per project)

| | procs / project | state / project | tree start p50 / max | unique code / project |
|---|---|---|---|---|
| own Bandit listener | 315 (100 acceptors + 100 acceptor sups + 100 DynamicSupervisors) | 1459 KB | 1.26 / 11.2 ms | 97 KB |
| no listener (host ingress) | 11 | 444 KB (processes 17 KB, ETS 70 KB, rest system) | 0.08 / 5.6 ms | 97 KB |

# Comparison with public numbers of other platforms (vendor claims, not our measurements)

| platform | unit | memory per tenant | cold start |
|---|---|---|---|
| Cloudflare Workers | V8 isolate in a shared process | ~3 MB (vs 35 MB Node), limit 128 MB | ~5 ms (2018), hidden behind the TLS handshake |
| Deno Deploy | Deno runtime on pre-provisioned microVMs | not published | <100 ms hello world, a few hundred ms larger apps |
| AWS Lambda | Firecracker microVM | VMM <=5 MiB + guest (min 128 MB) | VMM boot <=125 ms; end to end <100 ms to >1 s |
| Fly.io Machines | Firecracker microVM | whole VM | resume a few hundred ms; cold ~2+ s |
| Fermyon Spin | Wasm instance | 1-10 MB (third party) | ~0.5 ms (vendor) |
| this experiment (stock ERTS, no isolation yet) | namespace in one node | REST ~0.2 MB, Phoenix ~0.55 MB incl. unique code | resume 0.25 ms (17 KB state), 3 ms (456 KB) |

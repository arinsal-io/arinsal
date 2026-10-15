# Multi-tenant Arinsal: architecture

One Arinsal node hosts many Mix projects. A namespace (ns) is `(tenant_id, project_id)`. Namespace 0 is root and
behaves 1:1 with ERTS. Everything namespace-specific sits behind an `ns != 0` branch.

```
┌──────────────────────────── one Arinsal node ──────────────────────────────┐
│  root (ns 0), 1:1 with ERTS                                                │
│   ├─ OTP kernel (code_server, file, inet_db, user, ...) marked SHARED      │
│   └─ arinsal_cloud (manager): admin API, deploy/stop, log collection       │
│                                                                            │
│  ns 1 (acme/shop)                  ns 2 (globex/shop)                      │
│   ├─ init + small kernel:           ├─ ...                                  │
│   │  application_controller, Logger │                                       │
│   └─ project apps + Bandit on 127.0.0.1:ephemeral                          │
│                                                                            │
│  runtime (Rust): ns word on the process · check at signal delivery ·       │
│  per-ns name tables · code domains · RootOnly BIFs · counters              │
└────────────────────────────────────────────────────────────────────────────┘
```

## 1. Namespace word

- An `AtomicU32` on `sched::Process` (crates/sched/src/lib.rs, next to `reg_atom`) holds the ns id and a SHARED bit.
- SHARED marks root services that tenant processes may reach.
- The VM process (crates/vm/src/proc_create.rs) mirrors the ns for natives. A spawn inherits it where the group
  leader and parent are set (crates/vm/src/signals.rs).
- Only root can create a process in another ns or move a process between namespaces. Anyone can read the word.
- The namespace table lives on `Runtime` (crates/vm/src/process.rs) in a new `crates/vm/src/namespace.rs`.
  Each entry holds tenant, project, counters, caps, env overlay, and pterm scope.
- Natives: `arinsal_ns:create/spawn/destroy/expose/info/list`.

## 2. One check at signal delivery

- Where: `Inner::deliver_live` and `Inner::deliver_process` in crates/sched/src/lib.rs. Both run with the
  receiver's `Arc<Process>` in hand, so the check is one relaxed load.
- Sender ns: carried on `RunCtx`. Callers without a context (`signal_ordered`, the dirty handler, timers) look the
  sender up only when `Inner.any_ns` is set.
- Rule: allow when sender ns == receiver ns, or the sender is root, or the receiver has SHARED.
- Otherwise:
  - a message is dropped silently, like a send to a dead pid;
  - link and monitor return `noproc`;
  - an exit signal is dropped.
- Exempt: literal area copies, system tasks, dirty handler traffic.
- Covered by this point: send, `enif_send`, aliases, `group_leader/2`, link, monitor, exit, and EXIT/DOWN generated
  by the runtime. A cross-ns link cannot exist, so no cross-ns EXIT either.
- Checked elsewhere:
  - timers: ns checked when the timer is created; a name destination resolves in the creator's table;
  - ETS `give_away` and heir: ns equality;
  - ports (`erts_internal:open_port`) and distribution (`try_remote_send`): root only.

## 3. Names

- Per-ns tables:
  - `register` (crates/vm/src/register.rs): one `RegisterTable` per ns, root keeps the current one;
  - named ETS: keyed by `(ns, Atom)` (crates/ets/src/lib.rs);
  - persistent_term: `store_for(ns_scope)` (crates/pterm/src/lib.rs);
  - OS env: an overlay checked before the process-wide env (crates/vm/src/natives/env.rs).
- A lookup that misses in the ns falls back to root, only for processes with SHARED. OTP code inside a ns that
  calls `application_controller` by name finds its own instance; `file_server_2` or `inet_db` resolve to the
  shared root process.
- An ETS table records its ns next to its owner. Access by tid from another ns is refused, except reads of SHARED
  root tables. The check sits in the table handle lookup and the BeamAsm direct ETS path.
- `processes/0` and `registered/0` are filtered by ns.

## 4. Code domains

- Base code tables stay as they are. `CodeTables` (crates/vm/src/load.rs) gets overlays keyed by
  `(DomainId, Atom)` and `(DomainId, Mfa)`.
- Every module instance has a fixed lookup chain:
  - a project's own module: `[ns, dep_domain, 0]`;
  - a shared dependency: `[dep_domain, 0]`;
  - base OTP and Elixir: `[0]`.
- Static imports resolve through the caller instance's chain. Dynamic calls, `apply`, MFA spawns, and external funs
  resolve through the process's ns.
- An instance's chain never changes, so the per-instance `Import` cache stays valid with no per-ns state. The ns 0
  path adds one `ns != 0` branch before the module lookup.
- Loading (`prepare_loading`/`finish_loading`) goes into the caller's domain. When the md5 (`CodeMeta.md5`) matches
  an instance the domain may share, loading is a no-op.
- Sharing, stage 1: `dep_domain` is the hash of the deployment's sorted non-app `(module, md5)` set. Another project
  with the same deps adds only its own modules.
- Sharing, stage 2: closure classes, so different dep versions share their unchanged modules.
- BeamAsm call sites hold dispatch targets, not code addresses. The dispatch key becomes `(scope, domain, Mfa)`,
  and loading refreshes the slots of every chain that now resolves to the new instance.

## 5. Kernel inside a namespace

- `init` is an ordinary preloaded process in Arinsal, so a ns boots with `arinsal_ns:spawn(Ns, erl_init, start, ...)`.
- The manager generates the boot script for the ns:
  - `primLoad` of the release modules; base modules dedup to no-ops;
  - `arinsal_ns_kernel:start()` in place of booting the kernel application;
  - `start_boot` of the project apps.
- `arinsal_ns_kernel` starts only what holds per-project state: application_controller with `ac_tab`, and Logger
  (logger_sup, logger server, proxy, handler watcher, the `logger` table). Application env is per ns for free.
- code_server, file_server_2, inet_db, user, timer_server, and erl_signal_server stay shared in root. That keeps
  ~1 MB of code_server state out of every ns; the expected kernel cost is ~200 KB per ns.
- `code:ensure_loaded/1` checks `erlang:module_loaded/1` first, and that native follows the process's chain, so code
  inside a ns does not reach code_server.

## 6. Root-only natives

- A RootOnly bit is assigned once, when natives are classified (crates/vm/src/natives/mod.rs). It covers halt,
  system_flag, the trace natives, load_nif, open_port, and `erts_internal:*`.
- It is checked at dispatch only when `ns != 0`.
- `halt` and `init:stop` called from a ns destroy that ns instead of the node.

## 7. Accounting

- Reductions: added to the ns entry where a slice is accounted in sched.
- Heap: the live-heap delta after GC (crates/vm/src/natives/sys.rs).
- Processes: counted in `ProcessTable::insert`/`remove`; over the cap, spawn fails with `system_limit`.
- Over the byte cap, the ns is destroyed.

## 8. Manager

- `arinsal_cloud` runs in root. It accepts a release, generates the ns boot script, and spawns `erl_init:start`
  in the ns.
- It is the group leader of ns processes, so logs are collected without runtime work.
- It tracks project state and stops idle projects. A stopped project cold-starts on the next deploy or request.

## Known PoC gaps

- Atoms are shared with no quota (DoS risk).
- Per-ns persistent_term stores are not freed on destroy.
- `code:priv_dir/1` and `code:lib_dir/1` answer with root paths.
- `system_info` and `statistics` report node-wide values.

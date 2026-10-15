# NOTES-boot: a Mix release booted inside a namespace

## Chunk 1 (done)

`packages/arinsal_cloud/src/arinsal_ns_boot.erl` and `arinsal_ns_kernel.erl` replace the stub.
`implemented/0` is gone, so `backend => auto` picks the namespace backend on a runtime with the
natives. Contract: `arinsal_ns_boot:start(Ns, BootPlan, Opts) -> {ok, InitPid} | {error, Reason}`;
`arinsal_cloud_ns` was adapted (it took a bare pid before) and passes `os_env` to
`arinsal_ns:create/3` as well.

What `start/3` does (runs in root, in the manager):
1. `expose_root_services/0`: SHARED on code_server, inet_db, erl_prim_loader, user,
   standard_error, erl_signal_server, timer_server, kernel_refc, global_name_server (those that
   run). Idempotent, called on every start.
2. Preload into the base every plan module whose beam has the same md5 as the one root's code
   path finds (`code:ensure_loaded/1` in root). OTP and Elixir modules are then shared (native
   code) by every namespace and the namespace load skips them.
3. `arinsal_ns:spawn(Ns, ?MODULE, ns_init, ...)` with the project's group leader. The boot reports
   back through an alias (a namespace process cannot send to an unexposed root pid; alias sends
   pass the check). Every step is reported, so a timeout or exit names the step
   (`{boot_timeout, Step}`, `{boot_exit, Step, Reason}`).

Inside the namespace:
- `ns_init`: when the process has no code chain (before the code stream's wiring), it creates a
  domain with `arinsal_code:new_domain(0)` and hands over to a chained process
  (`arinsal_code:spawn`). With the wiring merged it goes straight on.
- `ns_main` registers `init` in the namespace's name table and answers the init protocol
  (get_argument/get_arguments/get_plain_arguments/get_status/script_id/notify_when_started/stop).
  Arguments are root's `root`, `bindir`, `progname`, `home`. `{stop, _}` exits init, which the
  manager's watcher sees as the project's exit.
- Like OTP's init, the boot runs in a second (linked) process so `init` can answer the
  application controller while it starts; that process stays alive as the parent of the kernel
  processes. Steps:
  - `file_server:start_link()`: a per-namespace `file_server_2`. Root's would spawn the io server
    of every `file:open/2` in root, and an unexposed root io server cannot answer a namespace
    process (`file:consult` failed with `terminated`).
  - load the plan modules: read with `file:read_file`, skip a module the chain resolves to an
    instance with the same md5 (`M:module_info(md5)` vs `beam_lib:md5/1`), `prepare_loading`,
    `finish_loading` in batches of 64. Protocol consolidations load into the namespace domain.
  - `os:putenv` of the project env.
  - `logger_server:start_link()` (registered `logger`, `logger` ETS table per namespace).
  - `application_controller:start(KernelApp)` where KernelApp is kernel's `.app` with
    `{mod, {arinsal_ns_kernel, []}}`. Starting `kernel` then runs `logger:internal_init_logger/0`,
    a `kernel_sup` with `logger_sup` and an empty `kernel_safe_sup`, and
    `logger:add_handlers(kernel)`. Nothing else of kernel_sup runs in the namespace.
  - every app of the plan loaded from its own `.app` (the release ebins are not on root's code
    path; base apps fall back to code_server), plan env set with `{persistent, true}`, then
    `application:start(App, Type)` in plan order.

Elixir's Logger works in the namespace (its output reaches the project's group leader).

## Measurements (bench/rest, own release build at bca0289^1, before the latest merge)

From `ns_boot_e2e.sh` (manager node, `erlang:memory/0` 0.5 s after the deploy returns):

| | first project | second project |
|---|---|---|
| total | 35.9 MB | 5.3 MB |
| code | 25.0 MB (OTP/Elixir preloaded into the shared base + own domain) | 2.9 MB |
| processes | 0.3 MB (sampled before the heaps grew) | 3.7 MB |
| ets | 1.0 MB | 0.17 MB |

A direct driver (three namespaces in a row, `erlang:memory/0` right after `start/3`): first boot
4.4 s (most of it loading the shared base), later boots 314 to 374 ms, 399 processes per
namespace (Bandit's acceptor pool is most of them), per project about 11.6 MB total of which
9.4 MB code and 2.2 to 4.7 MB process heaps. The code figure in the driver is higher than in the
e2e run; the e2e manager had already loaded more of the shared modules. Not investigated.

## After merging ns ports, pterm/env per ns, code-chain wiring (head of this branch)

- Preloaded modules are dropped from the plan (some, like `erts_internal`, are root only even for
  `module_info`); a module whose `module_info` is `notsup` (`erl_ddll`, classified root only by
  module) is treated as present in the base.
- persistent_term is per namespace, but code_server, erl_prim_loader, prim_socket and
  erl_features publish state there that their client code reads in the caller. The boot copies
  root's terms into the namespace (all except Logger's `logger_config`/`logger_olp`/`logger_proxy`
  keys). A chain-aware root fallback for these keys in the runtime would be cleaner.
- `logger_proxy` is not started in a namespace (it calls `system_flag(system_logger, ...)`,
  root only); the namespace's `logger_sup` runs only the handler watcher.
- `arinsal_ns_kernel` is loaded into the base before the spawn (a namespace process cannot make
  code_server load from root's path).
- `inet_gethost_native` is exposed with the other root services.
- e2e on the merged build: PASS, 398 processes per namespace, second project +3.3 MB total
  (code +2.9 MB, ets +0.17 MB; process heaps sampled early). One earlier run had the probe stop
  updating after the first deploy (no crash report); not reproduced, the probe now writes
  errors to `probe.txt.err`.

## Gaps

- `code:priv_dir/1`, `code:lib_dir/1` answer with root's view; release `priv` dirs are unknown
  to code_server.
- Runtime-generated logger events (crash reports from the VM) still go to root's `logger`.
- `init:stop/0` inside a namespace stops the namespace's init only; the manager reports the
  project's exit but does not destroy the namespace by itself.
- Config providers (`runtime.exs`) and `vm.args` are not applied (boot plan scope).
- `-on_load` modules of the release that are not identical to root's are refused by the domain
  loader (none in bench/rest; crypto is preloaded into the base).

## Run

```
export PATH=/Users/sts/dev/sq/arinsal-prs/bin:/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:$PATH
CARGO_TARGET_DIR=/Users/sts/dev/sq/arinsal-prs/target-mt-boot cargo build --release -p arinsal-cli
ln -sf /Users/sts/dev/sq/arinsal-prs/target-mt-boot/release/arinsal /Users/sts/dev/sq/arinsal-prs/mt-shim-boot/erl
poc/multitenancy/tests/ns_boot_e2e.sh            # REST_RELEASE=<built release> skips the stock build
```

# Stream cloud: manager (`packages/arinsal_cloud`)

## State

Done (chunks 1 to 3): app/supervisor, `arinsal_cloud_backend` behaviour with selection, the fake
backend, the namespace backend (against the merged natives; `arinsal_ns_boot` is still the
placeholder), the boot plan, the project registry (deploy, start, stop, delete, list, get, logs),
the per-project log collector, the admin HTTP API, port allocation, the Mix tasks, the
`arinsal-cloud` launcher and the e2e script.

Not yet: idle stop, the same-node fake mode, a real `arinsal_ns_boot:start/3` (other stream).
When it lands, replace `src/arinsal_ns_boot.erl` and drop `implemented/0` (or return `true`):
`backend => auto` then selects the namespace backend by itself.

## Layout

- `packages/arinsal_cloud`: Mix project with Erlang sources in `src/` (same packaging idea as
  `packages/arinsal`). `mix compile` builds it; the app depends only on kernel/stdlib (Mix adds
  `elixir` to the app file, so the node needs Elixir's ebin on the path).
- `arinsal_cloud_projects`: registry keyed by `{Tenant, Project}`. States so far: `starting`,
  `running`, `failed`. Deploy runs in a worker; a second deploy of a project that is starting
  answers 409. Redeploy stops the old copy only after the new tarball is verified, keeps the port
  when it is still free, and removes other version directories. Names must match
  `[A-Za-z0-9][A-Za-z0-9_-]{0,62}`; tar entries with `..` or absolute paths are rejected.
- `arinsal_cloud_fake`: every project is an OS process, `erl -boot releases/<vsn>/start
  -boot_var RELEASE_LIB <dir>/lib -config sys` with the host's `erl` (so Arinsal when Arinsal's
  `erl` is first on PATH). Env passed: `PORT`, `RT_PORT` and `project_env`. No isolation beyond
  the OS process. Its stdout and stderr go to the project's log collector.
- `arinsal_cloud_log`: one process per project, started under `arinsal_cloud_log_sup` when the
  project is first seen and kept until delete (stop/start/redeploy keep appending). It is a group
  leader (io protocol: put_chars in all variants, input answers `eof`), keeps the last
  `log_lines` (default 1000) complete lines in a ring buffer with sequence numbers and appends
  everything to `<data_dir>/<tenant>/<project>/out.log` (no rotation). `write/2` takes raw bytes
  (the fake backend uses it for stdout). The manager adds `[manager] ...` lines for start and
  stop. Group leader use is `{group_leader, Log}` on spawn; the ns backend will call
  `arinsal_ns:expose(Log)`.
- `arinsal_cloud_http`: `gen_tcp` with `{packet, http_bin}`, loopback only, no auth. Handles
  `Expect: 100-continue`, body limit 512 MiB (`max_body_bytes`). Endpoints:
  `GET /projects`, `GET|PUT|DELETE /projects/:t/:p`, `POST /projects/:t/:p/stop|start`,
  `GET /projects/:t/:p/logs?n=100[&since=Seq][&format=text]` (JSON `{lines, next}`; pass `next` as
  `since` to follow). States: stopped, starting, running, stopping, failed. A failed deploy keeps
  its record (state `failed`, `error`) until deleted. Operations on a project that is starting or
  stopping answer 409.
- Release shape: `mix release` output with only `lib/` and `releases/` tarred
  (`tar -C <release> -czf x.tar.gz lib releases`). The boot script's `$ROOT` entries (kernel,
  stdlib, ...) resolve to the host runtime, `$RELEASE_LIB` entries to the release.

## Run

```sh
export PATH=/Users/sts/dev/sq/arinsal-prs/mt-shim:/opt/homebrew/opt/elixir/bin:$PATH
export ERL_ROOTDIR=/opt/homebrew/opt/erlang@29/lib/erlang    # needed, see gaps
packages/arinsal_cloud/bin/arinsal-cloud --admin 127.0.0.1:7000 --data-dir /tmp/cloud-data
cd poc/multitenancy/bench/rest && mix arinsal.deploy --tenant acme --project shop   # stock OTP, see gaps
mix arinsal.list
```

App env (also settable with `-arinsal_cloud Key Value`): `admin_port` (7000; 0 = any),
`data_dir`, `ready_timeout_ms` (30000; 0 skips waiting for the project's port), `project_env`,
`erl` (path of the executable the fake backend runs), `backend` (`auto` or a module).

## Boot plan, namespace backend, backend selection

- `arinsal_cloud_boot:boot_plan(ReleaseDir)` returns `{ok, #{release, modules, apps, env, ebins}}`
  from `releases/<vsn>/start.boot` (falls back to `start.script`). `modules` are the
  `{Module, BeamPath}` pairs the script would `primLoad`, resolved the way the script resolves
  them: `$ROOT` entries (kernel, stdlib, compiler, sasl, crypto, ...) come from the host runtime's
  OTP root, `$RELEASE_LIB` entries from the release, the consolidated-protocol directory first.
  Base apps are included (the runtime dedups). `apps` is the `start_boot` order with name, vsn and
  type; `env` is `releases/<vsn>/sys.config`; `ebins` the ordered existing code path. Out of scope:
  `runtime.exs` and other config providers, `vm.args`. Module atoms are created from tenant-supplied
  beam names (atom table DoS, a known PoC gap).
- `arinsal_cloud_ns` (backend): `boot_plan`, `arinsal_ns:create/3` (opts from app env `ns_limits`),
  `arinsal_ns:expose(Log)`, then `arinsal_ns_boot:start(Ns, Plan, #{group_leader => Log, os_env => Env})`.
  A watcher process monitors the returned pid and reports `{project_exit, ...}`. `stop` calls
  `arinsal_ns:destroy/1`. `expose/1`, `destroy/1` and `info/1` were not merged yet when this
  was written; each is called under `try ... catch error:undef`, so the backend works before they
  land (destroy falls back to killing the boot process; the log collector is unreachable from the
  namespace until `expose` exists, so namespace output is not captured yet). If the boot module raises,
  the namespace is destroyed again and the error is `{boot_failed, {Class, Reason}}`.
  `PORT`/`RT_PORT` reach the boot as `os_env`; the OS environment is node-wide, so the real boot
  must serve it per namespace.
- `arinsal_ns_boot` is a stub: `start/3` raises `not_implemented`, `implemented/0` returns `false`.
- Selection (`arinsal_cloud_backend:select/0`, app env `backend`): `fake`, `ns`, `auto` (default)
  or a module. `auto` picks the namespace backend only when the natives exist and the boot module is
  not the stub (`arinsal_cloud_ns:usable/0`); today that means fake. `ns` with a stub boot fails
  each deploy with `boot_failed ... not_implemented` and leaves the project `failed` (checked on a
  build with the natives: `arinsal-cloud --backend ns`).
- Natives probe: `erlang:function_exported(arinsal_ns, create, 3)` is `false` on Arinsal even
  though the calls work (the module `arinsal_ns` has no code, `code:ensure_loaded` returns
  `{error, nofile}`), so `arinsal_cloud_ns:natives_available/0` calls `arinsal_ns:'of'(self())` and
  treats `undef` as "absent".

## Launcher

`packages/arinsal_cloud/bin/arinsal-cloud [--admin [127.0.0.1:]PORT] [--data-dir DIR]
[--backend fake|ns|auto] [-- ERL_ARGS...]` compiles the package if needed and `exec`s the first
`erl` on PATH with the manager (`-s arinsal_cloud`); with Arinsal's shim and `ERL_ROOTDIR` first it
is `arinsal cloud --admin 127.0.0.1:7000`. A `cloud` subcommand in `crates/cli` was not added: it
would need the package's ebin and Elixir's ebin paths, which the launcher already finds. Extra
settings go after `--`, e.g. `-- -arinsal_cloud project_env '[{"K","v"}]'`.

## Mix tasks (`packages/arinsal`)

`mix arinsal.deploy|list|stop|start|delete|logs`, all with `--url` (default
`http://127.0.0.1:7000`) and, except `list`, `--tenant` (required) and `--project` (default: the
Mix app name). `deploy` runs `MIX_ENV=prod mix release --overwrite --path <tmp>` with whatever
`mix`/`erl` come first on PATH, drops `releases/COOKIE`, tars `lib/` and `releases/` and PUTs it
(`--release NAME` for projects with several releases). `logs` takes `-n` and `--tail`. The client
is `Arinsal.Cloud` (`:httpc`, `JSON`); `:inets`, `:ssl` and `:public_key` were added to the
package's `extra_applications`. `bench/rest` and `bench/phxn` got `{:arinsal, path: ..., only: :dev,
runtime: false}` so `mix arinsal.deploy` works from them. The existing `mix arinsal` task is
unchanged.

## Tests

- `poc/multitenancy/tests/cloud_fake_e2e.sh` (about 1.5 minutes): builds the manager, copies
  `bench/rest` to a temp dir, starts the manager on Arinsal (projects print a marker through
  `ERL_AFLAGS`), then through the Mix tasks: deploys acme/shop and globex/shop, curls both
  `/t/1/items/1`, lists, reads logs (manager line, project stdout, `out.log`), stops acme (globex
  untouched), starts it (same port), redeploys it, checks 400/404 paths, deletes everything and
  checks that no process or file is left. `list/stop/start/logs/delete` run on Arinsal from
  `packages/arinsal`; `deploy` (compiles bench/rest) runs on stock OTP. `KEEP=1` keeps the temp
  dir, `ADMIN_PORT` changes the port.
- `cd packages/arinsal_cloud && mix test` (Arinsal first on PATH): 34 EUnit tests through an
  ExUnit wrapper (32 on a runtime without the natives, where the namespace tests skip): router,
  JSON conversion, name validation, the io protocol of the log collector (through `group_leader`),
  deploy/list/details/logs/stop/start/delete/redeploy/error paths over a real socket with a stub
  backend, boot plan against synthetic releases and against a real `bench/rest` release (the
  wrapper builds it once with stock OTP into `_build/rest_release`; delete it to rebuild), and
  the namespace backend and registry with `arinsal_cloud_test_boot` standing in for the boot (needs
  a build with `arinsal_ns`; `mt-shim-cloud` was built from this branch after merging
  `poc/multitenancy`).

## Arinsal gaps found (not fixed here)

1. `erl` from `mt-shim` fails with `arinsal: No such file or directory (os error 2)` unless
   `ERL_ROOTDIR` is set; it cannot infer the OTP root from the symlinked name.
2. Compiling `hpax` on Arinsal fails. A binary pattern in a module-body anonymous function never
   matches:

   ```elixir
   defmodule T2 do
     f = fn line ->
       case line do
         <<?a, rest::binary>> -> {:m, rest}
         _ -> {:other, line}
       end
     end
     IO.inspect(f.("abc"))   # prints {:other, "abc"}; stock OTP prints {:m, "bc"}
   end
   ```

   The same `case` inside a `def` works, and `erl_eval` of the same pattern works. Symptom in
   `mix compile`: `MatchError ... ["'", "'", "32", "010100", "14", "6"]` at `lib/hpax/huffman.ex:13`.
   Reproduce with `elixirc t2.ex`. The e2e script therefore builds the release with stock OTP;
   only the manager and the projects run on Arinsal.
3. `mix deps.get` on Arinsal wrote `~/.hex/cache.ets` in a form stock OTP cannot read
   (`:ets.file2tab` -> `binary_to_term` "invalid external representation of a term").
   The file was moved to `~/.hex/cache.ets.written-by-arinsal-corrupt`; stock Hex rebuilt it.
   Do not run `mix deps.get` on Arinsal against the real `~/.hex`.
4. `File.cp/2`, `File.cp_r/2` return `{:error, :badarg}` after copying the file's data (the copy
   exists), so `File.cp_r!` raises `File.CopyError ... bad argument`. `:file.copy/2`,
   `:file.change_mode/2` and `:file.read_file_info/1` work alone; the failing call inside Elixir's
   `File.cp` was not isolated (tracing with `:dbg` hung the node). The test wrapper uses `cp -R`.
5. `xref` cannot start on Arinsal: `xref_base` -> `sofs:specification` -> `erlang:is_builtin/3`
   raises `badarg` for `'$M_EXPR'`/`'$F_EXPR'`/`-1`. No cross-reference check was possible, so
   undefined calls are only caught by the tests.
6. Works on Arinsal and worth knowing: `ERL_AFLAGS` is honored by the shim (`-s erlang display x`
   printed `[x]` on the project's stdout), port stdout capture, `kill`-based stop of the child.

## Known limits

- Idle stop is not implemented. Idle detection and traffic-based cold start need a proxy or probe; the manager does not see
  requests to the project's port.
- The manager does not restore projects after a restart of the manager.
- Release modules' atoms come from tenant uploads (relevant once `boot_plan` lands).

# Stream cloud: manager (`packages/arinsal_cloud`)

## State

Done (chunks 1 and 2): app/supervisor, `arinsal_cloud_backend` behaviour, the fake backend, the
project registry (deploy, start, stop, delete, list, get, logs), the per-project log collector,
the admin HTTP API, port allocation, the Mix tasks and the e2e script. Everything is tested on
Arinsal (the e2e builds with stock OTP, see gaps).

Not yet: idle stop, `arinsal_cloud_boot:boot_plan/1`, the `arinsal_ns` backend and
`arinsal_ns_boot:start/3` stub, the same-node fake mode, `arinsal cloud` wiring. A draft of the
boot plan and ns backend exists in the author's scratchpad (`arinsal_cloud_full`, stock ERTS only).

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
cd packages/arinsal_cloud && mix compile
erl -noshell -pa _build/dev/lib/arinsal_cloud/ebin -pa "$(elixir -e 'IO.puts(:code.lib_dir(:elixir))')/ebin" \
  -s arinsal_cloud -arinsal_cloud admin_port 7000 -arinsal_cloud data_dir '"/tmp/cloud-data"'
curl -X PUT --data-binary @release.tar.gz 127.0.0.1:7000/projects/acme/shop
curl 127.0.0.1:7000/projects
```

App env (also settable with `-arinsal_cloud Key Value`): `admin_port` (7000; 0 = any),
`data_dir`, `ready_timeout_ms` (30000; 0 skips waiting for the project's port), `project_env`,
`erl` (path of the executable the fake backend runs), `backend` (`auto` or a module).

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
- `cd packages/arinsal_cloud && mix test` (Arinsal first on PATH): 22 EUnit tests through an
  ExUnit wrapper: router, JSON conversion, name validation, the io protocol of the log collector
  (through `group_leader`), and deploy/list/details/logs/stop/start/delete/redeploy/error paths
  over a real socket with a stub backend.

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
4. `xref` cannot start on Arinsal: `xref_base` -> `sofs:specification` -> `erlang:is_builtin/3`
   raises `badarg` for `'$M_EXPR'`/`'$F_EXPR'`/`-1`. No cross-reference check was possible, so
   undefined calls are only caught by the tests.
5. Works on Arinsal and worth knowing: `ERL_AFLAGS` is honored by the shim (`-s erlang display x`
   printed `[x]` on the project's stdout), port stdout capture, `kill`-based stop of the child.

## Known limits

- Idle stop is not implemented. Idle detection and traffic-based cold start need a proxy or probe; the manager does not see
  requests to the project's port.
- The manager does not restore projects after a restart of the manager.
- Release modules' atoms come from tenant uploads (relevant once `boot_plan` lands).

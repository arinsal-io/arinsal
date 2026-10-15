# Stream cloud: manager (`packages/arinsal_cloud`)

## State of this chunk

Done: app/supervisor, `arinsal_cloud_backend` behaviour, the fake backend, the project registry
(deploy and list only), the admin HTTP server (`PUT /projects/:t/:p`, `GET /projects`), port
allocation and the e2e script. Everything is tested on Arinsal.

Not yet (follow-up chunks): log collector / group leader, stop, start, delete, details and logs
endpoints, idle stop, `arinsal_cloud_boot:boot_plan/1`, the `arinsal_ns` backend and the
`arinsal_ns_boot:start/3` stub, the same-node fake mode, the Mix tasks, `arinsal cloud` wiring.
A draft of most of these exists in the author's scratchpad (`arinsal_cloud_full`, tested on stock
ERTS only) and gets re-landed one piece at a time.

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
  `erl` is first on PATH). Env passed: `PORT` and `RT_PORT`. No isolation beyond the OS process;
  stdout is dropped for now.
- `arinsal_cloud_http`: `gen_tcp` with `{packet, http_bin}`, loopback only, no auth. Handles
  `Expect: 100-continue`, body limit 512 MiB (`max_body_bytes`).
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

## Tests

- `poc/multitenancy/tests/cloud_fake_e2e.sh`: builds `bench/rest` (in a temp copy, with stock OTP),
  starts the manager on Arinsal, deploys it as `acme/shop` and `globex/shop`, curls
  `/t/1/items/1` on both ports, lists, redeploys acme (port kept, globex untouched), sends a
  garbage tarball and a bad name (400). `KEEP=1` keeps the temp dir, `ADMIN_PORT` changes the port.
- `cd packages/arinsal_cloud && mix test` (with Arinsal first on PATH): 16 EUnit tests through an
  ExUnit wrapper: router, JSON conversion, name validation, and deploy/list/redeploy/error
  paths over a real socket with a stub backend.

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

## Known limits

- Idle detection and traffic-based cold start need a proxy or probe; the manager does not see
  requests to the project's port.
- The manager does not restore projects after a restart of the manager.
- Release modules' atoms come from tenant uploads (relevant once `boot_plan` lands).

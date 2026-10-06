# ArinsalDemo

A small Elixir OTP application used to compare realistic workloads on erts and Arinsal. It targets Elixir 1.20.4 / Erlang OTP 29.1.1.

Run Mix commands through the local Arinsal integration to build the runtime and
launch a child Mix process with Arinsal selected:

```sh
mix arinsal compile
mix arinsal test
mix arinsal run -e 'IO.inspect(ArinsalDemo.Pure.module_info(:exports))'
```

The `arinsal` dependency is a path dependency to `../../packages/arinsal`.

Run its compatibility checks with `mix test`. Run all quick erts suites from the repository root with:

```sh
bench/elixir/compare.sh --suite all --runtime erts --quick
```

For full-duration benchmarks, omit `--quick`. Results are written to ignored `bench/out/` files. Once `target/release/arinsal-erl-shim/erl` exists, pass `--runtime arinsal` to run against it and load the latest erts results for side-by-side comparison. The `arinsal-erl-shim` directory is expected to contain the `erl` wrapper that selects Arinsal; Elixir's `bin/elixir` resolves `erl` through `PATH`.

`make compare` runs every suite three times on the same `MIX_ENV=bench` beams: `erts`, `arinsal_cold` (warm-up 0), and `arinsal_warm`. Arinsal runs go through the release shim under `timeout`. Before timing, each scenario is evaluated once on both runtimes and the command fails if the return values differ. A Markdown table is printed and written to `bench/out/compare-<date>-<gitsha>.md` (that directory is git-ignored). Memory and reduction counts are omitted from the table.

```sh
make compare                 # all suites, full benchee times
make compare QUICK=1         # shorter times
make compare SUITE=maps      # one suite
make compare BASELINE=bench/out/compare-YYYY-MM-DD-<sha>.md
```

`BASELINE` may be a previous Markdown table or a directory of `*-arinsal_warm.json` files. It adds a `vs baseline` column for the Arinsal warm run. `SUITE=maps` (or any other suite name) limits the run. The three runtimes always run one after another.

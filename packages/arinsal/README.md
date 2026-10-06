# Arinsal

The `arinsal` Mix package lets Elixir projects run Mix commands using the
Arinsal runtime. This package is currently intended for path-dependency use
from inside the Arinsal repository; it builds the runtime from the repository's
Cargo workspace.

Add it to a Mix project in this repository:

```elixir
{:arinsal, path: "../../packages/arinsal"}
```

Then prefix a Mix command with `mix arinsal`:

```sh
mix arinsal compile
mix arinsal test
mix arinsal run -e 'IO.puts(:hello)'
```

The task builds the release runtime, creates `target/release/arinsal-erl-shim/erl`,
and runs the requested Mix command with that shim first on `PATH`. Set
`ARINSAL_PROFILE=debug` to use the faster debug build.

Requirements: the repository's Rust toolchain, Cargo, and an installed Erlang /
Elixir toolchain for the initial Mix invocation.

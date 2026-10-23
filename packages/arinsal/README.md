# Arinsal Mix package

This package provides the `mix arinsal` task for projects that use Arinsal's source checkout. The task builds the CLI from the Arinsal Cargo workspace, creates an `erl` shim, and runs the requested Mix command with that shim first on `PATH`.

```sh
mix arinsal compile
mix arinsal test
mix arinsal run -e 'IO.puts(:hello)'
```

Set `ARINSAL_PROFILE=debug` for a faster debug build. The standalone [arinsal-demo](https://github.com/arinsal-io/arinsal-demo) project installs a versioned runtime through the `arinsal-io/asdf-arinsal` plugin and does not depend on this in-tree Mix package.

Requirements: the Arinsal repository checkout, its Rust toolchain and Cargo, and an installed Erlang / Elixir toolchain for the initial Mix invocation.

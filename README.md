# Arinsal

Arinsal is an alternative BEAM runtime for Erlang and Elixir. It is
written in Rust and is being developed as an independent implementation of the
runtime that runs BEAM bytecode and powers the Erlang ecosystem.

The project is experimental and under active development. Its current
compatibility target is Erlang/OTP 29.1.1; support is still incomplete, so this
is not yet a drop-in replacement for the Erlang Run-Time System (ERTS).

## Platforms

Supported:
- macOS on Apple Silicon (arm64)
- Linux on arm64 (aarch64)

Not supported yet: x86-64 (any OS), Windows.

## The name

ERTS is the Erlang Run-Time System. Erts is also a village in Andorra,
right next to Arinsal. The village of Arinsal is bigger and sits higher up the
mountain—so this runtime takes its name from the neighbor next door.

## What is in the repository

Arinsal includes a BEAM virtual machine and bytecode loader, runtime support
such as terms, processes, scheduling, and ETS, plus a command-line executable.
The workspace also contains compatibility tests, examples, and benchmarks
comparing Arinsal with ERTS.

## Build

Requires the Rust toolchain specified in [`rust-toolchain.toml`](rust-toolchain.toml).

```sh
cargo build -p arinsal-cli
```

The executable is named `arinsal`. For example, to print its version:

```sh
cargo run -p arinsal-cli -- --version
```

See [`arinsal-io/arinsal-demo`](https://github.com/arinsal-io/arinsal-demo) for an Elixir
application used to compare workloads on Arinsal and ERTS.

## Tests

The argument-parser differential tests use the installed OTP emulator as a
reference. They resolve the OTP root from `ARINSAL_OTP_ROOT` or from `erl` on
`PATH`. They launch `erlexec` directly and set `PROGNAME=erl`. This avoids
changes in a package wrapper's script name from changing Erlang launch
arguments.

Run the argument-parser differential tests with:

```sh
cargo nextest run -p arinsal-args
```

Set `ARINSAL_OTP_ROOT` to the directory reported by `code:root_dir()` to select
an OTP installation explicitly.

## License

Arinsal is licensed under Apache-2.0. See [LICENSE](LICENSE).

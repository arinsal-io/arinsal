# Benchmarks

This directory is the home for the repository's benchmark programs and runners.

- `kernels/bench.erl`, `vs-go/bench.go`, and `vs-rust/` contain the shared cross-language kernels.
- `prims/` measures process and messaging primitives.
- `http/` runs the HTTP comparison services in `examples/http/`.
- `mnesia/` and `nif/` contain focused subsystem probes.
- `elixir/` points to the standalone demo and its Benchee suites.
- `baseline/` contains the current checked-in kernel baseline; `out/` and `history/` are generated and ignored.

Run the kernel comparison with `python3 tools/bench/compare.py --quick` or its `tools/bench/run.sh` wrapper. Details and measurement rules are in [`docs/bench/README.md`](../../docs/bench/README.md).

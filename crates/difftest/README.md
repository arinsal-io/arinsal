# arinsal-difftest

`RefErl` starts OTP 29, compiles `tools/difftest/difftest_server.erl` on first use, and matches concurrent ETF responses by request ID. `Vm` is the adapter for an in-process interpreter. `CallResult::TransportError` is a harness failure and never compares equal to a VM result.

```rust
use arinsal_difftest::{compare, CompareMode, RefErl, Vm};
use arinsal_etf::OwnedTerm;

let reference = RefErl::start()?;
let expected = reference.call("erlang", "abs", &[OwnedTerm::Int(-5)]);
let actual = my_vm.call("erlang", "abs", &[OwnedTerm::Int(-5)]);
compare(&expected, &actual, CompareMode::Exact)?;
```

For tests, `difftest!(name, "module", "function", [args...])` creates a reference self-check. The five-argument form accepts two `&mut Vm` adapters. `gens::diff_prop(left, right, module, function, gens::for_spec(&spec), count)` runs generated cases. `suites::stage1()` holds function registrations, generator labels, comparison mode, and deterministic seed arguments.

Run `tools/difftest/smoke.sh` for a direct framed-protocol check. Run `cargo run -p difftest-runner --bin difftest -- --vm erl --suite stage1` for the reference self-check, or use `--vm arinsal` to compare the interpreter with OTP. The runner accepts a module name, such as `--suite lists`, to select one section; `--show-mismatches N` prints the first N differences.

Until S0.5 implements `arinsal-etf`, the default build uses a private bootstrap ETF codec covering the protocol and common data terms. It returns a transport error for unsupported term kinds, including local funs and opaque `Other` terms. After S0.5 lands, run `cargo test -p arinsal-difftest --features full-etf -- --ignored` and `cargo run -p difftest-runner --features full-etf --bin difftest -- --vm erl --suite stage1`. Then remove the ignored markers and select the full codec by default.

The server starts workers for calls and eval requests; it limits active calls with `DIFFTEST_MAX_CALLS` (default 32), queues excess requests, and starts each call's timeout when its worker starts. `call_opts` accepts timeout, output capture, reduction count, heap size, optional line stripping in stack frames, and `term_to_binary/2` options. The local-only reference process uses an Erlang port on stdin/stdout. OTP's logger is set to `emergency` on startup because its fd-control warning otherwise corrupts framed stdout.

Map traversal order can differ between two OTP nodes. Cases asserting ordered map traversals or exact map ETF bytes use one-entry maps; other map results use order-insensitive term comparison.

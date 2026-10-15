# NOTES-binmatch

## Repro

```elixir
defmodule T2 do
  f = fn line ->
    case line do
      <<?a, rest::binary>> -> {:m, rest}
      _ -> {:other, line}
    end
  end
  IO.inspect(f.("abc"))
end
```

Arinsal printed `{:other, "abc"}`, stock OTP prints `{:m, "bc"}`. `mix compile` of hpax failed with a
MatchError in `lib/hpax/huffman.ex` for the same reason.

## Narrowing

- Plain `erl -eval` funs, erlc-compiled modules and `compile:file` on Arinsal all work.
- Module-body code is compiled by Elixir through `compile:noenv_forms` from Core Erlang with
  `no_ssa_opt` and `no_bool_opt`. Without SSA optimization the compiler emits the old generic
  `bs_start_match3` / `bs_get_integer2` / `bs_get_binary2` instructions instead of `bs_match`.
- A beam compiled by stock OTP with those options fails on Arinsal; a beam compiled by Arinsal with
  the same options runs fine on stock OTP. So the fault is in the VM, not in the compiler.
- Minimal failing instruction: `{test,bs_get_binary2,{f,L},Live,[Ctx,{atom,all},8,Flags],Dst}`.
  `<<X:8, R/bitstring>> = Bin` in a module compiled with `no_ssa_opt` is enough
  (`bs_get_binary2` with size `all`, unit 1, also failed; this is what the test's `shifted/2` helper hit).

## Root cause

`bs_get_binary2` with the size atom `all` is rewritten by the ops table to `i_bs_get_binary_all2`.
`i_bs_get_binary_all2` is not ported in beamjit (`PORTED_OPS` in `crates/beamjit/src/lib.rs`), so any function
containing it falls back to the interpreter. The interpreter arm for `Opcode::BsGetBinary2`
(`crates/vm/src/bits.rs`, `BsGetInteger2 | BsGetBinary2 | BsGetFloat2`) computed the field width with
`field_bits`, which reads the size operand as a small integer. The atom `all` is not one, so the
instruction always took its fail label.

## Fix

New arm in `crates/vm/src/bits.rs` before the generic one: when the size operand of `bs_get_binary2` is
the atom `all`, check that the remaining bits are a multiple of the unit and build the tail sub-binary
(`get_tail_unit`), with the same GC handling (`allocated`, `live`) as the other arms. This matches the
BeamAsm lowering of `i_bs_get_binary_all2` (`ensure_at_least 0 Unit` followed by `get_tail Live Unit Dst`),
including that the match context position is not advanced.

## Test

`crates/vm/tests/bs_get_binary_all_differential.rs` compiles a module with `no_ssa_opt, no_bool_opt`
on the reference node, runs binary, bitstring, literal-source and two-field patterns over aligned,
sub-binary, every bit offset and trailing-bit inputs on both VMs, and compares results.

```
cargo test --release -p arinsal-vm --test bs_get_binary_all_differential
```

Fails before the fix (badmatch in `shifted/2`), passes after. The reference `erl` here is OTP 29.1, so
the test does not assert the exact `29.1.1` patch version that other differential tests check.

## Verification

- `elixirc t2.ex` prints `{:m, "bc"}`.
- A fresh copy of `poc/multitenancy/bench/rest` (deps fetched with stock OTP) compiles hpax, bandit and rt
  with `mix compile` on Arinsal.

## Gaps

- `i_bs_get_binary_all2` is still not JIT-compiled; functions using it run in the interpreter.
- None open for the rebar3 issue, see below.

## Follow-up: open_port badarg for rebar3 deps

Symptom: `:erlang.open_port({:spawn_executable, ".../rebar3"}, [..., {:cd, dir}, ...])` raised `badarg`
when Mix compiled telemetry and telemetry_poller.

Reduction: the rebar3 escript itself runs fine. Any `{cd, Dir}` option failed, even with `/bin/echo`;
`args`, `env`, `use_stdio`, `stderr_to_stdout`, `hide`, `binary`, `exit_status` were all fine.

Root cause: a port with `cd` is started through the `--port-exec-config` helper, which is the `arinsal`
binary located by `port_exec_helper` in `crates/vm/src/port.rs`. It used `std::env::current_exe()`, which on
macOS is the invoked path and not the symlink target. When the VM runs as a symlink named `erl` (the shim
setup) in a directory with no sibling `arinsal`, the lookup found nothing and `open_port` returned `badarg`.

Fix: canonicalize the executable path before looking for the helper.

Test: `crates/cli/tests/port_cd_symlink.rs` (`ns_port_cd_works_through_symlinked_binary`) runs a symlink
named `erl` pointing at the built binary and compares `open_port` with `{cd, "/"}` against reference `erl`.
Fails before, passes after.

Verified: fresh copy of bench/rest (deps from stock OTP, `_build` cleared, fresh MIX_HOME) builds
mime, jason, plug_crypto, hpax, telemetry, telemetry_poller, thousand_island, plug, websock, bandit and rt
with `mix compile` on Arinsal through a shim holding only the `erl` symlink.

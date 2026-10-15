# NOTES: compat stream

Two Arinsal compatibility bugs found while running Mix tooling. Namespace 0 behavior is unchanged
beyond the two fixes.

## 1. `erlang:is_builtin/3` with a negative arity
- Cause: the native raised badarg for a negative arity. ERTS accepts any small integer and returns
  `false` when no BIF has that arity. `xref:start(s)` failed because `xref_base:make_builtins/1`
  runs `sofs:specification/2` over the `{M,F,-1}` placeholder entries from xref's predefined
  function set.
- Fix: `crates/bifs/src/pure.rs`, dropped the `arity < 0` check. Non-atom module/name and non-small
  arity (bignums) still raise badarg, as in ERTS. Arity above 255 already returned `false`.
- Test: `is_builtin_out_of_range_arity_matches_otp` in `crates/bifs/tests/differential.rs`
  (differential against reference erl for arities -1, -100, 0, 255, 256, 100000). Fails before, passes after.
- Verified: the three-call one-liner prints `[true,false,true]` on both; `xref:start(s)`,
  `xref:add_directory/2` and `xref:analyze(s, undefined_function_calls | locals_not_used)` run on Arinsal.

## 2. `ets:tab2file/2` output unreadable by stock `ets:file2tab/1`
- Cause: the table header written by tab2file contains `{id, TableRef}`. Arinsal builds table
  handles as local references whose first id word is `0x45545329` ("ETS)"). ERTS rejects a
  reference of the local node whose first word is `>= 2^18`, so `binary_to_term` fails on the
  header chunk and `file2tab` returns `{error, badfile}`. The same applied to compiled match spec
  handles (`0x4554534d`).
- Fix: both tags are now below 2^18 (`TID_REF_TAG = 0x15329` in `crates/ets/src/lib.rs`,
  `PROGRAM_REF_TAG = 0x1534d` in `crates/ets/src/match_spec.rs`); `erts_debug.rs` uses the constant.
  Real references cannot collide in practice (their counters start high).
- Test: `crates/vm/tests/ets_tid_etf.rs` (`ets_tid_etf_matches_otp_29`, differential): the first id
  word of `term_to_binary` for a table handle and for a compiled match spec is below 2^18, the
  handle round-trips and stays usable. Fails before, passes after.
- Verified in a temp dir (never `~/.hex`): a set table with binaries, bit strings, maps, tuples,
  improper lists, bignums, floats, ASCII/UTF-8/wide atoms, funs, refs, pids and ports. Arinsal
  write to stock read, stock write to Arinsal read, and both same-engine reads all return `ok`
  with 23 objects (before the fix the first of those failed). The two files now differ only in
  the ids of the table ref, pid and port.
- `term_to_binary/1,2` compared byte for byte with ERTS for 37 terms (including 255-char and
  UTF-8 atoms, maps with 100 keys, tuples/lists of 300, bignums, -0.0) under options
  `[]`, `compressed`, `{compressed,9}`, `{minor_version,0|1}`, `deterministic`: all identical.
  Only the stack traces of the expected badarg for the invalid `{atom_utf8,false}` option differ.

## Gaps and side findings
- Arinsal's decoder still accepts a local reference with a first id word `>= 2^18` in
  NEWER_REFERENCE_EXT; ERTS rejects it for refs of its own node. Not changed (lenient, not the
  cause of the bug).
- `erlc` from a shim dir fails with `arinsal: unknown emulator flag +A0` (erlc passes `+A0`).
  Not fixed here.
- `cargo clippy -p arinsal-ets -p arinsal-bifs -- -D warnings` fails in `crates/alloc/src/raw.rs`
  (multiple unsafe operations per block, unrelated and pre-existing), so clippy could not be
  used on these crates.
- The existing `arinsal-ets` differential test `random_sequences_against_otp_29` failed once
  with the reference node killed and passed on rerun.

## Run
    export CARGO_TARGET_DIR=/Users/sts/dev/sq/arinsal-prs/target-mt-compat
    cargo test -p arinsal-bifs --test differential is_builtin
    cargo test -p arinsal-vm --test ets_tid_etf

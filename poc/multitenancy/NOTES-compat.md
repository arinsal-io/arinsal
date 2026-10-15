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

## 3. `+A0` and other attached emulator flag values
- Cause: erlexec passes `+A0` to the emulator as `-A0`; the emulator reads the value from the same
  token. Arinsal's parser only split attached values for some flags, so `erlc` (which runs
  `erl +A0`) failed with `unknown emulator flag +A0`.
- Fix: `crates/args/src/lib.rs` splits attached values for `+A +a +e +i +n +T +R +W +K` (the
  letters erlexec forwards). `+a` now validates its range like the emulator (16..8192).
- Tests: `flag_families_match_erl_boot_arguments` (new family with attached values) and
  `flag_family_rejections_match_erl` (`+A1025`, `+A-1`, `+Ax`, `+a1`, `+a 8193`, `+a16`) in
  `crates/args/tests/families.rs`; both differential against erlexec. Failed before the fix.
- Verified: `erlc m.erl` through the shim produces `m.beam` and the module loads.

## 4. Local references with a first id word of 2^18 or more
- ERTS rejects a NEWER_REFERENCE_EXT of its own node whose first word is `>= 2^18`; Arinsal
  decoded it. Both decoders (`crates/bifs/src/etf.rs`, `crates/etf/src/lib.rs`) now reject it for
  `nonode@nohost` creation 0, except the Arinsal magic reference shape `[lo, hi, 0xffffffff]`.
- Handle tags of the native NIFs (file, buffer, tty, zlib, socket lifecycle) were all above 2^18
  and are now below it, so they round-trip through the strict decoder and stock OTP.
- Tests: `binary_to_term_local_ref_first_word_limit_matches_otp` (differential, crates/bifs),
  `handle_reference_decodes_on_any_node` (crates/nif-file). The first failed before the fix.
- Open: magic references (`[lo, hi, 0xffffffff]`, ids from a counter) can exceed 2^18 after 262k
  allocations and stock OTP would reject them. Changing that wire shape touches the term,
  etf, ets, socket and binary crates, so it is left alone.

## 5. `File.cp/2` and `File.cp_r/2` returning `{:error, :badarg}`
- Cause: `file:write_file_info/2` raised badarg after the data was copied. The process had
  left a smaller live register count in `gc_live`; when the four-argument dirty NIF
  `set_time_nif` moved the process to a dirty scheduler, the switch-out saved only that many
  X registers, so the last argument (ctime) became `[]`. It needed a heap fragment adopted
  from an earlier dirty call (a successful `prim_file:open/2`), which forces a collection and
  makes the stale count matter.
- Fix: `trap_to_dirty_nif` in `crates/vm/src/native_helpers.rs` sets `gc_live` to the NIF
  arity before the trap.
- Test: `dirty_nif_arity_keeps_all_arguments` in `crates/vm/tests/dirty_nif_arity.rs` (runs the
  debug `arinsal` binary through a shim and compares with `erl`). Needs
  `ln -sfn $CARGO_TARGET_DIR <worktree>/target` and a built `target/debug/arinsal`. Failed
  before the fix (`{ok,{error,badarg},ok}`), passes after.
- Verified: `File.cp`, `File.exists?`, `File.cp_r` on Arinsal return `:ok` and `{:ok, [...]}`.

## 6. `dbg` tracing hangs the traced process
- Cause: `dbg`'s tracer suspends the traced process asynchronously on every `call` trace and
  resumes it after printing. With any trace active, `erlang:resume_process/1` took the slow path,
  which called `resume_process_light`; that function declines (`None`) while tracing is active,
  and the slow path turned the `None` into `badarg`. `dbg` catches it, so the suspend was never
  released and the traced process stayed `suspended` forever (here: the shell process, inside a
  `code_server:call`, with its reply already queued).
- Fix: `crates/vm/src/natives/proc.rs`, the slow path now runs the real body (`resume_core`) and
  the light variant only adds the "not while tracing" bail-out. `suspend_process` already did this.
- Test: `crates/vm/tests/resume_process_traced.rs` (`resume_process_while_tracing_matches_otp_29`,
  differential: suspend/resume status, `badarg` on a second resume, nested suspend counts). Failed
  before the fix (`badarg`).
- Verified with the one-liners from the report (`dbg:tpl` with `x`, `dbg:tp` with a match spec,
  `dbg:stop`, `dbg:stop_clear`, `dbg:ctp`): all finish and the output equals stock OTP. The
  `dbg:p(all, c)` variant also hangs on stock OTP (the tracer traces itself); not an Arinsal bug.

## Gaps and side findings
- `cargo clippy -p arinsal-ets -p arinsal-bifs -- -D warnings` fails in `crates/alloc/src/raw.rs`
  (multiple unsafe operations per block, unrelated and pre-existing), so clippy could not be
  used on these crates.
- The existing `arinsal-ets` differential test `random_sequences_against_otp_29` failed once
  with the reference node killed and passed on rerun.

## Run
    export CARGO_TARGET_DIR=/Users/sts/dev/sq/arinsal-prs/target-mt-compat
    cargo test -p arinsal-bifs --test differential is_builtin
    cargo test -p arinsal-vm --test ets_tid_etf

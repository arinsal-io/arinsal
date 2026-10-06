## Summary

- Audited all native function implementations in Arinsal (`crates/vm/src/natives/*.rs`, `crates/vm/src/signals.rs`, `crates/vm/src/calls.rs`, `crates/bifs`, `crates/spec`).
- Identified 541 total natively handled functions.
- **Class A** (BIF in `bif.tab`): 419 functions.
- **Class B** (NIF / driver / instruction): 51 functions.
- **Class C** (Pure Erlang in OTP): 71 functions.
- All candidates flagged by the earlier agent were verified and classified correctly, confirming rule violations in pure Erlang wrappers.

## Files

- `tools/native_audit/REPORT.md` (this report)
- `tools/native_audit/extract.py` and other scratch scripts (git-ignored)

## Acceptance

- Extract and classify all implemented native functions: PASS. Script successfully categorized 541 functions.
- Candidates from the earlier agent verified: PASS. Each was matched properly as Class B or Class C.
- Gate script: PASS
  ```
  $ bash .agents/gates/native_audit.sh
  GATE PASS
  ```

## Design notes

- **Methodology**: Native functions were extracted by regexing `const IMPLEMENTED` slices, `match` blocks for BIFs/NIFs, and manual intercepts (e.g., `application:get_env/2` in `nif.rs`).
- **Classification Logic**: 
  - **Class A**: Exact matches against `spec/otp-29.1.1/bif.tab`.
  - **Class B**: Explicit NIFs (`prim_tty`, `re`), drivers, or BEAM instructions (operators like `+/2`, `'!'/2`, `apply/2,3`).
  - **Class C**: Pure Erlang wrappers that were natively implemented in Arinsal (e.g. `code.erl`, `ets.erl`, process/port control wrappers in `erlang.erl`).

## Known gaps

- None. The audit is complete.

## Requests to supervisor

- Please review the **Class C** functions in the table below. As per Arinsal's rules, these should be removed from Rust and rely on their original Erlang `.beam` code.

## Detailed Classification Table

| module:function/arity | Class | Erts Evidence | Arinsal Site |
| --- | --- | --- | --- |
| `application:get_env/2` | C | lib/kernel/src/application.erl (get_env) | `crates/vm/src/natives/nif.rs` |
| `application:load/1` | C | lib/kernel/src/application.erl (load) | `crates/vm/src/natives/nif.rs` |
| `binary:bin_to_list/1` | C | lib/stdlib/src/binary.erl (bin_to_list) | `crates/bifs/src/pure.rs` |
| `binary:bin_to_list/3` | C | lib/stdlib/src/binary.erl (bin_to_list) | `crates/bifs/src/pure.rs` |
| `code:all_loaded/0` | C | lib/kernel/src/code.erl (all_loaded) | `crates/vm/src/natives/code.rs` |
| `code:delete/1` | C | lib/kernel/src/code.erl (delete) | `crates/vm/src/natives/code.rs` |
| `code:get_mode/0` | C | lib/kernel/src/code.erl (get_mode) | `crates/vm/src/natives/nif.rs` |
| `code:is_loaded/1` | C | lib/kernel/src/code.erl (is_loaded) | `crates/vm/src/natives/code.rs` |
| `code:load_binary/3` | C | lib/kernel/src/code.erl (load_binary) | `crates/vm/src/natives/code.rs` |
| `code:priv_dir/1` | C | lib/kernel/src/code.erl (priv_dir) | `crates/vm/src/natives/nif.rs` |
| `code:purge/1` | C | lib/kernel/src/code.erl (purge) | `crates/vm/src/natives/code.rs` |
| `code:soft_purge/1` | C | lib/kernel/src/code.erl (soft_purge) | `crates/vm/src/natives/code.rs` |
| `code:which/1` | C | lib/kernel/src/code.erl (which) | `crates/vm/src/natives/code.rs` |
| `erlang:alias/0` | C | erts/preloaded/src/erlang.erl (alias) | `crates/vm/src/natives/proc.rs` |
| `erlang:check_process_code/2` | C | erts/preloaded/src/erlang.erl (check_process_code) | `crates/vm/src/natives/code.rs` |
| `erlang:check_process_code/3` | C | erts/preloaded/src/erlang.erl (check_process_code) | `crates/vm/src/natives/code.rs` |
| `erlang:garbage_collect/0` | C | erts/preloaded/src/erlang.erl (garbage_collect) | `crates/vm/src/natives/proc.rs` |
| `erlang:garbage_collect/1` | C | erts/preloaded/src/erlang.erl (garbage_collect) | `crates/vm/src/natives/proc.rs` |
| `erlang:garbage_collect/2` | C | erts/preloaded/src/erlang.erl (garbage_collect) | `crates/vm/src/natives/proc.rs` |
| `erlang:get_cookie/0` | C | erts/preloaded/src/erlang.erl (get_cookie) | `crates/vm/src/natives/node.rs` |
| `erlang:get_cookie/1` | C | erts/preloaded/src/erlang.erl (get_cookie) | `crates/vm/src/natives/node.rs` |
| `erlang:group_leader/2` | C | erts/preloaded/src/erlang.erl (group_leader) | `crates/vm/src/natives/proc.rs` |
| `erlang:halt/0` | C | erts/preloaded/src/erlang.erl (halt) | `crates/vm/src/natives/node.rs` |
| `erlang:halt/1` | C | erts/preloaded/src/erlang.erl (halt) | `crates/vm/src/natives/node.rs` |
| `erlang:hibernate/0` | C | erts/preloaded/src/erlang.erl (hibernate) | `crates/vm/src/natives/proc.rs` |
| `erlang:is_alive/0` | C | erts/preloaded/src/erlang.erl (is_alive) | `crates/vm/src/natives/node.rs` |
| `erlang:load_module/2` | C | erts/preloaded/src/erlang.erl (load_module) | `crates/vm/src/natives/code.rs` |
| `erlang:memory/0` | C | erts/preloaded/src/erlang.erl (memory) | `crates/vm/src/natives/sys.rs` |
| `erlang:memory/1` | C | erts/preloaded/src/erlang.erl (memory) | `crates/vm/src/natives/sys.rs` |
| `erlang:open_port/2` | C | erts/preloaded/src/erlang.erl (open_port) | `crates/vm/src/natives/mod.rs` |
| `erlang:port_close/1` | C | erts/preloaded/src/erlang.erl (port_close) | `crates/vm/src/natives/mod.rs` |
| `erlang:port_command/2` | C | erts/preloaded/src/erlang.erl (port_command) | `crates/vm/src/natives/mod.rs` |
| `erlang:port_command/3` | C | erts/preloaded/src/erlang.erl (port_command) | `crates/vm/src/natives/mod.rs` |
| `erlang:port_connect/2` | C | erts/preloaded/src/erlang.erl (port_connect) | `crates/vm/src/natives/mod.rs` |
| `erlang:port_info/1` | C | erts/preloaded/src/erlang.erl (port_info) | `crates/vm/src/natives/mod.rs` |
| `erlang:port_info/2` | C | erts/preloaded/src/erlang.erl (port_info) | `crates/vm/src/natives/mod.rs` |
| `erlang:prepare_loading/2` | C | erts/preloaded/src/erlang.erl (prepare_loading) | `crates/vm/src/natives/code.rs` |
| `erlang:process_display/2` | C | erts/preloaded/src/erlang.erl (process_display) | `crates/vm/src/natives/proc.rs` |
| `erlang:process_flag/3` | C | erts/preloaded/src/erlang.erl (process_flag) | `crates/vm/src/natives/proc.rs` |
| `erlang:send_nosuspend/2` | C | erts/preloaded/src/erlang.erl (send_nosuspend) | `crates/vm/src/natives/proc.rs` |
| `erlang:send_nosuspend/3` | C | erts/preloaded/src/erlang.erl (send_nosuspend) | `crates/vm/src/natives/proc.rs` |
| `erlang:set_cookie/2` | C | erts/preloaded/src/erlang.erl (set_cookie) | `crates/vm/src/natives/node.rs` |
| `erlang:spawn/1` | C | erts/preloaded/src/erlang.erl (spawn) | `crates/vm/src/signals.rs` |
| `erlang:spawn/2` | C | erts/preloaded/src/erlang.erl (spawn) | `crates/vm/src/signals.rs` |
| `erlang:spawn/4` | C | erts/preloaded/src/erlang.erl (spawn) | `crates/vm/src/signals.rs` |
| `erlang:spawn_link/1` | C | erts/preloaded/src/erlang.erl (spawn_link) | `crates/vm/src/signals.rs` |
| `erlang:spawn_link/2` | C | erts/preloaded/src/erlang.erl (spawn_link) | `crates/vm/src/signals.rs` |
| `erlang:spawn_link/4` | C | erts/preloaded/src/erlang.erl (spawn_link) | `crates/vm/src/signals.rs` |
| `erlang:spawn_monitor/1` | C | erts/preloaded/src/erlang.erl (spawn_monitor) | `crates/vm/src/signals.rs` |
| `erlang:spawn_monitor/2` | C | erts/preloaded/src/erlang.erl (spawn_monitor) | `crates/vm/src/signals.rs` |
| `erlang:spawn_monitor/3` | C | erts/preloaded/src/erlang.erl (spawn_monitor) | `crates/vm/src/signals.rs` |
| `erlang:spawn_monitor/4` | C | erts/preloaded/src/erlang.erl (spawn_monitor) | `crates/vm/src/signals.rs` |
| `erlang:spawn_opt/2` | C | erts/preloaded/src/erlang.erl (spawn_opt) | `crates/vm/src/signals.rs` |
| `erlang:spawn_opt/3` | C | erts/preloaded/src/erlang.erl (spawn_opt) | `crates/vm/src/signals.rs` |
| `erlang:spawn_opt/5` | C | erts/preloaded/src/erlang.erl (spawn_opt) | `crates/vm/src/signals.rs` |
| `erlang:suspend_process/1` | C | erts/preloaded/src/erlang.erl (suspend_process) | `crates/vm/src/natives/proc.rs` |
| `erlang:suspend_process/2` | C | erts/preloaded/src/erlang.erl (suspend_process) | `crates/vm/src/natives/proc.rs` |
| `erlang:yield/0` | C | erts/preloaded/src/erlang.erl (yield) | `crates/vm/src/natives/proc.rs` |
| `erts_internal:check_process_code/3` | C | erts/preloaded/src/erts_internal.erl (check_process_code) | `crates/vm/src/natives/code.rs` |
| `erts_internal:port_command/2` | C | erts/preloaded/src/erts_internal.erl (port_command) | `crates/vm/src/natives/mod.rs` |
| `ets:all/0` | C | lib/stdlib/src/ets.erl (all) | `crates/vm/src/natives/ets.rs` |
| `ets:repair_continuation/2` | C | lib/stdlib/src/ets.erl (repair_continuation) | `crates/vm/src/natives/ets.rs` |
| `ets:select_delete/2` | C | lib/stdlib/src/ets.erl (select_delete) | `crates/vm/src/natives/ets.rs` |
| `ets:tab2list/1` | C | lib/stdlib/src/ets.erl (tab2list) | `crates/vm/src/natives/ets.rs` |
| `filename:join/1` | C | lib/stdlib/src/filename.erl (join) | `crates/vm/src/natives/nif.rs` |
| `os:getenv/0` | C | lib/kernel/src/os.erl (getenv) | `crates/bifs/src/sys.rs` |
| `os:getenv/0` | C | lib/kernel/src/os.erl (getenv) | `crates/vm/src/natives/env.rs` |
| `os:perf_counter/1` | C | lib/kernel/src/os.erl (perf_counter) | `crates/bifs/src/sys.rs` |
| `os:type/0` | C | lib/kernel/src/os.erl (type) | `crates/bifs/src/sys.rs` |
| `os:version/0` | C | lib/kernel/src/os.erl (version) | `crates/bifs/src/sys.rs` |
| `unicode:characters_to_binary/3` | C | lib/stdlib/src/unicode.erl (characters_to_binary) | `crates/vm/src/natives/nif.rs` |
| `atomics:add/3` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `atomics:add_get/3` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `atomics:compare_exchange/4` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `atomics:exchange/3` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `atomics:get/2` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `atomics:info/1` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `atomics:put/3` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `binary:at/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:compile_pattern/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:copy/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:copy/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:decode_unsigned/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:decode_unsigned/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:encode_unsigned/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:encode_unsigned/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:first/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:last/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:list_to_bin/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:longest_common_prefix/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:longest_common_suffix/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:match/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:match/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:matches/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:matches/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:part/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:part/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:referenced_byte_size/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:split/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `binary:split/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:abs/1` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erlang:abs/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:adler32/1` | A | bif.tab | `crates/bifs/src/checksum.rs` |
| `erlang:adler32/2` | A | bif.tab | `crates/bifs/src/checksum.rs` |
| `erlang:adler32_combine/3` | A | bif.tab | `crates/bifs/src/checksum.rs` |
| `erlang:alias/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:append/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:append_element/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:atom_to_binary/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:atom_to_list/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:binary_part/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:binary_part/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:binary_to_atom/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:binary_to_existing_atom/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:binary_to_float/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:binary_to_list/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:binary_to_list/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:binary_to_term/1` | A | bif.tab | `crates/bifs/src/etf.rs` |
| `erlang:binary_to_term/2` | A | bif.tab | `crates/bifs/src/etf.rs` |
| `erlang:bit_size/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:bitstring_to_list/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:bump_reductions/1` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erlang:byte_size/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:call_on_load_function/1` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:call_on_load_function/1` | A | bif.tab | `crates/vm/src/natives/nif.rs` |
| `erlang:cancel_timer/1` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:cancel_timer/2` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:ceil/1` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erlang:ceil/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:check_old_code/1` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:crc32/1` | A | bif.tab | `crates/bifs/src/checksum.rs` |
| `erlang:crc32/2` | A | bif.tab | `crates/bifs/src/checksum.rs` |
| `erlang:crc32_combine/3` | A | bif.tab | `crates/bifs/src/checksum.rs` |
| `erlang:date/0` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:delete_element/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:delete_module/1` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:demonitor/1` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:demonitor/2` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:display/1` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erlang:display_string/2` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erlang:dt_restore_tag/1` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erlang:dt_spread_tag/1` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erlang:element/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:erase/0` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:erase/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:error/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:error/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:error/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:exit/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:exit/1` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:exit/2` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:external_size/1` | A | bif.tab | `crates/bifs/src/etf.rs` |
| `erlang:external_size/2` | A | bif.tab | `crates/bifs/src/etf.rs` |
| `erlang:finish_after_on_load/2` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:finish_loading/1` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:float/1` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erlang:float/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:float_to_binary/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:float_to_binary/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:float_to_list/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:float_to_list/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:floor/1` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erlang:floor/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:fun_info_mfa/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:fun_to_list/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:function_exported/3` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:get/0` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:get/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:get_keys/0` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:get_keys/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:get_module_info/1` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:get_module_info/2` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:group_leader/0` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:halt/2` | A | bif.tab | `crates/vm/src/natives/node.rs` |
| `erlang:has_prepared_code_on_load/1` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:hd/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:hibernate/3` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:insert_element/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:integer_to_binary/1` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erlang:integer_to_binary/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:integer_to_binary/2` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erlang:integer_to_binary/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:integer_to_list/1` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erlang:integer_to_list/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:integer_to_list/2` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erlang:integer_to_list/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:iolist_size/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:iolist_to_binary/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:iolist_to_iovec/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_atom/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_binary/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_bitstring/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_boolean/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_builtin/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_float/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_function/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_function/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_integer/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_integer/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_list/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_map/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_map_key/2` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `erlang:is_map_key/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_number/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_pid/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_port/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_process_alive/1` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:is_record/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_record/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_record/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_reference/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:is_tuple/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:length/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:link/1` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:list_to_atom/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:list_to_binary/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:list_to_bitstring/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:list_to_existing_atom/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:list_to_float/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:list_to_tuple/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:load_nif/2` | A | bif.tab | `crates/vm/src/natives/nif.rs` |
| `erlang:loaded/0` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:localtime/0` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:localtime_to_universaltime/2` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:make_ref/0` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:make_tuple/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:make_tuple/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:map_get/2` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `erlang:map_get/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:map_size/1` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `erlang:map_size/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:max/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:md5/1` | A | bif.tab | `crates/bifs/src/checksum.rs` |
| `erlang:md5_final/1` | A | bif.tab | `crates/bifs/src/checksum.rs` |
| `erlang:md5_init/0` | A | bif.tab | `crates/bifs/src/checksum.rs` |
| `erlang:md5_update/2` | A | bif.tab | `crates/bifs/src/checksum.rs` |
| `erlang:min/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:module_loaded/1` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:monitor/2` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:monitor/3` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:monotonic_time/0` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:monotonic_time/1` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:nif_error/1` | A | bif.tab | `crates/vm/src/natives/nif.rs` |
| `erlang:nif_error/2` | A | bif.tab | `crates/vm/src/natives/nif.rs` |
| `erlang:node/0` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:node/0` | A | bif.tab | `crates/vm/src/natives/node.rs` |
| `erlang:node/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:node/1` | A | bif.tab | `crates/vm/src/natives/node.rs` |
| `erlang:nodes/0` | A | bif.tab | `crates/vm/src/natives/node.rs` |
| `erlang:nodes/0` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erlang:nodes/1` | A | bif.tab | `crates/vm/src/natives/node.rs` |
| `erlang:nodes/2` | A | bif.tab | `crates/vm/src/natives/node.rs` |
| `erlang:now/0` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:phash/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:phash2/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:phash2/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:pid_to_list/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:port_get_data/1` | A | bif.tab | `crates/vm/src/natives/mod.rs` |
| `erlang:port_set_data/2` | A | bif.tab | `crates/vm/src/natives/mod.rs` |
| `erlang:port_to_list/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:ports/0` | A | bif.tab | `crates/vm/src/natives/mod.rs` |
| `erlang:posixtime_to_universaltime/1` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:pre_loaded/0` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erlang:process_flag/2` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:process_info/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:process_info/2` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:processes/0` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:put/2` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:raise/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:read_timer/1` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:read_timer/2` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:ref_to_list/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:register/2` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:registered/0` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:resume_process/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:round/1` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erlang:round/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:self/0` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:self/0` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:send/2` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:send/3` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:send_after/3` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:send_after/4` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:setelement/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:size/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:spawn/3` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:spawn_link/3` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:spawn_opt/4` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:spawn_request_abandon/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:split_binary/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:start_timer/3` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:start_timer/4` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:statistics/1` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erlang:subtract/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:system_flag/2` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erlang:system_info/1` | A | bif.tab | `crates/bifs/src/sys.rs` |
| `erlang:system_time/0` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:system_time/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:term_to_binary/1` | A | bif.tab | `crates/bifs/src/etf.rs` |
| `erlang:term_to_binary/2` | A | bif.tab | `crates/bifs/src/etf.rs` |
| `erlang:term_to_iovec/1` | A | bif.tab | `crates/bifs/src/etf.rs` |
| `erlang:term_to_iovec/2` | A | bif.tab | `crates/bifs/src/etf.rs` |
| `erlang:throw/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:time/0` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:time_offset/0` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:time_offset/1` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:tl/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:trunc/1` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erlang:trunc/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:tuple_size/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:tuple_to_list/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:unalias/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erlang:unique_integer/0` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:unique_integer/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erlang:universaltime/0` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:universaltime_to_localtime/1` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:universaltime_to_posixtime/1` | A | bif.tab | `crates/bifs/src/time.rs` |
| `erlang:unlink/1` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:unregister/1` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erlang:whereis/1` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erts_debug:flat_size/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erts_debug:same/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erts_internal:atomics_new/2` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `erts_internal:binary_to_integer/2` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erts_internal:check_dirty_process_code/2` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erts_internal:check_process_code/1` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erts_internal:cmp_term/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erts_internal:counters_add/3` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `erts_internal:counters_get/2` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `erts_internal:counters_info/1` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `erts_internal:counters_new/1` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `erts_internal:counters_put/3` | A | bif.tab | `crates/bifs/src/atomics.rs` |
| `erts_internal:dirty_process_handle_signals/1` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erts_internal:dist_spawn_request/4` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erts_internal:erase_persistent_terms/0` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erts_internal:garbage_collect/1` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erts_internal:group_leader/2` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erts_internal:group_leader/3` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erts_internal:is_system_process/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erts_internal:list_to_integer/2` | A | bif.tab | `crates/bifs/src/arith.rs` |
| `erts_internal:map_next/3` | A | bif.tab | `crates/vm/src/natives/maps.rs` |
| `erts_internal:open_port/2` | A | bif.tab | `crates/vm/src/natives/mod.rs` |
| `erts_internal:perf_counter_unit/0` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erts_internal:port_close/1` | A | bif.tab | `crates/vm/src/natives/mod.rs` |
| `erts_internal:port_command/3` | A | bif.tab | `crates/vm/src/natives/mod.rs` |
| `erts_internal:port_connect/2` | A | bif.tab | `crates/vm/src/natives/mod.rs` |
| `erts_internal:port_control/3` | A | bif.tab | `crates/vm/src/natives/mod.rs` |
| `erts_internal:port_info/1` | A | bif.tab | `crates/vm/src/natives/mod.rs` |
| `erts_internal:port_info/2` | A | bif.tab | `crates/vm/src/natives/mod.rs` |
| `erts_internal:prepare_loading/2` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erts_internal:process_display/2` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erts_internal:process_flag/3` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erts_internal:processes_next/1` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erts_internal:purge_module/2` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erts_internal:request_system_task/3` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erts_internal:request_system_task/4` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erts_internal:scheduler_wall_time/1` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erts_internal:spawn_request/4` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erts_internal:spawn_system_process/3` | A | bif.tab | `crates/vm/src/signals.rs` |
| `erts_internal:suspend_process/2` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erts_internal:term_to_string/2` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `erts_internal:time_unit/0` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `erts_internal:trace/3` | A | bif.tab | `crates/vm/src/natives/proc.rs` |
| `erts_literal_area_collector:release_area_switch/0` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `erts_literal_area_collector:send_copy_request/3` | A | bif.tab | `crates/vm/src/natives/code.rs` |
| `ets:delete/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:delete/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:delete_object/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:first/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:first_lookup/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:give_away/3` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:info/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:info/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:insert/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:insert_new/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:internal_request_all/0` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:internal_select_delete/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:is_compiled_ms/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:last/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:last_lookup/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:lookup/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:lookup_element/3` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:lookup_element/4` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:match/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:match/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:match/3` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:match_object/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:match_object/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:match_object/3` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:match_spec_compile/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:match_spec_run_r/3` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:member/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:new/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:next/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:next_lookup/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:prev/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:prev_lookup/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:rename/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:safe_fixtable/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:select/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:select/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:select/3` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:select_count/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:select_replace/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:select_reverse/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:select_reverse/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:select_reverse/3` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:slot/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:take/2` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:update_counter/3` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:update_counter/4` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:update_element/3` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:update_element/4` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `ets:whereis/1` | A | bif.tab | `crates/vm/src/natives/ets.rs` |
| `file:native_name_encoding/0` | A | bif.tab | `crates/bifs/src/unicode.rs` |
| `io:printable_range/0` | A | bif.tab | `crates/bifs/src/unicode.rs` |
| `lists:keyfind/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `lists:keymember/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `lists:keysearch/3` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `lists:member/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `lists:reverse/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `maps:find/2` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `maps:from_keys/2` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `maps:from_list/1` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `maps:get/2` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `maps:is_key/2` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `maps:keys/1` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `maps:merge/2` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `maps:put/3` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `maps:remove/2` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `maps:take/2` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `maps:update/3` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `maps:values/1` | A | bif.tab | `crates/bifs/src/maps_bifs.rs` |
| `math:acos/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:acosh/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:asin/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:asinh/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:atan/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:atan2/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:atanh/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:ceil/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:cos/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:cosh/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:erf/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:erfc/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:exp/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:floor/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:fmod/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:log/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:log10/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:log2/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:pow/2` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:sin/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:sinh/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:sqrt/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:tan/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `math:tanh/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `os:env/0` | A | bif.tab | `crates/vm/src/natives/env.rs` |
| `os:getenv/1` | A | bif.tab | `crates/bifs/src/sys.rs` |
| `os:getenv/1` | A | bif.tab | `crates/vm/src/natives/env.rs` |
| `os:getpid/0` | A | bif.tab | `crates/bifs/src/sys.rs` |
| `os:perf_counter/0` | A | bif.tab | `crates/bifs/src/sys.rs` |
| `os:putenv/2` | A | bif.tab | `crates/vm/src/natives/env.rs` |
| `os:set_signal/2` | A | bif.tab | `crates/vm/src/natives/env.rs` |
| `os:system_time/0` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `os:system_time/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `os:timestamp/0` | A | bif.tab | `crates/bifs/src/time.rs` |
| `os:unsetenv/1` | A | bif.tab | `crates/vm/src/natives/env.rs` |
| `persistent_term:erase/1` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `persistent_term:get/0` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `persistent_term:get/1` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `persistent_term:get/2` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `persistent_term:info/0` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `persistent_term:put/2` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `persistent_term:put_new/2` | A | bif.tab | `crates/vm/src/natives/sys.rs` |
| `prim_file:internal_name2native/1` | A | bif.tab | `crates/bifs/src/unicode.rs` |
| `prim_file:internal_native2name/1` | A | bif.tab | `crates/bifs/src/unicode.rs` |
| `prim_file:internal_normalize_utf8/1` | A | bif.tab | `crates/bifs/src/unicode.rs` |
| `prim_file:is_translatable/1` | A | bif.tab | `crates/bifs/src/unicode.rs` |
| `re:compile/1` | A | bif.tab | `crates/vm/src/natives/re.rs` |
| `re:compile/2` | A | bif.tab | `crates/vm/src/natives/re.rs` |
| `re:import/1` | A | bif.tab | `crates/vm/src/natives/re.rs` |
| `re:inspect/2` | A | bif.tab | `crates/vm/src/natives/re.rs` |
| `re:internal_run/4` | A | bif.tab | `crates/vm/src/natives/re.rs` |
| `re:run/2` | A | bif.tab | `crates/vm/src/natives/re.rs` |
| `re:run/3` | A | bif.tab | `crates/vm/src/natives/re.rs` |
| `re:version/0` | A | bif.tab | `crates/vm/src/natives/re.rs` |
| `unicode:bin_is_7bit/1` | A | bif.tab | `crates/bifs/src/pure.rs` |
| `unicode:characters_to_binary/2` | A | bif.tab | `crates/bifs/src/unicode.rs` |
| `unicode:characters_to_list/2` | A | bif.tab | `crates/bifs/src/unicode.rs` |
| `erlang:!/2` | B | beam_emu.c (instruction) | `crates/vm/src/calls.rs` |
| `erlang:*/2` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:++/2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:+/1` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:+/2` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:--/2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:-/1` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:-/2` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang://2` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:/=/2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:</2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:=/=/2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:=:=/2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:=</2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:==/2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:>/2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:>=/2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:and/2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:apply/2` | B | beam_emu.c (instruction) | `crates/vm/src/calls.rs` |
| `erlang:apply/3` | B | beam_emu.c (instruction) | `crates/vm/src/calls.rs` |
| `erlang:band/2` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:bnot/1` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:bor/2` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:bsl/2` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:bsr/2` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:bxor/2` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:div/2` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:not/1` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:or/2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `erlang:rem/2` | B | beam_emu.c (instruction) | `crates/bifs/src/arith.rs` |
| `erlang:xor/2` | B | beam_emu.c (instruction) | `crates/bifs/src/pure.rs` |
| `prim_tty:isatty/1` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:isprint/1` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:read_nif/3` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:setlocale/1` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:setupterm_nif/0` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:sizeof_wchar/0` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:tigetflag_nif/1` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:tigetnum_nif/1` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:tigetstr_nif/1` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:tinfo_nif/0` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:tputs_nif/2` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:tty_create/1` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:tty_encoding/1` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:tty_init/2` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:tty_is_open/2` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:tty_select/2` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:tty_window_size/1` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:wcswidth/1` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:wcwidth/1` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |
| `prim_tty:write_nif/2` | B | erts/emulator/nifs/common/prim_tty_nif.c | `crates/vm/src/natives/tty.rs` |

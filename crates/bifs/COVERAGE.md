# BIF coverage — OTP 29.1.1

Source: `arinsal_spec::BIFS`. The differential test compares returned terms and exception classes. Unless noted, each row below has 1,000 generated cases, with an invalid first argument in 10% of cases.

**206 / 553** declarations passed the 1,000-case differential sweep; **0 mismatches / 206,000 comparisons**. Eight ETF declarations have separate differential tests below. The two Unicode conversion BIFs additionally passed 50,000 chardata inputs across nine encodings and both functions: **0 mismatches / 900,000 comparisons**. Filename BIFs also passed 1,000 mixed valid and invalid inputs per function. Another 19 registered BIFs have nondeterministic or opaque outputs and targeted checks. `erlang:convert_time_unit/3` is also implemented, but it is an `erlang.erl` wrapper and is absent from `bif.tab`.

Filename and printable-range results use the default OTP 29.1.1 emulator flags on macOS.

## ETF BIFs

| BIF | Evidence |
| --- | --- |
| `erlang:term_to_binary/1,2` | 20,000 generated terms times six option sets; zero byte mismatches against OTP 29.1.1, plus large integer maps, bitstrings, identities, local funs, native records, and a million-deep term test |
| `erlang:binary_to_term/1,2` | Decode of the generated OTP bytes, 10,000 malformed random binaries, and targeted `safe` and `used` checks |
| `erlang:term_to_iovec/1,2` | Targeted ordinary and compressed cases, including binaries over the 64-byte split threshold |
| `erlang:external_size/1,2` | Targeted comparisons across six encode option sets |

The malformed random test excludes ETF internal atom references (`I` and `K` tags): they encode VM-local atom indexes, and the two VMs boot with different atom tables. Those tags are accepted when the index exists in Arinsal's table.

On Apple Silicon, a release test over 200 calls on a 1,035,238-byte tuple of 1,000 integer/binary pairs measured Arinsal at a median of 82.9 µs encode and 225.1 µs decode over three runs. The same term in OTP 29.1.1 measured a median of 60.0 µs encode and 132.1 µs decode over three 200-call runs. Arinsal is below the task's supplied 1,067/769 µs baseline for a different mixed term, but does not beat OTP on this identical workload.

## Implemented

| BIF | Cases | Mismatches |
| --- | ---: | ---: |
| `erlang:abs/1` | 1,000 | 0 |
| `erlang:atom_to_list/1` | 1,000 | 0 |
| `erlang:binary_to_list/1` | 1,000 | 0 |
| `erlang:binary_to_list/3` | 1,000 | 0 |
| `erlang:element/2` | 1,000 | 0 |
| `erlang:exit/1` | 1,000 | 0 |
| `erlang:float/1` | 1,000 | 0 |
| `erlang:float_to_list/1` | 1,000 | 0 |
| `erlang:float_to_list/2` | 1,000 | 0 |
| `erlang:phash/2` | 1,000 | 0 |
| `erlang:phash2/1` | 1,000 | 0 |
| `erlang:phash2/2` | 1,000 | 0 |
| `erlang:hd/1` | 1,000 | 0 |
| `erlang:integer_to_list/1` | 1,000 | 0 |
| `erlang:length/1` | 1,000 | 0 |
| `erlang:list_to_atom/1` | 1,000 | 0 |
| `erlang:list_to_binary/1` | 1,000 | 0 |
| `erlang:list_to_float/1` | 1,000 | 0 |
| `erlang:list_to_tuple/1` | 1,000 | 0 |
| `erlang:node/1` | 1,000 | 0 |
| `erlang:node/0` | 1,000 | 0 |
| `erlang:round/1` | 1,000 | 0 |
| `erlang:setelement/3` | 1,000 | 0 |
| `erlang:size/1` | 1,000 | 0 |
| `erlang:split_binary/2` | 1,000 | 0 |
| `erlang:throw/1` | 1,000 | 0 |
| `erlang:tl/1` | 1,000 | 0 |
| `erlang:trunc/1` | 1,000 | 0 |
| `erlang:tuple_to_list/1` | 1,000 | 0 |
| `erts_internal:time_unit/0` | 1,000 | 0 |
| `erts_internal:perf_counter_unit/0` | 1,000 | 0 |
| `math:cos/1` | 1,000 | 0 |
| `math:cosh/1` | 1,000 | 0 |
| `math:sin/1` | 1,000 | 0 |
| `math:sinh/1` | 1,000 | 0 |
| `math:tan/1` | 1,000 | 0 |
| `math:tanh/1` | 1,000 | 0 |
| `math:acos/1` | 1,000 | 0 |
| `math:acosh/1` | 1,000 | 0 |
| `math:asin/1` | 1,000 | 0 |
| `math:asinh/1` | 1,000 | 0 |
| `math:atan/1` | 1,000 | 0 |
| `math:atanh/1` | 1,000 | 0 |
| `math:erf/1` | 1,000 | 0 |
| `math:erfc/1` | 1,000 | 0 |
| `math:exp/1` | 1,000 | 0 |
| `math:log/1` | 1,000 | 0 |
| `math:log2/1` | 1,000 | 0 |
| `math:log10/1` | 1,000 | 0 |
| `math:sqrt/1` | 1,000 | 0 |
| `math:atan2/2` | 1,000 | 0 |
| `math:pow/2` | 1,000 | 0 |
| `erlang:make_tuple/2` | 1,000 | 0 |
| `erlang:append_element/2` | 1,000 | 0 |
| `erlang:make_tuple/3` | 1,000 | 0 |
| `erlang:error/1` | 1,000 | 0 |
| `erlang:error/2` | 1,000 | 0 |
| `erlang:raise/3` | 1,000 | 0 |
| `erlang:is_builtin/3` | 1,000 | 0 |
| `erlang:and/2` | 1,000 | 0 |
| `erlang:or/2` | 1,000 | 0 |
| `erlang:xor/2` | 1,000 | 0 |
| `erlang:not/1` | 1,000 | 0 |
| `erlang:>/2` | 1,000 | 0 |
| `erlang:>=/2` | 1,000 | 0 |
| `erlang:</2` | 1,000 | 0 |
| `erlang:=</2` | 1,000 | 0 |
| `erlang:=:=/2` | 1,000 | 0 |
| `erlang:==/2` | 1,000 | 0 |
| `erlang:=/=/2` | 1,000 | 0 |
| `erlang:/=/2` | 1,000 | 0 |
| `erlang:++/2` | 1,000 | 0 |
| `erlang:append/2` | 1,000 | 0 |
| `erlang:--/2` | 1,000 | 0 |
| `erlang:subtract/2` | 1,000 | 0 |
| `erlang:is_atom/1` | 1,000 | 0 |
| `erlang:is_list/1` | 1,000 | 0 |
| `erlang:is_tuple/1` | 1,000 | 0 |
| `erlang:is_float/1` | 1,000 | 0 |
| `erlang:is_integer/1` | 1,000 | 0 |
| `erlang:is_number/1` | 1,000 | 0 |
| `erlang:is_pid/1` | 1,000 | 0 |
| `erlang:is_port/1` | 1,000 | 0 |
| `erlang:is_reference/1` | 1,000 | 0 |
| `erlang:is_binary/1` | 1,000 | 0 |
| `erlang:is_function/1` | 1,000 | 0 |
| `erlang:is_function/2` | 1,000 | 0 |
| `erlang:is_record/2` | 1,000 | 0 |
| `erlang:is_record/3` | 1,000 | 0 |
| `lists:member/2` | 1,000 | 0 |
| `lists:reverse/2` | 1,000 | 0 |
| `lists:keymember/3` | 1,000 | 0 |
| `lists:keysearch/3` | 1,000 | 0 |
| `lists:keyfind/3` | 1,000 | 0 |
| `erts_debug:same/2` | 1,000 | 0 |
| `erts_debug:flat_size/1` | 1,000 | 0 |
| `erlang:is_boolean/1` | 1,000 | 0 |
| `erlang:iolist_size/1` | 1,000 | 0 |
| `erlang:iolist_to_binary/1` | 1,000 | 0 |
| `erlang:list_to_existing_atom/1` | 1,000 | 0 |
| `erlang:is_bitstring/1` | 1,000 | 0 |
| `erlang:tuple_size/1` | 1,000 | 0 |
| `erlang:byte_size/1` | 1,000 | 0 |
| `erlang:bit_size/1` | 1,000 | 0 |
| `erlang:list_to_bitstring/1` | 1,000 | 0 |
| `erlang:bitstring_to_list/1` | 1,000 | 0 |
| `unicode:bin_is_7bit/1` | 1,000 | 0 |
| `unicode:characters_to_binary/2` | 1,000 + 450,000 | 0 |
| `unicode:characters_to_list/2` | 1,000 + 450,000 | 0 |
| `prim_file:internal_name2native/1` | 1,000 + 1,000 | 0 |
| `prim_file:internal_native2name/1` | 1,000 + 1,000 | 0 |
| `prim_file:internal_normalize_utf8/1` | 1,000 + 1,000 | 0 |
| `prim_file:is_translatable/1` | 1,000 + 1,000 | 0 |
| `file:native_name_encoding/0` | 1,000 + 1 | 0 |
| `io:printable_range/0` | 1,000 + 1 | 0 |
| `erlang:atom_to_binary/2` | 1,000 | 0 |
| `erlang:binary_to_atom/2` | 1,000 | 0 |
| `erlang:binary_to_existing_atom/2` | 1,000 | 0 |
| `erlang:binary_part/2` | 1,000 | 0 |
| `erlang:binary_part/3` | 1,000 | 0 |
| `binary:match/2` | 1,000 | 0 |
| `binary:match/3` | 1,000 | 0 |
| `binary:matches/2` | 1,000 | 0 |
| `binary:matches/3` | 1,000 | 0 |
| `binary:longest_common_prefix/1` | 1,000 | 0 |
| `binary:longest_common_suffix/1` | 1,000 | 0 |
| `binary:first/1` | 1,000 | 0 |
| `binary:last/1` | 1,000 | 0 |
| `binary:at/2` | 1,000 | 0 |
| `binary:part/2` | 1,000 | 0 |
| `binary:part/3` | 1,000 | 0 |
| `binary:list_to_bin/1` | 1,000 | 0 |
| `binary:copy/1` | 1,000 | 0 |
| `binary:copy/2` | 1,000 | 0 |
| `binary:referenced_byte_size/1` | 1,000 | 0 |
| `binary:encode_unsigned/1` | 1,000 | 0 |
| `binary:encode_unsigned/2` | 1,000 | 0 |
| `binary:decode_unsigned/1` | 1,000 | 0 |
| `binary:decode_unsigned/2` | 1,000 | 0 |
| `erlang:insert_element/3` | 1,000 | 0 |
| `erlang:delete_element/2` | 1,000 | 0 |
| `erlang:integer_to_binary/1` | 1,000 | 0 |
| `erlang:float_to_binary/1` | 1,000 | 0 |
| `erlang:float_to_binary/2` | 1,000 | 0 |
| `erlang:binary_to_float/1` | 1,000 | 0 |
| `erlang:is_map/1` | 1,000 | 0 |
| `erlang:map_size/1` | 1,000 | 0 |
| `erts_internal:cmp_term/2` | 1,000 | 0 |
| `binary:split/2` | 1,000 | 0 |
| `binary:split/3` | 1,000 | 0 |
| `erlang:floor/1` | 1,000 | 0 |
| `erlang:ceil/1` | 1,000 | 0 |
| `math:floor/1` | 1,000 | 0 |
| `math:ceil/1` | 1,000 | 0 |
| `math:fmod/2` | 1,000 | 0 |
| `erlang:map_get/2` | 1,000 | 0 |
| `erlang:is_map_key/2` | 1,000 | 0 |
| `erlang:integer_to_list/2` | 1,000 | 0 |
| `erlang:integer_to_binary/2` | 1,000 | 0 |
| `erlang:error/3` | 1,000 | 0 |
| `erlang:min/2` | 1,000 | 0 |
| `erlang:max/2` | 1,000 | 0 |
| `erlang:is_record/1` | 1,000 | 0 |

| `erlang:*/2` | 1,000 | 0 |
| `erlang:+/1` | 1,000 | 0 |
| `erlang:+/2` | 1,000 | 0 |
| `erlang:-/1` | 1,000 | 0 |
| `erlang:-/2` | 1,000 | 0 |
| `erlang://2` | 1,000 | 0 |
| `erlang:adler32/1` | 1,000 | 0 |
| `erlang:adler32/2` | 1,000 | 0 |
| `erlang:adler32_combine/3` | 1,000 | 0 |
| `erlang:band/2` | 1,000 | 0 |
| `erlang:bnot/1` | 1,000 | 0 |
| `erlang:bor/2` | 1,000 | 0 |
| `erlang:bsl/2` | 1,000 | 0 |
| `erlang:bsr/2` | 1,000 | 0 |
| `erlang:bxor/2` | 1,000 | 0 |
| `erlang:crc32/1` | 1,000 | 0 |
| `erlang:crc32/2` | 1,000 | 0 |
| `erlang:crc32_combine/3` | 1,000 | 0 |
| `erlang:div/2` | 1,000 | 0 |
| `erlang:is_integer/3` | 1,000 | 0 |
| `erlang:localtime_to_universaltime/2` | 1,000 | 0 |
| `erlang:md5/1` | 1,000 | 0 |
| `erlang:md5_final/1` | 1,000 | 0 |
| `erlang:md5_init/0` | 1,000 | 0 |
| `erlang:md5_update/2` | 1,000 | 0 |
| `erlang:posixtime_to_universaltime/1` | 1,000 | 0 |
| `erlang:rem/2` | 1,000 | 0 |
| `erlang:universaltime_to_localtime/1` | 1,000 | 0 |
| `erlang:universaltime_to_posixtime/1` | 1,000 | 0 |
| `erts_internal:binary_to_integer/2` | 1,000 | 0 |
| `erts_internal:list_to_integer/2` | 1,000 | 0 |
| `maps:find/2` | 1,000 | 0 |
| `maps:from_keys/2` | 1,000 | 0 |
| `maps:from_list/1` | 1,000 | 0 |
| `maps:get/2` | 1,000 | 0 |
| `maps:is_key/2` | 1,000 | 0 |
| `maps:keys/1` | 1,000 | 0 |
| `maps:merge/2` | 1,000 | 0 |
| `maps:put/3` | 1,000 | 0 |
| `maps:remove/2` | 1,000 | 0 |
| `maps:take/2` | 1,000 | 0 |
| `maps:update/3` | 1,000 | 0 |
| `maps:values/1` | 1,000 | 0 |

## Opaque and nondeterministic results

| BIF | Coverage |
| --- | --- |
| `erlang:make_ref/0` | 1,000 unique references, valid local-ref encoding |
| `erlang:unique_integer/0` | 1,000 negative unique integers |
| `erlang:unique_integer/1` | 1,000 positive unique integers |
| `binary:compile_pattern/1` | 1,000 compiled-pattern match results |
| `erlang:system_time/0` | 1,000 OTP wall-clock comparisons within 2 seconds |
| `erlang:system_time/1` | 6,000 OTP wall-clock comparisons across units |
| `os:system_time/0` | 1,000 OTP wall-clock comparisons within 2 seconds |
| `os:system_time/1` | 6,000 OTP wall-clock comparisons across units |
| `erlang:monotonic_time/0,1` | 1,000 monotonicity, unit, and wall-clock relation checks for each arity; 27.2 ns/call in release |
| `erlang:time_offset/0,1` | 1,000 wall-clock relation and unit checks for each arity |
| `erlang:timestamp/0` | 1,000 OTP-bracketed wall-clock tuple checks |
| `erlang:now/0` | 1,000 OTP-bracketed wall-clock tuple checks |
| `os:timestamp/0` | 1,000 OTP-bracketed wall-clock tuple checks |
| `erlang:time/0` | 1,000 OTP-bracketed local clock tuple checks |
| `erlang:date/0` | 1,000 OTP-bracketed local calendar tuple checks |
| `erlang:localtime/0` | 1,000 OTP-bracketed local calendar tuple checks |
| `erlang:universaltime/0` | 1,000 OTP-bracketed UTC calendar tuple checks |

`erlang:self/0` is registered but returns `BifError::Unsupported` until the process layer supplies the caller. It is listed below as unimplemented.

## Unimplemented declarations by primary reason

Each MFA appears once. These return `None` from `lookup`, except `erlang:self/0` as noted.

### Code loading and coverage (29)

`erlang:delete_module/1`, `erlang:fun_info/2`, `erlang:loaded/0`, `erlang:module_loaded/1`, `erlang:function_exported/3`, `erlang:pre_loaded/0`, `erts_internal:check_process_code/1`, `erlang:get_module_info/1`, `erlang:get_module_info/2`, `erlang:make_fun/3`, `erlang:load_nif/2`, `erlang:call_on_load_function/1`, `erlang:finish_after_on_load/2`, `erlang:check_old_code/1`, `erlang:finish_loading/1`, `erlang:fun_info_mfa/1`, `erts_internal:check_dirty_process_code/2`, `erts_internal:purge_module/2`, `erlang:has_prepared_code_on_load/1`, `erts_internal:prepare_loading/2`, `erts_internal:beamfile_chunk/2`, `erts_internal:beamfile_module_md5/1`, `code:coverage_support/0`, `code:get_coverage_mode/0`, `code:get_coverage_mode/1`, `code:get_coverage/2`, `code:reset_coverage/1`, `code:set_coverage_mode/1`, `code:get_debug_info/1`

### Distribution (1)

`net_kernel:dflag_unicode_io/1`

### Drivers and ports (36)

`erlang:display/1`, `erlang:display_string/2`, `erlang:halt/2`, `erlang:list_to_pid/1`, `erlang:list_to_port/1`, `erlang:list_to_ref/1`, `erts_internal:open_port/2`, `erlang:pid_to_list/1`, `erlang:ports/0`, `erlang:setnode/2`, `erlang:dist_get_stat/1`, `erlang:dist_ctrl_input_handler/2`, `erlang:dist_ctrl_put_data/2`, `erlang:dist_ctrl_get_data/1`, `erlang:dist_ctrl_get_data_notification/1`, `erlang:dist_ctrl_get_opt/2`, `erlang:dist_ctrl_set_opt/3`, `erts_internal:port_info/1`, `erts_internal:port_info/2`, `erts_internal:port_call/3`, `erts_internal:port_command/3`, `erts_internal:port_control/3`, `erts_internal:port_close/1`, `erts_internal:port_connect/2`, `erlang:port_set_data/2`, `erlang:port_get_data/1`, `erlang:ref_to_list/1`, `erlang:port_to_list/1`, `erlang:fun_to_list/1`, `erl_ddll:try_load/3`, `erl_ddll:try_unload/2`, `erl_ddll:loaded_drivers/0`, `erl_ddll:info/2`, `erl_ddll:format_error_int/1`, `erl_ddll:monitor/2`, `erl_ddll:demonitor/1`

### ETF and binary backlog (2)

`erlang:decode_packet/3`, `erlang:iolist_to_iovec/1`

### ETS tables (51)

`ets:internal_request_all/0`, `ets:new/2`, `ets:delete/1`, `ets:delete/2`, `ets:delete_object/2`, `ets:first/1`, `ets:first_lookup/1`, `ets:is_compiled_ms/1`, `ets:lookup/2`, `ets:lookup_element/3`, `ets:lookup_element/4`, `ets:info/1`, `ets:info/2`, `ets:last/1`, `ets:last_lookup/1`, `ets:match/1`, `ets:match/2`, `ets:match/3`, `ets:match_object/1`, `ets:match_object/2`, `ets:match_object/3`, `ets:member/2`, `ets:next/2`, `ets:next_lookup/2`, `ets:prev/2`, `ets:prev_lookup/2`, `ets:insert/2`, `ets:insert_new/2`, `ets:rename/2`, `ets:safe_fixtable/2`, `ets:slot/2`, `ets:update_counter/3`, `ets:select/1`, `ets:select/2`, `ets:select/3`, `ets:select_count/2`, `ets:select_reverse/1`, `ets:select_reverse/2`, `ets:select_reverse/3`, `ets:select_replace/2`, `ets:match_spec_compile/1`, `ets:match_spec_run_r/3`, `ets:update_element/3`, `ets:give_away/3`, `ets:setopts/2`, `ets:take/2`, `ets:update_counter/4`, `ets:whereis/1`, `ets:internal_delete_all/2`, `ets:internal_select_delete/2`, `ets:update_element/4`

### Global mutable state (14)

`persistent_term:put/2`, `persistent_term:get/1`, `persistent_term:get/0`, `persistent_term:erase/1`, `persistent_term:info/0`, `atomics:get/2`, `atomics:put/3`, `atomics:add/3`, `atomics:add_get/3`, `atomics:exchange/3`, `atomics:compare_exchange/4`, `atomics:info/1`, `persistent_term:get/2`, `persistent_term:put_new/2`

### Heap and runtime services (32)

`erts_internal:term_type/1`, `erts_internal:system_check/1`, `erts_internal:create_dist_channel/3`, `erts_internal:ets_super_user/1`, `erts_literal_area_collector:release_area_switch/0`, `erts_literal_area_collector:send_copy_request/3`, `erlang:system_flag/2`, `erlang:system_info/1`, `erlang:system_profile/2`, `erlang:system_profile/0`, `erlang:match_spec_test/3`, `erlang:nif_error/1`, `erlang:nif_error/2`, `erts_internal:get_dflags/0`, `erts_internal:new_connection/1`, `erts_internal:gather_alloc_histograms/1`, `erts_internal:gather_carrier_info/1`, `erts_internal:erase_persistent_terms/0`, `erts_internal:atomics_new/2`, `erts_internal:counters_new/1`, `erts_internal:counters_get/2`, `erts_internal:counters_add/3`, `erts_internal:counters_put/3`, `erts_internal:counters_info/1`, `erts_internal:ets_lookup_binary_info/2`, `erts_internal:ets_raw_first/1`, `erts_internal:ets_raw_next/2`, `erts_internal:abort_pending_connection/2`, `erts_internal:get_creation/0`, `erts_internal:system_monitor/1`, `erts_internal:system_monitor/3`, `erts_internal:notify_breakpoint_hit/3`

### Map and internal iterator services (4)

`erts_internal:map_to_tuple_keys/1`, `erts_internal:map_hashmap_children/1`, `erts_internal:map_next/3`, `erts_internal:term_to_string/2`

### Native record definitions (8)

`records:get_module/1`, `records:get_name/1`, `records:get/2`, `records:get_field_names/1`, `records:is_exported/1`, `records:create/4`, `records:update/4`, `records:get_definition/2`

### OS environment and time (7)

`os:getenv/1`, `os:putenv/2`, `os:unsetenv/1`, `os:getpid/0`, `os:perf_counter/0`, `os:set_signal/2`, `os:env/0`

### Other runtime services (1)

`error_logger:warning_map/0`

### Processes and schedulers (73)

`erlang:erase/0`, `erlang:erase/1`, `erlang:exit/2`, `erlang:exit_signal/2`, `erts_internal:garbage_collect/1`, `erlang:get/0`, `erlang:get/1`, `erlang:get_keys/1`, `erlang:group_leader/0`, `erts_internal:group_leader/2`, `erts_internal:group_leader/3`, `erlang:link/1`, `erlang:monitor_node/2`, `erlang:monitor_node/3`, `erlang:nodes/0`, `erlang:nodes/1`, `erlang:nodes/2`, `erlang:process_flag/2`, `erts_internal:process_flag/3`, `erlang:process_info/1`, `erlang:process_info/2`, `erlang:processes/0`, `erlang:put/2`, `erlang:register/2`, `erlang:registered/0`, `erlang:self/0`, `erlang:spawn/3`, `erlang:spawn_link/3`, `erlang:statistics/1`, `erlang:unlink/1`, `erlang:unregister/1`, `erlang:whereis/1`, `erlang:spawn_opt/4`, `erts_internal:request_system_task/3`, `erts_internal:request_system_task/4`, `erts_internal:is_system_process/1`, `erts_internal:scheduler_wall_time/1`, `erts_internal:dirty_process_handle_signals/1`, `erts_internal:spawn_request/4`, `erts_internal:dist_spawn_request/4`, `erts_internal:no_aux_work_threads/0`, `erlang:spawn_request_abandon/1`, `erts_internal:suspend_process/2`, `erlang:resume_process/1`, `erts_internal:process_display/2`, `erlang:bump_reductions/1`, `erlang:start_timer/3`, `erlang:start_timer/4`, `erlang:send_after/3`, `erlang:send_after/4`, `erlang:cancel_timer/1`, `erlang:cancel_timer/2`, `erlang:read_timer/1`, `erlang:read_timer/2`, `erlang:monitor/2`, `erlang:demonitor/1`, `erlang:demonitor/2`, `erlang:is_process_alive/1`, `erts_internal:is_process_alive/2`, `erlang:!/2`, `erlang:send/2`, `erlang:send/3`, `erlang:hibernate/3`, `erlang:get_keys/0`, `erts_internal:is_process_executing_dirty/1`, `erts_internal:spawn_system_process/3`, `erlang:alias/1`, `erlang:unalias/1`, `erlang:monitor/3`, `erts_internal:processes_next/1`, `erlang:exit/3`, `erlang:link/2`, `erlang:exit_signal/3`

### Regular expressions (8)

`re:version/0`, `re:compile/1`, `re:compile/2`, `re:run/2`, `re:run/3`, `re:internal_run/4`, `re:inspect/2`, `re:import/1`

### String conversion backlog (1)

`string:list_to_float/1`

### Tracing and debugging runtime (53)

`erts_internal:trace_pattern/3`, `erts_internal:trace/3`, `erlang:trace_info/2`, `erlang:trace_delivered/1`, `erlang:seq_trace/2`, `erlang:seq_trace_info/1`, `erlang:seq_trace_print/1`, `erlang:seq_trace_print/2`, `erts_debug:disassemble/1`, `erts_debug:breakpoint/2`, `erts_debug:get_internal_state/1`, `erts_debug:set_internal_state/2`, `erts_debug:dist_ext_to_term/2`, `erts_debug:instructions/0`, `erts_debug:interpreter_size/0`, `erts_debug:dirty_cpu/2`, `erts_debug:dirty_io/2`, `erts_debug:dirty/3`, `erts_debug:lcnt_control/2`, `erts_debug:lcnt_control/1`, `erts_debug:lcnt_collect/0`, `erts_debug:lcnt_clear/0`, `erlang:dt_put_tag/1`, `erlang:dt_get_tag/0`, `erlang:dt_get_tag_data/0`, `erlang:dt_spread_tag/1`, `erlang:dt_restore_tag/1`, `erlang:dt_prepend_vm_tag_data/1`, `erlang:dt_append_vm_tag_data/1`, `erts_debug:map_info/1`, `erts_debug:size_shared/1`, `erts_debug:copy_shared/2`, `erts_internal:trace_session_create/3`, `erts_internal:trace_session_destroy/1`, `erts_internal:trace/4`, `erts_internal:trace_pattern/4`, `erts_internal:trace_info/3`, `erts_trace_cleaner:check/0`, `erts_trace_cleaner:send_trace_clean_signal/1`, `erl_debugger:supported/0`, `erl_debugger:instrumentations/0`, `erl_debugger:toggle_instrumentations/1`, `erl_debugger:register/1`, `erl_debugger:unregister/2`, `erl_debugger:whereis/0`, `erl_debugger:breakpoint/3`, `erl_debugger:breakpoints/1`, `erl_debugger:breakpoints/3`, `erl_debugger:stack_frames/2`, `erl_debugger:peek_stack_frame_slot/4`, `erl_debugger:xregs_count/1`, `erl_debugger:peek_xreg/3`, `erts_debug:unaligned_bitstring/2`

## Performance and remaining scope

| Operation | Arinsal | OTP 29.1.1 |
| --- | ---: | ---: |
| `binary:match/2`, 1 MB subject, one 8-byte needle | 14.6 µs | 25.4 µs |
| `binary:match/2`, 1 MB subject, two 8-byte needles | 25.5 µs | 965.5 µs |
| `erlang:monotonic_time/0` | 27.2 ns (release) | ~20 ns (task baseline) |
| `unicode:characters_to_list/2`, 10 MiB UTF-8 | 140.7 MiB/s (release) | 22.8 MiB/s |
| `unicode:characters_to_binary/2`, 10 MiB ASCII list | 126.7 MiB/s (release) | 89.1 MiB/s |
| ETF encode, ~1 MB mixed term | unimplemented | 1,067 µs (task baseline) |
| ETF decode, ~1 MB mixed term | unimplemented | 769 µs (task baseline) |

ETF heap encode/decode and its 20,000-term byte-exact test and 1 MB performance table remain unimplemented. Unicode conversion BIFs and full timezone edge behavior remain open.

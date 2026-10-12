# OTP 29.1.1 suite pilot results

| Suite | Cases | erl pass | Arinsal pass | erl-pass/Arinsal-not | Arinsal exit | First failure line / notes |
|---|---:|---:|---:|---:|---:|---|
| `atomics_SUITE` | 6 | 6/6 | 6/6 | 0 | 0 | none |
| `bif_SUITE` | 34 | 29/34 | 28/34 | 1 | -9 | group_leader_prio_dirty: failed {'EXIT', {badarg, {erts_debug,dirty_io, [alive_waitexiting,<0.734.0>] |
| `big_SUITE` | 23 | 23/23 | 22/23 | 1 | 0 | reductions: failed {failed |
| `binary_SUITE` | 55 | 41/55 | 37/55 | 4 | -9 | bad_terms: failed {'EXIT',error}, unknown_location; error_after_yield: failed {{badmatch,false}; gc_test: failed {'EXIT',{badmatch,{45151692224,124,2}}}, unknown_location; otp_5484: failed {'EXIT',error}, unknown_location |
| `bs_construct_SUITE` | 31 | 30/31 | 28/31 | 2 | 0 | error_info: failed {{badmatch, {badarg, {3,binary,type,some_atom}, <<"segment 3 of type 'binary': expected a binary but got: some_atom">>}}; reductions: failed {if_clause |
| `bs_match_bin_SUITE` | 9 | 9/9 | 9/9 | 0 | 0 | none |
| `bs_match_int_SUITE` | 10 | 10/10 | 10/10 | 0 | 0 | none |
| `bs_match_misc_SUITE` | 20 | 20/20 | 20/20 | 0 | 0 | none |
| `bs_match_tail_SUITE` | 4 | 4/4 | 4/4 | 0 | 0 | none |
| `bs_utf_SUITE` | 8 | 8/8 | 0/8 | 8 | -9 | bad_construction: missing; utf16_illegal_sequences: missing; utf16_roundtrip: missing; utf32_illegal_sequences: missing; utf32_roundtrip: missing; utf8_big_file: missing; utf8_illegal_sequences: missing; utf8_roundtrip: missing |
| `code_SUITE` | 29 | 27/29 | 27/29 | 0 | 0 | none |
| `counters_SUITE` | 6 | 6/6 | 6/6 | 0 | 0 | none |
| `dirty_bif_SUITE` | 13 | 8/13 | 8/13 | 0 | 0 | none |
| `dirty_nif_SUITE` | 25 | 10/25 | 10/25 | 0 | 0 | none |
| `erts_debug_SUITE` | 8 | 7/8 | 7/8 | 0 | 0 | none |
| `exception_SUITE` | 16 | 15/16 | 15/16 | 0 | 0 | none |
| `float_SUITE` | 15 | 14/15 | 13/15 | 1 | 0 | fp_drv: failed {badarg |
| `fun_SUITE` | 18 | 17/18 | 17/18 | 0 | 0 | none |
| `guard_SUITE` | 6 | 6/6 | 6/6 | 0 | 0 | none |
| `hash_SUITE` | 29 | 27/29 | 26/29 | 1 | 0 | test_phash2_10MB_plus_bin: failed {function_clause |
| `list_bif_SUITE` | 9 | 8/9 | 8/9 | 0 | 0 | none |
| `map_SUITE` | 64 | 63/64 | 62/64 | 1 | 0 | t_tracing: failed {{badmatch,timeout} |
| `num_bif_SUITE` | 11 | 11/11 | 11/11 | 0 | 0 | none |
| `op_SUITE` | 12 | 12/12 | 9/12 | 3 | 0 | complex_relop: failed {test_case_failed, {'EXIT', {badarith; logical: failed testcase_aborted_or_killed, unknown_location; relop: failed {test_case_failed, {'EXIT', {badarith |
| `persistent_term_SUITE` | 22 | 22/22 | 0/22 | 22 | -9 | basic: failed {'EXIT', {noproc, {gen_server,call, [ct_hooks_lock,{release,<0.192.0>}]}}}, unknown_location; collisions: missing; destruction: missing; error_info: missing; gc_binary_orig: missing; get_all_race: missing; get_put_colliding_bucket: missing; get_trapping: missing; info: missing; info_trapping: missing; init_restart: missing; keys: missing; killed_while_trapping: missing; killed_while_trapping_erase: missing; killed_while_trapping_put: missing; non_message_signal: missing; off_heap_values: missing; purging: missing; put_erase_trapping: missing; shared_magic_ref: missing; sharing: missing; whole_message: missing |
| `receive_SUITE` | 14 | 12/14 | 12/14 | 0 | -9 | first failure: failed: {not_alive, |
| `ref_SUITE` | 5 | 4/5 | 4/5 | 0 | 0 | none |
| `small_SUITE` | 13 | 13/13 | 13/13 | 0 | 0 | none |
| `statistics_SUITE` | 18 | 18/18 | 16/18 | 2 | 0 | scheduler_wall_time: failed {{badmatch, {true,[99,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}; scheduler_wall_time_all: failed {{badmatch, {true, [99,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0]}} |
| `time_SUITE` | 18 | 16/18 | 16/18 | 0 | 0 | none |
| `tuple_SUITE` | 20 | 20/20 | 20/20 | 0 | 0 | none |
| `unique_SUITE` | 2 | 1/2 | 1/2 | 0 | 0 | none |

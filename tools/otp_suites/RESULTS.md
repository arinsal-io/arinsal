# OTP 29.1.1 suite pilot results

| Suite | Cases | erl pass | Arinsal pass | erl-pass/Arinsal-not | Arinsal exit | First failure line / notes |
|---|---:|---:|---:|---:|---:|---|
| `atomics_SUITE` | 6 | 6/6 | 6/6 | 0 | 0 | none |
| `big_SUITE` | 23 | 23/23 | 18/23 | 5 | 0 | big_float_2: failed {{badmatch,0.0}; big_float_3: failed {{badmatch,3.402823669209385e38}; reductions: failed {badarg; system_limit: failed {badarg; toobig: failed {{badmatch, {'EXIT', {system_limit |
| `binary_SUITE` | 55 | 42/55 | 34/55 | 8 | 0 | bad_terms: failed {'EXIT',error}, unknown_location; copy_terms: failed {'EXIT',error}, unknown_location; error_after_yield: failed {{badmatch,false}; gc_test: failed {{badmatch,{binary,[]}}; local_ext: failed {{badmatch,{error,exbadport}}; otp_5484: failed {'EXIT',error}, unknown_location; t2b_deterministic: failed {{badmatch; terms: failed {'EXIT',error}, unknown_location |
| `bs_construct_SUITE` | 31 | 30/31 | 26/31 | 4 | 0 | bs_append_offheap: failed "missing binary in erts_bs_private_append"; error_info: failed {{badmatch,false}; in_guard: failed {badarg; reductions: failed {if_clause |
| `bs_match_bin_SUITE` | 9 | 9/9 | 9/9 | 0 | 0 | none |
| `bs_match_int_SUITE` | 10 | 10/10 | 10/10 | 0 | 0 | none |
| `bs_match_misc_SUITE` | 20 | 20/20 | 18/20 | 2 | 0 | bad_bs_match: failed {{badmatch,{module,bad_bs_match}}; fp16: failed {badarg |
| `bs_match_tail_SUITE` | 4 | 4/4 | 0/4 | 4 | 0 | aligned: missing; huge_tail: missing; unaligned: missing; zero_tail: missing; suite-level: failed: 'bs_match_tail_SUITE:all/0 is missing', unknown_location |
| `bs_utf_SUITE` | 8 | 8/8 | 0/8 | 8 | -9 | bad_construction: missing; utf16_illegal_sequences: missing; utf16_roundtrip: missing; utf32_illegal_sequences: missing; utf32_roundtrip: missing; utf8_big_file: missing; utf8_illegal_sequences: missing; utf8_roundtrip: missing |
| `counters_SUITE` | 6 | 6/6 | 6/6 | 0 | 0 | none |
| `exception_SUITE` | 16 | 15/16 | 10/16 | 5 | 0 | change_exception_class: failed {test_case_failed,{wrong_exception_class,throw}}; error_3: failed {{badmatch,false}; line_numbers: failed {{badmatch, {'EXIT', {badarg; stacktrace: failed {{badmatch, {caught2, {error,[#Ref<0.0.0.5756>&#124;<0.222.0>]}; top_of_stacktrace: failed {{badmatch, {'EXIT', {badarg |
| `float_SUITE` | 15 | 14/15 | 12/15 | 2 | 0 | arith: failed {{badmatch,{{'EXIT',badarith}, [0, 3595386269724631416290548474634087135961411350516899931978349536063145215600570775211791172655337563430809179070287649284686426537789283655369350…; fp_drv: failed {'EXIT',error}, unknown_location |
| `fun_SUITE` | 18 | 17/18 | 15/18 | 2 | 0 | ordering: failed {badarg; t_fun_to_list: failed {{badmatch,"fun a-esc:b-esc/1"} |
| `guard_SUITE` | 6 | 6/6 | 4/6 | 2 | 0 | bad_arith: failed {badarith; type_tests: failed {badarg |
| `hash_SUITE` | 29 | 27/29 | 17/29 | 10 | 0 | test_native_record: failed {'EXIT',error}, unknown_location; test_phash2: failed {'EXIT',error}, unknown_location; test_phash2_10MB_plus_bin: failed {badarg; test_phash2_binary_aligned_and_unaligned_equal: failed {{badmatch,79194364}; test_phash2_deep_list: failed {{badmatch,114452829}; test_phash2_deep_tuple: failed {{badmatch,96295083}; test_phash2_shallow_long_list: failed {{badmatch,26899642}; test_phash2_with_super_large_unaligned_sub_binary: failed {{badmatch,31432554}; test_phash2_with_tiny_bin: failed {{badmatch,53964554}; test_phash2_with_tiny_unaligned_sub_binary: failed {{badmatch,104646675} |
| `list_bif_SUITE` | 9 | 8/9 | 7/9 | 1 | 0 | t_list_to_port: failed {badarg |
| `map_SUITE` | 64 | 63/64 | 63/64 | 0 | 0 | none |
| `num_bif_SUITE` | 11 | 11/11 | 11/11 | 0 | 0 | none |
| `op_SUITE` | 12 | 12/12 | 5/12 | 7 | -9 | combined_relops: missing; complex_relop: missing; is_in_range: missing; range_tests: missing; term_equivalence: missing; typed_relop: missing; unsafe_fusing: missing |
| `persistent_term_SUITE` | 22 | 22/22 | 0/22 | 22 | -9 | basic: failed {'EXIT',{badarg,[]}}, unknown_location; collisions: missing; destruction: missing; error_info: missing; gc_binary_orig: missing; get_all_race: missing; get_put_colliding_bucket: missing; get_trapping: missing; info: missing; info_trapping: missing; init_restart: missing; keys: missing; killed_while_trapping: missing; killed_while_trapping_erase: missing; killed_while_trapping_put: missing; non_message_signal: missing; off_heap_values: missing; purging: missing; put_erase_trapping: missing; shared_magic_ref: missing; sharing: missing; whole_message: missing |
| `receive_SUITE` | 14 | 12/14 | 5/14 | 7 | -9 | call_with_huge_message_queue: failed {test_case_failed,bad_ratio}; gh_5235_missing_save_reset: failed {timetrap_timeout,10000; gh_5235_recv_mark: failed {timetrap_timeout,10000; multi_recv_opt_clear: failed {test_case_failed,{ratio,73.37950460719765}}; prio_msg_while_in_receive: failed {badarg; receive_opt_deferred_save: failed {badarg; recv_marker_reserve: failed {badarg |
| `ref_SUITE` | 5 | 4/5 | 4/5 | 0 | 0 | none |
| `small_SUITE` | 13 | 13/13 | 8/13 | 5 | 0 | addition: failed {timetrap_timeout,60000; mul_add: failed {badarith; test_bitwise: failed {timetrap_timeout,60000; test_bsl: failed {timetrap_timeout,60000; test_bsr: failed {timetrap_timeout,60000 |
| `tuple_SUITE` | 20 | 20/20 | 20/20 | 0 | 0 | none |
| `unique_SUITE` | 2 | 1/2 | 0/2 | 1 | 0 | unique_integer_white_box: failed {badarg |

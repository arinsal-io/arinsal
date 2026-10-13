# OTP 29.1.1 suite pilot results

| Suite | Cases | erl pass | Arinsal pass | erl-pass/Arinsal-not | Arinsal exit | First failure line / notes |
|---|---:|---:|---:|---:|---:|---|
| `a_SUITE` | 4 | 3/4 | 2/4 | 1 | 0 | used_thread_specific_events: failed testcase_aborted |
| `after_SUITE` | 9 | 9/9 | 8/9 | 1 | 0 | receive_after_errors: failed testcase_aborted |
| `alloc_SUITE` | 13 | 1/13 | 0/13 | 1 | 0 | set_dyn_param: failed {{badmatch,notsup} |
| `application_SUITE` | 0 | 0 | 0 | 0 | 0 | trace: [{ct_run,wait_for_idle,0,[{file,"ct_run.erl"},{line,2616}]}, {ct_run,add_jobs,4,[{file,"ct_run.erl"},{line,2494}]}, {ct_run,do_run_test,3,[{file,"ct_run.erl"},{line,2268}]}, {ct_run,possibly_spawn,4,[{file,"ct_run.erl"},{line,1816}]}, {ct_run,compile_and_run,4,[{file,"ct_run.erl"},{line,1785}]}, {ct_run,run_dir,2,[{file,"ct_run.erl"},{line,1334}]}, {ct_run,run_test1,1,[{file,"ct_run.erl"},{line,898}]}] ct_util_server got EXIT from <0.81.0>: not_alive OTP_SUITE_RESULT=not_alive ; no Arinsal testcase results |
| `argparse_SUITE` | 31 | 31/31 | 31/31 | 0 | 0 | none |
| `array_SUITE` | 52 | 27/52 | 27/52 | 0 | 0 | none |
| `async_ports_SUITE` | 1 | 1/1 | 0/1 | 1 | 0 | permanent_busy_test: failed {'EXIT', {badarg, {erts_internal,port_command, [#Port<0.3>, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,… |
| `atomics_SUITE` | 6 | 6/6 | 6/6 | 0 | 0 | none |
| `base64_SUITE` | 19 | 19/19 | 19/19 | 0 | 0 | none |
| `base64_property_test_SUITE` | 24 | 0/24 | 0/24 | 0 | 0 | none |
| `beam_SUITE` | 12 | 12/12 | 10/12 | 2 | 0 | heap_sizes: failed {badarg; select_val: failed {function_clause |
| `beam_lib_SUITE` | 14 | 14/14 | 14/14 | 0 | 0 | none |
| `beam_literals_SUITE` | 14 | 14/14 | 13/14 | 1 | 0 | matching_more_bigs: failed {{badmatch,other} |
| `bif_SUITE` | 34 | 29/34 | 28/34 | 1 | 0 | is_process_alive_signal_from: failed {{badmatch,false} |
| `big_SUITE` | 23 | 23/23 | 22/23 | 1 | 0 | reductions: failed {failed |
| `binary_SUITE` | 55 | 42/55 | 36/55 | 6 | 0 | conversions: failed {badarg; deep: failed testcase_aborted; error_after_yield: failed testcase_aborted; gc_test: failed {'EXIT',{badmatch,[{50471079312,192,1}]}}, unknown_location; large: failed {badarg; trapping: failed testcase_aborted |
| `binary_module_SUITE` | 19 | 19/19 | 16/19 | 3 | 0 | bin_to_list: failed testcase_aborted; random_ref_comp: failed mismatch; random_ref_sr_comp: failed mismatch |
| `binary_property_test_SUITE` | 55 | 0/55 | 0/55 | 0 | 0 | none |
| `bs_bincomp_SUITE` | 6 | 6/6 | 6/6 | 0 | 0 | none |
| `bs_bit_binaries_SUITE` | 11 | 11/11 | 11/11 | 0 | 0 | none |
| `bs_construct_SUITE` | 31 | 30/31 | 29/31 | 1 | 0 | reductions: failed {if_clause |
| `bs_match_bin_SUITE` | 9 | 9/9 | 9/9 | 0 | 0 | none |
| `bs_match_int_SUITE` | 10 | 10/10 | 10/10 | 0 | 0 | none |
| `bs_match_misc_SUITE` | 20 | 20/20 | 20/20 | 0 | 0 | none |
| `bs_match_tail_SUITE` | 4 | 4/4 | 4/4 | 0 | 0 | none |
| `bs_utf_SUITE` | 8 | 8/8 | 8/8 | 0 | 0 | none |
| `busy_port_SUITE` | 18 | 18/18 | 18/18 | 0 | 0 | none |
| `c_SUITE` | 14 | 14/14 | 14/14 | 0 | 0 | none |
| `calendar_SUITE` | 17 | 17/17 | 17/17 | 0 | 0 | none |
| `calendar_prop_SUITE` | 9 | 0/9 | 0/9 | 0 | 0 | none |
| `call_trace_SUITE` | 14 | 14/14 | 10/14 | 4 | 0 | deep_exception: failed {'EXIT',normal}, unknown_location; exception_nocatch: failed {test_case_failed, {unexpected,[{trace,<0.356.0>,exit,normal}]}}; exception_trace: failed {'EXIT',normal}, unknown_location; return_trace: failed {'EXIT',normal}, unknown_location |
| `code_SUITE` | 29 | 27/29 | 13/29 | 14 | -9 | call_fun_before_load: missing; call_purged_fun_code_there: failed testcase_aborted; check_process_code_dirty_exec_proc: missing; check_process_code_signal_order: missing; code_permission_gc: failed testcase_aborted; constant_pools: missing; constant_refc_binaries: missing; coverage: missing; erl_544: missing; false_dependency: missing; fun_confusion: missing; max_heap_size: missing; t_copy_literals: missing; t_copy_literals_frags: missing |
| `code_coverage_SUITE` | 3 | 2/3 | 1/3 | 1 | 0 | get_coverage: failed {{badmatch |
| `code_parallel_load_SUITE` | 2 | 2/2 | 2/2 | 0 | 0 | none |
| `counters_SUITE` | 6 | 6/6 | 6/6 | 0 | 0 | none |
| `crypto_SUITE` | 6 | 6/6 | 6/6 | 0 | 0 | none |
| `ddll_SUITE` | 26 | 26/26 | 26/26 | 0 | 0 | none |
| `decode_packet_SUITE` | 10 | 10/10 | 9/10 | 1 | 0 | neg: failed {'EXIT',{badarg,[]}}, unknown_location |
| `dets_SUITE` | 51 | 48/51 | 39/51 | 9 | 0 | access: failed {{badmatch,{error,{file_error,[],port_died}}}; badarg: failed {function_clause; bags: failed {{badmatch,{error,{file_error,[],port_died}}}; duplicate_bags: failed {{badmatch,{error,{file_error,[],port_died}}}; open: failed {{badmatch,{error,{file_error,[],port_died}}}; otp_5402: failed {{badmatch,{error,{file_error,[],port_died}}}; repair_continuation: failed {{badmatch, {[true], {dets_cont,select,1, <<0,0,0,20,18,52,86,120,0,0,0,12,131,104,2,97, 3,119,1,99>>, {5496,5528,<<>>}, repair_continuation_table,<0.1011.0>, {match_spec,#Ref<0.0.…; select: failed {function_clause; sets: failed {{badmatch,{error,{file_error,[],port_died}}} |
| `dict_SUITE` | 7 | 7/7 | 7/7 | 0 | 0 | none |
| `digraph_SUITE` | 11 | 11/11 | 11/11 | 0 | 0 | none |
| `digraph_utils_SUITE` | 9 | 9/9 | 9/9 | 0 | 0 | none |
| `dirty_bif_SUITE` | 13 | 8/13 | 8/13 | 0 | 0 | none |
| `dirty_nif_SUITE` | 25 | 10/25 | 10/25 | 0 | 0 | none |
| `disk_log_SUITE` | 66 | 65/66 | 65/66 | 0 | 0 | none |
| `distribution_SUITE` | 56 | 11/56 | 11/56 | 0 | 0 | none |
| `driver_SUITE` | 50 | 41/50 | 39/50 | 2 | 0 | thread_mseg_alloc_cache_clean: skipped "No mseg_alloc"; z_test: failed {{badmatch,undefined} |
| `dump_SUITE` | 5 | 0/5 | 0/5 | 0 | 0 | none |
| `edlin_context_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `edlin_expand_SUITE` | 17 | 17/17 | 17/17 | 0 | 0 | none |
| `efile_SUITE` | 2 | 0/2 | 0/2 | 0 | 0 | none |
| `epp_SUITE` | 43 | 32/43 | 31/43 | 1 | 0 | otp_8911: failed {{badmatch,{ok,[{{i,6},0}]}} |
| `erl_anno_SUITE` | 12 | 12/12 | 12/12 | 0 | 0 | none |
| `erl_boot_server_SUITE` | 6 | 0/6 | 0/6 | 0 | 0 | none |
| `erl_debugger_SUITE` | 28 | 27/28 | 27/28 | 0 | 0 | none |
| `erl_distribution_SUITE` | 0 | 0 | 0 | 0 | 0 | trace: [{ct_run,wait_for_idle,0,[{file,"ct_run.erl"},{line,2616}]}, {ct_run,add_jobs,4,[{file,"ct_run.erl"},{line,2494}]}, {ct_run,do_run_test,3,[{file,"ct_run.erl"},{line,2268}]}, {ct_run,possibly_spawn,4,[{file,"ct_run.erl"},{line,1816}]}, {ct_run,compile_and_run,4,[{file,"ct_run.erl"},{line,1785}]}, {ct_run,run_dir,2,[{file,"ct_run.erl"},{line,1334}]}, {ct_run,run_test1,1,[{file,"ct_run.erl"},{line,898}]}] ct_util_server got EXIT from <0.81.0>: not_alive OTP_SUITE_RESULT=not_alive ; no Arinsal testcase results |
| `erl_distribution_wb_SUITE` | 4 | 1/4 | 1/4 | 0 | 0 | none |
| `erl_drv_thread_SUITE` | 3 | 0/3 | 0/3 | 0 | 0 | none |
| `erl_eval_SUITE` | 46 | 46/46 | 44/46 | 2 | 0 | custom_stacktrace: failed {function_clause; otp_14826: failed {function_clause |
| `erl_expand_records_SUITE` | 15 | 15/15 | 15/15 | 0 | 0 | none |
| `erl_internal_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `erl_link_SUITE` | 16 | 6/16 | 3/16 | 3 | 0 | links: failed {{badmatch,[{erl_link,process,<0.168.0>,linked,168}]}; otp_17127_local_random: failed {{badmatch,[{erl_link,process,<0.236.0>,linked,236}]}; process_monitors: failed {{badmatch |
| `erl_lint_SUITE` | 93 | 93/93 | 93/93 | 0 | 0 | none |
| `erl_pp_SUITE` | 47 | 46/47 | 46/47 | 0 | 0 | none |
| `erl_prim_loader_SUITE` | 14 | 6/14 | 6/14 | 0 | 0 | none |
| `erl_scan_SUITE` | 13 | 13/13 | 13/13 | 0 | 0 | none |
| `erpc_SUITE` | 24 | 3/24 | 1/24 | 2 | 0 | multicall_always_spawn: failed testcase_aborted; timeout_limit: failed {test_case_failed, "The ?MAX_INT_TIMEOUT define in erpc.erl needs to be updated to reflect max timeout value in a receive/after..."} |
| `error_handler_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `error_logger_SUITE` | 13 | 11/13 | 11/13 | 0 | 0 | none |
| `error_logger_h_SUITE` | 4 | 0/4 | 0/4 | 0 | 0 | none |
| `error_logger_warn_SUITE` | 0 | 0 | 0 | 0 | 0 | ize: 44 reductions: 117850 current_stacktrace: [{ct_run,wait_for_idle,0,[{file,"ct_run.erl"},{line,2616}]}, {ct_run,add_jobs,4,[{file,"ct_run.erl"},{line,2494}]}, {ct_run,do_run_test,3,[{file,"ct_run.erl"},{line,2268}]}, {ct_run,possibly_spawn,4,[{file,"ct_run.erl"},{line,1816}]}, {ct_run,compile_and_run,4,[{file,"ct_run.erl"},{line,1785}]}, {ct_run,run_dir,2,[{file,"ct_run.erl"},{line,1334}]}, {ct_run,run_test1,1,[{file,"ct_run.erl"},{line,898}]}] OTP_SUITE_RESULT=not_alive ; no Arinsal testcase results |
| `erts_debug_SUITE` | 8 | 7/8 | 7/8 | 0 | 0 | none |
| `escript_SUITE` | 17 | 17/17 | 17/17 | 0 | 0 | none |
| `estone_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `ets_SUITE` | 162 | 160/162 | 36/162 | 124 | -9 | bad_table: missing; badfile: missing; bound_maps: missing; compress_magic_ref: missing; delete_unfix_race: missing; doctests: missing; dups: missing; error_info: missing; ets_all: missing; evil_rename: missing; evil_update_counter: missing; exit_large_table_owner: missing; exit_many_large_table_owner: missing; exit_many_many_tables_owner: missing; exit_many_tables_owner: missing; fixtable_insert: missing; fixtable_iter_bag: missing; fixtable_next: missing; fold_badarg: missing; fold_empty: missing; foldl: missing; foldl_ordered: missing; foldr: missing; foldr_ordered: missing; give_away: missing; grow_pseudo_deleted: missing; grow_shrink: missing; heavy_concurrent: missing; heavy_lookup: missing; heavy_lookup_element: missing; heir: missing; heir_2: missing; info_binary_stress: missing; info_whereis_busy: missing; insert_trap_delete: missing; insert_trap_rename: missing; interface_equality: missing; massive_ets_all: missing; match_heavy: missing; member: missing; memory: missing; meta_lookup_named_read: missing; meta_lookup_named_write: missing; meta_lookup_unnamed_read: missing; meta_lookup_unnamed_write: missing; meta_newdel_named: missing; meta_newdel_unnamed: missing; meta_wb: missing; ms_excessive_nesting: missing; ordered: missing; ordered_match: missing; otp_10182: missing; otp_5340: missing; otp_6338: missing; otp_6842_select_1000: missing; otp_7665: missing; otp_8166: missing; otp_8732: missing; otp_9423: missing; otp_9932: missing; partly_bound: missing; racy_rename: missing; rename: missing; rename_unnamed: missing; select_bound_chunk: missing; select_fail: missing; select_fixtab_owner_change: missing; select_mbuf_trapping: missing; setopts: missing; shrink_pseudo_deleted: missing; smp_fixed_delete: missing; smp_insert: missing; smp_select_delete: missing; smp_select_replace: missing; smp_unfix_fix: missing; t_bucket_disappears: missing; t_delete_all_objects: missing; t_delete_all_objects_trap: missing; t_delete_object: missing; t_ets_dets: missing; t_init_table: missing; t_insert_list: missing; t_insert_list_bag: missing; t_insert_list_delete_parallel: missing; t_insert_list_delete_set: missing; t_insert_list_duplicate_bag: missing; t_insert_list_insert_order_preserved: missing; t_insert_list_kill_process: missing; t_insert_list_parallel: missing; t_insert_list_set: missing; t_insert_new: missing; t_named_select: missing; t_repair_continuation: missing; t_select_delete: missing; t_select_flatmap_term_copy_bug: missing; t_select_hashmap_term_copy_bug: missing; t_select_pam_stack_overflow_bug: missing; t_select_replace: missing; t_select_replace_next_bug: missing; t_select_reverse: missing; t_test_ms: missing; t_whitebox: missing; tab2file: missing; tab2file2: missing; tab2list: missing; tabfile_ext1: missing; tabfile_ext2: missing; tabfile_ext3: missing; tabfile_ext4: missing; take: missing; test_decentralized_counters_setting: missing; test_table_memory_concurrency: missing; test_table_size_concurrency: missing; test_throughput_benchmark: missing; types: missing; update_counter: missing; update_counter_table_growth: missing; update_counter_with_default: missing; update_counter_with_default_bad_default: missing; update_counter_with_default_bad_pos: missing; update_element: missing; update_element_default: missing; whereis_table: missing; write_concurrency: missing |
| `ets_property_test_SUITE` | 4 | 0/4 | 0/4 | 0 | 0 | none |
| `ets_tough_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `evil_SUITE` | 9 | 9/9 | 9/9 | 0 | 0 | none |
| `exception_SUITE` | 16 | 14/16 | 14/16 | 0 | 0 | none |
| `file_SUITE` | 91 | 83/91 | 78/91 | 5 | 0 | cur_dir_0: failed {function_clause; e_rename: failed {{badmatch,{error,enotempty}}; ipread: failed testcase_aborted; make_del_dir: failed {{case_clause,{error,enotempty}}; zstd: failed {{badmatch,{error,badarg}} |
| `file_name_SUITE` | 4 | 2/4 | 2/4 | 0 | 0 | none |
| `file_sorter_SUITE` | 19 | 19/19 | 19/19 | 0 | 0 | none |
| `filelib_SUITE` | 22 | 21/22 | 21/22 | 0 | 0 | none |
| `filename_SUITE` | 25 | 25/25 | 25/25 | 0 | 0 | none |
| `fixtable_SUITE` | 7 | 7/7 | 7/7 | 0 | 0 | none |
| `float_SUITE` | 15 | 14/15 | 14/15 | 0 | 0 | none |
| `format_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `fun_SUITE` | 18 | 17/18 | 16/18 | 1 | 0 | spurious_badfun: failed testcase_aborted |
| `gb_sets_property_test_SUITE` | 18 | 0/18 | 0/18 | 0 | 0 | none |
| `gc_SUITE` | 10 | 10/10 | 8/10 | 2 | 0 | gc_dirty_exec_proc: failed {test_case_failed, "Unexpected message: {trace,<0.241.0>,gc_minor_start,\n [{wordsize,0},\n {old_heap_block_size,0},\n …; gc_signal_order: failed {{badmatch,true} |
| `gen_event_SUITE` | 31 | 31/31 | 28/31 | 3 | 0 | send_request_check_reqid_collection: failed {{badmatch, {{error,{killed,<0.422.0>}}, req2, #{#Ref<0.57925.2005663752.34024> => req1, #Ref<0.57925.2005663752.34027> => req3, #Ref<0.57925.2005663752.34028> => req4}}}; send_request_receive_reqid_collection: failed {{badmatch, {{error,{killed,<0.408.0>}}, req2, #{#Ref<0.57925.2005663751.31258> => req1, #Ref<0.57925.2005663751.31261> => req3, #Ref<0.57925.2005663751.31262> => req4}}}; send_request_wait_reqid_collection: failed {{badmatch, {{error,{killed,<0.415.0>}}, req2, #{#Ref<0.57925.2005663752.33758> => req1, #Ref<0.57925.2005663752.33761> => req3, #Ref<0.57925.2005663752.33762> => req4}}} |
| `gen_fsm_SUITE` | 37 | 37/37 | 37/37 | 0 | 0 | none |
| `gen_sctp_SUITE` | 35 | 0/35 | 0/35 | 0 | 0 | none |
| `gen_server_SUITE` | 74 | 57/74 | 52/74 | 5 | 0 | auto_hibernate: failed {test_case_failed,is_not_hibernated}; handle_event_timeout: failed {test_case_failed,is_not_hibernated}; handle_event_timeout_infinity: failed {test_case_failed,is_not_hibernated}; hibernate: failed {test_case_failed,is_not_hibernated}; start_event_timeout: failed {test_case_failed,is_not_hibernated} |
| `gen_statem_SUITE` | 62 | 59/62 | 54/62 | 5 | 0 | auto_hibernate: failed {test_case_failed,not_in_expected_current_function}; hibernate: failed {test_case_failed,not_in_expected_current_function}; send_request_check_reqid_collection: failed {{badmatch, {{error,{killed,<0.1185.0>}}, req2, #{#Ref<0.40965.396099585.14786> => req1, #Ref<0.40965.396099585.14789> => req3}}}; send_request_receive_reqid_collection: failed {{badmatch, {{error,{killed,<0.1165.0>}}, req2, #{#Ref<0.40965.396099585.14275> => req1, #Ref<0.40965.396099585.14278> => req3}}}; send_request_wait_reqid_collection: failed {{badmatch, {{error,{killed,<0.1175.0>}}, req2, #{#Ref<0.40965.396099585.14509> => req1, #Ref<0.40965.396099585.14512> => req3}}} |
| `gen_tcp_api_SUITE` | 30 | 26/30 | 6/30 | 20 | 0 | s_accept_with_explicit_socket_backend: failed testcase_aborted_or_killed, unknown_location; t_accept_inet6_tclass: failed {{not_ok,{error,einval}}; t_fdconnect: failed {test_case_failed, {unexpected_connect_error,exbadport; t_fdopen: failed testcase_aborted_or_killed, unknown_location; t_implicit_inet6: skipped "Accept failed: einval"; t_local_basic: skipped AF_LOCAL not supported; t_local_fdopen: skipped AF_LOCAL not supported; t_local_fdopen_connect: skipped AF_LOCAL not supported; t_local_fdopen_connect_unbound: skipped AF_LOCAL not supported; t_local_fdopen_listen: skipped AF_LOCAL not supported; t_local_fdopen_listen_unbound: skipped AF_LOCAL not supported; t_local_unbound: skipped AF_LOCAL not supported; t_module_connect: failed testcase_aborted_or_killed, unknown_location; t_recv_delim: failed testcase_aborted_or_killed, unknown_location; t_recv_eof: failed testcase_aborted_or_killed, unknown_location; t_recv_timeout: failed testcase_aborted_or_killed, unknown_location; t_shutdown_async: failed testcase_aborted_or_killed, unknown_location; t_shutdown_both: failed testcase_aborted_or_killed, unknown_location; t_shutdown_write: failed testcase_aborted_or_killed, unknown_location; t_simple_local_sockaddr_in_send_recv: failed testcase_aborted_or_killed, unknown_location |
| `gen_tcp_echo_SUITE` | 9 | 9/9 | 4/9 | 5 | -9 | active_echo: failed testcase_aborted; active_once_echo: failed testcase_aborted; passive_echo: failed testcase_aborted; slow_active_echo: failed testcase_aborted; slow_passive_echo: failed testcase_aborted |
| `gen_tcp_misc_SUITE` | 68 | 51/68 | 5/68 | 46 | -9 | accept_system_limit: missing; accept_timeout: missing; accept_timeouts_in_order: missing; accept_timeouts_in_order2: missing; accept_timeouts_in_order3: missing; accept_timeouts_in_order4: missing; accept_timeouts_in_order5: missing; accept_timeouts_in_order6: missing; accept_timeouts_in_order7: missing; accept_timeouts_mixed: missing; active_n: failed testcase_aborted_or_killed, unknown_location; active_n_closed: failed testcase_aborted_or_killed, unknown_location; busy_disconnect_active: failed testcase_aborted_or_killed, unknown_location; busy_disconnect_passive: failed testcase_aborted_or_killed, unknown_location; busy_send: failed testcase_aborted_or_killed, unknown_location; data_before_close: failed testcase_aborted_or_killed, unknown_location; econnreset_after_async_send_active: failed testcase_aborted_or_killed, unknown_location; econnreset_after_async_send_active_once: failed testcase_aborted_or_killed, unknown_location; econnreset_after_async_send_passive: failed testcase_aborted_or_killed, unknown_location; econnreset_after_sync_send: failed testcase_aborted_or_killed, unknown_location; fill_sendq: missing; http_bad_packet: failed testcase_aborted_or_killed, unknown_location; killing_acceptor: missing; killing_multi_acceptors: missing; killing_multi_acceptors2: missing; linger_zero: failed testcase_aborted_or_killed, unknown_location; linger_zero_sndbuf: failed testcase_aborted_or_killed, unknown_location; multi_accept_close_listen: missing; otp_7731: missing; otp_7816: missing; otp_8102: missing; otp_9389: missing; partial_recv_and_close: missing; partial_recv_and_close_2: missing; partial_recv_and_close_3: missing; passive_sockets: failed {test_case_failed, {"Did not get {error, closed} before other error", {error,timeout}}}; primitive_accept: missing; several_accepts_in_one_go: missing; show_econnreset_active: failed testcase_aborted_or_killed, unknown_location; show_econnreset_active_once: failed testcase_aborted_or_killed, unknown_location; show_econnreset_passive: failed testcase_aborted_or_killed, unknown_location; shutdown_active: failed testcase_aborted_or_killed, unknown_location; shutdown_passive: failed testcase_aborted_or_killed, unknown_location; shutdown_pending: failed testcase_aborted_or_killed, unknown_location; wrapping_oct: missing; zombie_sockets: missing |
| `gen_tcp_socket_SUITE` | 11 | 11/11 | 0/11 | 11 | 0 | active_1: failed testcase_aborted; active_20: failed testcase_aborted; active_5: failed testcase_aborted; active_false: failed testcase_aborted; active_once: failed testcase_aborted; active_raw: failed testcase_aborted; active_true: failed testcase_aborted; socket_packet: failed testcase_aborted; socket_packet_buf: failed testcase_aborted; socket_packet_cheat: failed testcase_aborted; socket_raw: failed testcase_aborted |
| `gen_udp_SUITE` | 47 | 36/47 | 21/47 | 15 | 0 | active_n: failed {error,udp_passive_failure}; binary_passive_recv: failed {{badmatch,{error,einval}}; buffer_size: failed {test_case_failed, {reply_mismatch,2, {timeout,[]}, [correct], 8448, {ok,[{sndbuf,9728},{recbuf,9216}]}}}; local_fdopen: failed {{not_ok,{error,exbadport}}; local_fdopen_unbound: failed {{not_ok,{error,exbadport}}; max_buffer_size: failed {test_case_failed,{unexpected_buffer_size,9216}}; open_fd: failed {{badmatch,{error,exbadport}}; otp_18323_open: failed {{badmatch,{error,einval}}; otp_20102: failed {{badmatch,{error,timeout}}; reconnect: skipped "Failed open initial port: einval"; recv_poll_after_active_once: failed testcase_aborted; recvtclass: failed {{badmatch,{error,einval}}; sendtclass: failed {{badmatch,{error,einval}}; t_module_open: failed {listen,einval}; t_simple_local_sockaddr_in_send_recv: failed {test_case_failed,receive_timeout} |
| `global_SUITE` | 0 | 0 | 0 | 0 | 0 | trace: [{ct_run,wait_for_idle,0,[{file,"ct_run.erl"},{line,2616}]}, {ct_run,add_jobs,4,[{file,"ct_run.erl"},{line,2494}]}, {ct_run,do_run_test,3,[{file,"ct_run.erl"},{line,2268}]}, {ct_run,possibly_spawn,4,[{file,"ct_run.erl"},{line,1816}]}, {ct_run,compile_and_run,4,[{file,"ct_run.erl"},{line,1785}]}, {ct_run,run_dir,2,[{file,"ct_run.erl"},{line,1334}]}, {ct_run,run_test1,1,[{file,"ct_run.erl"},{line,898}]}] ct_util_server got EXIT from <0.81.0>: not_alive OTP_SUITE_RESULT=not_alive ; no Arinsal testcase results |
| `global_group_SUITE` | 10 | 0/10 | 0/10 | 0 | 0 | none |
| `graph_SUITE` | 20 | 20/20 | 20/20 | 0 | 0 | none |
| `group_SUITE` | 1 | 1/1 | 0/1 | 1 | 0 | check_unknown_message: failed {'EXIT',timeout_value}, unknown_location |
| `guard_SUITE` | 6 | 6/6 | 6/6 | 0 | 0 | none |
| `hash_SUITE` | 29 | 27/29 | 23/29 | 4 | 0 | test_phash2_with_large_bin: auto_skipped {failed, {ct_framework,init_tc, {testcase_aborted, {arinsal_case_timeout, test_phash2_with_short_list,20000}}}}; test_phash2_with_large_unaligned_sub_binary: failed testcase_aborted; test_phash2_with_small_unaligned_sub_binary: failed testcase_aborted; test_phash2_with_super_large_unaligned_sub_binary: failed testcase_aborted |
| `hash_property_test_SUITE` | 3 | 0/3 | 0/3 | 0 | 0 | none |
| `heart_SUITE` | 12 | 0/12 | 0/12 | 0 | 0 | none |
| `hello_SUITE` | 1 | 1/1 | 0/1 | 1 | 0 | hello: failed {{badmatch |
| `hibernate_SUITE` | 10 | 10/10 | 10/10 | 0 | 0 | none |
| `id_transform_SUITE` | 1 | 0/1 | 0/1 | 0 | 0 | none |
| `inet_SUITE` | 36 | 19/36 | 14/36 | 5 | 0 | getif: failed {'EXIT',error}, unknown_location; getifaddrs: failed {{badmatch,{error,einval}}; getservbyname_overflow: failed {{badmatch,{error,exbadport}}; socknames_tcp: skipped {listen_socket,exbadport}; socknames_udp: skipped {listen_socket,exbadport} |
| `inet_res_SUITE` | 0 | 0 | 0 | 0 | 1 | suite/helper compile failed (1): /var/folders/v5/w846m1655ylfpfnhmtgfbnvm0000gn/T/otp-inet_res-source-mb7au8vi/test/code_a_test.beam: Module name 'code_b_test' does not match file name 'code_a_test' ; suite/helper compile failed (1): /var/folders/v5/w846m1655ylfpfnhmtgfbnvm0000gn/T/otp-inet_res-source-mb7au8vi/test/code_a_test.beam: Module name 'code_b_test' does not match file name 'code_a_test' |
| `inet_sockopt_SUITE` | 18 | 14/18 | 9/18 | 5 | 0 | large_raw: failed {test_case_failed, {unexpected, {ok,[{raw,65535,128,<<1,0,0,0,10,0,0,0>>}]}}}; large_raw_getbin: failed {test_case_failed, {unexpected, {ok,[{raw,65535,128,<<1,0,0,0,10,0,0,0>>}]}}}; loop_all: failed {listen,einval}; multiple_raw: failed {{badmatch,{error,einval}}; multiple_raw_getbin: failed {{badmatch,{error,einval}} |
| `init_SUITE` | 20 | 10/20 | 6/20 | 4 | 0 | dash_S: failed {badarg; dash_extra: failed {badarg; dash_run: failed {badarg; dash_s: failed {badarg |
| `interactive_shell_SUITE` | 60 | 3/60 | 3/60 | 0 | 0 | none |
| `io_SUITE` | 57 | 54/57 | 53/57 | 1 | 0 | error_info: failed {test_case_failed,{6,errors}} |
| `io_ansi_SUITE` | 6 | 0/6 | 0/6 | 0 | 0 | none |
| `io_proto_SUITE` | 28 | 0/28 | 0/28 | 0 | 0 | none |
| `iovec_SUITE` | 13 | 13/13 | 13/13 | 0 | 0 | none |
| `jit_SUITE` | 6 | 2/6 | 1/6 | 1 | 0 | named_labels: auto_skipped {failed, {jit_SUITE,init_per_testcase, {badarg |
| `json_SUITE` | 28 | 23/28 | 23/28 | 0 | 0 | none |
| `kernel_SUITE` | 3 | 2/3 | 1/3 | 1 | 0 | refc: failed {{badmatch,false} |
| `kernel_config_SUITE` | 2 | 1/2 | 1/2 | 0 | 0 | none |
| `lcnt_SUITE` | 5 | 0/5 | 0/5 | 0 | 0 | none |
| `list_bif_SUITE` | 9 | 8/9 | 8/9 | 0 | 0 | none |
| `lists_SUITE` | 78 | 78/78 | 78/78 | 0 | 0 | none |
| `lists_property_test_SUITE` | 107 | 0/107 | 0/107 | 0 | 0 | none |
| `log_mf_h_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `logger_SUITE` | 30 | 26/30 | 26/30 | 0 | 0 | none |
| `logger_disk_log_h_SUITE` | 29 | 27/29 | 26/29 | 1 | 0 | op_switch_to_flush: failed testcase_aborted |
| `logger_env_var_SUITE` | 34 | 3/34 | 3/34 | 0 | 0 | none |
| `logger_filters_SUITE` | 3 | 3/3 | 3/3 | 0 | 0 | none |
| `logger_formatter_SUITE` | 18 | 18/18 | 18/18 | 0 | 0 | none |
| `logger_legacy_SUITE` | 6 | 6/6 | 6/6 | 0 | 0 | none |
| `logger_olp_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `logger_proxy_SUITE` | 8 | 6/8 | 5/8 | 1 | 0 | remote_emulator: failed {{case_clause,#Ref<0.55602.2008547329.248099>} |
| `logger_simple_h_SUITE` | 6 | 3/6 | 3/6 | 0 | 0 | none |
| `logger_std_h_SUITE` | 0 | 0 | 0 | 0 | 1 | suite/helper compile failed (1): /var/folders/v5/w846m1655ylfpfnhmtgfbnvm0000gn/T/otp-logger_std_h-source-nd0h385f/test/code_a_test.beam: Module name 'code_b_test' does not match file name 'code_a_test' ; suite/helper compile failed (1): /var/folders/v5/w846m1655ylfpfnhmtgfbnvm0000gn/T/otp-logger_std_h-source-nd0h385f/test/code_a_test.beam: Module name 'code_b_test' does not match file name 'code_a_test' |
| `logger_stress_SUITE` | 13 | 0/13 | 0/13 | 0 | 0 | none |
| `lttng_SUITE` | 9 | 0/9 | 0/9 | 0 | 0 | none |
| `map_SUITE` | 64 | 63/64 | 63/64 | 0 | 0 | none |
| `maps_SUITE` | 32 | 32/32 | 31/32 | 1 | 0 | error_info: failed {test_case_failed,{1,errors}} |
| `match_spec_SUITE` | 30 | 28/30 | 23/30 | 5 | 0 | ms_trace2: failed {test_case_failed,timeout}; ms_trace3: failed {test_case_failed, {got_unexpected, {trace,<0.381.0>,'receive', {<0.380.0>,#Ref<0.25488.3057647617.125239>, started}}}}; silent_no_ms: failed {test_case_failed,timeout}; test_2: failed {test_case_failed,timeout}; test_4b: failed {test_case_failed,timeout} |
| `math_SUITE` | 4 | 4/4 | 4/4 | 0 | 0 | none |
| `message_queue_data_SUITE` | 5 | 4/5 | 3/5 | 1 | 0 | total_heap_size: failed {{badmatch,false} |
| `module_info_SUITE` | 6 | 6/6 | 5/6 | 1 | 0 | nifs: failed {{badmatch,false} |
| `monitor_SUITE` | 25 | 16/25 | 16/25 | 0 | 0 | none |
| `ms_transform_SUITE` | 28 | 28/28 | 28/28 | 0 | 0 | none |
| `mtx_SUITE` | 22 | 22/22 | 21/22 | 1 | 0 | hammer_sched_freqread_tryrwlock: failed testcase_aborted |
| `multi_load_SUITE` | 3 | 3/3 | 3/3 | 0 | 0 | none |
| `native_record_SUITE` | 10 | 9/10 | 9/10 | 0 | 0 | none |
| `nested_SUITE` | 4 | 4/4 | 4/4 | 0 | 0 | none |
| `net_SUITE` | 11 | 0/11 | 0/11 | 0 | 0 | none |
| `nif_SUITE` | 80 | 78/80 | 0/80 | 78 | -6 | api_macros: missing; basic: failed {check_io_debug,error,{badmatch,undefined}}; binaries: missing; consume_timeslice: missing; demonitor_process: missing; from_array: missing; get_atom: missing; get_atom_length: missing; get_length: missing; get_string: missing; get_string_length: missing; heap_frag: missing; iolist_as_binary: missing; is_checks: missing; load_traced_nif: missing; make_atom: missing; make_existing_atoms: missing; make_new_atoms: missing; make_string: missing; many_args: missing; maps: missing; match_state_arg: missing; monitor_frenzy: missing; monitor_process_a: missing; monitor_process_b: missing; monitor_process_c: missing; monitor_process_d: missing; monitor_process_purge: missing; neg: missing; nif_atom_out_cache_index: missing; nif_atom_too_long: missing; nif_binary_to_term: missing; nif_convert_time_unit: missing; nif_cpu_time: missing; nif_exception: missing; nif_internal_hash: missing; nif_internal_hash_salted: missing; nif_ioq: missing; nif_is_port_alive: missing; nif_is_process_alive: missing; nif_monotonic_time: missing; nif_nan_and_inf: missing; nif_now_time: missing; nif_phash2: missing; nif_port_command: missing; nif_schedule: missing; nif_snprintf: missing; nif_term_size: missing; nif_term_to_binary: missing; nif_term_type: missing; nif_time_offset: missing; nif_unique_integer: missing; nif_whereis: missing; nif_whereis_parallel: missing; nif_whereis_threaded: missing; non_exported_nif: failed {check_io_debug,error,{badmatch,undefined}}; otp_9668: missing; otp_9828: missing; pid: missing; reload_error: missing; resource: missing; resource_binary: missing; resource_takeover: missing; reverse_list_test: missing; select: missing; select_steal: missing; send: missing; send2: missing; send3: missing; send_threaded: missing; t_call_nif_early: missing; t_dynamic_resource_call: missing; t_load_race: missing; t_nifs_attrib: missing; t_on_load: missing; threading: missing; types: missing; upgrade: failed {check_io_debug,error,{badmatch,undefined}} |
| `node_container_SUITE` | 20 | 12/20 | 12/20 | 0 | 0 | none |
| `nofrag_SUITE` | 5 | 5/5 | 4/5 | 1 | 0 | debug_breakpoint: failed {'EXIT', {fw_error, {ct_framework,error_notification, {{try_clause, [erlang_v1,nofrag_SUITE, {[{attribute, {1,1}, file, {"/var/folders/v5/w846m1655ylfpfnhmtgfbnvm0000gn/T/otp-nofra… |
| `num_bif_SUITE` | 11 | 11/11 | 11/11 | 0 | 0 | none |
| `op_SUITE` | 12 | 12/12 | 12/12 | 0 | 0 | none |
| `os_SUITE` | 21 | 19/21 | 19/21 | 0 | 0 | none |
| `os_signal_SUITE` | 10 | 10/10 | 9/10 | 1 | 0 | t_sigchld: failed {{badmatch |
| `pdict_SUITE` | 8 | 8/8 | 8/8 | 0 | 0 | none |
| `peer_SUITE` | 31 | 15/31 | 15/31 | 0 | 0 | none |
| `persistent_term_SUITE` | 22 | 22/22 | 22/22 | 0 | 0 | none |
| `pg_SUITE` | 28 | 8/28 | 8/28 | 0 | 0 | none |
| `pool_SUITE` | 2 | 0/2 | 0/2 | 0 | 0 | none |
| `port_SUITE` | 74 | 68/74 | 66/74 | 2 | 0 | exit_status_multi_scheduling_block: failed {{badmatch,false}; port_exit_demonitor_race: failed {'EXIT', {unexpected_msg, {'DOWN',#Ref<0.23037.645660676.14784>,port, #Port<0.3018203>,normal}}}, unknown_location |
| `port_bif_SUITE` | 9 | 9/9 | 4/9 | 5 | 0 | busy_options: failed {{badmatch,false}; connect: failed {badarg; control: failed {badarg; port_info1: failed {{badmatch,false}; port_info2: failed {badarg |
| `port_trace_SUITE` | 21 | 21/21 | 6/21 | 15 | 0 | call: failed "Unexpected trace messages"; command: failed "Unexpected trace messages"; connect: failed "Unexpected trace messages"; control: failed "Unexpected trace messages"; driver_output_term: failed "Unexpected trace messages"; driver_send_term: failed "Unexpected trace messages"; failure_eof: failed "Unexpected trace messages"; open_close: failed "Unexpected trace messages"; output: failed "Unexpected trace messages"; output2: failed "Unexpected trace messages"; output_binary: failed "Unexpected trace messages"; output_term: failed "Unexpected trace messages"; outputv: failed "Unexpected trace messages"; port_specs: failed {{badmatch,{tracer,<0.255.0>}}; send_term: failed "Unexpected trace messages" |
| `prim_eval_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `prim_file_SUITE` | 41 | 41/41 | 37/41 | 4 | 0 | cur_dir_0: failed {function_clause; e_rename: failed {{badmatch,{error,enotempty}}; large_write: skipped "Less than 5 GByte free disk/mem"; make_del_dir: failed {{case_clause,{error,enotempty}} |
| `prim_net_SUITE` | 6 | 0/6 | 0/6 | 0 | 0 | none |
| `proc_lib_SUITE` | 17 | 16/17 | 16/17 | 0 | 0 | none |
| `process_SUITE` | 104 | 25/104 | 68/104 | 0 | 0 | none |
| `process_max_heap_size_SUITE` | 1 | 1/1 | 0/1 | 1 | 0 | immediate_termination: failed {{badmatch, {{a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a, a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a, a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a, a,a,a,a,a,a,a,a,a,a,a,a… |
| `proplists_SUITE` | 4 | 4/4 | 4/4 | 0 | 0 | none |
| `pseudoknot_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `qlc_SUITE` | 65 | 64/65 | 62/65 | 2 | 0 | pre_fun: failed testcase_aborted_or_killed, unknown_location; process_dies: failed {'EXIT',{badmatch,{links,[<0.1835.0>]}}}, unknown_location |
| `queue_SUITE` | 7 | 7/7 | 7/7 | 0 | 0 | none |
| `queue_property_test_SUITE` | 72 | 0/72 | 0/72 | 0 | 0 | none |
| `ram_file_SUITE` | 9 | 8/9 | 0/9 | 8 | 0 | get_file_and_size: failed testcase_aborted; large_file_errors: failed testcase_aborted; large_file_light: failed testcase_aborted; open_modes: failed testcase_aborted; position: failed testcase_aborted; pread_pwrite: failed testcase_aborted; sync: failed testcase_aborted; truncate: failed testcase_aborted |
| `rand_SUITE` | 29 | 29/29 | 28/29 | 1 | 0 | measure: failed testcase_aborted |
| `random_SUITE` | 3 | 3/3 | 3/3 | 0 | 0 | none |
| `re_SUITE` | 37 | 36/37 | 28/37 | 8 | -9 | error_handling: failed {{badmatch,{match,[{1,1},{1,1}]}}; error_info: failed {test_case_failed,{9,errors}}; kill_yielding: missing; pcre2: failed {{badmatch,64}; replace_autogen: failed {{badmatch,<<"XabceXvWdefghi">>}; split_autogen: failed {{badmatch,<<"Xabc:defghi">>}; sub_binaries: failed {{badmatch,160}; yield_on_subject_validation: failed {{badmatch,false} |
| `receive_SUITE` | 14 | 12/14 | 12/14 | 0 | 0 | none |
| `records_SUITE` | 2 | 1/2 | 0/2 | 1 | 0 | doctests: failed {{7,errors} |
| `ref_SUITE` | 5 | 4/5 | 4/5 | 0 | 0 | none |
| `register_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `rpc_SUITE` | 19 | 3/19 | 2/19 | 1 | 0 | timeout_limit: failed {test_case_failed, "The ?MAX_INT_TIMEOUT define in rpc.erl needs to be updated to reflect max timeout value in a receive/after..."} |
| `save_calls_SUITE` | 2 | 2/2 | 1/2 | 1 | 0 | save_calls_1: failed {badarg |
| `scheduler_SUITE` | 25 | 14/25 | 14/25 | 0 | 0 | none |
| `select_SUITE` | 2 | 2/2 | 2/2 | 0 | 0 | none |
| `send_term_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |
| `sendfile_SUITE` | 14 | 14/14 | 1/14 | 13 | 0 | t_sendfile_big_all: failed {{badmatch,{error,exbadport}}; t_sendfile_big_size: failed {{badmatch,{error,exbadport}}; t_sendfile_closeduring: failed {{case_clause,{error,exbadport}}; t_sendfile_crashduring: failed {{badmatch, {{badmatch,{error,exbadport}}; t_sendfile_many_small: failed {{badmatch,{error,exbadport}}; t_sendfile_offset: failed {{badmatch,{error,exbadport}}; t_sendfile_partial: failed {{badmatch,{error,exbadport}}; t_sendfile_recvafter: failed {{badmatch,{error,exbadport}}; t_sendfile_recvafter_remoteclose: failed {{badmatch,{error,exbadport}}; t_sendfile_recvduring: failed {error, {case_clause,{error,exbadport}}; t_sendfile_sendafter: failed {{badmatch,{error,exbadport}}; t_sendfile_sendduring: failed {error, {case_clause,{error,exbadport}}; t_sendfile_small: failed {{badmatch,{error,exbadport}} |
| `sensitive_SUITE` | 12 | 12/12 | 11/12 | 1 | 0 | running_trace: failed {{badmatch |
| `seq_trace_SUITE` | 20 | 13/20 | 6/20 | 7 | 0 | call: failed testcase_aborted; inherit_on_spawn: failed {{case_clause,{error,timeout}}; port: failed {'EXIT',badsig}, unknown_location; recv: failed {{badmatch; send: failed {{badmatch; token_set_get: failed {{badmatch,{0,17,0,<0.162.0>,0}}; trace_exit: failed {{badmatch,{error,timeout}} |
| `sets_SUITE` | 21 | 21/21 | 21/21 | 0 | 0 | none |
| `sets_property_test_SUITE` | 21 | 0/21 | 0/21 | 0 | 0 | none |
| `shell_SUITE` | 37 | 30/37 | 26/37 | 4 | 0 | forget: failed {{badmatch, "exception error: {function_clause,[{shell,f,1}]}"}; otp_6554: failed {{badmatch,"exception error: {function_clause,"}; records: failed {{badmatch, "exception error: {function_clause,[{shell,rd,2}]}"}; start_restricted_from_shell: failed {{badmatch, "exception exit: {{restricted_shell_bad_return,non_conforming_reply},"} |
| `shell_docs_SUITE` | 12 | 11/12 | 11/12 | 0 | 0 | none |
| `shell_docs_markdown_SUITE` | 99 | 99/99 | 99/99 | 0 | 0 | none |
| `sigils_SUITE` | 3 | 3/3 | 3/3 | 0 | 0 | none |
| `signal_SUITE` | 39 | 22/39 | 21/39 | 2 | 0 | dirty_signal_handling_race: failed {'EXIT',driver_unloaded}, unknown_location; dirty_signal_handling_race_dirty_access: failed {'EXIT',driver_unloaded}, unknown_location |
| `slave_SUITE` | 4 | 0/4 | 0/4 | 0 | 0 | none |
| `small_SUITE` | 13 | 13/13 | 12/13 | 1 | 0 | mul_add: failed {{badmatch, {'EXIT', {badarith |
| `smoke_test_SUITE` | 3 | 2/3 | 2/3 | 0 | 0 | none |
| `socket_SUITE` | 98 | 0/98 | 0/98 | 0 | 0 | none |
| `socket_api_SUITE` | 150 | 0/150 | 0/150 | 0 | 0 | none |
| `socket_sctp_SUITE` | 0 | 0 | 0 | 0 | 1 | suite/helper compile failed (1): /var/folders/v5/w846m1655ylfpfnhmtgfbnvm0000gn/T/otp-socket_sctp-source-_jbql0_o/test/code_a_test.beam: Module name 'code_b_test' does not match file name 'code_a_test' ; suite/helper compile failed (1): /var/folders/v5/w846m1655ylfpfnhmtgfbnvm0000gn/T/otp-socket_sctp-source-_jbql0_o/test/code_a_test.beam: Module name 'code_b_test' does not match file name 'code_a_test' |
| `socket_sctp_example_SUITE` | 2 | 0/2 | 0/2 | 0 | 0 | none |
| `socket_traffic_SUITE` | 69 | 0/69 | 0/69 | 0 | 0 | none |
| `socket_ttest_SUITE` | 228 | 0/228 | 0/228 | 0 | 0 | none |
| `sofs_SUITE` | 60 | 60/60 | 60/60 | 0 | 0 | none |
| `standard_error_SUITE` | 4 | 4/4 | 4/4 | 0 | 0 | none |
| `statistics_SUITE` | 18 | 18/18 | 18/18 | 0 | 0 | none |
| `stdlib_SUITE` | 3 | 2/3 | 2/3 | 0 | 0 | none |
| `stdlib_bench_SUITE` | 47 | 47/47 | 46/47 | 1 | 0 | string_lexemes_list: failed testcase_aborted |
| `string_SUITE` | 46 | 46/46 | 46/46 | 0 | 0 | none |
| `supervisor_SUITE` | 96 | 96/96 | 92/96 | 4 | 0 | already_started_outside_supervisor: failed testcase_aborted; auto_hibernate: failed {test_case_failed,not_in_erlang_hibernate_3}; child_adm: failed {{badmatch,{current_function,{erlang,hibernate,0}}}; scale_start_stop_many_children: failed testcase_aborted_or_killed, unknown_location |
| `supervisor_bridge_SUITE` | 7 | 7/7 | 7/7 | 0 | 0 | none |
| `sys_SUITE` | 7 | 7/7 | 7/7 | 0 | 0 | none |
| `system_info_SUITE` | 12 | 10/12 | 10/12 | 0 | 0 | none |
| `system_profile_SUITE` | 6 | 6/6 | 5/6 | 1 | 0 | scheduler: failed {{badmatch,false} |
| `tar_SUITE` | 28 | 27/28 | 21/28 | 6 | 0 | bsdtgz: failed testcase_aborted; extract_filtered: failed {{badmatch,{error,eexist}}; extract_from_binary: failed testcase_aborted; extract_from_binary_compressed: failed testcase_aborted; max_size: failed testcase_aborted; streamed_extract: failed testcase_aborted |
| `time_SUITE` | 18 | 16/18 | 16/18 | 0 | 0 | none |
| `timer_SUITE` | 1 | 1/1 | 0/1 | 1 | 0 | do_big_test: failed {test_case_failed,{error,{early_timeouts,3}}} |
| `timer_bif_SUITE` | 23 | 20/23 | 20/23 | 0 | 0 | none |
| `timer_simple_SUITE` | 48 | 48/48 | 45/48 | 3 | 0 | apply_after3: failed {{badmatch,nor}; apply_after4: failed {{badmatch,nor}; cancel5: failed testcase_aborted |
| `trace_SUITE` | 39 | 34/39 | 23/39 | 11 | 0 | link_receive_call_correlation: failed {test_case_failed, {error, {trace_ts,<0.10573.0>,'receive',98,1, {1791,901180,499122}}}}; more_system_monitor_args: failed {badarg; new_clear: failed {{badmatch,{flags,[send]}}; system_monitor_args: failed {badarg; system_monitor_large_heap_1: failed {badarg; system_monitor_large_heap_2: failed {function_clause; system_monitor_long_gc_1: failed {function_clause; system_monitor_long_gc_2: failed {function_clause; system_monitor_long_message_queue: failed {badarg; system_monitor_long_message_queue_ignore: failed {badarg; system_monitor_long_schedule: failed "Unexpected trace messages" |
| `trace_bif_SUITE` | 7 | 7/7 | 7/7 | 0 | 0 | none |
| `trace_call_count_SUITE` | 5 | 5/5 | 5/5 | 0 | 0 | none |
| `trace_call_memory_SUITE` | 12 | 12/12 | 7/12 | 5 | 0 | delayed_gc: failed {'EXIT',system_limit}, unknown_location; parallel_map: failed {'EXIT',normal}, unknown_location; spawn_memory: failed {{badmatch,{call_memory,[{<0.294.0>,1,0}]}}; spawn_memory_lambda: failed {{badmatch,{call_memory,[]}}; trace_all: failed {'EXIT',normal}, unknown_location |
| `trace_call_time_SUITE` | 17 | 17/17 | 10/17 | 7 | 0 | bif: failed testcase_aborted; called_function: failed testcase_aborted; nif: failed testcase_aborted; on_and_off: failed testcase_aborted; reset: failed testcase_aborted; scheduling: failed testcase_aborted_or_killed, unknown_location; trace_info_noblock: failed testcase_aborted |
| `trace_local_SUITE` | 25 | 25/25 | 8/25 | 17 | -6 | exception: failed {'EXIT',error}, unknown_location; exception_apply: failed {{case_clause; exception_apply_function: failed {{case_clause; exception_function: failed {{case_clause; exception_meta: failed {'EXIT',normal}, unknown_location; exception_meta_apply: failed {'EXIT',normal}, unknown_location; exception_meta_apply_function: failed {'EXIT',normal}, unknown_location; exception_meta_function: failed {'EXIT',normal}, unknown_location; exception_meta_nocatch: failed {{case_clause; exception_meta_nocatch_apply: failed {{case_clause; exception_meta_nocatch_apply_function: failed {{case_clause; exception_meta_nocatch_function: failed {{case_clause; exception_nocatch: failed {{case_clause; exception_nocatch_apply: failed {{case_clause; exception_nocatch_apply_function: failed {{case_clause; exception_nocatch_function: failed {{case_clause; return: failed {thrown, {normal |
| `trace_meta_SUITE` | 8 | 8/8 | 3/8 | 5 | 0 | combo: failed testcase_aborted; nosilent: failed testcase_aborted; return: failed testcase_aborted; stack_grow: failed testcase_aborted; tracer: failed testcase_aborted |
| `trace_nif_SUITE` | 6 | 6/6 | 5/6 | 1 | 0 | trace_nif_return: failed {test_case_failed,"Got timeout\n"} |
| `trace_port_SUITE` | 10 | 10/10 | 1/10 | 9 | 0 | call_trace: failed "Unexpected trace messages"; gc: failed "Unexpected trace messages"; process_events: failed "Unexpected trace messages"; receive_trace: failed "Unexpected trace messages"; receive_trace_non_scheduler: failed "Unexpected trace messages"; return_trace: failed {'EXIT',normal}, unknown_location; schedule: failed "Unexpected trace messages"; send: failed "Unexpected trace messages"; tracer_port_crash: failed "Unexpected trace messages" |
| `trace_session_SUITE` | 20 | 19/20 | 18/20 | 1 | 0 | is_bif_traced: failed {test_case_failed,"Unexpected messages: timeout"} |
| `tracer_SUITE` | 21 | 21/21 | 21/21 | 0 | 0 | none |
| `tuple_SUITE` | 20 | 20/20 | 20/20 | 0 | 0 | none |
| `unicode_SUITE` | 20 | 18/20 | 17/20 | 1 | 0 | exceptions: failed {{assertException |
| `unicode_util_SUITE` | 17 | 17/17 | 17/17 | 0 | 0 | none |
| `unique_SUITE` | 2 | 1/2 | 1/2 | 0 | 0 | none |
| `uri_string_SUITE` | 73 | 72/73 | 0/73 | 72 | -11 | compose_query: missing; compose_query_latin1: missing; compose_query_negative: missing; compose_query_negative_unicode_guard: missing; dissect_query: missing; dissect_query_negative: missing; interop_query_latin1: missing; interop_query_utf8: missing; normalize: missing; normalize_binary_pct_encoded_fragment: missing; normalize_binary_pct_encoded_query: missing; normalize_binary_pct_encoded_userinfo: missing; normalize_map: missing; normalize_negative: missing; normalize_pct_encoded_fragment: missing; normalize_pct_encoded_negative: missing; normalize_pct_encoded_query: missing; normalize_pct_encoded_userinfo: missing; normalize_return_map: missing; parse_binary: missing; parse_binary_fragment: missing; parse_binary_host: missing; parse_binary_host_ipv4: missing; parse_binary_host_ipv6: missing; parse_binary_path: missing; parse_binary_pct_encoded_fragment: missing; parse_binary_pct_encoded_query: missing; parse_binary_pct_encoded_userinfo: missing; parse_binary_port: missing; parse_binary_query: missing; parse_binary_scheme: missing; parse_binary_userinfo: missing; parse_fragment: missing; parse_host: missing; parse_host_ipv4: missing; parse_host_ipv6: missing; parse_list: missing; parse_mixed: missing; parse_negative: missing; parse_path: missing; parse_pct_encoded_fragment: missing; parse_pct_encoded_query: missing; parse_pct_encoded_userinfo: missing; parse_port: missing; parse_query: missing; parse_recompose_autogen: missing; parse_relative: missing; parse_scheme: missing; parse_special: missing; parse_special2: missing; parse_userinfo: missing; quote: missing; recompose_autogen: missing; recompose_fragment: missing; recompose_host_absolute_path: missing; recompose_host_relative_path: missing; recompose_parse_fragment: missing; recompose_parse_path: missing; recompose_parse_query: missing; recompose_path: missing; recompose_query: missing; regression_normalize: missing; regression_parse: missing; regression_recompose: missing; resolve_abnormal_examples: missing; resolve_base_uri: missing; resolve_normal_examples: missing; resolve_return_map: missing; transcode_basic: missing; transcode_mixed: missing; transcode_negative: missing; transcode_options: missing |
| `uri_string_property_test_SUITE` | 2 | 0/2 | 0/2 | 0 | 0 | none |
| `win32reg_SUITE` | 6 | 0/6 | 0/6 | 0 | 0 | none |
| `wrap_log_reader_SUITE` | 9 | 9/9 | 9/9 | 0 | 0 | none |
| `y2k_SUITE` | 8 | 8/8 | 8/8 | 0 | 0 | none |
| `z_SUITE` | 9 | 5/9 | 4/9 | 1 | 0 | check_io_debug: failed {{badmatch,undefined} |
| `zip_SUITE` | 30 | 26/30 | 26/30 | 0 | 0 | none |
| `zlib_SUITE` | 36 | 36/36 | 33/36 | 3 | 0 | api_deflateSetDictionary: failed {test_case_failed, "Failed to match \"? EXIT ( badarg )\", actual result was 27000995"}; api_inflateSetDictionary: failed {test_case_failed, "Failed to match \"? EXIT ( badarg )\", actual result was {'EXIT',\n {stream_error,\n …; only_allow_owner: failed {test_case_failed, "Spawned worker crashed with reason {test_case_failed,\n \"Failed to match \\\"? EXIT ( not_on_controlling_process )\\\", a… |
| `zstd_SUITE` | 10 | 10/10 | 0/10 | 10 | 0 | bulk: failed {undef; bulk_with_dict: failed {undef; cstream: failed {undef; cstream_with_dict: failed {undef; dict_api: failed {undef; doctests: failed {{12,errors}; dstream: failed {undef; dstream_with_dict: failed {undef; parameters: failed {undef; pledge: failed {undef |
| `zzz_SUITE` | 1 | 1/1 | 1/1 | 0 | 0 | none |

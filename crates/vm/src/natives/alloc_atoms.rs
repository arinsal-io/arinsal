//! Lazy allocator atoms created the way erts does on the first
//! `erlang:memory/0,1` and `erlang:system_info` allocator queries.
//!
//! Port of erts/emulator/beam/erl_alloc_util.c:4690 (init_atoms),
//! erts/emulator/beam/erl_alloc.c:2789 (erts_alloc_util_allocators),
//! erts/emulator/beam/erl_alloc.c:2579 (erts_allocated_areas),
//! erts/emulator/beam/erl_alloc.c:2902 (erts_allocator_options),
//! erts/emulator/sys/common/erl_mseg.c:854 and erl_mmap.c:2202, OTP-29.1.1.
//! Type and allocator description order is `erl_alloc.types` via
//! `erts/emulator/utils/make_alloc_types` with `beamasm` and `unix`.

use std::sync::Mutex;

use arinsal_term::global_atoms;

static ORDER: Mutex<()> = Mutex::new(());

fn intern(name: &str) {
    // Existing atoms keep their index; only a first insertion advances atom_count.
    global_atoms().intern(name).expect("runtime atom");
}

fn intern_all(names: &[&str]) {
    for name in names {
        intern(name);
    }
}

const UTIL_ATOMS: &[&str] = &[
    "versions",
    "options",
    "e",
    "t",
    "ramv",
    "atags",
    "asbcst",
    "rsbcst",
    "rsbcmt",
    "rmbcmt",
    "mmbcs",
    "msbclt",
    "mmsbc",
    "mmmbc",
    "lmbcs",
    "smbcs",
    "mbcgs",
    "acul",
    "acful",
    "acnl",
    "acfml",
    "cp",
    "mmc",
    "ycs",
    "sac",
    "fix_types",
    "mbcs",
    "mbcs_pool",
    "fetch",
    "fail_pooled",
    "fail_shared",
    "fail_pend_dealloc",
    "fail",
    "skip_size",
    "skip_busy",
    "skip_not_pooled",
    "skip_homecoming",
    "skip_race",
    "entrance_removed",
    "sbcs",
    "sys_alloc_carriers_size",
    "mseg_alloc_carriers_size",
    "carriers_size",
    "sys_alloc_carriers",
    "mseg_alloc_carriers",
    "carriers",
    "blocks",
    "count",
    "size",
    "calls",
    "sys_alloc",
    "sys_free",
    "sys_realloc",
    "mseg_alloc",
    "mseg_dealloc",
    "mseg_realloc",
    "@",
];

const CARRIER_CHARS: &[&str] = &["Y", "T", "S", "D", "L", "H", "E", "F", "I", "B", "R", "Z"];

const ALLOCATOR_DESCRIPTIONS: &[&str] = &[
    "sys_alloc",
    "temp_alloc",
    "sl_alloc",
    "std_alloc",
    "ll_alloc",
    "eheap_alloc",
    "ets_alloc",
    "fix_alloc",
    "literal_alloc",
    "binary_alloc",
    "driver_alloc",
    "test_alloc",
];

const ALLOC_UTIL_DESCENDING: &[&str] = &[
    "driver_alloc",
    "binary_alloc",
    "literal_alloc",
    "fix_alloc",
    "ets_alloc",
    "eheap_alloc",
    "ll_alloc",
    "std_alloc",
    "sl_alloc",
    "temp_alloc",
];

const TYPE_DESCRIPTIONS: &[&str] = &[
    "undefined",
    "nbif_tab",
    "info_dsbuf",
    "environment",
    "tmp_heap",
    "root_set",
    "loader_tmp",
    "nc_tmp",
    "tmp",
    "dctrl_buf",
    "estack",
    "db_tmp",
    "db_mc_stack",
    "db_match_spec_cmpl_heap",
    "logger_dsbuf",
    "tmp_dsbuf",
    "ddll_tmp_buf",
    "re_tmp_buf",
    "temp_term",
    "sys_read_buf",
    "sys_write_buf",
    "proc_list",
    "saved_estack",
    "messages_queue_change",
    "prepared_code",
    "timer_request",
    "btm_yield_state",
    "db_fixation",
    "fixed_del",
    "db_match_spec_run_heap",
    "db_proc_cleanup_state",
    "ets_all_request",
    "ets_insert_list_bif_trap_state",
    "port_task",
    "port_task_handle_list",
    "misc_op_list",
    "port_names",
    "ptab_list_deleted_el",
    "ptab_list_chunk_info",
    "ptab_list_pids",
    "re_shortlived",
    "re_subject",
    "unicode_buffer",
    "binary_buffer",
    "tmp_cpu_ids",
    "external_term_data",
    "code_ix_lock_q",
    "busy_caller_table",
    "busy_caller",
    "proc_sys_task",
    "proc_sys_task_queues",
    "new_time_offset",
    "io_bytes_request",
    "trace_message_queue",
    "dirty_short_lived",
    "binary_find",
    "dist_transcode_context",
    "misc_aux_work",
    "short_lived_thr_queue",
    "async",
    "extra_port_list",
    "temp_thr_prgr_data",
    "release_literal_area",
    "signal_data",
    "signal_yield_data",
    "dist_demonitor",
    "connection_ml_cleanup",
    "monitor_link_yield_state",
    "process_flag_3_arguments",
    "trace_info_proc_request",
    "setup_connection_argument",
    "list_bif_trap_state",
    "continue_exit_trap_state",
    "dist_seq_yield_state",
    "phash2_trap_state",
    "map_bif_trap_state",
    "persistent_lock_q",
    "persistent_term_tmp_table",
    "term_to_binary_vector",
    "ethread_short_lived",
    "system_messages_queue",
    "sl_migration_paths",
    "term_to_binary_deterministic",
    "dirty_signal_handler_notification",
    "scheduled_signal_notify",
    "debugging",
    "literal_area_ref",
    "purge_data",
    "alloc_info_request",
    "sched_wall_time_request",
    "gc_info_request",
    "system_check_request",
    "short_lived_term",
    "pollset_update_req",
    "reg_proc",
    "paused_timer",
    "reg_tab",
    "fun_tab",
    "dist_tab",
    "node_tab",
    "module_refs",
    "nc_std",
    "dcache",
    "dist_entry",
    "node_entry",
    "arg_reg",
    "proc_dict",
    "calls_buf",
    "bpd",
    "line_buf",
    "io_queue",
    "bits_buf",
    "db_named_table_entry",
    "ddll_handle",
    "re_precompile",
    "process_specific_data",
    "port_specific_data",
    "magic_ref_entry",
    "magic_ref_table_buckets",
    "pid_ref_entry",
    "pid_ref_table_buckets",
    "crash_dump",
    "thr_q_element",
    "thr_queue",
    "zlib",
    "driver_lock",
    "monitor_link_dist",
    "ethread_standard",
    "code_coverage",
    "message_prio_queue_info",
    "ddll_processes",
    "monitor_extended",
    "link_extended",
    "db_heir_data",
    "nfunc_trap_wrapper",
    "monitor_tag",
    "alias",
    "monitor_suspend",
    "port_data_heap",
    "erl_bif_atomics",
    "erl_bif_counters",
    "fd_entry_buf",
    "sys_blocking",
    "atom_entry",
    "module_entry",
    "fun_entry",
    "atom_text",
    "timer_service",
    "atom_tab",
    "module_tab",
    "taint_list",
    "proc_tab",
    "port_tab",
    "timer_wheel",
    "internal_async_data",
    "db_tabs",
    "scheduler_sleep_info",
    "run_queues",
    "ddll_errcodes",
    "re_init",
    "pre_alloc_data",
    "cpu_data",
    "cpu_groups_map",
    "misc_aux_work_q",
    "tracer_nif",
    "magic_ref_table",
    "pid_ref_table",
    "release_literal_area_block_counters",
    "long_lived_thr_queue",
    "run_queue_balancing",
    "thr_prgr_internal_data",
    "thr_prgr_data",
    "persistent_term",
    "ethread_long_lived",
    "fp_exception",
    "ll_migration_paths",
    "errno_map",
    "errno_entry",
    "errno_table",
    "errno_table_buckets",
    "export_tab",
    "export_entry",
    "catches",
    "db_match_pseudo_proc",
    "scheduler_data",
    "record_table",
    "record_entry",
    "drv_tab",
    "driver_event_state",
    "pollset",
    "poll_fds",
    "block_poll_thread_data",
    "fd_status",
    "select_fds",
    "cs_prog_path",
    "beam_register",
    "heap",
    "old_heap",
    "heap_frag",
    "message",
    "db_tab",
    "db_segment",
    "db_stack",
    "db_trans_tab",
    "db_select_list",
    "db_dmc_error",
    "db_dmc_error_info",
    "db_term",
    "ets_decentralized_ctrs",
    "proc",
    "receive_marker_block",
    "msg_ref",
    "ll_ptimer",
    "hl_ptimer",
    "bif_timer",
    "nsched_magic_ref_entry",
    "nsched_pid_ref_entry",
    "magic_indirection",
    "process_signal_queue_buffers",
    "sl_thr_q_element",
    "monitor",
    "link",
    "driver_select_data_state",
    "enif_select_data_state",
    "literal",
    "drv_binary",
    "binary",
    "port",
    "drv_internal",
    "driver",
    "driver_command_data",
    "driver_control_data",
    "driver_call_data",
    "nif_internal",
    "port_data_lock",
    "driver_thread_opts",
    "driver_tid",
    "driver_mutex",
    "driver_cond",
    "driver_rwlock",
    "driver_tsd",
    "microstate_accounting",
    "testing",
];

const ALLOCATED_AREAS: &[&str] = &[
    "sys_misc",
    "static",
    "atom_space",
    "atom_table",
    "module_table",
    "export_table",
    "export_list",
    "register_table",
    "fun_table",
    "fun_list",
    "module_refs",
    "loaded_code",
    "dist_table",
    "node_table",
    "bif_timer",
    "process_table",
    "port_table",
    "ets_misc",
    "external_alloc",
];

const MSEG_ATOMS: &[&str] = &[
    "version",
    "memkind",
    "name",
    "options",
    "amcbf",
    "rmcbf",
    "mcs",
    "status",
    "cached_segments",
    "cache_hits",
    "segments",
    "segments_size",
    "segments_watermark",
    "calls",
    "mseg_alloc",
    "mseg_dealloc",
    "mseg_realloc",
    "mseg_create",
    "mseg_create_resize",
    "mseg_destroy",
    "mseg_recreate",
    "mseg_clear_cache",
    "mseg_check_cache",
];

const MMAP_ATOMS: &[&str] = &[
    "options",
    "total",
    "total_sa",
    "total_sua",
    "used",
    "used_sa",
    "used_sua",
    "max",
    "allocated",
    "reserved",
    "sizes",
    "free_segs",
    "supercarrier",
    "os",
    "scs",
    "sco",
    "scrpm",
    "scrfsd",
];

const AOFF_ATOMS: &[&str] = &[
    "as",
    "ageffcaoff",
    "ageffcaobf",
    "ageffcbf",
    "aoff",
    "aoffcaobf",
    "aoffcbf",
];

const AFIT_ATOMS: &[&str] = &["as", "af"];

const BESTFIT_ATOMS: &[&str] = &["as", "aobf", "bf"];

const GOODFIT_ATOMS: &[&str] = &["mbsd", "as", "gf"];

fn call_atoms(name: &str) {
    let (realloc, free) = match name {
        "temp_alloc" => ("temp_realloc", "temp_free"),
        "sl_alloc" => ("sl_realloc", "sl_free"),
        "std_alloc" => ("std_realloc", "std_free"),
        "ll_alloc" => ("ll_realloc", "ll_free"),
        "eheap_alloc" => ("eheap_realloc", "eheap_free"),
        "ets_alloc" => ("ets_realloc", "ets_free"),
        "fix_alloc" => ("fix_realloc", "fix_free"),
        "literal_alloc" => ("literal_realloc", "literal_free"),
        "binary_alloc" => ("binary_realloc", "binary_free"),
        "driver_alloc" => ("driver_realloc", "driver_free"),
        "test_alloc" => ("test_realloc", "test_free"),
        _ => return,
    };
    // Port of erl_alloc_util.c:5362 (make_name_atoms): prefix+"alloc", "realloc", "free".
    intern(name);
    intern(realloc);
    intern(free);
}

fn aoff() {
    // Port of erl_ao_firstfit_alloc.c:1147. Flavor strings are flavor_str[2][3].
    intern_all(AOFF_ATOMS);
}

fn afit() {
    // Port of erl_afit_alloc.c:191.
    intern_all(AFIT_ATOMS);
}

fn bestfit() {
    // Port of erl_bestfit_alloc.c:885.
    intern_all(BESTFIT_ATOMS);
}

fn goodfit() {
    // Port of erl_goodfit_alloc.c:518.
    intern_all(GOODFIT_ATOMS);
}

fn global_atoms_once() {
    // Port of erl_alloc_util.c:4694. HAVE_ERTS_MSEG is set in the OTP 29.1.1 macOS build:
    // the mseg carrier atoms are part of this list.
    intern_all(UTIL_ATOMS);
    intern_all(CARRIER_CHARS);
    intern_all(TYPE_DESCRIPTIONS);
    intern_all(ALLOCATOR_DESCRIPTIONS);
}

fn scheduler_strategy(name: &str) {
    // Thread instances of temp_alloc stay on afit (erl_alloc.c:1029). Every other
    // migrating allocator is adjusted to aoffcbf (erl_alloc.c:584).
    if name == "temp_alloc" {
        afit();
    } else {
        aoff();
    }
}

fn instance0_strategy(name: &str) {
    match name {
        // Instance 0 of a thread-specific temp_alloc is forced to goodfit.
        "temp_alloc" => goodfit(),
        // literal_alloc keeps address-ordered bestfit and is not thread specific.
        "literal_alloc" => bestfit(),
        _ => aoff(),
    }
}

fn thread_specific(name: &str) -> bool {
    // literal_alloc sets acul to 0, so carrier migration does not make it thread preferred.
    matches!(
        name,
        "temp_alloc"
            | "sl_alloc"
            | "std_alloc"
            | "ll_alloc"
            | "eheap_alloc"
            | "ets_alloc"
            | "fix_alloc"
            | "binary_alloc"
            | "driver_alloc"
    )
}

/// `erlang:system_info(alloc_util_allocators)` inserts descriptions from
/// `ERTS_ALC_A_MAX` down to `MIN`, skipping `sys_alloc` and `test_alloc`.
pub(super) fn note_alloc_util_allocator_names() {
    let _order = ORDER.lock().unwrap();
    intern_all(ALLOC_UTIL_DESCENDING);
}

/// Atoms created while `reply_alloc_info` serves `memory_internal` or
/// `{allocator, Ref, Allocs}`.
///
/// Aux threads run before the requesting scheduler returns from
/// `erts_schedule_multi_misc_aux_work` (erl_alloc.c:3433). They initialize
/// thread-specific instances only. The requesting scheduler then initializes
/// instance 0 and allocators that are not thread specific (`literal_alloc`).
pub(super) fn note_memory_internal(names: &[&str]) {
    let _order = ORDER.lock().unwrap();
    let mut reverse = names.to_vec();
    reverse.reverse();
    let mut started = false;
    let mut begin = || {
        if !started {
            global_atoms_once();
            started = true;
        }
    };
    for name in &reverse {
        if !thread_specific(name) {
            continue;
        }
        begin();
        call_atoms(name);
        scheduler_strategy(name);
    }
    for name in &reverse {
        match *name {
            "mseg_alloc" => {
                intern("mseg_alloc");
                intern_all(MSEG_ATOMS);
            }
            "erts_mmap" => {
                intern("erts_mmap");
                intern_all(MMAP_ATOMS);
            }
            "alloc_util" => {
                begin();
                intern("alloc_util");
            }
            "sys_alloc" => {
                intern("sys_alloc");
                intern("e");
                intern("m");
                intern("libc");
            }
            "test_alloc" => intern("test_alloc"),
            _ => {
                begin();
                call_atoms(name);
                instance0_strategy(name);
            }
        }
    }
}

/// `erlang:system_info(allocated_areas)`, called by `erlang:memory/0,1` after
/// the allocator replies have been received.
pub(super) fn note_allocated_areas() {
    let _order = ORDER.lock().unwrap();
    intern_all(ALLOCATED_AREAS);
}

/// `erlang:system_info({allocator, Name})` for one alloc_util allocator.
pub(super) fn note_one_allocator(name: &str) {
    note_memory_internal(&[name]);
}

/// A disabled allocator contributes only its name (`erts_bld_atom` of `ERTS_ALC_A2AD`).
pub(super) fn note_disabled_allocator(name: &str) {
    let _order = ORDER.lock().unwrap();
    intern(name);
}

/// Option atoms of `sys_alloc` (`m`/`libc`). `tt` and `tp` stay absent: this
/// host's trim threshold and top pad are negative, so erts does not create them.
pub(super) fn note_sys_alloc_options() {
    let _order = ORDER.lock().unwrap();
    intern("sys_alloc");
    intern("e");
    intern("m");
    intern("libc");
}

/// `erlang:system_info({allocator, mseg_alloc})`.
pub(super) fn note_mseg() {
    let _order = ORDER.lock().unwrap();
    intern("mseg_alloc");
    intern_all(MSEG_ATOMS);
}

/// `erlang:system_info(allocator)` — `erts_allocator_options`.
pub(super) fn note_allocator_catalog() {
    let _order = ORDER.lock().unwrap();
    intern("sys_alloc");
    intern("e");
    intern("m");
    intern("libc");
    for name in [
        "temp_alloc",
        "sl_alloc",
        "std_alloc",
        "ll_alloc",
        "eheap_alloc",
        "ets_alloc",
        "fix_alloc",
        "literal_alloc",
        "binary_alloc",
        "driver_alloc",
    ] {
        intern(name);
        // The options term is built from instance 0 only (erl_alloc.c:2940).
        global_atoms_once();
        call_atoms(name);
        instance0_strategy(name);
    }
    intern("test_alloc");
    intern("mseg_alloc");
    intern_all(MSEG_ATOMS);
    intern("alloc_util");
    intern("erts_mmap");
    intern_all(MMAP_ATOMS);
    intern("lock_physical_memory");
    intern("sys_aligned_alloc");
    intern("literal_mmap");
}

#[allow(dead_code)]
#[path = "../common/mod.rs"]
mod common;

mod bin_accounting;
mod bin_vheap_differential;
mod bs_append_alloc;
mod bs_append_integer_differential;
mod bs_construct_error_info_differential;
mod bs_create_bin_alloc;
mod bs_match_segments_differential;
mod bs_private_append_grow;
mod bs_utf8_differential;
mod dirty_major_gc;
mod dirty_nif;
mod dirty_sched;
mod dirty_shadow_gc_differential;
mod dirty_signals;
mod gc_bif_epilogue_once;
mod gc_failed_bif_differential;
mod gc_map_differential;
mod gc_reductions;
mod gc_root_probe;
mod gc_state_requests;
mod gc_stats_differential;
mod literal_gc;
mod memory_accounting;
mod prepare_loading_gc_differential;
mod resume_gc_timing_differential;
mod send_gc_after_bif_differential;
mod switch_out_gc_live;

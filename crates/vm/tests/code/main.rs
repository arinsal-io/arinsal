#[allow(dead_code)]
#[path = "../common/mod.rs"]
mod common;

mod code_bifs;
mod code_fix;
mod code_permission;
mod loader_ops;
mod onload_literal;
mod pending_purge_lambda;
mod purge_dirty_running;
mod purge_release_memory;
mod purge_roots;
mod purge_switch_out_live;
mod save_calls_differential;
mod sensitive_save_calls;

#[allow(dead_code)]
#[path = "../common/mod.rs"]
mod common;

mod drv_io;
mod drv_lib;
mod drv_smoke;
mod msgq_port;
mod open_port_filename_differential;
mod pid_port_follow_differential;
mod port_eof_close;
mod port_exit_demonitor_race;
mod port_fix;
mod port_life;
mod port_link_trees_differential;
mod port_monitor_differential;
mod port_opts;
mod port_tasks;
mod port_trace_differential;
mod ports_compat;
mod prim_file_dirty;
mod ram_file_compat;

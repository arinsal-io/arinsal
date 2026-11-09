#[allow(dead_code)]
#[path = "../common/mod.rs"]
mod common;

mod gen_tcp_api_compat;
mod gen_tcp_echo_compat;
mod gen_tcp_misc_compat;
mod gen_tcp_socket_compat;
mod gen_udp_compat;
mod inet_driver_vm_isolation;
mod inet_full;
mod inet_output;
mod inet_poll;
mod inet_port_tasks;
mod inet_recv_binary;
mod inet_refc_send;
mod inet_sched_poll;
mod inet_sendq;
mod inet_tcp;
mod inet_udp;
mod socket_select_close_mailbox;
mod socket_select_close_race;
mod udp_close_hang;

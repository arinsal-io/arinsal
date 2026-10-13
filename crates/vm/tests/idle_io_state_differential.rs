mod common;

// The idle runtime must look like erts to the OTP I/O self-checks: port zero is the forker and
// answers `port_info`, and the `check_io_debug` counters ignore the runtime's own wake pipes
// (driver_SUITE:check_io_debug/0 insists on {0, 0, 0, 0} at rest). The enif_select count is left
// out: a one-shot erl may hold its stdin there, which is outside what this test checks.
const SOURCE: &str = r#"
-module(idle_io_state).
-export([forker/0, check_io/0]).
forker() ->
    [P] = erlang:ports(),
    {P =:= hd(erlang:ports()), erlang:port_info(P),
     [erlang:port_info(P, I) || I <- [name, id, connected, os_pid, monitors, monitored_by,
                                      memory, queue_size, locking, parallelism, registered_name]]}.
check_io() ->
    erts_debug:set_internal_state(available_internal_state, true),
    {Errors, Used, DrvSelects, _EnifSelects} = erts_debug:get_internal_state(check_io_debug),
    {Errors, Used, DrvSelects}.
"#;

fn compare(expr: &str) {
    let Some(beam) = common::erl_beam("idle_io_state", SOURCE) else {
        eprintln!("erlc unavailable; skipping idle I/O state differential test");
        return;
    };
    let Some(expected) = common::erl_once("idle_io_state", SOURCE, expr) else {
        eprintln!("erl unavailable; skipping idle I/O state differential test");
        return;
    };
    assert_eq!(expected, common::arinsal_once("idle_io_state", &beam, expr));
}

#[test]
fn forker_port_info_matches_otp_29() {
    compare("idle_io_state:forker()");
}

#[test]
fn idle_check_io_debug_counters_match_otp_29() {
    compare("idle_io_state:check_io()");
}

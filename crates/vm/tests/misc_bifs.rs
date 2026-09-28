use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, decode, encode};
use arinsal_term::global_atoms;
use arinsal_vm::Vm;
use std::sync::Mutex;

static PROFILE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn compare(source: &str, module: &str, function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping {module}:{function} differential test");
        return;
    };
    let beam = reference.compile_named(module, source, &[]).unwrap();
    reference.load(module, &beam).unwrap();
    let expected = reference.call(module, function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(module, function, &[], 1, Some(47))
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

fn compare_threaded(source: &str, module: &str, function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping {module}:{function} differential test");
        return;
    };
    let beam = reference.compile_named(module, source, &[]).unwrap();
    reference.load(module, &beam).unwrap();
    let expected = reference.call(module, function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(module, function, &[], 1, None).unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

#[test]
fn misc_bifs_ddll_static_driver_results_match_erts() {
    compare(
        r#"-module(misc_bifs_ddll). -export([run/0]).
        run() -> {erl_ddll:loaded_drivers(),
                  erl_ddll:info("tcp_inet", linked_in_driver),
                  erl_ddll:info("tcp_inet", port_count),
                  erl_ddll:info("tcp_inet", processes),
                  erl_ddll:try_load("/missing", "tcp_inet", []),
                  erl_ddll:try_load("/missing", "not_a_driver", []),
                  erl_ddll:try_unload("tcp_inet", []),
                  erl_ddll:format_error_int(pending_process),
                  begin R=erl_ddll:monitor(driver, {"tcp_inet", loaded}),
                        {is_reference(R), receive {'UP', R, driver, _, permanent} -> true
                                          after 0 -> false end} end}."#,
        "misc_bifs_ddll",
        "run",
    );
}

#[test]
fn misc_bifs_ddll_demonitor_cancels_pending_driver_monitor_match_erts() {
    compare(
        r#"-module(misc_bifs_ddll_demonitor). -export([run/0]).
        run() -> R = erl_ddll:monitor(driver, {"missing_driver", loaded}),
                 First = receive {'DOWN', R, driver, _, unloaded} -> down
                         after 0 -> missing end,
                 D = erl_ddll:demonitor(R),
                 {First, D, receive {'UP', R, driver, _, _} -> duplicate;
                                  {'DOWN', R, driver, _, _} -> duplicate
                            after 0 -> none end}."#,
        "misc_bifs_ddll_demonitor",
        "run",
    );
}

#[test]
fn misc_bifs_system_profile_and_tags_match_erts() {
    let _guard = PROFILE_TEST_LOCK.lock().unwrap();
    compare(
        r#"-module(misc_bifs_profile). -export([run/0]).
        run() ->
            A = {erlang:dt_put_tag(not_a_bitstring), erlang:dt_get_tag(),
                 erlang:dt_get_tag_data(), erlang:dt_append_vm_tag_data(x),
                 erlang:dt_prepend_vm_tag_data(y)},
            _ = erlang:system_profile(self(), [scheduler, runnable_procs,
                                                runnable_ports]),
            {A, error_logger:warning_map(), element(2, erlang:system_profile()),
             element(2, erlang:system_profile(undefined, []))}."#,
        "misc_bifs_profile",
        "run",
    );
}

#[test]
fn misc_bifs_system_profile_emits_runnable_process_events_match_erts() {
    let _guard = PROFILE_TEST_LOCK.lock().unwrap();
    compare(
        r#"-module(misc_bifs_profile_events). -export([run/0]).
        run() ->
            Previous = erlang:system_profile(self(), [runnable_procs,
                                                        strict_monotonic_timestamp]),
            Pid = spawn(fun() -> ok end),
            Event = receive
                {profile, Pid, active, _MFA, Timestamp} ->
                    {active, tuple_size(Timestamp)}
            after 1000 -> timeout
            end,
            _ = erlang:system_profile(undefined, []),
            {Previous, Event}."#,
        "misc_bifs_profile_events",
        "run",
    );
}

#[test]
fn misc_bifs_system_profile_emits_scheduler_events_match_erts() {
    let _guard = PROFILE_TEST_LOCK.lock().unwrap();
    compare_threaded(
        r#"-module(misc_bifs_profile_scheduler). -export([run/0]).
        run() ->
            Previous = erlang:system_profile(self(), [scheduler, timestamp]),
            Event = receive
                {profile, scheduler, Id, State, Active, Timestamp} ->
                    {Id > 0, State, Active >= 0, tuple_size(Timestamp)}
            after 1000 -> timeout
            end,
            _ = erlang:system_profile(undefined, []),
            {Previous, Event}."#,
        "misc_bifs_profile_scheduler",
        "run",
    );
}

#[test]
fn misc_bifs_system_profile_emits_runnable_port_events_match_erts() {
    let _guard = PROFILE_TEST_LOCK.lock().unwrap();
    compare(
        r#"-module(misc_bifs_profile_ports). -export([run/0]).
        run() ->
            Previous = erlang:system_profile(self(), [runnable_ports]),
            Port = open_port({spawn, "sleep 1"}, [binary]),
            true = erlang:port_command(Port, binary:copy(<<0>>, 100000)),
            Event = receive
                {profile, Port, active, 0, _Timestamp} -> active
            after 1000 -> timeout
            end,
            _ = erlang:system_profile(undefined, []),
            _ = erlang:port_close(Port),
            {Previous, Event}."#,
        "misc_bifs_profile_ports",
        "run",
    );
}

#[test]
fn misc_bifs_string_list_to_float_prefix_and_errors_match_erts() {
    compare(
        r#"-module(misc_bifs_float). -export([run/0]).
        run() -> [string:list_to_float("1.25rest"),
                  string:list_to_float("2.5e-"),
                  string:list_to_float("no_float"),
                  string:list_to_float([])]."#,
        "misc_bifs_float",
        "run",
    );
}

#[test]
fn misc_bifs_decode_packet_and_dflag_match_erts() {
    let _ = global_atoms();
    compare(
        r#"-module(misc_bifs_packet). -export([run/0]).
        run() -> {erlang:decode_packet(raw, <<1,2>>, []),
                  erlang:decode_packet(line, <<"ok\nmore">>, []),
                  net_kernel:dflag_unicode_io(self()),
                  net_kernel:dflag_unicode_io(
                    erts_debug:dist_ext_to_term({},
                      <<131,88,100,0,12,"unknown@host",0,0,0,1,0,0,0,0,0,0,0,0>>)),
                  error_logger:warning_map(),
                  erts_debug:dist_ext_to_term({hello}, <<131,82,0>>),
                  erts_debug:dist_ext_to_term({}, term_to_binary({hello,42}))}."#,
        "misc_bifs_packet",
        "run",
    );
}

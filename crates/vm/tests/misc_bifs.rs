use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, decode, encode};
use arinsal_term::global_atoms;
use arinsal_vm::Vm;
use std::sync::Mutex;

mod common;

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
                  %% The open_error code indexes the node's dlerror string table,
                  %% which depends on earlier failed loads in the same node.
                  case erl_ddll:try_load("/missing", "not_a_driver", []) of
                      {error, {open_error, N}} when N =< -10 -> open_error;
                      Other -> Other
                  end,
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
fn misc_bifs_ddll_missing_driver_fails_with_formattable_open_error() {
    if !common::isolate_dyld_environment(
        "misc_bifs_ddll_missing_driver_fails_with_formattable_open_error",
    ) {
        return;
    }
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping missing-driver differential test");
        return;
    };
    let source = r#"-module(misc_bifs_missing_driver). -export([run/0]).
        run() -> case erl_ddll:try_load("/tmp", "arinsal_missing_driver", []) of
                      %% The code indexes the dlerror string table, which is
                      %% shared by every VM in this test process.
                      {error, {open_error, N} = E} when N =< -10 ->
                          {open_error, erl_ddll:format_error_int(E)};
                      Other -> Other
                  end."#;
    let beam = reference
        .compile_named("misc_bifs_missing_driver", source, &[])
        .unwrap();
    reference.load("misc_bifs_missing_driver", &beam).unwrap();
    let expected = reference.call("misc_bifs_missing_driver", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("misc_bifs_missing_driver", "run", &[], 1, Some(47))
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

#[test]
fn misc_bifs_ddll_open_error_formats_as_a_string() {
    compare(
        r#"-module(misc_bifs_ddll_open_error). -export([run/0]).
        run() -> S = erl_ddll:format_error_int({open_error, -10}),
                 true = is_list(S),
                 true = length(S) > 0,
                 true = lists:all(fun(C) -> is_integer(C) andalso C >= 0 andalso C =< 255 end, S),
                 formatted."#,
        "misc_bifs_ddll_open_error",
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

/// `decode_packet_3` opens a heap factory, which claims the free young heap, so its sub binaries
/// are `HAlloc`ed into heap fragments: `mbuf_size` grows by the words erts reports.
#[test]
fn misc_bifs_decode_packet_sub_binaries_go_to_heap_fragments_like_erts() {
    let _ = global_atoms();
    compare(
        r#"-module(misc_bifs_packet_mbuf). -export([run/0]).
        run() ->
            {_, R} = spawn_monitor(fun() ->
                Bin = <<148:32, (binary:copy(<<1>>, 148))/binary, 0:8>>,
                Small = <<4:32, 1,2,3,4, 9>>,
                Mb = fun() ->
                    {_, I} = process_info(self(), garbage_collection_info),
                    proplists:get_value(mbuf_size, I)
                end,
                M0 = Mb(),
                {ok, P1, R1} = erlang:decode_packet(4, Bin, []),
                M1 = Mb(),
                {ok, P2, R2} = erlang:decode_packet(4, Small, []),
                M2 = Mb(),
                {more, _} = erlang:decode_packet(4, <<0,0>>, []),
                M3 = Mb(),
                exit({[M1 - M0, M2 - M1, M3 - M2],
                      byte_size(P1), byte_size(R1), byte_size(P2), byte_size(R2)})
            end),
            receive {'DOWN', R, _, _, Reason} -> Reason end."#,
        "misc_bifs_packet_mbuf",
        "run",
    );
}

/// A magic reference encodes as its numbers; decoding finds the binary again only because
/// `term_to_binary` saved it in erts' magic reference table, so the copy stays usable.
#[test]
fn misc_bifs_magic_reference_roundtrip_through_the_external_format_matches_erts() {
    let _ = global_atoms();
    compare(
        r#"-module(misc_bifs_magic_ref).
-export([run/0]).
ref_of(T) when is_reference(T) -> T;
ref_of({_, _} = T) -> element(2, T);
ref_of(T) when is_tuple(T) -> element(tuple_size(T), T).
rt(T) -> binary_to_term(term_to_binary(T)).
probe(T, Use) ->
    T2 = rt(T),
    R = ref_of(T), R2 = ref_of(T2),
    [is_reference(R2), T =:= T2, R =:= R2, R == R2, R < R2, R2 < R,
     catch_class(fun() -> Use(T) end), catch_class(fun() -> Use(T2) end)].
catch_class(F) -> try F(), ok catch C:E -> {C, E} end.
run() ->
    Pat = binary:compile_pattern(<<"bc">>),
    Ac = binary:compile_pattern([<<"b">>, <<"c">>]),
    A = atomics:new(2, []),
    Ms = ets:match_spec_compile([{'_', [], [true]}]),
    Res = [probe(Pat, fun(P) -> binary:match(<<"abc">>, P) end),
           probe(Ac, fun(P) -> binary:match(<<"abc">>, P) end),
           probe(A, fun(X) -> atomics:get(X, 1) end),
           begin T = ets:new(t, []), probe(Ms, fun(M) -> ets:match_spec_run([{a}], M) end) end],
    Res."#,
        "misc_bifs_magic_ref",
        "run",
    );
}

#[test]
fn misc_bifs_decode_packet_errors_options_and_more_match_erts() {
    let _ = global_atoms();
    compare(
        r#"-module(misc_bifs_packet_err). -export([run/0]).
        run() ->
            [t(fun() -> erlang:decode_packet(4, <<0,0,0,5,1>>, []) end),
             t(fun() -> erlang:decode_packet(4, <<0,0>>, []) end),
             t(fun() -> erlang:decode_packet(4, <<0,0,0,5,"hello">>, [{packet_size, 4}]) end),
             t(fun() -> erlang:decode_packet(4, <<0,0,0,5,"hello">>, [{packet_size, 5}]) end),
             t(fun() -> erlang:decode_packet(2, <<0,5,"hello","rest">>, [{packet_size, 0}]) end),
             t(fun() -> erlang:decode_packet(1, <<5,"hello">>, [{line_length, 3}]) end),
             t(fun() -> erlang:decode_packet(line, <<"ab\ncd">>, [{line_delimiter, $b}]) end),
             t(fun() -> erlang:decode_packet(line, <<"abc">>, [{line_delimiter, 300}]) end),
             t(fun() -> erlang:decode_packet(line, <<"abcdef">>, [{line_length, 3}]) end),
             t(fun() -> erlang:decode_packet(not_a_type, <<>>, []) end),
             t(fun() -> erlang:decode_packet(5, <<>>, []) end),
             t(fun() -> erlang:decode_packet(4, <<>>, [bad]) end),
             t(fun() -> erlang:decode_packet(4, <<>>, [{packet_size, -1}]) end),
             t(fun() -> erlang:decode_packet(4, <<>>, [{unknown, 1}]) end),
             t(fun() -> erlang:decode_packet(4, <<>>, [{packet_size, 1} | tail]) end),
             t(fun() -> erlang:decode_packet(4, <<>>, not_a_list) end),
             t(fun() -> erlang:decode_packet(4, <<1:3>>, []) end),
             t(fun() -> erlang:decode_packet(4, not_a_binary, []) end),
             t(fun() -> erlang:decode_packet(http, <<"GET / HTTP/1.1\r\nHost: x\r\n\r\n">>, []) end),
             t(fun() -> erlang:decode_packet(httph_bin, <<"Host: x\r\n\r\n">>, []) end),
             t(fun() -> erlang:decode_packet(ssl_tls, <<22,3,1,0,2,9,9>>, []) end),
             t(fun() -> erlang:decode_packet(4, <<7:4, 0:4, 0:24, 3:8, "abc">>, []) end)].
        t(F) -> try F() catch C:R -> {C, R} end."#,
        "misc_bifs_packet_err",
        "run",
    );
}

#[test]
fn misc_bifs_decode_packet_reads_and_returns_sub_binaries_in_place() {
    let _ = global_atoms();
    compare(
        r#"-module(misc_bifs_packet_ref). -export([run/0]).
        run() ->
            Body = binary:copy(<<"x">>, 200),
            Big = binary:copy(<<200:32, Body/binary>>, 100),
            {ok, P1, R1} = erlang:decode_packet(4, Big, []),
            {ok, P2, R2} = erlang:decode_packet(4, R1, [{packet_size, 1000}]),
            Part = binary:part(Big, 4, byte_size(Big) - 4),
            {ok, P3, R3} = erlang:decode_packet(raw, Part, []),
            Small = <<4:32, "abcd", "tail">>,
            {ok, P4, R4} = erlang:decode_packet(4, Small, []),
            {byte_size(P1), byte_size(P2), byte_size(R2),
             binary:referenced_byte_size(P1), binary:referenced_byte_size(R1),
             binary:referenced_byte_size(R2), binary:referenced_byte_size(P3),
             binary:referenced_byte_size(R3), P4, R4}."#,
        "misc_bifs_packet_ref",
        "run",
    );
}

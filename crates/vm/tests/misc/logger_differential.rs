//! Logger events queued by the emulator (utils.c `do_send_logger_message` and its callers),
//! compared with erl 29.1.1: level, format, argument shape, metadata keys, and a `time` within
//! a window of `os:system_time(microsecond)`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use std::sync::{Mutex, MutexGuard};

const SOURCE: &str = r#"
-module(logger_diff).
-export([sysmon_large_heap/0, sysmon_long_gc/0, cpu_topology/0, scheduler_bind/0, max_heap/0, port_error/0, process_error/0, internal_state/0, bad_load/1]).

capture(Fun) ->
    Old = erlang:system_flag(system_logger, self()),
    try
        Fun(),
        receive {log, _, _, _, _} = Msg -> Msg after 5000 -> timeout end
    after
        erlang:system_flag(system_logger, Old)
    end.

meta({log, _Level, _Fmt, _Args, #{time := T} = Meta}) ->
    Gl = case Meta of #{gl := G} -> G =:= group_leader(); _ -> absent end,
    {lists:sort(maps:keys(Meta)),
     maps:get(error_logger, Meta),
     Gl,
     abs(os:system_time(microsecond) - T) < 60000000}.

cpu_topology() ->
    {log, L, F, A, _} = M = capture(fun() ->
        erlang:system_flag(cpu_topology, [{processor, [{core, [{thread, {logical, 0}}]}]}])
    end),
    {L, F, A, meta(M)}.

scheduler_bind() ->
    {log, L, F, A, _} = M = capture(fun() ->
        erlang:system_flag(scheduler_bind_type, unbound)
    end),
    {L, F, A, meta(M)}.

max_heap() ->
    Self = self(),
    {log, L, F, A, #{pid := P}} = M = capture(fun() ->
        {_, Ref} = spawn_opt(fun() -> grow([]) end,
            [monitor, {max_heap_size, #{size => 2000, kill => true, error_logger => true}}]),
        receive {'DOWN', Ref, _, _, _} -> ok after 5000 -> ok end,
        Self ! ok
    end),
    receive ok -> ok after 0 -> ok end,
    [Pid, Size, _Total, Kill, ErrLogger, _MQ, GC, Stack] = A,
    {L, F, {Pid =:= P, Size, Kill, ErrLogger, [K || {K, _} <- GC],
            [{Mod, Fun, Ar} || {Mod, Fun, Ar, _} <- Stack]}, meta(M)}.

sysmon_large_heap() ->
    Self = self(),
    _ = erlang:system_monitor(Self, [{large_heap, 20000}]),
    P = spawn(fun() ->
        L = lists:seq(1, 200000),
        garbage_collect(),
        Self ! {done, length(L)}
    end),
    Ev = receive {monitor, P, large_heap, Info} -> {[K || {K, _} <- Info], sizes_ok(Info)} after 5000 -> timeout end,
    _ = erlang:system_monitor(undefined, []),
    Ev.

%% Relations erl_trace.c's monitor_*_session values satisfy.
sizes_ok(Info) ->
    G = fun(K) -> proplists:get_value(K, Info) end,
    [G(heap_block_size) > 0, G(heap_size) > 0, G(heap_size) =< G(heap_block_size),
     G(old_heap_size) =< G(old_heap_block_size), G(mbuf_size) >= 0, G(stack_size) >= 0].

sysmon_long_gc() ->
    Self = self(),
    _ = erts_debug:set_internal_state(available_internal_state, true),
    _ = erts_debug:set_internal_state(test_long_gc_sleep, 50),
    _ = erlang:system_monitor(Self, [{long_gc, 10}]),
    P = spawn(fun() -> garbage_collect(), Self ! done end),
    Ev = receive {monitor, P, long_gc, Info} -> {[K || {K, _} <- Info], sizes_ok(Info), proplists:get_value(timeout, Info) >= 10} after 5000 -> timeout end,
    _ = erts_debug:set_internal_state(test_long_gc_sleep, 0),
    _ = erlang:system_monitor(undefined, []),
    Ev.

grow(Acc) -> grow([0, 1, 2, 3, 4, 5, 6, 7 | Acc]).

port_error() ->
    {log, L, F, A, _} = M = capture(fun() ->
        process_flag(trap_exit, true),
        Port = open_port({spawn, "cat"}, []),
        Port ! {self(), {command, foo}},
        receive after 300 -> ok end,
        catch port_close(Port)
    end),
    {L, F, A, meta(M)}.

process_error() ->
    {log, L, F, A, #{pid := P}} = M = capture(fun() ->
        {_, Ref} = spawn_opt(fun() -> erlang:error(boom) end, [monitor]),
        receive {'DOWN', Ref, _, _, _} -> ok after 5000 -> ok end
    end),
    [Pid, {Reason, _Stack}] = A,
    {L, F, {Pid =:= P, Reason}, meta(M)}.

internal_state() ->
    {log, L, F, A, _} = M = capture(fun() ->
        erts_debug:set_internal_state(available_internal_state, true)
    end),
    [Text] = A,
    Normalized = re:replace(Text, "<[0-9]+\\.[0-9]+\\.[0-9]+>", "<PID>", [global, {return, list}]),
    {L, F, [lists:flatten(Normalized)], meta(M)}.

bad_load(Path) ->
    {ok, Bin} = file:read_file(Path),
    Old = erlang:system_flag(system_logger, self()),
    Result = code:load_binary(logger_bad, "bad.beam", Bin),
    Event = receive
        {log, L, F, A, M} -> {L, F, A, maps:remove(gl, maps:remove(pid, maps:remove(time, M)))}
    after 2000 -> timeout
    end,
    erlang:system_flag(system_logger, Old),
    {Result, Event}.
"#;

fn guard() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn run(function: &str) {
    let _guard = guard();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping logger differential test");
        return;
    };
    let beam = reference
        .compile_named("logger_diff", SOURCE, &[])
        .expect("compile");
    reference.load("logger_diff", &beam).expect("load");
    let expected = reference.call("logger_diff", function, &[]);
    assert!(
        matches!(expected, CallResult::Ok(ref term) if *term != OwnedTerm::atom("timeout")),
        "{function}: erl returned {expected:?}"
    );
    // erlang:system_logger is a node global: run on a separate node, as erts tests use a peer.
    let actual = crate::common::peer_eval(&[], &[&beam], &format!("logger_diff:{function}()"));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual));
}

#[test]
fn cpu_topology_deprecation_warning_matches_erl() {
    run("cpu_topology");
}

#[test]
fn scheduler_bind_deprecation_warning_matches_erl() {
    run("scheduler_bind");
}

#[test]
fn max_heap_size_kill_report_matches_erl() {
    run("max_heap");
}

#[test]
fn port_bad_output_value_report_matches_erl() {
    run("port_error");
}

#[test]
fn process_exit_error_report_matches_erl() {
    run("process_error");
}

#[test]
fn internal_state_warning_matches_erl() {
    run("internal_state");
}

#[test]
fn system_monitor_large_heap_message_matches_erl() {
    run("sysmon_large_heap");
}

#[test]
fn system_monitor_long_gc_message_matches_erl() {
    run("sysmon_long_gc");
}

/// Both runtimes started as nodes with `logger` unregistered and the system logger set to the
/// `logger` name: the dispatcher's failure path prints on stderr.
#[test]
fn no_logger_present_stderr_matches_erl() {
    let _guard = guard();
    let arinsal =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let Ok(root) = std::process::Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s\", [code:root_dir()]), halt().",
        ])
        .output()
    else {
        eprintln!("erl unavailable; skipping no-logger test");
        return;
    };
    let root = String::from_utf8_lossy(&root.stdout).trim().to_owned();
    let programs = [
        "erlang:system_flag(system_logger, logger), unregister(logger), \
         erlang:system_flag(cpu_topology, [{processor, [{core, [{thread, {logical, 0}}]}]}]), \
         timer:sleep(300), halt().",
        "erlang:system_flag(system_logger, logger), unregister(logger), \
         spawn(fun() -> process_flag(max_heap_size, #{size => 2000, kill => true, error_logger => true}), \
         erlang:error(boom) end), timer:sleep(300), halt().",
    ];
    let normalize = |text: &str| {
        let mut out = String::new();
        let mut rest = text;
        while let Some(at) = rest.find("time=>") {
            out.push_str(&rest[..at + 6]);
            rest = &rest[at + 6..];
            let digits = rest.chars().take_while(char::is_ascii_digit).count();
            out.push('T');
            rest = &rest[digits..];
        }
        out.push_str(rest);
        // Pids and stacktrace line numbers are not part of the contract.
        let mut cleaned = String::new();
        let mut chars = out.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '<' && chars.peek().is_some_and(char::is_ascii_digit) {
                for next in chars.by_ref() {
                    if next == '>' {
                        break;
                    }
                }
                cleaned.push_str("<P>");
            } else {
                cleaned.push(c);
            }
        }
        cleaned
    };
    for program in programs {
        let erts = std::process::Command::new("erl")
            .args(["-noshell", "-eval", program])
            .output()
            .expect("erl");
        let arin = std::process::Command::new(&arinsal)
            .env("ERL_ROOTDIR", &root)
            .args(["-noshell", "-eval", program])
            .output()
            .expect("arinsal");
        let expected = String::from_utf8_lossy(&erts.stderr).to_string();
        let actual = String::from_utf8_lossy(&arin.stderr).to_string();
        assert!(
            expected.starts_with("(no logger present)"),
            "erl: {expected}"
        );
        similar_asserts::assert_eq!(normalize(&expected), normalize(&actual));
    }
}

#[test]
fn malformed_beam_load_diagnostics_match_erl() {
    let _guard = guard();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping malformed loader diagnostic differential test");
        return;
    };
    let control = reference
        .compile_named("logger_diff", SOURCE, &[])
        .expect("compile logger harness");
    reference
        .load("logger_diff", &control)
        .expect("load harness");
    let valid = reference
        .compile_named(
            "logger_bad",
            "-module(logger_bad). -export([run/0]). run() -> {lists:reverse([]), #{alpha => 1, beta => 2}}.",
            &[],
        )
        .expect("compile module to corrupt");
    let cases = ["truncated_code", "bad_opcode", "bad_import", "bad_literal"];
    let path = std::env::temp_dir().join(format!("arinsal-bad-beam-{}.beam", std::process::id()));
    for case in cases {
        let corrupt = corrupt_beam(&valid, case);
        std::fs::write(&path, &corrupt).expect("write malformed beam");
        let path_string = path.to_string_lossy().into_owned();
        let expected = reference.call(
            "logger_diff",
            "bad_load",
            &[OwnedTerm::List {
                elems: path_string
                    .chars()
                    .map(|ch| OwnedTerm::Int(ch as i64))
                    .collect(),
                tail: Box::new(OwnedTerm::Nil),
            }],
        );
        let expr = format!("logger_diff:bad_load({path_string:?})");
        let actual = crate::common::peer_eval(&[], &[&control], &expr);
        similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "case: {case}");
    }
    let _ = std::fs::remove_file(path);
}

fn corrupt_beam(input: &[u8], case: &str) -> Vec<u8> {
    let mut chunks = Vec::new();
    let mut offset = 12;
    while offset < input.len() {
        let id: [u8; 4] = input[offset..offset + 4].try_into().expect("chunk id");
        let size = u32::from_be_bytes(input[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let data_start = offset + 8;
        let data_end = data_start + size;
        chunks.push((id, input[data_start..data_end].to_vec()));
        offset = data_end + (4 - size % 4) % 4;
    }
    match case {
        "truncated_code" => chunks
            .iter_mut()
            .find(|(id, _)| id == b"Code")
            .expect("Code chunk")
            .1
            .truncate(4),
        "bad_opcode" => {
            let code = &mut chunks.iter_mut().find(|(id, _)| id == b"Code").unwrap().1;
            code[20] = 255;
        }
        "bad_import" => {
            let imports = &mut chunks.iter_mut().find(|(id, _)| id == b"ImpT").unwrap().1;
            imports[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        }
        "bad_literal" => {
            let literals = &mut chunks.iter_mut().find(|(id, _)| id == b"LitT").unwrap().1;
            literals[4] ^= 0xff;
        }
        _ => unreachable!(),
    }
    let mut output = b"FOR1\0\0\0\0BEAM".to_vec();
    for (id, data) in chunks {
        output.extend_from_slice(&id);
        output.extend_from_slice(&(data.len() as u32).to_be_bytes());
        output.extend_from_slice(&data);
        output.resize(output.len() + (4 - data.len() % 4) % 4, 0);
    }
    let form_size = (output.len() - 8) as u32;
    output[4..8].copy_from_slice(&form_size.to_be_bytes());
    output
}

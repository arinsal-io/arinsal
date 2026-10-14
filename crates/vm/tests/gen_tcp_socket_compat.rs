//! `gen_tcp` over the `socket` backend (prim_socket) against OTP 29.1.1. Every socket
//! binds and connects on 127.0.0.1. The runtimes are started as programs because the
//! backend needs the kernel application (inet_db, socket registry).

use arinsal_difftest::RefErl;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SOURCE: &str = r#"
-module(gen_tcp_socket_compat).
-export([connect_accept_send_recv/0, connect_refused/0, accept_timeout/0,
         connect_after_listener_close/0]).

listen() ->
    {ok, Listen} = gen_tcp:listen(0, [{inet_backend, socket}, {ip, {127,0,0,1}},
                                      {active, false}]),
    {ok, Port} = inet:port(Listen),
    {Listen, Port}.

connect_accept_send_recv() ->
    {Listen, Port} = listen(),
    Parent = self(),
    spawn(fun() ->
        {ok, Accepted} = gen_tcp:accept(Listen, 2000),
        Parent ! {accepted, ok},
        Parent ! {received, gen_tcp:recv(Accepted, 2, 2000)},
        receive stop -> gen_tcp:close(Accepted) end
    end),
    {ok, Client} = gen_tcp:connect({127,0,0,1}, Port,
                                   [{inet_backend, socket}, {active, false}], 2000),
    Accepted = receive {accepted, A} -> A after 3000 -> timeout end,
    Sent = gen_tcp:send(Client, <<"hi">>),
    Received = receive {received, R} -> R after 3000 -> timeout end,
    Peer = inet:peername(Client),
    ok = gen_tcp:close(Client),
    ok = gen_tcp:close(Listen),
    {Accepted, Sent, Received, element(1, Peer),
     element(1, element(2, Peer)) =:= {127,0,0,1}}.

connect_refused() ->
    {Listen, Port} = listen(),
    ok = gen_tcp:close(Listen),
    gen_tcp:connect({127,0,0,1}, Port, [{inet_backend, socket}, {active, false}], 2000).

accept_timeout() ->
    {Listen, _Port} = listen(),
    Result = gen_tcp:accept(Listen, 200),
    ok = gen_tcp:close(Listen),
    Result.

connect_after_listener_close() ->
    {Listen, Port} = listen(),
    Parent = self(),
    spawn(fun() -> Parent ! {accepted, gen_tcp:accept(Listen, 500)} end),
    {ok, Client} = gen_tcp:connect({127,0,0,1}, Port,
                                   [{inet_backend, socket}, {active, false}], 2000),
    Accepted = receive {accepted, {ok, _}} -> ok; {accepted, Other} -> Other
               after 3000 -> timeout end,
    ok = gen_tcp:close(Client),
    ok = gen_tcp:close(Listen),
    Accepted.
"#;

fn run(program: &Path, dir: &Path, module: &str, function: &str) -> (bool, String) {
    let eval = format!("io:format(\"~p~n\", [{module}:{function}()]), halt().");
    let root = arinsal_difftest::reference::otp_root();
    let mut command = if program == Path::new("erl") {
        match &root {
            Some(root) => Command::new(root.join("bin/erl")),
            None => Command::new("erl"),
        }
    } else {
        let mut command = Command::new(program);
        if let Some(root) = &root {
            command.env("ERL_ROOTDIR", root);
        }
        command
    };
    command
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &eval])
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", program.display()));
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().expect("output");
                return (
                    output.status.success(),
                    String::from_utf8_lossy(&output.stdout).trim().to_string(),
                );
            }
            Ok(None) if started.elapsed() > Duration::from_secs(60) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{} timed out in {function}", program.display());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("wait {}: {error}", program.display()),
        }
    }
}

fn compare(function: &str) {
    compare_in("gen_tcp_socket_compat", SOURCE, function);
}

fn compare_in(module: &str, source: &str, function: &str) {
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping gen_tcp_socket differential test");
        return;
    };
    let beam = reference
        .compile_named(module, source, &[])
        .unwrap_or_else(|error| panic!("compile {module}: {error:?}"));
    let dir = std::env::temp_dir().join(format!("{module}_{}_{function}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{module}.beam")), beam).unwrap();
    let (erl_ok, expected) = run(Path::new("erl"), &dir, module, function);
    let (ok, actual) = run(&arinsal, &dir, module, function);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(erl_ok, "erl failed in {function}: {expected}");
    assert!(ok, "arinsal failed in {function}: {actual}");
    similar_asserts::assert_eq!(expected, actual, "{function}");
}

#[test]
fn connect_accept_send_recv_matches_erts() {
    compare("connect_accept_send_recv");
}

#[test]
fn connect_refused_matches_erts() {
    compare("connect_refused");
}

#[test]
fn accept_timeout_matches_erts() {
    compare("accept_timeout");
}

#[test]
fn connect_with_acceptor_matches_erts() {
    compare("connect_after_listener_close");
}

const CLOSE_SOURCE: &str = include_str!("fixtures/sock_close_compat.erl");

fn compare_close(function: &str) {
    compare_in("sock_close_compat", CLOSE_SOURCE, function);
}

#[test]
fn close_aborts_blocked_recv_matches_erts() {
    compare_close("close_aborts_blocked_recv");
}

#[test]
fn close_aborts_blocked_accept_matches_erts() {
    compare_close("close_aborts_blocked_accept");
}

#[test]
fn close_aborts_nowait_requestors_matches_erts() {
    compare_close("close_aborts_nowait_requestors");
}

#[test]
fn controlling_process_transfer_keeps_the_socket_open() {
    compare_close("controlling_process_transfer");
}

#[test]
fn controlling_process_to_a_dead_process_closes_the_socket() {
    compare_close("controlling_process_to_dead");
}

#[test]
fn owner_exit_closes_the_socket() {
    compare_close("owner_exit_closes");
}

#[test]
fn owner_exit_aborts_waiting_readers() {
    compare_close("owner_dies_with_waiting_reader");
}

#[test]
fn closer_exit_before_finalize_closes_the_socket() {
    compare_close("closer_dies_before_finalize");
}

#[test]
fn closing_from_a_process_that_is_not_the_owner() {
    compare_close("closer_not_owner");
}

#[test]
fn reader_exit_activates_the_next_reader() {
    compare_close("reader_death_activates_next");
}

#[test]
fn readers_are_served_in_queue_order() {
    compare_close("reader_queue_order");
}

#[test]
fn otp_options_round_trip_like_erts() {
    compare_close("otp_options");
}

#[test]
fn accepted_sockets_inherit_the_otp_options() {
    compare_close("accept_inherits");
}

#[test]
fn socket_options_round_trip_like_erts() {
    compare_close("socket_options");
}

#[test]
fn cancel_results_match_erts() {
    compare_close("cancel_ops");
}

#[test]
fn info_counters_and_registry_match_erts() {
    compare_close("info_and_registry");
}

#[test]
fn errno_atoms_match_erts() {
    compare_close("errnos");
}

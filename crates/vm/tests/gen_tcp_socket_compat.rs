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
         connect_after_listener_close/0, recv_partial_nowait/0, recv_partial_blocking/0,
         recv_timeouts/0, recv_nowait_select_message/0, two_readers/0,
         eof_aborts_queued_reader/0, gen_tcp_recv_n_partial/0]).

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

norm(R) when is_reference(R) -> ref;
norm(T) when is_tuple(T) -> list_to_tuple([norm(E) || E <- tuple_to_list(T)]);
norm(L) when is_list(L) -> [norm(E) || E <- L];
norm(T) -> T.

sock_pair() ->
    Addr = #{family => inet, addr => {127,0,0,1}, port => 0},
    {ok, L} = socket:open(inet, stream),
    ok = socket:bind(L, Addr),
    ok = socket:listen(L),
    {ok, #{port := Port}} = socket:sockname(L),
    {ok, C} = socket:open(inet, stream),
    ok = socket:connect(C, Addr#{port := Port}),
    {ok, A} = socket:accept(L, 2000),
    ok = socket:close(L),
    {C, A}.

recv_partial_nowait() ->
    {C, A} = sock_pair(),
    ok = socket:send(C, <<1,2>>),
    timer:sleep(100),
    R1 = socket:recv(A, 4, [], nowait),
    {select, {{select_info, recv, H}, <<1,2>>}} = R1,
    ok = socket:send(C, <<3,4>>),
    Sel = receive {'$socket', _, select, H} -> select after 2000 -> timeout end,
    R2 = socket:recv(A, 2, [], nowait),
    ok = socket:close(C),
    ok = socket:close(A),
    norm({R1, Sel, R2}).

recv_partial_blocking() ->
    {C, A} = sock_pair(),
    spawn(fun() ->
        timer:sleep(100), ok = socket:send(C, <<1,2>>),
        timer:sleep(200), ok = socket:send(C, <<3,4>>),
        timer:sleep(200), ok = socket:send(C, <<5,6,7>>)
    end),
    R1 = socket:recv(A, 4, 3000),
    R2 = socket:recv(A, 0, 3000),
    ok = socket:close(C),
    ok = socket:close(A),
    {R1, R2}.

recv_timeouts() ->
    {C, A} = sock_pair(),
    R1 = socket:recv(A, 4, 100),
    R2 = socket:recv(A, 0, 0),
    ok = socket:send(C, <<1,2>>),
    timer:sleep(100),
    R3 = socket:recv(A, 4, 100),
    ok = socket:send(C, <<9,9>>),
    timer:sleep(100),
    R4 = socket:recv(A, 4, 0),
    R5 = socket:recv(A, 0, 0),
    ok = socket:close(C),
    ok = socket:close(A),
    {R1, R2, R3, R4, R5}.

recv_nowait_select_message() ->
    {C, A} = sock_pair(),
    R1 = socket:recv(A, 0, [], nowait),
    {select, {select_info, recv, H}} = R1,
    ok = socket:send(C, <<"abc">>),
    Sel = receive {'$socket', _, select, H} -> select after 2000 -> timeout end,
    R2 = socket:recv(A, 0, [], nowait),
    R3 = socket:recv(A, 0, [], nowait),
    {select, {select_info, recv, H3}} = R3,
    ok = socket:cancel(A, {select_info, recv, H3}),
    ok = socket:close(C),
    ok = socket:close(A),
    norm({R1, Sel, R2, R3}).

await(Name, Tag, Timeout) ->
    receive {Name, Tag, V} -> V after Timeout -> none end.

reader(A, Name, Parent) ->
    spawn(fun() ->
        R = socket:recv(A, 0, [], nowait),
        Parent ! {Name, first, norm(R)},
        {select, {select_info, recv, H}} = R,
        Sel = receive
                  {'$socket', _, select, H} -> select;
                  {'$socket', _, abort, {H, Reason}} -> {abort, Reason}
              after 3000 -> timeout end,
        Parent ! {Name, selected, Sel},
        receive go -> ok after 3000 -> ok end,
        Parent ! {Name, second, norm(socket:recv(A, 0, [], nowait))}
    end).

two_readers() ->
    {C, A} = sock_pair(),
    Me = self(),
    Ra = reader(A, a, Me),
    R1 = await(a, first, 2000),
    Rb = reader(A, b, Me),
    R2 = await(b, first, 2000),
    ok = socket:send(C, <<"x">>),
    S1 = await(a, selected, 2000),
    S2 = await(b, selected, 300),
    Ra ! go,
    R3 = await(a, second, 2000),
    timer:sleep(100),
    ok = socket:send(C, <<"y">>),
    S3 = await(b, selected, 2000),
    Rb ! go,
    R4 = await(b, second, 2000),
    ok = socket:close(C),
    ok = socket:close(A),
    {R1, R2, S1, S2, R3, S3, R4}.

eof_aborts_queued_reader() ->
    {C, A} = sock_pair(),
    Me = self(),
    Ra = reader(A, a, Me),
    R1 = await(a, first, 2000),
    Rb = reader(A, b, Me),
    R2 = await(b, first, 2000),
    ok = socket:close(C),
    S1 = await(a, selected, 2000),
    S2 = await(b, selected, 2000),
    Ra ! go,
    Rb ! go,
    R3 = await(a, second, 2000),
    ok = socket:close(A),
    {R1, R2, S1, S2, R3}.

gen_tcp_recv_n_partial() ->
    {Listen, Port} = listen(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(Listen, 2000),
        timer:sleep(100), ok = gen_tcp:send(S, <<1,2>>),
        timer:sleep(200), ok = gen_tcp:send(S, <<3,4,5>>),
        timer:sleep(500), gen_tcp:close(S)
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [{inet_backend, socket}, {active, false}, binary], 2000),
    R1 = gen_tcp:recv(C, 4, 3000),
    R2 = gen_tcp:recv(C, 0, 3000),
    R3 = gen_tcp:recv(C, 2, 3000),
    ok = gen_tcp:close(C),
    ok = gen_tcp:close(Listen),
    {R1, R2, R3}.
"#;

fn run(program: &Path, dir: &Path, function: &str) -> (bool, String) {
    let eval = format!("io:format(\"~p~n\", [gen_tcp_socket_compat:{function}()]), halt().");
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
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping gen_tcp_socket differential test");
        return;
    };
    let beam = reference
        .compile_named("gen_tcp_socket_compat", SOURCE, &[])
        .expect("compile gen_tcp_socket_compat");
    let dir = std::env::temp_dir().join(format!(
        "gen_tcp_socket_compat_{}_{function}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("gen_tcp_socket_compat.beam"), beam).unwrap();
    let (erl_ok, expected) = run(Path::new("erl"), &dir, function);
    let (ok, actual) = run(&arinsal, &dir, function);
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

#[test]
fn recv_partial_nowait_matches_erts() {
    compare("recv_partial_nowait");
}

#[test]
fn recv_partial_blocking_matches_erts() {
    compare("recv_partial_blocking");
}

#[test]
fn recv_timeouts_match_erts() {
    compare("recv_timeouts");
}

#[test]
fn recv_nowait_select_message_matches_erts() {
    compare("recv_nowait_select_message");
}

#[test]
fn two_concurrent_readers_match_erts() {
    compare("two_readers");
}

#[test]
fn eof_aborts_queued_reader_matches_erts() {
    compare("eof_aborts_queued_reader");
}

#[test]
fn gen_tcp_recv_n_partial_matches_erts() {
    compare("gen_tcp_recv_n_partial");
}

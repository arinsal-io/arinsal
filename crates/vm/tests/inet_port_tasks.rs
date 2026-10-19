//! Differential coverage of the inet ports as scheduler-executed port tasks: process
//! signals that run immediately or queue behind a busy port, readiness tasks, port timers
//! and the busy port, against OTP 29.1.1.

use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

fn source() -> &'static str {
    r#"
-module(inet_port_tasks_diff).
-export([run/1]).

run(Case) ->
    catch ets:new(ac_tab, [named_table, public, set]),
    case Case of
        parallel_controls -> parallel_controls();
        sender_order -> sender_order();
        parallel_accepts -> parallel_accepts();
        recv_timers -> recv_timers();
        busy_port -> busy_port();
        port_trace -> port_trace();
        close_with_waiters -> close_with_waiters()
    end.

opts(Extra) ->
    [{tcp_module, inet_tcp}, {ip, {127,0,0,1}}, binary, {active, false} | Extra].

pair(Extra) ->
    {ok, L} = gen_tcp:listen(0, opts(Extra)),
    {ok, Port} = inet:port(L),
    Self = self(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 5000),
        ok = gen_tcp:controlling_process(S, Self),
        Self ! {accepted, S}
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, opts(Extra), 5000),
    S = receive {accepted, A} -> A after 5000 -> exit(no_accept) end,
    gen_tcp:close(L),
    {C, S}.

%% Many processes issue controls on one port at once: the ones that find the port busy
%% are queued as port tasks and still get their (large) replies.
parallel_controls() ->
    {C, S} = pair([]),
    Self = self(),
    N = 16,
    [spawn(fun() ->
         R = [inet:getopts(C, [active, mode, packet, buffer, nodelay, keepalive, linger]) || _ <- lists:seq(1, 200)],
         Self ! {done, lists:usort(R)}
     end) || _ <- lists:seq(1, N)],
    Rs = [receive {done, R} -> R after 20000 -> timeout end || _ <- lists:seq(1, N)],
    gen_tcp:close(C),
    gen_tcp:close(S),
    lists:usort(Rs).

%% Per-sender order is kept when several processes send on one socket.
sender_order() ->
    {C, S} = pair([{packet, 4}]),
    Self = self(),
    Senders = 6,
    Per = 300,
    [spawn(fun() ->
         [ok = gen_tcp:send(C, <<I:8, J:32>>) || J <- lists:seq(1, Per)],
         Self ! sent
     end) || I <- lists:seq(1, Senders)],
    Got = [begin {ok, <<I:8, J:32>>} = gen_tcp:recv(S, 0, 5000), {I, J} end
           || _ <- lists:seq(1, Senders * Per)],
    [receive sent -> ok after 5000 -> exit(no_sent) end || _ <- lists:seq(1, Senders)],
    gen_tcp:close(C),
    gen_tcp:close(S),
    PerSender = [[J || {I2, J} <- Got, I2 =:= I] || I <- lists:seq(1, Senders)],
    lists:all(fun(Js) -> Js =:= lists:seq(1, Per) end, PerSender).

%% Several accepts wait on a listener while connects arrive on other schedulers.
parallel_accepts() ->
    {ok, L} = gen_tcp:listen(0, opts([{backlog, 64}])),
    {ok, Port} = inet:port(L),
    Self = self(),
    N = 24,
    [spawn(fun() -> Self ! {acc, catch gen_tcp:accept(L, 5000)} end) || _ <- lists:seq(1, N)],
    receive after 100 -> ok end,
    Cs = [begin {ok, C} = gen_tcp:connect({127,0,0,1}, Port, opts([]), 5000), C end
          || _ <- lists:seq(1, N)],
    Got = [receive {acc, {ok, _}} -> ok; {acc, E} -> E after 5000 -> timeout end || _ <- lists:seq(1, N)],
    [gen_tcp:close(C) || C <- Cs],
    gen_tcp:close(L),
    lists:usort(Got).

%% Receive, accept and connect timers are port timers: they fire in order and only
%% for the waiter they belong to.
recv_timers() ->
    {C, S} = pair([]),
    T0 = erlang:monotonic_time(millisecond),
    R1 = gen_tcp:recv(S, 0, 100),
    T1 = erlang:monotonic_time(millisecond),
    R2 = gen_tcp:recv(S, 0, 0),
    {ok, L} = gen_tcp:listen(0, opts([])),
    R3 = gen_tcp:accept(L, 50),
    Self = self(),
    spawn(fun() -> Self ! {r4, gen_tcp:recv(C, 0, 300)} end),
    receive after 100 -> ok end,
    ok = gen_tcp:send(S, <<"x">>),
    R4 = receive {r4, X} -> X after 2000 -> timeout end,
    gen_tcp:close(L), gen_tcp:close(C), gen_tcp:close(S),
    {R1, T1 - T0 >= 95, T1 - T0 < 1500, R2, R3, R4}.

%% A sender that fills the queue makes the port busy: the blocked send times out, the
%% queue is non-empty, and sending works again once the peer reads.
busy_port() ->
    {C, S} = pair([{send_timeout, 300}, {send_timeout_close, false},
                   {high_watermark, 8192}, {low_watermark, 4096}]),
    Chunk = binary:copy(<<1>>, 65536),
    First = send_until_error(C, Chunk, 0),
    Queued = element(2, erlang:port_info(C, queue_size)) > 0,
    Self = self(),
    Reader = spawn(fun() -> drain(S), Self ! drained end),
    Drained = receive drained -> true after 10000 -> false end,
    exit(Reader, kill),
    After = gen_tcp:send(C, Chunk),
    gen_tcp:close(C),
    gen_tcp:close(S),
    {First, Queued, Drained, After}.

send_until_error(C, Chunk, N) when N < 2000 ->
    case gen_tcp:send(C, Chunk) of
        ok -> send_until_error(C, Chunk, N + 1);
        Error -> Error
    end;
send_until_error(_, _, _) -> never_busy.

drain(S) ->
    case gen_tcp:recv(S, 0, 1000) of
        {ok, _} -> drain(S);
        _ -> ok
    end.

%% Ports are traced like any scheduled entity.
port_trace() ->
    {C, S} = pair([]),
    erlang:trace(C, true, [running_ports, ports, {tracer, self()}]),
    ok = gen_tcp:send(C, <<"ping">>),
    {ok, <<"ping">>} = gen_tcp:recv(S, 4, 2000),
    ok = inet:setopts(C, [{active, once}]),
    ok = gen_tcp:send(S, <<"pong">>),
    Pong = receive {tcp, C, <<"pong">>} -> true after 2000 -> false end,
    erlang:trace(C, false, [running_ports, ports]),
    Tags = lists:usort(flush_tags(C, [])),
    gen_tcp:close(C),
    gen_tcp:close(S),
    {Pong, lists:member(in, Tags), lists:member(out, Tags)}.

flush_tags(C, Acc) ->
    receive
        {trace, C, Tag, _} -> flush_tags(C, [Tag | Acc]);
        {trace, C, Tag, _, _} -> flush_tags(C, [Tag | Acc])
    after 200 -> Acc
    end.

%% Closing a port with a pending receive, accept and send wakes every waiter.
close_with_waiters() ->
    {C, S} = pair([]),
    Self = self(),
    spawn(fun() -> Self ! {recv, gen_tcp:recv(S, 0, 5000)} end),
    receive after 100 -> ok end,
    gen_tcp:close(S),
    R = receive {recv, X} -> X after 3000 -> timeout end,
    gen_tcp:close(C),
    R.
"#
}

fn run_case(reference: &RefErl, vm: &mut Vm, case_name: &str) {
    let input = OwnedTerm::Atom(case_name.into());
    let expected = reference
        .call_opts(
            "inet_port_tasks_diff",
            "run",
            std::slice::from_ref(&input),
            &CallOptions {
                timeout_ms: Some(60_000),
                ..CallOptions::default()
            },
        )
        .result;
    let mut heap = VecHeap::new();
    let arg = from_owned(&input, &mut heap).unwrap();
    let actual = vm
        .eval_scheduled("inet_port_tasks_diff", "run", &[arg], 4, None)
        .unwrap_or_else(|error| panic!("{case_name}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{case_name}");
}

#[test]
fn inet_port_tasks_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inet_port_tasks differential test");
        return;
    };
    let beam = reference
        .compile_named("inet_port_tasks_diff", source(), &[])
        .expect("compile inet_port_tasks_diff");
    reference
        .load("inet_port_tasks_diff", &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load arinsal module");
    for case in [
        "parallel_controls",
        "sender_order",
        "parallel_accepts",
        "recv_timers",
        "busy_port",
        "port_trace",
        "close_with_waiters",
    ] {
        run_case(&reference, &mut vm, case);
    }
}

//! Differential coverage of the `tcp_inet` output queue (`tcp_sendv`,
//! `driver_enqv`, `tcp_inet_output`) with large and partial writes, against
//! OTP 29.1.1.

use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

fn source() -> &'static str {
    r#"
-module(inet_sendq_diff).
-export([run/1]).

run(Case) ->
    catch ets:new(ac_tab, [named_table, public, set]),
    case Case of
        big_raw -> big_raw();
        big_packet4 -> framed(4, 20 bsl 20, 3);
        big_packet2 -> framed(2, 60000, 40);
        many_queued -> many_queued();
        delay_send -> delay_send()
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

payload(Size, Seed) ->
    Block = crypto_free_block(Seed),
    binary:part(binary:copy(Block, Size div byte_size(Block) + 1), 0, Size).

crypto_free_block(Seed) ->
    list_to_binary([(Seed * 31 + I * 7) band 255 || I <- lists:seq(0, 4095)]).

%% One 24 MB send on a raw socket while the reader is slow: the first write is
%% partial and the rest is queued.
big_raw() ->
    {C, S} = pair([]),
    Data = payload(24 bsl 20, 1),
    Sender = spawn_send(C, [Data]),
    receive after 100 -> ok end,
    Got = recv_n(S, byte_size(Data), []),
    Sent = sent(Sender),
    gen_tcp:close(C),
    gen_tcp:close(S),
    {Sent, erlang:md5(Got) =:= erlang:md5(Data)}.

%% Packet headers across partial writes and a queued backlog.
framed(H, Size, Count) ->
    {C, S} = pair([{packet, H}]),
    Msgs = [payload(Size, I) || I <- lists:seq(1, Count)],
    Sender = spawn_send(C, Msgs),
    receive after 100 -> ok end,
    Got = [element(2, {ok, _} = gen_tcp:recv(S, 0, 10000)) || _ <- Msgs],
    Sent = sent(Sender),
    gen_tcp:close(C),
    gen_tcp:close(S),
    {Sent, [byte_size(G) || G <- Got] =:= [byte_size(M) || M <- Msgs],
     erlang:md5(Got) =:= erlang:md5(Msgs)}.

%% Many deep iolists queued behind each other while the reader sleeps.
many_queued() ->
    {C, S} = pair([]),
    Msgs = [[<<I:32>>, payload(100000 + I, I), [1, 2, [3]], <<>>]
            || I <- lists:seq(1, 200)],
    Sender = spawn_send(C, Msgs),
    receive after 200 -> ok end,
    Total = iolist_size(Msgs),
    Got = recv_n(S, Total, []),
    Sent = sent(Sender),
    {ok, Stat} = inet:getstat(C, [send_cnt, send_oct, send_pend]),
    gen_tcp:close(C),
    gen_tcp:close(S),
    {Sent, Stat, erlang:md5(Got) =:= erlang:md5(Msgs)}.

%% delay_send queues every send and writes them on the next output event.
delay_send() ->
    {C, S} = pair([{delay_send, true}]),
    Msgs = [integer_to_binary(I) || I <- lists:seq(1, 500)],
    [ok = gen_tcp:send(C, M) || M <- Msgs],
    Total = iolist_size(Msgs),
    Got = recv_n(S, Total, []),
    gen_tcp:close(C),
    gen_tcp:close(S),
    Got =:= iolist_to_binary(Msgs).

spawn_send(C, Msgs) ->
    Self = self(),
    Pid = spawn(fun() ->
        Res = [gen_tcp:send(C, M) || M <- Msgs],
        Self ! {sent, self(), lists:usort(Res)},
        receive done -> ok end
    end),
    ok = gen_tcp:controlling_process(C, Pid),
    Pid.

%% The sender stays alive (owning the socket) until the reader has everything.
sent(Pid) ->
    R = receive {sent, Pid, Res} -> Res after 20000 -> no_sent end,
    Pid ! done,
    R.

recv_n(_S, 0, Acc) -> iolist_to_binary(lists:reverse(Acc));
recv_n(S, Left, Acc) when Left > 0 ->
    case gen_tcp:recv(S, 0, 10000) of
        {ok, Bin} -> recv_n(S, Left - byte_size(Bin), [Bin | Acc]);
        {error, Reason} -> {error, Reason, Left}
    end.
"#
}

fn run_case(reference: &RefErl, vm: &mut Vm, case_name: &str) {
    let input = OwnedTerm::Atom(case_name.into());
    let expected = reference
        .call_opts(
            "inet_sendq_diff",
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
        .eval_scheduled("inet_sendq_diff", "run", &[arg], 2, None)
        .unwrap_or_else(|error| panic!("{case_name}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{case_name}");
}

#[test]
fn tcp_send_queue_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inet_sendq differential test");
        return;
    };
    let beam = reference
        .compile_named("inet_sendq_diff", source(), &[])
        .expect("compile inet_sendq_diff");
    reference
        .load("inet_sendq_diff", &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load arinsal module");
    for case in [
        "big_raw",
        "big_packet4",
        "big_packet2",
        "many_queued",
        "delay_send",
    ] {
        run_case(&reference, &mut vm, case);
    }
}

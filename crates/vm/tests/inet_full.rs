//! Differential TCP `inet_drv` coverage against OTP 29.1.1.

use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

fn source() -> &'static str {
    r#"
-module(inet_full_diff).
-export([run/1]).

run(Case) ->
    catch ets:new(ac_tab, [named_table, public, set]),
    case Case of
        opts -> opts();
        opts6 -> opts6();
        rawopt -> rawopt();
        active_n -> active_n();
        errors -> errors();
        packets -> packets();
        http -> http();
        partial -> partial();
        stats -> stats();
        ifaces -> ifaces();
        local -> local();
        reset -> reset();
        send_timeout -> send_timeout();
        connect_timeout -> connect_timeout();
        refused -> refused();
        debug_on -> debug_on();
        sched -> sched();
        default_ifaces -> default_ifaces()
    end.

listen(Extra) ->
    gen_tcp:listen(0, [{tcp_module, inet_tcp}, {active, false} | Extra]).

opts() ->
    {ok, S} = listen([]),
    Spec = [
        {reuseaddr, true},
        {keepalive, true},
        {linger, {true, 3}},
        {sndbuf, 8192},
        {recbuf, 8192},
        {priority, 1},
        {tos, 16},
        {nodelay, true},
        {nopush, true},
        {buffer, 4096},
        {header, 2},
        {packet, 2},
        {packet_size, 1000},
        {mode, binary},
        {deliver, port},
        {exit_on_close, false},
        {high_watermark, 10000},
        {low_watermark, 2000},
        {high_msgq_watermark, 9000},
        {low_msgq_watermark, 1000},
        {send_timeout, 1500},
        {send_timeout_close, true},
        {delay_send, true},
        {show_econnreset, true},
        {line_delimiter, $\r},
        {recvtos, true},
        {ttl, 7},
        {recvttl, true},
        {reuseport, true},
        {reuseport_lb, true},
        {debug, false}
    ],
    Got = [roundtrip(S, Item) || Item <- Spec],
    gen_tcp:close(S),
    Got.

opts6() ->
    {ok, S} = listen([inet6]),
    Got = [roundtrip(S, Item) || Item <- [{tclass, 16}, {ipv6_v6only, true}]],
    gen_tcp:close(S),
    Got.

rawopt() ->
    {ok, S} = listen([]),
    Set = inet:setopts(S, [{raw, 6, 1, <<1:32/native>>}]),
    Get = inet:getopts(S, [{raw, 6, 1, 4}]),
    gen_tcp:close(S),
    {Set, Get}.

active_n() ->
    {ok, S} = listen([]),
    A = inet:setopts(S, [{active, 3}]),
    B = inet:getopts(S, [active]),
    C = inet:setopts(S, [{active, 2}]),
    D = inet:getopts(S, [active]),
    E = inet:setopts(S, [{active, -1}]),
    F = inet:getopts(S, [active]),
    gen_tcp:close(S),
    {A, B, C, D, E, F}.

roundtrip(S, {Opt, Val}) ->
    {Opt, inet:setopts(S, [{Opt, Val}]), inet:getopts(S, [Opt])}.

errors() ->
    {ok, S} = listen([]),
    E1 = inet:setopts(S, [{netns, <<"/">>}]),
    E2 = inet:setopts(S, [{bind_to_device, <<"lo0">>}]),
    E3 = inet:getopts(S, [netns]),
    E4 = inet:getopts(S, [bind_to_device]),
    E5 = inet:setopts(S, [{high_msgq_watermark, 0}]),
    E6 = inet:setopts(S, [{active, 99}]),
    gen_tcp:close(S),
    {E1, E2, E3, E4, E5, E6}.

packets() ->
    [echo(Mode) || Mode <- [raw, 0, 1, 2, 4, line, asn1, cdr, sunrm, fcgi, tpkt]].

echo(raw) -> {raw, split(<<"abcdef">>, 2, 4)};
echo(0) -> {0, split(<<"abcdef">>, 2, 4)};
echo(Mode) -> {Mode, two(Mode, <<"ab">>, <<"cd">>)}.

split(Payload, N, M) ->
    {ok, L} = listen([binary]),
    {ok, Port} = inet:port(L),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        ok = gen_tcp:send(S, Payload),
        receive after 300 -> gen_tcp:close(S) end
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [{tcp_module, inet_tcp}, binary, {active, false}], 2000),
    A = gen_tcp:recv(C, N, 2000),
    B = gen_tcp:recv(C, M, 2000),
    gen_tcp:close(C),
    gen_tcp:close(L),
    {A, B}.

two(Mode, A, B) ->
    Opts = [binary, {active, false}, {packet, Mode}],
    {ok, L} = gen_tcp:listen(0, [{tcp_module, inet_tcp} | Opts]),
    {ok, Port} = inet:port(L),
    Parent = self(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        R1 = gen_tcp:recv(S, 0, 200),
        R2 = gen_tcp:recv(S, 0, 200),
        Parent ! {got, R1, R2}
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [{tcp_module, inet_tcp} | Opts], 2000),
    ok = gen_tcp:send(C, A),
    ok = gen_tcp:send(C, B),
    Got = receive
        {got, R1, R2} -> {R1, R2}
    after 2000 ->
        timeout
    end,
    gen_tcp:close(C),
    gen_tcp:close(L),
    Got.

http() ->
    [http_mode(Mode) || Mode <- [http, http_bin, httph, httph_bin]].

http_mode(Mode) ->
    Opts = [binary, {active, false}, {packet, Mode}],
    {ok, L} = gen_tcp:listen(0, [{tcp_module, inet_tcp} | Opts]),
    {ok, Port} = inet:port(L),
    Parent = self(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        R1 = gen_tcp:recv(S, 0, 2000),
        R2 = gen_tcp:recv(S, 0, 2000),
        R3 = gen_tcp:recv(S, 0, 2000),
        Parent ! {http, R1, R2, R3}
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [{tcp_module, inet_tcp}, binary, {active, false}], 2000),
    ok = gen_tcp:send(C, <<"GET /idx HTTP/1.0\r\nHost: h\r\n\r\n">>),
    Got = receive
        {http, R1, R2, R3} -> {Mode, R1, R2, R3}
    after 2000 ->
        {Mode, timeout}
    end,
    gen_tcp:close(C),
    gen_tcp:close(L),
    Got.

partial() ->
    Opts = [binary, {active, false}, {packet, 2}],
    {ok, L} = gen_tcp:listen(0, [{tcp_module, inet_tcp} | Opts]),
    {ok, Port} = inet:port(L),
    Peer = spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        ok = gen_tcp:send(S, <<0>>),
        receive
            more -> ok = gen_tcp:send(S, <<0, 3, "xyz">>)
        after 2000 ->
            ok
        end,
        receive after 200 -> gen_tcp:close(S) end
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [{tcp_module, inet_tcp} | Opts], 2000),
    receive after 80 -> ok end,
    R1 = gen_tcp:recv(C, 0, 0),
    Peer ! more,
    R2 = gen_tcp:recv(C, 0, 2000),
    gen_tcp:close(C),
    gen_tcp:close(L),
    {R1, R2}.

stats() ->
    {ok, L} = listen([binary]),
    {ok, Port} = inet:port(L),
    Parent = self(),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        {ok, Bin} = gen_tcp:recv(S, 4, 2000),
        ok = gen_tcp:send(S, Bin),
        Parent ! sent,
        receive after 300 -> gen_tcp:close(S) end
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [{tcp_module, inet_tcp}, binary, {active, false}], 2000),
    {ok, Before} = inet:getstat(C),
    ok = gen_tcp:send(C, <<"ping">>),
    {ok, <<"ping">>} = gen_tcp:recv(C, 4, 2000),
    receive sent -> ok after 2000 -> ok end,
    {ok, After} = inet:getstat(C),
    {ok, Sub} = inet:getstat(C, [recv_cnt, send_cnt, send_pend]),
    gen_tcp:close(C),
    gen_tcp:close(L),
    {Before, After, Sub, mono(Before, After)}.

mono(Before, After) ->
    [cmp(Key, Before, After) || Key <- [recv_cnt, recv_oct, send_cnt, send_oct]].

cmp(Key, Before, After) ->
    {Key, proplists:get_value(Key, After) >= proplists:get_value(Key, Before)}.

ifaces() ->
    {ok, S} = listen([]),
    Addrs = inet:getifaddrs(S),
    Ifs = inet:getif(S),
    List = inet:getiflist(S) ,
    gen_tcp:close(S),
    {shape(Addrs), Ifs, List}.

default_ifaces() ->
    {shape(inet:getifaddrs()), inet:getiflist(), inet:getif()}.

shape({ok, Addrs}) ->
    {ok, [iface(A) || A <- Addrs]};
shape(Other) ->
    Other.

iface({Name, Opts}) ->
    {is_list(Name), [optkey(O) || O <- Opts]}.

optkey({flags, _}) -> flags;
optkey({addr, _}) -> addr;
optkey({netmask, _}) -> netmask;
optkey({broadaddr, _}) -> broadaddr;
optkey({dstaddr, _}) -> dstaddr;
optkey({hwaddr, _}) -> hwaddr;
optkey({K, _}) -> K.

local() ->
    Path = "/tmp/arinsal-inet-" ++ os:getpid(),
    case gen_tcp:listen(0, [{tcp_module, local_tcp}, local, binary, {ifaddr, {local, Path}}, {active, false}]) of
        {ok, L} ->
            spawn(fun() ->
                {ok, S} = gen_tcp:accept(L, 2000),
                {ok, Bin} = gen_tcp:recv(S, 4, 2000),
                ok = gen_tcp:send(S, Bin),
                receive after 200 -> gen_tcp:close(S) end
            end),
            Conn = gen_tcp:connect({local, Path}, 0, [{tcp_module, local_tcp}, local, binary, {active, false}], 2000),
            Got = case Conn of
                {ok, C} ->
                    ok = gen_tcp:send(C, <<"unix">>),
                    R = gen_tcp:recv(C, 4, 2000),
                    gen_tcp:close(C),
                    R;
                Err ->
                    Err
            end,
            gen_tcp:close(L),
            Got;
        Err ->
            Err
    end.

reset() ->
    %% gen_tcp_misc_SUITE:do_show_econnreset_passive connects and accepts
    %% before the peer aborts. Closing from a concurrent acceptor before
    %% SO_ERROR is read makes Darwin report the handshake as ECONNRESET.
    {ok, L} = listen([binary, {show_econnreset, true}]),
    {ok, Port} = inet:port(L),
    Parent = self(),
    Pid = spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        Parent ! accepted,
        receive close ->
            ok = inet:setopts(S, [{linger, {true, 0}}]),
            gen_tcp:close(S),
            Parent ! closed
        end
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [{tcp_module, inet_tcp}, binary, {active, false}, {show_econnreset, true}], 2000),
    receive accepted -> ok after 2000 -> timeout end,
    Pid ! close,
    receive closed -> ok after 2000 -> timeout end,
    R = gen_tcp:recv(C, 1, 2000),
    gen_tcp:close(C),
    gen_tcp:close(L),
    R.

send_timeout() ->
    {ok, L} = listen([binary]),
    {ok, Port} = inet:port(L),
    spawn(fun() ->
        {ok, S} = gen_tcp:accept(L, 2000),
        receive after 800 -> gen_tcp:close(S) end
    end),
    {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [{tcp_module, inet_tcp}, binary, {active, false}], 2000),
    ok = inet:setopts(C, [{send_timeout, 0}, {high_watermark, 1}, {sndbuf, 1024}]),
    Big = binary:copy(<<1>>, 262144),
    R1 = gen_tcp:send(C, Big),
    R2 = gen_tcp:send(C, Big),
    gen_tcp:close(C),
    gen_tcp:close(L),
    {R1, R2}.

connect_timeout() ->
    gen_tcp:connect({192,0,2,1}, 1, [{tcp_module, inet_tcp}, {active, false}], 200).

refused() ->
    gen_tcp:connect({127,0,0,1}, 1, [{tcp_module, inet_tcp}, {active, false}], 400).

sched() ->
    {ok, L} = listen([]),
    gen_tcp:close(L),
    ok.

%% `{debug, true}` makes inet_drv erts_printf on every later op, which would
%% corrupt the difftest port. This case only sets and gets that flag.
debug_on() ->
    {ok, S} = listen([]),
    Set = inet:setopts(S, [{debug, true}]),
    Get = inet:getopts(S, [debug]),
    gen_tcp:close(S),
    {Set, Get}.
"#
}

/// The TCP registry is process-global and keyed by port id. Two `Vm`s in one
/// test process allocate the same ids, so these tests must not overlap.
fn ports_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn run_case(reference: &RefErl, vm: &mut Vm, case_name: &str) {
    let input = OwnedTerm::Atom(case_name.into());
    let expected = reference
        .call_opts(
            "inet_full_diff",
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
        .eval_scheduled("inet_full_diff", "run", &[arg], 2, None)
        .unwrap_or_else(|error| panic!("{case_name}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{case_name}");
}

#[test]
fn tcp_inet_matches_erts() {
    let _ports = ports_lock();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inet_full differential test");
        return;
    };
    let beam = reference
        .compile_named("inet_full_diff", source(), &[])
        .expect("compile inet_full_diff");
    reference
        .load("inet_full_diff", &beam)
        .expect("load reference module");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load arinsal module");
    for case in [
        "opts",
        "opts6",
        "rawopt",
        "active_n",
        "errors",
        "packets",
        "http",
        "partial",
        "stats",
        "ifaces",
        "default_ifaces",
        "local",
        "reset",
        "send_timeout",
        "connect_timeout",
        "refused",
    ] {
        run_case(&reference, &mut vm, case);
    }
    std::fs::write("/tmp/inet_full_diff.beam", &beam).unwrap();
    let status = std::process::Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "{ok,B}=file:read_file(\"/tmp/inet_full_diff.beam\"), {module,_}=code:load_binary(inet_full_diff,\"x.beam\",B), file:write_file(\"/tmp/debug_on.term\", io_lib:format(\"~p\", [inet_full_diff:run(debug_on)])), halt().",
        ])
        .status()
        .expect("erl");
    assert!(status.success());
    let expected = std::fs::read_to_string("/tmp/debug_on.term").unwrap();
    assert_eq!(expected.trim(), "{ok,{ok,[{debug,true}]}}");
    let input = OwnedTerm::Atom("debug_on".into());
    let mut heap = VecHeap::new();
    let arg = from_owned(&input, &mut heap).unwrap();
    let actual = vm
        .eval_scheduled("inet_full_diff", "run", &[arg], 2, None)
        .expect("debug_on");
    assert_eq!(
        actual.term,
        OwnedTerm::Tuple(vec![
            OwnedTerm::Atom("ok".into()),
            OwnedTerm::Tuple(vec![
                OwnedTerm::Atom("ok".into()),
                OwnedTerm::List {
                    elems: vec![OwnedTerm::Tuple(vec![
                        OwnedTerm::Atom("debug".into()),
                        OwnedTerm::Atom("true".into()),
                    ])],
                    tail: Box::new(OwnedTerm::Nil),
                },
            ]),
        ])
    );
}

// Asks the kernel directly; `ps` is unavailable in sandboxed agent runs.
#[cfg(not(target_os = "macos"))]
fn thread_count() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("/proc/self/task")
        .count()
}

#[cfg(target_os = "macos")]
fn thread_count() -> usize {
    // SAFETY: proc_taskinfo is plain integers; all-zero is a valid value.
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: `info` is a writable buffer of exactly `size` bytes for PROC_PIDTASKINFO.
    let written = unsafe {
        libc::proc_pidinfo(
            std::process::id() as libc::c_int,
            libc::PROC_PIDTASKINFO,
            0,
            (&raw mut info).cast(),
            size,
        )
    };
    assert_eq!(written, size, "proc_pidinfo");
    info.pti_threadnum as usize
}

#[test]
fn scheduler_exits_after_tcp_port() {
    let _ports = ports_lock();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping scheduler-exit test");
        return;
    };
    let beam = reference
        .compile_named("inet_full_diff", source(), &[])
        .expect("compile");
    let once = || {
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).expect("load");
        let input = OwnedTerm::Atom("sched".into());
        let mut heap = VecHeap::new();
        let arg = from_owned(&input, &mut heap).unwrap();
        vm.eval_scheduled("inet_full_diff", "run", &[arg], 2, None)
            .expect("sched");
    };
    once();
    std::thread::sleep(std::time::Duration::from_millis(150));
    let after_first = thread_count();
    once();
    std::thread::sleep(std::time::Duration::from_millis(150));
    let after_second = thread_count();
    assert!(
        after_second <= after_first + 1,
        "scheduler threads leaked: {after_first} then {after_second}"
    );
}

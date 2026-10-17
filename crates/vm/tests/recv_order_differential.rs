use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(recv_order_diff).
-export([selective/0, skip_long/0, wait_nonmatching/0, after_zero/0, after_body/0,
         wait_forever_exit/0, signals_while_scanning/0, preempted_scan/0, nested_wait/0]).

selective() ->
    self() ! a, self() ! b, self() ! c, self() ! d,
    C = receive c -> c end,
    A = receive a -> a end,
    D = receive d -> d end,
    B = receive Any -> Any end,
    [C, A, D, B].

skip_long() ->
    N = 30000,
    [self() ! {m, I} || I <- lists:seq(1, N)],
    Last = receive {m, N} -> N end,
    Rest = [receive {m, I} -> I end || I <- lists:seq(1, N - 1)],
    {Last, length(Rest), hd(Rest), lists:last(Rest)}.

wait_nonmatching() ->
    Self = self(),
    spawn(fun() ->
                  timer:sleep(5), Self ! noise,
                  timer:sleep(5), Self ! noise2,
                  timer:sleep(5), Self ! wanted
          end),
    Got = receive wanted -> wanted end,
    Left = [receive X -> X after 0 -> none end, receive Y -> Y after 0 -> none end],
    {Got, Left}.

after_zero() ->
    self() ! other,
    R1 = receive wanted -> hit after 0 -> miss end,
    self() ! wanted,
    R2 = receive wanted -> hit after 0 -> miss end,
    R3 = receive wanted -> hit after 0 -> miss end,
    R4 = receive other -> hit after 0 -> miss end,
    [R1, R2, R3, R4].

after_body() ->
    self() ! one, self() ! two,
    R1 = receive three -> three after 5 -> timeout1 end,
    R2 = receive two -> two after 5 -> timeout2 end,
    R3 = receive two -> two after 5 -> timeout3 end,
    R4 = receive one -> one after 5 -> timeout4 end,
    [R1, R2, R3, R4].

wait_forever_exit() ->
    P = spawn(fun() -> receive never -> ok end end),
    Ref = monitor(process, P),
    receive after 10 -> ok end,
    S1 = process_info(P, status),
    P ! not_matching,
    receive after 10 -> ok end,
    S2 = process_info(P, [status, message_queue_len]),
    exit(P, kill),
    Reason = receive {'DOWN', Ref, process, P, R} -> R end,
    {S1, S2, Reason}.

signals_while_scanning() ->
    Self = self(),
    Pids = [spawn(fun() -> [Self ! {from, I, J} || J <- lists:seq(1, 200)] end)
            || I <- lists:seq(1, 20)],
    Counts = [begin
                  receive {from, I, 200} -> ok end,
                  length([ok || J <- lists:seq(1, 199),
                                receive {from, I, J} -> true after 1000 -> false end])
              end || I <- lists:seq(1, 20)],
    _ = Pids,
    lists:usort(Counts).

preempted_scan() ->
    Self = self(),
    Counter = spawn(fun() -> counter(0) end),
    [Self ! {m, I} || I <- lists:seq(1, 50000)],
    Last = receive {m, 50000} -> last end,
    Counter ! {get, Self},
    Ticks = receive {ticks, T} -> T end,
    {Last, Ticks > 0}.

counter(N) ->
    receive
        {get, From} -> From ! {ticks, N}
    after 0 -> counter(N + 1)
    end.

nested_wait() ->
    Self = self(),
    spawn(fun() -> timer:sleep(5), Self ! {inner, 1}, timer:sleep(5), Self ! {outer, 2} end),
    receive
        {outer, O} ->
            receive {inner, I} -> {O, I} after 0 -> {O, none} end
    after 2000 -> timeout
    end.
"#;

fn compare(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping {function} receive-order differential test");
        return;
    };
    let beam = reference
        .compile_named("recv_order_diff", SOURCE, &[])
        .unwrap();
    reference.load("recv_order_diff", &beam).unwrap();
    let expected = reference.call("recv_order_diff", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("recv_order_diff", function, &[], 2, Some(0x0dd5))
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn recv_order_selective() {
    compare("selective");
}

#[test]
fn recv_order_skip_long_queue() {
    compare("skip_long");
}

#[test]
fn recv_order_wait_nonmatching() {
    compare("wait_nonmatching");
}

#[test]
fn recv_order_after_zero() {
    compare("after_zero");
}

#[test]
fn recv_order_after_body() {
    compare("after_body");
}

#[test]
fn recv_order_wait_forever_then_exit() {
    compare("wait_forever_exit");
}

#[test]
fn recv_order_signals_while_scanning() {
    compare("signals_while_scanning");
}

#[test]
fn recv_order_preempted_scan() {
    compare("preempted_scan");
}

#[test]
fn recv_order_nested_wait() {
    compare("nested_wait");
}

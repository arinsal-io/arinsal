use arinsal_difftest::{CallResult, RefErl};

/// `code_server` spawns the on_load runner with
/// `spawn_opt(Fun, [{monitor, [{tag, {'ON_LOAD_DOWN', Mod}}]}])`.
/// The message tag is that tuple, and the return value is `{Pid, Ref}`.
#[test]
fn spawn_opt_monitor_tag_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping spawn_opt monitor-tag differential test");
        return;
    };
    let source = "-module(mix_loop2_monitor_tag). -export([run/0]).
        run() ->
            Tag = {on_load_down, crypto},
            {Pid, Ref} = spawn_opt(fun() -> ok end, [{monitor, [{tag, Tag}]}]),
            receive
                {Tag, Ref, process, Pid, Reason} -> {ok, Reason}
            after 2000 ->
                timeout
            end.";
    let beam = reference
        .compile_named("mix_loop2_monitor_tag", source, &[])
        .unwrap();
    reference.load("mix_loop2_monitor_tag", &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let expected = reference.call("mix_loop2_monitor_tag", "run", &[]);
    let actual = vm
        .eval_scheduled("mix_loop2_monitor_tag", "run", &[], 2)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

/// A child that exits in its first slice must still deliver a tagged DOWN.
/// `code_server` spawns the on_load runner this way; the monitor has to be
/// installed before the child is scheduled.
#[test]
fn spawn_opt_monitor_tag_survives_immediate_exit() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping immediate-exit monitor differential test");
        return;
    };
    let source = "-module(mix_loop2_monitor_race). -export([run/0]).
        run() ->
            Tag = {'ON_LOAD_DOWN', crypto},
            lists:foreach(fun(_) ->
                {Pid, Ref} = spawn_opt(fun() -> exit(ok) end, [{monitor, [{tag, Tag}]}]),
                receive
                    {Tag, Ref, process, Pid, ok} -> ok
                after 2000 ->
                    error(timeout)
                end
            end, lists:seq(1, 64)),
            ok.";
    let beam = reference
        .compile_named("mix_loop2_monitor_race", source, &[])
        .unwrap();
    reference.load("mix_loop2_monitor_race", &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let expected = reference.call("mix_loop2_monitor_race", "run", &[]);
    let actual = vm
        .eval_scheduled("mix_loop2_monitor_race", "run", &[], 4)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

/// Exercises the signal-fetch/inactivate race in `wait` with independent
/// senders running on other schedulers and a short reduction quantum.
#[test]
fn receive_sees_message_that_arrives_on_the_wait_instruction() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping wait-instruction receive test");
        return;
    };
    let source = "-module(mix_loop2_wait_yield). -export([run/0]).
        run() ->
            Parent = self(),
            N = 256,
            Rounds = 20,
            Receivers = [spawn(fun() -> receiver(Parent, I, Rounds) end)
                         || I <- lists:seq(1, N)],
            wait_ready(N),
            Senders = [spawn(fun() ->
                sender(Receiver, I, Rounds)
            end) || {Receiver, I} <- lists:zip(Receivers, lists:seq(1, N))],
            _ = Senders,
            collect(N).
        receiver(Parent, I, Rounds) ->
            Parent ! {ready, I},
            receive
                {payload, I, 1, Sender} ->
                    Sender ! {ack, I, 1},
                    receiver_loop(Parent, I, Rounds, 2, Sender)
            end.
        receiver_loop(Parent, I, Rounds, Rounds, _Sender) ->
            receive {payload, I, Rounds, _} -> Parent ! done end;
        receiver_loop(Parent, I, Rounds, Round, Sender) ->
            receive
                {payload, I, Round, Sender} ->
                    Sender ! {ack, I, Round},
                    receiver_loop(Parent, I, Rounds, Round + 1, Sender)
            end.
        sender(Receiver, I, Rounds) ->
            Receiver ! {payload, I, 1, self()},
            sender_loop(Receiver, I, Rounds, 1).
        sender_loop(_Receiver, _I, Rounds, Rounds) -> ok;
        sender_loop(Receiver, I, Rounds, Round) ->
            receive
                {ack, I, Round} ->
                    Receiver ! {payload, I, Round + 1, self()},
                    sender_loop(Receiver, I, Rounds, Round + 1)
            end.
        wait_ready(0) -> ok;
        wait_ready(N) ->
            receive {ready, _} -> wait_ready(N - 1)
            after 10000 -> error(ready_timeout) end.
        collect(0) -> ok;
        collect(N) ->
            receive
                done -> collect(N - 1);
                Other -> Other
            after 10000 ->
                {timeout, N}
            end.";
    let beam = reference
        .compile_named("mix_loop2_wait_yield", source, &[])
        .unwrap();
    reference.load("mix_loop2_wait_yield", &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let expected = reference.call("mix_loop2_wait_yield", "run", &[]);
    let actual = vm
        .eval_scheduled_reductions("mix_loop2_wait_yield", "run", &[], 4, 2)
        .unwrap();
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

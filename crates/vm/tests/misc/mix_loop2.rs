use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

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
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let expected = reference.call("mix_loop2_monitor_tag", "run", &[]);
    let actual = vm
        .eval_scheduled("mix_loop2_monitor_tag", "run", &[], 2, Some(83))
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
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let expected = reference.call("mix_loop2_monitor_race", "run", &[]);
    let actual = vm
        .eval_scheduled("mix_loop2_monitor_race", "run", &[], 4, None)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

/// A one-reduction quantum yields on `wait` after `loop_rec` saw an empty
/// mailbox. The message that arrives before that `wait` executes must still
/// be received. This is the Hex.State `gen:call` alias-reply timeout: the
/// server slept with `{'$gen_call', ...}` already in its inbox, the caller
/// demonitored, and `gen:reply` to the alias was dropped.
#[test]
fn receive_sees_message_that_arrives_on_the_wait_instruction() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping wait-instruction receive test");
        return;
    };
    let source = "-module(mix_loop2_wait_yield). -export([run/0]).
        run() ->
            Parent = self(),
            Server = spawn(fun() -> loop() end),
            N = 80,
            lists:foreach(fun(I) ->
                spawn(fun() ->
                    Server ! {self(), I},
                    receive
                        {ack, I} -> Parent ! done
                    after 2000 ->
                        Parent ! {timeout, I}
                    end
                end)
            end, lists:seq(1, N)),
            collect(N).
        loop() ->
            receive
                {From, I} -> From ! {ack, I}, loop()
            end.
        collect(0) -> ok;
        collect(N) ->
            receive
                done -> collect(N - 1);
                Other -> Other
            after 5000 ->
                {timeout, N}
            end.";
    let beam = reference
        .compile_named("mix_loop2_wait_yield", source, &[])
        .unwrap();
    reference.load("mix_loop2_wait_yield", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let expected = reference.call("mix_loop2_wait_yield", "run", &[]);
    let actual = vm
        .eval_scheduled_reductions("mix_loop2_wait_yield", "run", &[], 2, None, 1)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

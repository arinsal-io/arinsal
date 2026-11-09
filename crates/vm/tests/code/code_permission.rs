use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, decode, encode};
use arinsal_vm::Vm;

/// Whitebox scenario of code_SUITE:code_permission, trimmed: a waiter that is user-suspended
/// while queued for the code modification permission must still run a GC system task.
#[test]
fn code_permission_gc_of_suspended_waiter_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping code_permission differential test");
        return;
    };
    let source = r#"-module(code_perm_gc).
        -export([run/0]).
        run() ->
            erts_debug:set_internal_state(available_internal_state, true),
            %% Load everything needed while the permission is held.
            timer:sleep(1), _ = process_info(self(), status), _ = erlang:garbage_collect(self()),
            Tester = self(),
            Fun = fun() ->
                receive lock -> ok end,
                true = erts_debug:set_internal_state(code_mod_permission, true),
                Tester ! {self(), locked},
                receive unlock -> ok end,
                true = erts_debug:set_internal_state(code_mod_permission, false),
                Tester ! {self(), unlocked}
            end,
            L1 = spawn_link(Fun), L4 = spawn_link(Fun), L5 = spawn_link(Fun),
            L1 ! lock,
            {L1, locked} = recv(),
            L4 ! lock, wait_suspended(L4),
            erlang:suspend_process(L4),
            L5 ! lock, wait_suspended(L5),
            L1 ! unlock,
            {L1, unlocked} = recv(),
            R = (catch erlang:garbage_collect(L4)),
            erlang:resume_process(L4),
            {L5, locked} = recv(),
            L5 ! unlock,
            {L5, unlocked} = recv(),
            {L4, locked} = recv(),
            L4 ! unlock,
            {L4, unlocked} = recv(),
            R.
        recv() -> receive {P, _} = M when is_pid(P) -> M after 5000 -> timeout end.
        wait_suspended(P) ->
            timer:sleep(10),
            case process_info(P, status) of
                {status, suspended} -> ok;
                _ -> wait_suspended(P)
            end."#;
    let beam = reference
        .compile_named("code_perm_gc", source, &[])
        .unwrap();
    reference.load("code_perm_gc", &beam).unwrap();
    let expected = reference.call("code_perm_gc", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("code_perm_gc", "run", &[], 2, None)
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

//! Differential coverage of the process/port name registry against OTP 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(reg_table_diff).
-export([run/0]).
bad(F) ->
    try F() of _ -> no
    catch error:badarg -> badarg
    end.
wait_gone(Name, 0) -> whereis(Name);
wait_gone(Name, N) ->
    case whereis(Name) of
        undefined -> undefined;
        _ -> receive after 10 -> wait_gone(Name, N - 1) end
    end.
run() ->
    Name = reg_table_self,
    true = register(Name, self()),
    SelfWhere = whereis(Name) =:= self(),
    SelfMember = lists:member(Name, registered()),
    SelfInfo = process_info(self(), registered_name),
    Got = (Name ! reg_table_tok),
    Received = receive reg_table_tok -> ok after 1000 -> timeout end,
    Parent = self(),
    Other = spawn(fun() ->
        true = register(reg_table_other, self()),
        Parent ! {ready, self()},
        receive stop -> ok end
    end),
    receive {ready, Other} -> ok end,
    OtherWhere = whereis(reg_table_other) =:= Other,
    OtherMember = lists:member(reg_table_other, registered()),
    OtherInfo = process_info(Other, registered_name),
    AlreadyName = bad(fun() -> register(Name, Other) end),
    AlreadyProc = bad(fun() -> register(reg_table_second, self()) end),
    Undef = bad(fun() -> register(undefined, self()) end),
    NonAtom = bad(fun() -> register(1, self()) end),
    NonId = bad(fun() -> register(reg_table_bad_id, 1) end),
    {Dead, DeadRef} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', DeadRef, process, Dead, _} -> ok end,
    NotAlive = bad(fun() -> register(reg_table_dead, Dead) end),
    WhereUndef = whereis(undefined),
    WhereMissing = whereis(reg_table_no_such),
    WhereNonAtom = bad(fun() -> whereis(1) end),
    UnregMissing = bad(fun() -> unregister(reg_table_no_such) end),
    UnregUndef = bad(fun() -> unregister(undefined) end),
    true = unregister(Name),
    After = whereis(Name),
    AfterInfo = process_info(self(), registered_name),
    AfterMember = lists:member(Name, registered()),
    SendMissing = bad(fun() -> reg_table_no_such ! 1 end),
    {ExitPid, ExitRef} = spawn_monitor(fun() ->
        true = register(reg_table_exit, self()),
        Parent ! exit_ready,
        receive stop -> ok end
    end),
    receive exit_ready -> ok end,
    ExitWhere = whereis(reg_table_exit) =:= ExitPid,
    exit(ExitPid, kill),
    receive {'DOWN', ExitRef, process, ExitPid, _} -> ok end,
    ExitGone = wait_gone(reg_table_exit, 50),
    Port = open_port({spawn_executable, "/bin/cat"}, []),
    true = register(reg_table_port, Port),
    PortWhere = whereis(reg_table_port) =:= Port,
    PortMember = lists:member(reg_table_port, registered()),
    PortBusy = bad(fun() -> register(reg_table_port, self()) end),
    true = unregister(reg_table_port),
    PortUnreg = whereis(reg_table_port),
    true = register(reg_table_port, Port),
    port_close(Port),
    PortClosed = wait_gone(reg_table_port, 50),
    Other ! stop,
    {SelfWhere, SelfMember, SelfInfo, Got, Received,
     OtherWhere, OtherMember, OtherInfo,
     AlreadyName, AlreadyProc, Undef, NonAtom, NonId, NotAlive,
     WhereUndef, WhereMissing, WhereNonAtom, UnregMissing, UnregUndef,
     After, AfterInfo, AfterMember, SendMissing,
     ExitWhere, ExitGone,
     PortWhere, PortMember, PortBusy, PortUnreg, PortClosed}.
"#;

#[test]
fn register_whereis_unregister_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping register-table differential test");
        return;
    };
    let beam = reference
        .compile_named("reg_table_diff", SOURCE, &[])
        .expect("compile reg_table_diff");
    reference
        .load("reg_table_diff", &beam)
        .expect("load reg_table_diff into erl");
    let expected = reference.call("reg_table_diff", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load reg_table_diff");
    let actual = vm
        .eval_scheduled("reg_table_diff", "run", &[], 1, None)
        .expect("run reg_table_diff");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_class_c).
-export([scenario/1, noop/0]).
noop() -> ok.
scenario(0) -> P=spawn(fun() -> ok end), true=is_pid(P), ok;
scenario(1) -> P=spawn(node(), fun() -> ok end), true=is_pid(P), ok;
scenario(2) -> P=spawn(node(), proc_class_c, noop, []), true=is_pid(P), ok;
scenario(3) -> P=spawn_link(fun() -> ok end), true=is_pid(P), ok;
scenario(4) -> P=spawn_link(node(), fun() -> ok end), true=is_pid(P), ok;
scenario(5) -> P=spawn_link(node(), proc_class_c, noop, []), true=is_pid(P), ok;
scenario(6) -> {P,R}=spawn_monitor(fun() -> ok end), true=is_pid(P), receive {'DOWN',R,process,P,normal} -> ok end;
scenario(7) -> {P,R}=spawn_monitor(node(), fun() -> ok end), true=is_pid(P), receive {'DOWN',R,process,P,normal} -> ok end;
scenario(8) -> {P,R}=spawn_monitor(proc_class_c, noop, []), true=is_pid(P), receive {'DOWN',R,process,P,normal} -> ok end;
scenario(9) -> {P,R}=spawn_monitor(node(), proc_class_c, noop, []), true=is_pid(P), receive {'DOWN',R,process,P,normal} -> ok end;
scenario(10) -> P=spawn_opt(fun() -> ok end, []), true=is_pid(P), ok;
scenario(11) -> P=spawn_opt(node(), fun() -> ok end, []), true=is_pid(P), ok;
scenario(12) -> P=spawn_opt(node(), proc_class_c, noop, [], []), true=is_pid(P), ok;
scenario(13) -> badarg=catch_badarg(fun() -> spawn(not_a_fun) end), ok;
scenario(14) -> badarg=catch_badarg(fun() -> spawn(node(), not_a_fun) end), ok;
scenario(15) -> badarg=catch_badarg(fun() -> spawn_link(not_a_fun) end), ok;
scenario(16) -> badarg=catch_badarg(fun() -> spawn_link(node(), not_a_fun) end), ok;
scenario(17) -> badarg=catch_badarg(fun() -> spawn_monitor(not_a_fun) end), ok;
scenario(18) -> badarg=catch_badarg(fun() -> spawn_monitor(node(), not_a_fun) end), ok;
scenario(19) -> badarg=catch_badarg(fun() -> spawn_opt(not_a_fun, []) end), ok;
scenario(20) -> badarg=catch_badarg(fun() -> spawn_opt(node(), not_a_fun, []) end), ok;
scenario(21) -> badarg=catch_badarg(fun() -> spawn_opt(node(), proc_class_c, noop, [], [invalid]) end), ok;
scenario(22) -> true=garbage_collect(self()), ok;
scenario(23) -> badarg=catch_badarg(fun() -> garbage_collect(not_a_pid) end), ok;
scenario(24) -> true=garbage_collect(self(), [{type,minor}]), badarg=catch_badarg(fun() -> garbage_collect(self(), [invalid]) end), ok;
scenario(25) -> L=group_leader(), true=group_leader(L,self()), badarg=catch_badarg(fun() -> group_leader(true,self()) end), ok;
scenario(26) -> 0=process_flag(self(),save_calls,4), 4=process_flag(self(),save_calls,0), badarg=catch_badarg(fun() -> process_flag(not_a_pid,save_calls,1) end), ok;
scenario(27) -> true=erlang:send_nosuspend(self(),hello,[]), receive hello -> ok end, badarg=catch_badarg(fun() -> erlang:send_nosuspend(self(),hello,[bad]) end), ok;
scenario(28) -> P=spawn(fun() -> receive stop -> ok end end), true=erlang:suspend_process(P), true=erlang:resume_process(P), P!stop, ok;
scenario(29) -> P=spawn(fun() -> receive stop -> ok end end), true=erlang:suspend_process(P,[unless_suspending]), true=erlang:resume_process(P), P!stop, badarg=catch_badarg(fun() -> erlang:suspend_process(P,[bad]) end), ok;
scenario(30) -> badarg=catch_badarg(fun() -> erlang:process_display(self(),bad) end), ok.
catch_badarg(F) -> try F() of _ -> unexpected catch error:badarg -> badarg end.
"#;

#[test]
fn removed_process_wrappers_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process wrapper spawn differential test");
        return;
    };
    let beam = reference
        .compile_named("proc_class_c", SOURCE, &[])
        .unwrap();
    reference.load("proc_class_c", &beam).unwrap();
    for scenario in 0..31 {
        let expected = reference.call("proc_class_c", "scenario", &[OwnedTerm::Int(scenario)]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled(
                "proc_class_c",
                "scenario",
                &[Term::small(scenario).unwrap()],
                2,
                Some(97),
            )
            .unwrap_or_else(|error| panic!("scenario {scenario}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "scenario {scenario}");
    }
}

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_diff).
-export([scenario/2,send_value/2]).
scenario(0,N) ->
    Parent=self(), spawn(fun()->Parent!{value,N} end),
    receive {value,N} -> N end;
scenario(1,N) ->
    R=make_ref(), self()!{skip,N}, self()!{R,N+1},
    V=receive {R,X} -> X end,
    receive {skip,N} -> V end;
scenario(2,N) ->
    self()!{other,N}, receive {wanted,_} -> bad after 0 -> N end;
scenario(3,N) -> receive after 10 -> N end;
scenario(4,N) ->
    R=erlang:send_after(100,self(),{never,N}),
    V=erlang:cancel_timer(R),
    case is_integer(V) of true -> N; false -> bad end;
scenario(5,N) ->
    R=erlang:start_timer(10,self(),N),
    receive {timeout,R,N} -> N end;
scenario(6,N) ->
    process_flag(trap_exit,true),
    P=spawn_link(fun()->exit({bad,N}) end),
    receive {'EXIT',P,{bad,N}} -> N end;
scenario(7,N) ->
    P=spawn(fun()->exit({bad,N}) end),
    R=monitor(process,P),
    receive {'DOWN',R,process,P,{bad,N}} -> ok end,
    R2=monitor(process,P),
    receive {'DOWN',R2,process,P,noproc} -> N end;
scenario(8,N) ->
    register(proc_diff_name,self()),
    P=whereis(proc_diff_name),
    unregister(proc_diff_name),
    case P =:= self() of true -> N; false -> bad end;
scenario(9,N) ->
    P=spawn(fun()->receive after infinity -> ok end end),
    R=monitor(process,P),
    true=demonitor(R,[flush,info]),
    exit(P,kill),
    receive {'DOWN',R,process,P,_} -> bad after 0 -> N end;
scenario(10,N) ->
    {heap_size,S}=process_info(self(),heap_size),
    case S >= 64 of true -> N; false -> bad end;
scenario(11,N) ->
    spawn_link(fun()->ok end),
    receive after 10 -> N end;
scenario(12,N) ->
    {Pid,R}=spawn_monitor(fun()->
        spawn_link(fun()->exit({bad,N}) end),
        receive after infinity -> ok end
    end),
    receive {'DOWN',R,process,Pid,{bad,N}} -> N end;
scenario(13,N) ->
    register(proc_diff_name,self()),
    proc_diff_name ! N,
    receive N -> unregister(proc_diff_name), N end;
scenario(14,N) ->
    Parent=self(), spawn(node(),fun()->Parent!N end),
    receive N -> N end;
scenario(15,N) ->
    spawn(proc_diff,send_value,[self(),N]),
    receive N -> N end;
scenario(16,N) ->
    {Pid,R}=spawn_monitor(proc_diff,send_value,[self(),N]),
    receive N -> ok end,
    receive {'DOWN',R,process,Pid,normal} -> N end;
scenario(17,N) ->
    ok=erlang:send(self(),N,[nosuspend,noconnect]),
    receive N -> N end;
scenario(18,N) ->
    erlang:send_after(10,self(),N,[{abs,false}]),
    receive N -> N end;
scenario(19,N) ->
    R=erlang:send_after(100,self(),N),
    true=is_integer(erlang:read_timer(R,[{async,false}])),
    ok=erlang:cancel_timer(R,[{async,false},{info,false}]),
    N;
scenario(20,N) ->
    Parent=self(),
    {Pid,R}=spawn_opt(fun()->Parent!N end,[monitor,{min_heap_size,64}]),
    receive N -> ok end,
    receive {'DOWN',R,process,Pid,normal} -> N end;
scenario(21,N) ->
    process_flag(trap_exit,true),
    Pid=spawn_opt(node(),fun()->exit({bad,N}) end,[link]),
    receive {'EXIT',Pid,{bad,N}} -> N end;
scenario(22,N) ->
    {Pid,R}=spawn_opt(proc_diff,send_value,[self(),N],[monitor]),
    receive N -> ok end,
    receive {'DOWN',R,process,Pid,normal} -> N end;
scenario(23,N) ->
    {Pid,R}=spawn_opt(node(),proc_diff,send_value,[self(),N],[monitor]),
    receive N -> ok end,
    receive {'DOWN',R,process,Pid,normal} -> N end.
send_value(P,N) -> P ! N.
"#;

#[test]
fn process_scenarios_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process differential scenarios");
        return;
    };
    let beam = reference.compile_named("proc_diff", SOURCE, &[]).unwrap();
    reference.load("proc_diff", &beam).unwrap();
    let repetitions = std::env::var("ARINSAL_CASES")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(20);
    let mut count = 0;
    for category in 0..24 {
        for n in 1..=repetitions {
            let expected = reference.call(
                "proc_diff",
                "scenario",
                &[OwnedTerm::Int(category), OwnedTerm::Int(n)],
            );
            let mut vm = Vm::new([]);
            vm.load_bytes(&beam).unwrap();
            let args = [Term::small(category).unwrap(), Term::small(n).unwrap()];
            let actual = vm
                .eval_scheduled("proc_diff", "scenario", &args, 1, Some(17))
                .unwrap_or_else(|error| panic!("category {category} n {n}: {error}"));
            assert_eq!(
                expected,
                CallResult::Ok(actual.term),
                "category {category} n {n}"
            );
            count += 1;
        }
    }
    assert!(
        count >= 200 || repetitions < 20,
        "only {count} scenarios ran"
    );
    eprintln!("process differential: {count} scenarios, zero mismatches");
}

#[test]
fn child_port_round_trip_and_exit_events_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping child port differential scenarios");
        return;
    };
    let source = r#"
-module(port_diff).
-export([packet/0, line/0, status/0]).
packet() ->
    P = open_port({spawn_executable, "/bin/cat"}, [binary, {packet, 2}, exit_status]),
    true = port_command(P, <<"hi">>),
    receive {P, {data, <<"hi">>}} -> port_close(P), ok after 5000 -> timeout end.
line() ->
    P = open_port({spawn, "printf hello"}, [binary, {line, 5}, eof]),
    receive {P, {data, {noeol, <<"hello">>}}} -> receive {P, eof} -> port_close(P), ok after 5000 -> timeout end;
        _ -> timeout after 5000 -> timeout end.
status() ->
    P = open_port({spawn_executable, "/bin/sh"}, [exit_status, {args, ["-c", "exit 3"]}]),
    receive {P, {exit_status, 3}} -> ok after 5000 -> timeout end.
"#;
    let beam = reference.compile_named("port_diff", source, &[]).unwrap();
    reference.load("port_diff", &beam).unwrap();
    for function in ["packet", "line", "status"] {
        let expected = reference.call("port_diff", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled("port_diff", function, &[], 1, None);
        assert_eq!(expected, CallResult::Ok(actual.unwrap().term), "{function}");
    }
}

#[test]
fn simulation_repeats_thousand_process_trace() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping simulation trace");
        return;
    };
    let source = r#"
-module(sim_trace).
-export([run/0]).
run() ->
    Parent=self(),
    [spawn(fun()->Parent!{I,(I*73) rem 997} end) || I <- lists:seq(1,1000)],
    collect(1000,[]).
collect(0,Acc) -> lists:reverse(Acc);
collect(N,Acc) -> receive Message -> collect(N-1,[Message|Acc]) end.
"#;
    let beam = reference.compile_named("sim_trace", source, &[]).unwrap();
    let run = || {
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        vm.eval_scheduled("sim_trace", "run", &[], 1, Some(0x5eed))
            .unwrap()
            .term
    };
    let first = run();
    let second = run();
    assert_eq!(first, second);
    match &first {
        OwnedTerm::List { elems, tail } => {
            assert_eq!(elems.len(), 1000);
            assert_eq!(**tail, OwnedTerm::Nil);
        }
        other => panic!("expected a 1000-message trace, got {other:?}"),
    }
}

#[test]
fn process_errors_reach_beam_catch_handlers() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process error differential test");
        return;
    };
    let source = r#"
-module(proc_errors).
-export([scenario/1]).
scenario(0) -> try 42 ! ok catch error:badarg -> badarg end;
scenario(1) -> T = -1, try receive after T -> no_error end
               catch error:timeout_value -> timeout_value end;
scenario(2) -> try exit({stopped,42}) catch exit:{stopped,42} -> caught_exit end.
"#;
    let beam = reference.compile_named("proc_errors", source, &[]).unwrap();
    reference.load("proc_errors", &beam).unwrap();
    for category in 0..3 {
        let expected = reference.call("proc_errors", "scenario", &[OwnedTerm::Int(category)]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled(
                "proc_errors",
                "scenario",
                &[Term::small(category).unwrap()],
                2,
                None,
            )
            .unwrap_or_else(|error| panic!("category {category}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "category {category}");
    }
}

#[test]
fn parallel_lazy_imports_share_one_module_id() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping parallel import test");
        return;
    };
    let source = r#"
-module(load_race).
-export([run/1,worker/1]).
run(N) -> spawn_many(N,self()), gather(N).
spawn_many(0,_) -> ok;
spawn_many(N,P) -> spawn(load_race,worker,[P]), spawn_many(N-1,P).
worker(P) -> [1,2] = lists:seq(1,2), P ! ok.
gather(0) -> ok;
gather(N) -> receive ok -> gather(N-1) after 5000 -> timeout end.
"#;
    let beam = reference.compile_named("load_race", source, &[]).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let result = vm
        .eval_scheduled("load_race", "run", &[Term::small(200).unwrap()], 4, None)
        .unwrap();
    assert_eq!(result.term, OwnedTerm::Atom("ok".into()));
}

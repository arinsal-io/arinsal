use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_diff).
-export([scenario/2,scenario33_many/1,scenario33_start/0,scenario33_cycle/0,
         scenario33_stop/0,send_value/2]).
scenario33_start() ->
    Parent=self(),
    Names=[proc_diff_select_1,proc_diff_select_2,proc_diff_select_3,
           proc_diff_select_4,proc_diff_select_5],
    Pids=[spawn(fun() ->
        true=register(Name,self()),
        Parent!{selector_ready,self()},
        select_forever()
    end) || Name <- Names],
    [receive {selector_ready,Pid} -> ok end || Pid <- Pids],
    ok.
scenario33_cycle() -> select_owner_exit_exact(), ok.
scenario33_stop() ->
    Names=[proc_diff_select_1,proc_diff_select_2,proc_diff_select_3,
           proc_diff_select_4,proc_diff_select_5],
    [case whereis(Name) of undefined -> ok; Pid -> exit(Pid,kill) end || Name <- Names],
    ok.
scenario33_many(Count) ->
    Selectors=[spawn_link(fun select_forever/0) || _ <- lists:seq(1,5)],
    repeat_owner_exit(Count),
    [begin unlink(Pid),exit(Pid,kill) end || Pid <- Selectors],
    ok.
repeat_owner_exit(0) -> ok;
repeat_owner_exit(Count) ->
    select_owner_exit_exact(),
    repeat_owner_exit(Count-1).
select_owner_exit_exact() ->
    Parent=self(), Name=proc_diff_select_name,
    Owner=spawn_link(fun() ->
        true=register(Name,self()),
        Name=ets:new(Name,[named_table,ordered_set]),
        true=ets:insert(Name,[{I,I} || I <- lists:seq(1,100)]),
        lists:foreach(fun(_) -> erlang:send_after(1000000,self(),{a,b,c}) end,
                      lists:seq(1,1000)),
        Parent!ets_owner_ready,
        receive die -> ok end
    end),
    receive ets_owner_ready -> Owner!die end,
    wait_for_unregistered(Name),
    Name=ets:new(Name,[named_table,ordered_set]),
    true=ets:delete(Name).
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
    receive {'DOWN',R,process,Pid,normal} -> N end;
scenario(24,N) ->
    Pid=spawn(fun()->receive after infinity -> ok end end),
    Pid!hej,
    timer:sleep(300),
    {N,process_info(Pid,[reductions,status])};
scenario(25,N) ->
    Parent=self(),
    spawn_opt(fun() ->
        Controller=self(),
        Blocked=erlang:system_flag(multi_scheduling,block_normal),
        spawn_opt(fun() -> Controller ! high_ran end,[{priority,high}]),
        spawn_opt(fun() -> Controller ! normal_ran end,[{priority,normal}]),
        receive high_ran -> ok after 2000 -> erlang:system_flag(multi_scheduling,unblock_normal), erlang:error(high_starved) end,
        Early=receive normal_ran -> true after 0 -> false end,
        Previous=erlang:system_flag(multi_scheduling,unblock_normal),
        receive normal_ran -> Parent ! {priority_result,Blocked,Previous,Early} after 2000 -> erlang:error(normal_starved) end
    end,[{priority,max}]),
    receive {priority_result,Blocked,Previous,Early} -> {Blocked,Previous,Early,N} after 3000 -> erlang:error(timeout) end;
scenario(26,N) ->
    Previous=erlang:system_flag(schedulers_online,1),
    Online=erlang:system_info(schedulers_online),
    Restored=erlang:system_flag(schedulers_online,Previous),
    {Online,Restored,N};
scenario(27,N) ->
    OomFun=fun(run) -> grow_until_limit([],100); (Value) -> Value end,
    {Pid,Ref}=spawn_opt(fun() -> OomFun(run) end,
                        [monitor,{max_heap_size,2024}]),
    receive {'DOWN',Ref,process,Pid,killed} -> N end;
scenario(28,N) ->
    Pid=spawn_opt(fun() -> receive stop -> ok end end,
                  [{min_heap_size,987}]),
    {min_heap_size,987}=process_info(Pid,min_heap_size),
    Pid ! stop,
    N;
scenario(29,N) ->
    Pid=spawn(fun() -> receive stop -> ok end end),
    {initial_call,{erlang,apply,2}}=process_info(Pid,initial_call),
    Pid ! stop,
    N;
scenario(30,N) ->
    Pid=spawn(proc_diff,send_value,[self(),N]),
    {initial_call,{proc_diff,send_value,2}}=process_info(Pid,initial_call),
    receive N -> N end;
scenario(31,N) ->
    Parent=self(),
    Previous=erlang:system_flag(max_heap_size,
                                #{size=>0,kill=>false,error_logger=>false}),
    {PartialPid,PartialRef}=spawn_opt(
        fun() -> Parent!{partial_max_heap,process_info(self(),max_heap_size)} end,
        [monitor,{max_heap_size,#{size=>2024}}]),
    {InheritedPid,InheritedRef}=spawn_monitor(
        fun() -> Parent!{inherited_max_heap,process_info(self(),max_heap_size)} end),
    receive {partial_max_heap,Partial} ->
        receive {'DOWN',PartialRef,process,PartialPid,normal} -> ok end
    end,
    receive {inherited_max_heap,Inherited} ->
        receive {'DOWN',InheritedRef,process,InheritedPid,normal} -> ok end
    end,
    erlang:system_flag(max_heap_size,Previous),
    {Previous,Partial,Inherited,N};
scenario(32,N) ->
    Parent=self(),
    Previous=erlang:system_flag(max_heap_size,
        #{size=>2024,kill=>true,error_logger=>false,
          include_shared_binaries=>true}),
    {Pid,Ref}=spawn_monitor(fun() -> Parent!{finished,N} end),
    receive {finished,N} -> ok end,
    receive {'DOWN',Ref,process,Pid,normal} -> ok end,
    erlang:system_flag(max_heap_size,Previous),
    N;
scenario(33,N) ->
    Parent=self(),
    Name=proc_diff_ets_name,
    spawn(fun() ->
        true=register(Name,self()),
        Name=ets:new(Name,[named_table,ordered_set]),
        lists:foreach(fun(_) -> erlang:send_after(1000000,self(),{a,b,c}) end,
                       lists:seq(1,1000)),
        Parent!ets_ready
    end),
    receive ets_ready -> ok end,
    wait_for_unregistered(Name),
    Name=ets:new(Name,[named_table,ordered_set]),
    true=ets:delete(Name),
    N;
scenario(34,N) ->
    process_flag(trap_exit,true),
    Parent=self(), Name=proc_diff_select_name,
    Selectors=[spawn_link(fun select_forever/0) || _ <- lists:seq(1,5)],
    select_owner_exit(Parent,Name),
    [exit(Pid,kill) || Pid <- Selectors],
    {ok,N};
scenario(35,N) ->
    {run_spin(busy),run_spin(yield),run_spin(timer),N};
scenario(36,N) ->
    Table=ets:new(proc_diff_config,[bag,{keypos,2}]),
    true=ets:insert(Table,{ct_conf,key,value,handler,config,allocated,false}),
    true=ets:insert(Table,{ct_conf,key2,value,handler,config,'_UNDEF',false}),
    Spec=[{{ct_conf,'$1','_','_','_','$2','_'},
           [{'=/=','$2','_UNDEF'}],['$_']}],
    {ets:select(Table,Spec),N};
scenario(37,N) ->
    process_flag(trap_exit,true),
    Pid=spawn_link(fun() -> catch exit(self(),die) end),
    receive {'EXIT',Pid,die} -> N after 2000 -> timeout end;
scenario(38,N) ->
    erlang:garbage_collect(),
    erlang:yield(),
    {reductions,R1}=process_info(self(),reductions),
    true=erlang:bump_reductions(100),
    {reductions,R2}=process_info(self(),reductions),
    Diff=R2-R1,
    {Diff >= 100 andalso Diff =< 110,N};
scenario(39,N) ->
    %% gc_SUITE:max_heap_size: a sleeping receiver is not collected until a GC request.
    Pid=spawn_opt(fun() -> receive after 10000 -> ok end end,
                  [{max_heap_size,1024},{message_queue_data,on_heap}]),
    [Pid ! lists:duplicate(I,I) || I <- lists:seq(1,100)],
    Ref=erlang:monitor(process,Pid),
    erlang:process_info(Pid,messages),
    erlang:garbage_collect(Pid),
    receive {'DOWN',Ref,process,Pid,Reason} -> {Reason,N} after 5000 -> {timeout,N} end.
wait_for_unregistered(Name) ->
    case whereis(Name) of
        undefined -> ok;
        _ -> wait_for_unregistered(Name)
    end.
select_owner_exit(Parent,Name) ->
    Owner=spawn_link(fun() ->
        true=register(Name,self()),
        Name=ets:new(Name,[named_table,ordered_set]),
        true=ets:insert(Name,[{I,I} || I <- lists:seq(1,100)]),
        [erlang:send_after(1000000,self(),{a,b,c}) || _ <- lists:seq(1,1000)],
        Parent!{ets_owner_ready,self()},
        receive die -> ok end
    end),
    receive {ets_owner_ready,Owner} -> Owner!die end,
    wait_for_unregistered(Name),
    Name=ets:new(Name,[named_table,ordered_set]),
    true=ets:delete(Name),
    receive {'EXIT',Owner,normal} -> ok end.
select_forever() ->
    catch ets:select(proc_diff_select_name,
                     [{{'$1',does_not_exist},[],['$1']}]),
    select_forever().
spin_missing_ets() ->
    catch ets:lookup(proc_diff_missing_ets,key),
    spin_missing_ets().
run_spin(Mode) ->
    process_flag(trap_exit,true),
    Pid=spawn_link(fun spin_missing_ets/0),
    case Mode of
        busy -> spin_count(3000000);
        yield -> [erlang:yield() || _ <- lists:seq(1,1000)];
        timer -> receive after 100 -> ok end
    end,
    exit(Pid,kill),
    receive {'EXIT',Pid,killed} -> true after 2000 -> timeout end.
spin_count(0) -> ok;
spin_count(N) -> spin_count(N-1).
grow_until_limit(_Acc,0) -> done;
grow_until_limit(Acc,N) ->
    timer:sleep(5),
    grow_until_limit([lists:seq(1,1000)|Acc],N-1).
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
    let categories = std::env::var("ARINSAL_CASE_ONLY")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .map_or_else(|| (0..40).collect::<Vec<_>>(), |category| vec![category]);
    let mut count = 0;
    for category in categories {
        let started = std::time::Instant::now();
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
                .eval_scheduled(
                    "proc_diff",
                    "scenario",
                    &args,
                    if matches!(category, 25 | 33) { 6 } else { 1 },
                    if matches!(category, 33..=35) {
                        None
                    } else {
                        Some(17)
                    },
                )
                .unwrap_or_else(|error| panic!("category {category} n {n}: {error}"));
            assert_eq!(
                expected,
                CallResult::Ok(actual.term),
                "category {category} n {n}"
            );
            count += 1;
        }
        eprintln!("category {category}: {:?}", started.elapsed());
    }
    assert!(
        count >= 200 || repetitions < 20,
        "only {count} scenarios ran"
    );
    eprintln!("process differential: {count} scenarios, zero mismatches");
}

#[test]
fn process_info_sig_free_items_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping process_info fast-path differential test");
        return;
    };
    let source = r#"
-module(pinfo_qlen_diff).
-export([run/0]).
run() ->
    Parent=self(), Name=pinfo_qlen_target,
    Pid=spawn(fun() ->
        true=register(Name,self()), Parent!{ready,self()}, receive stop -> ok end
    end),
    receive {ready,Pid} -> ok end,
    await_waiting(Pid),
    {message_queue_len,0}=process_info(Pid,message_queue_len),
    {status,waiting}=process_info(Pid,status),
    {registered_name,Name}=process_info(Pid,registered_name),
    {heap_size,Heap}=process_info(Pid,heap_size),
    true=is_integer(Heap),
    [{message_queue_len,0},{status,waiting},{registered_name,Name},{heap_size,_}]=
        process_info(Pid,[message_queue_len,status,registered_name,heap_size]),
    Unnamed=spawn(fun() -> Parent!{unnamed,self()}, receive stop -> ok end end),
    receive {unnamed,Unnamed} -> ok end,
    await_waiting(Unnamed),
    []=process_info(Unnamed,registered_name),
    [{registered_name,[]}]=process_info(Unnamed,[registered_name]),
    exit(Unnamed,kill),
    Pid!queued,
    {message_queue_len,1}=process_info(Pid,message_queue_len),
    {memory,Memory}=process_info(Pid,memory),
    true=is_integer(Memory) andalso Memory > 0,
    exit(Pid,kill),
    {message_queue_len,0}=process_info(self(),message_queue_len),
    {status,running}=process_info(self(),status),
    {heap_size,SelfHeap}=process_info(self(),heap_size),
    true=is_integer(SelfHeap),
    self()!self_queued,
    {message_queue_len,1}=process_info(self(),message_queue_len),
    receive self_queued -> ok end,
    {message_queue_len,0}=process_info(self(),message_queue_len),
    true.
await_waiting(Pid) ->
    case process_info(Pid,status) of
        {status,waiting} -> ok;
        _ -> timer:sleep(1), await_waiting(Pid)
    end.
"#;
    let beam = reference
        .compile_named("pinfo_qlen_diff", source, &[])
        .unwrap();
    reference.load("pinfo_qlen_diff", &beam).unwrap();
    let expected = reference.call("pinfo_qlen_diff", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("pinfo_qlen_diff", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("process_info direct-path scenario: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
    assert_eq!(expected, CallResult::Ok(OwnedTerm::Atom("true".into())));
}

#[test]
fn otp_6237_owner_exit_100_cycles_match_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping otp_6237 differential stress scenario");
        return;
    };
    let beam = reference.compile_named("proc_diff", SOURCE, &[]).unwrap();
    reference.load("proc_diff", &beam).unwrap();
    let started = std::time::Instant::now();
    let expected = reference.call("proc_diff", "scenario33_many", &[OwnedTerm::Int(100)]);
    eprintln!(
        "OTP otp_6237: 100 owner cycles in {:.2}s",
        started.elapsed().as_secs_f64()
    );
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let _ = vm
        .eval_scheduled("proc_diff", "scenario33_start", &[], 6, None)
        .unwrap_or_else(|error| panic!("otp_6237 selector startup: {error}"));
    let started = std::time::Instant::now();
    let mut actual = None;
    for cycle in 1..=100 {
        if cycle % 10 == 0 {
            eprintln!("Arinsal otp_6237: starting owner cycle {cycle}");
        }
        actual = Some(
            vm.eval_scheduled("proc_diff", "scenario33_cycle", &[], 6, None)
                .unwrap_or_else(|error| panic!("otp_6237 owner cycle {cycle}: {error}")),
        );
    }
    let _ = vm
        .eval_scheduled("proc_diff", "scenario33_stop", &[], 6, None)
        .unwrap_or_else(|error| panic!("otp_6237 selector cleanup: {error}"));
    eprintln!(
        "Arinsal otp_6237: 100 owner cycles in {:.2}s",
        started.elapsed().as_secs_f64()
    );
    assert_eq!(
        expected,
        CallResult::Ok(actual.expect("100 cycles ran").term)
    );
}

#[test]
fn child_port_round_trip_and_exit_events_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping child port differential scenarios");
        return;
    };
    let source = r#"
-module(port_diff).
-export([packet/0, line/0, default_stdio/0, status/0, stream_list/0, eof/0, bang_close/0, linked_exit/0, badsig/0, packet_overflow/0, invalid_args/0, nouse_stdio/0, line_chunks/0, large_env/0, block_normal/0]).
packet() ->
    P = open_port({spawn_executable, "/bin/cat"}, [binary, {packet, 2}, exit_status]),
    true = port_command(P, <<"hi">>),
    receive {P, {data, <<"hi">>}} -> port_close(P), ok after 5000 -> timeout end.
line() ->
    P = open_port({spawn, "printf hello"}, [binary, {line, 5}, eof]),
    receive {P, {data, {noeol, <<"hello">>}}} -> receive {P, eof} -> port_close(P), ok after 5000 -> timeout end;
        _ -> timeout after 5000 -> timeout end.
default_stdio() ->
    %% A command that exits races port_close/1: erts can reap the port first
    %% and then port_close is badarg. cat stays up until the close.
    P = open_port({spawn, "cat"}, [{line, 64}]),
    port_command(P, "default_stdio\n"),
    receive {P, {data, {eol, "default_stdio"}}} -> port_close(P), ok
    after 5000 -> timeout end.
status() ->
    P = open_port({spawn_executable, "/bin/sh"}, [exit_status, {args, ["-c", "exit 3"]}]),
    receive {P, {exit_status, 3}} -> ok after 5000 -> timeout end.
stream_list() ->
    P = open_port({spawn, "cat"}, [stream]),
    Payload = lists:duplicate(512, 65),
    P ! {self(), {command, Payload}},
    receive {P, {data, Payload}} -> port_close(P), ok after 5000 -> timeout end.
eof() ->
    P = open_port({spawn_executable, "/usr/bin/true"}, [eof]),
    receive {P, eof} -> port_close(P), ok after 5000 -> timeout end.
bang_close() ->
    %% A command that exits races the close message: the port is gone after
    %% end of input, as in erts. cat stays up until the close.
    P = open_port({spawn_executable, "/bin/cat"}, []),
    P ! {self(), close},
    receive {P, closed} -> ok after 5000 -> timeout end.
linked_exit() ->
    process_flag(trap_exit, true),
    P = open_port({spawn_executable, "/usr/bin/true"}, []),
    receive {'EXIT', P, normal} -> ok after 5000 -> timeout end.
badsig() ->
    process_flag(trap_exit, true),
    P = open_port({spawn_executable, "/usr/bin/true"}, []),
    P ! {a, b},
    receive {'EXIT', P, badsig} -> ok after 5000 -> timeout end.
packet_overflow() ->
    process_flag(trap_exit, true),
    P = open_port({spawn, "cat"}, [{packet, 1}]),
    P ! {self(), {command, lists:duplicate(256, 65)}},
    receive {'EXIT', P, einval} -> ok after 5000 -> timeout end.
invalid_args() ->
    Cases = [[self()], ["head"|"tail"], ["head", "body"|"tail"],
             [<<"head">>, <<"body">>|<<"tail">>], not_a_list,
             ["string", <<"binary">>, 1472, "string"]],
    true = lists:all(fun(Args) ->
        try open_port({spawn_executable, "/bin/echo"}, [{args, Args}]) of
            Port -> port_close(Port), false
        catch error:badarg -> true end
    end, Cases),
    ok.
nouse_stdio() ->
    P = open_port({spawn, "printf hello >&4"}, [in, binary, nouse_stdio]),
    receive {P, {data, <<"hello">>}} ->
        try port_close(P) catch error:badarg -> true end, ok
    after 5000 -> timeout end.
line_chunks() ->
    P = open_port({spawn_executable, "/usr/bin/printf"},
                  [binary, {line, 5}, eof,
                   {args, ["abcde\nABCDEFGHIJ\nxy\rZ\nlast"]}]),
    line_chunks(P, []).
line_chunks(P, Acc) ->
    receive
        {P, {data, {Kind, Data}}} -> line_chunks(P, [{Kind, Data}|Acc]);
        {P, eof} ->
            port_close(P),
            case lists:reverse([eof|Acc]) of
                [{eol, <<"abcde">>}, {noeol, <<"ABCDE">>},
                 {eol, <<"FGHIJ">>}, {eol, <<"xy\rZ">>},
                 {noeol, <<"last">>}, eof] -> ok;
                Other -> {unexpected, Other}
            end
    after 5000 -> timeout end.
large_env() ->
    Env = [{"ARINSAL_PORT_" ++ integer_to_list(N), lists:duplicate(100, $x)}
           || N <- lists:seq(1, 1400)],
    P = open_port({spawn_executable, "/usr/bin/true"}, [exit_status, {env, Env}]),
    receive {P, {exit_status, 0}} -> ok after 5000 -> timeout end.
block_normal() ->
    Parent = self(),
    Child = spawn(fun() -> receive run -> Parent ! child_ran end end),
    blocked_normal = erlang:system_flag(multi_scheduling, block_normal),
    try
        Child ! run,
        receive child_ran -> ok after 5000 -> timeout end
    after
        enabled = erlang:system_flag(multi_scheduling, unblock_normal)
    end.
"#;
    let beam = reference.compile_named("port_diff", source, &[]).unwrap();
    reference.load("port_diff", &beam).unwrap();
    for function in [
        "packet",
        "line",
        "default_stdio",
        "status",
        "stream_list",
        "eof",
        "bang_close",
        "linked_exit",
        "badsig",
        "packet_overflow",
        "invalid_args",
        "nouse_stdio",
        "line_chunks",
        "large_env",
        "block_normal",
    ] {
        let expected = reference.call("port_diff", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let workers = 1;
        let actual = vm.eval_scheduled("port_diff", function, &[], workers, None);
        assert_eq!(expected, CallResult::Ok(actual.unwrap().term), "{function}");
        assert_eq!(
            expected,
            CallResult::Ok(arinsal_etf::OwnedTerm::Atom("ok".into())),
            "reference result for {function}"
        );
    }
}

#[test]
fn port_children_inherit_only_otp_port_descriptors() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inherited port descriptor differential test");
        return;
    };
    let dir = std::env::temp_dir().join(format!("arinsal-port-fd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source_path = dir.join("fd_count.c");
    let helper_path = dir.join("fd_count");
    std::fs::write(
        &source_path,
        r#"#include <fcntl.h>
#include <stdio.h>
int main(void) {
    int count = 0;
    for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    printf("%d", count);
    return 0;
}
"#,
    )
    .unwrap();
    let compiled = std::process::Command::new("clang")
        .arg(&source_path)
        .arg("-o")
        .arg(&helper_path)
        .status();
    if !matches!(compiled, Ok(status) if status.success()) {
        eprintln!("clang unavailable; skipping inherited port descriptor differential test");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    let source = format!(
        r#"
-module(port_fd_diff).
-export([count/0]).
count() ->
    {{ok, File}} = prim_file:open("/dev/null", [read]),
    Port1 = open_port({{spawn, "sleep 5"}}, []),
    Port2 = open_port({{spawn, "sleep 5"}}, []),
    Probe = open_port({{spawn_executable, "{}"}}, [binary]),
    Count = receive
        {{Probe, {{data, Data}}}} -> list_to_integer(binary_to_list(Data))
    after 5000 -> timeout end,
    try port_close(Probe) catch error:badarg -> true end,
    port_close(Port1), port_close(Port2),
    prim_file:close(File), Count.
"#,
        helper_path.display()
    );
    let beam = reference
        .compile_named("port_fd_diff", &source, &[])
        .unwrap();
    reference.load("port_fd_diff", &beam).unwrap();
    let expected = reference.call("port_fd_diff", "count", &[]);
    let _listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let _pipe = std::os::unix::net::UnixStream::pair().unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("port_fd_diff", "count", &[], 1, None)
        .unwrap_or_else(|error| panic!("port fd scenario: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
    assert_eq!(expected, CallResult::Ok(OwnedTerm::Int(3)));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn port_exit_status_survives_block_normal_after_scheduler_unbind() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping blocked-scheduler port regression");
        return;
    };
    let source = r#"
-module(port_scheduler_diff).
-export([run/0]).
run() ->
    lists:foreach(fun(_) -> run_round() end, lists:seq(1, 3)),
    ok.
run_round() ->
    Parent = self(),
    Workers = [spawn_opt(fun() -> worker(Parent) end, [{scheduler, N + 1}])
               || N <- lists:seq(1, 4)],
    collect_started(Workers),
    blocked_normal = erlang:system_flag(multi_scheduling, block_normal),
    try collect_done(Workers)
    after enabled = erlang:system_flag(multi_scheduling, unblock_normal) end,
    ok.
worker(Parent) ->
    Ports = [open_port({spawn, "sleep 1"}, [exit_status]) || _ <- lists:seq(1, 20)],
    _ = process_flag(scheduler, 0),
    Parent ! {self(), started},
    wait_statuses(Ports),
    Parent ! {self(), done}.
wait_statuses([]) -> ok;
wait_statuses(Ports) ->
    receive
        {Port, {exit_status, _}} when is_port(Port) ->
            wait_statuses(lists:delete(Port, Ports))
    end.
collect_started([]) -> ok;
collect_started(Workers) ->
    receive {Pid, started} -> collect_started(lists:delete(Pid, Workers))
    after 10000 -> timeout end.
collect_done([]) -> ok;
collect_done(Workers) ->
    receive {Pid, done} -> collect_done(lists:delete(Pid, Workers))
    after 10000 -> timeout end.
"#;
    let beam = reference
        .compile_named("port_scheduler_diff", source, &[])
        .unwrap();
    reference.load("port_scheduler_diff", &beam).unwrap();
    let expected = reference.call("port_scheduler_diff", "run", &[]);
    assert_eq!(expected, CallResult::Ok(OwnedTerm::Atom("ok".into())));

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("port_scheduler_diff", "run", &[], 5, None)
        .unwrap_or_else(|error| panic!("blocked-scheduler port scenario: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn completed_port_monitors_and_monitor_cleanup_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping port monitor lifecycle differential test");
        return;
    };
    let source = r#"
-module(port_monitor_lifecycle).
-export([run/0]).
run() ->
    Port = open_port({spawn, "sleep 3"}, [exit_status]),
    Parent = self(),
    Observer = spawn(fun() ->
        _ = erlang:monitor(port, Port),
        Parent ! {ready, self()},
        receive stop -> ok end
    end),
    receive {ready, Observer} -> ok after 1000 -> timeout end,
    {monitored_by, [Observer]} = erlang:port_info(Port, monitored_by),
    ProcessRef = erlang:monitor(process, Observer),
    Observer ! stop,
    receive {'DOWN', ProcessRef, process, Observer, normal} -> ok
    after 1000 -> timeout end,
    {monitored_by, []} = erlang:port_info(Port, monitored_by),
    true = erlang:port_close(Port),
    Dead = open_port({spawn, "true"}, [exit_status]),
    receive {Dead, {exit_status, _}} -> ok after 2000 -> timeout end,
    PortRef = erlang:monitor(port, Dead),
    receive {'DOWN', PortRef, port, Dead, noproc} -> ok
    after 1000 -> timeout end,
    ok.
"#;
    let beam = reference
        .compile_named("port_monitor_lifecycle", source, &[])
        .unwrap();
    reference.load("port_monitor_lifecycle", &beam).unwrap();
    let expected = reference.call("port_monitor_lifecycle", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("port_monitor_lifecycle", "run", &[], 2, None)
        .unwrap_or_else(|error| panic!("port monitor lifecycle: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
    assert_eq!(expected, CallResult::Ok(OwnedTerm::Atom("ok".into())));
}

#[test]
fn invalid_port_working_directory_returns_child_exit_status() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping invalid port cwd differential test");
        return;
    };
    let source = r#"
-module(port_invalid_cwd).
-export([run/0]).
run() ->
    Dir = "/private/tmp/arinsal_missing_port_cwd_" ++
          integer_to_list(erlang:unique_integer([positive])),
    Port = open_port({spawn, "true"}, [{cd, Dir}, exit_status]),
    receive {Port, {exit_status, Status}} -> is_integer(Status)
    after 2000 -> timeout end.
"#;
    let beam = reference
        .compile_named("port_invalid_cwd", source, &[])
        .unwrap();
    reference.load("port_invalid_cwd", &beam).unwrap();
    let expected = reference.call("port_invalid_cwd", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("port_invalid_cwd", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("invalid port cwd: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
    assert_eq!(expected, CallResult::Ok(OwnedTerm::Atom("true".into())));
}

#[test]
fn bare_line_port_option_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping bare line port option differential test");
        return;
    };
    let source = r#"
-module(port_line_default).
-export([run/0]).
run() ->
    Port = open_port({spawn, "printf 'one\\ntwo\\n'"}, [line, eof]),
    collect(Port, []).
collect(Port, Acc) ->
    receive
        {Port, {data, Line}} -> collect(Port, [Line | Acc]);
        {Port, eof} -> lists:reverse(Acc)
    after 2000 -> timeout end.
"#;
    let beam = reference
        .compile_named("port_line_default", source, &[])
        .unwrap();
    reference.load("port_line_default", &beam).unwrap();
    let expected = reference.call("port_line_default", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("port_line_default", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("bare line port option: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
    assert_eq!(
        expected,
        CallResult::Ok(OwnedTerm::List {
            elems: vec![
                OwnedTerm::Tuple(vec![OwnedTerm::atom("eol"), OwnedTerm::charlist("one")]),
                OwnedTerm::Tuple(vec![OwnedTerm::atom("eol"), OwnedTerm::charlist("two")]),
            ],
            tail: Box::new(OwnedTerm::Nil),
        })
    );
}

#[test]
fn linked_process_exit_closes_port_and_preserves_down_reason() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping linked port exit differential test");
        return;
    };
    let source = r#"
-module(port_link_exit).
-export([run/0]).
run() ->
    Port = open_port({spawn, "sleep 3"}, []),
    Ref = erlang:monitor(port, Port),
    true = erlang:unlink(Port),
    _ = spawn(fun() -> link(Port), exit({bye, bye}) end),
    receive {'DOWN', Ref, port, Port, {bye, bye}} -> ok
    after 2000 -> timeout end.
"#;
    let beam = reference
        .compile_named("port_link_exit", source, &[])
        .unwrap();
    reference.load("port_link_exit", &beam).unwrap();
    let expected = reference.call("port_link_exit", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("port_link_exit", "run", &[], 2, None)
        .unwrap_or_else(|error| panic!("linked port exit: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
    assert_eq!(expected, CallResult::Ok(OwnedTerm::Atom("ok".into())));
}

#[test]
fn spawn_executable_reports_os_errors_like_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping spawn_executable error differential test");
        return;
    };
    let dir = std::env::temp_dir().join(format!("arinsal-port-exec-errors-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let noexec = dir.join("not_executable");
    std::fs::write(&noexec, b"not executable").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&noexec, std::fs::Permissions::from_mode(0o600)).unwrap();
    let source = format!(
        r#"
-module(port_exec_errors).
-export([run/0]).
run() ->
    Missing = "/private/tmp/arinsal_missing_executable_" ++
              integer_to_list(erlang:unique_integer([positive])),
    MissingReason = try open_port({{spawn_executable, Missing}}, [])
                    catch error:MissingError -> MissingError end,
    Path = "{}",
    PermissionReason = try open_port({{spawn_executable, Path}}, [])
                       catch error:PermissionError -> PermissionError end,
    {{MissingReason, PermissionReason}}.
"#,
        noexec.display()
    );
    let beam = reference
        .compile_named("port_exec_errors", &source, &[])
        .unwrap();
    reference.load("port_exec_errors", &beam).unwrap();
    let expected = reference.call("port_exec_errors", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("port_exec_errors", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("spawn executable errors: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
    assert_eq!(
        expected,
        CallResult::Ok(OwnedTerm::Tuple(vec![
            OwnedTerm::atom("enoent"),
            OwnedTerm::atom("eacces"),
        ]))
    );
    std::fs::remove_dir_all(dir).unwrap();
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

/// Regression for the `process_differential` hang: caught BIF errors were ~50x slower than
/// erts because every raw stacktrace kept a slot forever and each capture resolved native
/// frames eagerly. 400k caught `badarg`s in a tight loop must finish quickly, with the
/// same result as erts.
#[test]
fn tight_loop_of_caught_bif_errors_is_fast_and_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping caught error loop test");
        return;
    };
    let source = r#"
-module(caught_loop).
-compile(nowarn_deprecated_catch).
-export([run/1]).
run(N) -> {loop(N, 0), try_loop(N, 0)}.
loop(0, Acc) -> Acc;
loop(N, Acc) ->
    {'EXIT', {badarg, _}} = catch ets:lookup(caught_loop_missing, key),
    loop(N - 1, Acc + 1).
try_loop(0, Acc) -> Acc;
try_loop(N, Acc) ->
    try ets:lookup(caught_loop_missing, key) catch error:badarg -> ok end,
    try_loop(N - 1, Acc + 1).
"#;
    let beam = reference.compile_named("caught_loop", source, &[]).unwrap();
    reference.load("caught_loop", &beam).unwrap();
    let count = 200_000;
    let expected = reference.call("caught_loop", "run", &[OwnedTerm::Int(count)]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let started = std::time::Instant::now();
    let actual = vm
        .eval_scheduled(
            "caught_loop",
            "run",
            &[Term::small(count).unwrap()],
            1,
            None,
        )
        .unwrap_or_else(|error| panic!("caught_loop: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "caught error loop took {:?}",
        started.elapsed()
    );
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

/// A multi-scheduling block belongs to the runtime that set it. A runtime started
/// while another runtime in the same OS process is blocked used to inherit the block
/// with no blocking scheduler, so every worker parked and the entry never ran.
#[test]
fn multi_scheduling_block_does_not_leak_into_new_runtimes() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping multi-scheduling isolation test");
        return;
    };
    let source = r#"
-module(msb_isolation).
-export([block/0, fresh/0]).
block() -> erlang:system_flag(multi_scheduling, block_normal).
fresh() ->
    Parent = self(),
    Pids = [spawn(fun() -> Parent ! {self(), erlang:system_info(multi_scheduling)} end)
            || _ <- lists:seq(1, 8)],
    States = [receive {Pid, State} -> State after 5000 -> timeout end || Pid <- Pids],
    {erlang:system_info(multi_scheduling), lists:usort(States)}.
"#;
    let beam = reference
        .compile_named("msb_isolation", source, &[])
        .unwrap();
    reference.load("msb_isolation", &beam).unwrap();
    let expected = reference.call("msb_isolation", "fresh", &[]);

    let mut blocker = Vm::new([]);
    blocker.load_bytes(&beam).unwrap();
    let blocked = blocker
        .eval_scheduled("msb_isolation", "block", &[], 2, None)
        .unwrap();
    assert_eq!(blocked.term, OwnedTerm::Atom("blocked_normal".into()));

    let (sender, receiver) = std::sync::mpsc::channel();
    let fresh_beam = beam.clone();
    std::thread::spawn(move || {
        let mut vm = Vm::new([]);
        vm.load_bytes(&fresh_beam).unwrap();
        let result = vm
            .eval_scheduled("msb_isolation", "fresh", &[], 2, None)
            .map(|result| result.term);
        let _ = sender.send(result);
    });
    let actual = receiver
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("runtime started after another runtime blocked multi-scheduling hung");
    assert_eq!(expected, CallResult::Ok(actual.unwrap()));
    drop(blocker);
}

/// `monitor(process, self())` creates only a ref (`bif.c` local_process). A live
/// other process updates both monitor trees. A port monitor's target half is
/// removed by the demonitor signal, and `port_close` still delivers `DOWN`.
#[test]
fn monitor_demonitor_trees_and_port_down_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping monitor/demonitor differential test");
        return;
    };
    let source = r#"
-module(mon_trees).
-export([run/0]).
run() ->
    Me = self(),
    SelfRef = erlang:monitor(process, Me),
    {monitors, []} = process_info(Me, monitors),
    false = erlang:demonitor(SelfRef, [info, flush]),
    Parent = Me,
    Other = spawn(fun() ->
        receive go -> ok end,
        {monitored_by, Mb} = process_info(self(), monitored_by),
        Parent ! {mb, Mb},
        receive stop -> ok end
    end),
    Ref = erlang:monitor(process, Other),
    {monitors, [{process, Other}]} = process_info(Me, monitors),
    Other ! go,
    Mb = receive {mb, Seen} -> Seen after 2000 -> timeout end,
    [Me] = Mb,
    true = erlang:demonitor(Ref, [info]),
    {monitors, []} = process_info(Me, monitors),
    Other ! stop,
    Port = open_port({spawn, "sleep 30"}, []),
    Pref = erlang:monitor(port, Port),
    {monitored_by, [Me]} = erlang:port_info(Port, monitored_by),
    {monitors, [{port, Port}]} = process_info(Me, monitors),
    true = erlang:demonitor(Pref, [flush]),
    {monitors, []} = process_info(Me, monitors),
    {monitored_by, []} = erlang:port_info(Port, monitored_by),
    Pref2 = erlang:monitor(port, Port),
    true = port_close(Port),
    receive {'DOWN', Pref2, port, Port, normal} -> ok after 2000 -> timeout end,
    ok.
"#;
    let beam = reference.compile_named("mon_trees", source, &[]).unwrap();
    reference.load("mon_trees", &beam).unwrap();
    let expected = reference.call("mon_trees", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("mon_trees", "run", &[], 2, None)
        .unwrap_or_else(|error| panic!("monitor trees: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
    assert_eq!(expected, CallResult::Ok(OwnedTerm::Atom("ok".into())));
}

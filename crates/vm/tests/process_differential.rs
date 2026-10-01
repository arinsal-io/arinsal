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
    receive {'DOWN',R,process,Pid,normal} -> N end;
scenario(24,N) ->
    Pid=spawn(fun()->receive after infinity -> ok end end),
    Pid!hej,
    timer:sleep(300),
    {N,process_info(Pid,[reductions,status])}.
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
    for category in 0..25 {
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
    P = open_port({spawn, "printf 'default_stdio\\n'"}, [{line, 64}]),
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
    P = open_port({spawn_executable, "/usr/bin/true"}, []),
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
    receive {P, {data, <<"hello">>}} -> port_close(P), ok after 5000 -> timeout end.
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
    port_close(Probe), port_close(Port1), port_close(Port2),
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

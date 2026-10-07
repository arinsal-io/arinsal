//! Scheduler-path differentials for hibernate, suspend, spawn_request, and max_heap_size.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_sched).
-export([
    hibernate/0, suspend_order/0, suspend_opts/0, suspend_self/0, resume_plain/0,
    suspend_badopt/0, hibernate_heap_size/0, spawn_ok/0, spawn_missing/0, spawn_badopt/0, spawn_error_only/0,
    spawn_success_only_bad/0, spawn_reply_no/0, spawn_tag/0, spawn_link_order/0,
    spawn_monitor_ref/0, spawn_remote/0, spawn_bad_list/0, spawn_bad_fun/0,
    abandon_ref/0, abandon_bad/0, heap_flag/0, heap_kill_yes/0, heap_kill_no/0,
    heap_bin_no/0, heap_bin_yes/0, die/0,
    spawn_opt_max_heap/0, spawn_opt_hfrag_kill/0, gc_trace_tags/0
]).

die() -> exit(boom).

norm(T) when is_pid(T) -> pid;
norm(T) when is_reference(T) -> ref;
norm(T) when is_port(T) -> port;
norm(T) when is_function(T) -> 'fun';
norm(T) when is_tuple(T) -> list_to_tuple([norm(E) || E <- tuple_to_list(T)]);
norm([H|T]) -> [norm(H) | norm(T)];
norm(T) when is_map(T) -> maps:from_list([{norm(K), norm(V)} || {K, V} <- maps:to_list(T)]);
norm(T) -> T.

caught(Fun) ->
    try {ok, norm(Fun())}
    catch Class:Reason -> {Class, norm(Reason)}
    end.

hibernate() ->
    Parent = self(),
    Pid = spawn(fun() ->
        erlang:hibernate(erlang, apply, [fun() ->
            receive M -> Parent ! {woke, M} end
        end, []])
    end),
    wait_waiting(Pid, 40),
    {status, Status} = process_info(Pid, status),
    {current_function, Cf} = process_info(Pid, current_function),
    Pid ! ping,
    Woke = receive {woke, ping} -> ping after 2000 -> timeout end,
    {Status, Cf, Woke}.

hibernate_heap_size() ->
    Parent = self(),
    Pid = spawn(fun() -> Parent ! ready, erlang:hibernate(erlang, apply, [fun() -> receive _ -> ok end end, []]) end),
    receive ready -> ok end,
    receive after 25 -> ok end,
    [{heap_size, Heap}, {total_heap_size, Total}] = process_info(Pid, [heap_size, total_heap_size]),
    exit(Pid, kill),
    Heap =:= Total.

wait_waiting(_Pid, 0) -> ok;
wait_waiting(Pid, N) ->
    case process_info(Pid, status) of
        {status, waiting} -> ok;
        _ -> receive after 1 -> wait_waiting(Pid, N - 1) end
    end.

suspend_order() ->
    Parent = self(),
    Pid = spawn(fun() ->
        receive M1 -> receive M2 -> Parent ! {got, M1, M2} end end
    end),
    receive after 1 -> ok end,
    true = erlang:suspend_process(Pid),
    true = erlang:suspend_process(Pid),
    Pid ! first,
    Pid ! second,
    Early = receive {got, _, _} -> early after 20 -> held end,
    true = erlang:resume_process(Pid),
    Still = receive {got, _, _} -> early after 20 -> held end,
    true = erlang:resume_process(Pid),
    Got = receive {got, A, B} -> {A, B} after 2000 -> timeout end,
    {Early, Still, Got}.

suspend_opts() ->
    Pid = spawn(fun() -> receive after infinity -> ok end end),
    receive after 1 -> ok end,
    First = erlang:suspend_process(Pid, [unless_suspending]),
    Second = erlang:suspend_process(Pid, [unless_suspending]),
    Tag = make_ref(),
    Async = erlang:suspend_process(Pid, [{asynchronous, Tag}]),
    Reply = receive {Tag, R} -> R after 200 -> timeout end,
    {suspending, List} = process_info(self(), suspending),
    Shape = lists:all(fun({P, N, 0}) ->
        is_pid(P) andalso is_integer(N) andalso N > 0
    end, List) andalso length(List) =:= 1,
    {status, Status} = process_info(Pid, status),
    erlang:resume_process(Pid),
    erlang:resume_process(Pid),
    {First, Second, Async, Reply, Shape, Status}.

suspend_self() -> caught(fun() -> erlang:suspend_process(self()) end).

resume_plain() ->
    Pid = spawn(fun() -> receive after infinity -> ok end end),
    caught(fun() -> erlang:resume_process(Pid) end).

suspend_badopt() ->
    Pid = spawn(fun() -> receive after infinity -> ok end end),
    caught(fun() -> erlang:suspend_process(Pid, [nope]) end).

spawn_ok() ->
    Ref = erlang:spawn_request(erlang, self, []),
    receive {spawn_reply, Ref, ok, Pid} when is_pid(Pid) -> ok after 2000 -> timeout end.

spawn_missing() ->
    Ref = erlang:spawn_request(no_such_mod_sched, no_such_fun, []),
    receive
        {spawn_reply, Ref, ok, Pid} ->
            Mon = monitor(process, Pid),
            receive
                {'DOWN', Mon, process, Pid, {undef, _}} -> undef;
                {'DOWN', Mon, process, Pid, undef} -> undef;
                {'DOWN', Mon, process, Pid, Reason} -> {other, norm(Reason)}
            after 2000 -> timeout
            end;
        {spawn_reply, Ref, error, Reason} -> {error, Reason}
    after 2000 -> timeout
    end.

spawn_badopt() ->
    Ref = erlang:spawn_request(erlang, self, [], [nope]),
    receive {spawn_reply, Ref, error, Reason} -> {error, Reason} after 2000 -> timeout end.

spawn_error_only() ->
    Ref = erlang:spawn_request(erlang, self, [], [{reply, error_only}]),
    receive {spawn_reply, Ref, _, _} -> msg after 0 -> nomsg end.

spawn_success_only_bad() ->
    Ref = erlang:spawn_request(erlang, self, [], [nope, {reply, success_only}]),
    receive {_, Ref, _, _} -> msg after 0 -> nomsg end.

spawn_reply_no() ->
    Ref = erlang:spawn_request(erlang, self, [], [{reply, no}]),
    Got = receive {_, Ref, _, _} -> msg after 0 -> nomsg end,
    {Got, is_reference(Ref)}.

spawn_tag() ->
    Ref = erlang:spawn_request(erlang, self, [], [{reply_tag, my_tag}]),
    receive {my_tag, Ref, ok, _} -> my_tag after 2000 -> timeout end.

spawn_link_order() ->
    process_flag(trap_exit, true),
    Ref = erlang:spawn_request(proc_sched, die, [], [link]),
    First = receive
        {spawn_reply, Ref, ok, _} -> reply;
        {'EXIT', _, boom} -> exit_sig
    after 2000 -> timeout
    end,
    Second = receive
        {spawn_reply, Ref, ok, _} -> reply;
        {'EXIT', _, boom} -> exit_sig;
        {'EXIT', _, Reason} -> {exit_sig, norm(Reason)}
    after 2000 -> timeout
    end,
    {First, Second}.

spawn_monitor_ref() ->
    Ref = erlang:spawn_request(proc_sched, die, [], [monitor]),
    receive
        {spawn_reply, Ref, ok, Pid} ->
            receive
                {'DOWN', Ref, process, Pid, boom} -> boom;
                {'DOWN', Ref, process, Pid, Reason} -> {other, norm(Reason)}
            after 2000 -> timeout
            end
    after 2000 -> timeout
    end.

spawn_remote() ->
    Ref = erlang:spawn_request('no@node', erlang, self, []),
    receive {spawn_reply, Ref, error, Reason} -> Reason after 2000 -> timeout end.

spawn_bad_list() -> caught(fun() -> erlang:spawn_request(erlang, self, 1, []) end).

spawn_bad_fun() -> caught(fun() -> erlang:spawn_request(1) end).

abandon_ref() -> erlang:spawn_request_abandon(make_ref()).

abandon_bad() -> caught(fun() -> erlang:spawn_request_abandon(1) end).

heap_flag() ->
    Prev = process_flag(max_heap_size, 0),
    process_flag(max_heap_size, 20000),
    {max_heap_size, Now} = process_info(self(), max_heap_size),
    Small = caught(fun() -> process_flag(max_heap_size, 100) end),
    {Prev, Now, Small}.

heap_kill(Kill) ->
    Pid = spawn(fun() ->
        process_flag(max_heap_size, #{
            size => 1500, kill => Kill, error_logger => false,
            include_shared_binaries => false
        }),
        lists:seq(1, 40000),
        ok
    end),
    Ref = monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, killed} -> killed;
        {'DOWN', Ref, process, Pid, normal} -> lived;
        {'DOWN', Ref, process, Pid, Reason} -> {other, norm(Reason)}
    after 5000 -> timeout
    end.

heap_kill_yes() -> heap_kill(true).
heap_kill_no() -> heap_kill(false).

heap_bin(Include) ->
    Pid = spawn(fun() ->
        process_flag(max_heap_size, #{
            size => 8000, kill => true, error_logger => false,
            include_shared_binaries => Include
        }),
        Bin = <<0:(200000*8)>>,
        put(bin, Bin),
        garbage_collect(),
        receive after infinity -> get(bin) end
    end),
    Ref = monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, killed} -> killed;
        {'DOWN', Ref, process, Pid, Reason} -> {other, norm(Reason)}
    after 80 -> alive
    end.

spawn_opt_max_heap() ->
    {Pid, Ref} = spawn_opt(fun() -> receive after 5000 -> ok end end,
                           [monitor, {max_heap_size, 1000}, {fullsweep_after, 7}]),
    {garbage_collection, Gc} = process_info(Pid, garbage_collection),
    #{size := Size} = proplists:get_value(max_heap_size, Gc),
    FullSweep = proplists:get_value(fullsweep_after, Gc),
    exit(Pid, kill),
    receive {'DOWN', Ref, process, Pid, killed} -> {Size, FullSweep} after 2000 -> timeout end.

%% A BIF that allocates a heap fragment larger than the young heap must
%% collect after the call so the limit is enforced.
spawn_opt_hfrag_kill() ->
    {Pid, Ref} = spawn_opt(fun F() -> erlang:make_tuple(2000, []), F() end,
                           [monitor, {max_heap_size, 1000}]),
    receive {'DOWN', Ref, process, Pid, Reason} -> Reason after 5000 -> timeout end.

gc_trace_tags() ->
    Pid = spawn(fun() -> receive after 5000 -> ok end end),
    erlang:trace(Pid, true, [garbage_collection]),
    erlang:garbage_collect(Pid, [{type, major}]),
    Major = trace_tag(Pid, 2),
    erlang:garbage_collect(Pid, [{type, minor}]),
    Minor = trace_tag(Pid, 2),
    exit(Pid, kill),
    {Major, Minor}.

trace_tag(_Pid, 0) -> [];
trace_tag(Pid, N) ->
    receive {trace, Pid, Tag, _} -> [Tag | trace_tag(Pid, N - 1)] after 2000 -> timeout end.

heap_bin_no() -> heap_bin(false).
heap_bin_yes() -> heap_bin(true).
"#;

#[test]
fn proc_sched_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping proc_sched differential");
        return;
    };
    let beam = reference
        .compile_named("proc_sched", SOURCE, &[])
        .expect("compile proc_sched");
    reference
        .load("proc_sched", &beam)
        .expect("load proc_sched");
    let functions = [
        "hibernate",
        "hibernate_heap_size",
        "suspend_order",
        "suspend_opts",
        "suspend_self",
        "resume_plain",
        "suspend_badopt",
        "spawn_ok",
        "spawn_missing",
        "spawn_badopt",
        "spawn_error_only",
        "spawn_success_only_bad",
        "spawn_reply_no",
        "spawn_tag",
        "spawn_link_order",
        "spawn_monitor_ref",
        "spawn_remote",
        "spawn_bad_list",
        "spawn_bad_fun",
        "abandon_ref",
        "abandon_bad",
        "heap_flag",
        "spawn_opt_max_heap",
        "spawn_opt_hfrag_kill",
        "gc_trace_tags",
        "heap_kill_yes",
        "heap_kill_no",
        "heap_bin_no",
        "heap_bin_yes",
    ];
    for function in functions {
        let expected = reference.call("proc_sched", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).expect("load");
        let actual = vm
            .eval_scheduled("proc_sched", function, &[], 1, Some(17))
            .unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}

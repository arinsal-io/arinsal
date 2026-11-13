//! `spawn/3`, `spawn_link/3`, `spawn_opt/4`, `erts_internal:spawn_request/4`,
//! `spawn_request_abandon/1`, `alias/1` and `unalias/1` (bif.c, erl_process.c
//! `erts_parse_spawn_opts` / `erl_create_process`) against erl: every spawn option and what the
//! child reports for it, bad options and bad MFAs in erts's failure order, the spawn_request
//! replies, and every alias option.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::VmError;

const SOURCE: &str = r#"
-module(spawn_alias_bif).
-export([run/0, idle/0, report/1]).

%% Runs in a fresh process: the caller's trap_exit and leftover messages stay out of it.
run() ->
    {P, R} = spawn_monitor(fun() -> exit({result, run1()}) end),
    receive {'DOWN', R, process, P, Reason} -> Reason after 20000 -> timeout end.

norm(T) when is_pid(T) -> pid;
norm(T) when is_port(T) -> port;
norm(T) when is_reference(T) -> ref;
norm(T) when is_list(T) -> [norm(E) || E <- T];
norm(T) when is_tuple(T) -> list_to_tuple(norm(tuple_to_list(T)));
norm(T) when is_map(T) -> maps:from_list(norm(maps:to_list(T)));
norm(T) -> T.

catching(F) ->
    try F() of
        V -> {ok, norm(V)}
    catch C:R:St ->
        [{M, Fn, A, Info} | _] = St,
        {C, R, M, Fn, arity(A), proplists:get_value(error_info, Info)}
    end.

arity(A) when is_list(A) -> length(A);
arity(A) -> A.

msgs() -> receive X -> [norm(X) | msgs()] after 50 -> [] end.

idle() -> receive stop -> ok end.

%% The child sends what process_info says about it, then waits.
report(Parent) ->
    Items = [priority, message_queue_data, async_dist, initial_call, links, parent],
    Info = [{I, norm(element(2, process_info(self(), I)))} || I <- Items],
    {garbage_collection, GC} = process_info(self(), garbage_collection),
    Gc = [{K, proplists:get_value(K, GC)}
          || K <- [min_heap_size, min_bin_vheap_size, fullsweep_after]],
    {max_heap_size, MHS} = process_info(self(), max_heap_size),
    Parent ! {report, Info, Gc, MHS},
    idle().

opt(Opts) ->
    M = erlang,
    case catching(fun() -> M:spawn_opt(spawn_alias_bif, report, [self()], Opts) end) of
        {ok, _} = Ok ->
            Res = receive {report, I, G, H} -> {I, G, H} after 2000 -> timeout end,
            {Ok, Res};
        Error ->
            Error
    end.

kill_children() ->
    {links, L} = process_info(self(), links),
    [(fun() -> unlink(P), exit(P, kill) end)() || P <- L, is_pid(P)],
    ok.

run1() ->
    M = erlang,
    Spawns = [
        {spawn_ok, catching(fun() -> P = M:spawn(spawn_alias_bif, idle, []), P ! stop, P end)},
        {spawn_bad_mod, catching(fun() -> M:spawn("m", idle, []) end)},
        {spawn_bad_fun, catching(fun() -> M:spawn(spawn_alias_bif, 1, []) end)},
        {spawn_bad_args, catching(fun() -> M:spawn(spawn_alias_bif, idle, [a | b]) end)},
        {spawn_link_ok, catching(fun() ->
            P = M:spawn_link(spawn_alias_bif, idle, []),
            {links, L} = process_info(self(), links),
            unlink(P), P ! stop, lists:member(P, L) end)},
        {spawn_link_bad, catching(fun() -> M:spawn_link(spawn_alias_bif, idle, x) end)},
        {spawn_undef, (fun() ->
            {P, R} = spawn_monitor(nonexistent_mod_xyz, f, []),
            receive {'DOWN', R, process, P, {Why, _}} -> Why after 2000 -> timeout end
        end)()}
    ],
    Opts = [
        {opt_none, opt([])},
        {opt_link, opt([link])},
        {opt_link_prio, opt([{link, [priority]}])},
        {opt_link_badopt, opt([{link, [bad]}])},
        {opt_monitor, opt([monitor])},
        {opt_monitor_tag, opt([{monitor, [{tag, my_tag}]}])},
        {opt_monitor_alias_explicit, opt([{monitor, [{alias, explicit_unalias}]}])},
        {opt_monitor_alias_demonitor, opt([{monitor, [{alias, demonitor}]}])},
        {opt_monitor_alias_reply, opt([{monitor, [{alias, reply_demonitor}]}])},
        {opt_monitor_prio, opt([{monitor, [priority]}])},
        {opt_monitor_bad, opt([{monitor, [{alias, bad}]}])},
        {opt_prio_low, opt([{priority, low}])},
        {opt_prio_high, opt([{priority, high}])},
        {opt_prio_max, opt([{priority, max}])},
        {opt_prio_bad, opt([{priority, bad}])},
        {opt_fullsweep, opt([{fullsweep_after, 7}])},
        {opt_fullsweep_neg, opt([{fullsweep_after, -1}])},
        {opt_min_heap, opt([{min_heap_size, 1000}])},
        {opt_min_heap_small, opt([{min_heap_size, 10}])},
        {opt_min_heap_neg, opt([{min_heap_size, -1}])},
        {opt_min_heap_bad, opt([{min_heap_size, big}])},
        {opt_min_vheap_alone, opt([{min_bin_vheap_size, 100000}])},
        {opt_min_vheap_with_gc, opt([{min_bin_vheap_size, 100000}, {fullsweep_after, 3}])},
        {opt_max_heap, opt([{max_heap_size, 100000}])},
        {opt_max_heap_map, opt([{max_heap_size, #{size => 100000, kill => false}}])},
        {opt_max_heap_below_min, opt([{max_heap_size, 300}, {min_heap_size, 1000}])},
        {opt_mqd_off, opt([{message_queue_data, off_heap}])},
        {opt_mqd_on, opt([{message_queue_data, on_heap}])},
        {opt_mqd_bad, opt([{message_queue_data, bad}])},
        {opt_async_dist, opt([{async_dist, true}])},
        {opt_async_dist_false, opt([{async_dist, false}])},
        {opt_async_dist_bad, opt([{async_dist, 1}])},
        {opt_scheduler, opt([{scheduler, 1}])},
        {opt_scheduler_bad, opt([{scheduler, 100000}])},
        {opt_reply, opt([{reply, yes}])},
        {opt_reply_tag, opt([{reply_tag, t}])},
        {opt_bad_atom, opt([bad])},
        {opt_bad_tuple3, opt([{a, b, c}])},
        {opt_improper, opt([link | x])},
        {opt_not_list, opt(foo)},
        {opt_bad_opt_bad_mfa, catching(fun() -> M:spawn_opt("m", f, [], [bad]) end)},
        {opt_bad_opt_bad_args, catching(fun() -> M:spawn_opt(m, f, x, [bad]) end)},
        {opt_good_opt_bad_mfa, catching(fun() -> M:spawn_opt("m", f, [], [link]) end)},
        {opt_good_opt_bad_args, catching(fun() -> M:spawn_opt(m, f, [a | b], []) end)}
    ],
    kill_children(),
    _ = msgs(),
    Requests = [
        {req_default, (fun() ->
            R = spawn_request(spawn_alias_bif, report, [self()]),
            receive {spawn_reply, R, ok, P} ->
                receive {report, I, _, _} -> exit(P, kill), {ok, norm(P), I} end
            after 2000 -> timeout end
        end)()},
        {req_tag, (fun() ->
            R = spawn_request(spawn_alias_bif, idle, [], [{reply_tag, my_tag}]),
            receive {my_tag, R, ok, P} -> exit(P, kill), ok after 2000 -> timeout end
        end)()},
        {req_no_reply, (fun() ->
            R = spawn_request(spawn_alias_bif, report, [self()], [{reply, no}]),
            receive {report, _, _, _} -> ok after 2000 -> timeout end,
            {is_reference(R), msgs()}
        end)()},
        {req_error_only, (fun() ->
            _ = spawn_request(spawn_alias_bif, report, [self()], [{reply, error_only}]),
            receive {report, _, _, _} -> ok after 2000 -> timeout end,
            msgs()
        end)()},
        {req_success_only_bad, (fun() ->
            R = spawn_request(spawn_alias_bif, idle, [], [{reply, success_only}, bad]),
            {is_reference(R), msgs()}
        end)()},
        {req_badopt, (fun() ->
            R = spawn_request(spawn_alias_bif, idle, [], [bad]),
            receive {spawn_reply, R, error, E} -> E after 2000 -> timeout end
        end)()},
        {req_badopt_tag, (fun() ->
            R = spawn_request(spawn_alias_bif, idle, [], [bad, {reply_tag, t}]),
            receive {t, R, error, E} -> E after 2000 -> timeout end
        end)()},
        {req_bad_reply, (fun() ->
            R = spawn_request(spawn_alias_bif, idle, [], [{reply, perhaps}]),
            receive {spawn_reply, R, error, E} -> E after 2000 -> timeout end
        end)()},
        {req_improper, catching(fun() -> spawn_request(spawn_alias_bif, idle, [], [link | x]) end)},
        {req_bad_mfa, catching(fun() -> spawn_request("m", idle, []) end)},
        {req_internal_badarg, erts_internal:spawn_request("m", f, [], [])},
        {req_internal_badopt, erts_internal:spawn_request(m, f, [], foo)},
        {req_monitor, (fun() ->
            R = spawn_request(spawn_alias_bif, idle, [], [monitor]),
            receive {spawn_reply, R, ok, P} ->
                exit(P, kill),
                receive {'DOWN', R, process, P, Why} -> Why after 2000 -> no_down end
            after 2000 -> timeout end
        end)()},
        {req_link, (fun() ->
            process_flag(trap_exit, true),
            R = spawn_request(spawn_alias_bif, idle, [], [link]),
            Res = receive {spawn_reply, R, ok, P} ->
                exit(P, kill),
                receive {'EXIT', P, Why} -> Why after 2000 -> no_exit end
            after 2000 -> timeout end,
            process_flag(trap_exit, false),
            Res
        end)()},
        {req_initial_call, (fun() ->
            R = spawn_request(spawn_alias_bif, idle, []),
            receive {spawn_reply, R, ok, P} ->
                IC = process_info(P, initial_call),
                exit(P, kill),
                IC
            after 2000 -> timeout end
        end)()},
        {req_crash_stack, (fun() ->
            R = spawn_request(lists, nth, [5, []], [monitor]),
            receive {'DOWN', R, process, _, {Why, [Top | _]}} -> {Why, element(1, Top)}
            after 2000 -> timeout end
        end)()},
        {abandon_done, (fun() ->
            R = spawn_request(spawn_alias_bif, idle, []),
            A = spawn_request_abandon(R),
            receive {spawn_reply, R, ok, P} -> exit(P, kill), A after 2000 -> {A, timeout} end
        end)()},
        {abandon_unknown, spawn_request_abandon(make_ref())},
        {abandon_bad, catching(fun() -> M:spawn_request_abandon(foo) end)}
    ],
    Other = spawn(fun() -> A = alias(), receive {get, P} -> P ! {alias, A} end, idle() end),
    Other ! {get, self()},
    OtherAlias = receive {alias, OA} -> OA after 2000 -> timeout end,
    Other ! stop,
    Aliases = [
        {alias_default, (fun() -> A = alias(), self() ! {A, x},
            A ! one, A ! two, U = unalias(A), A ! three, {U, msgs()} end)()},
        {alias_explicit, (fun() -> A = alias([explicit_unalias]),
            A ! one, A ! two, {unalias(A), unalias(A), msgs()} end)()},
        {alias_reply, (fun() -> A = alias([reply]), A ! one, A ! two, {unalias(A), msgs()} end)()},
        {alias_reply_explicit, (fun() -> A = alias([reply, explicit_unalias]),
            A ! one, A ! two, {unalias(A), msgs()} end)()},
        {alias_priority, (fun() -> A = alias([priority]), A ! one, {unalias(A), msgs()} end)()},
        {alias_bad, catching(fun() -> M:alias([bad]) end)},
        {alias_not_list, catching(fun() -> M:alias(foo) end)},
        {alias_improper, catching(fun() -> M:alias([reply | x]) end)},
        {unalias_bad, catching(fun() -> M:unalias(foo) end)},
        {unalias_plain_ref, unalias(make_ref())},
        {unalias_other, unalias(OtherAlias)},
        {unalias_monitor, (fun() -> P = spawn(fun idle/0),
            Ref = monitor(process, P), U = unalias(Ref), P ! stop,
            receive {'DOWN', Ref, _, _, W} -> {U, W} after 2000 -> timeout end end)()}
    ],
    kill_children(),
    {Spawns, Opts, Requests, Aliases, msgs()}.
"#;

#[test]
fn spawn_and_alias_bifs_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named("spawn_alias_bif", SOURCE, &[])
        .expect("compile differential");
    reference
        .load("spawn_alias_bif", &beam)
        .expect("load reference module");
    let expected = reference.call("spawn_alias_bif", "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load VM module");
    let actual = match vm.eval_scheduled("spawn_alias_bif", "run", &[], 2) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|diff| panic!("spawn/alias BIFs differ: {diff}"));
}

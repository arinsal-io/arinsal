//! `process_flag/2`, `self/0`, `node/0`, `group_leader/0,2` (bif.c `process_flag_2`,
//! `group_leader_0`, `erts_internal_group_leader_2`) and the BIF timers (erl_hl_timer.c) against
//! erl: every flag with good and bad values and the `error_info` cause, synchronous and
//! asynchronous timer access with `info`, expired timers and bad arguments, called statically
//! and through `apply`.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::VmError;

const SOURCE: &str = r#"
-module(pflag_timer).
-export([flags/0, timers/0]).

catching(F) ->
    try F() of
        V -> {ok, norm(V)}
    catch C:R:St ->
        [{M, Fn, A, Info} | _] = St,
        {C, R, M, Fn, length(A), proplists:get_value(error_info, Info)}
    end.

norm(P) when is_pid(P) -> pid;
norm(R) when is_reference(R) -> ref;
norm(I) when is_integer(I), I > 1000000 -> big;
norm(T) when is_tuple(T) -> list_to_tuple([norm(E) || E <- tuple_to_list(T)]);
norm(M) when is_map(M) -> maps:map(fun(_, V) -> norm(V) end, M);
norm(O) -> O.

flag(F, V) -> catching(fun() -> process_flag(F, V) end).
aflag(F, V) -> M = erlang, catching(fun() -> M:process_flag(F, V) end).

flags() ->
    Self = self(),
    M = erlang,
    Live = spawn(fun() -> receive stop -> ok end end),
    Dead = spawn(fun() -> ok end),
    Ref = monitor(process, Dead),
    receive {'DOWN', Ref, _, _, _} -> ok end,
    GL = group_leader(),
    Cases = [
        {self, Self =:= M:self(), node() =:= M:node(), is_pid(GL), GL =:= M:group_leader()},
        {trap_exit, flag(trap_exit, true), flag(trap_exit, false), flag(trap_exit, 3),
         aflag(trap_exit, true), aflag(trap_exit, false)},
        {error_handler, flag(error_handler, my_eh), flag(error_handler, error_handler),
         flag(error_handler, "x")},
        {priority, flag(priority, low), flag(priority, high), flag(priority, max),
         flag(priority, normal), flag(priority, bad), aflag(priority, low), aflag(priority, normal),
         process_info(Self, priority)},
        {scheduler, flag(scheduler, 1), flag(scheduler, 2), flag(scheduler, 0),
         flag(scheduler, -1), flag(scheduler, 100000), flag(scheduler, a)},
        {fullsweep, flag(fullsweep_after, 10), flag(fullsweep_after, 65535),
         flag(fullsweep_after, -1), flag(fullsweep_after, a)},
        {min_heap, flag(min_heap_size, 100), flag(min_heap_size, 233), flag(min_heap_size, -1)},
        {min_bin_vheap, flag(min_bin_vheap_size, 100), flag(min_bin_vheap_size, 46422),
         flag(min_bin_vheap_size, a)},
        {max_heap, flag(max_heap_size, 100000), flag(max_heap_size, #{size => 0}),
         flag(max_heap_size, bad), flag(max_heap_size, 10)},
        {mqd, flag(message_queue_data, off_heap), flag(message_queue_data, on_heap),
         flag(message_queue_data, bad), aflag(message_queue_data, on_heap)},
        {sensitive, flag(sensitive, true), flag(sensitive, false), flag(sensitive, 1)},
        {save_calls, flag(save_calls, 5), flag(save_calls, 0), flag(save_calls, 99999),
         flag(save_calls, a), aflag(save_calls, 0)},
        {async_dist, flag(async_dist, true), flag(async_dist, false), flag(async_dist, x)},
        {monitor_nodes, flag(monitor_nodes, true), flag(monitor_nodes, false),
         flag(monitor_nodes, x), flag({monitor_nodes, #{}}, true),
         flag({monitor_nodes, #{}}, false), flag({monitor_nodes, bad}, true)},
        {unknown, flag(foo, true), flag(42, true), flag({a, b}, true), flag({a, b, c}, true),
         aflag(foo, true)},
        {group_leader, catching(fun() -> group_leader(GL, Self) end),
         catching(fun() -> group_leader(GL, Live) end),
         catching(fun() -> group_leader(GL, Dead) end),
         catching(fun() -> group_leader(foo, Self) end),
         catching(fun() -> erts_internal:group_leader(GL, Self) end),
         catching(fun() -> erts_internal:group_leader(GL, Dead) end),
         catching(fun() -> erts_internal:group_leader(foo, Self) end),
         catching(fun() -> erts_internal:group_leader(GL, foo) end)}
    ],
    Live ! stop,
    {Cases, receive Any -> {leftover, Any} after 50 -> clean end}.

msg(Timeout) -> receive X -> tn(X) after Timeout -> none end.

%% Remaining times depend on timing; only their type is compared.
tn(I) when is_integer(I) -> int;
tn(T) when is_tuple(T) -> list_to_tuple([tn(E) || E <- tuple_to_list(T)]);
tn(O) -> norm(O).

timers() ->
    Self = self(),
    M = erlang,
    Dead = spawn(fun() -> ok end),
    Ref = monitor(process, Dead),
    receive {'DOWN', Ref, _, _, _} -> ok end,
    register(pflag_timer_name, Self),
    Cases = [
        {send_after, tn(erlang:send_after(5, Self, a)), msg(1000)},
        {send_after_apply, tn(M:send_after(5, Self, b)), msg(1000)},
        {start_timer, (fun() -> R = erlang:start_timer(5, Self, c),
                                receive {timeout, R, c} -> got after 1000 -> none end end)()},
        {start_timer_apply, (fun() -> R = M:start_timer(5, Self, d),
                                      receive {timeout, R, d} -> got after 1000 -> none end end)()},
        {name, tn(erlang:send_after(5, pflag_timer_name, e)), msg(1000)},
        {name_unregistered, tn(erlang:send_after(5, no_such_name, e)), msg(50)},
        {dead, tn(erlang:send_after(5, Dead, f)), msg(50)},
        {abs, tn(erlang:send_after(erlang:monotonic_time(millisecond) + 5, Self, g, [{abs, true}])),
         msg(1000)},
        {abs_past, tn(erlang:start_timer(-5, Self, h, [{abs, true}])), msg(1000)},
        {opts_false, tn(erlang:send_after(5, Self, i, [{abs, false}])), msg(1000)},
        {read_cancel, (fun() ->
                          R = erlang:send_after(100000, Self, x),
                          {tn(erlang:read_timer(R)), tn(erlang:cancel_timer(R)),
                           erlang:cancel_timer(R), erlang:read_timer(R)}
                      end)()},
        {apply_read_cancel, (fun() ->
                                R = M:start_timer(100000, Self, x),
                                {tn(M:read_timer(R)), tn(M:read_timer(R, [])),
                                 tn(M:cancel_timer(R, [])), M:cancel_timer(R)}
                            end)()},
        {info_false, (fun() ->
                         R = erlang:send_after(100000, Self, x),
                         {erlang:cancel_timer(R, [{info, false}]), erlang:read_timer(R)}
                     end)()},
        {async, (fun() ->
                    R = erlang:send_after(100000, Self, x),
                    A = erlang:read_timer(R, [{async, true}]),
                    MA = msg(1000),
                    B = erlang:cancel_timer(R, [{async, true}]),
                    MB = msg(1000),
                    C = erlang:cancel_timer(R, [{async, true}]),
                    MC = msg(1000),
                    D = erlang:read_timer(R, [{async, true}]),
                    MD = msg(1000),
                    {A, setelement(2, MA, r), B, setelement(2, MB, r), C, MC, D, MD}
                end)()},
        {async_info_false, (fun() ->
                               R = erlang:send_after(100000, Self, x),
                               {erlang:cancel_timer(R, [{async, true}, {info, false}]), msg(50),
                                erlang:cancel_timer(R, [{async, true}, {info, false}]), msg(50)}
                           end)()},
        {async_false, (fun() ->
                          R = erlang:send_after(100000, Self, x),
                          {tn(erlang:cancel_timer(R, [{async, false}, {info, true}])), msg(0)}
                      end)()},
        {expired, (fun() ->
                      R = erlang:send_after(0, Self, y),
                      Y = msg(1000),
                      {Y, erlang:cancel_timer(R), erlang:read_timer(R),
                       erlang:cancel_timer(R, [{info, false}]),
                       erlang:cancel_timer(R, [{async, true}]), msg(1000)}
                  end)()},
        {unknown_ref, erlang:cancel_timer(make_ref()), erlang:read_timer(make_ref())},
        {other_scheduler, (fun() ->
                              Parent = self(),
                              P = spawn_opt(fun() ->
                                                R = erlang:send_after(100000, Parent, z),
                                                Parent ! {ref, R},
                                                receive stop -> ok end
                                            end, [{scheduler, 2}]),
                              R = receive {ref, R0} -> R0 end,
                              Out = {tn(erlang:read_timer(R)), tn(erlang:cancel_timer(R)),
                                     erlang:cancel_timer(R)},
                              P ! stop,
                              Out
                          end)()},
        %% bad arguments
        {bad_time_neg, catching(fun() -> erlang:send_after(-1, Self, x) end)},
        {bad_time_float, catching(fun() -> M:send_after(1.0, Self, x) end)},
        {bad_time_big, catching(fun() -> erlang:start_timer(1 bsl 60, Self, x) end)},
        {bad_receiver, catching(fun() -> erlang:send_after(1, {a, b}, x) end)},
        {bad_receiver_int, catching(fun() -> erlang:start_timer(1, 42, x) end)},
        {bad_abs, catching(fun() -> erlang:send_after(1, Self, x, [{abs, 1}]) end)},
        {bad_opt, catching(fun() -> erlang:start_timer(1, Self, x, [{info, true}]) end)},
        {bad_optlist, catching(fun() -> M:send_after(1, Self, x, bad) end)},
        {bad_opt_time, catching(fun() -> erlang:send_after(a, Self, x, [bad]) end)},
        {cancel_bad, catching(fun() -> erlang:cancel_timer(foo) end)},
        {read_bad, catching(fun() -> M:read_timer(foo) end)},
        {cancel_badopt, catching(fun() -> erlang:cancel_timer(make_ref(), [{foo, 1}]) end)},
        {cancel_badinfo, catching(fun() -> erlang:cancel_timer(make_ref(), [{info, 1}]) end)},
        {read_info, catching(fun() -> erlang:read_timer(make_ref(), [{info, true}]) end)},
        {read_badlist, catching(fun() -> erlang:read_timer(make_ref(), [{async, true} | x]) end)}
    ],
    unregister(pflag_timer_name),
    {Cases, receive Any -> {leftover, Any} after 50 -> clean end}.
"#;

fn run(function: &str) {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named("pflag_timer", SOURCE, &[])
        .expect("compile differential");
    reference
        .load("pflag_timer", &beam)
        .expect("load reference module");
    let expected = reference.call("pflag_timer", function, &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load VM module");
    let actual = match vm.eval_scheduled("pflag_timer", function, &[], 2) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|diff| panic!("{function} differs: {diff}"));
}

#[test]
fn process_flag_and_process_bifs_match_otp() {
    run("flags");
}

#[test]
fn bif_timers_match_otp() {
    run("timers");
}

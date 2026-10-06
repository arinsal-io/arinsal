-module(defaults_probe).
-export([run/0, round_trips/0]).

value(Fun) ->
    try Fun() catch Class:Reason -> {Class, Reason} end.

print(Key, Value) -> io:format("~p=~w~n", [Key, Value]).

run() ->
    Keys = [schedulers, schedulers_online, dirty_cpu_schedulers,
            dirty_cpu_schedulers_online, dirty_io_schedulers, thread_pool_size,
            process_limit, port_limit, atom_limit, ets_limit, min_heap_size,
            min_bin_vheap_size, fullsweep_after, max_heap_size,
            message_queue_data, scheduler_bind_type, multi_scheduling,
            time_warp_mode, time_correction, kernel_poll, emu_flavor, emu_type,
            stack_size],
    lists:foreach(fun(Key) ->
        print(Key, value(fun() -> erlang:system_info(Key) end))
    end, Keys),
    Source = erlang:system_info(os_monotonic_time_source),
    print(os_monotonic_time_source_kind,
          {proplists:get_value(function, Source), proplists:get_value(clock_id, Source)}),
    print(init_arguments, init:get_arguments()),
    print(plain_arguments, init:get_plain_arguments()),
    print(code_mode, code:get_mode()),
    print(code_path, code:get_path()),
    print(kernel_env, lists:sort(application:get_all_env(kernel))),
    print(stdlib_env, lists:sort(application:get_all_env(stdlib))),
    Parent = self(),
    Pid = spawn(fun() -> Parent ! {ready, self()}, receive stop -> ok end end),
    receive {ready, Pid} -> ok end,
    lists:foreach(fun(Key) ->
        print({process, Key}, value(fun() -> process_info(Pid, Key) end))
    end, [priority, trap_exit, message_queue_data, error_handler,
          fullsweep_after, min_heap_size, min_bin_vheap_size, max_heap_size]),
    print(process_stack_bytes,
          element(2, process_info(Pid, stack_size)) * erlang:system_info(wordsize)),
    Pid ! stop,
    halt().

round_trips() ->
    lists:foreach(fun({Key, New}) ->
        Before = erlang:system_info(Key),
        Previous = value(fun() -> erlang:system_flag(Key, New) end),
        After = erlang:system_info(Key),
        print({system_flag_before, Key}, Before),
        print({system_flag_previous, Key}, Previous),
        print({system_flag_after, Key}, After)
    end, [{fullsweep_after, 42}, {min_heap_size, 377},
          {min_bin_vheap_size, 46422}, {max_heap_size, 100000},
          {schedulers_online, 2},
          {dirty_cpu_schedulers_online, 2}]),
    halt().

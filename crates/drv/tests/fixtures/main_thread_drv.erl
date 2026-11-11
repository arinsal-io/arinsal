-module(main_thread_drv).
-export([run/1]).

run(Dir) ->
    ok = erl_ddll:load_driver(Dir, "main_thread_drv"),
    Port = open_port({spawn_driver, "main_thread_drv"}, [binary]),
    Result = receive
        {Port, {data, <<Value>>}} -> Value
    after 5000 -> timeout
    end,
    true = port_close(Port),
    ok = erl_ddll:unload_driver("main_thread_drv"),
    Result.

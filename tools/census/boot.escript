#!/usr/bin/env escript
%%! -noshell

main([Source,Target]) ->
    {ok,[{script,Version,Commands}]} = file:consult(Source),
    {Before,[Marker|After]} = lists:splitwith(fun(C)->C =/= {progress,init_kernel_started} end,Commands),
    New = {script,Version,Before++[Marker,{primLoad,[census_hook]},
                                 {apply,{census_hook,start,[]}}|After]},
    ok = file:write_file(Target++".script",io_lib:format("~p.~n",[New])),
    ok = systools:script2boot(Target),
    io:format("boot: inserted trace hook after init_kernel_started~n").

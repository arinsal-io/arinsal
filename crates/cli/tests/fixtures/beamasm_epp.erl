-module(beamasm_epp).
-export([run/0]).

%% epp keeps its state in a record updated with update_record_in_place; a record that is not
%% younger than the last collection must be copied before it is mutated.
run() ->
    Dir = filename:basedir(user_cache, "arinsal_beamasm_epp"),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    File = filename:join(Dir, "beamasm_epp_src.erl"),
    ok = file:write_file(File, <<"-module(m).\n-export([?MODULE/0]).\n"
                                 "-define(X, 1).\nm() -> ?X.\n">>),
    Results = [case epp:parse_file(File, []) of
                   {ok, Forms} -> length(Forms);
                   Other -> Other
               end || _ <- lists:seq(1, 30)],
    io:format("~p~n", [lists:usort(Results)]).

%% The reply_return/2 function of OTP's logger_olp, which selects its reply shape by a map
%% pattern on `idle` (instr_map.cpp: an inline flatmap lookup of an immediate key).
-module(jit_reply_return).
-export([reply_return/2]).

-define(IDLE_DETECT_TIME, 300).

reply_return(Reply, #{idle := true} = State) ->
    {reply, Reply, State};
reply_return(Reply, #{idle := false} = State) ->
    {reply, Reply, State, ?IDLE_DETECT_TIME}.

-module(signal_test_handler).
-behaviour(gen_event).
-export([init/1, handle_event/2, handle_call/2, handle_info/2, terminate/2, code_change/3]).

init(Parent) -> {ok, Parent}.
handle_event(Signal, Parent) -> Parent ! {signal_event, Signal}, {ok, Parent}.
handle_call(_Request, Parent) -> {ok, ok, Parent}.
handle_info(_Info, Parent) -> {ok, Parent}.
terminate(_Reason, _Parent) -> ok.
code_change(_Old, Parent, _Extra) -> {ok, Parent}.

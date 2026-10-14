//! A trapping BIF continues as a call to its trap export, so a scheduled-out
//! process shows that export's frame: `process_info` stack size, current function
//! and backtrace match erts (OTP-29.1.1 `BIF_TRAP` / `emit_bif_export_trap`).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(trap_cont).
-export([run/0, run_shapes/0, child/3, plain_child/1]).
run() ->
    %% Each trap has to outlast a few schedule slices so the parent observes it
    %% while the child is still inside the continuation export.
    Encoded = term_to_binary(lists:seq(1, 500000)),
    L = lists:seq(1, 800000),
    Pairs = [{K, K} || K <- lists:seq(1, 100000)],
    [probe(rev, {lists, reverse, 2}, fun() -> lists:reverse(L, []) end),
     probe(b2t, {erts_internal, binary_to_term_trap, 1},
            fun() -> binary_to_term(Encoded) end),
     probe(map, {maps, from_list, 1}, fun() -> maps:from_list(Pairs) end)].
run_shapes() ->
    L = lists:seq(1, 800000),
    Want = {lists, reverse, 2},
    [plain(),
     probe(local_tail, Want, fun() -> tail(L) end),
     probe(local_call, Want, fun() -> call(L) end),
     probe(local_tail_frame, Want, fun() -> tail_frame(L) end),
     probe(fun_call, Want, fun() -> _ = lists:reverse(L, []), ok end)].
tail(L) -> lists:reverse(L, []).
call(L) -> X = lists:reverse(L, []), {X}.
tail_frame(L) -> _ = id(L), lists:reverse(L, []).
id(X) -> X.
plain() ->
    Parent = self(),
    Pid = spawn(trap_cont, plain_child, [Parent]),
    receive ready -> ok end,
    {plain, frames(process_info(Pid, [stack_size, current_function, backtrace]))}.
plain_child(Parent) ->
    Parent ! ready,
    receive stop -> ok end.
probe(Tag, Want, Fun) ->
    Parent = self(),
    Pid = spawn(trap_cont, child, [Parent, Tag, Fun]),
    1 = erlang:trace(Pid, true, [running, {tracer, Parent}]),
    Pid ! go,
    {Tag, wait(Pid, Want, [])}.
child(Parent, _Tag, Fun) ->
    receive go ->
        Fun(),
        Parent ! {done, self()}
    end.
wait(Pid, Want, Seen) ->
    receive
        {trace, Pid, out, _} ->
            case process_info(Pid, [stack_size, current_function, backtrace]) of
                undefined -> wait(Pid, Want, Seen);
                Info ->
                    case lists:keyfind(current_function, 1, Info) of
                        {current_function, Want} -> frames(Info);
                        {current_function, Other} ->
                            wait(Pid, Want, [Other | Seen])
                    end
            end;
        {trace, Pid, in, _} -> wait(Pid, Want, Seen);
        {done, Pid} -> {done, lists:reverse(Seen)}
    after 15000 -> {timeout, lists:reverse(Seen)}
    end.
frames(Info) ->
    {value, {stack_size, Stack}} = lists:keysearch(stack_size, 1, Info),
    {value, {current_function, Current}} = lists:keysearch(current_function, 1, Info),
    {value, {backtrace, Bin}} = lists:keysearch(backtrace, 1, Info),
    {Stack, Current, names(Bin)}.
names(Bin) ->
    [name(Line) || Line <- binary:split(Bin, <<"\n">>, [global]), name(Line) =/= skip].
name(Line) ->
    case binary:match(Line, <<"Return addr">>) of
        nomatch ->
            case binary:match(Line, <<"Program counter:">>) of
                nomatch -> skip;
                _ -> fun_name(Line)
            end;
        _ -> fun_name(Line)
    end.
fun_name(Line) ->
    case binary:match(Line, <<"(">>) of
        nomatch -> skip;
        {Pos, _} ->
            Rest = binary:part(Line, Pos + 1, byte_size(Line) - Pos - 1),
            case binary:split(Rest, <<")">>) of
                [Name, _] ->
                    Bare = binary:replace(Name, <<"'">>, <<>>, [global]),
                    case binary:split(Bare, <<" + ">>) of
                        [Fun, _] -> Fun;
                        [Fun] -> Fun
                    end;
                _ -> skip
            end
    end.
"#;

#[test]
fn trap_continuation_stack_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping trap continuation differential test");
        return;
    };
    let beam = reference.compile_named("trap_cont", SOURCE, &[]).unwrap();
    reference.load("trap_cont", &beam).unwrap();
    let expected = reference.call("trap_cont", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    // A short quantum makes each trap a real schedule-out the tracer can sample.
    // The frame at that out does not depend on how far the BIF got.
    let actual = vm
        .eval_scheduled_reductions("trap_cont", "run", &[], 1, Some(0x7C0), 4_000)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn trap_frames_of_each_call_shape_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping trap frame shape differential test");
        return;
    };
    let beam = reference.compile_named("trap_cont", SOURCE, &[]).unwrap();
    reference.load("trap_cont", &beam).unwrap();
    let expected = reference.call("trap_cont", "run_shapes", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled_reductions("trap_cont", "run_shapes", &[], 1, Some(0x7C2), 4_000)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}

#[test]
fn reverse_trap_result_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping reverse trap result test");
        return;
    };
    let source = r#"
-module(rev_val).
-export([run/0]).
run() ->
    L = lists:seq(1, 200000),
    R = lists:reverse(L, [0]),
    {lists:reverse([1,2,3], [9]), lists:reverse([], [7]), hd(R), lists:last(R), length(R)}.
"#;
    let beam = reference.compile_named("rev_val", source, &[]).unwrap();
    reference.load("rev_val", &beam).unwrap();
    let expected = reference.call("rev_val", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled_reductions("rev_val", "run", &[], 1, Some(0x7C1), 4_000)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}

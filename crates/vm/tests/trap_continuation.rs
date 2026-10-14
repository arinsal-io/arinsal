//! A trapping BIF continues as a call to its trap export, so a scheduled-out
//! process shows that export's frame: `process_info` stack size, current function
//! and backtrace match erts (OTP-29.1.1 `BIF_TRAP` / `emit_bif_export_trap`).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(trap_cont).
-export([run/0, run_shapes/0, run_fun_shapes/0, run_apply_traps/0, child/3, plain_child/1, out_child/2]).
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
    M = lists, F = reverse,
    [plain(),
     probe(local_tail, Want, fun() -> tail(L) end),
     probe(local_call, Want, fun() -> call(L) end),
     probe(local_tail_frame, Want, fun() -> tail_frame(L) end),
     probe(frame_words, Want, fun() -> tail_frame_words(L) end),
     probe(apply_last, Want, fun() -> apply_last(M, F, L) end),
     probe(fun_call, Want, fun() -> _ = lists:reverse(L, []), ok end)].
run_apply_traps() ->
    L = lists:seq(1, 800000),
    M = lists, F = reverse,
    [{direct, traps(fun() -> X = lists:reverse(L, []), {X} end)},
     {apply_call, traps(fun() -> X = M:F(L, []), {X} end)},
     {apply_tail, traps(fun() -> apply_tail(M, F, L) end)},
     {apply_frame, traps(fun() -> X = apply_last(M, F, L), {X} end)},
     {apply_three, traps(fun() -> X = apply(M, F, [L, []]), {X} end)}].
traps(Fun) ->
    Parent = self(),
    Pid = spawn(trap_cont, out_child, [Parent, Fun]),
    1 = erlang:trace(Pid, true, [running, {tracer, Parent}]),
    Pid ! go,
    outs(Pid, 0).
outs(Pid, Traps) ->
    receive
        {trace, Pid, out, {lists, reverse, 2}} -> outs(Pid, Traps + 1);
        {trace, Pid, _, _} -> outs(Pid, Traps);
        {done, Pid} -> {finished, Traps >= 2}
    after 60000 -> hung
    end.
out_child(Parent, Fun) ->
    receive go -> Fun(), Parent ! {done, self()} end.
run_fun_shapes() ->
    L = lists:seq(1, 800000),
    Want = {lists, reverse, 2},
    Fn = fun lists:reverse/2,
    [probe(fun_last, Want, fun() -> fun_last(Fn, L) end),
     probe(fun_tail, Want, fun() -> fun_tail(Fn, L) end)].
tail(L) -> lists:reverse(L, []).
call(L) -> X = lists:reverse(L, []), {X}.
tail_frame(L) -> _ = id(L), lists:reverse(L, []).
tail_frame_words(L) -> K = {marker, 1}, _ = id(L), lists:reverse(L, [K]).
apply_last(M, F, L) -> _ = id(L), M:F(L, []).
apply_tail(M, F, L) -> M:F(L, []).
fun_last(Fn, L) -> _ = id(L), Fn(L, []).
fun_tail(Fn, L) -> Fn(L, []).
id(X) -> X.
plain() ->
    Parent = self(),
    Pid = spawn(trap_cont, plain_child, [Parent]),
    receive ready -> ok end,
    {plain, frames(process_info(Pid, [stack_size, current_function, backtrace, current_stacktrace]))}.
plain_child(Parent) ->
    Parent ! ready,
    receive stop -> ok end.
probe(Tag, Want, Fun) ->
    Parent = self(),
    Pid = spawn(trap_cont, child, [Parent, Tag, Fun]),
    1 = erlang:trace(Pid, true, [running, {tracer, Parent}]),
    Pid ! go,
    Frames = wait(Pid, Want, []),
    Fin = receive {done, Pid} -> finished after 60000 -> hung end,
    {Tag, Frames, Fin}.
child(Parent, _Tag, Fun) ->
    receive go ->
        Fun(),
        Parent ! {done, self()}
    end.
wait(Pid, Want, Seen) ->
    receive
        {trace, Pid, out, _} ->
            case process_info(Pid, [stack_size, current_function, backtrace, current_stacktrace]) of
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
    {value, {current_stacktrace, Trace}} = lists:keysearch(current_stacktrace, 1, Info),
    {Stack, Current, names(Bin), [{M, F, A} || {M, F, A, _} <- Trace], ys(Bin)}.
ys(Bin) ->
    [yval(Line) || Line <- binary:split(Bin, <<"\n">>, [global]), is_y(Line)].
is_y(<<"y(", _/binary>>) -> true;
is_y(_) -> false.
yval(Line) ->
    [_, Rest] = binary:split(Line, <<")">>),
    Value = string:trim(Rest, leading),
    case Value of
        <<"<", _/binary>> -> pid_or_ref;
        <<"Catch", _/binary>> -> catch_slot;
        _ -> binary:part(Value, 0, min(60, byte_size(Value)))
    end.
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
fn apply_of_a_trapping_bif_traps_like_a_direct_call_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping apply trap differential test");
        return;
    };
    let beam = reference.compile_named("trap_cont", SOURCE, &[]).unwrap();
    reference.load("trap_cont", &beam).unwrap();
    let expected = reference.call("trap_cont", "run_apply_traps", &[]);
    for seed in [0x7C4, 1, 6, 10] {
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled_reductions("trap_cont", "run_apply_traps", &[], 1, Some(seed), 4_000)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "seed {seed:#x}");
    }
}

#[test]
fn trap_frames_of_a_tail_called_export_fun_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping export fun trap frame differential test");
        return;
    };
    let beam = reference.compile_named("trap_cont", SOURCE, &[]).unwrap();
    reference.load("trap_cont", &beam).unwrap();
    let expected = reference.call("trap_cont", "run_fun_shapes", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled_reductions("trap_cont", "run_fun_shapes", &[], 1, Some(0x7C3), 4_000)
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

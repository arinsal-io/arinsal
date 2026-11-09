//! Regression: a message carrying a seq_trace token makes the receiver emit its `receive`
//! event on its own heap inside `remove_message`; the JIT must publish HTOP/E around it.
//! A tracer that is itself the receiver of a tokened message used to get its accumulator
//! (an improper list) overwritten under the JIT.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(seq_trace_receive_heap_diff).
-export([run/0]).
run() ->
    Tracer = spawn_link(fun() -> loop([]) end),
    seq_trace:set_system_tracer(Tracer),
    seq_trace:set_token(label, 17),
    seq_trace:set_token(print, true),
    seq_trace:set_token(send, true),
    seq_trace:set_token('receive', true),
    [seq_trace:print(17, "trace started " ++ integer_to_list(I)) || I <- lists:seq(1, 8)],
    Ref = erlang:trace_delivered(all),
    receive {trace_delivered, all, Ref} -> ok end,
    Tracer ! {get, self()},
    receive {msgs, Msgs} ->
        seq_trace:reset_trace(),
        [Info || {seq_trace, 17, {print, _, _, _, Info}} <- Msgs]
    after 5000 -> tracer_timeout
    end.
loop(Acc) ->
    receive
        {get, From} -> From ! {msgs, lists:reverse(Acc)};
        Msg -> loop([Msg | Acc])
    end.
"#;

#[test]
fn tracer_receiving_a_tokened_message_keeps_its_accumulator() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping seq_trace receive heap differential test");
        return;
    };
    let beam = reference
        .compile_named("seq_trace_receive_heap_diff", SOURCE, &[])
        .unwrap();
    reference
        .load("seq_trace_receive_heap_diff", &beam)
        .unwrap();
    let CallResult::Ok(expected) = reference.call("seq_trace_receive_heap_diff", "run", &[]) else {
        panic!("reference run failed");
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("seq_trace_receive_heap_diff", "run", &[], 1, Some(74))
        .unwrap()
        .term;
    assert_eq!(actual, expected);
}

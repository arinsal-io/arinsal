use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(sig_buffers_order).
-export([run/0]).
run() ->
    process_flag(message_queue_data, off_heap),
    erts_debug:set_internal_state(available_internal_state, true),
    true = erts_debug:set_internal_state(proc_sig_buffers, true),
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        Parent ! {self(), first},
        Parent ! {self(), second}
    end),
    First = receive {Pid, first} -> first end,
    Second = receive {Pid, second} -> second end,
    Down = receive {'DOWN', Ref, process, Pid, Reason} -> Reason end,
    {First, Second, Down}.
"#;

#[test]
fn buffered_messages_precede_sender_down_signal_vs_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping parallel signal buffer differential test");
        return;
    };
    let beam = reference
        .compile_named("sig_buffers_order", SOURCE, &[])
        .expect("compile parallel signal buffer probe");
    reference.load("sig_buffers_order", &beam).unwrap();
    let expected = reference.call("sig_buffers_order", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("sig_buffers_order", "run", &[], 4, Some(0x51_6e_51))
        .unwrap_or_else(|error| panic!("parallel signal buffer probe: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}

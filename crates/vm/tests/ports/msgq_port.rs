use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(msgq_port).
-export([selective_receive_order/0, queue_data_switch/0, queue_fields/0, ref_marker/0]).

selective_receive_order() ->
    Ref = make_ref(),
    self() ! {skip, 2},
    self() ! {wanted, Ref, 3},
    A = receive {wanted, Ref, X} -> X end,
    B = receive {skip, 2} -> done end,
    {A, B}.

queue_data_switch() ->
    Old1 = process_flag(message_queue_data, off_heap),
    self() ! {queued, 1},
    Old2 = process_flag(message_queue_data, on_heap),
    self() ! {queued, 2},
    {message_queue_len, 2} = process_info(self(), message_queue_len),
    {messages, [{queued, 1}, {queued, 2}]} = process_info(self(), messages),
    {Old1, Old2, receive {queued, 1} -> first end,
     receive {queued, 2} -> second end}.

queue_fields() ->
    self() ! {field, one},
    self() ! {field, two},
    {message_queue_len, 2} = process_info(self(), message_queue_len),
    {messages, [{field, one}, {field, two}]} = process_info(self(), messages),
    {message_queue_data, on_heap} = process_info(self(), message_queue_data),
    {total_heap_size, Size} = process_info(self(), total_heap_size),
    is_integer(Size).

ref_marker() ->
    Ref = make_ref(),
    self() ! {other, earlier},
    self() ! {reply, Ref, answer},
    receive {reply, Ref, Value} -> Value end.
"#;

fn compare(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping {function} differential test");
        return;
    };
    let beam = reference.compile_named("msgq_port", SOURCE, &[]).unwrap();
    reference.load("msgq_port", &beam).unwrap();
    let expected = reference.call("msgq_port", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled("msgq_port", function, &[], 1, Some(91));
    assert_eq!(
        expected,
        CallResult::Ok(
            actual
                .unwrap_or_else(|error| panic!("{function}: {error}"))
                .term
        ),
        "{function}"
    );
}

#[test]
fn selective_receive_order_vs_erl() {
    compare("selective_receive_order");
}

#[test]
fn message_queue_data_switch_vs_erl() {
    compare("queue_data_switch");
}

#[test]
fn process_info_queue_fields_vs_erl() {
    compare("queue_fields");
}

#[test]
fn recv_marker_ref_receive_vs_erl() {
    compare("ref_marker");
}

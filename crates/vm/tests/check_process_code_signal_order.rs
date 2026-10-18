use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const WORKER: &str = "check_process_code_order_worker";
const SIGNAL_CONTROL: &str = "check_process_code_signal_control";

fn signal_worker_source() -> &'static str {
    "-module(check_process_code_order_worker). -export([loop/1]). loop(Parent) -> Parent ! {ready, self()}, receive stop -> ok after 10000 -> loop(Parent) end."
}

fn signal_control_source() -> &'static str {
    "-module(check_process_code_signal_control). -export([run/0]). run() -> process_flag(scheduler, 1), process_flag(priority, high), Pid = spawn_opt(check_process_code_order_worker, loop, [self()], [{scheduler, 1}]), receive {ready, Pid} -> ok after 10000 -> timeout end, true = erlang:delete_module(check_process_code_order_worker), true = erlang:check_process_code(Pid, check_process_code_order_worker), spam(Pid, 10000), exit(Pid, kill), Ref = make_ref(), async = erlang:check_process_code(Pid, check_process_code_order_worker, [{async, Ref}]), result(Ref). spam(_Pid, N) when N =< 0 -> ok; spam(Pid, N) -> link(Pid), unlink(Pid), spam(Pid, N - 2). result(Ref) -> receive {check_process_code, Ref, Result} -> Result after 10000 -> timeout end."
}

#[test]
fn async_check_process_code_observes_prior_exit_signal() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping check_process_code signal-order differential test");
        return;
    };
    let worker = reference
        .compile_named(WORKER, signal_worker_source(), &[])
        .unwrap();
    let control = reference
        .compile_named(SIGNAL_CONTROL, signal_control_source(), &[])
        .unwrap();
    reference.load(WORKER, &worker).unwrap();
    reference.load(SIGNAL_CONTROL, &control).unwrap();
    let expected = reference.call(SIGNAL_CONTROL, "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&worker).unwrap();
    vm.load_bytes(&control).unwrap();
    let actual = vm
        .eval_scheduled(SIGNAL_CONTROL, "run", &[], 1, None)
        .unwrap()
        .term;

    assert_eq!(expected, CallResult::Ok(OwnedTerm::Atom("false".into())));
    assert_eq!(CallResult::Ok(actual), expected);
}

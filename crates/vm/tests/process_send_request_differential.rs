use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_send_request_diff).
-export([run/0, wait/0]).

run() ->
    Pid = spawn(proc_send_request_diff, wait, []),
    unlink(Pid),
    exit(Pid, kill),
    ReqId = gen:send_request(Pid, '$gen_call', request),
    receive
        Msg ->
            case gen:check_response(Msg, ReqId) of
                {error, {Reason, Pid}} -> Reason;
                Other -> {unexpected, Other}
            end
    after 1000 -> timeout
    end.

wait() -> receive stop -> ok end.
"#;

#[test]
fn request_monitor_after_queued_exit_reports_noproc() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping send request differential");
        return;
    };
    let beam = reference
        .compile_named("proc_send_request_diff", SOURCE, &[])
        .expect("compile send request differential");
    reference
        .load("proc_send_request_diff", &beam)
        .expect("load send request differential");
    let expected = reference.call("proc_send_request_diff", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam)
        .expect("load send request differential");
    let actual = vm
        .eval_scheduled("proc_send_request_diff", "run", &[], 2, None)
        .expect("run send request differential")
        .term;

    similar_asserts::assert_eq!(expected, CallResult::Ok(OwnedTerm::atom("noproc")));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "Arinsal request error");
}

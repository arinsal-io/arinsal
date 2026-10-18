use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_spawn_bif_diff).
-export([run/0]).

run() ->
    Parent = self(),
    {Pid, Ref} = spawn_opt(erlang, send, [Parent, spawned_bif_message], [monitor]),
    receive
        spawned_bif_message -> delivered;
        {'DOWN', Ref, process, Pid, Reason} -> {down, Reason}
    after 1000 ->
        missing
    end.
"#;

#[test]
fn spawned_process_bif_receives_its_mfa_arguments() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping spawned BIF differential");
        return;
    };
    let beam = reference
        .compile_named("proc_spawn_bif_diff", SOURCE, &[])
        .expect("compile spawned BIF differential");
    reference
        .load("proc_spawn_bif_diff", &beam)
        .expect("load spawned BIF differential");
    let expected = reference.call("proc_spawn_bif_diff", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load spawned BIF differential");
    let actual = vm
        .eval_scheduled("proc_spawn_bif_diff", "run", &[], 2, None)
        .expect("run spawned BIF differential")
        .term;

    similar_asserts::assert_eq!(expected, CallResult::Ok(OwnedTerm::atom("delivered")));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual), "spawned BIF result");
}

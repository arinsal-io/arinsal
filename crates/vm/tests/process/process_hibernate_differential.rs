use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(proc_hib_diff).
-export([run/0, hibernate0/1, hibernate3/1, resume3/1]).

run() ->
    Parent = self(),
    P0 = spawn(proc_hib_diff, hibernate0, [Parent]),
    receive ready0 -> ok after 1000 -> erlang:error(ready0_timeout) end,
    receive after 25 -> ok end,
    {current_function, Cf0} = process_info(P0, current_function),
    P0 ! wake0,
    receive {woke0, P0} -> ok after 1000 -> erlang:error(wake0_timeout) end,

    P3 = spawn(proc_hib_diff, hibernate3, [Parent]),
    receive ready3 -> ok after 1000 -> erlang:error(ready3_timeout) end,
    receive after 25 -> ok end,
    {current_function, Cf3} = process_info(P3, current_function),
    P3 ! wake3,
    receive {woke3, P3} -> ok after 1000 -> erlang:error(wake3_timeout) end,
    {Cf0, Cf3}.

hibernate0(Parent) ->
    Parent ! ready0,
    erlang:hibernate(),
    Parent ! {woke0, self()}.

hibernate3(Parent) ->
    Parent ! ready3,
    erlang:hibernate(proc_hib_diff, resume3, [Parent]).

resume3(Parent) ->
    receive wake3 -> Parent ! {woke3, self()} end.

"#;

#[test]
fn hibernate_current_functions_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping hibernate differential");
        return;
    };
    let beam = reference
        .compile_named("proc_hib_diff", SOURCE, &[])
        .expect("compile hibernate differential");
    reference
        .load("proc_hib_diff", &beam)
        .expect("load hibernate differential");
    let expected = reference.call("proc_hib_diff", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load hibernate differential");
    let actual = vm
        .eval_scheduled("proc_hib_diff", "run", &[], 2, None)
        .expect("run hibernate differential")
        .term;

    similar_asserts::assert_eq!(
        expected,
        CallResult::Ok(actual),
        "hibernate current functions"
    );
    similar_asserts::assert_eq!(
        expected,
        CallResult::Ok(OwnedTerm::Tuple(vec![
            OwnedTerm::Tuple(vec![
                OwnedTerm::atom("proc_hib_diff"),
                OwnedTerm::atom("hibernate0"),
                OwnedTerm::Int(1),
            ]),
            OwnedTerm::Tuple(vec![
                OwnedTerm::atom("erlang"),
                OwnedTerm::atom("hibernate"),
                OwnedTerm::Int(3),
            ]),
        ])),
        "OTP hibernate continuation MFAs"
    );
}

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(env_diff).
-export([set_get/0, unset_get/0, list_has/0, invalid/0, child/0, signal/0]).
set_get() -> true = os:putenv("ARINSAL_ENV_TEST", "changed"), os:getenv("ARINSAL_ENV_TEST").
unset_get() -> true = os:unsetenv("ARINSAL_ENV_TEST"), os:getenv("ARINSAL_ENV_TEST").
list_has() -> true = os:putenv("ARINSAL_ENV_TEST", "listed"),
    lists:member("ARINSAL_ENV_TEST=listed", os:getenv()).
invalid() ->
    {(try os:putenv(not_a_string,"v") catch error:R1 -> {error,R1} end),
     (try os:putenv("=bad","v") catch error:R2 -> {error,R2} end),
     (try os:putenv("","v") catch error:R3 -> {error,R3} end),
     (try os:unsetenv("bad=name") catch error:R -> {error,R} end)}.
child() ->
    true = os:putenv("ARINSAL_ENV_TEST", "child-value"),
    P = open_port({spawn_executable, "/usr/bin/printenv"}, [{args, ["ARINSAL_ENV_TEST"]}, binary]),
    receive {P,{data,<<"child-value\n">>}} -> catch port_close(P), ok after 5000 -> timeout end.
signal() ->
    case whereis(erl_signal_server) of
        undefined ->
            register(erl_signal_server, self()),
            ok = os:set_signal(sigusr1, handle),
            P = open_port({spawn_executable, "/bin/kill"}, [{args, ["-USR1", os:getpid()]}, exit_status]),
            receive {notify, sigusr1} -> catch port_close(P), unregister(erl_signal_server), ok
            after 5000 -> catch port_close(P), unregister(erl_signal_server), timeout end;
        _ ->
            ok = os:set_signal(sigusr1, handle),
            P = open_port({spawn_executable, "/bin/kill"}, [{args, ["-USR1", os:getpid()]}, exit_status]),
            receive {notify, sigusr1} -> catch port_close(P), ok after 200 -> catch port_close(P), ok end
    end.
"#;

fn compare_call(reference: &RefErl, beam: &[u8], function: &str, args: &[OwnedTerm]) {
    let expected = reference.call("env_diff", function, args);
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).unwrap();
    let args = args
        .iter()
        .map(|arg| {
            let mut heap = arinsal_term::VecHeap::new();
            arinsal_term::from_owned(arg, &mut heap).unwrap()
        })
        .collect::<Vec<_>>();
    let actual = vm
        .eval_scheduled("env_diff", function, &args, 1, None)
        .map(|result| result.term)
        .unwrap_or_else(|error| panic!("{function}: VM error {error:?}"));
    assert_eq!(expected, CallResult::Ok(actual), "{function}");
}

#[test]
fn environment_and_signal_bifs_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping environment differential test");
        return;
    };
    let beam = reference.compile_named("env_diff", SOURCE, &[]).unwrap();
    reference.load("env_diff", &beam).unwrap();
    reference.call("os", "unsetenv", &[OwnedTerm::charlist("ARINSAL_ENV_TEST")]);
    for function in ["set_get", "list_has", "unset_get", "invalid", "child"] {
        compare_call(&reference, &beam, function, &[]);
    }
    let signal_expected = reference.call(
        "os",
        "set_signal",
        &[OwnedTerm::atom("sigusr1"), OwnedTerm::atom("handle")],
    );
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("env_diff", "signal", &[], 1, None)
        .unwrap();
    assert_eq!(signal_expected, CallResult::Ok(actual.term));
}

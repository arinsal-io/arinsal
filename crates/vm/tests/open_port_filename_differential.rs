use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "open_port_filename_test";
const SOURCE: &str = r#"
-module(open_port_filename_test).
-export([atom_arg/0, unicode_arg/0, binary_arg/0, atom_path/0]).

atom_arg() -> run("/usr/bin/printf", ["%s", open_port_filename_test]).
unicode_arg() -> run("/usr/bin/printf", ["%s", [960]]).
binary_arg() -> run("/usr/bin/printf", ["%s", <<255>>]).
atom_path() -> run('/usr/bin/printf', ["%s", "ok"]).

run(Path, Args) ->
    Port = open_port({spawn_executable, Path}, [binary, exit_status, {args, Args}]),
    collect(Port, []).

collect(Port, Chunks) ->
    receive
        {Port, {data, Data}} -> collect(Port, [Data | Chunks]);
        {Port, {exit_status, Status}} -> {iolist_to_binary(lists:reverse(Chunks)), Status}
    after 5000 ->
        erlang:error(port_timeout)
    end.
"#;

#[test]
fn spawn_executable_filename_terms_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    for function in ["atom_arg", "unicode_arg", "binary_arg", "atom_path"] {
        let CallResult::Ok(expected) = reference.call(MODULE, function, &[]) else {
            panic!("OTP open_port failed in {function}");
        };
        let actual = vm.eval_scheduled(MODULE, function, &[], 1, None).unwrap();
        assert_eq!(expected, actual.term, "open_port {function}");
    }
}

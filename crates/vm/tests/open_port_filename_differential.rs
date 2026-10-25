use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "open_port_filename_test";
const SOURCE: &str = r#"
-module(open_port_filename_test).
-export([atom_arg/0, unicode_arg/0, binary_arg/0, atom_path/0, spawn_args_invalid/0, fd_exhaustion/0]).

atom_arg() -> run("/usr/bin/printf", ["%s", open_port_filename_test]).
unicode_arg() -> run("/usr/bin/printf", ["%s", [960]]).
binary_arg() -> run("/usr/bin/printf", ["%s", <<255>>]).
atom_path() -> run('/usr/bin/printf', ["%s", "ok"]).
spawn_args_invalid() ->
    try open_port({spawn, "true"}, [{args, ["ignored"]}])
    catch error:Reason -> Reason
    end.

fd_exhaustion() -> open_many(128, []).
open_many(0, Ports) -> close_ports(Ports), none;
open_many(N, Ports) ->
    try open_port({spawn_executable, "/bin/cat"}, []) of
        Port -> open_many(N - 1, [Port | Ports])
    catch error:Reason -> close_ports(Ports), Reason
    end.
close_ports(Ports) -> lists:foreach(fun port_close/1, Ports).

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

    for function in [
        "atom_arg",
        "unicode_arg",
        "binary_arg",
        "atom_path",
        "spawn_args_invalid",
    ] {
        match reference.call(MODULE, function, &[]) {
            CallResult::Ok(expected) => {
                let actual = vm.eval_scheduled(MODULE, function, &[], 1, None).unwrap();
                assert_eq!(expected, actual.term, "open_port {function}");
            }
            CallResult::Exception {
                class,
                reason: expected,
                ..
            } => {
                let actual = match vm.eval_scheduled(MODULE, function, &[], 1, None) {
                    Ok(_) => {
                        panic!("Arinsal accepted open_port {function} arguments that OTP rejected")
                    }
                    Err(error) => error,
                };
                let arinsal_vm::VmError::Raised(actual) = actual else {
                    panic!("unexpected Arinsal error for open_port {function}: {actual:?}");
                };
                assert_eq!(class, "error", "open_port {function}");
                assert_eq!(
                    actual.class,
                    arinsal_bifs::Class::Error,
                    "open_port {function}"
                );
                assert_eq!(expected, actual.reason, "open_port {function}");
            }
            other => panic!("unexpected OTP result for open_port {function}: {other:?}"),
        }
    }
}

#[test]
fn spawn_port_descriptor_exhaustion_matches_otp() {
    let old_limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    let limit = rustix::process::Rlimit {
        current: Some(64),
        maximum: old_limit.maximum,
    };
    rustix::process::setrlimit(rustix::process::Resource::Nofile, limit)
        .expect("lower descriptor soft limit for the isolated test process");
    let _restore = RestoreFileLimit(old_limit);

    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let CallResult::Ok(expected) = reference.call(MODULE, "fd_exhaustion", &[]) else {
        panic!("OTP descriptor exhaustion probe failed");
    };

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "fd_exhaustion", &[], 1, None)
        .unwrap()
        .term;
    assert_eq!(expected, OwnedTerm::atom("emfile"));
    assert_eq!(actual, expected);
}

struct RestoreFileLimit(rustix::process::Rlimit);

impl Drop for RestoreFileLimit {
    fn drop(&mut self) {
        rustix::process::setrlimit(rustix::process::Resource::Nofile, self.0)
            .expect("restore descriptor limit");
    }
}

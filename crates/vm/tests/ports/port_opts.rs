use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

#[test]
fn spawn_options_iodata_fd_and_errors_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping port option differential scenarios");
        return;
    };
    let source = r#"
-module(port_opts_diff).
-export([env_cd_stderr/0, argv/0, iodata/0, port_message/0, fd_write/0, bad_option/0, bad_env/0, bad_busy/0, bad_iodata/0, accepted/0]).
env_cd_stderr() ->
    P=open_port({spawn,"printf '%s\\n%s\\nerr\\n' \"$X\" \"$PWD\" 1>&2"},[binary,{env,[{"X","value"},{"Y",false}]},{cd,"/tmp"},stderr_to_stdout]),
    receive {P,{data,D}} -> D after 5000 -> timeout end.
argv() ->
    P=open_port({spawn_executable,"/bin/sh"},[binary,{arg0,"custom-name"},{args,["-c","printf '%s' \"$0\""]},exit_status]),
    receive {P,{data,D}} -> receive {P,{exit_status,0}} -> D after 5000 -> timeout end after 5000 -> timeout end.
iodata() ->
    Sub = binary:part(<<99,3,4,99>>,1,2),
    P=open_port({spawn_executable,"/bin/cat"},[binary,eof]),
    Result=port_command(P,[1,[2,Sub]|<<5,6>>],[nosuspend]),
    true=port_close(P),
    Result.
port_message() -> P=open_port({spawn_executable,"/bin/cat"},[]), P ! {self(),{command,[1,[2,<<3>>]|<<4>>]}}, true=port_close(P), ok.
fd_write() -> P=open_port({fd,0,2},[]), true=port_command(P,<<"fd-port-write\n">>), ok.
bad_option() -> try open_port({spawn,"true"},[{parallelism,invalid}]) catch error:R -> R end.
bad_env() -> try open_port({spawn,"true"},[{env,[{"BAD=NAME","x"}]}]) catch error:R -> R end.
bad_busy() -> try open_port({spawn,"true"},[{busy_limits_port,{0,10}}]) catch error:R -> R end.
bad_iodata() -> P=open_port({spawn_executable,"/bin/cat"},[]), try port_command(P,[300]) catch error:R -> port_close(P), R end.
accepted() ->
    P=open_port({spawn,"printf ok >&4"},[binary,stream,hide,overlapped_io,nouse_stdio,{parallelism,false},{busy_limits_port,disabled},{busy_limits_msgq,disabled}]),
    receive {P,{data,D}} -> catch port_close(P), D after 5000 -> timeout end.
"#;
    let beam = reference
        .compile_named("port_opts_diff", source, &[])
        .unwrap();
    reference.load("port_opts_diff", &beam).unwrap();
    for function in [
        "env_cd_stderr",
        "argv",
        "iodata",
        "port_message",
        "bad_option",
        "bad_env",
        "bad_busy",
        "bad_iodata",
        "accepted",
        "fd_write",
    ] {
        let expected = reference.call("port_opts_diff", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm.eval_scheduled("port_opts_diff", function, &[], 1, None);
        assert_eq!(expected, CallResult::Ok(actual.unwrap().term), "{function}");
    }
}

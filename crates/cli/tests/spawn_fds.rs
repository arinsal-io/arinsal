//! A live `spawn` port holds the same number of descriptors as in erl: the in and out pipe
//! ends and nothing else (sys_drivers.c `spawn_start`); no per-port wake-up pipe.

use std::process::Command;

const SCRIPT: &str = r#"
Count = fun() -> {ok, L} = file:list_dir("/dev/fd"), length(L) end,
Before = Count(),
Ports = [open_port({spawn, "cat"}, [binary]) || _ <- lists:seq(1, 100)],
After = Count(),
[port_close(P) || P <- Ports],
io:format("~p~n", [After - Before]),
halt().
"#;

fn delta(program: &str) -> i64 {
    let output = Command::new(program)
        .args(["-noshell", "-eval", &SCRIPT.replace('\n', " ")])
        .output()
        .unwrap_or_else(|error| panic!("run {program}: {error}"));
    assert!(output.status.success(), "{program}: {output:?}");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("{program} printed {output:?}"))
}

#[test]
fn hundred_spawn_ports_hold_as_many_fds_as_in_erl() {
    let expected = delta("erl");
    let actual = delta(env!("CARGO_BIN_EXE_arinsal"));
    assert_eq!(actual, expected, "descriptors held by 100 live spawn ports");
}

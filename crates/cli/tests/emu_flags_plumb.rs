//! `+Bi`, `+pad` and `+zdntgc` against the installed OTP 29.1.1 emulator.

use similar_asserts::assert_eq;
use std::process::{Command, Output, Stdio};

const PROBE: &str = "\
Self = self(), \
Child = spawn(fun() -> Self ! {child, process_flag(async_dist, false)} end), \
Opt = spawn_opt(fun() -> Self ! {opt, process_flag(async_dist, false)} end, [{async_dist, true}]), \
Info = spawn(fun() -> receive stop -> ok end end), \
Rcv = fun(Tag) -> receive {Tag, V} -> V after 5000 -> timeout end end, \
io:format(\"~p~n\", [[{break_ignored, erlang:system_info(break_ignored)}, \
  {async_dist, erlang:system_info(async_dist)}, \
  {dntgc, erlang:system_info(delayed_node_table_gc)}, \
  {self_flag, process_flag(async_dist, false)}, \
  {child_info, process_info(Info, async_dist)}, \
  {child_flag, Rcv(child)}, {spawn_opt_flag, Rcv(opt)}, \
  {self_info, process_info(self(), async_dist)}]]), \
Child =/= Opt, halt().";

fn reference(flags: &[&str]) -> Option<Output> {
    let mut command = arinsal_difftest::reference::erl()?;
    Some(run(&mut command, flags))
}

fn arinsal(flags: &[&str]) -> Output {
    let mut command = Command::new("timeout");
    command.arg("30").arg(env!("CARGO_BIN_EXE_arinsal"));
    run(&mut command, flags)
}

fn run(command: &mut Command, flags: &[&str]) -> Output {
    command
        .args(flags)
        .args(["-noshell", "-eval", PROBE])
        .env("ERL_AFLAGS", "")
        .env("ERL_FLAGS", "")
        .env("ERL_ZFLAGS", "")
        .env("ERL_CRASH_DUMP", "/dev/null")
        .output()
        .expect("run emulator")
}

#[test]
fn flags_reach_system_info_and_spawned_processes() {
    if arinsal_difftest::reference::erl().is_none() {
        eprintln!("erl unavailable; skipping emulator flag differential");
        return;
    }
    for flags in [
        vec![],
        vec!["+Bi"],
        vec!["+B", "i"],
        vec!["+pad", "true"],
        vec!["+pad", "false"],
        vec!["+zdntgc", "0"],
        vec!["+zdntgc", "infinity"],
        vec!["+zdntgc", "1500"],
        vec!["+Bi", "+pad", "true", "+zdntgc", "7"],
    ] {
        let expected = reference(&flags).unwrap();
        let actual = arinsal(&flags);
        assert!(actual.status.success(), "{flags:?}: {actual:?}");
        assert_eq!(
            String::from_utf8_lossy(&actual.stdout),
            String::from_utf8_lossy(&expected.stdout),
            "{flags:?}"
        );
    }
}

#[test]
fn invalid_values_are_diagnosed_as_erts_does() {
    if arinsal_difftest::reference::erl().is_none() {
        eprintln!("erl unavailable; skipping emulator flag differential");
        return;
    }
    for flags in [
        ["+pad", "maybe"],
        ["+zdntgc", "-1"],
        ["+zdntgc", "abc"],
        ["+zdntgc", "100000001"],
    ] {
        let expected = reference(&flags).unwrap();
        let actual = arinsal(&flags);
        assert_eq!(actual.status.code(), expected.status.code(), "{flags:?}");
        let first_line = |output: &Output| {
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned()
        };
        assert_eq!(first_line(&actual), first_line(&expected), "{flags:?}");
    }
}

/// With `+Bi` SIGINT, SIGQUIT and SIGTSTP are ignored: the emulator survives them and halts
/// normally.
#[test]
fn ignore_break_survives_terminal_signals() {
    let Some(mut reference) = arinsal_difftest::reference::erl() else {
        eprintln!("erl unavailable; skipping emulator flag differential");
        return;
    };
    let eval = "timer:sleep(2500), halt().";
    let mut arinsal = Command::new("timeout");
    arinsal.arg("30").arg(env!("CARGO_BIN_EXE_arinsal"));
    for command in [&mut reference, &mut arinsal] {
        command
            .args(["+Bi", "-noshell", "-eval", eval])
            .env("ERL_AFLAGS", "")
            .env("ERL_FLAGS", "")
            .env("ERL_ZFLAGS", "")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }
    for (name, command) in [("erl", &mut reference), ("arinsal", &mut arinsal)] {
        let mut child = command.spawn().expect("spawn emulator");
        // `timeout` forwards signals to its child; erlexec execs the emulator in place.
        std::thread::sleep(std::time::Duration::from_millis(1500));
        for signal in ["-INT", "-QUIT"] {
            Command::new("kill")
                .args([signal, &child.id().to_string()])
                .status()
                .expect("kill");
        }
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(0), "{name}");
    }
}

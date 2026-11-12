use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn handler_dir() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = std::env::temp_dir().join(format!("arinsal-os-signals-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = root.join("crates/vm/tests/process/signal_test_handler.erl");
    let status = Command::new("timeout")
        .args(["60", "erlc", "-o"])
        .arg(&dir)
        .arg(source)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .expect("run timeout erlc");
    assert!(status.success(), "erlc failed: {status}");
    dir
}

fn run_node(
    binary: &Path,
    module_dir: &Path,
    signal: &str,
    signal_lower: &str,
    action: &str,
) -> Option<i32> {
    let expression = match action {
        "handle" => format!(
            "catch gen_event:delete_handler(erl_signal_server,erl_signal_handler,ok),\
             ok=gen_event:add_handler(erl_signal_server,signal_test_handler,self()),\
             ok=os:set_signal(sig{signal_lower},handle),\
             open_port({{spawn_executable,\"/bin/kill\"}},[{{args,[\"-{signal}\",os:getpid()]}},exit_status]),\
             receive {{signal_event,sig{signal_lower}}}->erlang:halt(0) after 3000->erlang:halt(2) end"
        ),
        "ignore" => format!(
            "catch gen_event:delete_handler(erl_signal_server,erl_signal_handler,ok),\
             ok=gen_event:add_handler(erl_signal_server,signal_test_handler,self()),\
             ok=os:set_signal(sig{signal_lower},ignore),\
             open_port({{spawn_executable,\"/bin/kill\"}},[{{args,[\"-{signal}\",os:getpid()]}},exit_status]),\
             receive {{signal_event,sig{signal_lower}}}->erlang:halt(3) after 100->erlang:halt(0) end"
        ),
        "default" => format!(
            "ok=os:set_signal(sig{signal_lower},default),\
             open_port({{spawn_executable,\"/bin/kill\"}},[{{args,[\"-{signal}\",os:getpid()]}},exit_status]),\
             receive after 3000->erlang:halt(4) end"
        ),
        _ => unreachable!(),
    };
    let mut command = Command::new("timeout");
    command
        .args(["--preserve-status", "-k", "2", "8"])
        .arg(binary)
        .args(["-noshell", "-pa"])
        .arg(module_dir)
        .args(["-eval", &expression])
        .env_remove("ERL_ROOTDIR")
        .env_remove("ARINSAL_OTP_ROOT")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.status().expect("run timeout node").code()
}

#[test]
fn os_set_signal_dispositions_match_erts() {
    let dir = handler_dir();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let arinsal = root.join("target/release/arinsal");
    assert!(arinsal.is_file(), "build target/release/arinsal first");
    for (signal, signal_lower, action) in [
        ("USR1", "usr1", "handle"),
        ("USR1", "usr1", "ignore"),
        ("USR1", "usr1", "default"),
        ("TERM", "term", "handle"),
        ("TERM", "term", "ignore"),
        ("TERM", "term", "default"),
    ] {
        let reference = run_node(Path::new("erl"), &dir, signal, signal_lower, action);
        let actual = run_node(&arinsal, &dir, signal, signal_lower, action);
        similar_asserts::assert_eq!(reference, actual, "SIG{signal} {action}");
        if action == "handle" {
            assert_eq!(
                actual,
                Some(0),
                "SIG{signal} handle event reaches gen_event"
            );
        }
        if action == "ignore" {
            assert_eq!(actual, Some(0), "SIG{signal} ignore leaves node running");
        }
    }
}

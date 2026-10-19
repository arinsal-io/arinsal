//! Port task scheduling (erl_port_task.c) against erl 29.1.1: busy port suspension,
//! nosuspend sends and commands, the busy queue with signal order dependencies, port
//! exit resuming suspended senders, and the busy port message queue.
//! Fixtures: crates/drv/tests/fixtures/{sched_drv.c,port_tasks.erl}.

use std::path::{Path, PathBuf};
use std::process::Command;

use arinsal_difftest::{CallOptions, CallResult, RefErl, pretty};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../drv/tests/fixtures")
}

fn otp_include() -> PathBuf {
    let output = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s/usr/include\",[code:root_dir()]),halt().",
        ])
        .output()
        .expect("erl on PATH");
    assert!(output.status.success());
    PathBuf::from(String::from_utf8(output.stdout).unwrap())
}

fn compile_driver(dir: &Path, name: &str) {
    let status = Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            #[cfg(target_os = "macos")]
            "-undefined",
            #[cfg(target_os = "macos")]
            "dynamic_lookup",
            "-I",
        ])
        .arg(otp_include())
        .arg(fixtures().join(format!("{name}.c")))
        .arg("-o")
        .arg(dir.join(format!("{name}.so")))
        .status()
        .expect("cc");
    assert!(status.success(), "compile {name}.so");
}

#[test]
fn port_tasks_match_erl() {
    let dir = std::env::temp_dir().join(format!("arinsal-port-tasks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    compile_driver(&dir, "sched_drv");

    let erl = RefErl::start().expect("erl reference node");
    let source = std::fs::read_to_string(fixtures().join("port_tasks.erl")).unwrap();
    let beam = erl
        .compile_named("port_tasks", &source, &[])
        .unwrap_or_else(|error| panic!("compile port_tasks: {error}"));
    std::fs::write(dir.join("port_tasks.beam"), &beam).unwrap();
    erl.load("port_tasks", &beam).unwrap();
    let main = format!(
        "-module(port_tasks_main).\n-export([run/0]).\nrun() -> port_tasks:run({:?}).\n",
        dir.to_str().unwrap()
    );
    let main_beam = erl
        .compile_named("port_tasks_main", &main, &[])
        .unwrap_or_else(|error| panic!("compile port_tasks_main: {error}"));
    std::fs::write(dir.join("port_tasks_main.beam"), &main_beam).unwrap();
    erl.load("port_tasks_main", &main_beam).unwrap();
    let options = CallOptions {
        timeout_ms: Some(60_000),
        ..CallOptions::default()
    };
    let expected = match erl
        .call_opts("port_tasks_main", "run", &[], &options)
        .result
    {
        CallResult::Ok(term) => term,
        other => panic!("port_tasks:run/1 on erl: {other:?}"),
    };
    drop(erl);

    let mut vm = Vm::new([dir.clone()]);
    let actual = match vm.eval_scheduled("port_tasks_main", "run", &[], 4, None) {
        Ok(result) => result.term,
        Err(error) => panic!("port_tasks:run/1 on Arinsal: {error}"),
    };
    let _ = std::fs::remove_dir_all(&dir);
    let sorted = |term: &OwnedTerm| match term {
        OwnedTerm::Map(entries) => {
            let mut entries = entries.clone();
            entries.sort_by(|a, b| arinsal_etf::erl_cmp(&a.0, &b.0));
            OwnedTerm::Map(entries)
        }
        other => other.clone(),
    };
    let (actual, expected) = (sorted(&actual), sorted(&expected));
    assert_eq!(
        actual,
        expected,
        "\nexpected {}\nactual   {}",
        pretty(&expected),
        pretty(&actual)
    );
}

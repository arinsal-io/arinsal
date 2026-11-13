//! A node's process exit halts scheduler threads and the forker (`erl_child_setup`) with its
//! reader thread. A node has one runtime for the life of the OS process, so repeated evaluations
//! reuse that node.

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};

#[allow(dead_code)]
#[path = "common/mod.rs"]
mod common;

const MODULE: &str = "vm_teardown";
const SOURCE: &str = r#"-module(vm_teardown).
-export([run/1]).
run(N) -> lists:sum([X * 2 || X <- lists:seq(1, N)]).
"#;

fn beam() -> Option<Vec<u8>> {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping vm teardown test");
        return None;
    };
    Some(
        reference
            .compile_named(MODULE, SOURCE, &[])
            .expect("compile"),
    )
}

fn run(vm: &mut arinsal_vm::Vm) -> OwnedTerm {
    let arg = Term::small(1000).unwrap();
    vm.eval_scheduled(MODULE, "run", &[arg], 2)
        .expect("run")
        .term
}

fn total_memory(vm: &mut arinsal_vm::Vm) -> i64 {
    let total = Term::atom(global_atoms().intern("total").unwrap());
    match vm
        .eval_scheduled("erlang", "memory", &[total], 1)
        .expect("read total memory")
        .term
    {
        OwnedTerm::Int(bytes) => bytes,
        other => panic!("total memory is not an integer: {other:?}"),
    }
}

#[test]
fn node_process_exit_stops_forker_and_scheduler_threads() {
    const CHILD: &str = "ARINSAL_VM_TEARDOWN_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let beam = beam().expect("compile teardown module");
        let mut vm = common::node();
        common::load_fresh(&mut vm, &beam);
        let _ = run(&mut vm);
        arinsal_vm::erts_exit(0);
    }

    let output = std::process::Command::new("timeout")
        .args(["120", std::env::current_exe().unwrap().to_str().unwrap()])
        .args([
            "--exact",
            "node_process_exit_stops_forker_and_scheduler_threads",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .expect("start isolated node process");
    assert!(
        output.status.success(),
        "isolated node exited {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn one_node_serves_repeated_evaluations() {
    let Some(beam) = beam() else { return };
    let mut vm = common::node();
    common::load_fresh(&mut vm, &beam);
    let _ = run(&mut vm);
    let memory_after_first = total_memory(&mut vm);
    let expected = 1_001_000;
    for _ in 0..10 {
        similar_asserts::assert_eq!(run(&mut vm), OwnedTerm::Int(expected));
        let memory = total_memory(&mut vm);
        assert!(
            memory < memory_after_first + 4 * 1024 * 1024,
            "total memory grew: {memory} vs {memory_after_first} bytes"
        );
    }
}

//! Trapped gc_bifs write their results to their encoded destination registers.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_term::global_atoms;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;
use std::process::Command;

const CHILD: &str = "ARINSAL_INTERP_LEN_TRAP_CHILD";
const MODULE: &str = "interp_len_trap";
const SOURCE: &str = r#"-module(interp_len_trap).
-export([run/0]).
run() ->
    Seen = lists:duplicate(200000, item),
    Big = lists:duplicate(200000, $x),
    {done, 7, length(Seen), erlang:iolist_size(Big)}.
"#;

#[test]
fn trapping_gc_bifs_preserve_destinations() {
    if let Some((path, mode)) = std::env::var_os(CHILD).and_then(|path| {
        let mode = std::env::var("ARINSAL_INTERP_LEN_TRAP_MODE").ok()?;
        Some((path, mode))
    }) {
        let mut vm = Vm::new([]);
        vm.load_bytes(&std::fs::read(path).unwrap()).unwrap();
        let actual = vm.eval_scheduled(MODULE, "run", &[], 2, None).unwrap();
        println!("RESULT:{mode}:{:?}", actual.term);
        let _ = global_atoms();
        return;
    }

    let reference = RefErl::start().expect("erl reference");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile module");
    reference.load(MODULE, &beam).expect("load module");
    let want = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => term,
        other => panic!("reference call failed: {other:?}"),
    };
    let dir = std::env::temp_dir().join(format!("arinsal-len-trap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&path, beam).unwrap();
    for (mode, env) in [
        ("interp", ("ARINSAL_INTERP", "1")),
        ("jit", ("ARINSAL_BEAMASM", "1")),
    ] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "trapping_gc_bifs_preserve_destinations",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, &path)
            .env("ARINSAL_INTERP_LEN_TRAP_MODE", mode)
            .env(env.0, env.1)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{mode} child failed: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let marker = format!("RESULT:{mode}:");
        let start = stdout.find(&marker).unwrap() + marker.len();
        assert_eq!(
            &stdout[start..].split_terminator('\n').next().unwrap(),
            &format!("{want:?}"),
            "{mode}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

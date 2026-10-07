//! Every spawned process enters native code at its first function (erl_create_process sets I to
//! the export's native address); the interpreter is entered only where no native code exists.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use std::process::Command;

const CHILD: &str = "ARINSAL_JIT_SPAWN_CHILD";
const MODULE: &str = "jit_spawn_test";

const SOURCE: &str = r#"-module(jit_spawn_test).
-export([run/0, three/2, loop/1, hib/1, hib2/1]).

three(Parent, N) -> two(Parent, N + 1).
two(Parent, N) -> one(Parent, N + 1).
one(Parent, N) -> Parent ! {done, N}.

loop(Parent) -> receive stop -> Parent ! {done, loop} end.

hib(Parent) -> erlang:hibernate(jit_spawn_test, hib2, [Parent]).
hib2(Parent) -> Parent ! {done, hib}.

wait(0, Acc) -> lists:sort(Acc);
wait(N, Acc) -> receive {done, V} -> wait(N - 1, [V | Acc]) after 5000 -> {timeout, Acc} end.

run() ->
    Self = self(),
    spawn(jit_spawn_test, three, [Self, 0]),
    spawn_link(jit_spawn_test, three, [Self, 10]),
    spawn_opt(jit_spawn_test, three, [Self, 20], [{min_heap_size, 1000}]),
    spawn(fun() -> three(Self, 30) end),
    spawn(fun() -> three(Self, 40) end),
    erlang:spawn_request(jit_spawn_test, three, [Self, 50], []),
    erlang:apply(erlang, spawn, [jit_spawn_test, three, [Self, 60]]),
    {_, Ref} = spawn_monitor(jit_spawn_test, three, [Self, 70]),
    receive {'DOWN', Ref, _, _, _} -> ok end,
    Pid = spawn(jit_spawn_test, loop, [Self]),
    Pid ! stop,
    Hib = spawn(jit_spawn_test, hib, [Self]),
    timer:sleep(50),
    Hib ! wake,
    wait(10, []).
"#;

fn child() -> bool {
    let Some(beam_path) = std::env::var_os(CHILD) else {
        return false;
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&std::fs::read(beam_path).unwrap()).unwrap();
    let before = arinsal_vm::interp_native_starts();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 2, None).unwrap();
    println!("RESULT:{}", actual.text);
    println!("STARTS:{}", arinsal_vm::interp_native_starts() - before);
    true
}

#[test]
#[cfg(target_arch = "aarch64")]
fn spawned_processes_start_in_native_code() {
    if child() {
        return;
    }
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let dir = std::env::temp_dir().join(format!("arinsal-jit-spawn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{MODULE}.beam"));
    std::fs::write(&path, beam).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "spawned_processes_start_in_native_code",
            "--nocapture",
        ])
        .env(CHILD, &path)
        .env_remove("ARINSAL_INTERP")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "child failed: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let field = |key: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap_or_else(|| panic!("missing {key} in {stdout}"))
            .to_owned()
    };
    let expected = match reference.call(MODULE, "run", &[]) {
        CallResult::Ok(term) => format!("{term}"),
        other => panic!("OTP call failed: {other:?}"),
    };
    assert_eq!(field("RESULT:"), expected);
    assert_eq!(
        field("STARTS:"),
        "0",
        "an interpreter slice began at a native function entry"
    );
    let _ = std::fs::remove_dir_all(dir);
}

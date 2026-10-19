use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MODULE: &str = "port_exit_demonitor_race_diff";
const DRIVER: &str = "port_exit_race_drv";
const SOURCE: &str = r#"
-module(port_exit_demonitor_race_diff).
-export([run/0]).

run() ->
    ok = erl_ddll:load_driver("{driver_dir}", "port_exit_race_drv"),
    process_flag(scheduler, 1),
    repeat(1000).

repeat(0) -> ok;
repeat(N) ->
    Parent = self(),
    Schedulers = erlang:system_info(schedulers_online),
    {OwnerScheduler, SenderSchedulers} = scheduler_plan(Schedulers),
    {Owner, OwnerRef} = spawn_opt(fun() ->
        Port = open_port({spawn_driver, "port_exit_race_drv"}, []),
        Port ! {self(), {command, "hej"}},
        receive {Port, {data, "hej"}} -> ok after 5000 -> exit(echo_timeout) end,
        Parent ! {prepared, self(), Port},
        receive {go, Parent} -> ok end,
        Port ! {self(), close}
    end, [link, monitor, {scheduler, OwnerScheduler}]),
    Port = receive {prepared, Owner, OpenPort} -> OpenPort
           after 5000 -> exit(open_timeout) end,
    Senders = [spawn_opt(fun() ->
        KeepRef = monitor(port, Port),
        DropRef = monitor(port, Port),
        Parent ! {prepared, self()},
        receive {go, Parent} -> true = demonitor(DropRef, [flush]) end,
        receive {'DOWN', KeepRef, port, Port, _} -> ok
        after 5000 -> exit(missing_down) end,
        receive {bye, Parent} -> ok end,
        receive Msg -> exit({unexpected_message, Msg}) after 0 -> ok end
    end, [link, monitor, {scheduler, Scheduler}]) || Scheduler <- SenderSchedulers],
    lists:foreach(fun({Pid, _Ref}) ->
        receive {prepared, Pid} -> ok after 5000 -> exit(prepare_timeout) end
    end, Senders),
    Owner ! {go, Parent},
    lists:foreach(fun({Pid, _Ref}) -> Pid ! {go, Parent} end, Senders),
    receive {'DOWN', OwnerRef, process, Owner, normal} -> ok
    after 5000 -> exit(owner_timeout) end,
    lists:foreach(fun({Pid, _Ref}) -> Pid ! {bye, Parent} end, Senders),
    lists:foreach(fun({Pid, Ref}) ->
        receive {'DOWN', Ref, process, Pid, normal} -> ok;
                {'DOWN', Ref, process, Pid, Reason} -> exit({sender_failed, Reason})
        after 5000 -> exit(sender_timeout) end
    end, Senders),
    repeat(N - 1).

scheduler_plan(1) -> {1, [1]};
scheduler_plan(2) -> {2, [1]};
scheduler_plan(3) -> {2, [3]};
scheduler_plan(N) -> {2, lists:seq(3, N)}.
"#;

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "arinsal-port-exit-race-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create driver scratch directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn otp_root() -> PathBuf {
    let output = Command::new("timeout")
        .args([
            "30",
            "erl",
            "-noshell",
            "-eval",
            "io:format(\"~s\",[code:root_dir()]),halt().",
        ])
        .output()
        .expect("run OTP to locate erl_driver.h");
    assert!(
        output.status.success(),
        "OTP root query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(String::from_utf8(output.stdout).expect("OTP path is UTF-8"))
}

fn compile_driver(directory: &Path, root: &Path) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/port_exit_race_drv.c");
    let library = directory.join(format!("{DRIVER}.so"));
    let mut command = Command::new("timeout");
    command.args(["60", "cc"]);
    #[cfg(target_os = "macos")]
    command.args(["-bundle", "-undefined", "dynamic_lookup", "-fPIC"]);
    #[cfg(not(target_os = "macos"))]
    command.args(["-shared", "-fPIC"]);
    let output = command
        .arg("-I")
        .arg(root.join("usr/include"))
        .arg("-o")
        .arg(&library)
        .arg(source)
        .output()
        .expect("compile the test driver");
    assert!(
        output.status.success(),
        "driver compile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    library
}

#[test]
fn demonitor_flush_drops_a_racing_dynamic_port_down() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping demonitor_flush_drops_a_racing_dynamic_port_down");
        return;
    };
    let scratch = ScratchDir::new();
    let root = otp_root();
    let _driver = compile_driver(scratch.path(), &root);
    let driver_dir = scratch.path().to_str().expect("scratch path is UTF-8");
    assert!(driver_dir.is_ascii() && !driver_dir.contains('"'));
    let source = SOURCE.replace("{driver_dir}", driver_dir);
    let beam = reference.compile_named(MODULE, &source, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();

    let CallResult::Ok(expected) = reference.call(MODULE, "run", &[]) else {
        panic!("OTP port monitor race failed");
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 10, None).unwrap();
    assert_eq!(expected, actual.term);
}

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct PidGuard(u32);

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-9", &self.0.to_string()])
            .status();
    }
}

fn temp_file(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "arinsal-peer-orphan-{}-{label}-{stamp}",
        std::process::id()
    ))
}

fn wait_for_pid_file(path: &Path) -> (u32, u32) {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(contents) = fs::read_to_string(path) {
            let values: Vec<_> = contents
                .lines()
                .filter_map(|line| line.parse::<u32>().ok())
                .collect();
            if values.len() >= 2 {
                return (values[0], values[1]);
            }
        }
        assert!(
            Instant::now() < deadline,
            "peer parent did not start: {path:?}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn kill_exact(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .expect("run kill for a pid started by this test");
    assert!(status.success(), "could not send {signal} to pid {pid}");
}

fn pid_exists(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_for_exit(pid: u32, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if !pid_exists(pid) {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    !pid_exists(pid)
}

fn erl_path() -> String {
    let output = Command::new("timeout")
        .args([
            "10",
            "erl",
            "-noshell",
            "-eval",
            "io:format(\"~s\",[code:root_dir()]),halt().",
        ])
        .output()
        .expect("find OTP root through erl");
    assert!(output.status.success());
    format!(
        "{}/bin/erl",
        String::from_utf8(output.stdout).expect("OTP root is UTF-8")
    )
}

fn start_peer_parent(executable: &str, label: &str, standard_io: bool) -> (Child, PathBuf) {
    let path = temp_file(label);
    let path_string = path.to_string_lossy();
    let connection = if standard_io {
        ",connection=>standard_io"
    } else {
        ""
    };
    let eval = format!(
        "file:write_file(\"{path_string}\",[os:getpid(),\"\\n\"]), \
         {{ok,_Peer,Node}}=peer:start(#{{name=>peer_orphan_{label},host=>\"127.0.0.1\",longnames=>true,args=>[\"-kernel\",\"inet_dist_use_interface\",\"{{127,0,0,1}}\"]{connection}}}), \
         file:write_file(\"{path_string}\",[rpc:call(Node,os,getpid,[]),\"\\n\"],[append]), timer:sleep(infinity)."
    );
    let parent_name = format!("peer_orphan_parent_{}@127.0.0.1", label);
    let child = Command::new("timeout")
        .args([
            "60",
            executable,
            "-noshell",
            "-name",
            &parent_name,
            "-kernel",
            "inet_dist_use_interface",
            "{127,0,0,1}",
            "-eval",
            &eval,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start peer parent under timeout");
    (child, path)
}

fn parent_loss_exits_peer(executable: &str, label: &str, standard_io: bool) {
    let (mut parent, path) = start_peer_parent(executable, label, standard_io);
    let (parent_pid, child_pid) = wait_for_pid_file(&path);
    let _child_guard = PidGuard(child_pid);
    kill_exact(parent_pid, "-9");
    assert!(
        wait_for_exit(child_pid, Duration::from_secs(8)),
        "{label} peer pid {child_pid} survived origin pid {parent_pid}"
    );
    let status = parent.wait().expect("reap peer parent");
    assert!(!status.success(), "origin parent was not killed");
    let _ = fs::remove_file(path);
}

#[test]
fn origin_process_monitor_stops_distributed_peer_after_sigkill() {
    parent_loss_exits_peer(env!("CARGO_BIN_EXE_arinsal"), "arinsal_dist", false);
    parent_loss_exits_peer(&erl_path(), "erl_dist", false);
}

#[test]
fn standard_io_eof_stops_peer_after_sigkill() {
    parent_loss_exits_peer(env!("CARGO_BIN_EXE_arinsal"), "arinsal_stdio", true);
    parent_loss_exits_peer(&erl_path(), "erl_stdio", true);
}

fn detached_sigterm_stops_node(executable: &str, label: &str) {
    let path = temp_file(label);
    let eval = format!(
        "file:write_file(\"{}\",os:getpid()), timer:sleep(infinity).",
        path.to_string_lossy()
    );
    let output = Command::new("timeout")
        .args([
            "30",
            executable,
            "-detached",
            "-noshell",
            "-name",
            &format!("{label}_{}@127.0.0.1", std::process::id()),
            "-kernel",
            "inet_dist_use_interface",
            "{127,0,0,1}",
            "-eval",
            &eval,
        ])
        .output()
        .expect("start detached node under timeout");
    assert!(output.status.success());
    let deadline = Instant::now() + Duration::from_secs(15);
    let pid = loop {
        if let Ok(value) = fs::read_to_string(&path)
            && let Ok(pid) = value.parse::<u32>()
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "detached node did not start");
        thread::sleep(Duration::from_millis(50));
    };
    let _guard = PidGuard(pid);
    kill_exact(pid, "-TERM");
    assert!(
        wait_for_exit(pid, Duration::from_secs(8)),
        "detached node pid {pid} did not stop after SIGTERM"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn detached_node_sigterm_matches_erts() {
    detached_sigterm_stops_node(env!("CARGO_BIN_EXE_arinsal"), "arinsal_detached_term");
    detached_sigterm_stops_node(&erl_path(), "erl_detached_term");
}

use similar_asserts::assert_eq;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("erl-call-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl ChildGuard {
    fn halt_on_stdin_eof(&mut self) {
        drop(self.0.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "reference node did not halt on stdin EOF");
                return;
            }
            if Instant::now() >= deadline {
                let _ = self.0.kill();
                let _ = self.0.wait();
                panic!("reference node did not halt on stdin EOF");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct ReferenceNode {
    child: ChildGuard,
    name: String,
    port: u16,
}

struct LoopbackEpmd {
    _child: ChildGuard,
    port: u16,
    preload: OsString,
    preload_variable: &'static str,
}

impl LoopbackEpmd {
    fn new(directory: &Path) -> Self {
        let (preload_variable, preload) = loopback_hostname_preload(directory);
        let port = free_port();
        let mut command = Command::new(reference_binary("epmd"));
        command
            .args(["-address", "127.0.0.1", "-port"])
            .arg(port.to_string())
            .env(preload_variable, &preload)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().unwrap();
        let epmd = Self {
            _child: ChildGuard(child),
            port,
            preload,
            preload_variable,
        };
        epmd.wait_ready();
        epmd
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = Command::new(reference_binary("epmd"))
                .args(["-port", &self.port.to_string(), "-names"])
                .env("ERL_EPMD_PORT", self.port.to_string())
                .env(self.preload_variable, &self.preload)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if status.is_ok_and(|status| status.success()) {
                return;
            }
            assert!(Instant::now() < deadline, "loopback epmd did not start");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn envs(&self) -> [(&'static str, OsString); 2] {
        [
            ("ERL_EPMD_PORT", self.port.to_string().into()),
            (self.preload_variable, self.preload.clone()),
        ]
    }
}

impl ReferenceNode {
    fn start(epmd: &LoopbackEpmd, directory: &Path, suffix: &str) -> Self {
        let name = format!("erl_call_{suffix}_{}", std::process::id());
        let ready_file = std::env::temp_dir().join(format!("{name}.ready"));
        let _ = fs::remove_file(&ready_file);
        let eval = format!(
            "file:write_file(\"{}\", <<\"ready\">>), Port=open_port({{fd,0,1}},[eof]), receive {{Port,eof}}->halt() end.",
            ready_file.display()
        );
        let mut command = Command::new(reference_binary("erl"));
        command
            .current_dir(directory)
            .args([
                "-noshell",
                "-sname",
                &name,
                "-setcookie",
                "erl_call_test_cookie",
                "-kernel",
                "inet_dist_use_interface",
                "{127,0,0,1}",
                "-eval",
                &eval,
            ])
            .env("ERL_EPMD_PORT", epmd.port.to_string())
            .env(epmd.preload_variable, &epmd.preload)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().unwrap();
        let mut node = Self {
            child: ChildGuard(child),
            name,
            port: 0,
        };
        node.wait_ready(&ready_file, epmd);
        let _ = fs::remove_file(&ready_file);
        let port = epmd_node_port(epmd, &node.name);
        Self { port, ..node }
    }

    fn wait_ready(&mut self, ready_file: &Path, epmd: &LoopbackEpmd) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if ready_file.is_file() && epmd_node_port_option(epmd, &self.name).is_some() {
                return;
            }
            if self.child.0.try_wait().unwrap().is_some() {
                panic!("reference Erlang node exited during startup");
            }
            assert!(
                Instant::now() < deadline,
                "reference Erlang node did not start"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn halt(&mut self) {
        self.child.halt_on_stdin_eof();
    }
}

fn loopback_hostname_preload(directory: &Path) -> (&'static str, OsString) {
    let library = directory.join(if cfg!(target_os = "macos") {
        "libloopback_hostname.dylib"
    } else {
        "libloopback_hostname.so"
    });
    let mut compiler = Command::new("cc");
    compiler.arg(if cfg!(target_os = "macos") {
        "-dynamiclib"
    } else {
        "-shared"
    });
    let compiler = compiler
        .arg("-fPIC")
        .arg("-o")
        .arg(&library)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/loopback_hostname.c"));
    if !cfg!(target_os = "macos") {
        compiler.arg("-ldl");
    }
    assert!(compiler.status().unwrap().success());
    let variable = if cfg!(target_os = "macos") {
        "DYLD_INSERT_LIBRARIES"
    } else {
        "LD_PRELOAD"
    };
    (variable, library.into_os_string())
}

fn reference_root() -> PathBuf {
    arinsal_difftest::reference::otp_root()
        .expect("reference OTP is required; set ARINSAL_OTP_ROOT or put erl on PATH")
}

fn reference_binary(name: &str) -> PathBuf {
    reference_root()
        .join("erts-17.1/bin")
        .join(arinsal_difftest::reference::program(name))
}

fn reference_erl_call() -> PathBuf {
    let root = reference_root().join("lib");
    fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| {
            entry
                .path()
                .join("bin")
                .join(arinsal_difftest::reference::program("erl_call"))
        })
        .find(|path| path.is_file())
        .expect("OTP-29.1.1 erl_call executable missing")
}

fn free_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.local_addr().unwrap().port()
}

fn epmd_node_port_option(epmd: &LoopbackEpmd, node: &str) -> Option<u16> {
    let output = Command::new(reference_binary("epmd"))
        .args(["-port", &epmd.port.to_string(), "-names"])
        .env("ERL_EPMD_PORT", epmd.port.to_string())
        .env(epmd.preload_variable, &epmd.preload)
        .output()
        .ok()?;
    let listing = String::from_utf8_lossy(&output.stdout);
    listing.lines().find_map(|line| {
        let (name, port) = line.trim().strip_prefix("name ")?.split_once(" at port ")?;
        (name == node).then(|| port.parse().ok()).flatten()
    })
}

fn epmd_node_port(epmd: &LoopbackEpmd, node: &str) -> u16 {
    epmd_node_port_option(epmd, node).expect("node missing from loopback epmd")
}

fn wait_node_stopped(epmd: &LoopbackEpmd, node: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while epmd_node_port_option(epmd, node).is_some() {
        assert!(
            Instant::now() < deadline,
            "node remained registered after halt"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn run(executable: &Path, args: &[&OsStr], input: &[u8], epmd: &LoopbackEpmd) -> Output {
    run_with_home(executable, args, input, epmd, None)
}

fn run_with_home(
    executable: &Path,
    args: &[&OsStr],
    input: &[u8],
    epmd: &LoopbackEpmd,
    home: Option<&Path>,
) -> Output {
    let mut command = Command::new(executable);
    command
        .args(args)
        .env("ERL_EPMD_PORT", epmd.port.to_string())
        .env(epmd.preload_variable, &epmd.preload)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(home) = home {
        command.env("HOME", home);
    }
    for (key, value) in epmd.envs() {
        command.env(key, value);
    }
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn assert_same(label: &str, reference: Output, arinsal: Output) {
    assert_eq!(
        reference.status.code(),
        arinsal.status.code(),
        "{label}: reference stdout={:?}, stderr={:?}; Arinsal stdout={:?}, stderr={:?}",
        reference.stdout,
        reference.stderr,
        arinsal.stdout,
        arinsal.stderr
    );
    assert_eq!(
        String::from_utf8_lossy(&reference.stdout),
        String::from_utf8_lossy(&arinsal.stdout),
        "{label}: stdout"
    );
    assert_eq!(
        String::from_utf8_lossy(&reference.stderr),
        String::from_utf8_lossy(&arinsal.stderr),
        "{label}: stderr"
    );
}

fn cargs<'a>(args: &'a [&'a str]) -> Vec<&'a OsStr> {
    args.iter().map(OsStr::new).collect()
}

#[test]
fn erl_call_rpc_arguments_stdout_and_connection_failures_match_otp() {
    let temp = TempDir::new();
    let epmd = LoopbackEpmd::new(&temp.0);
    let mut node = ReferenceNode::start(&epmd, &temp.0, "rpc");
    let reference = reference_erl_call();
    let arinsal = Path::new(env!("CARGO_BIN_EXE_arinsal_erl_call"));
    let node_args = ["-sname", node.name.as_str(), "-c", "erl_call_test_cookie"];

    for (label, name_option) in [
        ("short_name", "-sname"),
        ("long_name_alias", "-n"),
        ("long_name", "-name"),
    ] {
        let invocation = [
            name_option,
            node.name.as_str(),
            "-c",
            "erl_call_test_cookie",
            "-a",
            "erlang node []",
        ];
        assert_same(
            label,
            run(&reference, &cargs(&invocation), b"", &epmd),
            run(arinsal, &cargs(&invocation), b"", &epmd),
        );
    }

    let hidden = [
        "-h",
        "erl_call_hidden_client",
        "-sname",
        node.name.as_str(),
        "-c",
        "erl_call_test_cookie",
        "-v",
        "-a",
        "erlang node []",
    ];
    assert_same(
        "hidden_name_verbose",
        run(&reference, &cargs(&hidden), b"", &epmd),
        run(arinsal, &cargs(&hidden), b"", &epmd),
    );

    let dynamic_name = [
        "-R",
        "-sname",
        node.name.as_str(),
        "-c",
        "erl_call_test_cookie",
        "-a",
        "erlang node []",
    ];
    assert_same(
        "dynamic_client_name",
        run(&reference, &cargs(&dynamic_name), b"", &epmd),
        run(arinsal, &cargs(&dynamic_name), b"", &epmd),
    );

    let mut apply = node_args.to_vec();
    apply.extend(["-a", "erlang length [[a,b,c]]"]);
    assert_same(
        "apply",
        run(&reference, &cargs(&apply), b"", &epmd),
        run(arinsal, &cargs(&apply), b"", &epmd),
    );

    let mut eval = node_args.to_vec();
    eval.push("-e");
    assert_same(
        "eval",
        run(
            &reference,
            &cargs(&eval),
            b"io:format(\"eval-output~n\"), 42.",
            &epmd,
        ),
        run(
            arinsal,
            &cargs(&eval),
            b"io:format(\"eval-output~n\"), 42.",
            &epmd,
        ),
    );

    let mut timed_eval = node_args.to_vec();
    timed_eval.extend(["-timeout", "1", "-e"]);
    assert_same(
        "timeout",
        run(
            &reference,
            &cargs(&timed_eval),
            b"timer:sleep(2000), 42.",
            &epmd,
        ),
        run(
            arinsal,
            &cargs(&timed_eval),
            b"timer:sleep(2000), 42.",
            &epmd,
        ),
    );

    let mut module = node_args.to_vec();
    module.push("-m");
    assert_same(
        "module",
        run(
            &reference,
            &cargs(&module),
            b"-module(erl_call_fixture).\n-export([value/0]).\nvalue() -> 29.\n",
            &epmd,
        ),
        run(
            arinsal,
            &cargs(&module),
            b"-module(erl_call_fixture).\n-export([value/0]).\nvalue() -> 29.\n",
            &epmd,
        ),
    );

    let mut no_result = node_args.to_vec();
    no_result.extend(["-no_result_term", "-a", "erlang length [[a,b,c]]"]);
    assert_same(
        "no_result_term",
        run(&reference, &cargs(&no_result), b"", &epmd),
        run(arinsal, &cargs(&no_result), b"", &epmd),
    );

    let mut fetch_stdout = node_args.to_vec();
    fetch_stdout.extend(["-fetch_stdout", "-a", "io format [\"fetch-output~n\"]"]);
    assert_same(
        "fetch_stdout",
        run(&reference, &cargs(&fetch_stdout), b"", &epmd),
        run(arinsal, &cargs(&fetch_stdout), b"", &epmd),
    );

    let address_value = format!("127.0.0.1:{}", node.port);
    let address = [
        "-address",
        address_value.as_str(),
        "-c",
        "erl_call_test_cookie",
        "-a",
        "erlang node []",
    ];
    assert_same(
        "address",
        run(&reference, &cargs(&address), b"", &epmd),
        run(arinsal, &cargs(&address), b"", &epmd),
    );
    let bad_node = [
        "-sname",
        "erl_call_absent_991",
        "-c",
        "erl_call_test_cookie",
        "-a",
        "erlang node []",
    ];
    assert_same(
        "bad_node",
        run(&reference, &cargs(&bad_node), b"", &epmd),
        run(arinsal, &cargs(&bad_node), b"", &epmd),
    );
    let mut bad_cookie = node_args.to_vec();
    bad_cookie.extend(["-c", "erl_call_bad_cookie", "-a", "erlang node []"]);
    assert_same(
        "bad_cookie",
        run(&reference, &cargs(&bad_cookie), b"", &epmd),
        run(arinsal, &cargs(&bad_cookie), b"", &epmd),
    );

    node.halt();
}

#[test]
fn erl_call_start_and_halt_match_otp() {
    let temp = TempDir::new();
    let epmd = LoopbackEpmd::new(&temp.0);
    let reference = reference_erl_call();
    let arinsal = Path::new(env!("CARGO_BIN_EXE_arinsal_erl_call"));
    let node_name = format!("erl_call_start_{}", std::process::id());
    let reference_home = temp.0.join("reference_home");
    let arinsal_home = temp.0.join("arinsal_home");
    let erl_script = reference_binary("erl");
    fs::create_dir(&reference_home).unwrap();
    fs::create_dir(&arinsal_home).unwrap();
    let mut started = StartedNodes {
        epmd: &epmd,
        names: vec![node_name.clone()],
    };

    let start_reference = [
        OsStr::new("-sname"),
        OsStr::new(&node_name),
        OsStr::new("-c"),
        OsStr::new("erl_call_test_cookie"),
        OsStr::new("-s"),
        OsStr::new("-d"),
        OsStr::new("-x"),
        erl_script.as_os_str(),
        OsStr::new("-no_result_term"),
        OsStr::new("-a"),
        OsStr::new("erlang node []"),
    ];
    let start_arinsal = [
        OsStr::new("-sname"),
        OsStr::new(&node_name),
        OsStr::new("-c"),
        OsStr::new("erl_call_test_cookie"),
        OsStr::new("-s"),
        OsStr::new("-d"),
        OsStr::new("-x"),
        erl_script.as_os_str(),
        OsStr::new("-no_result_term"),
        OsStr::new("-a"),
        OsStr::new("erlang node []"),
    ];
    let reference_output = run_with_home(
        &reference,
        &start_reference,
        b"",
        &epmd,
        Some(&reference_home),
    );
    let reference_halt = [
        OsStr::new("-sname"),
        OsStr::new(&node_name),
        OsStr::new("-c"),
        OsStr::new("erl_call_test_cookie"),
        OsStr::new("-q"),
    ];
    let reference_halt_output = run(&reference, &reference_halt, b"", &epmd);
    assert_eq!(reference_halt_output.status.code(), Some(0));
    wait_node_stopped(&epmd, &node_name);
    assert!(
        reference_home
            .join(format!(".erl_start.out.{node_name}"))
            .is_file()
    );
    let arinsal_halt = [
        OsStr::new("-sname"),
        OsStr::new(&node_name),
        OsStr::new("-c"),
        OsStr::new("erl_call_test_cookie"),
        OsStr::new("-q"),
    ];
    let arinsal_output = run_with_home(arinsal, &start_arinsal, b"", &epmd, Some(&arinsal_home));
    let arinsal_halt_output = run(arinsal, &arinsal_halt, b"", &epmd);
    assert!(
        arinsal_home
            .join(format!(".erl_start.out.{node_name}"))
            .is_file()
    );
    assert_same("start", reference_output, arinsal_output);
    assert_same("halt", reference_halt_output, arinsal_halt_output);
    started.names.clear();
}

struct StartedNodes<'a> {
    epmd: &'a LoopbackEpmd,
    names: Vec<String>,
}

impl Drop for StartedNodes<'_> {
    fn drop(&mut self) {
        let reference = reference_erl_call();
        let arinsal = Path::new(env!("CARGO_BIN_EXE_arinsal_erl_call"));
        for name in &self.names {
            for executable in [&reference, arinsal] {
                let args = [
                    OsStr::new("-sname"),
                    OsStr::new(name),
                    OsStr::new("-c"),
                    OsStr::new("erl_call_test_cookie"),
                    OsStr::new("-q"),
                ];
                let _ = run(executable, &args, b"", self.epmd);
            }
        }
    }
}

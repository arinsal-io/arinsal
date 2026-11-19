use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("erts-etc-{}-{id}", std::process::id()));
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

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl ChildGuard {
    fn halt_on_stdin_eof(&mut self) {
        drop(self.0.stdin.take());
        let status = self.0.wait().unwrap();
        assert!(status.success());
    }
}

fn fake_erl(directory: &Path) {
    let path = directory.join("erl");
    fs::write(
        &path,
        "#!/bin/sh\nfor arg in \"$@\"; do [ \"$arg\" = -detached ] && exit 0; done\nprintf 'ARGS:'\nfor arg in \"$@\"; do printf ' <%s>' \"$arg\"; done\nprintf '\\n'\nprintf 'ESCRIPT_NAME=<%s>\\n' \"${ESCRIPT_NAME-}\"\nprintf 'ERL_FLAGS=<%s>\\n' \"${ERL_FLAGS-}\"\nprintf 'ERLC_CONFIGURATION=<%s>\\n' \"${ERLC_CONFIGURATION-}\"\nprintf 'ERLC_USE_SERVER=<%s>\\n' \"${ERLC_USE_SERVER-}\"\n",
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
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
    let status = compiler.status().unwrap();
    assert!(status.success());
    let variable = if cfg!(target_os = "macos") {
        "DYLD_INSERT_LIBRARIES"
    } else {
        "LD_PRELOAD"
    };
    (variable, library.into_os_string())
}

fn reference_binary(name: &str) -> PathBuf {
    let mut roots = Vec::new();
    if let Some(root) = std::env::var_os("ARINSAL_OTP_ROOT") {
        roots.push(PathBuf::from(root));
    }
    if let Some(root) = std::env::var_os("ERL_ROOT") {
        roots.push(PathBuf::from(root));
    }
    if let Some(asdf) = std::env::var_os("ASDF_DIR") {
        roots.push(PathBuf::from(asdf).join("installs/erlang/29.1.1"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(PathBuf::from(home).join(".asdf/installs/erlang/29.1.1"));
    }
    roots.extend([
        PathBuf::from("$HOME/.asdf/installs/erlang/29.1.1"),
        PathBuf::from("/home/ubuntu/.asdf/installs/erlang/29.1.1"),
    ]);
    roots
        .into_iter()
        .map(|root| root.join("erts-17.1/bin").join(name))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("OTP-29.1.1 reference binary missing: {name}"))
}

fn differential(
    name: &str,
    arinsal: &str,
    args: &[&OsStr],
    envs: &[(&str, &OsStr)],
    unset: &[&str],
    home: Option<&Path>,
) -> (Output, Output) {
    let temp = TempDir::new();
    fake_erl(&temp.0);
    let launcher = temp.0.join(name);
    fs::copy(reference_binary(name), &launcher).unwrap();
    let reference = run(&launcher, args, envs, unset, home);
    fs::copy(arinsal, &launcher).unwrap();
    let arinsal = run(&launcher, args, envs, unset, home);
    (reference, arinsal)
}

fn run(
    launcher: &Path,
    args: &[&OsStr],
    envs: &[(&str, &OsStr)],
    unset: &[&str],
    home: Option<&Path>,
) -> Output {
    let mut command = Command::new(launcher);
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    for key in unset {
        command.env_remove(key);
    }
    if let Some(home) = home {
        command.env("HOME", home);
    }
    command.output().unwrap()
}

fn run_from(launcher: &Path, args: &[&OsStr], envs: &[(&str, &OsStr)], cwd: &Path) -> Output {
    let mut command = Command::new(launcher);
    command.args(args).current_dir(cwd);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn assert_same(reference: Output, arinsal: Output) {
    similar_asserts::assert_eq!(reference.status.code(), arinsal.status.code());
    similar_asserts::assert_eq!(
        String::from_utf8_lossy(&reference.stdout),
        String::from_utf8_lossy(&arinsal.stdout)
    );
    similar_asserts::assert_eq!(
        String::from_utf8_lossy(&reference.stderr),
        String::from_utf8_lossy(&arinsal.stderr)
    );
}

#[test]
fn ct_run_translates_modes_and_common_test_options() {
    let args = [
        OsStr::new("-name"),
        OsStr::new("ct@node"),
        OsStr::new("-vts"),
        OsStr::new("-browser"),
        OsStr::new("firefox"),
        OsStr::new("-config"),
        OsStr::new("ct.config"),
        OsStr::new("-decrypt_key"),
        OsStr::new("key"),
        OsStr::new("-decrypt_file"),
        OsStr::new("secret"),
        OsStr::new("-erl_args"),
        OsStr::new("+S"),
        OsStr::new("2:2"),
    ];
    let envs = [("ERL_FLAGS", OsStr::new("+A2 -Werror"))];
    let (reference, arinsal) = differential(
        "ct_run",
        env!("CARGO_BIN_EXE_arinsal_ct_run"),
        &args,
        &envs,
        &[],
        None,
    );
    assert_same(reference, arinsal);
}

#[test]
fn dialyzer_translates_emulator_options_and_shell_mode() {
    let args = [
        OsStr::new("-smp"),
        OsStr::new("+S"),
        OsStr::new("2:2"),
        OsStr::new("+P"),
        OsStr::new("4000"),
        OsStr::new("+sbt"),
        OsStr::new("db"),
        OsStr::new("--shell"),
        OsStr::new("--quiet"),
    ];
    let envs = [("ERL_FLAGS", OsStr::new("+A2 -Werror"))];
    let (reference, arinsal) = differential(
        "dialyzer",
        env!("CARGO_BIN_EXE_arinsal_dialyzer"),
        &args,
        &envs,
        &["DIALYZER_EMULATOR"],
        None,
    );
    assert_same(reference, arinsal);
}

#[test]
fn typer_translates_shell_mode() {
    let args = [
        OsStr::new("-smp"),
        OsStr::new("--shell"),
        OsStr::new("--verbose"),
    ];
    let envs = [("ERL_FLAGS", OsStr::new("+A2 -Werror"))];
    let (reference, arinsal) = differential(
        "typer",
        env!("CARGO_BIN_EXE_arinsal_typer"),
        &args,
        &envs,
        &[],
        None,
    );
    assert_same(reference, arinsal);
}

#[test]
fn escript_parses_interpreter_options_and_shebang_arguments() {
    let temp = TempDir::new();
    let script = temp.0.join("sample.escript");
    fs::write(
        &script,
        "#!/usr/bin/env escript\n%%! +S 2:2 -smp\nmain(_) -> ok.\n",
    )
    .unwrap();
    let args = [
        OsStr::new("-s"),
        OsStr::new("-c"),
        OsStr::new("-i"),
        OsStr::new("-d"),
        script.as_os_str(),
        OsStr::new("arg1"),
        OsStr::new("two words"),
    ];
    let envs = [("ERL_FLAGS", OsStr::new("+A2 -Werror"))];
    let (reference, arinsal) = differential(
        "escript",
        env!("CARGO_BIN_EXE_arinsal_escript"),
        &args,
        &envs,
        &["ESCRIPT_EMULATOR"],
        None,
    );
    assert_same(reference, arinsal);
}

#[test]
fn escript_emulator_override_is_used() {
    let temp = TempDir::new();
    fake_erl(&temp.0);
    let launcher = temp.0.join("escript");
    let script = temp.0.join("sample.escript");
    fs::copy(reference_binary("escript"), &launcher).unwrap();
    fs::write(&script, "#!/usr/bin/env escript\nmain(_) -> ok.\n").unwrap();
    let emulator = temp.0.join("erl").into_os_string();
    let args = [script.as_os_str(), OsStr::new("arg")];
    let envs = [
        ("ESCRIPT_EMULATOR", emulator.as_os_str()),
        ("ERL_FLAGS", OsStr::new("+A3")),
    ];
    let reference = run(&launcher, &args, &envs, &[], None);
    fs::copy(env!("CARGO_BIN_EXE_arinsal_escript"), &launcher).unwrap();
    let arinsal = run(&launcher, &args, &envs, &[], None);
    assert_same(reference, arinsal);
}

#[test]
fn typer_uses_path_when_there_is_no_sibling_erl() {
    let temp = TempDir::new();
    let launcher_dir = temp.0.join("launcher");
    let path_dir = temp.0.join("path");
    fs::create_dir(&launcher_dir).unwrap();
    fs::create_dir(&path_dir).unwrap();
    fake_erl(&path_dir);
    let launcher = launcher_dir.join("typer");
    fs::copy(reference_binary("typer"), &launcher).unwrap();
    let path = path_dir.as_os_str();
    let args = [OsStr::new("--shell"), OsStr::new("--verbose")];
    let envs = [("PATH", path), ("ERL_FLAGS", OsStr::new("+A2 -Werror"))];
    let reference = run(&launcher, &args, &envs, &[], None);
    fs::copy(env!("CARGO_BIN_EXE_arinsal_typer"), &launcher).unwrap();
    let arinsal = run(&launcher, &args, &envs, &[], None);
    assert_same(reference, arinsal);
}

#[test]
fn erlc_translates_options_and_forwards_environment() {
    let args = [
        OsStr::new("-pa"),
        OsStr::new("include"),
        OsStr::new("-pzprelude"),
        OsStr::new("-smp"),
        OsStr::new("+A2"),
        OsStr::new("-no-server"),
        OsStr::new("module.erl"),
    ];
    let envs = [
        ("ERL_FLAGS", OsStr::new("+A2 -Werror")),
        ("ERLC_USE_SERVER", OsStr::new("no")),
    ];
    let (reference, arinsal) = differential(
        "erlc",
        env!("CARGO_BIN_EXE_arinsal_erlc"),
        &args,
        &envs,
        &["ERLC_EMULATOR"],
        None,
    );
    assert_same(reference, arinsal);
}

#[test]
fn erlc_server_start_falls_back_to_the_regular_compile_command_without_cookie() {
    let home = TempDir::new();
    let (preload_variable, loopback_hostname) = loopback_hostname_preload(&home.0);
    let args = [
        OsStr::new("-server"),
        OsStr::new("-pa"),
        OsStr::new("include"),
        OsStr::new("module.erl"),
    ];
    let preload_value = loopback_hostname.as_os_str();
    let envs = [
        ("ERL_FLAGS", OsStr::new("+A2 -Werror")),
        (preload_variable, preload_value),
        ("ERL_EPMD_PORT", OsStr::new("1")),
    ];
    let (reference, arinsal) = differential(
        "erlc",
        env!("CARGO_BIN_EXE_arinsal_erlc"),
        &args,
        &envs,
        &["ERLC_EMULATOR", "ERLC_USE_SERVER"],
        Some(&home.0),
    );
    assert_same(reference, arinsal);
}

#[test]
fn erlc_compile_server_rpc_matches_otp() {
    let temp = TempDir::new();
    let bin = temp.0.join("bin");
    fs::create_dir(&bin).unwrap();
    fake_erl(&bin);
    let launcher = bin.join("erlc");
    fs::copy(reference_binary("erlc"), &launcher).unwrap();
    let (preload_variable, loopback_hostname) = loopback_hostname_preload(&temp.0);
    let epmd_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let epmd_port = epmd_listener.local_addr().unwrap().port();
    drop(epmd_listener);
    let server_id = format!("test{}", std::process::id());
    let user = "launcher_test";
    let alive_name = format!("erl_compile_server_{server_id}_{user}");
    let full_name = format!("{alive_name}@localhost");
    let erl = reference_binary("erl");
    let epmd = reference_binary("epmd");
    let configuration = bin.join("erl");
    let _epmd = EpmdGuard {
        binary: epmd,
        port: epmd_port,
    };
    fs::write(
        temp.0.join("launcher_compile_test.erl"),
        "-module(launcher_compile_test).\n-export([value/0]).\nvalue() -> ok.\n",
    )
    .unwrap();

    let mut server = ChildGuard(
        Command::new(&erl)
            .args([
                OsStr::new("-noshell"),
                OsStr::new("-noinput"),
                OsStr::new("-name"),
                OsStr::new(&full_name),
                OsStr::new("-setcookie"),
                OsStr::new("erlc_compile_server_cookie"),
                OsStr::new("-kernel"),
                OsStr::new("inet_dist_use_interface"),
                OsStr::new("{127,0,0,1}"),
                OsStr::new("start_compile_server"),
                OsStr::new("true"),
                OsStr::new("-eval"),
                OsStr::new(
                    "Port = open_port({fd,0,1}, [eof]), io:format(\"READY~n\"), receive {Port,eof} -> halt(0) after 5000 -> halt(1) end.",
                ),
            ])
            .env("HOME", &temp.0)
            .env("LOGNAME", user)
            .env("USER", user)
            .env("ERLC_SERVER_ID", &server_id)
            .env("ERLC_CONFIGURATION", &configuration)
            .env("ERL_FLAGS", "+A2 -Werror")
            .env("ERL_EPMD_ADDRESS", "127.0.0.1")
            .env("ERL_EPMD_PORT", epmd_port.to_string())
            .env(preload_variable, &loopback_hostname)
            .current_dir(&temp.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut stdout = BufReader::new(server.0.stdout.take().unwrap());
    let mut readiness = String::new();
    stdout.read_line(&mut readiness).unwrap();
    assert_eq!(readiness, "READY\n");

    let preload_value = loopback_hostname.as_os_str();
    let config_value = configuration.as_os_str();
    let server_id_value = OsStr::new(&server_id);
    let epmd_port_value = epmd_port.to_string();
    let args = [
        OsStr::new("-d"),
        OsStr::new("-server"),
        OsStr::new("launcher_compile_test.erl"),
    ];
    let envs = [
        ("HOME", temp.0.as_os_str()),
        ("LOGNAME", OsStr::new(user)),
        ("USER", OsStr::new(user)),
        ("ERLC_SERVER_ID", server_id_value),
        ("ERLC_CONFIGURATION", config_value),
        ("ERLC_USE_SERVER", OsStr::new("yes")),
        ("ERL_FLAGS", OsStr::new("+A2 -Werror")),
        ("ERL_EPMD_ADDRESS", OsStr::new("127.0.0.1")),
        ("ERL_EPMD_PORT", OsStr::new(&epmd_port_value)),
        (preload_variable, preload_value),
    ];
    let reference = run_from(&launcher, &args, &envs, &temp.0);
    fs::copy(env!("CARGO_BIN_EXE_arinsal_erlc"), &launcher).unwrap();
    let arinsal = run_from(&launcher, &args, &envs, &temp.0);
    assert!(reference.status.success());
    assert!(arinsal.status.success());
    assert!(String::from_utf8_lossy(&reference.stderr).contains("called server for"));
    assert!(String::from_utf8_lossy(&arinsal.stderr).contains("called server for"));
    assert_same(reference, arinsal);
    server.halt_on_stdin_eof();
}

struct EpmdGuard {
    binary: PathBuf,
    port: u16,
}

impl Drop for EpmdGuard {
    fn drop(&mut self) {
        let _ = Command::new(&self.binary)
            .args(["-port", &self.port.to_string(), "-kill"])
            .status();
    }
}

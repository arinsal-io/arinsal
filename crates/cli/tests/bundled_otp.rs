use similar_asserts::assert_eq;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = Path::new("/tmp").join(format!("arinsal-bundled-otp-{nonce}"));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn otp_root() -> PathBuf {
    std::env::var_os("ARINSAL_TEST_OTP_ROOT")
        .or_else(|| std::env::var_os("ARINSAL_OTP_ROOT"))
        .map(PathBuf::from)
        .or_else(|| arinsal_args::discover_otp_root(&arinsal_args::ProcessEnv).map(PathBuf::from))
        .expect("set ARINSAL_TEST_OTP_ROOT or put OTP 29.1.1 erl on PATH")
}

fn timeout_program() -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join("timeout"))
        .find(|candidate| candidate.is_file())
        .expect("timeout must be installed to bound child processes")
}

fn timed(command: Command, seconds: &str) -> Output {
    let mut timeout = Command::new(timeout_program());
    timeout
        .arg(seconds)
        .arg(command.get_program())
        .args(command.get_args());
    for (key, value) in command.get_envs() {
        match value {
            Some(value) => {
                timeout.env(key, value);
            }
            None => {
                timeout.env_remove(key);
            }
        }
    }
    if let Some(directory) = command.get_current_dir() {
        timeout.current_dir(directory);
    }
    timeout.output().expect("run command under timeout")
}

#[test]
fn release_bundle_boots_without_erl_and_matches_otp() {
    let source_root = otp_root();
    let temp = TempDir::new();
    let prefix = temp.0.join("prefix");
    let rejected_prefix = temp.0.join("wrong-version-prefix");
    let bin_dir = prefix.join("bin");
    let no_erl_path = temp.0.join("path-without-erl");
    let source = temp.0.join("compile_probe.erl");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&no_erl_path).unwrap();
    fs::write(
        &source,
        "-module(compile_probe).\n-export([run/0]).\nrun() -> lists:sum([1, 2, 3]).\n",
    )
    .unwrap();

    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bundler = repository.join("tools/release/bundle_otp.sh");
    let mut reject_wrong_version = Command::new("bash");
    reject_wrong_version
        .arg(&bundler)
        .arg(&temp.0)
        .arg(&rejected_prefix)
        .current_dir("/tmp");
    let rejection = timed(reject_wrong_version, "30");
    assert!(!rejection.status.success());
    assert!(
        String::from_utf8_lossy(&rejection.stderr)
            .contains("expected an installed Erlang/OTP 29.1.1 tree"),
        "{}",
        String::from_utf8_lossy(&rejection.stderr)
    );

    let mut package = Command::new("bash");
    package
        .arg(bundler)
        .arg(&source_root)
        .arg(&prefix)
        .current_dir("/tmp");
    let package = timed(package, "180");
    assert!(
        package.status.success(),
        "{}",
        String::from_utf8_lossy(&package.stderr)
    );
    assert!(
        String::from_utf8_lossy(&package.stdout).contains("Bundled OTP 29.1.1"),
        "{}",
        String::from_utf8_lossy(&package.stdout)
    );

    let arinsal = bin_dir.join("arinsal");
    let release_binary = repository.join("target/release/arinsal");
    let binary = if release_binary.is_file() {
        release_binary.as_path()
    } else {
        Path::new(env!("CARGO_BIN_EXE_arinsal"))
    };
    fs::copy(binary, &arinsal).unwrap();
    let expression = format!(
        "io:format(\"root=~s~nstdlib=~s~ncompiler=~s~nroot_arg=~p~n\",[code:root_dir(),code:lib_dir(stdlib),code:lib_dir(compiler),init:get_argument(root)]), {{ok,Module,Binary}}=compile:file(\"{}\",[binary]), io:format(\"compiled=~p/~p~n\",[Module,byte_size(Binary)]), halt().",
        source.display()
    );

    let reference_erl = source_root.join("bin/erl");
    let mut reference = Command::new(timeout_program());
    reference
        .args(["60", reference_erl.to_str().unwrap(), "-noshell", "-eval"])
        .arg(&expression)
        .env_remove("ERL_FLAGS")
        .env_remove("ERL_AFLAGS")
        .env_remove("ERL_ZFLAGS")
        .current_dir("/tmp");
    let expected = reference.output().expect("run reference erl under timeout");

    let mut actual_command = Command::new(timeout_program());
    actual_command
        .args(["60", arinsal.to_str().unwrap(), "-noshell", "-eval"])
        .arg(&expression)
        .env("PATH", &no_erl_path)
        .env("ARINSAL_OTP_ROOT", temp.0.join("deliberately-wrong-root"))
        .env_remove("ERL_ROOTDIR")
        .env_remove("ROOTDIR")
        .env_remove("BINDIR")
        .env_remove("ERL_FLAGS")
        .env_remove("ERL_AFLAGS")
        .env_remove("ERL_ZFLAGS")
        .current_dir("/tmp");
    let actual = actual_command
        .output()
        .expect("run bundled arinsal under timeout");

    assert!(
        expected.status.success(),
        "{}",
        String::from_utf8_lossy(&expected.stderr)
    );
    assert!(
        actual.status.success(),
        "{}",
        String::from_utf8_lossy(&actual.stderr)
    );
    let normalized = String::from_utf8(expected.stdout).unwrap().replace(
        source_root.to_str().unwrap(),
        prefix.join("lib/arinsal/otp").to_str().unwrap(),
    );
    assert_eq!(String::from_utf8(actual.stdout).unwrap(), normalized);
    assert_eq!(actual.stderr, expected.stderr);
}

#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn otp_include() -> PathBuf {
    let output = Command::new("timeout")
        .arg("30")
        .arg("erl")
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

fn run(command: &mut Command, dir: &Path) -> Output {
    let expression = format!(
        "ok=erl_ddll:load_driver(\"{}\",\"main_thread_drv\"),P=open_port({{spawn_driver,\"main_thread_drv\"}},[binary]),true=port_command(P,<<>>),R=receive {{P,{{data,<<V>>}}}}->V after 5000->timeout end,io:format(\"~p~n\",[R]),port_close(P),halt().",
        dir.display()
    );
    command
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &expression])
        .env("ERL_AFLAGS", "")
        .env("ERL_FLAGS", "")
        .env("ERL_ZFLAGS", "")
        .env("ERL_CRASH_DUMP", "/dev/null")
        .output()
        .expect("run emulator")
}

#[test]
fn stolen_main_thread_matches_otp() {
    let dir = std::env::temp_dir().join(format!("arinsal-main-thread-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let status = Command::new("cc")
        .args([
            "-bundle",
            "-undefined",
            "dynamic_lookup",
            "-D__DARWIN__",
            "-I",
        ])
        .arg(otp_include())
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../drv/tests/fixtures/main_thread_drv.c"))
        .arg("-o")
        .arg(dir.join("main_thread_drv.so"))
        .status()
        .expect("cc");
    assert!(status.success(), "compile test driver");

    let expected = run(Command::new("timeout").arg("60").arg("erl"), &dir);
    assert!(expected.status.success(), "erl: {expected:?}");
    assert_eq!(
        expected.stdout, b"49\n",
        "callback must observe pthread main"
    );

    let actual = run(
        Command::new("timeout")
            .arg("60")
            .arg(env!("CARGO_BIN_EXE_arinsal")),
        &dir,
    );
    assert!(actual.status.success(), "arinsal: {actual:?}");
    assert_eq!(actual.stdout, expected.stdout);
    let _ = std::fs::remove_dir_all(dir);
}

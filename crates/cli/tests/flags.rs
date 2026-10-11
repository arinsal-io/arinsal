use similar_asserts::assert_eq;
use std::process::Command;

fn root() -> String {
    let output = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s\",[code:root_dir()]),halt().",
        ])
        .env("ERL_AFLAGS", "")
        .env("ERL_FLAGS", "")
        .env("ERL_ZFLAGS", "")
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

fn quiet(command: &mut Command) -> &mut Command {
    command
        .env("ERL_AFLAGS", "")
        .env("ERL_FLAGS", "")
        .env("ERL_ZFLAGS", "")
        .env("ERL_CRASH_DUMP", "/dev/null")
        .env_remove("ERL_EPMD_PORT")
}

#[test]
fn detached_is_rejected() {
    let output = quiet(
        Command::new(env!("CARGO_BIN_EXE_arinsal"))
            .arg("-detached")
            .env("ERL_ROOTDIR", root()),
    )
    .output()
    .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "arinsal: -detached is not supported\n"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn missing_name_and_emulator_type_match_erl() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("skipping missing_name_and_emulator_type_match_erl: erl is unavailable");
        return;
    }
    let root = root();
    for args in [
        vec!["-sname"],
        vec!["-name"],
        vec!["-emu_type"],
        vec!["-emu_type", "nosuch"],
    ] {
        let expected = quiet(Command::new("erl").args(&args)).output().unwrap();
        let actual = quiet(
            Command::new(env!("CARGO_BIN_EXE_arinsal"))
                .args(&args)
                .env("ERL_ROOTDIR", &root),
        )
        .output()
        .unwrap();
        assert_eq!(actual.status.code(), expected.status.code(), "{args:?}");
        assert_eq!(actual.stderr, expected.stderr, "{args:?}");
        assert_eq!(actual.stdout, expected.stdout, "{args:?}");
    }
}

#[test]
fn alloc_a4_bad_allocator_flags_match_otp_cli() {
    let otp_root = root();
    for args in [
        vec!["+MMsco", "maybe"],
        vec!["+Mea", "unknown"],
        vec!["+MEsbct", "-1"],
        vec!["+MDfoo", "1"],
    ] {
        let expected = quiet(Command::new("erl").args(&args)).output().unwrap();
        let actual = quiet(
            Command::new(env!("CARGO_BIN_EXE_arinsal"))
                .args(&args)
                .env("ERL_ROOTDIR", &otp_root),
        )
        .output()
        .unwrap();
        assert_eq!(actual.status.code(), expected.status.code(), "{args:?}");
        assert_eq!(actual.stderr, expected.stderr, "{args:?}");
        assert_eq!(actual.stdout, expected.stdout, "{args:?}");
    }
}

#[test]
fn s_and_run_execute_in_order() {
    let dir = std::env::temp_dir().join(format!("arinsal-s-run-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("flag_order.erl");
    std::fs::write(
        &source,
        "-module(flag_order).\n-export([s/1, r/1]).\ns(A) -> io:format(\"s:~p~n\", [A]).\nr(A) -> io:format(\"r:~p~n\", [A]).\n",
    )
    .unwrap();
    let compiled = Command::new("erlc")
        .args(["-o", dir.to_str().unwrap(), source.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(compiled.success());
    let pa = dir.to_str().unwrap();
    let args = [
        "-noshell",
        "-pa",
        pa,
        "-s",
        "flag_order",
        "s",
        "one",
        "-run",
        "flag_order",
        "r",
        "two",
        "-s",
        "erlang",
        "halt",
    ];
    let expected = quiet(Command::new("erl").args(args)).output().unwrap();
    let actual = quiet(
        Command::new("timeout")
            .args(["30", env!("CARGO_BIN_EXE_arinsal")])
            .args(args)
            .env("ERL_ROOTDIR", root()),
    )
    .output()
    .unwrap();
    assert_eq!(actual.status.code(), expected.status.code());
    assert_eq!(actual.stdout, expected.stdout);
    assert_eq!(actual.stderr, expected.stderr);
    let _ = std::fs::remove_dir_all(dir);
}

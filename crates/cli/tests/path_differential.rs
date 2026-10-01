//! erlexec puts the ERTS bindir at the front of PATH for the emulator and its children.

use std::process::Command;

const EXPR: &str = "io:format(\"~s~n~s~n\",[hd(string:split(os:getenv(\"PATH\"),\":\")),os:find_executable(\"erl\")]),halt().";

fn run(binary: &str, timeout: bool) -> String {
    // A directory first on PATH holding a decoy `erl` must not win over the bindir.
    let decoy = std::env::temp_dir().join(format!("arinsal-path-{}", std::process::id()));
    std::fs::create_dir_all(&decoy).unwrap();
    let path = format!("{}:{}", decoy.display(), std::env::var("PATH").unwrap());
    let mut command = if timeout {
        let mut c = Command::new("timeout");
        c.arg("60").arg(binary);
        c
    } else {
        Command::new(binary)
    };
    let output = command
        .args(["-noshell", "-eval", EXPR])
        .env("PATH", path)
        .output()
        .expect("run emulator");
    let _ = std::fs::remove_dir_all(&decoy);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn bindir_leads_path_like_erl() {
    let expected = run("erl", false);
    assert!(expected.contains("erts-17.1/bin"), "{expected}");
    assert_eq!(run(env!("CARGO_BIN_EXE_arinsal"), true), expected);
}

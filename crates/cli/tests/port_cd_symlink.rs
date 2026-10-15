//! `open_port` with `{cd, Dir}` must work when the VM runs through a symlink such as `erl`.

use std::process::Command;

const EXPR: &str = "P = open_port({spawn_executable, \"/bin/pwd\"}, [{cd, \"/\"}, use_stdio, stderr_to_stdout, binary, exit_status, hide]), R = (fun L(Acc) -> receive {P, {data, D}} -> L([D | Acc]); {P, {exit_status, S}} -> {S, iolist_to_binary(lists:reverse(Acc))} end end)([]), io:format(\"~p~n\", [R]), halt().";

fn reference_root() -> String {
    let output = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s\", [code:root_dir()]), halt().",
        ])
        .output()
        .expect("run reference erl");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn ns_port_cd_works_through_symlinked_binary() {
    let expected = Command::new("erl")
        .args(["-noshell", "-eval", EXPR])
        .output()
        .expect("run reference erl");
    let expected = String::from_utf8_lossy(&expected.stdout).into_owned();
    assert_eq!(expected.trim(), "{0,<<\"/\\n\">>}");

    let dir = std::env::temp_dir().join(format!("arinsal-port-cd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join("erl");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_arinsal"), &link).unwrap();
    let output = Command::new("timeout")
        .arg("60")
        .arg(&link)
        .args(["-noshell", "-eval", EXPR])
        .env("ERL_ROOTDIR", reference_root())
        .output()
        .expect("run symlinked emulator");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        expected,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

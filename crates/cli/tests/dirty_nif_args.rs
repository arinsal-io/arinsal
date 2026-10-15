//! A dirty NIF with more arguments than the module the process last interpreted has registers
//! must keep all of them while the process waits for the dirty scheduler. `file:copy/2` and
//! `file:change_mode/2` hit this through `prim_file:set_time_nif/4`.

use std::process::Command;

const EXPR: &str = "P = \"/tmp/arinsal_dirty_nif_args_\" ++ integer_to_list(erlang:unique_integer([positive])), {ok, _} = file:copy(\"/etc/hosts\", P), A = file:change_mode(P, 8#644), {ok, {file_info, _, _, _, _, _, _, M, _, _, _, _, _, _}} = file:read_file_info(P), ok = file:delete(P), io:format(\"~p~n\", [{A, M band 8#777}]), halt().";

fn run(program: &std::ffi::OsStr, root: Option<&str>) -> String {
    let mut command = Command::new("timeout");
    command
        .arg("60")
        .arg(program)
        .args(["-noshell", "-eval", EXPR]);
    if let Some(root) = root {
        command.env("ERL_ROOTDIR", root);
    }
    let output = command.output().expect("run emulator");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn ns_dirty_nif_keeps_all_arguments() {
    let root = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s\", [code:root_dir()]), halt().",
        ])
        .output()
        .expect("run reference erl");
    let root = String::from_utf8(root.stdout).unwrap();
    let expected = run("erl".as_ref(), None);
    assert_eq!(expected.trim(), "{ok,420}", "reference output");
    let actual = run(env!("CARGO_BIN_EXE_arinsal").as_ref(), Some(&root));
    assert_eq!(actual, expected);
}

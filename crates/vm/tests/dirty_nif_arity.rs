//! A four-argument dirty NIF keeps its last argument when the process moves to a dirty
//! scheduler after a call that left a smaller live register count behind. The node writes
//! file times after `prim_file:open/2` and prints the results; they must match `erl`.

use std::path::PathBuf;
use std::process::{Command, Stdio};

const PROGRAM: &str = r#"
Dir = filename:join(os:getenv("TMPDIR", "/tmp"), "arinsal_dirty_nif_arity_" ++ os:getpid()),
ok = prim_file:make_dir(Dir),
File = filename:join(Dir, "a.txt"),
ok = prim_file:write_file(File, <<"data">>),
{ok, Info} = prim_file:read_file_info(File),
Before = prim_file:write_file_info(File, Info),
{ok, Fd} = prim_file:open(File, [read, binary]),
After = prim_file:write_file_info(File, Info),
ok = prim_file:close(Fd),
{ok, Src} = prim_file:open(File, [read, binary]),
Copy = File ++ ".copy",
{ok, Dst} = prim_file:open(Copy, [write, binary]),
{ok, 4} = prim_file:copy(Src, Dst, infinity),
ok = prim_file:close(Dst),
ok = prim_file:close(Src),
Written = prim_file:write_file_info(Copy, Info),
ok = prim_file:delete(Copy),
ok = prim_file:delete(File),
ok = prim_file:del_dir(Dir),
io:format("~p~n", [{Before, After, Written}]),
halt().
"#;

fn shim_dir() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = root.join("target/debug/arinsal");
    assert!(binary.is_file(), "build target/debug/arinsal first");
    let dir = std::env::temp_dir().join(format!("arinsal-dirty-arity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join("erl");
    let _ = std::fs::remove_file(&link);
    #[cfg(unix)]
    std::os::unix::fs::symlink(binary.canonicalize().unwrap(), &link).unwrap();
    dir
}

fn run(shim: Option<&PathBuf>) -> String {
    let mut path = Vec::new();
    if let Some(dir) = shim {
        path.push(dir.clone());
    }
    path.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let output = Command::new("erl")
        .args(["-noshell", "-eval", PROGRAM])
        .env("PATH", std::env::join_paths(path).unwrap())
        .env_remove("ERL_ROOTDIR")
        .env_remove("ARINSAL_OTP_ROOT")
        .stdin(Stdio::null())
        .output()
        .expect("run erl");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn dirty_nif_arity_keeps_all_arguments() {
    let reference = run(None);
    assert_eq!(reference.trim(), "{ok,ok,ok}", "reference erl");
    let shim = shim_dir();
    assert_eq!(run(Some(&shim)), reference);
}

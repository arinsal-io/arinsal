//! Atom table observables against OTP 29.1.1: `+t`, encodings, and term order.

use similar_asserts::assert_eq;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn run(program: &Path, args: &[&str]) -> (bool, String, String) {
    run_at(program, args, None)
}

fn run_at(program: &Path, args: &[&str], dir: Option<&Path>) -> (bool, String, String) {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", program.display()));
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().expect("output");
                return (
                    output.status.success(),
                    String::from_utf8_lossy(&output.stdout).trim().to_string(),
                    String::from_utf8_lossy(&output.stderr).trim().to_string(),
                );
            }
            Ok(None) if started.elapsed() > Duration::from_secs(90) => {
                let pid = child.id();
                let _ = Command::new("kill").arg(pid.to_string()).status();
                let _ = child.wait();
                panic!("{} timed out", program.display());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("wait {}: {error}", program.display()),
        }
    }
}

const PROBE: &str = "\
Limit = erlang:system_info(atom_limit),\
Before = erlang:system_info(atom_count),\
_ = list_to_atom(\"atom_tab_probe_zzzz_unique\"),\
After = erlang:system_info(atom_count),\
Bad = element(1, element(2, catch binary_to_atom(<<255,255>>, utf8))),\
Long = element(1, element(2, catch binary_to_atom(list_to_binary(lists:duplicate(256, $q)), utf8))),\
Lat = binary_to_list(atom_to_binary(binary_to_atom(<<255>>, latin1), latin1)),\
Utf = binary_to_list(atom_to_binary(binary_to_atom(<<195,191>>, utf8), utf8)),\
Ord = lists:sort([b, a, ab, aa, list_to_atom([229]), z]),\
io:format(\"~p ~p ~p ~p ~w ~w ~w~n\", [Limit, After - Before, Bad, Long, Lat, Utf, Ord]),\
halt().\
";

#[test]
fn atom_limit_encoding_and_order_match_erl() {
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build target/debug/arinsal first");
    let (erl_ok, erl_out, erl_err) = run(Path::new("erl"), &["-noshell", "-eval", PROBE]);
    assert!(erl_ok, "erl failed: {erl_err}");
    let (ok, out, err) = run(&arinsal, &["-noshell", "-eval", PROBE]);
    assert!(ok, "arinsal failed: {err}\n{out}");
    assert_eq!(out, erl_out, "stderr {err}");

    // OTP 29.1.1 boots with 10563 atoms, so `+t 8192` aborts in `index_put_entry`
    // before `-eval`. 12000 is the smallest round limit that still starts.
    let (erl_ok, erl_limit, erl_err) = run(
        Path::new("erl"),
        &[
            "-noshell",
            "+t",
            "12000",
            "-eval",
            "io:format(\"~p~n\", [erlang:system_info(atom_limit)]), halt().",
        ],
    );
    assert!(erl_ok, "{erl_err}");
    let (ok, limit, err) = run(
        &arinsal,
        &[
            "-noshell",
            "+t",
            "12000",
            "-eval",
            "io:format(\"~p~n\", [erlang:system_info(atom_limit)]), halt().",
        ],
    );
    assert!(ok, "{err}");
    assert_eq!(limit, erl_limit);
    assert_eq!(limit, "12000");

    // index.c:89 exits the VM. OTP 29.1.1 boots with about 10562 atoms, so
    // `+t 11000` starts and the 2000 new atoms overflow the index.
    let dir = std::env::temp_dir().join(format!("atom_tab_full_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let overflow = "[list_to_atom(integer_to_list(N)) || N <- lists:seq(1,2000)], halt().";
    let args = ["-noshell", "+t", "11000", "-eval", overflow];
    let (erl_ok, _, erl_err) = run_at(Path::new("erl"), &args, Some(&dir));
    let (ok, out, err) = run_at(&arinsal, &args, Some(&dir));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!erl_ok, "erl should exit: {erl_err}");
    assert!(!ok, "arinsal should exit: {err}\n{out}");
    assert_eq!(err, erl_err);
}

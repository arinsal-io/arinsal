//! `-on_load` on the `eval_scheduled` / `code:load_file` paths, and refc literal
//! binaries released by purge.

use arinsal_vm::Vm;
use std::path::{Path, PathBuf};
use std::process::Command;

fn compile(dir: &Path, module: &str, source: &str) -> PathBuf {
    let source_path = dir.join(format!("{module}.erl"));
    std::fs::write(&source_path, source).unwrap();
    let output = Command::new("erlc")
        .arg("-o")
        .arg(dir)
        .arg(&source_path)
        .output()
        .expect("erlc");
    assert!(
        output.status.success(),
        "erlc {module}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    dir.join(format!("{module}.beam"))
}

fn erl_eval(args: &[&str]) -> String {
    let output = Command::new("erl").args(args).output().expect("erl");
    assert!(
        output.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// `eval_scheduled` of a module with `-on_load` runs that function before the entry.
/// OTP autoloads the same module through `code_server` and prints `ran`, not `not_loaded`.
#[test]
fn eval_scheduled_runs_on_load() {
    let dir = std::env::temp_dir().join(format!("arinsal-onload-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let source = r#"-module(ol_sched).
-on_load(init/0).
-export([init/0, ping/0]).
init() -> persistent_term:put(ol_sched, ran), ok.
ping() -> persistent_term:get(ol_sched, not_loaded).
"#;
    let beam = compile(&dir, "ol_sched", source);
    let expected = erl_eval(&[
        "-pa",
        dir.to_str().unwrap(),
        "-noshell",
        "-eval",
        "io:format(\"~p~n\", [ol_sched:ping()]), halt().",
    ]);
    assert_eq!(expected.trim(), "ran");

    let mut autoload = Vm::new([dir.clone()]);
    let autoloaded = autoload
        .eval_scheduled("ol_sched", "ping", &[], 1, None)
        .expect("autoload on_load");
    assert_eq!(autoloaded.text, "ran", "path load via eval_scheduled");

    let mut loaded = Vm::new([]);
    loaded.load_file(&beam).unwrap();
    let from_file = loaded
        .eval_scheduled("ol_sched", "ping", &[], 1, None)
        .expect("load_file on_load");
    assert_eq!(from_file.text, "ran", "Vm::load_file then eval_scheduled");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `code:load_file` of a module with `-on_load` makes the module loaded and runs the callback.
#[test]
fn code_load_file_runs_on_load() {
    let dir = std::env::temp_dir().join(format!("arinsal-onload-file-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    compile(
        &dir,
        "ol_file",
        r#"-module(ol_file).
-on_load(init/0).
-export([init/0, ping/0]).
init() -> persistent_term:put(ol_file, ran), ok.
ping() -> persistent_term:get(ol_file, not_loaded).
"#,
    );
    let eval = format!(
        "code:add_patha(\"{}\"), {{module, ol_file}} = code:load_file(ol_file), io:format(\"~p~n\", [ol_file:ping()]), halt().",
        dir.display()
    );
    let expected = erl_eval(&["-noshell", "-eval", &eval]);
    assert_eq!(expected.trim(), "ran");

    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(
        arinsal.is_file(),
        "build target/debug/arinsal before this test"
    );
    let output = Command::new(&arinsal)
        .args(["-noshell", "-eval", &eval])
        .output()
        .expect("arinsal");
    assert!(
        output.status.success(),
        "arinsal code:load_file failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "ran",
        "stderr {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Purging a module whose literal area holds a refc binary returns that memory after
/// `erts_debug:set_internal_state(wait, deallocations)`, within OTP's 64KB threshold.
#[test]
fn purged_literal_refc_binary_memory_returns() {
    let dir = std::env::temp_dir().join(format!("arinsal-litmem-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // 96KB, above the suite's 64KB leak threshold and the refc-binary cutoff.
    let holder = compile(
        &dir,
        "lit_mem_holder",
        "-module(lit_mem_holder).\n-export([bin/0]).\nbin() -> <<0:786432>>.\n",
    );
    let probe = format!(
        r#"-module(lit_mem_probe).
-export([run/0]).
run() ->
    ensure_purger(),
    {{ok, Beam}} = prim_file:read_file("{}"),
    erts_debug:set_internal_state(available_internal_state, true),
    ok = erts_debug:set_internal_state(wait, deallocations),
    Before = erlang:memory(binary),
    load_purge(Beam),
    load_purge(Beam),
    load_purge(Beam),
    load_purge(Beam),
    receive after 1 -> ok end,
    ok = erts_debug:set_internal_state(wait, deallocations),
    ok = erts_debug:set_internal_state(wait, deallocations),
    erlang:memory(binary) - Before.
load_purge(Beam) ->
    Prep = erlang:prepare_loading(lit_mem_holder, Beam),
    ok = erlang:finish_loading([Prep]),
    true = erlang:delete_module(lit_mem_holder),
    true = erlang:purge_module(lit_mem_holder),
    erlang:garbage_collect().
ensure_purger() ->
    case whereis(erts_code_purger) of
        undefined ->
            spawn(erts_code_purger, start, []),
            wait_purger();
        _ -> ok
    end.
wait_purger() ->
    case whereis(erts_code_purger) of
        undefined -> receive after 10 -> ok end, wait_purger();
        _ -> ok
    end.
"#,
        holder.display()
    );
    compile(&dir, "lit_mem_probe", &probe);

    let expected = erl_eval(&[
        "-pa",
        dir.to_str().unwrap(),
        "-noshell",
        "-eval",
        "io:format(\"~p~n\", [lit_mem_probe:run()]), halt().",
    ]);
    let expected_delta: i64 = expected
        .lines()
        .rev()
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .parse()
        .unwrap_or_else(|_| panic!("erl delta {expected}"));
    assert!(
        expected_delta < 64 * 1024,
        "erl itself leaked {expected_delta}"
    );

    let mut vm = Vm::new([dir.clone()]);
    let actual = vm
        .eval_scheduled("lit_mem_probe", "run", &[], 1, None)
        .expect("literal purge");
    let delta: i64 = actual
        .text
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("arinsal delta {}", actual.text));
    assert!(
        delta < 64 * 1024,
        "binary memory grew by {delta} after purging refc literals (erl {expected_delta})"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

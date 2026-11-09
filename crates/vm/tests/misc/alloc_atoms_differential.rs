//! Allocator info interns the same atoms, in the same order, as OTP 29.1.1.
//!
//! `erlang:memory/0` calls `system_info(alloc_util_allocators)`, then
//! `system_info({memory_internal, _, _})`, then `system_info(allocated_areas)`.
//! That is `erl_alloc.c:2789`, `erl_alloc_util.c:4690` (`init_atoms`), and
//! `erl_alloc.c:2579`. `system_info({allocator, eheap_alloc})` must not intern
//! anything further once memory/0 has run. Fresh atoms created afterwards
//! therefore receive the same indices (`erlang:phash2` mixes the atom index).

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use arinsal_difftest::RefErl;

const MODULE: &str = r#"
-module(alloc_atoms_probe).
-export([run/0]).

run() ->
    Before = erlang:system_info(atom_count),
    erlang:memory(),
    AfterMem = erlang:system_info(atom_count),
    erlang:system_info({allocator, eheap_alloc}),
    AfterEheap = erlang:system_info(atom_count),
    Fresh = [list_to_atom("alloc_fresh_" ++ integer_to_list(I)) || I <- lists:seq(1, 5)],
    Created = [versions, driver_alloc, aoffcbf, af, literal_realloc, aobf, gf, sys_misc],
    io:format("~p~n", [[Before, AfterMem, AfterEheap,
                        [erlang:phash2(A) || A <- Fresh],
                        [erlang:phash2(A) || A <- Created]]]),
    halt().
"#;

fn run(program: &std::path::Path, dir: &std::path::Path) -> String {
    let mut child = Command::new(program)
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", "alloc_atoms_probe:run()."])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {}: {error}", program.display()));
    let started = Instant::now();
    while child.try_wait().expect("wait").is_none() {
        if started.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{} did not finish", program.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().expect("output");
    assert!(
        output.status.success(),
        "{} failed ({:?}): {}",
        program.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn memory_and_eheap_allocator_atom_indices_match_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping alloc atom differential test");
        return;
    };
    let module = reference
        .compile_named("alloc_atoms_probe", MODULE, &[])
        .expect("compile alloc_atoms_probe");
    drop(reference);
    let dir = std::env::temp_dir().join(format!("arinsal-alloc-atoms-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join("alloc_atoms_probe.beam"), &module).expect("write beam");
    let expected = run(std::path::Path::new("erl"), &dir);
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release/arinsal");
    assert!(bin.is_file(), "build target/release/arinsal first");
    let actual = run(&bin, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        expected.starts_with('['),
        "unexpected erl output: {expected}"
    );
    assert_eq!(actual, expected, "erl={expected}");
}

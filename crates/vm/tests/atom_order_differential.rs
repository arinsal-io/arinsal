//! Atom table indices must match erts: flatmaps order atom keys by index
//! (erl_utils.h:267 erts_cmp_flatmap_keys) and HAMTs hash an atom key from its
//! term word (erl_term_hashing.c:2311 erts_map_hash), OTP-29.1.1.
//!
//! Only atoms whose erts index is deterministic are compared: the static table,
//! atoms of the C init, the preloaded modules and the static NIF loads, and
//! atoms created after boot. erts itself prepares the kernel modules of the
//! boot script in parallel, so atoms first created there differ between runs.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use arinsal_difftest::RefErl;

const MODULE: &str = r#"
-module(atom_order_probe).
-export([run/0]).

run() ->
    Count = erlang:system_info(atom_count),
    Static = [ok, error, true, false, undefined, normal, infinity, init, lists, logger, name,
              module, function, arity, line, file, pid, port, reason, value, data, state,
              x, y, select_trap, 'Cache-Control', 'TRACE', process_max, erts_beamasm,
              wait_for_request, boot, not_initialized, trace_ts, gc_buffer, skip_type_check,
              efile, adaptation_layer, gifaddr, '6to4', '$esock_name', sockets, address_info,
              net, 'IP', ggp, 'TCP'],
    Fresh = [list_to_atom("fresh_" ++ integer_to_list(I)) || I <- lists:seq(1, 40)],
    Literal = #{zebra => 1, a_new_key => 2, '__struct__' => 'Elixir.User', age => 3,
                email => 4, name => 5, ok => 6},
    Struct = #{'__struct__' => 'Elixir.Probe.User', name => <<"n">>, age => 3,
               email => e, inserted_at => nil},
    FreshSmall = maps:from_list([{A, 1} || A <- lists:sublist(Fresh, 12)]),
    FreshHamt = maps:from_list([{A, atom_to_list(A)} || A <- Fresh]),
    StaticHamt = maps:from_list([{A, 1} || A <- Static]),
    Mixed = maps:from_list([{A, 1} || A <- lists:sublist(Static, 20) ++ lists:sublist(Fresh, 20)]),
    {First, _, _} = maps:next(maps:iterator(FreshHamt)),
    Order = lists:sort(fun(X, Y) -> hd(maps:keys(#{X => 0, Y => 0})) =:= X end, Static),
    io:format("~p~n", [[Count, Literal, Struct, FreshSmall, maps:keys(FreshHamt),
                        maps:values(FreshHamt), maps:keys(StaticHamt), maps:to_list(Mixed),
                        First, Order, [erlang:phash2(A) || A <- Static],
                        [erlang:phash2(M) || M <- [Literal, Struct, StaticHamt]]]]).
"#;

const EVAL: &str = "atom_order_probe:run(), halt().";

fn run(program: &std::path::Path, dir: &std::path::Path) -> String {
    let mut child = Command::new(program)
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", EVAL])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", program.display()));
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
fn map_key_order_of_boot_and_fresh_atoms_matches_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping atom order test");
        return;
    };
    let module = reference
        .compile_named("atom_order_probe", MODULE, &[])
        .expect("compile atom_order_probe");
    drop(reference);
    let dir = std::env::temp_dir().join(format!("arinsal-atom-order-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join("atom_order_probe.beam"), &module).expect("write beam");
    let expected = run(std::path::Path::new("erl"), &dir);
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release/arinsal");
    assert!(bin.is_file(), "build target/release/arinsal first");
    let actual = run(&bin, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        expected.starts_with("[1"),
        "unexpected erl output: {expected}"
    );
    assert_eq!(actual, expected);
}

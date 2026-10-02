//! Local pid identifiers against erl 29.1.1: process-table layout, printing,
//! ordering, hashing, external format and `next_pid` wrap.

use std::path::{Path, PathBuf};
use std::process::Command;

const SOURCE: &str = r#"
-module(pid_layout_diff).
-export([main/0]).

main() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Limit = erlang:system_info(process_limit),
    show(limit, Limit),
    show(boot, [{P, name(P)} || P <- lists:sublist(processes(), 8)]),
    show(next, erts_debug:get_internal_state(next_pid)),
    %% Wrap past the table size: the reused slot's data grows by the table size.
    show(set_table, erts_debug:set_internal_state(next_pid, Limit)),
    spawn_batch(wrap_table, 4),
    show(set_mid, erts_debug:set_internal_state(next_pid, 100000000)),
    spawn_batch(mid, 2),
    %% Number overflow carries into the serial.
    show(set_num, erts_debug:set_internal_state(next_pid, (1 bsl 28) - 3)),
    spawn_batch(num_wrap, 4),
    show(after_num, erts_debug:get_internal_state(next_pid)),
    %% Data wraps at 60 bits and skips the invalid data.
    show(set_data, erts_debug:set_internal_state(next_pid, (1 bsl 60) - 3)),
    spawn_batch(data_wrap, 4),
    Fixed = [list_to_pid(S) || S <- ["<0.0.0>", "<0.7.0>", "<0.131071.0>", "<0.131072.0>",
                                     "<0.1048575.0>", "<0.1048576.0>", "<0.268435455.0>",
                                     "<0.1.1>", "<0.5.4294967295>", "<0.268435455.4294967295>"]],
    show(sorted, lists:sort(lists:reverse(Fixed) ++ [self()])),
    show(compare, [{A < B, A == B} || A <- Fixed, B <- Fixed]),
    [show(fixed, describe(P)) || P <- Fixed],
    show(bad_number, reason(fun() -> list_to_pid("<0.268435456.0>") end)),
    show(bad_serial, reason(fun() -> list_to_pid("<0.1.4294967296>") end)),
    Keys = [list_to_pid("<0." ++ integer_to_list(N) ++ ".0>") || N <- lists:seq(1, 200, 3)],
    Map = maps:from_list([{K, N} || {K, N} <- lists:zip(Keys, lists:seq(1, length(Keys)))]),
    show(map_order, maps:values(Map)),
    show(set_order, [index_of(K, Keys) || K <- sets:to_list(sets:from_list(Keys, [{version, 2}]))]),
    ok.

spawn_batch(Tag, N) ->
    Ps = [spawn(fun() -> ok end) || _ <- lists:seq(1, N)],
    [show(Tag, describe(P)) || P <- Ps].

describe(P) ->
    {pid_to_list(P), erlang:phash2(P), erlang:phash2(P, 1000), erlang:phash(P, 1 bsl 27),
     term_to_binary(P), term_to_binary(P, [{minor_version, 1}]),
     binary_to_term(term_to_binary(P)) =:= P, list_to_pid(pid_to_list(P)) =:= P,
     erlang:phash2({P, [P]})}.

name(P) ->
    case process_info(P, registered_name) of
        {registered_name, N} -> N;
        _ -> element(2, process_info(P, initial_call))
    end.

reason(F) ->
    try F() catch Class:Reason -> {Class, Reason} end.

index_of(K, Keys) -> length(lists:takewhile(fun(X) -> X =/= K end, Keys)).

show(Tag, Value) -> io:format("PL ~p ~w~n", [Tag, Value]).
"#;

fn arinsal() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal")
}

fn compile(dir: &Path) -> bool {
    std::fs::create_dir_all(dir).unwrap();
    let source = dir.join("pid_layout_diff.erl");
    std::fs::write(&source, SOURCE).unwrap();
    match Command::new("erlc")
        .arg("-o")
        .arg(dir)
        .arg(&source)
        .status()
    {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

fn run(program: &Path, flags: &[&str], dir: &Path) -> String {
    let output = Command::new(program)
        .args(flags)
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", "pid_layout_diff:main(), halt()."])
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", program.display()));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{} {flags:?} failed: {}\n{stdout}",
        program.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    // The internal-state warning report is logged asynchronously; keep only results.
    stdout
        .lines()
        .filter(|line| line.starts_with("PL "))
        .map(|line| format!("{line}\n"))
        .collect()
}

fn check(flags: &[&str], name: &str) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if !compile(&dir) {
        eprintln!("skipping: erlc is not available");
        return;
    }
    let bin = arinsal();
    assert!(bin.is_file(), "build arinsal-cli before this test");
    let expected = run(Path::new("erl"), flags, &dir);
    let actual = run(&bin, flags, &dir);
    for (line, (want, got)) in expected.lines().zip(actual.lines()).enumerate() {
        assert_eq!(got, want, "line {} differs for {flags:?}", line + 1);
    }
    assert_eq!(actual.lines().count(), expected.lines().count());
}

#[test]
fn pid_layout_matches_erl_default_table() {
    check(&[], "pid_layout_default");
}

#[test]
fn pid_layout_matches_erl_rounded_process_limit() {
    // +P 5000 rounds the table up to 8192 entries.
    check(&["+P", "5000"], "pid_layout_p5000");
}

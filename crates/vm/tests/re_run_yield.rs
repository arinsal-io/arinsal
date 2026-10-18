//! `re:run` yields between PCRE2 loop budgets, so a process stuck in a long match can be killed.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const MODULE: &str = "re_run_yield";
const SOURCE: &str = r#"
-module(re_run_yield).
-export([kill/0, same_result/0, kill_internal/0, internal_result/0, edge_cases/0,
         sub_binaries/0, sub_binary_fallbacks/0]).
kill() ->
    Subject = binary:copy(<<"hejsan">>, 100000),
    {ok, Compiled} = re:compile(<<"\\w+\\d">>, []),
    [begin
         {Pid, MRef} = spawn_monitor(fun() -> re:run(Subject, RE) end),
         erlang:yield(),
         exit(Pid, kill),
         receive {'DOWN', MRef, process, Pid, Reason} -> Reason after 5000 -> timeout end
     end || RE <- [<<"\\w+\\d">>, Compiled]].
kill_internal() ->
    Subject = binary:copy(<<"hejsan">>, 100000),
    {Pid, MRef} = spawn_monitor(fun() -> re:internal_run(Subject, <<"\\w+\\d">>, [], true) end),
    erlang:yield(),
    exit(Pid, kill),
    receive {'DOWN', MRef, process, Pid, Reason} -> Reason after 5000 -> timeout end.
internal_result() ->
    S = binary:copy(<<"abc123 def456 ">>, 2000),
    [re:internal_run(S, <<"\\d+">>, [{capture, all, binary}], true),
     re:internal_run(S, <<"[a-z]+">>, [{offset, 40}], false),
     (try re:internal_run(S, <<"\\d+">>, [], unknown) catch error:E -> {caught, E} end)].
same_result() ->
    S = binary:copy(<<"abc123 def456 ">>, 2000),
    [re:run(S, <<"\\d+">>, [global, {capture, all, binary}]),
     re:run(S, <<"x*">>, [global]),
     re:run(S, <<"(?<n>[a-z]+)(\\d)">>, [{capture, all_names, list}])].
edge_cases() ->
    [(try re:run([<<"ap">>|$a], <<"(p)">>, []) catch error:badarg -> badarg end),
     re:run("Xabcdefghi", "abc\\K|def\\K", [global]),
     re:replace("Xabcdefghi", "abc\\K|def\\K", "\\1e&&X&vW", [global]),
     re:split("Xabcdefghi", "abc\\K|def\\K", [{parts, 2}]),
     re:run("a\nb\nc", "^", [multiline, global]),
     re:replace("a\nb\nc", "^", "prefix&", [multiline, global])].
sub_binaries() ->
    Bin = << <<I>> || I <- lists:seq(1, 4096) >>,
    {match, [B, C]} = re:run(Bin, "a(.+)$", [{capture, all, binary}]),
    {match, [D]} = re:run(Bin, "a(.+)$", [{capture, [1], binary}]),
    {binary:referenced_byte_size(B), binary:referenced_byte_size(C),
     binary:referenced_byte_size(D)}.
sub_binary_fallbacks() ->
    Data = <<"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ">>,
    <<_:1, Unaligned:((byte_size(Data) * 8))/bitstring, _:7>> = <<0:1, Data/binary, 0:7>>,
    Small = <<"abcdefghijklmnopqrstuvwxyz0123456789">>,
    {match, [U]} = re:run(Unaligned, "(cdefgh)", [{capture, [1], binary}]),
    {match, [S]} = re:run(Small, "(cdefgh)", [{capture, [1], binary}]),
    {binary:referenced_byte_size(U), binary:referenced_byte_size(S)}.
"#;

fn both(function: &str) -> (CallResult, CallResult) {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, function, &[], 2, Some(82))
        .map(|outcome| CallResult::Ok(outcome.term))
        .unwrap_or_else(|error| CallResult::TransportError(format!("{error:?}")));
    (expected, actual)
}

#[test]
fn a_long_match_can_be_killed() {
    let (expected, actual) = both("kill");
    similar_asserts::assert_eq!(expected, actual);
}

#[test]
fn internal_run_traps_with_the_restart_state() {
    for function in ["kill_internal", "internal_result"] {
        let (expected, actual) = both(function);
        similar_asserts::assert_eq!(expected, actual, "{function}");
    }
}

#[test]
fn sliced_matches_give_the_same_result() {
    let (expected, actual) = both("same_result");
    similar_asserts::assert_eq!(expected, actual);
}

#[test]
fn global_empty_matches_and_improper_iodata_match_erts() {
    let (expected, actual) = both("edge_cases");
    similar_asserts::assert_eq!(expected, actual);
}

#[test]
fn binary_captures_keep_or_copy_the_subject_as_erts_does() {
    for function in ["sub_binaries", "sub_binary_fallbacks"] {
        let (expected, actual) = both(function);
        similar_asserts::assert_eq!(expected, actual, "{function}");
    }
}

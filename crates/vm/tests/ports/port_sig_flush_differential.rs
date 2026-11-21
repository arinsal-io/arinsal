//! `ERTS_BIF_HANDLE_SIGNALS_FROM_RETURN` on erts_internal port ops against OTP 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};

const MODULE: &str = "port_sig_flush";
const CASES: &[&str] = &[
    "port_info_after_self_send",
    "port_close_after_self_send",
    "port_info_badarg_after_self_send",
    "port_command_badopt",
    "port_info_dead",
];
const SOURCE: &str = r#"
-module(port_sig_flush).
-export([run/1]).

run(port_info_after_self_send) ->
    P = open_port({spawn_executable, "/bin/true"}, [exit_status]),
    self() ! a,
    self() ! b,
    Info = erlang:port_info(P, connected),
    {messages, Msgs} = process_info(self(), messages),
    port_close(P),
    {is_tuple(Info), Msgs};

run(port_close_after_self_send) ->
    P = open_port({spawn_executable, "/bin/cat"}, []),
    self() ! a,
    true = port_close(P),
    {messages, Msgs} = process_info(self(), messages),
    Msgs;

run(port_info_badarg_after_self_send) ->
    self() ! a,
    self() ! b,
    R = try erlang:port_info(not_a_port) catch error:E -> E end,
    {messages, Msgs} = process_info(self(), messages),
    {R, Msgs};

run(port_command_badopt) ->
    P = open_port({spawn_executable, "/bin/cat"}, []),
    R = try port_command(P, <<"x">>, [bogus]) catch error:E -> E end,
    port_close(P),
    R;

run(port_info_dead) ->
    P = open_port({spawn_executable, "/bin/cat"}, []),
    true = port_close(P),
    erlang:port_info(P).
"#;

#[test]
fn port_sig_flush_matches_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile differential");
    reference
        .load(MODULE, &beam)
        .expect("load reference module");
    let expected: Vec<(String, OwnedTerm)> = CASES
        .iter()
        .map(
            |case| match reference.call(MODULE, "run", &[OwnedTerm::Atom((*case).into())]) {
                CallResult::Ok(term) => ((*case).to_string(), term),
                other => panic!("{MODULE}:run({case}) on erl: {other:?}"),
            },
        )
        .collect();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load VM module");
    for (case, want) in &expected {
        let arg = Term::atom(global_atoms().intern(case).unwrap());
        let actual = vm
            .eval_scheduled(MODULE, "run", &[arg], 2)
            .unwrap_or_else(|error| panic!("{MODULE}:run({case}): {error}"));
        similar_asserts::assert_eq!(actual.term, *want, "{MODULE}:run({case})");
    }
}

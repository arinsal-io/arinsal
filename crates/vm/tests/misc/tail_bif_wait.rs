//! BIFs that wait for a signal reply or trap, called in tail position (`call_ext_last` after a
//! frame, `call_ext_only` without one) on a just-killed process: the continuation must return to
//! the caller's CP, so the loop result must match erl.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};

const MODULE: &str = "tail_bif_wait";
const CASES: &[&str] = &[
    "alive_last",
    "alive_only",
    "info_last",
    "info_only",
    "gc_last",
    "gc_only",
    "cpc_last",
    "cpc_only",
    "apply_last",
    "fun_last",
    "port_command_last",
    "port_command_only",
];

const SOURCE: &str = r#"-module(tail_bif_wait).
-export([run/1]).

run(Case) -> loop(10, Case, []).

loop(0, _Case, Acc) -> {done, Acc};
loop(N, Case, Acc) ->
    R = one(Case),
    loop(N - 1, Case, [R | Acc]).

one(Case) ->
    P = spawn(fun() -> receive stop -> ok end end),
    case Case of
        port_command_last -> pc_last(P);
        port_command_only -> pc_only(P);
        _ -> killed(Case, P)
    end.

killed(Case, P) ->
    exit(P, kill),
    case Case of
        alive_last -> alive_last(P);
        alive_only -> alive_only(P);
        info_last -> info_last(P);
        info_only -> info_only(P);
        gc_last -> gc_last(P);
        gc_only -> gc_only(P);
        cpc_last -> cpc_last(P);
        cpc_only -> cpc_only(P);
        apply_last -> apply_last(P);
        fun_last -> fun_last(P)
    end.

alive_last(P) -> exit(P, kill), is_process_alive(P).
alive_only(P) -> is_process_alive(P).
info_last(P) -> exit(P, kill), erlang:process_info(P, status).
info_only(P) -> erlang:process_info(P, status).
gc_last(P) -> exit(P, kill), erlang:garbage_collect(P).
gc_only(P) -> erlang:garbage_collect(P).
cpc_last(P) -> exit(P, kill), erlang:check_process_code(P, lists).
cpc_only(P) -> erlang:check_process_code(P, lists).

apply_last(P) -> exit(P, kill), apply(erlang, is_process_alive, [P]).
fun_last(P) -> exit(P, kill), F = fun erlang:is_process_alive/1, F(P).

pc_last(P) ->
    exit(P, kill),
    Port = open_port({spawn, "cat"}, [binary]),
    Port ! {self(), {command, <<"x">>}},
    R = erlang:port_command(Port, <<"y">>),
    port_close(Port),
    {R, is_process_alive(P)}.
pc_only(P) ->
    Port = open_port({spawn, "cat"}, [binary]),
    exit(P, kill),
    pc_tail(Port).
pc_tail(Port) -> erlang:port_command(Port, <<"y">>).
"#;

#[test]
fn tail_bif_waits_to_erts_internal_and_matches_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping tail bif wait test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile tail_bif_wait");
    reference.load(MODULE, &beam).expect("load into erl");
    let expected: Vec<(String, OwnedTerm)> = CASES
        .iter()
        .map(
            |case| match reference.call(MODULE, "run", &[OwnedTerm::Atom((*case).into())]) {
                CallResult::Ok(term) => (case.to_string(), term),
                other => panic!("{MODULE}:run({case}) on erl: {other:?}"),
            },
        )
        .collect();

    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load into arinsal");
    for (case, want) in &expected {
        let arg = Term::atom(global_atoms().intern(case).unwrap());
        let actual = vm
            .eval_scheduled(MODULE, "run", &[arg], 2)
            .expect("scheduled run");
        assert_eq!(actual.term, *want, "{MODULE}:run({case})");
    }
}

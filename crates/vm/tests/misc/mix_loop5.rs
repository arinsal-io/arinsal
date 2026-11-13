//! A remote call to an unloaded module must enter the process's
//! `error_handler` flag, not the hard-coded `error_handler` module.
//! Elixir's parallel compiler sets `Kernel.ErrorHandler` so a struct
//! expanded after a non-`defmodule` form can wait for the defining module.

use arinsal_difftest::{CallResult, RefErl};

#[test]
fn process_flag_error_handler_receives_unloaded_call() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping error_handler differential test");
        return;
    };
    let handler = r#"
-module(mix_loop5_eh).
-export([undefined_function/3, undefined_lambda/3]).
undefined_function(M, F, A) -> {handler, M, F, A}.
undefined_lambda(M, F, A) -> {lambda, M, F, A}.
"#;
    let caller = r#"
-module(mix_loop5_call).
-export([run/0, unloaded/0]).
ensure_code_server() ->
    case whereis(code_server) of
        undefined ->
            register(code_server, spawn(fun() -> receive _ -> ok end end));
        _ -> ok
    end.
run() ->
    code:ensure_loaded(mix_loop5_eh),
    ensure_code_server(),
    Old = erlang:process_flag(error_handler, mix_loop5_eh),
    {Old, missing_mod:nope(7)}.
unloaded() ->
    ensure_code_server(),
    erlang:process_flag(error_handler, mix_loop5_missing_eh),
    try also_missing:nope(1) catch error:undef -> undef end.
"#;
    let handler_beam = reference
        .compile_named("mix_loop5_eh", handler, &[])
        .unwrap();
    let caller_beam = reference
        .compile_named("mix_loop5_call", caller, &[])
        .unwrap();
    reference.load("mix_loop5_eh", &handler_beam).unwrap();
    reference.load("mix_loop5_call", &caller_beam).unwrap();
    for function in ["unloaded", "run"] {
        let expected = reference.call("mix_loop5_call", function, &[]);
        // The test registers a stand-in `code_server`, a registered name of the node: each case
        // runs in a node of its own, as a peer.
        let actual = crate::common::peer_eval(
            &[],
            &[&handler_beam, &caller_beam],
            &format!("mix_loop5_call:{function}()"),
        );
        assert_eq!(expected, CallResult::Ok(actual), "{function}");
    }
}

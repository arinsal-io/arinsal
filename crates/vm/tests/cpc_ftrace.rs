//! A caught stacktrace kept in a variable does not pin old code. After
//! `check_process_code` and purge it is still the symbolic list. A process
//! suspended in the old module does pin it.

use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

#[allow(dead_code)]
#[path = "common/mod.rs"]
mod common;

const V1: &str = r#"
-module(cpc_ftrace_m).
-export([boom/0, wait/0]).
boom() -> error(boom).
wait() -> receive stop -> ok end.
"#;

const V2: &str = r#"
-module(cpc_ftrace_m).
-export([boom/0, wait/0]).
boom() -> error(boom2).
wait() -> receive stop -> ok end.
"#;

const DRIVER: &str = r#"
-module(cpc_ftrace_drv).
-export([run/0]).

run() -> run(?V1, ?V2).

run(V1, V2) ->
    ensure_purger(),
    {module, cpc_ftrace_m} = erlang:load_module(cpc_ftrace_m, V1),
    Self = self(),
    Holder = spawn(fun() ->
        Stack = try cpc_ftrace_m:boom() catch error:Reason:S -> {Reason, S} end,
        Self ! {ready, self()},
        receive {ask, From} ->
            From ! {held, Stack, process_info(self(), current_stacktrace)}
        end
    end),
    Waiter = spawn(fun() ->
        Self ! {ready, self()},
        cpc_ftrace_m:wait()
    end),
    receive {ready, Holder} -> ok end,
    receive {ready, Waiter} -> ok end,
    {module, cpc_ftrace_m} = erlang:load_module(cpc_ftrace_m, V2),
    CheckHolder = erlang:check_process_code(Holder, cpc_ftrace_m),
    CheckWaiter = erlang:check_process_code(Waiter, cpc_ftrace_m),
    Mref = monitor(process, Waiter),
    exit(Waiter, kill),
    Down = receive {'DOWN', Mref, process, Waiter, Reason} -> Reason
           after 2000 -> timeout end,
    CheckAfter = erlang:check_process_code(Holder, cpc_ftrace_m),
    %% A bare node has no code_server. The purger's test soft-purge is the
    %% same prepare/check/complete sequence code:purge uses, on both VMs.
    Ref = make_ref(),
    erts_code_purger ! {test_purge, cpc_ftrace_m, self(), false, Ref},
    receive {started, Ref} -> ok after 2000 -> started_timeout end,
    erts_code_purger ! {continue, Ref},
    receive {continued, Ref} -> ok after 2000 -> continued_timeout end,
    erts_code_purger ! {complete, Ref},
    Purged = receive {test_purge, Res, Ref} -> Res after 2000 -> purge_timeout end,
    Holder ! {ask, self()},
    Held = receive {held, Stack, Info} -> {Stack, Info} after 2000 -> timeout end,
    {CheckHolder, CheckWaiter, Down, CheckAfter, Purged, Held}.

ensure_purger() ->
    case whereis(erts_code_purger) of
        undefined ->
            spawn(erts_code_purger, start, []),
            wait_registered(erts_code_purger);
        _ ->
            ok
    end.

wait_registered(Name) ->
    case whereis(Name) of
        undefined -> receive after 10 -> ok end, wait_registered(Name);
        _ -> ok
    end.
"#;

#[test]
fn caught_stacktrace_does_not_pin_old_code() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping cpc ftrace test");
        return;
    };
    let v1 = reference
        .compile_named("cpc_ftrace_m", V1, &[])
        .expect("compile v1");
    let v2 = reference
        .compile_named("cpc_ftrace_m", V2, &[])
        .expect("compile v2");
    let literal = |bytes: &[u8]| {
        let body = bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        format!("<<{body}>>")
    };
    let source = DRIVER
        .replace("?V1", &literal(&v1))
        .replace("?V2", &literal(&v2));
    let driver = reference
        .compile_named("cpc_ftrace_drv", &source, &[])
        .expect("compile driver");
    reference
        .load("cpc_ftrace_drv", &driver)
        .expect("load driver");
    let expected = reference.call("cpc_ftrace_drv", "run", &[]);
    let mut vm = common::node();
    common::load_fresh(&mut vm, &driver);
    let actual = vm
        .eval_scheduled("cpc_ftrace_drv", "run", &[], 2)
        .unwrap_or_else(|error| panic!("cpc_ftrace_drv:run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}

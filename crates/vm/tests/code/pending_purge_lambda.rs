//! A process calling a fun into code that is being purged waits in
//! `erts_code_purger:pending_purge_lambda/3` until the purge finishes.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const TARGET_V1: &str = r#"
-module(pp_target).
-export([make/1]).
make(N) -> fun(X) -> X + N end.
"#;

const TARGET_V2: &str = r#"
-module(pp_target).
-export([make/1]).
make(N) -> fun(X) -> X * N end.
"#;

const DRIVER: &str = r#"
-module(pp_driver).
-export([run/0]).

run() -> run(?V1, ?V2).

run(V1, V2) ->
    ensure_purger(),
    {module, pp_target} = erlang:load_module(pp_target, V1),
    F = pp_target:make(4711),
    {module, pp_target} = erlang:load_module(pp_target, V2),
    Before = erlang:fun_info(F, name),
    Ref = make_ref(),
    erts_code_purger ! {test_purge, pp_target, self(), true, Ref},
    receive {started, Ref} -> ok end,
    Self = self(),
    P = spawn(fun() ->
                      R = try F(1) catch error:{badfun, _} -> badfun end,
                      Self ! {self(), R}
              end),
    Suspended = wait_suspended(P, 50),
    Current = process_info(P, current_function),
    Pending = erlang:fun_info(F, name),
    erts_code_purger ! {continue, Ref},
    receive {continued, Ref} -> ok end,
    erts_code_purger ! {complete, Ref},
    Purge = receive {test_purge, Res, Ref} -> Res end,
    Called = receive {P, R} -> R after 5000 -> timeout end,
    After = erlang:fun_info(F, name),
    catch erlang:purge_module(pp_target),
    catch erlang:delete_module(pp_target),
    catch erlang:purge_module(pp_target),
    {Before, Suspended, Current, Pending, Purge, Called, After}.

%% A bare VM without a boot script has no purger process yet.
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

wait_suspended(_P, 0) ->
    timeout;
wait_suspended(P, N) ->
    case process_info(P, status) of
        {status, suspended} -> suspended;
        _ -> receive after 20 -> ok end, wait_suspended(P, N - 1)
    end.
"#;

#[test]
fn pending_purge_lambda_matches_erl() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping pending purge lambda test");
        return;
    };
    let v1 = reference
        .compile_named("pp_target", TARGET_V1, &[])
        .expect("compile v1");
    let v2 = reference
        .compile_named("pp_target", TARGET_V2, &[])
        .expect("compile v2");
    // The two target versions are embedded as binary literals of the driver.
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
        .compile_named("pp_driver", &source, &[])
        .expect("compile driver");
    reference.load("pp_driver", &driver).expect("load driver");
    let expected = reference.call("pp_driver", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&driver).expect("load VM driver");
    let actual = vm
        .eval_scheduled("pp_driver", "run", &[], 2, None)
        .unwrap_or_else(|error| panic!("pp_driver:run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}

//! A process queued before a second `load_module` must run its first call with the old code, so
//! `purge_module` finds it in a different old-code function after a dirty BIF and kills it
//! (dirty_nif_SUITE:code_purge). The loader stays suspended until the code barrier commits.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const TARGET: &str = r#"
-module(dpr_target).
-export([func/1]).
func(Fun) -> dirty_continuation(Fun).
dirty_continuation(Fun) -> Fun(), blipp:blapp().
"#;

const DRIVER: &str = r#"
-module(dpr_driver).
-export([run/0]).
run() ->
    ensure_purger(),
    Bin = ?TARGET,
    Wait = fun() -> erts_debug:dirty_io(wait, 1500) end,
    {module, dpr_target} = erlang:load_module(dpr_target, Bin),
    {P1, M1} = spawn_monitor(fun() -> dpr_target:func(Wait) end),
    {module, dpr_target} = erlang:load_module(dpr_target, Bin),
    {P2, M2} = spawn_monitor(fun() -> dpr_target:func(Wait) end),
    receive {'DOWN', M1, process, P1, _} -> premature after 100 -> ok end,
    Purged = erlang:purge_module(dpr_target),
    R1 = receive {'DOWN', M1, process, P1, R} -> R end,
    P2Alive = receive {'DOWN', M2, process, P2, _} -> false after 100 -> true end,
    {Purged, R1, P2Alive}.

ensure_purger() ->
    case whereis(erts_code_purger) of
        undefined -> spawn(erts_code_purger, start, []), wait_registered();
        _ -> ok
    end.

wait_registered() ->
    case whereis(erts_code_purger) of
        undefined -> receive after 10 -> ok end, wait_registered();
        _ -> ok
    end.
"#;

#[test]
fn purge_kills_process_running_dirty_bif_in_old_code() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dirty purge test");
        return;
    };
    let target = reference
        .compile_named("dpr_target", TARGET, &[])
        .expect("compile target");
    let body = target
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let source = DRIVER.replace("?TARGET", &format!("<<{body}>>"));
    let driver = reference
        .compile_named("dpr_driver", &source, &[])
        .expect("compile driver");
    reference.load("dpr_driver", &driver).expect("load driver");
    let expected = reference.call("dpr_driver", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&driver).expect("load VM driver");
    let actual = vm
        .eval_scheduled("dpr_driver", "run", &[], 4, None)
        .map(|value| value.term)
        .unwrap_or_else(|error| panic!("dpr_driver:run: {error}"));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual));
}

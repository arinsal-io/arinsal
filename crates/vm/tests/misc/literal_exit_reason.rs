//! A literal exit reason stays valid through process exit and module purge.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const TARGET: &str = r#"
-module(ler_target).
-export([lit/0]).
lit() -> {literal_reason, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], <<"literal binary reason">>}.
"#;

const DRIVER: &str = r#"
-module(ler_driver).
-export([run/0]).
run() ->
    ensure_purger(),
    Bin = ?TARGET,
    {module, ler_target} = erlang:load_module(ler_target, Bin),
    Rs = [begin
              {P, M} = spawn_monitor(fun() -> exit(ler_target:lit()) end),
              receive {'DOWN', M, process, P, R} -> R end
          end || _ <- lists:seq(1, 50)],
    true = erlang:delete_module(ler_target),
    true = erlang:purge_module(ler_target),
    receive after 200 -> ok end,
    {lists:usort(Rs), whereis(erts_literal_area_collector) =/= undefined}.

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
fn literal_exit_reason_survives_purge() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping literal exit reason test");
        return;
    };
    let target = reference
        .compile_named("ler_target", TARGET, &[])
        .expect("compile target");
    let body = target
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let source = DRIVER.replace("?TARGET", &format!("<<{body}>>"));
    let driver = reference
        .compile_named("ler_driver", &source, &[])
        .expect("compile driver");
    reference.load("ler_driver", &driver).expect("load driver");
    let expected = reference.call("ler_driver", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&driver).expect("load VM driver");
    let actual = vm
        .eval_scheduled("ler_driver", "run", &[], 4, None)
        .map(|value| value.term)
        .unwrap_or_else(|error| panic!("ler_driver:run: {error}"));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual));
}

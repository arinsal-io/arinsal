//! Literal-area purges while many processes are switched out must only root the
//! live X registers recorded at the switch-out point. Rooting dead registers
//! with stale pointers corrupted live terms, which killed `erts_code_purger`
//! (code_SUITE:many_purges).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const TARGET: &str = r#"
-module(sol_target).
-export([lit/0]).
lit() -> {a, [1, 2, 3], <<"literal binary data">>, #{k => v}}.
"#;

const DRIVER: &str = r#"
-module(sol_driver).
-export([run/0]).

run() ->
    ensure_purger(),
    Purger = whereis(erts_code_purger),
    Mon = monitor(process, Purger),
    Ps = [spawn_monitor(fun worker/0) || _ <- lists:seq(1, 300)],
    Self = self(),
    Runner = spawn(fun() -> Self ! {done, rounds(20, ?TARGET)} end),
    Result = receive
                 {done, R} -> R;
                 {'DOWN', Mon, _, _, Reason} -> {purger_down, Reason}
             after 30000 ->
                 {timeout, process_info(Runner, current_stacktrace)}
             end,
    %% Stop the workers only once the collector has released the last area and
    %% wait for them, so nothing still runs when the entry process returns.
    wait_collector_idle(),
    [exit(P, kill) || {P, _} <- Ps],
    [receive {'DOWN', M, process, P, _} -> ok end || {P, M} <- Ps],
    demonitor(Mon, [flush]),
    Alive = is_process_alive(Purger),
    {Result, Alive}.

rounds(0, _) ->
    ok;
rounds(N, Bin) ->
    {module, sol_target} = erlang:load_module(sol_target, Bin),
    _ = sol_target:lit(),
    true = erlang:delete_module(sol_target),
    true = erlang:purge_module(sol_target),
    rounds(N - 1, Bin).

worker() ->
    _ = lists:seq(1, rand:uniform(100)),
    receive after rand:uniform(10) -> ok end,
    worker().

%% Ask the literal area collector (erts_literal_area_collector.erl, get_status)
%% until it has no area left to release.
wait_collector_idle() ->
    [Collector] = [P || P <- processes(),
                        process_info(P, initial_call) =:=
                            {initial_call, {erts_literal_area_collector, start, 0}}],
    wait_collector_idle(Collector).

wait_collector_idle(Collector) ->
    Ref = make_ref(),
    Collector ! {get_status, Ref, self()},
    receive
        {Ref, idle} -> ok;
        {Ref, working} -> receive after 10 -> ok end, wait_collector_idle(Collector)
    end.

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
"#;

#[test]
fn many_purges_keep_purger_alive() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping purge switch-out live test");
        return;
    };
    let target = reference
        .compile_named("sol_target", TARGET, &[])
        .expect("compile target");
    let body = target
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let source = DRIVER.replace("?TARGET", &format!("<<{body}>>"));
    let driver = reference
        .compile_named("sol_driver", &source, &[])
        .expect("compile driver");
    reference.load("sol_driver", &driver).expect("load driver");
    let expected = reference.call("sol_driver", "run", &[]);
    // A dead purger leaves its literal area retired, which would block
    // `eval_scheduled` forever; bound the run so the regression fails instead.
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut vm = Vm::new([]);
        vm.load_bytes(&driver).expect("load VM driver");
        let actual = vm
            .eval_scheduled("sol_driver", "run", &[], 4, None)
            .map(|value| value.term)
            .map_err(|error| error.to_string());
        let _ = sender.send(actual);
    });
    let actual = receiver
        .recv_timeout(std::time::Duration::from_secs(120))
        .expect("sol_driver:run did not finish (literal area never released)")
        .unwrap_or_else(|error| panic!("sol_driver:run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual));
}

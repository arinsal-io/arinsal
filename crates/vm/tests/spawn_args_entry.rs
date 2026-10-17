//! Spawn entry glue: a spawn request leaves `apply/3` operands in X0..X2 (arity 3) whatever the
//! argument count; a spawned BIF runs on the argument list, wide argument lists survive the
//! first schedule-in, and a hibernated process resumes with its `apply/3` arguments.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, decode, encode};
use arinsal_vm::Vm;

#[test]
fn spawn_entry_arguments_match_otp() {
    let Ok(reference) = RefErl::start() else {
        return;
    };
    let source = r#"-module(spawn_args_entry).
        -export([run/0, five/5, eight/8, hib/1, hib2/8]).
        five(P, A, B, C, D) -> P ! {done, five, A+B+C+D}.
        eight(P, A, B, C, D, E, F, G) -> P ! {done, eight, A+B+C+D+E+F+G}.
        hib(P) -> erlang:hibernate(spawn_args_entry, hib2, [P, 1, 2, 3, 4, 5, 6, 7]).
        hib2(P, A, B, C, D, E, F, G) -> P ! {done, hib, A+B+C+D+E+F+G}.
        w(N, Acc) when N =:= 0 -> lists:sort(Acc);
        w(N, Acc) -> receive {done, K, V} -> w(N - 1, [{K, V} | Acc]) after 5000 -> {timeout, Acc} end.
        run() ->
            S = self(),
            {_, R1} = spawn_monitor(erlang, exit, [foo]),
            D1 = receive {'DOWN', R1, _, _, Rs1} -> Rs1 end,
            {_, R2} = spawn_monitor(erlang, error, [bar]),
            D2 = receive {'DOWN', R2, _, _, Rs2} -> element(1, Rs2) end,
            spawn(spawn_args_entry, five, [S, 1, 2, 3, 4]),
            spawn(spawn_args_entry, eight, [S, 1, 2, 3, 4, 5, 6, 7]),
            spawn(fun() -> eight(S, 7, 6, 5, 4, 3, 2, 1) end),
            H = spawn(spawn_args_entry, hib, [S]), timer:sleep(50), H ! wake,
            erlang:garbage_collect(),
            {D1, D2, w(4, [])}."#;
    let beam = reference
        .compile_named("spawn_args_entry", source, &[])
        .unwrap();
    reference.load("spawn_args_entry", &beam).unwrap();
    let expected = reference.call("spawn_args_entry", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("spawn_args_entry", "run", &[], 2, None)
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}

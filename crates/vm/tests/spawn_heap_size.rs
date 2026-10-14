//! A spawned process starts on a heap that holds its copied arguments and the reserved words,
//! rounded up to a heap size, like erts' `erl_create_process`: `heap_size` and `total_heap_size`
//! right after the spawn match erl for small and large arguments and for `min_heap_size`.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"-module(spawn_heap_size).
-export([run/0, wait/2]).

run() ->
    [probe(N, Opts) || N <- [0, 1, 50, 1000, 40000, 100000, 800000],
                       Opts <- [[], [{min_heap_size, 5000}]]].

probe(N, Opts) ->
    L = lists:seq(1, N),
    Pid = spawn_opt(spawn_heap_size, wait, [L, self()], Opts),
    receive {ready, Pid} -> ok end,
    {heap_size, H} = process_info(Pid, heap_size),
    {total_heap_size, T} = process_info(Pid, total_heap_size),
    Pid ! stop,
    {N, Opts, H, T}.

wait(L, Parent) ->
    Parent ! {ready, self()},
    receive stop -> length(L) end.
"#;

#[test]
fn spawned_process_heap_is_sized_like_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping spawn_heap_size differential test");
        return;
    };
    let beam = reference
        .compile_named("spawn_heap_size", SOURCE, &[])
        .expect("compile spawn_heap_size");
    reference
        .load("spawn_heap_size", &beam)
        .expect("load into erl");
    let expected = reference.call("spawn_heap_size", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled("spawn_heap_size", "run", &[], 2, None)
        .expect("scheduled run");
    assert_eq!(expected, CallResult::Ok(actual.term));
}

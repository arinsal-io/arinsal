use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const MODULE: &str = "spawn_priority_diff";
const SOURCE: &str = r#"
-module(spawn_priority_diff).
-behaviour(gen_server).
-export([run/0, init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

run() ->
    Parent = self(),
    Spawned = spawn_opt(
        fun() -> receive stop -> Parent ! {spawn_done, self()} end end,
        [{priority, high}]),
    SpawnPriority = process_info(Spawned, priority),
    Spawned ! stop,
    receive {spawn_done, Spawned} -> ok end,
    ProcLib = proc_lib:spawn_opt(
        fun() -> receive stop -> Parent ! {proclib_done, self()} end end,
        [{priority, high}]),
    ProcLibPriority = process_info(ProcLib, priority),
    ProcLib ! stop,
    receive {proclib_done, ProcLib} -> ok end,
    {ok, Server} = gen_server:start_link(
        spawn_priority_diff, [], [{spawn_opt, [{priority, high}]}]),
    ServerPriority = process_info(Server, priority),
    ok = gen_server:stop(Server),
    {SpawnPriority, ProcLibPriority, ServerPriority}.

init(State) -> {ok, State}.
handle_call(_Request, _From, State) -> {reply, ok, State}.
handle_cast(_Request, State) -> {noreply, State}.
handle_info(_Info, State) -> {noreply, State}.
terminate(_Reason, _State) -> ok.
code_change(_Old, State, _Extra) -> {ok, State}.
"#;

#[test]
fn spawn_opt_priority_is_visible_through_spawn_proc_lib_and_gen_server() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "run", &[], 1, Some(0x5052))
        .unwrap();

    let high = OwnedTerm::Tuple(vec![OwnedTerm::atom("priority"), OwnedTerm::atom("high")]);
    similar_asserts::assert_eq!(
        expected,
        CallResult::Ok(OwnedTerm::Tuple(vec![high.clone(), high.clone(), high,]))
    );
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

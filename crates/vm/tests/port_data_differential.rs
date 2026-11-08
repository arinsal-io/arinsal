use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(port_data_race_diff).
-export([run/0]).

run() ->
    Port = open_port({spawn, "cat"}, []),
    HeapData = {1, 2, 3, <<"A heap binary">>, fun() -> "This is fun" end,
                list_to_binary(lists:seq(1, 100))},
    PRs = [spawn_opt(fun() -> hammer(Port, HeapData, false) end,
                     [monitor]) || _ <- lists:seq(1, 10)],
    receive after 100 -> ok end,
    Papa = self(),
    [Pid ! {Papa, prepare_for_close} || {Pid, _} <- PRs],
    [receive {Pid, prepare_for_close} -> ok end || {Pid, _} <- PRs],
    port_close(Port),
    [receive {'DOWN', Ref, process, Pid, normal} -> ok end || {Pid, Ref} <- PRs],
    ok.

hammer(Port, HeapData, WasSet) ->
    Result = try case rand:uniform(3) of
        1 -> true = erlang:port_set_data(Port, atom), true;
        2 -> true = erlang:port_set_data(Port, HeapData), true;
        3 -> case erlang:port_get_data(Port) of
            atom -> true;
            HeapData -> true;
            undefined -> false = WasSet
        end
    end catch
        error:badarg ->
            true = get(prepare_for_close),
            exit(normal)
    end,
    receive {Papa, prepare_for_close} ->
        put(prepare_for_close, true),
        Papa ! {self(), prepare_for_close}
    after 0 -> ok
    end,
    hammer(Port, HeapData, Result).
"#;

#[test]
fn port_set_get_data_race_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping port data differential");
        return;
    };
    let beam = reference
        .compile_named("port_data_race_diff", SOURCE, &[])
        .expect("compile");
    reference.load("port_data_race_diff", &beam).unwrap();
    let expected = reference.call("port_data_race_diff", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load");
    let actual = vm
        .eval_scheduled("port_data_race_diff", "run", &[], 8, None)
        .expect("run");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

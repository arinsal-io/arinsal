use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const MODULE: &str = "otp_triage_d_differential";
const SOURCE: &str = r#"
-module(otp_triage_d_differential).
-export([run/1]).

run(named_port) ->
    Port = open_port({spawn, "cat"}, []),
    true = register(triage_d_port, Port),
    try
        {registered_name, triage_d_port} = erlang:port_info(triage_d_port, registered_name),
        true = erlang:port_connect(triage_d_port, self()),
        Info = erlang:port_info(triage_d_port),
        Control = try erlang:port_control(triage_d_port, 256, [])
                  catch error:badarg -> badarg end,
        {lists:keymember(registered_name, 1, Info), Control}
    after
        catch erlang:port_close(triage_d_port)
    end;
run(busy_port) ->
    Port = open_port({spawn, "sleep 5"},
                     [{busy_limits_port, {1, 1}}, {busy_limits_msgq, {1, 1}}]),
    Parent = self(),
    Data = lists:duplicate(100, $x),
    {Sender, Ref} = spawn_monitor(fun() -> send_until_busy(Port, Parent, Data) end),
    try
        wait_suspended(Sender, 3000)
    after
        exit(Sender, kill),
        catch erlang:port_close(Port),
        receive {'DOWN', Ref, process, Sender, _} -> ok after 1000 -> ok end
    end;
run(port_counts) ->
    Port = open_port({spawn, "cat"}, [binary]),
    try
        true = erlang:port_command(Port, <<"abc">>),
        receive {Port, {data, <<"abc">>}} -> ok after 1000 -> timeout end,
        {erlang:port_info(Port, input), erlang:port_info(Port, output)}
    after
        catch erlang:port_close(Port)
    end;
run(queue_heap) ->
    {on_heap, queue_heap_size(on_heap), off_heap, queue_heap_size(off_heap)};
run(mul_add) ->
    [mul_frame(fun() -> madd(a, 2, 0) end),
     mul_frame(fun() -> madd(3, b, c) end),
     mul_frame(fun() -> madd(2, 3, c) end)];
run(unicode_float) ->
    try unicode:characters_to_binary([1, 2, 3, 4.0], unicode)
    catch error:badarg -> badarg end;
run(unicode_list_float) ->
    try unicode:characters_to_list([1, 2, 3, 4.0], utf16)
    catch error:badarg -> badarg end;
run(zlib_owner) -> zlib_owner();
run(unknown) -> unknown.

send_until_busy(Port, Parent, Data) ->
    Port ! {Parent, {command, Data}},
    send_until_busy(Port, Parent, Data).

wait_suspended(_Pid, 0) -> false;
wait_suspended(Pid, Left) ->
    case process_info(Pid, status) of
        {status, suspended} -> true;
        _ -> receive after 10 -> wait_suspended(Pid, Left - 10) end
    end.

queue_heap_size(Mode) ->
    Fun = fun F() -> receive Pid when is_pid(Pid) -> Pid ! ok, F() end end,
    Pid = spawn_opt(Fun, [{message_queue_data, Mode}]),
    {total_heap_size, Before} = process_info(Pid, total_heap_size),
    [Pid ! lists:duplicate(N, N) || N <- lists:seq(1, 100)],
    Pid ! self(),
    receive ok -> ok end,
    {total_heap_size, After} = process_info(Pid, total_heap_size),
    exit(Pid, kill),
    {Before, After}.

madd(A, B, C) -> A * B + C.
mul_frame(Fun) ->
    {'EXIT', {badarith, [{Module, Function, Args, _} | _]}} = (catch Fun()),
    {Module, Function, Args}.

zlib_owner() ->
    Z = zlib:open(),
    Owner = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        First = normalize(catch zlib:inflateReset(Z)),
        Owner ! {self(), first, First},
        receive transfer ->
            Second = normalize(catch zlib:inflateReset(Z)),
            Closed = normalize(catch zlib:close(Z)),
            Owner ! {self(), second, Second, Closed}
        end
    end),
    receive {Pid, first, First} ->
        ok = zlib:set_controlling_process(Z, Pid),
        Pid ! transfer,
        receive {Pid, second, Second, Closed} ->
            receive {'DOWN', Ref, process, Pid, normal} -> {First, Second, Closed} end
        end
    end.

normalize({'EXIT', {Reason, _Stack}}) -> Reason;
normalize(Result) -> Result.
"#;

#[test]
fn otp_case_roots_match_otp_29_1_1() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping OTP triage_d differential scenarios");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile differential scenarios");
    reference.load(MODULE, &beam).expect("load into erl");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into Arinsal");

    for case in [
        "named_port",
        "busy_port",
        "port_counts",
        "queue_heap",
        "mul_add",
        "unicode_float",
        "unicode_list_float",
        "zlib_owner",
    ] {
        let expected = reference.call(MODULE, "run", &[OwnedTerm::Atom(case.into())]);
        let argument = Term::atom(global_atoms().intern(case).expect("case atom"));
        let actual = vm
            .eval_scheduled(MODULE, "run", &[argument], 1, None)
            .unwrap_or_else(|error| panic!("{MODULE}:run({case}): {error}"));
        assert_eq!(
            expected,
            CallResult::Ok(actual.term),
            "{MODULE}:run({case})"
        );
    }
}

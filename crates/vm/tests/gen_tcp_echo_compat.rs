use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(gen_tcp_echo_compat).
-export([read_ahead_packet_echo/0]).

read_ahead_packet_echo() ->
    catch ets:new(ac_tab, [named_table, public, set]),
    {ok, Listen} = gen_tcp:listen(0, [{tcp_module, inet_tcp},
                                     {ip, {127,0,0,1}}, binary,
                                     {active, false}]),
    {ok, Port} = inet:port(Listen),
    Echo = fun Loop(Socket) ->
        case gen_tcp:recv(Socket, 0) of
            {ok, Data} -> ok = gen_tcp:send(Socket, Data), Loop(Socket);
            {error, closed} -> ok
        end
    end,
    spawn_link(fun() -> {ok, Socket} = gen_tcp:accept(Listen), Echo(Socket) end),
    {ok, Client} = gen_tcp:connect({127,0,0,1}, Port,
                                  [{tcp_module, inet_tcp},
                                   {packet, 4}, {read_ahead, false}]),
    Options = inet:getopts(Client, [read_ahead]),
    ok = gen_tcp:send(Client, lists:duplicate(70000, $x)),
    Size = receive
        {tcp, Client, Packet} -> length(Packet)
    after 5000 -> timeout
    end,
    gen_tcp:close(Client),
    gen_tcp:close(Listen),
    {Options, Size}.
"#;

#[test]
fn read_ahead_packet_echo_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping gen_tcp echo differential test");
        return;
    };
    let beam = reference
        .compile_named("gen_tcp_echo_compat", SOURCE, &[])
        .expect("compile gen_tcp_echo_compat");
    reference
        .load("gen_tcp_echo_compat", &beam)
        .expect("load gen_tcp_echo_compat");
    let expected = reference.call("gen_tcp_echo_compat", "read_ahead_packet_echo", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled(
            "gen_tcp_echo_compat",
            "read_ahead_packet_echo",
            &[],
            2,
            None,
        )
        .expect("Arinsal read_ahead_packet_echo");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

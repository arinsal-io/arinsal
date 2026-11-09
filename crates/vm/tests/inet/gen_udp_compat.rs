use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(gen_udp_compat).
-export([buffer_cap/0, ipv6_class_opts/0, fd_lookup/0]).

buffer_cap() ->
    catch ets:new(ac_tab, [named_table, public, set]),
    {ok, S} = gen_udp:open(0, [inet, {ip, {127,0,0,1}}, binary, {active, false}]),
    ok = inet:setopts(S, [{recbuf, 1048576}]),
    {ok, [{buffer, Buffer}]} = inet:getopts(S, [buffer]),
    ok = gen_udp:close(S),
    Buffer.

ipv6_class_opts() ->
    catch ets:new(ac_tab, [named_table, public, set]),
    Loopback = {0,0,0,0,0,0,0,1},
    {ok, S} = gen_udp:open(0, [inet6, {ip, Loopback}, binary, {active, false}]),
    Recv = inet:setopts(S, [{recvtclass, true}]),
    Class = inet:setopts(S, [{tclass, 224}]),
    Got = inet:getopts(S, [recvtclass, tclass]),
    ok = gen_udp:close(S),
    {Recv, Class, Got}.

fd_lookup() ->
    catch ets:new(ac_tab, [named_table, public, set]),
    {ok, S} = gen_udp:open(0, [inet, {ip, {127,0,0,1}}]),
    Result = case prim_inet:getfd(S) of
        {ok, Fd} -> {is_integer(Fd), gen_udp:open(0, [inet6, {fd, Fd}])};
        GetFdError -> GetFdError
    end,
    ok = gen_udp:close(S),
    Result.

"#;

#[test]
fn udp_options_and_fd_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping gen_udp differential test");
        return;
    };
    let beam = reference
        .compile_named("gen_udp_compat", SOURCE, &[])
        .expect("compile gen_udp_compat");
    reference
        .load("gen_udp_compat", &beam)
        .expect("load gen_udp_compat");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    for function in ["buffer_cap", "ipv6_class_opts", "fd_lookup"] {
        let expected = reference.call("gen_udp_compat", function, &[]);
        let actual = vm
            .eval_scheduled("gen_udp_compat", function, &[], 2, None)
            .unwrap_or_else(|error| panic!("Arinsal {function}: {error}"));
        similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}

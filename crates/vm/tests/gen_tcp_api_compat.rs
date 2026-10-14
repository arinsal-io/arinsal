use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(gen_tcp_api_compat).
-export([ipv6_accept/0]).

ipv6_accept() ->
    catch ets:new(ac_tab, [named_table, public, set]),
    ets:insert(ac_tab, {{env, kernel, inet_default_listen_options}, []}),
    ets:insert(ac_tab, {{env, kernel, inet_default_connect_options}, []}),
    Loopback = {0,0,0,0,0,0,0,1},
    Opts = [inet6, {ip, Loopback}],
    {ok, Listen} = gen_tcp:listen(0, Opts),
    {ok, {_, Port}} = inet:sockname(Listen),
    {ok, Client} = gen_tcp:connect(Loopback, Port, [inet6], 1000),
    Result = case gen_tcp:accept(Listen, 1000) of
        {ok, Accepted} ->
            ok = gen_tcp:close(Accepted),
            accepted;
        Error -> Error
    end,
    ok = gen_tcp:close(Client),
    ok = gen_tcp:close(Listen),
    Result.
"#;

#[test]
fn ipv6_loopback_accept_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping gen_tcp API differential test");
        return;
    };
    let beam = reference
        .compile_named("gen_tcp_api_compat", SOURCE, &[])
        .expect("compile gen_tcp_api_compat");
    reference
        .load("gen_tcp_api_compat", &beam)
        .expect("load gen_tcp_api_compat");
    let expected = reference.call("gen_tcp_api_compat", "ipv6_accept", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled("gen_tcp_api_compat", "ipv6_accept", &[], 2, None)
        .expect("Arinsal ipv6_accept");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

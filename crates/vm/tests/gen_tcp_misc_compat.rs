use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(gen_tcp_misc_compat).
-export([primitive_accept/0, several_accepts_waiting/0]).

primitive_accept() ->
    catch ets:new(ac_tab, [named_table, public, set]),
    {ok, Listen} = gen_tcp:listen(0, [{tcp_module, inet_tcp}, {ip, {127,0,0,1}}, binary,
                                      {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Listen),
    Parent = self(),
    spawn(fun() -> Parent ! {accepted, gen_tcp:accept(Listen)} end),
    {ok, Client} = gen_tcp:connect({127,0,0,1}, Port,
                                   [{tcp_module, inet_tcp}, binary,
                                    {active, false}], 2000),
    Result = receive
        {accepted, {ok, Accepted}} ->
            gen_tcp:close(Accepted),
            ok;
        {accepted, Other} -> Other
    after 500 -> timeout
    end,
    gen_tcp:close(Client),
    gen_tcp:close(Listen),
    Result.

several_accepts_waiting() ->
    catch ets:new(ac_tab, [named_table, public, set]),
    N = 8,
    {ok, Listen} = gen_tcp:listen(0, [{tcp_module, inet_tcp}, {active, false},
                                     {reuseaddr, true}, {backlog, N}, {ip, {127,0,0,1}}]),
    {ok, Port} = inet:port(Listen),
    Parent = self(),
    [spawn(fun() -> Parent ! {accepted, gen_tcp:accept(Listen)} end)
     || _ <- lists:seq(1, N)],
    receive after 500 -> ok end,
    Clients = [begin
                   {ok, Client} = gen_tcp:connect({127,0,0,1}, Port,
                                                  [{tcp_module, inet_tcp},
                                                   {active, false}], 2000),
                   Client
               end || _ <- lists:seq(1, N)],
    Result = collect_accepts(N),
    [gen_tcp:close(Client) || Client <- Clients],
    gen_tcp:close(Listen),
    Result.

collect_accepts(0) -> ok;
collect_accepts(N) ->
    receive
        {accepted, {ok, Socket}} ->
            gen_tcp:close(Socket),
            collect_accepts(N - 1);
        {accepted, Error} -> Error
    after 15000 -> timeout
    end.
"#;

fn compare(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping gen_tcp_misc differential test");
        return;
    };
    let beam = reference
        .compile_named("gen_tcp_misc_compat", SOURCE, &[])
        .expect("compile gen_tcp_misc_compat");
    reference
        .load("gen_tcp_misc_compat", &beam)
        .expect("load gen_tcp_misc_compat");
    let expected = reference.call("gen_tcp_misc_compat", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled("gen_tcp_misc_compat", function, &[], 2, None)
        .unwrap_or_else(|error| panic!("Arinsal {function}: {error}"));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn primitive_accept_matches_erts() {
    compare("primitive_accept");
}

#[test]
fn several_accepts_waiting_matches_erts() {
    compare("several_accepts_waiting");
}

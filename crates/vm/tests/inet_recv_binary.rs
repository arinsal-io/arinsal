use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

// Packets read into a binary of their own and delivered as sub-binaries of it, or copied when
// small, in active, once and passive modes with packet headers and `{header, N}`.
const SOURCE: &str = r#"
-module(inet_recv_binary).
-export([t/0]).
%% receive paths: active/once/passive, packet 0/2/4/line, binary mode, header, sizes around 64
t() -> catch ets:new(ac_tab, [named_table, public, set]), [one(Pk, Act, Sz, H) || Pk <- [2, 4], Act <- [true, once, false], Sz <- [1, 63, 64, 65, 66, 300, 70000], H <- [0, 5]].
one(Pk, Act, Sz, H) ->
  {ok, L} = gen_tcp:listen(0, [{tcp_module, inet_tcp}, binary, {ip,{127,0,0,1}}, {active,false}, {packet,Pk}, {reuseaddr,true}, {header,H}]),
  {ok, P} = inet:port(L), Self = self(),
  Data = list_to_binary([(I*13) rem 251 || I <- lists:seq(1, Sz)]),
  spawn_link(fun() -> {ok, C} = gen_tcp:connect({127,0,0,1}, P, [{tcp_module, inet_tcp}, binary,{active,false},{packet,Pk}]),
      ok = gen_tcp:send(C, Data), ok = gen_tcp:send(C, Data), receive stop -> ok after 5000 -> ok end, gen_tcp:close(C), Self ! cdone end),
  {ok, S} = gen_tcp:accept(L),
  ok = inet:setopts(S, [{active, Act}]),
  R = case Act of
        false -> [rp(S, Pk, Sz), rp(S, Pk, Sz)];
        _ -> [ra(S, Act, Pk, Sz), ra(S, Act, Pk, Sz)]
      end,
  gen_tcp:close(S), gen_tcp:close(L),
  {Pk, Act, Sz, H, R}.
rp(S, 0, Sz) -> {ok, B} = gen_tcp:recv(S, Sz, 5000), B;
rp(S, _, _) -> {ok, B} = gen_tcp:recv(S, 0, 5000), B.
ra(S, Act, Pk, Sz) -> receive {tcp, S, D} -> (Act =:= once andalso inet:setopts(S, [{active, once}])), norm(Pk, D, Sz) after 5000 -> timeout end.
norm(0, D, Sz) when is_binary(D), byte_size(D) < Sz -> more(D, Sz);
norm(_, D, _) -> D.
more(D, _) -> D.
"#;

#[test]
fn recv_packets_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inet receive differential test");
        return;
    };
    let beam = reference
        .compile_named("inet_recv_binary", SOURCE, &[])
        .expect("compile inet_recv_binary");
    reference
        .load("inet_recv_binary", &beam)
        .expect("load inet_recv_binary");
    let expected = reference.call("inet_recv_binary", "t", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled("inet_recv_binary", "t", &[], 2, None)
        .expect("Arinsal inet_recv_binary");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

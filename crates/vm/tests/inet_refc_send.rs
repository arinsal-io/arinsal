use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

// A send of refc binaries (whole, sub-binary, mixed iolist) is queued by reference and
// written with writev, through partial writes on a small send buffer.
const SOURCE: &str = r#"
-module(inet_refc_send).
-export([t/0]).
t() ->
  catch ets:new(ac_tab, [named_table, public, set]),
  Big = list_to_binary([(I * 7 + I div 251) rem 256 || I <- lists:seq(1, 3*1024*1024)]),
  <<_:100/binary, Sub:2000000/binary, _/binary>> = Big,
  Cases = [Big, Sub, [<<1,2,3>>, Big, "abc", [Sub, 7]], binary:copy(<<5>>,65), <<1,2,3>>, [Sub, Sub], binary:part(Big, 5, 70)],
  R = [one(C, Mode) || C <- Cases, Mode <- [0, 4]],
  R.
one(C, Pk) ->
  {ok, L} = gen_tcp:listen(0, [{tcp_module, inet_tcp}, binary, {ip,{127,0,0,1}}, {active,false}, {packet,0}, {reuseaddr,true}, {sndbuf, 4096}, {recbuf, 4096}]),
  {ok, P} = inet:port(L),
  Self = self(),
  Size = iolist_size(C),
  spawn_link(fun() -> {ok, S} = gen_tcp:accept(L), timer:sleep(200),
     Self ! {got, recv_all(S, Size + case Pk of 4 -> 4; _ -> 0 end, [])} end),
  {ok, Cs} = gen_tcp:connect({127,0,0,1}, P, [{tcp_module, inet_tcp}, binary,{active,false},{packet,Pk},{sndbuf,4096}]),
  ok = gen_tcp:send(Cs, C),
  Got = receive {got, G} -> G after 20000 -> timeout end,
  gen_tcp:close(Cs), gen_tcp:close(L),
  {Size, erlang:md5(Got) =:= erlang:md5(case Pk of 4 -> <<Size:32, (iolist_to_binary(C))/binary>>; _ -> iolist_to_binary(C) end)}.
recv_all(_, 0, Acc) -> iolist_to_binary(lists:reverse(Acc));
recv_all(S, N, Acc) -> {ok, B} = gen_tcp:recv(S, 0, 10000), recv_all(S, N - byte_size(B), [B|Acc]).
"#;

#[test]
fn refc_binary_send_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping inet refc send differential test");
        return;
    };
    let beam = reference
        .compile_named("inet_refc_send", SOURCE, &[])
        .expect("compile inet_refc_send");
    reference
        .load("inet_refc_send", &beam)
        .expect("load inet_refc_send");
    let expected = reference.call("inet_refc_send", "t", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled("inet_refc_send", "t", &[], 2, None)
        .expect("Arinsal inet_refc_send");
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}

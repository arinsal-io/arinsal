//! A passive `{packet, 4}` socket delivers packets around the 64-byte heap-binary limit, with
//! the data there before `recv` or before the options are set, after a hand-off to another
//! process, and when it then turns active (`gen_rpc` handshake shape). erl is the reference.

use std::process::Command;

const MODULE_A: &str = r#"-module(tcp_packet4_a).
-export([run/0]).
run() ->
    [io:format("~p~n", [{Size, Mode, one(Size, Mode)}])
     || Size <- [60, 64, 65, 69, 200, 70000], Mode <- [direct, late_recv, handoff, setopts_after]],
    halt().
one(Size, Mode) ->
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127,0,0,1}}, {reuseaddr, true}]),
    {ok, P} = inet:port(L),
    Payload = binary:copy(<<"x">>, Size),
    spawn_link(fun() ->
        {ok, C} = gen_tcp:connect({127,0,0,1}, P, [binary, {active, false}, {packet, 4}]),
        ok = gen_tcp:send(C, Payload),
        receive stop -> ok after 8000 -> ok end,
        gen_tcp:close(C)
    end),
    {ok, S} = gen_tcp:accept(L, 5000),
    R = case Mode of
        direct ->
            ok = inet:setopts(S, [{packet, 4}, {active, false}]),
            gen_tcp:recv(S, 0, 5000);
        late_recv ->
            ok = inet:setopts(S, [{packet, 4}, {active, false}]),
            timer:sleep(300),
            gen_tcp:recv(S, 0, 5000);
        handoff ->
            Self = self(),
            Pid = spawn(fun() -> receive go -> Self ! {res, gen_tcp:recv(S, 0, 5000)} end end),
            ok = inet:setopts(S, [{packet, 4}, {active, false}]),
            ok = gen_tcp:controlling_process(S, Pid),
            timer:sleep(200),
            Pid ! go,
            receive {res, X} -> X after 7000 -> timeout end;
        setopts_after ->
            timer:sleep(300),
            ok = inet:setopts(S, [{packet, 4}, {active, false}]),
            gen_tcp:recv(S, 0, 5000)
    end,
    gen_tcp:close(S), gen_tcp:close(L),
    case R of {ok, B} -> {ok, byte_size(B), B =:= Payload}; Other -> Other end.
"#;
const MODULE_B: &str = r#"-module(tcp_packet4_b).
-export([run/0]).
run() ->
    [io:format("~p~n", [{Size, Gap, one(Size, Gap)}]) || Size <- [10, 60, 64, 65, 69, 200, 70000], Gap <- [0, 100]],
    halt().
one(Size, Gap) ->
    {ok, L} = gen_tcp:listen(0, [binary, {packet,4}, {active,false}, {ip,{127,0,0,1}}, {reuseaddr,true}]),
    {ok, P} = inet:port(L),
    P1 = term_to_binary({first, binary:copy(<<"a">>, 20)}),
    P2 = term_to_binary({second, binary:copy(<<"b">>, Size)}),
    spawn_link(fun() ->
        {ok, C} = gen_tcp:connect({127,0,0,1}, P, [binary, {packet,4}, {active,false}]),
        ok = gen_tcp:send(C, P1),
        timer:sleep(Gap),
        ok = gen_tcp:send(C, P2),
        receive stop -> ok after 8000 -> ok end,
        gen_tcp:close(C)
    end),
    {ok, S} = gen_tcp:accept(L, 5000),
    {ok, D1} = gen_tcp:recv(S, 0, 5000),
    ok = inet:setopts(S, [{active, 100}]),
    R2 = receive {tcp, S, D2} -> {tcp, byte_size(D2), D2 =:= P2}; Other -> Other after 3000 -> timeout end,
    gen_tcp:close(S), gen_tcp:close(L),
    {D1 =:= P1, R2}.
"#;

fn run(program: &str, dir: &std::path::Path, module: &str) -> String {
    let output = Command::new(program)
        .args(["-noshell", "-pa"])
        .arg(dir)
        .args(["-eval", &format!("{module}:run().")])
        .output()
        .unwrap_or_else(|error| panic!("run {program}: {error}"));
    assert!(output.status.success(), "{program} {module}: {output:?}");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn packet4_passive_and_active_match_erl() {
    let dir = std::env::temp_dir().join(format!("arinsal-tcp-packet4-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, source) in [("tcp_packet4_a", MODULE_A), ("tcp_packet4_b", MODULE_B)] {
        let file = dir.join(format!("{name}.erl"));
        std::fs::write(&file, source).unwrap();
        let status = Command::new("erlc")
            .arg("-o")
            .arg(&dir)
            .arg(&file)
            .output()
            .unwrap();
        assert!(status.status.success(), "erlc {name}: {status:?}");
        let expected = run("erl", &dir, name);
        let actual = run(env!("CARGO_BIN_EXE_arinsal"), &dir, name);
        assert_eq!(actual, expected, "{name}");
        assert!(expected.lines().count() > 10, "{name} printed {expected:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

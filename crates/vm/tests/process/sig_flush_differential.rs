//! Signal-flush machinery (`FS_FLUSHING_SIGS` / `FS_FLUSHED_SIGS`, `process_info` self-flush,
//! `is_process_alive` `ERTS_BIF_HANDLE_SIGNALS_FROM_RETURN`) against OTP 29.1.1.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};

const MODULE: &str = "sig_flush";
const CASES: &[&str] = &[
    "self_info_after_other_sends",
    "self_info_after_self_sends",
    "alive_after_exit",
    "alive_after_exit_with_mail",
    "info_other_messages_after_signals",
    "alive_self_and_dead",
    "info_self_list_after_other",
];
const SOURCE: &str = r#"
-module(sig_flush).
-export([run/1]).

run(self_info_after_other_sends) ->
    Self = self(),
    P = spawn(fun() ->
        [Self ! {m, N} || N <- lists:seq(1, 20)],
        Self ! done
    end),
    receive done -> ok end,
    {message_queue_len, Len} = process_info(self(), message_queue_len),
    {messages, Msgs} = process_info(self(), messages),
    flush(),
    {is_process_alive(P), Len, Msgs};

run(self_info_after_self_sends) ->
    [self() ! {s, N} || N <- lists:seq(1, 10)],
    {message_queue_len, Len} = process_info(self(), message_queue_len),
    {messages, Msgs} = process_info(self(), messages),
    Info = process_info(self(), [message_queue_len, messages]),
    flush(),
    {Len, Msgs, Info};

run(alive_after_exit) ->
    P = spawn(fun() -> receive stop -> ok end end),
    exit(P, kill),
    {is_process_alive(P), is_process_alive(self())};

run(alive_after_exit_with_mail) ->
    Self = self(),
    P = spawn(fun() -> Self ! before, receive stop -> ok end end),
    receive before -> ok end,
    exit(P, kill),
    Alive = is_process_alive(P),
    {Alive, is_process_alive(self())};

run(info_other_messages_after_signals) ->
    Self = self(),
    P = spawn(fun() ->
        receive
            {go, From} ->
                From ! here,
                receive stop -> ok end
        end
    end),
    P ! {go, Self},
    receive here -> ok end,
    [P ! {q, N} || N <- lists:seq(1, 5)],
    {messages, Msgs} = process_info(P, messages),
    {message_queue_len, Len} = process_info(P, message_queue_len),
    P ! stop,
    {Msgs, Len};

run(alive_self_and_dead) ->
    Dead = spawn(fun() -> ok end),
    R = monitor(process, Dead),
    receive {'DOWN', R, process, Dead, _} -> ok end,
    {is_process_alive(self()), is_process_alive(Dead)};

run(info_self_list_after_other) ->
    Self = self(),
    spawn(fun() -> Self ! a, Self ! b, Self ! c end),
    receive a -> ok end,
    Info = process_info(self(), [messages, message_queue_len]),
    flush(),
    Info.

flush() ->
    receive _ -> flush() after 0 -> ok end.
"#;

#[test]
fn sig_flush_matches_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile differential");
    reference
        .load(MODULE, &beam)
        .expect("load reference module");
    let expected: Vec<(String, OwnedTerm)> = CASES
        .iter()
        .map(
            |case| match reference.call(MODULE, "run", &[OwnedTerm::Atom((*case).into())]) {
                CallResult::Ok(term) => ((*case).to_string(), term),
                other => panic!("{MODULE}:run({case}) on erl: {other:?}"),
            },
        )
        .collect();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).expect("load VM module");
    for (case, want) in &expected {
        let arg = Term::atom(global_atoms().intern(case).unwrap());
        let actual = vm
            .eval_scheduled(MODULE, "run", &[arg], 2)
            .unwrap_or_else(|error| panic!("{MODULE}:run({case}): {error}"));
        similar_asserts::assert_eq!(actual.term, *want, "{MODULE}:run({case})");
    }
}

use crate::common;
use arinsal_etf::OwnedTerm;

// The process dictionary keeps erts' linear hash order, which depends on the table history.
// Each scenario runs in a child process on both sides, so both start from an empty dictionary
// (the difftest server's process carries its own entries, which would change the order).
const SOURCE: &str = r#"
-module(dict_port).
-export([scenario/2]).
key(0, N) -> {key, N};
key(1, N) -> N - 500;
key(2, N) -> list_to_atom("a" ++ integer_to_list(N));
key(3, N) -> N * 1.5.
scenario(Kind, K) ->
    Parent = self(), Ref = make_ref(),
    spawn(fun() ->
        [put(key(Kind, N), N) || N <- lists:seq(1, K)],
        [erase(key(Kind, N)) || N <- lists:seq(1, K, 3)],
        [put(key(Kind, N), other) || N <- lists:seq(1, K, 4)],
        A = get(),
        B = get_keys(other),
        PI = erlang:process_info(self(), dictionary),
        [erase(key(Kind, N)) || N <- lists:seq(2, K, 5)],
        C = get_keys(),
        D = erase(),
        E = get(),
        Parent ! {Ref, {A, B, PI, C, D, E}}
    end),
    receive {Ref, R} -> R end.
"#;

#[test]
fn process_dictionary_inserts_and_erases_match_otp_29() {
    let Some(beam) = common::erl_beam("dict_port", SOURCE) else {
        eprintln!("erlc unavailable; skipping process dictionary differential scenarios");
        return;
    };
    for kind in 0..4_i64 {
        for k in [0_i64, 1, 7, 50, 1000] {
            let expr = format!("dict_port:scenario({kind},{k})");
            let Some(expected) = common::erl_once("dict_port", SOURCE, &expr) else {
                eprintln!("erl unavailable; skipping process dictionary differential scenarios");
                return;
            };
            let actual = common::arinsal_once("dict_port", &beam, &expr);
            similar_asserts::assert_eq!(expected, actual, "kind {kind} k {k}");
        }
    }
}

#[test]
fn startup_atom_indices_match_otp_29() {
    let source = r#"
-module(atom_order_port).
-export([dump/0, key/0]).
key() -> key.
dump() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Count = erlang:system_info(atom_count),
    [{I, erts_debug:get_internal_state({atom, I})} || I <- lists:seq(0, Count - 1)].
"#;
    let expr = "begin key, erts_debug:set_internal_state(available_internal_state, true), Count = erlang:system_info(atom_count), [{I, erts_debug:get_internal_state({atom, I})} || I <- lists:seq(0, Count - 1)] end";
    let Some(expected) = common::erl_once("atom_order_port", source, expr) else {
        eprintln!("erl unavailable; skipping startup atom index differential");
        return;
    };
    let Some(beam) = common::erl_beam("atom_order_port", source) else {
        eprintln!("erlc unavailable; skipping startup atom index differential");
        return;
    };
    let actual = common::arinsal_once("atom_order_port", &beam, expr);
    let (
        OwnedTerm::List {
            elems: expected, ..
        },
        OwnedTerm::List { elems: actual, .. },
    ) = (&expected, &actual)
    else {
        panic!("atom table dump did not return lists: OTP={expected:?}, Arinsal={actual:?}");
    };
    fn atom_index(table: &[OwnedTerm]) -> Option<usize> {
        table.iter().position(|entry| {
            matches!(entry, OwnedTerm::Tuple(elems)
                if matches!(elems.as_slice(), [OwnedTerm::Int(_), OwnedTerm::Atom(name)] if name == "key"))
        })
    }
    let otp_key_index = atom_index(expected).expect("OTP atom table contains key");
    let arinsal_key_index = atom_index(actual).expect("Arinsal atom table contains key");
    similar_asserts::assert_eq!(
        otp_key_index,
        arinsal_key_index,
        "key atom index after startup"
    );
}

#[test]
fn traced_port_open_events_match_otp_29() {
    let source = r#"
-module(port_open_trace_order).
-export([run/0]).
run() ->
    _ = erlang:trace(new_ports, true, [ports]),
    Port = open_port({spawn, "true"}, [exit_status]),
    Open = receive {trace, Port, open, _Pid, Name} -> Name after 1000 -> timeout end,
    Linked = receive {trace, Port, getting_linked, _Pid} -> true after 1000 -> timeout end,
    {Open, Linked}.
"#;
    let expr = "port_open_trace_order:run()";
    let Some(expected) = common::erl_once("port_open_trace_order", source, expr) else {
        eprintln!("erl unavailable; skipping traced port open differential");
        return;
    };
    let Some(beam) = common::erl_beam("port_open_trace_order", source) else {
        eprintln!("erlc unavailable; skipping traced port open differential");
        return;
    };
    let actual = common::arinsal_once("port_open_trace_order", &beam, expr);
    similar_asserts::assert_eq!(expected, actual);
}

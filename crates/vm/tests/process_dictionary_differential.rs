mod common;

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
            assert_eq!(expected, actual, "kind {kind} k {k}");
        }
    }
}

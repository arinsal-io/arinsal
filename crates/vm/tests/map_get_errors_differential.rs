//! `map_get/2`, `is_map_key/2` and `map_size/1` failures must give the same exception class,
//! reason, stacktrace (with `error_info`) and formatted message as erts, in bodies and guards,
//! for flatmaps, hashmaps and non-maps, with immediate, boxed and unknown key types and with
//! maps whose type the compiler knows. The failure paths are the process-wide
//! `handle_map_get_badmap`, `handle_map_get_badkey` and `handle_map_size_error` fragments.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const MODULE: &str = r#"
-module(map_get_err_probe).
-compile(export_all).
-compile(nowarn_export_all).

get_imm(M) -> map_get(a, M).
get_int(M) -> map_get(1, M).
get_bin(M) -> map_get(<<"k">>, M).
get_any(K, M) -> map_get(K, M).
get_boxed_key(K, M) when is_binary(K) -> map_get(K, M).
get_exact(K, M) when is_map(M) -> map_get(K, M).
get_exact_boxed(K, M) when is_map(M), is_binary(K) -> map_get(K, M).
get_exact_imm(M) when is_map(M) -> map_get(a, M).
get_maybe(X, K) ->
    M = case X of a -> error; _ -> #{k => 1} end,
    case M of error -> none; _ -> map_get(K, M) end.

has_imm(M) -> is_map_key(a, M).
has_any(K, M) -> is_map_key(K, M).
has_boxed_key(K, M) when is_binary(K) -> is_map_key(K, M).
has_exact(K, M) when is_map(M) -> is_map_key(K, M).
has_exact_boxed(K, M) when is_map(M), is_binary(K) -> is_map_key(K, M).

size_any(M) -> map_size(M).
size_exact(M) when is_map(M) -> map_size(M).
size_maybe(X) ->
    M = case X of a -> error; _ -> #{k => 1} end,
    case M of error -> none; _ -> map_size(M) end.

g_get(K, M) when map_get(K, M) =:= v -> yes;
g_get(_, _) -> no.
g_get_imm(M) when map_get(a, M) =:= v -> yes;
g_get_imm(_) -> no.
g_get_bin(M) when map_get(<<"k">>, M) =:= v -> yes;
g_get_bin(_) -> no.
g_get_exact(K, M) when is_map(M), map_get(K, M) =:= v -> yes;
g_get_exact(_, _) -> no.
g_get_exact_boxed(K, M) when is_map(M), is_binary(K), map_get(K, M) =:= v -> yes;
g_get_exact_boxed(_, _) -> no.
g_get_or(K, M) when map_get(K, M) =:= v; map_get(a, M) =:= w -> yes;
g_get_or(_, _) -> no.
g_has(K, M) when is_map_key(K, M) -> yes;
g_has(_, _) -> no.
g_has_exact(K, M) when is_map(M), is_map_key(K, M) -> yes;
g_has_exact(_, _) -> no.
g_has_not(K, M) when not is_map_key(K, M) -> yes;
g_has_not(_, _) -> no.
g_size(M) when map_size(M) > 1 -> yes;
g_size(_) -> no.
g_size_exact(M) when is_map(M), map_size(M) > 1 -> yes;
g_size_exact(_) -> no.
g_size_eq(M) when map_size(M) =:= 0 -> yes;
g_size_eq(_) -> no.

try_get(K, M) ->
    try map_get(K, M) of V -> {ok, V}
    catch C:R:S -> {C, R, trim(S)}
    end.
try_size(M) ->
    try map_size(M) of V -> {ok, V}
    catch C:R:S -> {C, R, trim(S)}
    end.
try_has(K, M) ->
    try is_map_key(K, M) of V -> {ok, V}
    catch C:R:S -> {C, R, trim(S)}
    end.
old_catch_get(K, M) -> old(catch map_get(K, M)).
old_catch_size(M) -> old(catch map_size(M)).
old({'EXIT', {R, S}}) -> {'EXIT', {R, trim(S)}};
old(V) -> V.
nested(K, M) -> {before, get_any(K, M)}.
tail(K, M) -> get_any(K, M).

id(X) -> X.
pm2(#{a := A, b := B}) -> {A, B};
pm2(_) -> other.
pm3(#{c := C, a := A, b := B}) -> {A, B, C};
pm3(_) -> other.
pm8(#{a := A, b := B, c := C, d := D, e := E, f := F, g := G, h := H}) -> {A, B, C, D, E, F, G, H};
pm8(_) -> other.
pmy(#{a := A, b := B}) -> {id(A), id(B), A, B};
pmy(_) -> other.
pmb(#{<<"k">> := V, a := A}) -> {V, A};
pmb(_) -> other.
pm2_strict(#{a := A, b := B}) -> {A, B}.
pm3_strict(#{c := C, a := A, b := B}) -> {A, B, C}.
pmy_strict(#{a := A, b := B}) -> {id(A), id(B), A, B}.

maps() ->
    Big = maps:from_list([{I, I} || I <- lists:seq(1, 50)]),
    BigK = maps:put(a, v, Big),
    [#{}, #{a => 1, b => 2}, #{b => 1, a => 2}, #{a => 1, b => 2, c => 3},
     #{a => 1, b => 2, c => 3, d => 4, e => 5, f => 6, g => 7, h => 8},
     #{c => 3, b => 2, a => 1, d => 4, e => 5, f => 6, g => 7, h => 8, i => 9},
     #{<<"k">> => 1, a => 2}, #{a => 1}, #{a => v}, #{1 => x}, #{<<"k">> => y}, #{{a} => z, a => w},
     #{a => v, b => 2, c => 3}, Big, BigK].

nonmaps() ->
    [a, 1, [], [a], [a | b], {a}, {}, <<"abc">>, 1.5, 1 bsl 70, -(1 bsl 70), "str"].

keys() -> [a, b, 1, 2, <<"k">>, <<"zz">>, {a}, 1.5, "s", [], 1 bsl 70, 50, 51].

fmt(C, R, S) ->
    lists:flatten(erl_error:format_exception(C, R, S)).

trim([{map_get_err_probe, run, 0, _} = Last | _]) -> [Last];
trim([Frame | Rest]) -> [Frame | trim(Rest)];
trim([]) -> [].

big([{_, _, Args, _} | _]) when is_list(Args) -> lists:any(fun(A) -> is_map(A) andalso map_size(A) > 1 end, Args);
big(_) -> false.

norm(M) when is_map(M) -> {map, lists:sort([{norm(K), norm(V)} || {K, V} <- maps:to_list(M)])};
norm(T) when is_tuple(T) -> list_to_tuple([norm(E) || E <- tuple_to_list(T)]);
norm([H | T]) -> [norm(H) | norm(T)];
norm(T) -> T.

t(F) ->
    norm(try F() of
        V -> {ok, V}
    catch
        C:R:S0 ->
            S = trim(S0),
            {C, R, S, case big(S) of true -> skipped; false -> fmt(C, R, S) end}
    end).

run() ->
    Ms = maps() ++ nonmaps(),
    Ks = keys(),
    Pairs = [{K, M} || K <- Ks, M <- Ms],
    OneM = [get_imm, get_int, get_bin, get_exact_imm, has_imm, size_any, size_exact,
            g_get_imm, g_get_bin, g_size, g_size_exact, g_size_eq, try_size, old_catch_size,
            pm2, pm3, pm8, pmy, pmb, pm2_strict, pm3_strict, pmy_strict],
    TwoKM = [get_any, get_boxed_key, get_exact, get_exact_boxed, has_any, has_boxed_key,
             has_exact, has_exact_boxed, g_get, g_get_exact, g_get_exact_boxed, g_get_or,
             g_has, g_has_exact, g_has_not, try_get, try_has, old_catch_get, nested, tail],
    R1 = [{F, norm(M), t(fun() -> map_get_err_probe:F(M) end)} || F <- OneM, M <- Ms],
    R2 = [{F, K, norm(M), t(fun() -> map_get_err_probe:F(K, M) end)} || F <- TwoKM, {K, M} <- Pairs],
    R3 = [{get_maybe, X, K, t(fun() -> map_get_err_probe:get_maybe(X, K) end)} || X <- [a, b], K <- Ks],
    R4 = [{size_maybe, X, t(fun() -> map_get_err_probe:size_maybe(X) end)} || X <- [a, b]],
    [lists:flatten(io_lib:format("~w", [E])) || E <- R1 ++ R2 ++ R3 ++ R4].
"#;

fn text(term: &OwnedTerm) -> String {
    let OwnedTerm::List { elems, .. } = term else {
        panic!("case result is not a string: {term:?}");
    };
    elems
        .iter()
        .map(|c| match c {
            OwnedTerm::Int(c) => char::from_u32(*c as u32).unwrap_or('?'),
            other => panic!("not a character: {other:?}"),
        })
        .collect()
}

#[test]
fn map_get_is_map_key_and_map_size_failures_match_erts() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named("map_get_err_probe", MODULE, &[])
        .unwrap();
    reference.load("map_get_err_probe", &beam).unwrap();
    let expected = reference.call("map_get_err_probe", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("map_get_err_probe", "run", &[], 1, None)
        .unwrap();

    let CallResult::Ok(OwnedTerm::List {
        elems: ref expected,
        ..
    }) = expected
    else {
        panic!("reference did not return a list: {expected:?}");
    };
    let OwnedTerm::List {
        elems: ref actual, ..
    } = actual.term
    else {
        panic!("Arinsal did not return a list");
    };
    assert_eq!(expected.len(), actual.len());
    let mut mismatches = 0;
    for (want, got) in expected.iter().zip(actual.iter()) {
        let (want, got) = (text(want), text(got));
        if want != got {
            mismatches += 1;
            if mismatches <= 4 {
                let at = want
                    .chars()
                    .zip(got.chars())
                    .position(|(a, b)| a != b)
                    .unwrap_or(want.len().min(got.len()));
                let from = at.saturating_sub(120);
                let window = |text: &str| text.chars().skip(from).take(300).collect::<String>();
                eprintln!(
                    "MISMATCH at {at} of {}\n  erts:    {}\n  arinsal: {}",
                    &want[..want.len().min(40)],
                    window(&want),
                    window(&got)
                );
            }
        }
    }
    assert_eq!(
        mismatches,
        0,
        "{mismatches} of {} cases differ",
        expected.len()
    );
}

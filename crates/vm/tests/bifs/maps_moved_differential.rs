//! Differential coverage for the maps BIFs dispatched through the VM BIF table.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, from_owned};

const MODULE: &str = "maps_moved_differential";
const SOURCE: &str = r#"
-module(maps_moved_differential).
-export([run/1]).

norm(M) when is_map(M) -> {map, lists:sort([{norm(K), norm(V)} || {K, V} <- maps:to_list(M)])};
norm(T) when is_tuple(T) -> list_to_tuple([norm(E) || E <- tuple_to_list(T)]);
norm([H | T]) -> [norm(H) | norm(T)];
norm(T) -> T.

error_info([{_, _, _, Location} | Rest]) ->
    case proplists:get_value(error_info, Location, undefined) of
        undefined -> error_info(Rest);
        Info -> Info
    end;
error_info([_ | Rest]) -> error_info(Rest);
error_info([]) -> undefined.

run_case({Function, Args}) ->
    try apply(maps, Function, Args) of
        Value -> {ok, norm(Value)}
    catch
        Class:Reason:Stack -> {exception, Class, norm(Reason), norm(error_info(Stack))}
    end.

run(Cases) -> [run_case(Case) || Case <- Cases].
"#;

fn map_case(name: &str, args: Vec<O>) -> O {
    O::Tuple(vec![O::atom(name), O::list(args)])
}

fn map_with_keys(start: i64, end: i64) -> O {
    O::Map(
        (start..=end)
            .map(|key| (O::Int(key), O::Int(key * 10)))
            .collect(),
    )
}

fn cases() -> Vec<O> {
    let flat = map_with_keys(1, 8);
    let shrinking = map_with_keys(1, 33);
    let hamt = map_with_keys(1, 40);
    let not_map = O::atom("not_map");
    let mut cases = vec![
        map_case("find", vec![O::Int(4), flat.clone()]),
        map_case("find", vec![O::Int(99), hamt.clone()]),
        map_case("find", vec![O::Int(4), not_map.clone()]),
        map_case("get", vec![O::Int(4), flat.clone()]),
        map_case("get", vec![O::Int(99), hamt.clone()]),
        map_case("get", vec![O::Int(4), not_map.clone()]),
        map_case("is_key", vec![O::Int(4), hamt.clone()]),
        map_case("is_key", vec![O::Int(99), hamt.clone()]),
        map_case("is_key", vec![O::Int(4), not_map.clone()]),
        map_case("put", vec![O::Int(99), O::Int(7), flat.clone()]),
        map_case("put", vec![O::Int(40), O::Int(7), hamt.clone()]),
        map_case("put", vec![O::Int(99), O::Int(7), not_map.clone()]),
        map_case("update", vec![O::Int(4), O::Int(7), hamt.clone()]),
        map_case("update", vec![O::Int(99), O::Int(7), hamt.clone()]),
        map_case("update", vec![O::Int(4), O::Int(7), not_map.clone()]),
        map_case("remove", vec![O::Int(4), flat.clone()]),
        map_case("remove", vec![O::Int(99), hamt.clone()]),
        map_case("remove", vec![O::Int(1), shrinking]),
        map_case("remove", vec![O::Int(4), not_map.clone()]),
        map_case("take", vec![O::Int(4), hamt.clone()]),
        map_case("take", vec![O::Int(99), hamt.clone()]),
        map_case("take", vec![O::Int(4), not_map.clone()]),
        map_case("get", vec![O::atom("missing"), O::Map(vec![])]),
        map_case("get", vec![O::atom("missing"), not_map.clone()]),
        map_case("find", vec![O::atom("missing"), not_map.clone()]),
        map_case(
            "update",
            vec![O::atom("missing"), O::Int(1), O::Map(vec![])],
        ),
        map_case("remove", vec![O::atom("missing"), not_map.clone()]),
        map_case("take", vec![O::atom("missing"), not_map]),
    ];

    for n in 0..40 {
        cases.push(map_case("get", vec![O::Int(n), map_with_keys(0, 39)]));
    }
    for n in 0..1000 {
        let map = O::Map(vec![(O::Int(1), O::Int(n)), (O::Int(2), O::Int(n + 1))]);
        let inputs = [
            ("find", vec![O::Int(1), map.clone()]),
            ("get", vec![O::Int(1), map.clone()]),
            ("is_key", vec![O::Int(1), map.clone()]),
            ("put", vec![O::Int(1), O::Int(n + 5), map.clone()]),
            ("remove", vec![O::Int(1), map.clone()]),
            ("update", vec![O::Int(1), O::Int(n + 5), map.clone()]),
            ("take", vec![O::Int(1), map.clone()]),
            ("merge", vec![map.clone(), map]),
        ];
        cases.extend(inputs.into_iter().map(|(name, args)| map_case(name, args)));
    }
    cases
}

#[test]
fn moved_maps_bifs_match_otp_through_vm() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let input = O::list(cases());
    let expected = reference.call(MODULE, "run", std::slice::from_ref(&input));

    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let mut heap = ProcessHeap::with_words(300_000);
    let input = from_owned(&input, &mut heap).expect("allocate case input");
    let actual = vm
        .eval_scheduled(MODULE, "run", &[input], 1)
        .unwrap_or_else(|error| panic!("VM evaluation failed: {error}"));
    let actual = CallResult::Ok(actual.term);
    assert!(
        compare(&expected, &actual, CompareMode::Exact).is_ok(),
        "moved maps cases differ: expected {expected:#?}, actual {actual:#?}"
    );
}

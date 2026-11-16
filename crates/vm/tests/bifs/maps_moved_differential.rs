//! Differential coverage for the maps BIFs dispatched through the VM BIF table.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, from_owned};

const MODULE: &str = "maps_moved_differential";
const SOURCE: &str = r#"
-module(maps_moved_differential).
-export([run/1, run_reductions/1, run_trap_probe/1, project/2]).

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

run_op({from_list, List}) -> map_size(maps:from_list(List));
run_op({from_keys, Keys, Value}) -> map_size(maps:from_keys(Keys, Value));
run_op({keys, Map}) -> hd(maps:keys(Map));
run_op({values, Map}) -> hd(maps:values(Map)).

run_reductions(Cases) ->
    [begin
        {reductions, Before} = process_info(self(), reductions),
        Result = run_op(Case),
        {reductions, After} = process_info(self(), reductions),
        {Result, After - Before}
     end || Case <- Cases].

run_trap_probe(Size) ->
    Keys = lists:seq(1, Size),
    Pairs = [{Key, Key * 10} || Key <- Keys],
    Map = maps:from_list(Pairs),
    run_reductions([
        {from_list, Pairs},
        {from_keys, Keys, 7},
        {keys, Map},
        {values, Map}
    ]).

project(Map, keys) -> maps:keys(Map);
project(Map, values) -> maps:values(Map).
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
        map_case(
            "from_list",
            vec![O::list(vec![
                O::Tuple(vec![O::Int(1), O::Int(10)]),
                O::Tuple(vec![O::Int(2), O::Int(20)]),
                O::Tuple(vec![O::Int(1), O::Int(11)]),
            ])],
        ),
        map_case("from_list", vec![O::list(vec![O::atom("not_a_pair")])]),
        map_case("from_list", vec![O::list(vec![O::Tuple(vec![O::Int(1)])])]),
        map_case(
            "from_keys",
            vec![O::list(vec![O::Int(1), O::Int(2), O::Int(1)]), O::Int(9)],
        ),
        map_case("keys", vec![flat.clone()]),
        map_case("values", vec![flat]),
        map_case("keys", vec![hamt.clone()]),
        map_case("values", vec![hamt]),
        map_case("keys", vec![not_map.clone()]),
        map_case("values", vec![not_map.clone()]),
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

#[test]
fn moved_maps_projection_collision_nodes_match_otp_through_vm() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let pairs = [(1_i64, 10_i64), (2, 20), (3, 30)];
    let expected_map = O::Map(
        pairs
            .iter()
            .map(|(key, value)| (O::Int(*key), O::Int(*value)))
            .collect(),
    );
    let mut heap = ProcessHeap::with_words(256);
    let entries = pairs.map(|(key, value)| {
        (
            0,
            arinsal_term::Term::small(key).unwrap(),
            arinsal_term::Term::small(value).unwrap(),
        )
    });
    let mut leaves = arinsal_term::hashmap_leaves_hashed(&entries, &mut heap).unwrap();
    let map = arinsal_term::hashmap_from_unsorted_array(&mut leaves, false, &mut heap)
        .unwrap()
        .unwrap();
    assert!(map.is_hashmap());

    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    for (name, selector) in [("keys", "keys"), ("values", "values")] {
        let expected = reference.call(
            MODULE,
            "project",
            &[expected_map.clone(), O::atom(selector)],
        );
        let expected_values = match &expected {
            CallResult::Ok(O::List { elems, tail }) if tail.as_ref() == &O::Nil => elems
                .iter()
                .map(|term| match term {
                    O::Int(value) => *value,
                    other => panic!("unexpected OTP projection element: {other:?}"),
                })
                .collect::<Vec<_>>(),
            other => panic!("OTP maps:{name} did not return a proper list: {other:?}"),
        };
        let selector = O::atom(selector);
        let selector = from_owned(&selector, &mut heap).expect("allocate projection selector");
        let actual = vm
            .eval_scheduled(MODULE, "project", &[map, selector], 1)
            .unwrap_or_else(|error| panic!("VM maps:{name} failed: {error}"));
        let actual_values = match &actual.term {
            O::List { elems, tail } if tail.as_ref() == &O::Nil => elems
                .iter()
                .map(|term| match term {
                    O::Int(value) => *value,
                    other => panic!("unexpected VM projection element: {other:?}"),
                })
                .collect::<Vec<_>>(),
            other => panic!("VM maps:{name} returned {other:?}"),
        };
        let mut actual_values = actual_values;
        let mut expected_values = expected_values;
        actual_values.sort_unstable();
        expected_values.sort_unstable();
        similar_asserts::assert_eq!(actual_values, expected_values, "maps:{name} collision node");
    }
}

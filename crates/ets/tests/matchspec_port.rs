use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_ets::match_spec::{MatchDialect, MatchProgram, match_spec_test};
use arinsal_ets::{Protection, Registry, TableOptions, TableType, WriteConcurrency};
use arinsal_term::{Term, VecHeap, from_owned, global_atoms, to_owned};

fn atom(name: &str) -> OwnedTerm {
    OwnedTerm::atom(name)
}

fn int(value: i64) -> OwnedTerm {
    OwnedTerm::Int(value)
}

fn tuple(values: Vec<OwnedTerm>) -> OwnedTerm {
    OwnedTerm::Tuple(values)
}

fn list(values: Vec<OwnedTerm>) -> OwnedTerm {
    OwnedTerm::list(values)
}

fn string(value: &str) -> OwnedTerm {
    list(value.bytes().map(|byte| int(i64::from(byte))).collect())
}

fn ref_erl() -> Option<RefErl> {
    match RefErl::start() {
        Ok(erl) => Some(erl),
        Err(error) => {
            eprintln!("skipping OTP differential test: {error}");
            None
        }
    }
}

fn options(table_type: TableType) -> TableOptions {
    TableOptions {
        name: global_atoms().intern("matchspec_port").unwrap(),
        named_table: false,
        table_type,
        keypos: 1,
        protection: Protection::Protected,
        owner: Term::pid(1, 0).unwrap(),
        heir: None,
        read_concurrency: false,
        write_concurrency: WriteConcurrency::Disabled,
        decentralized_counters: false,
        compressed: false,
    }
}

fn local_select(table_type: TableType, spec: &OwnedTerm) -> OwnedTerm {
    let mut registry = Registry::new();
    let tid = registry.create(options(table_type)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut heap = VecHeap::new();
    for (key, value) in [(1, "a"), (2, "b"), (3, "c"), (4, "d"), (5, "e")] {
        let object = from_owned(&tuple(vec![int(key), atom(value)]), &mut heap).unwrap();
        table.insert(&[object]).unwrap();
    }
    let program = MatchProgram::compile(from_owned(spec, &mut heap).unwrap()).unwrap();
    let mut output = VecHeap::new();
    let mut values = table
        .select(&program, false, &mut output)
        .unwrap()
        .into_iter()
        .map(|term| to_owned(term).unwrap())
        .collect::<Vec<_>>();
    values.sort_by_key(|value| format!("{value:?}"));
    list(values)
}

fn canonical_list(term: OwnedTerm) -> OwnedTerm {
    let OwnedTerm::List { elems, tail } = &term else {
        panic!("expected result list")
    };
    assert_eq!(**tail, OwnedTerm::Nil);
    let mut elems = elems.clone();
    elems.sort_by_key(|value| format!("{value:?}"));
    list(elems)
}

#[test]
fn test_ms_results_vs_erl() {
    let Some(erl) = ref_erl() else { return };
    for seed in 0..200 {
        let value = seed - 100;
        let object = tuple(vec![int(seed), tuple(vec![atom("value"), int(value)])]);
        let head = tuple(vec![atom("$1"), tuple(vec![atom("value"), atom("$2")])]);
        let guards = match seed % 5 {
            0 => vec![tuple(vec![atom(">="), atom("$2"), int(0)])],
            1 => vec![tuple(vec![atom("is_integer"), atom("$1")])],
            2 => vec![tuple(vec![atom("=:="), atom("$2"), int(value)])],
            3 => vec![tuple(vec![
                atom("is_map"),
                OwnedTerm::Map(vec![(atom("a"), int(1))]),
            ])],
            _ => vec![],
        };
        let body = if seed == 199 {
            vec![atom("$2")]
        } else {
            match seed % 5 {
                0 => vec![atom("$_")],
                1 => vec![atom("$$")],
                2 => vec![tuple(vec![atom("+"), atom("$2"), int(1)])],
                3 => vec![OwnedTerm::Map(vec![(atom("a"), atom("$2"))])],
                _ => vec![tuple(vec![
                    atom("const"),
                    OwnedTerm::Binary(vec![0, 1, 255]),
                ])],
            }
        };
        let spec = list(vec![tuple(vec![head, list(guards), list(body)])]);
        let expected = erl.call(
            "erlang",
            "match_spec_test",
            &[object.clone(), spec.clone(), atom("table")],
        );
        let mut heap = VecHeap::new();
        let actual = match_spec_test(
            from_owned(&object, &mut heap).unwrap(),
            from_owned(&spec, &mut heap).unwrap(),
            MatchDialect::Table,
            &mut heap,
            &(),
        );
        match expected {
            CallResult::Ok(expected) => assert_eq!(
                actual.map(|term| to_owned(term).unwrap()),
                Ok(expected),
                "seed {seed}"
            ),
            CallResult::Exception { .. } => {
                assert!(actual.is_err(), "seed {seed}: expected compiler error")
            }
            result => panic!("unexpected OTP result for seed {seed}: {result:?}"),
        }
    }
}

#[test]
fn tuple_construction_evaluates_nested_matchspec_expressions_like_otp() {
    let Some(erl) = ref_erl() else { return };
    let factor = 0x0fff_ffff;
    let beam = erl
        .compile_named(
            "ms_tuple_expression_fixture",
            r#"
                -module(ms_tuple_expression_fixture).
                -export([run/0]).
                run() ->
                  Values = [{1},{2},{3}],
                  Spec = [{{'$1'},[{'>','$1',1}],[{{{'*','$1',268435455}}}]}],
                  ets:match_spec_run(Values,ets:match_spec_compile(Spec)).
            "#,
            &[],
        )
        .unwrap();
    erl.load("ms_tuple_expression_fixture", &beam).unwrap();
    let expected = erl.call("ms_tuple_expression_fixture", "run", &[]);

    let expression = tuple(vec![atom("*"), atom("$1"), int(factor)]);
    let tuple_expression = tuple(vec![tuple(vec![expression])]);
    let spec = list(vec![tuple(vec![
        tuple(vec![atom("$1")]),
        list(vec![tuple(vec![atom(">"), atom("$1"), int(1)])]),
        list(vec![tuple_expression]),
    ])]);
    let objects = [int(1), int(2), int(3)]
        .into_iter()
        .map(|value| tuple(vec![value]))
        .collect::<Vec<_>>();
    let mut heap = VecHeap::new();
    let program = MatchProgram::compile(from_owned(&spec, &mut heap).unwrap()).unwrap();
    let input = objects
        .iter()
        .map(|object| from_owned(object, &mut heap).unwrap())
        .collect::<Vec<_>>();
    let mut output = VecHeap::new();
    let actual = program
        .run_many(&input, &mut output)
        .unwrap()
        .into_iter()
        .map(|term| to_owned(term).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(expected, CallResult::Ok(list(actual)));
}

#[test]
fn tuple_construction_in_guard_matches_otp() {
    let Some(erl) = ref_erl() else { return };
    let beam = erl
        .compile_named(
            "ms_guard_tuple_fixture",
            r#"
                -module(ms_guard_tuple_fixture).
                -export([run/0]).
                run() ->
                  Term = atom,
                  Objects = [{[{second,Term},'and',"tail"],Term,['and',"tail"]}],
                  Spec = [{{'$1','$2','$3'},
                    [{'=:=','$1',[{{second,'$2'}}|'$3']}],
                    [{{"Building guard"}}]}],
                  ets:match_spec_run(Objects,ets:match_spec_compile(Spec)).
            "#,
            &[],
        )
        .unwrap();
    erl.load("ms_guard_tuple_fixture", &beam).unwrap();
    let expected = erl.call("ms_guard_tuple_fixture", "run", &[]);

    let term = atom("atom");
    let string_tail = string("tail");
    let object = tuple(vec![
        list(vec![
            tuple(vec![atom("second"), term.clone()]),
            atom("and"),
            string_tail.clone(),
        ]),
        term,
        list(vec![atom("and"), string_tail]),
    ]);
    let tuple_expression = tuple(vec![tuple(vec![atom("second"), atom("$2")])]);
    let guard_list = OwnedTerm::List {
        elems: vec![tuple_expression],
        tail: Box::new(atom("$3")),
    };
    let spec = list(vec![tuple(vec![
        tuple(vec![atom("$1"), atom("$2"), atom("$3")]),
        list(vec![tuple(vec![atom("=:="), atom("$1"), guard_list])]),
        list(vec![tuple(vec![tuple(vec![string("Building guard")])])]),
    ])]);
    let mut heap = VecHeap::new();
    let program = MatchProgram::compile(from_owned(&spec, &mut heap).unwrap()).unwrap();
    let object = from_owned(&object, &mut heap).unwrap();
    let mut output = VecHeap::new();
    let actual = program
        .run(object, &mut output)
        .unwrap()
        .map(|term| to_owned(term).unwrap());
    assert_eq!(expected, CallResult::Ok(list(actual.into_iter().collect())));
}

#[test]
fn ets_test_ms_errors_vs_erl() {
    let Some(erl) = ref_erl() else { return };
    let object = tuple(vec![int(1)]);
    let spec = list(vec![tuple(vec![
        tuple(vec![atom("$1")]),
        list(vec![]),
        list(vec![atom("$2")]),
    ])]);
    let expected = erl.call("ets", "test_ms", &[object.clone(), spec.clone()]);
    let mut heap = VecHeap::new();
    let actual = match_spec_test(
        from_owned(&object, &mut heap).unwrap(),
        from_owned(&spec, &mut heap).unwrap(),
        MatchDialect::Table,
        &mut heap,
        &(),
    )
    .map(|term| to_owned(term).unwrap());
    assert_eq!(
        actual,
        match expected {
            CallResult::Ok(value) => Ok(value),
            other => panic!("OTP ets:test_ms failed: {other:?}"),
        }
    );
}

#[test]
fn select_order_vs_erl() {
    let Some(erl) = ref_erl() else { return };
    let beam = erl
        .compile_named(
            "ms_port_fixture",
            r#"
        -module(ms_port_fixture).
        -export([select/2]).
        select(Type, Spec) ->
            T = ets:new(ms_port_fixture, [Type]),
            true = ets:insert(T, [{1, a}, {2, b}, {3, c}, {4, d}, {5, e}]),
            try ets:select(T, Spec) after ets:delete(T) end.
    "#,
            &[],
        )
        .unwrap();
    erl.load("ms_port_fixture", &beam).unwrap();
    let spec = list(vec![tuple(vec![
        tuple(vec![atom("$1"), atom("$2")]),
        list(vec![tuple(vec![atom(">"), atom("$1"), int(2)])]),
        list(vec![atom("$_")]),
    ])]);
    for (name, table_type) in [
        ("set", TableType::Set),
        ("ordered_set", TableType::OrderedSet),
        ("bag", TableType::Bag),
    ] {
        let expected = erl.call("ms_port_fixture", "select", &[atom(name), spec.clone()]);
        let CallResult::Ok(expected) = expected else {
            panic!("OTP select failed for {name}: {expected:?}");
        };
        let actual = local_select(table_type, &spec);
        if name == "ordered_set" {
            assert_eq!(expected, actual, "{name} order");
        } else {
            assert_eq!(canonical_list(expected), actual, "{name}");
        }
    }
}

#[test]
fn select_replace_vs_erl() {
    let Some(erl) = ref_erl() else { return };
    let beam = erl
        .compile_named(
            "ms_replace_fixture",
            r#"
        -module(ms_replace_fixture).
        -export([replace/0]).
        replace() ->
            T = ets:new(ms_replace_fixture, [ordered_set]),
            true = ets:insert(T, [{1, a}, {2, b}, {3, c}]),
            S = [{{'$1','$2'}, [{'>','$1',1}], [{{'$1', changed}}]}],
            try {ets:select_replace(T, S), ets:tab2list(T)} after ets:delete(T) end.
    "#,
            &[],
        )
        .unwrap();
    erl.load("ms_replace_fixture", &beam).unwrap();
    let expected = erl.call("ms_replace_fixture", "replace", &[]);
    let mut registry = Registry::new();
    let tid = registry.create(options(TableType::OrderedSet)).unwrap();
    let mut table = registry.get_mut(tid).unwrap();
    let mut heap = VecHeap::new();
    for (key, value) in [(1, "a"), (2, "b"), (3, "c")] {
        let object = from_owned(&tuple(vec![int(key), atom(value)]), &mut heap).unwrap();
        table.insert(&[object]).unwrap();
    }
    let spec = list(vec![tuple(vec![
        tuple(vec![atom("$1"), atom("$2")]),
        list(vec![tuple(vec![atom(">"), atom("$1"), int(1)])]),
        list(vec![tuple(vec![tuple(vec![atom("$1"), atom("changed")])])]),
    ])]);
    let program = MatchProgram::compile(from_owned(&spec, &mut heap).unwrap()).unwrap();
    let count = table.select_replace(&program).unwrap();
    let mut output = VecHeap::new();
    let mut rows = table
        .tab2list(&mut output)
        .unwrap()
        .into_iter()
        .map(|term| to_owned(term).unwrap())
        .collect::<Vec<_>>();
    rows.sort_by_key(|value| format!("{value:?}"));
    assert_eq!(
        expected,
        CallResult::Ok(tuple(vec![int(count as i64), list(rows)]))
    );
}

#[test]
fn match_spec_run_vs_erl() {
    let Some(erl) = ref_erl() else { return };
    let objects = list((0..20).map(|n| tuple(vec![int(n), atom("item")])).collect());
    let spec = list(vec![tuple(vec![
        tuple(vec![atom("$1"), atom("_")]),
        list(vec![tuple(vec![atom("is_integer"), atom("$1")])]),
        list(vec![tuple(vec![atom("+"), atom("$1"), int(10)])]),
    ])]);
    let expected = match erl.call("ets", "match_spec_compile", std::slice::from_ref(&spec)) {
        CallResult::Ok(compiled) => erl.call("ets", "match_spec_run", &[objects.clone(), compiled]),
        other => panic!("OTP compile failed: {other:?}"),
    };
    let mut heap = VecHeap::new();
    let object_terms = (0..20)
        .map(|n| from_owned(&tuple(vec![int(n), atom("item")]), &mut heap).unwrap())
        .collect::<Vec<_>>();
    let program = MatchProgram::compile(from_owned(&spec, &mut heap).unwrap()).unwrap();
    let mut output = VecHeap::new();
    let actual = OwnedTerm::list(
        program
            .run_many(&object_terms, &mut output)
            .unwrap()
            .iter()
            .map(|term| to_owned(*term).unwrap())
            .collect(),
    );
    assert_eq!(expected, CallResult::Ok(actual));
}

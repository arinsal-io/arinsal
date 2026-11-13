use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, Term, from_owned};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use similar_asserts::assert_eq;

const MODULE: &str = "etf_vm_differential";
const SOURCE: &str = r#"
-module(etf_vm_differential).
-export([run/3, run_raw/3, run_encoded/3, fun_encode/1, export_fun_encode/1, local_fun/0,
         stress/1, fun_identity/1]).

run(encode, Term, Options) ->
    try erlang:term_to_binary(Term, Options) of Value -> {ok, Value}
    catch Class:Reason:Stacktrace -> {exception, Class, Reason, lists:sublist(Stacktrace, 1)} end;
run(iovec, Term, Options) ->
    try erlang:term_to_iovec(Term, Options) of Value -> {ok, Value}
    catch Class:Reason:Stacktrace -> {exception, Class, Reason, lists:sublist(Stacktrace, 1)} end;
run(size, Term, Options) ->
    try erlang:external_size(Term, Options) of Value -> {ok, Value}
    catch Class:Reason:Stacktrace -> {exception, Class, Reason, lists:sublist(Stacktrace, 1)} end;
run(decode, Binary, Options) ->
    try erlang:binary_to_term(Binary, Options) of Value -> {ok, Value}
    catch Class:Reason:Stacktrace -> {exception, Class, Reason, lists:sublist(Stacktrace, 1)} end.

run_encoded(encode, Binary, Options) -> run(encode, erlang:binary_to_term(Binary), Options).

run_raw(encode, Term, Options) -> erlang:term_to_binary(Term, Options);
run_raw(iovec, Term, Options) -> erlang:term_to_iovec(Term, Options);
run_raw(size, Term, Options) -> erlang:external_size(Term, Options);
run_raw(decode, Binary, Options) -> erlang:binary_to_term(Binary, Options).

fun_encode(Options) -> erlang:term_to_binary(fun fun_identity/1, Options).
export_fun_encode(Options) ->
    erlang:term_to_binary(fun etf_vm_differential:fun_identity/1, Options).
local_fun() -> fun fun_identity/1.
stress(Kind) ->
    Term = deep(1000000, 1, Kind),
    Binary = erlang:term_to_binary(Term),
    erlang:binary_to_term(Binary) =:= Term.
deep(0, Term, _Kind) -> Term;
deep(N, Term, tuple) -> deep(N - 1, {Term}, tuple);
deep(N, Term, list) -> deep(N - 1, [Term], list).
fun_identity(X) -> X + 1.
"#;

fn terms() -> Vec<O> {
    let mut terms = vec![
        O::Int(-1),
        O::Int(0),
        O::Int(255),
        O::Int(256),
        O::BigInt("123456789012345678901234567890".parse().unwrap()),
        O::Float(-0.0),
        O::Float(1.25),
        O::atom("猫"),
        O::Nil,
        O::Tuple(vec![O::atom("a"), O::Int(42), O::Binary(vec![1, 2])]),
        O::list(vec![O::Int(1), O::Int(2), O::Int(3)]),
        O::List {
            elems: vec![O::Int(1)],
            tail: Box::new(O::atom("tail")),
        },
        O::Binary(Vec::new()),
        O::Binary(vec![7; 1000]),
        O::BitString {
            bytes: vec![0b1010_0000],
            bits: 3,
        },
        O::Map(vec![(O::Int(2), O::atom("b")), (O::Int(1), O::atom("a"))]),
        O::Pid {
            node: "nonode@nohost".into(),
            id: 7,
            serial: 0,
            creation: 0,
        },
        O::Port {
            node: "nonode@nohost".into(),
            id: 12,
            creation: 0,
        },
        O::Ref {
            node: "nonode@nohost".into(),
            creation: 0,
            ids: vec![1, 2, 3],
        },
    ];
    for bits in 1..8 {
        terms.push(O::BitString {
            bytes: vec![0xa5 & (0xff << (8 - bits))],
            bits,
        });
    }
    for count in [33, 100, 1000] {
        terms.push(O::Map(
            (0..count).map(|i| (O::Int(i), O::Int(i * i))).collect(),
        ));
    }
    terms
}

fn contains_external_identity(term: &O) -> bool {
    match term {
        O::Pid { .. } | O::Port { .. } | O::Ref { .. } => true,
        O::Tuple(values) => values.iter().any(contains_external_identity),
        O::List { elems, tail } => {
            elems.iter().any(contains_external_identity) || contains_external_identity(tail)
        }
        O::Map(entries) => entries.iter().any(|(key, value)| {
            contains_external_identity(key) || contains_external_identity(value)
        }),
        _ => false,
    }
}

fn options() -> Vec<O> {
    vec![
        O::Nil,
        O::list(vec![O::atom("compressed")]),
        O::list(vec![O::Tuple(vec![O::atom("compressed"), O::Int(0)])]),
        O::list(vec![O::Tuple(vec![O::atom("compressed"), O::Int(9)])]),
        O::list(vec![O::Tuple(vec![O::atom("minor_version"), O::Int(0)])]),
        O::list(vec![O::Tuple(vec![O::atom("minor_version"), O::Int(1)])]),
        O::list(vec![O::atom("deterministic")]),
    ]
}

fn args_to_terms(values: &[O], heap: &mut ProcessHeap) -> Vec<Term> {
    values
        .iter()
        .map(|value| from_owned(value, heap).expect("test input allocation"))
        .collect()
}

fn heap_words(term: &O) -> usize {
    match term {
        O::List { elems, tail } => elems
            .iter()
            .fold(elems.len().saturating_mul(2), |words, elem| {
                words.saturating_add(heap_words(elem))
            })
            .saturating_add(heap_words(tail)),
        O::Tuple(elements) => elements
            .iter()
            .fold(1, |words, elem| words.saturating_add(heap_words(elem))),
        O::Map(entries) => entries.iter().fold(1, |words, (key, value)| {
            words
                .saturating_add(heap_words(key))
                .saturating_add(heap_words(value))
                .saturating_add(1)
        }),
        O::BigInt(value) => value.bits().div_ceil(64) as usize + 2,
        O::Binary(bytes) | O::Other { raw: bytes, .. } => bytes.len().div_ceil(8) + 2,
        O::BitString { bytes, .. } => bytes.len().div_ceil(8) + 2,
        O::Pid { .. } | O::Port { .. } | O::Ref { .. } | O::MagicRef(_) => 4,
        O::Fun { pid, free_vars, .. } => {
            free_vars.iter().fold(8 + heap_words(pid), |words, value| {
                words.saturating_add(heap_words(value))
            })
        }
        O::Record { fields, .. } => fields.iter().fold(2, |words, (_, value)| {
            words.saturating_add(heap_words(value)).saturating_add(1)
        }),
        _ => 1,
    }
}

fn run_vm(vm: &mut arinsal_vm::Vm, function: &str, values: &[O]) -> CallResult {
    let words = values.iter().fold(4096usize, |words, term| {
        words.saturating_add(heap_words(term))
    });
    let mut heap = ProcessHeap::with_words(words.saturating_mul(4));
    let args = args_to_terms(values, &mut heap);
    match vm.eval_scheduled(MODULE, function, &args, 1) {
        Ok(result) => CallResult::Ok(result.term),
        Err(arinsal_vm::VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    }
}

fn compare_case(reference: &RefErl, vm: &mut arinsal_vm::Vm, operation: &str, value: O, opts: O) {
    let args = [value, opts];
    let bif = match operation {
        "encode" => "term_to_binary",
        "iovec" => "term_to_iovec",
        "size" => "external_size",
        "decode" => "binary_to_term",
        _ => unreachable!(),
    };
    let expected_raw = reference.call("erlang", bif, &args);
    if matches!(expected_raw, CallResult::Exception { .. }) {
        compare_error(reference, vm, operation, args[0].clone(), args[1].clone());
        return;
    }
    let expected = wrap_success(expected_raw);
    let actual = run_vm(
        vm,
        "run",
        &[O::atom(operation), args[0].clone(), args[1].clone()],
    );
    let (expected, actual) = if operation == "decode" {
        (canonical_result(expected), canonical_result(actual))
    } else {
        (expected, actual)
    };
    assert_eq!(actual, expected, "{operation} {args:?}");
}

fn canonical_result(result: CallResult) -> CallResult {
    match result {
        CallResult::Ok(term) => CallResult::Ok(canonical(&term)),
        other => other,
    }
}

fn canonical(term: &O) -> O {
    match term {
        O::Tuple(elements) => O::Tuple(elements.iter().map(canonical).collect()),
        O::List { elems, tail } => O::List {
            elems: elems.iter().map(canonical).collect(),
            tail: Box::new(canonical(tail)),
        },
        O::Map(entries) => {
            let mut entries: Vec<_> = entries
                .iter()
                .map(|(key, value)| (canonical(key), canonical(value)))
                .collect();
            entries.sort_by(|left, right| arinsal_etf::erl_cmp(&left.0, &right.0));
            O::Map(entries)
        }
        O::BigInt(value) => value
            .to_string()
            .parse::<i64>()
            .map(O::Int)
            .unwrap_or_else(|_| O::BigInt(value.clone())),
        other => other.clone(),
    }
}

fn wrap_success(result: CallResult) -> CallResult {
    match result {
        CallResult::Ok(value) => CallResult::Ok(O::Tuple(vec![O::atom("ok"), value])),
        other => other,
    }
}

fn compare_error(reference: &RefErl, vm: &mut arinsal_vm::Vm, operation: &str, value: O, opts: O) {
    let args = [O::atom(operation), value, opts];
    let bif = match operation {
        "encode" => "term_to_binary",
        "iovec" => "term_to_iovec",
        "size" => "external_size",
        "decode" => "binary_to_term",
        _ => unreachable!(),
    };
    let expected = reference.call("erlang", bif, &args[1..]);
    let actual = run_vm(vm, "run_raw", &args);
    let (
        CallResult::Exception {
            class: expected_class,
            reason: expected_reason,
            stack_top: expected_stack,
        },
        CallResult::Exception {
            class: actual_class,
            reason: actual_reason,
            stack_top: actual_stack,
        },
    ) = (&expected, &actual)
    else {
        assert_eq!(actual, expected, "error_info {args:?}");
        return;
    };
    assert_eq!(actual_class, expected_class, "error class {args:?}");
    assert_eq!(actual_reason, expected_reason, "error reason {args:?}");
    let mut expected_info = Vec::new();
    let mut actual_info = Vec::new();
    if let Some(stack) = expected_stack {
        collect_error_info(stack, &mut expected_info);
    }
    if let Some(stack) = actual_stack {
        collect_error_info(stack, &mut actual_info);
    }
    assert_eq!(actual_info, expected_info, "error_info {args:?}");
}

fn collect_error_info(term: &O, output: &mut Vec<O>) {
    match term {
        O::Tuple(elements) => {
            if elements.len() == 2 && elements[0] == O::atom("error_info") {
                output.push(elements[1].clone());
            }
            for element in elements {
                collect_error_info(element, output);
            }
        }
        O::List { elems, tail } => {
            for element in elems {
                collect_error_info(element, output);
            }
            collect_error_info(tail, output);
        }
        O::Map(entries) => {
            for (key, value) in entries {
                collect_error_info(key, output);
                collect_error_info(value, output);
            }
        }
        _ => {}
    }
}

#[test]
fn vm_etf_encode_decode_iovec_and_size_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile ETF fixture");
    reference.load(MODULE, &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    assert_eq!(
        reference.call(MODULE, "fun_identity", &[O::Int(1)]),
        CallResult::Ok(O::Int(2)),
        "reference fixture module must be loaded before fun encoding"
    );
    let mut differences = Vec::new();
    let local_options = O::list(vec![O::atom("local")]);
    let expected_fun = reference.call(MODULE, "fun_encode", std::slice::from_ref(&local_options));
    let actual_fun = run_vm(&mut vm, "fun_encode", &[local_options]);
    if actual_fun != expected_fun {
        differences.push(format!(
            "local fun encoding: Arinsal={actual_fun:?}; OTP={expected_fun:?}"
        ));
    }
    let local_options = O::list(vec![O::atom("local")]);
    let expected_export = reference.call(
        MODULE,
        "export_fun_encode",
        std::slice::from_ref(&local_options),
    );
    let actual_export = run_vm(&mut vm, "export_fun_encode", &[local_options]);
    if actual_export != expected_export {
        differences.push(format!(
            "local export-fun encoding: Arinsal={actual_export:?}; OTP={expected_export:?}"
        ));
    }

    for term in terms() {
        for option in options() {
            compare_case(&reference, &mut vm, "encode", term.clone(), option.clone());
            compare_case(&reference, &mut vm, "size", term.clone(), option.clone());
            // term_to_iovec shares the term encoding option set, including compression levels.
            compare_case(&reference, &mut vm, "iovec", term.clone(), option.clone());
        }
        let local_options = O::list(vec![O::atom("local")]);
        // The separate etf_local_ext_nodes task covers external identities under [local].
        if !contains_external_identity(&term) {
            let expected_local = wrap_success(reference.call(
                "erlang",
                "term_to_binary",
                &[term.clone(), local_options.clone()],
            ));
            let actual_local = run_vm(
                &mut vm,
                "run",
                &[O::atom("encode"), term.clone(), local_options],
            );
            match (
                wrapped_binary(&actual_local),
                wrapped_binary(&expected_local),
            ) {
                (Some(actual), Some(expected)) => {
                    assert_eq!(actual.len(), expected.len(), "local ETF size {term:?}");
                    assert_eq!(&actual[..2], &expected[..2], "local ETF tag {term:?}");
                    // LOCAL_EXT carries a node-specific hash in bytes 2..6.
                    assert_eq!(&actual[6..], &expected[6..], "local ETF body {term:?}");
                    if !matches!(term, O::Export { .. }) {
                        compare_case(
                            &reference,
                            &mut vm,
                            "size",
                            term.clone(),
                            O::list(vec![O::atom("local")]),
                        );
                        let iovec_args = [
                            O::atom("iovec"),
                            term.clone(),
                            O::list(vec![O::atom("local")]),
                        ];
                        let expected_iovec = wrap_success(reference.call(
                            "erlang",
                            "term_to_iovec",
                            &[term.clone(), iovec_args[2].clone()],
                        ));
                        let actual_iovec = run_vm(&mut vm, "run", &iovec_args);
                        if let (Some(actual_bytes), Some(expected_bytes)) =
                            (wrapped_iovec(&actual_iovec), wrapped_iovec(&expected_iovec))
                        {
                            assert_eq!(
                                actual_bytes.len(),
                                expected_bytes.len(),
                                "local iovec size {term:?}"
                            );
                            assert_eq!(
                                &actual_bytes[..2],
                                &expected_bytes[..2],
                                "local iovec tag {term:?}"
                            );
                            assert_eq!(
                                &actual_bytes[6..],
                                &expected_bytes[6..],
                                "local iovec body {term:?}"
                            );
                        } else {
                            assert_eq!(actual_iovec, expected_iovec, "local iovec {term:?}");
                        }
                    }
                }
                _ => differences.push(format!(
                    "local ETF {term:?}: Arinsal={actual_local:?}; OTP={expected_local:?}"
                )),
            }
        }
        let encoded =
            wrap_success(reference.call("erlang", "term_to_binary", &[term.clone(), O::Nil]));
        let CallResult::Ok(O::Tuple(parts)) = &encoded else {
            continue;
        };
        let O::Binary(bytes) = &parts[1] else {
            panic!("unexpected wrapped encoded term")
        };
        for option in [
            O::Nil,
            O::list(vec![O::atom("safe")]),
            O::list(vec![O::atom("used")]),
            O::list(vec![O::atom("safe"), O::atom("used")]),
        ] {
            compare_case(
                &reference,
                &mut vm,
                "decode",
                O::Binary(bytes.clone()),
                option,
            );
        }
    }
    let used_input = O::Binary(vec![131, 97, 42, 0, 1]);
    for option in [
        O::list(vec![O::atom("used")]),
        O::list(vec![O::atom("safe"), O::atom("used")]),
    ] {
        let bif_args = [used_input.clone(), option.clone()];
        let expected = reference.call("erlang", "binary_to_term", &bif_args);
        let actual = run_vm(
            &mut vm,
            "run_raw",
            &[O::atom("decode"), used_input.clone(), option],
        );
        assert_eq!(actual, expected, "binary_to_term used {bif_args:?}");
    }
    let unknown_atom = O::Binary(vec![
        131, 119, 15, b'u', b'n', b'k', b'n', b'o', b'w', b'n', b'_', b'e', b't', b'f', b'_', b'a',
        b't', b'm',
    ]);
    compare_error(
        &reference,
        &mut vm,
        "decode",
        unknown_atom,
        O::list(vec![O::atom("safe")]),
    );
    let malformed = [
        O::Binary(vec![131, 97]),
        O::Binary(vec![131, 80, 255, 255, 255, 255, 0]),
    ];
    for input in malformed {
        for option in [O::Nil, O::list(vec![O::atom("safe")])] {
            compare_error(&reference, &mut vm, "decode", input.clone(), option);
        }
    }
    let valid = O::Binary(vec![131, 97, 42]);
    for option in [
        O::atom("bad"),
        O::Int(1),
        O::list(vec![O::atom("bad")]),
        O::List {
            elems: vec![O::atom("safe")],
            tail: Box::new(O::atom("bad")),
        },
    ] {
        compare_error(&reference, &mut vm, "decode", valid.clone(), option);
    }
    for (operation, value, option) in [
        ("encode", O::Int(42), O::list(vec![O::atom("unknown")])),
        (
            "size",
            O::Int(42),
            O::list(vec![O::Tuple(vec![O::atom("minor_version"), O::Int(2)])]),
        ),
        (
            "iovec",
            O::Int(42),
            O::list(vec![O::Tuple(vec![O::atom("compressed"), O::Int(10)])]),
        ),
    ] {
        compare_error(&reference, &mut vm, operation, value, option);
    }
    assert!(
        differences.is_empty(),
        "ETF VM/OTP differences:\n{}",
        differences.join("\n")
    );
}

#[test]
fn vm_etf_20_000_term_property_corpus_matches_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile ETF fixture");
    reference.load(MODULE, &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let mut runner = TestRunner::deterministic();
    let strategy = arinsal_difftest::gens::any_term();
    let CallResult::Ok(local_fun) = reference.call(MODULE, "local_fun", &[]) else {
        panic!("reference local_fun/0 failed");
    };
    for case in 0..20_000 {
        let mut term = strategy
            .new_tree(&mut runner)
            .expect("generated ETF property term")
            .current();
        term = match case % 97 {
            0 => O::Map(
                (0..33 + case % 70)
                    .map(|i| (O::Int(i as i64), O::Int((i * i) as i64)))
                    .collect(),
            ),
            1 => {
                let bits = (case % 8 + 1) as u8;
                if bits == 8 {
                    O::Binary(vec![0xa5])
                } else {
                    O::BitString {
                        bytes: vec![0xa5 & (0xff << (8 - bits))],
                        bits,
                    }
                }
            }
            2 => local_fun.clone(),
            3 => O::Pid {
                node: "nonode@nohost".into(),
                id: 7,
                serial: 0,
                creation: 0,
            },
            4 => O::Ref {
                node: "nonode@nohost".into(),
                creation: 0,
                ids: vec![1, 2, 3],
            },
            5 => (0..128).fold(O::Int(1), |inner, _| O::Tuple(vec![inner])),
            _ => term,
        };
        let source_encoded = reference.call("erlang", "term_to_binary", &[term.clone(), O::Nil]);
        let CallResult::Ok(O::Binary(source_binary)) = &source_encoded else {
            panic!("OTP could not serialize property input at case {case}: {term:?}");
        };
        for option in options() {
            let args = [
                O::atom("encode"),
                O::Binary(source_binary.clone()),
                option.clone(),
            ];
            let expected = reference.call(MODULE, "run_encoded", &args);
            let actual = run_vm(&mut vm, "run_encoded", &args);
            if actual != expected {
                let detail = match (&actual, &expected) {
                    (CallResult::Ok(O::Binary(actual)), CallResult::Ok(O::Binary(expected))) => {
                        let offset = actual
                            .iter()
                            .zip(expected)
                            .position(|(actual, expected)| actual != expected);
                        format!(
                            "lengths {} and {}, first differing byte {offset:?}, Arinsal {:02x?}, OTP {:02x?}",
                            actual.len(),
                            expected.len(),
                            &actual[..actual.len().min(60)],
                            &expected[..expected.len().min(60)]
                        )
                    }
                    _ => format!("Arinsal {actual:?}, OTP {expected:?}"),
                };
                panic!("case {case}, option {option:?}: {detail}; term {term:?}");
            }
            if let CallResult::Ok(O::Tuple(values)) = &expected {
                compare_case(&reference, &mut vm, "decode", values[1].clone(), O::Nil);
            }
        }
    }
}

#[test]
fn vm_etf_million_deep_lists_and_tuples_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile ETF fixture");
    reference.load(MODULE, &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    for kind in ["list", "tuple"] {
        let arg = O::atom(kind);
        let expected = reference.call(MODULE, "stress", std::slice::from_ref(&arg));
        let actual = run_vm(&mut vm, "stress", &[arg]);
        assert_eq!(actual, expected, "million-deep {kind}");
    }
}

fn wrapped_binary(result: &CallResult) -> Option<&[u8]> {
    let CallResult::Ok(O::Tuple(parts)) = result else {
        return None;
    };
    match parts.get(1) {
        Some(O::Binary(bytes)) => Some(bytes),
        _ => None,
    }
}

fn wrapped_iovec(result: &CallResult) -> Option<Vec<u8>> {
    let CallResult::Ok(O::Tuple(parts)) = result else {
        return None;
    };
    let mut bytes = Vec::new();
    collect_binaries(parts.get(1)?, &mut bytes);
    (!bytes.is_empty()).then_some(bytes)
}

fn collect_binaries(term: &O, output: &mut Vec<u8>) {
    match term {
        O::Binary(bytes) => output.extend_from_slice(bytes),
        O::Tuple(elements) => elements
            .iter()
            .for_each(|element| collect_binaries(element, output)),
        O::List { elems, tail } => {
            elems
                .iter()
                .for_each(|element| collect_binaries(element, output));
            collect_binaries(tail, output);
        }
        _ => {}
    }
}

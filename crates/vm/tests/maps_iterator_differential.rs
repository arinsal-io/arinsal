use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::{Vm, VmError};

fn map(size: usize) -> OwnedTerm {
    OwnedTerm::Map(
        (0..size)
            .map(|n| {
                (
                    OwnedTerm::Int(n as i64),
                    OwnedTerm::Tuple(vec![OwnedTerm::Int(n as i64), OwnedTerm::Atom("v".into())]),
                )
            })
            .collect(),
    )
}

fn raw_continuation(result: &CallResult, map: &OwnedTerm) -> Option<OwnedTerm> {
    let CallResult::Ok(OwnedTerm::List { elems, .. }) = result else {
        return None;
    };
    if elems.len() >= 2
        && elems[1] == *map
        && matches!(elems[0], OwnedTerm::Int(_) | OwnedTerm::BigInt(_))
    {
        Some(elems[0].clone())
    } else {
        None
    }
}

fn iterator_continuation(result: &CallResult, map: &OwnedTerm) -> Option<OwnedTerm> {
    let CallResult::Ok(term) = result else {
        return None;
    };
    fn path(term: &OwnedTerm, map: &OwnedTerm) -> Option<OwnedTerm> {
        match term {
            OwnedTerm::Tuple(fields) if fields.len() == 3 => path(&fields[2], map),
            OwnedTerm::List { elems, tail }
                if elems.len() == 1
                    && **tail == *map
                    && matches!(elems[0], OwnedTerm::Int(_) | OwnedTerm::BigInt(_)) =>
            {
                Some(elems[0].clone())
            }
            _ => None,
        }
    }
    path(term, map)
}

#[test]
fn maps_iterator_operations_match_otp_for_flatmaps_and_hamts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping map iterator differential test");
        return;
    };
    let source = "-module(vm_map_iter_diff).\n\
        -export([to_list/1,to_list_iter/1,to_list_ordered/1,to_list_reversed/1,\n\
                 next/1,next_unordered/1,iterator/1,iterator_unordered/1,\n\
                 iterator_reversed/1,iterator_custom/1,raw/1,raw_at/2,raw_iter/1,raw_iter_at/2,fold/1,\n\
                 invalid/0,bad_mode/1,bad_path/1,bounds/0,churn/1]).\n\
        to_list(M) -> maps:to_list(M).\n\
        to_list_iter(M) -> maps:to_list(maps:iterator(M)).\n\
        to_list_ordered(M) -> maps:to_list(maps:iterator(M, ordered)).\n\
        to_list_reversed(M) -> maps:to_list(maps:iterator(M, reversed)).\n\
        next(M) -> case maps:next(maps:iterator(M, ordered)) of {K,V,_} -> {K,V}; none -> none end.\n\
        next_unordered(M) -> case maps:next(maps:iterator(M)) of {K,V,_} -> {K,V}; none -> none end.\n\
        iterator(M) -> maps:iterator(M, ordered).\n\
        iterator_unordered(M) -> maps:iterator(M).\n\
        iterator_reversed(M) -> maps:iterator(M, reversed).\n\
        iterator_custom(M) -> maps:iterator(M, fun(A,B) -> A > B end).\n\
        raw(M) -> erts_internal:map_next(0, M, []).\n\
        raw_at(M, Path) -> erts_internal:map_next(Path, M, []).\n\
        raw_iter(M) -> erts_internal:map_next(0, M, iterator).\n\
        raw_iter_at(M, Path) -> erts_internal:map_next(Path, M, iterator).\n\
        fold(M) -> maps:fold(fun(K, _V, A) -> [K | A] end, [], M).\n\
        invalid() -> try erts_internal:map_next(0, not_a_map, iterator) catch error:badarg -> badarg end.\n\
        bad_mode(M) -> try erts_internal:map_next(0, M, bad) catch error:badarg -> badarg end.\n\
        bad_path(M) -> try erts_internal:map_next(not_a_path, M, []) catch error:badarg -> badarg end.\n\
        churn(M) -> churn(M, 300, [], 0).\n\
        churn(_, 0, Acc, S) -> {length(Acc), S};\n\
        churn(M, N, Acc, S) ->\n\
            S1 = case erts_internal:map_next(0, M, iterator) of none -> S; {_,_,_} -> S + 1 end,\n\
            churn(M, N-1, erts_internal:map_next(0, M, Acc), S1).\n\
        bounds() ->\n\
            M = maps:from_list([{0,{0,v}},{1,{1,v}},{2,{2,v}}]),\n\
            Empty = maps:from_list([]),\n\
            {try erts_internal:map_next(4, M, []) catch error:badarg -> badarg end,\n\
             try erts_internal:map_next(-1, M, []) catch error:badarg -> badarg end,\n\
             try erts_internal:map_next(1, Empty, []) catch error:badarg -> badarg end,\n\
             erts_internal:map_next(0, Empty, []),\n\
             erts_internal:map_next(0, Empty, iterator),\n\
             erts_internal:map_next(3, M, []),\n\
             erts_internal:map_next(0, M, iterator)}.\n";
    let beam = reference
        .compile_named("vm_map_iter_diff", source, &[])
        .unwrap();
    reference.load("vm_map_iter_diff", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    for size in [0, 1, 8, 32, 33, 1_000, 20_000] {
        let input = map(size);
        let functions: &[&str] = if size == 20_000 {
            &[
                "to_list",
                "to_list_iter",
                "to_list_ordered",
                "raw",
                "raw_iter",
                "fold",
            ]
        } else {
            &[
                "to_list",
                "to_list_iter",
                "to_list_ordered",
                "to_list_reversed",
                "next",
                "next_unordered",
                "iterator",
                "iterator_unordered",
                "iterator_reversed",
                "iterator_custom",
                "raw",
                "raw_iter",
                "fold",
            ]
        };
        let churn: &[&str] = if size <= 32 { &["churn"] } else { &[] };
        let functions = functions.iter().chain(churn);
        for function in functions.copied() {
            let expected =
                reference.call("vm_map_iter_diff", function, std::slice::from_ref(&input));
            let mut heap = VecHeap::new();
            let term = from_owned(&input, &mut heap).unwrap();
            let actual = match vm.eval_scheduled("vm_map_iter_diff", function, &[term], 1, None) {
                Ok(outcome) => CallResult::Ok(outcome.term),
                Err(VmError::Raised(raised)) => CallResult::Exception {
                    class: format!("{:?}", raised.class).to_lowercase(),
                    reason: raised.reason,
                    stack_top: Some(raised.stack),
                },
                Err(error) => CallResult::TransportError(error.to_string()),
            };
            compare(&expected, &actual, CompareMode::Exact)
                .unwrap_or_else(|diff| panic!("{function} on {size}-key map: {diff}"));
            assert!(matches!(expected, CallResult::Ok(_)));
        }

        for (function, next_path) in [
            (
                "raw_at",
                raw_continuation as fn(&CallResult, &OwnedTerm) -> Option<OwnedTerm>,
            ),
            ("raw_iter_at", iterator_continuation),
        ] {
            let mut path = OwnedTerm::Int(0);
            for _ in 0..2 {
                let args = [input.clone(), path.clone()];
                let expected = reference.call("vm_map_iter_diff", function, &args);
                let mut heap = VecHeap::new();
                let terms: Vec<_> = args
                    .iter()
                    .map(|arg| from_owned(arg, &mut heap).unwrap())
                    .collect();
                let actual = match vm.eval_scheduled("vm_map_iter_diff", function, &terms, 1, None)
                {
                    Ok(outcome) => CallResult::Ok(outcome.term),
                    Err(VmError::Raised(raised)) => CallResult::Exception {
                        class: format!("{:?}", raised.class).to_lowercase(),
                        reason: raised.reason,
                        stack_top: Some(raised.stack),
                    },
                    Err(error) => CallResult::TransportError(error.to_string()),
                };
                compare(&expected, &actual, CompareMode::Exact).unwrap_or_else(|diff| {
                    panic!("{function} continuation at size {size}, path {path:?}: {diff}")
                });
                let Some(next) = next_path(&expected, &input) else {
                    break;
                };
                path = next;
            }
        }
    }

    let mut error_cases = vec![
        ("invalid", Vec::new()),
        ("bounds", Vec::new()),
        ("bad_mode", vec![map(3)]),
    ];
    for size in [3usize, 1_000] {
        error_cases.push(("bad_path", vec![map(size)]));
    }
    for (function, args) in error_cases {
        let expected = reference.call("vm_map_iter_diff", function, &args);
        let mut heap = VecHeap::new();
        let terms: Vec<_> = args
            .iter()
            .map(|arg| from_owned(arg, &mut heap).unwrap())
            .collect();
        let actual = match vm.eval_scheduled("vm_map_iter_diff", function, &terms, 1, None) {
            Ok(outcome) => CallResult::Ok(outcome.term),
            Err(VmError::Raised(raised)) => CallResult::Exception {
                class: format!("{:?}", raised.class).to_lowercase(),
                reason: raised.reason,
                stack_top: Some(raised.stack),
            },
            Err(error) => CallResult::TransportError(error.to_string()),
        };
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|diff| panic!("{function}: {diff}"));
    }
}

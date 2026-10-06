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

#[test]
fn maps_iterator_operations_match_otp_for_flatmaps_and_hamts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping map iterator differential test");
        return;
    };
    let source = "-module(vm_map_iter_diff).\n\
        -export([to_list/1,to_list_iter/1,to_list_ordered/1,to_list_reversed/1,\n\
                 next/1,next_unordered/1,iterator/1,iterator_unordered/1,\n\
                 iterator_reversed/1,iterator_custom/1,raw/1,raw_iter/1,\n\
                 invalid/0,bad_mode/1,bad_path/1,bounds/0]).\n\
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
        raw_iter(M) -> erts_internal:map_next(0, M, iterator).\n\
        invalid() -> try erts_internal:map_next(0, not_a_map, iterator) catch error:badarg -> badarg end.\n\
        bad_mode(M) -> try erts_internal:map_next(0, M, bad) catch error:badarg -> badarg end.\n\
        bad_path(M) -> try erts_internal:map_next(not_a_path, M, []) catch error:badarg -> badarg end.\n\
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

    for size in [3, 1_000] {
        let input = map(size);
        for function in [
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
        ] {
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

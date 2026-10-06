#![cfg(feature = "difftest")]

use arinsal_difftest::{CallResult, CompareMode, RefErl, Vm as _, compare, pretty};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::{Vm, VmError};

#[test]
fn closures_and_dynamic_calls_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping fun differential tests");
        return;
    };
    let mut source = String::from("-module(vm_funs_cases).\n-compile(export_all).\n");
    for count in 0..=20 {
        let captures = (0..count).map(|i| format!("V{i}")).collect::<Vec<_>>();
        source.push_str(&format!("c{count}(A) -> "));
        for (index, capture) in captures.iter().enumerate() {
            source.push_str(&format!("{capture} = A + {}, ", index + 1));
        }
        let expression = if captures.is_empty() {
            "X".to_owned()
        } else {
            format!("X + {}", captures.join(" + "))
        };
        source.push_str(&format!(
            "F = fun(X) -> {expression} end, [Result] = lists:map(F,[5]), Result.\n"
        ));
    }
    source.push_str("nested(A) -> F = fun(X) -> fun(Y) -> A+X+Y end end, G = F(2), G(3).\n");
    source.push_str("map(A) -> lists:map(fun(X) -> X+A end, [1,2,3]).\n");
    source.push_str("fold(A) -> lists:foldl(fun(X,Y) -> X+Y+A end, 0, [1,2,3]).\n");
    source.push_str("filter(A) -> lists:filter(fun(X) -> X>A end, [1,2,3,4]).\n");
    source.push_str("apply_fun(A) -> erlang:apply(fun(X) -> X+1 end, [A]).\n");
    source.push_str("apply_named(A) -> erlang:apply(erlang, abs, [A]).\n");
    source.push_str("apply_bif(A) -> erlang:apply(erlang, length, [A]).\n");
    source.push_str("export_fun(A) -> F = fun erlang:abs/1, F(A).\n");
    source.push_str("make_export(A) -> F = erlang:make_fun(erlang, abs, 1), F(A).\n");
    source.push_str("info_local(A,K) -> F = fun(X) -> X+A end, erlang:fun_info(F,K).\n");
    source.push_str("info_external(K) -> erlang:fun_info(fun erlang:abs/1,K).\n");
    source.push_str("info_all_external() -> erlang:fun_info(fun erlang:abs/1).\n");
    source.push_str("info_all_local(A) -> erlang:fun_info(fun(X) -> X+A end).\n");
    source.push_str("isfun(F,A) when is_function(F,A) -> true; isfun(_,_) -> false.\n");
    source.push_str("isfun1(F) when is_function(F,1) -> true; isfun1(_) -> false.\n");
    source.push_str("fixed(M,F,A) -> apply(M,F,[A]).\n");
    source.push_str("fixed_non_tail(M,F,A) -> {ok,apply(M,F,[A])}.\n");
    source.push_str("fun_named(M,F,A,X) -> G = fun M:F/A, G(X).\n");
    source.push_str("apply_dyn(M,F,A) -> erlang:apply(M,F,A).\n");
    source.push_str("map_zero(A) -> lists:map(fun(X) -> X+1 end,A).\n");
    source.push_str("bad_fun(F) -> F(1).\n");
    source.push_str("bad_arity(A) -> F = fun(X,Y) -> X+Y end, F(A).\n");
    source.push_str("bad_arity_export(A) -> F = erlang:make_fun(erlang,abs,1), F(A,A).\n");
    let beam = reference
        .compile_named("vm_funs_cases", &source, &[])
        .unwrap();
    let parsed = arinsal_beam::parse(&beam).unwrap();
    let captures = parsed
        .lambdas
        .iter()
        .map(|lambda| lambda.num_free)
        .collect::<std::collections::BTreeSet<_>>();
    for count in 0..=20 {
        assert!(captures.contains(&count), "missing {count}-capture lambda");
    }
    let loaded = arinsal_loader::load(&parsed).unwrap();
    let make_fun_sites = loaded
        .code
        .iter()
        .filter(|instruction| matches!(instruction, arinsal_loader::Instr::MakeFun { .. }))
        .count();
    assert!(
        make_fun_sites >= 20,
        "only {make_fun_sites} make_fun3 sites"
    );
    assert!(
        loaded
            .code
            .iter()
            .any(|instruction| matches!(instruction, arinsal_loader::Instr::CallFun { .. }))
    );
    let apply_sites = loaded
        .code
        .iter()
        .filter(|instruction| matches!(instruction, arinsal_loader::Instr::Apply { .. }))
        .count();
    assert!(
        apply_sites >= 2,
        "both fixed apply forms were not generated"
    );
    assert!(
        loaded.code.iter().any(|instruction| matches!(
            instruction,
            arinsal_loader::Instr::Apply { tail: true, .. }
        ))
    );
    assert!(loaded.code.iter().any(|instruction| matches!(
        instruction,
        arinsal_loader::Instr::Apply { tail: false, .. }
    )));
    eprintln!("{make_fun_sites} make_fun3 sites and {apply_sites} fixed apply sites");
    reference.load("vm_funs_cases", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load("vm_funs_cases", &beam).unwrap();
    let mut cases = 0;
    for count in 0..=20 {
        for value in -7..8 {
            let args = [OwnedTerm::Int(value)];
            let function = format!("c{count}");
            let expected = reference.call("vm_funs_cases", &function, &args);
            let actual = vm.call("vm_funs_cases", &function, &args);
            compare(&expected, &actual, CompareMode::Exact)
                .unwrap_or_else(|e| panic!("{function}({value}): {e}; {expected:?} != {actual:?}"));
            cases += 1;
        }
    }
    for (function, values) in [
        ("nested", vec![0, 1, 8]),
        ("map", vec![-2, 0, 2]),
        ("fold", vec![-2, 0, 2]),
        ("filter", vec![0, 2, 5]),
        ("apply_fun", vec![-2, 0, 2]),
        ("apply_named", vec![-2, 0, 2]),
        ("export_fun", vec![-2, 0, 2]),
        ("make_export", vec![-2, 0, 2]),
    ] {
        for value in values {
            let args = [OwnedTerm::Int(value)];
            let expected = reference.call("vm_funs_cases", function, &args);
            let actual = vm.call("vm_funs_cases", function, &args);
            compare(&expected, &actual, CompareMode::Exact)
                .unwrap_or_else(|e| panic!("{function}({value}): {e}; {expected:?} != {actual:?}"));
            cases += 1;
        }
    }
    for key in [
        "module",
        "name",
        "arity",
        "env",
        "type",
        "index",
        "new_index",
        "uniq",
        "new_uniq",
        "refc",
    ] {
        for value in [-2, 0, 2] {
            let args = [OwnedTerm::Int(value), OwnedTerm::Atom(key.into())];
            let expected = reference.call("vm_funs_cases", "info_local", &args);
            let actual = vm.call("vm_funs_cases", "info_local", &args);
            compare(&expected, &actual, CompareMode::Exact).unwrap_or_else(|e| {
                panic!("info_local({value},{key}): {e}; {expected:?} != {actual:?}")
            });
            cases += 1;
        }
        let args = [OwnedTerm::Atom(key.into())];
        let expected = reference.call("vm_funs_cases", "info_external", &args);
        let actual = vm.call("vm_funs_cases", "info_external", &args);
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|e| panic!("info_external({key}): {e}; {expected:?} != {actual:?}"));
        cases += 1;
    }
    let expected = reference.call("vm_funs_cases", "info_all_external", &[]);
    let actual = vm.call("vm_funs_cases", "info_all_external", &[]);
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|e| panic!("info_all_external: {e}; {expected:?} != {actual:?}"));
    cases += 1;
    for value in [-2, 0, 2] {
        let args = [OwnedTerm::Int(value)];
        let expected = reference.call("vm_funs_cases", "info_all_local", &args);
        let actual = vm.call("vm_funs_cases", "info_all_local", &args);
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|e| panic!("info_all_local({value}): {e}; {expected:?} != {actual:?}"));
        cases += 1;
    }
    for value in [-4, 0, 4] {
        let args = [
            OwnedTerm::Atom("erlang".into()),
            OwnedTerm::Atom("abs".into()),
            OwnedTerm::Int(value),
        ];
        let expected = reference.call("vm_funs_cases", "fixed", &args);
        let actual = vm.call("vm_funs_cases", "fixed", &args);
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|e| panic!("fixed({value}): {e}; {expected:?} != {actual:?}"));
        cases += 1;
        let expected = reference.call("vm_funs_cases", "fixed_non_tail", &args);
        let actual = vm.call("vm_funs_cases", "fixed_non_tail", &args);
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|e| panic!("fixed_non_tail({value}): {e}; {expected:?} != {actual:?}"));
        cases += 1;
        let args = [
            OwnedTerm::Atom("erlang".into()),
            OwnedTerm::Atom("abs".into()),
            OwnedTerm::Int(1),
            OwnedTerm::Int(value),
        ];
        let expected = reference.call("vm_funs_cases", "fun_named", &args);
        let actual = vm.call("vm_funs_cases", "fun_named", &args);
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|e| panic!("fun_named({value}): {e}; {expected:?} != {actual:?}"));
        cases += 1;
    }
    for (function, args) in [
        (
            "apply_dyn",
            vec![
                OwnedTerm::Atom("erlang".into()),
                OwnedTerm::Atom("no_such_function".into()),
                OwnedTerm::list(vec![OwnedTerm::Int(1)]),
            ],
        ),
        (
            "apply_dyn",
            vec![
                OwnedTerm::Atom("no_such_module".into()),
                OwnedTerm::Atom("f".into()),
                OwnedTerm::Nil,
            ],
        ),
        (
            "apply_dyn",
            vec![
                OwnedTerm::Int(1),
                OwnedTerm::Atom("abs".into()),
                OwnedTerm::list(vec![OwnedTerm::Int(1)]),
            ],
        ),
        (
            "apply_dyn",
            vec![
                OwnedTerm::Atom("erlang".into()),
                OwnedTerm::Atom("abs".into()),
                OwnedTerm::Int(1),
            ],
        ),
        (
            "fun_named",
            vec![
                OwnedTerm::Atom("erlang".into()),
                OwnedTerm::Atom("no_such_function".into()),
                OwnedTerm::Int(1),
                OwnedTerm::Int(1),
            ],
        ),
        (
            "apply_dyn",
            vec![
                OwnedTerm::Atom("erlang".into()),
                OwnedTerm::Atom("abs".into()),
                OwnedTerm::list(vec![OwnedTerm::Int(0); 1024]),
            ],
        ),
    ] {
        let expected = reference.call("vm_funs_cases", function, &args);
        let actual = vm.call("vm_funs_cases", function, &args);
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|e| panic!("{function}({args:?}): {e}; {expected:?} != {actual:?}"));
        cases += 1;
    }
    for (function, args) in [
        (
            "apply",
            vec![
                OwnedTerm::Export {
                    module: "erlang".into(),
                    function: "abs".into(),
                    arity: 1,
                },
                OwnedTerm::list(vec![OwnedTerm::Int(-7)]),
            ],
        ),
        (
            "apply",
            vec![
                OwnedTerm::Atom("erlang".into()),
                OwnedTerm::Atom("abs".into()),
                OwnedTerm::list(vec![OwnedTerm::Int(-7)]),
            ],
        ),
        (
            "make_fun",
            vec![
                OwnedTerm::Atom("erlang".into()),
                OwnedTerm::Atom("abs".into()),
                OwnedTerm::Int(1),
            ],
        ),
        (
            "fun_info",
            vec![OwnedTerm::Export {
                module: "erlang".into(),
                function: "abs".into(),
                arity: 1,
            }],
        ),
    ] {
        let expected = reference.call("erlang", function, &args);
        let actual = vm.call("erlang", function, &args);
        compare(&expected, &actual, CompareMode::Exact).unwrap_or_else(|e| {
            panic!("erlang:{function}({args:?}): {e}; {expected:?} != {actual:?}")
        });
        cases += 1;
    }
    for fun in [
        OwnedTerm::Int(2),
        OwnedTerm::Export {
            module: "erlang".into(),
            function: "abs".into(),
            arity: 1,
        },
    ] {
        for arity in [0, 1, 2] {
            let args = [fun.clone(), OwnedTerm::Int(arity)];
            let expected = reference.call("vm_funs_cases", "isfun", &args);
            let actual = vm.call("vm_funs_cases", "isfun", &args);
            compare(&expected, &actual, CompareMode::Exact).unwrap_or_else(|e| {
                panic!("isfun({fun:?},{arity}): {e}; {expected:?} != {actual:?}")
            });
            cases += 1;
        }
        let args = [fun.clone()];
        let expected = reference.call("vm_funs_cases", "isfun1", &args);
        let actual = vm.call("vm_funs_cases", "isfun1", &args);
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|e| panic!("isfun1({fun:?}): {e}; {expected:?} != {actual:?}"));
        cases += 1;
    }
    for value in [-4, 0, 4] {
        let args = [
            OwnedTerm::Atom("erlang".into()),
            OwnedTerm::Atom("abs".into()),
            OwnedTerm::list(vec![OwnedTerm::Int(value)]),
        ];
        let expected = reference.call("vm_funs_cases", "apply_dyn", &args);
        let actual = vm.call("vm_funs_cases", "apply_dyn", &args);
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|e| panic!("apply_dyn({value}): {e}; {expected:?} != {actual:?}"));
        cases += 1;
        let args = [OwnedTerm::list(vec![
            OwnedTerm::Int(value),
            OwnedTerm::Int(value + 1),
        ])];
        let expected = reference.call("vm_funs_cases", "map_zero", &args);
        let actual = vm.call("vm_funs_cases", "map_zero", &args);
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|e| panic!("map_zero({value}): {e}; {expected:?} != {actual:?}"));
        cases += 1;
    }
    eprintln!("{cases} fun differential cases matched OTP");
    assert!(cases >= 300);

    for value in [0, 7, 99] {
        let expected = reference.call("vm_funs_cases", "bad_fun", &[OwnedTerm::Int(value)]);
        let CallResult::Exception { reason, .. } = expected else {
            panic!("expected badfun from erl: {expected:?}");
        };
        let actual = vm.eval("vm_funs_cases", "bad_fun", &[Term::small(value).unwrap()]);
        let actual = vm_reason(actual).expect("expected badfun from VM");
        assert_eq!(actual, pretty(&reason));
    }
    let actual = vm.eval("vm_funs_cases", "bad_arity", &[Term::small(4).unwrap()]);
    let reason = vm_reason(actual).expect("expected badarity from VM");
    assert!(reason.starts_with("{badarity,{"), "{reason}");
    assert!(reason.contains("[4]"), "{reason}");
    for value in [-2, 0, 2] {
        let expected = reference.call(
            "vm_funs_cases",
            "bad_arity_export",
            &[OwnedTerm::Int(value)],
        );
        let CallResult::Exception { reason, .. } = expected else {
            panic!("expected badarity from erl: {expected:?}");
        };
        let actual = vm.eval(
            "vm_funs_cases",
            "bad_arity_export",
            &[Term::small(value).unwrap()],
        );
        let actual = vm_reason(actual).expect("expected badarity from VM");
        assert_eq!(actual, pretty(&reason));
    }
    let direct = vm.eval("erlang", "apply", &[Term::small(7).unwrap(), Term::NIL]);
    let reason = vm_reason(direct).expect("expected direct erlang:apply/2 badfun");
    assert_eq!(reason, "{badfun,7}");
}

/// Reason text of an uncaught exception, in either VM error form.
fn vm_reason<T>(result: Result<T, VmError>) -> Option<String> {
    match result {
        Err(VmError::Exception { reason, .. }) => Some(reason),
        Err(VmError::Raised(raised)) => Some(pretty(&raised.reason)),
        _ => None,
    }
}

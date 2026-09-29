use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, VecHeap, from_owned, global_atoms, to_owned};
use arinsal_vm::{Vm, VmError};

#[test]
fn direct_bif_raise_preserves_class_and_reason() {
    let mut vm = Vm::new([]);
    let value = Term::atom(global_atoms().intern("direct_reason").unwrap());
    for (function, class, expected) in [
        ("error", "Error", OwnedTerm::Atom("direct_reason".into())),
        ("exit", "Exit", OwnedTerm::Atom("direct_reason".into())),
        (
            "throw",
            "Error",
            OwnedTerm::Tuple(vec![
                OwnedTerm::Atom("nocatch".into()),
                OwnedTerm::Atom("direct_reason".into()),
            ]),
        ),
    ] {
        let Err(VmError::Raised(raised)) = vm.eval("erlang", function, &[value]) else {
            panic!("{function}/1 did not raise a structured exception");
        };
        assert_eq!(format!("{:?}", raised.class), class);
        assert_eq!(raised.reason, expected);
    }
}

fn vm_call(vm: &mut Vm, function: &str, args: &[OwnedTerm], module: &str) -> CallResult {
    let mut heap = VecHeap::new();
    let inputs = args
        .iter()
        .map(|arg| from_owned(arg, &mut heap).expect("test argument"))
        .collect::<Vec<_>>();
    match vm.eval(module, function, &inputs) {
        Ok(outcome) => CallResult::Ok(to_owned(outcome.term).expect("test result")),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    }
}

fn trim_harness(term: &OwnedTerm) -> OwnedTerm {
    match term {
        OwnedTerm::Tuple(items) => OwnedTerm::Tuple(items.iter().map(trim_harness).collect()),
        OwnedTerm::List { elems, tail } => {
            let trace = elems
                .first()
                .is_some_and(|term| matches!(term, OwnedTerm::Tuple(items) if items.len() == 4));
            let elems = if trace {
                elems
                    .iter()
                    .take_while(|term| {
                        matches!(term,
                            OwnedTerm::Tuple(items)
                                if matches!(&items[0], OwnedTerm::Atom(module)
                                    if module.starts_with("vm_exc_") || module == "erlang"))
                    })
                    .cloned()
                    .collect()
            } else {
                elems.iter().map(trim_harness).collect()
            };
            OwnedTerm::List {
                elems,
                tail: tail.clone(),
            }
        }
        other => other.clone(),
    }
}

#[test]
fn four_hundred_exception_snippets_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping exception differential test");
        return;
    };
    let beam = reference
        .compile_named("vm_exc_400", include_str!("fixtures/vm_exc_400.erl"), &[])
        .unwrap();
    reference.load("vm_exc_400", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for function in ["run", "captured", "nested", "after_run", "rethrow"] {
        for n in 1..=400 {
            let args = [OwnedTerm::Int(n)];
            let expected = trim_result(reference.call("vm_exc_400", function, &args));
            let actual = trim_result(vm_call(&mut vm, function, &args, "vm_exc_400"));
            assert!(
                compare(&expected, &actual, CompareMode::Exact).is_ok(),
                "{function}({n}): expected {expected:?}, actual {actual:?}"
            );
        }
    }
}

fn trim_result(result: CallResult) -> CallResult {
    match result {
        CallResult::Ok(term) => CallResult::Ok(trim_harness(&term)),
        other => other,
    }
}

#[test]
fn exception_smoke_against_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping exception differential test");
        return;
    };
    let source = r#"
-module(vm_exc_smoke).
-export([run/1, captured/1, native/1, depth/1, gc_catch/1, failed_clause/1,
         error_info_invalid/0, class_change/0, bs_invalid_size/1]).
run(N) -> try trigger(N) catch C:R:S -> {C,R,S} end.
captured(N) -> catch trigger(N).
native(X) -> try helper(X) catch C:R:S -> {C,R,S} end.
helper(X) -> X + 1.
depth(N) -> Old = erlang:system_flag(backtrace_depth,N), try run(4) after erlang:system_flag(backtrace_depth,Old) end.
gc_catch(N) -> try gc_allocate(N,[]) catch C:R:S -> {C,R,S} end.
gc_allocate(0,_) -> erlang:error(gc);
gc_allocate(N,Acc) -> gc_allocate(N-1,[{N,N,N}|Acc]).
failed_clause(0) -> zero.
trigger(1) -> erlang:error(oops);
trigger(2) -> erlang:exit(why);
trigger(3) -> erlang:throw(value);
trigger(4) -> erlang:element(10, {});
trigger(5) -> 1 div 0;
trigger(6) -> case 5 of 1 -> ok end;
trigger(7) -> if 1 =:= 2 -> ok end;
trigger(8) -> failed_clause(1);
trigger(9) -> element(1, erlang:make_tuple(0, ok)).
error_info_invalid() ->
    try erlang:error(reason, [], [{error_info, not_map}])
    catch error:reason:Stack -> lists:keyfind(error_info, 1, element(4, hd(Stack)))
    end.
class_change() ->
    try
        try throw(arne)
        catch throw:InnerReason:Stacktrace ->
            erlang:raise(error, InnerReason, Stacktrace)
        end
    catch error:arne -> ok;
          CaughtClass:CaughtReason -> {CaughtClass, CaughtReason}
    after ok
    end.
bs_invalid_size(Size) ->
    try <<0:Size>>
    catch error:badarg:Stack -> hd(Stack)
    end.
"#;
    let beam = reference
        .compile_named("vm_exc_smoke", source, &[])
        .unwrap();
    reference.load("vm_exc_smoke", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for function in ["run", "captured"] {
        for n in 1..=9 {
            let args = [OwnedTerm::Int(n)];
            let expected = trim_result(reference.call("vm_exc_smoke", function, &args));
            let actual = trim_result(vm_call(&mut vm, function, &args, "vm_exc_smoke"));
            assert!(
                compare(&expected, &actual, CompareMode::Exact).is_ok(),
                "{function}({n}): expected {expected:?}, actual {actual:?}"
            );
            assert!(matches!(actual, CallResult::Ok(_)));
        }
    }
    let args = [OwnedTerm::Atom("wrong".into())];
    let expected = trim_result(reference.call("vm_exc_smoke", "native", &args));
    let actual = trim_result(vm_call(&mut vm, "native", &args, "vm_exc_smoke"));
    assert!(
        compare(&expected, &actual, CompareMode::Exact).is_ok(),
        "native/1: expected {expected:?}, actual {actual:?}"
    );
    for depth in [0, 1, 2, 8, 64, 70] {
        let args = [OwnedTerm::Int(depth)];
        let expected = trim_result(reference.call("vm_exc_smoke", "depth", &args));
        let actual = trim_result(vm_call(&mut vm, "depth", &args, "vm_exc_smoke"));
        assert!(
            compare(&expected, &actual, CompareMode::Exact).is_ok(),
            "depth({depth}): expected {expected:?}, actual {actual:?}"
        );
    }
    let args = [OwnedTerm::Int(5000)];
    let expected = trim_result(reference.call("vm_exc_smoke", "gc_catch", &args));
    let actual = trim_result(vm_call(&mut vm, "gc_catch", &args, "vm_exc_smoke"));
    assert!(
        compare(&expected, &actual, CompareMode::Exact).is_ok(),
        "gc_catch/1: expected {expected:?}, actual {actual:?}"
    );
    for function in ["error_info_invalid", "class_change"] {
        let expected = reference.call("vm_exc_smoke", function, &[]);
        let actual = vm_call(&mut vm, function, &[], "vm_exc_smoke");
        assert_eq!(expected, actual, "{function}");
    }
    let args = [OwnedTerm::Atom("bad_size".into())];
    let expected = reference.call("vm_exc_smoke", "bs_invalid_size", &args);
    let actual = vm_call(&mut vm, "bs_invalid_size", &args, "vm_exc_smoke");
    assert_eq!(expected, actual, "bs_invalid_size");
}

#[test]
fn lazy_stacktraces_match_otp_at_handler_and_rethrow() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping lazy stacktrace differential test");
        return;
    };
    let source = r#"
-module(vm_exc_lazy).
-export([caught/2, catch_expr/2, rethrow/2, limited/3, nested/0,
         after_nested/1, after_nested_badarg/0, after_nested_clause/0,
         after_nested_explicit/0]).
caught(Class, Depth) ->
    try descend(Depth, Class) catch C:R:S -> {C,R,S} end.
catch_expr(Class, Depth) -> catch descend(Depth, Class).
rethrow(Class, Depth) ->
    try
        try descend(Depth, Class)
        catch InnerClass:InnerReason:InnerStack ->
            erlang:raise(InnerClass, InnerReason, InnerStack)
        end
    catch OuterClass:OuterReason:OuterStack ->
        {OuterClass,OuterReason,OuterStack}
    end.
limited(Limit, Class, Depth) ->
    Old = erlang:system_flag(backtrace_depth, Limit),
    try caught(Class, Depth)
    after erlang:system_flag(backtrace_depth, Old)
    end.
nested() ->
    try
        try descend(2, error)
        catch error:InnerReason:InnerStack ->
            _ = catch descend(1, throw),
            erlang:raise(error, InnerReason, InnerStack)
        end
    catch OuterClass:OuterReason:OuterStack ->
        {OuterClass,OuterReason,OuterStack}
    end.
after_nested(Class) ->
    try
        try descend(2, Class)
        after _ = catch descend(1, throw)
        end
    catch C:R:S -> {C,R,S}
    end.
after_nested_badarg() ->
    try
        try erlang:element(10, {})
        after _ = catch descend(1, throw)
        end
    catch C:R:S -> {C,R,S}
    end.
after_nested_clause() ->
    try
        try only(ok)
        after _ = catch descend(1, throw)
        end
    catch C:R:S -> {C,R,S}
    end.
after_nested_explicit() ->
    try
        try erlang:raise(exit, mark, [])
        after _ = catch descend(1, throw)
        end
    catch C:R:S -> {C,R,S}
    end.
only(other) -> ok.
descend(0, Class) -> trigger(Class);
descend(N, Class) ->
    case N rem 2 of
        0 -> even(N - 1, Class);
        1 -> odd(N - 1, Class)
    end.
even(N, Class) -> descend(N, Class), ok.
odd(N, Class) -> descend(N, Class), ok.
trigger(throw) -> erlang:throw(mark);
trigger(error) -> erlang:error(mark);
trigger(exit) -> erlang:exit(mark).
"#;
    let beam = reference.compile_named("vm_exc_lazy", source, &[]).unwrap();
    reference.load("vm_exc_lazy", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for class in ["throw", "error", "exit"] {
        for depth in [0, 1, 2, 4, 10] {
            let args = [OwnedTerm::Atom(class.into()), OwnedTerm::Int(depth)];
            for function in ["caught", "catch_expr", "rethrow"] {
                let expected = trim_result(reference.call("vm_exc_lazy", function, &args));
                let actual = trim_result(vm_call(&mut vm, function, &args, "vm_exc_lazy"));
                assert!(
                    compare(&expected, &actual, CompareMode::Exact).is_ok(),
                    "{function}({class},{depth}): expected {expected:?}, actual {actual:?}"
                );
            }
        }
        for limit in [0, 1, 2, 4, 8, 64] {
            let args = [
                OwnedTerm::Int(limit),
                OwnedTerm::Atom(class.into()),
                OwnedTerm::Int(10),
            ];
            let expected = trim_result(reference.call("vm_exc_lazy", "limited", &args));
            let actual = trim_result(vm_call(&mut vm, "limited", &args, "vm_exc_lazy"));
            assert!(
                compare(&expected, &actual, CompareMode::Exact).is_ok(),
                "limited({limit},{class}): expected {expected:?}, actual {actual:?}"
            );
        }
    }
    let expected = trim_result(reference.call("vm_exc_lazy", "nested", &[]));
    let actual = trim_result(vm_call(&mut vm, "nested", &[], "vm_exc_lazy"));
    assert!(
        compare(&expected, &actual, CompareMode::Exact).is_ok(),
        "nested: expected {expected:?}, actual {actual:?}"
    );
    for class in ["throw", "error", "exit"] {
        let args = [OwnedTerm::Atom(class.into())];
        let expected = trim_result(reference.call("vm_exc_lazy", "after_nested", &args));
        let actual = trim_result(vm_call(&mut vm, "after_nested", &args, "vm_exc_lazy"));
        assert!(
            compare(&expected, &actual, CompareMode::Exact).is_ok(),
            "after_nested({class}): expected {expected:?}, actual {actual:?}"
        );
    }
    for function in [
        "after_nested_badarg",
        "after_nested_clause",
        "after_nested_explicit",
    ] {
        let expected = trim_result(reference.call("vm_exc_lazy", function, &[]));
        let actual = trim_result(vm_call(&mut vm, function, &[], "vm_exc_lazy"));
        assert!(
            compare(&expected, &actual, CompareMode::Exact).is_ok(),
            "{function}: expected {expected:?}, actual {actual:?}"
        );
    }
}

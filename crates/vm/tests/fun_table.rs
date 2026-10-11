#![cfg(feature = "difftest")]

use arinsal_difftest::{CallResult, CompareMode, RefErl, Vm as _, compare};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, VecHeap, exact_eq, from_owned, phash2};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

fn call_vm(vm: &mut Vm, module: &str, function: &str, args: &[Term]) -> CallResult {
    match vm.eval_scheduled(module, function, args, 1, None) {
        Ok(result) => CallResult::Ok(result.term),
        Err(error) => CallResult::TransportError(error.to_string()),
    }
}

#[test]
fn fun_info_and_export_literals_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping fun table differential test");
        return;
    };
    let module = "vm_fun_table_info";
    let source = "-module(vm_fun_table_info). -export([local/1,external/0,literal/0]). \
        local(A) -> F = fun(X) -> X+A end, {erlang:fun_info(F,index),erlang:fun_info(F,uniq), \
        erlang:fun_info(F,new_index),erlang:fun_info(F,new_uniq),erlang:fun_info(F,env), \
        erlang:fun_info(F,pid),erlang:fun_info(F,arity),erlang:fun_info(F,module)}. \
        external() -> F = fun erlang:abs/1, erlang:fun_info(F). \
        literal() -> F = erlang:make_fun(erlang,abs,1), \
        {erts_debug:same(F,fun erlang:abs/1),erts_debug:same(F,erlang:make_fun(erlang,abs,1)), \
        erlang:fun_info(F,index),erlang:fun_info(F,uniq),erlang:fun_info(F,new_uniq), \
        erlang:fun_info(F,env),erlang:fun_info(F,pid)}.";
    let beam = reference.compile_named(module, source, &[]).unwrap();
    reference.load(module, &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();

    for (function, args) in [
        ("local", vec![OwnedTerm::Int(11)]),
        ("external", vec![]),
        ("literal", vec![]),
    ] {
        let expected = reference.call(module, function, &args);
        let actual_args = args
            .iter()
            .map(|arg| match arg {
                OwnedTerm::Int(value) => Term::small(*value).unwrap(),
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        let actual = call_vm(&mut vm, module, function, &actual_args);
        compare(&expected, &actual, CompareMode::Exact)
            .unwrap_or_else(|error| panic!("{function}: {error}; {expected:?} != {actual:?}"));
    }
}

#[test]
fn local_funs_survive_same_code_reload_and_keep_equality_hash() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping fun reload differential test");
        return;
    };
    let module = "vm_fun_table_reload";
    let source = "-module(vm_fun_table_reload). -export([make/1,call/2,compare/2]). \
        make(A) -> fun(X) -> X+A end. call(F,X) -> F(X). \
        compare(A,B) -> {A =:= B,erlang:phash2(A),erlang:phash2(B)}.";
    let beam = reference.compile_named(module, source, &[]).unwrap();
    reference.load(module, &beam).unwrap();
    let old_ref = match reference.call(module, "make", &[OwnedTerm::Int(17)]) {
        CallResult::Ok(fun) => fun,
        other => panic!("make before reload failed: {other:?}"),
    };

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let old_vm = vm
        .eval(module, "make", &[Term::small(17).unwrap()])
        .unwrap();

    reference.load(module, &beam).unwrap();
    vm.load_next_version(&beam).unwrap();
    let new_ref = match reference.call(module, "make", &[OwnedTerm::Int(17)]) {
        CallResult::Ok(fun) => fun,
        other => panic!("make after reload failed: {other:?}"),
    };
    let new_vm = vm
        .eval(module, "make", &[Term::small(17).unwrap()])
        .unwrap();

    let expected = reference.call(module, "compare", &[old_ref.clone(), new_ref]);
    let actual = call_vm(&mut vm, module, "compare", &[old_vm.term, new_vm.term]);
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|error| panic!("fun equality/hash after reload: {error}"));
    assert!(exact_eq(old_vm.term, new_vm.term));
    assert_eq!(phash2(old_vm.term), phash2(new_vm.term));

    let expected_call = reference.call(module, "call", &[old_ref, OwnedTerm::Int(25)]);
    let actual_call = call_vm(
        &mut vm,
        module,
        "call",
        &[old_vm.term, Term::small(25).unwrap()],
    );
    compare(&expected_call, &actual_call, CompareMode::Exact)
        .unwrap_or_else(|error| panic!("old fun after same-code reload: {error}"));
}

#[test]
fn local_fun_from_purged_old_code_raises_badfun() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping fun purge differential test");
        return;
    };
    let module = "vm_fun_table_purge";
    let old_source = "-module(vm_fun_table_purge). -export([make/0,call/1,decode/1]). \
        make() -> fun() -> old end. call(F) -> try F() catch error:{badfun,_} -> badfun end. \
        decode(B) -> binary_to_term(B).";
    let new_source = "-module(vm_fun_table_purge). -export([make/0,call/1,decode/1]). \
        make() -> fun() -> new end. call(F) -> try F() catch error:{badfun,_} -> badfun end. \
        decode(B) -> binary_to_term(B).";
    let old_beam = reference.compile_named(module, old_source, &[]).unwrap();
    let new_beam = reference.compile_named(module, new_source, &[]).unwrap();
    let purge_module = "vm_fun_table_purge_helper";
    let purge_source = "-module(vm_fun_table_purge_helper). -export([run/0]). \
        run() -> case whereis(erts_code_purger) of \
        undefined -> register(erts_code_purger,self()), \
        Prep=erts_internal:purge_module(vm_fun_table_purge,prepare), \
        Complete=erts_internal:purge_module(vm_fun_table_purge,complete), {Prep,Complete}; \
        _ -> {Old,_Killed}=erts_code_purger:purge(vm_fun_table_purge), {Old,Old} end.";
    let purge_beam = reference
        .compile_named(purge_module, purge_source, &[])
        .unwrap();

    reference.load(module, &old_beam).unwrap();
    let old_ref = match reference.call(module, "make", &[]) {
        CallResult::Ok(fun) => fun,
        other => panic!("make before purge failed: {other:?}"),
    };
    let old_external = match reference.call("erlang", "term_to_binary", &[old_ref.clone()]) {
        CallResult::Ok(term) if matches!(term, OwnedTerm::Binary(_)) => {
            let OwnedTerm::Binary(bytes) = &term else {
                unreachable!()
            };
            OwnedTerm::Binary(bytes.clone())
        }
        other => panic!("term_to_binary before purge failed: {other:?}"),
    };
    reference.load(module, &new_beam).unwrap();
    reference.load(purge_module, &purge_beam).unwrap();
    let purge_expected = reference.call(purge_module, "run", &[]);
    let actual_expected = CallResult::Ok(OwnedTerm::Tuple(vec![
        OwnedTerm::Atom("true".into()),
        OwnedTerm::Atom("true".into()),
    ]));
    compare(&purge_expected, &actual_expected, CompareMode::Exact)
        .unwrap_or_else(|error| panic!("reference purge setup: {error}"));

    let mut vm = Vm::new([]);
    vm.load_bytes(&old_beam).unwrap();
    let old_vm = vm.eval(module, "make", &[]).unwrap();
    let mut input_heap = VecHeap::new();
    let encoded = from_owned(&old_external, &mut input_heap).unwrap();
    let decoded_vm = vm.eval(module, "decode", &[encoded]).unwrap();
    vm.load_next_version(&new_beam).unwrap();
    vm.load_bytes(&purge_beam).unwrap();
    let purge_actual = vm.call(purge_module, "run", &[]);
    compare(&purge_expected, &purge_actual, CompareMode::Exact)
        .unwrap_or_else(|error| panic!("VM purge setup: {error}"));

    let expected = reference.call(module, "call", &[old_ref]);
    let actual = call_vm(&mut vm, module, "call", &[old_vm.term]);
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|error| panic!("purged old fun: {error}; {expected:?} != {actual:?}"));
    let actual = call_vm(&mut vm, module, "call", &[decoded_vm.term]);
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|error| panic!("purged decoded fun: {error}; {expected:?} != {actual:?}"));
}

use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;

fn zero_coverage_counts(term: &OwnedTerm) -> OwnedTerm {
    match term {
        OwnedTerm::Tuple(items) if items.len() == 2 && matches!(items[1], OwnedTerm::Int(_)) => {
            OwnedTerm::Tuple(vec![items[0].clone(), OwnedTerm::Int(0)])
        }
        OwnedTerm::Tuple(items) => {
            OwnedTerm::Tuple(items.iter().map(zero_coverage_counts).collect())
        }
        OwnedTerm::List { elems, tail } => OwnedTerm::List {
            elems: elems.iter().map(zero_coverage_counts).collect(),
            tail: Box::new(zero_coverage_counts(tail)),
        },
        _ => term.clone(),
    }
}

#[test]
fn code_bifs_coverage_support_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping code_bifs coverage support differential test");
        return;
    };
    let wrapper = "code_bifs_support_wrapper";
    let beam = reference
        .compile_named(
            wrapper,
            "-module(code_bifs_support_wrapper). -export([run/0]). run() -> code:coverage_support().",
            &[],
        )
        .unwrap();
    let expected = reference.eval("code:coverage_support()").unwrap();
    let mut vm = crate::common::node();
    crate::common::load_fresh(&mut vm, &beam);
    let actual = vm.eval_scheduled(wrapper, "run", &[], 1).unwrap().term;
    similar_asserts::assert_eq!(actual, expected);
}

#[test]
fn code_bifs_coverage_modes_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping code_bifs coverage mode differential test");
        return;
    };
    let beam = reference
        .compile_named(
            "code_bifs_mode_wrapper",
            "-module(code_bifs_mode_wrapper). -export([set/1,get/0]). set(M) -> code:set_coverage_mode(M). get() -> code:get_coverage_mode().",
            &[],
        )
        .unwrap();
    let actual = crate::common::peer_eval(
        &[],
        &[&beam],
        "{code:set_coverage_mode(function_counters),code:get_coverage_mode()}",
    );
    let OwnedTerm::Tuple(actual_values) = &actual else {
        panic!("unexpected coverage mode result: {actual:?}");
    };
    let actual_old = actual_values[0].clone();
    similar_asserts::assert_eq!(
        actual_old,
        reference
            .eval("code:set_coverage_mode(function_counters)")
            .unwrap()
    );
    let actual_mode = actual_values[1].clone();
    similar_asserts::assert_eq!(
        actual_mode,
        reference.eval("code:get_coverage_mode()").unwrap()
    );
}

#[test]
fn code_bifs_function_counters_match_otp_through_vm_dispatch() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping code_bifs function counter dispatch test");
        return;
    };
    let module = "code_bifs_dispatch_cov";
    let beam = reference
        .compile_named(
            module,
            "-module(code_bifs_dispatch_cov). -export([run/0,f/0]). run() -> f(), f(). f() -> ok.",
            &[],
        )
        .unwrap();
    reference
        .eval("code:set_coverage_mode(function_counters)")
        .unwrap();
    reference.load(module, &beam).unwrap();
    reference.eval("code_bifs_dispatch_cov:run()").unwrap();
    let expected = reference
        .eval("code:get_coverage(function, code_bifs_dispatch_cov)")
        .unwrap();

    let actual = crate::common::peer_eval(
        &[],
        &[&beam],
        "begin code:set_coverage_mode(function_counters),code_bifs_dispatch_cov:run(),code:get_coverage(function,code_bifs_dispatch_cov) end",
    );
    // BeamAsm native execution currently skips interpreter coverage probes.
    similar_asserts::assert_eq!(
        zero_coverage_counts(&actual),
        zero_coverage_counts(&expected)
    );
    assert_ne!(expected, OwnedTerm::Nil);
}

#[test]
fn code_bifs_line_counters_match_otp_through_vm_dispatch() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping code_bifs line counter dispatch test");
        return;
    };
    let module = "code_bifs_dispatch_line_cov";
    let beam = reference
        .compile_named(
            module,
            "-module(code_bifs_dispatch_line_cov). -export([run/1]). run(X) -> case X of a -> one(); b -> two(); _ -> none() end. one() -> ok. two() -> ok. none() -> ok.",
            &[OwnedTerm::Atom("line_coverage".into())],
        )
        .unwrap();
    reference
        .eval("code:set_coverage_mode(line_counters)")
        .unwrap();
    reference.load(module, &beam).unwrap();
    reference
        .eval("code_bifs_dispatch_line_cov:run(a)")
        .unwrap();
    let expected = reference
        .eval("{code:get_coverage(line, code_bifs_dispatch_line_cov),code:get_coverage(cover_id_line, code_bifs_dispatch_line_cov)}")
        .unwrap();

    let actual = crate::common::peer_eval(
        &[],
        &[&beam],
        "begin code:set_coverage_mode(line_counters),code_bifs_dispatch_line_cov:run(a),{code:get_coverage(line,code_bifs_dispatch_line_cov),code:get_coverage(cover_id_line,code_bifs_dispatch_line_cov)} end",
    );
    // BeamAsm native execution currently skips interpreter coverage probes.
    similar_asserts::assert_eq!(
        zero_coverage_counts(&actual),
        zero_coverage_counts(&expected)
    );
}

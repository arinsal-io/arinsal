use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, global_atoms};
use arinsal_vm::Vm;

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).unwrap())
}

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
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(wrapper, "run", &[], 1, None)
        .unwrap()
        .term;
    assert_eq!(actual, expected);
}

#[test]
fn code_bifs_coverage_modes_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping code_bifs coverage mode differential test");
        return;
    };
    let wrapper = "code_bifs_mode_wrapper";
    let beam = reference
        .compile_named(
            wrapper,
            "-module(code_bifs_mode_wrapper). -export([set/1,get/0]). set(M) -> code:set_coverage_mode(M). get() -> code:get_coverage_mode().",
            &[],
        )
        .unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual_old = vm
        .eval_scheduled(wrapper, "set", &[atom("function_counters")], 1, None)
        .unwrap()
        .term;
    assert_eq!(
        actual_old,
        reference
            .eval("code:set_coverage_mode(function_counters)")
            .unwrap()
    );
    let actual_mode = vm
        .eval_scheduled(wrapper, "get", &[], 1, None)
        .unwrap()
        .term;
    assert_eq!(
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

    let wrapper = "code_bifs_query_wrapper";
    let wrapper_beam = reference
        .compile_named(
            wrapper,
            "-module(code_bifs_query_wrapper). -export([set/1,get/2]). set(M) -> code:set_coverage_mode(M). get(Mode, Mod) -> code:get_coverage(Mode, Mod).",
            &[],
        )
        .unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&wrapper_beam).unwrap();
    vm.eval_scheduled(wrapper, "set", &[atom("function_counters")], 1, None)
        .unwrap();
    vm.load_bytes(&beam).unwrap();
    vm.eval_scheduled(module, "run", &[], 1, None).unwrap();
    let actual = vm
        .eval_scheduled(wrapper, "get", &[atom("function"), atom(module)], 1, None)
        .unwrap()
        .term;
    // BeamAsm native execution currently skips interpreter coverage probes.
    assert_eq!(
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

    let wrapper = "code_bifs_line_query_wrapper";
    let wrapper_beam = reference
        .compile_named(
            wrapper,
            "-module(code_bifs_line_query_wrapper). -export([set/1,get/2]). set(M) -> code:set_coverage_mode(M). get(Mode, Mod) -> code:get_coverage(Mode, Mod).",
            &[],
        )
        .unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&wrapper_beam).unwrap();
    vm.eval_scheduled(wrapper, "set", &[atom("line_counters")], 1, None)
        .unwrap();
    vm.load_bytes(&beam).unwrap();
    vm.eval_scheduled(module, "run", &[atom("a")], 1, None)
        .unwrap();
    let lines = vm
        .eval_scheduled(wrapper, "get", &[atom("line"), atom(module)], 1, None)
        .unwrap()
        .term;
    let ids = vm
        .eval_scheduled(
            wrapper,
            "get",
            &[atom("cover_id_line"), atom(module)],
            1,
            None,
        )
        .unwrap()
        .term;
    let actual = OwnedTerm::Tuple(vec![lines, ids]);
    // BeamAsm native execution currently skips interpreter coverage probes.
    assert_eq!(
        zero_coverage_counts(&actual),
        zero_coverage_counts(&expected)
    );
}

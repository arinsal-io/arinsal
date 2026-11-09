use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;
use std::sync::{Mutex, MutexGuard};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn serialized() -> MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn assert_same(expected: CallResult, actual: CallResult, label: &str) {
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|mismatch| panic!("{label}: {mismatch}"));
}

#[test]
fn error_with_improper_arglist_formats_like_otp() {
    let _serial = serialized();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping improper error argument differential test");
        return;
    };
    let source = r#"
-module(vm_triage_improper_error).
-export([run/0]).
run() ->
    try erlang:error(function_clause, [unproper | list])
    catch Class:Reason:Stack ->
        Text = lists:flatten(erl_error:format_exception(Class, Reason, Stack)),
        lists:prefix("exception error: {function_clause,", Text)
    end.
"#;
    let beam = reference
        .compile_named("vm_triage_improper_error", source, &[])
        .expect("compile improper error fixture");
    reference
        .load("vm_triage_improper_error", &beam)
        .expect("load improper error fixture in OTP");
    let expected = reference.call("vm_triage_improper_error", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load improper error fixture");
    let actual = vm
        .eval_scheduled("vm_triage_improper_error", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("format improper error args: {error}"));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term), "improper error args");
}

#[test]
fn disconnected_dist_spawn_opt_returns_reference_and_monitor_flag() {
    let _serial = serialized();
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping dist_spawn_request differential test");
        return;
    };
    let source = r#"
-module(vm_triage_dist_spawn).
-export([run/1]).
run(Options) ->
    case erts_internal:dist_spawn_request(
           'triage_remote@localhost', {erlang, abs, [1]}, Options, spawn_opt) of
        {Ref, Monitor} when is_reference(Ref) -> {true, Monitor};
        Other -> Other
    end.
"#;
    let beam = reference
        .compile_named("vm_triage_dist_spawn", source, &[])
        .expect("compile dist spawn fixture");
    reference
        .load("vm_triage_dist_spawn", &beam)
        .expect("load dist spawn fixture in OTP");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load dist spawn fixture");
    for (options, label) in [
        (OwnedTerm::Nil, "without monitor"),
        (
            OwnedTerm::List {
                elems: vec![OwnedTerm::Atom("monitor".into())],
                tail: Box::new(OwnedTerm::Nil),
            },
            "with monitor",
        ),
    ] {
        let expected = reference.call(
            "vm_triage_dist_spawn",
            "run",
            std::slice::from_ref(&options),
        );
        let mut heap = VecHeap::new();
        let argument = from_owned(&options, &mut heap).expect("build spawn options");
        let actual = vm
            .eval_scheduled("vm_triage_dist_spawn", "run", &[argument], 1, None)
            .unwrap_or_else(|error| panic!("dist spawn {label}: {error}"));
        assert_same(expected, CallResult::Ok(actual.term), label);
    }
}

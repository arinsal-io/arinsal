use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{ProcessHeap, from_owned};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;
use std::path::Path;

const MODULE: &str = "hello";

#[test]
fn hello_entry_point_preserves_unaligned_binary_match_tail() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping differential check");
        return;
    };
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/otp/erts/emulator/test/hello_SUITE_data/hello.erl");
    let source = source.to_str().expect("OTP source path is UTF-8");
    assert!(source.is_ascii() && !source.contains('"'));
    let compiled = reference
        .eval(&format!(
            "case compile:file(\"{source}\", [binary, export_all, {{d, 'RUN_AS_TESTCASE'}}]) of {{ok, hello, Beam}} -> Beam; {{ok, hello, Beam, _}} -> Beam; Other -> erlang:error(Other) end"
        ))
        .unwrap();
    let OwnedTerm::Binary(beam) = &compiled else {
        panic!("compile:file did not return a BEAM binary");
    };
    reference.load(MODULE, beam).unwrap();
    let boot_args = OwnedTerm::List {
        elems: [
            "-root",
            "/home/user/git/otp",
            "-progname",
            "/home/user/git/otp/bin/cerl -debug +asmdump",
            "--",
            "-home",
            "/home/user",
            "--",
            "-kernel",
            "shell_history",
            "enabled",
            "--",
            "--",
        ]
        .into_iter()
        .map(|value| OwnedTerm::Binary(value.as_bytes().to_vec()))
        .collect(),
        tail: Box::new(OwnedTerm::Nil),
    };
    let expected = reference.call(MODULE, "test", std::slice::from_ref(&boot_args));

    let mut vm = Vm::new([]);
    vm.load_bytes(beam).unwrap();
    let mut argument_heap = ProcessHeap::with_words(128);
    let boot_args_term = from_owned(&boot_args, &mut argument_heap).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "test", &[boot_args_term], 10, None)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

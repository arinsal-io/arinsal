use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(atomics_error_info_diff).
-export([run/0]).
run() ->
    try atomics:new(0, []) of
        Value -> Value
    catch
        error:Reason:Stack ->
            {Reason, proplists:get_value(error_info, element(4, hd(Stack))),
             erl_error:format_exception(error, Reason, Stack)}
    end.
"#;

#[test]
fn atomics_error_three_preserves_error_info_in_stacktrace() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping atomics error_info differential test");
        return;
    };
    let beam = reference
        .compile_named("atomics_error_info_diff", SOURCE, &[])
        .unwrap();
    reference.load("atomics_error_info_diff", &beam).unwrap();
    let expected = reference.call("atomics_error_info_diff", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("atomics_error_info_diff", "run", &[], 1, Some(73))
        .unwrap()
        .term;
    let CallResult::Ok(expected) = expected else {
        panic!("reference error result failed: {expected:?}");
    };
    let OwnedTerm::Tuple(expected) = &expected else {
        panic!("reference returned a non-tuple: {expected:?}");
    };
    let OwnedTerm::Tuple(actual) = &actual else {
        panic!("Arinsal returned a non-tuple: {actual:?}");
    };
    assert_eq!(&actual[..2], &expected[..2]);
    let mut formatted = Vec::new();
    flatten_iodata(&actual[2], &mut formatted);
    let formatted = String::from_utf8(formatted).unwrap();
    assert!(
        formatted.contains("*** argument 1: out of range"),
        "{formatted}"
    );
}

fn flatten_iodata(term: &OwnedTerm, output: &mut Vec<u8>) {
    match term {
        OwnedTerm::Int(value) if (0..=255).contains(value) => output.push(*value as u8),
        OwnedTerm::List { elems, tail } => {
            for item in elems {
                flatten_iodata(item, output);
            }
            flatten_iodata(tail, output);
        }
        OwnedTerm::Nil => {}
        OwnedTerm::Binary(bytes) => output.extend_from_slice(bytes),
        other => panic!("invalid iodata item: {other:?}"),
    }
}

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, VecHeap, from_owned, to_owned};
use arinsal_vm::{Vm, VmError};

fn compare_call(vm: &mut Vm, reference: &RefErl, name: &str, arg: i64) {
    let input = OwnedTerm::Int(arg);
    let expected = reference.call("vm_maps_bits_diff", name, std::slice::from_ref(&input));
    let mut heap = VecHeap::new();
    let term = from_owned(&input, &mut heap).unwrap();
    let actual = vm
        .eval("vm_maps_bits_diff", name, &[term])
        .map(|outcome| to_owned(outcome.term).unwrap());
    match (expected, actual) {
        (CallResult::Ok(expected), Ok(actual)) => assert_eq!(actual, expected, "{name}({arg})"),
        (expected, actual) => panic!("{name}({arg}): reference {expected:?}, VM {actual:?}"),
    }
}

#[test]
fn five_hundred_generated_map_and_bit_syntax_snippets() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping map and bit syntax differential test");
        return;
    };
    let names: Vec<_> = (0..500).map(|n| format!("case_{n:03}")).collect();
    let mut source = format!(
        "-module(vm_maps_bits_diff).\n-export([{}]).\n",
        names
            .iter()
            .map(|name| format!("{name}/1"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let big_entries = (1..=32)
        .map(|n| format!("{n}=>{n}"))
        .collect::<Vec<_>>()
        .join(",");
    for (n, name) in names.iter().enumerate() {
        let expression = match n {
            0..=99 => format!(
                "M=#{{a=>A,b=>{n}}}, R=M#{{a:=A+{n},c=>A}}, {{maps:get(a,R),maps:get(c,R),maps:size(R)}}"
            ),
            100..=199 => format!(
                "M=#{{inner=>#{{k=>A,n=>{n}}},outer=>A}}, case M of #{{inner:=#{{k:=K,n:={n}}},outer:=O}} -> {{K,O}}; _ -> no end"
            ),
            200..=299 => format!(
                "M=#{{0=>A,{big_entries}}}, K=A rem 33, R=M#{{K=>A+{n}}}, {{maps:size(R),maps:get(K,R)}}"
            ),
            300..=399 => {
                let binary = match n % 5 {
                    0 => format!("<<A:3,(A+{n}):13/little-signed,255:8>>"),
                    1 => "<<(A+1.5):32/float-little>>".into(),
                    2 => "<<A/utf8,A:16>>".into(),
                    3 => "<<A/utf16-little,A:5>>".into(),
                    _ => "<<A/utf32,1:1>>".into(),
                };
                format!("B = {binary}, {{B,is_binary(B),is_bitstring(B)}}")
            }
            _ => match n % 8 {
                0 => "B = <<A:16/little-signed,7,8>>, <<X:16/little-signed,Y:2/binary>> = B, {X,Y}"
                    .into(),
                1 => "B = <<A:3,17:5,42:8>>, <<X:3,Y:5,Z:8>> = B, {X,Y,Z}".into(),
                2 => "B = <<A/utf8,1,2>>, <<X/utf8,R/binary>> = B, {X,R}".into(),
                3 => "B = <<(A+0.25):32/float>>, <<X:32/float>> = B, X".into(),
                4 => "B = <<A:5,42:8,3:3>>, <<X:5,Y:8,Z:3>> = B, {X,Y,Z}".into(),
                5 => "B = <<A/utf16-little,3>>, <<X/utf16-little,R/binary>> = B, {X,R}".into(),
                6 => "B = <<A/utf32,3>>, <<X/utf32,R/binary>> = B, {X,R}".into(),
                _ => "B = <<\"AB\",A:8>>, <<\"AB\",X:8>> = B, X".into(),
            },
        };
        source.push_str(&format!("{name}(A) -> {expression}.\n"));
    }
    let beam = reference
        .compile_named("vm_maps_bits_diff", &source, &[])
        .unwrap();
    reference.load("vm_maps_bits_diff", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for (n, name) in names.iter().enumerate() {
        compare_call(&mut vm, &reference, name, n as i64 + 1);
    }
}

#[test]
fn one_hundred_thousand_binary_appends_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping append differential test");
        return;
    };
    let source = "-module(vm_maps_bits_loop). -export([run/1]).
        run(N) -> byte_size(loop(N,<<>>)).
        loop(0,B) -> B;
        loop(N,B) -> loop(N-1,<<B/binary,N>>).";
    let beam = reference
        .compile_named("vm_maps_bits_loop", source, &[])
        .unwrap();
    reference.load("vm_maps_bits_loop", &beam).unwrap();
    let expected = reference.call("vm_maps_bits_loop", "run", &[OwnedTerm::Int(100_000)]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval("vm_maps_bits_loop", "run", &[Term::small(100_000).unwrap()])
        .map(|outcome| to_owned(outcome.term).unwrap());
    match (expected, actual) {
        (CallResult::Ok(expected), Ok(actual)) => assert_eq!(actual, expected),
        (expected, actual) => panic!("reference {expected:?}, VM {actual:?}"),
    }
}

#[test]
fn map_and_bit_error_reasons_match_otp_for_immediate_terms() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping map error differential test");
        return;
    };
    let source = "-module(vm_maps_bits_errors). -export([badmap/1,badkey/1,bad_size/1]).
        badmap(M) -> M#{a=>1}.
        badkey(M) -> M#{a:=1}.
        bad_size(N) -> <<1:N>>.";
    let beam = reference
        .compile_named("vm_maps_bits_errors", source, &[])
        .unwrap();
    reference.load("vm_maps_bits_errors", &beam).unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    for (name, input, expected_reason) in [
        (
            "badmap",
            OwnedTerm::Int(42),
            OwnedTerm::Tuple(vec![OwnedTerm::Atom("badmap".into()), OwnedTerm::Int(42)]),
        ),
        (
            "badkey",
            OwnedTerm::Map(vec![]),
            OwnedTerm::Tuple(vec![
                OwnedTerm::Atom("badkey".into()),
                OwnedTerm::Atom("a".into()),
            ]),
        ),
    ] {
        let result = reference.call("vm_maps_bits_errors", name, std::slice::from_ref(&input));
        assert!(
            matches!(result, CallResult::Exception { reason, .. } if reason == expected_reason)
        );
        let mut arg_heap = VecHeap::new();
        let arg = from_owned(&input, &mut arg_heap).unwrap();
        let error = vm.eval("vm_maps_bits_errors", name, &[arg]).err().unwrap();
        // The structured reason must equal erts' reason term exactly.
        let VmError::Raised(raised) = error else {
            panic!("expected a raised exception: {error:?}");
        };
        assert_eq!(raised.reason, expected_reason, "{name}");
    }
    let expected = reference.call("vm_maps_bits_errors", "bad_size", &[OwnedTerm::Int(-1)]);
    assert!(
        matches!(expected, CallResult::Exception { reason: OwnedTerm::Atom(ref reason), .. } if reason == "badarg")
    );
    let error = vm
        .eval(
            "vm_maps_bits_errors",
            "bad_size",
            &[Term::small(-1).unwrap()],
        )
        .err()
        .unwrap();
    let VmError::Raised(raised) = error else {
        panic!("expected a raised exception: {error:?}");
    };
    assert_eq!(raised.reason, OwnedTerm::Atom("badarg".into()));
}

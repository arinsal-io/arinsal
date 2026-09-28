use arinsal_difftest::{CallOptions, CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm;
use std::time::{Duration, Instant};

fn atom(s: &str) -> OwnedTerm {
    OwnedTerm::Atom(s.into())
}
fn int(n: i64) -> OwnedTerm {
    OwnedTerm::Int(n)
}
fn chars(s: &str) -> OwnedTerm {
    OwnedTerm::List {
        elems: s.chars().map(|c| int(c as i64)).collect(),
        tail: Box::new(OwnedTerm::Nil),
    }
}

#[test]
fn version_and_basic_calls() {
    let erl = RefErl::start().unwrap();
    assert_eq!(erl.otp_version(), "29.1.1");
    assert_eq!(
        erl.call("erlang", "abs", &[int(-9)]),
        CallResult::Ok(int(9))
    );
    assert!(
        matches!(erl.call("erlang","element",&[int(3), OwnedTerm::Tuple(vec![int(1)])]),CallResult::Exception { class, .. } if class=="error")
    );
}
#[test]
fn concurrent_requests_match_ids() {
    let erl = RefErl::start().unwrap();
    let calls: Vec<_> = (0..1000)
        .map(|n| ("erlang", "abs", vec![int(-n)]))
        .collect();
    let replies = erl.call_batch(&calls);
    assert_eq!(replies.len(), calls.len());
    for (n, result) in replies.iter().enumerate() {
        assert_eq!(result, &CallResult::Ok(int(n as i64)));
    }
}
#[test]
fn timeout_crash_and_halt_are_isolated() {
    let erl = RefErl::start().unwrap();
    let opts = CallOptions {
        timeout_ms: Some(20),
        ..Default::default()
    };
    assert_eq!(
        erl.call_opts("timer", "sleep", &[atom("infinity")], &opts)
            .result,
        CallResult::Timeout
    );
    assert!(
        matches!(erl.call("erlang","exit",&[atom("kill")]),CallResult::Exception { class, .. } if class=="exit")
    );
    assert!(
        matches!(erl.call("erlang","halt",&[]),CallResult::Exception { reason: OwnedTerm::Atom(ref reason), .. } if reason=="forbidden_call")
    );
    assert!(
        matches!(erl.call("init","stop",&[]),CallResult::Exception { reason: OwnedTerm::Atom(ref reason), .. } if reason=="forbidden_call")
    );
    assert_eq!(
        erl.call("erlang", "abs", &[int(-7)]),
        CallResult::Ok(int(7))
    );
}
#[test]
fn eval_compile_load_and_metrics() {
    let erl = RefErl::start().unwrap();
    assert_eq!(erl.eval("1 + 2").unwrap(), int(3));
    let src = "-module(difftest_inline). -export([twice/1]). twice(X) -> X * 2.";
    let beam = erl.compile(src).unwrap();
    assert!(beam.starts_with(b"FOR1"));
    erl.load("difftest_inline", &beam).unwrap();
    assert_eq!(
        erl.call("difftest_inline", "twice", &[int(21)]),
        CallResult::Ok(int(42))
    );
    let opts = CallOptions {
        capture_io: true,
        reductions: true,
        heap: true,
        ..Default::default()
    };
    let result = erl.call_opts("io", "format", &[chars("hello"), OwnedTerm::Nil], &opts);
    assert_eq!(result.result, CallResult::Ok(atom("ok")));
    assert_eq!(result.io.as_deref(), Some(b"hello".as_slice()));
    assert!(result.reductions.is_some());
    assert!(result.heap.unwrap() > 0);
}
#[test]
fn comparison_paths_and_numeric_equality() {
    let a = CallResult::Ok(OwnedTerm::Tuple(vec![int(1), int(2)]));
    let b = CallResult::Ok(OwnedTerm::Tuple(vec![int(1), int(3)]));
    assert!(
        compare(&a, &b, CompareMode::Exact)
            .unwrap_err()
            .path
            .ends_with("element 2")
    );
    assert!(
        compare(
            &CallResult::Ok(int(2)),
            &CallResult::Ok(OwnedTerm::Float(2.0)),
            CompareMode::Equal
        )
        .is_ok()
    );
    assert!(
        compare(
            &CallResult::Ok(int(2)),
            &CallResult::Ok(OwnedTerm::Float(2.0)),
            CompareMode::Exact
        )
        .is_err()
    );
    assert!(
        compare(
            &CallResult::Ok(int(9_007_199_254_740_993)),
            &CallResult::Ok(OwnedTerm::Float(9_007_199_254_740_992.0)),
            CompareMode::Equal
        )
        .is_err()
    );
    assert!(
        compare(
            &CallResult::Ok(OwnedTerm::Float(0.0)),
            &CallResult::Ok(OwnedTerm::Float(-0.0)),
            CompareMode::Exact
        )
        .is_err()
    );
}
#[test]
fn pipelined_throughput() {
    let erl = RefErl::start().unwrap();
    let calls: Vec<_> = (0..10_000)
        .map(|_| ("erlang", "abs", vec![int(-1)]))
        .collect();
    let begin = Instant::now();
    let replies = erl.call_batch(&calls);
    let elapsed = begin.elapsed();
    assert!(replies.iter().all(|r| *r == CallResult::Ok(int(1))));
    let rate = calls.len() as f64 / elapsed.as_secs_f64();
    eprintln!("pipelined rate: {rate:.0} calls/s ({elapsed:?})");
    // Catches gross regressions only; parallel agents' builds can load the machine 30+.
    assert!(
        elapsed < Duration::from_secs(10),
        "{rate:.0} calls/s below 1,000"
    );
}

#[test]
fn full_etf_codec_roundtrip() {
    let value = OwnedTerm::Tuple(vec![int(1), atom("é")]);
    let bytes = arinsal_etf::encode(&value, Default::default());
    assert_eq!(arinsal_etf::decode(&bytes).unwrap(), value);
}
#[test]
fn full_etf_stage1_selfcheck() {
    let left = RefErl::start().unwrap();
    let right = RefErl::start().unwrap();
    for case in arinsal_difftest::suites::stage1() {
        compare(
            &left.call(case.spec.module, case.spec.function, &case.args),
            &right.call(case.spec.module, case.spec.function, &case.args),
            case.spec.mode,
        )
        .unwrap();
    }
}

arinsal_difftest::difftest!(
    macro_reverse,
    "lists",
    "reverse",
    [OwnedTerm::List {
        elems: vec![int(1), int(2)],
        tail: Box::new(OwnedTerm::Nil)
    }]
);

#[test]
fn bootstrap_codec_handles_large_and_bit_terms() {
    use num_bigint::BigInt;
    let erl = RefErl::start().unwrap();
    let huge = OwnedTerm::BigInt(BigInt::from(1_u64) << 80_usize);
    assert_eq!(
        erl.call("erlang", "abs", std::slice::from_ref(&huge)),
        CallResult::Ok(huge)
    );
    let bits = OwnedTerm::BitString {
        bytes: vec![0b1010_0000],
        bits: 3,
    };
    assert_eq!(
        erl.call("erlang", "bit_size", &[bits]),
        CallResult::Ok(int(3))
    );
    let opts = CallOptions {
        encode_opts: Some(vec![OwnedTerm::Tuple(vec![atom("compressed"), int(6)])]),
        ..Default::default()
    };
    let output = erl.call_opts("erlang", "abs", &[int(-123)], &opts);
    assert!(
        matches!(output.result,CallResult::Ok(OwnedTerm::Binary(ref b)) if b.starts_with(&[131]))
    );
}

#[test]
fn registry_generators_are_executable() {
    use proptest::strategy::{Strategy, ValueTree};
    let mut runner = proptest::test_runner::TestRunner::default();
    for case in arinsal_difftest::suites::stage1() {
        let generated = arinsal_difftest::gens::for_spec(&case.spec)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        assert_eq!(generated.len(), case.args.len(), "{}", case.name);
    }
}

#[test]
fn property_style_selfcheck() {
    let mut left = RefErl::start().unwrap();
    let mut right = RefErl::start().unwrap();
    let spec = arinsal_difftest::suites::stage1()
        .into_iter()
        .find(|c| c.name == "maps:put/3")
        .unwrap()
        .spec;
    arinsal_difftest::gens::diff_prop(
        &mut left,
        &mut right,
        "maps",
        "put",
        arinsal_difftest::gens::for_spec(&spec),
        100,
    )
    .unwrap();
}

#[test]
fn stack_locations_are_stripped_only_on_request() {
    fn has_line(result: &CallResult) -> bool {
        let CallResult::Exception {
            stack_top: Some(OwnedTerm::Tuple(frame)),
            ..
        } = result
        else {
            return false;
        };
        let Some(OwnedTerm::List { elems, .. }) = frame.get(3) else {
            return false;
        };
        elems.iter().any(|item| matches!(item,OwnedTerm::Tuple(pair) if matches!(pair.first(),Some(OwnedTerm::Atom(name)) if name=="line")))
    }
    let erl = RefErl::start().unwrap();
    let args = [int(0), OwnedTerm::Nil];
    let original = erl.call("lists", "nth", &args);
    let stripped = erl
        .call_opts(
            "lists",
            "nth",
            &args,
            &CallOptions {
                strip_lines: true,
                ..Default::default()
            },
        )
        .result;
    assert!(has_line(&original));
    assert!(!has_line(&stripped));
}

#[test]
fn captured_io_is_utf8() {
    let erl = RefErl::start().unwrap();
    let args = [
        chars("~ts"),
        OwnedTerm::List {
            elems: vec![chars("hé")],
            tail: Box::new(OwnedTerm::Nil),
        },
    ];
    let result = erl.call_opts(
        "io",
        "format",
        &args,
        &CallOptions {
            capture_io: true,
            ..Default::default()
        },
    );
    assert_eq!(result.io.as_deref(), Some("hé".as_bytes()));
}

#[test]
fn map_float_keys_preserve_zero_sign() {
    let erl = RefErl::start().unwrap();
    let map = OwnedTerm::Map(vec![
        (OwnedTerm::Float(0.0), int(1)),
        (OwnedTerm::Float(-0.0), int(2)),
    ]);
    assert_eq!(erl.call("maps", "size", &[map]), CallResult::Ok(int(2)));
}

#[test]
fn server_created_pid_and_ref_roundtrip() {
    let erl = RefErl::start().unwrap();
    let pid = arinsal_difftest::gens::pid(&erl).unwrap();
    let reference = arinsal_difftest::gens::reference(&erl).unwrap();
    let export = arinsal_difftest::gens::export(&erl).unwrap();
    let port = arinsal_difftest::gens::port(&erl).unwrap();
    assert!(matches!(port, OwnedTerm::Port { .. }));
    assert!(matches!(export, OwnedTerm::Export { .. }));
    assert!(matches!(pid, OwnedTerm::Pid { .. }));
    assert!(matches!(reference, OwnedTerm::Ref { .. }));
    assert_eq!(
        erl.call("erlang", "is_pid", &[pid]),
        CallResult::Ok(atom("true"))
    );
    assert_eq!(
        erl.call("erlang", "is_reference", &[reference]),
        CallResult::Ok(atom("true"))
    );
}

#[test]
fn large_map_strategy_crosses_flatmap_threshold() {
    use proptest::strategy::{Strategy, ValueTree};
    let mut runner = proptest::test_runner::TestRunner::default();
    let map = arinsal_difftest::gens::large_map()
        .new_tree(&mut runner)
        .unwrap()
        .current();
    let OwnedTerm::Map(ref entries) = map else {
        panic!("expected map")
    };
    let size = entries.len();
    assert!(size > 32);
    let erl = RefErl::start().unwrap();
    assert_eq!(
        erl.call("maps", "size", &[map]),
        CallResult::Ok(int(size as i64))
    );
}

#[test]
fn local_fun_from_reference() {
    let erl = RefErl::start().unwrap();
    assert!(matches!(
        arinsal_difftest::gens::local_fun(&erl).unwrap(),
        OwnedTerm::Fun { .. }
    ));
}

use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
use arinsal_difftest::{CallResult, Error as RefError, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, from_owned, to_owned};

fn atom(name: &str) -> O {
    O::atom(name)
}
fn call(name: &str, args: &[O]) -> Result<O, BifError> {
    let mut heap = ProcessHeap::with_words(1024);
    let mut alloc = ProcessHeapHandle(&mut heap);
    let terms = args
        .iter()
        .map(|a| from_owned(a, &mut alloc).unwrap())
        .collect::<Vec<_>>();
    let mut ctx = Ctx::new(&mut alloc);
    let bif = arinsal_re::lookup("re", name, args.len() as u8).unwrap();
    bif(&mut ctx, &terms).map(|value| to_owned(value).unwrap())
}
fn reference() -> Option<&'static RefErl> {
    match RefErl::shared() {
        Ok(r) => Some(r),
        Err(RefError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping OTP differential: erl or erlc not found");
            None
        }
        Err(e) => panic!("reference failed: {e}"),
    }
}
#[test]
fn registry_and_version() {
    for (name, arity) in [
        ("version", 0),
        ("compile", 1),
        ("compile", 2),
        ("run", 2),
        ("run", 3),
        ("internal_run", 4),
        ("inspect", 2),
        ("import", 1),
    ] {
        assert!(arinsal_re::lookup("re", name, arity).is_some());
    }
    assert!(arinsal_re::lookup("erlang", "run", 3).is_none());
    let local = call("version", &[]).unwrap();
    let Some(reference) = reference() else {
        return;
    };
    assert_eq!(CallResult::Ok(local), reference.call("re", "version", &[]));
}
#[test]
fn simple_compile_run_and_inspect() {
    let pattern = O::Binary(b"(?<word>ab)(c)?".to_vec());
    let opts = O::Nil;
    let compiled = call("compile", &[pattern.clone(), opts]).unwrap();
    let O::Tuple(ref parts) = compiled else {
        panic!("compile result")
    };
    assert_eq!(parts[0], atom("ok"));
    let mp = parts[1].clone();
    assert_eq!(
        call("inspect", &[mp.clone(), atom("namelist")]).unwrap(),
        O::Tuple(vec![
            atom("namelist"),
            O::list(vec![O::Binary(b"word".to_vec())])
        ])
    );
    let subject = O::Binary(b"xxabyy".to_vec());
    let direct = call("run", &[subject.clone(), pattern]).unwrap();
    let precompiled = call("run", &[subject, mp]).unwrap();
    assert_eq!(direct, precompiled);
    assert_eq!(
        direct,
        O::Tuple(vec![
            atom("match"),
            O::list(vec![
                O::Tuple(vec![O::Int(2), O::Int(2)]),
                O::Tuple(vec![O::Int(2), O::Int(2)])
            ])
        ])
    );
}

fn local_result(name: &str, args: &[O]) -> CallResult {
    match call(name, args) {
        Ok(result) => CallResult::Ok(result),
        Err(BifError::Badarg { .. }) => CallResult::Exception {
            class: "error".into(),
            reason: atom("badarg"),
            stack_top: None,
        },
        Err(other) => panic!("unexpected native error: {other:?}"),
    }
}
fn same_result(actual: &CallResult, expected: &CallResult) -> bool {
    match (actual, expected) {
        (CallResult::Ok(a), CallResult::Ok(b)) => a == b,
        (
            CallResult::Exception {
                class: ac,
                reason: ar,
                ..
            },
            CallResult::Exception {
                class: ec,
                reason: er,
                ..
            },
        ) => ac == ec && ar == er,
        _ => false,
    }
}
#[test]
fn generated_differential() {
    let Some(reference) = reference() else {
        return;
    };
    let patterns: &[&[u8]] = &[
        b"",
        b"a",
        b"b",
        b"ab",
        b"a+",
        b"a*",
        b"a?",
        b".",
        b"^a",
        b"a$",
        b"(a)",
        b"(a)(b)",
        b"(?<x>a)",
        b"(?<x>a)(?<y>b)",
        b"a|b",
        b"[ab]+",
        b"[^a]",
        b"\\d+",
        b"\\w+",
        b"a.*b",
        b"(a|b)+",
        b"(?i)a",
        b"(?<=a)b",
        b"(?:a)?b",
        b"(a)?b",
        b"(a*)(b*)",
        b"[",
        b"(",
        b"a{",
        b"(?<x>a)(?<x>b)",
        b"\\p{L}+",
        b"^$",
    ];
    let subjects: &[&[u8]] = &[
        b"",
        b"a",
        b"b",
        b"ab",
        b"aba",
        b"abc",
        b"ba",
        b"aaaa",
        b"bbb",
        b"a\nb",
        b"a\r\nb",
        b"123",
        b"a1b2",
        b"xxabyy",
        b"A",
        b"AB",
        b"foo",
        b"\xc3\xa9",
        b"a\xc3\xa9b",
        b"\xe4\xb8\xad",
        b"\xff",
        b"a\xffb",
        b"\xc3",
        b"\0a",
        b"abab",
    ];
    let cap = |spec: O, ty: &str| O::Tuple(vec![atom("capture"), spec, atom(ty)]);
    let optsets = vec![
        vec![],
        vec![atom("global")],
        vec![atom("caseless")],
        vec![atom("anchored")],
        vec![atom("multiline")],
        vec![atom("dotall")],
        vec![atom("unicode")],
        vec![atom("unicode"), atom("global")],
        vec![atom("ucp")],
        vec![atom("report_errors")],
        vec![atom("notempty")],
        vec![atom("notempty_atstart")],
        vec![O::Tuple(vec![atom("offset"), O::Int(1)])],
        vec![
            O::Tuple(vec![atom("match_limit"), O::Int(1)]),
            atom("report_errors"),
        ],
        vec![
            O::Tuple(vec![atom("match_limit_recursion"), O::Int(1)]),
            atom("report_errors"),
        ],
        vec![cap(atom("first"), "index")],
        vec![cap(atom("all_but_first"), "index")],
        vec![cap(atom("none"), "index")],
        vec![cap(atom("all"), "binary")],
        vec![cap(atom("all"), "list")],
        vec![cap(atom("all_names"), "index")],
        vec![cap(O::list(vec![O::Int(1), O::Int(0), O::Int(9)]), "index")],
        vec![cap(O::list(vec![atom("x"), atom("y")]), "binary")],
        vec![atom("global"), cap(atom("all"), "binary")],
        vec![atom("global"), cap(atom("first"), "list")],
    ];
    let mut cases = Vec::with_capacity(20_000);
    for pattern in patterns {
        for subject in subjects {
            for opts in &optsets {
                cases.push(vec![
                    O::Binary(subject.to_vec()),
                    O::Binary(pattern.to_vec()),
                    O::list(opts.clone()),
                ]);
            }
        }
    }
    let mut checked = 0;
    for chunk in cases.chunks(128) {
        let batch = chunk
            .iter()
            .map(|args| ("re", "run", args.clone()))
            .collect::<Vec<_>>();
        let expected = reference.call_batch(&batch);
        for (args, reference_result) in chunk.iter().zip(expected.iter()) {
            let actual = local_result("run", args);
            assert!(
                same_result(&actual, reference_result),
                "case {checked}: {args:?}\nactual: {actual:?}\nreference: {reference_result:?}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 20_000);
}

fn compare_compiles(actual: &CallResult, expected: &CallResult) -> bool {
    match (actual, expected) {
        (CallResult::Ok(O::Tuple(a)), CallResult::Ok(O::Tuple(b)))
            if a.len() == 2 && b.len() == 2 && a[0] == atom("ok") && b[0] == atom("ok") =>
        {
            match (&a[1], &b[1]) {
                (O::Tuple(left), O::Tuple(right)) if left.len() == 5 && right.len() == 5 => {
                    left[..4] == right[..4]
                }
                _ => false,
            }
        }
        _ => same_result(actual, expected),
    }
}
#[test]
fn generated_compile_differential() {
    let Some(reference) = reference() else {
        return;
    };
    let patterns: &[&[u8]] = &[
        b"",
        b"a",
        b"b",
        b"ab",
        b"a+",
        b"a*",
        b"a?",
        b".",
        b"^a",
        b"a$",
        b"(a)",
        b"(a)(b)",
        b"(?<x>a)",
        b"(?<x>a)(?<y>b)",
        b"a|b",
        b"[ab]+",
        b"[^a]",
        b"\\d+",
        b"\\w+",
        b"a.*b",
        b"(a|b)+",
        b"(?i)a",
        b"(?<=a)b",
        b"(?:a)?b",
        b"(a)?b",
        b"(a*)(b*)",
        b"[",
        b"(",
        b"a{",
        b"(?<x>a)(?<x>b)",
        b"\\p{L}+",
        b"^$",
        b"\xff",
        b"\xc3",
    ];
    let option_sets = [
        vec![],
        vec![atom("unicode")],
        vec![atom("caseless")],
        vec![atom("anchored")],
        vec![atom("ucp")],
        vec![atom("unicode"), atom("ucp")],
        vec![atom("multiline")],
        vec![atom("dotall")],
        vec![atom("extended")],
        vec![atom("no_auto_capture")],
        vec![atom("dupnames")],
        vec![atom("ungreedy")],
        vec![atom("firstline")],
        vec![atom("no_start_optimize")],
        vec![atom("never_utf")],
        vec![atom("bsr_anycrlf")],
        vec![atom("bsr_unicode")],
        vec![O::Tuple(vec![atom("newline"), atom("cr")])],
        vec![O::Tuple(vec![atom("newline"), atom("crlf")])],
        vec![O::Tuple(vec![atom("newline"), atom("any")])],
        vec![atom("report_errors")],
        vec![atom("global")],
        vec![O::Tuple(vec![atom("capture"), atom("first")])],
        vec![O::Tuple(vec![atom("offset"), O::Int(1)])],
        vec![atom("unicode"), atom("never_utf")],
    ];
    let mut cases = Vec::with_capacity(20_000);
    for i in 0..20_000 {
        let p = patterns[(i * 17 + i / 31) % patterns.len()];
        let options = &option_sets[(i * 13 + i / 41) % option_sets.len()];
        let mut generated = p.to_vec();
        generated.extend_from_slice(format!("(?#case_{i})").as_bytes());
        cases.push(vec![O::Binary(generated), O::list(options.clone())]);
    }
    let mut checked = 0;
    for chunk in cases.chunks(128) {
        let batch = chunk
            .iter()
            .map(|args| ("re", "compile", args.clone()))
            .collect::<Vec<_>>();
        let expected = reference.call_batch(&batch);
        for (args, reference_result) in chunk.iter().zip(expected.iter()) {
            let actual = local_result("compile", args);
            assert!(
                compare_compiles(&actual, reference_result),
                "case {checked}: {args:?}\nactual: {actual:?}\nreference: {reference_result:?}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 20_000);
}
#[test]
fn re_suite_data_pairs() {
    let Some(reference) = reference() else {
        return;
    };
    let pairs = include_str!("fixtures/re_suite_pairs.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let (pattern, subject) = line.split_once('\t').expect("fixture pair");
            vec![
                O::Binary(subject.as_bytes().to_vec()),
                O::Binary(pattern.as_bytes().to_vec()),
                O::Nil,
            ]
        })
        .collect::<Vec<_>>();
    let mut checked = 0;
    for chunk in pairs.chunks(128) {
        let batch = chunk
            .iter()
            .map(|args| ("re", "run", args.clone()))
            .collect::<Vec<_>>();
        let expected = reference.call_batch(&batch);
        for (args, reference_result) in chunk.iter().zip(expected.iter()) {
            let actual = local_result("run", args);
            assert!(
                same_result(&actual, reference_result),
                "suite pair {checked}: {args:?}\nactual: {actual:?}\nreference: {reference_result:?}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 1000, "extracted only {checked} suite pairs");
}

#[test]
fn export_matches_otp_serialization() {
    let Some(reference) = reference() else {
        return;
    };
    for pattern in [b"a".as_slice(), b"(?<x>a)(b)?", b"\\p{L}+"] {
        for options in [vec![atom("export")], vec![atom("export"), atom("unicode")]] {
            let args = [O::Binary(pattern.to_vec()), O::list(options)];
            let actual = local_result("compile", &args);
            let expected = reference.call("re", "compile", &args);
            assert!(
                same_result(&actual, &expected),
                "export: {args:?}\nactual: {actual:?}\nreference: {expected:?}"
            );
        }
    }
}

#[test]
fn import_export_roundtrip() {
    let Some(reference) = reference() else {
        return;
    };
    for pattern in [b"a".as_slice(), b"(?<x>a)(b)?", b"\\p{L}+"] {
        let options = O::list(vec![atom("export")]);
        let exported =
            match reference.call("re", "compile", &[O::Binary(pattern.to_vec()), options]) {
                CallResult::Ok(value) => value,
                other => panic!("reference export: {other:?}"),
            };
        let O::Tuple(ref result) = exported else {
            panic!("export result")
        };
        let local = local_result("import", &[result[1].clone()]);
        let expected = reference.call("re", "import", &[result[1].clone()]);
        let CallResult::Ok(O::Tuple(ref local_mp)) = local else {
            panic!("local import: {local:?}")
        };
        let CallResult::Ok(O::Tuple(ref reference_mp)) = expected else {
            panic!("reference import: {expected:?}")
        };
        assert_eq!(local_mp[..4], reference_mp[..4]);
    }
}

#[test]
fn patched_loop_budget_resumes() {
    arinsal_re::set_loop_budget(10).unwrap();
    let result = call(
        "run",
        &[O::Binary(vec![b'a'; 256]), O::Binary(b"a+$".to_vec())],
    )
    .unwrap();
    assert!(matches!(result, O::Tuple(_)));
    assert!(arinsal_re::last_loop_count() > 0);
    arinsal_re::set_loop_budget(1_000_000).unwrap();
}

#[test]
fn compiled_patterns_match_reference_raw_runs() {
    let Some(reference) = reference() else {
        return;
    };
    let patterns = [
        b"a+".as_slice(),
        b"(?<x>a)(b)?",
        b"a|b",
        b"^a",
        b"\\p{L}+",
        b"a*",
        b"(?<x>a)(?<y>b)",
    ];
    let subjects = [
        b"".as_slice(),
        b"a",
        b"ab",
        b"aba",
        b"bbb",
        b"xxab",
        b"\xc3\xa9a",
    ];
    let compile_opts = [
        vec![],
        vec![atom("caseless")],
        vec![atom("unicode")],
        vec![atom("multiline")],
    ];
    let run_opts = [
        vec![],
        vec![atom("global")],
        vec![O::Tuple(vec![atom("capture"), atom("all"), atom("binary")])],
        vec![O::Tuple(vec![
            atom("capture"),
            atom("all_names"),
            atom("index"),
        ])],
        vec![
            atom("global"),
            O::Tuple(vec![atom("capture"), atom("first"), atom("list")]),
        ],
    ];
    let mut checked = 0;
    for pattern in patterns {
        for subject in subjects {
            for compile_options in &compile_opts {
                let compiled = call(
                    "compile",
                    &[
                        O::Binary(pattern.to_vec()),
                        O::list(compile_options.clone()),
                    ],
                )
                .unwrap();
                let O::Tuple(ref parts) = compiled else {
                    panic!("compile result")
                };
                if parts[0] != atom("ok") {
                    continue;
                }
                for run_options in &run_opts {
                    let local = local_result(
                        "run",
                        &[
                            O::Binary(subject.to_vec()),
                            parts[1].clone(),
                            O::list(run_options.clone()),
                        ],
                    );
                    let mut all_options = compile_options.clone();
                    all_options.extend(run_options.iter().cloned());
                    let expected = reference.call(
                        "re",
                        "run",
                        &[
                            O::Binary(subject.to_vec()),
                            O::Binary(pattern.to_vec()),
                            O::list(all_options),
                        ],
                    );
                    assert!(
                        same_result(&local, &expected),
                        "compiled mismatch pattern={pattern:?} subject={subject:?} compile={compile_options:?} run={run_options:?}\nactual={local:?}\nreference={expected:?}"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked >= 900);
}

#[test]
fn duplicate_names_and_limits_match_reference() {
    let Some(reference) = reference() else {
        return;
    };
    let cases = [
        (
            b"b".as_slice(),
            b"(?<x>a)|(?<x>b)".as_slice(),
            vec![
                atom("dupnames"),
                O::Tuple(vec![atom("capture"), atom("all_names"), atom("index")]),
            ],
        ),
        (
            b"b",
            b"(?<x>a)|(?<x>b)",
            vec![
                atom("dupnames"),
                O::Tuple(vec![
                    atom("capture"),
                    O::list(vec![atom("x")]),
                    atom("binary"),
                ]),
            ],
        ),
        (
            b"aaaaaaaaaaaaaz",
            b"(a+)*z",
            vec![
                O::Tuple(vec![atom("match_limit"), O::Int(1)]),
                atom("report_errors"),
            ],
        ),
        (
            b"aaaaaaaaaaaaaz",
            b"(a+)*z",
            vec![
                O::Tuple(vec![atom("match_limit_recursion"), O::Int(1)]),
                atom("report_errors"),
            ],
        ),
    ];
    for (subject, pattern, options) in cases {
        let args = [
            O::Binary(subject.to_vec()),
            O::Binary(pattern.to_vec()),
            O::list(options),
        ];
        let actual = local_result("run", &args);
        let expected = reference.call("re", "run", &args);
        assert!(
            same_result(&actual, &expected),
            "args={args:?}\nactual={actual:?}\nreference={expected:?}"
        );
    }
}

#[test]
fn unicode_charlists_match_reference() {
    let Some(reference) = reference() else {
        return;
    };
    let subjects = ["é中a", "Καλημέρα", "a🙂b", "", "ab"];
    let patterns = ["é", "中", "\\p{L}+", ".", "a"];
    for subject in subjects {
        for pattern in patterns {
            for capture in ["index", "list", "binary"] {
                let args = [
                    O::charlist(subject),
                    O::charlist(pattern),
                    O::list(vec![
                        atom("unicode"),
                        O::Tuple(vec![atom("capture"), atom("all"), atom(capture)]),
                    ]),
                ];
                let actual = local_result("run", &args);
                let expected = reference.call("re", "run", &args);
                assert!(
                    same_result(&actual, &expected),
                    "args={args:?}\nactual={actual:?}\nreference={expected:?}"
                );
            }
        }
    }
}

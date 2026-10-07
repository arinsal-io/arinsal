use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, Term, from_owned};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(re_vm_diff).
-export([run/3, run_error/3, compile_run/3, replace3/3, replace4/4, split2/2, split3/3, elixir_regex/1]).
run(Pattern, Subject, Options) -> re:run(Subject, Pattern, Options).
run_error(Pattern, Subject, Options) ->
    try re:run(Subject, Pattern, Options) catch error:badarg -> badarg; error:Reason -> {error, Reason} end.
compile_run(Pattern, Subject, Options) ->
    {ok, Compiled} = re:compile(Pattern, [unicode]),
    re:run(Subject, Compiled, Options).
replace3(Pattern, Subject, Replacement) -> re:replace(Subject, Pattern, Replacement).
replace4(Pattern, Subject, Replacement, Options) -> re:replace(Subject, Pattern, Replacement, Options).
split2(Subject, Pattern) -> re:split(Subject, Pattern).
split3(Subject, Pattern, Options) -> re:split(Subject, Pattern, Options).
elixir_regex(Subject) ->
    {ok, Compiled} = re:compile(<<"a(b)">>, [unicode]),
    re:run(Subject, Compiled, [{capture, all, index}]).
"#;

fn args_to_terms(values: &[O], heap: &mut ProcessHeap) -> Vec<Term> {
    values
        .iter()
        .map(|value| from_owned(value, heap).expect("test argument allocation"))
        .collect()
}

fn eval(
    beam: &[u8],
    function: &str,
    values: &[O],
) -> Result<arinsal_vm::ScheduledResult, arinsal_vm::VmError> {
    let mut vm = Vm::new([]);
    vm.load_bytes(beam)?;
    let mut heap = ProcessHeap::with_words(1024);
    let terms = args_to_terms(values, &mut heap);
    vm.eval_scheduled("re_vm_diff", function, &terms, 1, Some(41))
}

#[test]
#[ignore = "blocked on `source operand kind 5` in re:replace (boot_loop1)"]
fn scheduled_re_calls_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping scheduled re differential scenarios");
        return;
    };
    let beam = reference.compile_named("re_vm_diff", SOURCE, &[]).unwrap();
    reference.load("re_vm_diff", &beam).unwrap();

    let patterns: &[&[u8]] = &[
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
        b"\\p{L}+",
        b"^$",
        b"(?<x>a)(?<x>b)",
        b"\\s+",
        b"[0-9]+",
        b"(?:ab)+",
        b"a{1,3}",
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
        "é".as_bytes(),
        "aéb".as_bytes(),
        "中文".as_bytes(),
        b"abab",
    ];
    let options = [
        vec![],
        vec![O::atom("global")],
        vec![O::atom("caseless")],
        vec![O::atom("unicode")],
        vec![O::atom("multiline")],
        vec![O::Tuple(vec![
            O::atom("capture"),
            O::atom("all"),
            O::atom("binary"),
        ])],
        vec![O::Tuple(vec![
            O::atom("capture"),
            O::atom("all_names"),
            O::atom("index"),
        ])],
        vec![O::Tuple(vec![O::atom("offset"), O::Int(1)])],
    ];
    let mut checked = 0;
    'cases: for (pi, pattern) in patterns.iter().enumerate() {
        for (si, subject) in subjects.iter().enumerate() {
            let opts = options[(pi + si) % options.len()].clone();
            let values = [
                O::Binary(pattern.to_vec()),
                O::Binary(subject.to_vec()),
                O::list(opts),
            ];
            let expected = reference.call("re_vm_diff", "run", &values);
            let actual = eval(&beam, "run", &values)
                .unwrap_or_else(|error| panic!("run {values:?}: {error}"));
            assert_eq!(expected, CallResult::Ok(actual.term), "{values:?}");
            checked += 1;
            if checked == 64 {
                break 'cases;
            }
        }
    }
    assert_eq!(checked, 64);

    for values in [
        vec![
            O::Binary(b"[".to_vec()),
            O::Binary(b"a".to_vec()),
            O::list(vec![O::atom("report_errors")]),
        ],
        vec![
            O::Binary(b"a".to_vec()),
            O::Binary(b"a".to_vec()),
            O::list(vec![O::atom("invalid_option")]),
        ],
        vec![
            O::Binary(b"a".to_vec()),
            O::Binary(b"a".to_vec()),
            O::list(vec![O::Tuple(vec![O::atom("offset"), O::Int(-1)])]),
        ],
    ] {
        let expected = reference.call("re_vm_diff", "run_error", &values);
        let actual = eval(&beam, "run_error", &values)
            .unwrap_or_else(|error| panic!("run_error {values:?}: {error}"));
        assert_eq!(
            expected,
            CallResult::Ok(actual.term),
            "run_error {values:?}"
        );
    }

    {
        let (function, args) = ("elixir_regex", vec![O::Binary(b"zab".to_vec())]);
        let expected = reference.call("re_vm_diff", function, &args);
        let actual =
            eval(&beam, function, &args).unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }

    for (function, args) in [
        (
            "replace3",
            vec![
                O::Binary(b"a+".to_vec()),
                O::Binary(b"zaaab".to_vec()),
                O::Binary(b"X".to_vec()),
            ],
        ),
        (
            "replace4",
            vec![
                O::Binary(b"a+".to_vec()),
                O::Binary(b"zaaab".to_vec()),
                O::Binary(b"X".to_vec()),
                O::list(vec![
                    O::atom("global"),
                    O::Tuple(vec![O::atom("return"), O::atom("binary")]),
                ]),
            ],
        ),
        (
            "split2",
            vec![O::Binary(b"a,,b,c".to_vec()), O::Binary(b",".to_vec())],
        ),
        (
            "split3",
            vec![
                O::Binary(b"a,,b,c".to_vec()),
                O::Binary(b",".to_vec()),
                O::list(vec![
                    O::Tuple(vec![O::atom("return"), O::atom("binary")]),
                    O::atom("trim"),
                ]),
            ],
        ),
    ] {
        let expected = reference.call("re_vm_diff", function, &args);
        let actual =
            eval(&beam, function, &args).unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }

    let compile_args = [
        O::Binary(b"(?<word>ab)(c)?".to_vec()),
        O::Binary(b"xxabyy".to_vec()),
        O::list(vec![O::atom("unicode"), O::atom("global")]),
    ];
    let expected = reference.call("re_vm_diff", "compile_run", &compile_args);
    let actual = eval(&beam, "compile_run", &compile_args)
        .unwrap_or_else(|error| panic!("compile_run: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term));
}

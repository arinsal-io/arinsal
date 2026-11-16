//! Differential coverage, against OTP 29.1.1, of the bif.c, erl_bif_op.c and erl_bif_guard.c
//! BIFs whose bodies are `bif_table[].f` (`natives::bif`, `natives::erl_bif_op`,
//! `natives::erl_bif_guard`): 1000 inputs per BIF, every tenth with an invalid first argument,
//! each called through `apply/3` and through a direct call, comparing the value or the class,
//! reason, top stack frame and `error_info`.

use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, from_owned};

const MODULE: &str = "bif_op_moved_differential";
const SOURCE: &str = r#"
-module(bif_op_moved_differential).
-export([run/1]).

top([{M, F, A, Location} | _]) -> {M, F, A, proplists:get_value(error_info, Location)};
top([]) -> [];
top(_) -> other.

direct(hd, [A]) -> erlang:hd(A);
direct(tl, [A]) -> erlang:tl(A);
direct(element, [A, B]) -> erlang:element(A, B);
direct(setelement, [A, B, C]) -> erlang:setelement(A, B, C);
direct(tuple_size, [A]) -> erlang:tuple_size(A);
direct(min, [A, B]) -> erlang:min(A, B);
direct(max, [A, B]) -> erlang:max(A, B);
direct('not', [A]) -> erlang:'not'(A);
direct('and', [A, B]) -> erlang:'and'(A, B);
direct('or', [A, B]) -> erlang:'or'(A, B);
direct('xor', [A, B]) -> erlang:'xor'(A, B);
direct('==', [A, B]) -> erlang:'=='(A, B);
direct('/=', [A, B]) -> erlang:'/='(A, B);
direct('=:=', [A, B]) -> erlang:'=:='(A, B);
direct('=/=', [A, B]) -> erlang:'=/='(A, B);
direct('<', [A, B]) -> erlang:'<'(A, B);
direct('=<', [A, B]) -> erlang:'=<'(A, B);
direct('>', [A, B]) -> erlang:'>'(A, B);
direct('>=', [A, B]) -> erlang:'>='(A, B);
direct(is_atom, [A]) -> erlang:is_atom(A);
direct(is_list, [A]) -> erlang:is_list(A);
direct(is_tuple, [A]) -> erlang:is_tuple(A);
direct(is_float, [A]) -> erlang:is_float(A);
direct(is_integer, [A]) -> erlang:is_integer(A);
direct(is_number, [A]) -> erlang:is_number(A);
direct(is_pid, [A]) -> erlang:is_pid(A);
direct(is_port, [A]) -> erlang:is_port(A);
direct(is_reference, [A]) -> erlang:is_reference(A);
direct(is_binary, [A]) -> erlang:is_binary(A);
direct(is_bitstring, [A]) -> erlang:is_bitstring(A);
direct(is_function, [A]) -> erlang:is_function(A);
direct(is_boolean, [A]) -> erlang:is_boolean(A);
direct(is_record, [A]) -> erlang:is_record(A);
direct(is_record, [A, B]) -> erlang:is_record(A, B);
direct(is_record, [A, B, C]) -> erlang:is_record(A, B, C);
direct(is_map, [A]) -> erlang:is_map(A);
direct(error, [A]) -> erlang:error(A);
direct(exit, [A]) -> erlang:exit(A);
direct(throw, [A]) -> erlang:throw(A);
direct(raise, [A, B, C]) -> erlang:raise(A, B, C).

outcome(Fun) ->
    try Fun() of
        Value -> {ok, Value}
    catch
        Class:Reason:Stack -> {exception, Class, Reason, top(Stack)}
    end.

run_case({F, Args}) ->
    {outcome(fun() -> apply(erlang, F, Args) end), outcome(fun() -> direct(F, Args) end)}.

run(Cases) -> [run_case(Case) || Case <- Cases].
"#;

/// The moved BIFs: name and arity.
const BIFS: &[(&str, usize)] = &[
    ("hd", 1),
    ("tl", 1),
    ("element", 2),
    ("setelement", 3),
    ("tuple_size", 1),
    ("min", 2),
    ("max", 2),
    ("not", 1),
    ("and", 2),
    ("or", 2),
    ("xor", 2),
    ("==", 2),
    ("/=", 2),
    ("=:=", 2),
    ("=/=", 2),
    ("<", 2),
    ("=<", 2),
    (">", 2),
    (">=", 2),
    ("is_atom", 1),
    ("is_list", 1),
    ("is_tuple", 1),
    ("is_float", 1),
    ("is_integer", 1),
    ("is_number", 1),
    ("is_pid", 1),
    ("is_port", 1),
    ("is_reference", 1),
    ("is_binary", 1),
    ("is_bitstring", 1),
    ("is_function", 1),
    ("is_boolean", 1),
    ("is_record", 1),
    ("is_record", 2),
    ("is_record", 3),
    ("is_map", 1),
    ("error", 1),
    ("exit", 1),
    ("throw", 1),
    ("raise", 3),
];

fn atom(s: &str) -> O {
    O::atom(s)
}

fn term(n: usize) -> O {
    match n % 9 {
        0 => O::Int(n as i64 - 500),
        1 => O::Float(n as f64 / 3.0),
        2 => atom("true"),
        3 => O::Tuple(vec![O::Int(n as i64), atom("x")]),
        4 => O::list(vec![O::Int(n as i64), atom("a")]),
        5 => O::Binary(vec![(n % 256) as u8, 2]),
        6 => O::Map(vec![(atom("a"), O::Int(n as i64))]),
        7 => O::BitString {
            bytes: vec![0xa0],
            bits: 3,
        },
        _ => O::Nil,
    }
}

fn boolean(value: bool) -> O {
    atom(if value { "true" } else { "false" })
}

fn args(f: &str, arity: usize, n: usize) -> Vec<O> {
    let x = O::Int((n % 100) as i64);
    let seq = O::list(vec![x.clone(), atom("a"), O::Int(3)]);
    let tup = O::Tuple(vec![atom("a"), x, atom("b")]);
    let index = O::Int((n % 5) as i64);
    match (f, arity) {
        ("hd" | "tl", 1) => vec![if n.is_multiple_of(3) { term(n) } else { seq }],
        ("tuple_size", 1) => vec![if n.is_multiple_of(3) { term(n) } else { tup }],
        ("element", 2) => vec![index, tup],
        ("setelement", 3) => vec![index, tup, term(n)],
        ("not", 1) => vec![boolean(n.is_multiple_of(2))],
        ("and" | "or" | "xor", 2) => vec![
            boolean(n.is_multiple_of(2)),
            if n.is_multiple_of(7) {
                term(n)
            } else {
                boolean(n.is_multiple_of(3))
            },
        ],
        ("is_record", 2) => vec![
            tup,
            if n.is_multiple_of(4) {
                term(n)
            } else {
                atom("a")
            },
        ],
        ("is_record", 3) => vec![
            tup,
            atom("a"),
            match n % 4 {
                0 => O::Int(3),
                1 => O::Int(2),
                2 => term(n),
                _ => atom("m"),
            },
        ],
        ("raise", 3) => vec![
            atom(["error", "exit", "throw", "bad"][n % 4]),
            term(n),
            match n % 3 {
                0 => O::Nil,
                1 => O::list(vec![O::Tuple(vec![
                    atom("m"),
                    atom("f"),
                    O::Int(1),
                    O::list(vec![]),
                ])]),
                _ => term(n),
            },
        ],
        (_, 2) => vec![term(n), term(n + 1)],
        _ => vec![term(n); arity],
    }
}

fn cases() -> Vec<O> {
    let mut cases = Vec::with_capacity(BIFS.len() * 1000);
    for &(f, arity) in BIFS {
        for n in 0..1000 {
            let mut input = args(f, arity, n);
            if n.is_multiple_of(10) {
                input[0] = atom("invalid");
            }
            cases.push(O::Tuple(vec![atom(f), O::list(input)]));
        }
    }
    cases
}

#[test]
fn moved_bif_op_bodies_match_otp_through_vm() {
    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let cases = cases();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    // One chunk per BIF keeps a mismatch report readable.
    for (chunk, &(f, arity)) in cases.chunks(1000).zip(BIFS) {
        let input = O::list(chunk.to_vec());
        let expected = reference.call(MODULE, "run", std::slice::from_ref(&input));
        let mut heap = ProcessHeap::with_words(200_000);
        let input = from_owned(&input, &mut heap).expect("allocate case input");
        let actual = vm
            .eval_scheduled(MODULE, "run", &[input], 1)
            .unwrap_or_else(|error| panic!("VM evaluation failed: {error}"));
        let actual = actual.term;
        let (
            CallResult::Ok(O::List {
                elems: expected, ..
            }),
            O::List { elems: actual, .. },
        ) = (&expected, &actual)
        else {
            panic!("erlang:{f}/{arity}: expected {expected:?}, actual {actual:?}");
        };
        for ((case, expected), actual) in chunk.iter().zip(expected).zip(actual) {
            let (expected, actual) = (
                CallResult::Ok(expected.clone()),
                CallResult::Ok(actual.clone()),
            );
            assert!(
                compare(&expected, &actual, CompareMode::Exact).is_ok(),
                "erlang:{f}/{arity} {case:?}: expected {expected:?}, actual {actual:?}"
            );
        }
    }
}

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const MODULE: &str = "big_reds_arithmetic_test";
const SOURCE: &str = r#"
    -module(big_reds_arithmetic_test).
    -export([run/0]).

    id(Value) -> Value.
    big_words(Words) -> id(1) bsl (64 * Words).

    run() ->
        Big100 = big_words(100),
        Big1000 = big_words(1000),
        Big50 = big_words(50),
        Ops = [
            {mul_1, '*', big_words(1), 7},
            {mul_20, '*', big_words(20), 7},
            {mul_100_50, '*', Big100, Big50},
            {madd_1, madd, big_words(1), 7},
            {madd_20, madd, big_words(20), 7},
            {madd_100_50, madd, Big100, Big50},
            {div_1, 'div', big_words(1), 7},
            {div_100, 'div', Big100, 7},
            {div_100_50, 'div', Big100, Big50},
            {rem_1, 'rem', big_words(1), 7},
            {rem_100, 'rem', Big100, 7},
            {rem_100_50, 'rem', Big100, Big50},
            {add_100_75, '+', Big100, big_words(75)},
            {add_1000_75, '+', Big1000, big_words(75)},
            {sub_100_75, '-', Big100, big_words(75)},
            {sub_1000_120, '-', Big1000, big_words(120)},
            {band_100_75, 'band', Big100, big_words(75)},
            {band_1000_75, 'band', Big1000, big_words(75)},
            {bor_100_75, 'bor', Big100, big_words(75)},
            {bor_1000_75, 'bor', Big1000, big_words(75)},
            {bxor_100_75, 'bxor', Big100, big_words(75)},
            {bxor_1000_75, 'bxor', Big1000, big_words(75)},
            {bsl_100, 'bsl', Big100, 1},
            {bsl_1000, 'bsl', Big1000, 1},
            {bsr_100, 'bsr', Big100, 1},
            {bsr_1000, 'bsr', Big1000, 1}
        ],
        Unary = [
            {neg_100, '-', Big100},
            {neg_1000, '-', Big1000},
            {bnot_100, 'bnot', Big100},
            {bnot_1000, 'bnot', Big1000}
        ],
        {[measure2(Name, Op, A, B) || {Name, Op, A, B} <- Ops],
         [measure1(Name, Op, A) || {Name, Op, A} <- Unary]}.

    measure2(Name, Op, A, B) ->
        {InstructionReds, Result} = measure_instruction(Op, A, B),
        GuardReds = measure_guard(Op, A, B, Result),
        BifReds = case Op of
            madd -> absent;
            _ -> measure_bif(Op, A, B)
        end,
        {Name, InstructionReds, GuardReds, BifReds}.

    measure1(Name, Op, A) ->
        {InstructionReds, Result} = measure_instruction(Op, A),
        GuardReds = measure_guard(Op, A, Result),
        BifReds = measure_bif(Op, A),
        {Name, InstructionReds, GuardReds, BifReds}.

    measure_instruction(Op, A, B) ->
        erlang:yield(),
        {reductions, Before} = process_info(self(), reductions),
        Result = eval_op(Op, A, B),
        {reductions, After} = process_info(self(), reductions),
        {After - Before - 1, Result}.

    measure_instruction(Op, A) ->
        erlang:yield(),
        {reductions, Before} = process_info(self(), reductions),
        Result = eval_op(Op, A),
        {reductions, After} = process_info(self(), reductions),
        {After - Before - 1, Result}.

    measure_guard(Op, A, B, Result) ->
        erlang:yield(),
        {reductions, Before} = process_info(self(), reductions),
        ok = eval_op_guard(Op, A, B, Result),
        {reductions, After} = process_info(self(), reductions),
        After - Before - 1.

    measure_guard(Op, A, Result) ->
        erlang:yield(),
        {reductions, Before} = process_info(self(), reductions),
        ok = eval_op_guard(Op, A, Result),
        {reductions, After} = process_info(self(), reductions),
        After - Before - 1.

    measure_bif(Op, A, B) ->
        erlang:yield(),
        {reductions, Before} = process_info(self(), reductions),
        Result = apply(erlang, Op, [A, B]),
        {reductions, After} = process_info(self(), reductions),
        {After - Before - 1, Result}.

    measure_bif(Op, A) ->
        erlang:yield(),
        {reductions, Before} = process_info(self(), reductions),
        Result = apply(erlang, Op, [A]),
        {reductions, After} = process_info(self(), reductions),
        {After - Before - 1, Result}.

    eval_op('-', A) -> -A;
    eval_op('bnot', A) -> bnot A.
    eval_op('+', A, B) -> A + B;
    eval_op('-', A, B) -> A - B;
    eval_op('*', A, B) -> A * B;
    eval_op(madd, A, B) -> A * B + 1;
    eval_op('div', A, B) -> A div B;
    eval_op('rem', A, B) -> A rem B;
    eval_op('band', A, B) -> A band B;
    eval_op('bor', A, B) -> A bor B;
    eval_op('bxor', A, B) -> A bxor B;
    eval_op('bsl', A, B) -> A bsl B;
    eval_op('bsr', A, B) -> A bsr B.

    eval_op_guard('-', A, Result) when Result =:= -A -> ok;
    eval_op_guard('bnot', A, Result) when Result =:= bnot A -> ok.
    eval_op_guard('-', A, B, Result) when Result =:= A - B -> ok;
    eval_op_guard('+', A, B, Result) when Result =:= A + B -> ok;
    eval_op_guard('*', A, B, Result) when Result =:= A * B -> ok;
    eval_op_guard(madd, A, B, Result) when Result =:= A * B + 1 -> ok;
    eval_op_guard('div', A, B, Result) when Result =:= A div B -> ok;
    eval_op_guard('rem', A, B, Result) when Result =:= A rem B -> ok;
    eval_op_guard('band', A, B, Result) when Result =:= A band B -> ok;
    eval_op_guard('bor', A, B, Result) when Result =:= A bor B -> ok;
    eval_op_guard('bxor', A, B, Result) when Result =:= A bxor B -> ok;
    eval_op_guard('bsl', A, B, Result) when Result =:= A bsl B -> ok;
    eval_op_guard('bsr', A, B, Result) when Result =:= A bsr B -> ok.
"#;

fn measurements(term: &OwnedTerm) -> Vec<(OwnedTerm, Vec<i64>)> {
    let OwnedTerm::Tuple(groups) = term else {
        panic!("arithmetic measurements did not return a tuple: {term:?}");
    };
    groups
        .iter()
        .flat_map(|group| {
            let OwnedTerm::List { elems, tail } = group else {
                panic!("arithmetic measurement group was not a list: {group:?}");
            };
            assert!(matches!(tail.as_ref(), OwnedTerm::Nil));
            elems.iter().map(|measurement| {
                let OwnedTerm::Tuple(values) = measurement else {
                    panic!("arithmetic measurement was not a tuple: {measurement:?}");
                };
                let name = values[0].clone();
                let counts: Vec<i64> = values[1..]
                    .iter()
                    .filter_map(|value| match value {
                        OwnedTerm::Int(count) => Some(*count),
                        OwnedTerm::Tuple(result) => match result.first() {
                            Some(OwnedTerm::Int(count)) => Some(*count),
                            other => panic!("BIF count was not an integer: {other:?}"),
                        },
                        OwnedTerm::Atom(atom) if atom.as_str() == "absent" => None,
                        other => panic!("reduction count has unexpected value: {other:?}"),
                    })
                    .collect();
                let expected_count_fields = match &name {
                    OwnedTerm::Atom(atom) if atom.as_str().starts_with("madd_") => 2,
                    _ => 3,
                };
                similar_asserts::assert_eq!(counts.len(), expected_count_fields);
                (name, counts)
            })
        })
        .collect()
}

#[test]
fn bignum_instruction_guard_and_bif_reductions_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping bignum reduction differential test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile bignum reduction fixture");
    reference.load(MODULE, &beam).unwrap();
    let CallResult::Ok(expected) = reference.call(MODULE, "run", &[]) else {
        panic!("OTP bignum reduction fixture failed");
    };

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "run", &[], 1, None)
        .expect("run bignum reduction fixture");
    let expected_counts = measurements(&expected);
    let actual_counts = measurements(&actual.term);
    eprintln!("OTP bignum reductions: {expected_counts:?}");
    eprintln!("Arinsal bignum reductions: {actual_counts:?}");
    similar_asserts::assert_eq!(expected_counts, actual_counts);
}

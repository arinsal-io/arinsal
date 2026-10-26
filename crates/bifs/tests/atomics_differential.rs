use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle, lookup};
use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, Term, from_owned, to_owned};
use num_bigint::BigInt;
use similar_asserts::assert_eq;

#[derive(Clone, Copy)]
enum Op {
    Get(usize),
    Put(usize, i64),
    Add(usize, i64),
    AddGet(usize, i64),
    Exchange(usize, i64),
    Compare(usize, i64, i64),
    InvalidIndex,
    InvalidValue,
}

fn random_ops() -> Vec<Op> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..5_000)
        .map(|n| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let index = (state as usize % 4) + 1;
            let value = ((state >> 16) as i32 as i64) % 10_000;
            match n % 23 {
                0 => Op::InvalidIndex,
                1 => Op::InvalidValue,
                _ => match state % 6 {
                    0 => Op::Get(index),
                    1 => Op::Put(index, value),
                    2 => Op::Add(index, value),
                    3 => Op::AddGet(index, value),
                    4 => Op::Exchange(index, value),
                    _ => Op::Compare(index, value, value.wrapping_add(1)),
                },
            }
        })
        .collect()
}

fn erl_ops(ops: &[Op], signed: bool) -> String {
    let entries = ops
        .iter()
        .map(|op| match op {
            Op::Get(i) => format!("{{get,{i}}}"),
            Op::Put(i, v) => format!("{{put,{i},{v}}}"),
            Op::Add(i, v) => format!("{{add,{i},{v}}}"),
            Op::AddGet(i, v) => format!("{{add_get,{i},{v}}}"),
            Op::Exchange(i, v) => format!("{{exchange,{i},{v}}}"),
            Op::Compare(i, a, b) => format!("{{compare,{i},{a},{b}}}"),
            Op::InvalidIndex => "{get,0}".to_owned(),
            Op::InvalidValue => "{put,1,not_an_integer}".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(",");
    let opts = if signed {
        "[{signed,true}]"
    } else {
        "[{signed,false}]"
    };
    format!(
        "A=atomics:new(4,{opts}), Ops=[{entries}], lists:map(fun(O)->try case O of {{get,I}}->atomics:get(A,I); {{put,I,V}}->atomics:put(A,I,V); {{add,I,V}}->atomics:add(A,I,V); {{add_get,I,V}}->atomics:add_get(A,I,V); {{exchange,I,V}}->atomics:exchange(A,I,V); {{compare,I,E,D}}->atomics:compare_exchange(A,I,E,D) end catch C:_ -> {{exception,C}} end end,Ops)"
    )
}

fn rust_sequence(ops: &[Op], signed: bool) -> Vec<O> {
    let mut heap = ProcessHeap::with_words(64);
    let mut allocator = ProcessHeapHandle(&mut heap);
    let new = lookup("erts_internal", "atomics_new", 2).unwrap();
    let args = [
        Term::small(4).unwrap(),
        Term::small(if signed { 1 } else { 0 }).unwrap(),
    ];
    let reference = {
        let mut state = arinsal_bifs::BifState::default();
        let mut ctx = Ctx::new(&mut allocator, &mut state);
        new(&mut ctx, &args).unwrap()
    };
    ops.iter()
        .map(|op| {
            let (name, values): (&str, Vec<O>) = match op {
                Op::Get(i) => ("get", vec![O::Int(*i as i64)]),
                Op::Put(i, v) => ("put", vec![O::Int(*i as i64), O::Int(*v)]),
                Op::Add(i, v) => ("add", vec![O::Int(*i as i64), O::Int(*v)]),
                Op::AddGet(i, v) => ("add_get", vec![O::Int(*i as i64), O::Int(*v)]),
                Op::Exchange(i, v) => ("exchange", vec![O::Int(*i as i64), O::Int(*v)]),
                Op::Compare(i, e, d) => (
                    "compare_exchange",
                    vec![O::Int(*i as i64), O::Int(*e), O::Int(*d)],
                ),
                Op::InvalidIndex => ("get", vec![O::Int(0)]),
                Op::InvalidValue => ("put", vec![O::Int(1), O::atom("not_an_integer")]),
            };
            let bif = lookup("atomics", name, (values.len() + 1) as u8).unwrap();
            let mut call_args = vec![reference];
            call_args.extend(
                values
                    .iter()
                    .map(|value| from_owned(value, &mut allocator).unwrap()),
            );
            let result = {
                let mut state = arinsal_bifs::BifState::default();
                let mut ctx = Ctx::new(&mut allocator, &mut state);
                match bif(&mut ctx, &call_args) {
                    Ok(term) => to_owned(term).unwrap(),
                    Err(BifError::Badarg { .. }) => {
                        O::Tuple(vec![O::atom("exception"), O::atom("error")])
                    }
                    Err(other) => panic!("unexpected BIF error: {other:?}"),
                }
            };
            match op {
                Op::InvalidIndex | Op::InvalidValue => {
                    O::Tuple(vec![O::atom("exception"), O::atom("error")])
                }
                _ => result,
            }
        })
        .collect()
}

#[test]
fn five_thousand_randomized_operations_match_otp_for_signed_and_unsigned_arrays() {
    let erl = RefErl::shared().expect("OTP 29 reference");
    let ops = random_ops();
    for signed in [true, false] {
        let expected = erl
            .eval(&erl_ops(&ops, signed))
            .expect("OTP operation sequence");
        let actual = rust_sequence(&ops, signed);
        assert_eq!(
            actual,
            match &expected {
                O::List { elems, tail } if **tail == O::Nil => elems.clone(),
                other => panic!("expected list: {other:?}"),
            },
            "signed={signed}"
        );
    }
}

#[test]
fn atomics_and_counters_array_length_overflow_matches_otp() {
    let erl = RefErl::shared().expect("OTP 29 reference");
    for (module, name, arity, expression) in [
        (
            "erts_internal",
            "atomics_new",
            2,
            "try atomics:new(1 bsl 64, []) catch error:Reason -> Reason end",
        ),
        (
            "erts_internal",
            "counters_new",
            1,
            "try counters:new(1 bsl 64, [write_concurrency]) catch error:Reason -> Reason end",
        ),
    ] {
        assert_eq!(erl.eval(expression).unwrap(), O::atom("system_limit"));
        let mut heap = ProcessHeap::with_words(64);
        let mut allocator = ProcessHeapHandle(&mut heap);
        let huge = from_owned(&O::BigInt(BigInt::from(1_u8) << 64), &mut allocator).unwrap();
        let args = if arity == 1 {
            vec![huge]
        } else {
            vec![huge, Term::small(0).unwrap()]
        };
        let mut state = arinsal_bifs::BifState::default();
        let mut ctx = Ctx::new(&mut allocator, &mut state);
        assert!(matches!(
            lookup(module, name, arity).unwrap()(&mut ctx, &args),
            Err(BifError::SystemLimit)
        ));
    }
}

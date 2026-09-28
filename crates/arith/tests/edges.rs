use arinsal_arith::{self as arith, ArithError};
use arinsal_term::{MAX_SMALL, ProcessHeap, Term, TermBuilder, VecHeap, to_owned};
use num_bigint::BigInt;

fn small(n: i64) -> Term {
    Term::small(n).unwrap()
}

#[test]
fn heap_full_is_atomic_and_reports_words() {
    let mut heap = ProcessHeap::with_words(0);
    assert_eq!(
        arith::add(small(MAX_SMALL), small(1), &mut heap),
        Err(ArithError::HeapFull { need_words: 2 })
    );
    assert_eq!(heap.used_words(), 0);
    assert_eq!(
        arith::integer_to_list(small(12345), small(10), &mut heap),
        Err(ArithError::HeapFull { need_words: 10 })
    );
    assert_eq!(heap.used_words(), 0);
    assert_eq!(
        arith::integer_to_binary(small(1), small(10), &mut heap),
        Err(ArithError::HeapFull { need_words: 3 })
    );
    assert_eq!(heap.used_words(), 0);
    assert_eq!(
        arith::fdiv(small(1), small(2), &mut heap),
        Err(ArithError::HeapFull { need_words: 2 })
    );
    assert_eq!(heap.used_words(), 0);
}

#[test]
fn large_shifts_saturate_or_raise() {
    let mut heap = VecHeap::new();
    let huge = TermBuilder::new(&mut heap)
        .int_from_bigint(&(BigInt::from(1u64) << 64usize))
        .unwrap();
    assert_eq!(
        arith::bsl(small(1), huge, &mut heap),
        Err(ArithError::SystemLimit)
    );
    assert_eq!(arith::bsr(small(1), huge, &mut heap), Ok(small(0)));
    assert_eq!(arith::bsr(small(-1), huge, &mut heap), Ok(small(-1)));
    assert_eq!(arith::bsl(small(0), huge, &mut heap), Ok(small(0)));
    let maximum = arith::bsl(small(1), small(4_194_239), &mut heap).unwrap();
    assert!(matches!(
        to_owned(maximum).unwrap(),
        arinsal_etf::OwnedTerm::BigInt(_)
    ));
    assert_eq!(
        arith::bsl(small(1), small(4_194_240), &mut heap),
        Err(ArithError::SystemLimit)
    );
}

#[test]
fn float_conversion_boundaries() {
    let mut heap = VecHeap::new();
    let n = TermBuilder::new(&mut heap)
        .int_from_bigint(&(BigInt::from(1u64) << 1024usize))
        .unwrap();
    assert_eq!(arith::to_float(n, &mut heap), Err(ArithError::Badarg));
    assert_eq!(
        arith::fdiv(n, small(2), &mut heap),
        Err(ArithError::Badarith)
    );
    let negative_zero = TermBuilder::new(&mut heap).float(-0.0).unwrap();
    let abs = arith::abs(negative_zero, &mut heap).unwrap();
    assert_eq!(format!("{:?}", to_owned(abs).unwrap()), "Float(0.0)");
}

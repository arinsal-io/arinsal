//! `TermBuilder::bytes_to_list` builds the same list as `list_from_slice` of small integers.

use arinsal_term::{ProcessHeap, Term, TermBuilder, to_owned};

#[test]
fn bytes_to_list_matches_list_from_slice() {
    for len in [0usize, 1, 2, 7, 255, 1024] {
        let bytes: Vec<u8> = (0..len).map(|i| (i * 31 % 256) as u8).collect();
        let mut heap = ProcessHeap::with_words(4096);
        let fast = TermBuilder::new(&mut heap).bytes_to_list(&bytes).unwrap();
        let terms: Vec<Term> = bytes
            .iter()
            .map(|b| Term::small(i64::from(*b)).unwrap())
            .collect();
        let slow = TermBuilder::new(&mut heap).list_from_slice(&terms).unwrap();
        assert_eq!(
            to_owned(fast).unwrap(),
            to_owned(slow).unwrap(),
            "len {len}"
        );
        assert_eq!(heap.used_words(), 4 * len, "two words per element, twice");
    }
}

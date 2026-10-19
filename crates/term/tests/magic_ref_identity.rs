use arinsal_term::{MagicRef, TermBuilder, VecHeap, cmp, exact_eq, phash2};
use std::cmp::Ordering;

#[test]
fn magic_and_plain_references_with_identical_numbers_compare_identically() {
    let owner = MagicRef::new(7_u32);
    let id = owner.id();
    let ids = [id as u32, (id >> 32) as u32, u32::MAX];
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let magic = builder.magic_ref(owner).unwrap();
    let plain = builder.local_ref(ids).unwrap();

    assert!(exact_eq(magic, plain));
    similar_asserts::assert_eq!(cmp(magic, plain), Ordering::Equal);
    similar_asserts::assert_eq!(phash2(magic), phash2(plain));
}

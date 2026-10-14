//! The off-heap BinRef chain has no length limit, as the erts MSO list has none.
//! Kept in its own test binary: it allocates refc binaries for several seconds and
//! `gc.rs` asserts on the process-global binary byte counter.

use arinsal_term::{ProcessHeap, Term, TermBuilder};

#[test]
fn live_off_heap_chain_longer_than_one_million_survives_heap_resize() {
    const SUB_BINARIES: usize = 1_200_000;
    let mut heap = ProcessHeap::with_words(1024);
    let parent = TermBuilder::new(&mut heap).binary(&[1; 256]).unwrap();
    let mut roots = [parent, Term::NIL];
    for _ in 0..SUB_BINARIES {
        loop {
            let mut builder = TermBuilder::new(&mut heap);
            let sub = builder.sub_binary(roots[0], 64, 64 * 8);
            let cell = sub.and_then(|sub| builder.cons(sub, roots[1]));
            match cell {
                Ok(list) => {
                    roots[1] = list;
                    break;
                }
                Err(_) => {
                    heap.collect(&mut roots, &mut [], 10).unwrap();
                }
            }
        }
    }
    heap.collect(&mut roots, &mut [], 0).unwrap();
    assert_eq!(heap.off_heap_count(), SUB_BINARIES + 1);
}

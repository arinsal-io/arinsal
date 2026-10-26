use arinsal_bifs::{Ctx, ProcessHeapHandle, lookup};
use arinsal_difftest::RefErl;
use arinsal_term::{ProcessHeap, TermBuilder, to_owned};
use similar_asserts::assert_eq;

#[test]
fn iolist_size_counts_shared_binary_graph_without_flattening() {
    let reference = match RefErl::shared() {
        Ok(reference) => reference,
        Err(error) => {
            eprintln!("OTP 29 reference unavailable; skipping differential assertion: {error}");
            return;
        }
    };
    let expected = reference
        .eval("erlang:iolist_size(lists:foldl(fun(_, X) -> [X, X] end, binary:copy(<<1>>, 1048576), lists:seq(1, 17)))")
        .expect("OTP computes iolist_size of a shared term graph");

    let mut process_heap = ProcessHeap::with_words(1024);
    let mut allocator = ProcessHeapHandle(&mut process_heap);
    let mut builder = TermBuilder::new(&mut allocator);
    let mut value = builder.binary(&vec![1; 1 << 20]).expect("leaf binary");
    for _ in 0..17 {
        value = builder
            .list_from_iter([value, value])
            .expect("shared pair list");
    }

    let bif = lookup("erlang", "iolist_size", 1).expect("iolist_size/1 registered");
    let mut state = arinsal_bifs::BifState::default();
    let mut ctx = Ctx::new(&mut allocator, &mut state);
    let actual = bif(&mut ctx, &[value]).expect("valid iolist");
    assert_eq!(to_owned(actual).expect("owned result"), expected);
    assert_eq!(expected, arinsal_etf::OwnedTerm::Int(1_i64 << 37));
}

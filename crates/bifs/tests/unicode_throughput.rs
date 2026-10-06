use std::time::Instant;

use arinsal_bifs::{Ctx, FragmentingHeap, lookup};
use arinsal_term::{ProcessHeap, Term, TermBuilder, global_atoms};

#[test]
#[ignore = "manual 10 MiB throughput check"]
fn ten_mib_utf8_to_list_and_back() {
    let data = vec![b'a'; 10 * 1024 * 1024];
    let mut heap = ProcessHeap::with_words(22_000_000);
    let mut alloc = FragmentingHeap(&mut heap);
    let input = TermBuilder::new(&mut alloc).binary(&data).unwrap();
    let utf8 = Term::atom(global_atoms().intern("utf8").unwrap());
    let to_list = lookup("unicode", "characters_to_list", 2).unwrap();
    let to_binary = lookup("unicode", "characters_to_binary", 2).unwrap();
    let mut ctx = Ctx::new(&mut alloc);

    let start = Instant::now();
    let list = to_list(&mut ctx, &[input, utf8]).unwrap();
    let list_seconds = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let binary = to_binary(&mut ctx, &[list, utf8]).unwrap();
    let binary_seconds = start.elapsed().as_secs_f64();

    // SAFETY: The process heap and retained binary owner remain live here.
    let result = unsafe { binary.binary_ref() }.unwrap();
    assert_eq!(result.bytes(), data);
    println!(
        "Arinsal list: {:.3} s ({:.1} MiB/s)",
        list_seconds,
        10.0 / list_seconds
    );
    println!(
        "Arinsal binary: {:.3} s ({:.1} MiB/s)",
        binary_seconds,
        10.0 / binary_seconds
    );
}

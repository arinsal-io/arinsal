use arinsal_maps::{from_pairs, get, put};
use arinsal_term::{Term, VecHeap};
use std::time::Instant;

fn main() {
    let mut heap = VecHeap::new();
    let mut map = from_pairs(&[], &mut heap).expect("empty map allocation");
    let put_start = Instant::now();
    for key in 0..100_000_i64 {
        let key = Term::small(key).expect("small integer key");
        map = put(map, key, key, &mut heap).expect("map insertion");
    }
    let put_elapsed = put_start.elapsed();

    let get_start = Instant::now();
    for key in 0..100_000_i64 {
        let key = Term::small(key).expect("small integer key");
        assert_eq!(get(map, key), Ok(Some(key)));
    }
    let get_elapsed = get_start.elapsed();
    let put_ns = put_elapsed.as_nanos() / 100_000;
    let get_ns = get_elapsed.as_nanos() / 100_000;
    let combined = put_ns + get_ns;
    println!("map put 100k: {put_ns} ns/op");
    println!("map get 100k: {get_ns} ns/op");
    println!("map put+get pair: {combined} ns/key (ERTS 29.1.1: 316 ns/key)");
    if combined > 316 {
        println!("REGRESSION");
    }
}

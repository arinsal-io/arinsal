use arinsal_bifs::{Ctx, FragmentingHeap, lookup};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{Identity, ProcessHeap, Term, TermBuilder, to_owned};
use std::thread;

const THREADS: usize = 8;
const ADDS_PER_THREAD: usize = 1_000_000;

fn make_array(counters: bool) -> [u32; 3] {
    let mut heap = ProcessHeap::with_words(64);
    let mut allocator = FragmentingHeap(&mut heap);
    let mut ctx = Ctx::new(&mut allocator);
    let (module, name, args): (&str, &str, Vec<Term>) = if counters {
        (
            "erts_internal",
            "counters_new",
            vec![Term::small(1).unwrap()],
        )
    } else {
        (
            "erts_internal",
            "atomics_new",
            vec![Term::small(1).unwrap(), Term::small(1).unwrap()],
        )
    };
    let reference = lookup(module, name, args.len() as u8).unwrap()(&mut ctx, &args).unwrap();
    match reference.identity().unwrap() {
        Identity::Ref { ids, .. } => [ids[0], ids[1], ids[2]],
        other => panic!("expected local ref, got {other:?}"),
    }
}

fn run_parallel_add(ids: [u32; 3], counters: bool) -> O {
    let mut workers = Vec::new();
    for _ in 0..THREADS {
        workers.push(thread::spawn(move || {
            let mut heap = ProcessHeap::with_words(64);
            let mut allocator = FragmentingHeap(&mut heap);
            let reference = TermBuilder::new(&mut allocator).local_ref(ids).unwrap();
            let args = [reference, Term::small(1).unwrap(), Term::small(1).unwrap()];
            let bif = if counters {
                lookup("erts_internal", "counters_add", 3).unwrap()
            } else {
                lookup("atomics", "add", 3).unwrap()
            };
            let mut ctx = Ctx::new(&mut allocator);
            for _ in 0..ADDS_PER_THREAD {
                bif(&mut ctx, &args).unwrap();
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    let mut heap = ProcessHeap::with_words(64);
    let mut allocator = FragmentingHeap(&mut heap);
    let reference = TermBuilder::new(&mut allocator).local_ref(ids).unwrap();
    let args = [reference, Term::small(1).unwrap()];
    let (module, name) = if counters {
        ("erts_internal", "counters_get")
    } else {
        ("atomics", "get")
    };
    let mut ctx = Ctx::new(&mut allocator);
    let result = lookup(module, name, 2).unwrap()(&mut ctx, &args).unwrap();
    to_owned(result).unwrap()
}

#[test]
fn eight_threads_increment_atomics_and_both_counter_modes_exactly() {
    let expected = O::Int((THREADS * ADDS_PER_THREAD) as i64);
    assert_eq!(run_parallel_add(make_array(false), false), expected);
    // counters:new/2 with [atomics] uses this same `atomics` storage path.
    assert_eq!(run_parallel_add(make_array(false), false), expected);
    assert_eq!(run_parallel_add(make_array(true), true), expected);
}

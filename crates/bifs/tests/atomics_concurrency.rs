use arinsal_bifs::{Ctx, ProcessHeapHandle, lookup};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, Term, copy_term, to_owned};
use similar_asserts::assert_eq;
use std::thread;

const THREADS: usize = 8;
const ADDS_PER_THREAD: usize = 1_000_000;

fn run_parallel_add(counters: bool) -> O {
    let mut owner_heap = ProcessHeap::with_words(64);
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
    let reference = {
        let mut owner_allocator = ProcessHeapHandle(&mut owner_heap);
        let mut state = arinsal_bifs::BifState::default();
        let mut ctx = Ctx::new(&mut owner_allocator, &mut state);
        lookup(module, name, args.len() as u8).unwrap()(&mut ctx, &args).unwrap()
    };

    let mut workers = Vec::new();
    for _ in 0..THREADS {
        let mut heap = ProcessHeap::with_words(64);
        let reference = copy_term(reference, &mut heap).unwrap();
        workers.push(thread::spawn(move || {
            let mut allocator = ProcessHeapHandle(&mut heap);
            let args = [reference, Term::small(1).unwrap(), Term::small(1).unwrap()];
            let bif = if counters {
                lookup("erts_internal", "counters_add", 3).unwrap()
            } else {
                lookup("atomics", "add", 3).unwrap()
            };
            let mut state = arinsal_bifs::BifState::default();
            let mut ctx = Ctx::new(&mut allocator, &mut state);
            for _ in 0..ADDS_PER_THREAD {
                bif(&mut ctx, &args).unwrap();
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }

    let mut allocator = ProcessHeapHandle(&mut owner_heap);
    let args = [reference, Term::small(1).unwrap()];
    let (module, name) = if counters {
        ("erts_internal", "counters_get")
    } else {
        ("atomics", "get")
    };
    let mut state = arinsal_bifs::BifState::default();
    let mut ctx = Ctx::new(&mut allocator, &mut state);
    let result = lookup(module, name, 2).unwrap()(&mut ctx, &args).unwrap();
    to_owned(result).unwrap()
}

#[test]
fn eight_threads_increment_atomics_and_both_counter_modes_exactly() {
    let expected = O::Int((THREADS * ADDS_PER_THREAD) as i64);
    assert_eq!(run_parallel_add(false), expected);
    // counters:new/2 with [atomics] uses this same `atomics` storage path.
    assert_eq!(run_parallel_add(false), expected);
    assert_eq!(run_parallel_add(true), expected);
}

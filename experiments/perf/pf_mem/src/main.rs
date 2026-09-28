use arinsal_sched::{Incoming, Private};
use arinsal_term::{ProcessHeap, Term, TermBuilder};
use arinsal_vm::Process;
use std::collections::{HashMap, VecDeque};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const N: usize = 20_000;

struct CompactProcess {
    registers: [u64; 16],
    heap: Option<Box<[u64]>>,
    inbox: VecDeque<u64>,
    monitors: InlineMonitors,
}

impl CompactProcess {
    fn new() -> Self {
        Self {
            registers: [0; 16],
            heap: None,
            inbox: VecDeque::new(),
            monitors: InlineMonitors::default(),
        }
    }
}

#[derive(Default)]
struct InlineMonitors {
    entries: [Option<(u64, u64)>; 4],
}

impl InlineMonitors {
    fn insert(&mut self, reference: u64, pid: u64) {
        *self
            .entries
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("kernel uses one monitor") = Some((reference, pid));
    }

    fn remove(&mut self, reference: u64) -> Option<u64> {
        let slot = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_some_and(|(id, _)| id == reference))?;
        slot.take().map(|(_, pid)| pid)
    }
}

fn measure(name: &str, n: usize, mut f: impl FnMut(usize)) {
    let mut samples = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        for i in 0..n {
            f(black_box(i));
        }
        samples.push(start.elapsed().as_nanos() as f64 / n as f64);
    }
    samples.sort_by(f64::total_cmp);
    println!("{name}: {:.1} ns/op (median of 5)", samples[2]);
}

fn measure_batch(name: &str, n: usize, mut f: impl FnMut(usize)) {
    let mut samples = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        f(n);
        samples.push(start.elapsed().as_nanos() as f64 / n as f64);
    }
    samples.sort_by(f64::total_cmp);
    println!("{name}: {:.1} ns/op (median of 5)", samples[2]);
}

fn measure_gc(name: &str, live: bool, min_heap_words: usize) {
    const CONS: usize = 65_536; // 1 MiB of two-word cons cells.
    let mut samples = Vec::new();
    let mut copied = 0;
    let mut promoted = 0;
    for _ in 0..5 {
        let mut heap = ProcessHeap::with_words(CONS * 2);
        heap.set_min_heap_size(min_heap_words);
        let mut tail = Term::NIL;
        {
            let mut builder = TermBuilder::new(&mut heap);
            for i in 0..CONS {
                tail = builder.cons(Term::small(i as i64).unwrap(), tail).unwrap();
            }
        }
        black_box(&heap);
        let mut roots = if live { vec![tail] } else { Vec::new() };
        let start = Instant::now();
        let stats = heap.collect(&mut roots, &mut [], 0).unwrap();
        samples.push(start.elapsed().as_nanos() as f64);
        copied = stats.words_copied;
        promoted = stats.words_promoted;
        black_box((roots, heap));
    }
    samples.sort_by(f64::total_cmp);
    println!(
        "{name}: {:.3} ms/MiB input (median of 5), copied={copied} promoted={promoted} words",
        samples[2] / 1_000_000.0
    );
}

fn main() {
    println!(
        "sizeof(Process)={} sizeof(CompactProcess)={}",
        size_of::<Process>(),
        size_of::<CompactProcess>()
    );
    measure_batch("alloc current checked bump + 2 writes", N * 10, |n| {
        let mut heap = ProcessHeap::with_words(n * 2);
        for i in 0..n {
            let ptr = heap.alloc(2).expect("preallocated capacity");
            // SAFETY: alloc reserved two initialized-size word slots exclusively.
            unsafe {
                ptr.write(arinsal_term::Term::small(i as i64).unwrap());
                ptr.add(1).write(arinsal_term::Term::NIL);
            }
            black_box(ptr);
        }
        black_box(heap.used_words());
    });
    measure_batch("alloc local cursor + 2 writes", N * 10, |n| {
        let mut heap = ProcessHeap::with_words(n * 2);
        let (mut cursor, end) = heap.heap_cursor();
        for i in 0..n {
            assert!(cursor.wrapping_add(2) <= end);
            // SAFETY: the checked cursor remains within the exclusive heap block.
            unsafe {
                cursor.cast::<Term>().write(Term::small(i as i64).unwrap());
                cursor.add(1).cast::<Term>().write(Term::NIL);
                cursor = cursor.add(2);
            }
            black_box(cursor);
        }
        heap.set_heap_top(cursor);
        black_box(heap.used_words());
    });
    measure_batch("tuple builder + 3 writes", N * 10, |n| {
        let mut heap = ProcessHeap::with_words(n * 3);
        let mut builder = TermBuilder::new(&mut heap);
        for i in 0..n {
            black_box(
                builder
                    .tuple(&[Term::small(i as i64).unwrap(), Term::NIL])
                    .unwrap(),
            );
        }
    });
    measure_batch("tuple local cursor + 3 writes", N * 10, |n| {
        let mut heap = ProcessHeap::with_words(n * 3);
        let (mut cursor, end) = heap.heap_cursor();
        for i in 0..n {
            assert!(cursor.wrapping_add(3) <= end);
            // SAFETY: the checked cursor reserves three exclusive words.
            unsafe {
                cursor.write(2 << 6);
                cursor
                    .add(1)
                    .cast::<Term>()
                    .write(Term::small(i as i64).unwrap());
                cursor.add(2).cast::<Term>().write(Term::NIL);
                cursor = cursor.add(3);
            }
            black_box(cursor);
        }
        heap.set_heap_top(cursor);
        black_box(heap.used_words());
    });
    measure_gc("minor GC dead", false, 64);
    measure_gc("minor GC live, graph sizing", true, 64);
    measure_gc("minor GC live, no sizing pass", true, 131_072);
    measure_batch("reference atomic + 3-word term", N * 10, |n| {
        let mut heap = ProcessHeap::with_words(n * 3);
        let counter = AtomicU64::new(0);
        let mut builder = TermBuilder::new(&mut heap);
        for _ in 0..n {
            let id = counter.fetch_add(1, Ordering::Relaxed);
            black_box(
                builder
                    .local_ref([id as u32, (id >> 32) as u32, 0])
                    .unwrap(),
            );
        }
    });
    measure_batch("mailbox push + detach + pop", N * 10, |n| {
        let input = Incoming::<u64>::default();
        let mut private = Private::default();
        for i in 0..n {
            input.push(i as u64);
            input.drain_into(&mut private);
            black_box(private.pop());
        }
    });
    measure("heap eager 64-word create/drop", N, |_| {
        black_box(ProcessHeap::with_words(64));
    });
    measure("heap lazy zero-word create/drop", N, |_| {
        black_box(ProcessHeap::with_words(0));
    });
    measure("process current create/drop", N, |_| {
        black_box(Process::new());
    });
    measure("process compact cold create/drop", N, |_| {
        let process = CompactProcess::new();
        black_box((
            process.registers[0],
            process.heap.is_none(),
            process.inbox.len(),
            process.monitors.entries.len(),
        ));
        black_box(process);
    });
    measure("monitor HashMap insert/remove", N * 10, |i| {
        let mut map = HashMap::<u64, u64>::new();
        map.insert(i as u64, 7);
        black_box(&map);
        black_box(map.remove(&(i as u64)));
    });
    measure("monitor inline insert/remove", N * 10, |i| {
        let mut monitors = InlineMonitors::default();
        monitors.insert(i as u64, 7);
        black_box(&monitors);
        black_box(monitors.remove(i as u64));
    });
    measure_batch("receive marker retained after bind", 10_000, |n| {
        let mut positions = HashMap::<u64, usize>::new();
        for i in 0..n {
            let reserved = (2 * i) as u64;
            let bound = reserved + 1;
            positions.insert(reserved, i);
            positions.insert(bound, i);
            positions.remove(&bound);
            for position in positions.values_mut() {
                *position = position.saturating_sub(1);
            }
            black_box(positions.len());
        }
    });
    measure_batch("receive marker removed on bind", 10_000, |n| {
        let mut positions = HashMap::<u64, usize>::new();
        for i in 0..n {
            let reserved = (2 * i) as u64;
            let bound = reserved + 1;
            positions.insert(reserved, i);
            positions.insert(bound, i);
            positions.remove(&reserved);
            positions.remove(&bound);
            for position in positions.values_mut() {
                *position = position.saturating_sub(1);
            }
            black_box(positions.len());
        }
    });
}

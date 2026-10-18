//! Timing of each allocator layer on one workload, through the public API only so the library is
//! built without its test-only counters: `cargo test --release -p arinsal-alloc --test layer_bench
//! -- --ignored --nocapture`.

use arinsal_alloc::alloc_util::{AllocUtil, AllocUtilOptions, Strategy};
use arinsal_alloc::instances::ThreadSpecificAllocators;
use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};
use arinsal_alloc::{ThreadKind, register_thread};
use std::time::Instant;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn cycles() -> usize {
    std::env::var("FRAG_CYCLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000)
}

fn best_of<F: FnMut(usize) -> f64>(mut run: F) -> f64 {
    let cycles = cycles();
    (0..5).map(|_| run(cycles)).fold(f64::MAX, f64::min)
}

fn per_pair(started: Instant, cycles: usize) -> f64 {
    started.elapsed().as_nanos() as f64 / (cycles as f64 * 26.0)
}

fn alloc_util_alone(background: bool) -> f64 {
    best_of(|cycles| {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let mut allocator = AllocUtil::new(Strategy::AoffCbf, AllocUtilOptions::default());
        if background {
            let bg: Vec<_> = (0..2000)
                .map(|_| {
                    allocator
                        .alloc(16 + (rng.next() % 20) as usize * 16)
                        .unwrap()
                })
                .collect();
            for allocation in bg.iter().step_by(2) {
                allocator.free(*allocation).unwrap();
            }
        }
        let mut live = Vec::with_capacity(32);
        let started = Instant::now();
        for _ in 0..cycles {
            for _ in 0..26 {
                live.push(allocator.alloc(8 + (rng.next() % 12) as usize * 8).unwrap());
            }
            for allocation in live.drain(..) {
                allocator.free(allocation).unwrap();
            }
        }
        per_pair(started, cycles)
    })
}

fn instance_layer(background: bool) -> f64 {
    best_of(|cycles| {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let allocators =
            ThreadSpecificAllocators::new(4, true, Strategy::AoffCbf, AllocUtilOptions::default());
        if background {
            let bg: Vec<_> = (0..2000)
                .map(|_| {
                    allocators
                        .alloc(16 + (rng.next() % 20) as usize * 16)
                        .unwrap()
                })
                .collect();
            for allocation in bg.iter().step_by(2) {
                allocators.free(*allocation).unwrap();
            }
        }
        let mut live = Vec::with_capacity(32);
        let started = Instant::now();
        for _ in 0..cycles {
            for _ in 0..26 {
                live.push(
                    allocators
                        .alloc(8 + (rng.next() % 12) as usize * 8)
                        .unwrap(),
                );
            }
            for handle in live.drain(..) {
                allocators.free(handle).unwrap();
            }
        }
        per_pair(started, cycles)
    })
}

fn instance_layer_at(background: bool) -> f64 {
    best_of(|cycles| {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let allocators =
            ThreadSpecificAllocators::new(4, true, Strategy::AoffCbf, AllocUtilOptions::default());
        if background {
            let bg: Vec<_> = (0..2000)
                .map(|_| {
                    allocators
                        .alloc(16 + (rng.next() % 20) as usize * 16)
                        .unwrap()
                })
                .collect();
            for allocation in bg.iter().step_by(2) {
                allocators.free(*allocation).unwrap();
            }
        }
        let ix = arinsal_alloc::thread_alloc_ix();
        let mut live = Vec::with_capacity(32);
        let started = Instant::now();
        for _ in 0..cycles {
            for _ in 0..26 {
                live.push(
                    allocators
                        .alloc_with_ptr_at(ix, 8 + (rng.next() % 12) as usize * 8)
                        .unwrap()
                        .0,
                );
            }
            for handle in live.drain(..) {
                allocators.free_at(ix, handle).unwrap();
            }
        }
        per_pair(started, cycles)
    })
}

fn alloc_block(background: bool) -> f64 {
    best_of(|cycles| {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        if background {
            let bg: Vec<_> = (0..2000)
                .map(|_| {
                    AllocBlock::new(ErtsAlcType::HEAP_FRAG, 2 + (rng.next() % 20) as usize * 2)
                        .unwrap()
                })
                .collect();
            for (index, block) in bg.into_iter().enumerate() {
                if index % 2 == 0 {
                    drop(block);
                } else {
                    std::mem::forget(block);
                }
            }
        }
        let mut live = Vec::with_capacity(32);
        let started = Instant::now();
        for _ in 0..cycles {
            for _ in 0..26 {
                live.push(
                    AllocBlock::new(ErtsAlcType::HEAP_FRAG, 1 + (rng.next() % 12) as usize)
                        .unwrap(),
                );
            }
            live.clear();
        }
        per_pair(started, cycles)
    })
}

fn alloc_block_at(background: bool) -> f64 {
    best_of(|cycles| {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        if background {
            let bg: Vec<_> = (0..2000)
                .map(|_| {
                    AllocBlock::new(ErtsAlcType::HEAP_FRAG, 2 + (rng.next() % 20) as usize * 2)
                        .unwrap()
                })
                .collect();
            for (index, block) in bg.into_iter().enumerate() {
                if index % 2 == 0 {
                    drop(block);
                } else {
                    std::mem::forget(block);
                }
            }
        }
        let ix = arinsal_alloc::thread_alloc_ix();
        let mut live = Vec::with_capacity(32);
        let started = Instant::now();
        for _ in 0..cycles {
            for _ in 0..26 {
                live.push(
                    AllocBlock::new_at(ix, ErtsAlcType::HEAP_FRAG, 1 + (rng.next() % 12) as usize)
                        .unwrap(),
                );
            }
            for block in live.drain(..) {
                block.release_at(ix);
            }
        }
        per_pair(started, cycles)
    })
}

/// Alloc and free halves of `alloc_util_alone`, timed apart: ns per alloc and ns per free.
fn alloc_util_split(background: bool) -> (f64, f64) {
    let cycles = cycles();
    let mut best = (f64::MAX, f64::MAX);
    for _ in 0..5 {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let mut allocator = AllocUtil::new(Strategy::AoffCbf, AllocUtilOptions::default());
        if background {
            let bg: Vec<_> = (0..2000)
                .map(|_| {
                    allocator
                        .alloc(16 + (rng.next() % 20) as usize * 16)
                        .unwrap()
                })
                .collect();
            for allocation in bg.iter().step_by(2) {
                allocator.free(*allocation).unwrap();
            }
        }
        let mut live = Vec::with_capacity(32);
        let (mut alloc_ns, mut free_ns) = (0u128, 0u128);
        for _ in 0..cycles {
            let started = Instant::now();
            for _ in 0..26 {
                live.push(allocator.alloc(8 + (rng.next() % 12) as usize * 8).unwrap());
            }
            alloc_ns += started.elapsed().as_nanos();
            let started = Instant::now();
            for allocation in live.drain(..) {
                allocator.free(allocation).unwrap();
            }
            free_ns += started.elapsed().as_nanos();
        }
        let per = |ns: u128| ns as f64 / (cycles as f64 * 26.0);
        best = (best.0.min(per(alloc_ns)), best.1.min(per(free_ns)));
    }
    best
}

#[test]
#[ignore = "timing: cargo test --release -p arinsal-alloc --test layer_bench -- --ignored --nocapture"]
fn layer_bench() {
    std::thread::spawn(|| {
        assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
        for background in [false, true] {
            eprintln!("background fragmentation: {background}");
            eprintln!(
                "  AllocUtil alone          {:6.2} ns per pair",
                alloc_util_alone(background)
            );
            let (alloc_ns, free_ns) = alloc_util_split(background);
            eprintln!(
                "  AllocUtil split          {alloc_ns:6.2} ns per alloc, {free_ns:6.2} ns per free"
            );
            eprintln!(
                "  ThreadSpecificAllocators {:6.2} ns per pair",
                instance_layer(background)
            );
            eprintln!(
                "  AllocBlock new+drop      {:6.2} ns per pair",
                alloc_block(background)
            );
            eprintln!(
                "  ThreadSpecificAllocators, index passed {:6.2} ns per pair",
                instance_layer_at(background)
            );
            eprintln!(
                "  AllocBlock new_at+release_at           {:6.2} ns per pair",
                alloc_block_at(background)
            );
        }
    })
    .join()
    .unwrap();
}

/// The `enif_alloc(160)` + `enif_free` pair of issue #49 at each layer, in ns per pair.
#[test]
#[ignore = "timing: cargo test --release -p arinsal-alloc --test layer_bench pair160 -- --ignored --nocapture"]
fn pair160() {
    std::thread::spawn(|| {
        assert_eq!(register_thread(ThreadKind::Scheduler(1)), Ok(1));
        let n: usize = std::env::var("PAIR_N")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5_000_000);
        let best = |mut f: Box<dyn FnMut()>| {
            (0..7)
                .map(|_| {
                    let started = Instant::now();
                    for _ in 0..n {
                        f();
                    }
                    started.elapsed().as_nanos() as f64 / n as f64
                })
                .fold(f64::MAX, f64::min)
        };
        let mut allocator = AllocUtil::new(Strategy::AoffCbf, AllocUtilOptions::default());
        if std::env::var_os("PAIR_ONLY_DRIVER").is_none() {
            let util = best(Box::new(move || {
                let a = allocator.alloc(160).unwrap();
                allocator.free(a).unwrap();
            }));
            eprintln!("AllocUtil alloc+free         {util:6.2} ns");
        }
        let allocators =
            ThreadSpecificAllocators::new(4, true, Strategy::AoffCbf, AllocUtilOptions::default());
        let inst = best(Box::new(move || {
            let (h, p) = allocators.alloc_with_ptr_at(1, 160).unwrap();
            std::hint::black_box(p);
            allocators.free_at(1, h).unwrap();
        }));
        eprintln!("instance layer alloc+free    {inst:6.2} ns");
        let driver = best(Box::new(|| {
            let p = arinsal_alloc::typed::driver_alloc(160);
            arinsal_alloc::typed::driver_free(std::hint::black_box(p));
        }));
        eprintln!("driver_alloc+driver_free     {driver:6.2} ns");
    })
    .join()
    .unwrap();
}

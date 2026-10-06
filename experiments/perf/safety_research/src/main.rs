use arinsal_term::{ProcessHeap, Term, TermBuilder};
use std::hint::black_box;
use std::marker::PhantomData;
use std::time::Instant;

const ROOT: Root = Root(0);
const TEMP: Root = Root(1);

#[derive(Clone, Copy)]
struct Root(usize);

// A term may be inspected only while its owner is immutably borrowed. The
// collector needs &mut SafeHeap and therefore invalidates all such views.
struct TermView<'h> {
    term: Term,
    _heap: PhantomData<&'h SafeHeap>,
}

impl TermView<'_> {
    fn classify(&self) -> arinsal_term::TermKind {
        self.term.classify()
    }
}

struct SafeHeap {
    heap: ProcessHeap,
    roots: [Term; 2],
}

impl SafeHeap {
    fn new() -> Self {
        Self {
            heap: ProcessHeap::with_words(256),
            roots: [Term::NIL; 2],
        }
    }

    fn view(&self, root: Root) -> TermView<'_> {
        TermView {
            term: self.roots[root.0],
            _heap: PhantomData,
        }
    }

    fn collect(&mut self) {
        self.heap.collect(&mut self.roots, &mut [], 5).unwrap();
    }

    fn put_pair(&mut self, root: Root, head: Term, force_mid_gc: bool) {
        if self.heap.free_words() < 3 {
            self.collect();
        }
        let tuple = TermBuilder::new(&mut self.heap)
            .tuple(&[head, Term::NIL])
            .unwrap();
        self.roots[TEMP.0] = tuple;
        if force_mid_gc || self.heap.free_words() < 2 {
            self.collect();
        }
        self.roots[root.0] = TermBuilder::new(&mut self.heap)
            .cons(self.roots[TEMP.0], Term::NIL)
            .unwrap();
        self.roots[TEMP.0] = Term::NIL;
    }
}

#[cfg(feature = "borrow-fail")]
fn stale_term_is_rejected(mut heap: SafeHeap) {
    let stale = heap.view(ROOT);
    heap.collect();
    let _ = stale.classify();
}

#[inline(never)]
fn allocation_current(ops: usize) -> u64 {
    let mut heap = ProcessHeap::with_words(256);
    let mut roots = [Term::NIL; 2];
    for i in 0..ops {
        if heap.free_words() < 3 {
            heap.collect(&mut roots, &mut [], 5).unwrap();
        }
        let tuple = TermBuilder::new(&mut heap)
            .tuple(&[Term::small((i & 255) as i64).unwrap(), Term::NIL])
            .unwrap();
        roots[TEMP.0] = tuple;
        if i & 63 == 0 || heap.free_words() < 2 {
            heap.collect(&mut roots, &mut [], 5).unwrap();
        }
        roots[0] = TermBuilder::new(&mut heap)
            .cons(roots[TEMP.0], Term::NIL)
            .unwrap();
        roots[TEMP.0] = Term::NIL;
        black_box(roots[0].classify());
    }
    black_box(roots[0]).classify() as u64
}

#[inline(never)]
fn allocation_scoped(ops: usize) -> u64 {
    let mut owner = SafeHeap::new();
    for i in 0..ops {
        owner.put_pair(ROOT, Term::small((i & 255) as i64).unwrap(), i & 63 == 0);
        black_box(owner.view(ROOT).classify());
    }
    owner.view(ROOT).classify() as u64
}

#[inline(never)]
fn register_checked(ops: &[u8], x: &mut [u64]) -> u64 {
    for &r in ops {
        let i = r as usize;
        x[i] = x[i].wrapping_add(1);
    }
    black_box(x[0])
}

#[inline(never)]
fn register_unchecked(ops: &[u8], x: &mut [u64]) -> u64 {
    for &r in ops {
        let i = r as usize;
        // SAFETY: the caller supplies at least 256 initialized X registers.
        unsafe { *x.get_unchecked_mut(i) = x.get_unchecked(i).wrapping_add(1) };
    }
    black_box(x[0])
}

#[inline(never)]
fn register_fixed(ops: &[u8], x: &mut [u64; 256]) -> u64 {
    for &r in ops {
        let i = r as usize;
        x[i] = x[i].wrapping_add(1);
    }
    black_box(x[0])
}

#[repr(u8)]
#[derive(Clone, Copy)]
enum Bank {
    Zero,
    One,
    Two,
    Three,
}

#[derive(Clone, Copy)]
struct XReg {
    bank: Bank,
    slot: u8,
}

impl XReg {
    fn decode(index: u16) -> Option<Self> {
        let bank = match index >> 8 {
            0 => Bank::Zero,
            1 => Bank::One,
            2 => Bank::Two,
            3 => Bank::Three,
            _ => return None,
        };
        Some(Self {
            bank,
            slot: index as u8,
        })
    }
}

#[derive(Clone, Copy)]
struct MaskedXReg(u16);

impl MaskedXReg {
    fn decode(index: u16) -> Option<Self> {
        (index < 1024).then_some(Self(index))
    }
}

#[derive(Clone, Copy)]
struct TypedXReg(u16);

impl TypedXReg {
    fn decode(index: u16) -> Option<Self> {
        (index < 1024).then_some(Self(index))
    }
}

struct RegisterFile<'a> {
    words: &'a mut [u64; 1024],
}

impl RegisterFile<'_> {
    #[inline(always)]
    fn bump(&mut self, register: TypedXReg) {
        debug_assert!(register.0 < 1024);
        // SAFETY: TypedXReg's private constructor checked the index and the
        // register file is an initialized 1024-entry array.
        let value = unsafe { self.words.get_unchecked_mut(register.0 as usize) };
        *value = value.wrapping_add(1);
    }
}

#[inline(never)]
fn register_1024_unchecked(ops: &[u16], x: &mut [u64]) -> u64 {
    for &r in ops {
        let i = r as usize;
        // SAFETY: every operand was decoded below 1024 and x has 1024 cells.
        unsafe { *x.get_unchecked_mut(i) = x.get_unchecked(i).wrapping_add(1) };
    }
    black_box(x[0])
}

#[inline(never)]
fn register_1024_banked(ops: &[XReg], x: &mut [[u64; 256]; 4]) -> u64 {
    for &r in ops {
        let value = &mut x[r.bank as usize][r.slot as usize];
        *value = value.wrapping_add(1);
    }
    black_box(x[0][0])
}

#[inline(never)]
fn register_1024_masked(ops: &[MaskedXReg], x: &mut [u64; 1024]) -> u64 {
    for &r in ops {
        // The mask exposes the decode-time bound to the optimizer. The
        // private constructor already rejected operands outside 0..1024.
        let i = (r.0 & 1023) as usize;
        x[i] = x[i].wrapping_add(1);
    }
    black_box(x[0])
}

#[inline(never)]
fn register_1024_typed_core(ops: &[TypedXReg], x: &mut [u64; 1024]) -> u64 {
    let mut file = RegisterFile { words: x };
    for &r in ops {
        file.bump(r);
    }
    black_box(file.words[0])
}

#[inline(never)]
fn bytes_raw(data: &[u8]) -> u64 {
    let mut total = 0u64;
    for i in 0..data.len() {
        // SAFETY: i is bounded by the length of this immutable byte slice.
        total = total.wrapping_add(unsafe { *data.as_ptr().add(i) } as u64);
    }
    black_box(total)
}

#[inline(never)]
fn bytes_checked(data: &[u8]) -> u64 {
    let mut total = 0u64;
    let mut i = 0;
    while i < data.len() {
        total = total.wrapping_add(data[i] as u64);
        i += 1;
    }
    black_box(total)
}

#[inline(never)]
fn bytes_cursor(data: &[u8]) -> u64 {
    let mut total = 0u64;
    for &byte in data {
        total = total.wrapping_add(byte as u64);
    }
    black_box(total)
}

fn measure(name: &str, operations: usize, mut run: impl FnMut() -> u64) {
    let mut times = Vec::new();
    let mut check = 0;
    for attempt in 0..9 {
        let start = Instant::now();
        check ^= black_box(run());
        let ns = start.elapsed().as_nanos() as f64 / operations as f64;
        if attempt > 0 {
            times.push(ns);
        }
    }
    times.sort_by(f64::total_cmp);
    println!(
        "{name},{:.4},{:.4},{:.4},{check}",
        (times[3] + times[4]) / 2.0,
        times[0],
        times[7]
    );
}

fn main() {
    const ALLOC_OPS: usize = 8_000;
    const REPETITIONS: usize = 400;
    let ops = (0..4096)
        .map(|i| ((i * 73 + 19) & 255) as u8)
        .collect::<Vec<_>>();
    let data = (0..8192)
        .map(|i| ((i * 97 + 17) & 255) as u8)
        .collect::<Vec<_>>();
    let ops1024 = (0..4096)
        .map(|i| ((i * 293 + 37) & 1023) as u16)
        .collect::<Vec<_>>();
    let decoded1024 = ops1024
        .iter()
        .map(|&i| XReg::decode(i).unwrap())
        .collect::<Vec<_>>();
    let masked1024 = ops1024
        .iter()
        .map(|&i| MaskedXReg::decode(i).unwrap())
        .collect::<Vec<_>>();
    let typed1024 = ops1024
        .iter()
        .map(|&i| TypedXReg::decode(i).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(bytes_raw(&data), bytes_checked(&data));
    assert_eq!(bytes_checked(&data), bytes_cursor(&data));
    let mut checked = vec![0; 256];
    let mut unchecked = vec![0; 256];
    let mut fixed = [0; 256];
    let mut unchecked1024 = vec![0; 1024];
    let mut banked1024 = [[0; 256]; 4];
    let mut safe1024 = [0; 1024];
    let mut typed_core1024 = [0; 1024];
    println!("case,median_ns_per_op,min,max,check");
    measure("heap_current", ALLOC_OPS, || allocation_current(ALLOC_OPS));
    measure("heap_scoped", ALLOC_OPS, || allocation_scoped(ALLOC_OPS));
    measure("regs_checked", REPETITIONS * ops.len(), || {
        let mut sum = 0;
        for _ in 0..REPETITIONS {
            sum ^= register_checked(black_box(&ops), black_box(&mut checked));
        }
        sum
    });
    measure("regs_unchecked", REPETITIONS * ops.len(), || {
        let mut sum = 0;
        for _ in 0..REPETITIONS {
            sum ^= register_unchecked(black_box(&ops), black_box(&mut unchecked));
        }
        sum
    });
    measure("regs_fixed", REPETITIONS * ops.len(), || {
        let mut sum = 0;
        for _ in 0..REPETITIONS {
            sum ^= register_fixed(black_box(&ops), black_box(&mut fixed));
        }
        sum
    });
    measure("regs_1024_unchecked", REPETITIONS * ops1024.len(), || {
        let mut sum = 0;
        for _ in 0..REPETITIONS {
            sum ^= register_1024_unchecked(black_box(&ops1024), black_box(&mut unchecked1024));
        }
        sum
    });
    measure("regs_1024_banked", REPETITIONS * decoded1024.len(), || {
        let mut sum = 0;
        for _ in 0..REPETITIONS {
            sum ^= register_1024_banked(black_box(&decoded1024), black_box(&mut banked1024));
        }
        sum
    });
    measure("regs_1024_masked", REPETITIONS * masked1024.len(), || {
        let mut sum = 0;
        for _ in 0..REPETITIONS {
            sum ^= register_1024_masked(black_box(&masked1024), black_box(&mut safe1024));
        }
        sum
    });
    measure(
        "regs_1024_typed_core",
        REPETITIONS * typed1024.len(),
        || {
            let mut sum = 0;
            for _ in 0..REPETITIONS {
                sum ^=
                    register_1024_typed_core(black_box(&typed1024), black_box(&mut typed_core1024));
            }
            sum
        },
    );
    measure("bytes_raw", REPETITIONS * data.len(), || {
        let mut sum = 0;
        for _ in 0..REPETITIONS {
            sum ^= bytes_raw(black_box(&data));
        }
        sum
    });
    measure("bytes_checked", REPETITIONS * data.len(), || {
        let mut sum = 0;
        for _ in 0..REPETITIONS {
            sum ^= bytes_checked(black_box(&data));
        }
        sum
    });
    measure("bytes_cursor", REPETITIONS * data.len(), || {
        let mut sum = 0;
        for _ in 0..REPETITIONS {
            sum ^= bytes_cursor(black_box(&data));
        }
        sum
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_allocation_matches_current_gc_path() {
        assert_eq!(allocation_current(8_000), allocation_scoped(8_000));

        use arinsal_etf::OwnedTerm;
        let mut owner = SafeHeap::new();
        for value in 0..130 {
            owner.put_pair(ROOT, Term::small(value).unwrap(), true);
            let actual = arinsal_term::to_owned(owner.view(ROOT).term).unwrap();
            assert_eq!(
                actual,
                OwnedTerm::List {
                    elems: vec![OwnedTerm::Tuple(vec![
                        OwnedTerm::Int(value),
                        OwnedTerm::Nil,
                    ])],
                    tail: Box::new(OwnedTerm::Nil),
                }
            );
        }
    }

    #[test]
    fn safe_register_and_byte_paths_match_raw_paths() {
        let ops = [0, 31, 255, 31, 0];
        let mut checked = [0u64; 256];
        let mut unchecked = [0u64; 256];
        let mut fixed = [0u64; 256];
        assert_eq!(
            register_checked(&ops, &mut checked),
            register_unchecked(&ops, &mut unchecked)
        );
        assert_eq!(checked, unchecked);
        assert_eq!(register_fixed(&ops, &mut fixed), checked[0]);
        assert_eq!(fixed, checked);
        assert!(XReg::decode(1024).is_none());
        assert!(MaskedXReg::decode(1024).is_none());
        assert!(TypedXReg::decode(1024).is_none());
        let wide = [0, 255, 256, 511, 512, 767, 768, 1023];
        let decoded = wide.map(|i| XReg::decode(i).unwrap());
        let masked = wide.map(|i| MaskedXReg::decode(i).unwrap());
        let typed = wide.map(|i| TypedXReg::decode(i).unwrap());
        let mut wide_unchecked = [0u64; 1024];
        let mut wide_banked = [[0u64; 256]; 4];
        let mut wide_masked = [0u64; 1024];
        let mut wide_typed = [0u64; 1024];
        assert_eq!(
            register_1024_unchecked(&wide, &mut wide_unchecked),
            register_1024_banked(&decoded, &mut wide_banked)
        );
        for (index, value) in wide_unchecked.iter().enumerate() {
            assert_eq!(*value, wide_banked[index / 256][index % 256]);
        }
        assert_eq!(
            register_1024_masked(&masked, &mut wide_masked),
            wide_unchecked[0]
        );
        assert_eq!(wide_masked, wide_unchecked);
        assert_eq!(
            register_1024_typed_core(&typed, &mut wide_typed),
            wide_unchecked[0]
        );
        assert_eq!(wide_typed, wide_unchecked);
        let data = [0, 1, 254, 255];
        assert_eq!(bytes_raw(&data), bytes_checked(&data));
        assert_eq!(bytes_checked(&data), bytes_cursor(&data));
    }
}

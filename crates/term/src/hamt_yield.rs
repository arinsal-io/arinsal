//! Yielding HAMT constructors and the reverse map iterator behind `maps:from_list/1`,
//! `maps:from_keys/2`, `maps:keys/1` and `maps:values/1`.
//!
//! erts builds these with functions transformed by YCF (Yielding C Fun,
//! erts/lib_src/yielding_c_fun): every loop body costs one unit of the `ycf_nr_of_reductions`
//! counter and the function yields when the counter reaches zero or below. Rust has no stackful
//! coroutines, so each YCF function is an explicit state machine whose phases are the loop
//! tests and bodies; a `tick!` is the generated `YCF_CONSUME_REDS(1)` plus yield check.

use crate::hamt::{
    HAMT_MAX_LEVEL, HEAD_ARRAY_HEADER, HxNode, boxed_object_words, cdepth, child_range,
    head_bitmap_header, leaf_key, maskval, node_bitmap_header, produce_words,
};
use crate::{HeapAlloc, HeapBlockBuilder, Term, TermBuilder, TermError, TermKind};
use smallvec::{SmallVec, smallvec};
use std::cell::Cell;
use std::cmp::Ordering;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

/// Consume `$n` reductions and leave the machine in phase `$next`; yields when the budget is
/// used up. Port of the code YCF generates for `YCF_CONSUME_REDS` (ycf_yield_fun.c:592-610).
macro_rules! tick {
    ($self:ident, $reds:ident, $n:expr, $next:expr) => {{
        $self.ph = $next;
        *$reds -= $n as i64;
        if *$reds <= 0 {
            return Ok(None);
        }
        continue;
    }};
}

thread_local! {
    /// `esdp->rand_state`: per-scheduler counter hashed by `erts_sched_local_random`.
    static RAND_STATE: Cell<Option<u64>> = const { Cell::new(None) };
}

static NOSCHED_RANDOM_STATE: AtomicU64 = AtomicU64::new(0);

/// Initialize the term builder's `esdp->rand_state` from its owning scheduler data address.
///
/// Port of erts/emulator/beam/erl_process.c:6083 (init_scheduler_data), OTP-29.1.1.
pub fn initialize_scheduler_random(scheduler_data: *const ()) {
    let address = scheduler_data as usize as u64;
    RAND_STATE.with(|state| state.set(Some(address.wrapping_add(address << 32))));
}

// Port of HALLOC_EXTRA in erts/emulator/beam/erl_map.c:112, OTP-29.1.1.
const HALLOC_EXTRA: usize = 200;

// Port of erts/emulator/beam/erl_process.h:3038 (erts_sched_local_random_hash_64_to_32_shift),
// OTP-29.1.1.
fn random_hash_64_to_32(mut key: u64) -> u32 {
    key = (!key).wrapping_add(key << 18);
    key ^= key >> 31;
    key = key.wrapping_add(key << 2).wrapping_add(key << 4);
    key ^= key >> 11;
    key = key.wrapping_add(key << 6);
    key ^= key >> 22;
    key as u32
}

// Port of erts/emulator/beam/erl_process.h:3054 (erts_sched_local_random), OTP-29.1.1.
fn sched_local_random(additional_seed: u64) -> u32 {
    let value = RAND_STATE.with(|state| match state.get() {
        Some(value) => {
            state.set(Some(value.wrapping_add(1)));
            Some(value)
        }
        None => None,
    });
    let value = value.unwrap_or_else(|| NOSCHED_RANDOM_STATE.fetch_add(1, AtomicOrdering::Relaxed));
    random_hash_64_to_32(value.wrapping_add(additional_seed))
}

/// Which `erts_qsort` comparison a sort uses.
#[derive(Clone, Copy)]
enum SortKey {
    /// `hxnodecmp`: descending swizzled hash.
    Hash,
    /// `hxnodecmpkey`: `CMP_TERM` order of the leaf keys.
    Key,
}
type NodeCompare = fn(*const HxNode, *const HxNode) -> i32;

// Port of erts/emulator/beam/erl_map.c:1160-1186 (hxnodecmp), OTP-29.1.1.
fn node_cmp_hash(a: *const HxNode, b: *const HxNode) -> i32 {
    let a_hx = crate::raw::load(a as usize);
    let b_hx = crate::raw::load(b as usize);
    if a_hx < b_hx {
        1
    } else if a_hx == b_hx {
        0
    } else {
        -1
    }
}

// Port of erts/emulator/beam/erl_map.c:1160-1186 (hxnodecmpkey), OTP-29.1.1.
fn node_cmp_key(a: *const HxNode, b: *const HxNode) -> i32 {
    let a_val = Term(crate::raw::load(a.cast::<u64>().wrapping_add(3) as usize));
    let b_val = Term(crate::raw::load(b.cast::<u64>().wrapping_add(3) as usize));
    match crate::heap::exact_flat_key_cmp(leaf_key(a_val), leaf_key(b_val), false) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// One pending `erts_qsort_helper(base, n, seed)` call.
#[derive(Clone, Copy)]
struct Frame {
    base: usize,
    n: usize,
    seed: u32,
}

#[derive(Clone, Copy)]
enum PartPhase {
    FastTest,
    SlowTest,
}

/// `erts_qsort_partion_array` in flight.
#[derive(Clone, Copy)]
struct Partition {
    frame: Frame,
    /// Absolute index of the first item of the greater-than-pivot part.
    second_part_start: usize,
    curr: usize,
    pivot_part_start: usize,
    pivot_part_end: usize,
    last_part_start: usize,
    ph: PartPhase,
}

/// Yielding `erts_qsort` over the hash records.
///
/// Port of erts/emulator/beam/utils.c:3459-3690 (erts_qsort, erts_qsort_helper,
/// erts_qsort_partion_array, erts_qsort_insertion_sort), OTP-29.1.1, as yielded by YCF
/// (erts/emulator/Makefile.in UTILS_YCF_FLAGS: `-f` on erts_qsort, erts_qsort_helper and
/// erts_qsort_partion_array; the swap and the insertion sort do not yield).
///
/// Recursion is an explicit stack of pending helper calls, run depth first in the order of the
/// two recursive calls.
struct Qsort {
    compare: NodeCompare,
    stack: SmallVec<[Frame; 8]>,
    part: Option<Partition>,
}

impl Qsort {
    fn new(kind: SortKey, n: usize) -> Self {
        // utils.c:3687: the improved seed is only worth its cost for big arrays.
        let seed = if n > 128 { sched_local_random(0) } else { 1 };
        Self {
            compare: match kind {
                SortKey::Hash => node_cmp_hash,
                SortKey::Key => node_cmp_key,
            },
            stack: smallvec![Frame { base: 0, n, seed }],
            part: None,
        }
    }

    /// Run until sorted (`true`) or out of reductions (`false`).
    fn step(&mut self, nodes: &mut [HxNode], reds: &mut i64) -> bool {
        loop {
            if let Some(mut part) = self.part {
                self.part = None;
                if let Some((start, end)) =
                    Self::partition_step(self.compare, &mut part, nodes, reds)
                {
                    let first = Frame {
                        base: part.frame.base,
                        n: start - part.frame.base,
                        seed: part.frame.seed.wrapping_add(1),
                    };
                    let second = Frame {
                        base: end,
                        n: part.frame.base + part.frame.n - end,
                        seed: part.frame.seed.wrapping_add(1),
                    };
                    // The first recursive call runs first.
                    self.stack.push(second);
                    self.stack.push(first);
                } else {
                    self.part = Some(part);
                    return false;
                }
                continue;
            }
            let Some(frame) = self.stack.pop() else {
                return true;
            };
            if frame.n <= 16 {
                insertion_sort(self.compare, &mut nodes[frame.base..frame.base + frame.n]);
                // YCF_CONSUME_REDS(nr_of_items * erts_fit_in_bits_int64(nr_of_items) * 2)
                let bits = (u64::BITS - (frame.n as u64).leading_zeros()) as i64;
                *reds -= frame.n as i64 * bits * 2;
                if *reds <= 0 {
                    return false;
                }
                continue;
            }
            self.part = Some(self.partition_start(nodes, frame));
        }
    }

    // Port of erts/emulator/beam/utils.c:3495-3530 (erts_qsort_partion_array), OTP-29.1.1.
    fn partition_start(&self, nodes: &mut [HxNode], frame: Frame) -> Partition {
        let compare = self.compare as *const () as usize;
        let base = nodes.as_ptr().wrapping_add(frame.base) as usize;
        let pivot_index = (random_hash_64_to_32(
            u64::from(frame.seed)
                .wrapping_add(compare as u64)
                .wrapping_add(base as u64)
                .wrapping_sub(frame.n as u64),
        ) as usize)
            % frame.n;
        swap_nodes(nodes.as_mut_ptr(), frame.base, frame.base + pivot_index);
        Partition {
            frame,
            second_part_start: frame.base + frame.n,
            curr: frame.base + 1,
            pivot_part_start: 0,
            pivot_part_end: 0,
            last_part_start: 0,
            ph: PartPhase::FastTest,
        }
    }

    // Port of erts/emulator/beam/utils.c:3495-3587 (erts_qsort_partion_array), OTP-29.1.1.
    #[inline(never)]
    fn partition_step(
        compare: NodeCompare,
        p: &mut Partition,
        nodes: &mut [HxNode],
        reds: &mut i64,
    ) -> Option<(usize, usize)> {
        let base = p.frame.base;
        let mut curr = p.curr;
        let mut second_part_start = p.second_part_start;
        let mut pivot_part_start = p.pivot_part_start;
        let mut pivot_part_end = p.pivot_part_end;
        let mut last_part_start = p.last_part_start;
        let mut remaining_reds = *reds;

        if matches!(p.ph, PartPhase::FastTest) {
            loop {
                if curr == second_part_start {
                    // Port of the successful fast path in utils.c:3521-3527.
                    let start = second_part_start - 1;
                    swap_nodes(nodes.as_mut_ptr(), base, start);
                    *reds = remaining_reds;
                    return Some((start, second_part_start));
                }
                remaining_reds -= 1;
                if remaining_reds <= 0 {
                    *reds = remaining_reds;
                    p.curr = curr;
                    p.second_part_start = second_part_start;
                    p.ph = PartPhase::FastTest;
                    return None;
                }

                // Port of the fast loop in utils.c:3511-3520. Keep the indices local
                // until a yield, as the C function does across its reduction check.
                let c = compare(
                    nodes.as_ptr().wrapping_add(curr),
                    nodes.as_ptr().wrapping_add(base),
                );
                if c < 0 {
                    curr += 1;
                } else if c == 0 {
                    pivot_part_start = curr - 1;
                    pivot_part_end = curr + 1;
                    last_part_start = second_part_start;
                    swap_nodes(nodes.as_mut_ptr(), base, pivot_part_start);
                    break;
                } else {
                    second_part_start -= 1;
                    swap_nodes(nodes.as_mut_ptr(), curr, second_part_start);
                }
            }
        }

        loop {
            if pivot_part_end == last_part_start {
                *reds = remaining_reds;
                return Some((pivot_part_start, pivot_part_end));
            }
            remaining_reds -= 1;
            if remaining_reds <= 0 {
                *reds = remaining_reds;
                p.curr = curr;
                p.second_part_start = second_part_start;
                p.pivot_part_start = pivot_part_start;
                p.pivot_part_end = pivot_part_end;
                p.last_part_start = last_part_start;
                p.ph = PartPhase::SlowTest;
                return None;
            }

            // Port of the duplicate-pivot loop in utils.c:3555-3572.
            let c = compare(
                nodes.as_ptr().wrapping_add(pivot_part_end),
                nodes.as_ptr().wrapping_add(pivot_part_end - 1),
            );
            if c == 0 {
                pivot_part_end += 1;
            } else if c < 0 {
                swap_nodes(nodes.as_mut_ptr(), pivot_part_start, pivot_part_end);
                pivot_part_start += 1;
                pivot_part_end += 1;
            } else {
                last_part_start -= 1;
                swap_nodes(nodes.as_mut_ptr(), pivot_part_end, last_part_start);
            }
        }
    }
}

/// Sort HAMT records with `erts_qsort` outside a yielding BIF body.
///
/// Port of erts/emulator/beam/utils.c:3685-3689 (erts_qsort), OTP-29.1.1.
pub(crate) fn qsort_nodes(nodes: &mut [HxNode], key_order: bool) {
    if nodes.len() < 2 {
        return;
    }
    let compare = if key_order {
        node_cmp_key
    } else {
        node_cmp_hash
    };
    let seed = if nodes.len() > 128 {
        sched_local_random(0)
    } else {
        1
    };
    qsort_helper(nodes, compare, seed);
}

// Port of erts/emulator/beam/utils.c:3495-3655
// (erts_qsort_partion_array, erts_qsort_helper), OTP-29.1.1.
fn qsort_helper(nodes: &mut [HxNode], compare: NodeCompare, extra_seed: u32) {
    if nodes.len() <= 16 {
        insertion_sort(compare, nodes);
        return;
    }
    let (pivot_start, pivot_end) = partition_array(nodes, compare, extra_seed);
    qsort_helper(
        &mut nodes[..pivot_start],
        compare,
        extra_seed.wrapping_add(1),
    );
    qsort_helper(&mut nodes[pivot_end..], compare, extra_seed.wrapping_add(1));
}

// Port of erts/emulator/beam/utils.c:3499-3587 (erts_qsort_partion_array), OTP-29.1.1.
fn partition_array(nodes: &mut [HxNode], compare: NodeCompare, extra_seed: u32) -> (usize, usize) {
    let base = nodes.as_ptr() as usize as u64;
    let n = nodes.len();
    let compare_address = compare as *const () as usize as u64;
    let pivot_index = random_hash_64_to_32(
        u64::from(extra_seed)
            .wrapping_add(compare_address)
            .wrapping_add(base)
            .wrapping_sub(n as u64),
    ) as usize
        % n;
    swap_nodes(nodes.as_mut_ptr(), 0, pivot_index);

    let mut second_part_start = n;
    let mut curr = 1;
    while curr != second_part_start {
        match compare(nodes.as_ptr().wrapping_add(curr), nodes.as_ptr()) {
            value if value < 0 => curr += 1,
            0 => {
                let mut pivot_part_start = curr - 1;
                let mut pivot_part_end = curr + 1;
                let mut last_part_start = second_part_start;
                swap_nodes(nodes.as_mut_ptr(), 0, pivot_part_start);
                while pivot_part_end != last_part_start {
                    match compare(
                        nodes.as_ptr().wrapping_add(pivot_part_end),
                        nodes.as_ptr().wrapping_add(pivot_part_end - 1),
                    ) {
                        0 => pivot_part_end += 1,
                        value if value < 0 => {
                            swap_nodes(nodes.as_mut_ptr(), pivot_part_start, pivot_part_end);
                            pivot_part_start += 1;
                            pivot_part_end += 1;
                        }
                        _ => {
                            last_part_start -= 1;
                            swap_nodes(nodes.as_mut_ptr(), pivot_part_end, last_part_start);
                        }
                    }
                }
                return (pivot_part_start, pivot_part_end);
            }
            _ => {
                second_part_start -= 1;
                swap_nodes(nodes.as_mut_ptr(), curr, second_part_start);
            }
        }
    }
    let pivot_part_start = second_part_start - 1;
    swap_nodes(nodes.as_mut_ptr(), 0, pivot_part_start);
    (pivot_part_start, second_part_start)
}

// Port of erts/emulator/beam/utils.c:3466-3484 (erts_qsort_swap), OTP-29.1.1.
fn swap_nodes(base: *mut HxNode, i: usize, j: usize) {
    if i == j {
        return;
    }
    let base = base.cast::<u64>();
    let words_per_node = std::mem::size_of::<HxNode>() / std::mem::size_of::<u64>();
    for word in 0..words_per_node {
        let left = base.wrapping_add(i * words_per_node + word) as usize;
        let right = base.wrapping_add(j * words_per_node + word) as usize;
        let value = crate::raw::load(left);
        crate::raw::store(left, crate::raw::load(right));
        crate::raw::store(right, value);
    }
}

// Port of erts/emulator/beam/utils.c:3590-3618 (erts_qsort_insertion_sort), OTP-29.1.1.
fn insertion_sort(compare: NodeCompare, nodes: &mut [HxNode]) {
    if nodes.len() < 2 {
        return;
    }
    let end = nodes.len() - 1;
    let mut unsorted_start = 0;
    while unsorted_start < end {
        let mut smallest_so_far = unsorted_start;
        let mut curr = smallest_so_far + 1;
        while curr <= end {
            if compare(
                nodes.as_ptr().wrapping_add(curr),
                nodes.as_ptr().wrapping_add(smallest_so_far),
            ) < 0
            {
                smallest_so_far = curr;
            }
            curr += 1;
        }
        if smallest_so_far != unsorted_start {
            swap_nodes(nodes.as_mut_ptr(), unsorted_start, smallest_so_far);
        }
        unsorted_start += 1;
    }
}

/// Phases of `hashmap_from_unsorted_array` (loop tests and bodies).
#[derive(Clone, Copy)]
enum UnsortedPhase {
    Sort1,
    OuterTest,
    OuterBody,
    JxTest,
    JxBody,
    Sort2,
    RegionTest,
    RegionBody,
    DupTest,
    DupBody,
    RegionEnd,
}

/// `hashmap_from_unsorted_array` with `reject_dupkeys == 0`, the only form the yielding
/// constructors use.
///
/// Port of erts/emulator/beam/erl_map.c:774-855 (hashmap_from_unsorted_array), OTP-29.1.1.
struct Unsorted {
    ph: UnsortedPhase,
    sort: Option<Qsort>,
    ix: usize,
    jx: usize,
    lx: usize,
    cx: usize,
}

enum UnsortedOut {
    Yield,
    /// Number of unique records left in the array prefix.
    Unique(usize),
}

impl Unsorted {
    fn step(&mut self, hxns: &mut [HxNode], reds: &mut i64) -> UnsortedOut {
        let n = hxns.len();
        loop {
            match self.ph {
                UnsortedPhase::Sort1 => {
                    let sort = self
                        .sort
                        .get_or_insert_with(|| Qsort::new(SortKey::Hash, n));
                    if !sort.step(hxns, reds) {
                        return UnsortedOut::Yield;
                    }
                    self.sort = None;
                    self.ix = 0;
                    self.cx = 0;
                    self.ph = UnsortedPhase::OuterTest;
                }
                UnsortedPhase::OuterTest => {
                    if self.ix < n - 1 {
                        self.ph = UnsortedPhase::OuterBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return UnsortedOut::Yield;
                        }
                    } else {
                        if self.ix < n {
                            hxns[self.cx].hx = hxns[self.ix].hx;
                            hxns[self.cx].val = hxns[self.ix].val;
                            self.cx += 1;
                        }
                        return UnsortedOut::Unique(self.cx);
                    }
                }
                UnsortedPhase::OuterBody => {
                    let ix = self.ix;
                    if hxns[ix].hx == hxns[ix + 1].hx {
                        // Find the region of equal hash values.
                        self.jx = ix + 2;
                        self.ph = UnsortedPhase::JxTest;
                    } else {
                        if ix > self.cx {
                            hxns[self.cx].hx = hxns[ix].hx;
                            hxns[self.cx].val = hxns[ix].val;
                        }
                        self.cx += 1;
                        self.ix += 1;
                        self.ph = UnsortedPhase::OuterTest;
                    }
                }
                UnsortedPhase::JxTest => {
                    if self.jx < n && hxns[self.ix].hx == hxns[self.jx].hx {
                        self.ph = UnsortedPhase::JxBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return UnsortedOut::Yield;
                        }
                    } else {
                        self.ph = UnsortedPhase::Sort2;
                    }
                }
                UnsortedPhase::JxBody => {
                    self.jx += 1;
                    self.ph = UnsortedPhase::JxTest;
                }
                UnsortedPhase::Sort2 => {
                    // Resort the region by key instead of hash value.
                    let (ix, jx) = (self.ix, self.jx);
                    let sort = self
                        .sort
                        .get_or_insert_with(|| Qsort::new(SortKey::Key, jx - ix));
                    if !sort.step(&mut hxns[ix..jx], reds) {
                        return UnsortedOut::Yield;
                    }
                    self.sort = None;
                    self.ph = UnsortedPhase::RegionTest;
                }
                UnsortedPhase::RegionTest => {
                    if self.ix < self.jx {
                        self.ph = UnsortedPhase::RegionBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return UnsortedOut::Yield;
                        }
                    } else {
                        self.ix = self.jx;
                        self.ph = UnsortedPhase::OuterTest;
                    }
                }
                UnsortedPhase::RegionBody => {
                    self.lx = self.ix;
                    self.ph = UnsortedPhase::DupTest;
                }
                UnsortedPhase::DupTest => {
                    self.ix += 1;
                    if self.ix < self.jx
                        && crate::exact_eq(leaf_key(hxns[self.ix].val), leaf_key(hxns[self.lx].val))
                    {
                        self.ph = UnsortedPhase::DupBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return UnsortedOut::Yield;
                        }
                    } else {
                        self.ph = UnsortedPhase::RegionEnd;
                    }
                }
                UnsortedPhase::DupBody => {
                    if hxns[self.ix].i > hxns[self.lx].i {
                        self.lx = self.ix;
                    }
                    self.ph = UnsortedPhase::DupTest;
                }
                UnsortedPhase::RegionEnd => {
                    hxns[self.cx].hx = hxns[self.lx].hx;
                    hxns[self.cx].val = hxns[self.lx].val;
                    self.cx += 1;
                    self.ph = UnsortedPhase::RegionTest;
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum SortedPhase {
    OutTest,
    OutBody,
    JTest,
    JBody,
    ForTest,
    ForBody,
    ForEnd,
}

/// `hashmap_from_sorted_unique_array`: collision nodes and skip counts.
///
/// Port of erts/emulator/beam/erl_map.c:857-911, OTP-29.1.1.
struct SortedUnique {
    ph: SortedPhase,
    ix: usize,
    jx: usize,
    elems: usize,
    i: usize,
    n_colliders: usize,
    pending: Option<HeapBlockBuilder>,
}

impl SortedUnique {
    fn new() -> Self {
        Self {
            ph: SortedPhase::OutTest,
            ix: 0,
            jx: 0,
            elems: 1,
            i: 0,
            n_colliders: 0,
            pending: None,
        }
    }

    /// Returns the element count for the chunked stage once the array is annotated.
    fn step<H: HeapAlloc + ?Sized>(
        &mut self,
        hxns: &mut [HxNode],
        reds: &mut i64,
        heap: &mut H,
    ) -> Result<Option<usize>, TermError> {
        let n = hxns.len();
        loop {
            match self.ph {
                SortedPhase::OutTest => {
                    if self.ix < n - 1 {
                        self.ph = SortedPhase::OutBody;
                        *reds -= 1;
                        if *reds <= 0 {
                            return Ok(None);
                        }
                    } else {
                        return Ok(Some(self.elems));
                    }
                }
                SortedPhase::OutBody => {
                    let ix = self.ix;
                    if hxns[ix].hx == hxns[ix + 1].hx {
                        self.jx = ix + 2;
                        self.ph = SortedPhase::JTest;
                    } else {
                        hxns[ix].skip = 1;
                        self.elems += 1;
                        self.ix += 1;
                        self.ph = SortedPhase::OutTest;
                    }
                }
                SortedPhase::JTest => {
                    if self.jx < n && hxns[self.ix].hx == hxns[self.jx].hx {
                        tick!(self, reds, 1, SortedPhase::JBody);
                    }
                    self.n_colliders = self.jx - self.ix;
                    let mut builder = TermBuilder::new(heap)
                        .reserve_boxed_words(self.n_colliders + 1, HALLOC_EXTRA)?;
                    builder.write_header((self.n_colliders as u64) << 6)?;
                    self.pending = Some(builder);
                    self.i = 0;
                    self.ph = SortedPhase::ForTest;
                }
                SortedPhase::JBody => {
                    self.jx += 1;
                    self.ph = SortedPhase::JTest;
                }
                SortedPhase::ForTest => {
                    if self.i < self.n_colliders {
                        tick!(self, reds, 1, SortedPhase::ForBody);
                    }
                    self.ph = SortedPhase::ForEnd;
                }
                SortedPhase::ForBody => {
                    self.pending
                        .as_mut()
                        .expect("collision node allocation")
                        .write_term(hxns[self.ix + self.i].val)?;
                    self.i += 1;
                    self.ph = SortedPhase::ForTest;
                }
                SortedPhase::ForEnd => {
                    hxns[self.ix].val = self
                        .pending
                        .take()
                        .expect("collision node allocation")
                        .finish()?;
                    hxns[self.ix].skip = self.n_colliders;
                    self.ix = self.jx;
                    if self.ix < n {
                        self.elems += 1;
                    }
                    self.ph = SortedPhase::OutTest;
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ChunkPhase {
    Init,
    OneTest,
    OneBody,
    L1Test,
    L1Body,
    AfterL1,
    L2Test,
    L2Body,
    PushFirst,
    ElemsTest,
    ElemsBody,
    L4Test,
    L4Body,
    Branch,
    L5Test,
    L5Body,
    L6Test,
    L6Body,
    L7Test,
    L7Body,
    L6End,
    ElemEnd,
    AfterElems,
    L8Test,
    L8Body,
    AfterL8,
    L9Test,
    L9Body,
    L10Test,
    L10Body,
    L9End,
    RootStart,
    L11Test,
    L11Body,
    RootEnd,
}

// The index comes from the sorted HxNode run and its skip counts, as in hashmap_from_chunked_array.
#[inline(always)]
fn hxnode_word(hxns: &[HxNode], index: usize, word_offset: usize) -> u64 {
    let node = hxns.as_ptr().wrapping_add(index) as usize;
    crate::raw::load(node.wrapping_add(word_offset * std::mem::size_of::<u64>()))
}

/// `hashmap_from_chunked_array`: builds the trie bottom-up on an explicit stack.
///
/// Port of erts/emulator/beam/erl_map.c:919-1158, OTP-29.1.1. Where C allocates a node and then
/// fills it inside a `while (sz--)` loop that can yield, the words are gathered first and the
/// node is allocated when the loop ends (nothing else allocates in between).
struct Chunked {
    ph: ChunkPhase,
    /// Records in the annotated array.
    n: usize,
    /// Number of leaves, stored in the root.
    size: usize,
    ix: usize,
    d: usize,
    dn: usize,
    dc: usize,
    wat: usize,
    slot: u64,
    v: u64,
    vp: u64,
    vn: u64,
    hdr: u64,
    sz: usize,
    elems: usize,
    res: Term,
    stack: ErtsEStack,
    pending: Option<HeapBlockBuilder>,
}

/// The default-array and growth behavior of erts `ErtsEStack`.
///
/// Port of erts/emulator/beam/global.h:306-445 and utils.c:212-237, OTP-29.1.1.
struct ErtsEStack {
    inline: [u64; 16],
    len: usize,
    spill: Option<Vec<u64>>,
}

impl ErtsEStack {
    #[inline(always)]
    fn new() -> Self {
        Self {
            inline: [0; 16],
            len: 0,
            spill: None,
        }
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.spill.as_ref().map_or(self.len, Vec::len)
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline(always)]
    fn as_slice(&self) -> &[u64] {
        self.spill.as_deref().unwrap_or(&self.inline[..self.len])
    }

    #[inline(always)]
    fn reserve(&mut self, need: usize) {
        if let Some(spill) = &mut self.spill {
            let old_size = spill.capacity();
            if old_size - spill.len() < need {
                let new_size = if need < old_size {
                    2 * old_size
                } else {
                    (need / old_size + 2) * old_size
                };
                let mut grown = Vec::with_capacity(new_size);
                grown.extend_from_slice(spill);
                *spill = grown;
            }
        } else if 16 - self.len < need {
            let new_size = if need < 16 { 32 } else { (need / 16 + 2) * 16 };
            let mut spill = Vec::with_capacity(new_size);
            spill.extend_from_slice(&self.inline[..self.len]);
            self.spill = Some(spill);
        }
    }

    #[inline(always)]
    fn push(&mut self, value: u64) {
        self.reserve(1);
        if let Some(spill) = &mut self.spill {
            spill.push(value);
        } else {
            self.inline[self.len] = value;
            self.len += 1;
        }
    }

    #[inline(always)]
    fn push2(&mut self, first: u64, second: u64) {
        self.reserve(2);
        if let Some(spill) = &mut self.spill {
            spill.push(first);
            spill.push(second);
        } else {
            self.inline[self.len] = first;
            self.inline[self.len + 1] = second;
            self.len += 2;
        }
    }

    #[inline(always)]
    fn pop(&mut self) -> Option<u64> {
        if let Some(spill) = &mut self.spill {
            spill.pop()
        } else if self.len == 0 {
            None
        } else {
            self.len -= 1;
            Some(self.inline[self.len])
        }
    }

    #[inline(always)]
    fn truncate(&mut self, len: usize) {
        if let Some(spill) = &mut self.spill {
            spill.truncate(len);
        } else {
            self.len = len;
        }
    }
}

impl Chunked {
    fn new(n: usize, size: usize) -> Self {
        Self {
            ph: ChunkPhase::Init,
            n,
            size,
            ix: 0,
            d: 0,
            dn: 0,
            dc: 0,
            wat: 0,
            slot: 0,
            v: 0,
            vp: 0,
            vn: 0,
            hdr: 0,
            sz: 0,
            elems: 0,
            res: Term::NIL,
            stack: ErtsEStack::new(),
            pending: None,
        }
    }

    fn collision_node<H: HeapAlloc + ?Sized>(
        heap: &mut H,
        level_hash: u64,
        dc: usize,
        res: Term,
    ) -> Result<Term, TermError> {
        let mut builder = TermBuilder::new(heap).reserve_boxed_words(2, HALLOC_EXTRA)?;
        builder.write_words(&[node_bitmap_header(1 << maskval(level_hash, dc)), res.bits()])?;
        builder.finish()
    }

    fn pop(&mut self) -> u64 {
        self.stack.pop().expect("HAMT build stack")
    }

    #[inline(always)]
    fn push2(&mut self, first: u64, second: u64) {
        self.stack.push2(first, second);
    }

    #[inline(always)]
    fn run_simple_elements(&mut self, hxns: &[HxNode], reds: &mut i64, paid_first: bool) {
        let mut elems = self.elems;
        let mut ix = self.ix;
        let mut d = self.d;
        let mut vp = self.vp;
        let mut v = self.v;
        let mut remaining_reds = *reds;
        let mut paid = paid_first;
        loop {
            if !paid {
                if elems == 0 {
                    self.elems = 0;
                    self.ix = ix;
                    self.d = d;
                    self.vp = vp;
                    self.v = v;
                    self.ph = ChunkPhase::AfterElems;
                    *reds = remaining_reds;
                    return;
                }
                elems -= 1;
                remaining_reds -= 1;
                if remaining_reds <= 0 {
                    self.elems = elems;
                    self.ix = ix;
                    self.d = d;
                    self.vp = vp;
                    self.v = v;
                    self.ph = ChunkPhase::ElemsBody;
                    *reds = remaining_reds;
                    return;
                }
            }
            paid = false;

            let hdr = self.pop();
            ix += hxnode_word(hxns, ix, 1) as usize;
            let skip = hxnode_word(hxns, ix, 1) as usize;
            let vn = hxnode_word(hxns, ix + skip, 0);
            let dn = cdepth(v, vn);
            debug_assert!(v > vn);
            let res = Term(hxnode_word(hxns, ix, 3));
            if skip > 1 || d != dn {
                self.elems = elems;
                self.ix = ix;
                self.d = d;
                self.dn = dn;
                self.vp = vp;
                self.v = v;
                self.vn = vn;
                self.hdr = hdr;
                self.res = res;
                if skip > 1 {
                    self.wat = d.max(dn);
                    self.dc = HAMT_MAX_LEVEL - 1;
                    self.ph = ChunkPhase::L4Test;
                } else if d < dn {
                    self.ph = ChunkPhase::L5Test;
                } else {
                    self.ph = ChunkPhase::L6Test;
                }
                *reds = remaining_reds;
                return;
            }
            let bp = 1 << maskval(v, d);
            self.push2(res.bits(), hdr | bp);
            vp = v;
            v = vn;
            d = dn;
        }
    }

    fn step<H: HeapAlloc + ?Sized>(
        &mut self,
        hxns: &[HxNode],
        reds: &mut i64,
        heap: &mut H,
    ) -> Result<Option<Term>, TermError> {
        use ChunkPhase as C;
        let max_level = HAMT_MAX_LEVEL;
        let mut phase = self.ph;
        let mut remaining_reds = *reds;
        macro_rules! chunk_tick {
            ($n:expr, $next:expr) => {{
                phase = $next;
                remaining_reds -= $n as i64;
                if remaining_reds <= 0 {
                    self.ph = phase;
                    *reds = remaining_reds;
                    return Ok(None);
                }
                continue;
            }};
        }
        loop {
            match phase {
                C::Init => {
                    if self.n == 1 {
                        // Every key shares all HAMT_MAX_LEVEL hash slots.
                        self.res = Term(hxnode_word(hxns, 0, 3));
                        self.v = hxnode_word(hxns, 0, 0);
                        self.d = max_level - 1;
                        phase = C::OneTest;
                    } else {
                        self.ix = 0;
                        self.d = 0;
                        self.vp = hxnode_word(hxns, 0, 0);
                        self.v = hxnode_word(hxns, hxnode_word(hxns, 0, 1) as usize, 0);
                        debug_assert!(self.vp > self.v);
                        self.slot = maskval(self.vp, self.d);
                        phase = C::L1Test;
                    }
                }
                C::OneTest => {
                    if self.d > 0 {
                        chunk_tick!(1, C::OneBody);
                    }
                    let slot = maskval(self.v, 0);
                    let root = produce_words(
                        heap,
                        &[
                            head_bitmap_header(1 << slot),
                            self.size as u64,
                            self.res.bits(),
                        ],
                    )?;
                    *reds = remaining_reds;
                    return Ok(Some(root));
                }
                C::OneBody => {
                    self.res = Self::collision_node(heap, self.v, self.d, self.res)?;
                    self.d -= 1;
                    phase = C::OneTest;
                }
                C::L1Test => {
                    if self.slot == maskval(self.v, self.d) {
                        chunk_tick!(1, C::L1Body);
                    }
                    phase = C::AfterL1;
                }
                C::L1Body => {
                    self.stack.push(1 << self.slot);
                    self.d += 1;
                    self.slot = maskval(self.vp, self.d);
                    phase = C::L1Test;
                }
                C::AfterL1 => {
                    self.res = Term(hxnode_word(hxns, self.ix, 3));
                    if hxnode_word(hxns, self.ix, 1) > 1 {
                        self.dc = max_level - 1;
                        phase = C::L2Test;
                    } else {
                        phase = C::PushFirst;
                    }
                }
                C::L2Test => {
                    if self.dc > self.d {
                        chunk_tick!(1, C::L2Body);
                    }
                    phase = C::PushFirst;
                }
                C::L2Body => {
                    self.res = Self::collision_node(heap, self.vp, self.dc, self.res)?;
                    self.dc -= 1;
                    phase = C::L2Test;
                }
                C::PushFirst => {
                    self.push2(self.res.bits(), 1 << self.slot);
                    // Remove first and last elements.
                    self.elems = self.n - 2;
                    phase = C::ElemsTest;
                }
                C::ElemsTest => {
                    self.run_simple_elements(hxns, &mut remaining_reds, false);
                    phase = self.ph;
                }
                C::ElemsBody => {
                    self.run_simple_elements(hxns, &mut remaining_reds, true);
                    phase = self.ph;
                }
                C::L4Test => {
                    if self.dc > self.wat {
                        chunk_tick!(1, C::L4Body);
                    }
                    phase = C::Branch;
                }
                C::L4Body => {
                    self.res = Self::collision_node(heap, self.v, self.dc, self.res)?;
                    self.dc -= 1;
                    phase = C::L4Test;
                }
                C::Branch => {
                    if self.d < self.dn {
                        // Next depth is higher (implies collision).
                        phase = C::L5Test;
                    } else if self.d == self.dn {
                        // No collisions at all.
                        let bp = 1 << maskval(self.v, self.d);
                        self.push2(self.res.bits(), self.hdr | bp);
                        phase = C::ElemEnd;
                    } else {
                        // A drop: build nodes and subtree.
                        phase = C::L6Test;
                    }
                }
                C::L5Test => {
                    if self.d < self.dn {
                        chunk_tick!(1, C::L5Body);
                    }
                    self.slot = maskval(self.v, self.d);
                    self.push2(self.res.bits(), 1 << self.slot);
                    phase = C::ElemEnd;
                }
                C::L5Body => {
                    self.slot = maskval(self.v, self.d);
                    self.stack.push(self.hdr | (1 << self.slot));
                    self.d += 1;
                    self.hdr = 0;
                    phase = C::L5Test;
                }
                C::L6Test => {
                    if self.dn != self.d {
                        chunk_tick!(1, C::L6Body);
                    }
                    self.push2(self.res.bits(), self.hdr);
                    phase = C::ElemEnd;
                }
                C::L6Body => {
                    self.slot = maskval(self.v, self.d);
                    // OR the bit position before the size calculation to handle redundant
                    // collisions.
                    self.hdr |= 1 << self.slot;
                    self.sz = (self.hdr as u16).count_ones() as usize;
                    let mut builder =
                        TermBuilder::new(heap).reserve_boxed_words(self.sz + 1, HALLOC_EXTRA)?;
                    builder.write_words(&[node_bitmap_header(self.hdr), self.res.bits()])?;
                    self.pending = Some(builder);
                    self.sz -= 1;
                    phase = C::L7Test;
                }
                C::L7Test => {
                    if self.sz != 0 && remaining_reds > 1 {
                        let count = self.sz.min((remaining_reds - 1) as usize);
                        let stack_start = self.stack.len() - count;
                        self.pending
                            .as_mut()
                            .expect("bitmap node allocation")
                            .write_term_bits_reversed(&self.stack.as_slice()[stack_start..])?;
                        self.stack.truncate(stack_start);
                        self.sz -= count;
                        remaining_reds -= count as i64;
                    }
                    if self.sz != 0 {
                        // YCF consumes the reduction before popping the next stack word.
                        self.sz -= 1;
                        remaining_reds -= 1;
                        phase = C::L7Body;
                        self.ph = phase;
                        *reds = remaining_reds;
                        return Ok(None);
                    }
                    phase = C::L6End;
                }
                C::L7Body => {
                    let word = self.pop();
                    self.pending
                        .as_mut()
                        .expect("bitmap node allocation")
                        .write_term_bits(word)?;
                    phase = C::L7Test;
                }
                C::L6End => {
                    self.res = self
                        .pending
                        .take()
                        .expect("bitmap node allocation")
                        .finish()?;
                    // Pop the next hdr; it is pushed back if it is not needed.
                    self.hdr = self.pop();
                    self.d -= 1;
                    phase = C::L6Test;
                }
                C::ElemEnd => {
                    self.vp = self.v;
                    self.v = self.vn;
                    self.d = self.dn;
                    phase = C::ElemsTest;
                }
                C::AfterElems => {
                    self.dn = cdepth(self.vp, self.v);
                    self.ix += hxnode_word(hxns, self.ix, 1) as usize;
                    self.res = Term(hxnode_word(hxns, self.ix, 3));
                    if hxnode_word(hxns, self.ix, 1) > 1 {
                        self.dc = max_level - 1;
                        phase = C::L8Test;
                    } else {
                        phase = C::AfterL8;
                    }
                }
                C::L8Test => {
                    if self.dc > self.dn {
                        chunk_tick!(1, C::L8Body);
                    }
                    phase = C::AfterL8;
                }
                C::L8Body => {
                    self.res = Self::collision_node(heap, self.v, self.dc, self.res)?;
                    self.dc -= 1;
                    phase = C::L8Test;
                }
                C::AfterL8 => {
                    self.hdr = self.pop();
                    phase = C::L9Test;
                }
                C::L9Test => {
                    if self.dn != 0 {
                        chunk_tick!(1, C::L9Body);
                    }
                    phase = C::RootStart;
                }
                C::L9Body => {
                    self.slot = maskval(self.v, self.dn);
                    self.hdr |= 1 << self.slot;
                    self.sz = (self.hdr as u16).count_ones() as usize;
                    let mut builder =
                        TermBuilder::new(heap).reserve_boxed_words(self.sz + 1, HALLOC_EXTRA)?;
                    builder.write_words(&[node_bitmap_header(self.hdr), self.res.bits()])?;
                    self.pending = Some(builder);
                    self.sz -= 1;
                    phase = C::L10Test;
                }
                C::L10Test => {
                    if self.sz != 0 && remaining_reds > 1 {
                        let count = self.sz.min((remaining_reds - 1) as usize);
                        let stack_start = self.stack.len() - count;
                        self.pending
                            .as_mut()
                            .expect("bitmap node allocation")
                            .write_term_bits_reversed(&self.stack.as_slice()[stack_start..])?;
                        self.stack.truncate(stack_start);
                        self.sz -= count;
                        remaining_reds -= count as i64;
                    }
                    if self.sz != 0 {
                        self.sz -= 1;
                        remaining_reds -= 1;
                        phase = C::L10Body;
                        self.ph = phase;
                        *reds = remaining_reds;
                        return Ok(None);
                    }
                    phase = C::L9End;
                }
                C::L10Body => {
                    let word = self.pop();
                    self.pending
                        .as_mut()
                        .expect("bitmap node allocation")
                        .write_term_bits(word)?;
                    phase = C::L10Test;
                }
                C::L9End => {
                    self.res = self
                        .pending
                        .take()
                        .expect("bitmap node allocation")
                        .finish()?;
                    self.hdr = self.pop();
                    self.dn -= 1;
                    phase = C::L9Test;
                }
                C::RootStart => {
                    // And finally the root.
                    self.slot = maskval(self.v, self.dn);
                    self.hdr |= 1 << self.slot;
                    self.sz = (self.hdr as u16).count_ones() as usize;
                    let mut builder = TermBuilder::new(heap).reserve_boxed_words(self.sz + 2, 0)?;
                    builder.write_words(&[
                        if self.hdr == 0xffff {
                            HEAD_ARRAY_HEADER
                        } else {
                            head_bitmap_header(self.hdr)
                        },
                        self.size as u64,
                        self.res.bits(),
                    ])?;
                    self.pending = Some(builder);
                    self.sz -= 1;
                    phase = C::L11Test;
                }
                C::L11Test => {
                    if self.sz != 0 && remaining_reds > 1 {
                        let count = self.sz.min((remaining_reds - 1) as usize);
                        let stack_start = self.stack.len() - count;
                        self.pending
                            .as_mut()
                            .expect("map head allocation")
                            .write_term_bits_reversed(&self.stack.as_slice()[stack_start..])?;
                        self.stack.truncate(stack_start);
                        self.sz -= count;
                        remaining_reds -= count as i64;
                    }
                    if self.sz != 0 {
                        self.sz -= 1;
                        remaining_reds -= 1;
                        phase = C::L11Body;
                        self.ph = phase;
                        *reds = remaining_reds;
                        return Ok(None);
                    }
                    phase = C::RootEnd;
                }
                C::L11Body => {
                    let word = self.pop();
                    self.pending
                        .as_mut()
                        .expect("map head allocation")
                        .write_term_bits(word)?;
                    phase = C::L11Test;
                }
                C::RootEnd => {
                    let root = self.pending.take().expect("map head allocation").finish()?;
                    debug_assert!(self.stack.is_empty());
                    *reds = remaining_reds;
                    return Ok(Some(root));
                }
            }
        }
    }
}

enum Stage {
    Unsorted(Unsorted),
    SortedUnique(SortedUnique),
    Chunked(Chunked),
}

/// Yielding `hashmap_from_unsorted_array`: sort, compact, annotate collisions, chunk.
///
/// Port of erts/emulator/beam/erl_map.c:774-1158 as transformed by YCF, OTP-29.1.1. All four
/// functions are `-f` (automatic) yielders and cost nothing for the calls between them.
pub struct HashmapBuild {
    hxns: Vec<HxNode>,
    stage: Stage,
}

impl HashmapBuild {
    /// Start building from the leaf records created by [`crate::hashmap_leaves_hashed`].
    pub fn new(hxns: Vec<HxNode>) -> Self {
        assert!(!hxns.is_empty());
        Self {
            hxns,
            stage: Stage::Unsorted(Unsorted {
                ph: UnsortedPhase::Sort1,
                sort: None,
                ix: 0,
                jx: 0,
                lx: 0,
                cx: 0,
            }),
        }
    }

    /// Run with `reds` reductions of budget left (the `ycf_nr_of_reductions` counter, which
    /// may end up negative). Returns the map once complete, `None` after a yield.
    pub fn step<H: HeapAlloc + ?Sized>(
        &mut self,
        reds: &mut i64,
        heap: &mut H,
    ) -> Result<Option<Term>, TermError> {
        loop {
            match &mut self.stage {
                Stage::Unsorted(unsorted) => match unsorted.step(&mut self.hxns, reds) {
                    UnsortedOut::Yield => return Ok(None),
                    UnsortedOut::Unique(cx) if cx > 1 => {
                        self.hxns.truncate(cx);
                        self.stage = Stage::SortedUnique(SortedUnique::new());
                    }
                    UnsortedOut::Unique(_) => {
                        // One item, either because n was 1 or because every key repeats. The
                        // swizzled hash keeps the root slot in its top nibble.
                        let slot = self.hxns[0].hx >> ((HAMT_MAX_LEVEL - 1) * 4);
                        return produce_words(
                            heap,
                            &[head_bitmap_header(1 << slot), 1, self.hxns[0].val.bits()],
                        )
                        .map(Some);
                    }
                },
                Stage::SortedUnique(sorted) => match sorted.step(&mut self.hxns, reds, heap)? {
                    None => return Ok(None),
                    Some(elems) => {
                        let size = self.hxns.len();
                        self.stage = Stage::Chunked(Chunked::new(elems, size));
                    }
                },
                Stage::Chunked(chunked) => return chunked.step(&self.hxns, reds, heap),
            }
        }
    }
}

/// Backwards walk over the children of one map or collision node.
///
/// `next` visits children in reverse storage order; `next_back` visits them in storage order.
pub struct MapNodeChildren {
    node: Term,
    front: usize,
    back: usize,
    head: bool,
}

impl MapNodeChildren {
    /// Start iterating the children of a HAMT node or collision tuple.
    // Port of erts/emulator/beam/external.c:3411-3424 (ENC_HASHMAP_NODE), OTP-29.1.1.
    pub fn new(node: Term) -> Option<Self> {
        let header = node.header()?;
        if !matches!(node.classify(), TermKind::Map | TermKind::Tuple) {
            return None;
        }
        let front = if header & 63 == crate::MAP {
            child_range(header, 0).start
        } else {
            1
        };
        // SAFETY: callers pass a live HAMT node or tuple; the header determines its allocation
        // size, and the source heap remains live for the iterator's use.
        let back = unsafe { boxed_object_words(header, node.raw_ptr()) };
        Some(Self {
            node,
            front,
            back,
            head: header & 0x80 != 0,
        })
    }

    /// Whether this is a HAMT head node that carries the map size and ETF header.
    pub fn is_head(&self) -> bool {
        self.head
    }

    fn child_at(&self, index: usize) -> Term {
        // SAFETY: index is an initialized child slot in the live HAMT node or tuple.
        Term(unsafe { *self.node.raw_ptr().add(index) })
    }
}

impl Iterator for MapNodeChildren {
    type Item = Term;

    // Port of erts/emulator/beam/external.c:3411-3424 (ENC_HASHMAP_NODE), OTP-29.1.1.
    fn next(&mut self) -> Option<Self::Item> {
        if self.back <= self.front {
            return None;
        }
        self.back -= 1;
        Some(self.child_at(self.back))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.back.saturating_sub(self.front);
        (remaining, Some(remaining))
    }
}

impl DoubleEndedIterator for MapNodeChildren {
    // Port of erts/emulator/beam/external.c:3411-3424 (ENC_HASHMAP_NODE), OTP-29.1.1.
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.back <= self.front {
            return None;
        }
        let index = self.front;
        self.front += 1;
        Some(self.child_at(index))
    }
}

/// Read a HAMT leaf's key and value without exposing its heap pointer.
// Port of erts/emulator/beam/external.c:3404-3419 (ENC_HASHMAP_NODE), OTP-29.1.1.
pub fn hashmap_leaf_pair(leaf: Term) -> Option<(Term, Term)> {
    if leaf.classify() != TermKind::List {
        return None;
    }
    // SAFETY: HAMT leaves are live two-word cons cells.
    unsafe { leaf.cons_ref() }
}

/// Backwards walk over a hashmap's entries, so that consing each one onto a list yields the
/// entries in `maps:to_list/1` order.
///
/// Port of erts/emulator/beam/erl_map.c:2337-2420 (hashmap_iterator_init with `reverse`,
/// hashmap_iterator_prev), OTP-29.1.1.
pub struct MapReverseIter {
    nodes: SmallVec<[MapNodeChildren; 16]>,
}

impl MapReverseIter {
    /// Start at the end of a hashmap; `None` for any other term.
    pub fn new(map: Term) -> Option<Self> {
        if map.classify() != TermKind::Map || !map.is_hashmap() {
            return None;
        }
        let mut iter = Self {
            nodes: SmallVec::new(),
        };
        iter.push_node(map);
        Some(iter)
    }

    fn push_node(&mut self, node: Term) {
        self.nodes
            .push(MapNodeChildren::new(node).expect("HAMT node"));
    }
}

impl Iterator for MapReverseIter {
    type Item = (Term, Term);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let Some(child) = self.nodes.last_mut()?.next() else {
                self.nodes.pop();
                continue;
            };
            if child.classify() == TermKind::List {
                return hashmap_leaf_pair(child);
            }
            self.push_node(child);
        }
    }
}

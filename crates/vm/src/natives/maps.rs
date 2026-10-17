//! Map iterator primitives used by the OTP maps module.

use crate::exceptions::Trap;
use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_sched::RunCtx;
use arinsal_term::{
    HeapReservation, Term, TermBuilder, TermKind, Tuple3Chain, atoms, global_atoms,
};

/// Elements returned on the first `path = 0` hashmap call.
/// Port of erts/emulator/beam/erl_map.h:96 (MAP_SMALL_MAP_LIMIT), OTP-29.1.1.
const MAP_SMALL_MAP_LIMIT: usize = 32;
/// Port of erts/emulator/beam/erl_map.c:3631 (PATH_ELEM_SIZE), OTP-29.1.1.
const PATH_ELEM_SIZE: u32 = 4;
/// 64-bit `ErtsDigit` holds 16 path nibbles.
/// Port of erts/emulator/beam/erl_map.c:3634 (PATH_ELEMS_PER_DIGIT), OTP-29.1.1.
const PATH_ELEMS_PER_DIGIT: usize = 16;
/// Port of erts/emulator/beam/erl_map.c:3660 (ORDERED_ITER_FACTOR), OTP-29.1.1.
const ORDERED_ITER_FACTOR: i32 = 32;

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("built-in atom"))
}

/// The `iterator` and `none` atoms. Both are predefined, so their indices are constants.
const ITERATOR: Term = Term::atom(atoms::ITERATOR);
const NONE: Term = Term::atom(atoms::NONE);

#[cold]
#[inline(never)]
fn badarg() -> Trap {
    Trap::error(atom("badarg"))
}

#[cold]
#[inline(never)]
fn system_limit() -> Trap {
    Trap::error(atom("system_limit"))
}

/// `DECLARE_WSTACK` holds 16 words, or four `WSTACK_PUSH4` frames, before growing.
/// Port of erts/emulator/beam/global.h:493-516, OTP-29.1.1.
const WSTACK_INLINE_FRAMES: usize = 4;

/// One `WSTACK_PUSH4` entry: node, index, size and child pointer.
/// Port of erts/emulator/beam/erl_map.c:3844-3847, OTP-29.1.1.
#[repr(C)]
#[derive(Clone, Copy)]
struct Frame {
    node: Term,
    idx: usize,
    sz: usize,
    ptr: *const u64,
}

impl Frame {
    const EMPTY: Self = Self {
        node: Term::NIL,
        idx: 0,
        sz: 0,
        ptr: std::ptr::null(),
    };
}

/// The inline and growing storage used by OTP's WSTACK macros.
// Port of erts/emulator/beam/global.h:493-516, 623-655 and utils.c:238-262, OTP-29.1.1.
struct WStack {
    inline: [Frame; WSTACK_INLINE_FRAMES],
    grown: Option<Box<[Frame]>>,
    len: usize,
}

impl WStack {
    #[inline(always)]
    fn new() -> Self {
        Self {
            inline: [Frame::EMPTY; WSTACK_INLINE_FRAMES],
            grown: None,
            len: 0,
        }
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn get(&self, index: usize) -> &Frame {
        debug_assert!(index < self.len);
        if let Some(grown) = self.grown.as_ref() {
            &grown[index]
        } else {
            &self.inline[index]
        }
    }

    #[inline(always)]
    fn push(&mut self, frame: Frame) -> Result<(), ()> {
        if self.len == WSTACK_INLINE_FRAMES && self.grown.is_none() {
            self.grow(WSTACK_INLINE_FRAMES * 2)?;
        } else if let Some(grown) = self.grown.as_ref()
            && self.len == grown.len()
        {
            self.grow(grown.len() * 2)?;
        }
        if let Some(grown) = self.grown.as_mut() {
            grown[self.len] = frame;
        } else {
            self.inline[self.len] = frame;
        }
        self.len += 1;
        Ok(())
    }

    #[inline(always)]
    fn pop(&mut self) -> Option<Frame> {
        if self.len == 0 {
            return None;
        }
        let index = self.len - 1;
        let frame = *self.get(index);
        self.len = index;
        Some(frame)
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, size: usize) -> Result<(), ()> {
        let mut frames = Vec::new();
        frames.try_reserve_exact(size).map_err(|_| ())?;
        if let Some(grown) = &self.grown {
            frames.extend_from_slice(grown);
        } else {
            frames.extend_from_slice(&self.inline);
        }
        frames.resize(size, Frame::EMPTY);
        self.grown = Some(frames.into_boxed_slice());
        Ok(())
    }
}

/// A decoded HAMT node: `sz` children starting at `ptr`.
/// Port of erts/emulator/beam/erl_map.c:2313-2335 (hashmap_node_size), OTP-29.1.1.
#[derive(Clone, Copy)]
struct NodeCursor {
    node: Term,
    sz: usize,
    ptr: *const u64,
}

impl NodeCursor {
    #[inline(always)]
    fn new(node: Term) -> Result<Self, Trap> {
        let header = node.header().ok_or_else(badarg)?;
        let subtype = (header >> 6) & 3;
        let collision = header & 63 == 0;
        let sz = if collision {
            (header >> 6) as usize
        } else if subtype == 2 {
            16
        } else if subtype == 1 || subtype == 3 {
            ((header >> 16) & 0xffff).count_ones() as usize
        } else {
            return Err(badarg());
        };
        let offset = if collision || subtype == 1 { 1 } else { 2 };
        // SAFETY: the validated HAMT header describes the node allocation and child range.
        let ptr = unsafe { node.raw_ptr().add(offset) };
        Ok(Self { node, sz, ptr })
    }

    #[inline(always)]
    fn is_collision(self) -> bool {
        self.node.header().is_some_and(|header| header & 63 == 0)
    }

    /// Read child word `idx` (`ptr[idx]`).
    #[inline(always)]
    fn word(self, idx: usize) -> u64 {
        debug_assert!(idx < self.sz);
        // SAFETY: `idx` is below the node's child count, all initialized words.
        unsafe { *self.ptr.add(idx) }
    }
}

/// Key and value of a leaf child word (a cons cell `[K | V]`).
#[inline(always)]
fn leaf_pair(word: u64) -> (Term, Term) {
    // SAFETY: the caller checked the list tag; a leaf is a two-word cell on the live map heap.
    unsafe {
        let cell = (word & !7) as *const u64;
        (
            Term::from_raw_bits(*cell),
            Term::from_raw_bits(*cell.add(1)),
        )
    }
}

#[inline(always)]
fn is_leaf_word(word: u64) -> bool {
    word & 3 == 1
}

/// Path words of the argument: a small, or the digits of a non-negative bignum.
/// Port of erts/emulator/beam/erl_map.c:3796-3810, OTP-29.1.1.
struct PathDigits {
    digits: [u64; 2],
    is_zero_small: bool,
}

impl PathDigits {
    /// Words past the encoded integer read as zero ("just follow 0 path").
    fn get(&self, index: usize) -> u64 {
        self.digits.get(index).copied().unwrap_or(0)
    }
}

#[inline(always)]
fn path_digits(path: Term) -> Result<PathDigits, Trap> {
    if let Some(value) = path.as_small() {
        // unsigned_val(): a logical shift of the tagged word, so negatives keep their low bits.
        let digit = (value as u64) & (u64::MAX >> 4);
        return Ok(PathDigits {
            digits: [digit, 0],
            is_zero_small: value == 0,
        });
    }
    // SAFETY: `big_ref` borrows a live bignum for this call.
    let Some(big) = (unsafe { path.big_ref() }) else {
        return Err(badarg());
    };
    if big.is_negative() {
        return Err(badarg());
    }
    let mut digits = [0; 2];
    for (dst, src) in digits.iter_mut().zip(big.digits()) {
        *dst = *src;
    }
    Ok(PathDigits {
        digits,
        is_zero_small: false,
    })
}

/// Number of elements per call from the reductions left.
/// Port of erts/emulator/beam/erl_map.c:3783-3801 (FCALLS_ELEMS), OTP-29.1.1.
#[inline(always)]
fn chunk_len(reductions: i32, map_size: usize) -> usize {
    let by_reds = ((reductions.max(0) as usize) / 4).max(1);
    by_reds.min(map_size)
}

/// Port of erts/emulator/beam/erl_map.c:3790-4130 (hashmap branch of erts_internal_map_next_3),
/// OTP-29.1.1. Terms are built with `HAlloc` semantics (heap fragment on shortage, never a GC),
/// so the node pointers kept on the stack stay valid; only the words used are allocated, which
/// is what `HRelease` leaves of erts' worst-case reservation.
fn hamt_next(
    process: &mut Process,
    path: Term,
    map: Term,
    map_size: usize,
    list_mode: bool,
    acc: Term,
) -> Result<Term, Trap> {
    let mut elems = chunk_len(process.reductions, map_size);
    let digits = path_digits(path)?;
    if digits.is_zero_small && elems > MAP_SMALL_MAP_LIMIT {
        elems = MAP_SMALL_MAP_LIMIT;
    }

    // Look for the leaf to start at, pushing each node on the way.
    let mut stack = WStack::new();
    let mut cur = NodeCursor::new(map)?;
    let mut curr_path = digits.get(0);
    let mut digit = 0usize;
    let mut level = 1usize;
    let mut idx;
    loop {
        let elem = (curr_path & 0xf) as usize;
        idx = if list_mode {
            cur.sz.wrapping_sub(1).wrapping_sub(elem)
        } else {
            elem
        };
        if idx >= cur.sz {
            return Err(badarg());
        }
        let word = cur.word(idx);
        if is_leaf_word(word) {
            break;
        }
        stack
            .push(Frame {
                node: cur.node,
                idx: if list_mode {
                    idx.wrapping_sub(1)
                } else {
                    idx + 1
                },
                sz: cur.sz,
                ptr: cur.ptr,
            })
            .map_err(|_| system_limit())?;
        // SAFETY: a non-leaf child word of a live HAMT node is a boxed node term.
        cur = NodeCursor::new(unsafe { Term::from_raw_bits(word) })?;
        curr_path >>= PATH_ELEM_SIZE;
        if level == PATH_ELEMS_PER_DIGIT {
            level = 0;
            digit += 1;
            curr_path = digits.get(digit);
        }
        level += 1;
    }

    // Iterator terms are {K,V,Next} (4 words), list terms a pair plus a cons cell (5 words).
    let words_per_elem = if list_mode { 5 } else { 4 };
    let orig_elems = elems;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut region =
        HeapReservation::new(&mut heap, words_per_elem * elems).map_err(|_| system_limit())?;
    let mut chain = Tuple3Chain::new();
    let mut res = acc;
    let enc = |idx: usize| {
        if list_mode {
            idx.wrapping_sub(1)
        } else {
            idx + 1
        }
    };
    loop {
        // A collision node must not be split: the 4-bit path cannot address it.
        let at_start = if list_mode {
            idx == cur.sz - 1
        } else {
            idx == 0
        };
        if at_start && elems < cur.sz && cur.is_collision() {
            elems = cur.sz;
            region
                .regrow(words_per_elem * elems)
                .map_err(|_| system_limit())?;
        }
        if list_mode {
            let mut sidx = idx as isize;
            while sidx >= 0 && elems != 0 {
                let word = cur.word(sidx as usize);
                if !is_leaf_word(word) {
                    break;
                }
                let (key, value) = leaf_pair(word);
                res = arinsal_maps::cons_pair(&mut region, key, value, res)
                    .map_err(|_| system_limit())?;
                elems -= 1;
                sidx -= 1;
            }
            idx = sidx as usize;
        } else {
            while idx < cur.sz && elems != 0 {
                let word = cur.word(idx);
                if !is_leaf_word(word) {
                    break;
                }
                let (key, value) = leaf_pair(word);
                TermBuilder::new(&mut region)
                    .chain3_push(&mut chain, key, value)
                    .map_err(|_| system_limit())?;
                elems -= 1;
                idx += 1;
            }
        }
        if elems == 0 {
            if idx < cur.sz {
                // More elements in this node.
                stack
                    .push(Frame {
                        node: cur.node,
                        idx: enc(idx),
                        sz: cur.sz,
                        ptr: cur.ptr,
                    })
                    .map_err(|_| system_limit())?;
            } else {
                // Pop to find the next value.
                while let Some(f) = stack.pop() {
                    if f.idx < f.sz {
                        stack
                            .push(Frame {
                                idx: enc(f.idx),
                                ..f
                            })
                            .map_err(|_| system_limit())?;
                        break;
                    }
                }
            }
            break;
        } else if idx < cur.sz {
            stack
                .push(Frame {
                    node: cur.node,
                    idx: enc(idx),
                    sz: cur.sz,
                    ptr: cur.ptr,
                })
                .map_err(|_| system_limit())?;
            // SAFETY: `idx < sz` and the word is not a leaf, so it is a boxed node term.
            cur = NodeCursor::new(unsafe { Term::from_raw_bits(cur.word(idx)) })?;
            idx = if list_mode { cur.sz - 1 } else { 0 };
        } else if let Some(f) = stack.pop() {
            cur = NodeCursor {
                node: f.node,
                sz: f.sz,
                ptr: f.ptr,
            };
            idx = f.idx;
        } else {
            break;
        }
    }

    if !stack.is_empty() {
        // Port of erts/emulator/beam/erl_map.c:4121-4124: HRelease is only called when
        // the traversal stack is empty; otherwise the reservation remains consumed.
        region.set_cursor(region.limit());
    }
    drop(region);
    let mut builder = TermBuilder::new(&mut heap);
    let result = if !stack.is_empty() {
        // Pop the stack to create the complete path to the next leaf.
        let mut depth = stack.len() + 1;
        let mut big = [0u64; 3];
        let big_len = (depth * PATH_ELEM_SIZE as usize).div_ceil(64);
        let use_big = depth >= PATH_ELEMS_PER_DIGIT;
        let mut slot = big_len;
        let mut path_word = 0u64;
        while let Some(f) = stack.pop() {
            let path_elem = if list_mode {
                f.sz - 1 - f.idx.wrapping_add(1)
            } else {
                f.idx - 1
            };
            depth -= 1;
            if depth.is_multiple_of(PATH_ELEMS_PER_DIGIT) {
                slot -= 1;
                big[slot] = path_word;
                path_word = 0;
            }
            path_word = (path_word << PATH_ELEM_SIZE) | path_elem as u64;
        }
        let path = if use_big {
            slot -= 1;
            big[slot] = path_word;
            builder.pos_bignum_from_digits(&big[slot..big_len])
        } else {
            builder.int_from_u64(path_word)
        }
        .map_err(|_| system_limit())?;
        if list_mode {
            res = builder.cons(map, res).map_err(|_| system_limit())?;
            builder.cons(path, res).map_err(|_| system_limit())?
        } else {
            let next = builder.cons(path, map).map_err(|_| system_limit())?;
            chain.finish(next)
        }
    } else if list_mode {
        res
    } else {
        chain.finish(NONE)
    };
    process.reductions -= (4 * (orig_elems as i64 - elems as i64)) as i32;
    Ok(result)
}

/// Port of erts/emulator/beam/erl_map.c:3709-3738 (flatmap branch), OTP-29.1.1.
#[inline(always)]
fn flat_next(
    process: &mut Process,
    path: Term,
    map: arinsal_maps::CheckedFlatMap,
    list_mode: bool,
    acc: Term,
) -> Result<Term, Trap> {
    let n = map.size();
    // `n < unsigned_val(path)` is badarg; a negative small is a huge unsigned value.
    let Some(index) = path.as_small().filter(|value| *value >= 0) else {
        return Err(badarg());
    };
    if (n as i64) < index {
        return Err(badarg());
    }
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    arinsal_maps::flatmap_next_checked(map, n, list_mode, acc, &mut heap)
        .map_err(|_| system_limit())
}

/// Port of erts/emulator/beam/erl_map.c:3655-3706, OTP-29.1.1.
fn ordered_next(
    process: &mut Process,
    mut path: Term,
    map: arinsal_maps::CheckedMap,
) -> Result<Term, Trap> {
    let orig_elems = (process.reductions / ORDERED_ITER_FACTOR).max(1) as usize;
    let mut elems = orig_elems;
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut region = HeapReservation::new(&mut heap, 4 * elems + 2).map_err(|_| system_limit())?;
    let mut builder = TermBuilder::new(&mut region);
    let mut chain = Tuple3Chain::new();
    while elems > 0 {
        if path.classify() != TermKind::List {
            break;
        }
        // SAFETY: the iterator path is a list on the live heap.
        let (key, tail) = unsafe { path.cons_ref() }.ok_or_else(badarg)?;
        let value = map.get(key).ok_or_else(badarg)?;
        builder
            .chain3_push(&mut chain, key, value)
            .map_err(|_| system_limit())?;
        path = tail;
        elems -= 1;
    }
    if path.classify() == TermKind::List {
        let next = builder.cons(path, map.term()).map_err(|_| system_limit())?;
        process.reductions = 0;
        Ok(chain.finish(next))
    } else if path == Term::NIL {
        process.reductions = process
            .reductions
            .saturating_sub(ORDERED_ITER_FACTOR * (orig_elems - elems) as i32);
        Ok(chain.finish(NONE))
    } else {
        Err(badarg())
    }
}

/// `erts_internal:map_next/3`.
/// Port of erts/emulator/beam/erl_map.c:3636 (erts_internal_map_next_3), OTP-29.1.1.
fn map_next(process: &mut Process, args: &[Term]) -> Result<Term, Trap> {
    if let Some((path, flat, list_mode, mode)) = flatmap_step(args) {
        return flat_next(process, path, flat, list_mode, mode);
    }
    map_next_general(process, args)
}

/// The hot case: a small path over a flatmap, in iterator mode or in list mode (`mode` is
/// the accumulator list). The flag tells which.
#[inline(always)]
fn flatmap_step(args: &[Term]) -> Option<(Term, arinsal_maps::CheckedFlatMap, bool, Term)> {
    if let &[path, map, mode] = args
        && path.as_small().is_some()
        && let Ok(checked) = arinsal_maps::checked_map(map)
        && let arinsal_maps::CheckedMapKind::Flatmap(flat) = checked.kind()
    {
        if mode == ITERATOR {
            return Some((path, flat, false, mode));
        }
        if mode == Term::NIL || mode.classify() == TermKind::List {
            return Some((path, flat, true, mode));
        }
    }
    None
}

#[inline(never)]
fn map_next_general(process: &mut Process, args: &[Term]) -> Result<Term, Trap> {
    if args.len() != 3 {
        return Err(badarg());
    }
    let path = args[0];
    let map = arinsal_maps::checked_map(args[1]).map_err(|_| badarg())?;
    let mode = args[2];
    let iterator = mode == ITERATOR;
    let list_mode = !iterator && (mode == Term::NIL || mode.classify() == TermKind::List);
    if !iterator && !list_mode {
        return Err(badarg());
    }
    if iterator && (path.classify() == TermKind::List || path == Term::NIL) {
        return ordered_next(process, path, map);
    }
    match map.kind() {
        arinsal_maps::CheckedMapKind::Hashmap(map) => {
            hamt_next(process, path, map.term(), map.size(), list_mode, mode)
        }
        arinsal_maps::CheckedMapKind::Flatmap(map) => {
            flat_next(process, path, map, list_mode, mode)
        }
    }
}

/// Dispatch map primitives that require allocation in the calling process.
/// Map iteration BIFs. `handler` is this table.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[("erts_internal", "map_next", 3)];

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

type Handler =
    fn(&mut Vm, &mut Process, &mut RunCtx<'_, Message>, &[Term]) -> Result<Term, VmError>;

pub(crate) fn handler(module: &str, function: &str, arity: u8) -> Option<Handler> {
    match (module, function, arity) {
        ("erts_internal", "map_next", 3) => Some(call_map_next),
        _ => None,
    }
}

/// The process BIF behind `module:function/arity`, which native code calls like any light BIF.
pub(crate) fn process_bif(module: &str, function: &str, arity: u8) -> Option<super::ProcessBif> {
    match (module, function, arity) {
        ("erts_internal", "map_next", 3) => Some(map_next_process_bif),
        _ => None,
    }
}

/// The light-BIF call site entry for `erts_internal:map_next/3`.
pub(crate) fn thin_entry(module: &str, function: &str, arity: u8) -> Option<usize> {
    match (module, function, arity) {
        ("erts_internal", "map_next", 3) => Some(map_next_light as *const () as usize),
        _ => None,
    }
}

/// The light-BIF entry of `erts_internal:map_next/3`.
///
/// The flatmap step allocates its result on `c_p->htop` and returns it, as
/// erts does: it reads no reduction counter and converts no heap cursor. Every other call
/// takes the generic light-BIF path.
// Port of erts/emulator/beam/erl_map.c (erts_internal_map_next_3, flatmap branch: HAlloc on
// c_p->htop), OTP-29.1.1.
extern "C" fn map_next_light(
    header: *mut arinsal_beamasm::ProcessHeader,
    regs: *mut u64,
    i: u64,
    descriptor: u64,
    identity: u64,
) -> u64 {
    if let Some(raw) = map_next_native(header) {
        return raw;
    }
    crate::native_helpers::thin_bif_light::<MapNext>(header, regs, i, descriptor, identity)
}

#[inline(always)]
fn map_next_native(header: *mut arinsal_beamasm::ProcessHeader) -> Option<u64> {
    let (process, registers) = crate::native_hooks::enter_runtime_no_cursors(header)?;
    let (path, flat, list_mode, mode) = flatmap_step(&registers.x_reg_array[..3])?;
    let n = flat.size();
    if path.as_small().filter(|index| *index >= 0)? > n as i64 {
        return None;
    }
    let mut top = crate::native_top_heap::NativeTopHeap::new(process)?;
    let words = if list_mode { 5 * n } else { 4 * n };
    if arinsal_term::HeapAlloc::words_left(&top)? < words {
        return None;
    }
    let term = arinsal_maps::flatmap_next_checked(flat, n, list_mode, mode, &mut top).ok()?;
    registers.x_reg_array[0] = term;
    Some(crate::native_hooks::raw(term))
}

/// `erts_internal:map_next/3` for the light-BIF call site.
// Port of erts/emulator/beam/erl_map.c:3636 (erts_internal_map_next_3), OTP-29.1.1.
pub(crate) struct MapNext;

impl super::ThinProcessBif for MapNext {
    const ARITY: usize = 3;

    #[inline(always)]
    fn call(process: &mut Process, args: &[Term]) -> Result<Term, Box<Trap>> {
        if let Some((path, flat, list_mode, mode)) = flatmap_step(args) {
            return flat_next(process, path, flat, list_mode, mode).map_err(Box::new);
        }
        map_next_general(process, args).map_err(Box::new)
    }
}

// Port of erts/emulator/beam/erl_map.c:3636 (erts_internal_map_next_3), OTP-29.1.1.
fn map_next_process_bif(
    process: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    Some(map_next(process, args))
}

fn call_map_next(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    map_next(process, args).map_err(VmError::Trap)
}

pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    handler(module, function, args.len() as u8).map(|handle| handle(vm, process, ctx, args))
}

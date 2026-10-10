//! Map iterator primitives used by the OTP maps module.

use crate::exceptions::Trap;
use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_sched::RunCtx;
use arinsal_term::{HeapReservation, Term, TermBuilder, TermKind, Tuple3Chain, global_atoms};

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

/// The `iterator` and `none` atoms, interned once instead of hashed on every call.
fn iterator_atom() -> Term {
    static ATOM: std::sync::OnceLock<Term> = std::sync::OnceLock::new();
    *ATOM.get_or_init(|| atom("iterator"))
}

fn none_atom() -> Term {
    static ATOM: std::sync::OnceLock<Term> = std::sync::OnceLock::new();
    *ATOM.get_or_init(|| atom("none"))
}

fn badarg() -> Trap {
    Trap::error(atom("badarg"))
}

fn system_limit() -> Trap {
    Trap::error(atom("system_limit"))
}

/// Deepest HAMT path the stack can hold: two path digits of `PATH_ELEMS_PER_DIGIT` levels.
/// Reaching it would need 128 equal hash bits; erts uses a growable WSTACK instead.
const MAX_HAMT_DEPTH: usize = 2 * PATH_ELEMS_PER_DIGIT;

/// One WSTACK_PUSH4 entry: the node and its `idx`, `sz` and `ptr` (the node is only a debug aid
/// in erts and is not kept; `collision` replaces re-reading its header).
#[derive(Clone, Copy)]
struct Frame {
    ptr: *const u64,
    idx: usize,
    sz: usize,
    collision: bool,
}

impl Frame {
    const EMPTY: Self = Self {
        ptr: std::ptr::null(),
        idx: 0,
        sz: 0,
        collision: false,
    };
}

/// A decoded HAMT node: `sz` children starting at `ptr`.
/// Port of erts/emulator/beam/erl_map.c:2313-2335 (hashmap_node_size), OTP-29.1.1.
#[derive(Clone, Copy)]
struct NodeCursor {
    sz: usize,
    ptr: *const u64,
    collision: bool,
}

impl NodeCursor {
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
        Ok(Self { sz, ptr, collision })
    }

    /// Read child word `idx` (`ptr[idx]`).
    #[inline(always)]
    fn word(self, idx: usize) -> u64 {
        assert!(idx < self.sz);
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
    list_mode: bool,
    acc: Term,
) -> Result<Term, Trap> {
    let map_size = arinsal_maps::size(map).map_err(|_| badarg())?;
    let mut elems = chunk_len(process.reductions, map_size);
    let digits = path_digits(path)?;
    if digits.is_zero_small && elems > MAP_SMALL_MAP_LIMIT {
        elems = MAP_SMALL_MAP_LIMIT;
    }

    // Look for the leaf to start at, pushing each node on the way.
    let mut stack = [Frame::EMPTY; MAX_HAMT_DEPTH];
    let mut top = 0usize;
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
        if top == MAX_HAMT_DEPTH {
            return Err(system_limit());
        }
        stack[top] = Frame {
            ptr: cur.ptr,
            idx: if list_mode {
                idx.wrapping_sub(1)
            } else {
                idx + 1
            },
            sz: cur.sz,
            collision: cur.collision,
        };
        top += 1;
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
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
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
        if at_start && elems < cur.sz && cur.collision {
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
                stack[top] = Frame {
                    ptr: cur.ptr,
                    idx: enc(idx),
                    sz: cur.sz,
                    collision: cur.collision,
                };
                top += 1;
            } else {
                // Pop to find the next value.
                while top > 0 {
                    top -= 1;
                    let f = stack[top];
                    if f.idx < f.sz {
                        stack[top].idx = enc(f.idx);
                        top += 1;
                        break;
                    }
                }
            }
            break;
        } else if idx < cur.sz {
            if top == MAX_HAMT_DEPTH {
                return Err(system_limit());
            }
            stack[top] = Frame {
                ptr: cur.ptr,
                idx: enc(idx),
                sz: cur.sz,
                collision: cur.collision,
            };
            top += 1;
            // SAFETY: `idx < sz` and the word is not a leaf, so it is a boxed node term.
            cur = NodeCursor::new(unsafe { Term::from_raw_bits(cur.word(idx)) })?;
            idx = if list_mode { cur.sz - 1 } else { 0 };
        } else if top > 0 {
            top -= 1;
            let f = stack[top];
            cur = NodeCursor {
                sz: f.sz,
                ptr: f.ptr,
                collision: f.collision,
            };
            idx = f.idx;
        } else {
            break;
        }
    }

    drop(region);
    let mut builder = TermBuilder::new(&mut heap);
    let result = if top > 0 {
        // Pop the stack to create the complete path to the next leaf.
        let mut depth = top + 1;
        let mut big = [0u64; 3];
        let big_len = (depth * PATH_ELEM_SIZE as usize).div_ceil(64);
        let use_big = depth >= PATH_ELEMS_PER_DIGIT;
        let mut slot = big_len;
        let mut path_word = 0u64;
        while top > 0 {
            top -= 1;
            let f = stack[top];
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
        chain.finish(none_atom())
    };
    process.reductions -= (4 * (orig_elems as i64 - elems as i64)) as i32;
    Ok(result)
}

/// Port of erts/emulator/beam/erl_map.c:3709-3738 (flatmap branch), OTP-29.1.1.
fn flat_next(
    process: &mut Process,
    path: Term,
    map: Term,
    list_mode: bool,
    acc: Term,
) -> Result<Term, Trap> {
    let n = arinsal_maps::size(map).map_err(|_| badarg())?;
    // `n < unsigned_val(path)` is badarg; a negative small is a huge unsigned value.
    let Some(index) = path.as_small().filter(|value| *value >= 0) else {
        return Err(badarg());
    };
    if (n as i64) < index {
        return Err(badarg());
    }
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    arinsal_maps::flatmap_next(map, list_mode, acc, &mut heap).map_err(|_| system_limit())
}

/// Port of erts/emulator/beam/erl_map.c:3655-3706, OTP-29.1.1.
fn ordered_next(process: &mut Process, mut path: Term, map: Term) -> Result<Term, Trap> {
    let orig_elems = (process.reductions / ORDERED_ITER_FACTOR).max(1) as usize;
    let mut elems = orig_elems;
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut region = HeapReservation::new(&mut heap, 4 * elems + 2).map_err(|_| system_limit())?;
    let mut builder = TermBuilder::new(&mut region);
    let mut chain = Tuple3Chain::new();
    while elems > 0 {
        if path.classify() != TermKind::List {
            break;
        }
        // SAFETY: the iterator path is a list on the live heap.
        let (key, tail) = unsafe { path.cons_ref() }.ok_or_else(badarg)?;
        let value = arinsal_maps::get(map, key)
            .map_err(|_| badarg())?
            .ok_or_else(badarg)?;
        builder
            .chain3_push(&mut chain, key, value)
            .map_err(|_| system_limit())?;
        path = tail;
        elems -= 1;
    }
    if path.classify() == TermKind::List {
        let next = builder.cons(path, map).map_err(|_| system_limit())?;
        process.reductions = 0;
        Ok(chain.finish(next))
    } else if path == Term::NIL {
        process.reductions = process
            .reductions
            .saturating_sub(ORDERED_ITER_FACTOR * (orig_elems - elems) as i32);
        Ok(chain.finish(none_atom()))
    } else {
        Err(badarg())
    }
}

/// `erts_internal:map_next/3`.
/// Port of erts/emulator/beam/erl_map.c:3636 (erts_internal_map_next_3), OTP-29.1.1.
fn map_next(process: &mut Process, args: &[Term]) -> Result<Term, Trap> {
    if args.len() != 3 {
        return Err(badarg());
    }
    let path = args[0];
    let map = args[1];
    let mode = args[2];
    if map.classify() != TermKind::Map {
        return Err(badarg());
    }
    let iterator = mode == iterator_atom();
    let list_mode = mode == Term::NIL || mode.classify() == TermKind::List;
    if !iterator && !list_mode {
        return Err(badarg());
    }
    if iterator && (path.classify() == TermKind::List || path == Term::NIL) {
        return ordered_next(process, path, map);
    }
    if map.is_hashmap() {
        hamt_next(process, path, map, list_mode, mode)
    } else {
        flat_next(process, path, map, list_mode, mode)
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
        ("erts_internal", "map_next", 3) => Some(map_next),
        _ => None,
    }
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

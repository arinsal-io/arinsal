//! Map iterator primitives used by the OTP maps module.

use crate::process::Message;
use crate::{Process, Vm, VmError, exceptions};
use arinsal_sched::RunCtx;
use arinsal_term::{Term, TermBuilder, TermKind, global_atoms};
use num_bigint::BigInt;

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

fn badarg() -> VmError {
    VmError::Trap(exceptions::Trap::error(atom("badarg")))
}

fn system_limit() -> VmError {
    VmError::Trap(exceptions::Trap::error(atom("system_limit")))
}

fn word_term(word: u64) -> Term {
    // SAFETY: `Term` is a transparent tagged word read from a live map node.
    unsafe { std::mem::transmute::<u64, Term>(word) }
}

fn is_leaf(term: Term) -> bool {
    term.classify() == TermKind::List
}

fn is_collision(node: Term) -> bool {
    node.header().is_some_and(|header| header & 63 == 0)
}

fn leaf_pair(term: Term) -> Result<(Term, Term), VmError> {
    // SAFETY: `term` is a live HAMT leaf cons; the map heap stays stable for this call.
    unsafe { term.cons_ref() }.ok_or_else(badarg)
}

/// Dense child array of a HAMT node, in slot order.
/// Port of erts/emulator/beam/erl_map.c:2312 (hashmap_node_size), OTP-29.1.1.
fn hamt_children(node: Term) -> Result<Vec<Term>, VmError> {
    let header = node.header().ok_or_else(badarg)?;
    // SAFETY: `header()` only succeeds for a boxed term whose heap remains stable.
    unsafe {
        let base = node.raw_ptr();
        if header & 63 == 0 {
            let count = (header >> 6) as usize;
            let mut children = Vec::with_capacity(count);
            for index in 0..count {
                children.push(word_term(*base.add(1 + index)));
            }
            return Ok(children);
        }
        if !node.is_hashmap() {
            return Err(badarg());
        }
        let bitmap = ((header >> 16) & 0xffff) as u16;
        // Root nodes (subtag >= 2) store a size word before the children.
        let offset = if (header >> 6) & 3 >= 2 { 2 } else { 1 };
        let mut children = Vec::with_capacity(bitmap.count_ones() as usize);
        let mut slot = 0usize;
        for index in 0..16 {
            if bitmap & (1 << index) != 0 {
                children.push(word_term(*base.add(offset + slot)));
                slot += 1;
            }
        }
        Ok(children)
    }
}

/// Little-endian path digits. Negative and non-integer paths are `badarg`.
/// Port of erts/emulator/beam/erl_map.c:3796-3810, OTP-29.1.1.
fn path_digits(path: Term) -> Result<Vec<u64>, VmError> {
    if let Some(value) = path.as_small() {
        return (value >= 0)
            .then_some(vec![value as u64])
            .ok_or_else(badarg);
    }
    // SAFETY: `big_ref` borrows a live bignum for this call.
    let Some(big) = (unsafe { path.big_ref() }) else {
        return Err(badarg());
    };
    if big.is_negative() {
        return Err(badarg());
    }
    Ok(big.digits().to_vec())
}

struct Frame {
    node: Term,
    /// Next index, stored with the same adjustment `erts_internal_map_next_3` pushes.
    idx: u64,
    sz: u64,
}

struct Cursor {
    node: Term,
    idx: u64,
    sz: u64,
    kids: Vec<Term>,
}

type Chunk = (Vec<(Term, Term)>, Vec<Frame>);

/// Walk `path` until the first leaf, recording parent frames.
/// Port of erts/emulator/beam/erl_map.c:3821-3866, OTP-29.1.1.
fn descend(map: Term, digits: &[u64], list_mode: bool) -> Result<(Cursor, Vec<Frame>), VmError> {
    let mut digit_at = 0usize;
    let mut curr = digits.first().copied().unwrap_or(0);
    let mut level = 1u32;
    let mut node = map;
    let mut stack = Vec::new();
    loop {
        if stack.len() > 64 {
            return Err(badarg());
        }
        let kids = hamt_children(node)?;
        let sz = kids.len() as u64;
        let elem = curr & 0xf;
        let idx = if list_mode {
            sz.wrapping_sub(1).wrapping_sub(elem)
        } else {
            elem
        };
        if idx >= sz {
            return Err(badarg());
        }
        let child = kids[idx as usize];
        if is_leaf(child) {
            return Ok((
                Cursor {
                    node,
                    idx,
                    sz,
                    kids,
                },
                stack,
            ));
        }
        let stored = if list_mode {
            idx.wrapping_sub(1)
        } else {
            idx.wrapping_add(1)
        };
        stack.push(Frame {
            node,
            idx: stored,
            sz,
        });
        node = child;
        curr >>= PATH_ELEM_SIZE;
        if level == PATH_ELEMS_PER_DIGIT as u32 {
            level = 0;
            digit_at += 1;
            curr = digits.get(digit_at).copied().unwrap_or(0);
        }
        level += 1;
    }
}

fn cursor_from(frame: Frame) -> Result<Cursor, VmError> {
    let kids = hamt_children(frame.node)?;
    Ok(Cursor {
        node: frame.node,
        idx: frame.idx,
        sz: kids.len() as u64,
        kids,
    })
}

/// Emit at most `elems` pairs. The stack left behind is the continuation path.
/// Port of erts/emulator/beam/erl_map.c:3893-4056, OTP-29.1.1.
fn take_chunk(
    mut cursor: Cursor,
    mut stack: Vec<Frame>,
    mut elems: u64,
    list_mode: bool,
) -> Result<Chunk, VmError> {
    let mut emitted = Vec::new();
    let mut steps = 0usize;
    loop {
        steps += 1;
        if steps > 100_000 {
            return Err(VmError::Unsupported("map_next did not terminate".into()));
        }
        if list_mode {
            if cursor.idx == cursor.sz.wrapping_sub(1)
                && elems < cursor.sz
                && is_collision(cursor.node)
            {
                elems = cursor.sz;
            }
            let mut sidx = cursor.idx as i64;
            while sidx >= 0 && elems != 0 && is_leaf(cursor.kids[sidx as usize]) {
                emitted.push(leaf_pair(cursor.kids[sidx as usize])?);
                elems -= 1;
                sidx -= 1;
            }
            cursor.idx = sidx as u64;
            if elems == 0 {
                if cursor.idx < cursor.sz {
                    stack.push(Frame {
                        node: cursor.node,
                        idx: cursor.idx.wrapping_sub(1),
                        sz: cursor.sz,
                    });
                } else {
                    while let Some(frame) = stack.pop() {
                        if frame.idx < frame.sz {
                            stack.push(Frame {
                                node: frame.node,
                                idx: frame.idx.wrapping_sub(1),
                                sz: frame.sz,
                            });
                            break;
                        }
                    }
                }
                break;
            } else if cursor.idx < cursor.sz {
                let child = cursor.kids[cursor.idx as usize];
                stack.push(Frame {
                    node: cursor.node,
                    idx: cursor.idx.wrapping_sub(1),
                    sz: cursor.sz,
                });
                let kids = hamt_children(child)?;
                let sz = kids.len() as u64;
                cursor = Cursor {
                    node: child,
                    idx: sz.wrapping_sub(1),
                    sz,
                    kids,
                };
            } else if let Some(frame) = stack.pop() {
                cursor = cursor_from(frame)?;
            } else {
                break;
            }
        } else {
            if cursor.idx == 0 && elems < cursor.sz && is_collision(cursor.node) {
                elems = cursor.sz;
            }
            while cursor.idx < cursor.sz && elems != 0 && is_leaf(cursor.kids[cursor.idx as usize])
            {
                emitted.push(leaf_pair(cursor.kids[cursor.idx as usize])?);
                elems -= 1;
                cursor.idx += 1;
            }
            if elems == 0 {
                if cursor.idx < cursor.sz {
                    stack.push(Frame {
                        node: cursor.node,
                        idx: cursor.idx.wrapping_add(1),
                        sz: cursor.sz,
                    });
                } else {
                    while let Some(frame) = stack.pop() {
                        if frame.idx < frame.sz {
                            stack.push(Frame {
                                node: frame.node,
                                idx: frame.idx.wrapping_add(1),
                                sz: frame.sz,
                            });
                            break;
                        }
                    }
                }
                break;
            } else if cursor.idx < cursor.sz {
                let child = cursor.kids[cursor.idx as usize];
                stack.push(Frame {
                    node: cursor.node,
                    idx: cursor.idx.wrapping_add(1),
                    sz: cursor.sz,
                });
                let kids = hamt_children(child)?;
                cursor = Cursor {
                    node: child,
                    idx: 0,
                    sz: kids.len() as u64,
                    kids,
                };
            } else if let Some(frame) = stack.pop() {
                cursor = cursor_from(frame)?;
            } else {
                break;
            }
        }
    }
    Ok((emitted, stack))
}

/// Port of erts/emulator/beam/erl_map.c:4058-4120, OTP-29.1.1.
fn encode_path(stack: &[Frame], list_mode: bool) -> BigInt {
    let mut depth = stack.len() + 1;
    let mut curr = 0u64;
    let mut high_digits = Vec::new();
    for frame in stack.iter().rev() {
        let interest = if list_mode {
            frame.idx.wrapping_add(1)
        } else {
            frame.idx.wrapping_sub(1)
        };
        let path_elem = if list_mode {
            frame.sz.wrapping_sub(1).wrapping_sub(interest)
        } else {
            interest
        };
        depth -= 1;
        if depth.is_multiple_of(PATH_ELEMS_PER_DIGIT) {
            high_digits.push(curr);
            curr = 0;
        }
        curr = (curr << PATH_ELEM_SIZE) | (path_elem & 0xf);
    }
    let mut value = BigInt::from(curr);
    for (index, digit) in high_digits.iter().rev().enumerate() {
        if *digit != 0 {
            value |= BigInt::from(*digit) << (64 * (index + 1));
        }
    }
    value
}

fn chunk_len(reductions: i32, map_size: usize, path_is_zero: bool) -> u64 {
    // Port of erts/emulator/beam/erl_map.c:3783-3801 (FCALLS_ELEMS), OTP-29.1.1.
    let by_reds = ((reductions.max(0) as usize) / 4).max(1);
    let mut elems = if by_reds < map_size {
        by_reds
    } else {
        map_size
    };
    if path_is_zero && elems > MAP_SMALL_MAP_LIMIT {
        elems = MAP_SMALL_MAP_LIMIT;
    }
    elems as u64
}

fn hamt_next(
    process: &mut Process,
    path: Term,
    map: Term,
    list_mode: bool,
    acc: Term,
) -> Result<Term, VmError> {
    let digits = path_digits(path)?;
    let map_size = arinsal_maps::size(map).map_err(|_| badarg())?;
    let elems = chunk_len(process.reductions, map_size, path.as_small() == Some(0));
    let (cursor, stack) = descend(map, &digits, list_mode)?;
    let (emitted, stack) = take_chunk(cursor, stack, elems, list_mode)?;
    let charge = (4 * emitted.len()) as i32;
    if charge > 0 {
        process.reductions = (process.reductions - charge).max(1);
    }
    let mut builder = TermBuilder::new(&mut process.heap);
    if list_mode {
        let mut result = acc;
        for (key, value) in emitted {
            let pair = builder.tuple(&[key, value]).map_err(|_| system_limit())?;
            result = builder.cons(pair, result).map_err(|_| system_limit())?;
        }
        if !stack.is_empty() {
            let path = builder
                .int_from_bigint(&encode_path(&stack, true))
                .map_err(|_| system_limit())?;
            result = builder.cons(map, result).map_err(|_| system_limit())?;
            result = builder.cons(path, result).map_err(|_| system_limit())?;
        }
        return Ok(result);
    }
    let mut result = if stack.is_empty() {
        atom("none")
    } else {
        let path = builder
            .int_from_bigint(&encode_path(&stack, false))
            .map_err(|_| system_limit())?;
        builder.cons(path, map).map_err(|_| system_limit())?
    };
    for (key, value) in emitted.into_iter().rev() {
        result = builder
            .tuple(&[key, value, result])
            .map_err(|_| system_limit())?;
    }
    Ok(result)
}

fn flat_next(
    process: &mut Process,
    path: Term,
    map: Term,
    list_mode: bool,
    acc: Term,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/erl_map.c:3709-3738, OTP-29.1.1.
    let n = arinsal_maps::size(map).map_err(|_| badarg())?;
    let Some(index) = path.as_small().filter(|value| *value >= 0) else {
        return Err(badarg());
    };
    let Ok(index) = usize::try_from(index) else {
        return Err(badarg());
    };
    if index > n {
        return Err(badarg());
    }
    let entries = arinsal_maps::to_list(map).map_err(|_| badarg())?;
    let mut builder = TermBuilder::new(&mut process.heap);
    if list_mode {
        let mut result = acc;
        for (key, value) in entries.into_iter().rev() {
            let pair = builder.tuple(&[key, value]).map_err(|_| system_limit())?;
            result = builder.cons(pair, result).map_err(|_| system_limit())?;
        }
        return Ok(result);
    }
    let mut result = atom("none");
    for (key, value) in entries.into_iter().rev() {
        result = builder
            .tuple(&[key, value, result])
            .map_err(|_| system_limit())?;
    }
    Ok(result)
}

/// Port of erts/emulator/beam/erl_map.c:3655-3706, OTP-29.1.1.
fn ordered_next(process: &mut Process, mut path: Term, map: Term) -> Result<Term, VmError> {
    let chunk = (process.reductions / ORDERED_ITER_FACTOR).max(1) as usize;
    let mut entries = Vec::with_capacity(chunk);
    while path.classify() == TermKind::List && entries.len() < chunk {
        // SAFETY: the iterator path is a proper list rooted for this call.
        let (key, tail) = unsafe { path.cons_ref() }.ok_or_else(badarg)?;
        let value = arinsal_maps::get(map, key)
            .map_err(|_| badarg())?
            .ok_or_else(badarg)?;
        entries.push((key, value));
        path = tail;
    }
    if path != Term::NIL && path.classify() != TermKind::List {
        return Err(badarg());
    }
    if entries.is_empty() {
        return Ok(atom("none"));
    }
    let mut builder = TermBuilder::new(&mut process.heap);
    let mut result = if path == Term::NIL {
        atom("none")
    } else {
        builder.cons(path, map).map_err(|_| system_limit())?
    };
    for (key, value) in entries.into_iter().rev() {
        result = builder
            .tuple(&[key, value, result])
            .map_err(|_| system_limit())?;
    }
    Ok(result)
}

/// `erts_internal:map_next/3`.
/// Port of erts/emulator/beam/erl_map.c:3636 (erts_internal_map_next_3), OTP-29.1.1.
fn map_next(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    if args.len() != 3 {
        return Err(badarg());
    }
    let extra_words = arinsal_maps::size(args[1])
        .unwrap_or(0)
        .saturating_mul(8)
        .saturating_add(64);
    process.ensure(extra_words, args.len())?;
    let path = process.x[0];
    let map = process.x[1];
    let mode = process.x[2];
    if map.classify() != TermKind::Map {
        return Err(badarg());
    }
    let iterator = mode == atom("iterator");
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

fn call_map_next(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    map_next(process, args)
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

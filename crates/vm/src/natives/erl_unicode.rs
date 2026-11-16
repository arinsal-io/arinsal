//! `unicode:characters_to_binary/2` of erl_unicode.c.
//!
//! Port of erts/emulator/beam/erl_unicode.c (unicode_characters_to_binary_2, utf8_need,
//! do_build_utf8, copy_utf8_bin, build_utf8_return, characters_to_utf8_trap), OTP-29.1.1.
//! Each BIF is `bif_table[].f` with `(c_p, reg, I)`. A conversion that runs out of loop
//! iterations traps with `BIF_TRAP4` to the hidden `erlang:characters_to_utf8_trap/4` export,
//! the binary being filled (a private writer) and the rest of the input in its arguments.

use crate::Process;
use crate::natives::bif::{badarg, bif_ret};
use crate::natives::erl_bif_lists::bif_trap;
use crate::natives::erl_iolist::charge;
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::raw::{
    BinRef, Cons, allocate_iolist_binary, finish_iolist_binary_output, with_iolist_binary_output,
};
use arinsal_term::{EStack, HeapBinaryWriter, Term, TermBuilder, atoms};

/// `LOOP_FACTOR` and `LOOP_FACTOR_SIMPLE`.
const LOOP_FACTOR: i64 = 10;
const LOOP_FACTOR_SIMPLE: i64 = 50;
/// `ERL_ONHEAP_BINARY_LIMIT`.
const ERL_ONHEAP_BINARY_LIMIT: i64 = 64;

const CHARACTERS_TO_UTF8_TRAP: &str = "erlang:characters_to_utf8_trap/4";
const CHARACTERS_TO_BINARY_INT: &str = "unicode:characters_to_binary_int/2";

/// `allowed_iterations`.
// Port of erts/emulator/beam/erl_unicode.c (allowed_iterations), OTP-29.1.1.
fn allowed_iterations(process: &Process) -> i64 {
    let tmp = i64::from(process.heap.abi.fcalls.max(0)) * LOOP_FACTOR;
    let max_loop_limit = crate::natives::erts_debug::unicode_loop_limit() as i64;
    max_loop_limit.min(tmp)
}

/// `cost_to_proc`.
// Port of erts/emulator/beam/erl_unicode.c (cost_to_proc), OTP-29.1.1.
fn cost_to_proc(process: &mut Process, cost: i64) {
    charge(process, (cost / LOOP_FACTOR).max(0) as usize);
}

/// `simple_loops_to_common`.
fn simple_loops_to_common(cost: i64) -> i64 {
    cost / (LOOP_FACTOR_SIMPLE / LOOP_FACTOR)
}

/// The bytes of a byte-sized bitstring (`erts_get_aligned_binary_bytes`), copying when the
/// binary does not start on a byte boundary; `None` when its size is not a whole number of
/// bytes.
fn aligned_bytes(term: Term) -> Option<std::borrow::Cow<'static, [u8]>> {
    let view = BinRef::try_from(term).ok()?;
    if let Some(bytes) = view.bytes() {
        return Some(std::borrow::Cow::Borrowed(bytes));
    }
    let bits = view.bit_len();
    if !bits.is_multiple_of(8) {
        return None;
    }
    let mut copy = vec![0u8; bits / 8];
    arinsal_term::erl_bits::copy_bitstring_range(term, 0, &mut copy, bits).ok()?;
    Some(std::borrow::Cow::Owned(copy))
}

/// `aligned_binary_size`: the size of a byte-sized bitstring, -1 otherwise.
fn aligned_binary_size(term: Term) -> i64 {
    match BinRef::try_from(term) {
        Ok(view) if view.bit_len().is_multiple_of(8) => (view.bit_len() / 8) as i64,
        _ => -1,
    }
}

/// `latin1_binary_need`.
fn latin1_binary_need(term: Term) -> i64 {
    let Some(bytes) = aligned_bytes(term) else {
        return -1;
    };
    bytes
        .iter()
        .map(|&byte| if byte & 0x80 != 0 { 2 } else { 1 })
        .sum()
}

fn is_bitstring(term: Term) -> bool {
    BinRef::try_from(term).is_ok()
}

/// `utf8_len`.
fn utf8_len(first: u8) -> i32 {
    if first & 0x80 == 0 {
        1
    } else if first & 0xE0 == 0xC0 {
        2
    } else if first & 0xF0 == 0xE0 {
        3
    } else if first & 0xF8 == 0xF0 {
        4
    } else {
        -1
    }
}

/// What `copy_utf8_bin` reports besides the bytes copied: the position of the first invalid
/// byte of `source`, if any.
struct CopyResult {
    copied: usize,
    err_pos: Option<usize>,
}

/// `copy_utf8_bin`: copy the valid UTF-8 of `source` to `target`, holding back an incomplete
/// character at the end in `leftover` when one is given.
// Port of erts/emulator/beam/erl_unicode.c (copy_utf8_bin), OTP-29.1.1.
fn copy_utf8_bin(
    target: &mut [u8],
    source: &[u8],
    mut leftover: Option<(&mut [u8; 4], &mut usize)>,
    characters: &mut usize,
) -> CopyResult {
    let mut copied = 0usize;
    let mut at = 0usize;
    let mut size = source.len();
    if let Some((buffer, count)) = leftover.as_mut()
        && **count != 0
    {
        let need = utf8_len(buffer[0]);
        let from_source = need as usize - **count;
        if size < from_source {
            buffer[**count..**count + size].copy_from_slice(source);
            **count += size;
            return CopyResult {
                copied: 0,
                err_pos: None,
            };
        }
        buffer[**count..**count + from_source].copy_from_slice(&source[..from_source]);
        let assembled: [u8; 4] = **buffer;
        let result = copy_utf8_bin(
            &mut target[..need as usize],
            &assembled[..need as usize],
            None,
            characters,
        );
        if result.err_pos.is_some() {
            return CopyResult {
                copied: 0,
                err_pos: Some(0),
            };
        }
        copied += result.copied;
        **count = 0;
        size -= from_source;
        at += from_source;
    }
    let source = &source[at..];
    let mut s = 0usize;
    let mut t = copied;
    macro_rules! stop {
        () => {
            return CopyResult {
                copied: t,
                err_pos: Some(at + s),
            }
        };
    }
    while size > 0 {
        let byte = source[s];
        if byte & 0x80 == 0 {
            target[t] = byte;
            t += 1;
            s += 1;
            size -= 1;
        } else if byte & 0xE0 == 0xC0 {
            if let Some((buffer, count)) = leftover.as_mut()
                && size < 2
            {
                buffer[0] = byte;
                **count = 1;
                break;
            }
            if size < 2 || source[s + 1] & 0xC0 != 0x80 || byte < 0xC2 {
                stop!();
            }
            target[t..t + 2].copy_from_slice(&source[s..s + 2]);
            t += 2;
            s += 2;
            size -= 2;
        } else if byte & 0xF0 == 0xE0 {
            if let Some((buffer, count)) = leftover.as_mut()
                && size < 3
            {
                buffer[..size].copy_from_slice(&source[s..s + size]);
                **count = size;
                break;
            }
            if size < 3
                || source[s + 1] & 0xC0 != 0x80
                || source[s + 2] & 0xC0 != 0x80
                || (byte == 0xE0 && source[s + 1] < 0xA0)
            {
                stop!();
            }
            if byte & 0xF == 0xD && source[s + 1] & 0x20 != 0 {
                stop!();
            }
            target[t..t + 3].copy_from_slice(&source[s..s + 3]);
            t += 3;
            s += 3;
            size -= 3;
        } else if byte & 0xF8 == 0xF0 {
            if let Some((buffer, count)) = leftover.as_mut()
                && size < 4
            {
                buffer[..size].copy_from_slice(&source[s..s + size]);
                **count = size;
                break;
            }
            if size < 4
                || source[s + 1] & 0xC0 != 0x80
                || source[s + 2] & 0xC0 != 0x80
                || source[s + 3] & 0xC0 != 0x80
                || (byte == 0xF0 && source[s + 1] < 0x90)
            {
                stop!();
            }
            if byte & 0x7 > 0x4 || (byte & 0x7 == 0x4 && source[s + 1] & 0x3F > 0xF) {
                stop!();
            }
            target[t..t + 4].copy_from_slice(&source[s..s + 4]);
            t += 4;
            s += 4;
            size -= 4;
        } else {
            stop!();
        }
        *characters += 1;
    }
    CopyResult {
        copied: t,
        err_pos: None,
    }
}

/// `utf8_need`: the size of the UTF-8 (or Latin-1 turned UTF-8) result, -1 when the input is
/// not a chardata, and the cost in loop iterations.
// Port of erts/emulator/beam/erl_unicode.c (utf8_need), OTP-29.1.1.
fn utf8_need(ioterm: Term, latin1: bool) -> (i64, i64) {
    if ioterm == Term::NIL {
        return (0, 0);
    }
    if is_bitstring(ioterm) {
        return if latin1 {
            let x = latin1_binary_need(ioterm);
            (x, x)
        } else {
            (aligned_binary_size(ioterm), 1)
        };
    }
    if Cons::try_from(ioterm).is_err() {
        return (-1, 0);
    }
    let mut stack = EStack::<8>::new();
    let mut need = 0i64;
    let mut cost = 0i64;
    stack.push(ioterm);
    while let Some(mut ioterm) = stack.pop() {
        if ioterm == Term::NIL {
            continue;
        }
        if Cons::try_from(ioterm).is_ok() {
            'again: loop {
                let mut cell = Cons::try_from(ioterm).expect("a list cell");
                let mut obj = cell.head();
                loop {
                    if obj.as_small().is_some() {
                        loop {
                            let x = small_value(obj);
                            need += if x < 0x80 {
                                1
                            } else if x < 0x800 {
                                2
                            } else if x < 0x10000 {
                                3
                            } else {
                                4
                            };
                            cost += 1;
                            ioterm = cell.tail();
                            let Ok(next) = Cons::try_from(ioterm) else {
                                break;
                            };
                            cell = next;
                            obj = cell.head();
                            if obj.as_small().is_none() {
                                break;
                            }
                        }
                    } else if obj == Term::NIL {
                        ioterm = cell.tail();
                        let Ok(next) = Cons::try_from(ioterm) else {
                            break;
                        };
                        cell = next;
                        obj = cell.head();
                    } else if Cons::try_from(obj).is_ok() {
                        stack.push(cell.tail());
                        ioterm = obj;
                        continue 'again;
                    } else if is_bitstring(obj) {
                        let x = if latin1 {
                            let x = latin1_binary_need(obj);
                            if x < 0 {
                                return (x, cost);
                            }
                            cost += x;
                            x
                        } else {
                            let x = aligned_binary_size(obj);
                            if x < 0 {
                                return (x, cost);
                            }
                            cost += 1;
                            x
                        };
                        need += x;
                        ioterm = cell.tail();
                        if let Ok(next) = Cons::try_from(ioterm) {
                            cell = next;
                            obj = cell.head();
                        }
                    } else if is_bignum(obj) {
                        // An error that do_build_utf8 reports with the informative tuple.
                        return (need, cost);
                    } else {
                        return (-1, cost);
                    }
                    if ioterm == Term::NIL || Cons::try_from(ioterm).is_err() {
                        break;
                    }
                }
                break;
            }
        }
        if Cons::try_from(ioterm).is_err() && ioterm != Term::NIL {
            // Improper list end.
            if is_bitstring(ioterm) {
                let x = if latin1 {
                    let x = latin1_binary_need(ioterm);
                    if x < 0 {
                        return (x, cost);
                    }
                    cost += x;
                    x
                } else {
                    let x = aligned_binary_size(ioterm);
                    if x < 0 {
                        return (x, cost);
                    }
                    cost += 1;
                    x
                };
                need += x;
            } else {
                return (-1, cost);
            }
        }
    }
    (need, cost)
}

/// `unsigned_val` of a small integer; the caller checked the tag (a negative one becomes a
/// huge value that fails like any other invalid code point).
fn small_value(obj: Term) -> u64 {
    obj.as_small().unwrap_or(0) as u64
}

/// `is_big`.
fn is_bignum(term: Term) -> bool {
    term.header()
        .is_some_and(|header| matches!(header & 63, 0x10 | 0x14))
}

/// The state `do_build_utf8` threads through its recursion (`target`, `pos`, `characters`,
/// `left`, `err`, `leftover`, `num_leftovers`).
struct BuildState<'t> {
    target: &'t mut [u8],
    pos: usize,
    characters: usize,
    left: i64,
    err: bool,
    leftover: [u8; 4],
    num_leftovers: usize,
}

/// `CONS(hp, head, tail)` on the process heap.
fn cons(process: &mut Process, head: Term, tail: Term) -> Term {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .cons(head, tail)
        .expect("HAlloc")
}

/// `do_build_utf8`: convert `ioterm` into `state.target` until `state.left` runs out; returns
/// what is left of the input (`NIL` when all was converted).
// Port of erts/emulator/beam/erl_unicode.c (do_build_utf8), OTP-29.1.1.
fn do_build_utf8(
    process: &mut Process,
    ioterm: Term,
    state: &mut BuildState<'_>,
    latin1: bool,
) -> Term {
    let mut ioterm = ioterm;
    state.err = false;
    if state.left <= 0 || ioterm == Term::NIL {
        return ioterm;
    }
    if is_bitstring(ioterm) {
        let Some(bytes) = aligned_bytes(ioterm) else {
            state.err = true;
            return ioterm;
        };
        let orig_size = bytes.len();
        let mut size = orig_size;
        let mut res_term = Term::NIL;
        // Do not split a binary in the middle of a character.
        if !latin1 {
            while size as i64 > state.left
                && bytes
                    .get(state.left as usize)
                    .is_some_and(|byte| byte & 0xC0 == 0x80)
            {
                state.left += 1;
            }
        }
        if size as i64 > state.left {
            let left = state.left as usize;
            res_term = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
                .sub_binary(ioterm, left * 8, (size - left) * 8)
                .expect("HAlloc");
            size = left;
        }
        if !latin1 {
            let leftover = Some((&mut state.leftover, &mut state.num_leftovers));
            let result = copy_utf8_bin(
                &mut state.target[state.pos..],
                &bytes[..size],
                leftover,
                &mut state.characters,
            );
            state.pos += result.copied;
            if let Some(err_pos) = result.err_pos {
                state.err = true;
                // The rest of the binary from the first invalid byte.
                let rest_offset = err_pos;
                return TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
                    .sub_binary(ioterm, rest_offset * 8, (orig_size - rest_offset) * 8)
                    .expect("HAlloc");
            }
        } else {
            for &byte in &bytes[..size] {
                if byte < 0x80 {
                    state.target[state.pos] = byte;
                    state.pos += 1;
                } else {
                    state.target[state.pos] = (byte >> 6) | 0xC0;
                    state.target[state.pos + 1] = (byte & 0x3F) | 0x80;
                    state.pos += 2;
                }
                state.characters += 1;
            }
        }
        state.left -= size as i64;
        return res_term;
    }
    if Cons::try_from(ioterm).is_err() {
        state.err = true;
        return finish_stack(process, &mut EStack::<8>::new(), ioterm);
    }
    let mut stack = EStack::<8>::new();
    stack.push(ioterm);
    'outer: while state.left != 0 {
        let Some(popped) = stack.pop() else {
            break;
        };
        ioterm = popped;
        if ioterm == Term::NIL {
            continue;
        }
        if Cons::try_from(ioterm).is_ok() {
            'again: loop {
                let mut cell = Cons::try_from(ioterm).expect("a list cell");
                let mut obj = cell.head();
                loop {
                    if obj.as_small().is_some() {
                        if state.num_leftovers != 0 {
                            // Rest from a previous binary and now an integer: not allowed.
                            state.err = true;
                            break 'outer;
                        }
                        // The run of integers keeps its cursor and counters in locals, as the C
                        // function does, so the byte stores cannot force a reload of the state.
                        let mut pos = state.pos;
                        let mut characters = state.characters;
                        let mut left = state.left;
                        let target = &mut *state.target;
                        macro_rules! sync {
                            () => {{
                                state.pos = pos;
                                state.characters = characters;
                                state.left = left;
                            }};
                        }
                        loop {
                            let x = small_value(obj);
                            if latin1 && x > 255 {
                                sync!();
                                state.err = true;
                                break 'outer;
                            }
                            if x < 0x80 {
                                target[pos] = x as u8;
                                pos += 1;
                            } else if x < 0x800 {
                                target[pos] = (x >> 6) as u8 | 0xC0;
                                target[pos + 1] = (x & 0x3F) as u8 | 0x80;
                                pos += 2;
                            } else if x < 0x10000 {
                                if (0xD800..=0xDFFF).contains(&x) {
                                    sync!();
                                    state.err = true;
                                    break 'outer;
                                }
                                target[pos] = (x >> 12) as u8 | 0xE0;
                                target[pos + 1] = ((x >> 6) & 0x3F) as u8 | 0x80;
                                target[pos + 2] = (x & 0x3F) as u8 | 0x80;
                                pos += 3;
                            } else if x < 0x110000 {
                                target[pos] = (x >> 18) as u8 | 0xF0;
                                target[pos + 1] = ((x >> 12) & 0x3F) as u8 | 0x80;
                                target[pos + 2] = ((x >> 6) & 0x3F) as u8 | 0x80;
                                target[pos + 3] = (x & 0x3F) as u8 | 0x80;
                                pos += 4;
                            } else {
                                sync!();
                                state.err = true;
                                break 'outer;
                            }
                            characters += 1;
                            left -= 1;
                            ioterm = cell.tail();
                            let Ok(next) = Cons::try_from(ioterm) else {
                                break;
                            };
                            if left == 0 {
                                break;
                            }
                            cell = next;
                            obj = cell.head();
                            if obj.as_small().is_none() {
                                break;
                            }
                        }
                        sync!();
                    } else if obj == Term::NIL {
                        ioterm = cell.tail();
                        let Ok(next) = Cons::try_from(ioterm) else {
                            break;
                        };
                        cell = next;
                        obj = cell.head();
                    } else if Cons::try_from(obj).is_ok() {
                        stack.push(cell.tail());
                        ioterm = obj;
                        continue 'again;
                    } else if is_bitstring(obj) {
                        let rest_term = do_build_utf8(process, obj, state, latin1);
                        if state.err {
                            ioterm = cons(process, rest_term, cell.tail());
                            break 'outer;
                        }
                        if rest_term != Term::NIL {
                            ioterm = cons(process, rest_term, cell.tail());
                            state.left = 0;
                            break;
                        }
                        ioterm = cell.tail();
                        if let Ok(next) = Cons::try_from(ioterm) {
                            cell = next;
                            obj = cell.head();
                        }
                    } else {
                        state.err = true;
                        break 'outer;
                    }
                    if state.left == 0 || ioterm == Term::NIL || Cons::try_from(ioterm).is_err() {
                        break;
                    }
                }
                break;
            }
        }
        if state.left != 0 && Cons::try_from(ioterm).is_err() && ioterm != Term::NIL {
            // Improper list end.
            if is_bitstring(ioterm) {
                ioterm = do_build_utf8(process, ioterm, state, latin1);
                if state.err {
                    break;
                }
            } else {
                state.err = true;
                break;
            }
        }
    }
    finish_stack(process, &mut stack, ioterm)
}

/// The `done:` label of `do_build_utf8`: what is left of the stack becomes the tail of the
/// rest term.
fn finish_stack(process: &mut Process, stack: &mut EStack<8>, mut ioterm: Term) -> Term {
    while let Some(st) = stack.pop() {
        ioterm = cons(process, ioterm, st);
    }
    ioterm
}

/// `check_leftovers`: 0 when `leftover` is the start of a valid but incomplete character.
fn check_leftovers(source: &[u8]) -> i32 {
    let size = source.len();
    let first = source[0];
    if first & 0xE0 == 0xC0 {
        return 0;
    } else if first & 0xF0 == 0xE0 {
        if size < 2 || (size < 3 && source[1] & 0xC0 == 0x80) {
            return 0;
        }
    } else if first & 0xF8 == 0xF0
        && (size < 2
            || (size < 3 && source[1] & 0xC0 == 0x80)
            || (size < 4 && source[1] & 0xC0 == 0x80 && source[2] & 0xC0 == 0x80))
    {
        return 0;
    }
    -1
}

/// The result binary of a conversion: an on-heap binary for a result of at most 64 bytes
/// (`erts_new_binary`), else a private writer.
enum Output {
    Heap(HeapBinaryWriter),
    Writer(Term),
}

/// `mk_utf8_result_bin`: shrink the result to `pos` bytes and share it.
// Port of erts/emulator/beam/erl_unicode.c (mk_utf8_result_bin), OTP-29.1.1.
fn mk_utf8_result_bin(process: &mut Process, output: &mut Output, pos: usize) -> Term {
    match output {
        Output::Heap(writer) => {
            writer.shrink_to(pos);
            writer
                .finish(&mut process.heap)
                .expect("the heap binary was reserved")
        }
        Output::Writer(bin) => {
            let _ = arinsal_term::writable_resize_private(*bin, pos * 8);
            finish_iolist_binary_output(*bin);
            *bin
        }
    }
}

/// `build_utf8_return`.
// Port of erts/emulator/beam/erl_unicode.c (build_utf8_return), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn build_utf8_return(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut Process,
    mut output: Output,
    state: &BuildState<'_>,
    rest_term: Term,
    encoding: Term,
) -> u64 {
    let (pos, err, num_leftovers) = (state.pos, state.err, state.num_leftovers);
    let leftover = &state.leftover[..num_leftovers];
    let mut rest_term = rest_term;
    let result = if !err && rest_term == Term::NIL && num_leftovers == 0 {
        mk_utf8_result_bin(process, &mut output, pos)
    } else if !err && rest_term != Term::NIL {
        // Trap.
        if num_leftovers > 0 {
            let leftover_bin = binary(process, leftover);
            rest_term = cons(process, leftover_bin, rest_term);
        }
        let Output::Writer(bin) = output else {
            // A result that fits an on-heap binary never traps.
            return bif_ret(c_p, i, Err(badarg()));
        };
        process.heap.abi.fcalls = 0;
        let pos_term = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
            .int_from_u64(pos as u64)
            .expect("HAlloc");
        let trap = bif_trap(
            process,
            CHARACTERS_TO_UTF8_TRAP,
            vec![bin, pos_term, rest_term, encoding],
        );
        return bif_ret(c_p, i, Err(trap));
    } else {
        let mut reason = Term::atom(atoms::ERROR);
        if err {
            if num_leftovers > 0 {
                let leftover_bin = binary(process, leftover);
                rest_term = cons(process, rest_term, Term::NIL);
                rest_term = cons(process, leftover_bin, rest_term);
            }
        } else {
            rest_term = binary(process, leftover);
            if check_leftovers(leftover) == 0 {
                reason = Term::atom(atoms::INCOMPLETE);
            }
        }
        let bin = mk_utf8_result_bin(process, &mut output, pos);
        TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
            .tuple(&[reason, bin, rest_term])
            .expect("HAlloc")
    };
    crate::native_hooks::raw(result)
}

/// `erts_new_binary_from_data`.
fn binary(process: &mut Process, bytes: &[u8]) -> Term {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .binary(bytes)
        .expect("HAlloc")
}

/// `unicode:characters_to_binary/2`.
// Port of erts/emulator/beam/erl_unicode.c (unicode_characters_to_binary_2), OTP-29.1.1.
pub(crate) extern "C" fn unicode_characters_to_binary_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [arg1, arg2] = crate::bif_table::bif_args::<2>(reg);
    let latin1 = if arg2 == Term::atom(atoms::LATIN1) {
        true
    } else if arg2 == Term::atom(atoms::UNICODE) || arg2 == Term::atom(atoms::UTF8) {
        false
    } else {
        let trap = bif_trap(process, CHARACTERS_TO_BINARY_INT, vec![arg1, arg2]);
        return bif_ret(c_p, i, Err(trap));
    };
    let subject = match Cons::try_from(arg1) {
        Ok(cell) if is_bitstring(cell.head()) && cell.tail() == Term::NIL => cell.head(),
        _ => arg1,
    };
    let (need, cost_of_utf8_need) = utf8_need(subject, latin1);
    if need < 0 {
        return bif_ret(c_p, i, Err(badarg()));
    }
    if is_bitstring(subject)
        && aligned_binary_size(subject) == need
        && (latin1
            || aligned_bytes(subject).is_some_and(|bytes| std::str::from_utf8(&bytes).is_ok()))
    {
        cost_to_proc(process, simple_loops_to_common(cost_of_utf8_need));
        return crate::native_hooks::raw(subject);
    }
    let need = need as usize;
    cost_to_proc(process, simple_loops_to_common(cost_of_utf8_need));
    let mut left = allowed_iterations(process) - simple_loops_to_common(cost_of_utf8_need);
    // Ensure that we do not trap when the result is a heap binary.
    if left <= ERL_ONHEAP_BINARY_LIMIT {
        left = ERL_ONHEAP_BINARY_LIMIT;
    }
    let sleft = left;
    let mut leftover = [0u8; 4];
    let mut build = |process: &mut Process, target: &mut [u8]| {
        let mut state = BuildState {
            target,
            pos: 0,
            characters: 0,
            left,
            err: false,
            leftover: [0; 4],
            num_leftovers: 0,
        };
        let rest_term = do_build_utf8(process, subject, &mut state, latin1);
        leftover = state.leftover;
        (
            rest_term,
            state.pos,
            state.left,
            state.err,
            state.num_leftovers,
        )
    };
    let (output, rest_term, pos, left_after, err, num_leftovers);
    if need as i64 <= ERL_ONHEAP_BINARY_LIMIT {
        let Ok(mut writer) = HeapBinaryWriter::new(&mut process.heap, need) else {
            return bif_ret(c_p, i, Err(badarg()));
        };
        // The writer owns the reserved words; the bytes are filled in place.
        (rest_term, pos, left_after, err, num_leftovers) = build(process, writer.bytes_mut());
        output = Output::Heap(writer);
    } else {
        let Ok(bin) = allocate_iolist_binary(&mut ProcessHeapHandle(&mut process.heap), need)
        else {
            return bif_ret(c_p, i, Err(badarg()));
        };
        let result = with_iolist_binary_output(bin, |target| build(process, target));
        let Some(result) = result else {
            return bif_ret(c_p, i, Err(badarg()));
        };
        (rest_term, pos, left_after, err, num_leftovers) = result;
        output = Output::Writer(bin);
    }
    cost_to_proc(process, sleft - left_after);
    let state = BuildState {
        target: &mut [],
        pos,
        characters: 0,
        left: left_after,
        err,
        leftover,
        num_leftovers,
    };
    build_utf8_return(c_p, i, process, output, &state, rest_term, arg2)
}

/// `characters_to_utf8_trap/4`.
// Port of erts/emulator/beam/erl_unicode.c (characters_to_utf8_trap), OTP-29.1.1.
pub(crate) extern "C" fn characters_to_utf8_trap(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [bin, pos_term, rest, encoding] = crate::bif_table::bif_args::<4>(reg);
    let Some(pos) = pos_term
        .as_small()
        .and_then(|pos| usize::try_from(pos).ok())
    else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    let latin1 = encoding == Term::atom(atoms::LATIN1);
    let sleft = allowed_iterations(process);
    let mut leftover = [0u8; 4];
    let result = with_iolist_binary_output(bin, |target| {
        let mut state = BuildState {
            target,
            pos,
            characters: 0,
            left: sleft,
            err: false,
            leftover: [0; 4],
            num_leftovers: 0,
        };
        let rest_term = do_build_utf8(process, rest, &mut state, latin1);
        leftover = state.leftover;
        (
            rest_term,
            state.pos,
            state.left,
            state.err,
            state.num_leftovers,
        )
    });
    let Some((rest_term, pos, left, err, num_leftovers)) = result else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    cost_to_proc(process, sleft - left);
    let state = BuildState {
        target: &mut [],
        pos,
        characters: 0,
        left,
        err,
        leftover,
        num_leftovers,
    };
    build_utf8_return(
        c_p,
        i,
        process,
        Output::Writer(bin),
        &state,
        rest_term,
        encoding,
    )
}

// ---- unicode:characters_to_list/2 ---------------------------------------------------------

const ERTS_UTF8_OK: i32 = 0;
const ERTS_UTF8_INCOMPLETE: i32 = 1;
const ERTS_UTF8_ERROR: i32 = 2;
const ERTS_UTF8_ANALYZE_MORE: i32 = 3;

const CHARACTERS_TO_LIST_INT: &str = "unicode:characters_to_list_int/2";
const CHARACTERS_TO_LIST_TRAP_1: &str = "erlang:characters_to_list_trap_1/3";
const CHARACTERS_TO_LIST_TRAP_2: &str = "erlang:characters_to_list_trap_2/3";
const CHARACTERS_TO_LIST_TRAP_3: &str = "erlang:characters_to_list_trap_3/3";
const CHARACTERS_TO_LIST_TRAP_4: &str = "erlang:characters_to_list_trap_4/1";

/// `sizeof(RestartContext)` on a 64-bit build: the magic binary's `orig_size`.
const ERTS_RESTART_CONTEXT_SIZE: usize = 40;

/// `RestartContext`: the UTF-8 buffer built so far and what remains to turn into a list.
// Port of erts/emulator/beam/erl_unicode.c (RestartContext), OTP-29.1.1.
struct RestartContext {
    bytes: Vec<u8>,
    num_processed_bytes: usize,
    num_bytes_to_process: usize,
    num_resulting_chars: usize,
    state: i32,
}

type RestartHolder = crate::bif_traps::TrapContext<RestartContext>;

// `cleanup_restart_context_bin`: dropping the context frees its buffer.
arinsal_term::magic_payload!(RestartHolder => cleanup_restart_context_bin);

/// `make_magic_bin_for_restart`: a magic reference holding `rc`.
fn make_magic_bin_for_restart(process: &mut Process, rc: RestartContext) -> Term {
    let bin = arinsal_term::MagicBin::with_erts_payload_size_and_refn(
        RestartHolder::new(rc),
        ERTS_RESTART_CONTEXT_SIZE,
        arinsal_bifs::next_ref_words(),
    );
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .magic_ref(bin)
        .expect("HAlloc")
}

/// `analyze_utf8` without the Latin-1 and maximum-character options: the state, the end of the
/// accepted prefix and the characters in it. `left` counts down one per character.
// Port of erts/emulator/beam/erl_unicode.c (analyze_utf8, erts_analyze_utf8), OTP-29.1.1.
fn analyze_utf8(source: &[u8], mut left: Option<&mut i64>) -> (i32, usize, usize) {
    let mut res = ERTS_UTF8_OK;
    let mut at = 0usize;
    let mut size = source.len();
    let mut nchars = 0usize;
    let mut err_pos = 0usize;
    while size > 0 {
        let byte = source[at];
        if byte & 0x80 == 0 {
            at += 1;
            size -= 1;
        } else if byte & 0xE0 == 0xC0 {
            if size < 2 {
                res = ERTS_UTF8_INCOMPLETE;
                break;
            }
            if source[at + 1] & 0xC0 != 0x80 || byte < 0xC2 {
                res = ERTS_UTF8_ERROR;
                break;
            }
            at += 2;
            size -= 2;
        } else if byte & 0xF0 == 0xE0 {
            if size < 3 {
                res = ERTS_UTF8_INCOMPLETE;
                break;
            }
            if source[at + 1] & 0xC0 != 0x80
                || source[at + 2] & 0xC0 != 0x80
                || (byte == 0xE0 && source[at + 1] < 0xA0)
                || (byte & 0xF == 0xD && source[at + 1] & 0x20 != 0)
            {
                res = ERTS_UTF8_ERROR;
                break;
            }
            at += 3;
            size -= 3;
        } else if byte & 0xF8 == 0xF0 {
            if size < 4 {
                res = ERTS_UTF8_INCOMPLETE;
                break;
            }
            if source[at + 1] & 0xC0 != 0x80
                || source[at + 2] & 0xC0 != 0x80
                || source[at + 3] & 0xC0 != 0x80
                || (byte == 0xF0 && source[at + 1] < 0x90)
                || byte & 0x7 > 0x4
                || (byte & 0x7 == 0x4 && source[at + 1] & 0x3F > 0xF)
            {
                res = ERTS_UTF8_ERROR;
                break;
            }
            at += 4;
            size -= 4;
        } else {
            res = ERTS_UTF8_ERROR;
            break;
        }
        nchars += 1;
        err_pos = at;
        if let Some(left) = left.as_deref_mut() {
            *left -= 1;
            if *left <= 0 && size > 0 {
                res = ERTS_UTF8_ANALYZE_MORE;
                break;
            }
        }
    }
    (res, err_pos, nchars)
}

/// `do_utf8_to_list` / `erts_make_list_from_utf8_buf`: the last `num` (at most `left`)
/// characters of the valid UTF-8 `bytes`, prepended to `tail`; returns the list, the
/// characters built and the bytes eaten from the end.
// Port of erts/emulator/beam/erl_unicode.c (do_utf8_to_list, erts_make_list_from_utf8_buf),
// OTP-29.1.1.
fn do_utf8_to_list(
    process: &mut Process,
    num: usize,
    bytes: &[u8],
    left: usize,
    tail: Term,
) -> (Term, usize, usize) {
    let mut num = num;
    if left < num {
        num = if left > 0 { left } else { 1 };
    }
    let mut points: smallvec::SmallVec<[Term; 64]> = smallvec::SmallVec::new();
    let mut remaining = num;
    let mut source = bytes.len();
    while source > 0 {
        source -= 1;
        let b = bytes[source];
        let unipoint = if b & 0x80 == 0 {
            u32::from(b)
        } else if b & 0xE0 == 0xC0 {
            (u32::from(b & 0x1F) << 6) | u32::from(bytes[source + 1] & 0x3F)
        } else if b & 0xF0 == 0xE0 {
            (u32::from(b & 0xF) << 12)
                | (u32::from(bytes[source + 1] & 0x3F) << 6)
                | u32::from(bytes[source + 2] & 0x3F)
        } else if b & 0xF8 == 0xF0 {
            (u32::from(b & 0x7) << 18)
                | (u32::from(bytes[source + 1] & 0x3F) << 12)
                | (u32::from(bytes[source + 2] & 0x3F) << 6)
                | u32::from(bytes[source + 3] & 0x3F)
        } else {
            // Ignore 2#10XXXXXX.
            continue;
        };
        points.push(Term::small(i64::from(unipoint)).expect("a code point is small"));
        remaining -= 1;
        if remaining == 0 {
            break;
        }
    }
    points.reverse();
    let eaten = bytes.len() - source;
    let list = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .list_from_slice_with_tail(&points, tail)
        .expect("HAlloc");
    (list, num, eaten)
}

/// `{Tag, Converted, Rest}` as `finalize_list_to_list` and `do_bif_utf8_to_list` return it.
fn tuple3(process: &mut Process, tag: arinsal_term::Atom, converted: Term, rest: Term) -> Term {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .tuple(&[Term::atom(tag), converted, rest])
        .expect("HAlloc")
}

/// `erts_make_integer`.
fn make_integer(process: &mut Process, value: usize) -> Term {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .int_from_u64(value as u64)
        .expect("HAlloc")
}

/// `finalize_list_to_list`: the last step of `characters_to_list`, building the list from the
/// UTF-8 buffer, trapping to `characters_to_list_trap_2` when the reductions run out.
// Port of erts/emulator/beam/erl_unicode.c (finalize_list_to_list), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn finalize_list_to_list(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut Process,
    bytes: Vec<u8>,
    rest: Term,
    num_processed_bytes: usize,
    num_bytes_to_process: usize,
    num_resulting_chars: usize,
    state: i32,
    left: i64,
    tail: Term,
) -> u64 {
    let converted = if num_bytes_to_process == 0 {
        tail
    } else {
        let (converted, num_built, num_eaten) = do_utf8_to_list(
            process,
            num_resulting_chars,
            &bytes[..num_bytes_to_process],
            left as u64 as usize,
            tail,
        );
        cost_to_proc(process, num_built as i64);
        if num_built != num_resulting_chars {
            // Work left to do.
            let rc = RestartContext {
                bytes,
                num_processed_bytes: num_processed_bytes + num_eaten,
                num_bytes_to_process: num_bytes_to_process - num_eaten,
                num_resulting_chars: num_resulting_chars - num_built,
                state,
            };
            process.heap.abi.fcalls = 0;
            let mref = make_magic_bin_for_restart(process, rc);
            let trap = bif_trap(
                process,
                CHARACTERS_TO_LIST_TRAP_2,
                vec![mref, rest, converted],
            );
            return bif_ret(c_p, i, Err(trap));
        }
        converted
    };
    // No more trapping: the temporary array is released (`free_restart`).
    drop(bytes);
    let ret = if state == ERTS_UTF8_INCOMPLETE {
        tuple3(process, atoms::INCOMPLETE, converted, rest)
    } else if state == ERTS_UTF8_ERROR {
        tuple3(process, atoms::ERROR, converted, rest)
    } else {
        converted
    };
    crate::native_hooks::raw(ret)
}

/// `build_list_return`.
// Port of erts/emulator/beam/erl_unicode.c (build_list_return), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn build_list_return(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut Process,
    bytes: Vec<u8>,
    state: &BuildState<'_>,
    rest_term: Term,
    latin1: Term,
    left: i64,
) -> u64 {
    let left = if left <= 0 { 1 } else { left };
    let (pos, characters, err, num_leftovers) =
        (state.pos, state.characters, state.err, state.num_leftovers);
    let leftover = &state.leftover[..num_leftovers];
    let mut rest_term = rest_term;
    if err {
        if num_leftovers > 0 {
            let leftover_bin = binary(process, leftover);
            rest_term = cons(process, rest_term, Term::NIL);
            rest_term = cons(process, leftover_bin, rest_term);
        }
        return finalize_list_to_list(
            c_p,
            i,
            process,
            bytes,
            rest_term,
            0,
            pos,
            characters,
            ERTS_UTF8_ERROR,
            left,
            Term::NIL,
        );
    }
    if rest_term == Term::NIL && num_leftovers != 0 {
        let leftover_bin = binary(process, leftover);
        let state = if check_leftovers(leftover) != 0 {
            ERTS_UTF8_ERROR
        } else {
            ERTS_UTF8_INCOMPLETE
        };
        return finalize_list_to_list(
            c_p,
            i,
            process,
            bytes,
            leftover_bin,
            0,
            pos,
            characters,
            state,
            left,
            Term::NIL,
        );
    }
    if rest_term != Term::NIL {
        // Trap.
        if num_leftovers > 0 {
            let rest_bin = binary(process, leftover);
            rest_term = cons(process, rest_bin, rest_term);
        }
        process.heap.abi.fcalls = 0;
        let rc = RestartContext {
            bytes,
            num_processed_bytes: 0,
            num_bytes_to_process: pos,
            num_resulting_chars: characters,
            state: ERTS_UTF8_OK,
        };
        let mref = make_magic_bin_for_restart(process, rc);
        let trap = bif_trap(
            process,
            CHARACTERS_TO_LIST_TRAP_1,
            vec![mref, rest_term, latin1],
        );
        return bif_ret(c_p, i, Err(trap));
    }
    finalize_list_to_list(
        c_p,
        i,
        process,
        bytes,
        Term::NIL,
        0,
        pos,
        characters,
        ERTS_UTF8_OK,
        left,
        Term::NIL,
    )
}

/// `unicode:characters_to_list/2`.
// Port of erts/emulator/beam/erl_unicode.c (unicode_characters_to_list_2), OTP-29.1.1.
pub(crate) extern "C" fn unicode_characters_to_list_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [arg1, arg2] = crate::bif_table::bif_args::<2>(reg);
    let latin1 = if arg2 == Term::atom(atoms::LATIN1) {
        true
    } else if arg2 == Term::atom(atoms::UNICODE) || arg2 == Term::atom(atoms::UTF8) {
        false
    } else {
        let trap = bif_trap(process, CHARACTERS_TO_LIST_INT, vec![arg1, arg2]);
        return bif_ret(c_p, i, Err(trap));
    };
    if is_bitstring(arg1) && !latin1 {
        // Optimized behaviour for this case: `utf8_to_list`.
        if aligned_binary_size(arg1) < 0 {
            return bif_ret(c_p, i, Err(badarg()));
        }
        return do_bif_utf8_to_list(
            c_p,
            i,
            process,
            arg1,
            0,
            0,
            0,
            ERTS_UTF8_ANALYZE_MORE,
            Term::NIL,
        );
    }
    let (need, cost_of_utf8_need) = utf8_need(arg1, latin1);
    if need < 0 {
        return bif_ret(c_p, i, Err(badarg()));
    }
    let mut bytes = vec![0u8; need as usize];
    cost_to_proc(process, simple_loops_to_common(cost_of_utf8_need));
    let mut left = allowed_iterations(process) - simple_loops_to_common(cost_of_utf8_need);
    if left <= 0 {
        // Simplified: let everything be set up by setting left to 1.
        left = 1;
    }
    let sleft = left;
    let mut state = BuildState {
        target: &mut bytes,
        pos: 0,
        characters: 0,
        left,
        err: false,
        leftover: [0; 4],
        num_leftovers: 0,
    };
    let rest_term = do_build_utf8(process, arg1, &mut state, latin1);
    cost_to_proc(process, sleft - state.left);
    let (pos, characters, left_after, err, leftover, num_leftovers) = (
        state.pos,
        state.characters,
        state.left,
        state.err,
        state.leftover,
        state.num_leftovers,
    );
    let state = BuildState {
        target: &mut [],
        pos,
        characters,
        left: left_after,
        err,
        leftover,
        num_leftovers,
    };
    build_list_return(c_p, i, process, bytes, &state, rest_term, arg2, left_after)
}

/// `do_bif_utf8_to_list`: a plain UTF-8 binary is analyzed from its start while the result is
/// built from the end of the accepted part, trapping in either phase.
// Port of erts/emulator/beam/erl_unicode.c (do_bif_utf8_to_list), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn do_bif_utf8_to_list(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut Process,
    orig_bin: Term,
    num_processed_bytes: usize,
    mut num_bytes_to_process: usize,
    mut num_resulting_chars: usize,
    mut state: i32,
    tail: Term,
) -> u64 {
    let Some(bytes) = aligned_bytes(orig_bin) else {
        let ret = tuple3(process, atoms::ERROR, Term::NIL, orig_bin);
        return crate::native_hooks::raw(ret);
    };
    let size = bytes.len();
    let mut left = allowed_iterations(process);
    if state == ERTS_UTF8_ANALYZE_MORE {
        let (analyzed, end, numchar) =
            analyze_utf8(&bytes[num_bytes_to_process..], Some(&mut left));
        state = analyzed;
        cost_to_proc(process, numchar as i64);
        num_resulting_chars += numchar;
        num_bytes_to_process += end;
        if state == ERTS_UTF8_ANALYZE_MORE {
            let epos = make_integer(process, num_bytes_to_process);
            let enumchar = make_integer(process, num_resulting_chars);
            process.heap.abi.fcalls = 0;
            let trap = bif_trap(
                process,
                CHARACTERS_TO_LIST_TRAP_3,
                vec![orig_bin, epos, enumchar],
            );
            return bif_ret(c_p, i, Err(trap));
        }
    }
    // Everything is analyzed: build.
    let converted = if num_bytes_to_process == 0 {
        tail
    } else {
        let (list, num_built, num_eaten) = do_utf8_to_list(
            process,
            num_resulting_chars,
            &bytes[..num_bytes_to_process],
            left as u64 as usize,
            tail,
        );
        cost_to_proc(process, num_built as i64);
        if num_built != num_resulting_chars {
            let new_chars = make_integer(process, num_resulting_chars - num_built);
            let new_bytes = make_integer(process, num_bytes_to_process - num_eaten);
            let new_processed = make_integer(process, num_processed_bytes + num_eaten);
            let state_term = Term::small(i64::from(state)).expect("a small state");
            let trap_tuple = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
                .tuple(&[
                    orig_bin,
                    new_processed,
                    new_bytes,
                    new_chars,
                    state_term,
                    list,
                ])
                .expect("HAlloc");
            process.heap.abi.fcalls = 0;
            let trap = bif_trap(process, CHARACTERS_TO_LIST_TRAP_4, vec![trap_tuple]);
            return bif_ret(c_p, i, Err(trap));
        }
        list
    };
    // No more trapping: build the rest binary if there is one.
    let b_sz = size - (num_bytes_to_process + num_processed_bytes);
    let mut rest = Term::NIL;
    if b_sz != 0 {
        let offset = num_bytes_to_process + num_processed_bytes;
        rest = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
            .sub_binary(orig_bin, offset * 8, b_sz * 8)
            .expect("HAlloc");
    }
    let error = |process: &mut Process, converted: Term, rest: Term| {
        let ret = tuple3(process, atoms::ERROR, converted, rest);
        crate::native_hooks::raw(ret)
    };
    if state == ERTS_UTF8_INCOMPLETE {
        let from = num_bytes_to_process + num_processed_bytes;
        if check_leftovers(&bytes[from..from + b_sz]) != 0 {
            return error(process, converted, rest);
        }
        let ret = tuple3(process, atoms::INCOMPLETE, converted, rest);
        return crate::native_hooks::raw(ret);
    }
    if state == ERTS_UTF8_ERROR {
        return error(process, converted, rest);
    }
    crate::native_hooks::raw(converted)
}

/// `characters_to_list_trap_1/3`.
// Port of erts/emulator/beam/erl_unicode.c (characters_to_list_trap_1), OTP-29.1.1.
pub(crate) extern "C" fn characters_to_list_trap_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [mref, rest, encoding] = crate::bif_table::bif_args::<3>(reg);
    let latin1 = encoding == Term::atom(atoms::LATIN1);
    let taken = mref.with_magic_payload::<RestartHolder, _>(|holder| {
        let mut rc = holder.lock().ok()?;
        Some((
            std::mem::take(&mut rc.bytes),
            rc.num_bytes_to_process,
            rc.num_resulting_chars,
        ))
    });
    let Some(Some((mut bytes, pos, characters))) = taken else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    let sleft = allowed_iterations(process);
    let mut state = BuildState {
        target: &mut bytes,
        pos,
        characters,
        left: sleft,
        err: false,
        leftover: [0; 4],
        num_leftovers: 0,
    };
    let rest_term = do_build_utf8(process, rest, &mut state, latin1);
    cost_to_proc(process, sleft - state.left);
    let (pos, characters, left, err, leftover, num_leftovers) = (
        state.pos,
        state.characters,
        state.left,
        state.err,
        state.leftover,
        state.num_leftovers,
    );
    let state = BuildState {
        target: &mut [],
        pos,
        characters,
        left,
        err,
        leftover,
        num_leftovers,
    };
    build_list_return(c_p, i, process, bytes, &state, rest_term, encoding, left)
}

/// `characters_to_list_trap_2/3`.
// Port of erts/emulator/beam/erl_unicode.c (characters_to_list_trap_2), OTP-29.1.1.
pub(crate) extern "C" fn characters_to_list_trap_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [mref, rest, tail] = crate::bif_table::bif_args::<3>(reg);
    let taken = mref.with_magic_payload::<RestartHolder, _>(|holder| {
        let mut rc = holder.lock().ok()?;
        Some((
            std::mem::take(&mut rc.bytes),
            rc.num_processed_bytes,
            rc.num_bytes_to_process,
            rc.num_resulting_chars,
            rc.state,
        ))
    });
    let Some(Some((bytes, processed, to_process, chars, state))) = taken else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    let left = allowed_iterations(process);
    finalize_list_to_list(
        c_p, i, process, bytes, rest, processed, to_process, chars, state, left, tail,
    )
}

/// `characters_to_list_trap_3/3`: analyzing is still to be done.
// Port of erts/emulator/beam/erl_unicode.c (characters_to_list_trap_3), OTP-29.1.1.
pub(crate) extern "C" fn characters_to_list_trap_3(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [bin, analyzed, chars] = crate::bif_table::bif_args::<3>(reg);
    let (Some(analyzed), Some(chars)) = (
        analyzed.as_small().and_then(|n| usize::try_from(n).ok()),
        chars.as_small().and_then(|n| usize::try_from(n).ok()),
    ) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    do_bif_utf8_to_list(
        c_p,
        i,
        process,
        bin,
        0,
        analyzed,
        chars,
        ERTS_UTF8_ANALYZE_MORE,
        Term::NIL,
    )
}

/// `characters_to_list_trap_4/1`: analyzing is done and the building trapped.
// Port of erts/emulator/beam/erl_unicode.c (characters_to_list_trap_4), OTP-29.1.1.
pub(crate) extern "C" fn characters_to_list_trap_4(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [state_tuple] = crate::bif_table::bif_args::<1>(reg);
    let element = |index: usize| arinsal_bifs::tuple_element(state_tuple, index).ok();
    let (
        Some(orig_bin),
        Some(processed),
        Some(to_process),
        Some(chars),
        Some(last_state),
        Some(tail),
    ) = (
        element(0),
        element(1).and_then(|t| t.as_small()),
        element(2).and_then(|t| t.as_small()),
        element(3).and_then(|t| t.as_small()),
        element(4).and_then(|t| t.as_small()),
        element(5),
    )
    else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    do_bif_utf8_to_list(
        c_p,
        i,
        process,
        orig_bin,
        processed as usize,
        to_process as usize,
        chars as usize,
        last_state as i32,
        tail,
    )
}

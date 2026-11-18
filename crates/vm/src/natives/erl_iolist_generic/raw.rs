//! Raw output stores for the iolist copy pass.
// Port of erts/emulator/beam/erl_iolist.c (generic_iolist_copy), OTP-29.1.1.

use super::*;

/// `generic_iolist_copy(copy_state, VecThreshold, Unit, 0, 1)`.
#[inline(always)]
pub(super) fn generic_iolist_copy<const UNIT: usize>(
    copy: &mut CopyState,
    process: &mut crate::Process,
    threshold: usize,
) -> IolistAction {
    if copy.iolist.reds_left <= 0 {
        return IolistAction::Yield;
    }
    let init = YIELDS_PER_RED * copy.iolist.reds_left;
    let start = copy.iolist.obj;
    // erts passes `base` directly to generic_iolist_copy; retain that data flow rather than
    // calling through UninitBitstring's byte-slice callback for each copy pass.
    let output = copy.to_base.as_mut().map(|writer| {
        // SAFETY: this pass uniquely owns the allocated writer and does not move the heap.
        unsafe { arinsal_term::raw::iolist_binary_output_ptr(writer) }.expect("a sized copy pass")
    });
    // Empty leaves have no target. The iovec target is off-heap and remains stable if enqueueing
    // allocates; list_to_bitstring uses a heap writer only in its non-allocating copy pass.
    let (stopped, yield_count) = match output {
        Some((ptr, len)) => {
            // SAFETY: the writer stays unique and alive for this pass; generic_iolist_size
            // reserved the exact payload extent before copying begins.
            let base = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
            copy_pass::<UNIT>(copy, process, threshold, init, start, base)
        }
        None => copy_pass::<UNIT>(copy, process, threshold, init, start, &mut []),
    };
    let CopyState {
        iolist,
        vec,
        to_offset,
        ..
    } = copy;
    match stopped {
        None => {
            if threshold < NO_VEC {
                vec_enqueue(vec, *to_offset, process, Term::NIL);
            }
            iolist.estack = EStack::new();
            iolist.finish_reds(process, init, yield_count);
            IolistAction::Ok
        }
        Some(obj) => iolist.yield_pass(process, obj),
    }
}

/// `generic_iolist_copy`'s direct pass over the destination pointer.
#[inline(always)]
fn copy_pass<const UNIT: usize>(
    copy: &mut CopyState,
    process: &mut crate::Process,
    threshold: usize,
    init: i64,
    start: Term,
    base: &mut [u8],
) -> (Option<Term>, i64) {
    let CopyState {
        iolist,
        vec,
        from,
        to_offset,
        ..
    } = copy;
    let mut yield_count = init;
    let mut obj = start;
    let mut resume = true;
    let mut offset = *to_offset;
    let base_ptr = base.as_mut_ptr();
    let stopped = 'pass: loop {
        if !resume {
            match iolist.estack.pop() {
                Some(next) => obj = next,
                None => break None,
            }
        }
        resume = false;
        while let Ok(cons) = Cons::try_from(obj) {
            yield_count -= 1;
            if yield_count <= 0 {
                break 'pass Some(obj);
            }
            let (head, tail) = cons.pair();
            obj = head;
            if let Some(byte) = as_byte(obj) {
                let byte_offset = offset / 8;
                let shift = if UNIT == 8 { 0 } else { offset % 8 };
                if shift == 0 {
                    // SAFETY: generic_iolist_size reserved this exact output extent; `offset`
                    // advances only after this byte is stored.
                    unsafe { base_ptr.add(byte_offset).write(byte) };
                } else {
                    // SAFETY: generic_iolist_size reserved the extent, and a byte-aligned
                    // iolist element in a non-byte unit spans these two adjacent bytes.
                    unsafe {
                        let current = base_ptr.add(byte_offset);
                        let leading_bits = current.read();
                        current.write(
                            (byte >> shift) | ((leading_bits >> (8 - shift)) << (8 - shift)),
                        );
                        current.add(1).write(byte << (8 - shift));
                    }
                }
                offset += 8;
                obj = tail;
                continue;
            } else if let Some((start, bits)) = bitstring_geometry(obj) {
                if should_copy::<UNIT>(threshold, start, bits) {
                    if copy_bitstring(from, base, &mut offset, obj, &mut yield_count) {
                        iolist.estack.push(tail);
                        break 'pass Some(obj);
                    }
                } else {
                    vec_enqueue(vec, offset, process, obj);
                }
            } else if Cons::try_from(obj).is_ok() {
                iolist.estack.push(tail);
                continue;
            }
            obj = tail;
        }
        yield_count -= 1;
        if yield_count <= 0 {
            break 'pass Some(obj);
        } else if let Some((start, bits)) = bitstring_geometry(obj) {
            if should_copy::<UNIT>(threshold, start, bits) {
                if copy_bitstring(from, base, &mut offset, obj, &mut yield_count) {
                    break 'pass Some(obj);
                }
            } else {
                vec_enqueue(vec, offset, process, obj);
            }
        }
    };
    *to_offset = offset;
    (stopped, yield_count)
}

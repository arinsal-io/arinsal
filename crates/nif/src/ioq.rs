//! `enif_ioq_*`: the NIF I/O queue.
//!
//! Port of erts/emulator/beam/erl_io_queue.c (erts_ioq_enqv, erts_ioq_deq, erts_ioq_peekq,
//! erts_ioq_clear) and erts/emulator/beam/erl_nif.c:4338-4440 (enif_ioq_*), OTP-29.1.1. The
//! queue holds `SysIOVec` segments in order, each with the `Binary*` handle that keeps its
//! bytes alive; erts' ring of two pointer arrays is a `Vec` with a head index, which
//! restarts at the front when the queue empties as erts_ioq_deq does.
use crate::binref::{NifBinary, adopt_block, copy_to_block, handle_clone, handle_free};
use crate::iovec::{ErlNifIOVec, SysIOVec};
use crate::raw::{deref, deref_mut, slice};
use crate::{ErlNifBinary, ErlNifEnv};
use arinsal_term::{MagicRef, Term, TermBuilder};
use std::ffi::{c_int, c_void};
use std::ptr;

/// `ERL_ONHEAP_BINARY_LIMIT` (erl_bits.h:167).
const ERL_ONHEAP_BINARY_LIMIT: usize = 64;
/// `ERL_NIF_IOQ_NORMAL`.
const ERL_NIF_IOQ_NORMAL: c_int = 1;

/// `ErtsIOQueue`.
pub struct ErlNifIOQueue {
    size: usize,
    iov: Vec<SysIOVec>,
    /// One handle per segment, NULL after a dequeued segment before the queue restarts.
    bins: Vec<*mut c_void>,
    head: usize,
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_ioq_create(opts: c_int) -> *mut ErlNifIOQueue {
    if opts != ERL_NIF_IOQ_NORMAL {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(ErlNifIOQueue {
        size: 0,
        iov: Vec::new(),
        bins: Vec::new(),
        head: 0,
    }))
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_ioq_destroy(queue: *mut ErlNifIOQueue) {
    if queue.is_null() {
        return;
    }
    // SAFETY: the NIF passes a queue from enif_ioq_create and destroys it once.
    let queue = unsafe { Box::from_raw(queue) };
    // erts_ioq_clear: free the binaries of the remaining segments.
    for handle in &queue.bins[queue.head..] {
        handle_free(*handle);
    }
}

/// Port of erts/emulator/beam/erl_io_queue.c:192-229 (skip): strips `skip` bytes from the
/// front of the vector, in place; the index of its first remaining entry.
fn skip_bytes(vec: &mut ErlNifIOVec, mut skip: usize) -> Option<usize> {
    if vec.size <= skip {
        return None;
    }
    let mut first = 0;
    // We use a do-while to strip iov_len=0 from the beginning.
    loop {
        // SAFETY: `iov` holds `iovcnt` entries and `size > skip` keeps the loop inside them.
        let entry = unsafe { &mut *vec.iov.add(first) };
        if entry.iov_len <= skip {
            skip -= entry.iov_len;
            first += 1;
        } else {
            entry.iov_base = entry.iov_base.cast::<u8>().wrapping_add(skip).cast();
            entry.iov_len -= skip;
            skip = 0;
        }
        if skip == 0 {
            return Some(first);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_ioq_enqv(
    queue: *mut ErlNifIOQueue,
    vec: *mut ErlNifIOVec,
    skip: usize,
) -> c_int {
    if queue.is_null() || vec.is_null() {
        return 0;
    }
    // SAFETY: the NIF passes a live queue and iovec.
    let (queue, vec) = unsafe { (&mut *queue, &mut *vec) };
    if skip > vec.size {
        return 0;
    }
    c_int::from(enqv(queue, vec, skip).is_some())
}

/// Port of erts/emulator/beam/erl_io_queue.c:233-340 (erts_ioq_enqv). `None` is -1.
fn enqv(queue: &mut ErlNifIOQueue, vec: &mut ErlNifIOVec, skip: usize) -> Option<()> {
    let size = vec.size - skip;
    if vec.size <= skip {
        return Some(());
    }
    let first = skip_bytes(vec, skip)?;
    let count = usize::try_from(vec.iovcnt).ok()?;
    // Queue and reference all binaries (remove zero length items).
    for index in first..count {
        // SAFETY: `iov` and `ref_bins` hold `iovcnt` entries.
        let (entry, bin) = unsafe { (*vec.iov.add(index), *vec.ref_bins.add(index)) };
        if entry.iov_len == 0 {
            continue;
        }
        if bin.is_null() {
            // Special case: create a binary.
            let (handle, block) = copy_to_block(entry.iov_base.cast(), entry.iov_len)?;
            queue.bins.push(handle);
            queue.iov.push(SysIOVec {
                iov_base: block.cast(),
                iov_len: entry.iov_len,
            });
        } else {
            queue.bins.push(handle_clone(bin));
            queue.iov.push(entry);
        }
    }
    queue.size += size;
    Some(())
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_ioq_enq_binary(
    queue: *mut ErlNifIOQueue,
    bin: *mut ErlNifBinary,
    skip: usize,
) -> c_int {
    if bin.is_null() {
        return 0;
    }
    // SAFETY: the NIF passes a live binary.
    let b = deref_mut(bin);
    // The Binary* of the vector: a binary from enif_alloc_binary owns its malloc block; one
    // from enif_inspect_binary has none and is copied by the queue.
    let owned = !b.ref_bin.is_null();
    let handle = if owned {
        adopt_block(b.data, b.size)
    } else {
        ptr::null_mut()
    };
    let mut vec = ErlNifIOVec::single(b.data.cast(), b.size, handle);
    vec.link();
    let result = enif_ioq_enqv(queue, &mut vec, skip);
    // enif_release_binary: the queue holds its own reference now.
    handle_free(handle);
    if owned {
        *b = ErlNifBinary::default();
    }
    result
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_ioq_size(queue: *mut ErlNifIOQueue) -> usize {
    // SAFETY: the NIF passes a live queue.
    deref(queue).size
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_ioq_deq(queue: *mut ErlNifIOQueue, elems: usize, size: *mut usize) -> c_int {
    // SAFETY: the NIF passes a live queue.
    let queue = deref_mut(queue);
    // Port of erts/emulator/beam/erl_io_queue.c:349-379 (erts_ioq_deq).
    if queue.size < elems {
        return 0;
    }
    let mut left = elems;
    queue.size -= elems;
    while left > 0 {
        let head = queue.head;
        let len = queue.iov[head].iov_len;
        if len <= left {
            left -= len;
            handle_free(queue.bins[head]);
            queue.bins[head] = ptr::null_mut();
            queue.head += 1;
        } else {
            let entry = &mut queue.iov[head];
            entry.iov_base = entry.iov_base.cast::<u8>().wrapping_add(left).cast();
            entry.iov_len -= left;
            left = 0;
        }
    }
    // Restart pointers (optimised for enq).
    if queue.head == queue.iov.len() {
        queue.head = 0;
        queue.iov.clear();
        queue.bins.clear();
    }
    if !size.is_null() {
        // SAFETY: a non-NULL out-parameter is writable.
        unsafe { *size = queue.size };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_ioq_peek_head(
    e: *mut ErlNifEnv,
    queue: *mut ErlNifIOQueue,
    size: *mut usize,
    bin_term: *mut Term,
) -> c_int {
    // SAFETY: the NIF passes a live queue and environment.
    let (queue, env) = unsafe { (&*queue, &mut *e) };
    if queue.size == 0 {
        return 0;
    }
    let entry = queue.iov[queue.head];
    let handle = queue.bins[queue.head];
    if !size.is_null() {
        // SAFETY: a non-NULL out-parameter is writable.
        unsafe { *size = entry.iov_len };
    }
    let mut builder = TermBuilder::new(&mut env.heap);
    let term = if entry.iov_len > ERL_ONHEAP_BINARY_LIMIT {
        // A refc binary term sharing the segment's binary.
        // SAFETY: the segment's handle is live while it is queued.
        let held: NifBinary = unsafe { &*handle.cast::<NifBinary>() }.clone();
        let orig_size = held.orig_size();
        // SAFETY: the segment's bytes stay readable while `held` is retained by the term.
        let external = unsafe {
            arinsal_term::ExternalBinary::new(
                entry.iov_base.cast(),
                entry.iov_len,
                // Port of erts/emulator/beam/erl_nif.c (enif_ioq_peek_head), OTP-29.1.1:
                // this wraps the retained refc Binary, whose orig_size is its allocation size.
                MagicRef::with_orig_size(held, orig_size),
            )
        };
        builder.external_binary(external)
    } else {
        // SAFETY: the segment holds `iov_len` readable bytes.
        let bytes = slice(entry.iov_base.cast::<u8>(), entry.iov_len);
        builder.binary(bytes)
    };
    let Ok(term) = term else {
        return 0;
    };
    // SAFETY: the NIF passes a writable slot.
    unsafe { *bin_term = term };
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_ioq_peek(queue: *mut ErlNifIOQueue, iovlen: *mut c_int) -> *mut SysIOVec {
    // SAFETY: the NIF passes a live queue and a writable length.
    let (queue, iovlen) = unsafe { (&mut *queue, &mut *iovlen) };
    let count = queue.iov.len() - queue.head;
    *iovlen = c_int::try_from(count).unwrap_or(c_int::MAX);
    if count == 0 {
        return ptr::null_mut();
    }
    queue.iov[queue.head..].as_mut_ptr()
}

pub(crate) fn retain_exports() {
    std::hint::black_box(enif_ioq_create as *const ());
    std::hint::black_box(enif_ioq_peek_head as *const ());
}

//! `enif_inspect_iovec` and `enif_free_iovec`.
//!
//! Port of erts/emulator/beam/erl_nif.c:4062-4335 (enif_free_iovec, examine_iovec_term,
//! marshal_iovec_binary, fill_iovec_with_slice, create_iovec_from_slice and
//! enif_inspect_iovec), OTP-29.1.1. Off-heap aligned binaries are referenced in place and
//! their owner is retained per entry; on-heap and unaligned binaries are copied into one
//! shared block that every entry referencing it retains.
use crate::ErlNifEnv;
use crate::binref::{NifBinary, alloc_block, handle_clone, handle_free, handle_new};
use crate::raw::{binary_view, cons, deref_mut};
use arinsal_term::{Term, binary_owner, writable_finalize};
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn malloc(n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
}

/// `SysIOVec`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SysIOVec {
    pub(crate) iov_base: *mut c_void,
    pub(crate) iov_len: usize,
}

const ERL_NIF_IOVEC_SIZE: usize = 16;
/// erl_nif.c:4062.
const ERL_NIF_IOVEC_FLAGS_PREALLOC: c_int = 1;
/// Largest length of one iovec entry: erl_io_queue.h:41-42 (release build).
const MAX_SYSIOVEC_IOVLEN: usize = 1 << (usize::BITS - 1);

/// `ErlNifIOVec` (erl_nif.h:288).
#[repr(C)]
pub struct ErlNifIOVec {
    pub(crate) iovcnt: c_int,
    pub(crate) size: usize,
    pub(crate) iov: *mut SysIOVec,
    pub(crate) ref_bins: *mut *mut c_void,
    flags: c_int,
    small_iov: [SysIOVec; ERL_NIF_IOVEC_SIZE],
    small_ref_bin: [*mut c_void; ERL_NIF_IOVEC_SIZE],
}
const _: () = assert!(size_of::<ErlNifIOVec>() == 424);

impl ErlNifIOVec {
    /// An iovec of one entry on the stack (`enif_ioq_enq_binary`, erl_nif.c:4349-4358).
    pub(crate) fn single(base: *mut c_void, len: usize, bin: *mut c_void) -> Self {
        let empty = SysIOVec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        };
        let mut vec = Self {
            iovcnt: 1,
            size: len,
            iov: std::ptr::null_mut(),
            ref_bins: std::ptr::null_mut(),
            flags: ERL_NIF_IOVEC_FLAGS_PREALLOC,
            small_iov: [empty; ERL_NIF_IOVEC_SIZE],
            small_ref_bin: [std::ptr::null_mut(); ERL_NIF_IOVEC_SIZE],
        };
        vec.small_iov[0] = SysIOVec {
            iov_base: base,
            iov_len: len,
        };
        vec.small_ref_bin[0] = bin;
        vec
    }

    /// Point `iov` and `ref_bins` at the inline tables; done in place, since the pointers
    /// would not survive a move of the struct.
    pub(crate) fn link(&mut self) {
        self.iov = self.small_iov.as_mut_ptr();
        self.ref_bins = self.small_ref_bin.as_mut_ptr();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_free_iovec(iov: *mut ErlNifIOVec) {
    if iov.is_null() {
        return;
    }
    // SAFETY: the NIF passes an iovec made by enif_inspect_iovec with a NULL environment.
    let (count, bins, flags) = unsafe { ((*iov).iovcnt, (*iov).ref_bins, (*iov).flags) };
    for index in 0..usize::try_from(count).unwrap_or(0) {
        // Decrement the refc of all the binaries; the entry can be NULL after enq_binary.
        // SAFETY: `ref_bins` holds `iovcnt` entries.
        handle_free(unsafe { *bins.add(index) });
    }
    if flags & ERL_NIF_IOVEC_FLAGS_PREALLOC == 0 {
        // SAFETY: a non-preallocated iovec is one malloc block.
        unsafe { free(iov.cast()) };
    }
}

struct Slice {
    sublist_length: usize,
    sublist_start: Term,
    sublist_end: Term,
    referenced_size: usize,
    copied_size: usize,
    iovec_len: usize,
}

fn cell(list: Term) -> Option<(Term, Term)> {
    // SAFETY: `list` is an argument of the running NIF call, whose heap stays live.
    cons(list)
}

/// Size in bytes, start bit and whether erts references (rather than copies) the binary.
fn describe(binary: Term) -> Option<(usize, usize, bool)> {
    // SAFETY: `binary` is an argument of the running NIF call, whose heap stays live.
    let view = binary_view(binary)?;
    if view.bit_len() % 8 != 0 {
        return None;
    }
    let start = view.start_bit();
    Some((
        view.bit_len() / 8,
        start,
        view.is_off_heap() && start % 8 == 0,
    ))
}

// Port of erts/emulator/beam/erl_nif.c:4092-4152 (examine_iovec_term).
fn examine(list: Term, max_length: usize) -> Option<Slice> {
    let mut result = Slice {
        sublist_length: 0,
        sublist_start: list,
        sublist_end: list,
        referenced_size: 0,
        copied_size: 0,
        iovec_len: 0,
    };
    let mut lookahead = list;
    while let Some((binary, tail)) = cell(lookahead) {
        let (size, _, referenced) = describe(binary)?;
        if size > 0 {
            if referenced {
                result.referenced_size += size;
            } else {
                result.copied_size += size;
            }
            result.iovec_len += size.div_ceil(MAX_SYSIOVEC_IOVLEN);
        }
        result.sublist_length += 1;
        lookahead = tail;
        if result.sublist_length >= max_length {
            break;
        }
    }
    if lookahead != Term::NIL && cell(lookahead).is_none() {
        return None;
    }
    result.sublist_end = lookahead;
    Some(result)
}

/// `iov[index]` and `ref_bins[index]` of an iovec whose tables are set up.
fn put_entry(
    iovec: &mut ErlNifIOVec,
    index: usize,
    base: *mut c_void,
    len: usize,
    bin: *mut c_void,
) {
    // SAFETY: `iovec.iov` and `ref_bins` hold `iovcnt` entries and `index < iovcnt`.
    unsafe {
        *iovec.iov.add(index) = SysIOVec {
            iov_base: base,
            iov_len: len,
        };
        *iovec.ref_bins.add(index) = bin;
    }
}

// Port of erts/emulator/beam/erl_nif.c:4210-4290 (marshal_iovec_binary and
// fill_iovec_with_slice). Returns the handles taken for an environment to keep.
fn fill(env: *mut ErlNifEnv, slice: &Slice, iovec: &mut ErlNifIOVec) -> Option<Vec<usize>> {
    // Set up a common block for all on-heap and unaligned binaries.
    let copy = if slice.copied_size > 0 {
        Some(alloc_block(slice.copied_size)?)
    } else {
        None
    };
    let mut copy_offset = 0;
    let mut index = 0;
    let mut cursor = slice.sublist_start;
    let mut kept = Vec::new();
    while cursor != slice.sublist_end {
        let (binary, tail) = cell(cursor)?;
        // ERTS_PIN_BITSTRING: a writable binary is shrunk in place, never reallocated.
        writable_finalize(binary);
        let (size, start, referenced) = describe(binary)?;
        let (mut base, part, part_handle) = if referenced {
            let owner = binary_owner(binary)?;
            // SAFETY: `binary` is an argument of the running NIF call.
            let view = binary_view(binary)?;
            let base = view.bytes().as_ptr().wrapping_add(start / 8).cast_mut();
            (base, size, handle_new(NifBinary::Owner(owner)))
        } else {
            // If this isn't an *aligned* refc binary, copy its contents to the block and
            // reference that instead.
            let (copy_handle, block) = copy?;
            let bytes = arinsal_bifs::binary_bytes(binary).ok()?;
            // SAFETY: `copy_offset + size <= copied_size`, the block's length.
            let base = unsafe { block.add(copy_offset) };
            // SAFETY: as above; `bytes` holds `size` bytes.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), base, size) };
            copy_offset += size;
            (base, size, handle_clone(copy_handle))
        };
        let mut remaining = part;
        while remaining > 0 {
            let chunk = remaining.min(MAX_SYSIOVEC_IOVLEN);
            let entry = handle_clone(part_handle);
            put_entry(iovec, index, base.cast(), chunk, entry);
            if !env.is_null() {
                kept.push(entry as usize);
            }
            base = base.wrapping_add(chunk);
            remaining -= chunk;
            index += 1;
        }
        handle_free(part_handle);
        cursor = tail;
    }
    if let Some((copy_handle, _)) = copy {
        if env.is_null() {
            // The entries hold their own references; release the creation reference.
            handle_free(copy_handle);
        } else {
            // Attach the block to the environment; entries are borrowed from it.
            kept.push(copy_handle as usize);
        }
    }
    Some(kept)
}

// Port of erts/emulator/beam/erl_nif.c:4258-4335 (create_iovec_from_slice).
fn create(env: *mut ErlNifEnv, slice: &Slice, result: *mut *mut ErlNifIOVec) -> Option<()> {
    // SAFETY: the NIF passes a writable `ErlNifIOVec*` slot.
    let mut iovec = unsafe { *result };
    if !iovec.is_null() && slice.iovec_len < ERL_NIF_IOVEC_SIZE {
        // SAFETY: the NIF passes storage for an ErlNifIOVec.
        let v = deref_mut(iovec);
        v.iov = v.small_iov.as_mut_ptr();
        v.ref_bins = v.small_ref_bin.as_mut_ptr();
        v.flags = ERL_NIF_IOVEC_FLAGS_PREALLOC;
    } else {
        let iov_offset = size_of::<ErlNifIOVec>().next_multiple_of(8);
        let binv_offset =
            iov_offset + (slice.iovec_len * size_of::<SysIOVec>()).next_multiple_of(8);
        let alloc_size = binv_offset + slice.iovec_len * size_of::<*mut c_void>();
        // When the user passes an environment the iovec is attached to it, so it
        // disappears with the environment; otherwise the caller frees it.
        let base: *mut u8 = if env.is_null() {
            // SAFETY: malloc returns a block of the requested size or NULL.
            let block = unsafe { malloc(alloc_size) }.cast::<u8>();
            if block.is_null() {
                return None;
            }
            block
        } else {
            // SAFETY: the NIF passes its live environment.
            let env = deref_mut(env);
            env.tmp_iovecs.push(vec![0u64; alloc_size.div_ceil(8)]);
            env.tmp_iovecs.last_mut()?.as_mut_ptr().cast()
        };
        iovec = base.cast();
        // SAFETY: the block holds the header, the SysIOVec table and the Binary table.
        unsafe {
            let v = &mut *iovec;
            v.iov = base.add(iov_offset).cast();
            v.ref_bins = base.add(binv_offset).cast();
            v.flags = 0;
        }
    }
    // SAFETY: `iovec` is a live ErlNifIOVec.
    let v = deref_mut(iovec);
    v.size = slice.referenced_size + slice.copied_size;
    v.iovcnt = c_int::try_from(slice.iovec_len).ok()?;
    let Some(kept) = fill(env, slice, v) else {
        if env.is_null() && v.flags & ERL_NIF_IOVEC_FLAGS_PREALLOC == 0 {
            // SAFETY: the block came from malloc above.
            unsafe { free(iovec.cast()) };
        }
        return None;
    };
    if !env.is_null() {
        // SAFETY: the NIF passes its live environment.
        deref_mut(env).tmp_handles.extend(kept);
    }
    // SAFETY: the NIF passes a writable slot.
    unsafe { *result = iovec };
    Some(())
}

#[unsafe(no_mangle)]
pub extern "C" fn enif_inspect_iovec(
    env: *mut ErlNifEnv,
    max_elements: usize,
    list: Term,
    tail: *mut Term,
    iov: *mut *mut ErlNifIOVec,
) -> c_int {
    let Some(slice) = examine(list, max_elements) else {
        return 0;
    };
    if create(env, &slice, iov).is_none() {
        return 0;
    }
    // SAFETY: the NIF passes a writable slot.
    unsafe { *tail = slice.sublist_end };
    1
}

pub(crate) fn retain_exports() {
    std::hint::black_box(enif_inspect_iovec as *const ());
    std::hint::black_box(enif_free_iovec as *const ());
}

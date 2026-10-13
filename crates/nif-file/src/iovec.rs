//! `enif_inspect_iovec` and the unix `efile_writev`/`efile_pwritev` loops for the
//! prim_file write NIFs. The iovec points into the argument binaries themselves; only
//! on-heap and unaligned binaries are copied, into one shared buffer, as in erts.

use std::io::IoSlice;
use std::os::fd::AsFd;

use arinsal_term::Term;
use rustix::io::Errno;

/// Largest length of one iovec entry: erts/emulator/beam/erl_io_queue.h:41-42 (release
/// build), OTP-29.1.1.
const MAX_SYSIOVEC_IOVLEN: usize = 1 << (usize::BITS - 1);
/// erts/emulator/nifs/unix/unix_prim_file.c:48, OTP-29.1.1.
const FALLBACK_RW_LENGTH: usize = (1 << 31) - 1;

/// An inspected iovec: up to `max_elements` cells of an iolist, by reference.
///
/// The entries borrow the inspected binaries, which stay live for `'a` (the NIF call's
/// argument terms), or the caller's copy buffer.
pub(crate) struct IoVec<'a> {
    pub(crate) iov: Vec<IoSlice<'a>>,
    /// The list after the inspected cells.
    pub(crate) tail: Term,
}

/// Result of `examine_iovec_term`.
struct Slice {
    sublist_length: usize,
    sublist_end: Term,
    referenced_size: usize,
    copied_size: usize,
    iovec_len: usize,
}

/// Borrowed bytes of one list element and whether erts references them in place.
struct Part<'a> {
    bytes: &'a [u8],
    start_bit: usize,
    size: usize,
    referenced: bool,
}

/// The head and tail of a list cell, `None` for any other term.
fn cell(list: Term) -> Option<(Term, Term)> {
    // SAFETY: `list` is (part of) an argument term of the running NIF call, whose heap
    // stays live and unmoved until the call returns.
    unsafe { list.cons_ref() }
}

/// Classify one list element; `None` when it is not a whole-byte bitstring.
fn part<'a>(binary: Term) -> Option<Part<'a>> {
    // SAFETY: the binary is an argument term of the running NIF call; its heap and owner
    // stay live and unmoved, and no writable append runs while the call borrows it.
    let view = unsafe { binary.binary_ref() }?;
    if view.bit_len() % 8 != 0 {
        return None;
    }
    let start_bit = view.start_bit();
    Some(Part {
        bytes: view.bytes(),
        start_bit,
        size: view.bit_len() / 8,
        referenced: view.is_off_heap() && start_bit % 8 == 0,
    })
}

// Port of erts/emulator/beam/erl_nif.c:4092-4152 (examine_iovec_term), OTP-29.1.1.
fn examine_iovec_term(list: Term, max_length: usize) -> Option<Slice> {
    let mut result = Slice {
        sublist_length: 0,
        sublist_end: list,
        referenced_size: 0,
        copied_size: 0,
        iovec_len: 0,
    };
    let mut lookahead = list;
    while let Some((binary, tail)) = cell(lookahead) {
        let part = part(binary)?;
        if part.size > 0 {
            // If we're unaligned or an on-heap binary we'll need to copy ourselves over
            // to a temporary buffer.
            if part.referenced {
                result.referenced_size += part.size;
            } else {
                result.copied_size += part.size;
            }
            result.iovec_len += part.size.div_ceil(MAX_SYSIOVEC_IOVLEN);
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

/// Copy `out.len()` bytes starting at bit `start_bit` of `src`.
// Port of erts/emulator/beam/erl_bits.h:540-556 (copy_binary_to_buffer) for a byte-aligned
// destination, OTP-29.1.1.
fn copy_binary_to_buffer(out: &mut [u8], src: &[u8], start_bit: usize) {
    let first = start_bit / 8;
    let shift = start_bit % 8;
    if shift == 0 {
        out.copy_from_slice(&src[first..first + out.len()]);
        return;
    }
    for (index, byte) in out.iter_mut().enumerate() {
        let high = src[first + index] << shift;
        let low = src
            .get(first + index + 1)
            .map_or(0, |next| next >> (8 - shift));
        *byte = high | low;
    }
}

/// Inspect up to `max_elements` cells of `list`; `None` is badarg.
///
/// `list` must be an argument term of the running NIF call: the iovec borrows its
/// binaries, whose heap is not collected or moved until the call returns. On-heap and
/// unaligned binaries are copied into `copy`.
// Port of erts/emulator/beam/erl_nif.c:4154-4335 (marshal_iovec_binary,
// fill_iovec_with_slice, create_iovec_from_slice and enif_inspect_iovec), OTP-29.1.1.
pub(crate) fn inspect_iovec<'a>(
    list: Term,
    max_elements: usize,
    copy: &'a mut Vec<u8>,
) -> Option<IoVec<'a>> {
    let slice = examine_iovec_term(list, max_elements)?;
    // Set up a common buffer for all on-heap and unaligned binaries.
    copy.clear();
    if copy.try_reserve_exact(slice.copied_size).is_err() {
        return None;
    }
    let mut parts = Vec::with_capacity(slice.sublist_length);
    let mut iterator = list;
    for _ in 0..slice.sublist_length {
        let (binary, tail) = cell(iterator)?;
        let part = part::<'a>(binary)?;
        if !part.referenced && part.size > 0 {
            // If this isn't an *aligned* refc binary, copy its contents to the buffer and
            // reference that instead.
            let offset = copy.len();
            copy.resize(offset + part.size, 0);
            copy_binary_to_buffer(&mut copy[offset..], part.bytes, part.start_bit);
        }
        parts.push(part);
        iterator = tail;
    }
    debug_assert_eq!(copy.len(), slice.copied_size);
    let copy: &'a [u8] = copy;
    let mut copy_offset = 0;
    let mut iov = Vec::with_capacity(slice.iovec_len);
    for part in parts {
        let mut data = if part.referenced {
            &part.bytes[part.start_bit / 8..][..part.size]
        } else {
            copy_offset += part.size;
            &copy[copy_offset - part.size..copy_offset]
        };
        while !data.is_empty() {
            let (chunk, rest) = data.split_at(data.len().min(MAX_SYSIOVEC_IOVLEN));
            iov.push(IoSlice::new(chunk));
            data = rest;
        }
    }
    debug_assert_eq!(iov.len(), slice.iovec_len);
    debug_assert_eq!(
        iov.iter().map(|chunk| chunk.len()).sum::<usize>(),
        slice.referenced_size + slice.copied_size
    );
    Some(IoVec {
        iov,
        tail: slice.sublist_end,
    })
}

/// Write the whole iovec at the file position; `Err` carries the errno.
// Port of erts/emulator/nifs/unix/unix_prim_file.c:343-391 (efile_writev), OTP-29.1.1.
// `IoSlice::advance_slices` is shift_iov (unix_prim_file.c:270-290) and rustix caps the
// count at IOV_MAX.
pub(crate) fn efile_writev(fd: impl AsFd, vec: &mut IoVec<'_>) -> Result<u64, i32> {
    let fd = fd.as_fd();
    let mut iov: &mut [IoSlice<'_>] = &mut vec.iov;
    let mut bytes_written: u64 = 0;
    let mut result: Result<usize, Errno>;
    loop {
        if iov.is_empty() {
            result = Ok(0);
            break;
        }
        result = rustix::io::writev(fd, iov);
        // Fall back to using write(2) if writev(2) reports that the combined size of iov
        // is greater than SSIZE_T_MAX.
        if result == Err(Errno::INVAL) {
            result = rustix::io::write(fd, &iov[0]);
            // Some OSs (e.g. macOS) do not allow writes greater than 2 GB, so if we get
            // EINVAL in the fallback, we try with a smaller length.
            if result == Err(Errno::INVAL) && iov[0].len() > FALLBACK_RW_LENGTH {
                result = rustix::io::write(fd, &iov[0][..FALLBACK_RW_LENGTH]);
            }
        }
        match result {
            Ok(0) => break,
            Ok(written) => {
                IoSlice::advance_slices(&mut iov, written);
                bytes_written += written as u64;
            }
            Err(Errno::INTR) => {}
            Err(_) => break,
        }
    }
    result
        .map(|_| bytes_written)
        .map_err(|errno| errno.raw_os_error())
}

/// Write the whole iovec at `offset`; `Err` carries the errno.
// Port of erts/emulator/nifs/unix/unix_prim_file.c:452-506 (efile_pwritev, HAVE_PWRITEV),
// OTP-29.1.1.
pub(crate) fn efile_pwritev(
    fd: impl AsFd,
    mut offset: u64,
    vec: &mut IoVec<'_>,
) -> Result<u64, i32> {
    let fd = fd.as_fd();
    let mut iov: &mut [IoSlice<'_>] = &mut vec.iov;
    let mut bytes_written: u64 = 0;
    let mut result: Result<usize, Errno>;
    loop {
        if iov.is_empty() {
            result = Ok(0);
            break;
        }
        result = rustix::io::pwritev(fd, iov, offset);
        match result {
            Ok(0) => break,
            Ok(written) => {
                IoSlice::advance_slices(&mut iov, written);
                bytes_written += written as u64;
                offset += written as u64;
            }
            Err(Errno::INTR) => {}
            Err(_) => break,
        }
    }
    result
        .map(|_| bytes_written)
        .map_err(|errno| errno.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_bifs::ProcessHeapHandle;
    use arinsal_term::{ProcessHeap, TermBuilder};

    fn list(heap: &mut ProcessHeapHandle<'_>, items: &[Term]) -> Term {
        let mut list = Term::NIL;
        for item in items.iter().rev() {
            list = TermBuilder::new(heap).cons(*item, list).unwrap();
        }
        list
    }

    #[test]
    fn refc_binaries_are_referenced_and_heap_or_unaligned_ones_copied() {
        let mut process = ProcessHeap::with_words(1024);
        let mut heap = ProcessHeapHandle(&mut process);
        let data: Vec<u8> = (0..=255).cycle().take(1 << 20).collect();
        let refc = TermBuilder::new(&mut heap).binary(&data).unwrap();
        let small = TermBuilder::new(&mut heap).binary(b"small").unwrap();
        let empty = TermBuilder::new(&mut heap).binary(b"").unwrap();
        let input = list(&mut heap, &[refc, empty, small, refc]);
        let refc_bytes = part(refc).unwrap().bytes.as_ptr();
        let mut copy = Vec::new();
        let vec = inspect_iovec(input, 64, &mut copy).unwrap();
        assert_eq!(vec.tail, Term::NIL);
        assert_eq!(vec.iov.len(), 3);
        // The refc binary is written from its own bytes: no payload copy.
        assert_eq!(vec.iov[0].as_ptr(), refc_bytes);
        assert_eq!(vec.iov[0].len(), data.len());
        assert_eq!(vec.iov[2].as_ptr(), refc_bytes);
        // The heap binary is copied, as erts copies on-heap binaries.
        assert_eq!(&*vec.iov[1], b"small");
        assert_eq!(copy, b"small");
    }

    #[test]
    fn unaligned_bits_are_copied_and_the_tail_is_kept() {
        let bytes = [0b1010_1010, 0b1100_1100, 0b1111_0000];
        let mut out = [0; 2];
        copy_binary_to_buffer(&mut out, &bytes, 3);
        assert_eq!(out, [0b0101_0110, 0b0110_0111]);
        let mut process = ProcessHeap::with_words(1024);
        let mut heap = ProcessHeapHandle(&mut process);
        let item = TermBuilder::new(&mut heap).binary(b"x").unwrap();
        let input = list(&mut heap, &[item; 65]);
        let mut copy = Vec::new();
        let vec = inspect_iovec(input, 64, &mut copy).unwrap();
        assert_eq!(vec.iov.len(), 64);
        let (_, rest) = cell(vec.tail).unwrap();
        assert_eq!(rest, Term::NIL);
        let bits = TermBuilder::new(&mut heap).bitstring(b"\xff", 7).unwrap();
        let improper = TermBuilder::new(&mut heap).cons(bits, Term::NIL).unwrap();
        assert!(inspect_iovec(improper, 64, &mut copy).is_none());
    }
}

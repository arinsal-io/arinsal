//! The port I/O queue behind `driver_enq` and friends.
//!
//! Port of erts/emulator/beam/erl_io_queue.c (driver variant), OTP-29.1.1: a
//! deque of `SysIOVec` slices, each referencing a reference-counted driver
//! binary. Addresses are kept as integers so the queue is `Send`; the peek
//! functions hand the contiguous element array to the driver as erts does.

use crate::binary::{self, ErlDrvBinary};
use crate::mem;
use crate::{ErlIOVec, SysIOVec};

/// One queued slice: `iov_base`, `iov_len`.
type Slot = [usize; 2];

/// `ErtsIOQueue` of a driver port.
#[derive(Default)]
pub(crate) struct IoQueue {
    iov: Vec<Slot>,
    /// Binary owning the slice at the same index of `iov`.
    binv: Vec<usize>,
    /// Index of the first live element; everything before it is dead.
    head: usize,
    size: usize,
}

/// Port of erl_io_queue.c:152 (skip): index of the first element of `vec` left
/// after `skip` bytes. As in erts the driver's own vector is edited: the element
/// that is cut keeps only its remainder.
pub(crate) fn skip_in_place(vec: &ErlIOVec, mut skip: usize) -> Option<usize> {
    if vec.size <= skip {
        return None;
    }
    let iov = mem::slice_mut(vec.iov, usize::try_from(vec.vsize).ok()?);
    let mut at = 0;
    // The `do` loop of erts strips one leading empty element even for skip 0.
    loop {
        let len = iov.get(at)?.iov_len;
        if len <= skip {
            skip -= len;
            at += 1;
            if skip == 0 {
                return Some(at);
            }
        } else {
            iov[at].iov_base = iov[at].iov_base.wrapping_add(skip);
            iov[at].iov_len = len - skip;
            return Some(at);
        }
    }
}

impl IoQueue {
    /// Bytes queued (`erts_ioq_size`).
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    /// The new slots of `vec` after `skip` bytes, binaries referenced.
    /// `None` on allocation failure.
    fn slots(vec: &ErlIOVec, skip: usize) -> Option<Vec<(Slot, usize)>> {
        let Some(first) = skip_in_place(vec, skip) else {
            return Some(Vec::new());
        };
        let count = usize::try_from(vec.vsize).ok()?;
        let iov = mem::slice(vec.iov.cast_const(), count);
        let binv = mem::slice(vec.binv.cast_const(), count);
        let mut out = Vec::new();
        for at in first..count {
            let (base, len) = (iov[at].iov_base as usize, iov[at].iov_len);
            if len == 0 {
                continue;
            }
            let bin = binv[at];
            if bin.is_null() {
                // Special case in erts: the driver passed no binary, so copy.
                let copy = binary::from_bytes(mem::slice(base as *const u8, len));
                if copy.is_null() {
                    for (_, bin) in out {
                        binary::free_binary(bin as *mut ErlDrvBinary);
                    }
                    return None;
                }
                out.push(([binary::bytes_ptr(copy) as usize, len], copy as usize));
            } else {
                binary::inc_refc(bin);
                out.push(([base, len], bin as usize));
            }
        }
        Some(out)
    }

    /// Port of erl_io_queue.c:229 (erts_ioq_enqv): `-1` on failure.
    pub(crate) fn enqv(&mut self, vec: &ErlIOVec, skip: usize) -> i32 {
        if vec.size <= skip {
            return 0;
        }
        let Some(slots) = Self::slots(vec, skip) else {
            return -1;
        };
        for (slot, bin) in slots {
            self.iov.push(slot);
            self.binv.push(bin);
        }
        self.size += vec.size - skip;
        0
    }

    /// Port of erl_io_queue.c:285 (erts_ioq_pushqv).
    pub(crate) fn pushqv(&mut self, vec: &ErlIOVec, skip: usize) -> i32 {
        if vec.size <= skip {
            return 0;
        }
        let Some(slots) = Self::slots(vec, skip) else {
            return -1;
        };
        let (iov, binv): (Vec<Slot>, Vec<usize>) = slots.into_iter().unzip();
        self.iov.splice(self.head..self.head, iov);
        self.binv.splice(self.head..self.head, binv);
        self.size += vec.size - skip;
        0
    }

    /// Port of erl_io_queue.c:337 (erts_ioq_deq): `false` when fewer than
    /// `size` bytes are queued.
    pub(crate) fn deq(&mut self, mut size: usize) -> bool {
        if self.size < size {
            return false;
        }
        self.size -= size;
        while size > 0 {
            let slot = &mut self.iov[self.head];
            if slot[1] <= size {
                size -= slot[1];
                binary::free_binary(self.binv[self.head] as *mut ErlDrvBinary);
                self.binv[self.head] = 0;
                self.head += 1;
            } else {
                slot[0] += size;
                slot[1] -= size;
                size = 0;
            }
        }
        if self.head == self.iov.len() {
            self.iov.clear();
            self.binv.clear();
            self.head = 0;
        }
        true
    }

    /// Port of erl_io_queue.c:373 (erts_ioq_peekqv): fill `ev` with the queue.
    pub(crate) fn peekqv(&mut self, ev: &mut ErlIOVec) -> usize {
        let live = self.iov.len() - self.head;
        ev.vsize = live as i32;
        if live == 0 {
            ev.size = 0;
            ev.iov = std::ptr::null_mut();
            ev.binv = std::ptr::null_mut();
        } else {
            ev.size = self.size;
            ev.iov = self
                .iov
                .as_mut_ptr()
                .wrapping_add(self.head)
                .cast::<SysIOVec>();
            ev.binv = self
                .binv
                .as_mut_ptr()
                .wrapping_add(self.head)
                .cast::<*mut ErlDrvBinary>();
        }
        self.size
    }

    /// Port of erl_io_queue.c:392 (erts_ioq_peekq): the element array and its length.
    pub(crate) fn peekq(&mut self) -> (*mut SysIOVec, i32) {
        let live = self.iov.len() - self.head;
        if live == 0 {
            return (std::ptr::null_mut(), 0);
        }
        let base: *mut Slot = self.iov.as_mut_ptr().wrapping_add(self.head);
        (base.cast::<SysIOVec>(), live as i32)
    }

    /// Port of erl_io_queue.c:58 (erts_ioq_clear): drop every queued binary.
    pub(crate) fn clear(&mut self) {
        for bin in self.binv.drain(self.head.min(self.binv.len())..) {
            binary::free_binary(bin as *mut ErlDrvBinary);
        }
        self.binv.clear();
        self.iov.clear();
        self.head = 0;
        self.size = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-segment vector over `bin`.
    fn vector(
        bin: *mut ErlDrvBinary,
        len: usize,
        iov: &mut SysIOVec,
        binv: &mut *mut ErlDrvBinary,
    ) -> ErlIOVec {
        iov.iov_base = binary::bytes_ptr(bin).cast();
        iov.iov_len = len;
        *binv = bin;
        ErlIOVec {
            vsize: 1,
            size: len,
            iov,
            binv,
        }
    }

    fn contents(queue: &mut IoQueue) -> Vec<u8> {
        let (iov, count) = queue.peekq();
        mem::slice(iov.cast_const(), count as usize)
            .iter()
            .flat_map(|slot| {
                mem::slice(slot.iov_base.cast_const().cast::<u8>(), slot.iov_len).to_vec()
            })
            .collect()
    }

    #[test]
    fn enq_push_and_deq_follow_erts() {
        let bin = binary::from_bytes(b"abcdef");
        let (mut iov, mut binv) = (
            SysIOVec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
            std::ptr::null_mut(),
        );
        let ev = vector(bin, 6, &mut iov, &mut binv);
        let mut queue = IoQueue::default();
        assert_eq!(queue.enqv(&ev, 2), 0);
        assert_eq!(queue.size(), 4);
        assert_eq!(binary::get_refc(bin), 2);
        let ev = vector(bin, 2, &mut iov, &mut binv);
        assert_eq!(queue.pushqv(&ev, 0), 0);
        assert_eq!(contents(&mut queue), b"abcdef");
        assert!(!queue.deq(7));
        assert!(queue.deq(3));
        assert_eq!(contents(&mut queue), b"def");
        assert_eq!(queue.size(), 3);
        queue.clear();
        assert_eq!(binary::get_refc(bin), 1);
        binary::free_binary(bin);
    }

    #[test]
    fn missing_binary_is_copied() {
        let mut data = *b"xyz";
        let mut iov = SysIOVec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: 3,
        };
        let mut binv: *mut ErlDrvBinary = std::ptr::null_mut();
        let ev = ErlIOVec {
            vsize: 1,
            size: 3,
            iov: &mut iov,
            binv: &mut binv,
        };
        let mut queue = IoQueue::default();
        assert_eq!(queue.enqv(&ev, 0), 0);
        data[0] = b'!';
        std::hint::black_box(&data);
        assert_eq!(contents(&mut queue), b"xyz");
        assert!(queue.deq(3));
        assert_eq!(queue.peekq().1, 0);
    }
}

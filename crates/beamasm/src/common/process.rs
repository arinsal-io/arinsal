//! `offsetof(Process, field)` of the fields native code addresses through `c_p`, the same
//! compile-time constants on every architecture.
//!
//! Port of erts/emulator/beam/erl_process.h (struct process), OTP-29.1.1: Arinsal's
//! `ProcessHeader` is the native prefix of the process.

use crate::ProcessHeader;
use core::mem::offset_of;

/// `offsetof(Process, htop)`.
pub const HTOP: i32 = offset_of!(ProcessHeader, htop) as i32;
/// `offsetof(Process, stop)`.
pub const STOP: i32 = offset_of!(ProcessHeader, stop) as i32;
/// `offsetof(Process, heap)`.
pub const HEAP: i32 = offset_of!(ProcessHeader, heap) as i32;
/// `offsetof(Process, hend)`.
pub const HEND: i32 = offset_of!(ProcessHeader, hend) as i32;
/// `offsetof(Process, fcalls)`.
pub const FCALLS: i32 = offset_of!(ProcessHeader, fcalls) as i32;
/// `offsetof(Process, freason)`.
pub const FREASON: i32 = offset_of!(ProcessHeader, exc.freason) as i32;
/// `offsetof(Process, fvalue)`.
pub const FVALUE: i32 = offset_of!(ProcessHeader, exc.fvalue) as i32;
/// `offsetof(Process, ftrace)`.
pub const FTRACE: i32 = offset_of!(ProcessHeader, exc.ftrace) as i32;
/// `offsetof(Process, i)`.
pub const I: i32 = offset_of!(ProcessHeader, i) as i32;
/// `offsetof(Process, arity)`.
pub const ARITY: i32 = offset_of!(ProcessHeader, arity) as i32;
/// `offsetof(Process, current)`.
pub const CURRENT: i32 = offset_of!(ProcessHeader, current) as i32;
/// `offsetof(Process, common.id)`.
pub const SELF_PID: i32 = offset_of!(ProcessHeader, self_pid) as i32;
/// `offsetof(Process, flags)`.
pub const FLAGS: i32 = offset_of!(ProcessHeader, flags) as i32;
/// `offsetof(Process, catches)`.
// Port of erts/emulator/beam/erl_process.h (struct process), OTP-29.1.1.
pub const CATCHES: i32 = offset_of!(ProcessHeader, catches) as i32;
/// `offsetof(Process, mbuf)`.
pub const MBUF: i32 = offset_of!(ProcessHeader, mbuf) as i32;
/// `offsetof(Process, mbuf_sz)`.
pub const MBUF_SZ: i32 = offset_of!(ProcessHeader, mbuf_sz) as i32;
/// `offsetof(Process, bin_vheap_sz)`. The process starts with its `ProcessHeap` (the VM
/// asserts `offset_of!(Process, heap) == 0`), so the heap's offsets are `c_p`'s.
pub const BIN_VHEAP_SZ: i32 = arinsal_term::ProcessHeap::BIN_VHEAP_SIZE_OFFSET as i32;
/// `offsetof(Process, off_heap.overhead)`, see [`BIN_VHEAP_SZ`].
pub const OFF_HEAP_OVERHEAD: i32 = arinsal_term::ProcessHeap::OFF_HEAP_OVERHEAD_OFFSET as i32;

const _: () = assert!(
    FLAGS as usize == arinsal_term::ProcessHeap::FLAGS_OFFSET
        && MBUF_SZ as usize == arinsal_term::ProcessHeap::MBUF_SZ_OFFSET
);

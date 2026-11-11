//! Thread creation with a known stack size and the per-thread stack limit.
//!
//! Port of erts/lib_src/pthread/ethread.c (`ethr_thr_create`, `thr_wrapper`) and
//! erts/lib_src/common/ethr_aux.c (`ethr_set_stacklimit__`, `ethr_get_stacklimit`),
//! OTP-29.1.1. Recursive erts code (the match-spec compiler, PCRE compile) bounds its
//! recursion by this limit instead of a fixed depth.

use std::cell::Cell;
use std::io;
use std::sync::OnceLock;
use std::thread::{self, JoinHandle};

thread_local! {
    /// `ethr_stacklimit_key__`: the lowest usable stack address of an ethr-created thread,
    /// or 0 on a thread that was not created by [`ethr_thr_create`].
    static STACKLIMIT: Cell<usize> = const { Cell::new(0) };
}

/// Bytes per kilo word (`ETHR_KW2B(1)`).
const KW_BYTES: usize = std::mem::size_of::<usize>() * 1024;

struct StackBounds {
    page: usize,
    min: usize,
    max: usize,
}

fn page_align(size: usize, page: usize) -> usize {
    // Port of erts/include/internal/ethr_internal.h (ETHR_PAGE_ALIGN), OTP-29.1.1.
    (size.saturating_sub(1) / page + 1) * page
}

// Port of erts/lib_src/common/ethr_aux.c (ethr_init_common__ stack sizes), OTP-29.1.1.
fn stack_bounds() -> &'static StackBounds {
    static BOUNDS: OnceLock<StackBounds> = OnceLock::new();
    BOUNDS.get_or_init(|| {
        let page = crate::raw::page_size();
        // At least 4 KB for the user, doubled on 64-bit, about 4 KB for the system, and room
        // for signal handlers.
        let mut min = 4 * 1024 * 2 + 4 * 1024 + libc::SIGSTKSZ;
        min = min.max(libc::PTHREAD_STACK_MIN);
        // ETHR_STACK_GUARD_SIZE: the guard page counts in the requested size.
        min += page;
        let min = page_align(min, page);
        let max = page_align(32 * 1024 * 1024 * 2, page);
        StackBounds { page, min, max }
    })
}

/// Stack size in bytes requested for a thread suggested `suggested_kw` kilo words, and the
/// usable part of it that becomes the thread's stack limit.
// Port of erts/lib_src/pthread/ethread.c (ethr_thr_create stack size), OTP-29.1.1.
fn thread_stack_size(suggested_kw: usize) -> (usize, usize) {
    let bounds = stack_bounds();
    let mut stack_size = page_align(suggested_kw * KW_BYTES, bounds.page);
    // One page for possible system usage and one for the guard (ETHR_STACK_GUARD_SIZE).
    stack_size += 2 * bounds.page;
    stack_size = stack_size.clamp(bounds.min, bounds.max);
    (stack_size, stack_size - 2 * bounds.page)
}

/// Create a named thread with a stack of `suggested_stack_size` kilo words (the system default
/// when `None`), and record its stack limit before `f` runs.
// Port of erts/lib_src/pthread/ethread.c (ethr_thr_create), OTP-29.1.1.
pub fn ethr_thr_create<F, T>(
    name: Option<String>,
    suggested_stack_size: Option<usize>,
    f: F,
) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let mut builder = thread::Builder::new();
    if let Some(name) = name {
        builder = builder.name(name);
    }
    let mut usable = 0;
    if let Some(kw) = suggested_stack_size {
        let (stack_size, stacksize) = thread_stack_size(kw);
        builder = builder.stack_size(stack_size);
        usable = stacksize;
    }
    builder.spawn(move || thr_wrapper(usable, f))
}

// Port of erts/lib_src/pthread/ethread.c (thr_wrapper), OTP-29.1.1.
#[inline(never)]
fn thr_wrapper<F: FnOnce() -> T, T>(stacksize: usize, f: F) -> T {
    let c = 0u8;
    ethr_set_stacklimit__(
        std::hint::black_box(std::ptr::addr_of!(c)) as usize,
        stacksize,
    );
    f()
}

/// Record the stack limit of the current thread from an address near its stack start.
// Port of erts/lib_src/common/ethr_aux.c (ethr_set_stacklimit__), OTP-29.1.1.
#[inline(never)]
fn ethr_set_stacklimit__(prev_c: usize, stacksize: usize) {
    let c = 0u8;
    let here = std::hint::black_box(std::ptr::addr_of!(c)) as usize;
    let mut limit = 0;
    if stacksize != 0 {
        let page = stack_bounds().page;
        if here > prev_c {
            limit = (prev_c / page) * page + stacksize;
        } else {
            limit = ((prev_c - 1) / page + 1) * page - stacksize;
        }
    }
    STACKLIMIT.with(|cell| cell.set(limit));
}

/// The stack limit of the current thread, or 0 when it was not created by
/// [`ethr_thr_create`] with a stack size.
// Port of erts/lib_src/common/ethr_aux.c (ethr_get_stacklimit), OTP-29.1.1.
pub fn ethr_get_stacklimit() -> usize {
    STACKLIMIT.with(Cell::get)
}

/// `erts_get_stacklimit`.
// Port of erts/emulator/beam/utils.c (erts_get_stacklimit), OTP-29.1.1.
pub fn erts_get_stacklimit() -> usize {
    ethr_get_stacklimit()
}

/// Whether `ptr` lies below `limit`; kept out of line so the caller's frame is real.
// Port of erts/emulator/beam/utils.c (erts_check_below_limit), OTP-29.1.1.
#[inline(never)]
pub fn erts_check_below_limit(ptr: usize, limit: usize) -> bool {
    ptr < limit
}

/// Whether `ptr` lies above `limit`; kept out of line so the caller's frame is real.
// Port of erts/emulator/beam/utils.c (erts_check_above_limit), OTP-29.1.1.
#[inline(never)]
pub fn erts_check_above_limit(ptr: usize, limit: usize) -> bool {
    ptr > limit
}

/// Whether the stack grows towards lower addresses, judged from a caller's local `ptr`.
// Port of erts/emulator/beam/utils.c (erts_check_if_stack_grows_downwards), OTP-29.1.1.
#[inline(never)]
pub fn erts_check_if_stack_grows_downwards(ptr: usize) -> bool {
    let c = 0u8;
    erts_check_below_limit(std::hint::black_box(std::ptr::addr_of!(c)) as usize, ptr)
}

/// Address of a local in the caller's frame, for the stack guards.
#[inline(always)]
pub fn stack_marker() -> usize {
    let c = 0u8;
    std::hint::black_box(std::ptr::addr_of!(c)) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_thread_has_a_limit_inside_its_stack() {
        let handle = ethr_thr_create(Some("ethr_test".into()), Some(128), || {
            let limit = erts_get_stacklimit();
            let here = stack_marker();
            (limit, here)
        })
        .unwrap();
        let (limit, here) = handle.join().unwrap();
        assert_ne!(limit, 0);
        assert!(here > limit);
        // 128 kilo words is 1 MiB on 64-bit.
        assert!(here - limit <= 128 * KW_BYTES);
        assert!(here - limit > 128 * KW_BYTES - 64 * 1024);
    }

    #[test]
    fn foreign_thread_has_no_limit() {
        assert_eq!(thread::spawn(erts_get_stacklimit).join().unwrap(), 0);
    }
}

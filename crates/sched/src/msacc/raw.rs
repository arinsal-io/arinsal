//! Raw per-thread storage for `erts_msacc_key`.
//!
//! Port of `erts/emulator/beam/erl_msacc.h` and `erl_msacc.c` (OTP-29.1.1).

use super::{MsAccAction, MsAccSnapshot};
use crate::{MSACC_STATE_COUNT, MsaccState};
use arinsal_term::Term;
use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

#[repr(transparent)]
#[derive(Clone, Copy)]
pub(super) struct ErtsMsAccPtr(*mut ErtsMsAcc);

// SAFETY: the pointer names one runtime-lifetime allocation. Managed access stays on its
// owning thread; unmanaged access is protected by the entry's mutex.
unsafe impl Send for ErtsMsAccPtr {}
// SAFETY: the pointer wrapper carries no access; ErtsMsAcc's data ownership is enforced above.
unsafe impl Sync for ErtsMsAccPtr {}

#[repr(C)]
// Field order and scalar representations follow erl_msacc.h. `pthread_mutex_t` is the native
// lock used by ethr on the supported Unix targets.
struct ErtsMsAcc {
    unmanaged: i32,
    mtx: MaybeUninit<libc::pthread_mutex_t>,
    next: ErtsMsAccPtr,
    tid: libc::pthread_t,
    id: Term,
    thread_type: *mut c_char,
    perf_counter: u64,
    state: usize,
    counters: [u64; MSACC_STATE_COUNT],
}

// SAFETY: the list lock protects list links and immutable metadata. Mutable counters are read
// only by their managed owner or under mtx for an unmanaged entry.
unsafe impl Send for ErtsMsAcc {}
// SAFETY: see the ownership and locking invariant above.
unsafe impl Sync for ErtsMsAcc {}

struct UnmanagedMutexGuard(*mut libc::pthread_mutex_t);

impl Drop for UnmanagedMutexGuard {
    fn drop(&mut self) {
        // SAFETY: this guard is created only after successfully locking this initialized mutex.
        if unsafe { libc::pthread_mutex_unlock(self.0) } != 0 {
            std::process::abort();
        }
    }
}

struct MsAccLists {
    managed: ErtsMsAccPtr,
    unmanaged: ErtsMsAccPtr,
    unmanaged_count: usize,
}

static MSACC_LISTS: RwLock<MsAccLists> = RwLock::new(MsAccLists {
    managed: ErtsMsAccPtr(std::ptr::null_mut()),
    unmanaged: ErtsMsAccPtr(std::ptr::null_mut()),
    unmanaged_count: 0,
});
static ENABLED: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// `ERTS_MSACC_TSD_GET()` / `ERTS_MSACC_TSD_SET()`.
    static MSACC_KEY: Cell<*mut ErtsMsAcc> = const { Cell::new(std::ptr::null_mut()) };
}

fn current_tid() -> libc::pthread_t {
    // SAFETY: pthread_self has no preconditions and returns the calling thread's identifier.
    unsafe { libc::pthread_self() }
}

fn tids_equal(left: libc::pthread_t, right: libc::pthread_t) -> bool {
    // SAFETY: both values were returned by pthread_self and remain valid thread identifiers.
    unsafe { libc::pthread_equal(left, right) != 0 }
}

fn set_tsd(msacc: *mut ErtsMsAcc) {
    MSACC_KEY.with(|key| key.set(msacc));
}

fn tsd() -> *mut ErtsMsAcc {
    MSACC_KEY.with(Cell::get)
}

pub(super) fn tsd_is_set() -> bool {
    !tsd().is_null()
}

/// Allocate one counter record and link it to the managed or unmanaged thread list.
// Port of erts/emulator/beam/erl_msacc.c (erts_msacc_init_thread), OTP-29.1.1.
pub(super) fn init_thread(thread_type: &'static str, id: i64, managed: bool) -> ErtsMsAccPtr {
    let mut mtx = MaybeUninit::<libc::pthread_mutex_t>::uninit();
    if !managed {
        // SAFETY: mtx points to suitably aligned storage and is initialized once before publication.
        if unsafe { libc::pthread_mutex_init(mtx.as_mut_ptr(), std::ptr::null()) } != 0 {
            std::process::abort();
        }
    }
    let id = Term::small(id).expect("msacc thread id fits an Erlang small integer");
    let allocation_words = core::mem::size_of::<ErtsMsAcc>().div_ceil(core::mem::size_of::<u64>());
    let allocation = arinsal_alloc::typed::AllocBlock::new(
        arinsal_alloc::typed::ErtsAlcType::MSACC,
        allocation_words,
    )
    .unwrap_or_else(|_| std::process::abort());
    let msacc_node = ErtsMsAcc {
        unmanaged: i32::from(!managed),
        mtx,
        next: ErtsMsAccPtr(std::ptr::null_mut()),
        tid: current_tid(),
        id,
        thread_type: CString::new(thread_type)
            .expect("msacc thread type has no NUL")
            .into_raw(),
        perf_counter: 0,
        state: MsaccState::Other as usize,
        counters: [0; MSACC_STATE_COUNT],
    };
    let msacc = allocation.into_raw().cast::<ErtsMsAcc>().as_ptr();
    // SAFETY: `AllocBlock` returned aligned storage for at least one ErtsMsAcc, which is written
    // exactly once and retained for the runtime lifetime like `erts_alloc(ERTS_ALC_T_MSACC)`.
    unsafe { msacc.write(msacc_node) };

    let mut lists = MSACC_LISTS.write().unwrap();
    // SAFETY: this allocation has not yet been published to another thread.
    unsafe {
        if managed {
            (*msacc).next = lists.managed;
            lists.managed = ErtsMsAccPtr(msacc);
        } else {
            (*msacc).next = lists.unmanaged;
            lists.unmanaged = ErtsMsAccPtr(msacc);
            lists.unmanaged_count += 1;
            set_tsd(msacc);
        }
    }
    ErtsMsAccPtr(msacc)
}

pub(super) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub(super) fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

fn lock_unmanaged(msacc: *mut ErtsMsAcc) -> Option<UnmanagedMutexGuard> {
    // SAFETY: all ErtsMsAcc nodes are retained for runtime lifetime, and the unmanaged mutex is
    // initialized before the node is linked into a list.
    unsafe {
        if (*msacc).unmanaged != 0 {
            let mutex = (*msacc).mtx.as_mut_ptr();
            if libc::pthread_mutex_lock(mutex) != 0 {
                std::process::abort();
            }
            Some(UnmanagedMutexGuard(mutex))
        } else {
            None
        }
    }
}

unsafe fn update(msacc: *mut ErtsMsAcc) {
    // SAFETY: callers own this managed entry or hold its unmanaged mutex. The mutable accesses
    // below touch only counter fields; they do not alias the separately locked mtx field.
    unsafe {
        if (*msacc).perf_counter == 0 {
            return;
        }
        let now = crate::sys_time::erts_sys_perf_counter();
        let state = (*msacc).state;
        (*msacc).counters[state] =
            (*msacc).counters[state].wrapping_add(now.wrapping_sub((*msacc).perf_counter));
        (*msacc).perf_counter = now;
    }
}

fn current_state(msacc: *mut ErtsMsAcc) -> MsaccState {
    let _guard = lock_unmanaged(msacc);
    // SAFETY: managed state is read only by its owning thread; unmanaged state is locked above.
    unsafe { state_from_index((*msacc).state) }
}

fn switch_state(msacc: *mut ErtsMsAcc, state: MsaccState) {
    let _guard = lock_unmanaged(msacc);
    // SAFETY: managed state is written only by its owning thread; unmanaged state is locked above.
    unsafe {
        if (*msacc).state != state as usize {
            if (*msacc).perf_counter == 0 {
                (*msacc).state = state as usize;
                return;
            }
            update(msacc);
            (*msacc).state = state as usize;
        }
    }
}

pub(super) fn set_current_state(state: MsaccState) {
    if !enabled() {
        return;
    }
    let msacc = tsd();
    if !msacc.is_null() {
        switch_state(msacc, state);
    }
}

pub(super) fn push_and_set_state(state: MsaccState) -> Option<CachedMsAccState> {
    if !enabled() {
        return None;
    }
    let msacc = tsd();
    if msacc.is_null() {
        return None;
    }
    let previous = current_state(msacc);
    switch_state(msacc, state);
    Some(CachedMsAccState { msacc, previous })
}

pub(super) struct CachedMsAccState {
    msacc: *mut ErtsMsAcc,
    previous: MsaccState,
}

pub(super) fn restore_state(cached: Option<CachedMsAccState>) {
    if let Some(cached) = cached {
        switch_state(cached.msacc, cached.previous);
    }
}

pub(super) fn apply_managed(msacc: ErtsMsAccPtr, action: MsAccAction) {
    let ptr = msacc.0;
    debug_assert!(!ptr.is_null());
    // SAFETY: managed actions execute on the scheduler thread that owns this entry.
    unsafe {
        debug_assert_eq!((*ptr).unmanaged, 0);
        debug_assert!(tids_equal((*ptr).tid, current_tid()));
        match action {
            MsAccAction::Enable => {
                if !tsd().is_null() {
                    return;
                }
                (*ptr).perf_counter = crate::sys_time::erts_sys_perf_counter();
                (*ptr).state = MsaccState::Other as usize;
                set_tsd(ptr);
            }
            MsAccAction::Disable => {
                if !tsd().is_null() {
                    set_tsd(std::ptr::null_mut());
                }
            }
            MsAccAction::Reset => (*ptr).counters = [0; MSACC_STATE_COUNT],
        }
    }
}

fn find_current_managed() -> *mut ErtsMsAcc {
    let tid = current_tid();
    let lists = MSACC_LISTS.read().unwrap();
    let mut ptr = lists.managed.0;
    while !ptr.is_null() {
        // SAFETY: the read lock protects list links and nodes remain allocated for runtime lifetime.
        unsafe {
            if tids_equal((*ptr).tid, tid) {
                return ptr;
            }
            ptr = (*ptr).next.0;
        }
    }
    panic!("managed thread has no ErtsMsAcc entry");
}

pub(super) fn apply_current_managed(action: MsAccAction) {
    let current = tsd();
    if (action == MsAccAction::Disable && current.is_null())
        || (action == MsAccAction::Enable && !current.is_null())
    {
        return;
    }
    let msacc = if current.is_null() {
        ErtsMsAccPtr(find_current_managed())
    } else {
        ErtsMsAccPtr(current)
    };
    apply_managed(msacc, action);
}

fn snapshot(msacc: &ErtsMsAcc) -> MsAccSnapshot {
    // SAFETY: thread_type is a NUL-terminated CString retained with the leaked entry.
    let thread_type = unsafe { CStr::from_ptr(msacc.thread_type) }
        .to_string_lossy()
        .into_owned();
    MsAccSnapshot {
        thread_type,
        id: msacc
            .id
            .as_small()
            .expect("msacc id is a tagged small integer"),
        counters: msacc.counters,
    }
}

pub(super) fn gather_current_managed() -> MsAccSnapshot {
    let mut msacc = tsd();
    if msacc.is_null() {
        msacc = find_current_managed();
    }
    // SAFETY: this callback runs on the managed owner of the entry.
    snapshot(unsafe { &*msacc })
}

/// Apply the unmanaged-thread action while holding the list lock and each entry lock.
// Port of erts/emulator/beam/erl_msacc.c (unmanaged action branches of erts_msacc_request), OTP-29.1.1.
pub(super) fn request_unmanaged(action: MsAccAction) {
    let lists = MSACC_LISTS.read().unwrap();
    let mut ptr = lists.unmanaged.0;
    while !ptr.is_null() {
        let _guard = lock_unmanaged(ptr);
        // SAFETY: the unmanaged entry is locked above and remains linked for runtime lifetime.
        unsafe {
            match action {
                MsAccAction::Enable => {
                    (*ptr).perf_counter = crate::sys_time::erts_sys_perf_counter();
                    (*ptr).state = MsaccState::Sleep as usize;
                }
                MsAccAction::Disable => {
                    let now = crate::sys_time::erts_sys_perf_counter();
                    (*ptr).counters[(*ptr).state] = (*ptr).counters[(*ptr).state]
                        .wrapping_add(now.wrapping_sub((*ptr).perf_counter));
                    (*ptr).perf_counter = 0;
                }
                MsAccAction::Reset => (*ptr).counters = [0; MSACC_STATE_COUNT],
            }
            ptr = (*ptr).next.0;
        }
    }
}

fn state_from_index(state: usize) -> MsaccState {
    match state {
        0 => MsaccState::Aux,
        1 => MsaccState::CheckIo,
        2 => MsaccState::Emulator,
        3 => MsaccState::Gc,
        4 => MsaccState::Other,
        5 => MsaccState::Port,
        6 => MsaccState::Sleep,
        _ => unreachable!("ErtsMsAcc state is set from MsaccState"),
    }
}

/// Read unmanaged counters after dropping the global list lock.
pub(super) fn gather_unmanaged() -> Vec<MsAccSnapshot> {
    let entries = {
        let lists = MSACC_LISTS.read().unwrap();
        let mut entries = Vec::with_capacity(lists.unmanaged_count);
        let mut ptr = lists.unmanaged.0;
        while !ptr.is_null() {
            entries.push(ErtsMsAccPtr(ptr));
            // SAFETY: list links are immutable after publication and protected by read lock.
            ptr = unsafe { (*ptr).next.0 };
        }
        entries
    };
    entries
        .into_iter()
        .map(|entry| {
            let _guard = lock_unmanaged(entry.0);
            // SAFETY: the unmanaged entry is locked above and remains allocated.
            unsafe {
                if (*entry.0).perf_counter != 0 {
                    update(entry.0);
                }
                snapshot(&*entry.0)
            }
        })
        .collect()
}

//! Checked views of the raw pointers and terms a NIF passes through the C ABI.
//!
//! Each helper holds the one `unsafe` block for its pattern, with the contract of the NIF API
//! as its safety argument, so call sites stay free of repeated blocks.
use arinsal_term::raw::magic_bin::MagicMonitor;
use arinsal_term::{BinaryRef, FloatRef, ListIter, MagicBin, MagicPayload, Term, TupleRef};
use std::ffi::{CStr, c_char, c_void};

/// A magic payload whose destructor defers payload destruction until its monitor state reaches
/// zero, and whose monitor state stays at a stable address inside the payload.
///
/// # Safety
/// `monitor_state` must return the same state that the payload's magic destructor checks before
/// dropping the payload. The state must remain allocated until all counts added through it have
/// been released.
pub unsafe trait MonitoredResourcePayload: MagicPayload {
    /// The payload's monitor state, if this resource supports process monitors.
    fn monitor_state(&self) -> Option<&crate::res_monitor::ResourceMonitors>;

    /// The monitor state reached from an already protected target half.
    fn monitor_state_from_bin(bin: &MagicMonitor) -> &crate::res_monitor::ResourceMonitors {
        Self::monitor_state(
            bin.downcast_ref::<Self>()
                .expect("a resource monitor holds its payload type"),
        )
        .expect("a monitored payload has monitor state")
    }

    /// The monitor state reached from a counted owner, if this payload supports monitors.
    fn monitor_state_from_owner(owner: &MagicBin) -> Option<&crate::res_monitor::ResourceMonitors> {
        owner.downcast_ref::<Self>().and_then(Self::monitor_state)
    }
}

// SAFETY: the resource destructor reads this same embedded monitor state before it may drop the
// payload; the magic block keeps the state at a stable address until its monitor count is zero.
unsafe impl MonitoredResourcePayload for crate::resources::Resource {
    fn monitor_state(&self) -> Option<&crate::res_monitor::ResourceMonitors> {
        self.monitors.as_ref()
    }
}

/// Adopts the resource count owned by an `enif_*_resource` C pointer.
///
/// # Safety
/// `data` must be a live resource pointer whose C caller owns one count from
/// `enif_alloc_resource` or `enif_keep_resource`.
unsafe fn adopt_resource_count(data: *mut c_void) -> Option<MagicBin> {
    // SAFETY: forwarded `erl_nif.c` count ownership contract.
    unsafe {
        MagicBin::from_trailing_data::<crate::resources::Resource>(
            data.cast(),
            crate::resources::DATA_ALIGN,
        )
    }
}

/// Gives one resource count from Rust to the `enif_*_resource` C owner.
///
/// # Safety
/// The caller must transfer this count to a C owner that will use the resource pointer under
/// the `enif_keep_resource` / `enif_release_resource` contract.
unsafe fn give_resource_count_to_c(owner: MagicBin) -> Option<*mut c_void> {
    // SAFETY: forwarded `erl_nif.c` count transfer contract.
    unsafe {
        MagicBin::into_trailing_data::<crate::resources::Resource>(
            owner,
            crate::resources::DATA_ALIGN,
        )
    }
    .map(|data| data.cast())
}

/// Runs `visit` with the count passed by C, then returns that count to the same C owner.
pub(crate) fn with_resource<R>(data: *mut c_void, visit: impl FnOnce(&MagicBin) -> R) -> Option<R> {
    // SAFETY: NIF C ABI entry points and runtime resource callbacks pass a pointer whose C
    // owner holds one count; that same count is returned after the borrowed access.
    unsafe {
        let owner = adopt_resource_count(data)?;
        let result = visit(&owner);
        let _ = give_resource_count_to_c(owner);
        Some(result)
    }
}

/// Gives one already-counted resource reference to C.
pub(crate) fn give_resource_count(owner: MagicBin) -> *mut c_void {
    // SAFETY: the caller transfers this count through the `enif_keep_resource` contract.
    unsafe { give_resource_count_to_c(owner) }.expect("a resource owner has trailing data")
}

/// Releases the count owned by a C `enif_*_resource` pointer.
pub(crate) fn release_resource(data: *mut c_void) {
    // SAFETY: this entry point consumes the count owned by the C caller.
    drop(unsafe { adopt_resource_count(data) });
}

/// Makes a weak monitor handle after the corresponding `ErtsResourceMonitors.refc` count was
/// added for `owner`.
pub(crate) fn monitor_ref<T: MagicPayload>(
    owner: &MagicBin,
    count: &crate::res_monitor::ResourceMonitorCount,
    monitor_state: &crate::res_monitor::ResourceMonitors,
) -> Option<MagicMonitor> {
    if !count.matches(owner, monitor_state) {
        return None;
    }
    // SAFETY: `ResourceMonitorCount` proves the external monitor count keeps this payload live.
    unsafe { owner.monitor_ref::<T>() }
}

/// Runs the deferred resource destructor after the final monitor count was released.
pub(crate) fn finish_dead_monitor(
    bin: &MagicMonitor,
    dead: crate::res_monitor::DeadResourceMonitor,
) {
    assert_eq!(bin.block_address(), dead.block);
    // SAFETY: the token is created only after `ResourceMonitors` reaches zero while dying.
    unsafe { bin.finish_dead() };
}

/// A shared reference to the object behind a pointer the NIF API contract makes valid.
pub(crate) fn deref<'a, T>(p: *const T) -> &'a T {
    // SAFETY: NIF API calls take live objects; the reference does not outlive the call.
    unsafe { &*p }
}

/// An exclusive reference to the object behind a pointer the NIF API contract makes valid.
pub(crate) fn deref_mut<'a, T>(p: *mut T) -> &'a mut T {
    // SAFETY: NIF API calls take live objects; the reference does not outlive the call.
    unsafe { &mut *p }
}

/// The NUL-terminated string a NIF passed.
pub(crate) fn cstr<'a>(p: *const c_char) -> &'a CStr {
    // SAFETY: the NIF passes a NUL-terminated string valid for the call.
    unsafe { CStr::from_ptr(p) }
}

/// The `n` elements a NIF passed at `p`.
pub(crate) fn slice<'a, T>(p: *const T, n: usize) -> &'a [T] {
    // SAFETY: the NIF passes `n` readable elements valid for the call.
    unsafe { std::slice::from_raw_parts(p, n) }
}

/// Head and tail of a list cell. The term's heap is live throughout the NIF call.
pub(crate) fn cons(t: Term) -> Option<(Term, Term)> {
    // SAFETY: the term's heap stays live and unmoved for the NIF call.
    unsafe { t.cons_ref() }
}

/// Iterator over the cells of a list term. The term's heap is live throughout the NIF call.
pub(crate) fn list_iter(t: Term) -> ListIter {
    // SAFETY: the term's heap stays live and unmoved for the NIF call.
    unsafe { ListIter::new(t) }
}

/// View of a bitstring term. The term's heap is live throughout the NIF call.
pub(crate) fn binary_view<'a>(t: Term) -> Option<BinaryRef<'a>> {
    // SAFETY: the term's heap and owner stay live and unmoved for the NIF call.
    unsafe { t.binary_ref() }
}

/// View of a float term. The term's heap is live throughout the NIF call.
pub(crate) fn float_view<'a>(t: Term) -> Option<FloatRef<'a>> {
    // SAFETY: the term's heap stays live and unmoved for the NIF call.
    unsafe { t.float_ref() }
}

/// View of a tuple term. The term's heap is live throughout the NIF call.
pub(crate) fn tuple_view<'a>(t: Term) -> Option<TupleRef<'a>> {
    // SAFETY: the term's heap stays live and unmoved for the NIF call.
    unsafe { t.tuple_ref() }
}

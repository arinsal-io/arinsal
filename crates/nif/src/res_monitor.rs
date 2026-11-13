//! Process monitors held by NIF resources (`enif_monitor_process`).
//!
//! Port of erts/emulator/beam/erl_nif.c:3040-3200 (enif_monitor_process,
//! enif_demonitor_process, erts_fire_nif_monitor), OTP-29.1.1. The origin half of a monitor
//! lives in the resource (`ErtsResourceMonitors`); the target half, [`ResourceMonitor`], is
//! inserted into the monitored process's monitor tree by a monitor signal
//! (`ERTS_MON_TYPE_RESOURCE`) and fired by the process exit handling. A monitor does not own
//! the resource: when the last reference to the resource goes away its monitors are removed
//! (demonitor signals) before the destructor runs.
use crate::ErlNifEnv;
use crate::extras::hooks;
use crate::resources::{self, Resource};
use arinsal_term::{MagicBin, MagicRef, Term};
use std::ffi::{c_int, c_void};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

/// Target half of a resource monitor (the `ERTS_MON_TYPE_RESOURCE` entry in the monitored
/// process's monitor tree).
pub struct ResourceMonitor {
    /// `tmon->other.ptr`: the resource's binary. The monitor owns no count of it; its share of
    /// `ErtsResourceMonitors.refc` keeps the memory until this target half is released.
    bin: NonNull<MagicRef>,
    /// The `ErtsResourceMonitors` inside the binary's data.
    monitors_of: MonitorsOf,
    /// `type->fn.down`, called with a counted reference to the live resource.
    down: DownFn,
    id: u64,
}

/// Locates the `ErtsResourceMonitors` of a resource binary.
/// The result borrows the binary's data, which the caller keeps (a monitor count or a
/// counted reference).
pub type MonitorsOf = fn(NonNull<MagicRef>) -> &'static ResourceMonitors;
/// The `down` callback of a resource type: the resource, the exiting pid and the monitor.
pub type DownFn = fn(&MagicBin, Term, u64);

// SAFETY: the raw binary is only touched under the resource's monitor lock or after
// `erts_refc_inc_unless` gave a count.
unsafe impl Send for ResourceMonitor {}
// SAFETY: as above.
unsafe impl Sync for ResourceMonitor {}

/// `ErtsResourceMonitors`: the origin halves of the process monitors a resource holds.
// Port of erts/emulator/beam/global.h (ErtsResourceMonitors), OTP-29.1.1.
pub struct ResourceMonitors {
    /// `lock` with `root`, `refc` and the dying flag it protects.
    lock: Mutex<MonitorState>,
}

/// The state behind `ErtsResourceMonitors.lock`.
#[derive(Default)]
struct MonitorState {
    /// `root`: target pid and monitor reference of each active monitor.
    root: Vec<(Term, u64)>,
    /// `rmon_refc`: target halves still referring to this resource's memory.
    refc: usize,
    /// `rmon_is_dying`: the resource's count reached zero and its destructor started.
    dying: bool,
}

impl Default for ResourceMonitors {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceMonitors {
    /// `erts_mtx_init` + `root = NULL`, `refc = 0` in `enif_alloc_resource`.
    pub fn new() -> Self {
        Self {
            lock: Mutex::new(MonitorState::default()),
        }
    }

    /// Insert the origin half of a new monitor and take its monitor count, before the
    /// monitor signal is sent (`enif_monitor_process`).
    pub fn add(&self, target: Term, id: u64) {
        let mut state = self.lock.lock().unwrap();
        state.root.push((target, id));
        state.refc += 1;
    }

    /// Remove the origin half `id` (`enif_demonitor_process`, or a monitor signal that could
    /// not be delivered). `None` when it is not active or the resource is dying.
    pub fn remove(&self, id: u64) -> Option<Term> {
        let mut state = self.lock.lock().unwrap();
        if state.dying {
            return None;
        }
        let index = state.root.iter().position(|(_, held)| *held == id)?;
        Some(state.root.remove(index).0)
    }

    /// The first part of `run_resource_dtor`: mark the resource dying, demonitor every
    /// monitored process with `demonitor`, and tell whether the memory may go now (no target
    /// half refers to it any more). When `false`, the last target half released calls
    /// `erts_bin_free` again.
    // Port of erts/emulator/beam/erl_nif.c (run_resource_dtor), OTP-29.1.1.
    pub fn dtor_prologue(&self, demonitor: impl Fn(Term, u64)) -> bool {
        let (root, refc) = {
            let mut state = self.lock.lock().unwrap();
            let root = if state.dying {
                Vec::new()
            } else {
                state.dying = true;
                std::mem::take(&mut state.root)
            };
            (root, state.refc)
        };
        for (target, id) in root {
            demonitor(target, id);
        }
        refc == 0
    }
}

fn handle(id: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&id.to_ne_bytes());
    bytes
}

impl ResourceMonitor {
    /// The target half of monitor `id` held by the resource in `bin`. The caller has added
    /// the origin half with [`ResourceMonitors::add`], which took the monitor count this
    /// target half gives back when it is dropped.
    ///
    /// # Safety
    /// `bin` is a live resource binary whose `ErtsResourceMonitors` `monitors_of` finds, and
    /// its destructor follows the [`ResourceMonitors::dtor_prologue`] protocol.
    pub unsafe fn new(
        id: u64,
        bin: NonNull<MagicRef>,
        monitors_of: MonitorsOf,
        down: DownFn,
    ) -> Self {
        Self {
            bin,
            monitors_of,
            down,
            id,
        }
    }

    /// The monitor reference.
    pub fn id(&self) -> u64 {
        self.id
    }

    fn monitors(&self) -> &ResourceMonitors {
        (self.monitors_of)(self.bin)
    }

    /// The monitoring resource as a magic reference, for `process_info(_, monitored_by)`.
    pub fn resource_ref(&self) -> Option<MagicBin> {
        let state = self.monitors().lock.lock().unwrap();
        if state.dying {
            return None;
        }
        // SAFETY: the monitor count keeps the memory; the lock orders against the destructor
        // setting `dying`.
        unsafe { MagicBin::retain_unless_dead(self.bin) }
    }

    /// The monitored process `pid` exits: run the `down` callback of a live resource.
    // Port of erts/emulator/beam/erl_nif.c (erts_fire_nif_monitor), OTP-29.1.1. The monitor
    // count is given back when this target half is released ([`Drop`]).
    pub fn fire(&self, pid: Term) {
        let counted = {
            let mut state = self.monitors().lock.lock().unwrap();
            let active = !state.dying && state.root.iter().any(|(_, id)| *id == self.id);
            if !active {
                return;
            }
            state.root.retain(|(_, id)| *id != self.id);
            // SAFETY: the monitor count keeps the memory while the lock is held.
            unsafe { MagicBin::retain_unless_dead(self.bin) }
        };
        if let Some(counted) = counted {
            (self.down)(&counted, pid, self.id);
        }
    }
}

impl Drop for ResourceMonitor {
    /// The target half is released (fired, demonitored or undelivered): give back its monitor
    /// count; the last one of a dying resource frees it.
    // Port of erts/emulator/beam/erl_nif.c (erts_nif_demonitored and the `!active` arm of
    // erts_fire_nif_monitor), OTP-29.1.1.
    fn drop(&mut self) {
        let free_me = {
            let mut state = self.monitors().lock.lock().unwrap();
            state.refc -= 1;
            state.refc == 0 && state.dying
        };
        if free_me {
            // SAFETY: the count is zero and the destructor handed the free to the last
            // monitor reference.
            unsafe { MagicBin::bin_free(self.bin) };
        }
    }
}

/// `ErtsResourceMonitors` of a dynamic NIF resource binary.
fn nif_resource_monitors(bin: NonNull<MagicRef>) -> &'static ResourceMonitors {
    // SAFETY: a monitor's share of the monitor count keeps the payload until it is released.
    let resource = unsafe { MagicRef::payload_of::<Resource>(bin) };
    resource
        .monitors
        .as_ref()
        .expect("a monitored resource has monitors")
}

/// `type->fn.down` of a dynamic NIF resource.
fn nif_resource_down(bin: &MagicBin, pid: Term, id: u64) {
    resources::call_down(bin, pid, &handle(id));
}

/// `enif_monitor_process`: 0 on success, 1 when the process is not alive, -1 when the
/// resource type has no `down` callback.
// Port of erts/emulator/beam/erl_nif.c (enif_monitor_process), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn enif_monitor_process(
    _: *mut ErlNifEnv,
    obj: *mut c_void,
    pid: *const Term,
    monitor: *mut [u8; 32],
) -> c_int {
    if pid.is_null() {
        return -1;
    }
    // SAFETY: the NIF holds a reference to the resource it monitors from.
    let bin = unsafe { resources::resource_bin(obj) };
    // SAFETY: as above.
    let Some(rm) = unsafe { resources::resource_at(obj) }.monitors.as_ref() else {
        return -1;
    };
    // SAFETY: the NIF passes a pid it got from enif_get_local_pid.
    let target = unsafe { *pid };
    if target.as_pid().is_none() {
        return -1;
    }
    let id = arinsal_bifs::next_ref_id();
    // The monitor handle is optional (the caller may pass NULL).
    // SAFETY: a non-NULL monitor is writable storage of the caller.
    if let Some(out) = unsafe { monitor.as_mut() } {
        *out = handle(id);
    }
    rm.add(target, id);
    let send = hooks().lock().unwrap().resource_monitor;
    // SAFETY: a resource binary follows the dtor_prologue protocol in run_resource_dtor.
    let monitor = Arc::new(unsafe {
        ResourceMonitor::new(id, bin, nif_resource_monitors, nif_resource_down)
    });
    // erts_proc_sig_send_monitor: a process that cannot receive the signal is not alive; the
    // undelivered target half gives its monitor count back when it is dropped.
    if send.is_some_and(|send| send(target, id, monitor)) {
        0
    } else {
        rm.remove(id);
        1
    }
}

/// `enif_demonitor_process`: 0 when the monitor was removed, 1 when it was not found.
// Port of erts/emulator/beam/erl_nif.c (enif_demonitor_process), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn enif_demonitor_process(
    _: *mut ErlNifEnv,
    obj: *mut c_void,
    monitor: *const [u8; 32],
) -> c_int {
    if monitor.is_null() {
        return -1;
    }
    // SAFETY: the NIF holds a reference to the resource.
    let Some(rm) = unsafe { resources::resource_at(obj) }.monitors.as_ref() else {
        return 1;
    };
    // SAFETY: the NIF passes the monitor it got from enif_monitor_process.
    let bytes: [u8; 32] = unsafe { *monitor };
    let id = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
    let Some(target) = rm.remove(id) else {
        return 1;
    };
    send_demonitor(target, id);
    0
}

/// `erts_proc_sig_send_demonitor` for the target half `id` in process `target`.
pub(crate) fn send_demonitor(target: Term, id: u64) {
    let send = hooks().lock().unwrap().resource_demonitor;
    if let Some(send) = send {
        send(target, id);
    }
}

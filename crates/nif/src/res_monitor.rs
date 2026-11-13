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
use std::sync::Arc;

/// Target half of a resource monitor (the `ERTS_MON_TYPE_RESOURCE` entry in the monitored
/// process's monitor tree).
pub struct ResourceMonitor {
    target: Target,
    id: u64,
}

/// What the exit of the monitored process notifies.
enum Target {
    /// A resource of a dynamically loaded NIF library: `tmon->other.ptr`, the resource's
    /// binary. The monitor does not own a count; its share of `ErtsResourceMonitors.refc`
    /// keeps the memory until this target half is released.
    Resource(NonNull<MagicRef>),
    /// A resource of a built-in NIF: the resource, which the monitor does not own, and its
    /// `down` callback, called with the exiting pid and the monitor.
    Native(arinsal_term::MagicWeak, NativeDown),
}

// SAFETY: the raw binary is only touched under the resource's monitor lock or after
// `erts_refc_inc_unless` gave a count.
unsafe impl Send for Target {}
// SAFETY: as above.
unsafe impl Sync for Target {}

/// The `down` callback of a built-in NIF resource.
pub type NativeDown = Arc<dyn Fn(Term, u64) + Send + Sync>;

fn handle(id: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&id.to_ne_bytes());
    bytes
}

/// The monitors of the resource in `bin`, whose memory the caller keeps.
fn monitors<'a>(bin: NonNull<MagicRef>) -> &'a resources::ResourceMonitors {
    // SAFETY: a monitor's share of the monitor count keeps the payload until it is released.
    let resource = unsafe { MagicRef::payload_of::<Resource>(bin) };
    resource
        .monitors
        .as_ref()
        .expect("a monitored resource has monitors")
}

impl ResourceMonitor {
    /// The target half of a monitor held by a built-in NIF resource.
    pub fn native(id: u64, resource: arinsal_term::MagicWeak, down: NativeDown) -> Self {
        Self {
            target: Target::Native(resource, down),
            id,
        }
    }

    /// The monitor reference.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The monitoring resource as a magic reference, for `process_info(_, monitored_by)`.
    pub fn resource_ref(&self) -> Option<MagicBin> {
        match &self.target {
            Target::Resource(bin) => {
                let state = monitors(*bin).lock.lock().unwrap();
                if state.dying {
                    return None;
                }
                // SAFETY: the monitor count keeps the memory; the lock orders against the
                // destructor setting `dying`.
                unsafe { MagicBin::retain_unless_dead(*bin) }
            }
            Target::Native(resource, _) => resource.upgrade(),
        }
    }

    /// The monitored process `pid` exits: run the `down` callback of a live resource.
    // Port of erts/emulator/beam/erl_nif.c (erts_fire_nif_monitor), OTP-29.1.1. The monitor
    // count is given back when this target half is released ([`Drop`]).
    pub fn fire(&self, pid: Term) {
        let bin = match &self.target {
            Target::Resource(bin) => *bin,
            Target::Native(_, down) => {
                down(pid, self.id);
                return;
            }
        };
        let counted = {
            let mut state = monitors(bin).lock.lock().unwrap();
            let active = !state.dying && state.root.iter().any(|(_, id)| *id == self.id);
            if !active {
                return;
            }
            state.root.retain(|(_, id)| *id != self.id);
            // SAFETY: the monitor count keeps the memory while the lock is held.
            unsafe { MagicBin::retain_unless_dead(bin) }
        };
        if let Some(counted) = counted {
            resources::call_down(&counted, pid, &handle(self.id));
        }
    }
}

impl Drop for ResourceMonitor {
    /// The target half is released (fired or demonitored): give back its monitor count; the
    /// last one of a dying resource frees it.
    // Port of erts/emulator/beam/erl_nif.c (erts_nif_demonitored and the `!active` arm of
    // erts_fire_nif_monitor), OTP-29.1.1.
    fn drop(&mut self) {
        let Target::Resource(bin) = self.target else {
            return;
        };
        let free_me = {
            let mut state = monitors(bin).lock.lock().unwrap();
            state.refc -= 1;
            state.refc == 0 && state.dying
        };
        if free_me {
            // SAFETY: the count is zero and the destructor handed the free to the last
            // monitor reference.
            unsafe { MagicBin::bin_free(bin) };
        }
    }
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
    {
        let mut state = rm.lock.lock().unwrap();
        state.root.push((target, id));
        state.refc += 1;
    }
    let send = hooks().lock().unwrap().resource_monitor;
    let monitor = Arc::new(ResourceMonitor {
        target: Target::Resource(bin),
        id,
    });
    // erts_proc_sig_send_monitor: a process that cannot receive the signal is not alive; the
    // undelivered target half gives its monitor count back when it is dropped.
    if send.is_some_and(|send| send(target, id, monitor)) {
        0
    } else {
        rm.lock.lock().unwrap().root.retain(|(_, held)| *held != id);
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
    let target = {
        let mut state = rm.lock.lock().unwrap();
        if state.dying {
            return 1;
        }
        let Some(index) = state.root.iter().position(|(_, held)| *held == id) else {
            return 1;
        };
        state.root.remove(index).0
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

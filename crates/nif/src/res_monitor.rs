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
use arinsal_term::Term;
use std::ffi::{c_int, c_void};
use std::sync::{Arc, Weak};

/// Target half of a resource monitor (the `ERTS_MON_TYPE_RESOURCE` entry in the monitored
/// process's monitor tree).
pub struct ResourceMonitor {
    target: Target,
    id: u64,
}

/// What the exit of the monitored process notifies.
enum Target {
    /// A resource of a dynamically loaded NIF library.
    Resource(Weak<Resource>),
    /// The `down` callback of a resource of a built-in NIF, called with the exiting pid and
    /// the monitor.
    Native(NativeDown),
}

/// The `down` callback of a built-in NIF resource.
pub type NativeDown = Arc<dyn Fn(Term, u64) + Send + Sync>;

fn handle(id: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&id.to_ne_bytes());
    bytes
}

impl ResourceMonitor {
    /// The target half of a monitor held by a built-in NIF resource.
    pub fn native(id: u64, down: NativeDown) -> Self {
        Self {
            target: Target::Native(down),
            id,
        }
    }

    /// The monitor reference.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The monitoring resource as a magic reference, for `process_info(_, monitored_by)`.
    pub fn resource_ref(&self) -> Option<Arc<arinsal_term::MagicRef>> {
        match &self.target {
            Target::Resource(resource) => Some(resource.upgrade()?.magic_ref()),
            Target::Native(_) => None,
        }
    }

    /// The monitored process `pid` exits: run the `down` callback of a live resource.
    // Port of erts/emulator/beam/erl_nif.c:3086-3110 (erts_fire_nif_monitor), OTP-29.1.1.
    pub fn fire(&self, pid: Term) {
        // A resource that is being destroyed has no strong reference left: no `down`.
        let resource = match &self.target {
            Target::Resource(resource) => resource,
            Target::Native(down) => {
                down(pid, self.id);
                return;
            }
        };
        let Some(resource) = resource.upgrade() else {
            return;
        };
        {
            let mut own = resource.monitors.lock().unwrap();
            let Some(index) = own.iter().position(|(_, id)| *id == self.id) else {
                return;
            };
            own.remove(index);
        }
        resources::call_down(&resource, pid, &handle(self.id));
    }
}

/// `enif_monitor_process`: 0 on success, 1 when the process is not alive, -1 when the
/// resource type has no `down` callback.
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
    let Some(resource) = resources::owner_for(obj) else {
        return -1;
    };
    if !resources::has_down(&resource) {
        return -1;
    }
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
    resource.monitors.lock().unwrap().push((target, id));
    let send = hooks().lock().unwrap().resource_monitor;
    let monitor = Arc::new(ResourceMonitor {
        target: Target::Resource(Arc::downgrade(&resource)),
        id,
    });
    // erts_proc_sig_send_monitor: a process that cannot receive the signal is not alive.
    if send.is_some_and(|send| send(target, id, monitor)) {
        0
    } else {
        resource
            .monitors
            .lock()
            .unwrap()
            .retain(|(_, held)| *held != id);
        1
    }
}

/// `enif_demonitor_process`: 0 when the monitor was removed, 1 when it was not found.
#[unsafe(no_mangle)]
pub extern "C" fn enif_demonitor_process(
    _: *mut ErlNifEnv,
    obj: *mut c_void,
    monitor: *const [u8; 32],
) -> c_int {
    if monitor.is_null() {
        return -1;
    }
    let Some(resource) = resources::owner_for(obj) else {
        return 1;
    };
    // SAFETY: the NIF passes the monitor it got from enif_monitor_process.
    let bytes: [u8; 32] = unsafe { *monitor };
    let id = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
    let target = {
        let mut own = resource.monitors.lock().unwrap();
        let Some(index) = own.iter().position(|(_, held)| *held == id) else {
            return 1;
        };
        own.remove(index).0
    };
    send_demonitor(target, id);
    0
}

fn send_demonitor(target: Term, id: u64) {
    let send = hooks().lock().unwrap().resource_demonitor;
    if let Some(send) = send {
        send(target, id);
    }
}

/// The resource is being destroyed: demonitor every process it monitors
/// (nif_resource_dtor_prologue).
pub(crate) fn demonitor_all(resource: &Resource) {
    let held = std::mem::take(&mut *resource.monitors.lock().unwrap());
    for (target, id) in held {
        send_demonitor(target, id);
    }
}

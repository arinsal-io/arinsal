//! The VM's descriptor poller as seen by `driver_select`.
//!
//! erts keeps one poll set behind `erts_io_control` (erl_check_io.c). Here the VM owns
//! that poller (`check_io`), so the driver host asks it for one-shot readiness through
//! this trait. Registrations are one-shot like the `active_events` of erts: after a
//! readiness callback the event stays unarmed until the port task has run.

use std::io;
use std::sync::{Arc, OnceLock};

/// One-shot readiness service implemented by the VM.
pub trait PollBackend: Send + Sync {
    /// Arm `fd` for readability (`write == false`) or writability. `ready` runs once on
    /// the poller thread and must not block or call back into the driver API. `id` names
    /// the registration for [`PollBackend::deregister`]. An error means the poller
    /// rejected the descriptor (`ERTS_POLL_EV_NVAL`).
    fn register(
        &self,
        id: u64,
        fd: i32,
        write: bool,
        ready: Box<dyn FnOnce(bool) + Send>,
    ) -> io::Result<()>;
    /// Remove registration `id`; when this returns `ready` will not run any more.
    fn deregister(&self, id: u64);
}

static BACKEND: OnceLock<Arc<dyn PollBackend>> = OnceLock::new();

/// Install the process-wide poller; later calls are ignored.
pub fn set_poll_backend(backend: Arc<dyn PollBackend>) {
    let _ = BACKEND.set(backend);
}

pub(crate) fn backend() -> Option<&'static Arc<dyn PollBackend>> {
    BACKEND.get()
}

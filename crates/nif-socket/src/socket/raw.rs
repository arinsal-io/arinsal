//! Type invariant for the monitor state embedded in an esock descriptor.

use super::Handle;
use arinsal_nif::{MonitoredResourcePayload, ResourceMonitors};

// SAFETY: `Handle::esock_dtor_prologue` checks this same field before dropping the descriptor;
// the field stays in the magic block until its monitor count is zero.
unsafe impl MonitoredResourcePayload for Handle {
    fn monitor_state(&self) -> Option<&ResourceMonitors> {
        Some(&self.monitors)
    }
}

//! Process-wide services behind driver API functions that take no port:
//! the clock, the OS environment, the scheduler count and the driver list.

use std::sync::{Arc, OnceLock};

use crate::Driver;

/// What the VM provides to the driver API besides per-port [`crate::PortHost`] calls.
pub trait SystemHooks: Send + Sync {
    /// `erlang:monotonic_time(nanosecond)`.
    fn monotonic_nanos(&self) -> i128;
    /// `erlang:time_offset(nanosecond)`.
    fn time_offset_nanos(&self) -> i128;
    /// The VM's copy of the OS environment (`os:getenv/1`).
    fn getenv(&self, key: &[u8]) -> Option<Vec<u8>>;
    /// `os:putenv/2`.
    fn putenv(&self, key: &[u8], value: &[u8]);
    /// Number of async threads (`driver_system_info`).
    fn async_threads(&self) -> usize;
    /// Number of schedulers (`driver_system_info`).
    fn scheduler_threads(&self) -> usize;
    /// Port of io.c:7636 (erts_add_driver_entry): put a linked-in driver on the
    /// driver list so `open_port({spawn_driver, Name}, _)` finds it.
    fn add_driver(&self, driver: Arc<Driver>);
    /// Port of io.c:7684 (remove_driver_entry): `1` removed, `0` unknown, `-1`
    /// a dynamically loaded driver.
    fn remove_driver(&self, entry: usize) -> i32;
}

static HOOKS: OnceLock<Arc<dyn SystemHooks>> = OnceLock::new();

/// Install the VM's hooks; the first call wins.
pub fn set_system_hooks(hooks: Arc<dyn SystemHooks>) {
    let _ = HOOKS.set(hooks);
}

pub(crate) fn hooks() -> Option<&'static Arc<dyn SystemHooks>> {
    HOOKS.get()
}

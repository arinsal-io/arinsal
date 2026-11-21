//! System performance-counter entry points shared by the VM and scheduler.
//!
//! Port of `erts_sys_perf_counter` and `erts_sys_perf_counter_unit` from
//! `erts/emulator/sys/unix/erl_unix_sys.h` (OTP-29.1.1).

/// Initialize the process-wide system time table before the VM starts worker threads.
#[cfg(target_os = "linux")]
pub fn initialize() {
    crate::raw::sys_time::init();
}

/// Read the selected ERTS performance counter in its native unit.
#[cfg(target_os = "linux")]
#[inline]
pub extern "C" fn erts_sys_perf_counter() -> u64 {
    crate::raw::sys_time::perf_counter()
}

/// Return the number of performance-counter ticks per second.
#[cfg(target_os = "linux")]
pub fn erts_sys_perf_counter_unit() -> u64 {
    crate::raw::sys_time::perf_counter_unit()
}

/// Initialize the system time provider on platforms whose provider is static.
#[cfg(not(target_os = "linux"))]
pub fn initialize() {}

/// Read the platform monotonic high resolution clock in nanoseconds.
#[cfg(not(target_os = "linux"))]
pub extern "C" fn erts_sys_perf_counter() -> u64 {
    crate::raw::sys_time_fallback::perf_counter()
}

/// Return the platform high resolution clock unit.
#[cfg(not(target_os = "linux"))]
pub fn erts_sys_perf_counter_unit() -> u64 {
    1_000_000_000
}

//! Value-only libc operations used by the time and calendar BIFs.
//!
//! Port of erts/emulator/beam/erl_time_sup.c and erts/emulator/sys/unix/sys_time.c, OTP-29.1.1.

use libc::{time_t, tm};

// Port of erts/emulator/beam/erl_time_sup.c (get_time, get_sys_now), OTP-29.1.1.
pub(super) fn time() -> time_t {
    // SAFETY: a null pointer requests the current wall clock and is permitted by POSIX.
    unsafe { libc::time(std::ptr::null_mut()) }
}

pub(super) fn zero_tm() -> tm {
    // SAFETY: `tm` is a C plain data structure and zero is a valid initialized buffer.
    unsafe { std::mem::zeroed() }
}

// Port of erts/emulator/sys/unix/sys_time.c (sys_localtime_r), OTP-29.1.1.
pub(super) fn localtime(seconds: time_t) -> Option<tm> {
    let mut out = zero_tm();
    // SAFETY: `seconds` and `out` are live, aligned C values for this call.
    (!unsafe { libc::localtime_r(&seconds, &mut out) }.is_null()).then_some(out)
}

// Port of erts/emulator/beam/erl_time_sup.c (univ_to_local, local_to_univ), OTP-29.1.1.
pub(super) fn gmtime(seconds: time_t) -> Option<tm> {
    let mut out = zero_tm();
    // SAFETY: `seconds` and `out` are live, aligned C values for this call.
    (!unsafe { libc::gmtime_r(&seconds, &mut out) }.is_null()).then_some(out)
}

// Port of erts/emulator/beam/erl_time_sup.c (local_to_univ), OTP-29.1.1.
pub(super) fn mktime(value: &mut tm) -> time_t {
    // SAFETY: `value` is initialized and writable; libc normalizes the supplied calendar fields.
    unsafe { libc::mktime(value) }
}

/// Determine whether the current timezone has a daylight transition this year.
// Port of erts/emulator/sys/unix/sys_time.c (sys_init_time, sys_daylight fallback), OTP-29.1.1.
pub(super) fn daylight() -> bool {
    let now = time();
    let Some(mut date) = localtime(now) else {
        return false;
    };
    date.tm_hour = 0;
    date.tm_min = 0;
    date.tm_sec = 0;
    date.tm_mday = 1;
    for month in 0..12 {
        date.tm_mon = month;
        let timestamp = mktime(&mut date);
        if localtime(timestamp).is_some_and(|value| value.tm_isdst != 0) {
            return true;
        }
    }
    false
}

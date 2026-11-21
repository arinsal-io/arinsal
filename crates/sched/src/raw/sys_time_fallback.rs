// Port of erts/emulator/sys/unix/sys_time.c (erts_sys_hrtime), OTP-29.1.1.

/// Read the nanosecond monotonic clock used by ERTS on non-Linux Unix targets.
pub(crate) fn perf_counter() -> u64 {
    let mut value = core::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `value` is writable storage for one `timespec`, as required by clock_gettime.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
        std::process::abort();
    }
    // SAFETY: clock_gettime returned success and initialized the timespec.
    let value = unsafe { value.assume_init() };
    (value.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(value.tv_nsec as u64)
}

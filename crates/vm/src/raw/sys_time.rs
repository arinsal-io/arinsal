//! Linux x86-compatible `ErtsSysTimeData__` storage and callbacks.
// Port of erts/emulator/sys/unix/sys_time.c (`erts_init_time`, `init_perf_counter`), OTP-29.1.1.

#[repr(C)]
#[derive(Clone, Copy)]
struct ErtsSysTimeReadOnlyData {
    os_monotonic_time: extern "C" fn() -> i64,
    os_times: extern "C" fn(*mut i64, *mut i64),
    perf_counter: extern "C" fn() -> i64,
    perf_counter_unit: i64,
    ticks_per_sec: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
union ErtsSysTimeDataReadOnly {
    o: ErtsSysTimeReadOnlyData,
    align: [u8; 64],
}

#[repr(C, align(64))]
pub struct CacheAlignedSysTimeData {
    r: ErtsSysTimeDataReadOnly,
}

fn timespec(clock: libc::clockid_t) -> libc::timespec {
    let mut value = core::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `value` is writable storage for one `timespec`, as required by clock_gettime.
    if unsafe { libc::clock_gettime(clock, value.as_mut_ptr()) } != 0 {
        std::process::abort();
    }
    // SAFETY: clock_gettime returned success and initialized the timespec.
    unsafe { value.assume_init() }
}

fn time_nanos(clock: libc::clockid_t) -> i64 {
    let value = timespec(clock);
    value
        .tv_sec
        .wrapping_mul(1_000_000_000)
        .wrapping_add(value.tv_nsec)
}

extern "C" fn monotonic() -> i64 {
    time_nanos(libc::CLOCK_MONOTONIC)
}

extern "C" fn monotonic_raw() -> i64 {
    time_nanos(libc::CLOCK_MONOTONIC_RAW)
}

extern "C" fn times_monotonic(monotonic: *mut i64, system: *mut i64) {
    write_times(monotonic, system, libc::CLOCK_MONOTONIC)
}

extern "C" fn times_monotonic_raw(monotonic: *mut i64, system: *mut i64) {
    write_times(monotonic, system, libc::CLOCK_MONOTONIC_RAW)
}

fn write_times(monotonic: *mut i64, system: *mut i64, clock: libc::clockid_t) {
    let monotonic_time = time_nanos(clock);
    let system_time = time_nanos(libc::CLOCK_REALTIME);
    // SAFETY: erts calls this callback with two writable time outputs.
    unsafe {
        monotonic.write(monotonic_time);
        system.write(system_time);
    }
}

extern "C" fn sys_hrtime() -> i64 {
    time_nanos(libc::CLOCK_MONOTONIC)
}

#[cfg(target_arch = "x86_64")]
extern "C" fn rdtsc() -> i64 {
    let low: u32;
    let high: u32;
    // SAFETY: this is the `rdtsc` instruction used by OTP's x86 perf callback.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            lateout("eax") low,
            lateout("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((u64::from(high) << 32) | u64::from(low)) as i64
}

#[cfg(target_os = "linux")]
fn monotonic_clock() -> (extern "C" fn() -> i64, extern "C" fn(*mut i64, *mut i64)) {
    let mut uts = core::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: `uts` points to writable storage for the uname result.
    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        std::process::abort();
    }
    // SAFETY: uname succeeded and initialized the result.
    let uts = unsafe { uts.assume_init() };
    // SAFETY: uname initializes its fixed-size NUL-terminated release array.
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }.to_bytes();
    let mut parts = release.split(|byte| *byte == b'.');
    let major = component(parts.next());
    let minor = component(parts.next());
    let patch = parts.next().map_or(0, |part| {
        component(Some(
            part.split(|byte| !byte.is_ascii_digit())
                .next()
                .unwrap_or_default(),
        ))
    });
    let version = (major, minor, patch);
    if version >= (2, 6, 33) {
        (monotonic, times_monotonic)
    } else if version >= (2, 6, 28) {
        (monotonic_raw, times_monotonic_raw)
    } else {
        (monotonic, times_monotonic)
    }
}

#[cfg(not(target_os = "linux"))]
fn monotonic_clock() -> (extern "C" fn() -> i64, extern "C" fn(*mut i64, *mut i64)) {
    (monotonic, times_monotonic)
}

fn component(value: Option<&[u8]>) -> u32 {
    value
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

#[cfg(target_arch = "x86_64")]
fn have_reliable_tsc() -> bool {
    // Port of erts/lib_src/common/ethr_aux.c (x86_init), OTP-29.1.1: ethread trusts the
    // extended TSC flags only for vendors whose feature-bit meanings it verified.
    // SAFETY: CPUID is available on x86-64.
    let vendor = core::arch::x86_64::__cpuid(0);
    let mut vendor_bytes = [0; 12];
    vendor_bytes[0..4].copy_from_slice(&vendor.ebx.to_le_bytes());
    vendor_bytes[4..8].copy_from_slice(&vendor.edx.to_le_bytes());
    vendor_bytes[8..12].copy_from_slice(&vendor.ecx.to_le_bytes());
    if !matches!(
        &vendor_bytes,
        b"GenuineIntel" | b"AuthenticAMD" | b"HygonGenuine"
    ) {
        return false;
    }
    // SAFETY: the extended maximum leaf is read before querying the feature leaf.
    let max = core::arch::x86_64::__cpuid(0x8000_0000);
    if max.eax < 0x8000_0007 {
        return false;
    }
    // SAFETY: 0x80000007 is present according to the preceding maximum-leaf check.
    let power = core::arch::x86_64::__cpuid(0x8000_0007);
    power.edx & (1 << 8) != 0 && power.edx & (1 << 23) != 0
}

#[cfg(target_arch = "x86_64")]
fn wall_clock_usec() -> i64 {
    time_nanos(libc::CLOCK_REALTIME) / 1_000
}

#[cfg(target_arch = "x86_64")]
fn calculate_perf_counter_unit() -> i64 {
    // Port of erts/emulator/sys/unix/sys_time.c (calculate_perf_counter_unit), OTP-29.1.1.
    const RESOLUTION: i64 = 100;
    let before_boundary = wall_clock_usec() / RESOLUTION;
    let mut after_boundary = before_boundary;
    while after_boundary == before_boundary {
        after_boundary = wall_clock_usec() / RESOLUTION;
    }
    let before = rdtsc();
    let start = wall_clock_usec() / RESOLUTION;
    let mut end = start;
    while end == start {
        end = wall_clock_usec() / RESOLUTION;
    }
    let elapsed = rdtsc().wrapping_sub(before) as f64;
    let ticks_per_usec = elapsed / RESOLUTION as f64;
    let round_factor = 10_f64.powf(3.0 - ticks_per_usec.log10().ceil());
    let rounded = ((ticks_per_usec * round_factor + 0.5) as i64) as f64 / round_factor;
    (rounded as i64).wrapping_mul(1_000_000)
}

/// Initialize the Linux `ErtsSysTimeData__` fields before JIT code uses its callbacks.
// Port of erts/emulator/sys/unix/sys_time.c (erts_init_time, init_perf_counter), OTP-29.1.1.
pub(crate) fn init() {
    let (os_monotonic_time, os_times) = monotonic_clock();
    // SAFETY: VM construction initializes the process-wide erts table before compiling or
    // entering native code; its layout matches Linux x86-64's C structure.
    unsafe {
        let ticks = libc::sysconf(libc::_SC_CLK_TCK);
        if ticks < 0 || ticks > i32::MAX as libc::c_long {
            std::process::abort();
        }
        #[cfg(target_arch = "x86_64")]
        let use_tsc = have_reliable_tsc();
        #[cfg(target_arch = "x86_64")]
        let (perf_counter, perf_counter_unit): (extern "C" fn() -> i64, i64) = if use_tsc {
            (rdtsc, calculate_perf_counter_unit())
        } else {
            (sys_hrtime, 1_000_000_000)
        };
        #[cfg(not(target_arch = "x86_64"))]
        let (perf_counter, perf_counter_unit) = (sys_hrtime, 1_000_000_000);
        let data = core::ptr::addr_of_mut!(erts_sys_time_data__).cast::<ErtsSysTimeReadOnlyData>();
        data.write(ErtsSysTimeReadOnlyData {
            os_monotonic_time,
            os_times,
            perf_counter,
            perf_counter_unit,
            ticks_per_sec: ticks as i32,
        });
    }
}

/// Cache-line-aligned callbacks read by x86 BeamAsm's `i_perf_counter` fragment.
#[unsafe(no_mangle)]
pub static mut erts_sys_time_data__: CacheAlignedSysTimeData = CacheAlignedSysTimeData {
    r: ErtsSysTimeDataReadOnly {
        o: ErtsSysTimeReadOnlyData {
            os_monotonic_time: monotonic,
            os_times: times_monotonic,
            perf_counter: sys_hrtime,
            perf_counter_unit: 1_000_000_000,
            ticks_per_sec: 100,
        },
    },
};

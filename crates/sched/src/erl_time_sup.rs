//! Clock state shared by the VM and native APIs.
//!
//! Port of erts/emulator/beam/erl_time_sup.c, OTP-29.1.1.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static START: OnceLock<Instant> = OnceLock::new();
static TIME_OFFSET: OnceLock<i128> = OnceLock::new();
static LAST_NOW: AtomicI64 = AtomicI64::new(0);

/// Initialize the monotonic clock origin with the VM's other boot statistics.
pub fn initialize_time_origin() {
    START.get_or_init(Instant::now);
}

/// Milliseconds from the external monotonic clock used by Erlang timers.
pub fn monotonic_time_milliseconds() -> i128 {
    monotonic_time_nanos().div_euclid(1_000_000)
}

/// External monotonic time, using the runtime start offset and native nanosecond unit.
// Port of erts/emulator/beam/erl_time_sup.c (`erts_get_monotonic_time`), OTP-29.1.1.
pub fn monotonic_time_nanos() -> i128 {
    i128::from(MONOTONIC_TIME_START_EXTERNAL) + i128::from(monotonic_time_raw_nanos())
}

/// `ERTS_MONOTONIC_TIME_START_EXTERNAL` on the 64-bit nanosecond clock.
// Port of erts/emulator/beam/erl_time.h (`ERTS_MONOTONIC_TIME_START_EXTERNAL`), OTP-29.1.1.
pub const MONOTONIC_TIME_START_EXTERNAL: i64 = (-(1_i64 << 59) / 1_000_000_000) * 1_000_000_000;

/// The last external monotonic time before the signed 64-bit range ends.
// Port of erts/emulator/beam/erl_time.h (`ERTS_MONOTONIC_TIME_END_EXTERNAL`), OTP-29.1.1.
pub const MONOTONIC_TIME_END_EXTERNAL: i64 =
    MONOTONIC_TIME_START_EXTERNAL + ((i64::MAX / 1_000_000_000) * 1_000_000_000 - 1_000_000_000);

/// Raw nanoseconds since the runtime initialized its monotonic clock.
pub fn monotonic_time_raw_nanos() -> i64 {
    START.get_or_init(Instant::now).elapsed().as_nanos() as i64
}

/// Next strictly increasing microsecond timestamp, shared with the NIF time API.
// Port of erts/emulator/beam/erl_time_sup.c (`get_now`), OTP-29.1.1.
pub fn next_now_micros() -> Option<i64> {
    let wall_nanos = monotonic_time_nanos().checked_add(time_offset_nanos()?)?;
    let micros = i64::try_from(wall_nanos / 1_000).ok()?;
    let mut previous = LAST_NOW.load(Ordering::Relaxed);
    loop {
        let next = micros.max(previous.checked_add(1)?);
        match LAST_NOW.compare_exchange_weak(previous, next, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => return Some(next),
            Err(observed) => previous = observed,
        }
    }
}

/// `erlang:time_offset/0` in nanoseconds, also used by `enif_time_offset`.
pub fn time_offset_nanos_value() -> Option<i128> {
    time_offset_nanos()
}

/// Raw clock offset before the external monotonic start offset is applied.
// Port of erts/emulator/beam/erl_time_sup.c (`get_time_offset`), OTP-29.1.1.
pub fn time_offset_raw_nanos() -> Option<i128> {
    time_offset_nanos().map(|offset| offset + i128::from(MONOTONIC_TIME_START_EXTERNAL))
}

fn time_offset_nanos() -> Option<i128> {
    if let Some(offset) = TIME_OFFSET.get() {
        return Some(*offset);
    }
    let mono_before = monotonic_time_nanos();
    let system = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos() as i128;
    let mono_after = monotonic_time_nanos();
    let midpoint = mono_before + (mono_after - mono_before) / 2;
    let _ = TIME_OFFSET.set(system - midpoint);
    TIME_OFFSET.get().copied()
}

//! Process-independent clock and calendar BIFs.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arinsal_term::{Term, TermBuilder};
use libc::{localtime_r, mktime, time_t, tm};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;

use crate::pure::{Heap, atom_name, bigint, tuple_arity, tuple_build, tuple_element};
use crate::{BifError, Ctx};

const NATIVE: i128 = 1_000_000_000;
static START: OnceLock<Instant> = OnceLock::new();
static TIME_OFFSET: OnceLock<i128> = OnceLock::new();
static LAST_NOW: AtomicI64 = AtomicI64::new(0);

/// Initialize the monotonic clock origin with the VM's other boot statistics.
pub fn initialize_time_origin() {
    START.get_or_init(Instant::now);
}

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    // `convert_time_unit/3` is an erlang.erl wrapper, absent from bif.tab.
    if (module, name, arity) == ("erlang", "convert_time_unit", 3) {
        return Some(v.entry::<word_bodies::convert_time_unit>());
    }
    let f = match (module, name, arity) {
        ("erlang", "monotonic_time", 0 | 1) => v.entry::<word_bodies::monotonic_time>(),
        ("erlang", "time_offset", 0 | 1) => v.entry::<word_bodies::time_offset>(),
        ("erlang", "timestamp", 0) | ("os", "timestamp", 0) => v.entry::<word_bodies::timestamp>(),
        ("erlang", "now", 0) => v.entry::<word_bodies::now>(),
        ("erlang", "time", 0) => v.entry::<word_bodies::time>(),
        ("erlang", "date", 0) => v.entry::<word_bodies::date>(),
        ("erlang", "localtime", 0) => v.entry::<word_bodies::localtime>(),
        ("erlang", "universaltime", 0) => v.entry::<word_bodies::universaltime>(),
        ("erlang", "universaltime_to_localtime", 1) => {
            v.entry::<word_bodies::universaltime_to_localtime>()
        }
        ("erlang", "localtime_to_universaltime", 2) => {
            v.entry::<word_bodies::localtime_to_universaltime>()
        }
        ("erlang", "universaltime_to_posixtime", 1) => {
            v.entry::<word_bodies::universaltime_to_posixtime>()
        }
        ("erlang", "posixtime_to_universaltime", 1) => {
            v.entry::<word_bodies::posixtime_to_universaltime>()
        }
        _ => return None,
    };
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

fn convert_time_unit_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let value = bigint(args[0])?;
    let from = unit(args[1])?;
    let to = unit(args[2])?;
    let numerator = value * to;
    let result = floor_div(numerator, from);
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .int_from_bigint(&result)
        .map_err(|_| BifError::SystemLimit)
}

fn floor_div(numerator: BigInt, denominator: BigInt) -> BigInt {
    if numerator.sign() == Sign::Minus {
        (numerator - (&denominator - 1)) / denominator
    } else {
        numerator / denominator
    }
}

fn unit(value: Term) -> Result<BigInt, BifError> {
    if let Some(name) = atom_name(value) {
        // Port of erts/emulator/beam/erl_time_sup.c:2607 (perf_counter_unit), OTP-29.1.1.
        return Ok(BigInt::from(match name {
            "native" | "nanosecond" | "nano_seconds" => NATIVE,
            // The OTP 29.1.1 macOS perf counter is nanosecond-resolution.
            "perf_counter" => NATIVE,
            "microsecond" | "micro_seconds" => 1_000_000,
            "millisecond" | "milli_seconds" => 1_000,
            "second" | "seconds" => 1,
            _ => return Err(BifError::BADARG),
        }));
    }
    let value = bigint(value)?;
    if value.sign() != Sign::Plus {
        return Err(BifError::BADARG);
    }
    Ok(value)
}

fn scaled(ctx: &mut Ctx<'_>, value: i128, args: &[Term]) -> Result<Term, BifError> {
    if (args.is_empty()
        || args
            .first()
            .and_then(|term| atom_name(*term))
            .is_some_and(|name| matches!(name, "native" | "nanosecond" | "nano_seconds")))
        && let Ok(small) = i64::try_from(value)
        && let Some(term) = Term::small(small)
    {
        return Ok(term);
    }
    let units = if let Some(unit_term) = args.first() {
        unit(*unit_term)?
    } else {
        BigInt::from(NATIVE)
    };
    let numerator = BigInt::from(value) * units;
    let denominator = BigInt::from(NATIVE);
    // Port of erts/emulator/beam/erl_time_sup.c (time unit conversion), OTP-29.1.1.
    let result = floor_div(numerator, denominator);
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .int_from_bigint(&result)
        .map_err(|_| BifError::SystemLimit)
}

pub fn monotonic_time_milliseconds() -> i128 {
    mono_nanos().div_euclid(1_000_000)
}

/// Return the same clock value as `erts_get_monotonic_time`, used by
/// `erlang:monotonic_time/0` in `erts/emulator/beam/erl_time_sup.c`, OTP-29.1.1.
pub fn monotonic_time_nanos() -> i128 {
    -(1_i128 << 59) + i128::from(monotonic_time_raw_nanos())
}

/// Return OTP's raw internal monotonic clock value for call_time accounting.
// Port of erts/emulator/beam/beam_bp.c (get_mtime), OTP-29.1.1. On macOS, OTP's
// ERTS_MONOTONIC unit is nanoseconds; unlike trace timestamps in erl_trace.c, call_time does not
// convert the value or add the external monotonic offset.
pub fn monotonic_time_raw_nanos() -> i64 {
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_nanos() as i64
}

fn mono_nanos() -> i128 {
    monotonic_time_nanos()
}

fn sys_nanos() -> Result<i128, BifError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BifError::SystemLimit)?
        .as_nanos() as i128)
}

fn monotonic_time_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    scaled(ctx, mono_nanos(), args)
}
fn time_offset_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    scaled(ctx, time_offset_nanos()?, args)
}
fn time_offset_nanos() -> Result<i128, BifError> {
    // Port of erts/emulator/beam/erl_time_sup.c:2542-2551 (time_offset_0/1), OTP-29.1.1.
    // The clock service publishes an offset snapshot; recomputing it on each
    // call makes equivalent unit queries disagree while the clocks advance.
    if let Some(offset) = TIME_OFFSET.get() {
        return Ok(*offset);
    }
    let mono_before = mono_nanos();
    let system = sys_nanos()?;
    let mono_after = mono_nanos();
    let mono_midpoint = mono_before + (mono_after - mono_before) / 2;
    let _ = TIME_OFFSET.set(system - mono_midpoint);
    Ok(*TIME_OFFSET.get().expect("time offset initialized"))
}
fn small(value: i64) -> Term {
    Term::small(value).expect("calendar component fits small integer")
}
fn date_tuple(ctx: &mut Ctx<'_>, year: i32, month: u32, day: u32) -> Term {
    tuple_build(
        ctx,
        &[small(year as i64), small(month as i64), small(day as i64)],
    )
}
fn clock_tuple(ctx: &mut Ctx<'_>, hour: u32, minute: u32, second: u32) -> Term {
    tuple_build(
        ctx,
        &[
            small(hour as i64),
            small(minute as i64),
            small(second as i64),
        ],
    )
}
#[derive(Clone, Copy)]
struct Calendar {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

fn datetime_tuple(ctx: &mut Ctx<'_>, value: Calendar) -> Term {
    let date = date_tuple(ctx, value.year, value.month, value.day);
    let time = clock_tuple(ctx, value.hour, value.minute, value.second);
    tuple_build(ctx, &[date, time])
}
fn timestamp_result(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    // Port of erts/emulator/beam/erl_time_sup.c:1880-1907 (get_now), OTP-29.1.1.
    // `timestamp/0` must use the same monotonic sample and offset as
    // `system_time/0`; sampling the wall clock independently can disagree with
    // a monotonic-time conversion by more than the permitted midpoint window.
    let micros = (mono_nanos() + time_offset_nanos()?) / 1_000;
    Ok(timestamp_tuple(ctx, micros))
}
fn timestamp_tuple(ctx: &mut Ctx<'_>, micros: i128) -> Term {
    let mega = micros / 1_000_000_000_000;
    let secs = micros / 1_000_000 % 1_000_000;
    let micro = micros % 1_000_000;
    tuple_build(
        ctx,
        &[small(mega as i64), small(secs as i64), small(micro as i64)],
    )
}
fn now_result(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    Ok(timestamp_tuple(ctx, next_now_micros()? as i128))
}
/// The strictly increasing microsecond clock of `erlang:now/0` (also `enif_now_time`).
pub fn next_now_micros() -> Result<i64, BifError> {
    let micros = i64::try_from(sys_nanos()? / 1_000).map_err(|_| BifError::SystemLimit)?;
    let value = LAST_NOW.fetch_max(micros, Ordering::Relaxed).max(micros);
    let mut prior = LAST_NOW.load(Ordering::Relaxed);
    loop {
        let next = prior
            .max(value)
            .checked_add(1)
            .ok_or(BifError::SystemLimit)?;
        match LAST_NOW.compare_exchange_weak(prior, next, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => return Ok(next),
            Err(observed) => prior = observed,
        }
    }
}
/// `erlang:time_offset/0` in nanoseconds (also `enif_time_offset`).
pub fn time_offset_nanos_value() -> Option<i128> {
    time_offset_nanos().ok()
}
fn time_result(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    let now = local_calendar(now_seconds()?)?;
    Ok(clock_tuple(ctx, now.hour, now.minute, now.second))
}
fn date_result(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    let now = local_calendar(now_seconds()?)?;
    Ok(date_tuple(ctx, now.year, now.month, now.day))
}
fn localtime_result(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    Ok(datetime_tuple(ctx, local_calendar(now_seconds()?)?))
}
fn universaltime_result(ctx: &mut Ctx<'_>, _: &[Term]) -> Result<Term, BifError> {
    Ok(datetime_tuple(ctx, calendar_from_unix(now_seconds()?)))
}

fn component(term: Term) -> Result<i32, BifError> {
    term.as_small()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(BifError::BADARG)
}
fn parse_datetime(term: Term) -> Result<Calendar, BifError> {
    if tuple_arity(term)? != 2 {
        return Err(BifError::BADARG);
    }
    let date = tuple_element(term, 0)?;
    let time = tuple_element(term, 1)?;
    if tuple_arity(date)? != 3 || tuple_arity(time)? != 3 {
        return Err(BifError::BADARG);
    }
    let year = component(tuple_element(date, 0)?)?;
    if year < 1 {
        return Err(BifError::BADARG);
    }
    let month = component(tuple_element(date, 1)?)?;
    let day = component(tuple_element(date, 2)?)?;
    let hour = component(tuple_element(time, 0)?)?;
    let minute = component(tuple_element(time, 1)?)?;
    let second = component(tuple_element(time, 2)?)?;
    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return Err(BifError::BADARG);
    }
    Ok(Calendar {
        year,
        month: month as u32,
        day: day as u32,
        hour: hour as u32,
        minute: minute as u32,
        second: second as u32,
    })
}
fn parse_localtime_datetime(term: Term) -> Result<Calendar, BifError> {
    // Port of erts/emulator/beam/erl_time_sup.c:1735-1810, OTP-29.1.1.
    // erts/emulator/beam/erl_time_sup.c:1600 defines BASEYEAR as 1902 for
    // both local conversion BIFs, while POSIX conversions accept earlier years.
    let value = parse_datetime(term)?;
    if value.year < 1902 || value.year == i32::MAX {
        return Err(BifError::BADARG);
    }
    Ok(value)
}
fn universaltime_to_localtime_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let seconds = unix_from_calendar(parse_localtime_datetime(args[0])?).ok_or(BifError::BADARG)?;
    Ok(datetime_tuple(ctx, local_calendar(seconds)?))
}
fn localtime_to_universaltime_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let value = parse_localtime_datetime(args[0])?;
    let is_dst = match atom_name(args[1]) {
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some("undefined") => None,
        _ => return Err(BifError::BADARG),
    };
    // Port of erts/emulator/beam/erl_time_sup.c:1735 (local_to_univ), OTP-29.1.1.
    let mut local = to_tm(value, is_dst.map_or(-1, i32::from));
    if !sys_daylight() {
        // A zone without DST: simulate the Linux/Solaris behaviour of treating is_dst as unset
        // instead of letting the OS refuse a DST time.
        local.tm_isdst = 0;
    }
    // SAFETY: `local` is initialized and mktime reads and normalizes this tm value.
    let seconds = unsafe { mktime(&mut local) };
    let utc = calendar_from_unix(seconds as i64);
    Ok(datetime_tuple(ctx, utc))
}
fn universaltime_to_posixtime_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let secs = unix_from_calendar(parse_datetime(args[0])?).ok_or(BifError::BADARG)?;
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .int_from_i64(secs)
        .map_err(|_| BifError::SystemLimit)
}
fn posixtime_to_universaltime_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let secs = bigint(args[0])?.to_i64().ok_or(BifError::BADARG)?;
    Ok(datetime_tuple(ctx, calendar_from_unix(secs)))
}

fn now_seconds() -> Result<i64, BifError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BifError::SystemLimit)?
        .as_secs() as i64)
}

fn leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i32, month: i32) -> i32 {
    match month {
        2 if leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year as i64 - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn calendar_from_unix(seconds: i64) -> Calendar {
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Calendar {
        year: year as i32,
        month: month as u32,
        day: day as u32,
        hour: (day_seconds / 3_600) as u32,
        minute: ((day_seconds % 3_600) / 60) as u32,
        second: (day_seconds % 60) as u32,
    }
}

fn unix_from_calendar(value: Calendar) -> Option<i64> {
    days_from_civil(value.year, value.month, value.day)
        .checked_mul(86_400)?
        .checked_add((value.hour * 3_600 + value.minute * 60 + value.second) as i64)
}

fn to_tm(value: Calendar, is_dst: i32) -> tm {
    // SAFETY: tm is a plain C struct; zero is a valid starting value before setting fields.
    let mut result: tm = unsafe { std::mem::zeroed() };
    result.tm_year = value.year - 1900;
    result.tm_mon = value.month as i32 - 1;
    result.tm_mday = value.day as i32;
    result.tm_hour = value.hour as i32;
    result.tm_min = value.minute as i32;
    result.tm_sec = value.second as i32;
    result.tm_isdst = is_dst;
    result
}

fn local_tm(seconds: i64) -> Result<tm, BifError> {
    let timestamp: time_t = seconds;
    // SAFETY: `out` is valid writable storage and localtime_r copies into it.
    let out = unsafe {
        let mut out: tm = std::mem::zeroed();
        if localtime_r(&timestamp, &mut out).is_null() {
            return Err(BifError::BADARG);
        }
        out
    };
    Ok(out)
}

fn local_calendar(seconds: i64) -> Result<Calendar, BifError> {
    local_tm(seconds).map(calendar_from_tm)
}

fn calendar_from_tm(value: tm) -> Calendar {
    Calendar {
        year: value.tm_year + 1900,
        month: (value.tm_mon + 1) as u32,
        day: value.tm_mday as u32,
        hour: value.tm_hour as u32,
        minute: value.tm_min as u32,
        second: value.tm_sec as u32,
    }
}

macro_rules! word_adapters {
    ($($word:ident => $body:ident),+ $(,)?) => {
        $(#[inline(always)]
        fn $word(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
            match $body(ctx, args) { Ok(value) => value, Err(error) => ctx.fail(error) }
        })+
    };
}
word_adapters!(monotonic_time => monotonic_time_result, time_offset => time_offset_result,
    timestamp => timestamp_result, now => now_result, time => time_result, date => date_result,
    localtime => localtime_result, universaltime => universaltime_result,
    universaltime_to_localtime => universaltime_to_localtime_result,
    localtime_to_universaltime => localtime_to_universaltime_result,
    universaltime_to_posixtime => universaltime_to_posixtime_result,
    posixtime_to_universaltime => posixtime_to_universaltime_result,
    convert_time_unit => convert_time_unit_result);
crate::word_bif_bodies_in!(word_bodies; monotonic_time, time_offset, timestamp, now, time, date,
    localtime, universaltime, universaltime_to_localtime, localtime_to_universaltime,
    universaltime_to_posixtime, posixtime_to_universaltime, convert_time_unit);

/// Whether the local time zone has daylight saving time.
// Port of erts/emulator/sys/unix/sys_time.c (sys_init_time, sys_daylight), OTP-29.1.1: the
// scan of the current year that erts uses where libc has no `daylight` variable. glibc's
// `daylight` is set from the zone rules; for the zones in use the two agree.
fn sys_daylight() -> bool {
    static DAYLIGHT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DAYLIGHT.get_or_init(|| {
        let Ok(now) = now_seconds() else { return false };
        let Ok(year) = local_tm(now).map(|tm| tm.tm_year + 1900) else {
            return false;
        };
        (1u32..=12).any(|month| {
            let first = Calendar {
                year,
                month,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            };
            unix_from_calendar(first)
                .and_then(|seconds| local_tm(seconds).ok())
                .is_some_and(|tm| tm.tm_isdst > 0)
        })
    })
}

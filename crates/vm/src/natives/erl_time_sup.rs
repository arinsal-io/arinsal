//! Clock and calendar BIFs.
//!
//! Port of erts/emulator/beam/erl_time_sup.c, bif.c, and erl_bif_os.c, OTP-29.1.1.

use crate::bif_table::bif_args;
use crate::natives::bif::{badarg, bif_ret};
use crate::natives::erl_bif_lists::bif_trap;
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::{Term, TermBuilder, atoms, global_atoms};
use libc::{time_t, tm};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "erl_time_sup/raw.rs"]
mod raw;

const NATIVE: i128 = 1_000_000_000;

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        atoms::SYSTEM_LIMIT,
    )))
}

fn process<'a>(c_p: *mut ProcessHeader) -> Option<&'a mut Process> {
    crate::native_hooks::process_from_header(c_p)
}

fn integer(process: &mut Process, value: i128) -> Result<Term, VmError> {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .int_from_i128(value)
        .map_err(|_| system_limit())
}

fn tuple2(process: &mut Process, a: Term, b: Term) -> Result<Term, VmError> {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .tuple2(a, b)
        .map_err(|_| system_limit())
}

fn tuple3(process: &mut Process, a: Term, b: Term, c: Term) -> Result<Term, VmError> {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .tuple3(a, b, c)
        .map_err(|_| system_limit())
}

fn small(value: i64) -> Result<Term, VmError> {
    Term::small(value).ok_or_else(system_limit)
}

fn tuple3_i64(process: &mut Process, a: i64, b: i64, c: i64) -> Result<Term, VmError> {
    let (a, b, c) = (small(a)?, small(b)?, small(c)?);
    tuple3(process, a, b, c)
}

fn datetime(process: &mut Process, value: Calendar) -> Result<Term, VmError> {
    let date = tuple3_i64(process, value.year, value.month, value.day)?;
    let time = tuple3_i64(process, value.hour, value.minute, value.second)?;
    tuple2(process, date, time)
}

fn atom_name(term: Term) -> Option<&'static str> {
    global_atoms().text(term.as_atom()?)
}

fn positive_integer(term: Term) -> Option<BigInt> {
    let value = term
        .as_small()
        .map(BigInt::from)
        .or_else(|| arinsal_term::raw::big_value(term))?;
    (value.sign() == Sign::Plus).then_some(value)
}

fn known_unit(term: Term) -> Option<i128> {
    Some(match atom_name(term)? {
        "native" | "nanosecond" | "nano_seconds" => NATIVE,
        "microsecond" | "micro_seconds" => 1_000_000,
        "millisecond" | "milli_seconds" => 1_000,
        "second" | "seconds" => 1,
        _ => return None,
    })
}

/// `time_unit_conversion`: standard units stay in the BIF; the other cases trap to the
/// preloaded `erlang:convert_time_unit/3`, preserving its floor arithmetic and error info.
// Port of erts/emulator/beam/erl_time_sup.c (time_unit_conversion), OTP-29.1.1.
fn convert_native(
    process: &mut Process,
    value: i128,
    unit: Term,
    offset_multiplier: i8,
) -> Result<Term, VmError> {
    let external_value = value
        + i128::from(offset_multiplier)
            * i128::from(arinsal_sched::erl_time_sup::MONOTONIC_TIME_START_EXTERNAL);
    if value < 0 || atom_name(unit) == Some("perf_counter") {
        let native = Term::small(NATIVE as i64).ok_or_else(system_limit)?;
        let value = integer(process, external_value)?;
        return Err(bif_trap(
            process,
            "erlang:convert_time_unit/3",
            vec![value, native, unit],
        ));
    }
    if let Some(frequency) = known_unit(unit) {
        let result = value * frequency / NATIVE;
        let offset = i128::from(offset_multiplier)
            * i128::from(arinsal_sched::erl_time_sup::MONOTONIC_TIME_START_EXTERNAL)
            * frequency
            / NATIVE;
        return integer(process, result + offset);
    }
    let Some(frequency) = positive_integer(unit) else {
        return Err(badarg());
    };
    if frequency == BigInt::from(1)
        || frequency == BigInt::from(1_000)
        || frequency == BigInt::from(1_000_000)
        || frequency == BigInt::from(NATIVE)
    {
        let frequency = frequency.to_i128().ok_or_else(badarg)?;
        let result = value * frequency / NATIVE;
        let offset = i128::from(offset_multiplier)
            * i128::from(arinsal_sched::erl_time_sup::MONOTONIC_TIME_START_EXTERNAL)
            * frequency
            / NATIVE;
        return integer(process, result + offset);
    }
    let native = Term::small(NATIVE as i64).ok_or_else(system_limit)?;
    let value = integer(process, value)?;
    Err(bif_trap(
        process,
        "erlang:convert_time_unit/3",
        vec![value, native, unit],
    ))
}

// Port of erts/emulator/beam/erl_time_sup.c (get_time), OTP-29.1.1.
fn monotonic_nanos() -> i128 {
    arinsal_sched::erl_time_sup::monotonic_time_nanos()
}

fn raw_monotonic_nanos() -> i128 {
    i128::from(arinsal_sched::erl_time_sup::monotonic_time_raw_nanos())
}

fn raw_time_offset_nanos() -> Result<i128, VmError> {
    arinsal_sched::erl_time_sup::time_offset_raw_nanos().ok_or_else(system_limit)
}

// Port of erts/emulator/beam/erl_time_sup.c (get_sys_now), OTP-29.1.1.
fn system_nanos() -> i128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as i128,
        Err(error) => -(error.duration().as_nanos() as i128),
    }
}

fn call(
    c_p: *mut ProcessHeader,
    i: u64,
    f: impl FnOnce(&mut Process) -> Result<Term, VmError>,
) -> u64 {
    let Some(process) = process(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    bif_ret(c_p, i, f(process))
}

/// `erlang:monotonic_time/0`.
// Port of erts/emulator/beam/erl_time_sup.c (monotonic_time_0), OTP-29.1.1.
pub(crate) extern "C" fn monotonic_time_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, |process| integer(process, monotonic_nanos()))
}

/// `erlang:monotonic_time/1`.
// Port of erts/emulator/beam/erl_time_sup.c (monotonic_time_1), OTP-29.1.1.
pub(crate) extern "C" fn monotonic_time_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [unit] = bif_args::<1>(reg);
    call(c_p, i, |process| {
        let raw = i128::from(arinsal_sched::erl_time_sup::monotonic_time_raw_nanos());
        convert_native(process, raw, unit, 1)
    })
}

/// `erlang:system_time/0`.
// Port of erts/emulator/beam/erl_time_sup.c (system_time_0), OTP-29.1.1.
pub(crate) extern "C" fn system_time_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, |process| {
        integer(process, raw_monotonic_nanos() + raw_time_offset_nanos()?)
    })
}

/// `erlang:system_time/1`.
// Port of erts/emulator/beam/erl_time_sup.c (system_time_1), OTP-29.1.1.
pub(crate) extern "C" fn system_time_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [unit] = bif_args::<1>(reg);
    call(c_p, i, |process| {
        let value = raw_monotonic_nanos() + raw_time_offset_nanos()?;
        convert_native(process, value, unit, 0)
    })
}

/// `os:system_time/0`.
// Port of erts/emulator/beam/erl_time_sup.c (os_system_time_0), OTP-29.1.1.
pub(crate) extern "C" fn os_system_time_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, |process| integer(process, system_nanos()))
}

/// `os:system_time/1`.
// Port of erts/emulator/beam/erl_time_sup.c (os_system_time_1), OTP-29.1.1.
pub(crate) extern "C" fn os_system_time_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [unit] = bif_args::<1>(reg);
    call(c_p, i, |process| {
        convert_native(process, system_nanos(), unit, 0)
    })
}

/// `erts_internal:time_unit/0`.
// Port of erts/emulator/beam/erl_time_sup.c (erts_internal_time_unit_0), OTP-29.1.1.
pub(crate) extern "C" fn time_unit_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, |_| small(NATIVE as i64))
}

/// `erts_internal:perf_counter_unit/0`.
// Port of erts/emulator/beam/erl_time_sup.c (erts_internal_perf_counter_unit_0), OTP-29.1.1.
pub(crate) extern "C" fn perf_counter_unit_0(
    c_p: *mut ProcessHeader,
    _reg: *mut u64,
    i: u64,
) -> u64 {
    // On macOS, erts_sys_perf_counter uses nanoseconds and reports 1e9 ticks per second.
    call(c_p, i, |_| small(NATIVE as i64))
}

/// `erlang:time_offset/0`.
// Port of erts/emulator/beam/erl_time_sup.c (time_offset_0), OTP-29.1.1.
pub(crate) extern "C" fn time_offset_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, |process| {
        let offset = raw_time_offset_nanos()?
            - i128::from(arinsal_sched::erl_time_sup::MONOTONIC_TIME_START_EXTERNAL);
        integer(process, offset)
    })
}

/// `erlang:time_offset/1`.
// Port of erts/emulator/beam/erl_time_sup.c (time_offset_1), OTP-29.1.1.
pub(crate) extern "C" fn time_offset_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [unit] = bif_args::<1>(reg);
    call(c_p, i, |process| {
        convert_native(process, raw_time_offset_nanos()?, unit, -1)
    })
}

// Port of erts/emulator/beam/erl_time_sup.c (make_timestamp_value), OTP-29.1.1.
fn timestamp_tuple(process: &mut Process, micros: i128) -> Result<Term, VmError> {
    let mega = micros / 1_000_000_000_000;
    let seconds = micros / 1_000_000 % 1_000_000;
    let micro = micros % 1_000_000;
    tuple3_i64(
        process,
        i64::try_from(mega).map_err(|_| system_limit())?,
        i64::try_from(seconds).map_err(|_| system_limit())?,
        i64::try_from(micro).map_err(|_| system_limit())?,
    )
}

/// `erlang:timestamp/0`.
// Port of erts/emulator/beam/erl_time_sup.c (timestamp_0, make_timestamp_value), OTP-29.1.1.
pub(crate) extern "C" fn timestamp_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, |process| {
        timestamp_tuple(
            process,
            (raw_monotonic_nanos() + raw_time_offset_nanos()?) / 1_000,
        )
    })
}

/// `os:timestamp/0`.
// Port of erts/emulator/beam/erl_bif_os.c (os_timestamp_0) and erl_time_sup.c (get_sys_now), OTP-29.1.1.
pub(crate) extern "C" fn os_timestamp_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, |process| {
        timestamp_tuple(process, system_nanos() / 1_000)
    })
}

fn now_tuple(process: &mut Process) -> Result<Term, VmError> {
    let micros = arinsal_sched::erl_time_sup::next_now_micros().ok_or_else(system_limit)?;
    timestamp_tuple(process, i128::from(micros))
}

/// `erlang:now/0`.
// Port of erts/emulator/beam/bif.c (now_0) and erl_time_sup.c (get_now), OTP-29.1.1.
pub(crate) extern "C" fn now_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, now_tuple)
}

// Port of erts/emulator/beam/erl_time_sup.c (get_time), OTP-29.1.1.
fn now_seconds() -> i64 {
    raw::time() as i64
}

#[derive(Clone, Copy)]
struct Calendar {
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
}

// Port of erts/emulator/beam/erl_time_sup.c (get_localtime, get_universaltime), OTP-29.1.1.
fn calendar_from_tm(value: tm) -> Calendar {
    Calendar {
        year: i64::from(value.tm_year) + 1900,
        month: i64::from(value.tm_mon) + 1,
        day: i64::from(value.tm_mday),
        hour: i64::from(value.tm_hour),
        minute: i64::from(value.tm_min),
        second: i64::from(value.tm_sec),
    }
}

// Port of erts/emulator/beam/erl_time_sup.c (seconds_to_univ), OTP-29.1.1.
fn calendar_from_unix(seconds: i64) -> Calendar {
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let days = days + 719_468;
    let mut year = (10_000 * days + 14_780) / 3_652_425;
    let mut day_of_year = days - (365 * year + year / 4 - year / 100 + year / 400);
    if day_of_year < 0 {
        year -= 1;
        day_of_year = days - (365 * year + year / 4 - year / 100 + year / 400);
    }
    let month_index = (100 * day_of_year + 52) / 3_060;
    Calendar {
        year: year + (month_index + 2) / 12,
        month: (month_index + 2) % 12 + 1,
        day: day_of_year - (month_index * 306 + 5) / 10 + 1,
        hour: day_seconds / 3_600,
        minute: day_seconds % 3_600 / 60,
        second: day_seconds % 60,
    }
}

// Port of erts/emulator/beam/erl_time_sup.c (get_localtime), OTP-29.1.1.
fn local_calendar(seconds: i64) -> Result<Calendar, VmError> {
    let seconds: time_t = seconds as time_t;
    raw::localtime(seconds)
        .map(calendar_from_tm)
        .ok_or_else(badarg)
}

// Port of erts/emulator/beam/erl_time_sup.c (get_universaltime), OTP-29.1.1.
fn universal_calendar(seconds: i64) -> Result<Calendar, VmError> {
    let seconds: time_t = seconds as time_t;
    raw::gmtime(seconds)
        .map(calendar_from_tm)
        .ok_or_else(badarg)
}

/// `erlang:time/0`.
// Port of erts/emulator/beam/bif.c (time_0) and erl_time_sup.c (get_time), OTP-29.1.1.
pub(crate) extern "C" fn time_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, |process| {
        let value = local_calendar(now_seconds())?;
        tuple3_i64(process, value.hour, value.minute, value.second)
    })
}

/// `erlang:date/0`.
// Port of erts/emulator/beam/bif.c (date_0) and erl_time_sup.c (get_date), OTP-29.1.1.
pub(crate) extern "C" fn date_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, |process| {
        let value = local_calendar(now_seconds())?;
        tuple3_i64(process, value.year, value.month, value.day)
    })
}

/// `erlang:localtime/0`.
// Port of erts/emulator/beam/bif.c (localtime_0) and erl_time_sup.c (get_localtime), OTP-29.1.1.
pub(crate) extern "C" fn localtime_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, |process| {
        datetime(process, local_calendar(now_seconds())?)
    })
}

/// `erlang:universaltime/0`.
// Port of erts/emulator/beam/bif.c (universaltime_0) and erl_time_sup.c (get_universaltime), OTP-29.1.1.
pub(crate) extern "C" fn universaltime_0(c_p: *mut ProcessHeader, _reg: *mut u64, i: u64) -> u64 {
    call(c_p, i, |process| {
        datetime(process, universal_calendar(now_seconds())?)
    })
}

// Port of erts/emulator/beam/bif.c (calendar BIF argument decoding), OTP-29.1.1.
fn component(value: Term) -> Result<i64, VmError> {
    value.as_small().ok_or_else(badarg)
}

// Port of erts/emulator/beam/bif.c (calendar BIF argument decoding), OTP-29.1.1.
fn tuple3_terms(value: Term) -> Result<[i64; 3], VmError> {
    if arinsal_bifs::tuple_arity(value).ok() != Some(3) {
        return Err(badarg());
    }
    Ok([
        component(arinsal_bifs::tuple_element(value, 0).map_err(|_| badarg())?)?,
        component(arinsal_bifs::tuple_element(value, 1).map_err(|_| badarg())?)?,
        component(arinsal_bifs::tuple_element(value, 2).map_err(|_| badarg())?)?,
    ])
}

// Port of erts/emulator/beam/bif.c (calendar BIF argument decoding), OTP-29.1.1.
fn parse_datetime(value: Term) -> Result<Calendar, VmError> {
    let (date, time) = arinsal_bifs::tuple_pair(value).ok_or_else(badarg)?;
    let [year, month, day] = tuple3_terms(date)?;
    let [hour, minute, second] = tuple3_terms(time)?;
    Ok(Calendar {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
}

// Port of erts/emulator/beam/erl_time_sup.c (gregorian date validation), OTP-29.1.1.
fn leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

// Port of erts/emulator/beam/erl_time_sup.c (univ_to_seconds, local_to_univ, univ_to_local),
// OTP-29.1.1.
fn valid_datetime(value: Calendar, min_year: i64, max_year: i64) -> bool {
    (min_year..=max_year).contains(&value.year)
        && (1..=12).contains(&value.month)
        && (1..=days_in_month(value.year, value.month)).contains(&value.day)
        && (0..=23).contains(&value.hour)
        && (0..=59).contains(&value.minute)
        && (0..=59).contains(&value.second)
}

// Port of erts/emulator/beam/erl_time_sup.c (univ_to_seconds), OTP-29.1.1.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Port of erts/emulator/beam/erl_time_sup.c (univ_to_seconds), OTP-29.1.1.
fn univ_to_seconds(value: Calendar) -> Result<i64, VmError> {
    if !valid_datetime(value, 1600, i64::from(i32::MAX) - 1) {
        return Err(badarg());
    }
    let years = value.year - 1600;
    let prior = years - 1;
    let mut days = if years > 0 {
        prior / 4 - prior / 100 + prior / 400 + prior * 365 + 366
    } else {
        0
    };
    for month in 1..value.month {
        days += days_in_month(value.year, month);
    }
    if leap_year(value.year) && value.month > 2 {
        days += 1;
    }
    days += value.day - 1 - 135_140;
    days.checked_mul(86_400)
        .and_then(|v| v.checked_add(value.hour * 3_600 + value.minute * 60 + value.second))
        .ok_or_else(badarg)
}

// Port of erts/emulator/beam/erl_time_sup.c (seconds_to_univ), OTP-29.1.1.
fn seconds_to_univ(seconds: i64) -> Calendar {
    calendar_from_unix(seconds)
}

// Port of erts/emulator/beam/erl_time_sup.c (local_to_univ), OTP-29.1.1.
fn to_tm(value: Calendar, is_dst: i32) -> Result<tm, VmError> {
    if !valid_datetime(value, 1902, i64::from(i32::MAX) - 1) {
        return Err(badarg());
    }
    let mut out = raw::zero_tm();
    out.tm_year = i32::try_from(value.year - 1900).map_err(|_| badarg())?;
    out.tm_mon = i32::try_from(value.month - 1).map_err(|_| badarg())?;
    out.tm_mday = i32::try_from(value.day).map_err(|_| badarg())?;
    out.tm_hour = i32::try_from(value.hour).map_err(|_| badarg())?;
    out.tm_min = i32::try_from(value.minute).map_err(|_| badarg())?;
    out.tm_sec = i32::try_from(value.second).map_err(|_| badarg())?;
    out.tm_isdst = is_dst;
    Ok(out)
}

// Port of erts/emulator/sys/unix/sys_time.c (sys_init_time), OTP-29.1.1.
fn sys_daylight() -> bool {
    static DAYLIGHT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DAYLIGHT.get_or_init(raw::daylight)
}

// Port of erts/emulator/beam/erl_time_sup.c (local_to_univ), OTP-29.1.1.
fn local_to_universal(value: Calendar, is_dst: i32) -> Result<Calendar, VmError> {
    let mut local = to_tm(value, if sys_daylight() { is_dst } else { 0 })?;
    let seconds = match raw::mktime(&mut local) {
        -1 => {
            let mut retry = local;
            retry.tm_sec -= 1;
            let adjusted = raw::mktime(&mut retry);
            if adjusted != -2 {
                return Err(badarg());
            }
            -1
        }
        seconds => seconds,
    };
    universal_calendar(seconds as i64)
}

// Port of erts/emulator/beam/erl_time_sup.c (univ_to_local), OTP-29.1.1.
fn universal_to_local(value: Calendar) -> Result<Calendar, VmError> {
    if !valid_datetime(value, 1902, i64::from(i32::MAX) - 1) {
        return Err(badarg());
    }
    let seconds = univ_to_seconds(value)?;
    local_calendar(seconds)
}

/// `erlang:localtime_to_universaltime/2`.
// Port of erts/emulator/beam/bif.c (localtime_to_universaltime_2) and erl_time_sup.c (local_to_univ), OTP-29.1.1.
pub(crate) extern "C" fn localtime_to_universaltime_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let [localtime, dst] = bif_args::<2>(reg);
    call(c_p, i, |process| {
        let value = parse_datetime(localtime)?;
        let is_dst = match atom_name(dst) {
            Some("true") => 1,
            Some("false") => 0,
            Some("undefined") => -1,
            _ => return Err(badarg()),
        };
        datetime(process, local_to_universal(value, is_dst)?)
    })
}

/// `erlang:universaltime_to_localtime/1`.
// Port of erts/emulator/beam/bif.c (universaltime_to_localtime_1) and erl_time_sup.c (univ_to_local), OTP-29.1.1.
pub(crate) extern "C" fn universaltime_to_localtime_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let [calendar] = bif_args::<1>(reg);
    call(c_p, i, |process| {
        let value = parse_datetime(calendar)?;
        datetime(process, universal_to_local(value)?)
    })
}

/// `erlang:universaltime_to_posixtime/1`.
// Port of erts/emulator/beam/bif.c (universaltime_to_posixtime_1) and erl_time_sup.c (univ_to_seconds), OTP-29.1.1.
pub(crate) extern "C" fn universaltime_to_posixtime_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let [calendar] = bif_args::<1>(reg);
    call(c_p, i, |process| {
        integer(
            process,
            i128::from(univ_to_seconds(parse_datetime(calendar)?)?),
        )
    })
}

/// `erlang:posixtime_to_universaltime/1`.
// Port of erts/emulator/beam/bif.c (posixtime_to_universaltime_1) and erl_time_sup.c (seconds_to_univ), OTP-29.1.1.
pub(crate) extern "C" fn posixtime_to_universaltime_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let [seconds] = bif_args::<1>(reg);
    call(c_p, i, |process| {
        let value = seconds
            .as_small()
            .map(i128::from)
            .or_else(|| arinsal_term::raw::big_value(seconds).and_then(|v| v.to_i128()))
            .and_then(|v| i64::try_from(v).ok())
            .ok_or_else(badarg)?;
        datetime(process, seconds_to_univ(value))
    })
}

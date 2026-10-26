//! Debug and trace switches, sampled once.
//!
//! `std::env::var_os` takes the process environment lock and scans every
//! variable. erts reads its debug switches at emulator startup; these helpers
//! do the same so send, receive, and load paths do not call `getenv` per use.

use std::ffi::{OsStr, OsString};
use std::sync::OnceLock;

fn presence(cell: &'static OnceLock<bool>, name: &str) -> bool {
    *cell.get_or_init(|| std::env::var_os(name).is_some())
}

/// `ARINSAL_TRACE_DIST`: log distribution send and receive.
pub(crate) fn trace_dist() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    presence(&FLAG, "ARINSAL_TRACE_DIST")
}

/// `ARINSAL_LITERAL_TRACE`: log literal-area and resource lifetime events.
pub(crate) fn literal_trace() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    presence(&FLAG, "ARINSAL_LITERAL_TRACE")
}

/// `ARINSAL_DIFFTEST_UNSCHEDULED`: run difftest calls without the scheduler.
#[cfg(feature = "difftest")]
pub(crate) fn difftest_unscheduled() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    presence(&FLAG, "ARINSAL_DIFFTEST_UNSCHEDULED")
}

/// `ARINSAL_BEAMASM_DUMP`: directory for native assembly dumps.
pub(crate) fn beamasm_dump() -> Option<&'static OsStr> {
    static VALUE: OnceLock<Option<OsString>> = OnceLock::new();
    VALUE
        .get_or_init(|| std::env::var_os("ARINSAL_BEAMASM_DUMP"))
        .as_deref()
}

/// `ARINSAL_BEAMASM_STATS=1`: print native-call counters when a VM drops.
#[inline]
pub(crate) fn beamasm_stats() -> bool {
    slice::get() & slice::BEAMASM_STATS != 0
}

/// Per-slice debug switches, folded into one byte.
///
/// The scheduler tests these on every slice and every native entry. erts reads its debug
/// switches once at startup into plain globals; this byte is the same: read from the
/// environment on first use, then a single relaxed load per test, and one load per slice for
/// all of them when the caller keeps the value in a local.
pub(crate) mod slice {
    use std::ffi::OsStr;
    use std::sync::atomic::{AtomicU8, Ordering};

    /// `ARINSAL_BEAMASM_RETURN_TRACE`: log native entries and exits.
    pub(crate) const RETURN_TRACE: u8 = 1;
    /// `ARINSAL_BEAMASM_EXCEPTION_TRACE`: log native exceptions.
    pub(crate) const EXCEPTION_TRACE: u8 = 1 << 1;
    /// `ARINSAL_BEAMASM_LIFETIME=1`: log native code memory lifetimes.
    pub(crate) const LIFETIME_TRACE: u8 = 1 << 2;
    /// `ARINSAL_TRACE_BOOT`: log scheduler boot events.
    pub(crate) const TRACE_BOOT: u8 = 1 << 3;
    /// `ARINSAL_XREG_POISON=1` in a debug build.
    pub(crate) const XREG_POISON: u8 = 1 << 4;
    /// `ARINSAL_BEAMASM_STATS=1`: count native calls and yields.
    pub(crate) const BEAMASM_STATS: u8 = 1 << 5;
    /// The native exit bridge ranges are registered.
    pub(crate) const BRIDGE_REGISTERED: u8 = 1 << 6;
    const INIT: u8 = 1 << 7;

    static FLAGS: AtomicU8 = AtomicU8::new(0);

    #[cold]
    #[inline(never)]
    fn init() -> u8 {
        let set = |name: &str, test: fn(&OsStr) -> bool, bit: u8| {
            if std::env::var_os(name).is_some_and(|value| test(&value)) {
                bit
            } else {
                0
            }
        };
        let mut flags = INIT;
        flags |= set("ARINSAL_BEAMASM_RETURN_TRACE", |_| true, RETURN_TRACE);
        flags |= set("ARINSAL_BEAMASM_EXCEPTION_TRACE", |_| true, EXCEPTION_TRACE);
        flags |= set(
            "ARINSAL_BEAMASM_LIFETIME",
            |value| value == "1",
            LIFETIME_TRACE,
        );
        flags |= set("ARINSAL_TRACE_BOOT", |_| true, TRACE_BOOT);
        if cfg!(debug_assertions) {
            flags |= set("ARINSAL_XREG_POISON", |value| value == "1", XREG_POISON);
        }
        flags |= set("ARINSAL_BEAMASM_STATS", |value| value == "1", BEAMASM_STATS);
        FLAGS.fetch_or(flags, Ordering::Relaxed);
        FLAGS.load(Ordering::Relaxed)
    }

    /// The switches, sampled from the environment on first use.
    #[inline(always)]
    pub(crate) fn get() -> u8 {
        let flags = FLAGS.load(Ordering::Relaxed);
        if flags & INIT != 0 { flags } else { init() }
    }

    /// Records that the native exit bridge ranges are registered.
    pub(crate) fn set_bridge_registered() {
        FLAGS.fetch_or(BRIDGE_REGISTERED, Ordering::Relaxed);
    }
}

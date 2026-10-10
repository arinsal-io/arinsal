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

fn cached_string(cell: &'static OnceLock<Option<String>>, name: &str) -> Option<&'static str> {
    cell.get_or_init(|| std::env::var(name).ok()).as_deref()
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

/// `ARINSAL_BEAMASM_MODULES`: comma-separated modules allowed to compile.
pub(crate) fn beamasm_modules() -> Option<&'static str> {
    static VALUE: OnceLock<Option<String>> = OnceLock::new();
    cached_string(&VALUE, "ARINSAL_BEAMASM_MODULES")
}

/// `ARINSAL_BEAMASM_SKIP`: comma-separated modules left interpreted.
pub(crate) fn beamasm_skip() -> Option<&'static str> {
    static VALUE: OnceLock<Option<String>> = OnceLock::new();
    cached_string(&VALUE, "ARINSAL_BEAMASM_SKIP")
}

/// `ARINSAL_BEAMASM_FUNCS`: comma-separated functions allowed to compile.
pub(crate) fn beamasm_funcs() -> Option<&'static str> {
    static VALUE: OnceLock<Option<String>> = OnceLock::new();
    cached_string(&VALUE, "ARINSAL_BEAMASM_FUNCS")
}

/// `ARINSAL_BEAMASM_DUMP`: directory for native assembly dumps.
pub(crate) fn beamasm_dump() -> Option<&'static OsStr> {
    static VALUE: OnceLock<Option<OsString>> = OnceLock::new();
    VALUE
        .get_or_init(|| std::env::var_os("ARINSAL_BEAMASM_DUMP"))
        .as_deref()
}

/// `ARINSAL_BEAMASM_STATS=1`: print native-call counters when a VM drops.
pub(crate) fn beamasm_stats() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| {
        std::env::var_os("ARINSAL_BEAMASM_STATS").as_deref() == Some(OsStr::new("1"))
    })
}

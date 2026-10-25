//! Exit codes and exception flags of a process (`c_p->freason`).
//!
//! Port of erts/emulator/beam/error.h, OTP-29.1.1. The class is in bits 0..2
//! (`EXTAG_*`), the flags above it (`EXF_*`), and the index into the short-hand error table
//! from bit 10 (`GET_EXC_INDEX`).

/// Class tag: `error`.
pub const EXTAG_ERROR: u64 = 0;
/// Class tag: `exit`.
pub const EXTAG_EXIT: u64 = 1;
/// Class tag: `throw`.
pub const EXTAG_THROWN: u64 = 2;
/// Mask of the class bits (`EXC_CLASSBITS`).
pub const EXC_CLASSBITS: u64 = 3;

const EXF_OFFSET: u32 = 2;
/// Ignore catches.
pub const EXF_PANIC: u64 = 1 << EXF_OFFSET;
/// Nonlocal return.
pub const EXF_THROWN: u64 = 1 << (EXF_OFFSET + 1);
/// Write to the logger on termination.
pub const EXF_LOG: u64 = 1 << (EXF_OFFSET + 2);
/// Occurred in native code.
pub const EXF_NATIVE: u64 = 1 << (EXF_OFFSET + 3);
/// Save the stacktrace in internal form.
pub const EXF_SAVETRACE: u64 = 1 << (EXF_OFFSET + 4);
/// Has an argument list for the top of the trace.
pub const EXF_ARGLIST: u64 = 1 << (EXF_OFFSET + 5);
/// Restore the original bif/nif; a re-raise of a saved stacktrace uses it in `i_raise`.
pub const EXF_RESTORE_NFUNC: u64 = 1 << (EXF_OFFSET + 6);
/// Has extended error information; `raw_raise` of a stacktrace uses it.
pub const EXF_HAS_EXT_INFO: u64 = 1 << (EXF_OFFSET + 7);

/// Bit position of the error-table index.
pub const EXC_OFFSET: u32 = 10;
/// Mask of the error-table index (`EXC_INDEXBITS`).
pub const EXC_INDEXBITS: u64 = 0x1f << EXC_OFFSET;

/// `GET_EXC_INDEX`.
pub const fn exc_index(freason: u64) -> u64 {
    (freason & EXC_INDEXBITS) >> EXC_OFFSET
}

/// Initial value of `freason`: no exception.
pub const EXC_NULL: u64 = 0;
const EXC_PRIMARY: u64 = EXF_SAVETRACE;
/// Generic error, reason in `fvalue`.
pub const EXC_ERROR: u64 = EXC_PRIMARY | EXTAG_ERROR | EXF_LOG;
/// Generic exit, reason in `fvalue`.
pub const EXC_EXIT: u64 = EXC_PRIMARY | EXTAG_EXIT;
/// Generic nonlocal return, thrown term in `fvalue`.
pub const EXC_THROWN: u64 = EXC_PRIMARY | EXTAG_THROWN | EXF_THROWN;

const fn coded(index: u64) -> u64 {
    (index << EXC_OFFSET) | EXC_ERROR
}
/// Bad argument to a BIF.
pub const EXC_BADARG: u64 = coded(3);
/// Bad arithmetic.
pub const EXC_BADARITH: u64 = coded(4);
/// Bad match in a function body.
pub const EXC_BADMATCH: u64 = coded(5);
/// No matching function head.
pub const EXC_FUNCTION_CLAUSE: u64 = coded(6);
/// No matching case clause.
pub const EXC_CASE_CLAUSE: u64 = coded(7);
/// No matching if clause.
pub const EXC_IF_CLAUSE: u64 = coded(8);
/// No function of that arity.
pub const EXC_UNDEF: u64 = coded(9);
/// Ran out of something.
pub const EXC_SYSTEM_LIMIT: u64 = coded(15);
/// No matching try clause.
pub const EXC_TRY_CLAUSE: u64 = coded(16);
/// Not supported.
pub const EXC_NOTSUP: u64 = coded(17);
/// Bad map.
pub const EXC_BADMAP: u64 = coded(18);
/// Bad key in a map.
pub const EXC_BADKEY: u64 = coded(19);
/// Bad record.
pub const EXC_BADRECORD: u64 = coded(20);

/// BIF trap to Erlang code (`TRAP`).
pub const TRAP: u64 = 1 << EXC_OFFSET;

/// The class tag of an `freason` (`GET_EXC_CLASS`).
pub const fn exc_class(freason: u64) -> u64 {
    freason & EXC_CLASSBITS
}

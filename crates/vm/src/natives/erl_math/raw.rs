//! Raw libm calls used by erl_math.c BIF bodies.
//!
//! Port of erts/emulator/beam/erl_math.c (math_call_1, math_call_errno_1, math_call_2),
//! OTP-29.1.1.

use std::ffi::c_int;

// SAFETY: declarations match the platform C libm ABI and errno accessor signatures.
#[link(name = "m")]
unsafe extern "C" {
    #[link_name = "acos"]
    fn c_acos(x: f64) -> f64;
    #[link_name = "acosh"]
    fn c_acosh(x: f64) -> f64;
    #[link_name = "asin"]
    fn c_asin(x: f64) -> f64;
    #[link_name = "asinh"]
    fn c_asinh(x: f64) -> f64;
    #[link_name = "atan"]
    fn c_atan(x: f64) -> f64;
    #[link_name = "atan2"]
    fn c_atan2(y: f64, x: f64) -> f64;
    #[link_name = "atanh"]
    fn c_atanh(x: f64) -> f64;
    #[link_name = "ceil"]
    fn c_ceil(x: f64) -> f64;
    #[link_name = "cos"]
    fn c_cos(x: f64) -> f64;
    #[link_name = "cosh"]
    fn c_cosh(x: f64) -> f64;
    #[link_name = "erf"]
    fn c_erf(x: f64) -> f64;
    #[link_name = "erfc"]
    fn c_erfc(x: f64) -> f64;
    #[link_name = "exp"]
    fn c_exp(x: f64) -> f64;
    #[link_name = "floor"]
    fn c_floor(x: f64) -> f64;
    #[link_name = "fmod"]
    fn c_fmod(x: f64, y: f64) -> f64;
    #[link_name = "log"]
    fn c_log(x: f64) -> f64;
    #[link_name = "log10"]
    fn c_log10(x: f64) -> f64;
    #[link_name = "log2"]
    fn c_log2(x: f64) -> f64;
    #[link_name = "pow"]
    fn c_pow(x: f64, y: f64) -> f64;
    #[link_name = "sin"]
    fn c_sin(x: f64) -> f64;
    #[link_name = "sinh"]
    fn c_sinh(x: f64) -> f64;
    #[link_name = "sqrt"]
    fn c_sqrt(x: f64) -> f64;
    #[link_name = "tan"]
    fn c_tan(x: f64) -> f64;
    #[link_name = "tanh"]
    fn c_tanh(x: f64) -> f64;
    #[cfg(target_vendor = "apple")]
    fn __error() -> *mut c_int;
    #[cfg(not(target_vendor = "apple"))]
    fn __errno_location() -> *mut c_int;
}

macro_rules! unary {
    ($($name:ident => $function:ident),* $(,)?) => {
        $(
            pub(super) fn $name(value: f64) -> f64 {
                // SAFETY: each declaration is the platform libm function with this f64 signature.
                unsafe { $function(value) }
            }
        )*
    };
}

unary!(
    acos => c_acos,
    acosh => c_acosh,
    asin => c_asin,
    asinh => c_asinh,
    atan => c_atan,
    atanh => c_atanh,
    ceil => c_ceil,
    cos => c_cos,
    cosh => c_cosh,
    erf => c_erf,
    erfc => c_erfc,
    exp => c_exp,
    floor => c_floor,
    log => c_log,
    log10 => c_log10,
    log2 => c_log2,
    sin => c_sin,
    sinh => c_sinh,
    sqrt => c_sqrt,
    tan => c_tan,
    tanh => c_tanh,
);

macro_rules! binary {
    ($($name:ident => $function:ident),* $(,)?) => {
        $(
            pub(super) fn $name(first: f64, second: f64) -> f64 {
                // SAFETY: each declaration is the platform libm function with this f64 signature.
                unsafe { $function(first, second) }
            }
        )*
    };
}

binary!(atan2 => c_atan2, fmod => c_fmod, pow => c_pow);

/// Run a C99 errno-sensitive math call, preserving errno across result construction.
pub(super) fn with_errno<T>(call: impl FnOnce() -> T) -> (T, bool) {
    // SAFETY: the platform accessor returns this thread's errno slot; the call runs on this
    // thread, and the slot remains valid through result construction.
    unsafe {
        #[cfg(target_vendor = "apple")]
        let errno = __error();
        #[cfg(not(target_vendor = "apple"))]
        let errno = __errno_location();
        *errno = 0;
        let result = call();
        (result, *errno != 0)
    }
}

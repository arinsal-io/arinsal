//! Bignum conversions called by native code.
//!
//! Port of erts/emulator/beam/big.c, OTP-29.1.1.

/// `int big_to_double(Eterm x, double *resp)`: converts the bignum `x` to a double; -1 when
/// it is too large for one.
// Port of erts/emulator/beam/big.c (big_to_double), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn big_to_double(x: u64, resp: *mut f64) -> i32 {
    match crate::native_hooks::integer_float(crate::native_hooks::from_raw(x)) {
        Ok(value) => {
            crate::raw::jit_ffi::write_out(resp, value);
            0
        }
        Err(_) => -1,
    }
}

//! Map runtime symbols called by BeamAsm generated code.
//!
//! Port of erts/emulator/beam/erl_map.c, OTP-29.1.1.

use arinsal_beamasm::ProcessHeader;
use arinsal_maps::MapError;
use arinsal_term::Term;

fn term(raw: u64) -> Term {
    crate::native_hooks::from_raw(raw)
}

fn raw(value: Term) -> u64 {
    crate::native_hooks::raw(value)
}

/// Returns a pointer to the value stored under `key` in `map`.
// Port of erts/emulator/beam/erl_map.c:186-217 (erts_maps_get), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_maps_get(key: u64, map: u64) -> *const u64 {
    match arinsal_maps::get_ptr(term(map), term(key)) {
        Ok(Some(value)) => value,
        Ok(None) | Err(_) => std::ptr::null(),
    }
}

/// Looks up a key in a map, replacing it only when present.
// Port of erts/emulator/beam/erl_map.c:2036-2103 (erts_maps_update), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_maps_update(
    c_p: *mut ProcessHeader,
    key: u64,
    value: u64,
    map: u64,
    result: *mut u64,
) -> i32 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return 0;
    };
    match arinsal_maps::update(term(map), term(key), term(value), &mut process.heap) {
        Ok(updated) => {
            crate::raw::beam_common_ffi::write_word(result, raw(updated));
            1
        }
        Err(MapError::Badkey(_)) => 0,
        Err(error) => {
            crate::beam_common::set_map_error(process, error);
            0
        }
    }
}

/// Inserts or replaces one key in a map.
// Port of erts/emulator/beam/erl_map.c:2105-2232 (erts_maps_put), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_maps_put(c_p: *mut ProcessHeader, key: u64, value: u64, map: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return Term::NON_VALUE.tagged_word();
    };
    match arinsal_maps::put(term(map), term(key), term(value), &mut process.heap) {
        Ok(updated) => raw(updated),
        Err(error) => crate::beam_common::set_map_error(process, error),
    }
}

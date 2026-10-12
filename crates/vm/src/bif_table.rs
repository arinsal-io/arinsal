//! Function pointer for every BIF export.
//!
//! Port of erts/emulator/beam/erl_bif_table.c (`bif_table[].f`), OTP-29.1.1.
//! The pointer is chosen once, when the export is created. The call fragment
//! branches to it with `(c_p, reg, I)`. `invoke_dispatch_bif` is not that pointer.

use crate::native_helpers::{
    atom_to_list_light, erase_1_light, get_1_light, integer_to_binary_light, make_ref_light,
    node_light, persistent_term_get_1_light, persistent_term_get_2_light, process_flag_light,
    put_2_light, self_light, setelement_light, unique_integer_0_light, unique_integer_1_light,
};

/// `bif_table[i].f` for a BIF whose body is not the shared plain/process/trap adapter.
///
/// The lookup runs when the export is interned, not on the call. A miss means the
/// export's kind adapter (`plain_bif_light`, `process_bif_light`, …) is the pointer.
pub(crate) fn special(module: &str, function: &str, arity: u8) -> Option<usize> {
    let func = match (module, function, arity) {
        ("erlang", "whereis", 1) => crate::signals::whereis_light as *const () as usize,
        ("erlang", "is_process_alive", 1) => {
            crate::signals::is_process_alive_light as *const () as usize
        }
        ("erlang", "process_flag", 2) => process_flag_light as *const () as usize,
        ("erlang", "put", 2) => put_2_light as *const () as usize,
        ("erlang", "get", 1) => get_1_light as *const () as usize,
        ("erlang", "erase", 1) => erase_1_light as *const () as usize,
        ("erlang", "atom_to_list", 1) => atom_to_list_light as *const () as usize,
        ("erlang", "integer_to_binary", 1) => integer_to_binary_light as *const () as usize,
        ("erlang", "setelement", 3) => setelement_light as *const () as usize,
        ("erlang", "make_ref", 0) => make_ref_light as *const () as usize,
        ("erlang", "unique_integer", 0) => unique_integer_0_light as *const () as usize,
        ("erlang", "unique_integer", 1) => unique_integer_1_light as *const () as usize,
        // These were `light_dispatch` → `invoke_dispatch_bif` (Native, no process BIF).
        ("erlang", "self", 0) => self_light as *const () as usize,
        ("erlang", "node", 0) => node_light as *const () as usize,
        ("persistent_term", "get", 1) => persistent_term_get_1_light as *const () as usize,
        ("persistent_term", "get", 2) => persistent_term_get_2_light as *const () as usize,
        _ => return None,
    };
    Some(func)
}

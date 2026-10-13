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
/// BIF's own [`entry`] or the export's kind adapter (`process_bif_light`, …) is the
/// pointer.
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

/// The light entry of a trapping BIF with its own body, compiled when the export is created.
pub(crate) fn trap_entry(module: &str, function: &str, arity: u8) -> Option<usize> {
    use crate::bif_traps::{MapsFromList, MapsKeys, MapsMerge, MapsValues};
    use crate::native_helpers::trap_bif_entry;
    let func = match (module, function, arity) {
        ("maps", "keys", 1) => trap_bif_entry::<MapsKeys> as *const () as usize,
        ("maps", "values", 1) => trap_bif_entry::<MapsValues> as *const () as usize,
        ("maps", "merge", 2) => trap_bif_entry::<MapsMerge> as *const () as usize,
        ("maps", "from_list", 1) => trap_bif_entry::<MapsFromList> as *const () as usize,
        _ => return None,
    };
    Some(func)
}

/// The entries compiled for one BIF of `arinsal_bifs`: its body is inlined into
/// each, so the call needs no `Ctx` or heap fragment unless the body allocates.
#[derive(Clone, Copy)]
pub(crate) struct Entry {
    /// Called as a plain BIF.
    pub(crate) plain: usize,
    /// Called as a list BIF that traps on the reduction budget.
    pub(crate) list_slice: usize,
    /// Called as a list BIF that never allocates (see `native_helpers::list_slice_nonalloc_entry`).
    pub(crate) list_slice_nonalloc: usize,
}

/// Whether `lists:function/arity` never allocates on its common path, so its call needs no
/// native cursor conversion.
pub(crate) fn never_allocates(module: &str, function: &str, arity: u8) -> bool {
    matches!(
        (module, function, arity),
        ("lists", "keyfind", 3) | ("lists", "member", 2) | ("lists", "keymember", 3)
    )
}

/// The entry compiled for `module:function/arity`, if `arinsal_bifs` has that BIF.
///
/// Runs when the export is created, like the `bif_table` erts builds at boot.
pub(crate) fn entry(module: &str, function: &str, arity: u8) -> Option<Entry> {
    arinsal_bifs::visit_bif(module, function, arity, &mut Compile)
}

/// Compiles the light-BIF entries of one BIF body.
struct Compile;

impl arinsal_bifs::BifTableVisitor for Compile {
    type Output = Entry;
    fn entry<B: arinsal_bifs::BifBody>(&mut self) -> Entry {
        Entry {
            plain: crate::native_helpers::plain_bif_entry::<B> as *const () as usize,
            list_slice: crate::native_helpers::list_slice_bif_entry::<B> as *const () as usize,
            list_slice_nonalloc: crate::native_helpers::list_slice_nonalloc_entry::<B> as *const ()
                as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::entry;

    #[test]
    fn every_bif_of_arinsal_bifs_has_its_own_entry() {
        let keyfind = entry("lists", "keyfind", 3).expect("keyfind");
        let element = entry("erlang", "element", 2).expect("element");
        assert_ne!(keyfind.plain, element.plain);
        assert_ne!(keyfind.plain, keyfind.list_slice);
        // Arities that share one body share its entry.
        let node0 = entry("erlang", "node", 0).expect("node/0");
        let node1 = entry("erlang", "node", 1).expect("node/1");
        assert_eq!(node0.plain, node1.plain);
        assert!(entry("erlang", "no_such_bif", 1).is_none());
        assert!(entry("lists", "keyfind", 2).is_none());
    }
}

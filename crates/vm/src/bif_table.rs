//! Function pointer for every BIF export.
//!
//! Port of erts/emulator/beam/erl_bif_table.c (`bif_table[].f`), OTP-29.1.1.
//! The pointer is chosen once, when the export is created. The call fragment
//! branches to it with `(c_p, reg, I)`. `invoke_dispatch_bif` is not that pointer.

use crate::native_helpers::{
    atom_to_list_light, binary_part_2_light, binary_part_3_light, bit_size_light, byte_size_light,
    erase_1_light, get_1_light, integer_to_binary_light, make_ref_light, node_light,
    persistent_term_get_1_light, persistent_term_get_2_light, process_flag_light, put_2_light,
    self_light, setelement_light, unique_integer_0_light, unique_integer_1_light,
};

/// Binary guards whose erts entries have dedicated BeamAsm BIF functions.
#[derive(Clone, Copy)]
pub(crate) enum BinaryGuard {
    ByteSize,
    BitSize,
    BinaryPart,
}

pub(crate) fn binary_guard(module: &str, function: &str, arity: u8) -> Option<BinaryGuard> {
    match (module, function, arity) {
        ("erlang", "byte_size", 1) => Some(BinaryGuard::ByteSize),
        ("erlang", "bit_size", 1) => Some(BinaryGuard::BitSize),
        ("erlang", "binary_part", 2) | ("binary", "part", 2) => Some(BinaryGuard::BinaryPart),
        ("erlang", "binary_part", 3) | ("binary", "part", 3) => Some(BinaryGuard::BinaryPart),
        _ => None,
    }
}

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
        ("erlang", "send_after", 3 | 4) => {
            crate::native_helpers::timer_start_light::<true> as *const () as usize
        }
        ("erlang", "start_timer", 3 | 4) => {
            crate::native_helpers::timer_start_light::<false> as *const () as usize
        }
        ("erlang", "cancel_timer", 1 | 2) => {
            crate::native_helpers::timer_query_light::<true> as *const () as usize
        }
        ("erlang", "read_timer", 1 | 2) => {
            crate::native_helpers::timer_query_light::<false> as *const () as usize
        }
        ("erlang", "group_leader", 0) => {
            crate::native_helpers::group_leader_0_light as *const () as usize
        }
        ("erlang", "process_info", 2) => {
            crate::native_helpers::process_info_2_light as *const () as usize
        }
        // The C BIFs have direct entries in external.c rather than the generic trap adapter.
        ("erlang", "term_to_binary", 1) => {
            crate::bif_traps::term_to_binary_1_light as *const () as usize
        }
        ("erlang", "external_size", 1) => {
            crate::bif_traps::external_size_1_light as *const () as usize
        }
        ("erlang", "binary_to_term", 1) => {
            crate::bif_traps::binary_to_term_1_light as *const () as usize
        }
        ("erlang", "put", 2) => put_2_light as *const () as usize,
        ("erlang", "get", 1) => get_1_light as *const () as usize,
        ("erlang", "erase", 1) => erase_1_light as *const () as usize,
        ("erlang", "atom_to_list", 1) => atom_to_list_light as *const () as usize,
        ("erlang", "integer_to_binary", 1) => integer_to_binary_light as *const () as usize,
        ("erlang", "byte_size", 1) => byte_size_light as *const () as usize,
        ("erlang", "bit_size", 1) => bit_size_light as *const () as usize,
        ("erlang", "binary_part", 2) | ("binary", "part", 2) => {
            binary_part_2_light as *const () as usize
        }
        ("erlang", "binary_part", 3) | ("binary", "part", 3) => {
            binary_part_3_light as *const () as usize
        }
        ("erlang", "setelement", 3) => setelement_light as *const () as usize,
        ("erlang", "make_ref", 0) => make_ref_light as *const () as usize,
        ("erlang", "unique_integer", 0) => unique_integer_0_light as *const () as usize,
        ("erlang", "unique_integer", 1) => unique_integer_1_light as *const () as usize,
        // These were `light_dispatch` → `invoke_dispatch_bif` (Native, no process BIF).
        ("erlang", "self", 0) => self_light as *const () as usize,
        ("erlang", "node", 0) => node_light as *const () as usize,
        ("lists", "member", 2) => crate::native_helpers::list_member_entry as *const () as usize,
        ("persistent_term", "get", 1) => persistent_term_get_1_light as *const () as usize,
        ("persistent_term", "get", 2) => persistent_term_get_2_light as *const () as usize,
        _ => return None,
    };
    Some(func)
}

/// The light entry of a trapping BIF with its own body, compiled when the export is created.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:421-447, OTP-29.1.1: the fragment calls the
// selected BIF body directly; that body leaves the light path only when it traps.
pub(crate) fn trap_entry(module: &str, function: &str, arity: u8) -> Option<usize> {
    use crate::bif_traps::{
        BinaryToTerm, IolistSize, IolistToBinary, IolistToIovec, ListToBinary, MapsFromList,
        MapsKeys, MapsMerge, MapsValues, Phash2, TermToBinary,
    };
    use crate::native_helpers::trap_bif_entry;
    if module == "erlang" && function == "binary_to_list" && matches!(arity, 1 | 3) {
        return arinsal_bifs::visit_bif(module, function, arity, &mut BinaryToListEntry);
    }
    let func = match (module, function, arity) {
        ("maps", "keys", 1) => trap_bif_entry::<MapsKeys> as *const () as usize,
        ("maps", "values", 1) => trap_bif_entry::<MapsValues> as *const () as usize,
        ("maps", "merge", 2) => trap_bif_entry::<MapsMerge> as *const () as usize,
        ("maps", "from_list", 1) => trap_bif_entry::<MapsFromList> as *const () as usize,
        ("erlang", "list_to_binary", 1) | ("binary", "list_to_bin", 1) => {
            trap_bif_entry::<ListToBinary> as *const () as usize
        }
        ("erlang", "iolist_to_binary", 1) => trap_bif_entry::<IolistToBinary> as *const () as usize,
        ("erlang", "iolist_size", 1) => trap_bif_entry::<IolistSize> as *const () as usize,
        ("erlang", "iolist_to_iovec", 1) => trap_bif_entry::<IolistToIovec> as *const () as usize,
        ("erlang", "term_to_binary", 1 | 2) => trap_bif_entry::<TermToBinary> as *const () as usize,
        ("erlang", "phash2", 1) => trap_bif_entry::<Phash2<1>> as *const () as usize,
        ("erlang", "phash2", 2) => trap_bif_entry::<Phash2<2>> as *const () as usize,
        ("erlang", "binary_to_term", 1 | 2) => trap_bif_entry::<BinaryToTerm> as *const () as usize,
        ("lists", "reverse", 2) => crate::native_helpers::list_reverse_entry as *const () as usize,
        _ => return None,
    };
    Some(func)
}

struct BinaryToListEntry;

impl arinsal_bifs::BifTableVisitor for BinaryToListEntry {
    type Output = usize;

    fn entry<B: arinsal_bifs::BifBody>(&mut self) -> Self::Output {
        crate::native_helpers::trap_bif_entry::<crate::bif_traps::BinaryToList<B>> as *const ()
            as usize
    }
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
    use super::{entry, special, trap_entry};

    #[test]
    fn every_bif_of_arinsal_bifs_has_its_own_entry() {
        let keyfind = entry("lists", "keyfind", 3).expect("keyfind");
        let element = entry("erlang", "element", 2).expect("element");
        assert_ne!(keyfind.plain, element.plain);
        assert_ne!(keyfind.plain, keyfind.list_slice);
        // Arities that share one body share its entry.
        let node0 = entry("erlang", "node", 0).expect("node/0");
        let node1 = entry("erlang", "node", 1).expect("node/1");
        similar_asserts::assert_eq!(node0.plain, node1.plain);
        assert!(entry("erlang", "no_such_bif", 1).is_none());
        assert!(entry("lists", "keyfind", 2).is_none());
    }

    #[test]
    fn binary_conversions_have_dedicated_trap_entries() {
        let binary_to_list = trap_entry("erlang", "binary_to_list", 1).unwrap();
        similar_asserts::assert_eq!(
            binary_to_list,
            trap_entry("erlang", "binary_to_list", 3).unwrap()
        );
        let list_to_binary = trap_entry("erlang", "list_to_binary", 1).unwrap();
        similar_asserts::assert_eq!(
            list_to_binary,
            trap_entry("binary", "list_to_bin", 1).unwrap()
        );
        assert_ne!(
            list_to_binary,
            trap_entry("erlang", "iolist_size", 1).unwrap()
        );
        assert_ne!(
            list_to_binary,
            trap_entry("erlang", "iolist_to_binary", 1).unwrap()
        );
        assert!(trap_entry("erlang", "not_a_binary_bif", 1).is_none());
    }

    #[test]
    fn external_term_bifs_have_direct_arity_one_entries() {
        let direct = [
            (
                "term_to_binary",
                crate::bif_traps::term_to_binary_1_light as *const () as usize,
            ),
            (
                "external_size",
                crate::bif_traps::external_size_1_light as *const () as usize,
            ),
            (
                "binary_to_term",
                crate::bif_traps::binary_to_term_1_light as *const () as usize,
            ),
        ];
        for (function, expected) in direct {
            similar_asserts::assert_eq!(special("erlang", function, 1), Some(expected));
        }
        assert!(special("erlang", "term_to_binary", 2).is_none());
        assert!(special("erlang", "binary_to_term", 2).is_none());
    }
}

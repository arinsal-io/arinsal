//! Function pointer for every BIF export.
//!
//! Port of erts/emulator/beam/erl_bif_table.c (`bif_table[].f`), OTP-29.1.1.
//! The pointer is chosen once, when the export is created. The call fragment
//! branches to it with `(c_p, reg, I)`. `invoke_dispatch_bif` is not that pointer.

mod raw;

use arinsal_beamasm::ProcessHeader;
use std::sync::atomic::{AtomicUsize, Ordering};

/// `BIF_RETTYPE (*)(BIF_ALIST)`: `(c_p, reg, I)`, the term or THE_NON_VALUE (0).
// Port of erts/emulator/beam/bif.h (BIF_ALIST, BIF_RETTYPE) and erl_bif_table.h (`ErtsBifFunc`),
// OTP-29.1.1.
pub(crate) type Bif = extern "C" fn(*mut ProcessHeader, *mut u64, u64) -> u64;

/// A BIF function's address, checked against [`Bif`] where it is taken.
macro_rules! bif {
    ($f:expr) => {{
        let f: $crate::bif_table::Bif = $f;
        f as usize
    }};
}
pub(crate) use bif;

/// Number of `bif_table` entries: bif.tab plus the dirty continuation BIFs.
// The five erts_internal:dirty_bif_* continuations follow bif.tab (spec DIRTY_CONTINUATION_BIFS).
pub(crate) const BIF_SIZE: usize = arinsal_spec::BIFS.len() + 5;

/// `bif_table[bif_number].f`, indexed by `Export.bif_number`. Zero for a BIF whose body is not
/// reached from native code yet (its export trampoline calls it).
// Port of erts/emulator/beam/erl_bif_table.c (`bif_table`), OTP-29.1.1. erts generates this
// array from bif.tab at build time; here each entry is written by `install_bifs` once, as the
// body each BIF reaches is still chosen per MFA (W2..Wn move bodies to their erts files).
static BIF_TABLE: [AtomicUsize; BIF_SIZE] = [const { AtomicUsize::new(0) }; BIF_SIZE];

/// Address of `bif_table`, which the call fragments index by `Export.bif_number`.
pub(crate) fn table_address() -> usize {
    BIF_TABLE.as_ptr() as usize
}

/// `bif_table[bif_number].f`, or 0.
pub(crate) fn function(bif_number: i32) -> usize {
    usize::try_from(bif_number)
        .ok()
        .and_then(|number| BIF_TABLE.get(number))
        .map_or(0, |f| f.load(Ordering::Acquire))
}

/// Sets `bif_table[bif_number].f` (install_bifs).
// Port of erts/emulator/beam/jit/beam_jit_main.cpp (install_bifs), OTP-29.1.1.
pub(crate) fn install(bif_number: i32, f: usize) {
    if let Some(entry) = usize::try_from(bif_number)
        .ok()
        .and_then(|number| BIF_TABLE.get(number))
    {
        entry.store(f, Ordering::Release);
    }
}

/// Whether `bif_table[]` has a body of its own for this BIF, as `install_bifs` would set it.
// Port of erts/emulator/beam/erl_bif_table.c (`bif_table[].f`), OTP-29.1.1.
pub fn has_function(module: &str, function: &str, arity: u8) -> bool {
    special(module, function, arity).is_some()
}

/// `Export.info` of the BIF being called: `c_p->current`, set by the call fragment.
pub(crate) fn current_info(header: *mut ProcessHeader) -> u64 {
    raw::header_current(header)
}

/// `(Export.info, Export*)` of the BIF being called: the call fragment points `c_p->current`
/// at the export's info before it calls `bif_table[].f`.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:399-405 (call_light_bif_shared stores
// `&exp->info.mfa` in `c_p->current`), OTP-29.1.1.
pub(crate) fn current_export(header: *mut ProcessHeader) -> (u64, u64) {
    let info = current_info(header);
    if info == 0 {
        return (0, 0);
    }
    let identity = crate::beamasm_integration::export_from_info(info).map_or(0, |export| {
        std::sync::Arc::as_ptr(export.export_object()) as u64
    });
    (info, identity)
}

/// Runs `bif_table[bif_number].f` for a BIF the executor calls by its MFA (a traced BIF, an
/// `apply` the executor resolves): the same function the call fragments branch to, with
/// `(c_p, reg, I)`. `None` when the entry is not a BIF body yet (no entry, or the W1 shim that
/// parks the call in the executor, whose named native runs it instead).
// Port of erts/emulator/beam/beam_bp.c (erts_bif_trace: `(*bif)(p, args, I)` through the BIF
// table), OTP-29.1.1.
pub(crate) fn call_from_executor(
    process: &mut crate::Process,
    module: &str,
    function: &str,
    arity: usize,
) -> Option<Result<arinsal_term::Term, crate::VmError>> {
    let spec = arinsal_spec::bif_lookup(module, function, u8::try_from(arity).ok()?)?;
    let func = function_at(usize::from(spec.index))?;
    // The executor calls the BIF as its export entry does: the trampoline stores the
    // export's info word in `c_p->current` first, which BIF_ERROR and BIF_TRAP* name.
    let export = crate::beamasm_integration::bif_mfa_export(module, function, spec.arity)?;
    process.heap.abi.current = std::ptr::from_ref(export).cast();
    process.x.ensure_x(arity.max(1));
    let reg = std::ptr::from_mut(&mut process.x[0]).cast::<u64>();
    let c_p = std::ptr::from_mut(process).cast::<ProcessHeader>();
    let raw = func(c_p, reg, 0);
    if raw != arinsal_term::THE_NON_VALUE {
        return Some(Ok(crate::native_hooks::from_raw(raw)));
    }
    let args = process.x[..arity].to_vec();
    Some(Err(
        match crate::native_helpers::decode_failure(&mut process.heap.abi.exc) {
            Some(error) => crate::exceptions::bif_error(process, module, function, &args, error),
            // BIF_TRAP*: the executor makes the trap export's call next.
            None => match crate::bif_traps::take_export_trap(process) {
                Some(trap) => crate::VmError::TrapExport(trap),
                None => crate::VmError::Unsupported(format!(
                    "{module}:{function}/{arity}: BIF_TRAP from the executor"
                )),
            },
        },
    ))
}

/// The [`Bif`] at `bif_table[index]`, unless it is empty or the executor shim.
fn function_at(index: usize) -> Option<Bif> {
    let address = BIF_TABLE.get(index)?.load(Ordering::Acquire);
    if address == 0 || address == bif!(crate::native_helpers::yield_executor_bif) {
        return None;
    }
    Some(raw::bif_at(address))
}

use crate::native_helpers::{
    atom_to_list_light, binary_part_2_light, binary_part_3_light, bit_size_light, byte_size_light,
    integer_to_binary_light, make_ref_light, persistent_term_get_1_light,
    persistent_term_get_2_light, setelement_light, unique_integer_0_light, unique_integer_1_light,
};
use crate::natives::{
    erl_bif_info, erl_bif_lists, erl_hl_timer, erl_map, erl_process_dict, register,
};

/// Binary guards whose erts entries have dedicated BeamAsm BIF functions.
#[derive(Clone, Copy)]
pub(crate) enum BinaryGuard {
    ByteSize,
    BitSize,
    BinaryPart2,
    BinaryPart3,
}

pub(crate) fn binary_guard(module: &str, function: &str, arity: u8) -> Option<BinaryGuard> {
    match (module, function, arity) {
        ("erlang", "byte_size", 1) => Some(BinaryGuard::ByteSize),
        ("erlang", "bit_size", 1) => Some(BinaryGuard::BitSize),
        ("erlang", "binary_part", 2) | ("binary", "part", 2) => Some(BinaryGuard::BinaryPart2),
        ("erlang", "binary_part", 3) | ("binary", "part", 3) => Some(BinaryGuard::BinaryPart3),
        _ => None,
    }
}

/// The `i_bif*` function of a binary guard BIF, chosen when the call site is emitted.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:110-151 (`mov ARG, bif->f` at load time),
// OTP-29.1.1: the guard is known from the import, never recognised by name per call.
pub(crate) fn guard_helper(module: &str, function: &str, arity: u8) -> Option<usize> {
    use crate::native_helpers::{
        binary_part_2_guard, binary_part_3_guard, bit_size_guard, byte_size_guard,
    };
    Some(match binary_guard(module, function, arity)? {
        BinaryGuard::ByteSize => byte_size_guard as *const () as usize,
        BinaryGuard::BitSize => bit_size_guard as *const () as usize,
        BinaryGuard::BinaryPart2 => binary_part_2_guard as *const () as usize,
        BinaryGuard::BinaryPart3 => binary_part_3_guard as *const () as usize,
    })
}

/// `bif_table[i].f` for a BIF whose body is not the shared plain/process/trap adapter.
///
/// The lookup runs when the export is interned, not on the call. A miss means the
/// BIF's own [`entry`] or the export's kind adapter (`process_bif_light`, …) is the
/// pointer.
pub(crate) fn special(module: &str, function: &str, arity: u8) -> Option<usize> {
    let func = match (module, function, arity) {
        // register.c
        ("erlang", "register", 2) => bif!(register::register_2),
        ("erlang", "unregister", 1) => bif!(register::unregister_1),
        ("erlang", "whereis", 1) => bif!(register::whereis_1),
        ("erlang", "registered", 0) => bif!(register::registered_0),
        // erl_bif_info.c
        ("erlang", "is_process_alive", 1) => bif!(erl_bif_info::is_process_alive_1),
        ("erlang", "process_info", 2) => {
            bif!(crate::native_helpers::process_info_2_light)
        }
        // The C BIFs have direct entries in external.c rather than the generic trap adapter.
        ("erlang", "term_to_binary", 1) => {
            bif!(crate::bif_traps::term_to_binary_1_light)
        }
        ("erlang", "external_size", 1) => {
            bif!(crate::bif_traps::external_size_1_light)
        }
        ("erlang", "binary_to_term", 1) => {
            bif!(crate::bif_traps::binary_to_term_1_light)
        }
        // erl_bif_lists.c
        ("erlang", "++", 2) => bif!(erl_bif_lists::ebif_plusplus_2),
        ("erlang", "append", 2) => bif!(erl_bif_lists::append_2),
        ("erlang", "--", 2) => bif!(erl_bif_lists::ebif_minusminus_2),
        ("erlang", "subtract", 2) => bif!(erl_bif_lists::subtract_2),
        ("lists", "member", 2) => bif!(erl_bif_lists::lists_member_2),
        ("lists", "reverse", 2) => bif!(erl_bif_lists::lists_reverse_2),
        ("lists", "keymember", 3) => bif!(erl_bif_lists::lists_keymember_3),
        ("lists", "keysearch", 3) => bif!(erl_bif_lists::lists_keysearch_3),
        ("lists", "keyfind", 3) => bif!(erl_bif_lists::lists_keyfind_3),
        // erl_map.c
        ("maps", "from_list", 1) => bif!(erl_map::maps_from_list_1),
        ("maps", "from_keys", 2) => bif!(erl_map::maps_from_keys_2),
        ("maps", "keys", 1) => bif!(erl_map::maps_keys_1),
        ("maps", "values", 1) => bif!(erl_map::maps_values_1),
        // erl_process_dict.c
        ("erlang", "get", 0) => bif!(erl_process_dict::get_0),
        ("erlang", "get", 1) => bif!(erl_process_dict::get_1),
        ("erlang", "get_keys", 0) => bif!(erl_process_dict::get_keys_0),
        ("erlang", "get_keys", 1) => bif!(erl_process_dict::get_keys_1),
        ("erlang", "put", 2) => bif!(erl_process_dict::put_2),
        ("erlang", "erase", 0) => bif!(erl_process_dict::erase_0),
        ("erlang", "erase", 1) => bif!(erl_process_dict::erase_1),
        // erl_bif_os.c
        ("os", "env", 0) => bif!(crate::natives::erl_bif_os::env_0),
        ("os", "getenv", 1) => bif!(crate::natives::erl_bif_os::getenv_1),
        ("os", "putenv", 2) => bif!(crate::natives::erl_bif_os::putenv_2),
        ("os", "unsetenv", 1) => bif!(crate::natives::erl_bif_os::unsetenv_1),
        ("os", "set_signal", 2) => bif!(crate::natives::erl_bif_os::set_signal_2),
        ("erlang", "atom_to_list", 1) => bif!(atom_to_list_light),
        ("erlang", "integer_to_binary", 1) => bif!(integer_to_binary_light),
        ("erlang", "byte_size", 1) => bif!(byte_size_light),
        ("erlang", "bit_size", 1) => bif!(bit_size_light),
        ("erlang", "binary_part", 2) | ("binary", "part", 2) => {
            bif!(binary_part_2_light)
        }
        ("erlang", "binary_part", 3) | ("binary", "part", 3) => {
            bif!(binary_part_3_light)
        }
        ("erlang", "setelement", 3) => bif!(setelement_light),
        ("erlang", "make_ref", 0) => bif!(make_ref_light),
        ("erlang", "unique_integer", 0) => bif!(unique_integer_0_light),
        ("erlang", "unique_integer", 1) => bif!(unique_integer_1_light),
        // These were `light_dispatch` → `invoke_dispatch_bif` (Native, no process BIF).
        ("erlang", "node", 0) => bif!(crate::dist::node_0),
        ("persistent_term", "get", 1) => bif!(persistent_term_get_1_light),
        ("persistent_term", "get", 2) => bif!(persistent_term_get_2_light),
        // bif.c
        ("erlang", "monitor", 2) => bif!(crate::natives::bif::monitor_2),
        ("erlang", "monitor", 3) => bif!(crate::natives::bif::monitor_3),
        ("erlang", "demonitor", 1) => bif!(crate::natives::bif::demonitor_1),
        ("erlang", "demonitor", 2) => bif!(crate::natives::bif::demonitor_2),
        ("erlang", "self", 0) => bif!(crate::natives::bif::self_0),
        ("erlang", "group_leader", 0) => bif!(crate::natives::bif::group_leader_0),
        ("erts_internal", "group_leader", 2) => {
            bif!(crate::natives::bif::erts_internal_group_leader_2)
        }
        ("erlang", "process_flag", 2) => bif!(crate::natives::bif::process_flag_2),
        ("erlang", "!", 2) => bif!(crate::natives::bif::ebif_bang_2),
        ("erlang", "send", 2) => bif!(crate::natives::bif::send_2),
        ("erlang", "send", 3) => bif!(crate::natives::bif::send_3),
        ("erlang", "link", 1) => bif!(crate::natives::bif::link_1),
        ("erlang", "link", 2) => bif!(crate::natives::bif::link_2),
        ("erlang", "unlink", 1) => bif!(crate::natives::bif::unlink_1),
        ("erlang", "exit", 2) => bif!(crate::natives::bif::exit_2),
        ("erlang", "exit", 3) => bif!(crate::natives::bif::exit_3),
        ("erlang", "exit_signal", 2) => bif!(crate::natives::bif::exit_signal_2),
        ("erlang", "exit_signal", 3) => bif!(crate::natives::bif::exit_signal_3),
        ("erlang", "spawn", 3) => bif!(crate::natives::bif::spawn_3),
        ("erlang", "spawn_link", 3) => bif!(crate::natives::bif::spawn_link_3),
        ("erlang", "spawn_opt", 4) => bif!(crate::natives::bif::spawn_opt_4),
        ("erts_internal", "spawn_request", 4) => {
            bif!(crate::natives::bif::erts_internal_spawn_request_4)
        }
        ("erlang", "spawn_request_abandon", 1) => {
            bif!(crate::natives::bif::spawn_request_abandon_1)
        }
        ("erlang", "alias", 1) => bif!(crate::natives::bif::alias_1),
        ("erlang", "unalias", 1) => bif!(crate::natives::bif::unalias_1),
        // erl_hl_timer.c
        ("erlang", "send_after", 3) => bif!(erl_hl_timer::send_after_3),
        ("erlang", "send_after", 4) => bif!(erl_hl_timer::send_after_4),
        ("erlang", "start_timer", 3) => bif!(erl_hl_timer::start_timer_3),
        ("erlang", "start_timer", 4) => bif!(erl_hl_timer::start_timer_4),
        ("erlang", "cancel_timer", 1) => bif!(erl_hl_timer::cancel_timer_1),
        ("erlang", "cancel_timer", 2) => bif!(erl_hl_timer::cancel_timer_2),
        ("erlang", "read_timer", 1) => bif!(erl_hl_timer::read_timer_1),
        ("erlang", "read_timer", 2) => bif!(erl_hl_timer::read_timer_2),
        ("erlang", "finish_loading", 1) => sched_entry::<FinishLoading1>(),
        ("erlang", "has_prepared_code_on_load", 1) => sched_entry::<HasPreparedCodeOnLoad1>(),
        ("erlang", "load_nif", 2) => sched_entry::<LoadNif2>(),
        ("erlang", "nodes", 2) => sched_entry::<Nodes2>(),
        ("erlang", "bif_return_trap", 2) => sched_entry::<BifReturnTrap2>(),
        ("persistent_term", "put", 2) => sched_entry::<PersistentTermPut2>(),
        ("persistent_term", "put_new", 2) => sched_entry::<PersistentTermPutNew2>(),
        ("persistent_term", "erase", 1) => sched_entry::<PersistentTermErase1>(),
        ("erts_internal", "erase_persistent_terms", 0) => sched_entry::<ErasePersistentTerms0>(),
        ("persistent_term", "get", 0) => sched_entry::<PersistentTermGet0>(),
        _ => return None,
    };
    Some(func)
}

/// The light entry of a trapping BIF with its own body, compiled when the export is created.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:421-447, OTP-29.1.1: the fragment calls the
// selected BIF body directly; that body leaves the light path only when it traps.
pub(crate) fn trap_entry(module: &str, function: &str, arity: u8) -> Option<usize> {
    use crate::bif_traps::{
        BinaryToTerm, IolistSize, IolistToBinary, IolistToIovec, ListToBinary, MapsMerge, Phash2,
        TermToBinary,
    };
    use crate::native_helpers::trap_bif_entry;
    if module == "erlang" && function == "binary_to_list" && matches!(arity, 1 | 3) {
        return arinsal_bifs::visit_bif(module, function, arity, &mut BinaryToListEntry);
    }
    let func = match (module, function, arity) {
        ("maps", "merge", 2) => bif!(trap_bif_entry::<MapsMerge>),
        ("erlang", "list_to_binary", 1) | ("binary", "list_to_bin", 1) => {
            bif!(trap_bif_entry::<ListToBinary>)
        }
        ("erlang", "iolist_to_binary", 1) => bif!(trap_bif_entry::<IolistToBinary>),
        ("erlang", "iolist_size", 1) => bif!(trap_bif_entry::<IolistSize>),
        ("erlang", "iolist_to_iovec", 1) => bif!(trap_bif_entry::<IolistToIovec>),
        ("erlang", "term_to_binary", 1 | 2) => bif!(trap_bif_entry::<TermToBinary>),
        ("erlang", "phash2", 1) => bif!(trap_bif_entry::<Phash2<1>>),
        ("erlang", "phash2", 2) => bif!(trap_bif_entry::<Phash2<2>>),
        ("erlang", "binary_to_term", 1 | 2) => bif!(trap_bif_entry::<BinaryToTerm>),
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
            plain: bif!(crate::native_helpers::plain_bif_entry::<B>),
        }
    }
}

/// `bif_table[].f` of a BIF whose body needs its scheduler's data.
fn sched_entry<B: crate::native_helpers::SchedBif>() -> usize {
    bif!(crate::native_helpers::sched_bif_light::<B>)
}

/// `erlang:finish_loading/1`.
struct FinishLoading1;
impl crate::native_helpers::SchedBif for FinishLoading1 {
    const ARITY: usize = 1;
    const BODY: crate::natives::DirectNative = crate::natives::code::finish_loading_1;
}

/// `erlang:has_prepared_code_on_load/1`.
struct HasPreparedCodeOnLoad1;
impl crate::native_helpers::SchedBif for HasPreparedCodeOnLoad1 {
    const ARITY: usize = 1;
    const BODY: crate::natives::DirectNative = crate::natives::code::has_prepared_code_on_load_1;
}

/// `erlang:load_nif/2`.
struct LoadNif2;
impl crate::native_helpers::SchedBif for LoadNif2 {
    const ARITY: usize = 2;
    const BODY: crate::natives::DirectNative = crate::natives::nif::load_nif_2;
}

/// `erlang:nodes/2`. Port of erts/emulator/beam/dist.c (nodes_2), OTP-29.1.1.
struct Nodes2;
impl crate::native_helpers::SchedBif for Nodes2 {
    const ARITY: usize = 2;
    const BODY: crate::natives::DirectNative = crate::natives::node::call_nodes2;
}

/// `erlang:bif_return_trap/2`. Port of erts/emulator/beam/bif.c (bif_return_trap), OTP-29.1.1.
struct BifReturnTrap2;
impl crate::native_helpers::SchedBif for BifReturnTrap2 {
    const ARITY: usize = 2;
    const BODY: crate::natives::DirectNative = crate::natives::sys::bif_return_trap_2;
}

/// A [`crate::native_helpers::SchedBif`] named by its body.
macro_rules! sched_bif {
    ($(#[$doc:meta])* $name:ident, $arity:literal, $body:path) => {
        $(#[$doc])*
        struct $name;
        impl crate::native_helpers::SchedBif for $name {
            const ARITY: usize = $arity;
            const BODY: crate::natives::DirectNative = $body;
        }
    };
}

sched_bif!(
    /// `persistent_term:put/2`. Port of erl_bif_persistent.c (persistent_term_put_2).
    PersistentTermPut2, 2, crate::natives::sys::persistent_term_put_2
);
sched_bif!(
    /// `persistent_term:put_new/2`. Port of erl_bif_persistent.c (persistent_term_put_new_2).
    PersistentTermPutNew2, 2, crate::natives::sys::persistent_term_put_new_2
);
sched_bif!(
    /// `persistent_term:erase/1`. Port of erl_bif_persistent.c (persistent_term_erase_1).
    PersistentTermErase1, 1, crate::natives::sys::persistent_term_erase_1
);
sched_bif!(
    /// `erts_internal:erase_persistent_terms/0`. Port of erl_bif_persistent.c.
    ErasePersistentTerms0, 0, crate::natives::sys::erase_persistent_terms_0
);
sched_bif!(
    /// `persistent_term:get/0`. Port of erl_bif_persistent.c (persistent_term_get_0).
    PersistentTermGet0, 0, crate::natives::sys::persistent_term_get_0
);

#[cfg(test)]
mod tests {
    use super::{entry, special, trap_entry};

    // install_bifs fills `bif_table[ep->bif_number]`; the export itself carries no function.
    #[test]
    fn a_bif_export_reaches_its_function_through_bif_number() {
        let atoms = arinsal_term::global_atoms();
        let mfa = (
            atoms.intern("erlang").expect("atom"),
            atoms.intern("self").expect("atom"),
            0,
        );
        let export = crate::beamasm_integration::make_export(mfa).expect("export");
        let number = export.bif_number();
        let spec = arinsal_spec::bif_lookup("erlang", "self", 0).expect("bif.tab entry");
        similar_asserts::assert_eq!(number, i32::from(spec.index));
        similar_asserts::assert_eq!(
            super::function(number),
            super::bif!(crate::natives::bif::self_0)
        );
        similar_asserts::assert_eq!(super::function(-1), 0);
    }

    #[test]
    fn every_bif_of_arinsal_bifs_has_its_own_entry() {
        let element = entry("erlang", "element", 2).expect("element");
        let hd = entry("erlang", "hd", 1).expect("hd");
        assert_ne!(hd.plain, element.plain);
        // Arities that share one body share its entry.
        let node0 = entry("erlang", "node", 0).expect("node/0");
        let node1 = entry("erlang", "node", 1).expect("node/1");
        similar_asserts::assert_eq!(node0.plain, node1.plain);
        assert!(entry("erlang", "no_such_bif", 1).is_none());
        assert!(entry("erlang", "element", 3).is_none());
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
                bif!(crate::bif_traps::term_to_binary_1_light),
            ),
            (
                "external_size",
                bif!(crate::bif_traps::external_size_1_light),
            ),
            (
                "binary_to_term",
                bif!(crate::bif_traps::binary_to_term_1_light),
            ),
        ];
        for (function, expected) in direct {
            similar_asserts::assert_eq!(special("erlang", function, 1), Some(expected));
        }
        assert!(special("erlang", "term_to_binary", 2).is_none());
        assert!(special("erlang", "binary_to_term", 2).is_none());
    }

    #[test]
    fn os_environment_bifs_have_direct_entries() {
        let entries = [
            ("env", 0, bif!(crate::natives::erl_bif_os::env_0)),
            ("getenv", 1, bif!(crate::natives::erl_bif_os::getenv_1)),
            ("putenv", 2, bif!(crate::natives::erl_bif_os::putenv_2)),
            ("unsetenv", 1, bif!(crate::natives::erl_bif_os::unsetenv_1)),
            (
                "set_signal",
                2,
                bif!(crate::natives::erl_bif_os::set_signal_2),
            ),
        ];
        for (function, arity, expected) in entries {
            similar_asserts::assert_eq!(special("os", function, arity), Some(expected));
            assert!(super::has_function("os", function, arity));
        }
    }
}

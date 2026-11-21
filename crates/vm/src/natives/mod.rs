//! Process-aware native functions (BIFs and NIF bindings that need the VM or
//! the calling process), grouped by family. Pure BIFs live in `arinsal-bifs`.
//!
//! Each family is one file with a function of type [`NativeFamily`] that
//! returns `None` for calls it does not implement. Adding a family means adding
//! its module below and one line to [`FAMILIES`].

pub(crate) mod beam_debug;
pub(crate) mod bif;
pub(crate) mod bif_phash2;
pub(crate) mod binary;
pub(crate) mod erl_arith;
pub(crate) mod erl_bif_atomics;
pub(crate) mod erl_bif_binary;
pub(crate) mod erl_bif_chksum;
pub(crate) mod erl_bif_coverage;
pub(crate) mod erl_bif_guard;
pub(crate) mod erl_bif_info;
pub(crate) mod erl_bif_lists;
pub(crate) mod erl_bif_op;
pub(crate) mod erl_bif_os;
pub(crate) mod erl_bif_port;
pub(crate) mod erl_bif_re;
pub(crate) mod erl_bif_trace;
pub(crate) mod erl_bif_unique;
pub(crate) mod erl_db;
pub(crate) mod erl_debugger;
pub(crate) mod erl_hl_timer;
pub(crate) mod erl_iolist;
pub(crate) mod erl_iolist_generic;
pub(crate) mod erl_map;
pub(crate) mod erl_time_sup;
// Port of erts/emulator/beam/erl_math.c, OTP-29.1.1.
pub(crate) mod erl_math;
pub(crate) mod erl_process;
pub(crate) mod erl_process_dict;
pub(crate) mod erl_ptab;
pub(crate) mod erl_record;
pub(crate) mod erl_unicode;
pub(crate) mod erl_unicode_atom;
mod erl_unicode_normalize;
pub(crate) mod erts_debug;
pub(crate) mod external;
pub(crate) mod external_dec;
pub(crate) mod external_dec_size;
pub(crate) mod external_dec_term;
pub(crate) mod external_dist;
pub(crate) mod misc;
pub(crate) mod register;
pub(crate) mod sys;

/// `table` contains `module:function/arity`.
pub(crate) fn listed(table: &[(&str, &str, u8)], module: &str, function: &str, arity: u8) -> bool {
    table
        .iter()
        .any(|&(item_module, item_function, item_arity)| {
            item_module == module && item_function == function && item_arity == arity
        })
}

use crate::{Process, Vm, VmError};
use arinsal_sched::RunCtx;
use arinsal_term::Term;

pub(crate) mod code;
pub(crate) use crate::dist;
pub(crate) mod ets;
pub(crate) mod maps;
pub(crate) mod nif;
mod nif_load_atoms;
pub(crate) mod tty;

pub(crate) fn static_nif_lookup(
    module: &str,
    function: &str,
    arity: u8,
) -> Option<arinsal_bifs::BifFn> {
    nif::lookup(module, function, arity)
}

/// The static NIF a call of `module:function/arity` from another function reaches directly.
///
/// Port of erts/emulator/beam/erl_nif.c:3437-3477 (static_schedule_dirty_nif and
/// static_schedule_dirty_io_nif), OTP-29.1.1: the dirty flag of a NIF decides the scheduler of
/// every call to it, so a NIF flagged dirty is reached through its function's native body,
/// which moves the process to a dirty scheduler first, and never as a plain BIF.
pub(crate) fn plain_static_nif_lookup(
    module: &str,
    function: &str,
    arity: u8,
) -> Option<arinsal_bifs::BifFn> {
    if crate::native_helpers::static_nif_dirty_class(module, function, arity).is_some() {
        return None;
    }
    static_nif_lookup(module, function, arity)
}
pub(crate) mod node;
pub(crate) mod proc;
pub(crate) mod raw;

/// Arguments passed to a process-aware native. Register windows stay in the scheduler's
/// register array `reg` and are copied only when a legacy family needs a slice.
#[derive(Clone, Copy)]
pub(crate) enum NativeArgs<'a> {
    /// `reg[..arity]`: the address of the register array (`esdp->registers`) and the arity.
    Registers(usize, usize),
    Slice(&'a [Term]),
}

impl NativeArgs<'_> {
    /// The first `arity` registers of the scheduler's register array `reg`.
    pub(crate) fn registers(reg: &mut [Term], arity: usize) -> Self {
        Self::Registers(reg.as_mut_ptr() as usize, arity)
    }

    #[inline]
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Registers(_, arity) => arity,
            Self::Slice(args) => args.len(),
        }
    }

    /// The registers, read when the native asks for them (a collection may have moved them).
    fn register_window<'r>(reg: usize, arity: usize) -> &'r [Term] {
        crate::native_hooks::registers_at(arinsal_beamasm::SchedulerRegisters::from_reg(
            reg as *mut u64,
        ))
        .map_or(&[], |registers| &registers.x_reg_array[..arity])
    }

    pub(crate) fn with_values<R>(
        self,
        process: &mut Process,
        f: impl FnOnce(&mut Process, &[Term]) -> R,
    ) -> R {
        match self {
            Self::Slice(args) => f(process, args),
            Self::Registers(_, 0) => f(process, &[]),
            Self::Registers(reg, arity) if arity <= 8 => {
                let mut values = [Term::NIL; 8];
                values[..arity].copy_from_slice(Self::register_window(reg, arity));
                f(process, &values[..arity])
            }
            Self::Registers(reg, arity) => {
                let values = Self::register_window(reg, arity).to_vec();
                f(process, &values)
            }
        }
    }
}

/// A family of process-aware natives: `None` when `module:function/args.len()`
/// is not one of its functions.
pub(crate) type NativeFamily = fn(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    module: &str,
    function: &str,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>>;

fn port_call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    module: &str,
    function: &str,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    // Port of erts/emulator/beam/erl_port_task.c:1731 (port execution state), OTP-29.1.1.
    ctx.set_msacc_state(arinsal_sched::MsaccState::Port);
    let result = args.with_values(process, |process, values| {
        crate::port::family(vm, process, ctx, module, function, values)
    });
    ctx.set_msacc_state(arinsal_sched::MsaccState::Emulator);
    result
}

/// Every process-aware native the VM families and `signals` dispatch, deduplicated.
pub fn implemented_natives() -> &'static [(&'static str, &'static str, u8)] {
    use std::sync::OnceLock;
    static ALL: OnceLock<Vec<(&'static str, &'static str, u8)>> = OnceLock::new();
    ALL.get_or_init(|| {
        let mut entries = Vec::new();
        for table in [
            code::IMPLEMENTED,
            erl_debugger::IMPLEMENTED,
            erts_debug::IMPLEMENTED,
            dist::IMPLEMENTED,
            nif::IMPLEMENTED,
            node::IMPLEMENTED,
            sys::IMPLEMENTED,
            misc::IMPLEMENTED,
            proc::IMPLEMENTED,
            tty::IMPLEMENTED,
            crate::signals::IMPLEMENTED,
            // `port::family` lives outside this module. Only `port_command/3`
            // stays here (`ERTS_BIF_YIELD3` on a busy port).
            PORT_IMPLEMENTED,
        ] {
            for entry in table {
                if !entries.contains(entry) {
                    entries.push(*entry);
                }
            }
        }
        entries.sort_unstable();
        entries
    })
    .as_slice()
}

#[cfg_attr(not(test), allow(dead_code))]
fn family_dispatches(module: &str, function: &str, arity: u8) -> bool {
    listed(erl_debugger::IMPLEMENTED, module, function, arity)
        || listed(erts_debug::IMPLEMENTED, module, function, arity)
        || code::recognizes(module, function, arity)
        || dist::recognizes(module, function, arity)
        || listed(misc::IMPLEMENTED, module, function, arity)
        || nif::recognizes(module, function, arity)
        || node::recognizes(module, function, arity)
        || sys::recognizes(module, function, arity)
        || proc::recognizes(module, function, arity)
        || tty::recognizes(module, function, arity)
        || crate::signals::recognizes(module, function, arity)
        || port_recognizes(module, function, arity)
}

/// The family's handler table (or lookup) accepts this MFA. Name-gated families
/// admit the function name from the same `IMPLEMENTED` slice `call` reads.
#[cfg_attr(not(test), allow(dead_code))]
fn handler_agrees(module: &str, function: &str, arity: u8) -> bool {
    if listed(erl_debugger::IMPLEMENTED, module, function, arity) {
        return true;
    }
    if node::recognizes(module, function, arity) {
        return node::handler(module, function, arity).is_some();
    }
    if nif::recognizes(module, function, arity) {
        return nif::handler(module, function, arity).is_some();
    }
    if sys::recognizes(module, function, arity) {
        return sys::handler(module, function, arity).is_some()
            || arinsal_pterm::lookup(module, function, arity).is_some();
    }
    if tty::recognizes(module, function, arity) {
        return arinsal_nif_tty::lookup(module, function, arity).is_some();
    }
    if code::recognizes(module, function, arity)
        || listed(erts_debug::IMPLEMENTED, module, function, arity)
        || dist::recognizes(module, function, arity)
        || proc::recognizes(module, function, arity)
        || crate::signals::recognizes(module, function, arity)
        || port_recognizes(module, function, arity)
        || listed(misc::IMPLEMENTED, module, function, arity)
    {
        return true;
    }
    false
}

/// `port::family` arms that stay on the executor (`ERTS_BIF_YIELD3` on a busy port).
const PORT_IMPLEMENTED: &[(&str, &str, u8)] = &[("erts_internal", "port_command", 3)];

#[cfg_attr(not(test), allow(dead_code))]
fn port_recognizes(module: &str, function: &str, arity: u8) -> bool {
    listed(PORT_IMPLEMENTED, module, function, arity)
}

/// Process-aware native with the MFA already chosen.
pub(crate) type DirectNative = fn(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    args: &[Term],
) -> Result<Term, VmError>;

/// A BIF that can run with only its process, like an erts BIF called with `c_p` and its
/// arguments. `None` asks the caller to retry with scheduler context; a failure is the Erlang
/// exception it raises (`BIF_ERROR`), and the call site gives it the BIF frame.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared), OTP-29.1.1.
pub(crate) type ProcessBif =
    fn(&mut Process, &[Term]) -> Option<Result<Term, crate::exceptions::Trap>>;

/// The process BIF native code calls for `module:function/arity`, if it has one.
pub(crate) fn process_bif(module: &str, function: &str, arity: u8) -> Option<ProcessBif> {
    // Port of bif.tab `hbif erts_internal:garbage_collect/1`: a plain BIF called
    // through the export entry (`call_light_bif`), not an executor native.
    if module == "erts_internal" && function == "garbage_collect" && arity == 1 {
        return Some(sys::garbage_collect_bif);
    }
    // Port of bif.tab `bif erlang:dt_spread_tag/1` and `dt_restore_tag/1`: plain BIFs.
    if module == "erlang" && function == "dt_spread_tag" && arity == 1 {
        return Some(sys::dt_spread_tag_light);
    }
    if module == "erlang" && function == "dt_restore_tag" && arity == 1 {
        return Some(sys::dt_restore_tag_light);
    }
    if module == "erlang" && matches!(function, "dt_get_tag" | "dt_get_tag_data") && arity == 0 {
        return Some(sys::dt_get_tag_light);
    }
    if module == "erlang" && function == "dt_put_tag" && arity == 1 {
        return Some(sys::dt_put_tag_light);
    }
    if module == "erlang"
        && matches!(function, "dt_prepend_vm_tag_data" | "dt_append_vm_tag_data")
        && arity == 1
    {
        return Some(sys::dt_vm_tag_data_light);
    }
    if module == "erlang" && function == "nodes" && arity == 0 {
        return Some(node::nodes0_bif);
    }
    if module == "erlang" && function == "list_to_pid" && arity == 1 {
        return Some(proc::list_to_pid_light);
    }
    if module == "erts_internal" && function == "suspend_process" && arity == 2 {
        return Some(proc::suspend_process_light);
    }
    if module == "erlang" {
        match (function, arity) {
            ("module_loaded", 1) => return Some(code::module_loaded_light),
            ("function_exported", 3) => return Some(code::function_exported_light),
            _ => {}
        }
    }
    None
}

/// Per-import process-aware entry with its MFA already resolved.
pub(crate) type ResolvedNative = fn(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::Process>,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>>;

/// One resolved process-aware entry. Family variants still match the name
/// inside that single family; the scan across families happens once, at load.
#[derive(Clone, Copy)]
pub(crate) enum NativeEntry {
    /// Handler that does not look at the MFA again.
    Direct(DirectNative),
    /// Family-specific entry resolved once for this import at load time.
    DirectFamily(NativeFamily),
    /// Entry selected for one import at load time; no MFA is passed at runtime.
    Resolved(ResolvedNative),
}

/// Pack a resolved entry. The two low bits distinguish direct and family entries.
pub(crate) fn pack_native(entry: NativeEntry) -> usize {
    match entry {
        NativeEntry::Direct(fun) => {
            let bits = fun as usize;
            debug_assert_eq!(bits & 3, 0);
            bits | 1
        }
        NativeEntry::DirectFamily(fun) => {
            let bits = fun as usize;
            debug_assert_eq!(bits & 3, 0);
            bits
        }
        NativeEntry::Resolved(fun) => {
            let bits = fun as usize;
            debug_assert_eq!(bits & 3, 0);
            bits | 2
        }
    }
}

/// Inverse of [`pack_native`].
pub(crate) fn unpack_native(bits: usize) -> Option<NativeEntry> {
    if bits == 0 {
        return None;
    }
    // SAFETY: every nonzero value is produced by `pack_native`; its low bits
    // select the exact function-pointer type and the remaining bits hold it.
    unsafe {
        match bits & 3 {
            1 => Some(NativeEntry::Direct(std::mem::transmute::<
                usize,
                DirectNative,
            >(bits & !3))),
            2 => Some(NativeEntry::Resolved(std::mem::transmute::<
                usize,
                ResolvedNative,
            >(bits & !3))),
            _ => Some(NativeEntry::DirectFamily(std::mem::transmute::<
                usize,
                NativeFamily,
            >(bits))),
        }
    }
}

/// `(ImportClass, packed NativeEntry)` of every bif.tab entry, indexed by `bif_number`.
///
/// Port of erts/emulator/beam/erl_bif_table.c (`bif_table`, one entry per bif.tab line, found by
/// `Export.bif_number`), OTP-29.1.1. A call that names a BIF reads its entry here; the per-family
/// name tables only build it once.
fn native_table() -> &'static [(arinsal_loader::ImportClass, usize)] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<(arinsal_loader::ImportClass, usize)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = vec![(arinsal_loader::ImportClass::Remote, 0); crate::bif_table::BIF_SIZE];
        for line in include_str!("../../../../spec/otp-29.1.1/bif.tab").lines() {
            let Some((module, function, arity)) = crate::load::parse_bif_mfa(line) else {
                continue;
            };
            if let Some(spec) = arinsal_spec::bif_lookup(&module, &function, arity) {
                let has_bif = arinsal_bifs::lookup(&module, &function, arity).is_some();
                table[usize::from(spec.index)] =
                    classify_by_name(&module, &function, arity, has_bif);
            }
        }
        table
    })
}

/// The native entry of `module:function/arity`: the BIF table's when it is a BIF, else the
/// classification of a NIF or Erlang function the runtime implements.
pub(crate) fn native_entry(
    module: &str,
    function: &str,
    arity: u8,
) -> (arinsal_loader::ImportClass, usize) {
    match arinsal_spec::bif_lookup(module, function, arity) {
        Some(spec) if usize::from(spec.index) < crate::bif_table::BIF_SIZE => {
            native_table()[usize::from(spec.index)]
        }
        _ => classify_by_name(
            module,
            function,
            arity,
            arinsal_bifs::lookup(module, function, arity).is_some(),
        ),
    }
}

/// Classify an import once, at load.
pub(crate) fn classify(
    module: &str,
    function: &str,
    arity: u8,
    has_bif: bool,
) -> (arinsal_loader::ImportClass, usize) {
    if let Some(spec) = arinsal_spec::bif_lookup(module, function, arity)
        && usize::from(spec.index) < crate::bif_table::BIF_SIZE
    {
        return native_table()[usize::from(spec.index)];
    }
    classify_by_name(module, function, arity, has_bif)
}

/// Classify an import by name: the generator of [`native_table`], and the lookup of a native
/// that is not in bif.tab.
fn classify_by_name(
    module: &str,
    function: &str,
    arity: u8,
    has_bif: bool,
) -> (arinsal_loader::ImportClass, usize) {
    use arinsal_loader::ImportClass;
    // Port of erts/emulator/beam/erl_bif_table.c (`bif_table[].f`): a bif.tab body is the
    // table entry. Hidden `erts_init_trap_export` BIFs are `trampoline.bif.address`, not a
    // family name table. Family tables are only for MFAs erts puts in neither.
    if crate::bif_table::special(module, function, arity).is_some()
        || crate::bif_table::trap_function(module, function, arity).is_some()
    {
        return (ImportClass::Native, 0);
    }
    if let Some(entry) = resolve(module, function, arity) {
        return (ImportClass::Native, pack_native(entry));
    }
    if is_dynamic(module, function, arity) {
        return (ImportClass::Dynamic, 0);
    }
    if has_bif {
        return (ImportClass::Pure, 0);
    }
    if arinsal_spec::bif_lookup(module, function, arity).is_some() {
        return (ImportClass::Unsupported, 0);
    }
    (ImportClass::Remote, 0)
}

/// Natives whose result depends on VM state, or miss-path side effects that
/// must still run (`prim_tty` owner, conditional `erl_tracer`).
fn is_dynamic(module: &str, function: &str, arity: u8) -> bool {
    module == "erl_tracer"
        || (module == "erlang"
            && function == "nif_error"
            && !nif::recognizes(module, function, arity))
}

fn proc_claims(module: &str, function: &str, arity: u8) -> bool {
    if module != "erlang" && module != "erts_internal" {
        return false;
    }
    if matches!(
        function,
        "spawn_request" | "dist_spawn_request" | "processes_next" | "trace"
    ) && module != "erts_internal"
    {
        return false;
    }
    listed(proc::IMPLEMENTED, module, function, arity)
}

fn sys_extra(module: &str, function: &str, arity: u8) -> bool {
    matches!(
        (module, function, arity),
        ("erlang", "dt_get_tag" | "dt_get_tag_data", 0)
            | ("erlang", "dt_put_tag", 1)
            | (
                "erlang",
                "dt_prepend_vm_tag_data" | "dt_append_vm_tag_data",
                1
            )
    )
}

/// The family or handler `call_import` would have selected, with signals first.
fn resolve(module: &str, function: &str, arity: u8) -> Option<NativeEntry> {
    if listed(erl_debugger::IMPLEMENTED, module, function, arity) {
        return Some(NativeEntry::DirectFamily(erl_debugger::call));
    }
    if listed(erts_debug::IMPLEMENTED, module, function, arity) {
        return Some(NativeEntry::DirectFamily(erts_debug::call));
    }
    if listed(misc::IMPLEMENTED, module, function, arity) {
        return Some(NativeEntry::DirectFamily(misc::call));
    }
    if module == "erlang" {
        match (function, arity) {
            ("monitor", 2 | 3) => return Some(NativeEntry::Direct(bif::monitor_executor)),
            ("demonitor", 1 | 2) => return Some(NativeEntry::Direct(bif::demonitor_executor)),
            _ => {}
        }
    }
    if dist::recognizes(module, function, arity) {
        return Some(NativeEntry::DirectFamily(dist::call));
    }
    if let Some(handle) = crate::signals::handler(module, function, arity) {
        return Some(NativeEntry::Resolved(handle));
    }
    if code::recognizes(module, function, arity) {
        return Some(NativeEntry::DirectFamily(code::call));
    }
    if nif::recognizes(module, function, arity) {
        return Some(NativeEntry::DirectFamily(nif::call));
    }
    if let Some(handle) = node::handler(module, function, arity) {
        return Some(NativeEntry::Direct(handle));
    }
    if port_recognizes(module, function, arity) {
        return Some(NativeEntry::DirectFamily(port_call));
    }
    if arinsal_pterm::lookup(module, function, arity).is_some() {
        return Some(NativeEntry::DirectFamily(sys::call));
    }
    if let Some(handle) = sys::handler(module, function, arity) {
        return Some(NativeEntry::Direct(handle));
    }
    if proc_claims(module, function, arity) {
        return Some(NativeEntry::DirectFamily(proc::call));
    }
    if tty::recognizes(module, function, arity) {
        return Some(NativeEntry::DirectFamily(tty::call));
    }
    if sys_extra(module, function, arity) {
        return Some(NativeEntry::DirectFamily(sys::call));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erlang_port_wrappers_use_the_preloaded_module_code() {
        for (function, arity) in [
            ("open_port", 2),
            ("port_close", 1),
            ("port_command", 2),
            ("port_command", 3),
            ("port_connect", 2),
            ("port_info", 1),
            ("port_info", 2),
        ] {
            assert!(
                !implemented_natives().contains(&("erlang", function, arity)),
                "erlang:{function}/{arity} must run its preloaded wrapper"
            );
        }
        assert!(
            !implemented_natives().contains(&("erts_internal", "port_command", 2)),
            "OTP 29.1.1 does not export or implement erts_internal:port_command/2"
        );
        assert!(implemented_natives().contains(&("erts_internal", "port_command", 3)));
        for (function, arity) in [
            ("open_port", 2),
            ("port_close", 1),
            ("port_connect", 2),
            ("port_control", 3),
            ("port_call", 3),
            ("port_info", 1),
            ("port_info", 2),
        ] {
            assert!(
                !implemented_natives().contains(&("erts_internal", function, arity)),
                "erts_internal:{function}/{arity} is bif_table, not the executor family"
            );
        }
        assert!(!implemented_natives().contains(&("erlang", "port_get_data", 1)));
        assert!(!implemented_natives().contains(&("erlang", "port_set_data", 2)));
    }

    #[test]
    fn decode_packet_is_called_from_native_code_like_a_plain_bif() {
        assert!(crate::bif_table::special("erlang", "decode_packet", 3).is_some());
        assert!(process_bif("erlang", "decode_packet", 3).is_none());
        assert!(process_bif("erlang", "decode_packet", 2).is_none());
    }

    #[test]
    fn listed_natives_are_dispatched_by_their_family() {
        for &(module, function, arity) in implemented_natives() {
            assert!(
                family_dispatches(module, function, arity),
                "{module}:{function}/{arity} is listed but no family recognizes it"
            );
            assert!(
                handler_agrees(module, function, arity),
                "{module}:{function}/{arity} is listed but its family does not dispatch it"
            );
        }
    }

    #[test]
    fn signal_imports_resolve_to_distinct_entries() {
        let direct = [
            ("erlang", "monitor", 2),
            ("erlang", "monitor", 3),
            ("erlang", "demonitor", 1),
            ("erlang", "demonitor", 2),
        ];
        let entries = crate::signals::IMPLEMENTED
            .iter()
            .filter(|entry| !direct.contains(entry))
            .map(|&(module, function, arity)| {
                crate::signals::handler(module, function, arity)
                    .expect("listed signal BIF has a resolved entry") as usize
            })
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            entries.len(),
            crate::signals::IMPLEMENTED.len() - direct.len()
        );

        for (module, function, arity) in crate::signals::IMPLEMENTED {
            let (class, bits) = classify(module, function, *arity, true);
            assert_eq!(class, arinsal_loader::ImportClass::Native);
            if crate::bif_table::has_function(module, function, *arity) {
                assert_eq!(
                    bits, 0,
                    "{module}:{function}/{arity} is bif_table, not a family entry"
                );
            } else {
                assert_ne!(bits, 0, "{module}:{function}/{arity} has a resolved entry");
            }
        }
    }

    #[test]
    fn classify_uses_bif_table_before_family() {
        for &(module, function, arity) in &[
            ("erts_debug", "copy_shared", 2),
            ("erlang", "process_info", 2),
            ("erlang", "monitor", 2),
            ("erlang", "bif_return_trap", 2),
        ] {
            let (class, bits) = classify(module, function, arity, true);
            assert_eq!(class, arinsal_loader::ImportClass::Native);
            assert_eq!(
                bits, 0,
                "{module}:{function}/{arity} must use bif_table or trap_function, not a packed family entry"
            );
        }
    }
}

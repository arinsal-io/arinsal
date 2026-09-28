//! Process-aware native functions (BIFs and NIF bindings that need the VM or
//! the calling process), grouped by family. Pure BIFs live in `arinsal-bifs`.
//!
//! Each family is one file with a function of type [`NativeFamily`] that
//! returns `None` for calls it does not implement. Adding a family means adding
//! its module below and one line to [`FAMILIES`].

pub(crate) mod env;
pub(crate) mod erl_debugger;
pub(crate) mod erts_debug;
pub(crate) mod misc;
pub(crate) mod sys;

/// `table` contains `module:function/arity`.
pub(crate) fn listed(table: &[(&str, &str, u8)], module: &str, function: &str, arity: u8) -> bool {
    table
        .iter()
        .any(|&(item_module, item_function, item_arity)| {
            item_module == module && item_function == function && item_arity == arity
        })
}

/// `table` contains `function` at any arity. Name-gated families use this so an
/// unknown arity still returns the same error as before the list existed.
pub(crate) fn listed_name(table: &[(&str, &str, u8)], function: &str) -> bool {
    table
        .iter()
        .any(|&(_, item_function, _)| item_function == function)
}

use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_sched::RunCtx;
use arinsal_term::Term;

mod code;
pub(crate) use crate::dist;
mod ets;
mod maps;
pub(crate) mod nif;
mod re;
mod records;
pub(crate) mod tty;

pub(crate) fn static_nif_lookup(
    module: &str,
    function: &str,
    arity: u8,
) -> Option<arinsal_bifs::BifFn> {
    nif::lookup(module, function, arity).or_else(|| arinsal_re::lookup(module, function, arity))
}
mod node;
pub(crate) mod proc;

/// Arguments passed to a process-aware native. Register windows stay in X
/// registers and are copied only when a legacy family needs a slice.
#[derive(Clone, Copy)]
pub(crate) enum NativeArgs<'a> {
    Registers(usize),
    Slice(&'a [Term]),
}

impl NativeArgs<'_> {
    #[inline]
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Registers(arity) => arity,
            Self::Slice(args) => args.len(),
        }
    }

    #[inline]
    pub(crate) fn get(self, process: &Process, index: usize) -> Option<Term> {
        match self {
            Self::Registers(arity) if index < arity => process.x.get(index).copied(),
            Self::Registers(_) => None,
            Self::Slice(args) => args.get(index).copied(),
        }
    }

    pub(crate) fn with_values<R>(
        self,
        process: &mut Process,
        f: impl FnOnce(&mut Process, &[Term]) -> R,
    ) -> R {
        match self {
            Self::Slice(args) => f(process, args),
            Self::Registers(0) => f(process, &[]),
            Self::Registers(1) => {
                let values = [process.x[0]];
                f(process, &values)
            }
            Self::Registers(2) => {
                let values = [process.x[0], process.x[1]];
                f(process, &values)
            }
            Self::Registers(3) => {
                let values = [process.x[0], process.x[1], process.x[2]];
                f(process, &values)
            }
            Self::Registers(arity) => {
                let mut values = Vec::with_capacity(arity);
                values.extend_from_slice(&process.x[..arity]);
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
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>>;

/// Registered families, tried in order.
pub(crate) const FAMILIES: &[NativeFamily] = &[
    // One family per line keeps parallel additions conflict-free.
    code::call,
    erl_debugger::call,
    erts_debug::call,
    dist::call,
    misc::call,
    // The ETS family also owns erlang:match_spec_test/3 and erts_internal ETS BIFs.
    ets::call,
    crate::seq_trace::call,
    nif::call,
    re::call,
    node_call,
    port_call,
    sys::call,
    env_call,
    proc::call,
    tty::call,
    maps_call,
    records::call,
];

fn node_call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    args.with_values(process, |process, values| {
        node::call(vm, process, ctx, module, function, values)
    })
}

pub(crate) fn dynamic_atom_to_list(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    tty::call(vm, process, ctx, "erlang", "atom_to_list", args)
}

pub(crate) fn dynamic_list_to_atom(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    tty::call(vm, process, ctx, "erlang", "list_to_atom", args)
}

pub(crate) fn dynamic_append(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    tty::call(vm, process, ctx, "erlang", "++", args)
}

fn env_call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    args.with_values(process, |process, values| {
        env::call(vm, process, ctx, module, function, values)
    })
}

fn maps_call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    args.with_values(process, |process, values| {
        maps::call(vm, process, ctx, module, function, values)
    })
}

fn port_call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
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
            ets::IMPLEMENTED,
            nif::IMPLEMENTED,
            re::IMPLEMENTED,
            node::IMPLEMENTED,
            sys::IMPLEMENTED,
            misc::IMPLEMENTED,
            crate::seq_trace::IMPLEMENTED,
            env::IMPLEMENTED,
            proc::IMPLEMENTED,
            tty::IMPLEMENTED,
            maps::IMPLEMENTED,
            records::IMPLEMENTED,
            crate::signals::IMPLEMENTED,
            // `port::family` lives outside this module. These are the arms that
            // run the operation; `port_control/3` always returns `badarg`.
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
        || ets::recognizes(module, function, arity)
        || nif::recognizes(module, function, arity)
        || re::recognizes(module, function, arity)
        || node::recognizes(module, function, arity)
        || sys::recognizes(module, function, arity)
        || crate::seq_trace::recognizes(module, function, arity)
        || env::recognizes(module, function, arity)
        || proc::recognizes(module, function, arity)
        || tty::recognizes(module, function, arity)
        || maps::recognizes(module, function, arity)
        || listed(records::IMPLEMENTED, module, function, arity)
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
    if env::recognizes(module, function, arity) {
        return env::handler(module, function, arity).is_some();
    }
    if node::recognizes(module, function, arity) {
        return node::handler(module, function, arity).is_some();
    }
    if maps::recognizes(module, function, arity) {
        return maps::handler(module, function, arity).is_some();
    }
    if nif::recognizes(module, function, arity) {
        return nif::handler(module, function, arity).is_some();
    }
    if sys::recognizes(module, function, arity) {
        return sys::handler(module, function, arity).is_some()
            || arinsal_pterm::lookup(module, function, arity).is_some();
    }
    if crate::seq_trace::recognizes(module, function, arity) {
        return true;
    }
    if re::recognizes(module, function, arity) {
        return arinsal_re::lookup(module, function, arity).is_some();
    }
    if tty::recognizes(module, function, arity) {
        return arinsal_nif_tty::lookup(module, function, arity).is_some();
    }
    if code::recognizes(module, function, arity)
        || listed(erts_debug::IMPLEMENTED, module, function, arity)
        || dist::recognizes(module, function, arity)
        || ets::recognizes(module, function, arity)
        || proc::recognizes(module, function, arity)
        || listed(records::IMPLEMENTED, module, function, arity)
        || crate::signals::recognizes(module, function, arity)
        || port_recognizes(module, function, arity)
        || listed(misc::IMPLEMENTED, module, function, arity)
    {
        return true;
    }
    false
}

/// `port::family` arms that perform the operation (`crates/vm/src/port.rs`).
const PORT_IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erts_internal", "open_port", 2),
    ("erts_internal", "port_command", 3),
    ("erts_internal", "port_close", 1),
    ("erts_internal", "port_connect", 2),
    ("erlang", "ports", 0),
    ("erts_internal", "port_info", 1),
    ("erts_internal", "port_info", 2),
    ("erts_internal", "port_control", 3),
    ("erts_internal", "port_call", 3),
    ("erlang", "port_get_data", 1),
    ("erlang", "port_set_data", 2),
];

#[cfg_attr(not(test), allow(dead_code))]
fn port_recognizes(module: &str, function: &str, arity: u8) -> bool {
    listed(PORT_IMPLEMENTED, module, function, arity)
}

/// Process-aware native with the MFA already chosen.
pub(crate) type DirectNative = fn(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError>;

/// Per-import process-aware entry with its MFA already resolved.
pub(crate) type ResolvedNative = fn(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
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

/// Classify an import the way `call_import` used to scan families, once.
pub(crate) fn classify(
    module: &str,
    function: &str,
    arity: u8,
    has_bif: bool,
) -> (arinsal_loader::ImportClass, usize) {
    use arinsal_loader::ImportClass;
    if let Some(entry) = resolve(module, function, arity) {
        return (ImportClass::Native, pack_native(entry));
    }
    if is_fun(module, function, arity) {
        return (ImportClass::Fun, 0);
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

fn is_fun(module: &str, function: &str, arity: u8) -> bool {
    module == "erlang"
        && matches!(
            (function, arity),
            ("apply", 2 | 3) | ("make_fun", 3) | ("fun_info", 1 | 2) | ("fun_info_mfa", 1)
        )
}

/// Natives whose result depends on VM state, or miss-path side effects that
/// must still run (`prim_tty` owner, conditional `erl_tracer`).
fn is_dynamic(module: &str, function: &str, arity: u8) -> bool {
    module == "erl_tracer"
        || (module == "erlang"
            && function == "nif_error"
            && !nif::recognizes(module, function, arity))
        || (module == "erlang" && matches!(function, "++" | "atom_to_list" | "list_to_atom"))
}

fn proc_claims(module: &str, function: &str) -> bool {
    if module != "erlang" && module != "erts_internal" {
        return false;
    }
    if matches!(function, "spawn_request" | "dist_spawn_request") && module != "erts_internal" {
        return false;
    }
    if function == "processes_next" && module != "erts_internal" {
        return false;
    }
    if function == "fun_info_mfa" && module != "erlang" {
        return false;
    }
    listed_name(proc::IMPLEMENTED, function)
}

fn sys_extra(module: &str, function: &str, arity: u8) -> bool {
    matches!(
        (module, function, arity),
        ("erlang", "system_info", 1)
            | ("erlang", "dt_get_tag" | "dt_get_tag_data", 0)
            | ("erlang", "dt_put_tag", 1)
            | (
                "erlang",
                "dt_prepend_vm_tag_data" | "dt_append_vm_tag_data",
                1
            )
            | ("net_kernel", "dflag_unicode_io", 1)
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
    if module == "erlang" {
        match (function, arity) {
            ("atom_to_list", 1) => return Some(NativeEntry::Resolved(dynamic_atom_to_list)),
            ("list_to_atom", 1) => return Some(NativeEntry::Resolved(dynamic_list_to_atom)),
            ("++", 2) => return Some(NativeEntry::Resolved(dynamic_append)),
            _ => {}
        }
    }
    if listed(records::IMPLEMENTED, module, function, arity) {
        return Some(NativeEntry::DirectFamily(records::call));
    }
    if listed(misc::IMPLEMENTED, module, function, arity) {
        return Some(NativeEntry::DirectFamily(misc::call));
    }
    if module == "erlang" {
        match (function, arity) {
            ("self", 0) => return Some(NativeEntry::Direct(crate::signals::native_self)),
            ("!", 2) => return Some(NativeEntry::Direct(crate::dist::native_send)),
            ("send", 2) => return Some(NativeEntry::Direct(crate::dist::native_send)),
            ("send", 3) => return Some(NativeEntry::Direct(crate::dist::native_send3)),
            ("link", 1) => return Some(NativeEntry::Direct(crate::dist::native_link)),
            ("unlink", 1) => return Some(NativeEntry::Direct(crate::dist::native_unlink)),
            ("exit", 2) => return Some(NativeEntry::Direct(crate::dist::native_exit2)),
            ("monitor", 2 | 3) => return Some(NativeEntry::Direct(crate::dist::native_monitor)),
            ("demonitor", 1 | 2) => {
                return Some(NativeEntry::Direct(crate::dist::native_demonitor));
            }
            ("is_process_alive", 1) => {
                return Some(NativeEntry::Direct(crate::signals::native_is_process_alive));
            }
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
    if let Some(handle) = ets::handler(module, function, arity) {
        return Some(NativeEntry::Resolved(handle));
    }
    if crate::seq_trace::recognizes(module, function, arity) {
        return Some(NativeEntry::DirectFamily(crate::seq_trace::call));
    }
    if nif::recognizes(module, function, arity) {
        return Some(NativeEntry::DirectFamily(nif::call));
    }
    if re::recognizes(module, function, arity) {
        return Some(NativeEntry::DirectFamily(re::call));
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
    if let Some(handle) = env::handler(module, function, arity) {
        return Some(NativeEntry::Direct(handle));
    }
    if proc_claims(module, function) {
        return Some(NativeEntry::DirectFamily(proc::call));
    }
    if tty::recognizes(module, function, arity) {
        return Some(NativeEntry::DirectFamily(tty::call));
    }
    if let Some(handle) = maps::handler(module, function, arity) {
        return Some(NativeEntry::Direct(handle));
    }
    if sys_extra(module, function, arity) {
        return Some(NativeEntry::DirectFamily(sys::call));
    }
    None
}

/// Record the NIF scheduler hub when it still names another process.
///
pub(crate) fn refresh_hub(process: &Process, ctx: &RunCtx<'_, Message>) {
    nif::refresh_hub(process, ctx);
}

/// Dispatch a call to the first family that implements it.
pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    FAMILIES
        .iter()
        .find_map(|family| family(vm, process, ctx, module, function, args))
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
        for (function, arity) in [
            ("open_port", 2),
            ("port_close", 1),
            ("port_command", 3),
            ("port_connect", 2),
            ("port_info", 1),
            ("port_info", 2),
        ] {
            assert!(implemented_natives().contains(&("erts_internal", function, arity)));
        }
    }

    #[test]
    fn pure_bif_imports_skip_family_dispatch() {
        use arinsal_loader::ImportClass;
        let (class, bits) = classify("lists", "reverse", 2, true);
        assert_eq!(class, ImportClass::Pure);
        assert_eq!(bits, 0);
        let (class, bits) = classify("erlang", "self", 0, true);
        assert_eq!(class, ImportClass::Native);
        assert_ne!(bits, 0);
        assert!(matches!(unpack_native(bits), Some(NativeEntry::Direct(_))));
        for (function, arity) in [("!", 2), ("send", 2), ("send", 3), ("is_process_alive", 1)] {
            let (class, bits) = classify("erlang", function, arity, true);
            assert_eq!(class, ImportClass::Native);
            assert!(matches!(unpack_native(bits), Some(NativeEntry::Direct(_))));
        }
        for (function, arity) in [("++", 2), ("atom_to_list", 1), ("list_to_atom", 1)] {
            let (class, bits) = classify("erlang", function, arity, true);
            assert_eq!(class, ImportClass::Native);
            assert!(matches!(
                unpack_native(bits),
                Some(NativeEntry::Resolved(_))
            ));
        }
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
    fn ets_imports_resolve_to_distinct_entries() {
        let entries = ets::IMPLEMENTED
            .iter()
            .map(|&(module, function, arity)| {
                ets::handler(module, function, arity).expect("listed ETS BIF has an entry") as usize
            })
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(entries.len(), ets::IMPLEMENTED.len());
    }

    #[test]
    fn signal_imports_resolve_to_distinct_entries() {
        let direct = [
            ("erlang", "self", 0),
            ("erlang", "!", 2),
            ("erlang", "send", 2),
            ("erlang", "send", 3),
            ("erlang", "is_process_alive", 1),
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
            assert_ne!(bits, 0, "{module}:{function}/{arity} has a resolved entry");
        }
    }
}

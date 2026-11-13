//! Fun dispatch glue: the node export lookup behind `erts_export_get_or_make_stub` for terms
//! built outside a process, and the runtime half of the `dispatch_save_calls_fun` fragment.
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{Atom, ExportEntry, FunEntry};
use std::sync::Arc;

/// Export fun lookup for the term crate.
// Port of erts/emulator/beam/export.c:200-245 (erts_export_get_or_make_stub), OTP-29.1.1.
fn export_stub_hook(module: Atom, function: Atom, arity: u8) -> Option<Arc<ExportEntry>> {
    crate::export::export_get_or_make_stub((module, function, arity))
}

/// Local fun lookup for ETF terms decoded by a process on this node.
// Port of erts/emulator/beam/erl_fun.c:299-309 (erts_fun_entry_get_or_make_stub), OTP-29.1.1.
fn fun_entry_stub_hook(candidate: Arc<FunEntry>) -> Option<Arc<FunEntry>> {
    Some(crate::code_ix::global().intern_fun_entry(candidate))
}

/// Publishes the fun dispatch fragments as `beam_unloaded_fun` / `beam_save_calls_fun` and
/// the export lookup, before any fun entry of the node is created.
// Port of erts/emulator/beam/jit/beam_jit_main.cpp (beamasm_init: beam_unloaded_fun and
// beam_save_calls_fun from the global fragments), OTP-29.1.1.
pub(crate) fn init(unloaded_fun: usize, save_calls_fun: usize) {
    arinsal_term::set_fun_dispatch_fragments(unloaded_fun, save_calls_fun);
    arinsal_term::set_export_stub_hook(export_stub_hook);
    arinsal_term::set_fun_entry_stub_hook(fun_entry_stub_hook);
}

/// The address a local fun call of a process saving calls continues with: the fun entry's
/// address in its node's active code index.
// Port of erts/emulator/beam/jit/arm/instr_fun.cpp:139-149 (emit_dispatch_save_calls_fun),
// OTP-29.1.1: erts reads `the_active_code_index`, here each node has its own.
pub(crate) extern "C" fn arinsal_beamasm_save_calls_fun(
    header: *mut ProcessHeader,
    fun_raw: u64,
) -> usize {
    let Some((_process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return arinsal_term::beam_unloaded_fun();
    };
    let active = crate::code_ix::global().active();
    match crate::native_hooks::fun_view(crate::native_hooks::from_raw(fun_raw)) {
        Some(arinsal_term::FunRef::Local { entry, .. }) => entry.dispatch_target.address(active),
        Some(arinsal_term::FunRef::Export { entry }) => entry.address(active),
        None => arinsal_term::beam_unloaded_fun(),
    }
}

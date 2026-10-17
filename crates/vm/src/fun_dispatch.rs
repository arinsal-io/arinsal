//! Fun dispatch glue: the node export lookup behind `erts_export_get_or_make_stub` for terms
//! built outside a process, and the runtime half of the `dispatch_save_calls_fun` fragment.
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{Atom, ExportEntry, FunEntry};
use std::cell::Cell;
use std::sync::Arc;

thread_local! {
    /// Code scope (node) of the runtime this thread works for; zero when it has none.
    static CODE_SCOPE: Cell<u64> = const { Cell::new(0) };
}

/// Records the node this thread runs code for, so export funs built here (literals,
/// `binary_to_term`) point at that node's export entries.
pub(crate) fn set_thread_code_scope(scope: u64) {
    CODE_SCOPE.with(|cell| cell.set(scope));
}

/// The node this thread runs code for, or 0 when none was recorded.
pub(crate) fn code_scope() -> u64 {
    CODE_SCOPE.with(Cell::get)
}

/// Export fun lookup for the term crate.
// Port of erts/emulator/beam/export.c:200-245 (erts_export_get_or_make_stub), OTP-29.1.1.
fn export_stub_hook(module: Atom, function: Atom, arity: u8) -> Option<Arc<ExportEntry>> {
    let scope = CODE_SCOPE.with(Cell::get);
    if scope == 0 {
        return None;
    }
    crate::beamasm_integration::export_get_or_make_stub(scope, (module, function, arity))
}

/// Local fun lookup for ETF terms decoded by a process on this node.
// Port of erts/emulator/beam/erl_fun.c:299-309 (erts_fun_entry_get_or_make_stub), OTP-29.1.1.
fn fun_entry_stub_hook(candidate: Arc<FunEntry>) -> Arc<FunEntry> {
    let scope = CODE_SCOPE.with(Cell::get);
    if scope == 0 {
        candidate
    } else {
        crate::code_ix::for_scope(scope).intern_fun_entry(candidate)
    }
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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return arinsal_term::beam_unloaded_fun();
    };
    let active = process.runtime.as_ref().map_or(0, |runtime| {
        crate::code_ix::for_scope(runtime.code_scope).active()
    });
    match crate::native_hooks::fun_view(crate::native_hooks::from_raw(fun_raw)) {
        Some(arinsal_term::FunRef::Local { entry, .. }) => entry.dispatch_target.address(active),
        Some(arinsal_term::FunRef::Export { entry }) => entry.address(active),
        None => arinsal_term::beam_unloaded_fun(),
    }
}

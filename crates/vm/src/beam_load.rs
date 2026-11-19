// Port of erts/emulator/beam/beam_load.c.

use crate::load::CodeMeta;
use arinsal_loader::Module;

/// Emits the prepared module body after its entries and imports have been resolved.
// Port of erts/emulator/beam/beam_load.c (load_code), OTP-29.1.1.
pub(crate) fn load_code(
    module: &mut Module,
    meta: &mut CodeMeta,
) -> Option<arinsal_beamjit::CompileError> {
    // The BEAM was parsed in prepare_loading. erts does not parse it again here.
    let mut failure = None;
    if let Some(native) = crate::beamasm_integration::compile(
        &meta.beam,
        module,
        meta.md5,
        crate::trace_bp::line_breakpoints_instrumented(),
        crate::code_ix::global(),
        &mut failure,
    ) {
        // Port of erts/emulator/beam/jit/asm_load.c (beamasm_get_on_load), OTP-29.1.1.
        if meta.on_load.is_none() {
            meta.on_load = native.on_load.clone();
        }
        meta.beamasm = Some(native);
    }
    failure
}

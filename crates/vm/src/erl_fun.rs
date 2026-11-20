// Port of erts/emulator/beam/erl_fun.c.

use arinsal_term::{ErtsCodeMfa, FunEntry, Term};

/// Resolve a local closure's function MFA in the active code index.
// Port of erts/emulator/beam/erl_fun.c:37 (`erts_get_fun_mfa`), OTP-29.1.1.
pub(crate) fn erts_get_fun_mfa(entry: &FunEntry) -> Option<ErtsCodeMfa> {
    let code_ix = crate::code_ix::erts_active_code_ix();
    let address = entry.dispatch_target.address(code_ix);
    if address == arinsal_term::beam_unloaded_fun() {
        return None;
    }
    let native = crate::beamasm_integration::native_function_for_pc(address)?;
    Some(ErtsCodeMfa {
        module: Term::atom(native.module_atom).tagged_word(),
        function: Term::atom(native.function_atom).tagged_word(),
        arity: usize::from(native.arity),
    })
}

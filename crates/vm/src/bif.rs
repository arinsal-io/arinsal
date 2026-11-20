// Port of erts/emulator/beam/bif.c.

use crate::{Process, VmError, exceptions};
use arinsal_bifs::BifError;
use arinsal_term::{Term, TermBuilder};

/// `erlang:make_fun/3` over the three BIF argument registers.
// Port of erts/emulator/beam/bif.c:4467 (`make_fun_3`), OTP-29.1.1.
pub(crate) fn make_fun_3(
    c_p: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    let [module, function, arity] = args else {
        return Some(Err(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::BADARG,
        ))));
    };
    let result = (|| {
        let module_atom = module.as_atom().ok_or_else(|| {
            exceptions::bif_error(c_p, "erlang", "make_fun", args, BifError::BADARG)
        })?;
        let function_atom = function.as_atom().ok_or_else(|| {
            exceptions::bif_error(c_p, "erlang", "make_fun", args, BifError::BADARG)
        })?;
        let arity_value = arity
            .as_small()
            .filter(|value| (0..=255).contains(value))
            .ok_or_else(|| {
                exceptions::bif_error(c_p, "erlang", "make_fun", args, BifError::BADARG)
            })? as u32;
        let entry =
            crate::export::export_get_or_make_stub((module_atom, function_atom, arity_value))
                .ok_or_else(|| VmError::Unsupported("make_fun export stub unavailable".into()))?;
        TermBuilder::new(&mut c_p.heap)
            .export_fun(entry)
            .map_err(|error| VmError::Unsupported(format!("make_fun allocation {error:?}")))
    })();
    Some(result.map_err(|error| match error {
        VmError::Trap(trap) => trap,
        _ => crate::exceptions::Trap::error(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT)),
    }))
}

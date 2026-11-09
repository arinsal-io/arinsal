//! Continuation BIFs used by `erts_call_dirty_bif`.

use crate::{BifError, BifTableVisitor, Class, Ctx, Term, bif_bodies};

bif_bodies!(dirty_bif_result, dirty_bif_exception, dirty_bif_trap);

pub(crate) fn lookup<V: BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    visitor: &mut V,
) -> Option<V::Output> {
    if module != "erts_internal" {
        return None;
    }
    Some(match (name, arity) {
        ("dirty_bif_result", 1) => visitor.entry::<bodies::dirty_bif_result>(),
        ("dirty_bif_exception", 2) => visitor.entry::<bodies::dirty_bif_exception>(),
        ("dirty_bif_trap", 1..=3) => visitor.entry::<bodies::dirty_bif_trap>(),
        _ => return None,
    })
}

// Port of erts/emulator/beam/bif.c:5605-5610 (dirty_bif_result), OTP-29.1.1.
fn dirty_bif_result(_ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    Ok(args[0])
}

// Port of erts/emulator/beam/bif.c:5630-5640 (dirty_bif_exception), OTP-29.1.1.
fn dirty_bif_exception(_ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let freason = args[0].as_small().ok_or(BifError::BADARG)? as u64;
    let class = match freason & 3 {
        2 => Class::Exit,
        3 => Class::Throw,
        _ => Class::Error,
    };
    Err(BifError::Raise {
        class,
        reason: args[1],
        stacktrace: None,
    })
}

// The trap handler restores the original native-function continuation and its arguments.
// That state is supplied by the process scheduler, so a heap-only BIF context cannot execute it.
// The scheduler's process-aware implementation handles this entry.
fn dirty_bif_trap(_ctx: &mut Ctx<'_>, _args: &[Term]) -> Result<Term, BifError> {
    Err(BifError::DirtyTrap)
}

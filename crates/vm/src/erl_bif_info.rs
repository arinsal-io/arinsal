// Port of erts/emulator/beam/erl_bif_info.c.

use crate::{Process, VmError, exceptions};
use arinsal_bifs::BifError;
use arinsal_term::{FunRef, Term, TermBuilder, global_atoms};

/// Return `{Module, Function, Arity}` for a local or external fun.
// Port of erts/emulator/beam/erl_bif_info.c:4011 (`fun_info_mfa_1`), OTP-29.1.1.
pub(crate) fn fun_info_mfa_1(c_p: &mut Process, reg: &mut [Term]) -> Result<Term, VmError> {
    c_p.ensure_objv(4, &mut reg[..1]);
    let fun = reg[0];
    // SAFETY: `reg[0]` roots the fun while its MFA tuple is allocated.
    let view = unsafe { fun.fun_ref() }.ok_or_else(|| {
        exceptions::bif_error(c_p, "erlang", "fun_info_mfa", &[fun], BifError::BADARG)
    })?;
    let (module, name) = match view {
        FunRef::Local { entry, .. } => {
            let mfa = crate::erl_fun::erts_get_fun_mfa(entry);
            (
                entry.module,
                mfa.map(|mfa| crate::native_hooks::from_raw(mfa.function)),
            )
        }
        FunRef::Export { entry } => (entry.module(), Some(Term::atom(entry.function()))),
    };
    let name = name.unwrap_or(Term::NIL);
    let arity = u32::from(fun.fun_arity().unwrap());
    TermBuilder::new(&mut c_p.heap)
        .tuple(&[
            Term::atom(module),
            name,
            Term::small(i64::from(arity)).unwrap(),
        ])
        .map_err(|error| VmError::Unsupported(format!("fun_info_mfa tuple: {error:?}")))
}

/// Return the requested `{Key, Value}` pair for a fun.
// Port of erts/emulator/beam/erl_bif_info.c:3912 (`fun_info_2`), OTP-29.1.1.
pub(crate) fn fun_info_2(
    c_p: &mut Process,
    args: &[Term],
) -> Option<Result<Term, crate::exceptions::Trap>> {
    if args.len() != 2 {
        return Some(Err(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::BADARG,
        ))));
    }
    let mut reg = [args[0], args[1]];
    Some(fun_info_2_body(c_p, &mut reg).map_err(|error| match error {
        VmError::Trap(trap) => trap,
        _ => crate::exceptions::Trap::error(Term::atom(arinsal_term::atoms::SYSTEM_LIMIT)),
    }))
}

fn fun_info_2_body(c_p: &mut Process, reg: &mut [Term]) -> Result<Term, VmError> {
    p_ensure_fun_info_roots(c_p, reg)?;
    let fun = reg[0];
    let what = reg[1];
    // SAFETY: `reg[..2]` roots the fun and key while the result is allocated.
    let view = unsafe { fun.fun_ref() }.ok_or_else(|| {
        exceptions::bif_error(c_p, "erlang", "fun_info", &[fun, what], BifError::BADARG)
    })?;
    let key = global_atoms()
        .text(what.as_atom().ok_or_else(|| {
            exceptions::bif_error(c_p, "erlang", "fun_info", &[fun, what], BifError::BADARG)
        })?)
        .ok_or_else(|| {
            exceptions::bif_error(c_p, "erlang", "fun_info", &[fun, what], BifError::BADARG)
        })?;
    let mut builder = TermBuilder::new(&mut c_p.heap);
    let value = match (&view, key) {
        (FunRef::Local { .. }, "pid") => Term::pid(0, 0).unwrap(),
        (FunRef::Export { .. }, "pid" | "index" | "new_index" | "uniq" | "new_uniq" | "refc") => {
            atom("undefined")?
        }
        (FunRef::Local { entry, .. }, "module") => Term::atom(entry.module),
        (FunRef::Export { entry }, "module") => Term::atom(entry.module()),
        (FunRef::Local { entry, .. }, "index") => Term::small(i64::from(entry.old_index))
            .ok_or_else(|| VmError::Unsupported("fun index".into()))?,
        (FunRef::Local { entry, .. }, "new_index") => Term::small(i64::from(entry.index))
            .ok_or_else(|| VmError::Unsupported("fun index".into()))?,
        (FunRef::Local { entry, .. }, "uniq") => Term::small(i64::from(entry.old_uniq))
            .ok_or_else(|| VmError::Unsupported("fun uniq".into()))?,
        (FunRef::Local { entry, .. }, "new_uniq") => builder
            .binary(&entry.uniq)
            .map_err(|error| VmError::Unsupported(format!("fun uniq allocation {error:?}")))?,
        (FunRef::Local { entry, .. }, "name") => crate::erl_fun::erts_get_fun_mfa(entry)
            .map(|mfa| crate::native_hooks::from_raw(mfa.function))
            .unwrap_or(Term::NIL),
        (FunRef::Export { entry }, "name") => Term::atom(entry.function()),
        (FunRef::Local { .. } | FunRef::Export { .. }, "arity") => {
            Term::small(i64::from(fun.fun_arity().unwrap())).unwrap()
        }
        (FunRef::Local { free_vars, .. }, "env") => {
            let mut list = Term::NIL;
            for &word in free_vars.iter().rev() {
                // SAFETY: The fun header bounds the captured term words.
                let value = unsafe { std::mem::transmute::<u64, Term>(word) };
                list = builder.cons(value, list).map_err(|error| {
                    VmError::Unsupported(format!("fun env allocation {error:?}"))
                })?;
            }
            list
        }
        (FunRef::Export { .. }, "env") => Term::NIL,
        (FunRef::Local { .. }, "type") => atom("local")?,
        (FunRef::Export { .. }, "type") => atom("external")?,
        (FunRef::Local { .. }, "refc") => Term::small(1).unwrap(),
        _ => {
            return Err(exceptions::bif_error(
                c_p,
                "erlang",
                "fun_info",
                &[fun, what],
                BifError::BADARG,
            ));
        }
    };
    let key = atom(key)?;
    builder
        .tuple(&[key, value])
        .map_err(|error| VmError::Unsupported(format!("fun info allocation {error:?}")))
}

fn p_ensure_fun_info_roots(c_p: &mut Process, reg: &mut [Term]) -> Result<(), VmError> {
    c_p.ensure_objv(1024, &mut reg[..2]);
    Ok(())
}

fn atom(name: &str) -> Result<Term, VmError> {
    global_atoms()
        .intern(name)
        .map(Term::atom)
        .map_err(|_| VmError::Unsupported(format!("fun info atom {name}")))
}

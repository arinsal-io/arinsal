//! OTP native record BIFs.

use super::NativeArgs;
use crate::process::Message;
use crate::{Process, Vm, VmError, exceptions};
use arinsal_bifs::FragmentingHeap;
use arinsal_sched::RunCtx;
use arinsal_term::{
    Atom, Term, TermBuilder, TermKind, from_owned, global_atoms, record_map_pairs, term_sequence,
};

pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("records", "create", 4),
    ("records", "get", 2),
    ("records", "get_definition", 2),
    ("records", "get_field_names", 1),
    ("records", "get_module", 1),
    ("records", "get_name", 1),
    ("records", "is_exported", 1),
    ("records", "update", 4),
];

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("built-in atom"))
}

fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|text| text.to_string())
}

fn badarg() -> VmError {
    VmError::Trap(exceptions::Trap::error(atom("badarg")))
}

fn system_limit() -> VmError {
    VmError::Trap(exceptions::Trap::error(atom("system_limit")))
}

fn error_with_value(process: &mut Process, reason: &str, value: Term) -> VmError {
    match TermBuilder::new(&mut FragmentingHeap(&mut process.heap)).tuple(&[atom(reason), value]) {
        Ok(reason) => VmError::Trap(exceptions::Trap::error(reason)),
        Err(_) => system_limit(),
    }
}

fn badfield(process: &mut Process, module: Atom, name: Atom, key: Term) -> VmError {
    let mut heap = FragmentingHeap(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let record_id = match builder.tuple(&[Term::atom(module), Term::atom(name)]) {
        Ok(value) => value,
        Err(_) => return system_limit(),
    };
    let field_id = match builder.tuple(&[record_id, key]) {
        Ok(value) => value,
        Err(_) => return system_limit(),
    };
    match builder.tuple(&[atom("badfield"), field_id]) {
        Ok(reason) => VmError::Trap(exceptions::Trap::error(reason)),
        Err(_) => system_limit(),
    }
}

fn map_pairs(map: Term) -> Result<Vec<(Term, Term)>, VmError> {
    record_map_pairs(map).ok_or_else(badarg)
}

/// Port of erts/emulator/beam/erl_record.c:592 (records_create_4), OTP-29.1.1.
fn create(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let module = args[0].as_atom();
    let name = args[1].as_atom();
    let (Some(module), Some(name)) = (module, name) else {
        return Err(error_with_value(process, "badrecord", args[1]));
    };
    if args[3].classify() != TermKind::Map {
        return Err(error_with_value(process, "badmap", args[3]));
    }
    let options = map_pairs(args[3])?;
    if options.len() != 1 {
        return Err(badarg());
    }
    let exported = if options[0].0 == atom("is_exported") {
        if options[0].1 == atom("true") {
            true
        } else if options[0].1 == atom("false") {
            false
        } else {
            return Err(badarg());
        }
    } else {
        return Err(badarg());
    };
    let Some(fields) = term_sequence(args[2]) else {
        return Err(badarg());
    };
    let mut parsed = Vec::with_capacity(fields.len());
    for pair in fields {
        let Some(values) = term_sequence(pair).filter(|values| values.len() == 2) else {
            return Err(badarg());
        };
        let Some(key) = values[0].as_atom() else {
            let record_id = TermBuilder::new(&mut FragmentingHeap(&mut process.heap))
                .tuple(&[Term::atom(module), Term::atom(name)])
                .map_err(|_| system_limit())?;
            let badfield = TermBuilder::new(&mut FragmentingHeap(&mut process.heap))
                .tuple(&[record_id, values[0]])
                .map_err(|_| system_limit())?;
            return Err(error_with_value(process, "badfield", badfield));
        };
        parsed.push((key, values[1]));
    }
    TermBuilder::new(&mut FragmentingHeap(&mut process.heap))
        .native_record(module, name, exported, &parsed)
        .map_err(|error| match error {
            arinsal_term::TermError::BadArg => badarg(),
            _ => system_limit(),
        })
}

/// Port of erts/emulator/beam/erl_record.c:775 (records_update_4), OTP-29.1.1.
fn update(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let Some(snapshot) = args[0].record_snapshot() else {
        return Err(error_with_value(process, "badrecord", args[0]));
    };
    let wildcard = atom("_");
    if args[2] != wildcard {
        let (Some(module), Some(name)) = (args[1].as_atom(), args[2].as_atom()) else {
            return Err(error_with_value(process, "badrecord", args[2]));
        };
        if module != snapshot.module || name != snapshot.name {
            return Err(error_with_value(process, "badrecord", args[2]));
        }
    }
    if args[3].classify() != TermKind::Map {
        return Err(error_with_value(process, "badmap", args[3]));
    }
    let changes = map_pairs(args[3])?;
    if changes.is_empty() {
        return Ok(args[0]);
    }
    for (key, _) in &changes {
        if !snapshot
            .fields
            .contains(&key.as_atom().unwrap_or(Atom(u32::MAX)))
        {
            return Err(badfield(process, snapshot.module, snapshot.name, *key));
        }
    }
    TermBuilder::new(&mut FragmentingHeap(&mut process.heap))
        .update_native_record(
            &snapshot,
            &changes
                .iter()
                .map(|(key, value)| (key.as_atom().unwrap(), *value))
                .collect::<Vec<_>>(),
        )
        .map_err(|error| match error {
            arinsal_term::TermError::BadArg => badarg(),
            _ => system_limit(),
        })
}

/// Port of erts/emulator/beam/erl_record.c:935 (records_get_2), OTP-29.1.1.
fn get(args: &[Term]) -> Result<Term, VmError> {
    let Some(key) = args[0].as_atom() else {
        return Err(badarg());
    };
    let Some(record) = args[1].record_snapshot() else {
        return Err(badarg());
    };
    let sorted_index = record.fields.iter().filter(|field| field.0 < key.0).count();
    if record.fields.contains(&key) {
        Ok(record.values[sorted_index])
    } else {
        Err(badarg())
    }
}

/// Port of erts/emulator/beam/erl_record.c:1030 (records_get_definition_2), OTP-29.1.1.
fn definition(vm: &Vm, process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let (Some(module), Some(name)) = (atom_name(args[0]), atom_name(args[1])) else {
        return Err(badarg());
    };
    let Some(record) = vm.native_record_definition(&module, &name).cloned() else {
        return Err(badarg());
    };
    let is_exported = Term::atom(if record.is_exported {
        arinsal_term::atoms::TRUE
    } else {
        arinsal_term::atoms::FALSE
    });
    let mut heap = FragmentingHeap(&mut process.heap);
    let mut defaults = Vec::with_capacity(record.fields.len());
    for (field, default) in &record.fields {
        let field = Term::atom(global_atoms().intern(field).map_err(|_| system_limit())?);
        let value = default
            .as_ref()
            .map(|default| from_owned(default, &mut heap).map_err(|_| system_limit()))
            .transpose()?;
        defaults.push((field, value));
    }
    let mut builder = TermBuilder::new(&mut heap);
    let options = builder
        .flatmap_from_pairs(&[(atom("is_exported"), is_exported)])
        .map_err(|_| system_limit())?;
    let mut fields = Vec::with_capacity(defaults.len());
    for (field, default) in defaults {
        let field = if let Some(value) = default {
            builder.tuple(&[field, value]).map_err(|_| system_limit())?
        } else {
            field
        };
        fields.push(field);
    }
    let fields = builder.list_from_iter(fields).map_err(|_| system_limit())?;
    builder
        .tuple(&[options, fields])
        .map_err(|_| system_limit())
}

/// Port of erts/emulator/beam/erl_record.c:986 (records_get_field_names_1), OTP-29.1.1.
fn get_field_names(process: &mut Process, term: Term) -> Result<Term, VmError> {
    let Some(record) = term.record_snapshot() else {
        return Err(error_with_value(process, "badrecord", term));
    };
    TermBuilder::new(&mut FragmentingHeap(&mut process.heap))
        .list_from_iter(record.fields.into_iter().map(Term::atom))
        .map_err(|_| system_limit())
}

/// Port of erts/emulator/beam/erl_record.c:964 (records_get_module_1), OTP-29.1.1.
fn get_module(term: Term) -> Result<Term, VmError> {
    term.record_snapshot()
        .map(|record| Term::atom(record.module))
        .ok_or_else(badarg)
}

/// Port of erts/emulator/beam/erl_record.c:975 (records_get_name_1), OTP-29.1.1.
fn get_name(term: Term) -> Result<Term, VmError> {
    term.record_snapshot()
        .map(|record| Term::atom(record.name))
        .ok_or_else(badarg)
}

/// Port of erts/emulator/beam/erl_record.c:1016 (records_is_exported_1), OTP-29.1.1.
fn is_exported(process: &mut Process, term: Term) -> Result<Term, VmError> {
    let Some(record) = term.record_snapshot() else {
        return Err(error_with_value(process, "badrecord", term));
    };
    Ok(Term::atom(if record.is_exported {
        arinsal_term::atoms::TRUE
    } else {
        arinsal_term::atoms::FALSE
    }))
}

pub(crate) fn dispatch(
    vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    let result = match function {
        "create" if args.len() == 4 => create(process, args),
        "get" if args.len() == 2 => get(args),
        "get_definition" if args.len() == 2 => definition(vm, process, args),
        "get_field_names" if args.len() == 1 => get_field_names(process, args[0]),
        "get_module" if args.len() == 1 => get_module(args[0]),
        "get_name" if args.len() == 1 => get_name(args[0]),
        "is_exported" if args.len() == 1 => is_exported(process, args[0]),
        "update" if args.len() == 4 => update(process, args),
        _ => return None,
    };
    Some(result)
}

pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    if module != "records" {
        return None;
    }
    args.with_values(process, |process, values| {
        dispatch(vm, process, ctx, function, values)
    })
}

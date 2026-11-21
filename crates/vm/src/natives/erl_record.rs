//! The native record BIFs of erl_record.c.
//!
//! Port of erts/emulator/beam/erl_record.c (records_create_4, records_update_4,
//! records_get_2, records_get_module_1, records_get_name_1, records_get_field_names_1,
//! records_is_exported_1, records_get_definition_2), OTP-29.1.1. Each BIF is
//! `bif_table[].f` with `(c_p, reg, I)`.

use crate::Process;
use crate::natives::bif::{bif_badarg, bif_system_limit};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::{
    Atom, HeapReservation, Term, TermBuilder, TermKind, atoms, find_record_definition,
    record_map_pairs, term_sequence,
};

enum Fail {
    Badarg,
    SystemLimit,
    Tagged(u64, Term),
}

impl Fail {
    fn into_non_value(self, c_p: *mut ProcessHeader) -> u64 {
        match self {
            Self::Badarg => bif_badarg(c_p),
            Self::SystemLimit => bif_system_limit(c_p),
            Self::Tagged(freason, value) => bif_error_value(c_p, freason, value),
        }
    }
}

/// `BIF_ERROR(c_p, freason)` with `c_p->fvalue` set when erts stores a tagged value.
// Port of erts/emulator/beam/bif.h (BIF_ERROR), OTP-29.1.1.
fn bif_error_value(c_p: *mut ProcessHeader, freason: u64, fvalue: Term) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.abi.exc.freason = freason;
    process.heap.abi.exc.fvalue = fvalue.word();
    arinsal_term::THE_NON_VALUE
}

fn ret(c_p: *mut ProcessHeader, result: Result<Term, Fail>) -> u64 {
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(fail) => fail.into_non_value(c_p),
    }
}

fn field_id(process: &mut Process, module: Atom, name: Atom, key: Term) -> Result<Term, Fail> {
    let mut heap = HeapReservation::new(&mut process.heap, 6).map_err(|_| Fail::SystemLimit)?;
    let record_id = TermBuilder::new(&mut heap)
        .tuple(&[Term::atom(module), Term::atom(name)])
        .map_err(|_| Fail::SystemLimit)?;
    TermBuilder::new(&mut heap)
        .tuple(&[record_id, key])
        .map_err(|_| Fail::SystemLimit)
}

/// `records:create/4`.
// Port of erts/emulator/beam/erl_record.c (records_create_4), OTP-29.1.1.
pub(crate) extern "C" fn records_create_4(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [module, name, fs, opts] = crate::bif_table::bif_args::<4>(reg);
    let (Some(module_atom), Some(name_atom)) = (module.as_atom(), name.as_atom()) else {
        return bif_error_value(c_p, arinsal_term::exc::EXC_BADRECORD, name);
    };
    if opts.classify() != TermKind::Map {
        return bif_error_value(c_p, arinsal_term::exc::EXC_BADMAP, opts);
    }
    ret(c_p, create(process, module_atom, name_atom, fs, opts))
}

fn create(
    process: &mut Process,
    module: Atom,
    name: Atom,
    fs: Term,
    opts: Term,
) -> Result<Term, Fail> {
    let options = record_map_pairs(opts).ok_or(Fail::Badarg)?;
    if options.len() != 1 {
        return Err(Fail::Badarg);
    }
    let exported = if options[0].0 == Term::atom(atoms::IS_EXPORTED) {
        if options[0].1 == Term::atom(atoms::TRUE) {
            true
        } else if options[0].1 == Term::atom(atoms::FALSE) {
            false
        } else {
            return Err(Fail::Badarg);
        }
    } else {
        return Err(Fail::Badarg);
    };
    let Some(fields) = term_sequence(fs) else {
        return Err(Fail::Badarg);
    };
    let mut parsed = Vec::with_capacity(fields.len());
    for pair in fields {
        let Some(values) = term_sequence(pair).filter(|values| values.len() == 2) else {
            return Err(Fail::Badarg);
        };
        let Some(key) = values[0].as_atom() else {
            let badfield = field_id(process, module, name, values[0])?;
            return Err(Fail::Tagged(arinsal_term::exc::EXC_BADFIELD, badfield));
        };
        parsed.push((key, values[1]));
    }
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .native_record(module, name, exported, &parsed)
        .map_err(|error| match error {
            arinsal_term::TermError::BadArg => Fail::Badarg,
            _ => Fail::SystemLimit,
        })
}

/// `records:update/4`.
// Port of erts/emulator/beam/erl_record.c (records_update_4), OTP-29.1.1.
pub(crate) extern "C" fn records_update_4(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = crate::bif_table::bif_args::<4>(reg);
    ret(c_p, update(process, &args))
}

fn update(process: &mut Process, args: &[Term; 4]) -> Result<Term, Fail> {
    let Some(snapshot) = args[0].record_snapshot() else {
        return Err(Fail::Tagged(arinsal_term::exc::EXC_BADRECORD, args[0]));
    };
    let wildcard = Term::atom(atoms::UNDERSCORE);
    if args[2] != wildcard {
        let (Some(module), Some(name)) = (args[1].as_atom(), args[2].as_atom()) else {
            return Err(Fail::Tagged(arinsal_term::exc::EXC_BADRECORD, args[2]));
        };
        if module != snapshot.module || name != snapshot.name {
            return Err(Fail::Tagged(arinsal_term::exc::EXC_BADRECORD, args[2]));
        }
    }
    if args[3].classify() != TermKind::Map {
        return Err(Fail::Tagged(arinsal_term::exc::EXC_BADMAP, args[3]));
    }
    let mut changes = record_map_pairs(args[3]).ok_or(Fail::Badarg)?;
    if changes.is_empty() {
        return Ok(args[0]);
    }
    // The first leftover key after matching the sorted keys against the record is the
    // reported bad field (erl_record.c:855-931).
    changes.sort_by(|a, b| arinsal_term::flat_key_cmp(a.0, b.0));
    let mut keys = snapshot.fields.clone();
    keys.sort_by_key(|field| field.0);
    let mut next = 0;
    for key in keys {
        if changes
            .get(next)
            .is_some_and(|(candidate, _)| candidate.as_atom() == Some(key))
        {
            next += 1;
        }
    }
    if let Some((key, _)) = changes.get(next) {
        let badfield = field_id(process, snapshot.module, snapshot.name, *key)?;
        return Err(Fail::Tagged(arinsal_term::exc::EXC_BADFIELD, badfield));
    }
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .update_native_record(
            &snapshot,
            &changes
                .iter()
                .map(|(key, value)| (key.as_atom().unwrap(), *value))
                .collect::<Vec<_>>(),
        )
        .map_err(|error| match error {
            arinsal_term::TermError::BadArg => Fail::Badarg,
            _ => Fail::SystemLimit,
        })
}

/// `records:get/2`.
// Port of erts/emulator/beam/erl_record.c (records_get_2), OTP-29.1.1.
pub(crate) extern "C" fn records_get_2(c_p: *mut ProcessHeader, reg: *mut u64, _i: u64) -> u64 {
    let [key, record] = crate::bif_table::bif_args::<2>(reg);
    let Some(key_atom) = key.as_atom() else {
        return bif_badarg(c_p);
    };
    let Some(record) = record.record_snapshot() else {
        return bif_badarg(c_p);
    };
    let sorted_index = record
        .fields
        .iter()
        .filter(|field| field.0 < key_atom.0)
        .count();
    if record.fields.contains(&key_atom) {
        crate::native_hooks::raw(record.values[sorted_index])
    } else {
        bif_badarg(c_p)
    }
}

/// `records:get_module/1`.
// Port of erts/emulator/beam/erl_record.c (records_get_module_1), OTP-29.1.1.
pub(crate) extern "C" fn records_get_module_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let [record] = crate::bif_table::bif_args::<1>(reg);
    match record.record_snapshot() {
        Some(record) => crate::native_hooks::raw(Term::atom(record.module)),
        None => bif_badarg(c_p),
    }
}

/// `records:get_name/1`.
// Port of erts/emulator/beam/erl_record.c (records_get_name_1), OTP-29.1.1.
pub(crate) extern "C" fn records_get_name_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let [record] = crate::bif_table::bif_args::<1>(reg);
    match record.record_snapshot() {
        Some(record) => crate::native_hooks::raw(Term::atom(record.name)),
        None => bif_badarg(c_p),
    }
}

/// `records:get_field_names/1`.
// Port of erts/emulator/beam/erl_record.c (records_get_field_names_1), OTP-29.1.1.
pub(crate) extern "C" fn records_get_field_names_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [record] = crate::bif_table::bif_args::<1>(reg);
    let Some(snapshot) = record.record_snapshot() else {
        return bif_error_value(c_p, arinsal_term::exc::EXC_BADRECORD, record);
    };
    ret(
        c_p,
        TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
            .list_from_iter(snapshot.fields.into_iter().map(Term::atom))
            .map_err(|_| Fail::SystemLimit),
    )
}

/// `records:is_exported/1`.
// Port of erts/emulator/beam/erl_record.c (records_is_exported_1), OTP-29.1.1.
pub(crate) extern "C" fn records_is_exported_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let [record] = crate::bif_table::bif_args::<1>(reg);
    let Some(snapshot) = record.record_snapshot() else {
        return bif_error_value(c_p, arinsal_term::exc::EXC_BADRECORD, record);
    };
    crate::native_hooks::raw(Term::atom(if snapshot.is_exported {
        atoms::TRUE
    } else {
        atoms::FALSE
    }))
}

/// `records:get_definition/2`.
// Port of erts/emulator/beam/erl_record.c (records_get_definition_2), OTP-29.1.1.
pub(crate) extern "C" fn records_get_definition_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [module, name] = crate::bif_table::bif_args::<2>(reg);
    let (Some(module), Some(name)) = (module.as_atom(), name.as_atom()) else {
        return bif_badarg(c_p);
    };
    ret(c_p, definition(process, module, name))
}

fn definition(process: &mut Process, module: Atom, name: Atom) -> Result<Term, Fail> {
    let cons = find_record_definition(module, name).ok_or(Fail::Badarg)?;
    let (def_term, defaults_term) = crate::lists::split(cons).ok_or(Fail::Badarg)?;
    let def_words = term_sequence(def_term).ok_or(Fail::Badarg)?;
    if def_words.len() < 5 {
        return Err(Fail::Badarg);
    }
    let order = term_sequence(def_words[0]).ok_or(Fail::Badarg)?;
    let exported = def_words[4];
    let keys = &def_words[5..];
    let defaults = term_sequence(defaults_term).ok_or(Fail::Badarg)?;
    if order.len() != keys.len() || defaults.len() != keys.len() {
        return Err(Fail::Badarg);
    }
    let mut heap = HeapReservation::new(&mut process.heap, 0).map_err(|_| Fail::SystemLimit)?;
    let mut fields = Vec::with_capacity(order.len());
    for slot in &order {
        let sorted =
            usize::try_from(slot.as_small().ok_or(Fail::Badarg)?).map_err(|_| Fail::Badarg)?;
        let key = *keys.get(sorted).ok_or(Fail::Badarg)?;
        let default = *defaults.get(sorted).ok_or(Fail::Badarg)?;
        let field = if default.classify() == TermKind::Catch {
            key
        } else {
            TermBuilder::new(&mut heap)
                .tuple(&[key, default])
                .map_err(|_| Fail::SystemLimit)?
        };
        fields.push(field);
    }
    let fields = TermBuilder::new(&mut heap)
        .list_from_iter(fields)
        .map_err(|_| Fail::SystemLimit)?;
    let options = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[(Term::atom(atoms::IS_EXPORTED), exported)])
        .map_err(|_| Fail::SystemLimit)?;
    TermBuilder::new(&mut heap)
        .tuple(&[options, fields])
        .map_err(|_| Fail::SystemLimit)
}

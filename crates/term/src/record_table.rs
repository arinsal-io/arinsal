//! Canonical native record definitions (`erts_record_put`, `erts_canonical_record_def`).
use crate::{Atom, Term, TermError};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::RwLock;

/// Definition of a record as built from its field names, before canonicalisation.
pub(crate) struct RecordLayout {
    pub(crate) module: Atom,
    pub(crate) name: Atom,
    pub(crate) exported: bool,
    pub(crate) hash: u32,
    /// `(original index, key)` in atom-index order.
    pub(crate) sorted: Vec<(usize, Atom)>,
    /// Sorted position of every field in definition order.
    pub(crate) order: Vec<usize>,
}

impl RecordLayout {
    // Port of erts/emulator/beam/erl_record.c:701-779 and beam_file.c:1100-1250, OTP-29.1.1.
    pub(crate) fn new(
        module: Atom,
        name: Atom,
        exported: bool,
        keys: impl Iterator<Item = Atom>,
    ) -> Result<Self, TermError> {
        let keys: Vec<Atom> = keys.collect();
        if keys.len() > (1 << 24) - 2 {
            return Err(TermError::SystemLimit);
        }
        let mut sorted: Vec<(usize, Atom)> = keys.iter().copied().enumerate().collect();
        sorted.sort_by_key(|(_, key)| key.0);
        if sorted.windows(2).any(|pair| pair[0].1 == pair[1].1) {
            return Err(TermError::BadArg);
        }
        let mut order = vec![0; keys.len()];
        for (sorted_index, (original_index, _)) in sorted.iter().enumerate() {
            order[*original_index] = sorted_index;
        }
        // The portable hash covers the keys in definition order.
        let mut temp = vec![0_u64; 4 + keys.len()];
        temp[0] = ((3 + keys.len()) as u64) << 6;
        temp[1] = Term::atom(module).bits();
        temp[2] = Term::atom(name).bits();
        temp[3] = bool_term(exported).bits();
        for (i, key) in keys.iter().enumerate() {
            temp[4 + i] = Term::atom(*key).bits();
        }
        let hash = crate::make_hash2(Term::from_ptr(temp.as_mut_ptr(), 2));
        Ok(Self {
            module,
            name,
            exported,
            hash,
            sorted,
            order,
        })
    }

    pub(crate) fn exported_term(&self) -> Term {
        bool_term(self.exported)
    }
}

fn bool_term(value: bool) -> Term {
    Term::atom(if value {
        crate::atoms::TRUE
    } else {
        crate::atoms::FALSE
    })
}

type Key = (u64, u32, u32);

static TABLE: RwLock<Option<HashMap<Key, (u64, u64)>>> = RwLock::new(None);

thread_local! {
    static SCOPE: Cell<u64> = const { Cell::new(0) };
}

/// Select the code scope whose record definitions canonicalise records built on this thread.
pub fn set_record_scope(scope: u64) {
    SCOPE.with(|cell| cell.set(scope));
}

/// Register the `[Definition | Defaults]` literal `cons` of `module:name` and its
/// `definition` tuple (`erts_record_put`).
pub fn put_record_definition(scope: u64, module: Atom, name: Atom, cons: Term, definition: Term) {
    let mut table = TABLE.write().expect("record table poisoned");
    table
        .get_or_insert_with(HashMap::new)
        .insert((scope, module.0, name.0), (cons.bits(), definition.bits()));
}

/// Forget every definition of `module` (`erts_record_module_delete`).
pub fn delete_module_record_definitions(scope: u64, module: Atom) {
    let mut table = TABLE.write().expect("record table poisoned");
    if let Some(table) = table.as_mut() {
        table.retain(|(entry_scope, entry_module, _), _| {
            !(*entry_scope == scope && *entry_module == module.0)
        });
    }
}

/// Forget all definitions of a code scope that is being released.
pub fn drop_record_scope(scope: u64) {
    let mut table = TABLE.write().expect("record table poisoned");
    if let Some(table) = table.as_mut() {
        table.retain(|(entry_scope, _, _), _| *entry_scope != scope);
    }
}

/// The registered `[Definition | Defaults]` literal of `module:name` in an explicit scope.
pub fn find_record_definition_in(scope: u64, module: Atom, name: Atom) -> Option<Term> {
    find_entry(scope, module, name).map(|(cons, _)| cons)
}

fn find_entry(scope: u64, module: Atom, name: Atom) -> Option<(Term, Term)> {
    let table = TABLE.read().expect("record table poisoned");
    table
        .as_ref()?
        .get(&(scope, module.0, name.0))
        .map(|(cons, definition)| (Term(*cons), Term(*definition)))
}

/// Port of erts/emulator/beam/erl_record.c:106-153 (erts_canonical_record_def), OTP-29.1.1:
/// the module's registered definition when it has the same visibility, keys and order.
pub(crate) fn canonical_definition(layout: &RecordLayout) -> Option<Term> {
    let scope = SCOPE.with(Cell::get);
    let (_, definition) = find_entry(scope, layout.module, layout.name)?;
    let words = crate::term_sequence(definition)?;
    if words.len() != 5 + layout.sorted.len() || words[4] != layout.exported_term() {
        return None;
    }
    let order = crate::term_sequence(words[0])?;
    if order.len() != layout.order.len()
        || order
            .iter()
            .zip(&layout.order)
            .any(|(have, want)| have.as_small() != Some(*want as i64))
    {
        return None;
    }
    let keys_match = layout
        .sorted
        .iter()
        .zip(&words[5..])
        .all(|((_, key), have)| *have == Term::atom(*key));
    keys_match.then_some(definition)
}

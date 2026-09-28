//! OTP 29 native record definition and instance views.
use crate::{ARITY, Atom, ListIter, RECORD, Term, TermKind};

/// Owned metadata copied from a live native record.
#[derive(Clone, Debug)]
pub struct RecordSnapshot {
    /// Original native record term.
    pub instance: Term,
    /// Term used as the canonical definition pointer by this record.
    pub definition: Term,
    /// Module defining the record.
    pub module: Atom,
    /// Record name.
    pub name: Atom,
    /// Export visibility.
    pub is_exported: bool,
    /// Definition hash.
    pub hash: u32,
    /// Field names in their original declaration order.
    pub fields: Vec<Atom>,
    /// Values in sorted atom order, matching OTP's instance layout.
    pub values: Vec<Term>,
}

/// Borrowed native record instance and its tuple-tagged definition.
pub struct RecordRef<'a> {
    words: &'a [u64],
    definition: &'a [u64],
    field_order: Vec<usize>,
    sorted_order: Vec<usize>,
}
impl RecordRef<'_> {
    /// Number of fields.
    pub fn len(&self) -> usize {
        self.words.len() - 2
    }
    /// Whether the record has no fields.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Defining module.
    pub fn module(&self) -> Atom {
        Term(self.definition[3]).as_atom().unwrap()
    }
    /// Record name.
    pub fn name(&self) -> Atom {
        Term(self.definition[4]).as_atom().unwrap()
    }
    /// Whether the definition was exported.
    pub fn is_exported(&self) -> bool {
        self.definition[5] == Term::atom(crate::atoms::TRUE).bits()
    }
    /// Definition hash used by `phash2`.
    pub fn definition_hash(&self) -> u32 {
        Term(self.definition[2]).as_small().unwrap() as u32
    }
    /// Field key in sorted storage order.
    pub fn key(&self, index: usize) -> Option<Atom> {
        self.definition
            .get(6 + index)
            .and_then(|word| Term(*word).as_atom())
    }
    /// Field value in sorted storage order.
    pub fn value(&self, index: usize) -> Option<Term> {
        self.words.get(2 + index).copied().map(Term)
    }
    /// Original field-order offset mapped to sorted storage order.
    pub fn original_index(&self, index: usize) -> Option<usize> {
        self.field_order.get(index).copied()
    }
    /// Sorted storage offset for a field in its original declaration order.
    pub fn sorted_index(&self, index: usize) -> Option<usize> {
        self.sorted_order.get(index).copied()
    }
}
impl Term {
    /// Test for a native record header.
    pub fn is_record(self) -> bool {
        self.header().is_some_and(|h| h & 63 == RECORD)
    }
    /// Borrow a native record instance and definition.
    ///
    /// # Safety
    /// Both the instance heap and its definition must remain live and unmoved.
    pub unsafe fn record_ref<'a>(self) -> Option<RecordRef<'a>> {
        let header = self.header()?;
        if header & 63 != RECORD {
            return None;
        }
        let len = (header >> 6) as usize;
        // SAFETY: both headers describe the complete initialized object spans.
        unsafe {
            let words = std::slice::from_raw_parts(self.raw_ptr(), len + 1);
            let definition_term = Term(words[1]);
            let def_header = definition_term.header()?;
            if def_header & 63 != ARITY {
                return None;
            }
            let definition = std::slice::from_raw_parts(
                definition_term.raw_ptr(),
                1 + (def_header >> 6) as usize,
            );
            let order_term = Term(definition[1]);
            let order_header = order_term.header()?;
            if order_header & 63 != ARITY {
                return None;
            }
            let sorted_order = std::slice::from_raw_parts(
                order_term.raw_ptr().add(1),
                (order_header >> 6) as usize,
            )
            .iter()
            .map(|word| usize::try_from(Term(*word).as_small()?).ok())
            .collect::<Option<Vec<_>>>()?;
            let mut field_order = vec![0; sorted_order.len()];
            for (original_index, sorted_index) in sorted_order.iter().copied().enumerate() {
                *field_order.get_mut(sorted_index)? = original_index;
            }
            Some(RecordRef {
                words,
                definition,
                field_order,
                sorted_order,
            })
        }
    }

    /// Copy the record's metadata and field values while its heap remains live.
    pub fn record_snapshot(self) -> Option<RecordSnapshot> {
        let header = self.header()?;
        if header & 63 != RECORD {
            return None;
        }
        let fields_count = (header >> 6) as usize - 1;
        // SAFETY: the instance and its definition are owned by the live source heap;
        // their headers bound every read below.
        unsafe {
            let instance = self.raw_ptr();
            let definition = Term(*instance.add(1));
            let def_header = definition.header()?;
            if def_header & 63 != ARITY || ((def_header >> 6) as usize) < 5 + fields_count {
                return None;
            }
            let def = definition.raw_ptr();
            let order = Term(*def.add(1));
            let order_header = order.header()?;
            if order_header & 63 != ARITY || (order_header >> 6) as usize != fields_count {
                return None;
            }
            let mut fields = vec![Atom(0); fields_count];
            let mut values = vec![Term::NIL; fields_count];
            for (sorted_index, value) in values.iter_mut().enumerate() {
                *value = Term(*instance.add(2 + sorted_index));
            }
            for (original_index, field) in fields.iter_mut().enumerate() {
                let sorted_index = Term(*order.raw_ptr().add(original_index + 1))
                    .as_small()
                    .and_then(|n| usize::try_from(n).ok())?;
                if sorted_index >= fields_count {
                    return None;
                }
                *field = Term(*def.add(6 + sorted_index)).as_atom()?;
            }
            Some(RecordSnapshot {
                instance: self,
                definition,
                module: Term(*def.add(3)).as_atom()?,
                name: Term(*def.add(4)).as_atom()?,
                is_exported: Term(*def.add(5)) == Term::atom(crate::atoms::TRUE),
                hash: Term(*def.add(2))
                    .as_small()
                    .and_then(|n| u32::try_from(n).ok())?,
                fields,
                values,
            })
        }
    }
}

/// Copy the elements of a proper list or tuple while its heap remains live.
pub fn term_sequence(term: Term) -> Option<Vec<Term>> {
    // SAFETY: the caller holds all source heaps live during the synchronous copy.
    unsafe {
        match term.classify() {
            TermKind::Tuple => Some(term.tuple_ref()?.iter().collect()),
            TermKind::Nil => Some(Vec::new()),
            TermKind::List => {
                let mut iter = ListIter::new(term);
                let values: Vec<_> = iter.by_ref().collect();
                (iter.tail() == Term::NIL).then_some(values)
            }
            _ => None,
        }
    }
}

/// Copy map entries in the map iterator order while its heap remains live.
pub fn record_map_pairs(term: Term) -> Option<Vec<(Term, Term)>> {
    (term.classify() == TermKind::Map).then(|| crate::hamt::pairs(term))
}

//! The part of `LoaderState` (erts/emulator/beam/beam_load.h, jit/asm_load.c) that the transform
//! engine and its predicates and generators use, and the generated engine itself.

use crate::NewLiteral;
use crate::beam_op::*;
use arinsal_beam::BeamFile;
use arinsal_etf::OwnedTerm;
use arinsal_term::{Atom, Term, VecHeap, from_owned, global_atoms};
use num_bigint::BigInt;

/// `TE_OK`, `TE_FAIL` and `TE_SHORT_WINDOW`: what `erts_transform_engine` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TeResult {
    /// The window was rewritten.
    Ok,
    /// No rule applies to the first instruction.
    Fail,
    /// A rule needs more instructions than the window holds.
    ShortWindow,
}

/// The `rest_args` pointer of the engine: operands `start..start + len` of `op`, read through
/// the allocator when needed. Operations are not freed before the transformation ends, so the
/// view stays valid as the pointer into `op->a` does in C.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RestArgs {
    pub op: OpId,
    pub start: usize,
    pub len: usize,
}

impl RestArgs {
    /// `Rest[k]`.
    pub(crate) fn get(&self, st: &LoaderState, k: usize) -> BeamOpArg {
        debug_assert!(k < self.len);
        st.ops.op(self.op).a(self.start + k)
    }
}

/// `BeamFile_ImportEntry`, with the atoms as global atom indexes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ImportEntry {
    pub module: u64,
    pub function: u64,
    pub arity: u32,
}

/// `Label`: what the loader remembers per label.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Label {
    /// `value`: the label has been defined by an emitted `label` instruction.
    pub defined: bool,
    pub looprec_targeted: bool,
    /// `lambda_index`, `None` for `INVALID_LAMBDA_INDEX`.
    pub lambda_index: Option<usize>,
}

/// The module's literals: `beam.literals` and the terms the loader adds. The file's literals
/// are decoded when a predicate or generator asks for them: erts decodes them all in
/// `beamfile_read`, and the loader of this runtime does so for the module it builds.
pub(crate) struct Literals<'a> {
    beam: &'a BeamFile,
    /// The literal area.
    pub heap: VecHeap,
    owned: Vec<Option<OwnedTerm>>,
    terms: Vec<Option<Term>>,
    pub extra: Vec<NewLiteral>,
    extra_terms: Vec<Option<Term>>,
    /// `BeamFile_Record.def_literal` of each record: the literal index.
    pub record_defs: Vec<u64>,
}

impl<'a> Literals<'a> {
    /// Port of erts/emulator/beam/beam_file.c (parse_record_chunk), OTP-29.1.1: the records'
    /// definitions are literals appended after the literal chunk.
    pub(crate) fn new(beam: &'a BeamFile) -> Option<Self> {
        let mut literals = Self {
            beam,
            heap: VecHeap::new_literal(),
            owned: vec![None; beam.literals.len()],
            terms: vec![None; beam.literals.len()],
            extra: Vec::new(),
            extra_terms: Vec::new(),
            record_defs: Vec::new(),
        };
        for index in 0..beam.records.len() {
            // `def_literal` is the index `beamfile_add_literal` returned.
            let literal = literals.add(NewLiteral::Record {
                index: index as u32,
            });
            literals.record_defs.push(literal);
        }
        Some(literals)
    }

    /// The number of literals: `beam.literals.count`.
    pub(crate) fn len(&self) -> usize {
        self.terms.len() + self.extra.len()
    }

    /// `beamfile_get_literal` as a structure: the heap-independent value of a file literal.
    /// `None` for the literals the loader added: none of them is a float, a map or a list of
    /// flags.
    pub(crate) fn owned(&mut self, index: u64) -> Option<&OwnedTerm> {
        let slot = self.owned.get_mut(index as usize)?;
        if slot.is_none() {
            *slot = Some(self.beam.literal(index as u32).ok()?);
        }
        slot.as_ref()
    }

    /// `beamfile_get_literal`.
    pub(crate) fn term(&mut self, index: u64) -> Option<Term> {
        let index = index as usize;
        if index < self.terms.len() {
            if let Some(term) = self.terms[index] {
                return Some(term);
            }
            self.owned(index as u64)?;
            let value = self.owned[index].as_ref()?;
            let term = from_owned(value, &mut self.heap).ok()?;
            self.terms[index] = Some(term);
            return Some(term);
        }
        let at = index - self.terms.len();
        if let Some(Some(term)) = self.extra_terms.get(at) {
            return Some(*term);
        }
        let term = match self.extra.get(at)? {
            NewLiteral::Bignum(text) => {
                let value = OwnedTerm::BigInt(text.parse::<BigInt>().ok()?);
                from_owned(&value, &mut self.heap).ok()?
            }
            _ => return None,
        };
        self.extra_terms[at] = Some(term);
        Some(term)
    }

    /// `beamfile_add_literal`: the index of the new literal.
    pub(crate) fn add(&mut self, literal: NewLiteral) -> u64 {
        self.extra.push(literal);
        self.extra_terms.push(None);
        (self.terms.len() + self.extra.len() - 1) as u64
    }
}

/// `LoaderState`.
pub(crate) struct LoaderState<'a> {
    /// `genop`: the head of the generic instruction chain.
    pub genop: Option<OpId>,
    /// `op_allocator`.
    pub ops: BeamOpAllocator,
    /// `beam`.
    pub beam: &'a BeamFile,
    /// `beam.imports`.
    pub imports: Vec<ImportEntry>,
    /// `bif_imports`: the `bif_table` index of an imported BIF.
    pub bif_imports: Vec<Option<u16>>,
    /// `labels`.
    pub labels: Vec<Label>,
    /// `lambda_literals`.
    pub lambda_literals: Vec<Option<u64>>,
    /// `beam.literals` and what generators add.
    pub literals: Literals<'a>,
    /// `may_load_nif`.
    pub may_load_nif: bool,
    /// `load_hdr->are_nifs`.
    pub are_nifs: Option<Vec<bool>>,
    /// `function_number`.
    pub function_number: usize,
    /// `load_hdr->debugger_flags`.
    pub debugger_flags: u64,
    /// `beam.atoms`: the global atom of each atom table entry.
    pub atoms: Vec<Atom>,
}

/// `ERTS_DEBUGGER_ENABLED` and `ERTS_DEBUGGER_LINE_BREAKPOINTS` (erl_debugger.h).
const ERTS_DEBUGGER_ENABLED: u64 = 1;
const ERTS_DEBUGGER_LINE_BREAKPOINTS: u64 = 1 << 1;

impl<'a> LoaderState<'a> {
    /// Port of erts/emulator/beam/jit/asm_load.c (beam_load_prepare_emit, the label, lambda and
    /// `bif_imports` setup), OTP-29.1.1. `None` when a lambda label is defined twice (erts
    /// reports a load error) or a literal cannot be built.
    pub(crate) fn new(
        beam: &'a BeamFile,
        ops: BeamOpAllocator,
        are_nifs: Option<Vec<bool>>,
        debugger_flags: u64,
    ) -> Option<Self> {
        let atoms: Vec<Atom> = beam
            .resolved_atoms(|name| global_atoms().intern(name).map(|atom| atom.0))
            .ok()?
            .iter()
            .map(|&index| Atom(index))
            .collect();
        let literals = Literals::new(beam)?;
        let mut labels = vec![
            Label {
                defined: false,
                looprec_targeted: false,
                lambda_index: None,
            };
            beam.code.label_count as usize
        ];
        let mut lambda_literals = Vec::with_capacity(beam.lambdas.len());
        for (index, lambda) in beam.lambdas.iter().enumerate() {
            let label = labels.get_mut(lambda.label as usize)?;
            if label.lambda_index.is_some() {
                return None;
            }
            label.lambda_index = Some(index);
            lambda_literals.push(None);
        }
        let mut may_load_nif = false;
        let mut imports = Vec::with_capacity(beam.imports.len());
        let mut bif_imports = Vec::with_capacity(beam.imports.len());
        for import in &beam.imports {
            let module = beam
                .atoms
                .get(import.module_atom.checked_sub(1)? as usize)?;
            let function = beam
                .atoms
                .get(import.function_atom.checked_sub(1)? as usize)?;
            imports.push(ImportEntry {
                module: u64::from(atoms[import.module_atom as usize - 1].0),
                function: u64::from(atoms[import.function_atom as usize - 1].0),
                arity: import.arity,
            });
            let bif = u8::try_from(import.arity)
                .ok()
                .and_then(|arity| arinsal_spec::bif_lookup(module, function, arity));
            if let Some(bif) = bif
                && bif.module == "erlang"
                && bif.name == "load_nif"
                && bif.arity == 2
            {
                may_load_nif = true;
            }
            bif_imports.push(bif.map(|bif| bif.index));
        }
        Some(Self {
            genop: None,
            ops,
            beam,
            imports,
            bif_imports,
            labels,
            lambda_literals,
            literals,
            may_load_nif,
            are_nifs,
            function_number: 0,
            debugger_flags,
            atoms,
        })
    }

    /// `ERTS_DEBUGGER_IS_ENABLED_IN(load_hdr->debugger_flags, ERTS_DEBUGGER_LINE_BREAKPOINTS)`.
    pub(crate) fn line_breakpoints_enabled(&self) -> bool {
        let wanted = ERTS_DEBUGGER_LINE_BREAKPOINTS | ERTS_DEBUGGER_ENABLED;
        self.debugger_flags & wanted == wanted
    }

    /// `beam_load_get_term`: the term of a literal-like operand, `None` for a non-value.
    pub(crate) fn get_term(&mut self, key: BeamOpArg) -> Option<Term> {
        match key.ty {
            TAG_A => Some(Term::atom(Atom(key.val as u32))),
            TAG_I => Term::small(key.val as i64),
            TAG_N => Some(Term::NIL),
            TAG_Q => self.literals.term(key.val),
            _ => None,
        }
    }

    /// `new_op` with `next = NULL`, as the generators write it.
    pub(crate) fn new_op(&mut self, op: i32, arity: usize) -> OpId {
        let id = self.ops.new_op();
        let o = self.ops.op_mut(id);
        o.next = None;
        o.op = op;
        o.arity = arity;
        id
    }
}

/// The index of an atom of `atom.names` or the `bif.tab` atoms, as the `am_*` constants of erts.
pub(crate) const fn am(name: &str) -> u64 {
    let wanted = name.as_bytes();
    let table = arinsal_term::atoms::PREDEFINED;
    let mut index = 0;
    while index < table.len() {
        let candidate = table[index].as_bytes();
        if candidate.len() == wanted.len() {
            let mut at = 0;
            while at < wanted.len() && candidate[at] == wanted[at] {
                at += 1;
            }
            if at == wanted.len() {
                return index as u64;
            }
        }
        index += 1;
    }
    panic!("atom is not predefined")
}

/// `BIF_<id>` of erts: the index of the BIF named `id` (`<name>_<arity>`, or the explicit name
/// of `bif.tab`) in `bif_table`.
pub(crate) const fn bif_id(id: &str) -> u16 {
    let wanted = id.as_bytes();
    let table = &arinsal_spec::BIFS;
    let mut index = 0;
    while index < table.len() {
        let bif = &table[index];
        let matches = match bif.c_name {
            Some(c_name) => bytes_eq(c_name.as_bytes(), wanted),
            None => name_arity_eq(bif.name.as_bytes(), bif.arity, wanted),
        };
        if matches {
            return bif.index;
        }
        index += 1;
    }
    panic!("unknown BIF id")
}

const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut at = 0;
    while at < a.len() {
        if a[at] != b[at] {
            return false;
        }
        at += 1;
    }
    true
}

/// Whether `id` is `<name>_<arity>`.
const fn name_arity_eq(name: &[u8], arity: u8, id: &[u8]) -> bool {
    let digits = if arity >= 100 {
        3
    } else if arity >= 10 {
        2
    } else {
        1
    };
    if id.len() != name.len() + 1 + digits || id[name.len()] != b'_' {
        return false;
    }
    let mut at = 0;
    while at < name.len() {
        if id[at] != name[at] {
            return false;
        }
        at += 1;
    }
    let mut rest = arity;
    let mut position = id.len();
    let mut written = 0;
    while written < digits {
        position -= 1;
        if id[position] != b'0' + rest % 10 {
            return false;
        }
        rest /= 10;
        written += 1;
    }
    true
}

use crate::transform_helpers::{generators, predicates};

include!(concat!(env!("OUT_DIR"), "/erts_transform_engine.rs"));

/// `erts_transform_engine`.
pub(crate) fn erts_transform_engine(st: &mut LoaderState) -> TeResult {
    erts_transform_engine_body(st)
}

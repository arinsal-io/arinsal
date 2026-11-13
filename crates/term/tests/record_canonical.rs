//! Canonical native record definitions: `erts_record_put` and `erts_canonical_record_def`.

use arinsal_term::{
    Atom, LiteralArea, ProcessHeap, Term, TermBuilder, delete_module_record_definitions,
    global_atoms, put_record_definition,
};

fn atom(name: &str) -> Atom {
    global_atoms().intern(name).unwrap()
}

fn definition_of(record: Term) -> u64 {
    record.record_snapshot().unwrap().definition.tagged_word()
}

/// Register the definition of `module:name` with the given fields.
fn register(
    area: &mut LiteralArea,
    module: Atom,
    name: Atom,
    exported: bool,
    fields: &[Atom],
) -> u64 {
    let fields: Vec<(Atom, Option<Term>)> = fields.iter().map(|field| (*field, None)).collect();
    let cons = area
        .builder()
        .native_record_literal(module, name, exported, &fields)
        .unwrap();
    // The definition tuple is the head of the literal; read it back through a record built
    // from the same layout while no definition is registered.
    let values: Vec<(Atom, Term)> = fields
        .iter()
        .map(|(field, _)| (*field, Term::NIL))
        .collect();
    let definition = area
        .builder()
        .native_record(module, name, exported, &values)
        .unwrap()
        .record_snapshot()
        .unwrap()
        .definition;
    put_record_definition(module, name, cons, definition);
    definition.tagged_word()
}

#[test]
fn records_reuse_the_registered_definition() {
    arinsal_term::init_global_literals();
    let (module, name) = (atom("canon_mod"), atom("point"));
    let (x, y) = (atom("canon_x"), atom("canon_y"));
    let mut area = LiteralArea::new();
    let registered = register(&mut area, module, name, true, &[x, y]);
    let mut heap = ProcessHeap::with_words(256);

    let one = TermBuilder::new(&mut heap)
        .native_record(
            module,
            name,
            true,
            &[(x, Term::small(1).unwrap()), (y, Term::small(2).unwrap())],
        )
        .unwrap();
    let two = TermBuilder::new(&mut heap)
        .native_record(
            module,
            name,
            true,
            &[(x, Term::small(3).unwrap()), (y, Term::small(4).unwrap())],
        )
        .unwrap();
    assert_eq!(definition_of(one), registered);
    assert_eq!(definition_of(two), registered);

    // A different field order, visibility or key set is not the registered definition.
    let reordered = TermBuilder::new(&mut heap)
        .native_record(module, name, true, &[(y, Term::NIL), (x, Term::NIL)])
        .unwrap();
    let private = TermBuilder::new(&mut heap)
        .native_record(module, name, false, &[(x, Term::NIL), (y, Term::NIL)])
        .unwrap();
    let other = TermBuilder::new(&mut heap)
        .native_record(module, name, true, &[(x, Term::NIL)])
        .unwrap();
    for record in [reordered, private, other] {
        assert_ne!(definition_of(record), registered);
    }

    // A deleted module has no canonical definition.
    delete_module_record_definitions(module);
    let deleted = TermBuilder::new(&mut heap)
        .native_record(module, name, true, &[(x, Term::NIL), (y, Term::NIL)])
        .unwrap();
    assert_ne!(definition_of(deleted), registered);
}

//! `AtomTable::intern_all` gives the atoms `intern` gives, and puts the new ones in order.

use arinsal_term::AtomTable;

#[test]
fn intern_all_matches_intern_and_keeps_the_order_of_new_atoms() {
    let table = AtomTable::new(1 << 16);
    let before = table.intern("already_there").unwrap();
    let names = [
        "new_one",
        "already_there",
        "new_two",
        "new_one",
        "h\u{e9}llo",
        "new_three",
    ];
    let atoms = table.intern_all(names.iter().copied()).unwrap();
    assert_eq!(atoms.len(), names.len());
    assert_eq!(atoms[1], before);
    assert_eq!(atoms[0], atoms[3]);
    for (atom, name) in atoms.iter().zip(names) {
        assert_eq!(table.intern(name).unwrap(), *atom, "{name}");
        assert_eq!(table.text(*atom), Some(name));
    }
    // New atoms get consecutive indexes in the order of first appearance.
    assert_eq!(atoms[2].0, atoms[0].0 + 1);
    assert_eq!(atoms[4].0, atoms[0].0 + 2);
    assert_eq!(atoms[5].0, atoms[0].0 + 3);
}

#[test]
fn intern_all_reports_the_name_the_table_refuses() {
    let table = AtomTable::new(1 << 16);
    let too_long = "a".repeat(300);
    let names = ["fine", too_long.as_str(), "after"];
    let error = table.intern_all(names.iter().copied()).unwrap_err();
    assert_eq!(error.0, 1);
}

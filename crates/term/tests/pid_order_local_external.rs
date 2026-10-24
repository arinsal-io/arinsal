//! A local pid compares as a pid of `erts_this_node` against external pids: serial, number,
//! then node name, then creation (utils.c erts_cmp_compound, pid_common).

use arinsal_term::{Node, ProcessHeap, Term, TermBuilder, cmp, global_atoms, set_this_node};
use std::cmp::Ordering;

#[test]
fn local_pid_orders_against_external_pids_by_node_name() {
    let this = global_atoms().intern("pidorder_m@localhost").unwrap();
    set_this_node(this, 4);
    let before = Node::new(global_atoms().intern("pidorder_a@localhost").unwrap(), 7);
    let after = Node::new(global_atoms().intern("pidorder_z@localhost").unwrap(), 7);
    let same_name = Node::new(this, 9);
    let mut heap = ProcessHeap::with_words(1024);
    let local = Term::pid(60, 0).unwrap();
    let mut builder = TermBuilder::new(&mut heap);
    let a = builder.external_pid(before, 60, 0).unwrap();
    let z = builder.external_pid(after, 60, 0).unwrap();
    let later_creation = builder.external_pid(same_name, 60, 0).unwrap();
    // Same serial and number, so the node name decides.
    assert_eq!(cmp(a, local), Ordering::Less);
    assert_eq!(cmp(local, a), Ordering::Greater);
    assert_eq!(cmp(local, z), Ordering::Less);
    assert_eq!(cmp(z, local), Ordering::Greater);
    // Same name: the creation decides.
    assert_eq!(cmp(local, later_creation), Ordering::Less);
    // The number is compared before the node.
    assert_eq!(cmp(Term::pid(59, 0).unwrap(), z), Ordering::Less);
}

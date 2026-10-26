use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, VecHeap, from_owned, to_owned};
use arinsal_vm::Vm;

fn term(value: &OwnedTerm, heap: &mut VecHeap) -> Term {
    from_owned(value, heap).expect("test term")
}

#[test]
fn prim_file_local_nif_entry_reads_existing_file() {
    let path = std::env::temp_dir().join(format!("arinsal-nif-{}.bin", std::process::id()));
    let bytes = b"local NIF entry";
    std::fs::write(&path, bytes).unwrap();
    let path_term = OwnedTerm::charlist(path.to_string_lossy().as_ref());
    let mut heap = VecHeap::new();
    let mut vm = Vm::new([]);
    let result = vm
        .eval_exported("prim_file", "read_file", &[term(&path_term, &mut heap)])
        .expect("prim_file:read_file/1");
    assert_eq!(
        to_owned(result.term).unwrap(),
        OwnedTerm::Tuple(vec![
            OwnedTerm::Atom("ok".into()),
            OwnedTerm::Binary(bytes.to_vec())
        ])
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn prim_file_missing_file_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping prim_file differential test");
        return;
    };
    let path = std::env::temp_dir().join(format!("arinsal-no-file-{}.bin", std::process::id()));
    let path_term = OwnedTerm::charlist(path.to_string_lossy().as_ref());
    let expected = reference.call("prim_file", "read_file", std::slice::from_ref(&path_term));
    let mut heap = VecHeap::new();
    let mut vm = Vm::new([]);
    let actual = vm
        .eval_exported("prim_file", "read_file", &[term(&path_term, &mut heap)])
        .expect("prim_file:read_file/1");
    let arinsal_difftest::CallResult::Ok(expected) = expected else {
        panic!("reference prim_file:read_file/1 failed: {expected:?}");
    };
    assert_eq!(to_owned(actual.term).unwrap(), expected);
}

#[test]
fn iolist_to_iovec_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping iolist_to_iovec differential test");
        return;
    };
    let inputs = [
        OwnedTerm::Binary(vec![1, 2]),
        OwnedTerm::list(vec![
            OwnedTerm::Int(1),
            OwnedTerm::Int(2),
            OwnedTerm::Binary(vec![3]),
        ]),
        OwnedTerm::Nil,
    ];
    let mut vm = Vm::new([]);
    for input in inputs {
        let expected = reference.call("erlang", "iolist_to_iovec", std::slice::from_ref(&input));
        let mut heap = VecHeap::new();
        let actual = vm
            .eval_exported("erlang", "iolist_to_iovec", &[term(&input, &mut heap)])
            .expect("iolist_to_iovec/1");
        let arinsal_difftest::CallResult::Ok(expected) = expected else {
            panic!("reference iolist_to_iovec/1 failed: {expected:?}");
        };
        assert_eq!(to_owned(actual.term).unwrap(), expected);
    }
}

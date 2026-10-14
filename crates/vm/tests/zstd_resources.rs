//! Resources made by the built-in `zstd` NIF library are released with the process that holds
//! them: the registry of magic references keeps no entry once the last reference is gone.

use arinsal_etf::OwnedTerm;
use arinsal_term::{MagicRef, to_owned};
use arinsal_vm::Vm;

fn resource_id(term: &OwnedTerm) -> u64 {
    let OwnedTerm::Ref { ids, .. } = term else {
        panic!("a zstd context is a reference: {term:?}")
    };
    assert_eq!(ids[2], u32::MAX, "a magic reference");
    u64::from(ids[0]) | (u64::from(ids[1]) << 32)
}

#[test]
fn zstd_contexts_leave_the_magic_registry_when_their_process_is_gone() {
    let mut vm = Vm::new([]);
    let mut ids = Vec::new();
    for _ in 0..5_000 {
        let name = if ids.len() % 2 == 0 {
            "init_compress_nif"
        } else {
            "init_decompress_nif"
        };
        let result = vm.eval("zstd", name, &[]).expect("zstd context");
        let id = resource_id(&to_owned(result.term).expect("owned reference"));
        assert!(MagicRef::is_registered(id), "alive with its process");
        ids.push(id);
    }
    let leaked = ids
        .iter()
        .filter(|id| MagicRef::is_registered(**id))
        .count();
    assert_eq!(
        leaked, 0,
        "registry entries kept after their resources died"
    );
}

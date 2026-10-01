use arinsal_beamasm::{
    ProcessHeader,
    module::{ArgVal, BeamModuleAssembler},
};

fn catch_module(labels: [u32; 2]) -> arinsal_beamasm::module::FinalizedModule {
    let mut assembler = BeamModuleAssembler::new();
    assembler.emit_i_func_label(labels[0]).unwrap();
    assembler.allocate_zero(2, 0).unwrap();
    assembler.emit_catch(ArgVal::Y(0), labels[1]).unwrap();
    assembler.emit_try_end(ArgVal::Y(0)).unwrap();
    assembler.deallocate_return(2).unwrap();
    assembler.emit_i_func_label(labels[1]).unwrap();
    assembler.deallocate_return(2).unwrap();
    assembler.finalize().unwrap()
}

#[test]
fn modules_reserve_unique_global_catch_tags() {
    let first = catch_module([1, 2]);
    let second = catch_module([3, 4]);

    assert_eq!(first.catch_table.len(), 1);
    assert_eq!(second.catch_table.len(), 1);
    assert_ne!(first.catch_base, second.catch_base);
    assert_eq!(
        arinsal_beamasm::catch::make_catch(first.catch_base),
        (u64::from(first.catch_base) << 6) | 0x1b
    );
}

#[test]
fn process_header_tracks_active_catch_count() {
    let module = catch_module([10, 11]);
    let header = ProcessHeader::default();
    assert_eq!(header.catches, 0);
    assert_eq!(module.catch_table.len(), 1);
}

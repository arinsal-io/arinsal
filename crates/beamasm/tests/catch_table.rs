#![cfg(target_arch = "aarch64")]

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
fn module_lists_its_catches_for_the_loader() {
    let module = catch_module([1, 2]);
    // The loader numbers each catch with `beam_catches_cons` and patches the tag.
    assert_eq!(module.catches.len(), 1);
    let handler = module.entries[&2];
    assert_eq!(module.catches[0].handler, handler);
}

#[test]
fn process_header_tracks_active_catch_count() {
    let module = catch_module([10, 11]);
    let header = ProcessHeader::default();
    assert_eq!(header.catches, 0);
    assert_eq!(module.catches.len(), 1);
}

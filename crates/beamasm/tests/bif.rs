#![cfg(target_arch = "aarch64")]

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    bif::ExportEntry,
    enter_native,
    module::{BeamModuleAssembler, FinalizedModule},
};

fn tagged(value: u64) -> u64 {
    (value << 4) | 15
}

#[cfg(target_arch = "aarch64")]
fn execute(
    module: &FinalizedModule,
    label: u32,
    mut header: ProcessHeader,
    values: [u64; 3],
) -> (u64, u64, u64) {
    let mut registers = SchedulerRegisters::default();
    arinsal_beamasm::rt::set_fixture_words(&mut registers.x_reg_array[..3], &values);
    let mut stack = [0u64; 64];
    header.stop = stack.as_mut_ptr().wrapping_add(stack.len());
    if header.fcalls == 0 {
        header.fcalls = 100;
    }
    let outcome = enter_native(&mut header, &mut registers, &module.entry(label).unwrap());
    assert_eq!(outcome, ExitReason::Returned);
    (
        registers.x_reg_array[0].tagged_word(),
        header.stop as usize as u64,
        header.exc.freason,
    )
}

#[cfg(target_arch = "aarch64")]
fn module_with_export(export: &'static ExportEntry, value: u64, tail_kind: u8) -> FinalizedModule {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    if tail_kind != 0 {
        asm.call(4).unwrap();
        asm.return_().unwrap();
        asm.emit_i_func_label(4).unwrap();
        asm.emit_enter_frame().unwrap();
    }
    match tail_kind {
        0 => asm.emit_i_call_ext(export).unwrap(),
        1 => asm.emit_i_call_ext_only(export).unwrap(),
        _ => asm.emit_i_call_ext_last(export, 0).unwrap(),
    }
    if tail_kind == 0 {
        asm.return_().unwrap();
    }
    asm.emit_i_func_label(2).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_raw(|e| e.mov_const(Gpr::x(25), value)).unwrap();
    asm.return_().unwrap();
    asm.emit_i_func_label(3).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.emit_raw(|e| e.mov_const(Gpr::x(25), tagged((value >> 4) + 1)))
        .unwrap();
    asm.return_().unwrap();
    asm.finalize().unwrap()
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_call_ext() {
    let export = Box::leak(Box::new(ExportEntry::with_addresses(
        arinsal_term::atoms::ERLANG,
        arinsal_term::atoms::ERLANG,
        0,
        0,
        0,
    )));
    let module = module_with_export(export, tagged(31), 0);
    export.set_address(0, module.entries[&2] as usize);
    assert_eq!(
        execute(&module, 1, ProcessHeader::default(), [0; 3]).0,
        tagged(31)
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_call_ext_last() {
    let export = Box::leak(Box::new(ExportEntry::with_addresses(
        arinsal_term::atoms::ERLANG,
        arinsal_term::atoms::ERLANG,
        0,
        0,
        0,
    )));
    let module = module_with_export(export, tagged(32), 2);
    export.set_address(0, module.entries[&2] as usize);
    execute(&module, 1, ProcessHeader::default(), [0; 3]);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_call_ext_only() {
    let export = Box::leak(Box::new(ExportEntry::with_addresses(
        arinsal_term::atoms::ERLANG,
        arinsal_term::atoms::ERLANG,
        0,
        0,
        0,
    )));
    let module = module_with_export(export, tagged(33), 1);
    export.set_address(0, module.entries[&2] as usize);
    execute(&module, 1, ProcessHeader::default(), [0; 3]);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn export_entry_repoints_between_calls() {
    let export = Box::leak(Box::new(ExportEntry::with_addresses(
        arinsal_term::atoms::ERLANG,
        arinsal_term::atoms::ERLANG,
        0,
        0,
        0,
    )));
    let module = module_with_export(export, tagged(41), 0);
    export.set_address(0, module.entries[&2] as usize);
    assert_eq!(
        execute(&module, 1, ProcessHeader::default(), [0; 3]).0,
        tagged(41)
    );
    export.set_address(0, module.entries[&3] as usize);
    assert_eq!(
        execute(&module, 1, ProcessHeader::default(), [0; 3]).0,
        tagged(42)
    );
}

#[cfg(not(target_arch = "aarch64"))]
#[test]
fn native_ops_require_aarch64() {
    let _: Option<ApplyResolver> = None;
}

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, Update, emit_enter_runtime, emit_leave_runtime,
    enter_native, module::BeamModuleAssembler,
};

#[test]
fn runtime_sync_emitters_encode_process_and_register_pairs() {
    let mut code = arinsal_a64::buf::CodeBuffer::new();
    let update = Update::HEAP_ALLOC
        .union(Update::REDUCTIONS)
        .union(Update::X_REGS);
    emit_enter_runtime(&mut code, 6, update).unwrap();
    emit_leave_runtime(&mut code, 6, update).unwrap();
    let (words, _) = code.finish_with_labels().unwrap();
    assert_eq!(words.len(), 10);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn finalized_entry_runs_through_native_abi() {
    let mut assembler = BeamModuleAssembler::new();
    assembler.emit_i_func_label(1).unwrap();
    assembler
        .emit_raw(|emitter| {
            emitter.mov_reg(Gpr::x(0), Gpr::xzr())?;
            emitter.ret(Gpr::x(30))
        })
        .unwrap();
    let module = assembler.finalize().unwrap();
    let entry = module.entry(1).unwrap();
    let mut header = ProcessHeader {
        fcalls: 8,
        ..ProcessHeader::default()
    };
    let mut registers = SchedulerRegisters::default();
    assert_eq!(
        enter_native(&mut header, &mut registers, &entry),
        ExitReason::Returned
    );
}

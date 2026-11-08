use similar_asserts::assert_eq;

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    module::{ArgVal, BeamModuleAssembler},
    rt,
};

#[test]
fn native_get_tuple_element_handles_offset_past_ldr_range() {
    let mut tuple = vec![0u64; 4097].into_boxed_slice();
    tuple[0] = (4096 << 6) | 2;
    let value = (0x1234_5678 << 4) | 0xf;
    tuple[4096] = value;

    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_raw(|e| e.mov_reg(Gpr::x(24), Gpr::x(30))).unwrap();
    asm.emit_i_get_tuple_element2(ArgVal::X(0), 4096 * 8, ArgVal::X(1))
        .unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(30), Gpr::x(24))?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();

    let mut heap = [0u64; 32];
    let heap_ptr = heap.as_mut_ptr();
    let mut header = ProcessHeader {
        htop: heap_ptr,
        stop: heap_ptr.wrapping_add(heap.len()),
        heap: heap_ptr,
        hend: heap_ptr.wrapping_add(heap.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = rt::fixture_term(tuple.as_mut_ptr() as u64);

    let result = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());

    assert_eq!(result, ExitReason::Returned);
    assert_eq!(regs.x_reg_array[1].tagged_word(), value);
}

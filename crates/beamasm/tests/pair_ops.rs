#![cfg(target_arch = "aarch64")]

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    module::{ArgVal, BeamModuleAssembler},
    rt,
};
use std::cell::Cell;

fn fixture(value: u64) -> u64 {
    value
}

fn run(
    emit: impl FnOnce(&mut BeamModuleAssembler),
    setup: impl FnOnce(&mut [u64; 64], &mut SchedulerRegisters),
) -> ([u64; 1024], [u64; 64], *const u64) {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_raw(|e| e.mov_reg(Gpr::x(24), Gpr::x(30))).unwrap();
    emit(&mut asm);
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(30), Gpr::x(24))?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut area = [0u64; 64];
    let mut regs = SchedulerRegisters::default();
    setup(&mut area, &mut regs);
    let base = area.as_mut_ptr();
    let mut header = ProcessHeader {
        htop: base,
        stop: base.wrapping_add(32),
        heap: base,
        hend: base.wrapping_add(16),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let result = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());
    assert_eq!(result, ExitReason::Returned);
    (
        rt::fixture_words(&regs.x_reg_array).try_into().unwrap(),
        area,
        header.stop,
    )
}

fn emitted_bytes(
    asm: &mut BeamModuleAssembler,
    emit: impl FnOnce(&mut BeamModuleAssembler),
) -> usize {
    let before = asm.code_offset();
    emit(asm);
    asm.code_offset() - before
}

#[test]
fn load_two_xregs_is_one_ldp_for_register_backed_destinations() {
    let size = Cell::new(0);
    let (regs, _, _) = run(
        |m| {
            m.move_(ArgVal::X(0), ArgVal::Y(0)).unwrap();
            m.move_(ArgVal::X(1), ArgVal::Y(1)).unwrap();
            size.set(emitted_bytes(m, |m| {
                m.emit_load_two_xregs(ArgVal::Y(0), ArgVal::X(2), ArgVal::Y(1), ArgVal::X(3))
                    .unwrap();
            }));
            m.move_(ArgVal::XMemory(6), ArgVal::Y(2)).unwrap();
        },
        |_, regs| {
            regs.x_reg_array[0] = rt::fixture_term(fixture(0x11));
            regs.x_reg_array[1] = rt::fixture_term(fixture(0x22));
        },
    );
    assert_eq!(size.get(), 4);
    assert_eq!((regs[2], regs[3]), (0x11, 0x22));
}

#[test]
fn load_two_xregs_into_memory_destinations_stores_one_pair() {
    let size = Cell::new(0);
    let (regs, _, _) = run(
        |m| {
            m.move_(ArgVal::X(0), ArgVal::Y(0)).unwrap();
            m.move_(ArgVal::X(1), ArgVal::Y(1)).unwrap();
            size.set(emitted_bytes(m, |m| {
                m.emit_load_two_xregs(
                    ArgVal::Y(0),
                    ArgVal::XMemory(6),
                    ArgVal::Y(1),
                    ArgVal::XMemory(7),
                )
                .unwrap();
            }));
        },
        |_, regs| {
            regs.x_reg_array[0] = rt::fixture_term(fixture(0x31));
            regs.x_reg_array[1] = rt::fixture_term(fixture(0x32));
        },
    );
    assert_eq!(size.get(), 8);
    assert_eq!((regs[6], regs[7]), (0x31, 0x32));
}

#[test]
fn swap_of_register_backed_xregs_takes_three_moves() {
    let size = Cell::new(0);
    let (regs, _, _) = run(
        |m| {
            size.set(emitted_bytes(m, |m| {
                m.swap(ArgVal::X(0), ArgVal::X(1)).unwrap();
            }));
        },
        |_, regs| {
            regs.x_reg_array[0] = rt::fixture_term(fixture(0x41));
            regs.x_reg_array[1] = rt::fixture_term(fixture(0x42));
        },
    );
    assert_eq!(size.get(), 12);
    assert_eq!((regs[0], regs[1]), (0x42, 0x41));
}

#[test]
fn swap_of_a_y_register_and_an_xreg_takes_a_load_a_store_and_a_move() {
    let size = Cell::new(0);
    let (regs, _, _) = run(
        |m| {
            m.move_(ArgVal::X(1), ArgVal::Y(0)).unwrap();
            size.set(emitted_bytes(m, |m| {
                m.swap(ArgVal::Y(0), ArgVal::X(0)).unwrap();
            }));
            m.move_(ArgVal::Y(0), ArgVal::X(2)).unwrap();
        },
        |_, regs| {
            regs.x_reg_array[0] = rt::fixture_term(fixture(0x51));
            regs.x_reg_array[1] = rt::fixture_term(fixture(0x52));
        },
    );
    assert_eq!(size.get(), 12);
    assert_eq!((regs[0], regs[2]), (0x52, 0x51));
}

#[test]
fn swap_of_adjacent_y_registers_is_one_ldp_and_one_stp() {
    let size = Cell::new(0);
    let (regs, _, _) = run(
        |m| {
            m.move_(ArgVal::X(0), ArgVal::Y(0)).unwrap();
            m.move_(ArgVal::X(1), ArgVal::Y(1)).unwrap();
            size.set(emitted_bytes(m, |m| {
                m.swap(ArgVal::Y(1), ArgVal::Y(0)).unwrap();
            }));
            m.move_(ArgVal::Y(0), ArgVal::X(2)).unwrap();
            m.move_(ArgVal::Y(1), ArgVal::X(3)).unwrap();
        },
        |_, regs| {
            regs.x_reg_array[0] = rt::fixture_term(fixture(0x61));
            regs.x_reg_array[1] = rt::fixture_term(fixture(0x62));
        },
    );
    assert_eq!(size.get(), 8);
    assert_eq!((regs[2], regs[3]), (0x62, 0x61));
}

#[test]
fn get_two_tuple_elements_is_one_ldp_from_the_tuple_pointer() {
    let size = Cell::new(0);
    let (regs, _, _) = run(
        |m| {
            m.emit_load_tuple_ptr(ArgVal::X(0), ArgVal::X(0)).unwrap();
            size.set(emitted_bytes(m, |m| {
                m.emit_get_two_tuple_elements(ArgVal::X(0), 8, ArgVal::X(1), ArgVal::X(2))
                    .unwrap();
            }));
            m.emit_get_two_tuple_elements(ArgVal::X(0), 8, ArgVal::XMemory(6), ArgVal::XMemory(7))
                .unwrap();
        },
        |area, regs| {
            area[..3].copy_from_slice(&[2 << 6, 0x71, 0x72]);
            regs.x_reg_array[0] = rt::fixture_term(area.as_ptr() as u64 | 2);
        },
    );
    assert_eq!(size.get(), 4);
    assert_eq!((regs[1], regs[2]), (0x71, 0x72));
    assert_eq!((regs[6], regs[7]), (0x71, 0x72));
}

#[test]
fn get_tuple_element_swap_is_a_move_and_a_load() {
    let size = Cell::new(0);
    let (regs, _, _) = run(
        |m| {
            m.emit_load_tuple_ptr(ArgVal::X(0), ArgVal::X(0)).unwrap();
            size.set(emitted_bytes(m, |m| {
                m.emit_get_tuple_element_swap(ArgVal::X(0), 16, ArgVal::X(1), ArgVal::X(2))
                    .unwrap();
            }));
        },
        |area, regs| {
            area[..3].copy_from_slice(&[2 << 6, 0x81, 0x82]);
            regs.x_reg_array[0] = rt::fixture_term(area.as_ptr() as u64 | 2);
            regs.x_reg_array[2] = rt::fixture_term(fixture(0x83));
        },
    );
    assert_eq!(size.get(), 8);
    assert_eq!((regs[1], regs[2]), (0x83, 0x82));
}

fn tail_call_through_frame(deallocate: u32, src_index: u32, expected_bytes: usize) {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    asm.allocate(deallocate, 0).unwrap();
    asm.move_(ArgVal::X(0), ArgVal::Y(src_index)).unwrap();
    let before = asm.code_offset();
    asm.move_call_last(ArgVal::Y(src_index), ArgVal::X(1), 2, deallocate)
        .unwrap();
    assert_eq!(asm.code_offset() - before, expected_bytes);
    asm.emit_i_func_label(2).unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut stack = [0u64; 64];
    let stack_end = stack.as_mut_ptr().wrapping_add(stack.len());
    let mut header = ProcessHeader {
        stop: stack_end,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = rt::fixture_term(fixture(0x91));
    let result = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());
    assert_eq!(result, ExitReason::Returned);
    assert_eq!(rt::fixture_words(&regs.x_reg_array)[1], 0x91);
    assert_eq!(header.stop, stack_end);
}

#[test]
fn move_call_last_pairs_the_last_y_slot_with_the_continuation() {
    tail_call_through_frame(1, 0, 8);
    tail_call_through_frame(3, 2, 12);
    tail_call_through_frame(4, 3, 12);
}

#[test]
fn move_call_last_from_y0_loads_with_post_index() {
    tail_call_through_frame(5, 0, 12);
}

#[test]
fn move_call_last_in_the_general_case_moves_then_deallocates() {
    tail_call_through_frame(4, 1, 16);
}

#[test]
fn move_trim_from_y0_is_one_post_index_load() {
    let size = Cell::new(0);
    let (regs, _, _) = run(
        |m| {
            m.move_(ArgVal::X(0), ArgVal::Y(0)).unwrap();
            m.move_(ArgVal::X(1), ArgVal::Y(1)).unwrap();
            size.set(emitted_bytes(m, |m| {
                m.move_trim(ArgVal::Y(0), ArgVal::X(2), 1).unwrap();
            }));
            m.move_(ArgVal::Y(0), ArgVal::X(3)).unwrap();
        },
        |_, regs| {
            regs.x_reg_array[0] = rt::fixture_term(fixture(0x31));
            regs.x_reg_array[1] = rt::fixture_term(fixture(0x32));
        },
    );
    assert_eq!(size.get(), 4);
    assert_eq!((regs[2], regs[3]), (0x31, 0x32));
}

#[test]
fn move_two_trim_from_y0_is_one_post_index_pair_load() {
    let size = Cell::new(0);
    let (regs, _, _) = run(
        |m| {
            m.move_(ArgVal::X(0), ArgVal::Y(0)).unwrap();
            m.move_(ArgVal::X(1), ArgVal::Y(1)).unwrap();
            size.set(emitted_bytes(m, |m| {
                m.move_two_trim(0, ArgVal::X(2), 1, ArgVal::X(3), 2)
                    .unwrap();
            }));
        },
        |_, regs| {
            regs.x_reg_array[0] = rt::fixture_term(fixture(0x41));
            regs.x_reg_array[1] = rt::fixture_term(fixture(0x42));
        },
    );
    assert_eq!(size.get(), 4);
    assert_eq!((regs[2], regs[3]), (0x41, 0x42));
}

#[test]
fn move_trim_into_the_first_surviving_slot_is_one_pre_index_store() {
    let size = Cell::new(0);
    let (regs, _, _) = run(
        |m| {
            m.move_(ArgVal::X(0), ArgVal::Y(1)).unwrap();
            size.set(emitted_bytes(m, |m| {
                m.move_trim(ArgVal::X(1), ArgVal::Y(1), 1).unwrap();
            }));
            m.move_(ArgVal::Y(0), ArgVal::X(2)).unwrap();
        },
        |_, regs| {
            regs.x_reg_array[0] = rt::fixture_term(fixture(0x51));
            regs.x_reg_array[1] = rt::fixture_term(fixture(0x52));
        },
    );
    assert_eq!(size.get(), 4);
    assert_eq!(regs[2], 0x52);
}

#[test]
fn init_yregs_of_four_slots_is_one_vector_pair_store() {
    let size = Cell::new(0);
    let (_, area, _) = run(
        |m| {
            size.set(emitted_bytes(m, |m| {
                m.init_yregs(0, 4).unwrap();
            }));
        },
        |area, _| area[32..36].fill(0x77),
    );
    assert_eq!(size.get(), 8);
    assert_eq!(&area[32..36], &[u64::MAX; 4]);
}

#[test]
fn put_list_deallocate_reads_y0_with_a_post_index_load() {
    let size = Cell::new(0);
    let (_, area, _) = run(
        |m| {
            m.move_(ArgVal::X(0), ArgVal::Y(0)).unwrap();
            size.set(emitted_bytes(m, |m| {
                m.emit_put_list_deallocate(ArgVal::Y(0), ArgVal::X(1), ArgVal::X(2), 1)
                    .unwrap();
            }));
        },
        |_, regs| {
            regs.x_reg_array[0] = rt::fixture_term(fixture(0x61));
            regs.x_reg_array[1] = rt::fixture_term(fixture(0x62));
        },
    );
    assert_eq!(size.get(), 12);
    assert_eq!((area[0], area[1]), (0x61, 0x62));
}

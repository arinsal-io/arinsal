use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule, ModuleError},
};

const TARGETS: [u32; 16] = [
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];

fn tagged_small(n: i64) -> u64 {
    ((n as u64) << 4) | 0xf
}

fn run(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), ModuleError>,
    source: u64,
    tuple_arity: Option<u64>,
) -> u64 {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit(&mut asm).unwrap();
    for (index, label) in TARGETS.iter().copied().enumerate() {
        asm.emit_i_func_label(label).unwrap();
        asm.emit_raw(|e| e.mov_const(Gpr::x(25), index as u64 + 100))
            .unwrap();
        asm.emit_raw(|e| e.mov_reg(Gpr::x(0), Gpr::xzr())).unwrap();
        asm.emit_raw(|e| e.ret(Gpr::x(30))).unwrap();
    }
    asm.emit_i_func_label(99).unwrap();
    asm.emit_raw(|e| e.mov_const(Gpr::x(25), 999)).unwrap();
    asm.emit_raw(|e| e.mov_reg(Gpr::x(0), Gpr::xzr())).unwrap();
    asm.emit_raw(|e| e.ret(Gpr::x(30))).unwrap();
    let module: FinalizedModule = asm.finalize().unwrap();
    let mut heap = [0u64; 16];
    if let Some(arity) = tuple_arity {
        heap[0] = arity << 6;
    }
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        stop: heap.as_mut_ptr().wrapping_add(heap.len()),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = if tuple_arity.is_some() {
        arinsal_beamasm::rt::fixture_term(heap.as_ptr() as u64 | 2)
    } else {
        arinsal_beamasm::rt::fixture_term(source)
    };
    let reason = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());
    assert_eq!(reason, ExitReason::Returned);
    regs.x_reg_array[0].tagged_word()
}

fn dest(label_index: usize) -> ArgVal {
    ArgVal::Label(TARGETS[label_index])
}

#[test]
fn native_i_select_val_lins() {
    let args = [
        ArgVal::Immediate(0x3f),
        ArgVal::Immediate(0x5f),
        ArgVal::Immediate(0x8b), // atom `ok`
        dest(0),
        dest(1),
        dest(2),
    ];
    for (source, expected) in [(0x3f, 100), (0x5f, 101), (0x8b, 102)] {
        assert_eq!(
            run(
                |m| m.emit_i_select_val_lins(ArgVal::X(0), ArgVal::Label(99), 6, &args),
                source,
                None,
            ),
            expected
        );
    }
    assert_eq!(
        run(
            |m| m.emit_i_select_val_lins(ArgVal::X(0), ArgVal::Label(99), 6, &args),
            0x6f,
            None,
        ),
        999
    );
}

#[test]
fn native_i_select_val_bins() {
    let mut args = (0..12)
        .map(|i| ArgVal::Immediate(tagged_small(i)))
        .collect::<Vec<_>>();
    args.extend(TARGETS[..12].iter().copied().map(ArgVal::Label));
    for i in 0..12 {
        assert_eq!(
            run(
                |m| m.emit_i_select_val_bins(ArgVal::X(0), ArgVal::Label(99), 24, &args),
                tagged_small(i as i64),
                None,
            ),
            100 + i as u64
        );
    }
    assert_eq!(
        run(
            |m| m.emit_i_select_val_bins(ArgVal::X(0), ArgVal::Label(99), 24, &args),
            tagged_small(40),
            None,
        ),
        999
    );
}

#[test]
fn native_i_select_val2() {
    for (source, expected) in [(tagged_small(1), 100), (tagged_small(4), 101)] {
        assert_eq!(
            run(
                |m| {
                    m.emit_i_select_val2(
                        ArgVal::X(0),
                        ArgVal::Label(99),
                        ArgVal::Immediate(tagged_small(1)),
                        dest(0),
                        ArgVal::Immediate(tagged_small(4)),
                        dest(1),
                    )
                },
                source,
                None,
            ),
            expected
        );
    }
    assert_eq!(
        run(
            |m| {
                m.emit_i_select_val2(
                    ArgVal::X(0),
                    ArgVal::Label(99),
                    ArgVal::Immediate(tagged_small(1)),
                    dest(0),
                    ArgVal::Immediate(tagged_small(4)),
                    dest(1),
                )
            },
            tagged_small(8),
            None,
        ),
        999
    );
    assert_eq!(
        run(
            |m| {
                m.emit_i_select_val2(
                    ArgVal::X(0),
                    ArgVal::Label(99),
                    ArgVal::Immediate(tagged_small(1)),
                    dest(0),
                    ArgVal::Immediate(tagged_small(4)),
                    dest(0),
                )
            },
            tagged_small(4),
            None,
        ),
        100
    );
}

#[test]
fn native_i_jump_on_val() {
    for i in 0..3 {
        assert_eq!(
            run(
                |m| {
                    m.emit_i_jump_on_val(
                        ArgVal::X(0),
                        ArgVal::Label(99),
                        3,
                        3,
                        &TARGETS[..3]
                            .iter()
                            .copied()
                            .map(ArgVal::Label)
                            .collect::<Vec<_>>(),
                    )
                },
                tagged_small((i + 3) as i64),
                None,
            ),
            100 + i as u64
        );
    }
    assert_eq!(
        run(
            |m| m.emit_i_jump_on_val(
                ArgVal::X(0),
                ArgVal::Label(99),
                3,
                3,
                &TARGETS[..3]
                    .iter()
                    .copied()
                    .map(ArgVal::Label)
                    .collect::<Vec<_>>()
            ),
            tagged_small(8),
            None,
        ),
        999
    );
}

#[test]
fn native_i_jump_on_val_zero() {
    let table = TARGETS[..3]
        .iter()
        .copied()
        .map(ArgVal::Label)
        .collect::<Vec<_>>();
    for i in 0..3 {
        assert_eq!(
            run(
                |m| m.emit_i_jump_on_val_zero(ArgVal::X(0), ArgVal::Label(99), 3, &table),
                tagged_small(i as i64),
                None,
            ),
            100 + i as u64
        );
    }
    assert_eq!(
        run(
            |m| m.emit_i_jump_on_val_zero(ArgVal::X(0), ArgVal::Label(99), 3, &table),
            0x3b,
            None,
        ),
        999
    );
}

#[test]
fn native_i_jump_on_val_uses_rodata_for_large_tables() {
    let table = TARGETS
        .iter()
        .copied()
        .map(ArgVal::Label)
        .collect::<Vec<_>>();
    for i in [0, 7, 15] {
        assert_eq!(
            run(
                |m| m.emit_i_jump_on_val_zero(ArgVal::X(0), ArgVal::Label(99), 16, &table),
                tagged_small(i as i64),
                None,
            ),
            100 + i as u64,
        );
    }
    assert_eq!(
        run(
            |m| m.emit_i_jump_on_val_zero(ArgVal::X(0), ArgVal::Label(99), 16, &table),
            tagged_small(16),
            None,
        ),
        999,
    );
}

#[test]
fn native_i_jump_on_val_large_otp_table() {
    let count = 16_385;
    let labels = (0..count).map(|i| 1_000 + i as u32).collect::<Vec<_>>();
    let table = labels
        .iter()
        .copied()
        .map(ArgVal::Label)
        .collect::<Vec<_>>();
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_jump_on_val_zero(ArgVal::X(0), ArgVal::Label(999_999), count, &table)
        .unwrap();
    for (i, label) in labels.into_iter().enumerate() {
        asm.emit_i_func_label(label).unwrap();
        asm.emit_raw(|e| e.mov_const(Gpr::x(25), 100 + i as u64))
            .unwrap();
        asm.emit_raw(|e| e.mov_reg(Gpr::x(0), Gpr::xzr())).unwrap();
        asm.emit_raw(|e| e.ret(Gpr::x(30))).unwrap();
    }
    asm.emit_i_func_label(999_999).unwrap();
    asm.emit_raw(|e| e.mov_const(Gpr::x(25), 999)).unwrap();
    asm.emit_raw(|e| e.mov_reg(Gpr::x(0), Gpr::xzr())).unwrap();
    asm.emit_raw(|e| e.ret(Gpr::x(30))).unwrap();
    let module = asm.finalize().unwrap();
    let mut heap = [0u64; 16];
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        stop: heap.as_mut_ptr().wrapping_add(heap.len()),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut regs = SchedulerRegisters::default();
    regs.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(tagged_small((count - 1) as i64));
    let reason = enter_native(&mut header, &mut regs, &module.entry(1).unwrap());
    assert_eq!(reason, ExitReason::Returned);
    assert_eq!(regs.x_reg_array[0].tagged_word(), 100 + count as u64 - 1);
}

#[test]
fn native_i_select_tuple_arity() {
    let args = [ArgVal::Immediate(2), ArgVal::Immediate(5), dest(0), dest(1)];
    for (arity, expected) in [(2, 100), (5, 101)] {
        assert_eq!(
            run(
                |m| m.emit_i_select_tuple_arity(ArgVal::X(0), ArgVal::Label(99), 4, &args),
                0,
                Some(arity),
            ),
            expected
        );
    }
    assert_eq!(
        run(
            |m| m.emit_i_select_tuple_arity(ArgVal::X(0), ArgVal::Label(99), 4, &args),
            0,
            Some(3),
        ),
        999
    );
}

#[test]
fn native_i_select_tuple_arity2() {
    assert_eq!(
        run(
            |m| {
                m.emit_i_select_tuple_arity2(
                    ArgVal::X(0),
                    ArgVal::Label(99),
                    ArgVal::Immediate(1),
                    dest(0),
                    ArgVal::Immediate(4),
                    dest(1),
                )
            },
            0,
            Some(1),
        ),
        100
    );
    assert_eq!(
        run(
            |m| {
                m.emit_i_select_tuple_arity2(
                    ArgVal::X(0),
                    ArgVal::Label(99),
                    ArgVal::Immediate(1),
                    dest(0),
                    ArgVal::Immediate(4),
                    dest(1),
                )
            },
            0,
            Some(4),
        ),
        101
    );
}

fn tagged_atom(index: u64) -> u64 {
    (index << 6) | 0xb
}

/// Atom indexes far above the 12-bit immediate force the untag + rebase plan: the value is
/// tag-tested once, shifted and rebased, and the compares become immediates.
#[test]
fn native_select_val_lins_untags_atoms() {
    let indexes: Vec<u64> = (0..14).map(|i| 20_000 + i * 3).collect();
    let mut args: Vec<ArgVal> = indexes
        .iter()
        .map(|i| ArgVal::Immediate(tagged_atom(*i)))
        .collect();
    args.extend(TARGETS[..14].iter().copied().map(ArgVal::Label));
    for (n, index) in indexes.iter().enumerate() {
        assert_eq!(
            run(
                |m| m.emit_i_select_val_lins(ArgVal::X(0), ArgVal::Label(99), 28, &args),
                tagged_atom(*index),
                None,
            ),
            100 + n as u64
        );
    }
    // Between two values, below and above the range, another atom tag, and a small.
    for miss in [
        tagged_atom(20_001),
        tagged_atom(19_999),
        tagged_atom(20_100),
        tagged_atom(0),
        tagged_small(20_000),
        0x3b,
    ] {
        assert_eq!(
            run(
                |m| m.emit_i_select_val_lins(ArgVal::X(0), ArgVal::Label(99), 28, &args),
                miss,
                None,
            ),
            999,
            "source {miss:#x}"
        );
    }
}

#[test]
fn native_select_val_bins_untags_atoms_and_negative_smalls() {
    let atoms: Vec<u64> = (0..24).map(|i| tagged_atom(50_000 + i * 2)).collect();
    let smalls: Vec<u64> = (0..24).map(|i| tagged_small(-12 + i)).collect();
    for values in [atoms, smalls] {
        let mut args: Vec<ArgVal> = values.iter().map(|v| ArgVal::Immediate(*v)).collect();
        args.extend((0..24).map(|i| ArgVal::Label(TARGETS[i % 16])));
        for (n, value) in values.iter().enumerate() {
            assert_eq!(
                run(
                    |m| m.emit_i_select_val_bins_untagged(
                        ArgVal::X(0),
                        ArgVal::Label(99),
                        48,
                        &args
                    ),
                    *value,
                    None,
                ),
                100 + (n % 16) as u64,
                "value {value:#x}"
            );
        }
        for miss in [
            tagged_atom(49_999),
            tagged_atom(50_001),
            tagged_atom(60_000),
            tagged_small(1000),
            tagged_small(-1000),
            0x3b,
        ] {
            let in_set = values.contains(&miss);
            let got = run(
                |m| m.emit_i_select_val_bins_untagged(ArgVal::X(0), ArgVal::Label(99), 48, &args),
                miss,
                None,
            );
            assert!(in_set || got == 999, "source {miss:#x} matched {got}");
        }
    }
}

#[test]
fn native_select_val_bins_full_word_compares_for_atoms() {
    let atoms: Vec<u64> = (0..24).map(|i| tagged_atom(50_000 + i * 2)).collect();
    let mut args: Vec<ArgVal> = atoms.iter().map(|v| ArgVal::Immediate(*v)).collect();
    args.extend((0..24).map(|i| ArgVal::Label(TARGETS[i % 16])));
    for (n, value) in atoms.iter().enumerate() {
        assert_eq!(
            run(
                |m| m.emit_i_select_val_bins(ArgVal::X(0), ArgVal::Label(99), 48, &args),
                *value,
                None,
            ),
            100 + (n % 16) as u64
        );
    }
    for miss in [
        tagged_atom(49_999),
        tagged_atom(50_001),
        tagged_small(5),
        0x3b,
    ] {
        assert_eq!(
            run(
                |m| m.emit_i_select_val_bins(ArgVal::X(0), ArgVal::Label(99), 48, &args),
                miss,
                None,
            ),
            999
        );
    }
}
